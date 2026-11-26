//! kernelline_test.go: a kernel line through the router and the real kernel (jarvis_kernel::kerneltest, the whole
//! kernel in-process): the phone signs the source, a machine is spawned and reads its boot documents, pulls its secrets,
//! adds and drops a store, pauses into a source holding its snapshot, resumes from it, is destroyed and restored.
use crate::kernelline::{KERNEL_ADD_APPROVAL_KIND, KERNEL_APPROVAL_KIND, SOURCE_META};
use crate::machines::{FlyMachineDetail, FlyMount, LIST_FLY_MACHINES};
use crate::roster::RosterCurrent;
use crate::testutil::*;
use jarvis_doc::gv::{self, Signed};
use jarvis_doc::peek_cert;
use jarvis_kernel::kerneltest::{FakeFly, FakeMachine, Kernel};
use jarvis_nethttp::{Req, W};
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

pub const KERNEL_IMAGE: &str = "ghcr.io/de0ch/jarvis4-session:sha-aaaaaaaaaaaa@sha256:1111111111111111111111111111111111111111111111111111111111111111";

/// the fake Fly the router's read-only token lists (LIST_FLY_MACHINES), with or without the destroyed machines
static FLY: RwLock<Option<(Arc<FakeFly>, bool)>> = RwLock::new(None);

fn fake_fly_list() -> anyhow::Result<Vec<FlyMachineDetail>> {
    let Some((f, destroyed)) = FLY.read().unwrap_or_else(|e| e.into_inner()).clone() else {
        return Ok(vec![]);
    };
    Ok(f.list()
        .into_iter()
        .filter(|m| destroyed || m.state != "destroyed")
        .map(|m| {
            let mut d = FlyMachineDetail {
                id: m.id.clone(),
                state: m.state.clone(),
                ..Default::default()
            };
            d.config.metadata = BTreeMap::from([(SOURCE_META.to_string(), m.source.clone())]);
            d.config.mounts = vec![FlyMount {
                volume: m.volume.clone(),
                ..Default::default()
            }];
            d
        })
        .collect())
}

/// the archive rig with the real kernel beside the fake core, its root grant in, new sessions on it (the test holds
/// `serial()`: the fake Fly list is process-wide)
pub struct KRig {
    pub k: Kernel,
    pub rg: Rig,
    _serial: std::sync::MutexGuard<'static, ()>,
}

impl std::ops::Deref for KRig {
    type Target = Rig;
    fn deref(&self) -> &Rig {
        &self.rg
    }
}

impl Drop for KRig {
    fn drop(&mut self) {
        // the fake Fly's ids repeat across tests: this test's pulls would make another wait BOOT_GRACE
        crate::vouch::forget_all_pulled();
        *FLY.write().unwrap_or_else(|e| e.into_inner()) = None;
    }
}

pub fn kernel_rig() -> KRig {
    let serial = serial();
    let k = Kernel::start(BTreeMap::from([(
        "JARVIS2_URL".to_string(),
        "http://router".to_string(),
    )]));
    let front = k.front.clone();
    let policy = crate::policy::Policy {
        harnesses: [("claude".to_string(), Default::default())]
            .into_iter()
            .collect(),
    };
    let rg = Rig::with_policy(
        move |c| {
            c.kernel_url = format!("{front}/%s");
            c.session_image = KERNEL_IMAGE.into();
            c.region = "lhr".into();
        },
        policy,
    );
    rg.wire_kernel();
    // the roster Deyao signed for blue, as the router keeps it
    let d = k.roster().unwrap_or_else(|e| panic!("{e:#}"));
    let root = k.root.public_key();
    let top = k.root_top();
    rg.st.do_(|p| {
        p.kernel_root_key = root.clone();
        p.kernel_roster = Some(RosterCurrent {
            copy: "blue".into(),
            payload: d.payload.clone(),
            sig: d.sig.clone(),
            at: jarvis_go::GoTime::now(),
            ..Default::default()
        });
        p.kernel_root = Some(Signed {
            grant: top.clone(),
            by: "root".into(),
            signer: None,
            keys: None,
            secrets: None,
        });
    });
    *FLY.write().unwrap_or_else(|e| e.into_inner()) = Some((k.fly.clone(), true));
    *LIST_FLY_MACHINES.write().unwrap_or_else(|e| e.into_inner()) = fake_fly_list;
    KRig {
        k,
        rg,
        _serial: serial,
    }
}

/// a request signed by a kernel machine's key, as the supervisor signs it (rust/machine/src/client.rs Client::raw)
pub fn kdo(
    h: &crate::http::AppFn,
    m: &FakeMachine,
    method: &str,
    path: &str,
    body: &str,
) -> (u16, Vec<u8>) {
    use sha2::Digest;
    let ts = crate::util::unix_now().to_string();
    let sum = hex::encode(sha2::Sha256::digest(body.as_bytes()));
    let sig = m.sig.sign(format!("{method} {path} {ts} {sum}").as_bytes());
    let mut req = Req::new(method, path, body.as_bytes())
        .with_header("X-Machine", &m.id)
        .with_header("X-Time", &ts)
        .with_header("X-Sig", &sig)
        .with_header("Content-Type", "application/json");
    let mut w = W::recorder();
    h(&mut w, &mut req);
    (w.status(), w.recorded.clone().unwrap_or_default())
}

pub fn kernel_session(rg: &Rig, sid: &str) -> crate::state::Session {
    rg.session(sid)
}

/// the approval of session sid, waited for
pub fn approval_of(rg: &Rig, sid: &str) -> crate::state::Approval {
    let mut a = None;
    wait_for("the approval", || {
        rg.st
            .do_(|d| d.approvals.values().find(|x| x.session == sid).cloned())
            .is_some()
    });
    rg.st.do_(|d| {
        a = d.approvals.values().find(|x| x.session == sid).cloned();
    });
    a.unwrap_or_else(|| panic!("no approval"))
}

/// an approval's challenge as the kernel's document
pub fn challenge_doc(a: &crate::state::Approval) -> jarvis_sig::Doc {
    let c = a
        .challenge
        .as_ref()
        .unwrap_or_else(|| panic!("no challenge"));
    jarvis_sig::Doc {
        payload: c.payload.clone(),
        sig: c.sig.clone(),
    }
}

pub fn challenge(a: &crate::state::Approval) -> String {
    a.challenge
        .as_ref()
        .map(|c| c.payload.clone())
        .unwrap_or_default()
}

/// a new kernel session, its source signed by the phone, its first machine up → (session, machine)
pub fn start_line(kr: &KRig, label: &str) -> (String, FakeMachine) {
    let sid = kr
        .create_session(crate::flows::NewSession {
            label: label.into(),
            harness: "claude".into(),
            ..Default::default()
        })
        .unwrap_or_else(|e| panic!("{e:#}"));
    let a = approval_of(kr, &sid);
    let sig = kr.k.phone.sign(challenge(&a).as_bytes());
    kr.respond(&a.id, &sig).unwrap_or_else(|e| panic!("{e:#}"));
    wait_for("the machine", || {
        let s = kernel_session(kr, &sid);
        !s.machine_id.is_empty() && s.kernel.as_ref().is_some_and(|k| k.machine_cert.is_some())
    });
    let mid = kernel_session(kr, &sid).machine_id;
    (
        sid,
        kr.k.fly
            .machine(&mid)
            .unwrap_or_else(|| panic!("no machine {mid}")),
    )
}

fn grant_of(kr: &KRig, sid: &str) -> jarvis_doc::Grant {
    let s = kernel_session(kr, sid);
    let g = s
        .kernel
        .and_then(|k| k.grant)
        .unwrap_or_else(|| panic!("no grant"));
    gv::open(&g, &kr.k.trust()).unwrap_or_else(|e| panic!("{e}"))
}

/// a kernel line's life through the router and the real kernel: the phone signs the source, a machine is spawned and
/// reads its boot documents, pulls its secrets, pauses into a source holding its snapshot, resumes from it (the new
/// machine restores the old one's snapshot), and the destroy archives it and burns its source
#[test]
fn a_kernel_lines_life() {
    use sha2::Digest;
    let kr = kernel_rig();
    let sid = kr
        .create_session(crate::flows::NewSession {
            label: "on the kernel".into(),
            harness: "claude".into(),
            ..Default::default()
        })
        .unwrap_or_else(|e| panic!("{e:#}"));
    let a = approval_of(&kr, &sid);
    assert_eq!(a.kind, KERNEL_APPROVAL_KIND);
    let c = peek_cert(&challenge_doc(&a)).unwrap_or_else(|e| panic!("{e}"));
    let src = c.source.as_ref().unwrap_or_else(|| panic!("no source"));
    assert!(c.pred.0 == "sink" && src.image == KERNEL_IMAGE, "{c:?}");
    let settings: Value = serde_json::from_str(src.settings.get()).unwrap_or_default();
    assert!(
        settings["harness"] == "claude"
            && settings["permissionMode"] == "bypass"
            && c.pair
                .conditions
                .as_ref()
                .is_some_and(|v| v[0] == format!("session:{sid}")),
        "{settings} {:?}",
        c.pair
    );
    let sig = kr.k.phone.sign(challenge(&a).as_bytes());
    kr.respond(&a.id, &sig).unwrap_or_else(|e| panic!("{e:#}"));
    wait_for("the machine", || {
        let s = kernel_session(&kr, &sid);
        !s.machine_id.is_empty() && s.kernel.as_ref().is_some_and(|k| k.machine_cert.is_some())
    });
    let m1 =
        kr.k.fly
            .machine(&kernel_session(&kr, &sid).machine_id)
            .unwrap_or_else(|| panic!("no machine"));
    let h = kr.machine_handler();
    let (code, body) = kdo(&h, &m1, "GET", "/m/kernel/boot", "");
    assert_eq!(code, 200, "{}", String::from_utf8_lossy(&body));
    let boot: Value = serde_json::from_slice(&body).unwrap_or_default();
    let bg: Signed =
        serde_json::from_value(boot["grant"].clone()).unwrap_or_else(|e| panic!("{e}"));
    let g = gv::open(&bg, &kr.k.trust()).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        g.machine.0 == format!("fly-{}", m1.id) && g.keys.signing_key == m1.sig.public_key(),
        "{g:?}"
    );
    let (code, body) = kdo(&h, &m1, "POST", "/m/pull-secrets", "{}");
    assert!(
        code == 200 && String::from_utf8_lossy(&body).contains("secrets"),
        "{code} {}",
        String::from_utf8_lossy(&body)
    );
    assert_eq!(kernel_session(&kr, &sid).state, "started");
    // a batch may ask for a store on a kernel line too (it was refused as "no running machine": it looked for the old
    // core's cert only)
    let (code, body) = kdo(
        &h,
        &m1,
        "POST",
        "/m/api/requests/batch",
        r#"{"summary":"two things","items":[{"intent":"add-store","store":"batched","explanation":"for a test"}]}"#,
    );
    assert_eq!(code, 200, "{}", String::from_utf8_lossy(&body));
    let batched = kr.st.do_(|d| {
        d.approvals
            .values()
            .find(|x| {
                x.session == sid && x.options.get("store").map(String::as_str) == Some("batched")
            })
            .cloned()
    });
    assert!(
        batched
            .as_ref()
            .is_some_and(|b| b.kind == KERNEL_ADD_APPROVAL_KIND && !b.batch.is_empty()),
        "{batched:?}"
    );
    // add-store: the phone signs both certs; the store's grant, moved onto the machine, merges with the main one
    let aid = kr
        .add_store_approval(&m1.id, "extra", Default::default(), "", "")
        .unwrap_or_else(|e| panic!("{e:#}"));
    let add = kr
        .st
        .do_(|d| d.approvals.get(&aid).cloned())
        .unwrap_or_else(|| panic!("no add"));
    assert_eq!(add.kind, KERNEL_ADD_APPROVAL_KIND);
    let s1 = kr.k.phone.sign(challenge(&add).as_bytes());
    let s2 = kr.k.phone.sign(add.earlier[0].payload.as_bytes());
    kr.respond(&aid, &format!("{s1}\n{s2}"))
        .unwrap_or_else(|e| panic!("{e:#}"));
    let g = grant_of(&kr, &sid);
    assert!(
        g.pair.allowed.contains("store:extra") && g.machine.0 == format!("fly-{}", m1.id),
        "{g:?}"
    );
    // downgrade: the identity signer narrows the grant to what is kept
    let (code, body) = kdo(&h, &m1, "POST", "/m/kernel/downgrade", r#"{"keep":[]}"#);
    assert_eq!(code, 200, "{}", String::from_utf8_lossy(&body));
    let g = grant_of(&kr, &sid);
    assert!(
        !g.pair.allowed.contains("store:extra") && g.machine.0 == format!("fly-{}", m1.id),
        "{g:?}"
    );
    // pause: the machine's signed snapshot is here; the spawner kills it into a source holding its hash
    let tarball = make_tar(&kr.files);
    let sum = hex::encode(sha2::Sha256::digest(&tarball));
    let snap_sig = m1.sig.sign(sum.as_bytes());
    put_snap(&kr.t.r, &m1.id, &tarball, &snap_sig);
    kr.pause(&sid).unwrap_or_else(|e| panic!("{e:#}"));
    kr.wait_action_end(&sid, "paused")
        .unwrap_or_else(|e| panic!("{e:#} {}", kernel_session(&kr, &sid).error));
    let s = kernel_session(&kr, &sid);
    let kl = s.kernel.clone().unwrap_or_default();
    let sc = peek_cert(
        kl.source_cert
            .as_ref()
            .unwrap_or_else(|| panic!("no source cert")),
    )
    .unwrap_or_else(|e| panic!("{e}"));
    assert!(
        sc.pred.0 == format!("fly-{}", m1.id)
            && sc.source.as_ref().is_some_and(|x| x.snapshot == sum)
            && kl.grant.is_some()
            && s.no_snapshot.is_empty(),
        "{sc:?} {:?}",
        s.no_snapshot
    );
    assert_eq!(
        kr.k.fly
            .machine(&m1.id)
            .map(|m| m.state)
            .unwrap_or_default(),
        "destroyed",
        "the old machine is still there"
    );
    // resume: a new machine from that source restores m1's snapshot
    kr.resume(&sid, false).unwrap_or_else(|e| panic!("{e:#}"));
    wait_for("the second machine", || {
        let s = kernel_session(&kr, &sid);
        !s.machine_id.is_empty()
            && s.machine_id != m1.id
            && s.kernel.as_ref().is_some_and(|k| k.machine_cert.is_some())
    });
    let m2 =
        kr.k.fly
            .machine(&kernel_session(&kr, &sid).machine_id)
            .unwrap_or_else(|| panic!("no machine"));
    let (code, body) = kdo(&h, &m2, "GET", "/m/snapshot", "");
    assert!(
        code == 200 && body == tarball,
        "the predecessor's snapshot: {code}"
    );
    // ✱ the first machine is gone: its calls are refused
    assert_ne!(
        kdo(&h, &m1, "GET", "/m/kernel/boot", "").0,
        200,
        "a killed machine read the line's documents"
    );
    // destroy: archived, the source burned (a second spawn from it would be refused by the notarizer)
    kr.destroy(&sid).unwrap_or_else(|e| panic!("{e:#}"));
    wait_for("the record", || {
        kr.st.do_(|d| !d.sessions.contains_key(&sid))
    });
    let rec = kr.record(&sid).unwrap_or_else(|| panic!("no record"));
    assert_eq!(
        rec.archive
            .as_ref()
            .map(|a| a.signer.clone())
            .unwrap_or_default(),
        m1.id,
        "the archive: {rec:?}"
    );
    // restore: a new kernel line whose source names the archived snapshot's hash (the phone signs it); its first
    // machine gets that snapshot
    let nsid = kr
        .restore_record(&sid, "")
        .unwrap_or_else(|e| panic!("{e:#}"));
    let ra = approval_of(&kr, &nsid);
    let rc = peek_cert(&challenge_doc(&ra)).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        ra.kind == KERNEL_APPROVAL_KIND && rc.source.as_ref().is_some_and(|x| x.snapshot == sum),
        "{ra:?}"
    );
    let rsig = kr.k.phone.sign(challenge(&ra).as_bytes());
    kr.respond(&ra.id, &rsig)
        .unwrap_or_else(|e| panic!("{e:#}"));
    wait_for("the restored machine", || {
        let s = kernel_session(&kr, &nsid);
        !s.machine_id.is_empty() && s.kernel.as_ref().is_some_and(|k| k.machine_cert.is_some())
    });
    let m3 =
        kr.k.fly
            .machine(&kernel_session(&kr, &nsid).machine_id)
            .unwrap_or_else(|| panic!("no machine"));
    let (code, body) = kdo(&h, &m3, "GET", "/m/snapshot", "");
    assert!(
        code == 200 && body == tarball,
        "the archived snapshot: {code}"
    );
}

/// ✱ without the root grant, new sessions stay on the old core
#[test]
fn no_kernel_root_no_kernel_sessions() {
    let kr = kernel_rig();
    kr.st.do_(|d| d.kernel_root = None);
    let sid = kr
        .create_session(crate::flows::NewSession {
            label: "x".into(),
            harness: "claude".into(),
            ..Default::default()
        })
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert!(
        kernel_session(&kr, &sid).kernel.is_none(),
        "a kernel line without the root's grant"
    );
}

/// A crash restart of the mover (new keys; its copy's re-signed roster names the old ones as retired): a running
/// line's grant, signed by the old mover, still opens, and its destroy goes through
#[test]
fn destroy_after_the_mover_restarted() {
    let mut kr = kernel_rig();
    let (sid, m1) = start_line(&kr, "on the kernel");
    kr.k.restart("mover");
    kr.k.post_roster("").unwrap_or_else(|e| panic!("{e:#}"));
    let g = kernel_session(&kr, &sid)
        .kernel
        .and_then(|k| k.grant)
        .unwrap_or_else(|| panic!("no grant"));
    gv::open(&g, &kr.k.trust())
        .unwrap_or_else(|e| panic!("the old mover's grant no longer opens: {e}"));
    crate::vouch::forget_pulled(&m1.id);
    kr.destroy(&sid).unwrap_or_else(|e| panic!("{e:#}"));
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let s = kr.st.do_(|d| {
            d.sessions
                .get(&sid)
                .map(|x| (x.state.clone(), x.error.clone()))
        });
        let Some((state, why)) = s else { break };
        assert!(
            std::time::Instant::now() < deadline,
            "not destroyed: {state} {why}"
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert_eq!(
        kr.k.fly
            .machine(&m1.id)
            .map(|m| m.state)
            .unwrap_or_default(),
        "destroyed"
    );
    let _ = &mut kr;
}

/// a new kernel session, its source signed by the phone (the spawn runs)
fn kernel_start(kr: &KRig, label: &str) -> String {
    kernel_start_in(
        kr,
        crate::flows::NewSession {
            label: label.into(),
            harness: "claude".into(),
            ..Default::default()
        },
    )
}

fn kernel_start_in(kr: &KRig, input: crate::flows::NewSession) -> String {
    let sid = kr.create_session(input).unwrap_or_else(|e| panic!("{e:#}"));
    let a = approval_of(kr, &sid);
    let sig = kr.k.phone.sign(challenge(&a).as_bytes());
    kr.respond(&a.id, &sig).unwrap_or_else(|e| panic!("{e:#}"));
    sid
}

fn wait_machine(kr: &KRig, sid: &str) {
    wait_for("the machine", || {
        let s = kernel_session(kr, sid);
        !s.machine_id.is_empty() && s.kernel.as_ref().is_some_and(|k| k.machine_cert.is_some())
    });
}

/// the spawner makes single calls and the router retries: ✱ a volume on a host with no room for the machine (Fly's 412
/// volume_placement_capacity) is deleted by the spawner and the router spawns again, a new volume on another host;
/// ✱ a create whose answer was lost left a machine the spawner never recorded: the router finds it by its source with
/// its read-only token, has the spawner destroy it, and spawns again; the line ends with one live machine either way
#[test]
fn a_kernel_spawn_is_retried_by_the_router() {
    let kr = kernel_rig();
    let live = |source: &str| -> Vec<FakeMachine> {
        kr.k.fly
            .list()
            .into_iter()
            .filter(|m| m.source == source && m.state != "destroyed")
            .collect()
    };
    let source_of = |sid: &str| {
        kernel_session(&kr, sid)
            .kernel
            .and_then(|k| k.source)
            .map(|o| o.0)
            .unwrap_or_default()
    };
    kr.k.fly.st().full = 2;
    let sid = kernel_start(&kr, "full hosts");
    wait_machine(&kr, &sid);
    let s = kernel_session(&kr, &sid);
    let ms = live(&source_of(&sid));
    assert!(
        ms.len() == 1 && ms[0].id == s.machine_id,
        "live machines {:?}, the session's {}",
        ms.iter().map(|m| &m.id).collect::<Vec<_>>(),
        s.machine_id
    );
    let vols = kr.k.fly.volumes();
    assert_eq!(vols.len(), 1, "volumes left by the full hosts: {vols:?}");
    let st = kr
        .st
        .do_(|d| d.started.get(&s.machine_id).cloned())
        .unwrap_or_default();
    assert!(
        st.volume
            .as_ref()
            .is_some_and(|v| v.size_gb == crate::disk::DEFAULT_DISK && v.id == vols[0]),
        "the router's record of the volume: {st:?}"
    );

    kr.k.fly.st().lose = 1;
    let sid2 = kernel_start(&kr, "lost answer");
    wait_machine(&kr, &sid2);
    let s2 = kernel_session(&kr, &sid2);
    let src2 = source_of(&sid2);
    let ms = live(&src2);
    assert!(
        ms.len() == 1 && ms[0].id == s2.machine_id,
        "live machines {:?}, the session's {}",
        ms.iter().map(|m| &m.id).collect::<Vec<_>>(),
        s2.machine_id
    );
    let n = kr.k.fly.list().iter().filter(|m| m.source == src2).count();
    assert_eq!(
        n, 2,
        "machines from the source: the lost one and the line's"
    );
}

/// a kernel-source approval nobody answers settles like a new-session one: a session's proposal goes, Deyao's own is
/// kept failed; a resume onto a new source goes back to paused (2026-10-26: the session stayed "approval" for good)
#[test]
fn a_lapsed_kernel_approval_settles_its_session() {
    let kr = kernel_rig();
    let proposed = kr
        .create_session(crate::flows::NewSession {
            label: "proposed".into(),
            harness: "claude".into(),
            origin: Some(crate::inbox::Origin {
                caller: crate::inbox::Caller {
                    kind: "session".into(),
                    session: "sOther".into(),
                },
                ..Default::default()
            }),
            ..Default::default()
        })
        .unwrap_or_else(|e| panic!("{e:#}"));
    let own = kr
        .create_session(crate::flows::NewSession {
            label: "own".into(),
            harness: "claude".into(),
            ..Default::default()
        })
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert!(
        approval_of(&kr, &proposed).kind == KERNEL_APPROVAL_KIND
            && approval_of(&kr, &own).kind == KERNEL_APPROVAL_KIND,
        "not kernel approvals"
    );
    let resumed = "sResumed";
    kr.st.do_(|d| {
        d.sessions.insert(
            resumed.into(),
            crate::state::Session {
                id: resumed.into(),
                state: "approval".into(),
                created: jarvis_go::GoTime::now(),
                harness: "claude".into(),
                kernel: Some(crate::kernelline::KernelLine {
                    source_cert: Some(jarvis_sig::Doc {
                        payload: "{}".into(),
                        sig: String::new(),
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
    });
    kr.add_approval(crate::state::Approval {
        kind: KERNEL_APPROVAL_KIND.into(),
        session: resumed.into(),
        ..Default::default()
    });
    kr.expire_approvals(jarvis_go::GoTime::from_unix(
        crate::util::unix_now() + 11 * 60,
    ));
    let s = kernel_session(&kr, &proposed);
    assert!(s.id.is_empty(), "a session's lapsed proposal stayed: {s:?}");
    assert_eq!(kernel_session(&kr, &own).state, "failed", "Deyao's own");
    assert_eq!(kernel_session(&kr, resumed).state, "paused", "the resume");
}

/// a session left "approval" with no approval is settled once past inboxTTL; a fresh one (its approval still being
/// made) is left alone
#[test]
fn a_stranded_approval_session_is_settled() {
    let kr = kernel_rig();
    let old = jarvis_go::GoTime::from_unix(crate::util::unix_now() - 3600);
    let line = |cert: bool| {
        Some(crate::kernelline::KernelLine {
            source_cert: cert.then(|| jarvis_sig::Doc {
                payload: "{}".into(),
                sig: String::new(),
            }),
            ..Default::default()
        })
    };
    kr.st.do_(|d| {
        for (id, created, cert) in [
            ("sNew", old, false),
            ("sRan", old, true),
            ("sFresh", jarvis_go::GoTime::now(), false),
        ] {
            d.sessions.insert(
                id.into(),
                crate::state::Session {
                    id: id.into(),
                    state: "approval".into(),
                    created,
                    harness: "claude".into(),
                    kernel: line(cert),
                    ..Default::default()
                },
            );
        }
    });
    kr.settle_stranded_approvals(jarvis_go::GoTime::now());
    let s = kernel_session(&kr, "sNew");
    assert!(
        s.state == "failed" && s.error.contains("Start again"),
        "new: {s:?}"
    );
    assert_eq!(kernel_session(&kr, "sRan").state, "paused", "ran");
    assert_eq!(kernel_session(&kr, "sFresh").state, "approval", "fresh");
}

/// the newest kernel-source approval of sid (satisfying ok), waited for
fn source_approval(
    kr: &KRig,
    sid: &str,
    what: &str,
    ok: impl Fn(&crate::state::Approval) -> bool,
) -> crate::state::Approval {
    let find = || {
        kr.st.do_(|d| {
            d.approvals
                .values()
                .filter(|x| x.session == sid && x.kind == KERNEL_APPROVAL_KIND)
                .find(|x| ok(x))
                .cloned()
        })
    };
    wait_for(what, || find().is_some());
    find().unwrap_or_else(|| panic!("{what}"))
}

/// the phone's answer; filed while the session's start still runs, it waits for that action to end
fn sign_approval(kr: &KRig, a: &crate::state::Approval) {
    let s = kr.k.phone.sign(challenge(a).as_bytes());
    let res = std::sync::Mutex::new(Ok(()));
    wait_for("the answer taken", || {
        let r = kr.respond(&a.id, &s).map(|_| ());
        let again = r
            .as_ref()
            .err()
            .is_some_and(|e| format!("{e:#}").contains("in the middle of another action"));
        *res.lock().unwrap_or_else(|e| e.into_inner()) = r;
        !again
    });
    let r = std::mem::replace(&mut *res.lock().unwrap_or_else(|e| e.into_inner()), Ok(()));
    r.unwrap_or_else(|e| panic!("{e:#}"));
}

fn snapshot_of(c: &jarvis_doc::Cert) -> String {
    c.source
        .as_ref()
        .map(|s| s.snapshot.clone())
        .unwrap_or_default()
}

/// a machine's next one: the machine the line's start made once its cert is in
fn next_machine(kr: &KRig, sid: &str, last: &mut String, what: &str) -> FakeMachine {
    let l = last.clone();
    wait_for(what, || {
        let s = kernel_session(kr, sid);
        !s.machine_id.is_empty()
            && s.machine_id != l
            && s.kernel.as_ref().is_some_and(|k| k.machine_cert.is_some())
    });
    *last = kernel_session(kr, sid).machine_id;
    kr.k.fly
        .machine(last)
        .unwrap_or_else(|| panic!("no machine {last}"))
}

fn pause_line(kr: &KRig, sid: &str) {
    kr.pause(sid).unwrap_or_else(|e| panic!("{e:#}"));
    kr.wait_action_end(sid, "paused")
        .unwrap_or_else(|e| panic!("{e:#} {}", kernel_session(kr, sid).error));
}

/// m's signed snapshot of the rig's files → its hash
fn leave_snapshot(kr: &KRig, m: &FakeMachine) -> (Vec<u8>, String) {
    use sha2::Digest;
    let tarball = make_tar(&kr.files);
    let want = hex::encode(sha2::Sha256::digest(&tarball));
    put_snap(&kr.t.r, &m.id, &tarball, &m.sig.sign(want.as_bytes()));
    (tarball, want)
}

/// a resume on the newest image (the phone signs a new source from the sink naming the last snapshot's hash) restores
/// that snapshot: its first machine's GET /m/snapshot was refused "no predecessor" (2026-11-05, the WeChat warm-up
/// session). An upgrade after a machine that never got past boot still names the line's newest snapshot.
#[test]
fn an_upgrade_resume_restores_the_last_snapshot() {
    let kr = kernel_rig();
    let sid = kr
        .create_session(crate::flows::NewSession {
            label: "upgraded".into(),
            harness: "claude".into(),
            ..Default::default()
        })
        .unwrap_or_else(|e| panic!("{e:#}"));
    sign_approval(&kr, &source_approval(&kr, &sid, "the approval", |_| true));
    let mut last = String::new();
    let m1 = next_machine(&kr, &sid, &mut last, "the machine");
    let h = kr.machine_handler();
    let (code, body) = kdo(&h, &m1, "GET", "/m/kernel/boot", "");
    assert_eq!(code, 200, "{}", String::from_utf8_lossy(&body));
    let (tarball, want) = leave_snapshot(&kr, &m1);
    pause_line(&kr, &sid);
    kr.resume(&sid, true).unwrap_or_else(|e| panic!("{e:#}"));
    let a = source_approval(&kr, &sid, "the upgrade's approval", |_| true);
    let c = peek_cert(&challenge_doc(&a)).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        c.pred.0 == "sink" && snapshot_of(&c) == want,
        "{}",
        challenge(&a)
    );
    sign_approval(&kr, &a);
    let m2 = next_machine(&kr, &sid, &mut last, "the upgraded machine");
    let (code, body) = kdo(&h, &m2, "GET", "/m/snapshot", "");
    assert!(
        code == 200 && body == tarball,
        "the upgraded machine's snapshot: {code}"
    );
    // m2 never gets past boot; the app's Restart on the newest image: its kill names no snapshot, the new source still
    // names m1's
    kr.restart(
        &sid,
        crate::sessionops::RestartRequest {
            upgrade: true,
            ..Default::default()
        },
    )
    .unwrap_or_else(|e| panic!("{e:#}"));
    let w = want.clone();
    let a = source_approval(&kr, &sid, "the second upgrade's approval", move |a| {
        peek_cert(&challenge_doc(a)).is_ok_and(|c| snapshot_of(&c) == w)
    });
    sign_approval(&kr, &a);
    let m3 = next_machine(&kr, &sid, &mut last, "the third machine");
    let (code, body) = kdo(&h, &m3, "GET", "/m/snapshot", "");
    assert!(
        code == 200 && body == tarball,
        "the third machine's snapshot: {code}"
    );
}

/// the machine whose snapshot the router serves this kernel machine's boot
fn started_pred(kr: &KRig, machine: &str) -> String {
    kr.st.do_(|d| {
        d.started
            .get(machine)
            .map(|st| st.kernel_pred.clone())
            .unwrap_or_default()
    })
}

/// a resume after a machine that never got past boot restores the line's last snapshot: that machine's kill passes on
/// the hash its source named, so the source comes from a machine with no snapshot of its own, and the next machine's
/// GET /m/snapshot was refused "no snapshot" (2026-11-16: a machine whose restore ran out of disk, paused, resumed).
/// The machine takes the snapshot by the hash its source names (rust/machine/src/kernelboot.rs kernel_restore).
#[test]
fn a_resume_after_a_machine_that_never_booted_restores_the_last_snapshot() {
    use sha2::Digest;
    let kr = kernel_rig();
    let sid = kr
        .create_session(crate::flows::NewSession {
            label: "never booted".into(),
            harness: "claude".into(),
            ..Default::default()
        })
        .unwrap_or_else(|e| panic!("{e:#}"));
    sign_approval(&kr, &source_approval(&kr, &sid, "the approval", |_| true));
    let h = kr.machine_handler();
    let mut last = String::new();
    // the first machine boots and leaves its signed snapshot at the pause
    let m1 = next_machine(&kr, &sid, &mut last, "the machine");
    kr.st.do_(|d| {
        if let Some(s) = d.sessions.get_mut(&sid) {
            s.booted = m1.id.clone();
        }
    });
    let (_, want) = leave_snapshot(&kr, &m1);
    pause_line(&kr, &sid);
    // what the machine's boot does: the hash its source names (GET /m/kernel/boot), then the snapshot, checked by it
    let restores = |m: &FakeMachine, who: &str| {
        let (code, body) = kdo(&h, m, "GET", "/m/kernel/boot", "");
        assert_eq!(
            code,
            200,
            "{who}: its boot documents: {}",
            String::from_utf8_lossy(&body)
        );
        let boot: Value = serde_json::from_slice(&body).unwrap_or_default();
        let sd: jarvis_sig::Doc = serde_json::from_value(boot["sourceCert"].clone())
            .unwrap_or_else(|e| panic!("{who}: {e}"));
        let sc = peek_cert(&sd).unwrap_or_else(|e| panic!("{who}: {e}"));
        assert_eq!(
            snapshot_of(&sc),
            want,
            "{who}: its source doesn't name the line's snapshot"
        );
        let (code, body) = kdo(&h, m, "GET", "/m/snapshot", "");
        assert_eq!(
            code,
            200,
            "{who}: GET /m/snapshot: {}",
            String::from_utf8_lossy(&body)
        );
        assert_eq!(
            hex::encode(sha2::Sha256::digest(&body)),
            want,
            "{who}: the snapshot it got isn't the one its source names"
        );
    };
    // a machine that did boot is its successor's predecessor, as before
    kr.resume(&sid, false).unwrap_or_else(|e| panic!("{e:#}"));
    let m2 = next_machine(&kr, &sid, &mut last, "the second machine");
    restores(&m2, "the second machine");
    assert_eq!(
        started_pred(&kr, &m2.id),
        m1.id,
        "the second machine's predecessor"
    );
    // m2 never gets past boot: paused with nothing to snapshot, its kill passes m1's hash on; the resume needs no
    // approval, and the third machine restores m1's snapshot though its source came from m2
    pause_line(&kr, &sid);
    let ks = kernel_session(&kr, &sid);
    let sc = peek_cert(
        ks.kernel
            .and_then(|k| k.source_cert)
            .as_ref()
            .unwrap_or_else(|| panic!("no source cert")),
    )
    .unwrap_or_else(|e| panic!("{e}"));
    assert!(
        sc.pred.0 == format!("fly-{}", m2.id) && snapshot_of(&sc) == want && !kr.have_snap(&m2.id),
        "the source after a machine that never booted: {sc:?}"
    );
    kr.resume(&sid, false).unwrap_or_else(|e| panic!("{e:#}"));
    let m3 = next_machine(&kr, &sid, &mut last, "the third machine");
    restores(&m3, "the third machine");
    assert_eq!(
        started_pred(&kr, &m3.id),
        m1.id,
        "the third machine's predecessor"
    );
    // and again: two machines in a row that never booted
    pause_line(&kr, &sid);
    kr.resume(&sid, false).unwrap_or_else(|e| panic!("{e:#}"));
    let m4 = next_machine(&kr, &sid, &mut last, "the fourth machine");
    restores(&m4, "the fourth machine");
}

/// the machine's first status report, as its supervisor sends it once the boot is done
fn booted(kr: &KRig, m: &FakeMachine) {
    let (code, body) = kdo(
        &kr.machine_handler(),
        m,
        "POST",
        "/m/status",
        r#"{"raw":""}"#,
    );
    assert_eq!(
        code,
        200,
        "the status report: {}",
        String::from_utf8_lossy(&body)
    );
}

/// a kernel machine asked for its snapshot while it is still booting carries over the snapshot its source names, as a
/// core line's does: the router looked for the predecessor in the old core's cert only, which a kernel machine has none
/// of, and refused the carry with 409
#[test]
fn a_booting_kernel_machine_carries_the_snapshot_its_source_names() {
    let kr = kernel_rig();
    let sid = kernel_start(&kr, "carried");
    let h = kr.machine_handler();
    let mut last = String::new();
    let m1 = next_machine(&kr, &sid, &mut last, "the machine");
    booted(&kr, &m1);
    let (tarball, want) = leave_snapshot(&kr, &m1);
    pause_line(&kr, &sid);
    kr.resume(&sid, false).unwrap_or_else(|e| panic!("{e:#}"));
    let m2 = next_machine(&kr, &sid, &mut last, "the second machine");
    // a hash its source doesn't name is refused; the one it names becomes its own snapshot, signed by its key
    let wrong = "1".repeat(64);
    let ws = m2.sig.sign(wrong.as_bytes());
    let (code, body) = kdo(
        &h,
        &m2,
        "POST",
        "/m/snapshot-carry",
        &format!(r#"{{"sha256":"{wrong}","sig":"{ws}"}}"#),
    );
    assert_eq!(
        code,
        409,
        "carried a hash the source doesn't name: {}",
        String::from_utf8_lossy(&body)
    );
    let cs = m2.sig.sign(want.as_bytes());
    let (code, body) = kdo(
        &h,
        &m2,
        "POST",
        "/m/snapshot-carry",
        &format!(r#"{{"sha256":"{want}","sig":"{cs}"}}"#),
    );
    assert_eq!(code, 200, "the carry: {}", String::from_utf8_lossy(&body));
    let s = kr.snap(&m2.id);
    assert!(
        s.as_ref()
            .is_some_and(|s| s.state == "committed" && s.sha256 == want)
            && snap_bytes(&kr.t.r, &m2.id).as_deref() == Some(&tarball[..]),
        "the second machine's snapshot: {s:?}"
    );
    // the pause kills it into a source that names the snapshot, and the next machine restores it
    pause_line(&kr, &sid);
    let ks = kernel_session(&kr, &sid);
    let sc = peek_cert(
        ks.kernel
            .clone()
            .and_then(|k| k.source_cert)
            .as_ref()
            .unwrap_or_else(|| panic!("no source")),
    )
    .unwrap_or_else(|e| panic!("{e}"));
    assert!(
        sc.pred.0 == format!("fly-{}", m2.id)
            && snapshot_of(&sc) == want
            && ks.no_snapshot.is_empty(),
        "the source after the carry: {sc:?} {:?}",
        ks.no_snapshot
    );
    kr.resume(&sid, false).unwrap_or_else(|e| panic!("{e:#}"));
    let m3 = next_machine(&kr, &sid, &mut last, "the third machine");
    let (code, body) = kdo(&h, &m3, "GET", "/m/snapshot", "");
    assert!(
        code == 200 && body == tarball,
        "the third machine's snapshot: {code}"
    );
}

/// a restoring line whose first machine never gets past boot is paused like any other machine that never booted, and
/// the next start restores the archived snapshot again: the pause kept the machine ("kept, not killed: no snapshot",
/// because the archived snapshot is none of the line's machines'), the minute's tidy dropped the archive's copy, and a
/// later machine was pointed at the first one, which has no snapshot
#[test]
fn a_restoring_line_whose_first_machine_never_boots_restores_the_archive_again() {
    let kr = kernel_rig();
    let old = kernel_start(&kr, "to restore");
    let h = kr.machine_handler();
    let mut last = String::new();
    let m0 = next_machine(&kr, &old, &mut last, "the machine");
    booted(&kr, &m0);
    let (tarball, want) = leave_snapshot(&kr, &m0);
    kr.destroy(&old).unwrap_or_else(|e| panic!("{e:#}"));
    wait_for("the record", || {
        kr.record(&old).is_some_and(|r| r.archive.is_some())
    });
    let nsid = kr
        .restore_record(&old, "")
        .unwrap_or_else(|e| panic!("{e:#}"));
    sign_approval(&kr, &approval_of(&kr, &nsid));
    let restores = |m: &FakeMachine, who: &str| {
        let (code, body) = kdo(&h, m, "GET", "/m/snapshot", "");
        assert!(
            code == 200 && body == tarball,
            "{who}: the archived snapshot: {code}"
        );
    };
    let mut last = String::new();
    let m1 = next_machine(&kr, &nsid, &mut last, "the restoring machine");
    restores(&m1, "the first machine");
    // it never gets past boot (say its restore ran out of disk): the pause kills it into a source that names the
    // archived snapshot still, and the archive's copy stays for the next start
    pause_line(&kr, &nsid);
    assert_eq!(
        kr.k.fly
            .machine(&m1.id)
            .map(|m| m.state)
            .unwrap_or_default(),
        "destroyed",
        "the machine that never booted is still there"
    );
    let ks = kernel_session(&kr, &nsid);
    let sc = peek_cert(
        ks.kernel
            .clone()
            .and_then(|k| k.source_cert)
            .as_ref()
            .unwrap_or_else(|| panic!("no source")),
    )
    .unwrap_or_else(|e| panic!("{e}"));
    assert!(
        sc.pred.0 == format!("fly-{}", m1.id)
            && snapshot_of(&sc) == want
            && ks.no_snapshot.is_empty(),
        "the source after the machine that never booted: {sc:?} {:?}",
        ks.no_snapshot
    );
    kr.tidy_restores();
    kr.resume(&nsid, false).unwrap_or_else(|e| panic!("{e:#}"));
    let m2 = next_machine(&kr, &nsid, &mut last, "the second machine");
    restores(&m2, "the second machine");
    // and again; then one that boots: the archive's copy goes and the record notes the restore
    pause_line(&kr, &nsid);
    kr.tidy_restores();
    kr.resume(&nsid, false).unwrap_or_else(|e| panic!("{e:#}"));
    let m3 = next_machine(&kr, &nsid, &mut last, "the third machine");
    restores(&m3, "the third machine");
    let (code, body) = kdo(&h, &m3, "POST", "/m/pull-secrets", "{}");
    assert_eq!(code, 200, "{}", String::from_utf8_lossy(&body));
    kr.tidy_restores();
    assert!(
        kr.snap(&crate::restore::restore_snap(&nsid)).is_some(),
        "the archive's copy went before the line's first boot"
    );
    booted(&kr, &m3);
    kr.tidy_restores();
    assert!(
        kr.snap(&crate::restore::restore_snap(&nsid)).is_none(),
        "the archive's copy stayed after the line booted"
    );
    let rec = kr.record(&old).unwrap_or_else(|| panic!("no record"));
    assert!(
        rec.restored.len() == 1 && rec.restored[0].session == nsid,
        "restored {:?}",
        rec.restored
    );
}

/// a spawn waits while its machine comes up, and stops at once when the spawner reports it destroyed (a fabric sandbox
/// whose start failed at hermit kept its session booting for 10 minutes, 2026-11-17)
#[test]
fn init_waits() {
    use crate::kernel::KernelError;
    use crate::kernelline::{REASON_AWS, REASON_FLY, REASON_NOT_STARTED};
    let ke = |reason: &str, msg: &str| -> anyhow::Error {
        KernelError {
            role: "spawner".into(),
            status: 409,
            msg: msg.into(),
            reason: reason.into(),
        }
        .into()
    };
    for (err, want) in [
        (
            ke(REASON_NOT_STARTED, "machine x1 is created, not started"),
            true,
        ),
        (ke(REASON_NOT_STARTED, "fabric init: not yet"), true),
        (ke(REASON_FLY, "fly inspect: EOF"), true),
        (ke(REASON_AWS, "aws: throttled"), true),
        (
            ke(
                REASON_NOT_STARTED,
                "machine x01a1ea606c96728a98f97c5978594fa2 is destroyed, not started",
            ),
            false,
        ),
        (
            ke("wrong-image", "machine x1 runs a, not its source's b"),
            false,
        ),
        (anyhow::anyhow!("connection refused"), false),
    ] {
        assert_eq!(crate::kernelline::init_waits(&err), want, "{err:#}");
    }
}

// ---- a kernel line running on its first machine (booted, its secrets pulled), the router reading the fake Fly
// (lostmachine_test.go's lostRig)

fn lost_fly_events(_: &str) -> anyhow::Result<Vec<crate::lifecycle::FlyEvent>> {
    let t = 1_792_661_400_000; // 2026-10-22 09:30 UTC
    Ok(vec![
        crate::lifecycle::FlyEvent {
            kind: "launch".into(),
            status: "created".into(),
            timestamp: t - 1000,
            ..Default::default()
        },
        crate::lifecycle::FlyEvent {
            kind: "exit".into(),
            status: "stopped".into(),
            source: "user".into(),
            timestamp: t,
            request: Some(crate::lifecycle::FlyEventRequest {
                exit_event: Some(Default::default()),
            }),
        },
    ])
}

fn no_fly_logs(_: &str, _: &str) -> anyhow::Result<(Vec<crate::lifecycle::FlyLogLine>, String)> {
    Ok((vec![], String::new()))
}

pub fn lost_rig() -> (KRig, String, FakeMachine) {
    let kr = kernel_rig();
    // Fly lists a destroyed machine for a while; gone is the harder case
    *FLY.write().unwrap_or_else(|e| e.into_inner()) = Some((kr.k.fly.clone(), false));
    {
        let mut h = kr.lc.hooks.write().unwrap_or_else(|e| e.into_inner());
        h.fly_events = lost_fly_events;
        h.fly_logs = no_fly_logs;
    }
    let sid = kernel_start(&kr, "lost one");
    wait_machine(&kr, &sid);
    let m1 =
        kr.k.fly
            .machine(&kernel_session(&kr, &sid).machine_id)
            .unwrap_or_else(|| panic!("no machine"));
    let h = kr.machine_handler();
    let (code, body) = kdo(&h, &m1, "POST", "/m/pull-secrets", "{}");
    assert_eq!(code, 200, "{}", String::from_utf8_lossy(&body));
    booted(&kr, &m1);
    let s = kernel_session(&kr, &sid);
    assert!(
        s.state == "started" && s.booted == m1.id,
        "{} {}",
        s.state,
        s.booted
    );
    (kr, sid, m1)
}

/// ✱ a pause that needs the machine's state (required) with no snapshot signed by the machine's key: the router doesn't
/// ask for the kill and the machine stays; ✱ a volume Fly won't delete yet: the kill goes through, the router keeps the
/// volume on the machine's record and kills it again until the spawner answers it gone
#[test]
fn a_kernel_kill_keeps_what_it_must() {
    let (kr, sid, m1) = lost_rig();
    let e = kr
        .kernel_kill(&sid, &m1.id, true, false)
        .err()
        .map(|e| format!("{e:#}"))
        .unwrap_or_default();
    assert!(e.contains("kept, not killed"), "{e}");
    assert_eq!(
        kr.k.fly
            .machine(&m1.id)
            .map(|m| m.state)
            .unwrap_or_default(),
        "started",
        "the machine was killed"
    );
    kr.k.fly.st().stuck_volumes = true;
    kr.kernel_kill(&sid, &m1.id, false, false)
        .unwrap_or_else(|e| panic!("{e:#}"));
    let left = || {
        kr.st.do_(|d| {
            d.started
                .get(&m1.id)
                .map(|s| s.kernel_volume_left.clone())
                .unwrap_or_default()
        })
    };
    assert!(
        kr.k.fly
            .machine(&m1.id)
            .is_some_and(|m| m.state == "destroyed")
            && left() == m1.volume,
        "volume left {:?}",
        left()
    );
    kr.kernel_volumes_tick(); // still stuck
    assert_eq!(left(), m1.volume, "the volume was forgotten");
    kr.k.fly.st().stuck_volumes = false;
    kr.kernel_volumes_tick();
    assert!(
        left().is_empty() && !kr.k.fly.volumes().contains(&m1.volume),
        "volume left {:?}, Fly's {:?}",
        left(),
        kr.k.fly.volumes()
    );
}

/// a kernel kill that fails on the way (Fly reset one request) is tried again like a core kill, and gives up after
/// as many tries
#[test]
fn a_kernel_kill_that_fails_on_the_way_is_tried_again() {
    use std::sync::atomic::Ordering;
    let tries = crate::flows::KILL_TRANSIENT_TRIES.load(Ordering::Relaxed) as usize;
    let step = crate::flows::KILL_TRANSIENT_STEP_MS.swap(1, Ordering::Relaxed);
    {
        let (kr, sid, m1) = lost_rig();
        *kr.k.fail_posts.lock().unwrap_or_else(|e| e.into_inner()) = ("/kill".into(), tries);
        kr.kernel_kill(&sid, &m1.id, false, false)
            .unwrap_or_else(|e| panic!("{e:#}"));
        let left = kr.k.fail_posts.lock().unwrap_or_else(|e| e.into_inner()).1;
        assert!(
            left == 0
                && kr
                    .k
                    .fly
                    .machine(&m1.id)
                    .is_some_and(|m| m.state == "destroyed"),
            "{left} failures left"
        );
    }
    {
        let (kr, sid, m2) = lost_rig();
        *kr.k.fail_posts.lock().unwrap_or_else(|e| e.into_inner()) = ("/kill".into(), tries + 1);
        let e = kr
            .kernel_kill(&sid, &m2.id, false, false)
            .err()
            .map(|e| format!("{e:#}"))
            .unwrap_or_default();
        assert!(e.contains("HTTP 502"), "err {e}");
        let left = kr.k.fail_posts.lock().unwrap_or_else(|e| e.into_inner()).1;
        assert!(
            left == 0
                && kr
                    .k
                    .fly
                    .machine(&m2.id)
                    .is_some_and(|m| m.state != "destroyed"),
            "{left} failures left"
        );
    }
    crate::flows::KILL_TRANSIENT_STEP_MS.store(step, Ordering::Relaxed);
}
