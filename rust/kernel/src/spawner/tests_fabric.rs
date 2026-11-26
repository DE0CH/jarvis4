//! the fabric runner against a fake hermit

use super::super::aws::KEYS_MARK;
use super::super::fabric::{
    FABRIC_REPO, FabricApi, FabricCredentials, FabricInput, Sandbox, fabric_machine_id,
    fabric_sandbox_id, fabric_state,
};
use super::super::{
    INFO_FABRIC, REASON_FABRIC, REASON_FABRIC_BUSY, REASON_NO_FABRIC_KEY, REASON_NOT_DESTROYED,
    REASON_NOT_STARTED, REASON_WRONG_IMAGE, SESSION_REPO, SpawnInput, object, runner_of,
};
use super::{Rig, id_of, kill_cert, open_spawner, reason, rig};
use crate::kt::{TestServer, source, source_content};
use jarvis_doc::perm::{Pair, Set};
use jarvis_doc::{Kind, Object, by, open_cert, peek_cert};
use jarvis_nethttp::{Req, W};
use jarvis_sig::{Doc, Signer};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

fn fabric_img() -> String {
    format!("{FABRIC_REPO}@sha256:{}", "c".repeat(64))
}

const CID_A: &str = "0190f6c2-4a0d-7b2c-8e1f-0a1b2c3d4e5f";
const CID_B: &str = "0190f6c2-4a0d-7b2c-8e1f-0a1b2c3d4e60";

#[derive(Clone, Default)]
struct FakeSbx {
    id: String,
    state: String,
    phase: String,
    console: String,
}

/// the routes of hermit's contract the fabric runner calls (aviary docs/CONTRACTS.md), one sandbox per conversation,
/// with the callers' tokens and headers checked as hermit's guard checks them
#[derive(Default)]
struct HermitState {
    n: usize,
    by_cid: BTreeMap<String, FakeSbx>,
    calls: Vec<String>,
    /// what hermit says it started the sandbox on
    image: String,
}

#[derive(Default)]
struct FakeHermit(Mutex<HermitState>);

impl FakeHermit {
    fn st(&self) -> std::sync::MutexGuard<'_, HermitState> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
    fn sandbox(&self, cid: &str) -> FakeSbx {
        self.st().by_cid.get(cid).cloned().unwrap_or_default()
    }
    fn set(&self, cid: &str, f: impl FnOnce(&mut FakeSbx)) {
        if let Some(s) = self.st().by_cid.get_mut(cid) {
            f(s)
        }
    }

    fn serve(&self, w: &mut W, r: &mut Req) {
        let mut h = self.st();
        h.calls.push(format!("{} {}", r.method, r.path));
        let fail = |w: &mut W, code: u16, c: &str| {
            w.write_header(code);
            w.write_str(&json!({"code": c, "message": c}).to_string());
        };
        if r.header("Aviary-Protocol") != "hermit-core=1" {
            return fail(w, 400, "unsupported_protocol");
        }
        let admin = r.path.starts_with("/v1/admin/");
        let tok = r.header("Authorization");
        if (admin && (tok != "Bearer admin-token" || r.header("Aviary-Admin") != "ops@example.org"))
            || (!admin && tok != "Bearer magpie-token")
        {
            return fail(w, 403, "wrong_caller");
        }
        let image = h.image.clone();
        let obj = |s: &FakeSbx| {
            let phase = if s.phase.is_empty() {
                Value::Null
            } else {
                json!(s.phase)
            };
            json!({"id": s.id, "state": s.state, "phase": phase, "image": image, "busy": false})
                .to_string()
        };
        let parts: Vec<String> = r
            .path
            .trim_matches('/')
            .split('/')
            .map(String::from)
            .collect();
        if parts.len() == 4 && parts[1] == "conversations" && parts[3] == "sandbox" {
            let cid = parts[2].clone();
            match r.method.as_str() {
                "PUT" => {
                    let body: Value =
                        serde_json::from_slice(&r.read_body(1 << 20)).unwrap_or_default();
                    if body["person"] != "deyao@example.org" {
                        return fail(w, 403, "not_allowed");
                    }
                    if h.by_cid.get(&cid).is_none_or(|s| s.state == "gone") {
                        h.n += 1;
                        let s = FakeSbx {
                            id: format!("0190f6c2-5b1e-7a3c-9d4e-{}{}", "0".repeat(11), h.n),
                            state: "starting".into(),
                            phase: "capacity".into(),
                            console: String::new(),
                        };
                        h.by_cid.insert(cid.clone(), s);
                    }
                    w.write_header(202);
                    w.write_str(&obj(&h.by_cid[&cid]));
                }
                "GET" => match h.by_cid.get(&cid) {
                    None => fail(w, 404, "no_sandbox"),
                    Some(s) => {
                        w.write_str(&obj(s));
                    }
                },
                _ => {}
            }
        } else if parts.len() == 5 && parts[1] == "admin" && parts[2] == "sandboxes" {
            let Some(s) = h.by_cid.values_mut().find(|x| x.id == parts[3]) else {
                return fail(w, 404, "not_found");
            };
            match (parts[4].as_str(), r.method.as_str()) {
                ("log", "GET") => {
                    if s.console.is_empty() {
                        return fail(w, 404, "not_found");
                    }
                    w.write_str(
                        &json!({"sandboxId": s.id, "reason": "live", "text": s.console})
                            .to_string(),
                    );
                }
                ("release", "POST") => {
                    if s.state == "gone" {
                        return fail(w, 409, "sandbox_gone");
                    }
                    s.state = "releasing".into();
                    s.phase = String::new();
                    w.write_str(&json!({"released": 1}).to_string());
                }
                _ => {}
            }
        } else {
            fail(w, 404, "not_found")
        }
    }
}

struct FabricRig {
    r: Rig,
    h: Arc<FakeHermit>,
    api: Arc<FabricApi>,
    _srv: TestServer,
}

fn fabric_env() -> BTreeMap<String, String> {
    BTreeMap::from([(
        "JARVIS2_URL".to_string(),
        "http://10.202.1.1:3128".to_string(),
    )])
}

fn fabric_rig() -> FabricRig {
    let r = rig();
    let h = Arc::new(FakeHermit::default());
    h.st().image = fabric_img()
        .trim_start_matches(&format!("{FABRIC_REPO}@"))
        .to_string();
    let h2 = h.clone();
    let srv = TestServer::handler(move |w, req| h2.serve(w, req));
    let api = Arc::new(FabricApi::new(&srv.url));
    r.sp.set_fabric(api.clone(), fabric_env());
    FabricRig {
        r,
        h,
        api,
        _srv: srv,
    }
}

impl FabricRig {
    fn credentials(&self) {
        let b = serde_json::to_vec(&FabricCredentials {
            magpie_token: "magpie-token".into(),
            admin_token: "admin-token".into(),
            admin: "ops@example.org".into(),
            person: "deyao@example.org".into(),
        })
        .unwrap_or_default();
        let sealed = jarvis_sig::seal_to(
            &self.r.w.c["spawner"].identity.agreement_key,
            &b,
            INFO_FABRIC,
        )
        .unwrap_or_else(|e| panic!("{e}"));
        self.r
            .sp
            .set_fabric_credentials(&sealed)
            .unwrap_or_else(|e| panic!("{e:#}"));
    }

    /// a notarized new source with the fabric's image
    fn fabric_source(&self) -> (Doc, Doc) {
        let mut src = source_content("t");
        src.image = fabric_img();
        let cert = self.r.w.cert(
            by::IPHONE,
            "sink",
            &source(),
            &Pair::new(Set::only(["store:a"]), vec![]),
            Some(src),
            None,
        );
        let nz = self.r.notarize(&cert);
        (cert, nz)
    }

    fn fabric_input(&self, cid: &str) -> SpawnInput {
        let (cert, nz) = self.fabric_source();
        let mut i = self.r.input(&cert, &nz);
        i.runner = "fabric".into();
        i.fabric = Some(FabricInput {
            conversation: cid.into(),
        });
        i
    }
}

/// A machine on the fabric from its spawn to its kill: hermit's sandbox is the machine, its console carries the keys,
/// its forced release is the kill, and the session's conversation never gets a second machine while one lives.
#[test]
fn fabric_spawn_init_kill() {
    let f = fabric_rig();
    let sp = &f.r.sp;
    let r0 = sp.spawn(&f.fabric_input(CID_A));
    assert_eq!(
        reason(&r0),
        REASON_NO_FABRIC_KEY,
        "a spawn before the credentials: {:?}",
        r0.err()
    );
    f.credentials();
    let out = sp
        .spawn(&f.fabric_input(CID_A))
        .unwrap_or_else(|e| panic!("{e:#}"));
    let id = id_of(&out);
    assert!(
        id == "x0190f6c25b1e7a3c9d4e000000000001"
            && runner_of(&id) == "fabric"
            && object(&id) == Object(format!("fabric-{id}"))
            && object(&id).kind() == Some(Kind::Machine),
        "machine id {id}"
    );
    assert_eq!(out["volume"], "", "a fabric machine has no volume");
    // the env the machine must get, for the router to serve: its source, the roster, the root key, the router's address
    let env = &out["env"];
    assert!(
        env["JARVIS2_SOURCE"] == out["source"]
            && env["JARVIS2_KERNEL_ROOT"]
                .as_str()
                .is_some_and(|s| !s.is_empty())
            && env["JARVIS2_KERNEL_ROSTER"]
                .as_str()
                .is_some_and(|s| !s.is_empty())
            && env["JARVIS2_URL"] == "http://10.202.1.1:3128",
        "env {env}"
    );
    // a new source on a live conversation's sandbox is refused
    assert!(
        sp.spawn(&f.fabric_input(CID_A)).is_err(),
        "a new source on a live conversation's sandbox was taken"
    );
    // the same spawn again (its answer was lost): the same machine, nothing new at hermit
    let nin = f.fabric_input(CID_B);
    let first = sp.spawn(&nin).unwrap_or_else(|e| panic!("{e:#}"));
    let again = sp.spawn(&nin).unwrap_or_else(|e| panic!("{e:#}"));
    assert_eq!(id_of(&again), id_of(&first), "a repeated spawn");
    // nothing went to Fly
    assert!(
        f.r.fly.st().ms.is_empty() && f.r.fly.st().vols.is_empty(),
        "a fabric spawn reached Fly"
    );
    // being placed: not started; created on a host with its first process running (hermit's phase supervisor): up
    let r1 = sp.init(&id);
    assert_eq!(
        reason(&r1),
        REASON_NOT_STARTED,
        "init while hermit places it: {:?}",
        r1.err()
    );
    f.h.set(CID_A, |s| s.phase = "supervisor".into());
    let r2 = sp.init(&id);
    assert_eq!(
        reason(&r2),
        REASON_NOT_STARTED,
        "init before the keys line: {:?}",
        r2.err()
    );
    let (mk, me) = (Signer::generate(), Signer::generate());
    let keys = format!(
        r#"{{"encryptionKey":"{}","signingKey":"{}"}}"#,
        me.public_key(),
        mk.public_key()
    );
    f.h.set(CID_A, |s| {
        s.console = format!(
            "boot\n{KEYS_MARK}{{\"encryptionKey\":\"old\",\"signingKey\":\"old\"}}\nmore\n\n{KEYS_MARK}{keys}\n"
        )
    });
    let d = sp.init(&id).unwrap_or_else(|e| panic!("{e:#}"));
    let c = peek_cert(&d).unwrap_or_else(|e| panic!("{e}"));
    let m = c
        .machine
        .as_ref()
        .unwrap_or_else(|| panic!("no machine in {c:?}"));
    assert!(
        c.succ == Object(format!("fabric-{id}"))
            && m.image == fabric_img()
            && m.signing_key == mk.public_key()
            && m.encryption_key == me.public_key(),
        "cert {c:?}"
    );
    // the conversation's sandbox is this machine: a second spawn on it is refused, another conversation's is not
    let r3 = sp.spawn(&f.fabric_input(CID_A));
    assert_eq!(
        reason(&r3),
        REASON_FABRIC_BUSY,
        "a second machine on the session's files: {:?}",
        r3.err()
    );
    // the kill: hermit's forced release of this sandbox; not destroyed until hermit says gone
    let r4 = sp.kill(&id, None);
    assert_eq!(
        reason(&r4),
        REASON_NOT_DESTROYED,
        "kill while hermit releases it: {:?}",
        r4.err()
    );
    assert_eq!(f.h.sandbox(CID_A).state, "releasing");
    f.h.set(CID_A, |s| s.state = "gone".into());
    let (kd, left) = kill_cert(sp.kill(&id, None));
    let kc = open_cert(&kd, &f.r.spawner_key()).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        kc.pred == Object(format!("fabric-{id}"))
            && kc.source.as_ref().is_some_and(|s| s.image == fabric_img())
            && left.is_empty(),
        "{kc:?} {left}"
    );
    f.r.notarize(&kd);
    // the session's next machine: the same conversation, a new sandbox, a new machine
    let out = sp
        .spawn(&f.fabric_input(CID_A))
        .unwrap_or_else(|e| panic!("{e:#}"));
    let id2 = id_of(&out);
    assert!(
        id2 != id && runner_of(&id2) == "fabric",
        "the next machine is {id2}"
    );
    // a restart keeps the machines and their conversations (a kill again answers the same cert; the tokens are sent
    // again, as the Fly token is)
    let sp2 = Arc::new(open_spawner(&f.r.w, &f.r.path, f.r.fly.clone()));
    sp2.set_fabric(f.api.clone(), fabric_env());
    let (again, _) = kill_cert(sp2.kill(&id, None));
    assert_eq!(again, kd, "a second kill signed another cert");
    let conv = sp2
        .lock()
        .machines
        .get(&id)
        .map(|m| m.conversation.clone())
        .unwrap_or_default();
    assert_eq!(conv, CID_A, "the machine's conversation after a restart");
}

/// What the fabric runner refuses: another runner's image, a spawn without its conversation, an image hermit did not
/// start; and a spawner without the runner never sends a fabric machine's call to Fly.
#[test]
fn fabric_refuses() {
    let f = fabric_rig();
    let sp = &f.r.sp;
    f.credentials();
    // the session image on the fabric, the fabric image on Fly
    let (cert, nz) = f.r.source();
    let mut i = f.r.input(&cert, &nz);
    i.runner = "fabric".into();
    i.fabric = Some(FabricInput {
        conversation: CID_A.into(),
    });
    let e = sp
        .spawn(&i)
        .err()
        .map(|e| format!("{e:#}"))
        .unwrap_or_default();
    assert!(
        e.contains(FABRIC_REPO),
        "the session image on the fabric: {e}"
    );
    let mut fi = f.fabric_input(CID_A);
    fi.runner = String::new();
    fi.fabric = None;
    let e = sp
        .spawn(&fi)
        .err()
        .map(|e| format!("{e:#}"))
        .unwrap_or_default();
    assert!(e.contains(SESSION_REPO), "the fabric image on Fly: {e}");
    for bad in [
        None,
        Some(""),
        Some("../admin"),
        Some(&*CID_A.to_uppercase()),
    ] {
        let mut i = f.fabric_input(CID_A);
        i.fabric = bad.map(|c| FabricInput {
            conversation: c.into(),
        });
        assert!(sp.spawn(&i).is_err(), "conversation {bad:?} taken");
    }
    assert!(
        f.h.st().calls.is_empty(),
        "a refused spawn reached hermit: {:?}",
        f.h.st().calls
    );
    // hermit started the sandbox on another image than the source's: no cert
    let out = sp
        .spawn(&f.fabric_input(CID_A))
        .unwrap_or_else(|e| panic!("{e:#}"));
    let id = id_of(&out);
    f.h.st().image = format!("sha256:{}", "d".repeat(64));
    f.h.set(CID_A, |s| {
        s.phase = "supervisor".into();
        s.console = format!(r#"{KEYS_MARK}{{"encryptionKey":"e","signingKey":"s"}}"#);
    });
    let r = sp.init(&id);
    assert_eq!(
        reason(&r),
        REASON_WRONG_IMAGE,
        "init on another image: {:?}",
        r.err()
    );
    // hermit down: a fabric refusal the router may retry, not a Fly one
    f.api.set_url("http://127.0.0.1:1");
    let r = sp.init(&id);
    assert_eq!(
        reason(&r),
        REASON_FABRIC,
        "init with hermit down: {:?}",
        r.err()
    );
    // a spawner without the fabric runner (an older Deployment's env) holds the machine but calls nothing for it
    let sp2 = open_spawner(&f.r.w, &f.r.path, f.r.fly.clone());
    let r = sp2.init(&id);
    assert_eq!(
        reason(&r),
        REASON_NO_FABRIC_KEY,
        "init on a spawner without the runner: {:?}",
        r.err()
    );
    assert!(
        f.r.fly.st().ms.is_empty(),
        "a fabric machine's call reached Fly"
    );
}

#[test]
fn fabric_ids() {
    let sid = "0190f6c2-5b1e-7a3c-9d4e-1f2a3b4c5d6e";
    let id = fabric_machine_id(sid);
    assert!(
        id == "x0190f6c25b1e7a3c9d4e1f2a3b4c5d6e"
            && fabric_sandbox_id(&id) == sid
            && fabric_sandbox_id("0190f6c25b1e7a3c9d4e1f2a3b4c5d6e").is_empty(),
        "{id} {}",
        fabric_sandbox_id(&id)
    );
    for (id, want) in [
        (id.as_str(), "fabric"),
        ("i-0abc1234def567890", "aws"),
        ("0190f6c25b1e7a", "fly"),
        ("0190f6c25b1e7a3c9d4e1f2a3b4c5d6e", "fly"),
    ] {
        assert_eq!(runner_of(id), want, "{id}");
    }
    let o = Object(format!("fabric-{id}"));
    assert!(
        o.kind() == Some(Kind::Machine) && o.runner() == Some("fabric") && o.machine_id() == id
    );
    assert!(
        Object("fabric-0190f6c25b1e7a3c9d4e1f2a3b4c5d6e".into())
            .kind()
            .is_none(),
        "a fabric object without the x"
    );
    for ((state, phase), want) in [
        (("starting", "capacity"), "created"),
        (("starting", "creating"), "created"),
        (("starting", "supervisor"), "started"),
        (("ready", ""), "started"),
        (("releasing", ""), "destroying"),
        (("gone", ""), "destroyed"),
    ] {
        let s = Sandbox {
            state: state.into(),
            phase: phase.into(),
            ..Default::default()
        };
        assert_eq!(fabric_state(&s), want, "{state} {phase}");
    }
}
