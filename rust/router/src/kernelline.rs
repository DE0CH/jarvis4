//! A session line on the kernel (DESIGN "Target design", docs/PLAN-grants.md §3, §5): its lifecycles as the router
//! runs them, each step a cert the notarizer checked and the grant moved along it.
//!
//! ```text
//! new session  the phone signs (sink, source-x, P), P = the line's stores and session:<id>; notarized; the root's ⊤
//!              on the sink moves along it (→ P on source-x); then a spawn
//! spawn        the spawner starts a machine from the line's source and signs (source, fly-M, ⊤) once it gave its
//!              keys; notarized; the grant moves onto M (its keys)
//! pause        the machine's final snapshot (as for a core line); the spawner kills it and signs (fly-M, source-y,
//!              ⊤), source-y holding the snapshot's hash; notarized; the grant moves onto source-y
//! resume       a spawn from source-y
//! destroy      after the archive, (source-y, sink) by the gullible signer, notarized: the source ends
//! ```
//!
//! The old core's lines go on beside these (D7): a session is the kernel's when Session.kernel is set, and every
//! lifecycle of it goes here.

use crate::core::{CoreError, Doc};
use crate::http::{Registrar, write_err};
use crate::inbox::Origin;
use crate::kernel::{KernelError, kernel_error, other_copy};
use crate::lifecycle::LcHandle;
use crate::nethttp::{Req, W, write_json};
use crate::router::Router;
use crate::state::{Approval, Session, Started};
use crate::types::Volume;
use crate::util::OnceFn;
use anyhow::{Result, anyhow};
use jarvis_doc::gv::Signed;
use jarvis_doc::perm::{Pair, Set};
use jarvis_doc::{Cert, Kind, Object, SINK};
use jarvis_go::GoTime;
use jarvis_sig::Doc as SDoc;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

/// where a kernel line is, as documents
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct KernelLine {
    /// the source the line rests in, or its machine came from
    pub source: Option<Object>,
    /// the cert into it
    #[serde(rename = "sourceCert")]
    pub source_cert: Option<SDoc>,
    /// and its notarization
    #[serde(rename = "sourceNotarized")]
    pub source_nz: Option<SDoc>,
    /// the main grant: on the source, or on the machine
    pub grant: Option<Signed>,
    /// (source, fly-M, ⊤) while a machine runs
    #[serde(rename = "machineCert", skip_serializing_if = "Option::is_none")]
    pub machine_cert: Option<SDoc>,
    /// and its notarization
    #[serde(rename = "machineNotarized", skip_serializing_if = "Option::is_none")]
    pub machine_nz: Option<SDoc>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub burned: bool,
}

impl KernelLine {
    /// the source as Go writes it: "" when there is none
    pub fn source_name(&self) -> &str {
        self.source.as_ref().map_or("", |o| o.0.as_str())
    }
}

/// the Inbox approval whose answer is the phone's signature over a cert into a new source
pub const KERNEL_APPROVAL_KIND: &str = "kernel-source";
/// an add-store on a kernel line: the phone signs two certs under one Face ID, the cert into a new source holding the
/// store (sink → source-a, P_add = the store for the session) and the cert from it onto the running machine
/// (source-a → fly-M, ⊤); the answer is the two signatures, one per line, in that order
pub const KERNEL_ADD_APPROVAL_KIND: &str = "kernel-add-store";

// the spawner's and the notarizer's reasons (kernel/spawner/spawner.go, kernel/notarizer/notarizer.go)
pub const REASON_NO_FLY_TOKEN: &str = "no-fly-token";
pub const REASON_FLY: &str = "fly";
pub const REASON_NO_AWS_KEY: &str = "no-aws-key";
pub const REASON_AWS: &str = "aws";
pub const REASON_HOST_FULL: &str = "host-full";
pub const REASON_UNKNOWN: &str = "unknown-machine";
pub const REASON_NOT_STARTED: &str = "not-started";
pub const REASON_NOT_DESTROYED: &str = "not-destroyed";
pub const REASON_DEFINED: &str = "already-defined";
/// a kernel machine's Fly metadata naming its source (kernel/spawner SourceMeta)
pub const SOURCE_META: &str = "jarvis4_source";

/// how long a spawn waits for its machine's keys, and how often it asks
pub const KERNEL_INIT_MAX: Duration = Duration::from_secs(10 * 60);
pub const KERNEL_INIT_STEP: Duration = Duration::from_secs(2);
/// how many spawns a start makes (each a new volume: one on a full host is deleted by the spawner)
pub const KERNEL_SPAWN_TRIES: u32 = 3;
/// the wait between kills while Fly isn't done destroying
pub const KERNEL_KILL_STEP: Duration = Duration::from_secs(5);

fn reason_of(e: &anyhow::Error) -> Option<&KernelError> {
    kernel_error(e)
}

fn new_source() -> Object {
    Object(format!(
        "source-{}",
        hex::encode(crate::util::rand_bytes(16))
    ))
}

fn sink() -> Object {
    Object(SINK.into())
}

fn peek(d: &SDoc) -> Option<Cert> {
    jarvis_doc::peek_cert(d).ok()
}

/// a source's settings, the guard's to read (rust/machine/src/kernelboot.rs): the harness, the permission mode (fixed
/// for the line's life, D3) and the session's config as the old core's cert carried it
pub fn kernel_settings(s: &Session, config: &str) -> Result<String> {
    let cfg: Value = if config.is_empty() {
        json!({})
    } else {
        serde_json::from_str(config)?
    };
    Ok(jarvis_go::marshal(
        &json!({"v": 1, "harness": s.harness, "permissionMode": crate::flows::norm_mode(&s.permission_mode), "config": cfg}),
    ))
}

/// what a line's grant allows: its stores, for its session
pub fn kernel_pair(s: &Session) -> Pair {
    let allowed: Vec<String> = s
        .stores
        .iter()
        .flatten()
        .map(|st| format!("store:{st}"))
        .collect();
    Pair::new(Set::only(allowed), vec![format!("session:{}", s.id)])
}

fn cert_payload(c: &Cert) -> Result<String> {
    c.check().map_err(|e| anyhow!("{e}"))?;
    jarvis_sig::go_json(c).map_err(|e| anyhow!("{e}"))
}

/// a kernel line's machine as the kernel names it, "<runner>-<id>" (kernel/doc Object; the machine checks the same
/// name, rust/machine/src/main.rs machine_object): the spawner's cert onto it when that names it, else by the
/// session's runner (fallback: the router's default, for a session from before runners were recorded)
pub fn kernel_object(s: Option<&Session>, machine: &str, fallback: &str) -> Object {
    if let Some(o) = s
        .and_then(|s| s.kernel.as_ref())
        .and_then(|l| l.machine_cert.as_ref())
        .map(must_succ)
        .filter(|o| o.kind() == Some(Kind::Machine) && o.machine_id() == machine)
    {
        return o;
    }
    let mut runner = fallback.to_string();
    if let Some(s) = s.filter(|s| crate::awsrunner::valid_runner(&s.runner)) {
        runner = s.runner.clone();
    }
    match runner.as_str() {
        "aws" => Object(format!("aws-{machine}")),
        "fabric" => Object(format!("fabric-{machine}")),
        _ => Object(format!("fly-{machine}")),
    }
}

pub fn must_succ(d: &SDoc) -> Object {
    peek(d)
        .map(|c| c.succ)
        .unwrap_or_else(|| Object(String::new()))
}

/// where a machine runs, by its id (an EC2 instance's is i-…)
pub fn runner_name(machine: &str) -> &'static str {
    if crate::awsrunner::is_aws_machine(machine) {
        "AWS"
    } else {
        "Fly"
    }
}

/// whether a spawn goes on waiting for its machine's keys after the spawner's answer err. It waits while the machine is
/// still coming up (not started yet, or its runner briefly unreachable); a machine the spawner reports destroyed never
/// starts, so the start fails at once with why (a fabric sandbox whose start failed at hermit left its session
/// "booting" for the whole 10 minutes, 2026-11-17). The spawner says it as "machine X is destroyed, not started" under
/// REASON_NOT_STARTED (kernel/spawner/spawner.go Init).
pub fn init_waits(err: &anyhow::Error) -> bool {
    let Some(ke) = reason_of(err) else {
        return false;
    };
    match ke.reason.as_str() {
        REASON_NOT_STARTED => !ke.msg.contains(" is destroyed, not started"),
        REASON_FLY | REASON_AWS => true,
        _ => false,
    }
}

impl Session {
    /// the session has a certified line: a core cert, or a kernel source the phone signed
    pub fn has_line(&self) -> bool {
        self.cert.is_some()
            || self
                .kernel
                .as_ref()
                .is_some_and(|k| k.source_cert.is_some())
    }
}

impl Router {
    fn kernel_client(&self) -> Result<&Arc<crate::kernel::KernelClient>> {
        self.kernel
            .as_ref()
            .ok_or_else(|| anyhow!("this box runs no kernel"))
    }

    /// new sessions start on the kernel (it is reachable and the root's grant is here)
    pub fn kernel_serves(&self) -> bool {
        self.kernel.is_some() && self.st.do_(|d| d.kernel_root.is_some())
    }

    /// the cert the phone signs for a new source of the line (sink → source) with this image and snapshot ("" = none)
    pub fn kernel_source_draft(
        &self,
        s: &Session,
        config: &str,
        image: &str,
        snapshot: &str,
    ) -> Result<SDoc> {
        let settings = kernel_settings(s, config)?;
        let c = Cert {
            kind: "succession".into(),
            pred: sink(),
            succ: new_source(),
            pair: kernel_pair(s),
            source: Some(jarvis_doc::Source {
                image: image.into(),
                settings: serde_json::value::RawValue::from_string(settings)?,
                snapshot: snapshot.into(),
            }),
            machine: None,
            signer: jarvis_doc::by::IPHONE.into(),
            issued_at: jarvis_doc::now(),
        };
        Ok(SDoc {
            payload: cert_payload(&c)?,
            sig: String::new(),
        })
    }

    /// the new session's Inbox approval (the phone signs the draft's payload)
    pub fn kernel_new_session_approval(
        self: &Arc<Self>,
        s: &Session,
        config: &str,
        opts: &BTreeMap<String, String>,
        input: &crate::flows::NewSession,
        snapshot: &str,
    ) -> Result<()> {
        let draft = self.kernel_source_draft(s, config, &self.source_image(s), snapshot)?;
        self.st.do_(|d| {
            if let Some(x) = d.sessions.get_mut(&s.id) {
                x.kernel = Some(KernelLine::default());
            }
        });
        let a = Approval {
            kind: KERNEL_APPROVAL_KIND.into(),
            session: s.id.clone(),
            label: s.label.clone(),
            challenge: Some(Doc {
                payload: draft.payload,
                sig: String::new(),
            }),
            options: opts.clone(),
            origin: input.origin.clone(),
            explanation: input.explanation.clone(),
            batch: input.batch.clone(),
            ..Default::default()
        };
        let r = self.clone();
        std::thread::spawn(move || {
            r.add_approval(a);
        });
        Ok(())
    }

    /// the phone's signature over the draft → the source, then a spawn
    pub fn respond_kernel(
        self: &Arc<Self>,
        a: &Approval,
        signature: &str,
    ) -> Result<(Doc, String)> {
        let k = self.kernel_client()?.clone();
        let cert = SDoc {
            payload: a
                .challenge
                .as_ref()
                .map(|c| c.payload.clone())
                .unwrap_or_default(),
            sig: signature.into(),
        };
        // the start is a job (jobs.rs "starting"): a replica that dies after the source is kept leaves it to another,
        // which spawns from the kept source (kernel_continue)
        let done = self.lock(&a.session, "starting")?;
        let res = (|| -> Result<(SDoc, Signed)> {
            let nz = k.notarize(&cert)?;
            let root = self
                .st
                .do_(|d| d.kernel_root.clone())
                .ok_or_else(|| anyhow!("the kernel has no root grant yet"))?;
            let g = k.move_(&root, &cert, &nz)?;
            Ok((nz, g))
        })();
        let (nz, g) = match res {
            Err(e) => {
                done.call();
                return Err(e);
            }
            Ok(x) => x,
        };
        let c = peek(&cert);
        let _ = self.kernel_burn(&a.session); // a resume on another image: the source it replaces ends (no-op for a new line)
        let nzd = Doc {
            payload: nz.payload.clone(),
            sig: nz.sig.clone(),
        };
        self.st.do_(|d| {
            d.approvals.remove(&a.id);
            if let Some(s) = d.sessions.get_mut(&a.session) {
                s.kernel = Some(KernelLine {
                    source: c.as_ref().map(|c| c.succ.clone()),
                    source_cert: Some(cert.clone()),
                    source_nz: Some(nz.clone()),
                    grant: Some(g.clone()),
                    ..Default::default()
                });
            }
            if let Some(o) = &a.origin {
                crate::outcomes::note_outcome(
                    d,
                    Some(o),
                    "new-session",
                    &a.session,
                    crate::outcomes::OUTCOME_APPROVED,
                    0,
                    Some(&nzd),
                );
            }
        });
        let (r, sid) = (self.clone(), a.session.clone());
        std::thread::spawn(move || {
            let _d = crate::flows::scopeguard(move || done.call());
            r.kernel_spawn(&sid);
        });
        Ok((nzd, a.session.clone()))
    }

    /// a machine from the line's source; the session runs on it once the grant is on it
    pub fn kernel_spawn(self: &Arc<Self>, sid: &str) {
        let s = self
            .st
            .do_(|d| d.sessions.get(sid).cloned())
            .unwrap_or_default();
        let op = self
            .lc_current(sid)
            .unwrap_or_else(|| self.lc_begin(sid, "boot"));
        op.set_handed();
        let fail = |msg: &str| {
            self.set_state(sid, "failed", msg);
            op.note("", msg);
            op.end_joined("failed", msg);
        };
        let Some(k) = self.kernel.clone() else {
            return fail("start: this box runs no kernel");
        };
        let l = match s.kernel.clone() {
            Some(l) if l.source_cert.is_some() && l.source_nz.is_some() && l.grant.is_some() => l,
            _ => return fail("start: the line has no source"),
        };
        let (Some(source_cert), Some(source_nz), Some(grant)) =
            (l.source_cert.clone(), l.source_nz.clone(), l.grant.clone())
        else {
            return fail("start: the line has no source");
        };
        let source = l.source.clone().unwrap_or_else(|| Object(String::new()));
        self.set_state(sid, "starting", "");
        // a source notarized before a flip: by a retired notarizer
        let nz_id = match k.signer_of("notarizer", &source_nz) {
            Err(e) => return fail(&format!("start: {e:#}")),
            Ok(id) => id,
        };
        let size = if s.size.is_empty() {
            "medium".to_string()
        } else {
            s.size.clone()
        };
        let gb = if s.disk_gb == 0 {
            crate::disk::DEFAULT_DISK
        } else {
            s.disk_gb
        };
        let runner = self.runner_of(&s);
        let region = self.spawn_region(&s);
        let mut wg = None;
        if runner == "aws" {
            match self.aws_spawn_wg(sid) {
                Err(e) => return fail(&format!("start: {e:#}")),
                Ok(w) => wg = Some(w),
            }
        }
        let mut fabric = None;
        if runner == "fabric" {
            match self.fabric_line(sid) {
                Err(e) => return fail(&format!("start: {e:#}")),
                Ok(f) => fabric = Some(f),
            }
        }
        let (mut id, mut vol) = (String::new(), String::new());
        if fabric.is_none() {
            // a fabric spawn asked again answers its machine (the spawner): nothing to look for
            (id, vol) = self.kernel_adopt(&op, &source);
        }
        let mut try_ = 1;
        while id.is_empty() {
            let mut input = json!({"cert": source_cert, "notarized": source_nz, "notarizer": nz_id, "region": region, "size": size, "diskGb": gb});
            if let Some(w) = &wg {
                // only an AWS spawn names its runner: a spawner from before the AWS runner refuses fields it doesn't know
                input["runner"] = json!(runner);
                input["wireguard"] = json!(w);
            }
            if let Some(f) = &fabric {
                input["runner"] = json!(runner);
                input["fabric"] = json!({"conversation": f.conversation});
            }
            op.note("", &format!("asked the kernel's spawner to start a machine from {} ({size}, {runner} {region})", source.0));
            match k.doc("spawner", "/spawn", &input) {
                Ok(d) => {
                    #[derive(Deserialize, Default)]
                    #[serde(default)]
                    struct Created {
                        id: String,
                        volume: String,
                        env: BTreeMap<String, String>,
                    }
                    let created: Created =
                        jarvis_go::unmarshal(d.payload.as_bytes()).unwrap_or_default();
                    id = created.id.clone();
                    vol = created.volume;
                    if fabric.is_some() {
                        self.set_fabric_machine(sid, &created.id, created.env);
                    }
                    break;
                }
                Err(e) => {
                    let ke = reason_of(&e).cloned();
                    let reason = ke.as_ref().map(|k| k.reason.as_str()).unwrap_or("");
                    let dm_once = |text: &str| {
                        if self
                            .kernel_token_dmed
                            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                            .is_ok()
                        {
                            self.dm(text);
                        }
                    };
                    if reason == REASON_NO_AWS_KEY {
                        dm_once(
                            "🔴 Jarvis 4 needs you — the kernel's spawner has no AWS key (it restarted), so no AWS session starts. Settings → Kernel → Recover gives it the key again (or the setup session: infra/setup.py kernel-aws-credentials).",
                        );
                    }
                    if reason == REASON_NO_FLY_TOKEN {
                        // a restarted spawner: its token comes again with the app's Recover of the kernel, or from the
                        // setup session
                        dm_once(
                            "🔴 Jarvis 4 needs you — the kernel's spawner has no Fly token (it restarted), so no kernel session starts. Settings → Kernel → Recover gives it the token again (or the setup session: infra/setup.py kernel-fly-token).",
                        );
                    }
                    // Fly's host for the volume was full (the spawner deleted that volume: a new spawn is a new volume,
                    // on another host), Fly failed, or the answer was lost (the machine it made, if any, is found and
                    // adopted or destroyed). Fly's org machine limit is known, not a hiccup (Deyao, 2026-11-17): said
                    // at once in its own words, no retries; a wakeup's firing marks its run missed and Run now delivers
                    // it once a machine is free (schedule.rs)
                    if crate::flows::fly_machine_limit(&e) {
                        crate::logf!("[kernel] spawn for {sid}: {e:#}");
                        return fail(&format!("start: {}", crate::flows::FLY_LIMIT_TEXT));
                    }
                    let again = ke.is_none()
                        || matches!(reason, REASON_HOST_FULL | REASON_FLY | REASON_AWS);
                    if !again || try_ >= KERNEL_SPAWN_TRIES {
                        return fail(&format!("start: {e:#}"));
                    }
                    op.note(
                        "",
                        &format!(
                            "the spawn failed ({e:#}): try {} of {KERNEL_SPAWN_TRIES}",
                            try_ + 1
                        ),
                    );
                    std::thread::sleep(KERNEL_INIT_STEP);
                    (id, vol) = self.kernel_adopt(&op, &source);
                }
            }
            try_ += 1;
        }
        op.machine(&id);
        let spawned = Instant::now();
        if crate::awsrunner::is_aws_machine(&id) {
            op.note(&id, &format!("the spawner launched EC2 instance {id} ({region}); waiting for its keys (the machine writes them to the instance's serial console once the session image runs)"));
        } else {
            op.note(
                &id,
                &format!("the spawner made Fly machine {id}; waiting for its keys"),
            );
        }
        let pred = peek(&source_cert)
            .map(|sc| self.kernel_pred(&s, &sc))
            .unwrap_or_default();
        self.st.do_(|d| {
            d.machines.insert(id.clone(), sid.to_string());
            let mut st = Started {
                id: id.clone(),
                kernel_pred: pred.clone(),
                volume: Some(Volume {
                    id: vol.clone(),
                    size_gb: gb,
                    path: "/data".into(),
                }),
                ..Default::default()
            };
            if wg.is_some()
                && let Some(x) = d.sessions.get_mut(sid)
                && let Some(w) = x.wg.take()
            {
                // the gateways list it from now on; the private key stays only in the instance
                st.wg = Some(crate::awsrunner::AwsWg {
                    private_key: String::new(),
                    public_key: w.public_key,
                    address: w.address,
                });
            }
            d.started.insert(id.clone(), st);
        });
        let end = Instant::now() + KERNEL_INIT_MAX;
        let mcert = loop {
            match k.doc("spawner", "/init", &json!({"id": id})) {
                Ok(c) => {
                    op.note(
                        &id,
                        &format!(
                            "the spawner has the machine's keys and its cert ({:.0} s after the spawn)",
                            spawned.elapsed().as_secs_f64()
                        ),
                    );
                    break c;
                }
                Err(e) => {
                    if !init_waits(&e) || Instant::now() > end {
                        let _ = self.kernel_kill_up(&id, None);
                        return fail(&format!("start: {e:#}"));
                    }
                    std::thread::sleep(KERNEL_INIT_STEP);
                }
            }
        };
        let res = (|| -> Result<()> {
            let mnz = k.notarize(&mcert)?;
            let g = k.move_(&grant, &mcert, &mnz)?;
            let mc = peek(&mcert)
                .and_then(|c| c.machine)
                .unwrap_or_else(|| jarvis_doc::Machine {
                    signing_key: String::new(),
                    encryption_key: String::new(),
                    image: String::new(),
                });
            self.st.do_(|d| {
                if let Some(st) = d.started.get_mut(&id) {
                    st.image = mc.image.clone();
                    st.signing_key = mc.signing_key.clone();
                    st.encryption_key = mc.encryption_key.clone();
                    st.kernel_cert = Some(Doc {
                        payload: mcert.payload.clone(),
                        sig: mcert.sig.clone(),
                    });
                }
                if let Some(x) = d.sessions.get_mut(sid)
                    && let Some(kl) = x.kernel.as_mut()
                {
                    kl.machine_cert = Some(mcert.clone());
                    kl.machine_nz = Some(mnz.clone());
                    kl.grant = Some(g.clone());
                    x.machine_id = id.clone();
                    x.image = mc.image.clone();
                    x.state = "initialising".into();
                    x.error.clear();
                    x.paused_at = None;
                }
            });
            Ok(())
        })();
        if let Err(e) = res {
            let _ = self.kernel_kill_up(&id, None);
            return fail(&format!("start: {e:#}"));
        }
        op.note(&id, &format!("the spawner's cert for {id} is notarized and the line's grant is on it; it boots now"));
        let (r, sid, id) = (self.clone(), sid.to_string(), id.clone());
        std::thread::spawn(move || r.lc_await_boot(op, &sid, &id));
    }

    /// the machine whose snapshot a start from this source restores (GET /m/snapshot, snapdirect.rs snapshot_for): the
    /// line's machine whose committed snapshot has the hash the source names (the machine checks the hash,
    /// rust/machine/src/kernelboot.rs kernel_restore). That is the machine the source came from when it left that
    /// snapshot. It is an earlier one when the source came from a machine that never got past boot, whose kill passed on
    /// the hash its own source named (never_booted_state_kept), or from the sink: a phone-signed source on a new image (a
    /// resume-upgrade) names the hash of the line's last snapshot. A restoring line's machine has none ("") while the
    /// hash is the archived snapshot's: its first machine, and every one after it until a machine of the line leaves a
    /// snapshot (the earlier ones never got past boot); snapshot_for then serves the archive's copy (restore.rs).
    pub fn kernel_pred(&self, s: &Session, sc: &Cert) -> String {
        let pred = if sc.pred.kind() == Some(Kind::Machine) {
            sc.pred.machine_id().to_string()
        } else {
            String::new()
        };
        let sum = sc
            .source
            .as_ref()
            .map(|x| x.snapshot.clone())
            .unwrap_or_default();
        if sum.is_empty() || (pred.is_empty() && s.restore_cert.is_some()) {
            return pred;
        }
        if !pred.is_empty()
            && let Some(p) = self.snap(&pred)
            && p.state == "committed"
            && p.sha256 == sum
        {
            return pred;
        }
        let m = self.snap_machine_with(&s.id, &sum);
        if !m.is_empty() {
            return m;
        }
        if self.restore_sum(&s.id) == sum {
            return String::new();
        }
        pred
    }

    /// the machine an earlier spawn from this source made whose answer was lost (a crash, a timeout, another replica's
    /// start that died), found with the router's read-only Fly token by the source its Fly metadata names, or with its
    /// read-only AWS key by the source tag → its id and volume ("" = none). One the spawner knows (its init answers
    /// anything but unknown-machine) is adopted; every other one is destroyed through the spawner. Only one machine of
    /// a source can take the line either way: the notarizer refuses a source's second successor.
    pub fn kernel_adopt(&self, op: &LcHandle, source: &Object) -> (String, String) {
        let Some(k) = &self.kernel else {
            return (String::new(), String::new());
        };
        let mut cands: Vec<(String, String)> = vec![];
        match crate::machines::list_fly_machines() {
            Err(e) => crate::logf!(
                "[kernel] {}: no look on Fly for an earlier spawn's machine ({e:#})",
                source.0
            ),
            Ok(ms) => {
                for m in ms {
                    if m.config.metadata.get(SOURCE_META).map(String::as_str)
                        != Some(source.0.as_str())
                        || m.state == "destroyed"
                        || m.state == "destroying"
                    {
                        continue;
                    }
                    let vol = m
                        .config
                        .mounts
                        .first()
                        .map(|x| x.volume.clone())
                        .unwrap_or_default();
                    cands.push((m.id, vol));
                }
            }
        }
        // awsrunner.rs: tagged with their source as Fly machines carry it in their metadata
        match crate::awsrunner::list_aws_machines() {
            Err(e) => crate::logf!(
                "[kernel] {}: no look on AWS for an earlier spawn's machine ({e:#})",
                source.0
            ),
            Ok(ins) => {
                for i in ins {
                    if i.source == source.0 && i.state != "destroyed" && i.state != "destroying" {
                        cands.push((i.id, String::new()));
                    }
                }
            }
        }
        let (mut id, mut vol) = (String::new(), String::new());
        for (mid, mvol) in cands {
            if id.is_empty() {
                let res = k.doc("spawner", "/init", &json!({"id": mid}));
                let unknown = res
                    .as_ref()
                    .err()
                    .and_then(reason_of)
                    .is_some_and(|ke| ke.reason == REASON_UNKNOWN);
                if !unknown {
                    op.note(&mid, &format!("machine {mid} from {} (an earlier spawn whose answer was lost) is the line's", source.0));
                    id = mid;
                    vol = mvol;
                    continue;
                }
            }
            op.note(&mid, &format!("machine {mid} from {} is a stray of an earlier spawn: asked the spawner to destroy it", source.0));
            if let Err(e) = k.doc("spawner", "/destroy", &json!({"id": mid})) {
                crate::logf!("[kernel] stray {mid}: destroy: {e:#}");
            }
        }
        (id, vol)
    }

    /// one kill of a kernel machine (snapshot: what it signed, None = none) → the kill's cert. Fly's destroy is waited
    /// for here (the spawner answers not-destroyed meanwhile); a volume the spawner's delete didn't take is kept in its
    /// Started record (kernel_volume_left) for the leader to kill again (kernel_volumes_tick).
    pub fn kernel_kill_up(&self, machine: &str, snapshot: Option<&Value>) -> Result<SDoc> {
        let k = self.kernel_client()?;
        let mut input = json!({"id": machine});
        if let Some(s) = snapshot {
            input["snapshot"] = s.clone();
        }
        let mut transient = 0;
        let mut i = 0;
        let d = loop {
            match k.doc("spawner", "/kill", &input) {
                Ok(d) => break d,
                Err(e) => {
                    let ke = reason_of(&e);
                    if ke.is_some_and(|k| k.reason == REASON_NOT_DESTROYED) && i <= 120 {
                        std::thread::sleep(KERNEL_KILL_STEP);
                        i += 1;
                        continue;
                    }
                    // failed on the way (Fly reset one request: "fly inspect: … EOF", 2026-11-17): tried again like a
                    // core kill
                    if ke.is_none_or(|k| k.status >= 500)
                        && transient < crate::flows::KILL_TRANSIENT_TRIES.load(Ordering::Relaxed)
                    {
                        transient += 1;
                        crate::logf!(
                            "kernel kill {machine}: {e:#}; trying again ({transient} of {})",
                            crate::flows::KILL_TRANSIENT_TRIES.load(Ordering::Relaxed)
                        );
                        std::thread::sleep(Duration::from_millis(
                            crate::flows::KILL_TRANSIENT_STEP_MS.load(Ordering::Relaxed),
                        ));
                        i += 1;
                        continue;
                    }
                    return Err(e);
                }
            }
        };
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct Kill {
            cert: SDoc,
            #[serde(rename = "volumeLeft")]
            volume_left: String,
        }
        let kd: Kill = jarvis_go::unmarshal(d.payload.as_bytes()).unwrap_or_default();
        if kd.cert.payload.is_empty() {
            return Err(anyhow!("kernel spawner /kill: no cert in the answer"));
        }
        self.st.do_(|dd| {
            if let Some(st) = dd.started.get_mut(machine) {
                st.kernel_volume_left = kd.volume_left.clone();
            }
        });
        Ok(kd.cert)
    }

    /// every killed kernel machine whose volume is left is killed again (the spawner answers the same cert and tries the
    /// volume once more)
    pub fn kernel_volumes_tick(&self) {
        if self.kernel.is_none() {
            return;
        }
        let ms: Vec<String> = self.st.do_(|d| {
            d.started
                .iter()
                .filter(|(_, st)| !st.kernel_volume_left.is_empty())
                .map(|(m, _)| m.clone())
                .collect()
        });
        for m in ms {
            if let Err(e) = self.kernel_kill_up(&m, None) {
                crate::logf!("[kernel] {m}'s volume: kill again: {e:#}");
            }
        }
    }

    pub fn kernel_volumes_loop(self: &Arc<Self>) {
        loop {
            crate::leaderlease::await_lead();
            self.kernel_volumes_tick();
            std::thread::sleep(Duration::from_secs(60));
        }
    }

    /// the spawner kills the machine with its snapshot, the cert into the new source is notarized and the grant moves
    /// onto it → the snapshot hash it names ("" = none). required: keep the machine rather than lose its state: with no
    /// committed snapshot signed by the machine's key the router doesn't ask for the kill. destroying: the line ends
    /// here, so the grant isn't moved (nothing takes it from the source, which the burn ends): a grant signed by a mover
    /// that has since restarted (new keys) no longer opens, and must not block a destroy; a repeat after the
    /// notarization went through finds the source already defined, which is the same outcome
    pub fn kernel_kill(
        &self,
        sid: &str,
        machine: &str,
        required: bool,
        destroying: bool,
    ) -> Result<String> {
        let k = self.kernel_client()?;
        let key = self.st.do_(|d| {
            d.started
                .get(machine)
                .map(|st| st.signing_key.clone())
                .unwrap_or_default()
        });
        let s = self.snap(machine);
        let mut snapshot = None;
        match &s {
            Some(s)
                if s.state == "committed"
                    && !key.is_empty()
                    && jarvis_sig::verify(&key, s.sha256.as_bytes(), &s.sig) =>
            {
                snapshot = Some(json!({"sha256": s.sha256, "sig": s.sig}));
            }
            _ if required => {
                let why = if s.as_ref().is_some_and(|s| s.state == "committed") {
                    "its snapshot isn't signed by its key"
                } else {
                    "no snapshot"
                };
                return Err(anyhow!("machine {machine} is kept, not killed: {why}"));
            }
            _ => {}
        }
        let d = self.kernel_kill_up(machine, snapshot.as_ref())?;
        let Some(c) = peek(&d) else {
            return Ok(String::new()); // a machine never up: a kill record, nothing goes on from it
        };
        let snap = c
            .source
            .as_ref()
            .map(|x| x.snapshot.clone())
            .unwrap_or_default();
        let nz = match k.notarize(&d) {
            Ok(nz) => Some(nz),
            // an earlier try of this destroy notarized it (the spawner's kill cert, and its source id, are kept)
            Err(e) if destroying && reason_of(&e).is_some_and(|ke| ke.reason == REASON_DEFINED) => {
                None
            }
            Err(e) => return Err(anyhow!("the kill's cert: {e:#}")),
        };
        if destroying {
            self.st.do_(|dd| {
                if let Some(kl) = dd.sessions.get_mut(sid).and_then(|x| x.kernel.as_mut()) {
                    kl.source = Some(c.succ.clone());
                    kl.source_cert = Some(d.clone());
                    kl.grant = None;
                    kl.source_nz = nz.clone().filter(|n| !n.sig.is_empty());
                    kl.machine_cert = None;
                    kl.machine_nz = None;
                }
            });
            crate::logf!(
                "session {sid}: {machine} killed into {} for its destroy (snapshot {})",
                c.succ.0,
                jarvis_go::fmt::go_quote(&snap)
            );
            return Ok(snap);
        }
        let nz = nz.unwrap_or_default();
        let cur = self
            .st
            .do_(|dd| {
                dd.sessions
                    .get(sid)
                    .and_then(|x| x.kernel.as_ref())
                    .and_then(|l| l.grant.clone())
            })
            .ok_or_else(|| anyhow!("the line has no grant"))?;
        let g = k
            .move_(&cur, &d, &nz)
            .map_err(|e| anyhow!("moving the grant onto {}: {e:#}", c.succ.0))?;
        self.st.do_(|dd| {
            if let Some(kl) = dd.sessions.get_mut(sid).and_then(|x| x.kernel.as_mut()) {
                kl.source = Some(c.succ.clone());
                kl.source_cert = Some(d.clone());
                kl.source_nz = Some(nz.clone());
                kl.grant = Some(g.clone());
                kl.machine_cert = None;
                kl.machine_nz = None;
            }
        });
        crate::logf!(
            "session {sid}: {machine} killed into {} (snapshot {})",
            c.succ.0,
            jarvis_go::fmt::go_quote(&snap)
        );
        Ok(snap)
    }

    /// the line's source ends, (source, sink) by the gullible signer, notarized
    pub fn kernel_burn(&self, sid: &str) -> Result<()> {
        let l = self
            .st
            .do_(|d| d.sessions.get(sid).and_then(|x| x.kernel.clone()));
        let Some(l) = l.filter(|l| {
            !l.burned
                && l.source
                    .as_ref()
                    .is_some_and(|s| s.kind() == Some(Kind::Source))
        }) else {
            return Ok(());
        };
        let k = self.kernel_client()?;
        let c = k.doc(
            "gullible",
            "/sign",
            &json!({"pred": l.source, "succ": SINK, "pair": Pair::top()}),
        )?;
        k.notarize(&c)?;
        self.st.do_(|d| {
            if let Some(kl) = d.sessions.get_mut(sid).and_then(|x| x.kernel.as_mut()) {
                kl.burned = true;
            }
        });
        Ok(())
    }

    fn running_kernel_line(&self, machine: &str) -> Option<KernelLine> {
        self.st.do_(|d| {
            d.machines
                .get(machine)
                .and_then(|sid| d.sessions.get(sid))
                .filter(|x| x.machine_id == machine)
                .and_then(|x| x.kernel.clone())
        })
    }

    /// what a kernel machine reads at boot (rust/machine/src/kernelboot.rs): its grant, the spawner's cert naming it,
    /// the cert into its source, each notarization, and the identities that check them
    pub fn kernel_boot(&self, machine: &str) -> Result<Value> {
        let l = self
            .running_kernel_line(machine)
            .filter(|l| l.machine_cert.is_some())
            .ok_or_else(|| anyhow!("no kernel line for this machine yet"))?;
        let k = self.kernel_client()?;
        let mut out = Map::new();
        out.insert("grant".into(), json!(l.grant));
        out.insert("machineCert".into(), json!(l.machine_cert));
        out.insert("machineNotarized".into(), json!(l.machine_nz));
        out.insert("sourceCert".into(), json!(l.source_cert));
        out.insert("sourceNotarized".into(), json!(l.source_nz));
        // secrets' signed statements the machine reads the phone's key and the stores' sensitivity from (its phone
        // grants and message approvals, as a core cert's phone and sensitive fields)
        let (ks, _) = k.keys()?;
        let sl = k.doc(
            "secrets",
            "/stores",
            &json!({"nonce": crate::util::rand_id()}),
        )?;
        out.insert("keys".into(), json!(ks));
        out.insert("stores".into(), json!(sl));
        // the serving copy's roster: the machine checks everything against it (its Fly config's may be an earlier one's)
        if let Some(d) = self.current_roster() {
            out.insert("roster".into(), json!(d));
        }
        for role in [
            "notary",
            "notarizer",
            "mover",
            "merger",
            "spawner",
            "secrets",
        ] {
            out.insert(role.into(), json!(k.identity(role)?));
        }
        Ok(Value::Object(out))
    }

    /// the machine's secrets, from the kernel's secrets with the line's grant
    pub fn kernel_pull(&self, machine: &str) -> Result<Doc> {
        let grant = self
            .running_kernel_line(machine)
            .and_then(|l| l.grant)
            .ok_or_else(|| anyhow!("no kernel line for this machine"))?;
        let k = self.kernel_client()?;
        match k.doc("secrets", "/pull", &serde_json::to_value(&grant)?) {
            Ok(d) => Ok(Doc {
                payload: d.payload,
                sig: d.sig,
            }),
            Err(e) => match kernel_error(&e) {
                Some(ke) => Err(CoreError {
                    status: ke.status,
                    body: vec![],
                    msg: ke.msg.clone(),
                }
                .into()),
                None => Err(e),
            },
        }
    }

    /// the machine is a kernel line's
    pub fn is_kernel_machine(&self, machine: &str) -> bool {
        self.st.do_(|d| {
            d.machines
                .get(machine)
                .and_then(|sid| d.sessions.get(sid))
                .is_some_and(|x| x.kernel.is_some())
        })
    }

    /// the machine never got past boot (it has no state of its own), and the snapshot its source named, if any, is
    /// still the line's newest: killing it without one loses nothing, because the next start names that snapshot again
    /// (kernel_resume). E.g. a resume-upgrade's machine that couldn't restore (2026-11-05). A restoring line that has no
    /// snapshot of its own yet: the archived one it still holds (restore.rs), which the next start restores.
    pub fn never_booted_state_kept(&self, id: &str, machine: &str) -> bool {
        let (booted, src) = self.st.do_(|d| {
            d.sessions
                .get(id)
                .map(|x| {
                    (
                        x.booted == machine,
                        x.kernel.as_ref().and_then(|k| k.source_cert.clone()),
                    )
                })
                .unwrap_or((false, None))
        });
        let Some(src) = src.filter(|_| !booted) else {
            return false;
        };
        let Some(source) = peek(&src).and_then(|c| c.source) else {
            return false;
        };
        if source.snapshot.is_empty() {
            return true;
        }
        let newest = self.newest_snap_sum(id);
        if !newest.is_empty() {
            return newest == source.snapshot;
        }
        self.restore_sum(id) == source.snapshot
    }

    /// snapsafe.rs's kill for a kernel machine (after its final snapshot, or past a failed one with force)
    pub fn kernel_kill_done(
        self: &Arc<Self>,
        id: &str,
        machine: &str,
        destroying: bool,
        serr: Option<&anyhow::Error>,
        ok: &mut bool,
    ) -> bool {
        self.lc_note(
            id,
            machine,
            "asked the kernel's spawner to kill the machine into the line's next source",
        );
        let required = !destroying && serr.is_none() && !self.never_booted_state_kept(id, machine);
        let snap = match self.kernel_kill(id, machine, required, destroying) {
            Err(e) => {
                self.lc_note(id, machine, &format!("the kill failed: {e:#}"));
                self.kill_failed(id, machine, true, destroying, &e);
                return false;
            }
            Ok(s) => s,
        };
        self.st.do_(|d| {
            let Some(s) = d.sessions.get_mut(id) else {
                return;
            };
            s.snapshot_failed.clear();
            if snap.is_empty() && s.booted == machine {
                let why = serr.map_or("it sent none".to_string(), |e| format!("{e:#}"));
                s.no_snapshot = format!("machine {machine} left no snapshot ({why})");
            } else {
                s.no_snapshot.clear();
            }
        });
        self.lc_note(
            id,
            machine,
            &format!(
                "the spawner confirmed the machine destroyed on {}",
                runner_name(machine)
            ),
        );
        *ok = true;
        true
    }

    /// a kernel line's resume. A machine still there (a pause cut off) is paused first; then a spawn from the line's
    /// source, or, on another image (D8), the phone signs a new source with that image and the same settings and
    /// snapshot. A line whose first source the phone never signed gets its approval again.
    pub fn kernel_resume(
        self: &Arc<Self>,
        s: Session,
        upgrade: bool,
        unlock: OnceFn,
        op: LcHandle,
    ) -> Result<()> {
        let id = s.id.clone();
        self.set_state(&id, "resuming", "");
        let r = self.clone();
        std::thread::spawn(move || {
            let _u = crate::flows::scopeguard(move || unlock.call());
            let op2 = op.clone();
            let _e = crate::flows::scopeguard(move || op2.end_from_state());
            let (r2, id2) = (r.clone(), id.clone());
            let _f = crate::flows::scopeguard(move || r2.settle_followups(&id2));
            let mut s = s;
            let mut upgrade = upgrade;
            if let Some(lost) = &s.lost
                && s.machine_id == lost.machine
                && !upgrade
            {
                // lostmachine.rs: it stopped outside Jarvis
                if r.kernel_resume_lost(&s, &op) {
                    return;
                }
                if let Some(x) = r.st.do_(|d| d.sessions.get(&id).cloned()) {
                    s = x;
                }
            }
            if !s.machine_id.is_empty() {
                op.machine(&s.machine_id);
                op.note(&s.machine_id, "finishing the machine's pause first");
                if !r.final_snapshot_and_kill_next(&id, &s.machine_id, None) {
                    return;
                }
                let now = GoTime::now();
                if let Some(x) = r.st.do_(|d| {
                    let x = d.sessions.get_mut(&id)?;
                    x.machine_id.clear();
                    x.paused_at = Some(now);
                    x.status.clear();
                    Some(x.clone())
                }) {
                    s = x;
                }
            }
            let l = s.kernel.clone().unwrap_or_default();
            if !upgrade
                && let Some(sc) = l.source_cert.as_ref()
                && let Some(c) = peek(sc)
                && c.source.as_ref().is_some_and(|x| x.snapshot.is_empty())
                && !r.newest_snap_sum(&id).is_empty()
            {
                // a source that names no snapshot while the line holds one (its last machine never got past boot): a
                // start from it would come up empty, so the phone signs a source naming the newest snapshot instead
                op.note("", "the line's source names no snapshot but the line holds one: a new source naming it, for Deyao's approval");
                upgrade = true;
            }
            if l.source_cert.is_none() || upgrade {
                let config = match r.session_config(&s) {
                    Err(e) => return r.set_state(&id, "failed", &format!("resume: {e:#}")),
                    Ok(c) => c,
                };
                let mut snap = l
                    .source_cert
                    .as_ref()
                    .and_then(peek)
                    .and_then(|c| c.source)
                    .map(|x| x.snapshot)
                    .unwrap_or_default();
                if snap.is_empty() && l.source_cert.is_some() {
                    // the last machine left none (it never got past boot, e.g. an upgrade that couldn't restore): the
                    // new source names the line's newest committed snapshot, so the state isn't dropped (the phone
                    // signs the hash)
                    snap = r.newest_snap_sum(&id);
                }
                let img = r.source_image(&s);
                let draft = match r.kernel_source_draft(&s, &config, &img, &snap) {
                    Err(e) => return r.set_state(&id, "failed", &format!("resume: {e:#}")),
                    Ok(d) => d,
                };
                r.set_state(&id, "approval", "");
                r.add_approval(Approval {
                    kind: KERNEL_APPROVAL_KIND.into(),
                    session: id.clone(),
                    label: s.label.clone(),
                    challenge: Some(Doc {
                        payload: draft.payload,
                        sig: String::new(),
                    }),
                    options: BTreeMap::from([
                        (
                            "permissionMode".to_string(),
                            crate::flows::norm_mode(&s.permission_mode).to_string(),
                        ),
                        ("image".to_string(), img.clone()),
                    ]),
                    again: l.source_cert.is_none(),
                    ..Default::default()
                });
                op.note(
                    "",
                    &format!(
                        "waiting for Deyao's approval in the Inbox: a new source on image {img}"
                    ),
                );
                return;
            }
            r.kernel_spawn(&id);
        });
        Ok(())
    }

    /// a kernel line's start or resume whose job another replica held when it died, carried on from where the records
    /// say it is (every step is safe to repeat: a spawn adopts the machine an earlier spawn of the source made,
    /// kernel_adopt; its keys, the notarization and the move come again):
    ///
    /// ```text
    /// resuming with its old machine still on it  → the pause first, then the spawn (as kernel_resume)
    /// starting / resuming with no machine         → the spawn from the kept source
    /// initialising / started on the new machine  → nothing left but waiting for it to boot
    /// ```
    pub fn kernel_continue(self: &Arc<Self>, sid: &str, unlock: OnceFn) {
        let s = self
            .st
            .do_(|d| d.sessions.get(sid).cloned())
            .unwrap_or_default();
        let op = self.lc_begin(sid, "boot");
        op.note(
            "",
            "carried on by another router replica: its holder stopped",
        );
        let Some(kl) = s
            .kernel
            .clone()
            .filter(|k| k.source_cert.is_some() || s.state == "resuming")
        else {
            unlock.call();
            op.end_joined("failed", "nothing to carry on");
            self.cut_off_session(sid);
            return;
        };
        if s.state == "initialising" || s.state == "started" {
            unlock.call();
            let (r, sid, m) = (self.clone(), sid.to_string(), s.machine_id.clone());
            std::thread::spawn(move || r.lc_await_boot(op, &sid, &m));
            return;
        }
        let def = crate::awsrunner::default_runner();
        if s.state == "resuming"
            && !s.machine_id.is_empty()
            && kl
                .machine_cert
                .as_ref()
                .is_none_or(|mc| kernel_object(Some(&s), &s.machine_id, &def) != must_succ(mc))
        {
            let _ = self.kernel_resume(s, false, unlock, op);
            return;
        }
        let (r, sid) = (self.clone(), sid.to_string());
        std::thread::spawn(move || {
            let _u = crate::flows::scopeguard(move || unlock.call());
            r.kernel_spawn(&sid);
        });
    }

    /// kernel_object for a running machine, by its session
    pub fn machine_object(&self, machine: &str) -> Object {
        let s = self.st.do_(|d| {
            d.machines
                .get(machine)
                .and_then(|sid| d.sessions.get(sid))
                .cloned()
        });
        kernel_object(s.as_ref(), machine, &crate::awsrunner::default_runner())
    }

    /// an input's entry in the log before it reaches a machine: the old core's input log, or, for a kernel machine, the
    /// log notary's challenge over (its object, the kind, the input's sha256) (rust/machine/src/kernelboot.rs
    /// KernelInputSubject)
    pub fn attest_input(&self, machine: &str, kind: &str, origin: &str, sum: &str) -> Result<Doc> {
        if !self.is_kernel_machine(machine) {
            let a = self.core.call(
                "/attest",
                &json!({"machine": machine, "input": kind, "origin": origin, "sha256": sum}),
            )?;
            self.log_inputs(Some(&a));
            return Ok(a);
        }
        let h = Sha256::digest(
            format!(
                "jarvis2-input\n{}\n{kind}\n{sum}",
                self.machine_object(machine).0
            )
            .as_bytes(),
        );
        let d = self.kernel_client()?.doc(
            "notary",
            "/challenge",
            &json!({"subject": hex::encode(h), "about": "input"}),
        )?;
        Ok(Doc {
            payload: d.payload,
            sig: d.sig,
        })
    }

    /// the machine keeps only these stores: the identity signer's (M, M, P), M its kernel_object, P the kept stores for
    /// the session, notarized; the main grant moves along it (a move only narrows); the machine pulls again
    pub fn kernel_downgrade(&self, machine: &str, keep: &[String]) -> Result<()> {
        let s = self
            .st
            .do_(|d| {
                d.machines
                    .get(machine)
                    .and_then(|sid| d.sessions.get(sid))
                    .filter(|x| x.machine_id == machine)
                    .cloned()
            })
            .unwrap_or_default();
        let grant = s
            .kernel
            .as_ref()
            .and_then(|l| l.grant.clone())
            .ok_or_else(|| anyhow!("this machine isn't a running kernel line"))?;
        let k = self.kernel_client()?;
        let allowed: Vec<String> = keep.iter().map(|st| format!("store:{st}")).collect();
        let p = Pair::new(Set::only(allowed), vec![format!("session:{}", s.id)]);
        let c = k.doc(
            "identity",
            "/sign",
            &json!({"machine": self.machine_object(machine), "pair": p}),
        )?;
        let nz = k.notarize(&c)?;
        let g = k.move_(&grant, &c, &nz)?;
        self.st.do_(|d| {
            if let Some(x) = d
                .sessions
                .get_mut(&s.id)
                .filter(|x| x.machine_id == machine)
                && let Some(kl) = x.kernel.as_mut()
            {
                kl.grant = Some(g.clone());
                x.stores = Some(keep.to_vec());
            }
        });
        Ok(())
    }

    pub fn kernel_add_store_approval(
        self: &Arc<Self>,
        s: &Session,
        store: &str,
        o: Origin,
        explanation: &str,
        batch: &str,
    ) -> Result<String> {
        let l = s
            .kernel
            .as_ref()
            .filter(|l| l.machine_cert.is_some() && l.source_cert.is_some())
            .ok_or_else(|| anyhow!("this machine isn't a running kernel line"))?;
        let mc = jarvis_doc::peek_cert(
            l.machine_cert
                .as_ref()
                .ok_or_else(|| anyhow!("no machine cert"))?,
        )
        .map_err(|e| anyhow!("{e}"))?;
        let sc = jarvis_doc::peek_cert(
            l.source_cert
                .as_ref()
                .ok_or_else(|| anyhow!("no source cert"))?,
        )
        .map_err(|e| anyhow!("{e}"))?;
        let add = new_source();
        let mut src = sc
            .source
            .ok_or_else(|| anyhow!("the line's source cert names no source"))?;
        src.snapshot.clear();
        let c1 = Cert {
            kind: "succession".into(),
            pred: sink(),
            succ: add.clone(),
            pair: Pair::new(
                Set::only([format!("store:{store}")]),
                vec![format!("session:{}", s.id)],
            ),
            source: Some(src),
            machine: None,
            signer: jarvis_doc::by::IPHONE.into(),
            issued_at: jarvis_doc::now(),
        };
        let c2 = Cert {
            kind: "succession".into(),
            pred: add,
            succ: mc.succ.clone(),
            pair: Pair::top(),
            source: None,
            machine: mc.machine.clone(),
            signer: jarvis_doc::by::IPHONE.into(),
            issued_at: jarvis_doc::now(),
        };
        let (p1, p2) = (cert_payload(&c1)?, cert_payload(&c2)?);
        let a = Approval {
            kind: KERNEL_ADD_APPROVAL_KIND.into(),
            session: s.id.clone(),
            machine: s.machine_id.clone(),
            label: s.label.clone(),
            challenge: Some(Doc {
                payload: p1,
                sig: String::new(),
            }),
            earlier: vec![Doc {
                payload: p2,
                sig: String::new(),
            }],
            options: BTreeMap::from([("store".to_string(), store.to_string())]),
            origin: Some(o),
            explanation: explanation.into(),
            batch: batch.into(),
            ..Default::default()
        };
        Ok(self.add_approval(a))
    }

    /// the two signatures → the store's grant moved onto the machine and merged with the main grant (both carry exactly
    /// session:<id>), then the machine pulls again
    pub fn respond_kernel_add(
        self: &Arc<Self>,
        a: &Approval,
        signatures: &str,
    ) -> Result<(Doc, String)> {
        let sigs: Vec<&str> = signatures.split_whitespace().collect();
        if sigs.len() != 2 || a.earlier.len() != 1 {
            return Err(anyhow!(
                "an add-store on a kernel line takes two signatures (one per line)"
            ));
        }
        let c1 = SDoc {
            payload: a
                .challenge
                .as_ref()
                .map(|c| c.payload.clone())
                .unwrap_or_default(),
            sig: sigs[0].into(),
        };
        let c2 = SDoc {
            payload: a.earlier[0].payload.clone(),
            sig: sigs[1].into(),
        };
        let (root, main) = self.st.do_(|d| {
            let main = d
                .sessions
                .get(&a.session)
                .filter(|s| s.machine_id == a.machine)
                .and_then(|s| s.kernel.as_ref())
                .and_then(|k| k.grant.clone());
            (d.kernel_root.clone(), main)
        });
        let (Some(root), Some(main)) = (root, main) else {
            return Err(anyhow!("the machine isn't running on the kernel any more"));
        };
        let k = self.kernel_client()?;
        let nz1 = k.notarize(&c1)?;
        let g = k.move_(&root, &c1, &nz1)?;
        let nz2 = k.notarize(&c2)?;
        let g = k.move_(&g, &c2, &nz2)?;
        let mid = k.identity("merger")?;
        let md = k.doc("merger", "/merge", &json!({"a": main, "b": g}))?;
        let merged = Signed {
            grant: md.clone(),
            by: "merger".into(),
            signer: Some(mid),
            keys: None,
            secrets: None,
        };
        let store = a.options.get("store").cloned().unwrap_or_default();
        let nz2d = Doc {
            payload: nz2.payload.clone(),
            sig: nz2.sig.clone(),
        };
        self.st.do_(|d| {
            d.approvals.remove(&a.id);
            if let Some(s) = d
                .sessions
                .get_mut(&a.session)
                .filter(|s| s.machine_id == a.machine)
                && let Some(kl) = s.kernel.as_mut()
            {
                kl.grant = Some(merged.clone());
                let stores = s.stores.get_or_insert_with(Vec::new);
                if !stores.contains(&store) {
                    stores.push(store.clone());
                    stores.sort();
                }
            }
            if let Some(o) = &a.origin {
                crate::outcomes::note_outcome(
                    d,
                    Some(o),
                    "add-store",
                    &a.session,
                    crate::outcomes::OUTCOME_APPROVED,
                    0,
                    Some(&nz2d),
                );
            }
        });
        self.send(&a.machine, "refresh-secrets");
        Ok((
            Doc {
                payload: md.payload,
                sig: md.sig,
            },
            a.session.clone(),
        ))
    }

    /// secrets' (or the spawner's) own API, relayed as is: every answer is signed by the component, which the app
    /// checks
    fn kernel_relay(
        &self,
        w: &mut W,
        role: &str,
        method: &str,
        path: &str,
        body: Option<&Value>,
        kernel_errors: bool,
    ) {
        let Some(k) = &self.kernel else {
            return write_json(w, 503, &json!({"error": "this box runs no kernel yet"}));
        };
        match k.call(role, method, path, body) {
            Err(e) => match kernel_error(&e).filter(|_| kernel_errors) {
                Some(ke) => write_json(w, ke.status, &json!({"error": ke.msg})),
                None => write_err(w, &e),
            },
            Ok(b) => {
                w.set_header("Content-Type", "application/json");
                w.write(&b);
            }
        }
    }
}

fn relay_secrets(r: &Arc<Router>, w: &mut W, req: &mut Req) {
    let Some(k) = &r.kernel else {
        return write_json(w, 503, &json!({"error": "this box runs no kernel yet"}));
    };
    let path = format!("/{}", req.path_value("path"));
    let mut role = "secrets".to_string();
    if req.query("secrets") == "next" {
        // the copy that doesn't serve: its secrets (empty until a flip)
        role = format!("secrets-{}", other_copy(&k.serving()));
    }
    let body = (req.method == "POST").then(|| {
        let b = req.read_body(4 << 20);
        serde_json::from_slice::<Value>(&b).unwrap_or_else(|_| json!({}))
    });
    let method = req.method.clone();
    r.kernel_relay(w, &role, &method, &path, body.as_ref(), true);
}

/// the app's side of the kernel
///
/// ```text
/// GET  /api/kernel                    {configured, core, serves, root, roster, health}: whether this box has a kernel,
///                                     whether it also runs the old core (NO_CORE=1: no; the app's first launch then
///                                     sets up the kernel, never the core), whether new sessions start on it, whether
///                                     the root's grant is here, and the roster's state (roster.rs), and its health
///                                     (kernelhealth.rs)
/// GET  /api/kernel/root-grant/draft   {payload}: what the root key signs
/// POST /api/kernel/root-grant         {grant}: the root key's ⊤ on the sink (the app signs it once, after secrets'
///                                     claim, behind the root key's own warning screen); kept, passed on
/// GET|POST /api/kernel/secrets/{path} secrets' own API, relayed as is (claim, identity, unlock, lock, …): every answer
///                                     is signed by secrets, which the app checks
/// ```
pub fn register_kernel(reg: &mut Registrar) {
    reg.app("GET /api/kernel", |r, w, _| {
        let root = r.st.do_(|d| d.kernel_root.is_some());
        write_json(
            w,
            200,
            &json!({"configured": r.kernel.is_some(), "core": !r.cfg.no_core, "serves": r.kernel_serves(), "root": root,
                "roster": r.roster_status(), "health": r.kernel_health_view()}),
        );
    });
    // the grant the root key signs once: ⊤ on the sink with the sink's keys (hashed from its name: the app can't
    // compute them; a draft naming other keys is refused by every component that takes the grant)
    reg.app("GET /api/kernel/root-grant/draft", |_, w, _| {
        let payload = jarvis_doc::gv::ideal_keys(&sink())
            .map_err(|e| anyhow!("{e}"))
            .and_then(|keys| {
                let g = jarvis_doc::Grant {
                    kind: "grant".into(),
                    machine: sink(),
                    keys,
                    pair: Pair::top(),
                    from: Some(vec![]),
                    at: jarvis_doc::now(),
                };
                jarvis_sig::go_json(&g).map_err(|e| anyhow!("{e}"))
            })
            .unwrap_or_default();
        write_json(w, 200, &json!({"payload": payload}));
    });
    reg.app("POST /api/kernel/root-grant", |r, w, req| {
        #[derive(Deserialize)]
        struct In {
            #[serde(default)]
            grant: SDoc,
        }
        let Ok(i) = crate::http::decode_body_strict::<In>(req, 1 << 20) else {
            return write_json(w, 400, &json!({"error": "{grant}"}));
        };
        let g: Option<jarvis_doc::Grant> = jarvis_sig::strict_json(i.grant.payload.as_bytes()).ok();
        let Some(k) = r.kernel.clone().filter(|_| {
            g.as_ref()
                .is_some_and(|g| g.machine.0 == SINK && Pair::top().leq(&g.pair))
        }) else {
            return write_json(
                w,
                400,
                &json!({"error": "not the root's ⊤ on the sink (or no kernel here)"}),
            );
        };
        // checked the way the mover will check it: signed by the root key secrets names
        let (ks, _) = match k.keys() {
            Err(e) => return write_err(w, &e),
            Ok(x) => x,
        };
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct K {
            #[serde(alias = "Root")]
            root: String,
        }
        let root = jarvis_go::unmarshal::<K>(ks.payload.as_bytes())
            .unwrap_or_default()
            .root;
        if !jarvis_sig::verify(&root, i.grant.payload.as_bytes(), &i.grant.sig) {
            return write_json(
                w,
                403,
                &json!({"error": "not signed by the root key secrets holds"}),
            );
        }
        // the mover gets secrets' current statement with every move
        let s = Signed {
            grant: i.grant,
            by: "root".into(),
            signer: None,
            keys: None,
            secrets: None,
        };
        r.st.do_(|d| d.kernel_root = Some(s.clone()));
        write_json(w, 200, &json!({"ok": true}));
    });
    // the spawner's Fly token from the app's Recover (the kit opens the core store's backup): sealed to the spawner's
    // box-vouched key, which the app checks; relayed as is
    reg.app("GET /api/kernel/spawner/identity", |r, w, _| {
        r.kernel_relay(w, "spawner", "GET", "/identity", None, false);
    });
    reg.app("POST /api/kernel/spawner/fly-token", |r, w, req| {
        let b = req.read_body(1 << 16);
        let parsed = serde_json::from_slice::<Value>(&b);
        let (Some(k), Ok(body)) = (&r.kernel, parsed) else {
            return write_json(
                w,
                400,
                &json!({"error": "{sealed}, on a box with a kernel"}),
            );
        };
        match k.call("spawner", "POST", "/fly-token", Some(&body)) {
            Err(e) => match kernel_error(&e) {
                Some(ke) => write_json(w, ke.status, &json!({"error": ke.msg})),
                None => write_err(w, &e),
            },
            Ok(b) => {
                r.kernel_token_dmed.store(false, Ordering::SeqCst);
                w.set_header("Content-Type", "application/json");
                w.write(&b);
            }
        }
    });
    reg.app("GET /api/kernel/secrets/{path...}", relay_secrets);
    reg.app("POST /api/kernel/secrets/{path...}", relay_secrets);
}
