//! The router's part of "only vouched inputs shape a machine that gets secrets" (docs/DESIGN.md "Inputs to a machine";
//! rust/machine/src/vouch.rs and rust/machine/src/deliver.rs do the checking, core/vouch.go and core/audit.go the
//! signing). The router is untrusted: nothing here is a check anyone relies on. It
//!
//!   - puts the session's settings into the succession challenge (Options.Config: title, first prompt, model, repos,
//!     one-shot, API proxy, attachments by hash, the task's parameters, what a restore restores), so the phone signs
//!     them and the cert carries them; an unattended resume passes the cert's own config unchanged;
//!   - puts a resume's one-time inputs (a prompt, a rollback) into Options.Once, which only the phone approves;
//!   - kills a machine with the hash and signature of its last snapshot, so its successor's cert names it;
//!   - serves the few values whose format can't carry an instruction (/m/config), and
//!   - delivers wakeups, crons and its own canned texts as deliveries the machine checks (the session's own signed
//!     request, or a text built into the image) and the core attests (the input log), instead of running a command
//!     under a grant.
//!
//! The held core (before Vouch 2) ignores Config and Once and has no input log: then everything stays as before (the
//! machine, for its part, takes none of those settings from such a cert).

use crate::core::Doc;
use crate::http::{Registrar, write_err};
use crate::inbox::Origin;
use crate::nethttp::{Req, write_json};
use crate::router::Router;
use crate::sessionlog::LOG_INPUT;
use crate::state::Session;
use anyhow::{Result, anyhow};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

fn is_false(b: &bool) -> bool {
    !*b
}

fn is_zero(n: &i64) -> bool {
    *n == 0
}

/// Options.Config (rust/machine/src/vouch.rs reads it strictly; the app's shell shows and checks it). The field order
/// is the one Go wrote: the phone signs these bytes.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct SessionConfig {
    pub v: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub label: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub prompt: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub model: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub repos: Vec<String>,
    /// content stores (content.rs): ~/content/<name>/ through the router
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub content: Vec<String>,
    #[serde(rename = "oneShot", skip_serializing_if = "is_false")]
    pub one_shot: bool,
    #[serde(rename = "apiProxy", skip_serializing_if = "is_false")]
    pub api_proxy: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<AttachmentRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub restore: Option<RestoreRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task: Option<TaskConfig>,
    /// the session's Claude account (claudeaccounts.rs), shown on the phone; only with SIGN_CLAUDE_ACCOUNT=1 (an app
    /// build that knows the key: older ones refuse settings they can't show). The machine takes the router's word
    /// anyway.
    #[serde(rename = "claudeAccount", skip_serializing_if = "String::is_empty")]
    pub claude_account: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct AttachmentRef {
    pub name: String,
    pub sha256: String,
    pub size: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct RestoreRef {
    pub machine: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct TaskConfig {
    pub instance: String,
    pub name: String,
    /// Go wrote null for none
    pub params: Option<Map<String, Value>>,
}

/// Options.Once
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct OnceInputs {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub prompt: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub rollback: String,
}

/// the cert's Config and Once
pub fn cert_options(c: Option<&Doc>) -> (String, String) {
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct O {
        config: String,
        once: String,
    }
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct X {
        options: O,
    }
    let x = c.and_then(|c| c.decode::<X>().ok()).unwrap_or_default();
    (x.options.config, x.options.once)
}

pub fn split_repos(s: &str) -> Vec<String> {
    s.split(',')
        .map(str::trim)
        .filter(|u| !u.is_empty())
        .map(String::from)
        .collect()
}

/// what a successor's challenge carries: the cert's own config (an unattended resume keeps it exactly), or, for a line
/// from a core that doesn't vouch, nothing
pub fn line_config(s: &Session) -> String {
    cert_options(s.cert.as_ref()).0
}

/// a scheduled delivery the session armed for itself, which nobody is watching arrive
pub fn scheduled_kind(kind: &str) -> bool {
    matches!(kind, "wakeup" | "cron" | "watch" | "watch-fail")
}

static RESTORE_MACHINE_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"^[a-z0-9]{1,40}$").unwrap_or_else(|_| unreachable!())); // rust/machine/src/vouch.rs MACHINE_ID_RE

/// the archived line's machine, as the restoring machine's config check wants it (rust/machine/src/vouch.rs
/// MACHINE_ID_RE): an old core's cert names it in machine.id; a kernel line's (the spawner's) only in succ,
/// "fly-<id>", its machine carrying keys and image but no id
pub fn restore_machine_id(cert: &Doc) -> Result<String> {
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct M {
        id: String,
    }
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct C {
        succ: String,
        machine: Option<M>,
    }
    let c = cert
        .decode::<C>()
        .ok()
        .filter(|c| c.machine.is_some())
        .ok_or_else(|| anyhow!("the cert names no machine"))?;
    let mut id = c.machine.map(|m| m.id).unwrap_or_default();
    if id.is_empty() {
        id = c.succ.strip_prefix("fly-").unwrap_or(&c.succ).to_string();
    }
    if !RESTORE_MACHINE_RE.is_match(&id) {
        return Err(anyhow!(
            "the cert's machine {} isn't a machine id",
            jarvis_go::fmt::go_quote(&id)
        ));
    }
    Ok(id)
}

// ---- deliveries ----------------------------------------------------------------------------------------------

/// a machine's request exactly as it signed it (rust/machine/src/deliver.rs checks it against its line's keys)
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct SignedRequest {
    pub machine: String,
    pub method: String,
    pub path: String,
    pub at: String,
    /// base64
    pub body: String,
    pub sig: String,
}

pub fn signed_request_of(req: &Req, machine: &str, body: &[u8]) -> SignedRequest {
    SignedRequest {
        machine: machine.into(),
        method: req.method.clone(),
        path: req.path.clone(),
        at: req.header("X-Time"),
        body: base64::engine::general_purpose::STANDARD.encode(body),
        sig: req.header("X-Sig"),
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Delivery {
    pub id: String,
    /// wakeup | cron | watch | watch-fail | continue | upgraded | lease-* | request-outcome | peer | resume-prompt
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: Option<SignedRequest>,
    #[serde(skip_serializing_if = "is_zero")]
    pub run: i64,
    #[serde(skip_serializing_if = "is_zero")]
    pub minutes: i64,
    /// upgraded: the old and new size (memory.rs)
    #[serde(skip_serializing_if = "String::is_empty")]
    pub from: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub to: String,
    /// leases.rs: the device (a lease name), whether Deyao had taken it over and the holder was interrupted by that
    #[serde(skip_serializing_if = "String::is_empty")]
    pub device: String,
    #[serde(skip_serializing_if = "is_false")]
    pub handover: bool,
    #[serde(skip_serializing_if = "is_false")]
    pub interrupted: bool,
    /// outcomes.rs: request-outcome — the decided items of the session's own filing (request)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub outcomes: Vec<crate::outcomes::OutcomeItem>,
    /// peermsg.rs: a peer message, with its verified sender and direction
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer: Option<crate::peermsg::PeerNote>,
    /// resume-prompt: Deyao's words from the app (rust/machine/src/deliver.rs takes them only under the phone's approval)
    #[serde(skip_serializing_if = "String::is_empty")]
    pub text: String,
    /// messages.rs: the phone's approval of this very message (a signed batch it is in, or a rule for its kind)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval: Option<Doc>,
    /// the machine only renders the text and answers it (messages.rs preview_text)
    #[serde(skip_serializing_if = "is_false")]
    pub preview: bool,
    pub attest: Option<Doc>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct DeliveryResult {
    pub id: String,
    pub ok: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub error: String,
    /// a preview's text, or the machine's own text when the phone signed another (messages.rs)
    #[serde(skip_serializing_if = "String::is_empty")]
    pub text: String,
    /// refused only for want of the phone's approval of this message
    #[serde(rename = "needsApproval", skip_serializing_if = "is_false")]
    pub needs_approval: bool,
}

/// what the core attests for a delivery (the machine recomputes it the same way) → (the input, its origin)
pub fn attested(d: &Delivery) -> Result<(Vec<u8>, String)> {
    let signed_by = |r: &SignedRequest| format!("session-signed:{}", r.machine);
    match d.kind.as_str() {
        "wakeup" | "cron" | "watch" | "watch-fail" => {
            let r = d
                .request
                .as_ref()
                .ok_or_else(|| anyhow!("no signed request"))?;
            let b = base64::engine::general_purpose::STANDARD.decode(&r.body)?;
            Ok((b, signed_by(r)))
        }
        "continue" => Ok((b"continue".to_vec(), "image-text".into())),
        "resume-prompt" => match crate::sessionapi::clean_resume_prompt(&d.text) {
            Ok(p) if !p.is_empty() => Ok((p.into_bytes(), "deyao".into())),
            _ => Err(anyhow!("resume-prompt: empty or too long")),
        },
        "request-outcome" => {
            let b = crate::outcomes::outcome_attested(d)?;
            let r = d
                .request
                .as_ref()
                .ok_or_else(|| anyhow!("no signed request"))?;
            Ok((b, signed_by(r)))
        }
        "lease-granted" | "lease-taken" | "lease-back" => {
            if !regex::Regex::new(r"^[a-z0-9][a-z0-9-]{0,40}$")
                .is_ok_and(|re| re.is_match(&d.device))
            {
                return Err(anyhow!("lease: not a device name"));
            }
            match d.kind.as_str() {
                "lease-taken" => Ok((
                    crate::leases::lease_taken_text(&d.device).into_bytes(),
                    "image-text".into(),
                )),
                "lease-back" => Ok((
                    crate::leases::lease_back_text(&d.device).into_bytes(),
                    "image-text".into(),
                )),
                _ => {
                    let origin = d
                        .request
                        .as_ref()
                        .map_or("image-text".to_string(), signed_by);
                    let t = crate::leases::lease_granted_text(
                        &d.device,
                        d.minutes,
                        d.handover,
                        d.interrupted,
                        &crate::leases::signed_prompt(d.request.as_ref()),
                    );
                    Ok((t.into_bytes(), origin))
                }
            }
        }
        "peer" => crate::peermsg::peer_attested(d.peer.as_ref()),
        "upgraded" => {
            if crate::sizes::size_mem_gb(&d.from) == 0 || crate::sizes::size_mem_gb(&d.to) == 0 {
                return Err(anyhow!("upgraded: not a machine size"));
            }
            Ok((
                crate::memory::upgraded_text(&d.from, &d.to).into_bytes(),
                "image-text".into(),
            ))
        }
        k => Err(anyhow!("unknown delivery {k}")),
    }
}

/// this wasn't asked for by the session itself (no session-signed request), and nothing else vouches for it
pub const NOT_VOUCHED: &str = "this wasn't asked for by the session itself (no session-signed request), and nothing else vouches for it: not delivered";

/// a held message counts as handed over: the approval queue delivers it, or tells whoever asked
pub fn handed_over(r: Result<()>) -> Result<()> {
    match r {
        Err(e) if crate::messages::is_awaiting_approval(&e) => Ok(()),
        other => other,
    }
}

// ---- a pause right after a start ------------------------------------------------------------------------------

pub const BOOT_GRACE: Duration = Duration::from_secs(90);

/// machine → its secrets pull went through (it is about to finish booting)
static PULLED_MACHINES: LazyLock<Mutex<BTreeSet<String>>> =
    LazyLock::new(|| Mutex::new(BTreeSet::new()));

pub fn mark_pulled(machine: &str) {
    PULLED_MACHINES
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(machine.to_string());
}

pub fn has_pulled(machine: &str) -> bool {
    PULLED_MACHINES
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .contains(machine)
}

// ---- the input log, persisted ---------------------------------------------------------------------------------
//
// Every entry is core-signed and names the hash of the one before. A core from R2 on keeps none: each entry arrives in
// the answer that made it (attest's answer; beside each cert), and the router appends it to the input log. A new
// core's chain begins again at seq 0 with no previous hash (the log shows where). The core before R2 kept its entries
// for reading (POST /input-log): with it the router reads them instead, as before.

#[derive(Default)]
struct InputLog {
    /// the core before R2: the next seq to fetch
    next: i64,
    /// the core before R2: its log was started from the persisted head (or there was none)
    chained: bool,
}

static INPUT_LOG: LazyLock<Mutex<InputLog>> = LazyLock::new(|| Mutex::new(InputLog::default()));
/// core URL → when it was last asked and whether it keeps its own input log
static KEPT_LOG_PROBE: LazyLock<Mutex<BTreeMap<String, (Instant, bool)>>> =
    LazyLock::new(Default::default);

#[derive(Deserialize, Default)]
#[serde(default)]
struct Seq {
    seq: i64,
}

impl Router {
    /// the settings a new line's cert carries (the first machine is the only one that uses the prompt, the attachments
    /// and the restore; the rest hold for the whole line)
    pub fn session_config(&self, s: &Session) -> Result<String> {
        let mut c = SessionConfig {
            v: 1,
            label: s.label.clone(),
            prompt: s.prompt.clone(),
            model: s.model.clone(),
            repos: split_repos(&s.repos),
            content: s.content.clone().unwrap_or_default(),
            ..Default::default()
        };
        if std::env::var("SIGN_CLAUDE_ACCOUNT").is_ok_and(|v| v == "1") {
            c.claude_account = s.claude_account.clone();
        }
        if let Some(l) = &s.live {
            c.one_shot = l.one_shot;
        }
        if let Some(ops) = &s.ops {
            c.api_proxy = ops.api_proxy;
            // only a line's first machine fetches the attachments, and the router drops the upload once it has
            // (DELETE /m/attachments): a later line (a restart onto a new image) carries none, where re-hashing the
            // dropped files failed its resume with "no such object" (2026-11-17)
            let held = self.st.read(|d| d.uploads.contains_key(&ops.upload));
            if held {
                for f in &ops.attach {
                    let (sum, size) = self
                        .obj_sha256(&crate::uploads::upload_key(&ops.upload, &f.name))
                        .map_err(|e| anyhow!("attachment {}: {e:#}", f.name))?;
                    c.attachments.push(AttachmentRef {
                        name: f.name.clone(),
                        sha256: sum,
                        size,
                    });
                }
            }
        }
        if let Some(rc) = &s.restore_cert {
            let rs = self
                .snap(&crate::restore::restore_snap(&s.id))
                .ok_or_else(|| {
                    anyhow!("the restore's snapshot or cert: its snapshot isn't here")
                })?;
            let m = restore_machine_id(rc)
                .map_err(|e| anyhow!("the restore's snapshot or cert: {e:#}"))?;
            c.restore = Some(RestoreRef {
                machine: m,
                sha256: rs.sha256,
            });
        }
        if !s.import_from.is_empty() {
            // jarvis1import.rs: the Jarvis 1 session id (its first machine's) and the import manifest's hash
            c.restore = Some(RestoreRef {
                machine: s.import_from.clone(),
                sha256: s.import_sha.clone(),
            });
        }
        if let Some(t) = &s.task_config {
            c.task = Some(t.clone());
        } else if crate::tasks::is_task_harness(&s.harness) {
            c.task = self.st.do_(|d| {
                crate::tasks::instance_by_session(d, &s.id).map(|i| TaskConfig {
                    instance: i.id.clone(),
                    name: i.name.clone(),
                    params: Some(i.params.clone().into_iter().collect()),
                })
            });
        }
        Ok(jarvis_go::marshal(&c))
    }

    /// a resume's one-time inputs — the pending resume prompt and the rollback asked for this predecessor — when the
    /// core vouches (they then need the phone; the old paths deliver neither); "" = none
    pub fn resume_once(&self, s: &Session) -> String {
        let mut o = OnceInputs {
            prompt: self.st.do_(|d| {
                d.schedules
                    .get(&s.id)
                    .map(|sc| sc.resume_prompt.clone())
                    .unwrap_or_default()
            }),
            ..Default::default()
        };
        if let Some(rb) = s.ops.as_ref().and_then(|ops| ops.rollback.as_ref())
            && !rb.marker.is_empty()
            && crate::sessionops::cert_machine(s.cert.as_ref()) == rb.pred
        {
            o.rollback = rb.marker.clone();
        }
        if o == OnceInputs::default() {
            return String::new();
        }
        jarvis_go::marshal(&o)
    }

    /// the approved resume carried them in its cert: nothing delivers them again
    pub fn once_taken(&self, sid: &str) {
        self.st.do_(|d| {
            if let Some(sc) = d.schedules.get_mut(sid) {
                sc.resume_prompt.clear();
            }
            if let Some(ops) = d.sessions.get_mut(sid).and_then(|s| s.ops.as_mut()) {
                ops.rollback = None;
            }
        });
    }

    /// kill, naming the machine's last snapshot (its sha256 and the machine's signature over it) so the successor's cert
    /// names exactly that one. require_snapshot (a pause): the core keeps the machine (409) rather than kill it without
    /// vouching for that snapshot; without it (a destroy, a takeover of a long-dead machine) a snapshot the core can't
    /// check doesn't stop the kill, it just isn't named (core.go Kill, DECISIONS 190).
    pub fn kill_machine(&self, machine: &str, require_snapshot: bool) -> Result<Option<Doc>> {
        let mut input = json!({"machine": machine});
        if let Some(s) = self.snap(machine).filter(|s| s.state == "committed") {
            input["snapshot"] =
                json!({"sha256": s.sha256, "sig": s.sig, "required": require_snapshot});
        }
        if let Ok(key) = self.core.key()
            && let Some(l) = self.legacy_for(
                machine,
                key.get("signingKey").map(String::as_str).unwrap_or(""),
            )
        {
            input["legacy"] = l; // legacy.rs: an earlier core's machine, its line taken over at this kill
        }
        let kd = self.kill_until_destroyed(&input)?;
        self.adopted(machine, Some(&kd));
        Ok(Some(kd))
    }

    /// the values the machine takes from the router alone (each a strict format)
    pub fn machine_config(self: &Arc<Self>, machine: &str) -> Result<Value> {
        let sid = self.machine_session(machine)?;
        let s = self
            .st
            .do_(|d| d.sessions.get(&sid).cloned())
            .unwrap_or_default();
        let e = self.machine_env(&s); // the same hooks as the env (Discord channel, task run, live sync)
        let get = |k: &str| e.get(k).cloned().unwrap_or_default();
        let mut out = json!({"sessionId": s.id, "discordChannel": get("LOBSTER_CHANNEL"), "taskRun": get("JARVIS2_TASK_RUN"),
            "taskTrigger": get("TASK_TRIGGER")});
        if let Ok(n) = get("JARVIS2_LIVE_SYNC_SECONDS").parse::<i64>() {
            out["liveSyncSeconds"] = json!(n);
        }
        let p = crate::remote::tunnel_proof(
            &std::env::var("JARVIS2_TUNNEL_KEY").unwrap_or_default(),
            &sid,
        );
        if !p.is_empty() {
            out["tunnelProof"] = json!(p);
        }
        Ok(out)
    }

    /// d into the machine's queue (mq.rs), and its answer within wait (None: none came)
    pub fn deliver_await(
        &self,
        machine: &str,
        d: &Delivery,
        wait: Duration,
    ) -> Result<Option<DeliveryResult>> {
        self.mq_put(machine, "delivery", &d.id, &serde_json::to_value(d)?, 0)?;
        match self.mq_await(&d.id, wait, None) {
            Ok(Some(ans)) => Ok(Some(jarvis_go::unmarshal(&ans).unwrap_or_default())),
            other => {
                self.mq_forget(&d.id);
                other.map(|_| None)
            }
        }
    }

    /// resume the session when it is paused, wait for it, then hand the machine the delivery with the core's
    /// attestation and wait for its answer. A message that waits for Deyao's approval (messages.rs) counts as handed
    /// over: the approval queue delivers it, or tells whoever asked.
    pub fn deliver_vouched(self: &Arc<Self>, sid: &str, d: Delivery) -> Result<()> {
        handed_over(self.deliver_vouched_opts(sid, d, true, None))
    }

    /// only into a running session (Skip otherwise): nothing is started for it (outcomes.rs)
    pub fn deliver_vouched_running(self: &Arc<Self>, sid: &str, d: Delivery) -> Result<()> {
        handed_over(self.deliver_vouched_opts(sid, d, false, None))
    }

    /// o is who is told when a held message is denied, lapses or fails (messages.rs message_origin covers the session's
    /// own wakeups, crons and watches); AwaitingApproval = held for Deyao
    pub fn deliver_vouched_opts(
        self: &Arc<Self>,
        sid: &str,
        mut d: Delivery,
        boot: bool,
        o: Option<&Origin>,
    ) -> Result<()> {
        use crate::messages as msg;
        use crate::schedule::skip;
        // messages.rs: into a session holding a sensitive store (and any resume prompt) only as the phone approved it
        let mut gated = d.approval.is_none() && self.needs_approval(sid, &d);
        if gated && let Some(rule) = self.rule_for(sid, &d.kind) {
            d.approval = Some(rule);
            gated = false;
        }
        let (state, _) = self.session_state(sid);
        if gated && state != "started" && !msg::preview_only(&d.kind) {
            // held without starting anything: the router renders this kind itself
            let Some((text, from, note)) = msg::message_text(&d) else {
                return Err(anyhow!(
                    "a {} delivery the router can't render: not delivered",
                    d.kind
                ));
            };
            self.hold_message(sid, &d, &text, &from, &note, o)?;
            return Err(msg::awaiting_approval());
        }
        if !boot && state != "started" {
            if state.is_empty() {
                return Err(crate::sessionapi::no_session());
            }
            return Err(skip(&format!("the session is {state}")));
        }
        match state.as_str() {
            "" => return Err(crate::sessionapi::no_session()),
            "paused" => {
                if let Err(e) = self.resume(sid, false) {
                    if crate::drain::is_busy(&e) {
                        return Err(skip(""));
                    }
                    return Err(e);
                }
            }
            "pausing" | "destroying" | "approval" => {
                return Err(skip(&format!("the session is {state}")));
            }
            "failed" => {
                return Err(anyhow!(
                    "the session has failed: Restart it (or Resume) and it gets this"
                ));
            }
            _ => {}
        }
        self.wait_started(sid)?;
        if gated {
            // the running machine renders the exact text Deyao sees
            let (text, note) = match self.preview_text(sid, &d) {
                Err(e) if msg::is_no_preview(&e) => {
                    // an image from before message approvals: Jarvis's rendering (messages.rs)
                    let Some(t) = msg::old_image_text(&d) else {
                        return Err(anyhow!(
                            "a {} delivery into a machine that can't preview it, and the router can't render it: not delivered (restart the session onto the newest image)",
                            d.kind
                        ));
                    };
                    (
                        t,
                        format!("{} {}", msg::message_note(&d), msg::NO_PREVIEW_NOTE)
                            .trim()
                            .to_string(),
                    )
                }
                Err(e) => return Err(e),
                Ok(t) => (t, msg::message_note(&d)),
            };
            self.hold_message(sid, &d, &text, &msg::message_from(&d), &note, o)?;
            return Err(msg::awaiting_approval());
        }
        let (input, origin) = attested(&d)?;
        let sum = hex::encode(Sha256::digest(&input));
        let deadline = Instant::now() + crate::schedule::HARNESS_UP_MAX;
        loop {
            let machine = self.st.do_(|p| {
                p.sessions
                    .get(sid)
                    .map(|s| s.machine_id.clone())
                    .unwrap_or_default()
            });
            if machine.is_empty() {
                return Err(anyhow!("the session has no running machine"));
            }
            // kernelline.rs: the core's or the notary's log
            let a = self.attest_input(&machine, &d.kind, &origin, &sum)?;
            d.id = crate::util::rand_id();
            d.attest = Some(a);
            let out = self
                .deliver_await(&machine, &d, Duration::from_secs(60))?
                .unwrap_or_else(|| DeliveryResult {
                    id: d.id.clone(),
                    error: "the machine didn't answer within 60 s".into(),
                    ..Default::default()
                });
            if out.ok {
                if scheduled_kind(&d.kind) {
                    // autopilot.rs: idle after this turn pauses in minutes, not the hour
                    let now = crate::claudelogin::unix_ms();
                    self.st.do_(|p| {
                        if let Some(s) = p.sessions.get_mut(sid) {
                            s.live.get_or_insert_with(Default::default).scheduled_at = now;
                        }
                    });
                }
                return Ok(());
            }
            // the harness may still be booting: retry while nobody listens yet (quick at first: a resumed harness is
            // usually up within seconds, and the input lands soon after it is)
            if out.error.contains("target session not found") && Instant::now() < deadline {
                let left = deadline.saturating_duration_since(Instant::now());
                let step = if left < crate::schedule::HARNESS_UP_MAX - Duration::from_secs(20) {
                    crate::schedule::SCHEDULE_WAIT_STEP
                } else {
                    crate::schedule::HARNESS_RETRY_FAST
                };
                std::thread::sleep(step);
                continue;
            }
            if out.needs_approval && !out.text.is_empty() {
                // the machine renders another text than the phone signed: Deyao sees it
                d.approval = None;
                self.hold_message(
                    sid,
                    &d,
                    &out.text,
                    &msg::message_from(&d),
                    &msg::message_note(&d),
                    o,
                )?;
                return Err(msg::awaiting_approval());
            }
            return Err(anyhow!("the machine refused or failed: {}", out.error));
        }
    }

    /// the running core is one from before R2 (it answers POST /input-log). Re-checked every minute: a core restart is
    /// a new core, possibly another version.
    pub fn core_keeps_input_log(&self) -> bool {
        let url = self.core.url();
        let last = KEPT_LOG_PROBE
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&url)
            .copied();
        if let Some((at, keeps)) = last
            && at.elapsed() < Duration::from_secs(60)
        {
            return keeps;
        }
        match self
            .core
            .raw("POST", "/input-log", Some(br#"{"from":1099511627776}"#))
        {
            Err(_) => last.is_some_and(|l| l.1), // unreachable: keep the last answer
            Ok((st, _)) => {
                KEPT_LOG_PROBE
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(url, (Instant::now(), st == 200));
                st == 200
            }
        }
    }

    /// entries from the core's answers, appended (empty ones skipped). With a core that keeps its own log, that log is
    /// read instead.
    pub fn log_inputs(&self, e: Option<&Doc>) {
        if let Some(e) = e {
            self.log_inputs_all(&[e]);
        }
    }

    pub fn log_inputs_all(&self, entries: &[&Doc]) {
        if self.core_keeps_input_log() {
            self.persist_input_log();
            return;
        }
        let _g = INPUT_LOG.lock().unwrap_or_else(|e| e.into_inner());
        let rows: Vec<String> = entries
            .iter()
            .filter(|e| !e.payload.is_empty())
            .map(|e| jarvis_go::marshal(*e))
            .collect();
        let refs: Vec<&[u8]> = rows.iter().map(|r| r.as_bytes()).collect();
        if let Err(e) = self.st.append_log("", LOG_INPUT, &refs) {
            crate::logf!("[input-log] {e:#}");
        }
    }

    /// the core before R2 — its new entries, read from it (POST /input-log); a new core of that kind first continues
    /// from the last persisted entry (chain_from)
    pub fn persist_input_log(&self) {
        let mut g = INPUT_LOG.lock().unwrap_or_else(|e| e.into_inner());
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct Out {
            entries: Vec<Doc>,
            head: Doc,
        }
        let Ok((200, b)) = self.core.raw(
            "POST",
            "/input-log",
            Some(format!(r#"{{"from":{}}}"#, g.next).as_bytes()),
        ) else {
            return;
        };
        let Ok(out) = jarvis_go::unmarshal::<Out>(&b) else {
            return;
        };
        let head = out.head.decode::<Seq>().unwrap_or_default();
        if head.seq < g.next {
            // a new core: its log starts again at 0
            g.next = 0;
            g.chained = false;
            self.persist_input_log_locked(&mut g, 0);
            return;
        }
        self.append_input_log(&mut g, &out.entries);
    }

    fn persist_input_log_locked(&self, g: &mut InputLog, from: i64) {
        if !g.chained {
            g.chained = true;
            let last = self.last_input_line();
            if let Ok(d) = jarvis_go::unmarshal::<Doc>(last.as_bytes())
                && !d.payload.is_empty()
            {
                let head = hex::encode(Sha256::digest(d.payload.as_bytes()));
                if let Err(e) = self
                    .core
                    .call("/input-log/chain-from", &json!({"head": head}))
                {
                    crate::logf!("[input-log] chain_from: {e:#}");
                }
            }
        }
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct Out {
            entries: Vec<Doc>,
        }
        if let Ok((200, b)) = self.core.raw(
            "POST",
            "/input-log",
            Some(format!(r#"{{"from":{from}}}"#).as_bytes()),
        ) && let Ok(out) = jarvis_go::unmarshal::<Out>(&b)
        {
            self.append_input_log(g, &out.entries);
        }
    }

    fn append_input_log(&self, g: &mut InputLog, entries: &[Doc]) {
        if entries.is_empty() {
            return;
        }
        let mut rows = vec![];
        let mut next = g.next;
        for e in entries {
            let x = e.decode::<Seq>().unwrap_or_default();
            if x.seq < next {
                continue;
            }
            rows.push(jarvis_go::marshal(e));
            next = x.seq + 1;
        }
        let refs: Vec<&[u8]> = rows.iter().map(|r| r.as_bytes()).collect();
        if let Err(e) = self.st.append_log("", LOG_INPUT, &refs) {
            crate::logf!("[input-log] {e:#}");
            return;
        }
        g.next = next;
    }

    /// the input log's newest entry ("" when none)
    fn last_input_line(&self) -> String {
        self.st
            .tail_log("", LOG_INPUT, 1)
            .ok()
            .and_then(|l| l.into_iter().next())
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .unwrap_or_default()
    }

    /// every minute, for the core before R2 (it logs certs by itself, without a router call)
    pub fn input_log_tick(&self) {
        if !self.core_keeps_input_log() {
            return;
        }
        let first = !INPUT_LOG.lock().unwrap_or_else(|e| e.into_inner()).chained;
        if first {
            let mut g = INPUT_LOG.lock().unwrap_or_else(|e| e.into_inner());
            self.persist_input_log_locked(&mut g, 0);
            return;
        }
        self.persist_input_log();
    }

    pub fn input_log_loop(self: &Arc<Self>) {
        loop {
            crate::leaderlease::await_lead();
            self.input_log_tick();
            std::thread::sleep(Duration::from_secs(60));
        }
    }
}

pub fn register_vouch(reg: &mut Registrar) {
    reg.m("GET /m/config", |r, w, _, machine, _| {
        match r.machine_config(machine) {
            Err(e) => write_json(w, 403, &json!({"error": format!("{e:#}")})),
            Ok(out) => write_json(w, 200, &out),
        }
    });
    reg.m("GET /m/restore-cert", |r, w, _, machine, _| {
        let (cert, cc) = r.st.do_(|d| {
            d.machines
                .get(machine)
                .and_then(|sid| d.sessions.get(sid))
                .filter(|s| s.machine_id == machine)
                .map(|s| (s.restore_cert.clone(), s.restore_core_cert.clone()))
                .unwrap_or((None, None))
        });
        let Some(cert) = cert else {
            return write_json(w, 404, &json!({"error": "no restore for this session"}));
        };
        let mut out = json!({"cert": cert});
        if let Some(cc) = cc {
            // rust/machine/src/restore.rs: an earlier core's cert, through the master key's claim of it
            out["coreCert"] = json!(cc);
            out["coreState"] = json!(r.core_state_doc());
        }
        write_json(w, 200, &out);
    });
    reg.m("POST /m/delivery-result", |r, w, _, _, body| {
        let res: DeliveryResult = jarvis_go::unmarshal(body).unwrap_or_default();
        // mq.rs: to whichever replica waits for it
        if let Err(e) = r.mq_answer(&res.id, &serde_json::to_value(&res).unwrap_or_default()) {
            crate::logf!("delivery {}: its answer: {e:#}", res.id);
        }
        write_json(w, 200, &json!({"ok": true}));
    });
    reg.app("GET /api/input-log", |r, w, req| {
        let mut n: i64 = req.query("last").parse().unwrap_or(0);
        if n <= 0 || n > 2000 {
            n = 200;
        }
        match r.st.tail_log("", LOG_INPUT, n) {
            Err(e) => write_err(w, &e),
            Ok(lines) => {
                let out: Vec<Value> = lines
                    .iter()
                    .filter_map(|l| serde_json::from_slice(l).ok())
                    .collect();
                write_json(w, 200, &json!({"entries": out}));
            }
        }
    });
}
