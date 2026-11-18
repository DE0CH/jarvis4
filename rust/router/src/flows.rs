//! The core's primitives, as the router chains them (flows.go): a new session, its approvals, pause, resume,
//! destroy, a store added or dropped in place, commands to machines.

use crate::core::{CoreError, Doc};
use crate::inbox::Origin;
use crate::router::{Router, bad};
use crate::state::{Approval, Record, Session, Started};
use crate::util::{OnceFn, rand_id};
use anyhow::{Result, anyhow};
use jarvis_go::GoTime;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct NewSession {
    #[serde(rename = "requestId")]
    pub request_id: String,
    pub label: String,
    pub prompt: String,
    pub model: String,
    #[serde(rename = "permissionMode")]
    pub permission_mode: String,
    pub size: String,
    /// regions.rs: "" = the router's default
    pub region: String,
    /// awsrunner.rs: aws | fly | fabric, "" = DEFAULT_RUNNER
    pub runner: String,
    pub harness: String,
    pub stores: Vec<String>,
    pub repos: String,
    /// content stores (content.rs), signed with the line
    pub content: Vec<String>,
    /// claudeaccounts.rs: the Claude account (claude-<name> or <name>); "" = the default
    pub account: String,
    /// tasks.rs: a prompt task's line runs claude -p
    #[serde(skip)]
    pub needs_account: bool,
    /// destroyed once its prompt is done (autopilot.rs)
    #[serde(rename = "oneShot")]
    pub one_shot: bool,
    /// default on
    #[serde(rename = "autoPause")]
    pub auto_pause: Option<bool>,
    /// SESSION_API_PROXY (sessionops.rs)
    #[serde(rename = "apiProxy")]
    pub api_proxy: bool,
    /// first-prompt attachments (uploads.rs)
    pub attachments: Option<crate::uploads::AttachmentsIn>,
    /// uploads.rs: whose uploads Attachments may name ("" = the app's)
    #[serde(skip)]
    pub attach_owner: String,
    /// inbox.rs: who asked, from the credential (the handler sets it)
    #[serde(skip)]
    pub origin: Option<Origin>,
    /// a session's proposal: its reason, shown with the approval (sessionapi.rs)
    #[serde(skip)]
    pub explanation: String,
    /// tasks.rs: a task line's instance and parameters
    #[serde(skip)]
    pub task: Option<crate::types::TaskConfig>,
    /// jarvis1import.rs: the paused Jarvis 1 session this line restores
    #[serde(skip)]
    pub import: Option<crate::jarvis1import::J1ImportRef>,
    /// batches.rs: the batch its approval belongs to
    #[serde(skip)]
    pub batch: String,
}

/// a succession to it burns the predecessor (core.NullImage)
pub const NULL_IMAGE: &str = "null";

/// the core opens it only inside a deploy-key call (core/deploykeys.go)
pub const DEPLOY_KEY_TOKEN_STORE: &str = "github-deploy-keys";

/// the router's waits on the core's single-shot machine calls (ms; tests shorten them)
pub static INIT_STEP_MS: AtomicU64 = AtomicU64::new(5_000);
pub static INIT_MAX_MS: AtomicU64 = AtomicU64::new(12 * 60_000);
pub static KILL_STEP_MS: AtomicU64 = AtomicU64::new(1_000);
pub static KILL_MAX_MS: AtomicU64 = AtomicU64::new(45 * 60_000);
/// how long a start waits out Fly's org machine limit, and how often it tries
pub static MACHINE_LIMIT_WAIT_MS: AtomicU64 = AtomicU64::new(3 * 3600_000);
pub static MACHINE_LIMIT_STEP_MS: AtomicU64 = AtomicU64::new(60_000);
/// how often and how far apart a kill that failed on the way is tried again
pub static KILL_TRANSIENT_TRIES: AtomicI64 = AtomicI64::new(4);
pub static KILL_TRANSIENT_STEP_MS: AtomicU64 = AtomicU64::new(30_000);
/// a booted machine whose last report is older than this isn't asked for a snapshot (s)
pub static SILENT_AFTER_SECS: AtomicI64 = AtomicI64::new(180);

fn ms(a: &AtomicU64) -> Duration {
    Duration::from_millis(a.load(Ordering::Relaxed))
}

pub fn flyl_machine_limit(err: &anyhow::Error) -> bool {
    fly_machine_limit_text(&format!("{err:#}"))
}

pub fn fly_machine_limit_text(s: &str) -> bool {
    s.to_lowercase().contains("machine limit")
}

/// Fly's org machine limit as a known error (Deyao, 2026-11-17): said in these words wherever it surfaces, never as
/// Fly's raw 422. It keeps "machine limit", so fly_machine_limit still matches it.
pub const FLY_LIMIT_TEXT: &str = "Fly's machine limit is reached: the Fly org already has as many machines as Fly allows it, so no new one starts until another session pauses or Fly raises the limit";

/// an error as Deyao reads it: the known text for Fly's machine limit, else the error itself (trimmed)
pub fn known_error(err: &anyhow::Error) -> String {
    if flyl_machine_limit(err) {
        return FLY_LIMIT_TEXT.into();
    }
    crate::util::trim_to(&format!("{err:#}"), 300)
}

fn core_err(e: &anyhow::Error) -> Option<&CoreError> {
    e.downcast_ref::<CoreError>()
}

/// one new cert of a running machine at a time (an add-store answer, a downgrade's finish); one lock per machine for
/// the process's life (a few bytes each)
static SELF_SUCCESSION_LOCKS: std::sync::LazyLock<Mutex<BTreeMap<String, &'static Mutex<()>>>> =
    std::sync::LazyLock::new(|| Mutex::new(BTreeMap::new()));

pub fn self_succession_lock(machine: &str) -> std::sync::MutexGuard<'static, ()> {
    let m: &'static Mutex<()> = *SELF_SUCCESSION_LOCKS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .entry(machine.to_string())
        .or_insert_with(|| Box::leak(Box::new(Mutex::new(()))));
    m.lock().unwrap_or_else(|e| e.into_inner())
}

pub fn contains_string(list: &[String], x: &str) -> bool {
    list.iter().any(|s| s == x)
}

/// every name of want is in have
pub fn contains_all(have: &[String], want: &[String]) -> bool {
    want.iter().all(|w| contains_string(have, w))
}

/// the stores sorted, each once (the core takes them only so)
pub fn sorted_set(xs: &[String]) -> Vec<String> {
    let mut v: Vec<String> = xs.to_vec();
    v.sort();
    v.dedup();
    v
}

pub fn norm_mode(m: &str) -> &'static str {
    if m == "bypass" { "bypass" } else { "auto" }
}

/// the permission mode the line's cert signs (a machine succeeding itself keeps it)
pub fn cert_mode(c: Option<&Doc>) -> &'static str {
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct O {
        #[serde(rename = "permissionMode")]
        permission_mode: String,
    }
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct X {
        options: O,
    }
    let Some(c) = c else { return "auto" };
    let x: X = c.decode().unwrap_or_default();
    norm_mode(&x.options.permission_mode)
}

/// the stores and harness the line's cert names (the fallbacks when it names none)
pub fn cert_stores_harness(c: Option<&Doc>, stores: &[String], harness: &str) -> (Vec<String>, String) {
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct O {
        harness: String,
    }
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct X {
        stores: Option<Vec<String>>,
        options: O,
    }
    let (mut s, mut h) = (stores.to_vec(), harness.to_string());
    let Some(c) = c else { return (s, h) };
    let Ok(x) = c.decode::<X>() else { return (s, h) };
    if let Some(st) = x.stores {
        s = st;
    }
    if !x.options.harness.is_empty() {
        h = x.options.harness;
    }
    (s, h)
}

/// the image the line's cert says its machine ran (what Fly reported, repo@digest); fallback when none
pub fn cert_image(c: Option<&Doc>, fallback: &str) -> String {
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct M {
        image: String,
    }
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct X {
        machine: Option<M>,
    }
    match c.and_then(|c| c.decode::<X>().ok()).and_then(|x| x.machine) {
        Some(m) if !m.image.is_empty() => m.image,
        _ => fallback.to_string(),
    }
}

/// the core's approve_by_dead_machine refusing a resume because it doesn't see the same line
pub fn refused_same_line(err: &anyhow::Error) -> bool {
    core_err(err).is_some_and(|c| c.status == 403 && c.msg.contains("differ from the predecessor"))
}

/// a session's state for a message ("gone" when there is none)
pub fn or_state(state: &str) -> &str {
    if state.is_empty() { "gone" } else { state }
}

/// "10 min", "45 s"
pub fn wait_text(d: Duration) -> String {
    if d >= Duration::from_secs(60) {
        return format!("{} min", (d.as_secs_f64() / 60.0).round() as i64);
    }
    format!("{} s", d.as_secs())
}

/// an approval Deyao asked for himself (the app or the web page), not one a session or the router filed
pub fn deyaos_own(o: Option<&Origin>) -> bool {
    o.is_none_or(|o| matches!(o.caller.kind.as_str(), "" | "app" | "web"))
}

// ---- session images ----------------------------------------------------------------------------------------------

/// session-image-sigs.txt as mounted ("<image> <sig>" per line; images.yml appends one per pin)
pub fn load_image_sigs(path: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    if path.is_empty() {
        return out;
    }
    match std::fs::read_to_string(path) {
        Err(e) => crate::logf!("session image signatures: {e}"),
        Ok(b) => {
            for l in b.lines() {
                let f: Vec<&str> = l.split_whitespace().collect();
                if f.len() == 2 {
                    out.insert(f[0].to_string(), f[1].to_string());
                }
            }
        }
    }
    out
}

/// the images of session-image-sigs.txt in line order
pub fn load_image_order(path: &str) -> Vec<String> {
    if path.is_empty() {
        return vec![];
    }
    std::fs::read_to_string(path)
        .map(|b| {
            b.lines()
                .filter_map(|l| {
                    let f: Vec<&str> = l.split_whitespace().collect();
                    (f.len() == 2).then(|| f[0].to_string())
                })
                .collect()
        })
        .unwrap_or_default()
}

/// the first pinned session image whose machine takes the Claude login from the router (2026-10-13 01:39)
pub const FIRST_ROUTER_LOGIN_IMAGE: &str = ":sha-c5427052a542@";

/// the sha256:… part of a ref@digest (the whole string when it names no digest)
pub fn image_digest(s: &str) -> &str {
    match s.rfind('@') {
        Some(i) => &s[i + 1..],
        None => s,
    }
}

/// the ref CI pinned and signed (ref:sha-…@digest) for image's digest; unchanged when no pin has the digest
pub fn pinned_image(image: &str, current: &str, order: &[String]) -> String {
    if !image.contains('@') {
        return image.to_string();
    }
    let d = image_digest(image);
    if image_digest(current) == d {
        return current.to_string();
    }
    order
        .iter()
        .find(|o| image_digest(o) == d)
        .cloned()
        .unwrap_or_else(|| image.to_string())
}

/// image is a pin older than FIRST_ROUTER_LOGIN_IMAGE, by its digest's place in the pin order
pub fn legacy_login_image(image: &str, order: &[String]) -> bool {
    let Some(mark) = order.iter().position(|o| o.contains(FIRST_ROUTER_LOGIN_IMAGE)) else {
        return false;
    };
    if image.is_empty() {
        return false;
    }
    let d = image_digest(image);
    match order.iter().position(|o| image_digest(o) == d) {
        Some(i) => i < mark,
        None => true,
    }
}

/// destroy's options: force = destroy even when the archive failed; report (oneshot.rs) gets, once the line is burnt
/// and the session is a record, the repos' state as the final snapshot recorded it and what the archive did
#[derive(Default, Clone)]
pub struct DestroyOpts {
    pub force: bool,
    #[allow(clippy::type_complexity)]
    pub report: Option<
        Arc<
            dyn Fn(&Session, Option<serde_json::Map<String, Value>>, Option<&crate::archive::ArchiveInfo>, Option<&anyhow::Error>)
                + Send
                + Sync,
        >,
    >,
}

impl Router {
    /// a session's lifecycle actions don't overlap, on any replica (jobs.rs: one running job per session); a clash
    /// is refused (409), not queued. Each lock is also a tracked lifecycle action of this process (drain.rs)
    pub fn lock(self: &Arc<Self>, id: &str, kind: &str) -> Result<OnceFn> {
        self.lock_args(id, kind, Value::Null)
    }

    /// lock with what a replica that carries the job on needs (jobs.rs carry_on)
    pub fn lock_args(self: &Arc<Self>, id: &str, kind: &str, args: Value) -> Result<OnceFn> {
        let done = self.begin(id, kind)?;
        let jid = match self.job_start(id, kind, args) {
            Ok(j) => j,
            Err(e) => {
                done.call();
                return Err(e);
            }
        };
        let hold = self.job_hold(&jid);
        let unlock = self.job_unlock(id, kind, hold);
        Ok(OnceFn::new(move || {
            unlock.call();
            done.call();
        }))
    }

    /// a lifecycle action holds the session (on any replica)
    pub fn busy(&self, id: &str) -> bool {
        self.job_busy(id)
    }

    pub fn set_state(&self, id: &str, state: &str, err_msg: &str) {
        self.st.do_(|d| {
            if let Some(s) = d.sessions.get_mut(id) {
                s.state = state.into();
                s.error = err_msg.into();
            }
        });
        if !err_msg.is_empty() {
            crate::logf!("session {id}: {state}: {err_msg}");
        }
    }

    pub fn machine_env(self: &Arc<Self>, s: &Session) -> BTreeMap<String, String> {
        let mut e: BTreeMap<String, String> = [
            ("JARVIS2_URL", self.cfg.machine_url.as_str()),
            ("JARVIS2_SESSION_ID", s.id.as_str()),
            ("SESSION_LABEL", s.label.as_str()),
            ("SESSION_MODEL", s.model.as_str()),
            ("SESSION_PERMISSION_MODE", s.permission_mode.as_str()),
            ("JARVIS2_REPOS", s.repos.as_str()),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        if !s.prompt.is_empty() {
            e.insert("SESSION_PROMPT".into(), s.prompt.clone());
        }
        if s.label.is_empty() && !s.app_title.is_empty() {
            // the title the Claude app showed: a resumed claude names a fresh Remote Control entry with it
            e.insert("SESSION_RESUME_TITLE".into(), s.app_title.clone());
        }
        for h in crate::features::env_hooks() {
            h(self, s, &mut e);
        }
        e
    }

    /// a challenge, before any machine exists. machine is set only for adding a store. config and once:
    /// Options.Config and Options.Once (vouch.rs)
    #[allow(clippy::too_many_arguments)]
    pub fn succession(
        &self,
        pred: Option<&Doc>,
        machine: &str,
        stores: &[String],
        harness: &str,
        mode: &str,
        image: &str,
        config: &str,
        once: &str,
    ) -> Result<Doc> {
        // the defaults are the router's: the core refuses rather than fills in (R2)
        let mode = if mode == "bypass" { "bypass" } else { "auto" };
        let harness = if harness.is_empty() { "claude" } else { harness };
        let mut opts: BTreeMap<&str, &str> = [("harness", harness), ("permissionMode", mode)].into_iter().collect();
        if !config.is_empty() {
            opts.insert("config", config);
        }
        if !once.is_empty() {
            opts.insert("once", once);
        }
        if image == NULL_IMAGE {
            opts.clear();
        }
        let mut input = json!({"predecessor": pred, "machine": machine, "stores": sorted_set(stores), "options": opts, "image": image});
        if pred.is_none() {
            input["salt"] = json!(format!("{}{}", rand_id(), rand_id())); // a new line: two identical requests differ
        }
        self.core.call("/succession", &input)
    }

    pub fn start_machine(self: &Arc<Self>, image: &str, size: &str) -> Result<Doc> {
        self.start_machine_with(image, size, "", 0, None, true)
    }

    /// start_machine with the machine's region ("" = the router's default) and volume size (disk.rs; 0 = the core's
    /// default); created: told the machine's id as soon as the core's Fly create made it
    pub fn start_machine_disk(
        self: &Arc<Self>,
        image: &str,
        size: &str,
        region: &str,
        disk_gb: i64,
        created: Option<&dyn Fn(&str)>,
    ) -> Result<Doc> {
        self.start_machine_with(image, size, region, disk_gb, created, true)
    }

    /// The core's start (one Fly create), then its init until Fly reports the machine up and the image's init
    /// command gave its keys → the core's signed "started" document. A machine that never comes up is killed.
    /// wait_limit = wait out Fly's org machine limit (a handover's spare doesn't: handover.rs)
    pub fn start_machine_with(
        self: &Arc<Self>,
        image: &str,
        size: &str,
        region: &str,
        disk_gb: i64,
        created: Option<&dyn Fn(&str)>,
        wait_limit: bool,
    ) -> Result<Doc> {
        let size = if size.is_empty() { "medium" } else { size };
        let region = if region.is_empty() { self.cfg.region.as_str() } else { region };
        let mut input = json!({"image": image, "region": region, "size": size});
        if disk_gb > 0 {
            input["diskGb"] = json!(disk_gb);
        }
        let mut d = self.core.call("/start", &input);
        // Fly's org machine limit (lessons/58): nothing was created and the approval is still unused, so wait for a
        // machine to go (sessions pause by themselves) instead of failing a start Deyao already approved
        let mut waited = Duration::ZERO;
        while wait_limit
            && d.as_ref().is_err_and(flyl_machine_limit)
            && waited < ms(&MACHINE_LIMIT_WAIT_MS)
        {
            if self.draining() {
                return Err(crate::drain::limit_draining());
            }
            let step = ms(&MACHINE_LIMIT_STEP_MS);
            crate::logf!(
                "start: the Fly org is at its machine limit; trying again in {}",
                jarvis_go::fmt::duration_string(step)
            );
            if self.sleep_unless_draining(step) {
                return Err(crate::drain::limit_draining());
            }
            waited += step;
            d = self.core.call("/start", &input);
        }
        let d = d?;
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct C {
            kind: String,
            id: String,
        }
        let c: C = d.decode().unwrap_or_default();
        if c.kind != "created" {
            return Ok(d);
        }
        if let Some(f) = created {
            f(&c.id);
        }
        let deadline = Instant::now() + ms(&INIT_MAX_MS);
        loop {
            match self.core.call("/init", &json!({"machine": c.id})) {
                Ok(st) => return Ok(st),
                Err(e) => {
                    let retry = core_err(&e)
                        .is_some_and(|ce| ce.status == 502 || (ce.status == 409 && ce.msg.contains("not started")));
                    if !retry || Instant::now() > deadline {
                        let _ = self.kill_until_destroyed(&json!({"machine": c.id}));
                        return Err(e);
                    }
                    std::thread::sleep(ms(&INIT_STEP_MS));
                }
            }
        }
    }

    /// The core's kill (one Fly destroy) again until Fly reports the machine destroyed (409 before). A kill that
    /// failed on the way (Fly's API timing out, 502, the core not answering) is tried again a few times over a few
    /// minutes (DECISIONS 181). A refusal (403, 400) is final.
    pub fn kill_until_destroyed(&self, input: &Value) -> Result<Doc> {
        let deadline = Instant::now() + ms(&KILL_MAX_MS);
        let mut transient = 0;
        loop {
            match self.core.call("/kill", input) {
                Ok(d) => return Ok(d),
                Err(e) => {
                    let ce = core_err(&e);
                    if ce.is_some_and(|c| c.status == 409) && Instant::now() < deadline {
                        std::thread::sleep(ms(&KILL_STEP_MS));
                    } else if ce.is_none_or(|c| c.status >= 500)
                        && transient < KILL_TRANSIENT_TRIES.load(Ordering::Relaxed)
                    {
                        transient += 1;
                        crate::logf!(
                            "kill {}: {e:#}; trying again ({transient} of {})",
                            input["machine"].as_str().unwrap_or(""),
                            KILL_TRANSIENT_TRIES.load(Ordering::Relaxed)
                        );
                        std::thread::sleep(ms(&KILL_TRANSIENT_STEP_MS));
                    } else {
                        return Err(e);
                    }
                }
            }
        }
    }

    /// an approval → a machine on the approved image → its cert. The core's start is open (it can't lead to a
    /// secret); certify binds the approval to that one machine.
    pub fn start_and_certify(self: &Arc<Self>, sid: &str, approval: &Doc) {
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct Rq {
            image: String,
            #[serde(rename = "predecessorId")]
            pred_id: String,
        }
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct A {
            request: Rq,
        }
        let a: A = approval.decode().unwrap_or_default();
        let s: Session = self.st.do_(|d| d.sessions.get(sid).cloned().unwrap_or_default());
        self.set_state(sid, "starting", "");
        // lifecycle.rs: the operation this start belongs to (a resume's), or a boot of its own; this function ends it
        let op = self
            .lc_current(sid)
            .unwrap_or_else(|| self.lc_begin(sid, if s.cert.is_some() { "resume" } else { "boot" }));
        op.set_handed();
        let fail = |msg: &str| {
            self.set_state(sid, "failed", msg);
            op.note("", msg);
            op.end_joined("failed", msg);
        };
        let size = if s.size.is_empty() { "medium".to_string() } else { s.size.clone() };
        // handover.rs: the machine started while the old one stopped, when it is the one this start asks for
        let region = self.region_of(&s);
        let next = crate::handover::NextMachine {
            image: a.request.image.clone(),
            size: s.size.clone(),
            region: region.clone(),
            disk_gb: s.disk_gb,
        };
        let d = match self.take_spare(sid, &next) {
            Some(d) => {
                op.note("", &format!("taking the next machine started while the old one stopped ({size}, image {})", a.request.image));
                Ok(d)
            }
            None => {
                op.note("", &format!("asked the core to start a machine ({size}, image {})", a.request.image));
                let created = |id: &str| {
                    op.machine(id);
                    op.note(id, &format!("the core's Fly create made machine {id}; waiting for it to come up and give its keys (init)"));
                };
                self.start_machine_disk(&a.request.image, &s.size, &region, s.disk_gb, Some(&created))
            }
        };
        let d = match d {
            Err(e) if flyl_machine_limit(&e) => {
                crate::logf!("start {sid}: {e:#}");
                fail(&format!("start: {FLY_LIMIT_TEXT}"));
                return;
            }
            Err(e) => {
                fail(&format!("start: {e:#}"));
                return;
            }
            Ok(d) => d,
        };
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct St {
            machine: Option<Started>,
        }
        let Some(m) = d.decode::<St>().ok().and_then(|x| x.machine) else {
            fail("start: unexpected answer");
            return;
        };
        op.machine(&m.id);
        op.note(&m.id, &format!("machine {} is up and gave its keys", m.id));
        self.st.do_(|dd| {
            dd.started.insert(m.id.clone(), m.clone());
            dd.machines.insert(m.id.clone(), sid.to_string());
        });
        let pred = a.request.pred_id.clone();
        let res = self.core.call_answer(
            "/certify",
            &json!({"approval": approval, "machine": m.id, "started": d, "carry": self.read_carry(&pred)}),
        );
        let (cert, ans) = match res {
            Err(e) => {
                op.note(&m.id, &format!("certify refused: {e:#}; asking the core to kill the machine"));
                let _ = self.kill_until_destroyed(&json!({"machine": m.id}));
                fail(&format!("certify: {e:#}"));
                return;
            }
            Ok(x) => x,
        };
        op.note(&m.id, "the core certified the machine (its succession cert); it boots now: snapshot, secrets, repos, then the harness");
        self.st.do_(|dd| {
            dd.certs.insert(m.id.clone(), cert.clone());
            if let Some(x) = dd.sessions.get_mut(sid) {
                x.cert = Some(cert.clone());
                x.machine_id = m.id.clone();
                x.image = m.image.clone();
                x.state = "initialising".into();
                x.error.clear();
                x.paused_at = None;
            }
        });
        self.log_inputs(ans.entry.as_ref()); // vouch.rs: the cert's input-log entry
        let p = crate::carry::pred_of(&cert);
        if !p.is_empty() {
            self.carry_after(&p, &m.id, &cert, &ans); // carry.rs: a resume carries the line's secrets
        }
        let r = self.clone();
        let (sid, mid) = (sid.to_string(), m.id.clone());
        std::thread::spawn(move || r.lc_await_boot(op, &sid, &mid));
    }

    pub fn add_approval(self: &Arc<Self>, mut a: Approval) -> String {
        a.id = rand_id();
        a.created = GoTime::now();
        if a.origin.is_none() {
            a.origin = crate::inbox::take_origin(&a.session); // inbox.rs: the caller the handler noted
        }
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct I {
            image: String,
        }
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct Ch {
            request: I,
            /// kernelline.rs: a cert into a new source names its image there
            source: I,
        }
        let mut img = String::new();
        if let Some(c) = &a.challenge
            && let Ok(ch) = c.decode::<Ch>()
        {
            img = ch.request.image;
            if img.is_empty() && a.kind == crate::kernelline::KERNEL_APPROVAL_KIND {
                img = ch.source.image;
            }
        }
        // a resume on the session's own image names an older CI build than the current one: its signature is listed
        let fabric = std::env::var("FABRIC_SESSION_IMAGE").unwrap_or_default();
        if !img.is_empty() && img == self.cfg.session_image {
            a.image_sig = self.cfg.session_image_sig.clone();
        } else if !img.is_empty() && img == fabric {
            a.image_sig = std::env::var("FABRIC_SESSION_IMAGE_SIG").unwrap_or_default(); // fabricrunner.rs
        } else if !img.is_empty() {
            a.image_sig = self.cfg.image_sigs.get(&img).cloned().unwrap_or_default();
        }
        let id = a.id.clone();
        let denied = self.st.do_(|d| {
            // a batch denied while this approval's challenge was being made: the approval goes the way the batch did
            let denied = !a.batch.is_empty() && !d.batches.contains_key(&a.batch);
            d.approvals.insert(a.id.clone(), a.clone());
            crate::apicalls::link_followup(d, &a); // apicalls.rs: an approved call's sheet follows it
            denied
        });
        if denied {
            let _ = self.reject(&id);
        }
        id
    }

    // ---- new session ----------------------------------------------------------------------------------------

    /// → the session's id. A requestId already on a session answers that session (idempotent).
    pub fn create_session(self: &Arc<Self>, mut input: NewSession) -> Result<String> {
        let mut h = self.policy.harnesses.get(&input.harness).cloned();
        if h.is_none() && crate::tasks::is_task_harness(&input.harness) {
            h = Some(Default::default()); // a task line (tasks.rs): the template's stores only, no harness stores
        }
        let h = match h {
            Some(h) => h,
            None => {
                input.harness = self.default_harness();
                self.policy
                    .harnesses
                    .get(&input.harness)
                    .cloned()
                    .ok_or_else(|| anyhow!("no harness {} in the policy", input.harness))?
            }
        };
        if input.size.is_empty() {
            input.size = "medium".into();
        }
        if !input.region.is_empty() && !crate::regions::valid_region(&input.region) {
            return Err(bad(format!("region {:?}: one of GET /api/regions", input.region)));
        }
        if !input.runner.is_empty() && !crate::awsrunner::valid_runner(&input.runner) {
            return Err(bad(format!("runner {:?}: aws or fly", input.runner)));
        }
        if input.runner.is_empty() {
            input.runner = crate::awsrunner::default_runner(); // fixed when made
        }
        input.model = crate::harness::session_model(&input.harness, &input.model)?;
        // bypass is the only start mode (Deyao, 2026-10-22): a running session may still switch (sessionops.rs)
        match input.permission_mode.as_str() {
            "" | "bypass" => input.permission_mode = "bypass".into(),
            m => {
                return Err(bad(format!(
                    "permission mode {m:?}: a new session always starts in bypass, the only start mode"
                )));
            }
        }
        // the harness's stores come with it (the policy document); the shared login's old store is gone: dropped
        let picked: Vec<String> = input
            .stores
            .iter()
            .filter(|n| n.as_str() != crate::claudestores::LEGACY_CLAUDE_STORE)
            .cloned()
            .collect();
        let stores = self.with_harness_stores(&picked, &h.stores)?;
        let account = self
            .accounts()
            .resolve(&input.account, h.claude_account || input.needs_account)
            .map_err(|e| bad(format!("{e:#}")))?;
        let stores = crate::claudestores::with_account_store(&stores, &account);
        let content = self.check_content_stores(&input.content)?; // content.rs: each an existing store
        let mut s = Session {
            id: format!("s{}", rand_id()),
            state: "approval".into(),
            created: GoTime::now(),
            label: input.label.clone(),
            prompt: input.prompt.clone(),
            model: input.model.clone(),
            permission_mode: input.permission_mode.clone(),
            size: input.size.clone(),
            region: input.region.clone(),
            runner: input.runner.clone(),
            harness: input.harness.clone(),
            stores: Some(stores),
            repos: input.repos.clone(),
            content: (!content.is_empty()).then_some(content),
            claude_account: account,
            request_id: input.request_id.clone(),
            live: Some(crate::autopilot::new_liveness(&input)),
            ..Default::default()
        };
        if let Some(i) = &input.import {
            s.import_from = i.session.clone();
            s.import_sha = i.sha256.clone();
        }
        let (dup, err) = self.st.do_(|d| match crate::autopilot::admit_session(d, &s, &input) {
            Ok(dup) => {
                if dup.is_empty() {
                    d.sessions.insert(s.id.clone(), s.clone());
                }
                (dup, None)
            }
            Err(e) => (String::new(), Some(e)),
        });
        if let Some(e) = err {
            return Err(e);
        }
        if !dup.is_empty() {
            return Ok(dup);
        }
        s.task_config = input.task.clone();
        let drop_it = |r: &Router| r.st.do_(|d| d.sessions.remove(&s.id).map(|_| ()));
        let config = match self.session_config(&s) {
            Ok(c) => c,
            Err(e) => {
                drop_it(self);
                return Err(e);
            }
        };
        // kernelline.rs: a new line goes on the kernel once it serves (D7); the old core's lines go on there
        let kernel = self.kernel_serves() && input.import.is_none() && !crate::tasks::is_task_harness(&s.harness);
        let mut ch = None;
        if !kernel {
            match self.succession(
                None,
                "",
                s.stores.as_deref().unwrap_or_default(),
                &s.harness,
                &s.permission_mode,
                &self.cfg.session_image,
                &config,
                "",
            ) {
                Ok(c) => ch = Some(c),
                Err(e) => {
                    drop_it(self);
                    return Err(e);
                }
            }
        }
        let mut opts: BTreeMap<String, String> = [
            ("model", s.model.clone()),
            ("size", s.size.clone()),
            ("permissionMode", s.permission_mode.clone()),
            ("repos", s.repos.clone()),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
        if !s.claude_account.is_empty() {
            opts.insert("claudeAccount".into(), s.claude_account.clone()); // the router's word, beside the challenge
        }
        if let Some(c) = &s.content {
            opts.insert("content".into(), c.join(","));
        }
        crate::autopilot::live_options(&s, &mut opts);
        crate::sessionops::ops_options(&s, &mut opts);
        if let Some(i) = &input.import {
            opts.insert("restore".into(), i.shown.clone()); // shown beside the signed "Restores machine" and hash
        }
        if kernel {
            if let Err(e) = self.kernel_new_session_approval(&s, &config, &opts, &input, "") {
                drop_it(self);
                return Err(e);
            }
            return Ok(s.id);
        }
        let r = self.clone();
        let a = Approval {
            kind: "new-session".into(),
            session: s.id.clone(),
            label: s.label.clone(),
            challenge: ch,
            options: opts,
            origin: input.origin.clone(),
            explanation: input.explanation.clone(),
            batch: input.batch.clone(),
            ..Default::default()
        };
        std::thread::spawn(move || {
            r.add_approval(a);
        });
        Ok(s.id)
    }

    /// the chosen stores plus the harness's, sorted (the core refuses unknown ones)
    pub fn with_harness_stores(&self, chosen: &[String], harness: &[String]) -> Result<Vec<String>> {
        let mut set = std::collections::BTreeSet::new();
        for n in chosen.iter().chain(harness.iter()) {
            if n == crate::claudestores::FLY_STORE {
                return Err(anyhow!("store {n} holds the core's Fly token and never goes to a session"));
            }
            if n == DEPLOY_KEY_TOKEN_STORE {
                return Err(anyhow!(
                    "store {n} holds the deploy-key token: only a phone-approved deploy-key call opens it"
                ));
            }
            set.insert(n.clone());
        }
        Ok(set.into_iter().collect())
    }

    // ---- approvals ------------------------------------------------------------------------------------------

    pub fn respond(self: &Arc<Self>, id: &str, signature: &str) -> Result<(Doc, String)> {
        self.expire_approvals(GoTime::now()); // an approval answered after inboxTTL is gone
        let a = self
            .st
            .do_(|d| d.approvals.get(id).cloned())
            .ok_or_else(|| anyhow!("no such approval (answered, denied or expired)"))?;
        if a.kind == "add-store" {
            return self.respond_add_store(&a, signature);
        }
        if a.kind == crate::kernelline::KERNEL_APPROVAL_KIND {
            return self.respond_kernel(&a, signature);
        }
        if a.kind == crate::kernelline::KERNEL_ADD_APPROVAL_KIND {
            return self.respond_kernel_add(&a, signature);
        }
        // a start the answer leads to is a tracked lifecycle action (drain.rs): during a drain the answer is refused
        // before the core uses it up, so the approval stays in the Inbox for the phone to answer again
        let done = self.begin(&a.session, "approved")?;
        let (ans, extra) = match self
            .core
            .call_answer("/approve/by-phone", &json!({"challenge": a.challenge, "signature": signature}))
        {
            Ok(x) => x,
            Err(e) => {
                done.call();
                return Err(e);
            }
        };
        self.log_inputs(extra.entry.as_ref());
        self.st.do_(|d| {
            d.approvals.remove(id);
            if a.kind == "new-session" {
                // outcomes.rs: the core's approval, by the phone, of exactly the proposal
                crate::outcomes::note_outcome(d, a.origin.as_ref(), &a.kind, &a.session, crate::outcomes::OUTCOME_APPROVED, 0, Some(&ans));
            }
        });
        let r = self.clone();
        let (sid, ans2) = (a.session.clone(), ans.clone());
        std::thread::spawn(move || {
            r.start_and_certify(&sid, &ans2);
            done.call();
        });
        Ok((ans, a.session))
    }

    /// The phone's answer to "add store X to this running machine". The core answers every add-store onto the
    /// machine's newest cert, which the router sends beside it as current (core addOnto). The router never stores an
    /// answer that loses a store the session holds: then the approval is filed again from the newest cert.
    pub fn respond_add_store(self: &Arc<Self>, a: &Approval, signature: &str) -> Result<(Doc, String)> {
        let _unlock = self_succession_lock(&a.machine);
        let (cur, have, chs) = self.st.do_(|d| {
            let (mut cur, mut have) = (None, vec![]);
            if let Some(s) = d.sessions.get(&a.session)
                && s.machine_id == a.machine
                && s.state == "started"
            {
                cur = s.cert.clone();
                have = s.stores.clone().unwrap_or_default();
            }
            let mut chs: Vec<Option<Doc>> = vec![a.challenge.clone()];
            if let Some(x) = d.approvals.get(&a.id) {
                // as it is now that this answer holds the machine's lock
                chs = std::iter::once(x.challenge.clone())
                    .chain(x.earlier.iter().cloned().map(Some))
                    .collect();
            }
            (cur, have, chs)
        });
        let Some(cur) = cur else {
            self.st.do_(|d| {
                d.approvals.remove(&a.id);
                crate::outcomes::note_outcome(d, a.origin.as_ref(), &a.kind, &a.session, crate::outcomes::OUTCOME_DROPPED, 0, None);
            });
            return Err(anyhow!("the session no longer runs on the machine this store was asked for"));
        };
        let store = a.options.get("store").cloned().unwrap_or_default();
        let done = self.begin(&a.session, "approved")?;
        let _done = scopeguard(move || done.call());
        // the phone signed the challenge it read: the current one, or one rebase_add_stores replaced while its page was
        // open
        let mut res = Err(anyhow!("no challenge"));
        for (i, ch) in chs.iter().enumerate() {
            let input = json!({"challenge": ch, "signature": signature, "current": cur, "carry": self.read_carry(&a.machine)});
            res = self.core.call_answer("/approve/by-phone", &input);
            match &res {
                Err(e) if core_err(e).is_some_and(|c| c.status == 403) && i + 1 < chs.len() => continue,
                _ => break,
            }
        }
        let (ans, extra) = match res {
            Err(e) => {
                if core_err(&e).is_some_and(|c| c.status == 409) && contains_string(&have, &store) {
                    // this very challenge was answered before (the same store asked for twice from one cert): it's in
                    self.st.do_(|d| {
                        d.approvals.remove(&a.id);
                        crate::outcomes::note_outcome(d, a.origin.as_ref(), &a.kind, &a.session, crate::outcomes::OUTCOME_APPROVED, 0, Some(&cur));
                    });
                    return Ok((cur, a.session.clone()));
                }
                return Err(e);
            }
            Ok(x) => x,
        };
        self.log_inputs(extra.entry.as_ref()); // the machine's new cert
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct C {
            stores: Vec<String>,
            machine: Option<Started>,
        }
        let c: C = ans.decode().unwrap_or_default();
        let mut want = have.clone();
        want.push(store.clone());
        if c.machine.as_ref().is_none_or(|m| m.id != a.machine) || !contains_all(&c.stores, &want) {
            crate::logf!(
                "add-store {store} for {}: the core answered {:?} from a stale cert (the session holds {:?}): filed again",
                a.session,
                c.stores,
                have
            );
            let (harness, config) = self.st.do_(|d| {
                d.sessions
                    .get(&a.session)
                    .map(|s| (s.harness.clone(), crate::vouch::line_config(s)))
                    .unwrap_or_default()
            });
            match self.succession(Some(&cur), &a.machine, &sorted_set(&want), &harness, cert_mode(Some(&cur)), "", &config, "") {
                Err(e) => {
                    self.st.do_(|d| d.approvals.remove(&a.id).map(|_| ()));
                    return Err(anyhow!(
                        "another store was added while this approval waited, and asking again failed: {e:#}"
                    ));
                }
                Ok(ch) => self.st.do_(|d| {
                    if let Some(x) = d.approvals.get_mut(&a.id) {
                        x.challenge = Some(ch.clone());
                    }
                }),
            }
            return Err(anyhow!(
                "another store was added to this session while this approval waited: approve it again"
            ));
        }
        self.st.do_(|d| {
            d.approvals.remove(&a.id);
            crate::outcomes::note_outcome(d, a.origin.as_ref(), &a.kind, &a.session, crate::outcomes::OUTCOME_APPROVED, 0, Some(&ans));
            d.certs.insert(a.machine.clone(), ans.clone());
            if let Some(s) = d.sessions.get_mut(&a.session) {
                s.cert = Some(ans.clone());
                s.stores = Some(c.stores.clone());
            }
        });
        self.carry_after(&a.machine, &a.machine, &ans, &extra); // its carried stores go on
        self.rebase_add_stores(&a.machine, &ans);
        Ok((ans, a.session.clone()))
    }

    /// The machine has a new cert (an add-store answered, a downgrade finished), so every other add-store still
    /// waiting for it is made again from that cert (the phone reads an add-store's challenge again right before
    /// signing it and checks it is the same ask). Called under the machine's self_succession_lock.
    pub fn rebase_add_stores(&self, machine: &str, cert: &Doc) {
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct C {
            stores: Vec<String>,
        }
        let Ok(c) = cert.decode::<C>() else { return };
        let (mut todo, harness, config) = self.st.do_(|d| {
            let todo: Vec<(String, String)> = d
                .approvals
                .iter()
                .filter(|(_, x)| x.kind == "add-store" && x.machine == machine)
                .map(|(id, x)| (id.clone(), x.options.get("store").cloned().unwrap_or_default()))
                .collect();
            let (h, cfg) = d
                .machines
                .get(machine)
                .and_then(|sid| d.sessions.get(sid))
                .map(|s| (s.harness.clone(), crate::vouch::line_config(s)))
                .unwrap_or_default();
            (todo, h, cfg)
        });
        todo.sort();
        for (id, store) in todo {
            if store.is_empty() || contains_string(&c.stores, &store) {
                continue; // already in (or nothing named): respond_add_store answers it as done
            }
            let mut want = c.stores.clone();
            want.push(store.clone());
            match self.succession(Some(cert), machine, &sorted_set(&want), &harness, cert_mode(Some(cert)), "", &config, "") {
                Err(e) => crate::logf!("add-store {store} for {machine}: making it again from the new cert failed: {e:#}"),
                Ok(ch) => self.st.do_(|d| {
                    if let Some(x) = d.approvals.get_mut(&id) {
                        if let Some(old) = x.challenge.take() {
                            x.earlier.insert(0, old);
                        }
                        x.earlier.truncate(crate::batches::BATCH_MAX_ITEMS);
                        x.challenge = Some(ch.clone());
                    }
                }),
            }
        }
    }

    pub fn reject(self: &Arc<Self>, id: &str) -> Result<()> {
        self.reject_as(id, crate::outcomes::OUTCOME_DENIED)
    }

    /// reject, telling a requesting session the outcome (denied, or lapsed when it expired; outcomes.rs)
    pub fn reject_as(self: &Arc<Self>, id: &str, outcome: &str) -> Result<()> {
        let a = self.st.do_(|d| {
            let a = d.approvals.remove(id);
            if let Some(a) = &a {
                crate::outcomes::note_outcome(d, a.origin.as_ref(), &a.kind, &a.session, outcome, 0, None);
            }
            a
        });
        let Some(a) = a else {
            return Err(crate::inbox::already_gone()); // inbox.rs
        };
        self.st.do_(|d| {
            let mut kind = a.kind.clone();
            if kind == crate::kernelline::KERNEL_APPROVAL_KIND {
                // kernelline.rs: a new line's first source, or a resume onto a new source
                kind = "new-session".into();
                if d
                    .sessions
                    .get(&a.session)
                    .is_some_and(|s| s.kernel.as_ref().is_some_and(|k| k.source_cert.is_some()))
                {
                    kind = "resume-upgrade".into();
                }
            }
            let Some(s) = d.sessions.get_mut(&a.session) else { return };
            match kind.as_str() {
                "new-session" if a.again => {
                    s.state = "failed".into(); // a failed line asked to start again stays
                    s.error = format!("the start again was {outcome}");
                }
                "new-session" if outcome == crate::outcomes::OUTCOME_LAPSED && deyaos_own(a.origin.as_ref()) => {
                    // Deyao's own New session that nobody answered in time: kept, so Start again asks again
                    s.state = "failed".into();
                    s.error = "the approval lapsed (nobody answered within 10 minutes): Start again asks again".into();
                }
                "new-session" => {
                    d.sessions.remove(&a.session); // no machine was made
                }
                "resume-upgrade" => {
                    s.state = "paused".into(); // nothing happened to the old machine
                    s.error.clear();
                }
                _ => {}
            }
        });
        Ok(())
    }

    // ---- pause ----------------------------------------------------------------------------------------------

    pub fn pause(self: &Arc<Self>, id: &str) -> Result<()> {
        self.pause_as(id, None, false)
    }

    /// the pause of a restart (an Upgrade, a bigger machine or disk): the session starts again right after, so its
    /// runners stay (runners.rs). next = a handover's next machine (handover.rs)
    pub fn pause_with(self: &Arc<Self>, id: &str, next: Option<crate::handover::NextMachine>) -> Result<()> {
        self.pause_as(id, next, true)
    }

    fn pause_as(self: &Arc<Self>, id: &str, next: Option<crate::handover::NextMachine>, restart: bool) -> Result<()> {
        let unlock = self.lock_args(id, "pausing", json!({"restart": restart}))?;
        let s: Session = self.st.do_(|d| d.sessions.get(id).cloned().unwrap_or_default());
        if !s.id.is_empty() && s.state == "paused" {
            return Ok(()); // already what was asked for
        }
        if s.id.is_empty() || s.machine_id.is_empty() || !crate::kernelline::has_line(&s) {
            return Err(anyhow!(
                "session {id} isn't running (it is {}): nothing to pause",
                or_state(&s.state)
            ));
        }
        self.set_state(id, "pausing", "");
        let op = self.lc_begin(id, "pause"); // lifecycle.rs
        op.machine(&s.machine_id);
        let r = self.clone();
        let (id, mid) = (id.to_string(), s.machine_id.clone());
        std::thread::spawn(move || r.pause_run(&id, &mid, next, restart, unlock, op));
        Ok(())
    }

    /// the pause's work under its job (jobs.rs); run again by a replica carrying on a job whose holder died
    pub fn pause_run(
        self: &Arc<Self>,
        id: &str,
        machine: &str,
        next: Option<crate::handover::NextMachine>,
        restart: bool,
        unlock: OnceFn,
        op: crate::lifecycle::LcHandle,
    ) {
        let _u = scopeguard(move || unlock.call());
        let op2 = op.clone();
        let _e = scopeguard(move || op2.end_from_state());
        if !self.final_snapshot_and_kill_next(id, machine, next) {
            return; // snapsafe.rs: kept, failed and DMed
        }
        let now = GoTime::now();
        self.st.do_(|d| {
            if let Some(x) = d.sessions.get_mut(id) {
                x.state = "paused".into();
                x.machine_id.clear();
                x.paused_at = Some(now);
                x.status.clear();
            }
        });
        if !restart {
            self.runners_after_pause(id, &op); // runners.rs: they go unless a wakeup or cron is armed
        }
    }

    // ---- resume ---------------------------------------------------------------------------------------------

    pub fn resume(self: &Arc<Self>, id: &str, upgrade: bool) -> Result<()> {
        let unlock = self.lock(id, "starting")?;
        let s: Session = self.st.do_(|d| d.sessions.get(id).cloned().unwrap_or_default());
        // paused, or failed. With no machine the line is where its last pause left it. With one (a pause or destroy
        // whose kill failed, or one cut off) the pause is finished first, then the resume, on this one tap.
        if !s.id.is_empty() && matches!(s.state.as_str(), "started" | "initialising" | "starting" | "resuming") {
            return Ok(()); // already running (or on its way)
        }
        if !s.id.is_empty() && s.state == "approval" {
            return Err(anyhow!(
                "session {id} waits for Deyao's approval in the Inbox: it starts once he allows it"
            ));
        }
        if s.id.is_empty() || !(s.state == "paused" || s.state == "failed") {
            return Err(anyhow!(
                "session {id} is {}, so it can't resume now: resume it once it is paused or failed",
                or_state(&s.state)
            ));
        }
        self.resume_refusal(id)?; // snapsafe.rs: its last machine left no snapshot
        let op = self.lc_begin(id, "resume"); // lifecycle.rs
        let mut upgrade = upgrade;
        if !upgrade && crate::autopilot::harness_retry_upgrade(&s, &self.cfg.session_image) {
            // autopilot.rs: its Claude never came up on that image: the retry goes on the newest one
            upgrade = true;
            op.note(
                "",
                &format!(
                    "its harness never came up on image {}: resuming on the newest session image (Deyao approves it in the Inbox)",
                    cert_image(s.cert.as_ref(), &s.image)
                ),
            );
        }
        if upgrade {
            op.note("", "on the newest session image");
        }
        if s.kernel.is_some() {
            return self.kernel_resume(s, upgrade, unlock, op); // kernelline.rs
        }
        if s.cert.is_none() {
            // a new line whose first start failed: the start again asks again
            return self.start_again(s, unlock, op);
        }
        self.set_state(id, "resuming", "");
        let r = self.clone();
        let id = id.to_string();
        std::thread::spawn(move || r.resume_run(id, s, upgrade, unlock, op));
        Ok(())
    }

    fn resume_run(self: &Arc<Self>, id: String, mut s: Session, mut upgrade: bool, unlock: OnceFn, op: crate::lifecycle::LcHandle) {
        let _u = scopeguard(move || unlock.call());
        let op2 = op.clone();
        let _e = scopeguard(move || op2.end_from_state()); // unless start_and_certify took it over
        let (r2, id2) = (self.clone(), id.clone());
        let _f = scopeguard(move || r2.settle_followups(&id2)); // apicalls.rs
        let (r3, id3) = (self.clone(), id.clone());
        let _c = scopeguard(move || r3.cancel_spare(&id3, "the resume started no machine")); // handover.rs
        if !s.machine_id.is_empty() {
            op.machine(&s.machine_id);
            op.note(&s.machine_id, "finishing the machine's pause first");
            self.set_waiting(&id, "finishing the pause first");
            // handover.rs: the next machine starts once the old one is told to stop (an unattended resume only)
            let next = if upgrade { None } else { self.handover_next(&s, "", 0) };
            if !self.final_snapshot_and_kill_next(&id, &s.machine_id, next) {
                self.set_waiting(&id, "");
                return;
            }
            self.set_waiting(&id, "");
            let now = GoTime::now();
            if let Some(x) = self.st.do_(|d| {
                d.sessions.get_mut(&id).map(|x| {
                    x.machine_id.clear();
                    x.paused_at = Some(now);
                    x.status.clear();
                    x.clone()
                })
            }) {
                s = x;
            }
        }
        // the same image: the dead-machine rule compares the cert's own image string (what Fly reported); a phone
        // approval names CI's pinned ref for that digest, whose signature the phone checks
        let own = cert_image(s.cert.as_ref(), &s.image);
        let pinned = pinned_image(&own, &self.cfg.session_image, &self.cfg.image_order);
        let stores = s.stores.clone().unwrap_or_default();
        if !upgrade && contains_string(&stores, "claude") && legacy_login_image(&own, &self.cfg.image_order) {
            upgrade = true; // its machine would fetch the Claude login from Jarvis 1: the newest image instead
            crate::logf!("session {id}: resume on the newest image (its image {own} predates the router's Claude login)");
        }
        let once = self.resume_once(&s); // vouch.rs: a resume prompt or a rollback: only the phone approves one
        // the permission mode is signed: a resume in another mode than the line's cert is a change the iPhone approves
        let mode_change = cert_mode(s.cert.as_ref()) != norm_mode(&s.permission_mode);
        let phone = |image: &str, opts: BTreeMap<String, String>| {
            self.cancel_spare(&id, "the resume waits for Deyao's approval"); // handover.rs
            let ch = match self.succession(s.cert.as_ref(), "", &stores, &s.harness, &s.permission_mode, image, &crate::vouch::line_config(&s), &once) {
                Err(e) => {
                    self.set_state(&id, "paused", &format!("resume: {e:#}"));
                    return;
                }
                Ok(c) => c,
            };
            if !once.is_empty() {
                self.once_taken(&id); // the cert will carry them; nothing else delivers them
            }
            self.set_state(&id, "approval", "");
            self.add_approval(Approval {
                kind: "resume-upgrade".into(),
                session: id.clone(),
                label: s.label.clone(),
                challenge: Some(ch),
                options: opts,
                ..Default::default()
            });
            op.note("", "waiting for Deyao's approval in the Inbox (resume-upgrade): the start is its own operation once he allows it");
        };
        let phone_image = if upgrade { self.cfg.session_image.clone() } else { pinned.clone() };
        let pm = || -> BTreeMap<String, String> {
            [("permissionMode".to_string(), norm_mode(&s.permission_mode).to_string())].into_iter().collect()
        };
        if !once.is_empty() {
            let mut o = pm();
            o.insert("once".into(), once.clone());
            phone(&phone_image, o);
            return;
        }
        if mode_change {
            phone(&phone_image, pm());
            return;
        }
        if upgrade {
            phone(&phone_image, BTreeMap::new()); // a change: the iPhone approves first
            return;
        }
        // the core compares the cert's stores, options and image with the challenge's: all of them from the cert
        let (cstores, harness) = cert_stores_harness(s.cert.as_ref(), &stores, &s.harness);
        let ch = match self.succession(s.cert.as_ref(), "", &cstores, &harness, &s.permission_mode, &own, &crate::vouch::line_config(&s), "") {
            Err(e) => {
                self.set_state(&id, "paused", &format!("resume: {e:#}"));
                return;
            }
            Ok(c) => c,
        };
        match self.core.call("/approve/by-dead-machine", &json!({"challenge": ch})) {
            Err(e) if refused_same_line(&e) => {
                // the core won't answer this resume by itself: it becomes the resume-upgrade approval in the Inbox, on
                // the same image, so one tap (and Face ID) resumes it
                crate::logf!("session {id}: the core refused the unattended resume ({e:#}): asking the phone");
                phone(&pinned, BTreeMap::new());
            }
            Err(e) => self.set_state(&id, "paused", &format!("resume: {e:#}")),
            Ok(a) => {
                self.settle_followups(&id); // no approval follows: the machine starts now
                op.note("", "the core answered the resume by itself (same line, same image)");
                self.start_and_certify(&id, &a);
            }
        }
    }

    /// a new line whose first start failed gets its new-session approval again, built from the session as it is:
    /// one Face ID starts it. Its Deny leaves the session failed (Approval.again) rather than removing it.
    fn start_again(self: &Arc<Self>, s: Session, unlock: OnceFn, op: crate::lifecycle::LcHandle) -> Result<()> {
        self.set_state(&s.id, "resuming", "");
        let r = self.clone();
        std::thread::spawn(move || {
            let _u = scopeguard(move || unlock.call());
            let op2 = op.clone();
            let _e = scopeguard(move || op2.end_from_state());
            let (r2, id2) = (r.clone(), s.id.clone());
            let _f = scopeguard(move || r2.settle_followups(&id2));
            let ch = r.session_config(&s).and_then(|config| {
                r.succession(None, "", s.stores.as_deref().unwrap_or_default(), &s.harness, &s.permission_mode, &r.cfg.session_image, &config, "")
            });
            let ch = match ch {
                Err(e) => {
                    r.set_state(&s.id, "failed", &format!("start again: {e:#}"));
                    return;
                }
                Ok(c) => c,
            };
            let mut opts: BTreeMap<String, String> = [
                ("model", s.model.clone()),
                ("size", s.size.clone()),
                ("permissionMode", s.permission_mode.clone()),
                ("repos", s.repos.clone()),
            ]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect();
            if let Some(c) = &s.content {
                opts.insert("content".into(), c.join(","));
            }
            crate::autopilot::live_options(&s, &mut opts);
            crate::sessionops::ops_options(&s, &mut opts);
            r.set_state(&s.id, "approval", "");
            r.add_approval(Approval {
                kind: "new-session".into(),
                session: s.id.clone(),
                label: s.label.clone(),
                challenge: Some(ch),
                options: opts,
                again: true,
                ..Default::default()
            });
            op.note("", "the first start failed: its new-session approval is in the Inbox again; the start is its own operation once Deyao allows it");
        });
        Ok(())
    }

    // ---- destroy --------------------------------------------------------------------------------------------

    pub fn destroy(self: &Arc<Self>, id: &str) -> Result<()> {
        self.destroy_with(id, false)
    }

    /// a running session is paused first (its final snapshot), then archived (archive.rs); a failed archive leaves
    /// it paused with the error, unless force. Then the destroy hooks, the burn, the records.
    pub fn destroy_with(self: &Arc<Self>, id: &str, force: bool) -> Result<()> {
        self.destroy_opts(id, DestroyOpts { force, report: None })
    }

    pub fn destroy_opts(self: &Arc<Self>, id: &str, o: DestroyOpts) -> Result<()> {
        let unlock = self.lock_args(id, "destroying", json!({"force": o.force}))?;
        let s: Session = self.st.do_(|d| d.sessions.get(id).cloned().unwrap_or_default());
        if s.id.is_empty() {
            return Err(anyhow!("no session {id}"));
        }
        self.set_state(id, "destroying", "");
        let op = self.lc_begin(id, "destroy"); // lifecycle.rs
        op.machine(&s.machine_id);
        let r = self.clone();
        let id = id.to_string();
        std::thread::spawn(move || r.destroy_run(&id, s, o, unlock, op));
        Ok(())
    }

    /// the destroy's work under its job (jobs.rs); a replica that carries on a job whose holder died runs it again:
    /// the kill answers the same cert, the archive skips what it holds, the burn is kept on the line
    pub fn destroy_run(self: &Arc<Self>, id: &str, mut s: Session, o: DestroyOpts, unlock: OnceFn, op: crate::lifecycle::LcHandle) {
        let force = o.force;
        let gone = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let _u = scopeguard(move || unlock.call());
        let (op2, g2) = (op.clone(), gone.clone());
        let _e = scopeguard(move || {
            if !g2.load(Ordering::SeqCst) {
                op2.end_from_state()
            }
        });
        if !s.machine_id.is_empty() && !self.snapshot_and_kill(id, &s.machine_id, force) {
            return;
        }
        let changes = o.report.as_ref().map(|_| self.snapshot_changes(id)); // archive.rs: before finish drops it
        op.note("", "archiving the session to the Storage Box");
        let (archived, aerr) = match self.archive(id) {
            Ok(a) => (a, None),
            Err(e) => (None, Some(e)),
        };
        match (&aerr, &archived) {
            (Some(e), _) => op.note("", &format!("the archive failed: {e:#}")),
            (None, Some(a)) => op.note(
                "",
                &format!("archived to {} ({}, uploaded in {:.1} s)", a.file, crate::util::mb(a.bytes), a.upload_seconds),
            ),
            (None, None) => op.note("", "nothing to archive"),
        }
        if let Some(e) = &aerr
            && !force
        {
            self.set_state(
                id,
                "paused",
                &format!("archive: {e:#} — nothing was lost (the session is paused): Destroy again once the Storage Box answers, or Destroy anyway (it goes without its archive)"),
            );
            return;
        }
        if s.kernel.is_some() {
            // kernelline.rs: the line's source ends
            match self.kernel_burn(id) {
                Err(e) => {
                    crate::logf!("session {id}: burn: {e:#}");
                    op.note("", &format!("ending the line (burn): {e:#}"));
                }
                Ok(()) => op.note("", "the line ended: its source burned"),
            }
        } else if let Some(cert) = &s.cert {
            // end the line: a succession to the null image, answered by the dead-machine responder → burn cert
            let res = self
                .succession(Some(cert), "", &[], "", "", NULL_IMAGE, "", "")
                .and_then(|ch| self.core.call("/approve/by-dead-machine", &json!({"challenge": ch})))
                .and_then(|a| self.core.call("/certify", &json!({"approval": a, "machine": ""})));
            match res {
                Err(e) => {
                    crate::logf!("session {id}: burn: {e:#}");
                    op.note("", &format!("ending the line (burn): {e:#}"));
                }
                Ok(_) => op.note("", "the line ended: the core's burn cert"),
            }
        }
        if let Some(f) = &s.fabric {
            // fabricrunner.rs: the session's files at the fabric hermit go with it
            match self.delete_fabric_files(&f.conversation) {
                Err(e) => {
                    crate::logf!("session {id}: the fabric files: {e:#}");
                    op.note("", &format!("deleting its files at the fabric hermit: {e:#}"));
                }
                Ok(()) => op.note("", "its files at the fabric hermit are deleted"),
            }
        }
        self.end_runners(id, &op, "destroyed"); // runners.rs
        op.note("", "the session becomes a record");
        op.end("done", "");
        if let Some(x) = self.st.do_(|d| d.sessions.get(id).cloned()) {
            s = x; // the latest: titles and hook fields moved on since the destroy began
        }
        for h in crate::features::on_destroy() {
            h(self, &s);
        }
        let live_kept = self.clear_archived_live(id, archived.as_ref(), aerr.as_ref()); // livearchive.rs
        let ae = aerr.as_ref().map(|e| format!("{e:#}"));
        let a2 = archived.clone();
        self.finish(id, move |rec| {
            rec.archive = a2.clone();
            rec.live_kept = live_kept.clone();
            if let Some(e) = &ae {
                rec.archive_error = e.clone();
            }
        });
        gone.store(true, Ordering::SeqCst);
        self.lc_drop(id); // lifecycle.rs: archived by its destroy hook
        self.drop_sup_log(id); // supervisorlog.rs: likewise
        if let Some(rep) = &o.report {
            rep(&s, changes.flatten(), archived.as_ref(), aerr.as_ref());
        }
    }

    /// the session leaves the list for the records; its snapshots go. fill completes the record in the same state
    /// change (its archive, what was kept)
    pub fn finish(&self, id: &str, fill: impl Fn(&mut Record)) {
        let drop_snaps = self.st.do_(|d| {
            let Some(mut s) = d.sessions.remove(id) else { return vec![] };
            d.approvals.retain(|_, ap| ap.session != id);
            let mut ms = vec![];
            for (m, sid) in &d.machines {
                if sid == id {
                    ms.push(m.clone());
                }
            }
            s.state = "destroyed".into();
            s.machine_id.clear();
            let mut rec = Record {
                session: s,
                destroyed_at: GoTime::now(),
                ..Default::default()
            };
            fill(&mut rec);
            d.records.insert(0, rec);
            ms
        });
        for m in drop_snaps {
            self.drop_carry(&m); // the carried secrets go with the line (the core has burnt it too)
            self.snap_drop(&m); // snapstore.rs: its row and its object, after the state lock
        }
    }

    // ---- add a store (asked by the machine) ----------------------------------------------------------------

    pub fn add_store(self: &Arc<Self>, machine: &str, store: &str) -> Result<()> {
        let sid = self.st.do_(|d| d.machines.get(machine).cloned().unwrap_or_default());
        let o = Origin {
            caller: crate::inbox::Caller { kind: "session".into(), session: sid, ..Default::default() },
            call: crate::inbox::ApiCall {
                method: "POST".into(),
                path: "/m/add-store".into(),
                args: json!({"store": store}).as_object().cloned().unwrap_or_default(),
                ..Default::default()
            },
            ..Default::default()
        };
        self.add_store_from(machine, store, o, "", "")
    }

    /// the add-store approval, with its caller and the caller's explanation (inbox.rs)
    pub fn add_store_from(self: &Arc<Self>, machine: &str, store: &str, o: Origin, explanation: &str, batch: &str) -> Result<()> {
        self.add_store_approval(machine, store, o, explanation, batch).map(|_| ())
    }

    /// add_store_from → the approval's id
    pub fn add_store_approval(self: &Arc<Self>, machine: &str, store: &str, o: Origin, explanation: &str, batch: &str) -> Result<String> {
        let s: Session = self.st.do_(|d| {
            d.machines
                .get(machine)
                .and_then(|sid| d.sessions.get(sid))
                .cloned()
                .unwrap_or_default()
        });
        if !s.id.is_empty() && s.machine_id == machine && s.kernel.is_some() {
            return self.kernel_add_store_approval(&s, store, o, explanation, batch); // kernelline.rs
        }
        let Some(cert) = s.cert.clone().filter(|_| !s.id.is_empty() && s.machine_id == machine) else {
            return Err(anyhow!("this machine isn't a running session"));
        };
        if store == crate::claudestores::LEGACY_CLAUDE_STORE {
            // what is asked for is a Claude login: a session with no account gets the default one; one with an
            // account keeps it
            let def = self.accounts().default_store();
            if s.claude_account.is_empty() && !def.is_empty() {
                self.st.do_(|d| {
                    if let Some(x) = d.sessions.get_mut(&s.id)
                        && x.claude_account.is_empty()
                    {
                        x.claude_account = def.clone();
                    }
                });
                return Err(bad(format!("the store claude is gone: this session now has the Claude account {def}; its machine logs in with it by itself (restart the harness if it doesn't)")));
            }
            return Err(bad(format!("the store claude is gone: this session already has the Claude account {} (Settings → Claude accounts re-logs it in)", s.claude_account)));
        }
        let mut want = s.stores.clone().unwrap_or_default();
        want.push(store.to_string());
        let stores = self.with_harness_stores(&want, &[])?;
        let ch = self.succession(Some(&cert), machine, &stores, &s.harness, cert_mode(Some(&cert)), "", &crate::vouch::line_config(&s), "")?;
        let id = self.add_approval(Approval {
            kind: "add-store".into(),
            session: s.id.clone(),
            machine: machine.into(),
            label: s.label.clone(),
            challenge: Some(ch),
            options: [("store".to_string(), store.to_string())].into_iter().collect(),
            origin: Some(o),
            explanation: explanation.into(),
            batch: batch.into(),
            ..Default::default()
        });
        Ok(id)
    }

    // ---- downgrade in place (asked by the machine) ---------------------------------------------------------

    /// the machine names a subset of its stores and its new key pair → the challenge it must sign with its old key
    pub fn downgrade_begin(&self, machine: &str, stores: &[String], enc_key: &str, sig_key: &str) -> Result<Doc> {
        let s: Session = self.st.do_(|d| {
            d.machines
                .get(machine)
                .and_then(|sid| d.sessions.get(sid))
                .cloned()
                .unwrap_or_default()
        });
        let Some(cert) = s.cert.clone().filter(|_| !s.id.is_empty() && s.machine_id == machine) else {
            return Err(anyhow!("this machine isn't a running session"));
        };
        let harness = if s.harness.is_empty() { "claude".to_string() } else { s.harness.clone() };
        let mut opts = json!({"harness": harness, "permissionMode": cert_mode(Some(&cert))});
        let c = crate::vouch::line_config(&s);
        if !c.is_empty() {
            opts["config"] = json!(c);
        }
        self.core.call(
            "/succession",
            &json!({"predecessor": cert, "machine": machine, "stores": sorted_set(stores),
                "options": opts, "newEncryptionKey": enc_key, "newSigningKey": sig_key}),
        )
    }

    /// the challenge signed with the machine's old key → its new cert; from now on the router knows the machine by its
    /// new signing key
    pub fn downgrade_finish(&self, machine: &str, challenge: Option<&Doc>, signature: &str) -> Result<Doc> {
        let _unlock = self_succession_lock(machine);
        let (cert, ans) = self.core.call_answer(
            "/approve/by-old-key",
            &json!({"challenge": challenge, "signature": signature, "carry": self.read_carry(machine)}),
        )?;
        self.log_inputs(ans.entry.as_ref());
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct C {
            machine: Option<Started>,
            stores: Vec<String>,
        }
        let c: C = cert.decode().unwrap_or_default();
        let Some(m) = c.machine.filter(|m| m.id == machine) else {
            return Err(anyhow!("the core's cert names another machine"));
        };
        self.st.do_(|d| {
            d.certs.insert(machine.into(), cert.clone());
            d.started.insert(machine.into(), m.clone());
            if let Some(sid) = d.machines.get(machine).cloned()
                && let Some(s) = d.sessions.get_mut(&sid)
            {
                s.cert = Some(cert.clone());
                s.stores = Some(c.stores.clone());
            }
        });
        self.carry_after(machine, machine, &cert, &ans); // the dropped stores leave the carried secrets at once
        self.rebase_add_stores(machine, &cert); // a waiting add-store no longer brings back what was dropped
        Ok(cert)
    }

    // ---- commands to machines ------------------------------------------------------------------------------

    /// a supervisor command into the machine's queue (mq.rs; at most 8 waiting: more are dropped)
    pub fn send(&self, machine: &str, cmd: &str) {
        if let Err(e) = self.mq_put(machine, "command", "", &json!(cmd), 8) {
            crate::logf!("machine {machine}: command {cmd}: {e:#}");
        }
    }

    pub fn last_snapshot(self: &Arc<Self>, id: &str, machine: &str) -> Result<()> {
        self.last_snapshot_then(id, machine, None, false)
    }

    /// Before a pause or destroy kills the machine, its last snapshot (or its "nothing to snapshot" while booting),
    /// waiting as long as the snapshot makes progress (snapwait.rs). A machine that never got past boot isn't asked.
    /// stop_sent runs once the supervisor has been sent the snapshot command (handover.rs). destroying: a fabric
    /// machine sends the whole state (fabricrunner.rs).
    pub fn last_snapshot_then(self: &Arc<Self>, id: &str, machine: &str, stop_sent: Option<&dyn Fn()>, destroying: bool) -> Result<()> {
        let booted = || {
            self.st
                .do_(|d| d.sessions.get(id).is_some_and(|x| x.booted == machine))
        };
        if self.have_snap(machine) {
            self.lc_note(id, machine, "the machine's final snapshot is already here");
            return Ok(()); // it already sent its final one (a machine signs only one)
        }
        // a machine that has its secrets is seconds from booted: wait for it, or a pause right after a start would
        // leave its successor with no state at all
        let deadline = Instant::now() + crate::vouch::boot_grace();
        while !booted() && crate::vouch::has_pulled(machine) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_secs(1));
        }
        if !booted() {
            crate::logf!("session {id}: {machine} never got past boot; nothing to snapshot");
            self.lc_note(id, machine, "the machine never got past boot: nothing to snapshot");
            return Ok(());
        }
        // a machine that has gone silent can't answer: no wait
        let last = self.st.do_(|d| {
            d.sessions
                .get(id)
                .and_then(|x| x.live.as_ref().map(|l| l.last_report))
                .unwrap_or_default()
        });
        if last.since().whole_seconds() > SILENT_AFTER_SECS.load(Ordering::Relaxed) {
            crate::logf!("session {id}: {machine} silent since {}; not waiting for a snapshot", last.rfc3339());
            self.lc_note(id, machine, &format!("the machine has been silent since {}: not asking it for a snapshot", last.utc().rfc3339()));
            return Err(anyhow!(
                "its machine has been silent since {}, so it can't send its snapshot",
                crate::util::fmt_utc_minute(&last)
            ));
        }
        let done = self.await_snapshot(machine);
        let cmd = if destroying && self.is_fabric_session(id) { "snapshot-full" } else { "snapshot" };
        self.send(machine, cmd);
        self.lc_note(id, machine, "asked the supervisor for the final snapshot (it pauses the Claude process and freezes the session first)");
        if let Some(f) = stop_sent {
            f();
        }
        self.set_waiting(id, "waiting for the machine's last snapshot");
        let _w = {
            let (r, id) = (self.clone(), id.to_string());
            scopeguard(move || r.set_waiting(&id, ""))
        };
        if let Err(e) = self.wait_snapshot(machine, done) {
            crate::logf!("session {id}: {machine}: {e:#}");
            self.lc_note(id, machine, &format!("{e:#}"));
            if let Some(f) = self.snapshot_error(machine) {
                return Err(f);
            }
            return Err(e);
        }
        if let Some(e) = self.snapshot_error(machine) {
            self.lc_note(id, machine, &format!("the snapshot failed: {e:#}"));
            return Err(e);
        }
        match self.snap(machine) {
            Some(s) if s.state == "committed" => self.lc_note(
                id,
                machine,
                &format!("the final snapshot arrived ({:.1} MB, signed by the machine)", s.bytes as f64 / (1 << 20) as f64),
            ),
            _ => self.lc_note(id, machine, "the machine answered: nothing to snapshot"),
        }
        Ok(())
    }

    pub fn set_waiting(&self, id: &str, what: &str) {
        self.st.do_(|d| {
            if let Some(x) = d.sessions.get_mut(id) {
                x.waiting = what.into();
            }
        });
    }
}

/// a closure run when the guard goes (Go's defer)
pub struct Guard<F: FnOnce()>(Option<F>);

impl<F: FnOnce()> Drop for Guard<F> {
    fn drop(&mut self) {
        if let Some(f) = self.0.take() {
            f();
        }
    }
}

pub fn scopeguard<F: FnOnce()>(f: F) -> Guard<F> {
    Guard(Some(f))
}
