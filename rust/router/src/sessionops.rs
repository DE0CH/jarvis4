//! The session operations Jarvis 1 has beyond create/pause/resume/destroy (docs/PARITY.md "Session lifecycle"):
//!
//! ```text
//! permission mode   POST /api/sessions/:id/permission-mode {mode}: running → in place, Jarvis 1's set-permission-mode
//!                   through the "terminal" holder (a grant, standing rule or the session's allow list); paused → the
//!                   next start's SESSION_PERMISSION_MODE
//! resume options    POST /api/sessions/:id/resume {size, model, apiProxy}: applied before the resume. None of them is
//!                   in the core's Options (only the harness is), so the dead-machine rule still approves the resume:
//!                   they are the router's unsigned word, like at New session.
//! restart           POST /api/sessions/:id/restart {env, rollback: {dropFromMarker}, prompt, upgrade}: pause (if
//!                   running) + resume on the same image (upgrade: the newest, through its resume-upgrade approval).
//!                   `env` patches the machine env with NON-secret keys only (secrets come from stores); a rollback is
//!                   applied by the next machine to the snapshot it has verified (rust/machine/src/rollback.rs), since
//!                   the router can't edit a machine-signed snapshot.
//! API proxy         New session / resume {apiProxy}: SESSION_API_PROXY=1 in the machine env
//! idempotent create the New Session form's requestId: a repeat answers the session it already made
//! busy              /api/state: the lifecycle action holding a session ({kind, since}); `wake`: the last
//!                   permission-mode / restart job ({kind, phase, error, finishedAt})
//! ```

use crate::autopilot::{Liveness, Registry};
use crate::flows::NewSession;
use crate::grants::GrantNeeded;
use crate::http::{Registrar, null_if_empty, write_err};
use crate::inbox::{ApiCall, Origin, RequestParams};
use crate::nethttp::{Req, write_json};
use crate::router::Router;
use crate::state::{Persisted, Session};
use crate::uploads::AttachFile;
use crate::vouch::Delivery;
use anyhow::{Result, anyhow};
use jarvis_go::GoTime;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::sync::{Arc, LazyLock, Mutex, MutexGuard};
use std::time::{Duration, Instant};

pub const OPS_POLL: Duration = Duration::from_millis(500);
pub const SET_PERMISSION_MODE_CMD: &str = "/usr/local/bin/set-permission-mode ";

fn is_false(b: &bool) -> bool {
    !*b
}

/// the per-session settings of these operations (Session.ops, persisted)
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct SessionOps {
    #[serde(rename = "apiProxy", skip_serializing_if = "is_false")]
    pub api_proxy: bool,
    /// non-secret env patch, kept for every later start
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
    /// for the next start only (see rollback_env)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rollback: Option<RollbackMark>,
    /// first-prompt attachments (uploads.rs)
    #[serde(skip_serializing_if = "String::is_empty")]
    pub upload: String,
    #[serde(rename = "attachments", skip_serializing_if = "Vec::is_empty")]
    pub attach: Vec<AttachFile>,
    /// a switch to bypass that waits on a terminal grant in the Inbox (ask_mode_grant): it runs once the phone signs it
    #[serde(rename = "modeAfterGrant", skip_serializing_if = "Option::is_none")]
    pub mode_after_grant: Option<ModeAfterGrant>,
    /// accountswap.rs: a switch of a paused session's Claude account asked for "continue": typed into its chat once
    /// its next start's Claude host is up and idle (autopilot.rs)
    #[serde(rename = "continueAfterStart", skip_serializing_if = "is_false")]
    pub continue_after_start: bool,
}

/// raising a running session to bypass needs a fresh phone grant for the terminal. Asked for where no Face ID sheet can
/// open (the web page, an approved API call, a session's actions), the router files that grant in the Inbox and keeps
/// the switch here; when the phone signs the grant (answering request inbox), add_grant runs it.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct ModeAfterGrant {
    pub mode: String,
    /// the grant request
    pub inbox: String,
    /// the request's expiry
    pub until: GoTime,
}

/// drop every transcript line from the first one containing marker, in the snapshot of machine pred (the machine the
/// next start succeeds)
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct RollbackMark {
    #[serde(rename = "dropFromMarker")]
    pub marker: String,
    #[serde(rename = "predecessor")]
    pub pred: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct BusyMark {
    pub kind: String,
    pub since: GoTime,
}

#[derive(Debug, Clone, Default)]
pub struct WakeJobData {
    pub kind: String,
    pub phase: String,
    pub error: String,
    pub started_at: GoTime,
    pub finished_at: Option<GoTime>,
}

/// a permission-mode / restart / upgrade / disk / account job: its phase and outcome, the session's `wake`
pub type WakeJob = Arc<Mutex<WakeJobData>>;

#[derive(Default)]
struct OpsInner {
    busy: BTreeMap<String, BusyMark>,
    wake: BTreeMap<String, WakeJob>,
}

/// in memory only (a router restart forgets running jobs, as Jarvis 1 does)
#[derive(Default)]
pub struct OpsState {
    mu: Mutex<OpsInner>,
    /// uploads.rs: one writer of an upload's files at a time
    pub upload_mu: Mutex<()>,
    /// repos.rs: the repo list
    pub repos_mu: Mutex<()>,
    pub gh: crate::repos::GhCache,
}

fn wj(j: &WakeJob) -> MutexGuard<'_, WakeJobData> {
    j.lock().unwrap_or_else(|e| e.into_inner())
}

impl OpsState {
    fn lock(&self) -> MutexGuard<'_, OpsInner> {
        self.mu.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn set_busy(&self, id: &str, kind: &str) {
        let mut g = self.lock();
        if kind.is_empty() {
            g.busy.remove(id);
            return;
        }
        g.busy.insert(id.into(), BusyMark { kind: kind.into(), since: GoTime::now() });
    }

    pub fn busy_of(&self, id: &str) -> Option<BusyMark> {
        self.lock().busy.get(id).cloned()
    }

    /// one job per session at a time
    pub fn start_job(&self, id: &str, kind: &str) -> Result<WakeJob> {
        let mut g = self.lock();
        if g.wake.get(id).is_some_and(|j| wj(j).finished_at.is_none()) {
            return Err(crate::router::Busy(String::new()).into());
        }
        let j: WakeJob = Arc::new(Mutex::new(WakeJobData {
            kind: kind.into(),
            phase: "starting".into(),
            started_at: GoTime::now(),
            ..Default::default()
        }));
        g.wake.insert(id.into(), j.clone());
        Ok(j)
    }

    /// something the job's outcome should say although it goes on (shown as its error)
    pub fn note(&self, j: &WakeJob, text: &str) {
        wj(j).error = text.into();
    }

    pub fn phase(&self, j: &WakeJob, phase: &str, err: Option<&anyhow::Error>) {
        let mut g = wj(j);
        g.phase = phase.into();
        if let Some(e) = err {
            g.error = format!("{e:#}");
        }
        if phase == "done" || phase == "failed" {
            g.finished_at = Some(GoTime::now());
        }
    }

    pub fn job_view(&self, id: &str) -> Option<Value> {
        let g = self.lock();
        let j = wj(g.wake.get(id)?).clone();
        if j.finished_at.is_some_and(|f| f.since() > time::Duration::minutes(10)) {
            return None;
        }
        Some(json!({"kind": j.kind, "phase": j.phase, "error": null_if_empty(&j.error), "startedAt": j.started_at,
            "finishedAt": j.finished_at}))
    }
}

/// the env hook: the machine env these settings make (a start and a resume; flows.rs machine_env)
pub fn ops_env(_: &Arc<Router>, s: &Session, e: &mut BTreeMap<String, String>) {
    let Some(o) = &s.ops else { return };
    for (k, v) in &o.env {
        if env_key_allowed(k).is_ok() {
            e.insert(k.clone(), v.clone());
        }
    }
    if o.api_proxy {
        e.insert("SESSION_API_PROXY".into(), "1".into());
    }
    rollback_env(s, e);
    crate::uploads::attach_env(s, e);
}

/// the state hook: each session's busy mark and job
pub fn ops_state_hook(r: &Arc<Router>, out: &mut Map<String, Value>) {
    let Some(Value::Array(ss)) = out.get_mut("sessions") else { return };
    for v in ss.iter_mut() {
        let Value::Object(v) = v else { continue };
        let id = v.get("id").and_then(Value::as_str).unwrap_or_default().to_string();
        if let Some(b) = r.ops.busy_of(&id) {
            v.insert("busy".into(), json!(b));
        }
        if let Some(j) = r.ops.job_view(&id) {
            v.insert("wake".into(), j);
        }
    }
}

/// only for the start that succeeds the machine the rollback was asked against. While a session is paused its cert is
/// the predecessor's, so a later start (another predecessor) never repeats it.
pub fn rollback_env(s: &Session, e: &mut BTreeMap<String, String>) {
    let Some(rb) = s.ops.as_ref().and_then(|o| o.rollback.as_ref()).filter(|rb| !rb.marker.is_empty()) else { return };
    if s.cert.is_none() || crate::sessionops::cert_machine(s.cert.as_ref()) != rb.pred {
        return;
    }
    e.insert("JARVIS2_ROLLBACK".into(), rb.marker.clone());
    e.insert("JARVIS2_ROLLBACK_PRED".into(), rb.pred.clone());
}

/// what the phone sees on the new-session approval
pub fn ops_options(s: &Session, o: &mut BTreeMap<String, String>) {
    let Some(ops) = &s.ops else { return };
    if ops.api_proxy {
        o.insert("apiProxy".into(), "on".into());
    }
    if !ops.attach.is_empty() {
        o.insert("attachments".into(), format!("{} file(s)", ops.attach.len()));
    }
}

pub fn ops_view(s: &Session, v: &mut Map<String, Value>) {
    v.insert("apiProxy".into(), json!("off"));
    let Some(ops) = &s.ops else { return };
    v.insert("apiProxy".into(), json!(crate::autopilot::on_off(!ops.api_proxy)));
    if let Some(m) = ops.mode_after_grant.as_ref().filter(|m| GoTime::now().before(&m.until)) {
        v.insert("modeAfterGrant".into(), json!({"mode": m.mode, "inbox": m.inbox, "until": m.until}));
    }
    if !ops.env.is_empty() {
        v.insert("envKeys".into(), json!(ops.env.keys().collect::<Vec<_>>()));
    }
}

/// under the state lock, before a new session is stored. A request id seen on a live session answers that session
/// (dup); attachments are bound to this session (uploads.rs).
pub fn admit_session(d: &mut Persisted, s: &mut Session, input: &NewSession) -> Result<String> {
    if !input.request_id.is_empty()
        && let Some(x) = d.sessions.values().find(|x| x.request_id == input.request_id)
    {
        return Ok(x.id.clone());
    }
    let mut ops = SessionOps { api_proxy: input.api_proxy, ..Default::default() };
    if let Some(a) = input.attachments.as_ref().filter(|a| !a.files.is_empty()) {
        ops.attach = crate::uploads::bind_upload(d, &s.id, &input.attach_owner, a)?;
        ops.upload = a.upload_id.clone();
    }
    s.ops = Some(ops);
    Ok(String::new())
}

/// the switch kept for the grant request just answered, if a phone grant answered it (answered: request id → by a
/// grant, not a rule); taken off the session once answered or lapsed. Inside st.do_.
pub fn mode_after_grant(s: &mut Session, answered: &BTreeMap<String, bool>, now: GoTime) -> String {
    let Some(ops) = s.ops.as_mut() else { return String::new() };
    let Some(m) = ops.mode_after_grant.clone() else { return String::new() };
    let hit = answered.get(&m.inbox).copied();
    if hit.is_none() && now.before(&m.until) {
        return String::new();
    }
    ops.mode_after_grant = None; // answered (a standing rule doesn't allow bypass: nothing runs) or lapsed
    if hit != Some(true) {
        return String::new();
    }
    m.mode
}

fn clip(s: &str, n: usize) -> String {
    crate::util::trim_to(s, n)
}

// ---- resume options -------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct ResumeOptions {
    pub size: String,
    pub model: String,
    #[serde(rename = "apiProxy")]
    pub api_proxy: Option<bool>,
}

impl ResumeOptions {
    pub fn check(&self) -> Result<()> {
        if !self.size.is_empty() && crate::sizes::size_mem_gb(&self.size) == 0 {
            return Err(anyhow!("size is small, medium, large or a doubling past it (16gb, 32gb, …)"));
        }
        Ok(())
    }
}

/// a model of the session's own harness (harness.rs's catalogue)
pub fn resume_model(harness: &str, model: &str) -> Result<()> {
    match crate::harness::session_model(harness, model) {
        Ok(m) if m == model => Ok(()),
        _ => Err(anyhow!(
            "{} isn't a model of the {harness} harness (GET /api/models?harness={harness})",
            jarvis_go::fmt::go_quote(model)
        )),
    }
}

// ---- restart: pause + resume, with an env patch and a transcript rollback --------------------------------------

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct RollbackIn {
    #[serde(rename = "dropFromMarker")]
    pub drop_from_marker: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct RestartRequest {
    pub env: Map<String, Value>,
    pub rollback: Option<RollbackIn>,
    pub prompt: String,
    /// resume on the newest session image (its resume-upgrade approval in the Inbox, one Face ID) instead of the same
    /// image, e.g. to bring a fixed supervisor to a running session (2026-10-20)
    pub upgrade: bool,
    #[serde(flatten)]
    pub resume: ResumeOptions,
}

fn re(s: &str) -> regex::Regex {
    regex::Regex::new(s).unwrap_or_else(|_| unreachable!())
}

/// env keys a patch may never set: the router's and the harness's own settings, the session-API placeholders, the
/// loader's
static ENV_RESERVED: LazyLock<regex::Regex> =
    LazyLock::new(|| re(r"^(JARVIS2?_|SESSION_|FLY_|CF_ACCESS_|LOBSTER_|CLAUDE_|ANTHROPIC_|LD_|HOME$|PATH$|USER$|SHELL$|TERM$)"));
/// env keys that name a secret: those come only from stores (core-sealed), never the unsigned machine env
static ENV_SECRETISH: LazyLock<regex::Regex> = LazyLock::new(|| {
    re(r"(?i)(TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE|CREDENTIAL|COOKIE|WEBHOOK|ACCESS_?KEY|API_?KEY|(^|_)(PASS|PWD|AUTH|KEY|API|DSN|SIG|SIGNATURE|SALT|OTP|TOTP|PIN|CERT)(_|$))")
});
static ENV_KEY_RE: LazyLock<regex::Regex> = LazyLock::new(|| re(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$"));

pub fn env_key_allowed(k: &str) -> Result<()> {
    if !ENV_KEY_RE.is_match(k) {
        return Err(anyhow!("bad env name {}", jarvis_go::fmt::go_quote(k)));
    }
    if ENV_RESERVED.is_match(k) {
        return Err(anyhow!("{k} is set by Jarvis itself"));
    }
    if ENV_SECRETISH.is_match(k) {
        return Err(anyhow!("{k} looks like a secret: secrets go in a store, never the machine env"));
    }
    Ok(())
}

/// string/number/bool values, at most 32 keys, 2000 characters each; "" or null removes
pub fn normalize_env_patch(input: &Map<String, Value>) -> Result<BTreeMap<String, Option<String>>> {
    if input.len() > 32 {
        return Err(anyhow!("at most 32 env keys"));
    }
    let mut out = BTreeMap::new();
    for (k, v) in input {
        env_key_allowed(k)?;
        let s = match v {
            Value::Null => {
                out.insert(k.clone(), None);
                continue;
            }
            Value::String(s) => s.clone(),
            Value::Bool(_) | Value::Number(_) => jarvis_go::fmt::go_sprint(v),
            _ => return Err(anyhow!("env {k}: a string value")),
        };
        if s.len() > 2000 || s.contains('\0') {
            return Err(anyhow!("env {k}: at most 2000 characters, no NUL"));
        }
        out.insert(k.clone(), (!s.is_empty()).then_some(s));
    }
    Ok(out)
}

/// whether a restart must tell the session to continue once it is back. A turn was running when the restart began (the
/// registry's status is neither idle nor waiting) and the restart carries no prompt of its own: a resume starts no turn,
/// so the cut-off one would never go on.
pub fn restart_continues(before: Option<&Registry>, prompt: &str) -> bool {
    prompt.is_empty() && before.is_some_and(|b| !b.status.is_empty() && b.status != "idle" && b.status != "waiting")
}

impl Router {
    /// running → in place (the supervisor relaunches claude --resume in the new mode within ~5 s; nothing else
    /// restarts); paused → the next start. Runs in the background; the job is the session's `wake` in /api/state.
    pub fn set_permission_mode(self: &Arc<Self>, id: &str, mode: &str) -> Result<Value> {
        let mode = if mode == "bypass" { "bypass" } else { "auto" };
        let s = self.st.do_(|d| d.sessions.get(id).cloned()).ok_or_else(crate::sessionapi::no_session)?;
        if s.permission_mode == mode {
            return Ok(json!({"ok": true, "permissionMode": mode, "unchanged": true}));
        }
        if s.machine_id.is_empty() {
            // no machine: the mode applies at its next start (a paused or failed session)
            if s.state != "paused" && s.state != "failed" {
                return Err(anyhow!("session is {}: set the mode once it is running, paused or failed", s.state));
            }
            self.st.do_(|d| {
                if let Some(x) = d.sessions.get_mut(id) {
                    x.permission_mode = mode.into();
                }
            });
            return Ok(json!({"ok": true, "permissionMode": mode, "nextStart": true}));
        }
        // raising a running session to bypass needs a fresh phone grant (Deyao, 2026-10-09), checked here and by the
        // machine (exec_phone)
        if mode == "bypass" && !self.has_phone_grant(id, "terminal") {
            return Err(GrantNeeded { holder: "terminal".into(), phone: true }.into());
        }
        let unlock = self.lock_args(id, "mode", json!({"mode": mode}))?;
        let j = match self.ops.start_job(id, "permission-mode") {
            Ok(j) => j,
            Err(e) => {
                unlock.call();
                return Err(e);
            }
        };
        let (r, id, m) = (self.clone(), id.to_string(), mode.to_string());
        std::thread::spawn(move || r.mode_run(&id, &m, j, unlock));
        Ok(json!({"started": true, "kind": "permission-mode", "permissionMode": mode, "inPlace": true}))
    }

    /// the running session's switch to mode, under its job (jobs.rs: a replica carrying the job on runs it again:
    /// setting the mode the session already has is a no-op on the machine)
    pub fn mode_run(self: &Arc<Self>, id: &str, mode: &str, j: WakeJob, unlock: crate::util::OnceFn) {
        let _u = crate::flows::scopeguard(move || unlock.call());
        self.ops.phase(&j, "switching", None);
        let cmd = format!("{SET_PERMISSION_MODE_CMD}{mode}");
        let res = if mode == "bypass" {
            self.exec_phone(id, "terminal", &cmd, Duration::from_secs(30))
        } else {
            self.exec(id, "terminal", &cmd, Duration::from_secs(30))
        };
        let res = res.and_then(|r| {
            if r.code != 0 {
                return Err(anyhow!("set-permission-mode exited {}: {}", r.code, clip(&format!("{}{}", r.stderr, r.stdout), 200)));
            }
            Ok(())
        });
        if let Err(e) = res {
            self.mark_refused(id, "terminal", &e);
            self.ops.phase(&j, "failed", Some(&e));
            return;
        }
        self.st.do_(|d| {
            if let Some(x) = d.sessions.get_mut(id) {
                x.permission_mode = mode.into();
            }
        });
        self.ops.phase(&j, "done", None);
    }

    /// the switch to mode waits on a fresh phone grant for holder: a grant request (10 minutes) goes into the Inbox,
    /// filed as the caller's, and the switch is kept on the session until that request lapses
    pub fn ask_mode_grant(self: &Arc<Self>, req: &Req, id: &str, mode: &str, holder: &str) -> Result<Value> {
        let mut args = Map::new();
        args.insert("mode".into(), json!(mode));
        let o = Origin {
            caller: crate::inbox::app_caller(req),
            call: ApiCall { method: req.method.clone(), path: req.path.clone(), args, ..Default::default() },
            via_call: crate::apicalls::via_call(req),
            ..Default::default()
        };
        let title = self.st.do_(|d| crate::inbox::inbox_session_name(d, id));
        // says what asked and for what: the caller is named from its credential (callerText), this names the session
        let why = format!(
            "Switch session “{title}” ({id}) to {mode} permission mode: Claude relaunches in it at once. Raising it to bypass needs this fresh 10-minute terminal grant; the switch runs as soon as it is signed."
        );
        let via = o.via_call.clone();
        let (q, dup) = self.file_request(
            crate::inbox::REQUEST_KIND_GRANT,
            RequestParams { session: id.into(), holder: holder.into(), minutes: 10, ..Default::default() },
            &why,
            o,
        )?;
        self.st.do_(|d| {
            if let Some(s) = d.sessions.get_mut(id) {
                s.ops.get_or_insert_with(Default::default).mode_after_grant =
                    Some(ModeAfterGrant { mode: mode.into(), inbox: q.id.clone(), until: q.expires });
            }
            // an approved API call's review sheet follows the grant it brought about (apicalls.rs)
            if let Some(x) = d.call_results.get_mut(&via) {
                if !x.followups.contains(&q.id) {
                    x.followups.push(q.id.clone());
                }
                x.awaiting = None;
            }
        });
        Ok(json!({"waiting": "inbox", "inboxId": q.id, "duplicate": dup, "needsGrant": holder, "phoneGrant": true, "permissionMode": mode}))
    }

    /// the switch a signed grant was waiting for; its outcome is the session's `wake` job, as when it is asked for
    /// directly
    pub fn run_mode_after_grant(self: &Arc<Self>, id: &str, mode: &str) {
        if let Err(e) = self.set_permission_mode(id, mode) {
            crate::logf!("session {id}: the switch to {mode} after the grant: {e:#}");
            if let Ok(j) = self.ops.start_job(id, "permission-mode") {
                self.ops.phase(&j, "failed", Some(&e));
            }
        }
    }

    /// a grant refusal shows as the session's needsGrant, so the app offers a grant
    pub fn mark_refused(&self, id: &str, holder: &str, err: &anyhow::Error) {
        if !crate::peer::is_grant_refusal(Some(err)) {
            return;
        }
        self.st.do_(|d| {
            if let Some(x) = d.sessions.get_mut(id) {
                x.live.get_or_insert_with(Liveness::default).needs_grant = holder.into();
            }
        });
    }

    /// only to a paused session (they reach the machine through the next start's env and /start's size)
    pub fn apply_resume_options(&self, id: &str, o: ResumeOptions) -> Result<()> {
        o.check()?;
        if o.size.is_empty() && o.model.is_empty() && o.api_proxy.is_none() {
            return Ok(());
        }
        self.st.do_(|d| {
            let s = d.sessions.get_mut(id).ok_or_else(crate::sessionapi::no_session)?;
            if s.state != "paused" && s.state != "failed" {
                return Err(anyhow!(
                    "session {id} is {}: its next start's options are set while it is paused or failed",
                    s.state
                ));
            }
            if !o.model.is_empty() {
                resume_model(&s.harness, &o.model)?;
            }
            if !o.size.is_empty() {
                s.size = o.size.clone();
            }
            if !o.model.is_empty() {
                s.model = o.model.clone();
            }
            if let Some(p) = o.api_proxy {
                s.ops.get_or_insert_with(Default::default).api_proxy = p;
            }
            Ok(())
        })
    }

    /// a running session is paused (its signed snapshot), then the patch and the rollback are recorded, then it resumes
    /// on the same image (the dead-machine rule). A paused one just resumes. One restarted in the middle of a turn gets
    /// "continue" once its harness is up again (restart_continues).
    pub fn restart(self: &Arc<Self>, id: &str, input: RestartRequest) -> Result<Value> {
        let patch = normalize_env_patch(&input.env)?;
        input.resume.check()?;
        let mut marker = String::new();
        if let Some(rb) = &input.rollback {
            marker = rb.drop_from_marker.trim().to_string();
            if marker.len() < 4 || marker.len() > 500 || marker.contains(['\n', '\r', '\0']) {
                return Err(anyhow!("rollback.dropFromMarker: 4–500 characters on one line"));
            }
        }
        let prompt = crate::sessionapi::clean_resume_prompt(&input.prompt)?;
        let s = self.st.do_(|d| d.sessions.get(id).cloned()).ok_or_else(crate::sessionapi::no_session)?;
        // paused or failed (Resume finishes a failed one's pause first), or running on its machine
        if s.state != "paused" && s.state != "failed" && (s.machine_id.is_empty() || (s.state != "started" && s.state != "initialising")) {
            return Err(anyhow!("session is {}: restart it once it is running, paused or failed", s.state));
        }
        // the whole job is one tracked lifecycle action (drain.rs): its pause and resume go on during a drain
        let end_job = self.begin_job(id, "restart")?;
        let j = match self.ops.start_job(id, "restart") {
            Ok(j) => j,
            Err(e) => {
                end_job.call();
                return Err(e);
            }
        };
        // a turn that runs now is cut off by the pause: the session is told to continue once it is back
        let before = if s.machine_id.is_empty() { None } else { self.live_reg(id, &s.machine_id).0 };
        let cont = restart_continues(before.as_ref(), &prompt);
        self.ops.set_busy(id, "restarting");
        let op = self.lc_begin_job(id, "restart"); // lifecycle.rs: its pause and resume are this one operation
        op.machine(&s.machine_id);
        let keys: Vec<String> = patch.keys().cloned().collect();
        let upgrade = input.upgrade;
        let has_marker = !marker.is_empty();
        let (r, id) = (self.clone(), id.to_string());
        std::thread::spawn(move || {
            let _e = crate::flows::scopeguard(move || end_job.call());
            let (r2, id2) = (r.clone(), id.clone());
            let _b = crate::flows::scopeguard(move || r2.ops.set_busy(&id2, ""));
            let fail = |e: anyhow::Error| {
                r.cancel_spare(&id, "the restart failed");
                r.ops.phase(&j, "failed", Some(&e));
                op.end_job(Some(&e));
            };
            if !s.machine_id.is_empty() {
                // handover.rs: an unattended restart (no prompt, no rollback: those go to the phone) starts its next
                // machine as soon as the old one is told to stop
                let next = if prompt.is_empty() && marker.is_empty() && !upgrade {
                    r.handover_next(&s, &input.resume.size, 0) // a spare runs the same image: not for an upgrade
                } else {
                    None
                };
                r.ops.phase(&j, "snapshotting", None);
                if let Err(e) = r.pause_with(&id, next) {
                    return fail(e);
                }
                if let Err(e) = r.wait_action_end(&id, "paused") {
                    return fail(e);
                }
            }
            r.ops.phase(&j, "patching", None);
            let res = r.st.do_(|d| {
                let x = d.sessions.get_mut(&id).filter(|x| x.state == "paused" || x.state == "failed").ok_or_else(|| {
                    anyhow!("the session isn't paused any more (another action started it): restart it again")
                })?;
                let pred = crate::sessionops::cert_machine(x.cert.as_ref());
                let ops = x.ops.get_or_insert_with(Default::default);
                for (k, v) in &patch {
                    match v {
                        None => {
                            ops.env.remove(k);
                        }
                        Some(v) => {
                            ops.env.insert(k.clone(), v.clone());
                        }
                    }
                }
                ops.rollback = (!marker.is_empty()).then(|| RollbackMark { marker: marker.clone(), pred });
                Ok(())
            });
            if let Err(e) = res.and_then(|()| r.apply_resume_options(&id, input.resume.clone())) {
                return fail(e);
            }
            r.ops.phase(&j, "resuming", None);
            if let Err(e) = r.handover_resume(&id, &prompt, upgrade) {
                return fail(e);
            }
            if cont {
                r.continue_after_restart(&j, &id);
            }
            r.ops.phase(&j, "done", None);
            op.end_job(None);
        });
        Ok(json!({"started": true, "kind": "restart", "env": keys, "rollback": has_marker, "upgrade": upgrade}))
    }

    /// "continue" into the restarted session once its new machine's harness is up and idle (the canned delivery the
    /// account switch uses). A harness that doesn't come up in time leaves a note on the job: the restart itself is
    /// done.
    fn continue_after_restart(self: &Arc<Self>, j: &WakeJob, id: &str) {
        let machine = self.st.do_(|d| d.sessions.get(id).map(|x| x.machine_id.clone()).unwrap_or_default());
        self.ops.phase(j, "delivering continue", None);
        let wait = crate::accountswap::swap_up_wait();
        if let Err(e) = self.wait_reg(id, &machine, wait, |g| g.status == "idle") {
            let w = jarvis_go::fmt::duration_string(wait);
            self.ops.note(j, &format!("the restarted session's harness didn't come up idle within {w}: its cut-off turn was not continued"));
            crate::logf!("[restart] {id}: no idle harness within {w}, \"continue\" not delivered: {e:#}");
            return;
        }
        if let Err(e) = self.deliver_canned(id, Delivery { kind: "continue".into(), ..Default::default() }, "continue") {
            self.ops.note(j, &format!("\"continue\" could not be delivered: {e:#}"));
            crate::logf!("[restart] {id}: delivering \"continue\": {e:#}");
            return;
        }
        crate::logf!("[restart] {id}: \"continue\" delivered (a turn was running when it was restarted)");
    }

    /// polls until the session reaches state (or fails / disappears) AND the action that got it there has ended. An
    /// action sets its end state a moment before it releases the session's lock (its lifecycle record and unlock run
    /// after), so returning on the state alone let the caller's next action (the resume after a pause) meet a busy
    /// session, and work of the ended action still run after the caller moved on.
    pub fn wait_state(&self, id: &str, want: &str, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        loop {
            let (st, msg) = self.st.do_(|d| d.sessions.get(id).map(|x| (x.state.clone(), x.error.clone())).unwrap_or_default());
            let busy = self.busy(id);
            if st == want && !busy {
                return Ok(());
            }
            if st.is_empty() {
                return Err(crate::sessionapi::no_session());
            }
            if st == "failed" && !busy {
                return Err(anyhow!("the session failed: {msg}"));
            }
            if Instant::now() > deadline {
                if busy {
                    return Err(anyhow!("the session is {st} and its action hasn't ended"));
                }
                return Err(anyhow!("the session is still {st}"));
            }
            std::thread::sleep(OPS_POLL);
        }
    }

    /// a job's step (a pause it began, which holds the session's lock) has ended, with no deadline of its own: the
    /// action ends by itself (a pause once its snapshot arrives, stalls or its machine goes silent: snapwait.rs, then the
    /// kill's own limit). want = the state it should end in; failed or anything else is the error.
    pub fn wait_action_end(&self, id: &str, want: &str) -> Result<()> {
        loop {
            let (st, msg) = self.st.do_(|d| d.sessions.get(id).map(|x| (x.state.clone(), x.error.clone())).unwrap_or_default());
            if st.is_empty() {
                return Err(crate::sessionapi::no_session());
            }
            if !self.busy(id) {
                if st == want {
                    return Ok(());
                }
                if st == "failed" {
                    return Err(anyhow!("the session failed: {msg}"));
                }
                return Err(anyhow!("the session is {st}"));
            }
            std::thread::sleep(OPS_POLL);
        }
    }
}

pub fn register_session_ops(reg: &mut Registrar) {
    reg.app("POST /api/sessions/{id}/permission-mode", |r, w, req| {
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct In {
            mode: String,
        }
        let i: In = crate::http::decode_body(req, 1 << 16);
        let id = req.path_value("id");
        let mut res = r.set_permission_mode(&id, &i.mode);
        // the iPhone app opens its own grant review on the 403 and switches again once it is signed; everyone else (the
        // web page, an approved API call) gets the grant filed in the Inbox, with the switch run when it is signed
        if let Err(e) = &res
            && let Some(gn) = e.downcast_ref::<GrantNeeded>()
            && gn.phone
            && crate::inbox::app_caller(req).kind != "app"
        {
            let holder = gn.holder.clone();
            res = r.ask_mode_grant(req, &id, &i.mode, &holder);
        }
        match res {
            Err(e) => crate::schedule::schedule_err(w, &e),
            Ok(out) => {
                let code = if out.get("started") == Some(&json!(true)) || out.get("waiting") == Some(&json!("inbox")) {
                    202
                } else {
                    200
                };
                write_json(w, code, &out);
            }
        }
    });
    reg.app("POST /api/sessions/{id}/restart", |r, w, req| {
        let b = req.read_body(1 << 20);
        let input: RestartRequest = if String::from_utf8_lossy(&b).trim().is_empty() {
            RestartRequest::default()
        } else {
            match jarvis_go::unmarshal(&b) {
                Ok(i) => i,
                Err(e) => return write_err(w, &anyhow!("bad JSON: {e}")),
            }
        };
        match r.restart(&req.path_value("id"), input) {
            Err(e) => crate::schedule::schedule_err(w, &e),
            Ok(out) => write_json(w, 202, &out),
        }
    });
    // Jarvis 1's env patch = a restart with only env
    reg.app("POST /api/sessions/{id}/env", |r, w, req| {
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct In {
            env: Map<String, Value>,
        }
        let i: In = crate::http::decode_body(req, 1 << 20);
        if i.env.is_empty() {
            return write_json(w, 400, &json!({"error": "body.env must be a non-empty object"}));
        }
        match r.restart(&req.path_value("id"), RestartRequest { env: i.env, ..Default::default() }) {
            Err(e) => crate::schedule::schedule_err(w, &e),
            Ok(out) => write_json(w, 202, &out),
        }
    });
    crate::accountswap::register_account_switch(reg); // accountswap.rs
    crate::uploads::register_uploads(reg); // uploads.rs
    crate::repos::register_repos(reg); // repos.rs: repo list, GitHub picker, usage
}


/// the machine a cert names (its machine.id; "" for none)
pub fn cert_machine(c: Option<&crate::core::Doc>) -> String {
    #[derive(serde::Deserialize, Default)]
    #[serde(default)]
    struct M {
        id: String,
    }
    #[derive(serde::Deserialize, Default)]
    #[serde(default)]
    struct X {
        machine: M,
    }
    c.and_then(|c| c.decode::<X>().ok()).map(|x| x.machine.id).unwrap_or_default()
}
