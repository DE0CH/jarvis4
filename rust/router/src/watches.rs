//! Watches (conditional wakeups; Jarvis 1's lib/watch.js and its server.js loop, in Jarvis 4's shape). A session arms
//! a watch with its own signed request: a check script, the prompt for when the condition is met, a "fail" prompt for
//! when it gives up, an interval and a maximum age. The router runs the check on the box's watch runner
//! (k8s/services/apps/watch/watch.yaml, services/watch) every interval, whether the session is running or paused; the
//! runner holds no secrets and reaches only the public internet, so a check gets none of the session's stores
//! (docs/DECISIONS.md 101). Exit 0 = met: the prompt is delivered (the session resumed first when it is paused); exit
//! 3, or the maximum age passed = give up: the fail prompt is delivered instead. Any other exit = not yet.
//!
//! The delivery is the session's own signed request ("watch" or "watch-fail", rust/machine/src/deliver.rs checks it
//! against the line's keys and the core attests it), exactly like a wakeup: the router picks when, never what. The
//! runner's output never reaches the agent (nothing vouches for it); the machine runs the check once more itself, with
//! the session's own env, and appends that output. Watches belong to their session (Schedule.watches) and end with it;
//! a session with an armed watch is kept (pending_schedule), so a paused one stays until the watch fires.

use crate::http::Registrar;
use crate::nethttp::{Req, W, write_error, write_json};
use crate::router::{Router, bad};
use crate::schedule::{
    SCHEDULE_MAX_ATTEMPT, SCHEDULE_NAME_RE, Schedule, clean_prompt, iso, number, sched, sched_claim, sched_failed, sched_forget,
    sched_release,
};
use crate::sessionapi::{no_session, schedule_err};
use crate::state::Persisted;
use crate::vouch::{Delivery, SignedRequest};
use anyhow::{Result, anyhow};
use jarvis_go::GoTime;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const WATCH_MAX_SCRIPT: usize = 32 * 1024;
pub const WATCH_MAX_PROMPT: usize = 3500;
pub const WATCH_MIN_INTERVAL: f64 = 30.0;
pub const WATCH_MAX_INTERVAL: f64 = 3600.0;
pub const WATCH_DEFAULT_INTERVAL: i64 = 60;
pub const WATCH_MAX_SECONDS: f64 = 400.0 * 24.0 * 60.0 * 60.0;
pub const WATCH_DEFAULT_SECONDS: i64 = 7 * 24 * 60 * 60;
/// seconds, on the runner
pub const WATCH_CHECK_TIMEOUT: u64 = 90;
pub const WATCH_TICK_EVERY: Duration = Duration::from_secs(10);
pub const WATCH_KEEP_OUTPUT: usize = 2000;

fn is_zero(n: &i64) -> bool {
    *n == 0
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Watch {
    pub name: String,
    pub script: String,
    pub prompt: String,
    #[serde(rename = "failPrompt", skip_serializing_if = "String::is_empty")]
    pub fail_prompt: String,
    /// seconds
    pub interval: i64,
    /// from armed_at
    #[serde(rename = "maxSeconds")]
    pub max_seconds: i64,
    /// ms: the arming's identity (compare-and-clear)
    #[serde(rename = "armedAt")]
    pub armed_at: i64,
    /// ms: the next check
    #[serde(rename = "nextAt")]
    pub next_at: i64,
    pub runs: i64,
    #[serde(rename = "lastRunAt", skip_serializing_if = "is_zero")]
    pub last_run_at: i64,
    #[serde(rename = "lastExit", skip_serializing_if = "Option::is_none")]
    pub last_exit: Option<i64>,
    /// the last stderr line, or why the runner couldn't run it
    #[serde(rename = "lastError", skip_serializing_if = "String::is_empty")]
    pub last_error: String,
    /// the start of the last stdout (shown in the app, never delivered)
    #[serde(rename = "lastOutput", skip_serializing_if = "String::is_empty")]
    pub last_output: String,
    /// "" = checking; "met" or "gave-up" = waiting for its delivery
    #[serde(skip_serializing_if = "String::is_empty")]
    pub outcome: String,
    /// the session's own request that armed it, as its machine signed it: what vouches for the delivery
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed: Option<SignedRequest>,
}

pub fn normalize_watch(b: &Map<String, Value>, now: GoTime) -> Result<Watch> {
    let name = match b.get("name") {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(s)) => s.trim().to_string(),
        Some(v) => jarvis_go::fmt::go_sprint(v).trim().to_string(),
    };
    if !SCHEDULE_NAME_RE.is_match(&name) {
        return Err(bad("name must be 1-40 chars of letters, digits, _ or -"));
    }
    let script = b.get("script").and_then(Value::as_str).unwrap_or("").replace("\r\n", "\n").replace('\r', "\n");
    if script.trim().is_empty() {
        return Err(bad("script is required (the check; exit 0 = condition met, 3 = give up, else not yet)"));
    }
    if script.len() > WATCH_MAX_SCRIPT {
        return Err(bad(format!("script longer than {WATCH_MAX_SCRIPT} bytes")));
    }
    let prompt = clean_prompt(b.get("prompt"));
    if prompt.is_empty() {
        return Err(bad("prompt is required — what the session should do when the condition is met"));
    }
    let fail = clean_prompt(b.get("failPrompt"));
    if prompt.chars().count() > WATCH_MAX_PROMPT || fail.chars().count() > WATCH_MAX_PROMPT {
        return Err(bad(format!("prompt or failPrompt longer than {WATCH_MAX_PROMPT} characters")));
    }
    let mut interval = WATCH_DEFAULT_INTERVAL;
    if let Some(v) = b.get("interval").filter(|v| !v.is_null()) {
        let f = number(v).ok_or_else(|| bad("interval must be seconds"))?;
        interval = f.round().clamp(WATCH_MIN_INTERVAL, WATCH_MAX_INTERVAL) as i64;
    }
    let mut max_s = WATCH_DEFAULT_SECONDS;
    if let Some(v) = b.get("maxSeconds").filter(|v| !v.is_null()) {
        let f = number(v).filter(|f| *f > 0.0).ok_or_else(|| bad("maxSeconds must be a positive number"))?;
        max_s = f.round().min(WATCH_MAX_SECONDS) as i64;
    }
    let ms = (now.unix_nanos() / 1_000_000) as i64;
    Ok(Watch {
        name,
        script,
        prompt,
        fail_prompt: fail,
        interval,
        max_seconds: max_s,
        armed_at: ms,
        next_at: ms,
        ..Default::default()
    })
}

/// no script body (Jarvis 1's view, plus the last run)
pub fn watch_view(w: &Watch) -> Value {
    json!({"name": w.name, "prompt": w.prompt, "failPrompt": w.fail_prompt, "interval": w.interval, "maxSeconds": w.max_seconds,
        "armedAt": w.armed_at, "armedAtIso": iso(w.armed_at), "expiresAtIso": iso(w.armed_at + w.max_seconds * 1000), "nextCheckIso": iso(w.next_at),
        "runs": w.runs, "lastExit": w.last_exit, "lastRunIso": if w.last_run_at != 0 { json!(iso(w.last_run_at)) } else { Value::Null },
        "lastError": w.last_error, "lastOutput": w.last_output, "outcome": w.outcome})
}

pub fn sorted_watches(s: Option<&Schedule>) -> Vec<Watch> {
    let mut out: Vec<Watch> = s.map(|s| s.watches.values().cloned().collect()).unwrap_or_default();
    out.sort_by_key(|w| w.armed_at);
    out
}

pub fn watches_view_of(d: &Persisted, sid: &str) -> Vec<Value> {
    sorted_watches(d.schedules.get(sid)).iter().map(watch_view).collect()
}

// ---- running the checks --------------------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct CheckResult {
    pub exit: i64,
    pub stdout: String,
    pub stderr: String,
    #[serde(rename = "timedOut")]
    pub timed_out: bool,
}

pub fn watch_runner_url() -> String {
    crate::router::env("WATCH_URL", "http://10.77.0.3:30095").trim_end_matches('/').to_string()
}

pub type CheckFn = fn(&Watch) -> Result<CheckResult>;

/// the real check: the watch runner runs it
fn run_check_live(w: &Watch) -> Result<CheckResult> {
    let c = reqwest::blocking::Client::builder().timeout(Duration::from_secs(WATCH_CHECK_TIMEOUT + 45)).build()?;
    let body = jarvis_go::marshal(&json!({"script": w.script, "name": w.name, "timeout": WATCH_CHECK_TIMEOUT}));
    let resp = c
        .post(format!("{}/run", watch_runner_url()))
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .map_err(|e| anyhow!("the watch runner is unreachable: {e}"))?;
    let st = resp.status().as_u16();
    let b = crate::util::read_limited(resp, 1 << 20).unwrap_or_default();
    if st != 200 {
        return Err(anyhow!("the watch runner answered {st}: {}", crate::util::trim_to(&String::from_utf8_lossy(&b), 200)));
    }
    jarvis_go::unmarshal(&b).map_err(|e| anyhow!("the watch runner's answer: {e}"))
}

/// a seam for tests; the real one asks the watch runner
pub static RUN_CHECK_HOOK: std::sync::RwLock<CheckFn> = std::sync::RwLock::new(run_check_live);

pub fn run_check_hook(w: &Watch) -> Result<CheckResult> {
    (*RUN_CHECK_HOOK.read().unwrap_or_else(|e| e.into_inner()))(w)
}

pub fn last_line_of(s: &str) -> String {
    let t = s.trim();
    let last = t.rsplit('\n').next().unwrap_or("");
    crate::util::trim_to(last.trim(), 300)
}

static WATCH_TICKING: Mutex<()> = Mutex::new(());

fn now_ms() -> i64 {
    (GoTime::now().unix_nanos() / 1_000_000) as i64
}

impl Router {
    pub fn list_watches(&self, sid: &str) -> Result<Vec<Value>> {
        self.st.do_(|d| {
            if !d.sessions.contains_key(sid) {
                return Err(no_session());
            }
            Ok(watches_view_of(d, sid))
        })
    }

    pub fn arm_watch(&self, sid: &str, w: &Watch) -> Result<()> {
        self.st.do_(|d| {
            self.live_session(d, sid)?;
            sched(d, sid).watches.insert(w.name.clone(), w.clone());
            Ok::<(), anyhow::Error>(())
        })?;
        sched_forget(&format!("{sid}/watch/{}", w.name));
        crate::logf!(
            "[watch] {sid} armed {} every {}s for up to {}h: {}",
            jarvis_go::fmt::go_quote(&w.name),
            w.interval,
            w.max_seconds / 3600,
            crate::util::trim_to(&w.prompt, 80)
        );
        Ok(())
    }

    pub fn cancel_watch(&self, sid: &str, name: &str) -> Result<()> {
        let res = self.st.do_(|d| {
            if !d.sessions.contains_key(sid) {
                return Err(no_session());
            }
            sched(d, sid).watches.remove(name);
            Ok(())
        });
        sched_forget(&format!("{sid}/watch/{name}"));
        if res.is_ok() {
            crate::logf!("[watch] {sid} cancelled {}", jarvis_go::fmt::go_quote(name));
        }
        res
    }

    pub fn watch_loop(self: &Arc<Self>) {
        loop {
            std::thread::sleep(WATCH_TICK_EVERY);
            crate::leaderlease::await_lead();
            self.watch_tick(GoTime::now());
        }
    }

    /// each due check runs (one at a time per watch); each met or given-up watch is delivered. → the threads started
    /// (tests wait for them)
    pub fn watch_tick(self: &Arc<Self>, now: GoTime) -> Vec<std::thread::JoinHandle<()>> {
        let Ok(_g) = WATCH_TICKING.try_lock() else { return vec![] };
        let now_ms = (now.unix_nanos() / 1_000_000) as i64;
        let items: Vec<(String, String, i64, bool)> = self.st.do_(|d| {
            let mut items = vec![];
            for (sid, s) in &d.schedules {
                let Some(ss) = d.sessions.get(sid) else { continue };
                if ss.state == "destroyed" || ss.state == "destroying" {
                    continue;
                }
                for w in s.watches.values() {
                    if !w.outcome.is_empty() {
                        items.push((sid.clone(), w.name.clone(), w.armed_at, true));
                    } else if w.next_at <= now_ms {
                        items.push((sid.clone(), w.name.clone(), w.armed_at, false));
                    }
                }
            }
            items
        });
        let mut out = vec![];
        for (sid, name, armed_at, deliver) in items {
            let key = format!("{sid}/watch/{name}");
            if !sched_claim(&key) {
                continue;
            }
            let r = self.clone();
            out.push(std::thread::spawn(move || {
                let _release = crate::flows::scopeguard(|| sched_release(&key));
                if deliver {
                    r.deliver_watch(&sid, &name, armed_at, &key);
                } else {
                    r.check_watch(&sid, &name, armed_at, &key);
                }
            }));
        }
        out
    }

    /// a copy of the armed watch, if it is still the one armed at armed_at
    pub fn watch_of(&self, sid: &str, name: &str, armed_at: i64) -> Option<Watch> {
        self.st.do_(|d| d.schedules.get(sid).and_then(|s| s.watches.get(name)).filter(|w| w.armed_at == armed_at).cloned())
    }

    pub fn check_watch(self: &Arc<Self>, sid: &str, name: &str, armed_at: i64, key: &str) {
        let Some(w) = self.watch_of(sid, name, armed_at).filter(|w| w.outcome.is_empty()) else { return };
        let res = run_check_hook(&w);
        let now = now_ms();
        let outcome = match &res {
            Ok(r) if r.exit == 0 => "met",
            Ok(r) if r.exit == 3 => "gave-up",
            _ if now >= w.armed_at + w.max_seconds * 1000 => "gave-up",
            _ => "",
        };
        self.st.do_(|d| {
            let Some(cur) = d.schedules.get_mut(sid).and_then(|s| s.watches.get_mut(name)).filter(|w| w.armed_at == armed_at) else {
                return; // cancelled or replaced meanwhile
            };
            cur.runs += 1;
            cur.last_run_at = now;
            cur.next_at = now + cur.interval * 1000;
            match &res {
                Err(e) => {
                    cur.last_error = format!("{e:#}");
                    cur.last_exit = None;
                }
                Ok(r) => {
                    cur.last_exit = Some(r.exit);
                    cur.last_error = last_line_of(&r.stderr);
                    cur.last_output = crate::util::trim_to(&r.stdout, WATCH_KEEP_OUTPUT);
                    if r.timed_out {
                        cur.last_error = "the check timed out after 90 s".into();
                    }
                }
            }
            cur.outcome = outcome.into();
        });
        match &res {
            _ if !outcome.is_empty() => {
                crate::logf!("[watch] {sid} {} {outcome} after {} checks", jarvis_go::fmt::go_quote(name), w.runs + 1);
                self.deliver_watch(sid, name, armed_at, key); // now rather than at the next tick
            }
            Err(e) => crate::logf!("[watch] {sid} {}: {e:#}", jarvis_go::fmt::go_quote(name)),
            Ok(r) if r.exit != 1 || r.timed_out || !r.stderr.trim().is_empty() => crate::logf!(
                "[watch] {sid} {} not yet (exit {}{}) {}",
                jarvis_go::fmt::go_quote(name),
                r.exit,
                if r.timed_out { ", timed out" } else { "" },
                crate::util::trim_to(&last_line_of(&r.stderr), 160)
            ),
            Ok(_) => {}
        }
    }

    pub fn deliver_watch(self: &Arc<Self>, sid: &str, name: &str, armed_at: i64, key: &str) {
        let Some(w) = self.watch_of(sid, name, armed_at).filter(|w| !w.outcome.is_empty()) else { return };
        let kind = if w.outcome == "gave-up" { "watch-fail" } else { "watch" };
        let res = match &w.signed {
            None => Err(anyhow!(crate::vouch::NOT_VOUCHED)),
            Some(s) => crate::schedule::deliver_vouched_hook(
                self,
                sid,
                Delivery { kind: kind.into(), request: Some(s.clone()), ..Default::default() },
            ),
        };
        let clear = || {
            self.st.do_(|d| {
                if let Some(s) = d.schedules.get_mut(sid)
                    && s.watches.get(name).is_some_and(|x| x.armed_at == armed_at)
                {
                    s.watches.remove(name);
                }
            })
        };
        let err = match res {
            Ok(()) => {
                sched_forget(key);
                crate::logf!("[watch] {sid} {} delivered ({kind})", jarvis_go::fmt::go_quote(name));
                clear();
                return;
            }
            Err(e) => e,
        };
        if crate::schedule::is_skip(&err) {
            return;
        }
        let drop = sched_failed(key);
        crate::logf!("[watch] {sid} {} delivery failed (drop={drop}): {err:#}", jarvis_go::fmt::go_quote(name));
        let known = crate::flows::known_error(&err);
        self.st.do_(|d| {
            if let Some(x) = d.schedules.get_mut(sid).and_then(|s| s.watches.get_mut(name)).filter(|x| x.armed_at == armed_at) {
                x.last_error = format!("delivery: {known}");
            }
        });
        if drop {
            clear();
            let label = self
                .st
                .do_(|d| d.sessions.get(sid).map(crate::titles::session_title))
                .unwrap_or_else(|| sid.to_string());
            self.dm(&format!(
                "Watch “{name}” of session “{label}” ({}) could not be delivered after {SCHEDULE_MAX_ATTEMPT} attempts: {known}",
                w.outcome
            ));
        }
    }

    fn get_watches(&self, w: &mut W, sid: &str) {
        match self.list_watches(sid) {
            Err(e) => schedule_err(w, &e),
            Ok(out) => write_json(w, 200, &json!({"watches": out})),
        }
    }

    fn delete_watch(&self, w: &mut W, sid: &str, name: &str) {
        if !SCHEDULE_NAME_RE.is_match(name) {
            return write_error(w, 400, "bad watch name");
        }
        match self.cancel_watch(sid, name) {
            Err(e) => schedule_err(w, &e),
            Ok(()) => write_json(w, 200, &json!({"ok": true})),
        }
    }
}

// ---- routes ------------------------------------------------------------------------------------------------

/// a route of the session's own machine: f gets its session id (the path's {id} must be it)
fn own(reg: &mut Registrar, pattern: &str, f: impl Fn(&Arc<Router>, &mut W, &mut Req, &str, &[u8]) + Send + Sync + 'static) {
    reg.m(pattern, move |r, w, req, machine, body| {
        let sid = match r.machine_session(machine) {
            Ok(s) => s,
            Err(e) => return write_error(w, 403, &format!("{e:#}")),
        };
        let id = req.path_value("id");
        if id != sid {
            return write_error(w, 403, &format!("this machine is session {sid}, not {id}"));
        }
        f(r, w, req, &sid, body)
    });
}

pub fn register_watches(reg: &mut Registrar) {
    reg.app("GET /api/sessions/{id}/watches", |r, w, req| r.get_watches(w, &req.path_value("id")));
    reg.app("DELETE /api/sessions/{id}/watches/{name}", |r, w, req| {
        r.delete_watch(w, &req.path_value("id"), &req.path_value("name"))
    });
    // arming from the app: nothing would vouch for its delivery into the session (only the session's own request does)
    reg.app("POST /api/sessions/{id}/watches", |_, w, _| {
        write_error(
            w,
            400,
            "a watch is armed by the session itself (scripts/schedule-watch.sh): only its own signed request can be delivered into it",
        )
    });
    own(reg, "GET /m/api/sessions/{id}/watches", |r, w, _, sid, _| r.get_watches(w, sid));
    own(reg, "POST /m/api/sessions/{id}/watches", |r, w, req, sid, b| {
        let res = crate::sessionapi::decode_map(b).and_then(|m| normalize_watch(&m, GoTime::now())).and_then(|mut wt| {
            wt.signed = Some(crate::vouch::signed_request_of(req, &req.header("X-Machine"), b));
            r.arm_watch(sid, &wt).map(|()| wt)
        });
        match res {
            Err(e) => schedule_err(w, &e),
            Ok(wt) => write_json(w, 200, &json!({"ok": true, "watch": watch_view(&wt)})),
        }
    });
    own(reg, "DELETE /m/api/sessions/{id}/watches/{name}", |r, w, req, sid, _| r.delete_watch(w, sid, &req.path_value("name")));
}
