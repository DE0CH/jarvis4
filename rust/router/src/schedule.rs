//! Wakeups, crons and the resume prompt (Jarvis 1's lib/wakeup.js, lib/cron.js and server.js "scheduled wakeup",
//! "recurring wakeup", "resume prompt"): at a due time the router delivers a prompt into the session, resuming it first
//! when it is paused. Same request and response shapes as Jarvis 1.
//!
//! They belong to their session (Persisted.schedules, keyed by session id) and end with it: once the session is gone
//! from the list, the tick drops them. A session with pending ones must not be destroyed by an automatic path
//! (pending_schedule).
//!
//! Each is delivered as a core-attested delivery the machine checks (vouch.rs): a wakeup or cron as the session's own
//! signed request; a resume prompt (Deyao's words from the app) only under the phone's signature of exactly it. Into a
//! session holding a sensitive store every message waits in the Inbox for Deyao to deliver or deny it (messages.rs).

use crate::router::{BadReq, Router, bad};
use crate::state::Persisted;
use crate::vouch::{Delivery, SignedRequest};
use crate::watches::Watch;
use anyhow::{Result, anyhow};
use jarvis_go::GoTime;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::sync::{Arc, LazyLock, Mutex, RwLock};
use std::time::{Duration, Instant};

pub const WAKEUP_DEFAULT: &str = "default";
pub const SCHEDULE_MAX_PROMPT: usize = 3500;
/// as far as a cron's until
pub const WAKEUP_MAX_DELAY_MS: i64 = 400 * 24 * 3600 * 1000;
pub const CRON_MIN_EVERY: i64 = 15 * 60;
pub const CRON_DEFAULT_EVERY: i64 = 24 * 60 * 60;
pub const CRON_MAX_EVERY: i64 = 90 * 24 * 60 * 60;
pub const CRON_MAX_UNTIL_MS: i64 = 400 * 24 * 3600 * 1000;
pub const RESUME_PROMPT_MAX: usize = 4000;
pub const SCHEDULE_TICK: Duration = Duration::from_secs(30);
pub const SCHEDULE_MAX_ATTEMPT: u32 = 5;
pub const SCHEDULE_WAIT_STEP: Duration = Duration::from_secs(5);
pub const SCHEDULE_WAIT_MAX: Duration = Duration::from_secs(10 * 60);
pub const HARNESS_UP_MAX: Duration = Duration::from_secs(5 * 60);
/// the first 20 s of a harness that isn't up yet
pub const HARNESS_RETRY_FAST: Duration = Duration::from_secs(2);
/// how long a Run now keeps trying while the session is busy with another action (Skip)
pub const RUN_NOW_SKIP_WAIT: Duration = Duration::from_secs(10 * 60);

fn re(s: &str) -> regex::Regex {
    regex::Regex::new(s).unwrap_or_else(|_| unreachable!())
}

pub(crate) static SCHEDULE_NAME_RE: LazyLock<regex::Regex> = LazyLock::new(|| re(r"^[A-Za-z0-9_-]{1,40}$"));
/// Go's \s: ASCII whitespace only
static SPACE_RE: LazyLock<regex::Regex> = LazyLock::new(|| re(r"[\t\n\x0C\r ]+"));
static HHMM_RE: LazyLock<regex::Regex> = LazyLock::new(|| re(r"^(\d{1,2}):(\d{2})$"));
/// the machine's refusal of a cron run it already has (rust/machine/src/deliver.rs replay_guard)
static SESSION_HAS_RUN_RE: LazyLock<regex::Regex> = LazyLock::new(|| re(r"cron run (\d+) was already delivered \(last (\d+)\)"));

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Wakeup {
    pub name: String,
    /// ms epoch
    pub at: i64,
    pub prompt: String,
    /// ms epoch: the arming's identity (compare-and-clear)
    #[serde(rename = "armedAt")]
    pub armed_at: i64,
    /// the session's own request that armed it, as its machine signed it (None = armed from the app): what vouches for
    /// the delivery to a machine whose cert vouches (vouch.rs)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed: Option<SignedRequest>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Cron {
    pub name: String,
    pub prompt: String,
    /// seconds
    pub every: i64,
    pub tz: String,
    /// ms epoch
    #[serde(rename = "nextAt")]
    pub next_at: i64,
    /// ms epoch
    #[serde(skip_serializing_if = "Option::is_none")]
    pub until: Option<i64>,
    #[serde(rename = "armedAt")]
    pub armed_at: i64,
    pub runs: i64,
    #[serde(rename = "lastFiredAt", skip_serializing_if = "Option::is_none")]
    pub last_fired_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed: Option<SignedRequest>,
    /// the last occurrence that could not be delivered (drop_failed, or a Run now that failed), until a later one is
    /// delivered: the app marks it beside Run now (Deyao, 2026-11-17)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub missed: Option<Missed>,
}

/// an occurrence given up on: when, its run number, and why (e.g. Fly's org machine limit on the resume)
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Missed {
    /// ms epoch
    pub at: i64,
    pub run: i64,
    pub error: String,
}

/// when the soonest of an aviary session's chat schedules fires next. An aviary session arms its wakeups as magpie's
/// schedules, the same ones YYC AI's conversations use (Deyao, 2026-11-17: dogfooding): magpie fires them into the
/// conversation and hermit-jarvis resumes a paused session for the turn. The router never fires one; it only knows one
/// is armed (hermit-jarvis reports it, PUT /api/sessions/{id}/chat-schedule), so a paused session keeps its runners and
/// its card says it will run again, as for a wakeup of its own.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct ChatSchedule {
    /// ms epoch
    #[serde(rename = "nextAt")]
    pub next_at: i64,
    #[serde(rename = "reportedAt")]
    pub reported_at: i64,
}

/// one session's wakeups, crons and pending resume prompt
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Schedule {
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub wakeups: BTreeMap<String, Wakeup>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub crons: BTreeMap<String, Cron>,
    #[serde(rename = "resumePrompt", skip_serializing_if = "String::is_empty")]
    pub resume_prompt: String,
    /// watches.rs
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub watches: BTreeMap<String, Watch>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chat: Option<ChatSchedule>,
}

impl Schedule {
    pub fn empty(&self) -> bool {
        self.wakeups.is_empty() && self.crons.is_empty() && self.resume_prompt.is_empty() && self.watches.is_empty() && self.chat.is_none()
    }
}

/// something armed will prompt the session again (a wakeup, a cron, a watch, also one met or given up and still being
/// delivered)
pub fn will_wake(d: &Persisted, sid: &str) -> bool {
    d.schedules
        .get(sid)
        .is_some_and(|s| s.wakeups.len() + s.crons.len() + s.watches.len() > 0 || s.chat.is_some())
}

/// the session's schedule, made on demand (callers hold the state lock)
pub fn sched<'a>(d: &'a mut Persisted, sid: &str) -> &'a mut Schedule {
    d.schedules.entry(sid.to_string()).or_default()
}

// ---- errors -------------------------------------------------------------------------------------------------

/// not an attempt (the session is busy with another action); the next tick tries again
#[derive(Debug)]
pub struct Skip(pub String);

impl std::fmt::Display for Skip {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0.is_empty() { f.write_str("busy") } else { write!(f, "busy: {}", self.0) }
    }
}

impl std::error::Error for Skip {}

pub fn skip(why: &str) -> anyhow::Error {
    Skip(why.into()).into()
}

pub fn is_skip(e: &anyhow::Error) -> bool {
    e.downcast_ref::<Skip>().is_some()
}

/// Run now refused for now (409): it is being delivered already, or the session would refuse it this soon
#[derive(Debug)]
pub struct Conflict(pub String);

impl std::fmt::Display for Conflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Conflict {}

pub const NO_SCHEDULE: &str = "no such wakeup or cron";

/// sessionapi.rs: an error the schedule routes answer with its status
pub use crate::sessionapi::schedule_err;

// ---- validation (lib/wakeup.js, lib/cron.js normalize) -------------------------------------------------------

pub fn clean_prompt(v: Option<&Value>) -> String {
    let s = v.and_then(Value::as_str).unwrap_or("");
    SPACE_RE.replace_all(s, " ").trim().to_string()
}

/// a JSON number, or a string that parses as one (finite)
pub fn number(v: &Value) -> Option<f64> {
    let f = match v {
        Value::Number(n) => n.as_f64()?,
        Value::String(s) => s.trim().parse::<f64>().ok()?,
        _ => return None,
    };
    f.is_finite().then_some(f)
}

/// an ISO-8601 time (as Date.parse takes it) or a number of ms since the epoch
pub fn parse_time(v: &Value) -> Option<i64> {
    match v {
        Value::Number(n) => {
            let x = n.as_f64()?;
            x.is_finite().then(|| x.round() as i64)
        }
        Value::String(s) => parse_time_text(s.trim()),
        _ => None,
    }
}

fn parse_time_text(s: &str) -> Option<i64> {
    use time::macros::format_description;
    let ms = |t: time::OffsetDateTime| (t.unix_timestamp_nanos() / 1_000_000) as i64;
    if let Some(t) = GoTime::parse(s).and_then(|t| t.0) {
        return Some(ms(t));
    }
    // "2006-01-02T15:04Z07:00"
    if let Ok(t) = time::OffsetDateTime::parse(
        s,
        format_description!("[year]-[month]-[day]T[hour]:[minute][offset_hour sign:mandatory]:[offset_minute]"),
    ) {
        return Some(ms(t));
    }
    if let Some(base) = s.strip_suffix('Z')
        && let Ok(t) = time::PrimitiveDateTime::parse(base, format_description!("[year]-[month]-[day]T[hour]:[minute]"))
    {
        return Some(ms(t.assume_utc()));
    }
    for f in [
        format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]"),
        format_description!("[year]-[month]-[day]T[hour]:[minute]"),
    ] {
        if let Ok(t) = time::PrimitiveDateTime::parse(s, f) {
            return Some(ms(t.assume_utc()));
        }
    }
    time::Date::parse(s, format_description!("[year]-[month]-[day]"))
        .ok()
        .map(|d| ms(d.midnight().assume_utc()))
}

pub fn wakeup_name(v: Option<&Value>) -> Result<String> {
    let mut s = WAKEUP_DEFAULT.to_string();
    if let Some(v) = v.filter(|v| !v.is_null()) {
        let x = match v {
            Value::String(t) => t.trim().to_string(),
            o => jarvis_go::fmt::go_sprint(o).trim().to_string(),
        };
        if !x.is_empty() {
            s = x;
        }
    }
    if !SCHEDULE_NAME_RE.is_match(&s) {
        return Err(bad("name must be 1-40 chars of letters, digits, _ or -"));
    }
    Ok(s)
}

fn present<'a>(b: &'a Map<String, Value>, k: &str) -> Option<&'a Value> {
    b.get(k).filter(|v| !v.is_null())
}

pub fn now_ms(now: GoTime) -> i64 {
    (now.unix_nanos() / 1_000_000) as i64
}

pub fn normalize_wakeup(b: &Map<String, Value>, now: GoTime) -> Result<Wakeup> {
    let name = wakeup_name(b.get("name"))?;
    let prompt = clean_prompt(b.get("prompt"));
    if prompt.is_empty() {
        return Err(bad("prompt is required — what the session should do when it wakes"));
    }
    if prompt.chars().count() > SCHEDULE_MAX_PROMPT {
        return Err(bad(format!("prompt longer than {SCHEDULE_MAX_PROMPT} characters")));
    }
    let ms = now_ms(now);
    let mut at = if let Some(v) = present(b, "delaySeconds") {
        match number(v) {
            Some(d) if d > 0.0 => ms + (d * 1000.0).round() as i64,
            _ => return Err(bad("delaySeconds must be a positive number")),
        }
    } else if let Some(v) = present(b, "at") {
        parse_time(v).ok_or_else(|| bad("at must be an ISO-8601 time or ms epoch"))?
    } else {
        return Err(bad("give at (ISO time) or delaySeconds"));
    };
    if at < ms {
        at = ms; // a time already past: due now, it fires at once
    }
    if at - ms > WAKEUP_MAX_DELAY_MS {
        return Err(bad("the wakeup is more than 400 days away"));
    }
    Ok(Wakeup { name, at, prompt, armed_at: ms, signed: None })
}

/// the next instant after now whose wall-clock time in tz is hh:mm
pub fn next_time_of_day(hh: i8, mm: i8, tz: &jiff::tz::TimeZone, now: GoTime) -> i64 {
    let ms = now_ms(now);
    let Ok(ts) = jiff::Timestamp::from_millisecond(ms) else { return ms + 86_400_000 };
    let local = ts.to_zoned(tz.clone());
    for d in -1..=2i64 {
        let Ok(day) = local.date().checked_add(jiff::Span::new().days(d)) else { continue };
        let Ok(t) = day.at(hh, mm, 0, 0).to_zoned(tz.clone()) else { continue };
        let t = t.timestamp().as_millisecond();
        if t > ms {
            return t;
        }
    }
    ms + 86_400_000 // unreachable
}

pub fn normalize_cron(b: &Map<String, Value>, now: GoTime) -> Result<Cron> {
    let name = match b.get("name") {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(s)) => s.trim().to_string(),
        Some(v) => jarvis_go::fmt::go_sprint(v).trim().to_string(),
    };
    if !SCHEDULE_NAME_RE.is_match(&name) {
        return Err(bad("name must be 1-40 chars of letters, digits, _ or -"));
    }
    let prompt = clean_prompt(b.get("prompt"));
    if prompt.is_empty() {
        return Err(bad("prompt is required — what the session should do each time"));
    }
    if prompt.chars().count() > SCHEDULE_MAX_PROMPT {
        return Err(bad(format!("prompt longer than {SCHEDULE_MAX_PROMPT} characters")));
    }
    let every_err = || bad(format!("everySeconds must be {CRON_MIN_EVERY}–{CRON_MAX_EVERY}"));
    let mut every = CRON_DEFAULT_EVERY;
    if let Some(v) = present(b, "everySeconds") {
        every = number(v).ok_or_else(every_err)?.round() as i64;
    }
    if !(CRON_MIN_EVERY..=CRON_MAX_EVERY).contains(&every) {
        return Err(every_err());
    }
    let tz_name = b
        .get("tz")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .unwrap_or("UTC")
        .to_string();
    let tz = match jiff::tz::TimeZone::get(&tz_name) {
        Ok(t) if tz_name != "Local" => t,
        _ => return Err(bad(format!("unknown time zone {}", jarvis_go::fmt::go_quote(&tz_name)))),
    };
    let ms = now_ms(now);
    let next = if let Some(t) = present(b, "time") {
        let txt = match t {
            Value::String(s) => s.trim().to_string(),
            o => jarvis_go::fmt::go_sprint(o).trim().to_string(),
        };
        let m = HHMM_RE.captures(&txt).ok_or_else(|| bad("time must be HH:MM"))?;
        let hh: i8 = m[1].parse().unwrap_or(99);
        let mm: i8 = m[2].parse().unwrap_or(99);
        if hh > 23 || mm > 59 {
            return Err(bad("time must be HH:MM"));
        }
        next_time_of_day(hh, mm, &tz, now)
    } else if let Some(v) = present(b, "delaySeconds") {
        match number(v) {
            Some(d) if d > 0.0 => ms + (d * 1000.0).round() as i64,
            _ => return Err(bad("delaySeconds must be a positive number")),
        }
    } else if let Some(v) = present(b, "at") {
        let mut next = parse_time(v).ok_or_else(|| bad("at must be an ISO-8601 time or ms epoch"))?;
        if next <= ms && every > 0 {
            // a first firing already past: the next slot of its period
            next += ((ms - next) / (every * 1000) + 1) * every * 1000;
        }
        next
    } else {
        ms + every * 1000
    };
    let mut c = Cron { name, prompt, every, tz: tz_name, next_at: next, armed_at: ms, ..Default::default() };
    if let Some(v) = present(b, "until").filter(|v| v.as_str() != Some("")) {
        let u = parse_time(v).filter(|u| *u > next).ok_or_else(|| bad("until must be a time after the first firing"))?;
        if u - ms > CRON_MAX_UNTIL_MS {
            return Err(bad("until is more than 400 days away"));
        }
        c.until = Some(u);
    }
    Ok(c)
}

/// the next occurrence strictly after now (a session unreachable for a while fires once, not a backlog), or None once
/// past until
pub fn advance_cron(c: &Cron, now: GoTime) -> Option<i64> {
    let (mut next, ms, step) = (c.next_at, now_ms(now), c.every * 1000);
    if next <= ms {
        next += (ms - next + 1 + step - 1) / step * step;
    }
    if c.until.is_some_and(|u| next > u) {
        return None;
    }
    Some(next)
}

// ---- views (lib/wakeup.js view, lib/cron.js view) ----------------------------------------------------------

pub fn iso(ms: i64) -> String {
    let t = GoTime::from_unix_nanos(ms as i128 * 1_000_000).utc().0.unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute(),
        t.second(),
        t.millisecond()
    )
}

pub fn wakeup_view(w: &Wakeup) -> Value {
    json!({"name": w.name, "at": w.at, "atIso": iso(w.at), "prompt": w.prompt})
}

pub fn cron_view(c: &Cron) -> Value {
    let mut v = json!({"name": c.name, "prompt": c.prompt, "everySeconds": c.every, "tz": if c.tz.is_empty() { "UTC" } else { &c.tz },
        "nextAt": c.next_at, "nextAtIso": iso(c.next_at), "until": null, "untilIso": null, "armedAtIso": iso(c.armed_at),
        "runs": c.runs, "lastFiredIso": null});
    if let Some(u) = c.until {
        v["until"] = json!(u);
        v["untilIso"] = json!(iso(u));
    }
    if let Some(l) = c.last_fired_at {
        v["lastFiredIso"] = json!(iso(l));
    }
    if let Some(m) = &c.missed {
        v["missed"] = json!({"at": m.at, "atIso": iso(m.at), "run": m.run, "error": m.error});
    }
    v
}

pub fn sorted_wakeups(s: Option<&Schedule>) -> Vec<Wakeup> {
    let mut out: Vec<Wakeup> = s.map(|s| s.wakeups.values().cloned().collect()).unwrap_or_default();
    out.sort_by_key(|w| w.at);
    out
}

pub fn sorted_crons(s: Option<&Schedule>) -> Vec<Cron> {
    let mut out: Vec<Cron> = s.map(|s| s.crons.values().cloned().collect()).unwrap_or_default();
    out.sort_by_key(|c| c.next_at);
    out
}

/// a session's wakeups, crons and queued resume prompt in its /api/state view (Jarvis 1 lists them on the card;
/// callers hold the state lock)
pub fn schedule_view(d: &Persisted, sid: &str, v: &mut Map<String, Value>) {
    let sc = d.schedules.get(sid);
    let ws: Vec<Value> = sorted_wakeups(sc).iter().map(wakeup_view).collect();
    let cs: Vec<Value> = sorted_crons(sc).iter().map(cron_view).collect();
    if let Some(sc) = sc {
        if !sc.resume_prompt.is_empty() {
            v.insert("resumePrompt".into(), json!(sc.resume_prompt));
        }
        if let Some(c) = &sc.chat {
            v.insert("chatScheduleIso".into(), json!(iso(c.next_at)));
        }
    }
    v.insert("wakeups".into(), json!(ws));
    v.insert("crons".into(), json!(cs));
    v.insert("watches".into(), crate::watches::watches_view_of(d, sid));
}

// ---- firing state ---------------------------------------------------------------------------------------------

/// in-memory run state, keyed "<sid>/w/<name>", "<sid>/c/<name>", "<sid>/resume" (lost on a restart, which only makes
/// due items due again)
#[derive(Default)]
struct Scheduler {
    busy: std::collections::BTreeSet<String>,
    attempts: BTreeMap<String, (u32, Instant)>,
}

static SCHED_RUN: LazyLock<Mutex<Scheduler>> = LazyLock::new(|| Mutex::new(Scheduler::default()));
static SCHED_TICKING: Mutex<()> = Mutex::new(());

fn sched_run() -> std::sync::MutexGuard<'static, Scheduler> {
    SCHED_RUN.lock().unwrap_or_else(|e| e.into_inner())
}

pub fn sched_forget(key: &str) {
    sched_run().attempts.remove(key);
}

/// the key is free and not backing off → mark it busy
pub(crate) fn sched_claim(key: &str) -> bool {
    let mut g = sched_run();
    if g.busy.contains(key) || g.attempts.get(key).is_some_and(|(_, at)| Instant::now() < *at) {
        return false;
    }
    g.busy.insert(key.to_string());
    true
}

pub(crate) fn sched_release(key: &str) {
    sched_run().busy.remove(key);
}

/// record a failed attempt; true = it has failed SCHEDULE_MAX_ATTEMPT times
pub(crate) fn sched_failed(key: &str) -> bool {
    let mut g = sched_run();
    let a = g.attempts.entry(key.to_string()).or_insert((0, Instant::now()));
    a.0 += 1;
    if a.0 >= SCHEDULE_MAX_ATTEMPT {
        g.attempts.remove(key);
        return true;
    }
    a.1 = Instant::now() + Duration::from_secs(2 * 60 * u64::from(a.0.min(4)));
    false
}

/// err is the session's refusal of cron run `run` as one it already has; → the session's own count. That run was
/// delivered: the session records a run only once its harness took it, and only the answer was lost (the harness took
/// over 60 s and the router gave up). Counting it keeps the router's run number the session's; otherwise every later
/// occurrence sent that same number again and was refused (2026-11-18).
pub fn session_has_run(err: Option<&anyhow::Error>, run: i64) -> Option<i64> {
    let m = SESSION_HAS_RUN_RE.captures(&format!("{:#}", err?))?.get(2)?.as_str().parse::<i64>().ok()?;
    (m >= run).then_some(m)
}

// ---- seams ----------------------------------------------------------------------------------------------------

pub type DeliverHook = Arc<dyn Fn(&Arc<Router>, &str, Delivery) -> Result<()> + Send + Sync>;
pub type ResumeHook = Arc<dyn Fn(&Arc<Router>, &str) -> Result<()> + Send + Sync>;
/// tests catch deliveries here (vouch.rs deliver_vouched otherwise)
pub static DELIVER_VOUCHED_HOOK: RwLock<Option<DeliverHook>> = RwLock::new(None);
/// tests catch the resume of a failed session here (the app's Resume otherwise)
pub static RESUME_FAILED_HOOK: RwLock<Option<ResumeHook>> = RwLock::new(None);

pub fn deliver_vouched_hook(r: &Arc<Router>, sid: &str, d: Delivery) -> Result<()> {
    if let Some(h) = DELIVER_VOUCHED_HOOK.read().unwrap_or_else(|e| e.into_inner()).clone() {
        return h(r, sid, d);
    }
    r.deliver_vouched(sid, d)
}

fn resume_failed_hook(r: &Arc<Router>, sid: &str) -> Result<()> {
    if let Some(h) = RESUME_FAILED_HOOK.read().unwrap_or_else(|e| e.into_inner()).clone() {
        return h(r, sid);
    }
    r.resume(sid, false)
}

fn label_of(s: &crate::state::Session, sid: &str) -> String {
    [&s.label, &s.title].into_iter().find(|x| !x.is_empty()).cloned().unwrap_or_else(|| sid.to_string())
}

impl Router {
    /// records the next fire of an aviary session's chat schedules (None: none armed) as hermit-jarvis reports it
    pub fn set_chat_schedule(&self, sid: &str, next_at: Option<GoTime>, now: GoTime) -> Result<()> {
        self.st.do_(|d| {
            let Some(s) = d.sessions.get(sid) else { return Err(crate::sessionapi::no_session()) };
            if s.harness != "aviary" {
                return Err(BadReq("only an aviary session has chat schedules".into()).into());
            }
            match next_at {
                None => {
                    if let Some(sc) = d.schedules.get_mut(sid) {
                        sc.chat = None;
                        if sc.empty() {
                            d.schedules.remove(sid);
                        }
                    }
                }
                Some(t) => sched(d, sid).chat = Some(ChatSchedule { next_at: now_ms(t), reported_at: now_ms(now) }),
            }
            Ok(())
        })
    }

    /// the session, refused when it is gone or going (Jarvis 1 answers 409 "session is destroying")
    pub fn live_session<'a>(&self, d: &'a Persisted, sid: &str) -> Result<&'a crate::state::Session> {
        let s = d.sessions.get(sid).ok_or_else(crate::sessionapi::no_session)?;
        if s.state == "destroyed" || s.state == "destroying" {
            return Err(anyhow!("session is {}", s.state));
        }
        Ok(s)
    }

    pub fn list_wakeups(&self, sid: &str) -> Result<Vec<Wakeup>> {
        self.st.do_(|d| {
            if !d.sessions.contains_key(sid) {
                return Err(crate::sessionapi::no_session());
            }
            Ok(sorted_wakeups(d.schedules.get(sid)))
        })
    }

    pub fn arm_wakeup(&self, sid: &str, w: Wakeup) -> Result<()> {
        self.st.do_(|d| {
            self.live_session(d, sid)?;
            sched(d, sid).wakeups.insert(w.name.clone(), w.clone());
            Ok(())
        })?;
        sched_forget(&format!("{sid}/w/{}", w.name));
        crate::logf!(
            "[wakeup] {sid} {} scheduled for {}: {}",
            jarvis_go::fmt::go_quote(&w.name),
            iso(w.at),
            crate::util::trim_to(&w.prompt, 80)
        );
        Ok(())
    }

    /// the named ones, or every one with all
    pub fn cancel_wakeups(&self, sid: &str, names: &[String], all: bool) -> Result<Vec<String>> {
        let out = self.st.do_(|d| {
            if !d.sessions.contains_key(sid) {
                return Err(crate::sessionapi::no_session());
            }
            let s = sched(d, sid);
            let names: Vec<String> = if all { s.wakeups.keys().cloned().collect() } else { names.to_vec() };
            for n in &names {
                s.wakeups.remove(n);
            }
            Ok(names)
        })?;
        for n in &out {
            sched_forget(&format!("{sid}/w/{n}"));
        }
        Ok(out)
    }

    pub fn list_crons(&self, sid: &str) -> Result<Vec<Cron>> {
        self.st.do_(|d| {
            if !d.sessions.contains_key(sid) {
                return Err(crate::sessionapi::no_session());
            }
            Ok(sorted_crons(d.schedules.get(sid)))
        })
    }

    pub fn arm_cron(&self, sid: &str, c: Cron) -> Result<()> {
        self.st.do_(|d| {
            self.live_session(d, sid)?;
            sched(d, sid).crons.insert(c.name.clone(), c.clone());
            Ok(())
        })?;
        sched_forget(&format!("{sid}/c/{}", c.name));
        crate::logf!(
            "[cron] {sid} armed {} every {}s, next {}: {}",
            jarvis_go::fmt::go_quote(&c.name),
            c.every,
            iso(c.next_at),
            crate::util::trim_to(&c.prompt, 80)
        );
        Ok(())
    }

    pub fn cancel_cron(&self, sid: &str, name: &str) -> Result<()> {
        let r = self.st.do_(|d| {
            if !d.sessions.contains_key(sid) {
                return Err(crate::sessionapi::no_session());
            }
            sched(d, sid).crons.remove(name);
            Ok(())
        });
        sched_forget(&format!("{sid}/c/{name}"));
        r
    }

    /// the prompt is queued BEFORE the resume starts, so the resume sees it (a vouching core carries it in the
    /// successor's cert, which the phone approves); queued after, the resume's thread could miss it and the prompt would
    /// reach the machine unsigned. A refused resume puts the earlier queued prompt back.
    ///
    /// A kernel line's resume carries no one-time inputs (it spawns from the line's source), so its prompt is filed at
    /// once as a pending message (messages.rs): the app that sent it opens it for Face ID straight away, and the
    /// approved message goes in as soon as the session is up (Deyao, 2026-10-24: "The resume with message is broken").
    pub fn resume_with_prompt(self: &Arc<Self>, sid: &str, upgrade: bool, prompt: &str) -> Result<()> {
        if prompt.is_empty() {
            return self.resume(sid, upgrade);
        }
        let (before, kernel) = self.st.do_(|d| {
            (
                d.schedules.get(sid).map(|s| s.resume_prompt.clone()).unwrap_or_default(),
                d.sessions.get(sid).is_some_and(|s| s.kernel.is_some()),
            )
        });
        if kernel {
            // one this prompt replaces: back if the resume is refused
            let earlier = self.st.do_(|d| {
                d.messages
                    .values()
                    .filter(|x| x.session == sid && x.kind == "resume-prompt" && x.state == "pending")
                    .next_back()
                    .cloned()
            });
            let dl = Delivery { kind: "resume-prompt".into(), text: prompt.into(), ..Default::default() };
            let (text, from, note) = crate::messages::message_text(&dl).unwrap_or_default();
            let pm = self.hold_message(sid, &dl, &text, &from, &note, None)?;
            if let Err(e) = self.resume(sid, upgrade) {
                let eid = earlier.as_ref().map(|x| x.id.clone()).unwrap_or_default();
                self.st.do_(|d| {
                    if d.messages.get(&pm.id).is_some_and(|x| x.state == "pending" && x.id != eid) {
                        d.messages.remove(&pm.id);
                    }
                    if let Some(e) = &earlier
                        && !d.messages.contains_key(&e.id)
                    {
                        d.messages.insert(e.id.clone(), e.clone());
                    }
                });
                return Err(e);
            }
            return Ok(());
        }
        self.set_resume_prompt(sid, prompt);
        if let Err(e) = self.resume(sid, upgrade) {
            self.set_resume_prompt(sid, &before);
            return Err(e);
        }
        Ok(())
    }

    /// delivered once the session is started again (the tick's resume prompt)
    pub fn set_resume_prompt(&self, sid: &str, prompt: &str) {
        self.st.do_(|d| {
            if d.sessions.contains_key(sid) {
                sched(d, sid).resume_prompt = prompt.to_string();
            }
        });
        sched_forget(&format!("{sid}/resume"));
    }

    /// the session's armed wakeups, crons and watches ("wakeup <name>", "cron <name>", "watch <name>"). Automatic paths
    /// (auto-destroy, one-shot clean-up, retirement) must not destroy a session while this is non-empty.
    pub fn pending_schedule(&self, sid: &str) -> Vec<String> {
        self.st.do_(|d| {
            let s = d.schedules.get(sid);
            let mut out: Vec<String> = sorted_wakeups(s).iter().map(|w| format!("wakeup {}", w.name)).collect();
            out.extend(sorted_crons(s).iter().map(|c| format!("cron {}", c.name)));
            out.extend(crate::watches::sorted_watches(s).iter().map(|w| format!("watch {}", w.name)));
            if s.is_some_and(|s| s.chat.is_some()) {
                out.push("chat schedule (schedule-wakeup --list)".into());
            }
            out
        })
    }

    /// a wakeup or cron fires within d (auto-pause should leave such a session running)
    pub fn schedule_due_within(&self, sid: &str, d: Duration) -> bool {
        self.st.do_(|p| schedule_due_within(p, sid, d))
    }

    pub fn schedule_loop(self: &Arc<Self>) {
        loop {
            crate::leaderlease::await_lead();
            self.schedule_tick(GoTime::now()); // at once at start: what came due during a handover fires right after it
            std::thread::sleep(self.until_next_due(GoTime::now(), SCHEDULE_TICK));
        }
    }

    /// how long until the next wakeup or cron comes due, at most max: a wakeup fires when it is due, not at the next
    /// 30 s tick. Only what is still ahead counts (one overdue and failing retries on the ticks, with its backoff).
    pub fn until_next_due(&self, now: GoTime, max: Duration) -> Duration {
        let ms = now_ms(now);
        let mut next = ms + max.as_millis() as i64;
        self.st.do_(|d| {
            for s in d.schedules.values() {
                for w in s.wakeups.values().filter(|w| w.at > ms) {
                    next = next.min(w.at);
                }
                for c in s.crons.values().filter(|c| c.next_at > ms) {
                    next = next.min(c.next_at);
                }
            }
        });
        Duration::from_millis((next - ms).max(0) as u64) + Duration::from_millis(10)
    }

    /// one pass; non-reentrant, each item re-read inside its busy section before it fires
    pub fn schedule_tick(self: &Arc<Self>, now: GoTime) {
        let Ok(_t) = SCHED_TICKING.try_lock() else { return };
        let ms = now_ms(now);
        // (sid, kind, name, armed_at, label)
        let items: Vec<(String, &'static str, String, i64, String)> = self.st.do_(|d| {
            let mut items = vec![];
            let sids: Vec<String> = d.schedules.keys().cloned().collect();
            for sid in sids {
                let Some(ss) = d.sessions.get(&sid).cloned() else {
                    d.schedules.remove(&sid); // the session is gone: its schedule goes with it
                    continue;
                };
                if ss.state == "destroyed" || ss.state == "destroying" {
                    continue;
                }
                let label = label_of(&ss, &sid);
                let Some(s) = d.schedules.get_mut(&sid) else { continue };
                for w in s.wakeups.values().filter(|w| w.at <= ms) {
                    items.push((sid.clone(), "w", w.name.clone(), w.armed_at, label.clone()));
                }
                for c in s.crons.values().filter(|c| c.next_at <= ms) {
                    items.push((sid.clone(), "c", c.name.clone(), c.armed_at, label.clone()));
                }
                if !s.resume_prompt.is_empty() {
                    match ss.state.as_str() {
                        "started" => items.push((sid.clone(), "resume", String::new(), 0, label.clone())),
                        "paused" | "failed" => {
                            // the start that should have carried it failed or was rejected: it never turns up after
                            // some later, unrelated start
                            crate::logf!("[resume-prompt] {sid}: the session is {}; prompt dropped", ss.state);
                            s.resume_prompt.clear();
                        }
                        _ => {}
                    }
                }
                if s.empty() {
                    d.schedules.remove(&sid);
                }
            }
            items
        });
        for (sid, kind, name, armed_at, label) in items {
            let key = if kind == "resume" { format!("{sid}/resume") } else { format!("{sid}/{kind}/{name}") };
            if !sched_claim(&key) {
                continue;
            }
            let r = self.clone();
            std::thread::spawn(move || {
                let k2 = key.clone();
                let _rel = crate::flows::scopeguard(move || sched_release(&k2));
                let (what, res) = match kind {
                    "w" => (
                        format!("Scheduled wakeup “{name}” for session “{label}”"),
                        r.fire_wakeup(&sid, &name, armed_at),
                    ),
                    "c" => (
                        format!("Recurring wakeup “{name}” for session “{label}”"),
                        r.fire_cron(&sid, &name, armed_at),
                    ),
                    _ => (format!("The prompt for the resumed session “{label}”"), r.fire_resume_prompt(&sid)),
                };
                let Err(err) = res else {
                    sched_forget(&key);
                    return;
                };
                if is_skip(&err) {
                    crate::logf!("[schedule] {key}: {err:#} — next tick");
                    return;
                }
                let again = if kind == "c" {
                    " It is marked missed on the session's Schedules page: Run now delivers it."
                } else {
                    ""
                };
                // Fly's org machine limit is a known error (Deyao, 2026-11-17): skipped and told at once, in its own
                // words; retrying in minutes only fails again, and Run now is there once a machine is free
                if crate::flows::fly_machine_limit(&err) {
                    crate::logf!("[schedule] {key}: {err:#} — skipped at once");
                    sched_forget(&key);
                    r.drop_failed(&sid, kind, &name, armed_at, &err);
                    r.dm(&format!("{what} could not be delivered: {}.{again}", crate::flows::FLY_LIMIT_TEXT));
                    return;
                }
                let drop = sched_failed(&key);
                crate::logf!("[schedule] {key} failed (drop={drop}): {err:#}");
                if drop {
                    r.drop_failed(&sid, kind, &name, armed_at, &err);
                    r.dm(&format!(
                        "{what} could not be delivered after {SCHEDULE_MAX_ATTEMPT} attempts: {}.{again}",
                        crate::flows::known_error(&err)
                    ));
                }
            });
        }
    }

    /// after too many failures a wakeup or resume prompt is dropped; a cron skips this occurrence and marks it missed
    /// (Run now delivers it)
    fn drop_failed(&self, sid: &str, kind: &str, name: &str, armed_at: i64, cause: &anyhow::Error) {
        let now = GoTime::now();
        self.st.do_(|d| {
            let Some(s) = d.schedules.get_mut(sid) else { return };
            match kind {
                "w" => {
                    if s.wakeups.get(name).is_some_and(|w| w.armed_at == armed_at) {
                        s.wakeups.remove(name);
                    }
                }
                "c" => {
                    let Some(c) = s.crons.get_mut(name).filter(|c| c.armed_at == armed_at) else { return };
                    c.missed = Some(Missed { at: now_ms(now), run: c.runs + 1, error: crate::flows::known_error(cause) });
                    match advance_cron(c, now) {
                        Some(n) => c.next_at = n,
                        None => {
                            s.crons.remove(name);
                        }
                    }
                }
                _ => s.resume_prompt.clear(),
            }
        });
    }

    fn fire_wakeup(self: &Arc<Self>, sid: &str, name: &str, armed_at: i64) -> Result<()> {
        let w = self
            .st
            .do_(|d| d.schedules.get(sid).and_then(|s| s.wakeups.get(name)).cloned())
            .unwrap_or_default();
        if w.name.is_empty() || w.armed_at != armed_at || w.at > now_ms(GoTime::now()) {
            return Ok(()); // cancelled, replaced or already fired
        }
        // vouch.rs: the session's own signed request, attested by the core
        let Some(signed) = w.signed.clone() else { return Err(anyhow!(crate::vouch::NOT_VOUCHED)) };
        self.deliver_scheduled(sid, Delivery { kind: "wakeup".into(), request: Some(signed), ..Default::default() })?;
        crate::logf!("[wakeup] {sid} {} delivered", jarvis_go::fmt::go_quote(name));
        self.st.do_(|d| {
            // compare-and-clear: never one re-armed meanwhile
            if let Some(s) = d.schedules.get_mut(sid)
                && s.wakeups.get(name).is_some_and(|x| x.armed_at == armed_at)
            {
                s.wakeups.remove(name);
            }
        });
        Ok(())
    }

    fn fire_cron(self: &Arc<Self>, sid: &str, name: &str, armed_at: i64) -> Result<()> {
        let c = self
            .st
            .do_(|d| d.schedules.get(sid).and_then(|s| s.crons.get(name)).cloned())
            .unwrap_or_default();
        if c.name.is_empty() || c.armed_at != armed_at || c.next_at > now_ms(GoTime::now()) {
            return Ok(());
        }
        let mut run = c.runs + 1;
        let mut res = match c.signed.clone() {
            // vouch.rs: the session's own signed request, attested by the core; no shell needed
            Some(signed) => self.deliver_scheduled(
                sid,
                Delivery { kind: "cron".into(), request: Some(signed), run, ..Default::default() },
            ),
            None => Err(anyhow!(crate::vouch::NOT_VOUCHED)),
        };
        if let Some(last) = session_has_run(res.as_ref().err(), run) {
            crate::logf!(
                "[cron] {sid} {}: the session already has run {last} (its answer was lost): counted",
                jarvis_go::fmt::go_quote(name)
            );
            run = last;
            res = Ok(());
        }
        res?;
        crate::logf!("[cron] {sid} {} delivered", jarvis_go::fmt::go_quote(name));
        self.cron_fired(sid, name, armed_at, run, GoTime::now(), false);
        Ok(())
    }

    /// a cron's run (its number) was delivered: count it, clear a missed mark, and move it to its next occurrence.
    /// early (a Run now): the next occurrence is at least half a period away, as the machine refuses a cron run sooner
    /// than that after the last (rust/machine/src/deliver.rs replay_guard).
    fn cron_fired(&self, sid: &str, name: &str, armed_at: i64, run: i64, now: GoTime, early: bool) {
        self.st.do_(|d| {
            let Some(s) = d.schedules.get_mut(sid) else { return };
            let Some(cur) = s.crons.get_mut(name).filter(|c| c.armed_at == armed_at) else {
                return; // cancelled or replaced meanwhile
            };
            let after = if early { now.add(time::Duration::milliseconds(cur.every * 1000 / 2)) } else { now };
            let (mut next, mut ok) = (Some(cur.next_at), cur.until.is_none_or(|u| cur.next_at <= u));
            if cur.next_at <= now_ms(after) {
                next = advance_cron(cur, after);
                ok = next.is_some();
            }
            match next.filter(|_| ok) {
                None => {
                    s.crons.remove(name);
                    crate::logf!("[cron] {sid} {} reached its end", jarvis_go::fmt::go_quote(name));
                }
                Some(n) => {
                    cur.next_at = n;
                    cur.runs = cur.runs.max(run);
                    cur.last_fired_at = Some(now_ms(now));
                    cur.missed = None;
                }
            }
        });
    }

    /// Deyao's Run now on a wakeup or cron (the app's Schedules page): deliver it at once exactly as its scheduled
    /// firing would (the session's own signed request, a paused session resumed first, the Inbox for a sensitive one)
    /// and count it as that firing: a wakeup is done, a cron's run number goes up and its schedule carries on. A failed
    /// session (its start refused) is resumed first. For a run skipped after failed attempts (Fly's org machine limit
    /// on the resume: Deyao, 2026-11-17) it is that run, delivered late. The delivery runs in the background (a resume
    /// can wait out the machine limit); a failure is DMed and marked missed.
    pub fn run_now(self: &Arc<Self>, sid: &str, kind: &str, name: &str) -> Result<()> {
        let key = format!("{sid}/{kind}/{name}");
        let now = GoTime::now();
        let (signed, armed_at, mut run, label) = self.st.do_(|d| -> Result<(SignedRequest, i64, i64, String)> {
            let ss = self.live_session(d, sid)?;
            let label = label_of(ss, sid);
            let s = d.schedules.get(sid);
            let (signed, armed_at, run) = match kind {
                "w" => {
                    let w = s.and_then(|s| s.wakeups.get(name)).ok_or_else(|| anyhow!(NO_SCHEDULE))?;
                    (w.signed.clone(), w.armed_at, 0)
                }
                _ => {
                    let c = s.and_then(|s| s.crons.get(name)).ok_or_else(|| anyhow!(NO_SCHEDULE))?;
                    if let Some(l) = c.last_fired_at
                        && now_ms(now) - l < c.every * 1000 / 2
                    {
                        return Err(Conflict(format!(
                            "it last ran at {}, less than half its period ago: the session refuses a repeat that soon (Run now from {}, or wait for its next run at {})",
                            iso(l),
                            iso(l + c.every * 1000 / 2),
                            iso(c.next_at)
                        ))
                        .into());
                    }
                    (c.signed.clone(), c.armed_at, c.runs + 1)
                }
            };
            let signed = signed.ok_or_else(|| {
                Conflict("it was not armed by the session's own signed request, so nothing vouches for delivering it".into())
            })?;
            Ok((signed, armed_at, run, label))
        })?;
        sched_forget(&key); // a Run now goes past the scheduled attempts' backoff
        if !sched_claim(&key) {
            return Err(Conflict("it is being delivered right now".into()).into());
        }
        let what = format!("Wakeup “{name}” of session “{label}”");
        let dl = if kind == "c" {
            Delivery { kind: "cron".into(), request: Some(signed), run, ..Default::default() }
        } else {
            Delivery { kind: "wakeup".into(), request: Some(signed), ..Default::default() }
        };
        crate::logf!("[schedule] {key}: Run now");
        let (r, sid, kind, name) = (self.clone(), sid.to_string(), kind.to_string(), name.to_string());
        std::thread::spawn(move || {
            let k2 = key.clone();
            let _rel = crate::flows::scopeguard(move || sched_release(&k2));
            let deadline = Instant::now() + RUN_NOW_SKIP_WAIT;
            let res = loop {
                let mut res = r.deliver_scheduled(&sid, dl.clone());
                if kind == "c"
                    && let Some(last) = session_has_run(res.as_ref().err(), run)
                {
                    crate::logf!("[schedule] {key}: the session already has run {last}: counted");
                    run = last;
                    res = Ok(());
                }
                match res {
                    Err(e) if is_skip(&e) && Instant::now() < deadline => std::thread::sleep(SCHEDULE_WAIT_STEP),
                    other => break other,
                }
            };
            if let Err(e) = res {
                crate::logf!("[schedule] {key}: Run now failed: {e:#}");
                if kind == "c" {
                    let ke = crate::flows::known_error(&e);
                    r.st.do_(|d| {
                        if let Some(c) = d
                            .schedules
                            .get_mut(&sid)
                            .and_then(|s| s.crons.get_mut(&name))
                            .filter(|c| c.armed_at == armed_at)
                        {
                            c.missed = Some(Missed { at: now_ms(GoTime::now()), run, error: ke.clone() });
                        }
                    });
                }
                r.dm(&format!("Run now: {what} could not be delivered: {}", crate::flows::known_error(&e)));
                return;
            }
            crate::logf!("[schedule] {key}: Run now delivered");
            if kind == "w" {
                r.st.do_(|d| {
                    // compare-and-clear, as fire_wakeup
                    if let Some(s) = d.schedules.get_mut(&sid)
                        && s.wakeups.get(&name).is_some_and(|w| w.armed_at == armed_at)
                    {
                        s.wakeups.remove(&name);
                    }
                });
            } else {
                r.cron_fired(&sid, &name, armed_at, run, GoTime::now(), true);
            }
        });
        Ok(())
    }

    /// a wakeup's or cron's delivery, scheduled or Run now. A failed session gets no delivery (deliver_vouched refuses
    /// it), so it is resumed first, as the app's Resume would (Deyao, 2026-11-18): a failed start (Fly's machine limit,
    /// lessons/92) starts again, a failed pause (its final snapshot met a one-off error) finishes its snapshot first. A
    /// resume that fails again fails this firing, as any other failure.
    pub fn deliver_scheduled(self: &Arc<Self>, sid: &str, d: Delivery) -> Result<()> {
        if self.session_state(sid).0 == "failed" {
            match resume_failed_hook(self, sid) {
                Err(e) if crate::drain::is_busy(&e) => return Err(skip("")),
                Err(e) => return Err(e),
                Ok(()) => {}
            }
        }
        deliver_vouched_hook(self, sid, d)
    }

    fn fire_resume_prompt(self: &Arc<Self>, sid: &str) -> Result<()> {
        let text = self.st.do_(|d| d.schedules.get(sid).map(|s| s.resume_prompt.clone()).unwrap_or_default());
        if text.is_empty() {
            return Ok(());
        }
        // Deyao's own words: the machine takes them only as the phone signed them (messages.rs), so they wait in the
        // Inbox
        deliver_vouched_hook(self, sid, Delivery { kind: "resume-prompt".into(), text: text.clone(), ..Default::default() })?;
        crate::logf!("[resume-prompt] {sid} handed over");
        self.st.do_(|d| {
            if let Some(s) = d.schedules.get_mut(sid).filter(|s| s.resume_prompt == text) {
                s.resume_prompt.clear();
            }
        });
        Ok(())
    }

    pub fn wait_started(&self, sid: &str) -> Result<()> {
        let deadline = Instant::now() + SCHEDULE_WAIT_MAX;
        loop {
            let (state, _) = self.session_state(sid);
            match state.as_str() {
                "started" => return Ok(()),
                "" | "paused" | "failed" | "destroying" => {
                    let e = self.st.do_(|d| d.sessions.get(sid).map(|s| s.error.clone()).unwrap_or_default());
                    return Err(anyhow!("the session didn't start (state {} {e})", jarvis_go::fmt::go_quote(&state)));
                }
                _ => {}
            }
            if Instant::now() > deadline {
                return Err(anyhow!("the session is still {state} after 10m0s"));
            }
            std::thread::sleep(SCHEDULE_WAIT_STEP);
        }
    }

    /// the session's state, and whether its cert says it holds a sensitive store
    pub fn session_state(&self, sid: &str) -> (String, bool) {
        self.st.read(|d| {
            let Some(s) = d.sessions.get(sid) else { return (String::new(), false) };
            #[derive(Deserialize, Default)]
            #[serde(default)]
            struct C {
                sensitive: bool,
            }
            let sensitive = s
                .cert
                .as_ref()
                .and_then(|c| serde_json::from_str::<C>(&c.payload).ok())
                .is_some_and(|c| c.sensitive);
            (s.state.clone(), sensitive)
        })
    }
}

/// the same, for callers that hold the state lock (the autopilot's veto)
pub fn schedule_due_within(p: &Persisted, sid: &str, d: Duration) -> bool {
    let lim = now_ms(GoTime::now()) + d.as_millis() as i64;
    let Some(s) = p.schedules.get(sid) else { return false };
    s.wakeups.values().any(|w| w.at < lim)
        || s.crons.values().any(|c| c.next_at < lim)
        || s.chat.as_ref().is_some_and(|c| c.next_at < lim)
}

/// the JSON body as a map ("" is an empty one)
pub fn json_map(b: &[u8]) -> Result<Map<String, Value>> {
    if String::from_utf8_lossy(b).trim().is_empty() {
        return Ok(Map::new());
    }
    serde_json::from_slice(b).map_err(|e| bad(format!("bad JSON: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crons_and_times() {
        let now = GoTime::parse("2026-11-18T10:00:00Z").unwrap_or_default();
        let b: Map<String, Value> = serde_json::from_str(r#"{"name":"daily","prompt":" go  on ","time":"09:30","tz":"Asia/Hong_Kong"}"#).unwrap_or_default();
        let c = normalize_cron(&b, now).unwrap_or_else(|e| panic!("{e:#}"));
        assert_eq!(c.prompt, "go on");
        assert_eq!(iso(c.next_at), "2026-11-19T01:30:00.000Z");
        let b: Map<String, Value> = serde_json::from_str(r#"{"name":"x","prompt":"p","everySeconds":60}"#).unwrap_or_default();
        assert!(normalize_cron(&b, now).is_err());
        assert_eq!(parse_time(&json!("2026-11-18T10:00")), Some(1763460000000));
        assert_eq!(parse_time(&json!("2026-11-18")), Some(1763424000000));
        let mut cr = Cron { next_at: 1000, every: 10, ..Default::default() };
        assert_eq!(advance_cron(&cr, GoTime::from_unix_nanos(25_000 * 1_000_000)), Some(31_000));
        cr.until = Some(20_000);
        assert_eq!(advance_cron(&cr, GoTime::from_unix_nanos(25_000 * 1_000_000)), None);
        let e = anyhow!("the machine refused or failed: cron run 4 was already delivered (last 5)");
        assert_eq!(session_has_run(Some(&e), 4), Some(5));
        assert_eq!(session_has_run(Some(&e), 6), None);
    }
}

/// auto-pause (autopilot.rs) leaves a session running when a wakeup or cron fires within 10 minutes
pub fn auto_pause_veto(d: &Persisted, sid: &str) -> bool {
    schedule_due_within(d, sid, Duration::from_secs(600))
}
