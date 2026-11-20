//! The lifecycle log (Deyao, 2026-10-16): every boot, pause, resume, upgrade, restart and destroy of a session is an
//! operation with its own log; the app and the web page show it in the session's one event stream (sessionevents.rs),
//! together with the supervisor's lines, live while it runs and afterwards. An operation's log is, in time order:
//!
//!   - the router's own steps (source "router"): asked the core to start a machine, the machine is up, the cert, asked
//!     the machine for its final snapshot, the snapshot arrived, asked the core to destroy the machine, the archive…;
//!   - what Fly did (source "fly"), read by the router itself with its READ-ONLY token (FLY_READ_TOKEN, app
//!     jarvis4-sessions; no core change): the machine's Fly events (launch, start, exit, destroy, with their source and
//!     exit code), polled every 2 s while the operation runs and for 30 s after it (Fly keeps only a few events per
//!     machine, so each is kept the first time it is seen), and Fly's own platform log lines for the machine (image
//!     pull, "Machine started in …", the VM's exit), from Fly's logs API (the app's stdout is left out);
//!   - what AWS did (source "aws") to an AWS machine (an EC2 instance, id i-…), read with the router's READ-ONLY AWS
//!     key (AWS_READ_*, awsread.rs): DescribeInstances every 2 s while the operation runs and for 30 s after it, one
//!     entry per change of the instance's state with its type, zone, public address and EC2's reasons, and one when
//!     EC2 no longer knows it; and the instance's notable serial console lines (awslogs.rs console_tick);
//!   - the supervisor's lines (source "supervisor", supervisorlog.rs) of the operation's machines from 5 s before it
//!     began until 30 s after it ended (until now while it runs), merged in when read.
//!
//! Stored per session in the database (session_log, kind lifecycle: the operation records and their router and Fly
//! entries, appended), kept for the session's life, and archived on Destroy (jarvis2/lifecycle.json) before the log
//! goes. The pollers run in the router process doing the operation (the leader); a drain stops their tails early, and
//! the next leader closes an operation a crash left open ("cut off").

use crate::awsread::AwsInstanceView;
use crate::http::Registrar;
use crate::nethttp::write_json;
use crate::router::Router;
use crate::sessionlog::{LOG_LIFECYCLE, LOG_SUPERVISOR};
use anyhow::{Result, anyhow};
use jarvis_go::GoTime;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard, RwLock};
use std::time::{Duration, Instant};

/// how long a start's operation waits for the machine's first report
pub const LC_BOOT_MAX: Duration = Duration::from_secs(15 * 60);
/// supervisor lines from this long before an operation began belong to it
pub const LC_LEAD: time::Duration = time::Duration::seconds(5);

/// one operation
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct LcOp {
    pub id: String,
    pub session: String,
    /// boot | pause | resume | upgrade | restart | destroy | harness-pause | harness-resume
    pub kind: String,
    pub started: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub ended: String,
    /// running | done | failed | cut off
    pub state: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub error: String,
    pub machines: Vec<String>,
}

/// one line of an operation's log
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct LcEntry {
    pub at: String,
    /// router | fly | aws | supervisor
    pub source: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub machine: String,
    pub text: String,
}

/// one line of a session's log
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct LcRec {
    /// the operation as it now is (the last record of an id wins)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub op: Option<LcOp>,
    /// an entry's operation
    #[serde(rename = "opId", skip_serializing_if = "String::is_empty")]
    pub op_id: String,
    /// a router or Fly entry
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry: Option<LcEntry>,
}

#[derive(Default)]
struct RunState {
    op: LcOp,
    /// Fly events and log lines already kept
    seen: BTreeSet<String>,
    /// machine → Fly logs' next_token
    log_next: BTreeMap<String, String>,
    /// Fly's logs API refused: events only
    logs_off: bool,
    /// AWS machine → the state (and reason) its last entry showed
    aws_last: BTreeMap<String, String>,
    /// end is writing its record: the operation is still current until it is written
    ending: bool,
}

pub struct LcRun {
    mu: Mutex<RunState>,
    stop: AtomicBool,
    /// an upgrade or restart: its pause and resume join it
    job: bool,
    /// start_and_certify took over ending it (lc_await_boot ends it once the machine reports in). On the run, not on a
    /// handle: start_and_certify holds its own (lc_current's), and the resume's end_from_state checks its own
    handed: AtomicBool,
}

impl LcRun {
    fn lock(&self) -> MutexGuard<'_, RunState> {
        self.mu.lock().unwrap_or_else(|e| e.into_inner())
    }
}

// ---- Fly, read only ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct FlyExitEvent {
    pub exit_code: i64,
    pub oom_killed: bool,
    pub requested_stop: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct FlyEventRequest {
    pub exit_event: Option<FlyExitEvent>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct FlyEvent {
    #[serde(rename = "type")]
    pub kind: String,
    pub status: String,
    pub source: String,
    /// ms
    pub timestamp: i64,
    pub request: Option<FlyEventRequest>,
}

#[derive(Debug, Clone, Default)]
pub struct FlyLogLine {
    pub id: String,
    pub timestamp: String,
    pub message: String,
    /// app | runner | proxy | …
    pub provider: String,
}

/// Fly's logs API said no (not a network error): events only from then on
#[derive(Debug)]
pub struct FlyLogsRefused(pub u16);

impl std::fmt::Display for FlyLogsRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Fly's logs API: HTTP {}", self.0)
    }
}

impl std::error::Error for FlyLogsRefused {}

/// a machine's Fly log lines after a token → them and the next token
pub type FlyLogsFn = fn(&str, &str) -> Result<(Vec<FlyLogLine>, String)>;

/// Fly and AWS, read only, and how often (tests swap them)
#[derive(Clone)]
pub struct LcHooks {
    pub poll_every: Duration,
    pub tail: Duration,
    pub fly_events: fn(&str) -> Result<Vec<FlyEvent>>,
    pub fly_logs: FlyLogsFn,
    /// a read token is there
    pub fly_on: fn() -> bool,
    /// an instance as EC2 describes it now (None: EC2 doesn't know it)
    pub aws_describe: fn(&str) -> Result<Option<AwsInstanceView>>,
    /// the read key is there
    pub aws_on: fn() -> bool,
}

fn fly_read_token() -> String {
    std::env::var("FLY_READ_TOKEN").unwrap_or_default()
}

impl Default for LcHooks {
    fn default() -> LcHooks {
        LcHooks {
            poll_every: Duration::from_secs(2),
            tail: Duration::from_secs(30),
            fly_events: lc_fly_events,
            fly_logs: lc_fly_logs,
            fly_on: || !fly_read_token().is_empty(),
            aws_describe: crate::awsread::aws_describe,
            aws_on: crate::awsread::aws_read_on,
        }
    }
}

#[derive(Default)]
struct LcInner {
    /// session → its latest operation (running, or in its tail)
    cur: BTreeMap<String, Arc<LcRun>>,
    /// destroyed: nothing more is written
    gone: BTreeSet<String>,
}

#[derive(Default)]
pub struct Lifecycle {
    pub hooks: RwLock<LcHooks>,
    mu: Mutex<LcInner>,
    /// appends
    file: Mutex<()>,
}

impl Lifecycle {
    fn lock(&self) -> MutexGuard<'_, LcInner> {
        self.mu.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn hooks(&self) -> LcHooks {
        self.hooks.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn dropped(&self, session: &str) -> bool {
        self.lock().gone.contains(session)
    }

    /// the session's latest operation as it now is (running, or in its tail); None when none
    pub fn current_op(&self, session: &str) -> Option<LcOp> {
        let run = self.lock().cur.get(session).cloned()?;
        let op = run.lock().op.clone();
        Some(op)
    }
}

pub fn now_text() -> String {
    GoTime::now().rfc3339_nano()
}

/// the machine's events as Fly lists them now
pub fn lc_fly_events(machine: &str) -> Result<Vec<FlyEvent>> {
    let token = fly_read_token();
    if token.is_empty() {
        return Err(anyhow!("FLY_READ_TOKEN not set"));
    }
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct M {
        events: Vec<FlyEvent>,
    }
    let m: M = crate::flyorgs::fly_get(
        &token,
        &format!(
            "/v1/apps/{}/machines/{}",
            crate::budget::SESSIONS_APP,
            jarvis_go::fmt::path_escape(machine)
        ),
    )?;
    Ok(m.events)
}

/// Fly's logs API (tests point it at a fake)
pub static FLY_LOGS_BASE: LazyLock<RwLock<String>> =
    LazyLock::new(|| RwLock::new("https://api.fly.io".into()));

/// the machine's log lines after next ("" = Fly's latest page), and the token for the next call
pub fn lc_fly_logs(machine: &str, next: &str) -> Result<(Vec<FlyLogLine>, String)> {
    let mut token = fly_read_token();
    if token.is_empty() {
        return Err(anyhow!("FLY_READ_TOKEN not set"));
    }
    let mut q = vec![("instance", machine.to_string())];
    if !next.is_empty() {
        q.push(("next_token", next.to_string()));
    }
    q.sort();
    let qs: Vec<String> = q
        .iter()
        .map(|(k, v)| format!("{k}={}", jarvis_go::fmt::query_escape(v)))
        .collect();
    if !token.starts_with("FlyV1 ") && !token.starts_with("Bearer ") {
        token = format!("Bearer {token}");
    }
    let base = FLY_LOGS_BASE
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let resp = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?
        .get(format!(
            "{base}/api/v1/apps/{}/logs?{}",
            crate::budget::SESSIONS_APP,
            qs.join("&")
        ))
        .header("Authorization", token)
        .header("Accept", "application/json")
        .send()?;
    let st = resp.status().as_u16();
    if st != 200 {
        return Err(FlyLogsRefused(st).into());
    }
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Ev {
        provider: String,
    }
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Meta {
        event: Ev,
    }
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Attrs {
        timestamp: String,
        message: String,
        meta: Meta,
    }
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct D {
        id: String,
        attributes: Attrs,
    }
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct NextMeta {
        next_token: String,
    }
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Out {
        data: Vec<D>,
        meta: NextMeta,
    }
    let b = crate::util::read_limited(resp, 16 << 20)?;
    let out: Out = jarvis_go::unmarshal(&b)?;
    let lines = out
        .data
        .into_iter()
        .map(|d| FlyLogLine {
            id: d.id,
            timestamp: d.attributes.timestamp,
            message: d.attributes.message,
            provider: d.attributes.meta.event.provider,
        })
        .collect();
    let next = if out.meta.next_token.is_empty() {
        next.to_string()
    } else {
        out.meta.next_token
    };
    Ok((lines, next))
}

pub fn event_text(e: &FlyEvent) -> String {
    let mut t = e.kind.clone();
    if !e.status.is_empty() {
        t += &format!(" → {}", e.status);
    }
    if !e.source.is_empty() {
        t += &format!(" ({})", e.source);
    }
    if let Some(x) = e.request.as_ref().and_then(|r| r.exit_event.as_ref()) {
        t += &format!(", exit code {}", x.exit_code);
        if x.oom_killed {
            t += ", killed for memory (OOM)";
        }
        if x.requested_stop {
            t += ", stop requested";
        }
    }
    format!("Fly: machine {t}")
}

/// "AWS: instance running (public IPv4 …)", "AWS: instance terminated: Client.InstanceInitiatedShutdown: …"
pub fn aws_state_text(v: &AwsInstanceView) -> String {
    let mut t = format!("AWS: instance {}", v.state);
    match v.state.as_str() {
        "pending" | "running" => {
            if !v.public_ip.is_empty() {
                t += &format!(" (public IPv4 {})", v.public_ip);
            }
        }
        _ => {
            let mut why = vec![];
            if !v.reason_msg.is_empty() {
                why.push(v.reason_msg.clone());
            } else if !v.reason_code.is_empty() {
                why.push(v.reason_code.clone());
            }
            if !v.transition.is_empty() {
                why.push(v.transition.clone());
            }
            if !why.is_empty() {
                t += &format!(": {}", why.join("; "));
            }
        }
    }
    t
}

static AWS_TRANSITION_AT_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"\((\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) GMT\)")
        .unwrap_or_else(|_| unreachable!())
});

/// when a stop or terminate began, if EC2 says (its transition reason carries the time it was asked for), else now
pub fn aws_state_at(v: &AwsInstanceView, now: GoTime) -> GoTime {
    if v.state != "stopping" && v.state != "shutting-down" {
        return now;
    }
    if let Some(m) = AWS_TRANSITION_AT_RE.captures(&v.transition)
        && let Some(t) = GoTime::parse(&format!("{}Z", m[1].replace(' ', "T")))
        && !t.after(&now)
        && now.sub(&t) < time::Duration::hours(1)
    {
        return t;
    }
    now
}

pub fn parse_at(s: &str) -> GoTime {
    GoTime::parse(s).unwrap_or_default()
}

// ---- what a flow holds ------------------------------------------------------------------------------------------

/// what a flow holds. joined: the flow runs inside a job's operation, which the job ends. An empty handle (a router
/// being torn down) does nothing.
#[derive(Clone)]
pub struct LcHandle {
    r: Option<Arc<Router>>,
    run: Arc<LcRun>,
    joined: bool,
}

impl LcHandle {
    fn new(r: Option<Arc<Router>>, run: Arc<LcRun>, joined: bool) -> LcHandle {
        LcHandle { r, run, joined }
    }

    pub fn op_id(&self) -> String {
        self.run.lock().op.id.clone()
    }

    pub fn set_handed(&self) {
        self.run.handed.store(true, Ordering::SeqCst);
    }

    pub fn note(&self, machine: &str, text: &str) {
        self.add(LcEntry {
            at: now_text(),
            source: "router".into(),
            machine: machine.into(),
            text: text.into(),
        });
    }

    pub fn add(&self, e: LcEntry) {
        let Some(r) = &self.r else { return };
        let (session, id) = {
            let g = self.run.lock();
            (g.op.session.clone(), g.op.id.clone())
        };
        r.lc_write(
            &session,
            LcRec {
                op_id: id,
                entry: Some(e),
                ..Default::default()
            },
        );
    }

    /// a machine the operation involves (its Fly events and logs are read from now on)
    pub fn machine(&self, m: &str) {
        let Some(r) = &self.r else { return };
        if m.is_empty() {
            return;
        }
        let op = {
            let mut g = self.run.lock();
            if g.op.machines.iter().any(|x| x == m) {
                return;
            }
            g.op.machines.push(m.to_string());
            g.op.clone()
        };
        r.lc_write(
            &op.session,
            LcRec {
                op: Some(op.clone()),
                ..Default::default()
            },
        );
    }

    /// the operation is over (state done or failed); its Fly tail goes on for the hooks' tail. A joined handle ends
    /// nothing. The end record is written before the operation stops being current: whoever sees no running operation
    /// (lc_current None) also finds its end in the log, and nothing of it is still being written (DECISIONS 213).
    pub fn end(&self, state: &str, err_msg: &str) {
        if self.joined {
            return;
        }
        let Some(r) = &self.r else { return };
        let op = {
            let mut g = self.run.lock();
            if g.op.state != "running" || g.ending {
                return;
            }
            g.ending = true;
            let mut op = g.op.clone();
            op.state = state.into();
            op.error = err_msg.into();
            op.ended = now_text();
            op
        };
        r.lc_write(
            &op.session,
            LcRec {
                op: Some(op.clone()),
                ..Default::default()
            },
        );
        let mut g = self.run.lock();
        g.op.state = op.state;
        g.op.error = op.error;
        g.op.ended = op.ended;
    }

    /// a job (upgrade, restart) ends its own operation
    pub fn end_job(&self, err: Option<&anyhow::Error>) {
        let j = LcHandle::new(self.r.clone(), self.run.clone(), false);
        match err {
            Some(e) => j.end("failed", &format!("{e:#}")),
            None => j.end("done", ""),
        }
    }

    /// done, or failed with the session's error (its state failed, or an error left on it)
    pub fn end_from_state(&self) {
        if self.joined || self.run.handed.load(Ordering::SeqCst) {
            return;
        }
        let Some(r) = &self.r else { return };
        let sid = self.run.lock().op.session.clone();
        let (state, err_msg) = r.st.do_(|d| {
            d.sessions
                .get(&sid)
                .map(|s| (s.state.clone(), s.error.clone()))
                .unwrap_or_default()
        });
        if state == "failed" || !err_msg.is_empty() {
            self.end("failed", &err_msg);
            return;
        }
        self.end("done", "");
    }

    /// end the operation even when this handle joined it — unless it is a job's (an upgrade or restart ends its own);
    /// a start ends the resume operation it took over
    pub fn end_joined(&self, state: &str, err_msg: &str) {
        if self.run.job {
            return;
        }
        LcHandle::new(self.r.clone(), self.run.clone(), false).end(state, err_msg);
    }
}

impl Router {
    fn me_arc(&self) -> Option<Arc<Router>> {
        self.me.get().and_then(std::sync::Weak::upgrade)
    }

    pub fn lc_write(&self, session: &str, rec: LcRec) {
        if self.lc.dropped(session) {
            return;
        }
        let _g = self.lc.file.lock().unwrap_or_else(|e| e.into_inner());
        let b = jarvis_go::marshal(&rec);
        if let Err(e) = self.st.append_log(session, LOG_LIFECYCLE, &[b.as_bytes()]) {
            crate::logf!("[lifecycle] {e:#}");
        }
    }

    /// a new operation of the session (its kind), or the job's operation it runs inside
    pub fn lc_begin(&self, session: &str, kind: &str) -> LcHandle {
        self.lc_start(session, kind, false)
    }

    /// an operation that runs others (an Upgrade's free, pause and resume; a restart's): they join it, and it ends
    /// only by end_job
    pub fn lc_begin_job(&self, session: &str, kind: &str) -> LcHandle {
        self.lc_start(session, kind, true)
    }

    fn lc_start(&self, session: &str, kind: &str, job: bool) -> LcHandle {
        let me = self.me_arc();
        let mut g = self.lc.lock();
        if let Some(prev) = g.cur.get(session).cloned() {
            let (running, pjob, pkind) = {
                let p = prev.lock();
                (
                    p.op.state == "running" && !p.ending,
                    prev.job,
                    p.op.kind.clone(),
                ) // one ending is over: nothing joins it
            };
            if running && pjob {
                drop(g);
                let h = LcHandle::new(me, prev, true);
                h.note("", &format!("{kind} (part of the {pkind})"));
                return h;
            }
            if running {
                // shouldn't happen (the session lock): close it so only one runs
                drop(g);
                LcHandle::new(me.clone(), prev.clone(), false).end("done", "");
                g = self.lc.lock();
            }
            prev.stop.store(true, Ordering::SeqCst);
        }
        let run = Arc::new(LcRun {
            mu: Mutex::new(RunState {
                op: LcOp {
                    id: crate::util::rand_id(),
                    session: session.into(),
                    kind: kind.into(),
                    started: now_text(),
                    state: "running".into(),
                    ..Default::default()
                },
                ..Default::default()
            }),
            stop: AtomicBool::new(false),
            job,
            handed: AtomicBool::new(false),
        });
        g.cur.insert(session.to_string(), run.clone());
        drop(g);
        let op = run.lock().op.clone();
        self.lc_write(
            session,
            LcRec {
                op: Some(op),
                ..Default::default()
            },
        );
        if let Some(r) = me.clone() {
            let run2 = run.clone();
            std::thread::spawn(move || r.lc_poll(&run2));
        }
        LcHandle::new(me, run, false)
    }

    /// the session's running operation (None when none)
    pub fn lc_current(&self, session: &str) -> Option<LcHandle> {
        let run = self.lc.lock().cur.get(session).cloned()?;
        if run.lock().op.state != "running" {
            return None;
        }
        Some(LcHandle::new(self.me_arc(), run, true))
    }

    /// a router step into the session's running operation (none: nothing)
    pub fn lc_note(&self, session: &str, machine: &str, text: &str) {
        if let Some(h) = self.lc_current(session) {
            h.note(machine, text);
        }
    }

    /// a machine the session's running operation involves (its Fly events and logs are read from now on)
    pub fn lc_machine(&self, session: &str, machine: &str) {
        if let Some(h) = self.lc_current(session) {
            h.machine(machine);
        }
    }

    /// the session is a record now (its archive holds the logs): its log goes and nothing more is written
    pub fn lc_drop(&self, session: &str) {
        {
            let mut g = self.lc.lock();
            if let Some(run) = g.cur.remove(session) {
                run.stop.store(true, Ordering::SeqCst);
            }
            g.gone.insert(session.to_string());
        }
        let _g = self.lc.file.lock().unwrap_or_else(|e| e.into_inner());
        self.st.drop_log(session, LOG_LIFECYCLE);
    }

    /// at the leader's start, an operation still open in a log was cut off (a crash, or a drain that ended its log
    /// early): closed as such
    pub fn lc_cut_off(&self) {
        for session in self.st.log_sessions(LOG_LIFECYCLE) {
            if self.job_busy(&session) {
                continue; // another replica runs it (jobs.rs)
            }
            let (ops, _) = self.lc_read(&session);
            for mut op in ops {
                if op.state == "running" {
                    op.state = "cut off".into();
                    op.ended = now_text();
                    op.error = "the router restarted while it ran: its log ends here (the supervisor's own log goes on)".into();
                    let s = op.session.clone();
                    self.lc_write(
                        &s,
                        LcRec {
                            op: Some(op),
                            ..Default::default()
                        },
                    );
                }
            }
        }
    }

    // ---- polling ---------------------------------------------------------------------------------------------

    /// new Fly events and platform log lines of the operation's machines, each kept once
    fn lc_poll_once(self: &Arc<Self>, run: &Arc<LcRun>) {
        let hooks = self.lc.hooks();
        let (machines, started, mut logs_off) = {
            let g = run.lock();
            (g.op.machines.clone(), parse_at(&g.op.started), g.logs_off)
        };
        let from = started.add(-LC_LEAD);
        let h = LcHandle::new(Some(self.clone()), run.clone(), false);
        let session = run.lock().op.session.clone();
        let runner = self.runner_of_session(&session);
        for m in &machines {
            match runner.as_str() {
                "aws" => {
                    if (hooks.aws_on)() {
                        self.lc_poll_aws(run, m, started, &hooks);
                    }
                    continue;
                }
                "fly" => {}
                // the fabric: no machine on Fly, the router's own steps and the supervisor's lines are its log
                _ => continue,
            }
            if !(hooks.fly_on)() {
                continue;
            }
            if let Ok(mut evs) = (hooks.fly_events)(m) {
                evs.sort_by_key(|e| e.timestamp);
                for e in evs {
                    let at = GoTime::from_unix_nanos(e.timestamp as i128 * 1_000_000);
                    let k = format!("e|{m}|{}|{}|{}", e.kind, e.status, e.timestamp);
                    let old = !run.lock().seen.insert(k);
                    if old || at.before(&from) {
                        continue;
                    }
                    h.add(LcEntry {
                        at: at.utc().rfc3339_nano(),
                        source: "fly".into(),
                        machine: m.clone(),
                        text: event_text(&e),
                    });
                }
            }
            if logs_off {
                continue;
            }
            let next = run.lock().log_next.get(m).cloned().unwrap_or_default();
            let (lines, nt) = match (hooks.fly_logs)(m, &next) {
                Err(e) => {
                    if e.downcast_ref::<FlyLogsRefused>().is_some() {
                        run.lock().logs_off = true;
                        logs_off = true;
                        h.note(
                            "",
                            &format!("{e:#} for the router's read-only token: Fly's events only"),
                        );
                    }
                    continue;
                }
                Ok(x) => x,
            };
            run.lock().log_next.insert(m.clone(), nt);
            for l in lines {
                if l.provider == "app" {
                    continue; // the machine's own output: the supervisor pushes its lines itself
                }
                let Some(at) = GoTime::parse(&l.timestamp) else {
                    continue;
                };
                if at.before(&from) {
                    continue;
                }
                let k = if l.id.is_empty() {
                    format!("l|{m}|{}|{}", l.timestamp, l.message)
                } else {
                    format!("l|{m}|{}", l.id)
                };
                if !run.lock().seen.insert(k) {
                    continue;
                }
                let provider = if l.provider.is_empty() {
                    "platform"
                } else {
                    &l.provider
                };
                h.add(LcEntry {
                    at: at.utc().rfc3339_nano(),
                    source: "fly".into(),
                    machine: m.clone(),
                    text: format!("Fly {provider}: {}", l.message.trim()),
                });
            }
        }
    }

    /// one DescribeInstances of an AWS machine; an entry when its state or EC2's reason for it changed since the
    /// operation's last one (the first look also says when and how it was launched)
    fn lc_poll_aws(self: &Arc<Self>, run: &Arc<LcRun>, m: &str, started: GoTime, hooks: &LcHooks) {
        let Ok(v) = (hooks.aws_describe)(m) else {
            return; // the next poll asks again (EC2 throttled, the network)
        };
        let h = LcHandle::new(Some(self.clone()), run.clone(), false);
        let key = v.as_ref().map_or("gone".to_string(), |v| {
            format!("{}|{}|{}", v.state, v.reason_code, v.transition)
        });
        let (last, seen) = {
            let mut g = run.lock();
            let last = g.aws_last.insert(m.to_string(), key.clone());
            (last.clone().unwrap_or_default(), last.is_some())
        };
        if seen && last == key {
            return;
        }
        let now = GoTime::now();
        let add = |at: GoTime, text: String| {
            h.add(LcEntry {
                at: at.utc().rfc3339_nano(),
                source: "aws".into(),
                machine: m.into(),
                text,
            });
        };
        let Some(v) = v else {
            if seen {
                add(now, format!("AWS: EC2 no longer lists instance {m}"));
            }
            return;
        };
        let before = v.launched.is_zero() || v.launched.before(&started.add(-LC_LEAD));
        if !seen && before && v.state == "running" {
            return; // up before the operation began, as the router knew it: only what changes from here is its log
        }
        if !seen && !before {
            let mut place = v.type_.clone();
            if !v.zone.is_empty() {
                place += &format!(" in {}", v.zone);
            }
            add(v.launched, format!("AWS: instance launched ({place})"));
            if v.state == "pending" {
                return; // launched is pending: one entry
            }
        }
        add(aws_state_at(&v, now), aws_state_text(&v));
    }

    /// Fly and AWS read while the operation runs and for the hooks' tail after; a drain cuts the tail short
    fn lc_poll(self: &Arc<Self>, run: &Arc<LcRun>) {
        let hooks = self.lc.hooks();
        if !(hooks.fly_on)() && !(hooks.aws_on)() {
            return; // no read token or key (a test router, a dev box): router and supervisor entries only
        }
        loop {
            let end = Instant::now() + hooks.poll_every;
            while Instant::now() < end && !run.stop.load(Ordering::SeqCst) {
                std::thread::sleep(
                    Duration::from_millis(100).min(end.saturating_duration_since(Instant::now())),
                );
            }
            if run.stop.load(Ordering::SeqCst) {
                self.lc_poll_once(run);
                return;
            }
            self.lc_poll_once(run);
            let (ended, state, session) = {
                let g = run.lock();
                (
                    parse_at(&g.op.ended),
                    g.op.state.clone(),
                    g.op.session.clone(),
                )
            };
            let tail = time::Duration::try_from(hooks.tail).unwrap_or(time::Duration::ZERO);
            if state != "running" && (ended.since() > tail || self.draining()) {
                return;
            }
            if self.lc.dropped(&session) {
                return;
            }
        }
    }

    // ---- reading ---------------------------------------------------------------------------------------------

    /// a session's log → its operations (oldest first) and each one's router and Fly entries
    pub fn lc_read(&self, session: &str) -> (Vec<LcOp>, BTreeMap<String, Vec<LcEntry>>) {
        let mut by_id: BTreeMap<String, LcOp> = BTreeMap::new();
        let mut order = vec![];
        let mut entries: BTreeMap<String, Vec<LcEntry>> = BTreeMap::new();
        for raw in self.lc_lines(session) {
            let Ok(rec) = jarvis_go::unmarshal::<LcRec>(&raw) else {
                continue;
            };
            if let Some(op) = rec.op {
                if !by_id.contains_key(&op.id) {
                    order.push(op.id.clone());
                }
                by_id.insert(op.id.clone(), op);
            }
            if let Some(e) = rec.entry {
                entries.entry(rec.op_id).or_default().push(e);
            }
        }
        let ops = order
            .into_iter()
            .filter_map(|id| by_id.remove(&id))
            .collect();
        (ops, entries)
    }

    /// an operation with its entries and the supervisor lines of its machines, in time order
    pub fn lc_op_log(
        &self,
        op: &LcOp,
        own: &[LcEntry],
        sup: &[crate::supervisorlog::SupLine],
    ) -> Vec<LcEntry> {
        let from = parse_at(&op.started).add(-LC_LEAD);
        let tail = time::Duration::try_from(self.lc.hooks().tail).unwrap_or(time::Duration::ZERO);
        let to = if op.state != "running" {
            parse_at(&op.ended).add(tail)
        } else {
            GoTime::now().add(time::Duration::seconds(1))
        };
        let mut out = own.to_vec();
        for l in sup {
            let at = parse_at(&l.at);
            if !op.machines.contains(&l.machine) || at.before(&from) || at.after(&to) {
                continue;
            }
            out.push(LcEntry {
                at: l.at.clone(),
                source: "supervisor".into(),
                machine: l.machine.clone(),
                text: l.text.clone(),
            });
        }
        out.sort_by_key(|e| parse_at(&e.at)); // stable: same-time entries keep their order
        out
    }

    /// every operation of the session, each with its log (the archive's lifecycle.json), oldest first
    pub fn lc_all(&self, session: &str) -> Vec<Value> {
        let (ops, entries) = self.lc_read(session);
        let sup = self.read_sup_log(session);
        ops.iter()
            .map(|op| {
                json!({"id": op.id, "kind": op.kind, "started": op.started, "ended": op.ended, "state": op.state,
                    "error": op.error, "machines": op.machines,
                    "entries": self.lc_op_log(op, entries.get(&op.id).map(Vec::as_slice).unwrap_or_default(), &sup)})
            })
            .collect()
    }

    /// the supervisor log and every operation's log, for the session's archive (archivetar.rs)
    pub fn lifecycle_files(&self, sid: &str) -> Vec<(String, Vec<u8>)> {
        let mut out = vec![];
        let ops = self.lc_all(sid);
        if !ops.is_empty() {
            out.push((
                "jarvis2/lifecycle.json".into(),
                jarvis_go::fmt::marshal_indent1(&ops).into_bytes(),
            ));
        }
        if let Ok(lines) = self.st.read_log(sid, LOG_SUPERVISOR)
            && !lines.is_empty()
        {
            let mut b = lines.join(&b"\n"[..]);
            b.push(b'\n');
            out.push(("jarvis2/supervisor-log.jsonl".into(), b));
        }
        out
    }

    /// a session's lifecycle log, its records' JSON in order
    pub fn lc_lines(&self, session: &str) -> Vec<Vec<u8>> {
        let _g = self.lc.file.lock().unwrap_or_else(|e| e.into_inner());
        self.st
            .read_log(session, LOG_LIFECYCLE)
            .unwrap_or_else(|e| {
                crate::logf!("[lifecycle] reading {session}: {e:#}");
                vec![]
            })
    }

    /// a start's operation ends when the machine first reports (booted), fails, or LC_BOOT_MAX passes; a drain ends
    /// its log early (the supervisor's own log goes on)
    pub fn lc_await_boot(&self, op: LcHandle, sid: &str, machine: &str) {
        let end = Instant::now() + LC_BOOT_MAX;
        loop {
            let (booted, state, err_msg, cur) = self.st.do_(|d| {
                d.sessions
                    .get(sid)
                    .map(|s| {
                        (
                            s.booted == machine,
                            s.state.clone(),
                            s.error.clone(),
                            s.machine_id.clone(),
                        )
                    })
                    .unwrap_or_default()
            });
            if booted {
                op.note(
                    machine,
                    "the machine reported in: booted, the harness is starting",
                );
                op.end_joined("done", "");
                return;
            }
            if cur != machine || state == "failed" {
                let why = if err_msg.is_empty() {
                    format!(
                        "the session moved on from machine {machine} ({})",
                        crate::sessionapi::or_state(&state)
                    )
                } else {
                    err_msg
                };
                op.end_joined("failed", &why);
                return;
            }
            if self.draining() {
                op.note(
                    machine,
                    "the router is updating: this log ends here; the supervisor's own log goes on",
                );
                op.end_joined("done", "");
                return;
            }
            if Instant::now() > end {
                op.end_joined(
                    "failed",
                    &format!(
                        "the machine hasn't reported in within {}",
                        crate::flows::wait_text(LC_BOOT_MAX)
                    ),
                );
                return;
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    }
}

pub fn register_lifecycle(reg: &mut Registrar) {
    // the supervisor's pause and resume of the Claude process (rust/machine/src/supervisor.rs), unguarded like
    // snapshot and free
    reg.app("POST /api/sessions/{id}/harness", |r, w, req| {
        let id = req.path_value("id");
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct In {
            action: String,
        }
        let i: In = crate::http::decode_body(req, 1 << 12);
        if i.action != "pause" && i.action != "resume" {
            return write_json(w, 400, &json!({"error": r#"action: "pause" or "resume""#}));
        }
        let Some(s) = r.st.do_(|d| d.sessions.get(&id).cloned()) else {
            return write_json(w, 404, &json!({"error": format!("no session {id}")}));
        };
        if s.machine_id.is_empty() {
            return write_json(
                w,
                409,
                &json!({"error": format!("session is {}: it has no machine to send that to", crate::sessionapi::or_state(&s.state))}),
            );
        }
        let h = r.lc_begin(&id, &format!("harness-{}", i.action));
        h.machine(&s.machine_id);
        let cmd = format!("{}-harness", i.action);
        r.send(&s.machine_id, &cmd);
        h.note(&s.machine_id, &format!("sent the supervisor {cmd}"));
        h.end("done", "");
        write_json(w, 200, &json!({"ok": true, "machine": s.machine_id, "command": cmd, "op": h.op_id()}));
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn texts() {
        let e = FlyEvent {
            kind: "exit".into(),
            status: "stopped".into(),
            source: "flyd".into(),
            timestamp: 0,
            request: Some(FlyEventRequest {
                exit_event: Some(FlyExitEvent {
                    exit_code: 137,
                    oom_killed: true,
                    requested_stop: false,
                }),
            }),
        };
        assert_eq!(
            event_text(&e),
            "Fly: machine exit → stopped (flyd), exit code 137, killed for memory (OOM)"
        );
        let v = AwsInstanceView {
            state: "stopping".into(),
            transition: "User initiated (2026-11-04 13:18:40 GMT)".into(),
            ..Default::default()
        };
        let now = GoTime::parse("2026-11-04T13:20:00Z").unwrap_or_default();
        assert_eq!(aws_state_at(&v, now).rfc3339(), "2026-11-04T13:18:40Z");
        assert_eq!(
            aws_state_text(&v),
            "AWS: instance stopping: User initiated (2026-11-04 13:18:40 GMT)"
        );
    }
}
