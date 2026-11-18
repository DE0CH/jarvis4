//! What the router does by itself with a running session, from the status its machine reports (registry.rs):
//!
//!   auto-pause      idle (no background jobs) for 1 h → Pause, 5 min when the last turn was a scheduled one (a wakeup,
//!                   cron or watch delivered after Deyao's last prompt); per-session off switch
//!   one-shot        the supervisor's ~/.claude/.one-shot-done marker → Destroy
//!   stale prompt    "waiting" for 1 h → Escape in the tmux pane (holder "status")
//!   attention DMs   idle / waiting / dead for 5 min → one DM per episode; the idle one can be muted
//!   downgrade DM    a new safeguard refusal or refusal fallback in a transcript, or the "switch model?" dialog
//!   login           a session with a Claude account stopped on "Please run /login" and its pair is in step with its
//!                   account's again → deliver "continue" (the router never writes a login)
//!
//! One tick at a time (a single loop). The decisions are made under the state lock by plan_tick (pure, tested); the
//! actions run outside it. A command the machine refuses (no grant) is recorded as the session's needsGrant and not
//! retried for grant_retry.

pub use crate::registry::{Refusal, Registry};
use crate::flows::NewSession;
use crate::grants::ExecResult;
use crate::http::Registrar;
use crate::nethttp::write_json;
use crate::router::Router;
use crate::state::{Persisted, Session};
use anyhow::Result;
use jarvis_go::GoTime;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::sync::{Arc, LazyLock};
use time::Duration as TD;

fn is_false(b: &bool) -> bool {
    !*b
}

fn is_zero(n: &i64) -> bool {
    *n == 0
}

/// a session's reported status, its settings, and the loop's clocks and episodes (all in the database; the machine's
/// pane is apart, in session_screens, screens.rs)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Liveness {
    #[serde(rename = "autoPauseOff", skip_serializing_if = "is_false")]
    pub auto_pause_off: bool,
    #[serde(rename = "notifyIdleOff", skip_serializing_if = "is_false")]
    pub notify_idle_off: bool,
    #[serde(rename = "oneShot", skip_serializing_if = "is_false")]
    pub one_shot: bool,
    /// a holder the machine refused; the app offers a grant
    #[serde(rename = "needsGrant", skip_serializing_if = "String::is_empty")]
    pub needs_grant: String,
    #[serde(rename = "downgradeSeenAt", skip_serializing_if = "is_zero")]
    pub downgrade_seen_at: i64,
    /// the auto-pause clock: idle since when, on which turn (statusUpdatedAt), kept across a router restart
    #[serde(rename = "idleSince")]
    pub idle_since: GoTime,
    #[serde(rename = "idleStatusAt", skip_serializing_if = "is_zero")]
    pub idle_status_at: i64,
    /// when the router last delivered a wakeup, cron or watch into the session (ms, vouch.rs)
    #[serde(rename = "scheduledAt", skip_serializing_if = "is_zero")]
    pub scheduled_at: i64,
    #[serde(rename = "attentionSent", skip_serializing_if = "String::is_empty")]
    pub attention_sent: String,
    #[serde(rename = "registry", skip_serializing_if = "Option::is_none")]
    pub reg: Option<Registry>,
    #[serde(rename = "lastReport")]
    pub last_report: GoTime,
    /// the harness check: when the running machine first reported, and the machine whose Claude host has reported since
    #[serde(rename = "bootedAt")]
    pub booted_at: GoTime,
    #[serde(rename = "hostUp", skip_serializing_if = "String::is_empty")]
    pub host_up: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub waiting: Option<WaitEpisode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settled: Option<SettledEpisode>,
    #[serde(rename = "loginRepaired", skip_serializing_if = "Option::is_none")]
    pub login_repaired: Option<RepairMark>,
    /// holder → not before
    #[serde(rename = "grantRetry", skip_serializing_if = "BTreeMap::is_empty")]
    pub grant_retry: BTreeMap<String, GoTime>,
    /// actions under way (a login "continue", a one-shot's destroy): when one started
    #[serde(rename = "loginBusyAt")]
    pub login_busy_at: GoTime,
    #[serde(rename = "oneShotFiringAt")]
    pub one_shot_firing_at: GoTime,
    /// statusUpdatedAt of the waiting episode whose pane was checked for the dialog
    #[serde(rename = "dialogCheckedAt", skip_serializing_if = "is_zero")]
    pub dialog_checked_at: i64,
    #[serde(rename = "dialogReported", skip_serializing_if = "is_false")]
    pub dialog_reported: bool,
    /// memory.rs: the starvation watch of the running machine
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mem: Option<crate::memory::MemState>,
    /// disk.rs: the disk watch of the running machine
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk: Option<crate::disk::DiskState>,
}

/// how long an action under way holds its mark (login_busy_at, one_shot_firing_at)
pub const IN_FLIGHT_FOR: TD = TD::minutes(10);

pub fn in_flight(at: &GoTime, now: &GoTime) -> bool {
    !at.is_zero() && now.sub(at) < IN_FLIGHT_FOR
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct WaitEpisode {
    pub at: GoTime,
    #[serde(rename = "statusAt")]
    pub status_at: i64,
    #[serde(skip_serializing_if = "is_false")]
    pub cancelled: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SettledEpisode {
    pub kind: String,
    pub since: GoTime,
    #[serde(skip_serializing_if = "is_false")]
    pub notified: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RepairMark {
    pub uuid: String,
    pub at: GoTime,
}

#[derive(Debug, Clone, Copy)]
pub struct PilotConfig {
    pub idle_pause: TD,
    pub waiting_cancel: TD,
    pub attention: TD,
    pub stale_report: TD,
    pub grant_retry: TD,
    pub repair_every: TD,
    pub downgrade_lookback: TD,
    pub harness_up: TD,
    pub idle_pause_scheduled: TD,
}

pub const DEFAULT_PILOT: PilotConfig = PilotConfig {
    idle_pause: TD::hours(1),
    waiting_cancel: TD::hours(1),
    attention: TD::minutes(5),
    stale_report: TD::minutes(3),
    grant_retry: TD::minutes(10),
    repair_every: TD::minutes(10),
    downgrade_lookback: TD::minutes(15),
    harness_up: TD::minutes(4),
    idle_pause_scheduled: TD::minutes(5),
};

/// how long a plain idle session runs before the auto-pause. A session that went idle after a scheduled turn nobody
/// is watching pauses in minutes (Deyao, 2026-11-02); after his own prompt it keeps the hour.
pub fn idle_pause_for(l: &Liveness, g: Option<&Registry>, c: &PilotConfig) -> TD {
    if let Some(g) = g
        && g.human_section
        && l.scheduled_at > 0
        && l.scheduled_at > g.last_human_at
        && c.idle_pause_scheduled > TD::ZERO
    {
        return c.idle_pause_scheduled;
    }
    c.idle_pause
}

pub const PILOT_TICK: std::time::Duration = std::time::Duration::from_secs(30);

pub static ROUTER_STARTED: LazyLock<GoTime> = LazyLock::new(GoTime::now);

pub fn new_liveness(i: &NewSession) -> Liveness {
    Liveness {
        one_shot: i.one_shot,
        auto_pause_off: i.one_shot || i.auto_pause == Some(false),
        ..Default::default()
    }
}

/// what the machine's env needs (harness-claude.sh reads SESSION_ONE_SHOT)
pub fn live_env(_: &Arc<Router>, s: &Session, e: &mut BTreeMap<String, String>) {
    if s.live.as_ref().is_some_and(|l| l.one_shot) {
        e.insert("SESSION_ONE_SHOT".into(), "1".into());
    }
}

/// what the phone sees on the new-session approval
pub fn live_options(s: &Session, o: &mut BTreeMap<String, String>) {
    if let Some(l) = &s.live {
        if l.one_shot {
            o.insert("oneShot".into(), "1".into());
        }
        if l.auto_pause_off {
            o.insert("autoPause".into(), "off".into());
        }
    }
}

/// one line, at most 200 characters (it names a Discord channel and an archive folder)
pub fn clean_app_title(t: &str) -> String {
    let t = jarvis_go::fmt::fields_join(t);
    t.chars().take(200).collect()
}

pub fn on_off(off: bool) -> &'static str {
    if off { "off" } else { "on" }
}

/// the status fields of /api/state, named as in Jarvis 1 (called under the state lock)
pub fn live_view(s: &Session, v: &mut Map<String, Value>) {
    let empty = Liveness::default();
    let l = s.live.as_ref().unwrap_or(&empty);
    v.insert("autoPause".into(), json!(on_off(l.auto_pause_off)));
    v.insert("notifyIdle".into(), json!(on_off(l.notify_idle_off)));
    v.insert("oneShot".into(), json!(l.one_shot));
    v.insert("needsGrant".into(), json!(l.needs_grant));
    if !l.last_report.is_zero() {
        v.insert("lastReport".into(), json!(l.last_report));
    }
    crate::memory::mem_view(s, v); // memory.rs: memAlert, memory
    let Some(g) = &l.reg else { return };
    if s.state != "started" || s.machine_id.is_empty() || l.last_report.since() > DEFAULT_PILOT.stale_report {
        return;
    }
    for (k, x) in [
        ("status", json!(g.status)),
        ("aiTitle", json!(g.ai_title)),
        ("liveName", json!(g.live_name)),
        ("nameSource", json!(g.name_source)),
        ("bgTasks", json!(g.bg_tasks)),
        ("statusUpdatedAt", json!(g.status_updated_at)),
        ("bridgeSessionId", json!(g.bridge_session_id)),
        ("sessionId", json!(g.session_id)),
        ("authFailed", json!(g.auth_failed)),
        ("credsExpiresAt", json!(g.creds_expires_at)),
        ("sessionsInside", json!(g.sessions_inside)),
        ("oneShotDone", json!(g.one_shot_done)),
        ("refusals", json!(g.refusals)),
    ] {
        v.insert(k.into(), x);
    }
    if let Some(wk) = &g.workers {
        v.insert("workers".into(), json!(wk)); // registry.rs: subagents and background jobs running now
    }
    if !l.auto_pause_off && !l.idle_since.is_zero() && idle_eligible(Some(g)) {
        let end = l.idle_since.add(idle_pause_for(l, Some(g), &DEFAULT_PILOT));
        let ms = end.sub(&GoTime::now()).whole_milliseconds().max(0) as i64;
        v.insert("pauseInMs".into(), json!(ms));
    }
}

pub fn register_autopilot(reg: &mut Registrar) {
    reg.m("POST /m/status", |r, w, _, machine, body| {
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct In {
            raw: String,
            /// the Claude app's title of the Remote Control entry (rust/machine/src/apptitle.rs)
            #[serde(rename = "appTitle")]
            app_title: String,
        }
        let i: In = jarvis_go::unmarshal(body).unwrap_or_default();
        let reg = crate::registry::parse_registry(&i.raw);
        let app_title = clean_app_title(&i.app_title);
        r.st.do_(|d| {
            let Some(sid) = d.machines.get(machine).cloned() else { return };
            let Some(s) = d.sessions.get_mut(&sid) else { return };
            if s.machine_id != machine {
                return;
            }
            let l = s.live.get_or_insert_with(Default::default);
            l.reg = reg.clone();
            l.last_report = GoTime::now();
            if s.booted != machine || l.booted_at.is_zero() {
                l.booted_at = l.last_report; // the harness check's clock (plan_tick)
            }
            s.booted = machine.into(); // its agent reports only once the machine has booted
            if reg.is_some() {
                l.host_up = machine.into();
                s.stuck_image.clear();
            }
            s.status.clear();
            if let Some(g) = &reg {
                s.status = g.status.clone();
                if !g.ai_title.is_empty() {
                    s.title = g.ai_title.clone();
                }
                if !g.name_source.is_empty() && g.name_source != "derived" && !g.live_name.is_empty() {
                    s.user_title = g.live_name.clone(); // Deyao named it himself
                }
            }
            if !app_title.is_empty() {
                s.app_title = app_title.clone(); // kept while paused
            }
        });
        write_json(w, 200, &json!({"ok": true}));
    });
    // the read-only terminal: the machine's own capture of its pane (rust/machine/src/screen.rs), in session_screens
    reg.m("POST /m/screen", |r, w, _, machine, body| {
        let i: crate::terminal::TermSnap = jarvis_go::unmarshal(body).unwrap_or_default();
        let session = r.st.read(|d| {
            d.machines
                .get(machine)
                .and_then(|sid| d.sessions.get(sid))
                .filter(|s| s.machine_id == machine)
                .map(|s| s.id.clone())
                .unwrap_or_default()
        });
        if !session.is_empty()
            && let Err(e) = r.st.put_screen(&session, machine, &i)
        {
            crate::nethttp::write_error(w, 503, &format!("{e:#}"));
            return;
        }
        write_json(w, 200, &json!({"ok": true}));
    });
    for field in ["autoPause", "notifyIdle"] {
        let path = if field == "autoPause" { "auto-pause" } else { "notify-idle" };
        reg.app(&format!("POST /api/sessions/{{id}}/{path}"), move |r, w, req| {
            #[derive(Deserialize, Default)]
            #[serde(default)]
            struct In {
                on: Option<bool>,
                /// Jarvis 1's name
                enabled: Option<bool>,
            }
            let i: In = crate::http::decode_body(req, 1 << 16);
            let on = i.on.or(i.enabled).unwrap_or(true);
            let id = req.path_value("id");
            let found = r.st.do_(|d| {
                let Some(s) = d.sessions.get_mut(&id) else { return false };
                let l = s.live.get_or_insert_with(Default::default);
                if field == "autoPause" {
                    l.auto_pause_off = !on;
                    l.idle_since = GoTime::default();
                } else {
                    l.notify_idle_off = !on;
                }
                true
            });
            if !found {
                crate::nethttp::write_error(w, 404, "no such session");
                return;
            }
            let mut out = json!({"ok": true});
            out[field] = json!(on_off(!on));
            write_json(w, 200, &out);
        });
    }
}

// ---- the loop ------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq)]
pub struct PilotAction {
    /// dm | escape | dialog | login | continue | pause | destroy | harness-stuck
    pub kind: String,
    pub session: String,
    /// harness-stuck: the machine whose harness never came up
    pub machine: String,
    /// dm
    pub text: String,
    /// login: the uuid of the "Please run /login" reply being repaired
    pub repair: String,
    pub name: String,
}

pub fn idle_eligible(g: Option<&Registry>) -> bool {
    g.is_some_and(|g| g.status == "idle" && g.bg_tasks == 0)
}

/// the state a session settled into, or "" while it works. None = no live claude inside → "dead".
pub fn attention_kind(g: Option<&Registry>, armed: bool) -> &'static str {
    match g {
        Some(g) if g.status == "waiting" => "waiting",
        Some(g) if g.status == "idle" && g.bg_tasks == 0 && !armed => "idle", // done, nothing will prompt it again
        Some(g) if !g.status.is_empty() => "",
        _ => "dead",
    }
}

/// one settled episode — its kind and the turn it settled on (a new turn is a new episode)
pub fn attention_key(kind: &str, g: Option<&Registry>) -> String {
    format!("{kind}:{}", g.map_or(0, |g| g.status_updated_at))
}

/// the name a session's DMs carry — its card/channel title, else the live AI title, else the CLI's derived Remote
/// Control name ("workspace-c1"), last
pub fn session_name(s: &Session, g: Option<&Registry>) -> String {
    let mut names: Vec<&str> = vec![&s.app_title, &s.user_title, &s.label];
    if let Some(g) = g {
        names.push(&g.ai_title);
    }
    names.push(&s.title);
    if let Some(g) = g {
        names.push(&g.live_name);
    }
    names
        .into_iter()
        .map(str::trim)
        .find(|n| !n.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| s.id.clone())
}

impl Liveness {
    pub fn may_exec(&self, holder: &str, now: &GoTime) -> bool {
        self.grant_retry.get(holder).is_none_or(|t| !now.before(t))
    }
}

/// one pass over the sessions; it moves the clocks and returns what to do. Called under the state lock.
pub fn plan_tick(
    d: &mut Persisted,
    now: GoTime,
    stored_exp: &BTreeMap<String, i64>,
    c: &PilotConfig,
    busy: &dyn Fn(&str) -> bool,
    veto: &dyn Fn(&Persisted, &str) -> bool,
) -> Vec<PilotAction> {
    let mut out = vec![];
    let ids: Vec<String> = d.sessions.keys().cloned().collect();
    for id in ids {
        let will_wake = crate::schedule::will_wake(d, &id);
        let vetoed = veto(d, &id);
        let Some(s) = d.sessions.get_mut(&id) else { continue };
        let task = crate::tasks::is_task_harness(&s.harness);
        let l = s.live.get_or_insert_with(Default::default);
        if s.state != "started" || s.machine_id.is_empty() {
            l.idle_since = GoTime::default();
            l.waiting = None;
            l.settled = None;
            l.dialog_checked_at = 0;
            l.dialog_reported = false;
            if s.machine_id.is_empty() {
                l.reg = None; // paused: the next machine reports afresh
            }
            continue;
        }
        if task {
            continue; // a task line runs a script, not a harness: tasks.rs pauses it once the run reports
        }
        let g = if l.last_report.is_zero() || now.sub(&l.last_report) > c.stale_report {
            None // no report lately: the machine (or its agent) isn't answering
        } else {
            l.reg.clone()
        };
        let g = g.as_ref();
        let operating = busy(&id);
        let s_view = s.clone();
        let name = session_name(&s_view, g);
        let l = s.live.get_or_insert_with(Default::default);

        // the harness check: a booted machine whose Claude never came up (no live host in the registry) for
        // harness_up is failed with what its screen shows (2026-10-20). Resume tries again on a new machine.
        if s_view.harness == "claude"
            && !operating
            && c.harness_up > TD::ZERO
            && l.host_up != s_view.machine_id
            && s_view.booted == s_view.machine_id
            && !l.booted_at.is_zero()
            && now.sub(&l.booted_at) >= c.harness_up
        {
            out.push(PilotAction {
                kind: "harness-stuck".into(),
                session: id.clone(),
                machine: s_view.machine_id.clone(),
                name,
                ..Default::default()
            });
            continue;
        }

        // "continue" after a start that took a new Claude account (accountswap.rs), once its host is up and idle
        if let Some(ops) = s.ops.as_mut()
            && ops.continue_after_start
            && !operating
            && let Some(g) = g
            && l.host_up == s_view.machine_id
            && !g.bridge_session_id.is_empty()
            && g.status == "idle"
        {
            ops.continue_after_start = false;
            out.push(PilotAction { kind: "continue".into(), session: id.clone(), name: name.clone(), ..Default::default() });
        }

        // one-shot: the prompt is done → destroy
        if l.one_shot && g.is_some_and(|g| g.one_shot_done) && !in_flight(&l.one_shot_firing_at, &now) && !operating {
            l.one_shot_firing_at = now;
            out.push(PilotAction { kind: "destroy".into(), session: id.clone(), name, ..Default::default() });
            continue;
        }

        // "needs you" / idle / dead DM, once per settled episode
        if operating || l.one_shot {
            l.settled = None;
        } else {
            let kind = attention_kind(g, will_wake);
            if kind.is_empty() {
                l.settled = None;
                l.attention_sent.clear();
            } else {
                let key = attention_key(kind, g);
                match &mut l.settled {
                    Some(st) if st.kind == kind => {
                        if !st.notified && now.sub(&st.since) >= c.attention {
                            st.notified = true;
                            l.attention_sent = key;
                            if !(kind == "idle" && l.notify_idle_off) {
                                out.push(PilotAction {
                                    kind: "dm".into(),
                                    session: id.clone(),
                                    text: attention_text(kind, &name),
                                    ..Default::default()
                                });
                            }
                        }
                    }
                    _ => {
                        l.settled = Some(SettledEpisode {
                            kind: kind.into(),
                            since: now,
                            notified: l.attention_sent == key,
                        })
                    }
                }
            }
        }

        // model downgrade: new refusal events in the transcripts, or the "switch model?" dialog on screen
        if let Some(g) = g
            && !operating
        {
            let since = l
                .downgrade_seen_at
                .max((ROUTER_STARTED.add(-c.downgrade_lookback).unix_nanos() / 1_000_000) as i64);
            let ev = fresh_refusals(&g.refusals, since);
            if let Some(last) = ev.last() {
                l.downgrade_seen_at = last.at;
                l.dialog_reported = true;
                out.push(PilotAction {
                    kind: "dm".into(),
                    session: id.clone(),
                    text: downgrade_text(&name, &ev),
                    ..Default::default()
                });
            } else if g.status != "waiting" {
                l.dialog_checked_at = 0;
                l.dialog_reported = false;
            } else if !l.dialog_reported && l.dialog_checked_at != g.status_updated_at && l.may_exec("status", &now) {
                l.dialog_checked_at = g.status_updated_at;
                out.push(PilotAction { kind: "dialog".into(), session: id.clone(), name: name.clone(), ..Default::default() });
            }
        }

        // Claude login: a session with a Claude account keeps that account's pair in step by itself; a turn that
        // stopped on "Please run /login" gets "continue" once the session's pair is in step again
        let exp = stored_exp.get(&s_view.claude_account).copied().unwrap_or(0);
        if let Some(g) = g
            && !operating
            && !in_flight(&l.login_busy_at, &now)
            && !s_view.claude_account.is_empty()
            && exp > (now.unix_nanos() / 1_000_000) as i64
            && g.creds_expires_at >= exp
            && g.status == "idle"
        {
            let u = &g.auth_failed;
            if !u.is_empty()
                && l
                    .login_repaired
                    .as_ref()
                    .is_none_or(|m| m.uuid != *u && now.sub(&m.at) >= c.repair_every)
            {
                l.login_repaired = Some(RepairMark { uuid: u.clone(), at: now });
                l.login_busy_at = now;
                out.push(PilotAction {
                    kind: "login".into(),
                    session: id.clone(),
                    repair: u.clone(),
                    name: name.clone(),
                    ..Default::default()
                });
            }
        }

        // a prompt unanswered for waiting_cancel → Escape (once per waiting episode)
        match g {
            Some(g) if g.status == "waiting" && !operating => match &mut l.waiting {
                Some(wt) if wt.status_at == g.status_updated_at => {
                    if !wt.cancelled && now.sub(&wt.at) >= c.waiting_cancel && l.grant_retry.get("status").is_none_or(|t| !now.before(t)) {
                        wt.cancelled = true;
                        out.push(PilotAction { kind: "escape".into(), session: id.clone(), name: name.clone(), ..Default::default() });
                    }
                }
                _ => l.waiting = Some(WaitEpisode { at: now, status_at: g.status_updated_at, cancelled: false }),
            },
            _ => {
                l.waiting = None;
                // "status" is only wanted while a prompt waits: once the session has moved on, the card stops
                // offering a grant for it (2026-10-12)
                if g.is_some() && l.needs_grant == "status" {
                    l.needs_grant.clear();
                    l.grant_retry.remove("status");
                }
            }
        }

        // auto-pause after idle_pause of plain idle (idle_pause_scheduled after a scheduled turn)
        if l.auto_pause_off || l.one_shot || vetoed || !idle_eligible(g) {
            l.idle_since = GoTime::default();
            continue;
        }
        let Some(g) = g else { continue };
        if l.idle_since.is_zero() || l.idle_status_at != g.status_updated_at {
            l.idle_since = now; // a turn the router didn't see starts the hour again
            l.idle_status_at = g.status_updated_at;
        }
        if now.sub(&l.idle_since) >= idle_pause_for(l, Some(g), c) && !operating {
            out.push(PilotAction { kind: "pause".into(), session: id.clone(), name, ..Default::default() });
        }
    }
    out
}

pub fn attention_text(kind: &str, name: &str) -> String {
    match kind {
        "waiting" => format!("🟠 Session “{name}” needs you — Claude is waiting for your input."),
        "idle" => format!("🟢 Session “{name}” is idle — Claude finished and is waiting."),
        _ => format!("🔴 Session “{name}” isn't running a live Claude session — it may have died or need a re-login."),
    }
}

pub fn fresh_refusals(ev: &[Refusal], since: i64) -> Vec<Refusal> {
    let mut seen = std::collections::BTreeSet::new();
    let mut out = vec![];
    for e in ev {
        if e.at <= since || (!e.uuid.is_empty() && seen.contains(&e.uuid)) {
            continue;
        }
        seen.insert(e.uuid.clone());
        out.push(e.clone());
    }
    out
}

/// lib/downgrade.js message — a fallback (the model actually changed) wins
pub fn downgrade_text(name: &str, ev: &[Refusal]) -> String {
    let cat = |e: &Refusal| {
        if e.category.is_empty() { String::new() } else { format!(" ({})", e.category) }
    };
    let or = |a: &str, b: &str| if a.is_empty() { b.to_string() } else { a.to_string() };
    for e in ev.iter().rev() {
        if e.kind == "fallback" {
            return format!(
                "🟡 Session “{name}”: {}'s safeguards flagged a message{} — Claude Code switched it to {}.",
                or(&e.from, "the model"),
                cat(e),
                or(&e.to, "a fallback model")
            );
        }
    }
    let Some(e) = ev.last() else { return String::new() };
    format!(
        "🟡 Session “{name}”: {}'s safeguards flagged a message{} and the turn stopped (no fallback model).",
        or(&e.model, "the model"),
        cat(e)
    )
}

static ANSI_SEQ: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"\x1b\[[0-9;?]*[A-Za-z]").unwrap_or_else(|e| panic!("{e}")));

pub fn strip_ansi(s: &str) -> String {
    ANSI_SEQ.replace_all(s, "").into_owned()
}

pub fn prompt_on_screen(screen: &str) -> bool {
    strip_ansi(screen).to_lowercase().contains("safeguards flagged")
}

/// how the harness check's error begins (Resume reads it: harness_retry_upgrade)
pub const HARNESS_STUCK_PREFIX: &str = "the harness didn't come up";

/// the failed session's error — the wait and the last lines of the pane
pub fn harness_stuck_text(wait: TD, screen: &str) -> String {
    let mut msg = format!(
        "{HARNESS_STUCK_PREFIX} within {} of boot (Claude Code never reported a live Remote Control host)",
        crate::flows::wait_text(std::time::Duration::from_secs(wait.whole_seconds().max(0) as u64))
    );
    let mut lines: Vec<String> = strip_ansi(screen)
        .split('\n')
        .map(jarvis_go::fmt::fields_join)
        .filter(|l| !l.is_empty() && !l.trim_matches(['─', '━', '-', '—', '╌', ' ']).is_empty())
        .collect();
    if lines.len() > 8 {
        lines = lines.split_off(lines.len() - 8);
    }
    let mut tail = lines.join(" / ");
    let n = tail.chars().count();
    if n > 500 {
        tail = format!("…{}", tail.chars().skip(n - 500).collect::<String>());
    }
    if tail.is_empty() {
        msg.push_str("; no screen from it");
    } else {
        msg.push_str(&format!("; its screen ends: {tail}"));
    }
    msg + ". Resume starts it again on a new machine."
}

/// a session the harness check failed resumes on the newest session image when its own is older (the phone approves
/// it): retrying the image whose Claude never came up would hang again
pub fn harness_retry_upgrade(s: &Session, newest: &str) -> bool {
    if s.stuck_image.is_empty() || (s.cert.is_none() && s.kernel.is_none()) || newest.is_empty() {
        return false;
    }
    let own_s = crate::flows::cert_image(s.cert.as_ref(), &s.image);
    let own = crate::flows::image_digest(&own_s);
    own == crate::flows::image_digest(&s.stuck_image) && own != crate::flows::image_digest(newest)
}

impl Router {
    pub fn start_autopilot(self: &Arc<Self>) {
        let r = self.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(PILOT_TICK);
            if crate::leaderlease::leads() {
                r.autopilot_tick();
            }
        });
    }

    pub fn autopilot_tick(self: &Arc<Self>) {
        let running = self
            .st
            .do_(|d| d.sessions.values().any(|s| s.state == "started" && !s.machine_id.is_empty()));
        if !running {
            return;
        }
        let stored_exp = self.login_expiries();
        let r = self.clone();
        let acts = self.st.do_(|d| {
            let now = GoTime::now();
            let mut acts = plan_tick(d, now, &stored_exp, &DEFAULT_PILOT, &|id| r.busy(id), &|d, id| {
                crate::schedule::auto_pause_veto(d, id)
            });
            for t in crate::memory::mem_silent_tick(d, now) {
                acts.push(PilotAction { kind: "dm".into(), text: t, ..Default::default() }); // memory.rs
            }
            acts
        });
        for a in acts {
            self.run_action(a);
        }
    }

    /// fail the session (the machine stays until a Resume finishes its pause, or a Destroy), log it, DM once
    fn harness_stuck(self: &Arc<Self>, mut a: PilotAction) {
        let screen = self.latest_screen(&a.session).map(|s| s.0.screen).unwrap_or_default();
        a.text = harness_stuck_text(DEFAULT_PILOT.harness_up, &screen);
        let failed = self.st.do_(|d| {
            let Some(s) = d.sessions.get_mut(&a.session) else { return false };
            if s.state != "started" || s.machine_id != a.machine || s.live.as_ref().is_some_and(|l| l.host_up == a.machine) {
                return false;
            }
            s.state = "failed".into();
            s.error = a.text.clone();
            s.stuck_image = crate::flows::cert_image(s.cert.as_ref(), &s.image);
            true
        });
        if !failed {
            return;
        }
        crate::logf!("session {}: failed: {}", a.session, a.text);
        let h = self.lc_begin(&a.session, "harness-check");
        h.machine(&a.machine);
        h.note(&a.machine, &a.text);
        h.end("failed", &a.text);
        self.dm(&format!("🔴 Session “{}” didn't come up: {}", a.name, a.text));
    }

    fn clear_live(&self, session: &str, f: impl Fn(&mut Liveness)) {
        self.st.do_(|d| {
            if let Some(l) = d.sessions.get_mut(session).and_then(|s| s.live.as_mut()) {
                f(l);
            }
        });
    }

    pub fn run_action(self: &Arc<Self>, a: PilotAction) {
        match a.kind.as_str() {
            "harness-stuck" => self.harness_stuck(a),
            "dm" => self.dm(&a.text),
            "pause" => {
                if let Err(e) = self.pause(&a.session) {
                    crate::logf!("[autopause] {}: {e:#}", a.session);
                    return;
                }
                crate::logf!("[autopause] paused idle session {} ({})", a.session, a.name);
                self.clear_live(&a.session, |l| l.idle_since = GoTime::default());
            }
            "destroy" => {
                if let Err(e) = self.finish_one_shot(&a.session) {
                    // oneshot.rs: forced, DMs about lost work
                    crate::logf!("[oneshot] {}: {e:#}", a.session);
                    self.clear_live(&a.session, |l| l.one_shot_firing_at = GoTime::default()); // the next tick looks
                    return;
                }
                crate::logf!("[oneshot] {} ({}) finished its prompt; destroying", a.session, a.name);
            }
            "escape" => {
                let r = self.clone();
                std::thread::spawn(move || {
                    if let Err(e) = r.exec_as(&a.session, "status", "tmux send-keys -t claude Escape", std::time::Duration::from_secs(20)) {
                        crate::logf!("[autopause] {}: cancelling the stale prompt failed: {e:#}", a.session);
                        r.clear_live(&a.session, |l| {
                            if let Some(w) = l.waiting.as_mut() {
                                w.cancelled = false;
                            }
                        });
                        return;
                    }
                    crate::logf!(
                        "[autopause] {} ({}): cancelled a prompt unanswered for {}",
                        a.session,
                        a.name,
                        jarvis_go::fmt::duration_string(std::time::Duration::from_secs(DEFAULT_PILOT.waiting_cancel.whole_seconds() as u64))
                    );
                });
            }
            "dialog" => {
                let r = self.clone();
                std::thread::spawn(move || {
                    // the machine's own pushed pane first (no grant); a machine without the screen push needs the status
                    // grant
                    let screen = match r.pushed_screen(&a.session) {
                        Some(s) => s.screen,
                        None => match r.exec_as(&a.session, "status", "tmux capture-pane -p -t claude", std::time::Duration::from_secs(20)) {
                            Err(_) => return,
                            Ok(res) => res.stdout,
                        },
                    };
                    if !prompt_on_screen(&screen) {
                        return;
                    }
                    r.clear_live(&a.session, |l| l.dialog_reported = true);
                    r.dm(&format!(
                        "🟡 Session “{}”: the safeguards flagged a message — Claude Code is asking whether to switch to another model.",
                        a.name
                    ));
                });
            }
            "continue" => {
                let r = self.clone();
                std::thread::spawn(move || {
                    match r.deliver_canned(&a.session, crate::vouch::Delivery { kind: "continue".into(), ..Default::default() }, "continue") {
                        Err(e) => crate::logf!("[account] {} ({}): \"continue\" after the start on its new Claude account failed: {e:#}", a.session, a.name),
                        Ok(()) => crate::logf!("[account] {} ({}): \"continue\" delivered after the start on its new Claude account", a.session, a.name),
                    }
                });
            }
            "login" => {
                let r = self.clone();
                std::thread::spawn(move || {
                    r.repair_login(&a);
                    r.clear_live(&a.session, |l| l.login_busy_at = GoTime::default());
                });
            }
            _ => {}
        }
    }

    /// exec, recording a refusal as the session's needsGrant (and backing off) and clearing it on success
    pub fn exec_as(self: &Arc<Self>, session: &str, holder: &str, cmd: &str, timeout: std::time::Duration) -> Result<ExecResult> {
        let res = self.exec(session, holder, cmd, timeout);
        match &res {
            Err(e) => self.note_refusal(session, holder, e),
            Ok(_) => self.clear_live(session, |l| {
                l.grant_retry.remove(holder);
                if l.needs_grant == holder {
                    l.needs_grant.clear();
                }
            }),
        }
        res
    }

    /// the machine refused (or the delivery through a grant failed): the app offers a grant, and the loop leaves that
    /// holder alone for grant_retry
    pub fn note_refusal(&self, session: &str, holder: &str, err: &anyhow::Error) {
        if !format!("{err:#}").contains("refused") {
            return;
        }
        self.clear_live(session, |l| {
            l.grant_retry
                .insert(holder.to_string(), GoTime::now().add(DEFAULT_PILOT.grant_retry));
            l.needs_grant = holder.to_string();
        });
    }
}
