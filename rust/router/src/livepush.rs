//! The live dashboard's Jarvis 4 panel (Deyao, 2026-11-12: "a panel for my jarvis 4 status, i just need to know
//! limited information like if session is working, idle, or with background"): the leading replica POSTs his running
//! sessions every LIVE_PUSH_EVERY to LIVE_PUSH_URL with the header X-Jarvis-Secret: LIVE_PUSH_SECRET (Secret
//! router-secrets-livepush, infra/router-secrets.py --part livepush; unset = off). Jarvis 4 holds the dashboard's write
//! secret; the dashboard holds nothing of Jarvis 4's. Each session is only its title, a state, two counts and since
//! when; at most LIVE_MAX in live_rank's order, with the total listed. A session that will wake by itself (a wakeup,
//! cron or watch armed) and has nothing running is "scheduled", paused or idle, as the app's Scheduled (Deyao,
//! 2026-11-17: "it should also show scheduled as blue, similar to background"), with its next wake when it has a time.

use crate::autopilot::DEFAULT_PILOT;
use crate::registry::Registry;
use crate::router::Router;
use crate::state::Persisted;
use anyhow::{Result, bail};
use jarvis_go::GoTime;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, LazyLock};
use std::time::Duration;

pub const LIVE_PUSH_EVERY: Duration = Duration::from_secs(5);
/// the most the dashboard's biggest layout shows (its right display: two columns of 16; Deyao, 2026-11-17)
pub const LIVE_MAX: usize = 32;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct LiveSession {
    pub name: String,
    /// working | waiting | background | scheduled | idle | booting
    pub state: String,
    pub jobs: i64,
    pub subagents: i64,
    /// ms: the status's last change (statusUpdatedAt; changes every turn)
    #[serde(skip_serializing_if = "is_zero")]
    pub since: i64,
    /// ms: a scheduled session's next wakeup or cron (a watch alone has none)
    #[serde(skip_serializing_if = "is_zero")]
    pub next: i64,
}

fn is_zero(n: &i64) -> bool {
    *n == 0
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct LiveDocument {
    pub at: i64,
    pub total: i64,
    pub sessions: Vec<LiveSession>,
}

/// Claude Code's working line ("✻ Thinking… (12s · esc to interrupt)"), as rust/machine/src/stall.rs reads it
static LIVE_SPINNER: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"(?m)^\s*\S\s+[A-Z][\p{L}-]*…\s*\(\d").unwrap_or_else(|_| unreachable!()));
static LIVE_ANSI: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"\x1b\[[0-9;?]*[A-Za-z]").unwrap_or_else(|_| unreachable!()));

fn spinning(screen: &str) -> bool {
    LIVE_SPINNER.is_match(&LIVE_ANSI.replace_all(screen, ""))
}

/// the order on the panel, the dashboard's amber states (waiting, idle; Deyao, 2026-11-17) first
pub fn live_rank(state: &str) -> i64 {
    match state {
        "waiting" => 0,
        "idle" => 1,
        "working" => 2,
        "background" => 3,
        "scheduled" => 4,
        "booting" => 5,
        _ => 0, // Go's map lookup of an unknown state
    }
}

/// the session's earliest wakeup or cron (0: none with a time, e.g. a watch only)
pub fn next_wake(d: &Persisted, sid: &str) -> i64 {
    let mut next = 0;
    if let Some(sc) = d.schedules.get(sid) {
        for w in sc.wakeups.values() {
            if next == 0 || w.at < next {
                next = w.at;
            }
        }
        for c in sc.crons.values() {
            if next == 0 || c.next_at < next {
                next = c.next_at;
            }
        }
    }
    next
}

/// a running session's state. Claude Code keeps a host "busy" while background jobs run after its turn ended
/// (rust/machine/src/stall.rs), so a busy host with jobs or subagents and no working line on its pane is "background".
/// screen: its pushed pane ("" when none is fresh). → (state, jobs, subagents)
pub fn live_state_of(g: Option<&Registry>, fresh: bool, screen: &str) -> (&'static str, i64, i64) {
    let Some(g) = g.filter(|g| fresh && !g.status.is_empty()) else { return ("booting", 0, 0) };
    let mut jobs = g.bg_tasks;
    let mut subagents = 0;
    if let Some(w) = &g.workers {
        let n: i64 = w.jobs.values().sum();
        jobs = jobs.max(n);
        subagents = w.subagents;
    }
    let state = match g.status.as_str() {
        "waiting" => "waiting",
        "idle" if jobs > 0 || subagents > 0 => "background",
        "idle" => "idle",
        "busy" if (jobs > 0 || subagents > 0) && !screen.is_empty() && !spinning(screen) => "background",
        _ => "working",
    };
    (state, jobs, subagents)
}

impl Router {
    /// the push's body (the screens are read outside the state lock: a database read each)
    pub fn live_doc(&self, now: GoTime) -> LiveDocument {
        struct Row {
            s: LiveSession,
            id: String,
            busy: bool,
        }
        let mut rows: Vec<Row> = self.st.read(|d| {
            let mut rows = vec![];
            // Go ranges over a map: the order is the stable sort's tie-break only
            for s in d.sessions.values() {
                let wakes = crate::schedule::will_wake(d, &s.id);
                if s.state == "paused" && wakes {
                    rows.push(Row {
                        s: LiveSession {
                            name: crate::titles::session_title(s),
                            state: "scheduled".into(),
                            next: next_wake(d, &s.id),
                            ..Default::default()
                        },
                        id: s.id.clone(),
                        busy: false,
                    });
                    continue;
                }
                if s.state != "started" || s.machine_id.is_empty() {
                    continue;
                }
                let (g, fresh) = match s.live.as_ref().and_then(|l| l.reg.as_ref().map(|g| (g, l))) {
                    Some((g, l)) => (Some(g), now.sub(&l.last_report) <= DEFAULT_PILOT.stale_report),
                    None => (None, false),
                };
                let (st, jobs, sub) = live_state_of(g, fresh, "");
                let mut x = LiveSession {
                    name: crate::titles::session_title(s),
                    state: st.into(),
                    jobs,
                    subagents: sub,
                    ..Default::default()
                };
                if st == "idle" && wakes {
                    x.state = "scheduled".into();
                    x.next = next_wake(d, &s.id);
                }
                if let Some(g) = g
                    && fresh
                    && g.status_updated_at > 0
                {
                    x.since = g.status_updated_at;
                }
                let busy = g.is_some_and(|g| fresh && g.status == "busy" && (jobs > 0 || sub > 0));
                rows.push(Row { s: x, id: s.id.clone(), busy });
            }
            rows
        });
        for row in rows.iter_mut().filter(|r| r.busy) {
            if let Some(snap) = self.pushed_screen(&row.id)
                && !spinning(&snap.screen)
            {
                row.s.state = "background".into();
            }
        }
        rows.sort_by(|x, y| {
            let (a, b) = (&x.s, &y.s);
            let (ra, rb) = (live_rank(&a.state), live_rank(&b.state));
            if ra != rb {
                return ra.cmp(&rb);
            }
            if a.state == "scheduled" && a.next != b.next {
                // the soonest first, a watch only (no time) last
                return if b.next == 0 || (a.next != 0 && a.next < b.next) {
                    std::cmp::Ordering::Less
                } else {
                    std::cmp::Ordering::Greater
                };
            }
            b.since.cmp(&a.since)
        });
        LiveDocument {
            at: (now.unix_nanos() / 1_000_000) as i64,
            total: rows.len() as i64,
            sessions: rows.into_iter().take(LIVE_MAX).map(|r| r.s).collect(),
        }
    }

    /// the loop, on the leading replica only (leaderlease.rs); off without LIVE_PUSH_URL / LIVE_PUSH_SECRET
    pub fn start_live_push(self: &Arc<Self>) {
        let url = std::env::var("LIVE_PUSH_URL").unwrap_or_default();
        let secret = std::env::var("LIVE_PUSH_SECRET").unwrap_or_default();
        if url.is_empty() || secret.is_empty() {
            return;
        }
        let c = reqwest::blocking::Client::builder().timeout(Duration::from_secs(10)).build().unwrap_or_default();
        let r = self.clone();
        std::thread::spawn(move || {
            let mut failing = false;
            loop {
                std::thread::sleep(LIVE_PUSH_EVERY);
                if !crate::leaderlease::leads() {
                    continue;
                }
                let res = live_post(&c, &url, &secret, &r.live_doc(GoTime::now()));
                if res.is_err() != failing {
                    failing = res.is_err();
                    match res {
                        Err(e) => crate::logf!("live push: {e:#}"),
                        Ok(()) => crate::logf!("live push: working again"),
                    }
                }
            }
        });
    }
}

pub fn live_post(c: &reqwest::blocking::Client, url: &str, secret: &str, doc: &LiveDocument) -> Result<()> {
    let res = c
        .post(url)
        .header("Content-Type", "application/json")
        .header("X-Jarvis-Secret", secret)
        .body(jarvis_go::marshal(doc))
        .send()?;
    let st = res.status();
    if st.as_u16() != 200 {
        bail!("HTTP {}", st.canonical_reason().unwrap_or(""));
    }
    Ok(())
}
