//! The stall watch (Deyao, 2026-10-24: "a simple watch from the supervisor, nothing outside the image"): a component of
//! the supervisor that looks at its own session's Claude host every 10 s. When the host has background jobs running
//! and no turn, and nothing has changed (its statusUpdatedAt) for 15 minutes, the supervisor sends the watchdog's text
//! into the harness through the Jarvis channel itself, and again every 15 minutes while it lasts.
//!
//! Claude Code keeps the host's status "busy" while background jobs run after the turn ended, so a "busy" host counts as
//! waiting on its jobs when the pane shows no turn running (no spinner line); with no pane, a busy host never starts
//! the clock.

use crate::deliver::{live_mode, send_to_harness};
use crate::session::rescue_command;
use crate::{gojson, logf, paths, re, util};
use serde::Deserialize;
use std::path::PathBuf;
use std::sync::RwLock;
use std::time::{Duration, Instant};

const STALL_EVERY: Duration = Duration::from_secs(10);
pub const STALL_AFTER: Duration = Duration::from_secs(15 * 60);

/// the session's Claude host as its registry file says, with its background jobs
#[derive(Debug, Clone, Default)]
pub struct HostStatus {
    pub ok: bool,
    /// idle | busy | waiting | shell …
    pub status: String,
    /// statusUpdatedAt (ms): changes with every turn
    pub status_at: i64,
    pub jobs: i64,
    pub pid: i64,
    /// its Remote Control entry ("" = none)
    pub bridge: String,
}

/// since when the host has waited on its jobs alone, on which turn
#[derive(Debug, Clone, Default)]
pub struct StallClock {
    pub status_at: i64,
    pub since: Option<Instant>,
}

/// one look → whether to nudge now, and for how many minutes it has waited
pub fn stall_step(
    c: &mut StallClock,
    h: &HostStatus,
    screen: &str,
    screen_ok: bool,
    now: Instant,
) -> (bool, i64) {
    if !h.ok || h.jobs <= 0 {
        *c = StallClock::default();
        return (false, 0);
    }
    let mut jobs_only = h.status == "idle" || h.status == "shell";
    if h.status == "busy" {
        if !screen_ok {
            return (false, 0); // can't tell a running turn from a finished one: the clock stays as it is
        }
        jobs_only = !turn_on_screen(screen);
    }
    if !jobs_only {
        *c = StallClock::default();
        return (false, 0);
    }
    let Some(since) = c.since.filter(|_| c.status_at == h.status_at) else {
        *c = StallClock {
            status_at: h.status_at,
            since: Some(now),
        };
        return (false, 0);
    };
    let stalled = now.saturating_duration_since(since);
    if stalled >= STALL_AFTER {
        c.since = Some(now);
        return (true, ((stalled.as_secs_f64() / 60.0).round()) as i64);
    }
    (false, 0)
}

// Claude Code's working line ("✻ Thinking… (12s · esc to interrupt)")
re!(SPINNER_LINE = r"(?m)^\s*\S\s+[A-Z][\p{L}-]*…\s*\(\d");
re!(ANSI_SEQ = r"\x1b\[[0-9;?]*[A-Za-z]");

pub fn turn_on_screen(screen: &str) -> bool {
    SPINNER_LINE.is_match(&ANSI_SEQ.replace_all(screen, ""))
}

/// the watchdog's message (Jarvis 1's lib/stall.js nudgeText)
pub fn stall_text(jobs: i64, minutes: i64) -> String {
    let j = if jobs == 1 {
        "1 background job has".to_string()
    } else {
        format!("{jobs} background jobs have")
    };
    format!(
        "Jarvis watchdog: this session has been idle for {minutes} min while {j} been running, and none has finished or woken you. "
    ) + "Check on them now: read their output, and if a job is hung or no longer needed, stop it and continue the task another way. "
        + "If a job is legitimately still running, make sure it will end on its own (a timeout or deadline), then end your turn — this check repeats while the state lasts. "
        + "This is an automated message from Jarvis."
}

/// claude's registry dir (tests move it)
pub static CLAUDE_SESSIONS: RwLock<Option<PathBuf>> = RwLock::new(None);

pub fn claude_sessions() -> PathBuf {
    CLAUDE_SESSIONS
        .read()
        .ok()
        .and_then(|p| p.clone())
        .unwrap_or_else(|| PathBuf::from("/home/claude/.claude/sessions"))
}

/// tests count the jobs here
pub static TEST_SHELL_JOBS: std::sync::Mutex<Option<i64>> = std::sync::Mutex::new(None);

/// The Remote Control host's registry entry (else the first one) and its background jobs: the shells it has running
/// (as the status report counts them) or the hook-fed count (workers.rs), whichever is more
pub fn read_host() -> HostStatus {
    #[derive(Deserialize, Default, Clone)]
    #[serde(default)]
    struct Entry {
        pid: i64,
        #[serde(rename = "sessionId")]
        session_id: String,
        status: String,
        #[serde(rename = "statusUpdatedAt")]
        status_at: i64,
        #[serde(rename = "startedAt")]
        started_at: i64,
        #[serde(rename = "bridgeSessionId")]
        bridge: String,
    }
    let mut files: Vec<PathBuf> = std::fs::read_dir(claude_sessions())
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    files.sort();
    let mut es: Vec<Entry> = files
        .iter()
        .filter_map(|f| std::fs::read(f).ok())
        .filter_map(|b| gojson::unmarshal::<Entry>(&b).ok())
        .filter(|e| e.pid > 0)
        .collect();
    if es.is_empty() {
        return HostStatus::default();
    }
    es.sort_by_key(|e| e.started_at);
    let h = es
        .iter()
        .find(|e| !e.bridge.is_empty())
        .cloned()
        .unwrap_or_else(|| es[0].clone());
    let mut jobs = shell_jobs(h.pid);
    if let Some(w) = crate::workers::get(&h.session_id) {
        jobs = jobs.max(w.jobs.values().sum());
    }
    HostStatus {
        ok: true,
        status: h.status,
        status_at: h.status_at,
        jobs,
        pid: h.pid,
        bridge: h.bridge,
    }
}

/// the background shells claude runs (its children running a shell snapshot), as status.rs's __BG__ counts
fn shell_jobs(pid: i64) -> i64 {
    if let Some(n) = TEST_SHELL_JOBS.lock().ok().and_then(|g| *g) {
        return n;
    }
    let p = pid.to_string();
    let (out, _) = util::output_timeout(
        rescue_command("pgrep", &["-c", "-P", &p, "-f", "shell-snapshots"]),
        Duration::from_secs(5),
    );
    String::from_utf8_lossy(&out).trim().parse().unwrap_or(0)
}

/// the supervisor's loop (started once booted); a one-shot session finishes by itself and never gets the nudge
pub fn stall_watch() {
    if crate::vouch::read_vouched_bool("oneShot") {
        return;
    }
    let mut c = StallClock::default();
    loop {
        util::sleep(STALL_EVERY);
        if paths::harness_paused_path().exists() {
            continue; // paused, or stopped for the final snapshot: not stalled
        }
        let (screen, ok) = match crate::screen::read_screen() {
            Some((s, _)) => (s, true),
            None => (String::new(), false),
        };
        let (nudge, minutes) = stall_step(&mut c, &read_host(), &screen, ok, Instant::now());
        if !nudge {
            continue;
        }
        let h = read_host();
        let cert = match crate::grants::current_cert() {
            Ok(c) => c,
            Err(e) => {
                logf!("stall watch: no cert: {e:#}");
                continue;
            }
        };
        if let Err(e) = send_to_harness(
            &cert.options.harness,
            &live_mode(&cert),
            "jarvis",
            &stall_text(h.jobs, minutes),
        ) {
            logf!("stall watch: the nudge wasn't taken: {e:#}");
            continue;
        }
        logf!(
            "stall watch: nudged (idle {minutes} min with {} background jobs)",
            h.jobs
        );
    }
}
