//! The Remote Control watch (Deyao, 2026-10-25: "Remote Control in a session is not always reliable"; "not jarvis do,
//! supervisor do"): a component of the supervisor that looks at its own session's Claude host every minute. Remote
//! Control is down when the host has no Remote Control entry, or its entry is "disconnected" on claude.ai while the
//! machine itself reaches Anthropic. Only an outage that lasts 3 minutes counts. Then, between turns, the supervisor
//! types /remote-control into the host: an entry the CLI still holds is disconnected first ("Disconnect this session"),
//! and "Enable Remote Control" makes a fresh connection with the same conversation. A revive that didn't take is tried
//! again after 10 minutes. The router takes no part.

use crate::claudelogin::{
    RC_ENABLE_TEXT, RC_TYPING, live_bridge, pane_text, rc_up_wait, send_keys, wait_until,
};
use crate::{logf, paths, util};
use std::time::{Duration, Instant};

const RC_EVERY: Duration = Duration::from_secs(60);
pub const RC_DOWN_AFTER: Duration = Duration::from_secs(180);
pub const RC_RETRY_WAIT: Duration = Duration::from_secs(600);
/// for the menu, typed between turns (ms; tests shorten it)
pub static RC_STEP_WAIT_MS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(30_000);
/// the /remote-control menu of a host that has Remote Control on
pub const RC_DISCONNECT_TEXT: &str = "Disconnect this session";

/// one look at the host
#[derive(Debug, Clone, Default)]
pub struct RcLook {
    /// the host's process is alive
    pub host_up: bool,
    /// its Remote Control entry ("" = Remote Control is off on the host)
    pub bridge: String,
    /// the entry's connection_status on claude.ai ("" = not known)
    pub server: String,
    /// between turns: what is typed runs at once and lands in no dialog
    pub idle: bool,
}

/// since when Remote Control has been down, and when it was last revived
#[derive(Debug, Clone, Default)]
pub struct RcClock {
    pub since: Option<Instant>,
    pub tried: Option<Instant>,
}

/// one look → whether to revive now
pub fn rc_step(c: &mut RcClock, l: &RcLook, now: Instant) -> bool {
    if !l.host_up || (!l.bridge.is_empty() && (l.server.is_empty() || l.server == "connected")) {
        *c = RcClock::default();
        return false;
    }
    let Some(since) = c.since else {
        c.since = Some(now);
        return false;
    };
    if now.saturating_duration_since(since) < RC_DOWN_AFTER
        || !l.idle
        || c.tried
            .is_some_and(|t| now.saturating_duration_since(t) < RC_RETRY_WAIT)
    {
        return false;
    }
    c.tried = Some(now);
    true
}

/// the host as its registry file says, and its entry as claude.ai says
pub fn look_rc() -> RcLook {
    let h = crate::stall::read_host();
    if !h.ok
        || h.pid <= 0
        || nix::sys::signal::kill(nix::unistd::Pid::from_raw(h.pid as i32), None).is_err()
    {
        return RcLook::default();
    }
    let mut l = RcLook {
        host_up: true,
        bridge: h.bridge.clone(),
        server: String::new(),
        idle: h.status == "idle",
    };
    if h.status == "busy" {
        // busy with background jobs only, as the stall watch tells it
        l.idle =
            crate::screen::read_screen().is_some_and(|(s, _)| !crate::stall::turn_on_screen(&s));
    }
    let key = h.bridge.strip_prefix("cse_").unwrap_or(&h.bridge);
    let key = key.strip_prefix("session_").unwrap_or(key);
    if !key.is_empty() {
        let tok = crate::apptitle::claude_access_token();
        if !tok.is_empty() {
            let (s, _, r) = crate::apptitle::fetch_code_session(key, &tok);
            if r.is_ok() {
                l.server = s.connection_status;
            }
        }
    }
    l
}

/// the supervisor's loop (started once booted), for the harness that is a Remote Control host
pub fn rc_watch() {
    let mut c = RcClock::default();
    loop {
        util::sleep(RC_EVERY);
        if paths::harness_paused_path().exists() {
            c = RcClock::default(); // paused, or stopped for the final snapshot
            continue;
        }
        let h = crate::harnesses::cert_harness();
        if !h.is_empty() && h != "claude" {
            continue;
        }
        let l = look_rc();
        if !rc_step(&mut c, &l, Instant::now()) {
            continue;
        }
        let down = c.since.map(|s| s.elapsed().as_secs()).unwrap_or(0);
        logf!(
            "remote control: down for {} (entry {}, claude.ai: {}): typing /remote-control",
            crate::keeper::dur_text(Duration::from_secs(down)),
            util::go_quote(&l.bridge),
            util::go_quote(&l.server)
        );
        revive_remote_control(&l.bridge);
    }
}

/// disconnect the entry the host still holds, then enable Remote Control again
pub fn revive_remote_control(held: &str) {
    let Ok(_g) = RC_TYPING.try_lock() else {
        logf!("remote control: an account switch is typing into the host: left to it");
        return;
    };
    if !held.is_empty() && !rc_choose(RC_DISCONNECT_TEXT, || live_bridge().is_empty()) {
        logf!("remote control: the host still holds its entry after Disconnect");
        return;
    }
    if rc_choose(RC_ENABLE_TEXT, || !live_bridge().is_empty()) {
        logf!("remote control: up again ({})", live_bridge());
    } else {
        logf!("remote control: no entry after choosing Enable");
    }
}

/// type /remote-control and choose the line of its menu that says want, until done; a command that does it with no menu
/// is done too. Escape only ever goes to the open menu
pub fn rc_choose(want: &str, done: impl Fn() -> bool) -> bool {
    if let Err(e) = send_keys(&["-l", "/remote-control"]) {
        logf!("remote control: typing: {e:#}");
        return false;
    }
    util::sleep(Duration::from_millis(300));
    let _ = send_keys(&["Enter"]);
    let escape = || {
        if !open_menu(&pane_text()).is_empty() {
            let _ = send_keys(&["Escape"]);
        }
    };
    if !wait_until(
        Duration::from_millis(RC_STEP_WAIT_MS.load(std::sync::atomic::Ordering::Relaxed)),
        || done() || open_menu(&pane_text()).contains(want),
    ) {
        logf!(
            "remote control: the /remote-control menu didn't offer {} within 30s",
            util::go_quote(want)
        );
        escape();
        return false;
    }
    if done() {
        return true;
    }
    for _ in 0..8 {
        match menu_distance(&open_menu(&pane_text()), want) {
            None => break,
            Some(0) => {
                let _ = send_keys(&["Enter"]);
                return wait_until(rc_up_wait(), &done);
            }
            Some(d) if d < 0 => {
                let _ = send_keys(&["Up"]);
            }
            Some(_) => {
                let _ = send_keys(&["Down"]);
            }
        }
        util::sleep(Duration::from_millis(200));
    }
    logf!(
        "remote control: couldn't select {} in the menu",
        util::go_quote(want)
    );
    escape();
    false
}

/// the /remote-control dialog at the bottom of the pane, from its title line ("Remote Control" alone), else ""
pub fn open_menu(pane: &str) -> String {
    let ls: Vec<&str> = pane.split('\n').collect();
    for i in (0..ls.len()).rev() {
        if ls[i].trim() == "Remote Control" {
            let m = ls[i..].join("\n");
            return if menu_distance(&m, "").is_some() {
                m
            } else {
                String::new()
            };
        }
    }
    String::new()
}

/// lines from the menu's cursor ("❯") to the choice that says want (negative = above it)
pub fn menu_distance(menu: &str, want: &str) -> Option<i64> {
    let (mut cur, mut at) = (-1i64, -1i64);
    for (i, line) in menu.split('\n').enumerate() {
        if line.starts_with("  ") && line.trim().starts_with('❯') {
            cur = i as i64; // the cursor is indented
        }
        if line.contains(want) {
            at = i as i64;
        }
    }
    (cur >= 0 && at >= 0).then_some(at - cur)
}
