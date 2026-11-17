//! Auto-accept (Deyao, 2026-11-04: "the supervisor can see the terminal screen, just make it auto accept prompts like
//! that"): a session in bypass mode still gets some tool permission dialogs. While the session's live mode is bypass,
//! the supervisor reads its own tmux pane every 2 s, and when the bottom of the pane is a tool permission dialog ("Do you
//! want to proceed?" with "❯ 1. Yes" focused) it presses Enter, which takes the focused "1. Yes" (allow once). A session
//! in auto mode is left alone: its prompts are Deyao's to answer. Only Claude Code's tool permission questions count.
//! Each accept is logged with the dialog's first lines.

use crate::claudelogin::{pane_text, send_keys};
use crate::deliver::live_mode;
use crate::stall::ANSI_SEQ;
use crate::{logf, paths, re, util};
use sha2::{Digest, Sha256};
use std::time::Duration;

const ACCEPT_EVERY: Duration = Duration::from_secs(2);

// the tool permission questions (Claude Code 2.1.318)
re!(
    ACCEPT_QUESTION = r"^\s*Do you want to (proceed\?|make this edit to .+\?|create .+\?|allow Claude to fetch this content\?)\s*$"
);
// the focused first option
re!(ACCEPT_YES = r"^\s*❯\s*1\.\s*Yes\s*$");
// the dialog's last line
re!(ACCEPT_FOOTER = r"^\s*Esc to cancel\b");

/// Whether the pane ends in a tool permission dialog with "1. Yes" focused, and the dialog's text (from its header) for
/// the log. The question must be followed directly by the focused Yes, and the footer must be the pane's last non-blank
/// line, so a dialog quoted in the conversation above never counts.
pub fn permission_dialog(screen: &str) -> (bool, String) {
    let clean = ANSI_SEQ.replace_all(screen, "");
    let lines: Vec<&str> = clean.split('\n').collect();
    let mut last = lines.len() as i64 - 1;
    while last >= 0 && lines[last as usize].trim().is_empty() {
        last -= 1;
    }
    if last < 2 || !ACCEPT_FOOTER.is_match(lines[last as usize]) {
        return (false, String::new());
    }
    let mut i = last - 1;
    while i >= 0 && i >= last - 40 {
        let iu = i as usize;
        if ACCEPT_QUESTION.is_match(lines[iu]) {
            if !ACCEPT_YES.is_match(lines[iu + 1]) {
                return (false, String::new());
            }
            let mut start = iu;
            while start > 0 && start as i64 > i - 12 && !lines[start - 1].trim().starts_with("────")
            {
                start -= 1;
            }
            return (true, lines[start..=iu].join("\n").trim().to_string());
        }
        i -= 1;
    }
    (false, String::new())
}

/// one look → whether to press Enter now. The same dialog (by its text) is pressed at most twice, so a screen that
/// doesn't change after Enter doesn't get Enter forever.
#[derive(Default)]
pub struct AcceptState {
    pub last: [u8; 32],
    pub tries: u32,
}

pub fn accept_step(s: &mut AcceptState, mode: &str, screen: &str) -> (bool, String) {
    if mode != "bypass" {
        *s = AcceptState::default();
        return (false, String::new());
    }
    let (ok, what) = permission_dialog(screen);
    if !ok {
        *s = AcceptState::default();
        return (false, String::new());
    }
    let h: [u8; 32] = Sha256::digest(screen.as_bytes()).into();
    if h == s.last {
        if s.tries >= 2 {
            return (false, String::new());
        }
    } else {
        s.last = h;
        s.tries = 0;
    }
    s.tries += 1;
    (true, what)
}

/// the supervisor's loop (started once booted)
pub fn auto_accept() {
    let mut s = AcceptState::default();
    loop {
        util::sleep(ACCEPT_EVERY);
        if paths::harness_paused_path().exists() {
            continue;
        }
        let Ok(cert) = crate::grants::current_cert() else {
            continue;
        };
        let mode = live_mode(&cert);
        if mode != "bypass" {
            s = AcceptState::default();
            continue;
        }
        let (press, what) = accept_step(&mut s, &mode, &pane_text());
        if !press {
            continue;
        }
        // read again right before pressing: the dialog may have gone (answered from the app or the web) in between
        if !permission_dialog(&pane_text()).0 {
            continue;
        }
        if let Err(e) = send_keys(&["Enter"]) {
            logf!("auto-accept: Enter wasn't sent: {e:#}");
            continue;
        }
        logf!(
            "auto-accept (bypass): allowed once: {}",
            util::go_quote(&what)
        );
    }
}
