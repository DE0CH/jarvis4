//! The read-only terminal (Deyao, 2026-10-12: "a read only terminal that doesn't require a grant"): like the status
//! report, the machine itself captures the harness's tmux pane every 2 s and POSTs it to /m/screen when it changed (and
//! every 30 s as a heartbeat). Nothing goes INTO the machine for it: no command, no flag, no grant; the router only
//! keeps the latest capture for the terminal page. Typing still goes through the "terminal" holder's grant.

use crate::client::Client;
use crate::session::rescue_command;
use crate::{logf, util};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

/// the same capture the router's terminal holder runs (router/terminal.go snapCmd)
pub const SCREEN_CMD: &str = r#"tmux capture-pane -p -e -t claude; printf '\n__CUR__%s\n' "$(tmux display-message -p -t claude '#{cursor_x},#{cursor_y},#{pane_width},#{pane_height},#{cursor_flag}')""#;

const SCREEN_EVERY: Duration = Duration::from_secs(2);
const SCREEN_HEARTBEAT: Duration = Duration::from_secs(30);
const SCREEN_MAX_BYTES: usize = 256 << 10;

/// the pane and the cursor line, or None when there is no tmux session `claude`
pub fn read_screen() -> Option<(String, String)> {
    let (out, st) = util::output_timeout(rescue_command("bash", &["-c", SCREEN_CMD]), SCREEN_EVERY);
    if !st.is_some_and(|s| s.success()) {
        return None;
    }
    let s = String::from_utf8_lossy(&out).into_owned();
    let i = s.rfind("\n__CUR__")?;
    let mut screen = s[..i].to_string();
    let cursor = s[i + "\n__CUR__".len()..].trim().to_string();
    if screen.len() > SCREEN_MAX_BYTES {
        let mut j = screen.len() - SCREEN_MAX_BYTES;
        while !screen.is_char_boundary(j) {
            j += 1;
        }
        screen = screen[j..].to_string();
    }
    (!cursor.is_empty()).then_some((screen, cursor))
}

/// the supervisor's screen component (started once booted); output only, unguarded
pub fn screen_reporter(c: &Client) {
    let mut last = String::new();
    let mut sent: Option<Instant> = None;
    loop {
        util::sleep(SCREEN_EVERY);
        let Some((screen, cursor)) = read_screen() else {
            continue;
        };
        let key = format!("{screen}{cursor}");
        if key == last && sent.is_some_and(|s| s.elapsed() < SCREEN_HEARTBEAT) {
            continue;
        }
        let body = BTreeMap::from([("screen", screen.as_str()), ("cursor", cursor.as_str())]);
        match c.json_ok("POST", "/m/screen", Some(&body)) {
            Err(e) => logf!("screen report failed: {e:#}"),
            Ok(()) => {
                last = key;
                sent = Some(Instant::now());
            }
        }
    }
}
