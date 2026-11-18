//! The live terminal (Jarvis 1's lib/tty.js over grants instead of Fly exec): the harness runs in tmux session `claude`
//! inside the machine. Viewing is the pane the machine's supervisor uploads itself (rust/machine/src/screen.rs), never
//! a command run in the machine; typing and resizing are commands under the "terminal" holder's grant.

use crate::router::Router;
use anyhow::{Result, anyhow, bail};
use jarvis_go::GoTime;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// a shell single-quoted word
pub fn shq(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct TermSnap {
    pub screen: String,
    /// x,y,width,height,visible
    pub cursor: String,
    /// when the machine pushed it
    #[serde(skip_serializing_if = "String::is_empty")]
    pub at: String,
}

/// a machine's screen push counts while its heartbeat (30 s) can still be on time
pub const SCREEN_FRESH: Duration = Duration::from_secs(45);

/// allowed tmux key names for term_input (anything else is refused)
const TMUX_KEYS: &[&str] = &[
    "Enter", "Escape", "Tab", "BTab", "BSpace", "Up", "Down", "Left", "Right", "C-c", "C-d", "C-j", "C-o", "C-r", "C-u", "PageUp",
    "PageDown",
];

/// when a pane age old was pushed (RFC 3339, UTC)
fn pushed_at(age: Duration) -> String {
    GoTime::from_unix_nanos(GoTime::now().unix_nanos() - age.as_nanos() as i128).utc().rfc3339()
}

impl Router {
    /// the latest pane the session's running machine pushed itself (rust/machine/src/screen.rs; screens.rs), if it is
    /// fresh
    pub fn pushed_screen(&self, session: &str) -> Option<TermSnap> {
        let (mut snap, age) = self.latest_screen(session)?;
        if age >= SCREEN_FRESH {
            return None;
        }
        snap.at = pushed_at(age);
        Some(snap)
    }

    /// the last pane the session's running machine pushed, however old
    pub fn latest_screen(&self, session: &str) -> Option<(TermSnap, Duration)> {
        let machine = self.st.do_(|d| d.sessions.get(session).map(|s| s.machine_id.clone()).unwrap_or_default());
        if machine.is_empty() {
            return None;
        }
        self.st.screen(session, &machine)
    }

    /// the pane the session's running machine last uploaded, however old (at says when). Viewing needs no grant and
    /// runs nothing in the machine (Deyao, 2026-10-12, 2026-10-24: "The supervisor should just upload it").
    pub fn term_snapshot(&self, session: &str) -> Result<TermSnap> {
        let (mut snap, age) = self.latest_screen(session).ok_or_else(|| {
            anyhow!("no screen from the machine yet: its supervisor sends the harness's pane every 2 s once the harness runs")
        })?;
        snap.at = pushed_at(age);
        Ok(snap)
    }

    pub fn term_input(&self, session: &str, text: &str, keys: &[String]) -> Result<()> {
        let mut cmd = vec![];
        if !text.is_empty() {
            let mut n = text.len().min(4000);
            while !text.is_char_boundary(n) {
                n -= 1;
            }
            cmd.push(format!("tmux send-keys -t claude -l -- {}", shq(&text[..n])));
        }
        for k in keys {
            if !TMUX_KEYS.contains(&k.as_str()) {
                bail!("unknown key {k}");
            }
            cmd.push(format!("tmux send-keys -t claude {k}"));
        }
        if cmd.is_empty() {
            return Ok(());
        }
        self.exec(session, "terminal", &cmd.join(" && "), Duration::from_secs(15))?;
        Ok(())
    }

    pub fn term_resize(&self, session: &str, cols: i64, rows: i64) -> Result<()> {
        if !(20..=400).contains(&cols) || !(5..=200).contains(&rows) {
            bail!("bad size");
        }
        self.exec(session, "terminal", &format!("tmux resize-window -t claude -x {cols} -y {rows}"), Duration::from_secs(15))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn shq_quotes() {
        assert_eq!(super::shq("it's"), r"'it'\''s'");
    }
}
