//! The final snapshot's progress (rust/machine/src/snapshot.rs): while the supervisor makes and uploads the snapshot of
//! a pause, destroy or Upgrade, it reports numbers every few seconds:
//!
//! ```text
//! POST /m/snapshot-progress  {phase: "measuring" | "uploading" | "writing", done, total /* uncompressed bytes */,
//!                             sent /* compressed bytes sent so far */, elapsedMs /* since the phase began */}
//! ```
//!
//! The router builds the words from the numbers itself (no machine text reaches the app) and puts them in the session's
//! `waiting` (the status line the app and web show: "pausing: uploading snapshot 1.2/3.4 GB, 40 MB/s, 55 s left"), only
//! while a snapshot of that machine is awaited, and a line into the running operation's lifecycle log at most every
//! PROGRESS_NOTE_EVERY.

use crate::http::Registrar;
use crate::nethttp::write_json;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

/// one report
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct SnapProgress {
    pub phase: String,
    pub done: i64,
    pub total: i64,
    pub sent: i64,
    #[serde(rename = "elapsedMs")]
    pub elapsed_ms: i64,
}

const PROGRESS_NOTE_EVERY: Duration = Duration::from_secs(20);

/// machine → the last lifecycle note
static PROGRESS_NOTES: LazyLock<Mutex<BTreeMap<String, Instant>>> = LazyLock::new(|| Mutex::new(BTreeMap::new()));

/// "uploading snapshot 1.2/3.4 GB, 40 MB/s, 55 s left" ("" for a report that makes no sense)
pub fn snap_progress_text(p: &SnapProgress) -> String {
    if p.done < 0 || p.total < 0 || p.sent < 0 || p.elapsed_ms < 0 {
        return String::new();
    }
    match p.phase.as_str() {
        "measuring" => return format!("measuring the snapshot ({} so far)", byte_text(p.total, p.total)),
        "uploading" | "writing" => {}
        _ => return String::new(),
    }
    let total = p.total.max(p.done);
    let what = if p.phase == "writing" { "writing snapshot" } else { "uploading snapshot" };
    let mut s = format!("{what} {}", byte_ratio(p.done, total));
    if total > 0 {
        s += &format!(" ({}%)", p.done * 100 / total);
    }
    if p.elapsed_ms >= 1000 && p.done > 0 {
        let rate = p.done as f64 / (p.elapsed_ms as f64 / 1000.0);
        s += &format!(", {}/s", byte_text(rate as i64, rate as i64));
        if total > p.done {
            let left = (total - p.done) as f64 / rate;
            s += &format!(", {} left", left_text(Duration::from_secs_f64(left.max(0.0))));
        }
    }
    s
}

/// n in the unit `scale` calls for (GB from 1 GB, else MB, else KB)
pub fn byte_text(n: i64, scale: i64) -> String {
    if scale >= 1_000_000_000 {
        format!("{:.1} GB", n as f64 / 1e9)
    } else if scale >= 1_000_000 {
        format!("{:.0} MB", n as f64 / 1e6)
    } else {
        format!("{:.0} KB", n as f64 / 1e3)
    }
}

/// "1.2/3.4 GB"
pub fn byte_ratio(done: i64, total: i64) -> String {
    let t = byte_text(total, total);
    let mut d = byte_text(done, total);
    for u in [" GB", " MB", " KB"] {
        if d.len() > u.len() && d.ends_with(u) {
            d.truncate(d.len() - u.len());
        }
    }
    format!("{d}/{t}")
}

/// "55 s", "3 min 20 s"
pub fn left_text(d: Duration) -> String {
    let sec = (d.as_millis() as u64 + 500) / 1000;
    if sec < 60 {
        return format!("{sec} s");
    }
    if sec % 60 == 0 {
        return format!("{} min", sec / 60);
    }
    format!("{} min {} s", sec / 60, sec % 60)
}

pub fn register_snap_progress(reg: &mut Registrar) {
    reg.m("POST /m/snapshot-progress", |r, w, _, machine, body| {
        let Ok(p) = jarvis_go::unmarshal::<SnapProgress>(body) else {
            return write_json(w, 400, &json!({"error": "{phase, done, total, sent, elapsedMs}"}));
        };
        let text = snap_progress_text(&p);
        if text.is_empty() {
            return write_json(w, 400, &json!({"error": "phase: measuring | uploading | writing; numbers ≥ 0"}));
        }
        let sid = r.st.do_(|d| {
            d.machines
                .get(machine)
                .and_then(|sid| d.sessions.get(sid))
                .filter(|s| s.machine_id == machine)
                .map(|s| s.id.clone())
                .unwrap_or_default()
        });
        if sid.is_empty() || !r.snapshot_awaited(machine) {
            return write_json(w, 200, &json!({"ok": false})); // nothing waits on it: not shown
        }
        r.snapshot_reported(machine, &p); // snapwait.rs: numbers that moved keep the wait going
        r.set_waiting(&sid, &text);
        let note = {
            let mut g = PROGRESS_NOTES.lock().unwrap_or_else(|e| e.into_inner());
            let due = g.get(machine).is_none_or(|t| t.elapsed() >= PROGRESS_NOTE_EVERY);
            if due {
                g.insert(machine.to_string(), Instant::now());
            }
            due
        };
        if note {
            r.lc_note(&sid, machine, &text);
        }
        write_json(w, 200, &json!({"ok": true}));
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn texts() {
        let p = SnapProgress { phase: "uploading".into(), done: 1_200_000_000, total: 3_400_000_000, sent: 0, elapsed_ms: 30_000 };
        assert_eq!(snap_progress_text(&p), "uploading snapshot 1.2/3.4 GB (35%), 40 MB/s, 55 s left");
        assert_eq!(left_text(Duration::from_secs(200)), "3 min 20 s");
        assert_eq!(snap_progress_text(&SnapProgress { phase: "x".into(), ..Default::default() }), "");
    }
}
