//! A session's tail, now (livetail.go; Deyao, 2026-11-20: "in addition to the transcript search that lags current by
//! some time, have a function to get the tail of a session in a timely manner"). Transcript search sees a running
//! session through its .live copies (livesync.rs), up to LIVE_SYNC_SECONDS (5 min) old, then indexed by a crawl every
//! 5 min.
//!
//! GET /m/api/tail/{session} (`jarvis-tail SESSION`): for a running session the router sends its machine the
//! "live-sync" command; the machine sends every transcript that changed since its last copy (POST /m/live-transcript,
//! as its own sync does) and then POST /m/live-synced. The router waits for that (up to LIVE_TAIL_WAIT_MS), then reads
//! the end of the session's conversation from its .live copy and parses it as the app's tails are (tails.rs), with the
//! tool calls and their results unless ?said=1. The conversation is the copy whose last entry is newest: one rule that
//! also picks right for an image that never answers the command. A session that isn't running (paused, frozen) or a
//! machine that doesn't answer gets its last copy, marked stale with why.
//!
//! Any session may read any session's tail, as transcript search already gives every session every transcript, only
//! later (Deyao, 2026-11-20). The machine sends only its own transcripts, so no router feature runs anything in it.

use crate::http::Registrar;
use crate::livesync::{LiveSync, live_dir};
use crate::nethttp::write_json;
use crate::peermsg::resolve_peer;
use crate::router::Router;
use crate::storagebox::StorageBox;
use crate::storagebox::no_storage_box;
use crate::tails::{TAIL_BYTES, Tail, parse_transcript_with};
use jarvis_go::GoTime;
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// a machine sends a 50 MB transcript in seconds; an old image never answers
pub static LIVE_TAIL_WAIT_MS: AtomicU64 = AtomicU64::new(45_000);
/// the round's answer may reach another replica: read the state again
pub static LIVE_TAIL_POLL_MS: AtomicU64 = AtomicU64::new(300);

/// how much of each .live copy's end is read for its last entry's time
const LIVE_SCAN_BYTES: usize = 256 << 10;

/// GET /m/api/tail/{session}
#[derive(Debug, Clone, Default, Serialize, PartialEq)]
pub struct LiveTail {
    #[serde(flatten)]
    pub tail: Tail,
    /// the router's id (s…)
    pub session: String,
    pub state: String,
    /// the conversation's .live copy (<uuid>.jsonl)
    pub file: String,
    /// its size when the router last received it
    pub bytes: i64,
    /// its last entry's time
    #[serde(rename = "lastAt")]
    pub last_at: String,
    /// why it is stale
    #[serde(skip_serializing_if = "String::is_empty")]
    pub why: String,
}

pub fn register_live_tail(reg: &mut Registrar) {
    reg.m("POST /m/live-synced", |r, w, _, machine, _| {
        let sid = match r.machine_session(machine) {
            Ok(s) => s,
            Err(e) => return write_json(w, 403, &json!({"error": e.to_string()})),
        };
        let now = GoTime::now().utc();
        r.st.do_(|d| {
            if let Some(s) = d.sessions.get_mut(&sid)
                && s.machine_id == machine
            {
                s.live_sync.get_or_insert_with(LiveSync::default).round_at = Some(now);
            }
        });
        write_json(w, 200, &json!({"ok": true}));
    });
    reg.m("GET /m/api/tail/{session}", |r, w, req, machine, _| {
        if let Err(e) = r.machine_session(machine) {
            return write_json(w, 403, &json!({"error": e.to_string()}));
        }
        let n = req.query("n").parse::<usize>().unwrap_or(0);
        match r.live_tail_of(&req.path_value("session"), req.query("said") != "1", n) {
            Ok(t) => write_json(w, 200, &t),
            Err((code, e)) => write_json(w, code, &json!({"error": e})),
        }
    });
}

impl Router {
    /// target = a session id or its exact title; tools: the tool calls and results too; n messages (default 40, at
    /// most 500)
    pub fn live_tail_of(
        &self,
        target: &str,
        tools: bool,
        n: usize,
    ) -> Result<LiveTail, (u16, String)> {
        let n = if n == 0 { 40 } else { n.min(500) };
        let s = self.st.read(|d| resolve_peer(d, target)).map_err(|e| {
            (
                404,
                format!("{e:#} (a destroyed session's transcript is in transcript search, whole)"),
            )
        })?;
        let mut out = LiveTail {
            session: s.id.clone(),
            state: s.state.clone(),
            ..Default::default()
        };
        if s.state == "started" && !s.machine_id.is_empty() {
            if !self.live_round(&s.id, &s.machine_id) {
                out.tail.stale = true;
                out.why = format!(
                    "its machine did not answer the live sync within {} (an image from before 2026-11-20 never does): its last copy",
                    jarvis_go::fmt::duration_string(Duration::from_millis(
                        LIVE_TAIL_WAIT_MS.load(Ordering::SeqCst)
                    ))
                );
            }
        } else {
            out.tail.stale = true;
            out.why = format!("it is {}: its last copy, taken before that", s.state);
        }
        let Some(b) = self.box_() else {
            return Err((500, no_storage_box().to_string()));
        };
        let files: BTreeMap<String, i64> = self.st.read(|d| {
            d.sessions
                .get(&s.id)
                .and_then(|x| x.live_sync.as_ref())
                .and_then(|l| l.files.clone())
                .unwrap_or_default()
        });
        let dir = live_dir(&s.id);
        let (name, last) =
            newest_conversation(&b, &dir, &files).map_err(|e| (502, format!("{e:#}")))?;
        if name.is_empty() {
            return Err((
                404,
                "no copy of its conversation has reached the router yet".into(),
            ));
        }
        let mut text = b
            .get_tail(&format!("{dir}/{name}"), TAIL_BYTES)
            .map_err(|e| (502, format!("{e:#}")))?
            .unwrap_or_default();
        if text.len() > TAIL_BYTES {
            text.drain(..text.len() - TAIL_BYTES);
        }
        let stale = out.tail.stale;
        out.tail = parse_transcript_with(
            &String::from_utf8_lossy(&text),
            text.len() >= TAIL_BYTES,
            n,
            4000,
            tools,
        );
        out.tail.stale = stale;
        out.bytes = files.get(&name).copied().unwrap_or(0);
        out.file = name;
        out.last_at = last;
        Ok(out)
    }

    /// ask the machine for a sync round now and wait for its answer; false when none came in time
    pub fn live_round(&self, sid: &str, machine: &str) -> bool {
        let asked = GoTime::now().utc();
        self.send(machine, "live-sync");
        let deadline = std::time::Instant::now()
            + Duration::from_millis(LIVE_TAIL_WAIT_MS.load(Ordering::SeqCst));
        loop {
            let done = self.st.read(|d| {
                d.sessions
                    .get(sid)
                    .and_then(|s| s.live_sync.as_ref())
                    .and_then(|l| l.round_at.as_ref())
                    .is_some_and(|t| !t.before(&asked))
            });
            if done {
                return true;
            }
            if std::time::Instant::now() > deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(
                LIVE_TAIL_POLL_MS.load(Ordering::SeqCst),
            ));
        }
    }
}

/// of a session's .live copies (name → size), the conversation whose last entry is newest, and that entry's time.
/// Subagents' copies (agent-*.jsonl) are not conversations.
pub fn newest_conversation(
    b: &StorageBox,
    dir: &str,
    files: &BTreeMap<String, i64>,
) -> anyhow::Result<(String, String)> {
    let (mut best, mut best_at, mut best_t) = (String::new(), String::new(), None::<GoTime>);
    for n in files.keys().filter(|n| !n.starts_with("agent-")) {
        let Some(tail) = b.get_tail(&format!("{dir}/{n}"), LIVE_SCAN_BYTES)? else {
            continue; // gone from the box (a purge)
        };
        let at = last_entry_time(&tail);
        let t = GoTime::parse(&at);
        let newer = match (&t, &best_t) {
            (Some(t), Some(b)) => t.after(b),
            (Some(_), None) => true,
            (None, _) => best.is_empty(),
        };
        if newer {
            (best, best_at, best_t) = (n.clone(), at, t);
        }
    }
    Ok((best, best_at))
}

/// the timestamp of the last whole line that has one ("" when none does)
pub fn last_entry_time(b: &[u8]) -> String {
    String::from_utf8_lossy(b)
        .split('\n')
        .rev()
        .find_map(|l| {
            let v: Value = serde_json::from_str(l).ok()?;
            v.get("timestamp")?
                .as_str()
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        })
        .unwrap_or_default()
}
