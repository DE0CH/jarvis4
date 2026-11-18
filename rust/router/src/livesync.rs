//! Live transcript sync (Jarvis 1's session-image/sync-live-transcripts): while a session runs, its machine sends each
//! conversation transcript that changed (every LIVE_SYNC_SECONDS, default 300) to POST /m/live-transcript, and the
//! router puts it on the Storage Box with its own credentials at
//!
//!     claude-records/.live/<session id>/<conversation uuid>.jsonl
//!
//! — Jarvis 1's layout, so transcript search (DE0CH/deyao-ai; its indexer reads .live/<id>/) covers Jarvis 4 sessions
//! that are still running. The session id is the router's (s…), stable across the session's machines. On destroy the
//! archive takes every copy the snapshot doesn't hold, and only then does the router delete the copies it archived
//! (livearchive.rs); one it didn't archive stays.
//!
//! No grant: the machine sends its own transcripts (as it sends its status report and its pause snapshots, which hold
//! the same transcripts), so no router feature runs anything in it; Storage Box credentials stay on the router.
//! docs/DECISIONS.md 38.

use crate::archive::RECORDS_ROOT;
use crate::nethttp::{Req, W, write_error, write_json};
use crate::router::Router;
use crate::types::Session;
use jarvis_go::GoTime;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, LazyLock, Mutex};

/// what the router last did with a session's transcripts (shown in /api/state as liveSync)
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct LiveSync {
    pub at: GoTime,
    /// conversation file → bytes last received
    pub files: Option<BTreeMap<String, i64>>,
    /// false: received but not written (no Storage Box, or RECORDS_OFF)
    pub stored: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub error: String,
}

pub fn live_root() -> String {
    format!("{RECORDS_ROOT}/.live")
}

/// a transcript's file name, as claude names them (<uuid>.jsonl); anything else is refused
static LIVE_NAME_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.jsonl$").unwrap_or_else(|_| unreachable!()));

/// a bigger transcript isn't sent (the machine checks the same limit)
pub const LIVE_SYNC_MAX_BYTES: usize = 256 << 20;

/// session ids whose .live dir exists on the box
static LIVE_DIRS: LazyLock<Mutex<BTreeSet<String>>> = LazyLock::new(Default::default);

pub fn live_dir(sid: &str) -> String {
    format!("{}/{sid}", live_root())
}

/// how often the machine looks for changed transcripts (unsigned machine env; the e2e test shortens it)
pub fn livesync_env(_: &Arc<Router>, _: &Session, e: &mut BTreeMap<String, String>) {
    if let Ok(n) = std::env::var("LIVE_SYNC_SECONDS").unwrap_or_default().parse::<i64>()
        && n > 0
    {
        e.insert("JARVIS2_LIVE_SYNC_SECONDS".into(), n.to_string());
    }
}

impl Router {
    /// POST /m/live-transcript, header X-Name = the file's name, body = the whole file
    pub fn live_transcript(&self, w: &mut W, req: &mut Req, machine: &str, body: &[u8]) {
        let sid = match self.machine_session(machine) {
            Ok(s) => s,
            Err(e) => return write_error(w, 403, &format!("{e:#}")),
        };
        let name = req.header("X-Name");
        if !LIVE_NAME_RE.is_match(&name) {
            return write_error(w, 400, "X-Name must be a transcript's file name (<uuid>.jsonl)");
        }
        if body.len() > LIVE_SYNC_MAX_BYTES {
            return write_error(w, 413, &format!("larger than {LIVE_SYNC_MAX_BYTES} bytes"));
        }
        let mut stored = false;
        let mut werr: Option<anyhow::Error> = None;
        if let Some(b) = self.box_()
            && !crate::archive::records_off()
        {
            let dir = live_dir(&sid);
            let known = LIVE_DIRS.lock().unwrap_or_else(|e| e.into_inner()).contains(&sid);
            let res = if known { Ok(()) } else { b.mkcols(&dir) };
            let res = res.and_then(|()| {
                LIVE_DIRS.lock().unwrap_or_else(|e| e.into_inner()).insert(sid.clone());
                b.put_bytes(&format!("{dir}/{name}"), body)
            });
            if let Err(e) = res {
                LIVE_DIRS.lock().unwrap_or_else(|e| e.into_inner()).remove(&sid); // the dir may have gone (a purge): make it again next time
                werr = Some(e);
            }
            stored = werr.is_none();
        }
        let err_text = werr.as_ref().map(|e| format!("{e:#}")).unwrap_or_default();
        self.st.do_(|d| {
            let Some(s) = d.sessions.get_mut(&sid) else { return };
            let l = s.live_sync.get_or_insert_with(LiveSync::default);
            l.at = GoTime::now().utc();
            l.stored = stored;
            l.error = err_text.clone();
            l.files.get_or_insert_with(BTreeMap::new).insert(name.clone(), body.len() as i64);
        });
        if werr.is_some() {
            crate::logf!("[livesync] {sid} {name}: {err_text}");
            return write_error(w, 502, &format!("Storage Box: {err_text}"));
        }
        write_json(w, 200, &json!({"ok": true, "stored": stored}));
    }
}
