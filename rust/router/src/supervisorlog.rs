//! The supervisor's log (Deyao, 2026-10-16): each session machine's supervisor (rust/machine/src/supervisor.rs) pushes
//! its own log lines here (POST /m/supervisor-log), from its first second (also while it boots, before its first status
//! report). The router keeps them per session in its database (session_log, sessionlog.rs), for the session's life;
//! the app and web page read them in the session's one event stream with the lifecycle log (sessionevents.rs,
//! GET /api/sessions/{id}/events). On Destroy both go into the session's Storage Box archive
//! (jarvis2/supervisor-log.jsonl), then off the volume.
//!
//! The lines are the machine's own words: the supervisor writes no secret into them (machine side), and the router
//! shows them only to Deyao's login.

use crate::http::Registrar;
use crate::nethttp::{write_error, write_json};
use crate::router::Router;
use crate::sessionlog::LOG_SUPERVISOR;
use anyhow::Result;
use jarvis_go::GoTime;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicI64, Ordering};

/// per push
pub const SUP_LOG_MAX_LINES: usize = 500;
/// bytes per line (clipped)
pub const SUP_LOG_MAX_LINE: usize = 2000;
/// lines per read
pub const SUP_LOG_READ_MAX: usize = 2000;

/// a session's log is cut to its newer half past this (tests shrink it)
pub static SUP_LOG_MAX_FILE: AtomicI64 = AtomicI64::new(20 << 20);

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct SupLine {
    pub seq: i64,
    pub at: String,
    pub machine: String,
    pub text: String,
}

/// session → the next seq (read from its log on first use)
#[derive(Default)]
pub struct SupLogs(Mutex<BTreeMap<String, i64>>);

/// a session id as a file name (ids are [a-z0-9-]; anything else is replaced)
pub fn log_file_name(s: &str) -> String {
    if s.is_empty() {
        return "_".into();
    }
    s.bytes()
        .map(|c| if c.is_ascii_alphanumeric() || c == b'-' || c == b'_' { c as char } else { '_' })
        .collect()
}

/// s cut to at most n bytes, on a character boundary
fn cut_bytes(s: &str, n: usize) -> &str {
    let mut i = n.min(s.len());
    while !s.is_char_boundary(i) {
        i -= 1;
    }
    &s[..i]
}

impl Router {
    /// every line of a session's supervisor log, in order
    pub fn read_sup_log(&self, session: &str) -> Vec<SupLine> {
        let _g = self.sup.0.lock().unwrap_or_else(|e| e.into_inner());
        self.read_sup_log_locked(session)
    }

    fn read_sup_log_locked(&self, session: &str) -> Vec<SupLine> {
        let raw = self.st.read_log(session, LOG_SUPERVISOR).unwrap_or_else(|e| {
            crate::logf!("[supervisor-log] reading {session}: {e:#}");
            vec![]
        });
        raw.iter().filter_map(|b| jarvis_go::unmarshal(b).ok()).collect()
    }

    /// lines of one machine onto its session's log, numbered; cut to the newer half past SUP_LOG_MAX_FILE
    pub fn append_sup_log(&self, session: &str, machine: &str, lines: Vec<SupLine>) -> Result<()> {
        let mut g = self.sup.0.lock().unwrap_or_else(|e| e.into_inner());
        if self.lc.dropped(session) {
            return Ok(());
        }
        let mut next = match g.get(session) {
            Some(n) => *n,
            None => self.read_sup_log_locked(session).last().map_or(1, |l| l.seq + 1),
        };
        let rows: Vec<String> = lines
            .into_iter()
            .map(|mut l| {
                l.seq = next;
                l.machine = machine.into();
                next += 1;
                jarvis_go::marshal(&l)
            })
            .collect();
        let refs: Vec<&[u8]> = rows.iter().map(|s| s.as_bytes()).collect();
        self.st.append_log(session, LOG_SUPERVISOR, &refs)?;
        g.insert(session.into(), next);
        let max = SUP_LOG_MAX_FILE.load(Ordering::Relaxed);
        if self.st.log_bytes(session, LOG_SUPERVISOR) > max {
            let all = self.read_sup_log_locked(session);
            if all.is_empty() {
                return Ok(());
            }
            let keep = &all[all.len() / 2..];
            let note = SupLine {
                seq: keep[0].seq - 1, // a dropped line's: the seqs stay in order
                at: GoTime::now().utc().rfc3339_nano(),
                machine: String::new(),
                text: format!(
                    "[router] the supervisor log passed {} MB: its {} oldest lines were dropped",
                    max >> 20,
                    all.len() - keep.len()
                ),
            };
            let out: Vec<Vec<u8>> =
                std::iter::once(&note).chain(keep.iter()).map(|l| jarvis_go::marshal(l).into_bytes()).collect();
            return self.st.replace_log(session, LOG_SUPERVISOR, &out);
        }
        Ok(())
    }

    /// the session is gone (a record now, its archive holds the log)
    pub fn drop_sup_log(&self, session: &str) {
        let mut g = self.sup.0.lock().unwrap_or_else(|e| e.into_inner());
        self.st.drop_log(session, LOG_SUPERVISOR);
        g.remove(session);
    }
}

pub fn register_supervisor_log(reg: &mut Registrar) {
    reg.m("POST /m/supervisor-log", |r, w, _, machine, body| {
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct Line {
            at: String,
            text: String,
        }
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct In {
            lines: Vec<Line>,
        }
        let i: In = match jarvis_go::unmarshal(body) {
            Ok(i) => i,
            Err(e) => return write_error(w, 400, &format!("not JSON: {e}")),
        };
        if i.lines.len() > SUP_LOG_MAX_LINES {
            return write_error(w, 400, &format!("at most {SUP_LOG_MAX_LINES} lines per push"));
        }
        let session = r.st.do_(|d| d.machines.get(machine).cloned().unwrap_or_default());
        if session.is_empty() {
            return write_error(w, 404, "this machine belongs to no session");
        }
        let now = GoTime::now().utc();
        let lines: Vec<SupLine> = i
            .lines
            .into_iter()
            .map(|l| {
                let at = match GoTime::parse(&l.at) {
                    Some(at) if (-86_400_000..=60_000).contains(&at.sub(&now).whole_milliseconds()) => at,
                    _ => now, // a machine clock off by a lot: the router's time
                };
                let text = if l.text.len() > SUP_LOG_MAX_LINE {
                    format!("{}…", cut_bytes(&l.text, SUP_LOG_MAX_LINE))
                } else {
                    l.text
                };
                SupLine { at: at.utc().rfc3339_nano(), text, ..Default::default() }
            })
            .collect();
        let texts: Vec<String> = lines.iter().map(|l| l.text.clone()).collect();
        if let Err(e) = r.append_sup_log(&session, machine, lines) {
            return write_error(w, 500, &format!("{e:#}"));
        }
        // neverbooted.rs: a machine that says it refuses to start fails its session
        if let Some(why) = texts.iter().map(|t| crate::neverbooted::refused_in_log(t)).find(|w| !w.is_empty()) {
            r.boot_failed(machine, &why);
        }
        write_json(w, 200, &json!({"ok": true}));
    });
}
