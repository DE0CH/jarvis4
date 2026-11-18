//! A failed session always says why, and when (2026-10-22: Jarvis 2's "Kates work" failed on its first start, with no
//! machine, and the setup API showed no reason). Whatever path makes a session failed, the state's every write
//! (State::do_) checks it here: a failed session gets failed_at (cleared once it is anything else) and, if the path
//! left none, a reason saying so. Each new failure is in the session's event stream: the operation that failed ends
//! with the reason (lifecycle.rs); a failure outside any operation (an approval that lapsed, a router crash's cut-off,
//! …) gets a one-line "Session failed: <reason>" of its own. The reason is shown wherever the session is listed: GET
//! /api/state (the app's list and session page, the web page), GET /setup/sessions (infra/setup.py sessions -v), the
//! events.

use crate::lifecycle::{LcOp, LcRec, now_text};
use crate::router::Router;
use crate::state::Persisted;
use jarvis_go::GoTime;

/// what a failed session says when the path that failed it gave no reason (a bug to fix there)
pub const NO_REASON: &str =
    "it failed without a reason recorded (the router's path that failed it gave none)";

/// failed_at and a reason on every failed session; the sessions that have just become failed, as (id, reason) pairs.
/// Called under the state's lock.
pub fn stamp_failures(d: &mut Persisted, now: GoTime) -> Vec<(String, String)> {
    let mut out = vec![];
    for (id, s) in d.sessions.iter_mut() {
        if s.state != "failed" {
            s.failed_at = None;
            continue;
        }
        if s.error.is_empty() {
            s.error = NO_REASON.into();
        }
        if s.failed_at.is_none() {
            s.failed_at = Some(now);
            out.push((id.clone(), s.error.clone()));
        }
    }
    out
}

impl Router {
    /// a session has just become failed: unless an operation of it is running (its end carries the reason) or the
    /// latest one already ended with this reason, the stream gets a "Session failed: <reason>" of its own
    pub fn failure_event(&self, session: &str, reason: &str) {
        if let Some(op) = self.lc.current_op(session)
            && (op.state == "running" || op.error == reason)
        {
            return;
        }
        self.lc_ended(session, "session", "", reason);
    }

    /// an operation written already ended, failed with reason (sessionevents.rs shows only its end: "<Kind> failed:
    /// <reason>")
    pub fn lc_ended(&self, session: &str, kind: &str, machine: &str, reason: &str) {
        let at = now_text();
        let ms = if machine.is_empty() {
            vec![]
        } else {
            vec![machine.to_string()]
        };
        let op = LcOp {
            id: crate::util::rand_id(),
            session: session.into(),
            kind: kind.into(),
            started: at.clone(),
            ended: at,
            state: "failed".into(),
            error: reason.into(),
            machines: ms,
        };
        self.lc_write(
            session,
            LcRec {
                op: Some(op),
                ..Default::default()
            },
        );
    }
}
