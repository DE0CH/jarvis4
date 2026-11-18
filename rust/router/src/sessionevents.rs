//! A session's events (Deyao, 2026-10-16: "it should be one stream which i can see all events"): ONE time-ordered
//! stream of everything the router keeps about a session's machines, which the app and the web page show as the
//! session's Log:
//!
//!   - the supervisor's lines (source "supervisor", supervisorlog.rs), all of them, from every machine the session had;
//!   - each operation of the lifecycle log (lifecycle.rs): its start and its end (source "router", mark "start" /
//!     "end", with the operation's kind and, at the end, its state and error), and its router steps and Fly entries
//!     (sources "router" and "fly") in between.
//!
//! GET /api/sessions/{id}/events → the newest `limit` events (default and max 2000), oldest first, and a cursor;
//! GET …/events?after=<cursor> → only what was written since (the client adds them and keeps its list in time order: a
//! Fly event is read a few seconds after it happened, so a new event can sort before one already shown). The cursor is
//! "<supervisor seq>.<lifecycle record>": both files only grow (the supervisor log's cut keeps its seqs), so it is
//! exact; an event's key ("s<seq>", "l<record>") is stable across reads.

use crate::flows::wait_text;
use crate::http::Registrar;
use crate::lifecycle::{LcOp, LcRec, parse_at};
use crate::nethttp::{write_error, write_json};
use crate::router::Router;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

pub const EVENTS_READ_MAX: usize = 2000;

/// one entry of a session's stream
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct SessionEvent {
    pub key: String,
    pub at: String,
    /// supervisor | router | fly
    pub source: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub machine: String,
    /// the operation it belongs to: its kind (pause, resume, …)
    #[serde(skip_serializing_if = "String::is_empty")]
    pub op: String,
    /// …and id
    #[serde(rename = "opId", skip_serializing_if = "String::is_empty")]
    pub op_id: String,
    /// start | end: the operation began / ended here
    #[serde(skip_serializing_if = "String::is_empty")]
    pub mark: String,
    /// an end's state: done | failed | cut off
    #[serde(skip_serializing_if = "String::is_empty")]
    pub state: String,
    pub text: String,
}

fn or<'a>(a: &'a str, b: &'a str) -> &'a str {
    if a.is_empty() { b } else { a }
}

pub fn op_title(kind: &str) -> String {
    let k = or(kind, "operation").replace('-', " ");
    let mut c = k.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => k,
    }
}

pub fn dur_text(from: &str, to: &str) -> String {
    let (a, b) = (parse_at(from), parse_at(to));
    if a.is_zero() || b.is_zero() {
        return String::new();
    }
    let d = b.sub(&a);
    if d < time::Duration::minutes(1) {
        return format!("{} s", d.whole_seconds());
    }
    wait_text(Duration::try_from(d).unwrap_or_default())
}

/// the lifecycle file's records as events (from record `from` on), and the operation still running (None if none)
pub fn lc_events(recs: &[LcRec], from: usize) -> (Vec<SessionEvent>, Option<LcOp>) {
    let mut ops: BTreeMap<String, LcOp> = BTreeMap::new(); // id → as it now is
    let mut ended: BTreeSet<String> = BTreeSet::new(); // an end already given
    let mut out = vec![];
    let mut latest = String::new();
    for (i, rec) in recs.iter().enumerate() {
        let key = format!("l{i}");
        if let Some(op) = &rec.op {
            let seen = ops.insert(op.id.clone(), op.clone()).is_some();
            if !seen {
                latest = op.id.clone();
                if i >= from && op.state == "running" {
                    // one written already ended (failures.rs, lostmachine.rs): its end only
                    out.push(SessionEvent {
                        key: key.clone(),
                        at: op.started.clone(),
                        source: "router".into(),
                        op: op.kind.clone(),
                        op_id: op.id.clone(),
                        mark: "start".into(),
                        state: "running".into(),
                        text: format!("{} started", op_title(&op.kind)),
                        ..Default::default()
                    });
                }
            }
            if op.state != "running" && ended.insert(op.id.clone()) && i >= from {
                let mut t = format!("{} {}", op_title(&op.kind), op.state);
                let d = dur_text(&op.started, &op.ended);
                if !d.is_empty() && op.started != op.ended {
                    t = format!("{t} after {d}");
                }
                if !op.error.is_empty() {
                    t = format!("{t}: {}", op.error);
                }
                out.push(SessionEvent {
                    key,
                    at: or(&op.ended, &op.started).to_string(),
                    source: "router".into(),
                    op: op.kind.clone(),
                    op_id: op.id.clone(),
                    mark: "end".into(),
                    state: op.state.clone(),
                    text: t,
                    ..Default::default()
                });
            }
        } else if let Some(e) = &rec.entry
            && i >= from
        {
            out.push(SessionEvent {
                key,
                at: e.at.clone(),
                source: or(&e.source, "router").to_string(),
                machine: e.machine.clone(),
                op: ops
                    .get(&rec.op_id)
                    .map(|o| o.kind.clone())
                    .unwrap_or_default(),
                op_id: rec.op_id.clone(),
                text: e.text.clone(),
                ..Default::default()
            });
        }
    }
    let running = ops.get(&latest).filter(|o| o.state == "running").cloned();
    (out, running)
}

pub fn sort_events(es: &mut [SessionEvent]) {
    es.sort_by_key(|e| parse_at(&e.at));
}

/// one read of a session's stream
#[derive(Debug, Clone, Default)]
pub struct EventsPage {
    pub events: Vec<SessionEvent>,
    pub next: String,
    pub running: Option<LcOp>,
    pub more: bool,
}

/// "<supervisor seq>.<lifecycle record>"
pub fn parse_cursor(s: &str) -> Option<(i64, usize)> {
    let (a, b, ok) = jarvis_go::fmt::cut(s, ".");
    if !ok {
        return None;
    }
    let sup: i64 = a.parse().ok()?;
    let lc: i64 = b.parse().ok()?;
    if sup < 0 || lc < 0 {
        return None;
    }
    Some((sup, lc as usize))
}

impl Router {
    /// every record of a session's lifecycle file, in file order
    pub fn lc_records(&self, session: &str) -> Vec<LcRec> {
        // a bad line stays a record (an empty one): the record numbers stay the log's
        self.lc_lines(session)
            .iter()
            .map(|raw| jarvis_go::unmarshal(raw).unwrap_or_default())
            .collect()
    }

    /// the session's stream. tail (no cursor): the newest limit events. Otherwise what came after the cursor
    /// (supervisor lines: at most limit, oldest first, so the cursor walks through a long backlog).
    pub fn session_events(
        &self,
        session: &str,
        tail: bool,
        after_sup: i64,
        after_lc: usize,
        limit: usize,
    ) -> EventsPage {
        let recs = self.lc_records(session);
        let (mut out, running) = lc_events(&recs, if tail { 0 } else { after_lc });
        let mut next_sup = if tail { 0 } else { after_sup };
        let mut more = false;
        let mut taken = 0;
        for l in self.read_sup_log(session) {
            if l.seq <= after_sup && !tail {
                continue;
            }
            if !tail && taken >= limit {
                more = true;
                break;
            }
            next_sup = l.seq;
            taken += 1;
            out.push(SessionEvent {
                key: format!("s{}", l.seq),
                at: l.at,
                source: "supervisor".into(),
                machine: l.machine,
                text: l.text,
                ..Default::default()
            });
        }
        sort_events(&mut out);
        if tail && out.len() > limit {
            out.drain(..out.len() - limit);
            more = true;
        }
        EventsPage {
            events: out,
            next: format!("{next_sup}.{}", recs.len()),
            running,
            more,
        }
    }
}

pub fn register_session_events(reg: &mut Registrar) {
    reg.app("GET /api/sessions/{id}/events", |r, w, req| {
        let id = req.path_value("id");
        let Some(machine) = r.st.do_(|d| d.sessions.get(&id).map(|s| s.machine_id.clone())) else {
            return write_error(w, 404, &format!("no session {id}"));
        };
        let limit = req.query("limit").parse::<i64>().unwrap_or(0);
        let limit = if limit <= 0 || limit as usize > EVENTS_READ_MAX { EVENTS_READ_MAX } else { limit as usize };
        let (mut tail, mut after_sup, mut after_lc) = (true, 0, 0);
        let c = req.query("after");
        if !c.is_empty() {
            match parse_cursor(&c) {
                None => return write_error(w, 400, r#"after: a cursor from a previous answer ("<seq>.<record>")"#),
                Some((s, l)) => (after_sup, after_lc) = (s, l),
            }
            tail = false;
        }
        let p = r.session_events(&id, tail, after_sup, after_lc, limit);
        let run = p.running.map_or(Value::Null, |o| json!({"id": o.id, "kind": o.kind, "started": o.started}));
        write_json(w, 200, &json!({"events": p.events, "next": p.next, "running": run, "more": p.more, "machine": machine}));
    });
}
