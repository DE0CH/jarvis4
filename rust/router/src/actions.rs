//! The actions (Deyao, 2026-10-13): what a session may do to Jarvis 4 beyond its own business — list sessions and the
//! Inbox, resume a paused session with no prompt (same image), pause one, move a running one to the next size,
//! destroy one, deny a request or approval, and file requests (a new session, an added store, a repo, a grant, an
//! unlock, or any app API call: apicalls.rs), which only wait in Deyao's Inbox.
//!
//! Each session's key is its own machine key, so every action is recorded as that session's actions
//! (Caller{kind: "actions", session}), shown in the Inbox and logged. The key works only while the session runs.

use crate::http::{Registrar, write_err};
use crate::inbox::{ApiCall, Caller, Origin};
use crate::nethttp::{Req, W, write_json};
use crate::router::Router;
use anyhow::{Result, anyhow};
use serde_json::{Value, json};
use std::sync::Arc;

impl Router {
    /// the running session whose machine signed this call
    pub fn actions_session(&self, machine: &str) -> Result<String> {
        let sid = self.st.do_(|d| {
            d.machines
                .get(machine)
                .and_then(|sid| d.sessions.get(sid))
                .filter(|s| {
                    s.machine_id == machine && (s.state == "started" || s.state == "initialising")
                })
                .map(|s| s.id.clone())
                .unwrap_or_default()
        });
        if sid.is_empty() {
            return Err(anyhow!(
                "this machine isn't a running session: its actions end when it pauses or is destroyed"
            ));
        }
        Ok(sid)
    }
}

fn act(
    reg: &mut Registrar,
    pattern: &str,
    f: impl Fn(&Arc<Router>, &mut W, &mut Req, Caller, &[u8]) + Send + Sync + 'static,
) {
    reg.m(pattern, move |r, w, req, machine, b| {
        let sid = match r.actions_session(machine) {
            Ok(s) => s,
            Err(e) => {
                crate::nethttp::write_error(w, 403, &format!("{e:#}"));
                return;
            }
        };
        if req.method != "GET" {
            crate::logf!("actions: session {sid}: {} {}", req.method, req.path);
        }
        f(
            r,
            w,
            req,
            Caller {
                kind: "actions".into(),
                session: sid,
            },
            b,
        )
    });
}

/// the path as the caller called it (without the machine listener's /m prefix), for the Inbox's "Call" row
fn path(req: &Req) -> String {
    req.path.strip_prefix("/m").unwrap_or(&req.path).to_string()
}

pub fn register_actions(reg: &mut Registrar) {
    act(reg, "GET /m/api/actions/sessions", |r, w, _, _, _| {
        let out: Vec<Value> = r.st.do_(|d| {
            d.sessions
                .values()
                .map(|s| {
                    let mut v = json!({"id": s.id, "machineId": s.machine_id, "state": s.state,
                        "title": crate::titles::session_title(s), "error": s.error, "image": s.image});
                    if let Some(l) = &s.live {
                        if let Some(reg) = &l.reg {
                            v["status"] = json!(reg.status);
                        }
                        if !l.needs_grant.is_empty() {
                            v["needsGrant"] = json!(l.needs_grant);
                        }
                    }
                    v
                })
                .collect()
        });
        write_json(w, 200, &json!({"sessions": out}));
    });
    act(reg, "GET /m/api/actions/requests", |r, w, _, _, _| {
        write_json(
            w,
            200,
            &json!({"requests": r.inbox(), "batches": r.inbox_batches(None)}),
        );
    });
    // resume: same image, no prompt, no option changes, so the core answers approve_by_dead_machine and nothing
    // reaches the phone (a line whose permission mode differs from its cert still gets its approval in the Inbox)
    act(
        reg,
        "POST /m/api/actions/sessions/{id}/resume",
        |r, w, req, c, _| {
            let id = req.path_value("id");
            r.note_origin(
                &id,
                Origin {
                    caller: c,
                    call: ApiCall {
                        method: "POST".into(),
                        path: path(req),
                        args: json!({"upgrade": false})
                            .as_object()
                            .cloned()
                            .unwrap_or_default(),
                    },
                    ..Default::default()
                },
            );
            match r.resume(&id, false) {
                Err(e) => write_err(w, &e),
                Ok(()) => write_json(w, 200, &json!({"ok": true})),
            }
        },
    );
    act(
        reg,
        "POST /m/api/actions/sessions/{id}/pause",
        |r, w, req, _, _| match r.pause(&req.path_value("id")) {
            Err(e) => write_err(w, &e),
            Ok(()) => write_json(w, 200, &json!({"ok": true})),
        },
    );
    // upgrade: the next size up, as the app's Upgrade (memory.rs): frees, snapshots, resumes on the bigger machine
    act(
        reg,
        "POST /m/api/actions/sessions/{id}/upgrade",
        |r, w, req, _, _| match r.upgrade(&req.path_value("id")) {
            Err(e) => write_err(w, &e),
            Ok(out) => write_json(w, 202, &out),
        },
    );
    // destroy (Deyao, 2026-10-13): exactly the app's Destroy, ?force=1 included
    act(
        reg,
        "POST /m/api/actions/sessions/{id}/destroy",
        |r, w, req, _, _| match r.destroy_with(&req.path_value("id"), req.query("force") == "1") {
            Err(e) => write_err(w, &e),
            Ok(()) => write_json(w, 200, &json!({"ok": true})),
        },
    );
    // deny: an Inbox request leaves; an approval is rejected as Deny in the app would
    act(
        reg,
        "POST /m/api/actions/requests/{id}/deny",
        |r, w, req, _, _| {
            crate::inbox::write_denied(w, r.deny_request(&req.path_value("id")));
        },
    );
    act(reg, "POST /m/api/actions/sessions", |r, w, req, c, b| {
        let signed = Some(crate::vouch::signed_request_of(
            req,
            &req.header("X-Machine"),
            b,
        ));
        let owner = format!("actions-{}", c.session);
        r.propose_session(w, c, &owner, b, signed);
    });
    act(
        reg,
        "POST /m/api/actions/requests/batch",
        |r, w, req, c, b| {
            let signed = Some(crate::vouch::signed_request_of(
                req,
                &req.header("X-Machine"),
                b,
            ));
            r.serve_file_batch(w, c, &req.method, &path(req), b, signed);
        },
    );
    act(
        reg,
        "POST /m/api/actions/requests/batches/{id}/deny",
        |r, w, req, _, _| {
            r.serve_deny_batch(w, &req.path_value("id"));
        },
    );
    for intent in crate::inbox::INTENTS {
        let it = intent.to_string();
        act(
            reg,
            &format!("POST /m/api/actions/requests/{intent}"),
            move |r, w, req, c, b| {
                let signed = Some(crate::vouch::signed_request_of(
                    req,
                    &req.header("X-Machine"),
                    b,
                ));
                r.file_intent(w, &req.method, &path(req), &it, c, b, signed);
            },
        );
    }
    // any app API call (apicalls.rs): filed for Deyao's approval; its result read back by the same session
    act(
        reg,
        "POST /m/api/actions/requests/call",
        |r, w, req, c, b| {
            let signed = Some(crate::vouch::signed_request_of(
                req,
                &req.header("X-Machine"),
                b,
            ));
            r.file_call(w, c, &path(req), b, signed);
        },
    );
    act(
        reg,
        "GET /m/api/actions/requests/call/{id}",
        |r, w, req, c, _| {
            r.serve_call_result(w, c, &req.path_value("id"));
        },
    );
}
