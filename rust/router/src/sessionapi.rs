//! The session-facing API (Jarvis 1's `$JARVIS_URL/api/...` as its session scripts call it). In a Jarvis 4 session
//! JARVIS_URL points at the machine's local proxy (the supervisor, rust/machine/src/apiproxy.rs), which signs each
//! request with the machine key and sends it here as /m/api/<rest>. Any session id in the path must be the calling
//! machine's own session.
//!
//! Served by the router: wakeups and crons (schedule.rs), watches (watches.rs), notify-idle (autopilot.rs's switch),
//! and the session retiring itself. The iCloud index (searchsvc.rs). Device leases: leases.rs; content stores:
//! content.rs. The shared Claude login: claudelogin.rs. Nothing is forwarded to Jarvis 1. The secrets and changes calls
//! never reach the router: the machine answers them itself (it holds its secrets and its repos).

use crate::flows::NewSession;
use crate::http::{Registrar, write_err};
use crate::inbox::{ApiCall, Caller, Origin};
use crate::nethttp::{Req, W, write_json};
use crate::router::{BadReq, Router};
use crate::schedule::{Conflict, NO_SCHEDULE};
use crate::state::Session;
use crate::vouch::{SignedRequest, signed_request_of};
use anyhow::{Result, anyhow};
use jarvis_go::GoTime;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::sync::Arc;

/// new sessions one session may have waiting for Deyao's approval at a time
pub const MAX_PROPOSED_SESSIONS: usize = 3;

/// the machine-side proxy's address (rust/machine/src/apiproxy.rs) and placeholders for the Access/session-token
/// variables Jarvis 1's scripts insist on before calling; the proxy ignores them (a store's real values override
/// these). Not for the harnesses that publish their own web UI: they take CF_ACCESS_* as "publish the web UI through
/// the cf-tunnel" and would loop on a placeholder.
pub const MACHINE_API_URL: &str = "http://127.0.0.1:7171";

/// no such session (404)
#[derive(Debug)]
pub struct NoSession;

impl std::fmt::Display for NoSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("no such session")
    }
}

impl std::error::Error for NoSession {}

pub fn no_session() -> anyhow::Error {
    NoSession.into()
}

pub fn is_no_session(e: &anyhow::Error) -> bool {
    e.downcast_ref::<NoSession>().is_some()
}

/// "" → "?" for a state in a message
pub fn or_state(s: &str) -> &str {
    if s.is_empty() { "gone" } else { s }
}

/// the env hook: the session API's address, its placeholders, and the tunnel's id
pub fn sessionapi_env(_: &Arc<Router>, s: &Session, e: &mut BTreeMap<String, String>) {
    session_api_env(e, &s.harness);
    // cf-tunnel/agent.js would otherwise name the tunnel after Claude's own conversation id, which the Worker refuses
    // for Jarvis 4 (only s+16 hex, with this session's proof)
    e.insert("TUNNEL_ID".into(), s.id.clone());
}

pub fn session_api_env(e: &mut BTreeMap<String, String>, harness: &str) {
    e.insert("JARVIS_URL".into(), MACHINE_API_URL.into());
    e.insert("SESSION_API_TOKEN".into(), "jarvis2-local-proxy".into());
    if !crate::peer::harness_send(harness) {
        e.insert("CF_ACCESS_CLIENT_ID".into(), "jarvis2-local-proxy".into());
        e.insert(
            "CF_ACCESS_CLIENT_SECRET".into(),
            "jarvis2-local-proxy".into(),
        );
    }
}

/// an error the schedule routes answer with its status
pub fn schedule_err(w: &mut W, err: &anyhow::Error) {
    let msg = format!("{err:#}");
    if let Some(b) = err.downcast_ref::<BadReq>() {
        return write_json(w, 400, &json!({"error": b.0}));
    }
    if is_no_session(err) || msg == NO_SCHEDULE {
        return write_json(w, 404, &json!({"error": msg}));
    }
    if err.downcast_ref::<Conflict>().is_some() || msg.starts_with("session is ") {
        return write_json(w, 409, &json!({"error": msg}));
    }
    write_err(w, err);
}

/// the JSON body as a map ("" is an empty one)
pub fn decode_map(b: &[u8]) -> Result<Map<String, Value>> {
    crate::schedule::json_map(b)
}

/// arming from the app. Nothing would vouch for its delivery into the session (only the session's own signed request
/// does, rust/machine/src/deliver.rs), so a wakeup or cron armed here could never fire: it was accepted and then failed
/// at every firing. Refused upfront instead, saying what works (like watches.rs).
fn app_arm_refused(w: &mut W, kind: &str, script: &str) {
    write_json(
        w,
        400,
        &json!({"error": format!("a {kind} is armed by the session itself ({script}): only its own signed request can be delivered into it. Ask the session to arm it (message it in its chat)")}),
    );
}

/// a proposed new session (POST /m/api/sessions, /actions/sessions, a batch's new-session item)
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct ProposalIn {
    #[serde(flatten)]
    pub ns: NewSession,
    pub explanation: String,
}

impl Router {
    /// the session a machine currently runs (a paused or replaced machine has none)
    pub fn machine_session(&self, machine: &str) -> Result<String> {
        let sid = self.st.do_(|d| {
            d.machines
                .get(machine)
                .and_then(|sid| d.sessions.get(sid))
                .filter(|s| s.machine_id == machine)
                .map(|s| s.id.clone())
                .unwrap_or_default()
        });
        if sid.is_empty() {
            return Err(anyhow!("this machine isn't a running session"));
        }
        Ok(sid)
    }

    /// GET …/wakeup → {wakeup (the soonest, or null), wakeups}; GET …/wakeups → {wakeups}
    fn get_wakeups(&self, w: &mut W, sid: &str, single: bool) {
        let ws = match self.list_wakeups(sid) {
            Err(e) => return schedule_err(w, &e),
            Ok(ws) => ws,
        };
        let views: Vec<Value> = ws.iter().map(crate::schedule::wakeup_view).collect();
        if !single {
            return write_json(w, 200, &json!({"wakeups": views}));
        }
        let first = views.first().cloned().unwrap_or(Value::Null);
        write_json(w, 200, &json!({"wakeup": first, "wakeups": views}));
    }

    fn post_wakeup(&self, w: &mut W, sid: &str, body: &[u8], signed: SignedRequest) {
        let res = decode_map(body)
            .and_then(|b| crate::schedule::normalize_wakeup(&b, GoTime::now()))
            .and_then(|mut wu| {
                wu.signed = Some(signed);
                self.arm_wakeup(sid, wu.clone()).map(|()| wu)
            });
        match res {
            Err(e) => schedule_err(w, &e),
            Ok(wu) => write_json(
                w,
                200,
                &json!({"ok": true, "wakeup": crate::schedule::wakeup_view(&wu)}),
            ),
        }
    }

    fn delete_wakeups(&self, w: &mut W, sid: &str, name: &str, all: bool) {
        let mut names = vec![];
        if !all {
            match crate::schedule::wakeup_name(Some(&json!(name))) {
                Err(e) => return schedule_err(w, &e),
                Ok(n) => names.push(n),
            }
        }
        match self.cancel_wakeups(sid, &names, all) {
            Err(e) => schedule_err(w, &e),
            Ok(out) => write_json(w, 200, &json!({"ok": true, "cancelled": out})),
        }
    }

    /// {"nextAt": RFC 3339} or {"nextAt": null} (none armed)
    pub fn put_chat_schedule(&self, w: &mut W, req: &mut Req) {
        let b = req.read_body(4096);
        let Ok(v) = serde_json::from_slice::<Map<String, Value>>(&b) else {
            return write_json(
                w,
                400,
                &json!({"error": "body: {\"nextAt\": RFC 3339 or null}"}),
            );
        };
        let at = match v.get("nextAt") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) => match GoTime::parse(s) {
                Some(t) => Some(t),
                None => {
                    return write_json(w, 400, &json!({"error": "nextAt is not an RFC 3339 time"}));
                }
            },
            Some(_) => {
                return write_json(
                    w,
                    400,
                    &json!({"error": "body: {\"nextAt\": RFC 3339 or null}"}),
                );
            }
        };
        match self.set_chat_schedule(&req.path_value("id"), at, GoTime::now()) {
            Err(e) => schedule_err(w, &e),
            Ok(()) => write_json(w, 200, &json!({"ok": true})),
        }
    }

    fn get_crons(&self, w: &mut W, sid: &str) {
        match self.list_crons(sid) {
            Err(e) => schedule_err(w, &e),
            Ok(cs) => {
                let views: Vec<Value> = cs.iter().map(crate::schedule::cron_view).collect();
                write_json(w, 200, &json!({"crons": views}));
            }
        }
    }

    fn post_cron(&self, w: &mut W, sid: &str, body: &[u8], signed: SignedRequest) {
        let res = decode_map(body)
            .and_then(|b| crate::schedule::normalize_cron(&b, GoTime::now()))
            .and_then(|mut c| {
                c.signed = Some(signed);
                self.arm_cron(sid, c.clone()).map(|()| c)
            });
        match res {
            Err(e) => schedule_err(w, &e),
            Ok(c) => write_json(
                w,
                200,
                &json!({"ok": true, "cron": crate::schedule::cron_view(&c)}),
            ),
        }
    }

    /// 202 once the delivery has started in the background (its failure is DMed and marked missed)
    fn post_run_now(self: &Arc<Self>, w: &mut W, sid: &str, kind: &str, name: &str) {
        if !regex::Regex::new(r"^[A-Za-z0-9_-]{1,40}$").is_ok_and(|re| re.is_match(name)) {
            return write_json(w, 400, &json!({"error": "bad name"}));
        }
        match self.run_now(sid, kind, name) {
            Err(e) => schedule_err(w, &e),
            Ok(()) => write_json(w, 202, &json!({"ok": true, "started": true})),
        }
    }

    fn delete_cron(&self, w: &mut W, sid: &str, name: &str) {
        if !regex::Regex::new(r"^[A-Za-z0-9_-]{1,40}$").is_ok_and(|re| re.is_match(name)) {
            return write_json(w, 400, &json!({"error": "bad cron name"}));
        }
        match self.cancel_cron(sid, name) {
            Err(e) => schedule_err(w, &e),
            Ok(()) => write_json(w, 200, &json!({"ok": true})),
        }
    }

    /// scripts/session-notify-idle.sh — the same switch as the app's (autopilot.rs Liveness)
    fn post_notify_idle(&self, w: &mut W, sid: &str, body: &[u8]) {
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct In {
            enabled: Option<bool>,
        }
        let on = jarvis_go::unmarshal::<In>(body)
            .unwrap_or_default()
            .enabled
            .unwrap_or(true);
        let found = self.st.do_(|d| {
            let Some(s) = d.sessions.get_mut(sid) else {
                return false;
            };
            s.live.get_or_insert_with(Default::default).notify_idle_off = !on;
            true
        });
        if !found {
            return schedule_err(w, &no_session());
        }
        write_json(
            w,
            200,
            &json!({"ok": true, "notifyIdle": crate::autopilot::on_off(!on)}),
        );
    }

    /// a caller that isn't Deyao (a session, the actions key) proposes a new session — the same line as the app's New
    /// session, so nothing starts until Deyao approves the core's succession from null with Face ID; the approval names
    /// the caller and carries its reason. Attachments only from a session, its own uploads (uploads.rs). prefix keeps
    /// the caller's request ids apart from the app's and every other caller's.
    pub fn propose_session(
        self: &Arc<Self>,
        w: &mut W,
        c: Caller,
        prefix: &str,
        b: &[u8],
        signed: Option<SignedRequest>,
    ) {
        let pin = match jarvis_go::unmarshal::<ProposalIn>(b) {
            Err(e) => return write_json(w, 400, &json!({"error": format!("bad JSON: {e}")})),
            Ok(p) => p,
        };
        let mut ns = match self.check_proposal(&c, prefix, pin, true) {
            Err(e) => return crate::inbox::write_request_err(w, &e),
            Ok(ns) => ns,
        };
        if let Some(o) = ns.origin.as_mut() {
            o.signed = signed;
        }
        let waiting = self.st.do_(|d| crate::batches::caller_load(d, &c).1);
        if waiting >= MAX_PROPOSED_SESSIONS {
            return write_json(
                w,
                429,
                &json!({"error": format!("{waiting} proposed sessions already wait for Deyao: wait for his answer, or deny one (jarvis4-actions.py deny ID), then propose again")}),
            );
        }
        let rid = ns.request_id.clone();
        match self.create_session(ns) {
            Err(e) => schedule_err(w, &e),
            Ok(id) => write_json(
                w,
                200,
                &json!({"id": id, "requestId": rid.strip_prefix(&format!("{prefix}:")).unwrap_or(&rid), "approval": true}),
            ),
        }
    }

    /// the proposal checked and made into the NewSession create_session takes (the caller and its call recorded);
    /// explanation required unless the batch's summary stands for it
    pub fn check_proposal(
        &self,
        c: &Caller,
        prefix: &str,
        pin: ProposalIn,
        expl_required: bool,
    ) -> Result<NewSession> {
        let expl = crate::inbox::clean_explanation(&pin.explanation, expl_required)
            .map_err(|e| BadReq(format!("{e:#}")))?;
        let mut ns = pin.ns;
        if ns.prompt.trim().is_empty() {
            return Err(BadReq("prompt is required".into()).into());
        }
        if ns.request_id.is_empty() {
            ns.request_id = crate::util::rand_id();
        }
        ns.request_id = format!("{prefix}:{}", ns.request_id);
        let mut attached = vec![];
        if let Some(att) = ns.attachments.clone() {
            if c.kind != "session" {
                return Err(BadReq(
                    "attachments come only with a session's own proposal (jarvis-request new-session --attach FILE)".into(),
                )
                .into());
            }
            let rid = ns.request_id.clone();
            let files = self
                .st
                .do_(|d| {
                    // a repeat of a proposal already made: its own upload
                    let sid = d
                        .sessions
                        .values()
                        .filter(|x| x.request_id == rid)
                        .map(|x| x.id.clone())
                        .next_back()
                        .unwrap_or_default();
                    crate::uploads::check_upload(d, &sid, &c.session, &att).map(|(f, _)| f)
                })
                .map_err(|e| BadReq(format!("{e:#}")))?;
            attached = files.into_iter().map(|f| f.name).collect::<Vec<_>>();
            ns.attach_owner = c.session.clone();
        }
        let chars = ns.prompt.chars().count();
        let mut args = Map::new();
        args.insert("label".into(), json!(ns.label));
        args.insert("harness".into(), json!(ns.harness));
        args.insert("stores".into(), json!(ns.stores));
        args.insert("model".into(), json!(ns.model));
        args.insert("permissionMode".into(), json!(ns.permission_mode));
        args.insert("size".into(), json!(ns.size));
        args.insert("prompt".into(), json!(format!("({chars} characters)")));
        if !ns.region.is_empty() {
            args.insert("region".into(), json!(ns.region));
        }
        if !ns.content.is_empty() {
            args.insert("content".into(), json!(ns.content));
        }
        if !ns.repos.is_empty() {
            args.insert("repos".into(), json!(ns.repos));
        }
        if !attached.is_empty() {
            args.insert("attachments".into(), json!(attached));
        }
        ns.origin = Some(Origin {
            caller: c.clone(),
            call: ApiCall {
                method: "POST".into(),
                path: "/api/sessions".into(),
                args,
            },
            ..Default::default()
        });
        ns.explanation = expl;
        Ok(ns)
    }
}

/// a machine route on its own session (the path's id, when there is one, must be its session)
fn own(
    reg: &mut Registrar,
    pattern: &str,
    f: impl Fn(&Arc<Router>, &mut W, &mut Req, &str, &[u8]) + Send + Sync + 'static,
) {
    reg.m(pattern, move |r, w, req, machine, body| {
        let sid = match r.machine_session(machine) {
            Err(e) => return write_json(w, 403, &json!({"error": format!("{e:#}")})),
            Ok(s) => s,
        };
        let id = req.path_value("id");
        if !id.is_empty() && id != sid {
            return write_json(
                w,
                403,
                &json!({"error": format!("this machine is session {sid}, not {id}: these routes act on the calling session only; to act on another session use its actions (scripts/jarvis4-actions.py, /m/api/actions/sessions/{id}/…) or message it")}),
            );
        }
        f(r, w, req, &sid, body)
    });
}

fn signed_of(req: &Req, b: &[u8]) -> SignedRequest {
    signed_request_of(req, &req.header("X-Machine"), b)
}

pub fn register_session_api(reg: &mut Registrar) {
    // ---- the app (Deyao) -----------------------------------------------------------------------------------
    reg.app("GET /api/sessions/{id}/wakeup", |r, w, req| {
        r.get_wakeups(w, &req.path_value("id"), true)
    });
    reg.app("GET /api/sessions/{id}/wakeups", |r, w, req| {
        r.get_wakeups(w, &req.path_value("id"), false)
    });
    for p in [
        "POST /api/sessions/{id}/wakeup",
        "POST /api/sessions/{id}/wakeups",
    ] {
        reg.app(p, |_, w, _| app_arm_refused(w, "wakeup", "schedule-wakeup"));
    }
    reg.app("DELETE /api/sessions/{id}/wakeup", |r, w, req| {
        r.delete_wakeups(
            w,
            &req.path_value("id"),
            &req.query("name"),
            req.query("all") == "1",
        )
    });
    reg.app("DELETE /api/sessions/{id}/wakeups/{name}", |r, w, req| {
        r.delete_wakeups(w, &req.path_value("id"), &req.path_value("name"), false)
    });
    // Run now (Deyao, 2026-11-17): deliver it at once as its scheduled firing would, counted as that firing
    reg.app("POST /api/sessions/{id}/wakeups/{name}/run", |r, w, req| {
        r.post_run_now(w, &req.path_value("id"), "w", &req.path_value("name"))
    });
    reg.app("POST /api/sessions/{id}/crons/{name}/run", |r, w, req| {
        r.post_run_now(w, &req.path_value("id"), "c", &req.path_value("name"))
    });
    reg.app("GET /api/sessions/{id}/crons", |r, w, req| {
        r.get_crons(w, &req.path_value("id"))
    });
    reg.app("POST /api/sessions/{id}/crons", |_, w, _| {
        app_arm_refused(w, "cron", "schedule-cron")
    });
    reg.app("DELETE /api/sessions/{id}/crons/{name}", |r, w, req| {
        r.delete_cron(w, &req.path_value("id"), &req.path_value("name"))
    });

    crate::searchsvc::register_search_services(reg); // the iCloud index (searchsvc.rs)

    // ---- the session itself (through its machine's local proxy) ---------------------------------------------
    own(reg, "GET /m/api/sessions/{id}/wakeup", |r, w, _, sid, _| {
        r.get_wakeups(w, sid, true)
    });
    own(
        reg,
        "GET /m/api/sessions/{id}/wakeups",
        |r, w, _, sid, _| r.get_wakeups(w, sid, false),
    );
    // the session's own request, kept exactly as its machine signed it: what vouches for the delivery (vouch.rs)
    own(
        reg,
        "POST /m/api/sessions/{id}/wakeup",
        |r, w, req, sid, b| r.post_wakeup(w, sid, b, signed_of(req, b)),
    );
    own(
        reg,
        "POST /m/api/sessions/{id}/wakeups",
        |r, w, req, sid, b| r.post_wakeup(w, sid, b, signed_of(req, b)),
    );
    own(
        reg,
        "DELETE /m/api/sessions/{id}/wakeup",
        |r, w, req, sid, _| r.delete_wakeups(w, sid, &req.query("name"), req.query("all") == "1"),
    );
    own(
        reg,
        "DELETE /m/api/sessions/{id}/wakeups/{name}",
        |r, w, req, sid, _| r.delete_wakeups(w, sid, &req.path_value("name"), false),
    );
    own(reg, "GET /m/api/sessions/{id}/crons", |r, w, _, sid, _| {
        r.get_crons(w, sid)
    });
    own(
        reg,
        "POST /m/api/sessions/{id}/crons",
        |r, w, req, sid, b| r.post_cron(w, sid, b, signed_of(req, b)),
    );
    own(
        reg,
        "DELETE /m/api/sessions/{id}/crons/{name}",
        |r, w, req, sid, _| r.delete_cron(w, sid, &req.path_value("name")),
    );
    own(
        reg,
        "POST /m/api/sessions/{id}/notify-idle",
        |r, w, _, sid, b| r.post_notify_idle(w, sid, b),
    );
    // retire-session: the session destroys itself, unless it still has a wakeup or cron to wait for
    own(reg, "DELETE /m/api/sessions/{id}", |r, w, _, sid, _| {
        let p = r.pending_schedule(sid);
        if !p.is_empty() {
            return write_json(
                w,
                409,
                &json!({"error": format!("the session still has pending {} — cancel them first, or let them fire", p.join(", ")), "pending": p}),
            );
        }
        match r.destroy(sid) {
            Err(e) => write_err(w, &e),
            Ok(()) => write_json(w, 202, &json!({"started": true, "phase": "destroying"})),
        }
    });
    // a session proposes a new session (Deyao, 2026-10-12: "launch a new session through jarvis 2"): the same line as
    // the app's New session, so nothing starts until Deyao approves the core's succession from null with Face ID; the
    // approval names the proposing session and carries its reason. Attachments: files this session staged
    // (PUT /m/api/sessions/{id}/uploads/…, uploads.rs), signed by hash with the line as the app's are.
    own(reg, "POST /m/api/sessions", |r, w, req, sid, b| {
        let signed = signed_of(req, b);
        r.propose_session(
            w,
            Caller {
                kind: "session".into(),
                session: sid.into(),
            },
            sid,
            b,
            Some(signed),
        )
    });
    own(reg, "/m/api/", |_, w, req, _, _| {
        write_json(
            w,
            404,
            &json!({"error": format!("Jarvis 4 doesn't serve {} {}", req.method, req.path.strip_prefix("/m").unwrap_or(&req.path))}),
        );
    });
}

/// CRLF → LF, trimmed, at most RESUME_PROMPT_MAX characters (multi-line kept)
pub fn clean_resume_prompt(p: &str) -> Result<String> {
    let p = p
        .replace("\r\n", "\n")
        .replace('\r', "\n")
        .trim()
        .to_string();
    if p.chars().count() > crate::schedule::RESUME_PROMPT_MAX {
        return Err(anyhow!(
            "prompt longer than {} characters",
            crate::schedule::RESUME_PROMPT_MAX
        ));
    }
    Ok(p)
}
