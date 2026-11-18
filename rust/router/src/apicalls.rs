//! API-call requests (Deyao, 2026-10-13): a session's actions (actions.rs) may ask for ANY app API call — one of the
//! routes only Deyao's Access login reaches — to be run as Deyao. The request waits in the Inbox (kind "api-call")
//! with its method, path and body; Deyao approves it from the app or the web page. The router then runs the call
//! through its own public mux carrying the approver's own Access login (so the route's require_deyao checks Deyao
//! himself), and keeps the outcome for INBOX_TTL; the requesting session reads it back.
//!
//! CALL_RULES classifies every app route (a test fails on a new route left out):
//!   Body    the call may be requested and its status and response body go back to the session
//!   Status  may be requested, but the response carries a credential, so only the status goes back
//!   No      never requestable: the Inbox itself, or a call that can't be run server-side or would hand out Deyao's
//!           own login

use crate::inbox::{ApiCall, Caller, InboxItem, InboxRequest, Origin, RequestParams, SignedRequest};
use crate::nethttp::{Req, W, write_json};
use crate::router::Router;
use crate::state::{Approval, Persisted};
use anyhow::{Result, anyhow};
use jarvis_go::GoTime;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::sync::Arc;

pub const REQUEST_KIND_CALL: &str = "api-call";
/// a requested call's body, kept in the Inbox
pub const CALL_BODY_MAX: usize = 64 << 10;
/// a call's response kept for the session
pub const CALL_RESULT_MAX: usize = 1 << 20;
/// how long an approved call's sheet waits for a request the call's work may still file
pub const FOLLOWUP_WAIT_SECS: i64 = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallRule {
    No,
    Body,
    Status,
}

fn is_false(b: &bool) -> bool {
    !*b
}

fn is_zero(n: &i64) -> bool {
    *n == 0
}

/// what an approved (or denied) API-call request came to, kept INBOX_TTL for its caller
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct CallResult {
    pub id: String,
    pub caller: Caller,
    pub method: String,
    pub path: String,
    /// running | done | denied | failed
    pub state: String,
    #[serde(skip_serializing_if = "is_zero")]
    pub status: i64,
    #[serde(rename = "contentType", skip_serializing_if = "String::is_empty")]
    pub content_type: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub body: String,
    /// Status rule: the body carried a credential
    #[serde(skip_serializing_if = "is_false")]
    pub withheld: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub error: String,
    /// app | web
    #[serde(rename = "approvedBy", skip_serializing_if = "String::is_empty")]
    pub approved_by: String,
    pub at: GoTime,
    /// the core requests the call brought about, and, while one may still come, what the router waits on
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub followups: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub awaiting: Option<CallAwait>,
}

/// an approved call started work that may still file a core request: the sheet waits for it until `until`
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct CallAwait {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub session: String,
    pub until: GoTime,
}

/// what POST /m/api/actions/requests/call takes. body is any JSON value (sent as application/json); bodyText a raw
/// body with its contentType instead.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct CallIn {
    pub method: String,
    pub path: String,
    pub body: Option<Box<serde_json::value::RawValue>>,
    #[serde(rename = "bodyText")]
    pub body_text: String,
    #[serde(rename = "contentType")]
    pub content_type: String,
    pub explanation: String,
}

/// what the review sheet of an API call shows after Approve
#[derive(Debug, Clone, Default, Serialize)]
pub struct CallFollowups {
    pub id: String,
    pub state: String,
    #[serde(skip_serializing_if = "is_zero")]
    pub status: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub error: String,
    pub followups: Vec<CallFollowup>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub awaiting: Option<CallAwait>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct CallFollowup {
    pub id: String,
    /// still in the Inbox
    pub open: bool,
    /// while open: the item, opened like any other (its signed page)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub item: Option<InboxItem>,
}

/// the request is gone
pub fn no_request() -> anyhow::Error {
    anyhow!("this request is gone (answered, denied or expired)")
}

fn call_no_why(pattern: &str) -> &'static str {
    if pattern.contains("/api/requests") || pattern.contains("/api/approvals") {
        return "the Inbox itself";
    }
    "it would hand out Deyao's own login, or it can't run on the router"
}

/// the request's context values a handler reads: whose approved call the router is running, and the API-call request
/// it runs for
pub const ON_BEHALF_KEY: &str = "onBehalf";
pub const VIA_CALL_KEY: &str = "viaCall";

/// the API-call request a request runs for ("" for Deyao's own calls)
pub fn via_call(req: &Req) -> String {
    req.ctx.get(VIA_CALL_KEY).cloned().unwrap_or_default()
}

/// the session's own two credentials (its requests and its actions, both its machine key) are one caller for reading a
/// call's result
pub fn same_session_caller(a: &Caller, b: &Caller) -> bool {
    let own = |c: &Caller| (c.kind == "session" || c.kind == "actions") && !c.session.is_empty();
    a == b || (own(a) && own(b) && a.session == b.session)
}

/// the requesting session is still there (any state but destroyed)
pub fn caller_exists(d: &Persisted, c: &Caller) -> bool {
    if c.kind != "session" && c.kind != "actions" {
        return true; // the setup session, the app or the web page: no session to end with
    }
    d.sessions.get(&c.session).is_some_and(|s| s.state != "destroyed")
}

/// an approval whose origin is an approved call joins that call's follow-ups (inside do_)
pub fn link_followup(d: &mut Persisted, a: &Approval) {
    let Some(o) = &a.origin else { return };
    if o.via_call.is_empty() {
        return;
    }
    let Some(x) = d.call_results.get_mut(&o.via_call) else { return };
    if !x.followups.contains(&a.id) {
        x.followups.push(a.id.clone());
    }
    x.awaiting = None;
}

pub fn prune_call_results(d: &mut Persisted, now: GoTime) {
    d.call_results
        .retain(|_, x| now.sub(&x.at).whole_seconds() < crate::inbox::INBOX_TTL_SECS);
}

impl Router {
    /// the app route a method + path (with its query) reaches, and its rule
    pub fn call_route(self: &Arc<Self>, method: &str, target: &str) -> Result<(String, CallRule)> {
        if !target.starts_with('/') || target.starts_with("//") {
            return Err(anyhow!(
                "path: an absolute path on the router, e.g. /api/sessions/ID/permission-mode"
            ));
        }
        let path = target.split_once('?').map_or(target, |(p, _)| p);
        let path = percent_encoding::percent_decode_str(path).decode_utf8_lossy().into_owned();
        let (public, _) = self.handlers();
        let pattern = public.pattern_for(method, &path);
        if pattern.is_empty() {
            return Err(anyhow!("no route {method} {path}"));
        }
        let known = CALL_RULES.iter().find(|(p, _)| *p == pattern).map(|(_, r)| *r);
        let is_app = self.app_patterns.get().is_some_and(|a| a.contains_key(&pattern));
        match known {
            Some(rule) if is_app => {
                if rule == CallRule::No {
                    return Err(anyhow!("{pattern} can't be requested ({})", call_no_why(&pattern)));
                }
                Ok((pattern, rule))
            }
            _ => Err(anyhow!("{pattern} is not an app API call")),
        }
    }

    /// a requested call as the Inbox keeps it (method, path, body) and the arguments shown as its call, or why it
    /// can't be requested
    pub fn check_call(self: &Arc<Self>, i: &CallIn) -> Result<(RequestParams, Map<String, Value>)> {
        let method = i.method.trim().to_uppercase();
        if !matches!(method.as_str(), "GET" | "POST" | "PUT" | "PATCH" | "DELETE") {
            return Err(anyhow!("method: GET, POST, PUT, PATCH or DELETE"));
        }
        let mut p = RequestParams {
            method,
            path: i.path.trim().to_string(),
            ..Default::default()
        };
        let json_body = i.body.as_ref().map(|b| b.get()).filter(|b| *b != "null");
        match (json_body, i.body_text.is_empty()) {
            (Some(_), false) => return Err(anyhow!("body (JSON) or bodyText, not both")),
            (Some(b), true) => {
                let v: Value = serde_json::from_str(b).map_err(|e| anyhow!("body: {e}"))?;
                p.body = jarvis_go::marshal(&v);
                p.content_type = "application/json".into();
            }
            (None, false) => {
                p.body = i.body_text.clone();
                p.content_type = if i.content_type.is_empty() { "text/plain".into() } else { i.content_type.clone() };
            }
            (None, true) => {}
        }
        if p.body.len() > CALL_BODY_MAX {
            return Err(anyhow!("body over {} KB", CALL_BODY_MAX >> 10));
        }
        let (pattern, _) = self.call_route(&p.method, &p.path)?;
        let mut args = json!({"method": p.method, "path": p.path, "route": pattern});
        if !p.body.is_empty() {
            args["body"] = json!(p.body);
        }
        Ok((p, args.as_object().cloned().unwrap_or_default()))
    }

    /// an API-call request into the Inbox → {id, duplicate, expires}
    pub fn file_call(self: &Arc<Self>, w: &mut W, c: Caller, path: &str, b: &[u8], signed: Option<SignedRequest>) {
        let i: CallIn = match jarvis_go::unmarshal(b) {
            Ok(i) => i,
            Err(e) => {
                crate::nethttp::write_error(w, 400, &format!("bad JSON: {e}"));
                return;
            }
        };
        let (p, args) = match self.check_call(&i) {
            Ok(x) => x,
            Err(e) => {
                crate::nethttp::write_error(w, 400, &format!("{e:#}"));
                return;
            }
        };
        let o = Origin {
            caller: c,
            call: ApiCall { method: "POST".into(), path: path.into(), args, ..Default::default() },
            signed,
            ..Default::default()
        };
        match self.file_request(REQUEST_KIND_CALL, p, &i.explanation, o) {
            Err(e) => crate::inbox::write_request_err(w, &e),
            Ok((q, dup)) => write_json(w, 200, &json!({"id": q.id, "duplicate": dup, "expires": q.expires})),
        }
    }

    /// Deyao's approval of an API-call request: the call runs now, as him (his Access login from the approving
    /// request), and its outcome is kept for the caller
    pub fn approve_call(self: &Arc<Self>, id: &str, approver: &Req) -> Result<CallResult> {
        let q: Option<InboxRequest> = self.st.do_(|d| {
            crate::inbox::prune_requests(d, GoTime::now());
            match d.inbox.get(id) {
                Some(x) if x.kind == REQUEST_KIND_CALL => d.inbox.remove(id),
                _ => None,
            }
        });
        let q = q.ok_or_else(no_request)?;
        let res = self.approve_call_run(&q, approver);
        // outcomes.rs: the requesting session is told (its result stays readable for INBOX_TTL)
        self.st.do_(|d| {
            let Some(x) = d.call_results.get(&q.id).cloned() else { return };
            let (o, st) = if x.state == "done" {
                (crate::outcomes::OUTCOME_APPROVED, x.status)
            } else {
                (crate::outcomes::OUTCOME_FAILED, 0)
            };
            crate::outcomes::note_outcome(d, Some(&q.origin), &q.kind, &q.id, o, st, None);
        });
        Ok(res)
    }

    fn approve_call_run(self: &Arc<Self>, q: &InboxRequest, approver: &Req) -> CallResult {
        let mut res = CallResult {
            id: q.id.clone(),
            caller: q.origin.caller.clone(),
            method: q.params.method.clone(),
            path: q.params.path.clone(),
            approved_by: crate::inbox::app_caller(approver).kind,
            at: GoTime::now(),
            ..Default::default()
        };
        let (pattern, rule) = match self.call_route(&q.params.method, &q.params.path) {
            Err(e) => {
                res.state = "failed".into();
                res.error = format!("{e:#}");
                self.keep_call_result(res.clone());
                return res;
            }
            Ok(x) => x,
        };
        let mut running = res.clone();
        running.state = "running".into();
        self.keep_call_result(running); // the approvals the call files link to it while it runs (link_followup)
        let mut req = Req::new(&q.params.method, &q.params.path, q.params.body.as_bytes());
        req.ctx.insert(ON_BEHALF_KEY.into(), jarvis_go::marshal(&q.origin.caller));
        req.ctx.insert(VIA_CALL_KEY.into(), q.id.clone());
        for h in ["Cf-Access-Jwt-Assertion", "cf-access-token", "Cf-Access-Authenticated-User-Email"] {
            let v = approver.header(h);
            if !v.is_empty() {
                req = req.with_header(h, &v);
            }
        }
        if !q.params.content_type.is_empty() {
            req = req.with_header("Content-Type", &q.params.content_type);
        }
        let mut rec = W::recorder();
        let (public, _) = self.handlers();
        public.serve(&mut rec, &mut req);
        res.state = "done".into();
        res.status = rec.status() as i64;
        res.content_type = rec
            .headers
            .get("Content-Type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        if rule == CallRule::Status {
            res.withheld = true;
        } else {
            let mut body = rec.recorded.clone().unwrap_or_default();
            if body.len() > CALL_RESULT_MAX {
                body.truncate(CALL_RESULT_MAX);
                res.error = format!("response cut at {} KB", CALL_RESULT_MAX >> 10);
            }
            res.body = String::from_utf8_lossy(&body).into_owned();
        }
        crate::logf!(
            "api-call {}: {} {} ({pattern}) for {}, approved from the {}: {}",
            q.id,
            q.params.method,
            q.params.path,
            q.origin.caller.session,
            res.approved_by,
            res.status
        );
        self.keep_call_result(res.clone());
        res
    }

    /// the handler of an approved call started work that may file a core request for session sid later (a resume):
    /// the call's sheet waits for it. Called BEFORE the work starts.
    pub fn expect_followup(&self, req: &Req, sid: &str) {
        let id = via_call(req);
        if id.is_empty() {
            return;
        }
        self.st.do_(|d| {
            if let Some(x) = d.call_results.get_mut(&id)
                && x.followups.is_empty()
            {
                x.awaiting = Some(CallAwait {
                    session: sid.into(),
                    until: GoTime::now().add(time::Duration::seconds(FOLLOWUP_WAIT_SECS)),
                });
            }
        });
    }

    /// the work on session sid ended; a call waiting on it gets nothing more
    pub fn settle_followups(&self, sid: &str) {
        self.st.do_(|d| {
            for x in d.call_results.values_mut() {
                if x.awaiting.as_ref().is_some_and(|a| a.session == sid) {
                    x.awaiting = None;
                }
            }
        });
    }

    pub fn call_followups_of(&self, id: &str) -> Option<CallFollowups> {
        let x = self.st.do_(|d| {
            let now = GoTime::now();
            prune_call_results(d, now);
            let c = d.call_results.get_mut(id)?;
            if c.awaiting.as_ref().is_some_and(|a| !now.before(&a.until)) {
                c.awaiting = None;
            }
            Some(c.clone())
        })?;
        let mut out = CallFollowups {
            id: x.id,
            state: x.state,
            status: x.status,
            error: x.error,
            followups: vec![],
            awaiting: x.awaiting,
        };
        for fid in x.followups {
            let mut f = CallFollowup { id: fid.clone(), ..Default::default() };
            if let Some(it) = self.inbox_item(&fid) {
                f.open = true;
                f.item = Some(it);
            }
            out.followups.push(f);
        }
        Some(out)
    }

    /// the call's outcome; the follow-ups linked while it ran stay, and a call that failed brings nothing more about
    pub fn keep_call_result(&self, mut res: CallResult) {
        self.st.do_(|d| {
            prune_call_results(d, GoTime::now());
            if let Some(old) = d.call_results.get(&res.id) {
                res.followups = old.followups.clone();
                res.awaiting = old.awaiting.clone();
            }
            if res.state == "failed" || res.status >= 400 {
                res.awaiting = None;
            }
            d.call_results.insert(res.id.clone(), res.clone());
        });
    }

    /// the caller's own request: pending while it waits, then its outcome
    pub fn serve_call_result(&self, w: &mut W, c: Caller, id: &str) {
        let out: Option<Value> = self.st.do_(|d| {
            let now = GoTime::now();
            crate::inbox::prune_requests(d, now);
            prune_call_results(d, now);
            if let Some(q) = d.inbox.get(id)
                && q.kind == REQUEST_KIND_CALL
                && same_session_caller(&q.origin.caller, &c)
            {
                return Some(json!({"id": id, "state": "pending", "expires": q.expires}));
            }
            d.call_results
                .get(id)
                .filter(|x| same_session_caller(&x.caller, &c))
                .map(|x| json!(x))
        });
        match out {
            None => crate::nethttp::write_error(
                w,
                404,
                &format!(
                    "no such request of this session (expired, or its result is over {} old)",
                    jarvis_go::fmt::duration_string(std::time::Duration::from_secs(crate::inbox::INBOX_TTL_SECS as u64))
                ),
            ),
            Some(v) => write_json(w, 200, &v),
        }
    }
}

/// every app route (the 2026-10-13 sweep). A new app route needs its line here (every_app_route_classified).
pub const CALL_RULES: &[(&str, CallRule)] = &[
    ("GET /api/messages", CallRule::No), // the Inbox: messages held for Deyao (messages.go)
    ("POST /api/messages/draft", CallRule::No), // the Inbox
    ("POST /api/messages/approve", CallRule::No), // the Inbox: takes the phone's signature
    ("POST /api/messages/deny", CallRule::No), // the Inbox
    ("GET /api/sessions/{id}/message-rules", CallRule::No), // Deyao's per-kind delivery rules
    ("POST /api/sessions/{id}/message-rules", CallRule::No), // takes a phone-signed rule
    ("POST /api/sessions/{id}/message-rules/draft", CallRule::No),
    ("DELETE /api/message-rules/{rid}", CallRule::No),
    ("GET /api/approvals", CallRule::No), // the Inbox
    ("POST /api/approvals/{id}/reject", CallRule::No), // the Inbox
    ("POST /api/approvals/{id}/respond", CallRule::No), // the Inbox
    ("GET /api/auth/start", CallRule::No), // hands out Deyao's Access login (a jarvis2:// redirect carrying it)
    ("GET /api/backups", CallRule::Status), // every store's sealed backup
    ("POST /api/backups/fallback", CallRule::Body), // an export the app saved, served only while the bucket fails
    ("DELETE /api/backups/fallback", CallRule::Body),
    ("DELETE /api/claude-accounts/{store}", CallRule::Body),
    ("GET /api/claude-accounts", CallRule::Body),
    ("GET /api/claude-accounts/{store}/usage", CallRule::Body),
    ("POST /api/claude-accounts", CallRule::Status), // the OAuth sign-in URL with its state and PKCE challenge
    ("POST /api/claude-accounts/{store}/code", CallRule::Body),
    ("POST /api/claude-accounts/{store}/default", CallRule::Body),
    ("POST /api/claude-accounts/{store}/login", CallRule::Status), // the OAuth sign-in URL with its state and PKCE challenge
    ("POST /api/claude-accounts/{store}/refresh", CallRule::Body),
    ("GET /api/claude-login", CallRule::Body),
    ("POST /api/claude-login/code", CallRule::Body),
    ("POST /api/claude-login/refresh", CallRule::Body),
    ("POST /api/claude-login/start", CallRule::Status), // the OAuth sign-in URL with its state and PKCE challenge
    ("GET /api/content", CallRule::Body),
    ("POST /api/content", CallRule::Body),
    ("DELETE /api/content/{name}", CallRule::Body),
    ("DELETE /api/content/{name}/file", CallRule::Body),
    ("GET /api/content/{name}/file", CallRule::Body),
    ("POST /api/content/{name}/file", CallRule::Body),
    ("GET /api/content/{name}/files", CallRule::Body),
    ("POST /api/core/claim", CallRule::No), // the iPhone app's Recover, signed by the master key
    ("GET /api/core/identity", CallRule::Body),
    ("GET /api/core/line-state", CallRule::Body), // sealed by the core: nothing in it opens outside a core from the same kit
    ("POST /api/core/lock", CallRule::Body),
    ("POST /api/core/store-key", CallRule::Body),
    ("POST /api/core/stores", CallRule::Body),
    ("POST /api/core/stores/create", CallRule::Body),
    ("POST /api/core/stores/mark-sensitive", CallRule::Body),
    ("POST /api/core/stores/restore/begin", CallRule::No), // half of a restore the phone finishes with its signature and shares
    ("POST /api/core/stores/versions", CallRule::Body),
    ("POST /api/core/unlock/begin", CallRule::No), // half of an unlock the phone finishes with its sealed share
    ("POST /api/core/unlock/finish", CallRule::No), // needs the phone's sealed share
    ("POST /api/core/unlocked", CallRule::Body),
    ("POST /api/core/wipe", CallRule::No), // the iPhone app's Reset, signed by the master key
    ("GET /api/devices", CallRule::Body),
    ("GET /api/devices/pair", CallRule::No), // mints a device service token: a login of its own
    ("POST /api/machine-signatures/verify", CallRule::Body), // whose machine signed a request (machinesig.go): a yes/no
    ("DELETE /api/devices/{id}", CallRule::Body),
    ("GET /api/github/repos", CallRule::Body),
    ("DELETE /api/grants/{gid}", CallRule::Body),
    ("GET /api/holders", CallRule::Body),
    ("GET /api/icloud/file", CallRule::Body),
    ("POST /api/icloud/relist", CallRule::Body),
    ("POST /api/icloud/retry", CallRule::Body),
    ("GET /api/icloud/search", CallRule::Body),
    ("GET /api/icloud/status", CallRule::Body),
    ("GET /api/input-log", CallRule::Body),
    ("GET /api/jarvis1/paused", CallRule::Body),
    ("GET /api/jarvis1/paused/{id}", CallRule::Body),
    ("POST /api/jarvis1/paused/{id}/import", CallRule::Body),
    ("POST /api/jarvis1/paused/{id}/prepare", CallRule::Body),
    ("GET /api/leases", CallRule::Body),
    ("GET /api/leases/{name}", CallRule::Body),
    ("POST /api/leases/{name}/force-return", CallRule::Body),
    ("POST /api/leases/{name}/hand-back", CallRule::Body),
    ("POST /api/leases/{name}/take-over", CallRule::Body),
    ("GET /api/machines", CallRule::Body),
    ("POST /api/machines/{id}/destroy", CallRule::Body),
    ("GET /api/runners", CallRule::Body), // runners.go: the Hetzner runners, each with its session
    ("POST /api/runners/{id}/delete", CallRule::Body), // only a runner no session at work owns
    ("GET /api/models", CallRule::Body),
    ("GET /api/policy", CallRule::Body),
    ("GET /api/build", CallRule::Body), // the web page's build (its index.html's hash)
    ("GET /api/kernel", CallRule::Body), // kernelline.go: whether the kernel is here and serves
    ("POST /api/kernel/root-grant", CallRule::No), // the root key's grant, signed on the phone
    ("POST /api/kernel/root-key", CallRule::No), // roster.go: the app's root key (only the app registers it)
    ("GET /api/kernel/roster", CallRule::Body), // roster.go: the current roster and what each component said
    ("GET /api/kernel/roster/pending", CallRule::Body),
    ("POST /api/kernel/roster", CallRule::No), // the root key's roster, signed on the phone
    ("GET /api/kernel/root-grant/draft", CallRule::Body),
    ("GET /api/kernel/line-state", CallRule::Body), // the kernel secrets' sealed line state (a Recover's)
    ("GET /api/kernel/spawner/identity", CallRule::Body),
    ("POST /api/kernel/spawner/fly-token", CallRule::No), // sealed to the spawner by the app's Recover
    ("GET /api/kernel/secrets/{path...}", CallRule::No), // the kernel's secrets, relayed for the app (claim, unlock: the phone's)
    ("POST /api/kernel/secrets/{path...}", CallRule::No),
    ("GET /api/records", CallRule::Body),
    ("DELETE /api/records/{id}", CallRule::Body),
    ("POST /api/records/{id}/restore", CallRule::Body),
    ("GET /api/records/{id}/tail", CallRule::Body),
    ("GET /api/remotes", CallRule::Status), // every session's OpenClaw token / OpenCode pairing URL
    ("POST /api/remotes", CallRule::No), // a session proposes a new session itself (jarvis-request new-session)
    ("GET /api/repos", CallRule::Body),
    ("POST /api/repos/key/begin", CallRule::No), // half of a deploy key the phone finishes with its signature
    ("POST /api/repos/key/finish", CallRule::No), // needs the phone's signature and sealed share
    ("GET /api/requests", CallRule::No), // the Inbox
    ("POST /api/requests/batch", CallRule::No), // the Inbox
    ("DELETE /api/requests/batches/{id}", CallRule::No), // the Inbox
    ("GET /api/requests/batches/{id}", CallRule::No), // the Inbox
    ("POST /api/requests/grant", CallRule::No), // the Inbox
    ("POST /api/requests/repo/add", CallRule::No), // the Inbox
    ("POST /api/requests/repo/remove", CallRule::No), // the Inbox
    ("POST /api/requests/restore", CallRule::No), // the Inbox
    ("POST /api/requests/unlock", CallRule::No), // the Inbox
    ("DELETE /api/requests/{id}", CallRule::No), // the Inbox
    ("GET /api/requests/{id}", CallRule::No), // the Inbox
    ("GET /api/requests/calls/{id}", CallRule::No), // the Inbox
    ("POST /api/requests/{id}/approve", CallRule::No), // the Inbox
    ("POST /api/requests/{id}/done", CallRule::No), // the Inbox
    ("POST /api/sessions", CallRule::Body),
    ("GET /api/sessions/{id}/attachments/{name}", CallRule::Body),
    ("POST /api/sessions/{id}/auto-pause", CallRule::Body),
    ("GET /api/sessions/{id}/cert", CallRule::Status), // the line's core-signed cert
    ("GET /api/sessions/{id}/changes", CallRule::Body),
    ("GET /api/sessions/{id}/crons", CallRule::Body),
    ("POST /api/sessions/{id}/crons", CallRule::Body),
    ("PUT /api/sessions/{id}/chat-schedule", CallRule::No), // hermit-jarvis's report (schedule.go ChatSchedule)
    ("DELETE /api/sessions/{id}/crons/{name}", CallRule::Body),
    ("POST /api/sessions/{id}/crons/{name}/run", CallRule::Body),
    ("POST /api/sessions/{id}/destroy", CallRule::Body),
    ("POST /api/sessions/{id}/env", CallRule::Body),
    ("POST /api/sessions/{id}/exec", CallRule::Status), // another session's command output (its env, its files)
    ("GET /api/sessions/{id}/grants", CallRule::Status), // phone-signed grant documents
    ("POST /api/sessions/{id}/grants", CallRule::No), // takes a phone-signed grant
    ("POST /api/sessions/{id}/grants/draft", CallRule::Body),
    ("POST /api/sessions/{id}/notify-idle", CallRule::Body),
    ("POST /api/sessions/{id}/pause", CallRule::Body),
    ("POST /api/sessions/{id}/permission-mode", CallRule::Body),
    ("POST /api/sessions/{id}/account", CallRule::Body),
    ("GET /api/sessions/{id}/remote", CallRule::Status), // the OpenClaw gateway token / OpenCode pairing URL
    ("POST /api/sessions/{id}/restart", CallRule::Body),
    ("POST /api/sessions/{id}/resume", CallRule::Body),
    ("POST /api/sessions/{id}/start", CallRule::Body),
    ("GET /api/sessions/{id}/tail", CallRule::Body),
    ("GET /api/sessions/{id}/terminal", CallRule::Status), // another session's screen
    ("GET /api/sessions/{id}/events", CallRule::Body), // the supervisor's lines (free of secrets) and the lifecycle log
    ("POST /api/sessions/{id}/harness", CallRule::Body), // pause/resume the Claude process
    ("POST /api/sessions/{id}/terminal", CallRule::Body),
    ("POST /api/sessions/{id}/upgrade", CallRule::Body),
    ("POST /api/sessions/{id}/disk", CallRule::Body),
    ("DELETE /api/sessions/{id}/wakeup", CallRule::Body),
    ("GET /api/sessions/{id}/wakeup", CallRule::Body),
    ("POST /api/sessions/{id}/wakeup", CallRule::Body),
    ("GET /api/sessions/{id}/wakeups", CallRule::Body),
    ("POST /api/sessions/{id}/wakeups", CallRule::Body),
    ("DELETE /api/sessions/{id}/wakeups/{name}", CallRule::Body),
    ("POST /api/sessions/{id}/wakeups/{name}/run", CallRule::Body),
    ("GET /api/sessions/{id}/watches", CallRule::Body),
    ("POST /api/sessions/{id}/watches", CallRule::No), // only a session's own signed request arms a watch (always 400 here)
    ("DELETE /api/sessions/{id}/watches/{name}", CallRule::Body),
    ("GET /api/sizes", CallRule::Body),
    ("GET /api/regions", CallRule::Body),
    ("GET /api/state", CallRule::Body),
    ("GET /api/stores", CallRule::Body),
    ("PUT /api/stores/{store}/docs", CallRule::Body), // explanations: no secret, no trust decision
    ("POST /api/stores/restore/finish", CallRule::No), // needs the phone's signature and sealed shares
    ("GET /api/tasks", CallRule::Body),
    ("POST /api/tasks/instances", CallRule::Body),
    ("DELETE /api/tasks/instances/{id}", CallRule::Body),
    ("PUT /api/tasks/instances/{id}", CallRule::Body),
    ("POST /api/tasks/instances/{id}/approve", CallRule::Body),
    ("POST /api/tasks/instances/{id}/run", CallRule::Body),
    ("GET /api/tasks/instances/{id}/runs", CallRule::Body),
    ("GET /api/tasks/runs/{id}", CallRule::Body),
    ("POST /api/tasks/runs/{id}/stop", CallRule::Body),
    ("POST /api/tasks/schedules", CallRule::Body),
    ("DELETE /api/tasks/schedules/{id}", CallRule::Body),
    ("PUT /api/tasks/schedules/{id}", CallRule::Body),
    ("POST /api/uploads", CallRule::No), // the app's attachment upload (raw file with its x-upload-* headers)
    ("GET /api/usage", CallRule::Body),
    ("GET /term/{id}", CallRule::No), // a terminal page for a browser
];
