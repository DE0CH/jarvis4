//! Requests (the app's Inbox, docs/API.md "Requests"): anything that needs Deyao's Face ID and was asked for somewhere
//! other than the phone itself — by a session, the web page or the setup session (Claude) — waits here until he
//! reviews it on the phone. The router keeps the request with who called (worked out from the caller's credential,
//! never from what it says about itself) and the exact call. Nothing here can approve anything: a request is a pointer
//! to a secure page, and Deny just drops it. The approvals the router already holds are listed in the same Inbox.

use crate::http::{Registrar, write_err};
use crate::nethttp::{Req, W, write_json};
use crate::router::Router;
use crate::state::{Approval, Persisted};
use anyhow::{Result, anyhow};
use jarvis_go::GoTime;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

/// Deyao, 2026-10-12: anything in the Inbox (request or approval) goes after 10 min
pub const INBOX_TTL_SECS: i64 = 600;
pub const INBOX_TTL: time::Duration = time::Duration::minutes(10);
/// pending requests one caller may have
pub const REQUEST_PER_CALLER: usize = 20;
/// characters
pub const EXPLANATION_MAX: usize = 600;
pub const EXPLANATION_LINES: usize = 8;
/// a caller noted before its approval is made (flows run on threads)
pub const ORIGIN_REMEMBER: time::Duration = time::Duration::minutes(10);
pub const REQUEST_KIND_REPO: &str = "repo-key";
pub const REQUEST_KIND_GRANT: &str = "grant";
pub const REQUEST_KIND_UNLOCK: &str = "unlock";

fn is_false(b: &bool) -> bool {
    !*b
}

fn is_zero(n: &i64) -> bool {
    *n == 0
}

/// who called, from the credential the call carried
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Caller {
    /// web | app | session | setup | actions | router
    pub kind: String,
    /// kind session: the calling machine's session
    #[serde(skip_serializing_if = "String::is_empty")]
    pub session: String,
}

/// the endpoint the caller called and its arguments (the parsed ones, without the explanation)
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ApiCall {
    pub method: String,
    pub path: String,
    #[serde(skip_serializing_if = "Map::is_empty")]
    pub args: Map<String, Value>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Origin {
    pub caller: Caller,
    pub call: ApiCall,
    /// outcomes.rs: a session's filing exactly as its machine signed it, and the item's index in it (a batch)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed: Option<SignedRequest>,
    #[serde(skip_serializing_if = "is_zero")]
    pub item: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub batch: String,
    /// apicalls.rs: the API-call request whose approved call made this
    #[serde(rename = "viaCall", skip_serializing_if = "String::is_empty")]
    pub via_call: String,
}

pub use crate::vouch::SignedRequest;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct RequestParams {
    /// repo-key: add | remove
    #[serde(skip_serializing_if = "String::is_empty")]
    pub action: String,
    /// repo-key: owner/name
    #[serde(skip_serializing_if = "String::is_empty")]
    pub repo: String,
    #[serde(skip_serializing_if = "is_false")]
    pub sensitive: bool,
    /// grant, unlock: the session it is for; repo-key add from a session: the session that gets the repo's store
    #[serde(skip_serializing_if = "String::is_empty")]
    pub session: String,
    /// grant
    #[serde(skip_serializing_if = "String::is_empty")]
    pub holder: String,
    /// grant: 1–10
    #[serde(skip_serializing_if = "is_zero")]
    pub minutes: i64,
    /// a standing rule instead: 1–365 days
    #[serde(skip_serializing_if = "is_zero")]
    pub days: i64,
    /// api-call (apicalls.rs): the call to run as Deyao
    #[serde(skip_serializing_if = "String::is_empty")]
    pub method: String,
    /// with its query
    #[serde(skip_serializing_if = "String::is_empty")]
    pub path: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub body: String,
    #[serde(rename = "contentType", skip_serializing_if = "String::is_empty")]
    pub content_type: String,
    /// restore (storerestore.rs): the store and the version to put back
    #[serde(skip_serializing_if = "String::is_empty")]
    pub store: String,
    #[serde(skip_serializing_if = "is_zero")]
    pub seq: i64,
    /// peer-message (peermsg.rs): the words; session is the receiving session, the caller the sending one
    #[serde(skip_serializing_if = "String::is_empty")]
    pub text: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct InboxRequest {
    pub id: String,
    /// repo-key | grant | unlock | api-call | restore | peer-message
    pub kind: String,
    pub params: RequestParams,
    pub origin: Origin,
    pub explanation: String,
    pub created: GoTime,
    pub expires: GoTime,
    /// dedup: kind + params
    pub key: String,
    /// batches.rs: filed in this batch
    #[serde(skip_serializing_if = "String::is_empty")]
    pub batch: String,
}

macro_rules! msg_err {
    ($name:ident) => {
        #[derive(Debug, Clone)]
        pub struct $name(pub String);
        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.0)
            }
        }
        impl std::error::Error for $name {}
    };
}

msg_err!(BadRequest);
msg_err!(Forbidden);
// a caller over its limit of waiting asks (429)
msg_err!(TooMany);
// a deny of something no longer waiting: what was asked for holds, answered 200 {ok, gone}
msg_err!(AlreadyGone);

pub fn already_gone() -> anyhow::Error {
    AlreadyGone("already gone (answered, denied or lapsed)".into()).into()
}

/// what a caller may ask for: every kind, for any session (every request still needs Deyao on the phone)
pub fn caller_may(c: &Caller, kind: &str, _p: &RequestParams) -> Result<()> {
    match kind {
        crate::storerestore::REQUEST_KIND_RESTORE
        | REQUEST_KIND_REPO
        | REQUEST_KIND_GRANT
        | REQUEST_KIND_UNLOCK
        | crate::apicalls::REQUEST_KIND_CALL => Ok(()),
        crate::peermsg::REQUEST_KIND_PEER => {
            if c.kind == "session" && !c.session.is_empty() {
                Ok(())
            } else {
                Err(anyhow!("only a session sends a peer message"))
            }
        }
        k => Err(anyhow!("unknown request kind {k}")),
    }
}

/// the caller's words as plain text — control characters dropped (line breaks kept), at most EXPLANATION_LINES lines
/// and EXPLANATION_MAX characters. Required from a session and the setup session.
pub fn clean_explanation(s: &str, required: bool) -> Result<String> {
    let s = plain_lines(s)?;
    let n = s.chars().count();
    if n > EXPLANATION_MAX {
        return Err(anyhow!(
            "explanation longer than {EXPLANATION_MAX} characters ({n})"
        ));
    }
    if required && s.is_empty() {
        return Err(anyhow!(
            "an explanation is required: say why this is needed"
        ));
    }
    Ok(s)
}

/// Go's unicode.IsControl or the Cf (format) category: the characters plain text drops
pub fn control_or_format(c: char) -> bool {
    let u = c as u32;
    c.is_control()
        || matches!(u, 0xAD | 0x600..=0x605 | 0x61C | 0x6DD | 0x70F | 0x8E2 | 0x180E | 0x200B..=0x200F | 0x202A..=0x202E | 0x2060..=0x2064 | 0x2066..=0x206F | 0xFEFF | 0xFFF9..=0xFFFB | 0x110BD | 0x110CD | 0x13430..=0x1343F | 0x1BCA0..=0x1BCA3 | 0x1D173..=0x1D17A | 0xE0001 | 0xE0020..=0xE007F)
}

/// plain text — control characters dropped (line breaks kept), blank runs collapsed, at most EXPLANATION_LINES lines
pub fn plain_lines(s: &str) -> Result<String> {
    let s = s.replace("\r\n", "\n").replace('\r', "\n");
    let b: String = s
        .chars()
        .filter_map(|c| match c {
            '\n' => Some('\n'),
            '\t' => Some(' '),
            c if control_or_format(c) => None,
            c => Some(c),
        })
        .collect();
    let mut out: Vec<&str> = vec![];
    for l in b.trim().split('\n') {
        let l = l.trim();
        if l.is_empty() && out.last().is_none_or(|x| x.is_empty()) {
            continue;
        }
        out.push(l);
    }
    if out.len() > EXPLANATION_LINES {
        return Err(anyhow!("explanation longer than {EXPLANATION_LINES} lines"));
    }
    Ok(out.join("\n"))
}

pub fn request_key(kind: &str, p: &RequestParams) -> String {
    let mut p = p.clone();
    p.repo = p.repo.to_lowercase();
    format!("{kind} {}", jarvis_go::marshal(&p))
}

pub fn prune_requests(d: &mut Persisted, now: GoTime) {
    let ids: Vec<String> = d.inbox.keys().cloned().collect();
    for id in ids {
        let Some(q) = d.inbox.get(&id) else { continue };
        let lapsed = !now.before(&q.expires);
        let mut gone = false;
        if q.kind == crate::apicalls::REQUEST_KIND_CALL {
            // it waits while its session is paused; only a destroyed session's goes
            gone = !crate::apicalls::caller_exists(d, &q.origin.caller);
        }
        if !q.params.session.is_empty() {
            gone = gone
                || d.sessions
                    .get(&q.params.session)
                    .is_none_or(|s| s.state == "destroyed");
        }
        if lapsed || gone {
            let Some(q) = d.inbox.remove(&id) else {
                continue;
            };
            let oc = if lapsed {
                crate::outcomes::OUTCOME_LAPSED
            } else {
                crate::outcomes::OUTCOME_DROPPED
            };
            crate::outcomes::note_outcome(d, Some(&q.origin), &q.kind, &q.id, oc, 0, None);
        }
    }
}

/// Deyao's own login. The iPhone app sends its device login in cf-access-token; a browser doesn't. A call the router
/// runs for an approved API-call request (apicalls.rs) carries its requester instead.
pub fn app_caller(req: &Req) -> Caller {
    if let Some(c) = req
        .ctx
        .get(crate::apicalls::ON_BEHALF_KEY)
        .and_then(|s| jarvis_go::unmarshal::<Caller>(s.as_bytes()).ok())
    {
        return c;
    }
    if !req.header("cf-access-token").is_empty() {
        return Caller {
            kind: "app".into(),
            ..Default::default()
        };
    }
    Caller {
        kind: "web".into(),
        ..Default::default()
    }
}

pub fn caller_text(d: &Persisted, c: &Caller) -> String {
    match c.kind.as_str() {
        "web" => "Deyao, from the web page".into(),
        "app" => "Deyao, from the Jarvis 4 app".into(),
        "chat" => "Deyao, from the chat (a new conversation)".into(),
        "device" => "Deyao, from a paired app".into(),
        "setup" => "Claude (setup session)".into(),
        "actions" => format!(
            "the actions of {}",
            caller_text(
                d,
                &Caller {
                    kind: "session".into(),
                    session: c.session.clone()
                }
            )
        ),
        "session" => {
            let mut title = c.session.clone();
            if let Some(s) = d.sessions.get(&c.session) {
                title = crate::titles::session_title(s);
            } else {
                for rec in &d.records {
                    if rec.session.id == c.session {
                        title = crate::titles::session_title(&rec.session);
                    }
                }
            }
            if title == c.session {
                format!("session {}", c.session)
            } else {
                format!("session “{title}” ({})", c.session)
            }
        }
        _ => "Jarvis 4 itself".into(),
    }
}

/// the caller of an action whose approval the router makes later, on a thread (resume, restore): session → it
pub type Origins = Mutex<BTreeMap<String, (Origin, GoTime)>>;

/// one entry. Title and core action are NOT here: the app renders them from kind + params (the list) and the shell
/// from the signed content (the review page) — never from router prose.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct InboxItem {
    pub id: String,
    /// repo-key | grant | unlock | new-session | resume-upgrade | add-store
    pub kind: String,
    pub approval: bool,
    pub params: RequestParams,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub session: String,
    #[serde(rename = "sessionName", skip_serializing_if = "String::is_empty")]
    pub session_name: String,
    pub caller: Caller,
    #[serde(rename = "callerText")]
    pub caller_text: String,
    pub call: ApiCall,
    pub explanation: String,
    pub created: GoTime,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<GoTime>,
    /// an approval's unsigned form fields
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub options: BTreeMap<String, String>,
    /// the shell page to open: {kind, options}
    pub open: Map<String, Value>,
    /// batches.rs: reviewed together with the batch's other items
    #[serde(skip_serializing_if = "String::is_empty")]
    pub batch: String,
    /// apicalls.rs: the API-call request whose approved call brought it about
    #[serde(rename = "viaCall", skip_serializing_if = "String::is_empty")]
    pub via_call: String,
    /// an API call's effect in words, rendered by the router (call_does)
    #[serde(skip_serializing_if = "String::is_empty")]
    pub does: String,
}

pub fn inbox_session_name(d: &Persisted, sid: &str) -> String {
    d.sessions
        .get(sid)
        .map(crate::titles::session_title)
        .unwrap_or_else(|| sid.to_string())
}

fn obj(v: Value) -> Map<String, Value> {
    v.as_object().cloned().unwrap_or_default()
}

pub fn request_item(d: &Persisted, q: &InboxRequest, now: GoTime) -> InboxItem {
    let mut it = InboxItem {
        id: q.id.clone(),
        kind: q.kind.clone(),
        params: q.params.clone(),
        session: q.params.session.clone(),
        caller: q.origin.caller.clone(),
        caller_text: caller_text(d, &q.origin.caller),
        call: q.origin.call.clone(),
        explanation: q.explanation.clone(),
        created: q.created,
        expires: Some(q.expires),
        batch: q.batch.clone(),
        ..Default::default()
    };
    let mut opts = obj(json!({"inboxId": q.id}));
    let p = &q.params;
    match q.kind.as_str() {
        REQUEST_KIND_REPO => {
            opts.insert("action".into(), json!(p.action));
            opts.insert("repo".into(), json!(p.repo));
            opts.insert("sensitive".into(), json!(p.sensitive));
            if !p.session.is_empty() {
                // the store goes into this session in the same approval (repos.rs)
                it.session_name = inbox_session_name(d, &p.session);
                opts.insert("into".into(), json!(p.session));
                opts.insert("intoLabel".into(), json!(it.session_name));
                opts.insert("store".into(), json!(crate::repos::repo_store(&p.repo)));
            }
        }
        REQUEST_KIND_GRANT => {
            it.session_name = inbox_session_name(d, &p.session);
            opts.insert("sessionId".into(), json!(p.session));
            opts.insert("label".into(), json!(it.session_name));
            opts.insert("holder".into(), json!(p.holder));
            if p.days > 0 {
                opts.insert("grantKind".into(), json!("rule"));
                opts.insert(
                    "until".into(),
                    json!(now.add(time::Duration::days(p.days)).rfc3339()),
                );
            } else {
                opts.insert("grantKind".into(), json!("grant"));
                opts.insert("minutes".into(), json!(p.minutes));
            }
        }
        REQUEST_KIND_UNLOCK => {
            it.session_name = inbox_session_name(d, &p.session);
            opts.insert("sessionId".into(), json!(p.session));
            opts.insert("label".into(), json!(it.session_name));
        }
        crate::storerestore::REQUEST_KIND_RESTORE => {
            opts.insert("store".into(), json!(p.store));
            opts.insert("seq".into(), json!(p.seq));
        }
        crate::peermsg::REQUEST_KIND_PEER => {
            // its own review (one tap, no Face ID)
            it.session_name = inbox_session_name(d, &p.session);
            opts.insert("session".into(), json!(p.session));
            opts.insert("sessionName".into(), json!(it.session_name));
            opts.insert("from".into(), json!(q.origin.caller.session));
            opts.insert(
                "fromName".into(),
                json!(inbox_session_name(d, &q.origin.caller.session)),
            );
        }
        crate::apicalls::REQUEST_KIND_CALL => {
            it.session = q.origin.caller.session.clone();
            it.session_name = inbox_session_name(d, &q.origin.caller.session);
            it.does = crate::accountswap::call_does(d, &q.params);
        }
        _ => {}
    }
    it.open = obj(json!({"kind": q.kind, "options": opts}));
    it
}

pub fn approval_item(d: &Persisted, a: &Approval) -> InboxItem {
    let o = a.origin.clone().unwrap_or_else(|| Origin {
        caller: Caller {
            kind: "router".into(),
            ..Default::default()
        },
        ..Default::default()
    });
    let mut it = InboxItem {
        id: a.id.clone(),
        kind: a.kind.clone(),
        approval: true,
        session: a.session.clone(),
        session_name: inbox_session_name(d, &a.session),
        caller_text: caller_text(d, &o.caller),
        caller: o.caller.clone(),
        call: o.call.clone(),
        explanation: a.explanation.clone(),
        created: a.created,
        options: a.options.clone(),
        batch: a.batch.clone(),
        via_call: o.via_call.clone(),
        ..Default::default()
    };
    if d.batches.contains_key(&a.batch) {
        it.expires = Some(crate::batches::approval_deadline(d, a));
    }
    if !a.label.is_empty() && !d.sessions.contains_key(&a.session) {
        it.session_name = a.label.clone();
    }
    it.open = obj(json!({"kind": "approval", "options": {"approvalId": a.id, "inboxId": a.id}}));
    it
}

/// a deny's answer
pub fn write_denied(w: &mut W, err: Result<()>) {
    match err {
        Err(e) if e.downcast_ref::<AlreadyGone>().is_some() => {
            write_json(w, 200, &json!({"ok": true, "gone": true}))
        }
        Err(e) => write_err(w, &e),
        Ok(()) => write_json(w, 200, &json!({"ok": true})),
    }
}

pub fn write_request_err(w: &mut W, err: &anyhow::Error) {
    if let Some(t) = err.downcast_ref::<TooMany>() {
        crate::nethttp::write_error(w, 429, &t.0);
    } else if let Some(b) = err.downcast_ref::<BadRequest>() {
        crate::nethttp::write_error(w, 400, &b.0);
    } else if let Some(f) = err.downcast_ref::<Forbidden>() {
        crate::nethttp::write_error(w, 403, &f.0);
    } else {
        write_err(w, err);
    }
}

/// what the intent endpoints take
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct RequestIn {
    pub repo: String,
    pub sensitive: bool,
    /// repo/add from a session: don't add the repo's store to the asking session
    #[serde(rename = "noStore")]
    pub no_store: bool,
    pub session: String,
    pub holder: String,
    pub minutes: i64,
    pub days: i64,
    pub store: String,
    pub seq: i64,
    pub explanation: String,
}

/// the intents: path suffix → kind + params from the body
pub const INTENTS: [&str; 5] = ["repo/add", "repo/remove", "grant", "unlock", "restore"];

pub fn intent(name: &str, i: &RequestIn) -> Option<(&'static str, RequestParams)> {
    let p = match name {
        "repo/add" => (
            REQUEST_KIND_REPO,
            RequestParams {
                action: "add".into(),
                repo: i.repo.clone(),
                sensitive: i.sensitive,
                ..Default::default()
            },
        ),
        "repo/remove" => (
            REQUEST_KIND_REPO,
            RequestParams {
                action: "remove".into(),
                repo: i.repo.clone(),
                ..Default::default()
            },
        ),
        "grant" => (
            REQUEST_KIND_GRANT,
            RequestParams {
                session: i.session.clone(),
                holder: i.holder.clone(),
                minutes: i.minutes,
                days: i.days,
                ..Default::default()
            },
        ),
        "unlock" => (
            REQUEST_KIND_UNLOCK,
            RequestParams {
                session: i.session.clone(),
                ..Default::default()
            },
        ),
        "restore" => (
            crate::storerestore::REQUEST_KIND_RESTORE,
            RequestParams {
                store: i.store.clone(),
                seq: i.seq,
                ..Default::default()
            },
        ),
        _ => return None,
    };
    Some(p)
}

/// what a session leaves out is its own — the session of a grant or an unlock, and, for a repo it asks to be added,
/// the session that gets the repo's store in the same approval (unless noStore)
pub fn own_session(c: &Caller, kind: &str, mut p: RequestParams, i: &RequestIn) -> RequestParams {
    let own = c.kind == "session" && p.session.is_empty() && kind != REQUEST_KIND_REPO;
    let repo_store = (c.kind == "session" || c.kind == "actions")
        && kind == REQUEST_KIND_REPO
        && p.action == "add"
        && !i.no_store;
    if own || repo_store {
        p.session = c.session.clone();
    }
    p
}

/// the arguments as the router understood them (shown as the API call; the explanation is shown apart)
pub fn call_args(kind: &str, p: &RequestParams) -> Map<String, Value> {
    match kind {
        REQUEST_KIND_REPO => {
            let mut a = obj(json!({"repo": p.repo}));
            if p.sensitive {
                a.insert("sensitive".into(), json!(true));
            }
            if !p.session.is_empty() {
                a.insert("into".into(), json!(p.session));
            }
            a
        }
        REQUEST_KIND_GRANT => {
            let mut a = obj(json!({"session": p.session, "holder": p.holder}));
            if p.days > 0 {
                a.insert("days".into(), json!(p.days));
            } else {
                a.insert("minutes".into(), json!(p.minutes));
            }
            a
        }
        crate::storerestore::REQUEST_KIND_RESTORE => obj(json!({"store": p.store, "seq": p.seq})),
        _ => obj(json!({"session": p.session})),
    }
}

impl Router {
    fn session_ok(&self, sid: &str) -> bool {
        self.st.do_(|d| {
            d.sessions
                .get(sid)
                .is_some_and(|s| s.state != "destroyed" && s.state != "destroying")
        })
    }

    /// the request's params checked and in one form (the dedup key depends on it)
    pub fn normalize_request(&self, kind: &str, p: &RequestParams) -> Result<RequestParams> {
        match kind {
            REQUEST_KIND_REPO => {
                let repo = crate::repos::parse_github_repo(&p.repo);
                if repo.is_empty() {
                    return Err(anyhow!("a GitHub repo: owner/name or its URL"));
                }
                if p.action != "add" && p.action != "remove" {
                    return Err(anyhow!("action add or remove"));
                }
                let mut out = RequestParams {
                    action: p.action.clone(),
                    repo,
                    ..Default::default()
                };
                if p.action == "add" {
                    out.sensitive = p.sensitive;
                    if !p.session.is_empty() {
                        if !self.session_ok(&p.session) {
                            return Err(anyhow!("no session {:?}", p.session));
                        }
                        out.session = p.session.clone();
                    }
                }
                Ok(out)
            }
            REQUEST_KIND_GRANT | REQUEST_KIND_UNLOCK => {
                if !self.session_ok(&p.session) {
                    return Err(anyhow!("no session {:?}", p.session));
                }
                if kind == REQUEST_KIND_UNLOCK {
                    return Ok(RequestParams {
                        session: p.session.clone(),
                        ..Default::default()
                    });
                }
                if !crate::grants::HOLDER_NAMES.contains(&p.holder.as_str()) {
                    return Err(anyhow!(
                        "holder is one of {}",
                        crate::grants::HOLDER_NAMES.join(", ")
                    ));
                }
                let mut out = RequestParams {
                    session: p.session.clone(),
                    holder: p.holder.clone(),
                    ..Default::default()
                };
                if p.days != 0 && p.minutes != 0 {
                    return Err(anyhow!(
                        "minutes (a grant) or days (a standing rule), not both"
                    ));
                }
                if p.days != 0 {
                    if !(1..=365).contains(&p.days) {
                        return Err(anyhow!("a standing rule lasts 1 to 365 days"));
                    }
                    out.days = p.days;
                } else {
                    let m = if p.minutes == 0 { 10 } else { p.minutes };
                    if !(1..=10).contains(&m) {
                        return Err(anyhow!("a grant lasts 1 to 10 minutes"));
                    }
                    out.minutes = m;
                }
                Ok(out)
            }
            crate::storerestore::REQUEST_KIND_RESTORE => {
                if p.store == crate::policy::FLY_STORE {
                    return Err(anyhow!(
                        "store {} (the core's Fly token) is never restored: write it again with infra/setup.py backup-core",
                        crate::policy::FLY_STORE
                    ));
                }
                if !crate::storedocs::store_name_ok(&p.store) {
                    return Err(anyhow!("no store {:?}", p.store));
                }
                if p.seq < 1 {
                    return Err(anyhow!(
                        "seq: the version to put back (infra/setup.py versions STORE, or the Stores page)"
                    ));
                }
                Ok(RequestParams {
                    store: p.store.clone(),
                    seq: p.seq,
                    ..Default::default()
                })
            }
            crate::peermsg::REQUEST_KIND_PEER => {
                if !self.session_ok(&p.session) {
                    return Err(anyhow!("no session {:?}", p.session));
                }
                let t = crate::peermsg::clean_peer_text(&p.text);
                if t.is_empty() || t.chars().count() > crate::peermsg::PEER_NOTE_MAX {
                    return Err(anyhow!(
                        "a message of 1 to {} characters",
                        crate::peermsg::PEER_NOTE_MAX
                    ));
                }
                Ok(RequestParams {
                    session: p.session.clone(),
                    text: t,
                    ..Default::default()
                })
            }
            crate::apicalls::REQUEST_KIND_CALL => Ok(RequestParams {
                method: p.method.clone(),
                path: p.path.clone(),
                body: p.body.clone(),
                content_type: p.content_type.clone(),
                ..Default::default()
            }),
            k => Err(anyhow!("unknown request kind {k}")),
        }
    }

    /// a request into the Inbox → it (or the same one already pending, dup true)
    pub fn file_request(
        &self,
        kind: &str,
        p: RequestParams,
        explanation: &str,
        o: Origin,
    ) -> Result<(InboxRequest, bool)> {
        let p = self
            .normalize_request(kind, &p)
            .map_err(|e| BadRequest(format!("{e:#}")))?;
        caller_may(&o.caller, kind, &p).map_err(|e| Forbidden(format!("{e:#}")))?;
        let required = matches!(o.caller.kind.as_str(), "session" | "setup" | "actions");
        let explanation =
            clean_explanation(explanation, required).map_err(|e| BadRequest(format!("{e:#}")))?;
        let now = GoTime::now();
        let q = InboxRequest {
            id: format!("q{}", crate::util::rand_id()),
            kind: kind.into(),
            key: request_key(kind, &p),
            params: p,
            origin: o.clone(),
            explanation,
            created: now,
            expires: now.add(INBOX_TTL),
            batch: String::new(),
        };
        self.st.do_(|d| {
            prune_requests(d, now);
            if let Some(dup) = d.inbox.values().find(|x| x.key == q.key) {
                return Ok((dup.clone(), true));
            }
            let (mine, _) = crate::batches::caller_load(d, &o.caller);
            if mine >= REQUEST_PER_CALLER {
                return Err(TooMany(format!("this caller has {REQUEST_PER_CALLER} requests waiting already: wait for Deyao to answer them, or deny some (DELETE /api/requests/ID, jarvis4-actions.py deny ID), then file again")).into());
            }
            d.inbox.insert(q.id.clone(), q.clone());
            Ok((q.clone(), false))
        })
    }

    /// requests that were done (by any path), with what the requesting session is told ("" = nothing)
    pub fn drop_requests(
        &self,
        matches: impl Fn(&InboxRequest) -> bool,
        outcome: &str,
        proof: Option<&crate::core::Doc>,
    ) {
        self.st.do_(|d| {
            let ids: Vec<String> = d
                .inbox
                .iter()
                .filter(|(_, q)| matches(q))
                .map(|(id, _)| id.clone())
                .collect();
            for id in ids {
                if let Some(q) = d.inbox.remove(&id)
                    && !outcome.is_empty()
                {
                    crate::outcomes::note_outcome(
                        d,
                        Some(&q.origin),
                        &q.kind,
                        &q.id,
                        outcome,
                        0,
                        proof,
                    );
                }
            }
        });
    }

    /// the caller of the approval session sid gets next (and of one it has already, without a caller)
    /// the caller noted for the session's next approval (note_origin), once
    pub fn take_origin(&self, sid: &str) -> Option<Origin> {
        let mut g = self.origins.lock().ok()?;
        match g.remove(sid) {
            Some((o, at)) if at.since() <= ORIGIN_REMEMBER => Some(o),
            _ => None,
        }
    }

    pub fn note_origin(&self, sid: &str, o: Origin) {
        if let Ok(mut g) = self.origins.lock() {
            g.retain(|_, (_, at)| at.since() <= ORIGIN_REMEMBER);
            g.insert(sid.to_string(), (o.clone(), GoTime::now()));
        }
        self.st.do_(|d| {
            let ids: Vec<String> = d
                .approvals
                .iter()
                .filter(|(_, a)| a.session == sid && a.origin.is_none())
                .map(|(id, _)| id.clone())
                .collect();
            for id in ids {
                if let Some(a) = d.approvals.get_mut(&id) {
                    a.origin = Some(o.clone());
                }
                if let Some(a) = d.approvals.get(&id).cloned() {
                    crate::apicalls::link_followup(d, &a);
                }
            }
        });
    }

    pub fn inbox(self: &Arc<Self>) -> Vec<InboxItem> {
        let now = GoTime::now();
        self.expire_approvals(now);
        let mut out = self.st.do_(|d| {
            prune_requests(d, now);
            crate::batches::prune_batches(d, now);
            let mut out: Vec<InboxItem> =
                d.inbox.values().map(|q| request_item(d, q, now)).collect();
            out.extend(d.approvals.values().map(|a| approval_item(d, a)));
            out.extend(crate::messages::message_inbox_items(d)); // messages.rs
            out
        });
        out.sort_by_key(|a| std::cmp::Reverse(a.created));
        out
    }

    pub fn inbox_item(self: &Arc<Self>, id: &str) -> Option<InboxItem> {
        self.inbox().into_iter().find(|it| it.id == id)
    }

    /// an approval older than INBOX_TTL is rejected, exactly as Deny would
    pub fn expire_approvals(self: &Arc<Self>, now: GoTime) {
        let old: Vec<String> = self.st.read(|d| {
            d.approvals
                .iter()
                .filter(|(_, a)| !now.before(&crate::batches::approval_deadline(d, a)))
                .map(|(id, _)| id.clone())
                .collect()
        });
        for id in old {
            if self.reject_as(&id, crate::outcomes::OUTCOME_LAPSED).is_ok() {
                crate::logf!("inbox: approval {id} expired after 10m0s");
            }
        }
    }

    pub fn inbox_loop(self: &Arc<Self>) {
        loop {
            std::thread::sleep(std::time::Duration::from_secs(60));
            crate::leaderlease::await_lead();
            let now = GoTime::now();
            self.expire_approvals(now);
            self.settle_stranded_approvals(now);
            self.st.do_(|d| {
                prune_requests(d, now);
                crate::batches::prune_batches(d, now);
            });
        }
    }

    /// a session left "approval" with no approval naming it waits for nothing: a line that ran before goes back to
    /// paused, a new one is failed, so Start again asks again (past INBOX_TTL and with no lifecycle action holding it)
    pub fn settle_stranded_approvals(&self, now: GoTime) {
        let ids: Vec<String> = self.st.do_(|d| {
            let named: std::collections::BTreeSet<&String> =
                d.approvals.values().map(|a| &a.session).collect();
            d.sessions
                .iter()
                .filter(|(id, s)| {
                    s.state == "approval"
                        && !named.contains(id)
                        && !now.before(&s.created.add(INBOX_TTL))
                })
                .map(|(id, _)| id.clone())
                .collect()
        });
        for id in ids {
            if self.busy(&id) {
                continue;
            }
            self.st.do_(|d| {
                if d.approvals.values().any(|a| a.session == id) {
                    return;
                }
                let Some(s) = d.sessions.get_mut(&id) else {
                    return;
                };
                if s.state != "approval" {
                    return;
                }
                if s.cert.is_some() || s.kernel.as_ref().is_some_and(|k| k.source_cert.is_some()) {
                    s.state = "paused".into();
                    s.error.clear();
                } else {
                    s.state = "failed".into();
                    s.error = "its approval was gone from the Inbox: Start again asks again".into();
                }
                crate::logf!(
                    "inbox: session {id} waited in approval with no approval: now {}",
                    s.state
                );
            });
        }
    }

    /// drop a request; for an approval, reject it (a new session disappears, a resume stays paused); a held message is
    /// denied (messages.rs)
    pub fn deny_request(self: &Arc<Self>, id: &str) -> Result<()> {
        if self.is_message(id) {
            if self.deny_messages(&[id.to_string()]).is_empty() {
                return Err(already_gone());
            }
            return Ok(());
        }
        let found = self.st.do_(|d| {
            let Some(q) = d.inbox.remove(id) else {
                return false;
            };
            crate::outcomes::note_outcome(
                d,
                Some(&q.origin),
                &q.kind,
                &q.id,
                crate::outcomes::OUTCOME_DENIED,
                0,
                None,
            );
            if q.kind == crate::apicalls::REQUEST_KIND_CALL {
                // the caller reads that it was denied
                crate::apicalls::prune_call_results(d, GoTime::now());
                d.call_results.insert(
                    id.to_string(),
                    crate::apicalls::CallResult {
                        id: id.into(),
                        caller: q.origin.caller.clone(),
                        method: q.params.method.clone(),
                        path: q.params.path.clone(),
                        state: "denied".into(),
                        at: GoTime::now(),
                        ..Default::default()
                    },
                );
            }
            true
        });
        if found {
            return Ok(());
        }
        self.reject(id).map_err(|_| already_gone())
    }

    /// one intent endpoint call → 200 {id, duplicate, expires} or the add-store approval
    #[allow(clippy::too_many_arguments)]
    pub fn file_intent(
        self: &Arc<Self>,
        w: &mut W,
        method: &str,
        path: &str,
        intent_name: &str,
        c: Caller,
        body: &[u8],
        signed: Option<SignedRequest>,
    ) {
        let i: RequestIn = if body.is_empty() {
            Default::default()
        } else {
            match jarvis_go::unmarshal(body) {
                Ok(i) => i,
                Err(e) => {
                    crate::nethttp::write_error(w, 400, &format!("bad JSON: {e}"));
                    return;
                }
            }
        };
        let Some((kind, p)) = intent(intent_name, &i) else {
            crate::nethttp::write_error(w, 404, &format!("no such request: {intent_name}"));
            return;
        };
        let p = own_session(&c, kind, p, &i);
        let np = match self.normalize_request(kind, &p) {
            Ok(n) => n,
            Err(e) => {
                write_request_err(w, &BadRequest(format!("{e:#}")).into());
                return;
            }
        };
        let mut o = Origin {
            caller: c.clone(),
            call: ApiCall {
                method: method.into(),
                path: path.into(),
                args: call_args(kind, &np),
            },
            signed,
            ..Default::default()
        };
        let (machine, store) = self.existing_repo_store(&c, kind, &np);
        if !machine.is_empty() {
            // repos.rs: the repo has its key, the session needs its store
            let expl = match clean_explanation(&i.explanation, true) {
                Ok(e) => e,
                Err(e) => {
                    write_request_err(w, &BadRequest(format!("{e:#}")).into());
                    return;
                }
            };
            o.call.args.insert("store".into(), json!(store));
            match self.add_store_approval(&machine, &store, o.clone(), &expl, "") {
                Ok(id) => {
                    write_json(
                        w,
                        200,
                        &json!({"ok": true, "approval": id, "id": id, "store": store, "existing": true,
                        "note": format!("{} has its deploy key already (store {store}): asked for that store, not for a new key", np.repo)}),
                    );
                    return;
                }
                Err(e) => {
                    // the list names a key whose store is gone (a Recover keeps no repo stores): a new key after all
                    crate::logf!(
                        "repos: {} asked for {}, which has a key, but the add-store of {store} failed ({e:#}): asking for a new key",
                        np.session,
                        np.repo
                    );
                    o.call.args.remove("store");
                }
            }
        }
        match self.file_request(kind, np, &i.explanation, o) {
            Err(e) => write_request_err(w, &e),
            Ok((q, dup)) => write_json(
                w,
                200,
                &json!({"id": q.id, "duplicate": dup, "expires": q.expires}),
            ),
        }
    }
}

fn setup_only(
    reg: &mut Registrar,
    pattern: &str,
    f: impl Fn(&Arc<Router>, &mut W, &mut Req, &[u8]) + Send + Sync + 'static,
) {
    reg.setup_route(pattern, move |r, w, req| {
        let b = req.read_body(1 << 20);
        if let Err(e) = r.check_setup_sig(
            &req.method,
            &req.path,
            &req.header("X-Setup-Time"),
            &req.header("X-Setup-Sig"),
            &b,
        ) {
            crate::nethttp::write_error(w, 401, &format!("{e:#}"));
            return;
        }
        f(r, w, req, &b)
    });
}

fn own(
    reg: &mut Registrar,
    pattern: &str,
    f: impl Fn(&Arc<Router>, &mut W, &mut Req, &str, &[u8]) + Send + Sync + 'static,
) {
    reg.m(pattern, move |r, w, req, machine, body| {
        match r.machine_session(machine) {
            Err(e) => crate::nethttp::write_error(w, 403, &format!("{e:#}")),
            Ok(sid) => f(r, w, req, &sid, body),
        }
    });
}

pub fn register_inbox(reg: &mut Registrar) {
    // a batch of 20 new sessions with their prompts
    let read_body = |req: &mut Req| req.read_body(1 << 20);
    // ---- the app and the web page (Deyao's Access login) ----
    reg.app("GET /api/requests", |r, w, _| {
        write_json(
            w,
            200,
            &json!({"requests": r.inbox(), "batches": r.inbox_batches(None)}),
        );
    });
    reg.app("GET /api/requests/{id}", |r, w, req| {
        match r.inbox_item(&req.path_value("id")) {
            None => crate::nethttp::write_error(
                w,
                404,
                "this request is gone (answered, denied or expired)",
            ),
            Some(it) => write_json(w, 200, &it),
        }
    });
    reg.app("DELETE /api/requests/{id}", |r, w, req| {
        write_denied(w, r.deny_request(&req.path_value("id")))
    });
    // done: the shell's page went through (the phone signed it); the request leaves the Inbox
    reg.app("POST /api/requests/{id}/done", |r, w, req| {
        let id = req.path_value("id");
        r.drop_requests(|q| q.id == id, crate::outcomes::OUTCOME_APPROVED, None);
        write_json(w, 200, &json!({"ok": true}));
    });
    // approve an API-call request (apicalls.rs): the call runs now as Deyao (this request's Access login)
    reg.app("POST /api/requests/{id}/approve", |r, w, req| {
        let id = req.path_value("id");
        let is_gone = |e: &anyhow::Error| format!("{e:#}") == format!("{:#}", crate::apicalls::no_request());
        if r.is_peer_request(&id) {
            // an upward peer message (peermsg.rs): one tap delivers it
            match r.approve_peer(&id) {
                Err(e) if is_gone(&e) => crate::nethttp::write_error(w, 404, &format!("{e:#}")),
                Err(e) => write_err(w, &e),
                Ok(out) => write_json(w, 200, &out),
            }
            return;
        }
        match r.approve_call(&id, req) {
            Err(e) if is_gone(&e) => crate::nethttp::write_error(w, 404, &format!("{e:#}")),
            Err(e) => write_err(w, &e),
            Ok(res) => {
                let mut out = json!({"ok": res.state == "done", "state": res.state, "status": res.status, "error": res.error});
                if let Some(f) = r.call_followups_of(&res.id) {
                    out["followups"] = json!(f.followups);
                    out["awaiting"] = json!(f.awaiting);
                }
                write_json(w, 200, &out);
            }
        }
    });
    // followups: the core requests an approved API call brought about, and whether one may still come
    reg.app("GET /api/requests/calls/{id}", |r, w, req| {
        let id = req.path_value("id");
        match r.call_followups_of(&id) {
            None => crate::nethttp::write_error(
                w,
                404,
                &format!("no approved call {id} (or its result is over 10m0s old)"),
            ),
            Some(f) => write_json(w, 200, &f),
        }
    });
    // batches (batches.rs): several items filed together, reviewed on one page under one Face ID
    reg.app("POST /api/requests/batch", move |r, w, req| {
        let b = read_body(req);
        r.serve_file_batch(w, app_caller(req), &req.method, &req.path.clone(), &b, None);
    });
    reg.app("GET /api/requests/batches/{id}", |r, w, req| {
        r.serve_batch(w, &req.path_value("id"), None)
    });
    reg.app("DELETE /api/requests/batches/{id}", |r, w, req| {
        r.serve_deny_batch(w, &req.path_value("id"))
    });
    for it in INTENTS {
        reg.app(&format!("POST /api/requests/{it}"), move |r, w, req| {
            let b = read_body(req);
            r.file_intent(
                w,
                &req.method.clone(),
                &req.path.clone(),
                it,
                app_caller(req),
                &b,
                None,
            );
        });
    }

    // ---- the setup session (Claude): its Access token and the setup key's signature ----
    let setup = || Caller {
        kind: "setup".into(),
        ..Default::default()
    };
    setup_only(reg, "GET /setup/requests", |r, w, _, _| {
        write_json(
            w,
            200,
            &json!({"requests": r.inbox(), "batches": r.inbox_batches(None)}),
        );
    });
    // the sessions and their current machines (ids, states, and why a failed one failed)
    setup_only(reg, "GET /setup/sessions", |r, w, _, _| {
        let ids_busy: BTreeMap<String, bool> =
            r.st.read(|d| d.sessions.keys().cloned().collect::<Vec<_>>())
                .into_iter()
                .map(|id| {
                    let b = r.busy(&id);
                    (id, b)
                })
                .collect();
        let out: Vec<Value> = r.st.do_(|d| {
            d.sessions
                .values()
                .map(|s| {
                    let mut v = json!({"id": s.id, "machineId": s.machine_id, "state": s.state,
                        "title": crate::titles::session_title(s), "image": s.image, "stores": s.stores,
                        "error": s.error, "failedAt": s.failed_at, "lost": s.lost, "waiting": s.waiting, "noSnapshot": s.no_snapshot});
                    if let Some(l) = &s.live {
                        v["lastReport"] = json!(l.last_report);
                        v["needsGrant"] = json!(l.needs_grant);
                        if let Some(g) = &l.reg {
                            v["status"] = json!(g.status);
                            v["bgTasks"] = json!(g.bg_tasks);
                            v["statusUpdatedAt"] = json!(g.status_updated_at);
                        }
                        v["busy"] = json!(ids_busy.get(&s.id).copied().unwrap_or(false));
                    }
                    v
                })
                .collect()
        });
        write_json(w, 200, &json!({"sessions": out}));
    });
    setup_only(reg, "GET /setup/repos", |r, w, _, _| {
        write_json(w, 200, &json!({"repos": r.repos()}))
    });
    setup_only(reg, "POST /setup/requests/batch", move |r, w, req, b| {
        r.serve_file_batch(w, setup(), &req.method.clone(), &req.path.clone(), b, None);
    });
    setup_only(reg, "GET /setup/requests/batches/{id}", |r, w, req, _| {
        r.serve_batch(w, &req.path_value("id"), None)
    });
    for it in INTENTS {
        setup_only(
            reg,
            &format!("POST /setup/requests/{it}"),
            move |r, w, req, b| {
                r.file_intent(
                    w,
                    &req.method.clone(),
                    &req.path.clone(),
                    it,
                    setup(),
                    b,
                    None,
                );
            },
        );
    }

    // ---- a session (its machine key, through the machine's local proxy: $JARVIS_URL/api/requests/…) ----
    let mine = |sid: &str| Caller {
        kind: "session".into(),
        session: sid.into(),
    };
    own(reg, "GET /m/api/requests", move |r, w, _, sid, _| {
        let c = mine(sid);
        let items: Vec<InboxItem> = r.inbox().into_iter().filter(|it| it.caller == c).collect();
        write_json(
            w,
            200,
            &json!({"requests": items, "batches": r.inbox_batches(Some(&c))}),
        );
    });
    own(
        reg,
        "POST /m/api/requests/batch",
        move |r, w, req, sid, b| {
            let signed = Some(crate::vouch::signed_request_of(
                req,
                &req.header("X-Machine"),
                b,
            ));
            let p = req.path.strip_prefix("/m").unwrap_or(&req.path).to_string();
            r.serve_file_batch(w, mine(sid), &req.method.clone(), &p, b, signed);
        },
    );
    own(
        reg,
        "GET /m/api/requests/batches/{id}",
        move |r, w, req, sid, _| {
            r.serve_batch(w, &req.path_value("id"), Some(&mine(sid)));
        },
    );
    for it in INTENTS {
        own(
            reg,
            &format!("POST /m/api/requests/{it}"),
            move |r, w, req, sid, b| {
                let signed = Some(crate::vouch::signed_request_of(
                    req,
                    &req.header("X-Machine"),
                    b,
                ));
                let p = req.path.strip_prefix("/m").unwrap_or(&req.path).to_string();
                r.file_intent(w, &req.method.clone(), &p, it, mine(sid), b, signed);
            },
        );
    }
    // one more store for this session: the router's add-store approval, with the caller's explanation
    own(
        reg,
        "POST /m/api/requests/add-store",
        move |r, w, req, sid, b| {
            let i: RequestIn = jarvis_go::unmarshal(b).unwrap_or_default();
            let expl = match clean_explanation(&i.explanation, true) {
                Ok(e) => e,
                Err(e) => {
                    crate::nethttp::write_error(w, 400, &format!("{e:#}"));
                    return;
                }
            };
            let machine = r.st.do_(|d| {
                d.sessions
                    .get(sid)
                    .map(|s| s.machine_id.clone())
                    .unwrap_or_default()
            });
            let o = Origin {
                caller: mine(sid),
                call: ApiCall {
                    method: "POST".into(),
                    path: "/api/requests/add-store".into(),
                    args: obj(json!({"store": i.store})),
                },
                signed: Some(crate::vouch::signed_request_of(
                    req,
                    &req.header("X-Machine"),
                    b,
                )),
                ..Default::default()
            };
            match r.add_store_approval(&machine, &i.store, o, &expl, "") {
                Err(e) => write_err(w, &e),
                // id: what the outcome is filed under (the approval's own, approval_ref), which jarvis-request waits on
                Ok(id) => write_json(w, 200, &json!({"ok": true, "approval": true, "id": id})),
            }
        },
    );
}

/// /api/state's inbox (features.rs state hooks)
pub fn inbox_state_hook(r: &Arc<Router>, out: &mut Map<String, Value>) {
    out.insert("inbox".into(), json!(r.inbox()));
    out.insert("inboxBatches".into(), json!(r.inbox_batches(None)));
}

/// a destroyed session's requests go (features.rs destroy hooks)
pub fn inbox_on_destroy(r: &Arc<Router>, s: &crate::state::Session) {
    r.drop_requests(
        |q| q.params.session == s.id,
        crate::outcomes::OUTCOME_DROPPED,
        None,
    );
}
