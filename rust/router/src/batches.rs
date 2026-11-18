//! Batches (Deyao, 2026-10-13): a caller files several Inbox items at once, with one summary; the Inbox shows them as
//! one entry and the phone reviews them on one page and allows them under ONE Face ID. Nothing about what is signed
//! changes: the app signs each item exactly as it would alone. A batch is only a grouping the router keeps:
//!   - the caller groups (through the API), any item kind; the summary is the caller's words, shown as unverified;
//!   - the whole batch goes 10 minutes after it was filed (INBOX_TTL), every item with it;
//!   - Deny drops the whole batch; a single item can still be denied (or allowed) on its own;
//!   - a batch counts once toward a caller's limits (20 waiting requests, 3 waiting proposals); at most 20 items.

use crate::flows::NewSession;
use crate::inbox::{
    ApiCall, BadRequest, Caller, Forbidden, InboxItem, InboxRequest, Origin, RequestIn,
    RequestParams, SignedRequest,
};
use crate::nethttp::{W, write_json};
use crate::router::Router;
use crate::state::{Approval, Persisted};
use anyhow::Result;
use jarvis_go::GoTime;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

pub const BATCH_MAX_ITEMS: usize = 20;

fn is_false(b: &bool) -> bool {
    !*b
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Batch {
    pub id: String,
    pub summary: String,
    pub origin: Origin,
    pub created: GoTime,
    pub expires: GoTime,
    pub entries: Vec<BatchEntry>,
    /// its items are still being filed: not pruned as empty
    #[serde(skip_serializing_if = "is_false")]
    pub filing: bool,
}

/// one filed item. A request is known by its id; an approval by its session
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct BatchEntry {
    pub intent: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub request: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub session: String,
    /// a new-session proposal (counted toward the 3)
    #[serde(rename = "proposesNew", skip_serializing_if = "is_false")]
    pub proposes_new: bool,
}

/// what a caller has waiting, as the limits count it — requests (each standalone request, each batch once) and
/// proposals (each standalone new-session approval it proposed, each batch that proposes any once)
pub fn caller_load(d: &Persisted, c: &Caller) -> (usize, usize) {
    let mut requests = d
        .inbox
        .values()
        .filter(|q| {
            q.origin.caller == *c && (q.batch.is_empty() || !d.batches.contains_key(&q.batch))
        })
        .count();
    let mut proposals = d
        .approvals
        .values()
        .filter(|a| {
            a.kind == "new-session"
                && a.origin.as_ref().is_some_and(|o| o.caller == *c)
                && (a.batch.is_empty() || !d.batches.contains_key(&a.batch))
        })
        .count();
    for b in d.batches.values() {
        if b.origin.caller != *c {
            continue;
        }
        requests += 1;
        if b.entries.iter().any(|e| e.proposes_new) {
            proposals += 1;
        }
    }
    (requests, proposals)
}

/// when an approval goes — INBOX_TTL after it was made, or its batch's end if sooner
pub fn approval_deadline(d: &Persisted, a: &Approval) -> GoTime {
    let t = a.created.add(crate::inbox::INBOX_TTL);
    match d.batches.get(&a.batch) {
        Some(b) if b.expires.before(&t) => b.expires,
        _ => t,
    }
}

/// the batch's approvals still being made (a new session whose challenge isn't in yet)
pub fn batch_preparing(d: &Persisted, b: &Batch) -> usize {
    b.entries
        .iter()
        .filter(|e| e.request.is_empty() && !e.session.is_empty())
        .filter(|e| {
            d.sessions
                .get(&e.session)
                .is_some_and(|s| s.state == "approval")
        })
        .filter(|e| {
            !d.approvals
                .values()
                .any(|a| a.session == e.session && a.batch == b.id)
        })
        .count()
}

pub fn batch_item_count(d: &Persisted, id: &str) -> usize {
    d.inbox.values().filter(|q| q.batch == id).count()
        + d.approvals.values().filter(|a| a.batch == id).count()
}

/// an expired batch goes (its items expire with it); a batch with nothing left in it goes
pub fn prune_batches(d: &mut Persisted, now: GoTime) {
    let gone: Vec<String> = d
        .batches
        .iter()
        .filter(|(id, b)| {
            !b.filing
                && (!now.before(&b.expires)
                    || (batch_item_count(d, id) == 0 && batch_preparing(d, b) == 0))
        })
        .map(|(id, _)| id.clone())
        .collect();
    for id in gone {
        d.batches.remove(&id);
    }
}

/// a batch as the Inbox lists it. Its items are the Inbox items whose `batch` is this id.
#[derive(Debug, Clone, Default, Serialize)]
pub struct InboxBatch {
    pub id: String,
    /// the caller's words, unverified
    pub summary: String,
    pub caller: Caller,
    #[serde(rename = "callerText")]
    pub caller_text: String,
    pub call: ApiCall,
    pub created: GoTime,
    pub expires: GoTime,
    /// the Inbox ids in it now, in the order filed
    pub items: Vec<String>,
    /// approvals still being made: the phone waits for them before Allow all
    pub preparing: usize,
}

/// POST …/requests/batch
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
struct BatchIn {
    summary: String,
    items: Vec<Box<serde_json::value::RawValue>>,
}

/// one item: its intent and that intent's own body (as the single endpoint takes it)
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
struct BatchItemIn {
    /// repo/add | repo/remove | grant | unlock | add-store | call | new-session | jarvis1-import | peer
    intent: String,
    #[serde(flatten)]
    request: RequestIn,
    /// jarvis1-import: the Jarvis 1 session
    id: String,
    /// peer: the receiving session (its id or exact title)
    to: String,
    /// peer: the message
    text: String,
}

/// a checked item, ready to file
#[derive(Default)]
struct BatchItem {
    intent: String,
    kind: String,
    p: RequestParams,
    machine: String,
    store: String,
    ns: Option<NewSession>,
    j1id: String,
    j1: crate::jarvis1import::J1ImportIn,
    /// peer: a message Deyao delivers signed (upward into a sensitive session, as POST …/requests/peer holds it)
    note: Option<crate::peermsg::PeerNote>,
    /// peer: equal | downward | upward, of a message filed as a peer-message request
    dir: String,
    expl: String,
    args: Map<String, Value>,
    signed: Option<SignedRequest>,
    index: i64,
}

/// what filing one item did
#[derive(Debug, Clone, Default, Serialize)]
pub struct BatchResult {
    pub intent: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub session: String,
    #[serde(skip_serializing_if = "is_false")]
    pub duplicate: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub batch: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub error: String,
    /// filed as a request of its own beside the batch (a restore is reviewed on its own page)
    #[serde(skip_serializing_if = "is_false")]
    pub own: bool,
    /// peer: equal | downward | upward; delivering: held for Deyao to deliver signed instead of waiting in the batch
    #[serde(skip_serializing_if = "String::is_empty")]
    pub direction: String,
    #[serde(skip_serializing_if = "is_false")]
    pub delivering: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub to: String,
}

fn obj(v: Value) -> Map<String, Value> {
    v.as_object().cloned().unwrap_or_default()
}

impl Router {
    /// every batch (or only one caller's), newest first
    pub fn inbox_batches(self: &Arc<Self>, only: Option<&Caller>) -> Vec<InboxBatch> {
        let items = self.inbox(); // prunes first
        let mut out: Vec<InboxBatch> = self.st.do_(|d| {
            d.batches
                .values()
                .filter(|b| !b.filing && only.is_none_or(|c| b.origin.caller == *c))
                .map(|b| {
                    let mut ib = InboxBatch {
                        id: b.id.clone(),
                        summary: b.summary.clone(),
                        caller: b.origin.caller.clone(),
                        caller_text: crate::inbox::caller_text(d, &b.origin.caller),
                        call: b.origin.call.clone(),
                        created: b.created,
                        expires: b.expires,
                        items: vec![],
                        preparing: batch_preparing(d, b),
                    };
                    // in the order filed: the entries' requests and sessions, then anything adopted
                    let mut seen = BTreeSet::new();
                    for e in &b.entries {
                        for it in &items {
                            let hit = (!e.request.is_empty() && it.id == e.request)
                                || (e.request.is_empty() && it.approval && it.session == e.session);
                            if it.batch == b.id && !seen.contains(&it.id) && hit {
                                ib.items.push(it.id.clone());
                                seen.insert(it.id.clone());
                            }
                        }
                    }
                    for it in &items {
                        if it.batch == b.id && seen.insert(it.id.clone()) {
                            ib.items.push(it.id.clone());
                        }
                    }
                    ib
                })
                .collect()
        });
        out.sort_by_key(|a| std::cmp::Reverse(a.created));
        out
    }

    /// one batch with its items (GET …/requests/batches/:id)
    pub fn inbox_batch_full(self: &Arc<Self>, id: &str, only: Option<&Caller>) -> Option<Value> {
        let b = self.inbox_batches(only).into_iter().find(|b| b.id == id)?;
        let by_id: BTreeMap<String, InboxItem> = self
            .inbox()
            .into_iter()
            .map(|it| (it.id.clone(), it))
            .collect();
        let list: Vec<&InboxItem> = b.items.iter().filter_map(|i| by_id.get(i)).collect();
        Some(json!({"batch": b, "items": list}))
    }

    /// every request in it leaves, every approval is rejected, and the batch goes; an approval still being made is
    /// rejected as it arrives (add_approval)
    pub fn deny_batch(self: &Arc<Self>, id: &str) -> Result<()> {
        let approvals = self.st.do_(|d| {
            d.batches.remove(id)?;
            let qs: Vec<String> = d
                .inbox
                .iter()
                .filter(|(_, q)| q.batch == id)
                .map(|(k, _)| k.clone())
                .collect();
            for qid in qs {
                if let Some(q) = d.inbox.remove(&qid) {
                    crate::outcomes::note_outcome(
                        d,
                        Some(&q.origin),
                        &q.kind,
                        &q.id,
                        crate::outcomes::OUTCOME_DENIED,
                        0,
                        None,
                    );
                }
            }
            Some(
                d.approvals
                    .iter()
                    .filter(|(_, a)| a.batch == id)
                    .map(|(k, _)| k.clone())
                    .collect::<Vec<_>>(),
            )
        });
        let Some(approvals) = approvals else {
            return Err(crate::inbox::already_gone());
        };
        for aid in approvals {
            let _ = self.reject(&aid);
        }
        Ok(())
    }

    /// one item checked as its own endpoint would check it, before anything is filed
    fn check_batch_item(self: &Arc<Self>, c: &Caller, raw: &str) -> Result<BatchItem> {
        let i: BatchItemIn = jarvis_go::unmarshal(raw.as_bytes())
            .map_err(|e| BadRequest(format!("bad JSON: {e}")))?;
        let expl = crate::inbox::clean_explanation(&i.request.explanation, false)
            .map_err(|e| BadRequest(format!("{e:#}")))?;
        let mut it = BatchItem {
            intent: i.intent.clone(),
            expl,
            ..Default::default()
        };
        if let Some((kind, p)) = crate::inbox::intent(&i.intent, &i.request) {
            let p = crate::inbox::own_session(c, kind, p, &i.request);
            let np = self
                .normalize_request(kind, &p)
                .map_err(|e| BadRequest(format!("{e:#}")))?;
            crate::inbox::caller_may(c, kind, &np).map_err(|e| Forbidden(format!("{e:#}")))?;
            let (machine, store) = self.existing_repo_store(c, kind, &np);
            if !machine.is_empty() {
                // repos.rs: the repo has its key, the session needs its store: the item is that add-store
                it.intent = "add-store".into();
                it.args = obj(
                    json!({"intent": it.intent, "session": np.session, "store": store, "repo": np.repo}),
                );
                it.machine = machine;
                it.store = store;
                return Ok(it);
            }
            it.args = crate::inbox::call_args(kind, &np);
            it.args.insert("intent".into(), json!(i.intent));
            it.kind = kind.into();
            it.p = np;
            return Ok(it);
        }
        match i.intent.as_str() {
            "call" => {
                // an app API call, run as Deyao once approved (apicalls.rs)
                let ci: crate::apicalls::CallIn = jarvis_go::unmarshal(raw.as_bytes())
                    .map_err(|e| BadRequest(format!("bad JSON: {e}")))?;
                let (p, args) = self
                    .check_call(&ci)
                    .map_err(|e| BadRequest(format!("call: {e:#}")))?;
                it.kind = crate::apicalls::REQUEST_KIND_CALL.into();
                it.p = p;
                it.args = args;
                it.args.insert("intent".into(), json!(i.intent));
                Ok(it)
            }
            "add-store" => {
                let mut sid = i.request.session.clone();
                if sid.is_empty() && (c.kind == "session" || c.kind == "actions") {
                    sid = c.session.clone(); // for itself by default
                }
                if i.request.store.trim().is_empty() {
                    return Err(BadRequest("add-store: store is required".into()).into());
                }
                it.machine = self.st.do_(|d| {
                    d.sessions
                        .get(&sid)
                        .filter(|s| {
                            !s.machine_id.is_empty()
                                && (s.cert.is_some() || s.kernel.is_some())
                                && (s.state == "started" || s.state == "initialising")
                        })
                        .map(|s| s.machine_id.clone())
                        .unwrap_or_default()
                });
                if it.machine.is_empty() {
                    return Err(BadRequest(format!("add-store: session {sid:?} has no running machine: a store is added to a paused session at its resume (jarvis-request add-store once it runs)")).into());
                }
                it.store = i.request.store.clone();
                it.args =
                    obj(json!({"intent": i.intent, "session": sid, "store": i.request.store}));
                Ok(it)
            }
            "new-session" => {
                let pin: crate::sessionapi::ProposalIn = jarvis_go::unmarshal(raw.as_bytes())
                    .map_err(|e| BadRequest(format!("bad JSON: {e}")))?;
                let prefix = if c.kind == "session" {
                    c.session.clone()
                } else {
                    c.kind.clone()
                };
                let ns = self.check_proposal(c, &prefix, pin, false)?;
                it.args = ns
                    .origin
                    .as_ref()
                    .map(|o| o.call.args.clone())
                    .unwrap_or_default();
                it.args.insert("intent".into(), json!(i.intent));
                it.ns = Some(ns);
                Ok(it)
            }
            "peer" => {
                // a message to another session (peermsg.rs): it waits in the batch as a peer-message request, or,
                // upward into a sensitive session, is held for Deyao to deliver signed
                if c.kind != "session" || c.session.is_empty() {
                    return Err(Forbidden("only a session sends a peer message".into()).into());
                }
                let (from, recv, text) = match self.peer_parties(&c.session, &i.to, &i.text) {
                    Err(e) if crate::sessionapi::is_no_session(&e) => {
                        return Err(Forbidden("peer: the sending session is gone".into()).into());
                    }
                    Err(e) => return Err(e),
                    Ok(x) => x,
                };
                it.args = obj(json!({"intent": i.intent, "to": recv.id}));
                let (note, held) = crate::peermsg::held_peer_note(
                    crate::peermsg::peer_note(&from, &recv, &text),
                    &recv,
                );
                if held {
                    it.note = Some(note); // the receiver holds a sensitive store: Deyao decides (messages.rs)
                    return Ok(it);
                }
                it.dir = note.direction;
                it.kind = crate::peermsg::REQUEST_KIND_PEER.into();
                it.p = RequestParams {
                    session: recv.id.clone(),
                    text,
                    ..Default::default()
                };
                it.expl = crate::peermsg::peer_explanation(&from, &recv);
                Ok(it)
            }
            "jarvis1-import" => {
                if !matches!(c.kind.as_str(), "setup" | "app" | "web") {
                    return Err(Forbidden(
                        "a Jarvis 1 import is filed by the setup session or Deyao".into(),
                    )
                    .into());
                }
                let mut j: crate::jarvis1import::J1ImportIn =
                    jarvis_go::unmarshal(raw.as_bytes()).unwrap_or_default();
                if i.id.is_empty() || j.stores.is_empty() {
                    return Err(
                        BadRequest("jarvis1-import: id and stores are required".into()).into(),
                    );
                }
                if let Err(e) = self.prepared_jarvis1(&i.id) {
                    return Err(BadRequest(format!("jarvis1-import {}: {e:#}", i.id)).into());
                }
                j.explanation = it.expl.clone();
                it.args = obj(
                    json!({"intent": i.intent, "id": i.id, "stores": j.stores, "size": j.size}),
                );
                it.j1id = i.id.clone();
                it.j1 = j;
                Ok(it)
            }
            x => Err(BadRequest(format!("unknown intent {x:?}")).into()),
        }
    }

    /// every item checked first (any bad item: nothing is filed, 400 naming it), then filed in order. An item that
    /// fails while being filed is reported and the rest stand; when none stands, the batch is dropped. A request
    /// already waiting outside any batch joins this one; one in another batch stays there.
    pub fn file_batch(
        self: &Arc<Self>,
        c: &Caller,
        method: &str,
        path: &str,
        body: &[u8],
        signed: Option<SignedRequest>,
    ) -> (u16, Value) {
        let i: BatchIn = match jarvis_go::unmarshal(body) {
            Ok(i) => i,
            Err(e) => return (400, json!({"error": format!("bad JSON: {e}")})),
        };
        let summary = match crate::inbox::clean_explanation(&i.summary, true) {
            Ok(s) => s,
            Err(e) => {
                return (
                    400,
                    json!({"error": format!("summary: {}", format!("{e:#}").replacen("explanation", "summary", 1))}),
                );
            }
        };
        if i.items.is_empty() || i.items.len() > BATCH_MAX_ITEMS {
            return (
                400,
                json!({"error": format!("a batch holds 1 to {BATCH_MAX_ITEMS} items ({} given)", i.items.len())}),
            );
        }
        let mut items = vec![];
        let mut keys: BTreeMap<String, usize> = BTreeMap::new();
        let mut uploads_used: BTreeMap<String, usize> = BTreeMap::new();
        let mut proposes = false;
        for (n, raw) in i.items.iter().enumerate() {
            let it = match self.check_batch_item(c, raw.get()) {
                Ok(it) => it,
                Err(e) => {
                    let code = if e.downcast_ref::<Forbidden>().is_some() {
                        403
                    } else {
                        400
                    };
                    return (
                        code,
                        json!({"error": format!("item {n}: {e:#}"), "item": n}),
                    );
                }
            };
            let k = if !it.kind.is_empty() {
                crate::inbox::request_key(&it.kind, &it.p)
            } else if it.intent == "new-session" {
                format!(
                    "new-session {}",
                    it.ns
                        .as_ref()
                        .map(|n| n.request_id.clone())
                        .unwrap_or_default()
                )
            } else if it.intent == "jarvis1-import" {
                format!("jarvis1-import {}", it.j1id)
            } else if let Some(note) = &it.note {
                format!("peer {}\n{}", note.to, note.text)
            } else {
                format!("{} {}", it.intent, jarvis_go::marshal(&it.args))
            };
            if let Some(j) = keys.get(&k) {
                return (
                    400,
                    json!({"error": format!("item {n} is the same as item {j}"), "item": n}),
                );
            }
            if let Some(a) = it.ns.as_ref().and_then(|ns| ns.attachments.as_ref()) {
                if let Some(j) = uploads_used.get(&a.upload_id) {
                    return (
                        400,
                        json!({"error": format!("item {n} attaches upload {}, as item {j} does: each new session needs its own upload", a.upload_id), "item": n}),
                    );
                }
                uploads_used.insert(a.upload_id.clone(), n);
            }
            keys.insert(k, n);
            proposes = proposes || it.intent == "new-session";
            items.push(it);
        }
        let now = GoTime::now();
        let b = Batch {
            id: format!("b{}", crate::util::rand_id()),
            summary,
            created: now,
            expires: now.add(crate::inbox::INBOX_TTL),
            filing: true,
            origin: Origin {
                caller: c.clone(),
                call: ApiCall {
                    method: method.into(),
                    path: path.into(),
                    args: obj(json!({"items": items.len()})),
                },
                ..Default::default()
            },
            entries: vec![],
        };
        let limit = self.st.do_(|d| {
            crate::inbox::prune_requests(d, now);
            prune_batches(d, now);
            let (reqs, props) = caller_load(d, c);
            if reqs >= crate::inbox::REQUEST_PER_CALLER {
                return format!("this caller has {reqs} requests waiting already: wait for Deyao to answer them, or deny some, then file again");
            }
            if proposes && (c.kind == "session" || c.kind == "actions") && props >= crate::sessionapi::MAX_PROPOSED_SESSIONS {
                return format!("{props} proposed sessions already wait for Deyao: wait for his answer, or deny one, then file again");
            }
            d.batches.insert(b.id.clone(), b.clone());
            String::new()
        });
        if !limit.is_empty() {
            return (429, json!({"error": limit}));
        }
        let mut results = vec![];
        let mut entries = vec![];
        for (n, mut it) in items.into_iter().enumerate() {
            it.signed = signed.clone();
            it.index = n as i64;
            let (res, entry) = self.file_batch_item(c, method, path, &b, it);
            results.push(res);
            if let Some(e) = entry {
                entries.push(e);
            }
        }
        let none = entries.is_empty();
        self.st.do_(|d| {
            if let Some(x) = d.batches.get_mut(&b.id) {
                x.entries = entries.clone();
                x.filing = false;
            }
            if none {
                d.batches.remove(&b.id);
            }
        });
        if none {
            if results
                .iter()
                .any(|x| (x.own || x.delivering) && x.error.is_empty())
            {
                // only requests of their own or messages held for a signature: no batch, but nothing failed
                return (200, json!({"items": results}));
            }
            return (
                400,
                json!({"error": "nothing in the batch could be filed", "items": results}),
            );
        }
        (
            200,
            json!({"id": b.id, "expires": b.expires, "items": results}),
        )
    }

    fn file_batch_item(
        self: &Arc<Self>,
        c: &Caller,
        method: &str,
        path: &str,
        b: &Batch,
        it: BatchItem,
    ) -> (BatchResult, Option<BatchEntry>) {
        let mut res = BatchResult {
            intent: it.intent.clone(),
            ..Default::default()
        };
        let mut o = Origin {
            caller: c.clone(),
            call: ApiCall {
                method: method.into(),
                path: path.into(),
                args: it.args.clone(),
            },
            signed: it.signed.clone(),
            item: it.index,
            batch: b.id.clone(),
            ..Default::default()
        };
        if let Some(note) = it.note {
            // a peer message Deyao delivers signed: held now, as POST …/requests/peer holds it
            o.batch.clear();
            res.direction = note.direction.clone();
            res.delivering = true;
            res.to = note.to.clone();
            self.go_peer_note(note, o, "");
            return (res, None);
        }
        if it.kind == crate::storerestore::REQUEST_KIND_RESTORE {
            // its own review page, so its own request beside the batch
            o.batch.clear();
            o.item = 0;
            match self.file_request(&it.kind, it.p, &it.expl, o) {
                Err(e) => res.error = format!("{e:#}"),
                Ok((q, dup)) => {
                    res.id = q.id;
                    res.duplicate = dup;
                    res.own = true;
                }
            }
            return (res, None);
        }
        if !it.kind.is_empty() {
            let q = InboxRequest {
                id: format!("q{}", crate::util::rand_id()),
                kind: it.kind.clone(),
                key: crate::inbox::request_key(&it.kind, &it.p),
                params: it.p.clone(),
                origin: o,
                explanation: it.expl.clone(),
                created: b.created,
                expires: b.expires,
                batch: b.id.clone(),
            };
            let (id, dup, other) = self.st.do_(|d| {
                let mut target = q.clone();
                let mut dup = false;
                let ids: Vec<String> = d
                    .inbox
                    .iter()
                    .filter(|(_, x)| x.key == q.key)
                    .map(|(k, _)| k.clone())
                    .collect();
                for xid in ids {
                    dup = true;
                    let Some(x) = d.inbox.get_mut(&xid) else {
                        continue;
                    };
                    if !x.batch.is_empty() && d.batches.contains_key(&x.batch) {
                        return (x.id.clone(), true, x.batch.clone()); // stays in its own batch
                    }
                    x.batch = b.id.clone(); // a standalone request joins
                    x.expires = b.expires;
                    target = x.clone();
                }
                d.inbox.insert(target.id.clone(), target.clone());
                (target.id, dup, String::new())
            });
            res.id = id.clone();
            res.duplicate = dup;
            res.batch = other.clone();
            if it.kind == crate::peermsg::REQUEST_KIND_PEER {
                res.direction = it.dir.clone();
                res.to = it.p.session.clone();
            }
            if !other.is_empty() {
                return (res, None);
            }
            return (
                res,
                Some(BatchEntry {
                    intent: it.intent,
                    request: id,
                    ..Default::default()
                }),
            );
        }
        if it.intent == "add-store" {
            let sid = self
                .st
                .do_(|d| d.machines.get(&it.machine).cloned().unwrap_or_default());
            res.session = sid.clone();
            if let Err(e) = self.add_store_from(&it.machine, &it.store, o, &it.expl, &b.id) {
                res.error = format!("{e:#}");
                return (res, None);
            }
            return (
                res,
                Some(BatchEntry {
                    intent: it.intent,
                    session: sid,
                    ..Default::default()
                }),
            );
        }
        if it.intent == "new-session" || it.intent == "jarvis1-import" {
            let sid = if it.intent == "new-session" {
                let mut ns = it.ns.clone().unwrap_or_default();
                let mut no = ns.origin.clone().unwrap_or_default();
                no.call = o.call.clone();
                no.call.path = path.into();
                no.signed = o.signed.clone();
                no.item = o.item;
                no.batch = o.batch.clone();
                ns.origin = Some(no);
                ns.batch = b.id.clone();
                self.create_session(ns)
            } else {
                let mut j = it.j1.clone();
                j.batch = b.id.clone();
                self.import_jarvis1(&it.j1id, j, o)
            };
            let sid = match sid {
                Err(e) => {
                    res.error = format!("{e:#}");
                    return (res, None);
                }
                Ok(s) => s,
            };
            res.id = sid.clone();
            res.session = sid.clone();
            // the same proposal again (its requestId): its approval joins this batch when it is in none
            let (dup, other) = self.st.do_(|d| {
                let mut dup = false;
                let mut other = String::new();
                let in_batch: BTreeSet<String> = d.batches.keys().cloned().collect();
                for a in d.approvals.values_mut() {
                    if a.session == sid && a.batch != b.id {
                        dup = true;
                        if a.batch.is_empty() || !in_batch.contains(&a.batch) {
                            a.batch = b.id.clone();
                        } else {
                            other = a.batch.clone();
                        }
                    }
                }
                (dup, other)
            });
            res.duplicate = dup;
            res.batch = other.clone();
            if !other.is_empty() {
                return (res, None);
            }
            let proposes = it.intent == "new-session";
            return (
                res,
                Some(BatchEntry {
                    intent: it.intent,
                    session: sid,
                    proposes_new: proposes,
                    ..Default::default()
                }),
            );
        }
        res.error = "unknown intent".into();
        (res, None)
    }

    pub fn serve_file_batch(
        self: &Arc<Self>,
        w: &mut W,
        c: Caller,
        method: &str,
        path: &str,
        body: &[u8],
        signed: Option<SignedRequest>,
    ) {
        let (code, out) = self.file_batch(&c, method, path, body, signed);
        write_json(w, code, &out);
    }

    pub fn serve_batch(self: &Arc<Self>, w: &mut W, id: &str, only: Option<&Caller>) {
        match self.inbox_batch_full(id, only) {
            None => crate::nethttp::write_error(
                w,
                404,
                "this batch is gone (answered, denied or expired)",
            ),
            Some(out) => write_json(w, 200, &out),
        }
    }

    pub fn serve_deny_batch(self: &Arc<Self>, w: &mut W, id: &str) {
        crate::inbox::write_denied(w, self.deny_batch(id));
    }
}
