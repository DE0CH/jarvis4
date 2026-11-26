//! Outcomes (Deyao, 2026-10-13: "Approving an Inbox request should send a message or something to notify the session
//! that requested it"): when an Inbox item a SESSION filed is decided — approved, denied, lapsed after the Inbox's TTL,
//! dropped (it left without a decision), or failed after approval — the requesting session gets a delivery saying so
//! (one per filing: a batch's items arrive together). It fits "router-only data never reaches the agent" the way the
//! lease wake does (leases.rs):
//!
//!   - the delivery carries the session's OWN signed filing request (the intent POST, the batch, the add-store, the
//!     new-session proposal) and the item's index in it; the machine (rust/machine/src/outcomes.rs) builds the text from
//!     that body and texts built into the image, never from router prose;
//!   - per item the router names only strict-format values: the outcome (a word), the Inbox id or session id (a
//!     [a-z0-9-] id), an HTTP status (a number), and a proof document;
//!   - an approval that leaves a signed trace carries it, and the machine refuses the delivery when it doesn't check
//!     out: a grant is the phone-signed grant, an added store is the machine's new core-signed cert naming it, a new
//!     session is the core's approval (by phone) whose config is the proposal's label and prompt, a deploy key is the
//!     core's signed key answer for the repo. An unlock and an API call leave nothing signed: the text says it is
//!     Jarvis's report. A denial, a lapse or a drop is the router's word too (docs/DECISIONS.md): nothing can sign a
//!     non-event, and the text says so;
//!   - the core attests the delivery (the input log) over the canonical record below.
//!
//! A paused session isn't started for this: the outcomes wait in the router's state and go in once it runs again. A
//! destroyed session's outcomes go with it. Deyao's own words (a note, a reason) never travel.

use crate::core::Doc;
use crate::http::Registrar;
use crate::inbox::Origin;
use crate::router::Router;
use crate::state::{Persisted, Session};
use crate::vouch::{Delivery, SignedRequest};
use anyhow::{Result, anyhow};
use base64::Engine;
use jarvis_go::GoTime;
use jarvis_nethttp::write_json;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Mutex, RwLock};
use std::time::{Duration, Instant};

pub const OUTCOME_APPROVED: &str = "approved";
pub const OUTCOME_DENIED: &str = "denied";
/// nobody answered within the Inbox's TTL
pub const OUTCOME_LAPSED: &str = "lapsed";
/// left the Inbox without a decision (the session paused, what it was about went away)
pub const OUTCOME_DROPPED: &str = "dropped";
/// approved, but carrying it out failed
pub const OUTCOME_FAILED: &str = "failed";

pub const OUTCOME_MAX_PER_SESSION: usize = 100;
pub const OUTCOME_MAX_ATTEMPTS: i64 = 20;
/// a batch's items are delivered together: until all are decided, or this long after the last
pub const OUTCOME_SETTLE: time::Duration = time::Duration::seconds(30);
pub const OUTCOME_TICK_EVERY: Duration = Duration::from_secs(15);

static OUTCOME_REF_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"^[a-z0-9-]{1,64}$").unwrap_or_else(|_| unreachable!()));

fn is_zero(n: &i64) -> bool {
    *n == 0
}

/// one decided item of a session's filing, kept until it is delivered (persisted)
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Outcome {
    pub id: String,
    /// the requesting session
    pub session: String,
    /// its own filing, as its machine signed it
    pub request: Option<SignedRequest>,
    /// the item's index in a batch (0 otherwise)
    pub item: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub batch: String,
    /// the Inbox id, or the session the approval was for
    pub r#ref: String,
    /// what was asked (for listing): repo-key | grant | unlock | api-call | add-store | new-session
    pub kind: String,
    pub outcome: String,
    /// an approved API call: its HTTP status
    #[serde(skip_serializing_if = "is_zero")]
    pub status: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<Doc>,
    pub at: GoTime,
    #[serde(rename = "deliveredAt", skip_serializing_if = "Option::is_none")]
    pub delivered_at: Option<GoTime>,
    #[serde(skip_serializing_if = "is_zero")]
    pub attempts: i64,
    /// the last delivery error (or why it was given up)
    #[serde(skip_serializing_if = "String::is_empty")]
    pub error: String,
}

/// one item in a request-outcome delivery
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct OutcomeItem {
    pub item: i64,
    pub outcome: String,
    pub r#ref: String,
    #[serde(skip_serializing_if = "is_zero")]
    pub status: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<Doc>,
}

/// what the core attests for a request-outcome delivery (rust/machine/src/outcomes.rs builds the same bytes)
#[derive(Serialize)]
struct OutcomeRecord {
    /// the filing's signature
    request: String,
    items: Vec<OutcomeRecordItem>,
}

#[derive(Serialize)]
struct OutcomeRecordItem {
    item: i64,
    outcome: String,
    r#ref: String,
    status: i64,
    /// sha256 of the proof's payload and signature, "" = none
    proof: String,
}

pub fn proof_hash(p: Option<&Doc>) -> String {
    p.map(|p| {
        hex::encode(Sha256::digest(
            format!("{}\n{}", p.payload, p.sig).as_bytes(),
        ))
    })
    .unwrap_or_default()
}

pub fn outcome_attested(d: &Delivery) -> Result<Vec<u8>> {
    let r = d
        .request
        .as_ref()
        .filter(|_| !d.outcomes.is_empty())
        .ok_or_else(|| anyhow!("request-outcome: no signed request or no items"))?;
    let mut rec = OutcomeRecord {
        request: r.sig.clone(),
        items: vec![],
    };
    for it in &d.outcomes {
        if !OUTCOME_REF_RE.is_match(&it.r#ref)
            || !(0..=999).contains(&it.status)
            || it.item < 0
            || it.item >= crate::batches::BATCH_MAX_ITEMS as i64
        {
            return Err(anyhow!("request-outcome: not an id, status or item index"));
        }
        if !matches!(
            it.outcome.as_str(),
            OUTCOME_APPROVED | OUTCOME_DENIED | OUTCOME_LAPSED | OUTCOME_DROPPED | OUTCOME_FAILED
        ) {
            return Err(anyhow!("request-outcome: not an outcome"));
        }
        rec.items.push(OutcomeRecordItem {
            item: it.item,
            outcome: it.outcome.clone(),
            r#ref: it.r#ref.clone(),
            status: it.status,
            proof: proof_hash(it.proof.as_ref()),
        });
    }
    Ok(jarvis_go::marshal(&rec).into_bytes())
}

/// a decision just landed: the loop looks at once
static OUTCOME_KICK: AtomicBool = AtomicBool::new(false);

/// What an approval's outcome is filed under, the id its filing answered: an add-store's own id (two store requests of
/// one session are two requests, each waited on by its own command and shown as its own card in the chat), any other
/// approval's session (a proposed session's id is what its proposal answered).
pub fn approval_ref(a: &crate::state::Approval) -> String {
    if a.kind == "add-store" || a.kind == crate::kernelline::KERNEL_ADD_APPROVAL_KIND {
        a.id.clone()
    } else {
        a.session.clone()
    }
}

/// (under the state lock) the item an Origin filed was decided. Only a session's own signed filing gets one; the first
/// decision of an item stands.
pub fn note_outcome(
    d: &mut Persisted,
    o: Option<&Origin>,
    kind: &str,
    r#ref: &str,
    outcome: &str,
    status: i64,
    proof: Option<&Doc>,
) {
    let Some(o) = o else { return };
    let Some(signed) = o.signed.as_ref() else {
        return;
    };
    if (o.caller.kind != "session" && o.caller.kind != "actions") || o.caller.session.is_empty() {
        return;
    }
    let sid = o.caller.session.clone();
    if d.sessions
        .get(&sid)
        .is_none_or(|s| s.state == "destroyed" || s.state == "destroying")
    {
        return;
    }
    if !OUTCOME_REF_RE.is_match(r#ref) {
        return;
    }
    let list = d.outcomes.entry(sid.clone()).or_default();
    if list
        .iter()
        .any(|x| x.request.as_ref().is_some_and(|r| r.sig == signed.sig) && x.item == o.item)
    {
        return;
    }
    let batch = if is_batch_path(&signed.path) {
        o.batch.clone()
    } else {
        String::new()
    };
    list.push(Outcome {
        id: crate::util::rand_id(),
        session: sid.clone(),
        request: Some(signed.clone()),
        item: o.item,
        batch,
        r#ref: r#ref.into(),
        kind: kind.into(),
        outcome: outcome.into(),
        status,
        proof: proof.cloned(),
        at: GoTime::now(),
        ..Default::default()
    });
    if list.len() > OUTCOME_MAX_PER_SESSION {
        // the oldest delivered one goes, else the oldest
        let drop = list
            .iter()
            .position(|x| x.delivered_at.is_some())
            .unwrap_or(0);
        list.remove(drop);
    }
    crate::logf!("[outcome] {sid}: {kind} {} {outcome}", r#ref);
    OUTCOME_KICK.store(true, Ordering::SeqCst);
}

pub fn is_batch_path(p: &str) -> bool {
    p.ends_with("/requests/batch")
}

/// the number of items in a signed batch filing (0 when it isn't one)
pub fn batch_size(sr: Option<&SignedRequest>) -> usize {
    let Some(sr) = sr.filter(|s| is_batch_path(&s.path)) else {
        return 0;
    };
    let Ok(b) = base64::engine::general_purpose::STANDARD.decode(&sr.body) else {
        return 0;
    };
    serde_json::from_slice::<Value>(&b)
        .ok()
        .and_then(|v| v.get("items").and_then(Value::as_array).map(Vec::len))
        .unwrap_or(0)
}

// ---- delivery -------------------------------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct OutcomeGroup {
    pub sid: String,
    pub sig: String,
    pub ids: Vec<String>,
    pub deliv: Delivery,
}

/// (under the lock) each started session's undelivered outcomes, grouped by filing; a batch's group is ready once every
/// item is decided or OUTCOME_SETTLE after its newest
pub fn ready_outcomes(d: &mut Persisted, now: GoTime) -> Vec<OutcomeGroup> {
    let mut out = vec![];
    let sids: Vec<String> = d.outcomes.keys().cloned().collect();
    for sid in sids {
        let Some(s) = d.sessions.get(&sid).filter(|s| s.state != "destroyed") else {
            d.outcomes.remove(&sid);
            continue;
        };
        if s.state != "started" || s.machine_id.is_empty() {
            continue; // a paused session gets them at its next start; nothing boots it for this
        }
        let list = d.outcomes.get(&sid).cloned().unwrap_or_default();
        let mut groups: BTreeMap<String, OutcomeGroup> = BTreeMap::new();
        let mut newest: BTreeMap<String, GoTime> = BTreeMap::new();
        let mut order = vec![];
        for x in &list {
            let Some(req) = x.request.as_ref().filter(|_| x.delivered_at.is_none()) else {
                continue;
            };
            let g = groups.entry(req.sig.clone()).or_insert_with(|| {
                order.push(req.sig.clone());
                OutcomeGroup {
                    sid: sid.clone(),
                    sig: req.sig.clone(),
                    ids: vec![],
                    deliv: Delivery {
                        kind: "request-outcome".into(),
                        request: Some(req.clone()),
                        ..Default::default()
                    },
                }
            });
            g.ids.push(x.id.clone());
            g.deliv.outcomes.push(OutcomeItem {
                item: x.item,
                outcome: x.outcome.clone(),
                r#ref: x.r#ref.clone(),
                status: x.status,
                proof: x.proof.clone(),
            });
            let n = newest.entry(req.sig.clone()).or_default();
            if x.at.after(n) {
                *n = x.at;
            }
        }
        for sig in order {
            let Some(mut g) = groups.remove(&sig) else {
                continue;
            };
            let n = batch_size(g.deliv.request.as_ref());
            if n > 0 {
                let decided: BTreeSet<i64> = list
                    .iter()
                    .filter(|x| x.request.as_ref().is_some_and(|r| r.sig == sig))
                    .map(|x| x.item)
                    .collect();
                if decided.len() < n
                    && now.sub(newest.get(&sig).unwrap_or(&GoTime::default())) < OUTCOME_SETTLE
                {
                    continue;
                }
            }
            g.deliv.outcomes.sort_by_key(|o| o.item);
            out.push(g);
        }
    }
    out
}

pub type OutcomeHook = Arc<dyn Fn(&Arc<Router>, &str, Delivery) -> Result<()> + Send + Sync>;
/// the outcomes' delivery (tests)
pub static DELIVER_OUTCOME_HOOK: RwLock<Option<OutcomeHook>> = RwLock::new(None);

static OUTCOME_BUSY: LazyLock<Mutex<BTreeSet<String>>> =
    LazyLock::new(|| Mutex::new(BTreeSet::new()));
static OUTCOME_TICKING: Mutex<()> = Mutex::new(());

/// outcome groups being delivered now (tests wait for none: Go's outcomeWG)
pub fn outcomes_in_flight() -> usize {
    OUTCOME_BUSY.lock().unwrap_or_else(|e| e.into_inner()).len()
}

#[derive(Debug, Clone, Serialize)]
struct OutcomeView {
    r#ref: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    batch: String,
    item: i64,
    kind: String,
    outcome: String,
    #[serde(skip_serializing_if = "is_zero")]
    status: i64,
    at: GoTime,
    #[serde(skip_serializing_if = "Option::is_none")]
    delivered: Option<GoTime>,
    #[serde(skip_serializing_if = "String::is_empty")]
    error: String,
}

impl Router {
    pub fn outcome_loop(self: &Arc<Self>) {
        loop {
            crate::leaderlease::await_lead();
            self.outcome_tick();
            let end = Instant::now() + OUTCOME_TICK_EVERY;
            while Instant::now() < end {
                if OUTCOME_KICK.swap(false, Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_secs(2)); // let a batch's other answers land
                    break;
                }
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    }

    /// deliver every ready group, each outside the lock and once at a time
    pub fn outcome_tick(self: &Arc<Self>) {
        let Ok(_t) = OUTCOME_TICKING.try_lock() else {
            return;
        };
        let ready = self.st.do_(|d| ready_outcomes(d, GoTime::now()));
        for g in ready {
            let key = format!("{} {}", g.sid, g.sig);
            if !OUTCOME_BUSY
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(key.clone())
            {
                continue;
            }
            let r = self.clone();
            std::thread::spawn(move || {
                let k2 = key.clone();
                let _b = crate::flows::scopeguard(move || {
                    OUTCOME_BUSY
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .remove(&k2);
                });
                let res = match DELIVER_OUTCOME_HOOK
                    .read()
                    .unwrap_or_else(|e| e.into_inner())
                    .clone()
                {
                    Some(h) => h(&r, &g.sid, g.deliv.clone()),
                    None => r.deliver_vouched_running(&g.sid, g.deliv.clone()),
                };
                if res.as_ref().is_err_and(crate::schedule::is_skip) {
                    return; // not running right now: the next tick (or the next start)
                }
                let now = GoTime::now();
                let ids: BTreeSet<&String> = g.ids.iter().collect();
                let err = res.as_ref().err().map(|e| format!("{e:#}"));
                let no_session = res.as_ref().is_err_and(crate::sessionapi::is_no_session);
                r.st.do_(|d| {
                    for x in d.outcomes.get_mut(&g.sid).into_iter().flatten() {
                        if !ids.contains(&x.id) {
                            continue;
                        }
                        let Some(e) = &err else {
                            x.delivered_at = Some(now);
                            x.error.clear();
                            continue;
                        };
                        x.attempts += 1;
                        x.error = crate::util::trim_to(e, 300);
                        // an image from before outcomes refuses the kind: it never will take it
                        if x.attempts >= OUTCOME_MAX_ATTEMPTS
                            || no_session
                            || e.contains("unknown delivery kind")
                        {
                            x.delivered_at = Some(now); // given up; the session can still read it (GET /m/api/requests/outcomes)
                            x.error = format!("not delivered: {}", x.error);
                        }
                    }
                });
                match err {
                    Some(e) => crate::logf!(
                        "[outcome] {}: delivering {} item(s) failed: {e}",
                        g.sid,
                        g.ids.len()
                    ),
                    None => crate::logf!("[outcome] {}: {} item(s) delivered", g.sid, g.ids.len()),
                }
            });
        }
    }
}

pub fn register_outcomes(reg: &mut Registrar) {
    reg.m("GET /m/api/requests/outcomes", |r, w, _, machine, _| {
        let sid = match r.machine_session(machine) {
            Err(e) => return write_json(w, 403, &json!({"error": format!("{e:#}")})),
            Ok(s) => s,
        };
        let mut out: Vec<OutcomeView> = r.st.do_(|d| {
            d.outcomes
                .get(&sid)
                .into_iter()
                .flatten()
                .map(|x| OutcomeView {
                    r#ref: x.r#ref.clone(),
                    batch: x.batch.clone(),
                    item: x.item,
                    kind: x.kind.clone(),
                    outcome: x.outcome.clone(),
                    status: x.status,
                    at: x.at,
                    delivered: x.delivered_at,
                    error: x.error.clone(),
                })
                .collect()
        });
        out.sort_by_key(|a| std::cmp::Reverse(a.at));
        write_json(w, 200, &json!({"outcomes": out}));
    });
}

pub fn outcomes_on_destroy(r: &Arc<Router>, s: &Session) {
    r.st.do_(|d| {
        d.outcomes.remove(&s.id);
    });
}
