//! router/addstore_test.go: two add-stores pending for one running session, both approved (2026-10-13: identity and
//! yyc for one session; the session ended with only the store answered last). Whatever order and timing the phone
//! answers in, the session ends with both stores: with a core that answers every add-store onto the newest cert, and,
//! with the production core that doesn't, by filing the stale one again rather than storing an answer that drops a
//! store.
use crate::inbox::{Caller, Origin};
use crate::router::Router;
use crate::testutil::*;
use crate::types::Doc;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

/// a core's add-store rules. held = the production core of 2026-10-13 (before R1): no newest cert at all, so it
/// answers any add-store challenge from the cert it was made from and ignores current
#[derive(Default)]
pub struct AddStoreState {
    held: bool,
    /// machine → newest cert nonce
    latest: BTreeMap<String, String>,
    answered: BTreeSet<String>,
    n: u32,
    /// the phone's signature must cover the challenge: "sig:" + its nonce (phone_sig)
    sigs: bool,
}

fn decode(d: &Value) -> Value {
    serde_json::from_str(d["payload"].as_str().unwrap_or_default()).unwrap_or_default()
}

fn strs(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|a| {
            a.iter()
                .map(|x| x.as_str().unwrap_or_default().to_string())
                .collect()
        })
        .unwrap_or_default()
}

fn doc(v: &Value) -> Value {
    json!({"payload": jarvis_go::marshal(v), "sig": "s"})
}

fn cert(nonce: &str, stores: &[String], machine: &str) -> Value {
    json!({"kind": "succession-cert", "nonce": nonce, "stores": stores, "machine": {"id": machine},
        "options": {"permissionMode": "auto"}})
}

pub fn add_store_router(held: bool) -> (TestRouter, Arc<Mutex<AddStoreState>>, TestServer) {
    let t = new_test_router();
    let st = Arc::new(Mutex::new(AddStoreState {
        held,
        latest: BTreeMap::from([("m1".to_string(), "c0".to_string())]),
        ..Default::default()
    }));
    let s2 = st.clone();
    let srv = TestServer::handler(move |w, req| {
        let input: Value = serde_json::from_slice(&req.read_body(1 << 20)).unwrap_or_default();
        let mut c = s2.lock().unwrap_or_else(|e| e.into_inner());
        let mut out = |status: u16, v: &Value| crate::nethttp::write_json(w, status, &doc(v));
        match req.path.as_str() {
            "/succession" => {
                let pc = decode(&input["predecessor"]);
                let machine = input["machine"].as_str().unwrap_or_default().to_string();
                if !c.held && c.latest.get(&machine).map(String::as_str) != pc["nonce"].as_str() {
                    return out(
                        409,
                        &json!({"error": "the predecessor cert isn't the newest"}),
                    );
                }
                let have = strs(&pc["stores"]);
                let added = strs(&input["stores"])
                    .into_iter()
                    .rfind(|s| !have.contains(s))
                    .unwrap_or_default();
                c.n += 1;
                out(
                    200,
                    &json!({"kind": "challenge", "nonce": format!("ch{}", c.n), "request": {
                    "predecessor": input["predecessor"], "machine": {"id": machine}, "stores": input["stores"],
                    "addedStore": added}}),
                );
            }
            "/approve/by-phone" => {
                let ch = decode(&input["challenge"]);
                let nonce = ch["nonce"].as_str().unwrap_or_default().to_string();
                let m = ch["request"]["machine"]["id"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string();
                if c.sigs && input["signature"].as_str() != Some(&format!("sig:{nonce}")) {
                    return out(
                        403,
                        &json!({"error": "the iPhone's signature doesn't cover this challenge"}),
                    );
                }
                if c.answered.contains(&nonce) {
                    return out(
                        409,
                        &json!({"error": "this challenge was already answered"}),
                    );
                }
                let mut stores = strs(&ch["request"]["stores"]);
                if !c.held {
                    // core addOnto: always the newest cert the router sends, plus the added store
                    let cur = decode(&input["current"]);
                    if input["current"].is_null()
                        || c.latest.get(&m).map(String::as_str) != cur["nonce"].as_str()
                    {
                        return out(409, &json!({"error": "current isn't the newest cert"}));
                    }
                    let added = ch["request"]["addedStore"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string();
                    let mut set: BTreeSet<String> = strs(&cur["stores"]).into_iter().collect();
                    if set.contains(&added) {
                        return out(409, &json!({"error": "already holds the store"}));
                    }
                    set.insert(added);
                    stores = set.into_iter().collect();
                }
                c.answered.insert(nonce.clone());
                c.latest.insert(m.clone(), nonce.clone());
                out(200, &cert(&nonce, &stores, &m));
            }
            _ => crate::nethttp::write_error(w, 404, "404 page not found"),
        }
    });
    let r = t.r.clone();
    r.core.set_url(&srv.url);
    let c0 = jarvis_go::marshal(&cert("c0", &["default".to_string()], "m1"));
    r.st.do_(|d| {
        d.sessions.insert(
            "s1".into(),
            crate::state::Session {
                id: "s1".into(),
                state: "started".into(),
                machine_id: "m1".into(),
                harness: "claude".into(),
                cert: Some(Doc {
                    payload: c0.clone(),
                    sig: String::new(),
                }),
                stores: Some(vec!["default".into()]),
                ..Default::default()
            },
        );
        d.machines.insert("m1".into(), "s1".into());
    });
    (t, st, srv)
}

/// the phone's signature over the approval's challenge as the phone reads it now (the stand-in core's form)
fn phone_sig(r: &Router, id: &str) -> String {
    let nonce = r.st.read(|d| {
        d.approvals
            .get(id)
            .and_then(|a| a.challenge.as_ref())
            .and_then(|c| serde_json::from_str::<Value>(&c.payload).ok())
            .and_then(|v| v["nonce"].as_str().map(String::from))
            .unwrap_or_default()
    });
    assert!(!nonce.is_empty(), "approval {id} has no challenge");
    format!("sig:{nonce}")
}

fn session_origin() -> Origin {
    Origin {
        caller: Caller {
            kind: "session".into(),
            session: "s1".into(),
        },
        ..Default::default()
    }
}

/// the approval ids by store
fn approvals_by_store(r: &Router) -> BTreeMap<String, String> {
    r.st.read(|d| {
        d.approvals
            .iter()
            .map(|(id, a)| {
                (
                    a.options.get("store").cloned().unwrap_or_default(),
                    id.clone(),
                )
            })
            .collect()
    })
}

/// identity and yyc asked for, both pending before either is answered → their approval ids
fn file_two(r: &Arc<Router>) -> BTreeMap<String, String> {
    for s in ["identity", "yyc"] {
        r.add_store_from("m1", s, session_origin(), "", "")
            .unwrap_or_else(|e| panic!("{e:#}"));
    }
    let ids = approvals_by_store(r);
    assert_eq!(ids.len(), 2, "filed {ids:?}");
    ids
}

/// the session's stores (its cert and its record agree)
fn session_stores(r: &Router) -> Vec<String> {
    r.st.read(|d| {
        let s = d.sessions.get("s1").cloned().unwrap_or_default();
        let c: Value = s
            .cert
            .as_ref()
            .and_then(|c| serde_json::from_str(&c.payload).ok())
            .unwrap_or_default();
        let a: BTreeSet<String> = strs(&c["stores"]).into_iter().collect();
        let b: BTreeSet<String> = s.stores.unwrap_or_default().into_iter().collect();
        if a != b {
            return vec!["cert and session disagree".to_string()];
        }
        a.into_iter().collect()
    })
}

fn set(v: &[&str]) -> Vec<String> {
    let s: BTreeSet<String> = v.iter().map(|x| x.to_string()).collect();
    s.into_iter().collect()
}

#[test]
fn two_pending_add_stores_both_approved_end_in_the_session() {
    let want = set(&["default", "identity", "yyc"]);
    for order in [["yyc", "identity"], ["identity", "yyc"]] {
        let (t, _c, _srv) = add_store_router(false);
        let ids = file_two(&t.r);
        for s in order {
            t.r.respond(&ids[s], "sig")
                .unwrap_or_else(|e| panic!("{order:?}: {s}: {e:#}"));
        }
        assert_eq!(session_stores(&t.r), want, "{order:?}");
    }
    // both answered at the same moment
    let (t, _c, _srv) = add_store_router(false);
    let ids = file_two(&t.r);
    let ths: Vec<_> = ids
        .values()
        .cloned()
        .map(|id| {
            let r = t.r.clone();
            std::thread::spawn(move || {
                r.respond(&id, "sig")
                    .map(|_| ())
                    .map_err(|e| format!("{e:#}"))
            })
        })
        .collect();
    for th in ths {
        let res = th.join().unwrap_or_else(|_| Err("panicked".into()));
        assert!(res.is_ok(), "{res:?}");
    }
    assert_eq!(session_stores(&t.r), want, "concurrent");
}

/// The held core answers a stale challenge from the cert it was made from: the router doesn't store that answer,
/// files the approval again from the newest cert, and the next answer ends with both.
#[test]
fn a_stale_answer_from_the_held_core_drops_no_store() {
    let (t, c, _srv) = add_store_router(true);
    c.lock().unwrap_or_else(|e| e.into_inner()).sigs = true;
    let r = &t.r;
    let ids = file_two(r);
    let stale = phone_sig(r, &ids["identity"]);
    r.respond(&ids["yyc"], &phone_sig(r, &ids["yyc"]))
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert!(
        r.respond(&ids["identity"], &stale).is_err(),
        "a stale answer was taken"
    );
    assert_eq!(
        session_stores(r),
        set(&["default", "yyc"]),
        "the stale answer dropped a store"
    );
    r.respond(&ids["identity"], &phone_sig(r, &ids["identity"]))
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert_eq!(session_stores(r), set(&["default", "identity", "yyc"]));
}

/// A batch of add-stores for one session, allowed together (Deyao, 2026-10-15): the phone signs each item's challenge
/// as it reads it right before signing, one after another. Each answer makes the others' challenges again from the
/// new cert, so every item goes in on the first Allow all, with either core and in any order.
#[test]
fn a_batch_of_add_stores_for_one_session_all_go_in_at_once() {
    let stores = ["identity", "gmail", "tunnel", "github-claude-env", "yyc"];
    for held in [true, false] {
        for reverse in [false, true] {
            let (t, c, _srv) = add_store_router(held);
            c.lock().unwrap_or_else(|e| e.into_inner()).sigs = true;
            let r = &t.r;
            for s in stores {
                r.add_store_from("m1", s, session_origin(), "", "")
                    .unwrap_or_else(|e| panic!("{e:#}"));
            }
            let ids = approvals_by_store(r);
            let mut order: Vec<&str> = stores.to_vec();
            if reverse {
                order.sort_by(|a, b| b.cmp(a));
            }
            for s in order {
                r.respond(&ids[s], &phone_sig(r, &ids[s]))
                    .unwrap_or_else(|e| panic!("held={held} reverse={reverse}: {s}: {e:#}"));
            }
            let mut want = vec!["default"];
            want.extend(stores);
            assert_eq!(
                session_stores(r),
                set(&want),
                "held={held} reverse={reverse}"
            );
        }
    }
}

/// The single Add store page read identity's challenge, then yyc went in (and identity's challenge was made again):
/// the phone's signature over the challenge it read is still answered, by the core that answers onto the newest cert.
#[test]
fn an_answer_to_the_challenge_before_the_rebase_is_still_taken() {
    let (t, c, _srv) = add_store_router(false);
    c.lock().unwrap_or_else(|e| e.into_inner()).sigs = true;
    let r = &t.r;
    let ids = file_two(r);
    let read = phone_sig(r, &ids["identity"]);
    r.respond(&ids["yyc"], &phone_sig(r, &ids["yyc"]))
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert_ne!(
        phone_sig(r, &ids["identity"]),
        read,
        "identity's challenge wasn't made again from the new cert"
    );
    r.respond(&ids["identity"], &read)
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert_eq!(session_stores(r), set(&["default", "identity", "yyc"]));
}
