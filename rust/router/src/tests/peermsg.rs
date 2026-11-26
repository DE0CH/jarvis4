//! peermsg_test.go
use crate::outcomes::{OUTCOME_APPROVED, OUTCOME_DENIED};
use crate::peermsg::{
    DELIVER_PEER_HOOK, PeerNote, REQUEST_KIND_PEER, peer_attested, peer_direction, peer_note,
};
use crate::router::Router;
use crate::state::Session;
use crate::testutil::*;
use crate::vouch::{Delivery, attested};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use std::time::Duration;

fn s(mode: &str, stores: &[&str]) -> Session {
    Session {
        permission_mode: mode.into(),
        stores: Some(stores.iter().map(|x| x.to_string()).collect()),
        ..Default::default()
    }
}

#[test]
fn peer_directions() {
    for (from, to, want) in [
        (
            s("auto", &["default", "infra"]),
            s("auto", &["infra", "default"]),
            "equal",
        ),
        (
            s("auto", &["default", "infra"]),
            s("auto", &["default"]),
            "downward",
        ),
        (
            s("bypass", &["default"]),
            s("auto", &["default"]),
            "downward",
        ), // a less permissive receiver
        (
            s("auto", &["default"]),
            s("auto", &["default", "infra"]),
            "upward",
        ), // a store the sender lacks
        (
            s("auto", &["default", "infra"]),
            s("bypass", &["default"]),
            "upward",
        ), // bypass while the sender doesn't
        (
            s("auto", &["default"]),
            s("auto", &["default", "github-jarvis2"]),
            "upward",
        ), // a repo is its store
        (s("bypass", &[]), s("bypass", &[]), "equal"),
    ] {
        assert_eq!(
            peer_direction(&from, &to).0,
            want,
            "{:?} {} → {:?}",
            from.stores,
            from.permission_mode,
            to.stores
        );
    }
}

/// sessions sLow (default), sHigh (default, infra; bypass) and sSame (default), the deliveries recorded. Holds the
/// serial lock (the delivery hook is global) and puts the hook back when dropped.
struct PeerRig {
    r: TestRouter,
    got: Arc<Mutex<Vec<PeerNote>>>,
    _s: std::sync::MutexGuard<'static, ()>,
}

impl Drop for PeerRig {
    fn drop(&mut self) {
        *DELIVER_PEER_HOOK.write().unwrap_or_else(|e| e.into_inner()) = None;
    }
}

fn peer_rig() -> PeerRig {
    let ser = serial();
    let r = new_test_router();
    for (id, m) in [("sLow", "mLow"), ("sHigh", "mHigh"), ("sSame", "mSame")] {
        add_session(&r, id, "started", m, false);
    }
    r.st.do_(|d| {
        for (id, stores, mode) in [
            ("sLow", vec!["default"], "auto"),
            ("sHigh", vec!["default", "infra"], "bypass"),
            ("sSame", vec!["default"], "auto"),
        ] {
            if let Some(s) = d.sessions.get_mut(id) {
                s.stores = Some(stores.iter().map(|x| x.to_string()).collect());
                s.permission_mode = mode.into();
            }
        }
    });
    let got: Arc<Mutex<Vec<PeerNote>>> = Arc::default();
    let g = got.clone();
    *DELIVER_PEER_HOOK.write().unwrap_or_else(|e| e.into_inner()) =
        Some(Arc::new(move |_, n, _| {
            g.lock().unwrap_or_else(|e| e.into_inner()).push(n.clone());
            Ok(())
        }));
    PeerRig { r, got, _s: ser }
}

impl PeerRig {
    fn notes(&self) -> Vec<PeerNote> {
        self.got.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
    fn wait_notes(&self, n: usize) -> Vec<PeerNote> {
        wait_for("deliveries", || self.notes().len() >= n);
        self.notes()
    }
}

fn outcome_of(r: &Router, session: &str, f: impl Fn(&crate::outcomes::Outcome) -> bool) -> bool {
    r.st.read(|d| d.outcomes.get(session).is_some_and(|l| l.iter().any(&f)))
}

/// equal and downward wait for Deyao too (DECISIONS 272): an Inbox request each, delivered with the verified sender
/// once he approves it
#[test]
fn peer_equal_and_downward_wait_for_deyao() {
    let pr = peer_rig();
    let r = &pr.r;
    let (m, mh) = (new_test_machine(r, "mLow"), r.machine_handler());
    let (code, out) = m.do_(
        &mh,
        "POST",
        "/m/api/requests/peer",
        r#"{"to": "label sSame", "text": "hello"}"#,
    );
    assert!(
        code == 200
            && out["direction"] == "equal"
            && out["to"] == "sSame"
            && out["waiting"] == "inbox"
            && out.get("delivering").is_none_or(Value::is_null),
        "{code} {out}"
    );
    let id = out["id"].as_str().unwrap_or_default().to_string();
    let it = r.inbox_item(&id).unwrap_or_default();
    assert!(
        it.kind == REQUEST_KIND_PEER
            && it.params.text == "hello"
            && it.session == "sSame"
            && it
                .explanation
                .starts_with("Equal: both hold the same stores in the same mode."),
        "{it:?}"
    );
    std::thread::sleep(Duration::from_millis(50));
    assert!(
        pr.notes().is_empty(),
        "an equal message was delivered before Deyao approved it"
    );
    let (code, out) = inbox_do(r, "POST", &format!("/api/requests/{id}/approve"), "", false);
    assert!(
        code == 200 && out["direction"] == "equal",
        "approve: {code} {out}"
    );
    let n = pr.wait_notes(1)[0].clone();
    assert!(
        n.from == "sLow"
            && n.from_title == "label sLow"
            && n.to == "sSame"
            && n.direction == "equal"
            && n.text == "hello"
            && n.approved
            && n.from_stores.join(",") == "default"
            && n.from_mode == "auto",
        "{n:?}"
    );
    // the sender names no one else: the caller is the machine's session, whatever the body says
    let (code, _) = m.do_(
        &mh,
        "POST",
        "/m/api/requests/peer",
        r#"{"to": "sLow", "text": "me"}"#,
    );
    assert_eq!(code, 400, "to itself");
    let (code, _) = m.do_(
        &mh,
        "POST",
        "/m/api/requests/peer",
        r#"{"to": "nobody", "text": "x"}"#,
    );
    assert_eq!(code, 400, "to nobody");
    // downward: sHigh → sLow
    let h = new_test_machine(r, "mHigh");
    let (code, out) = h.do_(
        &mh,
        "POST",
        "/m/api/requests/peer",
        r#"{"to": "sLow", "text": "do this"}"#,
    );
    assert!(
        code == 200 && out["direction"] == "downward" && out["waiting"] == "inbox",
        "{code} {out}"
    );
    let id2 = out["id"].as_str().unwrap_or_default().to_string();
    let it = r.inbox_item(&id2).unwrap_or_default();
    assert!(
        it.explanation
            .starts_with("Downward: the sender holds every store the receiver holds"),
        "{:?}",
        it.explanation
    );
    let (code, _) = inbox_do(
        r,
        "POST",
        &format!("/api/requests/{id2}/approve"),
        "",
        false,
    );
    assert_eq!(code, 200, "approve");
    let n = pr.wait_notes(2)[1].clone();
    assert!(
        n.from == "sHigh" && n.direction == "downward" && n.from_mode == "bypass" && n.approved,
        "{n:?}"
    );
}

/// upward waits in the Inbox, named as the sending session (never Jarvis 4), and goes once Deyao approves it
#[test]
fn peer_upward_waits_for_deyao() {
    let pr = peer_rig();
    let r = &pr.r;
    let (m, mh) = (new_test_machine(r, "mLow"), r.machine_handler());
    let (code, out) = m.do_(
        &mh,
        "POST",
        "/m/api/requests/peer",
        r#"{"to": "sHigh", "text": "run the deploy"}"#,
    );
    assert!(
        code == 200 && out["direction"] == "upward" && out["waiting"] == "inbox",
        "{code} {out}"
    );
    let id = out["id"].as_str().unwrap_or_default().to_string();
    let it = r.inbox_item(&id).unwrap_or_default();
    assert!(
        it.kind == REQUEST_KIND_PEER
            && it.params.text == "run the deploy"
            && it.session == "sHigh"
            && it.session_name == "label sHigh"
            && it.caller_text == "session “label sLow” (sLow)"
            && it.open.get("kind") == Some(&json!(REQUEST_KIND_PEER)),
        "{it:?}"
    );
    assert!(
        it.explanation.contains("Session “label sLow” (sLow; stores default; auto mode) wants to tell session “label sHigh” (sHigh; stores default, infra; bypass mode)")
            && it.explanation.contains("the receiver holds infra, which the sender doesn't")
            && it.explanation.contains("bypass mode and the sender doesn't"),
        "{:?}",
        it.explanation
    );
    std::thread::sleep(Duration::from_millis(50));
    assert!(pr.notes().is_empty(), "delivered before Deyao approved it");
    let (code, out) = inbox_do(r, "POST", &format!("/api/requests/{id}/approve"), "", false);
    assert!(code == 200 && out["ok"] == true, "approve: {code} {out}");
    let n = pr.wait_notes(1)[0].clone();
    assert!(
        n.direction == "upward"
            && n.approved
            && n.from == "sLow"
            && n.to == "sHigh"
            && n.text == "run the deploy",
        "{n:?}"
    );
    wait_for("approved outcome", || {
        outcome_of(r, "sLow", |o| {
            o.kind == REQUEST_KIND_PEER && o.outcome == OUTCOME_APPROVED && o.r#ref == id
        })
    });
    // denied: dropped, and the sender is told
    let (_, out) = m.do_(
        &mh,
        "POST",
        "/m/api/requests/peer",
        r#"{"to": "sHigh", "text": "again"}"#,
    );
    let id = out["id"].as_str().unwrap_or_default().to_string();
    let (code, _) = inbox_do(r, "DELETE", &format!("/api/requests/{id}"), "", false);
    assert_eq!(code, 200, "deny");
    assert!(
        outcome_of(r, "sLow", |o| o.r#ref == id && o.outcome == OUTCOME_DENIED),
        "the sender isn't told of the denial"
    );
    assert_eq!(pr.notes().len(), 1, "a denied message was delivered");
}

/// the core attests exactly the note's JSON, under the sender's name
#[test]
fn peer_attested_note() {
    let n = PeerNote {
        from: "sA".into(),
        to: "sB".into(),
        direction: "equal".into(),
        text: "x".into(),
        from_mode: "auto".into(),
        to_mode: "auto".into(),
        ..Default::default()
    };
    let (b, origin) = attested(&Delivery {
        kind: "peer".into(),
        peer: Some(n),
        ..Default::default()
    })
    .unwrap_or_else(|e| panic!("{e:#}"));
    assert!(
        origin == "session:sA" && String::from_utf8_lossy(&b).contains(r#""direction":"equal""#),
        "{} {origin}",
        String::from_utf8_lossy(&b)
    );
    assert!(
        attested(&Delivery {
            kind: "peer".into(),
            ..Default::default()
        })
        .is_err(),
        "a peer delivery without a note"
    );
}

/// the router attests the same bytes the machine checks (rust/machine/src/tests/outcomes.rs (the peer note))
#[test]
fn peer_note_json() {
    let want = r#"{"from":"sa","fromTitle":"A","fromStores":["default"],"fromMode":"auto","to":"sb","toStores":["default"],"toMode":"auto","direction":"equal","text":"hi"}"#;
    let n = PeerNote {
        from: "sa".into(),
        from_title: "A".into(),
        from_stores: vec!["default".into()],
        from_mode: "auto".into(),
        to: "sb".into(),
        to_stores: vec!["default".into()],
        to_mode: "auto".into(),
        direction: "equal".into(),
        text: "hi".into(),
        ..Default::default()
    };
    let (b, _) = peer_attested(Some(&n)).unwrap_or_else(|e| panic!("{e:#}"));
    assert_eq!(String::from_utf8_lossy(&b), want);
}

/// the cert's stores decide (the receiving machine checks against its cert), not the router's list
#[test]
fn peer_direction_uses_the_cert_stores() {
    let mk = |cert: &str| Session {
        stores: Some(vec!["default".into()]),
        cert: Some(crate::core::Doc {
            payload: cert.into(),
            sig: String::new(),
        }),
        ..Default::default()
    };
    let from = mk(r#"{"stores":["claude-x","default"]}"#);
    let to = mk(r#"{"stores":["claude-x","default","infra"]}"#);
    let (dir, extra, _) = peer_direction(&from, &to);
    assert!(
        dir == "upward" && extra.join(",") == "infra",
        "{dir} {extra:?}"
    );
    let n = peer_note(&from, &from, "x");
    assert_eq!(n.from_stores.join(","), "claude-x,default");
}

/// a peer message as a batch item (intent "peer"): every one waits in the batch with the session's other asks, one
/// Inbox entry, whatever its direction
#[test]
fn peer_in_a_batch() {
    let pr = peer_rig();
    let r = &pr.r;
    let (m, mh) = (new_test_machine(r, "mLow"), r.machine_handler());
    let (code, out) = m.do_(
        &mh,
        "POST",
        "/m/api/requests/batch",
        r#"{"summary":"status, and two messages","items":[
        {"intent":"grant","holder":"status","minutes":5},
        {"intent":"peer","to":"sHigh","text":"run the deploy"},
        {"intent":"peer","to":"label sSame","text":"fyi"}]}"#,
    );
    let bid = out["id"].as_str().unwrap_or_default().to_string();
    assert!(code == 200 && !bid.is_empty(), "{code} {out}");
    let (up, eq) = (out["items"][1].clone(), out["items"][2].clone());
    assert!(
        up["intent"] == "peer"
            && up["direction"] == "upward"
            && up["to"] == "sHigh"
            && !up["id"].is_null()
            && up.get("delivering").is_none_or(Value::is_null),
        "upward item: {up}"
    );
    assert!(
        eq["intent"] == "peer"
            && eq["direction"] == "equal"
            && eq["to"] == "sSame"
            && eq.get("delivering").is_none_or(Value::is_null)
            && !eq["id"].is_null(),
        "equal item: {eq}"
    );
    // both wait
    std::thread::sleep(Duration::from_millis(50));
    assert!(
        pr.notes().is_empty(),
        "delivered before Deyao approved: {:?}",
        pr.notes()
    );
    let full = r
        .inbox_batch_full(&bid, None)
        .unwrap_or_else(|| panic!("no batch"));
    let list = full["items"].as_array().cloned().unwrap_or_default();
    assert!(
        list.len() == 3
            && list[1]["kind"] == REQUEST_KIND_PEER
            && list[1]["params"]["text"] == "run the deploy"
            && list[1]["session"] == "sHigh"
            && list[1]["explanation"]
                .as_str()
                .is_some_and(|e| e.contains("the receiver holds infra, which the sender doesn't"))
            && list[2]["kind"] == REQUEST_KIND_PEER
            && list[2]["params"]["text"] == "fyi"
            && list[2]["session"] == "sSame",
        "{list:?}"
    );
    let id = up["id"].as_str().unwrap_or_default().to_string();
    let (code, out) = inbox_do(r, "POST", &format!("/api/requests/{id}/approve"), "", false);
    assert!(code == 200 && out["ok"] == true, "approve: {code} {out}");
    let n = pr.wait_notes(1)[0].clone();
    assert!(
        n.to == "sHigh" && n.direction == "upward" && n.approved && n.text == "run the deploy",
        "{n:?}"
    );
    // the outcome names the batch and the item's index, so the session reads it against its own signed filing
    wait_for("approved outcome", || {
        outcome_of(r, "sLow", |o| {
            o.r#ref == id && o.outcome == OUTCOME_APPROVED && o.item == 1 && o.batch == bid
        })
    });
    let eid = eq["id"].as_str().unwrap_or_default().to_string();
    let (code, _) = inbox_do(
        r,
        "POST",
        &format!("/api/requests/{eid}/approve"),
        "",
        false,
    );
    assert_eq!(code, 200, "approve");
    let n = pr.wait_notes(2)[1].clone();
    assert!(
        n.to == "sSame" && n.direction == "equal" && n.approved && n.text == "fyi",
        "{n:?}"
    );

    // a batch of one equal message: a batch, nothing sent yet
    let (code, out) = m.do_(
        &mh,
        "POST",
        "/m/api/requests/batch",
        r#"{"summary":"one note","items":[{"intent":"peer","to":"sSame","text":"second"}]}"#,
    );
    assert!(
        code == 200
            && !out["id"].is_null()
            && out["items"][0].get("delivering").is_none_or(Value::is_null),
        "{code} {out}"
    );
    // checked like the single endpoint: to itself, to nobody, empty, twice the same; nothing is filed or sent
    for items in [
        r#"{"intent":"peer","to":"sLow","text":"me"}"#,
        r#"{"intent":"peer","to":"nobody","text":"x"}"#,
        r#"{"intent":"peer","to":"sHigh","text":"  "}"#,
        r#"{"intent":"peer","to":"sSame","text":"x"},{"intent":"peer","to":"sSame","text":"x"}"#,
    ] {
        let body = format!(
            r#"{{"summary":"s","items":[{{"intent":"grant","holder":"archive","minutes":5}},{items}]}}"#
        );
        let (code, out) = m.do_(&mh, "POST", "/m/api/requests/batch", &body);
        assert_eq!(code, 400, "{items}: {out}");
    }
    // only a session sends one
    let (code, _) = inbox_do(
        r,
        "POST",
        "/api/requests/batch",
        r#"{"summary":"s","items":[{"intent":"peer","to":"sHigh","text":"x"}]}"#,
        true,
    );
    assert_eq!(code, 403, "from the app");
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(
        pr.notes().len(),
        2,
        "a refused or unapproved batch sent something"
    );
}
