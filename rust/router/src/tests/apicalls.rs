use crate::apicalls::{CALL_RULES, CallRule, REQUEST_KIND_CALL};
use crate::inbox::{Caller, app_caller};
use crate::testutil::{add_session, inbox_do, new_test_machine, new_test_router};

/// the sweep: every app route is classified in CALL_RULES, and CALL_RULES names no route that no longer exists
#[test]
fn every_app_route_classified() {
    let t = new_test_router();
    let _ = t.handlers();
    let pats = t.app_patterns.get().cloned().unwrap_or_default();
    let missing: Vec<&String> = pats
        .keys()
        .filter(|p| !CALL_RULES.iter().any(|(q, _)| q == p))
        .collect();
    let stale: Vec<&str> = CALL_RULES
        .iter()
        .map(|(p, _)| *p)
        .filter(|p| !pats.contains_key(*p))
        .collect();
    assert!(
        missing.is_empty() && stale.is_empty(),
        "apicalls.rs CALL_RULES: unclassified app routes {missing:?}; no longer app routes {stale:?}"
    );
    for (p, rule) in CALL_RULES {
        if p.contains("/api/requests") || p.contains("/api/approvals") {
            assert!(
                matches!(rule, CallRule::No),
                "{p} is the Inbox: CallRule::No"
            );
        }
    }
}

/// a session's actions ask for an app call; Deyao approves it; the call runs as him and the session reads the result
#[test]
fn api_call_request() {
    let t = new_test_router();
    add_session(&t, "sR", "started", "mR", false);
    add_session(&t, "sO", "started", "mO", false);
    let (m, o, mh) = (
        new_test_machine(&t, "mR"),
        new_test_machine(&t, "mO"),
        t.machine_handler(),
    );
    // refused: the Inbox itself, no such route, a bad method, a full URL, no explanation
    for body in [
        r#"{"method": "POST", "path": "/api/requests/x/approve", "explanation": "x"}"#,
        r#"{"method": "GET", "path": "/api/nothing-here", "explanation": "x"}"#,
        r#"{"method": "TRACE", "path": "/api/sizes", "explanation": "x"}"#,
        r#"{"method": "GET", "path": "https://evil.example/api/sizes", "explanation": "x"}"#,
        r#"{"method": "GET", "path": "/api/sizes"}"#,
    ] {
        let (code, out) = m.do_(&mh, "POST", "/m/api/actions/requests/call", body);
        assert_eq!(code, 400, "{body}: {out}");
    }
    let (code, out) =
        m.do_(&mh, "POST", "/m/api/actions/requests/call", r#"{"method": "post", "path": "/api/sessions/sO/auto-pause", "body": {"on": false}, "explanation": "keep sO up"}"#);
    assert_eq!(code, 200, "{out}");
    let id = out["id"].as_str().unwrap_or("").to_string();
    let it = t
        .inbox_item(&id)
        .unwrap_or_else(|| panic!("not in the Inbox"));
    assert!(
        it.kind == REQUEST_KIND_CALL
            && it.params.method == "POST"
            && it.params.path == "/api/sessions/sO/auto-pause"
            && it.params.body == r#"{"on":false}"#
            && it.caller_text == "the actions of session “label sR” (sR)"
            && it.call.args["route"] == "POST /api/sessions/{id}/auto-pause",
        "{it:?}"
    );
    let (code, out) = m.do_(
        &mh,
        "GET",
        &format!("/m/api/actions/requests/call/{id}"),
        "",
    );
    assert!(code == 200 && out["state"] == "pending", "{code} {out}");
    assert_eq!(
        o.do_(
            &mh,
            "GET",
            &format!("/m/api/actions/requests/call/{id}"),
            ""
        )
        .0,
        404,
        "another session read it"
    );
    // approved from the app: the call runs, the session reads its status and body
    let (code, out) = inbox_do(&t, "POST", &format!("/api/requests/{id}/approve"), "", true);
    assert!(
        code == 200 && out["state"] == "done" && out["status"] == 200,
        "approve: {code} {out}"
    );
    assert!(
        t.inbox_item(&id).is_none(),
        "an approved request stayed in the Inbox"
    );
    let (code, out) = m.do_(
        &mh,
        "GET",
        &format!("/m/api/actions/requests/call/{id}"),
        "",
    );
    assert!(
        code == 200
            && out["state"] == "done"
            && out["status"] == 200
            && out["body"].as_str().unwrap_or("").contains("off")
            && out["approvedBy"] == "app",
        "{code} {out}"
    );
    assert_eq!(
        inbox_do(&t, "POST", &format!("/api/requests/{id}/approve"), "", true).0,
        404,
        "approved twice"
    );
    // denied: the session reads that
    let (_, out) = m.do_(
        &mh,
        "POST",
        "/m/api/actions/requests/call",
        r#"{"method": "GET", "path": "/api/sizes", "explanation": "sizes"}"#,
    );
    let id = out["id"].as_str().unwrap_or("").to_string();
    assert_eq!(
        inbox_do(&t, "DELETE", &format!("/api/requests/{id}"), "", false).0,
        200,
        "deny"
    );
    let (code, out) = m.do_(
        &mh,
        "GET",
        &format!("/m/api/actions/requests/call/{id}"),
        "",
    );
    assert!(code == 200 && out["state"] == "denied", "{code} {out}");
    // a session that pauses: its call waits and runs once approved; a destroyed one's goes
    let (_, out) = m.do_(
        &mh,
        "POST",
        "/m/api/actions/requests/call",
        r#"{"method": "GET", "path": "/api/sizes", "explanation": "sizes again"}"#,
    );
    let id = out["id"].as_str().unwrap_or("").to_string();
    let set = |st: &str| {
        t.st.do_(|d| {
            if let Some(s) = d.sessions.get_mut("sR") {
                s.state = st.into();
            }
        })
    };
    set("pausing");
    assert!(
        t.inbox_item(&id).is_some(),
        "a pausing session's call left the Inbox"
    );
    let (code, out) = inbox_do(&t, "POST", &format!("/api/requests/{id}/approve"), "", true);
    assert!(
        code == 200 && out["state"] == "done",
        "a pausing session's call didn't run: {code} {out}"
    );
    set("started");
    let (_, out) = m.do_(
        &mh,
        "POST",
        "/m/api/actions/requests/call",
        r#"{"method": "GET", "path": "/api/sizes", "explanation": "sizes a third time"}"#,
    );
    let id = out["id"].as_str().unwrap_or("").to_string();
    set("destroyed");
    assert!(
        t.inbox_item(&id).is_none(),
        "a destroyed session's call stayed in the Inbox"
    );
}

/// what an approved call makes is its requester's: the route sees the session's actions as its caller
#[test]
fn replayed_call_keeps_its_caller() {
    let c = Caller {
        kind: "actions".into(),
        session: "sR".into(),
    };
    let mut req =
        jarvis_nethttp::Req::new("POST", "/api/sessions", b"").with_header("cf-access-token", "x");
    assert_eq!(app_caller(&req).kind, "app");
    req.ctx.insert(
        crate::apicalls::ON_BEHALF_KEY.into(),
        jarvis_go::marshal(&c),
    );
    assert_eq!(app_caller(&req), c);
}

/// an API call goes in a batch beside the session's other asks (DECISIONS 183): checked as alone, filed as the batch's
/// item, approved on its own (no Face ID), its result read by the session like its actions' own
#[test]
fn an_api_call_in_a_batch() {
    let t = new_test_router();
    add_session(&t, "sR", "started", "mR", false);
    add_session(&t, "sO", "started", "mO", false);
    let (m, o, mh) = (
        new_test_machine(&t, "mR"),
        new_test_machine(&t, "mO"),
        t.machine_handler(),
    );
    // a bad call refuses the whole batch, nothing filed
    for item in [
        r#"{"intent":"call","method":"POST","path":"/api/requests/x/approve"}"#,
        r#"{"intent":"call","method":"TRACE","path":"/api/sizes"}"#,
        r#"{"intent":"call","method":"GET","path":"/api/nothing-here"}"#,
    ] {
        let body = format!(
            r#"{{"summary":"s","items":[{{"intent":"grant","holder":"status","minutes":5}},{item}]}}"#
        );
        let (code, out) = m.do_(&mh, "POST", "/m/api/requests/batch", &body);
        assert_eq!(code, 400, "{item}: {out}");
    }
    assert!(t.inbox().is_empty(), "filed");
    // the setup session and Deyao's own page may ask for calls too (each runs only once approved)
    let (code, out) = inbox_do(
        &t,
        "POST",
        "/api/requests/batch",
        r#"{"summary":"s","items":[{"intent":"call","method":"GET","path":"/api/sizes"}]}"#,
        true,
    );
    assert_eq!(code, 200, "{out}");
    t.st.do_(|d| {
        d.inbox.clear();
        d.batches.clear();
    });
    let (code, out) = m.do_(
        &mh,
        "POST",
        "/m/api/requests/batch",
        r#"{"summary":"keep sO up and watch it","items":[
		{"intent":"grant","holder":"status","minutes":5},
		{"intent":"call","method":"post","path":"/api/sessions/sO/auto-pause","body":{"on":false},"explanation":"keep sO up"}]}"#,
    );
    assert_eq!(code, 200, "{out}");
    let bid = out["id"].as_str().unwrap_or("").to_string();
    let id = out["items"][1]["id"].as_str().unwrap_or("").to_string();
    let it = t
        .inbox_item(&id)
        .unwrap_or_else(|| panic!("not in the Inbox"));
    assert!(
        it.kind == REQUEST_KIND_CALL
            && it.batch == bid
            && it.params.method == "POST"
            && it.params.body == r#"{"on":false}"#
            && it.explanation == "keep sO up"
            && it.call.args["route"] == "POST /api/sessions/{id}/auto-pause"
            && it.session == "sR",
        "{it:?}"
    );
    let full = t.inbox_batch_full(&bid, None).unwrap_or_default();
    assert!(
        full["items"].as_array().map_or(0, Vec::len) == 2 && full["items"][1]["id"] == id.as_str(),
        "batch items {full}"
    );
    let (code, out) = m.do_(
        &mh,
        "GET",
        &format!("/m/api/actions/requests/call/{id}"),
        "",
    );
    assert!(code == 200 && out["state"] == "pending", "{code} {out}");
    assert_eq!(
        o.do_(
            &mh,
            "GET",
            &format!("/m/api/actions/requests/call/{id}"),
            ""
        )
        .0,
        404,
        "another session read it"
    );
    let (code, out) = inbox_do(&t, "POST", &format!("/api/requests/{id}/approve"), "", true);
    assert!(
        code == 200 && out["state"] == "done" && out["status"] == 200,
        "approve: {code} {out}"
    );
    let (code, out) = m.do_(
        &mh,
        "GET",
        &format!("/m/api/actions/requests/call/{id}"),
        "",
    );
    assert!(code == 200 && out["state"] == "done", "{code} {out}");
    // the session hears it as the batch's item 2
    let oc = t.st.do_(|d| {
        d.outcomes
            .get("sR")
            .and_then(|os| os.iter().find(|x| x.r#ref == id).cloned())
    });
    let oc = oc.unwrap_or_else(|| panic!("no outcome"));
    assert!(
        oc.item == 1
            && oc.batch == bid
            && oc.outcome == crate::outcomes::OUTCOME_APPROVED
            && oc.status == 200,
        "outcome {oc:?}"
    );
    // the batch's other item still waits in it
    let b = t.inbox_batch_full(&bid, None).unwrap_or_default();
    assert_eq!(b["items"].as_array().map_or(0, Vec::len), 1, "{b}");
}
