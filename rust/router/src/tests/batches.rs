//! batches_test.go
use crate::batches::{BATCH_MAX_ITEMS, caller_load, prune_batches};
use crate::inbox::{
    Caller, INBOX_TTL, InboxItem, Origin, REQUEST_KIND_REPO, RequestParams, prune_requests,
};
use crate::testutil::{OpsRig, add_session, inbox_do, new_test_machine, new_test_router, wait_for};
use jarvis_go::GoTime;
use std::collections::BTreeMap;

fn batch_body(summary: &str, items: &[&str]) -> String {
    format!(
        r#"{{"summary": {}, "items": [{}]}}"#,
        serde_json::to_string(summary).unwrap_or_default(),
        items.join(",")
    )
}

/// a session files a batch of every kind it may ask for: one Inbox entry with the summary, every item carrying the
/// batch's id and end; a single item can be denied on its own; Deny on the batch takes everything else
#[test]
fn batch_from_a_session() {
    let rg = OpsRig::new();
    let r: &crate::router::Router = &rg;
    add_session(r, "sA", "started", "mA", false);
    add_session(r, "sB", "started", "mB", false);
    let m = new_test_machine(r, "mA");
    let h = r.arc().machine_handler();
    let summary = "Set up the YYC work: two sessions, a repo, and an unlock.";
    let body = batch_body(
        summary,
        &[
            r#"{"intent": "grant", "holder": "terminal", "minutes": 5}"#,
            r#"{"intent": "repo/add", "repo": "DE0CH/yyc", "explanation": "the new work lives here"}"#,
            r#"{"intent": "unlock", "explanation": "it waits on a store"}"#,
            r#"{"intent": "new-session", "requestId": "n1", "label": "one", "prompt": "do one", "stores": ["default"]}"#,
            r#"{"intent": "new-session", "requestId": "n2", "label": "two", "prompt": "do two"}"#,
        ],
    );
    let (code, out) = m.do_(&h, "POST", "/m/api/requests/batch", &body);
    assert_eq!(code, 200, "{out}");
    let bid = out["id"].as_str().unwrap_or("").to_string();
    let res = out["items"].as_array().cloned().unwrap_or_default();
    assert_eq!(res.len(), 5, "{res:?}");
    for x in &res {
        assert!(x["error"].is_null(), "an item failed: {x}");
    }
    wait_for("the new sessions' approvals", || {
        let bs = rg.arc().inbox_batches(None);
        bs.len() == 1 && bs[0].preparing == 0 && bs[0].items.len() == 5
    });
    let b = rg.arc().inbox_batches(None).remove(0);
    assert!(
        b.id == bid
            && b.summary == summary
            && b.caller_text.starts_with("session “label sA”")
            && b.call.path == "/api/requests/batch"
            && b.expires.sub(&b.created) == INBOX_TTL,
        "{b:?}"
    );
    let items: BTreeMap<String, InboxItem> = rg
        .arc()
        .inbox()
        .into_iter()
        .map(|it| (it.id.clone(), it))
        .collect();
    let mut kinds = vec![];
    for id in &b.items {
        let it = &items[id];
        kinds.push(it.kind.clone());
        assert!(
            it.batch == bid
                && it.expires == Some(b.expires)
                && it.call.path == "/api/requests/batch"
                && it.call.args.contains_key("intent"),
            "{it:?}"
        );
    }
    assert_eq!(
        kinds.join(","),
        "grant,repo-key,unlock,new-session,new-session"
    );
    let (code, out) = inbox_do(r, "GET", &format!("/api/requests/batches/{bid}"), "", true);
    assert!(
        code == 200 && out["items"].as_array().map(Vec::len) == Some(5),
        "{code} {out}"
    );
    let (code, out) = m.do_(&h, "GET", "/m/api/requests", "");
    assert!(
        code == 200 && out["batches"].as_array().map(Vec::len) == Some(1),
        "{code} {out}"
    );
    let unlock = items
        .values()
        .find(|it| it.kind == "unlock")
        .cloned()
        .unwrap_or_default();
    assert!(
        unlock.open.get("kind").and_then(|v| v.as_str()) == Some("unlock")
            && unlock
                .open
                .get("options")
                .and_then(|o| o["sessionId"].as_str())
                == Some("sA")
            && unlock.explanation == "it waits on a store",
        "{unlock:?}"
    );
    // one item denied on its own: out of the batch, the rest stay
    let (code, _) = inbox_do(
        r,
        "DELETE",
        &format!("/api/requests/{}", unlock.id),
        "",
        true,
    );
    assert_eq!(code, 200);
    let bs = rg.arc().inbox_batches(None);
    assert!(bs.len() == 1 && bs[0].items.len() == 4, "{bs:?}");
    // Deny the batch: requests gone, the proposed sessions gone (their approvals rejected)
    let (code, out) = inbox_do(
        r,
        "DELETE",
        &format!("/api/requests/batches/{bid}"),
        "",
        true,
    );
    assert_eq!(code, 200, "{out}");
    assert!(rg.arc().inbox().is_empty() && rg.arc().inbox_batches(None).is_empty());
    rg.st.do_(|d| {
        for s in d.sessions.values() {
            assert_ne!(s.state, "approval", "a proposed session is left: {s:?}");
        }
    });
    let (code, out) = inbox_do(
        r,
        "DELETE",
        &format!("/api/requests/batches/{bid}"),
        "",
        true,
    );
    assert!(
        code == 200 && out["gone"] == true,
        "denied twice: {code} {out}"
    );
}

/// nothing is filed when any item is bad; the summary is required; a batch has 1–20 items, none the same twice
#[test]
fn batch_checks_every_item_first() {
    let t = new_test_router();
    let r: &crate::router::Router = &t;
    add_session(r, "sA", "started", "mA", false);
    add_session(r, "sB", "started", "mB", false);
    let m = new_test_machine(r, "mA");
    let h = r.arc().machine_handler();
    let ok = r#"{"intent": "repo/add", "repo": "DE0CH/a"}"#;
    let many: Vec<&str> = std::iter::repeat_n(ok, BATCH_MAX_ITEMS + 1).collect();
    for (name, body, want) in [
        (
            "a Jarvis 1 import",
            batch_body(
                "s",
                &[r#"{"intent": "jarvis1-import", "id": "x", "stores": ["default"]}"#],
            ),
            403,
        ),
        ("no summary", batch_body("  ", &[ok]), 400),
        (
            "unknown intent",
            batch_body("s", &[r#"{"intent": "format-disk"}"#]),
            400,
        ),
        (
            "the same twice",
            batch_body(
                "s",
                &[
                    ok,
                    r#"{"intent": "repo/add", "repo": "https://github.com/DE0CH/a"}"#,
                ],
            ),
            400,
        ),
        ("empty", batch_body("s", &[]), 400),
        ("too many", batch_body("s", &many), 400),
        (
            "an attachment not uploaded",
            batch_body(
                "s",
                &[r#"{"intent": "new-session", "prompt": "p", "attachments": {"uploadId": "u"}}"#],
            ),
            400,
        ),
    ] {
        let (code, out) = m.do_(&h, "POST", "/m/api/requests/batch", &body);
        assert_eq!(code, want, "{name}: {out}");
        assert!(r.arc().inbox().is_empty(), "{name}: something was filed");
    }
    // the setup session and a session's actions file batches too; a standalone request already waiting joins
    let (q, _) = r
        .file_request(
            REQUEST_KIND_REPO,
            RequestParams {
                action: "add".into(),
                repo: "DE0CH/b".into(),
                ..Default::default()
            },
            "why",
            Origin {
                caller: Caller {
                    kind: "setup".into(),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .expect("file");
    let (code, out) = inbox_do(
        r,
        "POST",
        "/setup/requests/batch",
        &batch_body(
            "two repos",
            &[
                r#"{"intent": "repo/add", "repo": "DE0CH/b"}"#,
                r#"{"intent": "repo/remove", "repo": "DE0CH/c"}"#,
            ],
        ),
        false,
    );
    assert_eq!(code, 200, "{out}");
    let first = &out["items"][0];
    assert!(
        first["id"] == q.id.as_str() && first["duplicate"] == true,
        "{first}"
    );
    let it = r.arc().inbox_item(&q.id).unwrap_or_default();
    assert_eq!(
        it.batch,
        out["id"].as_str().unwrap_or("-"),
        "the waiting request didn't join"
    );
    let (code, out) = m.do_(
        &h,
        "POST",
        "/m/api/actions/requests/batch",
        &batch_body("unlock", &[r#"{"intent": "unlock", "session": "sB"}"#]),
    );
    assert_eq!(code, 200, "{out}");
    let id = r
        .arc()
        .inbox_batches(Some(&Caller {
            kind: "actions".into(),
            session: "sA".into(),
        }))
        .first()
        .map(|b| b.id.clone())
        .unwrap_or_default();
    let (code, out) = m.do_(
        &h,
        "POST",
        &format!("/m/api/actions/requests/batches/{id}/deny"),
        "",
    );
    assert_eq!(code, 200, "{out}");
}

/// a batch counts once toward the caller's limits: one of its 20 waiting requests, one of its 3 waiting proposals
#[test]
fn batch_limits() {
    let rg = OpsRig::new();
    let r: &crate::router::Router = &rg;
    add_session(r, "sA", "started", "mA", false);
    let m = new_test_machine(r, "mA");
    let h = r.arc().machine_handler();
    let items: Vec<String> = (0..BATCH_MAX_ITEMS)
        .map(|i| format!(r#"{{"intent": "new-session", "requestId": "b{i}", "prompt": "p{i}"}}"#))
        .collect();
    let refs: Vec<&str> = items.iter().map(String::as_str).collect();
    let (code, out) = m.do_(
        &h,
        "POST",
        "/m/api/requests/batch",
        &batch_body("twenty", &refs),
    );
    assert_eq!(code, 200, "{out}");
    for i in 1..=2 {
        let (code, out) = m.do_(
            &h,
            "POST",
            "/m/api/sessions",
            &format!(r#"{{"requestId":"s{i}","prompt":"p","explanation":"e"}}"#),
        );
        assert_eq!(code, 200, "proposal {i} next to a batch: {out}");
    }
    wait_for("approvals", || {
        let mut n = 0;
        rg.st.do_(|d| n = d.approvals.len());
        n == BATCH_MAX_ITEMS + 2
    });
    let (code, _) = m.do_(
        &h,
        "POST",
        "/m/api/sessions",
        r#"{"requestId":"s3","prompt":"p","explanation":"e"}"#,
    );
    assert_eq!(
        code, 429,
        "a fourth waiting proposal (a batch counts as one)"
    );
    let (code, _) = m.do_(
        &h,
        "POST",
        "/m/api/requests/batch",
        &batch_body("more", &[r#"{"intent": "new-session", "prompt": "p"}"#]),
    );
    assert_eq!(code, 429, "a batch proposing past the limit");
    let mut reqs = 0;
    rg.st.do_(|d| {
        reqs = caller_load(
            d,
            &Caller {
                kind: "session".into(),
                session: "sA".into(),
            },
        )
        .0
    });
    assert_eq!(reqs, 1);
}

/// the whole batch goes after 10 minutes: its requests, its approvals (rejected), the batch itself
#[test]
fn batch_expires() {
    let rg = OpsRig::new();
    let r: &crate::router::Router = &rg;
    add_session(r, "sA", "started", "mA", false);
    let (code, out) = inbox_do(
        r,
        "POST",
        "/setup/requests/batch",
        &batch_body(
            "both",
            &[
                r#"{"intent": "unlock", "session": "sA"}"#,
                r#"{"intent": "new-session", "prompt": "p", "label": "x"}"#,
            ],
        ),
        false,
    );
    assert_eq!(code, 200, "{out}");
    wait_for("approval", || {
        let bs = rg.arc().inbox_batches(None);
        bs.len() == 1 && bs[0].items.len() == 2
    });
    let later = GoTime::now().add(INBOX_TTL + time::Duration::minutes(1));
    rg.arc().expire_approvals(later);
    rg.st.do_(|d| {
        prune_requests(d, later);
        prune_batches(d, later);
        assert!(
            d.approvals.is_empty() && d.inbox.is_empty() && d.batches.is_empty(),
            "approvals {} inbox {} batches {}",
            d.approvals.len(),
            d.inbox.len(),
            d.batches.len()
        );
    });
}
