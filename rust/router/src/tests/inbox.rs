//! router/inbox_test.go
use crate::inbox::{
    ApiCall, Caller, EXPLANATION_LINES, EXPLANATION_MAX, INTENTS, InboxItem, Origin,
    REQUEST_KIND_GRANT, REQUEST_KIND_REPO, REQUEST_PER_CALLER, RequestIn, RequestParams,
    clean_explanation, intent, prune_requests,
};
use crate::repos::KeyAnswer;
use crate::testutil::*;
use jarvis_go::GoTime;
use serde_json::json;
use std::collections::BTreeMap;
use std::time::Duration;

fn origin(kind: &str) -> Origin {
    Origin {
        caller: Caller {
            kind: kind.into(),
            ..Default::default()
        },
        ..Default::default()
    }
}

#[test]
fn inbox_from_each_caller() {
    let r = new_test_router();
    add_session(&r, "sA", "started", "mA", false);
    add_session(&r, "sB", "started", "mB", false);
    let (m, mh) = (new_test_machine(&r, "mA"), r.machine_handler());

    // a session: a repo add, with its explanation; the caller comes from the machine key, not from the body
    let (code, out) = m.do_(
        &mh,
        "POST",
        "/m/api/requests/repo/add",
        "{\"repo\": \"https://github.com/DE0CH/claude-env.git\", \"explanation\": \"I need to push the skill.\u{202e}\", \"caller\": \"setup\"}",
    );
    assert!(code == 200 && out["duplicate"] == false, "{code} {out}");
    let id = out["id"].as_str().unwrap_or_default().to_string();
    // the same again: one request
    let (code, out) = m.do_(
        &mh,
        "POST",
        "/m/api/requests/repo/add",
        r#"{"repo": "DE0CH/claude-env", "explanation": "again"}"#,
    );
    assert!(
        code == 200 && out["id"] == json!(id) && out["duplicate"] == true,
        "dedup: {code} {out}"
    );
    // a session may ask anything for any session (its actions could already; each still waits for Deyao)
    for (path, body) in [
        (
            "/m/api/requests/repo/remove",
            r#"{"repo": "DE0CH/claude-env", "explanation": "x"}"#,
        ),
        (
            "/m/api/requests/grant",
            r#"{"session": "sB", "holder": "terminal", "explanation": "x"}"#,
        ),
        (
            "/m/api/requests/unlock",
            r#"{"session": "sB", "explanation": "x"}"#,
        ),
    ] {
        let (code, out) = m.do_(&mh, "POST", path, body);
        assert_eq!(code, 200, "{path}: {out}");
        let _ = r.deny_request(out["id"].as_str().unwrap_or_default());
    }
    let (code, _) = m.do_(
        &mh,
        "POST",
        "/m/api/requests/grant",
        r#"{"holder": "terminal"}"#,
    );
    assert_eq!(code, 400, "no explanation");
    // its own grant, the session left out of the body
    let (code, out) = m.do_(
        &mh,
        "POST",
        "/m/api/requests/grant",
        r#"{"holder": "terminal", "minutes": 5, "explanation": "let me see the screen"}"#,
    );
    assert_eq!(code, 200, "{out}");
    let (code, _) = m.do_(
        &mh,
        "POST",
        "/m/api/requests/grant",
        r#"{"holder": "nope", "explanation": "x"}"#,
    );
    assert_eq!(code, 400, "unknown holder");

    // the web page (no device token) and the app
    let (code, out) = inbox_do(
        &r,
        "POST",
        "/api/requests/unlock",
        r#"{"session": "sB"}"#,
        false,
    );
    assert_eq!(code, 200, "web: {out}");
    let (code, out) = inbox_do(
        &r,
        "POST",
        "/api/requests/repo/remove",
        r#"{"repo": "DE0CH/china-train", "explanation": "done with it"}"#,
        true,
    );
    assert_eq!(code, 200, "app: {out}");

    let items = r.inbox();
    assert_eq!(items.len(), 4, "{items:?}");
    let by_kind: BTreeMap<String, InboxItem> = items
        .into_iter()
        .map(|it| (format!("{} {}", it.kind, it.params.action), it))
        .collect();
    let repo = by_kind.get("repo-key add").cloned().unwrap_or_default();
    assert!(
        repo.caller.kind == "session"
            && repo.caller.session == "sA"
            && repo.caller_text.starts_with("session “label sA”")
            && repo.call.path == "/api/requests/repo/add"
            && repo.call.args.get("repo") == Some(&json!("DE0CH/claude-env"))
            && repo.explanation == "I need to push the skill.",
        "{repo:?}"
    );
    let o = repo.open.get("options").cloned().unwrap_or_default();
    assert!(
        repo.open.get("kind") == Some(&json!("repo-key"))
            && o["repo"] == "DE0CH/claude-env"
            && o["action"] == "add"
            && o["inboxId"] == json!(repo.id),
        "open: {:?}",
        repo.open
    );
    let g = by_kind.get("grant ").cloned().unwrap_or_default();
    let go = g.open.get("options").cloned().unwrap_or_default();
    assert!(
        g.open.get("kind") == Some(&json!("grant"))
            && go["minutes"] == 5
            && go["sessionId"] == "sA",
        "grant: {g:?}"
    );
    let u = by_kind.get("unlock ").cloned().unwrap_or_default();
    assert!(
        u.caller_text == "Deyao, from the web page" && u.explanation.is_empty(),
        "unlock: {u:?}"
    );
    let rm = by_kind.get("repo-key remove").cloned().unwrap_or_default();
    assert_eq!(
        rm.caller_text, "Deyao, from the Jarvis 4 app",
        "remove: {rm:?}"
    );
    // a session lists only its own
    let (code, out) = m.do_(&mh, "GET", "/m/api/requests", "");
    assert!(
        code == 200 && out["requests"].as_array().is_some_and(|a| a.len() == 2),
        "{code} {out}"
    );

    // Deny drops it; done drops it; the core answer for the repo drops the add
    let (code, _) = inbox_do(&r, "DELETE", &format!("/api/requests/{}", u.id), "", true);
    assert_eq!(code, 200);
    let _ = inbox_do(
        &r,
        "POST",
        &format!("/api/requests/{}/done", g.id),
        "",
        true,
    );
    let _ = r.apply_key_answer(
        KeyAnswer {
            kind: "deploy-key-added".into(),
            repo: "DE0CH/claude-env".into(),
            ..Default::default()
        },
        &crate::core::Doc::default(),
    );
    let items = r.inbox();
    assert!(
        items.len() == 1 && items[0].kind == "repo-key" && items[0].params.action == "remove",
        "{items:?}"
    );
    // a destroyed session's requests go; expired ones go
    r.st.do_(|d| {
        for q in d.inbox.values_mut() {
            q.expires = GoTime::from_unix(GoTime::now().unix() - 1);
        }
    });
    assert!(r.inbox().is_empty(), "expired: {:?}", r.inbox());
}

#[test]
fn inbox_grant_rule_and_limits() {
    let r = new_test_router();
    add_session(&r, "sA", "started", "mA", false);
    let (q, _) = r
        .file_request(
            REQUEST_KIND_GRANT,
            RequestParams {
                session: "sA".into(),
                holder: "archive".into(),
                days: 30,
                ..Default::default()
            },
            "",
            origin("web"),
        )
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert!(q.params.days == 30 && q.params.minutes == 0, "{q:?}");
    let it = r.inbox_item(&q.id).unwrap_or_default();
    let o = it.open.get("options").cloned().unwrap_or_default();
    let until = GoTime::parse(o["until"].as_str().unwrap_or_default()).unwrap_or_default();
    assert!(
        o["grantKind"] == "rule" && until.sub(&GoTime::now()) >= time::Duration::hours(29 * 24),
        "{o}"
    );
    for p in [
        RequestParams {
            session: "sA".into(),
            holder: "terminal".into(),
            minutes: 11,
            ..Default::default()
        },
        RequestParams {
            session: "sA".into(),
            holder: "terminal".into(),
            days: 400,
            ..Default::default()
        },
        RequestParams {
            session: "sA".into(),
            holder: "terminal".into(),
            days: 3,
            minutes: 3,
            ..Default::default()
        },
        RequestParams {
            session: "nope".into(),
            holder: "terminal".into(),
            ..Default::default()
        },
    ] {
        assert!(
            r.file_request(REQUEST_KIND_GRANT, p.clone(), "x", origin("setup"))
                .is_err(),
            "{p:?} should be refused"
        );
    }
    // a setup request needs words; at most REQUEST_PER_CALLER pending per caller
    let repo = |name: &str| RequestParams {
        action: "add".into(),
        repo: name.into(),
        ..Default::default()
    };
    assert!(
        r.file_request(REQUEST_KIND_REPO, repo("a/b"), "  ", origin("setup"))
            .is_err(),
        "setup without an explanation"
    );
    for i in 0..REQUEST_PER_CALLER {
        let name = format!("a/r{}", char::from(b'a' + u8::try_from(i).unwrap_or(0)));
        r.file_request(REQUEST_KIND_REPO, repo(&name), "why", origin("setup"))
            .unwrap_or_else(|e| panic!("{e:#}"));
    }
    assert!(
        r.file_request(REQUEST_KIND_REPO, repo("a/zz"), "why", origin("setup"))
            .is_err(),
        "over the limit"
    );
}

#[test]
fn clean_explanations() {
    for (input, want) in [
        ("  plain  ", "plain"),
        ("a\r\n\r\n\r\nb", "a\n\nb"),
        ("tab\there\x1b[31mred\u{200b}", "tab here[31mred"),
        ("<b>kept as text</b>", "<b>kept as text</b>"),
        ("rtl \u{202e}gnp.exe\u{202c} trick", "rtl gnp.exe trick"),
    ] {
        assert_eq!(
            clean_explanation(input, false).unwrap_or_else(|e| panic!("{e:#}")),
            want,
            "{input:?}"
        );
    }
    assert!(
        clean_explanation(&"x".repeat(EXPLANATION_MAX + 1), false).is_err(),
        "too long"
    );
    assert!(
        clean_explanation(&"x\n".repeat(EXPLANATION_LINES + 1), false).is_err(),
        "too many lines"
    );
    assert!(clean_explanation("", true).is_err(), "required");
}

/// every intent endpoint makes a request the app can open: a kind the app lists and the shell has a page for
#[test]
fn every_intent_opens_a_page() {
    let r = new_test_router();
    add_session(&r, "sA", "started", "mA", false);
    let pages = ["repo-key", "grant", "unlock", "approval", "restore"];
    for name in INTENTS {
        let (kind, p) = intent(
            name,
            &RequestIn {
                repo: "DE0CH/x".into(),
                session: "sA".into(),
                holder: "terminal".into(),
                store: "default".into(),
                seq: 3,
                ..Default::default()
            },
        )
        .unwrap_or_else(|| panic!("{name}"));
        let o = Origin {
            caller: Caller {
                kind: "setup".into(),
                ..Default::default()
            },
            call: ApiCall {
                method: "POST".into(),
                path: format!("/setup/requests/{name}"),
                ..Default::default()
            },
            ..Default::default()
        };
        let (q, _) = r
            .file_request(kind, p, "why", o)
            .unwrap_or_else(|e| panic!("{name}: {e:#}"));
        let it = r.inbox_item(&q.id).unwrap_or_default();
        assert!(
            pages.contains(
                &it.open
                    .get("kind")
                    .and_then(|k| k.as_str())
                    .unwrap_or_default()
            ) && it
                .open
                .get("options")
                .is_some_and(|o| o["inboxId"] == json!(q.id))
                && !it.caller_text.is_empty()
                && !it.call.path.is_empty(),
            "{name}: {it:?}"
        );
    }
}

#[test]
fn approvals_in_the_inbox_with_their_caller() {
    let r = new_test_router();
    add_session(&r, "sA", "paused", "", false);
    r.note_origin(
        "sA",
        Origin {
            caller: Caller {
                kind: "web".into(),
                ..Default::default()
            },
            call: ApiCall {
                method: "POST".into(),
                path: "/api/sessions/sA/resume".into(),
                args: [("upgrade".to_string(), json!(true))].into_iter().collect(),
            },
            ..Default::default()
        },
    );
    r.add_approval(crate::state::Approval {
        kind: "resume-upgrade".into(),
        session: "sA".into(),
        ..Default::default()
    });
    r.add_approval(crate::state::Approval {
        kind: "add-store".into(),
        session: "sA".into(),
        origin: Some(Origin {
            caller: Caller {
                kind: "session".into(),
                session: "sA".into(),
            },
            ..Default::default()
        }),
        explanation: "need gmail".into(),
        ..Default::default()
    });
    let items = r.inbox();
    assert_eq!(items.len(), 2, "{items:?}");
    for it in &items {
        assert!(
            it.approval
                && it.open.get("kind") == Some(&json!("approval"))
                && it
                    .open
                    .get("options")
                    .is_some_and(|o| o["approvalId"] == json!(it.id)),
            "{it:?}"
        );
        match it.kind.as_str() {
            "resume-upgrade" => assert!(
                it.caller_text == "Deyao, from the web page"
                    && it.call.path == "/api/sessions/sA/resume",
                "{it:?}"
            ),
            "add-store" => assert!(
                it.explanation == "need gmail" && it.caller_text.starts_with("session "),
                "{it:?}"
            ),
            _ => {}
        }
    }
    // Deny on an approval rejects it: the resume stays paused
    r.deny_request(&items[0].id)
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert_eq!(r.inbox().len(), 1, "not dropped");
}

#[test]
fn setup_sessions_and_requests() {
    let r = new_test_router();
    add_session(&r, "sA", "started", "mA", false);
    let (code, out) = inbox_do(&r, "GET", "/setup/sessions", "", false);
    assert!(
        code == 200 && out["sessions"][0]["machineId"] == "mA",
        "{code} {out}"
    );
    let (code, out) = inbox_do(
        &r,
        "POST",
        "/setup/requests/repo/add",
        r#"{"repo": "DE0CH/claude-env", "explanation": "for the skill"}"#,
        false,
    );
    assert_eq!(code, 200, "{out}");
    let it = r
        .inbox_item(out["id"].as_str().unwrap_or_default())
        .unwrap_or_default();
    assert!(
        it.caller_text == "Claude (setup session)" && it.call.path == "/setup/requests/repo/add",
        "{it:?}"
    );
}

/// a session's actions (its machine key): resume only a paused session, deny an Inbox item, propose a session and
/// file a request — each named as that session's actions in the Inbox; nothing once the session stops running
#[test]
fn actions_key() {
    let r = new_test_router();
    add_session(&r, "sR", "started", "mR", false);
    add_session(&r, "sP", "paused", "", false);
    let (m, mh) = (new_test_machine(&r, "mR"), r.machine_handler());
    // a running session's resume: already what was asked, nothing done
    let (code, out) = m.do_(&mh, "POST", "/m/api/actions/sessions/sR/resume", "");
    assert_eq!(code, 200, "a running session's resume: {out}");
    let s =
        r.st.read(|d| d.sessions.get("sR").cloned().unwrap_or_default());
    assert!(
        s.state == "started" && s.machine_id == "mR",
        "the running session was touched: {s:?}"
    );
    let (code, out) = m.do_(&mh, "GET", "/m/api/actions/sessions", "");
    assert!(
        code == 200 && out["sessions"].as_array().is_some_and(|a| a.len() == 2),
        "{code} {out}"
    );
    let (code, out) = m.do_(
        &mh,
        "POST",
        "/m/api/actions/requests/unlock",
        r#"{"session": "sP", "explanation": "it waits for a store"}"#,
    );
    assert_eq!(code, 200, "{out}");
    let id = out["id"].as_str().unwrap_or_default().to_string();
    let it = r.inbox_item(&id).unwrap_or_default();
    assert!(
        it.caller_text == "the actions of session “label sR” (sR)"
            && it.call.path == "/api/actions/requests/unlock",
        "{it:?}"
    );
    let (code, out) = m.do_(
        &mh,
        "POST",
        &format!("/m/api/actions/requests/{id}/deny"),
        "",
    );
    assert!(
        code == 200 && r.inbox().is_empty(),
        "not denied: {code} {out}"
    );
    let (code, out) = m.do_(
        &mh,
        "POST",
        "/m/api/actions/sessions",
        r#"{"label": "x", "explanation": "a test"}"#,
    );
    assert_eq!(code, 400, "a proposal with no prompt: {out}");
    // the old shared key's path is gone (only the web page's fallback answers it)
    let (_, out) = inbox_do(&r, "GET", "/actions/sessions", "", false);
    assert!(
        out.get("sessions").is_none_or(|s| s.is_null()),
        "/actions still served: {out}"
    );
    // pausing ends the key
    r.st.do_(|d| {
        if let Some(s) = d.sessions.get_mut("sR") {
            s.state = "pausing".into();
        }
    });
    let (code, out) = m.do_(&mh, "GET", "/m/api/actions/sessions", "");
    assert_eq!(code, 403, "a pausing session's actions still work: {out}");
}

#[test]
fn inbox_items_go_after_ten_minutes() {
    let r = new_test_router();
    add_session(&r, "sA", "paused", "", false);
    add_session(&r, "sN", "pending", "", false);
    r.add_approval(crate::state::Approval {
        kind: "add-store".into(),
        session: "sA".into(),
        ..Default::default()
    });
    r.add_approval(crate::state::Approval {
        kind: "new-session".into(),
        session: "sN".into(),
        ..Default::default()
    });
    let (q, _) = r
        .file_request(
            "unlock",
            RequestParams {
                session: "sA".into(),
                ..Default::default()
            },
            "need it",
            Origin {
                caller: Caller {
                    kind: "session".into(),
                    session: "sA".into(),
                },
                ..Default::default()
            },
        )
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert_eq!(
        q.expires.sub(&q.created),
        time::Duration::minutes(10),
        "request lifetime"
    );
    assert_eq!(r.inbox().len(), 3, "{:?}", r.inbox());
    // eleven minutes on: every item is gone; Deyao's own new session is kept as failed, so Start again asks again
    let later = GoTime::now().utc().add_std(Duration::from_secs(11 * 60));
    r.expire_approvals(later);
    r.st.do_(|d| {
        prune_requests(d, later);
        assert!(
            d.approvals.is_empty()
                && d.inbox.is_empty()
                && d.sessions.get("sN").is_some_and(|s| s.state == "failed")
                && d.sessions.contains_key("sA"),
            "approvals {} inbox {} sN {:?}",
            d.approvals.len(),
            d.inbox.len(),
            d.sessions.get("sN")
        );
    });
    let e = r
        .respond("nope", "sig")
        .err()
        .map(|e| e.to_string())
        .unwrap_or_default();
    assert!(e.contains("expired"), "{e}");
}

/// Reject asked twice (the phone's first try timed out after the router had taken it): the second is told it holds
/// already, 200 {ok, gone}, not "no such approval"
#[test]
fn reject_twice() {
    let rg = Rig::with(|c| c.no_access = true);
    let cert = rg.cert.clone();
    rg.st.do_(|d| {
        d.sessions.insert(
            "s2".into(),
            crate::state::Session {
                id: "s2".into(),
                state: "paused".into(),
                cert: Some(cert.clone()),
                ..Default::default()
            },
        );
        d.approvals.insert(
            "a1".into(),
            crate::state::Approval {
                id: "a1".into(),
                kind: "add-store".into(),
                session: "s2".into(),
                created: GoTime::now().utc(),
                ..Default::default()
            },
        );
    });
    let (code, out) = inbox_do(&rg, "POST", "/api/approvals/a1/reject", "", true);
    assert!(
        code == 200 && out["ok"] == true && out.get("gone").is_none_or(|g| g.is_null()),
        "the first: {code} {out}"
    );
    let (code, out) = inbox_do(&rg, "POST", "/api/approvals/a1/reject", "", true);
    assert!(
        code == 200 && out["ok"] == true && out["gone"] == true,
        "the second: {code} {out}"
    );
}
