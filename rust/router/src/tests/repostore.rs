//! router/repostore_test.go: a repo a session asks for lands in that session in the same approval (Deyao, 2026-10-15;
//! DECISIONS 182): the request names the asking session; the finished deploy key files the add-store approval at once
//! and names it to the phone, which signs it under the same Face ID.
use crate::inbox::{Caller, INBOX_TTL, InboxRequest, Origin, REQUEST_KIND_REPO, RequestParams};
use crate::repos::repo_entry;
use crate::router::Router;
use crate::state::Approval;
use crate::testutil::*;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

type Successions = Arc<Mutex<Vec<Value>>>;

/// a stand-in core that answers a finish with the key added and any succession with a challenge
fn repo_core(r: &Router, repo: &str) -> (Successions, TestServer) {
    let succ: Successions = Arc::default();
    let s2 = succ.clone();
    let repo = repo.to_string();
    let srv = TestServer::handler(move |w, req| {
        let b: Value = serde_json::from_slice(&req.read_body(1 << 20)).unwrap_or_default();
        match req.path.as_str() {
            "/deploy-keys/finish" => {
                let p = format!(
                    r#"{{"kind":"deploy-key-added","repo":"{repo}","sensitive":false,"fingerprint":"SHA256:abc"}}"#
                );
                crate::nethttp::write_json(w, 200, &json!({"payload": p, "sig": "s"}));
            }
            "/succession" => {
                s2.lock().unwrap_or_else(|e| e.into_inner()).push(b.clone());
                let p = jarvis_go::marshal(
                    &json!({"kind": "challenge", "nonce": "c".repeat(64), "request": b}),
                );
                crate::nethttp::write_json(w, 200, &json!({"payload": p, "sig": "s"}));
            }
            _ => crate::nethttp::write_error(w, 404, "404 page not found"),
        }
    });
    r.core.set_url(&srv.url);
    (succ, srv)
}

fn approvals_for(r: &Router, sid: &str) -> Vec<Approval> {
    r.st.read(|d| {
        d.approvals
            .values()
            .filter(|a| a.session == sid)
            .cloned()
            .collect()
    })
}

fn set_stores(r: &Router, sid: &str, stores: &[&str]) {
    r.st.do_(|d| {
        if let Some(s) = d.sessions.get_mut(sid) {
            s.stores = Some(stores.iter().map(|x| x.to_string()).collect());
        }
    });
}

fn strs(v: &Value) -> String {
    v.as_array()
        .map(|a| {
            a.iter()
                .map(|x| x.as_str().unwrap_or_default())
                .collect::<Vec<_>>()
                .join(",")
        })
        .unwrap_or_default()
}

fn session_caller(s: &str) -> Caller {
    Caller {
        kind: "session".into(),
        session: s.into(),
    }
}

const APP: &[(&str, &str)] = &[("cf-access-token", "x")];

#[test]
fn a_repo_a_session_asks_for_lands_in_it_in_the_same_approval() {
    let t = new_test_router();
    let r = t.r.clone();
    let (succ, _srv) = repo_core(&r, "DE0CH/claude-env");
    add_session(&r, "sA", "started", "mA", false);
    add_session(&r, "sB", "started", "mB", false);
    add_session(&r, "sP", "paused", "", false);
    set_stores(&r, "sA", &["default"]);
    let (ma, mb, mh) = (
        new_test_machine(&r, "mA"),
        new_test_machine(&r, "mB"),
        t.machine_handler(),
    );
    let (code, out) = ma.do_(
        &mh,
        "POST",
        "/m/api/requests/repo/add",
        r#"{"repo":"https://github.com/DE0CH/claude-env","explanation":"push the skill"}"#,
    );
    assert_eq!(code, 200, "{out}");
    let qa = out["id"].as_str().unwrap_or_default().to_string();
    let it = r.inbox_item(&qa).unwrap_or_else(|| panic!("no item {qa}"));
    assert!(
        it.session == "sA"
            && it.open["options"]["into"] == "sA"
            && it.open["options"]["store"] == "github-claude-env",
        "the request doesn't name the session the store goes to: {it:?}"
    );
    assert_eq!(
        it.call.args.get("into"),
        Some(&json!("sA")),
        "the recorded call: {:?}",
        it.call
    );
    // a second session asks too; a session that opts out gets no store; a paused session's request stays without one
    let (_, out) = mb.do_(
        &mh,
        "POST",
        "/m/api/requests/repo/add",
        r#"{"repo":"DE0CH/claude-env","explanation":"me too"}"#,
    );
    let qb = out["id"].as_str().unwrap_or_default().to_string();
    let (_, out) = mb.do_(
        &mh,
        "POST",
        "/m/api/requests/repo/add",
        r#"{"repo":"DE0CH/other","noStore":true,"explanation":"for a new session"}"#,
    );
    let q = r
        .inbox_item(out["id"].as_str().unwrap_or_default())
        .unwrap_or_default();
    assert!(
        q.session.is_empty()
            && q.open
                .get("options")
                .is_none_or(|o| o.get("into").is_none_or(Value::is_null)),
        "noStore: {q:?}"
    );
    let created = it.created;
    r.st.do_(|d| {
        d.inbox.insert(
            "qP".into(),
            InboxRequest {
                id: "qP".into(),
                kind: REQUEST_KIND_REPO.into(),
                params: RequestParams {
                    action: "add".into(),
                    repo: "DE0CH/claude-env".into(),
                    session: "sP".into(),
                    ..Default::default()
                },
                origin: Origin {
                    caller: session_caller("sP"),
                    ..Default::default()
                },
                key: "p".into(),
                created,
                expires: created.add(INBOX_TTL),
                ..Default::default()
            },
        );
    });
    // the phone finishes the key for sA's request: the answer names sA's add-store approval
    let (code, out) = app_do(
        &r,
        "POST",
        &format!("/api/repos/key/finish?inbox={qa}"),
        r#"{"pending":"p"}"#,
        APP,
    );
    assert!(
        code == 200 && !out["payload"].is_null() && out["sig"] == "s",
        "{code} {out}"
    );
    let f = out["followups"].as_array().cloned().unwrap_or_default();
    let as_ = approvals_for(&r, "sA");
    assert!(
        f.len() == 1 && as_.len() == 1 && f[0] == as_[0].id.as_str(),
        "followups {f:?}, approvals {as_:?}"
    );
    let a = &as_[0];
    let o = a.origin.clone().unwrap_or_default();
    assert!(
        a.kind == "add-store"
            && a.options.get("store").map(String::as_str) == Some("github-claude-env")
            && a.machine == "mA"
            && o.caller == session_caller("sA")
            && o.signed.is_none()
            && a.explanation == "push the skill"
            && o.call.args.get("for") == Some(&json!(qa)),
        "{a:?}"
    );
    // the challenge adds exactly that store to sA's machine
    let ch = succ
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .rfind(|s| s["machine"] == "mA")
        .cloned()
        .unwrap_or_default();
    assert_eq!(
        strs(&ch["stores"]),
        "default,github-claude-env",
        "successions"
    );
    // sB's waits in the Inbox on its own; the paused session's gets none; every request for the repo is answered
    let bs = approvals_for(&r, "sB");
    assert!(bs.len() == 1 && bs[0].kind == "add-store", "sB {bs:?}");
    assert!(
        approvals_for(&r, "sP").is_empty(),
        "a paused session got an approval"
    );
    for q in [qa.as_str(), qb.as_str(), "qP"] {
        assert!(r.inbox_item(q).is_none(), "request {q} still waits");
    }
    // a session that holds the store already (a key rotated) gets no add-store
    r.st.do_(|d| d.approvals.clear());
    set_stores(&r, "sA", &["default", "github-claude-env"]);
    let (_, out) = ma.do_(
        &mh,
        "POST",
        "/m/api/requests/repo/add",
        r#"{"repo":"DE0CH/claude-env","explanation":"rotate"}"#,
    );
    let id = out["id"].as_str().unwrap_or_default().to_string();
    let (_, out) = app_do(
        &r,
        "POST",
        &format!("/api/repos/key/finish?inbox={id}"),
        r#"{"pending":"p"}"#,
        APP,
    );
    assert!(
        out["followups"].is_null() && approvals_for(&r, "sA").is_empty(),
        "{out}"
    );
}

#[test]
fn a_repo_in_a_batch_names_the_asking_session() {
    let t = new_test_router();
    let r = t.r.clone();
    let (_succ, _srv) = repo_core(&r, "DE0CH/claude-env");
    add_session(&r, "sA", "started", "mA", false);
    let ma = new_test_machine(&r, "mA");
    let (code, out) = ma.do_(
        &t.machine_handler(),
        "POST",
        "/m/api/requests/batch",
        r#"{"summary":"work","items":[{"intent":"repo/add","repo":"DE0CH/claude-env"},{"intent":"grant","holder":"status","minutes":5}]}"#,
    );
    assert_eq!(code, 200, "{out}");
    let id = out["items"][0]["id"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let it = r.inbox_item(&id).unwrap_or_default();
    assert!(it.session == "sA" && !it.batch.is_empty(), "{it:?}");
    // Deyao's own add (Settings → Repos, the web page) names no session
    let (_, out) = app_do(
        &r,
        "POST",
        "/api/requests/repo/add",
        r#"{"repo":"DE0CH/x"}"#,
        APP,
    );
    let it = r
        .inbox_item(out["id"].as_str().unwrap_or_default())
        .unwrap_or_default();
    assert!(it.session.is_empty(), "{it:?}");
}

/// A repo that has its deploy key already (Deyao, 2026-11-17): a session asking for it needs the key's store, so the
/// ask is the add-store of that store, alone or in a batch, and no new key is asked for. A session that holds the
/// store asks for a new key (a rotation), as does anyone naming no session.
#[test]
fn a_repo_that_has_its_key_is_an_add_store_not_a_new_key() {
    let t = new_test_router();
    let r = t.r.clone();
    let (succ, _srv) = repo_core(&r, "DE0CH/claude-env");
    add_session(&r, "sA", "started", "mA", false);
    add_session(&r, "sH", "started", "mH", false);
    set_stores(&r, "sA", &["default"]);
    set_stores(&r, "sH", &["github-claude-env"]);
    r.update_repos(|_| {
        let mut e = repo_entry("DE0CH/claude-env");
        e.fingerprint = "SHA256:abc".into();
        vec![e, repo_entry("DE0CH/nokey")]
    })
    .unwrap_or_else(|e| panic!("{e:#}"));
    let (ma, mh_, mh) = (
        new_test_machine(&r, "mA"),
        new_test_machine(&r, "mH"),
        t.machine_handler(),
    );
    let requests = || r.st.read(|d| d.inbox.len());
    let (code, out) = ma.do_(
        &mh,
        "POST",
        "/m/api/requests/repo/add",
        r#"{"repo":"https://github.com/de0ch/claude-env.git","explanation":"push the skill"}"#,
    );
    let as_ = approvals_for(&r, "sA");
    assert!(
        code == 200
            && out["existing"] == true
            && out["store"] == "github-claude-env"
            && out["id"].is_null()
            && requests() == 0
            && as_.len() == 1,
        "{code} {out}, {} requests, approvals {as_:?}",
        requests()
    );
    let a = &as_[0];
    let o = a.origin.clone().unwrap_or_default();
    assert!(
        a.kind == "add-store"
            && a.options.get("store").map(String::as_str) == Some("github-claude-env")
            && a.machine == "mA"
            && a.explanation == "push the skill"
            && o.caller == session_caller("sA")
            && o.call
                .args
                .get("repo")
                .and_then(Value::as_str)
                .is_some_and(|x| x.eq_ignore_ascii_case("DE0CH/claude-env"))
            && out["approval"] == a.id.as_str(),
        "{a:?}"
    );
    let ss = succ.lock().unwrap_or_else(|e| e.into_inner()).clone();
    assert!(
        ss.len() == 1 && strs(&ss[0]["stores"]) == "default,github-claude-env",
        "successions {ss:?}"
    );
    // in a batch: the item is the add-store
    r.st.do_(|d| d.approvals.clear());
    let (code, out) = ma.do_(
        &mh,
        "POST",
        "/m/api/requests/batch",
        r#"{"summary":"work","items":[{"intent":"repo/add","repo":"DE0CH/claude-env"}]}"#,
    );
    let as_ = approvals_for(&r, "sA");
    assert!(
        code == 200
            && requests() == 0
            && as_.len() == 1
            && as_[0].kind == "add-store"
            && as_[0].options.get("store").map(String::as_str) == Some("github-claude-env")
            && !as_[0].batch.is_empty(),
        "{code} {out}, {} requests, approvals {as_:?}",
        requests()
    );
    // still a new key: a repo with none, a session that holds the store (a rotation), an ask without the store
    for (i, (m, body)) in [
        (&ma, r#"{"repo":"DE0CH/nokey","explanation":"x"}"#),
        (&ma, r#"{"repo":"DE0CH/unlisted","explanation":"x"}"#),
        (
            &mh_,
            r#"{"repo":"DE0CH/claude-env","explanation":"rotate"}"#,
        ),
        (
            &ma,
            r#"{"repo":"DE0CH/claude-env","noStore":true,"explanation":"x"}"#,
        ),
    ]
    .iter()
    .enumerate()
    {
        let (code, out) = m.do_(&mh, "POST", "/m/api/requests/repo/add", body);
        assert!(
            code == 200 && !out["id"].is_null() && requests() == i + 1,
            "{body}: {code} {out} ({} requests)",
            requests()
        );
    }
    // Deyao's own add makes a key
    let (_, out) = app_do(
        &r,
        "POST",
        "/api/requests/repo/add",
        r#"{"repo":"DE0CH/claude-env"}"#,
        APP,
    );
    assert!(!out["id"].is_null(), "{out}");
}
