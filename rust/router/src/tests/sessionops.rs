//! sessionops_test.go
use crate::registry::Registry;
use crate::sessionops::{env_key_allowed, normalize_env_patch, restart_continues};
use crate::testutil::*;
use serde_json::{Map, Value, json};
use std::sync::Arc;
use std::time::Duration;

fn sess(r: &crate::router::Router, id: &str) -> crate::state::Session {
    r.st.read(|d| d.sessions.get(id).cloned().unwrap_or_default())
}

fn phase(r: &crate::router::Router, id: &str) -> Option<String> {
    r.ops
        .job_view(id)
        .and_then(|j| j["phase"].as_str().map(String::from))
}

/// A session restarted in the middle of a turn (it asked for its own restart onto a new image, 2026-11-13) is told to
/// continue once it is back: a restart resumes with no prompt, and the cut-off turn would never go on
#[test]
fn restart_continues_a_cut_off_turn() {
    for (status, prompt, want) in [
        ("busy", "", true),
        ("working", "", true),
        ("idle", "", false),         // nothing was running
        ("waiting", "", false),      // it waits for Deyao: his answer continues it
        ("", "", false),             // no live harness reported
        ("busy", "carry on", false), // the restart's own prompt continues it
    ] {
        let g = (!status.is_empty()).then(|| Registry {
            status: status.into(),
            ..Default::default()
        });
        assert_eq!(
            restart_continues(g.as_ref(), prompt),
            want,
            "status {status:?} prompt {prompt:?}"
        );
    }
    assert!(
        !restart_continues(None, ""),
        "no registry: nothing to continue"
    );
}

#[test]
fn permission_mode_in_place_and_paused() {
    let r = new_test_router();
    add_session(&r, "sA", "started", "mA", false);
    add_session(&r, "sP", "paused", "", false);
    let ex = answer_execs(&r, "mA", 0);

    // raising to bypass needs a fresh phone grant (a rule or the allow list isn't enough)
    let (code, out) = inbox_do(
        &r,
        "POST",
        "/api/sessions/sA/permission-mode",
        r#"{"mode":"bypass"}"#,
        true,
    );
    assert!(
        code == 403 && out["needsGrant"] == "terminal" && out["phoneGrant"] == true,
        "without a phone grant: {code} {out}"
    );
    add_grant_kind(&r, "sA", "terminal", "rule");
    let (code, _) = inbox_do(
        &r,
        "POST",
        "/api/sessions/sA/permission-mode",
        r#"{"mode":"bypass"}"#,
        true,
    );
    assert_eq!(code, 403, "a standing rule raised to bypass");
    add_grant_kind(&r, "sA", "terminal", "grant");
    let (code, out) = app_do(
        &r,
        "POST",
        "/api/sessions/sA/permission-mode",
        r#"{"mode":"bypass"}"#,
        &[],
    );
    assert!(code == 202 && out["inPlace"] == true, "{code} {out}");
    wait_for("mode switched", || {
        sess(&r, "sA").permission_mode == "bypass"
    });
    assert_eq!(ex.cmds(), vec!["/usr/local/bin/set-permission-mode bypass"]);
    wait_for("job done", || phase(&r, "sA").as_deref() == Some("done"));
    // the same mode again: nothing to do
    let (code, out) = app_do(
        &r,
        "POST",
        "/api/sessions/sA/permission-mode",
        r#"{"mode":"bypass"}"#,
        &[],
    );
    assert!(code == 200 && out["unchanged"] == true, "{code} {out}");
    // paused: recorded for the next start, which passes it in the env
    let (code, out) = app_do(
        &r,
        "POST",
        "/api/sessions/sP/permission-mode",
        r#"{"mode":"bypass"}"#,
        &[],
    );
    assert!(code == 200 && out["nextStart"] == true, "{code} {out}");
    let s = sess(&r, "sP");
    assert_eq!(
        r.machine_env(&s)
            .get("SESSION_PERMISSION_MODE")
            .map(String::as_str),
        Some("bypass"),
        "the next start doesn't carry the mode"
    );
}

#[test]
fn permission_mode_failure_keeps_mode() {
    let r = new_test_router();
    add_session(&r, "sA", "started", "mA", false);
    r.st.do_(|d| {
        if let Some(s) = d.sessions.get_mut("sA") {
            s.permission_mode = "auto".into();
        }
    });
    let _ex = answer_execs(&r, "mA", 1);
    add_grant_kind(&r, "sA", "terminal", "grant");
    let (code, _) = app_do(
        &r,
        "POST",
        "/api/sessions/sA/permission-mode",
        r#"{"mode":"bypass"}"#,
        &[],
    );
    assert_eq!(code, 202);
    wait_for("job failed", || {
        phase(&r, "sA").as_deref() == Some("failed")
    });
    assert_eq!(
        sess(&r, "sA").permission_mode,
        "auto",
        "mode changed although the switch failed"
    );
}

#[test]
fn busy_in_state() {
    let r = new_test_router();
    add_session(&r, "sA", "started", "mA", false);
    r.core.set_url("http://127.0.0.1:1");
    let unlock = r.lock("sA", "pausing").unwrap_or_else(|e| panic!("{e:#}"));
    let (_, out) = app_do(&r, "GET", "/api/state", "", &[]);
    assert_eq!(
        out["sessions"][0]["busy"]["kind"], "pausing",
        "{}",
        out["sessions"][0]
    );
    let e = r
        .lock("sA", "starting")
        .err()
        .map(|e| e.to_string())
        .unwrap_or_default();
    assert!(e.contains("pausing"), "a second action got the lock: {e}");
    unlock.call();
    let (_, out) = app_do(&r, "GET", "/api/state", "", &[]);
    assert!(out["sessions"][0].get("busy").is_none(), "still busy");
}

/// (a restart with a rollback needs the phone: the rollback is a one-time input in the cert, vouch tests)
#[test]
fn restart_patches_env() {
    let o = OpsRig::new();
    let r = o.t.r.clone();
    let (code, out) = app_do(
        &r,
        "POST",
        "/api/sessions/s1/restart",
        r#"{"env":{"FEATURE_FLAG":"on","DEBUG":1},"size":"large","apiProxy":true}"#,
        &[],
    );
    assert_eq!(code, 202, "{out}");
    wait_for("start asked", || o.last_start().is_some());
    let st = o.last_start().unwrap_or_default();
    assert!(
        st["size"] == "large" && st.get("env").is_none(),
        "start {st} (the core sets a machine's env itself: the router sends none)"
    );
    // the settings reach the machine as the router's machine config, from the session
    let env = r.machine_env(&sess(&r, "s1"));
    assert!(
        env.get("FEATURE_FLAG").map(String::as_str) == Some("on")
            && env.get("DEBUG").map(String::as_str) == Some("1")
            && env.get("SESSION_API_PROXY").map(String::as_str) == Some("1"),
        "machine env {env:?}"
    );
    wait_for("job finished", || {
        r.ops
            .job_view("s1")
            .is_some_and(|j| !j["finishedAt"].is_null())
    });
    // the patch stays for later starts
    let mut other = sess(&r, "s1");
    other.cert = Some(o.core.key.doc(&json!({"machine": {"id": "m9"}})));
    let e = r.machine_env(&other);
    assert!(
        e.get("FEATURE_FLAG").map(String::as_str) == Some("on")
            && e.get("JARVIS2_ROLLBACK").is_none_or(String::is_empty),
        "later start env {e:?}"
    );
    // "" removes a key
    r.st.do_(|d| {
        if let Some(s) = d.sessions.get_mut("s1") {
            s.state = "paused".into();
        }
    });
    let (code, out) = app_do(
        &r,
        "POST",
        "/api/sessions/s1/env",
        r#"{"env":{"FEATURE_FLAG":""}}"#,
        &[],
    );
    assert_eq!(code, 202, "{out}");
    wait_for("removed", || {
        sess(&r, "s1")
            .ops
            .as_ref()
            .is_some_and(|o| !o.env.contains_key("FEATURE_FLAG"))
    });
    wait_for("env job finished", || {
        r.ops
            .job_view("s1")
            .is_some_and(|j| !j["finishedAt"].is_null())
    });
    // …and the resume it set off: take the lifecycle lock and keep it, so nothing writes after the test
    wait_for("session idle", || r.lock("s1", "test-end").is_ok());
}

#[test]
fn env_patch_refuses_secrets() {
    for k in [
        "GITHUB_TOKEN",
        "OPENAI_API_KEY",
        "AWS_SECRET_ACCESS_KEY",
        "DB_PASSWORD",
        "IPROYAL_API",
        "MY_KEY",
        "SESSION_PROMPT",
        "JARVIS2_ROLLBACK",
        "CLAUDE_CREDENTIALS",
        "PATH",
        "LD_PRELOAD",
        "CF_ACCESS_CLIENT_ID",
        "1BAD",
        "STRIPE_AUTH",
    ] {
        assert!(env_key_allowed(k).is_err(), "{k} allowed");
    }
    for k in [
        "FEATURE_FLAG",
        "DEBUG",
        "GIT_AUTHOR_NAME",
        "NODE_ENV",
        "TZ",
        "KEYBOARD_LAYOUT",
    ] {
        assert!(env_key_allowed(k).is_ok(), "{k}");
    }
    let mut m = Map::new();
    m.insert("X".into(), json!({}));
    assert!(
        normalize_env_patch(&m).is_err(),
        "an object value was accepted"
    );
    let o = OpsRig::new();
    let (code, out) = app_do(
        &o.t.r,
        "POST",
        "/api/sessions/s1/restart",
        r#"{"env":{"API_TOKEN":"x"}}"#,
        &[],
    );
    assert!(
        code == 400 && out["error"].as_str().is_some_and(|e| e.contains("secret")),
        "{code} {out}"
    );
}

#[test]
fn resume_with_size_and_model() {
    let o = OpsRig::new();
    let r = o.t.r.clone();
    let (code, _) = app_do(
        &r,
        "POST",
        "/api/sessions/s1/resume",
        r#"{"size":"huge"}"#,
        &[],
    );
    assert_eq!(code, 400, "a bad size was accepted");
    let (code, _) = app_do(
        &r,
        "POST",
        "/api/sessions/s1/resume",
        r#"{"model":"gpt-9"}"#,
        &[],
    );
    assert_eq!(code, 400, "an unknown model was accepted");
    let (code, out) = app_do(
        &r,
        "POST",
        "/api/sessions/s1/resume",
        r#"{"size":"small","model":"claude-fable-5-2"}"#,
        &[],
    );
    assert_eq!(code, 200, "{out}");
    wait_for("start asked", || o.last_start().is_some());
    let st = o.last_start().unwrap_or_default();
    let env = r.machine_env(&sess(&r, "s1"));
    assert!(
        st["size"] == "small"
            && st.get("env").is_none()
            && env.get("SESSION_MODEL").map(String::as_str) == Some("claude-fable-5-2"),
        "{st}"
    );
    // the core saw a plain dead-machine resume (size and model aren't in its options)
    let calls = o.sc.calls.lock().unwrap_or_else(|e| e.into_inner()).clone();
    assert!(
        calls.iter().any(|c| c == "/approve/by-dead-machine"),
        "calls {calls:?}"
    );
}

#[test]
fn sweep_uploads_drops_old_and_orphans() {
    let r = new_test_router();
    for (id, name) in [("old", "a.txt"), ("new", "b.txt"), ("orphan", "c.txt")] {
        r.stage_upload(id, "", name, &mut "x".as_bytes())
            .unwrap_or_else(|e| panic!("{e:#}"));
    }
    r.st.do_(|d| {
        if let Some(u) = d.uploads.get_mut("old") {
            u.created = jarvis_go::GoTime::from_unix(jarvis_go::GoTime::now().unix() - 25 * 3600);
        }
        if let Some(u) = d.uploads.get_mut("orphan") {
            u.session = "sGone".into();
        }
    });
    r.sweep_uploads(jarvis_go::GoTime::now());
    r.st.read(|d| {
        assert!(
            !d.uploads.contains_key("old")
                && !d.uploads.contains_key("orphan")
                && d.uploads.contains_key("new"),
            "{:?}",
            d.uploads.keys().collect::<Vec<_>>()
        );
    });
    let mut big = std::io::Read::take(
        std::io::repeat(0),
        (crate::uploads::ATTACH_MAX_BYTES + 10) as u64,
    );
    assert!(
        r.stage_upload("big", "", "x.bin", &mut big).is_err(),
        "an oversize file was accepted"
    );
}

#[test]
fn repos_follow_the_core() {
    let r = new_test_router();
    // a stand-in core: the begin is relayed as asked; a finish answers what the core signs
    let begun: Arc<std::sync::Mutex<Value>> = Arc::default();
    let answer = Arc::new(std::sync::Mutex::new(
        r#"{"kind":"deploy-key-added","repo":"DE0CH/jarvis2","store":"github-jarvis2","sensitive":true,"fingerprint":"SHA256:abc"}"#.to_string(),
    ));
    let (b2, a2) = (begun.clone(), answer.clone());
    let core = TestServer::handler(move |w, req| {
        let b = req.read_body(1 << 20);
        match req.path.as_str() {
            "/deploy-keys/begin" => {
                *b2.lock().unwrap_or_else(|e| e.into_inner()) =
                    serde_json::from_slice(&b).unwrap_or_default();
                w.write(br#"{"payload":"{\"kind\":\"deploy-key-begin\"}","sig":"s"}"#);
            }
            "/deploy-keys/finish" => {
                let p = serde_json::to_string(&*a2.lock().unwrap_or_else(|e| e.into_inner()))
                    .unwrap_or_default();
                w.write(format!(r#"{{"payload":{p},"sig":"s"}}"#).as_bytes());
            }
            _ => jarvis_nethttp::not_found(w),
        }
    });
    r.core.set_url(&core.url);
    let (code, _) = app_do(
        &r,
        "POST",
        "/api/repos/key/begin",
        r#"{"action":"add","repo":"https://github.com/DE0CH/jarvis2.git"}"#,
        &[],
    );
    let bg = begun.lock().unwrap_or_else(|e| e.into_inner()).clone();
    assert!(
        code == 200 && bg["repo"] == "DE0CH/jarvis2" && bg["action"] == "add",
        "{code} {bg}"
    );
    for b in [
        r#"{"action":"add","repo":"gitlab.com/x/y"}"#,
        r#"{"action":"rotate","repo":"DE0CH/x"}"#,
        r#"{"action":"add","repo":"DE0CH/.."}"#,
    ] {
        let (code, _) = app_do(&r, "POST", "/api/repos/key/begin", b, &[]);
        assert_eq!(code, 400, "accepted {b}");
    }
    // the list follows the core's answer only
    let (_, out) = app_do(&r, "GET", "/api/repos", "", &[]);
    assert_eq!(
        out["repos"].as_array().map(Vec::len),
        Some(0),
        "a begin added to the list"
    );
    let (code, _) = app_do(
        &r,
        "POST",
        "/api/repos/key/finish",
        r#"{"pending":"p"}"#,
        &[],
    );
    assert_eq!(code, 200);
    let (_, out) = app_do(&r, "GET", "/api/state", "", &[]);
    let rs = out["repos"].as_array().cloned().unwrap_or_default();
    assert!(
        rs.len() == 1
            && rs[0]["name"] == "jarvis2"
            && rs[0]["store"] == "github-jarvis2"
            && rs[0]["sensitive"] == true
            && rs[0]["url"] == "https://github.com/DE0CH/jarvis2.git",
        "{rs:?}"
    );
    *answer.lock().unwrap_or_else(|e| e.into_inner()) =
        r#"{"kind":"deploy-key-removed","repo":"DE0CH/jarvis2","store":"github-jarvis2"}"#.into();
    let _ = app_do(
        &r,
        "POST",
        "/api/repos/key/finish",
        r#"{"pending":"p"}"#,
        &[],
    );
    let (_, out) = app_do(&r, "GET", "/api/repos", "", &[]);
    assert_eq!(out["repos"].as_array().map(Vec::len), Some(0), "{out}");
    // a core from before deploy keys: a plain sentence
    let nf = TestServer::handler(|w, _| jarvis_nethttp::not_found(w));
    r.core.set_url(&nf.url);
    let (code, out) = app_do(
        &r,
        "POST",
        "/api/repos/key/begin",
        r#"{"action":"add","repo":"DE0CH/x"}"#,
        &[],
    );
    assert!(
        code == 501
            && out["error"]
                .as_str()
                .is_some_and(|e| e.contains("predates")),
        "{code} {out}"
    );
    // entries that aren't GitHub repos (an older list) are left off
    r.st.write_doc(
        "repos.json",
        br#"[{"name":"a","url":"https://gitlab.com/x/a.git"},{"name":"b","url":"https://github.com/DE0CH/b.git"}]"#,
    )
    .unwrap_or_else(|e| panic!("{e:#}"));
    let rs = r.repos();
    assert!(
        rs.len() == 1 && rs[0].repo == "DE0CH/b" && rs[0].store == "github-b",
        "{rs:?}"
    );
    // the same store names as the core's RepoStore (core/deploykeys_test.go)
    for (input, want) in [
        ("DE0CH/claude-env", "github-claude-env"),
        ("DE0CH/china_train", "github-china-train"),
        ("de0ch/Jarvis2", "github-jarvis2"),
        ("someone/Thing.js", "github-someone-thing-js"),
    ] {
        assert_eq!(crate::repos::repo_store(input), want, "{input}");
    }
}

/// the web page proposes any store, sensitive ones included (Deyao, 2026-10-13; docs/DECISIONS.md 164): the request
/// becomes an approval holding them, filed as the web's, for the phone to review; the core's own store and the
/// deploy-key token's store are still refused.
#[test]
fn web_request_takes_sensitive_stores() {
    let o = OpsRig::new();
    let r = o.t.r.clone();
    let (code, out) = app_do(
        &r,
        "POST",
        "/api/sessions",
        r#"{"requestId":"web-sens","harness":"claude","stores":["default","identity","github-jarvis2"]}"#,
        &[],
    );
    let id = out["id"].as_str().unwrap_or_default().to_string();
    assert!(code == 200 && !id.is_empty(), "{code} {out}");
    wait_for("approval", || {
        r.st.read(|d| {
            d.approvals.values().any(|a| {
                a.session == id
                    && a.kind == "new-session"
                    && a.origin.as_ref().is_some_and(|o| o.caller.kind == "web")
            })
        })
    });
    let s = sess(&r, &id);
    let stores = s.stores.clone().unwrap_or_default();
    assert!(
        stores.iter().any(|x| x == "identity") && stores.iter().any(|x| x == "github-jarvis2"),
        "the sensitive stores didn't reach the request: {stores:?}"
    );
    for bad in [
        crate::policy::FLY_STORE,
        crate::flows::DEPLOY_KEY_TOKEN_STORE,
    ] {
        let (code, out) = app_do(
            &r,
            "POST",
            "/api/sessions",
            &format!(r#"{{"requestId":"web-{bad}","harness":"claude","stores":["{bad}"]}}"#),
            &[],
        );
        assert_ne!(code, 200, "store {bad} was accepted: {out}");
    }
}

/// a running session whose cert names a phone key, so add_grant takes what that key signs; returns the signer
fn phone_session(
    r: &Arc<crate::router::Router>,
    id: &str,
    machine: &str,
) -> impl Fn(&str, &str) + use<> {
    let phone = TestKey::new();
    let cert = jarvis_go::marshal(&json!({"line": format!("L{id}"), "phone": phone_b64(&phone)}));
    let s = crate::state::Session {
        id: id.into(),
        state: "started".into(),
        machine_id: machine.into(),
        label: format!("label {id}"),
        harness: "claude".into(),
        permission_mode: "auto".into(),
        cert: Some(crate::core::Doc {
            payload: cert,
            sig: String::new(),
        }),
        ..Default::default()
    };
    r.st.do_(|d| {
        d.sessions.insert(id.into(), s.clone());
        d.machines.insert(machine.into(), id.into());
    });
    let (r, id) = (r.clone(), id.to_string());
    move |holder: &str, kind: &str| {
        let pubs = r.holder_public_keys().unwrap_or_else(|e| panic!("{e:#}"));
        let now = jarvis_go::GoTime::now().utc();
        let mut g = json!({"kind": kind, "holder": pubs.get(holder).cloned().unwrap_or_default(), "session": format!("L{id}"), "scope": "shell", "issued": now.rfc3339()});
        if kind == "grant" {
            g["expires"] = json!(now.add_std(Duration::from_secs(600)).rfc3339());
        } else {
            g["until"] = json!(now.add_std(Duration::from_secs(24 * 3600)).rfc3339());
        }
        let doc = phone.doc(&g);
        r.add_grant(&id, Some(&doc))
            .unwrap_or_else(|e| panic!("{e:#}"));
    }
}

/// the phone's public key as a cert names it (base64 of the uncompressed point)
fn phone_b64(k: &TestKey) -> String {
    k.public()
}

/// The web page's "Switch to bypass mode" (Deyao, 2026-10-20): the router files the terminal grant in the Inbox as
/// the web's request and switches once the phone signs it. The iPhone app still gets the 403 and opens its own grant
/// review.
#[test]
fn bypass_from_the_web_waits_in_the_inbox() {
    let r = new_test_router();
    let sign = phone_session(&r, "sW", "mW");
    let ex = answer_execs(&r, "mW", 0);

    let (code, out) = inbox_do(
        &r,
        "POST",
        "/api/sessions/sW/permission-mode",
        r#"{"mode":"bypass"}"#,
        true,
    );
    assert!(
        code == 403 && out["needsGrant"] == "terminal",
        "the app: {code} {out}"
    );
    assert!(r.inbox().is_empty(), "the app's 403 filed a request");
    let (code, out) = app_do(
        &r,
        "POST",
        "/api/sessions/sW/permission-mode",
        r#"{"mode":"bypass"}"#,
        &[],
    );
    let qid = out["inboxId"].as_str().unwrap_or_default().to_string();
    assert!(
        code == 202
            && out["waiting"] == "inbox"
            && out["needsGrant"] == "terminal"
            && !qid.is_empty(),
        "the web: {code} {out}"
    );
    let it = r.inbox_item(&qid);
    assert!(
        it.as_ref()
            .is_some_and(|it| it.kind == crate::inbox::REQUEST_KIND_GRANT
                && it.params.holder == "terminal"
                && it.params.minutes == 10
                && it.caller.kind == "web"
                && it.call.path == "/api/sessions/sW/permission-mode"
                && it.call.args.get("mode").is_some_and(|m| m == "bypass")
                && it.open.get("kind") == Some(&json!("grant"))),
        "{it:?}"
    );
    let it = it.unwrap_or_default();
    // who and what asked, never "Jarvis 4" itself (Deyao, 2026-10-20)
    assert!(
        it.caller_text == "Deyao, from the web page"
            && it.session_name == "label sW"
            && it
                .explanation
                .starts_with("Switch session “label sW” (sW) to bypass permission mode")
            && !it.caller_text.contains("Jarvis 4"),
        "named as {:?}: {:?}",
        it.caller_text,
        it.explanation
    );
    let (code, out) = app_do(
        &r,
        "POST",
        "/api/sessions/sW/permission-mode",
        r#"{"mode":"bypass"}"#,
        &[],
    );
    assert!(
        code == 202 && out["inboxId"] == json!(qid) && out["duplicate"] == true,
        "again: {code} {out}"
    );
    r.core.set_url("http://127.0.0.1:1");
    let (_, st) = app_do(&r, "GET", "/api/state", "", &[]);
    let view = st["sessions"]
        .as_array()
        .and_then(|a| a.iter().find(|v| v["id"] == "sW").cloned())
        .unwrap_or_default();
    assert!(
        view["modeAfterGrant"]["mode"] == "bypass" && view["modeAfterGrant"]["inbox"] == json!(qid),
        "the state doesn't show the waiting switch: {}",
        view["modeAfterGrant"]
    );

    // signed: the request is answered and the switch runs under the grant
    sign("terminal", "grant");
    assert!(
        r.inbox_item(&qid).is_none(),
        "the grant request stayed in the Inbox"
    );
    wait_for("mode switched", || {
        sess(&r, "sW").permission_mode == "bypass"
    });
    wait_for("job done", || phase(&r, "sW").as_deref() == Some("done"));
    assert_eq!(ex.cmds(), vec!["/usr/local/bin/set-permission-mode bypass"]);
    assert!(
        sess(&r, "sW")
            .ops
            .and_then(|o| o.mode_after_grant)
            .is_none(),
        "the switch stayed waiting"
    );
}

/// a standing rule answers the request but doesn't allow bypass: nothing switches, and the waiting switch goes
#[test]
fn bypass_request_answered_by_a_rule() {
    let r = new_test_router();
    let sign = phone_session(&r, "sW", "mW");
    let ex = answer_execs(&r, "mW", 0);
    let (code, out) = app_do(
        &r,
        "POST",
        "/api/sessions/sW/permission-mode",
        r#"{"mode":"bypass"}"#,
        &[],
    );
    assert!(code == 202 && out["waiting"] == "inbox", "{code} {out}");
    sign("terminal", "rule");
    std::thread::sleep(Duration::from_millis(100));
    let s = sess(&r, "sW");
    assert!(
        s.permission_mode == "auto"
            && s.ops
                .as_ref()
                .and_then(|o| o.mode_after_grant.as_ref())
                .is_none(),
        "{} {:?}",
        s.permission_mode,
        s.ops
    );
    assert!(ex.cmds().is_empty(), "{:?}", ex.cmds());
}

/// the same switch asked for by a session's actions as an API call (2026-10-20): the approved call answers 202 and
/// its review sheet follows the grant it filed
#[test]
fn bypass_as_an_api_call_follows_its_grant() {
    let r = new_test_router();
    let _sign = phone_session(&r, "sW", "mW");
    add_session(&r, "sR", "started", "mR", false);
    let (m, mh) = (new_test_machine(&r, "mR"), r.machine_handler());
    let (code, out) = m.do_(
        &mh,
        "POST",
        "/m/api/actions/requests/call",
        r#"{"method": "POST", "path": "/api/sessions/sW/permission-mode", "body": {"mode": "bypass"}, "explanation": "bypass for the build"}"#,
    );
    assert_eq!(code, 200, "{out}");
    let id = out["id"].as_str().unwrap_or_default().to_string();
    let (code, out) = inbox_do(&r, "POST", &format!("/api/requests/{id}/approve"), "", true);
    assert!(code == 200 && out["status"] == 202, "approve: {code} {out}");
    let f = r.call_followups_of(&id);
    let fu = f.as_ref().map(|f| f.followups.clone()).unwrap_or_default();
    assert!(
        fu.len() == 1
            && fu[0].open
            && fu[0].item.as_ref().is_some_and(
                |i| i.kind == crate::inbox::REQUEST_KIND_GRANT && i.caller.kind == "actions"
            ),
        "{f:?}"
    );
    let g = fu[0].item.clone().unwrap_or_default();
    assert!(
        g.caller_text == "the actions of session “label sR” (sR)"
            && g.explanation
                .starts_with("Switch session “label sW” (sW) to bypass"),
        "named as {:?}: {:?}",
        g.caller_text,
        g.explanation
    );
}

/// a signed GET as the machine signs it, its raw answer (sessionops_test.go's mxRaw)
fn raw_get(h: &jarvis_nethttp::Handler, m: &TestMachine, path: &str) -> (u16, Vec<u8>) {
    let (ts, sig) = signed_headers(&m.key, "GET", path, b"", crate::util::unix_now());
    let mut req = jarvis_nethttp::Req::new("GET", path, b"")
        .with_header("X-Machine", &m.id)
        .with_header("X-Time", &ts)
        .with_header("X-Sig", &sig);
    let mut w = jarvis_nethttp::W::recorder();
    h(&mut w, &mut req);
    (w.status(), w.recorded.clone().unwrap_or_default())
}

#[test]
fn idempotent_create_and_attachments() {
    let rg = OpsRig::new();
    let r = rg.t.r.clone();
    // stage two files
    for (name, body) in [("my photo.png", "PNG"), ("notes.txt", "text")] {
        let (code, out) = app_do(
            &r,
            "POST",
            "/api/uploads",
            body,
            &[("x-upload-id", "up1"), ("x-upload-name", name)],
        );
        assert_eq!(code, 200, "{out}");
    }
    let (code, _) = app_do(
        &r,
        "POST",
        "/api/uploads",
        "x",
        &[("x-upload-id", "../bad")],
    );
    assert_eq!(code, 400, "a bad upload id was accepted");
    let req = r#"{"requestId":"req-1","label":"x","harness":"claude","apiProxy":true,
		"attachments":{"uploadId":"up1","files":[{"name":"my photo.png"},{"name":"notes.txt"}]}}"#;
    let (code, out) = app_do(&r, "POST", "/api/sessions", req, &[]);
    assert!(code == 200 && !out["id"].is_null(), "{code} {out}");
    let id = out["id"].as_str().unwrap_or_default().to_string();
    let (code, out) = app_do(&r, "POST", "/api/sessions", req, &[]);
    assert!(
        code == 200 && out["id"] == id.as_str(),
        "a repeat made another session: {code} {out}"
    );
    let n = r.st.read(|d| {
        d.sessions
            .values()
            .filter(|s| s.request_id == "req-1")
            .count()
    });
    assert_eq!(n, 1, "sessions for one requestId");
    wait_for("approval", || {
        r.st.read(|d| {
            d.approvals.values().any(|a| {
                a.session == id
                    && a.options.get("attachments").map(String::as_str) == Some("2 file(s)")
                    && a.options.get("apiProxy").map(String::as_str) == Some("on")
            })
        })
    });
    // another session can't take the same upload
    let (code, out) = app_do(
        &r,
        "POST",
        "/api/sessions",
        r#"{"requestId":"req-2","attachments":{"uploadId":"up1","files":[{"name":"notes.txt"}]}}"#,
        &[],
    );
    assert_eq!(code, 400, "{out}");
    // the first machine's env names them
    let mut s = rg.session(&id);
    let e = r.machine_env(&s);
    assert!(
        e.get("SESSION_ATTACHMENTS_JSON").map(String::as_str)
            == Some(
                r#"[{"name":"my_photo.png","isImage":true},{"name":"notes.txt","isImage":false}]"#
            )
            && e.get("SESSION_API_PROXY").map(String::as_str) == Some("1"),
        "{e:?}"
    );
    // the session's machine fetches them; another machine can't
    r.st.do_(|d| {
        if let Some(x) = d.sessions.get_mut(&id) {
            x.machine_id = "mX".into();
            x.state = "initialising".into();
        }
        d.machines.insert("mX".into(), id.clone());
    });
    let (mx, my) = (new_test_machine(&r, "mX"), new_test_machine(&r, "mY"));
    let h = rg.machine_handler();
    let (code, out) = mx.do_(&h, "GET", "/m/attachments", "");
    assert!(
        code == 200 && out["files"].as_array().map_or(0, Vec::len) == 2,
        "{code} {out}"
    );
    assert_eq!(
        my.do_(&h, "GET", "/m/attachments", "").0,
        404,
        "another machine"
    );
    let (code, b) = raw_get(&h, &mx, "/m/attachments/my_photo.png");
    assert!(
        code == 200 && b == b"PNG",
        "{code} {:?}",
        String::from_utf8_lossy(&b)
    );
    assert_eq!(mx.do_(&h, "GET", "/m/attachments/other.txt", "").0, 404);
    assert_eq!(mx.do_(&h, "DELETE", "/m/attachments", "").0, 200);
    let keys = r.objects.list("uploads/up1/").unwrap_or_default();
    assert!(
        keys.is_empty(),
        "the staged files are still there: {keys:?}"
    );
    // once certified (a resume), no attachment env
    s.cert = Some(crate::types::Doc {
        payload: "{}".into(),
        sig: String::new(),
    });
    assert!(
        !r.machine_env(&s).contains_key("SESSION_ATTACHMENTS_JSON"),
        "attachments on a later start"
    );
}
