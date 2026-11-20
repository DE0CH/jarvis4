//! router/sessionapi_test.go
use crate::inbox::Caller;
use crate::schedule::{RESUME_PROMPT_MAX, Schedule, Wakeup};
use crate::searchsvc::ICLOUD_INDEX_BASE;
use crate::sessionapi::{MACHINE_API_URL, session_api_env};
use crate::testutil::*;
use jarvis_go::GoTime;
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

fn err_of(v: &Value) -> String {
    v["error"].as_str().unwrap_or_default().to_string()
}

fn len_of(v: &Value) -> usize {
    v.as_array().map_or(usize::MAX, Vec::len)
}

#[test]
fn machine_api_wakeups_and_crons() {
    let t = new_test_router();
    let r = t.r.clone();
    add_session(&r, "sA", "started", "mA", false);
    add_session(&r, "sB", "started", "mB", false);
    let m = new_test_machine(&r, "mA");
    let h = t.machine_handler();
    let (code, out) = m.do_(
        &h,
        "POST",
        "/m/api/sessions/sA/wakeup",
        r#"{"delaySeconds": 3600, "prompt": "retry", "name": "r1"}"#,
    );
    assert!(
        code == 200 && out["ok"] == true && out["wakeup"]["name"] == "r1",
        "{code} {out}"
    );
    let (code, out) = m.do_(&h, "GET", "/m/api/sessions/sA/wakeup", "");
    assert!(
        code == 200 && len_of(&out["wakeups"]) == 1 && !out["wakeup"].is_null(),
        "{code} {out}"
    );
    // another session's id: refused
    let (code, _) = m.do_(
        &h,
        "POST",
        "/m/api/sessions/sB/wakeup",
        r#"{"delaySeconds": 60, "prompt": "x"}"#,
    );
    assert_eq!(code, 403, "another session's path");
    let (code, out) = m.do_(
        &h,
        "POST",
        "/m/api/sessions/sA/wakeups",
        r#"{"prompt": "x"}"#,
    );
    assert!(
        code == 400 && err_of(&out).contains("delaySeconds"),
        "{code} {out}"
    );
    let (code, out) = m.do_(
        &h,
        "POST",
        "/m/api/sessions/sA/crons",
        r#"{"name": "c1", "prompt": "daily", "time": "08:00", "tz": "Europe/London"}"#,
    );
    assert!(
        code == 200 && out["cron"]["tz"] == "Europe/London",
        "{code} {out}"
    );
    // retiring with pending ones is refused
    let (code, out) = m.do_(&h, "DELETE", "/m/api/sessions/sA", "");
    assert!(code == 409 && len_of(&out["pending"]) == 2, "{code} {out}");
    let (code, out) = m.do_(&h, "DELETE", "/m/api/sessions/sA/wakeups/r1", "");
    assert!(code == 200 && out["cancelled"][0] == "r1", "{code} {out}");
    assert_eq!(
        m.do_(&h, "DELETE", "/m/api/sessions/sA/crons/c1", "").0,
        200
    );
    let (code, out) = m.do_(&h, "GET", "/m/api/sessions/sA/crons", "");
    assert!(code == 200 && len_of(&out["crons"]) == 0, "{code} {out}");
    let (code, out) = m.do_(
        &h,
        "POST",
        "/m/api/sessions/sA/notify-idle",
        r#"{"enabled": false}"#,
    );
    let off = r.st.read(|d| {
        d.sessions
            .get("sA")
            .and_then(|s| s.live.as_ref())
            .is_some_and(|l| l.notify_idle_off)
    });
    assert!(
        code == 200 && out["notifyIdle"] == "off" && off,
        "{code} {out}"
    );
    assert_eq!(
        m.do_(&h, "POST", "/m/api/sessions/sA/watches", "{}").0,
        400,
        "watches refuse an empty one"
    );
    assert_eq!(m.do_(&h, "GET", "/m/api/whatever", "").0, 404, "unknown");
    // a machine that isn't the session's current one gets nothing
    r.st.do_(|d| {
        if let Some(s) = d.sessions.get_mut("sA") {
            s.machine_id = String::new();
        }
    });
    assert_eq!(
        m.do_(&h, "GET", "/m/api/sessions/sA/wakeups", "").0,
        403,
        "stale machine"
    );
}

#[test]
fn machine_api_nothing_goes_to_jarvis1() {
    let _g = serial(); // ICLOUD_INDEX_BASE
    let t = new_test_router();
    let r = t.r.clone();
    add_session(&r, "sA", "started", "mA", false);
    let m = new_test_machine(&r, "mA");
    let h = t.machine_handler();
    // the Claude login is the router's own (claudelogin.rs): a machine whose session has no Claude account gets nothing
    assert_eq!(
        m.do_(&h, "POST", "/m/api/credentials", r#"{"credentials":"{}"}"#)
            .0,
        404
    );
    // a session-scoped path for another session: refused
    assert_eq!(
        m.do_(&h, "GET", "/m/api/sessions/sOther/content", "").0,
        403
    );
    // a Jarvis 1 path that isn't on the list: no route
    assert_eq!(
        m.do_(&h, "POST", "/m/api/sessions/sA/content/x/zip", "").0,
        404
    );
    // transcript search is not Jarvis's (DE0CH/deyao-ai): no route
    assert_eq!(
        m.do_(&h, "GET", "/m/api/search?q=hello+world&n=5", "").0,
        404,
        "search"
    );
    // the iCloud index: only a session whose cert holds the identity store (Deyao, 2026-10-13)
    let seen: Arc<Mutex<Option<String>>> = Arc::default();
    let s2 = seen.clone();
    let icloud = TestServer::handler(move |w, req| {
        let q = req.raw_query.clone();
        *s2.lock().unwrap_or_else(|e| e.into_inner()) = Some(if q.is_empty() {
            req.path.clone()
        } else {
            format!("{}?{q}", req.path)
        });
        w.write_str(r#"{"hits":[]}"#);
    });
    let saved = std::mem::replace(
        &mut *ICLOUD_INDEX_BASE.write().unwrap_or_else(|e| e.into_inner()),
        icloud.url.clone(),
    );
    struct Restore(String);
    impl Drop for Restore {
        fn drop(&mut self) {
            *ICLOUD_INDEX_BASE.write().unwrap_or_else(|e| e.into_inner()) =
                std::mem::take(&mut self.0);
        }
    }
    let _restore = Restore(saved);
    let set_stores = |st: &[&str]| {
        r.st.do_(|d| {
            if let Some(s) = d.sessions.get_mut("sA") {
                s.stores = Some(st.iter().map(|x| x.to_string()).collect());
            }
        })
    };
    let seen_now = || seen.lock().unwrap_or_else(|e| e.into_inner()).clone();
    set_stores(&["default"]);
    for (method, path) in [
        ("GET", "/m/api/icloud/search?q=passport"),
        ("GET", "/m/api/icloud/file?path=a"),
        ("GET", "/m/api/icloud/status"),
        ("POST", "/m/api/icloud/relist"),
        ("POST", "/m/api/icloud/retry"),
    ] {
        let (code, out) = m.do_(&h, method, path, "");
        assert!(
            code == 403
                && seen_now().is_none()
                && out["needsStore"] == "identity"
                && err_of(&out).contains("jarvis-request add-store identity"),
            "{method} {path} without identity: {code} {out}"
        );
    }
    set_stores(&["default", "identity"]);
    let code = m.do_(&h, "GET", "/m/api/icloud/search?q=passport", "").0;
    assert!(
        code == 200 && seen_now().as_deref() == Some("/search?q=passport"),
        "with identity: {code} {:?}",
        seen_now()
    );
    // a machine with no running session can't reach the iCloud index
    let none = new_test_machine(&r, "mNone");
    assert_eq!(
        none.do_(&h, "GET", "/m/api/icloud/search?q=x", "").0,
        403,
        "no session"
    );
    // leases are Jarvis 4's own (leases.rs): never forwarded
    let (code, out) = m.do_(
        &h,
        "POST",
        "/m/api/sessions/sA/leases/iphone",
        r#"{"purpose":"x"}"#,
    );
    assert!(code == 200 && out["status"] == "granted", "{code} {out}");
}

#[test]
fn app_wakeup_routes_and_resume_prompt() {
    let t = new_test_router();
    let r = t.r.clone();
    add_session(&r, "sA", "started", "mA", false);
    // arming from the app could never be delivered (nothing vouches for it): refused upfront, saying what works
    for p in ["/api/sessions/sA/wakeups", "/api/sessions/sA/crons"] {
        let (code, out) = app_do(&r, "POST", p, r#"{"delaySeconds": 60, "prompt": "x"}"#, &[]);
        assert!(
            code == 400 && err_of(&out).contains("Ask the session"),
            "{p}: {code} {out}"
        );
    }
    let at = i64::try_from(GoTime::now().unix_nanos() / 1_000_000).unwrap_or(0) + 3_600_000;
    r.st.do_(|d| {
        d.schedules.insert(
            "sA".into(),
            Schedule {
                wakeups: BTreeMap::from([(
                    "default".to_string(),
                    Wakeup {
                        name: "default".into(),
                        at,
                        prompt: "x".into(),
                        ..Default::default()
                    },
                )]),
                ..Default::default()
            },
        );
    });
    let (code, out) = app_do(&r, "DELETE", "/api/sessions/sA/wakeup?all=1", "", &[]);
    assert!(
        code == 200 && len_of(&out["cancelled"]) == 1,
        "{code} {out}"
    );
    assert_eq!(
        app_do(&r, "GET", "/api/sessions/nope/crons", "", &[]).0,
        404
    );
    let long = format!(r#"{{"prompt": "{}"}}"#, "a".repeat(RESUME_PROMPT_MAX + 1));
    assert_eq!(
        app_do(&r, "POST", "/api/sessions/sA/resume", &long, &[]).0,
        400,
        "too long"
    );
}

#[test]
fn session_api_envs() {
    let mut e = BTreeMap::new();
    session_api_env(&mut e, "claude");
    assert!(
        e.get("JARVIS_URL").map(String::as_str) == Some(MACHINE_API_URL)
            && e.get("CF_ACCESS_CLIENT_ID").is_some_and(|v| !v.is_empty())
            && e.get("SESSION_API_TOKEN").is_some_and(|v| !v.is_empty()),
        "{e:?}"
    );
    let mut e = BTreeMap::new();
    session_api_env(&mut e, "opencode");
    assert!(
        !e.contains_key("CF_ACCESS_CLIENT_ID"),
        "no CF placeholders for opencode"
    );
}

#[test]
fn machine_proposes_new_session() {
    let rg = OpsRig::new();
    let r = rg.t.r.clone();
    add_session(&r, "sA", "started", "mA", false);
    let m = new_test_machine(&r, "mA");
    let h = rg.machine_handler();
    let (code, _) = m.do_(
        &h,
        "POST",
        "/m/api/sessions",
        r#"{"label":"x","prompt":"do it","harness":"claude"}"#,
    );
    assert_eq!(code, 400, "a proposal without a reason was accepted");
    let (code, _) = m.do_(
        &h,
        "POST",
        "/m/api/sessions",
        r#"{"label":"x","prompt":"do it","explanation":"why","attachments":{"uploadId":"u","files":[]}}"#,
    );
    assert_eq!(code, 400, "a proposal with attachments was accepted");
    let body = r#"{"requestId":"r1","label":"YYC parity","prompt":"build it","harness":"claude","stores":["default"],"explanation":"Deyao asked for a new session"}"#;
    let (code, out) = m.do_(&h, "POST", "/m/api/sessions", body);
    assert!(
        code == 200 && !out["id"].is_null() && out["requestId"] == "r1",
        "{code} {out}"
    );
    let id = out["id"].as_str().unwrap_or_default().to_string();
    let (code, out) = m.do_(&h, "POST", "/m/api/sessions", body);
    assert!(
        code == 200 && out["id"] == id.as_str(),
        "a repeat made another session: {code} {out}"
    );
    let want_caller = Caller {
        kind: "session".into(),
        session: "sA".into(),
    };
    wait_for("approval", || {
        r.st.read(|d| {
            d.approvals.values().any(|a| {
                a.kind == "new-session"
                    && a.session == id
                    && a.explanation == "Deyao asked for a new session"
                    && a.origin.as_ref().is_some_and(|o| o.caller == want_caller)
            })
        })
    });
    let s = rg.session(&id);
    assert!(s.state == "approval" && s.prompt == "build it", "{s:?}");
    for i in 2..=3 {
        let (code, out) = m.do_(
            &h,
            "POST",
            "/m/api/sessions",
            &format!(r#"{{"requestId":"r{i}","prompt":"p","explanation":"e"}}"#),
        );
        assert_eq!(code, 200, "{out}");
    }
    wait_for("three approvals", || {
        r.st.read(|d| {
            d.approvals
                .values()
                .filter(|a| a.kind == "new-session")
                .count()
                == 3
        })
    });
    let (code, _) = m.do_(
        &h,
        "POST",
        "/m/api/sessions",
        r#"{"requestId":"r4","prompt":"p","explanation":"e"}"#,
    );
    assert_eq!(code, 429, "a fourth waiting proposal was accepted");
}
