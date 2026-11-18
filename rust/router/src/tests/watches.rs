use crate::testutil::{FakeDelivery, add_session, body, call, new_test_machine, new_test_router};
use crate::watches::{
    CheckResult, RUN_CHECK_HOOK, WATCH_MAX_INTERVAL, WATCH_MAX_SCRIPT, WATCH_MAX_SECONDS,
    WATCH_MIN_INTERVAL, Watch, normalize_watch,
};
use jarvis_go::GoTime;
use serde_json::Value;
use std::sync::Mutex;

#[test]
fn normalize_watches() {
    let now = GoTime::parse("2026-10-13T12:00:00Z").unwrap_or_default();
    let ms = now.unix() * 1000;
    let w = normalize_watch(&body(r#"{"name":"ci","script":"exit 1\r\n","prompt":" go\n on ","interval":5,"maxSeconds":3600}"#), now)
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert!(
        w.script == "exit 1\n"
            && w.prompt == "go on"
            && w.interval == WATCH_MIN_INTERVAL as i64
            && w.max_seconds == 3600
            && w.next_at == ms,
        "{w:?}"
    );
    let w = normalize_watch(&body(r#"{"name":"a","script":"x","prompt":"p"}"#), now)
        .unwrap_or_default();
    assert!(
        w.interval == 60 && w.max_seconds == 7 * 86400,
        "defaults {w:?}"
    );
    let w = normalize_watch(
        &body(
            r#"{"name":"a","script":"x","prompt":"p","maxSeconds":99999999999,"interval":99999}"#,
        ),
        now,
    )
    .unwrap_or_default();
    assert!(
        w.max_seconds == WATCH_MAX_SECONDS as i64 && w.interval == WATCH_MAX_INTERVAL as i64,
        "ceilings {w:?}"
    );
    let long = format!(
        r#"{{"name":"a","script":"{}","prompt":"p"}}"#,
        "x".repeat(WATCH_MAX_SCRIPT + 1)
    );
    for b in [
        r#"{"script":"x","prompt":"p"}"#,
        r#"{"name":"a","prompt":"p"}"#,
        r#"{"name":"a","script":"x"}"#,
        r#"{"name":"bad name","script":"x","prompt":"p"}"#,
        r#"{"name":"a","script":"x","prompt":"p","maxSeconds":-1}"#,
        &long,
    ] {
        assert!(
            normalize_watch(&body(b), now).is_err(),
            "{b} should be refused"
        );
    }
}

/// the fake runner's exit and the checks it ran
static RUNNER: Mutex<(i64, Vec<String>)> = Mutex::new((1, vec![]));

fn fake_check(w: &Watch) -> anyhow::Result<CheckResult> {
    let mut g = RUNNER.lock().unwrap_or_else(|e| e.into_inner());
    g.1.push(w.name.clone());
    Ok(CheckResult {
        exit: g.0,
        stdout: format!("found {}", w.name),
        stderr: "note\nlast line".into(),
        ..Default::default()
    })
}

fn set_exit(e: i64) {
    RUNNER.lock().unwrap_or_else(|e| e.into_inner()).0 = e;
}

#[test]
fn watch_lifecycle() {
    let _g = crate::testutil::serial();
    let old = *RUN_CHECK_HOOK.read().unwrap_or_else(|e| e.into_inner());
    *RUN_CHECK_HOOK.write().unwrap_or_else(|e| e.into_inner()) = fake_check;
    *RUNNER.lock().unwrap_or_else(|e| e.into_inner()) = (1, vec![]);
    let res = std::panic::catch_unwind(watch_lifecycle_run);
    *RUN_CHECK_HOOK.write().unwrap_or_else(|e| e.into_inner()) = old;
    if let Err(p) = res {
        std::panic::resume_unwind(p);
    }
}

fn watch_lifecycle_run() {
    let t = new_test_router();
    add_session(&t, "sA", "started", "mA", false);
    add_session(&t, "sB", "paused", "", false);
    let m = new_test_machine(&t, "mA");
    let h = t.machine_handler();
    let fd = FakeDelivery::install(&t);
    let tick = |at: GoTime| {
        for j in t.watch_tick(at) {
            let _ = j.join();
        }
    };
    let (code, out) = m.do_(&h, "POST", "/m/api/sessions/sA/watches", r#"{"name":"ci","script":"exit 1","prompt":"CI done","failPrompt":"gave up","interval":30}"#);
    assert!(
        code == 200 && out["ok"] == true && out["watch"]["name"] == "ci",
        "{code} {out}"
    );
    assert!(
        out["watch"].get("script").is_none(),
        "the view carries no script"
    );
    assert_eq!(
        m.do_(
            &h,
            "POST",
            "/m/api/sessions/sB/watches",
            r#"{"name":"x","script":"x","prompt":"p"}"#
        )
        .0,
        403,
        "another session's path"
    );
    assert_eq!(
        call(
            &t.handler(),
            "POST",
            "/api/sessions/sA/watches",
            r#"{"name":"x","script":"x","prompt":"p"}"#
        )
        .0,
        400,
        "the app can't arm one"
    );
    assert_eq!(
        t.pending_schedule("sA"),
        ["watch ci"],
        "a watch keeps the session"
    );
    // not yet: checked, kept, next check an interval later
    tick(GoTime::now());
    let ws = t.list_watches("sA").unwrap_or_default();
    assert!(
        ws.len() == 1
            && ws[0]["runs"] == 1
            && ws[0]["lastExit"] == 1
            && ws[0]["lastError"] == "last line"
            && ws[0]["lastOutput"] == "found ci"
            && fd.texts().is_empty(),
        "{ws:?} {:?}",
        fd.texts()
    );
    tick(GoTime::now()); // not due again yet
    assert_eq!(
        RUNNER.lock().unwrap_or_else(|e| e.into_inner()).1.len(),
        1,
        "checked again before its interval"
    );
    // met: the session's own signed request is delivered (kind watch), and the watch is gone
    set_exit(0);
    tick(GoTime::from_unix(GoTime::now().unix() + 31));
    let tx = fd.texts();
    assert!(tx.len() == 1 && tx[0].starts_with("sA: watch "), "{tx:?}");
    assert!(
        t.list_watches("sA").unwrap_or_default().is_empty() && t.pending_schedule("sA").is_empty(),
        "delivered watch kept"
    );
    // give up: exit 3, and the maximum age
    let _ = m.do_(
        &h,
        "POST",
        "/m/api/sessions/sA/watches",
        r#"{"name":"g","script":"exit 3","prompt":"p"}"#,
    );
    set_exit(3);
    tick(GoTime::now());
    let tx = fd.texts();
    assert!(
        tx.len() == 2 && tx[1].starts_with("sA: watch-fail "),
        "{tx:?}"
    );
    let _ = m.do_(
        &h,
        "POST",
        "/m/api/sessions/sA/watches",
        r#"{"name":"old","script":"exit 1","prompt":"p","maxSeconds":60}"#,
    );
    set_exit(1);
    t.st.do_(|d| {
        if let Some(w) = d
            .schedules
            .get_mut("sA")
            .and_then(|s| s.watches.get_mut("old"))
        {
            w.armed_at -= 120_000;
        }
    });
    tick(GoTime::now());
    let tx = fd.texts();
    assert!(
        tx.len() == 3 && tx[2].starts_with("sA: watch-fail "),
        "expired watch: {tx:?}"
    );
    // a failed delivery is retried; the outcome is kept meanwhile
    let _ = m.do_(
        &h,
        "POST",
        "/m/api/sessions/sA/watches",
        r#"{"name":"r","script":"exit 0","prompt":"p"}"#,
    );
    set_exit(0);
    fd.set_err(Some(crate::vouch::NOT_VOUCHED));
    tick(GoTime::now());
    let ws = t.list_watches("sA").unwrap_or_default();
    assert!(
        ws.len() == 1
            && ws[0]["outcome"] == "met"
            && ws[0]["lastError"]
                .as_str()
                .unwrap_or("")
                .starts_with("delivery: "),
        "{ws:?}"
    );
    // cancel
    let (code, out) = m.do_(&h, "DELETE", "/m/api/sessions/sA/watches/r", "");
    assert!(code == 200 && out["ok"] == true, "{code} {out}");
    let (code, out) = call(&t.handler(), "GET", "/api/sessions/sA/watches", "");
    assert!(
        code == 200 && out["watches"].as_array().is_some_and(Vec::is_empty),
        "{code} {out}"
    );
    // the session's view lists them
    let _ = m.do_(
        &h,
        "POST",
        "/m/api/sessions/sA/watches",
        r#"{"name":"v","script":"exit 1","prompt":"p"}"#,
    );
    let v =
        t.st.do_(|d| crate::http::session_view(&d.sessions["sA"], d));
    let ws = v
        .get("watches")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    assert!(ws.len() == 1 && ws[0]["name"] == "v", "{ws:?}");
}
