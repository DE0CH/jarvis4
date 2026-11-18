use crate::terminal::TermSnap;
use crate::testutil::{add_session, call, new_test_machine, new_test_router, new_test_router_on};
use serde_json::json;

/// the read-only terminal: the machine pushes its pane, and the terminal shows it with no grant and no exec
#[test]
fn pushed_screen_needs_no_grant() {
    let t = new_test_router();
    add_session(&t, "sA", "started", "mA", false);
    let m = new_test_machine(&t, "mA");
    let mh = t.machine_handler();
    let ah = t.handler();
    let (code, out) = m.do_(
        &mh,
        "POST",
        "/m/screen",
        &jarvis_go::marshal(&json!({"screen": "\x1b[1mhello\x1b[0m", "cursor": "0,1,80,24,1"})),
    );
    assert_eq!(code, 200, "{out}");
    let (code, v) = call(&ah, "GET", "/api/sessions/sA/terminal", "");
    assert!(
        code == 200
            && v["screen"].as_str().unwrap_or("").contains("hello")
            && v["cursor"] == "0,1,80,24,1"
            && v["at"] != "",
        "{code} {v}"
    );
    // typing still needs the terminal grant
    assert_ne!(
        call(&ah, "POST", "/api/sessions/sA/terminal", r#"{"text":"x"}"#).0,
        200,
        "typing went through without a grant"
    );
    // a stale push (no heartbeat) isn't fresh for the autopilot, but the terminal still shows it, with its time and
    // without running anything in the machine; another machine's push doesn't land on this session
    let _ = t.st.db().and_then(|db| db.conn().ok()).map(|mut c| {
        c.batch_execute(
            "UPDATE session_screens SET at = now() - interval '46 seconds' WHERE session_id = 'sA'",
        )
    });
    assert!(t.pushed_screen("sA").is_none(), "a stale screen was used");
    let (code, v) = call(&ah, "GET", "/api/sessions/sA/terminal", "");
    assert!(
        code == 200 && v["screen"].as_str().unwrap_or("").contains("hello") && v["at"] != "",
        "the terminal didn't show the last screen: {code} {v}"
    );
    // no screen at all: an error, no exec
    add_session(&t, "sC", "started", "mC", false);
    let (code, v) = call(&ah, "GET", "/api/sessions/sC/terminal", "");
    assert!(
        code != 200 && v["error"].as_str().unwrap_or("").contains("no screen"),
        "{code} {v}"
    );
    // any replica sees it: another router on the same database
    let (r2, _dir) = new_test_router_on(&t);
    let _ = t.st.put_screen(
        "sA",
        "mA",
        &TermSnap {
            screen: "fresh".into(),
            ..Default::default()
        },
    );
    assert_eq!(
        r2.pushed_screen("sA").map(|s| s.screen),
        Some("fresh".into()),
        "the other replica doesn't see the push"
    );
    add_session(&t, "sB", "started", "mB", false);
    let other = new_test_machine(&t, "mB");
    let _ = other.do_(
        &mh,
        "POST",
        "/m/screen",
        &jarvis_go::marshal(&json!({"screen": "other", "cursor": "0,0,80,24,1"})),
    );
    assert!(
        !t.pushed_screen("sA")
            .is_some_and(|s| s.screen.contains("other")),
        "another machine's screen"
    );
    // a paused session drops it
    t.st.do_(|d| {
        if let Some(s) = d.sessions.get_mut("sB") {
            s.state = "paused".into();
            s.machine_id.clear();
        }
    });
    assert!(t.pushed_screen("sB").is_none(), "a paused session's screen");
}
