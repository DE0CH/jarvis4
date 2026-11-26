//! timemachine_test.go
use crate::fabricrunner::{FABRIC_FORCE, FabricLine};
use crate::testutil::*;
use crate::timemachine::{FABRIC_HERMIT_CALL, TimeMachine, frozen_verdict};
use crate::vouch::Delivery;
use jarvis_go::GoTime;
use serde_json::Value;
use std::sync::Mutex;
use std::sync::atomic::Ordering;
use std::time::Duration;

/// a fake fabric hermit: the conversation's sandbox state, the calls it got
static FAKE: Mutex<(String, Vec<String>)> = Mutex::new((String::new(), Vec::new()));

fn fake_call(method: &str, path: &str, body: Option<&Value>) -> anyhow::Result<(u16, Vec<u8>)> {
    let mut f = FAKE.lock().unwrap_or_else(|e| e.into_inner());
    let b = body.map_or("null".to_string(), |b| b.to_string());
    f.1.push(format!("{method} {path} {b}"));
    if path.ends_with("/freeze") {
        f.0 = "frozen".into();
    } else if path.ends_with("/thaw") {
        f.0 = "ready".into();
    }
    if f.0.is_empty() {
        return Ok((404, br#"{"code":"no_sandbox"}"#.to_vec()));
    }
    let out = serde_json::json!({"id": "0190f6c2-0000-7000-8000-000000000001", "state": f.0});
    Ok((200, out.to_string().into_bytes()))
}

/// installs the fake with this state; undone when the guard goes
struct FakeHermit;

impl FakeHermit {
    fn install(state: &str) -> FakeHermit {
        *FAKE.lock().unwrap_or_else(|e| e.into_inner()) = (state.into(), vec![]);
        *FABRIC_HERMIT_CALL
            .write()
            .unwrap_or_else(|e| e.into_inner()) = fake_call;
        FABRIC_FORCE.store(true, Ordering::SeqCst);
        FakeHermit
    }
    fn saw(&self, prefix: &str) -> bool {
        FAKE.lock()
            .unwrap_or_else(|e| e.into_inner())
            .1
            .iter()
            .any(|c| c.starts_with(prefix))
    }
    fn calls(&self) -> Vec<String> {
        FAKE.lock().unwrap_or_else(|e| e.into_inner()).1.clone()
    }
}

impl Drop for FakeHermit {
    fn drop(&mut self) {
        FABRIC_FORCE.store(false, Ordering::SeqCst);
    }
}

fn fabric_session(r: &crate::router::Router, id: &str, machine: &str) {
    add_session(r, id, "started", machine, false);
    r.st.do_(|d| {
        if let Some(s) = d.sessions.get_mut(id) {
            s.runner = "fabric".into();
            s.fabric = Some(FabricLine {
                conversation: format!("c-{id}"),
                machine: machine.into(),
                ..Default::default()
            });
        }
    });
}

/// time-machine: the machine's ask freezes its fabric sandbox until then and the session is frozen; a delivery (here
/// an Inbox decision's outcome, which goes only into a running session) thaws it first and the machine reads why it is
/// back; Resume thaws too; only a fabric session has the time machine
#[test]
fn the_time_machine_freezes_and_any_delivery_thaws() {
    let _s = serial();
    let f = FakeHermit::install("ready");
    let r = new_test_router();
    fabric_session(&r, "sT", "x01");
    let m = new_test_machine(&r, "x01");
    let h = r.machine_handler();

    let (code, out) = m.do_(&h, "POST", "/m/api/time-machine", r#"{"seconds": 7200}"#);
    assert!(code == 202 && out["frozen"] == true, "{code} {out}");
    assert_eq!(r.session_state("sT").0, "frozen");
    assert!(
        f.saw("POST /v1/conversations/c-sT/sandbox/freeze {\"until\":\""),
        "{:?}",
        f.calls()
    );
    let (_, out) = m.do_(&h, "GET", "/m/api/time-machine", "");
    assert_eq!(out["frozen"], true, "{out}");
    // a frozen session is not frozen again, and a delivery thaws it before it goes in (the machine here answers
    // nothing, so the delivery itself fails after the thaw: what is checked is the thaw)
    let (code, _) = m.do_(&h, "POST", "/m/api/time-machine", r#"{"seconds": 60}"#);
    assert_eq!(code, 409, "frozen twice");
    let _ = r.deliver_vouched_running(
        "sT",
        Delivery {
            kind: "request-outcome".into(),
            ..Default::default()
        },
    );
    assert!(
        f.saw("POST /v1/conversations/c-sT/sandbox/thaw"),
        "an outcome did not thaw it: {:?}",
        f.calls()
    );
    assert_eq!(r.session_state("sT").0, "started", "after the thaw");
    let (_, out) = m.do_(&h, "GET", "/m/api/time-machine", "");
    assert!(
        out["frozen"] == false
            && out["why"] == "a decision on an Inbox request"
            && !out["back"].is_null(),
        "{out}"
    );

    // Resume (the app, or hermit-jarvis for the chat) thaws a frozen session
    let (code, _) = m.do_(&h, "POST", "/m/api/time-machine", r#"{"seconds": 60}"#);
    assert_eq!(code, 202, "not frozen again");
    r.resume("sT", false).unwrap_or_else(|e| panic!("{e:#}"));
    wait_for("started after Resume", || {
        r.session_state("sT").0 == "started"
    });

    // a session on Fly or AWS has none
    add_session(&r, "sF", "started", "m2", false);
    let m2 = new_test_machine(&r, "m2");
    let (code, out) = m2.do_(&h, "POST", "/m/api/time-machine", r#"{"seconds": 60}"#);
    assert!(
        code == 409 && out["error"].as_str().is_some_and(|e| e.contains("fabric")),
        "{code} {out}"
    );
    // nor a time out of range
    let (code, _) = m.do_(&h, "POST", "/m/api/time-machine", r#"{"seconds": 0}"#);
    assert_eq!(code, 409, "0 s taken");
}

/// hermit thaws a frozen sandbox at its until by itself: the router's loop finds it running again (back, "the time");
/// one hermit no longer has fails the session (Resume starts it from its files)
#[test]
fn frozen_verdicts() {
    for (state, back, lost) in [
        ("ready", true, false),
        ("frozen", false, false),
        ("starting", false, false),
        ("releasing", false, false),
        ("gone", false, true),
        ("", false, true),
    ] {
        assert_eq!(frozen_verdict(state), (back, lost), "{state:?}");
    }
    let r = new_test_router();
    fabric_session(&r, "sB", "x02");
    r.st.do_(|d| {
        if let Some(s) = d.sessions.get_mut("sB") {
            s.state = "frozen".into();
            s.time_machine = Some(TimeMachine {
                since: GoTime::now(),
                ..Default::default()
            });
        }
    });
    r.back("sB", "the time");
    let s =
        r.st.read(|d| d.sessions.get("sB").cloned().unwrap_or_default());
    let tm = s.time_machine.clone().unwrap_or_default();
    assert!(
        s.state == "started" && tm.why == "the time" && tm.back.is_some(),
        "{} {tm:?}",
        s.state
    );
}

/// the loop: a frozen session hermit runs again is back ("the time"); one hermit no longer has is failed
#[test]
fn the_frozen_loop_brings_back_and_fails() {
    let _s = serial();
    let _f = FakeHermit::install("ready");
    let r = new_test_router();
    fabric_session(&r, "sR", "x03");
    r.st.do_(|d| {
        if let Some(s) = d.sessions.get_mut("sR") {
            s.state = "frozen".into();
        }
    });
    r.frozen_tick();
    let s =
        r.st.read(|d| d.sessions.get("sR").cloned().unwrap_or_default());
    assert_eq!(s.state, "started");
    assert_eq!(s.time_machine.unwrap_or_default().why, "the time");

    *FAKE.lock().unwrap_or_else(|e| e.into_inner()) = (String::new(), vec![]);
    r.st.do_(|d| {
        if let Some(s) = d.sessions.get_mut("sR") {
            s.state = "frozen".into();
        }
    });
    r.frozen_tick();
    let s =
        r.st.read(|d| d.sessions.get("sR").cloned().unwrap_or_default());
    assert!(
        s.state == "failed" && s.error.contains("frozen sandbox is gone") && s.failed_at.is_some(),
        "{s:?}"
    );
}

/// a frozen session's final snapshot (its pause, its destroy): the machine answers nothing while frozen, so the router
/// thaws it first and asks it once it reports again (2026-11-19: "silent since", the snapshot never asked for).
/// Through Pause, which sets `pausing` before it asks: the frozen record is the time machine's, not the state (the
/// fabric replica, the same day)
#[test]
fn a_frozen_session_is_thawed_for_its_final_snapshot() {
    let _s = serial();
    let rg = Rig::with(|c| c.snapshot_stall = Duration::from_millis(200));
    let _dms = capture_dm(&rg);
    rg.silent_after_secs.store(2, Ordering::SeqCst);
    let f = FakeHermit::install("frozen");
    rg.running_m2(false);
    let twenty_ago = GoTime::from_unix(GoTime::now().unix() - 20 * 60);
    rg.st.do_(|d| {
        if let Some(s) = d.sessions.get_mut("s1") {
            s.state = "frozen".into();
            s.runner = "fabric".into();
            s.fabric = Some(FabricLine {
                conversation: "c-s1".into(),
                machine: "m2".into(),
                ..Default::default()
            });
            s.time_machine = Some(TimeMachine {
                since: twenty_ago,
                ..Default::default()
            });
            if let Some(l) = s.live.as_mut() {
                l.last_report = twenty_ago; // frozen since: no report
            }
        }
    });
    // the machine reports again once thawed
    let r2 = rg.t.r.clone();
    let reporter = std::thread::spawn(move || {
        for _ in 0..1000 {
            let thawed = FAKE
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .1
                .iter()
                .any(|c| c.starts_with("POST /v1/conversations/c-s1/sandbox/thaw"));
            if thawed {
                r2.st.do_(|d| {
                    if let Some(l) = d.sessions.get_mut("s1").and_then(|s| s.live.as_mut()) {
                        l.last_report = GoTime::now();
                    }
                });
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    });
    rg.pause("s1").unwrap_or_else(|e| panic!("{e:#}"));
    // no snapshot comes from the test's machine: the pause fails at the stall, after asking for it
    rg.wait_action_end("s1", "failed")
        .unwrap_or_else(|e| panic!("{e:#}"));
    let _ = reporter.join();
    assert!(
        f.saw("POST /v1/conversations/c-s1/sandbox/thaw"),
        "not thawed (calls {:?})",
        f.calls()
    );
    let s = rg.session("s1");
    let tm = s.time_machine.clone().unwrap_or_default();
    assert!(
        !s.snapshot_failed.contains("silent since")
            && tm.back.is_some()
            && tm.why == "its final snapshot",
        "not asked for its snapshot after the thaw: {:?} {tm:?}",
        s.snapshot_failed
    );
}

/// New session offers the fabric with a fabric hermit, and not without one
#[test]
fn new_session_offers_the_fabric_with_a_hermit() {
    let _s = serial();
    let offered = || {
        crate::awsrunner::session_runners()
            .iter()
            .any(|g| g.id == "fabric")
    };
    assert!(!offered(), "offered without a fabric hermit");
    let _f = FakeHermit::install("ready");
    assert!(offered(), "not offered with a fabric hermit");
}
