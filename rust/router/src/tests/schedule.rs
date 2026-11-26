//! schedule_test.go
use crate::schedule::{
    Cron, Missed, SCHEDULE_MAX_ATTEMPT, Wakeup, advance_cron, cron_view, iso, normalize_cron,
    normalize_wakeup, sched_backoff_over, sched_idle, schedule_view, session_has_run, will_wake,
};
use crate::testutil::*;
use crate::vouch::SignedRequest;
use jarvis_go::GoTime;
use serde_json::Value;
use std::sync::{Arc, Mutex};
use std::time::Duration;

fn ms(t: &GoTime) -> i64 {
    i64::try_from(t.unix_nanos() / 1_000_000).unwrap_or(0)
}

fn now_ms() -> i64 {
    ms(&GoTime::now())
}

fn at_utc(y: i32, m: u8, d: u8, h: u8) -> GoTime {
    GoTime::parse(&format!("{y:04}-{m:02}-{d:02}T{h:02}:00:00Z")).unwrap_or_default()
}

/// a wakeup or cron as the session's own signed request (its payload is the test's label)
fn signed(label: &str) -> Option<SignedRequest> {
    Some(SignedRequest {
        body: label.into(),
        ..Default::default()
    })
}

fn wait_idle() {
    wait_for("the tick's runs are done", sched_idle);
}

fn wk(name: &str, at: i64, prompt: &str, armed: i64) -> Wakeup {
    Wakeup {
        name: name.into(),
        at,
        prompt: prompt.into(),
        armed_at: armed,
        signed: signed(name),
    }
}

fn cron(name: &str, every: i64, next_at: i64, runs: i64) -> Cron {
    Cron {
        name: name.into(),
        prompt: "do".into(),
        every,
        tz: "UTC".into(),
        next_at,
        armed_at: 1,
        runs,
        signed: signed(name),
        ..Default::default()
    }
}

#[test]
fn normalize_wakeups() {
    let now = at_utc(2026, 10, 9, 12);
    let w = normalize_wakeup(
        &body(r#"{"delaySeconds": 3600, "prompt": "  do\n  it  "}"#),
        now,
    )
    .unwrap_or_else(|e| panic!("{e:#}"));
    assert!(
        w.name == "default"
            && w.at == ms(&now) + 3_600_000
            && w.prompt == "do it"
            && w.armed_at == ms(&now),
        "{w:?}"
    );
    let w = normalize_wakeup(
        &body(r#"{"at": "2026-10-10T08:00:00Z", "prompt": "x", "name": "hotel-1"}"#),
        now,
    )
    .unwrap_or_else(|e| panic!("{e:#}"));
    assert!(
        w.name == "hotel-1" && w.at == ms(&at_utc(2026, 10, 10, 8)),
        "{w:?}"
    );
    let w = normalize_wakeup(&body(r#"{"at": 1791633600000, "prompt": "x"}"#), now)
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert_eq!(w.at, 1_791_633_600_000, "ms epoch");
    // a time already past is due now: it fires at once
    let w = normalize_wakeup(
        &body(r#"{"at": "2026-10-01T00:00:00Z", "prompt": "x"}"#),
        now,
    )
    .unwrap_or_else(|e| panic!("{e:#}"));
    assert_eq!(w.at, ms(&now), "past");
    // up to 400 days, as far as a cron's until
    assert!(
        normalize_wakeup(&body(r#"{"delaySeconds": 8000000, "prompt": "x"}"#), now).is_ok(),
        "93 days"
    );
    let long = format!(
        r#"{{"delaySeconds": 60, "prompt": "{}"}}"#,
        "a".repeat(3501)
    );
    for b in [
        r#"{"delaySeconds": 60}"#,
        r#"{"prompt": "x"}"#,
        r#"{"delaySeconds": -1, "prompt": "x"}"#,
        r#"{"delaySeconds": 40000000, "prompt": "x"}"#,
        r#"{"delaySeconds": 60, "prompt": "x", "name": "bad name"}"#,
        r#"{"at": "tomorrow", "prompt": "x"}"#,
        long.as_str(),
    ] {
        assert!(
            normalize_wakeup(&body(b), now).is_err(),
            "{b} should be refused"
        );
    }
}

#[test]
fn normalize_cron_and_advance() {
    let now = at_utc(2026, 10, 9, 12);
    let c = normalize_cron(
        &body(r#"{"name": "tix", "prompt": "check", "time": "12:00", "tz": "Asia/Shanghai"}"#),
        now,
    )
    .unwrap_or_else(|e| panic!("{e:#}"));
    // 12:00 in Shanghai = 04:00 UTC; today's is past → tomorrow's
    assert!(
        c.next_at == ms(&at_utc(2026, 10, 10, 4)) && c.every == 86400 && c.tz == "Asia/Shanghai",
        "{c:?}"
    );
    let c = normalize_cron(
        &body(r#"{"name": "d", "prompt": "p", "everySeconds": 21600, "until": "2026-12-10T00:00:00Z"}"#),
        now,
    )
    .unwrap_or_else(|e| panic!("{e:#}"));
    assert!(
        c.next_at == ms(&now) + 6 * 3_600_000 && c.until.is_some(),
        "{c:?}"
    );
    for b in [
        r#"{"prompt": "p"}"#,
        r#"{"name": "a", "prompt": "p", "everySeconds": 60}"#,
        r#"{"name": "a", "prompt": "p", "tz": "Mars/Base"}"#,
        r#"{"name": "a", "prompt": "p", "time": "25:00"}"#,
        r#"{"name": "a", "prompt": "p", "until": "2026-10-09T13:00:00Z"}"#,
    ] {
        assert!(
            normalize_cron(&body(b), now).is_err(),
            "{b} should be refused"
        );
    }
    // a first firing already past: the next slot of its period
    let past = GoTime::from_unix(now.unix() - 90 * 60).rfc3339();
    let c = normalize_cron(
        &body(&format!(
            r#"{{"name": "d", "prompt": "p", "everySeconds": 3600, "at": "{past}"}}"#
        )),
        now,
    )
    .unwrap_or_else(|e| panic!("{e:#}"));
    assert_eq!(c.next_at, ms(&now) + 30 * 60_000, "past first firing");
    // a session unreachable for 3.5 periods fires once and moves to the next occurrence after now
    let mut c = Cron {
        every: 3600,
        next_at: ms(&now),
        ..Default::default()
    };
    let next = advance_cron(&c, GoTime::from_unix(now.unix() + 210 * 60));
    assert_eq!(next, Some(ms(&now) + 4 * 3_600_000));
    c.until = Some(ms(&now) + 30 * 60_000);
    assert!(
        advance_cron(&c, GoTime::from_unix(now.unix() + 60)).is_none(),
        "past until: the cron ends"
    );
}

#[test]
fn wakeup_fires_once_and_clears() {
    let _s = serial(); // the scheduler's tick and backoffs are global
    let r = new_test_router();
    let f = FakeDelivery::install(&r);
    add_session(&r, "s1", "started", "m1", false);
    let now = now_ms();
    for w in [
        wk("default", now - 1000, "go", 1),
        wk("later", now + 3_600_000, "not yet", 2),
        wk("named", now - 1000, "x", 3),
    ] {
        r.arm_wakeup("s1", w).unwrap_or_else(|e| panic!("{e:#}"));
    }
    let t = GoTime::now();
    r.schedule_tick(t);
    wait_idle();
    r.schedule_tick(t);
    wait_idle();
    let got = f.texts();
    assert!(
        got.len() == 2
            && got.contains(&"s1: wakeup default".to_string())
            && got.contains(&"s1: wakeup named".to_string()),
        "delivered {got:?}"
    );
    let ws = r.list_wakeups("s1").unwrap_or_default();
    assert!(ws.len() == 1 && ws[0].name == "later", "left {ws:?}");
    assert_eq!(r.pending_schedule("s1"), vec!["wakeup later"]);
}

#[test]
fn wakeup_rearmed_during_fire_is_kept() {
    let _s = serial(); // the scheduler's tick and backoffs are global
    let r = new_test_router();
    add_session(&r, "s1", "started", "m1", false);
    *r.deliver_hook.write().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(|r, _, _| {
        let mut w = wk("default", now_ms() + 3_600_000, "new", 99);
        w.signed = signed("new");
        let _ = r.arm_wakeup("s1", w);
        Ok(())
    }));
    r.arm_wakeup("s1", wk("default", now_ms() - 1000, "old", 1))
        .unwrap_or_else(|e| panic!("{e:#}"));
    r.schedule_tick(GoTime::now());
    wait_for("fired", || {
        r.list_wakeups("s1")
            .unwrap_or_default()
            .iter()
            .any(|w| w.prompt == "new")
    });
    wait_idle();
    let ws = r.list_wakeups("s1").unwrap_or_default();
    assert!(ws.len() == 1 && ws[0].prompt == "new", "{ws:?}");
}

#[test]
fn wakeup_failures_back_off_then_drop() {
    let _s = serial(); // the scheduler's tick and backoffs are global
    let r = new_test_router();
    let dms = capture_dm(&r);
    let f = FakeDelivery::install(&r);
    f.set_err(Some("peer message not delivered: boom"));
    add_session(&r, "s2", "started", "m2", false);
    r.arm_wakeup("s2", wk("default", now_ms() - 1000, "go", 1))
        .unwrap_or_else(|e| panic!("{e:#}"));
    for _ in 0..SCHEDULE_MAX_ATTEMPT {
        r.schedule_tick(GoTime::now());
        wait_idle();
        sched_backoff_over(); // past every backoff
    }
    let ws = r.list_wakeups("s2").unwrap_or_default();
    assert!(
        ws.is_empty(),
        "dropped after {SCHEDULE_MAX_ATTEMPT} attempts: {ws:?}"
    );
    let d = dms.lock().unwrap_or_else(|e| e.into_inner()).clone();
    assert!(
        d.len() == 1 && d[0].contains("could not be delivered"),
        "dms {d:?}"
    );
}

#[test]
fn cron_fires_and_advances() {
    let _s = serial(); // the scheduler's tick and backoffs are global
    let r = new_test_router();
    let f = FakeDelivery::install(&r);
    add_session(&r, "s5", "started", "m5", false);
    let now = now_ms();
    r.arm_cron("s5", cron("daily", 86400, now - 60_000, 0))
        .unwrap_or_else(|e| panic!("{e:#}"));
    r.schedule_tick(GoTime::now());
    wait_idle();
    assert_eq!(f.texts(), vec!["s5: cron daily run 1"]);
    let cs = r.list_crons("s5").unwrap_or_default();
    assert!(
        cs.len() == 1 && cs[0].runs == 1 && cs[0].next_at > now && cs[0].last_fired_at.is_some(),
        "{:?}",
        cs.first()
    );
}

#[test]
fn resume_prompt() {
    let _s = serial(); // the scheduler's tick and backoffs are global
    let r = new_test_router();
    let got: Arc<Mutex<Vec<String>>> = Arc::default();
    {
        let g = got.clone();
        *r.deliver_hook.write().unwrap_or_else(|e| e.into_inner()) =
            Some(Arc::new(move |_, sid, d| {
                assert_eq!(d.kind, "resume-prompt", "a {} delivery", d.kind);
                g.lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(format!("{sid}: {}", d.text));
                Ok(())
            }));
    }
    let texts = || got.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let set_state = |id: &str, st: &str| {
        r.st.do_(|d| {
            if let Some(s) = d.sessions.get_mut(id) {
                s.state = st.into();
            }
        })
    };
    add_session(&r, "s6", "resuming", "", false);
    r.set_resume_prompt("s6", "carry on\nwith B");
    r.schedule_tick(GoTime::now());
    wait_idle();
    assert!(texts().is_empty(), "not before the session is started");
    set_state("s6", "started");
    r.schedule_tick(GoTime::now());
    wait_idle();
    assert_eq!(texts(), vec!["s6: carry on\nwith B"]);
    // a start that failed drops it
    add_session(&r, "s7", "resuming", "", false);
    r.set_resume_prompt("s7", "x");
    set_state("s7", "paused");
    r.schedule_tick(GoTime::now());
    wait_idle();
    set_state("s7", "started");
    r.schedule_tick(GoTime::now());
    wait_idle();
    assert_eq!(
        texts().len(),
        1,
        "a dropped resume prompt never turns up later"
    );
}

#[test]
fn schedule_goes_with_its_session() {
    let _s = serial(); // the scheduler's tick and backoffs are global
    let r = new_test_router();
    add_session(&r, "s8", "started", "m8", false);
    r.arm_wakeup(
        "s8",
        Wakeup {
            name: "default".into(),
            at: now_ms() + 3_600_000,
            prompt: "x".into(),
            armed_at: 1,
            ..Default::default()
        },
    )
    .unwrap_or_else(|e| panic!("{e:#}"));
    assert!(
        r.schedule_due_within("s8", Duration::from_secs(7200))
            && !r.schedule_due_within("s8", Duration::from_secs(60)),
        "due within"
    );
    r.finish("s8", |_| {});
    r.schedule_tick(GoTime::now());
    assert!(
        r.st.read(|d| !d.schedules.contains_key("s8")),
        "the schedule outlived its session"
    );
    let e = r.arm_wakeup(
        "gone",
        Wakeup {
            name: "default".into(),
            ..Default::default()
        },
    );
    assert!(e.is_err(), "{e:?}");
}

/// the autopilot asks the scheduler's veto while it holds the state lock: the veto must not take it again (it did,
/// and the first tick with a started session froze the whole router)
#[test]
fn autopilot_veto_does_not_deadlock() {
    let _s = serial(); // the scheduler's tick and backoffs are global
    let r = new_test_router();
    add_session(&r, "s9", "started", "m9", false);
    r.st.do_(|d| {
        if let Some(s) = d.sessions.get_mut("s9") {
            s.live = Some(crate::autopilot::Liveness {
                reg: Some(crate::registry::Registry {
                    status: "idle".into(),
                    ..Default::default()
                }),
                last_report: GoTime::now(),
                ..Default::default()
            });
        }
    });
    r.arm_wakeup(
        "s9",
        Wakeup {
            name: "default".into(),
            at: now_ms() + 300_000,
            prompt: "x".into(),
            armed_at: 1,
            ..Default::default()
        },
    )
    .unwrap_or_else(|e| panic!("{e:#}"));
    let (tx, rx) = std::sync::mpsc::channel();
    let r2 = r.r.clone();
    std::thread::spawn(move || {
        r2.autopilot_tick();
        let _ = tx.send(());
    });
    assert!(
        rx.recv_timeout(Duration::from_secs(10)).is_ok(),
        "autopilot_tick deadlocked on the scheduler's veto"
    );
}

/// a cron run that fails every attempt (Fly's org machine limit on the resume) is skipped and marked missed; Run now
/// then delivers that same run, counts it, clears the mark and leaves the next occurrence at least half a period away
/// (Deyao, 2026-11-17)
#[test]
fn cron_skipped_is_missed_then_run_now() {
    let _s = serial(); // the scheduler's tick and backoffs are global
    let r = new_test_router();
    let dms = capture_dm(&r);
    let f = FakeDelivery::install(&r);
    f.set_err(Some(r#"the session didn't start (state "failed" start: kernel spawner: HTTP 502 fly create: POST /machines: HTTP 422 {"error":"Your organization has reached its machine limit. Please contact billing@fly.io"})"#));
    add_session(&r, "s6", "paused", "", false);
    let mut c = cron("check", 3600, now_ms() - 60_000, 0);
    c.signed = signed("check");
    r.arm_cron("s6", c).unwrap_or_else(|e| panic!("{e:#}"));
    // Fly's machine limit is a known error: the first failure skips the run, marks it missed in its own words and DMs
    // at once (Deyao, 2026-11-17)
    r.schedule_tick(GoTime::now());
    wait_idle();
    let cs = r.list_crons("s6").unwrap_or_default();
    assert!(
        cs.len() == 1
            && cs[0]
                .missed
                .as_ref()
                .is_some_and(|m| m.run == 1 && m.error == crate::flows::FLY_LIMIT_TEXT)
            && cs[0].runs == 0
            && cs[0].next_at > now_ms(),
        "not marked missed at once: {cs:?}"
    );
    assert!(
        !cron_view(&cs[0])["missed"].is_null(),
        "view without missed"
    );
    let d = dms.lock().unwrap_or_else(|e| e.into_inner()).clone();
    assert!(
        d.len() == 1
            && d[0].contains("Fly's machine limit is reached")
            && d[0].contains("Run now")
            && !d[0].contains("attempts")
            && !d[0].contains("422"),
        "dms {d:?}"
    );
    assert!(f.texts().is_empty(), "delivered {:?}", f.texts());

    f.set_err(None);
    let (code, out) = app_do(&r, "POST", "/api/sessions/s6/crons/check/run", "", &[]);
    assert_eq!(code, 202, "run now: {out}");
    wait_for("delivered", || !f.texts().is_empty());
    wait_idle();
    assert_eq!(f.texts(), vec!["s6: cron check run 1"]);
    let cs = r.list_crons("s6").unwrap_or_default();
    assert!(
        cs[0].missed.is_none()
            && cs[0].runs == 1
            && cs[0].last_fired_at.is_some()
            && cs[0].next_at >= now_ms() + 30 * 60_000,
        "after run now: {:?}",
        cs[0]
    );
    // right after, the session would refuse a repeat: refused upfront, nothing delivered
    let (code, out) = app_do(&r, "POST", "/api/sessions/s6/crons/check/run", "", &[]);
    assert!(
        code == 409
            && out["error"]
                .as_str()
                .is_some_and(|e| e.contains("half its period")),
        "too soon: {code} {out}"
    );
    let (code, _) = app_do(&r, "POST", "/api/sessions/s6/crons/nope/run", "", &[]);
    assert_eq!(code, 404, "unknown cron");
    assert_eq!(f.texts().len(), 1, "delivered again");
}

/// Run now on a wakeup not yet due: delivered at once and done, as its own firing would be
#[test]
fn run_now_wakeup() {
    let _s = serial(); // the scheduler's tick and backoffs are global
    let r = new_test_router();
    let f = FakeDelivery::install(&r);
    add_session(&r, "s7", "started", "m7", false);
    r.arm_wakeup("s7", wk("later", now_ms() + 3_600_000, "go", 1))
        .unwrap_or_else(|e| panic!("{e:#}"));
    let (code, out) = app_do(&r, "POST", "/api/sessions/s7/wakeups/later/run", "", &[]);
    assert_eq!(code, 202, "run now: {out}");
    wait_for("delivered", || !f.texts().is_empty());
    wait_idle();
    assert_eq!(f.texts(), vec!["s7: wakeup later"]);
    assert!(r.list_wakeups("s7").unwrap_or_default().is_empty(), "left");
}

/// a Run now that fails is DMed and marks the run missed; the cron's schedule is left as it was
#[test]
fn run_now_failure_marks_missed() {
    let _s = serial(); // the scheduler's tick and backoffs are global
    let r = new_test_router();
    let dms = capture_dm(&r);
    let f = FakeDelivery::install(&r);
    f.set_err(Some("the session didn't start"));
    add_session(&r, "s8", "paused", "", false);
    let next = now_ms() + 2 * 3_600_000;
    r.arm_cron("s8", cron("d", 86400, next, 3))
        .unwrap_or_else(|e| panic!("{e:#}"));
    r.run_now("s8", "c", "d")
        .unwrap_or_else(|e| panic!("{e:#}"));
    wait_for("missed", || {
        r.list_crons("s8")
            .unwrap_or_default()
            .first()
            .is_some_and(|c| c.missed.is_some())
    });
    wait_idle();
    let cs = r.list_crons("s8").unwrap_or_default();
    assert!(
        cs[0].missed.as_ref().is_some_and(|m| m.run == 4)
            && cs[0].runs == 3
            && cs[0].next_at == next,
        "{:?}",
        cs[0]
    );
    let d = dms.lock().unwrap_or_else(|e| e.into_inner()).clone();
    assert!(d.len() == 1 && d[0].contains("Run now"), "dms {d:?}");
}

fn count_resumes(r: &crate::router::Router) -> Arc<std::sync::atomic::AtomicUsize> {
    let n: Arc<std::sync::atomic::AtomicUsize> = Arc::default();
    let n2 = n.clone();
    *r.resume_failed_hook
        .write()
        .unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(move |r, sid| {
        n2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        r.st.do_(|d| {
            if let Some(s) = d.sessions.get_mut(sid) {
                s.state = "started".into();
            }
        });
        Ok(())
    }));
    n
}

/// a session whose start failed at Fly's machine limit is resumed by Run now, then gets the delivery
#[test]
fn run_now_resumes_a_failed_session() {
    let _s = serial(); // the scheduler's tick and backoffs are global
    let r = new_test_router();
    let f = FakeDelivery::install(&r);
    add_session(&r, "s9", "failed", "", false);
    let resumed = count_resumes(&r);
    r.arm_cron("s9", cron("rel", 1800, now_ms() - 3_600_000, 0))
        .unwrap_or_else(|e| panic!("{e:#}"));
    r.run_now("s9", "c", "rel")
        .unwrap_or_else(|e| panic!("{e:#}"));
    wait_for("delivered", || !f.texts().is_empty());
    wait_idle();
    assert!(
        resumed.load(std::sync::atomic::Ordering::SeqCst) == 1
            && f.texts() == vec!["s9: cron rel run 1"],
        "delivered {:?}",
        f.texts()
    );
}

/// An aviary session's wakeups are magpie's schedules (Deyao, 2026-11-17): hermit-jarvis reports the next one, and the
/// router counts it as armed (a paused session keeps its runners, its card shows it) without ever firing it.
#[test]
fn chat_schedule_counts_as_armed() {
    let _s = serial(); // the scheduler's tick and backoffs are global
    let r = new_test_router();
    add_session(&r, "s1", "paused", "", false);
    add_session(&r, "s2", "running", "", false);
    r.st.do_(|d| {
        if let Some(s) = d.sessions.get_mut("s1") {
            s.harness = "aviary".into();
        }
    });
    let now = GoTime::now();
    let at = now.add_std(Duration::from_secs(5 * 3600));
    let wakes = |sid: &str| r.st.read(|d| will_wake(d, sid));
    assert!(!wakes("s1"), "nothing armed yet");
    r.set_chat_schedule("s1", Some(at), now)
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert!(wakes("s1"), "a chat schedule is an armed wakeup");
    // the session's own retire waits for it, and auto-pause leaves the session running when it is due soon
    assert_eq!(r.pending_schedule("s1").len(), 1);
    assert!(
        !r.schedule_due_within("s1", Duration::from_secs(3600)),
        "due in 5 h, not within 1 h"
    );
    let soon = GoTime::now().add_std(Duration::from_secs(300));
    r.set_chat_schedule("s1", Some(soon), now)
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert!(
        r.schedule_due_within("s1", Duration::from_secs(600)),
        "due in 5 min"
    );
    r.set_chat_schedule("s1", Some(at), now)
        .unwrap_or_else(|e| panic!("{e:#}"));
    let mut v = serde_json::Map::new();
    r.st.read(|d| schedule_view(d, "s1", &mut v));
    assert_eq!(
        v.get("chatScheduleIso"),
        Some(&Value::String(iso(ms(&at)))),
        "view: {v:?}"
    );
    // none armed any more: forgotten, and the schedule entry with it
    r.set_chat_schedule("s1", None, now)
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert!(!wakes("s1"), "cleared");
    assert!(
        r.st.read(|d| !d.schedules.contains_key("s1")),
        "an empty schedule is dropped"
    );
    // only an aviary session has them; an unknown session is 404's error
    assert!(
        r.set_chat_schedule("s2", Some(at), now).is_err(),
        "a claude session has no chat schedules"
    );
    assert!(
        r.set_chat_schedule("nope", Some(at), now).is_err(),
        "unknown session"
    );
}

/// known_error: Fly's machine limit in its own words, anything else as it is
#[test]
fn known_error_fly_limit() {
    let e = anyhow::anyhow!(
        r#"start: kernel spawner: HTTP 502 fly create: POST /machines: HTTP 422 {{"error":"Your organization has reached its machine limit. Please contact billing@fly.io"}}"#
    );
    assert_eq!(crate::flows::known_error(&e), crate::flows::FLY_LIMIT_TEXT);
    let again = anyhow::anyhow!("start: {}", crate::flows::FLY_LIMIT_TEXT);
    assert!(
        crate::flows::fly_machine_limit(&again),
        "the known text no longer reads as the machine limit"
    );
    assert_eq!(crate::flows::known_error(&anyhow::anyhow!("boom")), "boom");
}

/// the session already has the run the router sends (it took the run, but its answer was lost): that run was
/// delivered. The router counts it and moves on, no missed mark, no DM; the next run is the session's next number
#[test]
fn cron_run_the_session_already_has_is_delivered() {
    let _s = serial(); // the scheduler's tick and backoffs are global
    let r = new_test_router();
    let dms = capture_dm(&r);
    let f = FakeDelivery::install(&r);
    f.set_err(Some(
        "the machine refused or failed: cron run 6 was already delivered (last 6)",
    ));
    add_session(&r, "s9", "started", "m9", false);
    let now = now_ms();
    r.arm_cron("s9", cron("diag", 3600, now - 60_000, 5))
        .unwrap_or_else(|e| panic!("{e:#}"));
    r.schedule_tick(GoTime::now());
    wait_idle();
    let cs = r.list_crons("s9").unwrap_or_default();
    assert!(
        cs[0].runs == 6
            && cs[0].missed.is_none()
            && cs[0].next_at > now
            && cs[0].last_fired_at.is_some(),
        "not counted as delivered: {:?}",
        cs[0]
    );
    assert!(
        dms.lock().unwrap_or_else(|e| e.into_inner()).is_empty(),
        "dms"
    );
    // the next occurrence carries run 7
    f.set_err(None);
    r.st.do_(|d| {
        if let Some(c) = d
            .schedules
            .get_mut("s9")
            .and_then(|s| s.crons.get_mut("diag"))
        {
            c.next_at = now_ms() - 1000;
        }
    });
    r.schedule_tick(GoTime::now());
    wait_idle();
    assert_eq!(f.texts(), vec!["s9: cron diag run 7"]);
}

/// the same for a Run now of a run marked missed that the session in fact has: the mark goes, nothing is DMed
#[test]
fn run_now_of_a_run_the_session_already_has() {
    let _s = serial(); // the scheduler's tick and backoffs are global
    let r = new_test_router();
    let dms = capture_dm(&r);
    let f = FakeDelivery::install(&r);
    f.set_err(Some(
        "the machine refused or failed: cron run 6 was already delivered (last 6)",
    ));
    add_session(&r, "s10", "started", "m10", false);
    let mut c = cron("diag", 3600, now_ms() + 3_600_000, 5);
    c.missed = Some(Missed {
        at: 1,
        run: 6,
        error: "x".into(),
    });
    r.arm_cron("s10", c).unwrap_or_else(|e| panic!("{e:#}"));
    r.run_now("s10", "c", "diag")
        .unwrap_or_else(|e| panic!("{e:#}"));
    wait_for("counted", || {
        r.list_crons("s10")
            .unwrap_or_default()
            .first()
            .is_some_and(|c| c.runs == 6)
    });
    wait_idle();
    let cs = r.list_crons("s10").unwrap_or_default();
    assert!(cs[0].runs == 6 && cs[0].missed.is_none(), "{:?}", cs[0]);
    assert!(
        dms.lock().unwrap_or_else(|e| e.into_inner()).is_empty(),
        "dms"
    );
}

/// only the machine's own replay refusal, and only for this run or a later one, counts as delivered
#[test]
fn session_has_runs() {
    for (err, run, want) in [
        (
            "the machine refused or failed: cron run 6 was already delivered (last 6)",
            6,
            Some(6),
        ),
        (
            "the machine refused or failed: cron run 6 was already delivered (last 9)",
            6,
            Some(9),
        ),
        (
            "the machine refused or failed: cron run 6 was already delivered (last 6)",
            7,
            None,
        ),
        (
            "the machine refused or failed: this cron ran less than half its period ago",
            6,
            None,
        ),
        ("the machine didn't answer within 60 s", 6, None),
    ] {
        let e = anyhow::anyhow!("{err}");
        assert_eq!(session_has_run(Some(&e), run), want, "{err:?} run {run}");
    }
    assert!(session_has_run(None, 1).is_none(), "none");
}

/// a scheduled wakeup or cron on a failed session resumes it first, as Run now does (Deyao, 2026-11-18)
#[test]
fn a_scheduled_run_resumes_a_failed_session() {
    let _s = serial(); // the scheduler's tick and backoffs are global
    let r = new_test_router();
    let dms = capture_dm(&r);
    let f = FakeDelivery::install(&r);
    add_session(&r, "s11", "failed", "", false);
    let resumed = count_resumes(&r);
    r.arm_cron("s11", cron("marks", 1800, now_ms() - 60_000, 0))
        .unwrap_or_else(|e| panic!("{e:#}"));
    r.schedule_tick(GoTime::now());
    wait_idle();
    assert!(
        resumed.load(std::sync::atomic::Ordering::SeqCst) == 1
            && f.texts() == vec!["s11: cron marks run 1"],
        "delivered {:?}",
        f.texts()
    );
    r.st.do_(|d| {
        if let Some(s) = d.sessions.get_mut("s11") {
            s.state = "failed".into();
        }
    });
    r.arm_wakeup("s11", wk("once", now_ms() - 1000, "go", 2))
        .unwrap_or_else(|e| panic!("{e:#}"));
    r.schedule_tick(GoTime::now());
    wait_idle();
    let got = f.texts();
    assert!(
        resumed.load(std::sync::atomic::Ordering::SeqCst) == 2
            && got.len() == 2
            && got[1] == "s11: wakeup once",
        "delivered {got:?}"
    );
    assert!(
        dms.lock().unwrap_or_else(|e| e.into_inner()).is_empty(),
        "dms"
    );
}
