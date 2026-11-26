//! handover_test.go: a handover starts the next machine once the old one has been told to stop, without
//! waiting for Fly to report the old one destroyed; the cert still waits for the kill, which names the final snapshot
//! (handover.rs, DECISIONS 193).
use crate::flows::{INIT_STEP_MS, KILL_STEP_MS, KILL_TRANSIENT_STEP_MS};
use crate::handover::{NextMachine, SPARE_MAX_AGE_MS, SPARE_STARTED};
use crate::nethttp::write_json;
use crate::testutil::*;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// the v2 core whose kill of the old machine (m1) answers "not destroyed yet" kills_left times (Fly slow to report it
/// destroyed), whose start makes m2 and whose certify certifies it. events: what happened, in order.
#[derive(Default)]
struct SlowFly {
    kills_left: u32,
    /// approve_by_dead_machine refuses (the resume goes to the phone)
    refuse: bool,
    /// Fly answers m1's kills only once m2's start has reached it, and reports m1 destroyed only once m2 is up. The
    /// start and the first kill are sent together, so which one reaches the core first is the scheduler's pick; a
    /// router that waited for a kill's answer (or Fly's report) before starting m2 would never see m1 destroyed.
    with_kill: bool,
    saw_start: bool,
    saw_init: bool,
    events: Vec<String>,
    /// the bodies of the kills that went through
    killed: Vec<Value>,
}

type Slow = Arc<Mutex<SlowFly>>;

fn sl<R>(c: &Slow, f: impl FnOnce(&mut SlowFly) -> R) -> R {
    f(&mut c.lock().unwrap_or_else(|e| e.into_inner()))
}

fn log(c: &Slow) -> Vec<String> {
    sl(c, |s| s.events.clone())
}

fn index(ev: &[String], e: &str) -> Option<usize> {
    ev.iter().position(|x| x == e)
}

fn hook(c: Slow) -> V2Hook {
    Arc::new(move |w, k, path, b| {
        let s = |v: &Value| v.as_str().unwrap_or_default().to_string();
        match path {
            "/start" => {
                sl(&c, |x| {
                    x.events.push(format!("start {}", s(&b["size"])));
                    x.saw_start = true;
                });
                write_json(
                    w,
                    200,
                    &k.doc(&json!({"kind": "created", "id": "m2", "image": b["image"]})),
                );
            }
            "/init" => {
                sl(&c, |x| {
                    x.events.push("started m2".into());
                    x.saw_init = true;
                });
                write_json(
                    w,
                    200,
                    &k.doc(&json!({"kind": "started", "machine": {"id": "m2", "requested": "x", "image": "x"}})),
                );
            }
            "/approve/by-dead-machine" => {
                if sl(&c, |x| x.refuse) {
                    write_json(w, 403, &k.doc(&json!({"error": "store set, image or options differ from the predecessor's (or a one-time input is asked for)"})));
                    return true;
                }
                let p: Value =
                    serde_json::from_str(b["challenge"]["payload"].as_str().unwrap_or_default())
                        .unwrap_or_default();
                write_json(
                    w,
                    200,
                    &k.doc(&json!({"kind": "approval", "nonce": "b".repeat(64), "request": p["request"]})),
                );
            }
            "/certify" => {
                sl(&c, |x| {
                    x.events.push(format!("certify {}", s(&b["machine"])))
                });
                write_json(
                    w,
                    200,
                    &k.doc(
                        &json!({"kind": "succession-cert", "predecessorId": "m1", "line": "m1",
                    "machine": {"id": b["machine"], "image": "x"}}),
                    ),
                );
            }
            "/kill" => {
                let m = s(&b["machine"]);
                if m == "m1" && sl(&c, |x| x.with_kill) {
                    // the router waits for this kill's answer before it starts m2: then m2's start never comes
                    let end = Instant::now() + Duration::from_secs(10);
                    while !sl(&c, |x| x.saw_start) && Instant::now() < end {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                }
                let slow = sl(&c, |x| {
                    let slow = m == "m1" && (x.kills_left > 0 || x.with_kill && !x.saw_init);
                    if slow && x.kills_left > 0 {
                        x.kills_left -= 1;
                    }
                    slow
                });
                if slow {
                    sl(&c, |x| x.events.push(format!("destroying {m}")));
                    write_json(w, 409, &k.doc(&json!({"error": format!("machine {m} is destroying, not destroyed yet")})));
                    return true;
                }
                let sum = b["snapshot"]["sha256"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string();
                sl(&c, |x| {
                    x.killed.push(b.clone());
                    x.events.push(format!("destroyed {m}"));
                });
                write_json(
                    w,
                    200,
                    &k.doc(&json!({"kind": "killed", "id": m, "snapshot": sum})),
                );
            }
            _ => return false,
        }
        true
    })
}

/// the rig on the slow-Fly core, its steps short; holds serial() (the steps are global) until dropped
struct SlowRig {
    rg: Rig,
    _vc: V2Core,
    c: Slow,
    _steps: Vec<U64Set>,
    _s: std::sync::MutexGuard<'static, ()>,
}

fn slow_fly_rig(kills_left: u32) -> SlowRig {
    let s = serial();
    let c: Slow = Arc::new(Mutex::new(SlowFly {
        kills_left,
        ..Default::default()
    }));
    let (rg, vc) = Rig::v2_hooked(hook(c.clone()));
    let steps = vec![
        set_u64(&KILL_STEP_MS, 10),
        set_u64(&INIT_STEP_MS, 1),
        set_u64(&KILL_TRANSIENT_STEP_MS, 1), // failedsession_test.go's fastKills
    ];
    SlowRig {
        rg,
        _vc: vc,
        c,
        _steps: steps,
        _s: s,
    }
}

/// m2 reports in, so the start's lifecycle operation ends (and writes nothing after the test)
fn booted(rg: &Rig, machine: &str) {
    rg.st.do_(|d| {
        if let Some(s) = d.sessions.get_mut("s1") {
            s.booted = machine.into();
        }
    });
    wait_for("the operation's end", || rg.lc_current("s1").is_none());
    wait_for("the job's end", || rg.ops.busy_of("s1").is_none());
    wait_for("idle", || match rg.lock("s1", "test-end") {
        Ok(u) => {
            u.call();
            true
        }
        Err(_) => false,
    });
}

/// a failed session that still has its machine (its snapshot already sent): Resume finishes the pause; Fly takes 30
/// kill calls to report m1 destroyed, and m2 is created and up before that, certified only after
#[test]
fn a_handover_starts_the_next_machine_before_fly_reports_the_old_one_destroyed() {
    let sr = slow_fly_rig(30);
    let (rg, c) = (&sr.rg, &sr.c);
    sl(c, |x| x.with_kill = true);
    rg.failed_with_machine("kill: core: fly destroy: timeout");
    rg.resume("s1", false).unwrap_or_else(|e| panic!("{e:#}"));
    wait_for("certify", || index(&log(c), "certify m2").is_some());
    let ev = log(c);
    let (destroyed, started) = (index(&ev, "destroyed m1"), index(&ev, "started m2"));
    assert!(
        index(&ev, "start medium").is_some()
            && started.is_some()
            && destroyed.is_some()
            && started < destroyed,
        "m2 is up before Fly reports m1 destroyed: {ev:?}"
    );
    assert!(
        index(&ev, "start medium") < index(&ev, "destroying m1"),
        "m2's start goes with the first kill, not after Fly's report: {ev:?}"
    );
    assert!(
        index(&ev, "certify m2") > destroyed,
        "the cert waits for the kill: {ev:?}"
    );
    let n = ev.iter().filter(|e| e.starts_with("start ")).count();
    assert_eq!(n, 1, "one start (the spare taken): {ev:?}");
    // the kill that let the cert through named the final snapshot
    let k = sl(c, |x| x.killed.first().cloned().unwrap_or_default());
    assert!(
        k["machine"] == "m1"
            && k["snapshot"]["sha256"]
                .as_str()
                .is_some_and(|s| !s.is_empty())
            && k["snapshot"]["required"] == true,
        "the kill that let the cert through names the final snapshot: {k}"
    );
    wait_for("m2 is the session's", || {
        rg.session("s1").machine_id == "m2"
    });
    // the resume's action has ended (its lock is released after its deferred end): its operation goes on until m2
    // reports in (start_and_certify took it over), so nothing writes into an operation that is already over
    wait_for("the resume's action ended", || !rg.busy("s1"));
    assert!(
        rg.lc_current("s1").is_some(),
        "the resume's operation ended before its machine reported in"
    );
    booted(rg, "m2");
}

/// Upgrade: the bigger machine starts right after "free", while the old one snapshots and Fly destroys it
#[test]
fn upgrade_starts_the_bigger_machine_while_the_old_one_stops() {
    let sr = slow_fly_rig(30);
    let (rg, c) = (&sr.rg, &sr.c);
    let cert = rg.v2_cert("m1", r#"{"v":1}"#);
    let started = crate::state::Started {
        id: "m1".into(),
        signing_key: rg.mkey.public(),
        ..Default::default()
    };
    rg.st.do_(|d| {
        if let Some(s) = d.sessions.get_mut("s1") {
            s.state = "started".into();
            s.machine_id = "m1".into();
            s.cert = Some(cert.clone());
        }
        d.started.insert("m1".into(), started.clone());
    });
    rg.upgrade("s1").unwrap_or_else(|e| panic!("{e:#}"));
    wait_for("the spare's start", || {
        index(&log(c), "start large").is_some()
    });
    let ev = log(c);
    assert!(
        index(&ev, "destroyed m1").is_none() && index(&ev, "destroying m1").is_none(),
        "the bigger machine starts while the old one is still there (after free): {ev:?}"
    );
    let end = Instant::now() + Duration::from_secs(20); // the memory-free wait (5 s), then the pause
    while index(&log(c), "certify m2").is_none() {
        assert!(Instant::now() < end, "no certify: {:?}", log(c));
        std::thread::sleep(Duration::from_millis(20));
    }
    let ev = log(c);
    assert!(
        index(&ev, "certify m2") > index(&ev, "destroyed m1")
            && ev.join("|").matches("start ").count() == 1,
        "one start, the cert after the kill: {ev:?}"
    );
    assert_eq!(rg.session("s1").size, "large");
    wait_for("m2 is the session's", || {
        rg.session("s1").machine_id == "m2"
    });
    booted(rg, "m2");
}

/// the resume goes to the phone (the core won't answer it by itself): the spare isn't used and is destroyed
#[test]
fn a_spare_is_destroyed_when_the_resume_goes_to_the_phone() {
    let sr = slow_fly_rig(5);
    let (rg, c) = (&sr.rg, &sr.c);
    sl(c, |x| x.refuse = true);
    rg.failed_with_machine("kill: core: fly destroy: timeout");
    rg.resume("s1", false).unwrap_or_else(|e| panic!("{e:#}"));
    wait_for("the spare destroyed", || {
        index(&log(c), "destroyed m2").is_some()
    });
    assert!(
        index(&log(c), "certify m2").is_none(),
        "certified the spare: {:?}",
        log(c)
    );
    wait_for("the approval", || rg.session("s1").state != "resuming");
    let s = rg.session("s1");
    assert_eq!(
        s.state, "approval",
        "the resume waits for the phone: {:?}",
        s.error
    );
    // the resume sets "approval" a moment before it ends (its lifecycle record, then the unlock; DECISIONS 212)
    wait_for("the resume's action ended", || !rg.busy("s1"));
}

/// the old machine is still answering: the spare starts once the snapshot command (the stop) was sent, never before;
/// the snapshot never comes, so the old machine is kept, nothing is killed or certified, and the spare goes
#[test]
fn the_spare_starts_at_the_stop_and_goes_when_the_old_machine_is_kept() {
    let sr = slow_fly_rig(0);
    let (rg, c) = (&sr.rg, &sr.c);
    rg.failed_with_machine("kill: core: fly destroy: timeout");
    let (tx, rx) = std::sync::mpsc::channel::<bool>();
    let tx = Mutex::new(tx);
    let r = rg.t.r.clone();
    *SPARE_STARTED.write().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(move |_: &str| {
        let cmd = take_cmd(&r, "m1");
        let _ = tx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .send(cmd.as_deref() == Some("snapshot"));
    }));
    struct Unhook;
    impl Drop for Unhook {
        fn drop(&mut self) {
            *SPARE_STARTED.write().unwrap_or_else(|e| e.into_inner()) = None;
        }
    }
    let _unhook = Unhook;
    rg.st.do_(|d| {
        if let Some(s) = d.sessions.get_mut("s1") {
            s.booted = "m1".into();
            s.live.get_or_insert_with(Default::default).last_report = jarvis_go::GoTime::now();
        }
    });
    rg.snap_drop("m1");
    rg.resume("s1", false).unwrap_or_else(|e| panic!("{e:#}"));
    match rx.recv_timeout(Duration::from_secs(5)) {
        Ok(ok) => assert!(ok, "the spare started before the snapshot command was sent"),
        Err(_) => panic!("no spare"),
    }
    wait_for("the spare destroyed", || {
        index(&log(c), "destroyed m2").is_some()
    });
    let ev = log(c);
    assert!(
        index(&ev, "destroyed m1").is_none() && index(&ev, "certify m2").is_none(),
        "the kept machine is killed or the spare certified: {ev:?}"
    );
    wait_for("the resume's action ended", || !rg.busy("s1"));
    let s = rg.session("s1");
    assert!(
        s.machine_id == "m1" && s.state == "failed",
        "kept: {} {} {:?}",
        s.machine_id,
        s.state,
        s.error
    );
}

fn img() -> String {
    format!("img@sha256:{}", "1".repeat(64))
}

/// a spare that asks for another machine than the start (here: another disk) isn't used
#[test]
fn a_spare_for_another_machine_is_not_taken() {
    let sr = slow_fly_rig(0);
    let (rg, c) = (&sr.rg, &sr.c);
    let nm = |size: &str, disk: i64| NextMachine {
        image: img(),
        size: size.into(),
        disk_gb: disk,
        ..Default::default()
    };
    rg.launch_spare("s1", Some(&nm("medium", 20)));
    assert!(
        rg.take_spare("s1", &nm("", 30)).is_none(),
        "took a spare with another disk"
    );
    wait_for("the spare destroyed", || {
        index(&log(c), "destroyed m2").is_some()
    });
    rg.launch_spare("s1", Some(&nm("", 20)));
    assert!(
        rg.take_spare("s1", &nm("medium", 20)).is_some(),
        "the same machine (\"\" = medium) wasn't taken"
    );
}

/// a spare older than SPARE_MAX_AGE is destroyed rather than certified: its machine would have stopped waiting
#[test]
fn an_old_spare_is_destroyed() {
    let sr = slow_fly_rig(0);
    let _age = set_u64(&SPARE_MAX_AGE_MS, 50);
    let (rg, c) = (&sr.rg, &sr.c);
    let nm = NextMachine {
        image: img(),
        ..Default::default()
    };
    rg.launch_spare("s1", Some(&nm));
    wait_for("the old spare destroyed", || {
        index(&log(c), "destroyed m2").is_some()
    });
    assert!(rg.take_spare("s1", &nm).is_none(), "took an expired spare");
}
