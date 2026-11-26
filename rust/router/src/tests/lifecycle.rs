//! router/lifecycle_test.go
use crate::awsread::AwsInstanceView;
use crate::lifecycle::{
    FlyEvent, FlyLogLine, FlyLogsRefused, LcEntry, LcOp, LcRec, now_text, parse_at,
};
use crate::router::Router;
use crate::sessionlog::{LOG_LIFECYCLE, LOG_SUPERVISOR};
use crate::supervisorlog::{SUP_LOG_MAX_FILE, SUP_LOG_MAX_LINE, SUP_LOG_MAX_LINES, SupLine};
use crate::testutil::*;
use jarvis_go::GoTime;
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use time::Duration as TD;

pub fn sup_push(r: &Arc<Router>, m: &TestMachine, lines: &[&str]) -> u16 {
    let ls: Vec<Value> = lines
        .iter()
        .map(|l| json!({"at": GoTime::now().utc().rfc3339_nano(), "text": l}))
        .collect();
    m.do_(
        &r.machine_handler(),
        "POST",
        "/m/supervisor-log",
        &jarvis_go::marshal(&json!({"lines": ls})),
    )
    .0
}

/// GET …/events (after: a cursor, "" for the newest; q: a query instead)
pub fn events_of(
    r: &Router,
    session: &str,
    after: &str,
    q: &str,
) -> (Vec<Map<String, Value>>, String, Value) {
    let mut target = format!("/api/sessions/{session}/events");
    if !after.is_empty() {
        target += &format!("?after={after}");
    } else if !q.is_empty() {
        target += &format!("?{q}");
    }
    let (code, v) = app_do(r, "GET", &target, "", &[]);
    assert_eq!(code, 200, "events: {v}");
    let es = v["events"]
        .as_array()
        .map(|a| a.iter().filter_map(|e| e.as_object().cloned()).collect())
        .unwrap_or_default();
    let next = v["next"].as_str().unwrap_or_default().to_string();
    (es, next, v)
}

/// the session's latest operation (its kind, state, running, from the stream's start and end marks) and the whole
/// stream
pub fn op_entries(r: &Router, session: &str) -> (Map<String, Value>, Vec<Map<String, Value>>) {
    let (es, _, v) = events_of(r, session, "", "");
    let running = !v["running"].is_null();
    let mut op = Map::new();
    op.insert("running".into(), json!(running));
    for e in &es {
        match e.get("mark").and_then(Value::as_str) {
            Some("start") => {
                op = Map::new();
                op.insert("running".into(), json!(running));
                op.insert("kind".into(), e.get("op").cloned().unwrap_or_default());
                op.insert("id".into(), e.get("opId").cloned().unwrap_or_default());
                op.insert("state".into(), json!("running"));
            }
            Some("end") if e.get("opId") == op.get("id") => {
                op.insert("state".into(), e.get("state").cloned().unwrap_or_default());
                op.insert("text".into(), e.get("text").cloned().unwrap_or_default());
            }
            _ => {}
        }
    }
    assert!(
        op.get("kind").is_some_and(|k| !k.is_null()),
        "no operation in {es:?}"
    );
    (op, es)
}

fn s_of(e: &Map<String, Value>, k: &str) -> String {
    e.get(k)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

pub fn texts(es: &[Map<String, Value>]) -> String {
    es.iter()
        .map(|e| format!("{}|{}\n", s_of(e, "source"), s_of(e, "text")))
        .collect()
}

fn keys_texts(es: &[Map<String, Value>]) -> String {
    es.iter()
        .map(|e| s_of(e, "text"))
        .collect::<Vec<_>>()
        .join(",")
}

/// the machine pushes its lines; the app reads them in the session's events, after a cursor; a machine of no session
/// is refused
#[test]
fn supervisor_log_push_and_read() {
    let _g = serial(); // SUP_LOG_MAX_FILE
    let t = new_test_router();
    let r = t.r.clone();
    add_session(&r, "sA", "started", "mA", false);
    let m = new_test_machine(&r, "mA");
    assert_eq!(
        sup_push(
            &r,
            &m,
            &[
                "supervisor started (oom_score_adj -1000)",
                "guard: exec allowed"
            ]
        ),
        200
    );
    assert_eq!(sup_push(&r, &m, &[&"x".repeat(3000)]), 200);
    let (es, next, v) = events_of(&r, "sA", "", "");
    assert!(
        es.len() == 3 && v["machine"] == "mA" && next == "3.0",
        "{v}"
    );
    let l = &es[2];
    assert!(
        s_of(l, "text").len() <= SUP_LOG_MAX_LINE + 4
            && s_of(l, "machine") == "mA"
            && s_of(l, "source") == "supervisor"
            && s_of(l, "key") == "s3",
        "a long line wasn't clipped"
    );
    let (es, _, _) = events_of(&r, "sA", "2.0", "");
    assert!(
        es.len() == 1 && s_of(&es[0], "key") == "s3",
        "after: {es:?}"
    );
    let stray = new_test_machine(&r, "mX"); // started by the core, but no session's
    assert_eq!(
        sup_push(&r, &stray, &["hello"]),
        404,
        "a machine of no session"
    );
    let too = vec![""; SUP_LOG_MAX_LINES + 1];
    assert_eq!(sup_push(&r, &m, &too), 400, "too many lines");
    // a paused session keeps its log
    r.st.do_(|d| {
        if let Some(s) = d.sessions.get_mut("sA") {
            s.state = "paused".into();
            s.machine_id = String::new();
        }
    });
    assert_eq!(events_of(&r, "sA", "", "").0.len(), 3, "paused");
    // the seq goes on after a router restart (read back from the file)
    let r2 = Router::new(
        r.cfg.clone(),
        r.st.clone(),
        r.core.clone(),
        Default::default(),
    );
    r2.st.do_(|d| {
        if let Some(s) = d.sessions.get_mut("sA") {
            s.machine_id = "mA".into();
        }
    });
    r2.append_sup_log(
        "sA",
        "mA",
        vec![SupLine {
            at: now_text(),
            text: "after restart".into(),
            ..Default::default()
        }],
    )
    .unwrap_or_else(|e| panic!("{e:#}"));
    let (es, next, _) = events_of(&r2, "sA", "", "");
    assert!(es.len() == 4 && next == "4.0", "{es:?} {next}");
}

/// past the cap the file keeps its newer half and says so
#[test]
fn supervisor_log_cap() {
    let _g = serial();
    let t = new_test_router();
    let r = t.r.clone();
    add_session(&r, "sA", "started", "mA", false);
    let old = SUP_LOG_MAX_FILE.swap(4000, Ordering::SeqCst);
    struct Restore(i64);
    impl Drop for Restore {
        fn drop(&mut self) {
            SUP_LOG_MAX_FILE.store(self.0, Ordering::SeqCst);
        }
    }
    let _restore = Restore(old);
    for i in 0..100 {
        let _ = r.append_sup_log(
            "sA",
            "mA",
            vec![SupLine {
                at: now_text(),
                text: format!("line {i:03}"),
                ..Default::default()
            }],
        );
    }
    let n = r.st.log_bytes("sA", LOG_SUPERVISOR);
    assert!(n <= 4000 + 200, "log {n} bytes");
    let ls = r.read_sup_log("sA");
    let (first, last) = (
        ls.first().map(|l| l.text.clone()).unwrap_or_default(),
        ls.last().map(|l| l.text.clone()).unwrap_or_default(),
    );
    assert!(
        first.contains("oldest lines were dropped") && last == "line 099",
        "first {first:?} last {last:?}"
    );
    assert!(
        ls.windows(2).all(|w| w[1].seq > w[0].seq),
        "seq not increasing after a cut"
    );
}

// ---- Fly, faked: events and logs per machine, as Fly answers them (events repeat on every poll) ---------------

#[derive(Default)]
struct FakeFly {
    events: BTreeMap<String, Vec<FlyEvent>>,
    logs: BTreeMap<String, Vec<FlyLogLine>>,
    calls: usize,
    refuse: bool,
}

static FLY: Mutex<Option<FakeFly>> = Mutex::new(None);

fn fly<R>(f: impl FnOnce(&mut FakeFly) -> R) -> R {
    let mut g = FLY.lock().unwrap_or_else(|e| e.into_inner());
    f(g.get_or_insert_with(FakeFly::default))
}

fn fake_fly_events(m: &str) -> anyhow::Result<Vec<FlyEvent>> {
    Ok(fly(|f| {
        f.calls += 1;
        f.events.get(m).cloned().unwrap_or_default()
    }))
}

fn fake_fly_logs(m: &str, next: &str) -> anyhow::Result<(Vec<FlyLogLine>, String)> {
    fly(|f| {
        if f.refuse {
            return Err(FlyLogsRefused(403).into());
        }
        let ls = f.logs.get(m).cloned().unwrap_or_default();
        let i: usize = next.parse().unwrap_or(0);
        Ok((ls[i.min(ls.len())..].to_vec(), ls.len().to_string()))
    })
}

/// the fake Fly on r (its data is global: the caller holds serial())
fn use_fake_fly(r: &Router) {
    *FLY.lock().unwrap_or_else(|e| e.into_inner()) = Some(FakeFly::default());
    let mut h = r.lc.hooks.write().unwrap_or_else(|e| e.into_inner());
    h.fly_events = fake_fly_events;
    h.fly_logs = fake_fly_logs;
    h.fly_on = || true;
    h.poll_every = Duration::from_millis(20);
    h.tail = Duration::from_millis(100);
}

fn ms(t: GoTime) -> i64 {
    i64::try_from(t.unix_nanos() / 1_000_000).unwrap_or(0)
}

fn fly_event(m: &str, kind: &str, status: &str, at: GoTime) {
    fly(|f| {
        f.events.entry(m.into()).or_default().push(FlyEvent {
            kind: kind.into(),
            status: status.into(),
            source: "flyd".into(),
            timestamp: ms(at),
            ..Default::default()
        })
    });
}

fn fly_log(m: &str, provider: &str, msg: &str, at: GoTime) {
    fly(|f| {
        let ls = f.logs.entry(m.into()).or_default();
        let id = ls.len().to_string();
        ls.push(FlyLogLine {
            id,
            timestamp: at.utc().rfc3339_nano(),
            message: msg.into(),
            provider: provider.into(),
        })
    });
}

/// a pause is one operation: the router's steps, Fly's events (each once, though Fly repeats them) and its platform
/// log lines (not the app's stdout), and the supervisor's lines, in time order
#[test]
fn pause_records_its_lifecycle_log() {
    let _g = serial();
    let rg = Rig::with(|c| c.no_access = true);
    use_fake_fly(&rg);
    rg.lc.hooks.write().unwrap_or_else(|e| e.into_inner()).tail = Duration::from_secs(10); // the tail polls on after the pause
    rg.running_m2(false);
    rg.write_snapshot("m2", &rg.files);
    let m = rg.machine("m2");
    let now = GoTime::now();
    fly_event("m2", "exit", "stopped", now);
    fly_event("m2", "destroy", "destroyed", now.add(TD::milliseconds(10)));
    fly_log(
        "m2",
        "runner",
        "Machine destroyed",
        now.add(TD::milliseconds(20)),
    );
    fly_log(
        "m2",
        "app",
        "[jarvis] stdout of the machine",
        now.add(TD::milliseconds(20)),
    );
    sup_push(&rg, &m, &["supervisor: snapshot committed"]);
    rg.pause("s1").unwrap_or_else(|e| panic!("{e:#}"));
    rg.wait_state("s1", "paused", Duration::from_secs(5))
        .unwrap_or_else(|e| panic!("{e:#}"));
    wait_for("Fly read three times", || fly(|f| f.calls >= 3));
    let (op, es) = op_entries(&rg, "s1");
    let all = texts(&es);
    assert!(
        op["kind"] == "pause"
            && op["state"] == "done"
            && op["running"] == false
            && op["text"]
                .as_str()
                .is_some_and(|t| t.starts_with("Pause done after ")),
        "op {op:?}"
    );
    for want in [
        "router|the machine's final snapshot is already here",
        "router|asked the core to destroy the machine on Fly",
        "router|the core confirmed the machine destroyed on Fly",
        "fly|Fly: machine exit → stopped (flyd)",
        "fly|Fly: machine destroy → destroyed (flyd)",
        "fly|Fly runner: Machine destroyed",
        "supervisor|supervisor: snapshot committed",
    ] {
        assert_eq!(all.matches(want).count(), 1, "{want:?} in\n{all}");
    }
    assert!(
        !all.contains("stdout of the machine"),
        "the app's own stdout came in from Fly"
    );
    for w in es.windows(2) {
        assert!(
            !parse_at(&s_of(&w[1], "at")).before(&parse_at(&s_of(&w[0], "at"))),
            "not in time order:\n{all}"
        );
    }
}

/// Fly's logs API refusing the read-only token: one note, then events only
#[test]
fn fly_logs_refused_falls_back_to_events() {
    let _g = serial();
    let t = new_test_router_with(|c| c.no_access = true, None, Default::default());
    let r = t.r.clone();
    use_fake_fly(&r);
    fly(|f| f.refuse = true);
    add_session(&r, "sA", "started", "mA", false);
    let h = r.lc_begin("sA", "pause");
    h.machine("mA");
    fly_event("mA", "start", "started", GoTime::now());
    std::thread::sleep(Duration::from_millis(100));
    h.end("done", "");
    std::thread::sleep(Duration::from_millis(150));
    let (_, es) = op_entries(&r, "sA");
    let all = texts(&es);
    assert!(
        all.matches("HTTP 403 for the router's read-only token")
            .count()
            == 1
            && all.matches("start → started").count() == 1,
        "{all}"
    );
}

/// the dedupe: the same Fly event seen on every poll is kept once; an event from before the operation isn't
#[test]
fn fly_event_dedupe() {
    let _g = serial();
    let t = new_test_router();
    let r = t.r.clone();
    use_fake_fly(&r);
    r.lc.hooks
        .write()
        .unwrap_or_else(|e| e.into_inner())
        .poll_every = Duration::from_secs(3600); // polled by hand
    add_session(&r, "sA", "started", "mA", false);
    fly_event("mA", "launch", "created", GoTime::now().add(-TD::hours(1)));
    let h = r.lc_begin("sA", "boot");
    h.machine("mA");
    fly_event("mA", "start", "started", GoTime::now());
    for _ in 0..3 {
        r.lc_poll_once(&h.run());
    }
    let (_, entries) = r.lc_read("sA");
    let got = entries.get(&h.op_id()).cloned().unwrap_or_default();
    assert!(
        got.len() == 1 && got[0].text.contains("start → started"),
        "{got:?}"
    );
}

/// the merge: router and Fly entries and the supervisor lines of the op's machines in its window, by time
#[test]
fn lifecycle_merge_order() {
    let t = new_test_router();
    let r = t.r.clone();
    let t0 = GoTime::parse("2026-10-16T12:00:00Z").unwrap_or_default();
    let at = |s: i64| t0.add(TD::seconds(s)).rfc3339_nano();
    let op = LcOp {
        id: "o".into(),
        started: at(0),
        ended: at(10),
        state: "done".into(),
        machines: vec!["m1".into()],
        ..Default::default()
    };
    let e = |s: i64, src: &str, text: &str| LcEntry {
        at: at(s),
        source: src.into(),
        text: text.into(),
        ..Default::default()
    };
    let own = vec![e(1, "router", "r1"), e(5, "fly", "f5"), e(3, "fly", "f3")];
    let sl = |s: i64, m: &str, text: &str| SupLine {
        at: at(s),
        machine: m.into(),
        text: text.into(),
        ..Default::default()
    };
    let sup = vec![
        sl(-60, "m1", "too early"),
        sl(-2, "m1", "s-2"),
        sl(4, "m1", "s4"),
        sl(4, "m9", "other machine"),
        sl(35, "m1", "s35"),
        sl(60, "m1", "too late"),
    ];
    let got: Vec<String> = r
        .lc_op_log(&op, &own, &sup)
        .into_iter()
        .map(|e| e.text)
        .collect();
    assert_eq!(got.join(","), "s-2,r1,f3,s4,f5,s35");
}

/// Destroy: the supervisor log and every operation (the destroy's too, up to its upload) go into the archive, then
/// out of the database
#[test]
fn destroy_archives_the_logs() {
    let rg = Rig::with(|c| c.no_access = true);
    rg.running_m2(false);
    rg.write_snapshot("m2", &rg.files);
    let m = rg.machine("m2");
    sup_push(&rg, &m, &["supervisor started"]);
    rg.destroy("s1").unwrap_or_else(|e| panic!("{e:#}"));
    wait_for("the record", || {
        rg.record("s1").is_some_and(|x| x.archive.is_some())
    });
    let file = rg
        .record("s1")
        .and_then(|x| x.archive)
        .map(|a| a.file)
        .unwrap_or_default();
    let (files, _) = rg.dav.archive(&file);
    let sup = String::from_utf8_lossy(
        files
            .get("jarvis2/supervisor-log.jsonl")
            .map_or(&[][..], |v| v),
    )
    .into_owned();
    assert!(sup.contains("supervisor started"), "supervisor log {sup:?}");
    let ops: Vec<Value> =
        serde_json::from_slice(files.get("jarvis2/lifecycle.json").map_or(&[][..], |v| v))
            .unwrap_or_default();
    assert!(
        ops.len() == 1 && ops[0]["kind"] == "destroy",
        "lifecycle.json {ops:?}"
    );
    let b = jarvis_go::marshal(&ops[0]["entries"]);
    assert!(
        b.contains("uploading the archive") && b.contains("supervisor started"),
        "entries {b}"
    );
    // the record is written a moment before the logs leave the database (flows.rs destroy: finish, then the drops)
    wait_for("the logs out of the database", || {
        rg.st
            .read_log("s1", LOG_SUPERVISOR)
            .unwrap_or_default()
            .is_empty()
            && rg
                .st
                .read_log("s1", LOG_LIFECYCLE)
                .unwrap_or_default()
                .is_empty()
    });
}

/// the supervisor's pause/resume of the Claude process: queued for the machine, and an operation of its own
#[test]
fn harness_pause_queues_the_command() {
    let t = new_test_router();
    let r = t.r.clone();
    add_session(&r, "sA", "started", "mA", false);
    let (code, v) = app_do(
        &r,
        "POST",
        "/api/sessions/sA/harness",
        r#"{"action":"pause"}"#,
        &[],
    );
    assert!(code == 200 && v["command"] == "pause-harness", "{code} {v}");
    assert_eq!(take_cmd(&r, "mA").as_deref(), Some("pause-harness"));
    let (code, _) = app_do(
        &r,
        "POST",
        "/api/sessions/sA/harness",
        r#"{"action":"stop"}"#,
        &[],
    );
    assert_eq!(code, 400);
    app_do(
        &r,
        "POST",
        "/api/sessions/sA/harness",
        r#"{"action":"resume"}"#,
        &[],
    );
    assert_eq!(
        wait_cmd(&r, "mA", Duration::from_secs(5)).as_deref(),
        Some("resume-harness")
    );
    let (op, es) = op_entries(&r, "sA");
    assert!(
        op["kind"] == "harness-resume" && texts(&es).contains("sent the supervisor resume-harness"),
        "{op:?} {es:?}"
    );
    r.st.do_(|d| {
        if let Some(s) = d.sessions.get_mut("sA") {
            s.machine_id = String::new();
        }
    });
    let (code, _) = app_do(
        &r,
        "POST",
        "/api/sessions/sA/harness",
        r#"{"action":"pause"}"#,
        &[],
    );
    assert_eq!(code, 409);
}

/// an operation left open by a crash is closed as cut off at the next leader's start
#[test]
fn lifecycle_cut_off() {
    let t = new_test_router_with(|c| c.no_access = true, None, Default::default());
    let r = t.r.clone();
    add_session(&r, "sA", "started", "mA", false);
    let _h = r.lc_begin("sA", "pause");
    let r2 = Router::new(
        r.cfg.clone(),
        r.st.clone(),
        r.core.clone(),
        Default::default(),
    );
    r2.lc_cut_off();
    let (op, _) = op_entries(&r2, "sA");
    assert!(
        op["state"] == "cut off"
            && op["text"]
                .as_str()
                .is_some_and(|t| t.contains("the router restarted while it ran")),
        "{op:?}"
    );
}

/// the session's one stream: the supervisor's lines from every machine and each operation's start, steps, Fly entries
/// and end, all in time order; the cursor gives only what was written since, also an entry that sorts before others
#[test]
fn session_events_one_stream() {
    let t = new_test_router();
    let r = t.r.clone();
    add_session(&r, "sA", "started", "m1", false);
    let t0 = GoTime::now().utc().add(-TD::minutes(1));
    let at = |s: i64| t0.add(TD::seconds(s)).rfc3339_nano();
    let sup = |m: &str, s: i64, text: &str| {
        r.append_sup_log(
            "sA",
            m,
            vec![SupLine {
                at: at(s),
                text: text.into(),
                ..Default::default()
            }],
        )
        .unwrap_or_else(|e| panic!("{e:#}"));
    };
    let entry = |s: i64, src: &str, m: &str, text: &str| LcRec {
        op_id: "o1".into(),
        entry: Some(LcEntry {
            at: at(s),
            source: src.into(),
            machine: m.into(),
            text: text.into(),
        }),
        ..Default::default()
    };
    sup("m0", 0, "s0 old machine");
    let mut op = LcOp {
        id: "o1".into(),
        session: "sA".into(),
        kind: "pause".into(),
        started: at(1),
        state: "running".into(),
        machines: vec!["m1".into()],
        ..Default::default()
    };
    r.lc_write(
        "sA",
        LcRec {
            op: Some(op.clone()),
            ..Default::default()
        },
    );
    r.lc_write("sA", entry(2, "router", "", "r2"));
    sup("m1", 3, "s3");
    r.lc_write("sA", entry(4, "fly", "m1", "f4"));

    let (es, next, v) = events_of(&r, "sA", "", "");
    assert_eq!(keys_texts(&es), "s0 old machine,Pause started,r2,s3,f4");
    assert!(
        v["running"]["kind"] == "pause" && v["running"]["id"] == "o1",
        "running {}",
        v["running"]
    );
    assert!(
        s_of(&es[1], "mark") == "start"
            && s_of(&es[1], "op") == "pause"
            && s_of(&es[2], "op") == "pause"
            && s_of(&es[2], "source") == "router"
            && s_of(&es[3], "source") == "supervisor"
            && es[3].get("op").is_none_or(Value::is_null)
            && s_of(&es[4], "source") == "fly"
            && s_of(&es[4], "machine") == "m1",
        "{es:?}"
    );
    assert_eq!(next, "2.3");
    // nothing new: nothing
    let (es2, n2, _) = events_of(&r, "sA", &next, "");
    assert!(es2.is_empty() && n2 == next, "{es2:?} {n2}");
    // later: a Fly event read late (it happened before s3), a supervisor line, and the end
    r.lc_write("sA", entry(2 /* sorts before s3 */, "fly", "", "f2 late"));
    sup("m1", 6, "s6");
    op.state = "failed".into();
    op.ended = at(7);
    op.error = "the snapshot never came".into();
    r.lc_write(
        "sA",
        LcRec {
            op: Some(op.clone()),
            ..Default::default()
        },
    );
    let (es, next, v) = events_of(&r, "sA", &next, "");
    assert_eq!(
        keys_texts(&es),
        "f2 late,s6,Pause failed after 6 s: the snapshot never came"
    );
    assert!(
        v["running"].is_null()
            && s_of(&es[2], "mark") == "end"
            && s_of(&es[2], "state") == "failed"
            && next == "3.5",
        "{v} {next}"
    );
    // the whole stream again, in time order, and the newest only with a limit
    let (es, _, _) = events_of(&r, "sA", "", "");
    assert_eq!(
        keys_texts(&es),
        "s0 old machine,Pause started,r2,f2 late,s3,f4,s6,Pause failed after 6 s: the snapshot never came"
    );
    let (es, _, v) = events_of(&r, "sA", "", "limit=2");
    assert!(
        keys_texts(&es) == "s6,Pause failed after 6 s: the snapshot never came"
            && v["more"] == true,
        "{} {}",
        keys_texts(&es),
        v["more"]
    );
    // a backlog of supervisor lines comes limit at a time
    assert_eq!(events_of(&r, "sA", "0.5", "").0.len(), 3);
    let (code, _) = app_do(
        &r,
        "GET",
        "/api/sessions/sA/events?after=1.5&limit=1",
        "",
        &[],
    );
    assert_eq!(code, 200);
    let (_, v) = app_do(
        &r,
        "GET",
        "/api/sessions/sA/events?after=0.5&limit=1",
        "",
        &[],
    );
    assert!(v["more"] == true && v["next"] == "1.5", "{v}");
    let (code, _) = app_do(&r, "GET", "/api/sessions/sA/events?after=nonsense", "", &[]);
    assert_eq!(code, 400);
    let (code, _) = app_do(&r, "GET", "/api/sessions/nope/events", "", &[]);
    assert_eq!(code, 404);
    // the old separate views are gone (no API answer: the web page's files)
    for p in ["supervisor-log", "lifecycle", "lifecycle/o1"] {
        let (_, v) = app_do(&r, "GET", &format!("/api/sessions/sA/{p}"), "", &[]);
        assert!(
            v.as_object().is_none_or(Map::is_empty),
            "{p} still answers: {v}"
        );
    }
}

/// an operation stays current until its end record is written: whoever sees none running finds its end in the file
/// and nothing of it still being written (DECISIONS 213). The file lock held here stands for a slow write.
#[test]
fn an_operation_ends_once_its_record_is_written() {
    let t = new_test_router();
    let r = t.r.clone();
    add_session(&r, "sA", "started", "mA", false);
    let op = r.lc_begin("sA", "boot");
    let g = r.lc.file_lock();
    let th = std::thread::spawn(move || op.end("done", ""));
    for _ in 0..50 {
        // the old order dropped it from current at once, with its record still to write
        assert!(
            r.lc_current("sA").is_some(),
            "no running operation while its end record is still unwritten"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
    drop(g);
    let _ = th.join();
    assert!(
        r.lc_current("sA").is_none(),
        "the operation is still current after its end"
    );
    let (o, _) = op_entries(&r, "sA");
    assert_eq!(o["state"], "done", "{o:?}");
}

// ---- AWS, faked ------------------------------------------------------------------------------------------------

static AWS_CUR: Mutex<Option<AwsInstanceView>> = Mutex::new(None);
static AWS_FLY_CALLS: Mutex<usize> = Mutex::new(0);

fn aws_set(v: Option<AwsInstanceView>) {
    *AWS_CUR.lock().unwrap_or_else(|e| e.into_inner()) = v;
}

fn fake_aws_describe(m: &str) -> anyhow::Result<Option<AwsInstanceView>> {
    let cur = AWS_CUR.lock().unwrap_or_else(|e| e.into_inner()).clone();
    Ok(cur.filter(|c| c.id == m))
}

fn counted_fly_events(_: &str) -> anyhow::Result<Vec<FlyEvent>> {
    *AWS_FLY_CALLS.lock().unwrap_or_else(|e| e.into_inner()) += 1;
    Ok(vec![])
}

fn counted_fly_logs(_: &str, n: &str) -> anyhow::Result<(Vec<FlyLogLine>, String)> {
    *AWS_FLY_CALLS.lock().unwrap_or_else(|e| e.into_inner()) += 1;
    Ok((vec![], n.to_string()))
}

/// an AWS machine's operation: one entry per change of the instance's state as EC2 describes it (launched, running,
/// shutting-down and terminated with EC2's reasons, then gone), each once though every poll sees it; nothing of Fly
#[test]
fn lifecycle_aws_events() {
    let _g = serial();
    let t = new_test_router();
    let r = t.r.clone();
    *AWS_FLY_CALLS.lock().unwrap_or_else(|e| e.into_inner()) = 0;
    {
        let mut h = r.lc.hooks.write().unwrap_or_else(|e| e.into_inner());
        h.poll_every = Duration::from_secs(3600); // polled by hand
        h.fly_on = || true;
        h.fly_events = counted_fly_events;
        h.fly_logs = counted_fly_logs;
        h.aws_on = || true;
        h.aws_describe = fake_aws_describe;
    }
    aws_set(None);
    add_session(&r, "sA", "started", "i-0abc", false);
    // an AWS session: its runner says so, not its id
    r.st.do_(|d| {
        if let Some(s) = d.sessions.get_mut("sA") {
            s.runner = "aws".into();
        }
    });
    let h = r.lc_begin("sA", "boot");
    h.machine("i-0abc");
    let run = h.run();
    let launched = GoTime::now().utc();
    let base = AwsInstanceView {
        id: "i-0abc".into(),
        region: "eu-west-2".into(),
        type_: "t3.medium".into(),
        zone: "eu-west-2a".into(),
        launched,
        ..Default::default()
    };
    let poll = |n: usize| {
        for _ in 0..n {
            r.lc_poll_once(&run);
        }
    };
    aws_set(Some(AwsInstanceView {
        state: "pending".into(),
        ..base.clone()
    }));
    poll(2);
    aws_set(Some(AwsInstanceView {
        state: "running".into(),
        public_ip: "18.130.1.2".into(),
        ..base.clone()
    }));
    poll(2);
    let v3 = AwsInstanceView {
        state: "shutting-down".into(),
        reason_code: "Client.InstanceInitiatedShutdown".into(),
        reason_msg: "Client.InstanceInitiatedShutdown: Instance initiated shutdown".into(),
        transition: "User initiated".into(),
        ..base.clone()
    };
    aws_set(Some(v3.clone()));
    poll(1);
    aws_set(Some(AwsInstanceView {
        state: "terminated".into(),
        ..v3
    }));
    poll(2);
    aws_set(None);
    poll(2);
    let (_, entries) = r.lc_read("sA");
    let es = entries.get(&h.op_id()).cloned().unwrap_or_default();
    for e in &es {
        assert!(e.source == "aws" && e.machine == "i-0abc", "{e:?}");
    }
    let got: Vec<String> = es.iter().map(|e| e.text.clone()).collect();
    let want = [
        "AWS: instance launched (t3.medium in eu-west-2a)",
        "AWS: instance running (public IPv4 18.130.1.2)",
        "AWS: instance shutting-down: Client.InstanceInitiatedShutdown: Instance initiated shutdown; User initiated",
        "AWS: instance terminated: Client.InstanceInitiatedShutdown: Instance initiated shutdown; User initiated",
        "AWS: EC2 no longer lists instance i-0abc",
    ];
    assert_eq!(got.join("\n"), want.join("\n"));
    let fc = *AWS_FLY_CALLS.lock().unwrap_or_else(|e| e.into_inner());
    assert_eq!(fc, 0, "Fly asked about an EC2 instance");
    assert!(
        es.first().is_some_and(|e| parse_at(&e.at) == launched),
        "launched isn't at EC2's launch time"
    );
}

/// an instance already up when the operation began (a pause): only its changes from then on; a stop's time is EC2's
#[test]
fn lifecycle_aws_running_before() {
    let _g = serial();
    let t = new_test_router();
    let r = t.r.clone();
    {
        let mut h = r.lc.hooks.write().unwrap_or_else(|e| e.into_inner());
        h.poll_every = Duration::from_secs(3600);
        h.aws_on = || true;
        h.aws_describe = fake_aws_describe;
    }
    let now = GoTime::now().utc();
    let stop_at = GoTime::from_unix(now.unix() - 3);
    let launched = now.add(-TD::hours(1));
    aws_set(Some(AwsInstanceView {
        id: "i-0def".into(),
        region: "ap-southeast-1".into(),
        state: "running".into(),
        launched,
        ..Default::default()
    }));
    add_session(&r, "sB", "started", "i-0def", false);
    // an AWS session: its runner says so, not its id
    r.st.do_(|d| {
        if let Some(s) = d.sessions.get_mut("sB") {
            s.runner = "aws".into();
        }
    });
    let h = r.lc_begin("sB", "pause");
    h.machine("i-0def");
    r.lc_poll_once(&h.run());
    let stamp = format!(
        "{} {}",
        &stop_at.rfc3339()[..10],
        &stop_at.rfc3339()[11..19]
    );
    aws_set(Some(AwsInstanceView {
        id: "i-0def".into(),
        state: "shutting-down".into(),
        launched,
        transition: format!("User initiated ({stamp} GMT)"),
        ..Default::default()
    }));
    r.lc_poll_once(&h.run());
    let (_, entries) = r.lc_read("sB");
    let es = entries.get(&h.op_id()).cloned().unwrap_or_default();
    assert!(
        es.len() == 1
            && es[0].text == format!("AWS: instance shutting-down: User initiated ({stamp} GMT)")
            && parse_at(&es[0].at) == stop_at,
        "{es:?}"
    );
}
