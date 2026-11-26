//! tasks_test.go
use crate::autopilot::{DEFAULT_PILOT, Liveness, plan_tick};
use crate::flows::NewSession;
use crate::router::{Busy, Router};
use crate::tasks::{
    InstanceIn, TASK_KEEP_RUNS, TASK_KICK, TASK_MAX_QUEUED, TASK_OPS, TASK_START_MAX, TASKS_DIR,
    TaskInstance, TaskOps, TaskResult, TaskRun, TaskSchedule, check_params, due_slot, line_content,
    line_stores, next_slot, param_env, parse_template, prune_runs, read_templates, tasks_of,
    with_options,
};
use crate::testutil::*;
use jarvis_go::GoTime;
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

fn map(v: Value) -> Map<String, Value> {
    v.as_object().cloned().unwrap_or_default()
}

fn files(f: &[&str]) -> Vec<String> {
    f.iter().map(|x| x.to_string()).collect()
}

// ---- templates ------------------------------------------------------------------------------------------

#[test]
fn parse_templates() {
    let tm = parse_template(
        "x",
        br#"{"title":"X","fields":[{"name":"a"},{"name":"s","type":"select","options":["p",{"value":"q","label":"Q","sub":"qq"}]},
        {"name":"k","type":"select","optionsFrom":"stores"}]}"#,
        &files(&["run.sh"]),
    )
    .unwrap_or_else(|e| panic!("{e}"));
    assert!(
        tm.run == "run.sh"
            && tm.timeout_seconds == 600
            && tm.size == "small"
            && tm.fields[0].type_ == "text"
            && tm.fields[0].label == "a"
            && tm.fields[1].options[1].label == "Q"
            && tm.fields[1].options[0].label == "p"
            && tm.fields[2].options_from == "stores",
        "{tm:?}"
    );
    let p = parse_template("p", br#"{"title":"P"}"#, &files(&["prompt.md"]))
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(p.prompt == "prompt.md" && p.run.is_empty(), "{p:?}");
    for (name, spec) in [
        ("Bad", r#"{"title":"x"}"#),
        ("x", "{}"),
        ("x", r#"{"title":"x","run":"other.py"}"#),
        ("x", r#"{"title":"x","run":"run.sh","prompt":"prompt.md"}"#),
        ("x", r#"{"title":"x","timeoutSeconds":5}"#),
        ("x", r#"{"title":"x","size":"huge"}"#),
        ("x", r#"{"title":"x","stores":["core"]}"#),
        ("x", r#"{"title":"x","fields":[{"name":"a"},{"name":"a"}]}"#),
        (
            "x",
            r#"{"title":"x","fields":[{"name":"a","type":"radio"}]}"#,
        ),
        (
            "x",
            r#"{"title":"x","fields":[{"name":"a","type":"select"}]}"#,
        ),
        (
            "x",
            r#"{"title":"x","fields":[{"name":"a","type":"select","optionsFrom":"environments"}]}"#,
        ),
        (
            "x",
            r#"{"title":"x","fields":[{"name":"k","type":"select","optionsFrom":"stores","secretKeys":["AES_KEY"]}]}"#,
        ),
    ] {
        let res = parse_template(name, spec.as_bytes(), &files(&["run.sh", "prompt.md"]));
        assert!(
            res.is_err() || spec == r#"{"title":"x"}"#,
            "accepted {name} {spec}"
        );
    }
    // run.sh and prompt.md both present, neither named: the script wins
    let x = parse_template("x", br#"{"title":"x"}"#, &files(&["run.sh", "prompt.md"]))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(x.run, "run.sh");
}

/// the repo's own templates are all valid
#[test]
fn repo_templates() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tasks");
    let ts = read_templates(&root);
    assert!(!ts.is_empty(), "no templates in tasks/");
    for tm in ts {
        assert!(tm.error.is_empty(), "{}: {}", tm.name, tm.error);
    }
}

#[test]
fn check_params_and_stores() {
    let tm = parse_template(
        "x",
        br#"{"title":"X","stores":["base"],"fields":[
        {"name":"msg","required":true},{"name":"n","type":"number","default":3},{"name":"on","type":"checkbox"},
        {"name":"pick","type":"select","options":["a","b"],"default":"a"},
        {"name":"keys","type":"select","optionsFrom":"stores"},{"name":"more","type":"multiselect","optionsFrom":"stores"},
        {"name":"size","type":"select","optionsFrom":"sizes"}]}"#,
        &files(&["run.sh"]),
    )
    .unwrap_or_else(|e| panic!("{e}"));
    let tm = with_options(&tm);
    assert!(
        check_params(&tm, &Map::new()).is_err(),
        "a required field passed empty"
    );
    let p = check_params(
        &tm,
        &map(json!({"msg": "hi", "on": "true", "keys": "aes", "more": ["x", "x", "base"], "size": "large", "junk": 1})),
    )
    .unwrap_or_else(|e| panic!("{e:#}"));
    assert!(
        p.get("n").and_then(Value::as_f64) == Some(3.0)
            && p.get("on") == Some(&json!(true))
            && p.get("pick") == Some(&json!("a"))
            && p.get("junk").is_none()
            && p.get("more")
                .and_then(Value::as_array)
                .is_some_and(|a| a.len() == 2),
        "{p:?}"
    );
    assert_eq!(line_stores(&tm, &p).join(","), "aes,base,x");
    for input in [
        json!({"msg": "x", "pick": "c"}),
        json!({"msg": "x", "n": "z"}),
        json!({"msg": "x", "keys": "Bad Name"}),
        json!({"msg": "x", "keys": "core"}),
        json!({"msg": "x", "size": "huge"}),
    ] {
        assert!(
            check_params(&tm, &map(input.clone())).is_err(),
            "accepted {input}"
        );
    }
    assert!(
        param_env(&json!(["a", "b"])) == "a,b"
            && param_env(&json!(2.5)) == "2.5"
            && param_env(&json!(true)) == "true"
            && param_env(&Value::Null).is_empty(),
        "param_env"
    );
}

fn ms_of(s: &str) -> i64 {
    GoTime::parse(s)
        .map(|t| i64::try_from(t.unix_nanos() / 1_000_000).unwrap_or(0))
        .unwrap_or(0)
}

#[test]
fn due_slots() {
    let now = GoTime::parse("2026-10-09T08:30:00Z").unwrap_or_default();
    let mut s = TaskSchedule {
        time: "08:00".into(),
        tz: "UTC".into(),
        enabled: true,
        since: ms_of("2026-10-07T08:30:00Z"),
        ..Default::default()
    };
    let slot = due_slot(&s, now);
    assert_eq!(slot, Some(ms_of("2026-10-09T08:00:00Z")));
    s.last_slot = slot.unwrap_or(0);
    assert!(due_slot(&s, now).is_none(), "fired the same slot twice");
    s.last_slot = 0;
    s.since = ms_of("2026-10-09T08:20:00Z"); // made after the slot
    assert!(
        due_slot(&s, now).is_none(),
        "a schedule made after the slot fired it"
    );
    s.since = 0;
    assert!(
        due_slot(
            &s,
            GoTime::parse("2026-10-09T11:30:00Z").unwrap_or_default()
        )
        .is_none(),
        "a slot missed by more than the grace period fired"
    );
    s.enabled = false;
    assert!(due_slot(&s, now).is_none(), "a disabled schedule fired");
    // a zone with DST: 08:00 London on a summer day is 07:00 UTC
    let l = TaskSchedule {
        time: "08:00".into(),
        tz: "Europe/London".into(),
        enabled: true,
        ..Default::default()
    };
    let t = GoTime::parse("2026-07-01T07:05:00Z").unwrap_or_default();
    assert_eq!(due_slot(&l, t), Some(ms_of("2026-07-01T07:00:00Z")));
    let n = next_slot(&l, t).unwrap_or_else(|e| panic!("{e:#}"));
    assert_eq!(n, ms_of("2026-07-02T07:00:00Z"));
}

// ---- the lifecycle, with the session flows faked ------------------------------------------------------

#[derive(Default)]
struct FakeLine {
    calls: Vec<String>,
    n: u32,
    fail: Option<&'static str>,
    sensitive: bool,
    /// the last resume's machine env
    env: BTreeMap<String, String>,
}

static FAKE: Mutex<Option<FakeLine>> = Mutex::new(None);

fn fake<R>(f: impl FnOnce(&mut FakeLine) -> R) -> R {
    let mut g = FAKE.lock().unwrap_or_else(|e| e.into_inner());
    f(g.get_or_insert_with(FakeLine::default))
}

/// the phone approved and the machine is up (started, a new machine id)
fn approve(r: &Router, id: &str) {
    let (m, sensitive) = fake(|f| {
        f.n += 1;
        (format!("m{}", f.n), f.sensitive)
    });
    let cert = jarvis_go::marshal(&json!({"line": "L", "sensitive": sensitive}));
    r.st.do_(|d| {
        if let Some(s) = d.sessions.get_mut(id) {
            s.state = "started".into();
            s.machine_id = m.clone();
            s.cert = Some(crate::core::Doc {
                payload: cert.clone(),
                sig: String::new(),
            });
            s.image = "img@1".into();
        }
        d.machines.insert(m.clone(), id.into());
    });
}

fn fake_create(r: &Arc<Router>, i: NewSession) -> anyhow::Result<String> {
    let id = format!("s{}", crate::util::rand_id());
    r.st.do_(|d| {
        d.sessions.insert(
            id.clone(),
            crate::state::Session {
                id: id.clone(),
                state: "approval".into(),
                harness: i.harness.clone(),
                stores: Some(i.stores.clone()),
                size: i.size.clone(),
                label: i.label.clone(),
                request_id: i.request_id.clone(),
                ..Default::default()
            },
        );
    });
    fake(|f| {
        f.calls
            .push(format!("create:{}:{}", i.harness, i.stores.join(",")))
    });
    Ok(id)
}

fn fake_resume(r: &Arc<Router>, id: &str, _up: bool) -> anyhow::Result<()> {
    match fake(|f| f.fail) {
        Some("busy") => return Err(Busy("busy".into()).into()),
        Some(e) => return Err(anyhow::anyhow!("{e}")),
        None => {}
    }
    fake(|f| f.calls.push("resume".into()));
    let s =
        r.st.read(|d| d.sessions.get(id).cloned().unwrap_or_default());
    let env = r.machine_env(&s);
    fake(|f| f.env = env);
    approve(r, id);
    Ok(())
}

fn fake_pause(r: &Arc<Router>, id: &str) -> anyhow::Result<()> {
    fake(|f| f.calls.push("pause".into()));
    r.st.do_(|d| {
        if let Some(s) = d.sessions.get_mut(id) {
            s.state = "paused".into();
            s.machine_id = String::new();
        }
    });
    Ok(())
}

fn fake_destroy(r: &Arc<Router>, id: &str) -> anyhow::Result<()> {
    fake(|f| f.calls.push("destroy".into()));
    r.st.do_(|d| {
        d.sessions.remove(id);
    });
    Ok(())
}

fn fake_reject(r: &Arc<Router>, a: &str) -> anyhow::Result<()> {
    fake(|f| f.calls.push("reject".into()));
    r.st.do_(|d| {
        if let Some(ap) = d.approvals.remove(a) {
            d.sessions.remove(&ap.session);
        }
    });
    Ok(())
}

/// a router with the template `job` in its tasks folder and the flows faked; holds the serial lock (the seams are
/// global) and puts them back when dropped
struct TaskRig {
    r: TestRouter,
    _dir: tempfile::TempDir,
    saved: (TaskOps, String),
    _s: std::sync::MutexGuard<'static, ()>,
}

impl Drop for TaskRig {
    fn drop(&mut self) {
        *TASK_OPS.write().unwrap_or_else(|e| e.into_inner()) = self.saved.0;
        *TASKS_DIR.write().unwrap_or_else(|e| e.into_inner()) = self.saved.1.clone();
        TASK_KICK.store(true, Ordering::SeqCst);
        *FAKE.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }
}

fn task_rig(sensitive: bool) -> TaskRig {
    let s = serial();
    let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
    let job = dir.path().join("job");
    std::fs::create_dir_all(&job).unwrap_or_else(|e| panic!("{e}"));
    std::fs::write(
        job.join("task.json"),
        r#"{"title":"Job","stores":["base"],"timeoutSeconds":60,"fields":[
        {"name":"msg","required":true},{"name":"key","type":"select","optionsFrom":"stores"}]}"#,
    )
    .unwrap_or_else(|e| panic!("{e}"));
    std::fs::write(job.join("run.sh"), "echo hi\n").unwrap_or_else(|e| panic!("{e}"));
    let saved_dir = std::mem::replace(
        &mut *TASKS_DIR.write().unwrap_or_else(|e| e.into_inner()),
        dir.path().display().to_string(),
    );
    let saved_ops = std::mem::replace(
        &mut *TASK_OPS.write().unwrap_or_else(|e| e.into_inner()),
        TaskOps {
            create: fake_create,
            resume: fake_resume,
            pause: fake_pause,
            destroy: fake_destroy,
            reject: fake_reject,
        },
    );
    TASK_KICK.store(false, Ordering::SeqCst);
    *FAKE.lock().unwrap_or_else(|e| e.into_inner()) = Some(FakeLine {
        sensitive,
        ..Default::default()
    });
    TaskRig {
        r: new_test_router(),
        _dir: dir,
        saved: (saved_ops, saved_dir),
        _s: s,
    }
}

fn got() -> String {
    fake(|f| f.calls.join(" "))
}

fn env_of() -> BTreeMap<String, String> {
    fake(|f| f.env.clone())
}

fn instance(r: &Router, id: &str) -> TaskInstance {
    r.st.do_(|d| tasks_of(d).instances.get(id).cloned().unwrap_or_default())
}

fn run_of(r: &Router, id: &str, run: &str) -> TaskRun {
    instance(r, id)
        .runs
        .into_iter()
        .find(|x| x.id == run)
        .unwrap_or_default()
}

fn session_of(r: &Router, id: &str) -> crate::state::Session {
    r.st.read(|d| d.sessions.get(id).cloned().unwrap_or_default())
}

fn make_ready_task(r: &Arc<Router>) -> (String, String) {
    let v = r
        .create_task(InstanceIn {
            template: "job".into(),
            name: "T".into(),
            params: Some(map(json!({"msg": "m"}))),
            ..Default::default()
        })
        .unwrap_or_else(|e| panic!("{e:#}"));
    let id = v["id"].as_str().unwrap_or_default().to_string();
    let sid = instance(r, &id).session;
    approve(r, &sid);
    r.task_result(&session_of(r, &sid).machine_id, TaskResult::default())
        .unwrap_or_else(|e| panic!("{e:#}"));
    wait_for("ready", || session_of(r, &sid).state == "paused");
    (id, sid)
}

fn later(secs: u64) -> GoTime {
    GoTime::now().add_std(Duration::from_secs(secs))
}

#[test]
fn task_lifecycle() {
    let tr = task_rig(true); // a sensitive line: no grant is ever needed
    let r = tr.r.r.clone();
    let dms = capture_dm(&r);
    let (code, out) = app_do(
        &r,
        "POST",
        "/api/tasks/instances",
        r#"{"template":"job","name":"Nightly","params":{"msg":"hello world","key":"aes"}}"#,
        &[],
    );
    assert!(code == 200 && out["state"] == "approval", "{code} {out}");
    let id = out["id"].as_str().unwrap_or_default().to_string();
    assert_eq!(got(), "create:task:job:aes,base");
    let sid = instance(&r, &id).session;
    // a run asked for while the phone hasn't approved waits, queued, for the approved line (dropped here again)
    let (code, out) = app_do(
        &r,
        "POST",
        &format!("/api/tasks/instances/{id}/run"),
        "{}",
        &[],
    );
    assert!(
        code == 200
            && instance(&r, &id)
                .runs
                .first()
                .is_some_and(|x| x.phase == "queued"),
        "a run before the approval: {code} {out}"
    );
    r.stop_run(out["name"].as_str().unwrap_or_default())
        .unwrap_or_else(|e| panic!("{e:#}"));
    // the phone approves: the first machine boots with no run, reports ready, and is paused
    approve(&r, &sid);
    let m1 = session_of(&r, &sid).machine_id;
    r.task_result(&m1, TaskResult::default())
        .unwrap_or_else(|e| panic!("{e:#}"));
    wait_for("paused after the ready boot", || {
        session_of(&r, &sid).state == "paused"
    });
    assert!(instance(&r, &id).ready_at.is_some(), "not marked ready");
    // run now: queued, then the tick resumes the line with the run in its env
    let (code, out) = app_do(
        &r,
        "POST",
        &format!("/api/tasks/instances/{id}/run"),
        "{}",
        &[],
    );
    assert_eq!(code, 200, "{out}");
    let run_id = out["name"].as_str().unwrap_or_default().to_string();
    r.tasks_tick(GoTime::now());
    let env = env_of();
    assert!(
        got().contains("resume")
            && env.get("JARVIS2_TASK_RUN") == Some(&run_id)
            && env.get("PARAM_MSG").map(String::as_str) == Some("hello world")
            && env.get("TASK_TRIGGER").map(String::as_str) == Some("manual")
            && env
                .get("TASK_PARAMS")
                .is_some_and(|p| p.contains(r#""key":"aes""#))
            && env.get("SESSION_PROMPT").is_none_or(String::is_empty),
        "{} {env:?}",
        got()
    );
    r.tasks_tick(GoTime::now());
    let x = run_of(&r, &id, &run_id);
    assert!(x.phase == "running" && x.started_at.is_some(), "{x:?}");
    // another machine can't report for it
    assert!(
        r.task_result(
            "m-other",
            TaskResult {
                run: run_id.clone(),
                ..Default::default()
            }
        )
        .is_err(),
        "a stranger reported"
    );
    let m2 = session_of(&r, &sid).machine_id;
    r.task_result(
        &m2,
        TaskResult {
            run: run_id.clone(),
            exit_code: 0,
            log: "line 1\nline 2\n".into(),
            output: "result".into(),
            ..Default::default()
        },
    )
    .unwrap_or_else(|e| panic!("{e:#}"));
    wait_for("paused after the run", || {
        session_of(&r, &sid).state == "paused"
    });
    let x = run_of(&r, &id, &run_id);
    assert!(
        x.phase == "succeeded"
            && x.exit_code == Some(0)
            && x.tail == "line 1\nline 2"
            && x.machine == m2
            && x.image == "img@1",
        "{x:?}"
    );
    let (code, out) = app_do(&r, "GET", &format!("/api/tasks/runs/{run_id}"), "", &[]);
    assert!(
        code == 200 && out["log"] == "line 1\nline 2\n" && out["output"] == "result",
        "{code} {out}"
    );
    assert!(
        dms.lock().unwrap_or_else(|e| e.into_inner()).is_empty(),
        "a manual success DMed"
    );
    // overview
    let (code, out) = app_do(&r, "GET", "/api/tasks", "", &[]);
    assert!(
        code == 200
            && out["templates"].as_array().is_some_and(|a| a.len() == 1)
            && out["instances"].as_array().is_some_and(|a| a.len() == 1),
        "{code} {out}"
    );
    let iv = &out["instances"][0];
    assert!(
        iv["state"] == "ready" && iv["lastRun"]["phase"] == "succeeded",
        "{iv}"
    );
    let (code, out) = app_do(
        &r,
        "GET",
        &format!("/api/tasks/instances/{id}/runs"),
        "",
        &[],
    );
    // the run, and the one stopped before the approval
    assert!(
        code == 200 && out["runs"].as_array().is_some_and(|a| a.len() == 2),
        "{code} {out}"
    );
}

#[test]
fn scheduled_run_fails_and_dms() {
    let tr = task_rig(false);
    let r = tr.r.r.clone();
    let dms = capture_dm(&r);
    let (id, sid) = make_ready_task(&r);
    let now = GoTime::now().utc();
    let hhmm = GoTime::from_unix(now.unix() - 60).rfc3339()[11..16].to_string();
    let (code, out) = app_do(
        &r,
        "POST",
        "/api/tasks/schedules",
        &format!(r#"{{"instance":"{id}","time":"{hhmm}","tz":"UTC"}}"#),
        &[],
    );
    assert!(code == 200 && !out["nextAt"].is_null(), "{code} {out}");
    // a new schedule never fires a slot already past (since = now): make it older
    let hour_ago = i64::try_from(now.unix_nanos() / 1_000_000).unwrap_or(0) - 3_600_000;
    r.st.do_(|d| {
        for s in tasks_of(d).schedules.values_mut() {
            s.since = hour_ago;
        }
    });
    r.tasks_tick(now); // fires: a queued run
    r.tasks_tick(now); // starts it
    r.tasks_tick(now); // and it's running
    let i = instance(&r, &id);
    assert!(
        i.runs.len() == 1
            && i.runs[0].trigger == "schedule"
            && i.runs[0].phase == "running"
            && env_of().get("TASK_TRIGGER").map(String::as_str) == Some("schedule"),
        "{:?}",
        i.runs
    );
    r.tasks_tick(now.add_std(Duration::from_secs(60))); // the same slot doesn't fire again
    assert_eq!(instance(&r, &id).runs.len(), 1, "runs");
    r.task_result(
        &session_of(&r, &sid).machine_id,
        TaskResult {
            run: i.runs[0].id.clone(),
            exit_code: 3,
            log: "boom\n".into(),
            ..Default::default()
        },
    )
    .unwrap_or_else(|e| panic!("{e:#}"));
    let x = instance(&r, &id).runs[0].clone();
    assert!(x.phase == "failed" && x.reason == "exit code 3", "{x:?}");
    let d = dms.lock().unwrap_or_else(|e| e.into_inner()).clone();
    assert!(
        d.len() == 1
            && d[0].contains(&format!(
                "Scheduled task “T” (daily {hhmm} UTC) failed — exit code 3"
            ))
            && d[0].contains("boom"),
        "{d:?}"
    );
    wait_for("paused", || session_of(&r, &sid).state == "paused");
}

#[test]
fn timeout_lost_and_resume_failure() {
    let tr = task_rig(false);
    let r = tr.r.r.clone();
    let dms = capture_dm(&r);
    let (id, sid) = make_ready_task(&r);
    // no result long past the timeout: timed out, and the line is paused
    let run = r
        .start_run(&id, "schedule", "", None, false)
        .unwrap_or_else(|e| panic!("{e:#}"));
    r.tasks_tick(GoTime::now());
    r.tasks_tick(GoTime::now());
    r.tasks_tick(later(3600));
    assert_eq!(run_of(&r, &id, &run.id).phase, "timedout");
    r.tasks_tick(later(3600));
    wait_for("paused", || session_of(&r, &sid).state == "paused");
    // the session paused under a run that never reported (budget cap): lost
    let run = r
        .start_run(&id, "manual", "", None, false)
        .unwrap_or_else(|e| panic!("{e:#}"));
    r.tasks_tick(GoTime::now());
    r.tasks_tick(GoTime::now());
    r.st.do_(|d| {
        if let Some(s) = d.sessions.get_mut(&sid) {
            s.state = "paused".into();
            s.machine_id = String::new();
        }
    });
    r.tasks_tick(GoTime::now());
    assert_eq!(run_of(&r, &id, &run.id).phase, "lost");
    // a resume the core refuses: failed; a busy line: back in the queue
    fake(|f| f.fail = Some("store locked"));
    let run = r
        .start_run(&id, "manual", "", None, false)
        .unwrap_or_else(|e| panic!("{e:#}"));
    r.tasks_tick(GoTime::now());
    let x = run_of(&r, &id, &run.id);
    assert!(
        x.phase == "failed" && x.reason.contains("store locked"),
        "{x:?}"
    );
    fake(|f| f.fail = Some("busy"));
    let run = r
        .start_run(&id, "manual", "", None, false)
        .unwrap_or_else(|e| panic!("{e:#}"));
    r.tasks_tick(GoTime::now());
    let x = run_of(&r, &id, &run.id);
    assert!(
        x.phase == "queued" && instance(&r, &id).active.is_empty(),
        "{x:?}"
    );
    fake(|f| f.fail = None);
    r.tasks_tick(GoTime::now());
    assert_eq!(
        instance(&r, &id).active,
        run.id,
        "the requeued run didn't start"
    );
    let d = dms.lock().unwrap_or_else(|e| e.into_inner()).clone();
    assert!(d.len() == 1 && d[0].contains("timed out"), "{d:?}");
}

#[test]
fn stop_and_queue_limit() {
    let tr = task_rig(false);
    let r = tr.r.r.clone();
    let (id, sid) = make_ready_task(&r);
    let a = r
        .start_run(&id, "manual", "", None, false)
        .unwrap_or_else(|e| panic!("{e:#}"));
    for _ in 0..TASK_MAX_QUEUED - 1 {
        r.start_run(&id, "manual", "", None, false)
            .unwrap_or_else(|e| panic!("{e:#}"));
    }
    let (code, _) = app_do(
        &r,
        "POST",
        &format!("/api/tasks/instances/{id}/run"),
        "{}",
        &[],
    );
    assert_eq!(code, 409, "queue limit");
    r.tasks_tick(GoTime::now()); // a starts
    assert_eq!(instance(&r, &id).active, a.id, "not started");
    let (code, _) = app_do(
        &r,
        "POST",
        &format!("/api/tasks/runs/{}/stop", a.id),
        "",
        &[],
    );
    assert_eq!(code, 200);
    let x = run_of(&r, &id, &a.id);
    assert!(
        x.phase == "stopped" && instance(&r, &id).active.is_empty(),
        "{x:?}"
    );
    // the machine's late report for the stopped run doesn't revive it; the line is paused
    let _ = r.task_result(
        &session_of(&r, &sid).machine_id,
        TaskResult {
            run: a.id.clone(),
            ..Default::default()
        },
    );
    wait_for("paused", || session_of(&r, &sid).state == "paused");
    assert_eq!(run_of(&r, &id, &a.id).phase, "stopped");
    let (code, _) = app_do(
        &r,
        "POST",
        &format!("/api/tasks/runs/{}/stop", a.id),
        "",
        &[],
    );
    assert_eq!(code, 200, "a second stop refused"); // already over: done
}

/// A change of picked stores files the new line for the phone itself; the instance (name, schedules, runs) stays and
/// the old line goes.
#[test]
fn edit_of_stores_files_a_new_line() {
    let tr = task_rig(false);
    let r = tr.r.r.clone();
    let (id, sid) = make_ready_task(&r);
    r.save_schedule("", &map(json!({"instance": id, "time": "07:00"})))
        .unwrap_or_else(|e| panic!("{e:#}"));
    let (code, out) = app_do(
        &r,
        "PUT",
        &format!("/api/tasks/instances/{id}"),
        r#"{"params":{"msg":"new","key":"aes"}}"#,
        &[],
    );
    let i = instance(&r, &id);
    assert!(
        code == 200
            && i.session != sid
            && i.stores.join(",") == "aes,base"
            && out["state"] == "approval",
        "{code} {out} {i:?}"
    );
    assert!(
        r.st.do_(|d| tasks_of(d).doomed.contains(&sid)),
        "the old line wasn't let go"
    );
    let n = r.st.do_(|d| {
        tasks_of(d)
            .schedules
            .values()
            .filter(|x| x.instance == id)
            .count()
    });
    assert_eq!(n, 1, "schedules");
}

/// A run asked for on a line that is gone files a new line for the phone and waits for it, queued.
#[test]
fn a_run_on_a_gone_line_files_a_new_one() {
    let tr = task_rig(false);
    let r = tr.r.r.clone();
    let (id, sid) = make_ready_task(&r);
    r.st.do_(|d| {
        d.sessions.remove(&sid);
    });
    let run = r
        .start_run(&id, "manual", "", None, false)
        .unwrap_or_else(|e| panic!("{e:#}"));
    let i = instance(&r, &id);
    assert!(
        run.phase == "queued"
            && i.session != sid
            && !i.session.is_empty()
            && session_of(&r, &i.session).state == "approval",
        "{run:?} {i:?}"
    );
}

#[test]
fn edit_keeps_stores() {
    let tr = task_rig(false);
    let r = tr.r.r.clone();
    let (id, sid) = make_ready_task(&r);
    let (code, out) = app_do(
        &r,
        "PUT",
        &format!("/api/tasks/instances/{id}"),
        r#"{"name":"Renamed","params":{"msg":"new"},"size":"large"}"#,
        &[],
    );
    assert!(
        code == 200 && out["name"] == "Renamed" && out["params"]["msg"] == "new",
        "{code} {out}"
    );
    assert_eq!(
        session_of(&r, &sid).size,
        "large",
        "size not passed to the line"
    );
    let (code, _) = app_do(
        &r,
        "POST",
        "/api/tasks/instances",
        r#"{"template":"job","name":"x","params":{"msg":"m"},"hide":["msg"]}"#,
        &[],
    );
    assert_eq!(code, 400, "hidden values accepted");
    let (code, _) = app_do(
        &r,
        "POST",
        "/api/tasks/instances",
        r#"{"template":"nope","name":"x"}"#,
        &[],
    );
    assert_eq!(code, 400, "unknown template accepted");
}

#[test]
fn delete_task() {
    let tr = task_rig(false);
    let r = tr.r.r.clone();
    // waiting for approval: the approval is dropped
    let v = r
        .create_task(InstanceIn {
            template: "job".into(),
            name: "A".into(),
            params: Some(map(json!({"msg": "m"}))),
            ..Default::default()
        })
        .unwrap_or_else(|e| panic!("{e:#}"));
    let vid = v["id"].as_str().unwrap_or_default().to_string();
    let pend = instance(&r, &vid).session;
    r.st.do_(|d| {
        d.approvals.insert(
            "ap1".into(),
            crate::state::Approval {
                id: "ap1".into(),
                kind: "new-session".into(),
                session: pend.clone(),
                ..Default::default()
            },
        );
    });
    // a ready one with a schedule: its line is destroyed by the tick
    let (id, sid) = make_ready_task(&r);
    r.save_schedule("", &map(json!({"instance": id, "time": "07:00"})))
        .unwrap_or_else(|e| panic!("{e:#}"));
    for x in [&vid, &id] {
        let (code, _) = app_do(&r, "DELETE", &format!("/api/tasks/instances/{x}"), "", &[]);
        assert_eq!(code, 200);
    }
    r.tasks_tick(GoTime::now());
    assert!(
        got().contains("reject") && got().contains("destroy"),
        "{}",
        got()
    );
    r.st.do_(|d| {
        let ts = tasks_of(d).clone();
        assert!(
            ts.instances.is_empty() && ts.schedules.is_empty(),
            "{:?}",
            ts.instances.keys().collect::<Vec<_>>()
        );
        assert!(!d.sessions.contains_key(&sid) && !d.sessions.contains_key(&pend));
    });
    r.tasks_tick(GoTime::now());
    assert!(
        r.st.do_(|d| tasks_of(d).doomed.is_empty()),
        "doomed list not emptied"
    );
    let (code, _) = app_do(&r, "DELETE", &format!("/api/tasks/instances/{id}"), "", &[]);
    assert_eq!(code, 404);
}

#[test]
fn gone_line_and_reapprove() {
    let tr = task_rig(false);
    let r = tr.r.r.clone();
    let (id, sid) = make_ready_task(&r);
    let run = r
        .start_run(&id, "manual", "", None, false)
        .unwrap_or_else(|e| panic!("{e:#}"));
    r.st.do_(|d| {
        d.sessions.remove(&sid); // destroyed from the Sessions tab
    });
    r.tasks_tick(GoTime::now());
    let i = instance(&r, &id);
    assert!(
        i.session.is_empty() && i.runs.iter().any(|x| x.id == run.id && x.phase == "failed"),
        "{i:?}"
    );
    let (code, out) = app_do(
        &r,
        "POST",
        &format!("/api/tasks/instances/{id}/approve"),
        "",
        &[],
    );
    assert!(
        code == 200 && out["state"] == "approval" && out["session"] != json!(sid),
        "{code} {out}"
    );
    let (code, _) = app_do(
        &r,
        "POST",
        &format!("/api/tasks/instances/{id}/approve"),
        "",
        &[],
    );
    assert_eq!(code, 409, "re-approved a line waiting for the phone");
}

#[test]
fn task_lines_skip_autopilot() {
    let now = GoTime::now();
    let mut d = crate::state::Persisted::default();
    d.sessions.insert(
        "sT".into(),
        crate::state::Session {
            id: "sT".into(),
            machine_id: "m1".into(),
            state: "started".into(),
            harness: "task:job".into(),
            live: Some(Liveness::default()),
            ..Default::default()
        },
    );
    // no live claude in a task machine: no "dead" DM, no auto-pause
    let mut acts = plan_tick(
        &mut d,
        now,
        &BTreeMap::new(),
        &DEFAULT_PILOT,
        &|_| false,
        &|_, _| false,
    );
    acts.extend(plan_tick(
        &mut d,
        now.add_std(Duration::from_secs(3600)),
        &BTreeMap::new(),
        &DEFAULT_PILOT,
        &|_| false,
        &|_, _| false,
    ));
    assert!(
        acts.is_empty(),
        "{:?}",
        acts.iter().map(|a| a.kind.clone()).collect::<Vec<_>>()
    );
}

#[test]
fn task_schedules_api() {
    let tr = task_rig(false);
    let r = tr.r.r.clone();
    let (id, _) = make_ready_task(&r);
    for b in [
        r#"{"instance":"nope","time":"07:00"}"#.to_string(),
        format!(r#"{{"instance":"{id}","time":"7am"}}"#),
        format!(r#"{{"instance":"{id}","time":"07:00","tz":"Mars/Base"}}"#),
        format!(r#"{{"instance":"{id}"}}"#),
    ] {
        let (code, _) = app_do(&r, "POST", "/api/tasks/schedules", &b, &[]);
        assert!(code >= 400, "accepted {b}");
    }
    let (code, out) = app_do(
        &r,
        "POST",
        "/api/tasks/schedules",
        &format!(r#"{{"instance":"{id}","time":"7:05"}}"#),
        &[],
    );
    assert!(
        code == 200
            && out["time"] == "07:05"
            && out["tz"] == "Europe/London"
            && out["enabled"] == true,
        "{code} {out}"
    );
    let sid = out["id"].as_str().unwrap_or_default().to_string();
    let (code, out) = app_do(
        &r,
        "PUT",
        &format!("/api/tasks/schedules/{sid}"),
        r#"{"enabled":false}"#,
        &[],
    );
    assert!(
        code == 200
            && out["enabled"] == false
            && out.get("nextAt").is_none_or(Value::is_null)
            && out["time"] == "07:05",
        "{code} {out}"
    );
    let (code, _) = app_do(
        &r,
        "DELETE",
        &format!("/api/tasks/schedules/{sid}"),
        "",
        &[],
    );
    assert_eq!(code, 200);
    let (code, _) = app_do(
        &r,
        "DELETE",
        &format!("/api/tasks/schedules/{sid}"),
        "",
        &[],
    );
    assert_eq!(code, 404);
}

#[test]
fn runs_pruned() {
    let mut i = TaskInstance::default();
    for k in 0..TASK_KEEP_RUNS + 5 {
        i.runs.push(TaskRun {
            id: format!("old{}", char::from(b'a' + u8::try_from(k).unwrap_or(0))),
            phase: "succeeded".into(),
            ..Default::default()
        });
    }
    i.runs.insert(
        0,
        TaskRun {
            id: "q".into(),
            phase: "queued".into(),
            ..Default::default()
        },
    );
    let gone = prune_runs(&mut i);
    assert_eq!(i.runs.len(), TASK_KEEP_RUNS + 1);
    // the runs dropped are named, so their files go with them (task_result deletes their objects)
    assert_eq!(gone.len(), 5);
    assert!(gone.iter().all(|g| !i.runs.iter().any(|x| &x.id == g)));
}

#[test]
fn locked_store_fails_the_start() {
    let tr = task_rig(true);
    let r = tr.r.r.clone();
    let dms = capture_dm(&r);
    let (id, sid) = make_ready_task(&r);
    let run = r
        .start_run(&id, "schedule", "", None, false)
        .unwrap_or_else(|e| panic!("{e:#}"));
    r.tasks_tick(GoTime::now());
    // the machine is up but can't pull a locked store: it stays initialising
    r.st.do_(|d| {
        if let Some(s) = d.sessions.get_mut(&sid) {
            s.state = "initialising".into();
        }
    });
    r.tasks_tick(GoTime::now());
    let x = run_of(&r, &id, &run.id);
    assert!(
        x.phase == "starting" && x.waiting.contains("locked store"),
        "{x:?}"
    );
    let max = TASK_START_MAX.as_secs();
    r.tasks_tick(later(max + 60));
    let x = run_of(&r, &id, &run.id);
    assert!(
        x.phase == "failed" && x.reason.contains("locked store"),
        "{x:?}"
    );
    r.tasks_tick(later(max + 120)); // and the line is paused
    wait_for("paused", || session_of(&r, &sid).state == "paused");
    let d = dms.lock().unwrap_or_else(|e| e.into_inner()).clone();
    assert!(d.len() == 1 && d[0].contains("locked store"), "{d:?}");
}

#[test]
fn content_fields_go_to_the_line() {
    let tm = parse_template(
        "x",
        br#"{"title":"X","fields":[
        {"name":"store","type":"select","optionsFrom":"content","required":true},
        {"name":"more","type":"multiselect","optionsFrom":"content"},
        {"name":"keystore","type":"select","optionsFrom":"stores"}]}"#,
        &files(&["run.py"]),
    )
    .unwrap_or_else(|e| panic!("{e}"));
    let tm = with_options(&tm);
    assert!(
        check_params(&tm, &map(json!({"store": "../x"}))).is_err(),
        "a bad content store name passed"
    );
    let p = check_params(
        &tm,
        &map(
            json!({"store": "proton-email", "more": ["notes", "proton-email"], "keystore": "keys"}),
        ),
    )
    .unwrap_or_else(|e| panic!("{e:#}"));
    assert_eq!(line_content(&tm, &p), vec!["notes", "proton-email"]);
    assert_eq!(line_stores(&tm, &p), vec!["keys"]);
    assert!(
        line_content(&tm, &map(json!({"store": ""}))).is_empty(),
        "none picked"
    );
}
