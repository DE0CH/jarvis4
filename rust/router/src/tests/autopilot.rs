//! router/autopilot_test.go
use crate::autopilot::{
    DEFAULT_PILOT, Liveness, PilotAction, PilotConfig, ROUTER_STARTED, WaitEpisode, downgrade_text,
    harness_retry_upgrade, harness_stuck_text, live_env, live_view, new_liveness, plan_tick,
    prompt_on_screen, session_name,
};
use crate::flows::NewSession;
use crate::registry::{Refusal, Registry, normalize, parse_registry};
use crate::state::{Persisted, Session};
use crate::terminal::TermSnap;
use crate::testutil::*;
use crate::types::Doc;
use jarvis_go::GoTime;
use serde_json::{Map, json};
use std::collections::BTreeMap;
use time::Duration as TD;

pub const SAMPLE_RAW: &str = r#"{"pid":846,"sessionId":"aaaaaaaa-1111","name":"fix the build","nameSource":"derived","status":"shell","statusUpdatedAt":1791533106447,"startedAt":2,"bridgeSessionId":"session_x"}
{"pid":900,"sessionId":"bbbbbbbb-2222","name":"relay","status":"busy","startedAt":1}
__TITLES__
{"type":"ai-title","aiTitle":"Fix the build","sessionId":"aaaaaaaa-1111"}
__BG__
846 0
0
__ONESHOT__
__AUTH__
aaaaaaaa-1111 uuid-login-1
__CREDS__
1791539182634
__REFUSAL__
{"type":"system","subtype":"model_refusal_fallback","originalModel":"claude-opus-5-5","fallbackModel":"claude-fable-5-1","apiRefusalCategory":"cyber","uuid":"u2","timestamp":"2026-10-09T10:00:02.000Z"}
{"type":"assistant","uuid":"u1","timestamp":"2026-10-09T10:00:01.000Z","message":{"model":"<synthetic>","stop_reason":"refusal","stop_details":{"category":"cyber"},"content":[{"type":"text","text":"API Error: Opus 5.5's safeguards flagged this message"}]}}
"#;

#[test]
fn parse_registry_sample() {
    let g = parse_registry(SAMPLE_RAW).unwrap_or_else(|| panic!("nil"));
    assert!(
        g.session_id == "aaaaaaaa-1111"
            && g.live_name == "fix the build"
            && g.ai_title == "Fix the build",
        "host: {g:?}"
    );
    // "shell" folds into idle + ≥ 1 background job
    assert!(
        g.status == "idle" && g.bg_tasks == 1,
        "status {} bg {}",
        g.status,
        g.bg_tasks
    );
    assert!(
        g.auth_failed == "uuid-login-1"
            && g.creds_expires_at == 1791539182634
            && g.sessions_inside == 2
            && !g.one_shot_done,
        "login/inside: {g:?}"
    );
    let rf = g.refusals();
    assert!(
        rf.len() == 2
            && rf[0].kind == "refusal"
            && rf[0].model == "Opus 5.5"
            && rf[1].to == "claude-fable-5-1",
        "refusals: {rf:?}"
    );
    let all = downgrade_text("x", rf);
    assert!(all.contains("switched it to claude-fable-5-1"), "{all}");
    let one = downgrade_text("x", &rf[..1]);
    assert!(
        one.contains("Opus 5.5's safeguards flagged a message (cyber) and the turn stopped"),
        "{one}"
    );
}

#[test]
fn parse_registry_workers() {
    let g = parse_registry(SAMPLE_RAW).unwrap_or_default();
    assert!(
        g.workers.is_none(),
        "an image without the count: {:?}",
        g.workers
    );
    let raw = format!(
        "{SAMPLE_RAW}__WORKERS__\n{}\n{}\n",
        r#"{"workersOf":"bbbbbbbb-2222","at":5,"subagents":7,"jobs":{}}"#,
        r#"{"workersOf":"aaaaaaaa-1111","at":9,"subagents":2,"jobs":{"shell":3,"monitor":1,"Bad Type!":4,"zero":0},"listed":{"b1":"shell"}}"#
    );
    let g = parse_registry(&raw).unwrap_or_default();
    let w = g.workers.clone().unwrap_or_default();
    assert!(
        w.subagents == 2
            && w.at == 9
            && w.jobs.len() == 2
            && w.jobs.get("shell") == Some(&3)
            && w.jobs.get("monitor") == Some(&1),
        "workers {w:?}"
    );
    assert_eq!(
        g.refusals().len(),
        2,
        "the workers section broke the refusals"
    );
    let s = Session {
        state: "started".into(),
        machine_id: "m".into(),
        live: Some(Liveness {
            reg: Some(g),
            last_report: GoTime::now(),
            ..Default::default()
        }),
        ..Default::default()
    };
    let mut v = Map::new();
    live_view(&s, &mut v);
    assert_eq!(
        v.get("workers").map(|w| w["subagents"].clone()),
        Some(json!(2)),
        "state view {v:?}"
    );
}

#[test]
fn parse_registry_empty_and_one_shot() {
    assert!(
        parse_registry("__TITLES__\n__BG__\n__ONESHOT__\n__AUTH__\n__CREDS__\n__REFUSAL__\n")
            .is_none(),
        "no claude inside should be None"
    );
    let g = parse_registry(
        "__TITLES__\n{\"type\":\"ai-title\",\"aiTitle\":\"Job\",\"sessionId\":\"z\"}\n__BG__\n__ONESHOT__\ndone 2026-10-09\n__AUTH__\n__CREDS__\n__REFUSAL__\n",
    )
    .unwrap_or_default();
    assert!(g.one_shot_done && g.ai_title == "Job", "one-shot: {g:?}");
    assert_eq!(normalize("busy", 2), ("busy".to_string(), 2));
}

// ---- plan_tick ---------------------------------------------------------------------------------------------

fn running(id: &str) -> Persisted {
    let mut d = Persisted::default();
    d.sessions.insert(
        id.into(),
        Session {
            id: id.into(),
            machine_id: "m1".into(),
            state: "started".into(),
            harness: "claude".into(),
            live: Some(Liveness::default()),
            ..Default::default()
        },
    );
    d
}

fn running_with(id: &str, l: Liveness) -> Persisted {
    let mut d = running(id);
    if let Some(s) = d.sessions.get_mut(id) {
        s.live = Some(l);
    }
    d
}

fn lv<'a>(d: &'a mut Persisted, id: &str) -> &'a mut Liveness {
    d.sessions
        .get_mut(id)
        .unwrap_or_else(|| panic!("no session {id}"))
        .live
        .get_or_insert_with(Default::default)
}

fn ses<'a>(d: &'a mut Persisted, id: &str) -> &'a mut Session {
    d.sessions
        .get_mut(id)
        .unwrap_or_else(|| panic!("no session {id}"))
}

fn report(d: &mut Persisted, id: &str, now: GoTime, g: Option<Registry>) {
    let l = lv(d, id);
    l.reg = g;
    l.last_report = now;
}

fn reg(status: &str, at: i64) -> Option<Registry> {
    Some(Registry {
        status: status.into(),
        status_updated_at: at,
        ..Default::default()
    })
}

fn kinds(a: &[PilotAction]) -> String {
    a.iter()
        .map(|x| x.kind.clone())
        .collect::<Vec<_>>()
        .join(",")
}

fn no(_: &str) -> bool {
    false
}

fn yes(_: &str) -> bool {
    true
}

fn noveto(_: &Persisted, _: &str) -> bool {
    false
}

/// plan_tick with no stored pairs, nothing busy and no veto
fn tick(d: &mut Persisted, now: GoTime, c: &PilotConfig) -> Vec<PilotAction> {
    plan_tick(d, now, &BTreeMap::new(), c, &no, &noveto)
}

fn ms(t: GoTime) -> i64 {
    i64::try_from(t.unix_nanos() / 1_000_000).unwrap_or(0)
}

#[test]
fn auto_pause() {
    let (c, now) = (DEFAULT_PILOT, GoTime::now());
    let mut d = running("s1");
    let idle = reg("idle", 5);
    report(&mut d, "s1", now, idle.clone());
    let a = tick(&mut d, now, &c);
    assert_eq!(kinds(&a), "", "first idle tick");
    let now2 = now.add(c.idle_pause);
    report(&mut d, "s1", now2, idle.clone());
    let a = tick(&mut d, now2, &c);
    assert!(kinds(&a).contains("pause"), "after an hour: {}", kinds(&a));
    // a lifecycle action holds it: no pause
    let a = plan_tick(
        &mut d,
        now2,
        &BTreeMap::new(),
        &c,
        &|id: &str| id == "s1",
        &noveto,
    );
    assert!(!kinds(&a).contains("pause"), "paused a busy session");
    // busy resets the clock
    report(&mut d, "s1", now2, reg("busy", 0));
    tick(&mut d, now2, &c);
    assert!(
        lv(&mut d, "s1").idle_since.is_zero(),
        "busy should reset the idle clock"
    );
    // background jobs are work
    report(
        &mut d,
        "s1",
        now2,
        Some(Registry {
            status: "idle".into(),
            bg_tasks: 1,
            ..Default::default()
        }),
    );
    tick(&mut d, now2, &c);
    assert!(
        lv(&mut d, "s1").idle_since.is_zero(),
        "background jobs should reset the idle clock"
    );
    // switched off
    lv(&mut d, "s1").auto_pause_off = true;
    report(&mut d, "s1", now, idle.clone());
    tick(&mut d, now, &c);
    report(&mut d, "s1", now2, idle.clone());
    assert!(
        !kinds(&tick(&mut d, now2, &c)).contains("pause"),
        "auto-pause off but paused"
    );
    // vetoed (a wakeup due soon)
    lv(&mut d, "s1").auto_pause_off = false;
    lv(&mut d, "s1").idle_since = now;
    let a = plan_tick(
        &mut d,
        now2,
        &BTreeMap::new(),
        &c,
        &no,
        &|_: &Persisted, _: &str| true,
    );
    assert!(!kinds(&a).contains("pause"), "vetoed but paused");
    // paused sessions forget their clocks and their report
    lv(&mut d, "s1").idle_since = now;
    ses(&mut d, "s1").state = "paused".into();
    ses(&mut d, "s1").machine_id = String::new();
    tick(&mut d, now2, &c);
    let l = lv(&mut d, "s1");
    assert!(
        l.idle_since.is_zero() && l.reg.is_none(),
        "paused session kept its clock or report"
    );
}

#[test]
fn one_shot_destroys_once() {
    let now = GoTime::now();
    let mut d = running_with(
        "s1",
        Liveness {
            one_shot: true,
            auto_pause_off: true,
            ..Default::default()
        },
    );
    report(
        &mut d,
        "s1",
        now,
        Some(Registry {
            one_shot_done: true,
            ..Default::default()
        }),
    );
    assert_eq!(kinds(&tick(&mut d, now, &DEFAULT_PILOT)), "destroy");
    assert_eq!(kinds(&tick(&mut d, now, &DEFAULT_PILOT)), "", "second tick");
}

#[test]
fn stale_waiting_escape_once() {
    let mut c = DEFAULT_PILOT;
    let now = GoTime::now();
    c.attention = TD::hours(1000); // keep the DMs out of this test
    let mut d = running("s1");
    let w = reg("waiting", 7);
    report(&mut d, "s1", now, w.clone());
    tick(&mut d, now, &c);
    let later = now.add(c.waiting_cancel);
    report(&mut d, "s1", later, w);
    let a = tick(&mut d, later, &c);
    assert!(kinds(&a).contains("escape"), "got {}", kinds(&a));
    assert!(
        !kinds(&tick(&mut d, later, &c)).contains("escape"),
        "escaped twice in one episode"
    );
    // refused before: backing off
    let l = lv(&mut d, "s1");
    if let Some(we) = l.waiting.as_mut() {
        we.cancelled = false;
    } else {
        l.waiting = Some(WaitEpisode::default());
    }
    l.grant_retry = BTreeMap::from([("status".to_string(), later.add(TD::minutes(1)))]);
    assert!(
        !kinds(&tick(&mut d, later, &c)).contains("escape"),
        "escaped while backing off from a refusal"
    );
}

#[test]
fn attention_dm() {
    let (c, now) = (DEFAULT_PILOT, GoTime::now());
    let mut d = running("s1");
    ses(&mut d, "s1").label = "Build".into();
    let idle = reg("idle", 1);
    report(&mut d, "s1", now, idle.clone());
    tick(&mut d, now, &c);
    let t5 = now.add(c.attention);
    report(&mut d, "s1", t5, idle.clone());
    let a = tick(&mut d, t5, &c);
    assert!(
        a.len() == 1 && a[0].kind == "dm" && a[0].text.contains("is idle"),
        "got {a:?}"
    );
    assert!(!kinds(&tick(&mut d, t5, &c)).contains("dm"), "pinged twice");
    // muted idle ping
    lv(&mut d, "s1").settled = None;
    lv(&mut d, "s1").notify_idle_off = true;
    tick(&mut d, now, &c);
    assert!(
        !kinds(&tick(&mut d, t5, &c)).contains("dm"),
        "idle ping is muted"
    );
    // an armed watch: Claude stopped but something will prompt it again, so it isn't idle
    {
        let l = lv(&mut d, "s1");
        l.settled = None;
        l.attention_sent = String::new();
        l.notify_idle_off = false;
    }
    crate::schedule::sched(&mut d, "s1").watches.insert(
        "ci".into(),
        crate::watches::Watch {
            name: "ci".into(),
            ..Default::default()
        },
    );
    tick(&mut d, now, &c);
    assert!(
        !kinds(&tick(&mut d, t5, &c)).contains("dm"),
        "an idle ping with a watch armed"
    );
    crate::schedule::sched(&mut d, "s1").watches.remove("ci");
    // no report for a while = dead, which still pings
    lv(&mut d, "s1").last_report = now.add(-TD::hours(1));
    lv(&mut d, "s1").settled = None;
    tick(&mut d, now, &c);
    let a = tick(&mut d, t5, &c);
    assert!(
        a.len() == 1 && a[0].text.contains("isn't running a live Claude session"),
        "dead: {a:?}"
    );
}

/// the router never writes a login (Deyao, 2026-10-14); a session with a Claude account stuck on "Please run /login"
/// gets "continue" once, after its pair is in step with its account's
#[test]
fn login_continue_only() {
    let (c, now) = (DEFAULT_PILOT, GoTime::now());
    let exp = ms(now.add(TD::hours(1)));
    let stored = BTreeMap::from([
        ("claude-a".to_string(), exp),
        ("claude-b".to_string(), ms(now.add(-TD::minutes(1)))),
    ]);
    let mut d = running_with(
        "s1",
        Liveness {
            auto_pause_off: true,
            ..Default::default()
        },
    );
    ses(&mut d, "s1").claude_account = "claude-a".into();
    let st = |status: &str, creds: i64, auth: &str| {
        Some(Registry {
            status: status.into(),
            creds_expires_at: creds,
            auth_failed: auth.into(),
            ..Default::default()
        })
    };
    let pt = |d: &mut Persisted, at: GoTime| plan_tick(d, at, &stored, &c, &no, &noveto);
    // behind the shared pair: nothing (the machine catches up by itself)
    report(&mut d, "s1", now, st("busy", exp - 1, ""));
    let a = pt(&mut d, now);
    assert!(
        !kinds(&a).contains("login"),
        "a login action for a session behind: {a:?}"
    );
    // stuck while still behind: wait for its pair
    report(&mut d, "s1", now, st("idle", 0, "u1"));
    let a = pt(&mut d, now);
    assert!(
        !kinds(&a).contains("login"),
        "continue before the pair caught up: {a:?}"
    );
    // in step and stuck: "continue", once per error
    report(&mut d, "s1", now, st("idle", exp, "u1"));
    let a = pt(&mut d, now);
    assert!(
        a.len() == 1 && a[0].kind == "login" && a[0].repair == "u1",
        "continue: {a:?}"
    );
    assert!(
        !kinds(&pt(&mut d, now.add(TD::minutes(1)))).contains("login"),
        "continued while the first is under way"
    );
    lv(&mut d, "s1").login_busy_at = GoTime::default();
    assert!(
        !kinds(&pt(&mut d, now.add(TD::hours(1)))).contains("login"),
        "continued the same error twice"
    );
    // its account's pair itself expired: nothing
    report(&mut d, "s1", now, st("idle", exp, "u2"));
    ses(&mut d, "s1").claude_account = "claude-b".into();
    assert!(
        !kinds(&pt(&mut d, now)).contains("login"),
        "acted on an expired account pair"
    );
    // no Claude account: no login at all, nothing to continue
    let mut d2 = running_with(
        "s2",
        Liveness {
            auto_pause_off: true,
            ..Default::default()
        },
    );
    report(&mut d2, "s2", now, st("idle", exp, "u3"));
    let a = pt(&mut d2, now);
    assert!(
        !kinds(&a).contains("login"),
        "a session without a Claude account: {a:?}"
    );
}

#[test]
fn downgrade_once_and_dialog() {
    let mut c = DEFAULT_PILOT;
    let now = GoTime::now();
    c.attention = TD::hours(1000);
    let off = Liveness {
        auto_pause_off: true,
        ..Default::default()
    };
    let mut d = running_with("s1", off.clone());
    let ev = vec![Refusal {
        kind: "refusal".into(),
        at: ms(now),
        uuid: "u1".into(),
        model: "Opus 5.5".into(),
        ..Default::default()
    }];
    report(
        &mut d,
        "s1",
        now,
        Some(Registry {
            status: "busy".into(),
            refusals: Some(ev),
            ..Default::default()
        }),
    );
    let a = tick(&mut d, now, &c);
    assert!(
        a.len() == 1 && a[0].text.contains("safeguards flagged"),
        "got {a:?}"
    );
    assert!(tick(&mut d, now, &c).is_empty(), "reported twice");
    // an old event (before the lookback) isn't reported
    let mut d2 = running_with("s2", off);
    report(
        &mut d2,
        "s2",
        now,
        Some(Registry {
            status: "busy".into(),
            refusals: Some(vec![Refusal {
                kind: "refusal".into(),
                at: ms(ROUTER_STARTED.add(-TD::hours(1))),
                ..Default::default()
            }]),
            ..Default::default()
        }),
    );
    assert!(tick(&mut d2, now, &c).is_empty(), "reported an old refusal");
    // waiting: the pane is checked once per waiting episode
    report(&mut d2, "s2", now, reg("waiting", 9));
    assert_eq!(kinds(&tick(&mut d2, now, &c)), "dialog", "dialog check");
    assert_eq!(kinds(&tick(&mut d2, now, &c)), "", "checked the pane twice");
    assert!(prompt_on_screen(
        "\x1b[1mOpus 5.5's Safeguards flagged\x1b[0m this message"
    ));
}

#[test]
fn toggle_routes_and_view() {
    let t = new_test_router();
    let r = t.r.clone();
    r.st.do_(|d| {
        d.sessions.insert(
            "s1".into(),
            Session {
                id: "s1".into(),
                state: "started".into(),
                machine_id: "m1".into(),
                live: Some(Liveness {
                    idle_since: GoTime::now(),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
    });
    let (c, _) = app_do(
        &r,
        "POST",
        "/api/sessions/s1/auto-pause",
        r#"{"on":false}"#,
        &[],
    );
    assert_eq!(c, 200);
    let (c, _) = app_do(
        &r,
        "POST",
        "/api/sessions/s1/notify-idle",
        r#"{"enabled":false}"#,
        &[],
    );
    assert_eq!(c, 200);
    let (c, _) = app_do(
        &r,
        "POST",
        "/api/sessions/nope/auto-pause",
        r#"{"on":true}"#,
        &[],
    );
    assert_eq!(c, 404);
    r.st.do_(|d| {
        let snapshot = d.clone();
        let Some(s) = d.sessions.get_mut("s1") else {
            panic!("gone")
        };
        let l = s.live.get_or_insert_with(Default::default);
        assert!(
            l.auto_pause_off && l.notify_idle_off && l.idle_since.is_zero(),
            "{l:?}"
        );
        l.auto_pause_off = false;
        l.idle_since = GoTime::now().add(-TD::minutes(10));
        l.reg = Some(Registry {
            status: "idle".into(),
            ai_title: "T".into(),
            ..Default::default()
        });
        l.last_report = GoTime::now();
        let v = crate::http::session_view(s, &snapshot);
        let ms = v
            .get("pauseInMs")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(-1);
        assert!(
            v.get("autoPause") == Some(&json!("on"))
                && v.get("notifyIdle") == Some(&json!("off"))
                && v.get("aiTitle") == Some(&json!("T"))
                && (49 * 60 * 1000..=50 * 60 * 1000).contains(&ms),
            "view: {v:?}"
        );
    });
}

#[test]
fn one_shot_env() {
    let t = new_test_router();
    let s = Session {
        live: Some(new_liveness(&NewSession {
            one_shot: true,
            ..Default::default()
        })),
        ..Default::default()
    };
    let mut e = BTreeMap::new();
    live_env(&t.r, &s, &mut e);
    assert!(
        e.get("SESSION_ONE_SHOT").map(String::as_str) == Some("1")
            && s.live.as_ref().is_some_and(|l| l.auto_pause_off),
        "{e:?} {:?}",
        s.live
    );
    let l = new_liveness(&NewSession {
        auto_pause: Some(false),
        ..Default::default()
    });
    assert!(l.auto_pause_off && !l.one_shot, "{l:?}");
    assert!(
        !new_liveness(&NewSession::default()).auto_pause_off,
        "auto-pause is on by default"
    );
}

#[test]
fn attention_dm_names_the_app_title() {
    let (c, now) = (DEFAULT_PILOT, GoTime::now());
    let mut d = running("s1");
    ses(&mut d, "s1").app_title = "Bilingual Japanese news".into();
    let idle = Some(Registry {
        status: "idle".into(),
        status_updated_at: 1,
        live_name: "workspace-c1".into(),
        name_source: "derived".into(),
        ..Default::default()
    });
    report(&mut d, "s1", now, idle.clone());
    tick(&mut d, now, &c);
    report(&mut d, "s1", now.add(c.attention), idle.clone());
    let a = tick(&mut d, now.add(c.attention), &c);
    assert!(
        a.len() == 1 && a[0].text.contains("“Bilingual Japanese news”"),
        "got {a:?}"
    );
    let n = session_name(
        &Session {
            id: "s2".into(),
            ..Default::default()
        },
        idle.as_ref(),
    );
    assert_eq!(
        n, "workspace-c1",
        "with nothing else the derived name still beats the id"
    );
}

#[test]
fn attention_dm_not_repeated_after_restart() {
    let (c, now) = (DEFAULT_PILOT, GoTime::now());
    let mut d = running("s1");
    let idle = reg("idle", 7);
    report(&mut d, "s1", now, idle.clone());
    tick(&mut d, now, &c);
    report(&mut d, "s1", now.add(c.attention), idle.clone());
    let a = tick(&mut d, now.add(c.attention), &c);
    assert!(kinds(&a).contains("dm"), "no first ping: {a:?}");
    // a router restart: only the persisted fields survive
    let mut d2 = running_with(
        "s1",
        Liveness {
            attention_sent: lv(&mut d, "s1").attention_sent.clone(),
            ..Default::default()
        },
    );
    for at in [now.add(c.attention * 2), now.add(c.attention * 4)] {
        report(&mut d2, "s1", at, idle.clone());
        let a = tick(&mut d2, at, &c);
        assert!(
            !kinds(&a).contains("dm"),
            "same idle episode pinged again after a restart: {a:?}"
        );
    }
    // a new turn that settles again is a new episode
    report(&mut d2, "s1", now.add(c.attention * 5), reg("busy", 8));
    tick(&mut d2, now.add(c.attention * 5), &c);
    let idle2 = reg("idle", 9);
    report(&mut d2, "s1", now.add(c.attention * 6), idle2.clone());
    tick(&mut d2, now.add(c.attention * 6), &c);
    report(&mut d2, "s1", now.add(c.attention * 7), idle2);
    let a = tick(&mut d2, now.add(c.attention * 7), &c);
    assert!(
        kinds(&a).contains("dm"),
        "a new idle episode wasn't pinged: {a:?}"
    );
}

#[test]
fn auto_pause_clock_survives_restart() {
    let (c, now) = (DEFAULT_PILOT, GoTime::now());
    let mut d = running("s1");
    let idle = reg("idle", 3);
    report(&mut d, "s1", now, idle.clone());
    tick(&mut d, now, &c);
    // restarts every few minutes: only the persisted fields survive each one
    let mut at = now;
    while at.before(&now.add(c.idle_pause)) {
        let l = lv(&mut d, "s1").clone();
        d = running_with(
            "s1",
            Liveness {
                idle_since: l.idle_since,
                idle_status_at: l.idle_status_at,
                attention_sent: l.attention_sent,
                ..Default::default()
            },
        );
        report(&mut d, "s1", at, idle.clone());
        assert!(
            !kinds(&tick(&mut d, at, &c)).contains("pause"),
            "paused early"
        );
        at = at.add(TD::minutes(10));
    }
    report(&mut d, "s1", now.add(c.idle_pause), idle);
    assert!(
        kinds(&tick(&mut d, now.add(c.idle_pause), &c)).contains("pause"),
        "an hour idle across restarts didn't pause"
    );
    // a turn the router never saw (busy and idle again between reports) restarts the hour
    let mut d2 = running_with(
        "s1",
        Liveness {
            idle_since: now.add(c.idle_pause * -2),
            idle_status_at: 3,
            ..Default::default()
        },
    );
    report(&mut d2, "s1", now, reg("idle", 4));
    assert!(
        !kinds(&tick(&mut d2, now, &c)).contains("pause"),
        "paused right after an unseen turn"
    );
}

/// a "status" refusal from a waiting episode stops showing once the session is no longer waiting
#[test]
fn status_refusal_clears_after_waiting() {
    let mut c = DEFAULT_PILOT;
    let now = GoTime::now();
    c.attention = TD::hours(1000);
    let mut d = running_with(
        "s1",
        Liveness {
            auto_pause_off: true,
            ..Default::default()
        },
    );
    report(&mut d, "s1", now, reg("waiting", 3));
    tick(&mut d, now, &c);
    {
        let l = lv(&mut d, "s1");
        l.needs_grant = "status".into();
        l.grant_retry = BTreeMap::from([("status".to_string(), now.add(TD::hours(1)))]);
    }
    tick(&mut d, now, &c);
    assert_eq!(
        lv(&mut d, "s1").needs_grant,
        "status",
        "cleared while still waiting"
    );
    report(&mut d, "s1", now, reg("busy", 4));
    tick(&mut d, now, &c);
    let l = lv(&mut d, "s1");
    assert!(
        l.needs_grant.is_empty() && l.may_exec("status", &now),
        "still offered: {:?}",
        l.needs_grant
    );
    // another holder's refusal stays
    l.needs_grant = "archive".into();
    tick(&mut d, now, &c);
    assert_eq!(
        lv(&mut d, "s1").needs_grant,
        "archive",
        "cleared another holder's refusal"
    );
}

/// a booted machine whose Claude never came up (2026-10-20: Claude Code stuck on its "Settings Error" prompt) fails
/// after harness_up with what its screen shows; a host that came up, a busy session or a router-restart without the
/// clock are left alone
#[test]
fn harness_never_came_up() {
    let mut c = DEFAULT_PILOT;
    let now = GoTime::now();
    c.attention = TD::hours(1000);
    let mut d = running("s1");
    ses(&mut d, "s1").booted = "m1".into();
    report(&mut d, "s1", now, None); // the machine reports, no Claude host in the registry
    lv(&mut d, "s1").booted_at = now;
    let stuck_screen = "\x1b[1mSettings Error\x1b[0m\n\n /etc/claude-code/managed-settings.json\n   └ Settings file could not be read: EACCES: permission denied, stat\n\n ❯ 1. Fix with Claude\n   2. Exit and fix manually\n   3. Continue without these settings\n";
    let a = tick(&mut d, now.add(c.harness_up - TD::seconds(1)), &c);
    assert!(
        !kinds(&a).contains("harness-stuck"),
        "failed before harness_up"
    );
    let a = plan_tick(
        &mut d,
        now.add(c.harness_up),
        &BTreeMap::new(),
        &c,
        &yes,
        &noveto,
    );
    assert!(
        !kinds(&a).contains("harness-stuck"),
        "failed a session a lifecycle action holds"
    );
    let a = tick(&mut d, now.add(c.harness_up), &c);
    assert!(
        a.len() == 1 && a[0].kind == "harness-stuck" && a[0].machine == "m1",
        "got {a:?}"
    );
    // the router fails it: state failed with the reason, once
    let t = new_test_router();
    let r = t.r.clone();
    let _dms = capture_dm(&r);
    r.st.do_(|p| {
        p.sessions.insert(
            "s1".into(),
            Session {
                id: "s1".into(),
                state: "started".into(),
                machine_id: "m1".into(),
                booted: "m1".into(),
                harness: "claude".into(),
                live: Some(Liveness::default()),
                ..Default::default()
            },
        );
    });
    r.st.put_screen(
        "s1",
        "m1",
        &TermSnap {
            screen: stuck_screen.into(),
            ..Default::default()
        },
    )
    .unwrap_or_else(|e| panic!("{e:#}"));
    r.run_action(a[0].clone());
    let (st, er) = r.st.read(|p| {
        let s = p.sessions.get("s1").cloned().unwrap_or_default();
        (s.state, s.error)
    });
    assert_eq!(st, "failed");
    for want in [
        "didn't come up within 4 min",
        "Settings Error",
        "EACCES: permission denied",
        "3. Continue without these settings",
        "Resume starts it again",
    ] {
        assert!(er.contains(want), "{er:?} lacks {want:?}");
    }
    // a host that came up: nothing
    let mut d2 = running_with(
        "s2",
        Liveness {
            booted_at: now,
            host_up: "m1".into(),
            ..Default::default()
        },
    );
    ses(&mut d2, "s2").booted = "m1".into();
    report(&mut d2, "s2", now, reg("busy", 0));
    assert!(
        !kinds(&tick(&mut d2, now.add(TD::hours(1)), &c)).contains("harness-stuck"),
        "failed a session whose host came up"
    );
    // another harness, or no boot clock (booted under a router from before the check): nothing
    let mut d3 = running("s3");
    ses(&mut d3, "s3").booted = "m1".into();
    report(&mut d3, "s3", now, None);
    assert!(
        !kinds(&tick(&mut d3, now.add(TD::hours(1)), &c)).contains("harness-stuck"),
        "failed a session with no boot clock"
    );
    lv(&mut d3, "s3").booted_at = now;
    ses(&mut d3, "s3").harness = "opencode".into();
    assert!(
        !kinds(&tick(&mut d3, now.add(TD::hours(1)), &c)).contains("harness-stuck"),
        "failed another harness"
    );
}

fn post_status(r: &TestRouter, m: &TestMachine, raw: &str) {
    let (code, out) = m.do_(
        &r.machine_handler(),
        "POST",
        "/m/status",
        &jarvis_go::marshal(&json!({"raw": raw})),
    );
    assert_eq!(code, 200, "status: {out}");
}

fn live_of(r: &TestRouter, id: &str) -> Liveness {
    r.st.read(|p| {
        p.sessions
            .get(id)
            .and_then(|s| s.live.clone())
            .unwrap_or_default()
    })
}

/// /m/status keeps the harness check's clock: the boot time of the machine, and whether its host came up
#[test]
fn status_sets_harness_clock() {
    let r = new_test_router();
    add_session(&r, "s1", "started", "m1", false);
    let m = new_test_machine(&r, "m1");
    post_status(&r, &m, "");
    let l = live_of(&r, "s1");
    assert!(
        !l.booted_at.is_zero() && l.host_up.is_empty(),
        "after an empty report: {l:?}"
    );
    let first = l.booted_at;
    post_status(&r, &m, SAMPLE_RAW);
    let l = live_of(&r, "s1");
    assert!(
        l.host_up == "m1" && l.booted_at == first,
        "after a host: {l:?}"
    );
}

/// a session the harness check failed resumes on the newest image when its own is older; any other failure, or the
/// newest image itself, resumes as it is
#[test]
fn harness_retry_upgrades() {
    let cert = Doc {
        payload: r#"{"machine":{"id":"m1","image":"ghcr.io/de0ch/jarvis4-session@sha256:aaa"}}"#
            .into(),
        sig: String::new(),
    };
    let newest = "ghcr.io/de0ch/jarvis4-session:sha-1@sha256:bbb";
    let mut s = Session {
        state: "failed".into(),
        cert: Some(cert.clone()),
        stuck_image: "ghcr.io/de0ch/jarvis4-session@sha256:aaa".into(),
        ..Default::default()
    };
    assert!(harness_retry_upgrade(&s, newest), "not upgraded");
    s.state = "paused".into(); // a resume-upgrade nobody approved: still the stuck image
    assert!(
        harness_retry_upgrade(&s, newest),
        "not upgraded after a lapsed approval"
    );
    assert!(
        !harness_retry_upgrade(&s, "ghcr.io/de0ch/jarvis4-session:sha-0@sha256:aaa"),
        "upgraded onto its own image"
    );
    s.stuck_image = String::new();
    assert!(!harness_retry_upgrade(&s, newest), "upgraded with no mark");
    // the router marks it when it fails the session, and a host that comes up clears it
    let r = new_test_router();
    let _dms = capture_dm(&r);
    add_session(&r, "s1", "started", "m1", false);
    r.st.do_(|p| {
        if let Some(s) = p.sessions.get_mut("s1") {
            s.cert = Some(cert.clone());
            s.booted = "m1".into();
        }
    });
    r.run_action(PilotAction {
        kind: "harness-stuck".into(),
        session: "s1".into(),
        machine: "m1".into(),
        text: harness_stuck_text(TD::minutes(1), ""),
        ..Default::default()
    });
    let got =
        r.st.read(|p| p.sessions.get("s1").cloned().unwrap_or_default());
    assert!(
        got.state == "failed" && got.stuck_image == "ghcr.io/de0ch/jarvis4-session@sha256:aaa",
        "{} {}",
        got.state,
        got.stuck_image
    );
    r.st.do_(|p| {
        if let Some(s) = p.sessions.get_mut("s1") {
            s.state = "started".into();
        }
    });
    let m = new_test_machine(&r, "m1");
    post_status(&r, &m, SAMPLE_RAW);
    let got =
        r.st.read(|p| p.sessions.get("s1").cloned().unwrap_or_default());
    assert!(
        got.stuck_image.is_empty(),
        "a host that came up kept the mark"
    );
}

/// a kernel line has no cert of the old core: the image its Claude never came up on is its machine's (Session.image),
/// and its resume goes on the newest image all the same (it resumed on the image that hung, again and again)
#[test]
fn harness_retry_upgrade_on_a_kernel_line() {
    let own = "ghcr.io/de0ch/jarvis4-session:sha-0@sha256:aaa";
    let newest = "ghcr.io/de0ch/jarvis4-session:sha-1@sha256:bbb";
    let r = new_test_router();
    let _dms = capture_dm(&r);
    add_session(&r, "s1", "started", "m1", false);
    r.st.do_(|p| {
        if let Some(s) = p.sessions.get_mut("s1") {
            s.cert = None;
            s.kernel = Some(Default::default());
            s.image = own.into();
            s.booted = "m1".into();
        }
    });
    r.run_action(PilotAction {
        kind: "harness-stuck".into(),
        session: "s1".into(),
        machine: "m1".into(),
        text: harness_stuck_text(TD::minutes(1), ""),
        ..Default::default()
    });
    let mut got =
        r.st.read(|p| p.sessions.get("s1").cloned().unwrap_or_default());
    assert!(
        got.state == "failed" && got.stuck_image == own,
        "{}, stuck on {:?}",
        got.state,
        got.stuck_image
    );
    assert!(harness_retry_upgrade(&got, newest), "not upgraded");
    assert!(
        !harness_retry_upgrade(&got, own),
        "upgraded onto its own image"
    );
    got.kernel = None; // neither a core cert nor a kernel line: nothing to upgrade
    assert!(
        !harness_retry_upgrade(&got, newest),
        "upgraded a session with no line"
    );
}

/// idle after a scheduled turn pauses in idle_pause_scheduled; after Deyao's own prompt it keeps the hour (Deyao, 2026-11-02)
#[test]
fn auto_pause_after_scheduled_turn() {
    let (c, now) = (DEFAULT_PILOT, GoTime::now());
    let human = ms(now.add(-TD::hours(3)));
    let paused = |l: &mut Liveness, g: &Registry, at: GoTime| {
        let mut d = running_with("s1", l.clone());
        report(&mut d, "s1", at, Some(g.clone()));
        let p = kinds(&tick(&mut d, at, &c)).contains("pause");
        *l = lv(&mut d, "s1").clone();
        p
    };
    let sched_l = || Liveness {
        scheduled_at: ms(now.add(-TD::minutes(1))),
        ..Default::default()
    };
    // a cron delivered after his last prompt: 5 min
    let mut l = sched_l();
    let g = Registry {
        status: "idle".into(),
        status_updated_at: 7,
        human_section: true,
        last_human_at: human,
        ..Default::default()
    };
    assert!(
        !paused(&mut l, &g, now)
            && !paused(&mut l, &g, now.add(c.idle_pause_scheduled - TD::seconds(1))),
        "paused before idle_pause_scheduled"
    );
    assert!(
        paused(&mut l, &g, now.add(c.idle_pause_scheduled)),
        "idle after a scheduled turn didn't pause after idle_pause_scheduled"
    );
    // Deyao wrote after the wakeup: the hour
    let mut l = sched_l();
    let g = Registry {
        status: "idle".into(),
        status_updated_at: 8,
        human_section: true,
        last_human_at: ms(now),
        ..Default::default()
    };
    assert!(
        !paused(&mut l, &g, now) && !paused(&mut l, &g, now.add(TD::minutes(30))),
        "paused within the hour after Deyao's prompt"
    );
    assert!(
        paused(&mut l, &g, now.add(c.idle_pause)),
        "no pause after the hour"
    );
    // an image that doesn't report his prompts: the hour
    let mut l = sched_l();
    let g = Registry {
        status: "idle".into(),
        status_updated_at: 9,
        ..Default::default()
    };
    assert!(
        !paused(&mut l, &g, now) && !paused(&mut l, &g, now.add(c.idle_pause_scheduled)),
        "paused early without the __HUMAN__ section"
    );
}

#[test]
fn parse_human() {
    let raw = "{\"pid\":10,\"sessionId\":\"aaaaaaaa-1111\",\"status\":\"idle\",\"bridgeSessionId\":\"b\"}\n__TITLES__\n__BG__\n__ONESHOT__\n__AUTH__\n__CREDS__\n__REFUSAL__\n__ACCOUNT__\n\n__HUMAN__\naaaaaaaa-1111 2026-11-02T09:33:35.702Z\nbbbbbbbb-2222 -\n__WORKERS__\n";
    let g = parse_registry(raw).unwrap_or_default();
    let want = ms(GoTime::parse("2026-11-02T09:33:35.702Z").unwrap_or_default());
    assert!(
        g.human_section && g.last_human_at == want && want > 0,
        "got {g:?}"
    );
    let g =
        parse_registry(&raw.replacen("__HUMAN__\naaaaaaaa-1111 2026-11-02T09:33:35.702Z\n", "", 1))
            .unwrap_or_default();
    assert!(
        !g.human_section && g.last_human_at == 0,
        "an old image: {g:?}"
    );
    // the aviary harness: its transcripts never mark a person's prompt, so the machine reports none for it and the
    // session keeps the hour (a session on it paused minutes after every turn, Deyao 2026-11-17)
    let g = parse_registry(&raw.replacen(
        r#""status":"idle","#,
        r#""status":"idle","harness":"aviary","#,
        1,
    ));
    assert!(
        g.as_ref().is_some_and(|g| !g.human_section),
        "the aviary harness: {g:?}"
    );
}
