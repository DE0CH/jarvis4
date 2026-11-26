//! memory_test.go
use crate::autopilot::Liveness;
use crate::memory::{
    MEM_CLEAR, MemAlert, MemProc, MemSample, MemState, mem_message, mem_silent_tick, mem_view,
};
use crate::sizes::{core_takes_size, next_size, note_core_sizes, upgrade_target};
use crate::state::{Persisted, Session};
use crate::testutil::*;
use crate::vouch::{Delivery, attested};
use jarvis_go::GoTime;
use serde_json::{Map, Value};
use std::sync::{Arc, Mutex};
use time::Duration as TD;

fn sample(total: i64, avail: i64, oom: Option<i64>, psi: Option<f64>) -> MemSample {
    MemSample {
        total_kb: total,
        avail_kb: avail,
        oom_kills: oom,
        psi_full_60: psi,
        top: None,
    }
}

#[test]
fn mem_watch_episodes() {
    let now = GoTime::now();
    let mut m = MemState {
        machine: "m1".into(),
        ..Default::default()
    };
    let healthy = sample(4 << 20, 2 << 20, Some(0), Some(0.0));
    assert!(
        !m.observe(Some(&healthy), now) && m.alert.is_none(),
        "a healthy machine starts no episode"
    );
    // the kernel killed something
    let mut oom = sample(4 << 20, 400 << 10, Some(2), Some(1.0));
    oom.top = Some(vec![
        MemProc {
            rss_kb: 900 << 10,
            comm: "claude".into(),
        },
        MemProc {
            rss_kb: 300 << 10,
            comm: "chrome".into(),
        },
        MemProc {
            rss_kb: 50 << 10,
            comm: "node".into(),
        },
    ]);
    assert!(
        m.observe(Some(&oom), now.add(TD::seconds(10))),
        "an OOM kill starts an episode"
    );
    let a = m.alert.clone().unwrap_or_default();
    assert!(
        a.reason.contains("killed 2 processes")
            && a.detail == "400 MB free of 4.0 GB (biggest: claude 0.9 GB, chrome 0.3 GB)",
        "{a:?}"
    );
    // more starvation in the same episode: no second DM
    let thrash = sample(4 << 20, 300 << 10, Some(2), Some(25.0));
    let again = m.observe(Some(&thrash), now.add(TD::seconds(20)));
    assert!(
        !again
            && m.alert
                .as_ref()
                .is_some_and(|a| a.reason.contains("thrashing")),
        "{:?}",
        m.alert
    );
    // healthy for less than MEM_CLEAR: still on; then off
    let healthy = sample(4 << 20, 2 << 20, Some(2), Some(0.0));
    m.observe(Some(&healthy), now.add(TD::minutes(1)));
    assert!(m.alert.is_some(), "cleared too early");
    m.observe(Some(&healthy), now.add(TD::minutes(1) + MEM_CLEAR));
    assert!(
        m.alert.is_none(),
        "not cleared after MEM_CLEAR of healthy samples"
    );
    // almost out
    let low = sample(4 << 20, 100 << 10, Some(2), None);
    let started = m.observe(Some(&low), now.add(TD::hours(1)));
    assert!(
        started
            && m.alert
                .as_ref()
                .is_some_and(|a| a.reason == "it is almost out of memory"),
        "{:?}",
        m.alert
    );
}

fn watched(
    id: &str,
    label: &str,
    state: &str,
    machine: &str,
    size: &str,
    last: MemSample,
    at: GoTime,
) -> Session {
    Session {
        id: id.into(),
        label: label.into(),
        state: state.into(),
        machine_id: machine.into(),
        size: size.into(),
        live: Some(Liveness {
            mem: Some(MemState {
                machine: if machine.is_empty() {
                    "m3".into()
                } else {
                    machine.into()
                },
                last: Some(last),
                last_at: at,
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    }
}

#[test]
fn mem_silent_ticks() {
    let now = GoTime::now();
    let short = sample(4 << 20, 300 << 10, None, None);
    let mut d = Persisted::default();
    for s in [
        watched(
            "s1",
            "Busy one",
            "started",
            "m1",
            "small",
            short.clone(),
            now.add(-TD::minutes(2)),
        ),
        watched(
            "s2",
            "",
            "started",
            "m2",
            "",
            sample(4 << 20, 3 << 20, None, None),
            now.add(-TD::minutes(2)),
        ),
        watched("s3", "", "paused", "", "", short, now.add(-TD::hours(1))),
    ] {
        d.sessions.insert(s.id.clone(), s);
    }
    let dms = mem_silent_tick(&mut d, now);
    assert!(
        dms.len() == 1
            && dms[0].contains("“Busy one”")
            && dms[0].contains("stopped answering")
            && dms[0].contains("medium (4 GB)"),
        "{dms:?}"
    );
    assert!(
        mem_silent_tick(&mut d, now.add(TD::minutes(1))).is_empty(),
        "one DM per episode"
    );
    let mem_of = |d: &Persisted, id: &str| {
        d.sessions
            .get(id)
            .and_then(|s| s.live.as_ref())
            .and_then(|l| l.mem.clone())
    };
    assert!(
        mem_of(&d, "s3").is_none(),
        "a paused session's watch is dropped"
    );
    assert!(
        mem_of(&d, "s2").is_some_and(|m| m.alert.is_none()),
        "a silent machine with plenty of memory isn't starving"
    );
}

#[test]
fn memory_report_view_and_upgrade_refusals() {
    let t = new_test_router();
    let r = t.r.clone();
    let dms = capture_dm(&r);
    r.st.do_(|d| {
        for (id, label, state, m, size) in [
            ("s1", "Megathread", "started", "m1", "medium"),
            ("s2", "", "started", "m2", "large"),
            ("s3", "", "paused", "", "small"),
        ] {
            d.sessions.insert(
                id.into(),
                Session {
                    id: id.into(),
                    label: label.into(),
                    state: state.into(),
                    machine_id: m.into(),
                    size: size.into(),
                    ..Default::default()
                },
            );
        }
        d.machines.insert("m1".into(), "s1".into());
        d.machines.insert("m2".into(), "s2".into());
    });
    let m1 = new_test_machine(&r, "m1");
    let h = t.machine_handler();
    let post = |b: &str| m1.do_(&h, "POST", "/m/memory", b).0;
    assert_eq!(
        post(r#"{"totalKb":4000000,"availKb":2000000,"oomKills":0}"#),
        200
    );
    assert_eq!(
        post(
            r#"{"totalKb":4000000,"availKb":100000,"oomKills":1,"top":[{"rssKb":2000000,"comm":"claude"}]}"#
        ),
        200
    );
    assert_eq!(post(r#"{"totalKb":0}"#), 400);
    let d = dms.lock().unwrap_or_else(|e| e.into_inner()).clone();
    assert!(
        d.len() == 1
            && d[0].contains("“Megathread” is running out of memory: the kernel killed 1 process for lack of memory")
            && d[0].contains("large (8 GB)"),
        "{d:?}"
    );
    r.st.do_(|d| {
        let snapshot = d.clone();
        let s1 = d.sessions.get("s1").cloned().unwrap_or_default();
        let v = crate::http::session_view(&s1, &snapshot);
        let a = v.get("memAlert").cloned().unwrap_or_default();
        assert!(
            a["nextSize"] == "large"
                && a["detail"]
                    .as_str()
                    .is_some_and(|x| x.contains("biggest: claude 1.9 GB")),
            "{a}"
        );
        assert_eq!(
            v.get("memory").map(|m| m["availMb"].clone()),
            Some(Value::from(97)),
            "{:?}",
            v.get("memory")
        );
        let s2 = d.sessions.get("s2").cloned().unwrap_or_default();
        assert!(
            !crate::http::session_view(&s2, &snapshot).contains_key("memAlert"),
            "no alert on a session that reported nothing"
        );
    });
    // paused: its next start is on the bigger size
    let (code, _) = app_do(&r, "POST", "/api/sessions/s3/upgrade", "{}", &[]);
    assert!(code == 200 || code == 202, "paused: {code}");
    let size = r.st.read(|d| {
        d.sessions
            .get("s3")
            .map(|s| s.size.clone())
            .unwrap_or_default()
    });
    assert_eq!(size, next_size("small"), "paused: next size");
    assert_eq!(
        app_do(&r, "POST", "/api/sessions/nope/upgrade", "{}", &[]).0,
        404,
        "no session"
    );
}

/// the string literals of the function named sig in src, in order, with {} as the placeholder
fn literals_of(src: &str, sig: &str) -> String {
    let start = src.find(sig).unwrap_or_else(|| panic!("{sig} not found"));
    let body = &src[start..];
    let end = body.find("\n}\n").unwrap_or(body.len());
    let re = regex::Regex::new(r#""((?:[^"\\]|\\.)*)""#).unwrap_or_else(|e| panic!("{e}"));
    re.captures_iter(&body[..end])
        .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
        .filter(|l| l != "upgraded: not a machine size")
        .collect()
}

/// the "upgraded" text is built on both sides; the core attests the router's bytes and the machine refuses others
#[test]
fn upgraded_text_matches_machine() {
    let machine = literals_of(
        include_str!("../../../machine/src/deliver.rs"),
        "pub fn upgraded_text(from: &str, to: &str) -> Result<String> {",
    );
    let router = literals_of(
        include_str!("../memory.rs"),
        "pub fn upgraded_text(from: &str, to: &str) -> String {",
    );
    assert!(
        machine == router && machine.contains("ran out of memory"),
        "router/src/memory.rs upgraded_text and machine/src/deliver.rs upgraded_text differ:\n{router}\n{machine}"
    );
    let d = |from: &str, to: &str| Delivery {
        kind: "upgraded".into(),
        from: from.into(),
        to: to.into(),
        ..Default::default()
    };
    assert!(
        attested(&d("medium", "evil")).is_err(),
        "a size outside the three must be refused"
    );
    let (b, origin) = attested(&d("small", "medium")).unwrap_or_else(|e| panic!("{e:#}"));
    assert!(
        origin == "image-text"
            && String::from_utf8_lossy(&b).contains("from a small (2 GB) to a medium (4 GB)"),
        "{} {origin}",
        String::from_utf8_lossy(&b)
    );
    let (b, _) = attested(&d("large", "16gb")).unwrap_or_else(|e| panic!("{e:#}"));
    assert!(
        String::from_utf8_lossy(&b).contains("from a large (8 GB) to a 16 GB machine"),
        "{}",
        String::from_utf8_lossy(&b)
    );
}

struct Sizes;

impl Drop for Sizes {
    fn drop(&mut self) {
        note_core_sizes(false);
    }
}

/// sizes past large need the new core (it reports sizeLadder in /identity): until it runs, the memory DM, memAlert
/// and Upgrade offer only what the running core starts
#[test]
fn mem_upgrade_offers_only_sizes_the_core_starts() {
    let _g = serial(); // the core's sizes are global
    let _sizes = Sizes;
    let ladder = Arc::new(Mutex::new(false));
    let l2 = ladder.clone();
    let cs = TestServer::handler(move |w, _| {
        let mut id = Map::new();
        id.insert("signingKey".into(), "k".into());
        id.insert("agreementKey".into(), "a".into());
        if *l2.lock().unwrap_or_else(|e| e.into_inner()) {
            id.insert("sizeLadder".into(), 1.into());
        }
        jarvis_nethttp::write_json(w, 200, &id);
    });
    let t = new_test_router();
    let r = t.r.clone();
    r.core.set_url(&cs.url);
    r.core.key().unwrap_or_else(|e| panic!("{e:#}"));
    let a = MemAlert {
        reason: "r".into(),
        ..Default::default()
    };
    assert!(
        core_takes_size("large")
            && !core_takes_size("16gb")
            && upgrade_target("large").is_empty()
            && upgrade_target("medium") == "large",
        "the running core (no sizeLadder) starts only the named sizes"
    );
    let msg = mem_message("x", "large", &a);
    assert!(
        !msg.contains("Upgrade button")
            && !msg.contains("moves it to")
            && msg.contains("large (8 GB), the largest size the running core starts"),
        "{msg:?}"
    );
    let msg = mem_message("x", "medium", &a);
    assert!(msg.contains("One tap moves it to large (8 GB)"), "{msg:?}");
    let s = Session {
        id: "s1".into(),
        state: "started".into(),
        machine_id: "m1".into(),
        size: "large".into(),
        live: Some(Liveness {
            mem: Some(MemState {
                machine: "m1".into(),
                alert: Some(a.clone()),
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    };
    let mut v = Map::new();
    mem_view(&s, &mut v);
    let m = v.get("memAlert").cloned().unwrap_or_default();
    assert!(
        m.get("nextSize").is_none_or(Value::is_null) && m.get("nextGb").is_none_or(Value::is_null),
        "an Upgrade the core can't start: {m}"
    );
    r.st.do_(|d| {
        d.sessions.insert("s1".into(), s.clone());
        d.machines.insert("m1".into(), "s1".into());
    });
    let err = r.upgrade("s1").err();
    assert!(
        err.as_ref()
            .is_some_and(|e| format!("{e:#}").contains("needs the new core")),
        "upgrade past large on the old core: {err:?}"
    );
    // the new core says it starts the ladder: 16 GB is offered
    *ladder.lock().unwrap_or_else(|e| e.into_inner()) = true;
    r.core.key().unwrap_or_else(|e| panic!("{e:#}"));
    assert!(
        upgrade_target("large") == "16gb"
            && mem_message("x", "large", &a).contains("One tap moves it to 16 GB"),
        "{}",
        mem_message("x", "large", &a)
    );
    let mut v = Map::new();
    mem_view(&s, &mut v);
    let m = v.get("memAlert").cloned().unwrap_or_default();
    assert!(m["nextSize"] == "16gb" && m["nextGb"] == 16, "{m}");
}
