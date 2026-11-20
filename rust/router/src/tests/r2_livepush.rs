//! r2 (what comes beside a cert, deploy-key relays) and livepush tests

use crate::autopilot::Liveness;
use crate::livepush::{LIVE_MAX, LiveDocument, LiveSession, live_post, live_state_of};
use crate::registry::{Registry, Workers};
use crate::schedule::{Cron, Wakeup, sched};
use crate::sessionlog::LOG_INPUT;
use crate::testutil::{
    TestKey, TestServer, add_session, call, new_test_router, new_test_router_with,
};
use crate::watches::Watch;
use jarvis_go::GoTime;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

/// R2 (the core as small as it can be): what the core answers beside a cert — its input-log entry and the line's
/// carry rebound — is kept by the router; the core keeps no log for reading and has no /carry/forward.
#[test]
fn the_router_keeps_what_comes_beside_a_cert() {
    let ck = Arc::new(TestKey::new());
    let k = ck.clone();
    let core = TestServer::handler(move |w, req| match req.path.as_str() {
        "/certify" => {
            let d = k.doc(
                &json!({"kind": "succession-cert", "predecessorId": "m1", "machine": {"id": "m2"}}),
            );
            crate::nethttp::write_json(
                w,
                200,
                &json!({"payload": d.payload, "sig": d.sig,
                    "entry": k.doc(&json!({"kind": "input", "seq": 0, "input": "cert", "machine": "m2"})), "carry": "BLOB-M2"}),
            );
        }
        "/attest" => crate::nethttp::write_json(
            w,
            200,
            &k.doc(&json!({"kind": "input", "seq": 1, "input": "wakeup", "machine": "m2"})),
        ),
        // no /input-log, no /carry/forward
        _ => crate::nethttp::write_json(w, 404, &json!({"error": "no such route"})),
    });
    let t = new_test_router_with(|_| {}, Some(&core.url), Default::default());
    t.save_carry("m1", "BLOB-M1");
    let (cert, ans) = t
        .core
        .call_answer("/certify", &json!({"carry": t.read_carry("m1")}))
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert!(
        ans.entry.is_some() && ans.carry == "BLOB-M2" && !cert.payload.contains("BLOB"),
        "{ans:?}"
    );
    t.log_inputs(ans.entry.as_ref());
    t.carry_after("m1", "m2", &cert, &ans);
    assert!(
        t.read_carry("m2") == "BLOB-M2" && t.read_carry("m1").is_empty(),
        "the rebound carry wasn't kept for the successor"
    );
    let a = t.core.call("/attest", &json!({})).ok();
    t.log_inputs(a.as_ref());
    let lines: Vec<String> =
        t.st.read_log("", LOG_INPUT)
            .unwrap_or_default()
            .iter()
            .map(|l| String::from_utf8_lossy(l).into_owned())
            .collect();
    assert!(
        lines.len() == 2
            && lines[0].contains(r#"\"input\":\"cert\""#)
            && lines[1].contains(r#"\"input\":\"wakeup\""#),
        "input log {lines:?}"
    );
}

/// R2: the app's key pair passes through to the core; GitHub's refusal gets the token hint here, not in the core; the
/// list's fingerprint comes from the public key the core answers
#[test]
fn deploy_key_relay_for_the_apps_key_pair() {
    let ck = Arc::new(TestKey::new());
    let got: Arc<Mutex<Value>> = Arc::default();
    let (k, g) = (ck.clone(), got.clone());
    let core = TestServer::handler(move |w, req| {
        *g.lock().unwrap_or_else(|e| e.into_inner()) =
            serde_json::from_slice(&req.read_body(1 << 20)).unwrap_or_default();
        match req.path.as_str() {
            "/deploy-keys/begin" => {
                crate::nethttp::write_json(w, 200, &k.doc(&json!({"kind": "deploy-key-begin"})))
            }
            "/deploy-keys/finish" => crate::nethttp::write_json(
                w,
                502,
                &k.doc(
                    &json!({"kind": "error", "error": "github: HTTP 403: Resource not accessible"}),
                ),
            ),
            _ => {}
        }
    });
    let t = new_test_router_with(|_| {}, Some(&core.url), Default::default());
    let h = t.handler();
    // the app's per-key entries (core/keys.go) reach the core unchanged
    let _ = call(
        &h,
        "POST",
        "/api/repos/key/begin",
        r#"{"action":"add","repo":"DE0CH/x","store":"github-x","title":"jarvis4 github-x","publicKey":"ssh-ed25519 AAAA","keys":[{"store":"github-x","key":"K","data":"d"}]}"#,
    );
    let g = got.lock().unwrap_or_else(|e| e.into_inner()).clone();
    assert!(
        g["store"] == "github-x"
            && g["publicKey"] == "ssh-ed25519 AAAA"
            && g["keys"].as_array().map_or(0, Vec::len) == 1
            && g["keys"][0]["key"] == "K",
        "relayed {g}"
    );
    let (code, out) = call(&h, "POST", "/api/repos/key/finish", "{}");
    assert!(
        code == 502
            && out["error"]
                .as_str()
                .unwrap_or("")
                .contains("Administration: read and write"),
        "{code} {out}"
    );
    let fp = crate::repos::ssh_fingerprint(
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGjzWkhLdE9cqrkvb+MrbIBFxyF6Q9lXVddCSv5+R8gN",
    );
    assert!(
        fp.starts_with("SHA256:") && fp.len() == 50,
        "fingerprint {fp}"
    );
}

#[test]
fn live_states() {
    let wk = |jobs: i64, sub: i64| {
        Some(Workers {
            subagents: sub,
            jobs: [("shell".to_string(), jobs)].into_iter().collect(),
            ..Default::default()
        })
    };
    let spin = "  ✻ Thinking… (12s · esc to interrupt)\n";
    let reg = |status: &str| Registry {
        status: status.into(),
        ..Default::default()
    };
    for (g, fresh, screen, want, jobs) in [
        (None, false, "", "booting", 0),
        (Some(reg("idle")), false, "", "booting", 0), // a report too old to say
        (Some(reg("")), true, "", "booting", 0),      // claude not up yet
        (Some(reg("idle")), true, "", "idle", 0),
        (
            Some(Registry {
                status: "idle".into(),
                bg_tasks: 1,
                ..Default::default()
            }),
            true,
            "",
            "background",
            1,
        ),
        (
            Some(Registry {
                status: "idle".into(),
                workers: wk(0, 2),
                ..Default::default()
            }),
            true,
            "",
            "background",
            0,
        ),
        (Some(reg("waiting")), true, "", "waiting", 0),
        (Some(reg("busy")), true, "", "working", 0),
        (
            Some(Registry {
                status: "busy".into(),
                workers: wk(2, 0),
                ..Default::default()
            }),
            true,
            spin,
            "working",
            2,
        ), // a turn and jobs
        (
            Some(Registry {
                status: "busy".into(),
                workers: wk(2, 0),
                ..Default::default()
            }),
            true,
            "> \n",
            "background",
            2,
        ), // the turn ended
        (
            Some(Registry {
                status: "busy".into(),
                workers: wk(2, 0),
                ..Default::default()
            }),
            true,
            "",
            "working",
            2,
        ), // no pane: as busy says
    ] {
        let (got, j, _) = live_state_of(g.as_ref(), fresh, screen);
        assert!(
            got == want && j == jobs,
            "{g:?} fresh={fresh} screen={screen:?}: {got} {j}, want {want} {jobs}"
        );
    }
}

#[test]
fn live_doc() {
    let t = new_test_router();
    let now = GoTime::now();
    let reg = |id: &str, status: &str, bg: i64, at: i64| {
        t.st.do_(|d| {
            if let Some(s) = d.sessions.get_mut(id) {
                s.live = Some(Liveness {
                    last_report: now,
                    reg: Some(Registry {
                        status: status.into(),
                        bg_tasks: bg,
                        status_updated_at: at,
                        ..Default::default()
                    }),
                    ..Default::default()
                });
            }
        })
    };
    for (i, st) in ["idle", "busy", "waiting", "idle"].iter().enumerate() {
        let id = ((b'a' + i as u8) as char).to_string();
        add_session(&t, &id, "started", &format!("m{id}"), false);
        reg(&id, st, if i == 3 { 1 } else { 0 }, 1000 + i as i64);
    }
    add_session(&t, "e", "paused", "", false); // paused, nothing armed: not listed
    add_session(&t, "f", "paused", "", false); // paused with a cron and a wakeup: scheduled, the sooner one
    add_session(&t, "g", "started", "mg", false);
    reg("g", "idle", 0, 1);
    add_session(&t, "h", "paused", "", false); // a watch only: scheduled, no time, after the timed ones
    t.st.do_(|d| {
        sched(d, "f").crons.insert(
            "c".into(),
            Cron {
                name: "c".into(),
                next_at: 9000,
                ..Default::default()
            },
        );
        sched(d, "f").wakeups.insert(
            "w".into(),
            Wakeup {
                name: "w".into(),
                at: 7000,
                ..Default::default()
            },
        );
        sched(d, "g").wakeups.insert(
            "w".into(),
            Wakeup {
                name: "w".into(),
                at: 8000,
                ..Default::default()
            },
        ); // idle with a wakeup
        sched(d, "h").watches.insert(
            "x".into(),
            Watch {
                name: "x".into(),
                next_at: 1,
                ..Default::default()
            },
        );
    });
    for i in 0..20u8 {
        let id = format!("z{}", (b'a' + i) as char);
        add_session(&t, &id, "started", &format!("m{id}"), false);
        reg(&id, "idle", 0, i as i64);
    }
    for i in 0..10u8 {
        // past LIVE_MAX: the last of the watch-only ones are left out
        let id = format!("y{}", (b'a' + i) as char);
        add_session(&t, &id, "paused", "", false);
        t.st.do_(|d| {
            sched(d, &id).watches.insert(
                "x".into(),
                Watch {
                    name: "x".into(),
                    next_at: 1,
                    ..Default::default()
                },
            );
        });
    }
    let doc: LiveDocument = t.live_doc(now);
    assert!(
        doc.total == 37 && doc.sessions.len() == LIVE_MAX,
        "total {}, {} sessions",
        doc.total,
        doc.sessions.len()
    );
    let order: Vec<String> = doc
        .sessions
        .iter()
        .enumerate()
        .filter(|(i, _)| *i < 4 || (21..26).contains(i))
        .map(|(_, x)| format!("{}:{}", x.state, x.name))
        .collect();
    // waiting and idle first (the newest idle first), then working, background, scheduled (the soonest first, watch-only last)
    let want = [
        "waiting:label c",
        "idle:label a",
        "idle:label zt",
        "idle:label zs",
        "idle:label za",
        "working:label b",
        "background:label d",
        "scheduled:label f",
        "scheduled:label g",
    ];
    assert_eq!(order, want);
    let s = &doc.sessions;
    assert!(
        s[23].jobs == 1
            && s[0].since == 1002
            && s[24].next == 7000
            && s[25].next == 8000
            && s[26].state == "scheduled"
            && s[26].next == 0,
        "{:?}",
        &s[..3]
    );
}

#[test]
fn live_posts() {
    let got: Arc<Mutex<(LiveDocument, String)>> = Arc::default();
    let g = got.clone();
    let srv = TestServer::handler(move |w, req| {
        let secret = req.header("X-Jarvis-Secret");
        let doc = serde_json::from_slice(&req.read_body(1 << 20)).unwrap_or_default();
        *g.lock().unwrap_or_else(|e| e.into_inner()) = (doc, secret.clone());
        if secret != "s3" {
            w.write_header(403);
        }
    });
    let c = reqwest::blocking::Client::new();
    let doc = LiveDocument {
        at: 5,
        total: 1,
        sessions: vec![LiveSession {
            name: "n".into(),
            state: "idle".into(),
            ..Default::default()
        }],
    };
    let res = live_post(&c, &srv.url, "s3", &doc);
    let (d, secret) = got.lock().unwrap_or_else(|e| e.into_inner()).clone();
    assert!(
        res.is_ok() && d.sessions[0].name == "n" && secret == "s3",
        "{res:?} {d:?} {secret}"
    );
    assert!(
        live_post(&c, &srv.url, "wrong", &doc).is_err(),
        "a refused push is an error"
    );
}

/// a fabric session in the time machine is listed frozen, with its until as its next time
#[test]
fn live_doc_frozen() {
    let r = crate::testutil::new_test_router();
    crate::testutil::add_session(&r, "fz", "frozen", "mfz", false);
    r.st.do_(|d| {
        if let Some(s) = d.sessions.get_mut("fz") {
            s.time_machine = Some(crate::timemachine::TimeMachine {
                since: GoTime::now(),
                until: Some(GoTime::from_unix_nanos(5_000_000 * 1_000_000)),
                ..Default::default()
            });
        }
    });
    let doc = r.live_doc(GoTime::now());
    assert!(
        doc.sessions.len() == 1
            && doc.sessions[0].state == "frozen"
            && doc.sessions[0].next == 5_000_000,
        "{:?}",
        doc.sessions
    );
}
