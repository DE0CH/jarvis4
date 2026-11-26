//! bootfailed_test.go, changes_test.go and apptitle_test.go (with its live sync test).

use super::testutil::*;
use crate::apptitle::*;
use crate::boot::{BOOT_REPORT_TRIES, BOOT_REPORT_WAIT_MS, report_boot_failed};
use crate::livesync::LiveSyncer;
use crate::restore::{CHANGES_FILE, CHANGES_SCRIPT, CHANGES_TIMEOUT_MS, write_changes};
use std::collections::BTreeMap;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// a machine that refuses to start tells the router why (2026-11-16): the reason, signed as every machine request; told
/// again when the router didn't take it; an older router (404) is asked once
#[test]
fn a_refused_start_is_told_to_the_router() {
    let e = TestEnv::new();
    let key = e.machine_key();
    BOOT_REPORT_WAIT_MS.store(1, Ordering::SeqCst);
    #[derive(Default)]
    struct S {
        got: Vec<String>,
        calls: u32,
        down: u32,
        status: u16,
    }
    let st = Arc::new(Mutex::new(S::default()));
    let s2 = st.clone();
    let srv = FakeRouter::new(&key.sig.public_key(), move |r| {
        let mut s = s2.lock().unwrap();
        s.calls += 1;
        if r.method != "POST" || r.path != "/m/boot-failed" {
            return ans(401, "");
        }
        if s.down > 0 {
            s.down -= 1;
            return ans(503, "");
        }
        if s.status != 200 {
            return ans(s.status, "");
        }
        let v: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
        s.got.push(v["error"].as_str().unwrap_or("").into());
        ans(200, r#"{"ok":true}"#)
    });
    let c = srv.client();
    let why = "snapshot: write /data/x: no space left on device";
    let report = |failing: u32, answer: u16| {
        {
            let mut s = st.lock().unwrap();
            *s = S {
                down: failing,
                status: answer,
                ..Default::default()
            };
        }
        report_boot_failed(&c, why);
        let s = st.lock().unwrap();
        (s.got.clone(), s.calls)
    };
    assert_eq!(report(0, 200), (vec![why.to_string()], 1));
    // a router that doesn't take it at first is told again
    assert_eq!(report(2, 200), (vec![why.to_string()], 3));
    // it gives up after the tries; an older router is asked once
    assert_eq!(report(10, 200), (vec![], BOOT_REPORT_TRIES));
    assert_eq!(
        report(0, 404).1,
        1,
        "an older router was asked more than once"
    );
}

/// the repo check before a snapshot can't hang it (2026-10-21): a script that never ends is killed at the time limit,
/// and the snapshot goes on with no changes file content
#[test]
fn write_changes_gives_up_at_its_time_limit() {
    let e = TestEnv::new();
    *CHANGES_SCRIPT.write().unwrap() = Some("echo partial; sleep 30 & sleep 30".into());
    CHANGES_TIMEOUT_MS.store(300, Ordering::SeqCst);
    let t0 = std::time::Instant::now();
    write_changes();
    assert!(
        t0.elapsed() < Duration::from_secs(10),
        "took {:?}",
        t0.elapsed()
    );
    assert_eq!(std::fs::read(e.home.join(CHANGES_FILE)).unwrap(), b"");
}

#[test]
fn write_changes_writes_the_repos() {
    let e = TestEnv::new();
    *CHANGES_SCRIPT.write().unwrap() = Some("echo 'jarvis3 13 0'".into());
    write_changes();
    assert_eq!(
        std::fs::read_to_string(e.home.join(CHANGES_FILE)).unwrap(),
        "jarvis3 13 0\n"
    );
}

fn fake_home(e: &TestEnv) -> std::path::PathBuf {
    let h = e.root.join("claude");
    for d in [
        ".claude/sessions",
        ".claude/projects/-home-claude-workspace",
    ] {
        std::fs::create_dir_all(h.join(d)).unwrap();
    }
    *crate::paths::TEST_CLAUDE_HOME.write().unwrap() = Some(h.clone());
    h
}

#[test]
fn app_title() {
    let e = TestEnv::new();
    let home = fake_home(&e);
    let calls: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(vec![]));
    let auth_ok = Arc::new(Mutex::new(true));
    let broken = Arc::new(Mutex::new(false));
    let (c2, a2, b2) = (calls.clone(), auth_ok.clone(), broken.clone());
    let srv = FakeRouter::open("", move |r| {
        c2.lock().unwrap().push(if r.query.is_empty() {
            r.path.clone()
        } else {
            format!("{}?{}", r.path, r.query)
        });
        let ok = r.headers.get("Authorization").and_then(|v| v.to_str().ok())
            == Some("Bearer tok-1")
            && r.headers
                .get("anthropic-beta")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .contains("oauth-2025-04-20");
        let mut a = a2.lock().unwrap();
        *a = *a && ok;
        if *b2.lock().unwrap() {
            return ans(500, "");
        }
        match r.path.as_str() {
            "/v1/code/sessions/cse_abc" => {
                ans(200, r#"{"id":"cse_abc","title":"Renamed by Deyao"}"#)
            }
            "/v1/code/sessions/cse_wrapped" => ans(
                200,
                r#"{"response_shape":{"id":"cse_wrapped","title":"Inside the shape","connection_status":"connected"}}"#,
            ),
            "/v1/code/sessions/cse_old" => ans(404, ""),
            "/v1/code/sessions" => ans(
                200,
                r#"{"data":[{"id":"cse_x","title":"other"},{"id":"cse_old","title":"From the list"}]}"#,
            ),
            _ => ans(500, ""),
        }
    });
    *TEST_CODE_SESSIONS_URL.write().unwrap() = Some(format!("{}/v1/code/sessions", srv.url));
    let a = AppTitler::default();
    assert!(
        a.current().is_empty() && calls.lock().unwrap().is_empty(),
        "no claude yet: no title, no call"
    );
    std::fs::write(
        home.join(".claude/sessions/1.json"),
        r#"{"pid":1,"startedAt":5,"bridgeSessionId":"session_abc"}"#,
    )
    .unwrap();
    std::fs::write(
        home.join(".claude/sessions/2.json"),
        r#"{"pid":2,"startedAt":9}"#,
    )
    .unwrap();
    assert!(
        a.current().is_empty() && calls.lock().unwrap().is_empty(),
        "no credentials: no call"
    );
    std::fs::write(
        home.join(".claude/.credentials.json"),
        r#"{"claudeAiOauth":{"accessToken":"tok-1","refreshToken":"r"}}"#,
    )
    .unwrap();
    a.expire(); // the TTL would otherwise hold the empty answer
    assert_eq!(a.current(), "Renamed by Deyao");
    let n = calls.lock().unwrap().len();
    a.current();
    assert_eq!(calls.lock().unwrap().len(), n, "not cached");
    // a new Remote Control entry (a resume): read again; 404 on the single read → the list
    std::fs::write(
        home.join(".claude/sessions/1.json"),
        r#"{"pid":1,"startedAt":5,"bridgeSessionId":"cse_old"}"#,
    )
    .unwrap();
    assert_eq!(a.current(), "From the list");
    std::fs::write(
        home.join(".claude/sessions/1.json"),
        r#"{"pid":1,"startedAt":5,"bridgeSessionId":"session_wrapped"}"#,
    )
    .unwrap();
    assert_eq!(a.current(), "Inside the shape");
    let (s, _, r) = fetch_code_session("wrapped", "tok-1");
    assert!(r.is_ok() && s.connection_status == "connected", "{s:?}");
    assert!(
        *auth_ok.lock().unwrap(),
        "the request lacked the token or the beta header"
    );
    // a failed read keeps the last title of the same entry
    a.expire();
    *broken.lock().unwrap() = true;
    assert_eq!(a.current(), "Inside the shape", "after a failure");
}

/// the "live-sync" command (rust/router/src/livetail.rs): what changed goes first, then /m/live-synced, which the router's tail
/// waits for; an unchanged transcript isn't sent again, and the round is still told
#[test]
fn live_round_tells_the_router() {
    let e = TestEnv::new();
    let key = e.machine_key();
    let home = fake_home(&e);
    let dir = home.join(".claude/projects/-home-claude-workspace");
    std::fs::write(dir.join("aaaa.jsonl"), "{\"type\":\"user\"}\n").unwrap();
    let got: Arc<Mutex<Vec<String>>> = Arc::default();
    let g2 = got.clone();
    let srv = FakeRouter::new(&key.sig.public_key(), move |r| {
        let name = r
            .headers
            .get("X-Name")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        g2.lock()
            .unwrap()
            .push(format!("{} {name}", r.path).trim().to_string());
        ans(200, r#"{"ok":true}"#)
    });
    let c = srv.client();
    crate::livesync::live_round(&c);
    assert_eq!(
        *got.lock().unwrap(),
        vec!["/m/live-transcript aaaa.jsonl", "/m/live-synced"]
    );
    got.lock().unwrap().clear();
    crate::livesync::live_round(&c);
    assert_eq!(*got.lock().unwrap(), vec!["/m/live-synced"]);
}

#[test]
fn live_sync_once() {
    let e = TestEnv::new();
    let home = fake_home(&e);
    let dir = home.join(".claude/projects/-home-claude-workspace");
    let sent: Arc<Mutex<BTreeMap<String, String>>> = Arc::new(Mutex::new(BTreeMap::new()));
    let s2 = sent.clone();
    let l = LiveSyncer::new(
        Box::new(move |name, body| {
            s2.lock()
                .unwrap()
                .insert(name.into(), String::from_utf8_lossy(body).into());
            Ok(())
        }),
        None,
        BTreeMap::new(),
    );
    std::fs::write(dir.join("aaaa.jsonl"), "{\"type\":\"user\"}\n").unwrap();
    std::fs::write(
        dir.join("relay.jsonl"),
        r#"{"type":"user","message":{"content":"You are a delivery relay for Jarvis"}}"#,
    )
    .unwrap();
    std::fs::write(dir.join("notes.txt"), "x").unwrap();
    assert_eq!(l.once(), 1);
    assert!(sent.lock().unwrap().len() == 1 && sent.lock().unwrap().contains_key("aaaa.jsonl"));
    assert_eq!(l.once(), 0, "an unchanged file was sent again");
    std::fs::write(dir.join("aaaa.jsonl"), "a\nb\n").unwrap();
    let later = std::time::SystemTime::now() + Duration::from_secs(60);
    std::fs::File::options()
        .write(true)
        .open(dir.join("aaaa.jsonl"))
        .unwrap()
        .set_modified(later)
        .unwrap();
    assert_eq!(l.once(), 1);
    assert_eq!(sent.lock().unwrap()["aaaa.jsonl"], "a\nb\n");
    // a failed send is tried again on the next pass
    let fail = Arc::new(Mutex::new(true));
    let (f2, s3) = (fail.clone(), sent.clone());
    l.set_send(Box::new(move |name, body| {
        if *f2.lock().unwrap() {
            anyhow::bail!("deadline exceeded");
        }
        s3.lock()
            .unwrap()
            .insert(name.into(), String::from_utf8_lossy(body).into());
        Ok(())
    }));
    std::fs::write(dir.join("bbbb.jsonl"), "x\n").unwrap();
    assert_eq!(l.once(), 0, "counted a failed send");
    *fail.lock().unwrap() = false;
    assert_eq!(l.once(), 1, "not retried");
    assert_eq!(sent.lock().unwrap()["bbbb.jsonl"], "x\n");
    crate::env::set("JARVIS2_LIVE_SYNC_SECONDS", Some("20")); // the env: ignored
    assert_eq!(
        crate::livesync::live_sync_interval(),
        Duration::from_secs(300),
        "the env set the interval"
    );
    let v = crate::vouch::Vouched {
        ex: crate::vouch::FormatExceptions {
            live_sync_seconds: 20,
            ..Default::default()
        },
        ..Default::default()
    };
    crate::vouch::write_vouched(&v);
    assert_eq!(
        crate::livesync::live_sync_interval(),
        Duration::from_secs(20)
    );
}
