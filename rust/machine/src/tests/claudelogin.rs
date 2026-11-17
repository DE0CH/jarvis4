//! claudelogin_test.go (and harnesses_test.go's proxy-login switch): the session's Claude pair kept in step with the
//! router's, the CLI's refresh lock, an account switch under the running claude.

use super::testutil::*;
use crate::claudelogin::*;
use crate::client::Client;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

fn pair(exp: i64) -> String {
    format!(
        r#"{{"claudeAiOauth":{{"accessToken":"a{exp}","refreshToken":"r{exp}","expiresAt":{exp}}}}}"#
    )
}

const ACCT: &str = r#"{"oauthAccount":{"accountUuid":"acct-1","emailAddress":"x"}}"#;
const ACCT2: &str = r#"{"oauthAccount":{"accountUuid":"acct-2","emailAddress":"y"},"userID":"u2"}"#;

#[derive(Default)]
struct LoginRouter {
    /// served in turn, the last one repeated
    answers: Vec<serde_json::Value>,
    /// the query of each poll
    polls: Vec<String>,
    pushes: Vec<String>,
    /// the session has no Claude account (404 noAccount)
    none: bool,
}

fn login(
    creds: Option<&str>,
    account: Option<&str>,
    exp: i64,
    generation: i64,
    preparing: bool,
) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if let Some(c) = creds {
        m.insert("credentials".into(), c.into());
    }
    if let Some(a) = account {
        m.insert("account".into(), a.into());
    }
    m.insert("expiresAt".into(), exp.into());
    m.insert("gen".into(), generation.into());
    m.insert("preparing".into(), preparing.into());
    serde_json::Value::Object(m)
}

fn login_router(e: &TestEnv) -> (FakeRouter, Arc<Mutex<LoginRouter>>, Client) {
    let key = e.machine_key();
    let st = Arc::new(Mutex::new(LoginRouter::default()));
    let s2 = st.clone();
    let srv = FakeRouter::new(&key.sig.public_key(), move |r| {
        let mut f = s2.lock().unwrap();
        match (r.path.as_str(), r.method.as_str()) {
            ("/m/claude-login", "GET") if f.none => ans(
                404,
                r#"{"error":"this session has no Claude account","noAccount":true}"#,
            ),
            ("/m/claude-login", "GET") => {
                f.polls.push(r.query.clone());
                let a = f.answers[0].clone();
                if f.answers.len() > 1 {
                    f.answers.remove(0);
                }
                ok_json(a)
            }
            ("/m/claude-login", "POST") => {
                let b: serde_json::Value = serde_json::from_slice(&r.body).unwrap_or_default();
                f.pushes
                    .push(b["credentials"].as_str().unwrap_or("").into());
                ans(200, r#"{"stored":false}"#)
            }
            _ => ans(404, ""),
        }
    });
    let c = srv.client();
    (srv, st, c)
}

fn read(p: &std::path::Path) -> String {
    std::fs::read_to_string(p).unwrap_or_default()
}

/// a new session's Claude login comes from the router at boot (its Claude account's), whatever the account; a session
/// the router names no account for gets none
#[test]
fn session_claude_login_at_boot() {
    let e = TestEnv::new();
    let (_srv, f, c) = login_router(&e);
    f.lock().unwrap().answers = vec![login(Some(&pair(2000)), Some(ACCT), 2000, 0, false)];
    *TEST_STARTS.lock().unwrap() = Some(0);
    f.lock().unwrap().none = true;
    assert_eq!(session_claude_login(&c), "");
    assert_eq!(
        TEST_STARTS.lock().unwrap().unwrap(),
        0,
        "no Claude account for the session: nothing to do"
    );
    assert!(
        !creds_path().exists(),
        "a session with no account got a credentials file"
    );
    f.lock().unwrap().none = false;
    let acct = session_claude_login(&c);
    assert!(
        TEST_STARTS.lock().unwrap().unwrap() == 1 && acct.contains("acct-1"),
        "account {acct:?}"
    );
    assert_eq!(expires_at(read(&creds_path()).as_bytes()), 2000);
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(creds_path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        local_account(),
        "acct-1",
        "~/.claude.json didn't take the account"
    );
    // a resumed pair of the same account that expires later is kept
    std::fs::write(creds_path(), pair(3000)).unwrap();
    session_claude_login(&c);
    assert_eq!(
        expires_at(read(&creds_path()).as_bytes()),
        3000,
        "a later pair was replaced"
    );
    // a resume after a Re-login to another account: the restored ~/.claude.json takes the new account, other keys kept
    std::fs::write(
        e.home.join(".claude.json"),
        r#"{"oauthAccount":{"accountUuid":"acct-1"},"projects":{"x":1}}"#,
    )
    .unwrap();
    f.lock().unwrap().answers = vec![login(Some(&pair(2500)), Some(ACCT2), 2500, 0, false)];
    session_claude_login(&c);
    let j = read(&e.home.join(".claude.json"));
    assert!(
        local_account() == "acct-2" && j.contains(r#""projects""#) && j.contains(r#""u2""#),
        "{j}"
    );
}

/// afterSwitch's waits made short and its outside world faked (no Anthropic, no tmux)
fn quiet_after_switch() {
    RECHECK_AFTER_MS.store(10, Ordering::SeqCst);
    RC_DROP_WAIT_MS.store(50, Ordering::SeqCst);
    RC_MENU_WAIT_MS.store(50, Ordering::SeqCst);
    RC_UP_WAIT_MS.store(50, Ordering::SeqCst);
    SWITCH_POLL_MS.store(5, Ordering::SeqCst);
    *TEST_PROFILE.lock().unwrap() = Some(("acct-2".into(), "acct-2@example.com".into()));
    *TEST_PANE.lock().unwrap() = Some(Arc::new(String::new));
    *TEST_KEYS.lock().unwrap() = Some(Arc::new(|_: &[&str]| Ok(())));
}

fn syncer(c: &Client, pushed: &str) -> Syncer {
    Syncer {
        c: c.clone(),
        pushed: pushed.as_bytes().to_vec(),
        router_acc: String::new(),
        lock_gen: 0,
        locked_at: None,
    }
}

/// a switch to another account reaches a running machine: the router's pair wins even though the pair here expires
/// later, and both files change under the running claude
#[test]
fn creds_sync_account_switch() {
    let e = TestEnv::new();
    let (_srv, f, c) = login_router(&e);
    std::fs::create_dir_all(e.home.join(".claude")).unwrap();
    std::fs::write(e.home.join(".claude.json"), ACCT).unwrap();
    std::fs::write(creds_path(), pair(9000)).unwrap();
    quiet_after_switch();
    let mut s = syncer(&c, &pair(9000));
    // the first answer only tells the router's account (its pair expires sooner than ours)
    f.lock().unwrap().answers = vec![
        login(None, Some(ACCT2), 4000, 0, false),
        login(Some(&pair(4000)), Some(ACCT2), 4000, 0, false),
    ];
    s.step().unwrap();
    s.step().unwrap();
    {
        let f = f.lock().unwrap();
        assert!(
            f.polls[0].contains("have=9000") && f.polls[1].contains("have=0"),
            "polls {:?}",
            f.polls
        );
    }
    assert_eq!(
        expires_at(read(&creds_path()).as_bytes()),
        4000,
        "the other account's pair wasn't taken"
    );
    assert_eq!(
        local_account(),
        "acct-2",
        "~/.claude.json's oauthAccount wasn't switched"
    );
    assert!(
        !lock_dir().exists(),
        "the CLI's refresh lock was left taken"
    );
    // in step again: the usual expiry rule
    f.lock().unwrap().answers = vec![login(None, Some(ACCT2), 4000, 0, false)];
    let _ = s.step();
    assert!(f.lock().unwrap().polls[2].contains("have=4000"));
    std::thread::sleep(Duration::from_millis(300)); // the after-switch thread ends
}

/// lessons/74 on the machine: a refresh notice takes the CLI's lock and acknowledges; the new pair is written, then the
/// lock released; a failed refresh releases it
#[test]
fn creds_sync_lock_protocol() {
    let e = TestEnv::new();
    let (_srv, f, c) = login_router(&e);
    std::fs::create_dir_all(e.home.join(".claude")).unwrap();
    std::fs::write(creds_path(), pair(1000)).unwrap();
    let mut s = syncer(&c, &pair(1000));
    let answer = |v: serde_json::Value| f.lock().unwrap().answers = vec![v];
    answer(login(None, None, 1000, 1, true));
    s.step().unwrap();
    assert_eq!(s.lock_gen, 1, "no lock taken");
    assert!(lock_dir().exists(), "the CLI's lock dir isn't there");
    answer(login(Some(&pair(5000)), None, 5000, 1, false));
    s.step().unwrap();
    {
        let p = f.lock().unwrap().polls[1].clone();
        assert!(
            p.contains("ack=1") && p.contains("have=1000"),
            "the second poll must acknowledge: {p}"
        );
    }
    assert_eq!(
        expires_at(read(&creds_path()).as_bytes()),
        5000,
        "the new pair wasn't written"
    );
    assert!(
        !lock_dir().exists() && s.lock_gen == 0,
        "the lock wasn't released after the write"
    );
    assert!(
        f.lock().unwrap().pushes.is_empty(),
        "the router's own pair was pushed back"
    );
    // a failed refresh: preparing, then not preparing with no newer pair → released
    answer(login(None, None, 5000, 2, true));
    let _ = s.step();
    answer(login(None, None, 5000, 2, false));
    let _ = s.step();
    assert!(
        !lock_dir().exists() && s.lock_gen == 0,
        "a failed refresh left the lock"
    );
    // a lock the CLI holds (it is refreshing itself) is never removed by us
    std::fs::create_dir(lock_dir()).unwrap();
    answer(login(None, None, 5000, 3, true));
    let _ = s.step();
    answer(login(None, None, 5000, 3, false));
    let _ = s.step();
    assert!(lock_dir().exists(), "the CLI's own lock was removed");
    std::fs::remove_dir(lock_dir()).unwrap();
    // the session's claude refreshed by itself: its newer pair is pushed
    std::fs::write(creds_path(), pair(9000)).unwrap();
    answer(login(None, None, 5000, 0, false));
    let _ = s.step();
    {
        let p = f.lock().unwrap().pushes.clone();
        assert!(
            p.len() == 1 && expires_at(p[0].as_bytes()) == 9000,
            "the session's own refresh wasn't pushed: {p:?}"
        );
    }
    // a lock held past the limit is released before the next poll (which then acknowledges nothing)
    answer(login(None, None, 9000, 4, true));
    let _ = s.step();
    assert_eq!(s.lock_gen, 4, "no lock for gen 4");
    LOCK_HOLD_MAX_MS.store(0, Ordering::SeqCst);
    std::thread::sleep(Duration::from_millis(5));
    answer(login(None, None, 9000, 0, false));
    let _ = s.step();
    let last = f.lock().unwrap().polls.last().cloned().unwrap();
    assert!(
        last.contains("ack=0") && s.lock_gen == 0,
        "a stale lock wasn't released before the poll: {last}"
    );
    assert!(!lock_dir().exists(), "the stale lock is still there");
}

#[test]
fn take_if_later_rule() {
    let _e = TestEnv::new();
    assert!(
        take_if_later(b"{}").is_err(),
        "a pair without expiresAt is refused"
    );
    assert!(
        take_if_later(pair(10).as_bytes()).unwrap(),
        "no file: taken"
    );
    assert!(
        !take_if_later(pair(10).as_bytes()).unwrap(),
        "same expiry: kept"
    );
    assert!(take_if_later(pair(11).as_bytes()).unwrap(), "later: taken");
}

/// after the files changed: the token's account is checked and its proof written; an old record written back by
/// claude is set again; Remote Control, stopped by Claude Code, is enabled again through its menu
#[test]
fn after_switch_proof_and_remote_control() {
    let e = TestEnv::new();
    let sess = e.home.join(".claude/sessions");
    std::fs::create_dir_all(&sess).unwrap();
    quiet_after_switch();
    RC_DROP_WAIT_MS.store(3000, Ordering::SeqCst);
    RC_MENU_WAIT_MS.store(3000, Ordering::SeqCst);
    RC_UP_WAIT_MS.store(3000, Ordering::SeqCst);
    let reg = {
        let sess = sess.clone();
        move |bridge: &str| {
            let b = serde_json::json!({"status": "idle", "pid": std::process::id(), "bridgeSessionId": bridge});
            std::fs::write(sess.join("1.json"), b.to_string()).unwrap();
        }
    };
    reg("cse_old");
    std::fs::write(e.home.join(".claude.json"), ACCT).unwrap(); // claude's profile fetch put the old record back
    let st: Arc<Mutex<(String, Vec<String>)>> = Arc::new(Mutex::new(Default::default()));
    let s1 = st.clone();
    *TEST_PANE.lock().unwrap() = Some(Arc::new(move || s1.lock().unwrap().0.clone()));
    let (s2, reg2) = (st.clone(), reg.clone());
    *TEST_KEYS.lock().unwrap() = Some(Arc::new(move |a: &[&str]| {
        let mut s = s2.lock().unwrap();
        s.1.push(a.join(" "));
        if a.join(" ") == "Enter" {
            if s.0.contains(RC_ENABLE_TEXT) {
                s.0 = String::new();
                reg2("cse_new");
            } else if s.1.len() == 2 {
                s.0 = format!("Remote Control\n ❯ 1. {RC_ENABLE_TEXT}  Opens a secure connection");
            }
        }
        Ok(())
    }));
    let s3 = st.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        s3.lock().unwrap().0 = "signed-in claude.ai account or account or organization changed on this machine — run /remote-control".into();
    });
    let l = RouterLogin {
        credentials: pair(4000),
        account: ACCT2.into(),
        ..Default::default()
    };
    let c = Client::with_url("http://127.0.0.1:1", "m1");
    let t = std::thread::spawn(move || after_switch(&l, &c));
    let start = std::time::Instant::now();
    while !t.is_finished() {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "after_switch hung"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(read(&account_proof()).contains(r#""acct-2""#), "proof");
    assert_eq!(
        local_account(),
        "acct-2",
        "the old record written back by claude stayed"
    );
    let keys = st.lock().unwrap().1.join("|");
    assert_eq!(keys, "-l /remote-control|Enter|Enter");
    assert_eq!(live_bridge(), "cse_new");
}

/// Claude Code · Paseo (proxy login): after an account switch the token's account is checked and proven, but nothing is
/// typed into the terminal pane
#[test]
fn after_switch_proxy_login_types_nothing() {
    let e = TestEnv::new();
    let sess = e.home.join(".claude/sessions");
    std::fs::create_dir_all(&sess).unwrap();
    quiet_after_switch();
    let mut cert = crate::cert::Cert::default();
    cert.options.harness = "paseo-claude".into();
    *crate::grants::TEST_CERT.lock().unwrap() = Some(cert);
    let b = serde_json::json!({"status": "busy", "pid": std::process::id(), "bridgeSessionId": "paseo:s1"});
    std::fs::write(sess.join("paseo.json"), b.to_string()).unwrap();
    std::fs::write(e.home.join(".claude.json"), ACCT2).unwrap();
    let typed: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(vec![]));
    let t2 = typed.clone();
    *TEST_KEYS.lock().unwrap() = Some(Arc::new(move |a: &[&str]| {
        t2.lock().unwrap().push(a.join(" "));
        Ok(())
    }));
    *TEST_PANE.lock().unwrap() = Some(Arc::new(|| {
        "signed-in claude.ai account or account or organization changed".to_string()
    }));
    let l = RouterLogin {
        credentials: pair(4000),
        account: ACCT2.into(),
        ..Default::default()
    };
    after_switch(&l, &Client::with_url("http://127.0.0.1:1", "m1"));
    assert!(read(&account_proof()).contains(r#""acct-2""#), "proof");
    assert!(typed.lock().unwrap().is_empty(), "typed into the pane");
}

/// the installed token turns out to be another account's: no proof, nothing typed
#[test]
fn after_switch_wrong_account() {
    let e = TestEnv::new();
    std::fs::create_dir_all(e.home.join(".claude")).unwrap();
    quiet_after_switch();
    *TEST_PROFILE.lock().unwrap() = Some(("acct-9".into(), "other@example.com".into()));
    let typed = Arc::new(Mutex::new(false));
    let t2 = typed.clone();
    *TEST_KEYS.lock().unwrap() = Some(Arc::new(move |_: &[&str]| {
        *t2.lock().unwrap() = true;
        Ok(())
    }));
    let l = RouterLogin {
        credentials: pair(4000),
        account: ACCT2.into(),
        ..Default::default()
    };
    after_switch(&l, &Client::with_url("http://127.0.0.1:1", "m1"));
    assert!(
        !account_proof().exists() && !*typed.lock().unwrap(),
        "a proof for the wrong account, or keys typed"
    );
}

/// boot writes the Claude login marker seconds after "booted": the supervisor starts the sync whenever it appears
#[test]
fn creds_sync_starts_when_the_marker_comes_late() {
    let _e = TestEnv::new();
    MARKER_POLL_MS.store(10, Ordering::SeqCst);
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    let tx = Mutex::new(tx);
    *TEST_RUN_SYNC.lock().unwrap() = Some(Arc::new(move || {
        CREDS_SYNC_ON.store(true, Ordering::SeqCst);
        let _ = tx.lock().unwrap().send(());
    }));
    let t = std::thread::spawn(start_creds_sync_on_marker);
    std::thread::sleep(Duration::from_millis(100)); // booted, no marker yet
    assert!(rx.try_recv().is_err(), "started with no marker");
    std::fs::write(crate::paths::claude_login_on(), "1").unwrap();
    rx.recv_timeout(Duration::from_secs(3))
        .expect("the sync never started once the marker came");
    t.join().unwrap();
    // already running (the "claude-account" command started it): nothing more
    start_creds_sync_on_marker();
    assert!(
        rx.recv_timeout(Duration::from_millis(50)).is_err(),
        "started twice"
    );
}

/// the router's pair (no refresh token) is never pushed back, even on the first step after boot
#[test]
fn creds_sync_no_push_without_refresh_token() {
    let e = TestEnv::new();
    let (_srv, f, c) = login_router(&e);
    std::fs::create_dir_all(e.home.join(".claude")).unwrap();
    std::fs::write(
        creds_path(),
        r#"{"claudeAiOauth":{"accessToken":"a1","expiresAt":1000}}"#,
    )
    .unwrap();
    let mut s = syncer(&c, "");
    f.lock().unwrap().answers = vec![login(None, None, 1000, 0, false)];
    s.step().unwrap();
    assert!(
        f.lock().unwrap().pushes.is_empty(),
        "the router's pair was pushed back"
    );
}
