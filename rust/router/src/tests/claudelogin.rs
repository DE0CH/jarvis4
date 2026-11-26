//! claudelogin_test.go
use crate::claudelogin::{
    LoginAnswer, LoginErr, LoginHub, OAUTH, OAUTH_CLIENT_ID, OAUTH_SCOPES, OauthUrls, account_uuid,
    is_login_err,
};
use crate::ctx::Ctx;
use crate::nethttp::write_json;
use crate::testutil::*;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub fn pair_of(tag: &str, exp: i64) -> String {
    format!(
        r#"{{"claudeAiOauth":{{"accessToken":"at-{tag}","refreshToken":"rt-{tag}","expiresAt":{exp},"scopes":["user:inference","user:profile"],"subscriptionType":"max"}}}}"#
    )
}

pub const ACCT1: &str =
    r#"{"oauthAccount":{"accountUuid":"acct-1","emailAddress":"acct-1@example.com"}}"#;

pub fn now_ms() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
    )
    .unwrap_or(0)
}

#[derive(Default)]
pub struct FakeAState {
    pub refreshes: Vec<Value>,
    pub exchanges: Vec<Value>,
    pub reject: bool,
    pub accounts: HashMap<String, String>,
    pub on_refresh: Option<Arc<dyn Fn() + Send + Sync>>,
}

/// the token, profile and usage endpoints. Each access token "at-<tag>" belongs to the account named by
/// accounts[tag] (default "acct-1"); a refresh of "rt-<tag>" answers "at-<tag>'". OAUTH points at it until dropped.
pub struct FakeAnthropic {
    pub st: Arc<Mutex<FakeAState>>,
    _srv: TestServer,
    saved: OauthUrls,
}

impl FakeAnthropic {
    pub fn new() -> FakeAnthropic {
        let st: Arc<Mutex<FakeAState>> = Arc::default();
        let s2 = st.clone();
        let srv = TestServer::handler(move |w, req| {
            let path = req.path.clone();
            match path.as_str() {
                "/token" => {
                    let b: Value =
                        serde_json::from_slice(&req.read_body(1 << 20)).unwrap_or(Value::Null);
                    let mut f = s2.lock().unwrap_or_else(|e| e.into_inner());
                    if f.reject {
                        w.write_header(400);
                        w.write(br#"{"error":"invalid_grant","error_description":"Refresh token not found or invalid"}"#);
                        return;
                    }
                    match b["grant_type"].as_str() {
                        Some("refresh_token") => {
                            f.refreshes.push(b.clone());
                            if let Some(h) = f.on_refresh.clone() {
                                h();
                            }
                            let tag = format!(
                                "{}'",
                                b["refresh_token"]
                                    .as_str()
                                    .unwrap_or_default()
                                    .trim_start_matches("rt-")
                            );
                            write_json(
                                w,
                                200,
                                &json!({"access_token": format!("at-{tag}"), "refresh_token": format!("rt-{tag}"), "expires_in": 28800, "scope": "user:inference user:profile"}),
                            );
                        }
                        Some("authorization_code") => {
                            f.exchanges.push(b.clone());
                            write_json(
                                w,
                                200,
                                &json!({"access_token": "at-new", "refresh_token": "rt-new", "expires_in": 28800, "scope": "user:inference user:profile user:sessions:claude_code"}),
                            );
                        }
                        _ => {}
                    }
                }
                "/profile" => {
                    let auth = req.header("Authorization");
                    let tag = auth.trim_start_matches("Bearer ").trim_start_matches("at-");
                    let acct = s2
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .accounts
                        .get(tag.trim_end_matches('\''))
                        .cloned()
                        .unwrap_or_else(|| "acct-1".into());
                    write_json(
                        w,
                        200,
                        &json!({"account": {"uuid": acct, "email": format!("{acct}@example.com"), "display_name": "D"},
                            "organization": {"uuid": "org-1", "organization_type": "claude_max", "rate_limit_tier": "default_claude_max_20x"}}),
                    );
                }
                "/usage" => {
                    if req.header("Authorization").is_empty() {
                        w.write_header(401);
                        return;
                    }
                    w.write_header(200);
                    w.write(br#"{"limits":[{"kind":"session","group":"g","percent":12,"severity":"ok","resets_at":"2026-10-13T05:00:00Z","is_active":true,"scope":{"model":{"id":"m","display_name":"Opus"}}}],"extra_usage":{"is_enabled":false,"disabled_reason":"off"}}"#);
                }
                _ => {}
            }
        });
        let saved = OAUTH.read().unwrap_or_else(|e| e.into_inner()).clone();
        {
            let mut o = OAUTH.write().unwrap_or_else(|e| e.into_inner());
            o.token = format!("{}/token", srv.url);
            o.profile = format!("{}/profile", srv.url);
            o.usage = format!("{}/usage", srv.url);
        }
        FakeAnthropic {
            st,
            _srv: srv,
            saved,
        }
    }

    pub fn set(&self, f: impl FnOnce(&mut FakeAState)) {
        f(&mut self.st.lock().unwrap_or_else(|e| e.into_inner()));
    }

    pub fn get<R>(&self, f: impl FnOnce(&FakeAState) -> R) -> R {
        f(&self.st.lock().unwrap_or_else(|e| e.into_inner()))
    }
}

impl Drop for FakeAnthropic {
    fn drop(&mut self) {
        *OAUTH.write().unwrap_or_else(|e| e.into_inner()) = self.saved.clone();
    }
}

/// a router with one Claude account, claude-a (the default)
pub fn own_router() -> (TestRouter, Arc<LoginHub>) {
    let r = new_test_router();
    let h = r.accounts().add("a").unwrap_or_else(|e| panic!("{e:#}"));
    (r, h)
}

fn ok(res: anyhow::Result<bool>) {
    match res {
        Ok(true) => {}
        other => panic!("{other:?}"),
    }
}

#[test]
fn login_offer_newer_wins_and_account() {
    let _s = serial();
    let f = FakeAnthropic::new();
    let (r, h) = own_router();
    let now = now_ms();
    ok(h.offer(&pair_of("a", now + 1000), ACCT1, "seed", true, false));
    let e = h.offer(&pair_of("b", now + 500), "", "push", false, false);
    assert!(
        e.as_ref()
            .is_err_and(|e| is_login_err(e, LoginErr::NotNewer)),
        "an older pair must not replace a newer one: {e:?}"
    );
    f.set(|s| {
        s.accounts.insert("c".into(), "acct-2".into());
    });
    let e = h.offer(&pair_of("c", now + 2000), "", "push", false, false);
    assert!(
        e.as_ref()
            .is_err_and(|e| is_login_err(e, LoginErr::OtherAcct)),
        "another account's pair must be refused: {e:?}"
    );
    ok(h.offer(&pair_of("d", now + 3000), "", "push", false, false));
    let cur = h.current();
    assert!(
        cur.expires_at == now + 3000 && account_uuid(&cur.account) == "acct-1",
        "{cur:?}"
    );
    // sealed in the database (no refresh token in the clear there), and read back by a new hub (a router restart)
    let body: Vec<u8> =
        r.st.db()
            .and_then(|db| db.conn().ok())
            .and_then(|mut c| {
                c.query_opt("SELECT body FROM sealed_docs WHERE name = $1", &[&h.name])
                    .ok()
                    .flatten()
            })
            .map(|row| row.get::<_, Vec<u8>>(0))
            .unwrap_or_default();
    assert!(
        !body.is_empty() && !String::from_utf8_lossy(&body).contains("refresh"),
        "the sealed row: {} bytes",
        body.len()
    );
    let h2 = LoginHub::new(r.st.clone(), &h.name, &h.store);
    assert_eq!(h2.current().expires_at, now + 3000);
    let _ = h.offer("{}", "", "push", false, false);
    assert_eq!(
        h.current().expires_at,
        now + 3000,
        "a malformed pair changed the store"
    );
}

/// two replicas on one database: a pair one stores (the leader's refresh) reaches the other's waiting polls at once
/// (the reload stopgap), instead of the other serving the revoked pair until it restarts
#[test]
fn login_replica_reloads() {
    let _s = serial();
    let _f = FakeAnthropic::new();
    let (r1, h1) = own_router();
    let now = now_ms() + 8 * 3600 * 1000;
    let _ = h1.offer(&pair_of("a", now), ACCT1, "seed", true, false);
    let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
    let st2 = crate::state::State::open(r1.db.db(), dir.path(), r1.st.seal.clone())
        .unwrap_or_else(|e| panic!("{e:#}"));
    let r2 = crate::router::Router::new(
        test_config(dir.path()),
        Arc::new(st2),
        Arc::new(crate::core::CoreClient::new("http://127.0.0.1:9")),
        Default::default(),
    );
    let h2 = r2.accounts().hub(&h1.store);
    assert!(
        h2.as_ref().is_some_and(|h| h.current().expires_at == now),
        "the second replica's hub"
    );
    let h2 = h2.unwrap_or_else(|| unreachable!());
    std::thread::sleep(Duration::from_millis(200)); // its LISTEN is up
    let (tx, rx) = std::sync::mpsc::channel::<LoginAnswer>();
    let h2c = h2.clone();
    std::thread::spawn(move || {
        let _ = tx.send(h2c.poll(&Ctx::background(), "m:x", now, 0, Duration::from_secs(10)));
    });
    std::thread::sleep(Duration::from_millis(100));
    ok(h1.offer(&pair_of("b", now + 1000), "", "refresh", false, false));
    let a = rx
        .recv_timeout(Duration::from_secs(5))
        .unwrap_or_else(|_| panic!("the other replica's poll never got the new pair"));
    assert!(
        a.expires_at == now + 1000
            && a.credentials.contains("at-b")
            && !a.credentials.contains("refreshToken"),
        "the other replica answered {a:?}"
    );
}

/// the lessons/74 protocol: participants lock before the refresh, the refresh waits for them, then all get the pair
#[test]
fn login_refresh_protocol() {
    let _s = serial();
    let f = FakeAnthropic::new();
    let (_r, h) = own_router();
    let exp = now_ms() + 10 * 60 * 1000; // inside the margin: due
    let _ = h.offer(&pair_of("a", exp), ACCT1, "seed", true, false);
    let ctx = Ctx::background();
    // two participants, each seen (polling with have = the current expiry)
    for who in ["m:1", "jarvis1"] {
        let a = h.poll(&ctx, who, exp, 0, Duration::ZERO);
        assert!(
            a.credentials.is_empty() && !a.preparing,
            "{who}: nothing new yet: {a:?}"
        );
    }
    let locked = Arc::new(AtomicI32::new(0));
    let bad = Arc::new(Mutex::new(Vec::<String>::new()));
    {
        let (l, b) = (locked.clone(), bad.clone());
        f.set(|s| {
            s.on_refresh = Some(Arc::new(move || {
                if l.load(Ordering::SeqCst) != 2 {
                    b.lock().unwrap_or_else(|e| e.into_inner()).push(format!(
                        "refreshed with {} of 2 participants locked",
                        l.load(Ordering::SeqCst)
                    ));
                }
            }));
        });
    }
    let mut ths = vec![];
    for who in ["m:1", "jarvis1"] {
        let (h, l, b) = (h.clone(), locked.clone(), bad.clone());
        ths.push(std::thread::spawn(move || {
            let ctx = Ctx::background();
            let a = h.poll(&ctx, who, exp, 0, Duration::from_secs(30)); // waits for the prepare
            if !a.preparing {
                b.lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(format!("{who}: expected a prepare: {a:?}"));
                return LoginAnswer::default();
            }
            l.fetch_add(1, Ordering::SeqCst); // the participant took its CLI lock
            h.poll(&ctx, who, exp, a.r#gen, Duration::from_secs(30)) // acknowledges and waits for the pair
        }));
    }
    std::thread::sleep(Duration::from_millis(50));
    let start = Instant::now();
    ok(h.refresh(false));
    assert!(
        start.elapsed() <= Duration::from_secs(5),
        "the refresh waited out the ack timeout although both acknowledged"
    );
    for (i, th) in ths.into_iter().enumerate() {
        let a = th.join().unwrap_or_default();
        assert!(
            a.credentials.contains("at-a'") && !a.preparing && a.expires_at > exp,
            "participant {i}: {a:?}"
        );
    }
    let b = bad.lock().unwrap_or_else(|e| e.into_inner()).clone();
    assert!(b.is_empty(), "{b:?}");
    f.get(|s| {
        assert!(
            s.refreshes.len() == 1
                && s.refreshes[0]["refresh_token"] == "rt-a"
                && s.refreshes[0]["scope"] == "user:inference user:profile",
            "{:?}",
            s.refreshes
        );
    });
    // not due again
    assert!(!h.refresh(false).unwrap_or(false), "refreshed a fresh pair");
}

/// a refused refresh: participants are told to release; the dead login is DMed once, not retried
#[test]
fn login_refresh_rejected() {
    let _s = serial();
    let f = FakeAnthropic::new();
    let (r, h) = own_router();
    // the hub's DM is the router's (claudeaccounts.rs sets it when the hub is made)
    let dms = capture_dm(&r);
    let exp = now_ms() + 60 * 1000;
    let _ = h.offer(&pair_of("a", exp), ACCT1, "seed", true, false);
    h.poll(&Ctx::background(), "m:1", exp, 0, Duration::ZERO);
    f.set(|s| s.reject = true);
    let h2 = h.clone();
    let th = std::thread::spawn(move || {
        let ctx = Ctx::background();
        let a = h2.poll(&ctx, "m:1", exp, 0, Duration::from_secs(10));
        h2.poll(&ctx, "m:1", exp, a.r#gen, Duration::from_secs(10))
    });
    std::thread::sleep(Duration::from_millis(50));
    assert!(h.refresh(false).is_err(), "expected the refusal");
    let a = th.join().unwrap_or_default();
    assert!(
        !a.preparing && a.credentials.is_empty(),
        "the participant must be told to release: {a:?}"
    );
    // it answers at once while the participant still says it holds a lock (ack != 0, not preparing)
    let a = h.poll(&Ctx::background(), "m:1", exp, 1, Duration::from_secs(10));
    assert!(!a.preparing, "{a:?}");
    let n = f.get(|s| s.refreshes.len());
    assert!(
        h.refresh(false).is_err() && f.get(|s| s.refreshes.len()) == n,
        "a refused grant must not be retried"
    );
    std::thread::sleep(Duration::from_millis(20));
    let n = dms.lock().unwrap_or_else(|e| e.into_inner()).len();
    assert_eq!(n, 1, "DMs");
    let st = h.status();
    assert!(
        st.get("needLogin") == Some(&json!(true)) && st.get("rejected") == Some(&json!(true)),
        "{st:?}"
    );
    // a newer pair (a Re-login, a push) clears it
    let _ = h.offer(
        &pair_of("b", now_ms() + 8 * 3600 * 1000),
        "",
        "relogin",
        true,
        true,
    );
    assert!(
        h.status().get("needLogin") != Some(&json!(true)),
        "{:?}",
        h.status()
    );
}

fn query_of(u: &str) -> HashMap<String, String> {
    let q = u.split_once('?').map(|(_, q)| q).unwrap_or_default();
    q.split('&')
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| {
            (
                k.to_string(),
                percent_encoding::percent_decode_str(&v.replace('+', " "))
                    .decode_utf8_lossy()
                    .into_owned(),
            )
        })
        .collect()
}

#[test]
fn login_relogin() {
    let _s = serial();
    let f = FakeAnthropic::new();
    let (r, h) = own_router();
    let app = r.handler();
    let (code, out) = call(&app, "POST", "/api/claude-login/start", "");
    assert_eq!(code, 200, "{out}");
    let u = out["url"].as_str().unwrap_or_default().to_string();
    let q = query_of(&u);
    let redirect = OAUTH
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .redirect
        .clone();
    assert!(
        u.starts_with("https://claude.com/")
            && q.get("client_id").map(String::as_str) == Some(OAUTH_CLIENT_ID)
            && q.get("redirect_uri") == Some(&redirect)
            && q.get("code_challenge_method").map(String::as_str) == Some("S256")
            && q.get("scope") == Some(&OAUTH_SCOPES.join(" "))
            && q.get("state").is_some_and(|s| !s.is_empty())
            && q.get("code").map(String::as_str) == Some("true"),
        "{u}"
    );
    let state = q.get("state").cloned().unwrap_or_default();
    let (code, _) = call(
        &app,
        "POST",
        "/api/claude-login/code",
        r#"{"code":"abc#wrong"}"#,
    );
    assert_eq!(code, 400, "another sign-in's state must be refused");
    let (code, out) = call(
        &app,
        "POST",
        "/api/claude-login/code",
        &format!(r#"{{"code":"abc#{state}"}}"#),
    );
    assert!(
        code == 200 && out["email"] == "acct-1@example.com",
        "{code} {out}"
    );
    let x = f.get(|s| s.exchanges[0].clone());
    assert!(
        x["code"] == "abc"
            && x["redirect_uri"] == json!(redirect)
            && x["code_verifier"].as_str().is_some_and(|v| !v.is_empty())
            && x["state"] == json!(state),
        "{x}"
    );
    let cur = h.current();
    let d: Value = serde_json::from_str(&cur.credentials).unwrap_or(Value::Null);
    let o = &d["claudeAiOauth"];
    assert!(
        o["accessToken"] == "at-new"
            && o["subscriptionType"] == "max"
            && o["rateLimitTier"] == "default_claude_max_20x"
            && account_uuid(&cur.account) == "acct-1",
        "{o} {}",
        cur.account
    );
    let (code, _) = call(
        &app,
        "POST",
        "/api/claude-login/code",
        &format!(r#"{{"code":"abc#{state}"}}"#),
    );
    assert_eq!(code, 400, "a code is used once");
    // status and usage, with no secret in either
    let (code, st) = call(&app, "GET", "/api/claude-login", "");
    assert!(
        code == 200 && st["email"] == "acct-1@example.com" && !st.to_string().contains("at-new"),
        "{code} {st}"
    );
    let (code, us) = call(&app, "GET", "/api/usage", "");
    assert!(
        code == 200
            && us["limits"].as_array().is_some_and(|l| l.len() == 1)
            && us["limits"][0]["model"] == "Opus",
        "{code} {us}"
    );
}

/// machines: only one whose session uses the account gets its pair; its push is account-checked
#[test]
fn login_machine_routes() {
    let _s = serial();
    let f = FakeAnthropic::new();
    let (r, h) = own_router();
    let exp = now_ms() + 8 * 3600 * 1000;
    let _ = h.offer(&pair_of("a", exp), ACCT1, "seed", true, false);
    add_session(&r, "sA", "started", "mA", false);
    add_session(&r, "sB", "started", "mB", false);
    r.st.do_(|d| {
        if let Some(s) = d.sessions.get_mut("sA") {
            s.claude_account = "claude-a".into();
        }
    });
    let (ma, mb) = (new_test_machine(&r, "mA"), new_test_machine(&r, "mB"));
    let mh = r.machine_handler();
    let (code, out) = mb.do_(&mh, "GET", "/m/claude-login?have=0", "");
    assert!(
        code == 404 && out["noAccount"] == true,
        "a machine whose session has no account got a pair: {code} {out}"
    );
    let (code, out) = ma.do_(&mh, "GET", "/m/claude-login?have=0", "");
    assert!(
        code == 200
            && out["credentials"]
                .as_str()
                .is_some_and(|c| c.contains("at-a"))
            && account_uuid(out["account"].as_str().unwrap_or_default()) == "acct-1",
        "{code} {out}"
    );
    let (code, out) = ma.do_(&mh, "GET", &format!("/m/claude-login?have={exp}"), "");
    assert!(
        code == 200 && out.get("credentials").is_none_or(Value::is_null),
        "no pair when the caller's is as new: {code} {out}"
    );
    // a push of the machine's own refresh: newer, same account → stored
    let b = json!({"credentials": pair_of("b", exp + 1000)}).to_string();
    let (code, out) = ma.do_(&mh, "POST", "/m/claude-login", &b);
    assert!(code == 200 && out["stored"] == true, "{code} {out}");
    f.set(|s| {
        s.accounts.insert("c".into(), "acct-evil".into());
    });
    let b = json!({"credentials": pair_of("c", exp + 5000)}).to_string();
    let (code, _) = ma.do_(&mh, "POST", "/m/claude-login", &b);
    assert!(
        code == 403 && h.current().expires_at == exp + 1000,
        "another account's pair was stored: {code}"
    );
    // Jarvis 1's session script, through $JARVIS_URL
    let (code, out) = ma.do_(&mh, "GET", "/m/api/credentials", "");
    assert!(
        code == 200 && out["expiresAt"].as_i64() == Some(exp + 1000),
        "{code} {out}"
    );
}

/// the peer route (Jarvis 1): the same poll; a Re-login pushed from Jarvis 1 may switch the account
#[test]
fn login_peer() {
    let _s = serial();
    let f = FakeAnthropic::new();
    let (r, h) = own_router();
    let app = r.handler();
    let exp = now_ms() + 8 * 3600 * 1000;
    let _ = h.offer(&pair_of("a", exp), ACCT1, "seed", true, false);
    let (code, out) = call(&app, "GET", "/peer/claude-login?have=0", "");
    assert!(
        code == 200
            && out["credentials"]
                .as_str()
                .is_some_and(|c| c.contains("at-a")),
        "{code} {out}"
    );
    f.set(|s| {
        s.accounts.insert("z".into(), "acct-2".into());
    });
    let b = json!({"credentials": pair_of("z", exp + 10), "account": r#"{"oauthAccount":{"accountUuid":"acct-2"}}"#}).to_string();
    let (code, _) = call(&app, "POST", "/peer/claude-login", &b);
    assert_eq!(code, 403, "a plain push of another account must be refused");
    let b = json!({"credentials": pair_of("z", exp - 10), "account": r#"{"oauthAccount":{"accountUuid":"acct-2"}}"#, "relogin": true}).to_string();
    let (code, out) = call(&app, "POST", "/peer/claude-login", &b);
    assert!(
        code == 200 && out["stored"] == true && account_uuid(&h.current().account) == "acct-2",
        "a Re-login through Jarvis 1 wins: {code} {out}"
    );
    // the setup status is the setup session's (signed): a router with Access refuses anyone else
    let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
    let r2 = crate::router::Router::new(
        crate::router::Config {
            data_dir: dir.path().display().to_string(),
            app_aud: "a".into(),
            setup_aud: "s".into(),
            ..Default::default()
        },
        r.st.clone(),
        Arc::new(crate::core::CoreClient::new("http://127.0.0.1:9")),
        Default::default(),
    );
    let app2 = r2.handler();
    let (code, _) = call(&app2, "GET", "/setup/claude-login", "");
    assert_eq!(code, 403);
    let (code, _) = call(&app2, "GET", "/peer/claude-login", "");
    assert!(code == 503 || code == 403, "{code}");
}

/// a machine that signed its poll's path with the query (the session image of 2026-10-13 01:30-03:00) is answered too
#[test]
fn login_poll_signed_with_query() {
    let _s = serial();
    let _f = FakeAnthropic::new();
    let (r, h) = own_router();
    let _ = h.offer(
        &pair_of("a", now_ms() + 8 * 3600 * 1000),
        ACCT1,
        "seed",
        true,
        false,
    );
    add_session(&r, "sA", "started", "mA", false);
    r.st.do_(|d| {
        if let Some(s) = d.sessions.get_mut("sA") {
            s.claude_account = "claude-a".into();
        }
    });
    let m = new_test_machine(&r, "mA");
    let target = "/m/claude-login?have=0&ack=0&wait=0";
    let (ts, sig) = signed_headers(&m.key, "GET", target, b"", crate::util::unix_now());
    let mut req = crate::nethttp::Req::new("GET", target, b"")
        .with_header("X-Machine", "mA")
        .with_header("X-Time", &ts)
        .with_header("X-Sig", &sig);
    let mut w = crate::nethttp::W::recorder();
    (r.machine_handler())(&mut w, &mut req);
    assert!(
        w.status() == 200 && w.body_text().contains("at-a"),
        "{} {}",
        w.status(),
        w.body_text()
    );
}
