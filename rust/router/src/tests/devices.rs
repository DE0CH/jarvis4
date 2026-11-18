use crate::devices::{CfServiceToken, DELETE_DEVICE_TOKEN, MINT_DEVICE_TOKEN};
use crate::http::AccessClaims;
use crate::nethttp::{Req, W};
use crate::testutil::new_test_router_with;
use jarvis_go::GoTime;
use std::collections::BTreeMap;
use std::sync::Mutex;

/// the tokens a fake Cloudflare minted: id → name
static TOKENS: Mutex<(i64, BTreeMap<String, String>)> = Mutex::new((0, BTreeMap::new()));

fn mint(name: &str) -> anyhow::Result<CfServiceToken> {
    let mut g = TOKENS.lock().unwrap_or_else(|e| e.into_inner());
    g.0 += 1;
    let id = format!("tok{}", g.0);
    g.1.insert(id.clone(), name.into());
    Ok(CfServiceToken {
        client_id: format!("{id}.access"),
        client_secret: format!("secret-{id}"),
        id,
    })
}

fn delete(id: &str) -> anyhow::Result<()> {
    TOKENS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .1
        .remove(id); // a token already gone is no error
    Ok(())
}

#[test]
fn pair_list_admit_revoke_devices() {
    let _g = crate::testutil::serial();
    let (om, od) = (
        *MINT_DEVICE_TOKEN.read().unwrap_or_else(|e| e.into_inner()),
        *DELETE_DEVICE_TOKEN
            .read()
            .unwrap_or_else(|e| e.into_inner()),
    );
    *MINT_DEVICE_TOKEN.write().unwrap_or_else(|e| e.into_inner()) = mint;
    *DELETE_DEVICE_TOKEN
        .write()
        .unwrap_or_else(|e| e.into_inner()) = delete;
    *TOKENS.lock().unwrap_or_else(|e| e.into_inner()) = (0, BTreeMap::new());
    let res = std::panic::catch_unwind(run);
    *MINT_DEVICE_TOKEN.write().unwrap_or_else(|e| e.into_inner()) = om;
    *DELETE_DEVICE_TOKEN
        .write()
        .unwrap_or_else(|e| e.into_inner()) = od;
    if let Err(p) = res {
        std::panic::resume_unwind(p);
    }
}

fn run() {
    let t = new_test_router_with(
        |c| c.allowed_email = "chendeyao000@gmail.com".into(),
        None,
        Default::default(),
    );
    let h = t.handler();
    let get = |method: &str, target: &str| {
        let mut w = W::recorder();
        let mut req = Req::new(method, target, b"");
        h(&mut w, &mut req);
        w
    };
    let pair = |app: &str, state: &str| {
        let w = get(
            "GET",
            &format!(
                "/api/devices/pair?state={state}&name=Deyao%27s+iPhone&model=iPhone18,3&app={app}"
            ),
        );
        assert_eq!(w.status(), 302, "pair: {}", w.body_text());
        let loc = w
            .headers
            .get("Location")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        url::Url::parse(&loc).unwrap_or_else(|e| panic!("{loc}: {e}"))
    };
    let q = |u: &url::Url, k: &str| {
        u.query_pairs()
            .find(|(n, _)| n == k)
            .map(|(_, v)| v.into_owned())
            .unwrap_or_default()
    };
    let u = pair("paseo", "abcdefghijklmnop");
    assert!(
        u.scheme() == "paseo-de0ch"
            && u.host_str() == Some("paired")
            && q(&u, "state") == "abcdefghijklmnop"
            && q(&u, "clientId") == "tok1.access"
            && q(&u, "clientSecret") == "secret-tok1"
            && !q(&u, "id").is_empty(),
        "answer {u}"
    );
    assert_eq!(
        TOKENS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .1
            .get("tok1")
            .map(String::as_str),
        Some("jarvis2-device paseo Deyao's iPhone")
    );
    // a second pairing within 30 s: refused through the scheme, no token minted
    let u2 = pair("openclaw", "abcdefghijklmnopq");
    assert!(
        u2.scheme() == "openclaw-de0ch"
            && q(&u2, "status") == "429"
            && q(&u2, "clientSecret").is_empty(),
        "second: {u2}"
    );
    assert!(
        !TOKENS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .1
            .contains_key("tok2"),
        "a token for a refused pairing"
    );
    for target in [
        "/api/devices/pair?state=short&app=paseo",
        "/api/devices/pair?state=abcdefghijklmnop&app=jarvis",
    ] {
        assert_eq!(get("GET", target).status(), 400, "{target}");
    }
    // the list shows no token ids or secrets
    let w = get("GET", "/api/devices");
    let b = w.body_text();
    assert!(
        w.status() == 200
            && b.contains(r#""app":"paseo""#)
            && !b.contains("tok1")
            && !b.contains("secret"),
        "list: {b}"
    );
    // who /api/remotes admits: Deyao, a paired device's token, nobody else
    let now = GoTime::now();
    let c = |email: &str, cn: &str| AccessClaims {
        email: email.into(),
        common_name: cn.into(),
        ..Default::default()
    };
    assert!(
        t.admit_claims(&c("ChenDeyao000@gmail.com", ""), now)
            && !t.admit_claims(&c("x@y.z", ""), now)
            && t.admit_claims(&c("", "tok1.access"), now)
            && !t.admit_claims(&c("", "other.access"), now)
            && !t.admit_claims(&c("", ""), now),
        "admit"
    );
    // revoke: the token goes at Cloudflare, the device from the list, and its token is no longer admitted
    let id = q(&u, "id");
    let w = get("DELETE", &format!("/api/devices/{id}"));
    assert_eq!(w.status(), 200, "revoke: {}", w.body_text());
    assert!(
        !TOKENS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .1
            .contains_key("tok1")
            && !t.admit_claims(&c("", "tok1.access"), now),
        "revoked token still there"
    );
    assert_eq!(
        get("DELETE", &format!("/api/devices/{id}")).status(),
        200,
        "revoke twice"
    );
    assert_ne!(
        get("POST", "/api/sessions/snope/start").status(),
        202,
        "start of nothing"
    );
}

/// A session from the chat is the app's New session with nothing touched (Deyao, 2026-11-18: the first one started
/// with no CLAUDE.md, as it had no repo): the store `default` and DE0CH/claude-env with its key's store, never a
/// sensitive store.
#[test]
fn new_session_defaults_are_the_apps_pre_picks() {
    use crate::devices::new_session_defaults;
    use crate::repos::RepoEntry;
    use crate::storedocs::StoreRow;
    let entry = |name: &str, repo: &str, store: &str| RepoEntry {
        name: name.into(),
        url: format!("https://github.com/{repo}.git"),
        repo: repo.into(),
        store: store.into(),
        ..Default::default()
    };
    let row = |name: &str, sensitive: bool| StoreRow {
        name: name.into(),
        sensitive,
        ..Default::default()
    };
    let env = entry("claude-env", "DE0CH/claude-env", "github-claude-env");
    let other = entry("jarvis4", "DE0CH/jarvis4", "github-jarvis4");
    let rows = vec![
        row("default", false),
        row("github-claude-env", false),
        row("github-jarvis4", false),
        row("identity", true),
    ];
    let (stores, repos) = new_session_defaults(&rows, &[other, env.clone()]);
    assert!(
        stores.join(",") == "default,github-claude-env" && repos == env.url,
        "defaults: {stores:?} {repos:?}"
    );
    // a sensitive default store, or a sensitive (or missing) key store: never pre-picked, nor the repo it would clone
    let rows = vec![row("default", true), row("github-claude-env", true)];
    let (stores, repos) = new_session_defaults(&rows, std::slice::from_ref(&env));
    assert!(
        stores.is_empty() && repos.is_empty(),
        "sensitive: {stores:?} {repos:?}"
    );
    let (stores, repos) = new_session_defaults(&[row("default", false)], &[]);
    assert!(
        stores.join(",") == "default" && repos.is_empty(),
        "no repos on the list: {stores:?} {repos:?}"
    );
}
