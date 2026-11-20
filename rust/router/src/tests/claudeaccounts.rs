//! router/claudeaccounts_test.go
use super::claudelogin::FakeAnthropic;
use crate::claudeaccounts::{account_store_name, slug_from_email};
use crate::claudelogin::account_uuid;
use crate::flows::NewSession;
use crate::policy::{HarnessPolicy, Policy};
use crate::router::Router;
use crate::testutil::*;
use serde_json::Value;
use std::sync::Arc;

/// an account's sign-in through the app routes, as Deyao does it (start → the page → paste code#state)
fn sign_in(r: &Router, start_path: &str, start_body: &str) -> (u16, Value) {
    let (code, out) = app_do(r, "POST", start_path, start_body, &[]);
    if code != 200 {
        return (code, out);
    }
    let u = out["url"].as_str().unwrap_or_default();
    let state = u
        .split(['?', '&'])
        .find_map(|kv| kv.strip_prefix("state="))
        .unwrap_or_default()
        .to_string();
    let store = out["store"].as_str().unwrap_or_default().to_string();
    app_do(
        r,
        "POST",
        &format!("/api/claude-accounts/{store}/code"),
        &format!(r#"{{"code":"abc#{state}"}}"#),
        &[],
    )
}

/// Add, Re-login, Make default, Remove (DECISIONS 185)
#[test]
fn claude_accounts_manage() {
    let _s = serial();
    let f = FakeAnthropic::new();
    let r = new_test_router();
    let (code, out) = app_do(&r, "GET", "/api/claude-accounts", "", &[]);
    assert!(
        code == 200
            && out["default"] == ""
            && out["accounts"].as_array().is_some_and(Vec::is_empty),
        "{code} {out}"
    );
    let (code, _) = app_do(
        &r,
        "POST",
        "/api/claude-accounts",
        r#"{"name":"Bad Name!"}"#,
        &[],
    );
    assert_eq!(code, 400, "a name that can't be a store name was taken");
    // the first account: signed in, and the default
    let (code, out) = sign_in(&r, "/api/claude-accounts", r#"{"name":"main"}"#);
    assert!(
        code == 200 && out["store"] == "claude-main" && out["email"] == "acct-1@example.com",
        "{code} {out}"
    );
    // Add of a name that exists is its sign-in
    let (code, out) = app_do(
        &r,
        "POST",
        "/api/claude-accounts",
        r#"{"name":"claude-main"}"#,
        &[],
    );
    assert!(
        code == 200 && out["store"] == "claude-main",
        "the same name twice: {code} {out}"
    );
    // a second slot signed in to the same Claude account: the fresh grant lands in that account's own store
    let (code, out) = sign_in(&r, "/api/claude-accounts", r#"{"name":"work"}"#);
    assert!(
        code == 200
            && out["store"] == "claude-main"
            && out["note"]
                .as_str()
                .is_some_and(|n| n.contains("added as a new account, claude-main")),
        "the same Claude account in two slots: {code} {out}"
    );
    f.set(|s| {
        s.accounts.insert("new".into(), "acct-2".into());
    });
    let (code, out) = sign_in(&r, "/api/claude-accounts/claude-work/login", "");
    assert!(
        code == 200 && out["email"] == "acct-2@example.com",
        "{code} {out}"
    );
    // a Re-login into an account as another Claude account: kept as that account's own, claude-work unchanged
    f.set(|s| {
        s.accounts.insert("new".into(), "acct-3".into());
    });
    let (code, out) = sign_in(&r, "/api/claude-accounts/claude-work/login", "");
    assert!(
        code == 200 && out["store"] == "claude-acct-3",
        "a Re-login as another account: {code} {out}"
    );
    assert_eq!(
        r.accounts()
            .hub("claude-work")
            .map(|h| account_uuid(&h.current().account)),
        Some("acct-2".into()),
        "a Re-login switched an account's Claude account"
    );
    let (code, _) = app_do(&r, "DELETE", "/api/claude-accounts/claude-acct-3", "", &[]);
    assert_eq!(code, 200, "remove");
    let (_, out) = app_do(&r, "GET", "/api/claude-accounts", "", &[]);
    let rows = out["accounts"].as_array().cloned().unwrap_or_default();
    assert!(
        out["default"] == "claude-main"
            && rows.len() == 2
            && rows[1]["store"] == "claude-work"
            && rows[1]["email"] == "acct-2@example.com"
            && rows[0]["default"] == true
            && !out.to_string().contains("at-new"),
        "{out}"
    );
    // usage per account
    let (code, out) = app_do(&r, "GET", "/api/claude-accounts/claude-work/usage", "", &[]);
    assert!(
        code == 200
            && out["store"] == "claude-work"
            && out["limits"].as_array().is_some_and(|l| l.len() == 1),
        "{code} {out}"
    );
    // Remove: refused while a session uses it (a session keeps its account for its life), never moving the session
    add_session(&r, "s1", "paused", "", false);
    r.st.do_(|d| {
        if let Some(s) = d.sessions.get_mut("s1") {
            s.claude_account = "claude-main".into();
        }
    });
    let (code, out) = app_do(&r, "DELETE", "/api/claude-accounts/claude-main", "", &[]);
    assert!(
        code == 409 && out["error"].as_str().is_some_and(|e| e.contains("s1")),
        "removed an account a session uses: {code} {out}"
    );
    r.st.do_(|d| {
        assert_eq!(
            d.sessions.get("s1").map(|s| s.claude_account.as_str()),
            Some("claude-main"),
            "the session was moved to another account"
        );
        d.sessions.remove("s1");
    });
    // the default can go: the next account becomes the default
    let (code, out) = app_do(&r, "DELETE", "/api/claude-accounts/claude-main", "", &[]);
    assert!(
        code == 200 && out["default"] == "claude-work" && r.accounts().hub("claude-main").is_none(),
        "remove the default: {code} {out}"
    );
    assert!(
        !std::path::Path::new(&r.cfg.data_dir)
            .join("claude-accounts")
            .join("claude-main.json")
            .exists(),
        "a removed account's pair stayed on the volume"
    );
    // the routes of the one shared login act on the default account
    let (code, out) = app_do(&r, "GET", "/api/claude-login", "", &[]);
    assert!(code == 200 && out["store"] == "claude-work", "{code} {out}");
    // a router restart reads the accounts back
    let r2 = Router::new(
        crate::router::Config {
            no_access: true,
            data_dir: r.cfg.data_dir.clone(),
            ..Default::default()
        },
        r.st.clone(),
        Arc::new(crate::core::CoreClient::new("http://127.0.0.1:9")),
        Default::default(),
    );
    let a2 = r2.accounts();
    assert!(
        a2.hub("claude-work")
            .is_some_and(|h| account_uuid(&h.current().account) == "acct-2")
            && a2.default_store() == "claude-work",
        "not read back"
    );
}

// claudeaccounts_test.go's TestClaudeAccountsMigrateSharedLogin is not ported: the one-time move of claude-login.json
// is not carried over (claudeaccounts.rs: every router that runs this code has made it already).

#[test]
fn slug_and_store_names() {
    for (input, want) in [
        ("chendeyao.uk@gmail.com", "chendeyao-uk"),
        ("A_B..c@x", "a-b-c"),
        ("@x", ""),
    ] {
        assert_eq!(slug_from_email(input), want, "{input:?}");
    }
    for (input, want) in [
        ("work", "claude-work"),
        ("claude-work", "claude-work"),
        ("Work", "claude-work"),
        ("", ""),
        ("a--b", ""),
        ("claude-", ""),
        ("x y", ""),
    ] {
        assert_eq!(account_store_name(input), want, "{input:?}");
    }
}

/// a new session gets the account it names, else the default; a harness without one gets none; the old store is refused
#[test]
fn new_session_claude_account() {
    let _s = serial();
    let _f = FakeAnthropic::new();
    let policy = Policy {
        harnesses: [
            (
                "claude".to_string(),
                HarnessPolicy {
                    stores: vec!["tunnel".into()],
                    claude_account: true,
                },
            ),
            (
                "opencode".to_string(),
                HarnessPolicy {
                    stores: vec!["openrouter".into()],
                    claude_account: false,
                },
            ),
        ]
        .into_iter()
        .collect(),
    };
    let rg = Rig::with_policy(|_| {}, policy);
    let r = rg.t.r.clone();
    let acct = |id: &str| {
        r.st.read(|d| {
            d.sessions
                .get(id)
                .map(|s| s.claude_account.clone())
                .unwrap_or_default()
        })
    };
    let mode = |id: &str| {
        r.st.read(|d| {
            d.sessions
                .get(id)
                .map(|s| s.permission_mode.clone())
                .unwrap_or_default()
        })
    };
    let ns = |label: &str, harness: &str| NewSession {
        label: label.into(),
        harness: harness.into(),
        ..Default::default()
    };
    // no account at all (a new box): it starts logged out
    let id = r
        .create_session(ns("x", "claude"))
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert_eq!(acct(&id), "", "a Claude session with no account at all");
    // bypass is the only start mode (Deyao, 2026-10-22): unnamed → bypass, bypass → bypass, anything else refused
    let id = r
        .create_session(ns("m", "claude"))
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert_eq!(mode(&id), "bypass", "no mode named");
    let id = r
        .create_session(NewSession {
            permission_mode: "bypass".into(),
            ..ns("m", "claude")
        })
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert_eq!(mode(&id), "bypass", "bypass named");
    let e = r.create_session(NewSession {
        permission_mode: "auto".into(),
        ..ns("m", "claude")
    });
    assert!(
        e.as_ref()
            .is_err_and(|e| e.to_string().contains("only start mode")),
        "auto must be refused: {e:?}"
    );
    let _ = r.accounts().add("main");
    let _ = r.accounts().add("work");
    let id = r
        .create_session(ns("x", "claude"))
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert_eq!(acct(&id), "claude-main");
    let id = r
        .create_session(NewSession {
            account: "work".into(),
            ..ns("y", "claude")
        })
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert_eq!(acct(&id), "claude-work");
    assert!(
        r.create_session(NewSession {
            account: "nope".into(),
            ..ns("z", "claude")
        })
        .is_err(),
        "an unknown account was taken"
    );
    // the old shared store is dropped, not refused: the session gets its account instead
    let id = r
        .create_session(NewSession {
            stores: vec!["claude".into()],
            ..ns("z", "claude")
        })
        .unwrap_or_else(|e| panic!("{e:#}"));
    let zs = r.st.read(|d| {
        d.sessions
            .get(&id)
            .and_then(|s| s.stores.clone())
            .unwrap_or_default()
    });
    assert!(
        !zs.iter().any(|x| x == "claude") && !acct(&id).is_empty(),
        "the old store: {zs:?} {}",
        acct(&id)
    );
    let id = r
        .create_session(ns("o", "opencode"))
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert_eq!(acct(&id), "");
    // an account named for a harness that takes none changes nothing
    let id = r
        .create_session(NewSession {
            account: "work".into(),
            ..ns("o", "opencode")
        })
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert_eq!(acct(&id), "", "an account for a harness that takes none");
    // the app's, the web page's and jarvis-request's body names it as "account"
    let n: NewSession =
        serde_json::from_str(r#"{"label":"w","harness":"claude","account":"claude-work"}"#)
            .unwrap_or_default();
    let id = r.create_session(n).unwrap_or_else(|e| panic!("{e:#}"));
    assert_eq!(acct(&id), "claude-work");
    // every made session's approval is filed in the background: let them land before the temp dir goes
    wait_for("the approvals filed", || {
        r.st.read(|d| {
            let n = d
                .sessions
                .values()
                .filter(|s| s.state == "approval")
                .count();
            d.approvals.len() >= n
        })
    });
}
