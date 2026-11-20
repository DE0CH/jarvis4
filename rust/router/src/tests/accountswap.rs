//! router/accountswap_test.go and router/accountswap_paseo_test.go
use super::claudelogin::{ACCT1, FakeAnthropic, now_ms, own_router, pair_of};
use crate::accountswap::{
    SWAP_CHECK_WAIT_MS, SWAP_KILL_CMD, SWAP_LOGIN_WAIT_MS, SWAP_POLL_MS, SWAP_RC_WAIT_MS,
    SWAP_RESTART_WAIT_MS, SWAP_UP_WAIT_MS, call_does, signal_account_switch,
};
use crate::apicalls::CallRule;
use crate::autopilot::{DEFAULT_PILOT, Liveness, plan_tick};
use crate::claudelogin::{LoginHub, account_uuid};
use crate::ctx::Ctx;
use crate::inbox::RequestParams;
use crate::registry::{Registry, parse_registry};
use crate::router::Router;
use crate::testutil::*;
use jarvis_go::GoTime;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

const ACCT2: &str =
    r#"{"oauthAccount":{"accountUuid":"acct-2","emailAddress":"acct-2@example.com"}}"#;

/// claude-a (acct-1, the default) and claude-b (acct-2), both signed in; the expiries of their pairs
struct TwoAccounts {
    r: TestRouter,
    a: Arc<LoginHub>,
    exp_a: i64,
    exp_b: i64,
    _f: FakeAnthropic,
}

fn two_accounts() -> TwoAccounts {
    let f = FakeAnthropic::new();
    f.set(|s| {
        s.accounts.insert("b".into(), "acct-2".into());
    });
    let (r, a) = own_router();
    let b = r.accounts().add("b").unwrap_or_else(|e| panic!("{e:#}"));
    let now = now_ms();
    let (exp_a, exp_b) = (now + 3_600_000, now + 7_200_000);
    assert!(
        a.offer(&pair_of("a", exp_a), ACCT1, "seed", true, false)
            .unwrap_or(false)
    );
    assert!(
        b.offer(&pair_of("b", exp_b), ACCT2, "seed", true, false)
            .unwrap_or(false)
    );
    TwoAccounts {
        r,
        a,
        exp_a,
        exp_b,
        _f: f,
    }
}

fn set_reg(r: &Router, id: &str, f: impl Fn(&mut Registry)) {
    r.st.do_(|d| {
        if let Some(s) = d.sessions.get_mut(id) {
            let l = s.live.get_or_insert_with(Liveness::default);
            f(l.reg.get_or_insert_with(Registry::default));
            l.last_report = GoTime::now();
        }
    });
}

fn set_account(r: &Router, id: &str, account: &str, harness: Option<&str>) {
    r.st.do_(|d| {
        if let Some(s) = d.sessions.get_mut(id) {
            s.claude_account = account.into();
            if let Some(h) = harness {
                s.harness = h.into();
            }
        }
    });
}

/// short waits for the switch's phases, put back when dropped
struct ShortSwapWaits(Vec<(&'static AtomicU64, u64)>);

fn short_swap_waits() -> ShortSwapWaits {
    let all: [(&'static AtomicU64, u64); 6] = [
        (&SWAP_LOGIN_WAIT_MS, 3000),
        (&SWAP_RESTART_WAIT_MS, 300),
        (&SWAP_UP_WAIT_MS, 3000),
        (&SWAP_POLL_MS, 10),
        (&SWAP_CHECK_WAIT_MS, 3000),
        (&SWAP_RC_WAIT_MS, 3000),
    ];
    let saved = all
        .iter()
        .map(|(a, _)| (*a, a.load(Ordering::SeqCst)))
        .collect();
    for (a, v) in all {
        a.store(v, Ordering::SeqCst);
    }
    ShortSwapWaits(saved)
}

impl Drop for ShortSwapWaits {
    fn drop(&mut self) {
        for (a, v) in &self.0 {
            a.store(*v, Ordering::SeqCst);
        }
    }
}

fn phase(r: &Router, id: &str) -> Option<String> {
    r.ops
        .job_view(id)
        .and_then(|j| j["phase"].as_str().map(String::from))
}

fn job_error(r: &Router, id: &str) -> String {
    r.ops
        .job_view(id)
        .and_then(|j| j["error"].as_str().map(String::from))
        .unwrap_or_default()
}

/// a running session on an image from before the switch under a running claude (no __ACCOUNT__ in its status): the
/// account changes, the machine takes the new pair, and a host the machine doesn't restart by itself (not idle) is
/// restarted through the terminal holder; the conversation goes on
#[test]
fn account_switch_older_image() {
    let _s = serial();
    let t = two_accounts();
    let _w = short_swap_waits();
    let r = &t.r;
    add_session(r, "sA", "started", "mA", false);
    set_account(r, "sA", "claude-a", None);
    let exp_a = t.exp_a;
    set_reg(r, "sA", |g| {
        g.host_pid = 100;
        g.creds_expires_at = exp_a;
        g.bridge_session_id = "cse_1".into();
        g.status = "busy".into();
    });
    add_grant_kind(r, "sA", "terminal", "rule");
    let ex = answer_execs(r, "mA", 0);

    // errors first: an unknown account, the same account
    let (code, out) = app_do(
        r,
        "POST",
        "/api/sessions/sA/account",
        r#"{"account":"nope"}"#,
        &[],
    );
    assert_eq!(code, 400, "{out}");
    let (code, out) = app_do(
        r,
        "POST",
        "/api/sessions/sA/account",
        r#"{"account":"a"}"#,
        &[],
    );
    assert!(code == 200 && out["unchanged"] == true, "{code} {out}");

    let (code, out) = app_do(
        r,
        "POST",
        "/api/sessions/sA/account",
        r#"{"account":"claude-b"}"#,
        &[],
    );
    assert!(
        code == 202 && out["from"] == "claude-a" && out["to"] == "claude-b",
        "{code} {out}"
    );
    assert_eq!(
        r.st.read(|d| d.sessions.get("sA").map(|s| s.claude_account.clone())),
        Some("claude-b".into()),
        "the account didn't change"
    );
    assert_eq!(
        take_cmd(r, "mA").as_deref(),
        Some("claude-account"),
        "the machine wasn't told"
    );
    let (code, _) = app_do(
        r,
        "POST",
        "/api/sessions/sA/account",
        r#"{"account":"claude-a"}"#,
        &[],
    );
    assert_eq!(code, 409, "a second switch while the first runs");
    // the machine takes the new pair; nobody restarts the host: the router does, through the terminal holder
    let exp_b = t.exp_b;
    set_reg(r, "sA", |g| g.creds_expires_at = exp_b);
    wait_for("the host killed through the terminal holder", || {
        ex.cmds() == vec![SWAP_KILL_CMD]
    });
    assert_eq!(phase(r, "sA").as_deref(), Some("restarting Claude"));
    set_reg(r, "sA", |g| {
        g.host_pid = 200;
        g.status = "idle".into();
    });
    wait_for("the switch done", || {
        phase(r, "sA").as_deref() == Some("done")
    });
    assert!(r.ops.busy_of("sA").is_none(), "the session stayed locked");
}

/// an older image whose machine restarts the idle host by itself: no exec
#[test]
fn account_switch_older_image_restarts_itself() {
    let _s = serial();
    let t = two_accounts();
    let _w = short_swap_waits();
    SWAP_RESTART_WAIT_MS.store(3000, Ordering::SeqCst);
    let r = &t.r;
    add_session(r, "sA", "started", "mA", false);
    set_account(r, "sA", "claude-a", None);
    let exp_a = t.exp_a;
    set_reg(r, "sA", |g| {
        g.host_pid = 100;
        g.creds_expires_at = exp_a;
        g.bridge_session_id = "cse_1".into();
        g.status = "idle".into();
    });
    let ex = answer_execs(r, "mA", 0);
    let (code, out) = app_do(
        r,
        "POST",
        "/api/sessions/sA/account",
        r#"{"account":"b"}"#,
        &[],
    );
    assert_eq!(code, 202, "{out}");
    let exp_b = t.exp_b;
    set_reg(r, "sA", |g| {
        g.creds_expires_at = exp_b;
        g.host_pid = 300;
    });
    wait_for("the switch done", || {
        phase(r, "sA").as_deref() == Some("done")
    });
    assert!(
        ex.cmds().is_empty(),
        "an exec although the machine restarted the host: {:?}",
        ex.cmds()
    );
}

/// the machine never takes the pair: the job fails and says so
#[test]
fn account_switch_no_pair_fails() {
    let _s = serial();
    let t = two_accounts();
    let _w = short_swap_waits();
    SWAP_LOGIN_WAIT_MS.store(200, Ordering::SeqCst);
    let r = &t.r;
    add_session(r, "sA", "started", "mA", false);
    set_account(r, "sA", "claude-a", None);
    let exp_a = t.exp_a;
    set_reg(r, "sA", |g| {
        g.host_pid = 100;
        g.creds_expires_at = exp_a;
        g.status = "idle".into();
    });
    let (code, _) = app_do(
        r,
        "POST",
        "/api/sessions/sA/account",
        r#"{"account":"b"}"#,
        &[],
    );
    assert_eq!(code, 202);
    wait_for("failed", || phase(r, "sA").as_deref() == Some("failed"));
    let e = job_error(r, "sA");
    assert!(e.contains("didn't take claude-b's login"), "{e}");
}

/// a paused session: the next start takes the new account; with continue, "continue" goes in once its host is up and
/// idle
#[test]
fn account_switch_paused_continue_after_start() {
    let _s = serial();
    let t = two_accounts();
    let r = &t.r;
    add_session(r, "sP", "paused", "", false);
    set_account(r, "sP", "claude-a", None);
    let (code, out) = app_do(
        r,
        "POST",
        "/api/sessions/sP/account",
        r#"{"account":"b","continue":true}"#,
        &[],
    );
    assert!(
        code == 200 && out["nextStart"] == true && out["to"] == "claude-b",
        "{code} {out}"
    );
    let s =
        r.st.read(|d| d.sessions.get("sP").cloned().unwrap_or_default());
    assert!(
        s.claude_account == "claude-b" && s.ops.as_ref().is_some_and(|o| o.continue_after_start),
        "{} {:?}",
        s.claude_account,
        s.ops
    );
    // started again: nothing until its host is up and idle, then one "continue"
    let mut d = crate::state::Persisted::default();
    d.sessions.insert(
        "sP".into(),
        crate::state::Session {
            id: "sP".into(),
            machine_id: "m1".into(),
            state: "started".into(),
            harness: "claude".into(),
            live: Some(Liveness {
                reg: Some(Registry {
                    status: "busy".into(),
                    bridge_session_id: "cse_2".into(),
                    ..Default::default()
                }),
                last_report: GoTime::now(),
                host_up: "m1".into(),
                ..Default::default()
            }),
            ops: Some(crate::sessionops::SessionOps {
                continue_after_start: true,
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    let plan = |d: &mut crate::state::Persisted| {
        plan_tick(
            d,
            GoTime::now(),
            &BTreeMap::new(),
            &DEFAULT_PILOT,
            &|_| false,
            &|_, _| false,
        )
        .iter()
        .filter(|a| a.kind == "continue" && a.session == "sP")
        .count()
    };
    assert_eq!(plan(&mut d), 0, "continue into a busy host");
    if let Some(g) = d
        .sessions
        .get_mut("sP")
        .and_then(|s| s.live.as_mut())
        .and_then(|l| l.reg.as_mut())
    {
        g.status = "idle".into();
    }
    assert!(
        plan(&mut d) == 1 && plan(&mut d) == 0,
        "not exactly one continue"
    );
}

/// a machine's long poll held on its old account's hub returns at the switch with the new account's login
#[test]
fn account_switch_wakes_the_long_poll() {
    let _s = serial();
    let t = two_accounts();
    let r = t.r.r.clone();
    add_session(&r, "sA", "started", "mA", false);
    set_account(&r, "sA", "claude-a", None);
    let (tx, rx) = std::sync::mpsc::channel();
    let (r2, a, exp_a) = (r.clone(), t.a.clone(), t.exp_a);
    std::thread::spawn(move || {
        let (ans, _) = r2.poll_with_switch(
            &Ctx::background(),
            "mA",
            &a,
            exp_a,
            0,
            Duration::from_secs(30),
        );
        let _ = tx.send(ans);
    });
    std::thread::sleep(Duration::from_millis(100));
    set_account(&r, "sA", "claude-b", None);
    signal_account_switch();
    let ans = rx
        .recv_timeout(Duration::from_secs(5))
        .unwrap_or_else(|_| panic!("the poll held on the old account"));
    assert!(
        account_uuid(&ans.account) == "acct-2"
            && ans.expires_at == t.exp_b
            && !ans.credentials.is_empty(),
        "{ans:?}"
    );
}

/// the Inbox says what a requested switch does: which session, from which account to which
#[test]
fn account_switch_call_does() {
    let _s = serial();
    let t = two_accounts();
    let r = &t.r;
    add_session(r, "sA", "started", "mA", false);
    set_account(r, "sA", "claude-a", None);
    r.st.read(|d| {
        let got = call_does(
            d,
            &RequestParams {
                method: "POST".into(),
                path: "/api/sessions/sA/account".into(),
                body: r#"{"account":"b","continue":true}"#.into(),
                ..Default::default()
            },
        );
        assert!(
            got.contains("“label sA” (sA) from Claude account claude-a to claude-b")
                && got.contains("continue"),
            "{got}"
        );
        let other = call_does(
            d,
            &RequestParams {
                method: "POST".into(),
                path: "/api/sessions/sA/permission-mode".into(),
                ..Default::default()
            },
        );
        assert!(other.is_empty(), "does for another route");
    });
    let rule = r
        .call_route("POST", "/api/sessions/sA/account")
        .map(|(_, r)| r);
    assert!(
        matches!(rule, Ok(CallRule::Body)),
        "not requestable as an API call: {rule:?}"
    );
}

/// the switch under the running claude (images from 2026-10-20): the pair on disk, Anthropic's word on its account,
/// Remote Control back; no restart, no exec
#[test]
fn account_switch_transparent() {
    let _s = serial();
    let t = two_accounts();
    let _w = short_swap_waits();
    let r = &t.r;
    add_session(r, "sA", "started", "mA", false);
    set_account(r, "sA", "claude-a", None);
    let exp_a = t.exp_a;
    set_reg(r, "sA", |g| {
        g.host_pid = 100;
        g.creds_expires_at = exp_a;
        g.bridge_session_id = "cse_1".into();
        g.status = "idle".into();
        g.account_section = true;
        g.account_proof = "acct-1".into();
    });
    let ex = answer_execs(r, "mA", 0);
    let (code, out) = app_do(
        r,
        "POST",
        "/api/sessions/sA/account",
        r#"{"account":"b"}"#,
        &[],
    );
    assert_eq!(code, 202, "{out}");
    let exp_b = t.exp_b;
    set_reg(r, "sA", |g| g.creds_expires_at = exp_b);
    wait_for("checking the account", || {
        phase(r, "sA").as_deref() == Some("checking the account")
    });
    set_reg(r, "sA", |g| g.account_proof = "acct-2".into());
    wait_for("Remote Control", || {
        phase(r, "sA").as_deref() == Some("Remote Control")
    });
    set_reg(r, "sA", |g| g.bridge_session_id = "cse_2".into());
    wait_for("the switch done", || {
        phase(r, "sA").as_deref() == Some("done")
    });
    assert!(job_error(r, "sA").is_empty(), "{:?}", r.ops.job_view("sA"));
    assert!(
        ex.cmds().is_empty(),
        "an exec in a transparent switch: {:?}",
        ex.cmds()
    );
    let pid = r.st.read(|d| {
        d.sessions
            .get("sA")
            .and_then(|s| s.live.as_ref())
            .and_then(|l| l.reg.as_ref())
            .map(|g| g.host_pid)
    });
    assert_eq!(pid, Some(100), "the host was restarted");
}

/// Remote Control not coming back is said on the job, which still ends done; a token Anthropic names for another
/// account fails it
#[test]
fn account_switch_transparent_remote_control_and_proof() {
    let _s = serial();
    let t = two_accounts();
    let _w = short_swap_waits();
    SWAP_RC_WAIT_MS.store(200, Ordering::SeqCst);
    SWAP_CHECK_WAIT_MS.store(200, Ordering::SeqCst);
    let r = &t.r;
    add_session(r, "sA", "started", "mA", false);
    set_account(r, "sA", "claude-a", None);
    let exp_a = t.exp_a;
    set_reg(r, "sA", |g| {
        g.host_pid = 100;
        g.creds_expires_at = exp_a;
        g.bridge_session_id = "cse_1".into();
        g.status = "idle".into();
        g.account_section = true;
    });
    let _ = app_do(
        r,
        "POST",
        "/api/sessions/sA/account",
        r#"{"account":"b"}"#,
        &[],
    );
    let exp_b = t.exp_b;
    set_reg(r, "sA", |g| {
        g.creds_expires_at = exp_b;
        g.account_proof = "acct-2".into();
    });
    wait_for("done", || phase(r, "sA").as_deref() == Some("done"));
    let e = job_error(r, "sA");
    assert!(e.contains("/remote-control"), "{e}");
    // back to a, but the machine's proof stays b's: failed
    let _ = app_do(
        r,
        "POST",
        "/api/sessions/sA/account",
        r#"{"account":"a"}"#,
        &[],
    );
    set_reg(r, "sA", |g| g.creds_expires_at = exp_a);
    wait_for("failed", || phase(r, "sA").as_deref() == Some("failed"));
    let e = job_error(r, "sA");
    assert!(e.contains("didn't confirm"), "{e}");
}

/// the keeper's harness record (rust/machine/src/keeper.rs): parsed when the image sends it, none from an older image,
/// and the workers' section before it is unchanged
#[test]
fn registry_harness_section() {
    let base = "{\"pid\":7,\"sessionId\":\"s1\",\"bridgeSessionId\":\"cse_1\",\"status\":\"idle\",\"startedAt\":1}\n__TITLES__\n__BG__\n__ONESHOT__\n__AUTH__\n__CREDS__\n5\n__REFUSAL__\n";
    let w = "{\"workersOf\":\"s1\",\"subagents\":2,\"jobs\":{\"shell\":1},\"at\":3}\n";
    let g = parse_registry(&format!("{base}__WORKERS__\n{w}")).unwrap_or_default();
    assert!(
        g.harness.is_none() && g.workers.as_ref().is_some_and(|w| w.subagents == 2),
        "{g:?}"
    );
    let g = parse_registry(&format!(
        "{base}__WORKERS__\n{w}\n__HARNESS__\n{}\n",
        r#"{"starts":3,"running":true,"lastExit":"killed by SIGTERM","lastExitAt":"2026-10-21T23:30:57Z","lastUpSecs":42}"#
    ))
    .unwrap_or_default();
    let h = g.harness.clone().unwrap_or_default();
    assert!(
        h.starts == 3 && h.running && h.last_exit == "killed by SIGTERM" && h.last_up_secs == 42,
        "{h:?}"
    );
    assert!(
        g.workers
            .as_ref()
            .is_some_and(|w| w.subagents == 2 && w.jobs.get("shell") == Some(&1)),
        "workers {:?}",
        g.workers
    );
}

#[test]
fn registry_account_section() {
    let base = "{\"pid\":7,\"sessionId\":\"s1\",\"bridgeSessionId\":\"cse_1\",\"status\":\"idle\",\"startedAt\":1}\n__TITLES__\n__BG__\n__ONESHOT__\n__AUTH__\n__CREDS__\n5\n__REFUSAL__\n";
    let g = parse_registry(&format!("{base}__WORKERS__\n")).unwrap_or_default();
    assert!(
        !g.account_section && g.account_proof.is_empty() && g.host_pid == 7,
        "{g:?}"
    );
    let g = parse_registry(&format!(
        "{base}__ACCOUNT__\n{}\n__WORKERS__\n",
        r#"{"accountUuid":"acct-2","email":"x@example.com","at":1}"#
    ))
    .unwrap_or_default();
    assert!(
        g.account_section && g.account_proof == "acct-2" && g.creds_expires_at == 5,
        "{g:?}"
    );
    let g = parse_registry(&format!("{base}__ACCOUNT__\n\n__WORKERS__\n")).unwrap_or_default();
    assert!(g.account_section && g.account_proof.is_empty(), "{g:?}");
}

/// Claude Code · Paseo: a running session switches accounts with no restart. Once the machine reports the new pair on
/// disk and Anthropic's word on its account, the switch is done: no host restart and no Remote Control is waited for,
/// nothing is executed
#[test]
fn account_switch_proxy_harness_no_restart() {
    let _s = serial();
    let t = two_accounts();
    let _w = short_swap_waits();
    let r = &t.r;
    add_session(r, "sP", "started", "mP", false);
    set_account(r, "sP", "claude-a", Some("paseo-claude"));
    let exp_a = t.exp_a;
    set_reg(r, "sP", |g| {
        g.host_pid = 100;
        g.creds_expires_at = exp_a;
        g.bridge_session_id = "paseo:sP".into();
        g.status = "busy".into();
    });
    let ex = answer_execs(r, "mP", 0);
    let (code, out) = app_do(
        r,
        "POST",
        "/api/sessions/sP/account",
        r#"{"account":"claude-b"}"#,
        &[],
    );
    assert!(code == 202 && out["to"] == "claude-b", "{code} {out}");
    assert_eq!(
        take_cmd(r, "mP").as_deref(),
        Some("claude-account"),
        "the machine wasn't told"
    );
    wait_for("taking the login", || {
        phase(r, "sP").as_deref() == Some("taking the login")
    });
    let exp_b = t.exp_b;
    set_reg(r, "sP", |g| {
        g.creds_expires_at = exp_b;
        g.account_section = true;
    }); // same host pid: nothing restarted
    wait_for("checking the account", || {
        phase(r, "sP").as_deref() == Some("checking the account")
    });
    set_reg(r, "sP", |g| g.account_proof = "acct-2".into()); // the bridge stays "paseo:sP": no Remote Control phase
    wait_for("the switch done", || {
        phase(r, "sP").as_deref() == Some("done")
    });
    assert!(
        ex.cmds().is_empty(),
        "an exec for a proxy-login switch: {:?}",
        ex.cmds()
    );
    assert!(r.ops.busy_of("sP").is_none(), "the session stayed locked");
    r.st.read(|d| {
        assert_eq!(
            d.sessions.get("sP").map(|s| s.claude_account.as_str()),
            Some("claude-b"),
            "the account didn't change"
        );
        let got = call_does(
            d,
            &RequestParams {
                method: "POST".into(),
                path: "/api/sessions/sP/account".into(),
                body: r#"{"account":"a"}"#.into(),
                ..Default::default()
            },
        );
        assert!(got.contains("nothing restarts"), "{got}");
    });
}

/// the other non-claude harnesses are still refused while running
#[test]
fn account_switch_openclaw_still_refused() {
    let _s = serial();
    let t = two_accounts();
    let r = &t.r;
    add_session(r, "sO", "started", "mO", false);
    set_account(r, "sO", "claude-a", Some("openclaw"));
    let exp_a = t.exp_a;
    set_reg(r, "sO", |g| g.creds_expires_at = exp_a);
    let (code, out) = app_do(
        r,
        "POST",
        "/api/sessions/sO/account",
        r#"{"account":"claude-b"}"#,
        &[],
    );
    assert!(
        code != 202
            && out["error"]
                .as_str()
                .is_some_and(|e| e.contains("pause it")),
        "{code} {out}"
    );
}
