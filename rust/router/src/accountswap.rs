//! Switching a session's Claude account (Deyao, 2026-10-20: "I ran out of usage on the chendeyao.uk account; swap its
//! session to chendeyao000"). POST /api/sessions/{id}/account {account, continue}.
//!
//! Paused or failed: the account is changed on the session and its next start takes the new account's pair; with
//! `continue`, "continue" is typed into its chat once that start's Claude host is up and idle.
//!
//! Running (the claude harness): a background job shown as the session's `wake` ({kind: "account", phase}), holding the
//! session's lock. The switch is transparent: no restart, no --resume.
//!  1. switching            the session's account changes; every /m/claude-login long poll of the machine is woken
//!  2. taking the login     until the machine's status reports the new account's pair on disk (credsExpiresAt)
//!  3. checking the account until the status's __ACCOUNT__ names the new account
//!  4. Remote Control       Claude Code stops Remote Control when the account under it changes; the supervisor types
//!     /remote-control and chooses Enable: until the host reports a new Remote Control session
//!  5. delivering continue  with `continue`: "continue" into its chat as the canned delivery the login repair uses
//!
//! Claude Code · Paseo (proxy_login_harness) is switched the same way, minus step 4. A session image from before
//! 2026-10-20 (no __ACCOUNT__ in its status) restarts its host on the new account instead.

use crate::autopilot::Registry;
use crate::claudelogin::LoginHub;
use crate::ctx::Ctx;
use crate::http::Registrar;
use crate::inbox::{ApiCall, Origin, RequestParams};
use crate::nethttp::{Req, write_json};
use crate::router::{Router, bad};
use crate::sessionops::WakeJob;
use crate::state::{Persisted, Session};
use anyhow::{Result, anyhow};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// waits of the switch (ms; tests shorten them)
pub static SWAP_LOGIN_WAIT_MS: AtomicU64 = AtomicU64::new(120_000);
pub static SWAP_RESTART_WAIT_MS: AtomicU64 = AtomicU64::new(120_000);
pub static SWAP_UP_WAIT_MS: AtomicU64 = AtomicU64::new(180_000);
pub static SWAP_CHECK_WAIT_MS: AtomicU64 = AtomicU64::new(120_000);
pub static SWAP_RC_WAIT_MS: AtomicU64 = AtomicU64::new(300_000);
pub static SWAP_POLL_MS: AtomicU64 = AtomicU64::new(2_000);
pub const SWAP_KILL_CMD: &str = "tmux kill-session -t claude";

/// how long a switched session's harness may take to come up idle
pub fn swap_up_wait() -> Duration {
    ms(&SWAP_UP_WAIT_MS)
}

fn ms(a: &AtomicU64) -> Duration {
    Duration::from_millis(a.load(Ordering::Relaxed))
}

/// bumped whenever a session's account changes, so a machine's long poll held on its old account's hub returns and the
/// next one asks the new account's
static ACCT_SWITCH: (Mutex<u64>, Condvar) = (Mutex::new(0), Condvar::new());

pub fn account_switch_gen() -> u64 {
    ACCT_SWITCH.0.lock().map(|g| *g).unwrap_or(0)
}

pub fn signal_account_switch() {
    if let Ok(mut g) = ACCT_SWITCH.0.lock() {
        *g += 1;
    }
    ACCT_SWITCH.1.notify_all();
}

/// a ctx cancelled once any session's account changes after gen (the watcher ends with ctx)
fn cancel_on_switch(ctx: &Ctx, r#gen: u64) {
    let c = ctx.clone();
    std::thread::spawn(move || {
        let mut g = ACCT_SWITCH.0.lock().unwrap_or_else(|e| e.into_inner());
        while *g == r#gen && !c.cancelled() {
            g = ACCT_SWITCH
                .1
                .wait_timeout(g, Duration::from_secs(1))
                .map(|(g, _)| g)
                .unwrap_or_else(|e| e.into_inner().0);
        }
        if *g != r#gen {
            c.cancel();
        }
    });
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct AccountSwitchIn {
    pub account: String,
    #[serde(rename = "continue")]
    pub continue_: bool,
}

/// what the call does, as the Inbox shows it beside the caller (an API-call request's `does`)
pub fn account_switch_does(d: &Persisted, sid: &str, body: &str) -> String {
    let i: AccountSwitchIn = jarvis_go::unmarshal(body.as_bytes()).unwrap_or_default();
    let mut to = crate::claudeaccounts::account_store_name(&i.account);
    if to.is_empty() {
        to = i.account.clone();
    }
    let (mut from, mut title) = ("(none)".to_string(), sid.to_string());
    let s = d.sessions.get(sid);
    if let Some(s) = s {
        title = crate::titles::session_title(s);
        if !s.claude_account.is_empty() {
            from = s.claude_account.clone();
        }
    }
    let mut out = format!(
        "Switch session “{title}” ({sid}) from Claude account {from} to {to}: its Claude restarts on the same conversation"
    );
    if s.is_some_and(|s| crate::harness::proxy_login_harness(&s.harness)) {
        out = format!(
            "Switch session “{title}” ({sid}) from Claude account {from} to {to}: its next request goes out on the new account, nothing restarts"
        );
    }
    if i.continue_ {
        out.push_str(", then “continue” is typed into its chat");
    }
    out
}

/// a timeout of a wait of the switch
#[derive(Debug)]
pub struct SwapTimeout;

impl std::fmt::Display for SwapTimeout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("timed out")
    }
}

impl std::error::Error for SwapTimeout {}

pub fn or_none(s: &str) -> &str {
    if s.is_empty() { "(none)" } else { s }
}

impl Router {
    /// a machine's long poll on its account's hub, cut short when any session's account changes; then the
    /// session's account is looked up again and, when it changed, answered from the new account's hub at once
    pub fn poll_with_switch(
        &self,
        ctx: &Ctx,
        machine: &str,
        h: &Arc<LoginHub>,
        have: i64,
        ack: i64,
        wait: Duration,
    ) -> (crate::claudelogin::LoginAnswer, bool) {
        let c = ctx.child();
        cancel_on_switch(&c, account_switch_gen());
        let a = h.poll(&c, &format!("m:{machine}"), have, ack, wait);
        c.cancel();
        match self.machine_account(machine).1 {
            Some(now) if !Arc::ptr_eq(&now, h) => (
                now.poll(
                    &Ctx::background(),
                    &format!("m:{machine}"),
                    have,
                    0,
                    Duration::ZERO,
                ),
                true,
            ),
            None => (a, false),
            Some(_) => (a, true),
        }
    }

    /// the session's Claude account → store (see the file comment)
    pub fn switch_account(
        self: &Arc<Self>,
        req: &Req,
        id: &str,
        i: AccountSwitchIn,
    ) -> Result<Map<String, Value>> {
        let store = crate::claudeaccounts::account_store_name(&i.account);
        let Some(to) = (!store.is_empty())
            .then(|| self.accounts().hub(&store))
            .flatten()
        else {
            return Err(bad(format!(
                "no Claude account {:?} (Settings → Claude accounts lists them)",
                i.account
            )));
        };
        if to.current().credentials.is_empty() {
            return Err(bad(format!(
                "the Claude account {store} has no login: Re-login it in Settings → Claude accounts first"
            )));
        }
        let s: Session = self
            .st
            .do_(|d| d.sessions.get(id).cloned())
            .ok_or_else(crate::sessionapi::no_session)?;
        let harness = if s.harness.is_empty() {
            "claude".to_string()
        } else {
            s.harness.clone()
        };
        let takes = self
            .policy
            .harnesses
            .get(&harness)
            .is_some_and(|h| h.claude_account);
        if s.claude_account.is_empty() && !takes {
            return Err(bad(format!(
                "the session's harness ({harness}) takes no Claude account"
            )));
        }
        let from = s.claude_account.clone();
        let obj = |v: Value| v.as_object().cloned().unwrap_or_default();
        if from == store {
            return Ok(obj(
                json!({"ok": true, "unchanged": true, "account": store}),
            ));
        }
        let set_account = || {
            self.st.do_(|d| {
                if let Some(x) = d.sessions.get_mut(id) {
                    x.claude_account = store.clone();
                }
            });
            signal_account_switch();
            crate::logf!(
                "[account] {id}: Claude account {} → {store}",
                or_none(&from)
            );
        };
        let stores = s.stores.clone().unwrap_or_default();
        let in_cert = *crate::claudestores::CLAUDE_STORE_IN_CERT;
        if s.machine_id.is_empty() {
            if s.state != "paused" && s.state != "failed" {
                return Err(anyhow!(
                    "session is {}: switch its account once it is running, paused or failed",
                    s.state
                ));
            }
            if in_cert && !stores.contains(&store) {
                return Err(bad(format!(
                    "this session's cert names its Claude account's store: resume it first, then switch (the switch adds {store} to its cert)"
                )));
            }
            set_account();
            self.st.do_(|d| {
                if let Some(x) = d.sessions.get_mut(id) {
                    x.ops
                        .get_or_insert_with(Default::default)
                        .continue_after_start = i.continue_;
                }
            });
            return Ok(obj(
                json!({"ok": true, "nextStart": true, "from": crate::http::null_if_empty(&from), "to": store, "continue": i.continue_}),
            ));
        }
        if harness != "claude" && !crate::harness::proxy_login_harness(&harness) {
            return Err(anyhow!(
                "session is running the {harness} harness: pause it, switch its account, then resume it"
            ));
        }
        if s.state != "started" {
            return Err(anyhow!(
                "session is {}: switch its account once it is running, paused or failed",
                s.state
            ));
        }
        let unlock = self.lock_args(
            id,
            "account",
            json!({"store": store, "harness": harness, "continue": i.continue_}),
        )?;
        let j = self.ops.start_job(id, "account")?;
        let mut out = obj(
            json!({"started": true, "kind": "account", "from": crate::http::null_if_empty(&from), "to": store}),
        );
        if in_cert && !stores.contains(&store) {
            let o = Origin {
                caller: crate::inbox::app_caller(req),
                call: ApiCall {
                    method: req.method.clone(),
                    path: req.path.clone(),
                    args: obj(json!({"account": store})),
                },
                via_call: crate::apicalls::via_call(req),
                ..Default::default()
            };
            let why = format!(
                "Session “{}” ({id}) now uses the Claude account {store}: its cert names the account's store, so this adds {store} to it.",
                crate::titles::session_title(&s)
            );
            match self.add_store_approval(&s.machine_id, &store, o, &why, "") {
                Err(e) => crate::logf!(
                    "[account] {id}: the add-store of {store}: {e:#} (the switch goes on: the login travels over the long poll)"
                ),
                Ok(aid) => {
                    out.insert("addStore".into(), json!(aid));
                }
            }
        }
        let before = self.live_reg(id, &s.machine_id).0.unwrap_or_default(); // what runs now
        set_account();
        self.send(&s.machine_id, "claude-account"); // rust/machine/src/supervisor.rs
        let r = self.clone();
        let (id, machine) = (id.to_string(), s.machine_id.clone());
        std::thread::spawn(move || {
            let _u = crate::flows::scopeguard(move || unlock.call());
            match r.run_account_switch(&j, &id, &machine, &harness, before, &to, i.continue_) {
                Err(e) => {
                    crate::logf!("[account] {id}: {e:#}");
                    r.ops.phase(&j, "failed", Some(&e));
                }
                Ok(()) => {
                    crate::logf!("[account] {id}: now on {}", to.store);
                    r.ops.phase(&j, "done", None);
                }
            }
        });
        Ok(out)
    }

    /// the machine's latest status, while it is still the session's machine
    pub fn live_reg(&self, id: &str, machine: &str) -> (Option<Registry>, bool) {
        self.st.do_(|d| match d.sessions.get(id) {
            Some(s) if s.machine_id == machine && s.state == "started" => {
                (s.live.as_ref().and_then(|l| l.reg.clone()), true)
            }
            _ => (None, false),
        })
    }

    /// polls the machine's status until cond holds; an error when the machine stopped being the session's
    pub fn wait_reg(
        &self,
        id: &str,
        machine: &str,
        d: Duration,
        cond: impl Fn(&Registry) -> bool,
    ) -> Result<Registry> {
        let end = Instant::now() + d;
        loop {
            let (g, ok) = self.live_reg(id, machine);
            if !ok {
                return Err(anyhow!("the session's machine went away"));
            }
            if let Some(g) = &g
                && cond(g)
            {
                return Ok(g.clone());
            }
            if Instant::now() > end {
                return Err(SwapTimeout.into());
            }
            std::thread::sleep(ms(&SWAP_POLL_MS));
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn run_account_switch(
        self: &Arc<Self>,
        j: &WakeJob,
        id: &str,
        machine: &str,
        harness: &str,
        mut before: Registry,
        to: &Arc<LoginHub>,
        cont: bool,
    ) -> Result<()> {
        self.ops.phase(j, "switching", None);
        if before.host_pid == 0 {
            // no status since this router started: the next report says what runs now
            if let Ok(g) = self.wait_reg(id, machine, ms(&SWAP_LOGIN_WAIT_MS), |g| g.host_pid != 0)
            {
                before = g;
            }
        }
        let want = crate::claudelogin::account_uuid(&to.current().account);
        self.ops.phase(j, "taking the login", None);
        let g = self
            .wait_reg(id, machine, ms(&SWAP_LOGIN_WAIT_MS), |g| {
                let exp = to.current().expires_at;
                exp > 0 && g.creds_expires_at == exp
            })
            .map_err(|e| anyhow!("the machine didn't take {}'s login: {e:#}", to.store))?;
        crate::logf!("[account] {id}: the machine took {}'s login", to.store);
        if g.account_section {
            self.ops.phase(j, "checking the account", None);
            self.wait_reg(id, machine, ms(&SWAP_CHECK_WAIT_MS), |g| {
                !want.is_empty() && g.account_proof == want
            })
            .map_err(|e| {
                anyhow!(
                    "the machine didn't confirm {}'s token with Anthropic: {e:#}",
                    to.store
                )
            })?;
            crate::logf!(
                "[account] {id}: the installed token is {}'s (Anthropic's profile, asked by the machine)",
                to.store
            );
            if !before.bridge_session_id.is_empty() && !crate::harness::proxy_login_harness(harness)
            {
                self.ops.phase(j, "Remote Control", None);
                let bid = before.bridge_session_id.clone();
                let rc = ms(&SWAP_RC_WAIT_MS);
                match self.wait_reg(id, machine, rc, |g| {
                    !g.bridge_session_id.is_empty() && g.bridge_session_id != bid
                }) {
                    Err(_) => {
                        let w = jarvis_go::fmt::duration_string(rc);
                        self.ops.note(j, &format!("Remote Control didn't come back within {w}: type /remote-control in the session's terminal"));
                        crate::logf!("[account] {id}: Remote Control didn't come back within {w}");
                    }
                    Ok(_) => crate::logf!(
                        "[account] {id}: Remote Control is up again under {}",
                        to.store
                    ),
                }
            }
        } else {
            self.restart_old_image_host(j, id, machine, before.host_pid, to, cont)?;
        }
        if !cont {
            return Ok(());
        }
        self.ops.phase(j, "delivering continue", None);
        self.deliver_canned(
            id,
            crate::vouch::Delivery {
                kind: "continue".into(),
                ..Default::default()
            },
            "continue",
        )
        .map_err(|e| anyhow!("delivering \"continue\": {e:#}"))?;
        crate::logf!("[account] {id}: \"continue\" delivered");
        Ok(())
    }

    /// a session image from before the switch under a running claude restarts its host on the new account: by itself
    /// once idle, else through the terminal holder
    fn restart_old_image_host(
        self: &Arc<Self>,
        j: &WakeJob,
        id: &str,
        machine: &str,
        old_pid: i64,
        to: &Arc<LoginHub>,
        cont: bool,
    ) -> Result<()> {
        self.ops.phase(j, "restarting Claude", None);
        let restarted = |g: &Registry| g.host_pid != 0 && g.host_pid != old_pid;
        match self.wait_reg(id, machine, ms(&SWAP_RESTART_WAIT_MS), restarted) {
            Err(e) if e.downcast_ref::<SwapTimeout>().is_some() => {
                crate::logf!(
                    "[account] {id}: an older image's host wasn't restarted within {}: restarting it through the terminal holder",
                    jarvis_go::fmt::duration_string(ms(&SWAP_RESTART_WAIT_MS))
                );
                let res = self
                    .exec_as(id, "terminal", SWAP_KILL_CMD, Duration::from_secs(30))
                    .and_then(|res| {
                        if res.code != 0 && !res.stderr.contains("can't find session") {
                            Err(anyhow!(
                                "exited {}: {}",
                                res.code,
                                jarvis_go::fmt::clip(&format!("{}{}", res.stderr, res.stdout), 200)
                            ))
                        } else {
                            Ok(())
                        }
                    });
                res.map_err(|e| anyhow!("restarting Claude (holder terminal): {e:#}"))?;
            }
            Err(e) => return Err(anyhow!("restarting Claude: {e:#}")),
            Ok(_) => {}
        }
        self.wait_reg(id, machine, ms(&SWAP_UP_WAIT_MS), |g| {
            restarted(g) && !g.bridge_session_id.is_empty() && (!cont || g.status == "idle")
        })
        .map_err(|e| anyhow!("Claude didn't come back up under {}: {e:#}", to.store))?;
        crate::logf!("[account] {id}: Claude is back up under {}", to.store);
        Ok(())
    }
}

pub fn register_account_switch(reg: &mut Registrar) {
    reg.app("POST /api/sessions/{id}/account", |r, w, req| {
        let b = req.read_body(1 << 16);
        let i: AccountSwitchIn = if b.is_empty() {
            Default::default()
        } else {
            match jarvis_go::unmarshal(&b) {
                Ok(i) => i,
                Err(e) => {
                    crate::http::write_err(w, &anyhow!("bad JSON: {e}"));
                    return;
                }
            }
        };
        match r.switch_account(req, &req.path_value("id"), i) {
            Err(e) => crate::schedule::schedule_err(w, &e),
            Ok(out) => {
                let code = if out.get("started") == Some(&json!(true)) {
                    202
                } else {
                    200
                };
                write_json(w, code, &out);
            }
        }
    });
}

/// an API-call request's effect in words, for the routes whose path and body alone don't say it plainly; "" for the
/// rest
pub fn call_does(d: &Persisted, p: &RequestParams) -> String {
    if p.method != "POST" {
        return String::new();
    }
    let path = p.path.split_once('?').map_or(p.path.as_str(), |(a, _)| a);
    if let Some(rest) = path.strip_prefix("/api/sessions/")
        && let Some(sid) = rest.strip_suffix("/account")
        && !sid.is_empty()
        && !sid.contains('/')
    {
        return account_switch_does(d, sid, &p.body);
    }
    String::new()
}
