//! The Claude login: the OAuth pair of the session's Claude account, kept and refreshed by the router
//! (router/claudelogin.go, claudeaccounts.go: one account per session). A session with an account takes the pair at
//! boot over the signed /m channel and keeps in step for the machine's life (creds_sync): a long poll that answers with
//! a newer pair, or with "a refresh is coming": then creds_sync takes the CLI's own refresh lock
//! (~/.claude/.oauth_refresh.lock, lessons/74) until the new pair is written, so a claude process that gets a 401 in
//! between waits and adopts it instead of burning its refresh token.
//!
//! The router's pair is taken whatever its account (DECISIONS 116, 185, 202: trust the router). When it belongs to
//! another account than the one on this machine, the switch happens UNDER the running claude (switch_in_place): under
//! the CLI's refresh lock the new pair replaces ~/.claude/.credentials.json and the account record replaces
//! ~/.claude.json's oauthAccount, both atomically; Claude Code's next request goes out on the new account. Then
//! (after_switch): the installed token's account is checked with Anthropic's profile endpoint and reported in the
//! status (__ACCOUNT__), and Remote Control is started again.

use crate::client::Client;
use crate::session::session_command;
use crate::{gojson, logf, paths, util};
use anyhow::{Result, anyhow, bail};
use serde::Deserialize;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const CREDS_POLL_WAIT: Duration = Duration::from_secs(50);
const CREDS_RETRY: Duration = Duration::from_secs(10);
/// a lock held for a refresh that never answered is released (the CLI's own stale limit is 60 s)
const LOCK_HOLD_MAX: Duration = Duration::from_secs(45);
const SWITCH_LOCK_WAIT: Duration = Duration::from_secs(15);
const SWITCH_POLL: Duration = Duration::from_secs(1);
/// a profile fetch claude began with the old token may write the old record back
const RECHECK_AFTER: Duration = Duration::from_secs(15);
/// for Claude Code to stop Remote Control once the account under it changed
const RC_DROP_WAIT: Duration = Duration::from_secs(90);
/// for the /remote-control menu (a host in a turn shows it after the turn)
const RC_MENU_WAIT: Duration = Duration::from_secs(180);
pub const RC_UP_WAIT: Duration = Duration::from_secs(90);
const PROFILE_TRIES: u32 = 5;
const OAUTH_PROFILE_URL: &str = "https://api.anthropic.com/api/oauth/profile";
/// Claude Code's notice when it stops Remote Control for it
const RC_CHANGED_TEXT: &str = "account or organization changed";
/// the /remote-control menu's first choice (claude 2.1.304)
pub const RC_ENABLE_TEXT: &str = "Enable Remote Control";

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct RouterLogin {
    pub credentials: String,
    pub account: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: i64,
    #[serde(rename = "gen")]
    pub generation: i64,
    pub preparing: bool,
}

pub fn creds_path() -> PathBuf {
    paths::home().join(".claude").join(".credentials.json")
}

fn oauth_field(raw: &[u8], k: &str) -> Option<serde_json::Value> {
    let v: serde_json::Value = serde_json::from_slice(raw).ok()?;
    v.get("claudeAiOauth")?.get(k).cloned()
}

pub fn expires_at(raw: &[u8]) -> i64 {
    oauth_field(raw, "expiresAt")
        .and_then(|v| v.as_i64())
        .unwrap_or(0)
}

/// the pair carries its refresh token (only a pair this machine's claude got by itself does)
pub fn has_refresh_token(raw: &[u8]) -> bool {
    oauth_field(raw, "refreshToken")
        .and_then(|v| v.as_str().map(|s| !s.is_empty()))
        .unwrap_or(false)
}

pub fn access_token(raw: &[u8]) -> String {
    oauth_field(raw, "accessToken")
        .and_then(|v| v.as_str().map(String::from))
        .unwrap_or_default()
}

fn account_field(account: &str, k: &str) -> String {
    serde_json::from_str::<serde_json::Value>(account)
        .ok()
        .and_then(|v| v.get("oauthAccount")?.get(k)?.as_str().map(String::from))
        .unwrap_or_default()
}

pub fn record_account(account: &str) -> String {
    account_field(account, "accountUuid")
}

/// the account of the login on this machine (~/.claude.json's); "" = not known
pub fn local_account() -> String {
    record_account(&std::fs::read_to_string(paths::home().join(".claude.json")).unwrap_or_default())
}

/// write the router's pair; one for another account than this machine's always wins, and is switched to under the
/// running claude (switch_in_place) → (took, switched)
pub fn take_router_pair(l: &RouterLogin) -> Result<(bool, bool)> {
    let (ra, la) = (record_account(&l.account), local_account());
    if ra.is_empty() || la.is_empty() || ra == la {
        return Ok((take_if_later(l.credentials.as_bytes())?, false));
    }
    switch_in_place(l)?;
    Ok((true, true))
}

/// the router says this session has no Claude account (404; 403 from a router before accounts)
#[derive(Debug, thiserror::Error)]
#[error("this session has no Claude account")]
pub struct NoAccount;

pub fn is_no_account(e: &anyhow::Error) -> bool {
    e.downcast_ref::<NoAccount>().is_some()
}

/// one poll; the path is signed as every /m call, the query (numbers only) travels beside it
pub fn fetch_login(c: &Client, have: i64, ack: i64, wait: Duration) -> Result<RouterLogin> {
    let q = format!("have={have}&ack={ack}&wait={}", wait.as_secs());
    let mut c = c.clone();
    if wait > Duration::ZERO {
        c.timeout = Some(wait + Duration::from_secs(60));
    }
    let r = c.signed_do("GET", "/m/claude-login", "/m/claude-login", &q, b"", "")?;
    if r.status == 404 || r.status == 403 {
        return Err(NoAccount.into());
    }
    if r.status != 200 {
        bail!("GET /m/claude-login: HTTP {}", r.status);
    }
    Ok(gojson::unmarshal(&r.body)?)
}

/// A session's first Claude login, at boot, before the harness starts (Deyao, 2026-10-11: a new session logs in by
/// itself, no grant, no Face ID). Returns the account record for CLAUDE_ACCOUNT, "" when there is none.
pub fn session_claude_login(c: &Client) -> String {
    let mut res = Err(anyhow!("no try"));
    for _ in 0..3 {
        // a short retry: the harness starts right after, logged in or not (creds_sync catches up)
        res = fetch_login(c, 0, 0, Duration::ZERO).and_then(|l| {
            if l.credentials.is_empty() {
                bail!("the router holds no Claude login for this session's account")
            }
            Ok(l)
        });
        match &res {
            Ok(_) => break,
            Err(e) if is_no_account(e) => break,
            Err(_) => util::sleep(Duration::from_secs(2)),
        }
    }
    let l = match res {
        Err(e) if is_no_account(&e) => {
            logf!("claude login: none (the session has no Claude account)");
            return String::new();
        }
        Err(e) => {
            logf!("claude login: at boot: {e:#} (credsSync keeps trying)");
            start_creds_sync();
            return String::new();
        }
        Ok(l) => l,
    };
    // the host hasn't started: its ~/.claude.json takes the account now (the entrypoint merges CLAUDE_ACCOUNT too)
    let ra = record_account(&l.account);
    if !ra.is_empty()
        && ra != local_account()
        && let Err(e) = merge_account(&l.account)
    {
        logf!("claude login: ~/.claude.json: {e:#}");
    }
    match take_if_later(l.credentials.as_bytes()) {
        Err(e) => logf!("claude login: writing the credentials file: {e:#}"),
        Ok(true) => logf!("claude login: took the router's pair at boot"),
        Ok(false) => logf!("claude login: the pair here expires as late or later; kept"),
    }
    start_creds_sync();
    l.account
}

/// the account record's keys (oauthAccount, userID) into ~/.claude.json, the rest kept
pub fn merge_account(account: &str) -> Result<()> {
    let rec: serde_json::Map<String, serde_json::Value> = serde_json::from_str(account)?;
    let p = paths::home().join(".claude.json");
    let mut cur: serde_json::Map<String, serde_json::Value> = std::fs::read(&p)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    cur.extend(rec);
    write_atomic(&p, gojson::marshal(&cur).as_bytes())
}

/// tests replace the marker's effect
pub static TEST_NO_SYNC: AtomicBool = AtomicBool::new(false);

/// tells supervisor-normal to run creds_sync for the machine's life: boot (or an account switch) leaves the marker,
/// supervisor-normal starts it once booted
pub fn start_creds_sync() {
    if TEST_NO_SYNC.load(Ordering::SeqCst) {
        return;
    }
    if let Err(e) = util::write_file(&paths::claude_login_on(), b"1", 0o644) {
        logf!("claude login: {e}");
        return;
    }
    logf!("claude login: the supervisor keeps the pair in step (long poll on the router)");
}

static CREDS_SYNC_ON: AtomicBool = AtomicBool::new(false);

/// creds_sync as soon as boot leaves the marker. Boot writes it after booted (its login fetch takes seconds), so it is
/// watched for the machine's life, not looked at once when booted (YYC AI on Jarvis 3, 2026-10-20). A session with no
/// account never gets the marker: a stat every 2 s.
pub fn start_creds_sync_on_marker() {
    while !CREDS_SYNC_ON.load(Ordering::SeqCst) {
        if paths::claude_login_on().exists() {
            std::thread::spawn(creds_sync);
            return;
        }
        util::sleep(Duration::from_secs(2));
    }
}

/// 0600, through a rename
pub fn write_atomic(path: &std::path::Path, b: &[u8]) -> Result<()> {
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d)?;
    }
    let tmp = PathBuf::from(format!("{}.new", path.display()));
    util::write_file(&tmp, b, 0o600)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// write the pair unless the file here already expires as late or later; atomic, 0600
pub fn take_if_later(creds: &[u8]) -> Result<bool> {
    let ne = expires_at(creds);
    if ne == 0 {
        bail!("the pair has no expiresAt");
    }
    if let Ok(cur) = std::fs::read(creds_path())
        && expires_at(&cur) >= ne
    {
        return Ok(false);
    }
    write_atomic(&creds_path(), creds)?;
    Ok(true)
}

// ---- the CLI's refresh lock (Jarvis 1's LOCK_PY / UNLOCK_PY) ------------------------------------------------------

fn creds_dir() -> PathBuf {
    creds_path()
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_default()
}

pub fn lock_dir() -> PathBuf {
    creds_dir().join(".oauth_refresh.lock")
}

fn lock_mark() -> PathBuf {
    creds_dir().join(".jarvis-refresh-lock")
}

#[derive(serde::Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(default)]
struct LockMarker {
    ino: u64,
    mtime: i64,
}

fn lock_id(md: &std::fs::Metadata) -> LockMarker {
    LockMarker {
        ino: md.ino(),
        mtime: md.mtime() * 1_000_000_000 + md.mtime_nsec(),
    }
}

/// removes the lock only while it is still the one this machine made (a lock the CLI re-took after ours went stale has
/// another inode or mtime)
pub fn release_lock() {
    let Ok(b) = std::fs::read(lock_mark()) else {
        return;
    };
    let m: LockMarker = gojson::unmarshal(&b).unwrap_or_default();
    if let Ok(md) = std::fs::metadata(lock_dir())
        && lock_id(&md) == m
    {
        let _ = std::fs::remove_dir(lock_dir());
    }
    let _ = std::fs::remove_file(lock_mark());
}

/// "locked", or "busy" (a claude process is refreshing right now)
pub fn take_lock() -> &'static str {
    release_lock(); // one left from an earlier run that never got its pair
    let _ = std::fs::create_dir_all(creds_dir());
    use std::os::unix::fs::DirBuilderExt;
    if std::fs::DirBuilder::new()
        .mode(0o700)
        .create(lock_dir())
        .is_err()
    {
        return "busy";
    }
    let Ok(md) = std::fs::metadata(lock_dir()) else {
        return "busy";
    };
    let _ = util::write_file(
        &lock_mark(),
        gojson::marshal(&lock_id(&md)).as_bytes(),
        0o600,
    );
    "locked"
}

// ---- creds_sync ------------------------------------------------------------------------------------------------------

/// the machine's side of the router's login protocol, for the machine's life
pub fn creds_sync() {
    if CREDS_SYNC_ON.swap(true, Ordering::SeqCst) {
        return;
    }
    let c = match Client::new() {
        Ok(c) => c,
        Err(e) => {
            logf!("claude login: credsSync can't run: {e:#}");
            return;
        }
    };
    let mut s = Syncer {
        c,
        pushed: vec![],
        router_acc: String::new(),
        lock_gen: 0,
        locked_at: None,
    };
    loop {
        if let Err(e) = s.step() {
            logf!("claude login: {e:#}");
            util::sleep(CREDS_RETRY);
        }
    }
}

pub struct Syncer {
    pub c: Client,
    /// the content last pushed or taken
    pub pushed: Vec<u8>,
    /// the account of the router's login, from its last answer
    pub router_acc: String,
    /// the router's refresh this machine holds the CLI lock for (0: none)
    pub lock_gen: i64,
    pub locked_at: Option<Instant>,
}

impl Syncer {
    fn release(&mut self) {
        if self.lock_gen != 0 {
            release_lock();
            self.lock_gen = 0;
        }
    }

    /// push this machine's own newer pair (its claude refreshed by itself), then one long poll and its answer
    pub fn step(&mut self) -> Result<()> {
        let local = std::fs::read(creds_path()).unwrap_or_default();
        if self.lock_gen != 0 && self.locked_at.is_some_and(|t| t.elapsed() > LOCK_HOLD_MAX) {
            logf!("claude login: no pair 45s after the refresh notice: lock released");
            self.release();
        }
        // a pair with no refresh token is the router's own: this machine's claude can't have refreshed it, so there is
        // nothing to push
        if !local.is_empty()
            && local != self.pushed
            && self.lock_gen == 0
            && has_refresh_token(&local)
        {
            let body = serde_json::json!({"credentials": String::from_utf8_lossy(&local)});
            if let Err(e) = self.c.json_ok("POST", "/m/claude-login", Some(&body)) {
                logf!("claude login: push: {e:#}");
            }
            self.pushed = local.clone();
        }
        let mut have = expires_at(&local);
        let la = local_account();
        if !self.router_acc.is_empty() && !la.is_empty() && self.router_acc != la {
            have = 0; // the router holds another account's login: asked for whatever its expiry
        }
        let l = fetch_login(&self.c, have, self.lock_gen, CREDS_POLL_WAIT)
            .map_err(|e| anyhow!("poll: {e:#}"))?;
        self.router_acc = record_account(&l.account);
        if !l.credentials.is_empty() && l.expires_at > have {
            let r = take_router_pair(&l);
            self.release(); // after the write: a claude process waiting on the lock re-reads the file and adopts the pair
            let (took, switched) = r.map_err(|e| anyhow!("writing the credentials file: {e:#}"))?;
            if took {
                self.pushed = l.credentials.clone().into_bytes();
                logf!("claude login: took the router's newer pair");
            }
            if switched {
                let c = self.c.clone();
                std::thread::spawn(move || after_switch(&l, &c)); // the account check and Remote Control
            }
        } else if l.preparing && l.generation != self.lock_gen {
            self.release();
            // locked, or a claude process is refreshing right now: acknowledge anyway so the router doesn't wait for us
            let _ = take_lock();
            self.lock_gen = l.generation;
            self.locked_at = Some(Instant::now());
        } else if !l.preparing && self.lock_gen != 0 {
            self.release(); // the refresh is over (failed): the pair here stays
        }
        Ok(())
    }
}

// ---- an account switch, under the running claude ---------------------------------------------------------------------

/// the account of the installed token as Anthropic's profile endpoint names it, written once checked; the status reports
/// it (__ACCOUNT__), which is how the router knows the switch took
pub fn account_proof() -> PathBuf {
    creds_dir().join(".jarvis-account")
}

/// the new account's pair and record, under the CLI's refresh lock so no refresh of the old account is cut in half
pub fn switch_in_place(l: &RouterLogin) -> Result<()> {
    let end = Instant::now() + SWITCH_LOCK_WAIT;
    let mut locked = false;
    loop {
        if take_lock() == "locked" {
            locked = true;
            break;
        }
        if Instant::now() > end {
            break;
        }
        util::sleep(Duration::from_millis(200));
    }
    if !locked {
        logf!("claude login: the CLI's refresh lock stayed taken for 15s: switching anyway");
    }
    let r = (|| {
        let _ = std::fs::remove_file(account_proof()); // the old account's
        write_atomic(&creds_path(), l.credentials.as_bytes())?;
        merge_account(&l.account).map_err(|e| anyhow!("~/.claude.json: {e:#}"))?;
        logf!(
            "claude login: switched to the Claude account {} under the running claude (credentials and oauthAccount; its next request goes out on it)",
            record_email(&l.account)
        );
        Ok(())
    })();
    if locked {
        release_lock();
    }
    r
}

pub fn record_email(account: &str) -> String {
    let e = account_field(account, "emailAddress");
    if e.is_empty() {
        record_account(account)
    } else {
        e
    }
}

/// the installed token's account checked with Anthropic, the record kept, Remote Control back
pub fn after_switch(l: &RouterLogin, _c: &Client) {
    let want = record_account(&l.account);
    let old_bridge = live_bridge();
    let mut checked = false;
    for _ in 0..PROFILE_TRIES {
        if checked {
            break;
        }
        match profile_of(&access_token(l.credentials.as_bytes())) {
            Err(e) => {
                logf!("claude login: checking the installed token's account: {e:#}");
                util::sleep(Duration::from_secs(5));
            }
            Ok((uuid, email)) if uuid != want => {
                logf!(
                    "claude login: the installed token belongs to {email}, not the account the router named"
                );
                return;
            }
            Ok((uuid, email)) => {
                let b = serde_json::json!({"accountUuid": uuid, "email": email, "at": util::unix_now()});
                if let Err(e) = write_atomic(&account_proof(), gojson::marshal(&b).as_bytes()) {
                    logf!("claude login: {e:#}");
                }
                logf!("claude login: the installed token is {email}'s (Anthropic's profile)");
                checked = true;
            }
        }
    }
    util::sleep(RECHECK_AFTER);
    if local_account() != want {
        match merge_account(&l.account) {
            Err(e) => logf!("claude login: ~/.claude.json: {e:#}"),
            Ok(()) => logf!(
                "claude login: ~/.claude.json had the old account again (claude's own profile fetch): set again"
            ),
        }
    }
    if crate::harnesses::proxy_login(&crate::harnesses::cert_harness()) {
        logf!(
            "claude login: the harness's API proxy sends the new account's login from its next request (no Remote Control here)"
        );
        return;
    }
    enable_remote_control(&old_bridge);
}

/// the account Anthropic's profile endpoint names for a token → (uuid, email)
pub fn profile_of(token: &str) -> Result<(String, String)> {
    let auth = format!("Bearer {token}");
    let (st, b) = crate::https::get(
        OAUTH_PROFILE_URL,
        &[
            ("Authorization", &auth),
            ("anthropic-beta", "oauth-2025-04-20"),
            ("User-Agent", "jarvis-machine/1"),
        ],
        Duration::from_secs(20),
        1 << 20,
    )?;
    if st != 200 {
        bail!("profile: HTTP {st}");
    }
    let v: serde_json::Value =
        serde_json::from_slice(&b).map_err(|_| anyhow!("profile: no account in the answer"))?;
    let uuid = v
        .get("account")
        .and_then(|a| a.get("uuid"))
        .and_then(|x| x.as_str())
        .unwrap_or("");
    let email = v
        .get("account")
        .and_then(|a| a.get("email"))
        .and_then(|x| x.as_str())
        .unwrap_or("");
    if uuid.is_empty() {
        bail!("profile: no account in the answer");
    }
    Ok((uuid.into(), email.into()))
}

/// tmux's pane of the Claude host
pub fn pane_text() -> String {
    session_command("tmux", &["capture-pane", "-p", "-t", "claude"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

/// keys into the Claude host's pane
pub fn send_keys(args: &[&str]) -> Result<()> {
    let mut a = vec!["send-keys", "-t", "claude"];
    a.extend_from_slice(args);
    let st = session_command("tmux", &a).status()?;
    if !st.success() {
        bail!("tmux send-keys: {st}");
    }
    Ok(())
}

/// one typist into the host at a time (the Remote Control watch, an account switch)
pub static RC_TYPING: Mutex<()> = Mutex::new(());

/// Claude Code stops Remote Control when the account under it changes; typing /remote-control and choosing "Enable
/// Remote Control" starts it again for the new account. Nothing to do when there was none before the switch.
pub fn enable_remote_control(old_bridge: &str) {
    if old_bridge.is_empty() {
        logf!("claude login: no Remote Control before the switch: nothing to bring back");
        return;
    }
    if !wait_until(RC_DROP_WAIT, || {
        pane_text().contains(RC_CHANGED_TEXT) || live_bridge() != old_bridge
    }) {
        logf!("claude login: Remote Control is still up 1m30s after the switch: left as it is");
        return;
    }
    let b = live_bridge();
    if !b.is_empty() && b != old_bridge {
        logf!("claude login: Remote Control came back by itself");
        return;
    }
    logf!(
        "claude login: Claude Code stopped Remote Control for the account change: typing /remote-control"
    );
    let _g = RC_TYPING.lock().unwrap_or_else(|e| e.into_inner());
    if send_keys(&["-l", "/remote-control"]).is_ok() {
        util::sleep(Duration::from_millis(300));
        let _ = send_keys(&["Enter"]);
    }
    if !wait_until(RC_MENU_WAIT, || pane_text().contains(RC_ENABLE_TEXT)) {
        logf!("claude login: the /remote-control menu didn't show within 3m0s");
        return;
    }
    let _ = send_keys(&["Enter"]); // its first choice, selected: Enable Remote Control
    if wait_until(RC_UP_WAIT, || {
        let b = live_bridge();
        !b.is_empty() && b != old_bridge
    }) {
        logf!("claude login: Remote Control is up again under the new account");
    } else {
        logf!("claude login: Remote Control didn't come up within 1m30s of choosing Enable");
    }
}

pub fn wait_until(d: Duration, mut ok: impl FnMut() -> bool) -> bool {
    let end = Instant::now() + d;
    loop {
        if ok() {
            return true;
        }
        if Instant::now() > end {
            return false;
        }
        util::sleep(SWITCH_POLL);
    }
}

/// the Remote Control session id of the live claude host, from claude's own session registry; "" = none
pub fn live_bridge() -> String {
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct E {
        pid: i64,
        #[serde(rename = "bridgeSessionId")]
        bridge: String,
    }
    let dir = paths::home().join(".claude").join("sessions");
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    files.sort();
    for f in files {
        let Ok(b) = std::fs::read(&f) else { continue };
        let Ok(e) = gojson::unmarshal::<E>(&b) else {
            continue;
        };
        if e.bridge.is_empty() || e.pid == 0 {
            continue;
        }
        if nix::sys::signal::kill(nix::unistd::Pid::from_raw(e.pid as i32), None).is_ok() {
            return e.bridge;
        }
    }
    String::new()
}

/// the router switched the session's Claude account (supervisor-core's command "claude-account"; the long poll brings
/// the pair, creds_sync switches): a session that had no account leaves the marker, and supervisor-normal starts its sync
pub fn claude_account_cmd() {
    logf!("claude login: the router switched this session's Claude account");
    if !paths::claude_login_on().exists() {
        start_creds_sync();
    }
}
