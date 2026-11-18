//! The Claude login of one Claude account (Jarvis 1's lib/oauth.js, lib/claudelogin.js, /api/credentials, /api/usage
//! and its Re-login, moved here; docs/DECISIONS.md 115-121, 185). Each account is a Claude key store of the router's
//! own, `claude-<name>` (claudeaccounts.rs): one hub per account, its pair a sealed document of the database
//! (claude-accounts/<store>.json), and this router is its ONLY refresher. A refresh revokes the previous access token at
//! once, so there is one refresher: this router. Jarvis 1, while it still runs, only follows one account (reads its
//! pair from here).
//!
//! Who takes an account's pair, all with the same long poll (GET …/claude-login?have=&ack=&wait=):
//!   - a session machine whose session uses that account (Session.claude_account, fixed when the session is made;
//!     /m/claude-login, signed with its machine key);
//!   - Jarvis 1, while it still runs, for its own sessions (/peer/claude-login, behind a path-scoped Access app that
//!     admits one service token, JARVIS1_LOGIN_CLIENT_ID). Jarvis 4 never calls Jarvis 1.
//!
//! The refresh protocol keeps lessons/74's guarantee (a session that gets a 401 mid-refresh waits for the new pair
//! instead of burning its refresh token): before refreshing, the hub answers every waiting poll with {preparing, gen};
//! each participant takes the CLI's refresh lock (~/.claude/.oauth_refresh.lock) and polls again with ack=gen; the hub
//! waits for every participant seen in the last 2 minutes (at most 10 s), refreshes, writes the pair, then answers
//! every poll with it; a participant writes the file and releases the lock. A failed refresh answers {preparing:
//! false}: participants release.
//!
//! Pushes (a participant whose claude refreshed by itself, e.g. while the router was down): newer expiresAt wins, and
//! the pair's account must be the hub's (checked with Anthropic's profile endpoint). A Re-login (Deyao's own action)
//! must be the hub's account too, once it has one (claudeaccounts.rs checks it).

use crate::claudeaccounts::ClaudeAccounts;
use crate::ctx::Ctx;
use crate::http::{Registrar, null_if_empty};
use crate::nethttp::{Req, W, write_json};
use crate::router::Router;
use crate::state::State;
use anyhow::{Result, anyhow};
use base64::Engine;
use jarvis_go::GoTime;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::{Arc, Condvar, LazyLock, Mutex, MutexGuard, OnceLock, RwLock, Weak};
use std::time::{Duration, Instant};

/// The Claude Code CLI's own OAuth parameters (read from claude 2.1.296: dn().TOKEN_URL, CLAUDE_AI_AUTHORIZE_URL,
/// MANUAL_REDIRECT_URL, CLIENT_ID, the scopes of `claude auth login --claudeai`; lessons/39). Tests point them at
/// stand-ins.
#[derive(Debug, Clone)]
pub struct OauthUrls {
    pub token: String,
    pub authorize: String,
    pub redirect: String,
    pub profile: String,
    pub usage: String,
}

pub static OAUTH: LazyLock<RwLock<OauthUrls>> = LazyLock::new(|| {
    RwLock::new(OauthUrls {
        token: "https://platform.claude.com/v1/oauth/token".into(),
        authorize: "https://claude.com/cai/oauth/authorize".into(),
        redirect: "https://platform.claude.com/oauth/code/callback".into(),
        profile: "https://api.anthropic.com/api/oauth/profile".into(),
        usage: "https://api.anthropic.com/api/oauth/usage".into(),
    })
});

pub const OAUTH_CLIENT_ID: &str = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";
pub const OAUTH_SCOPES: &[&str] = &[
    "org:create_api_key",
    "user:profile",
    "user:inference",
    "user:sessions:claude_code",
    "user:mcp_servers",
    "user:file_upload",
    "user:plugins",
];

fn oauth() -> OauthUrls {
    OAUTH.read().unwrap_or_else(|e| e.into_inner()).clone()
}

static LOGIN_HTTP: LazyLock<reqwest::blocking::Client> = LazyLock::new(|| {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap_or_default()
});

/// refresh when less is left (Jarvis 1's FRESH_MARGIN_MS)
pub const LOGIN_FRESH_MARGIN: Duration = Duration::from_secs(30 * 60);
/// after a failed refresh, don't hammer the endpoint
pub const LOGIN_RETRY: Duration = Duration::from_secs(5 * 60);
/// the longest a refresh waits for participants to take their locks
pub const LOGIN_ACK_WAIT: Duration = Duration::from_secs(10);
/// a participant counts while it polled this recently
pub const LOGIN_SEEN_WINDOW: Duration = Duration::from_secs(2 * 60);
/// under Cloudflare's 100 s proxy timeout (Jarvis 1 polls through it)
pub const LOGIN_POLL_MAX: Duration = Duration::from_secs(55);
/// a Re-login's code must come within this
pub const LOGIN_PENDING_TTL: Duration = Duration::from_secs(15 * 60);

/// the login errors callers tell apart
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginErr {
    NoPair,
    NotNewer,
    OtherAcct,
}

impl std::fmt::Display for LoginErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            LoginErr::NoPair => "no Claude login stored: Re-login",
            LoginErr::NotNewer => "not newer than the stored pair",
            LoginErr::OtherAcct => "the pair belongs to another Claude account than the stored one",
        })
    }
}

impl std::error::Error for LoginErr {}

pub fn is_login_err(e: &anyhow::Error, k: LoginErr) -> bool {
    e.downcast_ref::<LoginErr>() == Some(&k)
}

fn std_dur(d: Duration) -> time::Duration {
    time::Duration::try_from(d).unwrap_or(time::Duration::MAX)
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct LoginFail {
    pub at: GoTime,
    pub error: String,
    /// of the pair whose refresh failed
    #[serde(rename = "expiresAt")]
    pub expires_at: i64,
    /// the token endpoint said no (not a network error): only a Re-login helps
    pub rejected: bool,
    /// the dead-login DM went out for this pair
    pub notified: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PendingLogin {
    pub verifier: String,
    pub state: String,
    pub at: GoTime,
}

/// the account's login document
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct LoginFile {
    /// ~/.claude/.credentials.json
    #[serde(skip_serializing_if = "String::is_empty")]
    pub credentials: String,
    /// ~/.claude.json's {oauthAccount, userID}
    #[serde(skip_serializing_if = "String::is_empty")]
    pub account: String,
    /// where the stored pair came from
    #[serde(skip_serializing_if = "String::is_empty")]
    pub source: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: GoTime,
    #[serde(rename = "refreshedAt")]
    pub refreshed_at: GoTime,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fail: Option<LoginFail>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending: Option<PendingLogin>,
}

#[derive(Default)]
struct Hub {
    f: LoginFile,
    /// bumped (and the condvar woken) on every change (pair, phase, acks)
    ver: u64,
    r#gen: i64,
    preparing: bool,
    acks: BTreeMap<String, i64>,
    seen: BTreeMap<String, GoTime>,
    usage_at: Option<Instant>,
    usage_body: Option<Map<String, Value>>,
    /// the document as this replica last read or wrote it (reload: another replica wrote a newer one)
    saved: Vec<u8>,
}

pub type DmHook = Arc<dyn Fn(String) + Send + Sync>;

pub struct LoginHub {
    /// sealed.rs: the pair is a sealed document of the database
    st: Arc<State>,
    /// its name there: claude-accounts/claude-<name>.json
    pub name: String,
    /// the account's key store, claude-<name>
    pub store: String,
    mu: Mutex<Hub>,
    cv: Condvar,
    /// one refresh (or Re-login exchange) at a time
    pub refresh_mu: Mutex<()>,
    pub dm: OnceLock<DmHook>,
    /// claudeaccounts.rs: a Re-login's account must be this hub's own and no other hub's; a sign-in it turns away
    /// lands in the hub of its own account (made when there is none), so a fresh grant is never thrown away. Unset:
    /// any account.
    pub accounts: OnceLock<Weak<ClaudeAccounts>>,
}

/// the pair as callers read it
#[derive(Debug, Clone, Default)]
pub struct LoginView {
    pub credentials: String,
    pub account: String,
    pub expires_at: i64,
}

impl LoginHub {
    pub fn new(st: Arc<State>, name: &str, store: &str) -> LoginHub {
        let mut hub = Hub::default();
        match st.read_sealed(name) {
            Err(e) => crate::logf!("[login] {name}: {e:#}"),
            Ok(Some(b)) => {
                match jarvis_go::unmarshal::<LoginFile>(&b) {
                    Ok(f) => hub.f = f,
                    Err(e) => crate::logf!("[login] {name} unreadable: {e}"),
                }
                hub.saved = b;
            }
            Ok(None) => {}
        }
        LoginHub {
            st,
            name: name.to_string(),
            store: store.to_string(),
            mu: Mutex::new(hub),
            cv: Condvar::new(),
            refresh_mu: Mutex::new(()),
            dm: OnceLock::new(),
            accounts: OnceLock::new(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Hub> {
        self.mu.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn lock_refresh(&self) -> MutexGuard<'_, ()> {
        self.refresh_mu.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn broadcast(&self, g: &mut Hub) {
        g.ver = g.ver.wrapping_add(1);
        self.cv.notify_all();
    }

    /// the document from the database when another replica wrote it since. A STOPGAP (2026-10-28): each replica keeps
    /// the login in memory and only the leader refreshes, so without this the other replica kept serving the pair the
    /// leader's refresh had just revoked ("Login expired" in the sessions whose polls reached it). The clean design
    /// (the row as the only truth, the refresh under a database lock) is in RUNBOOK "The Claude accounts".
    pub fn reload(&self) {
        let mut g = self.lock(); // across the read: a save in between must not be overwritten by the older document
        let Ok(Some(b)) = self.st.read_sealed(&self.name) else {
            return;
        };
        if b == g.saved {
            return;
        }
        let f = match jarvis_go::unmarshal::<LoginFile>(&b) {
            Ok(f) => f,
            Err(e) => {
                crate::logf!("[login] {} unreadable: {e}", self.name);
                return;
            }
        };
        let exp = creds_expiry(&f.credentials);
        g.f = f;
        g.saved = b;
        g.usage_body = None;
        self.broadcast(&mut g);
        crate::logf!(
            "[login] {}: reloaded the pair another replica wrote (valid until {})",
            self.store,
            ms_rfc3339(exp)
        );
    }

    /// sealed into the database, committed before it returns (a refreshed pair must survive a crash right after: the
    /// old refresh token is dead)
    fn save(&self, g: &mut Hub) -> Result<()> {
        let b = jarvis_go::fmt::marshal_indent1(&g.f);
        self.st.write_sealed(&self.name, b.as_bytes())?;
        g.saved = b.into_bytes();
        self.st.notify_mq(&login_note(&self.name));
        Ok(())
    }

    /// save with the hub locked here (a new account's slot)
    pub fn save_now(&self) -> Result<()> {
        let mut g = self.lock();
        self.save(&mut g)
    }

    pub fn current(&self) -> LoginView {
        let g = self.lock();
        LoginView {
            credentials: g.f.credentials.clone(),
            account: g.f.account.clone(),
            expires_at: creds_expiry(&g.f.credentials),
        }
    }

    /// a pair from somewhere (a push, Jarvis 1, a Re-login). Stored only when it expires later than the stored one
    /// (force: a Re-login, which always wins) and, unless switch_ok, only for the stored account (Anthropic's profile
    /// answers whose the access token is). account "" keeps the stored account record.
    pub fn offer(
        &self,
        credentials: &str,
        account: &str,
        source: &str,
        switch_ok: bool,
        force: bool,
    ) -> Result<bool> {
        let (p, _) = parse_pair(credentials)?;
        let cur = self.current();
        if !force && p.expires_at <= cur.expires_at {
            return Err(LoginErr::NotNewer.into());
        }
        let want = account_uuid(&cur.account);
        if !switch_ok && !want.is_empty() {
            let prof = fetch_profile(&p.access_token)
                .map_err(|e| anyhow!("checking the pair's account: {e:#}"))?;
            if prof.account.uuid != want {
                return Err(LoginErr::OtherAcct.into());
            }
        }
        let mut g = self.lock();
        if !force && p.expires_at <= creds_expiry(&g.f.credentials) {
            return Err(LoginErr::NotNewer.into()); // another offer landed meanwhile
        }
        let old = g.f.clone();
        g.f.credentials = credentials.to_string();
        g.f.source = source.to_string();
        g.f.updated_at = GoTime::now();
        if !account.is_empty() {
            g.f.account = account.to_string();
        }
        g.f.fail = None;
        if let Err(e) = self.save(&mut g) {
            g.f = old;
            return Err(e);
        }
        g.usage_body = None;
        self.broadcast(&mut g);
        crate::logf!(
            "[login] {}: stored a newer Claude pair from {source} (valid until {})",
            self.store,
            ms_rfc3339(p.expires_at)
        );
        Ok(true)
    }

    /// offer for a Re-login, with refresh_mu already held (force, any account)
    pub fn offer_locked(&self, credentials: &str, account: &str, source: &str) -> Result<bool> {
        self.offer(credentials, account, source, true, true)
    }

    // ---- the long poll ----------------------------------------------------------------------------------------

    /// answers at once when the stored pair expires later than `have`, when a refresh is being prepared that the
    /// caller hasn't acknowledged (ack != gen), or when the caller holds a lock for a refresh that is over (ack != 0,
    /// not preparing); else waits up to `wait` for one of those.
    pub fn poll(&self, ctx: &Ctx, who: &str, have: i64, ack: i64, wait: Duration) -> LoginAnswer {
        let end = Instant::now() + wait.min(LOGIN_POLL_MAX);
        let mut g = self.lock();
        loop {
            g.seen.insert(who.to_string(), GoTime::now());
            if g.preparing && ack == g.r#gen && g.acks.get(who).copied().unwrap_or(0) != ack {
                g.acks.insert(who.to_string(), ack);
                self.broadcast(&mut g);
            }
            let exp = creds_expiry(&g.f.credentials);
            let newer = exp > have && !g.f.credentials.is_empty();
            let a = LoginAnswer {
                credentials: if newer {
                    for_machine(&g.f.credentials)
                } else {
                    String::new()
                },
                account: g.f.account.clone(),
                expires_at: exp,
                r#gen: g.r#gen,
                preparing: g.preparing,
            };
            let ready = newer || (g.preparing && ack != g.r#gen) || (!g.preparing && ack != 0);
            if ready || wait.is_zero() {
                return a;
            }
            let ver = g.ver;
            while g.ver == ver {
                let now = Instant::now();
                if now >= end || ctx.cancelled() {
                    return a;
                }
                // a cancelled context is seen within a quarter second
                g = self
                    .cv
                    .wait_timeout(g, (end - now).min(Duration::from_millis(250)))
                    .map(|(g, _)| g)
                    .unwrap_or_else(|e| e.into_inner().0);
            }
        }
    }

    // ---- the refresh ------------------------------------------------------------------------------------------

    /// the router's own refresh, when less than LOGIN_FRESH_MARGIN is left or forced
    pub fn refresh(&self, force: bool) -> Result<bool> {
        let _r = self.lock_refresh();
        self.reload(); // a pair another replica stored (a push, a Re-login) is the one to refresh
        let mut g = self.lock();
        let creds = g.f.credentials.clone();
        if creds.is_empty() {
            return Err(LoginErr::NoPair.into());
        }
        let exp = creds_expiry(&creds);
        let left_ms = exp - unix_ms();
        if !force && left_ms > LOGIN_FRESH_MARGIN.as_millis() as i64 {
            return Ok(false);
        }
        if let Some(fl) = g.f.fail.clone() {
            if !force && fl.expires_at == exp && fl.at.since() < std_dur(LOGIN_RETRY) {
                if !fl.rejected && left_ms > 0 {
                    return Ok(false);
                }
                return Err(anyhow!(
                    "the Claude login has run out and its refresh was refused ({}): Re-login",
                    fl.error
                ));
            }
            if !force && fl.rejected && fl.expires_at == exp {
                // a dead grant: only a Re-login (or a newer pushed pair) helps
                return Err(anyhow!(
                    "the Claude login's refresh was refused ({}): Re-login",
                    fl.error
                ));
            }
        }
        // 1. prepare: every participant takes its CLI's refresh lock and acknowledges
        g.r#gen += 1;
        let r#gen = g.r#gen;
        g.preparing = true;
        let want: Vec<String> = g
            .seen
            .iter()
            .filter(|(_, at)| at.since() < std_dur(LOGIN_SEEN_WINDOW))
            .map(|(w, _)| w.clone())
            .collect();
        self.broadcast(&mut g);
        drop(g);
        let acked = self.wait_acks(r#gen, &want, LOGIN_ACK_WAIT);

        // 2. refresh, and keep the answer before anything else (the old refresh token is dead from here on)
        let res = oauth_refresh(&creds);
        let mut g = self.lock();
        g.preparing = false;
        let out = match res {
            Err((e, rejected)) => {
                let msg = format!("{e:#}");
                g.f.fail = Some(LoginFail {
                    at: GoTime::now(),
                    error: msg.clone(),
                    expires_at: exp,
                    rejected,
                    notified: false,
                });
                let _ = self.save(&mut g);
                crate::logf!(
                    "[login] {}: refresh failed ({acked}/{} participants locked): {msg}",
                    self.store,
                    want.len()
                );
                if rejected && let Some(dm) = self.dm.get().cloned() {
                    if let Some(fl) = g.f.fail.as_mut() {
                        fl.notified = true;
                    }
                    let _ = self.save(&mut g);
                    let text = dead_login_message(&self.store, &account_email(&g.f.account), &msg);
                    std::thread::spawn(move || dm(text));
                }
                Err(e)
            }
            Ok(new_creds) => {
                if creds_expiry(&new_creds) > creds_expiry(&g.f.credentials) {
                    // a pushed or re-logged pair that expires later wins
                    g.f.credentials = new_creds.clone();
                    g.f.source = "refresh".into();
                }
                g.f.fail = None;
                g.f.refreshed_at = GoTime::now();
                g.f.updated_at = GoTime::now();
                if let Err(e) = self.save(&mut g) {
                    crate::logf!("[login] writing the refreshed pair to the volume failed: {e:#}");
                }
                g.usage_body = None;
                crate::logf!(
                    "[login] {}: refreshed ({acked}/{} participants locked); valid until {}",
                    self.store,
                    want.len(),
                    ms_rfc3339(creds_expiry(&new_creds))
                );
                Ok(true)
            }
        };
        self.broadcast(&mut g); // participants get the pair, or release their locks
        out
    }

    /// until every participant in want acknowledged gen, or d passed; returns how many did
    fn wait_acks(&self, r#gen: i64, want: &[String], d: Duration) -> usize {
        let end = Instant::now() + d;
        let mut g = self.lock();
        loop {
            let n = want
                .iter()
                .filter(|w| g.acks.get(*w).copied() == Some(r#gen))
                .count();
            let now = Instant::now();
            if n == want.len() || now >= end {
                return n;
            }
            g = self
                .cv
                .wait_timeout(g, end - now)
                .map(|(g, _)| g)
                .unwrap_or_else(|e| e.into_inner().0);
        }
    }

    /// waits for a refresh in flight (SIGTERM): its answer must reach the database
    pub fn drain(&self, d: Duration) {
        let end = Instant::now() + d;
        loop {
            if self.refresh_mu.try_lock().is_ok() {
                return;
            }
            if Instant::now() >= end {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    // ---- Re-login (the CLI's manual OAuth flow: the browser shows "code#state", Deyao pastes it) -------------

    pub fn start_login(&self) -> Result<String> {
        let p = PendingLogin {
            verifier: b64url(&crate::util::rand_bytes(32)),
            state: b64url(&crate::util::rand_bytes(32)),
            at: GoTime::now(),
        };
        let challenge = b64url(&Sha256::digest(p.verifier.as_bytes()));
        let o = oauth();
        let scope = OAUTH_SCOPES.join(" ");
        // the CLI's order of parameters (URL.searchParams.append), so the page looks like the CLI's
        let q: [(&str, &str); 8] = [
            ("code", "true"),
            ("client_id", OAUTH_CLIENT_ID),
            ("response_type", "code"),
            ("redirect_uri", &o.redirect),
            ("scope", &scope),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
            ("state", &p.state),
        ];
        let parts: Vec<String> = q
            .iter()
            .map(|(k, v)| {
                format!(
                    "{}={}",
                    jarvis_go::fmt::query_escape(k),
                    jarvis_go::fmt::query_escape(v)
                )
            })
            .collect();
        let url = format!("{}?{}", o.authorize, parts.join("&"));
        let mut g = self.lock();
        g.f.pending = Some(p);
        self.save(&mut g)?;
        Ok(url)
    }

    /// the pasted "code#state" → the CLI's exchange (authorization_code, the manual redirect, PKCE) → the profile
    /// (subscription, rate tier, the account record) → stored, whatever the account (Deyao's own action) → (email,
    /// the store it landed in)
    pub fn finish_login(self: &Arc<Self>, pasted: &str) -> Result<(String, String)> {
        let (target, email) = self.finish_login_to(pasted)?;
        Ok((email, target.store.clone()))
    }

    /// the exchange, then the pair stored in this hub, or (another Claude account than this hub's) in the hub of that
    /// account, made if there is none: the store asked for keeps its own account (DECISIONS 190)
    pub fn finish_login_to(self: &Arc<Self>, pasted: &str) -> Result<(Arc<LoginHub>, String)> {
        let pasted = pasted.trim();
        let (code, state, _) = jarvis_go::fmt::cut(pasted, "#");
        let p = self.lock().f.pending.clone();
        let Some(p) = p.filter(|p| p.at.since() <= std_dur(LOGIN_PENDING_TTL)) else {
            return Err(anyhow!(
                "no sign-in in progress (or it is older than 15 minutes): press Re-login again"
            ));
        };
        if code.is_empty() || state.is_empty() {
            return Err(anyhow!(
                "paste the whole code shown after sign-in (it has a # in it)"
            ));
        }
        if state != p.state {
            return Err(anyhow!(
                "that code belongs to another sign-in: press Re-login again"
            ));
        }
        let _r = self.lock_refresh(); // not while a refresh is out
        let o = oauth();
        let j = token_call(
            &json!({"grant_type": "authorization_code", "code": code, "redirect_uri": o.redirect,
            "client_id": OAUTH_CLIENT_ID, "code_verifier": p.verifier, "state": state}),
        )
        .map_err(|(e, _)| e)?;
        let at = j
            .get("access_token")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let now = unix_ms();
        let mut oa_pair = Map::new();
        oa_pair.insert("accessToken".into(), json!(at));
        oa_pair.insert(
            "refreshToken".into(),
            j.get("refresh_token").cloned().unwrap_or(Value::Null),
        );
        oa_pair.insert(
            "expiresAt".into(),
            json!(now + jnum(j.get("expires_in")).max(60) * 1000),
        );
        let rte = jnum(j.get("refresh_token_expires_in"));
        if rte > 0 {
            oa_pair.insert("refreshTokenExpiresAt".into(), json!(now + rte * 1000));
        }
        let scopes: Vec<String> = match j.get("scope").and_then(Value::as_str) {
            Some(sc) if !sc.is_empty() => sc.split_whitespace().map(String::from).collect(),
            _ => OAUTH_SCOPES.iter().map(|s| s.to_string()).collect(),
        };
        oa_pair.insert("scopes".into(), json!(scopes));
        let mut acct = Map::new();
        match fetch_profile(&at) {
            Ok(prof) => {
                let sub = match prof.organization.organization_type.as_str() {
                    "claude_max" => "max",
                    "claude_pro" => "pro",
                    "claude_enterprise" => "enterprise",
                    "claude_team" => "team",
                    _ => "",
                };
                if !sub.is_empty() {
                    oa_pair.insert("subscriptionType".into(), json!(sub));
                }
                if !prof.organization.rate_limit_tier.is_empty() {
                    oa_pair.insert(
                        "rateLimitTier".into(),
                        json!(prof.organization.rate_limit_tier),
                    );
                }
                let mut oa = Map::new();
                oa.insert("accountUuid".into(), json!(prof.account.uuid));
                oa.insert("emailAddress".into(), json!(prof.account.email));
                oa.insert("organizationUuid".into(), json!(prof.organization.uuid));
                oa.insert(
                    "hasExtraUsageEnabled".into(),
                    json!(prof.organization.has_extra_usage_enabled),
                );
                for (k, v) in [
                    ("displayName", &prof.account.display_name),
                    ("fullName", &prof.account.full_name),
                    ("billingType", &prof.organization.billing_type),
                    ("accountCreatedAt", &prof.account.created_at),
                    (
                        "subscriptionCreatedAt",
                        &prof.organization.subscription_created_at,
                    ),
                ] {
                    if !v.is_empty() {
                        oa.insert(k.into(), json!(v));
                    }
                }
                acct.insert("oauthAccount".into(), Value::Object(oa));
            }
            Err(e) => {
                crate::logf!(
                    "[login] {}: Re-login: profile: {e:#} (stored without the account record)",
                    self.store
                );
                if let Some(a) = j.get("account").and_then(Value::as_object) {
                    let mut oa = Map::new();
                    oa.insert(
                        "accountUuid".into(),
                        a.get("uuid").cloned().unwrap_or(Value::Null),
                    );
                    oa.insert(
                        "emailAddress".into(),
                        a.get("email_address").cloned().unwrap_or(Value::Null),
                    );
                    if let Some(org) = j.get("organization").and_then(Value::as_object) {
                        oa.insert(
                            "organizationUuid".into(),
                            org.get("uuid").cloned().unwrap_or(Value::Null),
                        );
                    }
                    acct.insert("oauthAccount".into(), Value::Object(oa));
                }
            }
        }
        let creds = jarvis_go::marshal(&json!({"claudeAiOauth": oa_pair}));
        let account = if acct.is_empty() {
            String::new()
        } else {
            jarvis_go::marshal(&acct)
        };
        let mut target = self.clone();
        if let Some(a) = self.accounts.get().and_then(Weak::upgrade)
            && let Err(e) = a.check_relogin(&self.store, &account_uuid(&account))
        {
            let t = a
                .hub_for(&account_uuid(&account), &account_email(&account))
                .map_err(|te| {
                    anyhow!("{e:#} (keeping it as its own account failed too: {te:#})")
                })?;
            crate::logf!(
                "[login] {}: the sign-in is {}, kept in {} instead",
                self.store,
                account_email(&account),
                t.store
            );
            target = t;
        }
        self.lock().f.pending = None;
        let _t = (!Arc::ptr_eq(&target, self)).then(|| target.lock_refresh());
        target.offer_locked(&creds, &account, "relogin")?;
        Ok((target.clone(), account_email(&account)))
    }

    // ---- the usage quota (Jarvis 1's /api/usage) --------------------------------------------------------------

    pub fn usage_quota(&self, force: bool) -> (u16, Map<String, Value>) {
        let creds = {
            let g = self.lock();
            if !force
                && let Some(b) = &g.usage_body
                && g.usage_at
                    .is_some_and(|t| t.elapsed() < Duration::from_secs(60))
            {
                let mut b = b.clone();
                b.insert("cached".into(), json!(true));
                return (200, b);
            }
            g.f.credentials.clone()
        };
        let fail = |status: u16, msg: &str, need_login: bool| -> (u16, Map<String, Value>) {
            let g = self.lock();
            if let Some(b) = &g.usage_body
                && !need_login
            {
                let mut b = b.clone();
                b.insert("cached".into(), json!(true));
                b.insert("stale".into(), json!(true));
                b.insert("error".into(), json!(msg));
                return (200, b);
            }
            let mut out = Map::new();
            out.insert("error".into(), json!(msg));
            if need_login {
                out.insert("needLogin".into(), json!(true));
            }
            (status, out)
        };
        let Ok((p, _)) = parse_pair(&creds) else {
            return fail(409, "no Claude login stored: Re-login", true);
        };
        let resp = LOGIN_HTTP
            .get(oauth().usage)
            .header("Authorization", format!("Bearer {}", p.access_token))
            .header("anthropic-beta", "oauth-2025-04-20")
            .header("Accept", "application/json")
            .header("User-Agent", "jarvis2-router/1")
            .send();
        let resp = match resp {
            Err(e) => return fail(502, &format!("usage endpoint: {e}"), false),
            Ok(r) => r,
        };
        let status = resp.status().as_u16();
        let b = crate::util::read_limited(resp, 1 << 20).unwrap_or_default();
        if status == 401 || status == 403 {
            return fail(
                409,
                &format!("Claude refused the access token (HTTP {status}): Re-login"),
                true,
            );
        }
        if status != 200 {
            return fail(502, &format!("usage endpoint HTTP {status}"), false);
        }
        let Ok(j) = jarvis_go::unmarshal::<UsageAnswer>(&b) else {
            return fail(502, "usage endpoint: not JSON", false);
        };
        let limits: Vec<Value> = j
            .limits
            .iter()
            .map(|l| {
                let model = match &l.scope.model {
                    Some(m) if !m.display_name.is_empty() => json!(m.display_name),
                    Some(m) => json!(m.id),
                    None => Value::Null,
                };
                json!({"kind": l.kind, "group": l.group, "percent": crate::util::go_f64(l.percent),
                    "severity": l.severity, "resetsAt": null_if_empty(&l.resets_at), "model": model,
                    "surface": null_if_empty(&l.scope.surface), "active": l.is_active})
            })
            .collect();
        let mut body = Map::new();
        body.insert("fetchedAt".into(), json!(GoTime::now().rfc3339()));
        body.insert("limits".into(), json!(limits));
        body.insert(
            "extraUsage".into(),
            match &j.extra_usage {
                None => Value::Null,
                Some(x) => json!({"enabled": x.is_enabled, "monthlyLimit": x.monthly_limit, "usedCredits": x.used_credits,
                    "utilization": x.utilization, "currency": x.currency, "decimalPlaces": crate::util::go_f64(x.decimal_places),
                    "disabledReason": x.disabled_reason, "spendLimitReached": x.spend_limit_reached}),
            },
        );
        {
            let mut g = self.lock();
            g.usage_at = Some(Instant::now());
            g.usage_body = Some(body.clone());
        }
        body.insert("cached".into(), json!(false));
        (200, body)
    }

    // ---- status (no secrets) ----------------------------------------------------------------------------------

    pub fn status(&self) -> Map<String, Value> {
        let g = self.lock();
        let exp = creds_expiry(&g.f.credentials);
        let now = unix_ms();
        let parts: Vec<Value> = g
            .seen
            .iter()
            .filter(|(_, at)| at.since() < std_dur(LOGIN_SEEN_WINDOW))
            .map(|(who, at)| json!({"id": who, "seen": at.utc()}))
            .collect();
        let mut out = Map::new();
        out.insert("store".into(), json!(self.store));
        out.insert("hasLogin".into(), json!(!g.f.credentials.is_empty()));
        out.insert(
            "expiresAt".into(),
            if exp == 0 { Value::Null } else { json!(exp) },
        );
        out.insert("expired".into(), json!(exp != 0 && exp < now));
        out.insert("email".into(), json!(account_email(&g.f.account)));
        out.insert("accountUuid".into(), json!(account_uuid(&g.f.account)));
        out.insert("source".into(), json!(g.f.source));
        out.insert("updatedAt".into(), null_if_zero_time(g.f.updated_at));
        out.insert("refreshedAt".into(), null_if_zero_time(g.f.refreshed_at));
        out.insert("participants".into(), json!(parts));
        out.insert(
            "loginInProgress".into(),
            json!(
                g.f.pending
                    .as_ref()
                    .is_some_and(|p| p.at.since() < std_dur(LOGIN_PENDING_TTL))
            ),
        );
        out.insert("preparing".into(), json!(g.preparing));
        if let Some(fl) = g.f.fail.as_ref().filter(|fl| fl.expires_at == exp) {
            out.insert("error".into(), json!(fl.error));
            out.insert("rejected".into(), json!(fl.rejected));
            out.insert("needLogin".into(), json!(fl.rejected || exp < now));
        }
        if g.f.credentials.is_empty() {
            out.insert("needLogin".into(), json!(true));
        }
        out
    }
}

fn null_if_zero_time(t: GoTime) -> Value {
    if t.is_zero() {
        Value::Null
    } else {
        serde_json::to_value(t).unwrap_or(Value::Null)
    }
}

pub fn unix_ms() -> i64 {
    (GoTime::now().unix_nanos() / 1_000_000) as i64
}

fn ms_rfc3339(ms: i64) -> String {
    GoTime::from_unix_nanos(ms as i128 * 1_000_000)
        .utc()
        .rfc3339()
}

fn b64url(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

/// the pair as a session gets it: without the refresh token, so only the router can refresh (a session's claude that
/// refreshed by itself revoked the router's pair, 2026-10-28: every new session of that account started on a dead
/// token, with channels and Remote Control off). Claude Code runs on the access token alone, Remote Control and
/// channels included, and re-reads the file the supervisor swaps at each router refresh. A STOPGAP like reload: the
/// push path and the prepare/ack protocol stay until the clean fix (RUNBOOK "The Claude accounts").
pub fn for_machine(credentials: &str) -> String {
    let Ok(Value::Object(mut d)) = serde_json::from_str::<Value>(credentials) else {
        return credentials.to_string();
    };
    let Some(Value::Object(o)) = d.get_mut("claudeAiOauth") else {
        return credentials.to_string();
    };
    o.remove("refreshToken");
    o.remove("refreshTokenExpiresAt");
    jarvis_go::marshal(&d)
}

/// the mq notification (mq.rs) that an account's login document changed, so the other replica reloads it
pub fn login_note(name: &str) -> String {
    format!("l:{name}")
}

// ---- the pair's shape -----------------------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct OauthPair {
    #[serde(rename = "accessToken")]
    pub access_token: String,
    #[serde(rename = "refreshToken")]
    pub refresh_token: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: i64,
    pub scopes: Vec<String>,
}

pub fn parse_pair(credentials: &str) -> Result<(OauthPair, Map<String, Value>)> {
    let d: Map<String, Value> =
        serde_json::from_str(credentials).map_err(|_| anyhow!("credentials are not JSON"))?;
    let p: OauthPair = d
        .get("claudeAiOauth")
        .filter(|v| v.is_object())
        .and_then(|v| jarvis_go::unmarshal(jarvis_go::marshal(v).as_bytes()).ok())
        .unwrap_or_default();
    if p.access_token.is_empty() || p.refresh_token.is_empty() || p.expires_at == 0 {
        return Err(anyhow!(
            "credentials must be a ~/.claude/.credentials.json object with claudeAiOauth.{{accessToken,refreshToken,expiresAt}}"
        ));
    }
    Ok((p, d))
}

pub fn creds_expiry(raw: &str) -> i64 {
    serde_json::from_str::<Value>(raw)
        .ok()
        .and_then(|v| {
            v.pointer("/claudeAiOauth/expiresAt")
                .and_then(Value::as_f64)
        })
        .map_or(0, |x| x as i64)
}

pub fn account_uuid(account: &str) -> String {
    serde_json::from_str::<Value>(account)
        .ok()
        .and_then(|v| {
            v.pointer("/oauthAccount/accountUuid")
                .and_then(Value::as_str)
                .map(String::from)
        })
        .unwrap_or_default()
}

pub fn account_email(account: &str) -> String {
    serde_json::from_str::<Value>(account)
        .ok()
        .and_then(|v| {
            v.pointer("/oauthAccount/emailAddress")
                .and_then(Value::as_str)
                .map(String::from)
        })
        .unwrap_or_default()
}

// ---- Anthropic's endpoints ------------------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct ProfileAccount {
    pub uuid: String,
    pub email: String,
    pub display_name: String,
    pub full_name: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct ProfileOrg {
    pub uuid: String,
    pub organization_type: String,
    pub rate_limit_tier: String,
    pub billing_type: String,
    pub has_extra_usage_enabled: bool,
    pub subscription_created_at: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct OauthProfile {
    pub account: ProfileAccount,
    pub organization: ProfileOrg,
}

pub fn fetch_profile(access_token: &str) -> Result<OauthProfile> {
    let resp = LOGIN_HTTP
        .get(oauth().profile)
        .header("Authorization", format!("Bearer {access_token}"))
        .header("anthropic-beta", "oauth-2025-04-20")
        .header("User-Agent", "jarvis2-router/1")
        .send()?;
    let status = resp.status().as_u16();
    let b = crate::util::read_limited(resp, 1 << 20).unwrap_or_default();
    if status != 200 {
        return Err(anyhow!("profile: HTTP {status}"));
    }
    match jarvis_go::unmarshal::<OauthProfile>(&b) {
        Ok(p) if !p.account.uuid.is_empty() => Ok(p),
        _ => Err(anyhow!("profile: no account in the answer")),
    }
}

/// one POST to the token endpoint; rejected = a 4xx other than 429 (the grant is dead or the code wrong)
pub fn token_call(body: &Value) -> std::result::Result<Map<String, Value>, (anyhow::Error, bool)> {
    let resp = LOGIN_HTTP
        .post(oauth().token)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .header("User-Agent", "jarvis2-router/1")
        .body(jarvis_go::marshal(body))
        .send()
        .map_err(|e| (anyhow::Error::from(e), false))?;
    let status = resp.status().as_u16();
    let out = crate::util::read_limited(resp, 1 << 20).unwrap_or_default();
    let j: Map<String, Value> = serde_json::from_slice(&out).unwrap_or_default();
    let has_token = j.get("access_token").is_some_and(|v| !v.is_null());
    if status != 200 || !has_token {
        let sprint = |v: Option<&Value>| jarvis_go::fmt::go_sprint(v.unwrap_or(&Value::Null));
        let mut why = sprint(j.get("error_description"));
        if why == "<nil>" || why.is_empty() {
            why = sprint(j.get("error"));
        }
        if why == "<nil>" {
            why.clear();
        }
        let rejected = (400..500).contains(&status) && status != 429;
        // never the body: it may hold tokens
        return Err((
            anyhow!("token endpoint HTTP {status} {}", why.trim()),
            rejected,
        ));
    }
    Ok(j)
}

pub fn jnum(v: Option<&Value>) -> i64 {
    match v {
        Some(Value::Number(n)) => n.as_f64().map_or(0, |x| x as i64),
        Some(Value::String(s)) => s.parse().unwrap_or(0),
        _ => 0,
    }
}

/// the stored pair refreshed (the CLI's own request: grant_type refresh_token, its scopes); the answer keeps every
/// other field of the credentials file
pub fn oauth_refresh(credentials: &str) -> std::result::Result<String, (anyhow::Error, bool)> {
    let (p, mut d) = parse_pair(credentials).map_err(|e| (e, false))?;
    let mut body = json!({"grant_type": "refresh_token", "refresh_token": p.refresh_token, "client_id": OAUTH_CLIENT_ID});
    if !p.scopes.is_empty() {
        body["scope"] = json!(p.scopes.join(" "));
    }
    let j = token_call(&body)?;
    let mut o = d
        .get("claudeAiOauth")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    o.insert(
        "accessToken".into(),
        j.get("access_token").cloned().unwrap_or(Value::Null),
    );
    if let Some(rt) = j
        .get("refresh_token")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    {
        o.insert("refreshToken".into(), json!(rt));
    }
    let mut exp = jnum(j.get("expires_in"));
    if exp <= 0 {
        exp = 3600;
    }
    let now = unix_ms();
    o.insert("expiresAt".into(), json!(now + exp * 1000));
    let rte = jnum(j.get("refresh_token_expires_in"));
    if rte > 0 {
        o.insert("refreshTokenExpiresAt".into(), json!(now + rte * 1000));
    }
    if let Some(sc) = j
        .get("scope")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    {
        o.insert(
            "scopes".into(),
            json!(sc.split_whitespace().collect::<Vec<_>>()),
        );
    }
    d.insert("claudeAiOauth".into(), Value::Object(o));
    Ok(jarvis_go::marshal(&d))
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct UsageModel {
    id: String,
    display_name: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct UsageScope {
    model: Option<UsageModel>,
    surface: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct UsageLimit {
    kind: String,
    group: String,
    percent: f64,
    severity: String,
    resets_at: String,
    is_active: bool,
    scope: UsageScope,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct UsageExtra {
    is_enabled: bool,
    monthly_limit: Value,
    used_credits: Value,
    utilization: Value,
    currency: String,
    decimal_places: f64,
    disabled_reason: Value,
    spend_limit_reached: bool,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct UsageAnswer {
    limits: Vec<UsageLimit>,
    extra_usage: Option<UsageExtra>,
}

pub fn dead_login_message(store: &str, email: &str, why: &str) -> String {
    let why = jarvis_go::fmt::clip_bytes(why, 200);
    let mut who = store.to_string();
    if !email.is_empty() {
        who += &format!(" ({email})");
    }
    format!(
        "🔑 The Claude login of {who} has run out: refreshing it was refused ({why}). Only a new sign-in fixes it: Jarvis 4 → Settings → Claude accounts → {store} → Re-login. Its sessions stuck on “Please run /login” are resumed once that is done."
    )
}

// ---- the long poll's answer -----------------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize)]
pub struct LoginAnswer {
    /// only when it expires later than the caller's `have`
    #[serde(skip_serializing_if = "String::is_empty")]
    pub credentials: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub account: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: i64,
    pub r#gen: i64,
    pub preparing: bool,
}

// ---- the router's side ----------------------------------------------------------------------------------------

pub fn poll_args(req: &Req) -> (i64, i64, Duration) {
    let have = req.query("have").parse().unwrap_or(0);
    let ack = req.query("ack").parse().unwrap_or(0);
    let ws: i64 = req.query("wait").parse().unwrap_or(0);
    (have, ack, Duration::from_secs(ws.max(0) as u64))
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct PushBody {
    credentials: Option<Box<serde_json::value::RawValue>>,
    account: Option<Box<serde_json::value::RawValue>>,
    relogin: bool,
}

/// a JSON string, or any other JSON value as its text (Jarvis 1 accepted both)
fn as_string(raw: &Option<Box<serde_json::value::RawValue>>) -> String {
    let Some(raw) = raw else { return String::new() };
    let t = raw.get();
    if t == "null" {
        return String::new();
    }
    serde_json::from_str::<String>(t).unwrap_or_else(|_| t.to_string())
}

fn no_account(w: &mut W) {
    write_json(
        w,
        404,
        &json!({"error": "this session has no Claude account", "noAccount": true}),
    );
}

impl Router {
    /// each Claude account's stored pair's expiry, by store; accounts with no pair are left out (relogin.go)
    pub fn login_expiries(&self) -> BTreeMap<String, i64> {
        self.accounts()
            .all()
            .into_iter()
            .filter_map(|h| {
                let cur = h.current();
                (!cur.credentials.is_empty()).then(|| (h.store.clone(), cur.expires_at))
            })
            .collect()
    }

    /// waits for every account's refresh in flight (SIGTERM, a move's freeze): its answer must reach the database
    pub fn drain_logins(&self, d: Duration) {
        for h in self.accounts().all() {
            h.drain(d);
        }
    }

    /// refresh every account's login when due (checked every minute)
    pub fn login_loop(self: &Arc<Self>) {
        loop {
            crate::leaderlease::await_lead();
            for h in self.accounts().all() {
                if let Err(e) = h.refresh(false)
                    && !is_login_err(&e, LoginErr::NoPair)
                {
                    crate::logf!("[login] {}: {e:#}", h.store);
                }
            }
            self.sync_account_stores(); // claudestores.rs: each account's pair into its core store
            std::thread::sleep(Duration::from_secs(60));
        }
    }

    /// the session this machine runs and the hub of its Claude account; None when the session has none (or the
    /// account was removed)
    pub fn machine_account(&self, machine: &str) -> (String, Option<Arc<LoginHub>>) {
        let (sid, store) = self.st.do_(|d| {
            d.machines
                .get(machine)
                .and_then(|id| d.sessions.get(id))
                .filter(|s| s.machine_id == machine)
                .map(|s| (s.id.clone(), s.claude_account.clone()))
                .unwrap_or_default()
        });
        if sid.is_empty() || store.is_empty() {
            return (sid, None);
        }
        let h = self.accounts().hub(&store);
        (sid, h)
    }

    fn push_answer(&self, w: &mut W, h: &LoginHub, body: &[u8], source: &str, mut switch_ok: bool) {
        let Ok(b) = jarvis_go::unmarshal::<PushBody>(body) else {
            write_json(
                w,
                400,
                &json!({"error": "body must be {credentials, account?}"}),
            );
            return;
        };
        let (creds, account) = (as_string(&b.credentials), as_string(&b.account));
        if source == "jarvis1" && b.relogin {
            switch_ok = true;
        }
        match h.offer(
            &creds,
            &account,
            source,
            switch_ok,
            source == "jarvis1" && b.relogin,
        ) {
            Err(e) if is_login_err(&e, LoginErr::NotNewer) => write_json(
                w,
                200,
                &json!({"stored": false, "reason": "not newer than the stored credentials", "expiresAt": h.current().expires_at}),
            ),
            Err(e) => {
                let status = if is_login_err(&e, LoginErr::OtherAcct) {
                    403
                } else {
                    400
                };
                write_json(w, status, &json!({"error": format!("{e:#}")}));
            }
            Ok(stored) => write_json(
                w,
                200,
                &json!({"stored": stored, "expiresAt": creds_expiry(&creds)}),
            ),
        }
    }

    /// exactly one Access service token (its client id = the JWT's common_name) on a path-scoped Access app (aud);
    /// no email login
    pub fn require_client(&self, w: &mut W, req: &Req, aud: &str, client_id: &str) -> bool {
        if self.cfg.no_access {
            return true;
        }
        if aud.is_empty() || client_id.is_empty() {
            write_json(
                w,
                503,
                &json!({"error": "the router has no Access audience / client id for this path"}),
            );
            return false;
        }
        match self
            .access()
            .verify(&req.header("Cf-Access-Jwt-Assertion"), aud)
        {
            Ok(c) if c.email.is_empty() && c.common_name == client_id => true,
            _ => {
                write_json(w, 403, &json!({"error": "Access service token required"}));
                false
            }
        }
    }

    /// after a Re-login, the next autopilot tick delivers "continue" to sessions stuck on "Please run /login"
    /// (autopilot.rs plans it from the stored pair's expiry)
    pub fn resume_stuck_logins(self: &Arc<Self>) {
        self.autopilot_tick();
    }
}

pub fn register_claude_login(reg: &mut Registrar) {
    // ---- session machines (the session's own account) ----
    reg.m("GET /m/claude-login", |r, w, req, machine, _| {
        let Some(h) = r.machine_account(machine).1 else {
            return no_account(w);
        };
        let (have, ack, wait) = poll_args(req);
        // accountswap.rs: a switch cuts it short
        let (a, ok) = r.poll_with_switch(&Ctx::background(), machine, &h, have, ack, wait);
        if !ok {
            return no_account(w);
        }
        w.set_header("Cache-Control", "no-store");
        write_json(w, 200, &a);
    });
    let push = |r: &Arc<Router>, w: &mut W, _req: &mut Req, machine: &str, body: &[u8]| {
        let (sid, h) = r.machine_account(machine);
        let Some(h) = h else { return no_account(w) };
        r.push_answer(w, &h, body, &format!("session {sid}"), false);
    };
    reg.m("POST /m/claude-login", push);
    // session images from before 2026-10-13 (their push-claude-credentials, through the machine's $JARVIS_URL proxy)
    reg.m("GET /m/api/credentials", |r, w, _req, machine, _| {
        let Some(h) = r.machine_account(machine).1 else { return no_account(w) };
        let cur = h.current();
        if cur.credentials.is_empty() {
            write_json(w, 409, &json!({"error": "no Claude login stored: Re-login", "needLogin": true}));
            return;
        }
        w.set_header("Cache-Control", "no-store");
        write_json(
            w,
            200,
            &json!({"credentials": for_machine(&cur.credentials), "account": cur.account, "expiresAt": cur.expires_at}),
        );
    });
    reg.m("POST /m/api/credentials", push);

    // ---- Jarvis 1 (its sessions take the pair from here once it follows): one Access service token, one account ----
    let aud = std::env::var("ACCESS_PEER_AUD").unwrap_or_default();
    let client = std::env::var("JARVIS1_LOGIN_CLIENT_ID").unwrap_or_default();
    let peer = move |f: fn(&Arc<Router>, &mut W, &mut Req, &Arc<LoginHub>)| {
        let (aud, client) = (aud.clone(), client.clone());
        move |r: &Arc<Router>, w: &mut W, req: &mut Req| {
            if !r.require_client(w, req, &aud, &client) {
                return;
            }
            match r.accounts().jarvis1_hub() {
                None => write_json(
                    w,
                    409,
                    &json!({"error": "no Claude account is followed by Jarvis 1", "needLogin": true}),
                ),
                Some(h) => f(r, w, req, &h),
            }
        }
    };
    reg.public_fn(
        "GET /peer/claude-login",
        peer(|_, w, req, h| {
            let (have, ack, wait) = poll_args(req);
            w.set_header("Cache-Control", "no-store");
            write_json(
                w,
                200,
                &h.poll(&Ctx::background(), "jarvis1", have, ack, wait),
            );
        }),
    );
    reg.public_fn(
        "POST /peer/claude-login",
        peer(|r, w, req, h| {
            let b = req.read_body(1 << 20);
            r.push_answer(w, h, &b, "jarvis1", false);
        }),
    );
    reg.public_fn(
        "GET /peer/claude-login/status",
        peer(|_, w, _, h| write_json(w, 200, &h.status())),
    );

    crate::claudeaccounts::register_claude_accounts(reg); // the app's and the setup session's routes
}
