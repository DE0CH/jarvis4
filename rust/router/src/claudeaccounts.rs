//! Claude accounts (Deyao, 2026-10-15: "there should be multiple claude key stores, one per account, so I can choose
//! which account a session starts with and the session uses it (refreshed automatically), and I can manage the
//! accounts in the dashboard"; DECISIONS 185, 190). Each account is the core store `claude-<name>`, which this router
//! writes (claudestores.rs: its pair and record at every change, as the core's writer "router"), and the router's
//! working copy it refreshes with (the sealed document claude-accounts/<store>.json, one LoginHub each,
//! claudelogin.rs): the pair rotates every 8 hours with nobody there (DECISIONS 115), and the core gives a store back
//! only with the phone.
//!
//!   - A session's account is chosen when it is made (New session in the app and web page, `jarvis-request
//!     new-session --account`, a task instance, a restore) and kept for the session's life (Session.claude_account):
//!     a resume keeps it. Harnesses that need one (policy/stores.json `claudeAccount`: claude, openclaw) and prompt
//!     tasks get the default account when none is named. Trusted as the router's word, like the pair itself (Deyao,
//!     2026-10-15: no machine-side account check).
//!   - The default account (claude-accounts/accounts.json) is what New session pre-picks; Deyao sets it.
//!   - Remove is refused while any session (running, paused, waiting for approval, failed) uses the account. The
//!     default can be removed: the next account becomes the default. A removed account's core store loses its keys. A
//!     sign-in of another Claude account than the store's is kept as that account's own (its store, or a new
//!     claude-<its name>, and the answer's note says so), never thrown away (DECISIONS 190). A broken login gets no
//!     automatic action: the dashboard shows each account's state and Deyao re-logs it in.
//!
//! Routes (the app and web page; GET /setup/claude-accounts for the setup session):
//!
//! ```text
//! GET    /api/claude-accounts                    {default, accounts: [status + {name, default, sessions}]}
//! POST   /api/claude-accounts {name}             a new account: {store, url} — the sign-in page; then …/code
//! POST   /api/claude-accounts/{store}/login      Re-login: {url}
//! POST   /api/claude-accounts/{store}/code       {code: "code#state"} → {ok, email, expiresAt}
//! POST   /api/claude-accounts/{store}/refresh    refresh now
//! POST   /api/claude-accounts/{store}/default    make it the default
//! DELETE /api/claude-accounts/{store}            remove: {ok, default} (409 while a session uses it)
//! GET    /api/claude-accounts/{store}/usage      its usage quota (?refresh=1)
//! ```
//!
//! The routes of the one shared login (/api/claude-login, …/refresh, …/start, …/code, /api/usage) act on the default
//! account, for app builds from before accounts.
//!
//! The Go router's one-time move of the single shared login (claude-login.json on the volume) into an account is not
//! carried over: every router that runs this code has made it already.

use crate::claudelogin::{LoginErr, LoginHub, account_email, account_uuid, is_login_err, login_note};
use crate::http::{Registrar, null_if_empty};
use crate::nethttp::{Req, W, write_json};
use crate::router::Router;
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::sync::{Arc, LazyLock, Mutex, MutexGuard};
use std::time::Duration;

/// the core's store of the one shared login before accounts (sessions from before the cut still hold it)
pub const LEGACY_CLAUDE_STORE: &str = "claude";

static ACCOUNT_STORE_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"^claude-[a-z0-9]+(-[a-z0-9]+)*$").unwrap_or_else(|_| unreachable!()));

pub fn is_account_store(s: &str) -> bool {
    ACCOUNT_STORE_RE.is_match(s)
}

/// "work" or "claude-work" → "claude-work"; "" when it can't be one
pub fn account_store_name(name: &str) -> String {
    let mut n = name.trim().to_lowercase();
    if !n.starts_with("claude-") {
        n = format!("claude-{n}");
    }
    if n.len() > 48 || !is_account_store(&n) {
        return String::new();
    }
    n
}

/// "chendeyao.uk@gmail.com" → "chendeyao-uk"
pub fn slug_from_email(email: &str) -> String {
    let lower = email.to_lowercase();
    let (local, _, _) = jarvis_go::fmt::cut(&lower, "@");
    let mut b = String::new();
    let mut dash = false;
    for c in local.chars() {
        if c.is_ascii_lowercase() || c.is_ascii_digit() {
            b.push(c);
            dash = false;
        } else if !dash && !b.is_empty() {
            b.push('-');
            dash = true;
        }
    }
    b.trim_matches('-').to_string()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AccountsDoc {
    pub default: String,
    /// the account Jarvis 1 follows (the one the shared login became)
    #[serde(skip_serializing_if = "String::is_empty")]
    pub jarvis1: String,
}

#[derive(Default)]
struct Inner {
    hubs: BTreeMap<String, Arc<LoginHub>>,
    doc: AccountsDoc,
}

pub struct ClaudeAccounts {
    r: std::sync::Weak<Router>,
    st: Arc<crate::state::State>,
    mu: Mutex<Inner>,
}

/// the accounts' list and each account's pair are sealed documents (sealed.rs)
pub const ACCOUNTS_DOC_NAME: &str = "claude-accounts/accounts.json";

pub fn hub_doc(store: &str) -> String {
    format!("claude-accounts/{store}.json")
}

/// remove refused: a session uses the account (409)
#[derive(Debug)]
pub struct AccountConflict(pub String);

impl std::fmt::Display for AccountConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for AccountConflict {}

impl Router {
    /// the router's Claude accounts (loaded on first use)
    pub fn accounts(&self) -> Arc<ClaudeAccounts> {
        self.claude
            .get_or_init(|| {
                let a = Arc::new(ClaudeAccounts {
                    r: self.me.get().cloned().unwrap_or_default(),
                    st: self.st.clone(),
                    mu: Mutex::new(Inner::default()),
                });
                a.load();
                a
            })
            .clone()
    }

    /// the sessions (not destroyed) that use store
    pub fn account_users(&self, store: &str) -> Vec<String> {
        self.st.do_(|d| {
            d.sessions
                .values()
                .filter(|s| s.claude_account == store)
                .map(|s| s.id.clone())
                .collect()
        }) // BTreeMap order: sorted by id
    }
}

impl ClaudeAccounts {
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.mu.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn new_hub(self: &Arc<Self>, store: &str) -> Arc<LoginHub> {
        let h = Arc::new(LoginHub::new(self.st.clone(), &hub_doc(store), store));
        if let Some(r) = self.r.upgrade() {
            let w = Arc::downgrade(&r);
            let _ = h.dm.set(Arc::new(move |text: String| {
                if let Some(r) = w.upgrade() {
                    r.dm(&text);
                }
            }));
        }
        let _ = h.accounts.set(Arc::downgrade(self));
        let (a, h2, store) = (self.clone(), h.clone(), store.to_string());
        std::thread::spawn(move || a.follow(&store, &h2));
        h
    }

    /// reload the hub when another replica changed its document (the mq notification, or every 30 s in case one was
    /// lost), until the account is removed. Part of the reload stopgap (claudelogin.rs reload).
    fn follow(&self, store: &str, h: &Arc<LoginHub>) {
        let Some(r) = self.r.upgrade() else { return };
        let sub = r.notes.sub(&login_note(&h.name));
        drop(r);
        loop {
            sub.recv_timeout(Duration::from_secs(30));
            let gone = !self.lock().hubs.get(store).is_some_and(|x| Arc::ptr_eq(x, h));
            if gone {
                return;
            }
            h.reload();
        }
    }

    fn load(self: &Arc<Self>) {
        match self.st.read_sealed(ACCOUNTS_DOC_NAME) {
            Err(e) => crate::logf!("[accounts] {e:#}"),
            Ok(Some(b)) => {
                if let Ok(d) = jarvis_go::unmarshal::<AccountsDoc>(&b) {
                    self.lock().doc = d;
                }
            }
            Ok(None) => {}
        }
        let names = self.st.list_sealed("claude-accounts/claude-").unwrap_or_else(|e| {
            crate::logf!("[accounts] {e:#}");
            vec![]
        });
        for f in names {
            let store = f
                .trim_start_matches("claude-accounts/")
                .trim_end_matches(".json")
                .to_string();
            if is_account_store(&store) {
                let h = self.new_hub(&store);
                self.lock().hubs.insert(store, h);
            }
        }
    }

    fn save_doc(&self, g: &Inner) -> Result<()> {
        self.st
            .write_sealed(ACCOUNTS_DOC_NAME, jarvis_go::fmt::marshal_indent1(&g.doc).as_bytes())
    }

    /// the account's hub; None = no such account
    pub fn hub(&self, store: &str) -> Option<Arc<LoginHub>> {
        self.lock().hubs.get(store).cloned()
    }

    /// every account's hub, by name
    pub fn all(&self) -> Vec<Arc<LoginHub>> {
        self.lock().hubs.values().cloned().collect()
    }

    pub fn default_store(&self) -> String {
        let g = self.lock();
        if g.hubs.contains_key(&g.doc.default) { g.doc.default.clone() } else { String::new() }
    }

    pub fn default_hub(&self) -> Option<Arc<LoginHub>> {
        self.hub(&self.default_store())
    }

    /// the account Jarvis 1 follows: the one the shared login became, else the default
    pub fn jarvis1_hub(&self) -> Option<Arc<LoginHub>> {
        let g = self.lock();
        if !g.doc.jarvis1.is_empty() {
            return g.hubs.get(&g.doc.jarvis1).cloned();
        }
        g.hubs.get(&g.doc.default).cloned()
    }

    /// the account a new session gets — the one named, else the default; "" with no error when it needs none, or when
    /// there is no account at all
    pub fn resolve(&self, named: &str, needs: bool) -> Result<String> {
        if named.is_empty() {
            if !needs {
                return Ok(String::new());
            }
            // no account at all (a new box before its first sign-in): the session starts logged out
            return Ok(self.default_store());
        }
        let store = account_store_name(named);
        if store.is_empty() || self.hub(&store).is_none() {
            return Err(crate::router::bad(format!(
                "no Claude account {} (Settings → Claude accounts lists them)",
                jarvis_go::fmt::go_quote(named)
            )));
        }
        if !needs {
            return Ok(String::new()); // a harness that takes no Claude account: the name changes nothing
        }
        Ok(store)
    }

    /// where a sign-in of this Claude account belongs: the hub that holds it, else a new account named after its email
    /// (claude-<name>, a number added when taken)
    pub fn hub_for(self: &Arc<Self>, uuid: &str, email: &str) -> Result<Arc<LoginHub>> {
        if !uuid.is_empty()
            && let Some(h) = self.all().into_iter().find(|h| account_uuid(&h.current().account) == uuid)
        {
            return Ok(h);
        }
        let mut base = slug_from_email(email);
        if base.is_empty() {
            base = "account".into();
        }
        for i in 1..100 {
            let name = if i > 1 { format!("{base}-{i}") } else { base.clone() };
            let store = account_store_name(&name);
            if !store.is_empty() && self.hub(&store).is_none() {
                return self.add(&name);
            }
        }
        Err(anyhow!("no free account name for {email}"))
    }

    /// a sign-in into store must be its own account (once it has one) and no other account's
    pub fn check_relogin(&self, store: &str, uuid: &str) -> Result<()> {
        if uuid.is_empty() {
            return Ok(()); // the profile wasn't readable: nothing to check against
        }
        for h in self.all() {
            let cur = h.current();
            let u = account_uuid(&cur.account);
            if h.store == store && !u.is_empty() && u != uuid {
                let e = account_email(&cur.account);
                return Err(anyhow!(
                    "that sign-in is another Claude account than {store}'s ({e}): sign in as {e}, or add it as a new account"
                ));
            }
            if h.store != store && u == uuid {
                return Err(anyhow!("that Claude account is already {}", h.store));
            }
        }
        Ok(())
    }

    pub fn add(self: &Arc<Self>, name: &str) -> Result<Arc<LoginHub>> {
        let store = account_store_name(name);
        if store.is_empty() {
            return Err(anyhow!(
                "name: lowercase letters, digits and single dashes (it becomes claude-<name>)"
            ));
        }
        let mut g = self.lock();
        if let Some(h) = g.hubs.get(&store) {
            return Ok(h.clone()); // it exists: Add is then its sign-in, as Re-login
        }
        let h = self.new_hub(&store);
        h.save_now()?; // the slot exists from here on, signed in or not
        g.hubs.insert(store.clone(), h.clone());
        if g.doc.default.is_empty() || !g.hubs.contains_key(&g.doc.default) {
            g.doc.default = store.clone();
            let _ = self.save_doc(&g);
        }
        crate::logf!("[accounts] {store} added");
        Ok(h)
    }

    pub fn set_default(&self, store: &str) -> Result<()> {
        let mut g = self.lock();
        if !g.hubs.contains_key(store) {
            return Err(anyhow!("no Claude account {store}"));
        }
        g.doc.default = store.to_string();
        self.save_doc(&g)
    }

    /// refused while any session uses the account (Deyao's decision: a session's account is fixed for its life, never
    /// switched); otherwise it goes, the next account becomes the default when it was the default, and its core store
    /// loses its keys. Answers the new default.
    pub fn remove(&self, store: &str) -> Result<String> {
        let r = self.r.upgrade().ok_or_else(|| anyhow!("the router is gone"))?;
        let users = r.account_users(store);
        if !users.is_empty() {
            return Err(AccountConflict(format!(
                "{store} is used by {} session(s) ({}), and a session keeps its account for its life: destroy those sessions first (Previous keeps their archives), then Remove",
                users.len(),
                users.join(", ")
            ))
            .into());
        }
        let to = self.remove_hub(store)?;
        let store = store.to_string();
        std::thread::spawn(move || r.forget_account_store(&store)); // claudestores.rs
        Ok(to)
    }

    fn remove_hub(&self, store: &str) -> Result<String> {
        let h = self.hub(store).ok_or_else(|| anyhow!("no Claude account {store}"))?;
        // not while its refresh or a sign-in is out (taken before mu: finish_login's check takes mu)
        let _r = h.lock_refresh();
        let mut g = self.lock();
        self.st.delete_sealed(&h.name)?;
        g.hubs.remove(store);
        if g.doc.default == store || !g.hubs.contains_key(&g.doc.default) {
            g.doc.default = g.hubs.keys().next().cloned().unwrap_or_default();
        }
        if g.doc.jarvis1 == store {
            g.doc.jarvis1.clear();
        }
        let _ = self.save_doc(&g);
        crate::logf!("[accounts] {store} removed");
        Ok(g.doc.default.clone())
    }

    /// every account's status (no secrets), with its name, whether it is the default and the sessions using it
    pub fn list(&self) -> Value {
        let def = self.default_store();
        let r = self.r.upgrade();
        let rows: Vec<Value> = self
            .all()
            .into_iter()
            .map(|h| {
                let mut st = h.status();
                st.insert("name".into(), json!(h.store.trim_start_matches("claude-")));
                st.insert("default".into(), json!(h.store == def));
                let users = r.as_ref().map(|r| r.account_users(&h.store)).unwrap_or_default();
                st.insert("sessions".into(), json!(users));
                Value::Object(st)
            })
            .collect();
        json!({"default": def, "accounts": rows})
    }
}

fn login_err_status(e: &anyhow::Error) -> u16 {
    if e.downcast_ref::<AccountConflict>().is_some() || is_login_err(e, LoginErr::NoPair) {
        409
    } else {
        400
    }
}

fn no_such(w: &mut W, store: &str) {
    write_json(w, 404, &json!({"error": format!("no Claude account {store}")}));
}

fn refresh(_r: &Arc<Router>, w: &mut W, _req: &mut Req, h: &Arc<LoginHub>) {
    match h.refresh(true) {
        Err(e) => {
            let no_pair = is_login_err(&e, LoginErr::NoPair);
            let msg = format!("{e:#}");
            let status = if no_pair { 409 } else { 502 };
            write_json(w, status, &json!({"error": msg, "needLogin": no_pair || msg.contains("Re-login")}));
        }
        Ok(ok) => write_json(w, 200, &json!({"ok": true, "refreshed": ok, "expiresAt": h.current().expires_at})),
    }
}

fn start(_r: &Arc<Router>, w: &mut W, _req: &mut Req, h: &Arc<LoginHub>) {
    match h.start_login() {
        Err(e) => write_json(w, 500, &json!({"error": format!("{e:#}")})),
        Ok(u) => write_json(w, 200, &json!({"url": u, "store": h.store})),
    }
}

fn code(r: &Arc<Router>, w: &mut W, req: &mut Req, h: &Arc<LoginHub>) {
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct B {
        code: String,
    }
    let b: B = crate::http::decode_body(req, 1 << 16);
    let (email, store) = match h.finish_login(&b.code) {
        Err(e) => return write_json(w, 400, &json!({"error": format!("{e:#}")})),
        Ok(x) => x,
    };
    let exp = r.accounts().hub(&store).map(|t| t.current().expires_at).unwrap_or(0);
    let r2 = r.clone();
    std::thread::spawn(move || r2.resume_stuck_logins());
    let mut out = json!({"ok": true, "store": store, "email": email, "expiresAt": exp});
    if store != h.store {
        out["note"] = json!(format!(
            "That sign-in is {email}, another Claude account than {}'s, so it was added as a new account, {store}. {} is unchanged.",
            h.store, h.store
        ));
    }
    write_json(w, 200, &out);
}

fn usage(_r: &Arc<Router>, w: &mut W, req: &mut Req, h: &Arc<LoginHub>) {
    let (status, mut body): (u16, Map<String, Value>) = h.usage_quota(req.query("refresh") == "1");
    body.insert("store".into(), json!(h.store));
    write_json(w, status, &body);
}

type HubRoute = fn(&Arc<Router>, &mut W, &mut Req, &Arc<LoginHub>);

fn with_hub(f: HubRoute) -> impl Fn(&Arc<Router>, &mut W, &mut Req) + Send + Sync + 'static {
    move |r, w, req| {
        let store = req.path_value("store");
        match r.accounts().hub(&store) {
            None => no_such(w, &store),
            Some(h) => f(r, w, req, &h),
        }
    }
}

/// the default account, for the routes that took no account (app builds from before accounts)
fn with_default(f: HubRoute) -> impl Fn(&Arc<Router>, &mut W, &mut Req) + Send + Sync + 'static {
    move |r, w, req| match r.accounts().default_hub() {
        None => write_json(
            w,
            409,
            &json!({"error": "no Claude account yet: add one in Settings → Claude accounts", "needLogin": true}),
        ),
        Some(h) => f(r, w, req, &h),
    }
}

/// the setup session: its Access token and its key's signature over the request
fn setup_signed(f: fn(&Arc<Router>, &mut W)) -> impl Fn(&Arc<Router>, &mut W, &mut Req) + Send + Sync + 'static {
    move |r, w, req| {
        let b = req.read_body(1 << 20);
        if let Err(e) = r.check_setup_sig(
            &req.method,
            &req.path,
            &req.header("X-Setup-Time"),
            &req.header("X-Setup-Sig"),
            &b,
        ) {
            return write_json(w, 401, &json!({"error": format!("{e:#}")}));
        }
        f(r, w)
    }
}

pub fn register_claude_accounts(reg: &mut Registrar) {
    reg.app("GET /api/claude-accounts", |r, w, _| write_json(w, 200, &r.accounts().list()));
    reg.app("POST /api/claude-accounts", |r, w, req| {
        #[derive(Deserialize)]
        struct B {
            #[serde(default)]
            name: String,
        }
        let b: B = match crate::http::decode_body_strict(req, 1 << 16) {
            Err(_) => return write_json(w, 400, &json!({"error": "body must be {name}"})),
            Ok(b) => b,
        };
        match r.accounts().add(&b.name) {
            Err(e) => write_json(w, 400, &json!({"error": format!("{e:#}")})),
            Ok(h) => start(r, w, req, &h),
        }
    });
    reg.app("POST /api/claude-accounts/{store}/login", with_hub(start));
    reg.app("POST /api/claude-accounts/{store}/code", with_hub(code));
    reg.app("POST /api/claude-accounts/{store}/refresh", with_hub(refresh));
    reg.app("GET /api/claude-accounts/{store}/usage", with_hub(usage));
    reg.app(
        "POST /api/claude-accounts/{store}/default",
        with_hub(|r, w, _, h| match r.accounts().set_default(&h.store) {
            Err(e) => write_json(w, 400, &json!({"error": format!("{e:#}")})),
            Ok(()) => write_json(w, 200, &json!({"ok": true, "default": h.store})),
        }),
    );
    reg.app(
        "DELETE /api/claude-accounts/{store}",
        with_hub(|r, w, _, h| match r.accounts().remove(&h.store) {
            Err(e) => write_json(w, login_err_status(&e), &json!({"error": format!("{e:#}")})),
            Ok(to) => write_json(w, 200, &json!({"ok": true, "default": null_if_empty(&to)})),
        }),
    );

    reg.app("GET /api/claude-login", with_default(|_, w, _, h| write_json(w, 200, &h.status())));
    reg.app("POST /api/claude-login/refresh", with_default(refresh));
    reg.app("POST /api/claude-login/start", with_default(start));
    reg.app("POST /api/claude-login/code", with_default(code));
    reg.app("GET /api/usage", with_default(usage));

    // ---- the setup session: the status ----
    reg.setup_route(
        "GET /setup/claude-accounts",
        setup_signed(|r, w| write_json(w, 200, &r.accounts().list())),
    );
    reg.setup_route(
        "GET /setup/claude-login",
        setup_signed(|r, w| match r.accounts().default_hub() {
            Some(h) => write_json(w, 200, &h.status()),
            None => write_json(w, 409, &json!({"error": "no Claude account yet", "needLogin": true})),
        }),
    );
}
