//! The router (main.go's Config, flows.go's Router): chains the core's and the kernel's primitives into sessions and
//! serves the app, the web page and the session machines.

use crate::core::CoreClient;
use crate::kernel::KernelClient;
use crate::linestate::LineKeeper;
use crate::nethttp::Mux;
use crate::state::State;
use std::collections::BTreeMap;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::Duration;

#[derive(Debug, Clone, Default)]
pub struct Config {
    /// the core, inside the cluster
    pub core_url: String,
    /// NO_CORE=1: this box runs no core, only the kernel (Jarvis 4); GET /api/kernel says so
    pub no_core: bool,
    /// the kernel's components, %s = the Deployment "<role>-<copy>" (KERNEL_URL; "" = no kernel on this box)
    pub kernel_url: String,
    /// snapshots and the other files (a volume); the records are in Postgres (statedb.rs)
    pub data_dir: String,
    /// the web page (expo export), served at /
    pub web_dir: String,
    /// the image new sessions get (a tag; resume pins what Fly reported)
    pub session_image: String,
    /// CI's signature over it (images.yml; keys/ci.pub)
    pub session_image_sig: String,
    /// every earlier CI-pinned session image → its signature (SESSION_IMAGE_SIGS_FILE)
    pub image_sigs: BTreeMap<String, String>,
    /// the same images in pin order (the file's line order)
    pub image_order: Vec<String>,
    /// Fly region for session machines
    pub region: String,
    /// how machines reach the router (JARVIS2_URL on the machine)
    pub machine_url: String,
    /// e.g. de0ch.cloudflareaccess.com
    pub access_team: String,
    /// the Access app audience for /api and /
    pub app_aud: String,
    /// the Access app audience for /setup (service token jarvis2-setup)
    pub setup_aud: String,
    /// the setup session's public key: it signs every /setup call
    pub setup_key: String,
    /// the only person
    pub allowed_email: String,
    /// CI only: no Cloudflare in front, skip the JWT checks
    pub no_access: bool,
    /// snapwait.rs: a pause stops waiting for the machine's snapshot after this long with no progress
    pub snapshot_stall: Duration,
}

pub fn env(k: &str, def: &str) -> String {
    match std::env::var(k) {
        Ok(v) if !v.is_empty() => v,
        _ => def.to_string(),
    }
}

/// a lifecycle action holds the session already (409); the detail follows the message (Go's fmt.Errorf("%w: …",
/// errBusy, …)), "" for none
#[derive(Debug)]
pub struct Busy(pub String);

pub const BUSY_MSG: &str = "the session is in the middle of another action";

impl std::fmt::Display for Busy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0.is_empty() {
            f.write_str(BUSY_MSG)
        } else {
            write!(f, "{BUSY_MSG}: {}", self.0)
        }
    }
}

impl std::error::Error for Busy {}

/// a caller asked for something wrong (400): Go's badRequest, one type with inbox.rs's
pub use crate::inbox::BadRequest as BadReq;

pub fn bad(msg: impl Into<String>) -> anyhow::Error {
    BadReq(msg.into()).into()
}

static ROUTER_ID: OnceLock<String> = OnceLock::new();

/// this replica's name (the pod's, else the host's with a random suffix): the jobs' and leases' holder
pub fn router_id() -> String {
    ROUTER_ID
        .get_or_init(|| {
            let host = std::env::var("POD_NAME")
                .ok()
                .filter(|s| !s.is_empty())
                .or_else(|| {
                    nix::unistd::gethostname()
                        .ok()
                        .map(|h| h.to_string_lossy().into_owned())
                })
                .unwrap_or_else(|| "router".into());
            format!("{host}-{}", crate::util::rand_id())
        })
        .clone()
}

pub struct Router {
    pub cfg: Config,
    pub st: Arc<State>,
    pub core: Arc<CoreClient>,
    /// linestate.rs: the core's line state
    pub lines: OnceLock<Arc<LineKeeper>>,
    /// kernel.rs, kernelline.rs; None while this box has none (KERNEL_URL unset)
    pub kernel: Option<Arc<KernelClient>>,
    /// linestate.rs: the kernel secrets' line state
    pub kernel_lines: OnceLock<Arc<LineKeeper>>,
    /// on a box with no core (NO_CORE=1), the store calls go to the kernel's serving secrets
    pub secrets_stores: OnceLock<Arc<CoreClient>>,
    /// kernelhealth.rs: the kernel's health as last checked (None: not checked yet)
    pub kernel_health_now: Mutex<Option<crate::kernelhealth::KernelHealth>>,
    /// objstore.rs: the router's blobs (the bucket, or memory for a router with none)
    pub objects: Arc<dyn crate::objstore::ObjStore>,
    /// the spawner's missing Fly token was DMed (once, until a token comes)
    pub kernel_token_dmed: AtomicBool,
    pub cmd_mu: Mutex<()>,
    /// mq.rs: this replica's waiters on the machines' queue, woken by the database
    pub notes: Arc<crate::mq::Broker>,
    pub hk: crate::grants::Holders,
    /// drain.rs: the lifecycle actions running, refused once SIGTERM came
    pub drain: crate::drain::DrainState,
    /// sessionops.rs: busy marks, permission-mode/restart jobs, uploads, repos
    pub ops: crate::sessionops::OpsState,
    pub policy: crate::policy::Policy,
    pub setup_seen: Mutex<BTreeMap<String, i64>>,
    /// claudeaccounts.rs: the Claude accounts and their logins
    pub claude: OnceLock<Arc<crate::claudeaccounts::ClaudeAccounts>>,
    /// this router, for what it hands out a weak reference to (set by new)
    pub me: OnceLock<std::sync::Weak<Router>>,
    /// nextcore.rs: the next core and the flip
    pub next: crate::nextcore::NextCores,
    /// archive.rs: the Storage Box this router uses instead of the env's (tests: Some(None) = none)
    pub box_override: RwLock<Option<Option<Arc<crate::storagebox::StorageBox>>>>,
    /// flows.rs SILENT_AFTER_SECS for this router (tests shorten it): a machine silent this long isn't waited for
    pub silent_after_secs: std::sync::atomic::AtomicI64,
    /// schedule.rs: tests catch deliveries here (vouch.rs deliver_vouched otherwise)
    pub deliver_hook: RwLock<Option<crate::schedule::DeliverHook>>,
    /// schedule.rs: tests catch the resume of a failed session here (the app's Resume otherwise)
    pub resume_failed_hook: RwLock<Option<crate::schedule::ResumeHook>>,
    /// archive.rs: this router keeps no records on the Storage Box, as RECORDS_OFF=1 (tests)
    pub records_off: std::sync::atomic::AtomicBool,
    /// discord.rs: this router's DMs go here instead of the bot (tests)
    pub dm_hook: RwLock<Option<crate::discord::DmHook>>,
    /// tests: this router's own Discord client instead of the global one (tests run side by side)
    pub disc_hook: RwLock<Option<Arc<crate::discord::DiscordClient>>>,
    pub muxes: OnceLock<(Arc<Mux>, Arc<Mux>)>,
    /// http.rs: every app route's pattern (apicalls.rs classifies them)
    pub app_patterns: OnceLock<BTreeMap<String, bool>>,
    /// supervisorlog.rs: the machines' supervisor logs
    pub sup: crate::supervisorlog::SupLogs,
    /// lifecycle.rs: each session's lifecycle operations and their logs
    pub lc: crate::lifecycle::Lifecycle,
    /// handover.rs: session id → the next machine started while the old one stops
    pub spares: Mutex<BTreeMap<String, Arc<crate::handover::Spare>>>,
}

impl Router {
    pub fn new(
        cfg: Config,
        st: Arc<State>,
        core: Arc<CoreClient>,
        policy: crate::policy::Policy,
    ) -> Arc<Router> {
        let objects: Arc<dyn crate::objstore::ObjStore> = match crate::objstore::objects_from_env()
        {
            Err(e) => {
                crate::logf!("objects: {e:#}");
                std::process::exit(1);
            }
            Ok(Some(o)) => o,
            Ok(None) => Arc::new(crate::objstore::MemObjects::default()),
        };
        let kernel = KernelClient::new(&cfg.kernel_url).map(Arc::new);
        let r = Arc::new(Router {
            cfg,
            st,
            core,
            lines: OnceLock::new(),
            kernel,
            kernel_lines: OnceLock::new(),
            secrets_stores: OnceLock::new(),
            kernel_health_now: Mutex::new(None),
            objects,
            kernel_token_dmed: AtomicBool::new(false),
            cmd_mu: Mutex::new(()),
            notes: Arc::new(crate::mq::Broker::default()),
            hk: Default::default(),
            drain: Default::default(),
            ops: Default::default(),
            policy,
            setup_seen: Mutex::new(BTreeMap::new()),
            claude: OnceLock::new(),
            me: OnceLock::new(),
            next: crate::nextcore::NextCores::from_env(),
            box_override: RwLock::new(None),
            dm_hook: RwLock::new(None),
            disc_hook: RwLock::new(None),
            records_off: std::sync::atomic::AtomicBool::new(false),
            deliver_hook: RwLock::new(None),
            resume_failed_hook: RwLock::new(None),
            silent_after_secs: std::sync::atomic::AtomicI64::new(
                crate::flows::SILENT_AFTER_SECS.load(std::sync::atomic::Ordering::Relaxed),
            ),
            muxes: OnceLock::new(),
            app_patterns: OnceLock::new(),
            sup: Default::default(),
            lc: Default::default(),
            spares: Mutex::new(BTreeMap::new()),
        });
        {
            let w = Arc::downgrade(&r);
            if let Ok(mut g) = r.st.on_failed.lock() {
                *g = Some(Arc::new(move |s: &str, why: &str| {
                    if let Some(r) = w.upgrade() {
                        r.failure_event(s, why)
                    }
                }));
            }
        }
        if let Some(db) = r.st.db() {
            let b = r.notes.clone();
            let url = db.url.clone();
            let done = db.done.clone();
            std::thread::spawn(move || crate::mq::listen_loop(&url, &done, &b)); // mq.rs
        }
        let _ = r.me.set(Arc::downgrade(&r));
        r.wire_kernel();
        // linestate.rs: the core's line state, kept as its answers name a new one
        let lk = LineKeeper::new_core(r.st.clone(), r.core.clone());
        let lk2 = lk.clone();
        *r.core
            .on_line_seq
            .write()
            .unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(move |s| lk2.seen(s)));
        let _ = r.lines.set(lk);
        r
    }

    /// this router as an Arc (every Router is made by Router::new, which keeps its own weak reference)
    pub fn arc(&self) -> Arc<Router> {
        self.me
            .get()
            .and_then(std::sync::Weak::upgrade)
            .unwrap_or_else(|| unreachable!("a Router made outside Router::new"))
    }

    pub fn lines(&self) -> Option<&Arc<LineKeeper>> {
        self.lines.get()
    }
}
