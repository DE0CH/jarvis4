//! The Jarvis 4 router (docs/API.md): chains the core's primitives into sessions and serves the app, the web page and
//! the session machines. It is untrusted by design (docs/DESIGN.md): a bug here can fail or stall an action, but every
//! document that matters is signed by the core or the iPhone and checked at the far end, so it can't move a store to a
//! machine nobody approved.

#[macro_use]
pub mod util;
pub mod accountswap;
pub mod actions;
pub mod apicalls;
pub mod archive;
pub mod archivetar;
pub mod autopilot;
pub mod awsbudget;
pub mod awslogs;
pub mod awsowner;
pub mod awsread;
pub mod awsrunner;
pub mod backups;
pub mod batches;
pub mod bbbudget;
pub mod bootfailed;
pub mod budget;
pub mod carry;
pub mod claimdevice;
pub mod claudeaccounts;
pub mod claudelogin;
pub mod claudestores;
pub mod content;
pub mod core;
pub mod corechange;
pub mod ctx;
pub mod db;
pub mod devices;
pub mod discord;
pub mod disk;
pub mod drain;
pub mod fabricrunner;
pub mod failures;
pub mod features;
pub mod flows;
pub mod flyorgs;
pub mod grants;
pub mod handover;
pub mod harness;
pub mod healthz;
pub mod http;
pub mod inbox;
pub mod jarvis1import;
pub mod jobs;
pub mod kernel;
pub mod kernelflip;
pub mod kernelhealth;
pub mod kernelline;
pub mod leaderlease;
pub mod leases;
pub mod legacy;
pub mod lifecycle;
pub mod linestate;
pub mod livearchive;
pub mod livepush;
pub mod livesync;
pub mod livetail;
pub mod lockedstore;
pub mod lostmachine;
pub mod machines;
pub mod machinesig;
pub mod memory;
pub mod messages;
pub mod mgateway;
pub mod mq;
pub mod nethttp;
pub mod neverbooted;
pub mod nextcore;
pub mod objstore;
pub mod oneshot;
pub mod outcomes;
pub mod peer;
pub mod peermsg;
pub mod policy;
pub mod procstat;
pub mod regions;
pub mod registry;
pub mod relogin;
pub mod remote;
pub mod repos;
pub mod restore;
pub mod roster;
pub mod router;
pub mod runners;
pub mod schedule;
pub mod screens;
pub mod sealed;
pub mod searchsvc;
pub mod sessionapi;
pub mod sessionevents;
pub mod sessionlog;
pub mod sessionops;
pub mod setupservices;
pub mod sizes;
pub mod snapdirect;
pub mod snapformat;
pub mod snapprogress;
pub mod snapsafe;
pub mod snapstore;
pub mod snapstream;
pub mod snapwait;
pub mod state;
pub mod statedb;
pub mod statestats;
pub mod storagebox;
pub mod storedocs;
pub mod storerestore;
pub mod storeversions;
pub mod supervisorlog;
pub mod tails;
pub mod tasks;
pub mod terminal;
pub mod termpage;
#[cfg(test)]
mod tests;
#[cfg(test)]
pub mod testutil;
pub mod timemachine;
pub mod titles;
pub mod types;
pub mod uploads;
pub mod volsweep;
pub mod vouch;
pub mod watches;
pub mod wgserve;

use crate::router::{Config, Router, env};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

fn fatal(msg: impl std::fmt::Display) -> ! {
    logf!("{msg}");
    std::process::exit(1);
}

fn main() {
    crate::procstat::mark_start();
    if std::env::args().nth(1).as_deref() == Some("m-gateway") {
        // mgateway.rs: the machines' WireGuard peer, in its own Deployment
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap_or_else(|e| fatal(format!("m-gateway: {e}")));
        if let Err(e) = rt.block_on(crate::mgateway::command()) {
            fatal(format!("{e:#}"));
        }
        return;
    }
    let stall: u64 = env("SNAPSHOT_STALL_SECONDS", "600").parse().unwrap_or(0);
    let sigs_file = std::env::var("SESSION_IMAGE_SIGS_FILE").unwrap_or_default();
    let cfg = Config {
        core_url: env(
            "CORE_URL",
            "http://core.jarvis2-core.svc.cluster.local:8090",
        ),
        kernel_url: std::env::var("KERNEL_URL").unwrap_or_default(),
        no_core: std::env::var("NO_CORE").as_deref() == Ok("1"),
        data_dir: env("DATA_DIR", "/data"),
        web_dir: env("WEB_DIR", "/web"),
        session_image: env("SESSION_IMAGE", "ghcr.io/de0ch/jarvis4-session:latest"),
        session_image_sig: std::env::var("SESSION_IMAGE_SIG").unwrap_or_default(),
        image_sigs: crate::flows::load_image_sigs(&sigs_file),
        image_order: crate::flows::load_image_order(&sigs_file),
        region: env("FLY_REGION", "lhr"),
        machine_url: std::env::var("MACHINE_URL").unwrap_or_default(),
        access_team: env("ACCESS_TEAM", "de0ch.cloudflareaccess.com"),
        app_aud: std::env::var("ACCESS_APP_AUD").unwrap_or_default(),
        setup_aud: std::env::var("ACCESS_SETUP_AUD").unwrap_or_default(),
        setup_key: std::env::var("SETUP_KEY").unwrap_or_default(),
        allowed_email: env("ALLOWED_EMAIL", "chendeyao000@gmail.com"),
        no_access: std::env::var("NO_ACCESS").as_deref() == Ok("1"),
        snapshot_stall: Duration::from_secs(stall),
    };
    if cfg.no_access {
        logf!("NO_ACCESS=1: Cloudflare Access checks are OFF (CI only)");
    } else if cfg.app_aud.is_empty() || cfg.setup_aud.is_empty() {
        fatal("ACCESS_APP_AUD and ACCESS_SETUP_AUD are required (or NO_ACCESS=1 in CI)");
    }
    if cfg.machine_url.is_empty() {
        logf!("MACHINE_URL unset: machines will have no router address");
    }
    // the records are in Postgres (statedb.rs): the database first, before this pod listens or stands by, so a pod
    // that can't reach it (a wrong password, the database down) never becomes ready or takes over from a working leader
    let db_url = std::env::var("DATABASE_URL").unwrap_or_default();
    if db_url.is_empty() {
        fatal("DATABASE_URL is required: the router's records are in Postgres (docs/STATE.md)");
    }
    let db = crate::db::open_db_wait(&db_url);
    // the blobs are in object storage (objstore.rs); only a throwaway router (CI's stand-ins, e2e) keeps them in memory
    let throwaway = std::env::var("ROUTER_THROWAWAY").as_deref() == Ok("1");
    if std::env::var("OBJECTS_ACCESS_KEY")
        .unwrap_or_default()
        .is_empty()
        && !throwaway
    {
        fatal(
            "OBJECTS_ACCESS_KEY / OBJECTS_SECRET_KEY are required (Secret router-secrets-objects), or ROUTER_THROWAWAY=1 for a throwaway router",
        );
    }
    if !std::env::var("WG_CONFIG").unwrap_or_default().is_empty() {
        fatal(
            "WG_CONFIG: the machines' WireGuard peer runs in m-gateway (`router m-gateway`), not in the router",
        );
    }
    let (addr, maddr) = (env("ADDR", ":8080"), env("MACHINE_ADDR", ":8081"));
    // each core call has its own deadline (core.rs core_call_timeout)
    let core = Arc::new(crate::core::CoreClient::new(&cfg.core_url));
    let seal = crate::sealed::sealer_from_env().unwrap_or_else(|e| fatal(format!("{e:#}")));
    let st = crate::state::State::open(db, std::path::Path::new(&cfg.data_dir), Some(seal))
        .unwrap_or_else(|e| fatal(format!("{e:#}")));
    let policy = crate::policy::load_policy(&env("POLICY_FILE", "/policy/stores.json"))
        .unwrap_or_else(|e| fatal(format!("{e:#}")));
    let r = Router::new(cfg, Arc::new(st), core.clone(), policy);
    if let Err(e) = r.probe_objects(throwaway) {
        fatal(format!("objects: {e:#}"));
    }
    r.apply_active_core(); // nextcore.rs: the core a flip left serving
    r.start_features();
    r.lease_once(); // leaderlease.rs: the scheduler's lease (one replica runs the loops)
    let go = |f: fn(&Arc<Router>)| {
        let r = r.clone();
        std::thread::spawn(move || f(&r));
    };
    go(|r| r.lease_loop_scheduler()); // and kept
    go(|r| r.mq_sweep_loop()); // mq.rs: the machines' queue rows older than a day
    go(|r| r.jobs_loop(Duration::from_secs(5))); // jobs.rs: a job whose holder died is carried on here
    go(|r| r.roster_loop(Duration::from_secs(60))); // roster.rs: a restarted component gets the roster again
    go(|r| r.kernel_health_loop(crate::kernelhealth::KERNEL_HEALTH_EVERY)); // what the app warns about with no core
    go(|r| r.kernel_flip_loop()); // kernelflip.rs: a copy flip that didn't finish (a restart mid-flip) goes on
    go(|r| {
        let drain_max: u64 = env("DRAIN_SECONDS", "1740").parse().unwrap_or(0);
        r.next_core_loop(Duration::from_secs(30), Duration::from_secs(drain_max))
    });
    // two listeners, both in the pod network: the public one (cloudflared → app, web, setup; GET /readyz for the
    // probe) and the machines' one (only m-gateway reaches it, mgateway). Every replica serves both: the records are in
    // Postgres, the machines' queue too (mq.rs), the jobs carry on anywhere (jobs.rs).
    let stopping = Arc::new(AtomicBool::new(false));
    let mut public = crate::nethttp::Mux::new();
    let s2 = stopping.clone();
    public.handle(
        "GET /readyz",
        Arc::new(move |w, _| {
            let (code, state) = if s2.load(Ordering::SeqCst) {
                (503, "stopping")
            } else {
                (200, "serving")
            };
            crate::nethttp::write_json(w, code, &serde_json::json!({"state": state}));
        }),
    );
    public.handle("/", r.handler());
    let public = Arc::new(public);
    let public_h: crate::nethttp::Handler = Arc::new(move |w, req| public.serve(w, req));
    let machine_h = r.machine_handler();
    let fabric = std::env::var("FABRIC_MACHINE_ADDR").unwrap_or_default();
    let fabric_h = (!fabric.is_empty() && crate::fabricrunner::fabric_enabled()).then(|| {
        r.fabric_machine_handler(Arc::new(crate::fabricrunner::HermitKeys::new(Box::new(
            crate::fabricrunner::fetch_hermit_keys,
        ))))
    });
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|e| fatal(e));
    let stop = tokio_util::sync::CancellationToken::new();
    let mut servers = vec![];
    for (a, h) in [(addr.clone(), public_h), (maddr.clone(), machine_h)]
        .into_iter()
        .chain(fabric_h.map(|h| (fabric.clone(), h)))
    {
        let stop = stop.clone();
        servers.push(rt.spawn(async move {
            if let Err(e) = crate::nethttp::serve(&a, h, stop).await {
                fatal(format!("{a}: {e:#}"));
            }
        }));
    }
    logf!(
        "router {} on {addr} and {maddr} (core {})",
        crate::router::router_id(),
        core.url()
    );
    // SIGTERM (a rollout, a node drain): this replica leaves the Service (readyz 503), hands the scheduler's lease on,
    // lets its running jobs end (up to JOB_GRACE_SECONDS, under the pod's terminationGracePeriodSeconds: a job still
    // running then is carried on by another replica once its lease lapses, jobs.rs), lets a Claude login refresh in
    // flight finish, then closes its listeners (a long poll ends; the machine polls again, through the gateway, on
    // another replica).
    rt.block_on(async {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .unwrap_or_else(|e| fatal(e));
        tokio::select! {
            _ = term.recv() => {}
            _ = tokio::signal::ctrl_c() => {}
        }
    });
    stopping.store(true, Ordering::SeqCst);
    logf!(
        "stopping: out of the Service, the scheduler's lease handed on, waiting for this replica's jobs"
    );
    r.release_lead();
    std::thread::sleep(Duration::from_secs(5)); // the readiness probe sees it first
    let grace: u64 = env("JOB_GRACE_SECONDS", "1740").parse().unwrap_or(0);
    let end = Instant::now() + Duration::from_secs(grace);
    while Instant::now() < end && r.my_running_jobs() > 0 {
        std::thread::sleep(Duration::from_secs(1));
    }
    let n = r.my_running_jobs();
    if n > 0 {
        logf!(
            "stopping with {n} job(s) running: another replica carries them on once their lease lapses"
        );
    }
    r.drain_logins(Duration::from_secs(20));
    if let Some(l) = r.lines() {
        l.flush(); // linestate.rs: the newest line state into the bucket before the router goes
    }
    stop.cancel();
    rt.block_on(async {
        let _ = tokio::time::timeout(
            Duration::from_secs(30),
            futures_util::future::join_all(servers),
        )
        .await;
    });
    logf!("stopped");
}
