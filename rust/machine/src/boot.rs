//! The boot steps (main.go's boot half): `prepare` (as user claude, a child of the keeper): make the machine's key
//! pairs, wait for init, then check the succession cert, restore the predecessor's snapshot, have the supervisor pull
//! the secrets, clone the repos and hand the harness's env (no secret value) to the keeper. Any failed check → start
//! nothing. `init`: what the core runs through Fly exec. Adding a store and waiting for it.

use crate::cert::{Cert, cert_mode};
use crate::client::Client;
use crate::crypto::{Keys, SignedDoc, load_private, open_sealed, read_trim, verify_doc};
use crate::secrets::{SecretsReq, StoresLocked, ask_secrets};
use crate::session::session_command;
use crate::vouch::{CORE_KEY_ENV, HarnessSpec};
use crate::{deliver, gojson, logf, machine_id, paths, util};
use anyhow::{Result, anyhow, bail};
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap};
use std::io::Write;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

/// the boot steps, as user claude, a child of the keeper (which already threw away the env this machine was started
/// with). On success the harness's env (no secret value) goes to the keeper on fd 3 and this process ends.
pub fn prepare_cmd() -> Result<()> {
    keygen().map_err(|e| anyhow!("keygen: {e:#}"))?;
    crate::supervisorlog::log_to_supervisor_log(); // boot's lines are the first of the supervisor log
    logf!("keys ready; waiting for init");
    while !paths::go_path().exists() {
        util::sleep(Duration::from_secs(1));
    }
    let spec = match prepare() {
        Ok(s) => s,
        Err(e) => {
            // any failed check → start nothing; the keeper keeps the machine (and the supervisor) up, so the failure
            // stays visible in its log. The router is told why, so the session fails with the reason
            if let Ok(c) = Client::new() {
                report_boot_failed(&c, &format!("{e:#}"));
            }
            bail!("REFUSING TO START: {e:#}");
        }
    };
    // fd 3: the pipe the keeper handed over (keeper.rs start_prepare), reopened through /proc
    let mut out = std::fs::OpenOptions::new()
        .write(true)
        .open("/proc/self/fd/3")
        .map_err(|_| anyhow!("no fd 3 from the keeper"))?;
    out.write_all(format!("{}\n", gojson::marshal(&spec)).as_bytes())?;
    Ok(())
}

/// how often a refused start is told to the router, how long each try may take, the wait between
const BOOT_REPORT_TRIES: u32 = 3;

/// Tell the router why this machine starts nothing (POST /m/boot-failed: its session becomes failed with the reason).
/// Best effort; a router without the route (404) isn't asked again.
pub fn report_boot_failed(c: &Client, why: &str) {
    let mut rc = c.clone();
    rc.timeout = Some(Duration::from_secs(20));
    let body = gojson::marshal(&BTreeMap::from([("error", why)]));
    let mut tr = 1;
    loop {
        let r = rc.raw("POST", "/m/boot-failed", body.as_bytes(), &[]);
        let err = match r {
            Ok(r) if r.status == 200 => {
                logf!("told the router this machine refused to start");
                return;
            }
            Ok(r) if r.status == 404 || r.status == 405 => return, // an older router
            Ok(r) => format!("HTTP {}", r.status),
            Err(e) => format!("{e:#}"),
        };
        if tr >= BOOT_REPORT_TRIES {
            logf!("telling the router this machine refused to start: {err}");
            return;
        }
        util::sleep(Duration::from_secs(2));
        tr += 1;
    }
}

/// the one command the core runs through Fly (no arguments). It prints this machine's public keys (the core binds them
/// into the cert) and lets boot go on.
pub fn init_cmd() -> Result<()> {
    let mut b = Err(anyhow!("no keys"));
    for _ in 0..60 {
        // boot makes the keys first
        match std::fs::read(paths::keys_path()) {
            Ok(x) => {
                b = Ok(x);
                break;
            }
            Err(e) => {
                b = Err(e.into());
                util::sleep(Duration::from_secs(1));
            }
        }
    }
    let b = b.map_err(|e| anyhow!("no keys yet: {e:#}"))?;
    util::write_file(&paths::go_path(), util::now_rfc3339().as_bytes(), 0o644)?;
    std::io::stdout().write_all(&b)?;
    Ok(())
}

pub fn keygen() -> Result<()> {
    sudo(&[
        "install",
        "-d",
        "-o",
        "claude",
        "-m",
        "755",
        &paths::dir().to_string_lossy(),
    ])?;
    let k = Keys::generate();
    util::write_file(&paths::priv_path(), k.private_json().as_bytes(), 0o600)?;
    util::write_file(&paths::keys_path(), k.public_json().as_bytes(), 0o644)?;
    Ok(())
}

pub fn sudo(args: &[&str]) -> Result<()> {
    let st = if nix::unistd::Uid::effective().is_root() {
        std::process::Command::new(args[0])
            .args(&args[1..])
            .status()?
    } else {
        std::process::Command::new("sudo")
            .arg("-n")
            .args(args)
            .status()?
    };
    if !st.success() {
        bail!("{}: {st}", args.join(" "));
    }
    Ok(())
}

pub fn own_keys() -> Result<HashMap<String, String>> {
    Ok(gojson::unmarshal(&std::fs::read(paths::keys_path())?)?)
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Certs {
    cert: Option<SignedDoc>,
    #[serde(rename = "predecessorCert")]
    predecessor_cert: Option<SignedDoc>,
}

pub fn prepare() -> Result<HarnessSpec> {
    let me = machine_id();
    // the core: the one that created this machine. It sets its signing key in the machine's Fly config, and only the
    // core's Fly token can create or change machines in this app, so the key comes from the core through Fly, never
    // from the router.
    let core_key = crate::env::get(CORE_KEY_ENV)
        .trim()
        .to_string();
    let kernel = !crate::env::get(crate::kernelboot::KERNEL_ROOT_ENV)
        .trim()
        .is_empty();
    if core_key.is_empty() && !kernel {
        bail!("no core key in the machine's config ({CORE_KEY_ENV})");
    }
    let keys = own_keys()?;
    let c = Client::new()?;
    // 0. supervisor-core is the keeper's, up since init asked: until booted exists a snapshot command gets "nothing to
    // snapshot"
    let _ = std::fs::remove_file(paths::booted_path());

    // 1. this machine's succession cert: core-signed, naming this machine and its own keys (a kernel machine: its kernel
    // documents, kernelboot.rs)
    let k = |n: &str| keys.get(n).cloned().unwrap_or_default();
    let mut certs = Certs::default();
    let cert: Cert = if kernel {
        crate::kernelboot::kernel_boot_cert(&c, &me, &keys)?
    } else {
        let mut i = 0;
        loop {
            match c.json::<(), Certs>("GET", "/m/cert", None) {
                Ok(cs) if cs.cert.is_some() => {
                    certs = cs;
                    break;
                }
                r => {
                    if i > 300 {
                        let e = r
                            .err()
                            .map(|e| format!("{e:#}"))
                            .unwrap_or_else(|| "<nil>".into());
                        bail!("no cert: {e}");
                    }
                }
            }
            i += 1;
            util::sleep(Duration::from_secs(2));
        }
        util::write_file(&paths::core_key_path(), core_key.as_bytes(), 0o644)?;
        let cert: Cert = match verify_doc::<Cert>(&core_key, certs.cert.as_ref()) {
            Ok(c) if c.kind == "succession-cert" && c.machine.is_some() => c,
            Ok(_) => bail!("the cert isn't a succession cert signed by the core (<nil>)"),
            Err(e) => bail!("the cert isn't a succession cert signed by the core ({e:#})"),
        };
        let m = cert.machine();
        if m.id != me || m.encryption_key != k("encryptionKey") || m.signing_key != k("signingKey")
        {
            bail!("the cert names another machine or other keys");
        }
        let _ = util::write_file(
            &paths::cert_path(),
            gojson::marshal(&certs.cert).as_bytes(),
            0o644,
        );
        cert
    };
    logf!(
        "cert ok: stores {}, harness {}, predecessor {}",
        go_list(&cert.stores()),
        cert.options.harness,
        util::go_quote(&cert.pred_id)
    );

    let mut v = crate::vouch::vouch(&cert)?; // what the cert vouches for
    v.ex = crate::vouch::fetch_exceptions(&c); // the few router values whose format can't carry an instruction
    crate::vouch::write_vouched(&v);
    let first_machine = cert.pred_id.is_empty();

    // 1b. the volume: the state's directories onto it, before anything is restored there
    crate::volume::setup_volume();

    // 2. the predecessor's snapshot: the one whose hash the cert names, signed by the predecessor
    if kernel && !cert.snapshot.is_empty() {
        crate::kernelboot::kernel_restore(&c, &cert.snapshot)
            .map_err(|e| anyhow!("snapshot: {e:#}"))?;
        // a new line restoring an archive: its line keys come with it (deliver.rs)
        deliver::RESTORED_ARCHIVE.store(first_machine, Ordering::SeqCst);
    } else if kernel {
        if !first_machine {
            logf!(
                "the source names no snapshot of {}: starting with no predecessor state",
                cert.pred_id
            );
        }
    } else if !first_machine && cert.pred_id != me {
        let pc: Cert = match verify_doc::<Cert>(&core_key, certs.predecessor_cert.as_ref()) {
            Ok(pc)
                if pc.kind == "succession-cert"
                    && pc.machine.as_ref().is_some_and(|m| m.id == cert.pred_id) =>
            {
                pc
            }
            r => bail!(
                "the predecessor's cert isn't core-signed for {} ({})",
                cert.pred_id,
                r.err()
                    .map(|e| format!("{e:#}"))
                    .unwrap_or_else(|| "<nil>".into())
            ),
        };
        let pkey = pc.machine().signing_key;
        if !cert.snapshot.is_empty() {
            set_predecessor_key(&pkey);
            crate::snapshot::restore(&c, &pkey, &v).map_err(|e| anyhow!("snapshot: {e:#}"))?;
        } else if v.config.restore.is_some() {
            // a line whose machines never left a snapshot (an import stopped mid-way): the import its signed config
            // names again, Jarvis 1 imports only
            set_predecessor_key(&pkey);
            crate::restore::reimport_jarvis1(&c, &v).map_err(|e| anyhow!("re-import: {e:#}"))?;
        } else {
            logf!(
                "the cert names no snapshot of {}: starting with no predecessor state",
                cert.pred_id
            );
        }
        if !v.once.rollback.is_empty() {
            // only a rollback the phone approved, on the verified snapshot
            crate::rollback::apply_rollback(&v.once.rollback);
        }
    }
    // 2b. a new line restoring a destroyed session's archived snapshot: only the one the cert names
    let mut cert = cert;
    if !kernel {
        crate::restore::restore_archived(&c, &core_key, &me, &mut cert, &v)
            .map_err(|e| anyhow!("restore: {e:#}"))?;
    }
    deliver::trust_line_keys(&cert); // this line's signing keys, for what it asked to be delivered later

    // 3. the secrets, sealed to this machine's encryption key: the supervisor pulls them and holds them in RAM; boot
    // takes them from it for the harness's env. A store still locked after the wait doesn't stop the start: the
    // session runs with none of its secrets and gets them when Deyao's unlock goes through
    let mut secrets: HashMap<String, String> = HashMap::new();
    match ask_secrets(
        &SecretsReq {
            op: "pull".into(),
            ..Default::default()
        },
        Duration::from_secs(20 * 60),
    ) {
        Err(e) if e.downcast_ref::<StoresLocked>().is_some() => logf!(
            "{e:#}: starting without secrets; the supervisor takes them once the store is unlocked (Unlock… in the app, or `jarvis-request unlock`)"
        ),
        Err(e) => return Err(e),
        Ok(_) => {
            crate::keeper::await_harness_pid(Duration::from_secs(10)); // the keeper names this process first
            // the repos and a task's env (the harness gets its own from the keeper)
            let r = ask_secrets(
                &SecretsReq {
                    op: "boot-env".into(),
                    ..Default::default()
                },
                Duration::from_secs(60),
            )?;
            secrets.extend(r.secrets);
        }
    }
    logf!(
        "secrets ok: {} keys (held by the supervisor, in RAM)",
        secrets.len()
    );

    // 4. repos: each repo's deploy key is in the supervisor's ssh-agent, then the clones the cert names
    clone_repos(&crate::vouch::repos_to_clone(&v, &secrets));
    crate::jarvis1import::place_imported_transcripts(); // an import's transcripts, under the working dir's project
    crate::jarvis1import::rearm_jarvis1(&c, &crate::vouch::session_id(&me)); // its wakeups and crons, as this line's own

    // 5. booted: from now on a snapshot command gets a real snapshot; then the keeper runs the harness, unless a pause
    // already took the predecessor's snapshot as this machine's (snapstream.rs): it goes no further
    crate::snapstream::hold_if_carried();
    util::write_file(&paths::booted_path(), util::now_rfc3339().as_bytes(), 0o644)
        .map_err(|e| anyhow!("booted marker: {e}"))?;
    let clean: Vec<String> = crate::env::vars().into_iter().map(|(k, v)| format!("{k}={v}")).collect(); // already the clean env
    if let Some(t) = cert
        .options
        .harness
        .strip_prefix(crate::task::TASK_HARNESS_PREFIX)
    {
        for kv in crate::vouch::task_vouched_env(&v) {
            // task.rs reads these from the process env
            let (k, val, _) = util::cut(&kv, "=");
            crate::task::set_task_env(k, val);
        }
        crate::task::run_task(&c, t, &secrets, &cert.stores(), cert_mode(&cert));
    }
    // 6. the harness's env, without the secrets: the keeper adds the ones the supervisor holds at each start
    let mut spec = HarnessSpec {
        clean,
        fixed: crate::vouch::harness_fixed(&v, &me, first_machine),
        fallback: BTreeMap::new(),
    };
    // the Claude login: the pair of the session's Claude account, kept in step
    let account = crate::claudelogin::session_claude_login(&c);
    if !account.is_empty() {
        spec.fallback.insert("CLAUDE_ACCOUNT".into(), account); // the entrypoint merges it into ~/.claude.json
    }
    if !first_machine && !v.once.prompt.is_empty() {
        // the supervisor types the approved resume prompt
        let _ = std::fs::remove_file(paths::home().join(".claude").join(".first-prompt-sent"));
    }
    if first_machine && !v.config.attachments.is_empty() {
        for kv in crate::attachments::fetch_attachments(&c, &core_key, &v.config.attachments) {
            if let Some((k, val)) = kv.split_once('=') {
                spec.fixed.insert(k.into(), val.into());
            }
        }
    }
    if crate::harnesses::runs_claude_code(&cert.options.harness)
        && let Err(e) = crate::workers::install_worker_hooks(&paths::home())
    {
        logf!("workers hooks: {e:#}");
    }
    wait_api_proxy(Duration::from_secs(15)); // the entrypoint's first calls ($JARVIS_URL: content-sync pull) need it up
    logf!("booted: the keeper starts the harness");
    Ok(spec)
}

fn set_predecessor_key(k: &str) {
    if let Ok(mut g) = deliver::PREDECESSOR_KEY.lock() {
        *g = k.to_string();
    }
}

/// Go's %v of a []string
pub fn go_list(v: &[String]) -> String {
    format!("[{}]", v.join(" "))
}

/// the supervisor starts the local Jarvis API once booted exists; the harness's entrypoint calls it at once, so wait
/// until it accepts connections (at most d)
pub fn wait_api_proxy(d: Duration) {
    let mut addr = crate::env::get("JARVIS_API_ADDR");
    if addr.is_empty() {
        addr = crate::apiproxy::API_PROXY_ADDR.to_string();
    }
    let end = Instant::now() + d;
    while Instant::now() < end {
        if let Ok(a) = addr.parse::<std::net::SocketAddr>()
            && std::net::TcpStream::connect_timeout(&a, Duration::from_secs(1)).is_ok()
        {
            return;
        }
        util::sleep(Duration::from_millis(200));
    }
    logf!(
        "the local Jarvis API on {addr} isn't up after {}s: starting the harness anyway",
        d.as_secs()
    );
}

/// how long a pull waits on a locked store: tries × wait (tests shorten it)
pub static PULL_TRIES: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(300);
pub static PULL_WAIT_MS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(2000);

/// the core seals the answer to this machine's encryption key, so it needs no other proof
pub fn pull_secrets(c: &Client, core_key: &str, me: &str) -> Result<HashMap<String, String>> {
    // a store may still be locked: the app shows which and Deyao unlocks it on the phone; the pull is retried every 2 s
    // for 10 minutes, so the machine carries on within seconds of the unlock
    let tries = PULL_TRIES.load(Ordering::Relaxed);
    let mut last: Option<anyhow::Error> = None;
    let mut doc = SignedDoc::default();
    for i in 0..tries {
        match c.json::<BTreeMap<String, String>, SignedDoc>(
            "POST",
            "/m/pull-secrets",
            Some(&BTreeMap::new()),
        ) {
            Ok(d) => {
                doc = d;
                last = None;
                break;
            }
            Err(e) => {
                if i % 30 == 0 {
                    logf!("pull secrets: {e:#} (retrying)");
                }
                last = Some(e);
                util::sleep(Duration::from_millis(PULL_WAIT_MS.load(Ordering::Relaxed)));
            }
        }
    }
    if let Some(e) = last {
        if format!("{e:#}").contains("HTTP 423") {
            return Err(
                anyhow::Error::new(StoresLocked(format!(" ({e:#})"))).context("pull secrets")
            );
        }
        bail!("pull secrets: {e:#}");
    }
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct SealedV {
        e: String,
        data: String,
    }
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Out {
        kind: String,
        machine: String,
        sealed: SealedV,
    }
    let (mut key, mut want) = (core_key.to_string(), me.to_string());
    if let Some(t) = crate::kernelboot::read_kernel_trust() {
        // signed by the kernel's secrets, for this machine's object
        key = t.secrets;
        want = t.machine;
    }
    let out: Out = match verify_doc::<Out>(&key, Some(&doc)) {
        Ok(o) if o.kind == "secrets" && o.machine == want => o,
        Ok(_) => bail!("the secrets answer isn't signed for this machine (<nil>)"),
        Err(e) => bail!("the secrets answer isn't signed for this machine ({e:#})"),
    };
    let k = load_private()?;
    let plain = open_sealed(&k.enc, &out.sealed.e, &out.sealed.data, "jarvis2/secrets")
        .map_err(|e| anyhow!("the secrets don't decrypt with this machine's key: {e:#}"))?;
    Ok(gojson::unmarshal(&plain)?)
}

/// The repos the cert names into ~/workspace. A repo whose deploy key is in the session's stores goes over SSH with
/// that key (git's rewrites are written already); any other is cloned anonymously over HTTPS (public repos only).
pub fn clone_repos(repos: &[String]) {
    let home = paths::home();
    for url in repos {
        let url = crate::deploykeys::clone_url(url);
        if url.is_empty() {
            continue;
        }
        let base = url.rsplit('/').next().unwrap_or(&url);
        let name = base.strip_suffix(".git").unwrap_or(base).to_string();
        let dst = home.join("workspace").join(&name);
        if dst.join(".git").exists() {
            continue; // restored from the snapshot
        }
        let d = dst.to_string_lossy().into_owned();
        let mut cmd = session_command("git", &["clone", "-q", "--", &url, &d]);
        cmd.env("GIT_TERMINAL_PROMPT", "0");
        match cmd.output() {
            Ok(o) if o.status.success() => logf!("cloned {name}"),
            Ok(o) => {
                let mut t = String::from_utf8_lossy(&o.stdout).into_owned();
                t.push_str(&String::from_utf8_lossy(&o.stderr));
                logf!("clone {name} failed: {}", t.trim());
            }
            Err(e) => logf!("clone {name} failed: {e}"),
        }
    }
}

// ---- add a store ----------------------------------------------------------------------------------------------------

pub fn add_store(name: &str) -> Result<()> {
    let c = Client::new()?;
    c.json_ok(
        "POST",
        "/m/add-store",
        Some(&BTreeMap::from([("store", name)])),
    )?;
    eprintln!("asked Deyao to add {name} to this session (approval in the Jarvis 4 app)");
    await_store(name)
}

/// Wait (up to 1 h) for a cert of this machine that holds the store, then pull the secrets. Also what `jarvis-request
/// add-store` runs after its request, which asks by itself and so must not ask again.
pub fn await_store(name: &str) -> Result<()> {
    let kernel = crate::kernelboot::read_kernel_trust().is_some();
    let (core_key, c) = if kernel {
        (String::new(), None)
    } else {
        (read_trim(&paths::core_key_path())?, Some(Client::new()?))
    };
    eprintln!("waiting up to 1 h for {name} (Deyao's approval in the Jarvis 4 app)");
    let deadline = Instant::now() + Duration::from_secs(3600);
    while Instant::now() < deadline {
        util::sleep(Duration::from_secs(5));
        let held = match &c {
            // a kernel machine: the approval merges the store into this machine's grant and the router tells the
            // supervisor to reload, which rewrites cert.json from the checked documents
            None => crate::grants::read_cert()
                .map(|c| c.stores())
                .unwrap_or_default(),
            Some(c) => cert_stores(c, &core_key, &c.me).unwrap_or_default(),
        };
        if !held.iter().any(|s| s == name) {
            continue;
        }
        let r = ask_secrets(
            &SecretsReq {
                op: "reload".into(),
                ..Default::default()
            },
            Duration::from_secs(20 * 60),
        )?;
        eprintln!(
            "added {name}: the supervisor holds it now ({} keys); `session-secret --keys K1,K2 --exec CMD` runs a command with the keys it needs",
            r.n
        );
        return Ok(());
    }
    bail!("no approval within 1 h")
}

/// the router's cert for this machine, when it is core-signed for this machine and its current keys (read per call: a
/// downgrade replaces them)
pub fn newest_cert(c: &Client, core_key: &str, me: &str) -> Option<SignedDoc> {
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Cs {
        cert: Option<SignedDoc>,
    }
    let cs: Cs = c.json::<(), Cs>("GET", "/m/cert", None).ok()?;
    let d = cs.cert?;
    let keys = own_keys().unwrap_or_default();
    let cert: Cert = verify_doc(core_key, Some(&d)).ok()?;
    let m = cert.machine.as_ref()?;
    if cert.kind != "succession-cert"
        || m.id != me
        || Some(&m.signing_key) != keys.get("signingKey")
    {
        return None;
    }
    Some(d)
}

/// the stores of the newest cert (None: none could be read)
pub fn cert_stores(c: &Client, core_key: &str, me: &str) -> Option<Vec<String>> {
    let d = newest_cert(c, core_key, me)?;
    let cert: Cert = gojson::unmarshal(d.payload.as_bytes()).unwrap_or_default();
    Some(cert.stores())
}

/// one pull into the supervisor's copy at a time (with the cert file and the deploy keys it implies)
pub fn secrets_lock_path() -> std::path::PathBuf {
    paths::home().join(".jarvis-secrets.lock")
}

/// run f holding the machine-wide secrets lock
pub fn with_secrets_lock<T>(f: impl FnOnce() -> Result<T>) -> Result<T> {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(secrets_lock_path())?;
    let lock = nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusive)
        .map_err(|(_, e)| anyhow!("flock: {e}"))?;
    let r = f();
    drop(lock);
    r
}
