//! Secrets: a component of the supervisor (supervisor.rs). The supervisor pulls the session's secrets from the core
//! (sealed to this machine, through the router), holds them in RAM and serves them to the session's processes on
//! request; no secret sits in plain text on disk (Deyao, 2026-10-16).
//!
//!   - Pulls: the supervisor alone pulls (/m/pull-secrets): at boot when boot asks (op "pull"), on the router's
//!     refresh-secrets, and when a process of the session asks for one (op "reload": the router's newest cert, then a
//!     pull with it). A pull hands no value to anyone: its answer is the key names and the cert's stores.
//!   - RAM only: the values live in supervisor-core's memory and in a memfd the keeper holds (JARVIS_SECRETS_FD), so a
//!     restarted supervisor-core has them again without a new pull. Nothing is written to ~/.secrets, /run/jarvis or
//!     the snapshot.
//!   - Serving: the unix socket secrets.sock (0600, user claude; root may connect too): one JSON request per
//!     connection, {"op": "names" | "get" (with "keys") | "pull" | "reload" | "boot-env"}. A process gets values only
//!     with "get", naming each key it needs. Each request is logged with its op, the key names (or a count) and the
//!     caller's pid and command name (SO_PEERCRED), never a value.
//!   - Deploy keys: the private keys of the repo stores stay in RAM too, in the supervisor's ssh-agent.
//!   - The harness's env: op "boot-env", answered only to the keeper and to boot before the machine has booted.

use crate::client::Client;
use crate::crypto::read_trim;
use crate::session::{peer_of, session_peer};
use crate::task::ENV_NAME_RE;
use crate::util::{clip, go_quote};
use crate::{gojson, logf, paths, util};
use anyhow::{Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::io::{Read, Seek, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::{LazyLock, Mutex, RwLock};
use std::time::Duration;

/// supervisor-core's fd of the keeper's memfd
pub const SECRETS_FD_ENV: &str = "JARVIS_SECRETS_FD";

/// the marker of a pull refused because a store is still locked (the core's 423)
#[derive(Debug, thiserror::Error)]
#[error("a store this session's cert names is still locked{0}")]
pub struct StoresLocked(pub String);

/// the supervisor's RAM copy
pub struct HeldSecrets {
    vals: RwLock<(HashMap<String, String>, bool)>,
    /// the keeper's memfd, reopened through /proc (None in tests: memory only)
    mem: Mutex<Option<std::fs::File>>,
    /// one pull at a time
    pub pull_mu: Mutex<()>,
}

pub static HELD: LazyLock<HeldSecrets> = LazyLock::new(|| HeldSecrets {
    vals: RwLock::new((HashMap::new(), false)),
    mem: Mutex::new(None),
    pull_mu: Mutex::new(()),
});

/// an anonymous RAM file (the keeper's, handed to every supervisor-core): left open across exec
pub fn new_memfd() -> Result<std::os::fd::OwnedFd> {
    Ok(nix::sys::memfd::memfd_create(
        c"jarvis-secrets",
        nix::sys::memfd::MFdFlags::empty(),
    )?)
}

#[derive(Serialize, Deserialize, Default)]
#[serde(default)]
struct MemState {
    vals: Option<HashMap<String, String>>,
    pulled: bool,
}

impl HeldSecrets {
    /// a copy of its own (tests: two supervisor-cores' copies of one memfd)
    #[cfg(test)]
    pub fn new_with_mem(mem: Option<std::fs::File>) -> HeldSecrets {
        HeldSecrets {
            vals: RwLock::new((HashMap::new(), false)),
            mem: Mutex::new(mem),
            pull_mu: Mutex::new(()),
        }
    }

    /// supervisor-core's start: the values the memfd holds (from an earlier one), if any
    pub fn load_held(&self) {
        let Ok(fd) = crate::env::get(SECRETS_FD_ENV).parse::<i32>() else {
            return;
        };
        if fd < 3 {
            return;
        }
        let Ok(mut f) = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(format!("/proc/self/fd/{fd}"))
        else {
            return;
        };
        let mut b = vec![];
        let _ = (&mut f).take(64 << 20).read_to_end(&mut b);
        if let Ok(mut g) = self.mem.lock() {
            *g = Some(f);
        }
        if b.is_empty() {
            return;
        }
        if let Ok(st) = gojson::unmarshal::<MemState>(&b)
            && let Some(vals) = st.vals
        {
            let n = vals.len();
            if let Ok(mut g) = self.vals.write() {
                *g = (vals, st.pulled);
            }
            logf!("secrets: {n} keys kept in memory from the earlier supervisor-core");
        }
    }

    /// the new values replace the old at once (RAM and memfd), and the deploy keys follow
    pub fn set(&self, m: HashMap<String, String>) {
        let mut clean = HashMap::new();
        for (k, v) in m {
            if ENV_NAME_RE.is_match(&k) {
                clean.insert(k, v);
            } else {
                logf!(
                    "secrets: left out a key that isn't an env name ({} bytes)",
                    k.len()
                );
            }
        }
        if let Ok(mut g) = self.vals.write() {
            *g = (clean.clone(), true);
        }
        if let Ok(mut g) = self.mem.lock()
            && let Some(f) = g.as_mut()
        {
            let sorted: BTreeMap<&String, &String> = clean.iter().collect();
            let b = gojson::marshal(&serde_json::json!({"vals": sorted, "pulled": true}));
            let _ = f.set_len(0);
            let _ = f.rewind();
            let _ = f.write_all(b.as_bytes());
        }
        if let Err(e) = crate::deploykeys::setup_deploy_keys(&clean) {
            logf!("deploy keys: {e:#}");
        }
    }

    /// tests: the RAM copy as given (no deploy keys, no memfd)
    #[cfg(test)]
    pub fn set_for_test(&self, m: HashMap<String, String>) {
        if let Ok(mut g) = self.vals.write() {
            *g = (m, false);
        }
    }

    pub fn snapshot(&self) -> HashMap<String, String> {
        self.vals.read().map(|g| g.0.clone()).unwrap_or_default()
    }

    /// one pull from the core (with pull_secrets' wait for a locked store) into RAM
    pub fn pull(&self, c: &Client) -> Result<usize> {
        let _g = self.pull_mu.lock().unwrap_or_else(|e| e.into_inner());
        let core_key = read_trim(&paths::core_key_path());
        let kernel = crate::kernelboot::read_kernel_trust().is_some();
        let core_key = match core_key {
            Err(e) if !kernel => return Err(e),
            r => r.unwrap_or_default(),
        };
        let m = crate::boot::pull_secrets(c, &core_key, &c.me)?;
        let n = m.len();
        self.set(m);
        Ok(n)
    }

    /// The newest cert from the router, then a pull with it (refresh-secrets, add-store, downgrade). With drop, a
    /// failed pull empties the RAM copy (a downgrade: what the old keys opened must not stay). lock_held: the caller (a
    /// downgrade) holds the secrets lock already.
    pub fn reload(&self, c: &Client, drop: bool, lock_held: bool) -> Result<usize> {
        let kernel = crate::kernelboot::read_kernel_trust().is_some();
        let core_key = if kernel {
            String::new()
        } else {
            read_trim(&paths::core_key_path())?
        };
        let prepare = || -> Result<()> {
            if kernel {
                return crate::kernelboot::reload_documents(c);
            }
            let Some(doc) = crate::boot::newest_cert(c, &core_key, &c.me) else {
                bail!("the router has no cert for this machine");
            };
            util::write_file(&paths::cert_path(), gojson::marshal(&doc).as_bytes(), 0o644)?;
            Ok(())
        };
        let pull = || -> Result<HashMap<String, String>> {
            let _g = self.pull_mu.lock().unwrap_or_else(|e| e.into_inner());
            if kernel {
                return crate::boot::pull_secrets(c, "", &c.me);
            }
            let c2 = Client::new()?; // the keys may have changed (downgrade)
            crate::boot::pull_secrets(&c2, &core_key, &c2.me)
        };
        let r = if lock_held {
            refresh_unlocked(&prepare, &pull)
        } else {
            refresh_secrets(&prepare, &pull)
        };
        if r.is_err() && drop {
            self.set(HashMap::new());
        }
        r
    }
}

/// Under the lock, take the newest cert (prepare) and pull with it, then the RAM copy: each pull happens after the
/// previous one is held, from the router's newest cert at that moment, so the copy is always the newest.
pub fn refresh_secrets(
    prepare: &dyn Fn() -> Result<()>,
    pull: &dyn Fn() -> Result<HashMap<String, String>>,
) -> Result<usize> {
    crate::boot::with_secrets_lock(|| refresh_unlocked(prepare, pull))
}

/// refresh_secrets for a caller that holds the lock
pub fn refresh_unlocked(
    prepare: &dyn Fn() -> Result<()>,
    pull: &dyn Fn() -> Result<HashMap<String, String>>,
) -> Result<usize> {
    prepare()?;
    let m = pull()?;
    let n = m.len();
    HELD.set(m);
    Ok(n)
}

// ---- the socket ----------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SecretsReq {
    pub op: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub keys: Vec<String>,
    /// reload: empty the copy if the pull fails
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub drop: bool,
    /// reload: the caller holds the secrets lock (a downgrade)
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub held: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SecretsResp {
    pub ok: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub error: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub locked: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub names: Vec<String>,
    /// pull/reload: the stores of the cert the pull used
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub stores: Vec<String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub secrets: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "is_zero")]
    pub n: usize,
}

fn is_zero(n: &usize) -> bool {
    *n == 0
}

fn err_resp(s: impl Into<String>) -> SecretsResp {
    SecretsResp {
        error: s.into(),
        ..Default::default()
    }
}

/// the secrets socket (started by the supervisor)
pub fn serve_secrets(c: Client) {
    let p = paths::secrets_sock();
    let _ = std::fs::remove_file(&p);
    let ln = match UnixListener::bind(&p) {
        Ok(l) => l,
        Err(e) => {
            logf!("secrets: {e}");
            return;
        }
    };
    let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600));
    loop {
        match ln.accept() {
            Ok((conn, _)) => {
                let c = c.clone();
                std::thread::spawn(move || handle_secrets(&c, conn));
            }
            Err(_) => util::sleep(Duration::from_secs(1)),
        }
    }
}

/// one JSON value from a stream (Go's json.Decoder.Decode: no need for the writer to close)
pub fn read_one<T: serde::de::DeserializeOwned, R: Read>(r: R) -> Result<T> {
    let mut it = serde_json::Deserializer::from_reader(r).into_iter::<serde_json::Value>();
    let v = it.next().ok_or_else(|| anyhow!("EOF"))??;
    let b = serde_json::to_vec(&v)?;
    Ok(gojson::unmarshal(&b)?)
}

fn handle_secrets(c: &Client, conn: UnixStream) {
    let (pid, uid, comm) = peer_of(&conn);
    if !session_peer(uid) {
        logf!("secrets: refused a caller of uid {uid} (pid {pid} {comm})");
        return;
    }
    // a boot pull waits for a locked store
    let _ = conn.set_read_timeout(Some(Duration::from_secs(20 * 60)));
    let _ = conn.set_write_timeout(Some(Duration::from_secs(20 * 60)));
    let Ok(req) = read_one::<SecretsReq, _>((&conn).take(1 << 16)) else {
        return;
    };
    let resp = answer_secrets(c, &req, pid, uid, &format!("pid {pid} {comm}"));
    let mut w = &conn;
    let _ = w.write_all(format!("{}\n", gojson::marshal(&resp)).as_bytes());
}

/// One request, logged with the key names and the caller, never a value. Two kinds of request, kept strictly apart
/// (Deyao, 2026-10-20): pulling ("pull", "reload": the answer carries the key names and the cert's stores, never a
/// value) and asking ("get": exactly the keys named, from what is held now; no way to ask for every key). The one
/// hand-over of every value is "boot-env": only to the keeper (root, supervisor-core's parent) and to the boot steps
/// (the process the keeper named in harness.pid) before the machine has booted.
pub fn answer_secrets(
    c: &Client,
    req: &SecretsReq,
    pid: i32,
    uid: u32,
    caller: &str,
) -> SecretsResp {
    match req.op.as_str() {
        "names" => {
            let names = sorted(&HELD.snapshot());
            logf!("secrets: names ({}) for {caller}", names.len());
            SecretsResp {
                ok: true,
                names,
                ..Default::default()
            }
        }
        "get" => answer_get(&req.keys, caller),
        "boot-env" => {
            let kp = crate::supervisor::keeper_pid();
            let keeper = uid == 0 && pid == kp && (pid > 1 || crate::supervisor::keeper_is_init());
            if !keeper && crate::snapshot::booted() {
                logf!("secrets: refused boot-env for {caller}: the machine has booted");
                return err_resp(
                    "boot-env is only for the boot, before the harness starts; ask for the keys a command needs (session-secret --keys K1,K2 …)",
                );
            }
            let hp = read_trim(&crate::keeper::harness_pid_path()).unwrap_or_default();
            if !keeper && hp != pid.to_string() {
                logf!("secrets: refused boot-env for {caller}: not the boot process");
                return err_resp("boot-env is only for the boot process");
            }
            let m = HELD.snapshot();
            logf!(
                "secrets: boot-env ({} keys: {}) for {caller}",
                m.len(),
                clip_names(&sorted(&m)).join(" ")
            );
            SecretsResp {
                ok: true,
                secrets: m.into_iter().collect(),
                ..Default::default()
            }
        }
        "pull" | "reload" => {
            let r = if req.op == "pull" {
                HELD.pull(c)
            } else {
                HELD.reload(c, req.drop, req.held)
            };
            logf!("secrets: {} for {caller}: {}", req.op, result_text(&r));
            match r {
                Err(e) => SecretsResp {
                    error: format!("{e:#}"),
                    locked: e.downcast_ref::<StoresLocked>().is_some(),
                    ..Default::default()
                },
                Ok(n) => SecretsResp {
                    ok: true,
                    n,
                    names: sorted(&HELD.snapshot()),
                    stores: crate::grants::current_cert()
                        .map(|c| c.stores())
                        .unwrap_or_default(),
                    ..Default::default()
                },
            }
        }
        op => {
            logf!(
                "secrets: unknown op {} from {caller}",
                go_quote(&clip(op, 20))
            );
            err_resp("unknown op")
        }
    }
}

/// exactly the named keys, or an error; never all of them
pub fn answer_get(keys: &[String], caller: &str) -> SecretsResp {
    if keys.is_empty() {
        logf!("secrets: refused get with no keys for {caller}");
        return err_resp(
            "name the keys you need (session-secret --keys K1,K2 …); there is no request for all keys",
        );
    }
    for k in keys {
        if !ENV_NAME_RE.is_match(k) || k.len() > 100 {
            logf!("secrets: refused get with a key that isn't an env name for {caller}");
            return err_resp(format!("{} isn't a key name", go_quote(&clip(k, 40))));
        }
    }
    let m = HELD.snapshot();
    let mut out = BTreeMap::new();
    let mut missing: Vec<String> = vec![];
    for k in keys {
        match m.get(k) {
            Some(v) => {
                out.insert(k.clone(), v.clone());
            }
            None if !missing.contains(k) => missing.push(k.clone()),
            None => {}
        }
    }
    let names = clip_names(keys).join(" ");
    if !missing.is_empty() {
        logf!(
            "secrets: refused get {names} for {caller}{}",
            missing_text(&missing)
        );
        return err_resp(format!(
            "not held in this session: {} (session-secret --names lists what it holds; `jarvis stores` shows which store has a key)",
            missing.join(", ")
        ));
    }
    logf!("secrets: get {names} for {caller}");
    SecretsResp {
        ok: true,
        secrets: out,
        ..Default::default()
    }
}

fn result_text(r: &Result<usize>) -> String {
    match r {
        Err(e) => format!("failed: {e:#}"),
        Ok(n) => format!("{n} keys"),
    }
}

fn missing_text(missing: &[String]) -> String {
    if missing.is_empty() {
        return String::new();
    }
    format!(" (not held: {})", clip_names(missing).join(" "))
}

/// key names only as env names (anything else a caller sent is shown as ?), at most 60
pub fn clip_names(ks: &[String]) -> Vec<String> {
    let mut out = vec![];
    for (i, k) in ks.iter().enumerate() {
        if i == 60 {
            out.push(format!("… {} more", ks.len() - 60));
            break;
        }
        if ENV_NAME_RE.is_match(k) && k.len() <= 100 {
            out.push(k.clone());
        } else {
            out.push("?".into());
        }
    }
    out
}

pub fn sorted(m: &HashMap<String, String>) -> Vec<String> {
    let mut ks: Vec<String> = m.keys().cloned().collect();
    ks.sort();
    ks
}

// ---- the client side (boot, the CLI) -------------------------------------------------------------------------------

/// one request to the supervisor's secrets component
pub fn ask_secrets(req: &SecretsReq, timeout: Duration) -> Result<SecretsResp> {
    let mut conn = None;
    let mut last = None;
    for _ in 0..30 {
        // the supervisor may be starting (or supervisor-core restarting)
        match UnixStream::connect(paths::secrets_sock()) {
            Ok(c) => {
                conn = Some(c);
                break;
            }
            Err(e) => {
                last = Some(e);
                util::sleep(Duration::from_secs(1));
            }
        }
    }
    let Some(conn) = conn else {
        bail!(
            "the supervisor's secrets aren't reachable: {}",
            last.map(|e| e.to_string()).unwrap_or_default()
        );
    };
    let _ = conn.set_read_timeout(Some(timeout));
    let _ = conn.set_write_timeout(Some(timeout));
    (&conn).write_all(format!("{}\n", gojson::marshal(req)).as_bytes())?;
    let resp: SecretsResp =
        read_one(&conn).map_err(|e| anyhow!("the supervisor's secrets: {e:#}"))?;
    if !resp.ok {
        if resp.locked {
            return Err(StoresLocked(format!(" ({})", resp.error)).into());
        }
        bail!("{}", resp.error);
    }
    Ok(resp)
}
