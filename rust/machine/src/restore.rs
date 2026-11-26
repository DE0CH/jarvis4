//! Restoring a destroyed session's archived snapshot into a NEW line (rust/router/src/restore.rs), and the repos' state recorded
//! in every snapshot (for the router's uncommitted-work check of a paused session).
//!
//! A new line (a cert with no predecessor) whose cert names a restore (Config.restore: the old machine and the
//! snapshot's sha256, which the phone approved) restores the snapshot the router serves at /m/restore-snapshot, after
//! checking: its sha256 is the one the cert names; the old cert (/m/restore-cert) is a succession cert signed by the
//! core, for the machine the cert names; the snapshot is signed by that cert's machine signing key; a snapshot from a
//! line that held a sensitive store doesn't land in a line that holds none.

use crate::cert::Cert;
use crate::client::Client;
use crate::crypto::{SignedDoc, verify, verify_doc};
use crate::session::session_command;
use crate::vouch::Vouched;
use crate::{gojson, logf, paths, util};
use anyhow::{Result, anyhow, bail};
use serde::Deserialize;
use std::io::Read;
use std::os::unix::process::CommandExt;
use std::process::Stdio;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

/// the repos' state when the snapshot was taken (rust/router/src/archive.rs reads it); in the snapshot's paths
pub const CHANGES_FILE: &str = ".jarvis2-changes.txt";

/// one "<repo> <uncommitted files> <unpushed commits, -1 = no upstream>" line per repo
pub const REPO_CHANGES_SH: &str = concat!(
    r#"cd ~/workspace 2>/dev/null || exit 0; for d in */; do d=${d%/}; [ -d "$d/.git" ] || continue; "#,
    r#"u=$(git -C "$d" status --porcelain 2>/dev/null | wc -l); "#,
    r#"if git -C "$d" rev-parse --abbrev-ref @{u} >/dev/null 2>&1; then p=$(git -C "$d" rev-list @{u}..HEAD --count 2>/dev/null || echo 0); else p=-1; fi; "#,
    r#"echo "$d $u $p"; done"#
);

/// the repo check runs with the session frozen (2026-10-21: a final snapshot went silent right after the freeze, with
/// this check the only step before it): a git that waits on a stopped process or a slow disk can't hold the snapshot up
/// past it (ms; tests shorten it)
pub static CHANGES_TIMEOUT_MS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(60_000);
/// tests make it hang
pub static CHANGES_SCRIPT: std::sync::RwLock<Option<String>> = std::sync::RwLock::new(None);

/// Before every snapshot; a failure (or the time limit) only leaves the router without the check. No optional locks and
/// no fsmonitor: the session's processes are stopped, so nothing may be waited on.
pub fn write_changes() {
    let limit = Duration::from_millis(CHANGES_TIMEOUT_MS.load(Ordering::Relaxed));
    let script = CHANGES_SCRIPT
        .read()
        .ok()
        .and_then(|s| s.clone())
        .unwrap_or_else(|| REPO_CHANGES_SH.to_string());
    let t0 = Instant::now();
    let mut cmd = session_command("bash", &["-c", &script]);
    cmd.env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_CONFIG_COUNT", "1")
        .env("GIT_CONFIG_KEY_0", "core.fsmonitor")
        .env("GIT_CONFIG_VALUE_0", "false")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .process_group(0);
    let out = (|| -> Result<Option<Vec<u8>>> {
        let mut child = cmd.spawn()?;
        let mut so = child.stdout.take().ok_or_else(|| anyhow!("no stdout"))?;
        let reader = std::thread::spawn(move || {
            let mut b = vec![];
            let _ = so.read_to_end(&mut b);
            b
        });
        let st = loop {
            if let Some(st) = child.try_wait()? {
                break Some(st);
            }
            if t0.elapsed() >= limit {
                // bash and every git it started
                let _ = nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(-(child.id() as i32)),
                    nix::sys::signal::Signal::SIGKILL,
                );
                let _ = child.wait();
                break None;
            }
            util::sleep(Duration::from_millis(50));
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        while !reader.is_finished() && Instant::now() < deadline {
            util::sleep(Duration::from_millis(20));
        }
        let b = if reader.is_finished() {
            reader.join().unwrap_or_default()
        } else {
            vec![]
        };
        match st {
            None => Ok(None),
            Some(s) if !s.success() => Err(anyhow!("{s}")),
            Some(_) => Ok(Some(b)),
        }
    })();
    let b = match out {
        Ok(None) => {
            logf!(
                "repo changes: not done within {}; the snapshot goes on without them",
                crate::keeper::dur_text(limit)
            );
            vec![]
        }
        Err(e) => {
            logf!("repo changes: {e:#}");
            vec![]
        }
        Ok(Some(b)) => {
            logf!(
                "repo changes: checked in {:.1} s",
                t0.elapsed().as_secs_f64()
            );
            b
        }
    };
    let _ = util::write_file(&paths::home().join(CHANGES_FILE), &b, 0o600);
}

/// The archived snapshot into a new line's first machine, only when the cert names it. The bytes whose hash the cert
/// names are either a destroyed Jarvis 4 session's signed snapshot, or a Jarvis 1 import's manifest
/// (jarvis1import.rs), told apart by their content: either way they are exactly what the phone approved.
pub fn restore_archived(
    c: &Client,
    core_key: &str,
    me: &str,
    cert: &mut Cert,
    v: &Vouched,
) -> Result<()> {
    let Some(r) = &v.config.restore else {
        return Ok(());
    };
    if !cert.pred_id.is_empty() {
        return Ok(());
    }
    let tmp = paths::restore_tmp();
    let res = (|| {
        let (sum, hdr) = c.download("/m/restore-snapshot", &tmp).map_err(|e| {
            anyhow!("a restore was asked for but the router serves no snapshot ({e:#})")
        })?;
        if sum != r.sha256 {
            bail!("the archived snapshot isn't the one the cert names");
        }
        if let Some(man) = crate::jarvis1import::read_j1_manifest(&tmp, &r.machine) {
            return crate::jarvis1import::import_jarvis1(c, &man);
        }
        let rc: RestoreCertDocs =
            match c.json::<(), RestoreCertDocs>("GET", "/m/restore-cert", None) {
                Ok(rc) if rc.cert.is_some() => rc,
                Ok(_) => {
                    bail!("the cert names a restore but the router serves no old cert (<nil>)")
                }
                Err(e) => {
                    bail!("the cert names a restore but the router serves no old cert ({e:#})")
                }
            };
        let signer = restore_signer(core_key, &rc)?;
        let old = check_restore_cert(&signer, me, cert, rc.cert.as_ref())?;
        let om = old.machine();
        if om.id != r.machine {
            bail!(
                "the old cert is for {}, the cert names {}",
                om.id,
                r.machine
            );
        }
        let sig = hdr
            .get("X-Snapshot-Sig")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !verify(&om.signing_key, sum.as_bytes(), sig) {
            bail!("the snapshot isn't signed by the machine its cert names");
        }
        let n = crate::snapshot::unpack_file(&tmp)?;
        crate::deliver::RESTORED_ARCHIVE.store(true, Ordering::SeqCst);
        logf!(
            "restored the archived snapshot of {} (line {}, {n} files)",
            om.id,
            old.line
        );
        Ok(())
    })();
    let _ = std::fs::remove_file(&tmp);
    res
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct CoreCert {
    pub statement: String,
    #[serde(rename = "masterSig")]
    pub master_sig: String,
}

/// what /m/restore-cert serves: the old line's cert, and for a cert an earlier core signed, that core's claim (the
/// master key's statement naming it) and the running core's signed state (naming its master key)
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct RestoreCertDocs {
    pub cert: Option<SignedDoc>,
    #[serde(rename = "coreCert")]
    pub core_cert: Option<CoreCert>,
    #[serde(rename = "coreState")]
    pub core_state: Option<SignedDoc>,
}

/// The key the old cert must be signed by: this machine's core's, or an earlier core's that the master key claimed
/// (docs/DESIGN.md "Core continuity")
pub fn restore_signer(core_key: &str, rc: &RestoreCertDocs) -> Result<String> {
    let cert = rc.cert.clone().unwrap_or_default();
    let (Some(cc), Some(cs)) = (&rc.core_cert, &rc.core_state) else {
        return Ok(core_key.into());
    };
    if verify(core_key, cert.payload.as_bytes(), &cert.sig) {
        return Ok(core_key.into());
    }
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct St {
        kind: String,
        master: String,
    }
    let st: St = match verify_doc::<St>(core_key, Some(cs)) {
        Ok(st) if st.kind == "core-state" && !st.master.is_empty() => st,
        _ => bail!(
            "the restore names an earlier core, but the core's state isn't signed by this machine's core"
        ),
    };
    if !verify(&st.master, cc.statement.as_bytes(), &cc.master_sig) {
        bail!("the earlier core's claim isn't signed by the master key");
    }
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct K {
        #[serde(rename = "signingKey")]
        signing_key: String,
    }
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Claim {
        kind: String,
        master: String,
        core: K,
        identity: Option<K>,
    }
    let claim: Claim = match gojson::unmarshal::<Claim>(cc.statement.as_bytes()) {
        Ok(c) if c.kind == "claim" && c.master == st.master => c,
        _ => bail!("the earlier core's claim isn't a claim by this master key"),
    };
    for k in [
        claim.core.signing_key,
        claim.identity.map(|i| i.signing_key).unwrap_or_default(),
    ] {
        if !k.is_empty() && verify(&k, cert.payload.as_bytes(), &cert.sig) {
            return Ok(k);
        }
    }
    bail!("the restore cert isn't signed by the core the master key's claim names")
}

/// the old line's cert, core-signed, for another machine; sensitive stays sensitive
pub fn check_restore_cert(
    core_key: &str,
    me: &str,
    cert: &Cert,
    d: Option<&SignedDoc>,
) -> Result<Cert> {
    let old: Cert = match verify_doc::<Cert>(core_key, d) {
        Ok(o) if o.kind == "succession-cert" && o.machine.is_some() => o,
        r => bail!(
            "the restore cert isn't a succession cert signed by the core ({})",
            r.err()
                .map(|e| format!("{e:#}"))
                .unwrap_or_else(|| "<nil>".into())
        ),
    };
    if old.machine().id == me {
        bail!("the restore cert names this machine");
    }
    if old.sensitive && !cert.sensitive {
        bail!("the snapshot comes from a line with a sensitive store; this line holds none");
    }
    Ok(old)
}

#[cfg(test)]
pub fn check_snapshot_sig(signing_key: &str, body: &[u8], sig: &str) -> Result<()> {
    if !verify(signing_key, crate::crypto::sha256_hex(body).as_bytes(), sig) {
        bail!("the snapshot isn't signed by the machine its cert names");
    }
    Ok(())
}

/// A successor whose cert names no snapshot while the line's config names a restore takes that restore again, if it is
/// a Jarvis 1 import: exactly the bytes the phone approved for the line (DECISIONS 141).
pub fn reimport_jarvis1(c: &Client, v: &Vouched) -> Result<()> {
    let Some(r) = &v.config.restore else {
        return Ok(());
    };
    let tmp = paths::restore_tmp();
    let res = (|| {
        let sum = match c.download("/m/restore-snapshot", &tmp) {
            Ok((s, _)) => s,
            Err(e) => {
                logf!(
                    "no snapshot and no import to take again ({e:#}): starting with no predecessor state"
                );
                return Ok(());
            }
        };
        if sum != r.sha256 {
            bail!("the import manifest isn't the one the cert names");
        }
        let Some(man) = crate::jarvis1import::read_j1_manifest(&tmp, &r.machine) else {
            logf!("the line's restore isn't a Jarvis 1 import: starting with no predecessor state");
            return Ok(());
        };
        logf!(
            "the predecessor left no snapshot: importing Jarvis 1 session {} again",
            man.session
        );
        crate::jarvis1import::import_jarvis1(c, &man)
    })();
    let _ = std::fs::remove_file(&tmp);
    res
}
