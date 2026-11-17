//! The machine's volume (core/volumes.go): a machine the core made with a Fly volume finds it mounted at /data. The
//! session's state (what the snapshot holds) lives on it: each of the snapshot's directories is bind-mounted from
//! /data/home/<path> onto ~/<path>, and the snapshot's single files (~/.claude.json and the Jarvis records), which
//! programs replace by rename and so can't be bind-mounted, are copied to /data/home/ every minute and right before the
//! final snapshot.
//!
//! The volume is always new and empty at boot: no resume reads it. Whatever the image put at those paths is copied onto
//! the volume first. Without a volume nothing changes. The bind mounts need root: the image's claude has passwordless
//! sudo.

use crate::session::session_command;
use crate::snapshot::{SNAPSHOT_PATHS, snapshot_file};
use crate::{logf, paths, util};
use anyhow::{Result, bail};
use std::path::PathBuf;
use std::time::Duration;

pub const VOLUME_ROOT: &str = "/data";
const MOUNTS_FILE: &str = "/proc/self/mountinfo";

/// tests: the volume's root and the mount table elsewhere, and the privileged commands recorded instead of run
pub struct TestVolume {
    pub root: PathBuf,
    pub mounts: PathBuf,
    pub cmds: Vec<String>,
}

pub static TEST_VOLUME: std::sync::Mutex<Option<TestVolume>> = std::sync::Mutex::new(None);

fn volume_root() -> PathBuf {
    TEST_VOLUME
        .lock()
        .ok()
        .and_then(|g| g.as_ref().map(|t| t.root.clone()))
        .unwrap_or_else(|| PathBuf::from(VOLUME_ROOT))
}

fn mounts_file() -> PathBuf {
    TEST_VOLUME
        .lock()
        .ok()
        .and_then(|g| g.as_ref().map(|t| t.mounts.clone()))
        .unwrap_or_else(|| PathBuf::from(MOUNTS_FILE))
}
const MIRROR_EVERY: Duration = Duration::from_secs(60);

/// sudo: the bind mounts and the volume's owner
fn run_privileged(args: &[&str]) -> Result<()> {
    if let Ok(mut g) = TEST_VOLUME.lock()
        && let Some(t) = g.as_mut()
    {
        t.cmds.push(args.join(" "));
        return Ok(());
    }
    let out = std::process::Command::new("sudo")
        .arg("-n")
        .args(args)
        .output()?;
    if !out.status.success() {
        let mut t = String::from_utf8_lossy(&out.stdout).into_owned();
        t.push_str(&String::from_utf8_lossy(&out.stderr));
        bail!("{}: {} {}", args.join(" "), out.status, t.trim());
    }
    Ok(())
}

/// /data is a mount point (Fly mounts the volume there; nothing else does)
pub fn has_volume() -> bool {
    let root = volume_root();
    std::fs::read_to_string(mounts_file())
        .map(|s| {
            s.lines().any(|l| {
                let f: Vec<&str> = l.split_whitespace().collect();
                f.len() > 4 && std::path::Path::new(f[4]) == root
            })
        })
        .unwrap_or(false)
}

/// the snapshot's paths that are directories (bind-mounted) and files (mirrored)
pub fn volume_split() -> (Vec<&'static str>, Vec<&'static str>) {
    SNAPSHOT_PATHS
        .iter()
        .copied()
        .partition(|r| !snapshot_file(r))
}

/// At boot, before the predecessor's snapshot is restored: the state's directories onto the volume. false: no volume
/// (or it couldn't be set up: logged, and the machine runs on its root disk as before).
pub fn setup_volume() -> bool {
    if !has_volume() {
        return false;
    }
    let home = paths::home();
    let owner = format!(
        "{}:{}",
        nix::unistd::Uid::current(),
        nix::unistd::Gid::current()
    );
    let vroot = volume_root();
    if let Err(e) = run_privileged(&["chown", &owner, &vroot.to_string_lossy()]) {
        logf!("volume: {e:#}; the state stays on the root disk");
        return false;
    }
    let (dirs, _) = volume_split();
    let mut n = 0;
    for rel in &dirs {
        let (src, dst) = (vroot.join("home").join(rel), home.join(rel));
        if let Err(e) = std::fs::create_dir_all(&src).and_then(|_| std::fs::create_dir_all(&dst)) {
            logf!("volume: {rel}: {e}");
            continue;
        }
        // what the image has there goes onto the volume first (cp -a keeps modes, links and times)
        if std::fs::read_dir(&dst).is_ok_and(|mut d| d.next().is_some()) {
            let (s, d) = (
                format!("{}/.", dst.display()),
                format!("{}/", src.display()),
            );
            match session_command("cp", &["-a", &s, &d]).output() {
                Ok(o) if o.status.success() => {}
                Ok(o) => {
                    logf!(
                        "volume: copying the image's {rel}: {} {}",
                        o.status,
                        String::from_utf8_lossy(&o.stderr)
                    );
                    continue;
                }
                Err(e) => {
                    logf!("volume: copying the image's {rel}: {e}");
                    continue;
                }
            }
        }
        if let Err(e) = run_privileged(&[
            "mount",
            "--bind",
            &src.to_string_lossy(),
            &dst.to_string_lossy(),
        ]) {
            logf!("volume: {e:#}");
            continue;
        }
        n += 1;
    }
    // a multi-GB download lands on the volume
    if let Ok(mut p) = paths::PREDECESSOR_TMP.write() {
        *p = Some(vroot.join(".predecessor.tar.gz"));
    }
    logf!(
        "volume: {n} of {} state directories on {}",
        dirs.len(),
        vroot.display()
    );
    if TEST_VOLUME.lock().map(|g| g.is_none()).unwrap_or(true) {
        std::thread::spawn(|| {
            loop {
                mirror_volume_files();
                util::sleep(MIRROR_EVERY);
            }
        });
    }
    true
}

/// the snapshot's single files copied onto the volume (only on a machine with one)
pub fn mirror_volume_files() {
    if !has_volume() {
        return;
    }
    let home = paths::home();
    let (_, files) = volume_split();
    for rel in files {
        let Ok(b) = std::fs::read(home.join(rel)) else {
            continue;
        };
        let dst = volume_root().join("home").join(rel);
        if std::fs::read(&dst).is_ok_and(|old| old == b) {
            continue;
        }
        if let Some(d) = dst.parent() {
            let _ = std::fs::create_dir_all(d);
        }
        let tmp = PathBuf::from(format!("{}.tmp", dst.display()));
        if util::write_file(&tmp, &b, 0o600).is_ok() {
            let _ = std::fs::rename(&tmp, &dst);
        }
    }
}
