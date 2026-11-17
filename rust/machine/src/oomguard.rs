//! Memory for the control plane (DECISIONS 221; Deyao, 2026-10-22: "only the supervisor needs to be protected, the rest
//! dont matter", "The point is to keep control plane alive so we still can send restart command and also terminal grant
//! to rescue"). Three guards:
//!
//!   - The session's memory cgroup: at boot the keeper makes the session cgroup with its limit = MemTotal - 640 MB, and
//!     `unprotected` moves itself into it before it drops to user claude, so everything the session runs is charged
//!     there. At the limit the kernel reclaims and OOM-kills inside the cgroup only.
//!   - The rescue cgroup: `unprotected --rescue` (a grant's exec, the status and screen readers) joins the rescue cgroup
//!     instead, with its own limit, so a rescue command runs with memory to spare on a machine the session has filled.
//!   - The supervisor's own pages pinned: the keeper and supervisor-core each mlockall(MCL_CURRENT|MCL_FUTURE|
//!     MCL_ONFAULT) (with RLIMIT_MEMLOCK raised, as root). Locks aren't inherited across fork/exec.
//!
//! Fly's guest kernel has cgroup v1 (/sys/fs/cgroup/memory); an AWS instance runs Flatcar, whose /sys/fs/cgroup is the
//! unified cgroup v2 hierarchy: there the two cgroups are /sys/fs/cgroup/jarvis-session and jarvis-rescue, the limit is
//! memory.max, and the root's cgroup.subtree_control gets +memory first.

use crate::{logf, machine_id};
use anyhow::{Result, anyhow};
use std::path::{Path, PathBuf};

pub const SESSION_CGROUP: &str = "/sys/fs/cgroup/memory/jarvis-session";
pub const RESCUE_CGROUP: &str = "/sys/fs/cgroup/memory/jarvis-rescue";
/// bytes kept outside the session's limit
const SESSION_RESERVE: i64 = 640 << 20;
/// the rescue cgroup's limit (of the reserve)
const RESCUE_MAX: i64 = 384 << 20;
/// where the unified hierarchy is mounted on an AWS (Flatcar) instance
const CGROUP_V2_ROOT: &str = "/sys/fs/cgroup";

/// the session cgroup's limit for a machine of total_kb (MemTotal), never under half the machine
pub fn session_limit(total_kb: i64) -> i64 {
    let total = total_kb << 10;
    (total - SESSION_RESERVE).max(total / 2)
}

/// the rescue cgroup's, never over a quarter of the machine
pub fn rescue_limit(total_kb: i64) -> i64 {
    RESCUE_MAX.min((total_kb << 10) / 4)
}

/// the keeper's, at boot (before the boot steps start)
pub fn make_cgroups() {
    if machine_id().is_empty() {
        return;
    }
    if let Err(e) = setup_cgroups() {
        logf!("memory limits: {e:#} (the session can fill the machine)");
    }
}

/// /sys/fs/cgroup is the unified hierarchy (CGROUP2_SUPER_MAGIC)
pub fn is_cgroup_v2(root: &str) -> bool {
    nix::sys::statfs::statfs(root).is_ok_and(|fs| fs.filesystem_type().0 == 0x63677270)
}

/// dir (a v1 memory cgroup path) where it is on this machine: on the unified hierarchy the same name at its root
pub fn cgroup_dir(dir: &str) -> PathBuf {
    if let Some(rel) = dir.strip_prefix(&format!("{CGROUP_V2_ROOT}/memory/"))
        && is_cgroup_v2(CGROUP_V2_ROOT)
    {
        return Path::new(CGROUP_V2_ROOT).join(rel);
    }
    PathBuf::from(dir)
}

/// the memory limit's file in a cgroup dir (as cgroup_dir gives it), v1 or v2
pub fn limit_file(dir: &Path) -> PathBuf {
    if dir.starts_with(format!("{CGROUP_V2_ROOT}/memory")) || !is_cgroup_v2(CGROUP_V2_ROOT) {
        return dir.join("memory.limit_in_bytes");
    }
    dir.join("memory.max")
}

fn setup_cgroups() -> Result<()> {
    let s = crate::memory::read_memory()?;
    if cgroup_dir(SESSION_CGROUP) != Path::new(SESSION_CGROUP) {
        // v2: the memory controller for the root's children first
        std::fs::write(
            Path::new(CGROUP_V2_ROOT).join("cgroup.subtree_control"),
            "+memory",
        )
        .map_err(|e| anyhow!("enabling the memory controller: {e}"))?;
    }
    for (dir, limit) in [
        (cgroup_dir(SESSION_CGROUP), session_limit(s.total_kb)),
        (cgroup_dir(RESCUE_CGROUP), rescue_limit(s.total_kb)),
    ] {
        std::fs::create_dir_all(&dir)?;
        std::fs::write(limit_file(&dir), limit.to_string())
            .map_err(|e| anyhow!("{}: {e}", dir.display()))?;
        logf!(
            "memory limit {} MB of {} MB for {}",
            limit >> 20,
            s.total_kb >> 10,
            dir.display()
        );
    }
    Ok(())
}

/// `unprotected`, as root before it drops: this process (and so everything it execs and starts) into the cgroup dir. No
/// cgroup (not a session machine, a failed setup) = nothing to join.
pub fn join_cgroup(dir: &str) {
    let dir = cgroup_dir(dir);
    let procs = dir.join("cgroup.procs");
    if !procs.exists() {
        return;
    }
    if let Err(e) = std::fs::write(&procs, std::process::id().to_string()) {
        logf!("memory limit: joining {}: {e}", dir.display());
    }
}

/// this process's pages stay in RAM (the keeper at boot, supervisor-core as it starts)
pub fn lock_memory(who: &str) {
    if machine_id().is_empty() {
        return;
    }
    match mlock_all() {
        Err(e) => logf!("{who}: locking its memory: {e:#}"),
        Ok(()) => logf!("{who}: memory locked in RAM"),
    }
}

fn mlock_all() -> Result<()> {
    use nix::sys::resource::{RLIM_INFINITY, Resource, setrlimit};
    setrlimit(Resource::RLIMIT_MEMLOCK, RLIM_INFINITY, RLIM_INFINITY)
        .map_err(|e| anyhow!("RLIMIT_MEMLOCK: {e}"))?;
    use nix::sys::mman::{MlockAllFlags, mlockall};
    mlockall(
        MlockAllFlags::MCL_CURRENT | MlockAllFlags::MCL_FUTURE | MlockAllFlags::from_bits_retain(4),
    )?;
    Ok(())
}
