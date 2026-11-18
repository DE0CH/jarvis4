//! The session user (keeper.go's top half): user claude's ids, the commands the supervisor runs for the session
//! (`jarvis-machine unprotected`, which drops to user claude for good), the supervisors' file identity, signals to
//! the session.
//!
//! The split by uid: user claude (the session, with its sudo) can't signal a root process, so `kill PID`,
//! `pkill -f jarvis-machine`, `kill -TERM -1` from the session all fail with EPERM on the keeper and both supervisors;
//! root through sudo can (higher privilege: accepted). Both supervisors keep root's uid but take user claude's file
//! identity (setfsuid/setfsgid and claude's groups), so every file they read or write is checked and owned as user
//! claude's.

use anyhow::{Result, anyhow, bail};
use nix::unistd::{Gid, Uid};
use std::process::Command;
use std::sync::OnceLock;

pub const SESSION_USER: &str = "claude";

#[derive(Debug, Clone)]
pub struct SessionIds {
    pub uid: u32,
    pub gid: u32,
    pub groups: Vec<u32>,
    pub home: String,
}

static SESSION: OnceLock<SessionIds> = OnceLock::new();

/// user claude's ids (from /etc/passwd and /etc/group); off the image (tests) this process's own
pub fn session() -> &'static SessionIds {
    SESSION.get_or_init(|| {
        let own = SessionIds {
            uid: Uid::current().as_raw(),
            gid: Gid::current().as_raw(),
            groups: vec![],
            home: crate::env::get("HOME"),
        };
        let Ok(Some(u)) = nix::unistd::User::from_name(SESSION_USER) else {
            return own;
        };
        let mut groups: Vec<u32> = vec![];
        if let Ok(name) = std::ffi::CString::new(SESSION_USER)
            && let Ok(gs) = nix::unistd::getgrouplist(&name, u.gid)
        {
            groups = gs.into_iter().map(|g| g.as_raw()).collect();
        }
        if groups.is_empty() {
            groups.push(u.gid.as_raw());
        }
        SessionIds {
            uid: u.uid.as_raw(),
            gid: u.gid.as_raw(),
            groups,
            home: u.dir.to_string_lossy().into_owned(),
        }
    })
}

/// a socket caller the supervisor serves (secrets, ssh-agent): user claude, root, or this process's uid
pub fn session_peer(uid: u32) -> bool {
    uid == 0 || uid == session().uid || uid == Uid::current().as_raw()
}

/// this process runs as root (the keeper and both supervisors on the image)
pub fn privileged() -> bool {
    match TEST_PRIVILEGED.load(std::sync::atomic::Ordering::SeqCst) {
        1 => false,
        2 => true,
        _ => Uid::effective().is_root(),
    }
}

/// tests: 1 = not root, 2 = root, 0 = as this process is
pub static TEST_PRIVILEGED: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

/// A command the supervisor runs for the session. As root it goes through `jarvis-machine unprotected`, which takes
/// user claude's identity for good and the default OOM score, then execs it; otherwise (a CLI command, the tests) it
/// runs as it is.
pub fn session_command(name: &str, args: &[&str]) -> Command {
    unprotected_command("", name, args)
}

/// A command the router runs to look at or rescue the machine (a grant's exec, the status and screen readers): as
/// session_command, but in the rescue cgroup, outside the session's memory limit (oomguard.rs)
pub fn rescue_command(name: &str, args: &[&str]) -> Command {
    unprotected_command("--rescue", name, args)
}

fn unprotected_command(flag: &str, name: &str, args: &[&str]) -> Command {
    if !privileged() {
        let mut c = Command::new(name);
        c.args(args);
        crate::env::apply(&mut c);
        return c;
    }
    let mut c = Command::new("/proc/self/exe");
    c.arg("unprotected");
    if !flag.is_empty() {
        c.arg(flag);
    }
    c.arg("--").arg(name).args(args);
    c
}

/// `jarvis-machine unprotected [--rescue] -- CMD…`: back to the default OOM score (as root this also sets the floor,
/// so the command can't take -1000 back), then, as root, into the session's memory cgroup (--rescue: the rescue one)
/// and user claude's uid, gid and groups for good; then exec the command
pub fn unprotected(args: &[String]) -> Result<()> {
    let mut args = args;
    let mut rescue = false;
    let mut setsid = false;
    if args.first().map(String::as_str) == Some("--rescue") {
        rescue = true;
        args = &args[1..];
    }
    if args.first().map(String::as_str) == Some("--setsid") {
        // the keeper's children (the boot steps, the harness): a session and process group of their own, never the
        // keeper's (exec keeps it)
        setsid = true;
        args = &args[1..];
    }
    if args.first().map(String::as_str) == Some("--") {
        args = &args[1..];
    }
    if args.is_empty() {
        bail!("usage: jarvis-machine unprotected [--rescue] [--setsid] -- <command> [args…]");
    }
    if setsid {
        let _ = nix::unistd::setsid();
    }
    let _ = std::fs::write("/proc/self/oom_score_adj", "0\n");
    if privileged() {
        crate::oomguard::join_cgroup(if rescue {
            crate::oomguard::RESCUE_CGROUP
        } else {
            crate::oomguard::SESSION_CGROUP
        });
        drop_to_session()?;
    }
    exec(&args[0], &args[1..])
}

/// exec `name` (looked up in PATH) with `args`, this process's env
pub fn exec(name: &str, args: &[String]) -> Result<()> {
    use std::os::unix::process::CommandExt;
    let err = Command::new(name).args(args).exec();
    Err(anyhow!("{name}: {err}"))
}

/// this process becomes user claude (real, effective and saved ids; no way back)
pub fn drop_to_session() -> Result<()> {
    let s = session();
    if s.uid == 0 {
        bail!("no session user {SESSION_USER}");
    }
    let groups: Vec<Gid> = s.groups.iter().map(|g| Gid::from_raw(*g)).collect();
    nix::unistd::setgroups(&groups).map_err(|e| anyhow!("setgroups: {e}"))?;
    let g = Gid::from_raw(s.gid);
    nix::unistd::setresgid(g, g, g).map_err(|e| anyhow!("setresgid: {e}"))?;
    let u = Uid::from_raw(s.uid);
    nix::unistd::setresuid(u, u, u).map_err(|e| anyhow!("setresuid: {e}"))?;
    if Uid::effective().is_root() || Uid::current().is_root() {
        bail!("still root after the drop");
    }
    Ok(())
}

/// A supervisor's file identity becomes user claude's (fsuid, fsgid, groups) while its uid stays root. Called first
/// thing, before any other thread exists: a thread takes its creator's credentials, so every thread made after it has
/// the same file identity (Go's AllThreadsSyscall did the same for threads already running).
pub fn session_file_access() -> Result<()> {
    let s = session();
    if s.uid == 0 {
        bail!("no session user {SESSION_USER}");
    }
    let groups: Vec<Gid> = s.groups.iter().map(|g| Gid::from_raw(*g)).collect();
    nix::unistd::setgroups(&groups).map_err(|e| anyhow!("setgroups: {e}"))?;
    // setfsgid/setfsuid where the kernel has them; gVisor has neither (ENOSYS, measured with precopy-20261102.1): there
    // the effective ids take the file identity instead, with the real and saved ids left root (the session still can't
    // signal it) and the capabilities a file identity change drops dropped, the rest raised again, as setfsuid does
    if !set_fs_ids(s.gid, s.uid) {
        effective_file_identity(s.gid, s.uid)?;
    }
    not_dumpable();
    Ok(())
}

/// setfsgid then setfsuid (Linux answers the previous id and never fails; gVisor fails with ENOSYS, which nix reports
/// as the id u32::MAX). Whether the kernel has them.
fn set_fs_ids(gid: u32, uid: u32) -> bool {
    let g = nix::unistd::setfsgid(Gid::from_raw(gid));
    if g.as_raw() == u32::MAX && nix::errno::Errno::last() == nix::errno::Errno::ENOSYS {
        return false;
    }
    nix::unistd::setfsuid(Uid::from_raw(uid));
    true
}

/// The capabilities Linux drops from the effective set when the file uid leaves 0 (capabilities(7), "Effect of user
/// ID changes on capabilities"): CAP_CHOWN, CAP_DAC_OVERRIDE, CAP_DAC_READ_SEARCH, CAP_FOWNER, CAP_FSETID,
/// CAP_LINUX_IMMUTABLE, CAP_MKNOD (low word) and CAP_MAC_OVERRIDE (bit 32). The effective set (low, high words) a
/// file identity of user claude leaves from `permitted`.
#[must_use]
pub fn file_identity_caps(permitted: [u32; 2]) -> [u32; 2] {
    const FS_LOW: u32 = (1 << 0) | (1 << 1) | (1 << 2) | (1 << 3) | (1 << 4) | (1 << 9) | (1 << 27);
    const FS_HIGH: u32 = 1; // CAP_MAC_OVERRIDE, capability 32
    [permitted[0] & !FS_LOW, permitted[1] & !FS_HIGH]
}

/// Where there is no setfsuid: effective gid and uid become user claude's (real and saved stay root's 0), then the
/// effective capabilities are raised again to [`file_identity_caps`] of the permitted set (an effective uid change
/// cleared them all).
fn effective_file_identity(gid: u32, uid: u32) -> Result<()> {
    use caps::{CapSet, Capability};
    let root_g = Gid::from_raw(0);
    let root_u = Uid::from_raw(0);
    nix::unistd::setresgid(root_g, Gid::from_raw(gid), root_g)
        .map_err(|e| anyhow!("setresgid: {e}"))?;
    nix::unistd::setresuid(root_u, Uid::from_raw(uid), root_u)
        .map_err(|e| anyhow!("setresuid: {e}"))?;
    let permitted = caps::read(None, CapSet::Permitted).map_err(|e| anyhow!("capget: {e}"))?;
    let mut words = [0u32; 2];
    for c in &permitted {
        let i = c.index();
        words[usize::from(i / 32)] |= 1 << (i % 32);
    }
    let keep = file_identity_caps(words);
    let effective: caps::CapsHashSet = permitted
        .into_iter()
        .filter(|c: &Capability| keep[usize::from(c.index() / 32)] & (1 << (c.index() % 32)) != 0)
        .collect();
    caps::set(None, CapSet::Effective, &effective).map_err(|e| anyhow!("capset: {e}"))?;
    Ok(())
}

/// /proc/<pid>/{environ,mem,…} stay root's (the session can't read the supervisor's memory)
pub fn not_dumpable() {
    let _ = nix::sys::prctl::set_dumpable(false);
}

fn signal_of(s: &str) -> Option<nix::sys::signal::Signal> {
    use nix::sys::signal::Signal::*;
    match s {
        "STOP" => Some(SIGSTOP),
        "CONT" => Some(SIGCONT),
        "TERM" => Some(SIGTERM),
        "KILL" => Some(SIGKILL),
        _ => None,
    }
}

/// `jarvis-machine signal-session SIG`: kill(-1, SIG) as user claude, i.e. to every process of the session but this
/// one; never to root's (the keeper, the supervisors, Fly's)
pub fn signal_session_cmd(args: &[String]) -> Result<()> {
    if args.len() != 1 {
        bail!("usage: jarvis-machine signal-session STOP|CONT|TERM|KILL");
    }
    let sig = signal_of(&args[0]).ok_or_else(|| anyhow!("unknown signal {}", args[0]))?;
    if Uid::current().is_root() {
        bail!("refusing kill(-1) as root");
    }
    nix::sys::signal::kill(nix::unistd::Pid::from_raw(-1), sig)?;
    Ok(())
}

/// sig to every process of user claude. As root through a child that drops to claude first (kill(-1) as root would
/// reach every process on the machine); as claude, kill(-1) itself (it spares the caller).
pub fn signal_session(sig: &str) -> Result<()> {
    if !privileged() {
        let n = signal_of(sig).ok_or_else(|| anyhow!("unknown signal {sig}"))?;
        nix::sys::signal::kill(nix::unistd::Pid::from_raw(-1), n)?;
        return Ok(());
    }
    let out = Command::new("/proc/self/exe")
        .args(["unprotected", "--", "/proc/self/exe", "signal-session", sig])
        .output()?;
    if !out.status.success() {
        let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
        text.push_str(&String::from_utf8_lossy(&out.stderr));
        bail!("{}: {}", out.status, text.trim());
    }
    Ok(())
}

/// (pid, uid, comm) of a unix socket's peer
pub fn peer_of(conn: &std::os::unix::net::UnixStream) -> (i32, u32, String) {
    match nix::sys::socket::getsockopt(conn, nix::sys::socket::sockopt::PeerCredentials) {
        Ok(c) => {
            let mut comm = std::fs::read_to_string(format!("/proc/{}/comm", c.pid()))
                .map(|s| s.trim().to_string())
                .unwrap_or_default();
            if comm == "exe" {
                // jarvis-machine started as /proc/self/exe: its subcommand says more
                if let Ok(cl) = std::fs::read(format!("/proc/{}/cmdline", c.pid())) {
                    let f: Vec<&[u8]> = cl.split(|b| *b == 0).collect();
                    if f.len() > 1 {
                        comm = format!(
                            "jarvis-machine {}",
                            crate::util::clip(&String::from_utf8_lossy(f[1]), 20)
                        );
                    }
                }
            }
            (c.pid(), c.uid(), comm)
        }
        Err(_) => (0, u32::MAX, "?".into()),
    }
}
