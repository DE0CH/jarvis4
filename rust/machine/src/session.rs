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
    Uid::effective().is_root()
}

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
    nix::unistd::setfsgid(Gid::from_raw(s.gid));
    nix::unistd::setfsuid(Uid::from_raw(s.uid));
    not_dumpable();
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
