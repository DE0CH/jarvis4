//! Memory: the machine's own RAM report for the router's starvation watch (rust/router/src/memory.rs), and the "free" command
//! that goes before an Upgrade's snapshot.
//!
//! Every 10 s the supervisor reads /proc (MemTotal, MemAvailable, the kernel's oom_kill count, PSI memory "full" avg60,
//! the three biggest processes) and POSTs it to /m/memory. A machine too starved to send it is itself the signal.
//!
//! free (router command, an Upgrade only): the harness is SIGSTOPped, and every other process of this user except the
//! supervisor is SIGKILLed (Deyao, 2026-10-10: kill the AI too, or it starts the build again). The list of what was
//! killed goes to ~/artifacts/jarvis-upgrade-freed.txt, inside the snapshot, for the next machine's "upgraded" message.

use crate::client::Client;
use crate::session::session;
use crate::{logf, machine_id, paths, util};
use anyhow::{Result, bail};
use nix::sys::signal::Signal;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::RwLock;
use std::time::Duration;

const MEM_EVERY: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default, rename_all = "camelCase")]
pub struct MemProc {
    pub rss_kb: i64,
    pub comm: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct MemSample {
    #[serde(rename = "totalKb")]
    pub total_kb: i64,
    #[serde(rename = "availKb")]
    pub avail_kb: i64,
    #[serde(rename = "oomKills")]
    pub oom_kills: Option<i64>,
    #[serde(rename = "psiFull60")]
    pub psi_full60: Option<f64>,
    pub top: Option<Vec<MemProc>>,
}

/// /proc (tests move it)
pub static PROC_ROOT: RwLock<Option<PathBuf>> = RwLock::new(None);

pub fn proc_root() -> PathBuf {
    PROC_ROOT
        .read()
        .ok()
        .and_then(|p| p.clone())
        .unwrap_or_else(|| PathBuf::from("/proc"))
}

pub fn read_memory() -> Result<MemSample> {
    let root = proc_root();
    let mut s = MemSample::default();
    let mi = std::fs::read_to_string(root.join("meminfo"))?;
    for l in mi.lines() {
        let Some((k, v)) = l.split_once(':') else {
            continue;
        };
        let v = v.trim();
        let n: i64 = v.strip_suffix(" kB").unwrap_or(v).parse().unwrap_or(0);
        match k {
            "MemTotal" => s.total_kb = n,
            "MemAvailable" => s.avail_kb = n,
            _ => {}
        }
    }
    if s.total_kb == 0 {
        bail!("no MemTotal in meminfo");
    }
    if let Ok(b) = std::fs::read_to_string(root.join("vmstat")) {
        for l in b.lines() {
            if let Some(v) = l.strip_prefix("oom_kill ")
                && let Ok(n) = v.trim().parse()
            {
                s.oom_kills = Some(n);
            }
        }
    }
    if let Ok(b) = std::fs::read_to_string(root.join("pressure").join("memory")) {
        for l in b.lines().filter(|l| l.starts_with("full ")) {
            for f in l.split_whitespace() {
                if let Some(v) = f.strip_prefix("avg60=")
                    && let Ok(x) = v.parse()
                {
                    s.psi_full60 = Some(x);
                }
            }
        }
    }
    let mut procs = processes(|_, _| true);
    procs.sort_by_key(|p| std::cmp::Reverse(p.rss_kb));
    let top: Vec<MemProc> = procs
        .iter()
        .take(3)
        .map(|p| MemProc {
            rss_kb: p.rss_kb,
            comm: p.comm.clone(),
        })
        .collect();
    s.top = (!top.is_empty()).then_some(top);
    Ok(s)
}

#[derive(Debug, Clone)]
pub struct Proc {
    pub pid: i32,
    pub uid: i64,
    pub rss_kb: i64,
    pub comm: String,
}

/// every process in /proc that keep(pid, uid) accepts, with its resident set and name
pub fn processes(keep: impl Fn(i32, i64) -> bool) -> Vec<Proc> {
    let root = proc_root();
    let mut out = vec![];
    for e in std::fs::read_dir(&root).into_iter().flatten().flatten() {
        let Ok(pid) = e.file_name().to_string_lossy().parse::<i32>() else {
            continue;
        };
        let Ok(b) = std::fs::read_to_string(e.path().join("status")) else {
            continue;
        };
        let mut p = Proc {
            pid,
            uid: -1,
            rss_kb: 0,
            comm: String::new(),
        };
        for l in b.lines() {
            let (k, v, _) = util::cut(l, ":");
            let v = v.trim();
            match k {
                "Name" => p.comm = v.to_string(),
                "Uid" => {
                    p.uid = v
                        .split_whitespace()
                        .next()
                        .and_then(|x| x.parse().ok())
                        .unwrap_or(-1)
                }
                "VmRSS" => p.rss_kb = v.strip_suffix(" kB").unwrap_or(v).parse().unwrap_or(0),
                _ => {}
            }
        }
        if keep(pid, p.uid) {
            out.push(p);
        }
    }
    out
}

/// the supervisor's memory report (started with the status reports, once booted)
pub fn memory_reporter(c: &Client) {
    loop {
        util::sleep(MEM_EVERY);
        match read_memory() {
            Err(e) => logf!("memory: {e:#}"),
            Ok(s) => {
                if let Err(e) = c.json_ok("POST", "/m/memory", Some(&s)) {
                    logf!("memory report failed: {e:#}");
                }
            }
        }
    }
}

// ---- free (before an Upgrade's snapshot) -----------------------------------------------------------------------------

pub const FREED_FILE: &str = "artifacts/jarvis-upgrade-freed.txt";

/// tests record the signals here instead of sending them
pub static TEST_SIGNALS: std::sync::Mutex<Option<Vec<(i32, Signal)>>> = std::sync::Mutex::new(None);

/// the kill(2) the free step and the pause use (tests record it)
pub fn signal_proc(pid: i32, sig: Signal) -> Result<()> {
    if let Ok(mut g) = TEST_SIGNALS.lock()
        && let Some(v) = g.as_mut()
    {
        v.push((pid, sig));
        return Ok(());
    }
    nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), sig)?;
    Ok(())
}

/// stop the harness (the launcher the keeper started), kill every other process of user claude (never root's: the
/// keeper, this supervisor, Fly's), and record what was killed. Only on a session machine.
pub fn free_memory() {
    let uid = session().uid;
    if machine_id().is_empty() || uid == 0 {
        return; // never root's processes: it would kill the whole machine
    }
    free_processes(
        std::process::id() as i32,
        crate::supervisor::harness_pid(),
        uid as i64,
    );
}

pub fn free_processes(self_pid: i32, main: i32, uid: i64) -> Vec<Proc> {
    if main > 1
        && let Err(e) = signal_proc(main, Signal::SIGSTOP)
    {
        logf!("free: stopping the harness ({main}): {e:#}");
    }
    let kp = crate::supervisor::keeper_pid();
    let mut victims =
        processes(|pid, u| u == uid && pid != self_pid && pid != main && pid != kp && pid > 1);
    victims.sort_by_key(|p| std::cmp::Reverse(p.rss_kb));
    let killed: Vec<Proc> = victims
        .into_iter()
        .filter(|p| signal_proc(p.pid, Signal::SIGKILL).is_ok())
        .collect();
    let mut b = format!(
        "Jarvis 4 Upgrade, {}: the processes the old machine stopped to free memory for its snapshot (resident memory, name):\n",
        util::now_rfc3339()
    );
    for p in &killed {
        b += &format!("{} MB\t{}\n", p.rss_kb / 1024, p.comm);
    }
    let path = paths::home().join(FREED_FILE);
    if let Some(d) = path.parent() {
        let _ = std::fs::create_dir_all(d);
    }
    if let Err(e) = util::write_file(&path, b.as_bytes(), 0o644) {
        logf!("free: {e}");
    }
    logf!(
        "free: stopped the harness, killed {} processes",
        killed.len()
    );
    killed
}
