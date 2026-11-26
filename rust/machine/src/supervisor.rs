//! The supervisor (docs/DESIGN.md "The supervisor and the guard"): two long-running processes that talk to the router,
//! from the first second of boot to the kill, each a child of the keeper (keeper.rs), started again whenever it exits
//! (Deyao, 2026-10-24: the supervisor must not bloat; only the part that keeps the control plane alive is protected).
//!
//! supervisor-core keeps the control plane alive: whatever else fails, the router can still stop, snapshot, Upgrade,
//! pause, rescue through a terminal grant, and the teardown still uploads. Its memory is pinned (oomguard.rs) and the
//! OOM killer leaves it alone (oom_score_adj -1000, the keeper's, inherited). Its components: the guard (guard.rs),
//! commands and deliveries (here), snapshot and freeze (snapstream.rs, snapshot.rs), the teardown (teardown.rs), the
//! Claude pause and resume (here), the log (supervisorlog.rs), the secrets (secrets.rs, deploykeys.rs).
//!
//! supervisor-normal does the rest, none of which the control plane needs: no pinned memory, the default OOM score, in
//! the session's memory cgroup: the worker count, the screen, the stall and pressure watchdogs, the status, memory and
//! disk reports, the API proxy, the live transcript sync, the Claude login sync.
//!
//! Both run as root with user claude's file access; the session (user claude) can't signal them. What either starts for
//! the session goes through session_command: user claude, back at the default OOM score. A stop signal reaches the
//! keeper, which kills supervisor-normal and asks supervisor-core for the teardown (SIGUSR1).

use crate::client::Client;
use crate::deliver::Delivery;
use crate::grants::Exec;
use crate::session::{privileged, session_command, session_file_access, signal_session};
use crate::snapshot::{FROZEN, FULL_SNAPSHOT, booted};
use crate::util::{clip, go_quote};
use crate::{logf, machine_id, on_aws, paths, util};
use anyhow::{Result, anyhow, bail};
use nix::sys::signal::Signal;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::os::unix::fs::MetadataExt;
use std::sync::atomic::Ordering;
use std::time::Duration;

/// how long the router holds a poll of /m/commands open when it has nothing (rust/router/src/http.rs mqNext 50 s)
pub const COMMANDS_WAIT: Duration = Duration::from_secs(50);

/// supervisor-core, what keeps the control plane alive: the commands (stop, snapshot, Upgrade, pause), execs and
/// deliveries through the guard, the secrets and deploy keys, the supervisor log and the teardown's uploads. While the
/// machine boots it answers a snapshot with the predecessor's (or "nothing to snapshot").
pub fn supervise_core() -> Result<()> {
    if privileged() {
        // first, before any other thread: every thread made later takes this file identity
        session_file_access().map_err(|e| anyhow!("supervisor-core's file access: {e:#}"))?;
        crate::oomguard::lock_memory("supervisor-core"); // mlock isn't inherited from the keeper
    }
    crate::supervisorlog::log_to_supervisor_log();
    let c = Client::new()?;
    crate::kernelboot::arm_kernel_trust_refresh(&c); // a copy flip's new notary is learnt where deliveries are checked
    {
        // the keeper's teardown (a stop signal): upload, most important first, then end
        let c = c.clone();
        let mut sigs = signal_hook::iterator::Signals::new([signal_hook::consts::SIGUSR1])?;
        std::thread::spawn(move || {
            if sigs.forever().next().is_some() {
                crate::teardown::teardown(&c);
                std::process::exit(0);
            }
        });
    }
    if crate::snapshot::final_snapshot_sum().is_ok() {
        // an earlier supervisor-core of this machine took the final snapshot: nothing guarded runs again
        FROZEN.store(true, Ordering::SeqCst);
    }
    crate::secrets::HELD.load_held(); // what an earlier supervisor-core held
    {
        let c = c.clone();
        std::thread::spawn(move || crate::secrets::serve_secrets(c));
    }
    std::thread::spawn(crate::deploykeys::serve_ssh_agent);
    {
        let c = c.clone();
        std::thread::spawn(move || crate::supervisorlog::push_supervisor_log(&c));
    }
    if on_aws() {
        let c = c.clone();
        std::thread::spawn(move || crate::output::push_outputs(&c));
    }
    logf!("supervisor-core up (pid {})", std::process::id());
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Out {
        commands: Vec<String>,
        execs: Vec<Exec>,
        /// vouched, core-attested inputs (deliver.rs)
        deliveries: Vec<Delivery>,
    }
    // the router answers within COMMANDS_WAIT; past that plus a margin the poll is given up and made again (a far end
    // that holds the connection but never answers, e.g. a gateway's upstream gone), never the client's 10 minutes
    let mut poll = c.clone();
    poll.timeout = Some(COMMANDS_WAIT + Duration::from_secs(60));
    let mut failing = false;
    loop {
        let out: Out = match poll.json::<(), Out>("GET", "/m/commands", None) {
            Ok(o) => {
                if failing {
                    logf!("commands: the router answers again");
                    failing = false;
                }
                o
            }
            Err(e) => {
                if !failing {
                    // once per run of failures: deliveries wait while this lasts (the router retries them)
                    logf!("commands: GET /m/commands failed, polling again every 5 s: {e:#}");
                    failing = true;
                }
                util::sleep(Duration::from_secs(5));
                continue;
            }
        };
        for e in out.execs {
            // guarded (guard.rs guard_exec)
            let c = c.clone();
            std::thread::spawn(move || crate::grants::run_exec(&c, e));
        }
        for d in out.deliveries {
            // guarded (guard.rs guard_delivery)
            let c = c.clone();
            std::thread::spawn(move || crate::deliver::run_delivery(&c, d));
        }
        for cmd in out.commands {
            run_command(&c, &cmd);
        }
    }
}

/// supervisor-normal, everything that can go missing for a while without losing the machine. No pinned memory and no
/// OOM protection: it runs in the session's memory cgroup, and when it dies the keeper starts it again.
pub fn supervise_normal() -> Result<()> {
    if privileged() {
        let _ = std::fs::write("/proc/self/oom_score_adj", "0\n"); // the keeper's -1000 is for supervisor-core only
        crate::oomguard::join_cgroup(crate::oomguard::SESSION_CGROUP); // charged with the session
        session_file_access().map_err(|e| anyhow!("supervisor-normal's file access: {e:#}"))?;
    }
    crate::supervisorlog::log_to_supervisor_log();
    let c = Client::new()?;
    crate::kernelboot::arm_kernel_trust_refresh(&c);
    crate::workers::set_worker_count(&paths::workers_state());
    std::thread::spawn(crate::workers::serve_worker_count);
    while !booted() {
        util::sleep(Duration::from_secs(1));
    }
    let spawn = |f: fn(&Client), c: &Client| {
        let c = c.clone();
        std::thread::spawn(move || f(&c));
    };
    spawn(crate::status::status_reporter, &c);
    spawn(crate::memory::memory_reporter, &c);
    spawn(crate::disk::disk_reporter, &c);
    spawn(crate::screen::screen_reporter, &c);
    std::thread::spawn(crate::stall::stall_watch); // the 15-minute watchdog on its own harness
    std::thread::spawn(crate::pressure::pressure_watch_loop); // memory or disk pressure told to its own harness
    std::thread::spawn(crate::autoaccept::auto_accept); // in bypass, tool permission dialogs on its own pane allowed once
    std::thread::spawn(crate::rcwatch::rc_watch); // Remote Control brought back when it drops
    spawn(crate::apiproxy::serve_api_proxy, &c); // $JARVIS_URL for the session scripts
    spawn(crate::livesync::live_sync, &c); // the transcripts to the Storage Box (through the router) for search
    std::thread::spawn(crate::claudelogin::start_creds_sync_on_marker); // the Claude login sync, once boot leaves its marker
    logf!("supervisor-normal up (pid {})", std::process::id());
    loop {
        std::thread::park();
    }
}

/// the unguarded commands, which carry no instruction (a word each)
pub fn run_command(c: &Client, cmd: &str) {
    match cmd {
        "free" => {
            // memory.rs: an Upgrade, before its snapshot
            if booted() && !FROZEN.load(Ordering::SeqCst) {
                logf!("free: stopping the session's processes for an Upgrade");
                crate::memory::free_memory();
            }
        }
        "refresh-secrets" => {
            // putkey.rs: an unlock for this cert went through
            if booted() {
                let c = c.clone();
                std::thread::spawn(move || crate::putkey::refresh_from_router(&c));
            }
        }
        "claude-account" => {
            // claudelogin.rs: the router switched the session's Claude account
            if booted() && !FROZEN.load(Ordering::SeqCst) {
                crate::claudelogin::claude_account_cmd();
            }
        }
        "pause-harness" => {
            if let Err(e) = pause_harness() {
                logf!("pause-harness: {e:#}");
            }
        }
        "resume-harness" => {
            if FROZEN.load(Ordering::SeqCst) {
                logf!("resume-harness refused: the session is stopped for its final snapshot");
            } else if let Err(e) = resume_harness() {
                logf!("resume-harness: {e:#}");
            }
        }
        "live-sync" => {
            // livesync.rs: the router wants this session's tail now (rust/router/src/livetail.rs)
            if booted() {
                let c = c.clone();
                std::thread::spawn(move || crate::livesync::live_round(&c));
            }
        }
        "snapshot" | "snapshot-full" => {
            if booted() && !FROZEN.load(Ordering::SeqCst) {
                // the .live copies end where the snapshot does, so a paused session's tail is its last word
                let n = crate::livesync::live_syncer_for(c).once();
                logf!("snapshot: {n} changed transcripts sent first");
            }
            if cmd == "snapshot-full" {
                FULL_SNAPSHOT.store(true, Ordering::SeqCst); // the session ends with this machine (a destroy)
            }
            if !booted() {
                if let Err(e) = crate::snapstream::booting_snapshot(c) {
                    logf!("answering the snapshot while booting: {e:#}");
                }
            } else if let Err(e) = crate::snapstream::upload_snapshot(c) {
                logf!("snapshot failed: {e:#}");
                crate::snapstream::report_snapshot_failed(c, &e); // the pause stops waiting, and nothing is lost
            }
        }
        _ => logf!("unknown command {} ignored", go_quote(&clip(cmd, 40))),
    }
}

// ---- the Claude process: pause and resume ---------------------------------------------------------------------------

/// the harness's launcher (the keeper names it: keeper.rs), or the boot steps while booting
pub fn harness_pid() -> i32 {
    crate::crypto::read_trim(&crate::keeper::harness_pid_path())
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

/// the keeper (the supervisors' parent), never stopped or killed by the supervisor itself
pub fn keeper_pid() -> i32 {
    if let Some((p, _)) = TEST_KEEPER.lock().ok().and_then(|g| *g) {
        return p;
    }
    nix::unistd::getppid().as_raw()
}

/// tests: the keeper's pid and whether it is init
pub static TEST_KEEPER: std::sync::Mutex<Option<(i32, bool)>> = std::sync::Mutex::new(None);

/// The keeper is pid 1 of this pid namespace. On an AWS instance it is (docker runs the image's entrypoint as the
/// container's init). On Fly, pid 1 is Fly's own init, and a supervisor sees ppid 1 only once its keeper died and it
/// was re-parented there. Told apart by pid 1's executable: the keeper is this very binary.
pub fn keeper_is_init() -> bool {
    if let Some((_, i)) = TEST_KEEPER.lock().ok().and_then(|g| *g) {
        return i;
    }
    let root = crate::memory::proc_root();
    match (
        std::fs::metadata(root.join("1/exe")),
        std::fs::metadata(root.join("self/exe")),
    ) {
        (Ok(a), Ok(b)) => a.dev() == b.dev() && a.ino() == b.ino(),
        _ => false,
    }
}

/// tests: the process tree (pid → children) and the tmux panes instead of /proc and tmux
pub type TestTree = (HashMap<i32, Vec<i32>>, Vec<i32>);
pub static TEST_TREE: std::sync::Mutex<Option<TestTree>> = std::sync::Mutex::new(None);

/// pid → its children, from /proc
pub fn children() -> HashMap<i32, Vec<i32>> {
    if let Some((k, _)) = TEST_TREE.lock().ok().and_then(|g| g.clone()) {
        return k;
    }
    let mut out: HashMap<i32, Vec<i32>> = HashMap::new();
    let root = crate::memory::proc_root();
    for e in std::fs::read_dir(&root).into_iter().flatten().flatten() {
        let Ok(pid) = e.file_name().to_string_lossy().parse::<i32>() else {
            continue;
        };
        let Ok(s) = std::fs::read_to_string(e.path().join("stat")) else {
            continue;
        };
        // pid (comm) state ppid …: comm may hold spaces and parentheses, so cut at the last ')'
        let Some(i) = s.rfind(')') else { continue };
        let f: Vec<&str> = s[i + 1..].split_whitespace().collect();
        if f.len() < 2 {
            continue;
        }
        let ppid = f[1].parse().unwrap_or(0);
        out.entry(ppid).or_default().push(pid);
    }
    out
}

/// the pid of every pane's process (the Claude host runs in tmux session `claude`, whose server is not a child of the
/// launcher)
pub fn tmux_panes() -> Vec<i32> {
    if let Some((_, p)) = TEST_TREE.lock().ok().and_then(|g| g.clone()) {
        return p;
    }
    match session_command("tmux", &["list-panes", "-a", "-F", "#{pane_pid}"]).output() {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout)
            .split_whitespace()
            .filter_map(|l| l.parse().ok())
            .collect(),
        _ => vec![],
    }
}

/// the launcher, every tmux pane's process and all their descendants, parents first; never the supervisor (either
/// half, or the keeper) or pid 1
pub fn harness_tree() -> Vec<i32> {
    let kids = children();
    let skip: HashSet<i32> = [std::process::id() as i32, keeper_pid(), 1, 0]
        .into_iter()
        .collect();
    let mut seen = HashSet::new();
    let mut order = vec![];
    fn walk(
        p: i32,
        kids: &HashMap<i32, Vec<i32>>,
        skip: &HashSet<i32>,
        seen: &mut HashSet<i32>,
        order: &mut Vec<i32>,
    ) {
        if seen.contains(&p) || skip.contains(&p) {
            return;
        }
        seen.insert(p);
        order.push(p);
        let mut k = kids.get(&p).cloned().unwrap_or_default();
        k.sort();
        for c in k {
            walk(c, kids, skip, seen, order);
        }
    }
    let h = harness_pid();
    if h > 1 {
        walk(h, &kids, &skip, &mut seen, &mut order);
    }
    for p in tmux_panes() {
        walk(p, &kids, &skip, &mut seen, &mut order);
    }
    order
}

/// SIGSTOP the Claude process (its launcher, the tmux panes and everything under them), parents first so nothing
/// restarts a stopped child; the stopped pids are kept for resume_harness
pub fn pause_harness() -> Result<()> {
    let pids = harness_tree();
    if pids.is_empty() {
        bail!("no harness process found");
    }
    let stopped: Vec<String> = pids
        .into_iter()
        .filter(|p| crate::memory::signal_proc(*p, Signal::SIGSTOP).is_ok())
        .map(|p| p.to_string())
        .collect();
    util::write_file(
        &paths::harness_paused_path(),
        stopped.join("\n").as_bytes(),
        0o600,
    )?;
    logf!(
        "pause-harness: stopped the Claude process ({} processes)",
        stopped.len()
    );
    Ok(())
}

/// SIGCONT what pause_harness stopped, children first
pub fn resume_harness() -> Result<()> {
    let b = std::fs::read_to_string(paths::harness_paused_path())
        .map_err(|_| anyhow!("the harness isn't paused"))?;
    let pids: Vec<&str> = b.split_whitespace().collect();
    let n = pids
        .iter()
        .rev()
        .filter_map(|p| p.parse::<i32>().ok())
        .filter(|p| crate::memory::signal_proc(*p, Signal::SIGCONT).is_ok())
        .count();
    let _ = std::fs::remove_file(paths::harness_paused_path());
    logf!("resume-harness: let the Claude process go on ({n} processes)");
    Ok(())
}

// ---- the whole session, for the final snapshot ----------------------------------------------------------------------

/// the Claude process first (pause_harness), then SIGSTOP to every other process of user claude (signal_session: never
/// root's, so never the keeper or the supervisors). Only on a session machine.
/// tests count the freezes and thaws here (frozen, thawed) instead
pub static TEST_FREEZE: std::sync::Mutex<Option<(usize, usize)>> = std::sync::Mutex::new(None);

pub fn freeze_session() {
    if let Ok(mut g) = TEST_FREEZE.lock()
        && let Some(c) = g.as_mut()
    {
        c.0 += 1;
        return;
    }
    if machine_id().is_empty() {
        return;
    }
    if let Err(e) = pause_harness() {
        logf!("freezing the session: {e:#}");
    }
    if let Err(e) = signal_session("STOP") {
        logf!("freezing the session: {e:#}");
    }
    logf!("session stopped for the final snapshot");
}

/// SIGCONT to the session (the counterpart of freeze_session, after a failed snapshot); only on a session machine
pub fn thaw_session() {
    if let Ok(mut g) = TEST_FREEZE.lock()
        && let Some(c) = g.as_mut()
    {
        c.1 += 1;
        return;
    }
    if machine_id().is_empty() {
        return;
    }
    if let Err(e) = signal_session("CONT") {
        logf!("thawing the session: {e:#}");
    }
    let _ = std::fs::remove_file(paths::harness_paused_path());
    logf!("session let go on");
}
