//! The keeper (docs/DESIGN.md "The keeper"; DECISIONS 2026-10-21): `jarvis-machine boot`, the image's ENTRYPOINT, run
//! as root. It is Fly's main child for the machine's whole life: Fly ends the machine when its main child ends, so
//! nothing but the keeper's own exit can end it, and only root can signal it (Deyao, 2026-10-21: "The supervisor should
//! be the main child. Nothing should be able to kill the supervisor other than a sigterm or sigkill from something with
//! higher privilege.").
//!
//! Its children, each in its own session (setsid) so no process group of the session holds the keeper:
//!
//!   child                         identity                         restarted when it ends
//!   prepare (the boot steps)      user claude                      no: it hands the harness's env over and ends
//!   supervisor-core               root, with user claude's file    yes (backoff 1 s … 30 s)
//!                                 access, pinned memory,
//!                                 OOM-protected
//!   supervisor-normal             root, user claude's file access, yes (backoff 1 s … 1 min)
//!                                 the session's memory cgroup
//!   the harness (entrypoint.sh    user claude                      yes (backoff 1 s … 1 min), with the same
//!   → harness-*.sh)                                                conversation resumed
//!
//! A dead harness never ends the machine: the keeper logs how it ended and its uptime, kills what is left of its process
//! group, and starts it again after the backoff with the secrets the supervisor holds now and JARVIS_HARNESS_START=n.
//! No restart once the session is stopped for its final snapshot.
//!
//! Stop signals (SIGTERM, SIGINT: Fly's stop; SIGHUP, SIGQUIT) start the priority teardown, most important first:
//! supervisor-normal is killed, supervisor-core (SIGUSR1) sends the transcripts that changed and streams the final
//! snapshot and commits it; then the harness's process group gets SIGTERM, then SIGKILL, every other process of user
//! claude too, and the keeper exits.

use crate::harnesslog::{HarnessLog, harness_stdout};
use crate::secrets::{SecretsReq, ask_secrets};
use crate::session::{not_dumpable, privileged, session, signal_session};
use crate::vouch::HarnessSpec;
use crate::{gojson, logf, machine_id, on_aws, on_fabric, paths, util};
use anyhow::{Result, anyhow};
use command_fds::{CommandFdExt, FdMapping};
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Read;
use std::os::fd::OwnedFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// Jarvis 1's entrypoint: the harness
pub const BASE_ENTRY: &str = "/usr/local/bin/entrypoint.sh";
const HARNESS_BACKOFF0: Duration = Duration::from_secs(1);

/// tests: the harness's entry, its first backoff and the secrets it starts with
pub struct TestHarness {
    pub entry: PathBuf,
    pub backoff0: Duration,
    pub secrets: HashMap<String, String>,
}

pub static TEST_HARNESS: Mutex<Option<TestHarness>> = Mutex::new(None);
const HARNESS_BACKOFF_MAX: Duration = Duration::from_secs(60);
/// up this long: the backoff starts again at 1 s
const HARNESS_STABLE: Duration = Duration::from_secs(600);
/// SIGTERM → SIGKILL for the harness's process group
const HARNESS_GRACE: Duration = Duration::from_secs(5);
/// supervisor-core's teardown, at most (Fly's kill timeout ends it sooner)
const TEARDOWN_MAX: Duration = Duration::from_secs(30 * 60);

/// the boot steps' pid, then the harness launcher's (each start)
pub fn harness_pid_path() -> PathBuf {
    keeper_dir().join("harness.pid")
}

/// root's (0755): what only the keeper writes (tests move it)
pub static TEST_KEEPER_DIR: std::sync::RwLock<Option<PathBuf>> = std::sync::RwLock::new(None);

pub fn keeper_dir() -> PathBuf {
    TEST_KEEPER_DIR
        .read()
        .ok()
        .and_then(|p| p.clone())
        .unwrap_or_else(|| PathBuf::from(paths::KEEPER_DIR))
}

/// the harness's starts and last end (the status report)
pub fn harness_state_path() -> PathBuf {
    keeper_dir().join("harness.json")
}

/// what the keeper tells the status report about the harness
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct HarnessState {
    pub starts: i64,
    pub running: bool,
    #[serde(skip_serializing_if = "is_zero", rename = "pid")]
    pub pid: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub started_at: String,
    /// "exit status 1", "killed by SIGTERM", …
    #[serde(skip_serializing_if = "String::is_empty")]
    pub last_exit: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub last_exit_at: String,
    #[serde(skip_serializing_if = "is_zero")]
    pub last_up_secs: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub next_start: String,
}

fn is_zero(n: &i64) -> bool {
    *n == 0
}

#[derive(Default)]
struct KeeperState {
    stopping: bool,
    core: Option<u32>,
    normal: Option<u32>,
    harness: Option<u32>,
    state: HarnessState,
}

pub struct Keeper {
    mu: Mutex<KeeperState>,
    stop_cv: Condvar,
    core_end: (Mutex<bool>, Condvar),
    hlog: Arc<HarnessLog>,
}

pub fn keeper() -> Result<()> {
    // first: the env this machine was started with is thrown away, except what the image, Fly and the core set
    // (vouch.rs). Re-execs once.
    if let Err(e) = crate::vouch::ensure_clean_env() {
        logf!("REFUSING TO START: {e:#}");
        loop {
            std::thread::park();
        }
    }
    let k = Arc::new(Keeper::new());
    use signal_hook::consts::*;
    let mut sigs = signal_hook::iterator::Signals::new([SIGTERM, SIGINT, SIGHUP, SIGQUIT])?;
    // job control on a keeper with no terminal: caught and dropped
    let _quiet = signal_hook::iterator::Signals::new([SIGTTOU, SIGTTIN, SIGTSTP])?;
    if privileged() {
        if let Err(e) = keeper_dirs() {
            logf!("REFUSING TO START: {e:#}");
            loop {
                std::thread::park();
            }
        }
        if on_aws()
            && let Err(e) = crate::output::tee_output()
        {
            logf!("the output's tee: {e:#} (it goes to the instance's journal only)");
        }
        protect_from_oom();
        crate::oomguard::make_cgroups(); // the session's and the rescue memory limits, before the boot steps start
        crate::oomguard::lock_memory("keeper");
        not_dumpable();
    } else {
        logf!("the keeper isn't root: the session can signal it (an image whose USER isn't root?)");
    }
    crate::supervisorlog::log_to_supervisor_log();
    logf!(
        "keeper up (pid {}, uid {}): Fly's main child for this machine's life",
        std::process::id(),
        nix::unistd::Uid::current()
    );
    let (spec_tx, spec_rx) = std::sync::mpsc::channel::<Option<HarnessSpec>>();
    if let Err(e) = k.start_prepare(spec_tx) {
        logf!("REFUSING TO START: the boot steps: {e:#}");
        loop {
            std::thread::park();
        }
    }
    if (on_fabric() || on_aws()) && privileged() {
        let k = k.clone();
        std::thread::spawn(move || k.announce_keys()); // the spawner reads it from the console
    }
    if on_aws() && privileged() {
        let k = k.clone();
        std::thread::spawn(move || crate::output::ship_host_journal(&k.stopping_flag()));
    }
    {
        let k = k.clone();
        std::thread::spawn(move || k.core_loop());
    }
    {
        let k = k.clone();
        std::thread::spawn(move || k.normal_loop());
    }
    {
        let k = k.clone();
        std::thread::spawn(move || {
            if let Ok(Some(spec)) = spec_rx.recv() {
                k.harness_loop(spec);
            }
        });
    }
    let s = sigs.forever().next().unwrap_or(SIGTERM);
    let handle = sigs.handle();
    std::thread::spawn(move || {
        // a second stop signal while tearing down: logged, nothing more (Fly's SIGKILL ends it)
        for s2 in sigs.forever() {
            logf!("{} during the teardown; carrying on", signal_text(s2));
        }
    });
    k.teardown(s);
    handle.close();
    Ok(())
}

fn signal_text(s: i32) -> String {
    Signal::try_from(s)
        .map(|s| match s {
            Signal::SIGTERM => "terminated".to_string(),
            Signal::SIGINT => "interrupt".to_string(),
            Signal::SIGHUP => "hangup".to_string(),
            Signal::SIGQUIT => "quit".to_string(),
            s => s.as_str().to_string(),
        })
        .unwrap_or_else(|_| format!("signal {s}"))
}

/// /run/jarvis (user claude's) and the keeper's own /run/jarvis-keeper (root's). On a session machine /run/jarvis is
/// a tmpfs of its own: the machine's key pair lives there, in memory only, never on a disk or the volume (DECISIONS 228).
fn keeper_dirs() -> Result<()> {
    let s = session();
    let dir = paths::dir();
    std::fs::create_dir_all(&dir)?;
    if !machine_id().is_empty() {
        memory_dir(&dir).map_err(|e| anyhow!("{} in memory: {e:#}", dir.display()))?;
    }
    nix::unistd::chown(
        &dir,
        Some(nix::unistd::Uid::from_raw(s.uid)),
        Some(nix::unistd::Gid::from_raw(s.gid)),
    )?;
    let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755));
    std::fs::create_dir_all(paths::KEEPER_DIR)?;
    let _ = nix::unistd::chown(
        paths::KEEPER_DIR,
        Some(nix::unistd::Uid::from_raw(0)),
        Some(nix::unistd::Gid::from_raw(0)),
    );
    std::fs::set_permissions(paths::KEEPER_DIR, std::fs::Permissions::from_mode(0o755))?;
    Ok(())
}

/// a tmpfs on d, unless d is one already (the keeper started again in the same boot keeps what is there)
fn memory_dir(d: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let fs = nix::sys::statfs::statfs(d)?;
    let st = std::fs::metadata(d)?;
    let parent = std::fs::metadata(d.join(".."))?;
    if fs.filesystem_type().0 as i64 == 0x01021994 && st.dev() != parent.dev() {
        return Ok(()); // TMPFS_MAGIC, mounted on d itself
    }
    use nix::mount::{MsFlags, mount};
    mount(
        Some("tmpfs"),
        d,
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        Some("mode=755,size=256m"),
    )?;
    logf!(
        "{}: a tmpfs (the machine's keys live in memory only)",
        d.display()
    );
    Ok(())
}

/// oom_score_adj -1000 (never chosen by the OOM killer) for the keeper; supervisor-core inherits it (supervisor-normal
/// sets its own back to 0). Only on a session machine.
fn protect_from_oom() {
    if machine_id().is_empty() {
        return;
    }
    match std::fs::write("/proc/self/oom_score_adj", "-1000\n") {
        Err(e) => logf!("OOM protection: {e}"),
        Ok(()) => logf!("OOM protection on (oom_score_adj -1000)"),
    }
}

impl Keeper {
    pub(crate) fn new() -> Keeper {
        Keeper {
            mu: Mutex::new(KeeperState::default()),
            stop_cv: Condvar::new(),
            core_end: (Mutex::new(false), Condvar::new()),
            hlog: Arc::new(HarnessLog::supervisor()),
        }
    }

    /// the harness's state as the status report reads it
    pub(crate) fn harness_state(&self) -> HarnessState {
        self.lock().state.clone()
    }

    /// what a stop signal does first: the loops end
    pub(crate) fn stop(&self) {
        self.lock().stopping = true;
        self.stop_cv.notify_all();
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, KeeperState> {
        self.mu.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn is_stopping(&self) -> bool {
        self.lock().stopping
    }

    fn stopping_flag(self: &Arc<Self>) -> Arc<AtomicBool> {
        let f = Arc::new(AtomicBool::new(false));
        let (k, f2) = (self.clone(), f.clone());
        std::thread::spawn(move || {
            let mut g = k.lock();
            while !g.stopping {
                g = k.stop_cv.wait(g).unwrap_or_else(|e| e.into_inner());
            }
            f2.store(true, Ordering::SeqCst);
        });
        f
    }

    /// d, or less when the keeper starts stopping; false = stopping
    fn sleep(&self, d: Duration) -> bool {
        let g = self.lock();
        let (g, _) = self
            .stop_cv
            .wait_timeout_while(g, d, |s| !s.stopping)
            .unwrap_or_else(|e| e.into_inner());
        !g.stopping
    }

    /// the boot steps as user claude (prepare_cmd); the harness's env arrives on a pipe (fd 3), never on disk
    fn start_prepare(
        self: &Arc<Self>,
        spec_tx: std::sync::mpsc::Sender<Option<HarnessSpec>>,
    ) -> Result<()> {
        let (r, w) = std::io::pipe()?;
        let mut cmd = unprotected_setsid("/proc/self/exe", &["prepare"]);
        cmd.fd_mappings(vec![FdMapping {
            parent_fd: OwnedFd::from(w),
            child_fd: 3,
        }])
        .map_err(|e| anyhow!("{e:?}"))?;
        let mut child = cmd.spawn()?;
        drop(cmd); // the parent's copy of the write end goes with the command
        write_harness_pid(child.id() as i64); // boot-env: the boot steps ask for the secrets (secrets.rs)
        std::thread::spawn(move || {
            let mut b = vec![];
            let mut r = r;
            let _ = r.read_to_end(&mut b);
            let st = child.wait();
            match gojson::unmarshal::<HarnessSpec>(&b) {
                Ok(spec) if !spec.clean.is_empty() => {
                    let _ = spec_tx.send(Some(spec));
                }
                _ => {
                    logf!(
                        "the boot steps ended ({}) without the harness's env: no harness on this machine; the supervisor stays up for the router",
                        exit_text(&st)
                    );
                    let _ = spec_tx.send(None);
                }
            }
        });
        Ok(())
    }

    /// supervisor-core, started once init asked and again whenever it exits; the secrets' memfd is the keeper's, so a
    /// new supervisor-core has them without a pull
    fn core_loop(self: &Arc<Self>) {
        if self.wait_init() {
            let mem = match crate::secrets::new_memfd() {
                Ok(m) => Some(m),
                Err(e) => {
                    logf!("secrets memfd: {e:#} (a restarted supervisor-core pulls again)");
                    None
                }
            };
            self.child_loop(
                "supervisor-core",
                "--core",
                Duration::from_secs(30),
                mem.as_ref(),
                |s, p| s.core = p,
            );
        }
        let (m, cv) = &self.core_end;
        if let Ok(mut g) = m.lock() {
            *g = true;
        }
        cv.notify_all();
    }

    /// supervisor-normal, started with supervisor-core and again whenever it exits
    fn normal_loop(self: &Arc<Self>) {
        if !self.wait_init() {
            return;
        }
        self.child_loop(
            "supervisor-normal",
            "--normal",
            Duration::from_secs(60),
            None,
            |s, p| s.normal = p,
        );
    }

    /// On an AWS instance (and the fabric) nothing runs jarvis2-init: the spawner reads the keys from the console, so
    /// the keeper writes them there, and lets boot go on as init would, once boot has made them; again every 20 s until
    /// the cert is in.
    fn announce_keys(&self) {
        let console = keys_console();
        loop {
            match std::fs::read(paths::keys_path()) {
                Ok(b) => {
                    if !paths::go_path().exists() {
                        let _ = util::write_file(
                            &paths::go_path(),
                            util::now_rfc3339().as_bytes(),
                            0o644,
                        );
                    }
                    match std::fs::OpenOptions::new().write(true).open(console) {
                        Ok(mut f) => {
                            use std::io::Write;
                            let _ = write!(
                                f,
                                "\n{}{}\n",
                                paths::KEYS_MARK,
                                String::from_utf8_lossy(&b).trim()
                            );
                        }
                        Err(e) => logf!("keys to the console: {e}"),
                    }
                    if paths::cert_path().exists() || !self.sleep(Duration::from_secs(20)) {
                        return;
                    }
                }
                Err(_) => {
                    if !self.sleep(Duration::from_secs(1)) {
                        return;
                    }
                }
            }
        }
    }

    /// until init asked (false: the machine is stopping)
    fn wait_init(&self) -> bool {
        loop {
            if paths::go_path().exists() {
                return true;
            }
            if !self.sleep(Duration::from_secs(1)) {
                return false;
            }
        }
    }

    /// `jarvis-machine supervisor FLAG` in its own session (the child calls setsid itself), started again (backoff
    /// 1 s … max_backoff) until the machine stops; slot holds the running process
    fn child_loop(
        &self,
        name: &str,
        flag: &str,
        max_backoff: Duration,
        mem: Option<&OwnedFd>,
        slot: fn(&mut KeeperState, Option<u32>),
    ) {
        let mut backoff = Duration::from_secs(1);
        while !self.is_stopping() {
            let started = Instant::now();
            let mut cmd = Command::new("/proc/self/exe");
            cmd.args(["supervisor", flag]);
            if let Some(m) = mem
                && let Ok(fd) = m.try_clone()
            {
                let _ = cmd.fd_mappings(vec![FdMapping {
                    parent_fd: fd,
                    child_fd: 3,
                }]);
                cmd.env(crate::secrets::SECRETS_FD_ENV, "3");
            }
            let st = match cmd.spawn() {
                Err(e) => {
                    logf!("{name}: {e}");
                    Err(anyhow!("{e}"))
                }
                Ok(mut child) => {
                    {
                        let mut g = self.lock();
                        slot(&mut g, Some(child.id()));
                        if g.stopping && flag == "--core" {
                            // the teardown began while it started: it gets the signal the teardown sent the last one
                            let _ = kill(Pid::from_raw(child.id() as i32), Signal::SIGUSR1);
                        }
                    }
                    drop(cmd);
                    let st = child.wait().map_err(|e| anyhow!("{e}"));
                    slot(&mut self.lock(), None);
                    st
                }
            };
            if self.is_stopping() {
                logf!("{name} ended ({})", exit_text(&st));
                return;
            }
            if started.elapsed() > Duration::from_secs(60) {
                backoff = Duration::from_secs(1);
            }
            logf!(
                "{name} exited ({}); starting it again in {}",
                exit_text(&st),
                dur_text(backoff)
            );
            if !self.sleep(backoff) {
                return;
            }
            backoff = (backoff * 2).min(max_backoff);
        }
    }

    /// the harness (Jarvis 1's entrypoint, then harness-*.sh), as user claude in its own session, started again
    /// whenever it ends
    pub(crate) fn harness_loop(&self, spec: HarnessSpec) {
        let (entry, backoff0) = match TEST_HARNESS.lock().ok().as_deref().and_then(Option::as_ref) {
            Some(t) => (t.entry.to_string_lossy().into_owned(), t.backoff0),
            None => (BASE_ENTRY.to_string(), HARNESS_BACKOFF0),
        };
        let mut backoff = backoff0;
        let mut n: i64 = 1;
        loop {
            if self.is_stopping() {
                return;
            }
            if paths::final_snapshot_sig().exists() && n > 1 {
                logf!(
                    "the session is stopped for its final snapshot: the harness isn't started again"
                );
                return;
            }
            let mut env = spec.env(&self.secrets());
            env.push(format!("JARVIS_HARNESS_START={n}"));
            let mut cmd = unprotected_setsid(&entry, &[]);
            cmd.env_clear()
                .envs(env.iter().filter_map(|kv| kv.split_once('=')));
            if let Ok(out) = harness_stdout(self.hlog.clone())
                && let Ok(out2) = out.try_clone()
            {
                cmd.stdout(out).stderr(out2);
            }
            let home = &session().home;
            if std::fs::metadata(home).is_ok_and(|m| m.is_dir()) {
                cmd.current_dir(home);
            }
            let spawned = {
                let mut g = self.lock();
                if g.stopping {
                    return;
                }
                let r = cmd.spawn();
                if let Ok(c) = &r {
                    g.harness = Some(c.id());
                }
                r
            };
            drop(cmd); // the harness holds the pipe's write end now; the reader ends once the harness and its loops are gone
            drop(env);
            let mut child: Child = match spawned {
                Err(e) => {
                    logf!(
                        "the harness didn't start: {e}; trying again in {}",
                        dur_text(backoff)
                    );
                    if !self.sleep(backoff) {
                        return;
                    }
                    backoff = (backoff * 2).min(HARNESS_BACKOFF_MAX);
                    n += 1;
                    continue;
                }
                Ok(c) => c,
            };
            let pid = child.id() as i64;
            write_harness_pid(pid);
            let started = Instant::now();
            self.set_state(|s| {
                s.starts = n;
                s.running = true;
                s.pid = pid;
                s.started_at = util::now_rfc3339();
                s.next_start = String::new();
            });
            if n == 1 {
                logf!("harness started (pid {pid})");
            } else {
                logf!(
                    "harness started again (start {n}, pid {pid}): the same conversation resumes"
                );
            }
            let st = child.wait();
            let up = started.elapsed();
            let how = exit_how(&st);
            let stopping = {
                let mut g = self.lock();
                g.harness = None;
                g.stopping
            };
            kill_group(pid as i32); // what is left of its process group: the next start brings its own
            self.set_state(|s| {
                s.running = false;
                s.pid = 0;
                s.last_exit = how.clone();
                s.last_exit_at = util::now_rfc3339();
                s.last_up_secs = up.as_secs() as i64;
            });
            if stopping {
                logf!("harness ended ({how}) after {}", dur_text(round_secs(up)));
                return;
            }
            if up > HARNESS_STABLE {
                backoff = backoff0;
            }
            let next = util::format_rfc3339(util::unix_now() + backoff.as_secs() as i64);
            self.set_state(|s| s.next_start = next.clone());
            logf!(
                "HARNESS ENDED ({how}) after {} (start {n}, pid {pid}); the machine stays up; starting it again in {}",
                dur_text(round_secs(up)),
                dur_text(backoff)
            );
            if !self.sleep(backoff) {
                return;
            }
            backoff = (backoff * 2).min(HARNESS_BACKOFF_MAX);
            n += 1;
        }
    }

    /// what the supervisor holds now, for the harness's env (boot-env, answered to the keeper only: secrets.rs)
    fn secrets(&self) -> HashMap<String, String> {
        if let Some(t) = TEST_HARNESS.lock().ok().as_deref().and_then(Option::as_ref) {
            return t.secrets.clone();
        }
        match ask_secrets(
            &SecretsReq {
                op: "boot-env".into(),
                ..Default::default()
            },
            Duration::from_secs(60),
        ) {
            Ok(r) => r.secrets.into_iter().collect(),
            Err(e) => {
                logf!("the harness starts without secrets: {e:#}");
                HashMap::new()
            }
        }
    }

    fn set_state(&self, f: impl FnOnce(&mut HarnessState)) {
        let b = {
            let mut g = self.lock();
            f(&mut g.state);
            gojson::marshal(&g.state)
        };
        if !privileged() {
            return;
        }
        let p = harness_state_path();
        let tmp = PathBuf::from(format!("{}.tmp", p.display()));
        if util::write_file(&tmp, b.as_bytes(), 0o644).is_ok() {
            let _ = std::fs::rename(&tmp, &p);
        }
    }

    /// A stop signal. Most important first: supervisor-normal goes, supervisor-core uploads the transcripts that
    /// changed and then the final snapshot; then the harness's process group and the rest of the session are stopped;
    /// then the keeper exits (Fly ends the machine).
    fn teardown(&self, s: i32) {
        logf!(
            "{}: the teardown (the transcripts, then the final snapshot, then the session's processes)",
            signal_text(s)
        );
        let start = Instant::now();
        let (w, n) = {
            let mut g = self.lock();
            g.stopping = true;
            (g.core, g.normal)
        };
        self.stop_cv.notify_all();
        if let Some(n) = n {
            // supervisor-normal holds nothing the teardown needs; it doesn't compete with it
            let _ = kill(Pid::from_raw(n as i32), Signal::SIGKILL);
        }
        match w {
            Some(w) => {
                let _ = kill(Pid::from_raw(w as i32), Signal::SIGUSR1); // supervisor-core exits when it is done
            }
            None => logf!("no supervisor-core running (still booting, or between restarts)"),
        }
        let (m, cv) = &self.core_end;
        let g = m.lock().unwrap_or_else(|e| e.into_inner());
        let (g, to) = cv
            .wait_timeout_while(g, TEARDOWN_MAX, |done| !*done)
            .unwrap_or_else(|e| e.into_inner());
        drop(g);
        if to.timed_out() {
            logf!("supervisor-core's teardown is still going after 30m0s; going on without it");
            if let Some(c) = self.lock().core {
                let _ = kill(Pid::from_raw(c as i32), Signal::SIGKILL);
            }
        }
        if let Some(h) = self.lock().harness {
            kill_group(h as i32);
        }
        if privileged() {
            // every other process of the session (kill(-1) as user claude; never as anyone else)
            if let Err(e) = signal_session("CONT") {
                logf!("{e:#}"); // a frozen session: let it see the TERM
            }
            let _ = signal_session("TERM");
            util::sleep(Duration::from_secs(1));
            let _ = signal_session("KILL");
        }
        logf!("teardown done in {}; exiting", dur_text(start.elapsed()));
        push_keeper_log();
    }
}

/// a command for the session in its own session (setsid): as root through `unprotected --setsid`; otherwise in its
/// own process group (setsid needs unsafe code here; the group is what kill_group ends)
fn unprotected_setsid(name: &str, args: &[&str]) -> Command {
    if !privileged() {
        use std::os::unix::process::CommandExt;
        let mut c = Command::new(name);
        c.args(args).process_group(0);
        return c;
    }
    let mut c = Command::new("/proc/self/exe");
    c.args(["unprotected", "--setsid", "--", name]).args(args);
    c
}

pub fn exit_text<E: std::fmt::Display>(st: &Result<ExitStatus, E>) -> String {
    match st {
        Ok(s) if s.success() => "exit 0".into(),
        Ok(s) => match (s.code(), s.signal()) {
            (Some(c), _) => format!("exit status {c}"),
            (None, Some(sig)) => format!("signal: {}", signal_text(sig)),
            _ => s.to_string(),
        },
        Err(e) => e.to_string(),
    }
}

/// how a process ended, in words: "exit status 1", "killed by SIGTERM", …
pub fn exit_how<E: std::fmt::Display>(st: &Result<ExitStatus, E>) -> String {
    match st {
        Ok(s) => match (s.code(), s.signal()) {
            (Some(c), _) => format!("exit status {c}"),
            (None, Some(sig)) => format!("killed by {}", signal_name(sig)),
            _ => exit_text(st),
        },
        Err(_) => exit_text(st),
    }
}

pub fn signal_name(s: i32) -> String {
    match Signal::try_from(s) {
        Ok(
            sig @ (Signal::SIGTERM
            | Signal::SIGKILL
            | Signal::SIGINT
            | Signal::SIGHUP
            | Signal::SIGQUIT
            | Signal::SIGSEGV
            | Signal::SIGABRT
            | Signal::SIGPIPE
            | Signal::SIGUSR1
            | Signal::SIGUSR2
            | Signal::SIGBUS),
        ) => sig.as_str().to_string(),
        _ => format!("signal {s} ({})", signal_text(s)),
    }
}

/// SIGTERM (with SIGCONT, in case it is stopped) to the process group, SIGKILL after the grace
pub fn kill_group(pgid: i32) {
    if pgid <= 1 {
        return;
    }
    let g = Pid::from_raw(-pgid);
    if kill(g, Signal::SIGTERM).is_err() {
        return; // nothing left in it
    }
    let _ = kill(g, Signal::SIGCONT);
    let end = Instant::now() + HARNESS_GRACE;
    while Instant::now() < end {
        if kill(g, None).is_err() {
            return;
        }
        util::sleep(Duration::from_millis(100));
    }
    let _ = kill(g, Signal::SIGKILL);
}

pub fn write_harness_pid(pid: i64) {
    if !privileged() {
        return;
    }
    let p = harness_pid_path();
    let tmp = PathBuf::from(format!("{}.tmp", p.display()));
    if util::write_file(&tmp, pid.to_string().as_bytes(), 0o644).is_ok() {
        let _ = std::fs::rename(&tmp, &p);
    }
}

/// the boot steps wait (at most d) until the keeper has named them in harness.pid
pub fn await_harness_pid(d: Duration) {
    let end = Instant::now() + d;
    while Instant::now() < end {
        if crate::supervisor::harness_pid() == std::process::id() as i32 {
            return;
        }
        util::sleep(Duration::from_millis(50));
    }
}

/// the keeper's harness record, for the status report (None: none)
pub fn read_harness_state() -> Option<HarnessState> {
    gojson::unmarshal(&std::fs::read(harness_state_path()).ok()?).ok()
}

/// the keeper's last lines to the router (supervisor-core, which pushes the log, has ended)
fn push_keeper_log() {
    let Ok(c) = crate::client::Client::new() else {
        return;
    };
    let _ = crate::supervisorlog::push_log_once(&c);
    if on_aws() {
        util::sleep(Duration::from_millis(200)); // the tee's last lines into the file (output.rs)
        crate::output::push_outputs_once(&c);
    }
}

/// Go's Duration.String for whole seconds and up: "1s", "1m0s", "1h2m3s"; under a second "123ms"
pub fn dur_text(d: Duration) -> String {
    let ms = d.as_millis();
    if ms < 1000 {
        return format!("{ms}ms");
    }
    let total = d.as_secs_f64();
    let h = (total / 3600.0).floor() as u64;
    let m = ((total - h as f64 * 3600.0) / 60.0).floor() as u64;
    let s = total - h as f64 * 3600.0 - m as f64 * 60.0;
    let sec = if (s - s.round()).abs() < 1e-9 {
        format!("{}", s.round() as u64)
    } else {
        format!("{}", (s * 1000.0).round() / 1000.0)
    };
    if h > 0 {
        format!("{h}h{m}m{sec}s")
    } else if m > 0 {
        format!("{m}m{sec}s")
    } else {
        format!("{sec}s")
    }
}

fn round_secs(d: Duration) -> Duration {
    Duration::from_secs(d.as_secs_f64().round() as u64)
}

/// where the keys line goes: the sandbox's console on the fabric, the serial console on AWS
pub fn keys_console() -> &'static str {
    if on_fabric() {
        paths::FABRIC_CONSOLE_PATH
    } else {
        paths::CONSOLE_PATH
    }
}
