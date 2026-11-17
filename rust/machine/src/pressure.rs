//! The pressure watch (Deyao, 2026-11-12: "a jarvis watcher (similar to the idle/stall watcher) that says disk
//! pressure/memory pressure, do not upgrade; discord Deyao if upgrade is necessary or recommended"): a component of the
//! supervisor, beside the stall watch. Every 30 s it reads its own machine's memory and disk and decides by the router's
//! rules (router/memory.go, router/disk.go) whether the machine is short of memory or of disk. A process the harness's
//! own memory guard killed counts too. A new episode is told to the session's harness through the Jarvis channel at
//! once, and again every 15 minutes while it lasts. The text tells the session not to upgrade by itself: a bigger
//! machine or disk is Deyao's decision, asked for over Discord. The router takes no part.

use crate::deliver::{live_mode, send_to_harness};
use crate::disk::DiskSample;
use crate::memory::MemSample;
use crate::{logf, paths, util};
use serde::Deserialize;
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::sync::RwLock;
use std::time::{Duration, Instant};

const PRESSURE_EVERY: Duration = Duration::from_secs(30);
pub const PRESSURE_AGAIN: Duration = Duration::from_secs(15 * 60);
/// router/memory.go memClear
pub const PRESSURE_MEM_CLEAR: Duration = Duration::from_secs(15 * 60);
// router/memory.go
const PRESSURE_PSI_FULL_PCT: f64 = 10.0;
const PRESSURE_LOW_AVAIL_PCT: f64 = 5.0;
// router/disk.go
const PRESSURE_DISK_LOW_PCT: f64 = 10.0;
const PRESSURE_DISK_LOW_KB: i64 = 1024 * 1024;
const PRESSURE_DISK_CLEAR_PCT: f64 = 20.0;
const PRESSURE_DISK_CLEAR_KB: i64 = 2048 * 1024;

/// one kind of pressure (memory or disk): whether an episode runs, when the session was last told, since when the
/// machine has been healthy again
#[derive(Debug, Clone, Default)]
pub struct PressureEpisode {
    pub on: bool,
    pub told: Option<Instant>,
    pub healthy: Option<Instant>,
}

impl PressureEpisode {
    /// One look → whether to tell the session now. under: the machine is short now; healthy: it is clear (for memory the
    /// opposite of under, for the disk a higher mark); the episode ends after `clear` of healthy looks.
    pub fn step(&mut self, under: bool, healthy: bool, now: Instant, clear: Duration) -> bool {
        if under {
            self.healthy = None;
            if !self.on
                || self
                    .told
                    .is_none_or(|t| now.saturating_duration_since(t) >= PRESSURE_AGAIN)
            {
                self.on = true;
                self.told = Some(now);
                return true;
            }
            return false;
        }
        if !self.on {
            return false;
        }
        if !healthy {
            self.healthy = None;
            return false;
        }
        let h = *self.healthy.get_or_insert(now);
        if now.saturating_duration_since(h) >= clear {
            *self = PressureEpisode::default();
        }
        false
    }

    /// the harness didn't take the message: it is due again at the next look
    pub fn untold(&mut self) {
        self.told = None;
    }
}

/// the two episodes, the kernel's oom_kill count at the last look, and how far the harness's memory guard's log has
/// been read
#[derive(Debug, Default)]
pub struct PressureWatch {
    pub mem: PressureEpisode,
    pub disk: PressureEpisode,
    pub oom_kills: Option<i64>,
    pub guard: GuardLog,
}

/// where a harness with its own memory guard logs its kills: the aviary supervisor's log (JSON lines, `"msg":"memory
/// guard killed"` with `comm` and `rss` in bytes). Missing on every other harness. (tests move it)
pub static GUARD_LOG_PATH: RwLock<Option<PathBuf>> = RwLock::new(None);

fn guard_log_path() -> PathBuf {
    GUARD_LOG_PATH
        .read()
        .ok()
        .and_then(|p| p.clone())
        .unwrap_or_else(|| paths::home().join(".aviary").join("supervisor.out"))
}

/// the guard's log read up to offset; started says the first look is over (what the log held before it is not news)
#[derive(Debug, Default)]
pub struct GuardLog {
    pub offset: u64,
    pub started: bool,
}

impl GuardLog {
    /// the guard's kills logged since the last look, as "npm ci at 3.1 GB". A log that got shorter (a new one) is read
    /// from its start.
    pub fn kills(&mut self) -> Vec<String> {
        let Ok(mut f) = std::fs::File::open(guard_log_path()) else {
            return vec![];
        };
        let Ok(md) = f.metadata() else { return vec![] };
        if !self.started {
            self.started = true;
            self.offset = md.len();
            return vec![];
        }
        if md.len() < self.offset {
            self.offset = 0;
        }
        if f.seek(SeekFrom::Start(self.offset)).is_err() {
            return vec![];
        }
        let mut b = vec![];
        if f.take(4 << 20).read_to_end(&mut b).is_err() {
            return vec![];
        }
        // only whole lines: one still being written is read at the next look
        let end = b
            .iter()
            .rposition(|c| *c == b'\n')
            .map(|i| i + 1)
            .unwrap_or(0);
        self.offset += end as u64;
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct E {
            msg: String,
            comm: String,
            rss: f64,
        }
        String::from_utf8_lossy(&b[..end])
            .lines()
            .filter(|l| l.contains("memory guard killed"))
            .filter_map(|l| crate::gojson::unmarshal::<E>(l.as_bytes()).ok())
            .filter(|e| e.msg == "memory guard killed")
            .map(|e| format!("{} at {:.1} GB", e.comm, e.rss / (1u64 << 30) as f64))
            .collect()
    }
}

impl PressureWatch {
    /// why the machine is short of memory now ("" when it is not), as router/memory.go observe decides
    pub fn mem_reason(&mut self, s: &MemSample) -> String {
        let guard_kills = self.guard.kills();
        let reason = if !guard_kills.is_empty() {
            format!(
                "the session's memory guard killed {} for lack of memory",
                guard_kills.join(", ")
            )
        } else if let (Some(was), Some(now)) = (self.oom_kills, s.oom_kills)
            && now > was
        {
            let n = now - was;
            format!(
                "the kernel killed {n} process{} for lack of memory",
                if n == 1 { "" } else { "es" }
            )
        } else if let Some(p) = s.psi_full60.filter(|p| *p >= PRESSURE_PSI_FULL_PCT) {
            format!("it is thrashing (stalled on memory {p:.0}% of the last minute)")
        } else if s.total_kb > 0
            && 100.0 * s.avail_kb as f64 / (s.total_kb as f64) < PRESSURE_LOW_AVAIL_PCT
        {
            "it is almost out of memory".into()
        } else {
            String::new()
        };
        if s.oom_kills.is_some() {
            self.oom_kills = s.oom_kills;
        }
        reason
    }
}

/// the numbers and the biggest processes (router/memory.go describeMem)
pub fn mem_detail(s: &MemSample) -> String {
    let top: Vec<String> = s
        .top
        .iter()
        .flatten()
        .filter(|p| p.rss_kb > 100 * 1024)
        .map(|p| format!("{} {:.1} GB", p.comm, p.rss_kb as f64 / 1048576.0))
        .collect();
    let mut out = format!(
        "{} MB free of {:.1} GB",
        s.avail_kb / 1024,
        s.total_kb as f64 / 1048576.0
    );
    if !top.is_empty() {
        out += &format!(" (biggest: {})", top.join(", "));
    }
    out
}

/// the disk that counts (the volume when there is one, else the root): low, clear again, the numbers
pub fn disk_pressure(s: &DiskSample) -> (bool, bool, String) {
    let (fs, wh) = match &s.data {
        Some(d) if d.total_kb > 0 => (Some(d), "its volume"),
        _ => (s.root.as_ref(), "its machine's disk"),
    };
    let Some(fs) = fs.filter(|f| f.total_kb > 0) else {
        return (false, true, String::new());
    };
    let pct = 100.0 * fs.avail_kb as f64 / fs.total_kb as f64;
    let low = pct < PRESSURE_DISK_LOW_PCT || fs.avail_kb < PRESSURE_DISK_LOW_KB;
    let clear = pct >= PRESSURE_DISK_CLEAR_PCT && fs.avail_kb >= PRESSURE_DISK_CLEAR_KB;
    (
        low,
        clear,
        format!(
            "{:.1} GB free of {:.1} GB on {wh}",
            fs.avail_kb as f64 / 1048576.0,
            fs.total_kb as f64 / 1048576.0
        ),
    )
}

/// the watchdog's message; kind is "memory" or "disk"
pub fn pressure_text(kind: &str, reason: &str, detail: &str) -> String {
    let (free, more) = if kind == "disk" {
        (
            "remove files you made and no longer need (build output, caches, downloads)",
            "more disk or an upgrade",
        )
    } else {
        (
            "stop processes you no longer need (leftover browsers, finished servers, parallel builds)",
            "an upgrade to a bigger machine",
        )
    };
    format!("Jarvis watchdog: {kind} pressure on this session's machine: {reason} ({detail}). ")
        + &format!(
            "Do not upgrade the machine yourself. Free what you safely can, {free}, and carry on with the task. "
        )
        + &format!("If {more} is necessary or recommended, Discord Deyao and say why; he decides. ")
        + "This check repeats every 15 min while the pressure lasts. This is an automated message from Jarvis."
}

/// the supervisor's loop (started once booted)
pub fn pressure_watch_loop() {
    let mut w = PressureWatch::default();
    loop {
        util::sleep(PRESSURE_EVERY);
        if paths::harness_paused_path().exists() {
            continue; // paused, or stopped for the final snapshot: nobody to tell
        }
        let mut texts: Vec<(String, bool)> = vec![]; // (text, is memory)
        let now = Instant::now();
        if let Ok(s) = crate::memory::read_memory() {
            let reason = w.mem_reason(&s);
            if w.mem.step(
                !reason.is_empty(),
                reason.is_empty(),
                now,
                PRESSURE_MEM_CLEAR,
            ) {
                texts.push((pressure_text("memory", &reason, &mem_detail(&s)), true));
            }
        }
        if let Ok(s) = crate::disk::read_disk() {
            let (low, clear, detail) = disk_pressure(&s);
            if w.disk.step(low, clear, now, Duration::ZERO) {
                texts.push((
                    pressure_text("disk", "it is almost out of disk", &detail),
                    false,
                ));
            }
        }
        if texts.is_empty() {
            continue;
        }
        let mut cert = crate::grants::current_cert();
        for (text, is_mem) in texts {
            let r = match &cert {
                Ok(c) => send_to_harness(&c.options.harness, &live_mode(c), "jarvis", &text),
                Err(e) => Err(anyhow::anyhow!("{e:#}")),
            };
            match r {
                Err(e) => {
                    logf!("pressure watch: the message wasn't taken: {e:#}");
                    if is_mem {
                        w.mem.untold()
                    } else {
                        w.disk.untold()
                    }
                    cert = Err(e);
                }
                Ok(()) => logf!(
                    "pressure watch: told the session ({})",
                    text.split(". ").next().unwrap_or("")
                ),
            }
        }
    }
}
