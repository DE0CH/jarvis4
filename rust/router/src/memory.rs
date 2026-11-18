//! Memory-starvation watch and the one-tap Upgrade (Jarvis 1's lib/memory.js + POST /api/sessions/:id/upgrade).
//!
//! A session that runs builds, agents and a few Chromes thrashes: for minutes its machine is too short on memory to do
//! anything, then the kernel OOM-kills the biggest process, and the Claude app shows "Can't reach your computer"
//! (2026-10-12). The machine reports its RAM every 10 s (rust/machine/src/memory.rs, POST /m/memory); the watch decides
//! when it is starving:
//!
//!   - the kernel OOM-killed something since the last sample (oom_kill went up),
//!   - memory pressure: PSI "full" avg60 ≥ MEM_PSI_FULL_PCT, or MemAvailable < MEM_LOW_AVAIL_PCT of MemTotal,
//!   - or the machine stopped reporting (MEM_SILENT) while its last sample was already short (< MEM_SHORT_AVAIL_PCT).
//!
//! An episode is DMed once, shown on the session as memAlert {since, reason, detail, nextSize, nextGb, nextGuest} with
//! an Upgrade button, and ends after MEM_CLEAR of healthy samples (or with the machine: an upgrade replaces it).
//!
//! Upgrade (POST /api/sessions/:id/upgrade): the machine's agent frees memory first (command "free": the harness
//! SIGSTOPped, every other process of the session SIGKILLed, the list kept in the snapshot), then the usual pause (its
//! signed snapshot) and resume on the next size; once the new machine is up it gets the canned "upgraded" delivery (the
//! text is built into the image, the router names only the two sizes).

use crate::autopilot::Liveness;
use crate::http::Registrar;
use crate::nethttp::write_json;
use crate::router::Router;
use crate::sizes::{core_takes_size, next_size, size_label, size_mem_gb, size_text, upgrade_target};
use crate::state::{Persisted, Session};
use crate::vouch::Delivery;
use anyhow::{Result, anyhow};
use jarvis_go::GoTime;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// PSI memory full avg60 (%) that counts as thrashing
pub const MEM_PSI_FULL_PCT: f64 = 10.0;
/// MemAvailable below this % of MemTotal counts as starving
pub const MEM_LOW_AVAIL_PCT: f64 = 5.0;
/// a machine that goes silent with less than this left was starving
pub const MEM_SHORT_AVAIL_PCT: f64 = 15.0;
pub const MEM_CLEAR: time::Duration = time::Duration::minutes(15);
/// no memory report for this long = not answering
pub const MEM_SILENT: time::Duration = time::Duration::seconds(90);
/// after "free", before the snapshot
pub const MEM_FREE_WAIT: Duration = Duration::from_secs(5);
/// a start's longest road: Fly's machine-limit wait, then the image pull
pub const UPGRADE_START_WAIT: Duration = Duration::from_secs(30 * 60);

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct MemProc {
    #[serde(rename = "rssKb")]
    pub rss_kb: i64,
    pub comm: String,
}

/// what the machine reports (rust/machine/src/memory.rs MemSample)
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
    pub psi_full_60: Option<f64>,
    /// Go wrote null for none
    pub top: Option<Vec<MemProc>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct MemAlert {
    pub since: GoTime,
    pub reason: String,
    pub detail: String,
}

/// one machine's watch (in the records: any replica carries it on)
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct MemState {
    pub machine: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last: Option<MemSample>,
    #[serde(rename = "lastAt")]
    pub last_at: GoTime,
    #[serde(rename = "oomKills", skip_serializing_if = "Option::is_none")]
    pub oom_kills: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alert: Option<MemAlert>,
    #[serde(rename = "healthySince")]
    pub healthy_since: GoTime,
}

impl MemSample {
    fn avail_pct(&self) -> f64 {
        100.0 * self.avail_kb as f64 / self.total_kb as f64
    }
}

pub fn describe_mem(s: Option<&MemSample>) -> String {
    let Some(s) = s else { return String::new() };
    let top: Vec<String> = s
        .top
        .iter()
        .flatten()
        .filter(|p| p.rss_kb > 100 * 1024)
        .map(|p| format!("{} {:.1} GB", p.comm, p.rss_kb as f64 / 1048576.0))
        .collect();
    let mut out = format!("{} MB free of {:.1} GB", s.avail_kb / 1024, s.total_kb as f64 / 1048576.0);
    if !top.is_empty() {
        out += &format!(" (biggest: {})", top.join(", "));
    }
    out
}

impl MemState {
    /// a sample (or None when the machine went silent) → true when a new starvation episode begins (DM it)
    pub fn observe(&mut self, sample: Option<&MemSample>, now: GoTime) -> bool {
        let mut reason = String::new();
        if let Some(s) = sample {
            if let (Some(old), Some(new)) = (self.oom_kills, s.oom_kills)
                && new > old
            {
                let n = new - old;
                reason = format!("the kernel killed {n} process{} for lack of memory", if n == 1 { "" } else { "es" });
            } else if let Some(p) = s.psi_full_60.filter(|p| *p >= MEM_PSI_FULL_PCT) {
                reason = format!("it is thrashing (stalled on memory {p:.0}% of the last minute)");
            } else if s.avail_pct() < MEM_LOW_AVAIL_PCT {
                reason = "it is almost out of memory".into();
            }
            if s.oom_kills.is_some() {
                self.oom_kills = s.oom_kills;
            }
            self.last = Some(s.clone());
            self.last_at = now;
        } else if self.last.as_ref().is_some_and(|l| l.avail_pct() < MEM_SHORT_AVAIL_PCT) {
            reason = "its machine stopped answering while short of memory".into();
        }
        if !reason.is_empty() {
            self.healthy_since = GoTime::default();
            let mut detail = describe_mem(sample);
            if detail.is_empty() {
                detail = describe_mem(self.last.as_ref());
            }
            match self.alert.as_mut() {
                None => {
                    self.alert = Some(MemAlert { since: now, reason, detail });
                    return true;
                }
                Some(a) => {
                    a.reason = reason;
                    a.detail = detail;
                    return false;
                }
            }
        }
        if self.alert.is_some() && sample.is_some() {
            // healthy: the episode ends after MEM_CLEAR of these
            if self.healthy_since.is_zero() {
                self.healthy_since = now;
            }
            if now.sub(&self.healthy_since) >= MEM_CLEAR {
                self.alert = None;
                self.healthy_since = GoTime::default();
            }
        }
        false
    }
}

/// the DM; it offers Upgrade only to a size the running core starts (sizes.rs upgrade_target)
pub fn mem_message(name: &str, size: &str, a: &MemAlert) -> String {
    let mut msg = format!("🔴 Session “{name}” is running out of memory: {}.", a.reason);
    if !a.detail.is_empty() {
        msg += &format!(" Now {}.", a.detail);
    }
    let next = upgrade_target(size);
    if !next.is_empty() {
        return msg + &format!("\nOne tap moves it to {}: the Upgrade button on its card in the Jarvis 4 app.", size_text(&next));
    }
    let cur = if size_mem_gb(size) == 0 { "medium" } else { size };
    msg + &format!(
        "\nIt is on {}, the largest size the running core starts ({} needs the new core), so there is no Upgrade for it now: free memory in the session (fewer heavy jobs at once).",
        size_text(cur),
        size_text(&next_size(size))
    )
}

/// the "upgraded" delivery's text; rust/machine/src/deliver.rs builds the same and checks both sizes
pub fn upgraded_text(from: &str, to: &str) -> String {
    format!(
        "Jarvis: this session ran out of memory and was moved from a {} to a {} machine. ",
        size_text(from),
        size_text(to)
    ) + "To free memory for the move, every process of the old machine was stopped: Claude itself, background jobs, builds, dev servers, browsers. "
        + "Their list is in ~/artifacts/jarvis-upgrade-freed.txt. Check which of them the task still needs, restart only those, then carry on with the task as before: the bigger machine has the room, so do not cut back on parallel work. "
        + "This is an automated message from Jarvis."
}

/// the session's memAlert and latest memory sample in /api/state (under the state lock)
pub fn mem_view(s: &Session, v: &mut Map<String, Value>) {
    let Some(m) = s.live.as_ref().and_then(|l| l.mem.as_ref()) else { return };
    if s.state != "started" || m.machine != s.machine_id {
        return;
    }
    if let Some(al) = &m.alert {
        let mut a = json!({"since": al.since, "reason": al.reason, "detail": al.detail, "nextSize": null, "nextGb": null, "nextGuest": null});
        let next = upgrade_target(&s.size);
        if !next.is_empty() {
            // none: the running core can't start the next size, so no Upgrade button
            a["nextSize"] = json!(next);
            a["nextGb"] = json!(size_mem_gb(&next));
            a["nextGuest"] = json!(size_label(&next));
        }
        v.insert("memAlert".into(), a);
    }
    if let Some(l) = m.last.as_ref().filter(|_| m.last_at.since() < MEM_SILENT) {
        v.insert(
            "memory".into(),
            json!({"totalMb": l.total_kb / 1024, "availMb": l.avail_kb / 1024, "at": m.last_at}),
        );
    }
}

/// machines that stopped reporting (called by the autopilot tick under the state lock) → DMs
pub fn mem_silent_tick(d: &mut Persisted, now: GoTime) -> Vec<String> {
    let mut dms = vec![];
    for s in d.sessions.values_mut() {
        let (state, machine, size) = (s.state.clone(), s.machine_id.clone(), s.size.clone());
        let Some(live) = s.live.as_mut() else { continue };
        let Some(m) = live.mem.as_mut() else { continue };
        if state != "started" || machine != m.machine {
            live.mem = None;
            continue;
        }
        if !m.last_at.is_zero() && now.sub(&m.last_at) >= MEM_SILENT && m.observe(None, now) {
            let alert = m.alert.clone().unwrap_or_default();
            let name = crate::autopilot::session_name(s, s.live.as_ref().and_then(|l| l.reg.as_ref()));
            dms.push(mem_message(&name, &size, &alert));
        }
    }
    dms
}

pub fn register_memory(reg: &mut Registrar) {
    reg.m("POST /m/memory", |r, w, _, machine, body| {
        let input = match jarvis_go::unmarshal::<MemSample>(body) {
            Ok(i) if i.total_kb > 0 && i.avail_kb >= 0 && i.top.as_ref().is_none_or(|t| t.len() <= 10) => i,
            _ => return write_json(w, 400, &json!({"error": "bad memory sample"})),
        };
        r.refresh_core_sizes(); // sizes.rs: what the DM may offer (at most one /identity a minute)
        let dm = r.st.do_(|d| {
            let sid = d.machines.get(machine).cloned()?;
            let s = d.sessions.get_mut(&sid).filter(|s| s.machine_id == machine)?;
            let size = s.size.clone();
            let live = s.live.get_or_insert_with(Liveness::default);
            if live.mem.as_ref().is_none_or(|m| m.machine != machine) {
                live.mem = Some(MemState { machine: machine.to_string(), ..Default::default() });
            }
            let m = live.mem.as_mut()?;
            if !m.observe(Some(&input), GoTime::now()) {
                return None;
            }
            let alert = m.alert.clone().unwrap_or_default();
            let name = crate::autopilot::session_name(s, s.live.as_ref().and_then(|l| l.reg.as_ref()));
            Some(mem_message(&name, &size, &alert))
        });
        if let Some(dm) = dm {
            crate::logf!("[memory] {dm}");
            r.dm(&dm);
        }
        write_json(w, 200, &json!({"ok": true}));
    });
    reg.app("POST /api/sessions/{id}/upgrade", |r, w, req| match r.upgrade(&req.path_value("id")) {
        Err(e) => crate::schedule::schedule_err(w, &e),
        Ok(out) => write_json(w, 202, &out),
    });
}

impl Router {
    /// free the machine's memory, pause (its signed snapshot), resume on the next size, then tell the session what
    /// happened
    pub fn upgrade(self: &Arc<Self>, id: &str) -> Result<Value> {
        let s = self
            .st
            .do_(|d| d.sessions.get(id).cloned())
            .ok_or_else(crate::sessionapi::no_session)?;
        let from = if s.size.is_empty() { "medium".to_string() } else { s.size.clone() };
        let to = next_size(&s.size);
        let refuse = || {
            anyhow!(
                "session is on {}, the largest size the running core starts: {} needs the new core",
                size_text(&from),
                size_text(&to)
            ) // → 409
        };
        let takes = || {
            if core_takes_size(&to) {
                return true;
            }
            self.refresh_core_sizes();
            core_takes_size(&to)
        };
        if s.machine_id.is_empty() && (s.state == "paused" || s.state == "failed") {
            // no machine to free: the next start is on the bigger size
            if !takes() {
                return Err(refuse());
            }
            self.apply_resume_options(id, crate::sessionops::ResumeOptions { size: to.clone(), ..Default::default() })?;
            return Ok(json!({"ok": true, "kind": "upgrade", "from": from, "to": to, "nextStart": true}));
        }
        // running, or failed with its machine kept (an out-of-memory machine whose pause couldn't finish): freed,
        // paused, resumed bigger
        if s.machine_id.is_empty() || (s.state != "started" && s.state != "failed") {
            return Err(anyhow!("session is {}: Upgrade once it is running, paused or failed", s.state)); // → 409
        }
        if !takes() {
            return Err(refuse());
        }
        // the whole job is one tracked lifecycle action (drain.rs): its pause and resume go on during a drain
        let end_job = self.begin_job(id, "upgrade")?;
        let j = match self.ops.start_job(id, "upgrade") {
            Ok(j) => j,
            Err(e) => {
                end_job.call();
                return Err(e);
            }
        };
        self.ops.set_busy(id, "upgrading");
        let op = self.lc_begin_job(id, "upgrade"); // lifecycle.rs: its free, pause and resume are this one operation
        op.machine(&s.machine_id);
        op.note("", &format!("Upgrade {} → {}", size_text(&from), size_text(&to)));
        let (r, id, from2, to2) = (self.clone(), id.to_string(), from.clone(), to.clone());
        std::thread::spawn(move || {
            let (from, to) = (from2, to2);
            let _e = crate::flows::scopeguard(move || end_job.call());
            let (r2, id2) = (r.clone(), id.clone());
            let _b = crate::flows::scopeguard(move || r2.ops.set_busy(&id2, ""));
            let fail = |e: anyhow::Error| {
                crate::logf!("[memory] upgrade of {id} failed: {e:#}");
                r.cancel_spare(&id, "the upgrade failed");
                r.ops.phase(&j, "failed", Some(&e));
                op.end_job(Some(&e));
            };
            // handover.rs: the bigger machine starts as soon as the old one is told to stop ("free" stops the harness),
            // and gets its cert once the old one is killed
            let next = r.handover_next(&s, &to, 0);
            r.ops.phase(&j, "freeing", None);
            op.note(&s.machine_id, "sent the supervisor free (stop the harness and free memory before the snapshot)");
            r.send(&s.machine_id, "free");
            r.launch_spare(&id, next.as_ref());
            std::thread::sleep(MEM_FREE_WAIT);
            r.ops.phase(&j, "snapshotting", None);
            if let Err(e) = r.pause_with(&id, next) {
                return fail(e);
            }
            if let Err(e) = r.wait_action_end(&id, "paused") {
                return fail(e);
            }
            r.ops.phase(&j, "resuming", None);
            if let Err(e) = r.resume_bigger(&id, &from, &to) {
                return fail(e);
            }
            r.ops.phase(&j, "done", None);
            op.end_job(None);
            crate::logf!("[memory] {id} upgraded {from} → {to}");
            let d = Delivery { kind: "upgraded".into(), from: from.clone(), to: to.clone(), ..Default::default() };
            if let Err(e) = r.deliver_canned(&id, d, &upgraded_text(&from, &to)) {
                crate::logf!("[memory] telling {id} about its upgrade: {e:#}");
            }
        });
        Ok(json!({"started": true, "kind": "upgrade", "from": from, "to": to}))
    }

    /// the paused session resumes on the next size. A start refused on it (Fly can't make that guest, or the core
    /// doesn't know the size) ends with that error, word for word, and the session comes back on its old size rather
    /// than staying down.
    pub fn resume_bigger(self: &Arc<Self>, id: &str, from: &str, to: &str) -> Result<()> {
        self.apply_resume_options(id, crate::sessionops::ResumeOptions { size: to.into(), ..Default::default() })?;
        self.handover_resume(id, "", false)?;
        let msg = self.wait_start_outcome(id, UPGRADE_START_WAIT);
        if msg.is_empty() {
            return Ok(());
        }
        if let Err(e) = self.resume_on_size(id, from) {
            return Err(anyhow!("{to}: {msg}; resuming it on {from} failed too: {e:#}"));
        }
        Err(anyhow!("{to}: {msg}; it is back on {from}"))
    }

    /// "" once the resumed session got its machine (or waits on the phone), else the start's error (state "failed"
    /// with "start: …": nothing was created or certified, so the line's last machine is still unused)
    pub fn wait_start_outcome(&self, id: &str, timeout: Duration) -> String {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            let (st, msg) = self.st.do_(|d| d.sessions.get(id).map(|x| (x.state.clone(), x.error.clone())).unwrap_or_default());
            if st == "failed" && msg.starts_with("start: ") {
                return msg["start: ".len()..].to_string();
            }
            if st == "failed" || (st == "paused" && !msg.is_empty()) {
                return msg;
            }
            if matches!(st.as_str(), "" | "started" | "initialising" | "approval") {
                return String::new();
            }
            std::thread::sleep(crate::sessionops::OPS_POLL);
        }
        String::new()
    }

    /// a session whose start on the bigger size failed goes back to its old size and resumes there
    pub fn resume_on_size(self: &Arc<Self>, id: &str, size: &str) -> Result<()> {
        self.st.do_(|d| {
            if let Some(x) = d
                .sessions
                .get_mut(id)
                .filter(|x| (x.state == "failed" || x.state == "paused") && x.machine_id.is_empty())
            {
                x.size = size.into();
                x.state = "paused".into();
            }
        });
        // the failed resume still holds the session's lock for a moment
        let mut res = Err(anyhow!("not tried"));
        for _ in 0..60 {
            res = self.resume_with_prompt(id, false, "");
            match &res {
                Err(e) if crate::drain::is_busy(e) => std::thread::sleep(crate::sessionops::OPS_POLL),
                _ => break,
            }
        }
        res?;
        let msg = self.wait_start_outcome(id, UPGRADE_START_WAIT);
        if !msg.is_empty() {
            return Err(anyhow!(msg));
        }
        Ok(())
    }
}
