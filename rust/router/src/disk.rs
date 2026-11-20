//! Disk: the machine's disk report, the warning before it fills, and More disk — the disk counterpart of memory.rs
//! (2026-10-15: a session's disk filled, its final snapshot failed with "no space left on device").
//!
//! Every 30 s the machine's agent POSTs /m/disk (rust/machine/src/disk.rs): its root filesystem and, on a machine with
//! a volume (core/volumes.go), the volume at /data that holds the session's state. The disk that counts is the volume
//! when there is one, else the root. An episode begins when it has less than DISK_LOW_PCT free or less than
//! DISK_LOW_MB; it is DMed once, shown on the session as diskAlert {since, reason, detail, nextGb, canGrow, why} with a
//! More disk button, and ends when it has DISK_CLEAR_PCT and DISK_CLEAR_MB free again.
//!
//! More disk (POST /api/sessions/:id/disk): the core extends the machine's volume to twice its size (core /extend; at
//! most 500 GB); the session's diskGb is the new size, which every later machine of the line gets. When Fly says the
//! machine must restart to see it, the session is paused (its signed snapshot) and resumed. A machine without a volume
//! (a core from before volumes) can't grow: the button says so. A kernel line's volume is never extended (the spawner
//! has no such call): the bigger size is the next spawn's, so a running session is paused and resumed onto it.

use crate::autopilot::Liveness;
use crate::http::Registrar;
use crate::nethttp::write_json;
use crate::router::Router;
use crate::state::Session;
use crate::types::Volume;
use anyhow::{Result, anyhow};
use jarvis_go::GoTime;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::sync::Arc;

pub const DISK_LOW_PCT: f64 = 10.0;
pub const DISK_LOW_MB: i64 = 1024;
pub const DISK_CLEAR_PCT: f64 = 20.0;
pub const DISK_CLEAR_MB: i64 = 2048;
pub const DISK_SILENT: time::Duration = time::Duration::minutes(3);
/// core/volumes.go
pub const MAX_DISK_GB: i64 = 500;
/// core/volumes.go defaultDiskGB: the volume when the session asks for no size
pub const DEFAULT_DISK: i64 = 10;
/// an aviary session's when it asks for no size: aviary's sandbox image is fetched onto the volume (8,935 MiB with the
/// agent's tools, 2026-11-20; DE0CH/aviary images/sandbox), beside its upper and the workspace (disk.go aviaryDisk)
pub const AVIARY_DISK: i64 = 24;

/// the volume of a session of this harness that asks for no size
pub fn default_disk_for(harness: &str) -> i64 {
    if harness == "aviary" {
        AVIARY_DISK
    } else {
        DEFAULT_DISK
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct DiskFs {
    #[serde(rename = "totalKb")]
    pub total_kb: i64,
    #[serde(rename = "availKb")]
    pub avail_kb: i64,
}

/// what the machine reports (rust/machine/src/disk.rs)
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct DiskSample {
    pub root: Option<DiskFs>,
    /// the volume, when the machine has one
    pub data: Option<DiskFs>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct DiskAlert {
    pub since: GoTime,
    pub reason: String,
    pub detail: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct DiskState {
    pub machine: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last: Option<DiskSample>,
    #[serde(rename = "lastAt")]
    pub last_at: GoTime,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alert: Option<DiskAlert>,
}

impl DiskSample {
    pub fn main(&self) -> (Option<DiskFs>, &'static str) {
        match self.data {
            Some(d) if d.total_kb > 0 => (Some(d), "its volume"),
            _ => (self.root, "its machine's disk"),
        }
    }
}

impl DiskFs {
    pub fn pct(&self) -> f64 {
        100.0 * self.avail_kb as f64 / self.total_kb as f64
    }
}

pub fn gb_text(kb: i64) -> String {
    format!("{:.1} GB", kb as f64 / 1048576.0)
}

impl DiskState {
    /// a sample → true when a new low-disk episode begins (DM it)
    pub fn observe(&mut self, s: &DiskSample, now: GoTime) -> bool {
        self.last = Some(s.clone());
        self.last_at = now;
        let (fs, place) = s.main();
        let Some(fs) = fs.filter(|f| f.total_kb > 0) else {
            return false;
        };
        let low = fs.pct() < DISK_LOW_PCT || fs.avail_kb < DISK_LOW_MB * 1024;
        let detail = format!(
            "{} free of {} on {place}",
            gb_text(fs.avail_kb),
            gb_text(fs.total_kb)
        );
        match self.alert.as_mut() {
            None if low => {
                self.alert = Some(DiskAlert {
                    since: now,
                    reason: "it is almost out of disk".into(),
                    detail,
                });
                return true;
            }
            Some(a) if low => a.detail = detail,
            Some(_) if fs.pct() >= DISK_CLEAR_PCT && fs.avail_kb >= DISK_CLEAR_MB * 1024 => {
                self.alert = None
            }
            Some(a) => a.detail = detail,
            None => {}
        }
        false
    }
}

/// More disk's size: twice the volume, at most MAX_DISK_GB
pub fn next_disk(cur: i64) -> i64 {
    let cur = if cur <= 0 { DEFAULT_DISK } else { cur };
    (2 * cur).min(MAX_DISK_GB)
}

pub fn disk_message(name: &str, a: &DiskAlert, vol: Option<&Volume>) -> String {
    let msg = format!("🔴 Session “{name}” is running out of disk: {}.", a.detail);
    match vol {
        None => {
            msg + "\nIts machine has no volume, so More disk can't grow it yet (that comes with the core release that adds volumes): free space in it, or ask it to."
        }
        Some(v) => {
            msg + &format!(
                "\nOne tap gives it {} GB: the More disk button on its card in the Jarvis 4 app.",
                next_disk(v.size_gb)
            )
        }
    }
}

/// the session's disk, diskAlert and diskGb in /api/state (under the state lock)
pub fn disk_view(s: &Session, v: &mut Map<String, Value>) {
    v.insert("diskGb".into(), json!(s.disk_gb));
    let Some(d) = s.live.as_ref().and_then(|l| l.disk.as_ref()) else {
        return;
    };
    if s.state != "started" || d.machine != s.machine_id {
        return;
    }
    let Some(last) = d.last.as_ref().filter(|_| d.last_at.since() <= DISK_SILENT) else {
        return;
    };
    let Some(fs) = last.main().0 else { return };
    let has_vol = last.data.is_some_and(|x| x.total_kb > 0);
    let mut out = Map::new();
    out.insert("totalMb".into(), json!(fs.total_kb / 1024));
    out.insert("availMb".into(), json!(fs.avail_kb / 1024));
    out.insert("at".into(), json!(d.last_at));
    out.insert("volume".into(), json!(has_vol));
    if let (Some(r), Some(_)) = (last.root, last.data) {
        out.insert("rootTotalMb".into(), json!(r.total_kb / 1024));
        out.insert("rootAvailMb".into(), json!(r.avail_kb / 1024));
    }
    v.insert("disk".into(), Value::Object(out));
    if let Some(al) = &d.alert {
        let mut a = Map::new();
        a.insert("since".into(), json!(al.since));
        a.insert("reason".into(), json!(al.reason));
        a.insert("detail".into(), json!(al.detail));
        a.insert("canGrow".into(), json!(last.data.is_some()));
        match last.data {
            Some(data) => {
                a.insert("nextGb".into(), json!(next_disk(data.total_kb / 1048576)));
            }
            None => {
                a.insert(
                    "why".into(),
                    json!("its machine has no volume: More disk comes with the core release that adds volumes"),
                );
            }
        }
        v.insert("diskAlert".into(), Value::Object(a));
    }
}

fn bad_fs(f: &Option<DiskFs>) -> bool {
    f.is_some_and(|f| f.total_kb <= 0 || f.avail_kb < 0 || f.avail_kb > f.total_kb)
}

pub fn register_disk(reg: &mut Registrar) {
    reg.m("POST /m/disk", |r, w, _, machine, body| {
        let input = match jarvis_go::unmarshal::<DiskSample>(body) {
            Ok(i) if i.root.is_some() && !bad_fs(&i.root) && !bad_fs(&i.data) => i,
            _ => return write_json(w, 400, &json!({"error": "bad disk sample"})),
        };
        let alert = r.st.do_(|d| {
            let sid = d.machines.get(machine).cloned()?;
            let s = d
                .sessions
                .get_mut(&sid)
                .filter(|s| s.machine_id == machine)?;
            let live = s.live.get_or_insert_with(Liveness::default);
            if live.disk.as_ref().is_none_or(|x| x.machine != machine) {
                live.disk = Some(DiskState {
                    machine: machine.to_string(),
                    ..Default::default()
                });
            }
            let ds = live.disk.as_mut()?;
            if !ds.observe(&input, GoTime::now()) {
                return None;
            }
            let a = ds.alert.clone()?;
            Some((
                crate::autopilot::session_name(s, s.live.as_ref().and_then(|l| l.reg.as_ref())),
                a,
            ))
        });
        if let Some((name, a)) = alert {
            let msg = disk_message(&name, &a, r.machine_volume(machine).as_ref());
            crate::logf!("[disk] {msg}");
            r.dm(&msg);
        }
        write_json(w, 200, &json!({"ok": true}));
    });
    reg.app("POST /api/sessions/{id}/disk", |r, w, req| {
        match r.more_disk(&req.path_value("id")) {
            Err(e) => crate::schedule::schedule_err(w, &e),
            Ok(out) => write_json(w, 202, &out),
        }
    });
}

impl Router {
    /// the machine's volume to twice its size; a pause and resume when Fly says the machine must restart
    pub fn more_disk(self: &Arc<Self>, id: &str) -> Result<Value> {
        let s = self
            .st
            .do_(|d| d.sessions.get(id).cloned())
            .ok_or_else(crate::sessionapi::no_session)?;
        // a running session's volume grows now; a failed one whose machine was kept (its snapshot ran out of space)
        // too, then Pause again; one with no machine (paused, failed) or no volume gets the bigger disk at its next
        // start
        let live = !s.machine_id.is_empty() && (s.state == "started" || s.state == "failed");
        let mut vol = if live {
            self.machine_volume(&s.machine_id)
        } else {
            None
        };
        // a kernel line's volume doesn't grow in place: the kernel's spawner makes a machine's volume and deletes it,
        // nothing else (DECISIONS 231), and the old core knows none of its machines. The size is the next spawn's: a
        // failed session's kept machine is replaced at its Resume; a running one moves to a new machine now (below)
        let kernel = s.kernel.is_some();
        if kernel && s.state == "failed" {
            vol = None;
        }
        let Some(vol) = vol else {
            if !matches!(s.state.as_str(), "paused" | "failed" | "started") {
                // "session is …" → 409
                return Err(anyhow!(
                    "session is {}: More disk once it is running, paused or failed",
                    s.state
                ));
            }
            let cur = if s.disk_gb <= 0 {
                default_disk_for(&s.harness)
            } else {
                s.disk_gb
            };
            let to = next_disk(cur);
            if to <= cur {
                return Err(anyhow!("session is at the largest disk ({MAX_DISK_GB} GB)"));
            }
            self.st.do_(|d| {
                if let Some(x) = d.sessions.get_mut(id) {
                    x.disk_gb = to;
                }
            });
            return Ok(
                json!({"ok": true, "kind": "disk", "fromGb": cur, "toGb": to, "nextStart": true}),
            );
        };
        let from = vol.size_gb.max(s.disk_gb);
        let to = next_disk(from);
        if to <= from {
            return Err(anyhow!("session is at the largest disk ({MAX_DISK_GB} GB)"));
        }
        let end_job = self.begin_job(id, "disk")?;
        let j = match self.ops.start_job(id, "disk") {
            Ok(j) => j,
            Err(e) => {
                end_job.call();
                return Err(e);
            }
        };
        self.ops.set_busy(id, "growing-disk");
        let r = self.clone();
        let id = id.to_string();
        std::thread::spawn(move || {
            let _e = crate::flows::scopeguard(move || end_job.call());
            let (r2, id2) = (r.clone(), id.clone());
            let _b = crate::flows::scopeguard(move || r2.ops.set_busy(&id2, ""));
            let fail = |e: anyhow::Error| {
                crate::logf!("[disk] more disk for {id} failed: {e:#}");
                r.cancel_spare(&id, "more disk failed");
                r.ops.phase(&j, "failed", Some(&e));
            };
            r.ops.phase(&j, "extending", None);
            #[derive(Deserialize, Default)]
            #[serde(default)]
            struct Ext {
                #[serde(rename = "needsRestart")]
                needs_restart: bool,
            }
            let ext = if kernel {
                Ext {
                    needs_restart: true,
                } // the next machine's volume: a pause and a resume
            } else {
                match r
                    .core
                    .call("/extend", &json!({"machine": s.machine_id, "sizeGb": to}))
                {
                    Err(e) => return fail(e),
                    Ok(d) => d.decode::<Ext>().unwrap_or_default(),
                }
            };
            r.st.do_(|d| {
                if let Some(x) = d.sessions.get_mut(&id) {
                    x.disk_gb = to; // every later machine of the line gets the new size
                }
            });
            if ext.needs_restart && s.state == "started" {
                r.ops.phase(&j, "snapshotting", None);
                // handover.rs: the machine on the bigger volume starts as soon as the old one is told to stop
                let next = r.handover_next(&s, "", to);
                if let Err(e) = r.pause_with(&id, next) {
                    return fail(e);
                }
                if let Err(e) = r.wait_action_end(&id, "paused") {
                    return fail(e);
                }
                r.ops.phase(&j, "resuming", None);
                if let Err(e) = r.handover_resume(&id, "", false) {
                    return fail(e);
                }
                let msg = r.wait_start_outcome(&id, crate::memory::UPGRADE_START_WAIT);
                if !msg.is_empty() {
                    return fail(anyhow!("{msg}"));
                }
            }
            r.ops.phase(&j, "done", None);
            crate::logf!(
                "[disk] {id}: volume {from} → {to} GB (restart: {})",
                ext.needs_restart
            );
        });
        Ok(json!({"started": true, "kind": "disk", "fromGb": from, "toGb": to}))
    }
}
