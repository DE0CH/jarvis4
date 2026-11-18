//! The leftover-volume sweep (DECISIONS 195, which builds on 194). A session machine's volume (`jarvis4_state`,
//! core/volumes.go) is deleted by the core at the machine's kill, but only while the core remembers it (`vol.live`,
//! `vol.orphans`, both in its memory): after a core restart or Reset, or when a test run's core exits, a volume whose
//! machine is gone stays in jarvis4-sessions forever, billed. Every 10 minutes the leader router lists the app's
//! volumes and machines with its read-only FLY_READ_TOKEN and deletes, with FLY_VOLUME_TOKEN (infra/fly-volume-token.sh:
//! a token that can do nothing but delete volumes in jarvis4-sessions), each volume that is
//!
//!   - named `jarvis4_state` and in state `created`,
//!   - attached to nothing and in no listed machine's `config.mounts`,
//!   - at least 15 minutes old (a volume between its create and its machine's create looks like a leftover), and
//!   - named by no session the router knows: neither its current machine's nor its booted machine's volume (the
//!     machine's cert or start record).
//!
//! A delete Fly answers 404 (already gone) counts as done; a failed one is simply looked at again next sweep. A test
//! router (the replica's, the e2e's) has no FLY_VOLUME_TOKEN and never sweeps. The core is unchanged: a volume the core
//! still lists in `vol.orphans` and the sweep deletes first only makes the core's later delete a no-op (Fly answers a
//! repeated delete with the destroyed volume, 200).

use crate::budget::{FlyVolume, SESSIONS_APP};
use crate::core::Doc;
use crate::router::Router;
use anyhow::{Result, anyhow, bail};
use jarvis_go::GoTime;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::sync::{Arc, LazyLock, Mutex, RwLock};
use std::time::Duration;

pub const VOL_SWEEP_EVERY: Duration = Duration::from_secs(10 * 60);
/// after the router starts: its first look, so a rollout shows it working
pub const VOL_SWEEP_FIRST: Duration = Duration::from_secs(2 * 60);
pub const VOL_SWEEP_MIN_AGE: Duration = Duration::from_secs(15 * 60);
/// a bug can't empty the app in one sweep
pub const VOL_SWEEP_MAX_PER_GO: usize = 20;
pub const SESSION_VOLUME: &str = "jarvis4_state";

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct SweepMount {
    pub volume: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct SweepConfig {
    pub mounts: Vec<SweepMount>,
}

/// a machine as the sweep needs it (its mounts)
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct SweepMachine {
    pub id: String,
    pub state: String,
    pub config: SweepConfig,
}

/// what one sweep decided, volume by volume
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SweepChoice {
    /// volume ids to delete
    pub delete: Vec<String>,
    /// volume id → why it stays ("category: detail")
    pub kept: BTreeMap<String, String>,
}

/// the pure decision (tested): which volumes are leftovers. named = volume id → who names it.
pub fn sweep_select(
    vols: &[FlyVolume],
    ms: &[SweepMachine],
    named: &BTreeMap<String, String>,
    now: GoTime,
) -> SweepChoice {
    let mut mounted: BTreeMap<&str, &str> = BTreeMap::new();
    for m in ms.iter().filter(|m| m.state != "destroyed") {
        for mt in m.config.mounts.iter().filter(|mt| !mt.volume.is_empty()) {
            mounted.insert(&mt.volume, &m.id);
        }
    }
    let mut out = SweepChoice::default();
    for v in vols {
        let why = if v.name != SESSION_VOLUME {
            format!("other name: {}", v.name)
        } else if v.state != "created" {
            format!("state: {}", v.state)
        } else if !v.attached_machine_id.is_empty() {
            format!("attached: {}", v.attached_machine_id)
        } else if let Some(m) = mounted.get(v.id.as_str()).filter(|m| !m.is_empty()) {
            format!("mounted: {m}")
        } else if let Some(n) = named.get(&v.id).filter(|n| !n.is_empty()) {
            format!("named: {n}")
        } else {
            match GoTime::parse(&v.created_at) {
                None => format!("no creation time: {}", v.created_at),
                Some(t) if now.sub(&t) < VOL_SWEEP_MIN_AGE => {
                    format!("young: created {}", v.created_at)
                }
                Some(_) => String::new(),
            }
        };
        if !why.is_empty() {
            out.kept.insert(v.id.clone(), why);
            continue;
        }
        if out.delete.len() >= VOL_SWEEP_MAX_PER_GO {
            out.kept.insert(v.id.clone(), "limit: next sweep".into());
            continue;
        }
        out.delete.push(v.id.clone());
    }
    out.delete.sort();
    out
}

/// the volume a core-signed cert names for its machine ("" = none)
pub fn cert_volume(d: Option<&Doc>) -> String {
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct M {
        volume: Option<crate::snapsafe::Volume>,
    }
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct C {
        machine: Option<M>,
    }
    d.and_then(|d| d.decode::<C>().ok())
        .and_then(|c| c.machine)
        .and_then(|m| m.volume)
        .map(|v| v.id)
        .unwrap_or_default()
}

pub type DeleteFn = fn(&str, &str) -> Result<()>;
pub type ReaderFn = fn() -> Result<(Vec<FlyVolume>, Vec<SweepMachine>)>;

/// DELETE one volume with the volume-only token; 200 and 404 (gone) are done. Tests swap it.
fn volume_delete_live(token: &str, id: &str) -> Result<()> {
    let mut auth = token.to_string();
    if !auth.starts_with("FlyV1 ") && !auth.starts_with("Bearer ") {
        auth = format!("Bearer {auth}");
    }
    let u = format!(
        "https://api.machines.dev/v1/apps/{SESSIONS_APP}/volumes/{}",
        jarvis_go::fmt::path_escape(id)
    );
    let resp = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?
        .delete(u)
        .header("Authorization", auth)
        .send()?;
    match resp.status().as_u16() {
        200 | 404 => Ok(()),
        st => bail!("HTTP {st}"),
    }
}

/// the Fly lists (read-only token); tests swap it
fn vol_sweep_reader_live() -> Result<(Vec<FlyVolume>, Vec<SweepMachine>)> {
    let token = std::env::var("FLY_READ_TOKEN").unwrap_or_default();
    if token.is_empty() {
        return Err(anyhow!("FLY_READ_TOKEN not set"));
    }
    let vols = crate::flyorgs::fly_get(&token, &format!("/v1/apps/{SESSIONS_APP}/volumes"))?;
    let ms = crate::flyorgs::fly_get(&token, &format!("/v1/apps/{SESSIONS_APP}/machines"))?;
    Ok((vols, ms))
}

pub static VOLUME_DELETE: RwLock<DeleteFn> = RwLock::new(volume_delete_live);
pub static VOL_SWEEP_READER: RwLock<ReaderFn> = RwLock::new(vol_sweep_reader_live);

static VOL_SWEEP_STATUS: LazyLock<Mutex<Option<Map<String, Value>>>> =
    LazyLock::new(Default::default);

fn set_status(v: Value) {
    *VOL_SWEEP_STATUS.lock().unwrap_or_else(|e| e.into_inner()) = v.as_object().cloned();
}

/// the last sweep, for /setup/status (counts and ids only; null before the first)
pub fn volume_sweep_status() -> Value {
    VOL_SWEEP_STATUS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
        .map_or(Value::Null, Value::Object)
}

impl Router {
    /// every volume a session the router knows still names
    pub fn sweep_named(&self) -> BTreeMap<String, String> {
        self.st.do_(|d| {
            let mut named = BTreeMap::new();
            let mut add = |vol: String, who: String| {
                if !vol.is_empty() {
                    named.entry(vol).or_insert(who);
                }
            };
            for s in d.sessions.values() {
                add(
                    cert_volume(s.cert.as_ref()),
                    format!("session {}'s line", s.id),
                );
                add(
                    cert_volume(d.sess_certs.get(&s.id)),
                    format!("session {}'s line", s.id),
                );
                for m in [&s.machine_id, &s.booted] {
                    if m.is_empty() {
                        continue;
                    }
                    add(
                        cert_volume(d.certs.get(m)),
                        format!("session {}'s machine {m}", s.id),
                    );
                    if let Some(v) = d.started.get(m).and_then(|st| st.volume.as_ref()) {
                        add(v.id.clone(), format!("session {}'s machine {m}", s.id));
                    }
                }
            }
            named
        })
    }

    /// one sweep. Returns the ids deleted.
    pub fn volume_sweep(&self, token: &str, now: GoTime) -> Result<Vec<String>> {
        let reader = *VOL_SWEEP_READER.read().unwrap_or_else(|e| e.into_inner());
        let (vols, ms) = reader().map_err(|e| anyhow!("Fly list: {e:#}"))?;
        // the named set is read AFTER the Fly lists: a session that starts in between names its volume by then, or its
        // volume is under 15 minutes old
        let ch = sweep_select(&vols, &ms, &self.sweep_named(), now);
        let del = *VOLUME_DELETE.read().unwrap_or_else(|e| e.into_inner());
        let mut deleted = vec![];
        let mut failed = BTreeMap::new();
        for id in &ch.delete {
            match del(token, id) {
                Err(e) => {
                    failed.insert(id.clone(), format!("{e:#}"));
                }
                Ok(()) => deleted.push(id.clone()),
            }
        }
        let mut kept: BTreeMap<String, i64> = BTreeMap::new();
        for why in ch.kept.values() {
            *kept
                .entry(jarvis_go::fmt::cut(why, ":").0.to_string())
                .or_default() += 1;
        }
        crate::logf!(
            "[volsweep] {} volumes, {} machines in {SESSIONS_APP}: deleted {}, failed {} (tried again next sweep), kept {}",
            vols.len(),
            ms.len(),
            jarvis_go::fmt::go_sprint(&json!(deleted)),
            jarvis_go::fmt::go_sprint(&json!(failed)),
            jarvis_go::fmt::go_sprint(&json!(kept))
        );
        set_status(
            json!({"checkedAt": now.utc().rfc3339(), "volumes": vols.len(), "deleted": deleted, "failed": failed, "kept": kept}),
        );
        Ok(deleted)
    }

    pub fn vol_sweep_loop(self: &Arc<Self>) {
        let token = std::env::var("FLY_VOLUME_TOKEN").unwrap_or_default();
        if token.is_empty()
            || std::env::var("FLY_READ_TOKEN")
                .unwrap_or_default()
                .is_empty()
        {
            crate::logf!(
                "[volsweep] FLY_VOLUME_TOKEN or FLY_READ_TOKEN unset: no leftover-volume sweep"
            );
            set_status(json!({"error": "off: FLY_VOLUME_TOKEN or FLY_READ_TOKEN not set"}));
            return;
        }
        std::thread::sleep(VOL_SWEEP_FIRST);
        loop {
            crate::leaderlease::await_lead();
            if let Err(e) = self.volume_sweep(&token, GoTime::now()) {
                crate::logf!(
                    "[volsweep] {e:#} (tried again in {})",
                    jarvis_go::fmt::duration_string(VOL_SWEEP_EVERY)
                );
                set_status(
                    json!({"checkedAt": GoTime::now().utc().rfc3339(), "error": format!("{e:#}")}),
                );
            }
            std::thread::sleep(VOL_SWEEP_EVERY);
        }
    }
}
