//! The budget cap (Fly and AWS, one pool) and "Also on Fly". AWS spend joins the same pool (awsbudget.rs): the AWS
//! rate is added to the Fly rate every tick, the month's total is both, the cap pauses running sessions on either
//! runner, and Cost Explorer's billed figure for jarvis4's own AWS account is a floor under the AWS part.
//!
//! Fly has no spend cap, so the router ESTIMATES this month's spend: every tick it sums the $/hour of everything
//! accruing in the sessions' app (started machines by guest size and region, provisioned volumes) and adds rate ×
//! elapsed to a month-to-date total kept in the router's state (bounded by MAX_DELTA_H per gap). FLY_BUDGET_WARN_USD →
//! one DM; FLY_BUDGET_USD (0 = off) → pause every running session and DM, and keep pausing anything started while the
//! month stays over the cap. Raising a line above the month's spend so far re-arms it. Volume snapshots count too
//! (DECISIONS 179). FLY_READ_TOKEN reads only.

use crate::awsbudget::{AwsBilled, AwsCoster};
use crate::router::Router;
use anyhow::{Result, anyhow};
use jarvis_go::GoTime;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

pub const HOURS_PER_MONTH: f64 = 730.0;
/// the longest gap one sample may bill for
pub const MAX_DELTA_H: f64 = 6.0;
pub const BUDGET_TICK: Duration = Duration::from_secs(120);
pub const SESSIONS_APP: &str = "jarvis4-sessions";

/// rates (USD) from fly.io/docs/about/pricing (read 2026-10-15): a vCPU-second shared 8.465e-7 / performance 1.2732e-5,
/// each CPU with 0.25 GB (shared) or 2 GB (performance) of RAM included, every further GB-second 2.316e-6, all times
/// the region's markup; volumes USD 0.15 per provisioned GB-month; snapshots USD 0.08 per stored GB-month, 10 GB free
const SHARED_CPU_PER_HOUR: f64 = 8.465e-7 * 3600.0;
const PERFORMANCE_CPU_PER_HOUR: f64 = 1.2732e-5 * 3600.0;
const RAM_PER_GB_HOUR: f64 = 2.316e-6 * 3600.0;
const VOLUME_PER_GB_HOUR: f64 = 0.15 / HOURS_PER_MONTH;
const SHARED_RAM_INCLUDED: f64 = 0.25;
const PERFORMANCE_RAM_INCLUDED: f64 = 2.0;
const SNAPSHOT_PER_GB_HOUR: f64 = 0.08 / HOURS_PER_MONTH;
const SNAPSHOT_FREE_GB: f64 = 10.0;

pub const SNAPSHOT_EVERY: time::Duration = time::Duration::minutes(30);

/// one volume snapshot as Fly lists it (GET /volumes/:id/snapshots; size in bytes, stored)
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct FlySnapshot {
    pub id: String,
    pub size: i64,
    pub status: String,
}

/// each volume's snapshots, listed at most every SNAPSHOT_EVERY
type SnapCache = BTreeMap<String, (GoTime, Vec<FlySnapshot>)>;
static SNAP_CACHE: LazyLock<Mutex<SnapCache>> = LazyLock::new(|| Mutex::new(BTreeMap::new()));

/// the stored snapshot GB past the free ones, per hour
pub fn hourly_snapshot_cost(stored: i64) -> f64 {
    let gb = stored as f64 / 1e9;
    f64::max(0.0, gb - SNAPSHOT_FREE_GB) * SNAPSHOT_PER_GB_HOUR
}

/// every volume Fly lists, each once, sorted
pub fn snapshot_volumes(vs: &[FlyVolume]) -> Vec<String> {
    vs.iter()
        .filter(|v| !v.id.is_empty())
        .map(|v| v.id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// the stored bytes of every billed snapshot (each counted once) → bytes, snapshots, the first error
pub fn snapshot_storage(
    fly: &dyn FlyReader,
    volumes: &[String],
    now: GoTime,
) -> (i64, usize, Option<anyhow::Error>) {
    let mut first = None;
    let mut ids: BTreeMap<String, i64> = BTreeMap::new();
    for v in volumes {
        let cached = SNAP_CACHE.lock().ok().and_then(|g| g.get(v).cloned());
        let list = match &cached {
            Some((at, l)) if now.sub(at) < SNAPSHOT_EVERY => l.clone(),
            _ => match fly.snapshots(v) {
                None => vec![],
                Some(Err(e)) => {
                    if first.is_none() {
                        first = Some(anyhow!("snapshots of {v}: {e:#}"));
                    }
                    cached.map(|c| c.1).unwrap_or_default()
                }
                Some(Ok(got)) => {
                    if let Ok(mut g) = SNAP_CACHE.lock() {
                        g.insert(v.clone(), (now, got.clone()));
                    }
                    got
                }
            },
        };
        for s in list {
            if s.status != "failed" {
                ids.insert(s.id, s.size);
            }
        }
    }
    (ids.values().sum(), ids.len(), first)
}

/// Fly's machine price markup per region (read 2026-10-29); a region not listed is priced at the dearest
const REGION_MARKUP: &[(&str, f64)] = &[
    ("ams", 1.038461538),
    ("arn", 1.038461538),
    ("cdg", 1.134615385),
    ("dfw", 1.25),
    ("ewr", 1.0),
    ("fra", 1.153846154),
    ("gru", 1.615384615),
    ("iad", 1.0),
    ("jnb", 1.302884615),
    ("lax", 1.199519231),
    ("lhr", 1.134615385),
    ("nrt", 1.307692308),
    ("ord", 1.25),
    ("sin", 1.269230769),
    ("sjc", 1.192307692),
    ("syd", 1.269230769),
    ("yyz", 1.115384615),
];

pub fn markup_of(region: &str) -> f64 {
    REGION_MARKUP
        .iter()
        .find(|(r, _)| *r == region)
        .map(|(_, m)| *m)
        .unwrap_or_else(|| REGION_MARKUP.iter().map(|(_, m)| *m).fold(0.0, f64::max))
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct FlyGuest {
    pub cpu_kind: String,
    pub cpus: i64,
    pub memory_mb: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct FlyMachineConfig {
    pub guest: Option<FlyGuest>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct FlyMachine {
    pub id: String,
    pub name: String,
    pub state: String,
    pub region: String,
    pub created_at: String,
    pub config: FlyMachineConfig,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct FlyVolume {
    pub id: String,
    pub name: String,
    pub state: String,
    pub region: String,
    pub size_gb: i64,
    pub attached_machine_id: String,
    pub created_at: String,
}

/// Fly has deleted the volume (pending_destroy, destroying: not billed)
pub fn volume_gone(state: &str) -> bool {
    matches!(state, "destroyed" | "pending_destroy" | "destroying")
}

pub fn live_volumes(vs: &[FlyVolume]) -> usize {
    vs.iter().filter(|v| !volume_gone(&v.state)).count()
}

/// $/hour while started in region (a stopped machine bills cents a month for its rootfs: ignored)
pub fn hourly_machine_cost(g: Option<&FlyGuest>, region: &str) -> f64 {
    let Some(g) = g else { return 0.0 };
    let cpus = if g.cpus == 0 { 1.0 } else { g.cpus as f64 };
    let (rate, included) = if g.cpu_kind == "performance" {
        (PERFORMANCE_CPU_PER_HOUR, PERFORMANCE_RAM_INCLUDED)
    } else {
        (SHARED_CPU_PER_HOUR, SHARED_RAM_INCLUDED)
    };
    (cpus * rate + f64::max(0.0, g.memory_mb as f64 / 1024.0 - cpus * included) * RAM_PER_GB_HOUR)
        * markup_of(region)
}

pub fn hourly_volume_cost(size_gb: i64) -> f64 {
    size_gb as f64 * VOLUME_PER_GB_HOUR
}

#[derive(Debug, Clone, Default)]
pub struct Burn {
    pub rate_per_hour: f64,
    pub running: i64,
    pub volumes: i64,
    pub snapshot_bytes: i64,
    pub snapshots: i64,
}

pub fn burn_rate(ms: &[FlyMachine], vs: &[FlyVolume]) -> Burn {
    let mut b = Burn::default();
    for m in ms {
        if m.state == "started" {
            b.rate_per_hour += hourly_machine_cost(m.config.guest.as_ref(), &m.region);
            b.running += 1;
        }
    }
    for v in vs {
        if !volume_gone(&v.state) {
            b.rate_per_hour += hourly_volume_cost(v.size_gb);
            b.volumes += 1;
        }
    }
    b
}

// ---- the accumulator (pure) ----------------------------------------------------------------------------------

fn is_zero_f(n: &f64) -> bool {
    *n == 0.0
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct BudgetState {
    /// UTC "YYYY-MM"
    pub month: String,
    #[serde(rename = "spentUsd")]
    pub spent_usd: f64,
    #[serde(rename = "lastSampleAt", skip_serializing_if = "Option::is_none")]
    pub last_sample_at: Option<GoTime>,
    pub warned: bool,
    pub capped: bool,
    #[serde(rename = "cappedAt", skip_serializing_if = "Option::is_none")]
    pub capped_at: Option<GoTime>,
    #[serde(rename = "ratePerHour")]
    pub rate_per_hour: f64,
    /// the AWS part (awsbudget.rs): aws_usd of spent_usd is the AWS estimate (the rest is Fly's); aws_billed_usd is
    /// Cost Explorer's last figure for the month, which the pool counts when it is above the estimate
    #[serde(rename = "awsUsd", skip_serializing_if = "is_zero_f")]
    pub aws_usd: f64,
    #[serde(rename = "awsBilledUsd", skip_serializing_if = "is_zero_f")]
    pub aws_billed_usd: f64,
    #[serde(rename = "awsBilledAt", skip_serializing_if = "Option::is_none")]
    pub aws_billed_at: Option<GoTime>,
    /// the fabric's part of aws_usd (awsbudget.rs AWS_FABRIC_REGION)
    #[serde(rename = "fabricUsd", skip_serializing_if = "is_zero_f")]
    pub fabric_usd: f64,
}

impl BudgetState {
    /// the month's spend against the cap: Fly's estimate + AWS's (the larger of the estimate and the billed figure)
    pub fn pool(&self) -> f64 {
        self.spent_usd + f64::max(0.0, self.aws_billed_usd - self.aws_usd)
    }

    pub fn fly_part(&self) -> f64 {
        self.spent_usd - self.aws_usd
    }

    pub fn aws_part(&self) -> f64 {
        f64::max(self.aws_usd, self.aws_billed_usd)
    }
}

/// one tick's rates (USD an hour) and, when Cost Explorer was read, its figure
#[derive(Debug, Clone, Default)]
pub struct SpendSample {
    pub fly_rate: f64,
    pub aws_rate: f64,
    /// the fabric's part of aws_rate
    pub fabric_rate: f64,
    pub billed: Option<AwsBilled>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct BudgetActions {
    pub enforce: bool,
    pub cap_dm: bool,
    pub warn_dm: bool,
}

/// fold one sample in. enforce: the month is over the cap (every tick); cap_dm: first crossing of the cap this month;
/// warn_dm: first crossing of the warn line (none once capped, or in the same tick)
pub fn apply_sample(
    prev: Option<&BudgetState>,
    now: GoTime,
    smp: &SpendSample,
    cap: f64,
    warn: f64,
) -> (BudgetState, BudgetActions, f64) {
    let month = now.utc().rfc3339()[..7].to_string();
    let mut s = match prev {
        Some(p) if p.month == month => p.clone(),
        _ => BudgetState {
            month: month.clone(),
            ..Default::default()
        },
    };
    let mut delta_h = 0.0;
    if let Some(last) = &s.last_sample_at {
        delta_h = now.sub(last).as_seconds_f64() / 3600.0;
        if delta_h.is_nan() || delta_h <= 0.0 {
            delta_h = 0.0;
        }
        delta_h = delta_h.min(MAX_DELTA_H);
    }
    let t = now.utc();
    s.spent_usd += (smp.fly_rate + smp.aws_rate) * delta_h;
    s.aws_usd += smp.aws_rate * delta_h;
    s.fabric_usd += smp.fabric_rate * delta_h;
    s.last_sample_at = Some(t);
    s.rate_per_hour = smp.fly_rate + smp.aws_rate;
    if let Some(b) = &smp.billed
        && b.month == month
    {
        s.aws_billed_usd = b.usd;
        s.aws_billed_at = Some(b.at);
    }
    let spent = s.pool();
    // a line raised above this month's spend re-arms its DM
    if s.capped && !(cap > 0.0 && spent >= cap) {
        s.capped = false;
        s.capped_at = None;
    }
    if s.warned && !s.capped && !(warn > 0.0 && spent >= warn) {
        s.warned = false;
    }
    let mut a = BudgetActions::default();
    if cap > 0.0 && spent >= cap {
        a.enforce = true;
        if !s.capped {
            a.cap_dm = true;
            s.capped = true;
            s.capped_at = Some(t);
        }
        s.warned = true;
    } else if warn > 0.0 && spent >= warn && !s.warned {
        a.warn_dm = true;
        s.warned = true;
    }
    (s, a, delta_h)
}

/// FLY_BUDGET_USD (default 50, 0 = off) and FLY_BUDGET_WARN_USD (default 45, or 80% of a cap set without one)
pub fn budget_thresholds(getenv: impl Fn(&str) -> String) -> (f64, f64) {
    let cap = getenv("FLY_BUDGET_USD").parse::<f64>().unwrap_or(50.0);
    let warn = match getenv("FLY_BUDGET_WARN_USD").parse::<f64>() {
        Ok(v) => v,
        Err(_) if !getenv("FLY_BUDGET_USD").is_empty() => (cap * 0.8 * 100.0).round() / 100.0,
        Err(_) => 45.0,
    };
    (cap, warn)
}

// ---- Fly, read only ------------------------------------------------------------------------------------------

pub trait FlyReader: Send + Sync {
    fn machines(&self) -> Result<Vec<FlyMachine>>;
    fn volumes(&self) -> Result<Vec<FlyVolume>>;
    /// a volume's snapshots (None: this reader can't list them)
    fn snapshots(&self, _volume: &str) -> Option<Result<Vec<FlySnapshot>>> {
        None
    }
}

pub struct FlyApi {
    pub base: String,
    pub app: String,
    pub token: String,
}

impl FlyApi {
    fn get<T: serde::de::DeserializeOwned>(&self, p: &str) -> Result<T> {
        let mut auth = self.token.clone();
        if !auth.starts_with("FlyV1 ") && !auth.starts_with("Bearer ") {
            auth = format!("Bearer {auth}");
        }
        let resp = reqwest::blocking::Client::new()
            .get(format!("{}/v1/apps/{}{p}", self.base, self.app))
            .timeout(Duration::from_secs(30))
            .header("Authorization", auth)
            .send()?;
        if resp.status().as_u16() != 200 {
            return Err(anyhow!("Fly {p}: HTTP {}", resp.status().as_u16()));
        }
        let b = crate::util::read_limited(resp, 64 << 20)?;
        Ok(jarvis_go::unmarshal(&b)?)
    }
}

impl FlyReader for FlyApi {
    fn machines(&self) -> Result<Vec<FlyMachine>> {
        self.get("/machines")
    }

    fn volumes(&self) -> Result<Vec<FlyVolume>> {
        self.get("/volumes")
    }

    fn snapshots(&self, volume: &str) -> Option<Result<Vec<FlySnapshot>>> {
        Some(self.get(&format!("/volumes/{volume}/snapshots")))
    }
}

// ---- the tick ------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct FlyOther {
    /// machine | volume
    pub kind: String,
    pub app: String,
    pub id: String,
    pub name: String,
    pub state: String,
    pub region: String,
    pub created: String,
    pub detail: String,
}

/// the last tick's figures. Only the replica that leads ticks, so it also writes them to router_docs and /api/state
/// reads them from there, whichever replica answers; this copy is what a router without a database shows
static BUDGET_VIEW: LazyLock<Mutex<(Value, Value)>> =
    LazyLock::new(|| Mutex::new((Value::Null, Value::Null)));

pub const BUDGET_VIEW_DOC: &str = "fly-budget-view.json";

pub fn usd(n: f64) -> String {
    format!("USD {n:.2}")
}

type PauseFn = fn(&Arc<Router>, &str) -> Result<()>;
type DmFn = fn(&Arc<Router>, &str);

/// the effects, swappable in tests
pub static BUDGET_PAUSE: Mutex<Option<PauseFn>> = Mutex::new(None);
pub static BUDGET_DM: Mutex<Option<DmFn>> = Mutex::new(None);

pub fn budget_pause(r: &Arc<Router>, sid: &str) -> Result<()> {
    match BUDGET_PAUSE.lock().ok().and_then(|g| *g) {
        Some(f) => f(r, sid),
        None => r.pause(sid),
    }
}

pub fn budget_dm(r: &Arc<Router>, text: &str) {
    match BUDGET_DM.lock().ok().and_then(|g| *g) {
        Some(f) => f(r, text),
        None => r.dm(text),
    }
}

impl Router {
    fn save_budget_view(&self) {
        let (b, f) = BUDGET_VIEW.lock().map(|g| g.clone()).unwrap_or_default();
        let doc = jarvis_go::marshal(&json!({"budget": b, "fly": f}));
        if let Err(e) = self.st.write_doc(BUDGET_VIEW_DOC, doc.as_bytes())
            && self.st.db().is_some()
        {
            crate::logf!("[budget] saving the view: {e:#}");
        }
    }

    /// the leader's figures (budget, fly), else this replica's own
    pub fn load_budget_view(&self) -> (Value, Value) {
        if let Some(b) = self.st.read_doc(BUDGET_VIEW_DOC)
            && let Ok(v) = serde_json::from_slice::<Value>(&b)
        {
            return (v["budget"].clone(), v["fly"].clone());
        }
        BUDGET_VIEW.lock().map(|g| g.clone()).unwrap_or_default()
    }

    fn set_fly_view(&self, v: Value) {
        if let Ok(mut g) = BUDGET_VIEW.lock() {
            g.1 = v;
        }
    }

    /// what Fly has in the sessions' app that isn't a running session of the router's: machines it never started (or
    /// no session uses any more) and volumes (sessions use none)
    pub fn also_on_fly(&self, ms: &[FlyMachine], vs: &[FlyVolume]) -> Vec<FlyOther> {
        let mut out: Vec<FlyOther> = self.st.do_(|d| {
            let mut out = vec![];
            for m in ms {
                let sid = d.machines.get(&m.id);
                let mut detail = m
                    .config
                    .guest
                    .as_ref()
                    .map(|g| {
                        format!(
                            "{}×{} · {} GB",
                            g.cpus,
                            g.cpu_kind,
                            (g.memory_mb as f64 / 1024.0).round() as i64
                        )
                    })
                    .unwrap_or_default();
                let s = sid.and_then(|sid| d.sessions.get(sid));
                match (sid, s) {
                    (None, _) => {
                        detail = format!("{detail} · not started by this router")
                            .trim_start_matches(" · ")
                            .to_string();
                    }
                    (Some(sid), s) if s.is_none_or(|s| s.machine_id != m.id) => {
                        if m.state != "started" {
                            continue; // a session's old machine, stopped: Fly keeps it a while
                        }
                        detail = format!("{detail} · its session ({sid}) no longer runs on it")
                            .trim_start_matches(" · ")
                            .to_string();
                    }
                    _ => continue,
                }
                out.push(FlyOther {
                    kind: "machine".into(),
                    app: SESSIONS_APP.into(),
                    id: m.id.clone(),
                    name: m.name.clone(),
                    state: m.state.clone(),
                    region: m.region.clone(),
                    created: m.created_at.clone(),
                    detail,
                });
            }
            out
        });
        let live: BTreeSet<String> = self.st.read(|d| {
            d.sessions
                .values()
                .filter(|s| !s.machine_id.is_empty())
                .map(|s| s.machine_id.clone())
                .collect()
        });
        for v in vs {
            // deleted (pending_destroy: not billed) or a running session's own: not outside the sessions
            if volume_gone(&v.state) || live.contains(&v.attached_machine_id) {
                continue;
            }
            let at = if v.attached_machine_id.is_empty() {
                " · not attached".to_string()
            } else {
                format!(" · attached to {}", v.attached_machine_id)
            };
            out.push(FlyOther {
                kind: "volume".into(),
                app: SESSIONS_APP.into(),
                id: v.id.clone(),
                name: v.name.clone(),
                state: v.state.clone(),
                region: v.region.clone(),
                created: v.created_at.clone(),
                detail: format!("{} GB{at}", v.size_gb),
            });
        }
        out.sort_by(|a, b| a.kind.cmp(&b.kind).then(a.id.cmp(&b.id)));
        out
    }

    /// one sample (aws None: no AWS key, Fly alone) → what it did, for tests
    pub fn budget_tick(
        self: &Arc<Self>,
        fly: &dyn FlyReader,
        aws: Option<&dyn AwsCoster>,
        now: GoTime,
        cap: f64,
        warn: f64,
    ) -> Result<(BudgetActions, Vec<String>)> {
        let ms = match fly.machines() {
            Err(e) => {
                self.set_fly_view(json!({"apps": 1, "machines": 0, "volumes": 0, "other": [], "error": format!("{e:#}"), "checkedAt": now.utc()}));
                self.save_budget_view();
                return Err(e);
            }
            Ok(m) => m,
        };
        let (vs, verr) = match fly.volumes() {
            Ok(v) => (v, None),
            Err(e) => (vec![], Some(e)),
        };
        let mut view = json!({"apps": 1, "app": SESSIONS_APP, "machines": ms.len(), "volumes": live_volumes(&vs),
            "other": self.also_on_fly(&ms, &vs), "error": null, "checkedAt": now.utc()});
        if let Some(e) = verr {
            view["error"] = json!(format!("volumes: {e:#}"));
        }
        self.set_fly_view(view);
        if cap <= 0.0 {
            if let Ok(mut g) = BUDGET_VIEW.lock() {
                g.0 = Value::Null;
            }
            self.save_budget_view();
            return Ok((BudgetActions::default(), vec![]));
        }
        let mut b = burn_rate(&ms, &vs);
        let (stored, nsnap, serr) = snapshot_storage(fly, &snapshot_volumes(&vs), now);
        b.snapshot_bytes = stored;
        b.snapshots = nsnap as i64;
        b.rate_per_hour += hourly_snapshot_cost(stored);
        if let Some(e) = serr {
            crate::logf!("[budget] {e:#} (counted from the last list)");
        }
        let prev = self.st.do_(|d| d.budget.clone());
        let ap = crate::awsbudget::read_aws(aws, prev.as_ref(), now); // awsbudget.rs; None without a key
        let smp = SpendSample {
            fly_rate: b.rate_per_hour,
            aws_rate: ap.as_ref().map_or(0.0, |a| a.burn.rate_per_hour),
            fabric_rate: ap.as_ref().map_or(0.0, |a| a.burn.fabric_rate_per_hour),
            billed: ap.as_ref().and_then(|a| a.billed.clone()),
        };
        let (state, act) = self.st.do_(|d| {
            let (state, act, _) = apply_sample(d.budget.as_ref(), now, &smp, cap, warn);
            d.budget = Some(state.clone());
            (state, act)
        });
        let (spent, rate) = (state.pool(), smp.fly_rate + smp.aws_rate);
        let fly_part = json!({"spentUsd": state.fly_part(), "ratePerHour": b.rate_per_hour, "perMonth": b.rate_per_hour * HOURS_PER_MONTH,
            "running": b.running, "volumes": b.volumes, "snapshots": b.snapshots, "snapshotGb": b.snapshot_bytes as f64 / 1e9});
        let mut running = b.running;
        let mut aws_part = Value::Null;
        if let Some(ap) = &ap {
            aws_part = Value::Object(ap.view(self, &state));
            running += ap.burn.running;
        }
        if let Ok(mut g) = BUDGET_VIEW.lock() {
            g.0 = json!({"month": state.month, "spentUsd": spent, "capUsd": cap, "warnUsd": warn,
                "warned": state.warned, "capped": state.capped, "cappedAt": state.capped_at, "ratePerHour": rate,
                "perMonth": rate * HOURS_PER_MONTH, "running": running, "volumes": b.volumes,
                "snapshots": b.snapshots, "snapshotGb": b.snapshot_bytes as f64 / 1e9, "sampledAt": state.last_sample_at,
                "fly": fly_part, "aws": aws_part});
        }
        self.save_budget_view();
        // what is running: Fly's started machines and AWS's running instances, each a session's or not
        let mut up: Vec<String> = ms
            .iter()
            .filter(|m| m.state == "started")
            .map(|m| m.id.clone())
            .collect();
        if let Some(ap) = &ap {
            up.extend(
                ap.inv
                    .instances
                    .iter()
                    // the fabric's hosts are hermit's: they go when their sandboxes do (the fabric's sessions, below)
                    .filter(|i| {
                        (i.state == "running" || i.state == "pending")
                            && i.region != crate::awsbudget::AWS_FABRIC_REGION
                    })
                    .map(|i| i.id.clone()),
            );
        }
        // the fabric's sessions: their machines are hermit's sandboxes, in neither Fly's nor AWS's listing
        self.st.read(|d| {
            up.extend(
                d.sessions
                    .values()
                    .filter(|s| {
                        s.fabric.is_some()
                            && !s.machine_id.is_empty()
                            && (s.state == "started" || s.state == "frozen")
                    })
                    .map(|s| s.machine_id.clone()),
            );
        });
        let split = if ap.is_some() {
            format!(
                " (Fly {}, AWS {})",
                usd(state.fly_part()),
                usd(state.aws_part())
            )
        } else {
            String::new()
        };
        let mut paused = vec![];
        if act.enforce {
            let mut unknown = vec![];
            for id in &up {
                let found = self.st.do_(|d| {
                    let s = d
                        .machines
                        .get(id)
                        .and_then(|sid| d.sessions.get(sid))
                        .filter(|s| s.machine_id == *id)?;
                    let name = [&s.label, &s.title, &s.id]
                        .into_iter()
                        .find(|x| !x.is_empty())
                        .cloned()
                        .unwrap_or_default();
                    Some((s.id.clone(), name))
                });
                let Some((sid, name)) = found else {
                    unknown.push(id.clone());
                    continue;
                };
                // a session another action holds (starting, being destroyed…) is skipped; the next tick tries again
                if let Err(e) = budget_pause(self, &sid) {
                    crate::logf!("[budget] pause {sid}: {e:#}");
                    continue;
                }
                crate::logf!("[budget] paused {sid} ({id}): month over the cap");
                paused.push(name);
            }
            if act.cap_dm || !paused.is_empty() {
                let mut msg = format!(
                    "Budget cap (Jarvis 4, Fly + AWS): an estimated {}{split} of {} spent in {}. ",
                    usd(spent),
                    usd(cap),
                    state.month
                );
                if paused.is_empty() {
                    msg.push_str("No running sessions to pause. ");
                } else {
                    msg.push_str(&format!(
                        "Paused {} running session(s): {}. They resume from the app. ",
                        paused.len(),
                        paused.join(", ")
                    ));
                }
                if !unknown.is_empty() {
                    msg.push_str(&format!("{} machine(s) on Fly or AWS that are no session of the router's are still running ({}); the router can't stop them. ", unknown.len(), unknown.join(", ")));
                }
                msg.push_str(&format!(
                    "Anything started before the month ends is paused again. The burn rate was {} a month.",
                    usd(rate * HOURS_PER_MONTH)
                ));
                budget_dm(self, &msg);
            }
        } else if act.warn_dm {
            budget_dm(
                self,
                &format!(
                    "Spend (Jarvis 4, Fly + AWS): an estimated {}{split} of {} in {} ({}%), {running} session machine(s) running at {} a month. At {} running sessions are paused.",
                    usd(spent),
                    usd(cap),
                    state.month,
                    (spent / cap * 100.0) as i64,
                    usd(rate * HOURS_PER_MONTH),
                    usd(cap)
                ),
            );
        }
        Ok((act, paused))
    }

    pub fn budget_loop(self: &Arc<Self>) {
        let token = std::env::var("FLY_READ_TOKEN").unwrap_or_default();
        if token.is_empty() {
            crate::logf!("[budget] FLY_READ_TOKEN unset: no budget cap, no Also on Fly");
            self.set_fly_view(json!({"apps": 0, "machines": 0, "volumes": 0, "other": [], "error": "FLY_READ_TOKEN not set", "checkedAt": null}));
            self.save_budget_view();
            return;
        }
        let fly = FlyApi {
            base: "https://api.machines.dev".into(),
            app: SESSIONS_APP.into(),
            token,
        };
        let (cap, warn) = budget_thresholds(|k| std::env::var(k).unwrap_or_default());
        let aws = crate::awsbudget::aws_coster_from_env(); // AWS in the same pool (None without the router's key)
        if aws.is_none() {
            crate::logf!("[budget] AWS_READ_ACCESS_KEY_ID unset: AWS is not in the budget");
        }
        loop {
            crate::leaderlease::await_lead();
            if let Err(e) = self.budget_tick(&fly, aws.as_deref(), GoTime::now(), cap, warn) {
                crate::logf!("[budget] {e:#}");
            }
            std::thread::sleep(BUDGET_TICK);
        }
    }
}

/// /api/state's budget, fly, flyApp (features.rs state hooks): budget null until the first sample, or with the cap off
pub fn budget_state_hook(r: &Arc<Router>, out: &mut Map<String, Value>) {
    let (b, f) = r.load_budget_view();
    out.insert("budget".into(), b);
    out.insert("fly".into(), f);
    out.insert("flyApp".into(), json!(SESSIONS_APP));
}
