//! The Browserbase spend guard: DM only (Deyao, 2026-10-01: cap USD 10 overage, warn at 80%); nothing is blocked.
//! Browserbase has no spend limit, and its usage API doesn't follow the billing cycle, so the router re-prices the UTC
//! month from the session list (GET /v1/sessions) with the line items of the real Developer-plan invoices:
//!   - browser time: per session, rounded UP to whole minutes (1 min minimum); 6,000 min included, then USD 0.002/min
//!   - proxy, line A: per session, rounded to whole MB (1 MB minimum when any proxy was used); 1,000 MB included,
//!     then USD 0.012/MB
//!   - proxy, line B: every proxy byte at USD 0.00000001 (USD 10/GB, nothing included), on top of line A
//! BROWSERBASE_API_KEY, BROWSERBASE_BUDGET_USD (0/unset = off) and BROWSERBASE_BUDGET_WARN_USD (default 80% of the cap).

use crate::router::Router;
use anyhow::{Result, anyhow};
use jarvis_go::GoTime;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const INCLUDED_MINUTES: f64 = 6000.0;
const PER_MINUTE_USD: f64 = 0.002;
const INCLUDED_PROXY_MB: f64 = 1000.0;
const PER_PROXY_MB_USD: f64 = 0.012;
const PER_PROXY_BYTE_USD: f64 = 0.00000001;
pub const BB_TICK_EVERY: Duration = Duration::from_secs(600);

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct BbSession {
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "startedAt")]
    pub started_at: String,
    #[serde(rename = "endedAt")]
    pub ended_at: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
    pub status: String,
    #[serde(rename = "proxyBytes")]
    pub proxy_bytes: f64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct BbUsage {
    pub count: i64,
    pub minutes: f64,
    #[serde(rename = "proxyMb")]
    pub proxy_mb: f64,
    #[serde(rename = "proxyBytes")]
    pub proxy_bytes: f64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct BbOverage {
    pub time: f64,
    #[serde(rename = "proxyMb")]
    pub proxy_mb: f64,
    #[serde(rename = "proxyBytes")]
    pub proxy_bytes: f64,
    pub total: f64,
}

/// the month's DM flags (persisted)
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct BBBudgetState {
    pub month: String,
    pub warned: bool,
    pub capped: bool,
    #[serde(rename = "overUsd")]
    pub over_usd: f64,
    #[serde(rename = "sampledAt")]
    pub sampled_at: GoTime,
}

fn bb_time(s: &str) -> Option<GoTime> {
    if s.is_empty() { None } else { GoTime::parse(s) }
}

fn month_of(t: &GoTime) -> String {
    t.utc().rfc3339()[..7].to_string()
}

/// the sessions created in month (UTC "YYYY-MM"); a running one counts up to now
pub fn bb_cycle_usage(sessions: &[BbSession], month: &str, now: GoTime) -> BbUsage {
    let mut u = BbUsage::default();
    for s in sessions {
        let Some(created) = bb_time(&s.created_at) else { continue };
        if month_of(&created) != month {
            continue;
        }
        u.count += 1;
        let start = bb_time(&s.started_at).unwrap_or(created);
        let mut end_s = s.ended_at.clone();
        if end_s.is_empty() && s.status != "RUNNING" {
            end_s = s.updated_at.clone();
        }
        let end = bb_time(&end_s).unwrap_or(now);
        let mins = end.sub(&start).as_seconds_f64() / 60.0;
        u.minutes += f64::max(1.0, mins.ceil());
        if s.proxy_bytes > 0.0 {
            u.proxy_bytes += s.proxy_bytes;
            u.proxy_mb += f64::max(1.0, (s.proxy_bytes / 1e6).round());
        }
    }
    u
}

pub fn bb_overage_of(u: &BbUsage) -> BbOverage {
    let mut o = BbOverage {
        time: f64::max(0.0, u.minutes - INCLUDED_MINUTES) * PER_MINUTE_USD,
        proxy_mb: f64::max(0.0, u.proxy_mb - INCLUDED_PROXY_MB) * PER_PROXY_MB_USD,
        proxy_bytes: u.proxy_bytes * PER_PROXY_BYTE_USD,
        total: 0.0,
    };
    o.total = o.time + o.proxy_mb + o.proxy_bytes;
    o
}

/// fold one estimate into the month's flags; which DM (if any) to send now → (state, cap DM, warn DM)
pub fn bb_apply(prev: Option<&BBBudgetState>, now: GoTime, over: f64, cap: f64, warn: f64) -> (BBBudgetState, bool, bool) {
    let month = month_of(&now);
    let mut s = match prev {
        Some(p) if p.month == month => p.clone(),
        _ => BBBudgetState { month, ..Default::default() },
    };
    s.over_usd = over;
    s.sampled_at = now.utc();
    let (mut cap_dm, mut warn_dm) = (false, false);
    if cap > 0.0 && over >= cap {
        if !s.capped {
            cap_dm = true;
            s.capped = true;
        }
        s.warned = true; // no separate warn DM after (or in the same tick as) the cap
    } else if warn > 0.0 && over >= warn && !s.warned {
        warn_dm = true;
        s.warned = true;
    }
    (s, cap_dm, warn_dm)
}

pub fn bb_thresholds(getenv: impl Fn(&str) -> String) -> (f64, f64) {
    let cap: f64 = getenv("BROWSERBASE_BUDGET_USD").parse().unwrap_or(0.0);
    let warn = match getenv("BROWSERBASE_BUDGET_WARN_USD").parse::<f64>() {
        Ok(v) if v > 0.0 => v,
        _ if cap > 0.0 => (cap * 0.8 * 100.0).round() / 100.0,
        _ => 0.0,
    };
    (cap, warn)
}

/// tests point it elsewhere
pub static BB_API_BASE: Mutex<String> = Mutex::new(String::new());

fn bb_api_base() -> String {
    let b = BB_API_BASE.lock().map(|g| g.clone()).unwrap_or_default();
    if b.is_empty() { "https://api.browserbase.com".into() } else { b }
}

pub fn bb_list_sessions(key: &str) -> Result<Vec<BbSession>> {
    let resp = reqwest::blocking::Client::new()
        .get(format!("{}/v1/sessions", bb_api_base()))
        .timeout(Duration::from_secs(30))
        .header("X-BB-API-Key", key)
        .header("Accept", "application/json")
        .header("User-Agent", "jarvis2-router")
        .send()?;
    if resp.status().as_u16() != 200 {
        return Err(anyhow!("browserbase sessions: HTTP {}", resp.status().as_u16()));
    }
    let b = crate::util::read_limited(resp, 64 << 20)?;
    Ok(jarvis_go::unmarshal(&b)?)
}

/// the last tick's figures; written to router_docs (BB_VIEW_DOC) by the leader that ticks and read from there by
/// whichever replica answers /api/state
static BB_VIEW: Mutex<Option<Map<String, Value>>> = Mutex::new(None);
pub const BB_VIEW_DOC: &str = "browserbase-budget-view.json";

impl Router {
    /// one sample; the DM texts are Jarvis 1's
    pub fn bb_budget_tick(self: &Arc<Self>, sessions: &[BbSession], now: GoTime, cap: f64, warn: f64) {
        let month = month_of(&now);
        let u = bb_cycle_usage(sessions, &month, now);
        let o = bb_overage_of(&u);
        let (st, cap_dm, warn_dm) = self.st.do_(|d| {
            let (st, c, w) = bb_apply(d.bb_budget.as_ref(), now, o.total, cap, warn);
            d.bb_budget = Some(st.clone());
            (st, c, w)
        });
        let v = json!({"month": month, "capUsd": cap, "warnUsd": warn, "overUsd": o.total, "parts": o, "usage": u,
            "warned": st.warned, "capped": st.capped, "sampledAt": st.sampled_at})
        .as_object()
        .cloned()
        .unwrap_or_default();
        if let Ok(mut g) = BB_VIEW.lock() {
            *g = Some(v.clone());
        }
        if let Err(e) = self.st.write_doc(BB_VIEW_DOC, jarvis_go::marshal(&v).as_bytes())
            && self.st.db().is_some()
        {
            crate::logf!("[bb-budget] saving the view: {e:#}");
        }
        let detail = format!(
            "{:.0} browser min, {:.2} GB proxy across {} session(s)",
            u.minutes,
            u.proxy_bytes / 1e9,
            u.count
        );
        let usd = crate::budget::usd;
        if cap_dm {
            crate::budget::budget_dm(self, &format!("Browserbase spend cap reached: estimated overage {} above the USD 20 plan fee in {month} (cap {}). {detail}. Nothing is blocked.", usd(o.total), usd(cap)));
        } else if warn_dm {
            crate::budget::budget_dm(self, &format!("Browserbase spend: estimated overage {} of the {} cap in {month}. {detail}.", usd(o.total), usd(cap)));
        }
    }

    pub fn bb_budget_loop(self: &Arc<Self>) {
        let (cap, warn) = bb_thresholds(|k| std::env::var(k).unwrap_or_default());
        let key = std::env::var("BROWSERBASE_API_KEY").unwrap_or_default();
        if cap <= 0.0 || key.is_empty() {
            crate::logf!(
                "[bb-budget] off (BROWSERBASE_BUDGET_USD {}, key set {})",
                jarvis_go::fmt::go_float_g(cap),
                !key.is_empty()
            );
            return;
        }
        loop {
            crate::leaderlease::await_lead();
            match bb_list_sessions(&key) {
                Err(e) => crate::logf!("[bb-budget] {e:#}"),
                Ok(ss) => self.bb_budget_tick(&ss, GoTime::now(), cap, warn),
            }
            std::thread::sleep(BB_TICK_EVERY);
        }
    }
}

/// /api/state's browserbaseBudget (features.rs state hooks)
pub fn bb_state_hook(r: &Arc<Router>, out: &mut Map<String, Value>) {
    let mut v = BB_VIEW.lock().ok().and_then(|g| g.clone()).map(Value::Object).unwrap_or(Value::Null);
    if let Some(b) = r.st.read_doc(BB_VIEW_DOC)
        && let Ok(x) = serde_json::from_slice::<Value>(&b)
    {
        v = x;
    }
    out.insert("browserbaseBudget".into(), v);
}
