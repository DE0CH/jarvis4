//! The Machines view (Deyao, 2026-10-11: "I should be able to see all machines"; flyorgs.rs adds every other app and
//! org, read-only): every machine in the Fly app jarvis4-sessions, live from Fly with the router's read-only token
//! (FLY_READ_TOKEN, as budget.rs), each with the session it belongs to or none, and marked "test" when its JARVIS2_URL
//! is not production's router.
//!
//! Destroying one goes through the core's kill, the same call a pause makes: the core alone holds a Fly token that can
//! destroy, and its kill takes any machine of the app (Fly-confirmed). The router allows it only for a machine that
//! belongs to no session: Fly lists it, the router never started it (no Started entry, no cert, no session mapping)
//! and it is older than ORPHAN_MIN_AGE, so a machine the core is still creating for a Start (not yet recorded) is
//! never caught. A session machine is never acted on from this view; it is paused or destroyed as its session. The
//! kill gives the router no power it didn't have (it kills session machines on every pause).

use crate::budget::{FlyGuest, SESSIONS_APP};
use crate::http::{Registrar, write_err};
use crate::nethttp::write_json;
use crate::router::{Busy, Router};
use crate::state::Persisted;
use anyhow::{Result, anyhow};
use jarvis_go::GoTime;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;
use std::sync::RwLock;

/// production's router address on the Fly private network (the router's MACHINE_URL); any other JARVIS2_URL is a test
/// router's (an e2e, a rehearsal box)
pub const PRODUCTION_ROUTER_HOST: &str = "jarvis4-box._peer.internal";

/// a machine younger than this may be a Start in flight (the core creates it before the router records it)
pub const ORPHAN_MIN_AGE: time::Duration = time::Duration::minutes(15);

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct FlyMount {
    pub volume: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct FlyDetailConfig {
    pub image: String,
    pub env: BTreeMap<String, String>,
    pub guest: Option<FlyGuest>,
    /// a kernel machine's names its source (kernel/spawner SourceMeta)
    pub metadata: BTreeMap<String, String>,
    pub mounts: Vec<FlyMount>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct FlyImageRef {
    pub registry: String,
    pub repository: String,
    pub tag: String,
    pub digest: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct FlyMachineDetail {
    pub id: String,
    pub name: String,
    pub state: String,
    pub region: String,
    pub created_at: String,
    pub updated_at: String,
    pub config: FlyDetailConfig,
    pub image_ref: FlyImageRef,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct MachineView {
    pub id: String,
    pub name: String,
    pub state: String,
    pub region: String,
    /// small | medium | large when the guest is one of the sizes, else ""
    pub size: String,
    /// "4×shared · 4 GB"
    pub guest: String,
    pub image: String,
    pub created: String,
    pub updated: String,
    /// "" = no session
    #[serde(rename = "sessionId")]
    pub session_id: String,
    /// the session's current machine (false: an earlier machine of it that Fly still lists)
    pub current: bool,
    /// the machine's JARVIS2_URL
    #[serde(rename = "routerUrl")]
    pub router_url: String,
    /// JARVIS2_URL is not production's router
    pub test: bool,
    /// why Destroy isn't offered ("" = it is): belongs to a session, too new, another app (read-only), …
    #[serde(rename = "noDestroy")]
    pub no_destroy: String,
    /// why it stands out (a possible leak: stopped, failed, stuck, no session, an app no Jarvis uses), "" = it doesn't
    pub attention: String,
    /// org personal (via Jarvis 1): the Jarvis 1 session the machine belongs to; shown, never linked
    #[serde(rename = "otherSession", skip_serializing_if = "String::is_empty")]
    pub other_session: String,
}

pub fn guest_text(g: &FlyGuest) -> String {
    format!("{}×{} · {} GB", g.cpus, g.cpu_kind, (g.memory_mb as f64 / 1024.0).round() as i64)
}

/// the size whose guest this is (sizes.rs size_guest), "" = none of them
pub fn size_of(g: Option<&FlyGuest>) -> String {
    let Some(g) = g.filter(|g| g.memory_mb % 1024 == 0) else { return String::new() };
    let size = crate::sizes::NAMED_SIZES
        .iter()
        .find(|(_, gb)| gb * 1024 == g.memory_mb)
        .map(|(n, _)| n.to_string())
        .unwrap_or_else(|| format!("{}gb", g.memory_mb / 1024));
    let (kind, cpus, mb) = crate::sizes::size_guest(&size);
    if kind != g.cpu_kind || cpus != g.cpus || mb != g.memory_mb {
        return String::new();
    }
    size
}

pub fn is_test_router(u: &str) -> bool {
    if u.is_empty() {
        return false;
    }
    match url::Url::parse(u) {
        Err(_) => true,
        Ok(p) => p.host_str().unwrap_or_default() != PRODUCTION_ROUTER_HOST,
    }
}

pub fn image_of(m: &FlyMachineDetail) -> String {
    if m.config.image.is_empty() && !m.image_ref.repository.is_empty() {
        return format!("{}/{}:{}", m.image_ref.registry, m.image_ref.repository, m.image_ref.tag);
    }
    m.config.image.clone()
}

pub fn sort_machine_views(ms: &mut [MachineView]) {
    ms.sort_by(|a, b| b.created.cmp(&a.created).then_with(|| a.id.cmp(&b.id)));
}

/// why the machine may not be destroyed from the Machines view, or "" when it may. Called with the state held.
pub fn orphan_refusal(d: &Persisted, m: &FlyMachineDetail, now: GoTime) -> String {
    let sid = d.machines.get(&m.id);
    if let Some(sid) = sid
        && d.sessions.contains_key(sid)
    {
        return format!("it belongs to session {sid}: pause or destroy the session");
    }
    // a machine the router started that no session names now (a destroyed session's machine whose kill failed: Destroy
    // anyway, flows.rs) is an orphan like any other; one a live session still names is that session's
    if sid.is_none()
        && (d.started.contains_key(&m.id) || d.certs.contains_key(&m.id))
        && let Some(s) = d.sessions.values().find(|s| s.machine_id == m.id || s.booted == m.id)
    {
        return format!("it belongs to session {}: pause or destroy the session", s.id);
    }
    match GoTime::parse(&m.created_at) {
        Some(t) if now.sub(&t) >= ORPHAN_MIN_AGE => String::new(),
        _ => format!(
            "it is less than {} minutes old and may be a session still starting",
            ORPHAN_MIN_AGE.whole_minutes()
        ),
    }
}

/// jarvis4-sessions' machines from Fly (FLY_READ_TOKEN); tests swap it
pub type ListFn = fn() -> Result<Vec<FlyMachineDetail>>;

fn list_fly_machines_live() -> Result<Vec<FlyMachineDetail>> {
    let token = std::env::var("FLY_READ_TOKEN").unwrap_or_default();
    if token.is_empty() {
        return Err(anyhow!("FLY_READ_TOKEN not set"));
    }
    crate::flyorgs::fly_get(&token, &format!("/v1/apps/{SESSIONS_APP}/machines"))
}

pub static LIST_FLY_MACHINES: RwLock<ListFn> = RwLock::new(list_fly_machines_live);

pub fn list_fly_machines() -> Result<Vec<FlyMachineDetail>> {
    (*LIST_FLY_MACHINES.read().unwrap_or_else(|e| e.into_inner()))()
}

/// the core's kill (flows.rs makes the same call on a pause); tests swap it
pub type KillFn = fn(&Router, &str) -> Result<()>;

fn orphan_kill_live(r: &Router, id: &str) -> Result<()> {
    r.kill_until_destroyed(&json!({"machine": id})).map(|_| ())
}

pub static ORPHAN_KILL: RwLock<KillFn> = RwLock::new(orphan_kill_live);

pub fn or_dash(s: &str) -> &str {
    if s.trim().is_empty() { "-" } else { s }
}

impl Router {
    /// the list, newest first; pure (tests)
    pub fn machines_view(&self, ms: &[FlyMachineDetail], now: GoTime) -> Vec<MachineView> {
        let mut out: Vec<MachineView> = self.st.do_(|d| {
            ms.iter()
                .filter(|m| m.state != "destroyed")
                .map(|m| {
                    let mut v = MachineView {
                        id: m.id.clone(),
                        name: m.name.clone(),
                        state: m.state.clone(),
                        region: m.region.clone(),
                        created: m.created_at.clone(),
                        updated: m.updated_at.clone(),
                        image: image_of(m),
                        size: size_of(m.config.guest.as_ref()),
                        router_url: m.config.env.get("JARVIS2_URL").cloned().unwrap_or_default(),
                        ..Default::default()
                    };
                    if let Some(g) = &m.config.guest {
                        v.guest = guest_text(g);
                    }
                    v.test = is_test_router(&v.router_url);
                    if let Some(sid) = d.machines.get(&m.id) {
                        v.session_id = sid.clone();
                        v.current = d.sessions.get(sid).is_some_and(|s| s.machine_id == m.id);
                    }
                    v.no_destroy = orphan_refusal(d, m, now);
                    v.attention = crate::flyorgs::attention_of(&m.state, &m.created_at, true, &v.session_id, SESSIONS_APP, now);
                    v
                })
                .collect()
        });
        sort_machine_views(&mut out);
        out
    }

    /// destroy a machine that belongs to no session (re-checked against a fresh Fly list)
    pub fn destroy_orphan(&self, id: &str) -> Result<()> {
        let ms = list_fly_machines().map_err(|e| anyhow!("Fly: {e:#}"))?;
        let Some(m) = ms.into_iter().rfind(|m| m.id == id && m.state != "destroyed") else {
            return Err(anyhow!("no machine {id} in {SESSIONS_APP}"));
        };
        let why = self.st.do_(|d| orphan_refusal(d, &m, GoTime::now()));
        if !why.is_empty() {
            return Err(Busy(format!("machine {id} is not destroyed from here: {why}")).into());
        }
        (*ORPHAN_KILL.read().unwrap_or_else(|e| e.into_inner()))(self, id)?;
        crate::logf!(
            "machine {id} ({}, router {}) destroyed from the Machines view: it belonged to no session",
            or_dash(&m.name),
            or_dash(m.config.env.get("JARVIS2_URL").map(String::as_str).unwrap_or_default())
        );
        Ok(())
    }
}

pub fn register_machines(reg: &mut Registrar) {
    reg.app("GET /api/machines", |r, w, _| {
        let ms = match list_fly_machines() {
            Err(e) => return write_json(w, 502, &json!({"error": format!("Fly: {e:#}")})),
            Ok(ms) => ms,
        };
        let now = GoTime::now();
        let (orgs, config_err) = r.fly_orgs_overview(&ms, now);
        let (runners, runner_attention) = r.runners_for_machines(); // runners.rs: the Hetzner runners, each with its session
        write_json(
            w,
            200,
            &json!({"app": SESSIONS_APP, "org": crate::flyorgs::OWN_FLY_ORG, "machines": r.machines_view(&ms, now), "orgs": orgs,
                "runners": runners, "attention": crate::flyorgs::fly_attention_count(&orgs) + runner_attention,
                "configError": config_err, "checkedAt": now.utc()}),
        );
    });
    reg.app("POST /api/machines/{id}/destroy", |r, w, req| match r.destroy_orphan(&req.path_value("id")) {
        Err(e) => write_err(w, &e),
        Ok(()) => write_json(w, 200, &json!({"ok": true, "id": req.path_value("id")})),
    });
}
