//! Every Fly org on the Machines view (Deyao, 2026-10-11: "both list all machines so I can see a leak clearly"):
//! besides jarvis4-sessions (machines.rs: sessions, Destroy), every app in every org Deyao has, read-only, grouped
//! org → app, each machine and volume with why it stands out (a possible leak), if it does.
//!
//! Where each org comes from: Fly directly, with that org's READ-ONLY token. They can change nothing.
//!   - an org in FLY_ORG_READ_TOKENS ({"<org slug>": "<token>"}, router-secrets part `flyorgs`): jarvis2-370 (`fly
//!     tokens create readonly`);
//!   - org personal: FLY_PERSONAL_READ_TOKEN (part `flypersonal`): the personal org token attenuated to read on that
//!     org (caveat Organization mask "r"). It reads every machine's config in the org, env included, and Jarvis 1's
//!     session machines carry their stores in their Fly env: the trade-off is DECISIONS 138.
//!
//! Only the fields below leave this file: env never does.

use crate::budget::{FlyVolume, HOURS_PER_MONTH, SESSIONS_APP, hourly_machine_cost, volume_gone};
use crate::machines::{FlyMachineDetail, MachineView, guest_text, image_of, sort_machine_views};
use crate::router::Router;
use anyhow::{Result, anyhow};
use jarvis_go::GoTime;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::{LazyLock, RwLock};
use std::time::Duration;

/// this router's own org (the one jarvis4-sessions lives in)
pub const OWN_FLY_ORG: &str = "jarvis2-370";

/// the apps a Jarvis runs sessions in; a machine anywhere else is unexplained
pub fn known_fly_app(app: &str) -> &'static str {
    match app {
        "de0ch-claude-sessions" => "Jarvis 1 sessions",
        "jarvis4-sessions" => "Jarvis 4 sessions",
        _ => "",
    }
}

/// the apps Jarvis 4 itself runs that are not session apps: what each is for (the Machines tab's label, with the
/// monthly cost of its started machines added); their machines are expected, so not flagged as unexplained
pub fn jarvis_own_app(app: &str) -> &'static str {
    match app {
        "jarvis2-log-shipper" => {
            "Jarvis 4's log shipper: sends the session machines' logs to Grafana Cloud"
        }
        _ => "",
    }
}

/// what the app is for, plus what its started machines cost a month at budget.rs's rates (each in its region)
pub fn own_app_label(what: &str, ms: &[FlyMachineDetail]) -> String {
    let per_hour: f64 = ms
        .iter()
        .filter(|m| m.state == "started")
        .map(|m| hourly_machine_cost(m.config.guest.as_ref(), &m.region))
        .sum();
    if per_hour == 0.0 {
        return what.to_string();
    }
    format!("{what} · USD {:.2}/month", per_hour * HOURS_PER_MONTH)
}

/// a machine still created/starting after this is stuck
pub const STUCK_AFTER: time::Duration = time::Duration::minutes(15);

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct FlyVolumeView {
    pub id: String,
    pub name: String,
    pub state: String,
    pub region: String,
    #[serde(rename = "sizeGb")]
    pub size_gb: i64,
    #[serde(rename = "attachedTo")]
    pub attached_to: String,
    pub created: String,
    pub attention: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct FlyAppView {
    pub app: String,
    /// "Jarvis 4 sessions", or "" for an app no Jarvis uses
    pub label: String,
    /// jarvis4-sessions: sessions and Destroy
    pub own: bool,
    pub status: String,
    pub machines: Vec<MachineView>,
    pub volumes: Vec<FlyVolumeView>,
    pub error: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct FlyOrgView {
    pub org: String,
    /// "fly": read directly with a read-only token
    pub via: String,
    pub error: String,
    #[serde(rename = "checkedAt")]
    pub checked_at: String,
    pub apps: Vec<FlyAppView>,
}

/// why a machine stands out, or "". Both Jarvises destroy a machine on pause, so a stopped one is left over: it keeps
/// its disk (billed) and counts toward the org's machine cap.
pub fn attention_of(
    state: &str,
    created: &str,
    own: bool,
    session_id: &str,
    app: &str,
    now: GoTime,
) -> String {
    match state {
        "stopped" | "suspended" => {
            return "Stopped: keeps its disk (billed) and counts toward Fly's machine cap".into();
        }
        "failed" => return "Failed".into(),
        "created" | "starting" | "replacing" => {
            if let Some(t) = GoTime::parse(created)
                && now.sub(&t) > STUCK_AFTER
            {
                return format!("Stuck in {}", jarvis_go::fmt::go_quote(state));
            }
        }
        _ => {}
    }
    if own && session_id.is_empty() {
        return "No session".into();
    }
    if !own && !app.is_empty() && known_fly_app(app).is_empty() && jarvis_own_app(app).is_empty() {
        return "In an app no Jarvis runs sessions in".into();
    }
    String::new()
}

pub fn volume_view_of(v: &FlyVolume) -> FlyVolumeView {
    FlyVolumeView {
        id: v.id.clone(),
        name: v.name.clone(),
        state: v.state.clone(),
        region: v.region.clone(),
        size_gb: v.size_gb,
        attached_to: v.attached_machine_id.clone(),
        created: v.created_at.clone(),
        attention: if v.attached_machine_id.is_empty() {
            "Not attached to a machine: billed for nothing".into()
        } else {
            String::new()
        },
    }
}

/// a machine of another app, read-only (no session, no Destroy); env never copied
pub fn other_machine_view(m: &FlyMachineDetail, app: &str, now: GoTime) -> MachineView {
    MachineView {
        id: m.id.clone(),
        name: m.name.clone(),
        state: m.state.clone(),
        region: m.region.clone(),
        created: m.created_at.clone(),
        updated: m.updated_at.clone(),
        image: image_of(m),
        no_destroy: format!("it is not in {SESSIONS_APP}: read-only here"),
        guest: m.config.guest.as_ref().map(guest_text).unwrap_or_default(),
        attention: attention_of(&m.state, &m.created_at, false, "", app, now),
        ..Default::default()
    }
}

/// FLY_ORG_READ_TOKENS parsed; an unreadable value is an error shown on the page
pub fn fly_org_tokens() -> (BTreeMap<String, String>, Option<String>) {
    let mut raw = std::env::var("FLY_ORG_READ_TOKENS").unwrap_or_default();
    if raw.is_empty() {
        raw = "{}".into();
    }
    let (mut m, err) = match serde_json::from_str::<BTreeMap<String, String>>(&raw) {
        Ok(m) => (m, None),
        Err(_) => (
            BTreeMap::new(),
            Some("FLY_ORG_READ_TOKENS is not valid JSON".to_string()),
        ),
    };
    if let Ok(t) = std::env::var("FLY_PERSONAL_READ_TOKEN")
        && !t.is_empty()
    {
        m.insert("personal".into(), t);
    }
    (m, err)
}

/// the Machines API (tests point it at a fake)
pub static FLY_API_BASE: LazyLock<RwLock<String>> =
    LazyLock::new(|| RwLock::new("https://api.machines.dev".into()));

static FLY_ORG_HTTP: LazyLock<reqwest::blocking::Client> = LazyLock::new(|| {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap_or_default()
});

pub fn fly_get<T: serde::de::DeserializeOwned>(token: &str, path: &str) -> Result<T> {
    let mut auth = token.to_string();
    if !auth.starts_with("FlyV1 ") && !auth.starts_with("Bearer ") {
        auth = format!("Bearer {auth}");
    }
    let base = FLY_API_BASE
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let resp = FLY_ORG_HTTP
        .get(format!("{base}{path}"))
        .header("Authorization", auth)
        .send()?;
    let st = resp.status().as_u16();
    if st != 200 {
        let b = crate::util::read_limited(resp, 200).unwrap_or_default();
        return Err(anyhow!(
            "Fly GET {}: HTTP {st} {}",
            path.split('?').next().unwrap_or_default(),
            String::from_utf8_lossy(&b).trim()
        ));
    }
    let b = crate::util::read_limited(resp, 64 << 20)?;
    Ok(jarvis_go::unmarshal(&b)?)
}

fn now_text(now: GoTime) -> String {
    now.utc().rfc3339()
}

/// one org read directly. own (jarvis4-sessions, in the router's own org) is filled by the caller with
/// machines_view's session-aware list.
pub fn scan_fly_org(
    org: &str,
    token: &str,
    own: Option<&(dyn Fn() -> Vec<MachineView> + Sync)>,
    now: GoTime,
) -> FlyOrgView {
    let mut o = FlyOrgView {
        org: org.into(),
        via: "fly".into(),
        checked_at: now_text(now),
        ..Default::default()
    };
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct App {
        name: String,
        status: String,
    }
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Apps {
        apps: Vec<App>,
    }
    let apps: Apps = match fly_get(
        token,
        &format!("/v1/apps?org_slug={}", jarvis_go::fmt::query_escape(org)),
    ) {
        Err(e) => {
            o.error = format!("{e:#}");
            return o;
        }
        Ok(a) => a,
    };
    let mut out: Vec<FlyAppView> = std::thread::scope(|sc| {
        let hs: Vec<_> = apps
            .apps
            .iter()
            .map(|a| {
                sc.spawn(move || {
                    let name = a.name.as_str();
                    let mut av = FlyAppView {
                        app: name.into(),
                        label: known_fly_app(name).into(),
                        status: a.status.clone(),
                        ..Default::default()
                    };
                    let esc = jarvis_go::fmt::path_escape(name);
                    match own {
                        Some(own) if org == OWN_FLY_ORG && name == SESSIONS_APP => {
                            av.own = true;
                            av.machines = own();
                        }
                        _ => {
                            let ms: Vec<FlyMachineDetail> =
                                match fly_get(token, &format!("/v1/apps/{esc}/machines")) {
                                    Err(e) => {
                                        av.error = format!("{e:#}");
                                        vec![]
                                    }
                                    Ok(ms) => ms,
                                };
                            av.machines = ms
                                .iter()
                                .filter(|m| m.state != "destroyed")
                                .map(|m| other_machine_view(m, name, now))
                                .collect();
                            let what = jarvis_own_app(name);
                            if !what.is_empty() {
                                av.label = own_app_label(what, &ms);
                            }
                            sort_machine_views(&mut av.machines);
                        }
                    }
                    match fly_get::<Vec<FlyVolume>>(token, &format!("/v1/apps/{esc}/volumes")) {
                        Err(e) => {
                            if av.error.is_empty() {
                                av.error = format!("{e:#}");
                            }
                        }
                        Ok(vs) => {
                            // deleted ones (pending_destroy) are not billed: not leaks
                            av.volumes = vs
                                .iter()
                                .filter(|v| !volume_gone(&v.state))
                                .map(volume_view_of)
                                .collect();
                        }
                    }
                    av
                })
            })
            .collect();
        hs.into_iter()
            .map(|h| h.join().unwrap_or_default())
            .collect()
    });
    sort_apps(&mut out);
    o.apps = out;
    o
}

pub fn sort_apps(a: &mut [FlyAppView]) {
    a.sort_by(|x, y| y.own.cmp(&x.own).then_with(|| x.app.cmp(&y.app)));
}

/// how many machines, volumes, apps and orgs stand out
pub fn fly_attention_count(orgs: &[FlyOrgView]) -> usize {
    let mut n = 0;
    for o in orgs {
        n += usize::from(!o.error.is_empty());
        for a in &o.apps {
            n += usize::from(!a.error.is_empty());
            n += a
                .machines
                .iter()
                .filter(|m| !m.attention.is_empty())
                .count();
            n += a.volumes.iter().filter(|v| !v.attention.is_empty()).count();
        }
    }
    n
}

impl Router {
    /// every org, the router's own first, then the read-only ones by name (personal among them), and personal with an
    /// error when the router has no token for it. own_ms: jarvis4-sessions as the caller just listed it
    /// (FLY_READ_TOKEN). → (the orgs, the configuration's error or "")
    pub fn fly_orgs_overview(
        &self,
        own_ms: &[FlyMachineDetail],
        now: GoTime,
    ) -> (Vec<FlyOrgView>, String) {
        let (toks, err) = fly_org_tokens();
        let own = || self.machines_view(own_ms, now);
        let names: Vec<&String> = toks.keys().filter(|o| *o != OWN_FLY_ORG).collect();
        let mut orgs: Vec<FlyOrgView> = std::thread::scope(|sc| {
            let first = sc.spawn(|| {
                if let Some(t) = toks.get(OWN_FLY_ORG).filter(|t| !t.is_empty()) {
                    return scan_fly_org(OWN_FLY_ORG, t, Some(&own), now);
                }
                // no org token: the sessions app alone, with the app-scoped FLY_READ_TOKEN
                let av = FlyAppView {
                    app: SESSIONS_APP.into(),
                    label: known_fly_app(SESSIONS_APP).into(),
                    own: true,
                    machines: own(),
                    ..Default::default()
                };
                FlyOrgView {
                    org: OWN_FLY_ORG.into(),
                    via: "fly".into(),
                    checked_at: now_text(now),
                    apps: vec![av],
                    error: format!("no read-only token for the org in FLY_ORG_READ_TOKENS: only {SESSIONS_APP} is listed"),
                }
            });
            let rest: Vec<_> = names
                .iter()
                .map(|org| {
                    let t = toks.get(*org).cloned().unwrap_or_default();
                    sc.spawn(move || scan_fly_org(org, &t, None, now))
                })
                .collect();
            let mut out = vec![first.join().unwrap_or_default()];
            out.extend(rest.into_iter().map(|h| h.join().unwrap_or_default()));
            out
        });
        if toks.get("personal").is_none_or(|t| t.is_empty()) {
            orgs.push(FlyOrgView {
                org: "personal".into(),
                via: "fly".into(),
                checked_at: now_text(now),
                error: "no read-only token for org personal (FLY_PERSONAL_READ_TOKEN)".into(),
                ..Default::default()
            });
        }
        (orgs, err.unwrap_or_default())
    }
}
