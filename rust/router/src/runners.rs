//! Runners belong to a session (Deyao, 2026-11-17: "runners need to be owned by a session, just like fly sandboxes so I
//! can see orphaned or leaking runner machines"). A runner is a throwaway Hetzner Cloud server in the project "runners"
//! that a session uses for heavy work. The router holds that project's only token (HETZNER_RUNNERS_TOKEN,
//! router-secrets part `runners`); a session asks the router for a runner through its machine's proxy and never holds a
//! Hetzner token, so no server is made without an owner.
//!
//! The owner is the server's label `session=<session id>`, set by the router at create and never by the caller. The
//! router keeps no list of its own: Hetzner's is the only one, so a server the router didn't make shows too.
//!
//!   - Destroy deletes the session's runners.
//!   - A pause deletes them, unless a wakeup, cron or watch is armed: that session will run again and finds them
//!     ("Delete on idle pause. Kept when theres scheduled wakeup"). A restart, an Upgrade or a move to a bigger machine
//!     is no pause: the runners stay.
//!   - The Machines view (GET /api/runners) lists every server of the project with its session, or why it stands out:
//!     no session label, a session that is gone, a paused session nothing will wake. Delete is offered only for those.
//!
//! The session's SSH key is a Hetzner key object `runner-<session id>` (a server made with no key gets a root password
//! e-mailed to the account); it goes with the session's last runner.

use crate::http::Registrar;
use crate::lifecycle::LcHandle;
use crate::nethttp::{Req, W, write_error, write_json};
use crate::router::Router;
use crate::state::Persisted;
use anyhow::{Result, anyhow};
use jarvis_go::GoTime;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::{Arc, LazyLock, RwLock};
use std::time::Duration;

pub const RUNNERS_PROJECT: &str = "runners";
pub const RUNNER_PURPOSE: &str = "runner";
pub const MAX_SESSION_RUNNERS: usize = 10;
/// Hetzner's limit
pub const RUNNER_USER_DATA_MAX: usize = 32 << 10;

/// the Cloud API (a test's fake)
pub static HETZNER_API: LazyLock<RwLock<String>> =
    LazyLock::new(|| RwLock::new("https://api.hetzner.cloud/v1".into()));

static HETZNER_CLIENT: LazyLock<reqwest::blocking::Client> = LazyLock::new(|| {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(40))
        .build()
        .unwrap_or_default()
});

fn re(s: &str) -> regex::Regex {
    regex::Regex::new(s).unwrap_or_else(|_| unreachable!())
}

static RUNNER_NAME_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| re(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$"));
static RUNNER_WORD_RE: LazyLock<regex::Regex> = LazyLock::new(|| re(r"^[a-z0-9][a-z0-9.-]{0,62}$"));
static RUNNER_LABEL_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| re(r"^[A-Za-z0-9]([A-Za-z0-9._-]{0,61}[A-Za-z0-9])?$"));

/// what a session may do to its runner besides deleting it
fn runner_action(a: &str) -> bool {
    matches!(a, "poweron" | "poweroff" | "shutdown" | "reboot" | "reset")
}

/// runners aren't set up on this router
#[derive(Debug, Clone)]
pub struct NoRunners;

impl std::fmt::Display for NoRunners {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("runners aren't set up on this router (no HETZNER_RUNNERS_TOKEN)")
    }
}

impl std::error::Error for NoRunners {}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct HzGross {
    pub gross: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct HzPrice {
    pub location: String,
    pub price_monthly: HzGross,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct HzServerType {
    pub name: String,
    pub cores: i64,
    pub memory: f64,
    pub prices: Vec<HzPrice>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct HzName {
    pub name: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct HzDatacenter {
    pub location: HzName,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct HzIp {
    pub ip: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct HzPublicNet {
    pub ipv6: Option<HzIp>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct HzServer {
    pub id: i64,
    pub name: String,
    pub status: String,
    pub created: String,
    pub labels: BTreeMap<String, String>,
    pub server_type: HzServerType,
    pub location: Option<HzName>,
    pub datacenter: Option<HzDatacenter>,
    pub public_net: HzPublicNet,
}

impl HzServer {
    pub fn location(&self) -> String {
        if let Some(l) = self.location.as_ref().filter(|l| !l.name.is_empty()) {
            return l.name.clone();
        }
        self.datacenter
            .as_ref()
            .map(|d| d.location.name.clone())
            .unwrap_or_default()
    }

    /// the server's address, the first of its /64
    pub fn ipv6(&self) -> String {
        let Some(v6) = &self.public_net.ipv6 else {
            return String::new();
        };
        let mut ip = jarvis_go::fmt::cut(&v6.ip, "/").0.to_string();
        if ip.ends_with("::") {
            ip.push('1');
        }
        ip
    }

    /// what the server costs a month where it runs, as Hetzner prices it (gross), "" when it doesn't say
    pub fn monthly(&self) -> String {
        let loc = self.location();
        for p in &self.server_type.prices {
            if p.location == loc
                && !p.price_monthly.gross.is_empty()
                && let Ok(f) = p.price_monthly.gross.trim().parse::<f64>()
            {
                return format!("EUR {f:.2}/month");
            }
        }
        String::new()
    }
}

#[derive(Debug, Clone)]
pub struct HzError {
    pub status: u16,
    pub code: String,
    pub message: String,
}

impl std::fmt::Display for HzError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Hetzner: {} ({}, HTTP {})",
            self.message, self.code, self.status
        )
    }
}

impl std::error::Error for HzError {}

pub type HetznerFn = fn(&str, &str, Option<&Value>) -> Result<Vec<u8>>;

/// one call of the Cloud API with the runners project's token → its answer's body
fn hetzner_live(method: &str, path: &str, input: Option<&Value>) -> Result<Vec<u8>> {
    let tok = std::env::var("HETZNER_RUNNERS_TOKEN").unwrap_or_default();
    if tok.is_empty() {
        return Err(NoRunners.into());
    }
    let base = HETZNER_API
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let m = reqwest::Method::from_bytes(method.as_bytes())?;
    let mut req = HETZNER_CLIENT
        .request(m, format!("{base}{path}"))
        .header("Authorization", format!("Bearer {tok}"))
        .header("User-Agent", "jarvis4-router/1");
    if let Some(i) = input {
        req = req
            .header("Content-Type", "application/json")
            .body(jarvis_go::marshal(i));
    }
    let resp = req.send().map_err(|e| anyhow!("Hetzner: {e}"))?;
    let st = resp.status().as_u16();
    let b = crate::util::read_limited(resp, 8 << 20).unwrap_or_default();
    if st >= 300 {
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct E {
            code: String,
            message: String,
        }
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct Out {
            error: E,
        }
        let e: Out = jarvis_go::unmarshal(&b).unwrap_or_default();
        let message = if e.error.message.is_empty() {
            "no error text".into()
        } else {
            e.error.message
        };
        return Err(HzError {
            status: st,
            code: e.error.code,
            message,
        }
        .into());
    }
    Ok(b)
}

/// tests swap it
pub static HETZNER: RwLock<HetznerFn> = RwLock::new(hetzner_live);

fn hetzner(method: &str, path: &str, input: Option<&Value>) -> Result<Vec<u8>> {
    (*HETZNER.read().unwrap_or_else(|e| e.into_inner()))(method, path, input)
}

/// a call whose answer is decoded into T
fn hetzner_json<T: serde::de::DeserializeOwned + Default>(
    method: &str,
    path: &str,
    input: Option<&Value>,
) -> Result<T> {
    let b = hetzner(method, path, input)?;
    if b.is_empty() {
        return Ok(T::default());
    }
    jarvis_go::unmarshal(&b).map_err(|e| anyhow!("Hetzner's answer: {e}"))
}

pub fn hz_gone(err: &anyhow::Error) -> bool {
    err.downcast_ref::<HzError>()
        .is_some_and(|e| e.status == 404)
}

/// every server of the project matching the label selector ("" = all)
pub fn hz_servers(selector: &str) -> Result<Vec<HzServer>> {
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Pagination {
        next_page: Option<i64>,
    }
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Meta {
        pagination: Pagination,
    }
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Out {
        servers: Vec<HzServer>,
        meta: Meta,
    }
    let mut all = vec![];
    for page in 1..=20 {
        let mut q = url::form_urlencoded::Serializer::new(String::new());
        if !selector.is_empty() {
            q.append_pair("label_selector", selector);
        }
        q.append_pair("page", &page.to_string());
        q.append_pair("per_page", "50");
        let out: Out = hetzner_json("GET", &format!("/servers?{}", q.finish()), None)?;
        all.extend(out.servers);
        if out.meta.pagination.next_page.is_none() {
            break;
        }
    }
    all.sort_by(|a, b| a.created.cmp(&b.created));
    Ok(all)
}

pub fn runners_of(sid: &str) -> Result<Vec<HzServer>> {
    hz_servers(&format!("session={sid}"))
}

/// the Hetzner key object of a session's runners
pub fn runner_key_name(sid: &str) -> String {
    format!("runner-{sid}")
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct HzKey {
    pub id: i64,
    pub public_key: String,
}

fn hz_key_by_name(name: &str) -> Result<Option<HzKey>> {
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Out {
        ssh_keys: Vec<HzKey>,
    }
    let out: Out = hetzner_json(
        "GET",
        &format!("/ssh_keys?name={}", jarvis_go::fmt::query_escape(name)),
        None,
    )?;
    Ok(out.ssh_keys.into_iter().next())
}

/// an OpenSSH public key without its comment
pub fn key_body(public: &str) -> String {
    let f: Vec<&str> = public.split_whitespace().collect();
    if f.len() < 2 {
        return String::new();
    }
    format!("{} {}", f[0], f[1])
}

/// the session's key object holds this public key (a session on a new machine may have a new one)
fn ensure_runner_key(sid: &str, public: &str) -> Result<i64> {
    let name = runner_key_name(sid);
    let k = hz_key_by_name(&name)?;
    if let Some(k) = &k {
        if key_body(&k.public_key) == key_body(public) {
            return Ok(k.id);
        }
        if let Err(e) = hetzner("DELETE", &format!("/ssh_keys/{}", k.id), None)
            && !hz_gone(&e)
        {
            return Err(e);
        }
    }
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Out {
        ssh_key: HzKey,
    }
    let input = json!({"name": name, "public_key": key_body(public), "labels": {"session": sid}});
    let out: Out = hetzner_json("POST", "/ssh_keys", Some(&input))?;
    Ok(out.ssh_key.id)
}

/// what a session asks for
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct NewRunner {
    pub name: String,
    /// default cx23
    #[serde(rename = "type")]
    pub type_: String,
    /// default fsn1
    pub location: String,
    /// default ubuntu-24.04
    pub image: String,
    /// the session's public key: root's authorized key
    #[serde(rename = "sshKey")]
    pub ssh_key: String,
    /// cloud-init user data
    #[serde(rename = "userData")]
    pub user_data: String,
    /// the caller's own; `session` and `purpose` are the router's
    pub labels: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq)]
pub struct RunnerView {
    pub id: i64,
    pub name: String,
    pub status: String,
    #[serde(rename = "type")]
    pub type_: String,
    /// "2 vCPU · 4 GB"
    pub guest: String,
    pub location: String,
    pub ipv6: String,
    pub created: String,
    /// "EUR 6.59/month"
    pub monthly: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<BTreeMap<String, String>>,
    /// the `session` label, "" = none
    #[serde(rename = "sessionId")]
    pub session_id: String,
    /// the Machines view only: the owner's state ("" = no such session), why the runner stands out ("" = it doesn't),
    /// and whether Delete is offered (only for a runner that stands out for its owner)
    #[serde(rename = "sessionState", skip_serializing_if = "String::is_empty")]
    pub session_state: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub attention: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub deletable: bool,
}

pub fn runner_view_of(s: &HzServer) -> RunnerView {
    let mut v = RunnerView {
        id: s.id,
        name: s.name.clone(),
        status: s.status.clone(),
        type_: s.server_type.name.clone(),
        location: s.location(),
        ipv6: s.ipv6(),
        created: s.created.clone(),
        monthly: s.monthly(),
        session_id: s.labels.get("session").cloned().unwrap_or_default(),
        ..Default::default()
    };
    if s.server_type.cores > 0 {
        v.guest = format!(
            "{} vCPU · {} GB",
            s.server_type.cores,
            jarvis_go::fmt::go_float_g(s.server_type.memory)
        );
    }
    for (k, val) in &s.labels {
        if k != "session" && k != "purpose" {
            v.labels
                .get_or_insert_with(BTreeMap::new)
                .insert(k.clone(), val.clone());
        }
    }
    v
}

/// the session's runner of that name
fn own_runner(sid: &str, name: &str) -> Result<HzServer> {
    runners_of(sid)?
        .into_iter()
        .find(|s| s.name == name)
        .ok_or_else(|| {
            anyhow!(
                "this session has no runner {}",
                jarvis_go::fmt::go_quote(name)
            )
        })
}

/// the session's key object goes once it has no runner left
fn drop_runner_key(sid: &str) {
    if let Ok(Some(k)) = hz_key_by_name(&runner_key_name(sid))
        && let Err(e) = hetzner("DELETE", &format!("/ssh_keys/{}", k.id), None)
        && !hz_gone(&e)
    {
        crate::logf!("runners: session {sid}'s key: {e:#}");
    }
}

fn delete_server(id: i64) -> Result<()> {
    match hetzner("DELETE", &format!("/servers/{id}"), None) {
        Err(e) if !hz_gone(&e) => Err(e),
        _ => Ok(()),
    }
}

/// every runner of the session and its key; what was deleted, and the first failure
fn delete_session_runners(sid: &str) -> (Vec<String>, Option<anyhow::Error>) {
    let have = match runners_of(sid) {
        Err(e) => return (vec![], Some(e)),
        Ok(h) => h,
    };
    let mut gone = vec![];
    let mut first = None;
    for s in have {
        match delete_server(s.id) {
            Err(e) => {
                if first.is_none() {
                    first = Some(anyhow!("{}: {e:#}", s.name));
                }
            }
            Ok(()) => gone.push(s.name),
        }
    }
    if first.is_none() {
        drop_runner_key(sid);
    }
    (gone, first)
}

/// why a runner stands out on the Machines view ("" = it doesn't)
fn runner_attention(d: &Persisted, v: &mut RunnerView) {
    if v.session_id.is_empty() {
        v.attention = "No session: made outside Jarvis 4".into();
        v.deletable = true;
        return;
    }
    let Some(s) = d.sessions.get(&v.session_id) else {
        v.deletable = true;
        v.attention = if d.records.iter().any(|rec| rec.session.id == v.session_id) {
            "Its session was destroyed".into()
        } else {
            "Its session is gone".into()
        };
        return;
    };
    v.session_state = s.state.clone();
    if s.state == "paused" && !crate::schedule::will_wake(d, &s.id) {
        v.attention = "Its session is paused and nothing is armed to wake it".into();
        v.deletable = true;
    }
}

fn runner_err(w: &mut W, err: &anyhow::Error) {
    let status = if err.downcast_ref::<NoRunners>().is_some() {
        503
    } else if let Some(he) = err.downcast_ref::<HzError>() {
        if he.status == 409 || he.code == "uniqueness_error" {
            409
        } else {
            502
        }
    } else {
        400
    };
    write_error(w, status, &format!("{err:#}"));
}

impl Router {
    /// a server of the calling session
    pub fn create_runner(&self, sid: &str, mut i: NewRunner) -> Result<RunnerView> {
        i.name = i.name.trim().to_string();
        if !RUNNER_NAME_RE.is_match(&i.name) {
            return Err(anyhow!(
                "a runner's name is a host name: lower-case letters, digits and hyphens, at most 63 characters (got {})",
                jarvis_go::fmt::go_quote(&i.name)
            ));
        }
        for (field, v, def) in [
            ("type", &mut i.type_, "cx23"),
            ("location", &mut i.location, "fsn1"),
            ("image", &mut i.image, "ubuntu-24.04"),
        ] {
            if v.is_empty() {
                *v = def.into();
            }
            if !RUNNER_WORD_RE.is_match(v) {
                return Err(anyhow!(
                    "{field} {} is not a Hetzner name",
                    jarvis_go::fmt::go_quote(v)
                ));
            }
        }
        if key_body(&i.ssh_key).is_empty()
            || (!i.ssh_key.starts_with("ssh-") && !i.ssh_key.starts_with("ecdsa-"))
        {
            return Err(anyhow!(
                "sshKey must be the session's OpenSSH public key (root's authorized key on the runner)"
            ));
        }
        if i.user_data.len() > RUNNER_USER_DATA_MAX {
            return Err(anyhow!(
                "userData is {} bytes; Hetzner takes at most {RUNNER_USER_DATA_MAX}",
                i.user_data.len()
            ));
        }
        let mut labels = BTreeMap::new();
        for (k, v) in &i.labels {
            if k == "session" || k == "purpose" {
                continue;
            }
            if !RUNNER_LABEL_RE.is_match(k) || (!v.is_empty() && !RUNNER_LABEL_RE.is_match(v)) {
                return Err(anyhow!(
                    "label {k}={v}: letters, digits, '.', '_' and '-' only, at most 63 characters"
                ));
            }
            labels.insert(k.clone(), v.clone());
        }
        labels.insert("session".into(), sid.into());
        labels.insert("purpose".into(), RUNNER_PURPOSE.into());
        let have = runners_of(sid)?;
        if have.len() >= MAX_SESSION_RUNNERS {
            return Err(anyhow!(
                "this session has {} runners, the most one session may have: delete one first",
                have.len()
            ));
        }
        let key = ensure_runner_key(sid, &i.ssh_key)
            .map_err(|e| anyhow!("the session's SSH key: {e:#}"))?;
        let mut body = json!({"name": i.name, "server_type": i.type_, "image": i.image, "location": i.location,
            "labels": labels, "ssh_keys": [key], "start_after_create": true,
            // IPv6 only: the account is at its limit of primary IPv4 addresses (Deyao, 2026-10-13)
            "public_net": {"enable_ipv4": false, "enable_ipv6": true}});
        if !i.user_data.is_empty() {
            body["user_data"] = json!(i.user_data);
        }
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct Out {
            server: HzServer,
        }
        let out: Out = hetzner_json("POST", "/servers", Some(&body))?;
        crate::logf!(
            "runners: session {sid} made {} ({}, {} in {})",
            i.name,
            out.server.id,
            i.type_,
            i.location
        );
        self.lc_note(
            sid,
            "",
            &format!(
                "runner {} made (Hetzner {} in {})",
                i.name, i.type_, i.location
            ),
        );
        Ok(runner_view_of(&out.server))
    }

    /// one runner of the calling session
    pub fn delete_runner(&self, sid: &str, name: &str) -> Result<()> {
        let s = own_runner(sid, name)?;
        delete_server(s.id)?;
        crate::logf!("runners: session {sid} deleted {name} ({})", s.id);
        if runners_of(sid).is_ok_and(|l| l.is_empty()) {
            drop_runner_key(sid);
        }
        Ok(())
    }

    /// a session's runners go with it (a destroy, a pause nothing will wake). It never fails the action: a runner
    /// Hetzner didn't delete stays on the Machines view, standing out.
    pub fn end_runners(&self, sid: &str, op: &LcHandle, why: &str) {
        if std::env::var("HETZNER_RUNNERS_TOKEN")
            .unwrap_or_default()
            .is_empty()
        {
            return;
        }
        let (gone, err) = delete_session_runners(sid);
        if !gone.is_empty() {
            crate::logf!(
                "runners: session {sid} ({why}): deleted {}",
                gone.join(", ")
            );
            op.note(
                "",
                &format!("deleted the session's runners ({why}): {}", gone.join(", ")),
            );
        }
        if let Some(e) = err {
            crate::logf!("runners: session {sid} ({why}): {e:#}");
            op.note(
                "",
                &format!("a runner was not deleted (it shows on the Machines view): {e:#}"),
            );
        }
    }

    /// a paused session keeps its runners only when something armed will run it again
    pub fn runners_after_pause(&self, sid: &str, op: &LcHandle) {
        if std::env::var("HETZNER_RUNNERS_TOKEN")
            .unwrap_or_default()
            .is_empty()
        {
            return;
        }
        if !self.st.do_(|d| crate::schedule::will_wake(d, sid)) {
            return self.end_runners(sid, op, "paused with no wakeup or cron armed");
        }
        if let Ok(have) = runners_of(sid)
            && !have.is_empty()
        {
            op.note(
                "",
                &format!(
                    "kept the session's {} runner(s): a wakeup or cron is armed",
                    have.len()
                ),
            );
        }
    }

    /// every server of the project, for the Machines view
    pub fn runners_overview(&self) -> Result<(Vec<RunnerView>, i64)> {
        let all = hz_servers("")?;
        Ok(self.st.do_(|d| {
            let views: Vec<RunnerView> = all
                .iter()
                .map(|s| {
                    let mut v = runner_view_of(s);
                    runner_attention(d, &mut v);
                    v
                })
                .collect();
            let attention = views.iter().filter(|v| !v.attention.is_empty()).count() as i64;
            (views, attention)
        }))
    }

    /// the runners as a part of GET /api/machines, and how many stand out. null on a router with no runners (a test
    /// stack); Hetzner not answering is the part's error, not the view's.
    pub fn runners_for_machines(&self) -> (Value, i64) {
        match self.runners_overview() {
            Err(e) if e.downcast_ref::<NoRunners>().is_some() => (Value::Null, 0),
            Err(e) => (
                json!({"project": RUNNERS_PROJECT, "runners": [], "attention": 0, "error": format!("{e:#}")}),
                0,
            ),
            Ok((views, n)) => (
                json!({"project": RUNNERS_PROJECT, "runners": views, "attention": n, "checkedAt": GoTime::now().utc()}),
                n,
            ),
        }
    }

    /// Deyao's Delete on the Machines view, only for a runner that stands out for its owner (checked again here,
    /// against Hetzner's list and the sessions as they are now)
    pub fn delete_stray_runner(&self, id: i64) -> Result<()> {
        let s = hz_servers("")?
            .into_iter()
            .find(|s| s.id == id)
            .ok_or_else(|| anyhow!("no runner {id} in project {RUNNERS_PROJECT}"))?;
        let mut v = runner_view_of(&s);
        self.st.do_(|d| runner_attention(d, &mut v));
        if !v.deletable {
            return Err(anyhow!(
                "runner {} belongs to session {} ({}): it goes with its session",
                s.name,
                v.session_id,
                v.session_state
            ));
        }
        delete_server(id)?;
        crate::logf!(
            "runners: {} ({id}) deleted from the Machines view ({})",
            s.name,
            v.attention
        );
        if !v.session_id.is_empty() && runners_of(&v.session_id).is_ok_and(|l| l.is_empty()) {
            drop_runner_key(&v.session_id);
        }
        Ok(())
    }
}

/// the session itself, through its machine's proxy: its own runners only
fn own(
    reg: &mut Registrar,
    pattern: &str,
    f: impl Fn(&Arc<Router>, &mut W, &mut Req, &str, &[u8]) + Send + Sync + 'static,
) {
    reg.m(pattern, move |r, w, req, machine, body| {
        let sid = match r.machine_session(machine) {
            Ok(s) => s,
            Err(e) => return write_error(w, 403, &format!("{e:#}")),
        };
        let id = req.path_value("id");
        if id != sid {
            return write_error(
                w,
                403,
                &format!(
                    "this machine is session {sid}, not {id}: a session's runners are its own"
                ),
            );
        }
        f(r, w, req, &sid, body)
    });
}

pub fn register_runners(reg: &mut Registrar) {
    reg.app("GET /api/runners", |r, w, _| match r.runners_overview() {
        Err(e) => runner_err(w, &e),
        Ok((views, n)) => write_json(
            w,
            200,
            &json!({"project": RUNNERS_PROJECT, "runners": views, "attention": n, "checkedAt": GoTime::now().utc()}),
        ),
    });
    reg.app("POST /api/runners/{id}/delete", |r, w, req| {
        let Ok(id) = req.path_value("id").parse::<i64>() else {
            return write_error(w, 400, "a runner's id is a number");
        };
        match r.delete_stray_runner(id) {
            Err(e) => runner_err(w, &e),
            Ok(()) => write_json(w, 200, &json!({"ok": true, "id": id})),
        }
    });
    own(
        reg,
        "GET /m/api/sessions/{id}/runners",
        |_, w, _, sid, _| match runners_of(sid) {
            Err(e) => runner_err(w, &e),
            Ok(have) => {
                let views: Vec<RunnerView> = have.iter().map(runner_view_of).collect();
                write_json(w, 200, &json!({"runners": views}));
            }
        },
    );
    own(
        reg,
        "POST /m/api/sessions/{id}/runners",
        |r, w, _, sid, b| {
            let Ok(i) = jarvis_go::unmarshal::<NewRunner>(b) else {
                return write_error(
                    w,
                    400,
                    "the body must be JSON: {name, type, location, image, sshKey, userData, labels}",
                );
            };
            match r.create_runner(sid, i) {
                Err(e) => runner_err(w, &e),
                Ok(v) => write_json(w, 200, &v),
            }
        },
    );
    own(
        reg,
        "DELETE /m/api/sessions/{id}/runners/{name}",
        |r, w, req, sid, _| match r.delete_runner(sid, &req.path_value("name")) {
            Err(e) => runner_err(w, &e),
            Ok(()) => write_json(w, 200, &json!({"ok": true})),
        },
    );
    own(
        reg,
        "POST /m/api/sessions/{id}/runners/{name}/{action}",
        |_, w, req, sid, _| {
            let action = req.path_value("action");
            if !runner_action(&action) {
                return write_error(
                    w,
                    400,
                    "a runner's actions are poweron, poweroff, shutdown, reboot and reset",
                );
            }
            let res = own_runner(sid, &req.path_value("name")).and_then(|s| {
                hetzner(
                    "POST",
                    &format!("/servers/{}/actions/{action}", s.id),
                    Some(&json!({})),
                )
            });
            match res {
                Err(e) => runner_err(w, &e),
                Ok(_) => write_json(w, 200, &json!({"ok": true})),
            }
        },
    );
}
