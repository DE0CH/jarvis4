//! Only vouched inputs shape this machine (docs/DESIGN.md "Inputs to a machine", Deyao 2026-10-11). The machine gets
//! secrets, so everything that decides what it runs or what its agent reads at its entry points must be vouched for
//! by one of:
//!
//!   (a) the cert: what the phone approved, or what an unattended resume carried over unchanged;
//!   (b) the predecessor machine's signature (its snapshot, whose hash the cert names);
//!   (c) this line's own signature (what a machine of this line asked for itself: wakeups, crons; deliver.rs);
//!   (d) a trusted provider over an authenticated channel (GitHub, over SSH with the repo's deploy key).
//!
//! Nothing the router says on its own reaches a program or the agent, except a few values whose strict format can't
//! carry an instruction (format exceptions). So the env is thrown away at boot except the image's own, Fly's values,
//! the core's key and the router's address (clean_env); the settings come from the cert (Options.Config /
//! Options.Once); the repos are only those whose deploy-key store the cert names.

use crate::cert::{Cert, cert_mode};
use crate::client::Client;
use crate::harnesses::via_harness_send;
use crate::kernelboot::{KERNEL_ROOT_ENV, KERNEL_ROSTER_ENV, KERNEL_SOURCE_ENV};
use crate::task::{ENV_NAME_RE, TASK_TEMPLATE_RE};
use crate::{apiproxy::API_PROXY_ADDR, gojson, logf, paths, re};
use anyhow::{Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

pub const CORE_KEY_ENV: &str = "JARVIS2_CORE_KEY";
/// the image's own ENV, written at build (session-image/Dockerfile)
pub const IMAGE_ENV_FILE: &str = "/opt/jarvis/image.env";

/// what Fly itself sets in a machine, and what an AWS instance's unit sets (values only: they never name code)
const FLY_ENV: &[&str] = &[
    "FLY_MACHINE_ID",
    "FLY_APP_NAME",
    "FLY_REGION",
    "FLY_PRIVATE_IP",
    "FLY_PUBLIC_IP",
    "FLY_IMAGE_REF",
    "FLY_ALLOC_ID",
    "FLY_VM_MEMORY_MB",
    "PRIMARY_REGION",
    "JARVIS2_RUNNER",
    "JARVIS2_MACHINE_ID",
];

re!(FLY_VALUE_RE = r"^[A-Za-z0-9:._@/+-]{0,200}$");
re!(B64_KEY_RE = r"^[A-Za-z0-9+/]{60,120}={0,2}$");
re!(SOURCE_RE = r"^source-[0-9a-f]{32}$");
// a GitHub owner/name: an owner never starts with a dot, a name is never . or ..
re!(GH_REPO_RE = r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_.-]{1,100}$");
re!(MODEL_RE = r"^[A-Za-z0-9][A-Za-z0-9._/:\[\]-]{0,99}$");
re!(SHA256_RE = r"^[0-9a-f]{64}$");
re!(MACHINE_ID_RE = r"^[a-z0-9]{1,40}$");
re!(CONTENT_RE = r"^[a-z0-9]([a-z0-9-]{0,40}[a-z0-9])?$");
re!(SESSION_ID_RE = r"^[a-z0-9][a-z0-9-]{0,63}$");
re!(DIGITS_RE = r"^[0-9]{1,32}$");
re!(WORD_RE = r"^[a-z][a-z0-9-]{0,31}$");
re!(TOKEN_RE = r"^[A-Za-z0-9._~+/=-]{1,512}$");

fn env_map(env: &[String]) -> HashMap<String, String> {
    env.iter()
        .filter_map(|kv| {
            kv.split_once('=')
                .map(|(k, v)| (k.to_string(), v.to_string()))
        })
        .collect()
}

/// The env this machine runs with, from the env it was started with: the image's ENV (fixed by the image digest),
/// Fly's values, the core's key (or the kernel's root key, roster and source) and the router's address. Everything
/// else is dropped.
pub fn clean_env(started: &[String], image_env: &[String]) -> Result<Vec<String>> {
    let mut m: BTreeMap<String, String> = BTreeMap::new();
    for kv in image_env {
        if let Some((k, v)) = kv.split_once('=')
            && ENV_NAME_RE.is_match(k)
        {
            m.insert(k.into(), v.into());
        }
    }
    if m.get("PATH").is_none_or(|p| p.is_empty()) {
        m.insert(
            "PATH".into(),
            "/home/claude/.local/bin:/usr/local/bin:/usr/bin:/bin".into(),
        );
    }
    m.insert("HOME".into(), "/home/claude".into());
    m.insert("USER".into(), "claude".into());
    m.insert("LOGNAME".into(), "claude".into());
    m.insert("SHELL".into(), "/bin/bash".into());
    if m.get("LANG").is_none_or(|p| p.is_empty()) {
        m.insert("LANG".into(), "C.UTF-8".into());
    }
    let got = env_map(started);
    for k in FLY_ENV {
        if let Some(v) = got.get(*k)
            && FLY_VALUE_RE.is_match(v)
        {
            m.insert((*k).into(), v.clone());
        }
    }
    let g = |k: &str| got.get(k).cloned().unwrap_or_default();
    let key = g(CORE_KEY_ENV).trim().to_string();
    let root = g(KERNEL_ROOT_ENV).trim().to_string();
    let source = g(KERNEL_SOURCE_ENV).trim().to_string();
    if B64_KEY_RE.is_match(&key) {
        m.insert(CORE_KEY_ENV.into(), key);
    } else if B64_KEY_RE.is_match(&root)
        && serde_json::from_str::<serde_json::Value>(&g(KERNEL_ROSTER_ENV)).is_ok()
        && SOURCE_RE.is_match(&source)
    {
        // kernelboot.rs: the kernel's spawner started it: the root key, its roster and the source, from its Fly config
        // (the roster is checked against the root key at boot)
        m.insert(KERNEL_ROOT_ENV.into(), root);
        m.insert(KERNEL_ROSTER_ENV.into(), g(KERNEL_ROSTER_ENV));
        m.insert(KERNEL_SOURCE_ENV.into(), source);
    } else {
        bail!(
            "no core key ({CORE_KEY_ENV}) or kernel root key, roster and source ({KERNEL_ROOT_ENV}, {KERNEL_ROSTER_ENV}, {KERNEL_SOURCE_ENV}) in the machine's config"
        );
    }
    let u = g("JARVIS2_URL").trim().to_string();
    if crate::routerdial::router_urls_ok(&u) {
        m.insert("JARVIS2_URL".into(), u);
    }
    Ok(m.into_iter().map(|(k, v)| format!("{k}={v}")).collect())
}

pub fn read_image_env() -> Vec<String> {
    std::fs::read_to_string(IMAGE_ENV_FILE)
        .map(|s| s.lines().map(String::from).collect())
        .unwrap_or_default()
}

/// boot's first step. When the env isn't already the clean one, re-exec with it
pub fn ensure_clean_env() -> Result<()> {
    let cur_env: Vec<String> = crate::env::vars().into_iter().map(|(k, v)| format!("{k}={v}")).collect();
    let clean = clean_env(&cur_env, &read_image_env())?;
    let mut cur = cur_env.clone();
    cur.sort();
    if cur == clean {
        return Ok(());
    }
    let keep: std::collections::HashSet<&str> =
        clean.iter().map(|kv| crate::util::cut(kv, "=").0).collect();
    let dropped: Vec<&str> = cur
        .iter()
        .map(|kv| crate::util::cut(kv, "=").0)
        .filter(|k| !keep.contains(k))
        .collect();
    if !dropped.is_empty() {
        logf!(
            "env: dropping what the core didn't set: {}",
            dropped.join(" ")
        );
    }
    use std::os::unix::process::CommandExt;
    let args: Vec<String> = std::env::args().skip(1).collect();
    let err = std::process::Command::new("/proc/self/exe")
        .args(args)
        .env_clear()
        .envs(clean.iter().filter_map(|kv| kv.split_once('=')))
        .exec();
    Err(anyhow!("re-exec with the clean env: {err}"))
}

// ---- the settings the cert vouches for --------------------------------------------------------------------------

/// Options.Config (router/vouch.go builds it, the app's shell shows and checks it before Face ID)
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct SessionConfig {
    pub v: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub label: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub prompt: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub model: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repos: Option<Vec<String>>,
    /// content stores: content-sync pulls each into ~/content/<name>/ through the router
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub content: Vec<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub one_shot: bool,
    #[serde(rename = "apiProxy", skip_serializing_if = "std::ops::Not::not")]
    pub api_proxy: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<AttachmentRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub restore: Option<RestoreRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task: Option<TaskConfig>,
    /// the session's Claude account, signed for the phone to show; the login itself comes from the router
    #[serde(skip_serializing_if = "String::is_empty")]
    pub claude_account: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AttachmentRef {
    pub name: String,
    pub sha256: String,
    pub size: i64,
}

/// the archived snapshot a new line starts from: the old line's machine and the snapshot's hash
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RestoreRef {
    pub machine: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TaskConfig {
    pub instance: String,
    pub name: String,
    pub params: Option<serde_json::Map<String, serde_json::Value>>,
}

/// Options.Once: this machine's one-time inputs (approved on the phone, never carried over)
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OnceInputs {
    /// a resume's prompt: typed into the resumed conversation
    #[serde(skip_serializing_if = "String::is_empty")]
    pub prompt: String,
    /// drop every transcript line from the first containing it
    #[serde(skip_serializing_if = "String::is_empty")]
    pub rollback: String,
}

/// what this machine may use, each piece with its voucher
#[derive(Debug, Clone, Default)]
pub struct Vouched {
    pub cert: Cert,
    pub config: SessionConfig,
    pub once: OnceInputs,
    pub ex: FormatExceptions,
}

/// strict: an unknown field refuses it (Go's Decoder with DisallowUnknownFields; a null is the zero value)
fn strict<T: serde::de::DeserializeOwned>(s: &str) -> Result<T, serde_json::Error> {
    gojson::unmarshal(s.as_bytes())
}

/// The cert's settings, strictly read. A field the machine doesn't know refuses the whole config (the phone showed it;
/// this machine must not silently skip what Deyao approved).
pub fn vouch(cert: &Cert) -> Result<Vouched> {
    let mut v = Vouched {
        cert: cert.clone(),
        ..Default::default()
    };
    let s = &cert.options.config;
    if !s.is_empty() {
        v.config = strict(s).map_err(|e| anyhow!("the cert's config: {e}"))?;
        let c = &v.config;
        if !c.model.is_empty() && !MODEL_RE.is_match(&c.model) {
            bail!("the cert's model {:?}", c.model);
        }
        for r in c.repos.iter().flatten() {
            let rp = repo_of_url(r);
            if !GH_REPO_RE.is_match(&rp)
                || rp.ends_with("/.")
                || rp.ends_with("/..")
                || !crate::deploykeys::valid_repo(&rp)
            {
                bail!("the cert's repo {r:?} isn't a GitHub repo");
            }
        }
        for n in &c.content {
            if !CONTENT_RE.is_match(n) {
                bail!("the cert's content store {n:?}");
            }
        }
        for a in &c.attachments {
            if !crate::attachments::plain_name(&a.name)
                || !SHA256_RE.is_match(&a.sha256)
                || a.size < 0
            {
                bail!("the cert's attachment {:?}", a.name);
            }
        }
        if let Some(r) = &c.restore
            && (!MACHINE_ID_RE.is_match(&r.machine) || !SHA256_RE.is_match(&r.sha256))
        {
            bail!("the cert's restore");
        }
        if let Some(t) = &c.task
            && !TASK_TEMPLATE_RE.is_match(&t.instance)
            && !t.instance.is_empty()
        {
            bail!("the cert's task instance");
        }
    }
    let s = &cert.options.once;
    if !s.is_empty() {
        v.once = strict(s).map_err(|e| anyhow!("the cert's one-time inputs: {e}"))?;
        if !v.once.rollback.is_empty() && v.once.rollback.len() < 4 {
            bail!("the cert's rollback marker is too short");
        }
    }
    Ok(v)
}

/// owner/name of a GitHub https or ssh URL ("" otherwise)
pub fn repo_of_url(u: &str) -> String {
    let u = u.trim();
    for p in [
        "https://github.com/",
        "git@github.com:",
        "ssh://git@github.com/",
    ] {
        if let Some(rest) = u.strip_prefix(p) {
            let rest = rest.strip_suffix('/').unwrap_or(rest);
            return rest.strip_suffix(".git").unwrap_or(rest).to_string();
        }
    }
    String::new()
}

/// The cert's repos, or, from a cert that names none, each repo whose deploy-key store the cert gives this machine
/// (the store names the repo; the core wrote it). Never the router's list.
pub fn repos_to_clone(v: &Vouched, secrets: &HashMap<String, String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out = vec![];
    let mut add = |repo: &str| {
        if GH_REPO_RE.is_match(repo)
            && crate::deploykeys::valid_repo(repo)
            && seen.insert(repo.to_lowercase())
        {
            out.push(format!("https://github.com/{repo}.git"));
        }
    };
    if let Some(repos) = &v.config.repos {
        for r in repos {
            add(&repo_of_url(r));
        }
        return out;
    }
    for k in crate::deploykeys::deploy_keys(secrets) {
        add(&k.repo);
    }
    out
}

// ---- values the router may give on its own (their format can't carry an instruction) ---------------------------

/// GET /m/config. Every one is listed in docs/DESIGN.md "Inputs to a machine".
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct FormatExceptions {
    /// the router's id for the session: s + hex
    pub session_id: String,
    /// a Discord channel id: digits
    pub discord_channel: String,
    /// how often the transcripts go to the search index
    pub live_sync_seconds: i64,
    /// the run a task line's machine is started for: an id
    pub task_run: String,
    /// what started it: a word
    pub task_trigger: String,
    /// the router's proof for the cf-tunnel Worker: a token
    pub tunnel_proof: String,
}

/// each value in its format, or dropped
pub fn check_exceptions(i: &FormatExceptions) -> FormatExceptions {
    let keep = |ok: bool, s: &str| if ok { s.to_string() } else { String::new() };
    FormatExceptions {
        session_id: keep(SESSION_ID_RE.is_match(&i.session_id), &i.session_id),
        discord_channel: keep(DIGITS_RE.is_match(&i.discord_channel), &i.discord_channel),
        live_sync_seconds: if (5..=86400).contains(&i.live_sync_seconds) {
            i.live_sync_seconds
        } else {
            0
        },
        task_run: keep(SESSION_ID_RE.is_match(&i.task_run), &i.task_run),
        task_trigger: keep(WORD_RE.is_match(&i.task_trigger), &i.task_trigger),
        tunnel_proof: keep(TOKEN_RE.is_match(&i.tunnel_proof), &i.tunnel_proof),
    }
}

pub fn fetch_exceptions(c: &Client) -> FormatExceptions {
    let mut ex = match c.json::<(), FormatExceptions>("GET", "/m/config", None) {
        Ok(e) => e,
        Err(e) => {
            logf!("config: none from the router ({e:#})");
            FormatExceptions::default()
        }
    };
    if ex.tunnel_proof.is_empty() {
        ex.tunnel_proof = tunnel_proof(c);
    }
    check_exceptions(&ex)
}

/// The tunnel proof (router/remote.go): the router's proof for the session id, which the cf-tunnel Worker asks of an
/// agent that registers it; fetched at boot over the signed /m channel. None = no TUNNEL_AGENT_SECRET.
pub fn tunnel_proof(c: &Client) -> String {
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct P {
        proof: String,
    }
    match c.json::<(), P>("GET", "/m/tunnel-proof", None) {
        Ok(p) => p.proof,
        Err(e) => {
            logf!("tunnel proof: none ({e:#})");
            String::new()
        }
    }
}

// ---- the harness's env, built from vouched values only ---------------------------------------------------------

/// The clean env plus exactly what the cert, the secrets and the format exceptions give. first_machine: the first
/// machine of a new line (the first prompt and its attachments are its alone).
pub fn harness_env(
    clean: &[String],
    v: &Vouched,
    me: &str,
    first_machine: bool,
    secrets: &HashMap<String, String>,
) -> Vec<String> {
    HarnessSpec {
        clean: clean.to_vec(),
        fixed: harness_fixed(v, me, first_machine),
        fallback: BTreeMap::new(),
    }
    .env(secrets)
}

/// The harness's env without any secret value, as boot hands it to the keeper (keeper.rs), which adds the secrets the
/// supervisor holds at each start of the harness: the clean env, then the secrets over it, then Fallback where
/// neither set the key, then Fixed over everything.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct HarnessSpec {
    pub clean: Vec<String>,
    pub fixed: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub fallback: BTreeMap<String, String>,
}

impl HarnessSpec {
    pub fn env(&self, secrets: &HashMap<String, String>) -> Vec<String> {
        let mut m: BTreeMap<String, String> = BTreeMap::new();
        for kv in &self.clean {
            if let Some((k, v)) = kv.split_once('=') {
                m.insert(k.into(), v.into());
            }
        }
        for (k, v) in secrets {
            if ENV_NAME_RE.is_match(k) {
                m.insert(k.clone(), v.clone());
            }
        }
        for (k, v) in &self.fallback {
            m.entry(k.clone()).or_insert_with(|| v.clone());
        }
        for (k, v) in &self.fixed {
            m.insert(k.clone(), v.clone());
        }
        m.into_iter().map(|(k, v)| format!("{k}={v}")).collect()
    }
}

/// what the cert and the format exceptions set in the harness's env (over the clean env and the secrets)
pub fn harness_fixed(v: &Vouched, me: &str, first_machine: bool) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    let mut put = |k: &str, val: &str| {
        m.insert(k.to_string(), val.to_string());
    };
    let sid = if v.ex.session_id.is_empty() {
        me
    } else {
        &v.ex.session_id
    };
    put("SESSION_HARNESS", &v.cert.options.harness);
    put("SESSION_PERMISSION_MODE", cert_mode(&v.cert));
    put("SESSION_ID", sid);
    put("JARVIS2_SESSION_ID", sid);
    put("TUNNEL_ID", sid);
    put("JARVIS_URL", &format!("http://{API_PROXY_ADDR}"));
    put("SESSION_API_TOKEN", "jarvis2-local-proxy");
    if !via_harness_send(&v.cert.options.harness) {
        // Jarvis 1's scripts insist on these before calling the local API; the Paseo and OpenClaw harnesses take them
        // as "publish the web UI through the tunnel"
        put("CF_ACCESS_CLIENT_ID", "jarvis2-local-proxy");
        put("CF_ACCESS_CLIENT_SECRET", "jarvis2-local-proxy");
    }
    if !v.ex.discord_channel.is_empty() {
        put("LOBSTER_CHANNEL", &v.ex.discord_channel);
    }
    if !v.ex.tunnel_proof.is_empty() {
        put("TUNNEL_AGENT_SECRET", &v.ex.tunnel_proof);
    }
    let c = &v.config;
    if !c.label.is_empty() {
        put("SESSION_LABEL", &c.label);
    }
    if !c.model.is_empty() {
        put("SESSION_MODEL", &c.model);
    }
    if c.one_shot {
        put("SESSION_ONE_SHOT", "1");
    }
    if c.api_proxy {
        put("SESSION_API_PROXY", "1");
    }
    if !c.content.is_empty() {
        // Jarvis 1's entrypoint runs `content-sync pull` at every boot; content-sync talks to $JARVIS_URL
        put("SESSION_CONTENT", &c.content.join(","));
    }
    if first_machine && !c.prompt.is_empty() {
        put("SESSION_PROMPT", &c.prompt);
    } else if !first_machine && !v.once.prompt.is_empty() {
        put("SESSION_PROMPT", &v.once.prompt);
    }
    m
}

/// vouched.json: what the supervisor process (started before the cert is read) needs of the vouched values
pub fn write_vouched(v: &Vouched) {
    let b = serde_json::json!({"liveSyncSeconds": v.ex.live_sync_seconds, "sessionId": v.ex.session_id, "oneShot": v.config.one_shot});
    let _ = crate::util::write_file(
        &paths::vouched_path(),
        gojson::marshal(&b).as_bytes(),
        0o644,
    );
}

fn read_vouched() -> serde_json::Map<String, serde_json::Value> {
    std::fs::read(paths::vouched_path())
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

/// the router's id for this session (a format exception), else the machine id
pub fn session_id(me: &str) -> String {
    match read_vouched().get("sessionId").and_then(|v| v.as_str()) {
        Some(s) if SESSION_ID_RE.is_match(s) => s.to_string(),
        _ => me.to_string(),
    }
}

pub fn read_vouched_bool(k: &str) -> bool {
    read_vouched()
        .get(k)
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

pub fn read_vouched_int(k: &str) -> i64 {
    read_vouched()
        .get(k)
        .and_then(|v| v.as_f64())
        .map(|f| f as i64)
        .unwrap_or(0)
}

/// a task line's values for task.rs (which reads TASK_* / PARAM_* from the process env): the instance and its
/// parameters from the cert, the run id and trigger as format exceptions
pub fn task_vouched_env(v: &Vouched) -> Vec<String> {
    let sid = if v.ex.session_id.is_empty() {
        v.cert.machine().id
    } else {
        v.ex.session_id.clone()
    };
    let mut out = vec![
        format!("SESSION_ID={sid}"),
        format!("JARVIS2_SESSION_ID={sid}"),
        format!("JARVIS_URL=http://{API_PROXY_ADDR}"),
        "SESSION_API_TOKEN=jarvis2-local-proxy".to_string(),
    ];
    if !v.ex.discord_channel.is_empty() {
        out.push(format!("LOBSTER_CHANNEL={}", v.ex.discord_channel));
    }
    if !v.ex.task_run.is_empty() {
        out.push(format!("JARVIS2_TASK_RUN={}", v.ex.task_run));
        out.push(format!("TASK_RUN={}", v.ex.task_run));
        out.push(format!("TASK_TRIGGER={}", v.ex.task_trigger));
    }
    let Some(t) = &v.config.task else {
        out.push("TASK_PARAMS={}".into());
        return out;
    };
    let pj = match &t.params {
        Some(p) => gojson::marshal(p),
        None => "null".into(),
    };
    out.push(format!("TASK_INSTANCE={}", t.instance));
    out.push(format!("TASK_NAME={}", t.name));
    out.push(format!("TASK_PARAMS={pj}"));
    for (k, val) in t.params.iter().flatten() {
        let name = format!("PARAM_{}", k.to_uppercase());
        if ENV_NAME_RE.is_match(&name) {
            out.push(format!("{name}={}", param_value(val)));
        }
    }
    out
}

/// router/tasks.go paramEnv
pub fn param_value(v: &serde_json::Value) -> String {
    use serde_json::Value;
    match v {
        Value::Null => String::new(),
        Value::Array(a) => a
            .iter()
            .map(crate::util::go_sprint)
            .collect::<Vec<_>>()
            .join(","),
        Value::Number(n) => crate::util::go_float_f(n.as_f64().unwrap_or(0.0)),
        Value::Bool(b) => b.to_string(),
        Value::String(s) => s.clone(),
        Value::Object(_) => gojson::marshal(v),
    }
}
