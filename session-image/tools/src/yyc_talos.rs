//! yyc-talos: YYC's Talos cluster yyc-talos from a session (DE0CH/yyc-code news-stream/deploy/clusters/talos, README
//! "Operator access" and "Node work"). The cluster's facts (roles and their patches, the jump host, the forwards, the
//! add-ons and their versions, the tools' pins) are that folder's `yyc-talos.toml`; the Talos release is its
//! `release.env`. This is the mechanism only.
//!
//!   yyc-talos tunnel                    the control nodes' APIs on 127.0.0.1 through the jump host, from nothing: the tools,
//!                                       the jump host's key, then ~/talos/talosconfig and ~/talos/kubeconfig once it is
//!                                       up; stays in the foreground as the tunnel (run it as a background job)
//!   yyc-talos talosconfig               write ~/talos/talosconfig for the tunnel's endpoints
//!   yyc-talos kubeconfig                write ~/talos/kubeconfig (admin, server through the tunnel)
//!   yyc-talos gen NODE ROLE             render ~/talos/NODE.yaml (never committed), validated for the cloud
//!   yyc-talos apply NODE IP [--dry-run] apply ~/talos/NODE.yaml to the running node IP (mode auto)
//!   yyc-talos addons                    install or upgrade the Helm add-ons (KUBECONFIG, default ~/talos/kubeconfig)
//!   yyc-talos manifests                 kubectl apply -k of the folder
//!   yyc-talos tool NAME                 the path of the pinned talosctl, kubectl, helm, cloudflared or hcloud (fetched on first use)
//!   yyc-talos resize-db NODE TYPE       change a database node's Hetzner server type in place with no downtime: refused on
//!                                       a Postgres primary's node (db/switchover.py first); the other copies keep serving
//!
//! The folder: the yyc-code checkout around the working directory, else ~/src/yyc-code (cloned when missing). Out:
//! `$TALOS_OUT`, default ~/talos (mode 700; every file in it 600). Secrets come one at a time from `session-secret`, are
//! written only into the out folder or handed to a child's environment, and never printed. kubectl, helm and cloudflared
//! are fetched on first use at the toml's pinned versions and sums into ~/.cache/yyc-talos; talosctl at release.env's
//! version, checked against that release's sha256sum.txt.

use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

/// The folder's place in a yyc-code checkout
pub const FOLDER: &str = "news-stream/deploy/clusters/talos";
const REPO: &str = "https://github.com/DE0CH/yyc-code.git";

const USAGE: &str = "usage: yyc-talos tunnel | talosconfig | kubeconfig | gen NODE ROLE | apply NODE IP [--dry-run] | addons | manifests | tool talosctl|kubectl|helm|cloudflared|hcloud | resize-db NODE TYPE";

#[derive(Debug, Deserialize)]
pub struct Config {
    pub cluster: String,
    pub endpoint: String,
    pub secrets: Secrets,
    pub tunnel: Tunnel,
    pub r#gen: Gen,
    pub roles: BTreeMap<String, Role>,
    pub addons: Addons,
    pub tools: BTreeMap<String, Tool>,
    pub resize_db: ResizeDb,
}

#[derive(Debug, Deserialize)]
pub struct Secrets {
    pub talos: String,
    pub warp_prefix: String,
    pub ssh_key: String,
    pub access_id: String,
    pub access_secret: String,
    /// the Hetzner project's API token (hcloud's HCLOUD_TOKEN when that is not set)
    pub hetzner: String,
}

#[derive(Debug, Deserialize)]
pub struct ResizeDb {
    pub namespace: String,
    /// the CloudNativePG clusters whose primary must not be on the node
    pub primaries: Vec<String>,
    /// the cluster whose copies are counted and waited for
    pub copies: String,
    /// how far a standby may be behind to count as caught up
    pub max_lag_bytes: i64,
}

#[derive(Debug, Deserialize)]
pub struct Tunnel {
    pub host: String,
    pub access_hostname: String,
    /// the jump host's public host key (`ssh-ed25519 AAAA…`): checked strictly
    pub host_key: String,
    pub forwards: Vec<String>,
    pub talos_endpoints: Vec<String>,
    pub kubeconfig_node: String,
    pub kube_server: String,
}

#[derive(Debug, Deserialize)]
pub struct Gen {
    pub common: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct Role {
    pub output: String,
    pub patches: Vec<String>,
    pub warp: bool,
}

#[derive(Debug, Deserialize)]
pub struct Addons {
    pub before: Vec<String>,
    pub repos: Vec<Repo>,
    pub charts: Vec<Chart>,
}

#[derive(Debug, Deserialize)]
pub struct Repo {
    pub name: String,
    pub url: String,
}

#[derive(Debug, Deserialize)]
pub struct Chart {
    pub release: String,
    pub chart: String,
    pub version: String,
    pub namespace: String,
    pub values: String,
}

#[derive(Debug, Deserialize)]
pub struct Tool {
    pub version: String,
    pub url: String,
    pub sha256: String,
    /// the binary's path inside a .tar.gz download
    pub member: Option<String>,
}

#[derive(Debug, PartialEq)]
pub struct Release {
    pub version: String,
    pub installer: String,
}

pub fn parse_config(text: &str) -> Result<Config, String> {
    let c: Config = toml::from_str(text).map_err(|e| format!("yyc-talos.toml: {e}"))?;
    for t in ["kubectl", "helm", "cloudflared", "hcloud"] {
        if !c.tools.contains_key(t) {
            return Err(format!("yyc-talos.toml: no [tools.{t}]"));
        }
    }
    Ok(c)
}

/// release.env: `KEY=VALUE` lines (comments and blank lines skipped), TALOS_VERSION and TALOS_INSTALLER
pub fn parse_release(text: &str) -> Result<Release, String> {
    let mut kv = BTreeMap::new();
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (k, v) = line
            .split_once('=')
            .ok_or_else(|| format!("release.env: not KEY=VALUE: {line}"))?;
        kv.insert(k.trim(), v.trim().trim_matches('"'));
    }
    let get = |k: &str| {
        kv.get(k)
            .filter(|v| !v.is_empty())
            .map(|v| v.to_string())
            .ok_or_else(|| format!("release.env: no {k}"))
    };
    Ok(Release {
        version: get("TALOS_VERSION")?,
        installer: get("TALOS_INSTALLER")?,
    })
}

/// The store key of a node's WARP registration: the prefix + the name after `yyc-talos-`, upper case, `-` as `_`
pub fn warp_key(prefix: &str, node: &str) -> String {
    let suffix = node.strip_prefix("yyc-talos-").unwrap_or(node);
    format!("{prefix}{}", suffix.to_uppercase().replace('-', "_"))
}

/// The node's warp0 patch from its WARP registration (warp-register.py's JSON: privateKey, address, peerPublicKey,
/// endpoint)
pub fn warp_patch(registration: &str) -> Result<String, String> {
    let w: serde_json::Value = serde_json::from_str(registration)
        .map_err(|e| format!("the WARP registration is not JSON: {e}"))?;
    let field = |k: &str| {
        w.get(k)
            .and_then(|v| v.as_str())
            .filter(|v| !v.is_empty())
            .ok_or_else(|| format!("the WARP registration has no {k}"))
    };
    let address = field("address")?.split('/').next().unwrap_or_default();
    Ok(format!(
        r#"apiVersion: v1alpha1
kind: WireguardConfig
name: warp0                     # Cloudflare WARP: outgoing IPv4 (DESIGN 15.2.1 I6: never wg0, never udp 51821)
mtu: 1280
privateKey: {}
addresses:                      # WARP's /12, so its 172.16.0.1 is a gateway in the link's subnet
  - address: {address}/12
routes:                         # the IPv4 default route (Talos takes no 0.0.0.0/0 destination)
  - gateway: 172.16.0.1
peers:
  - publicKey: {}
    endpoint: "{}"
    allowedIPs: [0.0.0.0/0]
    persistentKeepaliveInterval: 25s
"#,
        field("privateKey")?,
        field("peerPublicKey")?,
        field("endpoint")?
    ))
}

/// `talosctl gen config …` for NODE in ROLE, and whether the role needs the node's WARP patch (then at `warp_patch`)
pub fn gen_args(
    c: &Config,
    rel: &Release,
    dir: &Path,
    out: &Path,
    node: &str,
    role: &str,
) -> Result<(Vec<String>, bool), String> {
    let r = c.roles.get(role).ok_or_else(|| {
        format!(
            "role: {}",
            c.roles.keys().cloned().collect::<Vec<_>>().join("|")
        )
    })?;
    let p = |x: &Path| x.display().to_string();
    let mut a: Vec<String> = [
        "gen",
        "config",
        &c.cluster,
        &c.endpoint,
        "--with-secrets",
        &p(&out.join("secrets.yaml")),
        "--talos-version",
        &rel.version,
        "--install-image",
        &format!("{}:{}", rel.installer, rel.version),
    ]
    .map(String::from)
    .into();
    for f in c.r#gen.common.iter().chain(&r.patches) {
        a.push("--config-patch".into());
        a.push(format!("@{}", p(&dir.join(f))));
    }
    if r.warp {
        a.push("--config-patch".into());
        a.push(format!("@{}", p(&out.join(format!("{node}.patch.yaml")))));
    }
    a.extend(
        [
            "--output-types",
            &r.output,
            "--output",
            &p(&out.join(format!("{node}.yaml"))),
            "--force",
        ]
        .map(String::from),
    );
    Ok((a, r.warp))
}

/// ssh's arguments for the tunnel: key, the pinned host key, the forwards, Access as the ProxyCommand
pub fn ssh_args(c: &Config, key: &Path, known_hosts: &Path, proxy: &str) -> Vec<String> {
    let mut a: Vec<String> = vec![
        "-N".into(),
        "-i".into(),
        key.display().to_string(),
        "-o".into(),
        "IdentitiesOnly=yes".into(),
        "-o".into(),
        format!("UserKnownHostsFile={}", known_hosts.display()),
        "-o".into(),
        "StrictHostKeyChecking=yes".into(),
        "-o".into(),
        "ExitOnForwardFailure=yes".into(),
        "-o".into(),
        "ServerAliveInterval=20".into(),
        "-o".into(),
        format!("ProxyCommand={proxy}"),
    ];
    for f in &c.tunnel.forwards {
        a.push("-L".into());
        a.push(f.clone());
    }
    a.push(c.tunnel.host.clone());
    a
}

/// known_hosts for the jump host: its address (the part of `host` after `@`) and the pinned key
pub fn known_hosts(c: &Config) -> String {
    let host = c.tunnel.host.rsplit('@').next().unwrap_or_default();
    format!("{host} {}\n", c.tunnel.host_key.trim())
}

/// The local port of the first forward (the tunnel is up once it accepts)
pub fn first_port(c: &Config) -> Result<u16, String> {
    c.tunnel
        .forwards
        .first()
        .and_then(|f| f.split(':').next())
        .and_then(|p| p.parse().ok())
        .ok_or_else(|| "yyc-talos.toml: no forwards".into())
}

/// The kubeconfig with every cluster's server through the tunnel
pub fn kubeconfig_through(text: &str, server: &str) -> String {
    text.lines()
        .map(|l| match l.find("server: ") {
            Some(i) if l.trim_start().starts_with("server: ") => {
                format!("{}server: {server}", &l[..i])
            }
            _ => l.to_string(),
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

/// `helm upgrade --install …` for each chart, in order
pub fn helm_installs(c: &Config, dir: &Path) -> Vec<Vec<String>> {
    c.addons
        .charts
        .iter()
        .map(|ch| {
            [
                "upgrade",
                "--install",
                &ch.release,
                &ch.chart,
                "--version",
                &ch.version,
                "-n",
                &ch.namespace,
                "--create-namespace",
                "-f",
                &dir.join("addons")
                    .join(format!("{}.values.yaml", ch.values))
                    .display()
                    .to_string(),
                "--wait",
                "--timeout",
                "10m",
            ]
            .map(String::from)
            .into()
        })
        .collect()
}

/// A tool's download URL (`{version}` filled in)
pub fn tool_url(t: &Tool) -> String {
    t.url.replace("{version}", &t.version)
}

/// The sum of `name` in a sha256sum listing
pub fn sum_of(listing: &str, name: &str) -> Option<String> {
    listing.lines().find_map(|l| {
        let mut it = l.split_whitespace();
        let (sum, file) = (it.next()?, it.next()?);
        (file.trim_start_matches('*') == name && sum.len() == 64).then(|| sum.to_string())
    })
}

/// A database pod: its name, its node (none while unscheduled), whether its first container is ready
#[derive(Debug, PartialEq)]
pub struct Pod {
    pub name: String,
    pub node: Option<String>,
    pub ready: bool,
}

/// `kubectl get pods -o json`'s items
pub fn parse_pods(json: &str) -> Result<Vec<Pod>, String> {
    let v: serde_json::Value =
        serde_json::from_str(json).map_err(|e| format!("kubectl's pod list: {e}"))?;
    Ok(v["items"]
        .as_array()
        .map(|a| a.as_slice())
        .unwrap_or_default()
        .iter()
        .map(|p| Pod {
            name: p["metadata"]["name"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            node: p["spec"]["nodeName"]
                .as_str()
                .filter(|n| !n.is_empty())
                .map(String::from),
            ready: p["status"]["containerStatuses"][0]["ready"]
                .as_bool()
                .unwrap_or(false),
        })
        .collect())
}

/// The node's own copy: the pod on it, or one waiting unscheduled for the room the resize makes
pub fn pick_copy(pods: &[Pod], node: &str) -> Option<String> {
    pods.iter()
        .find(|p| p.node.as_deref() == Some(node))
        .or_else(|| pods.iter().find(|p| p.node.is_none()))
        .map(|p| p.name.clone())
}

/// Every copy but the node's own, on the other nodes, ready
pub fn others_ready(pods: &[Pod], node: &str, copy: &str) -> bool {
    pods.iter()
        .filter(|p| p.name != copy && p.node.as_deref() != Some(node))
        .all(|p| p.ready)
}

/// All copies ready, and every standby streaming within `max_lag` bytes of the primary (`lag`: psql's
/// `max lag bytes|streaming standbys`)
pub fn caught_up(want: u32, ready: u32, lag: &str, max_lag: i64) -> bool {
    let Some((bytes, n)) = lag.trim().split_once('|') else {
        return false;
    };
    match (bytes.parse::<i64>(), n.parse::<u32>()) {
        (Ok(b), Ok(n)) => ready == want && want > 0 && n == want - 1 && b < max_lag,
        _ => false,
    }
}

// ---- effects ----

struct Ctx {
    dir: PathBuf,
    out: PathBuf,
    cfg: Config,
    rel: Release,
}

fn home() -> PathBuf {
    PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/root".into()))
}

/// The talos folder: around the working directory, else ~/src/yyc-code's (cloned when missing)
fn find_dir() -> Result<PathBuf, String> {
    if let Ok(cwd) = std::env::current_dir() {
        for d in cwd.ancestors() {
            if d.join(FOLDER).join("yyc-talos.toml").is_file() {
                return Ok(d.join(FOLDER));
            }
            if d.join("yyc-talos.toml").is_file() && d.ends_with(FOLDER) {
                return Ok(d.to_path_buf());
            }
        }
    }
    let repo = home().join("src/yyc-code");
    if !repo.join(FOLDER).join("yyc-talos.toml").is_file() {
        if repo.exists() {
            return Err(format!(
                "{} has no {FOLDER}/yyc-talos.toml: pull it, or run yyc-talos from inside a yyc-code checkout",
                repo.display()
            ));
        }
        eprintln!("yyc-talos: cloning {REPO} into {}", repo.display());
        fs::create_dir_all(home().join("src")).map_err(|e| e.to_string())?;
        run(Command::new("git")
            .args(["clone", "-q", "--depth", "1", REPO])
            .arg(&repo))?;
    }
    Ok(repo.join(FOLDER))
}

fn ctx() -> Result<Ctx, String> {
    let dir = find_dir()?;
    let read = |f: &str| {
        fs::read_to_string(dir.join(f)).map_err(|e| format!("{}: {e}", dir.join(f).display()))
    };
    let cfg = parse_config(&read("yyc-talos.toml")?)?;
    let rel = parse_release(&read("release.env")?)?;
    let out = std::env::var("TALOS_OUT")
        .ok()
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| home().join("talos"));
    fs::create_dir_all(&out).map_err(|e| format!("{}: {e}", out.display()))?;
    fs::set_permissions(&out, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    Ok(Ctx { dir, out, cfg, rel })
}

fn run(cmd: &mut Command) -> Result<(), String> {
    let name = cmd.get_program().to_string_lossy().to_string();
    let st = cmd.status().map_err(|e| format!("{name}: {e}"))?;
    if st.success() {
        Ok(())
    } else {
        Err(format!("{name} failed ({st})"))
    }
}

/// One secret's value, from session-secret (never printed)
fn secret(key: &str) -> Result<Vec<u8>, String> {
    let o = Command::new("session-secret")
        .args(["--keys", key, "--exec", "printenv", key])
        .stderr(Stdio::inherit())
        .output()
        .map_err(|e| format!("session-secret: {e}"))?;
    let mut v = o.stdout;
    if v.last() == Some(&b'\n') {
        v.pop();
    }
    if !o.status.success() || v.is_empty() {
        return Err(format!(
            "no value for {key} (is its store in this session?)"
        ));
    }
    Ok(v)
}

fn write_private(path: &Path, data: &[u8]) -> Result<(), String> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    f.write_all(data)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())
}

/// A secret into the out folder, once
fn secret_file(path: &Path, key: &str, trailing_newline: bool) -> Result<(), String> {
    if fs::metadata(path).map(|m| m.len() > 0).unwrap_or(false) {
        return Ok(());
    }
    let mut v = secret(key)?;
    if trailing_newline {
        v.push(b'\n');
    }
    write_private(path, &v)
}

fn sha256(path: &Path) -> Result<String, String> {
    let o = Command::new("sha256sum")
        .arg(path)
        .output()
        .map_err(|e| format!("sha256sum: {e}"))?;
    String::from_utf8_lossy(&o.stdout)
        .split_whitespace()
        .next()
        .map(String::from)
        .ok_or_else(|| "sha256sum printed nothing".into())
}

/// A binary in ~/.cache/yyc-talos, fetched and checked once
fn fetch(
    name: &str,
    version: &str,
    url: &str,
    sum: &str,
    member: Option<&str>,
) -> Result<PathBuf, String> {
    let cache = home().join(".cache/yyc-talos");
    let bin = cache.join(format!("{name}-{version}"));
    if bin.is_file() {
        return Ok(bin);
    }
    fs::create_dir_all(&cache).map_err(|e| e.to_string())?;
    let tmp = cache.join(format!(".{name}-{version}.download"));
    eprintln!("yyc-talos: fetching {name} {version}");
    run(Command::new("curl")
        .args(["-fsSL", "--retry", "5", "-o"])
        .arg(&tmp)
        .arg(url))?;
    let got = sha256(&tmp)?;
    if got != sum {
        let _ = fs::remove_file(&tmp);
        return Err(format!("{url}: sha256 {got}, expected {sum}"));
    }
    let staged = cache.join(format!(".{name}-{version}.bin"));
    match member {
        Some(m) => {
            let o = Command::new("tar")
                .arg("-xzOf")
                .arg(&tmp)
                .arg(m)
                .output()
                .map_err(|e| format!("tar: {e}"))?;
            if !o.status.success() || o.stdout.is_empty() {
                return Err(format!("{url} has no {m}"));
            }
            fs::write(&staged, o.stdout).map_err(|e| e.to_string())?;
            let _ = fs::remove_file(&tmp);
        }
        None => fs::rename(&tmp, &staged).map_err(|e| e.to_string())?,
    }
    fs::set_permissions(&staged, fs::Permissions::from_mode(0o755)).map_err(|e| e.to_string())?;
    fs::rename(&staged, &bin).map_err(|e| e.to_string())?;
    Ok(bin)
}

fn tool(c: &Ctx, name: &str) -> Result<PathBuf, String> {
    let t = &c.cfg.tools[name];
    fetch(
        name,
        &t.version,
        &tool_url(t),
        &t.sha256,
        t.member.as_deref(),
    )
}

fn talosctl(c: &Ctx) -> Result<PathBuf, String> {
    let v = &c.rel.version;
    let bin = home().join(format!(".cache/yyc-talos/talosctl-{v}"));
    if bin.is_file() {
        return Ok(bin);
    }
    let base = format!("https://github.com/siderolabs/talos/releases/download/{v}");
    let o = Command::new("curl")
        .args(["-fsSL", "--retry", "5"])
        .arg(format!("{base}/sha256sum.txt"))
        .output()
        .map_err(|e| format!("curl: {e}"))?;
    let sum = sum_of(&String::from_utf8_lossy(&o.stdout), "talosctl-linux-amd64")
        .ok_or_else(|| format!("{base}/sha256sum.txt names no talosctl-linux-amd64"))?;
    fetch(
        "talosctl",
        v,
        &format!("{base}/talosctl-linux-amd64"),
        &sum,
        None,
    )
}

fn secrets_yaml(c: &Ctx) -> Result<PathBuf, String> {
    let p = c.out.join("secrets.yaml");
    secret_file(&p, &c.cfg.secrets.talos, false)?;
    Ok(p)
}

fn talosconfig(c: &Ctx) -> Result<PathBuf, String> {
    let t = talosctl(c)?;
    secrets_yaml(c)?;
    let f = c.out.join("talosconfig");
    run(Command::new(&t)
        .args([
            "gen",
            "config",
            &c.cfg.cluster,
            &c.cfg.endpoint,
            "--with-secrets",
        ])
        .arg(c.out.join("secrets.yaml"))
        .args(["--output-types", "talosconfig", "--output"])
        .arg(&f)
        .arg("--force")
        .stdout(Stdio::null()))?;
    run(Command::new(&t)
        .arg("--talosconfig")
        .arg(&f)
        .args(["config", "endpoint"])
        .args(&c.cfg.tunnel.talos_endpoints))?;
    fs::set_permissions(&f, fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
    Ok(f)
}

fn kubeconfig(c: &Ctx) -> Result<PathBuf, String> {
    let t = talosctl(c)?;
    let tc = c.out.join("talosconfig");
    if !tc.is_file() {
        talosconfig(c)?;
    }
    let f = c.out.join("kubeconfig");
    run(Command::new(&t)
        .arg("--talosconfig")
        .arg(&tc)
        .args([
            "-n",
            &c.cfg.tunnel.kubeconfig_node,
            "-e",
            &c.cfg.tunnel.talos_endpoints[0],
            "kubeconfig",
        ])
        .arg(&f)
        .arg("--force"))?;
    let text = fs::read_to_string(&f).map_err(|e| e.to_string())?;
    write_private(
        &f,
        kubeconfig_through(&text, &c.cfg.tunnel.kube_server).as_bytes(),
    )?;
    Ok(f)
}

fn ensure_ssh() -> Result<(), String> {
    if Command::new("ssh")
        .arg("-V")
        .stderr(Stdio::null())
        .status()
        .is_ok()
    {
        return Ok(());
    }
    eprintln!("yyc-talos: installing openssh-client");
    run(Command::new("sudo").args(["apt-get", "update", "-qq"]))?;
    run(Command::new("sudo")
        .env("DEBIAN_FRONTEND", "noninteractive")
        .args(["apt-get", "install", "-y", "-qq", "openssh-client"]))
}

fn tunnel(c: &Ctx) -> Result<ExitCode, String> {
    ensure_ssh()?;
    let cloudflared = tool(c, "cloudflared")?;
    talosctl(c)?;
    let key = c.out.join("jump-key");
    secret_file(&key, &c.cfg.secrets.ssh_key, true)?;
    let kh = c.out.join("known_hosts");
    write_private(&kh, known_hosts(&c.cfg).as_bytes())?;
    let me = std::env::current_exe().map_err(|e| e.to_string())?;
    let proxy = format!(
        "{} yyc-talos proxy {} {} {} {}",
        me.display(),
        cloudflared.display(),
        c.cfg.tunnel.access_hostname,
        c.cfg.secrets.access_id,
        c.cfg.secrets.access_secret
    );
    let mut ssh = Command::new("session-secret")
        .args([
            "--keys",
            &format!(
                "{},{}",
                c.cfg.secrets.access_id, c.cfg.secrets.access_secret
            ),
            "--exec",
            "ssh",
        ])
        .args(ssh_args(&c.cfg, &key, &kh, &proxy))
        .spawn()
        .map_err(|e| format!("session-secret ssh: {e}"))?;
    let port = first_port(&c.cfg)?;
    let start = Instant::now();
    loop {
        if let Some(st) = ssh.try_wait().map_err(|e| e.to_string())? {
            return Err(format!("the tunnel's ssh ended before it was up ({st})"));
        }
        if std::net::TcpStream::connect_timeout(
            &([127, 0, 0, 1], port).into(),
            Duration::from_secs(2),
        )
        .is_ok()
        {
            break;
        }
        if start.elapsed() > Duration::from_secs(120) {
            let _ = ssh.kill();
            return Err(format!("127.0.0.1:{port} not up after 2 min"));
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    eprintln!("yyc-talos: tunnel up ({})", c.cfg.tunnel.forwards.join(" "));
    for (f, make) in [
        (
            "talosconfig",
            talosconfig as fn(&Ctx) -> Result<PathBuf, String>,
        ),
        ("kubeconfig", kubeconfig),
    ] {
        if !c.out.join(f).is_file() {
            match make(c) {
                Ok(p) => eprintln!("yyc-talos: wrote {}", p.display()),
                Err(e) => eprintln!("yyc-talos: WARN {f}: {e}"),
            }
        }
    }
    let st = ssh.wait().map_err(|e| e.to_string())?;
    eprintln!("yyc-talos: the tunnel's ssh ended ({st})");
    Ok(ExitCode::from(st.code().unwrap_or(1).clamp(0, 255) as u8))
}

/// ssh's ProxyCommand: cloudflared to the jump host with the Access token session-secret put in the environment
fn proxy(args: &[String]) -> Result<ExitCode, String> {
    let [cloudflared, hostname, id, secret] = args else {
        return Err("usage: yyc-talos proxy CLOUDFLARED HOSTNAME ID_VAR SECRET_VAR".into());
    };
    let var = |k: &str| {
        std::env::var(k)
            .ok()
            .filter(|v| !v.is_empty())
            .ok_or_else(|| format!("{k} not in the environment"))
    };
    let err = Command::new(cloudflared)
        .args(["access", "tcp", "--hostname", hostname])
        .env("TUNNEL_SERVICE_TOKEN_ID", var(id)?)
        .env("TUNNEL_SERVICE_TOKEN_SECRET", var(secret)?)
        .exec();
    Err(format!("{cloudflared}: {err}"))
}

fn gen_node(c: &Ctx, node: &str, role: &str) -> Result<(), String> {
    let (args, warp) = gen_args(&c.cfg, &c.rel, &c.dir, &c.out, node, role)?;
    let t = talosctl(c)?;
    secrets_yaml(c)?;
    if warp {
        let reg = c.out.join(format!("{node}.warp.json"));
        secret_file(&reg, &warp_key(&c.cfg.secrets.warp_prefix, node), false)?;
        let text = fs::read_to_string(&reg).map_err(|e| e.to_string())?;
        write_private(
            &c.out.join(format!("{node}.patch.yaml")),
            warp_patch(&text)?.as_bytes(),
        )?;
    }
    run(Command::new(&t).args(&args).stdout(Stdio::null()))?;
    let f = c.out.join(format!("{node}.yaml"));
    fs::set_permissions(&f, fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
    run(Command::new(&t)
        .args(["validate", "--mode", "cloud", "--config"])
        .arg(&f))?;
    println!("{}", f.display());
    Ok(())
}

fn apply(c: &Ctx, node: &str, ip: &str, dry: bool) -> Result<(), String> {
    let f = c.out.join(format!("{node}.yaml"));
    if !f.is_file() {
        return Err(format!(
            "no {}: yyc-talos gen {node} ROLE first",
            f.display()
        ));
    }
    let tc = c.out.join("talosconfig");
    if !tc.is_file() {
        talosconfig(c)?;
    }
    let mut cmd = Command::new(talosctl(c)?);
    cmd.arg("--talosconfig")
        .arg(&tc)
        .args(["-n", ip, "apply-config", "--file"])
        .arg(&f)
        .args(["--mode", "auto"]);
    if dry {
        cmd.arg("--dry-run");
    }
    run(&mut cmd)
}

fn kube_env(c: &Ctx, cmd: &mut Command) {
    if std::env::var_os("KUBECONFIG").is_none() {
        cmd.env("KUBECONFIG", c.out.join("kubeconfig"));
    }
}

fn addons(c: &Ctx) -> Result<(), String> {
    let helm = tool(c, "helm")?;
    let kubectl = tool(c, "kubectl")?;
    for r in &c.cfg.addons.repos {
        // already added is fine; a wrong URL shows in the update below
        let _ = Command::new(&helm)
            .args(["repo", "add", &r.name, &r.url])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    run(Command::new(&helm)
        .args(["repo", "update"])
        .stdout(Stdio::null()))?;
    let mut k = Command::new(&kubectl);
    kube_env(c, &mut k);
    k.arg("apply");
    for f in &c.cfg.addons.before {
        k.arg("-f").arg(c.dir.join(f));
    }
    run(&mut k)?;
    for a in helm_installs(&c.cfg, &c.dir) {
        let mut h = Command::new(&helm);
        kube_env(c, &mut h);
        run(h.args(&a))?;
    }
    Ok(())
}

fn manifests(c: &Ctx) -> Result<(), String> {
    let mut k = Command::new(tool(c, "kubectl")?);
    kube_env(c, &mut k);
    run(k.arg("apply").arg("-k").arg(&c.dir))
}

fn say(m: &str) {
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() % 86400)
        .unwrap_or(0);
    println!("{:02}:{:02}:{:02} {m}", t / 3600, t / 60 % 60, t % 60);
}

/// Poll `ok` once a second for at most `secs`
fn wait_for(secs: u64, what: &str, mut ok: impl FnMut() -> bool) -> Result<(), String> {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(secs) {
        if ok() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    Err(format!("STOP: {what}: not within {secs} s"))
}

fn capture(cmd: &mut Command) -> Result<String, String> {
    let name = cmd.get_program().to_string_lossy().to_string();
    let o = cmd
        .stderr(Stdio::inherit())
        .output()
        .map_err(|e| format!("{name}: {e}"))?;
    if !o.status.success() {
        return Err(format!("{name} failed ({})", o.status));
    }
    Ok(String::from_utf8_lossy(&o.stdout).to_string())
}

struct Db<'a> {
    c: &'a Ctx,
    kubectl: PathBuf,
    hcloud: PathBuf,
    token: String,
    node: String,
}

impl Db<'_> {
    fn kube(&self) -> Command {
        let mut k = Command::new(&self.kubectl);
        kube_env(self.c, &mut k);
        k
    }
    fn k(&self, args: &[&str]) -> Result<String, String> {
        capture(
            self.kube()
                .arg("-n")
                .arg(&self.c.cfg.resize_db.namespace)
                .args(args),
        )
    }
    fn hc(&self, args: &[&str]) -> Result<String, String> {
        capture(
            Command::new(&self.hcloud)
                .env("HCLOUD_TOKEN", &self.token)
                .args(args),
        )
    }
    fn server(&self) -> Result<serde_json::Value, String> {
        serde_json::from_str(&self.hc(&["server", "describe", &self.node, "-o", "json"])?)
            .map_err(|e| format!("hcloud's server: {e}"))
    }
    fn pods(&self) -> Result<Vec<Pod>, String> {
        let sel = format!("cnpg.io/cluster={}", self.c.cfg.resize_db.copies);
        parse_pods(&self.k(&["get", "pods", "-l", &sel, "-o", "json"])?)
    }
    fn cluster(&self, name: &str, path: &str) -> Result<String, String> {
        self.k(&[
            "get",
            "cluster",
            name,
            "-o",
            &format!("jsonpath={{{path}}}"),
        ])
    }
    fn node_ready(&self) -> bool {
        capture(self.kube().args([
            "get",
            "node",
            &self.node,
            "-o",
            "jsonpath={.status.conditions[?(@.type==\"Ready\")].status}",
        ]))
        .is_ok_and(|s| s.trim() == "True")
    }
    fn off(&self) -> bool {
        self.server().is_ok_and(|s| s["status"] == "off")
    }
    fn healthy(&self) -> bool {
        let r = &self.c.cfg.resize_db;
        let get = |p: &str| {
            self.cluster(&r.copies, p)
                .ok()
                .and_then(|v| v.trim().parse::<u32>().ok())
        };
        let (Some(want), Some(ready)) = (get(".spec.instances"), get(".status.readyInstances"))
        else {
            return false;
        };
        let Ok(primary) = self.cluster(&r.copies, ".status.currentPrimary") else {
            return false;
        };
        let q = "select coalesce(max(pg_wal_lsn_diff(pg_current_wal_lsn(), replay_lsn)), 0)::bigint, count(*) from pg_stat_replication where state = 'streaming'";
        self.k(&[
            "exec",
            primary.trim(),
            "-c",
            "postgres",
            "--",
            "psql",
            "-qAtX",
            "-c",
            q,
        ])
        .is_ok_and(|lag| caught_up(want, ready, &lag, r.max_lag_bytes))
    }
    fn cordon(&self, on: bool) -> Result<String, String> {
        capture(
            self.kube()
                .arg(if on { "cordon" } else { "uncordon" })
                .arg(&self.node),
        )
    }
}

fn resize_db(c: &Ctx, node: &str, typ: &str) -> Result<(), String> {
    let token = match std::env::var("HCLOUD_TOKEN").ok().filter(|v| !v.is_empty()) {
        Some(t) => t,
        None => String::from_utf8(secret(&c.cfg.secrets.hetzner)?).map_err(|e| e.to_string())?,
    };
    let d = Db {
        c,
        kubectl: tool(c, "kubectl")?,
        hcloud: tool(c, "hcloud")?,
        token,
        node: node.to_string(),
    };
    let r = &c.cfg.resize_db;
    for cl in &r.primaries {
        let p = d.cluster(cl, ".status.currentPrimary")?;
        let on = d.k(&["get", "pod", p.trim(), "-o", "jsonpath={.spec.nodeName}"])?;
        if on.trim() == node {
            return Err(format!(
                "STOP: {node} holds {cl}'s primary {}: db/switchover.py first",
                p.trim()
            ));
        }
    }
    let copy = pick_copy(&d.pods()?, node)
        .ok_or_else(|| format!("STOP: no {} copy on {node} or waiting for it", r.copies))?;
    if d.server()?["server_type"]["name"] == typ {
        say(&format!("{node} is already {typ}"));
        return Ok(());
    }
    wait_for(600, "every other copy ready before the stop", || {
        d.pods().is_ok_and(|p| others_ready(&p, node, &copy))
    })?;
    say(&format!("{node} ({copy}): cordon, shut down"));
    d.cordon(true)?;
    d.hc(&["server", "shutdown", node])?;
    if wait_for(180, "clean shutdown", || d.off()).is_err() {
        say("no clean shutdown in 3 min: power off");
        d.hc(&["server", "poweroff", node])?;
        wait_for(120, "power off", || d.off())?;
    }
    say(&format!("change type to {typ} (disk kept)"));
    if let Err(e) = d.hc(&["server", "change-type", "--keep-disk", node, typ]) {
        // e.g. the account's shared vCPU limit (2026-11-09): the server goes back on as it was
        d.hc(&["server", "poweron", node])?;
        wait_for(600, "node Ready again", || d.node_ready())?;
        d.cordon(false)?;
        return Err(format!(
            "STOP: the type change was refused ({e}); {node} is back on as before"
        ));
    }
    d.hc(&["server", "poweron", node])?;
    wait_for(600, "node Ready", || d.node_ready())?;
    d.cordon(false)?;
    wait_for(900, "every copy ready and caught up", || d.healthy())?;
    let mem = capture(d.kube().args([
        "get",
        "node",
        node,
        "-o",
        "jsonpath={.status.capacity.memory}",
    ]))
    .unwrap_or_default();
    say(&format!(
        "done: {node} is {typ}, {} memory; {copy} streaming",
        mem.trim()
    ));
    Ok(())
}

pub fn run_cli(args: &[String]) -> Result<ExitCode, String> {
    let a: Vec<&str> = args.iter().map(String::as_str).collect();
    if let ["proxy", rest @ ..] = a.as_slice() {
        return proxy(&rest.iter().map(|s| s.to_string()).collect::<Vec<_>>());
    }
    let ok = |r: Result<(), String>| r.map(|_| ExitCode::SUCCESS);
    match a.as_slice() {
        ["tunnel"] => tunnel(&ctx()?),
        ["talosconfig"] => talosconfig(&ctx()?).map(|p| {
            println!("{}", p.display());
            ExitCode::SUCCESS
        }),
        ["kubeconfig"] => kubeconfig(&ctx()?).map(|p| {
            println!("{}", p.display());
            ExitCode::SUCCESS
        }),
        ["gen", node, role] => ok(gen_node(&ctx()?, node, role)),
        ["apply", node, ip] => ok(apply(&ctx()?, node, ip, false)),
        ["apply", node, ip, "--dry-run"] => ok(apply(&ctx()?, node, ip, true)),
        ["addons"] => ok(addons(&ctx()?)),
        ["manifests"] => ok(manifests(&ctx()?)),
        ["resize-db", node, typ] => ok(resize_db(&ctx()?, node, typ)),
        ["tool", name] => {
            let c = ctx()?;
            let p = match *name {
                "talosctl" => talosctl(&c)?,
                n if c.cfg.tools.contains_key(n) => tool(&c, n)?,
                _ => return Err(USAGE.into()),
            };
            println!("{}", p.display());
            Ok(ExitCode::SUCCESS)
        }
        ["-h"] | ["--help"] => {
            println!("{USAGE}");
            Ok(ExitCode::SUCCESS)
        }
        _ => Err(USAGE.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> Config {
        parse_config(include_str!("../tests/yyc-talos.toml")).unwrap()
    }

    fn rel() -> Release {
        Release {
            version: "v1.14.6".into(),
            installer: "factory.talos.dev/hcloud-installer/abc".into(),
        }
    }

    #[test]
    fn release_env_is_read_without_a_shell() {
        let r = parse_release("# c\nTALOS_VERSION=v1.14.6\n\n# more\nTALOS_INSTALLER=factory.talos.dev/hcloud-installer/abc\n").unwrap();
        assert_eq!(r, rel());
        assert!(
            parse_release("TALOS_VERSION=v1\n")
                .unwrap_err()
                .contains("TALOS_INSTALLER")
        );
        assert!(parse_release("nonsense\n").is_err());
    }

    #[test]
    fn warp_key_names_the_node_suffix() {
        assert_eq!(
            warp_key("YYC_TALOS_WARP_", "yyc-talos-cp1"),
            "YYC_TALOS_WARP_CP1"
        );
        assert_eq!(
            warp_key("YYC_TALOS_WARP_", "yyc-talos-news-a2"),
            "YYC_TALOS_WARP_NEWS_A2"
        );
    }

    #[test]
    fn warp_patch_takes_the_registration() {
        let p = warp_patch(r#"{"privateKey":"PK","address":"172.16.0.2/32","peerPublicKey":"PUB","endpoint":"162.159.192.1:2408"}"#).unwrap();
        assert!(p.contains("privateKey: PK\n"));
        assert!(p.contains("  - address: 172.16.0.2/12\n"));
        assert!(p.contains("  - publicKey: PUB\n"));
        assert!(p.contains("    endpoint: \"162.159.192.1:2408\"\n"));
        assert!(p.contains("mtu: 1280\n") && p.contains("gateway: 172.16.0.1\n"));
        assert!(
            warp_patch(r#"{"privateKey":"PK"}"#)
                .unwrap_err()
                .contains("address")
        );
    }

    #[test]
    fn roles_take_common_then_their_patches_and_warp_only_where_named() {
        let c = cfg();
        let (dir, out) = (Path::new("/r/talos"), Path::new("/o"));
        let (a, warp) = gen_args(&c, &rel(), dir, out, "yyc-talos-cp1", "controlplane").unwrap();
        assert!(warp);
        let patches: Vec<&str> = a
            .windows(2)
            .filter(|w| w[0] == "--config-patch")
            .map(|w| w[1].as_str())
            .collect();
        assert_eq!(
            patches,
            [
                "@/r/talos/patches/common.yaml",
                "@/r/talos/patches/controlplane.yaml",
                "@/r/talos/patches/public.yaml",
                "@/r/talos/patches/eth0-dhcp.yaml",
                "@/o/yyc-talos-cp1.patch.yaml"
            ]
        );
        let s = a.join(" ");
        assert!(s.starts_with("gen config yyc-talos https://10.0.0.21:6443 --with-secrets /o/secrets.yaml --talos-version v1.14.6 --install-image factory.talos.dev/hcloud-installer/abc:v1.14.6 "));
        assert!(s.ends_with("--output-types controlplane --output /o/yyc-talos-cp1.yaml --force"));

        let (a, warp) = gen_args(&c, &rel(), dir, out, "yyc-talos-w4", "worker").unwrap();
        assert!(!warp);
        assert!(!a.join(" ").contains("patch.yaml"));
        assert!(a.join(" ").contains("--output-types worker"));
        assert!(
            gen_args(&c, &rel(), dir, out, "x", "gateway")
                .unwrap_err()
                .contains("controlplane")
        );
    }

    #[test]
    fn the_tunnel_pins_the_host_key_and_forwards_everything() {
        let c = cfg();
        let a = ssh_args(
            &c,
            Path::new("/o/jump-key"),
            Path::new("/o/known_hosts"),
            "P x",
        );
        let s = a.join(" ");
        assert!(s.contains("StrictHostKeyChecking=yes") && !s.contains("accept-new"));
        assert!(s.contains("UserKnownHostsFile=/o/known_hosts"));
        assert!(s.contains("ProxyCommand=P x"));
        assert_eq!(
            a.iter().filter(|x| *x == "-L").count(),
            c.tunnel.forwards.len()
        );
        assert_eq!(a.last().unwrap(), "root@10.0.0.30");
        assert_eq!(
            known_hosts(&c),
            format!("10.0.0.30 {}\n", c.tunnel.host_key)
        );
        assert_eq!(first_port(&c).unwrap(), 50001);
    }

    #[test]
    fn kubeconfig_servers_go_through_the_tunnel() {
        let k = "clusters:\n- cluster:\n    certificate-authority-data: X\n    server: https://10.0.0.21:6443\n  name: yyc-talos\n";
        let t = kubeconfig_through(k, "https://127.0.0.1:6443");
        assert!(t.contains("    server: https://127.0.0.1:6443\n"));
        assert!(!t.contains("10.0.0.21"));
        assert!(t.contains("certificate-authority-data: X"));
    }

    #[test]
    fn addons_install_in_order_with_their_values() {
        let c = cfg();
        let h = helm_installs(&c, Path::new("/r/talos"));
        assert_eq!(h.len(), c.addons.charts.len());
        assert_eq!(
            h[0].join(" "),
            "upgrade --install cilium cilium/cilium --version 1.20.4 -n kube-system --create-namespace -f /r/talos/addons/cilium.values.yaml --wait --timeout 10m"
        );
    }

    #[test]
    fn tool_urls_and_sums() {
        let c = cfg();
        assert_eq!(
            tool_url(&c.tools["helm"]),
            "https://get.helm.sh/helm-v3.22.1-linux-amd64.tar.gz"
        );
        let l = format!(
            "{}  talosctl-linux-arm64\n{}  talosctl-linux-amd64\n",
            "a".repeat(64),
            "b".repeat(64)
        );
        assert_eq!(sum_of(&l, "talosctl-linux-amd64").unwrap(), "b".repeat(64));
        assert_eq!(sum_of(&l, "talosctl-darwin-amd64"), None);
    }

    #[test]
    fn a_resize_waits_for_the_other_copies_and_for_streaming_standbys() {
        let j = r#"{"items":[
          {"metadata":{"name":"pg-1"},"spec":{"nodeName":"db1"},"status":{"containerStatuses":[{"ready":true}]}},
          {"metadata":{"name":"pg-2"},"spec":{"nodeName":"db2"},"status":{"containerStatuses":[{"ready":false}]}},
          {"metadata":{"name":"pg-3"},"spec":{},"status":{}}]}"#;
        let pods = parse_pods(j).unwrap();
        assert_eq!(
            pods[2],
            Pod {
                name: "pg-3".into(),
                node: None,
                ready: false
            }
        );
        assert_eq!(pick_copy(&pods, "db1").as_deref(), Some("pg-1"));
        // no pod on db3: the unscheduled one is its copy, waiting for the room
        assert_eq!(pick_copy(&pods, "db3").as_deref(), Some("pg-3"));
        assert_eq!(pick_copy(&pods[..2], "db3"), None);
        // pg-2 on db2 not ready: no stop of db1 (or of db3) yet; db2's own copy does not count
        assert!(!others_ready(&pods, "db1", "pg-1"));
        assert!(others_ready(&pods[..2], "db2", "pg-2"));
        assert!(caught_up(3, 3, "1024|2\n", 67108864));
        assert!(!caught_up(3, 3, "1024|1", 67108864));
        assert!(!caught_up(3, 2, "0|2", 67108864));
        assert!(!caught_up(3, 3, "67108864|2", 67108864));
        assert!(!caught_up(3, 3, "", 67108864));
    }

    #[test]
    fn a_config_without_a_tool_pin_is_refused() {
        let t = include_str!("../tests/yyc-talos.toml");
        let cut = t.find("[tools.cloudflared]").unwrap();
        assert!(parse_config(&t[..cut]).unwrap_err().contains("cloudflared"));
    }
}
