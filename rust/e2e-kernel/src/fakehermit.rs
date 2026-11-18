//! `e2e-kernel fake-hermit`: the fabric's hermit for the fabric replica (docs/PLAN-fabric.md), on one box. It answers
//! the routes the spawner's fabric runner and the router call (kernel/spawner/fabric.go, router/fabricrunner.go) and
//! runs each sandbox with the real runsc of the fork on this box, from the fabric image unpacked here, in the bundle
//! sandboxd writes (aviary crates/sandboxd/src/runsc.rs: its flags, capabilities, rlimits, mounts, the FUSE device),
//! so a fabric machine boots here as on a host. Each sandbox has a network namespace of its own on the run's bridge
//! (`fhbr0`, 10.89.0.1/24, NATed to the box's uplink: `bridge_up`), as sandboxd gives each its own: two machines never
//! share a port (2026-11-18: a second session's gateway found 3128 taken on the box's loopback). The router's fabric
//! listener and the e2e front listen on the bridge's address, where on the fabric the gateway leads. No cgroup limits.
//!
//!   GET    /v1/sandbox-token-keys                    caller tools: the Ed25519 key its sandbox tokens are signed with
//!   PUT    /v1/conversations/{cid}/sandbox {person}  caller magpie: the conversation's sandbox, started if none
//!   GET    /v1/conversations/{cid}/sandbox           caller magpie: its state (404 no_sandbox when none)
//!   GET    /v1/admin/sandboxes/{id}/log              admin: its console
//!   POST   /v1/admin/sandboxes/{id}/release          admin: killed and deleted
//!   DELETE /v1/workspaces/{cid}                      caller magpie: its sandbox released, its folders removed
//!   POST   /v1/conversations/{cid}/sandbox/freeze {until}  caller magpie: paused in place (runsc pause) until then
//!   POST   /v1/conversations/{cid}/sandbox/thaw     caller magpie: a frozen one resumed (runsc resume)
//!   GET    /v1/sandbox-tokens/{id}                   caller gateway: the sandbox's liveness (hermit-jarvis, aviary/src/fabric.rs)
//!   GET    /v1/sandbox/self                          caller gateway, `aviary-sandbox-id`: its descriptor's control hashes
//!
//! Its sandbox tokens are hermit's (aviary crates/hermit-api/src/token.rs): `hst1.<kid>.<payload>.<sig>`, the payload
//! `1 | sandbox | conversation | 0.0.0.0 | expiry (u64 BE) | person`, Ed25519 over "hermit-sandbox-token\0" + payload.

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use ring::rand::{SecureRandom as _, SystemRandom};
use ring::signature::{Ed25519KeyPair, KeyPair as _};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

/// What it is run with (environment of `e2e-kernel fake-hermit`).
pub struct Cfg {
    pub listen: String,
    pub work: PathBuf,
    /// The fabric image unpacked (its rootfs) and its config's Entrypoint + Cmd and Env.
    pub rootfs: PathBuf,
    pub args: Vec<String>,
    pub env: Vec<String>,
    /// `sha256:<hex>`, the image the spawner's source names.
    pub digest: String,
    /// Where the sandbox's proxy URL points: the router's fabric listener.
    pub proxy_at: String,
    pub runsc: String,
    pub magpie: String,
    pub admin: String,
    pub tools: String,
    /// The caller gateway's token (hermit-jarvis's `FABRIC_HERMIT_GATEWAY_TOKEN`); empty: none.
    pub gateway: String,
}

#[derive(Clone)]
struct Sbx {
    id: String,
    cid: String,
    name: String,
    person: String,
    state: &'static str,
    /// each freeze's number: a thaw at `until` acts only on the freeze that set it
    frozen_gen: u64,
}

struct St {
    cfg: Cfg,
    /// the next sandbox's address on the bridge (10.89.0.<n>)
    next_ip: u8,
    key: Ed25519KeyPair,
    rng: SystemRandom,
    by_cid: HashMap<String, Sbx>,
}

const RUNSC_FLAGS: [&str; 8] = [
    "--platform=systrap",
    "--network=sandbox",
    "--overlay2=none",
    "--host-uds=none",
    "--host-fifo=none",
    "--net-raw",
    "--allow-packet-socket-write",
    "--allow-suid",
];

/// sandboxd's DOCKER_CAPS (aviary runsc.rs)
const CAPS: [&str; 20] = [
    "CAP_CHOWN",
    "CAP_DAC_OVERRIDE",
    "CAP_FOWNER",
    "CAP_FSETID",
    "CAP_KILL",
    "CAP_SETGID",
    "CAP_SETUID",
    "CAP_SETPCAP",
    "CAP_NET_BIND_SERVICE",
    "CAP_NET_RAW",
    "CAP_NET_ADMIN",
    "CAP_SYS_CHROOT",
    "CAP_MKNOD",
    "CAP_AUDIT_WRITE",
    "CAP_SETFCAP",
    "CAP_SYS_ADMIN",
    "CAP_SYS_PTRACE",
    "CAP_SYS_RESOURCE",
    "CAP_IPC_LOCK",
    "CAP_SYS_NICE",
];

fn uuid_v4(rng: &SystemRandom) -> [u8; 16] {
    let mut b = [0u8; 16];
    rng.fill(&mut b).unwrap_or_default();
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    b
}

fn uuid_text(b: &[u8]) -> String {
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

fn uuid_bytes(s: &str) -> Option<[u8; 16]> {
    let h: String = s.chars().filter(|c| *c != '-').collect();
    if h.len() != 32 {
        return None;
    }
    let mut b = [0u8; 16];
    for (i, x) in b.iter_mut().enumerate() {
        *x = u8::from_str_radix(&h[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(b)
}

/// hermit's sandbox token for `s`, a day long
fn token(st: &St, s: &Sbx) -> Result<String> {
    let mut p = vec![1u8];
    p.extend_from_slice(&uuid_bytes(&s.id).context("sandbox id")?);
    p.extend_from_slice(&uuid_bytes(&s.cid).context("conversation id")?);
    p.extend_from_slice(&[0, 0, 0, 0]);
    let exp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs()
        + 86_400;
    p.extend_from_slice(&exp.to_be_bytes());
    p.extend_from_slice(s.person.as_bytes());
    let mut msg = b"hermit-sandbox-token\0".to_vec();
    msg.extend_from_slice(&p);
    let sig = st.key.sign(&msg);
    Ok(format!(
        "hst1.1.{}.{}",
        B64.encode(&p),
        B64.encode(sig.as_ref())
    ))
}

fn sandbox_json(st: &St, s: &Sbx) -> serde_json::Value {
    serde_json::json!({"id": s.id, "conversationId": s.cid, "person": s.person, "state": s.state,
        "phase": if s.state == "starting" { serde_json::json!("creating") } else { serde_json::Value::Null },
        "version": 1, "image": st.cfg.digest, "busy": false})
}

fn sudo(args: &[&str]) -> Result<()> {
    let st = Command::new("sudo").arg("-n").args(args).status()?;
    if !st.success() {
        bail!("sudo {}: {st}", args.join(" "));
    }
    Ok(())
}

/// The OCI spec of a sandbox, as sandboxd writes it (bar the network namespace and the cgroup).
fn bundle(cfg: &Cfg, s: &Sbx, root: &Path, dirs: &Path, proxy: &str) -> serde_json::Value {
    let mut env: Vec<String> = cfg
        .env
        .iter()
        .map(|kv| {
            if kv.starts_with("HOME=") {
                "HOME=/home/sandbox".to_owned()
            } else {
                kv.clone()
            }
        })
        .collect();
    if !env.iter().any(|kv| kv.starts_with("HOME=")) {
        env.push("HOME=/home/sandbox".into());
    }
    for k in ["http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"] {
        env.push(format!("{k}={proxy}"));
    }
    let bind = |dst: &str, src: PathBuf| serde_json::json!({"destination": dst, "type": "bind", "source": src, "options": ["rbind", "rw"]});
    let caps: Vec<&str> = CAPS.to_vec();
    serde_json::json!({
        "ociVersion": "1.0.0",
        "process": {"user": {"uid": 0, "gid": 0}, "cwd": "/work", "args": cfg.args, "env": env,
            "capabilities": {"bounding": caps, "effective": caps, "permitted": caps, "inheritable": [], "ambient": []},
            "rlimits": [{"type": "RLIMIT_NOFILE", "hard": 65536, "soft": 65536}]},
        "root": {"path": root, "readonly": false},
        "hostname": "sandbox",
        "mounts": [
            {"destination": "/proc", "type": "proc", "source": "proc"},
            {"destination": "/dev", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid", "strictatime", "mode=755", "size=65536k"]},
            {"destination": "/dev/pts", "type": "devpts", "source": "devpts", "options": ["nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620"]},
            {"destination": "/dev/shm", "type": "tmpfs", "source": "shm", "options": ["nosuid", "noexec", "nodev", "mode=1777", "size=65536k"]},
            {"destination": "/sys", "type": "sysfs", "source": "sysfs", "options": ["nosuid", "noexec", "nodev", "ro"]},
            {"destination": "/sys/fs/cgroup", "type": "cgroup", "source": "cgroup", "options": ["nosuid", "noexec", "nodev"]},
            {"destination": "/run", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid", "nodev", "mode=755"]},
            bind("/tmp", dirs.join("tmp")),
            bind("/var/lib/docker", dirs.join("docker")),
            bind("/workspace", cfg.work.join("ws").join(&s.cid)),
            bind("/home/claude", cfg.work.join("home").join(&s.cid)),
        ],
        "linux": {"namespaces": [{"type": "pid"}, {"type": "ipc"}, {"type": "uts"}, {"type": "mount"},
                {"type": "network", "path": format!("/var/run/netns/{}", netns_of(s))}],
            "devices": [{"path": "/dev/fuse", "type": "c", "major": 10, "minor": 229, "fileMode": 438, "uid": 0, "gid": 0}]}
    })
}

fn runsc(cfg: &Cfg, args: &[&str]) -> Command {
    let mut c = Command::new("sudo");
    c.arg("-n")
        .arg(&cfg.runsc)
        .arg("--root")
        .arg(cfg.work.join("runsc"))
        .args(RUNSC_FLAGS)
        .args(args);
    c
}

/// Starts `s` (a thread of its own): its folders, the overlay root over the unpacked image, the bundle, `runsc run`.
fn start(st: &Arc<Mutex<St>>, s: Sbx) {
    let st = st.clone();
    std::thread::spawn(move || {
        let r = (|| -> Result<()> {
            let (cfg_work, rootfs, proxy, ip) = {
                let mut g = st.lock().unwrap_or_else(|e| e.into_inner());
                let tok = token(&g, &s)?;
                let ip = g.next_ip;
                g.next_ip = g.next_ip.wrapping_add(1).max(10);
                (
                    g.cfg.work.clone(),
                    g.cfg.rootfs.clone(),
                    format!("http://sbx:{tok}@{}", g.cfg.proxy_at),
                    ip,
                )
            };
            netns_up(&s, ip)?;
            let dirs = cfg_work.join("sbx").join(&s.name);
            let root = dirs.join("root");
            for d in ["upper", "ovl", "root", "tmp", "docker"] {
                std::fs::create_dir_all(dirs.join(d))?;
            }
            for d in [
                cfg_work.join("ws").join(&s.cid),
                cfg_work.join("home").join(&s.cid),
            ] {
                std::fs::create_dir_all(&d)?;
                sudo(&["chown", "1000:1000", &d.to_string_lossy()])?;
            }
            sudo(&["chmod", "1777", &dirs.join("tmp").to_string_lossy()])?;
            let opts = format!(
                "lowerdir={},upperdir={},workdir={}",
                rootfs.display(),
                dirs.join("upper").display(),
                dirs.join("ovl").display()
            );
            sudo(&[
                "mount",
                "-t",
                "overlay",
                "overlay",
                "-o",
                &opts,
                &root.to_string_lossy(),
            ])?;
            let spec = {
                let g = st.lock().unwrap_or_else(|e| e.into_inner());
                bundle(&g.cfg, &s, &root, &dirs, &proxy)
            };
            std::fs::write(dirs.join("config.json"), serde_json::to_vec_pretty(&spec)?)?;
            let log = std::fs::File::create(dirs.join("console.log"))?;
            let out = {
                let g = st.lock().unwrap_or_else(|e| e.into_inner());
                runsc(
                    &g.cfg,
                    &[
                        "run",
                        "--bundle",
                        &dirs.to_string_lossy(),
                        "--detach",
                        &s.name,
                    ],
                )
                .stdout(log.try_clone()?)
                .stderr(log)
                .status()?
            };
            if !out.success() {
                bail!("runsc run: {out}");
            }
            Ok(())
        })();
        let mut g = st.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(x) = g.by_cid.get_mut(&s.cid).filter(|x| x.id == s.id) {
            x.state = if r.is_ok() { "ready" } else { "gone" };
        }
        match r {
            Ok(()) => eprintln!("fake-hermit: {} ({}) runs", s.name, s.id),
            Err(e) => eprintln!("fake-hermit: {} failed to start: {e:#}", s.name),
        }
    });
}

/// Unix seconds of an RFC 3339 UTC time (`2026-11-18T12:34:56.789Z`), as the router writes `until`.
fn unix_of(t: &str) -> Option<i64> {
    let (date, rest) = t.split_once('T')?;
    let mut d = date.split('-').map(|x| x.parse::<i64>().ok());
    let (y, m, day) = (d.next()??, d.next()??, d.next()??);
    let hms = rest.trim_end_matches('Z');
    let hms = hms.split(['.', '+']).next()?;
    let mut h = hms.split(':').map(|x| x.parse::<i64>().ok());
    let (hh, mm, ss) = (h.next()??, h.next()??, h.next()??);
    // days from the civil date (Howard Hinnant's algorithm)
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some((era * 146_097 + doe - 719_468) * 86_400 + hh * 3600 + mm * 60 + ss)
}

/// Paused in place, as the fabric hermit freezes (aviary hermit `fabric/pausing.rs`); thawed at `until` by itself
fn freeze(
    st: &Arc<Mutex<St>>,
    cid: &str,
    until: Option<i64>,
) -> Result<serde_json::Value, (u16, &'static str)> {
    let (s, mut pause) = {
        let g = st.lock().unwrap_or_else(|e| e.into_inner());
        let Some(s) = g.by_cid.get(cid).cloned() else {
            return Err((404, "no_sandbox"));
        };
        if s.state != "ready" {
            return Err((409, "sandbox_busy"));
        }
        let c = runsc(&g.cfg, &["pause", &s.name]);
        (s, c)
    };
    if !pause.status().is_ok_and(|x| x.success()) {
        return Err((502, "pause_failed"));
    }
    let out = {
        let mut g = st.lock().unwrap_or_else(|e| e.into_inner());
        let x = g
            .by_cid
            .get_mut(cid)
            .filter(|x| x.id == s.id)
            .ok_or((404, "no_sandbox"))?;
        x.state = "frozen";
        x.frozen_gen += 1;
        let gen_ = x.frozen_gen;
        let snap = x.clone();
        if let Some(u) = until {
            let (st2, cid2) = (st.clone(), cid.to_owned());
            std::thread::spawn(move || {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(0));
                std::thread::sleep(std::time::Duration::from_secs(
                    u64::try_from((u - now).max(0)).unwrap_or(0),
                ));
                let still = st2
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .by_cid
                    .get(&cid2)
                    .is_some_and(|x| x.state == "frozen" && x.frozen_gen == gen_);
                if still {
                    eprintln!("fake-hermit: {cid2} until passed: thawing");
                    let _ = thaw(&st2, &cid2);
                }
            });
        }
        sandbox_json(&g, &snap)
    };
    Ok(out)
}

fn thaw(st: &Arc<Mutex<St>>, cid: &str) -> Result<serde_json::Value, (u16, &'static str)> {
    let (s, mut resume) = {
        let g = st.lock().unwrap_or_else(|e| e.into_inner());
        let Some(s) = g.by_cid.get(cid).cloned() else {
            return Err((404, "no_sandbox"));
        };
        if s.state != "frozen" {
            return Ok(sandbox_json(&g, &s));
        }
        let c = runsc(&g.cfg, &["resume", &s.name]);
        (s, c)
    };
    if !resume.status().is_ok_and(|x| x.success()) {
        return Err((502, "resume_failed"));
    }
    let mut g = st.lock().unwrap_or_else(|e| e.into_inner());
    let x = g
        .by_cid
        .get_mut(cid)
        .filter(|x| x.id == s.id)
        .ok_or((404, "no_sandbox"))?;
    x.state = "ready";
    let snap = x.clone();
    Ok(sandbox_json(&g, &snap))
}

/// The bridge the sandboxes' namespaces hang on, at `BRIDGE_IP`/24, NATed out (`e2e-kernel` makes it before the router
/// listens on its address; `bridge_down` removes it).
pub const BRIDGE: &str = "fhbr0";
pub const BRIDGE_IP: &str = "10.89.0.1";

/// The bridge, forwarding and the NAT out.
///
/// # Errors
/// A command failing.
pub fn bridge_up() -> Result<()> {
    bridge_down();
    sudo(&["ip", "link", "add", BRIDGE, "type", "bridge"])?;
    sudo(&[
        "ip",
        "addr",
        "add",
        &format!("{BRIDGE_IP}/24"),
        "dev",
        BRIDGE,
    ])?;
    sudo(&["ip", "link", "set", BRIDGE, "up"])?;
    sudo(&["sysctl", "-q", "-w", "net.ipv4.ip_forward=1"])?;
    sudo(&[
        "iptables",
        "-t",
        "nat",
        "-A",
        "POSTROUTING",
        "-s",
        "10.89.0.0/24",
        "!",
        "-o",
        BRIDGE,
        "-j",
        "MASQUERADE",
    ])?;
    Ok(())
}

/// What `bridge_up` made, gone (a missing piece is fine).
pub fn bridge_down() {
    let q = |a: &[&str]| {
        let _ = Command::new("sudo")
            .arg("-n")
            .args(a)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    };
    q(&[
        "iptables",
        "-t",
        "nat",
        "-D",
        "POSTROUTING",
        "-s",
        "10.89.0.0/24",
        "!",
        "-o",
        BRIDGE,
        "-j",
        "MASQUERADE",
    ]);
    q(&["ip", "link", "del", BRIDGE]);
}

fn netns_of(s: &Sbx) -> String {
    format!("fh-{}", &s.name[4..])
}

/// The sandbox's own network namespace on the bridge, at 10.89.0.`ip`, its default route the bridge.
fn netns_up(s: &Sbx, ip: u8) -> Result<()> {
    let (ns, host_if, sb_if) = (netns_of(s), format!("fhv{ip}"), format!("fhs{ip}"));
    let _ = Command::new("sudo")
        .args(["-n", "ip", "netns", "del", &ns])
        .status();
    sudo(&["ip", "netns", "add", &ns])?;
    sudo(&[
        "ip", "link", "add", &host_if, "type", "veth", "peer", "name", &sb_if,
    ])?;
    sudo(&["ip", "link", "set", &sb_if, "netns", &ns])?;
    sudo(&["ip", "link", "set", &host_if, "master", BRIDGE, "up"])?;
    let inns = |a: &[&str]| -> Result<()> {
        let mut v = vec!["ip", "netns", "exec", ns.as_str()];
        v.extend_from_slice(a);
        sudo(&v)
    };
    inns(&["ip", "link", "set", &sb_if, "name", "eth0"])?;
    inns(&[
        "ip",
        "addr",
        "add",
        &format!("10.89.0.{ip}/24"),
        "dev",
        "eth0",
    ])?;
    inns(&["ip", "link", "set", "eth0", "up"])?;
    inns(&["ip", "link", "set", "lo", "up"])?;
    inns(&["ip", "route", "add", "default", "via", BRIDGE_IP])?;
    Ok(())
}

fn release(st: &Arc<Mutex<St>>, s: &Sbx) {
    let (work, cmd_kill, cmd_del) = {
        let g = st.lock().unwrap_or_else(|e| e.into_inner());
        (
            g.cfg.work.clone(),
            runsc(&g.cfg, &["kill", &s.name, "KILL"]),
            runsc(&g.cfg, &["delete", "-force", &s.name]),
        )
    };
    for mut c in [cmd_kill, cmd_del] {
        let _ = c.status();
    }
    let _ = sudo(&[
        "umount",
        "-l",
        &work
            .join("sbx")
            .join(&s.name)
            .join("root")
            .to_string_lossy(),
    ]);
    let _ = Command::new("sudo")
        .args(["-n", "ip", "netns", "del", &netns_of(s)])
        .status();
    let mut g = st.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(x) = g.by_cid.get_mut(&s.cid).filter(|x| x.id == s.id) {
        x.state = "gone";
    }
}

struct Req {
    method: String,
    path: String,
    auth: String,
    sandbox: String,
    body: Vec<u8>,
}

fn read_req(c: &mut TcpStream) -> Result<Req> {
    let mut r = BufReader::new(c.try_clone()?);
    let mut line = String::new();
    r.read_line(&mut line)?;
    let mut it = line.split_whitespace();
    let (method, path) = (
        it.next().unwrap_or("").to_owned(),
        it.next().unwrap_or("").to_owned(),
    );
    let (mut len, mut auth, mut sandbox) = (0usize, String::new(), String::new());
    loop {
        let mut h = String::new();
        if r.read_line(&mut h)? == 0 || h == "\r\n" || h == "\n" {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            match k.trim().to_ascii_lowercase().as_str() {
                "content-length" => len = v.trim().parse().unwrap_or(0),
                "authorization" => auth = v.trim().trim_start_matches("Bearer ").to_owned(),
                "aviary-sandbox-id" => sandbox = v.trim().to_owned(),
                _ => {}
            }
        }
    }
    let mut body = vec![0u8; len.min(1 << 20)];
    r.read_exact(&mut body)?;
    Ok(Req {
        method,
        path: path.split('?').next().unwrap_or("").to_owned(),
        auth,
        sandbox,
        body,
    })
}

fn reply(c: &mut TcpStream, code: u16, body: &serde_json::Value) {
    let b = if code == 204 {
        Vec::new()
    } else {
        serde_json::to_vec(body).unwrap_or_default()
    };
    let _ = write!(
        c,
        "HTTP/1.1 {code} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        b.len()
    );
    let _ = c.write_all(&b);
}

fn err(code: u16, what: &str) -> (u16, serde_json::Value) {
    (code, serde_json::json!({"code": what, "message": what}))
}

fn handle(st: &Arc<Mutex<St>>, q: &Req) -> (u16, serde_json::Value) {
    let parts: Vec<&str> = q.path.trim_matches('/').split('/').collect();
    let (magpie, admin, tools, gateway) = {
        let g = st.lock().unwrap_or_else(|e| e.into_inner());
        (
            q.auth == g.cfg.magpie,
            q.auth == g.cfg.admin,
            q.auth == g.cfg.tools,
            !g.cfg.gateway.is_empty() && q.auth == g.cfg.gateway,
        )
    };
    match (q.method.as_str(), parts.as_slice()) {
        ("GET", ["v1", "sandbox-token-keys"]) if tools => {
            let g = st.lock().unwrap_or_else(|e| e.into_inner());
            let pk = B64.encode(g.key.public_key().as_ref());
            (
                200,
                serde_json::json!({"keys": [{"kid": 1, "alg": "Ed25519", "publicKey": pk}]}),
            )
        }
        ("PUT", ["v1", "conversations", cid, "sandbox"]) if magpie => {
            let person = serde_json::from_slice::<serde_json::Value>(&q.body)
                .ok()
                .and_then(|v| v["person"].as_str().map(str::to_owned))
                .unwrap_or_else(|| "jarvis4@deyaochen.com".into());
            let mut g = st.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(s) = g.by_cid.get(*cid).filter(|s| s.state != "gone").cloned() {
                return (
                    if s.state == "ready" { 200 } else { 202 },
                    sandbox_json(&g, &s),
                );
            }
            let id = uuid_text(&uuid_v4(&g.rng));
            let s = Sbx {
                name: format!("sbx-{}", &id.replace('-', "")[..16]),
                id,
                cid: (*cid).to_owned(),
                person,
                state: "starting",
                frozen_gen: 0,
            };
            g.by_cid.insert((*cid).to_owned(), s.clone());
            let out = sandbox_json(&g, &s);
            drop(g);
            start(st, s);
            (202, out)
        }
        ("POST", ["v1", "conversations", cid, "sandbox", "freeze"]) if magpie => {
            let until = serde_json::from_slice::<serde_json::Value>(&q.body)
                .ok()
                .and_then(|v| v["until"].as_str().and_then(unix_of));
            match freeze(st, cid, until) {
                Ok(v) => (202, v),
                Err((c, w)) => err(c, w),
            }
        }
        ("POST", ["v1", "conversations", cid, "sandbox", "thaw"]) if magpie => {
            match thaw(st, cid) {
                Ok(v) => (202, v),
                Err((c, w)) => err(c, w),
            }
        }
        ("GET", ["v1", "conversations", cid, "sandbox"]) if magpie => {
            let g = st.lock().unwrap_or_else(|e| e.into_inner());
            match g.by_cid.get(*cid) {
                Some(s) => (200, sandbox_json(&g, s)),
                None => err(404, "no_sandbox"),
            }
        }
        ("GET", ["v1", "admin", "sandboxes", id, "log"]) if admin => {
            let (work, name) = {
                let g = st.lock().unwrap_or_else(|e| e.into_inner());
                let Some(s) = g.by_cid.values().find(|s| s.id == *id) else {
                    return err(404, "no_sandbox");
                };
                (g.cfg.work.clone(), s.name.clone())
            };
            let text =
                std::fs::read(work.join("sbx").join(name).join("console.log")).unwrap_or_default();
            let tail = &text[text.len().saturating_sub(64 << 10)..];
            (
                200,
                serde_json::json!({"text": String::from_utf8_lossy(tail), "reason": "live", "sandboxId": id}),
            )
        }
        ("POST", ["v1", "admin", "sandboxes", id, "release"]) if admin => {
            let s = {
                let g = st.lock().unwrap_or_else(|e| e.into_inner());
                g.by_cid.values().find(|s| s.id == *id).cloned()
            };
            let Some(s) = s else {
                return err(404, "no_sandbox");
            };
            release(st, &s);
            (200, serde_json::json!({"released": 1}))
        }
        ("DELETE", ["v1", "workspaces", cid]) if magpie => {
            let (s, work) = {
                let g = st.lock().unwrap_or_else(|e| e.into_inner());
                (
                    g.by_cid.get(*cid).filter(|s| s.state != "gone").cloned(),
                    g.cfg.work.clone(),
                )
            };
            if let Some(s) = s {
                release(st, &s);
            }
            for d in [work.join("ws").join(cid), work.join("home").join(cid)] {
                let _ = sudo(&["rm", "-rf", &d.to_string_lossy()]);
            }
            (204, serde_json::Value::Null)
        }
        ("GET", ["v1", "sandbox-tokens", id]) if gateway => {
            let g = st.lock().unwrap_or_else(|e| e.into_inner());
            match g.by_cid.values().find(|s| s.id == *id && s.state != "gone") {
                Some(s) => (
                    200,
                    serde_json::json!({"conversationId": s.cid, "person": s.person, "live": true}),
                ),
                None => err(404, "no_sandbox"),
            }
        }
        // the control hashes: this hermit checks no supervisor, so any SHA-256 is its own
        ("GET", ["v1", "sandbox", "self"]) if gateway => {
            let g = st.lock().unwrap_or_else(|e| e.into_inner());
            match g
                .by_cid
                .values()
                .find(|s| s.id == q.sandbox && s.state != "gone")
            {
                Some(s) => {
                    let h = ring::digest::digest(&ring::digest::SHA256, s.id.as_bytes());
                    let hex: String = h.as_ref().iter().map(|b| format!("{b:02x}")).collect();
                    (200, serde_json::json!({"control": {"tokenSha256": [hex]}}))
                }
                None => err(404, "no_sandbox"),
            }
        }
        _ if !(magpie || admin || tools || gateway) => err(401, "unauthenticated"),
        _ => err(404, "not_found"),
    }
}

/// Serves until killed.
pub fn serve(cfg: Cfg) -> Result<()> {
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).map_err(|_| anyhow::anyhow!("key"))?;
    let key = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).map_err(|_| anyhow::anyhow!("key"))?;
    std::fs::create_dir_all(cfg.work.join("runsc"))?;
    let l = TcpListener::bind(&cfg.listen).with_context(|| format!("listen {}", cfg.listen))?;
    eprintln!("fake-hermit on {} (image {})", cfg.listen, cfg.digest);
    let st = Arc::new(Mutex::new(St {
        cfg,
        key,
        rng,
        by_cid: HashMap::new(),
        next_ip: 10,
    }));
    for c in l.incoming() {
        let Ok(mut c) = c else { continue };
        let st = st.clone();
        std::thread::spawn(move || {
            if let Ok(q) = read_req(&mut c) {
                let (code, body) = handle(&st, &q);
                eprintln!("fake-hermit: {} {} → {code}", q.method, q.path);
                reply(&mut c, code, &body);
            }
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// its tokens are what the router's verifyHST reads (router/fabricrunner.go): the layout, the context, the key
    #[test]
    fn until_reads_as_the_router_writes_it() {
        assert_eq!(unix_of("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            unix_of("2026-11-18T12:34:56.123456789Z"),
            Some(1_795_005_296)
        );
        assert_eq!(unix_of("2000-03-01T00:00:01Z"), Some(951_868_801));
        assert_eq!(unix_of("not a time"), None);
    }

    #[test]
    fn a_token_is_hermits() {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("a key");
        let key = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("the key");
        let pk = key.public_key().as_ref().to_vec();
        let st = St {
            cfg: Cfg {
                listen: String::new(),
                work: PathBuf::new(),
                rootfs: PathBuf::new(),
                args: vec![],
                env: vec![],
                digest: String::new(),
                proxy_at: String::new(),
                runsc: String::new(),
                magpie: String::new(),
                admin: String::new(),
                tools: String::new(),
                gateway: String::new(),
            },
            key,
            rng,
            by_cid: HashMap::new(),
            next_ip: 10,
        };
        let s = Sbx {
            id: "01a1ec41-c22f-71e4-9e50-601a78aeffde".into(),
            cid: "6bd76dff-094c-425f-b971-c9b531254b1e".into(),
            name: "sbx-01a1ec41c22f71e4".into(),
            person: "jarvis4@deyaochen.com".into(),
            state: "ready",
            frozen_gen: 0,
        };
        let t = token(&st, &s).expect("a token");
        let p: Vec<&str> = t.split('.').collect();
        assert_eq!((p.len(), p[0], p[1]), (4, "hst1", "1"));
        let payload = B64.decode(p[2]).expect("base64 payload");
        assert_eq!(payload[0], 1);
        assert_eq!(uuid_text(&payload[1..17]), s.id);
        assert_eq!(uuid_text(&payload[17..33]), s.cid);
        assert_eq!(&payload[45..], b"jarvis4@deyaochen.com");
        let mut msg = b"hermit-sandbox-token\0".to_vec();
        msg.extend_from_slice(&payload);
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &pk)
            .verify(&msg, &B64.decode(p[3]).expect("base64 signature"))
            .expect("hermit's signature");
    }
}
