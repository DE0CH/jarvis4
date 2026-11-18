//! e2e-kernel: a kernel line's life on real Fly machines, with nothing of production's touched. It builds the nine
//! kernel components and the router of this tree, runs them here with a throwaway box key and root key (each
//! component on its own loopback address, named `<role>-blue.kernel.e2e` in the router's own /etc/hosts), the
//! machines' way back to the router over a throwaway WireGuard peer of the Fly org (served by `router m-gateway`, as
//! on the cluster), and the session image; e2e/kernel plays the iPhone: the roster, a Reset with the public TEST master
//! key, the root grant, a new session, pause (its snapshot), resume (restored), destroy.
//! Leaves nothing behind but the logs (`$E2E_LOGS`, default /tmp/jarvis2-e2e-kernel-logs): every machine naming this
//! run's peer is destroyed with its volume, the peer removed, the processes stopped. Needs sudo (a mount namespace).
//!
//!   JARVIS2_FLY_TOKEN   the jarvis2-370 org token (the spawner's here, the sweep's, the peer's)
//!   E2E_RUNNER=fabric   the fabric replica instead (docs/PLAN-fabric.md): no Fly; the session's machines are gVisor
//!                       sandboxes on this box, made by the fake hermit (fakehermit.rs, `e2e-kernel fake-hermit`) with
//!                       the fork's runsc (E2E_RUNSC, default /usr/local/bin/runsc) from the fabric image
//!                       (E2E_FABRIC_IMAGE, default ghcr.io/de0ch/jarvis4-session-fabric:latest), unpacked once into
//!                       E2E_FABRIC_CACHE (default ~/.cache/jarvis4-e2e-fabric). Needs crane and sudo. No Inbox, no
//!                       approval: the boot check of a fabric change.
//!   E2E_HARNESS=aviary  the session's harness aviary, with the chat stack beside the kernel (chat.rs: hermit-jarvis
//!                       of this tree, magpie of the pinned release, a TLS Postgres, an S3 stand-in) and e2e/aviary
//!                       as the phone, the stand-in model and the chat front (127.0.0.1:31085) instead of e2e/kernel.
//!                       On Fly the machines reach the front through a second throwaway peer (`-chat`), or over 6PN
//!                       when this runs on a Fly machine ([`Net`]); with the fabric, on loopback. aviary-pin.yml's
//!                       replica (every aviary release, before it is pinned); by hand from a session:
//!                       `session-secret --keys JARVIS2_FLY_TOKEN --exec env E2E_HARNESS=aviary e2e-kernel`
//!   E2E_SESSION_IMAGE   the session image (default ghcr.io/de0ch/jarvis4-session:latest), pinned by digest here
//!
//! `e2e-kernel hosts-exec HOSTS UID GID -- CMD…` (run by the router's `sudo unshare`): HOSTS bound over /etc/hosts in
//! this mount namespace, then CMD as UID:GID with no supplementary groups.

mod chat;
mod fakehermit;

use anyhow::{Context, Result, bail};
use std::fs;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const ORG: &str = "jarvis2-370";
const PEER: &str = "jarvis2-e2e-kernel";
const MAPI: &str = "https://api.machines.dev/v1/apps/jarvis4-sessions";
const ROLES: [&str; 9] = [
    "notary",
    "notarizer",
    "mover",
    "merger",
    "spawner",
    "identity",
    "gullible",
    "minter",
    "secrets",
];
const ROUTER: &str = "127.0.0.1:29080";
const MACHINES: &str = "127.0.0.1:29081";
const GATEWAY_HEALTH: &str = "127.0.0.1:29082";
/// the fabric replica: the fake hermit, and the router's fabric listener (a fabric machine's way to the router)
const FAKE_HERMIT: &str = "127.0.2.1:29090";
const FABRIC_LISTENER: &str = "127.0.0.1:29083";

fn fabric() -> bool {
    std::env::var("E2E_RUNNER").is_ok_and(|r| r == "fabric")
}

fn aviary() -> bool {
    std::env::var("E2E_HARNESS").is_ok_and(|r| r == "aviary")
}

/// `E2E_ONLY=chat` (with E2E_HARNESS=aviary): only the chat stack, kept up until interrupted (debugging hermit-jarvis
/// against a real magpie; no Fly token needed)
fn only_chat() -> bool {
    aviary() && std::env::var("E2E_ONLY").is_ok_and(|r| r == "chat")
}

/// e2e/aviary's front: the stand-in model and hermit-jarvis's gateway listener, as the machines reach the chat stack
const CHAT_FRONT: &str = "127.0.0.1:31085";
/// the chat stack's own WireGuard peer (aviary on Fly): machines reach e2e/aviary's front through it
const CHAT_PEER: &str = "jarvis2-e2e-kernel-chat";
const CHAT_GATEWAY_HEALTH: &str = "127.0.0.1:29084";

/// How Fly machines reach this run. On a Fly machine of the sessions' org (a session): straight over Fly's private
/// network to this machine's own 6PN address (the router's machines' port and e2e/aviary's front listen there; both
/// answer only signed or throwaway requests). Elsewhere (CI): throwaway WireGuard peers of the org, each served by
/// `router m-gateway`, as production's machines reach the router (the peers did not connect from a Fly machine,
/// 2026-11-11).
struct Net {
    /// the router as the machines know it (their JARVIS2_URL)
    machine_url: String,
    /// where the router listens for the machines
    machine_addr: String,
    /// e2e/aviary's front as the machines know it, and where it listens
    chat_url: String,
    front_addr: String,
    /// the peers and their m-gateways are this run's
    peers: bool,
}

fn net() -> Net {
    if fabric() {
        // the fabric's machines are sandboxes on this box: the router's fabric listener and the front on loopback
        return Net {
            machine_url: format!("http://{PEER}._peer.internal:8081"),
            machine_addr: MACHINES.into(),
            chat_url: format!("http://{CHAT_FRONT}"),
            front_addr: CHAT_FRONT.into(),
            peers: false,
        };
    }
    let six = std::env::var("FLY_MACHINE_ID")
        .ok()
        .zip(std::env::var("FLY_APP_NAME").ok());
    if let Some((id, app)) = six.filter(|(i, a)| !i.is_empty() && !a.is_empty()) {
        let host = format!("{id}.vm.{app}.internal");
        let ip = std::net::ToSocketAddrs::to_socket_addrs(&(host.as_str(), 0))
            .ok()
            .and_then(|mut a| a.find(std::net::SocketAddr::is_ipv6))
            .map(|a| a.ip().to_string())
            .unwrap_or_default();
        return Net {
            machine_url: format!("http://{host}:29081"),
            machine_addr: format!("[{ip}]:29081"),
            chat_url: format!("http://{host}:31085"),
            front_addr: format!("[{ip}]:31085"),
            peers: false,
        };
    }
    Net {
        machine_url: format!("http://{PEER}._peer.internal:8081"),
        machine_addr: MACHINES.into(),
        chat_url: format!("http://{CHAT_PEER}._peer.internal:8081"),
        front_addr: CHAT_FRONT.into(),
        peers: true,
    }
}

fn murl() -> String {
    net().machine_url
}

/// what the run started and must end
struct Cleanup {
    w: PathBuf,
    token: String,
    children: Vec<Child>,
    sudo: Vec<u32>,
    /// the chat stack is up (its namespace, NAT rules and Postgres to undo), with the tree's root
    chat: Option<PathBuf>,
    done: bool,
}

impl Cleanup {
    fn run(&mut self) {
        if self.done {
            return;
        }
        self.done = true;
        let logs = PathBuf::from(
            std::env::var("E2E_LOGS").unwrap_or_else(|_| "/tmp/jarvis2-e2e-kernel-logs".into()),
        );
        let _ = fs::create_dir_all(&logs);
        for e in fs::read_dir(&self.w).into_iter().flatten().flatten() {
            if e.path().extension().is_some_and(|x| x == "log") {
                let _ = fs::copy(e.path(), logs.join(e.file_name()));
            }
        }
        for c in &mut self.children {
            let _ = c.kill();
            let _ = c.wait();
        }
        for p in &self.sudo {
            let p = p.to_string();
            let _ = Command::new("sudo")
                .args(["-n", "pkill", "-P", &p])
                .status();
            let _ = Command::new("sudo").args(["-n", "kill", &p]).status();
        }
        if let Some(root) = &self.chat {
            chat::teardown(&self.w, root);
        }
        if fabric() {
            // the fake hermit's sandboxes: killed, deleted, their roots unmounted
            let rs = std::env::var("E2E_RUNSC").unwrap_or_else(|_| "/usr/local/bin/runsc".into());
            let root = self.w.join("fh").join("runsc");
            if let Ok(o) = Command::new("sudo")
                .arg("-n")
                .arg(&rs)
                .arg("--root")
                .arg(&root)
                .args(["list", "-q"])
                .output()
            {
                for id in String::from_utf8_lossy(&o.stdout).split_whitespace() {
                    for a in [vec!["kill", id, "KILL"], vec!["delete", "-force", id]] {
                        let _ = Command::new("sudo")
                            .arg("-n")
                            .arg(&rs)
                            .arg("--root")
                            .arg(&root)
                            .args(&a)
                            .status();
                    }
                }
            }
            for e in fs::read_dir(self.w.join("fh").join("sbx"))
                .into_iter()
                .flatten()
                .flatten()
            {
                // each sandbox's console with the logs (the boot's own account of itself)
                let _ = fs::copy(
                    e.path().join("console.log"),
                    logs.join(format!("console-{}.log", e.file_name().to_string_lossy())),
                );
                let _ = Command::new("sudo")
                    .args(["-n", "umount", "-l"])
                    .arg(e.path().join("root"))
                    .status();
            }
            let _ = Command::new("sudo")
                .args(["-n", "rm", "-rf"])
                .arg(&self.w)
                .status();
            return;
        }
        sweep(&self.token);
        for p in [PEER, CHAT_PEER] {
            let _ = Command::new("flyctl")
                .args(["wireguard", "remove", ORG, p])
                .env("FLY_API_TOKEN", &self.token)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        let _ = fs::remove_dir_all(&self.w);
    }
}

/// every machine in jarvis4-sessions whose JARVIS2_URL names this run's peer, destroyed with its volumes (earlier runs'
/// leftovers at the start, this run's own at the end). Never one naming another peer: production's name jarvis2-box.
fn sweep(token: &str) {
    let c = reqwest::blocking::Client::new();
    let Ok(r) = c.get(format!("{MAPI}/machines")).bearer_auth(token).send() else {
        return;
    };
    let Ok(ms) = r.json::<serde_json::Value>() else {
        return;
    };
    let want = murl();
    for m in ms.as_array().into_iter().flatten() {
        let env_url = m["config"]["env"]["JARVIS2_URL"].as_str().unwrap_or("");
        if m["state"] == "destroyed" || env_url != want {
            continue;
        }
        let Some(id) = m["id"].as_str() else { continue };
        if c.delete(format!("{MAPI}/machines/{id}?force=true"))
            .bearer_auth(token)
            .send()
            .is_ok_and(|r| r.status().is_success())
        {
            println!("e2e-kernel: destroyed leftover machine {id}");
        }
        for v in m["config"]["mounts"].as_array().into_iter().flatten() {
            let Some(v) = v["volume"].as_str().filter(|v| !v.is_empty()) else {
                continue;
            };
            for _ in 0..6 {
                if c.delete(format!("{MAPI}/volumes/{v}"))
                    .bearer_auth(token)
                    .send()
                    .is_ok_and(|r| r.status().is_success())
                {
                    println!("e2e-kernel: deleted its volume {v}");
                    break;
                }
                std::thread::sleep(Duration::from_secs(5));
            }
        }
    }
}

fn run_ok(c: &mut Command, what: &str) -> Result<()> {
    let st = c.status().with_context(|| what.to_string())?;
    if !st.success() {
        bail!("{what}: {st}");
    }
    Ok(())
}

fn output(c: &mut Command, what: &str) -> Result<String> {
    let o = c
        .stderr(Stdio::inherit())
        .output()
        .with_context(|| what.to_string())?;
    if !o.status.success() {
        bail!("{what}: {}", o.status);
    }
    Ok(String::from_utf8_lossy(&o.stdout).trim().to_string())
}

fn log_to(w: &Path, name: &str) -> Result<(Stdio, Stdio)> {
    let f = fs::File::create(w.join(format!("{name}.log")))?;
    Ok((f.try_clone()?.into(), f.into()))
}

fn ready(url: &str, limit: Duration) -> Result<()> {
    let c = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()?;
    let end = Instant::now() + limit;
    while Instant::now() < end {
        if c.get(url).send().is_ok_and(|r| r.status().is_success()) {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    bail!("{url} isn't up after {limit:?}")
}

fn hosts_exec(args: &[String]) -> Result<()> {
    let [hosts, uid, gid, sep, cmd @ ..] = args else {
        bail!("usage: e2e-kernel hosts-exec HOSTS UID GID -- CMD…")
    };
    if sep != "--" || cmd.is_empty() {
        bail!("usage: e2e-kernel hosts-exec HOSTS UID GID -- CMD…");
    }
    use nix::mount::{MsFlags, mount};
    mount(
        Some(hosts.as_str()),
        "/etc/hosts",
        None::<&str>,
        MsFlags::MS_BIND,
        None::<&str>,
    )
    .context("binding the hosts file")?;
    nix::unistd::setgroups(&[])?;
    nix::unistd::setgid(nix::unistd::Gid::from_raw(gid.parse()?))?;
    nix::unistd::setuid(nix::unistd::Uid::from_raw(uid.parse()?))?;
    let e = Command::new(&cmd[0]).args(&cmd[1..]).exec();
    bail!("exec {}: {e}", cmd[0])
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let r = if args.get(1).map(String::as_str) == Some("hosts-exec") {
        hosts_exec(&args[2..])
    } else if args.get(1).map(String::as_str) == Some("fake-hermit") {
        fake_hermit()
    } else {
        e2e()
    };
    if let Err(e) = r {
        eprintln!("e2e-kernel: {e:#}");
        std::process::exit(1);
    }
}

/// `e2e-kernel fake-hermit`, its settings in FH_* (set by the fabric run)
fn fake_hermit() -> Result<()> {
    let v = |k: &str| std::env::var(k).with_context(|| format!("{k} isn't set"));
    let config: serde_json::Value = serde_json::from_slice(&fs::read(v("FH_CONFIG")?)?)?;
    let list = |k: &str| -> Vec<String> {
        config["config"][k]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|x| x.as_str().map(str::to_owned))
            .collect()
    };
    let mut args = list("Entrypoint");
    args.extend(list("Cmd"));
    fakehermit::serve(fakehermit::Cfg {
        listen: FAKE_HERMIT.into(),
        work: PathBuf::from(v("FH_WORK")?),
        rootfs: PathBuf::from(v("FH_ROOTFS")?),
        args,
        env: list("Env"),
        digest: v("FH_DIGEST")?,
        proxy_at: FABRIC_LISTENER.into(),
        runsc: v("FH_RUNSC")?,
        magpie: v("FH_MAGPIE")?,
        admin: v("FH_ADMIN")?,
        tools: v("FH_TOOLS")?,
        gateway: std::env::var("FH_GATEWAY").unwrap_or_default(),
    })
}

/// The fabric image unpacked (its rootfs, once per digest) and its config: (ref@digest, rootfs, config.json)
fn fabric_image(root: &Path) -> Result<(String, PathBuf, PathBuf)> {
    let image = std::env::var("E2E_FABRIC_IMAGE")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "ghcr.io/de0ch/jarvis4-session-fabric:latest".into());
    let pinned = output(
        Command::new(root.join("infra/image-digest.sh")).arg(&image),
        "the fabric image's digest",
    )?;
    let digest = pinned
        .rsplit_once("@sha256:")
        .map(|(_, d)| d.to_owned())
        .context("no digest")?;
    let cache = std::env::var("E2E_FABRIC_CACHE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(std::env::var("HOME").unwrap_or_default())
                .join(".cache/jarvis4-e2e-fabric")
        });
    let dir = cache.join(&digest);
    let (rootfs, config) = (dir.join("rootfs"), dir.join("config.json"));
    if !dir.join(".done").exists() {
        let _ = Command::new("sudo")
            .args(["-n", "rm", "-rf"])
            .arg(&dir)
            .status();
        fs::create_dir_all(&rootfs)?;
        eprintln!("e2e-kernel: unpacking {pinned} (once per digest)");
        run_ok(
            Command::new("sh").arg("-c").arg(format!(
                "crane export '{pinned}' - | sudo -n tar -x -C '{}'",
                rootfs.display()
            )),
            "unpacking the fabric image",
        )?;
        fs::write(
            &config,
            output(
                Command::new("crane").args(["config", &pinned]),
                "the image's config",
            )?,
        )?;
        fs::write(dir.join(".done"), "")?;
    }
    Ok((pinned, rootfs, config))
}

fn e2e() -> Result<()> {
    let token = if fabric() || only_chat() {
        String::new()
    } else {
        std::env::var("JARVIS2_FLY_TOKEN")
            .ok()
            .filter(|t| !t.is_empty())
            .context("JARVIS2_FLY_TOKEN isn't set")?
    };
    let root = PathBuf::from(output(
        Command::new("git").args(["rev-parse", "--show-toplevel"]),
        "the repository",
    )?);
    let w = std::env::temp_dir().join(format!("e2e-kernel-{}", std::process::id()));
    fs::create_dir_all(&w)?;
    let cl = Arc::new(Mutex::new(Cleanup {
        w: w.clone(),
        token: token.clone(),
        children: vec![],
        sudo: vec![],
        chat: None,
        done: false,
    }));
    {
        let cl = cl.clone();
        let mut sigs = signal_hook::iterator::Signals::new([
            signal_hook::consts::SIGINT,
            signal_hook::consts::SIGTERM,
            signal_hook::consts::SIGHUP,
        ])?;
        std::thread::spawn(move || {
            if sigs.forever().next().is_some() {
                cl.lock().unwrap_or_else(|e| e.into_inner()).run();
                std::process::exit(130);
            }
        });
    }
    let r = steps(&root, &w, &token, &cl);
    cl.lock().unwrap_or_else(|e| e.into_inner()).run();
    r
}

fn steps(root: &Path, w: &Path, token: &str, cl: &Arc<Mutex<Cleanup>>) -> Result<()> {
    let start = |c: &mut Command, name: &str| -> Result<()> {
        let (o, e) = log_to(w, name)?;
        let child = c
            .stdout(o)
            .stderr(e)
            .spawn()
            .with_context(|| format!("starting {name}"))?;
        cl.lock()
            .unwrap_or_else(|e| e.into_inner())
            .children
            .push(child);
        Ok(())
    };
    if !fabric() && !only_chat() {
        sweep(token);
    }
    for r in ROLES {
        run_ok(
            Command::new("go")
                .args(["build", "-o"])
                .arg(w.join(r))
                .arg(format!("./cmd/{r}"))
                .current_dir(root.join("kernel")),
            &format!("building the {r}"),
        )?;
    }
    run_ok(
        Command::new("go")
            .args(["build", "-o"])
            .arg(w.join("router"))
            .arg(".")
            .current_dir(root.join("router")),
        "building the router",
    )?;
    run_ok(
        Command::new("go")
            .args(["build", "-o"])
            .arg(w.join("driver"))
            .arg(if aviary() { "./aviary" } else { "./kernel" })
            .current_dir(root.join("e2e")),
        "building e2e/kernel",
    )?;
    let box_key = w.join("box-key.pem");
    let root_key = w.join("root-key.pem");
    fs::write(&box_key, jarvis_sig::Signer::generate().to_pkcs8_pem())?;
    let rk = jarvis_sig::Signer::generate();
    fs::write(&root_key, rk.to_pkcs8_pem())?;
    let kernel_root = rk.public_key();
    let policy = w.join("policy.json");
    fs::write(
        &policy,
        if aviary() {
            r#"{"harnesses":{"aviary":{"stores":["aviary-gw"],"claudeAccount":true}}}"#
        } else {
            r#"{"harnesses":{"claude":{"stores":[],"claudeAccount":true},"opencode":{"stores":[]}}}"#
        },
    )?;
    let fly = |args: &[&str]| {
        let mut c = Command::new("flyctl");
        c.args(args).env("FLY_API_TOKEN", token);
        c
    };
    let wg = w.join("wg.conf");
    let wg_chat = w.join("wg-chat.conf");
    let net = net();
    if net.peers && !only_chat() {
        let mut peers = vec![(PEER, &wg)];
        if aviary() {
            peers.push((CHAT_PEER, &wg_chat));
        }
        for (p, conf) in peers {
            let _ = fly(&["wireguard", "remove", ORG, p])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            run_ok(
                fly(&["wireguard", "create", ORG, "lhr", p])
                    .arg(conf)
                    .stdout(Stdio::null()),
                "the WireGuard peer",
            )?;
        }
    }
    // the fabric replica: the fake hermit on the unpacked fabric image, with tokens of this run
    let fabric_tokens = {
        let r = |n: &str| format!("e2e-{n}-{}", std::process::id());
        (r("magpie"), r("admin"), r("tools"), r("gateway"))
    };
    let mut fabric_image_ref = String::new();
    if fabric() {
        let (pinned, rootfs, config) = fabric_image(root)?;
        fabric_image_ref = pinned.clone();
        let me = std::env::current_exe()?;
        start(
            Command::new(&me)
                .arg("fake-hermit")
                .env("FH_WORK", w.join("fh"))
                .env("FH_ROOTFS", &rootfs)
                .env("FH_CONFIG", &config)
                .env(
                    "FH_DIGEST",
                    format!(
                        "sha256:{}",
                        pinned.rsplit_once("@sha256:").map_or("", |x| x.1)
                    ),
                )
                .env(
                    "FH_RUNSC",
                    std::env::var("E2E_RUNSC").unwrap_or_else(|_| "/usr/local/bin/runsc".into()),
                )
                .env("FH_MAGPIE", &fabric_tokens.0)
                .env("FH_ADMIN", &fabric_tokens.1)
                .env("FH_TOOLS", &fabric_tokens.2)
                .env("FH_GATEWAY", &fabric_tokens.3),
            "fake-hermit",
        )?;
    }
    // the chat stack, its hermit-jarvis asking the fake hermit for its sandboxes' control hashes
    let mut chat_keys = chat::Chat::default();
    if aviary() {
        cl.lock().unwrap_or_else(|e| e.into_inner()).chat = Some(root.to_owned());
        let extra: Vec<String> = if fabric() {
            vec![
                format!("FABRIC_HERMIT_URL=http://{FAKE_HERMIT}"),
                format!("FABRIC_HERMIT_GATEWAY_TOKEN={}", fabric_tokens.3),
            ]
        } else {
            vec![]
        };
        let mut spawn = |c: &mut Command, name: &str, under_sudo: bool| -> Result<()> {
            let (o, e) = log_to(w, name)?;
            let child = c
                .stdout(o)
                .stderr(e)
                .spawn()
                .with_context(|| format!("starting {name}"))?;
            let mut g = cl.lock().unwrap_or_else(|e| e.into_inner());
            if under_sudo {
                g.sudo.push(child.id());
            } else {
                g.children.push(child);
            }
            Ok(())
        };
        chat_keys = chat::up(root, w, &extra, &mut spawn)?;
        if only_chat() {
            println!(
                "e2e-kernel: chat stack up (Ctrl-C ends it): magpie 10.88.0.2:8080 (admin token {}), hermit-jarvis \
                 127.0.0.1:8080; logs in {}",
                chat_keys.magpie_admin,
                w.display()
            );
            loop {
                std::thread::sleep(Duration::from_secs(3600));
            }
        }
    }

    // the kernel: each component on 127.0.1.<n>:28080, its state in its own directory
    let mut hosts = fs::read_to_string("/etc/hosts").unwrap_or_default();
    let mut kaddrs = String::new();
    for (i, r) in ROLES.iter().enumerate() {
        let n = i + 1;
        let data = w.join(format!("k-{r}"));
        fs::create_dir_all(&data)?;
        let mut c = Command::new(w.join(r));
        c.env("KERNEL_ROOT", &kernel_root)
            .env("KERNEL_BOX_KEY", &box_key)
            .env("KERNEL_DATA", &data)
            .env("KERNEL_ADDR", format!("127.0.1.{n}:28080"));
        if *r == "spawner" {
            c.env("KERNEL_MACHINE_URL", murl());
            if fabric() {
                c.env("KERNEL_FABRIC_HERMIT_URL", format!("http://{FAKE_HERMIT}"))
                    .env(
                        "KERNEL_FABRIC_MACHINE_URL",
                        format!("http://{FABRIC_LISTENER}"),
                    );
            }
        }
        if *r == "secrets" {
            c.env("KERNEL_MINTER_URL", "http://127.0.1.8:28080"); // the minter is the 8th
        }
        start(&mut c, &format!("kernel-{r}"))?;
        // the router calls a Deployment "<role>-<copy>": this run is copy blue
        hosts.push_str(&format!("127.0.1.{n} {r}-blue.kernel.e2e\n"));
        kaddrs.push_str(&format!("{r}=http://127.0.1.{n}:28080,"));
    }
    let hosts_file = w.join("hosts");
    fs::write(&hosts_file, &hosts)?;
    let image = std::env::var("E2E_SESSION_IMAGE")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "ghcr.io/de0ch/jarvis4-session:latest".into());
    let image = output(
        Command::new(root.join("infra/image-digest.sh")).arg(&image),
        "the session image's digest",
    )?;
    let db = output(
        Command::new(root.join("infra/test-postgres.sh")).args(["fresh", "e2e_kernel"]),
        "the router's database",
    )?;
    let data = w.join("data");
    let web = w.join("web");
    fs::create_dir_all(&data)?;
    fs::create_dir_all(&web)?;
    // the router in its own mount namespace, whose /etc/hosts names the kernel's components
    let me = std::env::current_exe()?;
    let path = std::env::var("PATH").unwrap_or_default();
    let home = std::env::var("HOME").unwrap_or_default();
    let kv =
        |k: &str, v: &dyn AsRef<std::ffi::OsStr>| format!("{k}={}", v.as_ref().to_string_lossy());
    let mut router_env = vec![
        kv("PATH", &path),
        kv("HOME", &home),
        kv("DATABASE_URL", &db),
        "ROUTER_THROWAWAY=1".into(),
        "KERNEL_URL=http://%s.kernel.e2e:28080".into(),
        "NO_ACCESS=1".into(),
        // no core, as production's router (k8s/cluster/router/router.yaml): the store calls go to the kernel's
        // secrets (a session from the chat reads the store list for its defaults; the core's address is no one's here)
        "NO_CORE=1".into(),
        "RECORDS_OFF=1".into(),
        kv("ADDR", &ROUTER),
        kv("MACHINE_ADDR", &net.machine_addr),
        kv("DATA_DIR", &data),
        kv("WEB_DIR", &web),
        kv("MACHINE_URL", &murl()),
        kv("POLICY_FILE", &policy),
        kv("TASKS_DIR", &root.join("tasks")),
        kv("SESSION_IMAGE", &image),
    ];
    if fabric() {
        router_env.extend([
            // a session the router proposes with the defaults (a conversation begun in the chat) runs here too
            "DEFAULT_RUNNER=fabric".into(),
            format!("FABRIC_HERMIT_URL=http://{FAKE_HERMIT}"),
            kv("FABRIC_HERMIT_TOOLS_TOKEN", &fabric_tokens.2),
            kv("FABRIC_HERMIT_MAGPIE_TOKEN", &fabric_tokens.0),
            kv("FABRIC_MACHINE_ADDR", &FABRIC_LISTENER),
            kv("FABRIC_SESSION_IMAGE", &fabric_image_ref),
        ]);
    }
    let uid = nix::unistd::Uid::current().to_string();
    let gid = nix::unistd::Gid::current().to_string();
    {
        let (o, e) = log_to(w, "router")?;
        let child = Command::new("sudo")
            .args(["-n", "unshare", "-m", "--propagation", "private"])
            .arg(&me)
            .arg("hosts-exec")
            .arg(&hosts_file)
            .args([&uid, &gid, "--", "env", "-i"])
            .args(&router_env)
            .arg(w.join("router"))
            .stdout(o)
            .stderr(e)
            .spawn()
            .context("starting the router")?;
        cl.lock()
            .unwrap_or_else(|e| e.into_inner())
            .sudo
            .push(child.id());
    }
    // the machines' WireGuard peers run in the gateway (router/mgateway.go), as on the cluster: one passing /m to the
    // router, and for aviary one passing the chat stack's calls to e2e/aviary's front
    if net.peers {
        start(
            Command::new(w.join("router"))
                .arg("m-gateway")
                .env("POD_NAME", "m-gateway-0")
                .env("WG_CONFIGS", &wg)
                .env("M_GATEWAY_TO", format!("http://{MACHINES}"))
                .env("HEALTH_ADDR", GATEWAY_HEALTH),
            "m-gateway",
        )?;
        if aviary() {
            start(
                Command::new(w.join("router"))
                    .arg("m-gateway")
                    .env("POD_NAME", "m-gateway-0")
                    .env("WG_CONFIGS", &wg_chat)
                    .env("M_GATEWAY_TO", format!("http://{CHAT_FRONT}"))
                    .env("HEALTH_ADDR", CHAT_GATEWAY_HEALTH),
                "m-gateway-chat",
            )?;
        }
    }
    ready(
        &format!("http://{ROUTER}/api/kernel"),
        Duration::from_secs(60),
    )?;

    let mut driver = Command::new(w.join("driver"))
        .env("E2E_ROUTER", format!("http://{ROUTER}"))
        .env("E2E_SPAWNER", "http://127.0.1.5:28080")
        .env("E2E_DATA_DIR", &data)
        .env("E2E_DATABASE_URL", &db)
        .env("ROUTER_THROWAWAY", "1")
        .env(
            "E2E_MASTER_KEY_FILE",
            root.join("e2e/testdata/master-test.pem"),
        )
        .env("E2E_ROOT_KEY_FILE", &root_key)
        .env("E2E_KERNEL", &kaddrs)
        .env("E2E_FLY_TOKEN", token)
        .env("E2E_RUNNER", if fabric() { "fabric" } else { "" })
        .env("E2E_FABRIC_MAGPIE", &fabric_tokens.0)
        .env("E2E_FABRIC_ADMIN", &fabric_tokens.1)
        .env("E2E_FRONT_ADDR", &net.front_addr)
        .env("E2E_HERMIT_GW", "http://127.0.0.1:8081")
        .env("E2E_CHAT_URL", &net.chat_url)
        .env("E2E_MAGPIE", "http://10.88.0.2:8080")
        .env("E2E_MAGPIE_ADMIN", &chat_keys.magpie_admin)
        .env("E2E_MAGPIE_PIGEON", &chat_keys.magpie_pigeon)
        .env("E2E_OWNER", chat::OWNER)
        .spawn()
        .context("starting e2e/kernel")?;
    let st = driver.wait()?;
    if !st.success() {
        bail!("e2e/kernel: {st}");
    }
    println!("e2e-kernel: ok");
    Ok(())
}
