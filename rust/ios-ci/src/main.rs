//! ios-ci: the app's CI stand-ins and the phone replica's throwaway Jarvis 4, on the runner (ios.yml, transitions.yml;
//! it replaces ios/ci/standins.sh and ios/ci/replica-stack.sh). Everything is the run's own and throwaway.
//!
//!   ios-ci standins W         the stand-ins of the app's tests, all on 127.0.0.1:
//!       - a box key and a setup key (ios/ci/standin.py keys); their public halves served at :18099 in place of GitHub
//!         (the CI build only, KeySource.swift);
//!       - the backup bucket on rclone's S3 server at :18098 (it checks SigV4), seeded with infra/setup.py's own code,
//!         encrypted to the public TEST master key; read keys in W/s3.env (ACCESS_KEY=/SECRET_KEY=), which the router
//!         gets as BACKUP_READ_* (W/router-backup.env); every bucket's objects also in W/backups.json; the seeded
//!         bucket kept (W/s3-seeded) for `ios-ci s3-fresh W`;
//!       - the core (fakefly) and router binaries at W/core and W/router. Unless NO_CORE=1 the core (:8090, empty) and
//!         a router (:18080, or ROUTER_PORT; reading the stand-in bucket) are started.
//!   ios-ci s3-fresh W         the stand-in bucket back to its seeded state (each walkthrough attempt starts from it)
//!   ios-ci core-loop W LOG    the core, started again whenever it ends (a wipe ends the core and Kubernetes starts a
//!                             new, empty one in production); its output appended to LOG
//!   ios-ci replica up W       the phone replica's stack (ios.yml job `replica`): the real core and router built from
//!                             this commit (no fakefly), real Fly session machines in jarvis4-sessions reaching the
//!                             router over a WireGuard peer of the Fly org that `router m-gateway` serves in userspace,
//!                             as on the cluster; writes W/env for the setup answers (rust/replica-setup)
//!   ios-ci replica down W     this run's machines and their volumes, its peer, the processes; idempotent. Also the
//!                             run's volumes whose machine is already gone (infra/run-volumes.py: only ids this run's
//!                             router state and core log name, so never production's)
//!   ios-ci replica sweep      every earlier replica run's leftovers (machines naming a jarvis4-replica-* peer, and
//!                             those peers): one run at a time (ios.yml's concurrency group), so none is in flight.
//!                             NOT an earlier run's bare volume (its machine gone): Fly keeps no label on a volume
//!                             (docs/RUNBOOK.md "Leftover volumes"); `down` deletes them while the run's records exist
//!
//!   ios-ci rostervec | vectors | fakekernel   the kernel's side of the app's tests (kernel.rs)
//!
//! Env of `replica`: REPLICA_FLY_TOKEN (an org token of jarvis2-370: peers, machines, exec), REPLICA_RUN (digits and
//! dashes). The router runs NO_ACCESS=1 on the loopback address: the simulator talks to it directly (app/DECISIONS.md
//! "The phone replica").

use anyhow::{Context, Result, anyhow, bail};
use std::fs;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const ORG: &str = "jarvis2-370";
const MAPI: &str = "https://api.machines.dev/v1/apps/jarvis4-sessions";
const CORE: &str = "127.0.0.1:8090";
const S3: &str = "127.0.0.1:18098";
const KEYS: &str = "127.0.0.1:18099";
/// the stand-ins' machines' router address (no machine ever dials it: fakefly)
const STANDIN_MURL: &str = "http://ci-router._peer.internal:8081";

mod kernel;

fn main() {
    let mut a: Vec<String> = std::env::args().collect();
    // run as `rostervec` (a link to this binary: the Swift test runs it with rostervec's args alone)
    if Path::new(&a[0])
        .file_name()
        .is_some_and(|n| n == "rostervec")
    {
        a[0] = "rostervec".into();
    } else {
        a.remove(0);
    }
    let s: Vec<&str> = a.iter().map(String::as_str).collect();
    let res = match s.as_slice() {
        ["rostervec", rest @ ..] => kernel::rostervec(rest),
        ["vectors"] => kernel::vectors(),
        ["fakekernel", addr] => kernel::fakekernel(addr, None),
        ["fakekernel", addr, router] => kernel::fakekernel(addr, Some(router)),
        ["standins", w] => standins(Path::new(w)),
        ["s3-fresh", w] => s3_fresh(Path::new(w)),
        ["core-loop", w, log] => core_loop(Path::new(w), Path::new(log), STANDIN_MURL),
        ["core-loop", w, log, murl] => core_loop(Path::new(w), Path::new(log), murl),
        ["replica", "up", w] => replica_up(Path::new(w)),
        ["replica", "down", w] => replica_down(Path::new(w)),
        ["replica", "sweep"] => replica_sweep(),
        _ => Err(anyhow!(
            "usage: ios-ci standins W | s3-fresh W | core-loop W LOG [MACHINE_URL] | replica up|down W | replica sweep | \
             rostervec [-open ROOTPUB] | vectors | fakekernel ADDR [ROUTER]"
        )),
    };
    if let Err(e) = res {
        eprintln!("ios-ci: {e:#}");
        std::process::exit(1);
    }
}

/// the repository's root (this binary is built and run from a checkout: rust/target/…/ios-ci)
fn root() -> Result<PathBuf> {
    let out = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()?;
    if !out.status.success() {
        bail!("not in the repository");
    }
    Ok(PathBuf::from(String::from_utf8_lossy(&out.stdout).trim()))
}

fn run(c: &mut Command, what: &str) -> Result<()> {
    let st = c.status().with_context(|| what.to_string())?;
    if !st.success() {
        bail!("{what}: {st}");
    }
    Ok(())
}

fn output(c: &mut Command, what: &str) -> Result<String> {
    let o = c.output().with_context(|| what.to_string())?;
    if !o.status.success() {
        bail!(
            "{what}: {} {}",
            o.status,
            String::from_utf8_lossy(&o.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&o.stdout).trim().to_string())
}

/// a process left running after this one ends (its own process group, no stdin), its pid in pidfile
fn detach(c: &mut Command, log: &Path, pidfile: Option<&Path>) -> Result<u32> {
    let f = fs::OpenOptions::new().create(true).append(true).open(log)?;
    let child = c
        .stdin(Stdio::null())
        .stdout(f.try_clone()?)
        .stderr(f)
        .process_group(0)
        .spawn()?;
    if let Some(p) = pidfile {
        fs::write(p, child.id().to_string())?;
    }
    Ok(child.id())
}

fn have(tool: &str) -> bool {
    Command::new("sh")
        .args(["-c", &format!("command -v {tool}")])
        .stdout(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn brew(tool: &str) -> Result<()> {
    if !have(tool) {
        run(
            Command::new("brew").args(["install", tool]),
            &format!("brew install {tool}"),
        )?;
    }
    Ok(())
}

/// GET url answers 2xx within secs
fn up(url: &str, secs: u64) -> bool {
    let c = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(2))
        .build();
    let Ok(c) = c else { return false };
    let end = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < end {
        if c.get(url).send().is_ok_and(|r| r.status().is_success()) {
            return true;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    false
}

/// any answer at all (rclone's S3 root answers 403 to an unsigned GET)
fn answers(url: &str, secs: u64) -> bool {
    let Ok(c) = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
    else {
        return false;
    };
    let end = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < end {
        if c.get(url).send().is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    false
}

fn tail(p: &Path, n: usize) -> String {
    let s = fs::read_to_string(p).unwrap_or_default();
    let lines: Vec<&str> = s.lines().collect();
    lines[lines.len().saturating_sub(n)..].join("\n")
}

fn hex_secret() -> String {
    (0..16)
        .map(|_| format!("{:02x}", rand::random::<u8>()))
        .collect()
}

/// a venv with what ios/ci/standin.py and infra/setup.py import → its python
fn venv(w: &Path) -> Result<PathBuf> {
    run(
        Command::new("python3")
            .args(["-m", "venv"])
            .arg(w.join("venv")),
        "python3 -m venv",
    )?;
    let py = w.join("venv/bin/python");
    run(
        Command::new(w.join("venv/bin/pip")).args(["-q", "install", "cryptography", "boto3"]),
        "pip install",
    )?;
    Ok(py)
}

fn standin_keys(py: &Path, root: &Path, w: &Path) -> Result<()> {
    run(
        Command::new(py)
            .arg("-B")
            .arg(root.join("ios/ci/standin.py"))
            .arg("keys")
            .arg(w),
        "standin.py keys",
    )
}

/// the S3 stand-in serving W/s3 with these keys
fn rclone(w: &Path, access: &str, secret: &str) -> Result<()> {
    detach(
        Command::new("rclone")
            .args(["serve", "s3", "--addr", S3, "--auth-key"])
            .arg(format!("{access},{secret}"))
            .arg(w.join("s3")),
        &w.join("s3.log"),
        Some(&w.join("s3.pid")),
    )?;
    Ok(())
}

/// the core (fakefly for the stand-ins) and the router of this commit (rust/router, as its image builds it)
fn build(root: &Path, w: &Path, fakefly: bool) -> Result<()> {
    let mut go = Command::new("go");
    go.arg("build");
    if fakefly {
        go.args(["-tags", "fakefly"]);
    }
    run(
        go.arg("-o")
            .arg(w.join("core"))
            .arg(".")
            .current_dir(root.join("core")),
        "building the core",
    )?;
    run(
        Command::new("cargo")
            .args([
                "build",
                "--profile",
                "router",
                "--locked",
                "-p",
                "jarvis-router",
            ])
            .current_dir(root.join("rust")),
        "building the router",
    )?;
    let target = std::env::var("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| root.join("rust/target"));
    fs::copy(target.join("router/router"), w.join("router")).context("the router binary")?;
    Ok(())
}

/// a fresh database on the throwaway Postgres (infra/test-postgres.sh) → its URL
fn fresh_db(root: &Path, name: &str) -> Result<String> {
    output(
        Command::new("bash")
            .arg(root.join("infra/test-postgres.sh"))
            .args(["fresh", name]),
        "infra/test-postgres.sh fresh",
    )
}

fn env_file(p: &Path) -> Vec<(String, String)> {
    fs::read_to_string(p)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| {
            l.split_once('=')
                .map(|(k, v)| (k.to_string(), v.to_string()))
        })
        .collect()
}

fn standins(w: &Path) -> Result<()> {
    let root = root()?;
    fs::create_dir_all(w)?;
    let py = venv(w)?;
    brew("rclone")?;
    standin_keys(&py, &root, w)?;
    let secret = hex_secret();
    fs::write(
        w.join("s3.env"),
        format!("ACCESS_KEY=ciaccess\nSECRET_KEY={secret}\n"),
    )?;
    fs::create_dir_all(w.join("s3"))?;
    rclone(w, "ciaccess", &secret)?;
    detach(
        Command::new(&py)
            .args(["-m", "http.server", "--bind", "127.0.0.1", "--directory"])
            .arg(w.join("keys"))
            .arg("18099"),
        &w.join("keys-server.log"),
        None,
    )?;
    if !answers(&format!("http://{S3}/"), 30) || !up(&format!("http://{KEYS}/box.pub"), 30) {
        bail!("the S3 stand-in or the keys' server didn't come up");
    }
    run(
        Command::new(&py)
            .arg("-B")
            .arg(root.join("ios/ci/standin.py"))
            .arg("seed")
            .arg(w)
            .env("HETZNER_S3_ENDPOINT", format!("http://{S3}"))
            .env("HETZNER_S3_REGION", "fsn1")
            .env("HETZNER_S3_ACCESS_KEY", "ciaccess")
            .env("HETZNER_S3_SECRET_KEY", &secret),
        "standin.py seed",
    )?;
    // the seeded bucket, kept: a bucket a failed attempt left behind holds that attempt's backups and the router's
    // line state, which names the fake Fly's machine ids; the next attempt's fresh core numbers its machines from
    // fake000001 again, so the Recover that brings that line state back makes the core refuse to certify the new
    // session ("not a started machine without a line")
    let seeded = w.join("s3-seeded");
    let _ = fs::remove_dir_all(&seeded);
    copy_dir(&w.join("s3"), &seeded)?;
    build(&root, w, true)?;
    fs::write(
        w.join("router-backup.env"),
        format!(
            "BACKUP_READ_ACCESS_KEY=ciaccess\nBACKUP_READ_SECRET_KEY={secret}\nBACKUP_ENDPOINT=http://{S3}\nBACKUP_BUCKET=jarvis2-backup-ci\n"
        ),
    )?;
    if std::env::var("NO_CORE").as_deref() == Ok("1") {
        return Ok(());
    }
    detach(
        Command::new(w.join("core"))
            .env("BOX_KEY_FILE", w.join("box-key.pem"))
            .env("MACHINE_URL", STANDIN_MURL)
            .env("ADDR", CORE),
        &w.join("core.log"),
        Some(&w.join("core.pid")),
    )?;
    if !up(&format!("http://{CORE}/identity"), 30) {
        bail!(
            "the core didn't come up:\n{}",
            tail(&w.join("core.log"), 20)
        );
    }
    fs::create_dir_all(w.join("router-data"))?;
    fs::create_dir_all(w.join("web"))?;
    fs::write(
        w.join("policy.json"),
        r#"{"harnesses":{"claude":{"stores":["claude-login"]}}}"#,
    )?;
    let db = fresh_db(&root, "router_standins")?;
    let port: u16 = std::env::var("ROUTER_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(18080);
    let mut c = Command::new(w.join("router"));
    c.envs(env_file(&w.join("router-backup.env")))
        .env("DATABASE_URL", db)
        .env("ROUTER_THROWAWAY", "1")
        .env("NO_ACCESS", "1")
        .env("CORE_URL", format!("http://{CORE}"))
        .env("DATA_DIR", w.join("router-data"))
        .env("WEB_DIR", w.join("web"))
        .env("POLICY_FILE", w.join("policy.json"))
        .env("TASKS_DIR", root.join("tasks"))
        .env("ADDR", format!("127.0.0.1:{port}"))
        .env("MACHINE_ADDR", format!("127.0.0.1:{}", port + 1));
    detach(&mut c, &w.join("router.log"), Some(&w.join("router.pid")))?;
    if !up(&format!("http://127.0.0.1:{port}/api/state"), 30) {
        bail!(
            "the router didn't come up:\n{}",
            tail(&w.join("router.log"), 20)
        );
    }
    println!("core and router up");
    Ok(())
}

fn copy_dir(from: &Path, to: &Path) -> Result<()> {
    fs::create_dir_all(to)?;
    for e in fs::read_dir(from)? {
        let e = e?;
        let t = to.join(e.file_name());
        if e.file_type()?.is_dir() {
            copy_dir(&e.path(), &t)?;
        } else {
            fs::copy(e.path(), t)?;
        }
    }
    Ok(())
}

fn kill_pidfile(p: &Path) {
    if let Ok(pid) = fs::read_to_string(p) {
        let pid = pid.trim();
        if !pid.is_empty() {
            let _ = Command::new("kill").arg(pid).stderr(Stdio::null()).status();
        }
    }
}

/// rclone stopped (it caches the directory), the seeded files put back, started again with the same keys
fn s3_fresh(w: &Path) -> Result<()> {
    let env = env_file(&w.join("s3.env"));
    let get = |k: &str| {
        env.iter()
            .find(|(x, _)| x == k)
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    };
    kill_pidfile(&w.join("s3.pid"));
    std::thread::sleep(Duration::from_secs(1));
    let _ = fs::remove_dir_all(w.join("s3"));
    copy_dir(&w.join("s3-seeded"), &w.join("s3"))?;
    rclone(w, &get("ACCESS_KEY"), &get("SECRET_KEY"))?;
    if !answers(&format!("http://{S3}/"), 30) {
        bail!("the stand-in bucket didn't come back");
    }
    Ok(())
}

/// the core, started again whenever it ends; runs until killed
fn core_loop(w: &Path, log: &Path, murl: &str) -> Result<()> {
    loop {
        let f = fs::OpenOptions::new().create(true).append(true).open(log)?;
        let _ = Command::new(w.join("core"))
            .env("BOX_KEY_FILE", w.join("box-key.pem"))
            .env("MACHINE_URL", murl)
            .env("ADDR", CORE)
            .stdin(Stdio::null())
            .stdout(f.try_clone()?)
            .stderr(f)
            .status();
        std::thread::sleep(Duration::from_secs(1));
    }
}

// ---- the phone replica ---------------------------------------------------------------------------------------------

fn fly_token() -> Result<String> {
    let t = std::env::var("REPLICA_FLY_TOKEN").unwrap_or_default();
    if t.is_empty() {
        bail!("REPLICA_FLY_TOKEN is not set");
    }
    Ok(t)
}

fn run_id() -> Result<String> {
    let r = std::env::var("REPLICA_RUN").unwrap_or_default();
    if r.is_empty() || !r.chars().all(|c| c.is_ascii_digit() || c == '-') {
        bail!("REPLICA_RUN must be digits and dashes");
    }
    Ok(r)
}

fn http() -> Result<reqwest::blocking::Client> {
    Ok(reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(60))
        .build()?)
}

/// the machines whose router address names a peer the regex matches, and then their volumes (a force destroy leaves
/// a machine's state volume behind)
fn destroy_machines(token: &str, peer_re: &str) -> Result<()> {
    let want = regex::Regex::new(&format!(r"^http://({peer_re})\._peer\.internal:8081$"))?;
    let c = http()?;
    let ms: serde_json::Value = c
        .get(format!("{MAPI}/machines"))
        .bearer_auth(token)
        .send()?
        .error_for_status()?
        .json()?;
    for m in ms.as_array().cloned().unwrap_or_default() {
        let url = m["config"]["env"]["JARVIS2_URL"]
            .as_str()
            .unwrap_or_default();
        if m["state"] == "destroyed" || !want.is_match(url) {
            continue;
        }
        let id = m["id"].as_str().unwrap_or_default();
        if c.delete(format!("{MAPI}/machines/{id}?force=true"))
            .bearer_auth(token)
            .send()
            .is_ok_and(|r| r.status().is_success())
        {
            println!("machine {id} destroyed");
        }
        for mount in m["config"]["mounts"]
            .as_array()
            .cloned()
            .unwrap_or_default()
        {
            let Some(v) = mount["volume"].as_str().filter(|v| !v.is_empty()) else {
                continue;
            };
            for _ in 0..6 {
                if c.delete(format!("{MAPI}/volumes/{v}"))
                    .bearer_auth(token)
                    .send()
                    .is_ok_and(|r| r.status().is_success())
                {
                    println!("its volume {v} deleted");
                    break;
                }
                std::thread::sleep(Duration::from_secs(5));
            }
        }
    }
    Ok(())
}

fn flyctl(token: &str) -> Command {
    let mut c = Command::new("flyctl");
    c.env("FLY_API_TOKEN", token);
    c
}

fn replica_sweep() -> Result<()> {
    let token = fly_token()?;
    destroy_machines(&token, "jarvis4-replica-[0-9-]+")?;
    let peers = flyctl(&token)
        .args(["wireguard", "list", ORG, "--json"])
        .stderr(Stdio::null())
        .output()?;
    let v: serde_json::Value = serde_json::from_slice(&peers.stdout).unwrap_or_default();
    let re = regex::Regex::new(r"^jarvis4-replica-[0-9-]+$")?;
    for p in v.as_array().cloned().unwrap_or_default() {
        let n = p["Name"]
            .as_str()
            .or_else(|| p["name"].as_str())
            .unwrap_or_default();
        if re.is_match(n)
            && flyctl(&token)
                .args(["wireguard", "remove", ORG, n])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok_and(|s| s.success())
        {
            println!("peer {n} removed");
        }
    }
    Ok(())
}

fn replica_down(w: &Path) -> Result<()> {
    let token = fly_token()?;
    let peer = format!("jarvis4-replica-{}", run_id()?);
    if let Ok(rd) = fs::read_dir(w) {
        for e in rd.flatten() {
            if e.path().extension().is_some_and(|x| x == "pid") {
                kill_pidfile(&e.path());
            }
        }
    }
    for p in ["core", "router"] {
        let _ = Command::new("pkill")
            .arg("-f")
            .arg(w.join(p))
            .stderr(Stdio::null())
            .status();
    }
    if let Err(e) = destroy_machines(&token, &regex::escape(&peer)) {
        eprintln!("machines: {e:#}");
    }
    let root = root()?;
    let _ = Command::new("python3")
        .arg("-I")
        .arg(root.join("infra/run-volumes.py"))
        .arg(w.join("data/state.json"))
        .arg(w.join("core.log"))
        .env("FLY_TOKEN", &token)
        .status();
    if flyctl(&token)
        .args(["wireguard", "remove", ORG, &peer])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
    {
        println!("peer {peer} removed");
    }
    for f in [
        "fly.tok",
        "fly-read",
        "wg.conf",
        "box-key.pem",
        "setup-key.pem",
    ] {
        let _ = fs::remove_file(w.join(f));
    }
    Ok(())
}

/// a value of the router's manifest (`name: K, value: "V"`)
fn manifest_value(text: &str, k: &str) -> Option<String> {
    let re = regex::Regex::new(&format!(r#"name: {k}, value: "([^"]*)""#)).ok()?;
    re.captures(text)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
}

fn replica_up(w: &Path) -> Result<()> {
    let token = fly_token()?;
    let peer = format!("jarvis4-replica-{}", run_id()?);
    let murl = format!("http://{peer}._peer.internal:8081");
    let root = root()?;
    let home = PathBuf::from(std::env::var("HOME").unwrap_or_default());
    fs::create_dir_all(w)?;
    fs::create_dir_all(home.join(".jarvis2"))?;
    for d in [w.to_path_buf(), home.join(".jarvis2")] {
        run(Command::new("chmod").arg("700").arg(&d), "chmod")?;
    }
    let py = venv(w)?;
    standin_keys(&py, &root, w)?;
    brew("rclone")?;
    brew("flyctl")?;

    println!("== the backup bucket (rclone's S3 server, this run's key)");
    let secret = hex_secret();
    fs::create_dir_all(w.join("s3/jarvis2-backup-replica"))?;
    rclone(w, "replica", &secret)?;

    println!(
        "== the WireGuard peer {peer} (the machines reach the router as {peer}._peer.internal)"
    );
    let _ = flyctl(&token)
        .args(["wireguard", "remove", ORG, &peer])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    run(
        flyctl(&token)
            .args(["wireguard", "create", ORG, "lhr", &peer])
            .arg(w.join("wg.conf"))
            .stdout(Stdio::null()),
        "flyctl wireguard create",
    )?;
    run(
        Command::new("chmod").arg("600").arg(w.join("wg.conf")),
        "chmod",
    )?;

    println!(
        "== the core's Fly token (narrowed as production's, 6 hours) and the router's read-only one"
    );
    run(
        Command::new("bash")
            .arg(root.join("infra/fly-token.sh"))
            .arg(w.join("fly.tok"))
            .env("JARVIS2_FLY_TOKEN", &token)
            .env("FLY_TOKEN_HOURS", "6"),
        "infra/fly-token.sh",
    )?;
    run(
        Command::new("bash")
            .arg(root.join("infra/fly-read-token.sh"))
            .arg(w.join("fly-read"))
            .env("JARVIS2_FLY_TOKEN", &token),
        "infra/fly-read-token.sh",
    )?;

    println!("== the core and the router, built from this commit");
    build(&root, w, false)?;
    let me = std::env::current_exe()?;
    detach(
        Command::new(me)
            .arg("core-loop")
            .arg(w)
            .arg(w.join("core.log"))
            .arg(&murl),
        &w.join("core-loop.log"),
        Some(&w.join("core-loop.pid")),
    )?;
    if !up(&format!("http://{CORE}/identity"), 30) {
        bail!(
            "the core didn't come up:\n{}",
            tail(&w.join("core.log"), 20)
        );
    }

    // production's session image, its signature and the earlier pins' (the phone checks them against keys/ci.pub)
    let ry = fs::read_to_string(root.join("k8s/cluster/router/router.yaml"))?;
    let (simg, ssig) = (
        manifest_value(&ry, "SESSION_IMAGE").unwrap_or_default(),
        manifest_value(&ry, "SESSION_IMAGE_SIG").unwrap_or_default(),
    );
    if simg.is_empty() || ssig.is_empty() {
        bail!("no SESSION_IMAGE / SESSION_IMAGE_SIG in k8s/cluster/router/router.yaml");
    }
    fs::create_dir_all(w.join("data"))?;
    let db = fresh_db(&root, "router_replica")?;
    // the router's whole env: nothing of production's (no Discord, Storage Box, Jarvis 1 or Claude keys)
    let path = std::env::var("PATH").unwrap_or_default();
    let mut c = Command::new(w.join("router"));
    c.env_clear()
        .env("PATH", &path)
        .env("HOME", &home)
        .env("DATABASE_URL", db)
        .env("ROUTER_THROWAWAY", "1")
        .env("NO_ACCESS", "1")
        .env("RECORDS_OFF", "1")
        .env("CORE_URL", format!("http://{CORE}"))
        .env("ADDR", "127.0.0.1:18080")
        .env("MACHINE_ADDR", "127.0.0.1:18081")
        .env("DATA_DIR", w.join("data"))
        .env("WEB_DIR", root.join("web"))
        .env("TASKS_DIR", root.join("tasks"))
        .env("POLICY_FILE", root.join("policy/stores.json"))
        .env("SESSION_IMAGE", &simg)
        .env("SESSION_IMAGE_SIG", &ssig)
        .env(
            "SESSION_IMAGE_SIGS_FILE",
            root.join("k8s/cluster/router/session-image-sigs.txt"),
        )
        .env("FLY_REGION", "lhr")
        .env("MACHINE_URL", &murl)
        .env(
            "FLY_READ_TOKEN",
            fs::read_to_string(w.join("fly-read"))?.trim(),
        )
        .env(
            "SETUP_KEY",
            fs::read_to_string(w.join("keys/setup.pub"))?.trim(),
        )
        .env("BACKUP_ENDPOINT", format!("http://{S3}"))
        .env("BACKUP_BUCKET", "jarvis2-backup-replica")
        .env("BACKUP_READ_ACCESS_KEY", "replica")
        .env("BACKUP_READ_SECRET_KEY", &secret);
    detach(&mut c, &w.join("router.log"), Some(&w.join("router.pid")))?;
    if !up("http://127.0.0.1:18080/api/state", 30) {
        bail!(
            "the router didn't come up:\n{}",
            tail(&w.join("router.log"), 20)
        );
    }
    // the machines' WireGuard peer runs in the gateway (rust/router mgateway.rs), as on the cluster, passing /m on
    let mut g = Command::new(w.join("router"));
    g.arg("m-gateway")
        .env_clear()
        .env("PATH", &path)
        .env("HOME", &home)
        .env("WG_CONFIGS", w.join("wg.conf"))
        .env("POD_NAME", "m-gateway-0")
        .env("M_GATEWAY_TO", "http://127.0.0.1:18081")
        .env("HEALTH_ADDR", "127.0.0.1:18082");
    detach(
        &mut g,
        &w.join("m-gateway.log"),
        Some(&w.join("m-gateway.pid")),
    )?;
    let end = Instant::now() + Duration::from_secs(20);
    while !fs::read_to_string(w.join("m-gateway.log"))
        .unwrap_or_default()
        .contains("WireGuard peer from")
    {
        if Instant::now() > end {
            bail!(
                "the gateway has no WireGuard peer:\n{}",
                tail(&w.join("m-gateway.log"), 20)
            );
        }
        std::thread::sleep(Duration::from_secs(1));
    }

    // what the setup answers (rust/replica-setup) need: infra/setup.py pointed at this stack
    fs::write(w.join("env"), setup_env(w, &py, &secret))?;
    run(Command::new("chmod").arg("600").arg(w.join("env")), "chmod")?;
    println!("ok: core :8090, router :18080, peer {peer}, session image {simg}");
    Ok(())
}

/// The environment rust/replica-setup runs infra/setup.py in: pointed at this stack, the /setup Access headers
/// set to anything (the local router has no Access in front of it), the backup bucket on the local S3 server
fn setup_env(w: &Path, py: &Path, secret: &str) -> String {
    format!(
        "export JARVIS2_URL=http://127.0.0.1:18080 JARVIS_KEYS_DIR=\"{w}/keys\" JARVIS_BACKUP_BUCKET=jarvis2-backup-replica\n\
         export JARVIS2_SETUP_KEY=\"$(cat \"{w}/setup-key.pem\")\" JARVIS4_SETUP_ACCESS_ID=none JARVIS4_SETUP_ACCESS_SECRET=none\n\
         export HETZNER_S3_ENDPOINT=http://{S3} HETZNER_S3_REGION=fsn1 HETZNER_S3_ACCESS_KEY=replica HETZNER_S3_SECRET_KEY=\"{secret}\"\n\
         export REPLICA_W=\"{w}\" REPLICA_PY=\"{py}\"\n",
        w = w.display(),
        py = py.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_values() {
        let y = r#"            - { name: SESSION_IMAGE, value: "ghcr.io/de0ch/jarvis4-session:sha-1@sha256:aa" }
            - { name: SESSION_IMAGE_SIG, value: "MEUC" }"#;
        assert_eq!(
            manifest_value(y, "SESSION_IMAGE").as_deref(),
            Some("ghcr.io/de0ch/jarvis4-session:sha-1@sha256:aa")
        );
        assert_eq!(
            manifest_value(y, "SESSION_IMAGE_SIG").as_deref(),
            Some("MEUC")
        );
        assert_eq!(manifest_value(y, "NOPE"), None);
    }

    #[test]
    fn env_files_and_secrets() {
        let d = std::env::temp_dir().join(format!("ios-ci-{}", std::process::id()));
        let _ = fs::create_dir_all(&d);
        let p = d.join("s3.env");
        let _ = fs::write(&p, "ACCESS_KEY=a\nSECRET_KEY=b=c\n");
        assert_eq!(
            env_file(&p),
            vec![
                ("ACCESS_KEY".into(), "a".into()),
                ("SECRET_KEY".into(), "b=c".into())
            ]
        );
        let s = hex_secret();
        assert!(s.len() == 32 && s.chars().all(|c| c.is_ascii_hexdigit()));
        let _ = fs::remove_dir_all(&d);
    }

    /// The replica runs only on main (the `replica` environment): a name infra/setup.py stops reading must fail here, on
    /// every branch. 2026-11-26/28: setup.py moved to JARVIS4_SETUP_ACCESS_*, the replica kept exporting
    /// JARVIS2_SETUP_ACCESS_*, and every main run failed "No such file … ~/.jarvis/cloudflare.env".
    #[test]
    fn the_setup_env_sets_every_variable_setup_py_reads_for_access() {
        let py = fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../infra/setup.py"))
            .expect("infra/setup.py");
        let body = py
            .split("def access():")
            .nth(1)
            .expect("setup.py has access()");
        let body = body.split("\ndef ").next().unwrap_or(body);
        let names: Vec<&str> = body
            .split("os.environ.get(\"")
            .skip(1)
            .filter_map(|r| r.split('"').next())
            .collect();
        assert!(!names.is_empty(), "access() reads no variable");
        let env = setup_env(Path::new("/w"), Path::new("/py"), "s");
        for n in names {
            assert!(
                env.contains(&format!(" {n}=")),
                "the replica's setup env lacks {n}: {env}"
            );
        }
    }
}
