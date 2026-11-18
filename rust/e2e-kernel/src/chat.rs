//! The chat stack beside the kernel for the aviary harness (`E2E_HARNESS=aviary`, on Fly machines or the fabric's): hermit-jarvis built from this tree's aviary/, magpie from the image the session image's aviary
//! release names (its root unpacked once, run in its own network namespace as its image's user), a TLS Postgres for
//! hermit, magpie and the router, an S3 stand-in (rclone serve s3), and the chat stack's keys as DE0CH/deyao-ai's
//! infra/chat-keys.py makes them.
//!
//!   magpie 10.88.0.2:8080 (as `http://magpie` to hermit-jarvis), hermit-jarvis 0.0.0.0:8080/8081/8082/9090 (as
//!   `http://hermit` to magpie), Postgres 127.0.0.1:31432 and 10.88.0.1, S3 10.88.0.1:31900.

use anyhow::{Context, Result, bail};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub const NS: &str = "e2e-aviary-mag";
const PG_PORT: &str = "31432";
const S3_ADDR: &str = "10.88.0.1:31900";

/// hermit-jarvis's person (its owner): the chat's calls are made as them.
pub const OWNER: &str = "e2e@example.com";

/// What the driver needs of the stack: magpie's admin token, and the token magpie takes from pigeon (the driver makes
/// the chat's own calls: a conversation begun in the chat).
#[derive(Default)]
pub struct Chat {
    pub magpie_admin: String,
    pub magpie_pigeon: String,
}

fn sudo(args: &[&str]) -> Result<()> {
    let st = Command::new("sudo").arg("-n").args(args).status()?;
    if !st.success() {
        bail!("sudo {}: {st}", args.join(" "));
    }
    Ok(())
}

fn quiet_sudo(args: &[&str]) {
    let _ = Command::new("sudo")
        .arg("-n")
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

fn tok() -> Result<String> {
    use base64::Engine as _;
    let mut b = [0u8; 32];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut b)
        .map_err(|_| anyhow::anyhow!("random"))?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b))
}

fn nat(op: &str) {
    quiet_sudo(&[
        "iptables",
        "-t",
        "nat",
        op,
        "PREROUTING",
        "-i",
        "e2e-avm0",
        "-p",
        "tcp",
        "--dport",
        "80",
        "-j",
        "REDIRECT",
        "--to-ports",
        "8080",
    ]);
    quiet_sudo(&[
        "ip",
        "netns",
        "exec",
        NS,
        "iptables",
        "-t",
        "nat",
        op,
        "PREROUTING",
        "-p",
        "tcp",
        "--dport",
        "80",
        "-j",
        "REDIRECT",
        "--to-ports",
        "8080",
    ]);
}

/// Everything the stack made, undone (the processes are the caller's).
pub fn teardown(w: &Path, root: &Path) {
    nat("-D");
    quiet_sudo(&["ip", "netns", "del", NS]);
    quiet_sudo(&["ip", "link", "del", "e2e-avm0"]);
    let _ = Command::new(root.join("infra/test-postgres.sh"))
        .arg("stop")
        .env("TEST_PG_DIR", w.join("pg"))
        .env("TEST_PG_PORT", PG_PORT)
        .status();
}

fn ready(name: &str, url: &str, log: &Path) -> Result<()> {
    let end = Instant::now() + Duration::from_secs(90);
    let c = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()?;
    while Instant::now() < end {
        if c.get(url).send().is_ok_and(|r| r.status().is_success()) {
            eprintln!("e2e-kernel: {name} ready");
            return Ok(());
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    let tail = fs::read_to_string(log).unwrap_or_default();
    bail!(
        "{name} never became ready ({url}): {}",
        tail.lines().rev().take(20).collect::<Vec<_>>().join("\n")
    )
}

/// Brings the stack up, hermit-jarvis with `hermit_extra` in its env besides its own; `spawn(cmd, name, under_sudo)`
/// starts a process the run ends.
pub fn up(
    root: &Path,
    w: &Path,
    hermit_extra: &[String],
    spawn: &mut dyn FnMut(&mut Command, &str, bool) -> Result<()>,
) -> Result<Chat> {
    let cache = PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(".cache/jarvis4-e2e");
    fs::create_dir_all(&cache)?;
    // hermit-jarvis, built from this tree
    let st = Command::new("cargo")
        .args(["build", "--release", "--locked", "--bin", "hermit-jarvis"])
        .current_dir(root.join("aviary"))
        .env("CARGO_INCREMENTAL", "0")
        .status()?;
    if !st.success() {
        bail!("building hermit-jarvis: {st}");
    }
    let meta = Command::new("cargo")
        .args(["metadata", "--format-version", "1", "--no-deps"])
        .current_dir(root.join("aviary"))
        .output()?;
    let target = serde_json::from_slice::<serde_json::Value>(&meta.stdout)?["target_directory"]
        .as_str()
        .context("cargo metadata")?
        .to_owned();
    let hermit_bin = PathBuf::from(target).join("release/hermit-jarvis");
    // rclone (the S3 stand-in)
    let rclone = cache.join("rclone");
    if !rclone.exists() {
        let st = Command::new("sh")
            .arg("-c")
            .arg(format!(
                "curl -fsSL -o '{0}/rclone.zip' https://downloads.rclone.org/rclone-current-linux-amd64.zip && \
                 cd '{0}' && python3 -I -c 'import zipfile,sys;z=zipfile.ZipFile(sys.argv[1]);n=[x for x in z.namelist() if x.endswith(\"/rclone\")][0];open(sys.argv[2],\"wb\").write(z.read(n))' rclone.zip rclone && chmod +x rclone && rm -f rclone.zip",
                cache.display()
            ))
            .status()?;
        if !st.success() {
            bail!("rclone: {st}");
        }
    }
    // magpie: the root of the image the session image's aviary release names
    let rel: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("session-image/aviary.json"))?)?;
    let tag = rel["release"]
        .as_str()
        .context("aviary.json release")?
        .trim_start_matches("aviary-")
        .to_owned();
    let digest = String::from_utf8(
        Command::new("crane")
            .args(["digest", &format!("ghcr.io/de0ch/magpie:{tag}")])
            .output()?
            .stdout,
    )?
    .trim()
    .to_owned();
    let image = format!("ghcr.io/de0ch/magpie:{tag}@{digest}");
    let mroot = cache.join(format!("magpie-{}", digest.trim_start_matches("sha256:")));
    if !mroot.join("usr/local/bin/magpie").exists() {
        let tmp = mroot.with_extension("tmp");
        quiet_sudo(&["rm", "-rf", &tmp.to_string_lossy()]);
        fs::create_dir_all(&tmp)?;
        let st = Command::new("sh")
            .arg("-c")
            .arg(format!(
                "crane export '{image}' - | sudo -n tar -x -C '{}'",
                tmp.display()
            ))
            .status()?;
        if !st.success() {
            bail!("unpacking magpie: {st}");
        }
        sudo(&["mv", &tmp.to_string_lossy(), &mroot.to_string_lossy()])?;
    }
    // magpie's network namespace: 10.88.0.1 (here) ↔ 10.88.0.2 (magpie)
    quiet_sudo(&["ip", "netns", "del", NS]);
    quiet_sudo(&["ip", "link", "del", "e2e-avm0"]);
    sudo(&["ip", "netns", "add", NS])?;
    sudo(&[
        "ip", "link", "add", "e2e-avm0", "type", "veth", "peer", "name", "e2e-avm1",
    ])?;
    sudo(&["ip", "link", "set", "e2e-avm1", "netns", NS])?;
    sudo(&["ip", "addr", "add", "10.88.0.1/30", "dev", "e2e-avm0"])?;
    sudo(&["ip", "link", "set", "e2e-avm0", "up"])?;
    sudo(&[
        "ip",
        "netns",
        "exec",
        NS,
        "ip",
        "addr",
        "add",
        "10.88.0.2/30",
        "dev",
        "e2e-avm1",
    ])?;
    sudo(&[
        "ip", "netns", "exec", NS, "ip", "link", "set", "e2e-avm1", "up",
    ])?;
    sudo(&["ip", "netns", "exec", NS, "ip", "link", "set", "lo", "up"])?;
    nat("-A");
    // Postgres (TLS), for magpie in the namespace too
    let pg = |name: &str| -> Result<String> {
        let o = Command::new(root.join("infra/test-postgres.sh"))
            .args(["fresh", name])
            .env("TEST_PG_DIR", w.join("pg"))
            .env("TEST_PG_PORT", PG_PORT)
            .env("TEST_PG_LISTEN", "127.0.0.1,10.88.0.1")
            .env("TEST_PG_TRUST", "10.88.0.0/30")
            .output()?;
        if !o.status.success() {
            bail!("Postgres {name}: {}", String::from_utf8_lossy(&o.stderr));
        }
        Ok(String::from_utf8(o.stdout)?.trim().to_owned())
    };
    pg("magpie")?;
    let hermit_db = pg("hermit")?.replace("sslmode=disable", "sslmode=require");
    let magpie_db = format!("postgres://postgres@10.88.0.1:{PG_PORT}/magpie?sslmode=require");
    // S3
    let (s3k, s3s) = (format!("e2e{}", &tok()?[..12]), tok()?);
    fs::create_dir_all(w.join("s3/magpie"))?;
    spawn(
        Command::new(&rclone)
            .args([
                "serve",
                "s3",
                "--addr",
                S3_ADDR,
                "--auth-key",
                &format!("{s3k},{s3s}"),
                "--force-path-style=true",
            ])
            .arg(w.join("s3")),
        "s3",
        false,
    )?;
    // the keys
    let mut k = std::collections::HashMap::new();
    for pair in [
        "PIGEON_MAGPIE",
        "PIGEON_HERMIT",
        "PIGEON_MODEL",
        "GATEWAY_MAGPIE",
        "GATEWAY_HERMIT",
        "HERMIT_MAGPIE",
        "MAGPIE_HERMIT",
        "ADMIN_MAGPIE",
        "ADMIN_HERMIT",
    ] {
        k.insert(pair, tok()?);
    }
    // magpie: its image's root, in the namespace, as its image's user; `http://hermit` = 10.88.0.1
    sudo(&[
        "sh",
        "-c",
        &format!(
            "printf '127.0.0.1 localhost\\n10.88.0.1 hermit\\n' > '{0}/etc/hosts'; mkdir -p '{0}/tmp'; chmod 1777 '{0}/tmp'",
            mroot.display()
        ),
    ])?;
    let magpie_env = [
        "POD_NAME=magpie-e2e".to_owned(),
        format!("MAGPIE_DATABASE_URL={magpie_db}"),
        format!("MAGPIE_S3_ENDPOINT=http://{S3_ADDR}"),
        "MAGPIE_S3_REGION=us-east-1".into(),
        "MAGPIE_S3_BUCKET=magpie".into(),
        format!("MAGPIE_S3_ACCESS_KEY_ID={s3k}"),
        format!("MAGPIE_S3_SECRET_ACCESS_KEY={s3s}"),
        format!("MAGPIE_ACCEPT_PIGEON={}", k["PIGEON_MAGPIE"]),
        format!("MAGPIE_ACCEPT_GATEWAY={}", k["GATEWAY_MAGPIE"]),
        format!("MAGPIE_ACCEPT_HERMIT={}", k["HERMIT_MAGPIE"]),
        format!("MAGPIE_ACCEPT_ADMIN={}", k["ADMIN_MAGPIE"]),
        format!("MAGPIE_TOKEN_HERMIT={}", k["MAGPIE_HERMIT"]),
    ];
    let chroot = String::from_utf8(
        Command::new("sh")
            .args(["-c", "PATH=$PATH:/usr/sbin:/sbin command -v chroot"])
            .output()?
            .stdout,
    )?
    .trim()
    .to_owned();
    spawn(
        Command::new("sudo")
            .args([
                "-n",
                "ip",
                "netns",
                "exec",
                NS,
                "env",
                "-i",
                "PATH=/usr/local/bin:/usr/bin:/bin",
            ])
            .args(&magpie_env)
            .arg(&chroot)
            .arg("--userspec=10001:10001")
            .arg(&mroot)
            .args(["/usr/local/bin/magpie", "serve"]),
        "magpie",
        true,
    )?;
    // hermit-jarvis: here, `http://magpie` = 10.88.0.2 (its own /etc/hosts, a private mount namespace)
    let hosts = w.join("hosts-hermit");
    fs::write(
        &hosts,
        format!(
            "{}10.88.0.2 magpie\n",
            fs::read_to_string("/etc/hosts").unwrap_or_default()
        ),
    )?;
    let mut hermit_env = vec![
        "POD_NAME=hermit-e2e".to_owned(),
        format!("HERMIT_DATABASE_URL={hermit_db}"),
        format!("HERMIT_TOKEN_KEYS=1:{}", tok()?),
        "HERMIT_JARVIS_URL=http://127.0.0.1:29080".into(),
        "HERMIT_JARVIS_ACCESS_ID=e2e".into(),
        "HERMIT_JARVIS_ACCESS_SECRET=e2e".into(),
        format!("HERMIT_OWNER={OWNER}"),
        "HERMIT_ACCESS_TEAM=e2e.cloudflareaccess.com".into(),
        "HERMIT_ACCESS_AUD=e2e".into(),
        format!(
            "HERMIT_SETTINGS={}",
            root.join("aviary/tests/settings.json").display()
        ),
        format!("HERMIT_ACCEPT_PIGEON={}", k["PIGEON_HERMIT"]),
        format!("HERMIT_ACCEPT_MAGPIE={}", k["MAGPIE_HERMIT"]),
        format!("HERMIT_ACCEPT_GATEWAY={}", k["GATEWAY_HERMIT"]),
        format!("HERMIT_ACCEPT_ADMIN={}", k["ADMIN_HERMIT"]),
        format!("MODEL_ACCEPT_PIGEON={}", k["PIGEON_MODEL"]),
        format!("HERMIT_TOKEN_MAGPIE={}", k["HERMIT_MAGPIE"]),
        format!("GATEWAY_TOKEN_MAGPIE={}", k["GATEWAY_MAGPIE"]),
        format!("GATEWAY_TOKEN_HERMIT={}", k["GATEWAY_HERMIT"]),
    ];
    hermit_env.extend_from_slice(hermit_extra);
    let (uid, gid) = (
        nix::unistd::Uid::current().to_string(),
        nix::unistd::Gid::current().to_string(),
    );
    let me = std::env::current_exe()?;
    spawn(
        Command::new("sudo")
            .args(["-n", "unshare", "-m", "--propagation", "private"])
            .arg(&me)
            .arg("hosts-exec")
            .arg(&hosts)
            .args([&uid, &gid, "--", "env", "-i", "PATH=/usr/bin:/bin"])
            .args(&hermit_env)
            .arg(&hermit_bin),
        "hermit",
        true,
    )?;
    ready(
        "magpie",
        "http://10.88.0.2:9090/readyz",
        &w.join("magpie.log"),
    )?;
    ready(
        "hermit",
        "http://127.0.0.1:9090/readyz",
        &w.join("hermit.log"),
    )?;
    Ok(Chat {
        magpie_admin: k["ADMIN_MAGPIE"].clone(),
        magpie_pigeon: k["PIGEON_MAGPIE"].clone(),
    })
}
