//! aviary-sandbox BOOT_ENV_FILE [WORKDIR] (as root, by harness-aviary.sh through sudo): runs this session's sandbox IN
//! DE0CH/aviary's own sandbox image, the one YYC AI's sandboxes run (ghcr.io/de0ch/hermit-sandbox, pinned by digest in
//! session-image/aviary.json "sandbox"; DE0CH/aviary images/sandbox/).
//! aviary-sandbox --fetch: only fetches the image; prints where its root filesystem is.
//!
//! Dogfooding (Deyao, 2026-11-14/16; claude-env `dogfood-aviary` skill): the supervisor, its keeper, Claude Code, the
//! agent's tools, the paths and the environment are the image's, unmodified. Nothing of them is built, pinned or
//! written a second time here: a new aviary release needs only its digest in aviary.json.
//!
//!   the image    unpacked once on the session's volume (/data/aviary/image-<digest12>), as aviary's sandboxd unpacks
//!                it for a host (`crane export | tar -x`), with its config beside it. It is 1.4 GB to fetch, 3.3 GB on
//!                disk, so it cannot be a layer of the session image (Fly's unpack limit, claude-env lessons/72). One
//!                image at a time: another pin's image and what was installed over it are removed first.
//!   the root     an overlay over the image (/data/aviary/upper-<digest12>: what the agent installs with apt stays
//!                while the session lives, as a sandbox's root does), entered with pivot_root; the machine's own root
//!                is unmounted from the namespace, so the agent sees the image's files and tools, not the machine's.
//!                On a fabric machine (docs/PLAN-fabric.md) the fabric image carries the sandbox image unpacked at
//!                AVIARY_SANDBOX_IMAGE_DIR, its config beside it (<dir>.config): nothing is fetched, and the root is a
//!                bind of that directory, writable because the fabric's own root (sandboxd's overlay over the image)
//!                is; gVisor refuses an overlay whose upper directory is not in memory, so none is made inside it
//!   the start    the image's Entrypoint (supervisor-keeper) as PID 1 of a PID namespace, in the image's WorkingDir,
//!                with the image's Env plus the gateway's boot environment: what a container runtime does
//!
//! What Jarvis 4 puts in, being what a deployment implements (the session, its files, its secrets):
//!   /home/sandbox            the machine's /home/claude with what is mounted in it (the volume's ~/workspace and
//!                            ~/artifacts): the session's files outlive the sandbox. aviary-home has given it what the
//!                            image's own /home/sandbox holds (the ~/.claude and ~/.qwen links, ~/.npmrc)
//!   /home/sandbox/.harness   empty, as in the image (the supervisor mounts magpie's FUSE there): a tmpfs over the
//!                            machine's ~/.harness, where the machine's own ~/.claude (its login, the transcript
//!                            mirror) lives
//!   /workspace               the harness's working directory WORKDIR: the one repo (~/workspace/<repo>), or
//!                            ~/workspace with several (workspace-layer.sh), or the empty ~/workspace
//!   /run/jarvis              the machine's (session-secret's socket, the ssh agent)
//!   /run/jarvis-transcripts  the machine's transcript mirror, for harness-aviary.sh's copy out of the FUSE mount
//!   /usr/local/bin/…         Jarvis's session commands ([`TOOLS`]), read-only binds of the machine's: without
//!                            them a sandbox had no schedule-wakeup (2026-11-18)
//!   /etc/resolv.conf, hosts  the machine's (the network namespace is the machine's: $JARVIS_URL, the gateway)

use serde_json::Value;
use std::ffi::{CString, OsStr};
use std::fs;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::symlink;
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::Duration;

/// The machine's session commands the sandbox gets (the three names of jarvis-tools are links to it on the machine;
/// a bind follows the link, and the tool goes by the name it is run under).
pub const TOOLS: [&str; 10] = [
    "jarvis-machine",
    "jarvis-request",
    "jarvis-message",
    "session-secret",
    "pull-secrets",
    "content-sync",
    "jarvis-tools",
    "schedule-wakeup",
    "schedule-cron",
    "retire-session",
];
const ROOT: &str = "/run/aviary-sandbox-root";

fn env_or(k: &str, d: &str) -> String {
    std::env::var(k)
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| d.to_string())
}

/// `ghcr.io/…@sha256:<64 hex>`: a sandbox image pinned by digest.
pub fn pinned(image: &str) -> bool {
    let Some((name, digest)) = image.split_once("@sha256:") else {
        return false;
    };
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "./-".contains(c))
        && digest.len() == 64
        && digest
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

/// `realpath -m`: the path with its existing part's links resolved and `.`/`..` taken away, missing parts kept.
pub fn realpath_m(p: &Path) -> PathBuf {
    let mut out = PathBuf::from("/");
    let mut parts: Vec<Component> = p.components().collect();
    if !p.is_absolute() {
        out = std::env::current_dir().unwrap_or_else(|_| "/".into());
        parts.retain(|c| !matches!(c, Component::RootDir));
    }
    for c in parts {
        match c {
            Component::RootDir | Component::CurDir | Component::Prefix(_) => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(n) => {
                out.push(n);
                if let Ok(r) = fs::canonicalize(&out) {
                    out = r;
                }
            }
        }
    }
    out
}

/// Is `wd` under `home`/workspace (the directory itself included)?
pub fn under_workspace(wd: &Path, home: &str) -> bool {
    let real = format!("{}/", realpath_m(wd).display());
    real.starts_with(&format!("{}/workspace/", home.trim_end_matches('/')))
}

/// The entrypoint's environment: the image's `Env`, then each `NAME=value` line of the boot environment over it.
pub fn environment(config: &Value, boot: &str) -> Vec<(String, String)> {
    let mut env: Vec<(String, String)> = Vec::new();
    let mut set = |k: &str, v: &str| match env.iter_mut().find(|(n, _)| n == k) {
        Some(e) => e.1 = v.to_string(),
        None => env.push((k.to_string(), v.to_string())),
    };
    for e in config["Env"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
    {
        if let Some((k, v)) = e.split_once('=') {
            set(k, v);
        }
    }
    for line in boot.lines() {
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let mut cs = k.chars();
        let name = cs
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && cs.all(|c| c.is_ascii_alphanumeric() || c == '_');
        if name {
            set(k, v);
        }
    }
    env
}

/// The entrypoint's argv: the image's `Entrypoint` then its `Cmd`.
pub fn argv(config: &Value) -> Vec<String> {
    ["Entrypoint", "Cmd"]
        .iter()
        .flat_map(|k| config[*k].as_array().cloned().unwrap_or_default())
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect()
}

struct Paths {
    home: String,
    bin: String,
    store: String,
    image: String,
    id: String,
    img: String,
    image_dir: bool,
}

fn paths() -> Result<Paths, String> {
    let pins = env_or("AVIARY_PINS", "/usr/local/share/aviary.json");
    let image = fs::read_to_string(&pins)
        .ok()
        .and_then(|s| serde_json::from_str::<Value>(&s).ok())
        .and_then(|v| v["sandbox"].as_str().map(str::to_string))
        .unwrap_or_default();
    if !pinned(&image) {
        return Err(format!(
            "no sandbox image by digest in the aviary pins ({image})"
        ));
    }
    let id = image
        .rsplit_once("@sha256:")
        .map(|(_, d)| d[..12].to_string())
        .unwrap_or_default();
    let store = env_or("AVIARY_SANDBOX_STORE", "/data/aviary");
    let dir = env_or("AVIARY_SANDBOX_IMAGE_DIR", "");
    Ok(Paths {
        home: env_or("AVIARY_SANDBOX_HOME", "/home/claude"),
        bin: env_or("AVIARY_SANDBOX_BIN", "/usr/local/bin"),
        img: if dir.is_empty() {
            format!("{store}/image-{id}")
        } else {
            dir.clone()
        },
        image_dir: !dir.is_empty(),
        store,
        image,
        id,
    })
}

fn last_line(path: &str) -> String {
    fs::read_to_string(path)
        .ok()
        .and_then(|s| s.lines().last().map(str::to_string))
        .unwrap_or_default()
}

/// One try at `crane export IMAGE - | tar -x` into `dir`, then `crane config IMAGE > config`.
fn unpack(image: &str, dir: &str, config: &str, log: &str) -> bool {
    let Ok(log_f) = fs::File::create(log) else {
        return false;
    };
    let err = || log_f.try_clone().map(Stdio::from).unwrap_or(Stdio::null());
    let Ok(mut crane) = Command::new("crane")
        .args(["export", image, "-"])
        .stdout(Stdio::piped())
        .stderr(err())
        .spawn()
    else {
        let _ = writeln!(&log_f, "crane could not be started");
        return false;
    };
    let tar = crane.stdout.take().map(|out| {
        Command::new("tar")
            .args(["-x", "--numeric-owner", "-C", dir])
            .stdin(out)
            .stderr(err())
            .status()
    });
    let crane_ok = crane.wait().is_ok_and(|s| s.success());
    let tar_ok = matches!(tar, Some(Ok(s)) if s.success());
    if !(crane_ok && tar_ok) {
        return false;
    }
    let Ok(cfg) = fs::File::create(config) else {
        return false;
    };
    Command::new("crane")
        .args(["config", image])
        .stdout(cfg)
        .stderr(err())
        .status()
        .is_ok_and(|s| s.success())
        && Path::new(dir).join("home/sandbox").is_dir()
}

fn fetch(p: &Paths) -> Result<(), String> {
    let img = &p.img;
    if Path::new(&format!("{img}.ok")).exists() {
        return Ok(());
    }
    if p.image_dir {
        let cfg_ok = fs::metadata(format!("{img}.config")).is_ok_and(|m| m.len() > 0);
        if Path::new(img).join("home/sandbox").is_dir() && cfg_ok {
            return Ok(());
        }
        return Err(format!("no sandbox image at {img} (with {img}.config)"));
    }
    fs::create_dir_all(&p.store).map_err(|e| format!("{}: {e}", p.store))?;
    let keep = format!("upper-{}", p.id);
    for e in fs::read_dir(&p.store)
        .map_err(|e| format!("{}: {e}", p.store))?
        .flatten()
    {
        if e.file_name() != OsStr::new(&keep) {
            let path = e.path();
            let gone = if path.is_dir() && !path.is_symlink() {
                fs::remove_dir_all(&path)
            } else {
                fs::remove_file(&path)
            };
            gone.map_err(|e| format!("removing {}: {e}", path.display()))?;
        }
    }
    let (tmp, log) = (format!("{img}.tmp"), format!("{}/fetch.log", p.store));
    for attempt in 1..=5 {
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir(&tmp).map_err(|e| format!("{tmp}: {e}"))?;
        if unpack(&p.image, &tmp, &format!("{img}.config"), &log) {
            fs::rename(&tmp, img).map_err(|e| format!("{img}: {e}"))?;
            fs::File::create(format!("{img}.ok")).map_err(|e| format!("{img}.ok: {e}"))?;
            eprintln!(
                "aviary-sandbox: the sandbox image {} is unpacked in {img}",
                p.image
            );
            return Ok(());
        }
        eprintln!(
            "aviary-sandbox: fetching {} failed (attempt {attempt}): {}",
            p.image,
            last_line(&log)
        );
        std::thread::sleep(Duration::from_secs(5));
    }
    Err("the sandbox image could not be fetched".into())
}

fn c(s: impl AsRef<OsStr>) -> CString {
    CString::new(s.as_ref().as_bytes()).unwrap_or_default()
}

fn mount(
    src: &str,
    target: &str,
    fstype: Option<&str>,
    flags: libc::c_ulong,
    data: Option<&str>,
) -> Result<(), String> {
    let (s, t) = (c(src), c(target));
    let f = fstype.map(c);
    let d = data.map(c);
    // SAFETY: every pointer is a NUL-terminated string that lives across the call, or null
    let rc = unsafe {
        libc::mount(
            s.as_ptr(),
            t.as_ptr(),
            f.as_ref().map_or(std::ptr::null(), |x| x.as_ptr()),
            flags,
            d.as_ref().map_or(std::ptr::null(), |x| x.as_ptr().cast()),
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(format!(
            "mounting {src} on {target}: {}",
            std::io::Error::last_os_error()
        ))
    }
}

fn mkdirs(p: &str) -> Result<(), String> {
    fs::create_dir_all(p).map_err(|e| format!("{p}: {e}"))
}

fn errno() -> String {
    std::io::Error::last_os_error().to_string()
}

/// The machine's side: the image fetched, the home checked, then this tool again as PID 1 of new namespaces.
fn outer(p: &Paths, boot: &str, wd: &str) -> Result<ExitCode, String> {
    fetch(p)?;
    // the home has what the image's home has (aviary-home): Claude Code finds its home through the image's own link
    let ih = Path::new(&p.img).join("home/sandbox");
    let mut links: Vec<_> = fs::read_dir(&ih)
        .map_err(|e| format!("{}: {e}", ih.display()))?
        .flatten()
        .collect();
    links.sort_by_key(|e| e.file_name());
    for e in links {
        let n = e.file_name();
        if !n.as_bytes().starts_with(b".")
            || n.as_bytes().starts_with(b"..")
            || !e.path().is_symlink()
        {
            continue;
        }
        let want = fs::read_link(e.path()).unwrap_or_default();
        let mine = Path::new(&p.home).join(&n);
        if fs::read_link(&mine).ok().as_ref() != Some(&want) {
            return Err(format!(
                "{} is not the image's link to {} (aviary-home)",
                mine.display(),
                want.display()
            ));
        }
    }
    // a PID namespace (the image's entrypoint = PID 1) and a private mount namespace
    let me = std::env::current_exe().map_err(|e| format!("this program's path: {e}"))?;
    let e = Command::new("unshare")
        .args(["--pid", "--fork", "--mount", "--propagation", "private"])
        .arg(me)
        .args(["aviary-sandbox", boot, wd])
        .env("AVIARY_SANDBOX_INNER", "1")
        .exec();
    Err(format!("starting unshare: {e}"))
}

/// Inside the new namespaces: the image's root with Jarvis's parts in it, then into it and the image's entrypoint.
fn inner(p: &Paths, boot: &str, wd: &str) -> Result<ExitCode, String> {
    let (img, new) = (p.img.as_str(), ROOT);
    mkdirs(new)?;
    if p.image_dir {
        mount(img, new, None, libc::MS_BIND, None)?;
    } else {
        let up = format!("{}/upper-{}", p.store, p.id);
        mkdirs(&format!("{up}/up"))?;
        mkdirs(&format!("{up}/work"))?;
        let opts = format!("lowerdir={img},upperdir={up}/up,workdir={up}/work");
        mount("overlay", new, Some("overlay"), 0, Some(&opts))?;
    }
    let rbind = libc::MS_BIND | libc::MS_REC;
    mount("proc", &format!("{new}/proc"), Some("proc"), 0, None)?;
    mount("/sys", &format!("{new}/sys"), None, rbind, None)?;
    mount("/dev", &format!("{new}/dev"), None, rbind, None)?;
    // rbind: with what is mounted in the machine's home. ~/workspace and ~/artifacts are mounts from the session's
    // volume there; a plain bind left them out, and the agent wrote its repos and records to the root disk, which a
    // pause throws away (tests/aviary_sandbox.rs). The tmpfs hides the machine's ~/.harness.
    mount(&p.home, &format!("{new}/home/sandbox"), None, rbind, None)?;
    mount(
        "tmpfs",
        &format!("{new}/home/sandbox/.harness"),
        Some("tmpfs"),
        0,
        Some("mode=0755,uid=1000,gid=1000,size=1m"),
    )?;
    mount(wd, &format!("{new}/workspace"), None, libc::MS_BIND, None)?;
    if Path::new("/run/jarvis").is_dir() {
        mkdirs(&format!("{new}/run/jarvis"))?;
        mount(
            "/run/jarvis",
            &format!("{new}/run/jarvis"),
            None,
            rbind,
            None,
        )?;
    }
    let mirror = format!("{}/.harness/claude/projects/-home-claude-workspace", p.home);
    if Path::new(&mirror).is_dir() {
        mkdirs(&format!("{new}/run/jarvis-transcripts"))?;
        mount(
            &mirror,
            &format!("{new}/run/jarvis-transcripts"),
            None,
            libc::MS_BIND,
            None,
        )?;
    }
    for f in ["resolv.conf", "hosts"] {
        let src = format!("/etc/{f}");
        if Path::new(&src).exists() {
            let dst = format!("{new}/etc/{f}");
            let _ = fs::remove_file(&dst);
            fs::copy(&src, &dst).map_err(|e| format!("copying {src}: {e}"))?;
        }
    }
    for t in TOOLS {
        let src = format!("{}/{t}", p.bin);
        if !Path::new(&src).exists() {
            continue;
        }
        // never over a file of the image's: a name the image takes is the image's
        if Path::new(&format!("{img}/usr/local/bin/{t}")).exists() {
            return Err(format!("the image has its own /usr/local/bin/{t}"));
        }
        let dst = format!("{new}/usr/local/bin/{t}");
        if !Path::new(&dst).exists() {
            fs::File::create(&dst).map_err(|e| format!("{dst}: {e}"))?;
        }
        mount(&src, &dst, None, libc::MS_BIND, None)?;
        mount(
            "none",
            &dst,
            None,
            libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY,
            None,
        )?;
    }
    if Path::new(&format!("{new}/usr/local/bin/jarvis-machine")).exists() {
        let j = format!("{new}/usr/local/bin/jarvis");
        let _ = fs::remove_file(&j);
        symlink("jarvis-machine", &j).map_err(|e| format!("{j}: {e}"))?;
    }

    // Into the image's root, then the image's entrypoint with the image's environment and the boot environment
    // (supervisor 6.2: nothing else of the machine's is passed on)
    let config: Value = fs::read_to_string(format!("{img}.config"))
        .ok()
        .and_then(|s| serde_json::from_str::<Value>(&s).ok())
        .map(|v| v["config"].clone())
        .ok_or_else(|| format!("no image config at {img}.config"))?;
    let boot_env = fs::read_to_string(boot).map_err(|e| format!("{boot}: {e}"))?;
    let env: Vec<CString> = environment(&config, &boot_env)
        .iter()
        .map(|(k, v)| c(format!("{k}={v}")))
        .collect();
    let args: Vec<CString> = argv(&config).iter().map(c).collect();
    if args.is_empty() {
        return Err("the image has no Entrypoint or Cmd".into());
    }
    let wdir = config["WorkingDir"]
        .as_str()
        .filter(|w| !w.is_empty())
        .unwrap_or("/")
        .to_string();
    std::env::set_current_dir(new).map_err(|e| format!("{new}: {e}"))?;
    let (dot, mnt) = (c("."), c("mnt"));
    // SAFETY: plain system calls on NUL-terminated strings that live across them
    unsafe {
        if libc::syscall(libc::SYS_pivot_root, dot.as_ptr(), mnt.as_ptr()) == 0 {
            if libc::chroot(dot.as_ptr()) != 0 {
                return Err(format!("entering the image: {}", errno()));
            }
            // MNT_DETACH: the machine root leaves this namespace
            if libc::umount2(c("/mnt").as_ptr(), libc::MNT_DETACH) != 0 {
                return Err(format!("unmounting the machine root: {}", errno()));
            }
        } else {
            // a root that cannot be pivoted from (an initramfs): the image moves over it
            if libc::mount(
                dot.as_ptr(),
                c("/").as_ptr(),
                std::ptr::null(),
                libc::MS_MOVE,
                std::ptr::null(),
            ) != 0
            {
                return Err(format!("entering the image: {}", errno()));
            }
            if libc::chroot(dot.as_ptr()) != 0 {
                return Err(format!("entering the image: {}", errno()));
            }
        }
    }
    std::env::set_current_dir(&wdir).map_err(|e| format!("{wdir}: {e}"))?;
    let mut av: Vec<*const libc::c_char> = args.iter().map(|a| a.as_ptr()).collect();
    av.push(std::ptr::null());
    let mut ev: Vec<*const libc::c_char> = env.iter().map(|a| a.as_ptr()).collect();
    ev.push(std::ptr::null());
    // SAFETY: null-terminated arrays of NUL-terminated strings that live across the call
    unsafe { libc::execve(args[0].as_ptr(), av.as_ptr(), ev.as_ptr()) };
    Err(format!(
        "starting {}: {}",
        args[0].to_string_lossy(),
        errno()
    ))
}

pub fn run(args: &[String]) -> Result<ExitCode, String> {
    // SAFETY: a plain system call
    if unsafe { libc::geteuid() } != 0 {
        return Err("run as root".into());
    }
    let p = paths()?;
    if args.first().map(String::as_str) == Some("--fetch") {
        fetch(&p)?;
        println!("{}", p.img);
        return Ok(ExitCode::SUCCESS);
    }
    let boot = args
        .first()
        .ok_or("usage: aviary-sandbox BOOT_ENV_FILE [WORKDIR] | --fetch")?;
    let wd = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| format!("{}/workspace", p.home));
    if !under_workspace(Path::new(&wd), &p.home) {
        return Err(format!("{wd} is not under ~/workspace"));
    }
    if !Path::new(&wd).is_dir() {
        return Err(format!("no directory {wd}"));
    }
    if !fs::metadata(boot).is_ok_and(|m| m.len() > 0) {
        return Err(format!("no boot environment at {boot}"));
    }
    if std::env::var("AVIARY_SANDBOX_INNER").as_deref() == Ok("1") {
        inner(&p, boot, &wd)
    } else {
        outer(&p, boot, &wd)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn images_are_pinned_by_digest() {
        let d = "0".repeat(64);
        assert!(pinned(&format!("ghcr.io/de0ch/hermit-sandbox@sha256:{d}")));
        assert!(!pinned("ghcr.io/de0ch/hermit-sandbox:latest"));
        assert!(!pinned(&format!("ghcr.io/De0CH/x@sha256:{d}")));
        assert!(!pinned("ghcr.io/x@sha256:abc"));
        assert!(!pinned(&format!("@sha256:{d}")));
    }

    #[test]
    fn the_workdir_is_under_the_homes_workspace() {
        assert!(under_workspace(
            Path::new("/nowhere-home/workspace"),
            "/nowhere-home"
        ));
        assert!(under_workspace(
            Path::new("/nowhere-home/workspace/repo"),
            "/nowhere-home"
        ));
        assert!(!under_workspace(
            Path::new("/nowhere-home/workspace/../etc"),
            "/nowhere-home"
        ));
        assert!(!under_workspace(
            Path::new("/nowhere-home/workspaces"),
            "/nowhere-home"
        ));
        assert!(!under_workspace(Path::new("/etc"), "/nowhere-home"));
    }

    #[test]
    fn the_boot_environment_goes_over_the_images() {
        let cfg = json!({"Env": ["PATH=/usr/bin", "A=image", "B=image"]});
        let env = environment(&cfg, "A=boot\n# a comment\n1X=no\nC=c=d\nnot a line\n");
        assert_eq!(
            env,
            vec![
                ("PATH".into(), "/usr/bin".into()),
                ("A".into(), "boot".into()),
                ("B".into(), "image".into()),
                ("C".into(), "c=d".into())
            ]
        );
    }

    #[test]
    fn the_entrypoint_then_the_command() {
        assert_eq!(
            argv(&json!({"Entrypoint": ["/k"], "Cmd": ["run"]})),
            vec!["/k", "run"]
        );
        assert_eq!(
            argv(&json!({"Entrypoint": null, "Cmd": ["/c"]})),
            vec!["/c"]
        );
        assert!(argv(&json!({})).is_empty());
    }
}
