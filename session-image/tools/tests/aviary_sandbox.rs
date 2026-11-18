//! aviary-sandbox (as root; images.yml runs `cargo test -- --ignored` under sudo): an aviary session's sandbox, on
//! stand-in trees, in a mount namespace of its own. A stand-in for aviary's sandbox image (a root filesystem with this
//! test program and its libraries, its home's links, a config whose entrypoint is this program reporting what it sees
//! from inside: [`inside_the_sandbox`]) is fetched through a stand-in `crane`, and aviary-sandbox runs it:
//!
//!  - Dogfooding (Deyao, 2026-11-14/16): the sandbox IS the image. Its entrypoint runs as PID 1 in the image's working
//!    directory with the image's environment and the boot environment, nothing of the machine's; the root is the
//!    image's (the machine's files are out of sight); the home has the image's links, so Claude Code finds its home in
//!    the supervisor's mount with nothing telling it where. A sandbox whose ~/.claude was a directory of its own had
//!    Claude Code write its transcript beside the mount: no tool calls in the chat, a turn that never ended.
//!  - The sandbox's home is the machine's home WITH what is mounted in it. ~/workspace and ~/artifacts are mounts from
//!    the session's volume; a plain bind left them out, so an aviary session's task record, cloned repos and on-start
//!    scripts were gone after its first pause (2026-11-13).
//!  - Jarvis's session commands are in the sandbox, read-only, schedule-wakeup among them (an aviary session had none
//!    of the Rust tools until 2026-11-18).

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_jarvis-tools");
const SANDBOX_TOOLS: [&str; 5] = [
    "jarvis-machine",
    "jarvis-request",
    "session-secret",
    "jarvis-tools",
    "schedule-wakeup",
];

fn sh(cmd: &mut Command) -> Output {
    cmd.output().unwrap_or_else(|e| panic!("{cmd:?}: {e}"))
}

fn mount(args: &[&str]) {
    let o = sh(Command::new("mount").args(args));
    assert!(
        o.status.success(),
        "mount {args:?}: {}",
        String::from_utf8_lossy(&o.stderr)
    );
}

fn write(p: impl AsRef<Path>, s: &str) {
    let p = p.as_ref();
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, s).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
}

fn read(p: impl AsRef<Path>) -> String {
    fs::read_to_string(p.as_ref()).unwrap_or_else(|e| format!("({}: {e})", p.as_ref().display()))
}

fn readlink(p: impl AsRef<Path>) -> String {
    fs::read_link(p)
        .map(|l| l.display().to_string())
        .unwrap_or_default()
}

/// This machine's program at the same path in `root`, with the libraries it loads.
fn put(root: &Path, prog: &Path, at: &str) {
    let dst = root.join(at.trim_start_matches('/'));
    fs::create_dir_all(dst.parent().unwrap()).unwrap();
    fs::copy(prog, &dst).unwrap();
    let ldd = String::from_utf8_lossy(&sh(Command::new("ldd").arg(prog)).stdout).to_string();
    for lib in ldd.split_whitespace().filter(|w| w.starts_with('/')) {
        let d = root.join(lib.trim_start_matches('/'));
        if !d.exists() {
            fs::create_dir_all(d.parent().unwrap()).unwrap();
            fs::copy(lib, &d).unwrap();
        }
    }
}

fn chown_r(p: &Path) {
    let o = sh(Command::new("chown").args(["-hR", "1000:1000"]).arg(p));
    assert!(o.status.success());
}

/// aviary-sandbox ARGS with the test's environment: (status, stderr).
fn sandbox(env: &[(&str, String)], args: &[&str]) -> (i32, String) {
    let o = sh(Command::new(BIN)
        .arg("aviary-sandbox")
        .args(args)
        .envs(env.iter().map(|(k, v)| (*k, v))));
    (
        o.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&o.stderr).to_string(),
    )
}

/// The stand-in image's entrypoint: this test program, run as PID 1 inside the sandbox (the config's Env sets
/// AVIARY_SANDBOX_CHECK); outside it the test does nothing.
#[test]
#[ignore = "the stand-in image's entrypoint (run by the_sandbox_is_the_image)"]
fn inside_the_sandbox() {
    if std::env::var("AVIARY_SANDBOX_CHECK").as_deref() != Ok("1") {
        return;
    }
    let mut out = String::new();
    let mut say = |s: String| {
        out.push_str(&s);
        out.push('\n');
    };
    let env = |k: &str| std::env::var(k).unwrap_or_else(|_| "none".into());
    say(format!("pid={}", std::process::id()));
    say(format!(
        "cwd={}",
        std::env::current_dir().unwrap().display()
    ));
    say(format!("image-env={}", env("IMAGE_ENV")));
    say(format!("boot-env={}", env("BOOT_VAR")));
    say(format!("machine-env={}", env("MACHINE_VAR")));
    say(format!("path={}", env("PATH")));
    say(format!(
        "workspace={}",
        read("/home/sandbox/workspace/where").trim()
    ));
    say(format!(
        "artifacts={}",
        read("/home/sandbox/artifacts/where").trim()
    ));
    say(format!("claude-link={}", readlink("/home/sandbox/.claude")));
    let harness: Vec<String> = fs::read_dir("/home/sandbox/.harness")
        .map(|d| {
            d.flatten()
                .map(|e| e.file_name().to_string_lossy().to_string())
                .collect()
        })
        .unwrap_or_default();
    say(format!("harness={}", harness.join(" ")));
    // what Claude Code does
    let _ = fs::create_dir("/home/sandbox/.harness/claude");
    let _ = fs::write("/home/sandbox/.claude/transcript", "line\n");
    say(format!(
        "transcript={}",
        read("/home/sandbox/.harness/claude/transcript").trim()
    ));
    say(format!("wd={}", read("/workspace/f").trim()));
    say(format!(
        "keeper={}",
        read("/usr/local/bin/supervisor-keeper").trim()
    ));
    let marker = env("MARKER");
    let mnt: Vec<String> = fs::read_dir("/mnt")
        .map(|d| {
            d.flatten()
                .map(|e| e.file_name().to_string_lossy().to_string())
                .collect()
        })
        .unwrap_or_default();
    say(format!(
        "machine-root={}; mnt={}",
        if Path::new(&marker).exists() {
            "visible"
        } else {
            "gone"
        },
        mnt.join(" ")
    ));
    for t in SANDBOX_TOOLS {
        say(format!(
            "tool {t}={}",
            read(format!("/usr/local/bin/{t}")).trim()
        ));
        if fs::OpenOptions::new()
            .write(true)
            .open(format!("/usr/local/bin/{t}"))
            .is_ok()
        {
            say(format!("tool-writable {t}"));
        }
    }
    say(format!("jarvis={}", readlink("/usr/local/bin/jarvis")));
    say(format!("secrets={}", read("/run/jarvis/sock").trim()));
    say(format!(
        "resolv={}",
        read("/etc/resolv.conf").lines().next().unwrap_or_default()
    ));
    say(format!(
        "installed-before={}",
        fs::read_to_string("/etc/installed").map_or("no".into(), |s| s.trim().to_string())
    ));
    fs::write("/etc/installed", "yes\n").unwrap();
    fs::write("/run/jarvis-transcripts/c.jsonl", "t").unwrap();
    fs::write("/home/sandbox/artifacts/result", out).unwrap();
    std::process::exit(7);
}

#[test]
#[ignore = "needs root: mounts and namespaces (images.yml runs it with sudo)"]
fn the_sandbox_is_the_image() {
    // SAFETY: a plain system call
    assert_eq!(unsafe { libc::geteuid() }, 0, "run as root");
    if std::env::var("AVIARY_SANDBOX_TEST_INNER").as_deref() != Ok("1") {
        // a private mount namespace of its own, as the machine gives the sandbox
        let me = std::env::current_exe().unwrap();
        let o = sh(Command::new("unshare")
            .args(["--mount", "--propagation", "private"])
            .arg(me)
            .args([
                "the_sandbox_is_the_image",
                "--exact",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("AVIARY_SANDBOX_TEST_INNER", "1"));
        let all = format!(
            "{}{}",
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        );
        assert!(o.status.success() && all.contains("1 passed"), "{all}");
        return;
    }
    let t =
        PathBuf::from(String::from_utf8_lossy(&sh(Command::new("mktemp").arg("-d")).stdout).trim());
    fs::set_permissions(&t, fs::Permissions::from_mode(0o755)).unwrap();

    // ---- the stand-in image: a root filesystem and its config
    let src = t.join("image-src");
    put(&src, &std::env::current_exe().unwrap(), "/check");
    for d in [
        "proc",
        "sys",
        "dev",
        "run",
        "mnt",
        "etc",
        "tmp",
        "work",
        "workspace",
        "usr/local/bin",
        "home/sandbox/.harness",
    ] {
        fs::create_dir_all(src.join(d)).unwrap();
    }
    symlink(".harness/claude", src.join("home/sandbox/.claude")).unwrap();
    symlink(".harness/qwen", src.join("home/sandbox/.qwen")).unwrap();
    write(src.join("home/sandbox/.npmrc"), "prefix=~/.npm-global\n");
    chown_r(&src.join("home/sandbox"));
    write(src.join("usr/local/bin/supervisor-keeper"), "image\n");
    let config = serde_json::json!({"config": {
        "Env": ["PATH=/usr/local/bin:/usr/bin:/bin", "IMAGE_ENV=from-the-image", "AVIARY_SANDBOX_CHECK=1"],
        "WorkingDir": "/work",
        "Entrypoint": ["/check", "inside_the_sandbox", "--exact", "--ignored", "--test-threads=1", "-q"]
    }});
    write(t.join("config.json"), &config.to_string());
    let digest = format!("{:064}", 7);
    let id = &digest[..12];
    write(
        t.join("pins.json"),
        &format!(
            "{{\"release\": \"aviary-test\", \"sandbox\": \"ghcr.io/de0ch/hermit-sandbox@sha256:{digest}\"}}"
        ),
    );
    // the stand-in crane: `export REF -` the image's files as a tar, `config REF` its config
    let crane = t.join("path/crane");
    write(
        &crane,
        &format!(
            "#!/usr/bin/env -S python3 -I\nimport os, sys\nopen({calls:?}, 'a').write(' '.join(sys.argv[1:]) + '\\n')\n\
             if sys.argv[1] == 'export':\n    os.execvp('tar', ['tar', '-c', '-C', {src:?}, '.'])\n\
             if sys.argv[1] == 'config':\n    sys.stdout.write(open({cfg:?}).read())\n    sys.exit(0)\nsys.exit(1)\n",
            calls = t.join("crane.calls").display().to_string(),
            src = src.display().to_string(),
            cfg = t.join("config.json").display().to_string(),
        ),
    );
    fs::set_permissions(&crane, fs::Permissions::from_mode(0o755)).unwrap();

    // ---- the machine: its home with the volume's directories mounted in, its own ~/.claude, its session commands
    let home = t.join("claude");
    for d in [
        "artifacts",
        "workspace",
        ".claude/projects",
        ".claude/sessions",
    ] {
        fs::create_dir_all(home.join(d)).unwrap();
    }
    let (bin, store) = (t.join("bin"), t.join("store"));
    fs::create_dir_all(&bin).unwrap();
    fs::create_dir_all(&store).unwrap();
    // the session's volume (an overlay's upper cannot sit on a machine's overlay root)
    mount(&["-t", "tmpfs", "tmpfs", store.to_str().unwrap()]);
    fs::create_dir(store.join("image-old")).unwrap();
    fs::create_dir(store.join("upper-old")).unwrap();
    write(home.join("artifacts/where"), "root-disk\n");
    for d in ["artifacts", "workspace"] {
        mount(&["-t", "tmpfs", "tmpfs", home.join(d).to_str().unwrap()]);
        write(home.join(d).join("where"), "volume\n");
    }
    write(home.join("workspace/repo/f"), "repo-file\n");
    write(home.join(".claude/.credentials.json"), "login\n");
    // the volume's transcript mirror, mounted inside as the entrypoint does
    mount(&[
        "-t",
        "tmpfs",
        "tmpfs",
        home.join(".claude/projects").to_str().unwrap(),
    ]);
    fs::create_dir(home.join(".claude/projects/-home-claude-workspace")).unwrap();
    for c in [
        "jarvis-machine",
        "jarvis-request",
        "session-secret",
        "jarvis-tools",
    ] {
        write(bin.join(c), &format!("machine's {c}\n"));
    }
    // on the machine the tools' names are links to jarvis-tools
    symlink("jarvis-tools", bin.join("schedule-wakeup")).unwrap();
    let marker = t.join("pins.json");
    write(
        t.join("boot.env"),
        &format!("BOOT_VAR=from-the-boot\nMARKER={}\n", marker.display()),
    );
    let path = format!(
        "{}:{}",
        t.join("path").display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let env: Vec<(&str, String)> = vec![
        ("AVIARY_PINS", t.join("pins.json").display().to_string()),
        ("AVIARY_SANDBOX_STORE", store.display().to_string()),
        ("AVIARY_SANDBOX_HOME", home.display().to_string()),
        ("AVIARY_SANDBOX_BIN", bin.display().to_string()),
        ("PATH", path),
        ("MACHINE_VAR", "from-the-machine".into()),
    ];
    let (boot, repo) = (
        t.join("boot.env").display().to_string(),
        home.join("workspace/repo").display().to_string(),
    );

    // ---- the fetch: the image on the volume, another pin's image and overlay gone
    let o = sh(Command::new(BIN)
        .args(["aviary-sandbox", "--fetch"])
        .envs(env.iter().map(|(k, v)| (*k, v))));
    let img = PathBuf::from(String::from_utf8_lossy(&o.stdout).trim());
    assert_eq!(
        img,
        store.join(format!("image-{id}")),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(
        img.join("check").exists()
            && fs::metadata(format!("{}.config", img.display()))
                .unwrap()
                .len()
                > 0
    );
    assert!(
        !store.join("image-old").exists() && !store.join("upper-old").exists(),
        "another pin's image stays on the volume"
    );
    sandbox(&env, &["--fetch"]);
    assert_eq!(
        read(t.join("crane.calls"))
            .lines()
            .filter(|l| l.starts_with("export"))
            .count(),
        1,
        "an image already on the volume is fetched again"
    );

    // ---- the home gets what the image's home holds; without that the sandbox refuses to start
    let (rc, err) = sandbox(&env, &[&boot, &repo]);
    assert_ne!(
        rc, 0,
        "the sandbox started in a home without the image's links"
    );
    assert!(
        err.contains("aviary-home"),
        "no word on why the sandbox did not start: {err}"
    );
    let aviary_home = Path::new(env!("CARGO_MANIFEST_DIR")).join("../base/aviary-home");
    for _ in 0..2 {
        // twice: nothing changes the second time
        let o = sh(Command::new(&aviary_home)
            .arg(&home)
            .arg(img.join("home/sandbox")));
        assert!(
            o.status.success(),
            "aviary-home: {}",
            String::from_utf8_lossy(&o.stderr)
        );
    }
    assert_eq!(readlink(home.join(".claude")), ".harness/claude");
    assert_eq!(readlink(home.join(".qwen")), ".harness/qwen");
    assert_eq!(read(home.join(".npmrc")).trim(), "prefix=~/.npm-global");
    assert_eq!(
        read(home.join(".claude/.credentials.json")).trim(),
        "login",
        "the machine's ~/.claude files are not reachable through the link"
    );

    // ---- the sandbox
    let (rc, err) = sandbox(&env, &[&boot, &repo]);
    assert_eq!(
        rc, 7,
        "the sandbox did not end with the image's entrypoint's status (7): {err}"
    );
    let r = read(home.join("artifacts/result"));
    let want = |line: &str, why: &str| {
        assert!(
            r.lines().any(|l| l == line),
            "{why} (wanted: {line}) in:\n{r}"
        )
    };
    want("pid=1", "the image's entrypoint is not PID 1");
    want(
        "cwd=/work",
        "the entrypoint does not start in the image's working directory",
    );
    want(
        "image-env=from-the-image",
        "the image's environment is not the entrypoint's",
    );
    want(
        "boot-env=from-the-boot",
        "the boot environment is not passed on",
    );
    want(
        "machine-env=none",
        "the machine's environment reaches the sandbox",
    );
    want(
        "path=/usr/local/bin:/usr/bin:/bin",
        "the PATH is not the image's",
    );
    want(
        "workspace=volume",
        "the sandbox's ~/workspace is the machine's root disk, not the volume",
    );
    want(
        "artifacts=volume",
        "the sandbox's ~/artifacts is the machine's root disk, not the volume",
    );
    want(
        "claude-link=.harness/claude",
        "the sandbox's ~/.claude is not the image's link",
    );
    want(
        "harness=",
        "the machine's ~/.harness (its login, the mirror) shows in the sandbox",
    );
    want(
        "transcript=line",
        "a file written to the sandbox's ~/.claude is not in ~/.harness (the supervisor's mount)",
    );
    want(
        "wd=repo-file",
        "/workspace is not the harness's working directory",
    );
    want("keeper=image", "the supervisor is not the image's own");
    want(
        "machine-root=gone; mnt=",
        "the machine's root is visible in the sandbox",
    );
    for c in [
        "jarvis-machine",
        "jarvis-request",
        "session-secret",
        "jarvis-tools",
    ] {
        want(
            &format!("tool {c}=machine's {c}"),
            "Jarvis's session commands are not in the sandbox",
        );
    }
    want(
        "tool schedule-wakeup=machine's jarvis-tools",
        "schedule-wakeup (a link to jarvis-tools) is not in the sandbox",
    );
    want("jarvis=jarvis-machine", "no jarvis link in the sandbox");
    want(
        &format!(
            "secrets=({})",
            "/run/jarvis/sock: No such file or directory (os error 2)"
        ),
        "unexpected /run/jarvis",
    );
    want(
        &format!(
            "resolv={}",
            read("/etc/resolv.conf").lines().next().unwrap_or_default()
        ),
        "the sandbox has not the machine's resolv.conf",
    );
    want(
        "installed-before=no",
        "the image's root is not clean at the first start",
    );
    assert!(
        !r.contains("tool-writable"),
        "the sandbox can write Jarvis's session commands:\n{r}"
    );
    assert!(
        !home.join(".harness/claude/transcript").exists(),
        "the sandbox's ~/.claude writes into the machine's own"
    );
    assert_eq!(
        read(home.join(".claude/projects/-home-claude-workspace/c.jsonl")),
        "t",
        "/run/jarvis-transcripts is not the machine's transcript mirror"
    );
    assert!(
        !img.join("etc/installed").exists()
            && read(store.join(format!("upper-{id}/up/etc/installed"))).trim() == "yes",
        "what the agent installs is written into the image, not over it"
    );
    // again: what was installed is still there (a sandbox's root lives as long as the session)
    sandbox(&env, &[&boot, &repo]);
    let r = read(home.join("artifacts/result"));
    assert!(
        r.lines().any(|l| l == "installed-before=yes"),
        "what the agent installed is gone at the next start:\n{r}"
    );
    // nothing of the sandbox's mounts is left on the machine's side
    let mounts =
        String::from_utf8_lossy(&sh(Command::new("findmnt").args(["-rn", "-o", "TARGET"])).stdout)
            .to_string();
    assert!(
        !mounts.contains("aviary-sandbox-root"),
        "the sandbox's root is mounted on the machine's side"
    );

    // ---- a fabric machine (docs/PLAN-fabric.md): the image unpacked in the fabric image, its config beside it;
    // nothing is fetched, the root is a bind of that directory (gVisor refuses the overlay), what is installed goes in it
    let fab = t.join("fabric");
    fs::create_dir_all(&fab).unwrap();
    mount(&["-t", "tmpfs", "tmpfs", fab.to_str().unwrap()]); // the fabric's own writable root
    assert!(
        sh(Command::new("cp")
            .arg("-a")
            .arg(&src)
            .arg(fab.join("aviary-sandbox")))
        .status
        .success()
    );
    fs::copy(t.join("config.json"), fab.join("aviary-sandbox.config")).unwrap();
    let calls_before = read(t.join("crane.calls")).lines().count();
    let mut fenv = env.clone();
    fenv.push((
        "AVIARY_SANDBOX_IMAGE_DIR",
        fab.join("aviary-sandbox").display().to_string(),
    ));
    let (rc, err) = sandbox(&fenv, &[&boot, &repo]);
    assert_eq!(
        rc, 7,
        "the fabric sandbox did not end with the image's entrypoint's status (7): {err}"
    );
    let r = read(home.join("artifacts/result"));
    for (line, why) in [
        ("pid=1", "the image's entrypoint is not PID 1"),
        (
            "boot-env=from-the-boot",
            "the boot environment is not passed on",
        ),
        (
            "machine-root=gone; mnt=",
            "the machine's root is visible in the sandbox",
        ),
        (
            "workspace=volume",
            "the sandbox's ~/workspace is not the machine's home",
        ),
        (
            "installed-before=no",
            "the image's root is not clean at the first start",
        ),
    ] {
        assert!(
            r.lines().any(|l| l == line),
            "(fabric) {why} (wanted: {line}) in:\n{r}"
        );
    }
    assert_eq!(
        read(fab.join("aviary-sandbox/etc/installed")).trim(),
        "yes",
        "(fabric) what the agent installs is not in the fabric's root"
    );
    assert_eq!(
        read(t.join("crane.calls")).lines().count(),
        calls_before,
        "(fabric) the image was fetched"
    );
    let mut nowhere = env.clone();
    nowhere.push((
        "AVIARY_SANDBOX_IMAGE_DIR",
        t.join("nowhere").display().to_string(),
    ));
    let (rc, err) = sandbox(&nowhere, &[&boot, &repo]);
    assert!(
        rc != 0 && err.contains("no sandbox image at"),
        "(fabric) a missing image dir started: {err}"
    );

    // ---- both ways aviary-home moves the machine's ~/.claude: the atomic exchange, and the copy a new machine's
    // overlay root needs (it refuses to rename a directory that comes from several image layers: 2026-11-14)
    for way in ["exchange", "copy"] {
        let h = PathBuf::from(
            String::from_utf8_lossy(&sh(Command::new("mktemp").arg("-d")).stdout).trim(),
        )
        .join("claude");
        write(h.join(".claude/.credentials.json"), "login\n");
        write(h.join(".claude/sessions/aviary.json"), "shim\n");
        fs::create_dir_all(h.join(".claude/projects")).unwrap();
        mount(&[
            "-t",
            "tmpfs",
            "tmpfs",
            h.join(".claude/projects").to_str().unwrap(),
        ]);
        write(h.join(".claude/projects/t.jsonl"), "mirror\n");
        for _ in 0..2 {
            let mut cmd = Command::new(&aviary_home);
            cmd.arg(&h).arg(img.join("home/sandbox"));
            if way == "copy" {
                cmd.env("AVIARY_HOME_TEST_NO_EXCHANGE", "1");
            }
            let o = sh(&mut cmd);
            assert!(
                o.status.success(),
                "({way}) aviary-home: {}",
                String::from_utf8_lossy(&o.stderr)
            );
        }
        assert_eq!(
            readlink(h.join(".claude")),
            ".harness/claude",
            "({way}) the home's ~/.claude is not a link to .harness/claude"
        );
        assert_eq!(
            readlink(h.join(".qwen")),
            ".harness/qwen",
            "({way}) the home's ~/.qwen is not a link to .harness/qwen"
        );
        // the machine's side still reaches its own files through the old paths, the volume's mount among them
        assert_eq!(
            read(h.join(".claude/.credentials.json")).trim(),
            "login",
            "({way})"
        );
        assert_eq!(
            read(h.join(".claude/sessions/aviary.json")).trim(),
            "shim",
            "({way})"
        );
        assert_eq!(
            read(h.join(".claude/projects/t.jsonl")).trim(),
            "mirror",
            "({way})"
        );
        let mounts = String::from_utf8_lossy(
            &sh(Command::new("findmnt").args(["-rn", "-o", "TARGET"])).stdout,
        )
        .to_string();
        let under: Vec<&str> = mounts
            .lines()
            .filter(|m| m.starts_with(&format!("{}/", h.display())))
            .collect();
        assert_eq!(
            under,
            vec![format!("{}/.harness/claude/projects", h.display())],
            "({way}) the volume's mount is not (only) at ~/.harness/claude/projects"
        );
    }
}

/// Nothing of the image's is written a second time here (the dogfood-aviary check).
#[test]
fn the_supervisor_claude_code_and_the_home_links_come_from_the_image_only() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let sandbox = read(dir.join("src/aviary_sandbox.rs"));
    let harness = read(dir.join("../base/harness-aviary.sh"));
    let home = read(dir.join("../base/aviary-home"));
    let image = read(dir.join("../Dockerfile"));
    assert!(
        !sandbox.contains("CLAUDE_CONFIG_DIR") && !harness.contains("CLAUDE_CONFIG_DIR"),
        "the harness tells Claude Code where its home is (an aviary sandbox never does)"
    );
    for s in [&sandbox, &home] {
        for bad in [
            "npm install",
            "claude-code@",
            ".harness/claude\"",
            ".harness/qwen\"",
        ] {
            assert!(
                !s.contains(bad),
                "the harness installs Claude Code or names the image's links itself ({bad})"
            );
        }
    }
    assert!(
        !image.contains("/out/supervisor")
            && !(image.contains("releases/download/") && image.contains("supervisor")),
        "the session image carries a supervisor of its own"
    );
}
