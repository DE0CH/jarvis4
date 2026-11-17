//! keeper_test.go (the root-only tests, rootRig, are skipped as in CI).

use super::testutil::*;
use crate::keeper::*;
use crate::secrets::{HELD, SecretsReq, answer_secrets};
use crate::snapshot::TEST_BOOTED;
use crate::supervisor::TEST_KEEPER;
use crate::vouch::HarnessSpec;
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

fn hm(kv: &[(&str, &str)]) -> HashMap<String, String> {
    kv.iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn bm(kv: &[(&str, &str)]) -> BTreeMap<String, String> {
    kv.iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn env_map(env: &[String]) -> HashMap<String, String> {
    env.iter()
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (k.into(), v.into()))
        .collect()
}

/// the harness's env: the clean env, the secrets over it, the fallback only where nothing set it, the cert's fixed
/// values over everything; never a secret with a bad name
#[test]
fn harness_spec_env() {
    let spec = HarnessSpec {
        clean: ["PATH=/bin", "LANG=C", "HOME=/home/claude"]
            .map(String::from)
            .to_vec(),
        fixed: bm(&[("SESSION_ID", "s1"), ("LANG", "fixed")]),
        fallback: bm(&[("CLAUDE_ACCOUNT", "router"), ("OTHER", "fb")]),
    };
    let m = env_map(&spec.env(&hm(&[
        ("API_KEY", "v"),
        ("CLAUDE_ACCOUNT", "store"),
        ("PATH", "/secret"),
        ("bad name", "x"),
        ("SESSION_ID", "no"),
    ])));
    let want = hm(&[
        ("PATH", "/secret"),
        ("LANG", "fixed"),
        ("HOME", "/home/claude"),
        ("API_KEY", "v"),
        ("CLAUDE_ACCOUNT", "store"),
        ("OTHER", "fb"),
        ("SESSION_ID", "s1"),
    ]);
    assert_eq!(m, want);
    let m = env_map(&spec.env(&HashMap::new()));
    assert!(
        m["CLAUDE_ACCOUNT"] == "router" && !m.contains_key("API_KEY"),
        "no secrets: {m:?}"
    );
}

fn boot_env(pid: i32, uid: u32, caller: &str) -> crate::secrets::SecretsResp {
    let c = crate::client::Client::with_url("http://127.0.0.1:9", "m1");
    answer_secrets(
        &c,
        &SecretsReq {
            op: "boot-env".into(),
            ..Default::default()
        },
        pid,
        uid,
        caller,
    )
}

fn keeper_dir_with_harness(e: &TestEnv, pid: &str) {
    *TEST_KEEPER_DIR.write().unwrap() = Some(e.root.clone());
    std::fs::write(harness_pid_path(), pid).unwrap();
}

/// boot-env: the keeper (root, the worker's parent) at any time; the boot steps (harness.pid) only before booted;
/// nobody else
#[test]
fn boot_env_for_the_keeper() {
    let e = TestEnv::new();
    HELD.set(hm(&[("API_KEY", "v1")]));
    keeper_dir_with_harness(&e, "4242");
    *TEST_BOOTED.lock().unwrap() = Some(true);
    let keeper = crate::supervisor::keeper_pid();
    let r = boot_env(keeper, 0, "keeper");
    assert!(
        r.ok && r.secrets.get("API_KEY").map(String::as_str) == Some("v1"),
        "the keeper after booted: {r:?}"
    );
    assert!(
        !boot_env(keeper, 1001, "same pid, not root").ok,
        "a non-root caller with the keeper's pid"
    );
    assert!(
        !boot_env(4242, 1001, "the launcher").ok,
        "the harness's launcher after booted"
    );
    *TEST_BOOTED.lock().unwrap() = Some(false);
    assert!(
        boot_env(4242, 1001, "the boot steps").ok,
        "the boot steps before booted"
    );
    assert!(
        !boot_env(4243, 0, "another root process").ok,
        "a root process that isn't the keeper"
    );
    HELD.set(HashMap::new());
}

/// on an AWS instance the keeper is the container's pid 1 (docker runs the image's entrypoint as init), so
/// supervisor-core's parent is pid 1; the harness's env must still get the secrets. On Fly a pid 1 that isn't the
/// keeper's binary (Fly's init, after the keeper died) gets nothing.
#[test]
fn boot_env_for_a_keeper_that_is_init() {
    let e = TestEnv::new();
    HELD.set(hm(&[("API_KEY", "v1")]));
    keeper_dir_with_harness(&e, "4242");
    *TEST_BOOTED.lock().unwrap() = Some(true);
    *TEST_KEEPER.lock().unwrap() = Some((1, true));
    let r = boot_env(1, 0, "the keeper as init");
    assert!(
        r.ok && r.secrets.get("API_KEY").map(String::as_str) == Some("v1"),
        "the keeper as pid 1: {r:?}"
    );
    *TEST_KEEPER.lock().unwrap() = Some((1, false));
    assert!(
        !boot_env(1, 0, "Fly's init").ok,
        "a pid 1 that isn't the keeper"
    );
    HELD.set(HashMap::new());
}

#[test]
fn keeper_is_init_reads_pid1s_executable() {
    let e = TestEnv::new();
    let root = e.root.join("proc");
    let (bin, other) = (root.join("jarvis-machine"), root.join("init"));
    std::fs::create_dir_all(root.join("1")).unwrap();
    std::fs::create_dir_all(root.join("self")).unwrap();
    std::fs::write(&bin, "a").unwrap();
    std::fs::write(&other, "b").unwrap();
    std::os::unix::fs::symlink(&bin, root.join("self/exe")).unwrap();
    *crate::memory::PROC_ROOT.write().unwrap() = Some(root.clone());
    std::os::unix::fs::symlink(&other, root.join("1/exe")).unwrap();
    assert!(
        !crate::supervisor::keeper_is_init(),
        "pid 1 runs another binary (Fly's init): not the keeper"
    );
    std::fs::remove_file(root.join("1/exe")).unwrap();
    std::os::unix::fs::symlink(&bin, root.join("1/exe")).unwrap();
    assert!(
        crate::supervisor::keeper_is_init(),
        "pid 1 runs this binary (the AWS container's keeper): the keeper"
    );
}

#[test]
fn exit_how_words() {
    let st = std::process::Command::new("sh")
        .args(["-c", "kill -TERM $$"])
        .status();
    assert_eq!(exit_how(&st), "killed by SIGTERM");
    let st = std::process::Command::new("sh")
        .args(["-c", "exit 3"])
        .status();
    assert_eq!(exit_how(&st), "exit status 3");
}

struct Rig {
    k: Arc<Keeper>,
    rec: PathBuf,
    done: std::sync::mpsc::Receiver<()>,
}

impl Rig {
    fn starts(&self) -> String {
        let s = std::fs::read_to_string(&self.rec).unwrap_or_default();
        s.trim()
            .lines()
            .map(|l| l.split_whitespace().collect::<Vec<_>>().join(" "))
            .collect::<Vec<_>>()
            .join(" | ")
    }

    fn ended(&self, d: Duration) -> bool {
        self.done.recv_timeout(d).is_ok()
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        self.k.stop(); // a loop never outlives its test
    }
}

/// a harness that records each start (its JARVIS_HARNESS_START, pid and API_KEY) and ends the way the test says
fn keeper_rig(e: &TestEnv, script: &str) -> Rig {
    *TEST_KEEPER_DIR.write().unwrap() = Some(e.root.clone());
    let rec = e.root.join("starts");
    let entry = e.root.join("entry.sh");
    std::fs::write(
        &entry,
        format!(
            "#!/bin/sh\necho \"$JARVIS_HARNESS_START $$ $API_KEY\" >> {}\n{script}\n",
            rec.display()
        ),
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&entry, std::fs::Permissions::from_mode(0o755)).unwrap();
    *TEST_HARNESS.lock().unwrap() = Some(TestHarness {
        entry,
        backoff0: Duration::from_millis(20),
        secrets: hm(&[("API_KEY", "held-now")]),
    });
    let k = Arc::new(Keeper::new());
    let (tx, done) = std::sync::mpsc::channel();
    let k2 = k.clone();
    let spec = HarnessSpec {
        clean: vec![format!(
            "PATH={}",
            std::env::var("PATH").unwrap_or_default()
        )],
        ..Default::default()
    };
    std::thread::spawn(move || {
        k2.harness_loop(spec);
        let _ = tx.send(());
    });
    Rig { k, rec, done }
}

fn wait_for(what: &str, d: Duration, ok: impl Fn() -> bool) {
    let end = Instant::now() + d;
    while Instant::now() < end {
        if ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("timed out waiting for {what}");
}

/// a harness killed by SIGTERM (2026-10-21: a subagent's `xargs kill` hit the launcher) is started again with the
/// secrets held now and its start number; the keeper itself carries on; a stop ends the loop
#[test]
fn the_keeper_restarts_a_killed_harness() {
    let e = TestEnv::new();
    let r = keeper_rig(&e, "kill -TERM $$");
    wait_for("three starts", Duration::from_secs(5), || {
        r.starts().matches('|').count() >= 2
    });
    let got = r.starts();
    assert!(
        got.starts_with("1 ")
            && got.contains("| 2 ")
            && got.contains("| 3 ")
            && got.contains("held-now"),
        "starts {got:?}"
    );
    r.k.stop();
    assert!(
        r.ended(Duration::from_secs(5)),
        "the harness loop didn't end on stop"
    );
    let s = r.k.harness_state();
    assert!(
        s.last_exit == "killed by SIGTERM" && s.starts >= 3 && !s.running,
        "state {s:?}"
    );
}

/// once the session is stopped for its final snapshot, a harness that ends isn't started again
#[test]
fn no_restart_after_the_final_snapshot() {
    let e = TestEnv::new();
    let r = keeper_rig(&e, "exit 1");
    std::fs::write(crate::paths::final_snapshot_sig(), "sig").unwrap();
    assert!(
        r.ended(Duration::from_secs(5)),
        "restarted after the final snapshot"
    );
    assert_eq!(r.starts().split('|').count(), 1, "starts {}", r.starts());
}

/// what is left of a dead launcher's process group (its loops) is ended before the next start
#[test]
fn the_dead_harness_group_is_cleared() {
    let e = TestEnv::new();
    let pidf = e.root.join("child");
    let r = keeper_rig(
        &e,
        &format!("sleep 300 & echo $! > {}\nkill -TERM $$", pidf.display()),
    );
    wait_for("a second start", Duration::from_secs(5), || {
        r.starts().contains("| 2 ")
    });
    let pid: i32 = std::fs::read_to_string(&pidf)
        .unwrap_or_default()
        .trim()
        .parse()
        .unwrap_or(0);
    assert!(pid > 1, "no child pid");
    wait_for("the old group's child gone", Duration::from_secs(8), || {
        // gone, or a zombie nobody reaps yet (its parent, the harness's shell, is dead: init reaps it)
        std::fs::read_to_string(format!("/proc/{pid}/stat")).map_or(true, |s| s.contains(") Z "))
    });
}

/// every command the supervisor runs for the session goes through session_command (as root: user claude); only the
/// keeper's own starts and sudo run otherwise
#[test]
fn every_command_goes_through_session_command() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let allowed: HashMap<&str, usize> = HashMap::from([
        ("keeper.rs", 3),
        ("boot.rs", 2),
        ("session.rs", 4),
        ("volume.rs", 1),
        ("output.rs", 1),
        ("vouch.rs", 1),
    ]);
    for e in std::fs::read_dir(&dir).unwrap().flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if !name.ends_with(".rs") {
            continue;
        }
        let n = std::fs::read_to_string(e.path())
            .unwrap()
            .matches("Command::new(")
            .count();
        let a = allowed.get(name.as_str()).copied().unwrap_or(0);
        assert!(
            n <= a,
            "{name}: {n} direct Command::new calls (allowed {a}): use session_command"
        );
    }
}

/// the teardown: the transcripts that changed go first (newest first, subagents after), then the final snapshot,
/// whose stream carries the transcripts and ~/.claude.json before the workspace and the artifacts. A short window
/// (the router cuts the stream off, as Fly's kill would) still leaves the router the transcript tail.
#[test]
fn the_teardown_sends_the_transcript_tail_first() {
    use std::sync::Mutex;
    let e = TestEnv::new();
    let home = e.home.clone();
    let key = e.machine_key();
    *crate::paths::TEST_CLAUDE_HOME.write().unwrap() = Some(home.clone());
    *TEST_BOOTED.lock().unwrap() = Some(true);
    *crate::supervisor::TEST_FREEZE.lock().unwrap() = Some((0, 0));
    let proj = home.join(".claude/projects/-home-claude-workspace");
    std::fs::create_dir_all(proj.join("conv1/subagents")).unwrap();
    std::fs::write(proj.join("old.jsonl"), "{\"type\":\"user\"}\n").unwrap();
    std::fs::write(
        proj.join("conv1.jsonl"),
        "{\"type\":\"assistant\",\"tail\":\"the latest turn\"}\n",
    )
    .unwrap();
    std::fs::write(
        proj.join("conv1/subagents/agent-a1.jsonl"),
        "{\"type\":\"user\"}\n",
    )
    .unwrap();
    let past = std::time::SystemTime::now() - Duration::from_secs(3600);
    std::fs::File::options()
        .write(true)
        .open(proj.join("old.jsonl"))
        .unwrap()
        .set_modified(past)
        .unwrap();
    std::fs::write(home.join(".claude.json"), "{}").unwrap();
    std::fs::create_dir_all(home.join("workspace")).unwrap();
    let mut big = vec![0u8; 4 << 20]; // incompressible: the cut-off falls inside it
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut big);
    std::fs::write(home.join("workspace/big"), &big).unwrap();
    std::fs::create_dir_all(home.join("artifacts")).unwrap();
    std::fs::write(home.join("artifacts/a"), "a").unwrap();

    let events: Arc<Mutex<Vec<String>>> = Arc::default();
    let entries: Arc<Mutex<Vec<String>>> = Arc::default();
    let (ev, en) = (events.clone(), entries.clone());
    let srv = FakeRouter::new(&key.sig.public_key(), move |r| match r.path.as_str() {
        "/m/live-transcript" => {
            let name = r
                .headers
                .get("X-Name")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            let mut ev = ev.lock().unwrap();
            if name == "conv1.jsonl"
                && !String::from_utf8_lossy(&r.body).contains("the latest turn")
            {
                ev.push("WRONG BODY".into());
            }
            ev.push(format!("live {name}"));
            ans(200, r#"{"ok":true}"#)
        }
        "/m/snapshot-upload" => ans(404, ""), // a router with no bucket URLs: the stream below
        "/m/snapshot-stream" => {
            ev.lock().unwrap().push("snapshot".into());
            // the window closes partway: what came in the first 64 KiB, as tar entries; the stream fails
            let cut = &r.body[..r.body.len().min(64 << 10)];
            if let Ok(gz) = crate::snapformat::open_snap_reader(cut) {
                let mut tr = tar::Archive::new(gz);
                if let Ok(es) = tr.entries() {
                    for h in es {
                        let Ok(h) = h else { break };
                        let Ok(p) = h.path() else { break };
                        en.lock().unwrap().push(p.to_string_lossy().into_owned());
                    }
                }
            }
            ans(502, "")
        }
        _ => ans(200, r#"{"ok":true}"#),
    });
    crate::teardown::teardown(&srv.client());

    let got = events.lock().unwrap().join(", ");
    assert_eq!(
        got, "live conv1.jsonl, live old.jsonl, live agent-a1.jsonl, snapshot",
        "order"
    );
    // the stream: the conversations and ~/.claude.json come before the workspace and the artifacts
    let entries = entries.lock().unwrap().clone();
    let mut first: HashMap<String, usize> = HashMap::new();
    for (i, e) in entries.iter().enumerate() {
        let top = if e == ".claude.json" {
            e.clone()
        } else {
            e.split('/').next().unwrap_or("").to_string()
        };
        first.entry(top).or_insert(i);
    }
    assert!(
        entries
            .first()
            .is_some_and(|e| e.starts_with(".claude/projects")),
        "the stream doesn't start with the transcripts: {entries:?}"
    );
    if let Some(w) = first.get("workspace") {
        assert!(
            *w > first[".claude.json"],
            "the workspace before ~/.claude.json: {entries:?}"
        );
    }
    assert!(
        !first.contains_key("artifacts"),
        "the artifacts reached the router before the cut-off workspace: {entries:?}"
    );
    assert!(
        !crate::snapstream::snapshot_committed(),
        "a cut-off stream was committed"
    );
}

/// a machine whose final snapshot the router already has (a pause: snapshot, then the core's stop) uploads nothing more
#[test]
fn the_teardown_after_a_pause_uploads_nothing() {
    let e = TestEnv::new();
    let key = e.machine_key();
    crate::snapstream::SIGNED.lock().unwrap().committed = true;
    let n = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let n2 = n.clone();
    let srv = FakeRouter::new(&key.sig.public_key(), move |r| {
        if r.path != "/m/supervisor-log" {
            n2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        ans(200, r#"{"ok":true}"#)
    });
    crate::teardown::teardown(&srv.client());
    let n = n.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(n, 0, "{n} uploads after a committed snapshot");
}

/// apiproxy_wait_test.go: boot waits for the local Jarvis API to accept connections, and only that long
#[test]
fn wait_api_proxy() {
    let _e = TestEnv::new();
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    crate::env::set(
        "JARVIS_API_ADDR",
        Some(&l.local_addr().unwrap().to_string()),
    );
    let t0 = Instant::now();
    crate::boot::wait_api_proxy(Duration::from_secs(5));
    assert!(
        t0.elapsed() < Duration::from_secs(2),
        "waited for a listening proxy"
    );
    drop(l);
    let t0 = Instant::now();
    crate::boot::wait_api_proxy(Duration::from_millis(600));
    assert!(
        t0.elapsed() >= Duration::from_millis(500),
        "didn't wait for a missing proxy"
    );
    crate::env::set("JARVIS_API_ADDR", None);
}
