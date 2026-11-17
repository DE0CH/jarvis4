//! task_test.go, memory_test.go and oomguard_test.go (the parts that run as any user; the cgroup and mlock tests need
//! root and a cgroup v1 machine, as in Go, where CI skips them too).

use super::testutil::*;
use crate::deliver::{Delivery, delivery_text, upgraded_text};
use crate::memory::*;
use crate::oomguard::{rescue_limit, session_limit};
use crate::task::*;
use nix::sys::signal::Signal;
use std::collections::{BTreeMap, HashMap};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

fn write_template(root: &Path, name: &str, spec: &str, files: &[(&str, &str)]) -> PathBuf {
    let dir = root.join(name);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("task.json"), spec).unwrap();
    for (f, body) in files {
        std::fs::write(dir.join(f), body).unwrap();
        std::fs::set_permissions(dir.join(f), std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    dir
}

#[test]
fn load_task_spec_and_command() {
    let root = tempdir();
    let d = write_template(
        &root,
        "a",
        r#"{"title":"A","timeoutSeconds":30}"#,
        &[("run.sh", "echo")],
    );
    let (s, timeout) = load_task_spec(&d).unwrap();
    assert_eq!(
        (s.run.as_str(), timeout),
        ("run.sh", Duration::from_secs(30))
    );
    let (args, stdin) = task_command(&d, &s, "auto", "").unwrap();
    assert_eq!(
        args.join(" "),
        format!("bash {}", d.join("run.sh").display())
    );
    assert!(stdin.is_empty());
    for (f, want) in [
        ("x.py", "python3 -u".to_string()),
        ("x.js", "node".into()),
        ("x", d.join("x").display().to_string()),
    ] {
        let spec = TaskSpec {
            run: f.into(),
            ..Default::default()
        };
        let (a, _) = task_command(&d, &spec, "auto", "").unwrap();
        assert!(a.join(" ").starts_with(&want), "{f}: {a:?}");
    }
    let p = write_template(
        &root,
        "p",
        r#"{"title":"P","model":"claude-fable-5-2"}"#,
        &[(
            "prompt.md",
            "Summarise {{topic}} for {{ who }}; keep {{unknown}}.",
        )],
    );
    let (s, timeout) = load_task_spec(&p).unwrap();
    assert_eq!(
        (s.prompt.as_str(), timeout),
        ("prompt.md", Duration::from_secs(600))
    );
    let (args, stdin) =
        task_command(&p, &s, "bypass", r#"{"topic":"the news","who":["a","b"]}"#).unwrap();
    assert_eq!(stdin, "Summarise the news for a,b; keep {{unknown}}.");
    assert_eq!(
        args.join(" "),
        "claude -p --output-format text --dangerously-skip-permissions --model claude-fable-5-2"
    );
    let (args, _) = task_command(&p, &s, "auto", "").unwrap();
    assert!(
        args.join(" ").contains("--permission-mode auto"),
        "{args:?}"
    );
    for spec in [
        r#"{"run":"missing.sh"}"#,
        r#"{"run":"../x"}"#,
        "{}",
        "not json",
    ] {
        let d = write_template(&root, "bad", spec, &[]);
        assert!(load_task_spec(&d).is_err(), "accepted {spec}");
        std::fs::remove_dir_all(&d).unwrap();
    }
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn task_environ_order() {
    let os_env: Vec<String> = [
        "PATH=/bin",
        "HOME=/home/claude",
        "LD_PRELOAD=/evil.so",
        "BASH_ENV=/evil",
        "TASK_PARAMS={}",
        "PARAM_MSG=hi",
        "PARAM_TOKEN=router",
        "SESSION_PROMPT=x",
        "JARVIS_URL=http://127.0.0.1:7171",
        "TASK_OUTPUT=/router/says",
    ]
    .map(String::from)
    .to_vec();
    let secrets: HashMap<String, String> = [
        ("PARAM_TOKEN", "store"),
        ("API_KEY", "k"),
        ("bad name", "x"),
    ]
    .map(|(k, v)| (k.into(), v.into()))
    .into();
    let fixed: BTreeMap<String, String> = [("TASK_OUTPUT".to_string(), "/real".to_string())].into();
    let env = task_environ(&os_env, &secrets, &fixed).join("\n") + "\n";
    for want in [
        "PATH=/bin\n",
        "HOME=/home/claude\n",
        "PARAM_MSG=hi\n",
        "TASK_PARAMS={}\n",
        "API_KEY=k\n",
        "PARAM_TOKEN=store\n",
        "TASK_OUTPUT=/real\n",
        "JARVIS_URL=http://127.0.0.1:7171\n",
        "LANG=C.UTF-8\n",
    ] {
        assert!(env.contains(want), "missing {want:?}");
    }
    for not in [
        "LD_PRELOAD",
        "BASH_ENV",
        "SESSION_PROMPT",
        "bad name",
        "/router/says",
    ] {
        assert!(!env.contains(not), "leaked {not:?}");
    }
}

#[test]
fn redact_longest_first() {
    let secrets: HashMap<String, String> =
        [("A", "abcdef123"), ("B", "abcdef123456"), ("S", "abc")]
            .map(|(k, v)| (k.into(), v.into()))
            .into();
    assert_eq!(
        redact("key=abcdef123 short=abc long=abcdef123456", &secrets),
        "key=[secret A] short=abc long=[secret B]"
    );
}

#[test]
fn exec_task_runs_and_times_out() {
    let dir = tempdir();
    let logp = dir.join("log");
    let env: Vec<String> = std::env::vars().map(|(k, v)| format!("{k}={v}")).collect();
    let s = |a: &[&str]| a.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    let (code, to) = exec_task(
        &s(&["bash", "-c", "echo out; echo err >&2; exit 4"]),
        "",
        &env,
        &dir,
        &logp,
        Duration::from_secs(5),
    )
    .unwrap();
    assert_eq!(
        (code, to, std::fs::read_to_string(&logp).unwrap().as_str()),
        (4, false, "out\nerr\n")
    );
    let (code, _) = exec_task(
        &s(&["bash", "-c", "cat"]),
        "from stdin",
        &env,
        &dir,
        &logp,
        Duration::from_secs(5),
    )
    .unwrap();
    assert_eq!(
        (code, std::fs::read_to_string(&logp).unwrap().as_str()),
        (0, "from stdin")
    );
    // the timeout kills the whole process group (a child that ignores the parent's death too)
    let marker = dir.join("late");
    let start = std::time::Instant::now();
    let script = format!("(sleep 1; touch {}) & sleep 30", marker.display());
    let (_, to) = exec_task(
        &s(&["bash", "-c", &script]),
        "",
        &env,
        &dir,
        &logp,
        Duration::from_millis(200),
    )
    .unwrap();
    assert!(to && start.elapsed() < Duration::from_secs(5), "no timeout");
    std::thread::sleep(Duration::from_millis(1500));
    assert!(!marker.exists(), "a child outlived the timeout");
    assert!(
        exec_task(
            &[dir.join("nope").display().to_string()],
            "",
            &[],
            &dir,
            &logp,
            Duration::from_secs(1)
        )
        .is_err(),
        "a missing program ran"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn do_run_reports_redacted() {
    let e = TestEnv::new();
    let root = e.root.join("tasks");
    *TASKS_ROOT.write().unwrap() = Some(root.clone());
    write_template(
        &root,
        "job",
        r#"{"title":"Job","timeoutSeconds":20}"#,
        &[(
            "run.sh",
            r#"
n=$(( $(cat "$TASK_STATE_DIR/n" 2>/dev/null || echo 0) + 1 )); echo $n > "$TASK_STATE_DIR/n"
echo "run $n msg=$PARAM_MSG secret=$API_KEY cwd=$(pwd)"
echo "result $n $API_KEY" > "$TASK_OUTPUT"
[ "$PARAM_FAIL" = true ] && exit 2
exit 0"#,
        )],
    );
    crate::env::set("PARAM_MSG", Some("hi"));
    crate::env::set("TASK_PARAMS", Some(r#"{"msg":"hi"}"#));
    let secrets: HashMap<String, String> =
        [("API_KEY".to_string(), "s3cr3t-value".to_string())].into();
    let res = do_run("job", "r1", &secrets, &[], "auto");
    assert!(
        res.error.is_empty() && res.exit_code == 0 && res.run == "r1",
        "{res:?}"
    );
    assert!(
        res.log.contains(&format!(
            "run 1 msg=hi secret=[secret API_KEY] cwd={}",
            e.home.join("task-work").display()
        )),
        "{:?}",
        res.log
    );
    assert_eq!(res.output, "result 1 [secret API_KEY]\n");
    let disk = std::fs::read_to_string(e.home.join("artifacts/task-runs/r1.log")).unwrap();
    assert!(!disk.contains("s3cr3t"), "the log on disk keeps the secret");
    assert!(
        !e.home.join(".secrets").exists(),
        "~/.secrets written: secrets stay in RAM"
    );
    crate::env::set("PARAM_FAIL", Some("true"));
    let res = do_run("job", "r2", &secrets, &[], "auto");
    assert!(res.exit_code == 2 && res.log.contains("run 2"), "{res:?}");
    let res = do_run("nope", "r3", &secrets, &[], "auto");
    assert!(!res.error.is_empty() && res.exit_code == -1, "{res:?}");
    let res = do_run("../etc", "r4", &secrets, &[], "auto");
    assert!(res.error.contains("bad template name"), "{res:?}");
}

#[test]
fn prune_logs_keeps_the_newest() {
    let dir = tempdir();
    let base = std::time::SystemTime::now() - Duration::from_secs(3600);
    for k in 0..23u64 {
        for ext in [".log", ".output"] {
            let p = dir.join(format!("r{k:02}{ext}"));
            std::fs::write(&p, "x").unwrap();
            std::fs::File::options()
                .write(true)
                .open(&p)
                .unwrap()
                .set_modified(base + Duration::from_secs(60 * k))
                .unwrap();
        }
    }
    prune_logs(&dir);
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 40);
    assert!(!dir.join("r00.log").exists(), "the oldest stayed");
    let _ = std::fs::remove_dir_all(&dir);
}

fn fake_proc(root: &Path) {
    let w = |rel: &str, s: &str| {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, s).unwrap();
    };
    w(
        "meminfo",
        "MemTotal:        4002000 kB\nMemFree:          100000 kB\nMemAvailable:     400000 kB\n",
    );
    w("vmstat", "pgfault 12\noom_kill 3\n");
    w(
        "pressure/memory",
        "some avg10=1.00 avg60=2.00 avg300=0.50 total=1\nfull avg10=0.50 avg60=12.50 avg300=0.10 total=2\n",
    );
    for (pid, name, uid, rss) in [
        ("1", "init", 0, 1000),
        ("10", "harness", 1000, 50000),
        ("11", "jarvis-machine", 1000, 20000),
        ("12", "claude", 1000, 900000),
        ("13", "chrome", 1000, 600000),
        ("14", "sshd", 0, 700000),
    ] {
        w(
            &format!("{pid}/status"),
            &format!("Name:\t{name}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\nVmRSS:\t   {rss} kB\n"),
        );
    }
}

#[test]
fn read_memory_sample() {
    let e = TestEnv::new();
    let root = e.root.join("proc");
    fake_proc(&root);
    *PROC_ROOT.write().unwrap() = Some(root);
    let s = read_memory().unwrap();
    assert_eq!(
        (s.total_kb, s.avail_kb, s.oom_kills, s.psi_full60),
        (4002000, 400000, Some(3), Some(12.5))
    );
    let top: Vec<String> = s.top.unwrap().iter().map(|p| p.comm.clone()).collect();
    assert_eq!(top, vec!["claude", "sshd", "chrome"]);
}

#[test]
fn free_processes_spares_the_supervisor() {
    let e = TestEnv::new();
    let root = e.root.join("proc");
    fake_proc(&root);
    *PROC_ROOT.write().unwrap() = Some(root);
    *TEST_SIGNALS.lock().unwrap() = Some(vec![]);
    let killed = free_processes(11, 10, 1000);
    let sent: HashMap<i32, Signal> = TEST_SIGNALS
        .lock()
        .unwrap()
        .clone()
        .unwrap()
        .into_iter()
        .collect();
    assert_eq!(
        sent.get(&10),
        Some(&Signal::SIGSTOP),
        "the harness must be stopped, not killed: {sent:?}"
    );
    assert_eq!(
        (sent.get(&12), sent.get(&13)),
        (Some(&Signal::SIGKILL), Some(&Signal::SIGKILL)),
        "{sent:?}"
    );
    assert!(!sent.contains_key(&11), "the supervisor killed itself");
    assert!(
        !sent.contains_key(&14),
        "another user's process was signalled"
    );
    assert!(!sent.contains_key(&1), "init was signalled");
    assert_eq!(killed.len(), 2);
    assert_eq!(killed[0].comm, "claude");
    let b = std::fs::read_to_string(e.home.join(FREED_FILE)).unwrap();
    assert!(
        b.contains("878 MB\tclaude") && b.contains("585 MB\tchrome"),
        "{b:?}"
    );
}

#[test]
fn upgraded_text_names_the_sizes() {
    let s = upgraded_text("medium", "large").unwrap();
    assert!(s.contains("from a medium (4 GB) to a large (8 GB)"), "{s}");
    let s = upgraded_text("16gb", "32gb").unwrap();
    assert!(s.contains("from a 16 GB to a 32 GB machine"), "{s}");
    for bad in ["do this instead", "24gb", "8gb"] {
        assert!(
            upgraded_text("medium", bad).is_err(),
            "{bad:?} isn't a size"
        );
    }
    let d = Delivery {
        kind: "upgraded".into(),
        from: "small".into(),
        to: "medium".into(),
        ..Default::default()
    };
    delivery_text(&d, &[]).unwrap();
}

#[test]
fn session_and_rescue_limits() {
    for (total_mb, want) in [
        (4010184i64 >> 10, (4010184i64 >> 10) - 640),
        (8 << 10, (8 << 10) - 640),
        (1024, 512),
    ] {
        assert_eq!(
            session_limit(total_mb << 10) >> 20,
            want,
            "session_limit({total_mb} MB)"
        );
    }
    assert_eq!(rescue_limit(3916 << 10) >> 20, 384);
    assert_eq!(rescue_limit(1024 << 10) >> 20, 256, "a quarter");
}
