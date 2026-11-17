//! workers_test.go, rollback_test.go (with the attachments' test), harnesslog_test.go, downgradeargs_test.go.

use super::testutil::*;
use super::vouch::attest_for;
use crate::attachments::*;
use crate::crypto::{SignedDoc, sha256_hex};
use crate::downgrade::downgrade_args;
use crate::harnesslog::{HarnessLog, harness_stdout};
use crate::rollback::*;
use crate::vouch::AttachmentRef;
use crate::workers::*;
use std::collections::BTreeMap;
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// the event order Claude Code 2.1.300 sent for: a background Bash, a background subagent, a foreground subagent
#[test]
fn workers_hook_sequence() {
    let e = TestEnv::new();
    let state = e.root.join("workers.json");
    set_worker_count(&state);
    let now = crate::util::unix_now() * 1000;
    let ev = |s: &str| {
        if let Some(x) = worker_event_of(s.as_bytes()) {
            apply(&x, now);
        }
    };
    let want = |step: &str, sub: i64, jobs: &[(&str, i64)]| {
        let f = get("s1").unwrap_or_else(|| panic!("{step}: no count"));
        let want: BTreeMap<String, i64> = jobs.iter().map(|(k, v)| (k.to_string(), *v)).collect();
        assert_eq!((f.subagents, &f.jobs), (sub, &want), "{step}");
    };
    ev(r#"{"session_id":"s1","hook_event_name":"SessionStart","source":"startup"}"#);
    want("start", 0, &[]);
    ev(
        r#"{"session_id":"s1","hook_event_name":"SubagentStart","agent_id":"abg","agent_type":"general-purpose"}"#,
    );
    want("bg agent started", 1, &[]);
    ev(
        r#"{"session_id":"s1","hook_event_name":"PostToolUse","tool_name":"Agent","tool_response":{"isAsync":true,"status":"async_launched","agentId":"abg"}}"#,
    );
    ev(
        r#"{"session_id":"s1","hook_event_name":"PostToolUse","tool_name":"Bash","tool_response":{"stdout":"","backgroundTaskId":"b1"}}"#,
    );
    want("bash", 1, &[("shell", 1)]);
    ev(
        r#"{"session_id":"s1","hook_event_name":"PostToolUse","tool_name":"Bash","tool_response":{"stdout":"x"}}"#,
    );
    ev(
        r#"{"session_id":"s1","hook_event_name":"SubagentStart","agent_id":"afg","agent_type":"Explore"}"#,
    );
    ev(
        r#"{"session_id":"s1","hook_event_name":"SubagentStart","agent_id":"internal","agent_type":""}"#,
    );
    want("fg agent", 2, &[("shell", 1)]);
    ev(
        r#"{"session_id":"s1","hook_event_name":"SubagentStop","agent_id":"afg","agent_type":"Explore","background_tasks":[{"id":"abg","type":"subagent","status":"running"},{"id":"b1","type":"shell","status":"running"}]}"#,
    );
    want("fg stopped", 1, &[("shell", 1)]);
    ev(
        r#"{"session_id":"s1","hook_event_name":"SubagentStart","agent_id":"afg2","agent_type":"Explore"}"#,
    );
    ev(
        r#"{"session_id":"s1","hook_event_name":"SubagentStop","agent_id":"abg","agent_type":"general-purpose","background_tasks":[{"id":"abg","type":"subagent","status":"running"},{"id":"m1","type":"monitor","status":"running"}]}"#,
    );
    want("bg stopped", 1, &[("monitor", 1)]);
    ev(
        r#"{"session_id":"s1","hook_event_name":"Stop","background_tasks":[{"id":"w1","type":"workflow","status":"running"},{"id":"x","type":"shell","status":"completed"}]}"#,
    );
    want("turn end", 0, &[("workflow", 1)]);
    ev(r#"{"session_id":"s1","hook_event_name":"Stop"}"#);
    want("no list", 0, &[("workflow", 1)]);
    ev(r#"{"session_id":"s1","hook_event_name":"SessionStart","source":"compact"}"#);
    want("compact", 0, &[("workflow", 1)]);
    ev(r#"{"session_id":"s1","hook_event_name":"SessionStart","source":"resume"}"#);
    want("restart", 0, &[]);
    ev(r#"{"session_id":"../x","hook_event_name":"Stop","background_tasks":[]}"#);
    assert!(get("../x").is_none(), "unsafe session id kept");
    ev("not json");
    // a restarted supervisor-normal starts from the kept count
    let r = report();
    set_worker_count(&state);
    let again = get("s1").expect("kept count");
    assert!(again.jobs.is_empty(), "{again:?}");
    assert!(
        r.contains(r#""workersOf":"s1""#) && r.matches('\n').count() == 1,
        "report {r:?}"
    );
}

/// the hook only notifies: its event reaches the supervisor's count over the socket, and with no supervisor listening
/// it still exits quietly
#[test]
fn workers_hook_notifies_the_supervisor() {
    let _e = TestEnv::new();
    set_worker_count(&crate::paths::dir().join("none.json"));
    notify(br#"{"session_id":"s1","hook_event_name":"SubagentStart","agent_id":"a1","agent_type":"Explore"}"#); // nobody listens
    std::thread::spawn(serve_worker_count);
    for _ in 0..100 {
        if crate::paths::workers_sock().exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    notify(br#"{"session_id":"s1","hook_event_name":"SubagentStart","agent_id":"a1","agent_type":"Explore","prompt":"secret text"}"#);
    for _ in 0..100 {
        if get("s1").is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(get("s1").map(|f| f.subagents), Some(1));
    let e = worker_event_of(br#"{"session_id":"s1","hook_event_name":"PostToolUse","tool_name":"Bash","tool_input":{"command":"echo hunter2"},"tool_response":{"stdout":"hunter2","backgroundTaskId":"b1"}}"#).unwrap();
    assert!(
        !crate::gojson::marshal(&e).contains("hunter2"),
        "the notification carries a command or its output"
    );
    // the server thread goes on; the next test's directory has no socket
    let _ = std::fs::remove_file(crate::paths::workers_sock());
}

#[test]
fn install_worker_hooks_keeps_the_rest() {
    let e = TestEnv::new();
    let p = e.home.join(".claude/settings.json");
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(&p, r#"{"remoteControlAtStartup":true,"hooks":{"Stop":[{"hooks":[{"type":"command","command":"mine"}]}]}}"#).unwrap();
    for _ in 0..2 {
        install_worker_hooks(&e.home).unwrap(); // idempotent
    }
    let s: serde_json::Value = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
    assert_eq!(s["remoteControlAtStartup"], true);
    assert_eq!(s["hooks"]["Stop"].as_array().unwrap().len(), 2);
    assert_eq!(s["hooks"]["SubagentStart"].as_array().unwrap().len(), 1);
    assert_eq!(
        s["hooks"]["PostToolUse"][0]["matcher"],
        "Bash|Monitor|Agent"
    );
    std::fs::write(&p, "{broken").unwrap();
    assert!(
        install_worker_hooks(&e.home).is_err(),
        "overwrote an unreadable settings file"
    );
}

#[test]
fn truncate_at_marker_rule() {
    let body = b"a\nb\nc MARK here\nd\n";
    assert_eq!(
        truncate_at_marker(body, "MARK"),
        (b"a\nb\n".to_vec(), 4, 2, true)
    );
    let (kept, before, after, cut) = truncate_at_marker(body, "nowhere");
    assert!(!cut && kept == body && before == after);
    let (kept, _, after, _) = truncate_at_marker(b"MARK first\nx\n", "MARK");
    assert!(kept.is_empty() && after == 0);
}

#[test]
fn apply_rollback_only_with_a_marker() {
    let e = TestEnv::new();
    let proj = e.home.join(".claude/projects/-home-claude-workspace");
    std::fs::create_dir_all(proj.join("conv/subagents")).unwrap();
    let conv = proj.join("conv.jsonl");
    let sub = proj.join("conv/subagents/agent.jsonl");
    let other = proj.join("other.jsonl");
    let write = || {
        std::fs::write(
            &conv,
            "{\"n\":1}\n{\"n\":2,\"text\":\"bad turn XYZZY\"}\n{\"n\":3}\n",
        )
        .unwrap();
        std::fs::write(&sub, "{\"text\":\"XYZZY\"}\n").unwrap();
        std::fs::write(&other, "{\"n\":1}\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&conv, std::fs::Permissions::from_mode(0o600)).unwrap();
    };
    write();
    // the env asks for one: nothing happens (only the cert's one-time inputs do)
    crate::env::set("JARVIS2_ROLLBACK", Some("XYZZY"));
    apply_rollback("");
    assert!(
        std::fs::read_to_string(&conv).unwrap().contains("XYZZY"),
        "a rollback from the env was applied"
    );
    apply_rollback("XYZZY");
    assert_eq!(std::fs::read_to_string(&conv).unwrap(), "{\"n\":1}\n");
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(&conv).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(
        std::fs::read_to_string(&sub).unwrap().contains("XYZZY"),
        "a subagent transcript was touched"
    );
    assert_eq!(std::fs::read_to_string(&other).unwrap(), "{\"n\":1}\n");
    write();
    apply_rollback("");
    assert!(
        std::fs::read_to_string(&conv).unwrap().contains("XYZZY"),
        "rolled back without a marker"
    );
    assert!(
        rollback_transcripts(&e.home, "ab").1.is_some(),
        "a 2-character marker was accepted"
    );
}

#[test]
fn fetch_attachments_checks_each_file() {
    let e = TestEnv::new();
    let key = e.machine_key();
    let core = new_key();
    let files: BTreeMap<&str, &str> = [("photo 1.png", "PNG"), ("notes%.txt", "text")].into();
    let attest: Arc<Mutex<BTreeMap<String, Option<SignedDoc>>>> = Arc::new(Mutex::new(
        files
            .iter()
            .map(|(n, b)| {
                (
                    n.to_string(),
                    Some(attest_for(&core, "m1", "attachment", b.as_bytes())),
                )
            })
            .collect(),
    ));
    let state = Arc::new(Mutex::new((false, 0)));
    let (a2, s2, f2) = (attest.clone(), state.clone(), files.clone());
    let f2: BTreeMap<String, String> = f2.into_iter().map(|(k, v)| (k.into(), v.into())).collect();
    let srv = FakeRouter::new(&key.sig.public_key(), move |r| {
        let mut s = s2.lock().unwrap();
        if r.method == "GET" && r.path == "/m/attachments" {
            s.1 += 1;
            let att: BTreeMap<String, serde_json::Value> = a2
                .lock()
                .unwrap()
                .iter()
                .map(|(k, v)| (k.clone(), serde_json::to_value(v).unwrap()))
                .collect();
            return ok_json(
                serde_json::json!({"files": [{"name": "photo 1.png", "isImage": true}, {"name": "notes%.txt"}], "attest": att}),
            );
        }
        if r.method == "GET"
            && let Some(n) = r.path.strip_prefix("/m/attachments/")
        {
            return match f2.get(n) {
                Some(b) => ans(200, b.as_bytes().to_vec()),
                None => ans(404, ""),
            };
        }
        if r.method == "DELETE" && r.path == "/m/attachments" {
            s.0 = true;
            return ans(200, r#"{"ok":true}"#);
        }
        ans(404, "")
    });
    let c = srv.client();
    let refs: Vec<AttachmentRef> = files
        .iter()
        .map(|(n, b)| AttachmentRef {
            name: n.to_string(),
            sha256: sha256_hex(b.as_bytes()),
            size: b.len() as i64,
        })
        .collect();
    let staging = e.home.join(ATTACH_STAGING);
    let refused = |why: &str, r: &[AttachmentRef], bad: &str| {
        let env = fetch_attachments(&c, &core.public(), r).join("\n");
        assert!(
            env.contains("SESSION_ATTACHMENTS_REFUSED=") && env.contains(bad),
            "{why}: the refused file isn't named: {env}"
        );
        assert!(
            !staging.join(bad).exists(),
            "{why}: a refused attachment was left on disk"
        );
        assert!(
            !state.lock().unwrap().0,
            "{why}: the router's copy was dropped for a refused set"
        );
        for f in r {
            if f.name != bad {
                assert!(
                    env.contains(&format!(r#"{{"name":{}"#, crate::gojson::marshal(&f.name))),
                    "{why}: the verified {} was dropped too: {env}",
                    f.name
                );
            }
        }
        let _ = std::fs::remove_dir_all(&staging);
    };
    // the router swapped a file: its bytes aren't the ones the cert names
    let mut bad = refs.clone();
    bad[0].sha256 = sha256_hex(b"other bytes");
    refused("a swapped file", &bad, &bad[0].name.clone());
    let mut bad = refs.clone();
    bad[1].size += 1;
    refused("another size", &bad, &bad[1].name.clone());
    // no attestation, an attestation for another machine, kind, input, or not by the core: not in the input log
    let saved = attest.lock().unwrap()["notes%.txt"].clone();
    for a in [
        None,
        Some(attest_for(&core, "m2", "attachment", b"text")),
        Some(attest_for(&core, "m1", "wakeup", b"text")),
        Some(attest_for(&core, "m1", "attachment", b"PNG")),
        Some(attest_for(&new_key(), "m1", "attachment", b"text")),
    ] {
        attest.lock().unwrap().insert("notes%.txt".into(), a);
        refused(
            "an attachment without the core's attestation",
            &refs,
            "notes%.txt",
        );
    }
    attest.lock().unwrap().insert("notes%.txt".into(), saved);
    let env = fetch_attachments(&c, &core.public(), &refs);
    for (n, want) in &files {
        assert_eq!(
            std::fs::read_to_string(staging.join(n)).unwrap(),
            *want,
            "{n}"
        );
    }
    let (deleted, listed) = *state.lock().unwrap();
    assert!(
        deleted && listed > 0,
        "the router's copy wasn't dropped ({deleted}) or the listing wasn't read ({listed})"
    );
    let joined = env.join("\n");
    assert!(
        joined.contains(&format!(
            "SESSION_ATTACH_DAV_BASE=file://{}\n",
            e.home.display()
        )) && joined.contains(&format!("SESSION_ATTACH_DIR={ATTACH_STAGING}"))
            && joined.contains(r#"{"name":"photo 1.png","isImage":true}"#),
        "env {env:?}"
    );
    for bad in ["", ".", "..", "a/b", r"a\b"] {
        assert!(!plain_name(bad), "{bad:?} passed");
    }
}

#[derive(Clone, Default)]
struct Buf(Arc<Mutex<Vec<u8>>>);

impl Write for Buf {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Buf {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
    fn reset(&self) {
        self.0.lock().unwrap().clear();
    }
}

/// only the launcher's tagged lines reach the supervisor log, clipped and rate limited; the rest stays on the console
#[test]
fn harness_log_keeps_only_tagged_lines() {
    let b = Buf::default();
    let h = HarnessLog::new(Box::new(b.clone()));
    h.line("[dsh] dsh web exited (code 1) after 3 s; restarting");
    h.line("some program's own output, maybe a prompt");
    h.line("[Weird] not a tag");
    h.line(&format!("[entrypoint] {}", "x".repeat(3000)));
    let t = b.text();
    let got: Vec<&str> = t.trim().split('\n').collect();
    assert_eq!(got.len(), 2, "{got:?}");
    assert_eq!(
        got[0],
        "[dsh] dsh web exited (code 1) after 3 s; restarting"
    );
    assert_eq!(got[1].len(), crate::supervisorlog::MAX_LOG_LINE);
    b.reset();
    for _ in 0..200 {
        h.line("[dsh] flood");
    }
    assert!(b.text().matches('\n').count() <= 60, "lines past the burst");
    h.backdate(Duration::from_secs(60));
    b.reset();
    h.line("[dsh] after");
    let t = b.text();
    assert!(
        t.contains("harness lines left out") && t.ends_with("[dsh] after\n"),
        "{t:?}"
    );
}

/// the pipe: a child's lines arrive, and the reader ends once the last holder of the write end is gone
#[test]
fn harness_stdout_pipe() {
    let b = Buf::default();
    let h = Arc::new(HarnessLog::new(Box::new(b.clone())));
    let mut w = harness_stdout(h).unwrap();
    w.write_all(b"[dsh] up\nnoise\n").unwrap();
    drop(w);
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while b.text() != "[dsh] up\n" {
        assert!(std::time::Instant::now() < deadline, "{:?}", b.text());
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn downgrade_needs_a_mode() {
    let s = |a: &[&str]| a.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    for bad in [
        s(&[]),
        s(&["default"]),
        s(&["default", "tunnel"]),
        s(&["--all"]),
        s(&["--keep"]),
        s(&["--drop"]),
        s(&["--none", "default"]),
        s(&["--keep", "a", "--drop", "b"]),
    ] {
        assert!(downgrade_args(&bad).is_err(), "{bad:?} must be refused");
    }
    let held = s(&["default", "github-claude-env", "infra", "tunnel"]);
    let keep = |a: &[&str]| downgrade_args(&s(a)).unwrap().keep_for(&held);
    assert_eq!(
        keep(&["--keep", "default", "tunnel"]).unwrap().join(" "),
        "default tunnel"
    );
    assert_eq!(
        keep(&["--drop", "infra"]).unwrap().join(" "),
        "default github-claude-env tunnel"
    );
    assert!(keep(&["--none"]).unwrap().is_empty());
    assert_eq!(
        keep(&["--drop", "identity", "infra"]).unwrap().join(" "),
        "default github-claude-env tunnel"
    );
    let e = keep(&["--drop", "identity", "gmail"]).unwrap_err();
    assert!(
        e.downcast_ref::<crate::downgrade::NothingToDrop>()
            .is_some(),
        "--drop of only unheld stores: {e:#}"
    );
    assert!(
        keep(&["--keep", "default", "gmail"]).is_err(),
        "keeping a store not held must be refused"
    );
    assert!(
        keep(&["--drop", "default", "github-claude-env", "infra", "tunnel"]).is_err(),
        "--drop of every held store must be refused"
    );
}
