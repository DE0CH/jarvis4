use super::*;

#[test]
fn a_filed_request_is_its_json_answer_before_the_wait() {
    let out = "{\"id\": \"q123\", \"ok\": true}\nWaiting for Deyao's decision in his Inbox (the Jarvis 4 app)…\n";
    let Filing::Filed(a) = filing(out) else {
        panic!("not filed: {out}")
    };
    assert_eq!(a.get("id").and_then(Value::as_str), Some("q123"));
}

#[test]
fn nothing_yet_is_pending() {
    assert_eq!(filing(""), Filing::Pending);
    assert_eq!(filing("attached x as y (3 bytes)\n"), Filing::Pending);
}

#[test]
fn a_refused_filing_ends_without_an_answer() {
    let out = "POST /api/requests/grant: HTTP 403: not this session's\nreplica-request-ended\n";
    assert_eq!(filing(out), Filing::Ended);
}

#[test]
fn an_answer_counts_even_after_the_request_ended() {
    // Deyao's decision came quickly: the JSON, the decision, then the end line
    let out = "{\"id\": \"b9\"}\nWaiting…\nallowed\nreplica-request-ended\n";
    assert!(matches!(filing(out), Filing::Filed(_)));
}

#[test]
fn a_batch_answer_has_a_b_id() {
    let Filing::Filed(a) = filing("{\"id\": \"b7f\", \"items\": []}") else {
        panic!()
    };
    assert!(is_batch(&a));
    let Filing::Filed(a) = filing("{\"id\": \"q7f\"}") else {
        panic!()
    };
    assert!(!is_batch(&a));
    let Filing::Filed(a) = filing("{\"ok\": true}") else {
        panic!()
    };
    assert!(!is_batch(&a));
}

#[test]
fn the_start_returns_at_once_and_marks_the_end() {
    let c = detached(
        "/usr/local/bin/jarvis-request grant status --minutes 5 --why x",
        "/tmp/r.out",
    );
    assert!(c.starts_with("sh -c \"setsid sh -c '/usr/local/bin/jarvis-request grant status"));
    assert!(c.contains("> /tmp/r.out 2>&1; echo replica-request-ended >> /tmp/r.out'"));
    assert!(c.ends_with("< /dev/null > /dev/null 2>&1 &\""));
    assert!(!c.contains('$'));
}

#[test]
fn the_start_runs_in_a_real_shell_and_does_not_wait() {
    // the inner command as the machine's sh sees it, with a stand-in request that answers, then waits
    let dir = std::env::temp_dir().join(format!("replica-setup-test-{}", random_hex(4)));
    fs::create_dir_all(&dir).expect("dir");
    let out = dir.join("r.out");
    let req = dir.join("req");
    fs::write(&req, "echo '{\"id\": \"q1\"}'\nsleep 3\n").expect("req");
    let line = detached(&format!("sh {}", req.display()), &out.display().to_string());
    let inner = line
        .strip_prefix("sh -c \"")
        .and_then(|s| s.strip_suffix('"'))
        .expect("sh -c \"…\"");
    let t = std::time::Instant::now();
    let st = Command::new("sh")
        .arg("-c")
        .arg(inner)
        .status()
        .expect("sh");
    assert!(st.success());
    assert!(
        t.elapsed() < Duration::from_secs(5),
        "the start waited for the request"
    );
    let mut got = Filing::Pending;
    for _ in 0..50 {
        got = filing(&fs::read_to_string(&out).unwrap_or_default());
        if got != Filing::Pending {
            break;
        }
        sleep(Duration::from_millis(100));
    }
    assert!(matches!(got, Filing::Filed(_)), "{got:?}");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn the_machine_is_the_sessions_second_column() {
    let s = "s1 - paused - A\ns2 8ed9e11b1d7098 started idle B\n";
    assert_eq!(machine_in(s, "s2").as_deref(), Some("8ed9e11b1d7098"));
    assert_eq!(machine_in(s, "s1"), None);
    assert_eq!(machine_in(s, "s3"), None);
}

#[test]
fn only_upload_copies_count() {
    let find = "/root/.jarvis-uploads/p.png\r\n/home/claude/uploads/p.png\n/home/claude/p.png\n/root/x/p.png.bak\n";
    assert_eq!(
        uploads_of(find, "p.png"),
        vec!["/root/.jarvis-uploads/p.png", "/home/claude/uploads/p.png"]
    );
}

#[test]
fn words_are_safe_on_a_command_line() {
    assert!(word("ci-photo_1.png"));
    assert!(!word(""));
    assert!(!word("a b"));
    assert!(!word("a;rm"));
    assert!(!word("$(x)"));
}

#[test]
fn tail_and_clock() {
    assert_eq!(tail("a\n\nb\nc\n", 2), "b c");
    assert_eq!(tail("a", 5), "a");
    assert_eq!(clock(86_400 + 3 * 3600 + 4 * 60 + 5), "03:04:05");
}
