//! router/awslogs_test.go
use crate::awslogs::{
    AWS_LOGS, AwsLogLine, AwsLogQueue, MACHINE_OUT_LINES, aws_log_labels, clean_console,
    console_new, console_off_until, console_reset, loki_push, push_once,
};
use crate::awsread::{AWS_READ_ENDPOINT, AWS_READ_KEY};
use crate::awsrunner::{Instance, aws_seen_set};
use crate::router::Router;
use crate::testutil::*;
use base64::Engine;
use jarvis_go::GoTime;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

/// Loki's push API as the shipper serves it; every stream it was sent
#[derive(Default)]
struct ShipperState {
    streams: Vec<Value>,
    fail: bool,
}

/// the fake shipper as the queue's (a fresh queue), put back when dropped; the caller holds serial()
struct FakeShipper {
    st: Arc<Mutex<ShipperState>>,
    _srv: TestServer,
}

impl Drop for FakeShipper {
    fn drop(&mut self) {
        *AWS_LOGS.lock().unwrap_or_else(|e| e.into_inner()) = AwsLogQueue::default();
    }
}

impl FakeShipper {
    fn set_fail(&self, f: bool) {
        self.st.lock().unwrap_or_else(|e| e.into_inner()).fail = f;
    }

    /// every line of the streams with these labels, in order
    fn lines(&self, labels: &[(&str, &str)]) -> Vec<String> {
        let g = self.st.lock().unwrap_or_else(|e| e.into_inner());
        g.streams
            .iter()
            .filter(|s| labels.iter().all(|(k, v)| s["stream"][k] == *v))
            .flat_map(|s| {
                s["values"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .map(|v| v[1].as_str().unwrap_or_default().to_string())
            })
            .collect()
    }

    fn streams(&self) -> Vec<Value> {
        self.st
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .streams
            .clone()
    }
}

fn use_fake_shipper() -> FakeShipper {
    let st: Arc<Mutex<ShipperState>> = Arc::default();
    let s2 = st.clone();
    let srv = TestServer::handler(move |w, req| {
        let b = req.read_body(16 << 20);
        let mut f = s2.lock().unwrap_or_else(|e| e.into_inner());
        if req.path != "/loki/api/v1/push" || f.fail {
            w.write_header(503);
            return;
        }
        let input: Value = serde_json::from_slice(&b).unwrap_or_default();
        f.streams
            .extend(input["streams"].as_array().cloned().unwrap_or_default());
        w.write_header(204);
    });
    *AWS_LOGS.lock().unwrap_or_else(|e| e.into_inner()) = AwsLogQueue {
        url: Some(format!("{}/loki/api/v1/push", srv.url)),
        ..Default::default()
    };
    FakeShipper { st, _srv: srv }
}

fn seen(id: &str, state: &str) {
    aws_seen_set(
        id,
        Some(Instance {
            id: id.into(),
            region: "eu-west-2".into(),
            state: state.into(),
            ..Default::default()
        }),
    );
}

struct Unseen(Vec<&'static str>);

impl Drop for Unseen {
    fn drop(&mut self) {
        for id in &self.0 {
            aws_seen_set(id, None);
        }
    }
}

fn push(r: &Arc<Router>, m: &TestMachine, source: &str, lines: &[&str]) -> u16 {
    let ls: Vec<Value> = lines
        .iter()
        .map(|l| json!({"at": GoTime::now().utc().rfc3339_nano(), "text": l}))
        .collect();
    m.do_(
        &r.machine_handler(),
        "POST",
        "/m/machine-output",
        &jarvis_go::marshal(&json!({"source": source, "lines": ls})),
    )
    .0
}

/// an AWS machine's output: signed by the machine, labelled by the router with its instance, region, session and
/// source, kept while the shipper refuses and sent once it takes them; a Fly machine's is Fly's
#[test]
fn machine_output_to_the_shipper() {
    let _g = serial();
    let sh = use_fake_shipper();
    let t = new_test_router();
    let r = t.r.clone();
    add_session(&r, "sA", "started", "i-0abc", false);
    seen("i-0abc", "started");
    let _unseen = Unseen(vec!["i-0abc"]);
    let m = new_test_machine(&r, "i-0abc");
    sh.set_fail(true);
    assert_eq!(
        push(&r, &m, "machine", &["[jarvis] keeper up", "second"]),
        200
    );
    assert_eq!(
        push(
            &r,
            &m,
            "journal",
            &["systemd: Started jarvis4-session.service"]
        ),
        200
    );
    assert!(push_once().is_err(), "a refused push counted as sent");
    sh.set_fail(false);
    push_once().unwrap_or_else(|e| panic!("{e:#}"));
    let want = [
        ("instance", "i-0abc"),
        ("aws_region", "eu-west-2"),
        ("session", "sA"),
        ("source", "machine"),
    ];
    assert_eq!(
        sh.lines(&want).join("|"),
        "[jarvis] keeper up|second",
        "{:?}",
        sh.streams()
    );
    let want = [
        ("instance", "i-0abc"),
        ("aws_region", "eu-west-2"),
        ("session", "sA"),
        ("source", "journal"),
    ];
    assert_eq!(sh.lines(&want).len(), 1, "{:?}", sh.streams());
    assert_eq!(push(&r, &m, "other", &[]), 400, "an unknown source");
    let fly = new_test_machine(&r, "mFly");
    assert_eq!(
        push(&r, &fly, "machine", &["x"]),
        404,
        "a Fly machine's output"
    );
    let too = vec![""; MACHINE_OUT_LINES + 1];
    assert_eq!(push(&r, &m, "machine", &too), 400, "too many lines");
}

/// the console's window: what follows the last shipped line, also when the 64 KB window slid on; an unfinished line
/// waits; terminal escapes and carriage returns go
#[test]
fn console_news() {
    let (lines, prev) = console_new(
        "",
        "\x1b[2J\x1b[01;01HGRUB\r\n[    0.000000] Linux version 6.12\npartial",
    );
    assert!(
        lines.join("|") == "GRUB|[    0.000000] Linux version 6.12"
            && prev == "\x1b[2J\x1b[01;01HGRUB\r\n[    0.000000] Linux version 6.12\n",
        "{lines:?} {prev:?}"
    );
    let out = format!("{prev}partial line done\nlogin: ");
    let (lines, prev) = console_new(&prev, &out);
    assert_eq!(lines.join("|"), "partial line done");
    let (lines, _) = console_new(&prev, &out);
    assert!(lines.is_empty(), "again: {lines:?}");
    // the window slides: the start is gone, the anchor (prev's end) is found
    let all: String = (0..4000)
        .map(|i| format!("[ {:8.3}] line {i}\n", f64::from(i) / 100.0))
        .collect();
    let (_, prev) = console_new("", &all[..40000]);
    let cut = prev[..prev.len() - 1].rfind('\n').map_or(0, |i| i + 1);
    let prev = &prev[..cut];
    let (lines, _) = console_new(prev, &all[all.len() - 65535..]);
    let first = prev.matches('\n').count();
    assert!(
        lines.len() == 4000 - first && lines[0].ends_with(&format!("line {first}")),
        "{} lines from {:?} (want {} from line {first})",
        lines.len(),
        lines.first(),
        4000 - first
    );
    // nothing in common: all of it
    let (lines, _) = console_new("something else entirely\n", "a\nb\n");
    assert_eq!(lines.join("|"), "a|b");
    assert_eq!(
        clean_console("\x1bP+q6E616D65\x1b\\\x1b[?7h\x1b[1G\x1b[0J\x1b[6n ip-10-40-0-146 login: x"),
        "ip-10-40-0-146 login: x"
    );
}

#[derive(Default)]
struct Ec2State {
    console: String,
    refuse: bool,
}

static EC2: Mutex<Option<(String, Arc<Mutex<Ec2State>>)>> = Mutex::new(None);

fn fake_endpoint(_: &str) -> String {
    EC2.lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .map(|(u, _)| format!("{u}/"))
        .unwrap_or_default()
}

struct Ec2Restore;

impl Drop for Ec2Restore {
    fn drop(&mut self) {
        *AWS_READ_ENDPOINT.lock().unwrap_or_else(|e| e.into_inner()) = None;
        *AWS_READ_KEY.write().unwrap_or_else(|e| e.into_inner()) = None;
        *EC2.lock().unwrap_or_else(|e| e.into_inner()) = None;
        console_reset();
    }
}

/// the leader's console read: each live instance's new lines to the shipper as source "console", once; an OOM kill
/// also into the session's running operation; a read key without GetConsoleOutput stops it for a while
#[test]
fn console_tick() {
    let _g = serial();
    let sh = use_fake_shipper();
    let t = new_test_router();
    let r = t.r.clone();
    let st = Arc::new(Mutex::new(Ec2State {
        console: "[    1.0] Linux version 6.12\nJARVIS2-KEYS {\"sign\":\"…\"}\n".into(),
        ..Default::default()
    }));
    let s2 = st.clone();
    let ec2 = TestServer::handler(move |w, req| {
        let b = String::from_utf8_lossy(&req.read_body(1 << 20)).into_owned();
        let g = s2.lock().unwrap_or_else(|e| e.into_inner());
        if !b.contains("Action=GetConsoleOutput")
            || !b.contains("InstanceId=i-0abc")
            || !req
                .header("Authorization")
                .starts_with("AWS4-HMAC-SHA256 Credential=AKIATEST/")
        {
            w.write_header(400);
            return;
        }
        if g.refuse {
            w.write_header(403);
            w.write_str("<Response><Errors><Error><Code>UnauthorizedOperation</Code><Message>no</Message></Error></Errors></Response>");
            return;
        }
        let out = base64::engine::general_purpose::STANDARD.encode(g.console.as_bytes());
        w.write_str(&format!(
            "<GetConsoleOutputResponse><output>{out}</output></GetConsoleOutputResponse>"
        ));
    });
    let _restore = Ec2Restore;
    *EC2.lock().unwrap_or_else(|e| e.into_inner()) = Some((ec2.url.clone(), st.clone()));
    *AWS_READ_ENDPOINT.lock().unwrap_or_else(|e| e.into_inner()) = Some(fake_endpoint);
    *AWS_READ_KEY.write().unwrap_or_else(|e| e.into_inner()) =
        Some(("AKIATEST".into(), "secret".into()));
    console_reset();
    add_session(&r, "sA", "started", "i-0abc", false);
    seen("i-0abc", "started");
    seen("i-0old", "destroyed");
    let _unseen = Unseen(vec!["i-0abc", "i-0old"]);
    let h = r.lc_begin("sA", "boot");
    h.machine("i-0abc");
    r.console_tick();
    st.lock()
        .unwrap_or_else(|e| e.into_inner())
        .console
        .push_str("[   61.2] Out of memory: Killed process 4242 (node)\n");
    r.console_tick();
    r.console_tick();
    push_once().unwrap_or_else(|e| panic!("{e:#}"));
    let got = sh.lines(&[
        ("instance", "i-0abc"),
        ("source", "console"),
        ("session", "sA"),
        ("aws_region", "eu-west-2"),
    ]);
    assert_eq!(
        got.join("|"),
        r#"[    1.0] Linux version 6.12|JARVIS2-KEYS {"sign":"…"}|[   61.2] Out of memory: Killed process 4242 (node)"#
    );
    let (_, entries) = r.lc_read("sA");
    let aws: Vec<String> = entries
        .get(&h.op_id())
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|e| e.source == "aws")
        .map(|e| e.text)
        .collect();
    assert_eq!(
        aws.join("|"),
        "AWS console: [   61.2] Out of memory: Killed process 4242 (node)"
    );
    st.lock().unwrap_or_else(|e| e.into_inner()).refuse = true;
    r.console_tick();
    assert!(
        console_off_until().is_some_and(|t| GoTime::now().before(&t)),
        "a refused GetConsoleOutput didn't stop the reads"
    );
}

/// the push body: one stream per label set, its values in time order, as Loki takes them
#[test]
fn loki_pushes() {
    let t0: i128 = 1_700_000_000 * 1_000_000_000;
    let (a, b) = (
        aws_log_labels("i-1", "eu-west-2", "s1", "machine"),
        aws_log_labels("i-1", "eu-west-2", "s1", "console"),
    );
    let line = |l: &str, at: i128, text: &str| AwsLogLine {
        labels: l.into(),
        at_nanos: at,
        text: text.into(),
    };
    let body = loki_push(&[
        line(&a, t0 + 2, "two"),
        line(&b, t0, "console"),
        line(&a, t0 + 1, "one"),
    ])
    .unwrap_or_else(|e| panic!("{e:#}"));
    assert_eq!(
        body,
        r#"{"streams":[{"stream":{"aws_region":"eu-west-2","instance":"i-1","session":"s1","source":"machine"},"values":[["1700000000000000001","one"],["1700000000000000002","two"]]},{"stream":{"aws_region":"eu-west-2","instance":"i-1","session":"s1","source":"console"},"values":[["1700000000000000000","console"]]}]}"#
    );
}
