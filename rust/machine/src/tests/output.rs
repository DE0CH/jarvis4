//! output_test.go, snapprogress_test.go, harnesses_test.go (the kinds) and livemode_test.go.

use super::testutil::*;
use crate::cert::Cert;
use crate::deliver::{MODE_FILE, live_mode};
use crate::harnesses::*;
use crate::output::*;
use crate::snapshot::*;
use crate::supervisorlog::LogLine;
use std::collections::BTreeMap;
use std::io::Write;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

/// the tee: every line of the pipe goes on to the original output unchanged and into the file, a long one in pieces
#[test]
fn tee_lines_pass_through() {
    let _e = TestEnv::new();
    let (r, mut w) = std::io::pipe().unwrap();
    let out = Arc::new(Mutex::new(Vec::<u8>::new()));
    let o2 = out.clone();
    let t = std::thread::spawn(move || tee_lines(r, &o2, &OUTPUT_SHIP));
    let long = "x".repeat(20 << 10);
    let input = format!("[jarvis] keeper up\r\nsecond\n\n{long}\nlast without newline");
    w.write_all(input.as_bytes()).unwrap();
    drop(w);
    t.join().unwrap();
    assert_eq!(String::from_utf8_lossy(&out.lock().unwrap()), input, "the original output changed");
    let b = std::fs::read_to_string(crate::paths::output_log_path()).unwrap();
    let got: Vec<String> = b
        .trim()
        .split('\n')
        .map(|l| crate::gojson::unmarshal::<LogLine>(l.as_bytes()).unwrap().text)
        .collect();
    assert_eq!(got.len(), 5, "{} lines", got.len());
    assert_eq!((got[0].as_str(), got[1].as_str(), got[2].len(), got[4].as_str()), ("[jarvis] keeper up", "second", 16 << 10, "last without newline"));
}

/// the push: both files to /m/machine-output with their source, each line once, the held values replaced; a file past
/// its cap takes no more lines and says how many it missed
#[test]
fn output_push() {
    let e = TestEnv::new();
    let key = e.machine_key();
    crate::env::set("JARVIS2_RUNNER", Some("aws"));
    crate::secrets::HELD.set_for_test([("A".to_string(), "hunter2hunter2".to_string())].into());
    let got: Arc<Mutex<BTreeMap<String, Vec<String>>>> = Arc::new(Mutex::new(BTreeMap::new()));
    let g2 = got.clone();
    let srv = FakeRouter::new(&key.sig.public_key(), move |r| {
        if r.path != "/m/machine-output" {
            return ans(404, "");
        }
        let v: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
        let src = v["source"].as_str().unwrap_or("").to_string();
        for l in v["lines"].as_array().into_iter().flatten() {
            g2.lock().unwrap().entry(src.clone()).or_default().push(l["text"].as_str().unwrap_or("").into());
        }
        ans(200, r#"{"ok":true}"#)
    });
    let c = srv.client();
    OUTPUT_SHIP.add(SystemTime::now(), "panic: token hunter2hunter2");
    JOURNAL_SHIP.add(SystemTime::now(), "jarvis4-session.service docker: Pulling fs layer");
    push_outputs_once(&c);
    push_outputs_once(&c);
    {
        let g = got.lock().unwrap();
        assert_eq!(g.get("machine").map(|v| v.join("|")).unwrap_or_default(), "panic: token [secret]");
        assert_eq!(g.get("journal").map(|v| v.join("|")).unwrap_or_default(), "jarvis4-session.service docker: Pulling fs layer");
    }
    SHIP_FILE_CAP.store(10, Ordering::SeqCst);
    OUTPUT_SHIP.add(SystemTime::now(), "taken: everything before it was pushed");
    OUTPUT_SHIP.add(SystemTime::now(), "past the cap: counted");
    OUTPUT_SHIP.add(SystemTime::now(), "and another");
    SHIP_FILE_CAP.store(32 << 20, Ordering::SeqCst);
    OUTPUT_SHIP.add(SystemTime::now(), "room again");
    push_outputs_once(&c);
    let m = got.lock().unwrap()["machine"].clone();
    assert!(
        m.len() == 4 && m[1] == "taken: everything before it was pushed" && m[2].contains("2 machine lines not sent") && m[3] == "room again",
        "{m:?}"
    );
}

/// the journal's entries as lines: the kernel's left out, the session unit's docker client from the keeper's start on
/// left out, a non-UTF-8 message kept
#[test]
fn journal_lines() {
    let since = SystemTime::UNIX_EPOCH + Duration::from_secs(1_793_793_600);
    let us = |t: SystemTime| t.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_micros().to_string();
    let (before, after) = (us(since - Duration::from_secs(60)), us(since + Duration::from_secs(1)));
    let entry = |rt: &str, msg: &str, unit: &str, ident: &str, comm: &str, transport: &str| JournalEntry {
        realtime: rt.into(),
        message: Some(serde_json::value::RawValue::from_string(msg.into()).unwrap()),
        unit: unit.into(),
        ident: ident.into(),
        comm: comm.into(),
        transport: transport.into(),
        cursor: String::new(),
    };
    let cases = [
        (entry(&before, r#""Pulling fs layer""#, "jarvis4-session.service", "docker", "docker", ""), "jarvis4-session.service docker: Pulling fs layer"),
        (entry(&after, r#""[jarvis] keeper up""#, "jarvis4-session.service", "docker", "docker", ""), ""),
        (entry(&after, r#""Out of memory: Killed process 7""#, "", "", "", "kernel"), ""),
        (entry(&after, r#""Started jarvis4-session.service""#, "init.scope", "systemd", "", ""), "systemd: Started jarvis4-session.service"),
        (entry(&after, "[104,105,255]", "", "x", "", ""), "x: hi\u{fffd}"),
    ];
    for (i, (e, want)) in cases.iter().enumerate() {
        let (at, got) = journal_line(e, since);
        assert_eq!(got, *want, "{i}");
        if e.realtime == after {
            assert_eq!(at, since + Duration::from_secs(1), "{i}");
        }
    }
}

/// the ROOT partition, found by its name in sysfs
#[test]
fn root_partition_by_name() {
    let d = tempdir();
    for (name, ev) in [
        ("nvme0n1", "DEVTYPE=disk\nDEVNAME=nvme0n1\n"),
        ("nvme0n1p6", "PARTNAME=OEM\nDEVNAME=nvme0n1p6\n"),
        ("nvme0n1p9", "MAJOR=259\nDEVNAME=nvme0n1p9\nDEVTYPE=partition\nPARTN=9\nPARTNAME=ROOT\n"),
    ] {
        std::fs::create_dir_all(d.join(name)).unwrap();
        std::fs::write(d.join(name).join("uevent"), ev).unwrap();
    }
    assert_eq!(root_partition_in(&d).unwrap(), "/dev/nvme0n1p9");
    let _ = std::fs::remove_dir_all(&d);
}

/// the snapshot is measured first, then counted as write_snapshot reads its files; the router gets the numbers
/// (throttled) and the log a line per period plus the last one
#[test]
fn snapshot_progress() {
    let e = TestEnv::new();
    std::fs::create_dir_all(e.home.join("workspace/repo")).unwrap();
    let mut big = vec![0u8; 3 << 20];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut big); // incompressible
    std::fs::write(e.home.join("workspace/repo/big.bin"), &big).unwrap();
    std::fs::write(e.home.join("workspace/small.txt"), "hello").unwrap();
    std::fs::create_dir_all(e.home.join(".paseo/models")).unwrap();
    std::fs::write(e.home.join(".paseo/models/skip.bin"), vec![0u8; 1 << 20]).unwrap(); // left out: not counted
    PROGRESS_POST_EVERY_MS.store(0, Ordering::SeqCst);
    PROGRESS_LOG_EVERY_MS.store(3_600_000, Ordering::SeqCst);
    let reports: Arc<Mutex<Vec<serde_json::Value>>> = Arc::new(Mutex::new(vec![]));
    let lines: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(vec![]));
    let (r2, l2) = (reports.clone(), lines.clone());
    let p = Progress::new(
        Box::new(move |m| {
            r2.lock().unwrap().push(m.clone());
            Ok(())
        }),
        Box::new(move |s| l2.lock().unwrap().push(s.into())),
    );
    let p = begin_progress(p);
    let want = (big.len() + 5) as i64;
    assert_eq!(p.total.load(Ordering::SeqCst), want);
    p.set_phase("uploading");
    let mut out = vec![];
    let (_, n) = write_snapshot(&mut out).unwrap();
    p.tick(true);
    p.end(None);
    assert!(p.done.load(Ordering::SeqCst) == want && p.sent.load(Ordering::SeqCst) == n as i64 && n > 0);
    assert!(current_progress().is_none(), "still counting after end");
    {
        let r = reports.lock().unwrap();
        assert!(r.len() >= 2 && r[0]["phase"] == "measuring" && r[r.len() - 1]["phase"] == "uploading" && r[r.len() - 1]["done"] == want, "{r:?}");
        let l = lines.lock().unwrap();
        assert!(l.last().unwrap().contains("snapshot: uploading done, 0.00 GB read"), "{l:?}");
        assert!(l.join("\n").contains("(100%)"), "no 100% line: {l:?}");
    }
    // a router without the route: reported once, then only logged; the snapshot isn't held up
    let calls = Arc::new(Mutex::new(0));
    let c2 = calls.clone();
    let l3 = lines.clone();
    let q = begin_progress(Progress::new(
        Box::new(move |_| {
            *c2.lock().unwrap() += 1;
            Err(anyhow::anyhow!("HTTP 404"))
        }),
        Box::new(move |s| l3.lock().unwrap().push(s.into())),
    ));
    q.set_phase("uploading");
    write_snapshot(std::io::sink()).unwrap();
    q.tick(true);
    q.end(None);
    assert_eq!(*calls.lock().unwrap(), 1, "reported more than once to a router without the route");
}

#[test]
fn harness_kinds() {
    for (h, want) in [
        ("", [false, true, false]),
        ("claude", [false, true, false]),
        ("opencode", [true, false, false]),
        ("openclaw", [true, false, false]),
        ("paseo-claude", [true, true, true]),
    ] {
        assert_eq!([via_harness_send(h), runs_claude_code(h), proxy_login(h)], want, "{h:?}");
    }
}

/// A session raised to bypass in place keeps a cert that says auto: Jarvis's own messages must go in the class claude
/// really runs in (2026-10-20). Decided as harness-claude.sh decides.
#[test]
fn live_mode_follows_the_in_place_switch() {
    let e = TestEnv::new();
    *crate::paths::TEST_CLAUDE_HOME.write().unwrap() = Some(e.root.clone());
    let auto = Cert::default();
    let mut bypass = Cert::default();
    bypass.options.permission_mode = "bypass".into();
    assert_eq!((live_mode(&auto).as_str(), live_mode(&bypass).as_str()), ("auto", "bypass"), "without the in-place file the cert decides");
    let p = e.root.join(MODE_FILE);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(&p, "bypass\n").unwrap();
    assert_eq!(live_mode(&auto), "bypass", "raised in place to bypass, sent as auto");
    std::fs::write(&p, "auto\n").unwrap();
    assert_eq!(live_mode(&bypass), "auto", "lowered in place to auto, sent as bypass");
    std::fs::write(&p, "nonsense").unwrap();
    assert_eq!(live_mode(&bypass), "auto", "harness-claude.sh runs anything but bypass as auto");
}
