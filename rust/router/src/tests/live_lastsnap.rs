//! livearchive and lastsnapshot tests

use crate::archive::ArchiveInfo;
use crate::archivetar::ARCHIVES_ROOT;
use crate::autopilot::Liveness;
use crate::livearchive::LiveCopy;
use crate::state::Session;
use crate::testutil::{Rig, capture_dm, wait_for};
use jarvis_go::GoTime;
use serde_json::Value;
use sha2::Digest;
use std::time::{Duration, Instant};

const LIVE_S1: &str = "claude-records/.live/s1";

/// a .live copy of s1 on the box, as the machine's live sync leaves it
fn put_live(rg: &Rig, name: &str, body: &str) {
    let b = rg.box_().unwrap_or_else(|| panic!("no box"));
    b.mkcols(LIVE_S1).unwrap_or_else(|e| panic!("{e:#}"));
    b.put_bytes(&format!("{LIVE_S1}/{name}"), body.as_bytes())
        .unwrap_or_else(|e| panic!("{e:#}"));
}

/// the rig's snapshot transcript, byte for byte
fn snapshot_body(rg: &Rig, name: &str) -> String {
    rg.files
        .iter()
        .find(|f| f.name.ends_with(&format!("/{name}")))
        .map(|f| f.body.clone())
        .unwrap_or_default()
}

fn s1_destroyed(rg: &Rig) -> bool {
    rg.st.do_(|d| !d.sessions.contains_key("s1"))
}

/// the incident (2026-10-15, sb8e0273d6c308894): the session went on under a new conversation after a failed
/// snapshot, so its original conversation was only in .live. Now every live copy the snapshot doesn't hold
/// byte-identical is copied in (and checked) first, and the destroy sends no resume DM.
#[test]
fn destroy_archives_every_live_transcript_first() {
    let rg = Rig::with(|c| c.snapshot_stall = Duration::from_millis(200));
    let dms = capture_dm(&rg);
    rg.running_m2(true); // its final snapshot never comes; Destroy anyway goes on (its volume is backed up)
    let orig = format!(
        "{}\n",
        r#"{"type":"user","message":{"content":"the original conversation"}}"#
    );
    let orig = orig.repeat(2000);
    put_live(&rg, "cccc.jsonl", &orig); // only here: the original conversation
    put_live(&rg, "bbbb.jsonl", &snapshot_body(&rg, "bbbb.jsonl")); // the snapshot holds it byte-identical
    put_live(&rg, "aaaa.jsonl", "an older version\n"); // the snapshot holds another version of it
    rg.destroy_with("s1", true)
        .unwrap_or_else(|e| panic!("{e:#}"));
    wait_for("the record", || s1_destroyed(&rg));
    let rec = rg.record("s1").unwrap_or_default();
    let a = rec
        .archive
        .clone()
        .unwrap_or_else(|| panic!("no archive: {rec:?}"));
    assert!(
        rec.archive_error.is_empty() && rec.live_kept.is_empty(),
        "record {rec:?}"
    );
    let (files, _) = rg.dav.archive(&a.file);
    assert_eq!(
        String::from_utf8_lossy(&files["transcript-cccc.jsonl"]),
        orig,
        "the original conversation isn't in the archive"
    );
    assert_eq!(
        String::from_utf8_lossy(&files["transcript-aaaa.live.jsonl"]),
        "an older version\n"
    );
    assert_eq!(
        String::from_utf8_lossy(&files["transcript-aaaa.jsonl"]),
        snapshot_body(&rg, "aaaa.jsonl"),
        "the snapshot's aaaa was replaced"
    );
    assert_eq!(a.live.len(), 3, "live {:?}", a.live);
    for c in &a.live {
        let want = match c.name.as_str() {
            "aaaa.jsonl" => "transcript-aaaa.live.jsonl",
            "bbbb.jsonl" => "snapshot",
            _ => "transcript-cccc.jsonl",
        };
        assert_eq!(c.in_, want, "live {:?}", a.live);
    }
    let c = &a.live[2];
    assert!(
        c.size == orig.len() as i64
            && c.sha256 == hex::encode(sha2::Sha256::digest(orig.as_bytes())),
        "cccc accounted as {c:?}"
    );
    assert_eq!(
        a.transcripts.join(","),
        "transcript-aaaa.live.jsonl,transcript-cccc.jsonl,transcript-aaaa.jsonl,transcript-bbbb.jsonl",
        "the snapshot's newest must stay last"
    );
    assert!(
        rg.dav.under(LIVE_S1).is_empty(),
        "the live copies stayed after a full archive"
    );
    // no resume-refusal DM from a destroy; the record says the last machine left no snapshot
    for dm in dms.lock().unwrap_or_else(|e| e.into_inner()).iter() {
        assert!(
            !dm.contains("won't resume") && !dm.contains("left no snapshot"),
            "a destroy DMed: {dm}"
        );
    }
    assert!(
        a.no_snapshot.contains("machine m2 left no snapshot"),
        "noSnapshot {}",
        a.no_snapshot
    );
    let meta: Value = serde_json::from_slice(&files["session.json"]).unwrap_or_default();
    assert!(
        meta["noSnapshot"]
            .as_str()
            .unwrap_or("")
            .contains("machine m2 left no snapshot")
            && !meta["live"].is_null(),
        "session.json {meta}"
    );
}

/// a copy that fails keeps the session (an archive failure) and every live copy; Destroy anyway goes on but still
/// deletes none of them, and the record says so
#[test]
fn a_live_copy_failure_keeps_every_live_file() {
    let rg = Rig::new();
    put_live(&rg, "cccc.jsonl", "the original\n");
    put_live(&rg, "bbbb.jsonl", &snapshot_body(&rg, "bbbb.jsonl"));
    rg.dav.set_fail(&format!("{ARCHIVES_ROOT}/2026"));
    let _ = rg.destroy("s1");
    wait_for("the error", || {
        let s = rg.session("s1");
        s.state == "paused" && s.error.starts_with("archive:")
    });
    rg.wait_state("s1", "paused", Duration::from_secs(5))
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert_eq!(
        rg.dav.under(LIVE_S1).len(),
        2,
        "live copies after a failed archive"
    );
    rg.destroy_with("s1", true)
        .unwrap_or_else(|e| panic!("{e:#}"));
    wait_for("the record", || s1_destroyed(&rg));
    let rec = rg.record("s1").unwrap_or_default();
    assert!(
        !rec.archive_error.is_empty()
            && rec.live_kept.contains("kept 2 live transcript(s)")
            && rec.live_kept.contains("the archive failed"),
        "record: archiveError {}, liveKept {}",
        rec.archive_error,
        rec.live_kept
    );
    assert!(
        rg.dav.get(&format!("{LIVE_S1}/cccc.jsonl")).as_deref() == Some(&b"the original\n"[..])
            && rg.dav.under(LIVE_S1).len() == 2,
        "a forced destroy deleted live copies"
    );
}

/// a session with no snapshot at all but live copies gets a record of them (nothing to restore), and they go only then
#[test]
fn no_snapshot_still_archives_the_live_copies() {
    let rg = Rig::new();
    rg.snap_drop("m1");
    put_live(&rg, "dddd.jsonl", "only here\n");
    rg.destroy("s1").unwrap_or_else(|e| panic!("{e:#}"));
    wait_for("the record", || s1_destroyed(&rg));
    let a = rg
        .record("s1")
        .and_then(|r| r.archive)
        .unwrap_or_else(|| panic!("no archive"));
    assert!(
        a.signer.is_empty() && a.live.len() == 1 && a.no_snapshot.contains("no signed snapshot"),
        "record {a:?}"
    );
    let (files, order) = rg.dav.archive(&a.file);
    assert!(
        files["transcript-dddd.jsonl"] == b"only here\n" && rg.dav.under(LIVE_S1).is_empty(),
        "archive {order:?}"
    );
    assert!(
        order
            .join(",")
            .starts_with("session.json,restore-s1.json,transcript-dddd.jsonl,jarvis2/")
            && !files.contains_key("jarvis2/snapshot.tar.gz"),
        "members {order:?}"
    );
    let meta: Value = serde_json::from_slice(&files["session.json"]).unwrap_or_default();
    assert!(
        meta.get("snapshot").is_none_or(Value::is_null)
            && meta["noSnapshot"]
                .as_str()
                .unwrap_or("")
                .contains("only its live transcript copies"),
        "session.json {meta}"
    );
    let idx: Vec<Value> = serde_json::from_slice(
        &rg.dav
            .get(&crate::archive::records_index())
            .unwrap_or_default(),
    )
    .unwrap_or_default();
    assert!(idx.len() == 1 && idx[0]["id"] == "s1", "index {idx:?}");
}

/// only what the archive accounted for goes: a copy that arrived or grew since stays, and so does the dir
#[test]
fn clear_deletes_only_archived_live_files() {
    let rg = Rig::new();
    put_live(&rg, "a.jsonl", "aa\n");
    put_live(&rg, "b.jsonl", "bb grown\n");
    put_live(&rg, "c.jsonl", "late\n");
    let lc = |n: &str, i: &str| LiveCopy {
        name: n.into(),
        size: 3,
        in_: i.into(),
        ..Default::default()
    };
    let info = ArchiveInfo {
        live: vec![
            lc("a.jsonl", "transcript-a.jsonl"),
            lc("b.jsonl", "transcript-b.jsonl"),
        ],
        ..Default::default()
    };
    let kept = rg.clear_archived_live("s1", Some(&info), None);
    assert_eq!(rg.dav.under(LIVE_S1).join(","), "b.jsonl,c.jsonl", "left");
    assert!(
        kept.contains("kept 2") && kept.contains("b.jsonl, c.jsonl"),
        "kept {kept}"
    );
    let kept = rg.clear_archived_live("s1", None, None);
    assert!(
        kept.contains("there is no archive") && rg.dav.under(LIVE_S1).len() == 2,
        "no archive: {kept}"
    );
}

fn unsign_snap(rg: &Rig, machine: &str) {
    let _ = rg.st.db().and_then(|db| db.conn().ok()).map(|mut c| {
        c.execute("UPDATE snapshots SET state = 'pending', sig = '', committed_at = NULL WHERE machine_id = $1", &[&machine])
    });
}

/// a pause or destroy never waits on a machine that can't snapshot: one that never got past boot isn't asked at all;
/// one that answers "nothing to snapshot" ends the wait at once; while it does wait, the session says what it waits on
#[test]
fn last_snapshot_never_waits_on_a_booting_machine() {
    let rg = Rig::with(|c| c.snapshot_stall = Duration::from_secs(30));
    unsign_snap(&rg, "m1"); // m1 runs: it hasn't sent its final snapshot yet
    let running = |booted: &str, last: GoTime| {
        let cert = rg.cert.clone();
        rg.st.do_(|d| {
            if let Some(s) = d.sessions.get_mut("s1") {
                s.state = "started".into();
                s.machine_id = "m1".into();
                s.booted = booted.into();
                s.cert = Some(cert.clone());
                s.live = Some(Liveness {
                    last_report: last,
                    ..Default::default()
                });
            }
        })
    };
    // never booted (e.g. looping on a locked store): no wait at all
    running("", GoTime::now());
    let t0 = Instant::now();
    rg.pause("s1").unwrap_or_else(|e| panic!("{e:#}"));
    rg.wait_state("s1", "paused", Duration::from_secs(5))
        .unwrap_or_else(|e| panic!("a never-booted machine held the pause: {e:#}"));
    assert!(
        t0.elapsed() <= Duration::from_secs(5),
        "pause took {:?}",
        t0.elapsed()
    );
    // booted: asked, and the session shows what it waits on until the machine answers "nothing to snapshot"
    running("m1", GoTime::now());
    rg.pause("s1").unwrap_or_else(|e| panic!("{e:#}"));
    let mut waiting = String::new();
    for _ in 0..50 {
        std::thread::sleep(Duration::from_millis(20));
        waiting = rg.session("s1").waiting;
        if !waiting.is_empty() {
            break;
        }
    }
    assert_eq!(waiting, "waiting for the machine's last snapshot");
    rg.snapshot_arrived("m1"); // what POST /m/snapshot with X-Snapshot-None does
    rg.wait_state("s1", "paused", Duration::from_secs(5))
        .unwrap_or_else(|e| panic!("the answer didn't end the wait: {e:#}"));
    assert_eq!(rg.session("s1").waiting, "", "still waiting");
    // booted but silent: not asked and not waited for; without a volume it can't be backed up, so it is kept, at once
    running("m1", GoTime::from_unix(GoTime::now().unix() - 600));
    let t0 = Instant::now();
    rg.pause("s1").unwrap_or_else(|e| panic!("{e:#}"));
    rg.wait_state("s1", "failed", Duration::from_secs(5))
        .unwrap_or_else(|e| panic!("a silent machine held the pause: {e:#}"));
    assert!(t0.elapsed() <= Duration::from_secs(5));
    let s = rg.session("s1");
    assert!(
        s.machine_id == "m1" && s.snapshot_failed.contains("silent since"),
        "not kept: {s:?}"
    );
    assert_eq!(crate::flows::wait_text(Duration::from_secs(600)), "10 min");
}

/// wait_state returns once the action that reached the state has ended, not the moment it sets the state
#[test]
fn wait_state_waits_for_the_action_to_end() {
    let rg = Rig::new();
    let unlock = rg.lock("s1", "pausing").unwrap_or_else(|e| panic!("{e:#}"));
    rg.set_state("s1", "paused", "");
    std::thread::scope(|sc| {
        let got = sc.spawn(|| rg.wait_state("s1", "paused", Duration::from_secs(10)));
        std::thread::sleep(3 * crate::sessionops::OPS_POLL);
        assert!(
            !got.is_finished(),
            "wait_state returned while the pause still held the session"
        );
        assert!(rg.busy("s1"), "busy() doesn't see the held lock");
        unlock.call();
        got.join()
            .unwrap_or_else(|_| panic!("panicked"))
            .unwrap_or_else(|e| panic!("{e:#}"));
    });
    assert!(!rg.busy("s1"), "still busy after the unlock");
    // the next action takes the session at once; asking busy() never makes it fail
    let stop = std::sync::atomic::AtomicBool::new(false);
    std::thread::scope(|sc| {
        sc.spawn(|| {
            while !stop.load(std::sync::atomic::Ordering::SeqCst) {
                rg.busy("s1");
            }
        });
        for i in 0..300 {
            let u = rg
                .lock("s1", "pausing")
                .unwrap_or_else(|e| panic!("lock {i}: {e:#}"));
            u.call();
        }
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
    });
}

/// a crash cut actions off: at start each such session becomes a plain one with the reason, nothing is run again by
/// itself, and Deyao's retry works from there (Deyao, 2026-10-13)
#[test]
fn cut_off_actions_end_with_a_reason() {
    let rg = Rig::new();
    let cert = rg.cert.clone();
    rg.st.do_(|d| {
        if let Some(s) = d.sessions.get_mut("s1") {
            s.state = "starting".into(); // a resume: its line is still there
            s.machine_id.clear();
            s.cert = Some(cert.clone());
        }
        let mk = |id: &str, state: &str, m: &str, cert: Option<crate::core::Doc>, waiting: &str| {
            Session {
                id: id.into(),
                state: state.into(),
                machine_id: m.into(),
                cert,
                waiting: waiting.into(),
                ..Default::default()
            }
        };
        d.sessions
            .insert("sNew".into(), mk("sNew", "starting", "", None, "")); // a new line's first start
        d.sessions.insert(
            "sP".into(),
            mk("sP", "pausing", "m2", Some(cert.clone()), "x"),
        );
        d.sessions.insert(
            "sD".into(),
            mk("sD", "destroying", "m3", Some(cert.clone()), ""),
        );
        d.sessions.insert(
            "sR".into(),
            mk("sR", "resuming", "", Some(cert.clone()), ""),
        );
        d.sessions.insert(
            "sOK".into(),
            mk("sOK", "started", "m4", Some(cert.clone()), ""),
        );
    });
    let calls0 = rg
        .core
        .calls
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .len();
    rg.end_cut_off();
    for (id, st) in [
        ("s1", "paused"),
        ("sR", "paused"),
        ("sNew", "failed"),
        ("sP", "failed"),
        ("sD", "failed"),
        ("sOK", "started"),
    ] {
        let s = rg.session(id);
        assert_eq!(s.state, st, "{id}");
        if st != "started" {
            assert!(
                s.error.contains("cut off by a router crash"),
                "{id}: error {}",
                s.error
            );
        }
        assert!(s.waiting.is_empty(), "{id}: still waiting {}", s.waiting);
    }
    let calls = rg
        .core
        .calls
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    assert_eq!(
        calls.len(),
        calls0,
        "the core was called (something ran again): {calls:?}"
    );
    // the retry: the cut-off resume resumes again
    rg.resume("s1", false).unwrap_or_else(|e| panic!("{e:#}"));
    wait_for("the resume's end", || rg.lock("s1", "test").is_ok());
}
