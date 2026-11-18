use crate::archive::{ArchiveInfo, RepoChange, records_index, resolve_link};
use crate::archivetar::{ARCHIVES_ROOT, archive_file_for};
use crate::state::{Record, Session};
use crate::testutil::{Rig, tfile, wait_for};
use jarvis_go::GoTime;
use serde_json::{Value, json};
use std::sync::atomic::Ordering;

/// the transcript's title, made path-safe
fn rig_archive() -> String {
    format!("{ARCHIVES_ROOT}/2026-10-01 Fix the router.tar.gz")
}

fn destroyed(rg: &Rig) {
    rg.destroy("s1").unwrap_or_else(|e| panic!("{e:#}"));
    // finish lists it a moment before its archive is set (flows.rs)
    wait_for("the record", || {
        rg.record("s1").is_some_and(|r| r.archive.is_some())
    });
}

#[test]
fn archive_layout_and_index() {
    let rg = Rig::new();
    let info = rg
        .archive("s1")
        .unwrap_or_else(|e| panic!("{e:#}"))
        .unwrap_or_else(|| panic!("no archive"));
    assert_eq!(info.file, rig_archive());
    // ONE file in Jarvis 4's folder, and only the index next to it: nothing anywhere else
    assert_eq!(
        rg.dav.under("claude-records").join(","),
        ".jarvis4-records/2026-10-01 Fix the router.tar.gz,.jarvis4-records/index.json"
    );
    let (files, order) = rg.dav.archive(&rig_archive());
    let mut want = vec![
        "session.json",
        "restore-s1.json",
        "transcript-aaaa.jsonl",
        "transcript-bbbb.jsonl",
        "artifacts/proj/report.html",
        "artifacts/record.md",
        "artifacts/report.html",
        "artifacts/sub/shot.png",
        "jarvis2/cert.json",
        "jarvis2/core-cert.json",
        "jarvis2/snapshot.sig",
        "jarvis2/snapshot.tar.gz",
    ];
    let mut got: Vec<&str> = order.iter().map(String::as_str).collect();
    got.sort();
    want.sort();
    assert_eq!(got, want, "members");
    // the transcripts come before the artifacts, and the snapshot last
    assert!(
        order[0] == "session.json"
            && order[2] == "transcript-aaaa.jsonl"
            && order[3] == "transcript-bbbb.jsonl"
            && order.last().map(String::as_str) == Some("jarvis2/snapshot.tar.gz"),
        "order {order:?}"
    );
    assert!(
        files["artifacts/report.html"] == b"<p>r</p>"
            && files["artifacts/proj/report.html"] == b"<p>r</p>",
        "a symlinked artifact wasn't followed"
    );
    assert_eq!(
        info.transcripts.join(","),
        "transcript-aaaa.jsonl,transcript-bbbb.jsonl",
        "transcripts oldest first"
    );
    let on_box = rg.dav.get(&rig_archive()).map_or(0, |b| b.len()) as i64;
    assert!(
        info.bytes == on_box && info.upload_seconds > 0.0,
        "size {} (box {on_box}), upload {}",
        info.bytes,
        info.upload_seconds
    );
    let meta: Value = serde_json::from_slice(&files["session.json"]).unwrap_or_default();
    assert!(
        meta["id"] == "s1"
            && meta["snapshotMachine"] == "m1"
            && meta["unresolvedArtifactLinks"] == json!(["artifacts/outside"])
            && meta["archive"] == json!(rig_archive()),
        "session.json {meta}"
    );
    // the signed snapshot verifies against the archived cert's machine key
    let cd: crate::core::Doc =
        serde_json::from_slice(&files["jarvis2/cert.json"]).unwrap_or_default();
    let c: Value = serde_json::from_str(&cd.payload).unwrap_or_default();
    use sha2::Digest;
    let sum = hex::encode(sha2::Sha256::digest(&files["jarvis2/snapshot.tar.gz"]));
    let sig = String::from_utf8_lossy(&files["jarvis2/snapshot.sig"]).into_owned();
    assert!(
        crate::http::verify_p256(
            c["machine"]["signingKey"].as_str().unwrap_or(""),
            sum.as_bytes(),
            &sig
        ),
        "archived snapshot doesn't verify against the archived cert"
    );
    let idx: Vec<Value> = serde_json::from_slice(&rg.dav.get(&records_index()).unwrap_or_default())
        .unwrap_or_default();
    assert!(
        idx.len() == 1 && idx[0]["id"] == "s1" && idx[0]["archive"] == json!(rig_archive()),
        "index {idx:?}"
    );
    assert_eq!(
        rg.session("s1").archive_file,
        rig_archive(),
        "the session doesn't keep its archive's name"
    );
}

#[test]
fn archive_file_unique() {
    let rg = Rig::new();
    rg.st.do_(|d| {
        if let Some(s) = d.sessions.get_mut("s1") {
            s.label = "Mine".into();
        }
    });
    let b = rg.box_().unwrap_or_else(|| panic!("no box"));
    let _ = b.mkcols(ARCHIVES_ROOT);
    let _ = b.put_bytes(&format!("{ARCHIVES_ROOT}/2026-10-01 Mine.tar.gz"), b"x"); // another session's, same day and title
    let info = rg
        .archive("s1")
        .unwrap_or_else(|e| panic!("{e:#}"))
        .unwrap_or_default();
    assert_eq!(
        info.file,
        format!("{ARCHIVES_ROOT}/2026-10-01 Mine 2.tar.gz")
    );
}

/// a failed upload leaves no archive under its real name (only the .part, deleted), and the next try writes it whole
#[test]
fn archive_upload_fails_whole() {
    let rg = Rig::new();
    rg.dav.set_fail(&rig_archive()); // the rename fails
    assert!(rg.archive("s1").is_err(), "no error");
    assert!(
        rg.dav.under(ARCHIVES_ROOT).is_empty(),
        "left on the box: {:?}",
        rg.dav.under(ARCHIVES_ROOT)
    );
    rg.dav.set_fail("");
    let info = rg
        .archive("s1")
        .unwrap_or_else(|e| panic!("{e:#}"))
        .unwrap_or_default();
    assert_eq!(info.file, rig_archive());
    rg.dav.archive(&rig_archive());
}

#[test]
fn destroy_archives_then_records() {
    let rg = Rig::new();
    destroyed(&rg);
    let rec = rg.record("s1").unwrap_or_default();
    let a = rec.archive.clone().unwrap_or_default();
    assert!(
        a.file == rig_archive() && a.last.as_ref().is_some_and(|l| l.text == "done it"),
        "record {a:?}"
    );
    assert_eq!(rec.session.archive_file, rig_archive());
    wait_for("the snapshot gone", || rg.snap("m1").is_none());
    assert!(
        rg.objects.list("snapshots/").unwrap_or_default().is_empty(),
        "the snapshot stayed in the bucket"
    );
    // the tail of the archived conversation
    let tail = rg
        .record_tail("s1")
        .unwrap_or_else(|(st, e)| panic!("{st} {e:#}"));
    assert!(
        tail.title == "Fix the: router" && tail.messages.len() == 2,
        "tail {tail:?}"
    );
}

#[test]
fn destroy_archive_failure_keeps_session() {
    let rg = Rig::new();
    rg.dav.set_fail(&format!("{ARCHIVES_ROOT}/2026"));
    let _ = rg.destroy("s1");
    wait_for("the error", || {
        let s = rg.session("s1");
        s.state == "paused" && s.error.starts_with("archive:")
    });
    assert!(
        rg.record("s1").is_none(),
        "a failed archive still destroyed the session"
    );
    // force: destroyed anyway, the error kept on the record
    wait_for("the lock", || rg.destroy_with("s1", true).is_ok());
    wait_for("the record", || rg.record("s1").is_some());
    let rec = rg.record("s1").unwrap_or_default();
    assert!(
        rec.archive.is_none() && !rec.archive_error.is_empty(),
        "forced record {rec:?}"
    );
}

#[test]
fn destroy_without_snapshot_needs_no_box() {
    let rg = Rig::new();
    rg.snap_drop("m1");
    *rg.box_override.write().unwrap_or_else(|e| e.into_inner()) = Some(None);
    let _ = rg.destroy("s1");
    wait_for("the record", || rg.record("s1").is_some());
}

#[test]
fn paused_tail_and_changes() {
    let rg = Rig::new();
    let tail = rg
        .paused_tail("s1")
        .unwrap_or_else(|(st, e)| panic!("{st} {e:#}"));
    assert!(
        tail.title == "Fix the: router"
            && tail.messages.last().is_some_and(|m| m.text == "done it"),
        "{tail:?}"
    );
    let ch = rg.changes("s1");
    let repos: Vec<RepoChange> = serde_json::from_value(ch["repos"].clone()).unwrap_or_default();
    assert!(
        ch["checked"] == true
            && repos.len() == 2
            && repos[0].name == "proj"
            && repos[0].uncommitted == 2
            && repos[0].unpushed == 1
            && repos[1].unpushed == -1,
        "changes {ch:?}"
    );
    rg.st.do_(|d| {
        if let Some(s) = d.sessions.get_mut("s1") {
            s.machine_id = "m1".into();
            s.state = "started".into();
        }
    });
    // its last pause's tail, marked stale
    let tl = rg
        .paused_tail("s1")
        .unwrap_or_else(|(st, e)| panic!("{st} {e:#}"));
    assert!(tl.stale, "a running session's tail: {tl:?}");
    // Exec has no machine to answer
    assert_eq!(
        rg.changes("s1")["checked"],
        false,
        "a running session without a grant"
    );
}

#[test]
fn purge_record() {
    let rg = Rig::new();
    destroyed(&rg);
    let file = rg
        .record("s1")
        .and_then(|r| r.archive)
        .map(|a| a.file)
        .unwrap_or_default();
    let out = rg.delete_record("s1", true);
    assert!(out.is_ok() && rg.dav.get(&file).is_none(), "purge {out:?}");
    // a record whose archive isn't one of Jarvis 4's is refused
    rg.st.do_(|d| {
        d.records.push(Record {
            session: Session {
                id: "s2".into(),
                ..Default::default()
            },
            archive: Some(ArchiveInfo {
                file: "claude-records/2026-10-01 Jarvis 2's".into(),
                ..Default::default()
            }),
            ..Default::default()
        });
    });
    assert!(
        rg.delete_record("s2", true).is_err(),
        "purged a file outside Jarvis 4's folder"
    );
    let _ = rg.delete_record("s2", false);
    let idx: Vec<Value> = serde_json::from_slice(&rg.dav.get(&records_index()).unwrap_or_default())
        .unwrap_or_default();
    assert!(idx.is_empty() && rg.record("s1").is_none(), "index {idx:?}");
}

#[test]
fn restore_record() {
    let rg = Rig::new();
    destroyed(&rg);
    let sid = rg
        .restore_record("s1", "req1")
        .unwrap_or_else(|e| panic!("{e:#}"));
    let (s, appr) = rg.st.do_(|d| {
        (
            d.sessions.get(&sid).cloned().unwrap_or_default(),
            d.approvals.values().find(|a| a.session == sid).cloned(),
        )
    });
    assert!(
        s.state == "approval"
            && s.restore_from == "s1"
            && s.restore_cert
                .as_ref()
                .is_some_and(|c| c.payload == rg.cert.payload),
        "session {s:?}"
    );
    let appr = appr.unwrap_or_else(|| panic!("no approval"));
    assert!(
        appr.kind == "new-session"
            && appr
                .options
                .get("restore")
                .is_some_and(|r| r.starts_with("Fix the: router (destroyed ")),
        "approval {appr:?}"
    );
    // the only start mode, whatever s1 ran in
    assert!(s.permission_mode == "bypass" && appr.options["permissionMode"] == "bypass");
    // the first machine gets the old cert in its env; a later one doesn't
    assert!(
        rg.machine_env(&s)
            .get("JARVIS2_RESTORE_CERT")
            .is_some_and(|c| !c.is_empty()),
        "no restore cert in the first machine's env"
    );
    // only the line's first machine may fetch the snapshot
    let first = rg
        .core
        .key
        .doc(&json!({"kind": "succession-cert", "predecessorId": ""}));
    rg.st.do_(|d| {
        d.machines.insert("m9".into(), sid.clone());
        d.certs.insert("m9".into(), first.clone());
        if let Some(x) = d.sessions.get_mut(&sid) {
            x.machine_id = "m9".into();
            x.cert = Some(first.clone());
        }
    });
    assert!(
        rg.restore_files_for("m9").is_some(),
        "the first machine can't fetch the restore"
    );
    let succ = Session {
        restore_cert: s.restore_cert.clone(),
        cert: Some(rg.cert.clone()),
        ..Default::default()
    };
    assert!(
        rg.machine_env(&succ)
            .get("JARVIS2_RESTORE_CERT")
            .is_none_or(|c| c.is_empty()),
        "a successor got the restore cert"
    );
    let later = rg
        .core
        .key
        .doc(&json!({"kind": "succession-cert", "predecessorId": "m8"}));
    rg.st.do_(|d| {
        d.certs.insert("m9".into(), later.clone());
    });
    assert!(
        rg.restore_files_for("m9").is_none(),
        "a successor may fetch the restore"
    );
    // once it runs, the files go and the record notes the restore
    rg.st.do_(|d| {
        if let Some(x) = d.sessions.get_mut(&sid) {
            x.state = "started".into();
        }
    });
    rg.tidy_restores();
    assert!(
        rg.snap(&crate::restore::restore_snap(&sid)).is_none(),
        "the restore's snapshot stayed"
    );
    let rec = rg.record("s1").unwrap_or_default();
    assert!(
        rec.restored.len() == 1 && rec.restored[0].session == sid,
        "restored {:?}",
        rec.restored
    );
}

#[test]
fn restore_refuses_bad_signature() {
    let rg = Rig::new();
    destroyed(&rg);
    let file = rg
        .record("s1")
        .and_then(|r| r.archive)
        .map(|a| a.file)
        .unwrap_or_default();
    let (mut members, order) = rg.dav.archive(&file);
    members.insert("jarvis2/snapshot.tar.gz".into(), b"tampered".to_vec());
    let gz = flate2::write::GzEncoder::new(vec![], flate2::Compression::default());
    let mut tw = tar::Builder::new(gz);
    for n in &order {
        let mut h = tar::Header::new_gnu();
        h.set_mode(0o644);
        h.set_size(members[n].len() as u64);
        let _ = tw.append_data(&mut h, n, &members[n][..]);
    }
    let b = tw
        .into_inner()
        .and_then(|gz| gz.finish())
        .unwrap_or_default();
    let _ = rg.box_().map(|x| x.put_bytes(&file, &b));
    match rg.restore_record("s1", "r") {
        Err(e) => assert!(format!("{e:#}").contains("isn't signed"), "err {e:#}"),
        Ok(_) => panic!("a tampered archive restored"),
    }
}

#[test]
fn resolve_links() {
    for (a, b, want) in [
        ("artifacts/a", "../workspace/x", "workspace/x"),
        ("artifacts/a", "/home/claude/workspace/x", "workspace/x"),
        ("artifacts/a", "/etc/passwd", ""),
        ("artifacts/a", "../../../etc", ""),
        ("artifacts/sub/a", "b", "artifacts/sub/b"),
    ] {
        assert_eq!(resolve_link(a, b), want, "resolve_link({a}, {b})");
    }
}

#[test]
fn archive_file_names() {
    let s = Session {
        id: "s1".into(),
        created: GoTime::parse("2026-10-01T00:00:00Z").unwrap_or_default(),
        ..Default::default()
    };
    assert_eq!(
        archive_file_for(&s, "..hidden/x"),
        "claude-records/.jarvis4-records/2026-10-01 hidden x.tar.gz"
    );
    assert_eq!(
        archive_file_for(&s, ""),
        "claude-records/.jarvis4-records/2026-10-01 s1.tar.gz"
    );
}

/// A snapshot with no transcript archived with transcripts nil went out as "transcripts": null and blanked the web
/// page's Previous tab. GET /api/records always lists them as an array, old records included.
#[test]
fn records_list_no_transcripts_as_array() {
    let rg = Rig::new();
    rg.st.do_(|d| {
        d.records.push(Record {
            session: Session {
                id: "s9".into(),
                ..Default::default()
            },
            destroyed_at: GoTime::now(),
            archive: Some(ArchiveInfo {
                file: format!("{ARCHIVES_ROOT}/2026-10-16 s9.tar.gz"),
                title: "s9".into(),
                signer: "m9".into(),
                ..Default::default()
            }),
            ..Default::default()
        });
    });
    // the rig's router checks Access; this one doesn't (NoAccess), on the same records
    let (r, _dir) = crate::testutil::new_test_router_on(&rg.t);
    let h = r.handler();
    let (code, v) = crate::testutil::call(&h, "GET", "/api/records", "");
    assert_eq!(code, 200, "{v}");
    let recs = v["records"].as_array().cloned().unwrap_or_default();
    assert!(!recs.is_empty(), "records {v}");
    assert_eq!(
        recs.last().map(|r| r["archive"]["transcripts"].clone()),
        Some(json!([]))
    );
}

/// many artifacts go into the one archive (streamed, nothing left in tmp), with progress; a failed upload fails the
/// archive and leaves nothing in tmp
#[test]
fn archive_many_artifacts_and_progress() {
    let _g = crate::testutil::serial();
    let rg = Rig::new();
    let mut files = rg.files.clone();
    for i in 0..60 {
        files.push(tfile(
            &format!("artifacts/deep/d{}/e/f{i}.txt", i % 7),
            &format!("file {i}"),
            crate::testutil::RIG_T0,
        ));
    }
    rg.write_snapshot("m1", &files);
    let every = crate::archivetar::ARCHIVE_PROGRESS_EVERY_MS.swap(0, Ordering::SeqCst);
    let info = rg
        .archive("s1")
        .unwrap_or_else(|e| panic!("{e:#}"))
        .unwrap_or_default();
    crate::archivetar::ARCHIVE_PROGRESS_EVERY_MS.store(every, Ordering::SeqCst);
    let (got, _) = rg.dav.archive(&info.file);
    for i in 0..60 {
        let f = format!("artifacts/deep/d{}/e/f{i}.txt", i % 7);
        assert_eq!(
            got.get(&f).map(Vec::as_slice),
            Some(format!("file {i}").as_bytes()),
            "{f} missing or wrong"
        );
    }
    assert!(
        info.artifacts == 64 && info.transcripts.len() == 2,
        "artifacts {} transcripts {:?}",
        info.artifacts,
        info.transcripts
    );
    assert_eq!(rg.session("s1").waiting, "", "waiting left");
    let tmp = std::path::Path::new(&rg.cfg.data_dir).join("tmp");
    assert_eq!(
        std::fs::read_dir(&tmp).map(|d| d.count()).unwrap_or(0),
        0,
        "temp files left"
    );
    // a failing upload: the archive fails, nothing is left in tmp
    let rg = Rig::new();
    rg.write_snapshot("m1", &files);
    let tmp = std::path::Path::new(&rg.cfg.data_dir).join("tmp");
    rg.dav.set_fail(&format!("{ARCHIVES_ROOT}/2026"));
    match rg.archive("s1") {
        Err(e) => assert!(format!("{e:#}").contains("507"), "want the 507, got {e:#}"),
        Ok(_) => panic!("archived through a failing upload"),
    }
    assert_eq!(
        std::fs::read_dir(&tmp).map(|d| d.count()).unwrap_or(0),
        0,
        "temp files left after the failure"
    );
}

#[test]
fn archive_progress_text() {
    let _g = crate::testutil::serial();
    let rg = Rig::new();
    let every = crate::archivetar::ARCHIVE_PROGRESS_EVERY_MS.swap(3_600_000, Ordering::SeqCst);
    {
        let p = rg.archive_progress("s1", 10_000_000);
        p(1_000_000); // the first is always shown
        p(2_000_000); // within the interval: not
    }
    crate::archivetar::ARCHIVE_PROGRESS_EVERY_MS.store(every, Ordering::SeqCst);
    assert_eq!(
        rg.session("s1").waiting,
        "archiving to the Storage Box: 1.0 MB of 10.0 MB"
    );
}

/// a kernel line's archived cert (the spawner's) names its machine only in succ: a restore of it once signed
/// restore.machine "" and the machine refused to start ("the cert's restore")
#[test]
fn restore_machine_id() {
    let rg = Rig::new();
    for (cert, want) in [
        (
            json!({"kind": "succession", "pred": "source-26f541401cc8edec59e664b47591a506", "succ": "fly-185923da026d08",
                "machine": {"signingKey": "k", "encryptionKey": "e", "image": "i"}}),
            "185923da026d08",
        ),
        (
            json!({"kind": "succession-cert", "machine": {"id": "m1", "signingKey": "k"}}),
            "m1",
        ),
        (
            json!({"kind": "succession", "succ": "source-26f541401cc8edec59e664b47591a506", "machine": {}}),
            "",
        ),
        (
            json!({"kind": "succession", "succ": "fly-185923da026d08"}),
            "",
        ),
    ] {
        let got = crate::vouch::restore_machine_id(&rg.core.key.doc(&cert));
        match got {
            Ok(id) => assert_eq!(id, want, "{cert}"),
            Err(e) => assert_eq!(want, "", "{cert}: {e:#}"),
        }
    }
}
