//! fabric_test.go, lockedstart_test.go and volume_test.go.

use super::testutil::*;
use crate::deliver::{DELIVERED_FILE, LINE_KEYS_FILE};
use crate::grants::ALLOW_FILE;
use crate::restore::CHANGES_FILE;
use crate::snapshot::*;
use crate::volume::*;
use crate::{machine_id, machine_object, on_aws, on_fabric};
use std::sync::atomic::Ordering;

/// A fabric machine (docs/PLAN-fabric.md): its object is fabric-<its id>, its keys line goes to the sandbox's console,
/// and its snapshot carries the Jarvis records and the other small files only
#[test]
fn fabric_machine() {
    let e = TestEnv::new();
    let home = e.home.clone();
    crate::env::set("JARVIS2_RUNNER", Some("fabric"));
    crate::env::set(
        "JARVIS2_MACHINE_ID",
        Some("x0190f6c25b1e7a3c9d4e1f2a3b4c5d6e"),
    );
    assert!(
        on_fabric() && !on_aws() && machine_id() == "x0190f6c25b1e7a3c9d4e1f2a3b4c5d6e",
        "not a fabric machine"
    );
    let o = jarvis_doc::Object(machine_object(&machine_id()));
    assert_eq!(o.0, "fabric-x0190f6c25b1e7a3c9d4e1f2a3b4c5d6e");
    assert_eq!(o.kind(), Some(jarvis_doc::Kind::Machine));
    assert_eq!(o.runner(), Some("fabric"));
    assert_eq!(
        crate::keeper::keys_console(),
        crate::paths::FABRIC_CONSOLE_PATH
    );
    for rel in state_paths() {
        assert!(snapshot_file(rel), "{rel} in a fabric snapshot");
    }
    for rel in [
        ALLOW_FILE,
        LINE_KEYS_FILE,
        DELIVERED_FILE,
        CHANGES_FILE,
        ".claude.json",
    ] {
        assert!(
            state_paths().contains(&rel),
            "{rel} not in a fabric snapshot"
        );
    }
    std::fs::create_dir_all(home.join("workspace/repo")).unwrap();
    std::fs::write(
        home.join("workspace/repo/f.txt"),
        "on the network filesystem",
    )
    .unwrap();
    std::fs::create_dir_all(home.join(".claude/projects/p")).unwrap();
    std::fs::write(home.join(".claude/projects/p/t.jsonl"), "{}").unwrap();
    std::fs::write(home.join(ALLOW_FILE), r#"{"signed":"grant"}"#).unwrap();
    std::fs::write(home.join(DELIVERED_FILE), r#"["d1"]"#).unwrap();
    let mut snap = vec![];
    write_snapshot(&mut snap).unwrap();
    // the shared disk's copies change after the snapshot: the restore puts the signed records back and leaves the
    // directories as the disk has them
    std::fs::write(home.join(ALLOW_FILE), r#"{"forged":"grant"}"#).unwrap();
    std::fs::write(home.join(DELIVERED_FILE), "[]").unwrap();
    std::fs::write(home.join("workspace/repo/f.txt"), "newer work").unwrap();
    assert_eq!(unpack_reader(&snap[..]).unwrap(), 2);
    for (rel, want) in [
        (ALLOW_FILE, r#"{"signed":"grant"}"#),
        (DELIVERED_FILE, r#"["d1"]"#),
        ("workspace/repo/f.txt", "newer work"),
    ] {
        assert_eq!(
            std::fs::read_to_string(home.join(rel)).unwrap(),
            want,
            "{rel}"
        );
    }
    // a destroy (snapshot-full): the whole state
    FULL_SNAPSHOT.store(true, Ordering::SeqCst);
    assert_eq!(
        state_paths().len(),
        SNAPSHOT_PATHS.len(),
        "a destroy's snapshot on the fabric is not whole"
    );
    FULL_SNAPSHOT.store(false, Ordering::SeqCst);
    // the other runners keep the whole snapshot
    crate::env::set("JARVIS2_RUNNER", Some(""));
    assert!(
        state_paths().len() == SNAPSHOT_PATHS.len()
            && machine_object("abc123") == "fly-abc123"
            && crate::keeper::keys_console() == crate::paths::CONSOLE_PATH
    );
    crate::env::set("JARVIS2_RUNNER", Some("aws"));
    assert!(
        state_paths().len() == SNAPSHOT_PATHS.len() && machine_object("i-0abc") == "aws-i-0abc"
    );
}

/// A store still locked after the wait doesn't stop the machine: the pull says so and prepare starts the harness
/// without secrets; any other failure still stops it.
#[test]
fn a_locked_store_is_reported_apart_from_other_pull_failures() {
    let e = TestEnv::new();
    let key = e.machine_key();
    crate::boot::PULL_TRIES.store(2, Ordering::SeqCst);
    crate::boot::PULL_WAIT_MS.store(1, Ordering::SeqCst);
    for (status, locked) in [(423u16, true), (409, false), (500, false)] {
        let srv = FakeRouter::new(&key.sig.public_key(), move |_| {
            ans(status, r#"{"error":"store gmail is locked"}"#)
        });
        let r = crate::boot::pull_secrets(&srv.client(), "core", "m1");
        let e = r.expect_err("pulled");
        assert_eq!(
            e.downcast_ref::<crate::secrets::StoresLocked>().is_some(),
            locked,
            "HTTP {status}: {e:#}"
        );
    }
}

/// every path the snapshot holds goes onto the volume: directories bind-mounted, single files mirrored
#[test]
fn the_volume_holds_every_snapshot_path() {
    let (dirs, files) = volume_split();
    assert_eq!(dirs.len() + files.len(), SNAPSHOT_PATHS.len());
    // .claude/.dsh-session (2026-10-26): bind-mounted as a directory, no dsh session could keep its conversation id
    for f in [
        ".claude.json",
        ALLOW_FILE,
        DELIVERED_FILE,
        ".claude/.dsh-session",
        ".claude/.paseo-agent",
    ] {
        assert!(files.contains(&f), "{f} isn't mirrored: {files:?}");
    }
    for d in ["workspace", "artifacts", ".claude/projects"] {
        assert!(dirs.contains(&d), "{d} isn't bind-mounted: {dirs:?}");
    }
}

/// with /data mounted, boot puts the state directories onto it (the image's files copied first) and mirrors the files
#[test]
fn setup_volume_bind_mounts_the_state() {
    let e = TestEnv::new();
    let data = e.root.join("data");
    std::fs::create_dir_all(&data).unwrap();
    let mi = e.root.join("mountinfo");
    *TEST_VOLUME.lock().unwrap() = Some(TestVolume {
        root: data.clone(),
        mounts: mi.clone(),
        cmds: vec![],
    });
    assert!(!setup_volume(), "a volume without a mount");
    std::fs::write(
        &mi,
        format!("36 35 0:1 / {} rw - ext4 /dev/vdb rw\n", data.display()),
    )
    .unwrap();
    std::fs::create_dir_all(e.home.join("artifacts")).unwrap();
    std::fs::write(e.home.join("artifacts/from-image"), "x").unwrap();
    std::fs::write(e.home.join(".claude.json"), r#"{"a":1}"#).unwrap();
    assert!(setup_volume(), "no volume set up");
    assert_eq!(
        std::fs::read_to_string(data.join("home/artifacts/from-image")).unwrap(),
        "x",
        "the image's files weren't copied onto the volume"
    );
    let cmds = TEST_VOLUME
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .cmds
        .join("\n");
    let want = format!(
        "mount --bind {} {}",
        data.join("home/workspace").display(),
        e.home.join("workspace").display()
    );
    assert!(cmds.contains(&want), "commands {cmds}");
    mirror_volume_files();
    assert_eq!(
        std::fs::read_to_string(data.join("home/.claude.json")).unwrap(),
        r#"{"a":1}"#,
        "~/.claude.json isn't mirrored"
    );
    assert_eq!(
        crate::paths::predecessor_tmp(),
        data.join(".predecessor.tar.gz")
    );
}
