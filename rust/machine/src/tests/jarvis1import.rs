//! jarvis1import_test.go: a Jarvis 1 session imported, every byte the manifest names checked.

use super::testutil::*;
use super::vouch::v2;
use crate::crypto::sha256_hex;
use crate::jarvis1import::*;
use crate::restore::{reimport_jarvis1, restore_archived};
use crate::vouch::vouch;
use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};

const T_UUID: &str = "0fa81372-5d1c-49af-b680-25a842f5df96";

enum Ent<'a> {
    Dir(&'a str),
    File(&'a str, &'a str),
    Sym(&'a str, &'a str),
    Hard(&'a str, &'a str),
}

/// a tar.gz with headers written by hand (the tar crate refuses to write a name with ..)
fn tgz(ents: &[Ent]) -> Vec<u8> {
    let mut raw = vec![];
    for e in ents {
        let mut h = tar::Header::new_ustar();
        let (name, body, link, ty, mode) = match e {
            Ent::Dir(n) => (*n, "", "", tar::EntryType::Directory, 0o755),
            Ent::File(n, b) => (*n, *b, "", tar::EntryType::Regular, 0o644),
            Ent::Sym(n, l) => (*n, "", *l, tar::EntryType::Symlink, 0o644),
            Ent::Hard(n, l) => (*n, "", *l, tar::EntryType::Link, 0o644),
        };
        h.as_old_mut().name[..name.len()].copy_from_slice(name.as_bytes());
        h.as_old_mut().linkname[..link.len()].copy_from_slice(link.as_bytes());
        h.set_mode(mode);
        h.set_mtime(1_790_812_800);
        h.set_entry_type(ty);
        h.set_size(body.len() as u64);
        h.set_cksum();
        raw.extend_from_slice(h.as_bytes());
        raw.extend_from_slice(body.as_bytes());
        raw.resize(raw.len().div_ceil(512) * 512, 0);
    }
    raw.extend_from_slice(&[0u8; 1024]);
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gz.write_all(&raw).unwrap();
    gz.finish().unwrap()
}

type Files = BTreeMap<String, Vec<u8>>;

/// a fake router serving one import: the manifest at /m/restore-snapshot, its files at /m/import-file/<name>, and
/// taking the wakeups and crons the machine arms
fn import_router(
    key: &str,
    files: &Files,
    order: &[String],
    tamper: Files,
) -> (FakeRouter, Vec<u8>, Arc<Mutex<Vec<String>>>) {
    let man = serde_json::json!({"kind": "jarvis1-import", "v": 1, "session": "j1abc",
        "files": order.iter().map(|n| serde_json::json!({"name": n, "sha256": sha256_hex(&files[n]), "size": files[n].len()})).collect::<Vec<_>>()});
    let mb = crate::gojson::marshal(&man).into_bytes();
    let armed = Arc::new(Mutex::new(vec![]));
    let (a2, f2, m2) = (armed.clone(), files.clone(), mb.clone());
    let srv = FakeRouter::new(key, move |r| {
        if r.path == "/m/restore-snapshot" {
            return ans(200, m2.clone());
        }
        if let Some(n) = r.path.strip_prefix("/m/import-file/") {
            return ans(
                200,
                tamper
                    .get(n)
                    .or_else(|| f2.get(n))
                    .cloned()
                    .unwrap_or_default(),
            );
        }
        if r.path.starts_with("/m/api/sessions/s1/") {
            a2.lock()
                .unwrap()
                .push(format!("{} {}", r.path, String::from_utf8_lossy(&r.body)));
            return ans(200, r#"{"ok":true}"#);
        }
        ans(404, "")
    });
    (srv, mb, armed)
}

fn j1_files(home: &Path) -> (Files, Vec<String>) {
    let esc = format!("{}/.ssh", home.display());
    let ws = tgz(&[
        Ent::Dir("workspace/"),
        Ent::Dir("workspace/claude-env/"),
        Ent::File("workspace/claude-env/README.md", "readme"),
        Ent::Sym("workspace/claude-env/link", "README.md"),
        Ent::Hard(
            "workspace/claude-env/hard",
            "workspace/claude-env/README.md",
        ),
        Ent::Sym("workspace/escape", &esc),
        Ent::File("workspace/escape/authorized_keys", "through a symlink"),
        Ent::File("../evil", "outside"),
        Ent::File(".bashrc", "outside the root"),
    ]);
    let art = tgz(&[Ent::File("artifacts/record.md", "# record")]);
    let now_ms = crate::util::unix_now() * 1000;
    let rec = format!(
        r#"{{"id":"j1abc","title":"T","metadata":{{"wake_default":"{{\"name\":\"default\",\"at\":1000,\"prompt\":\"warm up\"}}","cron_owcs-tix":"{{\"name\":\"owcs-tix\",\"prompt\":\"check tickets\",\"every\":86400,\"tz\":\"Asia/Shanghai\",\"nextAt\":{},\"until\":{}}}","watch_x":"{{}}"}}}}"#,
        now_ms - 2 * 3_600_000,
        now_ms + 30 * 86_400_000
    );
    let files: Files = [
        ("session.json".to_string(), rec.into_bytes()),
        ("manifest.txt".to_string(), format!("{T_UUID}.jsonl\n").into_bytes()),
        (
            "claude.json".to_string(),
            br#"{"machineID":"m-old","oauthAccount":{"emailAddress":"x"},"userID":"u","projects":{"/home/claude/workspace/claude-env":{}}}"#.to_vec(),
        ),
        (format!("{T_UUID}.jsonl"), b"{\"type\":\"user\",\"message\":{\"content\":\"hello\"}}\n".to_vec()),
        ("workspace.tar.gz".to_string(), ws),
        ("artifacts.tar.gz".to_string(), art),
    ]
    .into();
    let order = [
        "session.json",
        "manifest.txt",
        "claude.json",
        &format!("{T_UUID}.jsonl"),
        "artifacts.tar.gz",
        "workspace.tar.gz",
    ]
    .map(String::from)
    .to_vec();
    (files, order)
}

fn restore_cert(machine: &str, sha: &str) -> crate::cert::Cert {
    v2(
        &format!(r#"{{"v":1,"restore":{{"machine":"{machine}","sha256":"{sha}"}}}}"#),
        "",
    )
}

#[test]
fn jarvis1_import_restores_what_the_cert_names() {
    let e = TestEnv::new();
    let key = e.machine_key();
    let home = e.home.clone();
    std::fs::create_dir_all(home.join(".ssh")).unwrap();
    let (files, order) = j1_files(&home);
    let (srv, mb, armed) = import_router(&key.sig.public_key(), &files, &order, Files::new());
    let c = srv.client();
    let mut cert = restore_cert("j1abc", &sha256_hex(&mb));
    let v = vouch(&cert).unwrap();
    restore_archived(&c, "", "m1", &mut cert, &v).unwrap();
    let read = |rel: &str| std::fs::read_to_string(home.join(rel)).unwrap_or_default();
    assert!(
        read("workspace/claude-env/README.md") == "readme"
            && read("artifacts/record.md") == "# record",
        "tarballs not in place"
    );
    assert_eq!(
        std::fs::read_link(home.join("workspace/claude-env/link"))
            .unwrap()
            .to_str(),
        Some("README.md")
    );
    assert_eq!(read("workspace/claude-env/hard"), "readme", "hard link");
    assert!(
        !home.join(".ssh/authorized_keys").exists(),
        "wrote through a symlink"
    );
    assert!(
        !home.join(".bashrc").exists(),
        "wrote outside the tarball's root"
    );
    assert!(
        !home.parent().unwrap().join("evil").exists(),
        "wrote outside home"
    );
    let cj: serde_json::Value = serde_json::from_str(&read(".claude.json")).unwrap();
    assert!(
        cj["machineID"] == "m-old"
            && cj.get("oauthAccount").is_none()
            && cj.get("userID").is_none()
            && cj.get("projects").is_some(),
        "{cj}"
    );
    // the transcripts wait for the repos, then go under the working dir's project
    place_imported_transcripts();
    let slug = format!(
        "-{}-workspace-claude-env",
        home.display()
            .to_string()
            .trim_matches('/')
            .replace('/', "-")
    );
    assert!(
        !read(&format!(".claude/projects/{slug}/{T_UUID}.jsonl")).is_empty(),
        "transcript not placed"
    );
    // the record's wakeup (long past) fires soon; the cron keeps its period and time of day; its missed run fires soon
    rearm_jarvis1(&c, "s1");
    let a = armed.lock().unwrap().clone();
    assert_eq!(a.len(), 3, "armed {a:?}");
    let all = a.join("\n");
    for want in [
        r#"/wakeups {"delaySeconds":300,"name":"default","prompt":"warm up"}"#,
        r#"/crons {"at":"#,
        r#""everySeconds":86400"#,
        r#""tz":"Asia/Shanghai""#,
        r#""name":"missed-owcs-tix""#,
    ] {
        assert!(all.contains(want), "armed lacks {want}: {all}");
    }
    let note = read("artifacts/jarvis1-import/rearmed.txt");
    assert!(
        note.contains("passed while paused")
            && note.contains("watch_x")
            && !read("artifacts/jarvis1-import/session.json").is_empty(),
        "{note}"
    );
    assert!(!home.join(".jarvis1-import").exists(), "staging dir left");
}

#[test]
fn jarvis1_import_refuses_other_bytes() {
    for n in [
        "workspace.tar.gz".to_string(),
        format!("{T_UUID}.jsonl"),
        "claude.json".to_string(),
    ] {
        let e = TestEnv::new();
        let key = e.machine_key();
        let (files, order) = j1_files(&e.home);
        let mut other = files[&n].clone();
        other.push(b'x');
        if n == "workspace.tar.gz" {
            other = tgz(&[Ent::File("workspace/claude-env/README.md", "swapped")]);
        }
        let (srv, mb, _) = import_router(
            &key.sig.public_key(),
            &files,
            &order,
            [(n.clone(), other)].into(),
        );
        let mut cert = restore_cert("j1abc", &sha256_hex(&mb));
        let v = vouch(&cert).unwrap();
        let r = restore_archived(&srv.client(), "", "m1", &mut cert, &v);
        assert!(
            format!("{:#}", r.as_ref().unwrap_err()).contains("not the bytes the cert names"),
            "{n}: {r:?}"
        );
        if n == "workspace.tar.gz" {
            assert!(
                !e.home.join("workspace/claude-env/README.md").exists(),
                "swapped workspace moved into place"
            );
        }
    }
    // a manifest whose hash isn't the cert's: refused before anything is fetched
    let e = TestEnv::new();
    let key = e.machine_key();
    let (files, order) = j1_files(&e.home);
    let (srv, mb, _) = import_router(&key.sig.public_key(), &files, &order, Files::new());
    let mut cert = restore_cert("j1abc", &"a".repeat(64));
    let v = vouch(&cert).unwrap();
    let r = restore_archived(&srv.client(), "", "m1", &mut cert, &v);
    assert!(
        format!("{:#}", r.as_ref().unwrap_err()).contains("isn't the one the cert names"),
        "{r:?}"
    );
    // a manifest for another Jarvis 1 session than the cert names is not an import (and not a signed snapshot)
    let mut cert = restore_cert("other", &sha256_hex(&mb));
    let v = vouch(&cert).unwrap();
    assert!(
        restore_archived(&srv.client(), "", "m1", &mut cert, &v).is_err(),
        "imported a manifest naming another session"
    );
}

#[test]
fn j1_fix_url_and_remotes() {
    let e = TestEnv::new();
    for (inp, want) in [
        (
            "https://x-access-token:ghp_abc@github.com/DE0CH/claude-env.git",
            "https://github.com/DE0CH/claude-env.git",
        ),
        (
            "https://github.com/de0ch/claude-env",
            "https://github.com/de0ch/claude-env.git",
        ),
        (
            "https://github.com/DE0CH/YCC.git",
            "https://github.com/DE0CH/YCC.git",
        ),
        ("git@github.com:DE0CH/x.git", "git@github.com:DE0CH/x.git"),
        ("https://gitlab.com/a/b", "https://gitlab.com/a/b"),
    ] {
        assert_eq!(j1_fix_url(inp), want, "{inp}");
    }
    let ws = e.root.join("ws");
    let repo = ws.join("r");
    let git = |args: &[&str]| {
        let mut c = std::process::Command::new("git");
        c.args(args);
        crate::env::apply(&mut c);
        c.output().unwrap()
    };
    git(&["init", "-q", repo.to_str().unwrap()]);
    git(&[
        "-C",
        repo.to_str().unwrap(),
        "remote",
        "add",
        "origin",
        "https://u:secret@github.com/DE0CH/r",
    ]);
    j1_fix_remotes(&ws);
    let out = git(&["-C", repo.to_str().unwrap(), "remote", "get-url", "origin"]);
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "https://github.com/DE0CH/r.git"
    );
}

#[test]
fn j1_schedule_keeps_future_times() {
    let now: i64 = 1_791_684_000_000;
    let at = now + 3 * 3_600_000;
    let next = now + 10 * 3_600_000;
    let rec = format!(
        r#"{{"metadata":{{"wake_a":"{{\"name\":\"a\",\"at\":{at},\"prompt\":\"p\"}}","cron_c":"{{\"name\":\"c\",\"prompt\":\"q\",\"every\":86400,\"nextAt\":{next},\"until\":{}}}","cron_d":"{{\"name\":\"d\",\"prompt\":\"q\",\"every\":3600,\"nextAt\":{next}}}"}}}}"#,
        now - 3_600_000
    );
    let (arms, notes) = j1_schedule(rec.as_bytes(), "s1", now);
    assert_eq!(arms.len(), 2, "{arms:?}");
    assert!(
        arms[0].body["name"] == "d"
            && arms[0].body["at"] == next
            && arms[0].body.get("until").is_none()
            && arms[1].body["at"] == at,
        "{arms:?}"
    );
    assert!(
        notes.len() == 1 && notes[0].contains(r#"cron "c": ended"#),
        "{notes:?}"
    );
}

#[test]
fn a_successor_with_no_snapshot_imports_again() {
    let e = TestEnv::new();
    let key = e.machine_key();
    let (files, order) = j1_files(&e.home);
    let (srv, mb, _) = import_router(&key.sig.public_key(), &files, &order, Files::new());
    let c = srv.client();
    let mut cert = restore_cert("j1abc", &sha256_hex(&mb));
    cert.pred_id = "m0".into();
    reimport_jarvis1(&c, &vouch(&cert).unwrap()).unwrap();
    assert_eq!(
        std::fs::read_to_string(e.home.join("workspace/claude-env/README.md")).unwrap(),
        "readme",
        "not imported again"
    );
    let bad = restore_cert("j1abc", &"c".repeat(64));
    assert!(
        reimport_jarvis1(&c, &vouch(&bad).unwrap()).is_err(),
        "took a manifest the cert doesn't name"
    );
}

/// the import's staging dir and the volume-backed state dirs are different filesystems: a move copies across
#[test]
fn move_across_filesystems() {
    let e = TestEnv::new();
    let other = Path::new("/dev/shm").join(format!("j2move-{}", rand::random::<u32>()));
    if std::fs::create_dir_all(&other).is_err() {
        return; // no /dev/shm
    }
    let src = e.root.join("d");
    std::fs::create_dir_all(src.join("sub")).unwrap();
    std::fs::write(src.join("sub/f"), "x").unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(src.join("sub/f"), std::fs::Permissions::from_mode(0o640)).unwrap();
    let dst = other.join("d");
    move_across(&src, &dst).unwrap();
    assert_eq!(std::fs::read_to_string(dst.join("sub/f")).unwrap(), "x");
    assert_eq!(
        std::fs::metadata(dst.join("sub/f"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o640,
        "mode not kept"
    );
    assert!(!src.exists(), "the source stayed");
    let _ = std::fs::remove_dir_all(&other);
}
