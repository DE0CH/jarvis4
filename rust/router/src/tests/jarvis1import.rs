//! jarvis1import_test.go
use crate::inbox::{Caller, Origin};
use crate::jarvis1import::{
    J1_MANIFEST_FILE, J1_PAUSED_ROOT, J1ImportIn, J1ImportManifest, J1Prep, j1_doc, j1_forget,
    j1_prep,
};
use crate::nethttp::{Handler, Req, W};
use crate::storagebox::StorageBox;
use crate::testutil::*;
use serde_json::{Map, Value, json};
use sha2::Digest;
use std::collections::BTreeMap;

const J1_TEST_ID: &str = "j1abcdef012345";
const J1_TEST_UUID: &str = "0fa81372-5d1c-49af-b680-25a842f5df96";

/// a paused Jarvis 1 session's file on the (in-memory) Storage Box
fn j1_put(rg: &Rig, name: &str, body: &[u8]) {
    let b = rg.box_().unwrap_or_else(|| panic!("no box"));
    b.mkcols(&format!("{J1_PAUSED_ROOT}/{J1_TEST_ID}"))
        .unwrap_or_else(|e| panic!("{e:#}"));
    b.put_bytes(&format!("{J1_PAUSED_ROOT}/{J1_TEST_ID}/{name}"), body)
        .unwrap_or_else(|e| panic!("{e:#}"));
}

fn j1_snapshot(rg: &Rig) -> BTreeMap<String, Vec<u8>> {
    let session = format!(
        r#"{{"id":"{J1_TEST_ID}","title":"OWCS ticket cron","label":"","model":"claude-opus-5-5","size":"xlarge","harness":"claude","permissionMode":"auto","autoPause":"on","repos":"https://github.com/de0ch/claude-env.git https://github.com/DE0CH/YCC.git","pausedAt":"2026-10-12T13:50:30.612Z","metadata":{{"cron_owcs":"{{\"name\":\"owcs\",\"prompt\":\"check\",\"every\":86400,\"nextAt\":1}}"}}}}"#
    );
    let files: BTreeMap<String, Vec<u8>> = [
        ("session.json".to_string(), session.into_bytes()),
        (
            "manifest.txt".to_string(),
            format!("{J1_TEST_UUID}.jsonl\n").into_bytes(),
        ),
        (
            format!("{J1_TEST_UUID}.jsonl"),
            b"{\"type\":\"user\"}\n".to_vec(),
        ),
        (
            "claude.json".to_string(),
            br#"{"machineID":"abc"}"#.to_vec(),
        ),
        (
            "workspace.tar.gz".to_string(),
            make_tar(&[tfile(
                "workspace/claude-env/README.md",
                "hi",
                crate::util::unix_now(),
            )]),
        ),
        ("changes.txt".to_string(), b"claude-env 0 0\n".to_vec()), // not taken
        ("artifacts-manifest.txt".to_string(), b"x\n".to_vec()),   // not taken
    ]
    .into_iter()
    .collect();
    for (n, b) in &files {
        j1_put(rg, n, b);
    }
    files
}

fn wait_prepared() -> J1Prep {
    wait_for("the prepare", || {
        j1_prep(J1_TEST_ID).is_some_and(|x| x.state != "preparing")
    });
    j1_prep(J1_TEST_ID).unwrap_or_default()
}

fn hex_sum(b: &[u8]) -> String {
    hex::encode(sha2::Sha256::digest(b))
}

/// a GET signed as the machine signs it, its raw answer
fn raw_get(h: &Handler, m: &TestMachine, path: &str) -> (u16, Vec<u8>) {
    let (ts, sig) = signed_headers(&m.key, "GET", path, b"", crate::util::unix_now());
    let mut req = Req::new("GET", path, b"")
        .with_header("X-Machine", &m.id)
        .with_header("X-Time", &ts)
        .with_header("X-Sig", &sig);
    let mut w = W::recorder();
    h(&mut w, &mut req);
    (w.status(), w.recorded.clone().unwrap_or_default())
}

struct Forget;

impl Drop for Forget {
    fn drop(&mut self) {
        j1_forget(J1_TEST_ID);
    }
}

#[test]
fn jarvis1_import_prepare_and_import() {
    let _g = serial(); // the prepares are kept by id, the test's id is every test's
    let _f = Forget;
    j1_forget(J1_TEST_ID);
    let rg = Rig::new();
    let files = j1_snapshot(&rg);
    // an import nobody prepared prepares it first (rather than refusing)
    rg.ensure_prepared_jarvis1(J1_TEST_ID)
        .unwrap_or_else(|e| panic!("an import's own prepare: {e:#}"));
    rg.prepared_jarvis1(J1_TEST_ID)
        .unwrap_or_else(|e| panic!("not prepared by the import: {e:#}"));
    assert!(rg.prepare_jarvis1("../etc").is_err(), "prepared a bad id");
    rg.prepare_jarvis1(J1_TEST_ID)
        .unwrap_or_else(|e| panic!("{e:#}"));
    let p = wait_prepared();
    assert!(p.state == "ready" && !p.sha256.is_empty(), "prepare {p:?}");
    let (mb, sum, rec) = rg
        .prepared_jarvis1(J1_TEST_ID)
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert!(
        sum == p.sha256 && rec.title == "OWCS ticket cron",
        "{sum} {rec:?}"
    );
    let man: J1ImportManifest =
        serde_json::from_slice(&mb).unwrap_or_else(|e| panic!("manifest: {e}"));
    assert!(
        man.kind == "jarvis1-import" && man.session == J1_TEST_ID,
        "manifest {man:?}"
    );
    let mf = man.files.clone().unwrap_or_default();
    let got: BTreeMap<String, _> = mf.iter().map(|f| (f.name.clone(), f.clone())).collect();
    for n in [
        "session.json",
        "manifest.txt",
        &format!("{J1_TEST_UUID}.jsonl"),
        "claude.json",
        "workspace.tar.gz",
    ] {
        let f = &got[n];
        let want = &files[n];
        assert!(
            f.sha256 == hex_sum(want) && f.size == i64::try_from(want.len()).unwrap_or(-1),
            "{n}: {f:?}"
        );
    }
    assert!(
        !got.contains_key("changes.txt") && got.len() == 5,
        "took files it shouldn't: {:?}",
        got.keys()
    );
    assert!(
        mf.first().is_some_and(|f| f.name == "session.json")
            && mf.last().is_some_and(|f| f.name == "workspace.tar.gz"),
        "order {mf:?}"
    );

    // the import: a new session waiting for the phone, its cert's restore naming the manifest's hash
    let o = Origin {
        caller: Caller {
            kind: "setup".into(),
            ..Default::default()
        },
        ..Default::default()
    };
    let sid = rg
        .import_jarvis1(
            J1_TEST_ID,
            J1ImportIn {
                stores: vec!["default".into()],
                explanation: "move it".into(),
                ..Default::default()
            },
            o.clone(),
        )
        .unwrap_or_else(|e| panic!("{e:#}"));
    let find = || {
        rg.st
            .read(|d| d.approvals.values().find(|a| a.session == sid).cloned())
    };
    wait_for("the approval", || find().is_some());
    let appr = find().unwrap_or_default();
    let s = rg.session(&sid);
    assert!(
        s.state == "approval"
            && s.import_from == J1_TEST_ID
            && s.import_sha == sum
            && s.label == "OWCS ticket cron"
            && s.size == "large"
            && s.permission_mode == "bypass" // Jarvis 1 ran it in auto: bypass is the only start mode
            && s.model == "claude-opus-5-5"
            && s.repos == "https://github.com/de0ch/claude-env.git,https://github.com/DE0CH/YCC.git"
            && s.stores.as_ref().map(|x| x.join(",")).as_deref() == Some("default,tunnel")
            && s.live.as_ref().is_some_and(|l| !l.auto_pause_off),
        "session {s:?}"
    );
    assert!(
        s.prompt.contains("moved from Jarvis 1 to Jarvis 4") && s.prompt.contains(J1_TEST_ID),
        "prompt {:?}",
        s.prompt
    );
    let restore = appr.options.get("restore").cloned().unwrap_or_default();
    assert!(
        appr.kind == "new-session"
            && restore.starts_with(&format!(
                "Jarvis 1 session “OWCS ticket cron” ({J1_TEST_ID}, paused 2026-10-12)"
            ))
            && appr.explanation == "move it"
            && appr
                .origin
                .as_ref()
                .is_some_and(|o| o.caller.kind == "setup"),
        "approval {appr:?}"
    );
    let config = rg.session_config(&s).unwrap_or_else(|e| panic!("{e:#}"));
    let c: Value = serde_json::from_str(&config).unwrap_or_default();
    assert!(
        c["restore"]["machine"] == J1_TEST_ID
            && c["restore"]["sha256"] == sum.as_str()
            && c["label"] == "OWCS ticket cron"
            && c["prompt"] == s.prompt.as_str(),
        "config {config}"
    );
    // the same import again answers the same session
    let again = rg.import_jarvis1(
        J1_TEST_ID,
        J1ImportIn {
            stores: vec!["default".into()],
            ..Default::default()
        },
        o,
    );
    assert!(again.as_deref().is_ok_and(|a| a == sid), "again: {again:?}");

    // only the line's first machine gets the manifest and the files, and only the manifest's files
    let m = new_test_machine(&rg, "m9");
    let h = rg.machine_handler();
    let set_cert = |v: Value| {
        let d = rg.core.key.doc(&v);
        rg.st.do_(|p| {
            p.certs.insert("m9".into(), d.clone());
        });
    };
    rg.st.do_(|d| {
        d.machines.insert("m9".into(), sid.clone());
        if let Some(x) = d.sessions.get_mut(&sid) {
            x.machine_id = "m9".into();
        }
    });
    set_cert(json!({"kind": "succession-cert", "predecessorId": ""}));
    let (code, b) = raw_get(&h, &m, "/m/restore-snapshot");
    assert!(
        code == 200 && b == mb,
        "manifest: {code} {}",
        String::from_utf8_lossy(&b)
    );
    let (code, b) = raw_get(&h, &m, "/m/import-file/workspace.tar.gz");
    assert!(
        code == 200 && b == files["workspace.tar.gz"],
        "file: {code} {} bytes",
        b.len()
    );
    assert_eq!(
        raw_get(&h, &m, "/m/import-file/changes.txt").0,
        404,
        "a file outside the manifest"
    );
    // a successor whose predecessor left no snapshot takes the import again; one with a snapshot doesn't
    set_cert(json!({"kind": "succession-cert", "predecessorId": "m8"}));
    assert_eq!(
        raw_get(&h, &m, "/m/restore-snapshot").0,
        200,
        "a successor with no snapshot can't take the import again"
    );
    set_cert(json!({"kind": "succession-cert", "predecessorId": "m8", "snapshot": "b".repeat(64)}));
    assert_eq!(
        raw_get(&h, &m, "/m/import-file/workspace.tar.gz").0,
        404,
        "a successor fetched an import file"
    );
    assert_ne!(
        raw_get(&h, &m, "/m/restore-snapshot").0,
        200,
        "a successor fetched the import manifest"
    );

    // once it came up, the import notes the session
    rg.st.do_(|d| {
        if let Some(x) = d.sessions.get_mut(&sid) {
            x.booted = "m9".into();
        }
    });
    rg.tidy_imports();
    let mut v = Map::new();
    rg.j1_status(J1_TEST_ID, &mut v);
    assert_eq!(
        v.get("imported").map(|i| i["session"].clone()),
        Some(json!(sid)),
        "status {v:?}"
    );
}

#[test]
fn jarvis1_import_refuses_an_incomplete_snapshot() {
    let _g = serial();
    let _f = Forget;
    j1_forget(J1_TEST_ID);
    let rg = Rig::new();
    j1_put(
        &rg,
        "session.json",
        format!(r#"{{"id":"{J1_TEST_ID}"}}"#).as_bytes(),
    );
    j1_put(&rg, "workspace.tar.gz", b"x");
    rg.prepare_jarvis1(J1_TEST_ID)
        .unwrap_or_else(|e| panic!("{e:#}"));
    let p = wait_prepared();
    assert!(
        p.state == "failed" && p.error.contains("manifest.txt"),
        "{p:?}"
    );
    assert!(
        rg.st
            .read_doc(&j1_doc(J1_TEST_ID, J1_MANIFEST_FILE))
            .is_none(),
        "a manifest was written"
    );
}

#[test]
fn snapshot_upload_streams_and_checks_the_signature() {
    let t = new_test_router();
    let r = t.r.clone();
    add_session(&r, "sA", "started", "mA", false);
    let m = new_test_machine(&r, "mA");
    let h = t.machine_handler();
    let body = "snapshot bytes ".repeat(1000);
    let req = |signed: &str| {
        let (ts, sig) = signed_headers(
            &m.key,
            "POST",
            "/m/snapshot",
            signed.as_bytes(),
            crate::util::unix_now(),
        );
        let mut q = Req::new("POST", "/m/snapshot", body.as_bytes())
            .with_header("X-Machine", "mA")
            .with_header("X-Time", &ts)
            .with_header("X-Sig", &sig)
            .with_header("X-Snapshot-Sig", "snapsig");
        let mut w = W::recorder();
        h(&mut w, &mut q);
        (w.status(), w.body_text())
    };
    // a signature over other bytes: refused, nothing kept
    let (code, out) = req("other bytes");
    assert_eq!(code, 401, "{out}");
    assert!(
        r.snap("mA").is_none(),
        "a snapshot with a bad signature was kept"
    );
    let tmp = std::path::Path::new(&r.cfg.data_dir).join("tmp");
    for e in std::fs::read_dir(&tmp).into_iter().flatten().flatten() {
        let n = e.file_name().to_string_lossy().into_owned();
        assert!(!n.starts_with(".upload-"), "temp file left: {n}");
    }
    let (code, out) = req(&body);
    assert_eq!(code, 200, "{out}");
    assert_eq!(
        snap_bytes(&r, "mA").as_deref(),
        Some(body.as_bytes()),
        "stored snapshot differs"
    );
    let s = r.snap("mA");
    assert!(s.as_ref().is_some_and(|s| s.sig == "snapsig"), "{s:?}");
    // an unknown machine: refused before a byte is read
    let mut q = Req::new("POST", "/m/snapshot", body.as_bytes())
        .with_header("X-Machine", "nobody")
        .with_header("X-Time", &crate::util::unix_now().to_string());
    let mut w = W::recorder();
    h(&mut w, &mut q);
    assert_eq!(w.status(), 401, "unknown machine");
}

/// Apache redirects a collection asked for without its trailing slash; a client would follow the 301 as a GET
#[test]
fn propfind_keeps_the_directory_slash() {
    let got: std::sync::Arc<std::sync::Mutex<Vec<String>>> = Default::default();
    let g2 = got.clone();
    let srv = TestServer::handler(move |w, req| {
        g2.lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(format!("{} {}", req.method, req.path));
        if !req.path.ends_with('/') {
            w.set_header("Location", &format!("{}/", req.path));
            w.write_header(301);
            return;
        }
        w.write_header(207);
        w.write_str(r#"<?xml version="1.0"?><D:multistatus xmlns:D="DAV:"><D:response><D:href>/a/b/</D:href><D:propstat><D:prop><D:resourcetype><D:collection/></D:resourcetype></D:prop></D:propstat></D:response><D:response><D:href>/a/b/f.txt</D:href><D:propstat><D:prop><D:resourcetype/><D:getcontentlength>3</D:getcontentlength></D:prop></D:propstat></D:response></D:multistatus>"#);
    });
    let ls = StorageBox::new(&srv.url, "u", "p").list("a/b");
    let calls = got.lock().unwrap_or_else(|e| e.into_inner()).clone();
    assert!(
        ls.as_ref()
            .is_ok_and(|l| l.as_ref().and_then(|m| m.get("f.txt")) == Some(&3))
            && calls == ["PROPFIND /a/b/"],
        "{ls:?} {calls:?}"
    );
}
