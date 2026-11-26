//! snapstream_test.go: the final snapshot streamed and committed with the machine's one signature.

use super::testutil::*;
use crate::crypto::Keys;
use crate::snapstream::*;
use crate::supervisor::TEST_FREEZE;
use sha2::{Digest, Sha256};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

#[derive(Default)]
pub struct SnapRouter {
    pub pending: String,
    pub commits: Vec<String>,
    pub failed: Vec<String>,
    pub carried: Vec<String>,
    pub no_stream: bool,
    pub stream_fail: bool,
    pub fail_commit: bool,
    pub streamed: usize,
    pub legacy: usize,
}

/// the router's side of rust/router/src/snapstream.rs, checking the machine's signatures (the fake router checks each request's)
pub fn snap_router(key: &Keys) -> (FakeRouter, Arc<Mutex<SnapRouter>>) {
    let st = Arc::new(Mutex::new(SnapRouter::default()));
    let (s2, pk) = (st.clone(), key.sig.public_key());
    let srv = FakeRouter::new(&key.sig.public_key(), move |r| {
        let mut fr = s2.lock().unwrap();
        match r.path.as_str() {
            "/m/snapshot-stream" => {
                if fr.no_stream {
                    return ans(404, "");
                }
                if fr.stream_fail {
                    return ans(507, "");
                }
                fr.pending = hex::encode(Sha256::digest(&r.body));
                fr.streamed += 1;
                ok_json(serde_json::json!({"sha256": fr.pending, "bytes": r.body.len()}))
            }
            "/m/snapshot-commit" | "/m/snapshot-carry" | "/m/snapshot-failed" => {
                let inp: std::collections::BTreeMap<String, String> =
                    serde_json::from_slice(&r.body).unwrap_or_default();
                let g = |k: &str| inp.get(k).cloned().unwrap_or_default();
                match r.path.as_str() {
                    "/m/snapshot-failed" => fr.failed.push(g("error")),
                    "/m/snapshot-carry" => {
                        if !jarvis_sig::verify(&pk, g("sha256").as_bytes(), &g("sig")) {
                            return ans(403, "");
                        }
                        fr.carried.push(g("sha256"));
                    }
                    _ => {
                        if fr.fail_commit {
                            fr.fail_commit = false;
                            return ans(500, "");
                        }
                        if !jarvis_sig::verify(&pk, g("sha256").as_bytes(), &g("sig"))
                            || (g("sha256") != fr.pending && fr.commits.is_empty())
                        {
                            return ans(409, "");
                        }
                        fr.commits.push(format!("{} {}", g("sha256"), g("sig")));
                    }
                }
                ans(200, r#"{"ok":true}"#)
            }
            "/m/snapshot" => {
                fr.legacy += 1;
                ans(200, r#"{"ok":true}"#)
            }
            _ => ans(404, ""),
        }
    });
    (srv, st)
}

fn reset_signed() {
    *SIGNED.lock().unwrap() = Default::default();
}

/// the final snapshot needs no free disk: it streams into the request, and nothing but the tiny signature lands on the
/// machine's disk (2026-10-15: "no space left on device" lost a session)
#[test]
fn the_final_snapshot_streams_without_a_local_copy() {
    let e = TestEnv::new();
    let key = e.machine_key();
    *TEST_FREEZE.lock().unwrap() = Some((0, 0));
    let (srv, fr) = snap_router(&key);
    let c = srv.client();
    std::fs::create_dir_all(e.home.join("workspace")).unwrap();
    std::fs::write(e.home.join("workspace/big"), "x".repeat(1 << 20)).unwrap();
    upload_snapshot(&c).unwrap();
    assert!(
        !crate::paths::final_snapshot().exists(),
        "a local copy of the snapshot was written"
    );
    {
        let f = fr.lock().unwrap();
        assert!(
            f.streamed == 1
                && f.commits.len() == 1
                && f.commits[0].starts_with(&format!("{} ", f.pending))
                && f.legacy == 0,
            "streamed {}, commits {:?}",
            f.streamed,
            f.commits
        );
    }
    // a commit that didn't reach the router: the frozen files are streamed again and committed under the same signature
    reset_signed();
    let _ = std::fs::remove_file(crate::paths::final_snapshot_sig());
    let _ = std::fs::remove_file(format!(
        "{}.sha256",
        crate::paths::final_snapshot_sig().display()
    ));
    fr.lock().unwrap().fail_commit = true;
    assert!(
        upload_snapshot(&c).is_err(),
        "a failed commit went unnoticed"
    );
    let first = SIGNED.lock().unwrap().sig.clone();
    upload_snapshot(&c).unwrap();
    assert_eq!(SIGNED.lock().unwrap().sig, first, "signed again");
    assert_eq!(fr.lock().unwrap().streamed, 3, "not streamed again");
    // files that changed after the signature: no second signature, the snapshot fails
    SIGNED.lock().unwrap().committed = false;
    std::fs::write(e.home.join("workspace/big"), "changed").unwrap();
    let r = upload_snapshot(&c);
    assert!(
        format!("{:#}", r.as_ref().unwrap_err()).contains("no second"),
        "a second snapshot: {r:?}"
    );
}

/// a router from before streaming gets the old whole-file upload
#[test]
fn an_older_router_gets_the_file_upload() {
    let e = TestEnv::new();
    let key = e.machine_key();
    *TEST_FREEZE.lock().unwrap() = Some((0, 0));
    let (srv, fr) = snap_router(&key);
    fr.lock().unwrap().no_stream = true;
    std::fs::create_dir_all(e.home.join("workspace")).unwrap();
    upload_snapshot(&srv.client()).unwrap();
    assert_eq!(fr.lock().unwrap().legacy, 1, "no whole-file upload");
}

/// a snapshot that can't be taken is reported at once, and with nothing signed the session goes on
#[test]
fn a_failed_snapshot_is_reported_and_thawed() {
    let e = TestEnv::new();
    let key = e.machine_key();
    *TEST_FREEZE.lock().unwrap() = Some((0, 0));
    let (srv, fr) = snap_router(&key);
    fr.lock().unwrap().stream_fail = true;
    let c = srv.client();
    let err = upload_snapshot(&c).expect_err("no error from a router that refuses the stream");
    let thawed = TEST_FREEZE.lock().unwrap().unwrap().1;
    assert!(
        !crate::snapshot::FROZEN.load(Ordering::SeqCst)
            && thawed == 1
            && SIGNED.lock().unwrap().sum.is_empty()
    );
    report_snapshot_failed(&c, &err);
    assert_eq!(fr.lock().unwrap().failed.len(), 1, "not reported");
}

/// asked while booting, a successor's state is its predecessor's snapshot: it carries that one over (signed once) and
/// the boot stops; the line's first machine still has nothing to snapshot
#[test]
fn a_booting_machine_carries_its_predecessors_snapshot() {
    let e = TestEnv::new();
    let key = e.machine_key();
    let core = new_key();
    let cert_file = e.root.join("cert.json");
    *TEST_CERT_FILE.lock().unwrap() = Some(cert_file.clone());
    let (srv, fr) = snap_router(&key);
    let c1 = srv.client(); // machine m1, a successor of m0
    let sum = "cd".repeat(32);
    let doc = core.doc(&serde_json::json!({"kind": "succession-cert", "predecessorId": "m0", "snapshot": sum, "machine": {"id": "m1"}}));
    std::fs::write(&cert_file, crate::gojson::marshal(&doc)).unwrap();
    booting_snapshot(&c1).unwrap();
    let f = fr.lock().unwrap();
    assert!(
        f.carried.len() == 1 && f.carried[0] == sum && SIGNED.lock().unwrap().sum == sum,
        "carried {:?}",
        f.carried
    );
    assert!(crate::paths::carried_run().exists(), "the boot would go on");
}
