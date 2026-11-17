//! restore_test.go: archived restores, the snapshot's signature, unpacking, the harnesses' state in the snapshot, core
//! continuity.

use super::testutil::*;
use super::vouch::tarball;
use crate::cert::{Cert, Machine};
use crate::client::Client;
use crate::crypto::sha256_hex;
use crate::restore::*;
use crate::snapshot::{make_snapshot, unpack_file, unpack_reader};
use crate::vouch::{RestoreRef, SessionConfig, Vouched};

fn old_cert(other: &Tkey) -> Cert {
    Cert {
        kind: "succession-cert".into(),
        machine: Some(Machine {
            id: "old".into(),
            signing_key: other.public(),
            ..Default::default()
        }),
        line: "old".into(),
        ..Default::default()
    }
}

#[test]
fn check_restore_cert_rules() {
    let (core, other) = (new_key(), new_key());
    let old = old_cert(&other);
    let plain = Cert::default();
    check_restore_cert(&core.public(), "new", &plain, Some(&core.doc(&old))).unwrap();
    assert!(
        check_restore_cert(&core.public(), "new", &plain, Some(&other.doc(&old))).is_err(),
        "accepted a cert the core didn't sign"
    );
    assert!(
        check_restore_cert(&core.public(), "old", &plain, Some(&core.doc(&old))).is_err(),
        "accepted a cert naming this machine"
    );
    let mut not_cert = old.clone();
    not_cert.kind = "burn-cert".into();
    assert!(
        check_restore_cert(&core.public(), "new", &plain, Some(&core.doc(&not_cert))).is_err(),
        "accepted another kind of document"
    );
    let mut sens = old.clone();
    sens.sensitive = true;
    assert!(
        check_restore_cert(&core.public(), "new", &plain, Some(&core.doc(&sens))).is_err(),
        "a sensitive line's snapshot went into a line without one"
    );
    let sensitive = Cert {
        sensitive: true,
        ..Default::default()
    };
    check_restore_cert(&core.public(), "new", &sensitive, Some(&core.doc(&sens))).unwrap();
}

#[test]
fn snapshot_sig_and_unpack() {
    let e = TestEnv::new();
    let m = new_key();
    let body = tarball("artifacts/x.txt", "hi");
    let sig = m.0.sign(sha256_hex(&body).as_bytes());
    check_snapshot_sig(&m.public(), &body, &sig).unwrap();
    assert!(
        check_snapshot_sig(&new_key().public(), &body, &sig).is_err(),
        "another key's signature passed"
    );
    assert_eq!(unpack_reader(&body[..]).unwrap(), 1);
    assert_eq!(
        std::fs::read_to_string(e.home.join("artifacts/x.txt")).unwrap(),
        "hi"
    );
    // a bad path is refused (written by hand: the tar crate refuses to write one)
    let mut h = tar::Header::new_ustar();
    h.as_old_mut().name[..7].copy_from_slice(b"../evil");
    h.set_mode(0o644);
    h.set_size(0);
    h.set_entry_type(tar::EntryType::Regular);
    h.set_cksum();
    let mut raw = h.as_bytes().to_vec();
    raw.extend_from_slice(&[0u8; 1024]);
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    std::io::Write::write_all(&mut gz, &raw).unwrap();
    let bad = gz.finish().unwrap();
    let r = unpack_reader(&bad[..]);
    assert!(
        format!("{:#}", r.as_ref().unwrap_err()).contains("bad path"),
        "{r:?}"
    );
}

#[test]
fn restore_archived_only_when_the_cert_names_it() {
    let _e = TestEnv::new();
    crate::env::set("JARVIS2_RESTORE_CERT", Some("{}")); // the env asking: ignored
    let c = Client::with_url("http://127.0.0.1:1", "me");
    restore_archived(&c, "", "me", &mut Cert::default(), &Vouched::default()).unwrap();
    let r = RestoreRef {
        machine: "old".into(),
        sha256: "a".repeat(64),
    };
    let v = Vouched {
        config: SessionConfig {
            restore: Some(r),
            ..Default::default()
        },
        ..Default::default()
    };
    let mut succ = Cert {
        pred_id: "pred".into(),
        ..Default::default()
    };
    restore_archived(&c, "", "me", &mut succ, &v).expect("a successor acted on a restore");
}

/// The harnesses' own state travels in the snapshot, so the OpenCode/OpenClaw apps stay paired across a pause; their
/// logs, pid files and caches don't.
#[test]
fn snapshot_carries_harness_state() {
    let e = TestEnv::new();
    let files = [
        (".paseo/config.json", true),
        (".paseo/agents/a.json", true),
        (".claude/.paseo-agent", true),
        (".local/share/opencode/storage/session/s.json", true),
        (".openclaw/openclaw.json", true),
        (".openclaw/jarvis-remote.json", true),
        (".openclaw/devices/paired.json", true),
        ("workspace/w.txt", true),
        (".paseo/models/big.bin", false),
        (".paseo/runtime/x", false),
        (".paseo/paseo.pid", false),
        (".paseo/daemon.out", false),
        (".paseo/a.log", false),
        (".local/share/opencode/log/x.log", false),
        (".local/share/opencode/bin/rg", false),
        (".openclaw/logs/l", false),
        (".openclaw/tmp/t", false),
        (".openclaw/gateway.out", false),
        (".openclaw/gateway.pid", false),
        (".openclaw/.hold", false),
        (".config/other/x", false),
    ];
    for (p, _) in &files {
        let f = e.home.join(p);
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(&f, p).unwrap();
    }
    let snap = e.root.join("s.tar.gz");
    make_snapshot(&snap).unwrap();
    let next = e.root.join("next");
    std::fs::create_dir_all(&next).unwrap();
    crate::env::set("HOME", Some(next.to_str().unwrap()));
    unpack_file(&snap).unwrap();
    for (p, kept) in files {
        let b = std::fs::read_to_string(next.join(p));
        if kept {
            assert_eq!(b.as_deref().ok(), Some(p), "{p} not restored");
        } else {
            assert!(b.is_err(), "{p} travelled in the snapshot");
        }
    }
}

/// an archive from an earlier core restores through the master key's claim of that core (core continuity)
#[test]
fn a_restore_from_an_earlier_core_goes_through_the_masters_claim() {
    let (now, earlier, master, other) = (new_key(), new_key(), new_key(), new_key());
    let old = old_cert(&new_key());
    let cert_doc = earlier.doc(&old);
    let state = now.doc(&serde_json::json!({"kind": "core-state", "master": master.public()}));
    let claim = |k: &Tkey, v: serde_json::Value| {
        let b = crate::gojson::marshal(&v);
        CoreCert {
            master_sig: k.0.sign(b.as_bytes()),
            statement: b,
        }
    };
    let mut rc = RestoreCertDocs {
        cert: Some(cert_doc),
        core_state: Some(state.clone()),
        core_cert: Some(claim(
            &master,
            serde_json::json!({"kind": "claim", "master": master.public(), "core": {"signingKey": earlier.public()}}),
        )),
    };
    assert_eq!(
        restore_signer(&now.public(), &rc).unwrap(),
        earlier.public()
    );
    // a seeded claim names the derived key as its identity
    rc.core_cert = Some(claim(
        &master,
        serde_json::json!({"kind": "claim", "master": master.public(), "core": {"signingKey": other.public()}, "identity": {"signingKey": earlier.public()}}),
    ));
    assert_eq!(
        restore_signer(&now.public(), &rc).unwrap(),
        earlier.public(),
        "identity"
    );
    // a claim another key signed, a state another core signed, a claim naming another core: refused
    rc.core_cert = Some(claim(
        &other,
        serde_json::json!({"kind": "claim", "master": master.public(), "core": {"signingKey": earlier.public()}}),
    ));
    assert!(
        restore_signer(&now.public(), &rc).is_err(),
        "a claim the master didn't sign"
    );
    rc.core_cert = Some(claim(
        &master,
        serde_json::json!({"kind": "claim", "master": master.public(), "core": {"signingKey": earlier.public()}}),
    ));
    rc.core_state =
        Some(other.doc(&serde_json::json!({"kind": "core-state", "master": master.public()})));
    assert!(
        restore_signer(&now.public(), &rc).is_err(),
        "a state this machine's core didn't sign"
    );
    rc.core_state = Some(state);
    rc.core_cert = Some(claim(
        &master,
        serde_json::json!({"kind": "claim", "master": master.public(), "core": {"signingKey": other.public()}}),
    ));
    assert!(
        restore_signer(&now.public(), &rc).is_err(),
        "a claim of another core"
    );
    // the running core's own cert needs nothing else
    let own = RestoreCertDocs {
        cert: Some(now.doc(&old)),
        ..Default::default()
    };
    assert_eq!(restore_signer(&now.public(), &own).unwrap(), now.public());
}
