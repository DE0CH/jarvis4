//! kernelboot_test.go, on documents the Go kernel's test harness made (rust/machine/tests/vectors/kernelboot.json,
//! written before the kernel's cut, 2026-11-26).

use super::testutil::*;
use crate::crypto::SignedDoc;
use crate::kernelboot::*;
use jarvis_sig::{Component, Doc, Identity, Roster, Signer, Trust};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Deserialize, Clone)]
struct Line {
    docs: serde_json::Value,
    id: String,
    source: String,
    keys: HashMap<String, String>,
}

impl Line {
    fn docs(&self) -> KernelBootDocs {
        crate::gojson::unmarshal(self.docs.to_string().as_bytes()).unwrap()
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Vectors {
    root: String,
    phone: String,
    blue: Doc,
    a: Line,
    b: Line,
    input: Doc,
    cert: Doc,
    other_root: String,
    other_roster: Doc,
    green: Doc,
    green_ids: HashMap<String, Identity>,
    green_input: Doc,
}

fn vectors() -> Vectors {
    serde_json::from_str(include_str!("../../tests/vectors/kernelboot.json")).unwrap()
}

fn trust(root: &str, roster: &Doc) -> Trust {
    let t = Trust::new(root);
    t.set(roster.clone(), None).unwrap();
    t
}

fn sd(d: &Doc) -> SignedDoc {
    d.clone().into()
}

fn loose(id: &Identity) -> LooseIdentity {
    crate::gojson::unmarshal(jarvis_sig::go_json(id).unwrap().as_bytes()).unwrap()
}

/// the documents a kernel machine boots from check, and give the settings, stores and session the source names
#[test]
fn a_kernel_machine_reads_its_documents() {
    let _e = TestEnv::new();
    let v = vectors();
    let (cert, kt) = check_kernel_boot(
        &v.a.docs(),
        &trust(&v.root, &v.blue),
        &v.a.source,
        &v.a.id,
        &v.a.keys,
    )
    .unwrap();
    assert!(
        cert.options.harness == "claude"
            && cert.options.permission_mode == "auto"
            && cert.options.config.contains(r#""label":"x""#)
            && cert.stores() == ["default", "tunnel"]
            && cert.line == "s1"
            && cert.pred_id.is_empty()
            && cert.snapshot.is_empty(),
        "{cert:?}"
    );
    let vc = crate::vouch::vouch(&cert).unwrap();
    assert!(
        vc.config.label == "x" && vc.config.model == "claude-opus-5-5",
        "{:?}",
        vc.config
    );
    // no store secrets lists: counted sensitive
    assert!(
        cert.phone == v.phone && cert.sensitive,
        "phone {:?} sensitive {}",
        cert.phone,
        cert.sensitive
    );
    assert!(
        kt.machine == format!("fly-{}", v.a.id) && kt.root == v.root,
        "{kt:?}"
    );
}

/// ✱ what a router could hand a kernel machine instead: another machine's documents, another source, another roster,
/// a grant from elsewhere, a cert not notarized
#[test]
fn a_kernel_machine_refuses_other_documents() {
    let _e = TestEnv::new();
    let v = vectors();
    let (b, b2) = (v.a.docs(), v.b.docs());
    let bx = trust(&v.root, &v.blue);
    let (src, keys) = (&v.a.source, &v.a.keys);
    let refuse = |name: &str,
                  d: &KernelBootDocs,
                  bx: &Trust,
                  src: &str,
                  me: &str,
                  keys: &HashMap<String, String>| {
        assert!(
            check_kernel_boot(d, bx, src, me, keys).is_err(),
            "{name}: accepted"
        );
    };
    refuse("another machine's documents", &b2, &bx, src, &v.a.id, keys);
    refuse("another source", &b, &bx, &v.b.source, &v.a.id, keys);
    refuse(
        "another roster",
        &b,
        &trust(&v.other_root, &v.other_roster),
        src,
        &v.a.id,
        keys,
    );
    assert!(
        Trust::new(&v.root)
            .set(v.other_roster.clone(), None)
            .is_err(),
        "a roster another key signed, taken as the root key's"
    );
    refuse("other keys", &b, &bx, src, &v.a.id, &v.b.keys);
    let mut x = b.clone();
    x.grant = b2.grant.clone();
    refuse("another machine's grant", &x, &bx, src, &v.a.id, keys);
    let mut x = b.clone();
    x.machine_notarized = b2.machine_notarized.clone();
    refuse(
        "a notarization of another cert",
        &x,
        &bx,
        src,
        &v.a.id,
        keys,
    );
    let mut x = b.clone();
    (x.source_cert, x.source_notarized) = (b2.source_cert.clone(), b2.source_notarized.clone());
    refuse("another source's cert", &x, &bx, src, &v.a.id, keys);
    let mut x = b.clone();
    x.grant.signer = Some(loose(&Component::new("mover").identity));
    refuse(
        "a mover the roster doesn't name",
        &x,
        &bx,
        src,
        &v.a.id,
        keys,
    );
    check_kernel_boot(&b, &bx, src, &v.a.id, keys).unwrap();
}

/// the clean env keeps a kernel machine's root key, roster and source, and refuses a machine with neither
#[test]
fn clean_env_keeps_the_kernels_keys() {
    let key = format!("{}=", "A".repeat(87));
    let s = |v: &[String]| v.to_vec();
    let env = crate::vouch::clean_env(
        &s(&[
            format!("JARVIS2_KERNEL_ROOT={key}"),
            r#"JARVIS2_KERNEL_ROSTER={"payload":"{}","sig":"x"}"#.into(),
            format!("JARVIS2_SOURCE=source-{}", "ab".repeat(16)),
            "EVIL=1".into(),
        ]),
        &[],
    )
    .unwrap()
    .join("\n");
    assert!(
        env.contains("JARVIS2_SOURCE=source-") && !env.contains("EVIL"),
        "{env}"
    );
    let r = crate::vouch::clean_env(
        &s(&[
            format!("JARVIS2_KERNEL_ROOT={key}"),
            "JARVIS2_KERNEL_ROSTER={}".into(),
            "JARVIS2_SOURCE=nope".into(),
        ]),
        &[],
    );
    assert!(r.is_err(), "a bad source accepted");
}

/// a delivered input is the log notary's challenge over (this machine, its kind, its hash); ✱ another machine's,
/// another kind, other bytes, not about an input, another notary
#[test]
fn a_kernel_machine_checks_the_notarys_log() {
    let _e = TestEnv::new();
    let v = vectors();
    let (_, t) = check_kernel_boot(
        &v.a.docs(),
        &trust(&v.root, &v.blue),
        &v.a.source,
        &v.a.id,
        &v.a.keys,
    )
    .unwrap();
    let (body, d) = (b"wake up".as_slice(), sd(&v.input));
    check_kernel_attest(&t, &v.a.id, "wakeup", body, Some(&d)).unwrap();
    let mut t2 = t.clone();
    t2.notary = t.secrets.clone();
    for (name, r) in [
        (
            "another machine",
            check_kernel_attest(&t, "00000000000001", "wakeup", body, Some(&d)),
        ),
        (
            "another kind",
            check_kernel_attest(&t, &v.a.id, "cron", body, Some(&d)),
        ),
        (
            "other bytes",
            check_kernel_attest(&t, &v.a.id, "wakeup", b"rm -rf", Some(&d)),
        ),
        (
            "not an input",
            check_kernel_attest(&t, &v.a.id, "wakeup", body, Some(&sd(&v.cert))),
        ),
        (
            "another notary",
            check_kernel_attest(&t2, &v.a.id, "wakeup", body, Some(&d)),
        ),
        (
            "no challenge",
            check_kernel_attest(&t, &v.a.id, "wakeup", body, None),
        ),
    ] {
        assert!(r.is_err(), "{name}: accepted");
    }
}

/// a copy flip under a live machine: its documents from before the flip (the grant, the spawner's cert and the
/// notarizations, all signed by the blue copy) check against the green copy's roster the router now serves (it retires
/// blue's members), with green's identities; an input green's notary logged makes the machine read its documents again
/// and then checks; ✱ a roster the root key didn't sign is refused
#[test]
fn a_kernel_machine_after_a_copy_flip() {
    let _e = TestEnv::new();
    let v = vectors();
    let (src, keys) = (&v.a.source, &v.a.keys);
    let mut b = v.a.docs();
    let (_, before) = check_kernel_boot(&b, &trust(&v.root, &v.blue), src, &v.a.id, keys).unwrap();
    b.roster = Some(sd(&v.green));
    let id = |r: &str| loose(&v.green_ids[r]);
    (b.notary, b.notarizer, b.mover, b.merger, b.spawner) = (
        id("notary"),
        id("notarizer"),
        id("mover"),
        id("merger"),
        id("spawner"),
    );
    crate::env::set(KERNEL_ROOT_ENV, Some(&v.root));
    let bx = kernel_trust_for(&b).unwrap();
    let (_, after) = check_kernel_boot(&b, &bx, src, &v.a.id, keys)
        .expect("the blue documents under the green roster");
    assert!(
        after.notary != before.notary && after.secrets == before.secrets,
        "the notary is green's, secrets the same keys"
    );
    let (body, d) = (b"wake up".as_slice(), sd(&v.green_input));
    assert!(
        check_kernel_attest(&before, &v.a.id, "wakeup", body, Some(&d)).is_err(),
        "green's notary passed with blue's trust and no way to read the documents again"
    );
    let reads = Arc::new(AtomicUsize::new(0));
    let (r2, a2) = (reads.clone(), after.clone());
    set_refresh_for_test(Some(Box::new(move || {
        r2.fetch_add(1, Ordering::SeqCst);
        Ok(a2.clone())
    })));
    check_kernel_attest(&before, &v.a.id, "wakeup", body, Some(&d)).unwrap();
    assert_eq!(reads.load(Ordering::SeqCst), 1);
    let _ = check_kernel_attest(&before, &v.a.id, "wakeup", body, Some(&d));
    assert_eq!(
        reads.load(Ordering::SeqCst),
        1,
        "read again within KERNEL_TRUST_EVERY"
    );
    let green: Roster = jarvis_sig::open_roster(&v.green, &v.root).unwrap();
    assert_eq!(green.copy, "green");
    let other = Signer::generate();
    b.roster = Some(SignedDoc {
        payload: v.green.payload.clone(),
        sig: other.sign(v.green.payload.as_bytes()),
    });
    assert!(
        kernel_trust_for(&b).is_err(),
        "a roster the root key didn't sign"
    );
}

/// 2026-11-17: boot (jarvis-machine prepare) armed the documents' re-read, but deliveries are checked in
/// supervisor-core, another process, where it was never armed: after the 12:40 UTC copy flip every machine started
/// before it refused every wakeup ("no notary challenge") until it was restarted. Each supervisor arms it itself.
#[test]
fn a_supervisor_can_read_the_kernels_documents_again() {
    let _e = TestEnv::new();
    let c = crate::client::Client::with_url("http://127.0.0.1:9", "0123456789abcd");
    arm_kernel_trust_refresh(&c); // an old core line: no kernel trust, nothing to arm
    assert!(!refresh_armed(), "armed on a machine with no kernel trust");
    std::fs::write(
        crate::paths::kernel_trust_path(),
        r#"{"root":"r","notary":"n","machine":"fly-0123456789abcd"}"#,
    )
    .unwrap();
    arm_kernel_trust_refresh(&c);
    assert!(
        refresh_armed(),
        "a kernel machine's supervisor can't read the documents again after a copy flip"
    );
}
