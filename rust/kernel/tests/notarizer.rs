//! The notarizer and the log notary
use jarvis_doc::perm::{Pair, Set};
use jarvis_doc::{Cert, Challenge, Notarized, Object, by, peek_cert};
use jarvis_kernel::kt::{World, machine_keys, source, source_content};
use jarvis_kernel::notarizer::{Input, Notarizer};
use jarvis_kernel::notary::Notary;
use jarvis_sig::{Component, Doc, Signer};
use std::path::PathBuf;

struct Rig {
    w: World,
    n: Notarizer,
    path: PathBuf,
    _dir: tempfile::TempDir,
}

fn rig() -> Rig {
    let w = World::new();
    let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
    let path = dir.path().join("state");
    let n = Notarizer::open(&path, &w.trust).unwrap_or_else(|e| panic!("{e:#}"));
    Rig {
        w,
        n,
        path,
        _dir: dir,
    }
}

fn store() -> Pair {
    Pair::new(Set::only(["store:claude"]), vec!["session:s1".into()])
}

impl Rig {
    /// the cert with a fresh challenge and whatever names its signer's key
    fn input(&self, cert: &Doc) -> Input {
        let c = peek_cert(cert).unwrap_or_else(|e| panic!("{e}"));
        let mut i = Input {
            cert: cert.clone(),
            challenge: self
                .w
                .challenge(&cert.id(), "cert", time::OffsetDateTime::now_utc()),
            notary: self.w.id("notary"),
            signer: None,
            keys: None,
            secrets: None,
        };
        if c.signer == by::IPHONE || c.signer == by::ROOT {
            i.keys = Some(self.w.keys_doc.clone());
            i.secrets = Some(self.w.id("secrets"));
        } else {
            i.signer = Some(self.w.id(&c.signer));
        }
        i
    }

    fn ok(&self, cert: &Doc) {
        let d = self
            .n
            .notarize(
                &self.w.c["notarizer"].signer,
                &self.w.trust,
                &self.input(cert),
            )
            .unwrap_or_else(|e| panic!("{e:#}"));
        let nz: Notarized = d
            .open(&self.w.c["notarizer"].identity.signing_key)
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(nz.cert, cert.id());
    }

    fn refused(&self, i: &Input, want: &str) {
        match self
            .n
            .notarize(&self.w.c["notarizer"].signer, &self.w.trust, i)
        {
            Ok(_) => panic!("want a refusal containing {want:?}, got none"),
            Err(e) => assert!(
                format!("{e:#}").contains(want),
                "want a refusal containing {want:?}, got {e:#}"
            ),
        }
    }
}

fn top() -> Pair {
    Pair::top()
}

/// a whole life: phone → source, spawn, kill into a new source, spawn again, burn
#[test]
fn a_life_along_the_table() {
    let mut r = rig();
    let (x, y) = (source(), source());
    let (_, m1) = machine_keys();
    let (_, m2) = machine_keys();
    r.ok(&r.w.cert(
        by::IPHONE,
        "sink",
        &x,
        &store(),
        Some(source_content("t")),
        None,
    ));
    r.ok(&r
        .w
        .cert(by::SPAWNER, &x, "fly-aaaaaaaa01", &top(), None, Some(m1)));
    r.ok(&r.w.cert(
        by::IDENTITY,
        "fly-aaaaaaaa01",
        "fly-aaaaaaaa01",
        &store(),
        None,
        None,
    ));
    let mut snap = source_content("t");
    snap.snapshot = "ab".repeat(32);
    r.ok(&r
        .w
        .cert(by::SPAWNER, "fly-aaaaaaaa01", &y, &top(), Some(snap), None));
    r.ok(&r
        .w
        .cert(by::SPAWNER, &y, "fly-aaaaaaaa02", &top(), None, Some(m2)));
    // the state survives a restart: y has its successor, so a second spawn from it is refused
    r.n = Notarizer::open(&r.path, &r.w.trust).unwrap_or_else(|e| panic!("{e:#}"));
    let (_, m3) = machine_keys();
    r.refused(
        &r.input(&r.w.cert(by::SPAWNER, &y, "fly-aaaaaaaa03", &top(), None, Some(m3))),
        "already has a successor",
    );
    // the burn is the gullible signer's, and it isn't a first-successor row
    r.ok(&r.w.cert(by::GULLIBLE, &y, "sink", &store(), None, None));
}

/// ✱ every shape outside the table, per signer
#[test]
fn shapes_outside_the_table_are_refused() {
    let r = rig();
    let x = source();
    let (_, m) = machine_keys();
    r.ok(&r.w.cert(
        by::IPHONE,
        "sink",
        &x,
        &store(),
        Some(source_content("t")),
        None,
    ));
    let w = &r.w;
    for c in [
        w.cert(
            by::IPHONE,
            "sink",
            "fly-aaaaaaaa01",
            &store(),
            None,
            Some(m.clone()),
        ), // the phone can't widen onto a machine
        w.cert(
            by::IPHONE,
            "fly-aaaaaaaa01",
            &source(),
            &store(),
            Some(source_content("t")),
            None,
        ), // nor kill
        w.cert(by::IPHONE, &x, "sink", &store(), None, None), // nor burn
        w.cert(
            by::SPAWNER,
            "sink",
            &source(),
            &top(),
            Some(source_content("t")),
            None,
        ), // the spawner widens nothing out of the sink
        w.cert(by::SPAWNER, &x, "sink", &top(), None, None),
        w.cert(
            by::IDENTITY,
            "fly-aaaaaaaa01",
            "fly-aaaaaaaa02",
            &store(),
            None,
            Some(m.clone()),
        ), // identity only (M, M)
        w.cert(
            by::IDENTITY,
            &x,
            &x,
            &store(),
            Some(source_content("t")),
            None,
        ), // and only for Fly machines
        w.cert(
            by::GULLIBLE,
            "sink",
            &source(),
            &top(),
            Some(source_content("t")),
            None,
        ), // gullible only ends things
        w.cert(by::GULLIBLE, "fly-aaaaaaaa01", "sink", &store(), None, None), // a machine can't be burned
    ] {
        r.refused(&r.input(&c), "not in the table");
    }
    // ✱ the spawner's pair is always ⊤
    r.refused(
        &r.input(&w.cert(by::SPAWNER, &x, "fly-aaaaaaaa01", &store(), None, Some(m))),
        "⊤",
    );
}

/// ✱ a cert signed by the wrong key for its signer, a vouched identity of another role, an unvouched one
#[test]
fn signer_keys_are_checked() {
    let r = rig();
    let w = &r.w;
    let x = source();
    r.ok(&w.cert(
        by::IPHONE,
        "sink",
        &x,
        &store(),
        Some(source_content("t")),
        None,
    ));
    let (_, m) = machine_keys();
    // signed by the identity signer but claiming the spawner
    let c = Cert {
        kind: "succession".into(),
        pred: Object(x.clone()),
        succ: Object("fly-aaaaaaaa01".into()),
        pair: top(),
        source: None,
        machine: Some(m.clone()),
        signer: by::SPAWNER.into(),
        issued_at: jarvis_doc::now(),
    };
    let forged = w.c["identity"]
        .signer
        .sign_json(&c)
        .unwrap_or_else(|e| panic!("{e}"));
    r.refused(&r.input(&forged), "isn't signed by the spawner");
    // the identity signer's identity passed off as the spawner's
    let mut i = r.input(&w.cert(
        by::SPAWNER,
        &x,
        "fly-aaaaaaaa01",
        &top(),
        None,
        Some(m.clone()),
    ));
    i.signer = Some(w.id("identity"));
    r.refused(&i, "not a spawner identity");
    // an identity the roster doesn't name
    let fake = Component::new("spawner");
    let mut i = r.input(&w.cert(by::SPAWNER, &x, "fly-aaaaaaaa01", &top(), None, Some(m)));
    i.signer = Some(fake.identity.clone());
    r.refused(&i, "isn't the roster's");
    // the phone's cert checked against keys secrets didn't sign
    let y = source();
    let mut i = r.input(&w.cert(
        by::IPHONE,
        "sink",
        &y,
        &store(),
        Some(source_content("t")),
        None,
    ));
    let bad = w.c["notary"]
        .signer
        .sign_json(&serde_json::json!({"kind": "keys", "phone": w.phone.public_key(), "root": w.root.public_key()}))
        .unwrap_or_else(|e| panic!("{e}"));
    i.keys = Some(bad);
    r.refused(&i, "secrets' keys");
    // the root key is not the phone key
    let c = Cert {
        kind: "succession".into(),
        pred: Object("sink".into()),
        succ: Object(y),
        pair: store(),
        source: Some(source_content("t")),
        machine: None,
        signer: by::IPHONE.into(),
        issued_at: jarvis_doc::now(),
    };
    let root_signed = w.root.sign_json(&c).unwrap_or_else(|e| panic!("{e}"));
    r.refused(&r.input(&root_signed), "isn't signed by the iphone's key");
}

/// ✱ a challenge from elsewhere: another subject, not about a cert, stale, by an unvouched notary
#[test]
fn the_challenge_is_checked() {
    let r = rig();
    let w = &r.w;
    let cert = w.cert(
        by::IPHONE,
        "sink",
        &source(),
        &store(),
        Some(source_content("t")),
        None,
    );
    let now = time::OffsetDateTime::now_utc();
    let mut i = r.input(&cert);
    i.challenge = w.challenge(&"0".repeat(64), "cert", now);
    r.refused(&i, "challenge");
    let mut i = r.input(&cert);
    i.challenge = w.challenge(&cert.id(), "grant", now);
    r.refused(&i, "challenge");
    let mut i = r.input(&cert);
    i.challenge = w.challenge(&cert.id(), "cert", now - time::Duration::hours(1));
    r.refused(&i, "challenge");
    let mut i = r.input(&cert);
    i.notary = w.id("mover");
    r.refused(&i, "not a notary identity");
    r.ok(&cert);
}

/// ✱ a source defined twice; a successor of a source never defined
#[test]
fn sources_are_defined_once() {
    let r = rig();
    let w = &r.w;
    let x = source();
    r.ok(&w.cert(
        by::IPHONE,
        "sink",
        &x,
        &store(),
        Some(source_content("a")),
        None,
    ));
    r.refused(
        &r.input(&w.cert(
            by::IPHONE,
            "sink",
            &x,
            &top(),
            Some(source_content("b")),
            None,
        )),
        "already defined",
    );
    r.refused(
        &r.input(&w.cert(
            by::ROOT,
            "sink",
            &x,
            &top(),
            Some(source_content("b")),
            None,
        )),
        "already defined",
    );
    let (_, m) = machine_keys();
    r.refused(
        &r.input(&w.cert(
            by::SPAWNER,
            &source(),
            "fly-aaaaaaaa01",
            &top(),
            None,
            Some(m),
        )),
        "never defined",
    );
    // root signs any shape
    r.ok(&w.cert(by::ROOT, "fly-aaaaaaaa09", "sink", &store(), None, None));
}

const SUBJ: &str = "00000000000000000000000000000000000000000000000000000000000000ab";

#[test]
fn the_log_chains_and_survives_a_restart() {
    let s = Signer::generate();
    let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
    let path = dir.path().join("log");
    let n = Notary::open(&path).unwrap_or_else(|e| panic!("{e:#}"));
    let d1 = n
        .challenge(&s, SUBJ, "cert")
        .unwrap_or_else(|e| panic!("{e:#}"));
    drop(n);
    let n2 = Notary::open(&path).unwrap_or_else(|e| panic!("{e:#}"));
    let d2 = n2
        .challenge(&s, SUBJ, "grant")
        .unwrap_or_else(|e| panic!("{e:#}"));
    let c1: Challenge = d1.open(&s.public_key()).unwrap_or_else(|e| panic!("{e}"));
    let c2: Challenge = d2.open(&s.public_key()).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        c1.seq == 1
            && c1.prev.is_empty()
            && c2.seq == 2
            && c2.prev == d1.id()
            && c1.nonce != c2.nonce,
        "{c1:?} {c2:?}"
    );
}

/// ✱ a subject that isn't a sha256, an about that isn't a short word
#[test]
fn bad_challenge_inputs_are_refused() {
    let s = Signer::generate();
    let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
    let path = dir.path().join("log");
    let n = Notary::open(&path).unwrap_or_else(|e| panic!("{e:#}"));
    for (subj, about) in [
        ("x", "cert"),
        (&*SUBJ.to_uppercase(), "cert"),
        (SUBJ, "Cert"),
        (SUBJ, "a b"),
        (SUBJ, ""),
    ] {
        assert!(
            n.challenge(&s, subj, about).is_err(),
            "accepted {subj} {about}"
        );
    }
    assert_eq!(
        std::fs::read(&path).unwrap_or_default().len(),
        0,
        "a refused challenge was logged"
    );
}
