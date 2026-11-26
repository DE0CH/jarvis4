//! A session's chain through the real notarizer, mover, merger and signers (no HTTP)

use jarvis_doc::gv::{self, Signed, ideal_keys};
use jarvis_doc::perm::{Pair, Set};
use jarvis_doc::{Grant, Notarized, Object, SINK, by, now, peek_cert};
use jarvis_kernel::kt::{World, keys_of, machine_keys, source, source_content};
use jarvis_kernel::notarizer::{Input as NzInput, Notarizer};
use jarvis_kernel::{merger, mover, signers};
use jarvis_sig::{Component, Doc, Signer};

struct K {
    w: World,
    nz: Notarizer,
    _dir: tempfile::TempDir,
}

fn new_k() -> K {
    let w = World::new();
    let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
    let nz = Notarizer::open(&dir.path().join("s"), &w.trust).unwrap_or_else(|e| panic!("{e:#}"));
    K { w, nz, _dir: dir }
}

fn p() -> Pair {
    Pair::new(
        Set::only(["store:claude", "store:default"]),
        vec!["session:s1".into()],
    )
}

fn grant_doc(s: &Signer, machine: &str, keys: jarvis_doc::Keys, pair: Pair) -> Doc {
    s.sign_json(&Grant {
        kind: "grant".into(),
        machine: Object(machine.into()),
        keys,
        pair,
        from: Some(vec![]),
        at: now(),
    })
    .unwrap_or_else(|e| panic!("{e}"))
}

impl K {
    /// the cert with a fresh challenge
    fn notarize(&self, cert: &Doc) -> Doc {
        let c = peek_cert(cert).unwrap_or_else(|e| panic!("{e}"));
        let mut i = NzInput {
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
        self.nz
            .notarize(&self.w.c["notarizer"].signer, &self.w.trust, &i)
            .unwrap_or_else(|e| panic!("{e:#}"))
    }

    /// ⊤ on the sink, by the root key
    fn root_top(&self) -> Signed {
        let ik = ideal_keys(&Object(SINK.into())).unwrap_or_else(|e| panic!("{e}"));
        Signed {
            grant: grant_doc(&self.w.root, SINK, ik, Pair::top()),
            by: "root".into(),
            signer: None,
            keys: Some(self.w.keys_doc.clone()),
            secrets: Some(self.w.id("secrets")),
        }
    }

    fn move_in(&self, g: &Signed, cert: &Doc, nz: &Doc) -> mover::Input {
        mover::Input {
            grant: g.grant.clone(),
            by: g.by.clone(),
            signer: g.signer.clone(),
            keys: g.keys.clone(),
            secrets: g.secrets.clone(),
            cert: cert.clone(),
            notarized: nz.clone(),
            notarizer: self.w.id("notarizer"),
            notary: self.w.id("notary"),
        }
    }

    fn mv(&self, i: &mover::Input) -> anyhow::Result<Doc> {
        mover::mv(&self.w.c["mover"].signer, &self.w.trust, i)
    }

    fn mg(&self, a: &Signed, b: &Signed) -> anyhow::Result<Doc> {
        merger::merge(
            &self.w.c["merger"].signer,
            &self.w.trust,
            &merger::Input {
                a: a.clone(),
                b: b.clone(),
            },
        )
    }

    fn mov(&self, g: &Signed, cert: &Doc) -> (Signed, Grant) {
        let d = self
            .mv(&self.move_in(g, cert, &self.notarize(cert)))
            .unwrap_or_else(|e| panic!("{e:#}"));
        let s = Signed {
            grant: d,
            by: "mover".into(),
            signer: Some(self.w.id("mover")),
            keys: None,
            secrets: None,
        };
        let out = gv::open(&s, &self.w.trust).unwrap_or_else(|e| panic!("{e}"));
        (s, out)
    }
}

/// New session → spawn → narrow → add a shell for a while → merge → kill into a source → spawn again → burn
#[test]
fn a_sessions_chain() {
    let k = new_k();
    let w = &k.w;
    let p = p();
    let x = source();
    let (g_x, on_x) = k.mov(
        &k.root_top(),
        &w.cert(by::IPHONE, SINK, &x, &p, Some(source_content("t")), None),
    );
    assert!(
        on_x.machine.0 == x && on_x.pair.leq(&p) && p.leq(&on_x.pair),
        "{on_x:?}"
    );
    let (_, m1) = machine_keys();
    let (g_m, on_m) = k.mov(
        &g_x,
        &w.cert(
            by::SPAWNER,
            &x,
            "fly-aaaaaaaa01",
            &Pair::top(),
            None,
            Some(m1.clone()),
        ),
    );
    assert!(
        on_m.keys == keys_of(&m1) && on_m.pair.allowed.contains("store:claude"),
        "{on_m:?}"
    );
    // adding a shell until T: the phone's small grant, and the main grant narrowed to the same conditions
    let cond = vec![
        "session:s1".to_string(),
        "until:2026-10-21T15:00:00Z".to_string(),
    ];
    let a = source();
    let (g_a, _) = k.mov(
        &k.root_top(),
        &w.cert(
            by::IPHONE,
            SINK,
            &a,
            &Pair::new(Set::only(["shell"]), cond.clone()),
            Some(source_content("add")),
            None,
        ),
    );
    let (g_a2, _) = k.mov(
        &g_a,
        &w.cert(
            by::IPHONE,
            &a,
            "fly-aaaaaaaa01",
            &Pair::top(),
            None,
            Some(m1.clone()),
        ),
    );
    let idc = signers::identity(
        &w.c["identity"].signer,
        &Object("fly-aaaaaaaa01".into()),
        &Pair::new(Set::except(Vec::<String>::new()), cond.clone()),
    )
    .unwrap_or_else(|e| panic!("{e:#}"));
    let (g_n, on_n) = k.mov(&g_m, &idc);
    assert!(
        on_n.keys == keys_of(&m1) && on_n.pair.conditions.as_ref().map_or(0, Vec::len) == 2,
        "{on_n:?}"
    );
    let md = k.mg(&g_n, &g_a2).unwrap_or_else(|e| panic!("{e:#}"));
    let merged = gv::open(
        &Signed {
            grant: md,
            by: "merger".into(),
            signer: Some(w.id("merger")),
            keys: None,
            secrets: None,
        },
        &w.trust,
    )
    .unwrap_or_else(|e| panic!("{e}"));
    assert!(
        merged.pair.allowed.contains("shell") && merged.pair.allowed.contains("store:default"),
        "{merged:?}"
    );
    // ✱ merging the main grant (no until) with the shell grant is refused: conditions differ
    let e = k
        .mg(&g_m, &g_a2)
        .err()
        .map(|e| format!("{e:#}"))
        .unwrap_or_default();
    assert!(e.contains("conditions differ"), "{e}");
    // pause: kill into y, then spawn from it; the main grant follows
    let y = source();
    let mut snap = source_content("t");
    snap.snapshot = "cd".repeat(32);
    let (g_y, on_y) = k.mov(
        &g_m,
        &w.cert(
            by::SPAWNER,
            "fly-aaaaaaaa01",
            &y,
            &Pair::top(),
            Some(snap),
            None,
        ),
    );
    assert_eq!(on_y.machine.0, y);
    let (_, m2) = machine_keys();
    let (_, on2) = k.mov(
        &g_y,
        &w.cert(
            by::SPAWNER,
            &y,
            "fly-aaaaaaaa02",
            &Pair::top(),
            None,
            Some(m2.clone()),
        ),
    );
    assert!(
        on2.keys == keys_of(&m2)
            && on2.pair.allowed.contains("store:claude")
            && !on2.pair.allowed.contains("shell"),
        "{on2:?}"
    );
    // destroy: the burn ends y's line (y already spawned, so this is only the record)
    k.notarize(&w.cert(by::GULLIBLE, &y, SINK, &Pair::top(), None, None));
}

/// ✱ the mover's refusals: a grant on another object, a cert not notarized, a forged notarizer, a grant by an
/// unvouched mover, the root's grant that isn't ⊤ on the sink, ideal-keyed objects with other keys
#[test]
fn the_mover_refuses() {
    let k = new_k();
    let w = &k.w;
    let p = p();
    let x = source();
    let cert = w.cert(by::IPHONE, SINK, &x, &p, Some(source_content("t")), None);
    let nz = k.notarize(&cert);
    let (g_x, _) = k.mov(
        &k.root_top(),
        &w.cert(
            by::IPHONE,
            SINK,
            &source(),
            &p,
            Some(source_content("u")),
            None,
        ),
    );
    let refuse = |i: mover::Input, want: &str| {
        let e = k.mv(&i).err().map(|e| format!("{e:#}")).unwrap_or_default();
        assert!(e.contains(want), "want {want:?}, got {e:?}");
    };
    refuse(k.move_in(&g_x, &cert, &nz), "the cert leaves sink");
    let other = w.cert(
        by::IPHONE,
        SINK,
        &source(),
        &p,
        Some(source_content("v")),
        None,
    );
    refuse(k.move_in(&k.root_top(), &other, &nz), "isn't notarized");
    let mut i = k.move_in(&k.root_top(), &cert, &nz);
    i.notarizer = w.id("notary");
    refuse(i, "not a notarizer identity");
    let fake = Signer::generate();
    let fake_nz = fake
        .sign_json(&Notarized {
            kind: "notarized".into(),
            cert: cert.id(),
            challenge: Doc {
                payload: String::new(),
                sig: String::new(),
            },
        })
        .unwrap_or_else(|e| panic!("{e}"));
    refuse(k.move_in(&k.root_top(), &cert, &fake_nz), "isn't notarized");
    // a grant signed by a mover the roster doesn't name
    let m2 = Component::new("mover");
    let ik = ideal_keys(&Object(SINK.into())).unwrap_or_else(|e| panic!("{e}"));
    let gd = grant_doc(&m2.signer, SINK, ik.clone(), Pair::top());
    let s = Signed {
        grant: gd,
        by: "mover".into(),
        signer: Some(m2.identity.clone()),
        keys: None,
        secrets: None,
    };
    refuse(k.move_in(&s, &cert, &nz), "isn't the roster's");
    // the root key's grant on anything but ⊤ on the sink
    let rd = grant_doc(&w.root, SINK, ik, p.clone());
    let s = Signed {
        grant: rd,
        by: "root".into(),
        signer: None,
        keys: Some(w.keys_doc.clone()),
        secrets: Some(w.id("secrets")),
    };
    refuse(k.move_in(&s, &cert, &nz), "⊤ on the sink only");
    // a grant on the sink naming other keys
    let (_, mk) = machine_keys();
    let bd = grant_doc(&w.c["mover"].signer, SINK, keys_of(&mk), Pair::top());
    let s = Signed {
        grant: bd,
        by: "mover".into(),
        signer: Some(w.id("mover")),
        keys: None,
        secrets: None,
    };
    refuse(k.move_in(&s, &cert, &nz), "aren't its own");
    // the real one goes
    k.mv(&k.move_in(&k.root_top(), &cert, &nz))
        .unwrap_or_else(|e| panic!("{e:#}"));
}

/// a move only narrows: whatever the cert's pair, the result is ≤ the grant
#[test]
fn a_move_only_narrows() {
    let k = new_k();
    let w = &k.w;
    let small = Pair::new(Set::only(["store:a"]), vec!["session:s1".into()]);
    let (g_x, _) = k.mov(
        &k.root_top(),
        &w.cert(
            by::IPHONE,
            SINK,
            &source(),
            &small,
            Some(source_content("t")),
            None,
        ),
    );
    let (_, mk) = machine_keys();
    let x = gv::open(&g_x, &w.trust).unwrap_or_else(|e| panic!("{e}"));
    let (_, on) = k.mov(
        &g_x,
        &w.cert(
            by::ROOT,
            &x.machine.0,
            "fly-aaaaaaaa01",
            &Pair::top(),
            None,
            Some(mk),
        ),
    );
    assert!(
        on.pair.leq(&small) && !on.pair.allowed.contains("shell"),
        "{on:?}"
    );
}

/// ✱ the merger: different machines
#[test]
fn the_merger_refuses_other_machines() {
    let k = new_k();
    let w = &k.w;
    let p = p();
    let (a, _) = k.mov(
        &k.root_top(),
        &w.cert(
            by::IPHONE,
            SINK,
            &source(),
            &p,
            Some(source_content("a")),
            None,
        ),
    );
    let (b, _) = k.mov(
        &k.root_top(),
        &w.cert(
            by::IPHONE,
            SINK,
            &source(),
            &p,
            Some(source_content("b")),
            None,
        ),
    );
    let e = k
        .mg(&a, &b)
        .err()
        .map(|e| format!("{e:#}"))
        .unwrap_or_default();
    assert!(e.contains("different machines"), "{e}");
}

/// ✱ the identity signer signs only (M, M) for a Fly machine
#[test]
fn the_identity_signer_only_fly_machines() {
    let w = World::new();
    assert!(
        signers::identity(&w.c["identity"].signer, &Object(source()), &Pair::top()).is_err(),
        "signed for a source"
    );
}
