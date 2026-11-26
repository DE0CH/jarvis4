//! secrets: claims, stores, unlocks, pulls, the line state and its replays

use super::continuity::{MODE_HANDED_OFF, allowed_in};
use super::crypto::{INFO_STORE, WrappedKey, add_points, gcm_seal, kdf, scalar_mult};
use super::deploykeys::DEPLOY_KEY_TOKEN_STORE;
use super::keys::{KeyEntry, WriteKeyInput, key_aad, writer_text};
use super::{INFO_LIVE, INFO_SHARE, Secrets};
use crate::kt::{World, sign_roster, source};
use jarvis_doc::gv::{self, Signed};
use jarvis_doc::perm::{Pair, Set};
use jarvis_doc::{Grant, Keys, Object};
use jarvis_sig::{Component, Doc, Identity, Opener, Roster, Sealed, Signer, b64, seal_to, unb64};
use serde_json::{Value, json};
use std::collections::BTreeMap;

/// a P-256 key holder: the iPhone (signing + the Enclave's key agreement, here in software), the master key, the root
/// key, the setup key
pub(crate) struct Phone {
    pub s: Signer,
    pub a: Opener,
}

impl Phone {
    pub fn new() -> Phone {
        Phone {
            s: Signer::generate(),
            a: Opener::generate(),
        }
    }
    pub fn signing_key(&self) -> String {
        self.s.public_key()
    }
    pub fn agreement_key(&self) -> String {
        self.a.public_key()
    }
    pub fn sign(&self, payload: &str) -> String {
        self.s.sign(payload.as_bytes())
    }
    /// the phone's share of an unlock, x(p·E) per key, sealed to the one-off T
    pub fn share(&self, begin: &Doc) -> (String, BTreeMap<String, Sealed>) {
        let b: Value = serde_json::from_str(&begin.payload).unwrap_or_default();
        let t = b["t"].as_str().unwrap_or_default();
        let out = b["keys"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .iter()
            .map(|k| {
                (
                    k["key"].as_str().unwrap_or_default().to_string(),
                    self.share_of(k["e"].as_str().unwrap_or_default(), t),
                )
            })
            .collect();
        (b["pending"].as_str().unwrap_or_default().to_string(), out)
    }
    pub fn share_of(&self, e: &str, t: &str) -> Sealed {
        let x = scalar_mult(&self.a.scalar(), &unb64(e).unwrap_or_default())
            .unwrap_or_else(|e| panic!("{e:#}"));
        seal_to(t, &x[1..33], INFO_SHARE).unwrap_or_else(|e| panic!("{e}"))
    }
}

/// the payload of an answer, failing the test on an error
pub(crate) fn pl(r: anyhow::Result<Doc>) -> Value {
    let d = r.unwrap_or_else(|e| panic!("{e:#}"));
    serde_json::from_str(&d.payload).unwrap_or_default()
}

pub(crate) fn test_values(store: &str) -> BTreeMap<String, String> {
    let kv: &[(&str, &str)] = match store {
        "default" => &[("A", "1"), ("B", "2")],
        "gmail" => &[("G", "secret")],
        "claude" => &[("CLAUDE_CREDENTIALS", "c")],
        "openrouter" => &[("OPENROUTER_API", "o")],
        _ => &[],
    };
    kv.iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// a data key wrapped to the point (as the app wraps a key to the store key P + K)
pub(crate) fn wrap_to_point(combined: &[u8], dk: &[u8; 32]) -> WrappedKey {
    let e = Opener::generate();
    let shared = scalar_mult(&e.scalar(), combined).unwrap_or_else(|e| panic!("{e:#}"));
    WrappedKey {
        e: e.public_key(),
        wrapped: b64(&gcm_seal(&kdf(&shared[1..33], INFO_STORE), dk, &[])),
    }
}

/// C = P + K for a phone and a secrets' agreement key (base64)
pub(crate) fn store_key(p: &Phone, secrets_agreement: &str) -> Vec<u8> {
    add_points(
        &unb64(&p.agreement_key()).unwrap_or_default(),
        &unb64(secrets_agreement).unwrap_or_default(),
    )
    .unwrap_or_else(|e| panic!("{e:#}"))
}

fn rand32() -> [u8; 32] {
    use rand_core::RngCore as _;
    let mut b = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut b);
    b
}

/// a writer's key, wrapped to the combined key P + K
pub(crate) fn seal_key(c: &Secrets, p: &Phone, store: &str, key: &str, value: &str) -> KeyEntry {
    let dk = rand32();
    let w = wrap_to_point(&store_key(p, &c.component_identity().agreement_key), &dk);
    KeyEntry {
        store: store.into(),
        key: key.into(),
        wrapped: w,
        data: b64(&gcm_seal(&dk, value.as_bytes(), &key_aad(store, key))),
        ..Default::default()
    }
}

pub(crate) fn setup_write(c: &Secrets, x: &KeyEntry) -> anyhow::Result<Doc> {
    c.write_key(WriteKeyInput {
        store: x.store.clone(),
        key: x.key.clone(),
        wrapped: x.wrapped.clone(),
        data: x.data.clone(),
        writer: "setup".into(),
        sig: "c2ln".into(),
        ..Default::default()
    })
}

pub(crate) fn write_store(c: &Secrets, p: &Phone, name: &str, vals: &BTreeMap<String, String>) {
    for (k, v) in vals {
        setup_write(c, &seal_key(c, p, name, k, v)).unwrap_or_else(|e| panic!("{e:#}"));
    }
}

/// the app's keys of a store, wrapped to the store key of this secrets
fn app_wrap(c: &Secrets, p: &Phone, name: &str) -> Vec<KeyEntry> {
    test_values(name)
        .iter()
        .map(|(k, v)| {
            let dk = rand32();
            KeyEntry {
                store: name.into(),
                key: k.clone(),
                wrapped: wrap_to_point(&store_key(p, &c.component_identity().agreement_key), &dk),
                data: b64(&gcm_seal(&dk, v.as_bytes(), &key_aad(name, k))),
                ..Default::default()
            }
        })
        .collect()
}

fn recover_bundle(c: &Secrets, p: &Phone) -> Value {
    let mut keys = vec![];
    for n in ["claude", "default", "gmail", "openrouter"] {
        keys.extend(app_wrap(c, p, n));
    }
    json!({"format": "keys", "stores": ["claude", "default", "gmail", "openrouter"], "keys": keys,
        "notSensitive": ["default", "claude", "openrouter"]})
}

/// the statement (master key, secrets, phone, root), signed by the master key, and the sealed bundle
pub(crate) fn claim_for(
    c: &Secrets,
    master: &Phone,
    p: &Phone,
    root: &Phone,
    bundle: &Value,
    identity: Option<(String, String)>,
) -> (String, String, Sealed) {
    use sha2::Digest as _;
    let plain = jarvis_sig::go_json(bundle).unwrap_or_default();
    let me = c.component_identity();
    let mut st = json!({"kind": "kernel-claim", "master": master.signing_key(), "root": root.signing_key(),
        "secrets": {"signingKey": me.signing_key, "agreementKey": me.agreement_key},
        "phone": {"signingKey": p.signing_key(), "agreementKey": p.agreement_key()},
        "bundleSha256": super::hex(&sha2::Sha256::digest(plain.as_bytes()))});
    if let Some((s, a)) = identity {
        st["identity"] = json!({"signingKey": s, "agreementKey": a});
    }
    let sb = jarvis_sig::go_json(&st).unwrap_or_default();
    let sealed = seal_to(&me.agreement_key, plain.as_bytes(), "jarvis2/kernel-claim")
        .unwrap_or_else(|e| panic!("{e}"));
    let sig = master.sign(&sb);
    (sb, sig, sealed)
}

/// secrets Recovered with the test stores; the phone and the root key
pub(crate) fn setup() -> (Secrets, Phone, Phone) {
    let c = Secrets::new(&Signer::generate().public_key(), None);
    let (master, p, root) = (Phone::new(), Phone::new(), Phone::new());
    let (s, sg, b) = claim_for(&c, &master, &p, &root, &recover_bundle(&c, &p), None);
    pl(c.claim(&s, &sg, &b));
    (c, p, root)
}

pub(crate) fn unlock(c: &Secrets, p: &Phone, store: &str) -> String {
    let b = c.unlock_begin(store).unwrap_or_else(|e| panic!("{e:#}"));
    let (id, s) = p.share(&b);
    pl(c.unlock_finish(&id, &s))["id"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

/// a store's values, as an unlock opens them
pub(crate) fn store_of(c: &Secrets, p: &Phone, name: &str) -> BTreeMap<String, String> {
    unlock(c, p, name);
    c.unlocked_values(name).unwrap_or_default()
}

/// the world's roster with c as its secrets, taken by c and by the world's trust
fn roster_for(w: &World, c: &Secrets) {
    let mut ids = vec![c.component_identity()];
    ids.extend(
        crate::kt::ROLES
            .iter()
            .filter(|r| **r != "secrets")
            .map(|r| w.id(r)),
    );
    let d = sign_roster(
        &w.root,
        &Roster {
            copy: "blue".into(),
            members: ids,
            ..Default::default()
        },
    );
    c.set_roster(d.clone()).unwrap_or_else(|e| panic!("{e:#}"));
    w.trust.set(d, None).unwrap_or_else(|e| panic!("{e}"));
}

struct Kernel {
    w: World,
    c: Secrets,
    p: Phone,
    root: Phone,
    /// the machine's encryption and signing keys
    enc: Opener,
    msig: Signer,
}

fn new_kernel() -> Kernel {
    let w = World::new();
    let c = Secrets::new(&w.root.public_key(), None);
    let (master, p, root) = (Phone::new(), Phone::new(), Phone::new());
    let (s, sg, b) = claim_for(&c, &master, &p, &root, &recover_bundle(&c, &p), None);
    pl(c.claim(&s, &sg, &b));
    roster_for(&w, &c);
    Kernel {
        w,
        c,
        p,
        root,
        enc: Opener::generate(),
        msig: Signer::generate(),
    }
}

impl Kernel {
    /// a mover-signed grant with this allowed set on the machine
    fn grant(&self, allowed: Set) -> Signed {
        let g = Grant {
            kind: "grant".into(),
            machine: Object("fly-aaaaaaaa01".into()),
            keys: Keys {
                signing_key: self.msig.public_key(),
                encryption_key: self.enc.public_key(),
            },
            pair: Pair::new(allowed, vec!["session:s1".into()]),
            from: Some(vec![]),
            at: jarvis_doc::now(),
        };
        Signed {
            grant: self.w.c["mover"]
                .signer
                .sign_json(&g)
                .unwrap_or_else(|e| panic!("{e}")),
            by: "mover".into(),
            signer: Some(self.w.id("mover")),
            keys: None,
            secrets: None,
        }
    }

    /// the values the machine opens, and the answer
    fn pull(&self, g: Signed) -> anyhow::Result<(BTreeMap<String, String>, Value)> {
        let d = self.c.pull(g)?;
        let m: Value = serde_json::from_str(&d.payload).unwrap_or_default();
        let sealed: Sealed = serde_json::from_value(m["sealed"].clone())?;
        let plain = self
            .enc
            .open(&sealed, "jarvis2/secrets")
            .unwrap_or_else(|e| panic!("{e}"));
        Ok((serde_json::from_slice(&plain).unwrap_or_default(), m))
    }
}

fn s(v: &BTreeMap<String, String>, k: &str) -> String {
    v.get(k).cloned().unwrap_or_default()
}

/// a finite grant pulls exactly its stores, each open; a locked one is 423 naming it; a cofinite grant pulls the open
/// stores it doesn't exclude; the deploy-key token store is never served
#[test]
fn pull_takes_a_grant() {
    let k = new_kernel();
    unlock(&k.c, &k.p, "default");
    let g = k.grant(Set::only(["store:default", "store:gmail", "shell"]));
    let e = k
        .pull(g.clone())
        .err()
        .map(|e| format!("{e:#}"))
        .unwrap_or_default();
    assert!(e.contains("store gmail is locked"), "{e}");
    unlock(&k.c, &k.p, "gmail");
    let (vals, _) = k.pull(g).unwrap_or_else(|e| panic!("{e:#}"));
    assert!(
        s(&vals, "A") == "1" && s(&vals, "G") == "secret" && s(&vals, "OPENROUTER_API").is_empty(),
        "{vals:?}"
    );
    let (vals, _) = k
        .pull(k.grant(Set::except(["store:gmail"])))
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert!(s(&vals, "A") == "1" && s(&vals, "G").is_empty(), "{vals:?}");
    write_store(
        &k.c,
        &k.p,
        DEPLOY_KEY_TOKEN_STORE,
        &BTreeMap::from([("T".into(), "tok".into())]),
    );
    let (vals, m) = k
        .pull(k.grant(Set::only([
            "store:default".to_string(),
            format!("store:{DEPLOY_KEY_TOKEN_STORE}"),
        ])))
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert!(
        s(&vals, "T").is_empty() && m["stores"].as_array().map(Vec::len) == Some(1),
        "{vals:?} {m}"
    );
}

/// ✱ a grant not by the mover or merger: another role's key, an unvouched mover, the root key on anything but ⊤ on the
/// sink, a changed grant
#[test]
fn pull_refuses_other_grants() {
    let k = new_kernel();
    unlock(&k.c, &k.p, "default");
    let g = k.grant(Set::only(["store:default"]));
    let mut bad = g.clone();
    bad.signer = Some(k.w.id("notary"));
    assert!(
        k.c.pull(bad).is_err(),
        "a notary identity passed as the mover's"
    );
    let m2 = Component::new("mover");
    let gr: Value = serde_json::from_str(&g.grant.payload).unwrap_or_default();
    let d = m2.signer.sign_json(&gr).unwrap_or_else(|e| panic!("{e}"));
    let forged = Signed {
        grant: d,
        by: "mover".into(),
        signer: Some(m2.identity.clone()),
        keys: None,
        secrets: None,
    };
    assert!(k.c.pull(forged).is_err(), "a mover the roster doesn't name");
    let rd = k.w.root.sign_json(&gr).unwrap_or_else(|e| panic!("{e}"));
    let rooted = Signed {
        grant: rd,
        by: "root".into(),
        signer: None,
        keys: None,
        secrets: None,
    };
    assert!(
        k.c.pull(rooted).is_err(),
        "the root key's grant on a machine"
    );
    let mut changed = g;
    changed.grant.payload = changed
        .grant
        .payload
        .replacen("store:default", "store:gmail", 1);
    assert!(k.c.pull(changed).is_err(), "a changed grant");
}

/// D1: a key written with its live value reaches the next pull; one written without it leaves the store behind
/// (stale) until the phone unlocks again; a delete reaches it too. D2: nothing locks by itself; lock ends it.
#[test]
fn written_keys_reach_the_next_pull() {
    let k = new_kernel();
    let id = unlock(&k.c, &k.p, "default");
    let g = k.grant(Set::only(["store:default"]));
    let x = seal_key(&k.c, &k.p, "default", "C", "3");
    let agr = k.c.component_identity().agreement_key;
    let live =
        seal_to(&agr, b"3", &format!("{INFO_LIVE}\ndefault\nC")).unwrap_or_else(|e| panic!("{e}"));
    pl(k.c.write_key(WriteKeyInput {
        store: "default".into(),
        key: "C".into(),
        wrapped: x.wrapped,
        data: x.data,
        writer: "setup".into(),
        sig: "c2ln".into(),
        live: Some(live),
        ..Default::default()
    }));
    let (vals, m) = k.pull(g.clone()).unwrap_or_else(|e| panic!("{e:#}"));
    assert!(
        s(&vals, "C") == "3" && m["stale"].as_array().map(Vec::len) == Some(0),
        "{vals:?} {m}"
    );
    pl(k.c.write_key(WriteKeyInput {
        store: "default".into(),
        key: "A".into(),
        delete: true,
        writer: "setup".into(),
        sig: "c2ln".into(),
        ..Default::default()
    }));
    let (vals, _) = k.pull(g.clone()).unwrap_or_else(|e| panic!("{e:#}"));
    assert!(s(&vals, "A").is_empty() && s(&vals, "B") == "2", "{vals:?}");
    pl(setup_write(
        &k.c,
        &seal_key(&k.c, &k.p, "default", "D", "4"),
    )); // no live value
    let (vals, m) = k.pull(g.clone()).unwrap_or_else(|e| panic!("{e:#}"));
    assert!(
        s(&vals, "D").is_empty() && m["stale"].as_array().map(Vec::len) == Some(1),
        "{vals:?} {m}"
    );
    // ✱ a live value sealed for another key doesn't open as this one
    let wrong = seal_to(&agr, b"x", &format!("{INFO_LIVE}\ndefault\nOTHER"))
        .unwrap_or_else(|e| panic!("{e}"));
    let y = seal_key(&k.c, &k.p, "default", "E", "5");
    pl(k.c.write_key(WriteKeyInput {
        store: "default".into(),
        key: "E".into(),
        wrapped: y.wrapped,
        data: y.data,
        writer: "setup".into(),
        sig: "c2ln".into(),
        live: Some(wrong),
        ..Default::default()
    }));
    let (vals, _) = k.pull(g.clone()).unwrap_or_else(|e| panic!("{e:#}"));
    assert!(
        s(&vals, "E").is_empty(),
        "a live value for another key was taken"
    );
    pl(k.c.lock_unlock(&id));
    let e = k
        .pull(g)
        .err()
        .map(|e| format!("{e:#}"))
        .unwrap_or_default();
    assert!(e.contains("locked"), "{e}");
}

/// a machine writes with the grant it holds, signed by that grant's machine key; ✱ another key, ✱ a grant on a source;
/// the router writes only the Claude login stores
#[test]
fn writers() {
    let k = new_kernel();
    let g = k.grant(Set::only(["store:default"]));
    let x = seal_key(&k.c, &k.p, "notes", "N", "n");
    let text = writer_text("notes", "N", &x.wrapped.e, &x.data, "");
    let good = k.msig.sign(text.as_bytes());
    let write = |sig: &str, grant: Signed| {
        k.c.write_key(WriteKeyInput {
            store: "notes".into(),
            key: "N".into(),
            wrapped: x.wrapped.clone(),
            data: x.data.clone(),
            writer: "machine".into(),
            sig: sig.into(),
            grant: Some(grant),
            ..Default::default()
        })
    };
    let out = pl(write(&good, g.clone()));
    assert!(
        out["writer"]["by"] == "machine" && out["writer"]["machine"] == "aaaaaaaa01",
        "{out}"
    );
    let bad = Signer::generate().sign(text.as_bytes());
    assert!(
        write(&bad, g.clone()).is_err(),
        "another key wrote as the machine"
    );
    let src = Object(source());
    let mut gr: Grant = serde_json::from_str(&g.grant.payload).unwrap_or_else(|e| panic!("{e}"));
    gr.keys = gv::ideal_keys(&src).unwrap_or_else(|e| panic!("{e}"));
    gr.machine = src;
    let sd = k.w.c["mover"]
        .signer
        .sign_json(&gr)
        .unwrap_or_else(|e| panic!("{e}"));
    let on_source = Signed {
        grant: sd,
        by: "mover".into(),
        signer: Some(k.w.id("mover")),
        keys: None,
        secrets: None,
    };
    assert!(
        write(&good, on_source).is_err(),
        "a grant on a source wrote as a machine"
    );
    let y = seal_key(&k.c, &k.p, "claude", "CLAUDE_CREDENTIALS", "new");
    pl(k.c.write_key(WriteKeyInput {
        store: "claude".into(),
        key: "CLAUDE_CREDENTIALS".into(),
        wrapped: y.wrapped,
        data: y.data,
        writer: "router".into(),
        ..Default::default()
    }));
    let z = seal_key(&k.c, &k.p, "default", "A", "x");
    let r = k.c.write_key(WriteKeyInput {
        store: "default".into(),
        key: "A".into(),
        wrapped: z.wrapped,
        data: z.data,
        writer: "router".into(),
        ..Default::default()
    });
    assert!(
        r.is_err(),
        "the router wrote a store that isn't the Claude login's"
    );
}

/// the claim names a root key of its own; the keys statement is what the notarizer and the mover read
#[test]
fn the_root_key() {
    let c = Secrets::new(&Signer::generate().public_key(), None);
    let (master, p) = (Phone::new(), Phone::new());
    let (st, sg, b) = claim_for(&c, &master, &p, &p, &json!({"format": "keys"}), None); // the phone's key as the root key
    assert!(
        c.claim(&st, &sg, &b).is_err(),
        "the phone's key taken as the root key"
    );
    let k = new_kernel();
    let d = k.c.keys_statement().unwrap_or_else(|e| panic!("{e:#}"));
    let ks: Value = serde_json::from_str(&d.payload).unwrap_or_default();
    assert!(
        ks["phone"] == k.p.signing_key().as_str() && ks["root"] == k.root.signing_key().as_str(),
        "{ks}"
    );
    let me: Identity = k.c.component_identity();
    gv::root_key(Some(&d), Some(&me), &k.w.trust).unwrap_or_else(|e| panic!("{e}"));
}

/// a claim with secrets' seed (the same kit derives the same secrets)
fn seeded_claim(c: &Secrets, master: &Phone, p: &Phone, root: &Phone, seed: &[u8; 32]) {
    let dk = super::continuity::derive_core_keys(seed).unwrap_or_else(|e| panic!("{e:#}"));
    let derived = (dk.signer.public_key(), dk.agreement.public_key());
    let combined = store_key(p, &derived.1); // the store key with the derived K, as the app wraps a Recover
    let keys: Vec<KeyEntry> = test_values("default")
        .iter()
        .map(|(k, v)| {
            let d = rand32();
            KeyEntry {
                store: "default".into(),
                key: k.clone(),
                wrapped: wrap_to_point(&combined, &d),
                data: b64(&gcm_seal(&d, v.as_bytes(), &key_aad("default", k))),
                ..Default::default()
            }
        })
        .collect();
    let bundle =
        json!({"format": "keys", "stores": ["default"], "keys": keys, "secretsSeed": b64(seed)});
    let (st, sg, b) = claim_for(c, master, p, root, &bundle, Some(derived));
    pl(c.claim(&st, &sg, &b));
}

/// the world's components as the other copy's roster names them: secrets as the kit derives it (a's keys) and, taking
/// over, b's boot keys
fn other_copy(w: &World, a: &Secrets, b: &Secrets) -> Doc {
    let mut ids = vec![a.component_identity()];
    ids.extend(
        crate::kt::ROLES
            .iter()
            .filter(|r| **r != "secrets")
            .map(|r| w.id(r)),
    );
    sign_roster(
        &w.root,
        &Roster {
            copy: "green".into(),
            members: ids,
            secrets_boot: Some(b.component_identity()),
            ..Default::default()
        },
    )
}

/// the copy flip: the serving secrets hands its seed and final state (the open unlocks included: they never end by
/// themselves, so a flip mustn't drop them) to the other copy's empty secrets, which derives the same keys and serves;
/// the old one serves nothing after its handoff
#[test]
fn a_handoff_keeps_the_open_unlocks() {
    let w = World::new();
    let (master, p, root) = (Phone::new(), Phone::new(), Phone::new());
    let seed = rand32();
    let a = Secrets::new(&w.root.public_key(), None);
    seeded_claim(&a, &master, &p, &root, &seed);
    roster_for(&w, &a);
    unlock(&a, &p, "default");
    let b = Secrets::new(&w.root.public_key(), None);
    let green = other_copy(&w, &a, &b);
    b.set_roster(green.clone())
        .unwrap_or_else(|e| panic!("{e:#}"));
    let d = a.handoff(&green).unwrap_or_else(|e| panic!("{e:#}"));
    assert_eq!(a.mode(), MODE_HANDED_OFF, "a still serves");
    assert_eq!(
        a.handoff(&green).ok(),
        Some(d.clone()),
        "a second handoff for the same roster isn't the same"
    );
    pl(b.takeover(&d));
    assert_eq!(
        a.component_identity().signing_key,
        b.component_identity().signing_key,
        "b doesn't serve with the keys the seed derives"
    );
    assert_eq!(b.unlocked_values("default"), Some(test_values("default")));
    assert!(
        pl(b.takeover(&d))["again"] == true,
        "the same handoff again isn't answered the same"
    );
    // a frozen source serves nothing (its HTTP surface refuses every call but these) and hands over to no other roster
    assert!(
        !allowed_in("POST /keys") && !allowed_in("POST /pull"),
        "a handed-off secrets still answers"
    );
    let c2 = Secrets::new(&w.root.public_key(), None);
    assert!(
        a.handoff(&other_copy(&w, &a, &c2)).is_err(),
        "a frozen secrets handed over to a second roster"
    );
}

/// ✱ a takeover is refused when the handoff is for another roster, is signed by another key than the roster's
/// secrets, when the roster doesn't name this secrets to take over, or once it is set up
#[test]
fn a_takeover_refuses_other_handoffs() {
    let w = World::new();
    let (master, p, root) = (Phone::new(), Phone::new(), Phone::new());
    let a = Secrets::new(&w.root.public_key(), None);
    seeded_claim(&a, &master, &p, &root, &rand32());
    roster_for(&w, &a);
    let b = Secrets::new(&w.root.public_key(), None);
    let c = Secrets::new(&w.root.public_key(), None);
    let (for_b, for_c) = (other_copy(&w, &a, &b), other_copy(&w, &a, &c));
    c.set_roster(for_c).unwrap_or_else(|e| panic!("{e:#}"));
    let d = a.handoff(&for_b).unwrap_or_else(|e| panic!("{e:#}"));
    let e = c
        .takeover(&d)
        .err()
        .map(|e| format!("{e:#}"))
        .unwrap_or_default();
    assert!(
        e.contains("another roster"),
        "a handoff to another roster was taken: {e}"
    );
    b.set_roster(for_b).unwrap_or_else(|e| panic!("{e:#}"));
    let mut forged = d.clone();
    forged.sig = Signer::generate().sign(d.payload.as_bytes());
    let e = b
        .takeover(&forged)
        .err()
        .map(|e| format!("{e:#}"))
        .unwrap_or_default();
    assert!(
        e.contains("isn't signed by the secrets"),
        "a handoff not signed by the roster's secrets was taken: {e}"
    );
    pl(b.takeover(&d));
    let twice = Doc {
        payload: format!("{} ", d.payload),
        sig: d.sig.clone(),
    };
    assert!(
        b.takeover(&twice).is_err(),
        "a set-up secrets took a second handoff"
    );
    // a roster that names no secretsBoot: nobody empty takes over
    let none = sign_roster(
        &w.root,
        &Roster {
            copy: "green".into(),
            members: vec![a.component_identity()],
            ..Default::default()
        },
    );
    let a2 = Secrets::new(&w.root.public_key(), None);
    seeded_claim(&a2, &master, &p, &root, &rand32());
    roster_for(&w, &a2);
    assert!(
        a2.handoff(&none).is_err(),
        "a handoff to a roster with no secrets to take over"
    );
}

/// a restore is the router writing an earlier entry back with secrets' own receipt for it (writer "replay"): the entry
/// comes back with the writer and time the receipt names; ✱ a receipt of another entry, ✱ one another key signed, ✱ a
/// delete's receipt, ✱ a repo's deploy-key store, ✱ a store that doesn't exist; a replayed delete needs no receipt
#[test]
fn a_replay_puts_an_earlier_entry_back() {
    let (c, p, _) = setup();
    let v1 = seal_key(&c, &p, "default", "A", "first");
    let r1 = c
        .write_key(WriteKeyInput {
            store: "default".into(),
            key: "A".into(),
            wrapped: v1.wrapped.clone(),
            data: v1.data.clone(),
            writer: "setup".into(),
            sig: "c2lnMQ==".into(),
            backup_sha256: "a".repeat(64),
            ..Default::default()
        })
        .unwrap_or_else(|e| panic!("{e:#}"));
    let first: Value = serde_json::from_str(&r1.payload).unwrap_or_default();
    let backup = first["backupSha256"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    pl(setup_write(&c, &seal_key(&c, &p, "default", "A", "second")));
    assert_eq!(s(&store_of(&c, &p, "default"), "A"), "second");
    let replay = |x: &KeyEntry, backup: &str, r: Option<Doc>| {
        c.write_key(WriteKeyInput {
            store: x.store.clone(),
            key: x.key.clone(),
            wrapped: x.wrapped.clone(),
            data: x.data.clone(),
            backup_sha256: backup.into(),
            writer: "replay".into(),
            receipt: r,
            ..Default::default()
        })
    };
    let other = seal_key(&c, &p, "default", "A", "other");
    let fs = Signer::generate().sign(r1.payload.as_bytes());
    let del = c
        .write_key(WriteKeyInput {
            store: "default".into(),
            key: "B".into(),
            delete: true,
            writer: "setup".into(),
            sig: "c2ln".into(),
            ..Default::default()
        })
        .unwrap_or_else(|e| panic!("{e:#}"));
    let mut v_c = v1.clone();
    v_c.key = "C".into();
    for (name, r) in [
        ("no receipt", replay(&v1, &backup, None)),
        (
            "another entry's receipt",
            replay(&other, &backup, Some(r1.clone())),
        ),
        ("another backup", replay(&v1, "", Some(r1.clone()))),
        (
            "a receipt another key signed",
            replay(
                &v1,
                &backup,
                Some(Doc {
                    payload: r1.payload.clone(),
                    sig: fs.clone(),
                }),
            ),
        ),
        (
            "a delete's receipt",
            replay(&v1, &backup, Some(del.clone())),
        ),
        (
            "another key's receipt",
            replay(&v_c, &backup, Some(r1.clone())),
        ),
    ] {
        assert!(r.is_err(), "{name}: replayed");
    }
    let again = replay(&v1, &backup, Some(r1.clone())).unwrap_or_else(|e| panic!("{e:#}"));
    let out: Value = serde_json::from_str(&again.payload).unwrap_or_default();
    assert!(
        out["kind"] == "key-written"
            && out["writer"]["by"] == "setup"
            && out["writer"]["sig"] == "c2lnMQ=="
            && out["at"] == first["at"]
            && !out["replayedAt"].is_null(),
        "the replay's receipt: {out}"
    );
    {
        let g = c.lock();
        let x = &g.stores["default"]["A"];
        let w = x.writer.clone().unwrap_or_default();
        assert!(
            w.by == "setup"
                && w.sig == "c2lnMQ=="
                && x.at == first["at"].as_str().unwrap_or_default()
                && x.backup_sha256 == backup,
            "the entry put back: {x:?}"
        );
    }
    assert_eq!(
        s(&store_of(&c, &p, "default"), "A"),
        "first",
        "the earlier value isn't back"
    );
    // the replay's own receipt replays too (a restore of a restore)
    pl(setup_write(&c, &seal_key(&c, &p, "default", "A", "third")));
    pl(replay(&v1, &backup, Some(again)));
    assert_eq!(
        s(&store_of(&c, &p, "default"), "A"),
        "first",
        "a replay's receipt didn't replay"
    );
    // a replayed delete
    pl(c.write_key(WriteKeyInput {
        store: "default".into(),
        key: "A".into(),
        delete: true,
        writer: "replay".into(),
        ..Default::default()
    }));
    assert!(
        !c.lock().stores["default"].contains_key("A"),
        "the replayed delete left the key"
    );
    // never into a store that isn't there, nor a repo's deploy-key store
    let nowhere = seal_key(&c, &p, "nowhere", "A", "x");
    assert!(
        replay(&nowhere, "", Some(r1.clone())).is_err(),
        "a replay made a store"
    );
    c.lock()
        .repo_owner
        .insert("default".into(), "DE0CH/x".into());
    let e = replay(&v1, &backup, Some(r1))
        .err()
        .map(|e| format!("{e:#}"))
        .unwrap_or_default();
    assert!(
        e.contains("deploy-key"),
        "a replay into a repo's store: {e}"
    );
}
