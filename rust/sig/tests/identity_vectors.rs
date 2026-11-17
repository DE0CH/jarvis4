//! identity.rs against Go's kernel/sig identity.go and storekey.go (kernel/sig/rustidvec_test.go): go-identity.json is
//! what Go made, checked here; rust-identity.json what this crate made, checked by the Go test.
//! `GEN_RUST_VECTORS=1 cargo test -p jarvis-sig --test identity_vectors` writes rust-identity.json again.
#![allow(clippy::unwrap_used)]

use jarvis_sig::{
    Component, Doc, Roster, Signer, Trust, check_identity, go_json, open_roster, store_key,
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Vectors {
    root: String,
    roster: Doc,
    payload: String,
    unsorted: Roster,
    phone: String,
    secrets: String,
    store_key: String,
    plain: String,
    escaped: String,
}

fn dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

#[test]
fn go_made_identity_vectors_check_here() {
    let v: Vectors =
        serde_json::from_slice(&std::fs::read(dir().join("go-identity.json")).unwrap()).unwrap();
    let r = open_roster(&v.roster, &v.root).unwrap();
    assert_eq!(v.unsorted.payload().unwrap(), v.payload);
    assert_eq!(v.payload, v.roster.payload);
    assert_eq!(r.payload().unwrap(), v.payload);
    let t = Trust::new(&v.root);
    t.set(v.roster.clone(), None).unwrap();
    let ret = &r.retired[0];
    check_identity(ret, &ret.role, &t).unwrap();
    let boot = r.secrets_boot.clone().unwrap();
    assert!(t.set(v.roster.clone(), Some(&boot)).is_ok(), "secretsBoot");
    assert!(
        check_identity(&boot, "secrets", &t).is_err(),
        "secretsBoot isn't a member"
    );
    assert_eq!(store_key(&v.phone, &v.secrets).unwrap(), v.store_key);
    assert_eq!(store_key(&v.secrets, &v.phone).unwrap(), v.store_key);
    assert!(store_key("AAAA", &v.secrets).is_err());
    assert_eq!(go_json(&v.plain).unwrap(), v.escaped);
}

#[test]
fn rust_identity_vectors_write() {
    if std::env::var("GEN_RUST_VECTORS").as_deref() != Ok("1") {
        return;
    }
    let root = Signer::generate();
    let cs: Vec<Component> = ["secrets", "notary", "mover", "merger", "mover", "notary"]
        .iter()
        .map(|r| Component::new(r))
        .collect();
    let unsorted = Roster {
        kind: String::new(),
        copy: "blue".into(),
        members: vec![
            cs[3].identity.clone(),
            cs[1].identity.clone(),
            cs[0].identity.clone(),
            cs[2].identity.clone(),
        ],
        retired: vec![cs[5].identity.clone(), cs[4].identity.clone()],
        secrets_boot: Some(Component::new("secrets").identity),
    };
    let payload = unsorted.payload().unwrap();
    let roster = Doc {
        sig: root.sign(payload.as_bytes()),
        payload: payload.clone(),
    };
    let (p, k) = (Component::new("phone"), Component::new("secrets"));
    let plain = "a <b> & c \u{2028}\u{2029} é".to_string();
    let v = Vectors {
        root: root.public_key(),
        roster,
        payload,
        unsorted,
        store_key: store_key(&p.identity.agreement_key, &k.identity.agreement_key).unwrap(),
        phone: p.identity.agreement_key,
        secrets: k.identity.agreement_key,
        escaped: go_json(&plain).unwrap(),
        plain,
    };
    std::fs::write(
        dir().join("rust-identity.json"),
        serde_json::to_string_pretty(&v).unwrap() + "\n",
    )
    .unwrap();
}
