//! Go and Rust agree byte for byte: tests/vectors/go.json is what the Go kernel's sig made (before its cut, 2026-11-26),
//! checked here; tests/vectors/rust.json is what this crate made, checked by the Go test.
//! `GEN_RUST_VECTORS=1 cargo test -p jarvis-sig --test vectors` writes rust.json again.
#![allow(clippy::unwrap_used)]

use jarvis_sig::{Doc, Opener, Sealed, Signer, seal_to, verify};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Vectors {
    signing_key: String,
    payload: String,
    sigs: Vec<String>,
    doc: Doc,
    recipient_scalar: String,
    info: String,
    plain: String,
    sealed: Sealed,
}

fn dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

#[test]
fn go_made_vectors_check_here() {
    let v: Vectors =
        serde_json::from_slice(&std::fs::read(dir().join("go.json")).unwrap()).unwrap();
    for (i, s) in v.sigs.iter().enumerate() {
        assert!(
            verify(&v.signing_key, v.payload.as_bytes(), s),
            "Go signature {i} doesn't verify"
        );
    }
    let d: BTreeMap<String, serde_json::Value> = v.doc.open(&v.signing_key).unwrap();
    assert_eq!(d["b"], "two");
    let o = Opener::from_scalar(&hex::decode(&v.recipient_scalar).unwrap()).unwrap();
    assert_eq!(o.open(&v.sealed, &v.info).unwrap(), v.plain.as_bytes());
}

#[test]
fn rust_vectors_write() {
    if std::env::var("GEN_RUST_VECTORS").as_deref() != Ok("1") {
        return;
    }
    let s = Signer::generate();
    let payload = r#"{"kind":"vector","n":1}"#.to_string();
    let recipient_scalar =
        "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721".to_string();
    let o = Opener::from_scalar(&hex::decode(&recipient_scalar).unwrap()).unwrap();
    let (info, plain) = (
        "jarvis4 rust vectors".to_string(),
        "the plain text".to_string(),
    );
    let v = Vectors {
        signing_key: s.public_key(),
        sigs: (0..16).map(|_| s.sign(payload.as_bytes())).collect(),
        payload,
        doc: s
            .sign_json(&serde_json::json!({"a": 1, "b": "two"}))
            .unwrap(),
        sealed: seal_to(&o.public_key(), plain.as_bytes(), &info).unwrap(),
        recipient_scalar,
        info,
        plain,
    };
    std::fs::write(
        dir().join("rust.json"),
        serde_json::to_string_pretty(&v).unwrap() + "\n",
    )
    .unwrap();
}
