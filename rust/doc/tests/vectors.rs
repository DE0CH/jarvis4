//! kernel/doc/rustvec_test.go marshalled these documents in Go; each opens here, checks, and marshals again to the
//! same bytes (what a Rust kernel signs must be what the Go kernel signed).
#![allow(clippy::unwrap_used)]

use jarvis_doc::{Cert, Challenge, Grant, Notarized};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Vectors {
    certs: Vec<String>,
    grant: String,
    challenge: String,
    notarized: String,
}

#[test]
fn go_documents_round_trip() {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/go.json");
    let v: Vectors = serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap();
    for c in &v.certs {
        let cert: Cert = serde_json::from_str(c).unwrap();
        cert.check().unwrap();
        assert_eq!(&serde_json::to_string(&cert).unwrap(), c);
    }
    let g: Grant = serde_json::from_str(&v.grant).unwrap();
    g.check().unwrap();
    assert_eq!(serde_json::to_string(&g).unwrap(), v.grant);
    let ch: Challenge = serde_json::from_str(&v.challenge).unwrap();
    assert_eq!(serde_json::to_string(&ch).unwrap(), v.challenge);
    let n: Notarized = serde_json::from_str(&v.notarized).unwrap();
    assert_eq!(serde_json::to_string(&n).unwrap(), v.notarized);
}
