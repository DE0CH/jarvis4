//! A Go secrets' copy flip taken by the Rust secrets (kernel/secrets/rustvec_test.go writes the vector): the kernel's
//! cut is a copy flip from a Go secrets to a Rust one, so the Rust one must take Go's handoff whole — the derived keys,
//! the claim's keys, every store and the open unlocks — and open the stores with the phone's share afterwards.

use jarvis_kernel::secrets::Secrets;
use jarvis_kernel::secrets::crypto::scalar_mult;
use jarvis_sig::{Doc, Opener, Signer, b64, seal_to, unb64};
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Keys {
    signing_key: String,
    agreement_key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct V {
    root: String,
    green: Doc,
    boot_signing: String,
    boot_agreement: String,
    handoff: Doc,
    derived: Keys,
    master: String,
    root_key: String,
    phone: Keys,
    unlocked: BTreeMap<String, String>,
    stores: Vec<String>,
    final_seq: i64,
    phone_agreement: String,
}

fn vectors() -> V {
    let b = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/secrets-handoff.json"
    ))
    .unwrap_or_else(|e| panic!("{e}"));
    serde_json::from_slice(&b).unwrap_or_else(|e| panic!("{e}"))
}

fn payload(d: &Doc) -> serde_json::Value {
    serde_json::from_str(&d.payload).unwrap_or_default()
}

#[test]
fn a_rust_secrets_takes_a_go_secrets_handoff() {
    let v = vectors();
    let signer = Signer::from_scalar(&unb64(&v.boot_signing).unwrap_or_default())
        .unwrap_or_else(|e| panic!("{e}"));
    let agreement = Opener::from_scalar(&unb64(&v.boot_agreement).unwrap_or_default())
        .unwrap_or_else(|e| panic!("{e}"));
    let s = Secrets::with_keys(&v.root, signer, agreement, None);
    s.set_roster(v.green.clone())
        .unwrap_or_else(|e| panic!("the green roster: {e:#}"));
    let out = s
        .takeover(&v.handoff)
        .unwrap_or_else(|e| panic!("the takeover: {e:#}"));
    let o = payload(&out);
    assert!(
        o["kind"] == "took-over" && o["lineSeq"] == v.final_seq,
        "{o}"
    );
    // the keys the seed derives, the claim's keys
    let id = s.component_identity();
    assert_eq!(
        (id.signing_key.as_str(), id.agreement_key.as_str()),
        (
            v.derived.signing_key.as_str(),
            v.derived.agreement_key.as_str()
        )
    );
    let k = payload(&s.keys_statement().unwrap_or_else(|e| panic!("{e:#}")));
    assert!(
        k["phone"] == v.phone.signing_key.as_str() && k["root"] == v.root_key.as_str(),
        "{k}"
    );
    let st = payload(
        &serde_json::from_value::<Doc>(s.identity().unwrap_or_default()["state"].clone())
            .unwrap_or_default(),
    );
    assert!(
        st["master"] == v.master.as_str() && st["derived"] == true && st["serving"] == "serving",
        "{st}"
    );
    // every store, and the open unlock as it was
    let stores = payload(&s.stores("n").unwrap_or_else(|e| panic!("{e:#}")));
    let names: Vec<String> = stores["stores"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|r| r["name"].as_str().unwrap_or_default().to_string())
        .collect();
    assert_eq!(names, v.stores);
    assert_eq!(s.unlocked_values("default"), Some(v.unlocked.clone()));
    // the same handoff again: the same answer, nothing changed
    let again = payload(&s.takeover(&v.handoff).unwrap_or_else(|e| panic!("{e:#}")));
    assert!(again["again"] == true, "{again}");
    // the stores open with the phone's share under the derived K: unlock gmail as the phone would
    let begin = payload(&s.unlock_begin("gmail").unwrap_or_else(|e| panic!("{e:#}")));
    let t = begin["t"].as_str().unwrap_or_default();
    let p = unb64(&v.phone_agreement).unwrap_or_default();
    let mut shares = BTreeMap::new();
    for row in begin["keys"].as_array().cloned().unwrap_or_default() {
        let e = unb64(row["e"].as_str().unwrap_or_default()).unwrap_or_default();
        let pe = scalar_mult(&p, &e).unwrap_or_else(|e| panic!("{e:#}"));
        shares.insert(
            row["key"].as_str().unwrap_or_default().to_string(),
            seal_to(t, &pe[1..33], "jarvis2/unlock-share").unwrap_or_else(|e| panic!("{e}")),
        );
    }
    s.unlock_finish(begin["pending"].as_str().unwrap_or_default(), &shares)
        .unwrap_or_else(|e| panic!("unlocking gmail after the takeover: {e:#}"));
    assert_eq!(
        s.unlocked_values("gmail"),
        Some(BTreeMap::from([("G".to_string(), "secret".to_string())]))
    );
    // its own line state goes on from Go's numbering
    let ls = s.line_state().unwrap_or_else(|e| panic!("{e:#}"));
    assert!(
        payload(&ls.head)["seq"] == v.final_seq + 1,
        "{}",
        ls.head.payload
    );
    let _ = b64(b"");
}
