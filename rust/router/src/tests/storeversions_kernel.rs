//! storeversions_test.go's kernel test: a restore on a box with no core replays the earlier entry into the kernel's
//! secrets (the whole kernel in-process)
use super::storedocs::FakeBucket;
use crate::storedocs::backup_sha;
use crate::testutil::*;
use jarvis_kernel::kerneltest::Kernel;
use serde_json::{Value, json};
use std::collections::BTreeMap;

fn hex_sha(s: &str) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(s.as_bytes()))
}

fn kw_body(data: &str, be: &str) -> String {
    json!({"wrapped": {"e": format!("E{data}"), "wrapped": "W"}, "data": data,
        "backup": {"e": be, "data": "BD"}, "backupSha256": backup_sha(be, "BD"), "sig": format!("S{data}"),
        "explanation": "a key"})
    .to_string()
}

/// the kernel's secrets keeps no history (DECISIONS 232): the router keeps each version with secrets' receipts, and a
/// restore writes the earlier entry back with its receipt (writer "replay"), its backup back into the bucket first, and
/// deletes the keys the earlier version didn't have; secrets keeps the writer the receipt names
#[test]
fn a_kernel_restore_replays_the_earlier_entry() {
    let _s = serial();
    let k = Kernel::start(BTreeMap::new());
    let front = k.front.clone();
    let t = new_test_router_with(
        move |c| {
            c.no_core = true;
            c.kernel_url = format!("{front}/%s");
        },
        Some("http://core.invalid:8090"),
        Default::default(),
    );
    let r = t.r.clone();
    r.wire_kernel();
    let fb = FakeBucket::new();
    *r.backup_override.write().unwrap_or_else(|e| e.into_inner()) = Some(fb.bucket());
    add_session(&r, "sA", "started", "mA", false);
    r.st.do_(|d| {
        if let Some(s) = d.sessions.get_mut("sA") {
            s.stores = Some(vec!["default".into()]);
        }
    });
    let mut v1_backup = vec![]; // A's backup at version 1, overwritten since: the router kept it
    for (i, (key, data, be)) in [("A", "D1", "BE1"), ("A", "D2", "BE2"), ("B", "D3", "BE3")]
        .into_iter()
        .enumerate()
    {
        let (code, out) = app_do(
            &r,
            "POST",
            &format!("/setup/stores/default/keys/{key}"),
            &kw_body(data, be),
            &[],
        );
        assert_eq!(code, 200, "write {key}: {out}");
        if i == 0 {
            v1_backup = fb.get(|b| {
                b.objs
                    .get("keys/default/A.json")
                    .cloned()
                    .unwrap_or_default()
            });
        }
    }
    let (code, out) = app_do(
        &r,
        "POST",
        "/api/core/stores/versions",
        r#"{"store":"default","nonce":"n1"}"#,
        &[],
    );
    let vs = out["versions"].as_array().cloned().unwrap_or_default();
    assert!(
        code == 200 && out["kind"] == "store-versions" && out["nonce"] == "n1" && vs.len() == 3,
        "versions: {code} {out}"
    );
    let oldest = &vs[2];
    let row = &oldest["keys"][0];
    assert!(
        oldest["seq"] == 1
            && oldest["keys"].as_array().map(Vec::len) == Some(1)
            && row["name"] == "A"
            && row["dataSha256"] == hex_sha("D1").as_str()
            && !row["receipt"].is_null(),
        "version 1: {oldest}"
    );
    // the receipt is secrets' own signature
    let rc: jarvis_sig::Doc =
        serde_json::from_value(row["receipt"].clone()).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        jarvis_sig::verify(
            &k.identity("secrets").signing_key,
            rc.payload.as_bytes(),
            &rc.sig
        ),
        "the receipt isn't secrets'"
    );
    let (code, out) = app_do(
        &r,
        "POST",
        "/api/core/stores/restore/begin",
        r#"{"store":"default","seq":1}"#,
        &[],
    );
    let put = out["put"].as_array().cloned().unwrap_or_default();
    assert!(
        code == 200
            && out["replay"] == true
            && put.len() == 1
            && put[0]["key"] == "A"
            && out["remove"].as_array().map(Vec::len) == Some(1),
        "begin: {code} {out}"
    );
    let pending = out["pending"].as_str().unwrap_or_default().to_string();
    let (code, out) = app_do(
        &r,
        "POST",
        "/api/stores/restore/finish",
        &json!({"pending": pending}).to_string(),
        &[],
    );
    let done = out["restored"].clone();
    assert!(
        code == 200 && done["kind"] == "store-restored" && done["from"] == 1 && done["seq"] == 4,
        "finish: {code} {out}"
    );
    // secrets holds version 1's entry, with its writer; B is gone
    let ub = k
        .secrets
        .unlock_begin("default")
        .unwrap_or_else(|e| panic!("{e:#}"));
    let u: Value = serde_json::from_str(&ub.payload).unwrap_or_default();
    let keys = u["keys"].as_array().cloned().unwrap_or_default();
    assert!(
        keys.len() == 1
            && keys[0]["key"] == "A"
            && keys[0]["dataSha256"] == hex_sha("D1").as_str()
            && keys[0]["writer"]["by"] == "setup"
            && keys[0]["writer"]["sig"] == "SD1",
        "secrets after the restore: {keys:?}"
    );
    // the bucket: version 1's backup of A back; B's delete marker over its last backup, its writer secrets' receipt of
    // the delete (what the app's Recover checks against the secrets its kit derives), so a Recover leaves B out
    let a1: Value = serde_json::from_slice(&v1_backup).unwrap_or_default();
    let a_now: Value = fb.get(|b| {
        serde_json::from_slice(
            b.objs
                .get("keys/default/A.json")
                .map(Vec::as_slice)
                .unwrap_or_default(),
        )
        .unwrap_or_default()
    });
    assert!(
        a_now["dataSha256"] == hex_sha("D1").as_str()
            && a_now["backupSha256"] == a1["backupSha256"]
            && a_now["at"] == a1["at"],
        "A's backup isn't version 1's: {a_now}"
    );
    let bobj: Value = fb.get(|b| {
        serde_json::from_slice(
            b.objs
                .get("keys/default/B.json")
                .map(Vec::as_slice)
                .unwrap_or_default(),
        )
        .unwrap_or_default()
    });
    let brd: Option<jarvis_sig::Doc> =
        serde_json::from_value(bobj["writer"]["receipt"].clone()).ok();
    let brc: Option<crate::storeversions::KeyReceipt> = brd
        .as_ref()
        .and_then(|d| serde_json::from_str(&d.payload).ok());
    assert!(
        bobj["deleted"] == true
            && bobj["kind"] == "key-backup"
            && bobj["key"] == "B"
            && bobj["sealed"].is_null()
            && bobj["dataSha256"].as_str().unwrap_or_default().is_empty()
            && bobj["writer"]["by"] == "replay"
            && brc.is_some(),
        "B's delete marker: {bobj}"
    );
    let (brd, brc) = (
        brd.unwrap_or_else(|| panic!("no receipt")),
        brc.unwrap_or_default(),
    );
    assert!(
        jarvis_sig::verify(
            &k.identity("secrets").signing_key,
            brd.payload.as_bytes(),
            &brd.sig
        ) && brc.kind == "key-written"
            && brc.deleted
            && brc.store == "default"
            && brc.key == "B",
        "the marker's receipt isn't secrets' of B's delete: {brc:?}"
    );
    assert_eq!(
        out["refreshAsked"].as_array().map(Vec::len),
        Some(1),
        "refresh {}",
        out["refreshAsked"]
    );
    // a pending is used once; a version already current is refused
    let (code, _) = app_do(
        &r,
        "POST",
        "/api/stores/restore/finish",
        &json!({"pending": done["pending"]}).to_string(),
        &[],
    );
    assert_eq!(code, 404, "a pending twice");
    let (code, _) = app_do(
        &r,
        "POST",
        "/api/core/stores/restore/begin",
        r#"{"store":"default","seq":4}"#,
        &[],
    );
    assert_eq!(code, 409, "the current version");
    // the setup session reads the same list
    let (code, out) = app_do(
        &r,
        "POST",
        "/setup/stores/versions",
        r#"{"store":"default","nonce":"n2"}"#,
        &[],
    );
    assert!(
        code == 200 && out["versions"].as_array().map(Vec::len) == Some(4),
        "setup versions: {code} {out}"
    );
}
