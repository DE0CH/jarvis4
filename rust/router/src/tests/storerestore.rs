//! storerestore_test.go
use super::storedocs::{BucketState, store_router};
use crate::storedocs::backup_sha;
use crate::storerestore::REQUEST_KIND_RESTORE;
use crate::testutil::*;
use jarvis_nethttp::{write_error, write_json};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

/// the core's restore primitives as the router sees them (the core does the real checks)
#[derive(Default)]
struct RestoreState {
    /// answer finish with this status
    refuse: u16,
    /// a backup whose hash isn't the receipt's
    bad_backup: bool,
    calls: Vec<String>,
    puts_at_commit: usize,
}

struct RestoreRig {
    sr: super::storedocs::StoreRig,
    c: Arc<Mutex<RestoreState>>,
    _srv: TestServer,
}

fn restore_router() -> RestoreRig {
    let sr = store_router();
    let key = Arc::new(TestKey::new());
    let c: Arc<Mutex<RestoreState>> = Arc::default();
    let (c2, k, bucket) = (c.clone(), key.clone(), sr.fb.st.clone());
    let srv = TestServer::handler(move |w, req| {
        let b: Value = serde_json::from_slice(&req.read_body(1 << 20)).unwrap_or_default();
        let mut c = c2.lock().unwrap_or_else(|e| e.into_inner());
        c.calls.push(req.path.clone());
        match req.path.as_str() {
            "/identity" => write_json(
                w,
                200,
                &json!({"signingKey": k.public(),
                "state": k.doc(&json!({"kind": "core-state", "master": "M"}))}),
            ),
            "/stores/restore/finish" => {
                if c.refuse != 0 {
                    return write_json(
                        w,
                        c.refuse,
                        &k.doc(
                            &json!({"error": "the iPhone's signature doesn't cover this restore"}),
                        ),
                    );
                }
                let sha = if c.bad_backup {
                    backup_sha("X", "Y")
                } else {
                    backup_sha("BE", "BD")
                };
                write_json(
                    w,
                    200,
                    &json!({
                    "receipt": k.doc(&json!({"kind": "store-restore-approved", "pending": b["pending"], "store": "default",
                        "from": 4, "to": 2, "put": [{"key": "A", "e": "E", "dataSha256": "d", "backupSha256": sha}],
                        "remove": ["Z"], "begin": "{}", "phoneSig": "S"})),
                    "backups": {"A": {"e": "BE", "data": "BD", "sha256": backup_sha("BE", "BD")}}}),
                );
            }
            "/stores/restore/commit" => {
                c.puts_at_commit = bucket.lock().unwrap_or_else(|e| e.into_inner()).puts.len();
                write_json(
                    w,
                    200,
                    &k.doc(
                        &json!({"kind": "store-restored", "store": "default", "from": 2, "seq": 5}),
                    ),
                );
            }
            "/stores/versions" => write_json(
                w,
                200,
                &k.doc(&json!({"kind": "store-versions", "store": "default"})),
            ),
            _ => write_error(w, 404, "404 page not found"),
        }
    });
    sr.r.core.set_url(&srv.url);
    RestoreRig { sr, c, _srv: srv }
}

const FINISH_BODY: &str =
    r#"{"pending":"p1","signature":"sig","shares":{"A":{"e":"x","data":"y"}}}"#;

/// the phone's approval: the core's backups into the bucket first, then the commit; the sessions holding the store are
/// asked to refresh and a restore request for the store leaves the Inbox
#[test]
fn a_restore_writes_its_backups_before_the_commit() {
    let rr = restore_router();
    let r = &rr.sr.r;
    add_session(r, "sA", "started", "mA", false);
    r.st.do_(|d| {
        if let Some(s) = d.sessions.get_mut("sA") {
            s.stores = Some(vec!["default".into()]);
        }
    });
    let (code, out) = app_do(
        r,
        "POST",
        "/api/requests/restore",
        r#"{"store":"default","seq":2}"#,
        &[],
    );
    assert_eq!(code, 200, "{out}");
    let (code, out) = app_do(r, "POST", "/api/stores/restore/finish", FINISH_BODY, &[]);
    assert!(code == 200 && !out["restored"].is_null(), "{code} {out}");
    let at_commit =
        rr.c.lock()
            .unwrap_or_else(|e| e.into_inner())
            .puts_at_commit;
    let puts = rr.sr.fb.get(|b| b.puts.clone());
    assert!(
        at_commit == 2 && puts.join(",") == "keys/default/A.json,keys/default/Z.json",
        "puts {puts:?} (at commit {at_commit})"
    );
    let obj = |k: &str, b: &BucketState| -> Value {
        serde_json::from_slice(b.objs.get(k).map_or(&[][..], |v| v)).unwrap_or_default()
    };
    let (a, z) = rr
        .sr
        .fb
        .get(|b| (obj("keys/default/A.json", b), obj("keys/default/Z.json", b)));
    let w = &a["writer"];
    assert!(
        a["kind"] == "key-backup"
            && a["deleted"] == false
            && a["backupSha256"] == backup_sha("BE", "BD").as_str()
            && w["by"] == "restore"
            && !w["receipt"].is_null()
            && !a["core"].is_null(),
        "A: {a}"
    );
    assert!(z["deleted"] == true && z["sealed"].is_null(), "Z: {z}");
    let asked = out["refreshAsked"].as_array().cloned().unwrap_or_default();
    assert!(
        asked.len() == 1 && asked[0] == "sA",
        "refresh {}",
        out["refreshAsked"]
    );
    for it in r.inbox() {
        assert_ne!(
            it.kind, REQUEST_KIND_RESTORE,
            "the restore request stayed: {it:?}"
        );
    }
}

#[test]
fn a_restore_without_its_backups_commits_nothing() {
    type Set = fn(&mut RestoreState, &mut BucketState);
    let cases: [(&str, Set); 3] = [
        ("the bucket is down", |_, b| b.down = true),
        ("a backup that isn't the receipt's", |c, _| {
            c.bad_backup = true
        }),
        ("the core refuses the phone's answer", |c, _| c.refuse = 403),
    ];
    for (name, set) in cases {
        let rr = restore_router();
        let r = &rr.sr.r;
        rr.sr
            .fb
            .get(|b| set(&mut rr.c.lock().unwrap_or_else(|e| e.into_inner()), b));
        let (code, _) = app_do(r, "POST", "/api/stores/restore/finish", FINISH_BODY, &[]);
        assert_ne!(code, 200, "{name}: restored");
        let c = rr.c.lock().unwrap_or_else(|e| e.into_inner());
        assert!(
            !c.calls.iter().any(|p| p == "/stores/restore/commit"),
            "{name}: committed"
        );
        if c.refuse != 0 {
            assert!(
                rr.sr.fb.get(|b| b.puts.is_empty()),
                "{name}: backups written"
            );
        }
    }
}

/// who may ask for a restore: the web page, the app, the setup session, and a session (Deyao reviews it on its own
/// page; in a batch it is filed beside the batch)
#[test]
fn who_may_ask_for_a_restore() {
    let rr = restore_router();
    let r = &rr.sr.r;
    add_session(r, "sA", "started", "mA", false);
    let (code, out) = app_do(
        r,
        "POST",
        "/setup/requests/restore",
        r#"{"store":"default","seq":2,"explanation":"put the keys back"}"#,
        &[],
    );
    assert_eq!(code, 200, "setup: {out}");
    assert_eq!(
        app_do(
            r,
            "POST",
            "/api/requests/restore",
            r#"{"store":"default"}"#,
            &[]
        )
        .0,
        400,
        "a restore with no version was filed"
    );
    assert_eq!(
        app_do(
            r,
            "POST",
            "/api/requests/restore",
            r#"{"store":"core","seq":1}"#,
            &[]
        )
        .0,
        400,
        "a restore of the core store was filed"
    );
    let m = new_test_machine(r, "mA");
    let (code, out) = m.do_(
        &rr.sr.t.machine_handler(),
        "POST",
        "/m/api/requests/restore",
        r#"{"store":"default","seq":2,"explanation":"x"}"#,
    );
    assert!(
        code == 200 && out["duplicate"] == true,
        "a session's restore: {code} {out}"
    );
    let (code, out) = app_do(
        r,
        "POST",
        "/setup/requests/batch",
        r#"{"summary":"s","items":[{"intent":"restore","store":"default","seq":2,"explanation":"put the keys back"}]}"#,
        &[],
    );
    assert!(
        code == 200 && out["id"].is_null(),
        "a restore in a batch: {code} {out}"
    );
    let it = &out["items"][0];
    assert!(
        it["own"] == true && it["duplicate"] == true,
        "the restore item: {it}"
    );
    let found = r.inbox().into_iter().any(|it| {
        it.kind == REQUEST_KIND_RESTORE
            && it.open["kind"] == "restore"
            && it.open["options"]["store"] == "default"
            && it.open["options"]["seq"] == 2
            && it.call.args.get("seq") == Some(&json!(2))
    });
    assert!(
        found,
        "the restore request isn't in the Inbox with its store and version"
    );
    assert_eq!(
        app_do(
            r,
            "POST",
            "/setup/stores/versions",
            r#"{"store":"default","nonce":"n"}"#,
            &[]
        )
        .0,
        200,
        "setup versions"
    );
    assert_eq!(
        app_do(
            r,
            "POST",
            "/api/core/stores/versions",
            r#"{"store":"default","nonce":"n"}"#,
            &[]
        )
        .0,
        200,
        "app versions"
    );
}
