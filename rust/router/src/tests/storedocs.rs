//! storedocs_test.go
use crate::backups::BackupBucket;
use crate::nethttp::{write_error, write_json};
use crate::router::Router;
use crate::storedocs::backup_sha;
use crate::testutil::*;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// a core with stores made of keys
#[derive(Default)]
pub struct StoreCoreState {
    pub writes: Vec<Value>,
    /// answer write-key with this status
    pub fail: u16,
}

pub struct StoreCore {
    pub key: Arc<TestKey>,
    pub st: Arc<Mutex<StoreCoreState>>,
    pub srv: TestServer,
}

impl StoreCore {
    pub fn new() -> StoreCore {
        let key = Arc::new(TestKey::new());
        let st: Arc<Mutex<StoreCoreState>> = Arc::default();
        let (k, s2) = (key.clone(), st.clone());
        let srv = TestServer::handler(move |w, req| {
            let b = req.read_body(1 << 20);
            let mut c = s2.lock().unwrap_or_else(|e| e.into_inner());
            match req.path.as_str() {
                "/identity" => write_json(w, 200, &json!({"signingKey": k.public(),
                    "state": k.doc(&json!({"kind": "core-state", "master": "M", "phone": {"agreementKey": "P"}}))})),
                "/store-key" => write_json(w, 200, &k.doc(&json!({"kind": "store-key", "phone": "P", "storeKey": "C"}))),
                "/stores" => write_json(w, 200, &k.doc(&json!({"kind": "stores", "nonce": "n", "stores": [
                    {"name": "default", "sensitive": false, "empty": false, "unlocked": true, "keys": [
                        {"name": "EXA_API", "at": "t1", "writer": {"by": "machine", "machine": "mA", "line": "LsA"}},
                        {"name": "OPENROUTER_API", "at": "t0", "writer": {"by": "setup"}}]},
                    {"name": "fresh", "sensitive": false, "empty": true, "unlocked": false, "keys": []},
                    {"name": "github-claude-env", "sensitive": false, "empty": false, "unlocked": false, "keys": [
                        {"name": "GITHUB_DEPLOY_KEY_DE0CH_CLAUDE_ENV", "writer": {"by": "core"}}]}]}))),
                "/stores/write-key" => {
                    if c.fail != 0 {
                        return write_json(w, c.fail, &k.doc(&json!({"error": "refused"})));
                    }
                    let input: Value = serde_json::from_slice(&b).unwrap_or_default();
                    c.writes.push(input.clone());
                    write_json(w, 200, &k.doc(&json!({"kind": "key-written", "store": input["store"], "key": input["key"]})));
                }
                _ => write_error(w, 404, "404 page not found"),
            }
        });
        StoreCore { key, st, srv }
    }

    pub fn writes(&self) -> Vec<Value> {
        self.st
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .writes
            .clone()
    }
}

/// the backup bucket (PUT and GET of objects), recording each version
#[derive(Default)]
pub struct BucketState {
    pub puts: Vec<String>,
    pub objs: BTreeMap<String, Vec<u8>>,
    pub down: bool,
}

pub struct FakeBucket {
    pub st: Arc<Mutex<BucketState>>,
    pub srv: TestServer,
}

impl FakeBucket {
    pub fn new() -> FakeBucket {
        let st: Arc<Mutex<BucketState>> = Arc::default();
        let s2 = st.clone();
        let srv = TestServer::handler(move |w, req| {
            let body = req.read_body(64 << 20);
            let mut b = s2.lock().unwrap_or_else(|e| e.into_inner());
            if b.down {
                w.write_header(503);
                return;
            }
            let key = req
                .path
                .strip_prefix("/jarvis2-backup-de0ch/")
                .unwrap_or(&req.path)
                .to_string();
            match req.method.as_str() {
                "PUT" => {
                    b.puts.push(key.clone());
                    b.objs.insert(key, body);
                }
                "GET" => {
                    let o = b.objs.get(&key).cloned().unwrap_or_default();
                    w.write(&o);
                }
                _ => {}
            }
        });
        FakeBucket { st, srv }
    }

    pub fn get<R>(&self, f: impl FnOnce(&mut BucketState) -> R) -> R {
        f(&mut self.st.lock().unwrap_or_else(|e| e.into_inner()))
    }

    /// the bucket as the router's backup bucket
    pub fn bucket(&self) -> BackupBucket {
        BackupBucket {
            endpoint: self.srv.url.clone(),
            region: "fsn1".into(),
            bucket: "jarvis2-backup-de0ch".into(),
            write: String::new(),
            access_key: "ak".into(),
            secret_key: "sk".into(),
        }
    }
}

pub struct StoreRig {
    pub t: TestRouter,
    pub r: Arc<Router>,
    pub c: StoreCore,
    pub fb: FakeBucket,
}

pub fn store_router() -> StoreRig {
    let t = new_test_router();
    let r = t.r.clone();
    let c = StoreCore::new();
    r.core.set_url(&c.srv.url);
    let fb = FakeBucket::new();
    *r.backup_override.write().unwrap_or_else(|e| e.into_inner()) = Some(fb.bucket());
    StoreRig { t, r, c, fb }
}

fn by_name(rows: &Value) -> BTreeMap<String, Value> {
    rows.as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|m| (m["name"].as_str().unwrap_or_default().to_string(), m))
        .collect()
}

/// names: the shape every session image reads
fn key_names(row: &Value) -> Vec<String> {
    row["keys"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|k| k.as_str().unwrap_or_default().to_string())
                .collect()
        })
        .unwrap_or_default()
}

/// the core's keys with their writers (a machine's line as the session that wrote it) and the explanations
#[test]
fn stores_list_keys_writers_and_explanations() {
    let sr = store_router();
    let r = &sr.r;
    add_session(r, "sA", "started", "mA", false);
    let (code, out) = app_do(
        r,
        "POST",
        "/setup/store-docs",
        r#"{"store":"default","about":"everyday keys","keys":{"EXA_API":"Exa search","OPENROUTER_API":"OpenRouter, every model"}}"#,
        &[],
    );
    assert_eq!(code, 200, "{out}");
    let (code, _) = app_do(
        r,
        "PUT",
        "/api/stores/default/docs",
        r#"{"keys":{"EXA_API":"Exa web search (the exa skill)"}}"#,
        &[],
    );
    assert_eq!(code, 200);
    let long = "a".repeat(1500); // longer than an Inbox explanation, within an explanation of a key
    let (code, out) = app_do(
        r,
        "POST",
        "/setup/store-docs",
        &format!(r#"{{"store":"shopping","about":"{long}"}}"#),
        &[],
    );
    assert_eq!(code, 200, "a 1500-character about text: {out}");
    let (code, _) = app_do(
        r,
        "POST",
        "/setup/store-docs",
        &format!(r#"{{"store":"shopping","about":"{long}{long}"}}"#),
        &[],
    );
    assert_eq!(code, 400, "a 3000-character about text was taken");
    let (code, _) = app_do(
        r,
        "PUT",
        "/api/stores/default/docs",
        r#"{"keys":{"bad name":"x"}}"#,
        &[],
    );
    assert_eq!(code, 400, "a bad key name was documented");
    let check = |(code, out): (u16, Value)| {
        assert!(code == 200 && !out["signed"].is_null(), "{code} {out}");
        let s = by_name(&out["stores"]);
        let d = &s["default"];
        assert_eq!(
            key_names(d).join(","),
            "EXA_API,OPENROUTER_API",
            "default's names: {}",
            d["keys"]
        );
        let ks = &d["keyInfo"];
        let (exa, w) = (&ks[0], &ks[0]["writer"]);
        assert!(
            d["about"] == "everyday keys"
                && d["keysFrom"] == "core"
                && exa["explanation"] == "Exa web search (the exa skill)"
                && w["by"] == "machine"
                && w["session"] == "sA"
                && w["sessionLabel"] == "label sA",
            "default: {d}"
        );
        assert_eq!(
            ks[1]["explanation"], "OpenRouter, every model",
            "default: {d}"
        );
        assert!(
            key_names(&s["fresh"]).is_empty() && s["fresh"]["keys"].is_array(),
            "fresh: {}",
            s["fresh"]
        );
    };
    check(app_do(r, "GET", "/api/stores", "", &[]));
    check(app_do(r, "GET", "/setup/stores/keys", "", &[]));
    let m = new_test_machine(r, "mA");
    check(m.do_(&sr.t.machine_handler(), "GET", "/m/stores", "")); // every session sees every store
}

pub fn write_body(expl: &str) -> String {
    jarvis_go::marshal(&json!({"wrapped": {"e": "E", "wrapped": "W"}, "data": "D",
        "backup": {"e": "BE", "data": "BD"}, "backupSha256": backup_sha("BE", "BD"), "sig": "S", "explanation": expl}))
}

fn err_of(v: &Value) -> String {
    v["error"].as_str().unwrap_or_default().to_string()
}

/// a running session writes one key: the backup first, then the core (with the machine's newest cert), the
/// explanation kept; no request goes to Deyao for the other sessions holding the store
#[test]
fn a_session_writes_a_key() {
    let sr = store_router();
    let (r, c, fb) = (&sr.r, &sr.c, &sr.fb);
    for (id, st, m) in [
        ("sA", "started", "mA"),
        ("sB", "started", "mB"),
        ("sC", "started", "mC"),
        ("sP", "paused", ""),
    ] {
        add_session(r, id, st, m, false);
    }
    r.st.do_(|d| {
        for (id, stores) in [
            ("sB", vec!["default", "gmail"]),
            ("sC", vec!["default"]),
            ("sP", vec!["default"]),
        ] {
            if let Some(s) = d.sessions.get_mut(id) {
                s.stores = Some(stores.iter().map(|x| x.to_string()).collect());
            }
        }
    });
    let m = new_test_machine(r, "mA");
    let h = sr.t.machine_handler();
    let (code, out) = m.do_(
        &h,
        "POST",
        "/m/stores/default/keys/NEW_KEY",
        &write_body(""),
    );
    assert!(
        code == 400 && err_of(&out).contains("explanation"),
        "a new key without an explanation: {code} {out}"
    );
    let bad = write_body("x").replacen(&backup_sha("BE", "BD"), &backup_sha("BE", "other"), 1);
    assert_eq!(
        m.do_(&h, "POST", "/m/stores/default/keys/NEW_KEY", &bad).0,
        400,
        "a backup that isn't the one signed was taken"
    );
    for store in ["core", "github-deploy-keys"] {
        let code = m
            .do_(
                &h,
                "POST",
                &format!("/m/stores/{store}/keys/K"),
                &write_body("x"),
            )
            .0;
        assert_eq!(code, 403, "{store} written");
    }
    assert!(
        fb.get(|b| b.puts.is_empty()) && c.writes().is_empty(),
        "a refused write reached the bucket or the core"
    );
    let (code, out) = m.do_(
        &h,
        "POST",
        "/m/stores/default/keys/NEW_KEY",
        &write_body("The new API's key"),
    );
    assert!(code == 200 && out["ok"] == true, "{code} {out}");
    let puts = fb.get(|b| b.puts.clone());
    assert!(
        puts == ["keys/default/NEW_KEY.json"] && c.writes().len() == 1,
        "puts {puts:?} writes {:?}",
        c.writes()
    );
    let obj: Value = serde_json::from_slice(&fb.get(|b| {
        b.objs
            .get("keys/default/NEW_KEY.json")
            .cloned()
            .unwrap_or_default()
    }))
    .unwrap_or_default();
    let w = &obj["writer"];
    assert!(
        obj["kind"] == "key-backup"
            && obj["explanation"] == "The new API's key"
            && w["by"] == "machine"
            && !w["cert"].is_null()
            && !obj["core"].is_null(),
        "backup {obj}"
    );
    let w0 = &c.writes()[0];
    assert!(
        w0["writer"] == "machine"
            && !w0["cert"].is_null()
            && w0["backupSha256"] == backup_sha("BE", "BD").as_str(),
        "core got {w0}"
    );
    assert_eq!(
        r.read_store_docs()
            .get("default")
            .and_then(|d| d.keys.get("NEW_KEY").cloned())
            .as_deref(),
        Some("The new API's key"),
        "the explanation wasn't kept"
    );
    // sB and sC hold default and run: no request goes to Deyao for them (they get it at their next pull, 2026-10-22)
    assert!(
        out.get("refreshAsked").is_none()
            && r.inbox().is_empty()
            && r.inbox_batches(None).is_empty(),
        "a write filed a request: {out}"
    );
    // a documented key needs no explanation again
    let (code, out) = m.do_(
        &h,
        "POST",
        "/m/stores/default/keys/NEW_KEY",
        &write_body(""),
    );
    assert_eq!(code, 200, "{out}");
    // a paused session writes nothing
    add_session(r, "sQ", "paused", "mQ", false);
    let mq = new_test_machine(r, "mQ");
    assert_eq!(
        mq.do_(&h, "POST", "/m/stores/default/keys/K", &write_body("x"))
            .0,
        403,
        "a session that isn't running wrote"
    );
}

/// no backup, no write: the bucket down leaves the core untouched; the core's refusal comes back as it is
#[test]
fn no_key_without_its_backup() {
    let sr = store_router();
    let (r, c, fb) = (&sr.r, &sr.c, &sr.fb);
    add_session(r, "sA", "started", "mA", false);
    let m = new_test_machine(r, "mA");
    let h = sr.t.machine_handler();
    fb.get(|b| b.down = true);
    let code = m
        .do_(&h, "POST", "/m/stores/default/keys/K", &write_body("x"))
        .0;
    assert!(
        code != 200 && c.writes().is_empty(),
        "a key was written with its backup failing"
    );
    fb.get(|b| b.down = false);
    c.st.lock().unwrap_or_else(|e| e.into_inner()).fail = 403;
    let code = m
        .do_(&h, "POST", "/m/stores/default/keys/K", &write_body("x"))
        .0;
    assert_eq!(code, 403, "the core's refusal came back as {code}");
}

/// the setup session writes the same way, its own signature passed on
#[test]
fn the_setup_session_writes_a_key() {
    let sr = store_router();
    let (r, c) = (&sr.r, &sr.c);
    let (code, out) = app_do(
        r,
        "POST",
        "/setup/stores/infra/keys/K",
        &write_body("a key"),
        &[],
    );
    assert_eq!(code, 200, "{out}");
    let w0 = &c.writes()[0];
    assert!(
        w0["writer"] == "setup" && w0["cert"].is_null(),
        "core got {w0}"
    );
    // the deploy-key token (RUNBOOK: setup.py write github-deploy-keys …; the replica writes its throwaway PAT): the
    // setup session writes it, as the core allows; never the core's own store
    let (code, out) = app_do(
        r,
        "POST",
        "/setup/stores/github-deploy-keys/keys/GITHUB_DEPLOY_KEYS_TOKEN",
        &write_body("the PAT"),
        &[],
    );
    assert_eq!(
        code, 200,
        "the setup session's deploy-key token write: {out}"
    );
    let w1 = &c.writes()[1];
    assert!(
        w1["store"] == "github-deploy-keys" && w1["writer"] == "setup",
        "core got {w1}"
    );
    let (code, _) = app_do(
        r,
        "POST",
        "/setup/stores/core/keys/FLY_API_TOKEN",
        &write_body("x"),
        &[],
    );
    assert_eq!(code, 403, "the core's own store was written key by key");
    let (code, out) = app_do(r, "GET", "/setup/store-key", "", &[]);
    assert!(
        code == 200 && !out["identity"].is_null() && !out["storeKey"].is_null(),
        "{code} {out}"
    );
}

/// the phone's unlock for a running, booted machine's cert makes that machine pull again
#[test]
fn an_unlock_pulls_again() {
    let sr = store_router();
    let (r, c) = (&sr.r, &sr.c);
    add_session(r, "sA", "started", "mA", false);
    let payload = jarvis_go::marshal(&json!({"line": "LsA", "nonce": "N1"}));
    r.st.do_(|d| {
        if let Some(s) = d.sessions.get_mut("sA") {
            s.cert = Some(crate::types::Doc {
                payload: payload.clone(),
                sig: String::new(),
            });
            s.booted = "mA".into();
        }
    });
    let ans = jarvis_go::marshal(
        &c.key
            .doc(&json!({"kind": "unlocked", "for": "N1", "store": "yyc"})),
    );
    r.unlock_arrived(ans.as_bytes());
    assert_eq!(
        wait_cmd(r, "mA", Duration::from_secs(1)).as_deref(),
        Some("refresh-secrets"),
        "the machine wasn't told to pull again"
    );
    let other = jarvis_go::marshal(
        &c.key
            .doc(&json!({"kind": "unlocked", "for": "N2", "store": "yyc"})),
    );
    r.unlock_arrived(other.as_bytes());
    let cmd = take_cmd(r, "mA");
    assert!(cmd.is_none(), "an unlock for another cert sent {cmd:?}");
}
