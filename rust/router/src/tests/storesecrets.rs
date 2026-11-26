//! storesecrets_test.go: on a box with no core (NO_CORE=1) the store routes reach the kernel's serving secrets
use super::storedocs::{FakeBucket, write_body};
use crate::nethttp::{write_error, write_json};
use crate::router::Router;
use crate::testutil::*;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

/// one copy's secrets: the core's store routes
#[derive(Default)]
struct Copy {
    writes: Vec<Value>,
}

struct KernelStores {
    t: TestRouter,
    r: Arc<Router>,
    keys: BTreeMap<&'static str, Arc<TestKey>>,
    copies: Arc<Mutex<BTreeMap<String, Copy>>>,
    _srv: TestServer,
    _fb: FakeBucket,
}

impl KernelStores {
    fn writes(&self, copy: &str) -> Vec<Value> {
        self.copies
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(copy)
            .map(|c| c.writes.clone())
            .unwrap_or_default()
    }
}

/// a box with no core (its URL unreachable) whose kernel copies' secrets (secrets-blue, secrets-green) answer the
/// core's store routes; the kernel's URL template points at one server that tells the components apart by path
fn kernel_store_router() -> KernelStores {
    let keys: BTreeMap<&'static str, Arc<TestKey>> = [
        ("blue", Arc::new(TestKey::new())),
        ("green", Arc::new(TestKey::new())),
    ]
    .into_iter()
    .collect();
    let copies: Arc<Mutex<BTreeMap<String, Copy>>> = Arc::default();
    let (k2, c2) = (keys.clone(), copies.clone());
    let srv = TestServer::handler(move |w, req| {
        let b: Value = serde_json::from_slice(&req.read_body(1 << 20)).unwrap_or_default();
        let path = req.path.trim_start_matches('/').to_string();
        let (role, rest) = path.split_once('/').unwrap_or((&path, ""));
        let Some(copy) = role.strip_prefix("secrets-") else {
            return write_error(w, 404, "not a secrets component");
        };
        let Some(k) = k2.get(copy) else {
            return write_error(w, 404, "no such copy");
        };
        match format!("/{rest}").as_str() {
            "/identity" => write_json(w, 200, &json!({"signingKey": k.public(),
                "state": k.doc(&json!({"kind": "core-state", "master": "M", "phone": {"agreementKey": "P"}}))})),
            "/stores" => write_json(w, 200, &k.doc(&json!({"kind": "stores", "nonce": "n", "stores": [
                {"name": "default", "keys": []}, {"name": "fresh", "keys": []}, {"name": "github-claude-env", "keys": []}]}))),
            "/stores/write-key" => {
                c2.lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .entry(copy.to_string())
                    .or_default()
                    .writes
                    .push(b.clone());
                write_json(w, 200, &k.doc(&json!({"kind": "key-written", "store": b["store"], "key": b["key"]})));
            }
            _ => write_json(w, 200, &k.doc(&json!({"kind": "ok"}))),
        }
    });
    let url = srv.url.clone();
    let t = new_test_router_with(
        move |c| {
            c.no_core = true;
            c.kernel_url = format!("{url}/%s");
        },
        Some("http://core.invalid:8090"),
        Default::default(),
    );
    let r = t.r.clone();
    let fb = FakeBucket::new();
    *r.backup_override.write().unwrap_or_else(|e| e.into_inner()) = Some(fb.bucket());
    KernelStores {
        t,
        r,
        keys,
        copies,
        _srv: srv,
        _fb: fb,
    }
}

/// on a box with no core every store path reaches the kernel's serving secrets: the setup session's listing and
/// writes, the app's store pages and its relayed store calls, the identity a writer computes the store key from
#[test]
fn stores_go_to_secrets_with_no_core() {
    let ks = kernel_store_router();
    let r = &ks.r;
    let (code, out) = app_do(r, "GET", "/setup/stores/keys", "", &[]);
    assert!(
        code == 200 && out["stores"].as_array().map_or(0, Vec::len) == 3,
        "setup store list: {code} {out}"
    );
    let (code, out) = app_do(r, "GET", "/api/stores", "", &[]);
    assert!(
        code == 200 && out["stores"].as_array().map_or(0, Vec::len) == 3,
        "app store list: {code} {out}"
    );
    for p in [
        "/setup/stores",
        "/api/core/stores",
        "/api/core/stores/versions",
    ] {
        let (code, out) = app_do(r, "POST", p, r#"{"nonce":"n"}"#, &[]);
        assert!(
            code != 503 && out["coreDown"].is_null(),
            "{p} didn't reach secrets: {code} {out}"
        );
    }
    let (code, out) = app_do(r, "GET", "/setup/identity", "", &[]);
    assert!(
        code == 200 && out["signingKey"] == ks.keys["blue"].public().as_str(),
        "setup identity: {code} {out}"
    );
    // secrets signs no store key: each writer computes P + K
    let (code, out) = app_do(r, "GET", "/setup/store-key", "", &[]);
    assert!(
        code == 200 && !out["identity"].is_null() && out["storeKey"].is_null(),
        "store key: {code} {out}"
    );
    let body =
        write_body("a key").replacen(r#""sig""#, r#""live":{"e":"LE","data":"LD"},"sig""#, 1);
    let (code, out) = app_do(r, "POST", "/setup/stores/infra/keys/K", &body, &[]);
    assert_eq!(code, 200, "setup write: {out}");
    let blue = ks.writes("blue");
    assert!(
        blue.len() == 1 && blue[0]["writer"] == "setup" && !blue[0]["live"].is_null(),
        "secrets got {blue:?}"
    );
    // a flip: every later store call goes to the other colour
    r.st.do_(|d| d.kernel_copy = "green".into());
    let (code, _) = app_do(
        r,
        "POST",
        "/setup/stores/infra/keys/K2",
        &write_body("another"),
        &[],
    );
    assert!(
        code == 200 && ks.writes("green").len() == 1 && ks.writes("blue").len() == 1,
        "after the flip: {code} blue {} green {}",
        ks.writes("blue").len(),
        ks.writes("green").len()
    );
}

/// a kernel session's machine writes with the grant it holds (secrets checks it), not a core cert
#[test]
fn a_kernel_session_writes_with_its_grant() {
    let ks = kernel_store_router();
    let r = &ks.r;
    add_session(r, "sK", "started", "mK", false);
    let grant: jarvis_doc::gv::Signed = serde_json::from_value(
        json!({"grant": {"payload": r#"{"kind":"grant"}"#, "sig": "G"}, "by": "mover"}),
    )
    .unwrap_or_else(|e| panic!("{e}"));
    r.st.do_(|d| {
        if let Some(s) = d.sessions.get_mut("sK") {
            s.cert = None;
            s.kernel = Some(crate::kernelline::KernelLine {
                grant: Some(grant.clone()),
                machine_cert: Some(jarvis_sig::Doc {
                    payload: "{}".into(),
                    sig: String::new(),
                }),
                ..Default::default()
            });
        }
    });
    let m = new_test_machine(r, "mK");
    let h = ks.t.machine_handler();
    let (code, out) = m.do_(
        &h,
        "POST",
        "/m/stores/default/keys/NEW_KEY",
        &write_body("a key"),
    );
    assert_eq!(code, 200, "{out}");
    let blue = ks.writes("blue");
    assert!(
        blue.len() == 1
            && !blue[0]["grant"].is_null()
            && blue[0]["cert"].is_null()
            && blue[0]["writer"] == "machine",
        "secrets got {blue:?}"
    );
    // a kernel line with no machine grant yet writes nothing
    r.st.do_(|d| {
        if let Some(k) = d.sessions.get_mut("sK").and_then(|s| s.kernel.as_mut()) {
            k.machine_cert = None;
        }
    });
    let (code, _) = m.do_(
        &h,
        "POST",
        "/m/stores/default/keys/NEW_KEY",
        &write_body(""),
    );
    assert_eq!(code, 403, "a write without the machine's grant");
}
