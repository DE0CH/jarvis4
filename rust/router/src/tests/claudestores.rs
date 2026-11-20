//! router/claudestores_test.go
use super::claudeaccounts::sign_in;
use super::claudelogin::FakeAnthropic;
use crate::claudelogin::for_machine;
use crate::claudestores::account_store_state;
use crate::nethttp::{write_error, write_json};
use crate::testutil::*;
use base64::Engine;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

/// a core with the router writer: its store key is a real point, so a write can be opened
struct AccountState {
    key: Arc<TestKey>,
    created: Vec<String>,
    writes: Vec<Value>,
    /// a core from before the router writer
    refuse: bool,
}

struct AccountCore {
    st: Arc<Mutex<AccountState>>,
    store: p256::SecretKey,
    srv: TestServer,
}

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

fn unb64(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .unwrap_or_default()
}

fn account_core(refuse: bool) -> AccountCore {
    let store = p256::SecretKey::random(&mut rand_core::OsRng);
    let point = b64(store.public_key().to_encoded_point(false).as_bytes());
    let st = Arc::new(Mutex::new(AccountState {
        key: Arc::new(TestKey::new()),
        created: vec![],
        writes: vec![],
        refuse,
    }));
    let s2 = st.clone();
    let srv = TestServer::handler(move |w, req| {
        let input: Value = serde_json::from_slice(&req.read_body(1 << 20)).unwrap_or_default();
        let mut c = s2.lock().unwrap_or_else(|e| e.into_inner());
        let k = c.key.clone();
        match req.path.as_str() {
            "/key" => write_json(w, 200, &json!({"signingKey": k.public()})),
            "/identity" => write_json(
                w,
                200,
                &json!({"signingKey": k.public(),
                "state": k.doc(&json!({"kind": "core-state", "master": "M", "phone": {"agreementKey": "P"}}))}),
            ),
            "/store-key" => write_json(
                w,
                200,
                &k.doc(&json!({"kind": "store-key", "phone": "P", "storeKey": point})),
            ),
            "/stores/create" => {
                c.created
                    .push(input["name"].as_str().unwrap_or_default().to_string());
                write_json(
                    w,
                    200,
                    &k.doc(&json!({"kind": "store-created", "name": input["name"]})),
                );
            }
            "/stores/write-key" => {
                if c.refuse {
                    return write_json(w, 400, &json!({"error": "writer: setup or machine"}));
                }
                c.writes.push(input.clone());
                write_json(w, 200, &k.doc(&json!({"kind": "key-written", "store": input["store"], "key": input["key"]})));
            }
            _ => write_error(w, 404, "404 page not found"),
        }
    });
    AccountCore { st, store, srv }
}

fn gcm_open(key: &[u8], b64s: &str, aad: &[u8]) -> Vec<u8> {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    let raw = unb64(b64s);
    let c = aes_gcm::Aes256Gcm::new_from_slice(key).unwrap_or_else(|_| panic!("bad key"));
    let (nonce, ct) = raw.split_at(12.min(raw.len()));
    let mut n = [0u8; 12];
    n.copy_from_slice(nonce);
    c.decrypt(&aes_gcm::Nonce::from(n), Payload { msg: ct, aad })
        .unwrap_or_else(|_| panic!("doesn't open"))
}

impl AccountCore {
    fn get<R>(&self, f: impl FnOnce(&mut AccountState) -> R) -> R {
        f(&mut self.st.lock().unwrap_or_else(|e| e.into_inner()))
    }

    /// a written key's value, with the store key's private half (what the phone's share and the core do together)
    fn open(&self, x: &Value) -> String {
        let wr = &x["wrapped"];
        let e = p256::PublicKey::from_sec1_bytes(&unb64(wr["e"].as_str().unwrap_or_default()))
            .unwrap_or_else(|_| panic!("bad e"));
        let sh = p256::ecdh::diffie_hellman(self.store.to_nonzero_scalar(), e.as_affine());
        let mut k = [0u8; 32];
        hkdf::Hkdf::<sha2::Sha256>::new(None, sh.raw_secret_bytes())
            .expand(b"jarvis2/store-data-key", &mut k)
            .unwrap_or_else(|_| panic!("hkdf"));
        let dk = gcm_open(&k, wr["wrapped"].as_str().unwrap_or_default(), b"");
        let aad = format!(
            "{}\n{}",
            x["store"].as_str().unwrap_or_default(),
            x["key"].as_str().unwrap_or_default()
        );
        String::from_utf8_lossy(&gcm_open(
            &dk,
            x["data"].as_str().unwrap_or_default(),
            aad.as_bytes(),
        ))
        .into_owned()
    }
}

/// Each Claude account is its core store claude-<name>: the router writes its pair and record there when they change
/// (writer "router", no Inbox refresh), once per change and core, and again for a new core; a removed account's keys
/// go.
#[test]
fn the_router_writes_each_account_into_its_core_store() {
    let _s = serial(); // the fake Anthropic and the account stores' state are global
    let _f = FakeAnthropic::new();
    let t = new_test_router();
    let r = t.r.clone();
    let c = account_core(false);
    r.core.set_url(&c.srv.url);
    let (code, out) = sign_in(&r, "/api/claude-accounts", r#"{"name":"main"}"#);
    assert_eq!(code, 200, "{out}");
    r.sync_account_stores();
    let (created, writes) = c.get(|s| (s.created.clone(), s.writes.clone()));
    assert!(
        created == ["claude-main"] && writes.len() == 2,
        "created {created:?}, writes {writes:?}"
    );
    let cur = r
        .accounts()
        .hub("claude-main")
        .unwrap_or_else(|| panic!("no hub"))
        .current();
    let mut got = std::collections::BTreeMap::new();
    for x in &writes {
        assert!(
            x["writer"] == "router" && x["store"] == "claude-main" && x["sig"].is_null(),
            "write {x}"
        );
        got.insert(x["key"].as_str().unwrap_or_default().to_string(), c.open(x));
    }
    // the store gets the pair as sessions do: without the refresh token (only the router refreshes)
    let creds = got.get("CLAUDE_CREDENTIALS").cloned().unwrap_or_default();
    assert!(
        creds == for_machine(&cur.credentials)
            && !creds.contains("refreshToken")
            && got.get("CLAUDE_ACCOUNT") == Some(&cur.account),
        "got {got:?}"
    );
    // nothing changed: nothing written; no Inbox refresh was filed for the write
    r.sync_account_stores();
    assert_eq!(
        c.get(|s| s.writes.len()),
        2,
        "written again with nothing changed"
    );
    assert!(r.st.read(|d| d.approvals.is_empty()), "a refresh was filed");
    // a new core (another key): written again
    c.get(|s| s.key = Arc::new(TestKey::new()));
    r.sync_account_stores();
    assert_eq!(
        c.get(|s| s.writes.len()),
        4,
        "a new core didn't get the account"
    );
    // removed: its keys are deleted from its store
    r.forget_account_store("claude-main");
    let writes = c.get(|s| s.writes.clone());
    let last = writes.last().cloned().unwrap_or_default();
    assert!(
        writes.len() == 6 && last["delete"] == true && last["writer"] == "router",
        "writes {writes:?}"
    );
}

/// A core from before the router writer refuses: the account stays the router's, tried again later, nothing breaks
#[test]
fn a_core_without_the_router_writer_is_tried_again_later() {
    let _s = serial(); // its own account: the stores' retry state is global, by store name
    let _f = FakeAnthropic::new();
    let t = new_test_router();
    let r = t.r.clone();
    let c = account_core(true);
    r.core.set_url(&c.srv.url);
    sign_in(&r, "/api/claude-accounts", r#"{"name":"spare"}"#);
    r.sync_account_stores();
    let st = account_store_state("claude-spare");
    assert!(
        st.as_ref()
            .is_some_and(|(written, retry)| written.is_empty() && !retry.is_zero()),
        "state {st:?}"
    );
}
