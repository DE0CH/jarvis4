//! The Claude accounts in the core (DECISIONS 185, 190). Each account is the core store claude-<name>: the router, its
//! only refresher, writes the account's pair (CLAUDE_CREDENTIALS, ~/.claude/.credentials.json) and record
//! (CLAUDE_ACCOUNT, ~/.claude.json's oauthAccount) into it whenever they change, as the per-key write does, sealed to
//! the store key P + K, with no approval (the core's writer `router`, allowed for claude-* stores only and named
//! "router" on every unlock). A session whose cert names its account's store gets the pair through its store like any
//! other secret, the account vouched for by the phone at Start; its machine then keeps in step through the router's
//! long poll (claudelogin.rs), since the pair rotates every 8 hours with nobody there to unlock it.
//!
//! What is still the router's: the working copy it refreshes with (the core can't hand a store back without the
//! phone). These writes have no bucket backup and file no Inbox refresh: an earlier pair is worthless once rotated, a
//! Recover leaves the claude-* stores to this router (it writes them again within a minute of seeing a core without
//! them), and running sessions take refreshes from the long poll.
//!
//! The loop (login_loop, every minute) writes an account whose pair or record changed since it was last written to
//! this core (or to any core: a new core, a Recover, the move). A core that has no router writer (from before 190)
//! refuses; that is logged once per account and retried every 10 minutes.

use crate::claudelogin::for_machine;
use crate::core::Doc;
use crate::router::Router;
use anyhow::{Result, anyhow};
use base64::Engine;
use jarvis_go::GoTime;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::{LazyLock, Mutex};

/// a new session's cert names its account's store (claude-<name>), so the phone vouches for the account and the
/// session gets its pair from its store. The router's env CLAUDE_STORE_IN_CERT=1 (k8s/control/apps/router/router.yaml),
/// set only once Deyao's iPhone runs an app that accepts the router as a key's writer (ios Checks.keyWriter "router"):
/// an older app refuses to unlock such a store, so Start would fail. Like SIGN_CLAUDE_ACCOUNT.
pub static CLAUDE_STORE_IN_CERT: LazyLock<bool> =
    LazyLock::new(|| std::env::var("CLAUDE_STORE_IN_CERT").is_ok_and(|v| v == "1"));

/// what was last written for one account (router memory only: a restart writes once more)
#[derive(Default)]
struct AccountStoreState {
    /// sha256 of core key + pair + record last written
    written: String,
    /// after a failure
    retry: GoTime,
    last_err: String,
}

static ACCOUNT_STORES: LazyLock<Mutex<BTreeMap<String, AccountStoreState>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));

/// tests: what was last written of a store, and when it is tried again
#[cfg(test)]
pub fn account_store_state(store: &str) -> Option<(String, GoTime)> {
    ACCOUNT_STORES
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(store)
        .map(|s| (s.written.clone(), s.retry))
}

/// a new line's stores plus its account's store (when certs name it)
pub fn with_account_store(stores: &[String], account: &str) -> Vec<String> {
    with_account_store_if(*CLAUDE_STORE_IN_CERT, stores, account)
}

pub fn with_account_store_if(on: bool, stores: &[String], account: &str) -> Vec<String> {
    if !on || account.is_empty() || stores.iter().any(|s| s == account) {
        return stores.to_vec();
    }
    let mut out = stores.to_vec();
    out.push(account.to_string());
    out.sort();
    out
}

impl Router {
    /// every account whose pair or record changed since it was last written into this core
    pub fn sync_account_stores(&self) {
        let Ok(key) = self.store_core().key() else {
            return;
        };
        let sk = key.get("signingKey").cloned().unwrap_or_default();
        for h in self.accounts().all() {
            let v = h.current();
            if v.credentials.is_empty() {
                continue;
            }
            let want = hex::encode(Sha256::digest(format!(
                "{sk}\n{}\n{}",
                v.credentials, v.account
            )));
            let skip = {
                let mut g = ACCOUNT_STORES.lock().unwrap_or_else(|e| e.into_inner());
                let st = g.entry(h.store.clone()).or_default();
                st.written == want || GoTime::now().before(&st.retry)
            };
            if skip {
                continue;
            }
            let res = self.write_account_store(&h.store, &v.credentials, &v.account);
            let mut g = ACCOUNT_STORES.lock().unwrap_or_else(|e| e.into_inner());
            let st = g.entry(h.store.clone()).or_default();
            match res {
                Err(e) => {
                    let msg = format!("{e:#}");
                    if msg != st.last_err {
                        crate::logf!(
                            "[accounts] {}: writing it into the core: {msg} (tried again every 10 minutes)",
                            h.store
                        );
                    }
                    st.retry = GoTime::now().add(time::Duration::minutes(10));
                    st.last_err = msg;
                }
                Ok(()) => {
                    if st.written.is_empty() || !st.last_err.is_empty() {
                        crate::logf!(
                            "[accounts] {}: written into the core's store {}",
                            h.store,
                            h.store
                        );
                    }
                    st.written = want;
                    st.retry = GoTime::default();
                    st.last_err.clear();
                }
            }
        }
    }

    /// a removed account's keys leave its core store (a store itself can't be deleted)
    pub fn forget_account_store(&self, store: &str) {
        for k in ["CLAUDE_CREDENTIALS", "CLAUDE_ACCOUNT"] {
            if let Err(e) = self.write_router_key(store, k, None) {
                crate::logf!("[accounts] {store}: deleting {k} from the core: {e:#}");
            }
        }
        ACCOUNT_STORES
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(store);
    }

    /// the store made (not sensitive: a Claude login can't reach a code push) if the core lacks it, then both keys
    pub fn write_account_store(&self, store: &str, credentials: &str, account: &str) -> Result<()> {
        if let Err(e) = self
            .store_core()
            .call("/stores/create", &json!({"name": store}))
            && !format!("{e:#}").contains("exists")
        {
            return Err(anyhow!("making the store: {e:#}"));
        }
        self.write_router_key(
            store,
            "CLAUDE_CREDENTIALS",
            Some(for_machine(credentials).as_bytes()),
        )?;
        if account.is_empty() {
            return Ok(());
        }
        self.write_router_key(store, "CLAUDE_ACCOUNT", Some(account.as_bytes()))
    }

    /// one key sealed to the core's store key and written as the router (core/keys.go writer "router"); None deletes it
    pub fn write_router_key(&self, store: &str, key: &str, value: Option<&[u8]>) -> Result<()> {
        let mut input =
            json!({"store": store, "key": key, "writer": "router", "delete": value.is_none()});
        if let Some(value) = value {
            let store_key = self.router_store_key()?;
            let dk = crate::util::rand_bytes(32);
            let (e, wrapped) = seal_to_point(&store_key, &dk, "jarvis2/store-data-key", b"")
                .map_err(|e| anyhow!("the store key: {e:#}"))?;
            input["wrapped"] = json!({"e": e, "wrapped": wrapped});
            input["data"] = json!(b64(&gcm_seal_key(
                &dk,
                value,
                format!("{store}\n{key}").as_bytes()
            )?));
        }
        match self.store_core().call("/stores/write-key", &input) {
            Err(e) if value.is_none() && format!("{e:#}").contains("has no key") => Ok(()),
            Err(e) => Err(e),
            Ok(d) => {
                // storeversions.rs: the version this write makes (a box with no core)
                let entry = value.map(|_| crate::storeversions::VerEntry {
                    wrapped: input["wrapped"].clone(),
                    data: input["data"].as_str().unwrap_or_default().to_string(),
                    ..Default::default()
                });
                self.record_key_write(store, key, entry, Some(&d));
                Ok(())
            }
        }
    }

    /// P + K for the router's own writes — the core's signed store key, or on a box with no core computed from
    /// secrets' identity (its agreement key and the phone its signed state names)
    pub fn router_store_key(&self) -> Result<String> {
        let t = self.store_key_for()?;
        if self.secrets_stores.get().is_some() {
            #[derive(Deserialize, Default)]
            #[serde(default)]
            struct Id {
                #[serde(rename = "agreementKey")]
                agreement_key: String,
                state: Option<Doc>,
            }
            #[derive(Deserialize, Default)]
            #[serde(default)]
            struct Phone {
                #[serde(rename = "agreementKey")]
                agreement_key: String,
            }
            #[derive(Deserialize, Default)]
            #[serde(default)]
            struct St {
                phone: Phone,
            }
            let id: Id = jarvis_go::unmarshal(jarvis_go::marshal(&t["identity"]).as_bytes())
                .map_err(|_| anyhow!("secrets' identity isn't readable"))?;
            let st: St = id
                .state
                .as_ref()
                .and_then(|s| s.decode().ok())
                .ok_or_else(|| anyhow!("secrets' identity isn't readable"))?;
            return jarvis_sig::store_key(&st.phone.agreement_key, &id.agreement_key)
                .map_err(|e| anyhow!("{e}"));
        }
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct Sk {
            #[serde(rename = "storeKey")]
            store_key: String,
        }
        match serde_json::from_value::<Doc>(t["storeKey"].clone())
            .ok()
            .and_then(|d| d.decode::<Sk>().ok())
        {
            Some(sk) if !sk.store_key.is_empty() => Ok(sk.store_key),
            _ => Err(anyhow!("the core answered no store key")),
        }
    }
}

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

/// ephemeral ECDH with the recipient point, HKDF-SHA256(info), AES-256-GCM (nonce ‖ ciphertext ‖ tag), as
/// rust/machine/src/putkey.rs seal_parts and core WrapToPoint → (e, sealed)
pub fn seal_to_point(
    recipient_b64: &str,
    plain: &[u8],
    info: &str,
    aad: &[u8],
) -> Result<(String, String)> {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    let rb = base64::engine::general_purpose::STANDARD.decode(recipient_b64)?;
    let rk = p256::PublicKey::from_sec1_bytes(&rb).map_err(|_| anyhow!("bad public key"))?;
    let e = p256::ecdh::EphemeralSecret::random(&mut rand_core::OsRng);
    let x = e.diffie_hellman(&rk);
    let mut k = [0u8; 32];
    hkdf::Hkdf::<Sha256>::new(None, x.raw_secret_bytes())
        .expand(info.as_bytes(), &mut k)
        .map_err(|_| anyhow!("hkdf"))?;
    Ok((
        b64(e.public_key().to_encoded_point(false).as_bytes()),
        b64(&gcm_seal_key(&k, plain, aad)?),
    ))
}

pub fn gcm_seal_key(key: &[u8], plain: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    let c = aes_gcm::Aes256Gcm::new_from_slice(key).map_err(|_| anyhow!("bad key"))?;
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&crate::util::rand_bytes(12));
    let ct = c
        .encrypt(&aes_gcm::Nonce::from(nonce), Payload { msg: plain, aad })
        .map_err(|_| anyhow!("seal"))?;
    let mut out = nonce.to_vec();
    out.extend_from_slice(&ct);
    Ok(out)
}
