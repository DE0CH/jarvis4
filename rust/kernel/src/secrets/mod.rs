//! The kernel's secrets (kernel/secrets; DESIGN "Target design"), carried over from the old core's store half (same
//! formats, so the app's store code serves both). It holds the stores, the unlocks and a signed list of open unlocks,
//! and keeps nothing it doesn't need. It hands secrets out and never uses one (DECISIONS 232): a deploy key's GitHub
//! call is the minter's (minter.rs), and a store's earlier versions are the router's (a restore writes back an earlier
//! key with its key-written receipt, keys.rs). Given a grant (signed by the mover or the merger), it returns the stores
//! the grant's allowed set names (store:x), sealed to the grant's machine and signed. An unlock is per store and never
//! locks by itself (D2): it ends with a lock call, and the phone sees open ones. Any written key reaches the next pull,
//! whoever wrote it (D1): a write carries its value sealed to secrets as well ("live"), which secrets uses only to
//! update an open unlock of that store. It checks nothing about who may write: writing is protected only by the
//! router.

pub mod continuity;
pub mod crypto;
pub mod deploykeys;
pub mod http;
pub mod keys;

use crate::minter::{MintError, Request as MintRequest};
use continuity::{LineStateDoc, MODE_HANDED_OFF, MODE_SERVING};
use crypto::{gcm_open, unwrap_with_shares};
use deploykeys::{DEPLOY_KEY_TOKEN_STORE, PendingDeployKey};
use jarvis_doc::gv::{self, Signed};
use jarvis_go::GoTime;
use jarvis_sig::{Doc, Identity, Opener, Sealed, Signer, Trust, go_json, seal_to, verify};
use keys::{EntryWriter, KeyEntry, store_version};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, MutexGuard};

/// an error with the HTTP status it answers
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Err {
    pub status: u16,
    pub msg: String,
}

impl std::fmt::Display for Err {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.msg)
    }
}

impl std::error::Error for Err {}

pub fn fail(status: u16, msg: impl Into<String>) -> anyhow::Error {
    Err {
        status,
        msg: msg.into(),
    }
    .into()
}

pub type Result<T> = anyhow::Result<T>;

/// where an approved deploy-key call goes (minter.rs: over HTTP in the cluster, in-process in tests)
pub trait MinterApi: Send + Sync {
    fn mint(&self, r: &MintRequest) -> Result<Doc>;
}

impl MinterApi for crate::minter::Client {
    fn mint(&self, r: &MintRequest) -> Result<Doc> {
        crate::minter::Client::mint(self, r)
    }
}

pub(crate) struct Unlocked {
    pub values: BTreeMap<String, String>,
    /// the store's version these values are (store_version)
    pub version: String,
    /// each open unlock of the store → since
    pub ids: BTreeMap<String, GoTime>,
}

pub(crate) struct PendingUnlock {
    store: String,
    entries: BTreeMap<String, KeyEntry>,
    version: String,
    t: Opener,
}

/// what the mutex guards
pub(crate) struct Inner {
    pub signer: Signer,
    /// secrets' share K of every store's key
    pub agreement: Opener,
    /// the master public key it was claimed with ("" = empty)
    pub master_key: String,
    pub phone_signing: String,
    pub phone_agreement: String,
    /// the root key (a separate key on the iPhone)
    pub root: String,
    pub stores: BTreeMap<String, BTreeMap<String, KeyEntry>>,
    pub not_sensitive: BTreeSet<String>,
    pending: BTreeMap<String, PendingUnlock>,
    pub unlocked: BTreeMap<String, Unlocked>,
    pub pending_keys: BTreeMap<String, PendingDeployKey>,
    pub repo_owner: BTreeMap<String, String>,
    /// a deploy-key store → the id GitHub gave its key (what a remove deletes)
    pub repo_key_id: BTreeMap<String, i64>,
    // continuity.rs: the state key, the newest state's seq and hash and the sealed document; the copy flip: the kit's
    // seed, the mode, the handoff made and the one taken
    pub line_key: Option<[u8; 32]>,
    pub line_seq: i64,
    pub line_hash: String,
    pub line_doc: Option<LineStateDoc>,
    pub seed: Option<Vec<u8>>,
    pub mode: String,
    pub handed_to: String,
    pub handoff: Option<Doc>,
    pub took: String,
}

pub struct Secrets {
    pub(crate) mu: Mutex<Inner>,
    /// the root key's roster: the other components' identities (and its own) are checked with it
    pub trust: Arc<Trust>,
    minter: Option<Box<dyn MinterApi>>,
    exit: Mutex<Option<Box<dyn Fn() + Send + Sync>>>,
    /// the clock (a test's own)
    pub now: fn() -> GoTime,
}

pub(crate) fn sha256_hex(s: &str) -> String {
    hex(&Sha256::digest(s.as_bytes()))
}

pub(crate) fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub(crate) fn rand_id() -> String {
    use rand_core::RngCore as _;
    let mut b = [0u8; 12];
    rand_core::OsRng.fill_bytes(&mut b);
    hex(&b)
}

pub(crate) fn is_hex64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

/// the old core's own Fly token store, a name secrets never holds (store_name refuses it)
pub const FLY_STORE: &str = "core";

/// a store's name — lower case, digits and "-", never the old core's own store
pub fn store_name(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 64
        && n != FLY_STORE
        && n.chars()
            .all(|r| r.is_ascii_lowercase() || r.is_ascii_digit() || r == '-')
}

/// a P-256 public point, base64 of the 65-byte uncompressed encoding (an agreement key)
fn agreement_key_ok(k: &str) -> bool {
    jarvis_sig::unb64(k).is_ok_and(|b| b.len() == 65 && crypto::point_ok(&b))
}

/// a signing key ECDSA takes (a point on the curve)
fn signing_key_ok(k: &str) -> bool {
    jarvis_sig::unb64(k).is_ok_and(|b| crypto::point_ok(&b))
}

const INFO_CLAIM: &str = "jarvis2/kernel-claim";
pub(crate) const INFO_LIVE: &str = "jarvis2/live-key";
pub(crate) const INFO_SHARE: &str = "jarvis2/unlock-share";

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct KeyPair {
    signing_key: String,
    agreement_key: String,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct ClaimStatement {
    kind: String,
    master: String,
    secrets: KeyPair,
    phone: KeyPair,
    root: String,
    bundle_sha256: String,
    identity: Option<KeyPair>,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct ClaimBundle {
    format: String,
    stores: Vec<String>,
    keys: Vec<KeyEntry>,
    not_sensitive: Vec<String>,
    owners: BTreeMap<String, String>,
    secrets_seed: String,
    line_state: Option<LineStateDoc>,
}

impl Secrets {
    /// an empty secrets with fresh keys; root_pub is the root key's public half (keys/root.pub), which the roster is
    /// checked against; m is where an approved deploy-key call goes (the minter)
    pub fn new(root_pub: &str, m: Option<Box<dyn MinterApi>>) -> Secrets {
        Secrets {
            mu: Mutex::new(Inner {
                signer: Signer::generate(),
                agreement: Opener::generate(),
                master_key: String::new(),
                phone_signing: String::new(),
                phone_agreement: String::new(),
                root: String::new(),
                stores: BTreeMap::new(),
                not_sensitive: BTreeSet::new(),
                pending: BTreeMap::new(),
                unlocked: BTreeMap::new(),
                pending_keys: BTreeMap::new(),
                repo_owner: BTreeMap::new(),
                repo_key_id: BTreeMap::new(),
                line_key: None,
                line_seq: 0,
                line_hash: String::new(),
                line_doc: None,
                seed: None,
                mode: MODE_SERVING.into(),
                handed_to: String::new(),
                handoff: None,
                took: String::new(),
            }),
            trust: Arc::new(Trust::new(root_pub)),
            minter: m,
            exit: Mutex::new(None),
            now: GoTime::now,
        }
    }

    pub(crate) fn lock(&self) -> MutexGuard<'_, Inner> {
        self.mu.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// what a wipe calls (the process exits)
    pub fn set_exit(&self, f: Box<dyn Fn() + Send + Sync>) {
        *self.exit.lock().unwrap_or_else(|e| e.into_inner()) = Some(f);
    }

    pub(crate) fn now_rfc3339(&self) -> String {
        (self.now)().utc().rfc3339()
    }

    /// the root key's roster, which must name the keys secrets serves with now (after a claim with a seed: the
    /// derived ones)
    pub fn set_roster(&self, d: Doc) -> Result<Value> {
        let me = self.component_identity();
        self.trust
            .set(d.clone(), Some(&me))
            .map_err(|e| fail(403, e.to_string()))?;
        crate::serve::log("the root key's roster taken");
        Ok(json!({"kind": "roster-taken", "roster": d.id()}))
    }

    /// the roster held (None: none yet)
    pub fn roster(&self) -> Option<Doc> {
        self.trust.doc()
    }

    // ---- identity -----------------------------------------------------------------------------------------------

    /// this secrets' identity as the other components check it
    pub fn component_identity(&self) -> Identity {
        let g = self.lock();
        Identity {
            role: "secrets".into(),
            signing_key: g.signer.public_key(),
            agreement_key: g.agreement.public_key(),
        }
    }

    /// the keys (role "secrets"; the roster vouches for them), and the signed state: the master key it was claimed
    /// with, the phone's keys and the root key
    pub fn identity(&self) -> Result<Value> {
        let g = self.lock();
        let mut st = json!({"kind": "secrets-state", "master": g.master_key, "phone": null, "root": g.root,
            "lineSeq": g.line_seq, "derived": g.line_key.is_some(),
            "serving": match g.mode.as_str() { MODE_SERVING => "serving", MODE_HANDED_OFF => "handed-off", _ => "" }});
        if !g.phone_signing.is_empty() {
            st["phone"] = json!({"signingKey": g.phone_signing, "agreementKey": g.phone_agreement});
        }
        let d = sign(&g, &st)?;
        Ok(
            json!({"role": "secrets", "signingKey": g.signer.public_key(),
            "agreementKey": g.agreement.public_key(), "state": d, "bundle": "keys", "continuity": 1}),
        )
    }

    /// {kind: "keys", phone, root}, what the notarizer and the mover take the phone's and the root key from
    pub fn keys_statement(&self) -> Result<Doc> {
        let g = self.lock();
        keys_statement(&g)
    }

    // ---- claim -----------------------------------------------------------------------------------------------------

    /// once, on an empty secrets (Reset or Recover from the app), as the old core's claim, plus the root key
    pub fn claim(&self, statement: &str, master_sig: &str, bundle: &Sealed) -> Result<Doc> {
        let mut g = self.lock();
        if !g.master_key.is_empty() {
            return Err(fail(
                409,
                "secrets is already set up: end it with its own kit (the app's wipe) first",
            ));
        }
        let st: ClaimStatement = match serde_json::from_str::<ClaimStatement>(statement) {
            Ok(s) if s.kind == "kernel-claim" => s,
            _ => return Err(fail(400, "not a kernel claim statement")),
        };
        if !signing_key_ok(&st.master) {
            return Err(fail(400, "bad master key: not a P-256 point"));
        }
        if !verify(&st.master, statement.as_bytes(), master_sig) {
            return Err(fail(
                403,
                "the claim isn't signed by the master key it names",
            ));
        }
        if st.secrets.signing_key != g.signer.public_key()
            || st.secrets.agreement_key != g.agreement.public_key()
        {
            return Err(fail(403, "the claim names another secrets"));
        }
        if !signing_key_ok(&st.phone.signing_key) {
            return Err(fail(400, "bad phone signing key: not a P-256 point"));
        }
        if !signing_key_ok(&st.root) || st.root == st.phone.signing_key {
            return Err(fail(
                400,
                "the root key: a P-256 key of its own (not the phone's)",
            ));
        }
        if !agreement_key_ok(&st.phone.agreement_key) {
            return Err(fail(400, "bad phone agreement key"));
        }
        let plain = g
            .agreement
            .open(bundle, INFO_CLAIM)
            .map_err(|_| fail(400, "can't open the bundle"))?;
        if hex(&Sha256::digest(&plain)) != st.bundle_sha256 {
            return Err(fail(403, "the bundle isn't the one the master key signed"));
        }
        let b: ClaimBundle = match serde_json::from_slice::<ClaimBundle>(&plain) {
            Ok(b) if b.format == "keys" => b,
            _ => return Err(fail(400, "bad bundle")),
        };
        let mut stores: BTreeMap<String, BTreeMap<String, KeyEntry>> = BTreeMap::new();
        for n in &b.stores {
            if !store_name(n) || stores.contains_key(n) {
                return Err(fail(
                    400,
                    format!(
                        "bad or repeated store {} in the bundle",
                        jarvis_go::fmt::go_quote(n)
                    ),
                ));
            }
            stores.insert(n.clone(), BTreeMap::new());
        }
        let now = self.now_rfc3339();
        for x in &b.keys {
            let ok = stores
                .get(&x.store)
                .is_some_and(|keys| !keys.contains_key(&x.key))
                && keys::valid_entry(x, &x.store);
            if !ok {
                return Err(fail(
                    400,
                    format!(
                        "bad or repeated key {} of store {} in the bundle",
                        jarvis_go::fmt::go_quote(&x.key),
                        jarvis_go::fmt::go_quote(&x.store)
                    ),
                ));
            }
            let mut x = x.clone();
            x.writer = Some(EntryWriter {
                by: "core".into(),
                ..Default::default()
            });
            x.at = now.clone();
            x.backup_sha256 = String::new();
            if let Some(keys) = stores.get_mut(&x.store) {
                keys.insert(x.key.clone(), x);
            }
        }
        let mut owners = BTreeMap::new();
        for (s, repo) in &b.owners {
            if stores.contains_key(s) && crate::minter::repo_ok(repo) {
                owners.insert(s.clone(), repo.clone());
            }
        }
        let mut dk = None;
        let mut line = None;
        if !b.secrets_seed.is_empty() {
            let seed = jarvis_sig::unb64(&b.secrets_seed).unwrap_or_default();
            if seed.len() != 32 {
                return Err(fail(400, "secretsSeed: 32 bytes, base64"));
            }
            let k = continuity::derive_core_keys(&seed)
                .map_err(|e| fail(400, format!("secretsSeed: {e:#}")))?;
            let named = st.identity.as_ref().is_some_and(|i| {
                i.signing_key == k.signer.public_key()
                    && i.agreement_key == k.agreement.public_key()
            });
            if !named {
                return Err(fail(
                    403,
                    "the claim's identity isn't the keys its seed derives",
                ));
            }
            if let Some(ls) = &b.line_state {
                line = Some(continuity::open_line_state(ls, &k)?);
            }
            dk = Some((k, seed));
        } else if st.identity.is_some() || b.line_state.is_some() {
            return Err(fail(400, "an identity or a state comes with a secretsSeed"));
        }
        g.master_key = st.master.clone();
        g.root = st.root.clone();
        g.repo_owner = owners;
        g.repo_key_id = BTreeMap::new();
        g.phone_signing = st.phone.signing_key.clone();
        g.phone_agreement = st.phone.agreement_key.clone();
        g.stores = stores;
        g.not_sensitive = b
            .not_sensitive
            .iter()
            .filter(|n| g.stores.contains_key(*n))
            .cloned()
            .collect();
        let mut restored = vec![];
        let derived = dk.is_some();
        if let Some((k, seed)) = dk {
            g.signer = k.signer;
            g.agreement = k.agreement;
            g.line_key = Some(k.state);
            g.seed = Some(seed);
            if let Some(l) = &line {
                restored = continuity::restore_line(&mut g, l, l.r#final);
            }
            g.line_hash.clear();
            g.line_doc = None;
        }
        crate::serve::log(&format!(
            "claimed: master key, phone and root keys, {} stores, derived keys {derived}, state {} (deploy-key stores back: {restored:?})",
            g.stores.len(),
            line.is_some()
        ));
        let mut out = json!({"kind": "claimed", "stores": g.stores.len(), "derived": derived});
        if let Some(l) = &line {
            out["lineSeq"] = json!(l.seq);
            out["repoStores"] = json!(restored);
        }
        sign(&g, &out)
    }

    /// the current master key ends secrets (it answers, then exits; Kubernetes starts an empty one)
    pub fn wipe(&self, statement: &str, master_sig: &str) -> Result<Doc> {
        let g = self.lock();
        if g.master_key.is_empty() {
            return sign(
                &g,
                &json!({"kind": "wiping", "secrets": g.signer.public_key(), "alreadyEmpty": true}),
            );
        }
        if !verify(&g.master_key, statement.as_bytes(), master_sig) {
            return Err(fail(403, "the wipe isn't signed by this master key"));
        }
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct W {
            kind: String,
            secrets: String,
        }
        let st: W = serde_json::from_str(statement).unwrap_or_default();
        if st.kind != "kernel-wipe" || st.secrets != g.signer.public_key() {
            return Err(fail(403, "the wipe names another secrets"));
        }
        let d = sign(&g, &json!({"kind": "wiping", "secrets": st.secrets}))?;
        if let Some(f) = self.exit.lock().unwrap_or_else(|e| e.into_inner()).take() {
            std::thread::spawn(f);
        }
        Ok(d)
    }

    // ---- stores ----------------------------------------------------------------------------------------------------

    /// once per name — an empty, non-sensitive store
    pub fn create_store(&self, name: &str) -> Result<Doc> {
        let mut g = self.lock();
        if g.master_key.is_empty() {
            return Err(fail(
                409,
                "secrets isn't set up yet: Reset or Recover it in the app first",
            ));
        }
        if !store_name(name) || name == DEPLOY_KEY_TOKEN_STORE {
            return Err(fail(
                400,
                format!("bad store name ({DEPLOY_KEY_TOKEN_STORE} is always sensitive)"),
            ));
        }
        if g.stores.contains_key(name) {
            return Err(fail(409, format!("store {name} exists")));
        }
        g.stores.insert(name.into(), BTreeMap::new());
        g.not_sensitive.insert(name.into());
        sign(&g, &json!({"kind": "store-created", "name": name}))
    }

    /// the one-way upgrade
    pub fn mark_sensitive(&self, name: &str) -> Result<Doc> {
        let mut g = self.lock();
        if !g.not_sensitive.contains(name) {
            return sign(
                &g,
                &json!({"kind": "marked-sensitive", "name": name, "already": true}),
            );
        }
        g.not_sensitive.remove(name);
        sign(&g, &json!({"kind": "marked-sensitive", "name": name}))
    }

    /// the signed list (names, sensitivity, empty, unlocked, keys with writers, version)
    pub fn stores(&self, nonce: &str) -> Result<Doc> {
        let g = self.lock();
        #[derive(Serialize)]
        struct Row {
            name: String,
            sensitive: bool,
            empty: bool,
            unlocked: bool,
            keys: Vec<keys::KeyRow>,
            version: String,
        }
        let out: Vec<Row> = g
            .stores
            .iter()
            .map(|(n, keys)| Row {
                name: n.clone(),
                sensitive: !g.not_sensitive.contains(n),
                empty: keys.is_empty(),
                unlocked: g.unlocked.contains_key(n),
                keys: keys::key_rows(keys),
                version: store_version(keys),
            })
            .collect();
        sign(
            &g,
            &json!({"kind": "stores", "nonce": nonce, "stores": out}),
        )
    }

    // ---- unlock (per store; never ends by itself: D2) --------------------------------------------------------------

    pub fn unlock_begin(&self, name: &str) -> Result<Doc> {
        let mut g = self.lock();
        if name == DEPLOY_KEY_TOKEN_STORE {
            return Err(fail(
                403,
                format!(
                    "{DEPLOY_KEY_TOKEN_STORE} is opened only by a deploy-key call, never unlocked"
                ),
            ));
        }
        let keys = g.stores.get(name).cloned().unwrap_or_default();
        if keys.is_empty() {
            return Err(fail(
                404,
                format!(
                    "no store {name} with contents: write a key into it first (jarvis2 put-key)"
                ),
            ));
        }
        let t = Opener::generate();
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct KeyBegin {
            key: String,
            e: String,
            writer: EntryWriter,
            data_sha256: String,
            backup_sha256: String,
            at: String,
        }
        let rows: Vec<KeyBegin> = keys
            .iter()
            .map(|(k, x)| KeyBegin {
                key: k.clone(),
                e: x.wrapped.e.clone(),
                writer: keys::entry_writer(x),
                data_sha256: sha256_hex(&x.data),
                backup_sha256: x.backup_sha256.clone(),
                at: x.at.clone(),
            })
            .collect();
        let id = rand_id();
        let version = store_version(&keys);
        let tp = t.public_key();
        g.pending.insert(
            id.clone(),
            PendingUnlock {
                store: name.into(),
                entries: keys,
                version: version.clone(),
                t,
            },
        );
        sign(
            &g,
            &json!({"kind": "unlock-begin", "pending": id, "store": name, "t": tp, "keys": rows, "version": version}),
        )
    }

    /// the phone's share of every key unlock_begin named, each sealed to T (one try)
    pub fn unlock_finish(&self, pending: &str, shares: &BTreeMap<String, Sealed>) -> Result<Doc> {
        let mut g = self.lock();
        let Some(p) = g.pending.remove(pending) else {
            return Err(fail(404, "no such pending unlock"));
        };
        if shares.len() != p.entries.len() {
            return Err(fail(
                400,
                format!("one share for each of the {} keys", p.entries.len()),
            ));
        }
        let mut vals = BTreeMap::new();
        for (k, x) in &p.entries {
            let Some(sh) = shares.get(k) else {
                return Err(fail(400, format!("no share for key {k}")));
            };
            let px = p.t.open(sh, INFO_SHARE).map_err(|_| {
                fail(
                    400,
                    format!("the share for {k} isn't sealed to this unlock"),
                )
            })?;
            let v = open_entry(&g.agreement, x, &px).map_err(|e| fail(403, e.to_string()))?;
            vals.insert(k.clone(), v);
        }
        let cur = g.stores.get(&p.store).cloned().unwrap_or_default();
        if store_version(&cur) != p.version {
            return Err(fail(
                409,
                format!("store {} changed during the unlock: unlock again", p.store),
            ));
        }
        let id = rand_id();
        let now = (self.now)();
        let u = g.unlocked.entry(p.store.clone()).or_insert(Unlocked {
            values: BTreeMap::new(),
            version: String::new(),
            ids: BTreeMap::new(),
        });
        u.values = vals;
        u.version = p.version.clone();
        u.ids.insert(id.clone(), now);
        crate::serve::log(&format!("store {} unlocked ({id})", p.store));
        sign(
            &g,
            &json!({"kind": "unlocked", "id": id, "store": p.store, "version": p.version}),
        )
    }

    /// one unlock ends; the store's plaintext goes with its last one
    pub fn lock_unlock(&self, id: &str) -> Result<Doc> {
        let mut g = self.lock();
        let found = g
            .unlocked
            .iter()
            .find(|(_, u)| u.ids.contains_key(id))
            .map(|(n, _)| n.clone());
        if let Some(name) = found {
            if let Some(u) = g.unlocked.get_mut(&name) {
                u.ids.remove(id);
                if u.ids.is_empty() {
                    g.unlocked.remove(&name);
                }
            }
            crate::serve::log(&format!("unlock {id} ended ({name})"));
            return sign(&g, &json!({"kind": "locked", "id": id, "store": name}));
        }
        sign(&g, &json!({"kind": "locked", "id": id, "already": true}))
    }

    /// the signed list of open unlocks (what the phone shows)
    pub fn list_unlocked(&self, nonce: &str) -> Result<Doc> {
        let g = self.lock();
        #[derive(Serialize)]
        struct Row {
            id: String,
            store: String,
            since: String,
        }
        let mut rows: Vec<Row> = g
            .unlocked
            .iter()
            .flat_map(|(name, u)| {
                u.ids.iter().map(|(id, since)| Row {
                    id: id.clone(),
                    store: name.clone(),
                    since: since.utc().rfc3339(),
                })
            })
            .collect();
        rows.sort_by(|a, b| a.since.cmp(&b.since));
        sign(
            &g,
            &json!({"kind": "unlocked-list", "nonce": nonce, "unlocked": rows}),
        )
    }

    // ---- pull (a grant) --------------------------------------------------------------------------------------------

    /// the stores the grant's allowed set names (store:x), each from its open unlock, sealed to the grant's machine. A
    /// finite set: every store it names must be open (else 423 naming it). A cofinite set: the open stores it doesn't
    /// exclude. The deploy-key token store is never served.
    pub fn pull(&self, mut s: Signed) -> Result<Doc> {
        if s.by == "root" {
            let k = self.keys_statement()?;
            s.keys = Some(k);
            s.secrets = Some(self.component_identity());
        }
        let gr = gv::open(&s, &self.trust).map_err(|e| fail(403, e.to_string()))?;
        let g = self.lock();
        let served = |n: &str| n != DEPLOY_KEY_TOKEN_STORE;
        let mut names: Vec<String> = match &gr.pair.allowed.only {
            Some(only) => only
                .iter()
                .filter_map(|x| x.strip_prefix("store:"))
                .filter(|n| served(n))
                .map(String::from)
                .collect(),
            None => g
                .unlocked
                .keys()
                .filter(|n| gr.pair.allowed.contains(&format!("store:{n}")) && served(n))
                .cloned()
                .collect(),
        };
        names.sort();
        let mut merged: BTreeMap<String, String> = BTreeMap::new();
        let mut versions: BTreeMap<String, String> = BTreeMap::new();
        let mut stale: Vec<String> = vec![];
        for n in &names {
            let Some(u) = g.unlocked.get(n) else {
                return Err(fail(
                    423,
                    format!("store {n} is locked: the session waits for Deyao's unlock of it"),
                ));
            };
            merged.extend(u.values.iter().map(|(k, v)| (k.clone(), v.clone())));
            versions.insert(n.clone(), u.version.clone());
            let cur = g.stores.get(n).cloned().unwrap_or_default();
            if u.version != store_version(&cur) {
                stale.push(n.clone()); // a key written without its live value: only a new unlock brings it
            }
        }
        let plain = go_json(&merged)?;
        let sealed = seal_to(&gr.keys.encryption_key, plain.as_bytes(), "jarvis2/secrets")?;
        crate::serve::log(&format!("pulled by {}: {names:?}", gr.machine.0));
        sign(
            &g,
            &json!({"kind": "secrets", "machine": gr.machine, "grant": s.grant.id(), "stores": names,
                "versions": versions, "stale": stale, "sealed": sealed}),
        )
    }

    /// the minter's one GitHub call for an approval
    pub(crate) fn mint(&self, r: &MintRequest) -> Result<Doc> {
        match &self.minter {
            None => Err(fail(503, "no minter configured (KERNEL_MINTER_URL)")),
            Some(m) => m.mint(r).map_err(|e| match e.downcast_ref::<MintError>() {
                Some(me) => fail(me.status, me.msg.clone()),
                None => fail(502, format!("the minter: {e:#}")),
            }),
        }
    }
}

/// v signed by secrets' key
pub(crate) fn sign<T: Serialize>(g: &Inner, v: &T) -> Result<Doc> {
    Ok(g.signer.sign_json(v)?)
}

pub(crate) fn keys_statement(g: &Inner) -> Result<Doc> {
    if g.master_key.is_empty() {
        return Err(fail(
            409,
            "secrets isn't set up yet: Reset or Recover it in the app first",
        ));
    }
    sign(
        g,
        &json!({"kind": "keys", "phone": g.phone_signing, "root": g.root}),
    )
}

/// one key's value, with the phone's share x(p·E) and secrets' k
pub(crate) fn open_entry(agreement: &Opener, x: &KeyEntry, phone_share_x: &[u8]) -> Result<String> {
    let dk = unwrap_with_shares(&x.wrapped, phone_share_x, &agreement.scalar())?;
    let key: [u8; 32] = dk
        .as_slice()
        .try_into()
        .map_err(|_| fail(403, "a data key is 32 bytes"))?;
    let data = jarvis_sig::unb64(&x.data).unwrap_or_default();
    let plain = gcm_open(&key, &data, &keys::key_aad(&x.store, &x.key)).map_err(|_| {
        fail(
            403,
            format!(
                "key {} of {} doesn't decrypt (a wrong or altered entry)",
                x.key, x.store
            ),
        )
    })?;
    Ok(String::from_utf8_lossy(&plain).into_owned())
}

/// verify_own: the payload of a document only if secrets signed it
pub(crate) fn verify_own<T: serde::de::DeserializeOwned>(g: &Inner, d: Option<&Doc>) -> Result<T> {
    match d {
        Some(d) if verify(&g.signer.public_key(), d.payload.as_bytes(), &d.sig) => {
            Ok(serde_json::from_str(&d.payload)?)
        }
        _ => Err(fail(400, "not a document secrets signed")),
    }
}
