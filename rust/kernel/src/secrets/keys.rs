//! A store is a set of keys, each sealed on its own (Deyao, 2026-10-13: "writing one key by
//! name is allowed, and it doesn't just overwrite the whole key store"). Each key's value is under its own data key
//! (the store's and the key's names as associated data, so a value doesn't decrypt under another name), and that data
//! key is wrapped to the combined key P + K (phone + secrets) — the public store key, so anyone can write a key and
//! nobody but the phone and secrets together can read one. Writing a key replaces that key only.
//!
//! write_key is open, like create_store: a write can't reveal a secret, and the router decides who may write. What
//! secrets records is who wrote each key, which unlock_begin shows the phone before it gives its share:
//!   - setup: the setup key's signature over writer_text (the phone checks it against keys/setup.pub);
//!   - machine: a session machine, named by the grant it holds now and its signature over writer_text with that
//!     grant's machine key (checked here);
//!   - router: the router (unsigned, named for what it is: the Claude login stores);
//!   - core: secrets' own wrapping (a Recover's bundle, a deploy key);
//!   - replay: a restore (DECISIONS 232): the router puts an earlier key back by writing that very entry with secrets'
//!     signed key-written receipt; secrets checks the receipt is its own for exactly this store, key, E, data and
//!     backup, and the entry keeps the writer and time the receipt names. A replayed delete needs no receipt.
//!
//! A write may carry the value sealed to secrets as well (live): secrets uses it only to keep an open unlock of the
//! store current, so the key reaches the next pull (D1), and never stores it.

use super::{Inner, Result, Secrets, fail, is_hex64, sha256_hex, sign, store_name, verify_own};
use crate::secrets::crypto::WrappedKey;
use crate::secrets::deploykeys::DEPLOY_KEY_TOKEN_STORE;
use jarvis_doc::Kind;
use jarvis_doc::gv::{self, Signed};
use jarvis_sig::{Doc, Sealed, verify};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// one key of a store
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyEntry {
    #[serde(default)]
    pub store: String,
    #[serde(default)]
    pub key: String,
    /// the data key, to phone + secrets
    #[serde(default)]
    pub wrapped: WrappedKey,
    /// AES-GCM(value) under the data key, key_aad(store, key) as associated data
    #[serde(default)]
    pub data: String,
    /// set by secrets from the write, never taken from a bundle: who wrote it, when, and the sha256 of its backup
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub writer: Option<EntryWriter>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub at: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub backup_sha256: String,
}

/// who wrote a key (see the file comment)
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryWriter {
    /// "setup" | "machine" | "router" | "core" | "replay"
    #[serde(default)]
    pub by: String,
    /// setup: its signature over writer_text (the phone checks it)
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sig: String,
    /// machine: the session machine (secrets checked its signature)
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub machine: String,
}

/// the stores the router writes (the Claude accounts, rust/router/src/claudeaccounts.rs): ^claude(-[a-z0-9]+)*$
fn router_store(name: &str) -> bool {
    let Some(rest) = name.strip_prefix("claude") else {
        return false;
    };
    rest.is_empty()
        || (rest.starts_with('-')
            && rest[1..].split('-').all(|p| {
                !p.is_empty()
                    && p.bytes()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
            }))
}

/// names a machine's write never makes (a repo's deploy-key store is made by its deploy-key call)
fn reserved_store(name: &str) -> bool {
    name == DEPLOY_KEY_TOKEN_STORE || name.starts_with("github-")
}

/// a key's value is bound to its store and its name
pub fn key_aad(store: &str, key: &str) -> Vec<u8> {
    format!("{store}\n{key}").into_bytes()
}

/// what a key's writer signs — the store, the key, its E and the sha256 of its data ("" and "" for a delete), and the
/// sha256 of the key's backup ("" when it has none)
pub fn writer_text(store: &str, key: &str, e: &str, data: &str, backup_sha256: &str) -> String {
    let sum = if data.is_empty() {
        String::new()
    } else {
        sha256_hex(data)
    };
    format!("jarvis2-store-key\n{store}\n{key}\n{e}\n{sum}\n{backup_sha256}")
}

/// ^[A-Za-z_][A-Za-z0-9_]{0,127}$
pub fn key_name(k: &str) -> bool {
    let b = k.as_bytes();
    !b.is_empty()
        && b.len() <= 128
        && (b[0].is_ascii_alphabetic() || b[0] == b'_')
        && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_')
}

/// one store's contents as a hash (each key's name, E and data hash): an unlock and a carried copy are "current" while
/// the store's version is the one they were taken at
pub fn store_version(keys: &BTreeMap<String, KeyEntry>) -> String {
    let mut h = Sha256::new();
    for (k, x) in keys {
        h.update(format!("{k}\t{}\t{}\n", x.wrapped.e, sha256_hex(&x.data)).as_bytes());
    }
    super::hex(&h.finalize())
}

/// a key as a writer or a bundle brings it (callers set writer and at)
pub fn valid_entry(x: &KeyEntry, store: &str) -> bool {
    x.store == store
        && key_name(&x.key)
        && !x.wrapped.e.is_empty()
        && !x.wrapped.wrapped.is_empty()
        && !x.data.is_empty()
}

/// write_key's input. Delete: the key goes (no wrapped/data). Writer "setup" brings sig; writer "machine" brings sig
/// and grant, the grant the machine holds now; writer "replay" brings receipt (a put).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct WriteKeyInput {
    pub store: String,
    pub key: String,
    pub delete: bool,
    pub wrapped: WrappedKey,
    pub data: String,
    pub backup_sha256: String,
    pub writer: String,
    pub sig: String,
    /// writer "machine": the grant the machine holds now
    pub grant: Option<Signed>,
    /// the value sealed to secrets (INFO_LIVE + "\n" + store + "\n" + key)
    pub live: Option<Sealed>,
    /// writer "replay": secrets' key-written receipt of this very entry
    pub receipt: Option<Doc>,
}

/// what a key-written answer says
#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct Receipt {
    kind: String,
    store: String,
    key: String,
    deleted: bool,
    e: String,
    data_sha256: String,
    backup_sha256: String,
    writer: Option<EntryWriter>,
    at: String,
}

/// a store's key as the signed store list shows it (names and writers, never values)
#[derive(Debug, Clone, Serialize)]
pub struct KeyRow {
    pub name: String,
    pub at: String,
    pub writer: Option<EntryWriter>,
}

pub fn key_rows(keys: &BTreeMap<String, KeyEntry>) -> Vec<KeyRow> {
    keys.iter()
        .map(|(k, x)| {
            let w = match &x.writer {
                // the list doesn't carry signatures (unlock_begin does)
                Some(w) if w.by == "setup" => Some(EntryWriter {
                    by: "setup".into(),
                    ..Default::default()
                }),
                w => w.clone(),
            };
            KeyRow {
                name: k.clone(),
                at: x.at.clone(),
                writer: w,
            }
        })
        .collect()
}

/// unlock_begin's writer field for a key ({by, sig} | {by, machine} | {by: "core"})
pub fn entry_writer(x: &KeyEntry) -> EntryWriter {
    x.writer.clone().unwrap_or_else(|| EntryWriter {
        by: "core".into(),
        ..Default::default()
    })
}

impl Secrets {
    /// one key written (or deleted). A writer's first key of a name secrets doesn't have makes that store (sensitive);
    /// a machine never writes the deploy-key token store or a repo's deploy-key store, nor makes a github-* store; the
    /// router writes only claude-* stores; a replay only puts an existing store's key back (never a repo's deploy-key
    /// store). Unlocked plaintext of the store stays as it was until locked (the store's version tells it is behind).
    pub fn write_key(&self, i: WriteKeyInput) -> Result<Doc> {
        let mut g = self.lock();
        let mut i = i;
        if g.master_key.is_empty() {
            return Err(fail(
                409,
                "this core isn't set up yet: Reset or Recover it in the app first",
            ));
        }
        let exists = g.stores.contains_key(&i.store);
        if !store_name(&i.store) {
            return Err(fail(
                400,
                format!(
                    "store: {} isn't one a key is written to",
                    jarvis_go::fmt::go_quote(&i.store)
                ),
            ));
        }
        if !key_name(&i.key) {
            return Err(fail(
                400,
                "key: letters, digits and _, not starting with a digit",
            ));
        }
        if !i.backup_sha256.is_empty() && !is_hex64(&i.backup_sha256) {
            return Err(fail(400, "backupSha256: hex sha256"));
        }
        let mut e = String::new();
        if i.delete {
            let has = g
                .stores
                .get(&i.store)
                .is_some_and(|k| k.contains_key(&i.key));
            if !has {
                return Err(fail(404, format!("store {} has no key {}", i.store, i.key)));
            }
            i.wrapped = WrappedKey::default();
            i.data.clear();
        } else {
            let x = KeyEntry {
                store: i.store.clone(),
                key: i.key.clone(),
                wrapped: i.wrapped.clone(),
                data: i.data.clone(),
                ..Default::default()
            };
            if !valid_entry(&x, &i.store) {
                return Err(fail(400, "not a sealed key: wrapped {e, wrapped} and data"));
            }
            e = i.wrapped.e.clone();
        }
        let text = writer_text(&i.store, &i.key, &e, &i.data, &i.backup_sha256);
        let now = self.now_rfc3339();
        let mut at = now.clone();
        let w = match i.writer.as_str() {
            "setup" => {
                if i.sig.is_empty() {
                    return Err(fail(400, "a setup write carries the setup key's signature"));
                }
                EntryWriter {
                    by: "setup".into(),
                    sig: i.sig.clone(),
                    ..Default::default()
                }
            }
            "machine" => {
                let Some(gs) = &i.grant else {
                    return Err(fail(
                        400,
                        "a machine write carries the grant the machine holds",
                    ));
                };
                let gr = match gv::open(gs, &self.trust) {
                    Ok(gr) if gr.machine.kind() == Some(Kind::Machine) => gr,
                    Ok(_) => return Err(fail(403, "a machine write's grant: <nil>")),
                    Err(e) => return Err(fail(403, format!("a machine write's grant: {e}"))),
                };
                if !verify(&gr.keys.signing_key, text.as_bytes(), &i.sig) {
                    return Err(fail(403, "not signed by the key of the grant's machine"));
                }
                if i.store == DEPLOY_KEY_TOKEN_STORE || g.repo_owner.contains_key(&i.store) {
                    return Err(fail(
                        403,
                        format!(
                            "store {}'s keys come only from a phone-approved deploy-key call",
                            i.store
                        ),
                    ));
                }
                if !exists && reserved_store(&i.store) {
                    return Err(fail(
                        403,
                        format!(
                            "store {} doesn't exist and a session doesn't make it: github-* stores come only from a repo's deploy key (Settings → Repos)",
                            i.store
                        ),
                    ));
                }
                EntryWriter {
                    by: "machine".into(),
                    machine: gr.machine.machine_id().to_string(),
                    ..Default::default()
                }
            }
            "router" => {
                // the router's own writes: only the Claude account stores, whose pair it refreshes with nobody there
                // (DECISIONS 185, 188); unsigned, so the writer is named as what it is and the phone shows it
                if !router_store(&i.store) {
                    return Err(fail(
                        403,
                        format!(
                            "the router writes only the Claude login stores (claude, claude-<name>), not {}",
                            i.store
                        ),
                    ));
                }
                EntryWriter {
                    by: "router".into(),
                    ..Default::default()
                }
            }
            "replay" => {
                if !exists || g.repo_owner.contains_key(&i.store) {
                    return Err(fail(
                        403,
                        format!(
                            "a replay puts a key of an existing store back, never a repo's deploy-key store ({})",
                            i.store
                        ),
                    ));
                }
                if i.delete {
                    EntryWriter {
                        by: "replay".into(),
                        ..Default::default()
                    }
                } else {
                    let r: Receipt = verify_own(&g, i.receipt.as_ref()).map_err(|e| {
                        fail(
                            403,
                            format!("a replay carries secrets' own receipt of the entry: {e:#}"),
                        )
                    })?;
                    let ok = r.kind == "key-written"
                        && !r.deleted
                        && r.store == i.store
                        && r.key == i.key
                        && r.e == e
                        && r.data_sha256 == sha256_hex(&i.data)
                        && r.backup_sha256 == i.backup_sha256;
                    let Some(rw) = r.writer.filter(|_| ok) else {
                        return Err(fail(
                            403,
                            "the receipt isn't of this entry (store, key, E, data and backup)",
                        ));
                    };
                    at = r.at;
                    rw
                }
            }
            _ => return Err(fail(400, "writer: setup, machine, router or replay")),
        };
        let before = store_version(&g.stores.get(&i.store).cloned().unwrap_or_default());
        let keys = g.stores.entry(i.store.clone()).or_default(); // a writer's first key makes the store, sensitive
        if i.delete {
            keys.remove(&i.key);
        } else {
            keys.insert(
                i.key.clone(),
                KeyEntry {
                    store: i.store.clone(),
                    key: i.key.clone(),
                    wrapped: i.wrapped.clone(),
                    data: i.data.clone(),
                    writer: Some(w.clone()),
                    at: at.clone(),
                    backup_sha256: i.backup_sha256.clone(),
                },
            );
        }
        live_update(&mut g, &i.store, &i.key, i.delete, i.live.as_ref(), &before);
        crate::serve::log(&format!(
            "store {}: key {} {} by {} {} ({})",
            i.store,
            i.key,
            if i.delete { "deleted" } else { "written" },
            w.by,
            w.machine,
            i.writer
        ));
        let sum = if i.data.is_empty() {
            String::new()
        } else {
            sha256_hex(&i.data)
        };
        let version = store_version(&g.stores.get(&i.store).cloned().unwrap_or_default());
        let mut out = json!({"kind": "key-written", "store": i.store, "key": i.key, "deleted": i.delete, "e": e,
            "dataSha256": sum, "backupSha256": i.backup_sha256, "writer": w, "at": at,
            "sensitive": !g.not_sensitive.contains(&i.store), "version": version});
        if i.writer == "replay" {
            out["replayedAt"] = json!(now);
        }
        sign(&g, &out)
    }
}

/// a written key's value (sealed to secrets) into an open unlock of its store, which stays current (D1; after the
/// write)
pub(crate) fn live_update(
    g: &mut Inner,
    store: &str,
    key: &str,
    deleted: bool,
    live: Option<&Sealed>,
    before: &str,
) {
    let cur = store_version(&g.stores.get(store).cloned().unwrap_or_default());
    let value = if deleted {
        None
    } else {
        let Some(l) = live else {
            return; // the unlock is behind until the phone unlocks again
        };
        match g
            .agreement
            .open(l, &format!("{}\n{store}\n{key}", super::INFO_LIVE))
        {
            Ok(v) => Some(String::from_utf8_lossy(&v).into_owned()),
            Err(_) => {
                if g.unlocked.contains_key(store) {
                    crate::serve::log(&format!(
                        "store {store}: key {key}'s live value doesn't open; the unlock is behind"
                    ));
                }
                return;
            }
        }
    };
    let Some(u) = g.unlocked.get_mut(store) else {
        return;
    };
    // the unlock had the store as it was just before this write
    let current = u.version == before;
    match value {
        None => {
            u.values.remove(key);
        }
        Some(v) => {
            u.values.insert(key.into(), v);
        }
    }
    if current {
        u.version = cur;
    }
}
