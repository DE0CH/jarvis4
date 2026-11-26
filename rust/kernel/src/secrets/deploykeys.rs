//! Deploy keys (kernel/secrets/deploykeys.go; Deyao, 2026-10-10): adding a repo in the app's Settings adds an SSH
//! public key to that one repo on GitHub as a read/write deploy key, and keeps the private half in a store of its own
//! (`github-<repo>`), which sessions include to clone, pull and push that repo — and no other. The app makes the key
//! pair and wraps the private half's store to the store key P + K, so secrets never sees it. Removing the repo deletes
//! the deploy key on GitHub (by the id GitHub gave it at the add) and the store.
//!
//! Both are phone-approved, and the box alone can never make a key: the GitHub token that may manage deploy keys lives
//! only in the sensitive store `github-deploy-keys`. deploy_key_begin answers, signed, exactly what will happen (the
//! repo, the store, its sensitivity, add or remove, the key id a remove deletes) with the token store's E and a one-off
//! T, as an unlock does. The phone shows it, and under one Face ID signs that text and computes its share of the token
//! store; deploy_key_finish checks the signature and opens the token store with the share for this call only (it never
//! joins the unlocked set). Secrets never uses the token (DECISIONS 232): it seals it to the minter's agreement key
//! (the root key's roster names it) and hands the minter the phone-signed request, drops the plaintext, and takes back
//! the minter's signed answer; then it writes or deletes the repo's store. No other store is touched.
//!
//! Store names can collide (DE0CH/foo-bar and foo/bar both make github-foo-bar). Secrets knows which repo owns a
//! deploy-key store (repo_owner) and refuses an add or a remove for another repo with 409.

use super::keys::{EntryWriter, KeyEntry, entry_writer, valid_entry};
use super::{
    INFO_SHARE, Inner, Result, Secrets, fail, keys_statement, open_entry, rand_id, sha256_hex,
    sign, store_name,
};
use crate::minter::{Minted, Request as MintRequest, TOKEN_INFO, repo_ok};
use jarvis_sig::{Doc, Opener, Sealed, seal_to, verify};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;

/// the store whose GitHub token may manage deploy keys; the only store this flow opens
pub const DEPLOY_KEY_TOKEN_STORE: &str = "github-deploy-keys";
pub const DEPLOY_KEY_TOKEN_KEY: &str = "GITHUB_DEPLOY_KEYS_TOKEN";

pub(crate) struct PendingDeployKey {
    /// the signed begin document: what the phone signs, and what the minter checks
    begin: Doc,
    b: DeployKeyBegin,
    action: String,
    repo: String,
    store: String,
    /// remove: the GitHub key it deletes (0: none known, GitHub isn't called)
    key_id: i64,
    /// remove: only that key goes; the store stays
    orphan: bool,
    /// add: the store's keys holding the private half, wrapped by the app to the store key
    keys: BTreeMap<String, KeyEntry>,
    sensitive: bool,
    /// the token key as it was at begin (its E is what the phone answers)
    token: KeyEntry,
    t: Opener,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeployKeyBegin {
    /// "deploy-key-begin"
    kind: String,
    pending: String,
    action: String,
    repo: String,
    store: String,
    sensitive: bool,
    /// add: the store exists and its contents are replaced
    replaces: bool,
    /// the deploy key's title on GitHub
    title: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    public_key: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    keys: Vec<DeployKeyItem>,
    #[serde(default, skip_serializing_if = "is_zero")]
    key_id: i64,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    orphan: bool,
    token_store: String,
    token_writer: EntryWriter,
    token_data_sha256: String,
    token_backup_sha256: String,
    token_key: String,
    e: String,
    t: String,
}

fn is_zero(n: &i64) -> bool {
    *n == 0
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeployKeyItem {
    key: String,
    e: String,
    data_sha256: String,
}

/// deploy_key_begin's input (see the file comment): the store and the key's title, and for an add the key pair
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct DeployKeyRequest {
    pub action: String,
    pub repo: String,
    pub sensitive: bool,
    pub store: String,
    pub title: String,
    pub public_key: String,
    pub keys: Vec<KeyEntry>,
    pub key_id: i64,
}

/// another repo owns the store
fn owner_clash(g: &Inner, store: &str, repo: &str) -> Result<()> {
    match g.repo_owner.get(store) {
        Some(o) if !o.is_empty() && !o.eq_ignore_ascii_case(repo) => {
            Err(fail(409, format!("store {store} belongs to {o}")))
        }
        _ => Ok(()),
    }
}

impl Secrets {
    /// a pending add or remove for one repo, signed, with the token store's E and a one-off T
    pub fn deploy_key_begin(&self, i: DeployKeyRequest) -> Result<Doc> {
        let mut g = self.lock();
        if g.phone_signing.is_empty() {
            return Err(fail(
                409,
                "secrets isn't set up yet: Reset or Recover it in the app first",
            ));
        }
        if i.action != "add" && i.action != "remove" {
            return Err(fail(400, "action: add or remove"));
        }
        if !repo_ok(&i.repo) {
            return Err(fail(400, "repo: owner/name"));
        }
        let store = i.store.clone();
        if !store_name(&store) || store == DEPLOY_KEY_TOKEN_STORE {
            return Err(fail(
                400,
                format!("store: {} isn't allowed", jarvis_go::fmt::go_quote(&store)),
            ));
        }
        let mut keys = BTreeMap::new();
        for x in &i.keys {
            if keys.contains_key(&x.key) || !valid_entry(x, &store) {
                return Err(fail(
                    400,
                    format!(
                        "bad or repeated key {} for store {store}",
                        jarvis_go::fmt::go_quote(&x.key)
                    ),
                ));
            }
            keys.insert(x.key.clone(), x.clone());
        }
        if i.action == "add" && (i.public_key.is_empty() || keys.is_empty() || i.key_id != 0) {
            return Err(fail(
                400,
                format!("an add brings the key pair: publicKey and the store's keys for {store}"),
            ));
        }
        let Some(tok) = g
            .stores
            .get(DEPLOY_KEY_TOKEN_STORE)
            .and_then(|s| s.get(DEPLOY_KEY_TOKEN_KEY))
            .cloned()
        else {
            return Err(fail(
                404,
                format!(
                    "no store {DEPLOY_KEY_TOKEN_STORE} with contents: the setup session writes its GitHub token ({DEPLOY_KEY_TOKEN_KEY})"
                ),
            ));
        };
        owner_clash(&g, &store, &i.repo)?;
        let old = g.stores.get(&store).cloned();
        let exists = old.is_some();
        let (mut key_id, mut orphan) = (0i64, false);
        let mut sensitive = i.sensitive;
        if i.action == "remove" {
            sensitive = exists && !g.not_sensitive.contains(&store);
            key_id = g.repo_key_id.get(&store).copied().unwrap_or(0);
            if i.key_id < 0 {
                return Err(fail(400, "keyId: GitHub's id of the key"));
            }
            if i.key_id != 0 && i.key_id != key_id {
                key_id = i.key_id;
                orphan = true;
            }
        } else {
            // an existing sensitive store stays sensitive
            sensitive = sensitive || (exists && !g.not_sensitive.contains(&store));
        }
        let t = Opener::generate();
        let id = rand_id();
        let mut b = DeployKeyBegin {
            kind: "deploy-key-begin".into(),
            pending: id.clone(),
            action: i.action.clone(),
            repo: i.repo.clone(),
            store: store.clone(),
            sensitive,
            replaces: i.action == "add" && old.as_ref().is_some_and(|o| !o.is_empty()),
            title: i.title.clone(),
            public_key: String::new(),
            keys: vec![],
            key_id,
            orphan,
            token_store: DEPLOY_KEY_TOKEN_STORE.into(),
            token_writer: entry_writer(&tok),
            token_data_sha256: sha256_hex(&tok.data),
            token_backup_sha256: tok.backup_sha256.clone(),
            token_key: DEPLOY_KEY_TOKEN_KEY.into(),
            e: tok.wrapped.e.clone(),
            t: t.public_key(),
        };
        if i.action == "add" {
            b.public_key = i.public_key.clone();
            b.keys = keys
                .iter()
                .map(|(k, x)| DeployKeyItem {
                    key: k.clone(),
                    e: x.wrapped.e.clone(),
                    data_sha256: sha256_hex(&x.data),
                })
                .collect();
        } else {
            keys.clear();
        }
        let d = sign(&g, &b)?;
        g.pending_keys.insert(
            id,
            PendingDeployKey {
                begin: d.clone(),
                b,
                action: i.action,
                repo: i.repo,
                store,
                key_id,
                orphan,
                keys,
                sensitive,
                token: tok,
                t,
            },
        );
        Ok(d)
    }

    /// the phone's signature over the begin document and its share of the token store, sealed to T. One try: the
    /// pending and its one-off key are gone either way.
    pub fn deploy_key_finish(&self, pending: &str, share: &Sealed, phone_sig: &str) -> Result<Doc> {
        let (p, sealed) = self.open_deploy_key_token(pending, share, phone_sig)?;
        let mut key_id = p.key_id;
        if p.action == "add" || key_id != 0 {
            // the minter is called without secrets' lock (GitHub may take seconds); it gets the token sealed to it alone
            let m = self.mint_for(&p, phone_sig, sealed)?;
            key_id = m.key_id;
        }
        let mut g = self.lock();
        if p.action == "remove" {
            if p.orphan {
                crate::serve::log(&format!(
                    "deploy key: orphan key {key_id} of {} deleted on GitHub; store {} kept",
                    p.repo, p.store
                ));
                return sign(
                    &g,
                    &json!({"kind": "deploy-key-removed", "pending": pending, "repo": p.repo, "store": p.store,
                        "deleted": 1, "keyId": key_id, "orphan": true}),
                );
            }
            g.stores.remove(&p.store);
            g.not_sensitive.remove(&p.store);
            g.unlocked.remove(&p.store);
            g.repo_owner.remove(&p.store);
            g.repo_key_id.remove(&p.store);
            let deleted = if key_id != 0 { 1 } else { 0 };
            crate::serve::log(&format!(
                "deploy key: {} removed (GitHub key {key_id}), store {} deleted",
                p.repo, p.store
            ));
            return sign(
                &g,
                &json!({"kind": "deploy-key-removed", "pending": pending, "repo": p.repo, "store": p.store,
                    "deleted": deleted, "keyId": key_id}),
            );
        }
        if let Err(e) = owner_clash(&g, &p.store, &p.repo) {
            // another repo's add finished first while the minter called GitHub: the key just added is an orphan
            crate::serve::log(&format!(
                "deploy key: {} lost {} to {}; GitHub key {key_id} is an orphan",
                p.repo,
                p.store,
                g.repo_owner.get(&p.store).cloned().unwrap_or_default()
            ));
            return Err(fail(
                409,
                format!(
                    "{e}: GitHub key {key_id} on {} is an orphan now (remove it by id)",
                    p.repo
                ),
            ));
        }
        let existed = g.stores.contains_key(&p.store);
        let replaced = g.repo_key_id.get(&p.store).copied().unwrap_or(0);
        let now = self.now_rfc3339();
        let keys: BTreeMap<String, KeyEntry> = p
            .keys
            .iter()
            .map(|(k, x)| {
                let mut x = x.clone();
                // stored only after GitHub took the phone-signed key: secrets vouches (no backup)
                x.writer = Some(EntryWriter {
                    by: "core".into(),
                    ..Default::default()
                });
                x.at = now.clone();
                x.backup_sha256.clear();
                (k.clone(), x)
            })
            .collect();
        g.stores.insert(p.store.clone(), keys);
        g.repo_owner.insert(p.store.clone(), p.repo.clone());
        g.repo_key_id.insert(p.store.clone(), key_id);
        g.unlocked.remove(&p.store); // an earlier key's plaintext
        if p.sensitive {
            g.not_sensitive.remove(&p.store);
        } else if !existed {
            g.not_sensitive.insert(p.store.clone());
        }
        let sensitive = !g.not_sensitive.contains(&p.store);
        crate::serve::log(&format!(
            "deploy key: {} added (GitHub key {key_id}), store {} (sensitive={sensitive})",
            p.repo, p.store
        ));
        let mut out = json!({"kind": "deploy-key-added", "pending": pending, "repo": p.repo, "store": p.store,
            "sensitive": sensitive, "title": p.b.title, "publicKey": p.b.public_key, "keyId": key_id});
        if replaced != 0 && replaced != key_id {
            out["replacedKeyId"] = json!(replaced); // the earlier key stays on GitHub until a remove by its id
        }
        sign(&g, &out)
    }

    /// the minter's one GitHub call for this approval, its signed answer checked against the roster's minter
    fn mint_for(&self, p: &PendingDeployKey, phone_sig: &str, token: Sealed) -> Result<Minted> {
        let keys = keys_statement(&self.lock())?;
        let mid = self
            .trust
            .member("minter")
            .map_err(|e| fail(503, format!("the minter: {e}")))?;
        let d = self
            .mint(&MintRequest {
                begin: p.begin.clone(),
                phone_sig: phone_sig.into(),
                keys,
                token,
            })
            .inspect_err(|e| {
                crate::serve::log(&format!(
                    "deploy key: {} {} failed at the minter: {e:#}",
                    p.action, p.repo
                ))
            })?;
        let m: Option<Minted> = verify(&mid.signing_key, d.payload.as_bytes(), &d.sig)
            .then(|| serde_json::from_str::<Minted>(&d.payload).ok())
            .flatten();
        match m {
            Some(m)
                if m.kind == "deploy-key-minted"
                    && m.pending == p.b.pending
                    && m.action == p.action
                    && m.repo == p.repo
                    && !(p.action == "remove" && m.key_id != p.key_id)
                    && m.key_id > 0 =>
            {
                Ok(m)
            }
            _ => Err(fail(
                502,
                "the minter's answer isn't the roster's minter's for this request",
            )),
        }
    }

    /// the pending's checks (the phone signed exactly the begin document) and the token store opened with the phone's
    /// share — its plaintext only sealed to the minter, for this request
    fn open_deploy_key_token(
        &self,
        pending: &str,
        share: &Sealed,
        phone_sig: &str,
    ) -> Result<(PendingDeployKey, Sealed)> {
        let mut g = self.lock();
        let Some(p) = g.pending_keys.remove(pending) else {
            return Err(fail(404, "no such pending deploy-key request"));
        };
        owner_clash(&g, &p.store, &p.repo)?;
        if g.phone_signing.is_empty()
            || !verify(&g.phone_signing, p.begin.payload.as_bytes(), phone_sig)
        {
            return Err(fail(
                403,
                "the iPhone's signature doesn't cover this request",
            ));
        }
        let x =
            p.t.open(share, INFO_SHARE)
                .map_err(|_| fail(400, "the share isn't sealed to this request"))?;
        let tok = open_entry(&g.agreement, &p.token, &x)
            .map_err(|e| fail(403, format!("the token key doesn't decrypt: {e}")))?;
        if tok.is_empty() {
            return Err(fail(
                400,
                format!("the store {DEPLOY_KEY_TOKEN_STORE} holds no {DEPLOY_KEY_TOKEN_KEY}"),
            ));
        }
        if p.action == "remove" && p.key_id == 0 {
            // no GitHub key known: nothing for the minter
            return Ok((
                p,
                Sealed {
                    e: String::new(),
                    data: String::new(),
                },
            ));
        }
        let mid = self
            .trust
            .member("minter")
            .map_err(|e| fail(503, format!("the minter: {e}")))?;
        let sealed = seal_to(
            &mid.agreement_key,
            tok.as_bytes(),
            &format!("{TOKEN_INFO}{pending}"),
        )
        .map_err(|e| fail(500, format!("sealing the token to the minter: {e}")))?;
        drop(tok);
        crate::serve::log(&format!(
            "deploy key: {} {} approved by the phone; {DEPLOY_KEY_TOKEN_STORE} opened and sealed to the minter",
            p.action, p.repo
        ));
        Ok((p, sealed))
    }
}
