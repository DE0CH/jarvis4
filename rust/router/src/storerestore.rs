//! Restoring a store to an earlier version (docs/DESIGN.md "Restoring a store"; core/history.go). The core keeps each
//! store's last versions; putting one back is the phone's signature over the core's exact begin document plus its
//! shares of the keys put back, under one Face ID — no kit, no plaintext outside the core. On a box with no core the
//! kernel's secrets keeps no history: the same routes are the router's own (storeversions.rs). The router's part:
//!
//!     POST /api/core/stores/versions {store, nonce}     the core's signed list, relayed (app, web)
//!     POST /api/core/stores/restore/begin {store, seq}  the core's signed begin document, relayed (the app's review)
//!     POST /api/stores/restore/finish {pending, signature, shares}
//!         the app, after Face ID: the core checks the phone's signature, opens the keys put back and seals each one's
//!         backup to the master key; the router writes those backups (keys/<store>/<key>.json, writer "restore" with
//!         the core's signed receipt) and only then commits; then every running session holding the store is asked to
//!         refresh, as after a write
//!     POST /setup/stores/versions                       the same list for the setup session
//!     …/requests/restore {store, seq, explanation}      an Inbox request (web page, app, setup session; never a
//!                                                       session): it opens the app's restore review

use crate::core::{CoreError, Doc};
use crate::http::Registrar;
use crate::inbox::BadRequest;
use crate::nethttp::{W, write_error, write_json};
use crate::router::Router;
use crate::storedocs::{backup_sha, write_write_err};
use anyhow::{Result, anyhow};
use jarvis_go::GoTime;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;


pub const REQUEST_KIND_RESTORE: &str = "restore";

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
struct Backup {
    e: String,
    data: String,
    sha256: String,
}

/// what the core's finish answers
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
struct RestoreApproved {
    receipt: Option<Doc>,
    backups: BTreeMap<String, Backup>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
struct PutKey {
    key: String,
    e: String,
    #[serde(rename = "dataSha256")]
    data_sha256: String,
    #[serde(rename = "backupSha256")]
    backup_sha256: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
struct RestoreReceipt {
    kind: String,
    pending: String,
    store: String,
    to: i64,
    put: Vec<PutKey>,
    remove: Vec<String>,
}

impl Router {
    /// the phone's approval through the core, the backups into the bucket, then the commit
    pub fn finish_restore(&self, body: &[u8]) -> Result<Value> {
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct In {
            pending: String,
            signature: String,
        }
        let i: In = jarvis_go::unmarshal(body).unwrap_or_default();
        if i.pending.is_empty() || i.signature.is_empty() {
            return Err(BadRequest("pending, signature and shares (the phone's)".into()).into());
        }
        let b = crate::backups::backup_bucket_from_env().ok_or_else(|| {
            anyhow!("the router has no backup credential (BACKUP_READ_ACCESS_KEY): nothing is restored without its backups")
        })?;
        let sc = self.store_core();
        let (status, raw) =
            sc.raw("POST", "/stores/restore/finish", Some(body)).map_err(|e| anyhow!("{} /stores/restore/finish: {e:#}", sc.who()))?;
        if status != 200 {
            return Err(CoreError { status, body: raw, msg: "core: the restore was refused".into() }.into());
        }
        let ap: RestoreApproved = jarvis_go::unmarshal(&raw).unwrap_or_default();
        let (receipt, rc) = match ap.receipt.as_ref().map(|r| (r, r.decode::<RestoreReceipt>())) {
            Some((r, Ok(rc))) if rc.kind == "store-restore-approved" && rc.pending == i.pending => (r.clone(), rc),
            _ => return Err(anyhow!("the core's restore answer isn't readable")),
        };
        let ident = match sc.raw("GET", "/identity", None) {
            Ok((200, b)) => b,
            Ok(_) => return Err(anyhow!("the core's identity isn't readable: <nil>")),
            Err(e) => return Err(anyhow!("the core's identity isn't readable: {e:#}")),
        };
        let ident: Value = serde_json::from_slice(&ident).unwrap_or(Value::Null);
        let docs = {
            let _g = crate::storedocs::STORE_DOCS_MU.lock().unwrap_or_else(|e| e.into_inner());
            self.read_store_docs().remove(&rc.store).unwrap_or_default()
        };
        let now = GoTime::now().utc().rfc3339();
        let put = |key: &str, mut obj: Map<String, Value>| -> Result<()> {
            obj.insert("kind".into(), json!("key-backup"));
            obj.insert("store".into(), json!(rc.store));
            obj.insert("key".into(), json!(key));
            obj.insert("core".into(), ident.clone());
            obj.insert("explanation".into(), json!(docs.keys.get(key).cloned().unwrap_or_default()));
            obj.insert("at".into(), json!(now));
            obj.insert("writer".into(), json!({"by": "restore", "receipt": receipt}));
            b.put(&format!("keys/{}/{key}.json", rc.store), jarvis_go::marshal(&obj).as_bytes())
        };
        let obj = |v: Value| v.as_object().cloned().unwrap_or_default();
        // the backups first: the core changes the store only once they are in the bucket
        for x in &rc.put {
            match ap.backups.get(&x.key) {
                Some(bk) if bk.sha256 == x.backup_sha256 && backup_sha(&bk.e, &bk.data) == x.backup_sha256 => {
                    put(
                        &x.key,
                        obj(json!({"deleted": false, "sealed": {"e": bk.e, "data": bk.data}, "backupSha256": x.backup_sha256,
                            "e": x.e, "dataSha256": x.data_sha256})),
                    )
                    .map_err(|e| anyhow!("the backups weren't written, so nothing was restored: {e:#}"))?;
                }
                _ => return Err(anyhow!("the core's backup of {} doesn't match its receipt: nothing restored", x.key)),
            }
        }
        for k in &rc.remove {
            put(k, obj(json!({"deleted": true, "sealed": null, "backupSha256": "", "e": "", "dataSha256": ""})))
                .map_err(|e| anyhow!("the backups weren't written, so nothing was restored: {e:#}"))?;
        }
        let done = sc.call("/stores/restore/commit", &json!({"pending": i.pending}))?;
        crate::logf!(
            "store {}: version {} put back (phone-approved; {} keys back, {} removed)",
            rc.store,
            rc.to,
            rc.put.len(),
            rc.remove.len()
        );
        let store = rc.store.clone();
        self.drop_requests(
            move |q| q.kind == REQUEST_KIND_RESTORE && q.params.store == store,
            crate::outcomes::OUTCOME_APPROVED,
            None,
        );
        let asked = self.refresh_holders(
            &rc.store,
            &format!(
                "Store {} was restored to its version {} (approved on the phone). Unlock gives these sessions the store as it is now.",
                rc.store, rc.to
            ),
        );
        Ok(json!({"ok": true, "restored": done, "refreshAsked": asked}))
    }

    /// versions and restore/begin on a box with no core (storeversions.rs)
    fn kernel_versions_route(&self, w: &mut W, path: &str, body: &[u8]) {
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct In {
            store: String,
            nonce: String,
            seq: i64,
        }
        let i = match jarvis_go::unmarshal::<In>(body) {
            Ok(i) if !i.store.is_empty() => i,
            _ => return write_error(w, 400, "store (and seq for a restore)"),
        };
        let out = if path == "/stores/versions" {
            self.kernel_store_versions(&i.store, &i.nonce)
        } else {
            self.kernel_restore_begin(&i.store, i.seq)
        };
        match out {
            Err(e) => write_write_err(w, &e),
            Ok(v) => write_json(w, 200, &v),
        }
    }
}

pub fn register_restore(reg: &mut Registrar) {
    for path in ["/stores/versions", "/stores/restore/begin"] {
        reg.app(&format!("POST /api/core{path}"), move |r, w, req| {
            let b = req.read_body(1 << 20);
            if r.secrets_stores.get().is_some() {
                return r.kernel_versions_route(w, path, &b);
            }
            r.relay_stores(w, req, "POST", path, &b);
        });
    }
    reg.app("POST /api/stores/restore/finish", |r, w, req| {
        let b = req.read_body(1 << 20);
        let out = if r.secrets_stores.get().is_some() {
            #[derive(Deserialize, Default)]
            #[serde(default)]
            struct In {
                pending: String,
            }
            let i: In = jarvis_go::unmarshal(&b).unwrap_or_default();
            r.kernel_restore_finish(&i.pending)
        } else {
            r.finish_restore(&b)
        };
        match out {
            Err(e) => write_write_err(w, &e),
            Ok(v) => write_json(w, 200, &v),
        }
    });
    reg.setup_signed("POST /setup/stores/versions", 4 << 20, |r, w, _, b| {
        if r.secrets_stores.get().is_some() {
            return r.kernel_versions_route(w, "/stores/versions", b);
        }
        let c = r.store_core();
        r.relay_to(w, &c, "POST", "/stores/versions", Some(b));
    });
}

