//! Each store's earlier versions on a box with no core (NO_CORE=1; DECISIONS 232: the kernel's secrets keeps nothing
//! it doesn't need, so no history). The router keeps them in Postgres (store_versions): after every key write secrets
//! took, the store's keys as they now are — each entry the router saw written (wrapped to P + K: it reveals nothing),
//! secrets' signed key-written receipt for it and the backup object the router wrote for it — and null for a key the
//! router never saw written (a Recover's). A restore writes each earlier entry back to secrets with its receipt
//! (writer "replay": secrets checks the receipt is its own for exactly that entry and keeps the writer it names), and
//! deletes the keys the earlier version didn't have; the put-back keys' backups go back into the bucket first, and
//! each removed key gets a delete marker there after (writer "replay" with secrets' receipt of the delete, which the
//! app's Recover checks against the secrets its kit derives), so a Recover from the bucket doesn't bring it back.
//!
//!     POST /api/core/stores/versions {store, nonce}     the router's list (the app checks each key's receipt)
//!     POST /api/core/stores/restore/begin {store, seq}  what putting version seq back changes: put (with receipts),
//!                                                       remove, keep, cannot (keys whose earlier value the router
//!                                                       never saw); pending for 10 minutes
//!     POST /api/stores/restore/finish {pending}         the app's Allow: the writes, then sessions holding the store
//!                                                       are asked to refresh
//!     POST /setup/stores/versions                       the list for the setup session

use crate::backups::BackupBucket;
use crate::core::{CoreError, Doc};
use crate::db::DB;
use crate::inbox::Forbidden;
use crate::router::Router;
use anyhow::{Result, anyhow};
use jarvis_go::GoTime;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

pub const STORE_VERSIONS_KEPT: i32 = 50;
pub const RESTORE_PENDING_TTL: Duration = Duration::from_secs(10 * 60);

/// one key of a version as the router saw it written
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct VerEntry {
    pub wrapped: Value,
    pub data: String,
    #[serde(rename = "backupSha256", skip_serializing_if = "String::is_empty")]
    pub backup_sha256: String,
    pub receipt: Option<Doc>,
    /// the bucket's keys/<store>/<key>.json as the router wrote it
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backup: Option<Box<RawValue>>,
}

/// what secrets' key-written receipt says
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct KeyReceipt {
    pub kind: String,
    pub store: String,
    pub key: String,
    pub deleted: bool,
    pub e: String,
    #[serde(rename = "dataSha256")]
    pub data_sha256: String,
    #[serde(rename = "backupSha256")]
    pub backup_sha256: String,
    pub writer: Option<Box<RawValue>>,
    pub at: String,
    pub version: String,
}

fn receipt_of(e: Option<&VerEntry>) -> KeyReceipt {
    e.and_then(|e| e.receipt.as_ref())
        .and_then(|d| d.decode().ok())
        .unwrap_or_default()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct VerCause {
    /// write | delete | restore
    pub kind: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub key: String,
    /// restore: the version put back
    #[serde(skip_serializing_if = "is_zero")]
    pub from: i64,
    /// write, delete: who (as secrets' receipt names it, a setup writer without its signature)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub writer: Option<Box<RawValue>>,
}

fn is_zero(n: &i64) -> bool {
    *n == 0
}

/// a version's keys: name → entry, None for a key the router never saw written
pub type VerKeys = BTreeMap<String, Option<VerEntry>>;

#[derive(Debug, Clone, Default)]
pub struct StoreVer {
    pub seq: i64,
    pub at: GoTime,
    pub version: String,
    pub cause: VerCause,
    pub keys: VerKeys,
}

/// one store's row of secrets' signed list
#[derive(Debug, Clone, Default)]
pub struct SecretsStore {
    pub names: Vec<String>,
    pub version: String,
    pub sensitive: bool,
}

#[derive(Debug, Clone)]
struct RestorePlan {
    store: String,
    to: StoreVer,
    /// the store's version at begin
    current: String,
    put: Vec<String>,
    remove: Vec<String>,
    expires: Instant,
}

static RESTORE_PENDING: LazyLock<Mutex<BTreeMap<String, RestorePlan>>> =
    LazyLock::new(Default::default);

/// the newest version's keys, for exactly the names the store has now (a name the router never saw written is None);
/// a newest version that isn't the store as it is makes every key unseen
pub fn current_keys(latest: Option<&StoreVer>, names: &[String], version: &str) -> VerKeys {
    names
        .iter()
        .map(|n| {
            let e = latest
                .filter(|l| l.version == version)
                .and_then(|l| l.keys.get(n).cloned().flatten());
            (n.clone(), e)
        })
        .collect()
}

/// a writer without a setup signature (the list doesn't carry signatures; each key's receipt does)
pub fn strip_sig(w: Option<&RawValue>) -> Option<Box<RawValue>> {
    let mut m: serde_json::Map<String, Value> = serde_json::from_str(w?.get()).ok()?;
    m.remove("sig");
    RawValue::from_string(jarvis_go::marshal(&m)).ok()
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct VerKeyRow {
    pub name: String,
    pub e: String,
    #[serde(rename = "dataSha256")]
    pub data_sha256: String,
    #[serde(rename = "backupSha256", skip_serializing_if = "String::is_empty")]
    pub backup_sha256: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub writer: Option<Box<RawValue>>,
    /// secrets' signed receipt (None: a key the router never saw written)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt: Option<Doc>,
}

pub fn key_rows(keys: &VerKeys) -> Vec<VerKeyRow> {
    keys.iter()
        .map(|(k, e)| {
            let rc = receipt_of(e.as_ref());
            VerKeyRow {
                name: k.clone(),
                e: rc.e,
                data_sha256: rc.data_sha256,
                backup_sha256: rc.backup_sha256,
                at: rc.at,
                writer: rc.writer,
                receipt: e.as_ref().and_then(|e| e.receipt.clone()),
            }
        })
        .collect()
}

/// a removed key's delete marker over its last backup (keys/<store>/<key>.json): writer "replay" with secrets' signed
/// receipt of the delete; a few tries, the store already changed
fn put_removal(
    b: &BackupBucket,
    store: &str,
    key: &str,
    receipt: &Doc,
    ident: &[u8],
) -> Result<()> {
    let mut obj = json!({"kind": "key-backup", "store": store, "key": key, "deleted": true, "sealed": null, "backupSha256": "", "e": "",
        "dataSha256": "", "writer": {"by": "replay", "receipt": receipt}, "explanation": "removed by a restore",
        "at": GoTime::now().utc().rfc3339()});
    if let Ok(v) = serde_json::from_slice::<Value>(ident) {
        obj["core"] = v;
    }
    let raw = jarvis_go::marshal(&obj);
    let mut err = anyhow!("not tried");
    for i in 0..3u64 {
        match b.put(&format!("keys/{store}/{key}.json"), raw.as_bytes()) {
            Ok(()) => return Ok(()),
            Err(e) => err = e,
        }
        std::thread::sleep(Duration::from_secs(i + 1));
    }
    Err(err)
}

/// a repo's deploy-key store (its keys come only from a phone-approved deploy-key call)
pub fn is_repo_store(r: &Router, store: &str) -> bool {
    r.repos().iter().any(|e| e.store == store)
}

fn core_err(status: u16, msg: impl Into<String>) -> anyhow::Error {
    CoreError {
        status,
        body: vec![],
        msg: msg.into(),
    }
    .into()
}

impl Router {
    fn versions_db(&self) -> Option<&DB> {
        self.st.db()
    }

    /// a store's kept versions, newest first
    pub fn store_versions(&self, store: &str) -> Result<Vec<StoreVer>> {
        let db = self.versions_db().ok_or_else(|| anyhow!("no database"))?;
        let rows = db.conn()?.query(
            "SELECT seq, at, version, cause::text, keys::text FROM store_versions WHERE store = $1 ORDER BY seq DESC",
            &[&store],
        )?;
        Ok(rows
            .iter()
            .map(|row| {
                let seq: i32 = row.get(0);
                let at: time::OffsetDateTime = row.get(1);
                let cause: String = row.get(3);
                let keys: String = row.get(4);
                StoreVer {
                    seq: seq as i64,
                    at: GoTime(Some(at)),
                    version: row.get(2),
                    // as the database has them: a null key is one never seen written, not a zero value
                    cause: serde_json::from_str(&cause).unwrap_or_default(),
                    keys: serde_json::from_str::<Option<VerKeys>>(&keys)
                        .ok()
                        .flatten()
                        .unwrap_or_default(),
                }
            })
            .collect())
    }

    /// the next version of a store; the oldest beyond STORE_VERSIONS_KEPT go
    pub fn add_version(
        &self,
        store: &str,
        version: &str,
        cause: &VerCause,
        keys: &VerKeys,
    ) -> Result<i64> {
        let db = self.versions_db().ok_or_else(|| anyhow!("no database"))?;
        let (cb, kb) = (jarvis_go::marshal(cause), jarvis_go::marshal(keys));
        let mut c = db.conn()?;
        let mut tx = c.transaction()?;
        tx.execute(
            "SELECT pg_advisory_xact_lock(hashtext('store-versions:' || $1))",
            &[&store],
        )?;
        let seq: i32 = tx
            .query_one(
                "SELECT (coalesce(max(seq), 0) + 1)::int FROM store_versions WHERE store = $1",
                &[&store],
            )?
            .get(0);
        tx.execute(
            "INSERT INTO store_versions (store, seq, version, cause, keys) VALUES ($1, $2, $3, $4::text::jsonb, $5::text::jsonb)",
            &[&store, &seq, &version, &cb, &kb],
        )?;
        tx.execute(
            "DELETE FROM store_versions WHERE store = $1 AND seq <= $2",
            &[&store, &(seq - STORE_VERSIONS_KEPT)],
        )?;
        tx.commit()?;
        Ok(seq as i64)
    }

    /// one store's row of secrets' signed list (its key names and version); None: no such store
    pub fn secrets_store(&self, store: &str) -> Result<Option<SecretsStore>> {
        let d = self.store_core().call(
            "/stores",
            &json!({"nonce": format!("versions-{}", crate::util::rand_id())}),
        )?;
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct List {
            stores: Vec<crate::storedocs::CoreStoreRow>,
        }
        let list: List = d.decode()?;
        Ok(list
            .stores
            .into_iter()
            .find(|s| s.name == store)
            .map(|s| SecretsStore {
                names: s.keys.into_iter().map(|k| k.name).collect(),
                version: s.version,
                sensitive: s.sensitive,
            }))
    }

    /// after secrets took a write on a box with no core, the store's new version (best effort: the write stands either
    /// way; a version the router missed only makes its keys unseen)
    pub fn record_key_write(
        &self,
        store: &str,
        key: &str,
        entry: Option<VerEntry>,
        receipt: Option<&Doc>,
    ) {
        let Some(receipt) = receipt else { return };
        if self.secrets_stores.get().is_none() || self.versions_db().is_none() {
            return;
        }
        let Ok(rc) = receipt.decode::<KeyReceipt>() else {
            return;
        };
        if rc.kind != "key-written" {
            return;
        }
        if let Err(e) = self.record_version(store, key, entry, receipt, &rc) {
            crate::logf!("store {store}: the version after {key} wasn't kept: {e:#}");
        }
    }

    fn record_version(
        &self,
        store: &str,
        key: &str,
        entry: Option<VerEntry>,
        receipt: &Doc,
        rc: &KeyReceipt,
    ) -> Result<()> {
        let names = self
            .secrets_store(store)?
            .map(|s| s.names)
            .unwrap_or_default();
        let vs = self.store_versions(store)?;
        // the version before this write: the newest kept one, if this write is the only change since (else unseen keys)
        let latest = vs.first();
        let mut keys: VerKeys = names
            .iter()
            .map(|n| {
                (
                    n.clone(),
                    latest.and_then(|l| l.keys.get(n).cloned().flatten()),
                )
            })
            .collect();
        let mut cause = VerCause {
            kind: "write".into(),
            key: key.into(),
            writer: strip_sig(rc.writer.as_deref()),
            ..Default::default()
        };
        if rc.deleted {
            keys.remove(key);
            cause.kind = "delete".into();
        } else {
            keys.insert(
                key.into(),
                entry.map(|mut e| {
                    e.receipt = Some(receipt.clone());
                    e
                }),
            );
        }
        self.add_version(store, &rc.version, &cause, &keys)?;
        Ok(())
    }

    // ---- the list, a restore's plan and the restore itself -----------------------------------------------------

    /// the router's list of a store's versions (StoreVersionsDoc's shape, unsigned: each key's receipt is secrets')
    pub fn kernel_store_versions(&self, store: &str, nonce: &str) -> Result<Value> {
        let s = self
            .secrets_store(store)?
            .ok_or_else(|| core_err(404, format!("no store {store}")))?;
        let rows: Vec<Value> = self
            .store_versions(store)?
            .iter()
            .map(|v| json!({"seq": v.seq, "at": v.at.utc().rfc3339(), "version": v.version, "cause": v.cause, "keys": key_rows(&v.keys)}))
            .collect();
        Ok(
            json!({"kind": "store-versions", "nonce": nonce, "store": store, "current": s.version, "sensitive": s.sensitive, "versions": rows}),
        )
    }

    /// what putting version seq back changes (RestoreBegin's shape, unsigned; "replay": true)
    pub fn kernel_restore_begin(&self, store: &str, seq: i64) -> Result<Value> {
        let s = self
            .secrets_store(store)?
            .ok_or_else(|| core_err(404, format!("no store {store}")))?;
        if is_repo_store(self, store) {
            return Err(Forbidden(format!(
                "store {store} holds a repo's deploy key: a repo's key is made again, not restored"
            ))
            .into());
        }
        let vs = self.store_versions(store)?;
        let to = vs
            .iter()
            .rfind(|v| v.seq == seq)
            .cloned()
            .ok_or_else(|| core_err(404, format!("store {store} keeps no version {seq}")))?;
        let latest = vs.first();
        let cur = current_keys(latest, &s.names, &s.version);
        let (mut put, mut put_names, mut keep, mut cannot) = (vec![], vec![], vec![], vec![]);
        for row in key_rows(&to.keys) {
            let k = row.name.clone();
            let want = to.keys.get(&k).cloned().flatten();
            let present = cur.contains_key(&k);
            let have = cur.get(&k).cloned().flatten();
            match (&want, &have) {
                (None, None) if present => keep.push(k), // never seen written, still there
                (None, _) => cannot.push(k), // its value then is one the router never saw
                (Some(w), Some(h))
                    if present
                        && receipt_of(Some(h)).e == receipt_of(Some(w)).e
                        && receipt_of(Some(h)).data_sha256 == receipt_of(Some(w)).data_sha256 =>
                {
                    keep.push(k)
                }
                _ => {
                    put.push(json!({"key": k, "e": row.e, "dataSha256": row.data_sha256, "backupSha256": row.backup_sha256, "at": row.at,
                        "writer": row.writer, "receipt": row.receipt}));
                    put_names.push(k);
                }
            }
        }
        let remove: Vec<String> = cur
            .keys()
            .filter(|k| !to.keys.contains_key(*k))
            .cloned()
            .collect();
        if put_names.is_empty() && remove.is_empty() {
            return Err(core_err(
                409,
                format!(
                    "store {store} already is version {seq} (as far as the router saw it written)"
                ),
            ));
        }
        let from = latest.map_or(0, |l| l.seq);
        let id = crate::util::rand_id();
        {
            let mut p = RESTORE_PENDING.lock().unwrap_or_else(|e| e.into_inner());
            let now = Instant::now();
            p.retain(|_, x| now <= x.expires);
            p.insert(
                id.clone(),
                RestorePlan {
                    store: store.into(),
                    to: to.clone(),
                    current: s.version.clone(),
                    put: put_names,
                    remove: remove.clone(),
                    expires: now + RESTORE_PENDING_TTL,
                },
            );
        }
        Ok(
            json!({"kind": "store-restore-begin", "pending": id, "store": store, "sensitive": s.sensitive, "replay": true,
            "from": {"seq": from, "version": s.version},
            "to": {"seq": to.seq, "version": to.version, "at": to.at.utc().rfc3339()},
            "put": put, "remove": remove, "keep": keep, "cannot": cannot, "t": ""}),
        )
    }

    /// the plan applied — each backup back into the bucket, then each entry replayed (or deleted) in secrets, if the
    /// store is still exactly as the plan saw it; one new version
    pub fn kernel_restore_finish(&self, pending: &str) -> Result<Value> {
        let p = RESTORE_PENDING
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(pending);
        let p = p
            .filter(|p| Instant::now() <= p.expires)
            .ok_or_else(|| core_err(404, "no such pending restore"))?;
        let s = match self.secrets_store(&p.store)? {
            Some(s) if s.version == p.current => s,
            _ => {
                return Err(core_err(
                    409,
                    format!(
                        "store {} changed since this restore was asked for: review it again",
                        p.store
                    ),
                ));
            }
        };
        let b = crate::backups::backup_bucket_from_env().ok_or_else(|| {
            anyhow!("the router has no backup credential (BACKUP_READ_ACCESS_KEY): nothing is restored without its backups")
        })?;
        let vs = self.store_versions(&p.store)?;
        let mut keys = current_keys(vs.first(), &s.names, &s.version);
        let sc = self.store_core();
        // the backups first: no key changes in secrets before its backup is in the bucket (each key put back gets the
        // very backup object written with it, which the app's Recover checks as it did then). A key the restore removes
        // gets its delete marker once secrets' receipt of the delete exists (below).
        for k in &p.put {
            if let Some(Some(e)) = p.to.keys.get(k)
                && let Some(bk) = &e.backup
            {
                b.put(&format!("keys/{}/{k}.json", p.store), bk.get().as_bytes())
                    .map_err(|e| {
                        anyhow!("the backups weren't written, so nothing was restored: {e:#}")
                    })?;
            }
        }
        let mut last = s.version.clone();
        for k in &p.put {
            let e = p.to.keys.get(k).cloned().flatten().unwrap_or_default();
            let rc = receipt_of(Some(&e));
            let d = sc
                .call(
                    "/stores/write-key",
                    &json!({"store": p.store, "key": k, "wrapped": e.wrapped, "data": e.data,
                        "backupSha256": rc.backup_sha256, "writer": "replay", "receipt": e.receipt}),
                )
                .map_err(|err| anyhow!("putting {k} back: {err:#}"))?;
            last = d.decode::<KeyReceipt>().unwrap_or_default().version;
            keys.insert(
                k.clone(),
                Some(VerEntry {
                    wrapped: e.wrapped.clone(),
                    data: e.data.clone(),
                    backup_sha256: e.backup_sha256.clone(),
                    receipt: Some(d),
                    backup: e.backup.clone(),
                }),
            );
        }
        let ident = sc
            .raw("GET", "/identity", None)
            .map(|(_, b)| b)
            .unwrap_or_default();
        let mut unmarked = vec![];
        for k in &p.remove {
            let d = sc
                .call(
                    "/stores/write-key",
                    &json!({"store": p.store, "key": k, "delete": true, "writer": "replay"}),
                )
                .map_err(|err| anyhow!("removing {k}: {err:#}"))?;
            last = d.decode::<KeyReceipt>().unwrap_or_default().version;
            keys.remove(k);
            if let Err(e) = put_removal(&b, &p.store, k, &d, &ident) {
                crate::logf!(
                    "store {}: {k} removed, but its delete marker isn't in the bucket: {e:#}",
                    p.store
                );
                unmarked.push(k.clone());
            }
        }
        let cause = VerCause {
            kind: "restore".into(),
            from: p.to.seq,
            ..Default::default()
        };
        let seq = self
            .add_version(&p.store, &last, &cause, &keys)
            .unwrap_or_else(|e| {
                crate::logf!("store {}: the restored version wasn't kept: {e:#}", p.store);
                0
            });
        if !unmarked.is_empty() {
            self.dm(&format!(
                "🔴 Jarvis 4: store {} was restored, but the bucket couldn't take the removal of {}: a Recover from the bucket alone would bring {} back.",
                p.store,
                jarvis_go::fmt::go_sprint(&json!(unmarked)),
                if unmarked.len() == 1 { "it" } else { "them" }
            ));
        }
        crate::logf!(
            "store {}: version {} put back as version {seq} ({} keys back, {} removed)",
            p.store,
            p.to.seq,
            p.put.len(),
            p.remove.len()
        );
        let store = p.store.clone();
        self.drop_requests(
            move |q| q.kind == crate::storerestore::REQUEST_KIND_RESTORE && q.params.store == store,
            crate::outcomes::OUTCOME_APPROVED,
            None,
        );
        let asked = self.refresh_holders(
            &p.store,
            &format!("Store {} was restored to its version {}. Unlock gives these sessions the store as it is now.", p.store, p.to.seq),
        );
        Ok(
            json!({"ok": true, "restored": {"kind": "store-restored", "pending": pending, "store": p.store,
            "from": p.to.seq, "seq": seq, "version": last}, "refreshAsked": asked}),
        )
    }
}
