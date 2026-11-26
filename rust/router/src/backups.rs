//! The store backups for the app's Recover (docs/DESIGN.md "Recover"). The router holds the backup bucket's credential
//! (BACKUP_READ_ACCESS_KEY / BACKUP_READ_SECRET_KEY: reads of the bucket and new versions of keys/, no delete), writes
//! each key's backup as the key is written (storedocs.rs: keys/<store>/<key>.json, sealed to the master key by the
//! writer and signed by it), and hands the app the locked backups as they are in the bucket. The router can't read,
//! change or forge one; it can only withhold a backup or serve an older version.
//!
//! With BACKUP_WRITE_BUCKET (Jarvis 4: jarvis4-backup-de0ch) the router writes its key backups there, never into the
//! bucket it reads, and serves both: the write bucket's objects over the read bucket's of the same name.
//!
//!   GET /api/backups → {bucket, objects: [{key, body}]}: every object under stores/, keys/ and sensitive/

use crate::http::Registrar;
use crate::router::{Router, env};
use anyhow::{Result, anyhow};
use hmac::{Hmac, Mac};
use jarvis_go::GoTime;
use jarvis_nethttp::write_json;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::time::Duration;

#[derive(Clone)]
pub struct BackupBucket {
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    /// the bucket the router writes ("" = bucket)
    pub write: String,
    pub access_key: String,
    pub secret_key: String,
}

impl Router {
    /// the backup bucket: a test's own, else the env's
    pub fn backup_bucket(&self) -> Option<BackupBucket> {
        self.backup_override
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .or_else(backup_bucket_from_env)
    }
}

pub fn backup_bucket_from_env() -> Option<BackupBucket> {
    let ak = std::env::var("BACKUP_READ_ACCESS_KEY").unwrap_or_default();
    let sk = std::env::var("BACKUP_READ_SECRET_KEY").unwrap_or_default();
    if ak.is_empty() || sk.is_empty() {
        return None;
    }
    Some(BackupBucket {
        endpoint: env("BACKUP_ENDPOINT", "https://fsn1.your-objectstorage.com")
            .trim_end_matches('/')
            .to_string(),
        region: env("BACKUP_REGION", "fsn1"),
        bucket: env("BACKUP_BUCKET", "jarvis2-backup-de0ch"),
        write: std::env::var("BACKUP_WRITE_BUCKET").unwrap_or_default(),
        access_key: ak,
        secret_key: sk,
    })
}

/// AWS's URI encoding (unreserved characters kept; "/" kept in a key path)
pub fn s3enc(s: &str, slash: bool) -> String {
    let mut b = String::new();
    for c in s.bytes() {
        if c.is_ascii_alphanumeric()
            || matches!(c, b'-' | b'.' | b'_' | b'~')
            || (slash && c == b'/')
        {
            b.push(c as char);
        } else {
            b.push_str(&format!("%{c:02X}"));
        }
    }
    b
}

pub fn hmac_sha(key: &[u8], msg: &str) -> Vec<u8> {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).unwrap_or_else(|e| panic!("{e}"));
    m.update(msg.as_bytes());
    m.finalize().into_bytes().to_vec()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct BackupObject {
    pub key: String,
    pub body: String,
}

impl BackupBucket {
    /// a SigV4-signed, path-style GET of /<bucket>/<key>?<query>
    pub fn get(&self, key: &str, query: &BTreeMap<&str, &str>) -> Result<Vec<u8>> {
        self.do_("GET", key, query, b"")
    }

    /// a new version of one object in the bucket the router writes (versioned: every earlier version stays)
    pub fn put(&self, key: &str, body: &[u8]) -> Result<()> {
        self.writer()
            .do_("PUT", key, &BTreeMap::new(), body)
            .map(|_| ())
    }

    /// the bucket the router writes, as a client
    pub fn writer(&self) -> BackupBucket {
        if self.write.is_empty() || self.write == self.bucket {
            return self.clone();
        }
        let mut w = self.clone();
        w.bucket = self.write.clone();
        w.write.clear();
        w
    }

    fn is_writer(&self) -> bool {
        self.write.is_empty() || self.write == self.bucket
    }

    fn do_(
        &self,
        method: &str,
        key: &str,
        query: &BTreeMap<&str, &str>,
        body: &[u8],
    ) -> Result<Vec<u8>> {
        let mut path = format!("/{}", s3enc(&self.bucket, false));
        if !key.is_empty() {
            path.push('/');
            path.push_str(&s3enc(key, true));
        }
        let q = query
            .iter()
            .map(|(k, v)| format!("{}={}", s3enc(k, false), s3enc(v, false)))
            .collect::<Vec<_>>()
            .join("&");
        let host = url::Url::parse(&self.endpoint)
            .ok()
            .map(|u| match u.port() {
                Some(p) => format!("{}:{p}", u.host_str().unwrap_or("")),
                None => u.host_str().unwrap_or("").to_string(),
            })
            .unwrap_or_default();
        let t = GoTime::now()
            .utc()
            .0
            .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
        let day = format!("{:04}{:02}{:02}", t.year(), u8::from(t.month()), t.day());
        let amz = format!("{day}T{:02}{:02}{:02}Z", t.hour(), t.minute(), t.second());
        let payload = hex::encode(Sha256::digest(body));
        let signed = "host;x-amz-content-sha256;x-amz-date";
        let canonical = [
            method,
            &path,
            &q,
            &format!("host:{host}\nx-amz-content-sha256:{payload}\nx-amz-date:{amz}\n"),
            signed,
            &payload,
        ]
        .join("\n");
        let scope = format!("{day}/{}/s3/aws4_request", self.region);
        let to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz}\n{scope}\n{}",
            hex::encode(Sha256::digest(canonical.as_bytes()))
        );
        let mut k = hmac_sha(format!("AWS4{}", self.secret_key).as_bytes(), &day);
        for p in [self.region.as_str(), "s3", "aws4_request"] {
            k = hmac_sha(&k, p);
        }
        let mut u = format!("{}{path}", self.endpoint);
        if !q.is_empty() {
            u.push('?');
            u.push_str(&q);
        }
        let m = reqwest::Method::from_bytes(method.as_bytes())?;
        let resp = reqwest::blocking::Client::new()
            .request(m, &u)
            .timeout(Duration::from_secs(60))
            .header("x-amz-content-sha256", &payload)
            .header("x-amz-date", &amz)
            .header(
                "Authorization",
                format!(
                    "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed}, Signature={}",
                    self.access_key,
                    hex::encode(hmac_sha(&k, &to_sign))
                ),
            )
            .body(body.to_vec())
            .send()?;
        let status = resp.status().as_u16();
        let out = crate::util::read_limited(resp, 16 << 20)?;
        if status != 200 {
            #[derive(Deserialize, Default)]
            #[serde(default)]
            struct E {
                #[serde(rename = "Code")]
                code: String,
            }
            let mut e: E = quick_xml::de::from_reader(&out[..]).unwrap_or_default();
            if e.code.is_empty() {
                e.code = format!("HTTP {status}");
            }
            return Err(anyhow!(
                "the backup bucket refused {method} {path}: {}",
                e.code
            ));
        }
        Ok(out)
    }

    /// every key under prefix (all pages)
    pub fn list(&self, prefix: &str) -> Result<Vec<String>> {
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct C {
            #[serde(rename = "Key")]
            key: String,
        }
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct L {
            #[serde(rename = "Contents")]
            contents: Vec<C>,
            #[serde(rename = "IsTruncated")]
            is_truncated: bool,
            #[serde(rename = "NextContinuationToken")]
            next: String,
        }
        let mut keys = vec![];
        let mut token = String::new();
        loop {
            let mut q: BTreeMap<&str, &str> = [("list-type", "2"), ("prefix", prefix)]
                .into_iter()
                .collect();
            if !token.is_empty() {
                q.insert("continuation-token", &token);
            }
            let body = self.get("", &q)?;
            let l: L = quick_xml::de::from_reader(&body[..])
                .map_err(|e| anyhow!("the backup bucket's listing isn't readable: {e}"))?;
            keys.extend(l.contents.into_iter().map(|c| c.key));
            if !l.is_truncated || l.next.is_empty() {
                return Ok(keys);
            }
            token = l.next;
        }
    }

    /// the store backups and the sensitivity markers, as they are — the read bucket's, then the write bucket's over
    /// them (an object of the same name replaced)
    pub fn all(&self) -> Result<Vec<BackupObject>> {
        let mut out = self.objects()?;
        if self.is_writer() {
            return Ok(out);
        }
        let mine = self.writer().objects()?;
        let at: BTreeMap<String, usize> = out
            .iter()
            .enumerate()
            .map(|(i, o)| (o.key.clone(), i))
            .collect();
        for o in mine {
            match at.get(&o.key) {
                Some(i) => out[*i] = o,
                None => out.push(o),
            }
        }
        Ok(out)
    }

    /// one bucket's backup objects
    pub fn objects(&self) -> Result<Vec<BackupObject>> {
        let mut out = vec![];
        for prefix in ["stores/", "keys/", "sensitive/"] {
            for k in self.list(prefix)? {
                if !k.ends_with(".json") || crate::linestate::is_line_state_object(&k) {
                    continue; // linestate.rs: the router's own object, no backup
                }
                let body = self.get(&k, &BTreeMap::new())?;
                out.push(BackupObject {
                    key: k,
                    body: String::from_utf8_lossy(&body).into_owned(),
                });
            }
        }
        Ok(out)
    }
}

pub const BACKUP_FALLBACK_FILE: &str = "backups-fallback.json";

/// the app's saved copy of the bucket (ios CoreSetup.exportFormat, tools/decrypt-backup.py)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct BackupExport {
    pub format: String,
    pub version: i64,
    pub bucket: String,
    #[serde(rename = "fetchedAt")]
    pub fetched_at: String,
    pub objects: Vec<BackupObject>,
}

impl BackupExport {
    pub fn check(&self) -> Result<()> {
        if self.format != "jarvis2-backup-export" || self.version != 1 {
            return Err(anyhow!("not a jarvis2-backup-export version 1 file"));
        }
        if self.objects.is_empty() {
            return Err(anyhow!("the export holds no objects"));
        }
        for o in &self.objects {
            let ok = ["stores/", "keys/", "sensitive/"]
                .iter()
                .any(|p| o.key.starts_with(p));
            if !ok || !o.key.ends_with(".json") || o.body.is_empty() {
                return Err(anyhow!("not a backup object: {:?}", o.key));
            }
        }
        Ok(())
    }
}

impl Router {
    /// the kept export, or None
    pub fn backup_fallback(&self) -> Option<BackupExport> {
        let b = self.st.read_doc(BACKUP_FALLBACK_FILE)?;
        jarvis_go::unmarshal::<BackupExport>(&b)
            .ok()
            .filter(|f| f.check().is_ok())
    }
}

pub fn register_backups(reg: &mut Registrar) {
    reg.app("GET /api/backups", |r, w, _| {
        let Some(b) = r.backup_bucket() else {
            jarvis_nethttp::write_error(w, 503, "the router has no read key for the backups (BACKUP_READ_ACCESS_KEY): the setup session installs it with infra/backup-read-key.py install (RUNBOOK, the router's secrets)");
            return;
        };
        match b.all() {
            Ok(objs) => write_json(w, 200, &json!({"bucket": b.bucket, "objects": objs})),
            Err(e) => {
                if let Some(f) = r.backup_fallback() {
                    crate::logf!("GET /api/backups: the bucket failed ({e:#}): serving the fallback export of {}", f.fetched_at);
                    write_json(w, 200, &json!({"bucket": f.bucket, "objects": f.objects,
                        "fallback": {"fetchedAt": f.fetched_at, "reason": format!("{e:#}")}}));
                    return;
                }
                crate::logf!("GET /api/backups: {e:#}");
                jarvis_nethttp::write_error(w, 502, &format!("{e:#}"));
            }
        }
    });
    // A fallback for when the bucket can't be read (2026-10-16: Hetzner's fsn1 Object Storage outage blocked a
    // Recover): an export the app saved earlier, served by GET /api/backups only while the bucket fails. It adds no
    // trust: the app checks every object's signature as it does for the bucket's.
    reg.app("POST /api/backups/fallback", |r, w, req| {
        let b = req.read_body(16 << 20);
        let mut f: BackupExport = match jarvis_go::unmarshal(&b) {
            Ok(f) => f,
            Err(e) => {
                jarvis_nethttp::write_error(w, 400, &format!("not an export: {e}"));
                return;
            }
        };
        if let Err(e) = f.check() {
            jarvis_nethttp::write_error(w, 400, &format!("{e:#}"));
            return;
        }
        // an export over an API call's body limit comes in parts: a part of the same export adds its objects to the
        // kept ones (a key sent again replaces its object)
        if let Some(mut old) = r.backup_fallback()
            && old.bucket == f.bucket
            && old.fetched_at == f.fetched_at
        {
            let by: BTreeMap<String, usize> = old
                .objects
                .iter()
                .enumerate()
                .map(|(i, o)| (o.key.clone(), i))
                .collect();
            for o in f.objects {
                match by.get(&o.key) {
                    Some(i) => old.objects[*i] = o,
                    None => old.objects.push(o),
                }
            }
            f.objects = old.objects;
        }
        if let Err(e) =
            r.st.write_doc(BACKUP_FALLBACK_FILE, jarvis_go::marshal(&f).as_bytes())
        {
            jarvis_nethttp::write_error(w, 500, &format!("{e:#}"));
            return;
        }
        crate::logf!(
            "backups: a fallback export of {} is kept ({} objects)",
            f.fetched_at,
            f.objects.len()
        );
        write_json(
            w,
            200,
            &json!({"ok": true, "fetchedAt": f.fetched_at, "objects": f.objects.len()}),
        );
    });
    reg.app("DELETE /api/backups/fallback", |r, w, _| {
        r.st.delete_doc(BACKUP_FALLBACK_FILE);
        write_json(w, 200, &json!({"ok": true}));
    });
}
