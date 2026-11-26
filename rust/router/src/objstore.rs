//! The router's blobs in object storage (docs/STATE.md 2.2): the bucket jarvis4-snapshots-de0ch through the credential
//! jarvis4-objects (infra/objects-key.py: it can reach that bucket only), env OBJECTS_ACCESS_KEY / OBJECTS_SECRET_KEY
//! (Secret router-secrets-objects), OBJECTS_ENDPOINT / OBJECTS_REGION / OBJECTS_BUCKET. Keys:
//!
//! ```text
//! uploads/<id>/<name>          a first-prompt attachment (uploads.rs)
//! task-runs/<run>.log|.output  a task run's log and output (tasks.rs)
//! snapshots/…                  the machines' snapshots (snapstore.rs, snapdirect.rs)
//! ```
//!
//! A router outside the cluster with no credential (tests, CI's stand-ins, e2e) keeps them in memory (MemObjects); main
//! refuses to start that way. The bucket is spoken to with SigV4 (path style), as the Go router's minio client did.

use crate::backups::{hmac_sha, s3enc};
use crate::router::{Router, env};
use anyhow::{Result, anyhow};
use jarvis_go::GoTime;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::{Cursor, Read};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// no object under that key
#[derive(Debug)]
pub struct NoObject;

impl std::fmt::Display for NoObject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("no such object")
    }
}

impl std::error::Error for NoObject {}

pub fn is_no_object(e: &anyhow::Error) -> bool {
    e.downcast_ref::<NoObject>().is_some()
}

/// an object's bytes, streamed, and its size (-1: not known)
pub struct ObjReader {
    pub body: Box<dyn Read + Send>,
    pub size: i64,
}

impl Read for ObjReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.body.read(buf)
    }
}

/// how often one read of an object is taken up again after its connection dropped, and the wait before each (times
/// the try)
const RESUMES: u32 = 5;
const RESUME_WAIT: std::time::Duration = std::time::Duration::from_secs(2);

type Opener = Box<dyn FnMut(u64) -> Result<Box<dyn Read + Send>> + Send>;

/// an object's read that a dropped connection doesn't end: a read that fails goes on from the same offset on a new
/// request (router/objstore.go resumingObject: the bucket's IPv4 through WARP resets a long read now and then; on
/// 2026-11-21 that failed four Destroys and a pause until someone tried again; Deyao, 2026-11-22)
pub struct Resuming {
    cur: Box<dyn Read + Send>,
    open: Opener,
    off: u64,
    tries: u32,
    wait: std::time::Duration,
}

impl Resuming {
    pub fn new(cur: Box<dyn Read + Send>, open: Opener) -> Resuming {
        Resuming {
            cur,
            open,
            off: 0,
            tries: 0,
            wait: RESUME_WAIT,
        }
    }
}

impl Read for Resuming {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            match self.cur.read(buf) {
                Ok(n) => {
                    self.off += n as u64;
                    return Ok(n);
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) if self.tries >= RESUMES => return Err(e),
                Err(e) => {
                    self.tries += 1;
                    crate::logf!(
                        "objects: a read broke at byte {} ({e}): going on from there (try {} of {RESUMES})",
                        self.off,
                        self.tries
                    );
                    std::thread::sleep(self.wait * self.tries);
                    match (self.open)(self.off) {
                        Ok(next) => self.cur = next,
                        // the broken reader fails again at once, so the next round tries again
                        Err(oe) => crate::logf!("objects: reopening at byte {}: {oe:#}", self.off),
                    }
                }
            }
        }
    }
}

pub trait ObjStore: Send + Sync {
    /// size -1: unknown (streamed in parts)
    fn put(&self, key: &str, r: &mut dyn Read, size: i64) -> Result<()>;
    /// NoObject when there is none
    fn get(&self, key: &str) -> Result<ObjReader>;
    fn delete(&self, key: &str) -> Result<()>;
    fn delete_prefix(&self, prefix: &str) -> Result<()> {
        for k in self.list(prefix)? {
            self.delete(&k)?;
        }
        Ok(())
    }
    fn list(&self, prefix: &str) -> Result<Vec<String>>;
    /// the store the machines reach themselves (snapdirect.rs), None for the memory stand-in (its machines stream
    /// through the router)
    fn direct(&self) -> Option<&dyn ObjDirect> {
        None
    }
}

/// a multipart upload whose parts the machines put through signed URLs, and signed reads
pub trait ObjDirect: Send + Sync {
    /// → the upload id (earlier unfinished ones of key aborted)
    fn start_upload(&self, key: &str) -> Result<String>;
    fn part_url(&self, key: &str, upload: &str, part: i64, ttl: Duration) -> Result<String>;
    /// etags[i] is part i+1's
    fn finish_upload(&self, key: &str, upload: &str, etags: &[String]) -> Result<()>;
    fn abort_upload(&self, key: &str, upload: &str) -> Result<()>;
    fn get_url(&self, key: &str, ttl: Duration) -> Result<String>;
}

/// the bucket, or None when no credential is set
pub fn objects_from_env() -> Result<Option<Arc<dyn ObjStore>>> {
    let ak = std::env::var("OBJECTS_ACCESS_KEY").unwrap_or_default();
    let sk = std::env::var("OBJECTS_SECRET_KEY").unwrap_or_default();
    if ak.is_empty() || sk.is_empty() {
        return Ok(None);
    }
    let endpoint = env("OBJECTS_ENDPOINT", "https://fsn1.your-objectstorage.com");
    url::Url::parse(&endpoint)?;
    Ok(Some(Arc::new(S3Objects::new(
        &endpoint,
        &env("OBJECTS_REGION", "fsn1"),
        &env("OBJECTS_BUCKET", "jarvis4-snapshots-de0ch"),
        &ak,
        &sk,
    ))))
}

/// an S3 bucket, path style, SigV4
#[derive(Clone)]
pub struct S3Objects {
    endpoint: String,
    host: String,
    region: String,
    bucket: String,
    ak: String,
    sk: String,
    http: reqwest::blocking::Client,
}

const UNSIGNED: &str = "UNSIGNED-PAYLOAD";
/// a streamed object's parts (minio's PartSize was 16 MiB)
const PART_SIZE: usize = 16 << 20;

fn xml_values(body: &[u8], tag: &str) -> Vec<String> {
    use quick_xml::events::Event;
    let mut rd = quick_xml::Reader::from_reader(body);
    let mut buf = vec![];
    let mut out = vec![];
    let mut inside = false;
    let mut text = String::new();
    loop {
        match rd.read_event_into(&mut buf) {
            Ok(Event::Start(e)) if e.local_name().as_ref() == tag.as_bytes() => {
                inside = true;
                text.clear();
            }
            Ok(Event::Text(t)) if inside => {
                text.push_str(&t.unescape().map(|c| c.into_owned()).unwrap_or_default())
            }
            Ok(Event::End(e)) if e.local_name().as_ref() == tag.as_bytes() => {
                inside = false;
                out.push(text.clone());
            }
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
        buf.clear();
    }
    out
}

/// the pairs of two tags inside each `outer` element (a list's Upload: Key and UploadId)
fn xml_pairs(body: &[u8], outer: &str, a: &str, b: &str) -> Vec<(String, String)> {
    use quick_xml::events::Event;
    let mut rd = quick_xml::Reader::from_reader(body);
    let mut buf = vec![];
    let mut out = vec![];
    let (mut in_outer, mut cur) = (false, String::new());
    let (mut va, mut vb) = (String::new(), String::new());
    let mut text = String::new();
    loop {
        match rd.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let n = String::from_utf8_lossy(e.local_name().as_ref()).into_owned();
                if n == outer {
                    in_outer = true;
                    va.clear();
                    vb.clear();
                }
                cur = n;
                text.clear();
            }
            Ok(Event::Text(t)) => {
                text.push_str(&t.unescape().map(|c| c.into_owned()).unwrap_or_default())
            }
            Ok(Event::End(e)) => {
                let n = String::from_utf8_lossy(e.local_name().as_ref()).into_owned();
                if in_outer && n == a && cur == a {
                    va = text.clone();
                } else if in_outer && n == b && cur == b {
                    vb = text.clone();
                } else if n == outer {
                    in_outer = false;
                    out.push((va.clone(), vb.clone()));
                }
                text.clear();
            }
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
        buf.clear();
    }
    out
}

fn amz_now() -> (String, String) {
    let t = GoTime::now()
        .utc()
        .0
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    let day = format!("{:04}{:02}{:02}", t.year(), u8::from(t.month()), t.day());
    let amz = format!("{day}T{:02}{:02}{:02}Z", t.hour(), t.minute(), t.second());
    (day, amz)
}

impl S3Objects {
    pub fn new(endpoint: &str, region: &str, bucket: &str, ak: &str, sk: &str) -> S3Objects {
        let endpoint = endpoint.trim_end_matches('/').to_string();
        let host = url::Url::parse(&endpoint)
            .ok()
            .map(|u| match u.port() {
                Some(p) => format!("{}:{p}", u.host_str().unwrap_or("")),
                None => u.host_str().unwrap_or("").to_string(),
            })
            .unwrap_or_default();
        S3Objects {
            endpoint,
            host,
            region: region.into(),
            bucket: bucket.into(),
            ak: ak.into(),
            sk: sk.into(),
            http: reqwest::blocking::Client::builder()
                .timeout(None)
                .connect_timeout(Duration::from_secs(30))
                .build()
                .unwrap_or_default(),
        }
    }

    fn path(&self, key: &str) -> String {
        let mut p = format!("/{}", s3enc(&self.bucket, false));
        if !key.is_empty() {
            p.push('/');
            p.push_str(&s3enc(key, true));
        }
        p
    }

    fn query(q: &[(String, String)]) -> String {
        let mut q: Vec<(String, String)> = q
            .iter()
            .map(|(k, v)| (s3enc(k, false), s3enc(v, false)))
            .collect();
        q.sort();
        q.iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("&")
    }

    fn signing_key(&self, day: &str) -> Vec<u8> {
        let mut k = hmac_sha(format!("AWS4{}", self.sk).as_bytes(), day);
        for p in [self.region.as_str(), "s3", "aws4_request"] {
            k = hmac_sha(&k, p);
        }
        k
    }

    /// a header-signed request → (the URL, its headers)
    fn sign(
        &self,
        method: &str,
        key: &str,
        q: &[(String, String)],
        payload: &str,
    ) -> (String, Vec<(String, String)>) {
        let (day, amz) = amz_now();
        let path = self.path(key);
        let qs = S3Objects::query(q);
        let signed = "host;x-amz-content-sha256;x-amz-date";
        let canonical = format!(
            "{method}\n{path}\n{qs}\nhost:{}\nx-amz-content-sha256:{payload}\nx-amz-date:{amz}\n\n{signed}\n{payload}",
            self.host
        );
        let scope = format!("{day}/{}/s3/aws4_request", self.region);
        let to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz}\n{scope}\n{}",
            hex::encode(Sha256::digest(canonical.as_bytes()))
        );
        let sig = hex::encode(hmac_sha(&self.signing_key(&day), &to_sign));
        let auth = format!(
            "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed}, Signature={sig}",
            self.ak
        );
        let url = if qs.is_empty() {
            format!("{}{path}", self.endpoint)
        } else {
            format!("{}{path}?{qs}", self.endpoint)
        };
        (
            url,
            vec![
                ("Authorization".into(), auth),
                ("x-amz-content-sha256".into(), payload.into()),
                ("x-amz-date".into(), amz),
            ],
        )
    }

    /// a query-signed URL anyone holding it may use until ttl passes
    fn presign(
        &self,
        method: &str,
        key: &str,
        extra: &[(String, String)],
        ttl: Duration,
    ) -> String {
        let (day, amz) = amz_now();
        let scope = format!("{day}/{}/s3/aws4_request", self.region);
        let mut q: Vec<(String, String)> = extra.to_vec();
        q.push(("X-Amz-Algorithm".into(), "AWS4-HMAC-SHA256".into()));
        q.push(("X-Amz-Credential".into(), format!("{}/{scope}", self.ak)));
        q.push(("X-Amz-Date".into(), amz.clone()));
        q.push(("X-Amz-Expires".into(), ttl.as_secs().to_string()));
        q.push(("X-Amz-SignedHeaders".into(), "host".into()));
        let path = self.path(key);
        let qs = S3Objects::query(&q);
        let canonical = format!(
            "{method}\n{path}\n{qs}\nhost:{}\n\nhost\n{UNSIGNED}",
            self.host
        );
        let to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz}\n{scope}\n{}",
            hex::encode(Sha256::digest(canonical.as_bytes()))
        );
        let sig = hex::encode(hmac_sha(&self.signing_key(&day), &to_sign));
        format!("{}{path}?{qs}&X-Amz-Signature={sig}", self.endpoint)
    }

    fn send(
        &self,
        method: &str,
        key: &str,
        q: &[(String, String)],
        body: Option<reqwest::blocking::Body>,
        payload: &str,
    ) -> Result<reqwest::blocking::Response> {
        let (u, hs) = self.sign(method, key, q, payload);
        let mut rb = self
            .http
            .request(reqwest::Method::from_bytes(method.as_bytes())?, u);
        for (k, v) in hs {
            rb = rb.header(k, v);
        }
        if let Some(b) = body {
            rb = rb.body(b);
        }
        Ok(rb.send()?)
    }

    /// the object from byte `off` on (a Range request after the first byte)
    fn get_from(&self, key: &str, off: u64) -> Result<reqwest::blocking::Response> {
        let (u, hs) = self.sign("GET", key, &[], UNSIGNED);
        let mut rb = self.http.get(u);
        for (k, v) in hs {
            rb = rb.header(k, v);
        }
        if off > 0 {
            rb = rb.header("Range", format!("bytes={off}-"));
        }
        let resp = rb.send()?;
        let st = resp.status().as_u16();
        if !(200..300).contains(&st) {
            S3Objects::ok(resp, "get")?;
            return Err(anyhow!("get: HTTP {st}"));
        }
        Ok(resp)
    }

    fn ok(resp: reqwest::blocking::Response, what: &str) -> Result<Vec<u8>> {
        let st = resp.status().as_u16();
        let b = crate::util::read_limited(resp, 16 << 20).unwrap_or_default();
        if !(200..300).contains(&st) {
            let code = xml_values(&b, "Code")
                .into_iter()
                .next()
                .unwrap_or_default();
            if code == "NoSuchKey" || (st == 404 && code.is_empty()) {
                return Err(NoObject.into());
            }
            let msg = xml_values(&b, "Message")
                .into_iter()
                .next()
                .unwrap_or_default();
            return Err(anyhow!("{what}: HTTP {st} {code} {msg}"));
        }
        Ok(b)
    }

    fn put_part(&self, key: &str, upload: &str, n: i64, b: Vec<u8>) -> Result<String> {
        let payload = hex::encode(Sha256::digest(&b));
        let resp = self.send(
            "PUT",
            key,
            &[
                ("partNumber".into(), n.to_string()),
                ("uploadId".into(), upload.into()),
            ],
            Some(reqwest::blocking::Body::from(b)),
            &payload,
        )?;
        let etag = resp
            .headers()
            .get("ETag")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        S3Objects::ok(resp, "upload part")?;
        Ok(etag)
    }

    fn create_upload(&self, key: &str) -> Result<String> {
        let resp = self.send(
            "POST",
            key,
            &[("uploads".into(), String::new())],
            None,
            UNSIGNED,
        )?;
        let b = S3Objects::ok(resp, "start upload")?;
        xml_values(&b, "UploadId")
            .into_iter()
            .next()
            .filter(|u| !u.is_empty())
            .ok_or_else(|| anyhow!("start upload: no upload id"))
    }
}

/// read until buf is full or the reader ends → how much was read
fn fill(r: &mut dyn Read, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..])? {
            0 => break,
            k => n += k,
        }
    }
    Ok(n)
}

impl ObjStore for S3Objects {
    fn put(&self, key: &str, r: &mut dyn Read, size: i64) -> Result<()> {
        if size >= 0 && (size as usize) <= PART_SIZE {
            let mut b = Vec::with_capacity(size as usize);
            r.read_to_end(&mut b)?;
            let payload = hex::encode(Sha256::digest(&b));
            let resp = self.send(
                "PUT",
                key,
                &[],
                Some(reqwest::blocking::Body::from(b)),
                &payload,
            )?;
            return S3Objects::ok(resp, "put").map(|_| ());
        }
        // streamed: the first part tells whether it is one object or many
        let mut first = vec![0u8; PART_SIZE];
        let n = fill(r, &mut first)?;
        first.truncate(n);
        if n < PART_SIZE {
            let payload = hex::encode(Sha256::digest(&first));
            let resp = self.send(
                "PUT",
                key,
                &[],
                Some(reqwest::blocking::Body::from(first)),
                &payload,
            )?;
            return S3Objects::ok(resp, "put").map(|_| ());
        }
        let upload = self.create_upload(key)?;
        let res = (|| -> Result<()> {
            let mut etags = vec![self.put_part(key, &upload, 1, first)?];
            loop {
                let mut b = vec![0u8; PART_SIZE];
                let n = fill(r, &mut b)?;
                if n == 0 {
                    break;
                }
                b.truncate(n);
                etags.push(self.put_part(key, &upload, etags.len() as i64 + 1, b)?);
                if n < PART_SIZE {
                    break;
                }
            }
            self.finish_upload(key, &upload, &etags)
        })();
        if res.is_err() {
            let _ = self.abort_upload(key, &upload);
        }
        res
    }

    fn get(&self, key: &str) -> Result<ObjReader> {
        let resp = self.get_from(key, 0)?;
        let size = resp.content_length().map_or(-1, |n| n as i64);
        let (store, key) = (self.clone(), key.to_string());
        Ok(ObjReader {
            body: Box::new(Resuming::new(
                Box::new(resp),
                Box::new(move |off| {
                    store
                        .get_from(&key, off)
                        .map(|r| Box::new(r) as Box<dyn Read + Send>)
                }),
            )),
            size,
        })
    }

    fn delete(&self, key: &str) -> Result<()> {
        let resp = self.send("DELETE", key, &[], None, UNSIGNED)?;
        match S3Objects::ok(resp, "delete") {
            Err(e) if is_no_object(&e) => Ok(()),
            other => other.map(|_| ()),
        }
    }

    fn list(&self, prefix: &str) -> Result<Vec<String>> {
        let mut out = vec![];
        let mut token = String::new();
        loop {
            let mut q = vec![
                ("list-type".to_string(), "2".to_string()),
                ("prefix".to_string(), prefix.to_string()),
            ];
            if !token.is_empty() {
                q.push(("continuation-token".into(), token.clone()));
            }
            let resp = self.send("GET", "", &q, None, UNSIGNED)?;
            let b = S3Objects::ok(resp, "list")?;
            out.extend(
                xml_pairs(&b, "Contents", "Key", "Size")
                    .into_iter()
                    .map(|(k, _)| k),
            );
            let truncated = xml_values(&b, "IsTruncated")
                .first()
                .is_some_and(|t| t == "true");
            token = xml_values(&b, "NextContinuationToken")
                .into_iter()
                .next()
                .unwrap_or_default();
            if !truncated || token.is_empty() {
                break;
            }
        }
        Ok(out)
    }

    fn direct(&self) -> Option<&dyn ObjDirect> {
        Some(self)
    }
}

impl ObjDirect for S3Objects {
    fn start_upload(&self, key: &str) -> Result<String> {
        // a machine that died mid-upload left its parts (stored, and billed): its successor's start ends them
        if let Ok(resp) = self.send(
            "GET",
            "",
            &[
                ("uploads".into(), String::new()),
                ("prefix".into(), key.into()),
                ("max-uploads".into(), "100".into()),
            ],
            None,
            UNSIGNED,
        ) && let Ok(b) = S3Objects::ok(resp, "list uploads")
        {
            for (k, id) in xml_pairs(&b, "Upload", "Key", "UploadId") {
                if k == key {
                    let _ = self.abort_upload(key, &id);
                }
            }
        }
        self.create_upload(key)
    }

    fn part_url(&self, key: &str, upload: &str, part: i64, ttl: Duration) -> Result<String> {
        Ok(self.presign(
            "PUT",
            key,
            &[
                ("partNumber".into(), part.to_string()),
                ("uploadId".into(), upload.into()),
            ],
            ttl,
        ))
    }

    fn finish_upload(&self, key: &str, upload: &str, etags: &[String]) -> Result<()> {
        let mut x = String::from("<CompleteMultipartUpload>");
        for (i, e) in etags.iter().enumerate() {
            let e = e
                .replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;")
                .replace('"', "&quot;");
            x += &format!(
                "<Part><PartNumber>{}</PartNumber><ETag>{e}</ETag></Part>",
                i + 1
            );
        }
        x += "</CompleteMultipartUpload>";
        let payload = hex::encode(Sha256::digest(x.as_bytes()));
        let resp = self.send(
            "POST",
            key,
            &[("uploadId".into(), upload.into())],
            Some(reqwest::blocking::Body::from(x)),
            &payload,
        )?;
        let b = S3Objects::ok(resp, "finish upload")?;
        // S3 can answer 200 with an error inside
        if let Some(code) = xml_values(&b, "Code").first() {
            return Err(anyhow!("finish upload: {code}"));
        }
        Ok(())
    }

    fn abort_upload(&self, key: &str, upload: &str) -> Result<()> {
        let resp = self.send(
            "DELETE",
            key,
            &[("uploadId".into(), upload.into())],
            None,
            UNSIGNED,
        )?;
        S3Objects::ok(resp, "abort upload").map(|_| ())
    }

    fn get_url(&self, key: &str, ttl: Duration) -> Result<String> {
        Ok(self.presign("GET", key, &[], ttl))
    }
}

/// objects in memory (a router with no bucket: tests, CI's stand-ins)
#[derive(Default)]
pub struct MemObjects {
    m: Mutex<BTreeMap<String, Vec<u8>>>,
}

impl ObjStore for MemObjects {
    fn put(&self, key: &str, r: &mut dyn Read, _: i64) -> Result<()> {
        let mut b = vec![];
        r.read_to_end(&mut b)?;
        self.m
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key.into(), b);
        Ok(())
    }

    fn get(&self, key: &str) -> Result<ObjReader> {
        let b = self
            .m
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(key)
            .cloned()
            .ok_or(NoObject)?;
        let size = b.len() as i64;
        Ok(ObjReader {
            body: Box::new(Cursor::new(b)),
            size,
        })
    }

    fn delete(&self, key: &str) -> Result<()> {
        self.m.lock().unwrap_or_else(|e| e.into_inner()).remove(key);
        Ok(())
    }

    fn list(&self, prefix: &str) -> Result<Vec<String>> {
        Ok(self
            .m
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .keys()
            .filter(|k| k.starts_with(prefix))
            .cloned()
            .collect())
    }
}

impl Router {
    /// small objects whole
    pub fn obj_put_bytes(&self, key: &str, b: &[u8]) -> Result<()> {
        self.objects.put(key, &mut Cursor::new(b), b.len() as i64)
    }

    pub fn obj_get_bytes(&self, key: &str) -> Result<Vec<u8>> {
        let mut rd = self.objects.get(key)?;
        let mut b = vec![];
        rd.read_to_end(&mut b)?;
        Ok(b)
    }

    /// an object's sha256 (hex) and size, read through
    pub fn obj_sha256(&self, key: &str) -> Result<(String, i64)> {
        let mut rd = self.objects.get(key)?;
        let mut h = Sha256::new();
        let n = std::io::copy(&mut rd, &mut h)?;
        Ok((hex::encode(h.finalize()), n as i64))
    }

    /// a small object written, read back and deleted (the credential and the bucket work)
    pub fn probe_objects(&self, in_memory: bool) -> Result<()> {
        let key = format!("probe/{}", crate::util::rand_id());
        self.obj_put_bytes(&key, b"ok")?;
        let b = self.obj_get_bytes(&key)?;
        if b != b"ok" {
            return Err(anyhow!(
                "read back: {} <nil>",
                jarvis_go::fmt::go_quote(&String::from_utf8_lossy(&b))
            ));
        }
        self.objects.delete(&key)?;
        if in_memory {
            crate::logf!("objects: in memory (ROUTER_THROWAWAY=1: a throwaway router)");
        } else {
            crate::logf!(
                "objects: the bucket {} answers (put, get, delete)",
                env("OBJECTS_BUCKET", "jarvis4-snapshots-de0ch")
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// a body that gives `cut` bytes and then a reset (a cut at its length is the whole body, then its end)
    struct Cut(std::io::Cursor<Vec<u8>>, usize);

    impl Read for Cut {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.0.position() as usize >= self.1 && self.1 < self.0.get_ref().len() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionReset,
                    "connection reset by peer",
                ));
            }
            let room = (self.1 - self.0.position() as usize).min(buf.len());
            self.0.read(&mut buf[..room])
        }
    }

    fn resuming(body: &[u8], cuts: usize) -> Resuming {
        let whole = body.to_vec();
        let mut opens = 0;
        let mut r = Resuming::new(
            Box::new(Cut(std::io::Cursor::new(whole.clone()), whole.len() / 2)),
            Box::new(move |off| {
                opens += 1;
                let rest = whole[off as usize..].to_vec();
                let cut = if opens < cuts {
                    rest.len() / 2
                } else {
                    rest.len()
                };
                Ok(Box::new(Cut(std::io::Cursor::new(rest), cut)) as Box<dyn Read + Send>)
            }),
        );
        r.wait = std::time::Duration::from_millis(1);
        r
    }

    #[test]
    fn an_object_read_cut_off_goes_on_from_where_it_broke() {
        let body: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let mut got = vec![];
        resuming(&body, 3)
            .read_to_end(&mut got)
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(got, body);
    }

    #[test]
    fn an_object_read_that_keeps_breaking_fails_in_the_end() {
        let mut got = vec![];
        assert!(resuming(&[7u8; 4096], 1000).read_to_end(&mut got).is_err());
    }

    #[test]
    fn xml_lists() {
        let b = br#"<ListBucketResult><IsTruncated>true</IsTruncated><Contents><Key>a/1</Key><Size>3</Size></Contents><Contents><Key>a/&amp;2</Key><Size>4</Size></Contents><NextContinuationToken>t1</NextContinuationToken></ListBucketResult>"#;
        assert_eq!(
            xml_pairs(b, "Contents", "Key", "Size"),
            vec![("a/1".into(), "3".into()), ("a/&2".into(), "4".into())]
        );
        assert_eq!(
            xml_values(b, "NextContinuationToken"),
            vec!["t1".to_string()]
        );
    }

    #[test]
    fn memory_store() {
        let m = MemObjects::default();
        m.put("u/1", &mut Cursor::new(b"hi"), 2)
            .unwrap_or_else(|e| panic!("{e:#}"));
        assert_eq!(m.list("u/").unwrap_or_default(), vec!["u/1".to_string()]);
        assert!(m.get("u/2").is_err_and(|e| is_no_object(&e)));
        m.delete_prefix("u/").unwrap_or_else(|e| panic!("{e:#}"));
        assert!(m.list("").unwrap_or_default().is_empty());
    }
}
