//! Content stores (Jarvis 1's lib/content.js, PARITY "Stores, repos, content"): named folders of files on the Storage
//! Box, claude-records/.content/<store>/ — the same folders Jarvis 1 used, read and written in place. They are the
//! file counterpart of the key stores, and hold no secret: a store is data a session reads and writes, not a
//! credential.
//!
//!   - Deyao manages them in the app's Content tab: list, create, delete a store; list, upload, download, delete a
//!     file (/api/content…, his Access login).
//!   - A session gets the stores picked in New session. The pick is a signed setting (SessionConfig.Content: the phone
//!     approves it with the line, every machine of the line gets the same ones). The machine's local API proxy turns
//!     Jarvis 1's content-sync calls (`$JARVIS_URL/api/sessions/<id>/content…`) into machine-signed /m/api calls, and
//!     the router answers them with its own Storage Box credentials, only for the stores the calling machine's cert
//!     names. The machine never holds Storage Box credentials.
//!   - Each file a machine downloads carries the core's attestation (input "content", origin "router", its sha256):
//!     the machine's proxy refuses a file without it, so every content file a machine took is in the input log. The
//!     bytes are the router's word (the Storage Box is the router's storage): a content store is data the session
//!     reads, as it reads the web, kept in ~/content (never the cwd, never run). DECISIONS 132-133.
//!
//! The box is Apache mod_dav: PROPFIND with Depth infinity is refused, so a store is walked one level at a time.

use crate::http::Registrar;
use crate::nethttp::{Req, W, write_json};
use crate::router::Router;
use crate::storagebox::{DavEntry, StorageBox};
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

pub const CONTENT_ROOT: &str = "claude-records/.content";
/// per file (Jarvis 1's limit: the cf-tunnel caps a request body at 25 MB)
pub const CONTENT_MAX_FILE: usize = 25 << 20;
const CONTENT_CACHE_OK: Duration = Duration::from_secs(60);

static CONTENT_NAME_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"^[a-z0-9]([a-z0-9-]{0,40}[a-z0-9])?$").unwrap_or_else(|_| unreachable!()));

/// a content error with its HTTP status
#[derive(Debug)]
pub struct ContentErr {
    pub status: u16,
    pub msg: String,
}

impl std::fmt::Display for ContentErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.msg)
    }
}

impl std::error::Error for ContentErr {}

fn content_fail(status: u16, msg: String) -> anyhow::Error {
    ContentErr { status, msg }.into()
}

pub fn content_write_err(w: &mut W, err: &anyhow::Error) {
    match err.downcast_ref::<ContentErr>() {
        Some(ce) => write_json(w, ce.status, &json!({"error": ce.msg})),
        None => write_json(w, 502, &json!({"error": format!("{err:#}")})),
    }
}

pub fn content_name(raw: &str) -> Result<String> {
    let n = raw.trim();
    if !CONTENT_NAME_RE.is_match(n) {
        return Err(content_fail(
            400,
            format!(
                "invalid content store name {} (lowercase letters, digits, dashes)",
                jarvis_go::fmt::go_quote(n)
            ),
        ));
    }
    Ok(n.to_string())
}

/// a file inside a store: relative, "/"-separated, no empty / "." / ".." segments, no control characters or
/// backslashes; returned without leading/trailing slashes
pub fn content_path(raw: &str) -> Result<String> {
    let p = raw.trim_matches('/');
    let mut bad = p.is_empty() || p.len() > 1024 || p.contains('\\');
    if p.chars().any(|c| (c as u32) < 0x20 || c as u32 == 0x7f) {
        bad = true;
    }
    if p.split('/').any(|s| s.is_empty() || s == "." || s == ".." || s.len() > 255) {
        bad = true;
    }
    if bad {
        return Err(content_fail(400, format!("invalid file path {}", jarvis_go::fmt::go_quote(p))));
    }
    Ok(p.to_string())
}

/// ?path= or Jarvis 1's x-content-path header
fn content_path_of(req: &Req) -> Result<String> {
    let mut raw = req.query("path");
    if raw.is_empty() {
        raw = req.header("X-Content-Path");
        if let Ok(u) = percent_encoding::percent_decode_str(&raw).decode_utf8() {
            raw = u.into_owned();
        }
    }
    content_path(&raw)
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ContentFile {
    pub path: String,
    pub size: i64,
    pub modified: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ContentStore {
    pub name: String,
    pub files: usize,
    pub bytes: i64,
}

// ---- stores -------------------------------------------------------------------------------------------------

static CONTENT_CACHE: Mutex<Option<(Instant, Vec<ContentStore>)>> = Mutex::new(None);

pub fn invalidate_content() {
    *CONTENT_CACHE.lock().unwrap_or_else(|e| e.into_inner()) = None;
}

fn dav_status(b: &StorageBox, method: &str, p: &str, hdr: &[(&'static str, &str)]) -> Result<(u16, Vec<u8>)> {
    let h: BTreeMap<&str, String> = hdr.iter().map(|(k, v)| (*k, v.to_string())).collect();
    let resp = b.do_(method, p, None, &h)?;
    let st = resp.status().as_u16();
    let body = if method == "GET" { crate::util::read_limited(resp, CONTENT_MAX_FILE as u64 + 1)? } else { vec![] };
    Ok((st, body))
}

impl Router {
    fn content_box(&self) -> Result<Arc<StorageBox>> {
        self.box_().ok_or_else(|| {
            content_fail(
                503,
                "content stores need the router's Storage Box (STORAGEBOX_HOST/USER/PASSWORD)".into(),
            )
        })
    }

    /// every file of a store, sorted by path; None when the store doesn't exist
    pub fn content_files(&self, name: &str) -> Result<Option<Vec<ContentFile>>> {
        let n = content_name(name)?;
        let b = self.content_box()?;
        let base = format!("{CONTENT_ROOT}/{n}");
        let Some(top) = b.children(&base)? else { return Ok(None) };
        let mut files = vec![];
        fn walk(b: &StorageBox, base: &str, rel: &str, entries: Vec<DavEntry>, depth: u32, files: &mut Vec<ContentFile>) -> Result<()> {
            for e in entries {
                let p = if rel.is_empty() { e.name.clone() } else { format!("{rel}/{}", e.name) };
                if e.dir {
                    if depth > 32 {
                        continue;
                    }
                    let kids = b.children(&format!("{base}/{p}"))?.unwrap_or_default();
                    walk(b, base, &p, kids, depth + 1, files)?;
                    continue;
                }
                files.push(ContentFile { path: p, size: e.size, modified: e.modified });
            }
            Ok(())
        }
        walk(&b, &base, "", top, 0, &mut files)?;
        files.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(Some(files))
    }

    /// every store with its file count and size (cached a minute; any write through here drops it)
    pub fn content_stores(&self, fresh: bool) -> Result<Vec<ContentStore>> {
        if !fresh
            && let Some((at, s)) = CONTENT_CACHE.lock().unwrap_or_else(|e| e.into_inner()).as_ref()
            && at.elapsed() < CONTENT_CACHE_OK
        {
            return Ok(s.clone());
        }
        let b = self.content_box()?;
        let top = b.children(CONTENT_ROOT)?.unwrap_or_default();
        let mut names: Vec<String> = top
            .into_iter()
            .filter(|e| e.dir && CONTENT_NAME_RE.is_match(&e.name))
            .map(|e| e.name)
            .collect();
        names.sort();
        let results: Vec<Result<ContentStore>> = std::thread::scope(|sc| {
            let hs: Vec<_> = names
                .iter()
                .map(|n| {
                    sc.spawn(move || {
                        let files = self.content_files(n)?.unwrap_or_default();
                        Ok(ContentStore {
                            name: n.clone(),
                            files: files.len(),
                            bytes: files.iter().map(|f| f.size).sum(),
                        })
                    })
                })
                .collect();
            hs.into_iter()
                .map(|h| h.join().unwrap_or_else(|_| Err(anyhow!("a content listing panicked"))))
                .collect()
        });
        let out = results.into_iter().collect::<Result<Vec<_>>>()?;
        *CONTENT_CACHE.lock().unwrap_or_else(|e| e.into_inner()) = Some((Instant::now(), out.clone()));
        Ok(out)
    }

    /// whether the store's folder is there
    pub fn content_exists(&self, name: &str) -> Result<bool> {
        let n = content_name(name)?;
        let b = self.content_box()?;
        match dav_status(&b, "PROPFIND", &format!("{CONTENT_ROOT}/{n}/"), &[("Depth", "0")])?.0 {
            404 => Ok(false),
            st if st == 207 || st < 300 => Ok(true),
            st => Err(anyhow!("PROPFIND {n}: HTTP {st}")),
        }
    }

    /// the names cleaned, unique, sorted, each an existing store (None for none)
    pub fn check_content_stores(&self, input: &[String]) -> Result<Option<Vec<String>>> {
        let mut set = BTreeSet::new();
        for raw in input {
            set.insert(content_name(raw)?);
        }
        for n in &set {
            if !self.content_exists(n)? {
                return Err(content_fail(400, format!("no content store {}", jarvis_go::fmt::go_quote(n))));
            }
        }
        Ok((!set.is_empty()).then(|| set.into_iter().collect()))
    }

    pub fn create_content_store(&self, name: &str) -> Result<()> {
        let n = content_name(name)?;
        if self.content_exists(&n)? {
            return Ok(()); // already there: what was asked for holds
        }
        let b = self.content_box()?;
        let r = b.mkcols(&format!("{CONTENT_ROOT}/{n}"));
        invalidate_content();
        r
    }

    pub fn delete_content_store(&self, name: &str) -> Result<()> {
        let n = content_name(name)?;
        if !self.content_exists(&n)? {
            return Ok(()); // already gone: what was asked for holds
        }
        let b = self.content_box()?;
        let r = b.delete(&format!("{CONTENT_ROOT}/{n}/"));
        invalidate_content();
        r
    }

    /// a file's bytes (at most CONTENT_MAX_FILE; the box gzips text, so identity is asked for)
    pub fn read_content_file(&self, name: &str, p: &str) -> Result<Vec<u8>> {
        let b = self.content_box()?;
        let (st, data) = dav_status(
            &b,
            "GET",
            &format!("{CONTENT_ROOT}/{name}/{p}"),
            &[("Accept-Encoding", "identity")],
        )?;
        if st == 404 {
            return Err(content_fail(404, "no such file".into()));
        }
        if st >= 300 {
            return Err(anyhow!("GET {name}/{p}: HTTP {st}"));
        }
        if data.len() > CONTENT_MAX_FILE {
            return Err(content_fail(413, format!("file over {} MB", CONTENT_MAX_FILE >> 20)));
        }
        Ok(data)
    }

    /// the file into an existing store, its parent folders made
    pub fn write_content_file(&self, name: &str, p: &str, data: &[u8]) -> Result<ContentFile> {
        if data.len() > CONTENT_MAX_FILE {
            return Err(content_fail(413, format!("file too large (max {} MB)", CONTENT_MAX_FILE >> 20)));
        }
        if !self.content_exists(name)? {
            return Err(content_fail(404, format!("no content store {}", jarvis_go::fmt::go_quote(name))));
        }
        let b = self.content_box()?;
        if let Some(i) = p.rfind('/').filter(|i| *i > 0) {
            b.mkcols(&format!("{CONTENT_ROOT}/{name}/{}", &p[..i]))?;
        }
        let r = b.put_bytes(&format!("{CONTENT_ROOT}/{name}/{p}"), data);
        invalidate_content();
        r?;
        Ok(ContentFile { path: p.to_string(), size: data.len() as i64, modified: String::new() })
    }

    /// the file, then any folders it leaves empty (up to the store's root)
    pub fn delete_content_file(&self, name: &str, p: &str) -> Result<()> {
        let b = self.content_box()?;
        let (st, _) = dav_status(&b, "DELETE", &format!("{CONTENT_ROOT}/{name}/{p}"), &[])?;
        invalidate_content();
        if st == 404 {
            return Ok(()); // already gone: what was asked for holds
        }
        if st >= 300 {
            return Err(anyhow!("DELETE {name}/{p}: HTTP {st}"));
        }
        let mut segs: Vec<&str> = p.split('/').collect();
        segs.pop();
        while !segs.is_empty() {
            let dir = format!("{CONTENT_ROOT}/{name}/{}", segs.join("/"));
            match b.children(&dir) {
                Ok(Some(k)) if k.is_empty() => {
                    let _ = b.delete(&format!("{dir}/"));
                }
                _ => break,
            }
            segs.pop();
        }
        Ok(())
    }

    // ---- a session's stores -------------------------------------------------------------------------------

    /// the content stores the machine's current cert names (its signed config); a machine with no cert, or a cert
    /// naming none, has none
    pub fn cert_content(&self, machine: &str) -> Vec<String> {
        let cert = self.st.do_(|d| d.certs.get(machine).cloned());
        let (config, _) = crate::vouch::cert_options(cert.as_ref());
        if config.is_empty() {
            return vec![];
        }
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct C {
            content: Vec<String>,
        }
        serde_json::from_str::<C>(&config).map(|c| c.content).unwrap_or_default()
    }

    pub fn machine_content_store(&self, machine: &str, name: &str) -> Result<String> {
        if self.cert_content(machine).iter().any(|n| n == name) {
            return Ok(name.to_string());
        }
        Err(content_fail(
            403,
            format!(
                "content store {} is not one this session was started with",
                jarvis_go::fmt::go_quote(name)
            ),
        ))
    }

    /// the core's input-log entry for a content file a machine is about to take
    pub fn attest_content(&self, machine: &str, data: &[u8]) -> Result<crate::core::Doc> {
        self.attest_input(machine, "content", "router", &sha256_hex(data))
    }
}

pub fn sha256_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

fn file_op(w: &mut W, req: &Req) -> Option<(String, String)> {
    match content_name(&req.path_value("name")).and_then(|n| Ok((n, content_path_of(req)?))) {
        Ok(x) => Some(x),
        Err(e) => {
            content_write_err(w, &e);
            None
        }
    }
}

fn m_file(r: &Router, w: &mut W, req: &Req, machine: &str) -> Option<(String, String)> {
    match r
        .machine_content_store(machine, &req.path_value("name"))
        .and_then(|n| Ok((n, content_path_of(req)?)))
    {
        Ok(x) => Some(x),
        Err(e) => {
            content_write_err(w, &e);
            None
        }
    }
}

/// a machine route on its own session's content (the {id} is its session or itself)
fn own(
    reg: &mut Registrar,
    pattern: &str,
    f: impl Fn(&Arc<Router>, &mut W, &mut Req, &str, &[u8]) + Send + Sync + 'static,
) {
    reg.m(pattern, move |r, w, req, machine, body| {
        let sid = match r.machine_session(machine) {
            Err(e) => return write_json(w, 403, &json!({"error": format!("{e:#}")})),
            Ok(s) => s,
        };
        let id = req.path_value("id");
        if id != sid && id != machine {
            return write_json(w, 403, &json!({"error": format!("this machine is session {sid}, not {id}")}));
        }
        f(r, w, req, machine, body)
    });
}

pub fn register_content(reg: &mut Registrar) {
    reg.app("GET /api/content", |r, w, req| match r.content_stores(req.query("fresh") == "1") {
        Err(e) => content_write_err(w, &e),
        Ok(stores) => write_json(w, 200, &json!({"stores": stores})),
    });
    reg.app("POST /api/content", |r, w, req| {
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct In {
            name: String,
        }
        let i: In = crate::http::decode_body(req, 1 << 16);
        if let Err(e) = r.create_content_store(&i.name) {
            return content_write_err(w, &e);
        }
        crate::logf!("[content] store {} made", i.name.trim());
        write_json(w, 200, &json!({"ok": true, "name": i.name.trim()}));
    });
    reg.app("DELETE /api/content/{name}", |r, w, req| {
        if let Err(e) = r.delete_content_store(&req.path_value("name")) {
            return content_write_err(w, &e);
        }
        crate::logf!("[content] store {} deleted", req.path_value("name"));
        write_json(w, 200, &json!({"ok": true}));
    });
    reg.app("GET /api/content/{name}/files", |r, w, req| {
        let name = req.path_value("name");
        match r.content_files(&name) {
            Err(e) => content_write_err(w, &e),
            Ok(None) => content_write_err(
                w,
                &content_fail(404, format!("no content store {}", jarvis_go::fmt::go_quote(&name))),
            ),
            Ok(Some(files)) => write_json(w, 200, &json!({"name": name, "files": files})),
        }
    });
    reg.app("GET /api/content/{name}/file", |r, w, req| {
        let Some((n, p)) = file_op(w, req) else { return };
        match r.read_content_file(&n, &p) {
            Err(e) => content_write_err(w, &e),
            Ok(data) => {
                let base = p.rsplit('/').next().unwrap_or_default();
                w.set_header("Content-Type", "application/octet-stream");
                w.set_header(
                    "Content-Disposition",
                    &format!("attachment; filename*=UTF-8''{}", jarvis_go::fmt::path_escape(base)),
                );
                w.set_header("Cache-Control", "no-store");
                w.write(&data);
            }
        }
    });
    reg.app("POST /api/content/{name}/file", |r, w, req| {
        let Some((n, p)) = file_op(w, req) else { return };
        let mut data = vec![];
        let res = (&mut req.body)
            .take(CONTENT_MAX_FILE as u64 + 1)
            .read_to_end(&mut data)
            .map_err(anyhow::Error::from)
            .and_then(|_| r.write_content_file(&n, &p, &data));
        match res {
            Ok(f) => write_json(w, 200, &f),
            Err(e) => content_write_err(w, &e),
        }
    });
    reg.app("DELETE /api/content/{name}/file", |r, w, req| {
        let Some((n, p)) = file_op(w, req) else { return };
        match r.delete_content_file(&n, &p) {
            Err(e) => content_write_err(w, &e),
            Ok(()) => write_json(w, 200, &json!({"ok": true})),
        }
    });

    // ---- the session (through its machine's local proxy: Jarvis 1's content-sync, a task's script) ----------
    own(reg, "GET /m/api/sessions/{id}/content", |r, w, _, machine, _| {
        let mut stores = BTreeMap::new();
        for n in r.cert_content(machine) {
            match r.content_files(&n) {
                Err(e) => return content_write_err(w, &e),
                // a store deleted since the line began: empty
                Ok(files) => {
                    stores.insert(n, files.unwrap_or_default());
                }
            }
        }
        write_json(w, 200, &json!({"ok": true, "stores": stores}));
    });
    own(reg, "GET /m/api/sessions/{id}/content/{name}/file", |r, w, req, machine, _| {
        let Some((n, p)) = m_file(r, w, req, machine) else { return };
        let data = match r.read_content_file(&n, &p) {
            Err(e) => return content_write_err(w, &e),
            Ok(d) => d,
        };
        match r.attest_content(machine, &data) {
            Err(e) => write_json(w, 503, &json!({"error": format!("the core's attestation: {e:#}")})),
            Ok(a) => {
                w.set_header("Content-Type", "application/octet-stream");
                w.set_header("X-Jarvis2-Attest", &jarvis_go::marshal(&a));
                w.write(&data);
            }
        }
    });
    own(reg, "PUT /m/api/sessions/{id}/content/{name}/file", |r, w, req, machine, body| {
        let Some((n, p)) = m_file(r, w, req, machine) else { return };
        match r.write_content_file(&n, &p, body) {
            Err(e) => content_write_err(w, &e),
            Ok(f) => write_json(w, 200, &f),
        }
    });
    own(reg, "DELETE /m/api/sessions/{id}/content/{name}/file", |r, w, req, machine, _| {
        let Some((n, p)) = m_file(r, w, req, machine) else { return };
        match r.delete_content_file(&n, &p) {
            Err(e) => content_write_err(w, &e),
            Ok(()) => write_json(w, 200, &json!({"ok": true})),
        }
    });
}
