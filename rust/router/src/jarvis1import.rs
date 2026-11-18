//! Importing a paused Jarvis 1 session (Deyao, 2026-10-13: "move all paused Jarvis 1 sessions to Jarvis 4, so each
//! continues there as the same conversation with its working tree").
//!
//! Jarvis 1 left each paused session on the Storage Box at claude-records/.paused/<id>/: its transcripts
//! (<uuid>.jsonl), ~/.claude.json (claude.json), ~/workspace and ~/artifacts (workspace.tar.gz, artifacts.tar.gz), an
//! optional harness tarball, the record (session.json: title, model, size, repos, armed wakeups and crons) and
//! manifest.txt, written last (its presence = the snapshot is complete). None of it is signed by anything Jarvis 4
//! trusts, so an import is a NEW line whose cert vouches for exactly those bytes (DESIGN "Inputs to a machine" (a)):
//!
//!  1. prepare: the router streams every file once and hashes it, and writes the import manifest
//!     {kind "jarvis1-import", session, files: [{name, sha256, size}]} onto its volume;
//!  2. import: a new session whose config carries restore = {machine: the Jarvis 1 session id (its first machine's
//!     id), sha256: the manifest's sha256}, waiting for the phone like any new session (the app shows "Restores machine
//!     <id>" and the hash, as for a restore of a destroyed Jarvis 4 session). Deyao's Face ID signs that hash, so it
//!     vouches for every byte the manifest lists;
//!  3. the line's first machine fetches the manifest (/m/restore-snapshot), checks its hash against the cert, then
//!     fetches each file through the router (/m/import-file/<name>, streamed from the Storage Box: the machine holds no
//!     Storage Box credential) and refuses any whose sha256 or size differs (rust/machine/src/jarvis1import.rs).
//!
//! The router's choice of WHICH bytes to hash is its own (as with attachments, decision 78): the phone binds the bytes
//! the router read at prepare time, and the Storage Box (ours, over TLS) is where they came from.

use crate::http::{Registrar, write_err};
use crate::inbox::{ApiCall, Caller, Origin};
use crate::nethttp::{Req, W, write_error, write_json};
use crate::router::{Router, bad};
use crate::storagebox::StorageBox;
use anyhow::{Result, anyhow, bail};
use jarvis_go::GoTime;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

pub const J1_IMPORT_KIND: &str = "jarvis1-import";
pub const J1_PAUSED_ROOT: &str = "claude-records/.paused";
pub const J1_PAUSED_INDEX: &str = "claude-records/.index/paused-sessions.json";
/// the import manifest, on the router's volume
pub const J1_MANIFEST_FILE: &str = "manifest.json";
/// Jarvis 1's session.json as read at prepare (the router's own use: label, model…)
pub const J1_RECORD_FILE: &str = "record.json";
/// the Jarvis 4 session the import became, once it came up
pub const J1_IMPORTED_FILE: &str = "imported.json";

static J1_SESSION_ID_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"^[a-z0-9]{1,40}$").unwrap_or_else(|_| unreachable!()));
/// the files an import takes (rust/machine/src/jarvis1import.rs accepts the same names)
static J1_FILE_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(
        r"^(session\.json|claude\.json|manifest\.txt|workspace\.tar\.gz|artifacts\.tar\.gz|harness\.tar\.gz|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.jsonl)$",
    )
    .unwrap_or_else(|_| unreachable!())
});

/// what the cert's restore hash covers (the manifest's exact bytes)
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct J1ImportFile {
    pub name: String,
    pub sha256: String,
    pub size: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct J1ImportManifest {
    pub kind: String,
    pub v: i64,
    pub session: String,
    pub files: Option<Vec<J1ImportFile>>,
}

/// the parts of Jarvis 1's session.json the router uses to fill in the new session (all of it goes to the phone in
/// the challenge or the approval's options)
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct J1Record {
    pub id: String,
    pub label: String,
    pub title: String,
    pub model: String,
    pub size: String,
    pub harness: String,
    #[serde(rename = "autoPause")]
    pub auto_pause: String,
    #[serde(rename = "oneShot")]
    pub one_shot: bool,
    pub repos: String,
    pub environment: String,
    #[serde(rename = "pausedAt")]
    pub paused_at: String,
    pub metadata: BTreeMap<String, String>,
}

fn j1_path(root: &str, parts: &[&str]) -> String {
    if root.is_empty() { parts.join("/") } else { format!("{root}/{}", parts.join("/")) }
}

/// an import's small files are rows of router_docs, jarvis1-imports/<id>/<file> (statedb.rs)
fn j1_doc(id: &str, file: &str) -> String {
    format!("jarvis1-imports/{id}/{file}")
}

pub fn sha256_bytes(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

// ---- prepare ------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize)]
pub struct J1Prep {
    /// preparing | ready | failed
    pub state: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub file: String,
    #[serde(rename = "bytesDone")]
    pub done: i64,
    #[serde(rename = "bytesTotal")]
    pub total: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub error: String,
    /// the manifest's
    #[serde(skip_serializing_if = "String::is_empty")]
    pub sha256: String,
    pub started: GoTime,
}

static J1_PREPS: LazyLock<Mutex<BTreeMap<String, J1Prep>>> = LazyLock::new(Default::default);

fn preps() -> std::sync::MutexGuard<'static, BTreeMap<String, J1Prep>> {
    J1_PREPS.lock().unwrap_or_else(|e| e.into_inner())
}

/// how long an import waits for the prepare it starts itself (ms; tests shorten it)
pub static J1_PREPARE_WAIT_MS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(10 * 60 * 1000);

/// small files first (the record, the manifest, claude.json, transcripts), then the tarballs
fn j1_order(n: &str) -> i64 {
    match n {
        "session.json" => 0,
        "manifest.txt" => 1,
        "claude.json" => 2,
        _ if n.ends_with(".jsonl") => 3,
        "harness.tar.gz" => 4,
        "artifacts.tar.gz" => 5,
        _ => 6,
    }
}

fn check_id(id: &str) -> Result<()> {
    if !J1_SESSION_ID_RE.is_match(id) {
        return Err(bad(format!("not a Jarvis 1 session id: {}", jarvis_go::fmt::go_quote(id))));
    }
    Ok(())
}

/// what an import asks for
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct J1ImportIn {
    /// Jarvis 4 stores (the harness's come with it)
    pub stores: Vec<String>,
    /// typed into the resumed conversation once it is up ("" = j1_default_prompt)
    pub prompt: String,
    /// "" = Jarvis 1's size (xlarge → large)
    pub size: String,
    pub explanation: String,
    /// its Claude account (claudeaccounts.rs); "" = the default
    pub account: String,
    /// batches.rs: filed in this batch
    #[serde(skip)]
    pub batch: String,
}

/// on NewSession, the import a new line restores
#[derive(Debug, Clone, Default)]
pub struct J1ImportRef {
    /// the Jarvis 1 session id
    pub session: String,
    /// the import manifest's
    pub sha256: String,
    /// the approval's "restore" line
    pub shown: String,
}

/// what the resumed conversation is told first (the phone shows it; Deyao signs it)
pub fn j1_default_prompt(id: &str, stores: &[String]) -> String {
    let today = GoTime::now().utc().rfc3339();
    format!(
        "[Jarvis 4] This conversation was moved from Jarvis 1 to Jarvis 4 on {} (Jarvis 1 session {id}). Its transcript, ~/workspace and ~/artifacts were restored from the Jarvis 1 pause snapshot, and any wakeups or crons it had armed were re-armed on Jarvis 4 (see ~/artifacts/jarvis1-import/rearmed.txt). It now runs on Jarvis 4 with the stores {} (`jarvis stores` lists them; `jarvis-request add-store` asks for another). Jarvis 1 is being frozen, so don't use its API. Nothing to do now: reply with one short line and wait for Deyao.",
        &today[..10],
        stores.join(", ")
    )
}

fn j1_size(s: &str) -> Option<&'static str> {
    match s {
        "small" => Some("small"),
        "medium" | "" => Some("medium"),
        "large" | "xlarge" => Some("large"),
        _ => None,
    }
}

fn first_non_empty(s: &[&str]) -> String {
    s.iter().map(|x| x.trim()).find(|x| !x.is_empty()).unwrap_or("").to_string()
}

/// sha256 and byte count of what is written through it, reporting progress
struct HashCounter<F: FnMut(i64)> {
    h: Sha256,
    n: i64,
    progress: F,
}

impl<F: FnMut(i64)> Write for HashCounter<F> {
    fn write(&mut self, p: &[u8]) -> std::io::Result<usize> {
        self.h.update(p);
        self.n += p.len() as i64;
        (self.progress)(p.len() as i64);
        Ok(p.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Router {
    /// where the paused sessions are — the Storage Box (production), or JARVIS1_PAUSED_URL (the end-to-end test's
    /// stand-in: the same WebDAV calls, no credentials)
    fn j1_source(&self) -> Result<(Arc<StorageBox>, &'static str)> {
        let u = std::env::var("JARVIS1_PAUSED_URL").unwrap_or_default();
        if !u.is_empty() {
            return Ok((Arc::new(StorageBox::new(&u, "", "")), ""));
        }
        Ok((self.box_().ok_or_else(crate::storagebox::no_storage_box)?, J1_PAUSED_ROOT))
    }

    /// starts hashing a paused Jarvis 1 session's files (in the background; j1_status follows it)
    pub fn prepare_jarvis1(self: &Arc<Self>, id: &str) -> Result<J1Prep> {
        check_id(id)?;
        let mut g = preps();
        if let Some(p) = g.get(id).filter(|p| p.state == "preparing") {
            return Ok(p.clone());
        }
        let p = J1Prep { state: "preparing".into(), started: GoTime::now().utc(), ..Default::default() };
        g.insert(id.into(), p.clone());
        let (r, id) = (self.clone(), id.to_string());
        std::thread::spawn(move || {
            let res = r.prepare_jarvis1_run(&id);
            let mut g = preps();
            let Some(p) = g.get_mut(&id) else { return };
            match res {
                Err(e) => {
                    p.state = "failed".into();
                    p.error = format!("{e:#}");
                    crate::logf!("jarvis1 import {id}: prepare failed: {e:#}");
                }
                Ok(sum) => {
                    p.state = "ready".into();
                    p.sha256 = sum.clone();
                    p.file.clear();
                    crate::logf!("jarvis1 import {id}: prepared (manifest sha256 {sum})");
                }
            }
        });
        Ok(p)
    }

    fn prepare_jarvis1_run(&self, id: &str) -> Result<String> {
        let (src, root) = self.j1_source()?;
        let ls = src.list(&j1_path(root, &[id]))?.ok_or_else(|| anyhow!("no paused Jarvis 1 session {id}"))?;
        if !ls.contains_key("manifest.txt") {
            bail!("the snapshot has no manifest.txt (Jarvis 1 writes it last): incomplete, not imported");
        }
        if !ls.contains_key("session.json") {
            bail!("the snapshot has no session.json");
        }
        let mut names: Vec<&String> = ls.keys().filter(|n| J1_FILE_RE.is_match(n)).collect();
        let total: i64 = names.iter().map(|n| ls[*n]).sum();
        names.sort_by(|a, b| j1_order(a).cmp(&j1_order(b)).then(a.cmp(b)));
        let set = |f: &dyn Fn(&mut J1Prep)| {
            if let Some(p) = preps().get_mut(id) {
                f(p);
            }
        };
        set(&|p| p.total = total);
        let mut man = J1ImportManifest { kind: J1_IMPORT_KIND.into(), v: 1, session: id.into(), files: None };
        let mut rec = vec![];
        for n in names {
            set(&|p| p.file = n.clone());
            let (mut body, _) = src.open(&j1_path(root, &[id, n]))?.ok_or_else(|| anyhow!("{n} went missing"))?;
            let mut h = HashCounter {
                h: Sha256::new(),
                n: 0,
                progress: |k| {
                    if let Some(p) = preps().get_mut(id) {
                        p.done += k;
                    }
                },
            };
            let mut buf = vec![0u8; 256 << 10];
            loop {
                let k = body.read(&mut buf).map_err(|e| anyhow!("{n}: {e}"))?;
                if k == 0 {
                    break;
                }
                h.write_all(&buf[..k])?;
                if n == "session.json" {
                    rec.extend_from_slice(&buf[..k]);
                }
            }
            let sum = hex::encode(h.h.finalize());
            man.files.get_or_insert_with(Vec::new).push(J1ImportFile { name: n.clone(), sha256: sum, size: h.n });
        }
        let jr: J1Record = jarvis_go::unmarshal(&rec).map_err(|e| anyhow!("session.json: {e}"))?;
        if !jr.id.is_empty() && jr.id != id {
            bail!("session.json names session {}, not {id}", jr.id);
        }
        let mb = jarvis_go::marshal(&man);
        self.st.write_doc(&j1_doc(id, J1_RECORD_FILE), &rec)?;
        self.st.write_doc(&j1_doc(id, J1_MANIFEST_FILE), mb.as_bytes())?;
        Ok(sha256_bytes(mb.as_bytes()))
    }

    /// an import of a session nobody prepared prepares it first (rather than refusing): the prepare starts (or the
    /// running one is joined) and the import waits for it
    fn ensure_prepared_jarvis1(self: &Arc<Self>, id: &str) -> Result<()> {
        check_id(id)?;
        if self.st.read_doc(&j1_doc(id, J1_MANIFEST_FILE)).is_some() {
            return Ok(());
        }
        self.prepare_jarvis1(id)?;
        let wait = Duration::from_millis(J1_PREPARE_WAIT_MS.load(std::sync::atomic::Ordering::Relaxed));
        let end = Instant::now() + wait;
        while Instant::now() < end {
            let (st, msg) = preps().get(id).map(|p| (p.state.clone(), p.error.clone())).unwrap_or_default();
            match st.as_str() {
                "ready" => return Ok(()),
                "failed" => bail!("Jarvis 1 session {id} couldn't be prepared: {msg}"),
                _ => std::thread::sleep(Duration::from_millis(200)),
            }
        }
        bail!(
            "Jarvis 1 session {id} is still being prepared after {}: ask again once GET …/jarvis1/{id} says ready",
            jarvis_go::fmt::duration_string(wait)
        )
    }

    /// the prepared manifest (its bytes and sha256) and record, or an error saying what's missing
    pub fn prepared_jarvis1(&self, id: &str) -> Result<(Vec<u8>, String, J1Record)> {
        check_id(id)?;
        let mb = self
            .st
            .read_doc(&j1_doc(id, J1_MANIFEST_FILE))
            .ok_or_else(|| bad(format!("Jarvis 1 session {id} isn't prepared: POST …/jarvis1/{id}/prepare first")))?;
        let rb = self.st.read_doc(&j1_doc(id, J1_RECORD_FILE)).ok_or_else(|| anyhow!("Jarvis 1 session {id}: its record is gone"))?;
        let rec: J1Record = jarvis_go::unmarshal(&rb)?;
        let sum = sha256_bytes(&mb);
        Ok((mb, sum, rec))
    }

    /// the prepared Jarvis 1 session as a new session waiting for the phone (approval kind new-session,
    /// options.restore names it). The same import asked again answers the session it already made (requestId).
    pub fn import_jarvis1(self: &Arc<Self>, id: &str, mut i: J1ImportIn, o: Origin) -> Result<String> {
        self.ensure_prepared_jarvis1(id)?;
        let (_, sum, rec) = self.prepared_jarvis1(id)?;
        // the shared login's old store comes as the Claude account
        i.stores.retain(|n| n != crate::claudeaccounts::LEGACY_CLAUDE_STORE);
        let label = first_non_empty(&[&rec.title, &rec.label, &format!("Jarvis 1 {id}")]);
        let harness = first_non_empty(&[&rec.harness, "claude"]);
        let h = self.policy.harnesses.get(&harness).cloned().ok_or_else(|| anyhow!("no harness {harness} in the policy"))?;
        let size = if i.size.is_empty() { j1_size(&rec.size).unwrap_or("medium").to_string() } else { i.size.clone() };
        let all = self.with_harness_stores(&i.stores, &h.stores)?;
        let mut prompt = i.prompt.trim().to_string();
        if prompt.is_empty() {
            prompt = j1_default_prompt(id, &all);
        }
        let repos: Vec<&str> = rec.repos.split([',', ' ', '\n']).filter(|s| !s.is_empty()).collect();
        let auto = rec.auto_pause != "off";
        let mut paused = rec.paused_at.as_str();
        if paused.len() >= 10 && paused.is_char_boundary(10) {
            paused = &paused[..10];
        }
        let ns = crate::flows::NewSession {
            request_id: format!("jarvis1-import:{id}:{}", &sum[..16]),
            label: label.clone(),
            prompt,
            model: rec.model.clone(),
            permission_mode: "bypass".into(), // the only start mode
            size,
            harness,
            stores: i.stores.clone(),
            account: i.account.clone(),
            repos: repos.join(","),
            auto_pause: Some(auto),
            origin: Some(o),
            explanation: i.explanation.clone(),
            batch: i.batch.clone(),
            import: Some(J1ImportRef {
                session: id.into(),
                sha256: sum.clone(),
                shown: format!("Jarvis 1 session “{label}” ({id}, paused {paused})"),
            }),
            ..Default::default()
        };
        self.create_session(ns)
    }

    // ---- the machine's side: the manifest and the files, only to the importing line's first machine -------------

    /// the Jarvis 1 session a machine imports
    pub fn import_for(&self, machine: &str) -> String {
        self.st.do_(|d| {
            let Some(s) = d.machines.get(machine).and_then(|sid| d.sessions.get(sid)) else { return String::new() };
            // the line's first machine, or a successor whose cert names no snapshot (its predecessor left none: the
            // machine takes the import again, rust/machine/src/restore.rs reimport_jarvis1)
            let cert = d.certs.get(machine);
            if s.import_from.is_empty()
                || s.machine_id != machine
                || (!crate::grants::cert_field(cert, "predecessorId").is_empty() && !crate::grants::cert_field(cert, "snapshot").is_empty())
            {
                return String::new();
            }
            s.import_from.clone()
        })
    }

    pub fn serve_import_manifest(&self, w: &mut W, id: &str) {
        match self.prepared_jarvis1(id) {
            Err(e) => write_error(w, 404, &format!("{e:#}")),
            Ok((mb, _, _)) => {
                w.set_header("Content-Type", "application/json");
                w.write(&mb);
            }
        }
    }

    fn serve_import_file(&self, w: &mut W, machine: &str, name: &str) {
        let id = self.import_for(machine);
        if id.is_empty() {
            return write_error(w, 404, "no Jarvis 1 import for this machine");
        }
        let mb = match self.prepared_jarvis1(&id) {
            Err(e) => return write_error(w, 404, &format!("{e:#}")),
            Ok((mb, _, _)) => mb,
        };
        let man: J1ImportManifest = jarvis_go::unmarshal(&mb).unwrap_or_default();
        let Some(want) = man.files.unwrap_or_default().into_iter().rfind(|f| f.name == name) else {
            return write_error(w, 404, "not a file of this import");
        };
        let (src, root) = match self.j1_source() {
            Err(e) => return write_err(w, &e),
            Ok(x) => x,
        };
        let mut body = match src.open(&j1_path(root, &[&id, name])) {
            Ok(Some((b, _))) => b,
            Ok(None) => return write_error(w, 502, "the Storage Box: <nil>"),
            Err(e) => return write_error(w, 502, &format!("the Storage Box: {e:#}")),
        };
        w.set_header("Content-Type", "application/octet-stream");
        w.set_header("Content-Length", &want.size.to_string()); // the machine checks size and sha256 itself
        let mut lim = (&mut body).take(want.size.max(0) as u64);
        if let Err(e) = std::io::copy(&mut lim, w) {
            crate::logf!("jarvis1 import {id}: {name} to {machine} cut off: {e}");
        }
    }

    /// an import whose session came up is noted (imported.json) so the list shows where it went
    pub fn tidy_imports(&self) {
        let list: Vec<(String, String)> = self.st.do_(|d| {
            d.sessions
                .values()
                .filter(|s| !s.import_from.is_empty() && !s.booted.is_empty())
                .map(|s| (s.import_from.clone(), s.id.clone()))
                .collect()
        });
        for (from, sid) in list {
            if self.st.read_doc(&j1_doc(&from, J1_IMPORTED_FILE)).is_some() {
                continue;
            }
            let b = jarvis_go::marshal(&json!({"session": sid, "at": GoTime::now().utc()}));
            let _ = self.st.write_doc(&j1_doc(&from, J1_IMPORTED_FILE), b.as_bytes());
        }
    }

    // ---- the list ---------------------------------------------------------------------------------------------------

    /// Jarvis 1's paused sessions (its index) with each one's import state here
    pub fn jarvis1_list(&self) -> Result<Vec<Value>> {
        let (src, root) = self.j1_source()?;
        let mut entries: Vec<(String, Map<String, Value>)> = vec![];
        if !root.is_empty() {
            let b = src.get(J1_PAUSED_INDEX)?.unwrap_or_default();
            let idx: Vec<Map<String, Value>> = serde_json::from_slice(&b).unwrap_or_default();
            for e in idx {
                if let Some(id) = e.get("id").and_then(Value::as_str).filter(|id| J1_SESSION_ID_RE.is_match(id)) {
                    entries.push((id.to_string(), e.clone()));
                }
            }
        }
        Ok(entries
            .into_iter()
            .map(|(id, e)| {
                let s = |k: &str| match e.get(k) {
                    None | Some(Value::Null) => String::new(),
                    Some(Value::String(s)) => s.clone(),
                    Some(v) => jarvis_go::fmt::go_sprint(v),
                };
                let g = |k: &str| e.get(k).cloned().unwrap_or(Value::Null);
                let mut v = Map::new();
                v.insert("id".into(), json!(id));
                v.insert("title".into(), json!(first_non_empty(&[&s("title"), &s("label")])));
                for k in ["pausedAt", "size", "model", "environment", "repos"] {
                    v.insert(k.into(), g(k));
                }
                self.j1_status(&id, &mut v);
                Value::Object(v)
            })
            .collect())
    }

    /// prepare state, manifest hash, the session made from it (waiting or imported)
    fn j1_status(&self, id: &str, v: &mut Map<String, Value>) {
        if let Some(p) = preps().get(id) {
            v.insert("prepare".into(), json!(p));
        }
        if let Ok((_, sum, _)) = self.prepared_jarvis1(id) {
            v.insert("sha256".into(), json!(sum));
        }
        if let Some(b) = self.st.read_doc(&j1_doc(id, J1_IMPORTED_FILE)) {
            v.insert("imported".into(), serde_json::from_slice(&b).unwrap_or(Value::Null));
        }
        let sessions: Vec<Value> = self.st.do_(|d| {
            d.sessions
                .values()
                .filter(|s| s.import_from == id)
                .map(|s| json!({"id": s.id, "state": s.state}))
                .collect()
        });
        v.insert("sessions".into(), json!(sessions));
    }
}

// ---- routes ------------------------------------------------------------------------------------------------------

fn list(r: &Arc<Router>, w: &mut W) {
    match r.jarvis1_list() {
        Err(e) => write_err(w, &e),
        Ok(l) => write_json(w, 200, &json!({"sessions": l})),
    }
}

fn status(r: &Arc<Router>, w: &mut W, id: &str) {
    let mut v = Map::new();
    v.insert("id".into(), json!(id));
    r.j1_status(id, &mut v);
    write_json(w, 200, &v);
}

fn prepare(r: &Arc<Router>, w: &mut W, id: &str) {
    match r.prepare_jarvis1(id) {
        Err(e) => write_err(w, &e),
        Ok(p) => write_json(w, 202, &json!({"id": id, "prepare": p})),
    }
}

fn import_it(r: &Arc<Router>, w: &mut W, req: &Req, id: &str, caller: Caller, b: &[u8]) {
    let mut i: J1ImportIn = match jarvis_go::unmarshal(b) {
        Ok(i) => i,
        Err(e) => return write_error(w, 400, &format!("bad JSON: {e}")),
    };
    i.explanation = match crate::inbox::clean_explanation(&i.explanation, caller.kind == "setup") {
        Ok(e) => e,
        Err(e) => return write_error(w, 400, &format!("{e:#}")),
    };
    let mut args = Map::new();
    args.insert("stores".into(), json!(i.stores));
    args.insert("size".into(), json!(i.size));
    let o = Origin { caller, call: ApiCall { method: "POST".into(), path: req.path.clone(), args }, ..Default::default() };
    match r.import_jarvis1(id, i, o) {
        Err(e) => write_err(w, &e),
        Ok(sid) => write_json(w, 200, &json!({"id": sid, "from": id, "approval": true})),
    }
}

pub fn register_jarvis1_import(reg: &mut Registrar) {
    // Deyao's login (the web page; the app later)
    reg.app("GET /api/jarvis1/paused", |r, w, _| list(r, w));
    reg.app("GET /api/jarvis1/paused/{id}", |r, w, req| status(r, w, &req.path_value("id")));
    reg.app("POST /api/jarvis1/paused/{id}/prepare", |r, w, req| prepare(r, w, &req.path_value("id")));
    reg.app("POST /api/jarvis1/paused/{id}/import", |r, w, req| {
        let b = req.read_body(1 << 16);
        let caller = crate::inbox::app_caller(req);
        import_it(r, w, req, &req.path_value("id"), caller, &b);
    });
    // the setup session (Claude): its Access token and the setup key's signature
    reg.setup_signed("GET /setup/jarvis1/paused", 1 << 16, |r, w, _, _| list(r, w));
    reg.setup_signed("GET /setup/jarvis1/paused/{id}", 1 << 16, |r, w, req, _| status(r, w, &req.path_value("id")));
    reg.setup_signed("POST /setup/jarvis1/paused/{id}/prepare", 1 << 16, |r, w, req, _| prepare(r, w, &req.path_value("id")));
    reg.setup_signed("POST /setup/jarvis1/paused/{id}/import", 1 << 16, |r, w, req, b| {
        let caller = Caller { kind: "setup".into(), ..Default::default() };
        import_it(r, w, req, &req.path_value("id"), caller, b);
    });
    // stopping a session from the setup session (2026-10-13: Deyao stopped the imported sessions): pause it (its
    // snapshot if the machine answers, else none) and cancel its wakeups and crons, so nothing resumes it by itself
    reg.setup_signed("POST /setup/sessions/{id}/pause", 1 << 16, |r, w, req, _| {
        let id = req.path_value("id");
        let mut cancelled = r.cancel_wakeups(&id, &[], true).unwrap_or_default();
        for c in r.list_crons(&id).unwrap_or_default() {
            let _ = r.cancel_cron(&id, &c.name);
            cancelled.push(format!("cron {}", c.name));
        }
        if let Err(e) = r.pause(&id) {
            let status = if e.downcast_ref::<crate::router::Busy>().is_some() {
                409 // another action holds it: try again (as write_err)
            } else if e.downcast_ref::<crate::drain::Draining>().is_some() {
                503
            } else {
                400
            };
            return write_json(w, status, &json!({"error": format!("{e:#}"), "cancelled": cancelled}));
        }
        write_json(w, 202, &json!({"ok": true, "phase": "pausing", "cancelled": cancelled}));
    });
    // resume and restart from the setup session, as the actions key's resume and the app's Restart (no prompt, no
    // option change): a line on an image from before the router's Claude login gets a resume-upgrade approval instead
    // (flows.rs legacy_login_image), so the phone decides; wakeups and crons stay armed
    reg.setup_signed("POST /setup/sessions/{id}/resume", 1 << 16, |r, w, req, _| match r.resume(&req.path_value("id"), false) {
        Err(e) => write_err(w, &e),
        Ok(()) => write_json(w, 202, &json!({"ok": true})),
    });
    reg.setup_signed("POST /setup/sessions/{id}/restart", 1 << 16, |r, w, req, _| {
        match r.restart(&req.path_value("id"), Default::default()) {
            Err(e) => write_err(w, &e),
            Ok(out) => write_json(w, 202, &out),
        }
    });
    // destroy from the setup session (Deyao, 2026-10-22: "destroy should be an api endpoint too"): the app's
    // POST /api/sessions/{id}/destroy — a running session is paused first (its final snapshot), then archived to the
    // Storage Box and burnt; a failed archive leaves it paused with the error unless force (?force=1 as the app's, or
    // {"force": true} in the body, which the setup signature covers; infra/setup.py sends the body)
    reg.setup_signed("POST /setup/sessions/{id}/destroy", 1 << 16, |r, w, req, b| {
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct In {
            force: bool,
        }
        let i: In = jarvis_go::unmarshal(b).unwrap_or_default();
        match r.destroy_with(&req.path_value("id"), i.force || req.query("force") == "1") {
            Err(e) => write_err(w, &e),
            Ok(()) => write_json(w, 202, &json!({"ok": true, "phase": "destroying"})),
        }
    });
    // the importing line's first machine (its manifest is served at /m/restore-snapshot, archive.rs)
    reg.m("GET /m/import-file/{name}", |r, w, req, machine, _| r.serve_import_file(w, machine, &req.path_value("name")));
}
