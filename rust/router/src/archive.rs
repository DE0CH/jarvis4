//! Archives of destroyed sessions, previous sessions and restoring one (docs/PARITY.md "Previous sessions").
//!
//! Destroy (flows.rs) pauses a running session first, so its machine signs and uploads a final snapshot, then
//! archive() writes it to the Storage Box with the router's own credentials as ONE streamed .tar.gz in Jarvis 4's own
//! folder (archivetar.rs has the layout). A reader verifies jarvis2/ in it: core-cert against the master key → cert
//! against the core key → snapshot against the cert's machine signing key.

use crate::core::{CoreError, Doc};
use crate::http::{Registrar, write_err};
use crate::inbox::{ApiCall, Origin};
use crate::nethttp::write_json;
use crate::router::Router;
use crate::state::{Record, Session};
use crate::storagebox::StorageBox;
use anyhow::{Result, anyhow};
use jarvis_go::GoTime;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::io::Read;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

pub const RECORDS_ROOT: &str = "claude-records";
/// Jarvis 4's own (archivetar.rs); Jarvis 2 keeps claude-records/.index
pub fn records_index() -> String {
    format!("{}/index.json", crate::archivetar::ARCHIVES_ROOT)
}
/// the repos' state, written by the machine into every snapshot (rust/machine/src/restore.rs)
pub const CHANGES_FILE: &str = ".jarvis2-changes.txt";

/// one "<repo> <uncommitted files> <unpushed commits, -1 = no upstream>" line per repo under ~/workspace (the same
/// script as rust/machine/src/restore.rs's)
pub const REPO_CHANGES_SH: &str = concat!(
    r#"cd ~/workspace 2>/dev/null || exit 0; for d in */; do d=${d%/}; [ -d "$d/.git" ] || continue; "#,
    r#"u=$(git -C "$d" status --porcelain 2>/dev/null | wc -l); "#,
    r#"if git -C "$d" rev-parse --abbrev-ref @{u} >/dev/null 2>&1; then p=$(git -C "$d" rev-list @{u}..HEAD --count 2>/dev/null || echo 0); else p=-1; fi; "#,
    r#"echo "$d $u $p"; done"#
);

fn is_zero_i64(n: &i64) -> bool {
    *n == 0
}

fn is_zero_f64(n: &f64) -> bool {
    *n == 0.0
}

/// what a destroy put on the Storage Box
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ArchiveInfo {
    /// claude-records/.jarvis4-records/<date> <title>.tar.gz (archivetar.rs)
    pub file: String,
    /// the title it was archived under
    pub title: String,
    /// their names in the archive, oldest first (always an array: "transcripts": null blanked the Previous tab)
    pub transcripts: Vec<String>,
    pub artifacts: i64,
    /// the machine whose snapshot it is
    pub signer: String,
    #[serde(rename = "snapshotAt")]
    pub snapshot_at: GoTime,
    /// the snapshot wasn't named in the kill (Session.snapshot_note): kept, but not restorable until the core vouches
    #[serde(skip_serializing_if = "String::is_empty")]
    pub unverified: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last: Option<crate::tails::TailMessage>,
    /// the session's .live transcripts, each in the snapshot or copied into the archive (livearchive.rs)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub live: Vec<crate::livearchive::LiveCopy>,
    /// why the record has no signed snapshot, or why the snapshot isn't the last machine's
    #[serde(rename = "noSnapshot", skip_serializing_if = "String::is_empty")]
    pub no_snapshot: String,
    /// the archive's size on the Storage Box; how long its upload took
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub bytes: i64,
    #[serde(rename = "uploadSeconds", skip_serializing_if = "is_zero_f64")]
    pub upload_seconds: f64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RestoreMark {
    #[serde(rename = "sessionId")]
    pub session: String,
    pub at: GoTime,
}

static SBOX: OnceLock<Option<Arc<StorageBox>>> = OnceLock::new();
/// the index is read-modify-write and WebDAV has no append
static INDEX_MU: Mutex<()> = Mutex::new(());

/// RECORDS_OFF=1 (the e2e test, which has no Storage Box) destroys without archiving
pub fn records_off() -> bool {
    std::env::var("RECORDS_OFF").as_deref() == Ok("1")
}

/// the mark on an archive whose snapshot the core refused to name in the kill
pub const SNAPSHOT_FROM_EARLIER_CORE: &str = "from an earlier core, not verified by this core";

/// the end of a failed destroy's error, which the apps match to offer Destroy anyway
pub const DESTROY_ANYWAY_HINT: &str =
    " (Destroy anyway removes the session; the machine is then on the Machines tab)";

/// the core refusing a kill because the snapshot isn't signed by the machine's current key
pub fn refused_snapshot(err: &anyhow::Error) -> bool {
    err.downcast_ref::<CoreError>()
        .is_some_and(|c| c.status == 403 && c.msg.contains("snapshot"))
}

type GoneFn = fn(&str) -> Result<bool>;

/// tests: Fly's answer replaced
pub static FLY_MACHINE_GONE: Mutex<Option<GoneFn>> = Mutex::new(None);

/// Fly (the router's read token) lists no such live machine. An error when Fly can't be asked.
pub fn fly_machine_gone(id: &str) -> Result<bool> {
    if let Some(f) = FLY_MACHINE_GONE.lock().ok().and_then(|g| *g) {
        return f(id);
    }
    let ms = crate::machines::list_fly_machines()?;
    Ok(!ms.iter().any(|m| m.id == id && m.state != "destroyed"))
}

/// a symlink's target as a path in the snapshot ("" when it points outside it)
pub fn resolve_link(link: &str, target: &str) -> String {
    const HOME: &str = "/home/claude/";
    let t = if target.starts_with('/') {
        let Some(rest) = target.strip_prefix(HOME) else {
            return String::new();
        };
        crate::util::path_clean(rest)
    } else {
        let dir = link.rsplit_once('/').map_or("", |(d, _)| d);
        crate::util::path_clean(&format!("{dir}/{target}"))
    };
    if t == "." || t == ".." || t.starts_with("../") || t.starts_with('/') {
        return String::new();
    }
    t
}

/// each entry of the snapshot at p (S2 or gzip, snapformat.rs)
pub fn walk_tar(
    p: &std::path::Path,
    mut f: impl FnMut(&tar::Header, &mut dyn Read) -> Result<()>,
) -> Result<()> {
    let file = std::fs::File::open(p)?;
    let zr = crate::snapformat::open_snap_reader(file)?;
    let mut tr = tar::Archive::new(zr);
    for e in tr.entries()? {
        let mut e = e?;
        let h = e.header().clone();
        f(&h, &mut e)?;
    }
    Ok(())
}

pub fn update_index(
    box_: &StorageBox,
    f: impl FnOnce(Vec<Map<String, Value>>) -> Vec<Map<String, Value>>,
) -> Result<()> {
    let _g = INDEX_MU.lock().unwrap_or_else(|e| e.into_inner());
    let idx = records_index();
    let raw = box_.get(&idx)?;
    let list: Vec<Map<String, Value>> = match raw {
        Some(b) => {
            serde_json::from_slice(&b).map_err(|e| anyhow!("{idx} is not a JSON array: {e}"))?
        }
        None => vec![],
    };
    let next = f(list);
    box_.mkcols(idx.rsplit_once('/').map_or("", |(d, _)| d))?;
    box_.put_bytes(&idx, jarvis_go::fmt::marshal_indent1(&next).as_bytes())
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RepoChange {
    pub name: String,
    pub uncommitted: i64,
    /// -1: the branch has no upstream
    pub unpushed: i64,
}

pub fn parse_repo_changes(text: &str) -> Vec<RepoChange> {
    text.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            (f.len() >= 3).then(|| RepoChange {
                name: f[0].into(),
                uncommitted: f[1].parse().unwrap_or(0),
                unpushed: f[2].parse().unwrap_or(0),
            })
        })
        .collect()
}

fn no_changes(reason: &str) -> Map<String, Value> {
    json!({"checked": false, "reason": reason, "repos": []})
        .as_object()
        .cloned()
        .unwrap_or_default()
}

/// sha256 hex of a file: what a machine signs for a snapshot
pub fn sha256hex(p: &std::path::Path) -> Result<String> {
    use sha2::Digest;
    let mut f = std::fs::File::open(p)?;
    let mut h = sha2::Sha256::new();
    std::io::copy(&mut f, &mut h)?;
    Ok(hex::encode(h.finalize()))
}

impl Router {
    pub fn box_(&self) -> Option<Arc<StorageBox>> {
        if let Some(b) = self
            .box_override
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        {
            return b;
        }
        SBOX.get_or_init(|| crate::storagebox::records_box_from_env().map(Arc::new))
            .clone()
    }

    /// the newest snapshot any of the session's machines left, and that machine's cert (its signing key checks the
    /// snapshot)
    pub fn latest_snapshot(&self, session_id: &str) -> (String, Option<Doc>, GoTime) {
        let ms: Vec<(String, Option<Doc>)> = self.st.do_(|d| {
            d.machines
                .iter()
                .filter(|(_, sid)| *sid == session_id)
                .map(|(m, _)| {
                    let mut c = d.certs.get(m).cloned();
                    if c.is_none() {
                        // kernelline.rs: a kernel machine's, the spawner's cert naming its key
                        c = d.started.get(m).and_then(|s| s.kernel_cert.clone());
                    }
                    (m.clone(), c)
                })
                .collect()
        });
        let (mut machine, mut cert, mut at) = (String::new(), None, GoTime::default());
        for (m, c) in ms {
            let Some(s) = self.snap(&m) else { continue };
            if s.state != "committed" || c.is_none() {
                continue;
            }
            if machine.is_empty() || s.committed_at.after(&at) {
                machine = m;
                cert = c;
                at = s.committed_at;
            }
        }
        (machine, cert, at)
    }

    /// what a destroy does to a running machine (flows.rs); false (state failed, machine kept) when its final snapshot
    /// or the kill fails (snapsafe.rs; force: Destroy anyway goes on past a failed snapshot or kill). DECISIONS 181.
    pub fn snapshot_and_kill(self: &Arc<Self>, id: &str, machine: &str, force: bool) -> bool {
        if !self.final_snapshot_and_kill_for(id, machine, true, force) {
            return false;
        }
        let now = GoTime::now();
        self.st.do_(|d| {
            if let Some(x) = d.sessions.get_mut(id) {
                x.machine_id.clear();
                x.paused_at = Some(now);
                x.status.clear();
            }
        });
        true
    }

    /// the session's archive onto the Storage Box (archivetar.rs): its latest snapshot with every live copy it doesn't
    /// hold, or the live copies alone. None when there is nothing to archive or records are off.
    pub fn archive(self: &Arc<Self>, id: &str) -> Result<Option<ArchiveInfo>> {
        if records_off() {
            return Ok(None);
        }
        let Some(b) = self.box_() else {
            if self.latest_snapshot(id).0.is_empty() {
                crate::logf!("session {id}: no snapshot to archive");
                return Ok(None);
            }
            return Err(crate::storagebox::no_storage_box());
        };
        let s: Session = self
            .st
            .do_(|d| d.sessions.get(id).cloned())
            .ok_or_else(|| anyhow!("no session {id}"))?;
        self.archive_session(&b, &s)
    }

    /// a running session's repos (a command under the archive holder's grant), or a paused session's as its last
    /// snapshot recorded them
    pub fn changes(self: &Arc<Self>, id: &str) -> Map<String, Value> {
        let s: Session = self
            .st
            .do_(|d| d.sessions.get(id).cloned().unwrap_or_default());
        if s.id.is_empty() {
            return no_changes("no such session");
        }
        if !s.machine_id.is_empty() && s.state == "started" {
            return match self.exec(id, "archive", REPO_CHANGES_SH, Duration::from_secs(20)) {
                Err(e) => no_changes(&format!("{e:#}")),
                Ok(res) => json!({"checked": true, "repos": parse_repo_changes(&res.stdout), "status": s.status})
                    .as_object()
                    .cloned()
                    .unwrap_or_default(),
            };
        }
        if s.machine_id.is_empty() && s.state == "paused" {
            return self.snapshot_changes(id).unwrap_or_else(|| no_changes("?"));
        }
        no_changes(&format!("session is {}", s.state))
    }

    /// the repos' state as the session's newest snapshot recorded it
    pub fn snapshot_changes(&self, id: &str) -> Option<Map<String, Value>> {
        let (m, _, _) = self.latest_snapshot(id);
        if m.is_empty() {
            return Some(no_changes("it has no pause snapshot"));
        }
        Some(match self.snap_facts_of(&m) {
            Err(e) => no_changes(&format!("{e:#}")),
            Ok(f) => match f.changes {
                None => no_changes("its pause snapshot has no record of the repos' state — resume it and check again"),
                Some(c) => json!({"checked": true, "paused": true, "repos": parse_repo_changes(&c), "status": ""})
                    .as_object()
                    .cloned()
                    .unwrap_or_default(),
            },
        })
    }

    /// the end of a paused session's conversation, from its snapshot
    pub fn paused_tail(&self, id: &str) -> Result<crate::tails::Tail, (u16, anyhow::Error)> {
        let s: Session = self
            .st
            .do_(|d| d.sessions.get(id).cloned().unwrap_or_default());
        if s.id.is_empty() {
            return Err((404, anyhow!("no such session")));
        }
        let stale = !s.machine_id.is_empty(); // running: its last pause snapshot's tail, marked stale
        let (m, _, _) = self.latest_snapshot(id);
        if m.is_empty() {
            return Err((404, anyhow!("this session has no pause snapshot yet")));
        }
        let facts = self.snap_facts_of(&m).map_err(|e| (500, e))?;
        let mut t = facts.tail.unwrap_or_default();
        t.stale = stale;
        Ok(t)
    }

    pub fn record(&self, id: &str) -> Option<Record> {
        self.st
            .do_(|d| d.records.iter().find(|x| x.session.id == id).cloned())
    }

    /// the end of a destroyed session's conversation, from its archive (a Range read)
    pub fn record_tail(&self, id: &str) -> Result<crate::tails::Tail, (u16, anyhow::Error)> {
        let rec = self
            .record(id)
            .ok_or_else(|| (404, anyhow!("no such previous session")))?;
        let Some(a) = rec.archive.filter(|a| !a.transcripts.is_empty()) else {
            return Err((
                404,
                anyhow!("this session was destroyed without an archived transcript"),
            ));
        };
        let b = self
            .box_()
            .ok_or_else(|| (500, crate::storagebox::no_storage_box()))?;
        let name = a.transcripts.last().cloned().unwrap_or_default();
        let text = crate::archivetar::archive_tail(&b, &a.file, &name, crate::tails::TAIL_BYTES)
            .map_err(|e| {
                if e.downcast_ref::<crate::archivetar::NoArchive>().is_some() {
                    (404, e)
                } else {
                    (500, e)
                }
            })?;
        let Some(mut text) = text else {
            return Err((404, anyhow!("transcript missing: {name} in {}", a.file)));
        };
        if text.len() > crate::tails::TAIL_BYTES {
            text = text[text.len() - crate::tails::TAIL_BYTES..].to_vec();
        }
        Ok(crate::tails::tail_of(&text))
    }

    /// off the list (and the box's index); with purge its archive file too
    pub fn delete_record(&self, id: &str, purge: bool) -> Result<Value> {
        let Some(rec) = self.record(id) else {
            return Ok(json!({"ok": true, "already": true})); // gone already: what was asked for
        };
        let b = self.box_();
        let mut out = json!({"ok": true});
        if purge && let Some(a) = &rec.archive {
            let b = b.as_ref().ok_or_else(crate::storagebox::no_storage_box)?;
            if !ARCHIVE_FILE_RE.is_match(&a.file) {
                return Err(anyhow!(
                    "refusing to delete '{}': not a {}/<name>.tar.gz archive",
                    a.file,
                    crate::archivetar::ARCHIVES_ROOT
                ));
            }
            b.delete(&a.file)?;
            out["purged"] = json!({"file": a.file});
        }
        if let Some(b) = &b {
            update_index(b, |list| {
                list.into_iter()
                    .filter(|e| e.get("id").and_then(|v| v.as_str()) != Some(id))
                    .collect()
            })?;
        }
        self.st.do_(|d| d.records.retain(|x| x.session.id != id));
        Ok(out)
    }

    pub fn archive_loop(self: &Arc<Self>) {
        loop {
            crate::leaderlease::await_lead();
            self.tidy_restores();
            self.tidy_imports(); // jarvis1import.rs
            std::thread::sleep(Duration::from_secs(60));
        }
    }
}

static ARCHIVE_FILE_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
    regex::Regex::new(r"^claude-records/\.jarvis4-records/[^/.][^/]*\.tar\.gz$")
        .unwrap_or_else(|e| panic!("{e}"))
});

pub fn register_archive(reg: &mut Registrar) {
    reg.app("GET /api/sessions/{id}/changes", |r, w, req| {
        write_json(w, 200, &r.changes(&req.path_value("id")))
    });
    reg.app("GET /api/sessions/{id}/tail", |r, w, req| {
        match r.paused_tail(&req.path_value("id")) {
            Err((st, e)) => crate::nethttp::write_error(w, st, &format!("{e:#}")),
            Ok(t) => write_json(w, 200, &t),
        }
    });
    reg.app("GET /api/records/{id}/tail", |r, w, req| {
        match r.record_tail(&req.path_value("id")) {
            Err((st, e)) => crate::nethttp::write_error(w, st, &format!("{e:#}")),
            Ok(t) => write_json(w, 200, &t),
        }
    });
    reg.app("DELETE /api/records/{id}", |r, w, req| {
        match r.delete_record(&req.path_value("id"), req.query("purge") == "1") {
            Err(e) => write_err(w, &e),
            Ok(o) => write_json(w, 200, &o),
        }
    });
    reg.app("POST /api/records/{id}/restore", |r, w, req| {
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct In {
            #[serde(rename = "requestId")]
            request_id: String,
        }
        let mut i: In = crate::http::decode_body(req, 1 << 16);
        if i.request_id.is_empty() {
            i.request_id = crate::util::rand_id();
        }
        match r.restore_record(&req.path_value("id"), &i.request_id) {
            Err(e) => write_err(w, &e),
            Ok(sid) => {
                r.note_origin(
                    &sid,
                    Origin {
                        caller: crate::inbox::app_caller(req),
                        call: ApiCall {
                            method: "POST".into(),
                            path: req.path.clone(),
                            ..Default::default()
                        },
                        via_call: crate::apicalls::via_call(req),
                        ..Default::default()
                    },
                );
                write_json(w, 200, &json!({"id": sid, "requestId": i.request_id}));
            }
        }
    });
    reg.m("POST /m/live-transcript", |r, w, req, machine, body| {
        r.live_transcript(w, req, machine, body)
    }); // livesync.rs
    reg.m("GET /m/restore-snapshot", |r, w, req, machine, _| {
        let id = r.import_for(machine);
        if !id.is_empty() {
            // jarvis1import.rs: an import's manifest (the cert names its hash)
            r.serve_import_manifest(w, &id);
            return;
        }
        let Some(s) = r.restore_files_for(machine) else {
            crate::nethttp::write_error(w, 404, "no restore for this machine");
            return;
        };
        match r.snap_open(&s) {
            Err(_) => crate::nethttp::write_error(w, 404, "no restore snapshot"),
            Ok(rd) => {
                w.set_header("X-Snapshot-Sig", &s.sig);
                w.set_header("Content-Type", "application/gzip");
                let size = rd.size;
                crate::util::serve_content(w, req, s.committed_at, rd, size);
            }
        }
    });
}
