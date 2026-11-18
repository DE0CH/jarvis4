//! A destroyed session's archive: ONE .tar.gz on the Storage Box, written while it uploads (a chunked PUT fed by a
//! pipe: no copy of the archive on disk or in memory), in Jarvis 4's own folder:
//!
//!   claude-records/.jarvis4-records/<yyyy-mm-dd> <title>.tar.gz      (" 2", " 3", … when the name is taken)
//!   claude-records/.jarvis4-records/index.json                        every archive, newest first
//!
//! Inside, in this order (readers that want a transcript stop early; the snapshot, the biggest part, is last):
//!   session.json, restore-<session id>.json, transcript-<id>.jsonl (the snapshot's and every live copy it doesn't hold
//!   byte-identical), artifacts/** (symlinks followed inside the snapshot; a file a link also names is stored once and
//!   the other names are tar hard links to it), jarvis2/lifecycle.json, jarvis2/supervisor-log.jsonl,
//!   discord/messages.json + discord/attachments/…, jarvis2/cert.json, jarvis2/core-cert.json, jarvis2/snapshot.sig,
//!   jarvis2/snapshot.tar.gz.
//!
//! The upload goes to <name>.part and is renamed once the Storage Box holds every byte, so an archive under its real
//! name is always whole.

use crate::archive::{ArchiveInfo, RECORDS_ROOT, resolve_link, update_index, walk_tar};
use crate::core::Doc;
use crate::livesync::FileSum;
use crate::router::Router;
use crate::state::Session;
use crate::storagebox::StorageBox;
use anyhow::{Result, anyhow};
use jarvis_go::GoTime;
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const ARCHIVES_ROOT: &str = "claude-records/.jarvis4-records";

/// how often an upload is made again from the plan before the archive fails
pub static ARCHIVE_TRIES: AtomicI64 = AtomicI64::new(3);
/// at most every 20 s, a progress line
pub static ARCHIVE_PROGRESS_EVERY_MS: AtomicU64 = AtomicU64::new(20_000);

/// "12.3 MB"
pub fn mb(n: i64) -> String {
    format!("{:.1} MB", n as f64 / 1e6)
}

pub fn safe_title(t: &str, fallback: &str) -> String {
    let t: String = t
        .chars()
        .map(|c| if "/\\:*?\"<>|".contains(c) || (c as u32) < 0x20 { ' ' } else { c })
        .collect();
    let mut t = jarvis_go::fmt::fields_join(&t);
    if t.chars().count() > 60 {
        t = t.chars().take(60).collect::<String>().trim().to_string();
    }
    if t.is_empty() { fallback.to_string() } else { t }
}

/// the archive's name for a title (a leading "." is dropped)
pub fn archive_file_for(s: &Session, title: &str) -> String {
    let created = if s.created.is_zero() { GoTime::now() } else { s.created };
    let day = created.utc().rfc3339()[..10].to_string();
    format!(
        "{ARCHIVES_ROOT}/{day} {}.tar.gz",
        safe_title(title.trim_start_matches(['.', ' ']), &s.id)
    )
}

/// everything one archive holds, gathered before the upload so the stream can be made again on a retry
#[derive(Default)]
pub struct ArchivePlan {
    pub file: String,
    pub head: Vec<(String, Vec<u8>)>,
    pub live: Vec<(String, PathBuf)>,
    /// the snapshot (None: a live-only archive): its local copy, and per snapshot name the archive names it goes to
    pub snap: Option<PathBuf>,
    pub dests: BTreeMap<String, Vec<String>>,
    pub transcripts: BTreeSet<String>,
    pub tail: Vec<(String, Vec<u8>)>,
    /// a local dir with the Discord export (None: none)
    pub discord: Option<PathBuf>,
    pub sigs: Vec<(String, Vec<u8>)>,
    /// the files' total size (progress)
    pub raw_bytes: i64,
}

/// pass one over the snapshot: what each file becomes in the archive, the transcripts in time order, and the
/// transcripts' sums (to compare with the live copies)
#[derive(Default)]
pub struct SnapshotLayout {
    pub dests: BTreeMap<String, Vec<String>>,
    /// archive names, oldest first
    pub transcripts: Vec<String>,
    pub is_transcript: BTreeSet<String>,
    /// transcript file name (<uuid>.jsonl) → its size and sha256
    pub sums: BTreeMap<String, FileSum>,
    pub artifacts: i64,
    pub artifact_names: Vec<String>,
    pub unresolved: Vec<String>,
    pub bytes: i64,
}

fn base(p: &str) -> &str {
    p.rsplit_once('/').map_or(p, |(_, b)| b)
}

pub fn layout_snapshot(snap: &Path) -> Result<SnapshotLayout> {
    let mut regular: BTreeMap<String, (u64, i64)> = BTreeMap::new();
    let mut links: BTreeMap<String, String> = BTreeMap::new();
    let mut out = SnapshotLayout::default();
    walk_tar(snap, |h, body| {
        let name = crate::util::path_clean(&String::from_utf8_lossy(&h.path_bytes()));
        match h.entry_type() {
            tar::EntryType::Regular => {
                regular.insert(name.clone(), (h.mtime().unwrap_or(0), h.size().unwrap_or(0) as i64));
                if crate::tails::is_transcript(&name) {
                    out.sums.insert(base(&name).to_string(), crate::livesync::sum_reader(body)?);
                }
            }
            tar::EntryType::Symlink if name.starts_with("artifacts/") => {
                let l = h
                    .link_name_bytes()
                    .map(|b| String::from_utf8_lossy(&b).into_owned())
                    .unwrap_or_default();
                links.insert(name, l);
            }
            _ => {}
        }
        Ok(())
    })?;
    let mut transcripts = vec![];
    for name in regular.keys() {
        if crate::tails::is_transcript(name) {
            transcripts.push(name.clone());
            out.is_transcript.insert(name.clone());
            out.dests.entry(name.clone()).or_default().push(format!("transcript-{}", base(name)));
        } else if name.starts_with("artifacts/") {
            out.dests.entry(name.clone()).or_default().push(name.clone());
        }
    }
    for (l, target) in &links {
        let t = resolve_link(l, target);
        if t.is_empty() {
            out.unresolved.push(l.clone());
            continue;
        }
        let mut hit = false;
        for name in regular.keys() {
            if *name == t {
                out.dests.entry(name.clone()).or_default().push(l.clone());
                hit = true;
            } else if let Some(rest) = name.strip_prefix(&format!("{t}/")) {
                out.dests.entry(name.clone()).or_default().push(format!("{l}/{rest}"));
                hit = true;
            }
        }
        if !hit {
            out.unresolved.push(l.clone());
        }
    }
    transcripts.sort_by(|a, b| {
        let (x, y) = (regular[a].0, regular[b].0);
        x.cmp(&y).then(a.cmp(b))
    });
    out.transcripts = transcripts.iter().map(|t| format!("transcript-{}", base(t))).collect();
    for (name, ds) in out.dests.iter_mut() {
        ds.sort(); // the first name holds the bytes, the others link to it: the same on every pass
        out.bytes += regular.get(name).map_or(0, |x| x.1);
        for d in ds.iter() {
            if let Some(a) = d.strip_prefix("artifacts/") {
                out.artifacts += 1;
                out.artifact_names.push(a.to_string());
            }
        }
    }
    out.artifact_names.sort();
    out.unresolved.sort();
    Ok(out)
}

/// the plan as one gzip-compressed tar into w
pub fn write_archive(w: impl Write, p: &ArchivePlan, progress: &dyn Fn(i64)) -> Result<()> {
    // the snapshot inside is compressed already
    let gz = flate2::write::GzEncoder::new(w, flate2::Compression::fast());
    let mut tw = tar::Builder::new(gz);
    let now = crate::util::unix_now() as u64;
    let mut raw: i64 = 0;
    let mut add = |tw: &mut tar::Builder<_>, name: &str, size: u64, at: u64, body: &mut dyn Read| -> Result<()> {
        let mut h = tar::Header::new_gnu();
        h.set_size(size);
        h.set_mode(0o644);
        h.set_mtime(at);
        h.set_entry_type(tar::EntryType::Regular);
        let mut counted = CountingReader { r: body, n: 0 };
        tw.append_data(&mut h, name, &mut counted)?;
        if counted.n != size {
            return Err(anyhow!("{name}: {} bytes, expected {size}", counted.n));
        }
        raw += size as i64;
        progress(raw);
        Ok(())
    };
    for (name, body) in &p.head {
        add(&mut tw, name, body.len() as u64, now, &mut &body[..])?;
    }
    let disk = |tw: &mut tar::Builder<_>, add: &mut dyn FnMut(&mut tar::Builder<_>, &str, u64, u64, &mut dyn Read) -> Result<()>, name: &str, local: &Path| -> Result<()> {
        let mut f = std::fs::File::open(local)?;
        let md = f.metadata()?;
        let at = md
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or(now, |d| d.as_secs());
        add(tw, name, md.len(), at, &mut f)
    };
    for (name, local) in &p.live {
        disk(&mut tw, &mut add, name, local)?;
    }
    if let Some(snap) = &p.snap {
        // two passes over the local snapshot: the transcripts first, then the artifacts
        for transcripts in [true, false] {
            walk_tar(snap, |h, body| {
                let name = crate::util::path_clean(&String::from_utf8_lossy(&h.path_bytes()));
                let Some(ds) = p.dests.get(&name) else { return Ok(()) };
                if h.entry_type() != tar::EntryType::Regular || ds.is_empty() || p.transcripts.contains(&name) != transcripts {
                    return Ok(());
                }
                let at = h.mtime().unwrap_or(now);
                add(&mut tw, &ds[0], h.size().unwrap_or(0), at, body)?;
                for d in &ds[1..] {
                    let mut lh = tar::Header::new_gnu();
                    lh.set_entry_type(tar::EntryType::Link);
                    lh.set_mode(0o644);
                    lh.set_mtime(at);
                    lh.set_size(0);
                    tw.append_link(&mut lh, d, &ds[0])?;
                }
                Ok(())
            })?;
        }
    }
    for (name, body) in &p.tail {
        add(&mut tw, name, body.len() as u64, now, &mut &body[..])?;
    }
    if let Some(dir) = &p.discord {
        let mut files = vec![];
        crate::util::walk_files(dir, &mut files)?;
        files.sort();
        for local in files {
            let rel = local.strip_prefix(dir).unwrap_or(&local).to_string_lossy().into_owned();
            disk(&mut tw, &mut add, &format!("discord/{rel}"), &local)?;
        }
    }
    for (name, body) in &p.sigs {
        add(&mut tw, name, body.len() as u64, now, &mut &body[..])?;
    }
    if let Some(snap) = &p.snap {
        disk(&mut tw, &mut add, "jarvis2/snapshot.tar.gz", snap)?;
    }
    let gz = tw.into_inner()?;
    gz.finish()?;
    Ok(())
}

struct CountingReader<'a> {
    r: &'a mut dyn Read,
    n: u64,
}

impl Read for CountingReader<'_> {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        let n = self.r.read(b)?;
        self.n += n as u64;
        Ok(n)
    }
}

struct SentCounter<W: Write> {
    w: W,
    n: Arc<AtomicI64>,
}

impl<W: Write> Write for SentCounter<W> {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        let n = self.w.write(b)?;
        self.n.fetch_add(n as i64, Ordering::SeqCst);
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.w.flush()
    }
}

/// the record's archive isn't on the Storage Box
#[derive(Debug)]
pub struct NoArchive(pub String);

impl std::fmt::Display for NoArchive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the archive is not on the Storage Box: {}", self.0)
    }
}

impl std::error::Error for NoArchive {}

/// an archive's entries, streamed from the Storage Box (f returns Ok(false) to stop early)
pub fn walk_archive(b: &StorageBox, file: &str, mut f: impl FnMut(&tar::Header, &mut dyn Read) -> Result<bool>) -> Result<()> {
    let Some((rc, _)) = b.open(file)? else {
        return Err(NoArchive(file.to_string()).into());
    };
    let gz = flate2::read::GzDecoder::new(rc);
    let mut tr = tar::Archive::new(gz);
    for e in tr.entries()? {
        let mut e = e?;
        let h = e.header().clone();
        if !f(&h, &mut e)? {
            return Ok(());
        }
    }
    Ok(())
}

fn entry_name(h: &tar::Header) -> String {
    String::from_utf8_lossy(&h.path_bytes()).into_owned()
}

/// the last n bytes of one file in an archive (None when the archive doesn't hold it)
pub fn archive_tail(b: &StorageBox, file: &str, name: &str, n: usize) -> Result<Option<Vec<u8>>> {
    let mut out = None;
    walk_archive(b, file, |h, body| {
        if entry_name(h) != name {
            return Ok(true);
        }
        let mut t = crate::tails::TailBuf::new(n);
        std::io::copy(body, &mut t)?;
        out = Some(t.bytes());
        Ok(false)
    })?;
    Ok(out)
}

/// the named entries of an archive into dir (each under its base name); the names it found
pub fn extract_archive(b: &StorageBox, file: &str, dir: &Path, names: &[&str]) -> Result<BTreeSet<String>> {
    let want: BTreeSet<&str> = names.iter().copied().collect();
    let mut found = BTreeSet::new();
    walk_archive(b, file, |h, body| {
        let name = entry_name(h);
        if h.entry_type() != tar::EntryType::Regular || !want.contains(name.as_str()) {
            return Ok(true);
        }
        let mut f = std::fs::File::create(dir.join(base(&name)))?;
        std::io::copy(body, &mut f)?;
        found.insert(name);
        Ok(found.len() < want.len())
    })?;
    Ok(found)
}

impl Router {
    /// the session's archive name, made unique against what is already in the folder and kept on the session, so a
    /// retried destroy writes the same one
    pub fn pick_archive_file(&self, b: &StorageBox, s: &mut Session, title: &str) -> Result<String> {
        if !s.archive_file.is_empty() {
            return Ok(s.archive_file.clone());
        }
        let f = archive_file_for(s, title);
        let base_name = f.strip_suffix(".tar.gz").unwrap_or(&f).to_string();
        let mut name = base_name.clone();
        let mut i = 2;
        loop {
            if !b.exists(&format!("{name}.tar.gz"))? {
                break;
            }
            if i > 50 {
                // 50 of the same name: the session id makes it unique
                name = format!("{base_name} {}", s.id);
                break;
            }
            name = format!("{base_name} {i}");
            i += 1;
        }
        let file = format!("{name}.tar.gz");
        self.st.do_(|d| {
            if let Some(x) = d.sessions.get_mut(&s.id) {
                x.archive_file = file.clone();
            }
        });
        s.archive_file = file.clone();
        Ok(file)
    }

    /// the plan streamed to <file>.part, its size checked against what was sent, then renamed to file → the bytes
    /// the Storage Box holds and how long the upload took
    pub fn upload_archive(&self, b: &StorageBox, sid: &str, p: &ArchivePlan) -> Result<(i64, Duration)> {
        b.mkcols(ARCHIVES_ROOT)?;
        let part = format!("{}.part", p.file);
        let mut last = anyhow!("no upload");
        let tries = ARCHIVE_TRIES.load(Ordering::Relaxed);
        for t in 1..=tries {
            let t0 = Instant::now();
            let (pr, pw) = std::io::pipe()?;
            let sent = Arc::new(AtomicI64::new(0));
            let progress = self.archive_progress(sid, p.raw_bytes);
            let s2 = sent.clone();
            let res = std::thread::scope(|sc| {
                let wr = sc.spawn(move || write_archive(SentCounter { w: pw, n: s2 }, p, &*progress));
                let up = b.put_stream(&part, pr);
                let w = wr.join().unwrap_or_else(|_| Err(anyhow!("the archive writer panicked")));
                up.and(w)
            });
            let res = res.and_then(|()| {
                let size = b.size(&part)?;
                if size != sent.load(Ordering::SeqCst) {
                    return Err(anyhow!(
                        "the Storage Box holds {size} bytes of {part}, {} were sent",
                        sent.load(Ordering::SeqCst)
                    ));
                }
                b.move_(&part, &p.file)?;
                Ok(size)
            });
            match res {
                Ok(size) => {
                    self.set_waiting(sid, "");
                    return Ok((size, t0.elapsed()));
                }
                Err(e) => {
                    crate::logf!("session {sid}: archive upload {t} of {tries}: {e:#}");
                    let _ = b.delete(&part);
                    last = e;
                    std::thread::sleep(crate::storagebox::put_backoff() * t as u32);
                }
            }
        }
        self.set_waiting(sid, "");
        Err(last)
    }

    /// an archive's upload progress, as the session's waiting text and, at most every 20 s, a line in the destroy's
    /// lifecycle log and the router's log
    fn archive_progress(&self, sid: &str, total: i64) -> Box<dyn Fn(i64) + Send + Sync + '_> {
        let last: Mutex<Option<Instant>> = Mutex::new(None);
        let sid = sid.to_string();
        Box::new(move |raw| {
            let mut g = last.lock().unwrap_or_else(|e| e.into_inner());
            if g.is_some_and(|l| l.elapsed() < Duration::from_millis(ARCHIVE_PROGRESS_EVERY_MS.load(Ordering::Relaxed))) {
                return;
            }
            *g = Some(Instant::now());
            let text = format!("archiving to the Storage Box: {} of {}", mb(raw), mb(total));
            self.set_waiting(&sid, &text);
            self.lc_note(&sid, "", &text);
            crate::logf!("session {sid}: {text}");
        })
    }

    /// the session's archive (its latest snapshot, or only its live copies) onto the Storage Box and into the index.
    /// None when there is neither (the session never ran).
    pub fn archive_session(self: &Arc<Self>, b: &StorageBox, s: &Session) -> Result<Option<ArchiveInfo>> {
        let mut s = s.clone();
        let scratch = Path::new(&self.cfg.data_dir).join("tmp");
        std::fs::create_dir_all(&scratch)?;
        let tmp = scratch.join(format!("archive-{}", crate::util::rand_id()));
        std::fs::create_dir_all(&tmp)?;
        let _rm = {
            let t = tmp.clone();
            crate::flows::scopeguard(move || {
                let _ = std::fs::remove_dir_all(&t); // the snapshot's scratch copy, the live copies, the Discord export
            })
        };
        let mut p = ArchivePlan::default();
        let mut lay = SnapshotLayout::default();
        let mut title = crate::titles::session_title(&s);
        let (machine, cert, at) = self.latest_snapshot(&s.id);
        let mut tail = None;
        if !machine.is_empty() {
            let sn = self
                .snap(&machine)
                .ok_or_else(|| anyhow!("the snapshot of {machine} is gone"))?;
            let facts = self
                .snap_facts(&sn)
                .map_err(|e| anyhow!("reading the snapshot: {e:#}"))?;
            tail = facts.tail;
            if s.app_title.is_empty()
                && s.label.is_empty()
                && s.user_title.is_empty()
                && let Some(t) = &tail
                && !t.title.is_empty()
            {
                title = t.title.clone(); // the title the app showed, from the transcript
            }
            let local = self
                .snap_to_file(&sn, &tmp)
                .map_err(|e| anyhow!("fetching the snapshot: {e:#}"))?;
            lay = layout_snapshot(&local)?;
            p.dests = lay.dests.clone();
            p.transcripts = lay.is_transcript.clone();
            p.snap = Some(local);
        }
        let taken: BTreeSet<String> = lay.transcripts.iter().cloned().collect();
        let (live, live_files) = self.gather_live(b, &s.id, &tmp, &lay.sums, &taken)?;
        if machine.is_empty() && live.is_empty() {
            crate::logf!("session {}: no snapshot and no live copy to archive", s.id);
            return Ok(None);
        }
        let file = self.pick_archive_file(b, &mut s, &title)?;
        p.file = file.clone();
        p.live = live_files.clone();
        let mut transcripts: Vec<String> = live_files.iter().map(|(n, _)| n.clone()).collect();
        transcripts.extend(lay.transcripts.iter().cloned()); // older conversations first; the snapshot's newest last
        let mut info = ArchiveInfo {
            file: file.clone(),
            title: title.clone(),
            transcripts: transcripts.clone(),
            artifacts: lay.artifacts,
            live: live.clone(),
            no_snapshot: s.no_snapshot.clone(),
            ..Default::default()
        };
        let now = GoTime::now();
        let stores = s.stores.clone().unwrap_or_default();
        let mut meta: Map<String, Value> = json!({
            "id": s.id, "jarvis": 4, "title": title, "label": s.label, "aiTitle": s.title, "created": s.created,
            "destroyedAt": now, "archive": file, "environment": stores.join(","), "stores": s.stores,
            "repos": s.repos, "model": s.model, "permissionMode": s.permission_mode, "size": s.size, "harness": s.harness,
            "image": s.image, "live": live,
        })
        .as_object()
        .cloned()
        .unwrap_or_default();
        let mut man: Map<String, Value> =
            json!({"id": s.id, "archive": file, "transcripts": transcripts, "artifacts": lay.artifact_names})
                .as_object()
                .cloned()
                .unwrap_or_default();
        if let (false, Some(snap), Some(cert)) = (machine.is_empty(), &p.snap, &cert) {
            info.signer = machine.clone();
            info.snapshot_at = at.utc();
            info.unverified = s.snapshot_note.clone();
            if let Some(t) = &tail {
                info.last = crate::tails::snippet(t);
            }
            meta.insert("line".into(), json!(crate::vouch::cert_field(Some(cert), "line")));
            meta.insert("snapshotMachine".into(), json!(machine));
            meta.insert("snapshotAt".into(), json!(info.snapshot_at));
            meta.insert("unresolvedArtifactLinks".into(), json!(lay.unresolved));
            if !s.no_snapshot.is_empty() {
                meta.insert(
                    "noSnapshot".into(),
                    json!(format!("{}; this is the newest signed snapshot the router had", s.no_snapshot)),
                );
            }
            if !s.snapshot_note.is_empty() {
                meta.insert("snapshotUnverified".into(), json!(s.snapshot_note));
            }
            man.insert("snapshot".into(), json!("jarvis2/snapshot.tar.gz"));
            man.insert("signer".into(), json!(machine));
            let sig = std::fs::read_to_string(format!("{}.sig", snap.display()))?;
            p.sigs.push(("jarvis2/cert.json".into(), jarvis_go::marshal(cert).into_bytes()));
            if let Some(b) = self.core_cert() {
                p.sigs.push(("jarvis2/core-cert.json".into(), b));
            }
            p.sigs.push(("jarvis2/snapshot.sig".into(), sig.trim().as_bytes().to_vec()));
        } else {
            let mut why = "the session left no signed snapshot".to_string();
            if !s.no_snapshot.is_empty() {
                why.push_str(&format!(" ({})", s.no_snapshot));
            }
            why.push_str(": this record holds only its live transcript copies, so it can't be restored");
            info.no_snapshot = why.clone();
            meta.insert("line".into(), json!(crate::vouch::cert_field(s.cert.as_ref(), "line")));
            meta.insert("snapshot".into(), Value::Null);
            meta.insert("noSnapshot".into(), json!(why));
            man.insert("snapshot".into(), Value::Null);
        }
        p.head = vec![
            ("session.json".into(), jarvis_go::fmt::marshal_indent1(&meta).into_bytes()),
            (format!("restore-{}.json", s.id), jarvis_go::marshal(&man).into_bytes()),
        ];
        self.lc_note(&s.id, "", &format!("uploading the archive to {file}"));
        p.tail = self.lifecycle_files(&s.id); // up to here
        let (discord, discord_done) = self.discord_export(&s, &tmp); // discord.rs: None without a channel
        p.discord = discord;
        p.raw_bytes = lay.bytes
            + p.head.iter().chain(p.tail.iter()).chain(p.sigs.iter()).map(|(_, b)| b.len() as i64).sum::<i64>()
            + live_files
                .iter()
                .filter_map(|(_, l)| std::fs::metadata(l).ok())
                .map(|m| m.len() as i64)
                .sum::<i64>()
            + p.snap
                .as_ref()
                .and_then(|s| std::fs::metadata(s).ok())
                .map_or(0, |m| m.len() as i64);
        let up = self.upload_archive(b, &s.id, &p);
        discord_done(up.as_ref().err()); // the channel goes only once its archive is on the Storage Box
        let (size, took) = up?;
        info.bytes = size;
        info.upload_seconds = took.as_secs_f64();
        let mut entry: Map<String, Value> = json!({"id": s.id, "jarvis": 4, "title": title, "label": s.label,
            "archive": file, "bytes": size, "created": s.created, "destroyedAt": now, "transcripts": transcripts.len(),
            "artifacts": lay.artifacts, "last": info.last, "environment": stores.join(","), "repos": s.repos,
            "model": s.model, "size": s.size, "harness": s.harness, "permissionMode": s.permission_mode, "restored": []})
        .as_object()
        .cloned()
        .unwrap_or_default();
        if info.signer.is_empty() {
            entry.insert("noSnapshot".into(), json!(info.no_snapshot));
        }
        let sid = s.id.clone();
        update_index(b, |list| {
            std::iter::once(entry)
                .chain(list.into_iter().filter(|e| e.get("id").and_then(|v| v.as_str()) != Some(sid.as_str())))
                .collect()
        })
        .map_err(|e| anyhow!("indexing the archive: {e:#}"))?;
        crate::logf!(
            "session {}: archived to {file} ({} transcript(s), {} artifact file(s), {} in {:.1} s)",
            s.id,
            transcripts.len(),
            lay.artifacts,
            mb(size),
            took.as_secs_f64()
        );
        let _ = (RECORDS_ROOT, Doc::default);
        Ok(Some(info))
    }
}
