//! The snapshot (main.go's snapshot half): what it holds and in which order, writing it (a compressed tar of paths
//! under $HOME), unpacking one, the machine's one signed final snapshot, and its progress (snapprogress.go).
//!
//! The snapshot is this machine's LAST state (R1 audit, 2026-10-11): the router asks for one only to pause or destroy
//! the machine, and the core fixes the snapshot its kill names as what the successor restores. So the machine signs
//! exactly one in its life: before taking it, it stops every process of the session (SIGSTOP), so nothing changes after
//! it, and a later snapshot command gets that same one again.

use crate::client::Client;
use crate::crypto::{load_private, read_trim, verify};
use crate::grants::ALLOW_FILE;
use crate::restore::CHANGES_FILE;
use crate::snapformat::{SnapWriter, open_snap_reader};
use crate::vouch::Vouched;
use crate::{deliver, logf, on_fabric, paths, util};
use anyhow::{Result, anyhow, bail};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// What a snapshot holds (relative to $HOME): the conversation, the work, the artefacts, and the other harnesses' own
/// state, in the order of what matters most (Deyao, 2026-10-21: the teardown uploads the most important first): the
/// conversations and ~/.claude.json, the small records, the other harnesses' state, then the workspace and the
/// artifacts last.
pub const SNAPSHOT_PATHS: &[&str] = &[
    ".claude/projects",
    ".claude.json",
    ".claude/.first-prompt-sent",
    ".claude/.paseo-agent",
    ALLOW_FILE,
    CHANGES_FILE,
    deliver::LINE_KEYS_FILE,
    deliver::DELIVERED_FILE,
    ".paseo",
    ".local/share/opencode",
    ".openclaw",
    ".dsh",
    ".claude/.dsh-session",
    "workspace",
    "artifacts",
];

/// which of SNAPSHOT_PATHS are single files, not directories: the volume mirrors them instead of bind-mounting them
pub fn snapshot_file(rel: &str) -> bool {
    matches!(
        rel,
        ".claude.json"
            | ".claude/.first-prompt-sent"
            | ".claude/.paseo-agent"
            | ".claude/.dsh-session"
    ) || rel == ALLOW_FILE
        || rel == CHANGES_FILE
        || rel == deliver::LINE_KEYS_FILE
        || rel == deliver::DELIVERED_FILE
}

/// what the snapshot leaves out under those roots (a glob against the path relative to $HOME): the harnesses' logs,
/// pid files, caches and downloaded binaries, which a successor rebuilds
const SNAPSHOT_SKIP: &[&str] = &[
    ".paseo/models",
    ".paseo/runtime",
    ".paseo/paseo.pid",
    ".paseo/*.log",
    ".paseo/*.out",
    ".paseo/*.err",
    ".local/share/opencode/log",
    ".local/share/opencode/bin",
    ".openclaw/logs",
    ".openclaw/tmp",
    ".openclaw/*.out",
    ".openclaw/*.err",
    ".openclaw/.hold",
    ".openclaw/gateway.pid",
    ".dsh/profiles/*/node_modules",
    ".dsh/*.lock",
];

/// Go's filepath.Match for the patterns above (`*` matches within one path segment)
pub fn glob_match(pat: &str, name: &str) -> bool {
    let (p, n): (Vec<&str>, Vec<&str>) = (pat.split('/').collect(), name.split('/').collect());
    p.len() == n.len()
        && p.iter()
            .zip(n.iter())
            .all(|(a, b)| seg_match(a.as_bytes(), b.as_bytes()))
}

fn seg_match(p: &[u8], n: &[u8]) -> bool {
    match (p.first(), n.first()) {
        (None, None) => true,
        (Some(b'*'), _) => seg_match(&p[1..], n) || (!n.is_empty() && seg_match(p, &n[1..])),
        (Some(b'?'), Some(_)) => seg_match(&p[1..], &n[1..]),
        (Some(a), Some(b)) if a == b => seg_match(&p[1..], &n[1..]),
        _ => false,
    }
}

pub fn skip_in_snapshot(rel: &str) -> bool {
    SNAPSHOT_SKIP.iter().any(|p| glob_match(p, rel))
}

/// the router asked for the whole state (snapshot-full: a destroy, so no next machine finds the files on the fabric's
/// disk)
pub static FULL_SNAPSHOT: AtomicBool = AtomicBool::new(false);

/// What a fabric machine's snapshot holds: the small files, the Jarvis records among them. The directories stay on the
/// fabric's network filesystem, where the next machine of the session finds them; the records travel signed.
pub fn fabric_state_paths() -> Vec<&'static str> {
    SNAPSHOT_PATHS
        .iter()
        .copied()
        .filter(|r| snapshot_file(r))
        .collect()
}

/// what this machine's snapshot holds, in SNAPSHOT_PATHS' order
pub fn state_paths() -> Vec<&'static str> {
    if on_fabric() && !FULL_SNAPSHOT.load(Ordering::SeqCst) {
        return fabric_state_paths();
    }
    SNAPSHOT_PATHS.to_vec()
}

/// Go's filepath.Walk order: lexical within each directory, symlinks not followed; `f` gets each path and its lstat;
/// returning false from `f` for a directory skips it
fn walk(p: &Path, f: &mut dyn FnMut(&Path, &std::fs::Metadata) -> Result<bool>) -> Result<()> {
    let Ok(md) = std::fs::symlink_metadata(p) else {
        return Ok(());
    };
    let descend = f(p, &md)?;
    if md.is_dir() && descend {
        let Ok(rd) = std::fs::read_dir(p) else {
            return Ok(());
        };
        let mut names: Vec<PathBuf> = rd.flatten().map(|e| e.path()).collect();
        names.sort();
        for n in names {
            walk(&n, f)?;
        }
    }
    Ok(())
}

fn rel_of(home: &Path, p: &Path) -> String {
    p.strip_prefix(home)
        .map(|r| r.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// The snapshot as a compressed tar (snapformat.rs) into w → its sha256 and size
pub fn write_snapshot<W: Write>(w: W) -> Result<(String, u64)> {
    let home = paths::home();
    let prog = current_progress();
    let mut cw = CountWriter {
        w,
        h: Sha256::new(),
        n: 0,
        prog: prog.clone(),
    };
    {
        let gz = SnapWriter::new(&mut cw);
        let mut tw = tar::Builder::new(gz);
        tw.mode(tar::HeaderMode::Complete);
        tw.follow_symlinks(false);
        for rel in state_paths() {
            let root = home.join(rel);
            if std::fs::symlink_metadata(&root).is_err() {
                continue;
            }
            walk(&root, &mut |p, md| {
                let name = rel_of(&home, p);
                if skip_in_snapshot(&name) {
                    return Ok(false);
                }
                add_entry(&mut tw, p, &name, md, prog.as_deref())?;
                Ok(true)
            })?;
            // each root in blocks of its own: the conversations and records go out whole before the workspace starts
            tw.get_mut().flush()?;
        }
        tw.finish()?;
        let gz = tw.into_inner()?;
        gz.finish()?;
    }
    cw.w.flush()?;
    Ok((hex::encode(cw.h.finalize()), cw.n))
}

fn add_entry<W: Write>(
    tw: &mut tar::Builder<W>,
    p: &Path,
    name: &str,
    md: &std::fs::Metadata,
    prog: Option<&Progress>,
) -> Result<()> {
    let mut h = tar::Header::new_gnu();
    h.set_metadata_in_mode(md, tar::HeaderMode::Complete);
    let ft = md.file_type();
    if ft.is_symlink() {
        let link = std::fs::read_link(p).unwrap_or_default();
        h.set_entry_type(tar::EntryType::Symlink);
        h.set_size(0);
        tw.append_link(&mut h, name, link)?;
        return Ok(());
    }
    if ft.is_dir() {
        h.set_entry_type(tar::EntryType::Directory);
        h.set_size(0);
        tw.append_data(&mut h, format!("{name}/"), std::io::empty())?;
        return Ok(());
    }
    if !ft.is_file() {
        return Ok(()); // sockets, fifos, devices: Go's FileInfoHeader wrote a header with no data; nothing to restore
    }
    let Ok(f) = std::fs::File::open(p) else {
        return Ok(());
    };
    let size = md.len();
    h.set_size(size);
    // a file that shrank while being read would break the archive: pad to the header's size
    let src = CountReader { r: f, prog };
    let r = src.take(size).chain(std::io::repeat(0)).take(size);
    tw.append_data(
        &mut h,
        name,
        std::io::BufReader::with_capacity(256 << 10, r),
    )?;
    Ok(())
}

struct CountWriter<W: Write> {
    w: W,
    h: Sha256,
    n: u64,
    prog: Option<Arc<Progress>>,
}

impl<W: Write> Write for CountWriter<W> {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        let n = self.w.write(b)?;
        self.h.update(&b[..n]);
        self.n += n as u64;
        if let Some(p) = &self.prog {
            p.sent.store(self.n as i64, Ordering::Relaxed);
        }
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.w.flush()
    }
}

struct CountReader<'a, R: Read> {
    r: R,
    prog: Option<&'a Progress>,
}

impl<R: Read> Read for CountReader<'_, R> {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        let n = self.r.read(b)?;
        if let Some(p) = self.prog {
            p.done.fetch_add(n as i64, Ordering::Relaxed);
        }
        Ok(n)
    }
}

/// the snapshot written to path (streamed: a workspace can be several GB) → its sha256 and size
pub fn make_snapshot(path: &Path) -> Result<(String, u64)> {
    let f = util::create_file(path, 0o600)?;
    let mut bw = std::io::BufWriter::with_capacity(1 << 20, f);
    let r = write_snapshot(&mut bw)?;
    let f = bw.into_inner().map_err(|e| anyhow!("{e}"))?;
    f.sync_all()?;
    Ok(r)
}

/// the predecessor's snapshot. The cert names its hash (the core took it from the predecessor's signed kill): exactly
/// that one, or nothing starts.
pub fn restore(c: &Client, pred_signing_key: &str, v: &Vouched) -> Result<()> {
    let tmp = paths::predecessor_tmp();
    let r = (|| {
        let (sum, sig) = crate::snapdirect::fetch_snapshot(c, &tmp)?;
        if sum != v.cert.snapshot {
            bail!("the snapshot isn't the one the cert names");
        }
        if !verify(pred_signing_key, sum.as_bytes(), &sig) {
            bail!("the snapshot isn't signed by the predecessor");
        }
        let n = unpack_file(&tmp)?;
        logf!("restored the predecessor's snapshot ({n} files)");
        Ok(())
    })();
    let _ = std::fs::remove_file(&tmp);
    r
}

/// a downloaded snapshot unpacked, its progress in the log
pub fn unpack_file(p: &Path) -> Result<usize> {
    let f = std::fs::File::open(p)?;
    let prog = crate::snapdirect::RestoreLog::start("unpacking", 0);
    let r = unpack_with(f, Some(&prog.done));
    prog.stop();
    r
}

/// a snapshot's files into $HOME
pub fn unpack_reader<R: Read>(r: R) -> Result<usize> {
    unpack_with(r, None)
}

/// unpack_reader, counting the uncompressed bytes into done
pub fn unpack_with<R: Read>(r: R, done: Option<&AtomicI64>) -> Result<usize> {
    let home = paths::home();
    let zr = open_snap_reader(r)?;
    let mut ar = tar::Archive::new(zr);
    let mut dirs = std::collections::HashSet::new();
    let mut n = 0;
    let mut buf = vec![0u8; 1 << 20];
    for e in ar.entries()? {
        let mut e = e?;
        let hname = e.path_bytes();
        let hname = String::from_utf8_lossy(&hname).into_owned();
        let name = clean(&hname);
        if name.starts_with('/') || name.starts_with("..") {
            bail!("bad path in snapshot: {hname}");
        }
        let dst = home.join(&name);
        let mode = e.header().mode().unwrap_or(0o644);
        match e.header().entry_type() {
            tar::EntryType::Directory => {
                let _ = mkdir_all(&dst, (mode & 0o7777) | 0o700);
            }
            tar::EntryType::Symlink => {
                if let Some(parent) = dst.parent() {
                    let _ = mkdir_all(parent, 0o755);
                }
                let _ = std::fs::remove_file(&dst);
                if let Ok(Some(l)) = e.link_name() {
                    let _ = std::os::unix::fs::symlink(l, &dst);
                }
            }
            tar::EntryType::Regular | tar::EntryType::Continuous => {
                if let Some(d) = dst.parent()
                    && dirs.insert(d.to_path_buf())
                {
                    let _ = mkdir_all(d, 0o755);
                }
                let mut f = util::create_file(&dst, mode & 0o777)?;
                let size = e.header().size().unwrap_or(0);
                loop {
                    let k = e.read(&mut buf)?;
                    if k == 0 {
                        break;
                    }
                    f.write_all(&buf[..k])?;
                }
                drop(f);
                if let Ok(mt) = e.header().mtime() {
                    // git's index keeps trusting unchanged files
                    let t = std::time::UNIX_EPOCH + Duration::from_secs(mt);
                    if let Ok(f) = std::fs::File::options().write(true).open(&dst) {
                        let _ =
                            f.set_times(std::fs::FileTimes::new().set_accessed(t).set_modified(t));
                    }
                }
                if let Some(d) = done {
                    d.fetch_add(size as i64, Ordering::Relaxed);
                }
                n += 1;
            }
            _ => {}
        }
    }
    Ok(n)
}

/// Go's os.MkdirAll with a mode
fn mkdir_all(p: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(mode)
        .create(p)
}

/// Go's filepath.Clean
pub fn clean(p: &str) -> String {
    let abs = p.starts_with('/');
    let mut out: Vec<&str> = vec![];
    for seg in p.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                if out.last().is_some_and(|l| *l != "..") {
                    out.pop();
                } else if !abs {
                    out.push("..");
                }
            }
            s => out.push(s),
        }
    }
    let s = out.join("/");
    match (abs, s.is_empty()) {
        (true, _) => format!("/{s}"),
        (false, true) => ".".into(),
        (false, false) => s,
    }
}

// ---- the snapshot (the supervisor's snapshot command: pause or destroy) ---------------------------------------------

/// tests set it
pub static TEST_BOOTED: Mutex<Option<bool>> = Mutex::new(None);

pub fn booted() -> bool {
    if let Some(b) = TEST_BOOTED.lock().ok().and_then(|g| *g) {
        return b;
    }
    paths::booted_path().exists()
}

/// the answer to a snapshot command while booting: nothing to snapshot, so the router kills at once
pub fn no_snapshot(c: &Client) -> Result<()> {
    let r = c.raw(
        "POST",
        "/m/snapshot",
        b"",
        &[("X-Snapshot-None", "booting")],
    )?;
    if r.status != 200 {
        bail!("HTTP {}", r.status);
    }
    logf!("snapshot asked while booting: answered nothing to snapshot");
    Ok(())
}

/// the session is stopped for its final snapshot: no execs, no deliveries
pub static FROZEN: AtomicBool = AtomicBool::new(false);

pub fn not_frozen() -> Result<()> {
    if FROZEN.load(Ordering::SeqCst) {
        bail!("the session is stopped for its final snapshot");
    }
    Ok(())
}

/// the machine's current signing key (re-read: a downgrade changes it under the supervisor)
pub fn snapshot_key() -> Result<jarvis_sig::Signer> {
    Ok(load_private()?.sig)
}

fn sig_sum_path() -> PathBuf {
    PathBuf::from(format!("{}.sha256", paths::final_snapshot_sig().display()))
}

/// the kept final snapshot's sha256 and signature
pub fn final_snapshot_sum() -> Result<(String, String)> {
    let sig = read_trim(&paths::final_snapshot_sig())?;
    let sum = read_trim(&sig_sum_path())?;
    Ok((sum, sig))
}

/// keep the signed sum and signature (best effort: a full disk can't stop the snapshot)
pub fn keep_signed(sum: &str, sig: &str) -> Result<()> {
    util::write_file(&sig_sum_path(), sum.as_bytes(), 0o600)?;
    util::write_file(&paths::final_snapshot_sig(), sig.as_bytes(), 0o600)?;
    Ok(())
}

/// the snapshot through a local file (a router from before snapshot streaming)
pub fn upload_snapshot_file(c: &Client) -> Result<()> {
    let (sum, sig) = match final_snapshot_sum() {
        Ok(x) => x,
        Err(_) => {
            // the first: freeze, take, sign, keep
            FROZEN.store(true, Ordering::SeqCst);
            crate::supervisor::freeze_session();
            crate::restore::write_changes(); // the repos' state, for the router's uncommitted-work check
            let prog = start_progress(c);
            prog.set_phase("writing");
            let r = make_snapshot(&paths::final_snapshot());
            prog.end(r.as_ref().err());
            let (sum, _) = r?;
            let sig = snapshot_key()?.sign(sum.as_bytes());
            keep_signed(&sum, &sig)?;
            (sum, sig)
        }
    };
    let (status, n) = c.upload(
        "/m/snapshot",
        &paths::final_snapshot(),
        &sum,
        &[("X-Snapshot-Sig", &sig)],
    )?;
    if status != 200 {
        bail!("HTTP {status}");
    }
    logf!("snapshot uploaded ({n} bytes)");
    Ok(())
}

// ---- progress (snapprogress.go) ------------------------------------------------------------------------------------
//
// Before streaming it, the supervisor measures what the snapshot holds (the same walk, sizes only: "measuring"), then
// counts the bytes read into the tar as it goes. Every 3 s it reports the numbers to the router (POST
// /m/snapshot-progress), which shows them as the session's status line; every 10 s it writes a line into its own log.
// A router without the route (404) or a failed report never holds the snapshot up.

const PROGRESS_POST_EVERY: Duration = Duration::from_secs(3);
pub const PROGRESS_LOG_EVERY: Duration = Duration::from_secs(10);

type Report = Box<dyn Fn(&serde_json::Value) -> Result<()> + Send + Sync>;
type Logf = Box<dyn Fn(&str) + Send + Sync>;

/// the running snapshot's numbers (all bytes: done/total uncompressed file bytes, sent the compressed bytes)
pub struct Progress {
    phase: Mutex<String>,
    pub done: AtomicI64,
    pub total: AtomicI64,
    pub sent: AtomicI64,
    /// unix ms the phase began
    started: AtomicI64,
    stop: AtomicBool,
    report: Report,
    logf: Logf,
    tick: Mutex<(Option<Instant>, Option<Instant>, bool)>, // last log, last post, report off
    ticker: Mutex<Option<std::thread::JoinHandle<()>>>,
}

static CUR_PROGRESS: Mutex<Option<Arc<Progress>>> = Mutex::new(None);

fn current_progress() -> Option<Arc<Progress>> {
    CUR_PROGRESS.lock().ok().and_then(|g| g.clone())
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

pub fn gb(n: i64) -> String {
    format!("{:.2} GB", n as f64 / 1e9)
}

impl Progress {
    pub fn new(report: Report, logf: Logf) -> Arc<Progress> {
        Arc::new(Progress {
            phase: Mutex::new(String::new()),
            done: AtomicI64::new(0),
            total: AtomicI64::new(0),
            sent: AtomicI64::new(0),
            started: AtomicI64::new(0),
            stop: AtomicBool::new(false),
            report,
            logf,
            tick: Mutex::new((None, None, false)),
            ticker: Mutex::new(None),
        })
    }

    pub fn set_phase(&self, phase: &str) {
        if let Ok(mut p) = self.phase.lock() {
            *p = phase.to_string();
        }
        self.started.store(now_ms(), Ordering::SeqCst);
    }

    fn phase(&self) -> String {
        self.phase.lock().map(|p| p.clone()).unwrap_or_default()
    }

    pub fn numbers(&self) -> serde_json::Value {
        serde_json::json!({"phase": self.phase(), "done": self.done.load(Ordering::Relaxed), "total": self.total.load(Ordering::Relaxed),
            "sent": self.sent.load(Ordering::Relaxed), "elapsedMs": (now_ms() - self.started.load(Ordering::Relaxed)).max(0)})
    }

    /// the log line ("snapshot: uploading 1.2/3.4 GB (35%), 0.6 GB sent, 40 MB/s, 55 s left")
    pub fn line(&self) -> String {
        let ph = self.phase();
        let (done, mut total, sent) = (
            self.done.load(Ordering::Relaxed),
            self.total.load(Ordering::Relaxed),
            self.sent.load(Ordering::Relaxed),
        );
        if ph == "measuring" {
            return format!("snapshot: measuring, {} so far", gb(total));
        }
        total = total.max(done);
        let mut s = format!("snapshot: {ph} {}/{}", gb(done), gb(total));
        if total > 0 {
            s += &format!(" ({}%)", done * 100 / total);
        }
        s += &format!(", {} compressed sent", gb(sent));
        let el = (now_ms() - self.started.load(Ordering::Relaxed)) as f64 / 1000.0;
        if el >= 1.0 && done > 0 {
            let rate = done as f64 / el;
            s += &format!(", {:.0} MB/s", rate / 1e6);
            if total > done {
                s += &format!(", {:.0} s left", (total - done) as f64 / rate);
            }
        }
        s
    }

    /// post and log when their time has come (force: both now)
    pub fn tick(&self, force: bool) {
        let mut t = self.tick.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        if !t.2 && (force || t.1.is_none_or(|l| now - l >= PROGRESS_POST_EVERY)) {
            t.1 = Some(now);
            if let Err(e) = (self.report)(&self.numbers()) {
                t.2 = true; // an older router, or none: the log still has it
                (self.logf)(&format!(
                    "snapshot progress: not reported to the router ({e:#}); only logged"
                ));
            }
        }
        if force || t.0.is_none_or(|l| now - l >= PROGRESS_LOG_EVERY) {
            t.0 = Some(now);
            (self.logf)(&self.line());
        }
    }

    /// the last numbers, logged (and reported), then the reporter stops
    pub fn end(self: &Arc<Self>, err: Option<&anyhow::Error>) {
        if let Ok(mut g) = CUR_PROGRESS.lock()
            && g.as_ref().is_some_and(|p| Arc::ptr_eq(p, self))
        {
            *g = None;
        }
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.ticker.lock().ok().and_then(|mut g| g.take()) {
            let _ = h.join();
        }
        if let Some(e) = err {
            (self.logf)(&format!("{}; failed: {e:#}", self.line()));
            return;
        }
        let el = (now_ms() - self.started.load(Ordering::Relaxed)) as f64 / 1000.0;
        (self.logf)(&format!(
            "snapshot: {} done, {} read, {} compressed in {el:.0} s",
            self.phase(),
            gb(self.done.load(Ordering::Relaxed)),
            gb(self.sent.load(Ordering::Relaxed))
        ));
    }
}

/// measure, then report until stopped. The caller sets the phase it counts and calls end.
pub fn start_progress(c: &Client) -> Arc<Progress> {
    let c = c.clone();
    let p = Progress::new(
        Box::new(move |m| c.json_ok("POST", "/m/snapshot-progress", Some(m))),
        Box::new(|s| logf!("{s}")),
    );
    begin_progress(p)
}

pub fn begin_progress(p: Arc<Progress>) -> Arc<Progress> {
    p.set_phase("measuring");
    if let Ok(mut t) = p.tick.lock() {
        *t = (Some(Instant::now()), Some(Instant::now()), false);
    }
    let q = p.clone();
    let h = std::thread::spawn(move || {
        while !q.stop.load(Ordering::SeqCst) {
            util::sleep(Duration::from_secs(1));
            if !q.stop.load(Ordering::SeqCst) {
                q.tick(false);
            }
        }
    });
    if let Ok(mut g) = p.ticker.lock() {
        *g = Some(h);
    }
    measure_snapshot(&p.total);
    p.tick(true);
    if let Ok(mut g) = CUR_PROGRESS.lock() {
        *g = Some(p.clone());
    }
    p
}

/// the bytes of the regular files write_snapshot will read (the same walk, sizes only), counted into n as it goes
pub fn measure_snapshot(n: &AtomicI64) {
    let home = paths::home();
    for rel in state_paths() {
        let root = home.join(rel);
        let _ = walk(&root, &mut |p, md| {
            if skip_in_snapshot(&rel_of(&home, p)) {
                return Ok(false);
            }
            if md.file_type().is_file() {
                n.fetch_add(md.len() as i64, Ordering::Relaxed);
            }
            Ok(true)
        });
    }
}
