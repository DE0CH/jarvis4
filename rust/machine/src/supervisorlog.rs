//! The supervisor log: what boot and the supervisor do, one JSON line each ({"at","text"}) in supervisor.log (tmpfs,
//! this machine only). The boot steps, the keeper and the supervisors append to it (each write opens the file, so a
//! rotation never loses a line); supervisor-core pushes new lines to the router (POST /m/supervisor-log), which keeps
//! the session's log for its whole life and shows it in the app. The lines name commands, ids, counts, key names and
//! errors, never a command's text, a prompt or a secret value; as a second line of defence every value the supervisor
//! holds (8 characters or more) is replaced by [secret] before a line leaves.

use crate::client::Client;
use crate::session::{privileged, session};
use crate::{gojson, paths, util};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

/// rotate once everything is pushed and the file is this big
const SUPERVISOR_LOG_ROLL: u64 = 2 << 20;
const LOG_PUSH_EVERY: Duration = Duration::from_secs(2);
pub const MAX_LOG_LINE: usize = 2000;
const MAX_LOG_BATCH: usize = 500;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct LogLine {
    pub at: String,
    pub text: String,
}

/// one JSON line per write, tagged (the keeper's harness lines: "harness")
pub struct FileLog {
    tag: String,
}

impl FileLog {
    pub fn new(tag: &str) -> FileLog {
        FileLog { tag: tag.into() }
    }

    pub fn line(&self, text: &str) {
        append_line(&self.tag, text);
    }
}

impl Write for FileLog {
    fn write(&mut self, p: &[u8]) -> std::io::Result<usize> {
        let s = String::from_utf8_lossy(p);
        let s = s.strip_prefix("[jarvis] ").unwrap_or(&s);
        append_line(&self.tag, s.strip_suffix('\n').unwrap_or(s));
        Ok(p.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn append_line(tag: &str, text: &str) {
    let l = LogLine {
        at: jarvis_doc::now(),
        text: format!("{tag}: {text}"),
    };
    let p = paths::supervisor_log_path();
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(&p)
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(md) = f.metadata()
            && md.permissions().mode() & 0o777 != 0o600
            && md.len() == 0
        {
            let _ = f.set_permissions(std::fs::Permissions::from_mode(0o600));
        }
        if privileged() {
            // the keeper (root): the file stays user claude's, as the supervisor reads and rotates it
            let s = session();
            let _ = std::os::unix::fs::fchown(&f, Some(s.uid), Some(s.gid));
        }
        let _ = f.write_all(format!("{}\n", gojson::marshal(&l)).as_bytes());
    }
}

/// this process's tag in the supervisor log, once log_to_supervisor_log ran
static TAG: OnceLock<String> = OnceLock::new();

/// this process's log lines also go to the supervisor log
pub fn log_to_supervisor_log() {
    let args: Vec<String> = std::env::args().collect();
    let tag = match args.get(1).map(String::as_str) {
        Some("prepare") => "boot",
        Some("boot") => "keeper",
        Some("supervisor") if args.get(2).map(String::as_str) == Some("--normal") => {
            "supervisor-normal"
        }
        _ => "supervisor",
    };
    let _ = TAG.set(tag.to_string());
}

/// tests read the lines here
pub static TEST_LOG: Mutex<Option<Vec<String>>> = Mutex::new(None);

/// one log line: stderr, and the supervisor log when this process logs there (logf! calls it)
pub fn log_line(text: &str) {
    if let Ok(mut g) = TEST_LOG.lock()
        && let Some(v) = g.as_mut()
    {
        v.push(text.to_string());
    }
    eprintln!("[jarvis] {text}");
    if let Some(tag) = TAG.get() {
        append_line(tag, text);
    }
}

/// supervisor-core's push loop (supervisor-normal's lines are in the same file)
pub fn push_supervisor_log(c: &Client) {
    loop {
        let _ = push_log_once(c);
        util::sleep(LOG_PUSH_EVERY);
    }
}

static PUSH_MU: Mutex<()> = Mutex::new(());

/// everything not yet pushed, in batches; then the rotation when it is due
pub fn push_log_once(c: &Client) -> Result<()> {
    let _g = PUSH_MU.lock().unwrap_or_else(|e| e.into_inner());
    let p = paths::supervisor_log_path();
    let mut off = read_offset();
    let r = push_from(c, &p, off);
    off += r.as_ref().map(|n| *n).unwrap_or_else(|(n, _)| *n);
    write_offset(off);
    if let Err((_, e)) = r {
        return Err(e);
    }
    if let Ok(md) = std::fs::metadata(&p)
        && md.len() >= SUPERVISOR_LOG_ROLL
        && off >= md.len()
    {
        let old = std::path::PathBuf::from(format!("{}.old", p.display()));
        if std::fs::rename(&p, &old).is_ok() {
            util::sleep(Duration::from_millis(50)); // a write that opened the old file just before
            let _ = push_from(c, &old, off);
            let _ = std::fs::remove_file(&old);
            write_offset(0);
        }
    }
    Ok(())
}

fn read_offset() -> u64 {
    crate::crypto::read_trim(&paths::supervisor_log_sent())
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

fn write_offset(n: u64) {
    let _ = util::write_file(
        &paths::supervisor_log_sent(),
        n.to_string().as_bytes(),
        0o600,
    );
}

/// the complete lines of path after off, pushed to the supervisor log → the bytes pushed (with the error, the bytes
/// pushed before it)
fn push_from(c: &Client, path: &Path, off: u64) -> Result<u64, (u64, anyhow::Error)> {
    push_lines_from(c, path, off, "/m/supervisor-log", &serde_json::Map::new())
}

/// the complete {"at","text"} lines of path after off, pushed to endpoint in batches (body: extra and "lines")
pub fn push_lines_from(
    c: &Client,
    path: &Path,
    off: u64,
    endpoint: &str,
    extra: &serde_json::Map<String, serde_json::Value>,
) -> Result<u64, (u64, anyhow::Error)> {
    let Ok(mut f) = std::fs::File::open(path) else {
        return Ok(0);
    };
    if let Err(e) = f.seek(SeekFrom::Start(off)) {
        return Err((0, e.into()));
    }
    let mut rd = BufReader::with_capacity(64 << 10, f);
    let red = secret_redactor();
    let mut done: u64 = 0;
    loop {
        let mut batch: Vec<LogLine> = vec![];
        let mut size: u64 = 0;
        while batch.len() < MAX_LOG_BATCH {
            let mut b = vec![];
            match rd.read_until(b'\n', &mut b) {
                Ok(_) if b.last() == Some(&b'\n') => {}
                // an unfinished last line waits for the next round (the offset says where to start again)
                _ => break,
            }
            size += b.len() as u64;
            let Ok(mut l) =
                gojson::unmarshal::<LogLine>(String::from_utf8_lossy(&b).trim().as_bytes())
            else {
                continue;
            };
            l.text = red(&l.text);
            if l.text.len() > MAX_LOG_LINE {
                l.text = format!("{}…", util::clip_bytes(&l.text, MAX_LOG_LINE - 3));
            }
            batch.push(l);
        }
        if size == 0 {
            return Ok(done);
        }
        if !batch.is_empty() {
            let mut body = extra.clone();
            body.insert(
                "lines".into(),
                serde_json::to_value(&batch).unwrap_or_default(),
            );
            let r = c.raw("POST", endpoint, gojson::marshal(&body).as_bytes(), &[]);
            match r {
                Err(e) => return Err((done, e)),
                Ok(r) if r.status == 404 || r.status == 405 => {
                    // a router without this endpoint: try again later
                    util::sleep(Duration::from_secs(60));
                    return Ok(done);
                }
                Ok(r) if r.status != 200 => {
                    return Err((done, anyhow::anyhow!("HTTP {}", r.status)));
                }
                Ok(_) => {}
            }
        }
        done += size;
    }
}

/// replaces every value the supervisor holds (secrets.rs) of 8 characters or more
pub fn secret_redactor() -> impl Fn(&str) -> String {
    let mut vals: Vec<String> = vec![];
    for v in crate::secrets::HELD.snapshot().values() {
        if v.len() >= 8 {
            vals.push(v.clone());
        }
        for l in v.split('\n') {
            // a multi-line value's lines on their own (a PEM in an error)
            let l = l.trim();
            if l.len() >= 16 && l != v {
                vals.push(l.to_string());
            }
        }
    }
    move |s: &str| {
        let mut s = s.to_string();
        for v in &vals {
            if s.contains(v.as_str()) {
                s = s.replace(v.as_str(), "[secret]");
            }
        }
        s
    }
}
