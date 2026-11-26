//! Live transcript sync: every liveSyncSeconds (default 300) each conversation transcript under ~/.claude/projects that
//! changed since its last copy goes to the router (POST /m/live-transcript, X-Name = its file name, the whole file),
//! which puts it at claude-records/.live/<session id>/ for transcript search (router/livesync.go); the "live-sync" command
//! runs a round at once and then says so (POST /m/live-synced: a session's tail, now, router/livetail.go), and the
//! final snapshot sends a round first. The machine holds no
//! Storage Box credentials. Jarvis's peer-message relays ("You are a delivery relay…") are plumbing and are skipped.

use crate::client::Client;
use crate::{gojson, logf, paths, util};
use anyhow::{Result, bail};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

/// the router refuses more
const LIVE_SYNC_MAX_BYTES: u64 = 256 << 20;

#[cfg(test)]
pub type SendFnPub = SendFn;
type SendFn = Box<dyn Fn(&str, &[u8]) -> Result<()> + Send + Sync>;

pub struct LiveSyncer {
    /// file → the modification time last sent (RFC 3339 with nanoseconds, as Go wrote it)
    sent: Mutex<BTreeMap<String, String>>,
    send: Mutex<SendFn>,
    /// where sent is kept (None = memory only)
    state: Option<PathBuf>,
}

static LIVE: Mutex<Option<Arc<LiveSyncer>>> = Mutex::new(None);

#[cfg(test)]
/// tests: the next live_syncer_for makes a new one
pub fn reset_live_syncer() {
    *LIVE.lock().unwrap_or_else(|e| e.into_inner()) = None;
}

fn mtime_text(t: SystemTime) -> String {
    let d = t.duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default();
    let odt = time::OffsetDateTime::from_unix_timestamp_nanos(d.as_nanos() as i128)
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    jarvis_doc::rfc3339_nano(odt)
}

fn parse(s: &str) -> Option<time::OffsetDateTime> {
    time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).ok()
}

/// this process's syncer, sending through c
pub fn live_syncer_for(c: &Client) -> Arc<LiveSyncer> {
    let mut g = LIVE.lock().unwrap_or_else(|e| e.into_inner());
    g.get_or_insert_with(|| {
        let c = c.clone();
        let sent = std::fs::read(paths::live_sent_path())
            .ok()
            .and_then(|b| gojson::unmarshal(&b).ok())
            .unwrap_or_default();
        Arc::new(LiveSyncer::new(
            Box::new(move |name, body| {
                let r = c.raw("POST", "/m/live-transcript", body, &[("X-Name", name)])?;
                if r.status != 200 {
                    let t = String::from_utf8_lossy(&r.body[..r.body.len().min(200)])
                        .trim()
                        .to_string();
                    bail!("HTTP {} {t}", r.status);
                }
                Ok(())
            }),
            Some(paths::live_sent_path()),
            sent,
        ))
    })
    .clone()
}

fn glob(pattern_dir: &Path, depth_pattern: &[&str]) -> Vec<PathBuf> {
    // the two fixed shapes below: projects/*/*.jsonl and projects/*/*/subagents/*.jsonl
    let mut cur = vec![pattern_dir.to_path_buf()];
    for (i, part) in depth_pattern.iter().enumerate() {
        let last = i == depth_pattern.len() - 1;
        let mut next = vec![];
        for d in &cur {
            if *part == "*" || part.starts_with("*.") {
                let ext = part.strip_prefix("*.");
                for e in std::fs::read_dir(d).into_iter().flatten().flatten() {
                    let p = e.path();
                    match ext {
                        Some(x) if last => {
                            if p.extension().is_some_and(|y| y == x) {
                                next.push(p);
                            }
                        }
                        _ => {
                            if !last || p.exists() {
                                next.push(p);
                            }
                        }
                    }
                }
            } else {
                next.push(d.join(part));
            }
        }
        cur = next;
    }
    cur.sort();
    cur
}

/// the conversations' files
pub fn main_transcripts() -> Vec<PathBuf> {
    glob(
        &paths::claude_home().join(".claude/projects"),
        &["*", "*.jsonl"],
    )
}

/// their subagents' (<conversation>/subagents/)
pub fn subagent_transcripts() -> Vec<PathBuf> {
    glob(
        &paths::claude_home().join(".claude/projects"),
        &["*", "*", "subagents", "*.jsonl"],
    )
}

pub fn live_sync_interval() -> Duration {
    let n = crate::vouch::read_vouched_int("liveSyncSeconds"); // a format exception from /m/config
    if n >= 5 {
        return Duration::from_secs(n as u64);
    }
    Duration::from_secs(300)
}

impl LiveSyncer {
    pub fn new(send: SendFn, state: Option<PathBuf>, sent: BTreeMap<String, String>) -> LiveSyncer {
        LiveSyncer {
            sent: Mutex::new(sent),
            send: Mutex::new(send),
            state,
        }
    }

    /// tests: another way to send
    #[cfg(test)]
    pub fn set_send(&self, f: SendFn) {
        if let Ok(mut g) = self.send.lock() {
            *g = f;
        }
    }

    /// one pass over the conversations' transcripts; the number sent
    pub fn once(&self) -> usize {
        self.pass(&main_transcripts())
    }

    /// each of files that changed since its last copy, the newest first; the number sent
    pub fn pass(&self, files: &[PathBuf]) -> usize {
        let mut sent = self.sent.lock().unwrap_or_else(|e| e.into_inner());
        // supervisor-normal's rounds and supervisor-core's (a live-sync command, the teardown) share the state file:
        // what the other process sent since is not sent again
        if let Some(st) = &self.state
            && let Ok(b) = std::fs::read(st)
            && let Ok(theirs) = gojson::unmarshal::<BTreeMap<String, String>>(&b)
        {
            for (k, v) in theirs {
                let newer = match (sent.get(&k).and_then(|p| parse(p)), parse(&v)) {
                    (Some(p), Some(t)) => t > p,
                    (None, Some(_)) => true,
                    _ => false,
                };
                if newer {
                    sent.insert(k, v);
                }
            }
        }
        let mut cs: Vec<(PathBuf, std::fs::Metadata, SystemTime)> = files
            .iter()
            .filter_map(|f| {
                let md = std::fs::metadata(f).ok()?;
                let t = md.modified().ok()?;
                md.is_file().then(|| (f.clone(), md, t))
            })
            .collect();
        cs.sort_by_key(|x| std::cmp::Reverse(x.2));
        let mut n = 0;
        for (f, md, t) in cs {
            let key = f.to_string_lossy().into_owned();
            let tt = mtime_text(t);
            if let Some(prev) = sent.get(&key)
                && let (Some(p), Some(now)) = (parse(prev), parse(&tt))
                && now <= p
            {
                continue;
            }
            let base = f
                .file_name()
                .map(|x| x.to_string_lossy().into_owned())
                .unwrap_or_default();
            if md.len() > LIVE_SYNC_MAX_BYTES {
                sent.insert(key, tt);
                logf!(
                    "live sync: {base} is {} bytes, over the limit; not sent",
                    md.len()
                );
                continue;
            }
            let Ok(body) = std::fs::read(&f) else {
                continue;
            };
            let head = &body[..body.len().min(4000)];
            if head.windows(24).any(|w| w == b"You are a delivery relay") {
                sent.insert(key, tt);
                continue;
            }
            let r = match self.send.lock() {
                Ok(f) => f(&base, &body),
                Err(_) => Err(anyhow::anyhow!("the sender is gone")),
            };
            if let Err(e) = r {
                logf!("live sync: {base}: {e:#}");
                continue; // tried again next pass
            }
            sent.insert(key, tt);
            n += 1;
        }
        if let Some(st) = &self.state
            && let Err(e) = crate::claudelogin::write_atomic(st, gojson::marshal(&*sent).as_bytes())
        {
            logf!("live sync: {e:#}");
        }
        n
    }
}

/// the "live-sync" command (router/livetail.go): a round now, then POST /m/live-synced, which the router's tail waits for
pub fn live_round(c: &Client) {
    let n = live_syncer_for(c).once();
    match c.raw("POST", "/m/live-synced", b"{}", &[]) {
        Ok(r) if r.status == 200 => logf!("live sync asked for: {n} changed transcripts sent"),
        Ok(r) => logf!("live sync asked for: /m/live-synced HTTP {}", r.status),
        Err(e) => logf!("live sync asked for: /m/live-synced: {e:#}"),
    }
}

/// supervisor-normal's live transcript sync (started once booted)
pub fn live_sync(c: &Client) {
    let l = live_syncer_for(c);
    let every = live_sync_interval();
    loop {
        util::sleep(every);
        l.once();
    }
}
