//! Transcript rollback (Jarvis 1's restart {rollback: {dropFromMarker}}). The router can't edit a snapshot: it is signed
//! by the machine that took it, and this machine checks that signature. A rollback is a one-time input of the
//! successor's cert (Options.Once "rollback", approved on the phone; vouch.rs), and this machine applies it AFTER it has
//! verified and unpacked the snapshot: in every conversation transcript (~/.claude/projects/<dir>/<id>.jsonl), the first
//! line containing the marker and everything after it are dropped.

use crate::{logf, paths, util};
use anyhow::{Result, bail};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RollbackResult {
    pub name: String,
    pub before: usize,
    pub after: usize,
    pub dropped: usize,
}

/// called by prepare once the predecessor's snapshot is restored, with the marker from the cert's one-time inputs
pub fn apply_rollback(marker: &str) {
    if marker.is_empty() {
        return;
    }
    let (res, err) = rollback_transcripts(&paths::home(), marker);
    if let Some(e) = err {
        logf!("rollback: {e:#}");
    }
    for r in res.iter().filter(|r| r.dropped > 0) {
        logf!("rollback: {}: {} → {} lines", r.name, r.before, r.after);
    }
}

/// the conversation transcripts directly under ~/.claude/projects/<dir>/ (not subagents')
pub fn rollback_transcripts(
    home: &Path,
    marker: &str,
) -> (Vec<RollbackResult>, Option<anyhow::Error>) {
    let mut out = vec![];
    let r = (|| -> Result<()> {
        if marker.len() < 4 {
            bail!("marker too short");
        }
        let mut files = vec![];
        for d in std::fs::read_dir(home.join(".claude").join("projects"))
            .into_iter()
            .flatten()
            .flatten()
        {
            for f in std::fs::read_dir(d.path()).into_iter().flatten().flatten() {
                if f.path().extension().is_some_and(|x| x == "jsonl") {
                    files.push(f.path());
                }
            }
        }
        files.sort();
        for p in files {
            let Ok(md) = std::fs::symlink_metadata(&p) else {
                continue;
            };
            if !md.is_file() {
                continue;
            }
            let body = std::fs::read(&p)?;
            let (kept, before, after, cut) = truncate_at_marker(&body, marker);
            let rel = p
                .strip_prefix(home)
                .map(|r| r.to_string_lossy().into_owned())
                .unwrap_or_default();
            out.push(RollbackResult {
                name: rel,
                before,
                after,
                dropped: before - after,
            });
            if !cut {
                continue;
            }
            let tmp = std::path::PathBuf::from(format!("{}.rollback", p.display()));
            util::write_file(&tmp, &kept, md.permissions().mode() & 0o777)?;
            std::fs::rename(&tmp, &p)?;
        }
        Ok(())
    })();
    (out, r.err())
}

/// Jarvis 1's rule: the lines before the first one containing the marker, newline-ended → (kept, before, after, cut)
pub fn truncate_at_marker(body: &[u8], marker: &str) -> (Vec<u8>, usize, usize, bool) {
    let s = String::from_utf8_lossy(body);
    let lines: Vec<&str> = s.split('\n').collect();
    let non_empty = |ls: &[&str]| ls.iter().filter(|l| !l.trim().is_empty()).count();
    let before = non_empty(&lines);
    for (i, l) in lines.iter().enumerate() {
        if l.contains(marker) {
            let mut b = String::new();
            for k in &lines[..i] {
                b.push_str(k);
                b.push('\n');
            }
            return (b.into_bytes(), before, non_empty(&lines[..i]), true);
        }
    }
    (body.to_vec(), before, before, false)
}
