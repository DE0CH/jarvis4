//! The live copies go into the archive before any of them goes (2026-10-15: destroying session sb8e0273d6c308894
//! deleted claude-records/.live/sb8e0273d6c308894/, which held its ORIGINAL conversation — its machine's snapshot had
//! failed, the session went on under a new conversation, and the archive took only the latest snapshot's transcripts,
//! so the original had no other copy).
//!
//!   - An archive holds EVERY transcript in the session's .live dir that the snapshot doesn't already hold
//!     byte-identical (same size and sha256): transcript-<uuid>.jsonl, or transcript-<uuid>.live.jsonl when the
//!     snapshot holds a different version of that conversation. They count once the whole archive is on the Storage
//!     Box (its size checked, archivetar.rs). The record lists them all (ArchiveInfo.live).
//!   - A session with no snapshot but live copies still gets an archive: the live transcripts and session.json, which
//!     notes that there is no snapshot (nothing to restore).
//!   - clear_archived_live deletes only the .live files the archive accounted for, each still the size it had then;
//!     the dir goes only once it is empty. Anything else (no archive, a failed one, a file that came or changed since)
//!     stays, and the record says so (Record.live_kept). There is no other path that deletes .live copies.

use crate::archive::{ArchiveInfo, records_off};
use crate::livesync::live_dir;
use crate::router::Router;
use crate::storagebox::StorageBox;
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Path, PathBuf};

/// one .live transcript as the archive accounted for it
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct LiveCopy {
    /// its name in claude-records/.live/<session id>/
    pub name: String,
    pub size: i64,
    pub sha256: String,
    /// where the record holds it — "snapshot" (the signed snapshot has it byte-identical, and so its transcript-…
    /// file), else the file in the archive dir it was copied to
    #[serde(rename = "in")]
    pub in_: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FileSum {
    pub size: i64,
    pub sha: String,
}

/// a local file's size and sha256
pub fn sum_file(p: &Path) -> Result<FileSum> {
    sum_reader(&mut std::fs::File::open(p)?)
}

/// a stream's size and sha256
pub fn sum_reader<R: Read + ?Sized>(rd: &mut R) -> Result<FileSum> {
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 << 10];
    let mut n = 0i64;
    loop {
        let k = rd.read(&mut buf)?;
        if k == 0 {
            break;
        }
        h.update(&buf[..k]);
        n += k as i64;
    }
    Ok(FileSum { size: n, sha: hex::encode(h.finalize()) })
}

impl Router {
    /// every .live transcript of the session downloaded into tmp, unless held (snapshot transcript name → sum) has it
    /// byte-identical; taken: the transcript names the archive already uses. Returns the accounting (sorted by name)
    /// and the files to put in the archive (name in the archive, local file). Any error: nothing may be deleted from
    /// .live.
    pub fn gather_live(
        &self,
        b: &StorageBox,
        sid: &str,
        tmp: &Path,
        held: &BTreeMap<String, FileSum>,
        taken: &BTreeSet<String>,
    ) -> Result<(Vec<LiveCopy>, Vec<(String, PathBuf)>)> {
        let listed = b.list(&live_dir(sid)).map_err(|e| anyhow!("listing the live copies: {e:#}"))?.unwrap_or_default();
        let mut taken = taken.clone();
        let mut out = vec![];
        let mut files = vec![];
        for (name, &size) in &listed {
            if !crate::livesync::is_live_name(name) {
                crate::logf!("[livesync] {sid}: {} in the live dir isn't a transcript: left there", jarvis_go::fmt::go_quote(name));
                continue;
            }
            let local = tmp.join(format!("live-{name}"));
            let found = b
                .download(&format!("{}/{name}", live_dir(sid)), &local)
                .map_err(|e| anyhow!("reading the live transcript {name}: {e:#}"))?;
            if !found {
                continue; // gone since the listing
            }
            let sum = sum_file(&local)?;
            if sum.size != size {
                return Err(anyhow!(
                    "the live transcript {name} changed while being read ({size} bytes listed, {} read)",
                    sum.size
                ));
            }
            let mut c = LiveCopy { name: name.clone(), size: sum.size, sha256: sum.sha.clone(), ..Default::default() };
            if held.get(name) == Some(&sum) {
                c.in_ = "snapshot".into();
                out.push(c);
                continue;
            }
            let stem = name.strip_suffix(".jsonl").unwrap_or(name);
            let mut dest = format!("transcript-{name}");
            if held.contains_key(name) || taken.contains(&dest) {
                dest = format!("transcript-{stem}.live.jsonl"); // the snapshot's version of this conversation differs
                let mut i = 2;
                while taken.contains(&dest) {
                    dest = format!("transcript-{stem}.live-{i}.jsonl");
                    i += 1;
                }
            }
            taken.insert(dest.clone());
            c.in_ = dest.clone();
            out.push(c);
            files.push((dest, local));
        }
        Ok((out, files))
    }

    /// the .live files the archive accounted for go (each only while it is still the size it had); "" when the dir is
    /// gone, else what was kept and why (for the record and the log)
    pub fn clear_archived_live(&self, sid: &str, archived: Option<&ArchiveInfo>, aerr: Option<&anyhow::Error>) -> String {
        crate::livesync::forget_live_dir(sid);
        let Some(b) = self.box_() else { return String::new() };
        if records_off() {
            return String::new();
        }
        let dir = live_dir(sid);
        let listed = match b.list(&dir) {
            Err(e) => {
                let msg = format!("the live copies in {dir}/ were kept (listing them failed: {e:#})");
                crate::logf!("[livesync] {sid}: {msg}");
                return msg;
            }
            Ok(l) => l,
        };
        let listed = match listed {
            None => return String::new(),
            Some(l) if l.is_empty() => {
                let _ = b.delete(&format!("{dir}/")); // an empty dir
                return String::new();
            }
            Some(l) => l,
        };
        let done: BTreeMap<&str, &LiveCopy> = match (archived, aerr) {
            (Some(a), None) => a.live.iter().map(|c| (c.name.as_str(), c)).collect(),
            _ => BTreeMap::new(),
        };
        let mut kept = vec![];
        for (name, &size) in &listed {
            match done.get(name.as_str()) {
                Some(c) if c.size == size => {
                    if let Err(e) = b.delete(&format!("{dir}/{name}")) {
                        crate::logf!("[livesync] {sid}: removing the archived live copy {name}: {e:#}");
                        kept.push(name.clone());
                    }
                }
                _ => kept.push(name.clone()),
            }
        }
        if kept.is_empty() {
            if let Err(e) = b.delete(&format!("{dir}/")) {
                crate::logf!("[livesync] {sid}: removing the empty live dir: {e:#}");
            }
            return String::new();
        }
        kept.sort();
        let why = match (aerr, archived) {
            (Some(e), _) => format!("the archive failed: {e:#}"),
            (None, None) => "there is no archive".into(),
            _ => "not in the archive".into(),
        };
        let msg = format!("kept {} live transcript(s) in {dir}/ ({why}): {}", kept.len(), kept.join(", "));
        crate::logf!("[livesync] {sid}: {msg}");
        msg
    }
}

