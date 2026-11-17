//! A Jarvis 1 import (router/jarvis1import.go): a new line whose cert's restore names a paused Jarvis 1 session (its id)
//! and the sha256 of the router's import manifest {kind "jarvis1-import", session, files: [{name, sha256, size}]}.
//! Deyao's Face ID signed that hash, so it vouches for every byte the manifest lists; this machine takes each file
//! through the router and refuses any whose sha256 or size differs from the manifest. Then it does what Jarvis 1's
//! restore-snapshot + entrypoint did: the tarballs into their roots (extracted into a staging dir while hashed, moved
//! into place only once the hash matched; nothing outside those roots, nothing through a symlink), the transcripts into
//! ~/.claude/projects/<slug>/ once the repos are in place, claude.json without Jarvis 1's account fields, repo remotes
//! without credentials, and every wakeup and cron Jarvis 1 had armed armed again as THIS line's own signed request.

use crate::client::Client;
use crate::session::session_command;
use crate::snapshot::clean;
use crate::util::go_quote;
use crate::vouch::SHA256_RE;
use crate::{gojson, logf, paths, re, util};
use anyhow::{Result, anyhow, bail};
use serde::Deserialize;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

const J1_KIND: &str = "jarvis1-import";
re!(
    J1_FILE_RE = r"^(session\.json|claude\.json|manifest\.txt|workspace\.tar\.gz|artifacts\.tar\.gz|harness\.tar\.gz|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.jsonl)$"
);
/// under $HOME, outside the snapshot's paths
const J1_STAGE_DIR: &str = ".jarvis1-import";
/// a wakeup (or a missed cron run) whose time passed while paused fires this long after boot
const J1_SOON: Duration = Duration::from_secs(300);

/// the roots each tarball may write (relative to $HOME)
fn j1_roots(name: &str) -> Option<&'static [&'static str]> {
    match name {
        "workspace.tar.gz" => Some(&["workspace"]),
        "artifacts.tar.gz" => Some(&["artifacts"]),
        "harness.tar.gz" => Some(&[".paseo", ".openclaw", ".local/share/opencode"]),
        _ => None,
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct J1File {
    pub name: String,
    pub sha256: String,
    pub size: i64,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct J1Manifest {
    pub kind: String,
    pub v: i64,
    pub session: String,
    pub files: Vec<J1File>,
}

/// the restore bytes as an import manifest (strictly: known fields and names, for the session the cert names), or None
/// (they are something else: a Jarvis 4 snapshot)
pub fn read_j1_manifest(p: &Path, session: &str) -> Option<J1Manifest> {
    if std::fs::metadata(p).ok()?.len() > 1 << 20 {
        return None;
    }
    let b = std::fs::read(p).ok()?;
    let m: J1Manifest = gojson::unmarshal(&b).ok()?;
    if m.kind != J1_KIND || m.v != 1 || m.session != session || m.files.is_empty() {
        return None;
    }
    let mut seen = std::collections::HashSet::new();
    for f in &m.files {
        if !J1_FILE_RE.is_match(&f.name)
            || !SHA256_RE.is_match(&f.sha256)
            || f.size < 0
            || !seen.insert(f.name.clone())
        {
            return None;
        }
    }
    Some(m)
}

/// set by import_jarvis1: the transcripts and the schedule still to place
static J1_IMPORTED: Mutex<Option<J1Manifest>> = Mutex::new(None);

fn imported() -> Option<J1Manifest> {
    J1_IMPORTED.lock().ok().and_then(|g| g.clone())
}

/// every file of the manifest, checked, into place (the transcripts wait in the staging dir for
/// place_imported_transcripts, after the repos are cloned)
pub fn import_jarvis1(c: &Client, m: &J1Manifest) -> Result<()> {
    let home = paths::home();
    let stage = home.join(J1_STAGE_DIR);
    let _ = std::fs::remove_dir_all(&stage);
    std::fs::create_dir_all(stage.join("transcripts"))?;
    let mut record = None;
    for f in &m.files {
        let start = Instant::now();
        let r = (|| -> Result<()> {
            if let Some(roots) = j1_roots(&f.name) {
                return j1_extract(c, f, &stage, roots);
            }
            if f.name.ends_with(".jsonl") {
                return j1_fetch_file(c, f, &stage.join("transcripts").join(&f.name));
            }
            // session.json, claude.json, manifest.txt
            let p = stage.join(&f.name);
            j1_fetch_file(c, f, &p)?;
            match f.name.as_str() {
                "claude.json" => j1_claude_json(&p, &home.join(".claude.json")),
                "session.json" => {
                    record = Some(std::fs::read(&p)?);
                    Ok(())
                }
                _ => Ok(()),
            }
        })();
        r.map_err(|e| anyhow!("Jarvis 1 import, {}: {e:#}", f.name))?;
        logf!(
            "jarvis1 import: {} ({} bytes) checked and in place in {}",
            f.name,
            f.size,
            crate::keeper::dur_text(Duration::from_secs(
                start.elapsed().as_secs_f64().round() as u64
            ))
        );
    }
    let out = home.join("artifacts").join("jarvis1-import");
    let _ = std::fs::create_dir_all(&out);
    if let Some(r) = record {
        let _ = util::write_file(&out.join("session.json"), &r, 0o600);
    }
    j1_fix_remotes(&home.join("workspace"));
    // a new line's own keys: Jarvis 1 brings none (deliver.rs)
    crate::deliver::RESTORED_ARCHIVE.store(false, std::sync::atomic::Ordering::SeqCst);
    if let Ok(mut g) = J1_IMPORTED.lock() {
        *g = Some(m.clone());
    }
    logf!(
        "imported Jarvis 1 session {} ({} files)",
        m.session,
        m.files.len()
    );
    Ok(())
}

/// one file through the router, to p, refused unless its size and sha256 are the manifest's
fn j1_fetch_file(c: &Client, f: &J1File, p: &Path) -> Result<()> {
    let (sum, _) = match c.download(&format!("/m/import-file/{}", f.name), p) {
        Ok(x) => x,
        Err(e) => {
            let _ = std::fs::remove_file(p);
            return Err(e);
        }
    };
    let n = std::fs::metadata(p).map(|m| m.len() as i64).unwrap_or(-1);
    j1_check(f, &sum, n, || {
        let _ = std::fs::remove_file(p);
    })
}

fn j1_check(f: &J1File, sum: &str, n: i64, drop: impl FnOnce()) -> Result<()> {
    if n != f.size || sum != f.sha256 {
        drop();
        bail!(
            "not the bytes the cert names (got {n} bytes, sha256 {}…)",
            util::clip_bytes(sum, 12)
        );
    }
    Ok(())
}

/// a tarball streamed through the router, extracted into the staging dir while it is hashed, then (only when the hash
/// and size match) each of its roots moved into $HOME
fn j1_extract(c: &Client, f: &J1File, stage: &Path, roots: &[&str]) -> Result<()> {
    let tmp = stage.join(format!(
        "x-{}",
        f.name.strip_suffix(".tar.gz").unwrap_or(&f.name)
    ));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp)?;
    let r = (|| {
        let (sum, _, n) = c.download_to(&format!("/m/import-file/{}", f.name), |r| {
            untar_confined(r, &tmp, roots)
        })?;
        j1_check(f, &sum, n as i64, || {})?;
        let home = paths::home();
        for root in roots {
            let src = tmp.join(root);
            if std::fs::symlink_metadata(&src).is_err() {
                continue;
            }
            let dst = home.join(root);
            if let Some(d) = dst.parent() {
                std::fs::create_dir_all(d)?;
            }
            if *root == "workspace" || *root == "artifacts" {
                // the image may have made the directory already: move its entries in, replacing what is there
                std::fs::create_dir_all(&dst)?;
                for e in std::fs::read_dir(&src)?.flatten() {
                    let d = dst.join(e.file_name());
                    let _ = remove_all(&d);
                    move_across(&e.path(), &d)?;
                }
                continue;
            }
            let _ = remove_all(&dst);
            move_across(&src, &dst)?;
        }
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&tmp);
    r
}

/// Go's os.RemoveAll (a file or a tree; a missing path is no error)
fn remove_all(p: &Path) -> std::io::Result<()> {
    match std::fs::symlink_metadata(p) {
        Err(_) => Ok(()),
        Ok(m) if m.is_dir() => std::fs::remove_dir_all(p),
        Ok(_) => std::fs::remove_file(p),
    }
}

/// A tar.gz into dir, only entries under one of roots, never through a symlink, never outside dir. It reads the stream
/// to its end (the caller hashes all of it).
pub fn untar_confined(r: &mut dyn Read, dir: &Path, roots: &[&str]) -> Result<()> {
    let mut gz = flate2::read::GzDecoder::new(r);
    let mut skipped = 0;
    {
        let mut ar = tar::Archive::new(&mut gz);
        for e in ar.entries()? {
            let mut e = e?;
            let raw = String::from_utf8_lossy(&e.path_bytes()).into_owned();
            let name = clean(raw.strip_prefix("./").unwrap_or(&raw));
            if name.starts_with('/')
                || name == ".."
                || name.starts_with("../")
                || !under_roots(&name, roots)
            {
                skipped += 1;
                continue;
            }
            let dst = dir.join(&name);
            if !no_symlink_parents(dir, &name) {
                skipped += 1;
                continue;
            }
            let mode = e.header().mode().unwrap_or(0o644);
            match e.header().entry_type() {
                tar::EntryType::Directory => {
                    use std::os::unix::fs::DirBuilderExt;
                    std::fs::DirBuilder::new()
                        .recursive(true)
                        .mode((mode & 0o777) | 0o700)
                        .create(&dst)?;
                }
                tar::EntryType::Symlink => {
                    if let Some(p) = dst.parent() {
                        let _ = std::fs::create_dir_all(p);
                    }
                    let _ = remove_all(&dst);
                    let l = e.link_name()?.map(|l| l.into_owned()).unwrap_or_default();
                    std::os::unix::fs::symlink(l, &dst)?;
                }
                tar::EntryType::Link => {
                    let lr = e
                        .link_name_bytes()
                        .map(|b| String::from_utf8_lossy(&b).into_owned())
                        .unwrap_or_default();
                    let target = clean(lr.strip_prefix("./").unwrap_or(&lr));
                    if target.starts_with('/')
                        || target.starts_with("..")
                        || !under_roots(&target, roots)
                        || !no_symlink_parents(dir, &target)
                    {
                        skipped += 1;
                        continue;
                    }
                    if let Some(p) = dst.parent() {
                        let _ = std::fs::create_dir_all(p);
                    }
                    let _ = remove_all(&dst);
                    std::fs::hard_link(dir.join(&target), &dst)?;
                }
                tar::EntryType::Regular | tar::EntryType::Continuous => {
                    if let Some(p) = dst.parent() {
                        let _ = std::fs::create_dir_all(p);
                    }
                    let _ = remove_all(&dst);
                    use std::os::unix::fs::OpenOptionsExt;
                    let mut f = std::fs::OpenOptions::new()
                        .create_new(true)
                        .write(true)
                        .mode((mode & 0o777) | 0o600)
                        .open(&dst)?;
                    std::io::copy(&mut e, &mut f)?;
                    drop(f);
                    if let Ok(mt) = e.header().mtime() {
                        // git's index keeps trusting unchanged files
                        let t = std::time::UNIX_EPOCH + Duration::from_secs(mt);
                        if let Ok(f) = std::fs::File::options().write(true).open(&dst) {
                            let _ = f.set_times(
                                std::fs::FileTimes::new().set_accessed(t).set_modified(t),
                            );
                        }
                    }
                }
                _ => skipped += 1,
            }
        }
    }
    if skipped > 0 {
        logf!(
            "jarvis1 import: {skipped} tar entries skipped (outside [{}], through a symlink, or not a file/dir/link)",
            roots.join(" ")
        );
    }
    std::io::copy(&mut gz, &mut std::io::sink())?;
    Ok(())
}

pub fn under_roots(name: &str, roots: &[&str]) -> bool {
    roots
        .iter()
        .any(|r| name == *r || name.starts_with(&format!("{r}/")))
}

/// no directory between dir and name's parent is a symlink (an entry can't be written through one)
pub fn no_symlink_parents(dir: &Path, name: &str) -> bool {
    let parent = Path::new(name)
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_default();
    let mut cur = dir.to_path_buf();
    for p in parent.components() {
        cur = cur.join(p);
        match std::fs::symlink_metadata(&cur) {
            Err(_) => return true, // not made yet: create_dir_all makes a real directory
            Ok(m) if m.file_type().is_symlink() => return false,
            Ok(_) => {}
        }
    }
    true
}

/// Jarvis 1's ~/.claude.json without its account (the entrypoint adds this session's)
pub fn j1_claude_json(src: &Path, dst: &Path) -> Result<()> {
    let b = std::fs::read(src)?;
    let mut m: serde_json::Map<String, serde_json::Value> =
        serde_json::from_slice(&b).map_err(|e| anyhow!("not JSON: {e}"))?;
    m.remove("oauthAccount");
    m.remove("userID");
    util::write_file(dst, gojson::marshal(&m).as_bytes(), 0o600)?;
    Ok(())
}

re!(GH_CRED_URL_RE = r"^https://[^/@]+@github\.com/(.+)$");
re!(GH_HTTPS_RE = r"^https://github\.com/([A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9_.-]+?)(\.git)?/?$");

/// each repo's remotes without embedded credentials, GitHub https URLs ending in .git (the form the deploy-key
/// rewrites match)
pub fn j1_fix_remotes(ws: &Path) {
    for e in std::fs::read_dir(ws).into_iter().flatten().flatten() {
        let repo = e.path();
        if !repo.join(".git").exists() {
            continue;
        }
        let r = repo.to_string_lossy().into_owned();
        let out = session_command(
            "git",
            &["-C", &r, "config", "--get-regexp", r"^remote\..*\.url$"],
        )
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
        for line in out.trim().lines() {
            let Some((key, url)) = line.split_once(' ') else {
                continue;
            };
            let fixed = j1_fix_url(url);
            if fixed != url
                && session_command("git", &["-C", &r, "config", key, &fixed])
                    .status()
                    .is_ok_and(|s| s.success())
            {
                logf!(
                    "jarvis1 import: {} {key} → {fixed}",
                    e.file_name().to_string_lossy()
                );
            }
        }
    }
}

pub fn j1_fix_url(u: &str) -> String {
    let mut u = u.to_string();
    if let Some(m) = GH_CRED_URL_RE.captures(&u) {
        u = format!("https://github.com/{}", &m[1]);
    }
    if let Some(m) = GH_HTTPS_RE.captures(&u) {
        return format!("https://github.com/{}.git", &m[1]);
    }
    u
}

/// After the repos are cloned (the working dir decides the project slug, as Jarvis 1's entrypoint computes it): the
/// imported transcripts into ~/.claude/projects/<slug>/
pub fn place_imported_transcripts() {
    if imported().is_none() {
        return;
    }
    let home = paths::home();
    let src = home.join(J1_STAGE_DIR).join("transcripts");
    let ents: Vec<_> = std::fs::read_dir(&src)
        .into_iter()
        .flatten()
        .flatten()
        .collect();
    if ents.is_empty() {
        return;
    }
    let pdir = home
        .join(".claude")
        .join("projects")
        .join(project_slug(&working_dir(&home).to_string_lossy()));
    if let Err(e) = std::fs::create_dir_all(&pdir) {
        logf!("jarvis1 import: {e}");
        return;
    }
    for e in &ents {
        if let Err(err) = move_across(&e.path(), &pdir.join(e.file_name())) {
            logf!(
                "jarvis1 import: transcript {}: {err:#}",
                e.file_name().to_string_lossy()
            );
        }
    }
    // the approved first prompt goes into the resumed conversation
    let _ = std::fs::remove_file(home.join(".claude").join(".first-prompt-sent"));
    logf!(
        "jarvis1 import: {} transcript(s) in {}",
        ents.len(),
        pdir.display()
    );
}

/// the single repo in ~/workspace if there is exactly one, else ~/workspace (Jarvis 1's entrypoint)
pub fn working_dir(home: &Path) -> PathBuf {
    let ws = home.join("workspace");
    let dirs: Vec<PathBuf> = std::fs::read_dir(&ws)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .map(|e| e.path())
        .collect();
    if dirs.len() == 1 {
        return dirs[0].clone();
    }
    ws
}

re!(SLUG_RE = r"[^A-Za-z0-9]");

pub fn project_slug(wd: &str) -> String {
    SLUG_RE.replace_all(wd, "-").into_owned()
}

// ---- the schedule ----------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
struct J1Wake {
    name: String,
    at: i64,
    prompt: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
struct J1Cron {
    name: String,
    prompt: String,
    every: i64,
    tz: String,
    #[serde(rename = "nextAt")]
    next_at: i64,
    until: i64,
}

/// a wakeup or cron the Jarvis 1 record had armed, as this line's own request (path, body), with its line for
/// rearmed.txt
#[derive(Debug, Clone)]
pub struct J1Arm {
    pub path: String,
    pub body: serde_json::Map<String, serde_json::Value>,
    pub note: String,
}

fn ms_text(ms: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp_nanos(ms as i128 * 1_000_000)
        .ok()
        .and_then(|t| t.replace_nanosecond(0).ok())
        .and_then(|t| {
            t.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_default()
}

pub fn j1_schedule(record: &[u8], sid: &str, now_ms: i64) -> (Vec<J1Arm>, Vec<String>) {
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Rec {
        metadata: std::collections::BTreeMap<String, String>,
    }
    let rec: Rec = gojson::unmarshal(record).unwrap_or_default();
    let (mut out, mut notes) = (vec![], vec![]);
    let soon = J1_SOON.as_secs() as i64;
    let soon_text = crate::keeper::dur_text(J1_SOON);
    let wakeups = format!("/m/api/sessions/{sid}/wakeups");
    for (k, v) in &rec.metadata {
        if let Some(rest) = k.strip_prefix("wake_") {
            let mut w: J1Wake = match gojson::unmarshal::<J1Wake>(v.as_bytes()) {
                Ok(w) if !w.prompt.is_empty() => w,
                _ => {
                    notes.push(format!("skipped {k}: not a wakeup record"));
                    continue;
                }
            };
            if w.name.is_empty() {
                w.name = rest.to_string();
            }
            let mut body = serde_json::Map::new();
            body.insert("name".into(), w.name.clone().into());
            body.insert("prompt".into(), w.prompt.clone().into());
            let when = ms_text(w.at);
            if w.at <= now_ms + 60_000 {
                body.insert("delaySeconds".into(), soon.into());
                out.push(J1Arm {
                    path: wakeups.clone(),
                    body,
                    note: format!(
                        "wakeup {}: was due {when} (passed while paused), fires {soon_text} after this boot",
                        go_quote(&w.name)
                    ),
                });
            } else {
                body.insert("at".into(), w.at.into());
                out.push(J1Arm {
                    path: wakeups.clone(),
                    body,
                    note: format!("wakeup {}: at {when}, as in Jarvis 1", go_quote(&w.name)),
                });
            }
        } else if let Some(rest) = k.strip_prefix("cron_") {
            let mut c: J1Cron = match gojson::unmarshal::<J1Cron>(v.as_bytes()) {
                Ok(c) if !c.prompt.is_empty() && c.every > 0 => c,
                _ => {
                    notes.push(format!("skipped {k}: not a cron record"));
                    continue;
                }
            };
            if c.name.is_empty() {
                c.name = rest.to_string();
            }
            if c.until > 0 && c.until <= now_ms {
                notes.push(format!(
                    "cron {}: ended {} in Jarvis 1, not armed",
                    go_quote(&c.name),
                    ms_text(c.until)
                ));
                continue;
            }
            let (mut next, step) = (c.next_at, c.every * 1000);
            let missed = next > 0 && next <= now_ms;
            if next <= now_ms {
                if next <= 0 {
                    next = now_ms;
                }
                next += ((now_ms - next) / step + 1) * step;
            }
            let mut body = serde_json::Map::new();
            body.insert("name".into(), c.name.clone().into());
            body.insert("prompt".into(), c.prompt.clone().into());
            body.insert("everySeconds".into(), c.every.into());
            body.insert("at".into(), next.into());
            if !c.tz.is_empty() {
                body.insert("tz".into(), c.tz.clone().into());
            }
            if c.until > next {
                body.insert("until".into(), c.until.into());
            }
            out.push(J1Arm {
                path: format!("/m/api/sessions/{sid}/crons"),
                body,
                note: format!(
                    "cron {}: every {}s, next {} (Jarvis 1's time of day kept)",
                    go_quote(&c.name),
                    c.every,
                    ms_text(next)
                ),
            });
            if missed {
                let mn = j1_missed_name(&c.name);
                let mut body = serde_json::Map::new();
                body.insert("name".into(), mn.clone().into());
                body.insert("prompt".into(), c.prompt.clone().into());
                body.insert("delaySeconds".into(), soon.into());
                out.push(J1Arm {
                    path: wakeups.clone(),
                    body,
                    note: format!(
                        "cron {}: its run due {} was missed while paused, so it runs once {soon_text} after this boot (wakeup {})",
                        go_quote(&c.name),
                        ms_text(c.next_at),
                        go_quote(&mn)
                    ),
                });
            }
        } else if k.starts_with("watch_") {
            notes.push(format!(
                "not armed: {k} (a Jarvis 1 watch; Jarvis 4 has no watches yet)"
            ));
        }
    }
    (out, notes)
}

pub fn j1_missed_name(n: &str) -> String {
    let n = format!("missed-{n}");
    util::clip_bytes(&n, 40).to_string()
}

/// The Jarvis 1 record's wakeups and crons, signed by this machine (the router keeps each request exactly as signed:
/// what vouches for its delivery later). A failure is noted, never fatal.
pub fn rearm_jarvis1(c: &Client, sid: &str) {
    let Some(m) = imported() else { return };
    let home = paths::home();
    let out = home.join("artifacts").join("jarvis1-import");
    let Ok(record) = std::fs::read(out.join("session.json")) else {
        return;
    };
    let now_ms = (util::unix_now() as i128 * 1000) as i64;
    let (arms, notes) = j1_schedule(&record, sid, now_ms);
    let mut lines = vec![format!(
        "Re-armed from Jarvis 1 session {} on {}:",
        m.session,
        util::now_rfc3339()
    )];
    for a in &arms {
        if let Err(e) = c.json_ok("POST", &a.path, Some(&a.body)) {
            lines.push(format!("FAILED {}: {e:#}", a.note));
            logf!("jarvis1 import: arming failed: {}: {e:#}", a.note);
            continue;
        }
        lines.push(a.note.clone());
        logf!("jarvis1 import: armed {}", a.note);
    }
    let empty = arms.is_empty() && notes.is_empty();
    lines.extend(notes);
    if empty {
        lines.push("(nothing was armed in Jarvis 1)".into());
    }
    let _ = util::write_file(
        &out.join("rearmed.txt"),
        format!("{}\n", lines.join("\n")).as_bytes(),
        0o600,
    );
    let _ = std::fs::remove_dir_all(home.join(J1_STAGE_DIR));
}

/// a rename, or (the state directories are bind-mounted from the volume, so the import's staging dir on the root disk
/// is another filesystem) a copy that keeps modes, links and times, then the source goes
pub fn move_across(src: &Path, dst: &Path) -> Result<()> {
    match std::fs::rename(src, dst) {
        Ok(()) => return Ok(()),
        Err(e) if e.raw_os_error() != Some(nix::libc::EXDEV) => return Err(e.into()),
        Err(_) => {}
    }
    let (s, d) = (
        src.to_string_lossy().into_owned(),
        dst.to_string_lossy().into_owned(),
    );
    let o = session_command("cp", &["-a", "--", &s, &d]).output()?;
    if !o.status.success() {
        bail!(
            "copying {} across filesystems: {} {}",
            src.file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
            o.status,
            String::from_utf8_lossy(&o.stderr).trim()
        );
    }
    remove_all(src)?;
    Ok(())
}
