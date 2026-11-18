//! One-shot sessions end by themselves (Jarvis 1 oneShotTick / finishOneShot): once the supervisor marks the prompt
//! done (the machine's status report, autopilot.rs), the session is destroyed FORCEFULLY — paused for its final signed
//! snapshot, archived to the Storage Box, burnt — without stopping for uncommitted or unpushed work (one prompt rarely
//! leaves anything valuable) nor for a failed archive. Whenever work WAS lost (dirty repos as the final snapshot
//! recorded them, a check that couldn't run, or the archive failed) Deyao gets a DM saying exactly what.

use crate::archive::{ArchiveInfo, RepoChange};
use crate::flows::DestroyOpts;
use crate::router::Router;
use anyhow::Result;
use serde_json::{Map, Value};
use std::sync::Arc;

impl Router {
    /// the autopilot's destroy action
    pub fn finish_one_shot(self: &Arc<Self>, id: &str) -> Result<()> {
        let r = self.clone();
        let id2 = id.to_string();
        self.destroy_opts(
            id,
            DestroyOpts {
                force: true,
                report: Some(Arc::new(move |s, changes, archived, aerr| {
                    let mut title = crate::titles::session_title(s);
                    if let Some(a) = archived
                        && !a.title.is_empty()
                    {
                        title = a.title.clone(); // the title it was archived under (the app's, from the transcript)
                    }
                    let text =
                        one_shot_lost_dm(&title, &changes.unwrap_or_default(), archived, aerr);
                    if !text.is_empty() {
                        r.dm(&text);
                    }
                    crate::logf!(
                        "[oneshot] {id2} destroyed (archive: {})",
                        archive_where(archived, aerr)
                    );
                })),
            },
        )
    }
}

/// one line per repo with unsaved work ("claude-env: 2 uncommitted file(s), 1 unpushed commit(s)")
pub fn dirty_lines(repos: &[RepoChange]) -> Vec<String> {
    repos
        .iter()
        .filter(|r| r.uncommitted > 0 || r.unpushed != 0)
        .map(|r| {
            let mut parts = vec![];
            if r.uncommitted > 0 {
                parts.push(format!("{} uncommitted file(s)", r.uncommitted));
            }
            if r.unpushed > 0 {
                parts.push(format!("{} unpushed commit(s)", r.unpushed));
            } else if r.unpushed == -1 {
                parts.push("branch has no upstream (nothing pushed)".into());
            }
            format!("{}: {}", r.name, parts.join(", "))
        })
        .collect()
}

pub fn archive_where(a: Option<&ArchiveInfo>, aerr: Option<&anyhow::Error>) -> String {
    if let Some(e) = aerr {
        return format!("FAILED: {e:#}");
    }
    match a {
        None => "nothing archived (no snapshot, or records off)".into(),
        Some(a) => format!(
            "{} ({} transcript(s), {} artifact file(s))",
            a.file,
            a.transcripts.len(),
            a.artifacts
        ),
    }
}

/// the DM, or "" when nothing was lost
pub fn one_shot_lost_dm(
    title: &str,
    changes: &Map<String, Value>,
    archived: Option<&ArchiveInfo>,
    aerr: Option<&anyhow::Error>,
) -> String {
    let checked = changes
        .get("checked")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let repos: Vec<RepoChange> = changes
        .get("repos")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    let lost = dirty_lines(&repos);
    if lost.is_empty() && checked && aerr.is_none() {
        return String::new();
    }
    let mut lines = vec![format!(
        "Jarvis 4: one-shot session “{title}” was destroyed with work lost:"
    )];
    lines.extend(lost.iter().map(|l| format!("• {l}")));
    if !checked {
        let reason = changes
            .get("reason")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .unwrap_or("unknown");
        lines.push(format!(
            "• could not check the repos for unsaved work ({reason})"
        ));
    }
    match aerr {
        Some(e) => lines.push(format!("• the archive to the Storage Box failed — the transcript and ~/artifacts are gone: {e:#}")),
        None => lines.push(format!("Transcript + ~/artifacts: {}.", archive_where(archived, None))),
    }
    lines.join("\n")
}
