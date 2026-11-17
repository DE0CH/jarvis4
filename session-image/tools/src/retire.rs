//! retire-session: retire THIS Jarvis 4 session. Checks every repo under ~/workspace is committed and pushed, the
//! task record exists, the machine sees no unpushed work and no wakeup, cron or watch is pending (the router answers
//! 409 "pending" otherwise), then asks the router to destroy it: the router takes the final snapshot, archives it
//! (transcripts, ~/workspace, ~/artifacts) and burns the machine. `--check` stops before the destroy.
//! Skill: retire-session in Deyao's workspace.

use crate::{call, session_url};
use serde_json::Value;
use std::path::Path;
use std::process::{Command, ExitCode};

/// Repos the machine's pre-destroy check (`GET …/changes`) still sees uncommitted or unpushed work in
fn dirty_repos(changes: &Value) -> Vec<String> {
    changes["repos"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|r| {
            r["uncommitted"].as_u64().unwrap_or(0) > 0 || r["unpushed"].as_u64().unwrap_or(0) > 0
        })
        .map(|r| {
            r["name"]
                .as_str()
                .or(r["path"].as_str())
                .unwrap_or("?")
                .to_string()
        })
        .collect()
}

/// How many wakeups, crons or watches a list answer holds; None when it isn't one
fn pending(list: &Value) -> Option<usize> {
    ["wakeups", "crons", "watches"]
        .iter()
        .find_map(|k| list.get(*k))
        .map(|v| v.as_array().map_or(0, Vec::len))
}

/// One repo's state in words, and whether it blocks the retire
fn repo_state(dirty: usize, ahead: Option<usize>) -> (String, bool) {
    let mut parts = vec![];
    if dirty > 0 {
        parts.push(format!("{dirty} uncommitted change(s)"));
    }
    match ahead {
        Some(n) if n > 0 => parts.push(format!("{n} unpushed commit(s)")),
        None => parts.push("branch has no upstream (push it: git push -u origin HEAD:main)".into()),
        _ => {}
    }
    if parts.is_empty() {
        ("ok".into(), false)
    } else {
        (parts.join(", "), true)
    }
}

fn git(dir: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

fn count_entries(dir: &Path) -> usize {
    std::fs::read_dir(dir)
        .map(|rd| {
            rd.flatten()
                .map(|e| {
                    1 + if e.path().is_dir() {
                        count_entries(&e.path())
                    } else {
                        0
                    }
                })
                .sum()
        })
        .unwrap_or(0)
}

pub fn run(check_only: bool) -> Result<ExitCode, String> {
    let elsewhere = "on the Mac / a web pod upload records yourself (retire-session skill, \"Other runtimes\") instead";
    let base = session_url("", elsewhere)?;
    let home = std::path::PathBuf::from(std::env::var("HOME").unwrap_or_default());

    // 1. every repo under ~/workspace committed, on a branch with an upstream, pushed
    let mut blocked = false;
    let mut repos: Vec<_> = std::fs::read_dir(home.join("workspace"))
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .collect();
    repos.sort();
    for d in repos.iter().filter(|d| d.join(".git").is_dir()) {
        let name = d.file_name().unwrap_or_default().to_string_lossy();
        git(d, &["fetch", "-q"]);
        let dirty = git(d, &["status", "--porcelain"]).map_or(0, |s| s.lines().count());
        let ahead = git(d, &["rev-parse", "--abbrev-ref", "@{u}"]).map(|_| {
            git(d, &["rev-list", "@{u}..HEAD", "--count"])
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(0)
        });
        let (st, blocks) = repo_state(dirty, ahead);
        blocked |= blocks;
        println!("repo {name}: {st}");
    }
    if blocked {
        return Err("commit and push first (see above)".into());
    }

    // 2. the record the archive should carry
    let record = home.join("artifacts/record.md");
    if std::fs::metadata(&record).map_or(true, |m| m.len() == 0) {
        return Err("~/artifacts/record.md missing — write the task record first (chronicle, result, support transcripts)".into());
    }
    println!(
        "artifacts: {} entries under ~/artifacts (record.md present)",
        count_entries(&home.join("artifacts"))
    );

    // 3. the machine's own pre-destroy check (the one the app's Destroy shows)
    let ch = call("GET", &format!("{base}/changes"), None).map_err(|_| "jarvis unreachable")?;
    println!("pre-destroy check: {ch}");
    let changes: Value = serde_json::from_str(&ch)
        .map_err(|_| "the machine's pre-destroy check answered no JSON")?;
    let bad = dirty_repos(&changes);
    if !bad.is_empty() {
        return Err(format!(
            "the machine still sees unpushed/uncommitted work: {}",
            bad.join(", ")
        ));
    }

    // 4. pending wakeups, crons and watches keep a session (the router answers 409 "pending")
    for w in ["wakeup", "crons", "watches"] {
        let n = call("GET", &format!("{base}/{w}"), None)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .and_then(|v| pending(&v));
        match n {
            Some(0) => {}
            Some(n) => {
                return Err(format!(
                    "{n} pending {w} — cancel them first (schedule-wakeup --cancel-all / schedule-cron --cancel)"
                ));
            }
            None => return Err(format!("could not read the pending {w}")),
        }
    }
    let sid = std::env::var("SESSION_ID").unwrap_or_default();
    if check_only {
        println!("pre-flight OK — this session ({sid}) can be retired");
        return Ok(ExitCode::SUCCESS);
    }

    // 5. the destroy: DELETE answers 202 {started}
    let out = call("DELETE", &base, None).unwrap_or_else(|e| e);
    println!("{out}");
    if !out.contains("\"started\"") {
        return Err("the router didn't start the destroy (see above)".into());
    }
    println!(
        "destroy requested for session {sid} — the router archives it to the Storage Box and burns this machine shortly. Nothing more to do here."
    );
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_machine_check_names_dirty_repos() {
        let c = json!({"repos": [{"name": "a", "uncommitted": 0, "unpushed": 0}, {"name": "b", "unpushed": 2}, {"path": "/w/c", "uncommitted": 1}]});
        assert_eq!(dirty_repos(&c), vec!["b", "/w/c"]);
        assert!(dirty_repos(&json!({})).is_empty());
    }

    #[test]
    fn pending_counts_each_list_shape() {
        assert_eq!(pending(&json!({"wakeup": null, "wakeups": []})), Some(0));
        assert_eq!(
            pending(&json!({"crons": [{"name": "x"}, {"name": "y"}]})),
            Some(2)
        );
        assert_eq!(pending(&json!({"watches": null})), Some(0));
        assert_eq!(pending(&json!({"error": "no"})), None);
    }

    #[test]
    fn repo_states() {
        assert_eq!(repo_state(0, Some(0)), ("ok".into(), false));
        assert_eq!(
            repo_state(2, Some(1)),
            ("2 uncommitted change(s), 1 unpushed commit(s)".into(), true)
        );
        assert!(repo_state(0, None).1);
    }
}
