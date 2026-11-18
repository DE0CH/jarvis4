//! gate: an agent's branch reaches main only when CI is green (Deyao, 2026-11-18). Runs in every agent-pushed
//! repo's workflows (docs/DESIGN.md "Agent branches"), downloaded from this repo's gate release:
//!
//!   gate open    branch.yml, on every push to a branch other than main: open the branch's pull request (a draft for
//!                wip/<topic>) and set the commit's `gate` status pending
//!   gate merge   merge.yml, when any workflow on a branch finishes (workflow_run: GitHub runs it from main's copy,
//!                so a branch can't change it): once every workflow on the head commit is done, set `gate` green or
//!                red; green on main's head fast-forwards main to that exact commit with the merge deploy key; green
//!                on an older base merges main into the branch, which runs its CI again
//!
//! Environment: GITHUB_REPOSITORY, GH_TOKEN (the workflow's token: pull requests, statuses, actions read),
//! GATE_BRANCH and GATE_SHA (the pushed branch and commit), GATE_RUN_URL (the status's link); merge also
//! GATE_WORKFLOWS (the workflows that make up the repo's CI, comma-separated: merge.yml's list) and MERGE_DEPLOY_KEY (the repo's deploy key `jarvis-merge`, which main's ruleset lets push).

mod decide;

use anyhow::{Context, Result, anyhow, bail};
use decide::{Action, Rel, Run};
use serde_json::{Value, json};
use std::path::Path;
use std::process::{Command, ExitCode};

const OWN: &str = ".github/workflows/merge.yml";

struct Gh {
    http: reqwest::blocking::Client,
    api: String,
    token: String,
    repo: String,
}

impl Gh {
    fn from_env() -> Result<Gh> {
        Ok(Gh {
            http: reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(60))
                .build()?,
            api: std::env::var("GITHUB_API_URL")
                .unwrap_or_else(|_| "https://api.github.com".into()),
            token: env("GH_TOKEN")?,
            repo: env("GITHUB_REPOSITORY")?,
        })
    }

    /// (status, body) of one API call
    fn call(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<(u16, Value)> {
        let mut req = self
            .http
            .request(
                method.clone(),
                format!("{}/repos/{}{path}", self.api, self.repo),
            )
            .bearer_auth(&self.token)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header("User-Agent", "jarvis4-gate");
        if let Some(b) = body {
            req = req.json(b);
        }
        let res = req.send().with_context(|| format!("{method} {path}"))?;
        let code = res.status().as_u16();
        let text = res.text().unwrap_or_default();
        Ok((
            code,
            serde_json::from_str(&text).unwrap_or(Value::String(text)),
        ))
    }

    fn get(&self, path: &str) -> Result<Value> {
        match self.call(reqwest::Method::GET, path, None)? {
            (200, v) => Ok(v),
            (c, v) => bail!("GET {path}: {c} {v}"),
        }
    }

    fn post(&self, path: &str, body: &Value) -> Result<Value> {
        match self.call(reqwest::Method::POST, path, Some(body))? {
            (200 | 201, v) => Ok(v),
            (c, v) => bail!("POST {path}: {c} {v}"),
        }
    }

    fn default_branch(&self) -> Result<String> {
        let v = self.get("")?;
        v["default_branch"]
            .as_str()
            .map(String::from)
            .ok_or_else(|| anyhow!("the repo has no default branch"))
    }

    fn status(&self, sha: &str, state: &str, description: &str) -> Result<()> {
        let mut d: String = description.chars().take(139).collect();
        if d.is_empty() {
            d = state.into();
        }
        let url = std::env::var("GATE_RUN_URL").unwrap_or_default();
        let mut b = json!({"state": state, "context": "gate", "description": d});
        if !url.is_empty() {
            b["target_url"] = json!(url);
        }
        self.post(&format!("/statuses/{sha}"), &b)?;
        println!("gate {state}: {description}");
        Ok(())
    }

    fn open_pr(&self, branch: &str) -> Result<Option<Value>> {
        let owner = self.repo.split('/').next().unwrap_or("");
        let v = self.get(&format!("/pulls?state=open&head={owner}:{branch}"))?;
        Ok(v.as_array().and_then(|a| a.first().cloned()))
    }
}

fn env(k: &str) -> Result<String> {
    match std::env::var(k) {
        Ok(v) if !v.is_empty() => Ok(v),
        _ => bail!("{k} is not set"),
    }
}

/// branch.yml: the pull request, and the commit's gate pending
fn open(gh: &Gh) -> Result<()> {
    let (branch, sha) = (env("GATE_BRANCH")?, env("GATE_SHA")?);
    let base = gh.default_branch()?;
    if branch == base {
        return Ok(());
    }
    gh.status(&sha, "pending", "waiting for every workflow on this commit")?;
    if let Some(pr) = gh.open_pr(&branch)? {
        println!("pull request #{} is open", pr["number"]);
        return Ok(());
    }
    let msg = gh.get(&format!("/commits/{sha}"))?["commit"]["message"]
        .as_str()
        .unwrap_or("")
        .to_string();
    let title = msg
        .lines()
        .next()
        .filter(|l| !l.is_empty())
        .unwrap_or(&branch)
        .to_string();
    let wip = branch.starts_with("wip/");
    let body = if wip {
        "An agent's work in progress (`wip/`): CI runs on every push; it is never merged by the gate.".to_string()
    } else {
        "An agent's branch. The gate merges it into main once every workflow on its head commit is green \
         (jarvis4 `rust/gate`); close this pull request to keep it out."
            .to_string()
    };
    let pr = gh.post(
        "/pulls",
        &json!({"title": title, "head": branch, "base": base, "body": body, "draft": wip}),
    )?;
    println!("opened pull request #{}", pr["number"]);
    Ok(())
}

/// git as the merge deploy key, in dir
struct Git {
    dir: tempfile::TempDir,
    ssh: String,
    url: String,
}

impl Git {
    fn new(repo: &str) -> Result<Git> {
        let dir = tempfile::tempdir()?;
        let key = dir.path().join("merge-key");
        let mut k = env("MERGE_DEPLOY_KEY")?;
        if !k.ends_with('\n') {
            k.push('\n');
        }
        write_private(&key, &k)?;
        let g = Git {
            ssh: format!(
                "ssh -i {} -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new",
                key.display()
            ),
            url: format!("git@github.com:{repo}.git"),
            dir,
        };
        g.run(&["init", "-q", "repo"])?;
        g.git(&["remote", "add", "origin", &g.url])?;
        g.git(&["config", "user.name", "jarvis4-gate"])?;
        g.git(&[
            "config",
            "user.email",
            "jarvis4-gate@users.noreply.github.com",
        ])?;
        Ok(g)
    }

    fn run(&self, args: &[&str]) -> Result<std::process::Output> {
        let out = Command::new("git")
            .args(args)
            .current_dir(self.dir.path())
            .env("GIT_SSH_COMMAND", &self.ssh)
            .output()
            .context("running git")?;
        Ok(out)
    }

    fn git(&self, args: &[&str]) -> Result<String> {
        let mut a = vec!["-C", "repo"];
        a.extend_from_slice(args);
        let out = self.run(&a)?;
        if !out.status.success() {
            bail!(
                "git {}: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }
}

fn write_private(p: &Path, s: &str) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(p)?;
    f.write_all(s.as_bytes())?;
    Ok(())
}

/// merge.yml: decide, then act
fn merge(gh: &Gh) -> Result<()> {
    let (branch, sha) = (env("GATE_BRANCH")?, env("GATE_SHA")?);
    let base = gh.default_branch()?;
    if branch == base {
        return Ok(());
    }
    // the workflows merge.yml names (its workflow_run list): the repo's CI; a fork's upstream workflows that don't
    // apply here are left out by not naming them
    let gated: Vec<String> = std::env::var("GATE_WORKFLOWS")
        .unwrap_or_default()
        .split(',')
        .map(|w| w.trim().to_string())
        .filter(|w| !w.is_empty())
        .collect();
    let runs_v = gh.get(&format!("/actions/runs?head_sha={sha}&per_page=100"))?;
    let runs: Vec<Run> = runs_v["workflow_runs"]
        .as_array()
        .map(|a| a.as_slice())
        .unwrap_or(&[])
        .iter()
        .filter(|r| r["event"] != "workflow_run" && r["head_branch"] == branch.as_str())
        .filter(|r| gated.is_empty() || gated.iter().any(|w| r["name"] == w.as_str()))
        .map(|r| Run {
            path: r["path"].as_str().unwrap_or("").into(),
            id: r["id"].as_u64().unwrap_or(0),
            status: r["status"].as_str().unwrap_or("").into(),
            conclusion: r["conclusion"].as_str().unwrap_or("").into(),
        })
        .collect();
    let runs = decide::latest(&runs, OWN);
    let current = match gh.call(
        reqwest::Method::GET,
        &format!("/git/ref/heads/{branch}"),
        None,
    )? {
        (200, v) => v["object"]["sha"] == sha.as_str(),
        _ => false,
    };
    let pr = gh.open_pr(&branch)?;
    let rel = match gh.get(&format!("/compare/{base}...{sha}"))?["status"].as_str() {
        Some("ahead") => Rel::Ahead,
        Some("identical") => Rel::Identical,
        Some("behind") => Rel::Behind,
        _ => Rel::Diverged,
    };
    let action = decide::decide(&branch, &runs, current, pr.is_some(), rel);
    println!("{branch} at {sha}: {action:?}");
    match action {
        Action::Wait(why) => {
            if current {
                gh.status(&sha, "pending", &why)?;
            }
            Ok(())
        }
        Action::Fail(why) => gh.status(&sha, "failure", &format!("red: {why}")),
        Action::Green(why) => gh.status(&sha, "success", &why),
        Action::Merge => {
            gh.status(
                &sha,
                "success",
                &format!("{} workflows green; merging into {base}", runs.len()),
            )?;
            let g = Git::new(&gh.repo)?;
            g.git(&[
                "fetch",
                "-q",
                "--filter=blob:none",
                "origin",
                &branch,
                &base,
            ])?;
            match g.git(&["push", "-q", "origin", &format!("{sha}:refs/heads/{base}")]) {
                Ok(_) => {
                    println!("{base} is now {sha}");
                    if let Err(e) = g.git(&["push", "-q", "origin", "--delete", &branch]) {
                        println!("deleting {branch}: {e:#}");
                    }
                    Ok(())
                }
                // main moved since the compare (a pin): bring it in and test again
                Err(e) => {
                    println!("{base} moved while merging ({e:#}): merging it into {branch}");
                    update(gh, &g, &branch, &base, &sha, pr.as_ref())
                }
            }
        }
        Action::Update => {
            let g = Git::new(&gh.repo)?;
            g.git(&[
                "fetch",
                "-q",
                "--filter=blob:none",
                "origin",
                &branch,
                &base,
            ])?;
            update(gh, &g, &branch, &base, &sha, pr.as_ref())
        }
    }
}

/// main merged into the branch (never a force push): the branch's CI runs again on the merge
fn update(gh: &Gh, g: &Git, branch: &str, base: &str, sha: &str, pr: Option<&Value>) -> Result<()> {
    g.git(&["fetch", "-q", "--filter=blob:none", "origin", base])?;
    g.git(&["checkout", "-q", "--detach", sha])?;
    if let Err(e) = g.git(&["merge", "--no-edit", "-q", &format!("origin/{base}")]) {
        let _ = g.git(&["merge", "--abort"]);
        let why = format!("conflicts with {base}: merge {base} into the branch and push");
        gh.status(sha, "failure", &why)?;
        if let Some(n) = pr.and_then(|p| p["number"].as_u64()) {
            let _ = gh.post(&format!("/issues/{n}/comments"), &json!({"body": format!("The gate couldn't merge `{base}` into this branch:\n\n```\n{e:#}\n```\n\nMerge it in and push; CI runs again.")}));
        }
        return Ok(());
    }
    g.git(&["push", "-q", "origin", &format!("HEAD:refs/heads/{branch}")])?;
    gh.status(
        sha,
        "success",
        &format!("green; {base} was merged into the branch, whose CI runs again"),
    )
}

fn main() -> ExitCode {
    let cmd = std::env::args().nth(1).unwrap_or_default();
    let res = Gh::from_env().and_then(|gh| match cmd.as_str() {
        "open" => open(&gh),
        "merge" => merge(&gh),
        _ => Err(anyhow!("usage: gate open|merge")),
    });
    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("gate: {e:#}");
            ExitCode::FAILURE
        }
    }
}
