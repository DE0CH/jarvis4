//! gate: an agent's branch reaches main only when CI is green (Deyao, 2026-11-18). Runs in every agent-pushed
//! repo's workflows (docs/DESIGN.md "Agent branches"), downloaded from this repo's gate release:
//!
//!   gate open    branch.yml, on every push to a branch other than main: open the branch's pull request (a draft for
//!                wip/<topic>) and set the commit's `gate` status pending
//!   gate vendor  a repo's three workflows (gate.yml, branch.yml, merge.yml) from rust/gate/templates
//!   gate setup   one repo's GitHub side, idempotent: the deploy key jarvis-merge and its secret in the `merge`
//!                environment, and main's ruleset requiring the gate (setup.rs; GH_TOKEN is a repo admin's;
//!                GATE_REPOS=owner/name[+actions],…: +actions when the repo's workflows push main with their token)
//!   gate key     one more deploy key for a job that pushes the default branch (GATE_REPO, GATE_ENV, GATE_KEY_TITLE,
//!                GATE_SECRET): the key's private half is that environment's secret
//!   gate merge   merge.yml, when any workflow on a branch finishes (workflow_run: GitHub runs it from main's copy,
//!                so a branch can't change it): once every workflow on the head commit is done, set `gate` green or
//!                red; green on main's head fast-forwards main to that exact commit with the merge deploy key; green
//!                on an older base merges main into the branch, which runs its CI again
//!
//! Environment: GITHUB_REPOSITORY, GH_TOKEN (the workflow's token: pull requests, statuses, actions read),
//! GATE_BRANCH and GATE_SHA (the pushed branch and commit), GATE_RUN_URL (the status's link); merge also
//! GATE_WORKFLOWS (the workflows that make up the repo's CI, comma-separated: merge.yml's list) and MERGE_DEPLOY_KEY (the repo's deploy key `jarvis-merge`, which main's ruleset lets push).

mod decide;
mod setup;
mod vendor;

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
            .request(method.clone(), self.url(path))
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

    /// a path of this repo ("/pulls"), or any repo's when it starts with "/repos/" (gate setup)
    fn url(&self, path: &str) -> String {
        if path.starts_with("/repos/") {
            format!("{}{path}", self.api)
        } else {
            format!("{}/repos/{}{path}", self.api, self.repo)
        }
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
        let ssh = format!(
            "ssh -i {} -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new",
            key.display()
        );
        Git::at(dir, ssh, format!("git@github.com:{repo}.git"))
    }

    /// an empty repo in dir whose origin is url (tests: a local bare repo)
    fn at(dir: tempfile::TempDir, ssh: String, url: String) -> Result<Git> {
        let g = Git { ssh, url, dir };
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
        Action::Merge | Action::MergeIn => {
            gh.status(
                &sha,
                "success",
                &format!("{} workflows green; merging into {base}", runs.len()),
            )?;
            land(gh, &branch, &base, &sha, runs.len(), pr.as_ref())
        }
    }
}

/// what land_git did
#[derive(Debug, PartialEq)]
enum Landed {
    /// main is now this commit (ff: the tested commit itself)
    Pushed { target: String, ff: bool },
    /// main doesn't merge into the commit cleanly
    Conflict(String),
    /// main kept moving under every push
    Moved,
}

/// the green commit into main, git only: a fast-forward when main is its ancestor, else main merged into it and the
/// merge pushed. Main moving during the push is tried again (5 times). Never a force push.
fn land_git(g: &Git, branch: &str, base: &str, sha: &str, n: usize) -> Result<Landed> {
    for attempt in 1..=5 {
        g.git(&["fetch", "-q", "--filter=blob:none", "origin", branch, base])?;
        let main = g.git(&["rev-parse", &format!("refs/remotes/origin/{base}")])?;
        let ff = g.git(&["merge-base", "--is-ancestor", &main, sha]).is_ok();
        let target = if ff {
            sha.to_string()
        } else {
            g.git(&["checkout", "-q", "--detach", sha])?;
            let msg = format!(
                "Merge {branch} into {base}\n\nThe gate: {n} workflows green on {}; {base} merged in cleanly.",
                &sha[..sha.len().min(12)]
            );
            if let Err(e) = g.git(&["merge", "--no-ff", "-q", "-m", &msg, &main]) {
                let _ = g.git(&["merge", "--abort"]);
                return Ok(Landed::Conflict(format!("{e:#}")));
            }
            g.git(&["rev-parse", "HEAD"])?
        };
        match g.git(&[
            "push",
            "-q",
            "origin",
            &format!("{target}:refs/heads/{base}"),
        ]) {
            Ok(_) => return Ok(Landed::Pushed { target, ff }),
            Err(e) => println!("{base} moved while landing (attempt {attempt}): {e:#}"),
        }
    }
    Ok(Landed::Moved)
}

/// land_git, then what it means for the gate's status, the pull request and the branch
fn land(gh: &Gh, branch: &str, base: &str, sha: &str, n: usize, pr: Option<&Value>) -> Result<()> {
    let g = Git::new(&gh.repo)?;
    match land_git(&g, branch, base, sha, n)? {
        Landed::Pushed { target, ff } => {
            println!(
                "{base} is now {target}{}",
                if ff { "" } else { " (a merge)" }
            );
            if let Err(e) = g.git(&["push", "-q", "origin", "--delete", branch]) {
                println!("deleting {branch}: {e:#}");
            }
            Ok(())
        }
        Landed::Conflict(e) => {
            gh.status(
                sha,
                "failure",
                &format!("conflicts with {base}: merge {base} into the branch and push"),
            )?;
            if let Some(num) = pr.and_then(|p| p["number"].as_u64()) {
                let _ = gh.post(
                    &format!("/issues/{num}/comments"),
                    &json!({"body": format!("The gate couldn't merge `{base}` into this branch:\n\n```\n{e}\n```\n\nMerge it in and push; CI runs again.")}),
                );
            }
            Ok(())
        }
        Landed::Moved => {
            gh.status(
                sha,
                "pending",
                &format!("green; {base} kept moving while landing, tried again at the next run"),
            )?;
            bail!("{base} kept moving: not landed")
        }
    }
}

fn main() -> ExitCode {
    let cmd = std::env::args().nth(1).unwrap_or_default();
    // vendor and its help need no token: it only writes files
    if cmd == "vendor" {
        return match vendor() {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("gate: {e:#}");
                ExitCode::FAILURE
            }
        };
    }
    let res = Gh::from_env().and_then(|gh| match cmd.as_str() {
        "open" => open(&gh),
        "merge" => merge(&gh),
        "setup" => setup_repos(&gh),
        "key" => key_one(&gh),
        _ => Err(anyhow!("usage: gate open|merge|setup|vendor")),
    });
    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("gate: {e:#}");
            ExitCode::FAILURE
        }
    }
}

// ---- gate setup ----------------------------------------------------------------------------------------------------

/// every repo the gate runs in, by its workflows (GATE_REPOS: owner/name, comma-separated); `--dry-run` prints the
/// payloads only
fn setup_repos(gh: &Gh) -> Result<()> {
    let repos = env("GATE_REPOS")?;
    let dry = std::env::args().any(|a| a == "--dry-run");
    for entry in repos.split(',').map(str::trim).filter(|r| !r.is_empty()) {
        // owner/name+actions: the repo's workflows push main with the workflow token
        let (repo, actions) = match entry.strip_suffix("+actions") {
            Some(r) => (r, true),
            None => (entry, false),
        };
        match setup_one(gh, repo, actions, dry) {
            Ok(lines) => {
                for l in lines {
                    println!("{repo}: {l}");
                }
            }
            Err(e) => eprintln!("{repo}: {e:#}"),
        }
    }
    Ok(())
}

fn setup_one(gh: &Gh, repo: &str, actions: bool, dry: bool) -> Result<Vec<String>> {
    let mut done = vec![];
    let base = gh.get(&format!("/repos/{repo}"))?;
    let branch = base["default_branch"]
        .as_str()
        .unwrap_or("main")
        .to_string();
    if dry {
        println!(
            "{repo}: ruleset {}",
            setup::ruleset_payload(&branch, actions)
        );
        return Ok(done);
    }
    done.extend(install_key(
        gh,
        repo,
        &branch,
        "merge",
        setup::KEY_TITLE,
        setup::SECRET,
    )?);
    // main's ruleset: made, or the one this tool made before updated in place
    let want = setup::ruleset_payload(&branch, actions);
    let rs = gh.get(&format!("/repos/{repo}/rulesets"))?;
    let mine = rs
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .find(|r| r["name"] == want["name"]);
    match mine {
        Some(r) => {
            let id = r["id"].as_u64().unwrap_or(0);
            gh.call(
                reqwest::Method::PUT,
                &format!("/repos/{repo}/rulesets/{id}"),
                Some(&want),
            )?;
            done.push(format!("ruleset {id} (gate required on {branch})"));
        }
        None => {
            gh.post(&format!("/repos/{repo}/rulesets"), &want)?;
            done.push(format!("ruleset made (gate required on {branch})"));
        }
    }
    Ok(done)
}

/// a write deploy key titled `title` (one with that title replaced) whose private half is the secret `secret` of the
/// environment `env`; an environment that does not exist yet is made, admitting `branch` only (an existing one is
/// left as it is: it may hold reviewers or other secrets)
fn install_key(
    gh: &Gh,
    repo: &str,
    branch: &str,
    env: &str,
    title: &str,
    secret: &str,
) -> Result<Vec<String>> {
    let mut done = vec![];
    let dir = tempfile::tempdir()?;
    let key = dir.path().join("key");
    let st = Command::new("ssh-keygen")
        .args([
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            &format!("jarvis4-{title}@{repo}"),
            "-f",
        ])
        .arg(&key)
        .status()
        .context("running ssh-keygen")?;
    if !st.success() {
        bail!("ssh-keygen failed");
    }
    let public = std::fs::read_to_string(key.with_extension("pub"))?;
    let private = std::fs::read_to_string(&key)?;
    if !public.contains("ed25519") {
        bail!("ssh-keygen wrote no ed25519 key");
    }
    let keys = gh.get(&format!("/repos/{repo}/keys"))?;
    for k in keys.as_array().cloned().unwrap_or_default() {
        if k["title"] == title {
            let id = k["id"].as_u64().unwrap_or(0);
            gh.call(
                reqwest::Method::DELETE,
                &format!("/repos/{repo}/keys/{id}"),
                None,
            )?;
            done.push(format!("deploy key {id} replaced"));
        }
    }
    gh.post(
        &format!("/repos/{repo}/keys"),
        &json!({"title": title, "key": public.trim(), "read_only": false}),
    )?;
    done.push(format!("deploy key {title} (write)"));
    // the environment first: an environment secret reaches only jobs that name the environment, and the
    // environment admits the default branch's runs only, so no branch's workflow can read the key
    let exists = matches!(
        gh.call(
            reqwest::Method::GET,
            &format!("/repos/{repo}/environments/{env}"),
            None
        )?,
        (200, _)
    );
    if !exists {
        gh.call(
            reqwest::Method::PUT,
            &format!("/repos/{repo}/environments/{env}"),
            Some(&setup::environment_payload()),
        )?;
        gh.post(
            &format!("/repos/{repo}/environments/{env}/deployment-branch-policies"),
            &setup::branch_policy_payload(branch),
        )?;
        done.push(format!("environment {env}: {branch} only"));
    } else if env == "merge" {
        // the gate's own environment: make sure it still admits the default branch only
        let pol = gh.get(&format!(
            "/repos/{repo}/environments/{env}/deployment-branch-policies"
        ))?;
        let have = pol["branch_policies"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .iter()
            .any(|p| p["name"] == branch && p["type"] == "branch");
        if !have {
            gh.call(
                reqwest::Method::PUT,
                &format!("/repos/{repo}/environments/{env}"),
                Some(&setup::environment_payload()),
            )?;
            gh.post(
                &format!("/repos/{repo}/environments/{env}/deployment-branch-policies"),
                &setup::branch_policy_payload(branch),
            )?;
        }
        done.push(format!("environment {env}: {branch} only"));
    } else {
        done.push(format!("environment {env} (there, left as it is)"));
    }
    let pk = gh.get(&format!(
        "/repos/{repo}/environments/{env}/secrets/public-key"
    ))?;
    let sealed = seal(pk["key"].as_str().unwrap_or(""), private.as_bytes())?;
    match gh.call(
        reqwest::Method::PUT,
        &format!("/repos/{repo}/environments/{env}/secrets/{secret}"),
        Some(&json!({"encrypted_value": sealed, "key_id": pk["key_id"]})),
    )? {
        (201 | 204, _) => done.push(format!("secret {secret} in environment {env}")),
        (c, v) => bail!("the environment secret: {c} {v}"),
    }
    Ok(done)
}

/// gate key: GATE_REPO, GATE_ENV, GATE_KEY_TITLE, GATE_SECRET — one deploy key for a job that pushes the default
/// branch (a pin, a land job), as install_key makes it
fn key_one(gh: &Gh) -> Result<()> {
    let repo = env("GATE_REPO")?;
    let base = gh.get(&format!("/repos/{repo}"))?;
    let branch = base["default_branch"]
        .as_str()
        .unwrap_or("main")
        .to_string();
    for l in install_key(
        gh,
        &repo,
        &branch,
        &env("GATE_ENV")?,
        &env("GATE_KEY_TITLE")?,
        &env("GATE_SECRET")?,
    )? {
        println!("{repo}: {l}");
    }
    Ok(())
}

/// GitHub's sealed box for an Actions secret (libsodium crypto_box_seal)
fn seal(public_b64: &str, plain: &[u8]) -> Result<String> {
    use base64::Engine;
    let raw = base64::engine::general_purpose::STANDARD.decode(public_b64)?;
    let pk: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("GitHub's public key is not 32 bytes"))?;
    let sealed = crypto_box::PublicKey::from(pk)
        .seal(&mut rand_core::OsRng, plain)
        .map_err(|e| anyhow!("sealing the secret: {e}"))?;
    Ok(base64::engine::general_purpose::STANDARD.encode(sealed))
}

/// gate vendor <dir> [--workflows "a, b"] [--branch main]
fn vendor() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let mut dir = None;
    let mut wfs: Vec<String> = vec!["branch".into()];
    let mut branch = "main".to_string();
    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--workflows" => {
                i += 1;
                if let Some(w) = args.get(i) {
                    wfs.extend(
                        w.split(',')
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty()),
                    );
                }
            }
            "--branch" => {
                i += 1;
                if let Some(b) = args.get(i) {
                    branch = b.clone();
                }
            }
            a if !a.starts_with("--") => dir = Some(a.to_string()),
            a => bail!("unknown {a}"),
        }
        i += 1;
    }
    let dir = dir.ok_or_else(|| {
        anyhow!("usage: gate vendor <dir> [--workflows \"a, b\"] [--branch main]")
    })?;
    let wf = Path::new(&dir).join(".github/workflows");
    std::fs::create_dir_all(&wf)?;
    for (name, body) in [
        ("gate.yml", vendor::GATE.to_string()),
        ("branch.yml", vendor::branch_for(&branch)),
        ("merge.yml", vendor::merge_for(&wfs, &branch)),
    ] {
        std::fs::write(wf.join(name), body)?;
        println!("{}", wf.join(name).display());
    }
    Ok(())
}

#[cfg(test)]
mod land_tests {
    use super::*;

    fn sh(dir: &Path, args: &[&str]) -> String {
        let out = Command::new("git")
            .args(args)
            .current_dir(dir)
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@t")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@t")
            .output()
            .unwrap_or_else(|e| panic!("git: {e}"));
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    /// a bare origin with main, and a work clone to make commits in
    struct Origin {
        _tmp: tempfile::TempDir,
        bare: std::path::PathBuf,
        work: std::path::PathBuf,
    }

    impl Origin {
        fn new() -> Origin {
            let tmp = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
            let bare = tmp.path().join("origin.git");
            let work = tmp.path().join("work");
            sh(
                tmp.path(),
                &[
                    "init",
                    "-q",
                    "--bare",
                    "-b",
                    "main",
                    bare.to_str().unwrap_or(""),
                ],
            );
            sh(
                tmp.path(),
                &[
                    "clone",
                    "-q",
                    bare.to_str().unwrap_or(""),
                    work.to_str().unwrap_or(""),
                ],
            );
            sh(&work, &["checkout", "-q", "-b", "main"]);
            Origin {
                _tmp: tmp,
                bare,
                work,
            }
        }

        fn commit(&self, file: &str, body: &str) -> String {
            std::fs::write(self.work.join(file), body).unwrap_or_else(|e| panic!("{e}"));
            sh(&self.work, &["add", file]);
            sh(&self.work, &["commit", "-q", "-m", file]);
            sh(&self.work, &["rev-parse", "HEAD"])
        }

        fn push(&self, refspec: &str) {
            sh(&self.work, &["push", "-q", "origin", refspec]);
        }

        fn main(&self) -> String {
            sh(&self.bare, &["rev-parse", "refs/heads/main"])
        }

        fn gate(&self) -> Git {
            let g = Git::at(
                tempfile::tempdir().unwrap_or_else(|e| panic!("{e}")),
                "ssh".into(),
                self.bare.to_str().unwrap_or("").into(),
            )
            .unwrap_or_else(|e| panic!("{e:#}"));
            g.git(&["config", "user.name", "gate"])
                .unwrap_or_else(|e| panic!("{e:#}"));
            g
        }
    }

    #[test]
    fn a_commit_on_mains_head_is_mains_new_head() {
        let o = Origin::new();
        o.commit("a", "a");
        o.push("main");
        sh(&o.work, &["checkout", "-q", "-b", "claude/x"]);
        let sha = o.commit("b", "b");
        o.push("claude/x");
        let got =
            land_git(&o.gate(), "claude/x", "main", &sha, 2).unwrap_or_else(|e| panic!("{e:#}"));
        assert_eq!(
            got,
            Landed::Pushed {
                target: sha.clone(),
                ff: true
            }
        );
        assert_eq!(o.main(), sha);
    }

    #[test]
    fn main_moved_meanwhile_is_merged_in_and_the_merge_lands() {
        let o = Origin::new();
        let base = o.commit("a", "a");
        o.push("main");
        sh(&o.work, &["checkout", "-q", "-b", "claude/x"]);
        let sha = o.commit("b", "b");
        o.push("claude/x");
        // a pin lands on main while the branch's CI runs
        sh(&o.work, &["checkout", "-q", &base]);
        let pin = o.commit("pin", "sha-1");
        o.push(&format!("{pin}:refs/heads/main"));
        let got =
            land_git(&o.gate(), "claude/x", "main", &sha, 2).unwrap_or_else(|e| panic!("{e:#}"));
        let Landed::Pushed { target, ff } = got else {
            panic!("not landed: {got:?}")
        };
        assert!(!ff);
        assert_eq!(o.main(), target);
        // the merge holds both, and both parents are the tested commit and the pin
        let parents = sh(&o.bare, &["rev-list", "--parents", "-n", "1", &target]);
        assert!(
            parents.contains(&sha) && parents.contains(&pin),
            "{parents}"
        );
        assert!(!sh(&o.bare, &["log", "-1", "--format=%B", &target]).contains("skip ci"));
    }

    #[test]
    fn a_conflict_with_main_lands_nothing() {
        let o = Origin::new();
        let base = o.commit("a", "a");
        o.push("main");
        sh(&o.work, &["checkout", "-q", "-b", "claude/x"]);
        let sha = o.commit("a", "the branch's a");
        o.push("claude/x");
        sh(&o.work, &["checkout", "-q", &base]);
        let other = o.commit("a", "main's a");
        o.push(&format!("{other}:refs/heads/main"));
        let got =
            land_git(&o.gate(), "claude/x", "main", &sha, 2).unwrap_or_else(|e| panic!("{e:#}"));
        assert!(matches!(got, Landed::Conflict(_)), "{got:?}");
        assert_eq!(o.main(), other, "main changed after a conflict");
    }
}
