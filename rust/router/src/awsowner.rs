//! Who owns an AWS instance that is no session's machine (Deyao, 2026-11-12: "there should be an ownership tracked by
//! jarvis 4": the budget view warned about the bake's builders on every image pin).
//!
//! Whatever starts an instance outside the spawner names its owner in the tag jarvis4_owner. One kind today:
//! "github-run:<run id>", a run of a workflow of this repo (infra/aws/bake.sh's builder and test instances). While the
//! run is queued or in progress the instance is owned; once it is over, an instance it left behind is a stray again.
//! The tag is not a credential: it only decides which row of the budget view an instance is in.

use anyhow::{Result, anyhow};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::sync::{LazyLock, Mutex};

/// the repo whose workflow runs may own an instance
pub const OWNER_REPO: &str = "DE0CH/jarvis4";

/// what the router found out about an instance's jarvis4_owner tag
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AwsOwner {
    /// "workflow aws, run 43185774604 (in progress)"
    pub text: String,
    /// the owner is still at work: not a stray
    pub live: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct GhRun {
    pub name: String,
    pub status: String,
    pub conclusion: String,
}

static OWNER_RUN_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"^github-run:([0-9]{1,20})$").unwrap_or_else(|e| panic!("{e}")));

/// a finished run never changes: looked up once
static OWNER_RUNS: LazyLock<Mutex<BTreeMap<String, GhRun>>> = LazyLock::new(|| Mutex::new(BTreeMap::new()));

type RunFn = fn(&str) -> Result<GhRun>;

/// tests replace GitHub
pub static GITHUB_RUN: Mutex<Option<RunFn>> = Mutex::new(None);

/// one workflow run of OWNER_REPO (a public repo: the read token only lifts the rate limit)
pub fn github_run(id: &str) -> Result<GhRun> {
    if let Some(f) = GITHUB_RUN.lock().ok().and_then(|g| *g) {
        return f(id);
    }
    let mut req = crate::repos::github_client()
        .get(format!("{}/repos/{OWNER_REPO}/actions/runs/{id}", crate::repos::github_api()))
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .header("User-Agent", "jarvis2-router/1");
    if let Ok(t) = std::env::var("GITHUB_READ_TOKEN")
        && !t.is_empty()
    {
        req = req.bearer_auth(t);
    }
    let resp = req.send()?;
    let status = resp.status().as_u16();
    let b = crate::util::read_limited(resp, 4 << 20)?;
    if status != 200 {
        return Err(anyhow!("GitHub answered {status}"));
    }
    match jarvis_go::unmarshal::<GhRun>(&b) {
        Ok(r) if !r.status.is_empty() => Ok(r),
        _ => Err(anyhow!("GitHub's answer has no run status")),
    }
}

/// the owner a jarvis4_owner tag names, and whether it is still at work
pub fn resolve_aws_owner(tag: &str) -> AwsOwner {
    if tag.is_empty() {
        return AwsOwner::default();
    }
    let Some(m) = OWNER_RUN_RE.captures(tag) else {
        return AwsOwner { text: format!("owner tag {tag} (a kind the router doesn't know)"), live: false };
    };
    let id = m[1].to_string();
    let cached = OWNER_RUNS.lock().ok().and_then(|g| g.get(&id).cloned());
    let run = match cached {
        Some(r) => r,
        None => match github_run(&id) {
            Err(e) => {
                return AwsOwner { text: format!("workflow run {id} (not checked: {e:#})"), live: false };
            }
            Ok(r) => {
                if r.status == "completed"
                    && let Ok(mut g) = OWNER_RUNS.lock()
                {
                    g.insert(id.clone(), r.clone());
                }
                r
            }
        },
    };
    let name = format!("workflow {}", run.name).trim().to_string();
    if run.status == "completed" {
        return AwsOwner { text: format!("left by {name}, run {id} ({})", run.conclusion), live: false };
    }
    AwsOwner {
        text: format!("{name}, run {id} ({})", run.status.replace('_', " ")),
        live: true,
    }
}

/// the owner of every live instance carrying the tag, by instance id (one lookup per run)
pub fn aws_owners(ins: &[crate::awsbudget::AwsInstance]) -> BTreeMap<String, AwsOwner> {
    let mut out = BTreeMap::new();
    let mut by_tag: BTreeMap<String, AwsOwner> = BTreeMap::new();
    for i in ins {
        if i.owner.is_empty() || i.state == "terminated" || i.state == "shutting-down" {
            continue;
        }
        let o = by_tag
            .entry(i.owner.clone())
            .or_insert_with(|| resolve_aws_owner(&i.owner))
            .clone();
        out.insert(i.id.clone(), o);
    }
    out
}
