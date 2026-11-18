//! What the gate does with a branch's commit once a workflow on it has finished: a pure function of what GitHub
//! reports, so the rule is tested alone (Deyao, 2026-11-18: an agent's change reaches main only when CI is green).
//!
//! The one rule: a commit whose every workflow is green goes into main. On main's head it is main's new head (a
//! fast-forward); on an older base main is merged into it and the merge, if clean, is main's new head without another
//! run (Deyao, 2026-11-18: main moves every 15-30 min in jarvis4, faster in aviary, and a branch re-tested for each
//! move would never land; main's own CI runs on the merge). A branch pushed again meanwhile is left to the newer
//! push's own runs.

/// one workflow run on the branch's head commit, as the Actions API lists it
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Run {
    /// .github/workflows/<file>
    pub path: String,
    /// the commit it ran on
    pub sha: String,
    pub id: u64,
    /// queued | in_progress | completed | …
    pub status: String,
    /// success | failure | cancelled | skipped | neutral | timed_out | … ("" until completed)
    pub conclusion: String,
}

/// how the tested commit stands against main (the compare API's status of main...commit)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rel {
    /// main is an ancestor: a fast-forward
    Ahead,
    Identical,
    /// the commit is already in main
    Behind,
    /// main moved on since the branch left it
    Diverged,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// not every run is over: the status stays pending; the last run's completion decides
    Wait(String),
    /// a run failed: the gate is red, nothing merges
    Fail(String),
    /// green, and nothing to merge (a wip/ branch, no open pull request, already in main)
    Green(String),
    /// green on an older base: main merged into the commit, the merge (when clean) main's new head
    MergeIn,
    /// green on main's head: main moves to this commit
    Merge,
}

/// a workflow's conclusion that lets the commit through
fn passed(conclusion: &str) -> bool {
    matches!(conclusion, "success" | "skipped" | "neutral")
}

/// the newest run of each workflow on any of the branch's own commits (`commits`: those since it left main, the head
/// among them), the gate's own runs left out. A later commit that doesn't start a workflow (its paths untouched)
/// carries that workflow's last result on the branch: a red iOS run stays red under a README-only push, and a change
/// the workflow reads starts a newer run. Run ids grow with time; a re-run keeps its id and its newest result.
pub fn latest(runs: &[Run], commits: &std::collections::BTreeSet<String>, own: &str) -> Vec<Run> {
    let mut by: std::collections::BTreeMap<&str, &Run> = std::collections::BTreeMap::new();
    for r in runs
        .iter()
        .filter(|r| r.path != own && commits.contains(&r.sha))
    {
        if by.get(r.path.as_str()).is_none_or(|o| r.id > o.id) {
            by.insert(&r.path, r);
        }
    }
    by.into_values().cloned().collect()
}

/// branch: the head branch; current: the branch still points at the tested commit; pr_open: its pull request is open
pub fn decide(branch: &str, runs: &[Run], current: bool, pr_open: bool, rel: Rel) -> Action {
    if !current {
        return Action::Wait("the branch was pushed again: its newer commit decides".into());
    }
    if runs.is_empty() {
        return Action::Wait("no workflow has run on this commit yet".into());
    }
    let open: Vec<&Run> = runs.iter().filter(|r| r.status != "completed").collect();
    if !open.is_empty() {
        return Action::Wait(format!(
            "{} of {} workflows still running",
            open.len(),
            runs.len()
        ));
    }
    let failed: Vec<String> = runs
        .iter()
        .filter(|r| !passed(&r.conclusion))
        .map(|r| format!("{} {}", file_name(&r.path), r.conclusion))
        .collect();
    if !failed.is_empty() {
        return Action::Fail(failed.join(", "));
    }
    let n = runs.len();
    if branch.starts_with("wip/") {
        return Action::Green(format!("{n} workflows green; a wip/ branch is not merged"));
    }
    if !pr_open {
        return Action::Green(format!(
            "{n} workflows green; its pull request is not open, so it is not merged"
        ));
    }
    match rel {
        Rel::Ahead => Action::Merge,
        Rel::Diverged => Action::MergeIn,
        Rel::Identical | Rel::Behind => {
            Action::Green(format!("{n} workflows green; already in main"))
        }
    }
}

pub fn file_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(path: &str, id: u64, status: &str, conclusion: &str) -> Run {
        on("head", path, id, status, conclusion)
    }

    fn on(sha: &str, path: &str, id: u64, status: &str, conclusion: &str) -> Run {
        Run {
            path: format!(".github/workflows/{path}"),
            sha: sha.into(),
            id,
            status: status.into(),
            conclusion: conclusion.into(),
        }
    }

    fn green() -> Vec<Run> {
        vec![
            run("branch.yml", 1, "completed", "success"),
            run("images.yml", 2, "completed", "success"),
        ]
    }

    #[test]
    fn a_green_commit_on_mains_head_merges() {
        assert_eq!(
            decide("claude/x", &green(), true, true, Rel::Ahead),
            Action::Merge
        );
    }

    #[test]
    fn a_run_still_going_waits() {
        let mut runs = green();
        runs.push(run("ios.yml", 3, "in_progress", ""));
        assert!(
            matches!(decide("claude/x", &runs, true, true, Rel::Ahead), Action::Wait(w) if w == "1 of 3 workflows still running")
        );
    }

    #[test]
    fn a_failed_or_cancelled_run_fails_the_gate() {
        let mut runs = green();
        runs.push(run("ios.yml", 3, "completed", "failure"));
        runs.push(run("k8s.yml", 4, "completed", "cancelled"));
        assert_eq!(
            decide("claude/x", &runs, true, true, Rel::Ahead),
            Action::Fail("ios.yml failure, k8s.yml cancelled".into())
        );
    }

    #[test]
    fn skipped_and_neutral_runs_pass() {
        let mut runs = green();
        runs.push(run("aws.yml", 3, "completed", "skipped"));
        runs.push(run("lint.yml", 4, "completed", "neutral"));
        assert_eq!(
            decide("claude/x", &runs, true, true, Rel::Ahead),
            Action::Merge
        );
    }

    #[test]
    fn an_old_base_gets_main_merged_in_and_lands_without_another_run() {
        assert_eq!(
            decide("claude/x", &green(), true, true, Rel::Diverged),
            Action::MergeIn
        );
    }

    #[test]
    fn a_branch_pushed_again_is_left_to_its_newer_commit() {
        assert!(matches!(
            decide("claude/x", &green(), false, true, Rel::Ahead),
            Action::Wait(_)
        ));
    }

    #[test]
    fn wip_branches_and_closed_pull_requests_never_merge() {
        assert!(matches!(
            decide("wip/x", &green(), true, true, Rel::Ahead),
            Action::Green(_)
        ));
        assert!(matches!(
            decide("claude/x", &green(), true, false, Rel::Ahead),
            Action::Green(_)
        ));
        assert!(matches!(
            decide("claude/x", &green(), true, true, Rel::Identical),
            Action::Green(_)
        ));
    }

    #[test]
    fn no_runs_yet_waits() {
        assert!(matches!(
            decide("claude/x", &[], true, true, Rel::Ahead),
            Action::Wait(_)
        ));
    }

    fn commits(shas: &[&str]) -> std::collections::BTreeSet<String> {
        shas.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn the_newest_run_of_each_workflow_counts_and_the_gates_own_never() {
        let runs = vec![
            run("images.yml", 5, "completed", "failure"),
            run("images.yml", 9, "completed", "success"),
            run("merge.yml", 10, "in_progress", ""),
        ];
        let l = latest(&runs, &commits(&["head"]), ".github/workflows/merge.yml");
        assert_eq!(l, vec![run("images.yml", 9, "completed", "success")]);
    }

    #[test]
    fn a_later_commit_that_starts_no_workflow_keeps_the_earlier_red() {
        // the code push turned ios red; a README push after it starts only branch.yml
        let runs = vec![
            on("c1", "ios.yml", 3, "completed", "failure"),
            on("c1", "branch.yml", 4, "completed", "success"),
            on("c2", "branch.yml", 7, "completed", "success"),
        ];
        let l = latest(
            &runs,
            &commits(&["c1", "c2"]),
            ".github/workflows/merge.yml",
        );
        assert_eq!(
            decide("claude/x", &l, true, true, Rel::Ahead),
            Action::Fail("ios.yml failure".into())
        );
    }

    #[test]
    fn runs_on_commits_outside_the_branch_dont_count() {
        // a branch of the same name before, deleted and made again: its old red is not this branch's
        let runs = vec![
            on("old", "ios.yml", 1, "completed", "failure"),
            on("c1", "branch.yml", 4, "completed", "success"),
        ];
        let l = latest(&runs, &commits(&["c1"]), ".github/workflows/merge.yml");
        assert_eq!(
            decide("claude/x", &l, true, true, Rel::Ahead),
            Action::Merge
        );
    }
}
