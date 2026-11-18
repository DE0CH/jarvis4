//! `gate vendor <dir>`: the two workflows the gate needs in a repo, from the templates beside this file, so every repo
//! gets the same ones. Each holds its job itself, not a call to a reusable workflow: a job inside a called workflow
//! got the `merge` environment's secret empty (2026-11-18), and a private repo can't call another's anyway.
//! merges: the names of the repo's CI workflows, as merge.yml's `on.workflow_run.workflows` takes them.

pub const BRANCH: &str = include_str!("../templates/branch.yml");
pub const MERGE: &str = include_str!("../templates/merge.yml");

pub fn merge_for(workflows: &[String], branch: &str) -> String {
    MERGE
        .replace("{{WORKFLOWS}}", &workflows.join(", "))
        .replace(
            "branches-ignore: [main]",
            &format!("branches-ignore: [{branch}]"),
        )
}

pub fn branch_for(branch: &str) -> String {
    BRANCH.replace(
        "branches-ignore: [main]",
        &format!("branches-ignore: [{branch}]"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wfs() -> Vec<String> {
        ["branch", "ci", "ios"].map(String::from).to_vec()
    }

    #[test]
    fn merge_names_the_repos_ci_twice_and_its_default_branch() {
        let m = merge_for(&wfs(), "master");
        assert!(m.contains("workflows: [branch, ci, ios]"));
        assert!(m.contains(r#"GATE_WORKFLOWS: "branch, ci, ios""#));
        assert!(m.contains("branches-ignore: [master]") || m.contains("default_branch"));
        assert!(!m.contains("{{WORKFLOWS}}"));
    }

    #[test]
    fn branch_ignores_the_default_branch() {
        assert!(branch_for("main").contains("branches-ignore: [main]"));
    }

    #[test]
    fn each_template_holds_its_job_and_fetches_the_pinned_binary() {
        for t in [BRANCH, MERGE] {
            assert!(t.contains("raw.githubusercontent.com/DE0CH/jarvis4/main/rust/gate/pin.txt"));
            assert!(!t.contains("workflow_call") && !t.contains("uses: ./"));
        }
        // the deploy key reaches only the merge job, through its environment
        assert!(MERGE.contains("environment: merge") && MERGE.contains("secrets.MERGE_DEPLOY_KEY"));
        assert!(!BRANCH.contains("secrets."));
    }
}
