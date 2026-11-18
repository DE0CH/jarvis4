//! `gate vendor <dir>`: the three workflows the gate needs in a repo, from the templates beside this file, so every
//! repo gets the same ones (gate.yml included: a private repo can't call another private repo's reusable workflow).
//! merges: the names of the repo's CI workflows, as merge.yml's `on.workflow_run.workflows` takes them.

pub const GATE: &str = include_str!("../templates/gate.yml");
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
        assert!(m.contains(r#"workflows: "branch, ci, ios""#));
        assert!(m.contains("branches-ignore: [master]") || m.contains("default_branch"));
        assert!(!m.contains("{{WORKFLOWS}}"));
    }

    #[test]
    fn branch_ignores_the_default_branch() {
        assert!(branch_for("main").contains("branches-ignore: [main]"));
    }

    #[test]
    fn the_templates_call_the_gate_locally_and_fetch_the_pinned_binary() {
        assert!(GATE.contains("workflow_call"));
        assert!(GATE.contains("raw.githubusercontent.com/DE0CH/jarvis4/main/rust/gate/pin.txt"));
        assert!(BRANCH.contains("uses: ./.github/workflows/gate.yml"));
        assert!(MERGE.contains("uses: ./.github/workflows/gate.yml"));
        assert!(!GATE.contains("{{WORKFLOWS}}"));
    }
}
