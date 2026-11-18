//! `gate setup`: what the gate needs on GitHub in a repo (Deyao, 2026-11-18), idempotent so it can run again after a
//! change: a deploy key `jarvis-merge` with write access and its private half as the `merge` environment's
//! MERGE_DEPLOY_KEY (the environment admits main only), and main's ruleset, which adds the required status `gate` to
//! what main already had (admins and deploy keys still bypass: Deyao, 2026-11-18).
//!
//! The payloads are pure functions here, so they are tested alone; the calls are the caller's.

use serde_json::{Value, json};

/// GitHub Actions' app: the bypass a repo needs when its own workflows push main with the workflow token
pub const ACTIONS_APP: i64 = 15368;

/// main's ruleset: no deletion, no force push, updates only by the bypass actors, and the required status `gate`.
/// actions: the repo's workflows push main with the workflow token (a pin, a land job), so GitHub Actions bypasses too
pub fn ruleset_payload(branch: &str, actions: bool) -> Value {
    let mut v = json!({
        "name": "main: the gate, admins and deploy keys",
        "target": "branch",
        "enforcement": "active",
        "conditions": {"ref_name": {"include": [format!("refs/heads/{branch}")], "exclude": []}},
        "rules": [
            {"type": "deletion"},
            {"type": "non_fast_forward"},
            {"type": "update"},
            {"type": "required_status_checks", "parameters": {
                "strict_required_status_checks_policy": false,
                "do_not_enforce_on_create": true,
                "required_status_checks": [{"context": "gate"}]
            }}
        ],
        // deploy keys (the pins, the gate's merge key, agents' pushes, which the claude-env hook turns away first) and
        // the admin role (5, Deyao) keep updating main
        "bypass_actors": [
            {"actor_id": null, "actor_type": "DeployKey", "bypass_mode": "always"},
            {"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always"}
        ]
    });
    if actions && let Some(b) = v["bypass_actors"].as_array_mut() {
        b.push(
            json!({"actor_id": ACTIONS_APP, "actor_type": "Integration", "bypass_mode": "always"}),
        );
    }
    v
}

/// the `merge` environment: main only, through a custom branch policy
pub fn environment_payload() -> Value {
    json!({
        "deployment_branch_policy": {"protected_branches": false, "custom_branch_policies": true}
    })
}

pub fn branch_policy_payload(branch: &str) -> Value {
    json!({"name": branch, "type": "branch"})
}

/// the secret's name and the deploy key's title
pub const SECRET: &str = "MERGE_DEPLOY_KEY";
pub const KEY_TITLE: &str = "jarvis-merge";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ruleset_keeps_what_main_had_and_adds_the_gate() {
        let v = ruleset_payload("main", false);
        let rules: Vec<&str> = v["rules"]
            .as_array()
            .map(|a| a.iter().filter_map(|r| r["type"].as_str()).collect())
            .unwrap_or_default();
        assert_eq!(
            rules,
            [
                "deletion",
                "non_fast_forward",
                "update",
                "required_status_checks"
            ]
        );
        assert_eq!(v["conditions"]["ref_name"]["include"][0], "refs/heads/main");
        let check = &v["rules"][3]["parameters"]["required_status_checks"][0]["context"];
        assert_eq!(check, "gate");
        // without the DeployKey entry every pin and the gate's own merge would be refused
        assert_eq!(v["bypass_actors"][0]["actor_type"], "DeployKey");
        assert_eq!(v["bypass_actors"][1]["actor_type"], "RepositoryRole");
        assert_eq!(v["bypass_actors"][1]["actor_id"], 5);
    }

    #[test]
    fn a_repo_whose_workflows_push_main_lets_actions_through() {
        let v = ruleset_payload("main", true);
        assert_eq!(v["bypass_actors"].as_array().map(Vec::len), Some(3));
        assert_eq!(v["bypass_actors"][2]["actor_id"], ACTIONS_APP);
        assert_eq!(
            ruleset_payload("main", false)["bypass_actors"]
                .as_array()
                .map(Vec::len),
            Some(2)
        );
    }

    #[test]
    fn another_default_branch() {
        let v = ruleset_payload("master", false);
        assert_eq!(
            v["conditions"]["ref_name"]["include"][0],
            "refs/heads/master"
        );
    }

    #[test]
    fn the_environment_takes_a_branch_policy_of_its_own() {
        assert_eq!(
            environment_payload()["deployment_branch_policy"]["custom_branch_policies"],
            true
        );
        assert_eq!(
            branch_policy_payload("main"),
            json!({"name": "main", "type": "branch"})
        );
    }
}
