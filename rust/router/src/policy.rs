//! The router's policy (policy/stores.json, baked into its image): which stores each harness brings, and whether it
//! runs on a Claude account. The router adds the stores to a session's; the app hides them. The core knows nothing
//! about it.

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// the store whose contents are the core's Fly token (core.FlyStore) — never a session's
pub const FLY_STORE: &str = "core";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Policy {
    pub harnesses: BTreeMap<String, HarnessPolicy>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct HarnessPolicy {
    pub stores: Vec<String>,
    /// its sessions run on a Claude account (claudeaccounts.rs): the one picked, else the default
    #[serde(rename = "claudeAccount", skip_serializing_if = "std::ops::Not::not")]
    pub claude_account: bool,
}

pub fn load_policy(path: &str) -> Result<Policy> {
    let b = std::fs::read(path).map_err(|e| anyhow!("open {path}: {e}"))?;
    match jarvis_go::unmarshal::<Policy>(&b) {
        Ok(p) if !p.harnesses.is_empty() => Ok(p),
        Ok(_) => Err(anyhow!("{path}: not a policy (<nil>)")),
        Err(e) => Err(anyhow!("{path}: not a policy ({e})")),
    }
}
