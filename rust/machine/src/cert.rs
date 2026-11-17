//! The machine's succession cert (main.go `Cert`, core-signed or rebuilt from the kernel's documents) as the machine
//! reads it: unknown fields ignored, as Go's json.Unmarshal.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Machine {
    pub id: String,
    pub image: String,
    #[serde(rename = "encryptionKey")]
    pub encryption_key: String,
    #[serde(rename = "signingKey")]
    pub signing_key: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Options {
    pub harness: String,
    #[serde(rename = "permissionMode")]
    pub permission_mode: String,
    /// the session's settings (vouch.rs)
    pub config: String,
    /// this machine's one-time inputs
    pub once: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Cert {
    pub kind: String,
    #[serde(rename = "predecessorId")]
    pub pred_id: String,
    pub machine: Option<Machine>,
    pub stores: Option<Vec<String>>,
    pub options: Options,
    pub phone: String,
    pub sensitive: bool,
    pub line: String,
    /// sha256 of the predecessor's snapshot, from the core's kill record
    pub snapshot: String,
}

impl Cert {
    /// the machine named (an empty one when none)
    pub fn machine(&self) -> Machine {
        self.machine.clone().unwrap_or_default()
    }

    pub fn stores(&self) -> Vec<String> {
        self.stores.clone().unwrap_or_default()
    }
}

/// the signed permission mode (it replaces the router's env value); a running session raised in place keeps bypass
/// until its next cert, which then signs it
pub fn cert_mode(c: &Cert) -> &'static str {
    if c.options.permission_mode == "bypass" {
        "bypass"
    } else {
        "auto"
    }
}
