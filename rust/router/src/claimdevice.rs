//! The app's device-key countersignature on a claim (R1 audit 2026-10-11: claim is first-come, so a router or box that
//! claims an emptied core with its own master key must not get the setup session's writes). The router keeps the last
//! few and serves them to the setup session (GET /setup/claim-device), which checks the signature itself against the
//! device key it pinned. And the master's signature on the core (R2): a claim the core accepted, kept by the router and
//! served to the setup session (GET /setup/core-cert) and into each archive.

use crate::router::Router;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ClaimDevice {
    pub statement: String,
    #[serde(rename = "deviceKey")]
    pub device_key: String,
    #[serde(rename = "deviceSig")]
    pub device_sig: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct MasterCert {
    pub statement: String,
    #[serde(rename = "masterSig")]
    pub master_sig: String,
}

static CLAIM_DEVICE_MU: Mutex<()> = Mutex::new(());

impl Router {
    pub fn claim_devices(&self) -> Vec<ClaimDevice> {
        let _g = CLAIM_DEVICE_MU.lock();
        self.st
            .read_doc("claim-device.json")
            .and_then(|b| jarvis_go::unmarshal(&b).ok())
            .unwrap_or_default()
    }

    /// the countersignature in a claim body, if any (the newest 10 kept)
    pub fn keep_claim_device(&self, body: &[u8]) {
        let Ok(i) = jarvis_go::unmarshal::<ClaimDevice>(body) else { return };
        if i.statement.is_empty()
            || i.device_key.is_empty()
            || i.device_sig.is_empty()
            || i.statement.len() > 8 << 10
            || i.device_key.len() > 200
            || i.device_sig.len() > 200
        {
            return;
        }
        let mut list = self.claim_devices();
        let _g = CLAIM_DEVICE_MU.lock();
        list.insert(0, i);
        list.truncate(10);
        if let Err(e) = self.st.write_doc("claim-device.json", jarvis_go::marshal(&list).as_bytes()) {
            crate::logf!("claim device: {e:#}");
        }
    }

    /// a claim body the core answered 200
    pub fn keep_core_cert(&self, body: &[u8]) {
        let Ok(i) = jarvis_go::unmarshal::<MasterCert>(body) else { return };
        if i.statement.is_empty() || i.master_sig.is_empty() || i.statement.len() > 8 << 10 {
            return;
        }
        let _g = CLAIM_DEVICE_MU.lock();
        let mut list: Vec<MasterCert> = self
            .st
            .read_doc("core-certs.json")
            .and_then(|b| jarvis_go::unmarshal(&b).ok())
            .unwrap_or_default();
        list.insert(0, i);
        list.truncate(10);
        if let Err(e) = self.st.write_doc("core-certs.json", jarvis_go::marshal(&list).as_bytes()) {
            crate::logf!("core certs: {e:#}");
        }
    }

    /// the kept claim naming the running core (by its signing key from /identity); None when none. A core claimed
    /// before the router kept them still answers GET /core-cert.
    pub fn core_cert(&self) -> Option<Vec<u8>> {
        let key = self.core.key().ok()?;
        let sk = key.get("signingKey").cloned().unwrap_or_default();
        let list: Vec<MasterCert> = {
            let _g = CLAIM_DEVICE_MU.lock();
            self.st
                .read_doc("core-certs.json")
                .and_then(|b| jarvis_go::unmarshal(&b).ok())
                .unwrap_or_default()
        };
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct K {
            #[serde(rename = "signingKey")]
            signing_key: String,
        }
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct St {
            core: K,
            /// a claim with the master key's seed names the keys the core takes from it (core/continuity.go)
            identity: Option<K>,
        }
        for mc in list {
            if let Ok(st) = jarvis_go::unmarshal::<St>(mc.statement.as_bytes())
                && (st.core.signing_key == sk || st.identity.is_some_and(|i| i.signing_key == sk))
            {
                return Some(jarvis_go::marshal(&mc).into_bytes());
            }
        }
        match self.core.raw("GET", "/core-cert", None) {
            Ok((200, b)) => Some(b),
            _ => None,
        }
    }
}
