//! Sessions of an earlier core (core/legacy.go; Deyao, 2026-10-15: the release of core continuity must not end the
//! sessions running on the random-key core before it). A session whose cert the running core's key didn't sign, but
//! whose core a master-signed claim the router kept names (core-certs.json), is taken over by the running core at its
//! machine's kill: the kill carries the earlier cert and that claim (`legacy`), and the core answers the same cert
//! signed by itself (`adopted`), which becomes the session's cert. A running one is taken over when it pauses; a paused
//! one at once (corechange.rs). The earlier core's carry blob doesn't open on the new core, so the first resume waits
//! for one unlock of the session's stores; the router files that Inbox request itself (note_secrets_pull).

use crate::claimdevice::{CLAIM_DEVICE_MU, MasterCert};
use crate::core::Doc;
use crate::http::verify_p256;
use crate::router::Router;
use jarvis_go::GoTime;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::{LazyLock, Mutex};

pub const LEGACY_WAIT_TEXT: &str =
    "this session's line is an earlier core's: the running core takes it over at its pause";

#[derive(Deserialize, Default)]
#[serde(default)]
struct Key {
    #[serde(rename = "signingKey")]
    signing_key: String,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Claim {
    kind: String,
    master: String,
    core: Key,
    identity: Option<Key>,
}

static ADOPT_TRIED: LazyLock<Mutex<BTreeMap<String, GoTime>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));

impl Router {
    fn kept_core_certs(&self) -> Vec<MasterCert> {
        let _g = CLAIM_DEVICE_MU.lock();
        self.st
            .read_doc("core-certs.json")
            .and_then(|b| jarvis_go::unmarshal(&b).ok())
            .unwrap_or_default()
    }

    /// the kept master-signed claim naming a core whose key signed this document (None: none)
    pub fn claim_of_signer(&self, doc: Option<&Doc>) -> Option<MasterCert> {
        let doc = doc?;
        self.kept_core_certs().into_iter().find(|mc| {
            let Ok(st) = jarvis_go::unmarshal::<Claim>(mc.statement.as_bytes()) else {
                return false;
            };
            verify_p256(&st.core.signing_key, doc.payload.as_bytes(), &doc.sig)
                || st
                    .identity
                    .is_some_and(|i| verify_p256(&i.signing_key, doc.payload.as_bytes(), &doc.sig))
        })
    }

    /// the kill's `legacy` for a machine whose cert the running core (key) didn't sign; None when it did, or when no
    /// kept claim names the core that did
    pub fn legacy_for(&self, machine: &str, key: &str) -> Option<Value> {
        let cert = self.st.do_(|d| d.certs.get(machine).cloned())?;
        if key.is_empty() || verify_p256(key, cert.payload.as_bytes(), &cert.sig) {
            return None;
        }
        let mc = self.claim_of_signer(Some(&cert))?;
        Some(json!({"cert": cert, "coreCert": mc}))
    }

    /// the kill's answer took the machine's line over: its cert (the same payload, the running core's signature)
    /// replaces the earlier one, and the session's first resume will wait for an unlock (carry_lost)
    pub fn adopted(&self, machine: &str, kd: Option<&Doc>) {
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct K {
            adopted: Option<Doc>,
        }
        let Some(a) = kd
            .and_then(|d| d.decode::<K>().ok())
            .and_then(|k| k.adopted)
        else {
            return;
        };
        self.st.do_(|d| {
            if d.certs.get(machine).is_none_or(|old| old.payload != a.payload) {
                return;
            }
            d.certs.insert(machine.to_string(), a.clone());
            for s in d.sessions.values_mut() {
                if s.cert.as_ref().is_some_and(|c| c.payload == a.payload) {
                    s.cert = Some(a.clone());
                    s.old_core = false;
                    s.carry_lost = true;
                    if s.error == LEGACY_WAIT_TEXT {
                        s.error.clear();
                    }
                    crate::logf!("session {}: its line was taken over by the running core at {machine}'s kill", s.id);
                }
            }
        });
    }

    /// a paused session of an earlier core, taken over now (its machine is long gone; the kill names the snapshot its
    /// machine signed, which the router keeps)
    pub fn adopt_paused(&self, id: &str) {
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct M {
            id: String,
        }
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct C {
            machine: Option<M>,
        }
        let machine = self.st.do_(|d| {
            d.sessions
                .get(id)
                .filter(|s| s.state == "paused")
                .and_then(|s| s.cert.as_ref())
                .and_then(|c| c.decode::<C>().ok())
                .and_then(|c| c.machine)
                .map(|m| m.id)
                .unwrap_or_default()
        });
        if machine.is_empty() {
            return;
        }
        {
            let mut g = ADOPT_TRIED.lock().unwrap_or_else(|e| e.into_inner());
            if g.get(id)
                .is_some_and(|t| t.since() < time::Duration::minutes(10))
            {
                return;
            }
            g.insert(id.to_string(), GoTime::now());
        }
        if let Err(e) = self.kill_machine(&machine, false) {
            crate::logf!("session {id} (an earlier core's, paused): taking its line over: {e:#}");
        }
    }

    /// the router keeps the master-signed claim of the running core (it keeps every claim it passes on; a core claimed
    /// before the router did answers its own GET /core-cert), so a later core can take its lines over
    pub fn keep_running_claim(&self, key: &str) {
        for mc in self.kept_core_certs() {
            if let Ok(st) = jarvis_go::unmarshal::<Claim>(mc.statement.as_bytes())
                && (st.core.signing_key == key || st.identity.is_some_and(|i| i.signing_key == key))
            {
                return;
            }
        }
        let Ok((200, b)) = self.core.raw("GET", "/core-cert", None) else {
            return;
        };
        let Ok(mc) = jarvis_go::unmarshal::<MasterCert>(&b) else {
            return;
        };
        let Ok(st) = jarvis_go::unmarshal::<Claim>(mc.statement.as_bytes()) else {
            return;
        };
        if st.kind != "claim"
            || st.core.signing_key != key
            || !verify_p256(&st.master, mc.statement.as_bytes(), &mc.master_sig)
        {
            return;
        }
        self.keep_core_cert(&b);
        crate::logf!(
            "kept the running core's claim ({}…), for a later core to take its sessions over",
            jarvis_go::fmt::clip_bytes(key, 16)
        );
    }
}
