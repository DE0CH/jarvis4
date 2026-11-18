//! Since core continuity (core/continuity.go, Deyao 2026-10-15) a Recover with the same kit brings back the SAME core,
//! so its sessions are untouched: only a session whose cert the running core's key didn't sign is an earlier core's.
//! A new core can't continue the lines of the core before it. Deyao, 2026-10-11: "They are just automatically
//! destroyed." So when the router sees a new core identity it marks every session that has a line (old_core) and
//! destroys each one once it is paused, the normal way (legacy.rs takes over the ones a kept claim names).

use crate::core::Doc;
use crate::router::Router;
use jarvis_go::GoTime;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

pub const CORE_CHANGE_EVERY: Duration = Duration::from_secs(30);

/// a destroy that failed is tried again 10 minutes later, not every tick
static OLD_CORE_TRIED: LazyLock<Mutex<BTreeMap<String, GoTime>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));

impl Router {
    pub fn core_change_loop(self: &Arc<Self>) {
        loop {
            crate::leaderlease::await_lead();
            self.core_change_tick();
            std::thread::sleep(CORE_CHANGE_EVERY);
        }
    }

    /// the running core's signing key, from an identity whose state document it signed itself ("" when the core can't
    /// be reached or answers something else: nothing is decided on that)
    pub fn core_identity_key(&self) -> String {
        let Ok((200, b)) = self.core.raw("GET", "/identity", None) else {
            return String::new();
        };
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct Id {
            #[serde(rename = "signingKey")]
            signing_key: String,
            state: Doc,
        }
        let Ok(id) = jarvis_go::unmarshal::<Id>(&b) else {
            return String::new();
        };
        if id.signing_key.is_empty()
            || !crate::http::verify_p256(
                &id.signing_key,
                id.state.payload.as_bytes(),
                &id.state.sig,
            )
        {
            return String::new();
        }
        // an empty core shows only the keys it was started with; nothing is decided before it is set up
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct St {
            master: String,
        }
        match id.state.decode::<St>() {
            Ok(st) if !st.master.is_empty() => id.signing_key,
            _ => String::new(),
        }
    }

    pub fn core_change_tick(self: &Arc<Self>) {
        let key = self.core_identity_key();
        if key.is_empty() {
            return;
        }
        self.keep_running_claim(&key); // legacy.rs: so its sessions can be taken over by whatever core comes next
        let (marked, gone) = self.st.do_(|d| {
            let mut marked = 0;
            if d.core_key != key {
                let first = d.core_key.is_empty();
                d.core_key = key.clone(); // first sight (a router that predates this): the sessions are this core's
                if !first {
                    for s in d.sessions.values_mut() {
                        // a cert the new core's key signed is still this core's (core/continuity.go)
                        if let Some(c) = &s.cert
                            && !s.old_core
                            && !crate::http::verify_p256(&key, c.payload.as_bytes(), &c.sig)
                        {
                            s.old_core = true;
                            marked += 1;
                        }
                    }
                }
            }
            let gone: Vec<String> = d
                .sessions
                .iter()
                .filter(|(_, s)| s.old_core && s.state == "paused")
                .map(|(id, _)| id.clone())
                .collect();
            (marked, gone)
        });
        // legacy.rs: a session whose earlier core a kept master-signed claim names isn't destroyed: the running core
        // takes its line over; only the rest go
        let mut keep = vec![];
        for id in gone {
            let cert = self
                .st
                .do_(|d| d.sessions.get(&id).and_then(|s| s.cert.clone()));
            if self.claim_of_signer(cert.as_ref()).is_some() {
                let r = self.clone();
                std::thread::spawn(move || r.adopt_paused(&id));
                continue;
            }
            keep.push(id);
        }
        if marked > 0 {
            crate::logf!(
                "a new core ({}…): {marked} session(s) belong to an earlier core: taken over at their pause when a kept claim names that core, else destroyed once paused",
                jarvis_go::fmt::clip_bytes(&key, 16)
            );
        }
        for id in keep {
            let recent = {
                let mut g = OLD_CORE_TRIED.lock().unwrap_or_else(|e| e.into_inner());
                let recent = g
                    .get(&id)
                    .is_some_and(|t| t.since() < time::Duration::minutes(10));
                if !recent {
                    g.insert(id.clone(), GoTime::now());
                }
                recent
            };
            if recent {
                continue;
            }
            match self.destroy_opts(&id, Default::default()) {
                Err(e) => crate::logf!("session {id} (an earlier core's): destroy: {e:#}"),
                Ok(()) => crate::logf!(
                    "session {id} (an earlier core's): destroying; Restore it from Previous as a new line"
                ),
            }
        }
    }
}
