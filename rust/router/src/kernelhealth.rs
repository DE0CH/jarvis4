//! The kernel's health, for a router that runs no core (NO_CORE=1, Jarvis 4): what the app's Sessions page warns about
//! in place of the old "Core not answering". Every replica checks it on its own (read-only: GET /roster on each
//! component of both copies), every KERNEL_HEALTH_EVERY, and GET /api/state carries the last answer:
//!
//! ```text
//! "kernel": {"checked": true, "healthy": false, "problems": ["notary-blue not answering", …], "at": …,
//!            "copies": {"blue": {"serving": true, "components": {"notary-blue": "ok", …}}, "green": {…}}}
//! ```
//!
//! Healthy means: this box has a kernel, the root key has signed a roster, it isn't stale, every component of the
//! serving copy answers and holds exactly that roster, and no copy flip is waiting (kernelflip.rs). The other copy is
//! shown as it is: idle between releases (its Deployments scaled to zero: "down"), or, once a release landed on it,
//! holding its own roster ("ok" against the other copy's roster while it takes over). GET /api/kernel carries the same
//! under "health".

use crate::kernel::KERNEL_COPIES;
use crate::roster::{KERNEL_ROLES, roster_targets};
use crate::router::Router;
use jarvis_go::GoTime;
use jarvis_sig::Doc as SDoc;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

/// the last check
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct KernelHealth {
    pub healthy: bool,
    pub problems: Vec<String>,
    pub at: GoTime,
    pub copies: BTreeMap<String, CopyHealth>,
}

/// one copy as the check found it: each Deployment "ok" (holds the copy's roster), "down", "none" (no roster) or
/// "other" (another roster)
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct CopyHealth {
    pub serving: bool,
    /// the ID of the roster it should hold ("" = none: idle)
    #[serde(skip_serializing_if = "String::is_empty")]
    pub roster: String,
    pub components: BTreeMap<String, String>,
}

pub const KERNEL_HEALTH_EVERY: Duration = Duration::from_secs(15);

impl Router {
    /// checks now, then every `every`
    pub fn kernel_health_loop(self: &Arc<Self>, every: Duration) {
        loop {
            self.kernel_health_check();
            std::thread::sleep(every);
        }
    }

    /// checks the kernel once and keeps the answer
    pub fn kernel_health_check(&self) -> KernelHealth {
        let (problems, copies) = self.kernel_problems();
        let h = KernelHealth {
            healthy: problems.is_empty(),
            problems,
            at: GoTime::now(),
            copies,
        };
        *self
            .kernel_health_now
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(h.clone());
        h
    }

    /// what is wrong with the kernel right now, each a short plain sentence (none: healthy), and both copies as the
    /// check found them
    pub fn kernel_problems(&self) -> (Vec<String>, BTreeMap<String, CopyHealth>) {
        if self.kernel.is_none() {
            return (vec!["No kernel on this box".into()], BTreeMap::new());
        }
        let mut probs = vec![];
        let cur = self.current_roster();
        let serving = self.serving_copy();
        let (pending, mut stale, waiting) = self.st.do_(|p| {
            let stale: Vec<String> = p
                .kernel_roster
                .as_ref()
                .map(|c| c.stale.keys().cloned().collect())
                .unwrap_or_default();
            let waiting = p
                .kernel_flip
                .as_ref()
                .filter(|f| !f.waiting.is_empty())
                .map(|f| format!("Kernel flip to {} waiting: {}", f.to, f.waiting))
                .unwrap_or_default();
            (p.kernel_roster_pending.is_some(), stale, waiting)
        });
        stale.sort();
        if cur.is_none() && pending {
            probs.push("Kernel roster waiting for your signature".to_string());
        } else if cur.is_none() {
            probs.push("No signed kernel roster".to_string());
        } else if !stale.is_empty() {
            probs.push(format!(
                "Kernel roster stale: {} restarted",
                stale.join(", ")
            ));
        }
        if !waiting.is_empty() {
            probs.push(waiting);
        }
        let mut copies = BTreeMap::new();
        std::thread::scope(|sc| {
            let mut hs = vec![];
            for c in KERNEL_COPIES {
                let rc = self.roster_of_copy(c);
                let want: Option<SDoc> = rc.as_ref().map(|x| x.doc());
                copies.insert(
                    c.to_string(),
                    CopyHealth {
                        serving: c == serving,
                        roster: want.as_ref().map(|d| d.id()).unwrap_or_default(),
                        components: BTreeMap::new(),
                    },
                );
                for dep in roster_targets(c) {
                    let want = want.clone();
                    hs.push(sc.spawn(move || {
                        let st = self.kernel_roster_held(&dep, want.as_ref());
                        (c, dep, if st.is_empty() { "ok".to_string() } else { st })
                    }));
                }
            }
            for h in hs {
                if let Ok((c, dep, st)) = h.join()
                    && let Some(ch) = copies.get_mut(c)
                {
                    ch.components.insert(dep, st);
                }
            }
        });
        let mut by: BTreeMap<&str, Vec<String>> = BTreeMap::new();
        if let Some(ch) = copies.get(&serving) {
            for (dep, st) in &ch.components {
                if st != "ok" {
                    by.entry(st.as_str()).or_default().push(dep.clone());
                }
            }
        }
        for s in ["down", "none", "other"] {
            let Some(deps) = by.get_mut(s).filter(|d| !d.is_empty()) else {
                continue;
            };
            deps.sort();
            let names = deps.join(", ");
            match s {
                "down" if deps.len() == KERNEL_ROLES.len() => {
                    probs.push("No kernel component answering".into())
                }
                "down" => probs.push(format!("{names} not answering")),
                // without a signed roster, holding none is expected (said above)
                "none" if cur.is_some() => probs.push(format!("{names} holding no roster")),
                "other" => probs.push(format!("{names} not holding the current roster")),
                _ => {}
            }
        }
        (probs, copies)
    }

    /// one component's GET /roster against cur: "" (answers and holds cur, or holds a roster while none is signed),
    /// "down" (no answer, or not a roster), "none" (it holds no roster), "other" (another roster)
    pub fn kernel_roster_held(&self, dep: &str, cur: Option<&SDoc>) -> String {
        let Some(k) = &self.kernel else {
            return "down".into();
        };
        let resp = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .and_then(|c| c.get(format!("{}/roster", k.url(dep))).send());
        let Ok(resp) = resp else { return "down".into() };
        let st = resp.status().as_u16();
        let b = crate::util::read_limited(resp, 1 << 20).unwrap_or_default();
        if st != 200 {
            if String::from_utf8_lossy(&b).contains("no roster yet") {
                return "none".into();
            }
            return "down".into();
        }
        let Ok(held) = jarvis_go::unmarshal::<SDoc>(&b) else {
            return "down".into();
        };
        if held.payload.is_empty() {
            return "down".into();
        }
        if cur.is_some_and(|c| held.payload != c.payload) {
            return "other".into();
        }
        String::new()
    }

    /// the last check as the app reads it ({"checked": false} before the first)
    pub fn kernel_health_view(&self) -> Value {
        match self
            .kernel_health_now
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
        {
            None => json!({"checked": false, "healthy": false, "problems": []}),
            Some(h) => {
                json!({"checked": true, "healthy": h.healthy, "problems": h.problems, "at": h.at, "copies": h.copies})
            }
        }
    }
}

/// GET /api/state's "kernel": only on a router that runs no core, where it replaces core.up as what the app warns about
pub fn kernel_health_state_hook(r: &Arc<Router>, out: &mut Map<String, Value>) {
    if r.cfg.no_core {
        out.insert("kernel".into(), r.kernel_health_view());
    }
}
