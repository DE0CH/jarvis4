//! The copy flip (docs/PLAN-cluster.md "Releases: the copy flip", DECISIONS 233): a kernel release lands on the copy
//! that doesn't serve; the setup session files that copy's roster (its components' fresh keys, the serving copy's
//! members as retired, its empty secrets as secretsBoot) and Deyao signs it with one Face ID. Then the router, on its
//! own:
//!
//!  1. checks both copies are where the flip needs them: every component of the other copy holds the new roster
//!     (posted again if one lost it), and every serving component is one the new roster retires (else one restarted
//!     since the roster was read: a new roster is needed, nothing has frozen);
//!  2. with every kernel call held (KernelClient.gate), asks each serving component for its handoff (POST /handoff
//!     with the new roster): each freezes; the notarizer, the spawner and secrets seal their state to the other copy;
//!  3. gives the other copy's notarizer, spawner and secrets their predecessor's handoff (POST /takeover);
//!  4. switches every call to the other copy (Persisted.kernel_copy; the new roster becomes the current one) and lets
//!     the held calls go.
//!
//! Each step is kept (Persisted.kernel_flip) before the next, and each is safe to repeat (a frozen component answers
//! the same handoff again, a component that took a handoff answers it again), so a router that restarts mid-flip
//! carries on (kernel_flip_loop). A step that fails ends the try (held calls go, to a copy partly frozen: they fail
//! until the flip finishes) and the loop tries again; Deyao gets one DM. After the flip, a setup session commits
//! k8s/cluster/kernel/active-kernel.txt and scales the old copy to zero (infra/setup.py kernel-flipped): the router
//! can't push, and git is how the cluster changes.

use crate::kernel::{copy_of, other_copy};
use crate::roster::{KERNEL_ROLES, RosterCurrent, roster_targets};
use crate::router::Router;
use anyhow::{Result, anyhow};
use jarvis_go::GoTime;
use jarvis_sig::{Doc as SDoc, Identity, Roster};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// the copy flip under way
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct KernelFlip {
    /// the copy that takes over
    pub to: String,
    /// the ID of its roster (Persisted.kernel_roster_next)
    pub roster: String,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub handoffs: BTreeMap<String, SDoc>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub taken: BTreeMap<String, bool>,
    pub started: GoTime,
    /// why the last try didn't finish
    #[serde(skip_serializing_if = "String::is_empty")]
    pub waiting: String,
}

/// the components whose state moves (the others only freeze)
pub const FLIP_STATEFUL: &[&str] = &["notarizer", "spawner", "preloader", "secrets"];

/// whether a role is in the serving copy's roster. A role it lacks (one released for the first time, as the preloader
/// was) has nothing to hand over: the new roster retires none of its keys, so the new copy's component serves at once
/// (kernel/internal/serve flip.go Decide), and the flip neither waits for nor asks the old copy's. No serving roster
/// recorded: every role moves.
pub fn serving_roles(cur: Option<&RosterCurrent>) -> impl Fn(&str) -> bool + use<> {
    let ro: Option<Roster> = cur.map(RosterCurrent::roster);
    move |role: &str| ro.as_ref().is_none_or(|r| r.member(role).is_some())
}

/// one try at a time
static KERNEL_FLIP_MU: Mutex<()> = Mutex::new(());
static FLIP_DMED: AtomicBool = AtomicBool::new(false);
pub const FLIP_EVERY: Duration = Duration::from_secs(30);

/// a component's GET /identity answer read (secrets answers its keys in the open; the others a self-signed document)
pub fn identity_answer(dep: &str, b: &[u8]) -> Result<Identity> {
    let c = copy_of(dep);
    if !c.is_empty() && &dep[..dep.len() - c.len() - 1] == "secrets" {
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct M {
            #[serde(rename = "signingKey", alias = "SigningKey")]
            signing_key: String,
            #[serde(rename = "agreementKey", alias = "AgreementKey")]
            agreement_key: String,
        }
        let m: M = jarvis_go::unmarshal(b).map_err(|_| anyhow!("{dep}: bad identity"))?;
        return Ok(Identity {
            role: "secrets".into(),
            signing_key: m.signing_key,
            agreement_key: m.agreement_key,
        });
    }
    let d: SDoc = jarvis_go::unmarshal(b).map_err(|_| anyhow!("{dep}: bad identity"))?;
    serde_json::from_str::<Identity>(&d.payload).map_err(|_| anyhow!("{dep}: bad identity"))
}

impl Router {
    /// the flip to copy `to`, whose roster (id) Deyao just signed. A newer roster during a flip to the same copy (one of
    /// its components restarted before taking over) starts the handoffs again for it; the takeovers done stay done
    pub fn start_flip(self: &Arc<Self>, to: &str, roster: &str) {
        self.st.do_(|p| {
            let taken = p
                .kernel_flip
                .as_ref()
                .filter(|f| f.to == to)
                .map(|f| f.taken.clone())
                .unwrap_or_default();
            p.kernel_flip = Some(KernelFlip {
                to: to.into(),
                roster: roster.into(),
                taken,
                started: GoTime::now(),
                ..Default::default()
            });
        });
        FLIP_DMED.store(false, Ordering::SeqCst);
        crate::logf!("kernel: the flip to the {to} copy begins");
        let r = self.clone();
        std::thread::spawn(move || {
            let _ = r.kernel_flip_run();
        });
    }

    /// a flip that didn't finish (a failed step, a router restart) is tried again
    pub fn kernel_flip_loop(self: &Arc<Self>) {
        loop {
            crate::leaderlease::await_lead();
            let pending = self.st.do_(|p| p.kernel_flip.is_some());
            if pending
                && self.kernel.is_some()
                && let Err(e) = self.kernel_flip_run()
            {
                crate::logf!("kernel: the flip: {e:#} (tried again in 30s)");
            }
            std::thread::sleep(FLIP_EVERY);
        }
    }

    /// the flip under way, for the status views (Null: none)
    pub fn flip_status(&self) -> Value {
        self.st.do_(|p| {
            let Some(f) = &p.kernel_flip else { return Value::Null };
            let handed: Vec<&String> = f.handoffs.keys().collect();
            let taken: Vec<&String> = f.taken.iter().filter(|(_, ok)| **ok).map(|(k, _)| k).collect();
            json!({"to": f.to, "roster": f.roster, "started": f.started, "handedOver": handed, "tookOver": taken, "waiting": f.waiting})
        })
    }

    fn flip_waiting(&self, why: &str) {
        self.st.do_(|p| {
            if let Some(f) = p.kernel_flip.as_mut() {
                f.waiting = why.to_string();
            }
        });
        if FLIP_DMED
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            self.dm(&format!(
                "🔴 Jarvis 4's kernel flip is waiting — {why}. The router tries again every 30 s."
            ));
        }
    }

    /// one try at the flip; Ok once it finished (or there is none)
    pub fn kernel_flip_run(&self) -> Result<()> {
        let _g = KERNEL_FLIP_MU.lock().unwrap_or_else(|e| e.into_inner());
        let (f, next, cur) = self.st.do_(|p| {
            (
                p.kernel_flip.clone(),
                p.kernel_roster_next.clone(),
                p.kernel_roster.clone(),
            )
        });
        let Some(mut f) = f else { return Ok(()) };
        let Some(next) = next.filter(|n| n.copy == f.to && n.doc().id() == f.roster) else {
            let why = "the roster it was started with is gone";
            self.flip_waiting(why);
            return Err(anyhow!(why));
        };
        let from = other_copy(&f.to);
        let moves = serving_roles(cur.as_ref());
        if f.handoffs.is_empty() {
            let why = self.flip_ready(from, &next, &moves);
            if !why.is_empty() {
                self.flip_waiting(&why);
                return Err(anyhow!(why));
            }
        }
        let Some(k) = &self.kernel else { return Ok(()) };
        let res = {
            let _w = k.gate.write();
            let res = self.flip_steps(&mut f, &next.doc(), from, &moves);
            if res.is_ok() {
                self.st.do_(|p| {
                    p.kernel_copy = f.to.clone();
                    p.kernel_roster = Some(next.clone());
                    p.kernel_roster_next = None;
                    p.kernel_flip = None;
                });
                k.forget_all();
                self.kernel_token_dmed.store(false, Ordering::SeqCst); // the new spawner has the old one's Fly token
            }
            res
        };
        if let Err(e) = res {
            self.flip_waiting(&format!("{e:#}"));
            return Err(e);
        }
        let took = Duration::from_secs(
            (f.started.since().whole_milliseconds().max(0) as u64 + 500) / 1000,
        );
        crate::logf!(
            "kernel: the {} copy serves from now on (the flip took {}); a setup session commits active-kernel.txt (infra/setup.py kernel-flipped)",
            f.to,
            jarvis_go::fmt::duration_string(took)
        );
        self.kernel_health_check();
        Ok(())
    }

    /// "" when the flip can begin: every component of the other copy holds its roster (posted again if one lost it),
    /// and every serving component is one that roster retires (the serving secrets: the one it names)
    fn flip_ready(&self, from: &str, next: &RosterCurrent, moves: &dyn Fn(&str) -> bool) -> String {
        let Some(k) = &self.kernel else {
            return "no kernel".into();
        };
        let d = next.doc();
        let ro: Roster = next.roster();
        for dep in roster_targets(&next.copy) {
            if let Ok((b, _)) = k.do_(&dep, &dep, "GET", "/roster", None)
                && jarvis_go::unmarshal::<SDoc>(&b).is_ok_and(|h| h.payload == d.payload)
            {
                continue;
            }
            if let Err(e) = k.post_roster(&dep, &d) {
                return format!("{dep} doesn't hold the {} roster ({e:#})", next.copy);
            }
        }
        for role in KERNEL_ROLES {
            if !moves(role) {
                continue;
            }
            let dep = format!("{role}-{from}");
            let b = match k.do_(&dep, &dep, "GET", "/identity", None) {
                Err(e) => return format!("{dep} doesn't answer ({e:#})"),
                Ok((b, _)) => b,
            };
            let id = match identity_answer(&dep, &b) {
                Err(e) => return format!("{e:#}"),
                Ok(id) => id,
            };
            if *role == "secrets" {
                if ro.member("secrets") != Some(&id) {
                    return format!(
                        "{dep} isn't the secrets the {} roster names (Recovered again since it was read?): a new roster is needed",
                        next.copy
                    );
                }
                continue;
            }
            if !ro.retired.contains(&id) {
                return format!(
                    "{dep} restarted since the {} roster was read (it doesn't retire its keys): a new roster is needed",
                    next.copy
                );
            }
        }
        String::new()
    }

    /// the handoffs, then the takeovers, each kept before the next (callers hold the gate)
    fn flip_steps(
        &self,
        f: &mut KernelFlip,
        roster: &SDoc,
        from: &str,
        moves: &dyn Fn(&str) -> bool,
    ) -> Result<()> {
        let Some(k) = &self.kernel else {
            return Err(anyhow!("no kernel"));
        };
        for role in KERNEL_ROLES {
            if f.handoffs.contains_key(*role) || !moves(role) {
                continue;
            }
            let dep = format!("{role}-{from}");
            let (b, _) = k
                .do_(
                    &dep,
                    &dep,
                    "POST",
                    "/handoff",
                    Some(&json!({"roster": roster})),
                )
                .map_err(|e| anyhow!("{dep}'s handoff: {e:#}"))?;
            let d = match jarvis_go::unmarshal::<SDoc>(&b) {
                Ok(d) if !d.payload.is_empty() => d,
                _ => return Err(anyhow!("{dep}'s handoff isn't a signed document")),
            };
            f.handoffs.insert(role.to_string(), d.clone());
            self.st.do_(|p| {
                if let Some(pf) = p.kernel_flip.as_mut() {
                    pf.handoffs.insert(role.to_string(), d.clone());
                }
            });
            crate::logf!("kernel: {dep} handed over to the {} copy", f.to);
        }
        for role in FLIP_STATEFUL {
            if f.taken.get(*role).copied().unwrap_or(false) || !moves(role) {
                continue;
            }
            let dep = format!("{role}-{}", f.to);
            let h = f.handoffs.get(*role).cloned().unwrap_or_default();
            if let Err(e) = k.do_(
                &dep,
                &dep,
                "POST",
                "/takeover",
                Some(&json!({"handoff": h})),
            ) {
                // secrets keeps nothing on disk: one that restarted before its takeover is Recovered with the kit (the
                // crash path), and then already serves with the keys the roster names
                if *role != "secrets" || !self.secrets_serves_as(&dep, roster) {
                    return Err(anyhow!("{dep}'s takeover: {e:#}"));
                }
                crate::logf!(
                    "kernel: {dep} was Recovered with the kit instead of taking the handoff"
                );
            }
            f.taken.insert(role.to_string(), true);
            self.st.do_(|p| {
                if let Some(pf) = p.kernel_flip.as_mut() {
                    pf.taken.insert(role.to_string(), true);
                }
            });
            crate::logf!("kernel: {dep} took over");
        }
        Ok(())
    }

    /// the secrets Deployment serves (set up, not handed off) with the keys the roster names for secrets
    fn secrets_serves_as(&self, dep: &str, roster: &SDoc) -> bool {
        let Some(k) = &self.kernel else { return false };
        let Ok((b, _)) = k.do_(dep, dep, "GET", "/identity", None) else {
            return false;
        };
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct Id {
            #[serde(rename = "signingKey", alias = "SigningKey")]
            signing_key: String,
            state: SDoc,
        }
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct St {
            master: String,
            serving: String,
        }
        let (Ok(id), Ok(ro)) = (
            jarvis_go::unmarshal::<Id>(&b),
            serde_json::from_str::<Roster>(&roster.payload),
        ) else {
            return false;
        };
        let Some(m) = ro.member("secrets") else {
            return false;
        };
        m.signing_key == id.signing_key
            && jarvis_sig::verify(&id.signing_key, id.state.payload.as_bytes(), &id.state.sig)
            && jarvis_go::unmarshal::<St>(id.state.payload.as_bytes())
                .is_ok_and(|st| !st.master.is_empty() && st.serving == "serving")
    }
}
