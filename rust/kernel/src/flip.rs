//! The copy flip (kernel/internal/serve/flip.go; docs/PLAN-cluster.md "Releases: the copy flip"): a kernel release
//! lands on the copy that doesn't serve; once the root key signed that copy's roster (which names the serving copy's
//! members as retired), the router asks every serving component to hand over:
//!
//!   POST /handoff  {roster}   on a serving component: the other copy's root-signed roster, which must retire this
//!                             component's keys → {kind: "handoff", role, from, roster, to, sealed?}, signed. A
//!                             stateful component (the notarizer, the spawner) seals its state to the agreement key
//!                             that roster names for its role; every component freezes in the same step (it answers
//!                             nothing but its identity, its roster and a handoff again from then on), so no state
//!                             goes on in two places. Again for a newer roster of the other copy (one of its
//!                             components restarted before it took over): the same frozen state, sealed to that roster.
//!   POST /takeover {handoff}  on the other copy's stateful component: a handoff for exactly the roster it holds,
//!                             sealed to its own key and signed by the member of its role that roster retires → it
//!                             takes the state whole (replacing what its volume held) and serves. The same handoff
//!                             again answers the same; any other is refused: once it took one it serves (kept on its
//!                             volume), so a frozen state handed over again can never replace the newer one it went on
//!                             with.
//!
//! A stateful component keeps its place in the flip on its volume (Continuity): serving, standby (never served, or
//! waiting to take a handoff) or handed-off. A volume that never held either is decided by its first roster: standby
//! when that roster retires a member of its role (another copy served before it), serving otherwise (the first copy).

use crate::serve::{Answer, Server, fail, fail_because, handle, no_roster};
use jarvis_sig::{Doc, Sealed, seal_to, strict_json, verify};
use jarvis_sig::{Roster, open_roster};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

pub const MODE_SERVING: &str = "serving";
pub const MODE_STANDBY: &str = "standby";
pub const MODE_HANDED_OFF: &str = "handed-off";

/// 409: a standby serves nothing until it takes its predecessor's handoff
pub const REASON_STANDBY: &str = "standby";
/// 409: this component handed over to the other copy and serves nothing
pub const REASON_HANDED_OFF: &str = "handed-off";

/// what a handoff's state is sealed under (+ the role)
pub const HANDOFF_INFO: &str = "jarvis2/kernel-handoff/";

/// what a component signs when it hands over (the state sealed to its successor's agreement key)
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Handoff {
    /// "handoff"
    pub kind: String,
    /// the component's role
    pub role: String,
    /// the copy it served in
    pub from: String,
    /// the ID of the roster it handed over to
    pub roster: String,
    /// that roster's agreement key for the role
    pub to: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub sealed: Option<Sealed>,
}

/// a component whose state moves to the other copy (Continuity holds its mode)
pub trait Stateful: Send + Sync {
    /// the first roster a never-decided volume holds sets its mode
    fn decide(&self, r: &Roster) -> anyhow::Result<()>;
    /// the component freezes (kept before it answers) and gives its state; again for the same roster: the same state
    /// (nothing changed since)
    fn handoff(&self, roster: &str) -> anyhow::Result<Vec<u8>>;
    /// the state replaces the component's own and it serves; again with the same handoff: nothing
    fn takeover(&self, handoff: &str, state: &[u8]) -> anyhow::Result<()>;
}

// ---- continuity: a stateful component's mode on its volume -----------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
struct ContinuityState {
    #[serde(default)]
    mode: String,
    /// handed-off: the roster it handed over to
    #[serde(skip_serializing_if = "String::is_empty", default)]
    to: String,
    /// the last handoff it took
    #[serde(skip_serializing_if = "String::is_empty", default)]
    took: String,
}

/// a stateful component's place in the flip, kept in a file on its volume. Its methods are called with the
/// component's own lock held, so a mode change and the component's work never interleave.
pub struct Continuity {
    path: PathBuf,
    st: Mutex<ContinuityState>,
}

impl Continuity {
    /// the mode at path ("" until the first roster decides it)
    pub fn open(path: &Path) -> anyhow::Result<Continuity> {
        let st = match std::fs::read(path) {
            Ok(b) => serde_json::from_slice(&b)
                .map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => ContinuityState::default(),
            Err(e) => return Err(e.into()),
        };
        Ok(Continuity {
            path: path.into(),
            st: Mutex::new(st),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, ContinuityState> {
        self.st.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn save(&self, g: &mut ContinuityState, st: ContinuityState) -> anyhow::Result<()> {
        crate::files::write_synced(&self.path, jarvis_sig::go_json(&st)?.as_bytes())?;
        *g = st;
        Ok(())
    }

    /// serving, standby, handed-off, or "" (no roster has decided it yet)
    pub fn mode(&self) -> String {
        self.lock().mode.clone()
    }

    /// a volume no roster decided yet: standby when r retires a member of role (another copy served before this one;
    /// its state comes with its handoff), else serving (the first copy)
    pub fn decide(&self, r: &Roster, role: &str) -> anyhow::Result<()> {
        let mut g = self.lock();
        if !g.mode.is_empty() {
            return Ok(());
        }
        let mode = if r.retired_of(role).is_empty() {
            MODE_SERVING
        } else {
            MODE_STANDBY
        };
        self.save(
            &mut g,
            ContinuityState {
                mode: mode.into(),
                ..Default::default()
            },
        )
    }

    /// Ok when the component serves, else the refusal
    pub fn serving(&self) -> anyhow::Result<()> {
        match self.lock().mode.as_str() {
            MODE_SERVING => Ok(()),
            MODE_HANDED_OFF => Err(fail_because(
                409,
                REASON_HANDED_OFF,
                "this component handed over to the other kernel copy: it serves nothing",
            )),
            MODE_STANDBY => Err(fail_because(
                409,
                REASON_STANDBY,
                "this component is a standby: it serves nothing until it takes its predecessor's handoff",
            )),
            _ => Err(fail_because(503, REASON_STANDBY, no_roster())),
        }
    }

    /// a serving component hands over to roster (kept before the state leaves); a frozen one again, to that roster or
    /// a newer one of the same other copy (its component restarted before it took the first: the frozen state is the
    /// same, and a component that took a handoff serves and takes no other, so it can't come back stale)
    pub fn freeze(&self, roster: &str) -> anyhow::Result<()> {
        let mut g = self.lock();
        if g.mode == MODE_HANDED_OFF && g.to == roster {
            return Ok(());
        }
        if g.mode != MODE_HANDED_OFF && g.mode != MODE_SERVING {
            return Err(fail_because(
                409,
                REASON_STANDBY,
                "this component doesn't serve: it has nothing to hand over",
            ));
        }
        let took = g.took.clone();
        self.save(
            &mut g,
            ContinuityState {
                mode: MODE_HANDED_OFF.into(),
                to: roster.into(),
                took,
            },
        )
    }

    /// whether the component takes handoff now (again: it took exactly that one already)
    pub fn can_take(&self, handoff: &str) -> anyhow::Result<bool> {
        let g = self.lock();
        if g.mode == MODE_SERVING && g.took == handoff {
            return Ok(true);
        }
        if g.mode == MODE_SERVING {
            return Err(fail(409, "this component serves: it takes no handoff"));
        }
        if g.mode.is_empty() {
            return Err(fail(503, no_roster()));
        }
        Ok(false)
    }

    /// the component serves from the handoff's state (called once that state is kept)
    pub fn took(&self, handoff: &str) -> anyhow::Result<()> {
        let mut g = self.lock();
        self.save(
            &mut g,
            ContinuityState {
                mode: MODE_SERVING.into(),
                took: handoff.into(),
                ..Default::default()
            },
        )
    }
}

// ---- the routes --------------------------------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HandoffIn {
    roster: Doc,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TakeoverIn {
    handoff: Doc,
}

pub(crate) fn register_flip(s: &Arc<Server>) {
    let s2 = s.clone();
    handle(s, "POST /handoff", move |i: HandoffIn| {
        Ok(Answer::Doc(handoff(&s2, &i.roster)?))
    });
    let s2 = s.clone();
    handle(s, "POST /takeover", move |i: TakeoverIn| {
        takeover(&s2, &i.handoff)
    });
}

/// the checks, the freeze, the signed handoff
fn handoff(s: &Server, d: &Doc) -> anyhow::Result<Doc> {
    let own = s.trust.roster().ok_or_else(|| fail(503, no_roster()))?;
    let r = open_roster(d, s.trust.root()).map_err(|e| fail(403, e.to_string()))?;
    let role = &s.c.role;
    if r.copy == own.copy {
        return Err(fail(
            409,
            format!(
                "a handoff goes to the other kernel copy (this is {}'s {role})",
                own.copy
            ),
        ));
    }
    if !r.retired_of(role).contains(&s.c.identity) {
        return Err(fail(
            403,
            format!("the {} roster doesn't retire this {role}'s keys", r.copy),
        ));
    }
    let to = r
        .member(role)
        .cloned()
        .ok_or_else(|| fail(403, format!("the {} roster names no {role}", r.copy)))?;
    let id = d.id();
    let mut h = Handoff {
        kind: "handoff".into(),
        role: role.clone(),
        from: own.copy.clone(),
        roster: id.clone(),
        to: to.agreement_key.clone(),
        sealed: None,
    };
    let mut frozen = s.frozen_to.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(st) = s.state.get() {
        let state = st.handoff(&id)?;
        h.sealed = Some(seal_to(
            &to.agreement_key,
            &state,
            &format!("{HANDOFF_INFO}{role}"),
        )?);
    }
    *frozen = id;
    Ok(s.c.signer.sign_json(&h)?)
}

/// a handoff for the roster this component holds, from the member of its role that roster retires
fn takeover(s: &Server, d: &Doc) -> anyhow::Result<Answer> {
    let (Some(held), Some(own)) = (s.trust.doc(), s.trust.roster()) else {
        return Err(fail(503, no_roster()));
    };
    let role = &s.c.role;
    let Some(st) = s.state.get() else {
        return Err(fail(
            400,
            format!("a {role} holds no state: it takes no handoff"),
        ));
    };
    let h: Handoff = match strict_json::<Handoff>(d.payload.as_bytes()) {
        Ok(h) if h.kind == "handoff" && h.sealed.is_some() => h,
        _ => return Err(fail(400, "not a handoff")),
    };
    if h.role != *role {
        return Err(fail(
            403,
            format!("a handoff of a {}, not of this {role}", h.role),
        ));
    }
    if h.roster != held.id() {
        return Err(fail(
            403,
            format!("a handoff to another roster than the one this {role} holds"),
        ));
    }
    if h.to != s.c.identity.agreement_key {
        return Err(fail(
            403,
            format!("a handoff sealed to other keys than this {role}'s"),
        ));
    }
    let by = own
        .retired_of(role)
        .into_iter()
        .any(|m| verify(&m.signing_key, d.payload.as_bytes(), &d.sig));
    if !by {
        return Err(fail(
            403,
            format!("the handoff isn't signed by the {role} this roster retires"),
        ));
    }
    let Some(sealed) = h.sealed.clone() else {
        return Err(fail(400, "not a handoff"));
    };
    let plain =
        s.c.agreement
            .open(&sealed, &format!("{HANDOFF_INFO}{role}"))
            .map_err(|_| {
                fail(
                    403,
                    format!("the handoff's state doesn't open with this {role}'s key"),
                )
            })?;
    let mut frozen = s.frozen_to.lock().unwrap_or_else(|e| e.into_inner());
    st.takeover(&d.id(), &plain)?;
    frozen.clear();
    Answer::of(
        &serde_json::json!({"kind": "took-over", "role": role, "handoff": d.id(), "from": h.from}),
    )
}
