//! Components' keys and the kernel's roster: a component's
//! fresh keys are checked against the roster the root key signs (docs/PLAN-cluster.md "The roster").

use crate::{Doc, Error as SigError, Opener, Signer, go_json, strict_json, unb64, verify};
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::{AffinePoint, EncodedPoint, ProjectivePoint};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error(
        "no roster yet: the kernel's components wait for the root key's roster (Settings → Kernel)"
    )]
    NoRoster,
    #[error("{0}")]
    Msg(String),
}

fn msg(s: impl Into<String>) -> Error {
    Error::Msg(s.into())
}

/// A component's fresh keys, made when it starts. Nobody vouches for them by themselves: anyone checks them against
/// the kernel's roster, which the root key signs.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Identity {
    pub role: String,
    pub signing_key: String,
    pub agreement_key: String,
}

/// A running component's keys
pub struct Component {
    pub role: String,
    pub signer: Signer,
    pub agreement: Opener,
    pub identity: Identity,
}

impl Component {
    /// Fresh keys for `role`, held in RAM only (a restart makes new ones, which need a new roster)
    pub fn new(role: &str) -> Self {
        let signer = Signer::generate();
        let agreement = Opener::generate();
        let identity = Identity {
            role: role.into(),
            signing_key: signer.public_key(),
            agreement_key: agreement.public_key(),
        };
        Self {
            role: role.into(),
            signer,
            agreement,
            identity,
        }
    }
}

/// One kernel copy's components and their keys, as the root key signs it. Members sorted by role, one each; retired:
/// keys that served before and sign nothing new (what they signed while they served still counts), sorted by role then
/// signing key; secretsBoot: the keys the taking-over copy's secrets started with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Roster {
    pub kind: String,
    pub copy: String,
    pub members: Vec<Identity>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub retired: Vec<Identity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secrets_boot: Option<Identity>,
}

fn keys_ok(m: &Identity) -> bool {
    !m.role.is_empty()
        && !m.signing_key.is_empty()
        && !m.agreement_key.is_empty()
        && !format!("{}{}", m.signing_key, m.agreement_key).contains([' ', '\n'])
}

fn retired_less(a: &Identity, b: &Identity) -> bool {
    (&a.role, &a.signing_key) < (&b.role, &b.signing_key)
}

/// `d` is a roster the root key signed
pub fn open_roster(d: &Doc, root_pub: &str) -> Result<Roster, Error> {
    if root_pub.is_empty() {
        return Err(msg("no root key to check the roster with"));
    }
    if !verify(root_pub, d.payload.as_bytes(), &d.sig) {
        return Err(msg("the roster isn't signed by the root key"));
    }
    let r: Roster =
        strict_json(d.payload.as_bytes()).map_err(|e| msg(format!("the roster: {e}")))?;
    if r.kind != "kernel-roster" || (r.copy != "blue" && r.copy != "green") || r.members.is_empty()
    {
        return Err(msg("not a kernel roster"));
    }
    let mut keys = std::collections::HashSet::new();
    for (i, m) in r.members.iter().enumerate() {
        if !keys_ok(m) {
            return Err(msg("a roster member without keys"));
        }
        if i > 0 && r.members[i - 1].role >= m.role {
            return Err(msg("the roster's members aren't sorted by role, one each"));
        }
        keys.insert(m.signing_key.clone());
    }
    for (i, m) in r.retired.iter().enumerate() {
        if !keys_ok(m) || m.role == "secrets" {
            return Err(msg(
                "a retired member without keys, or secrets (never retired)",
            ));
        }
        if keys.contains(&m.signing_key) {
            return Err(msg("a retired key is also a member"));
        }
        if i > 0 && (retired_less(m, &r.retired[i - 1]) || r.retired[i - 1] == *m) {
            return Err(msg(
                "the roster's retired members aren't sorted by role and signing key, once each",
            ));
        }
    }
    if let Some(b) = &r.secrets_boot
        && (!keys_ok(b) || b.role != "secrets")
    {
        return Err(msg("secretsBoot: a secrets identity"));
    }
    Ok(r)
}

impl Roster {
    /// The exact payload the setup key and the root key sign (kind set, members sorted by role, retired by role and
    /// signing key)
    pub fn payload(&self) -> Result<String, SigError> {
        let mut r = self.clone();
        r.kind = "kernel-roster".into();
        r.members.sort_by(|a, b| a.role.cmp(&b.role));
        r.retired
            .sort_by(|a, b| (&a.role, &a.signing_key).cmp(&(&b.role, &b.signing_key)));
        go_json(&r)
    }

    /// The roster's keys for `role`
    pub fn member(&self, role: &str) -> Option<&Identity> {
        self.members.iter().find(|m| m.role == role)
    }

    /// The roster's retired keys of `role` (they sign nothing new; what they signed still counts)
    pub fn retired_of(&self, role: &str) -> Vec<Identity> {
        self.retired
            .iter()
            .filter(|m| m.role == role)
            .cloned()
            .collect()
    }
}

/// The roster a component (or a machine) checks identities against. It starts empty; `set` takes a roster the root
/// key signed. A component keeps only a roster that names its own keys under its own role.
pub struct Trust {
    root: String,
    held: Mutex<Option<(Doc, Roster)>>,
}

impl Trust {
    pub fn new(root_pub: &str) -> Self {
        Self {
            root: root_pub.into(),
            held: Mutex::new(None),
        }
    }

    fn held(&self) -> Option<(Doc, Roster)> {
        self.held.lock().map(|g| g.clone()).unwrap_or(None)
    }

    /// `d` is the root key's roster, and it names `self_` (None: a machine, which is no member): as the member of its
    /// role, or, for an empty secrets, as the roster's secretsBoot (it takes over in the copy flip)
    pub fn set(&self, d: Doc, self_: Option<&Identity>) -> Result<(), Error> {
        let r = open_roster(&d, &self.root)?;
        if let Some(me) = self_ {
            let named = r.member(&me.role) == Some(me);
            let boot = me.role == "secrets" && r.secrets_boot.as_ref() == Some(me);
            if !named && !boot {
                return Err(msg(format!(
                    "the roster doesn't name this {}'s keys",
                    me.role
                )));
            }
        }
        if let Ok(mut g) = self.held.lock() {
            *g = Some((d, r));
        }
        Ok(())
    }

    /// The roster document held (None: none yet)
    pub fn doc(&self) -> Option<Doc> {
        self.held().map(|(d, _)| d)
    }

    pub fn root(&self) -> &str {
        &self.root
    }

    /// The roster held (None: none yet)
    pub fn roster(&self) -> Option<Roster> {
        self.held().map(|(_, r)| r)
    }

    /// Every key whose signature as `role` the held roster takes: the member's, then the retired ones
    pub fn signing_keys(&self, role: &str) -> Vec<String> {
        let Some(r) = self.roster() else {
            return vec![];
        };
        r.member(role)
            .into_iter()
            .map(|m| m.signing_key.clone())
            .chain(r.retired_of(role).into_iter().map(|m| m.signing_key))
            .collect()
    }

    /// The keys the held roster names for `role` (the current member only)
    pub fn member(&self, role: &str) -> Result<Identity, Error> {
        let r = self.roster().ok_or(Error::NoRoster)?;
        r.member(role)
            .cloned()
            .ok_or_else(|| msg(format!("the roster names no {role}")))
    }
}

/// `id` is the roster's for that role: its member, or a retired one (what it signed while it served still counts)
pub fn check_identity(id: &Identity, role: &str, t: &Trust) -> Result<(), Error> {
    if id.role != role || format!("{}{}", id.signing_key, id.agreement_key).contains([' ', '\n']) {
        return Err(msg(format!("not a {role} identity")));
    }
    let r = t.roster().ok_or(Error::NoRoster)?;
    if r.member(role) == Some(id) || r.retired_of(role).contains(id) {
        return Ok(());
    }
    Err(msg(format!("the {role} identity isn't the roster's")))
}

fn point(b64: &str, what: &str) -> Result<ProjectivePoint, Error> {
    let b = unb64(b64).map_err(|e| msg(format!("{what}: {e}")))?;
    let ep = EncodedPoint::from_bytes(&b).map_err(|_| msg(format!("{what}: invalid point")))?;
    Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&ep))
        .map(ProjectivePoint::from)
        .ok_or_else(|| msg(format!("{what}: invalid point")))
}

/// The store key C = P + K, what every writer wraps a key's data key to: the phone's agreement key P plus secrets'
/// agreement key K (both base64 X9.63; the answer too)
pub fn store_key(phone: &str, secrets: &str) -> Result<String, Error> {
    let p = point(phone, "the phone's agreement key")?;
    let k = point(secrets, "secrets' agreement key")?;
    let c = (p + k).to_affine().to_encoded_point(false);
    if c.as_bytes().len() != 65 {
        return Err(msg("P + K is the point at infinity"));
    }
    Ok(crate::b64(c.as_bytes()))
}
