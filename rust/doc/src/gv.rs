//! Checking a grant as everyone who takes one does, the Rust port of kernel/gv: a grant is signed by the mover or the
//! merger (their identities, checked against the root key's roster: its member, or a retired one whose grants still
//! open though it signs nothing new), or is the root key's ⊤ on the sink.

use crate::perm::Pair;
use crate::{Error, Grant, Keys, Kind, Object, open_grant};
use jarvis_sig::{Doc, Identity, Trust, check_identity};
use serde::{Deserialize, Serialize};

/// A grant and what vouches for its signer
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signed {
    pub grant: Doc,
    /// "mover", "merger" or "root"
    pub by: String,
    /// the mover's or merger's identity
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<Identity>,
    /// root: secrets' signed keys statement
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<Doc>,
    /// … and secrets' identity
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secrets: Option<Identity>,
}

fn err(s: impl Into<String>) -> Error {
    Error::Invalid(s.into())
}

/// The keys of the sink or a source, hashed from its name (nobody holds their private halves)
pub fn ideal_keys(o: &Object) -> Result<Keys, Error> {
    match o.kind() {
        Some(Kind::Sink | Kind::Source) => Ok(Keys {
            signing_key: crate::h2c::object_key(&o.0, "signing"),
            encryption_key: crate::h2c::object_key(&o.0, "encryption"),
        }),
        _ => Err(err(format!("{} has no ideal keys", o.0))),
    }
}

/// The root key from secrets' signed keys statement
pub fn root_key(
    keys: Option<&Doc>,
    secrets: Option<&Identity>,
    t: &Trust,
) -> Result<String, Error> {
    let (Some(keys), Some(secrets)) = (keys, secrets) else {
        return Err(err("the root key needs secrets' signed keys"));
    };
    check_identity(secrets, "secrets", t).map_err(|e| err(e.to_string()))?;
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct K {
        kind: String,
        #[allow(dead_code)]
        phone: String,
        root: String,
    }
    match keys.open::<K>(&secrets.signing_key) {
        Ok(k) if k.kind == "keys" => Ok(k.root),
        Ok(_) => Err(err("secrets' keys: not a keys statement")),
        Err(e) => Err(err(format!("secrets' keys: {e}"))),
    }
}

/// The grant, checked
pub fn open(s: &Signed, t: &Trust) -> Result<Grant, Error> {
    let key = match s.by.as_str() {
        "mover" | "merger" => {
            let Some(signer) = &s.signer else {
                return Err(err(format!(
                    "a {} grant needs the {}'s identity",
                    s.by, s.by
                )));
            };
            check_identity(signer, &s.by, t).map_err(|e| err(e.to_string()))?;
            signer.signing_key.clone()
        }
        "root" => root_key(s.keys.as_ref(), s.secrets.as_ref(), t)?,
        by => return Err(err(format!("a grant signed by {by:?}"))),
    };
    let g = open_grant(&s.grant, &key).map_err(|e| err(format!("grant: {e}")))?;
    if s.by == "root" && (g.machine.0 != crate::SINK || !Pair::top().leq(&g.pair)) {
        return Err(err("the root key's grant is ⊤ on the sink only"));
    }
    if matches!(g.machine.kind(), Some(Kind::Sink | Kind::Source))
        && ideal_keys(&g.machine).ok().as_ref() != Some(&g.keys)
    {
        return Err(err(format!(
            "a grant on {} names keys that aren't its own",
            g.machine.0
        )));
    }
    Ok(g)
}

/// The later of two RFC 3339 times (an unparsable `a` gives `b`)
pub fn later<'a>(a: &'a str, b: &'a str) -> &'a str {
    let p = |s: &str| {
        time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).ok()
    };
    match (p(a), p(b)) {
        (None, _) => b,
        (Some(ta), Some(tb)) if tb > ta => b,
        _ => a,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::perm::Set;
    use jarvis_sig::{Component, Roster, Signer};

    fn grant(c: &Component, by: &str) -> Signed {
        let g = Grant {
            kind: "grant".into(),
            machine: Object("fly-aaaaaaaa01".into()),
            keys: Keys {
                signing_key: Signer::generate().public_key(),
                encryption_key: Signer::generate().public_key(),
            },
            pair: Pair::new(Set::only(["store:x"]), vec!["session:s".into()]),
            from: Some(vec![]),
            at: crate::now(),
        };
        Signed {
            grant: c.signer.sign_json(&g).unwrap_or_else(|e| panic!("{e}")),
            by: by.into(),
            signer: Some(c.identity.clone()),
            keys: None,
            secrets: None,
        }
    }

    /// a grant signed by a retired mover or merger opens as one signed by the current one; a retired key passes only
    /// for its own role; a key the roster names nowhere is refused (kernel/gv TestRetiredSignersGrantsOpen)
    #[test]
    fn retired_signers_grants_open() {
        let root = Signer::generate();
        let cur: Vec<Component> = ["merger", "mover", "notarizer", "secrets"]
            .iter()
            .map(|r| Component::new(r))
            .collect();
        let (old_mover, old_merger, old_notarizer) = (
            Component::new("mover"),
            Component::new("merger"),
            Component::new("notarizer"),
        );
        let r = Roster {
            kind: String::new(),
            copy: "green".into(),
            members: cur.iter().map(|c| c.identity.clone()).collect(),
            retired: vec![
                old_mover.identity.clone(),
                old_merger.identity.clone(),
                old_notarizer.identity.clone(),
            ],
            secrets_boot: None,
        };
        let payload = r.payload().unwrap_or_else(|e| panic!("{e}"));
        let t = Trust::new(&root.public_key());
        t.set(
            Doc {
                sig: root.sign(payload.as_bytes()),
                payload,
            },
            None,
        )
        .unwrap_or_else(|e| panic!("{e}"));
        for s in [
            grant(&cur[1], "mover"),
            grant(&old_mover, "mover"),
            grant(&cur[0], "merger"),
            grant(&old_merger, "merger"),
        ] {
            let g = open(&s, &t).unwrap_or_else(|e| panic!("{}: {e}", s.by));
            assert_eq!(g.machine.0, "fly-aaaaaaaa01");
        }
        let mut retired_as = old_notarizer.identity.clone();
        retired_as.role = "mover".into();
        let mut as_mover = grant(&old_notarizer, "mover");
        as_mover.signer = Some(retired_as);
        for (what, s) in [
            (
                "a retired mover's grant as the merger's",
                grant(&old_mover, "merger"),
            ),
            ("a retired notarizer's key named as a mover", as_mover),
            (
                "a mover the roster names nowhere",
                grant(&Component::new("mover"), "mover"),
            ),
        ] {
            assert!(open(&s, &t).is_err(), "{what} opened");
        }
    }

    #[test]
    fn later_picks_the_later() {
        assert_eq!(
            later("2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z"),
            "2026-01-02T00:00:00Z"
        );
        assert_eq!(
            later("2026-01-03T00:00:00Z", "2026-01-02T00:00:00Z"),
            "2026-01-03T00:00:00Z"
        );
        assert_eq!(later("x", "2026-01-02T00:00:00Z"), "2026-01-02T00:00:00Z");
        assert_eq!(later("2026-01-03T00:00:00Z", "x"), "2026-01-03T00:00:00Z");
    }
}
