//! Permission pairs, the Rust port of kernel/perm (DESIGN "Target design"). `allowed` is a finite ("only") or cofinite
//! ("except") set of exact strings, covariant; `conditions` a finite set of exact strings, contravariant.
//! P' ≤ P iff allowed' ⊆ allowed and conditions' ⊇ conditions; P ⊓ Q = (allowed ∩, conditions ∪). Only these set
//! operations, never what a string means. Strings are kept sorted and unique, so equal pairs marshal to equal bytes.

use serde::{Deserialize, Serialize, Serializer};

/// `only` xor `except` is meaningful; `except` = cofinite (everything but these). Both `None` = invalid.
/// A missing side and `null` are both `None`; `[]` is an empty set (as Go's nil vs empty slice).
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Set {
    #[serde(default)]
    pub only: Option<Vec<String>>,
    #[serde(default)]
    pub except: Option<Vec<String>>,
}

impl Serialize for Set {
    /// the one non-None side, empty included (`{"only":[]}` is nothing, `{"except":[]}` everything)
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::{Error, SerializeMap};
        let (k, v) = match (&self.except, &self.only) {
            (Some(e), _) => ("except", e),
            (None, Some(o)) => ("only", o),
            (None, None) => return Err(S::Error::custom("an empty set value")),
        };
        let mut m = s.serialize_map(Some(1))?;
        m.serialize_entry(k, v)?;
        m.end()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pair {
    pub allowed: Set,
    /// `None` only when a document left it out (invalid)
    pub conditions: Option<Vec<String>>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Invalid {
    #[error("allowed: exactly one of only and except")]
    OnlyXorExcept,
    #[error("conditions missing")]
    NoConditions,
    #[error("bad string {0:?}")]
    BadString(String),
    #[error("strings not sorted and unique")]
    NotSorted,
    #[error("the conditions differ")]
    ConditionsDiffer,
}

fn norm(mut v: Vec<String>) -> Vec<String> {
    v.sort();
    v.dedup();
    v
}

fn inter(a: &[String], b: &[String]) -> Vec<String> {
    a.iter().filter(|x| b.contains(x)).cloned().collect()
}

fn minus(a: &[String], b: &[String]) -> Vec<String> {
    a.iter().filter(|x| !b.contains(x)).cloned().collect()
}

fn union(a: &[String], b: &[String]) -> Vec<String> {
    norm(a.iter().chain(b).cloned().collect())
}

fn check_strings(s: &[String]) -> Result<(), Invalid> {
    for x in s {
        // Go's unicode.IsSpace covers the same code points as char::is_whitespace for every rune that matters here
        // (both include U+0085 and U+00A0); unicode.IsControl is Cc, as char::is_control
        if x.is_empty() || x.len() > 512 || x.chars().any(|c| c.is_control() || c.is_whitespace()) {
            return Err(Invalid::BadString(x.clone()));
        }
    }
    if s.windows(2).any(|w| w[0] >= w[1]) {
        return Err(Invalid::NotSorted);
    }
    Ok(())
}

impl Set {
    pub fn only<I: IntoIterator<Item = S>, S: Into<String>>(xs: I) -> Set {
        Set {
            only: Some(norm(xs.into_iter().map(Into::into).collect())),
            except: None,
        }
    }

    pub fn except<I: IntoIterator<Item = S>, S: Into<String>>(xs: I) -> Set {
        Set {
            only: None,
            except: Some(norm(xs.into_iter().map(Into::into).collect())),
        }
    }

    fn cofinite(&self) -> bool {
        self.except.is_some()
    }

    fn only_v(&self) -> &[String] {
        self.only.as_deref().unwrap_or(&[])
    }

    fn except_v(&self) -> &[String] {
        self.except.as_deref().unwrap_or(&[])
    }

    pub fn contains(&self, x: &str) -> bool {
        if self.cofinite() {
            !self.except_v().iter().any(|e| e == x)
        } else {
            self.only_v().iter().any(|o| o == x)
        }
    }

    pub fn meet(&self, t: &Set) -> Set {
        match (self.cofinite(), t.cofinite()) {
            (false, false) => Set {
                only: Some(inter(self.only_v(), t.only_v())),
                except: None,
            },
            (false, true) => Set {
                only: Some(minus(self.only_v(), t.except_v())),
                except: None,
            },
            (true, false) => Set {
                only: Some(minus(t.only_v(), self.except_v())),
                except: None,
            },
            (true, true) => Set {
                only: None,
                except: Some(union(self.except_v(), t.except_v())),
            },
        }
    }

    pub fn join(&self, t: &Set) -> Set {
        match (self.cofinite(), t.cofinite()) {
            (false, false) => Set {
                only: Some(union(self.only_v(), t.only_v())),
                except: None,
            },
            (false, true) => Set {
                only: None,
                except: Some(minus(t.except_v(), self.only_v())),
            },
            (true, false) => Set {
                only: None,
                except: Some(minus(self.except_v(), t.only_v())),
            },
            (true, true) => Set {
                only: None,
                except: Some(inter(self.except_v(), t.except_v())),
            },
        }
    }

    /// self ⊆ t
    pub fn subset_of(&self, t: &Set) -> bool {
        match (self.cofinite(), t.cofinite()) {
            (false, false) => minus(self.only_v(), t.only_v()).is_empty(),
            (false, true) => inter(self.only_v(), t.except_v()).is_empty(),
            (true, false) => false, // a cofinite set is in no finite one
            (true, true) => minus(t.except_v(), self.except_v()).is_empty(),
        }
    }
}

impl Pair {
    pub fn new(allowed: Set, conditions: Vec<String>) -> Pair {
        Pair {
            allowed,
            conditions: Some(conditions),
        }
    }

    /// (everything, ∅)
    pub fn top() -> Pair {
        Pair::new(Set::except(Vec::<String>::new()), vec![])
    }

    fn conds(&self) -> &[String] {
        self.conditions.as_deref().unwrap_or(&[])
    }

    /// Well formed, as a document carries it (exactly one of only/except, sorted and unique)
    pub fn valid(&self) -> Result<(), Invalid> {
        if self.allowed.only.is_some() == self.allowed.except.is_some() {
            return Err(Invalid::OnlyXorExcept);
        }
        let Some(c) = &self.conditions else {
            return Err(Invalid::NoConditions);
        };
        check_strings(self.allowed.only_v())?;
        check_strings(self.allowed.except_v())?;
        check_strings(c)
    }

    /// P ⊓ Q
    pub fn meet(&self, q: &Pair) -> Pair {
        Pair::new(
            self.allowed.meet(&q.allowed),
            union(self.conds(), q.conds()),
        )
    }

    /// self ≤ q
    pub fn leq(&self, q: &Pair) -> bool {
        self.allowed.subset_of(&q.allowed) && minus(q.conds(), self.conds()).is_empty()
    }

    /// what the merger requires
    pub fn same_conditions(&self, q: &Pair) -> bool {
        self.conds() == q.conds()
    }

    /// (allowed₁ ∪ allowed₂, conditions), for pairs with the same conditions
    pub fn merge(&self, q: &Pair) -> Result<Pair, Invalid> {
        if !self.same_conditions(q) {
            return Err(Invalid::ConditionsDiffer);
        }
        Ok(Pair::new(
            self.allowed.join(&q.allowed),
            self.conds().to_vec(),
        ))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use rand::{Rng, SeedableRng};
    use std::collections::BTreeSet;

    const UNIVERSE: [&str; 4] = ["a", "b", "c", "d"];

    // every set over a small universe, checked against brute force (a cofinite set is judged on the universe plus
    // one string none of them names, standing for "everything else")
    fn sets() -> Vec<Set> {
        let mut out = vec![];
        for m in 0..16 {
            let xs: Vec<&str> = UNIVERSE
                .iter()
                .enumerate()
                .filter(|(i, _)| m & (1 << i) != 0)
                .map(|(_, u)| *u)
                .collect();
            out.push(Set::only(xs.clone()));
            out.push(Set::except(xs));
        }
        out
    }

    fn members(s: &Set) -> BTreeSet<&'static str> {
        UNIVERSE
            .iter()
            .copied()
            .chain(["zz"])
            .filter(|x| s.contains(x))
            .collect()
    }

    #[test]
    fn set_algebra_against_brute_force() {
        for s in sets() {
            for u in sets() {
                let (ms, mu) = (members(&s), members(&u));
                assert_eq!(s.subset_of(&u), ms.is_subset(&mu), "{s:?} ⊆ {u:?}");
                assert_eq!(members(&s.meet(&u)), &ms & &mu, "{s:?} ⊓ {u:?}");
                assert_eq!(members(&s.join(&u)), &ms | &mu, "{s:?} ⊔ {u:?}");
            }
        }
    }

    #[test]
    fn meet_only_narrows() {
        let mut r = rand::rngs::StdRng::seed_from_u64(1);
        let ss = sets();
        for _ in 0..2000 {
            let p = Pair::new(
                ss[r.gen_range(0..ss.len())].clone(),
                norm(vec![UNIVERSE[r.gen_range(0..4)].into()]),
            );
            let q = Pair::new(
                ss[r.gen_range(0..ss.len())].clone(),
                norm(vec![UNIVERSE[r.gen_range(0..4)].into(), "until:x".into()]),
            );
            let m = p.meet(&q);
            assert!(
                m.leq(&p) && m.leq(&q) && m.valid().is_ok(),
                "{p:?} {q:?} {m:?}"
            );
        }
        assert!(
            Pair::top()
                .meet(&Pair::new(Set::only(["x"]), vec!["c".into()]))
                .leq(&Pair::top())
        );
        assert!(Pair::top().valid().is_ok());
    }

    #[test]
    fn merge_needs_same_conditions() {
        let p = Pair::new(Set::only(["store:a"]), vec!["session:s1".into()]);
        let q = Pair::new(Set::only(["shell"]), vec!["session:s1".into()]);
        let m = p.merge(&q).unwrap();
        assert!(m.allowed.contains("shell") && m.allowed.contains("store:a"));
        assert!(
            p.merge(&Pair::new(
                Set::only(["shell"]),
                vec!["session:s1".into(), "until:x".into()]
            ))
            .is_err()
        );
    }

    #[test]
    fn valid_refuses() {
        for s in [
            r#"{"allowed":{},"conditions":[]}"#,
            r#"{"allowed":{"only":["a"],"except":["b"]},"conditions":[]}"#,
            r#"{"allowed":{"only":["b","a"]},"conditions":[]}"#,
            r#"{"allowed":{"only":["a","a"]},"conditions":[]}"#,
            r#"{"allowed":{"only":["a b"]},"conditions":[]}"#,
            r#"{"allowed":{"only":["a"]}}"#,
        ] {
            let accepted = serde_json::from_str::<Pair>(s).is_ok_and(|p| p.valid().is_ok());
            assert!(!accepted, "accepted {s}");
        }
    }

    #[test]
    fn json_round_trip() {
        for p in [
            Pair::top(),
            Pair::new(Set::only(Vec::<String>::new()), vec![]),
            Pair::new(Set::only(["a"]), vec!["x".into()]),
            Pair::new(Set::except(["b"]), vec![]),
        ] {
            let b = serde_json::to_string(&p).unwrap();
            let q: Pair = serde_json::from_str(&b).unwrap();
            assert!(q.valid().is_ok(), "{b}");
            assert_eq!(serde_json::to_string(&q).unwrap(), b);
        }
        assert_eq!(
            serde_json::to_string(&Pair::top()).unwrap(),
            r#"{"allowed":{"except":[]},"conditions":[]}"#
        );
    }
}
