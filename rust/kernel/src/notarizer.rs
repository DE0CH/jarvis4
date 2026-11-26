//! The succession notarizer (kernel/notarizer; DESIGN "Target design"). It checks a succession cert against the policy
//! table — the shape (kinds of predecessor and successor), the signer's key, and "first successor of a source" — and
//! answers the log notary's challenge over the cert's ID. A shape not in the table is refused. It remembers, on its
//! own volume, every source that has been defined (a source is defined once, by the first cert into it) and every
//! source that has a successor; both are written and synced before the answer. That state moves to the other kernel
//! copy in the copy flip (flip.rs): the notarizer hands it over and freezes, the other copy's takes it.

use crate::serve::{Answer, Continuity, Server, Stateful, fail, fail_because, handle, log};
use jarvis_doc::perm::Pair;
use jarvis_doc::{Cert, Challenge, Kind, Notarized, Object, by, peek_cert};
use jarvis_sig::{
    Doc, Identity, Roster, Signer, Trust, check_identity, go_json, strict_json, verify,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// how far a challenge's time may be from the notarizer's clock
pub const CHALLENGE_SKEW: time::Duration = time::Duration::minutes(10);

/// 409: the cert's source was defined by an earlier cert
pub const REASON_DEFINED: &str = "already-defined";
/// 409: the cert's source already has its first successor
pub const REASON_HAS_SUCCESSOR: &str = "already-has-successor";

/// the phone's and the root key, as secrets signs them after the claim ({"kind":"keys",…})
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Keys {
    /// "keys"
    pub kind: String,
    pub phone: String,
    pub root: String,
}

/// a cert, the notary's challenge over it, and what names the signer's key
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub cert: Doc,
    pub challenge: Doc,
    pub notary: Identity,
    /// spawner, identity or gullible: its identity, checked against the roster
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<Identity>,
    /// iphone or root: secrets' signed Keys
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<Doc>,
    /// … and secrets' identity
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secrets: Option<Identity>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Entry {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    defined: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    succeeded: String,
}

struct St {
    f: std::fs::File,
    defined: BTreeSet<String>,
    succeeded: BTreeSet<String>,
}

pub struct Notarizer {
    path: PathBuf,
    st: Mutex<St>,
    /// its mode in the copy flip (path + ".mode")
    cont: Continuity,
    /// the clock (a test's own)
    pub now: fn() -> time::OffsetDateTime,
}

fn kind_name(o: &Object) -> &'static str {
    match o.kind() {
        Some(Kind::Sink) => "sink",
        Some(Kind::Source) => "source",
        Some(Kind::Machine) => "machine",
        None => "",
    }
}

fn open_append(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .append(true)
        .mode(0o600)
        .open(path)
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut p = path.as_os_str().to_owned();
    p.push(suffix);
    PathBuf::from(p)
}

/// the table row for a shape and signer, or why there is none
pub fn rule(c: &Cert) -> Result<(), String> {
    let (pk, sk, same) = (kind_name(&c.pred), kind_name(&c.succ), c.pred == c.succ);
    let ok = match c.signer.as_str() {
        by::ROOT => true,
        by::IPHONE => (pk == "sink" && sk == "source") || (pk == "source" && sk == "machine"),
        by::SPAWNER => {
            let ok = (pk == "source" && sk == "machine") || (pk == "machine" && sk == "source");
            if ok && (!c.pair.leq(&Pair::top()) || !Pair::top().leq(&c.pair)) {
                return Err("the spawner attests Fly facts only: its pair is ⊤".into());
            }
            ok
        }
        by::IDENTITY => pk == "machine" && same,
        by::GULLIBLE => pk == "source" && sk == "sink",
        other => {
            return Err(format!(
                "unknown signer {}",
                jarvis_go::fmt::go_quote(other)
            ));
        }
    };
    if !ok {
        return Err(format!(
            "({pk}, {sk}) signed by {} is not in the table",
            c.signer
        ));
    }
    Ok(())
}

impl Notarizer {
    /// the state at path (made if missing), its mode beside it
    pub fn open(path: &Path, t: &Trust) -> anyhow::Result<Notarizer> {
        let cont = Continuity::open(&with_suffix(path, ".mode"))?;
        let f = open_append(path)?;
        let (mut defined, mut succeeded) = (BTreeSet::new(), BTreeSet::new());
        for line in std::io::BufReader::new(&f).lines() {
            let line = line?;
            let e: Entry = serde_json::from_str(&line)
                .map_err(|e| anyhow::anyhow!("{}: a bad line: {e}", path.display()))?;
            if !e.defined.is_empty() {
                defined.insert(e.defined);
            }
            if !e.succeeded.is_empty() {
                succeeded.insert(e.succeeded);
            }
        }
        // a roster already held decides a new volume's mode now (else POST /roster does)
        if let Some(r) = t.roster() {
            cont.decide(&r, "notarizer")?;
        }
        Ok(Notarizer {
            path: path.into(),
            st: Mutex::new(St {
                f,
                defined,
                succeeded,
            }),
            cont,
            now: time::OffsetDateTime::now_utc,
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, St> {
        self.st.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// serving, standby or handed-off ("" before the first roster)
    pub fn mode(&self) -> String {
        self.cont.mode()
    }

    /// the public key that must have signed the cert
    fn signer_key(c: &Cert, i: &Input, t: &Trust) -> Result<String, String> {
        if c.signer == by::IPHONE || c.signer == by::ROOT {
            let (Some(kd), Some(sec)) = (&i.keys, &i.secrets) else {
                return Err(format!("a {} cert needs secrets' signed keys", c.signer));
            };
            check_identity(sec, "secrets", t).map_err(|e| e.to_string())?;
            let k: Keys = match kd.open::<Keys>(&sec.signing_key) {
                Ok(k) if k.kind == "keys" => k,
                Ok(_) => return Err("secrets' keys: <nil>".into()),
                Err(e) => return Err(format!("secrets' keys: {e}")),
            };
            return Ok(if c.signer == by::ROOT {
                k.root
            } else {
                k.phone
            });
        }
        let Some(s) = &i.signer else {
            return Err(format!(
                "a {} cert needs the {}'s identity",
                c.signer, c.signer
            ));
        };
        check_identity(s, &c.signer, t).map_err(|e| e.to_string())?;
        Ok(s.signing_key.clone())
    }

    /// the checks, then the record, then the answer
    pub fn notarize(&self, s: &Signer, t: &Trust, i: &Input) -> anyhow::Result<Doc> {
        let c = peek_cert(&i.cert).map_err(|e| fail(400, format!("cert: {e}")))?;
        rule(&c).map_err(|e| fail(403, e))?;
        let key = Self::signer_key(&c, i, t).map_err(|e| fail(403, e))?;
        if !verify(&key, i.cert.payload.as_bytes(), &i.cert.sig) {
            return Err(fail(
                403,
                format!("the cert isn't signed by the {}'s key", c.signer),
            ));
        }
        check_identity(&i.notary, "notary", t).map_err(|e| fail(403, e.to_string()))?;
        let ch: Challenge = match i.challenge.open::<Challenge>(&i.notary.signing_key) {
            Ok(ch) if ch.kind == "challenge" => ch,
            Ok(_) => return Err(fail(403, "challenge: <nil>")),
            Err(e) => return Err(fail(403, format!("challenge: {e}"))),
        };
        let at =
            time::OffsetDateTime::parse(&ch.at, &time::format_description::well_known::Rfc3339);
        let fresh = at.is_ok_and(|at| ((self.now)() - at).abs() <= CHALLENGE_SKEW);
        if ch.subject != i.cert.id() || ch.about != "cert" || !fresh {
            return Err(fail(403, "the challenge isn't a fresh one over this cert"));
        }
        let mut g = self.lock();
        self.cont.serving()?;
        let mut rec = vec![];
        if c.succ.kind() == Some(Kind::Source) {
            if g.defined.contains(&c.succ.0) {
                return Err(fail_because(
                    409,
                    REASON_DEFINED,
                    format!("{} is already defined", c.succ.0),
                ));
            }
            rec.push(Entry {
                defined: c.succ.0.clone(),
                ..Default::default()
            });
        }
        if c.pred.kind() == Some(Kind::Source) {
            if !g.defined.contains(&c.pred.0) {
                return Err(fail(409, format!("{} was never defined", c.pred.0)));
            }
            // the table's "first successor" rows
            let first = c.signer == by::SPAWNER || c.signer == by::IPHONE;
            if first && g.succeeded.contains(&c.pred.0) {
                return Err(fail_because(
                    409,
                    REASON_HAS_SUCCESSOR,
                    format!("{} already has a successor", c.pred.0),
                ));
            }
            rec.push(Entry {
                succeeded: c.pred.0.clone(),
                ..Default::default()
            });
        }
        for e in &rec {
            let mut b = go_json(e)?;
            b.push('\n');
            g.f.write_all(b.as_bytes())?;
        }
        g.f.sync_all()?;
        for e in rec {
            if !e.defined.is_empty() {
                g.defined.insert(e.defined);
            }
            if !e.succeeded.is_empty() {
                g.succeeded.insert(e.succeeded);
            }
        }
        Ok(s.sign_json(&Notarized {
            kind: "notarized".into(),
            cert: i.cert.id(),
            challenge: i.challenge.clone(),
        })?)
    }
}

/// the state as it moves to the other copy
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Handed {
    defined: Vec<String>,
    succeeded: Vec<String>,
}

impl Stateful for Notarizer {
    fn decide(&self, r: &Roster) -> anyhow::Result<()> {
        let _g = self.lock();
        self.cont.decide(r, "notarizer")
    }

    /// frozen (no notarization after it), then every defined and succeeded source
    fn handoff(&self, roster: &str) -> anyhow::Result<Vec<u8>> {
        let g = self.lock();
        self.cont.freeze(roster)?;
        Ok(go_json(&Handed {
            defined: g.defined.iter().cloned().collect(),
            succeeded: g.succeeded.iter().cloned().collect(),
        })?
        .into_bytes())
    }

    /// the predecessor's sources replace this volume's (written and synced before it serves)
    fn takeover(&self, id: &str, state: &[u8]) -> anyhow::Result<()> {
        let mut g = self.lock();
        if self.cont.can_take(id)? {
            return Ok(());
        }
        let h: Handed =
            strict_json(state).map_err(|e| fail(400, format!("the handed state: {e}")))?;
        let mut out = String::new();
        for o in &h.defined {
            out.push_str(&go_json(&Entry {
                defined: o.clone(),
                ..Default::default()
            })?);
            out.push('\n');
        }
        for o in &h.succeeded {
            out.push_str(&go_json(&Entry {
                succeeded: o.clone(),
                ..Default::default()
            })?);
            out.push('\n');
        }
        crate::files::write_synced(&self.path, out.as_bytes())?;
        g.f = open_append(&self.path)?;
        g.defined = h.defined.into_iter().collect();
        g.succeeded = h.succeeded.into_iter().collect();
        self.cont.took(id)?;
        log(&format!(
            "notarizer: took over {} defined and {} succeeded sources; serving",
            g.defined.len(),
            g.succeeded.len()
        ));
        Ok(())
    }
}

pub fn register(s: &Arc<Server>, n: Arc<Notarizer>) {
    let st: Arc<dyn Stateful> = n.clone();
    let _ = s.state.set(st);
    let s2 = s.clone();
    handle(s, "POST /notarize", move |i: Input| {
        Ok(Answer::Doc(n.notarize(&s2.c.signer, &s2.trust, &i)?))
    });
}
