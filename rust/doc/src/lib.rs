//! The kernel's documents, the Rust port of kernel/doc (docs/PLAN-grants.md §2). Every one travels as a signed
//! [`Doc`] and opens strictly: an unknown field refuses it. A source's settings stay opaque JSON (only the guard gives
//! them meaning), kept byte for byte.
//!
//! Not ported here: `IdealKeys` (hash-to-curve, kernel/h2c), which only the kernel needs; it comes with the kernel.

pub mod perm;

use jarvis_sig::{Doc, strict_json};
use perm::Pair;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use std::sync::LazyLock;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Sig(#[from] jarvis_sig::Error),
    #[error("{0}")]
    Invalid(String),
}

fn invalid<T>(s: impl Into<String>) -> Result<T, Error> {
    Err(Error::Invalid(s.into()))
}

#[allow(clippy::unwrap_used)] // fixed patterns, checked by the tests
fn re(p: &str) -> Regex {
    Regex::new(p).unwrap()
}

static SOURCE_RE: LazyLock<Regex> = LazyLock::new(|| re(r"^source-[0-9a-f]{32}$"));
static MACHINE_RE: LazyLock<Regex> =
    LazyLock::new(|| re(r"^(fly-[0-9a-f]{8,32}|aws-i-[0-9a-f]{8,17}|fabric-x[0-9a-f]{32})$"));
static IMAGE_RE: LazyLock<Regex> = LazyLock::new(|| {
    re(r"^[a-z0-9./-]+(:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?@sha256:[0-9a-f]{64}$")
});
static HEX64_RE: LazyLock<Regex> = LazyLock::new(|| re(r"^[0-9a-f]{64}$"));
static ABOUT_RE: LazyLock<Regex> = LazyLock::new(|| re(r"^[a-z][a-z0-9-]{0,31}$"));

// ---- objects --------------------------------------------------------------------------------------------------

/// "sink", "source-<32 hex>" or a machine: "fly-<Fly machine id>", "aws-<EC2 instance id>" or
/// "fabric-x<the sandbox's id at the fabric hermit, 32 hex>"
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Object(pub String);

pub const SINK: &str = "sink";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Sink,
    Source,
    Machine,
}

impl Object {
    /// None: not an object
    pub fn kind(&self) -> Option<Kind> {
        if self.0 == SINK {
            Some(Kind::Sink)
        } else if SOURCE_RE.is_match(&self.0) {
            Some(Kind::Source)
        } else if MACHINE_RE.is_match(&self.0) {
            Some(Kind::Machine)
        } else {
            None
        }
    }

    /// where a machine object runs, "fly", "aws" or "fabric" (None for the sink and a source)
    pub fn runner(&self) -> Option<&str> {
        (self.kind() == Some(Kind::Machine)).then(|| self.0.split_once('-').map_or("", |(r, _)| r))
    }

    /// the runner's id of a machine object (a Fly machine id, an EC2 instance id, x<a sandbox's id>)
    pub fn machine_id(&self) -> &str {
        self.0.split_once('-').map_or("", |(_, id)| id)
    }
}

/// an object's public keys
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Keys {
    pub signing_key: String,
    pub encryption_key: String,
}

// ---- sources and certs ----------------------------------------------------------------------------------------

/// what a cert into a source defines it as
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    /// ref@sha256:…
    pub image: String,
    /// the start settings (the guard's), kept byte for byte
    pub settings: Box<RawValue>,
    /// a kill's: the machine's signed snapshot hash
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub snapshot: String,
}

/// a machine as the spawner attests it (Go embeds Keys: its fields sit beside `image`)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Machine {
    pub signing_key: String,
    pub encryption_key: String,
    /// ref@sha256:… the runner reported
    pub image: String,
}

/// signers of succession certs (DESIGN's table)
pub mod by {
    pub const IPHONE: &str = "iphone";
    pub const ROOT: &str = "root";
    pub const SPAWNER: &str = "spawner";
    pub const IDENTITY: &str = "identity";
    pub const GULLIBLE: &str = "gullible";
}

/// a succession cert (pred → succ with pair), signed by `signer`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Cert {
    /// "succession"
    pub kind: String,
    pub pred: Object,
    pub succ: Object,
    pub pair: Pair,
    /// succ is a source
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<Source>,
    /// succ is a machine other than pred: its keys and image
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine: Option<Machine>,
    pub signer: String,
    pub issued_at: String,
}

/// RFC 3339 with or without fractional seconds, as Go's time.RFC3339Nano parses
pub fn rfc3339_ok(s: &str) -> bool {
    time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).is_ok()
}

impl Cert {
    /// well formed (not who signed it: the notarizer's table)
    pub fn check(&self) -> Result<(), Error> {
        let (pk, sk) = (self.pred.kind(), self.succ.kind());
        if self.kind != "succession" {
            return invalid("not a succession cert");
        }
        if pk.is_none() || sk.is_none() {
            return invalid("predecessor or successor isn't an object");
        }
        if (sk == Some(Kind::Source)) != self.source.is_some() {
            return invalid("a cert into a source carries the source, and only then");
        }
        if (sk == Some(Kind::Machine) && self.pred != self.succ) != self.machine.is_some() {
            return invalid("a cert into another Fly machine names its keys, and only then");
        }
        if let Err(e) = self.pair.valid() {
            return invalid(format!("pair: {e}"));
        }
        if let Some(s) = &self.source {
            if !IMAGE_RE.is_match(&s.image) {
                return invalid("source image: not ref@sha256:digest");
            }
            if !s.snapshot.is_empty() && !HEX64_RE.is_match(&s.snapshot) {
                return invalid("source snapshot: not a sha256");
            }
            if !matches!(
                serde_json::from_str::<serde_json::Value>(s.settings.get()),
                Ok(serde_json::Value::Object(_))
            ) {
                return invalid("source settings: not a JSON object");
            }
        }
        if let Some(m) = &self.machine
            && !IMAGE_RE.is_match(&m.image)
        {
            return invalid("machine image: not ref@sha256:digest");
        }
        if !rfc3339_ok(&self.issued_at) {
            return invalid("issuedAt");
        }
        Ok(())
    }
}

/// the cert `d` holds, signed by `public`, well formed
pub fn open_cert(d: &Doc, public: &str) -> Result<Cert, Error> {
    let c: Cert = d.open(public)?;
    c.check()?;
    Ok(c)
}

/// the cert's text, not checked against a signer (to find who signed it)
pub fn peek_cert(d: &Doc) -> Result<Cert, Error> {
    let c: Cert = strict_json(d.payload.as_bytes())?;
    c.check()?;
    Ok(c)
}

// ---- the log notary -------------------------------------------------------------------------------------------

/// one entry of the log notary's log
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Challenge {
    /// "challenge"
    pub kind: String,
    pub seq: i64,
    /// ID of the previous entry ("" = the first)
    pub prev: String,
    /// the notary's clock, RFC 3339 UTC
    pub at: String,
    pub subject: String,
    pub about: String,
    pub nonce: String,
}

/// what a challenge may be asked for
pub fn check_challenge_input(subject: &str, about: &str) -> Result<(), Error> {
    if !HEX64_RE.is_match(subject) {
        return invalid("subject: a sha256 in hex");
    }
    if !ABOUT_RE.is_match(about) {
        return invalid("about: a short lowercase word");
    }
    Ok(())
}

/// the notarizer's answer for a cert, carrying the notary's challenge over the cert's ID
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Notarized {
    /// "notarized"
    pub kind: String,
    /// ID of the cert
    pub cert: String,
    pub challenge: Doc,
}

// ---- grants ---------------------------------------------------------------------------------------------------

/// (machine, pair), made by the mover or the merger (⊤ on the sink by the root key)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    /// "grant"
    pub kind: String,
    pub machine: Object,
    /// the machine's keys (ideal keys for the sink or a source)
    pub keys: Keys,
    pub pair: Pair,
    /// IDs: the grant and notarization it was moved along, or the two merged (None: left out, invalid)
    pub from: Option<Vec<String>>,
    /// the newest notarized time along its chain
    pub at: String,
}

impl Grant {
    pub fn check(&self) -> Result<(), Error> {
        if self.kind != "grant" {
            return invalid("not a grant");
        }
        if self.machine.kind().is_none() {
            return invalid("machine isn't an object");
        }
        if self.keys.signing_key.is_empty() || self.keys.encryption_key.is_empty() {
            return invalid("keys missing");
        }
        if self.from.is_none() {
            return invalid("from missing");
        }
        if !rfc3339_ok(&self.at) {
            return invalid("at");
        }
        self.pair.valid().map_err(|e| Error::Invalid(e.to_string()))
    }
}

/// a grant signed by `public`, well formed
pub fn open_grant(d: &Doc, public: &str) -> Result<Grant, Error> {
    let g: Grant = d.open(public)?;
    g.check()?;
    Ok(g)
}

/// the kernel's time format (Go's time.RFC3339Nano in UTC: fraction without trailing zeros, "Z")
pub fn now() -> String {
    rfc3339_nano(time::OffsetDateTime::now_utc())
}

pub fn rfc3339_nano(t: time::OffsetDateTime) -> String {
    let t = t.to_offset(time::UtcOffset::UTC);
    let base = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    );
    let ns = t.nanosecond();
    if ns == 0 {
        return base + "Z";
    }
    let frac = format!("{ns:09}");
    format!("{base}.{}Z", frac.trim_end_matches('0'))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use jarvis_sig::Signer;

    fn obj(s: &str) -> Object {
        Object(s.into())
    }

    #[test]
    fn objects() {
        assert_eq!(obj("sink").kind(), Some(Kind::Sink));
        assert_eq!(
            obj(&format!("source-{}", "a".repeat(32))).kind(),
            Some(Kind::Source)
        );
        assert_eq!(obj("source-abc").kind(), None);
        let fly = obj("fly-0123456789abcd");
        assert_eq!(
            (fly.kind(), fly.runner(), fly.machine_id()),
            (Some(Kind::Machine), Some("fly"), "0123456789abcd")
        );
        let aws = obj("aws-i-0123456789abcdef0");
        assert_eq!(
            (aws.runner(), aws.machine_id()),
            (Some("aws"), "i-0123456789abcdef0")
        );
        let fab = obj(&format!("fabric-x{}", "f".repeat(32)));
        assert_eq!(fab.runner(), Some("fabric"));
        assert_eq!(obj("FLY-0123456789").kind(), None);
        assert_eq!(obj("sink").runner(), None);
    }

    fn cert_json(extra: &str) -> String {
        format!(
            r#"{{"kind":"succession","pred":"fly-0123456789abcd","succ":"source-{}","pair":{{"allowed":{{"only":["shell"]}},"conditions":[]}},"source":{{"image":"ghcr.io/de0ch/jarvis4-session:sha-1@sha256:{}","settings":{{"a": 1}}}},"signer":"iphone","issuedAt":"2026-11-17T14:00:00.123Z"{extra}}}"#,
            "b".repeat(32),
            "c".repeat(64)
        )
    }

    #[test]
    fn certs_open_and_check() {
        let s = Signer::generate();
        let payload = cert_json("");
        let d = Doc {
            sig: s.sign(payload.as_bytes()),
            payload,
        };
        let c = open_cert(&d, &s.public_key()).unwrap();
        assert_eq!(
            c.source.as_ref().unwrap().settings.get(),
            r#"{"a": 1}"#,
            "settings kept byte for byte"
        );
        assert!(peek_cert(&d).is_ok());
        assert!(open_cert(&d, &Signer::generate().public_key()).is_err());
        // an unknown field refuses it
        let payload = cert_json(r#","extra":1"#);
        assert!(
            peek_cert(&Doc {
                sig: s.sign(payload.as_bytes()),
                payload
            })
            .is_err()
        );
        // a cert into a source without the source
        let payload = cert_json("").replace(&format!(r#""source":{{"image":"ghcr.io/de0ch/jarvis4-session:sha-1@sha256:{}","settings":{{"a": 1}}}},"#, "c".repeat(64)), "");
        assert!(matches!(
            peek_cert(&Doc {
                sig: String::new(),
                payload
            }),
            Err(Error::Invalid(_))
        ));
        // a bad time
        let payload = cert_json("").replace("2026-11-17T14:00:00.123Z", "yesterday");
        assert!(
            peek_cert(&Doc {
                sig: String::new(),
                payload
            })
            .is_err()
        );
    }

    #[test]
    fn challenge_input() {
        assert!(check_challenge_input(&"a".repeat(64), "cert").is_ok());
        assert!(check_challenge_input(&"A".repeat(64), "cert").is_err());
        assert!(check_challenge_input(&"a".repeat(64), "Cert").is_err());
        assert!(check_challenge_input(&"a".repeat(64), &"a".repeat(33)).is_err());
    }

    #[test]
    fn grants_check() {
        let g = Grant {
            kind: "grant".into(),
            machine: obj("sink"),
            keys: Keys {
                signing_key: "k".into(),
                encryption_key: "e".into(),
            },
            pair: Pair::top(),
            from: Some(vec![]),
            at: now(),
        };
        assert!(g.check().is_ok(), "{}", g.at);
        assert!(
            Grant {
                from: None,
                ..g.clone()
            }
            .check()
            .is_err()
        );
        assert!(
            Grant {
                machine: obj("nobody"),
                ..g.clone()
            }
            .check()
            .is_err()
        );
        let s = Signer::generate();
        let d = s.sign_json(&g).unwrap();
        assert_eq!(open_grant(&d, &s.public_key()).unwrap(), g);
    }

    #[test]
    fn time_format_as_go() {
        let t = time::OffsetDateTime::from_unix_timestamp_nanos(1_794_927_600_120_000_000).unwrap();
        assert_eq!(rfc3339_nano(t), "2026-11-17T15:00:00.12Z");
        let t = time::OffsetDateTime::from_unix_timestamp(1_794_927_600).unwrap();
        assert_eq!(rfc3339_nano(t), "2026-11-17T15:00:00Z");
        assert!(
            rfc3339_ok("2026-11-17T15:00:00Z") && rfc3339_ok("2026-11-17T15:00:00.123456789+08:00")
        );
    }
}
