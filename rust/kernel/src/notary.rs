//! The log notary (kernel/notary; DESIGN "Target design"). It issues challenges with its own timestamp and logs each
//! one before answering it: an append-only file on its own volume, each entry naming the previous one's ID, so a gap
//! or an edit shows. It holds no secret but its key, and never reads what a subject means.

use crate::serve::{Answer, Server, fail, handle};
use jarvis_doc::{Challenge, check_challenge_input, rfc3339_nano};
use jarvis_sig::{Doc, Signer, go_json};
use serde::Deserialize;
use std::io::{BufRead, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};

struct Log {
    f: std::fs::File,
    seq: i64,
    prev: String,
}

pub struct Notary {
    log: Mutex<Log>,
    /// the clock (a test's own)
    pub now: fn() -> time::OffsetDateTime,
}

impl Notary {
    /// the log at path (made if missing); the chain goes on from its last entry
    pub fn open(path: &Path) -> anyhow::Result<Notary> {
        use std::os::unix::fs::OpenOptionsExt as _;
        let f = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .mode(0o600)
            .open(path)?;
        let (mut seq, mut prev) = (0i64, String::new());
        for line in std::io::BufReader::new(&f).lines() {
            let line = line?;
            let bad = || {
                anyhow::anyhow!(
                    "the log at {} has a bad line after seq {seq}",
                    path.display()
                )
            };
            let d: Doc = serde_json::from_str(&line).map_err(|_| bad())?;
            let c: Challenge = serde_json::from_str(&d.payload).map_err(|_| bad())?;
            (seq, prev) = (c.seq, d.id());
        }
        Ok(Notary {
            log: Mutex::new(Log { f, seq, prev }),
            now: time::OffsetDateTime::now_utc,
        })
    }

    /// the next log entry over subject, written (and synced) before it is answered
    pub fn challenge(&self, s: &Signer, subject: &str, about: &str) -> anyhow::Result<Doc> {
        check_challenge_input(subject, about).map_err(|e| fail(400, e.to_string()))?;
        let nonce = {
            let mut b = [0u8; 16];
            getrandom(&mut b);
            hex(&b)
        };
        let mut g = self.log.lock().unwrap_or_else(|e| e.into_inner());
        let c = Challenge {
            kind: "challenge".into(),
            seq: g.seq + 1,
            prev: g.prev.clone(),
            at: rfc3339_nano((self.now)()),
            subject: subject.into(),
            about: about.into(),
            nonce,
        };
        let d = s.sign_json(&c)?;
        let mut line = go_json(&d)?;
        line.push('\n');
        g.f.write_all(line.as_bytes())?;
        g.f.sync_all()?;
        (g.seq, g.prev) = (c.seq, d.id());
        Ok(d)
    }
}

fn getrandom(b: &mut [u8]) {
    use rand_core::RngCore as _;
    rand_core::OsRng.fill_bytes(b);
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChallengeIn {
    #[serde(default)]
    subject: String,
    #[serde(default)]
    about: String,
}

/// POST /challenge {subject, about}
pub fn register(s: &Arc<Server>, n: Arc<Notary>) {
    let s2 = s.clone();
    handle(s, "POST /challenge", move |i: ChallengeIn| {
        Ok(Answer::Doc(n.challenge(
            &s2.c.signer,
            &i.subject,
            &i.about,
        )?))
    });
}
