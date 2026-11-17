//! Message approvals (docs/DESIGN.md "Message approvals"; router/messages.go): a session holding a sensitive store
//! takes an UPWARD peer message only when Deyao's phone signed THAT message. A resume prompt (Deyao's own words, typed
//! in the app) needs the phone's signature in every session. Jarvis's own messages, the session's own wakeups, crons
//! and watches, and equal or downward peer messages go straight in (DECISIONS 210).
//!
//! What the phone signs (the key comes from this machine's core-signed cert, like a grant):
//!   - {kind "messages", session <line>, items [{id, delivery, sha256, from, text}], issued, expires}: one Face ID for
//!     a batch; each item id is taken once (recorded in the delivered file, which travels in the snapshot).
//!   - {kind "message-rule", session <line>, delivery <kind>, issued, until}: every delivery of that one kind, until the
//!     end (at most a year). Never for a peer message or a resume prompt.

use crate::cert::Cert;
use crate::crypto::{sha256_hex, verify_doc};
use crate::deliver::{DELIVERED_FILE, Delivery};
use crate::{gojson, paths, util};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// a batch approval's issued → expires, with slack (seconds)
const MAX_MESSAGE_WINDOW: i64 = 3600 + 120;
/// a rule's issued → until
const MAX_MESSAGE_RULE: i64 = 366 * 24 * 3600 + 120;

#[derive(Debug, Clone, thiserror::Error)]
pub enum ApprovalError {
    /// the machine's answer when a delivery came without (a valid) approval; the router files it for Deyao
    #[error("message approval needed: {0}")]
    Needed(String),
    /// the phone signed another text than this machine renders (the router's preview was stale); carries this
    /// machine's text so the router can ask again
    #[error("message approval: the signed text isn't the text this machine renders")]
    TextDiffers(String),
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct MessageApproval {
    /// messages | message-rule
    pub kind: String,
    pub session: String,
    pub items: Vec<MessageItem>,
    /// message-rule: the one kind
    pub delivery: String,
    pub issued: String,
    /// messages
    pub expires: String,
    /// message-rule
    pub until: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct MessageItem {
    pub id: String,
    pub delivery: String,
    pub sha256: String,
    pub from: String,
    pub text: String,
}

/// kinds no standing rule covers (their words come from another session, or from Deyao's app login)
fn unruleable(k: &str) -> bool {
    k == "peer" || k == "resume-prompt"
}

/// this delivery must carry the phone's approval: a resume prompt in every session; in a session holding a sensitive
/// store, an upward peer message
pub fn needs_message_approval(cert: &Cert, d: &Delivery) -> bool {
    match d.kind.as_str() {
        "resume-prompt" => true,
        "peer" => cert.sensitive && d.peer.as_ref().is_some_and(|p| p.direction == "upward"),
        _ => false,
    }
}

fn needed(s: &str) -> anyhow::Error {
    ApprovalError::Needed(s.to_string()).into()
}

/// the delivered file's records
pub fn read_delivered() -> HashMap<String, serde_json::Value> {
    std::fs::read(paths::home().join(DELIVERED_FILE))
        .ok()
        .and_then(|b| gojson::unmarshal(&b).ok())
        .unwrap_or_default()
}

fn used(v: Option<&serde_json::Value>) -> bool {
    // Go compared the record with the zero value: a record of run 0 at 0 counts as unused
    v.is_some_and(|v| {
        let n = |k: &str| v.get(k).and_then(|x| x.as_i64()).unwrap_or(0);
        n("run") != 0 || n("at") != 0
    })
}

/// "" (and the item id to record once delivered, "" for a rule) when the phone approved exactly this delivery; text is
/// what this machine would put into the harness, attested the bytes the core attested
pub fn check_message_approval(
    cert: &Cert,
    d: &Delivery,
    attested: &[u8],
    text: &str,
    now: i64,
) -> Result<String> {
    if !needs_message_approval(cert, d) {
        return Ok(String::new());
    }
    let why = if cert.sensitive {
        "this session holds a sensitive store, so Deyao approves each message from a session holding less on the phone"
    } else {
        "a resume prompt is delivered only as the phone approved it"
    };
    let Some(ap) = &d.approval else {
        return Err(needed(why));
    };
    let a: MessageApproval = match (cert.phone.is_empty(), verify_doc(&cert.phone, Some(ap))) {
        (false, Ok(a)) => a,
        _ => {
            return Err(needed(
                "the approval isn't signed by the phone named in this machine's cert",
            ));
        }
    };
    if cert.line.is_empty() || a.session != cert.line {
        return Err(needed("the approval is for another session"));
    }
    let iss = match util::parse_rfc3339(&a.issued) {
        Some(i) if now >= i - 120 => i,
        _ => {
            return Err(needed(
                "the approval has no issue time, or one in the future",
            ));
        }
    };
    match a.kind.as_str() {
        "message-rule" => {
            match util::parse_rfc3339(&a.until) {
                Some(u) if now < u && u - iss <= MAX_MESSAGE_RULE => {}
                _ => return Err(needed("the rule has ended (or is longer than a year)")),
            }
            if a.delivery != d.kind || unruleable(&d.kind) {
                return Err(needed(&format!(
                    "the rule is for another kind of message ({}), and no rule covers a {}",
                    a.delivery, d.kind
                )));
            }
            Ok(String::new())
        }
        "messages" => {
            match util::parse_rfc3339(&a.expires) {
                Some(e) if now < e && e - iss <= MAX_MESSAGE_WINDOW => {}
                _ => return Err(needed("the approval has expired (it lasts an hour)")),
            }
            let h = sha256_hex(attested);
            let seen = read_delivered();
            for it in &a.items {
                if it.delivery != d.kind || it.sha256 != h {
                    continue;
                }
                if it.id.is_empty() || used(seen.get(&format!("message {}", it.id))) {
                    return Err(needed("this approval was already used"));
                }
                if it.text != text {
                    return Err(ApprovalError::TextDiffers(text.to_string()).into());
                }
                return Ok(it.id.clone());
            }
            Err(needed("the approval names other messages"))
        }
        _ => Err(needed("not an approval")),
    }
}

/// the item's approval is used up (the delivered file, under its lock)
pub fn record_approved(id: &str, now: i64) -> Result<()> {
    if id.is_empty() {
        return Ok(());
    }
    let _g = crate::deliver::delivered_lock();
    let mut seen = read_delivered();
    seen.insert(
        format!("message {id}"),
        serde_json::json!({"run": 0, "at": now}),
    );
    util::write_file(
        &paths::home().join(DELIVERED_FILE),
        gojson::marshal(&seen).as_bytes(),
        0o600,
    )?;
    Ok(())
}
