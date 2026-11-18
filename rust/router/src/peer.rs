//! Helpers shared by the message paths. Every message into a session goes in as a core-attested delivery the machine
//! sends into its harness itself (vouch.rs deliver_vouched, rust/machine/src/deliver.rs); the router runs no command
//! for it, and no router feature holds a grant for it (into a session holding a sensitive store, Deyao delivers or
//! denies each message: messages.rs).

pub const PEER_MAX_TEXT: usize = 16000;

/// harnesses that take prompts through /usr/local/bin/harness-send rather than a claude host
pub fn harness_send(h: &str) -> bool {
    matches!(
        h,
        "opencode" | "openclaw" | "paseo-claude" | "aviary" | "dsh"
    )
}

/// CRLF → LF, trimmed, capped
pub fn clean_peer_text(text: &str) -> String {
    let t = text.replace("\r\n", "\n").replace('\r', "\n");
    jarvis_go::fmt::clip_bytes(t.trim(), PEER_MAX_TEXT).to_string()
}

/// the machine refused a router feature's shell (no grant, not on the allow list, a sensitive store). Retrying won't
/// help until Deyao grants it from the phone.
pub fn is_grant_refusal(err: Option<&anyhow::Error>) -> bool {
    let Some(e) = err else { return false };
    let m = format!("{e:#}");
    if !m.contains("the machine refused or failed") {
        return false;
    }
    [
        "allow list",
        "sensitive store",
        "phone grant",
        "grant is",
        "standing rule",
        "not signed by the phone",
    ]
    .iter()
    .any(|k| m.contains(k))
}
