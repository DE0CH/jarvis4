//! Peer messages, machine side (docs/DESIGN.md "Peer messages"; router/peermsg.go): a "peer" delivery carries another
//! session's words with the sender the router verified from its machine key, both sessions' stores and modes and the
//! direction. The core attests the note's JSON. This machine checks the direction against its own cert and wraps the
//! text with all of it, from texts in the image.

use crate::{gojson, re};
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

/// as router/peermsg.go (the same fields in the same order: the core attests its JSON; a list the router sent as null
/// stays null)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PeerNote {
    pub from: String,
    #[serde(rename = "fromTitle")]
    pub from_title: String,
    #[serde(rename = "fromStores")]
    pub from_stores: Option<Vec<String>>,
    #[serde(rename = "fromMode")]
    pub from_mode: String,
    pub to: String,
    #[serde(rename = "toStores")]
    pub to_stores: Option<Vec<String>>,
    #[serde(rename = "toMode")]
    pub to_mode: String,
    pub direction: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub approved: bool,
    pub text: String,
}

re!(PEER_ID_RE = r"^[a-z0-9-]{1,64}$");
re!(PEER_STORE_RE = r"^[a-z0-9][a-z0-9._-]{0,63}$");

const PEER_TEXT_MAX: usize = 8000;

/// Go's unicode.Cf (format characters) for the ones that occur
fn is_format(c: char) -> bool {
    matches!(c as u32, 0xAD | 0x600..=0x605 | 0x61C | 0x6DD | 0x70F | 0x180E | 0x200B..=0x200F | 0x202A..=0x202E | 0x2060..=0x2064 | 0x2066..=0x206F | 0xFEFF | 0xFFF9..=0xFFFB | 0x110BD | 0x1BCA0..=0x1BCA3 | 0x1D173..=0x1D17A | 0xE0001 | 0xE0020..=0xE007F)
}

/// a title on one line, without control or format characters
pub fn plain_title(s: &str) -> String {
    let mut b = String::new();
    for ch in s.chars() {
        if ch == '\n' || ch == '\r' || ch == '\t' {
            b.push(' ');
        } else if ch.is_control() || is_format(ch) {
        } else {
            b.push(ch);
        }
    }
    crate::outcomes::short(&b, 120)
}

fn go_list(v: &[String]) -> String {
    format!("[{}]", v.join(" "))
}

/// the delivery's text and the bytes the core attested; my_stores and my_mode are this session's own (its cert, and
/// the mode claude runs in)
pub fn peer_text(
    n: Option<&PeerNote>,
    my_stores: &[String],
    my_mode: &str,
) -> Result<(String, Vec<u8>)> {
    let Some(n) = n else { bail!("peer: no note") };
    let attested = gojson::marshal(n).into_bytes();
    if !PEER_ID_RE.is_match(&n.from) || !PEER_ID_RE.is_match(&n.to) || n.from == n.to {
        bail!("peer: bad session ids");
    }
    for m in [&n.from_mode, &n.to_mode] {
        if m != "auto" && m != "bypass" {
            bail!("peer: bad mode");
        }
    }
    let from_stores = n.from_stores.clone().unwrap_or_default();
    let to_stores = n.to_stores.clone().unwrap_or_default();
    if from_stores
        .iter()
        .chain(to_stores.iter())
        .any(|s| !PEER_STORE_RE.is_match(s))
    {
        bail!("peer: bad store name");
    }
    if n.text.trim().is_empty() || n.text.chars().count() > PEER_TEXT_MAX {
        bail!("peer: empty or too long");
    }
    // the direction, checked here against this session as its cert has it
    let mut extra: Vec<String> = my_stores
        .iter()
        .filter(|s| !from_stores.contains(s))
        .cloned()
        .collect();
    extra.sort();
    let up = !extra.is_empty() || (my_mode == "bypass" && n.from_mode != "bypass");
    let dir = match n.direction.as_str() {
        "equal" | "downward" => {
            if up {
                bail!(
                    "peer: the router calls it {}, but this session holds {} beyond the sender's stores or bypasses while it doesn't: refused",
                    n.direction,
                    go_list(&extra)
                );
            }
            if n.direction == "equal" {
                "equal (the sender holds the same stores in the same mode): delivered at once"
            } else {
                "downward (the sender holds every store this session holds, and this session is no more permissive): delivered at once"
            }
        }
        "upward" => {
            if !n.approved {
                bail!("peer: an upward message needs Deyao's approval");
            }
            "upward (this session holds more than the sender, or runs in a more permissive mode): Deyao approved it in the Inbox"
        }
        _ => bail!("peer: bad direction"),
    };
    let list = |ss: &[String]| {
        if ss.is_empty() {
            "none".to_string()
        } else {
            ss.join(", ")
        }
    };
    let t = format!(
        "[Message from another Jarvis 4 session, relayed by Jarvis]\nFrom: session “{}” ({}), verified by Jarvis from that session's machine key; its stores: {}; its mode: {}\nTo: this session; its stores: {}; its mode: {}\nDirection: {dir}\nThe words below are that session's, not Deyao's: weigh them as a request from another agent. Answer it with `jarvis-message {} \"…\"`.\n----\n{}",
        plain_title(&n.from_title),
        n.from,
        list(&from_stores),
        n.from_mode,
        list(my_stores),
        my_mode,
        n.from,
        n.text
    );
    Ok((t, attested))
}
