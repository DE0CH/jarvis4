//! Peer messages (docs/DESIGN.md "Peer messages", DECISIONS 199): the only way one session's words reach another.
//! Claude Code's own cross-session channels are refused in every session (session-image/claude-code/
//! managed-settings.json: crossSessionInbound "refuse"), so a session with fewer secrets can't get one with more to act
//! for it (a confused deputy) behind Deyao's back. A session calls POST /m/api/requests/peer {to, text}
//! (`jarvis-message`); the router names the sender from its machine key and decides the direction:
//!
//! ```text
//! equal     the receiver holds exactly the sender's stores, in the same permission mode
//! downward  the receiver holds no store the sender lacks, and bypasses only if the sender does
//! upward    anything else: the receiver holds a store the sender lacks, or bypasses while the sender doesn't
//! ```
//!
//! Every peer message waits for Deyao (Deyao, 2026-11-18; DECISIONS 272): in the Inbox as a "peer-message" request that
//! he approves or denies with one tap (no Face ID: nothing is signed, like an API call), or, upward into a session
//! holding a sensitive store, as a message he delivers signed (messages.rs). The direction is shown to him and to the
//! receiver; it no longer decides whether the message waits. The receiving machine gets a core-attested "peer"
//! delivery carrying the verified sender, both sides' stores and modes, the direction and Deyao's approval; it checks
//! the direction against its own cert and wraps the text with all of it (rust/machine/src/peer.rs). A denial, a lapse
//! or a failed delivery comes back to the sender as its request's outcome (outcomes.rs).
//!
//! Repos count through their stores (a repo is its deploy-key store). Grants and standing rules don't count: they let a
//! router feature run commands in the session, not the session's Claude do more.

use crate::http::Registrar;
use crate::inbox::{ApiCall, BadRequest, Caller, Origin, RequestParams};
use crate::nethttp::write_json;
use crate::outcomes::{OUTCOME_APPROVED, OUTCOME_FAILED, note_outcome};
use crate::router::Router;
use crate::state::{Persisted, Session};
use crate::titles::session_title;
use crate::vouch::{Delivery, SignedRequest};
use anyhow::{Result, anyhow};
use jarvis_go::GoTime;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::BTreeSet;
use std::sync::{Arc, RwLock};

pub use crate::peer::clean_peer_text;

pub const REQUEST_KIND_PEER: &str = "peer-message";
/// characters of a peer message
pub const PEER_NOTE_MAX: usize = 8000;

/// what the receiving machine gets (rust/machine/src/peer.rs has the same struct: the core attests its JSON)
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct PeerNote {
    /// the sending session's id
    pub from: String,
    #[serde(rename = "fromTitle")]
    pub from_title: String,
    #[serde(rename = "fromStores")]
    pub from_stores: Vec<String>,
    /// auto | bypass
    #[serde(rename = "fromMode")]
    pub from_mode: String,
    pub to: String,
    #[serde(rename = "toStores")]
    pub to_stores: Vec<String>,
    #[serde(rename = "toMode")]
    pub to_mode: String,
    /// equal | downward | upward
    pub direction: String,
    /// Deyao approved it in the Inbox (every delivered note)
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub approved: bool,
    pub text: String,
}

pub fn mode_of(s: &Session) -> &'static str {
    if s.permission_mode == "bypass" {
        "bypass"
    } else {
        "auto"
    }
}

/// the stores the session's machine holds, as its latest cert names them (the machine checks against the same list);
/// the router's list when there is no cert yet
pub fn peer_stores(s: &Session) -> Vec<String> {
    crate::flows::cert_stores_harness(s.cert.as_ref(), s.stores.as_deref().unwrap_or_default(), "")
        .0
}

fn sorted(mut v: Vec<String>) -> Vec<String> {
    v.sort();
    v
}

/// equal, downward or upward, and why it is upward (the stores the receiver has beyond the sender's, and whether it
/// bypasses while the sender doesn't)
pub fn peer_direction(from: &Session, to: &Session) -> (&'static str, Vec<String>, bool) {
    let have: BTreeSet<String> = peer_stores(from).into_iter().collect();
    let extra = sorted(
        peer_stores(to)
            .into_iter()
            .filter(|s| !have.contains(s))
            .collect(),
    );
    let mode_up = mode_of(to) == "bypass" && mode_of(from) != "bypass";
    if !extra.is_empty() || mode_up {
        return ("upward", extra, mode_up);
    }
    if peer_stores(from).len() == peer_stores(to).len() && mode_of(from) == mode_of(to) {
        return ("equal", vec![], false);
    }
    ("downward", vec![], false)
}

fn clip(s: &str, n: usize) -> String {
    crate::util::trim_to(s, n)
}

pub fn peer_note(from: &Session, to: &Session, text: &str) -> PeerNote {
    PeerNote {
        from: from.id.clone(),
        from_title: clip(&session_title(from), 200),
        from_stores: sorted(peer_stores(from)),
        from_mode: mode_of(from).into(),
        to: to.id.clone(),
        to_stores: sorted(peer_stores(to)),
        to_mode: mode_of(to).into(),
        direction: peer_direction(from, to).0.into(),
        approved: false,
        text: text.into(),
    }
}

/// the receiving session by id, or by its exact title when exactly one live session has it
pub fn resolve_peer(d: &Persisted, to: &str) -> Result<Session> {
    let to = to.trim();
    let live = |s: &Session| s.state != "destroyed" && s.state != "destroying";
    if let Some(s) = d.sessions.get(to).filter(|s| live(s)) {
        return Ok(s.clone());
    }
    let hit: Vec<&Session> = d
        .sessions
        .values()
        .filter(|s| live(s) && !to.is_empty() && session_title(s).eq_ignore_ascii_case(to))
        .collect();
    match hit.len() {
        1 => Ok(hit[0].clone()),
        0 => Err(BadRequest(format!(
            "no session {} (its id, or its exact title)",
            jarvis_go::fmt::go_quote(to)
        ))
        .into()),
        n => Err(BadRequest(format!(
            "{n} sessions are titled {}: use the session id",
            jarvis_go::fmt::go_quote(to)
        ))
        .into()),
    }
}

fn list_or_none(ss: &[String]) -> String {
    if ss.is_empty() {
        "none".into()
    } else {
        clip(&ss.join(", "), 120)
    }
}

/// the Inbox item's words, by the router: who wants to tell whom, the direction and why
pub fn peer_explanation(from: &Session, to: &Session) -> String {
    let (dir, extra, mode_up) = peer_direction(from, to);
    let mut why = vec![];
    match dir {
        "equal" => why.push("both hold the same stores in the same mode".to_string()),
        "downward" => why.push(
            "the sender holds every store the receiver holds, and the receiver is no more permissive"
                .to_string(),
        ),
        _ => {}
    }
    if !extra.is_empty() {
        why.push(format!(
            "the receiver holds {}, which the sender doesn't",
            list_or_none(&extra)
        ));
    }
    if mode_up {
        why.push("the receiver runs in bypass mode and the sender doesn't".to_string());
    }
    format!(
        "{}{}: {}.\nSession “{}” ({}; stores {}; {} mode) wants to tell session “{}” ({}; stores {}; {} mode) the message above.",
        dir[..1].to_uppercase(),
        &dir[1..],
        why.join("; "),
        clip(&session_title(from), 80),
        from.id,
        list_or_none(&sorted(peer_stores(from))),
        mode_of(from),
        clip(&session_title(to), 80),
        to.id,
        list_or_none(&sorted(peer_stores(to))),
        mode_of(to)
    )
}

/// an upward message into a session holding a sensitive store isn't filed as a peer request: Deyao delivers or denies
/// the message itself, signed (messages.rs), so it carries his approval in that signature. Every other message is a
/// peer request (DECISIONS 272) → (the note, held)
pub fn held_peer_note(mut note: PeerNote, recv: &Session) -> (PeerNote, bool) {
    if !crate::messages::cert_sensitive(recv.cert.as_ref()) || note.direction != "upward" {
        return (note, false);
    }
    note.approved = true;
    (note, true)
}

/// what the core attests for a peer delivery (rust/machine/src/peer.rs checks the same bytes)
pub fn peer_attested(n: Option<&PeerNote>) -> Result<(Vec<u8>, String)> {
    let n = n
        .filter(|n| !n.from.is_empty() && !n.to.is_empty() && !n.text.is_empty())
        .ok_or_else(|| anyhow!("peer: no note"))?;
    Ok((
        jarvis_go::marshal(n).into_bytes(),
        format!("session:{}", n.from),
    ))
}

pub type PeerHook = Arc<dyn Fn(&Arc<Router>, &PeerNote, &Origin) -> Result<()> + Send + Sync>;
/// a peer note's delivery (tests); AwaitingApproval: held for Deyao, who decides; o hears of it
pub static DELIVER_PEER_HOOK: RwLock<Option<PeerHook>> = RwLock::new(None);

impl Router {
    /// the sending session, the receiving one (its id or exact title) and the cleaned text, checked as a message is
    /// checked wherever it is filed (alone or as a batch item)
    pub fn peer_parties(
        &self,
        sender: &str,
        to: &str,
        text: &str,
    ) -> Result<(Session, Session, String)> {
        let clean = clean_peer_text(text);
        if clean.is_empty() {
            return Err(BadRequest("an empty message".into()).into());
        }
        let n = clean.chars().count();
        if n > PEER_NOTE_MAX {
            return Err(BadRequest(format!(
                "a message longer than {PEER_NOTE_MAX} characters ({n})"
            ))
            .into());
        }
        let (from, recv) = self.st.do_(|d| -> Result<(Session, Session)> {
            let from = d
                .sessions
                .get(sender)
                .cloned()
                .ok_or_else(crate::sessionapi::no_session)?;
            Ok((from, resolve_peer(d, to)?))
        })?;
        if recv.id == from.id {
            return Err(BadRequest("that is this session".into()).into());
        }
        Ok((from, recv, clean))
    }

    /// the sending session's message → filed in the Inbox for Deyao's one tap, or (upward into a sensitive session)
    /// held for him to deliver signed. A batch takes the same message as an item (intent "peer", batches.rs), so it
    /// goes in one Inbox entry with the session's other asks.
    pub fn send_peer(
        self: &Arc<Self>,
        sender: &str,
        to: &str,
        text: &str,
        signed: SignedRequest,
        method: &str,
        path: &str,
    ) -> Result<Value> {
        let (from, recv, text) = self.peer_parties(sender, to, text)?;
        let mut args = Map::new();
        args.insert("to".into(), json!(recv.id));
        let o = Origin {
            caller: Caller {
                kind: "session".into(),
                session: sender.into(),
            },
            call: ApiCall {
                method: method.into(),
                path: path.strip_prefix("/m").unwrap_or(path).into(),
                args,
            },
            signed: Some(signed),
            ..Default::default()
        };
        let note = peer_note(&from, &recv, &text);
        let (held, is_held) = held_peer_note(note.clone(), &recv);
        if is_held {
            self.go_peer_note(held, o, "");
            return Ok(
                json!({"delivering": true, "direction": note.direction, "to": recv.id, "waiting": "message",
                "note": "the receiving session holds a sensitive store: Deyao delivers or denies this message in the Inbox; you hear the outcome"}),
            );
        }
        let (q, dup) = self.file_request(
            REQUEST_KIND_PEER,
            RequestParams {
                session: recv.id.clone(),
                text,
                ..Default::default()
            },
            &peer_explanation(&from, &recv),
            o,
        )?;
        Ok(
            json!({"id": q.id, "duplicate": dup, "expires": q.expires, "direction": note.direction, "waiting": "inbox", "to": recv.id}),
        )
    }

    /// deliver_peer_note in the background
    pub fn go_peer_note(self: &Arc<Self>, note: PeerNote, o: Origin, r#ref: &str) {
        let (r, rf) = (self.clone(), r#ref.to_string());
        std::thread::spawn(move || r.deliver_peer_note(&note, &o, &rf));
    }

    /// the note into the receiving session (started if paused); a failure is the sender's outcome. ref: the Inbox id
    /// an approved message had ("" for one Deyao delivers signed: the receiver's id names it then).
    fn deliver_peer_note(self: &Arc<Self>, note: &PeerNote, o: &Origin, r#ref: &str) {
        let res = match DELIVER_PEER_HOOK
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        {
            Some(h) => h(self, note, o),
            None => self.deliver_vouched_opts(
                &note.to,
                Delivery {
                    kind: "peer".into(),
                    peer: Some(note.clone()),
                    ..Default::default()
                },
                true,
                Some(o),
            ),
        };
        let rf = if r#ref.is_empty() {
            note.to.clone()
        } else {
            r#ref.to_string()
        };
        match res {
            // messages.rs: the receiver holds a sensitive store; Deyao decides, the sender hears
            Err(e) if crate::messages::is_awaiting_approval(&e) => {
                crate::logf!(
                    "peer message {} → {} ({}) waits for Deyao",
                    note.from,
                    note.to,
                    note.direction
                );
            }
            Err(e) => {
                crate::logf!(
                    "peer message {} → {} ({}) not delivered: {e:#}",
                    note.from,
                    note.to,
                    note.direction
                );
                self.st.do_(|d| {
                    note_outcome(d, Some(o), REQUEST_KIND_PEER, &rf, OUTCOME_FAILED, 0, None)
                });
            }
            Ok(()) => {
                crate::logf!(
                    "peer message {} → {} ({}) delivered",
                    note.from,
                    note.to,
                    note.direction
                );
                if note.approved {
                    self.st.do_(|d| {
                        note_outcome(
                            d,
                            Some(o),
                            REQUEST_KIND_PEER,
                            &rf,
                            OUTCOME_APPROVED,
                            0,
                            None,
                        )
                    });
                }
            }
        }
    }

    /// Deyao's one tap on a peer message: it is delivered now, with the sessions' current stores
    pub fn approve_peer(self: &Arc<Self>, id: &str) -> Result<Value> {
        let found = self.st.do_(|d| {
            crate::inbox::prune_requests(d, GoTime::now());
            let x = d
                .inbox
                .get(id)
                .filter(|x| x.kind == REQUEST_KIND_PEER)?
                .clone();
            let f = d.sessions.get(&x.origin.caller.session)?.clone();
            let t = d.sessions.get(&x.params.session)?.clone();
            d.inbox.remove(id);
            Some((x, f, t))
        });
        let (q, from, to) = found.ok_or_else(crate::apicalls::no_request)?;
        let mut note = peer_note(&from, &to, &q.params.text);
        note.approved = true;
        let dir = note.direction.clone();
        self.go_peer_note(note, q.origin.clone(), &q.id);
        Ok(json!({"ok": true, "state": "delivering", "direction": dir}))
    }

    /// an Inbox id that is a peer message (the approve route serves both kinds)
    pub fn is_peer_request(&self, id: &str) -> bool {
        self.st
            .do_(|d| d.inbox.get(id).is_some_and(|x| x.kind == REQUEST_KIND_PEER))
    }
}

pub fn register_peer_messages(reg: &mut Registrar) {
    reg.m("POST /m/api/requests/peer", |r, w, req, machine, b| {
        let sid = match r.machine_session(machine) {
            Err(e) => return write_json(w, 403, &json!({"error": format!("{e:#}")})),
            Ok(s) => s,
        };
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct In {
            to: String,
            text: String,
        }
        let i = match jarvis_go::unmarshal::<In>(b) {
            Err(e) => return write_json(w, 400, &json!({"error": format!("bad JSON: {e}")})),
            Ok(i) => i,
        };
        let signed = crate::vouch::signed_request_of(req, &req.header("X-Machine"), b);
        let (method, path) = (req.method.clone(), req.path.clone());
        match r.send_peer(&sid, &i.to, &i.text, signed, &method, &path) {
            Err(e) => crate::inbox::write_request_err(w, &e),
            Ok(out) => {
                let code = if out.get("delivering") == Some(&json!(true)) {
                    202
                } else {
                    200
                };
                write_json(w, code, &out);
            }
        }
    });
}
