//! Shared-device leases (Jarvis 1's lib/leases.js and its server.js routes, ported): several sessions share one
//! physical or cloud device (the WeChat cloud phone, Deyao's iPhone, his Mac) and must never drive it at the same
//! time. A resource is just a name; the router keeps, per name, at most ONE holder and a FIFO queue of waiting
//! sessions.
//!
//! ```text
//! acquire  → granted at once when free (or already ours: a renew), else queued (FIFO); a lowPriority caller (the
//!            WeChat warm-up) is never queued: it gets "busy".
//! renew    → the holder only; pushes expiresAt out by the lease's ttl (the device helpers renew on every action).
//! return   → the holder hands it back; the next waiter becomes the holder and is WOKEN (a delivery, resuming the
//!            session when it is paused). A waiter's DELETE leaves the queue.
//! expiry   → a holder that stopped renewing loses the lease at expiresAt; the next waiter is promoted the same way.
//! take-over / hand-back → Deyao takes the device himself from the app (holder "deyao", never expires); an agent
//!            holding it is told and goes to the front of the queue; on hand-back the next waiter is woken, and every
//!            other session that found it taken over meanwhile is told it is back.
//! ```
//!
//! Leases end with their session: a destroyed session's holder or queue place goes at the next tick.
//!
//! Jarvis 4 differences (docs/DECISIONS.md 100): the state is the router's (Persisted.leases), the holder is the
//! calling machine's own session (the path's id must be it), and the wake messages are deliveries the machine checks
//! (rust/machine/src/deliver.rs): "lease-granted" carries the waiter's own signed acquire request (its prompt and the
//! device name in the signed path), "lease-taken" and "lease-back" are texts built into the image over the device
//! name. Deyao's notes never go into a session (nothing vouches for them); the session reads them with lease.py
//! status. Jarvis 1's lease table is separate: Jarvis 4 is the lease authority for Jarvis 4 sessions.

use crate::http::{Registrar, null_if_empty};
use crate::router::Router;
use crate::vouch::{Delivery, SignedRequest};
use anyhow::Result;
use base64::Engine;
use jarvis_go::GoTime;
use jarvis_nethttp::{Req, W, write_json};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

/// seconds (Deyao, 2026-09-26: 1 hour, renewable)
pub const LEASE_DEFAULT_TTL: i64 = 3600;
pub const LEASE_MIN_TTL: i64 = 60;
pub const LEASE_MAX_TTL: i64 = 6 * 3600;
pub const LEASE_MAX_PURPOSE: usize = 200;
pub const LEASE_MAX_DESCR: usize = 2000;
pub const LEASE_MAX_PROMPT: usize = 2000;
pub const LEASE_MAX_NOTE: usize = 1000;
pub const LEASE_LOG_MAX: usize = 50;
/// the holder while Deyao has taken the device over
pub const LEASE_HUMAN: &str = "deyao";
pub const LEASE_TICK_EVERY: Duration = Duration::from_secs(30);
/// wake deliveries tried per promotion before the holder is left un-notified (logged)
pub const LEASE_MAX_ATTEMPTS: u32 = 20;

/// always listed (so Take over is there even when a device is free)
pub const KNOWN_DEVICES: &[&str] = &["wechat-phone", "iphone", "mac"];

static LEASE_NAME_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"^[a-z0-9][a-z0-9-]{0,40}$").unwrap_or_else(|_| unreachable!())
});
/// Go's \s: ASCII whitespace only
static SPACE_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"[\t\n\x0C\r ]+").unwrap_or_else(|_| unreachable!()));
static TRAILING_SPACE_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"[ \t]+\n").unwrap_or_else(|_| unreachable!()));
static BLANK_RUN_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"\n{3,}").unwrap_or_else(|_| unreachable!()));

fn is_false(b: &bool) -> bool {
    !*b
}

fn is_zero(n: &i64) -> bool {
    *n == 0
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct LeaseEntry {
    pub sid: String,
    #[serde(skip_serializing_if = "is_false")]
    pub human: bool,
    pub purpose: String,
    pub description: String,
    #[serde(rename = "describedAt")]
    pub described_at: i64,
    /// seconds
    pub ttl: i64,
    #[serde(skip_serializing_if = "is_zero")]
    pub since: i64,
    /// ms; 0 for Deyao
    #[serde(rename = "expiresAt", skip_serializing_if = "is_zero")]
    pub expires_at: i64,
    #[serde(rename = "enqueuedAt", skip_serializing_if = "is_zero")]
    pub enqueued_at: i64,
    /// the wake note (the session's own words)
    #[serde(skip_serializing_if = "String::is_empty")]
    pub prompt: String,
    /// the acquire request that carried the prompt, as signed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed: Option<SignedRequest>,
    /// Deyao's take-over note
    #[serde(skip_serializing_if = "String::is_empty")]
    pub note: String,
    #[serde(skip_serializing_if = "is_false")]
    pub promoted: bool,
    #[serde(skip_serializing_if = "is_false")]
    pub notified: bool,
    #[serde(skip_serializing_if = "is_false")]
    pub interrupted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handover: Option<LeaseHandover>,
    /// sessions that found it taken over (told on hand-back)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub blocked: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct LeaseHandover {
    #[serde(rename = "takenAt")]
    pub taken_at: i64,
    #[serde(rename = "returnedAt")]
    pub returned_at: i64,
    #[serde(rename = "takeNote", skip_serializing_if = "String::is_empty")]
    pub take_note: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub note: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct LeaseEvent {
    pub at: i64,
    pub kind: String,
    pub sid: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub purpose: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub note: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub interrupted: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct LeaseResource {
    pub holder: Option<LeaseEntry>,
    pub queue: Vec<LeaseEntry>,
    pub log: Vec<LeaseEvent>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct LeaseState {
    pub resources: BTreeMap<String, LeaseResource>,
}

#[derive(Debug)]
pub struct LeaseError {
    pub status: u16,
    pub msg: String,
    pub taken_over: bool,
}

impl std::fmt::Display for LeaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.msg)
    }
}

impl std::error::Error for LeaseError {}

fn lease_err(status: u16, msg: impl Into<String>) -> anyhow::Error {
    LeaseError {
        status,
        msg: msg.into(),
        taken_over: false,
    }
    .into()
}

fn bad_name() -> anyhow::Error {
    lease_err(400, "bad resource name (lowercase letters/digits/dashes)")
}

impl LeaseResource {
    fn log_ev(&mut self, now: i64, kind: &str, sid: &str, mut ev: LeaseEvent) {
        ev.at = now;
        ev.kind = kind.into();
        ev.sid = sid.into();
        self.log.push(ev);
        if self.log.len() > LEASE_LOG_MAX {
            let n = self.log.len() - LEASE_LOG_MAX;
            self.log.drain(..n);
        }
    }

    /// the next waiter becomes the holder (the tick wakes it); None when the queue is empty
    fn promote(&mut self, now: i64) -> Option<LeaseEntry> {
        if self.queue.is_empty() {
            self.holder = None;
            return None;
        }
        let next = self.queue.remove(0);
        let ttl = if next.ttl == 0 {
            LEASE_DEFAULT_TTL
        } else {
            next.ttl
        };
        let d = if next.described_at == 0 {
            now
        } else {
            next.described_at
        };
        self.holder = Some(LeaseEntry {
            sid: next.sid.clone(),
            purpose: next.purpose.clone(),
            description: next.description.clone(),
            described_at: d,
            ttl,
            since: now,
            expires_at: now + ttl * 1000,
            promoted: true,
            prompt: next.prompt.clone(),
            signed: next.signed.clone(),
            interrupted: next.interrupted,
            ..Default::default()
        });
        self.log_ev(now, "promoted", &next.sid, LeaseEvent::default());
        Some(next)
    }
}

pub fn lease_ttl(v: Option<&Value>) -> Result<i64> {
    let Some(v) = v.filter(|v| !v.is_null()) else {
        return Ok(LEASE_DEFAULT_TTL);
    };
    let f =
        crate::schedule::number(v).ok_or_else(|| lease_err(400, "ttlSeconds must be a number"))?;
    Ok((f.round().max(LEASE_MIN_TTL as f64)).min(LEASE_MAX_TTL as f64) as i64)
}

fn trunc_runes(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

pub fn clean_line(s: &str, max: usize) -> String {
    trunc_runes(SPACE_RE.replace_all(s, " ").trim(), max)
}

/// multi-line: keeps line breaks, trims trailing spaces, collapses blank runs
pub fn clean_text(s: &str, max: usize) -> String {
    let s = s.replace("\r\n", "\n").replace('\r', "\n");
    let s = TRAILING_SPACE_RE
        .replace_all(&format!("{s}\n"), "\n")
        .into_owned();
    let s = BLANK_RUN_RE.replace_all(&s, "\n\n").into_owned();
    trunc_runes(s.trim(), max)
}

/// an acquire's or describe's body
#[derive(Debug, Clone, Default)]
pub struct LeaseOpts {
    pub purpose: Option<String>,
    pub description: Option<String>,
    pub prompt: String,
    pub ttl: Option<Value>,
    pub low_priority: bool,
    pub signed: Option<SignedRequest>,
}

impl LeaseEntry {
    fn set_text(&mut self, o: &LeaseOpts, now: i64) {
        if let Some(p) = o.purpose.as_ref().filter(|p| !p.is_empty()) {
            self.purpose = clean_line(p, LEASE_MAX_PURPOSE);
        }
        if let Some(d) = &o.description {
            self.description = clean_text(d, LEASE_MAX_DESCR);
            self.described_at = now;
        }
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct LeaseOut {
    pub status: String,
    #[serde(skip_serializing_if = "is_zero_usize")]
    pub position: usize,
    pub lease: Value,
}

fn is_zero_usize(n: &usize) -> bool {
    *n == 0
}

#[derive(Debug, Clone, Default)]
pub struct GiveBackOut {
    pub returned: bool,
    pub previous: String,
    pub promoted: Option<LeaseEntry>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct TakeOverOut {
    pub taken: bool,
    pub interrupted: String,
    #[serde(rename = "noteUpdated", skip_serializing_if = "is_false")]
    pub note_updated: bool,
}

#[derive(Debug, Clone, Default)]
pub struct HandBackOut {
    pub handed_back: bool,
    pub promoted: Option<LeaseEntry>,
    pub notify: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct SweepChange {
    pub name: String,
    pub expired: String,
    pub promoted: Option<LeaseEntry>,
}

#[derive(Debug, Clone, Default)]
pub struct LeasePending {
    pub name: String,
    pub sid: String,
    pub since: i64,
    pub ttl: i64,
    pub signed: Option<SignedRequest>,
    pub handover: bool,
    pub interrupted: bool,
}

fn iso_ms(ms: i64) -> String {
    GoTime::from_unix_nanos(ms as i128 * 1_000_000)
        .utc()
        .rfc3339()
}

pub fn is_known_device(name: &str) -> bool {
    KNOWN_DEVICES.contains(&name)
}

impl LeaseState {
    fn res(&mut self, name: &str) -> Result<&mut LeaseResource> {
        if !LEASE_NAME_RE.is_match(name) {
            return Err(bad_name());
        }
        Ok(self.resources.entry(name.to_string()).or_default())
    }

    pub fn acquire(&mut self, name: &str, sid: &str, o: &LeaseOpts, now: i64) -> Result<LeaseOut> {
        let ttl = {
            self.res(name)?;
            lease_ttl(o.ttl.as_ref())?
        };
        let r = self.res(name)?;
        if let Some(h) = r.holder.as_mut().filter(|h| h.sid == sid) {
            h.expires_at = now + h.ttl * 1000;
            h.set_text(o, now);
            return Ok(LeaseOut {
                status: "renewed".into(),
                position: 0,
                lease: lease_view(r, name, now),
            });
        }
        let prompt = clean_line(&o.prompt, LEASE_MAX_PROMPT);
        if r.holder.is_none() {
            r.queue.retain(|w| w.sid != sid);
            // the prompt is kept for a direct grant too: if Deyao takes the device over, it goes back in the queue with it
            let h = LeaseEntry {
                sid: sid.into(),
                purpose: clean_line(o.purpose.as_deref().unwrap_or(""), LEASE_MAX_PURPOSE),
                description: clean_text(o.description.as_deref().unwrap_or(""), LEASE_MAX_DESCR),
                described_at: now,
                ttl,
                since: now,
                expires_at: now + ttl * 1000,
                prompt,
                signed: o.signed.clone(),
                ..Default::default()
            };
            let purpose = h.purpose.clone();
            r.holder = Some(h);
            r.log_ev(
                now,
                "granted",
                sid,
                LeaseEvent {
                    purpose,
                    ..Default::default()
                },
            );
            return Ok(LeaseOut {
                status: "granted".into(),
                position: 0,
                lease: lease_view(r, name, now),
            });
        }
        if o.low_priority {
            return Ok(LeaseOut {
                status: "busy".into(),
                position: 0,
                lease: lease_view(r, name, now),
            });
        }
        if !r.queue.iter().any(|x| x.sid == sid) {
            r.queue.push(LeaseEntry {
                sid: sid.into(),
                enqueued_at: now,
                ..Default::default()
            });
        }
        let i = r.queue.iter().rposition(|x| x.sid == sid).unwrap_or(0);
        let w = &mut r.queue[i];
        w.purpose = clean_line(o.purpose.as_deref().unwrap_or(""), LEASE_MAX_PURPOSE);
        if o.description.is_some() || w.described_at == 0 {
            w.description = clean_text(o.description.as_deref().unwrap_or(""), LEASE_MAX_DESCR);
            w.described_at = now;
        }
        w.prompt = prompt;
        w.signed = o.signed.clone();
        w.ttl = ttl;
        let pos = r
            .queue
            .iter()
            .position(|x| x.sid == sid)
            .map_or(0, |p| p + 1);
        Ok(LeaseOut {
            status: "queued".into(),
            position: pos,
            lease: lease_view(r, name, now),
        })
    }

    /// a session found the device taken over by Deyao; it is told when he hands it back. True while he has it.
    pub fn note_blocked(&mut self, name: &str, sid: &str) -> Result<bool> {
        let r = self.res(name)?;
        let Some(h) = r.holder.as_mut().filter(|h| h.human && !sid.is_empty()) else {
            return Ok(false);
        };
        if h.blocked.iter().any(|b| b == sid) {
            return Ok(true);
        }
        h.blocked.push(sid.into());
        if h.blocked.len() > 50 {
            h.blocked.remove(0);
        }
        Ok(true)
    }

    /// the holder only. While Deyao has the device the refusal says why and records the session (the caller keeps the
    /// state even then).
    pub fn renew(&mut self, name: &str, sid: &str, now: i64) -> Result<LeaseOut> {
        let r = self.res(name)?;
        if let Some(h) = r.holder.clone().filter(|h| h.human && h.sid != sid) {
            let pos = r.queue.iter().position(|w| w.sid == sid);
            self.note_blocked(name, sid)?;
            let msg = match pos {
                Some(i) => format!(
                    "don't touch it. You are #{} in the queue and will be woken when it is your turn",
                    i + 1
                ),
                None => format!(
                    "don't touch it. Jarvis will tell this session when he hands it back; to be GIVEN it then, queue now with scripts/lease.py acquire {name}"
                ),
            };
            let why = if h.note.is_empty() {
                " (no note)".to_string()
            } else {
                format!(" — his note: {}", jarvis_go::fmt::go_quote(&h.note))
            };
            return Err(LeaseError {
                status: 409,
                taken_over: true,
                msg: format!(
                    "Deyao has taken over {} himself (since {}){why} — {msg}",
                    jarvis_go::fmt::go_quote(name),
                    iso_ms(h.since)
                ),
            }
            .into());
        }
        let r = self.res(name)?;
        match r.holder.as_mut() {
            Some(h) if h.sid == sid => {
                h.expires_at = now + h.ttl * 1000;
                Ok(LeaseOut {
                    status: "renewed".into(),
                    position: 0,
                    lease: lease_view(r, name, now),
                })
            }
            other => {
                let held = other
                    .map(|h| format!(" (held by {})", h.sid))
                    .unwrap_or_default();
                Err(lease_err(
                    409,
                    format!(
                        "this session does not hold {}{held}",
                        jarvis_go::fmt::go_quote(name)
                    ),
                ))
            }
        }
    }

    /// the purpose and/or description of this session's holder or queue entry (no renew)
    pub fn describe(&mut self, name: &str, sid: &str, o: &LeaseOpts, now: i64) -> Result<LeaseOut> {
        let r = self.res(name)?;
        let status = if let Some(h) = r.holder.as_mut().filter(|h| h.sid == sid) {
            h.set_text(o, now);
            "holder"
        } else if let Some(w) = r.queue.iter_mut().find(|w| w.sid == sid) {
            w.set_text(o, now);
            "queued"
        } else {
            // nothing of this session's to describe: the lease as it is
            "none"
        };
        Ok(LeaseOut {
            status: status.into(),
            position: 0,
            lease: lease_view(r, name, now),
        })
    }

    /// the holder returns it ("return", never "release": releasing the cloud phone deletes it); force = the app's
    /// escape hatch
    pub fn give_back(
        &mut self,
        name: &str,
        sid: &str,
        now: i64,
        force: bool,
    ) -> Result<GiveBackOut> {
        let r = self.res(name)?;
        let Some(h) = r.holder.as_ref() else {
            return Ok(GiveBackOut::default());
        };
        if !force && h.sid != sid {
            return Err(lease_err(
                409,
                format!(
                    "this session does not hold {} (held by {})",
                    jarvis_go::fmt::go_quote(name),
                    h.sid
                ),
            ));
        }
        let prev = h.sid.clone();
        r.log_ev(
            now,
            if force { "force-returned" } else { "returned" },
            &prev,
            LeaseEvent::default(),
        );
        Ok(GiveBackOut {
            returned: true,
            previous: prev,
            promoted: r.promote(now),
        })
    }

    pub fn leave(&mut self, name: &str, sid: &str) -> Result<bool> {
        let r = self.res(name)?;
        let n = r.queue.len();
        r.queue.retain(|w| w.sid != sid);
        Ok(r.queue.len() < n)
    }

    /// Deyao takes the device himself; an agent holding it goes to the front of the queue. While he already has it, a
    /// take-over with a note only replaces his note.
    pub fn take_over(&mut self, name: &str, note: Option<&str>, now: i64) -> Result<TakeOverOut> {
        let r = self.res(name)?;
        if let Some(h) = r.holder.as_mut().filter(|h| h.human) {
            let Some(note) = note else {
                return Ok(TakeOverOut::default());
            };
            h.note = clean_line(note, LEASE_MAX_NOTE);
            let n = h.note.clone();
            r.log_ev(
                now,
                "note",
                LEASE_HUMAN,
                LeaseEvent {
                    note: n,
                    ..Default::default()
                },
            );
            return Ok(TakeOverOut {
                note_updated: true,
                ..Default::default()
            });
        }
        let mut out = TakeOverOut {
            taken: true,
            ..Default::default()
        };
        if let Some(h) = r.holder.take() {
            out.interrupted = h.sid.clone();
            r.queue.retain(|w| w.sid != h.sid);
            r.queue.insert(
                0,
                LeaseEntry {
                    sid: h.sid.clone(),
                    enqueued_at: now,
                    purpose: h.purpose.clone(),
                    description: h.description.clone(),
                    described_at: h.described_at,
                    prompt: h.prompt.clone(),
                    signed: h.signed.clone(),
                    ttl: h.ttl,
                    interrupted: true,
                    ..Default::default()
                },
            );
        }
        let note = clean_line(note.unwrap_or(""), LEASE_MAX_NOTE);
        r.holder = Some(LeaseEntry {
            sid: LEASE_HUMAN.into(),
            human: true,
            purpose: "Deyao is using it himself".into(),
            since: now,
            note: note.clone(),
            ..Default::default()
        });
        r.log_ev(
            now,
            "taken-over",
            LEASE_HUMAN,
            LeaseEvent {
                note,
                interrupted: out.interrupted.clone(),
                ..Default::default()
            },
        );
        Ok(out)
    }

    /// Deyao gives it back; the next waiter is promoted (woken by the tick) and the other sessions that found it taken
    /// over meanwhile are to be told it is back
    pub fn hand_back(&mut self, name: &str, note: &str, now: i64) -> Result<HandBackOut> {
        let r = self.res(name)?;
        let Some(holder) = r.holder.clone().filter(|h| h.human) else {
            return Ok(HandBackOut::default());
        };
        let h = LeaseHandover {
            taken_at: holder.since,
            returned_at: now,
            take_note: holder.note.clone(),
            note: clean_line(note, LEASE_MAX_NOTE),
        };
        r.log_ev(
            now,
            "handed-back",
            LEASE_HUMAN,
            LeaseEvent {
                note: h.note.clone(),
                ..Default::default()
            },
        );
        let p = r.promote(now);
        if p.is_some()
            && let Some(nh) = r.holder.as_mut()
        {
            nh.handover = Some(h);
        }
        let notify = holder
            .blocked
            .iter()
            .filter(|sid| p.as_ref().is_none_or(|p| **sid != p.sid))
            .cloned()
            .collect();
        Ok(HandBackOut {
            handed_back: true,
            promoted: p,
            notify,
        })
    }

    /// expire holders that stopped renewing; drop sessions that no longer exist (holder or waiting)
    pub fn sweep(&mut self, now: i64, alive: &dyn Fn(&str) -> bool) -> Vec<SweepChange> {
        let mut out = vec![];
        let names: Vec<String> = self.resources.keys().cloned().collect();
        for name in names {
            let Some(r) = self.resources.get_mut(&name) else {
                continue;
            };
            r.queue.retain(|w| alive(&w.sid));
            while let Some(h) = r
                .holder
                .as_ref()
                .filter(|h| !h.human && (h.expires_at <= now || !alive(&h.sid)))
            {
                let exp = h.sid.clone();
                r.log_ev(now, "expired", &exp, LeaseEvent::default());
                r.queue.retain(|w| alive(&w.sid));
                let promoted = r.promote(now);
                out.push(SweepChange {
                    name: name.clone(),
                    expired: exp,
                    promoted,
                });
            }
            if r.holder.is_none()
                && r.queue.is_empty()
                && !is_known_device(&name)
                && r.log.is_empty()
            {
                self.resources.remove(&name);
            }
        }
        out
    }

    /// holders promoted from the queue that haven't been told yet
    pub fn pending_notifications(&self) -> Vec<LeasePending> {
        self.resources
            .iter()
            .filter_map(|(name, r)| {
                let h = r.holder.as_ref().filter(|h| h.promoted && !h.notified)?;
                Some(LeasePending {
                    name: name.clone(),
                    sid: h.sid.clone(),
                    since: h.since,
                    ttl: h.ttl,
                    signed: h.signed.clone(),
                    handover: h.handover.is_some(),
                    interrupted: h.interrupted,
                })
            })
            .collect()
    }

    pub fn mark_notified(&mut self, name: &str, sid: &str, since: i64) {
        if let Some(h) = self
            .resources
            .get_mut(name)
            .and_then(|r| r.holder.as_mut())
            .filter(|h| h.sid == sid && h.since == since)
        {
            h.notified = true;
        }
    }

    pub fn list(&self, now: i64) -> Vec<Value> {
        let mut names: Vec<String> = KNOWN_DEVICES.iter().map(|s| s.to_string()).collect();
        names.extend(
            self.resources
                .keys()
                .filter(|n| !is_known_device(n))
                .cloned(),
        );
        let empty = LeaseResource::default();
        names
            .iter()
            .map(|n| lease_view(self.resources.get(n).unwrap_or(&empty), n, now))
            .collect()
    }
}

pub fn lease_entry_view(e: &LeaseEntry, now: i64) -> Value {
    let d = if e.described_at == 0 {
        e.since
    } else {
        e.described_at
    };
    let mut v = Map::new();
    v.insert("sid".into(), json!(e.sid));
    v.insert("human".into(), json!(e.human));
    v.insert("purpose".into(), json!(e.purpose));
    v.insert("description".into(), json!(e.description));
    v.insert("describedAt".into(), json!(d));
    v.insert("note".into(), json!(e.note));
    v.insert("since".into(), json!(e.since));
    v.insert("expiresAt".into(), Value::Null);
    v.insert("expiresInSeconds".into(), Value::Null);
    if !e.human {
        v.insert("expiresAt".into(), json!(e.expires_at));
        v.insert(
            "expiresInSeconds".into(),
            json!(0.max(((e.expires_at - now) as f64 / 1000.0).round() as i64)),
        );
    }
    Value::Object(v)
}

pub fn lease_view(r: &LeaseResource, name: &str, now: i64) -> Value {
    let holder = r
        .holder
        .as_ref()
        .map_or(Value::Null, |h| lease_entry_view(h, now));
    let q: Vec<Value> = r
        .queue
        .iter()
        .enumerate()
        .map(|(i, w)| {
            let d = if w.described_at == 0 { w.enqueued_at } else { w.described_at };
            json!({"position": i + 1, "sid": w.sid, "purpose": w.purpose, "description": w.description, "describedAt": d,
                "enqueuedAt": w.enqueued_at, "interrupted": w.interrupted})
        })
        .collect();
    let lg = &r.log[r.log.len().saturating_sub(20)..];
    json!({"name": name, "holder": holder, "queue": q, "log": lg})
}

// ---- the wake texts (built the same way in rust/machine/src/deliver.rs; the router picks when and for which device) --

pub fn lease_granted_text(
    device: &str,
    ttl_min: i64,
    handover: bool,
    interrupted: bool,
    prompt: &str,
) -> String {
    let q = jarvis_go::fmt::go_quote(device);
    let mut t = format!(
        "[lease {q} granted] This session now holds the shared device {q} (you were queued for it). "
    ) + &format!(
        "It is yours for {ttl_min} min, renewed automatically by the device helpers on every action; return it when done (scripts/lease.py return {device}). "
    );
    if handover {
        t += &format!("Deyao had taken {q} over himself");
        if interrupted {
            t += " (interrupting you: your earlier steps may no longer apply)";
        }
        t += &format!(
            " and has handed it back; his notes are in scripts/lease.py status {device}. The device is in whatever state he left it: look at it first (screenshot / UI tree) and continue from there."
        );
    } else {
        t += "The previous holder may have left it in any state: inspect it first.";
    }
    if !prompt.is_empty() {
        t += &format!(" Your note: {prompt}");
    }
    t
}

pub fn lease_taken_text(device: &str) -> String {
    let q = jarvis_go::fmt::go_quote(device);
    format!(
        "[lease {q} taken over] Deyao has taken the shared device {q} himself. Stop using it now: every device action is refused while he has it. "
    ) + "You are first in the queue; when he hands it back you'll be woken. Then look at the device first: it will be in whatever state he left it. "
        + "This is an automated message from Jarvis."
}

pub fn lease_back_text(device: &str) -> String {
    let q = jarvis_go::fmt::go_quote(device);
    format!(
        "[lease {q} handed back] Deyao has handed the shared device {q} back. Earlier this session found it taken over: that no longer applies. "
    ) + &format!(
        "Run scripts/lease.py status {device} to see whether it is free or who holds it now, and acquire it if this session still needs it (scripts/lease.py acquire {device} --purpose \"…\"). "
    ) + "If you told Deyao or planned around it being unavailable, reconsider now. It is in whatever state he left it: look at it first. "
        + "This is an automated message from Jarvis."
}

/// the prompt of a signed acquire request (what the machine reads from it too)
pub fn signed_prompt(s: Option<&SignedRequest>) -> String {
    let Some(s) = s else { return String::new() };
    let Ok(b) = base64::engine::general_purpose::STANDARD.decode(&s.body) else {
        return String::new();
    };
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct X {
        prompt: String,
    }
    clean_line(
        &jarvis_go::unmarshal::<X>(&b).unwrap_or_default().prompt,
        LEASE_MAX_PROMPT,
    )
}

// ---- the router's side --------------------------------------------------------------------------------------------

fn now_ms() -> i64 {
    (GoTime::now().unix_nanos() / 1_000_000) as i64
}

pub fn lease_error_out(w: &mut W, err: &anyhow::Error) {
    if let Some(le) = err.downcast_ref::<LeaseError>() {
        let mut out = json!({"error": le.msg});
        if le.taken_over {
            out["takenOver"] = json!(true);
        }
        return write_json(w, le.status, &out);
    }
    crate::schedule::schedule_err(w, err);
}

fn lease_body(b: &[u8]) -> Result<Map<String, Value>> {
    crate::sessionapi::decode_map(b).map_err(|e| lease_err(400, format!("{e:#}")))
}

fn opt_str(m: &Map<String, Value>, k: &str) -> Option<String> {
    match m.get(k) {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.clone()),
        Some(v) => Some(jarvis_go::fmt::go_sprint(v)),
    }
}

fn promoted_sid(p: &Option<LeaseEntry>) -> Value {
    p.as_ref().map_or(Value::Null, |p| json!(p.sid))
}

fn promoted_suffix(p: &Option<LeaseEntry>) -> String {
    p.as_ref()
        .map(|p| format!(" → {}", p.sid))
        .unwrap_or_default()
}

/// the wait between tries of a lease text (tests shorten it)
pub static LEASE_RETRY_WAIT_MS: AtomicU64 = AtomicU64::new(60_000);

#[derive(Default)]
struct LeaseRun {
    busy: BTreeSet<String>,
    attempts: BTreeMap<String, u32>,
}

static LEASE_RUN: LazyLock<Mutex<LeaseRun>> = LazyLock::new(|| Mutex::new(LeaseRun::default()));
static LEASE_TICKING: Mutex<()> = Mutex::new(());

fn lease_run() -> std::sync::MutexGuard<'static, LeaseRun> {
    LEASE_RUN.lock().unwrap_or_else(|e| e.into_inner())
}

impl Router {
    /// fn on the lease state inside one records change (kept even when fn refuses: a take-over refusal records the
    /// session that found it)
    pub fn lease_tx<R>(&self, mut f: impl FnMut(&mut LeaseState) -> Result<R>) -> Result<R> {
        self.st
            .do_(|d| f(d.leases.get_or_insert_with(LeaseState::default)))
    }

    pub fn lease_list(&self) -> Vec<Value> {
        self.lease_tx(|st| Ok(st.list(now_ms())))
            .unwrap_or_default()
    }

    fn get_lease(&self, w: &mut W, name: &str) {
        if !LEASE_NAME_RE.is_match(name) {
            return write_json(
                w,
                400,
                &json!({"error": "bad resource name (lowercase letters/digits/dashes)"}),
            );
        }
        let v = self
            .lease_tx(|st| {
                let empty = LeaseResource::default();
                Ok(lease_view(
                    st.resources.get(name).unwrap_or(&empty),
                    name,
                    now_ms(),
                ))
            })
            .unwrap_or_default();
        write_json(w, 200, &json!({"lease": v}));
    }

    /// Deyao takes the device himself (the app, or the setup session for him)
    pub fn take_over_lease(self: &Arc<Self>, w: &mut W, name: &str, b: &[u8]) {
        let res = lease_body(b).and_then(|m| {
            self.lease_tx(|st| st.take_over(name, opt_str(&m, "note").as_deref(), now_ms()))
        });
        let out = match res {
            Err(e) => return lease_error_out(w, &e),
            Ok(o) => o,
        };
        crate::logf!(
            "[lease] {name}: Deyao took it over (interrupted {})",
            jarvis_go::fmt::go_quote(&out.interrupted)
        );
        write_json(
            w,
            200,
            &json!({"taken": out.taken, "interrupted": null_if_empty(&out.interrupted), "noteUpdated": out.note_updated}),
        );
        if !out.interrupted.is_empty() {
            let (r, sid, name) = (self.clone(), out.interrupted.clone(), name.to_string());
            std::thread::spawn(move || {
                r.tell_lease(
                    &sid,
                    Delivery {
                        kind: "lease-taken".into(),
                        device: name,
                        ..Default::default()
                    },
                    1,
                )
            });
        }
    }

    /// Deyao gives it back
    pub fn hand_back_lease(self: &Arc<Self>, w: &mut W, name: &str, b: &[u8]) {
        let res = lease_body(b).and_then(|m| {
            let note = opt_str(&m, "note").unwrap_or_default();
            self.lease_tx(|st| st.hand_back(name, &note, now_ms()))
        });
        let out = match res {
            Err(e) => return lease_error_out(w, &e),
            Ok(o) => o,
        };
        crate::logf!(
            "[lease] {name}: Deyao handed it back{}; telling [{}]",
            promoted_suffix(&out.promoted),
            out.notify.join(" ")
        );
        write_json(
            w,
            200,
            &json!({"handedBack": out.handed_back, "next": promoted_sid(&out.promoted), "notified": out.notify}),
        );
        self.kick_leases(&out.promoted);
        for sid in out.notify {
            let (r, name) = (self.clone(), name.to_string());
            std::thread::spawn(move || {
                r.tell_lease(
                    &sid,
                    Delivery {
                        kind: "lease-back".into(),
                        device: name,
                        ..Default::default()
                    },
                    5,
                )
            });
        }
    }

    /// wake a promoted holder now rather than on the next tick
    fn kick_leases(self: &Arc<Self>, p: &Option<LeaseEntry>) {
        if p.is_some() {
            let r = self.clone();
            std::thread::spawn(move || r.lease_tick());
        }
    }

    /// an image text about a device (taken over, handed back), with a few retries (a session mid-pause or mid-start
    /// refuses a delivery for a while)
    fn tell_lease(self: &Arc<Self>, sid: &str, d: Delivery, tries: u32) {
        let mut i = 1;
        loop {
            match crate::schedule::deliver_vouched_hook(self, sid, d.clone()) {
                Ok(()) => {
                    crate::logf!("[lease] {}: told {sid} ({})", d.device, d.kind);
                    return;
                }
                Err(e) => {
                    if i >= tries || crate::sessionapi::is_no_session(&e) {
                        crate::logf!(
                            "[lease] {}: telling {sid} ({}) failed: {e:#}",
                            d.device,
                            d.kind
                        );
                        return;
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(
                LEASE_RETRY_WAIT_MS.load(Ordering::Relaxed),
            ));
            i += 1;
        }
    }

    pub fn lease_loop(self: &Arc<Self>) {
        loop {
            crate::leaderlease::await_lead();
            self.lease_tick();
            std::thread::sleep(LEASE_TICK_EVERY);
        }
    }

    /// expire silent holders, drop gone sessions, and wake each newly promoted holder. The wake is delivered outside
    /// the state lock (a paused session takes minutes to start) and marked only once delivered, so a failure is retried
    /// at the next tick.
    pub fn lease_tick(self: &Arc<Self>) {
        let Ok(_t) = LEASE_TICKING.try_lock() else {
            return;
        };
        let now = now_ms();
        let (changes, pending) = self.st.do_(|d| {
            let alive: BTreeSet<String> = d
                .sessions
                .iter()
                .filter(|(_, s)| s.state != "destroyed" && s.state != "destroying")
                .map(|(id, _)| id.clone())
                .collect();
            let st = d.leases.get_or_insert_with(LeaseState::default);
            let changes = st.sweep(now, &|sid| alive.contains(sid));
            (changes, st.pending_notifications())
        });
        for c in &changes {
            crate::logf!(
                "[lease] {}: {} lost it (expired or gone){}",
                c.name,
                c.expired,
                promoted_suffix(&c.promoted)
            );
        }
        for p in pending {
            let key = format!("{}/{}/{}", p.name, p.sid, p.since);
            {
                let mut g = lease_run();
                if g.busy.contains(&key)
                    || g.attempts.get(&key).copied().unwrap_or(0) >= LEASE_MAX_ATTEMPTS
                {
                    continue;
                }
                g.busy.insert(key.clone());
            }
            let r = self.clone();
            std::thread::spawn(move || {
                let k2 = key.clone();
                let _b = crate::flows::scopeguard(move || {
                    lease_run().busy.remove(&k2);
                });
                let d = Delivery {
                    kind: "lease-granted".into(),
                    device: p.name.clone(),
                    request: p.signed.clone(),
                    minutes: 1.max(p.ttl / 60),
                    handover: p.handover,
                    interrupted: p.interrupted,
                    ..Default::default()
                };
                let mark = |r: &Router| {
                    let _ = r.lease_tx(|st| {
                        st.mark_notified(&p.name, &p.sid, p.since);
                        Ok(())
                    });
                };
                match crate::schedule::deliver_vouched_hook(&r, &p.sid, d) {
                    Err(e) => {
                        let n = {
                            let mut g = lease_run();
                            let n = g.attempts.entry(key.clone()).or_default();
                            *n += 1;
                            *n
                        };
                        crate::logf!(
                            "[lease] {}: waking {} failed ({n}/{LEASE_MAX_ATTEMPTS}): {e:#}",
                            p.name,
                            p.sid
                        );
                        if crate::sessionapi::is_no_session(&e) || n >= LEASE_MAX_ATTEMPTS {
                            mark(&r);
                        }
                    }
                    Ok(()) => {
                        mark(&r);
                        lease_run().attempts.remove(&key);
                        crate::logf!("[lease] {}: {} woken", p.name, p.sid);
                    }
                }
            });
        }
    }
}

pub fn leases_state_hook(r: &Arc<Router>, out: &mut Map<String, Value>) {
    out.insert("leases".into(), json!(r.lease_list()));
}

/// a machine route on its own session's leases (the path's id, when there is one, must be its session)
fn own(
    reg: &mut Registrar,
    pattern: &str,
    f: impl Fn(&Arc<Router>, &mut W, &mut Req, &str, &str, &[u8]) + Send + Sync + 'static,
) {
    reg.m(pattern, move |r, w, req, machine, body| {
        let sid = match r.machine_session(machine) {
            Err(e) => return write_json(w, 403, &json!({"error": format!("{e:#}")})),
            Ok(s) => s,
        };
        let id = req.path_value("id");
        if !id.is_empty() && id != sid {
            return write_json(
                w,
                403,
                &json!({"error": format!("this machine is session {sid}, not {id}")}),
            );
        }
        f(r, w, req, &sid, machine, body)
    });
}

pub fn register_leases(reg: &mut Registrar) {
    // ---- the app (Deyao) ------------------------------------------------------------------------------------
    reg.app("GET /api/leases", |r, w, _| {
        write_json(w, 200, &json!({"leases": r.lease_list()}))
    });
    reg.app("GET /api/leases/{name}", |r, w, req| {
        r.get_lease(w, &req.path_value("name"))
    });
    reg.app("POST /api/leases/{name}/force-return", |r, w, req| {
        let name = req.path_value("name");
        let out = match r.lease_tx(|st| st.give_back(&name, "", now_ms(), true)) {
            Err(e) => return lease_error_out(w, &e),
            Ok(o) => o,
        };
        crate::logf!(
            "[lease] {name}: force-returned from {}{}",
            jarvis_go::fmt::go_quote(&out.previous),
            promoted_suffix(&out.promoted)
        );
        write_json(
            w,
            200,
            &json!({"returned": out.returned, "previous": null_if_empty(&out.previous), "next": promoted_sid(&out.promoted)}),
        );
        r.kick_leases(&out.promoted);
    });
    reg.app("POST /api/leases/{name}/take-over", |r, w, req| {
        let b = req.read_body(1 << 16);
        r.take_over_lease(w, &req.path_value("name"), &b);
    });
    reg.app("POST /api/leases/{name}/hand-back", |r, w, req| {
        let b = req.read_body(1 << 16);
        r.hand_back_lease(w, &req.path_value("name"), &b);
    });
    // the setup session (Claude, fully trusted: DECISIONS 57) acts for Deyao here, e.g. to carry his Jarvis 1
    // take-overs over (DECISIONS 113); signed with the setup key like every /setup call
    for act in ["take-over", "hand-back"] {
        reg.setup_route(
            &format!("POST /setup/leases/{{name}}/{act}"),
            move |r, w, req| {
                let b = req.read_body(1 << 16);
                if let Err(e) = r.check_setup_sig(
                    &req.method,
                    &req.path,
                    &req.header("X-Setup-Time"),
                    &req.header("X-Setup-Sig"),
                    &b,
                ) {
                    return write_json(w, 401, &json!({"error": format!("{e:#}")}));
                }
                if act == "take-over" {
                    r.take_over_lease(w, &req.path_value("name"), &b);
                } else {
                    r.hand_back_lease(w, &req.path_value("name"), &b);
                }
            },
        );
    }

    // ---- the session itself (through its machine's local proxy; the path's id must be its own) ---------------
    own(reg, "GET /m/api/leases", |r, w, _, _, _, _| {
        write_json(w, 200, &json!({"leases": r.lease_list()}))
    });
    own(reg, "GET /m/api/leases/{name}", |r, w, req, _, _, _| {
        r.get_lease(w, &req.path_value("name"))
    });
    own(
        reg,
        "POST /m/api/sessions/{id}/leases/{name}",
        |r, w, req, sid, machine, b| {
            let name = req.path_value("name");
            let m = match lease_body(b) {
                Err(e) => return lease_error_out(w, &e),
                Ok(m) => m,
            };
            let o = LeaseOpts {
                purpose: opt_str(&m, "purpose"),
                description: opt_str(&m, "description"),
                prompt: opt_str(&m, "prompt").unwrap_or_default(),
                ttl: m.get("ttlSeconds").cloned(),
                low_priority: m
                    .get("lowPriority")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                signed: Some(crate::vouch::signed_request_of(req, machine, b)),
            };
            let out = match r.lease_tx(|st| st.acquire(&name, sid, &o, now_ms())) {
                Err(e) => return lease_error_out(w, &e),
                Ok(o) => o,
            };
            if out.status != "renewed" {
                crate::logf!(
                    "[lease] {name}: {sid} {} #{} ({})",
                    out.status,
                    out.position,
                    crate::util::trim_to(o.purpose.as_deref().unwrap_or(""), 60)
                );
            }
            write_json(w, if out.status == "busy" { 409 } else { 200 }, &out);
        },
    );
    own(
        reg,
        "PUT /m/api/sessions/{id}/leases/{name}",
        |r, w, req, sid, _, _| {
            // a take-over refusal is kept too: it records the session to be told when Deyao hands the device back
            let res = r.lease_tx(|st| st.renew(&req.path_value("name"), sid, now_ms()));
            match res {
                Err(e) => lease_error_out(w, &e),
                Ok(out) => write_json(w, 200, &out),
            }
        },
    );
    own(
        reg,
        "PATCH /m/api/sessions/{id}/leases/{name}",
        |r, w, req, sid, _, b| {
            let res = lease_body(b).and_then(|m| {
                let o = LeaseOpts {
                    purpose: opt_str(&m, "purpose"),
                    description: opt_str(&m, "description"),
                    ..Default::default()
                };
                r.lease_tx(|st| st.describe(&req.path_value("name"), sid, &o, now_ms()))
            });
            match res {
                Err(e) => lease_error_out(w, &e),
                Ok(out) => write_json(w, 200, &out),
            }
        },
    );
    own(
        reg,
        "POST /m/api/sessions/{id}/leases/{name}/seen",
        |r, w, req, sid, _, _| match r.lease_tx(|st| st.note_blocked(&req.path_value("name"), sid))
        {
            Err(e) => lease_error_out(w, &e),
            Ok(taken) => write_json(w, 200, &json!({"takenOver": taken})),
        },
    );
    own(
        reg,
        "DELETE /m/api/sessions/{id}/leases/{name}",
        |r, w, req, sid, _, _| {
            let name = req.path_value("name");
            let res = r.lease_tx(|st| {
                let holds = st.res(&name)?.holder.as_ref().is_some_and(|h| h.sid == sid);
                if holds {
                    return Ok((st.give_back(&name, sid, now_ms(), false)?, false));
                }
                Ok((GiveBackOut::default(), st.leave(&name, sid)?))
            });
            let (gb, left) = match res {
                Err(e) => return lease_error_out(w, &e),
                Ok(x) => x,
            };
            let what = if gb.returned {
                "returned it"
            } else if left {
                "left the queue"
            } else {
                "had nothing"
            };
            crate::logf!(
                "[lease] {name}: {sid} {what}{}",
                promoted_suffix(&gb.promoted)
            );
            write_json(
                w,
                200,
                &json!({"returned": gb.returned, "left": left, "next": promoted_sid(&gb.promoted)}),
            );
            r.kick_leases(&gb.promoted);
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_take_over_and_back() {
        let mut st = LeaseState::default();
        let o = LeaseOpts {
            purpose: Some("  screen  shot ".into()),
            ..Default::default()
        };
        assert_eq!(
            st.acquire("mac", "a", &o, 1000).map(|x| x.status).ok(),
            Some("granted".into())
        );
        let q = st.acquire("mac", "b", &o, 2000).unwrap_or_default();
        assert_eq!((q.status.as_str(), q.position), ("queued", 1));
        let t = st.take_over("mac", Some("mine"), 3000).unwrap_or_default();
        assert_eq!(t.interrupted, "a");
        let r = st.renew("mac", "c", 3500);
        assert!(r.is_err_and(|e| e.downcast_ref::<LeaseError>().is_some_and(|l| l.taken_over)));
        let hb = st.hand_back("mac", "done", 4000).unwrap_or_default();
        assert_eq!(hb.promoted.map(|p| p.sid), Some("a".into()));
        assert_eq!(hb.notify, vec!["c".to_string()]);
        let res = &st.resources["mac"];
        assert_eq!(
            res.holder.as_ref().map(|h| h.purpose.as_str()),
            Some("screen shot")
        );
        assert!(res.holder.as_ref().is_some_and(|h| h.handover.is_some()));
        assert_eq!(clean_text("a  \n\n\n\nb\r\n", 100), "a\n\nb");
    }
}
