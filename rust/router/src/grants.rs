//! Grants (docs/DESIGN.md "Grants"): each router feature that needs a shell in a session has its own key pair (a
//! holder), kept sealed in the database. A session's machine runs a holder's command when the phone signed a grant (10
//! minutes at most) or a standing rule for that holder and line, or when the session put the holder on its own allow
//! list (`jarvis-machine allow`). The machine checks all of it against its core-signed cert; the router only drafts the
//! text for the phone, keeps what the phone signed, and relays requests and results.

use crate::core::Doc;
use crate::router::Router;
use crate::state::Session;
use anyhow::{Result, anyhow};
use jarvis_go::GoTime;
use jarvis_sig::Signer;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

/// the features that may hold grants (messages into a session are no feature's: they are deliveries the machine
/// checks, and into a session holding a sensitive store Deyao delivers or denies each one, messages.rs)
pub const HOLDER_NAMES: &[&str] = &["terminal", "status", "archive", "remote"];

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct StoredGrant {
    pub id: String,
    /// the router's session id
    pub session: String,
    /// the feature's name
    pub holder: String,
    /// grant | rule
    pub kind: String,
    pub ends: GoTime,
    pub doc: Option<Doc>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct GrantText {
    pub kind: String,
    pub holder: String,
    /// the line id (the machine's cert names it)
    pub session: String,
    pub scope: String,
    pub issued: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub expires: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub until: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct ExecResult {
    pub id: String,
    pub code: i64,
    pub stdout: String,
    pub stderr: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub error: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ExecItem {
    pub request: String,
    pub sig: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant: Option<Doc>,
}

/// each holder's private scalar, made once and kept sealed in the database (holders/<name>.key, sealed.rs), so standing
/// rules naming a key survive restarts
#[derive(Default)]
pub struct Holders(OnceLock<std::result::Result<BTreeMap<String, Vec<u8>>, String>>);

/// no grant that allows this; phone = only a fresh phone grant would
#[derive(Debug)]
pub struct GrantNeeded {
    pub holder: String,
    pub phone: bool,
}

impl std::fmt::Display for GrantNeeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.phone {
            write!(f, "this needs a fresh phone grant for {}", self.holder)
        } else {
            write!(f, "no grant for {}", self.holder)
        }
    }
}

impl std::error::Error for GrantNeeded {}

/// one field of a session's latest succession cert (the line id, the phone key)
pub fn cert_field(c: Option<&Doc>, field: &str) -> String {
    let Some(c) = c else { return String::new() };
    serde_json::from_str::<Value>(&c.payload)
        .ok()
        .and_then(|m| m.get(field).and_then(Value::as_str).map(String::from))
        .unwrap_or_default()
}

impl Router {
    fn holder_keys(&self) -> Result<BTreeMap<String, Vec<u8>>> {
        self.hk
            .0
            .get_or_init(|| {
                let mut keys = BTreeMap::new();
                for n in HOLDER_NAMES {
                    let name = format!("holders/{n}.key");
                    let k = match self.st.read_sealed(&name) {
                        Ok(Some(b)) => Signer::from_scalar(&b).map(|_| b).map_err(|e| anyhow!("{e}")),
                        Ok(None) => {
                            let s = Signer::generate().scalar();
                            self.st.write_sealed(&name, &s).map(|()| s)
                        }
                        Err(e) => Err(e),
                    };
                    match k {
                        Ok(k) => {
                            keys.insert(n.to_string(), k);
                        }
                        Err(e) => return Err(format!("holder {n}: {e:#}")),
                    }
                }
                Ok(keys)
            })
            .clone()
            .map_err(|e| anyhow!(e))
    }

    fn holder_signer(&self, holder: &str) -> Result<Signer> {
        let ks = self.holder_keys()?;
        let k = ks.get(holder).ok_or_else(|| anyhow!("unknown holder {holder}"))?;
        Signer::from_scalar(k).map_err(|e| anyhow!("{e}"))
    }

    pub fn holder_public_keys(&self) -> Result<BTreeMap<String, String>> {
        let ks = self.holder_keys()?;
        let mut out = BTreeMap::new();
        for (n, k) in ks {
            let s = Signer::from_scalar(&k).map_err(|e| anyhow!("{e}"))?;
            out.insert(n, s.public_key());
        }
        Ok(out)
    }

    /// the exact text the phone signs. kind "grant" lasts minutes (≤ 10); "rule" lasts until `until`.
    pub fn draft_grant(&self, session: &str, holder: &str, kind: &str, minutes: i64, until: GoTime) -> Result<String> {
        let public = self.holder_public_keys()?;
        let hk = public.get(holder).cloned().unwrap_or_default();
        if hk.is_empty() {
            return Err(anyhow!("unknown holder {holder}"));
        }
        let line = self.st.do_(|d| d.sessions.get(session).map(session_line).unwrap_or_default());
        if line.is_empty() {
            return Err(anyhow!("the session has no certified machine yet"));
        }
        let now = GoTime::now();
        let mut g = GrantText {
            kind: kind.into(),
            holder: hk,
            session: line,
            scope: "shell".into(),
            issued: now.rfc3339(),
            ..Default::default()
        };
        match kind {
            "grant" => {
                if !(1..=10).contains(&minutes) {
                    return Err(anyhow!("a grant lasts 1 to 10 minutes"));
                }
                g.expires = now.add(time::Duration::minutes(minutes)).rfc3339();
            }
            "rule" => {
                if !until.after(&now) {
                    return Err(anyhow!("a standing rule needs an end in the future"));
                }
                g.until = until.utc().rfc3339();
            }
            _ => return Err(anyhow!("kind is grant or rule")),
        }
        Ok(jarvis_go::marshal(&g))
    }

    /// keep what the phone signed, after checking it against the phone key in the session's cert
    pub fn add_grant(self: &Arc<Self>, session: &str, doc: Option<&Doc>) -> Result<StoredGrant> {
        let Some((doc, g)) = doc.and_then(|d| Some((d, jarvis_go::unmarshal::<GrantText>(d.payload.as_bytes()).ok()?))) else {
            return Err(anyhow!("bad grant"));
        };
        let public = self.holder_public_keys()?;
        let holder = public
            .iter()
            .filter(|(_, k)| **k == g.holder)
            .map(|(n, _)| n.clone())
            .next_back()
            .unwrap_or_default();
        let end = GoTime::parse(&format!("{}{}", g.expires, g.until));
        let (Some(end), false) = (end, holder.is_empty()) else {
            return Err(anyhow!("the grant names no holder of this router, or has no end"));
        };
        let res = self.st.do_(|d| -> Result<(StoredGrant, String)> {
            let Some(s) = d.sessions.get(session).filter(|s| session_line(s) == g.session) else {
                return Err(anyhow!("the grant is for another session"));
            };
            let phone = cert_field(s.cert.as_ref(), "phone");
            if phone.is_empty() || !crate::http::verify_p256(&phone, doc.payload.as_bytes(), &doc.sig) {
                return Err(anyhow!("not signed by the phone this session's cert names"));
            }
            let sg = StoredGrant {
                id: crate::util::rand_id(),
                session: session.into(),
                holder: holder.clone(),
                kind: g.kind.clone(),
                ends: end,
                doc: Some(doc.clone()),
            };
            d.grants.insert(sg.id.clone(), sg.clone());
            // the feature the machine turned away is tried again at the next tick, under this grant: without this the
            // loop kept its 10-minute back-off after a refusal, so a 10-minute grant often ran out unused and the
            // callout stayed — the button looked like it did nothing (2026-10-11)
            if let Some(l) = d.sessions.get_mut(session).and_then(|s| s.live.as_mut()) {
                l.grant_retry.remove(&holder);
                if l.needs_grant == holder {
                    l.needs_grant.clear();
                }
            }
            let mut answered = BTreeMap::new();
            let ids: Vec<String> = d
                .inbox
                .iter()
                .filter(|(_, q)| {
                    q.kind == crate::inbox::REQUEST_KIND_GRANT && q.params.session == session && q.params.holder == holder
                })
                .map(|(id, _)| id.clone())
                .collect();
            for id in ids {
                // a pending request for this feature is answered (inbox.rs)
                if let Some(q) = d.inbox.remove(&id) {
                    // the phone-signed grant vouches
                    crate::outcomes::note_outcome(d, Some(&q.origin), &q.kind, &q.id, crate::outcomes::OUTCOME_APPROVED, 0, Some(doc));
                    answered.insert(id, g.kind == "grant"); // a rule doesn't allow bypass
                }
            }
            let mut then = String::new(); // the permission mode to switch to now (ask_mode_grant)
            if holder == "terminal"
                && let Some(s) = d.sessions.get_mut(session)
            {
                // a switch to bypass that waited on this grant (sessionops.rs ask_mode_grant)
                then = crate::sessionops::mode_after_grant(s, &answered, GoTime::now());
            }
            Ok((sg, then))
        });
        let (sg, then) = res?;
        if !then.is_empty() {
            let (r, session) = (self.clone(), session.to_string());
            std::thread::spawn(move || r.run_mode_after_grant(&session, &then));
        }
        Ok(sg)
    }

    pub fn grants(&self, session: &str) -> Vec<StoredGrant> {
        let now = GoTime::now();
        let mut out: Vec<StoredGrant> = self.st.do_(|d| {
            let gone: Vec<String> = d
                .grants
                .iter()
                .filter(|(_, g)| {
                    // a holder no longer listed goes too
                    !now.before(&g.ends) || !d.sessions.contains_key(&g.session) || !HOLDER_NAMES.contains(&g.holder.as_str())
                })
                .map(|(id, _)| id.clone())
                .collect();
            for id in gone {
                d.grants.remove(&id);
            }
            d.grants
                .values()
                .filter(|g| session.is_empty() || g.session == session)
                .cloned()
                .collect()
        });
        out.sort_by(|a, b| a.ends.cmp(&b.ends));
        out
    }

    pub fn forget_grant(&self, id: &str) {
        self.st.do_(|d| {
            d.grants.remove(id);
        });
    }

    /// runs cmd as holder in the session's machine: with a live phone grant if one exists, else a standing rule, else
    /// no grant (the session's own allow list). The machine decides.
    pub fn exec(&self, session: &str, holder: &str, cmd: &str, timeout: Duration) -> Result<ExecResult> {
        self.exec_with(session, holder, cmd, timeout, false)
    }

    /// a live phone grant (not a rule) for holder on the session
    pub fn has_phone_grant(&self, session: &str, holder: &str) -> bool {
        self.grants(session).iter().any(|g| g.holder == holder && g.kind == "grant")
    }

    /// like exec, but only under a live phone grant, and the machine is told so (it refuses a rule or its allow list
    /// for this request). For raising a session to bypass (Deyao, 2026-10-09).
    pub fn exec_phone(&self, session: &str, holder: &str, cmd: &str, timeout: Duration) -> Result<ExecResult> {
        self.exec_with(session, holder, cmd, timeout, true)
    }

    fn exec_with(&self, session: &str, holder: &str, cmd: &str, timeout: Duration, phone_only: bool) -> Result<ExecResult> {
        let k = self.holder_signer(holder)?;
        let (machine, line) = self.st.do_(|d| {
            d.sessions
                .get(session)
                .map(|s| (s.machine_id.clone(), session_line(s)))
                .unwrap_or_default()
        });
        if machine.is_empty() || line.is_empty() {
            return Err(anyhow!("the session has no running machine"));
        }
        let mut grant: Option<Doc> = None;
        let mut best = "";
        for g in self.grants(session) {
            if g.holder == holder
                && (!phone_only || g.kind == "grant")
                && (best.is_empty() || (best == "rule" && g.kind == "grant"))
            {
                grant = g.doc.clone();
                best = if g.kind == "grant" { "grant" } else { "rule" };
            }
        }
        if phone_only && grant.is_none() {
            return Err(GrantNeeded { holder: holder.into(), phone: true }.into());
        }
        let id = crate::util::rand_id();
        let req = jarvis_go::marshal(&json!({"id": id, "session": line, "holder": k.public_key(),
            "cmd": cmd, "timeout": timeout.as_secs(), "at": GoTime::now().unix(), "phoneOnly": phone_only}));
        let sig = k.sign(req.as_bytes());
        // mq.rs: a row of the machine's queue; its answer comes back on the row, to whichever replica waits
        let item = ExecItem { request: req, sig, grant };
        if !self.mq_put(&machine, "exec", &id, &serde_json::to_value(&item)?, 16)? {
            return Err(anyhow!(
                "the machine has too many commands waiting (16): wait for them to finish, then try again"
            ));
        }
        let Some(ans) = self.mq_await(&id, timeout + Duration::from_secs(60), None)? else {
            self.mq_forget(&id);
            return Err(anyhow!("no answer from the machine"));
        };
        let res: ExecResult = jarvis_go::unmarshal(&ans).unwrap_or_default();
        if !res.error.is_empty() {
            return Err(anyhow!("the machine refused or failed: {}", res.error));
        }
        Ok(res)
    }

    pub fn exec_result(&self, res: ExecResult) {
        if let Err(e) = self.mq_answer(&res.id, &serde_json::to_value(&res).unwrap_or_default()) {
            crate::logf!("exec {}: its answer: {e:#}", res.id);
        }
    }
}

/// the line a session is: a kernel line's own id (kernelline.rs), else the line id its cert names
pub fn session_line(s: &Session) -> String {
    if s.kernel.is_some() {
        return s.id.clone();
    }
    cert_field(s.cert.as_ref(), "line")
}
