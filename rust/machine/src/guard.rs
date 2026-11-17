//! The guard (docs/DESIGN.md "The supervisor and the guard"): the part of the supervisor that checks what comes in from
//! the router and lets through only what something Deyao trusts vouches for. It guards exactly the commands that can
//! steer the session or run code in it:
//!   - execs (a router feature's shell command): the holder's signature, then a phone grant, a standing rule or the
//!     session's own allow list (authorise_exec; "Grants");
//!   - deliveries (prompts into the harness): the line's own signature or the image's text, the core's attestation,
//!     once each ("Inputs to a machine"); in a session holding a sensitive store also the phone's signature over that
//!     very message or a per-kind rule (messages.rs).
//!
//! Everything else the supervisor takes (snapshot, free, refresh-secrets, pause-harness, resume-harness) can't carry an
//! instruction and runs unguarded. Nothing guarded runs once the session is frozen for its final snapshot.

use crate::cert::Cert;
use crate::client::Client;
use crate::crypto::{verify, verify_doc};
use crate::deliver::{Delivery, check_attest, delivery_text, read_line_keys};
use crate::grants::{Exec, ExecRequest, Grant, MAX_GRANT_SECS, current_cert, read_allow};
use crate::{gojson, util};
use anyhow::{Result, anyhow, bail};
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

/// the exec request, when it may run now
pub fn guard_exec(e: &Exec, now: i64) -> (ExecRequest, Result<()>) {
    let (r, res) = authorise_exec(e, now);
    let res = res.and_then(|_| crate::snapshot::not_frozen());
    (r, res)
}

pub struct Guarded {
    pub text: String,
    pub delivery: Delivery,
    pub cert: Cert,
    /// the approval item to record once the harness took it
    pub approved: String,
}

/// The text a delivery puts into the harness, once its voucher and the core's attestation check out, and (a sensitive
/// session, or a resume prompt) the phone's approval of exactly that message (messages.rs). The replay check and record
/// happen in deliver, in order with the send.
pub fn guard_delivery(c: &Client, d: &Delivery) -> Result<Guarded> {
    let r = render_delivery(d)?;
    let core_key = crate::kernelboot::attest_key()?;
    check_attest(&core_key, &c.me, &d.kind, &r.attested, d.attest.as_ref())?;
    let approved = crate::messages::check_message_approval(
        &r.cert,
        d,
        &r.attested,
        &r.text,
        util::unix_now(),
    )?;
    crate::snapshot::not_frozen()?;
    Ok(Guarded {
        text: r.text,
        delivery: r.delivery,
        cert: r.cert,
        approved,
    })
}

pub struct Rendered {
    pub text: String,
    pub delivery: Delivery,
    pub cert: Cert,
    pub attested: Vec<u8>,
}

/// The text the harness would get (a request-outcome's items already told left out), the delivery as it goes in, this
/// machine's cert and the bytes the core attests. Nothing is recorded or sent: the router's preview of a message for
/// Deyao's approval is exactly this text.
pub fn render_delivery(d: &Delivery) -> Result<Rendered> {
    let cert = current_cert()?;
    let (mut text, attested) = delivery_text(d, &read_line_keys())?;
    let mut out = d.clone();
    if d.kind == "request-outcome" && d.request.is_some() {
        let f = crate::outcomes::outcome_fresh(d);
        if f.outcomes.len() != d.outcomes.len() {
            // the same checks, on the items still untold
            text = delivery_text(&f, &read_line_keys())?.0;
            out = f;
        }
    }
    Ok(Rendered {
        text,
        delivery: out,
        cert,
        attested,
    })
}

/// request ids taken in the last 5 minutes
static SEEN: LazyLock<Mutex<HashMap<String, i64>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

/// Ok when the holder-signed request may run (a phone grant, a standing rule or the allow list)
pub fn authorise_exec(e: &Exec, now: i64) -> (ExecRequest, Result<()>) {
    let r: ExecRequest = match gojson::unmarshal(e.request.as_bytes()) {
        Ok(r) => r,
        Err(_) => return (ExecRequest::default(), Err(anyhow!("bad request"))),
    };
    let res = authorise(e, &r, now);
    (r, res)
}

fn authorise(e: &Exec, r: &ExecRequest, now: i64) -> Result<()> {
    if !verify(&r.holder, e.request.as_bytes(), &e.sig) {
        bail!("not signed by the holder it names");
    }
    if now - r.at > 120 || r.at - now > 120 {
        bail!("request too old or from the future");
    }
    let dup = {
        let mut seen = SEEN.lock().unwrap_or_else(|e| e.into_inner());
        seen.retain(|_, t| now - *t <= 300);
        seen.insert(r.id.clone(), now).is_some()
    };
    if r.id.is_empty() || dup {
        bail!("request id missing or already used");
    }
    let cert = current_cert().map_err(|e| anyhow!("no valid cert: {e:#}"))?;
    let me = &cert.line; // core-signed, so the router can't relabel a machine to reuse another line's grant
    if me.is_empty() || &r.session != me {
        bail!("request is for line {}, this is {}", r.session, me);
    }
    let h = &r.holder;
    if r.phone_only && e.grant.is_none() {
        bail!(
            "this request needs a phone grant: file `jarvis-request grant {h} --minutes N --why …` and Deyao approves it with Face ID"
        );
    }
    let Some(gd) = &e.grant else {
        if cert.sensitive {
            bail!(
                "this session holds a sensitive store, so only a phone grant opens a shell: `jarvis-request grant {h} --minutes N --why …`"
            );
        }
        for a in read_allow() {
            if let Some(u) = util::parse_rfc3339(&a.until)
                && a.holder == *h
                && now < u
            {
                return Ok(());
            }
        }
        bail!(
            "no grant, and {h} isn't on this session's allow list: `jarvis-machine allow {h} DURATION` (non-sensitive sessions), or `jarvis-request grant {h} --why …`"
        );
    };
    let g: Grant = match (cert.phone.is_empty(), verify_doc(&cert.phone, Some(gd))) {
        (false, Ok(g)) => g,
        _ => bail!("the grant isn't signed by the phone named in this machine's cert"),
    };
    if g.holder != *h || g.session != *me || g.scope != "shell" {
        bail!("the grant is for another holder, session or scope");
    }
    match g.kind.as_str() {
        "grant" => {
            let ok = match (
                util::parse_rfc3339(&g.issued),
                util::parse_rfc3339(&g.expires),
            ) {
                (Some(iss), Some(exp)) => {
                    exp - iss <= MAX_GRANT_SECS && now < exp && now >= iss - 120
                }
                _ => false,
            };
            if !ok {
                bail!(
                    "the grant is expired, or longer than 10 minutes: ask for a new one (`jarvis-request grant {h} --minutes N --why …`)"
                );
            }
        }
        "rule" => {
            if r.phone_only {
                bail!(
                    "this request needs a phone grant, not a standing rule: `jarvis-request grant {h} --minutes N --why …`"
                );
            }
            if cert.sensitive {
                bail!(
                    "this session holds a sensitive store, so standing rules don't apply: `jarvis-request grant {h} --minutes N --why …` (at most 10 minutes)"
                );
            }
            match util::parse_rfc3339(&g.until) {
                Some(u) if now < u => {}
                _ => bail!(
                    "the standing rule has expired: ask again (`jarvis-request grant {h} --days N --why …`)"
                ),
            }
        }
        _ => bail!("unknown grant kind"),
    }
    Ok(())
}
