//! The identity signer and the gullible signer (DESIGN "Target design"). Neither checks anything but
//! the shape it is for: what their certs may do is the notarizer's table (the identity signer's (M, M, P) only narrows
//! a machine's own grant; the gullible signer's certs count only where the table takes any signer: ending a source).

use crate::serve::{Answer, Server, fail, handle};
use jarvis_doc::perm::Pair;
use jarvis_doc::{Cert, Kind, Object, Source, by, now};
use jarvis_sig::{Doc, Signer};
use serde::Deserialize;
use std::sync::Arc;

/// signs (M, M, P) for any P (the router picks P)
pub fn identity(s: &Signer, machine: &Object, p: &Pair) -> anyhow::Result<Doc> {
    let c = Cert {
        kind: "succession".into(),
        pred: machine.clone(),
        succ: machine.clone(),
        pair: p.clone(),
        source: None,
        machine: None,
        signer: by::IDENTITY.into(),
        issued_at: now(),
    };
    if machine.kind() != Some(Kind::Machine) {
        return Err(fail(
            400,
            "the identity signer signs (M, M, P) for a Fly machine M",
        ));
    }
    c.check().map_err(|e| fail(400, e.to_string()))?;
    Ok(s.sign_json(&c)?)
}

/// signs any well-formed (X, Y, P)
pub fn gullible(
    s: &Signer,
    pred: &Object,
    succ: &Object,
    p: &Pair,
    src: Option<Source>,
) -> anyhow::Result<Doc> {
    let c = Cert {
        kind: "succession".into(),
        pred: pred.clone(),
        succ: succ.clone(),
        pair: p.clone(),
        source: src,
        machine: None,
        signer: by::GULLIBLE.into(),
        issued_at: now(),
    };
    c.check().map_err(|e| fail(400, e.to_string()))?;
    Ok(s.sign_json(&c)?)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityIn {
    machine: Object,
    pair: Pair,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GullibleIn {
    pred: Object,
    succ: Object,
    pair: Pair,
    #[serde(default)]
    source: Option<Source>,
}

pub fn register_identity(s: &Arc<Server>) {
    let s2 = s.clone();
    handle(s, "POST /sign", move |i: IdentityIn| {
        Ok(Answer::Doc(identity(&s2.c.signer, &i.machine, &i.pair)?))
    });
}

pub fn register_gullible(s: &Arc<Server>) {
    let s2 = s.clone();
    handle(s, "POST /sign", move |i: GullibleIn| {
        Ok(Answer::Doc(gullible(
            &s2.c.signer,
            &i.pred,
            &i.succ,
            &i.pair,
            i.source,
        )?))
    });
}
