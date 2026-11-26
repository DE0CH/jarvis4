//! The grant mover (kernel/mover; DESIGN "Target design"). Grant G on a cert's predecessor, along that notarized cert
//! with pair P → (successor, G ⊓ P). It never refuses a well-formed move and a move can only narrow. It doesn't check
//! the cert's signer: the notarization says the notarizer did.

use crate::serve::{Answer, Server, fail, handle};
use jarvis_doc::gv::{self, Signed};
use jarvis_doc::{Challenge, Grant, Keys, Kind, Notarized, peek_cert, rfc3339_ok};
use jarvis_sig::{Doc, Identity, Signer, Trust, check_identity};
use serde::Deserialize;
use std::sync::Arc;

/// a grant (gv.Signed's fields, as Go embeds it) and the notarized cert to move it along
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub grant: Doc,
    pub by: String,
    #[serde(default)]
    pub signer: Option<Identity>,
    #[serde(default)]
    pub keys: Option<Doc>,
    #[serde(default)]
    pub secrets: Option<Identity>,
    pub cert: Doc,
    pub notarized: Doc,
    pub notarizer: Identity,
    pub notary: Identity,
}

pub fn mv(s: &Signer, t: &Trust, i: &Input) -> anyhow::Result<Doc> {
    let signed = Signed {
        grant: i.grant.clone(),
        by: i.by.clone(),
        signer: i.signer.clone(),
        keys: i.keys.clone(),
        secrets: i.secrets.clone(),
    };
    let g = gv::open(&signed, t).map_err(|e| fail(403, e.to_string()))?;
    check_identity(&i.notarizer, "notarizer", t).map_err(|e| fail(403, e.to_string()))?;
    let nz: Notarized = match i.notarized.open(&i.notarizer.signing_key) {
        Ok(nz) => nz,
        Err(_) => return Err(fail(403, "the cert isn't notarized")),
    };
    if nz.kind != "notarized" || nz.cert != i.cert.id() {
        return Err(fail(403, "the cert isn't notarized"));
    }
    check_identity(&i.notary, "notary", t).map_err(|e| fail(403, e.to_string()))?;
    let ch: Challenge = nz
        .challenge
        .open(&i.notary.signing_key)
        .map_err(|e| fail(403, format!("the notarization's challenge: {e}")))?;
    let c = peek_cert(&i.cert).map_err(|e| fail(400, format!("cert: {e}")))?;
    if g.machine != c.pred {
        return Err(fail(
            409,
            format!(
                "the grant is on {}, the cert leaves {}",
                g.machine.0, c.pred.0
            ),
        ));
    }
    // an identity edge keeps the machine's keys
    let keys = match (&c.machine, c.succ.kind()) {
        (Some(m), _) => Keys {
            signing_key: m.signing_key.clone(),
            encryption_key: m.encryption_key.clone(),
        },
        (None, Some(Kind::Sink | Kind::Source)) => {
            gv::ideal_keys(&c.succ).unwrap_or(g.keys.clone())
        }
        _ => g.keys.clone(),
    };
    let out = Grant {
        kind: "grant".into(),
        machine: c.succ.clone(),
        keys,
        pair: g.pair.meet(&c.pair),
        from: Some(vec![i.grant.id(), i.notarized.id()]),
        at: gv::later(&g.at, &ch.at).to_string(),
    };
    if !rfc3339_ok(&out.at) {
        return Err(fail(400, "times"));
    }
    Ok(s.sign_json(&out)?)
}

pub fn register(s: &Arc<Server>) {
    let s2 = s.clone();
    handle(s, "POST /move", move |i: Input| {
        Ok(Answer::Doc(mv(&s2.c.signer, &s2.trust, &i)?))
    });
}
