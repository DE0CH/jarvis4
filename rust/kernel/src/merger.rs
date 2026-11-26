//! The grant merger (kernel/merger; DESIGN "Target design"). Two grants on one machine with identical conditions →
//! (M, allowed₁ ∪ allowed₂, conditions); anything else is refused.

use crate::serve::{Answer, Server, fail, handle};
use jarvis_doc::Grant;
use jarvis_doc::gv::{self, Signed};
use jarvis_sig::{Doc, Signer, Trust};
use serde::Deserialize;
use std::sync::Arc;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub a: Signed,
    pub b: Signed,
}

pub fn merge(s: &Signer, t: &Trust, i: &Input) -> anyhow::Result<Doc> {
    let a = gv::open(&i.a, t).map_err(|e| fail(403, format!("a: {e}")))?;
    let b = gv::open(&i.b, t).map_err(|e| fail(403, format!("b: {e}")))?;
    if a.machine != b.machine || a.keys != b.keys {
        return Err(fail(409, "the grants are on different machines"));
    }
    let p = a
        .pair
        .merge(&b.pair)
        .map_err(|e| fail(409, e.to_string()))?;
    let at = gv::later(&a.at, &b.at).to_string();
    Ok(s.sign_json(&Grant {
        kind: "grant".into(),
        machine: a.machine,
        keys: a.keys,
        pair: p,
        from: Some(vec![i.a.grant.id(), i.b.grant.id()]),
        at,
    })?)
}

pub fn register(s: &Arc<Server>) {
    let s2 = s.clone();
    handle(s, "POST /merge", move |i: Input| {
        Ok(Answer::Doc(merge(&s2.c.signer, &s2.trust, &i)?))
    });
}
