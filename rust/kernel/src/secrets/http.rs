//! Secrets' HTTP surface (kernel/secrets/http.go: the old core's store routes, the same shapes), plus /keys and /pull.
//! Only the router reaches it (NetworkPolicy). Nothing here trusts the caller: what matters is signed (the phone, the
//! master key, the mover or merger) or sealed to secrets. Bodies are read as Go's encoding/json did (a missing field
//! is its zero value); every answer carries X-Line-Seq once there is a line state; errors leave signed too.

use super::continuity::{LINE_SEQ_HEADER, MODE_SERVING, allowed_in};
use super::deploykeys::DeployKeyRequest;
use super::keys::WriteKeyInput;
use super::{Err, Secrets, fail};
use jarvis_doc::gv::Signed;
use jarvis_nethttp::{HandlerFn, Mux, Req, W};
use jarvis_sig::{Doc, Sealed, go_json};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::sync::Arc;

type Body = Map<String, Value>;

fn str_of(b: &Body, k: &str) -> String {
    b.get(k)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn sealed_of(b: &Body, k: &str) -> anyhow::Result<Sealed> {
    match b
        .get(k)
        .and_then(|v| serde_json::from_value::<Sealed>(v.clone()).ok())
    {
        Some(s) if !s.e.is_empty() => Ok(s),
        _ => Err(fail(
            400,
            format!("{k} must be sealed to secrets' agreement key"),
        )),
    }
}

fn into<T: DeserializeOwned>(b: &Body) -> anyhow::Result<T> {
    serde_json::from_value(Value::Object(b.clone())).map_err(|_| fail(400, "bad request"))
}

fn doc_of(b: &Body, k: &str) -> Option<Doc> {
    b.get(k)
        .and_then(|v| serde_json::from_value::<Doc>(v.clone()).ok())
        .filter(|d| !d.payload.is_empty())
}

/// what a route answers: written as JSON as it is (a signed document, or a plain value such as the identity)
fn out<T: Serialize>(v: T) -> anyhow::Result<Value> {
    Ok(serde_json::to_value(v)?)
}

pub fn handler(c: Arc<Secrets>) -> HandlerFn {
    let mut mux = Mux::new();
    let route = |mux: &mut Mux,
                 pattern: &'static str,
                 f: fn(&Secrets, &Body) -> anyhow::Result<Value>| {
        let c = c.clone();
        mux.handle(
            pattern,
            Arc::new(move |w: &mut W, req: &mut Req| {
                let m = c.mode();
                if m != MODE_SERVING && !allowed_in(pattern) {
                    return write_err(
                        &c,
                        w,
                        &fail(409, format!("this secrets is {m}: it serves nothing")),
                    );
                }
                let raw = req.read_body(4 << 20);
                let b: Body = if raw.is_empty() {
                    Map::new()
                } else {
                    match serde_json::from_slice::<Value>(&raw) {
                        Ok(Value::Object(o)) => o,
                        Ok(_) => Map::new(),
                        Err(e) => return write_err(&c, w, &fail(400, format!("bad JSON: {e}"))),
                    }
                };
                let res = f(&c, &b);
                c.sync_line();
                let n = c.line_seq();
                if n > 0 {
                    w.set_header(LINE_SEQ_HEADER, &n.to_string());
                }
                match res {
                    Err(e) => write_err(&c, w, &e),
                    Ok(v) => {
                        w.set_header("Content-Type", "application/json");
                        w.write_header(200);
                        let mut s = go_json(&v).unwrap_or_default();
                        s.push('\n');
                        w.write_str(&s);
                    }
                }
            }),
        );
    };

    route(&mut mux, "GET /identity", |c, _| c.identity());
    route(&mut mux, "GET /roster", |c, _| match c.roster() {
        Some(d) => out(d),
        None => Err(fail(404, crate::serve::no_roster())),
    });
    route(&mut mux, "POST /roster", |c, b| {
        #[derive(serde::Deserialize)]
        struct In {
            #[serde(default)]
            roster: Doc,
        }
        let i: In = into(b)?;
        c.set_roster(i.roster)
    });
    route(&mut mux, "POST /keys", |c, _| out(c.keys_statement()?));
    route(&mut mux, "POST /claim", |c, b| {
        let s = sealed_of(b, "bundle")?;
        out(c.claim(&str_of(b, "statement"), &str_of(b, "masterSig"), &s)?)
    });
    route(&mut mux, "GET /line-state", |c, _| out(c.line_state()?));
    route(&mut mux, "POST /handoff", |c, b| {
        let Some(d) = doc_of(b, "roster") else {
            return Err(fail(400, "roster: the other copy's root-signed roster"));
        };
        out(c.handoff(&d)?)
    });
    route(&mut mux, "POST /takeover", |c, b| {
        let Some(d) = doc_of(b, "handoff") else {
            return Err(fail(400, "handoff: the serving secrets' signed handoff"));
        };
        out(c.takeover(&d)?)
    });
    route(&mut mux, "POST /wipe", |c, b| {
        out(c.wipe(&str_of(b, "statement"), &str_of(b, "masterSig"))?)
    });

    route(&mut mux, "POST /stores", |c, b| {
        out(c.stores(&str_of(b, "nonce"))?)
    });
    route(&mut mux, "POST /stores/create", |c, b| {
        out(c.create_store(&str_of(b, "name"))?)
    });
    route(&mut mux, "POST /stores/mark-sensitive", |c, b| {
        out(c.mark_sensitive(&str_of(b, "name"))?)
    });
    route(&mut mux, "POST /stores/write-key", |c, b| {
        out(c.write_key(into::<WriteKeyInput>(b)?)?)
    });

    route(&mut mux, "POST /unlock/begin", |c, b| {
        out(c.unlock_begin(&str_of(b, "store"))?)
    });
    route(&mut mux, "POST /unlock/finish", |c, b| {
        let shares: BTreeMap<String, Sealed> = b
            .get("shares")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .ok_or_else(|| fail(400, "shares: {key: sealed share}"))?;
        out(c.unlock_finish(&str_of(b, "pending"), &shares)?)
    });
    route(&mut mux, "POST /lock", |c, b| {
        out(c.lock_unlock(&str_of(b, "id"))?)
    });
    route(&mut mux, "POST /unlocked", |c, b| {
        out(c.list_unlocked(&str_of(b, "nonce"))?)
    });

    route(&mut mux, "POST /deploy-keys/begin", |c, b| {
        out(c.deploy_key_begin(into::<DeployKeyRequest>(b)?)?)
    });
    route(&mut mux, "POST /deploy-keys/finish", |c, b| {
        let s: Sealed = b
            .get("share")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or(Sealed {
                e: String::new(),
                data: String::new(),
            });
        out(c.deploy_key_finish(&str_of(b, "pending"), &s, &str_of(b, "signature"))?)
    });

    route(&mut mux, "POST /pull", |c, b| {
        out(c.pull(into::<Signed>(b)?)?)
    });

    let mux = Arc::new(mux);
    Arc::new(move |w: &mut W, req: &mut Req| mux.serve(w, req))
}

/// errors leave signed too
fn write_err(c: &Secrets, w: &mut W, e: &anyhow::Error) {
    let status = e.downcast_ref::<Err>().map_or(500, |x| x.status);
    let g = c.lock();
    let d =
        super::sign(&g, &json!({"kind": "error", "error": format!("{e:#}")})).unwrap_or_default();
    drop(g);
    w.set_header("Content-Type", "application/json");
    w.write_header(status);
    let mut s = go_json(&d).unwrap_or_default();
    s.push('\n');
    w.write_str(&s);
}
