//! The core's HTTP API (core/main.go). The router reads what it needs from the signed answers' payloads but doesn't
//! rely on them for anything security-relevant; it passes the documents on unchanged.

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};
use std::time::Duration;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Doc {
    pub payload: String,
    pub sig: String,
}

impl Doc {
    pub fn decode<T: serde::de::DeserializeOwned>(&self) -> Result<T> {
        Ok(jarvis_go::unmarshal(self.payload.as_bytes())?)
    }

    pub fn as_sig_doc(&self) -> jarvis_sig::Doc {
        jarvis_sig::Doc {
            payload: self.payload.clone(),
            sig: self.sig.clone(),
        }
    }
}

impl From<jarvis_sig::Doc> for Doc {
    fn from(d: jarvis_sig::Doc) -> Self {
        Doc {
            payload: d.payload,
            sig: d.sig,
        }
    }
}

type BaseFn = Arc<dyn Fn() -> String + Send + Sync>;
type SeqFn = Arc<dyn Fn(i64) + Send + Sync>;
type GateFn = Arc<dyn Fn() -> Box<dyn FnOnce() + Send> + Send + Sync>;

pub struct CoreClient {
    base: RwLock<String>,
    /// where the client points, asked at every call (the kernel's serving secrets, kernel.rs stores_on_secrets)
    pub base_fn: Option<BaseFn>,
    /// what its errors call it ("" = "core")
    pub name: String,
    http: reqwest::blocking::Client,
    /// every answer's X-Line-Seq (linestate.rs keeps the core's line state when it moved)
    pub on_line_seq: RwLock<Option<SeqFn>>,
    /// held around every call, its answer the release (the kernel's copy flip, kernel.rs)
    pub gate: Option<GateFn>,
}

/// the core refused; body is its signed error document (relayed as is)
#[derive(Debug, Clone)]
pub struct CoreError {
    pub status: u16,
    pub body: Vec<u8>,
    pub msg: String,
}

impl std::fmt::Display for CoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.msg)
    }
}

impl std::error::Error for CoreError {}

/// how long the router waits for one core call: /start and /kill wait past the old core's own worst case (it waits
/// inside them, ≈ 34 min) and always hear its answer (DECISIONS 181); everything else 15 minutes
pub fn core_call_timeout(path: &str) -> Duration {
    match path {
        "/start" | "/kill" => Duration::from_secs(40 * 60),
        _ => Duration::from_secs(15 * 60),
    }
}

/// what the core answers beside a cert (not under its signature; each its own proof)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Answer {
    pub entry: Option<Doc>,
    pub carry: String,
}

impl CoreClient {
    pub fn new(base: &str) -> CoreClient {
        CoreClient {
            base: RwLock::new(base.to_string()),
            base_fn: None,
            name: String::new(),
            http: reqwest::blocking::Client::builder()
                .timeout(None)
                .build()
                .unwrap_or_else(|e| panic!("{e}")),
            on_line_seq: RwLock::new(None),
            gate: None,
        }
    }

    /// the core this client talks to now
    pub fn url(&self) -> String {
        if let Some(f) = &self.base_fn {
            return f();
        }
        self.base.read().map(|b| b.clone()).unwrap_or_default()
    }

    /// point the client at another core (nextcore.rs: a flip), for every later call
    pub fn set_url(&self, u: &str) {
        if let Ok(mut b) = self.base.write() {
            *b = u.to_string();
        }
    }

    pub fn raw(&self, method: &str, path: &str, body: Option<&[u8]>) -> Result<(u16, Vec<u8>)> {
        let (status, b, seq) = self.raw_seq(method, path, body)?;
        if seq > 0 {
            let hook = self.on_line_seq.read().ok().and_then(|g| g.clone());
            if let Some(h) = hook {
                h(seq);
            }
        }
        Ok((status, b))
    }

    /// raw without the line-state hook (the hook's own calls)
    pub fn raw_no_hook(
        &self,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
    ) -> Result<(u16, Vec<u8>)> {
        let (s, b, _) = self.raw_seq(method, path, body)?;
        Ok((s, b))
    }

    fn raw_seq(
        &self,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
    ) -> Result<(u16, Vec<u8>, i64)> {
        let release = self.gate.as_ref().map(|g| g());
        let url = format!("{}{path}", self.url().trim_end_matches('/'));
        let m = reqwest::Method::from_bytes(method.as_bytes())?;
        let mut req = self.http.request(m, &url).timeout(core_call_timeout(path));
        if let Some(b) = body {
            req = req
                .header("Content-Type", "application/json")
                .body(b.to_vec());
        }
        let r = (|| -> Result<(u16, Vec<u8>, i64)> {
            let resp = req.send()?;
            let status = resp.status().as_u16();
            let seq = resp
                .headers()
                .get(crate::linestate::LINE_SEQ_HEADER)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            let b = crate::util::read_limited(resp, 64 << 20)?;
            Ok((status, b, seq))
        })();
        if let Some(rel) = release {
            rel();
        }
        r
    }

    /// what errors call the client's server
    pub fn who(&self) -> &str {
        if self.name.is_empty() {
            "core"
        } else {
            &self.name
        }
    }

    /// POST a JSON body, expect a signed document
    pub fn call<T: Serialize + ?Sized>(&self, path: &str, input: &T) -> Result<Doc> {
        self.call_answer(path, input).map(|(d, _)| d)
    }

    /// call, with what came beside the signed document
    pub fn call_answer<T: Serialize + ?Sized>(
        &self,
        path: &str,
        input: &T,
    ) -> Result<(Doc, Answer)> {
        let body = jarvis_go::marshal(input);
        let (status, b) = self
            .raw("POST", path, Some(body.as_bytes()))
            .map_err(|e| anyhow!("{} {path}: {e:#}", self.who()))?;
        if status != 200 {
            let mut msg = format!("{} {path}: HTTP {status}", self.who());
            if let Ok(d) = jarvis_go::unmarshal::<Doc>(&b) {
                #[derive(Deserialize, Default)]
                #[serde(default)]
                struct E {
                    error: String,
                }
                if let Ok(e) = d.decode::<E>()
                    && !e.error.is_empty()
                {
                    msg = format!("{}: {}", self.who(), e.error);
                }
            }
            return Err(CoreError {
                status,
                body: b,
                msg,
            }
            .into());
        }
        let d: Doc = match jarvis_go::unmarshal::<Doc>(&b) {
            Ok(d) if !d.payload.is_empty() => d,
            _ => return Err(anyhow!("{} {path}: not a signed document", self.who())),
        };
        let a: Answer = jarvis_go::unmarshal(&b).unwrap_or_default();
        Ok((
            Doc {
                payload: d.payload,
                sig: d.sig,
            },
            a,
        ))
    }

    /// the core's public keys (from /identity)
    pub fn key(&self) -> Result<std::collections::BTreeMap<String, String>> {
        let (status, b) = self.raw("GET", "/identity", None)?;
        if status != 200 {
            return Err(anyhow!("{} /identity: HTTP {status}", self.who()));
        }
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct Id {
            #[serde(rename = "signingKey")]
            signing_key: String,
            #[serde(rename = "agreementKey")]
            agreement_key: String,
            #[serde(rename = "sizeLadder")]
            size_ladder: i64,
        }
        let id: Id = jarvis_go::unmarshal(&b)?;
        if self.name.is_empty() {
            crate::sizes::note_core_sizes(id.size_ladder >= 1); // sizes.rs (the core's own; secrets starts no machine)
        }
        Ok([
            ("signingKey".to_string(), id.signing_key),
            ("agreementKey".to_string(), id.agreement_key),
        ]
        .into_iter()
        .collect())
    }
}
