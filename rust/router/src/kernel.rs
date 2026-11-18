//! The kernel's HTTP API (kernel/, DESIGN "Target design", docs/PLAN-grants.md): nine components in each of two
//! copies, blue and green, each at KERNEL_URL with %s = its Deployment, "<role>-<copy>". Every call goes to the copy
//! that serves (Persisted.kernel_copy); kernelflip.rs moves the kernel to the other copy. The router carries documents
//! between the components and keeps them; it can't make one (each is signed by a component or the phone), only
//! withhold or delay it.

use crate::core::CoreClient;
use crate::router::Router;
use anyhow::{Result, anyhow};
use jarvis_doc::gv::Signed;
use jarvis_sig::{Doc as SDoc, Identity, Roster};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

type SeqFn = Arc<dyn Fn(i64) + Send + Sync>;
type ActiveFn = Arc<dyn Fn() -> String + Send + Sync>;
type RosterFn = Arc<dyn Fn() -> Option<SDoc> + Send + Sync>;
type StaleFn = Arc<dyn Fn(&str, &str) + Send + Sync>;

pub struct KernelClient {
    tmpl: String,
    http: reqwest::blocking::Client,
    ids: Mutex<BTreeMap<String, Identity>>,
    /// every secrets answer's X-Line-Seq (linestate.rs keeps secrets' newest line state)
    pub on_secrets_seq: RwLock<Option<SeqFn>>,
    /// the copy that serves (blue or green)
    pub active: RwLock<Option<ActiveFn>>,
    /// the root key's current roster (roster.rs), re-posted to a component that answers it has none (a restart)
    pub roster: RwLock<Option<RosterFn>>,
    /// a component refused it (it restarted with new keys: Deyao signs a new one)
    pub on_stale: RwLock<Option<StaleFn>>,
    /// every call holds it shared; the copy flip holds it alone while the serving copy hands over
    pub gate: Arc<parking_lot::RwLock<()>>,
}

/// the two copies
pub const KERNEL_COPIES: [&str; 2] = ["blue", "green"];

/// the copy that isn't c
pub fn other_copy(c: &str) -> &'static str {
    if c == "green" { "blue" } else { "green" }
}

/// the copy a Deployment name ("<role>-<copy>") is in ("" = a bare role)
pub fn copy_of(dep: &str) -> &'static str {
    for c in KERNEL_COPIES {
        if dep.ends_with(&format!("-{c}")) {
            return c;
        }
    }
    ""
}

/// a component refused (its signed error, relayed)
#[derive(Debug, Clone)]
pub struct KernelError {
    pub role: String,
    pub status: u16,
    pub msg: String,
    /// the component's stable reason for it (serve.FailBecause), "" when it gave none
    pub reason: String,
}

impl std::fmt::Display for KernelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "kernel {}: HTTP {} {}", self.role, self.status, self.msg)
    }
}

impl std::error::Error for KernelError {}

pub fn kernel_error(e: &anyhow::Error) -> Option<&KernelError> {
    e.downcast_ref::<KernelError>()
}

/// the component answered that it holds no roster yet (sig.ErrNoRoster)
pub fn is_no_roster(e: &anyhow::Error) -> bool {
    kernel_error(e).is_some_and(|k| k.msg.contains("no roster yet"))
}

impl KernelClient {
    /// None when KERNEL_URL isn't set (no kernel on this box yet)
    pub fn new(tmpl: &str) -> Option<KernelClient> {
        if tmpl.is_empty() || !tmpl.contains("%s") {
            return None;
        }
        Some(KernelClient {
            tmpl: tmpl.to_string(),
            http: reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(120))
                .build()
                .ok()?,
            ids: Mutex::new(BTreeMap::new()),
            on_secrets_seq: RwLock::new(None),
            active: RwLock::new(None),
            roster: RwLock::new(None),
            on_stale: RwLock::new(None),
            gate: Arc::new(parking_lot::RwLock::new(())),
        })
    }

    pub fn url(&self, dep: &str) -> String {
        self.tmpl.replacen("%s", dep, 1)
    }

    /// the copy that serves
    pub fn serving(&self) -> String {
        match self.active.read().ok().and_then(|g| g.clone()) {
            Some(f) => f(),
            None => "blue".into(),
        }
    }

    /// the Deployment a name means: a role is the serving copy's ("notary" → "notary-blue"); a Deployment name stays
    pub fn dep(&self, name: &str) -> String {
        if !copy_of(name).is_empty() {
            return name.to_string();
        }
        format!("{name}-{}", self.serving())
    }

    /// POST (body Some) or GET → the raw answer
    pub fn call(&self, role: &str, method: &str, path: &str, body: Option<&Value>) -> Result<Vec<u8>> {
        let (b, seq) = self.call_seq(role, method, path, body)?;
        if role == "secrets" && seq > 0 {
            let h = self.on_secrets_seq.read().ok().and_then(|g| g.clone());
            if let Some(h) = h {
                h(seq);
            }
        }
        Ok(b)
    }

    /// call without the line-state hook (the keeper's own fetches)
    pub fn call_no_hook(&self, role: &str, method: &str, path: &str, body: Option<&Value>) -> Result<Vec<u8>> {
        self.call_seq(role, method, path, body).map(|(b, _)| b)
    }

    fn call_seq(&self, role: &str, method: &str, path: &str, body: Option<&Value>) -> Result<(Vec<u8>, i64)> {
        let _g = self.gate.read();
        let dep = self.dep(role);
        let r = self.do_(role, &dep, method, path, body);
        let roster = self.roster.read().ok().and_then(|g| g.clone());
        let (Err(e), Some(rf)) = (&r, roster) else {
            return r;
        };
        if path == "/roster" || !is_no_roster(e) {
            return r;
        }
        // a component without the roster restarted (fresh keys): it takes the current roster again only if it names
        // its keys, which a restart's new keys never are, unless the roster was signed after it
        let Some(d) = rf() else { return r };
        self.post_roster(&dep, &d)?;
        self.forget(&dep);
        self.do_(role, &dep, method, path, body)
    }

    /// the roster to one Deployment; a refusal (403: it doesn't name this component's keys) means the component
    /// restarted since the roster was signed: the roster is stale
    pub fn post_roster(&self, dep: &str, d: &SDoc) -> Result<()> {
        match self.do_(dep, dep, "POST", "/roster", Some(&json!({"roster": d}))) {
            Err(e) if kernel_error(&e).is_some_and(|k| k.status == 403) => {
                let msg = format!(
                    "roster stale: component {dep} restarted ({})",
                    kernel_error(&e).map(|k| k.msg.clone()).unwrap_or_default()
                );
                let h = self.on_stale.read().ok().and_then(|g| g.clone());
                if let Some(h) = h {
                    h(dep, &msg);
                }
                Err(anyhow!("kernel {dep}: {msg}"))
            }
            Err(e) => Err(e),
            Ok(_) => Ok(()),
        }
    }

    /// one request to one Deployment (dep), its errors named by role
    fn do_(&self, role: &str, dep: &str, method: &str, path: &str, body: Option<&Value>) -> Result<(Vec<u8>, i64)> {
        let m = reqwest::Method::from_bytes(method.as_bytes())?;
        let mut req = self
            .http
            .request(m, format!("{}{path}", self.url(dep)))
            .header("Content-Type", "application/json");
        if let Some(b) = body {
            req = req.body(jarvis_go::marshal(b));
        }
        let resp = req.send().map_err(|e| anyhow!("kernel {role}: {e}"))?;
        let status = resp.status().as_u16();
        let seq = resp
            .headers()
            .get(crate::linestate::LINE_SEQ_HEADER)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let b = crate::util::read_limited(resp, 16 << 20).unwrap_or_default();
        if status != 200 {
            let mut msg = String::from_utf8_lossy(&b).trim().to_string();
            let mut reason = String::new();
            if let Ok(d) = jarvis_go::unmarshal::<crate::core::Doc>(&b)
                && !d.payload.is_empty()
            {
                #[derive(Deserialize, Default)]
                #[serde(default)]
                struct E {
                    error: String,
                    reason: String,
                }
                if let Ok(e) = d.decode::<E>()
                    && !e.error.is_empty()
                {
                    msg = e.error;
                    reason = e.reason;
                }
            }
            return Err(KernelError {
                role: role.into(),
                status,
                msg,
                reason,
            }
            .into());
        }
        Ok((b, seq))
    }

    /// a POST answered with a signed document
    pub fn doc(&self, role: &str, path: &str, body: &Value) -> Result<SDoc> {
        let b = self.call(role, "POST", path, Some(body))?;
        match jarvis_go::unmarshal::<crate::core::Doc>(&b) {
            Ok(d) if !d.payload.is_empty() => Ok(d.as_sig_doc()),
            _ => Err(anyhow!("kernel {role}{path}: not a signed document")),
        }
    }

    /// a component's identity (the root key's roster vouches for it): a role is the serving copy's, a Deployment name
    /// its own (cached; refetched when a call says it changed: forget)
    pub fn identity(&self, role: &str) -> Result<Identity> {
        let dep = self.dep(role);
        if let Some(id) = self.ids.lock().ok().and_then(|g| g.get(&dep).cloned()) {
            return Ok(id);
        }
        let b = self.call_no_hook(&dep, "GET", "/identity", None)?;
        let id = if dep.starts_with("secrets-") {
            #[derive(Deserialize, Default)]
            #[serde(default)]
            struct M {
                #[serde(rename = "signingKey", alias = "SigningKey")]
                signing_key: String,
                #[serde(rename = "agreementKey", alias = "AgreementKey")]
                agreement_key: String,
            }
            let m: M = jarvis_go::unmarshal(&b)?;
            Identity {
                role: "secrets".into(),
                signing_key: m.signing_key,
                agreement_key: m.agreement_key,
            }
        } else {
            let d: crate::core::Doc =
                jarvis_go::unmarshal(&b).map_err(|_| anyhow!("kernel {role}: bad identity"))?;
            jarvis_go::unmarshal(d.payload.as_bytes())
                .map_err(|_| anyhow!("kernel {role}: bad identity"))?
        };
        if let Ok(mut g) = self.ids.lock() {
            g.insert(dep, id.clone());
        }
        Ok(id)
    }

    /// a component restarted (new keys): its identity is read again (a role: the serving copy's)
    pub fn forget(&self, role: &str) {
        let dep = self.dep(role);
        if let Ok(mut g) = self.ids.lock() {
            g.remove(&dep);
        }
    }

    /// every identity is read again (a new roster, a flip)
    pub fn forget_all(&self) {
        if let Ok(mut g) = self.ids.lock() {
            g.clear();
        }
    }

    /// the identity whose key signed d as role, as the current roster names it: the serving member, else a retired
    /// one (a document from before a flip or a restart); the serving member when none does
    pub fn signer_of(&self, role: &str, d: &SDoc) -> Result<Identity> {
        let id = self.identity(role)?;
        if jarvis_sig::verify(&id.signing_key, d.payload.as_bytes(), &d.sig) {
            return Ok(id);
        }
        let rf = self.roster.read().ok().and_then(|g| g.clone());
        if let Some(rd) = rf.and_then(|f| f())
            && let Ok(ro) = jarvis_go::unmarshal::<Roster>(rd.payload.as_bytes())
        {
            for m in ro.retired_of(role) {
                if jarvis_sig::verify(&m.signing_key, d.payload.as_bytes(), &d.sig) {
                    return Ok(m);
                }
            }
        }
        Ok(id)
    }

    /// secrets' signed statement of the phone's and the root key
    pub fn keys(&self) -> Result<(SDoc, Identity)> {
        let id = self.identity("secrets")?;
        let d = self.doc("secrets", "/keys", &json!({}))?;
        Ok((d, id))
    }

    /// the notary's challenge over the cert, then the notarizer's answer (with what names the cert's signer)
    pub fn notarize(&self, cert: &SDoc) -> Result<SDoc> {
        let c = jarvis_doc::peek_cert(cert).map_err(|e| anyhow!("cert: {e}"))?;
        let nid = self.identity("notary")?;
        let ch = self.doc(
            "notary",
            "/challenge",
            &json!({"subject": cert.id(), "about": "cert"}),
        )?;
        let mut input = json!({"cert": cert, "challenge": ch, "notary": nid});
        match c.signer.as_str() {
            jarvis_doc::by::IPHONE | jarvis_doc::by::ROOT => {
                let (ks, sid) = self.keys()?;
                input["keys"] = json!(ks);
                input["secrets"] = json!(sid);
            }
            s => {
                // a cert signed before a flip or a restart: by a retired member
                input["signer"] = json!(self.signer_of(s, cert)?);
            }
        }
        self.doc("notarizer", "/notarize", &input)
    }

    /// grant g along a notarized cert → the mover's grant on the cert's successor
    pub fn move_(&self, g: &Signed, cert: &SDoc, notarized: &SDoc) -> Result<Signed> {
        let nz_id = self.signer_of("notarizer", notarized)?;
        let n_id = self.identity("notary")?;
        let mut input = json!({"grant": g.grant, "by": g.by, "cert": cert, "notarized": notarized,
            "notarizer": nz_id, "notary": n_id});
        if let Some(s) = &g.signer {
            input["signer"] = json!(s);
        }
        if g.by == "root" {
            let (ks, sid) = self.keys()?;
            input["keys"] = json!(ks);
            input["secrets"] = json!(sid);
        }
        let d = self.doc("mover", "/move", &input)?;
        let mid = self.identity("mover")?;
        Ok(Signed {
            grant: d,
            by: "mover".into(),
            signer: Some(mid),
            keys: None,
            secrets: None,
        })
    }
}

impl Router {
    /// the router's kernel client, the copy that serves, and the keeper of secrets' line state
    pub fn wire_kernel(self: &Arc<Self>) {
        let Some(k) = self.kernel.clone() else { return };
        let r = Arc::downgrade(self);
        *k.active.write().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(move || {
            r.upgrade().map(|r| r.serving_copy()).unwrap_or_else(|| "blue".into())
        }));
        let kl = crate::linestate::LineKeeper::new_kernel(self.st.clone(), k.clone());
        let kl2 = kl.clone();
        *k.on_secrets_seq.write().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(move |s| kl2.seen(s)));
        let _ = self.kernel_lines.set(kl.clone());
        let r = Arc::downgrade(self);
        *k.roster.write().unwrap_or_else(|e| e.into_inner()) =
            Some(Arc::new(move || r.upgrade().and_then(|r| r.current_roster())));
        let r = Arc::downgrade(self);
        *k.on_stale.write().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(move |dep, msg| {
            if let Some(r) = r.upgrade() {
                r.roster_stale(dep, msg)
            }
        }));
        if self.cfg.no_core {
            let mut c = CoreClient::new("");
            c.name = "secrets".into();
            let k2 = k.clone();
            c.base_fn = Some(Arc::new(move || k2.url(&k2.dep("secrets"))));
            let gate = k.gate.clone();
            c.gate = Some(Arc::new(move || {
                let g = gate.read_arc(); // shared for the call, released by what it returns
                Box::new(move || drop(g))
            }));
            let kl3 = kl.clone();
            *c.on_line_seq.write().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(move |s| kl3.seen(s)));
            let _ = self.secrets_stores.set(Arc::new(c));
        }
    }

    /// the kernel copy that serves (Persisted.kernel_copy; "" = blue)
    pub fn serving_copy(&self) -> String {
        self.st.read(|d| {
            if d.kernel_copy == "green" { "green".to_string() } else { "blue".to_string() }
        })
    }

    /// where the store calls go — the kernel's serving secrets on a box with no core, else the core
    pub fn store_core(&self) -> Arc<CoreClient> {
        self.secrets_stores
            .get()
            .cloned()
            .unwrap_or_else(|| self.core.clone())
    }
}
