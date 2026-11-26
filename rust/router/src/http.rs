//! The router's routes (http.go): the app's (behind Cloudflare Access, the JWT checked here too), setup's (the setup
//! session's service token and its key's signature), the machines' (signed by a machine the core started), and the
//! web page.

use crate::core::{CoreClient, CoreError, Doc};
use crate::nethttp::{Mux, Req, W, write_json};
use crate::router::Router;
use crate::state::{Approval, Persisted, Record, Session, StateWriteError};
use anyhow::{Result, anyhow};
use base64::Engine;
use jarvis_go::GoTime;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Read;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub type AppFn = Arc<dyn Fn(&mut W, &mut Req) + Send + Sync>;
/// a machine route whose body arrives as a file (its path)
pub type StreamFn = Arc<dyn Fn(&mut W, &mut Req, &str, &std::path::Path) + Send + Sync>;
pub type MachineFn = Arc<dyn Fn(&mut W, &mut Req, &str, &[u8]) + Send + Sync>;

/// a response that carries why: the status a refusal maps to (writeErr)
pub fn write_err(w: &mut W, err: &anyhow::Error) {
    if let Some(gn) = err.downcast_ref::<crate::grants::GrantNeeded>() {
        write_json(
            w,
            403,
            &json!({"error": format!("{err:#}"), "needsGrant": gn.holder, "phoneGrant": gn.phone}),
        );
        return;
    }
    if let Some(ce) = err.downcast_ref::<CoreError>() {
        w.set_header("Content-Type", "application/json");
        w.write_header(ce.status);
        w.write(&ce.body); // the core's signed error, unchanged
        return;
    }
    let mut status = 400;
    if err.downcast_ref::<crate::drain::Draining>().is_some() {
        status = 503; // drain.rs: "router updating, try again shortly", shown as is
    } else if err.downcast_ref::<crate::router::Busy>().is_some() {
        status = 409;
    }
    write_json(w, status, &json!({"error": crate::util::err_text(err)}));
}

/// a request whose change the records couldn't take (State::do_) answers 503 with why, never a 200
pub fn state_write_guard(h: AppFn) -> AppFn {
    Arc::new(move |w: &mut W, req: &mut Req| {
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| h(w, req)));
        if let Err(p) = r {
            if let Some(e) = p.downcast_ref::<StateWriteError>() {
                crate::logf!("{} {}: {e}", req.method, req.path);
                write_json(
                    w,
                    503,
                    &json!({"error": format!("{e}: nothing of this request was kept, try again")}),
                );
                return;
            }
            std::panic::resume_unwind(p);
        }
    })
}

/// a body decoded as Go's json.NewDecoder(io.LimitReader(req.Body, n)).Decode (a bad one leaves the zero value)
pub fn decode_body<T: serde::de::DeserializeOwned + Default>(req: &mut Req, n: u64) -> T {
    let b = req.read_body(n);
    jarvis_go::unmarshal(&b).unwrap_or_default()
}

pub fn decode_body_strict<T: serde::de::DeserializeOwned>(req: &mut Req, n: u64) -> Result<T> {
    let b = req.read_body(n);
    Ok(jarvis_go::unmarshal(&b)?)
}

impl Router {
    /// /m only, for the listener that only Fly's private network reaches
    pub fn machine_handler(self: &Arc<Self>) -> AppFn {
        let mux = self.handlers().1;
        state_write_guard(Arc::new(move |w, req| mux.serve(w, req)))
    }

    /// the public listener behind cloudflared — the app, the web page and setup
    pub fn handler(self: &Arc<Self>) -> AppFn {
        let mux = self.handlers().0;
        state_write_guard(Arc::new(move |w, req| mux.serve(w, req)))
    }

    pub fn handlers(self: &Arc<Self>) -> (Arc<Mux>, Arc<Mux>) {
        self.muxes
            .get_or_init(|| {
                let (a, b, pats) = self.build_handlers();
                let _ = self.app_patterns.set(pats);
                (Arc::new(a), Arc::new(b))
            })
            .clone()
    }

    fn build_handlers(self: &Arc<Self>) -> (Mux, Mux, BTreeMap<String, bool>) {
        let mut reg = Registrar {
            r: self.clone(),
            public: Mux::new(),
            machine: Mux::new(),
            app_patterns: BTreeMap::new(),
        };
        reg.build();
        (reg.public, reg.machine, reg.app_patterns)
    }

    /// one call relayed to the core, its answer unchanged
    pub fn relay(&self, w: &mut W, method: &str, path: &str, body: Option<&[u8]>) {
        let c = self.core.clone();
        self.relay_to(w, &c, method, path, body)
    }

    /// one call relayed to c (the core, or secrets for the stores on a box with no core), its answer unchanged
    pub fn relay_to(
        &self,
        w: &mut W,
        c: &CoreClient,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
    ) {
        match c.raw(method, path, body) {
            Err(e) => {
                // no core to talk to (its pod is restarting, e.g. after a wipe): a state, not a fault
                crate::logf!("{} {method} {path}: {e:#}", c.who());
                write_json(
                    w,
                    503,
                    &json!({"error": format!("the {} isn't running", c.who()), "coreDown": true}),
                );
            }
            Ok((status, b)) => {
                w.set_header("Content-Type", "application/json");
                w.write_header(status);
                w.write(&b);
            }
        }
    }

    /// a setup call is signed by the setup key over "<METHOD> <path> <unix time> <sha256hex body>", within two
    /// minutes, each signature once
    pub fn check_setup_sig(
        &self,
        method: &str,
        path: &str,
        t: &str,
        sig: &str,
        body: &[u8],
    ) -> Result<()> {
        if self.cfg.no_access && self.cfg.setup_key.is_empty() {
            return Ok(()); // CI without a setup key
        }
        let ts: i64 = t.parse().map_err(|_| anyhow!("setup signature required"))?;
        let d = crate::util::unix_now() - ts;
        if !(-120..=120).contains(&d) {
            return Err(anyhow!("X-Setup-Time too far off"));
        }
        let msg = format!("{method} {path} {ts} {}", hex::encode(Sha256::digest(body)));
        if self.cfg.setup_key.is_empty() || !verify_p256(&self.cfg.setup_key, msg.as_bytes(), sig) {
            return Err(anyhow!("bad setup signature"));
        }
        let mut seen = self.setup_seen.lock().unwrap_or_else(|e| e.into_inner());
        let now = crate::util::unix_now();
        seen.retain(|_, at| now - *at <= 300);
        if seen.contains_key(sig) {
            return Err(anyhow!("setup signature already used"));
        }
        seen.insert(sig.to_string(), now);
        Ok(())
    }

    pub fn require_deyao(self: &Arc<Self>, f: AppFn) -> AppFn {
        let r = self.clone();
        Arc::new(move |w, req| {
            if !r.cfg.no_access {
                let tok = req.header("Cf-Access-Jwt-Assertion");
                match r.access().verify(&tok, &r.cfg.app_aud) {
                    Ok(c) if c.email.eq_ignore_ascii_case(&r.cfg.allowed_email) => {}
                    _ => {
                        write_json(w, 403, &json!({"error": "Access login required"}));
                        return;
                    }
                }
            }
            f(w, req)
        })
    }

    /// the setup session's Access service token (app jarvis4.deyaochen.com/setup); the core then checks the setup
    /// key's own signature, so this gate only keeps strangers away from the code
    pub fn require_setup(self: &Arc<Self>, f: AppFn) -> AppFn {
        let r = self.clone();
        Arc::new(move |w, req| {
            if !r.cfg.no_access
                && r.access()
                    .verify(&req.header("Cf-Access-Jwt-Assertion"), &r.cfg.setup_aud)
                    .is_err()
            {
                write_json(w, 403, &json!({"error": "Access service token required"}));
                return;
            }
            f(w, req)
        })
    }

    /// No Access here — this listener is reachable only over Fly's private network; every request must be signed by
    /// a machine the core started. The time is checked as the request arrives, before its body is read (a large body
    /// over a slow link took over 2 min to arrive and was refused as too old, 2026-10-21).
    pub fn require_machine(self: &Arc<Self>, f: MachineFn) -> AppFn {
        let r = self.clone();
        Arc::new(move |w, req| {
            let (machine, t, sig) = (
                req.header("X-Machine"),
                req.header("X-Time"),
                req.header("X-Sig"),
            );
            if !time_ok(&t) {
                write_json(w, 401, &json!({"error": "X-Time too far off"}));
                return;
            }
            let mut body = vec![];
            if let Err(e) = (&mut req.body).take(4 << 30).read_to_end(&mut body) {
                write_err(w, &e.into());
                return;
            }
            let key = r.st.read(|d| {
                d.started
                    .get(&machine)
                    .map(|s| s.signing_key.clone())
                    .unwrap_or_default()
            });
            let sum = hex::encode(Sha256::digest(&body));
            let msg = format!("{} {} {t} {sum}", req.method, req.path);
            // a signature over the path WITH its query is as good (it binds more): the session image of 2026-10-13
            // 01:30-03:00 signed its Claude login polls that way
            let with_query = format!("{} {}?{} {t} {sum}", req.method, req.path, req.raw_query);
            if key.is_empty()
                || !(verify_p256(&key, msg.as_bytes(), &sig)
                    || (!req.raw_query.is_empty()
                        && verify_p256(&key, with_query.as_bytes(), &sig)))
            {
                write_json(
                    w,
                    401,
                    &json!({"error": "not signed by a machine the core started"}),
                );
                return;
            }
            f(w, req, &machine, &body)
        })
    }

    /// require_machine for a large body — streamed to a temp file on the volume while it is hashed, then the signature
    /// (over that hash) checked; f gets the file's path and must move or remove it
    pub fn require_machine_stream(self: &Arc<Self>, f: StreamFn) -> AppFn {
        let r = self.clone();
        Arc::new(move |w, req| {
            let (machine, t, sig) = (
                req.header("X-Machine"),
                req.header("X-Time"),
                req.header("X-Sig"),
            );
            if !time_ok(&t) {
                write_json(w, 401, &json!({"error": "X-Time too far off"}));
                return;
            }
            let key = r.st.do_(|d| {
                d.started
                    .get(&machine)
                    .map(|s| s.signing_key.clone())
                    .unwrap_or_default()
            });
            if key.is_empty() {
                // before reading a byte: only a machine the core started may write to the volume
                write_json(
                    w,
                    401,
                    &json!({"error": "not signed by a machine the core started"}),
                );
                return;
            }
            let scratch = std::path::Path::new(&r.cfg.data_dir).join("tmp");
            let _ = std::fs::create_dir_all(&scratch);
            let tmp = scratch.join(format!(".upload-{}", crate::util::rand_id()));
            let res = (|| -> Result<String> {
                let mut f = std::fs::File::create(&tmp)?;
                let mut h = Sha256::new();
                let mut body: Box<dyn Read> = Box::new(&mut req.body);
                if req.path == "/m/snapshot" {
                    // snapwait.rs: the final snapshot's bytes arriving are progress
                    body = Box::new(crate::snapwait::MovedReader::new(body, r.clone(), &machine));
                }
                let mut buf = vec![0u8; 256 << 10];
                let mut n: u64 = 0;
                let mut limited = body.take(crate::snapstore::SNAPSHOT_MAX + 1);
                loop {
                    let k = limited.read(&mut buf)?;
                    if k == 0 {
                        break;
                    }
                    h.update(&buf[..k]);
                    std::io::Write::write_all(&mut f, &buf[..k])?;
                    n += k as u64;
                }
                if n > crate::snapstore::SNAPSHOT_MAX {
                    return Err(anyhow!(
                        "body over {} bytes",
                        crate::snapstore::SNAPSHOT_MAX
                    ));
                }
                Ok(hex::encode(h.finalize()))
            })();
            let sum = match res {
                Ok(s) => s,
                Err(e) => {
                    let _ = std::fs::remove_file(&tmp);
                    write_err(w, &e);
                    return;
                }
            };
            let msg = format!("{} {} {t} {sum}", req.method, req.path);
            if !verify_p256(&key, msg.as_bytes(), &sig) {
                let _ = std::fs::remove_file(&tmp);
                write_json(
                    w,
                    401,
                    &json!({"error": "not signed by a machine the core started"}),
                );
                return;
            }
            f(w, req, &machine, &tmp)
        })
    }

    pub fn access(&self) -> Arc<AccessKeys> {
        let mut g = ACCESS_CACHE.lock().unwrap_or_else(|e| e.into_inner());
        g.entry(self.cfg.access_team.clone())
            .or_insert_with(|| {
                Arc::new(AccessKeys {
                    team: self.cfg.access_team.clone(),
                    keys: Mutex::new((BTreeMap::new(), 0)),
                })
            })
            .clone()
    }
}

/// how far a machine's X-Time may be from the router's clock, as the request arrives (seconds; tests change it)
pub static MACHINE_TIME_SKEW: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(120);

fn time_ok(t: &str) -> bool {
    let ts: i64 = t.parse().unwrap_or(0);
    let d = crate::util::unix_now() - ts;
    let k = MACHINE_TIME_SKEW.load(std::sync::atomic::Ordering::Relaxed);
    (-k..=k).contains(&d)
}

/// a P-256 signature (base64 DER over sha256(payload)) by the base64 uncompressed public key
pub fn verify_p256(pub_raw: &str, payload: &[u8], sig_b64: &str) -> bool {
    jarvis_sig::verify(pub_raw, payload, sig_b64)
}

/// what the session list shows of a session
pub fn session_view(s: &Session, d: &Persisted) -> Map<String, Value> {
    let name = if s.label.is_empty() {
        &s.title
    } else {
        &s.label
    };
    let stores = s.stores.clone();
    let runner = crate::awsrunner::session_runner(s);
    // one kind of sandbox, on the fabric's hosts: the session's size and Fly region are not its
    let (guest, region) = if runner == "fabric" {
        (
            crate::fabricrunner::FABRIC_GUEST.to_string(),
            crate::fabricrunner::FABRIC_REGION.to_string(),
        )
    } else {
        (crate::sizes::size_label(&s.size), s.region.clone())
    };
    let mut v: Map<String, Value> = json!({
        "serverTitle": s.app_title, "userTitle": s.user_title, "title": crate::titles::session_title(s), "liveSync": s.live_sync,
        "id": s.id, "machineId": null_if_empty(&s.machine_id), "released": s.machine_id.is_empty() && s.state == "paused",
        "name": name, "state": s.state, "status": s.status, "error": s.error, "created": s.created, "region": region, "runner": runner,
        "environment": stores.clone().unwrap_or_default().join(","), "stores": stores, "content": s.content.clone().unwrap_or_default(),
        "harness": s.harness, "label": s.label, "aiTitle": s.title,
        "model": s.model, "permissionMode": s.permission_mode, "guest": guest, "size": s.size, "pausedAt": s.paused_at,
        "image": s.image, "createRequestId": s.request_id, "repos": s.repos, "discordChannel": s.discord_channel,
        "waiting": s.waiting, "lockedStore": s.locked_store, "carryLost": s.carry_lost, "oldCore": s.old_core,
        "claudeAccount": null_if_empty(&s.claude_account),
        "kernel": s.kernel.is_some(),
        "failedAt": s.failed_at,
        "lost": s.lost,
    })
    .as_object()
    .cloned()
    .unwrap_or_default();
    crate::autopilot::live_view(s, &mut v);
    crate::snapsafe::snapshot_view(s, &mut v);
    crate::disk::disk_view(s, &mut v);
    crate::schedule::schedule_view(d, &s.id, &mut v);
    crate::messages::messages_view(d, &s.id, &mut v);
    crate::sessionops::ops_view(s, &mut v);
    v
}

pub fn null_if_empty(s: &str) -> Value {
    if s.is_empty() {
        Value::Null
    } else {
        Value::String(s.to_string())
    }
}

// ---- Cloudflare Access: the router checks the JWT itself too -------------------------------------------------

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct AccessClaims {
    pub aud: Value,
    pub email: String,
    /// a service token's client id (no email)
    pub common_name: String,
    pub exp: i64,
    pub iss: String,
}

pub struct AccessKeys {
    team: String,
    keys: Mutex<(BTreeMap<String, rsa::RsaPublicKey>, i64)>,
}

static ACCESS_CACHE: std::sync::LazyLock<Mutex<BTreeMap<String, Arc<AccessKeys>>>> =
    std::sync::LazyLock::new(|| Mutex::new(BTreeMap::new()));

fn b64url(s: &str) -> Result<Vec<u8>> {
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s)?)
}

impl AccessKeys {
    fn key(&self, kid: &str) -> Result<rsa::RsaPublicKey> {
        let mut g = self.keys.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(k) = g.0.get(kid)
            && crate::util::unix_now() - g.1 < 3600
        {
            return Ok(k.clone());
        }
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct K {
            kid: String,
            n: String,
            e: String,
        }
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct Set {
            keys: Vec<K>,
        }
        let set: Set = reqwest::blocking::Client::new()
            .get(format!("https://{}/cdn-cgi/access/certs", self.team))
            .timeout(Duration::from_secs(30))
            .send()?
            .json()?;
        g.0.clear();
        g.1 = crate::util::unix_now();
        for k in set.keys {
            let (Ok(n), Ok(e)) = (b64url(&k.n), b64url(&k.e)) else {
                continue;
            };
            if let Ok(pk) = rsa::RsaPublicKey::new(
                rsa::BigUint::from_bytes_be(&n),
                rsa::BigUint::from_bytes_be(&e),
            ) {
                g.0.insert(k.kid, pk);
            }
        }
        g.0.get(kid)
            .cloned()
            .ok_or_else(|| anyhow!("unknown Access key"))
    }

    pub fn verify(&self, tok: &str, aud: &str) -> Result<AccessClaims> {
        let parts: Vec<&str> = tok.split('.').collect();
        if parts.len() != 3 {
            return Err(anyhow!("no Access token"));
        }
        let (Ok(hb), Ok(pb), Ok(sig)) = (b64url(parts[0]), b64url(parts[1]), b64url(parts[2]))
        else {
            return Err(anyhow!("bad token"));
        };
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct H {
            alg: String,
            kid: String,
        }
        let h: H = jarvis_go::unmarshal(&hb).unwrap_or_default();
        if h.alg != "RS256" {
            return Err(anyhow!("bad alg"));
        }
        let k = self.key(&h.kid)?;
        let sum = Sha256::digest(format!("{}.{}", parts[0], parts[1]).as_bytes());
        k.verify(rsa::Pkcs1v15Sign::new::<Sha256>(), &sum, &sig)
            .map_err(|_| anyhow!("bad token signature"))?;
        let c: AccessClaims = jarvis_go::unmarshal(&pb)?;
        if crate::util::unix_now() > c.exp {
            return Err(anyhow!("token expired"));
        }
        if c.iss != format!("https://{}", self.team) {
            return Err(anyhow!("wrong issuer"));
        }
        let ok = match &c.aud {
            Value::String(s) => s == aud,
            Value::Array(a) => a.iter().any(|x| x.as_str() == Some(aud)),
            _ => false,
        };
        if !ok {
            return Err(anyhow!("wrong audience"));
        }
        Ok(c)
    }
}

// ---- registering the routes ----------------------------------------------------------------------------------

pub struct Registrar {
    pub r: Arc<Router>,
    pub public: Mux,
    pub machine: Mux,
    pub app_patterns: BTreeMap<String, bool>,
}

impl Registrar {
    /// an app route: Deyao's Access login
    pub fn app(
        &mut self,
        pattern: &str,
        f: impl Fn(&Arc<Router>, &mut W, &mut Req) + Send + Sync + 'static,
    ) {
        self.app_patterns.insert(pattern.to_string(), true);
        let r = self.r.clone();
        let h = self.r.require_deyao(Arc::new(move |w, req| f(&r, w, req)));
        self.public.handle(pattern, h);
    }

    /// a machine route: signed by a machine the core started
    pub fn m(
        &mut self,
        pattern: &str,
        f: impl Fn(&Arc<Router>, &mut W, &mut Req, &str, &[u8]) + Send + Sync + 'static,
    ) {
        let r = self.r.clone();
        let h = self
            .r
            .require_machine(Arc::new(move |w, req, m, b| f(&r, w, req, m, b)));
        self.machine.handle(pattern, h);
    }

    /// a public route as it is (its own gate)
    pub fn handle(&mut self, pattern: &str, h: AppFn) {
        self.public.handle(pattern, h);
    }

    /// a public route with its own gate, given the router
    pub fn public_fn(
        &mut self,
        pattern: &str,
        f: impl Fn(&Arc<Router>, &mut W, &mut Req) + Send + Sync + 'static,
    ) {
        let r = self.r.clone();
        self.public
            .handle(pattern, Arc::new(move |w, req| f(&r, w, req)));
    }

    /// a setup route: the setup session's Access token
    pub fn setup_route(
        &mut self,
        pattern: &str,
        f: impl Fn(&Arc<Router>, &mut W, &mut Req) + Send + Sync + 'static,
    ) {
        let r = self.r.clone();
        let h = self.r.require_setup(Arc::new(move |w, req| f(&r, w, req)));
        self.public.handle(pattern, h);
    }

    /// a setup route whose request the setup key signed (X-Setup-Time, X-Setup-Sig over the method, path and body): f gets
    /// the body, at most max bytes
    pub fn setup_signed(
        &mut self,
        pattern: &str,
        max: u64,
        f: impl Fn(&Arc<Router>, &mut W, &mut Req, &[u8]) + Send + Sync + 'static,
    ) {
        self.setup_route(pattern, move |r, w, req| {
            let b = req.read_body(max);
            if let Err(e) = r.check_setup_sig(
                &req.method,
                &req.path,
                &req.header("X-Setup-Time"),
                &req.header("X-Setup-Sig"),
                &b,
            ) {
                crate::nethttp::write_error(w, 401, &format!("{e:#}"));
                return;
            }
            f(r, w, req, &b)
        });
    }

    /// setup: the setup session's Access token AND its key's signature, relayed to the core (the core's store calls
    /// are open, the router decides who uses them)
    fn setup_relay(&mut self, pattern: &str, method: &'static str, core_path: &'static str) {
        self.setup_route(pattern, move |r, w, req| {
            let b = req.read_body(1 << 20);
            if let Err(e) = r.check_setup_sig(
                &req.method,
                &req.path,
                &req.header("X-Setup-Time"),
                &req.header("X-Setup-Sig"),
                &b,
            ) {
                crate::nethttp::write_error(w, 401, &format!("{e:#}"));
                return;
            }
            let body = if method == "GET" { None } else { Some(&b[..]) };
            if core_path == "/identity" || core_path.starts_with("/stores") {
                let c = r.store_core(); // the stores' keeper: secrets on a box with no core
                r.relay_to(w, &c, method, core_path, body);
                return;
            }
            r.relay(w, method, core_path, body);
        });
    }

    fn spawner_relay(&mut self, pattern: &str, path: &'static str) {
        self.setup_route(pattern, move |r, w, req| {
            let b = req.read_body(1 << 16);
            let input: Option<Value> = serde_json::from_slice(&b).ok();
            let (Some(k), Some(input)) = (&r.kernel, input) else {
                crate::nethttp::write_error(w, 400, "{sealed}, on a box with a kernel");
                return;
            };
            match k.call("spawner", "POST", path, Some(&input)) {
                Err(e) => write_err(w, &e),
                Ok(b) => {
                    w.set_header("Content-Type", "application/json");
                    w.write(&b);
                }
            }
        });
    }

    fn build(&mut self) {
        let r = self.r.clone();
        crate::features::register_features(self);
        crate::storedocs::register_store_docs(self); // every store's keys, what they are for, and writing one key
        crate::storerestore::register_restore(self); // a store's versions and putting one back (phone-signed)
        crate::actions::register_actions(self); // each session's actions, on its machine key
        crate::nextcore::register_next_core(self); // the flip to the next core
        crate::healthz::register_healthz(self); // the external uptime probe
        // the router's own health, for an operator with no way into the box: secret NAMES present, image, core up
        self.setup_route("GET /setup/status", |r, w, req| {
            if let Err(e) = r.check_setup_sig(&req.method, &req.path, &req.header("X-Setup-Time"), &req.header("X-Setup-Sig"), b"") {
                crate::nethttp::write_error(w, 401, &format!("{e:#}"));
                return;
            }
            let present: Vec<&str> = [
                "LOBSTER_TOKEN", "STORAGEBOX_HOST", "STORAGEBOX_USER", "STORAGEBOX_PASSWORD", "FLY_READ_TOKEN",
                "JARVIS2_TUNNEL_KEY", "GITHUB_READ_TOKEN", "BACKUP_READ_ACCESS_KEY", "BACKUP_READ_SECRET_KEY",
                "FLY_ORG_READ_TOKENS", "FLY_PERSONAL_READ_TOKEN", "FLY_VOLUME_TOKEN", "BROWSERBASE_API_KEY",
                "CF_DEVICE_TOKENS_API",
            ]
            .into_iter()
            .filter(|k| std::env::var(k).is_ok_and(|v| !v.is_empty()))
            .collect();
            let core_up = r.core.key().is_ok();
            // what the repo picker's token sees, as counts only
            let gh = match r.github_repos(false) {
                Err(e) => json!({"error": format!("{e:#}")}),
                Ok((repos, _)) => json!({"total": repos.len(), "private": repos.iter().filter(|x| x.private).count()}),
            };
            // the Machines view's orgs, as counts only (flyorgs.rs)
            let own = crate::machines::list_fly_machines().unwrap_or_default();
            let (orgs, _) = r.fly_orgs_overview(&own, GoTime::now());
            let fly_orgs: Vec<Value> = orgs
                .iter()
                .map(|o| {
                    let apps: Vec<&str> = o.apps.iter().map(|a| a.app.as_str()).collect();
                    let machines: usize = o.apps.iter().map(|a| a.machines.len()).sum();
                    json!({"org": o.org, "via": o.via, "error": o.error, "apps": apps, "machines": machines,
                        "attention": crate::flyorgs::fly_attention_count(std::slice::from_ref(o))})
                })
                .collect();
            write_json(w, 200, &json!({"secrets": present, "sessionImage": r.cfg.session_image, "coreUp": core_up,
                "version": std::env::var("VERSION").unwrap_or_default(), "githubRepos": gh, "flyOrgs": fly_orgs,
                "core": r.next_core_status(), "leads": crate::leaderlease::leads(), "replica": crate::router::router_id(),
                "process": crate::procstat::process_status(), "volumeSweep": crate::volsweep::volume_sweep_status(),
                "db": r.db_status()}));
        });
        self.setup_route("GET /setup/services", |r, w, req| r.setup_services(w, req)); // search and the watch runner
        self.setup_relay("GET /setup/identity", "GET", "/identity");
        self.setup_relay("POST /setup/stores", "POST", "/stores");
        self.setup_relay("POST /setup/stores/create", "POST", "/stores/create");
        self.setup_relay(
            "POST /setup/stores/mark-sensitive",
            "POST",
            "/stores/mark-sensitive",
        );
        // the core's Fly token, sealed to the core (after a Reset; a Recover brings it from the backups)
        self.setup_relay("POST /setup/fly-token", "POST", "/fly-token");
        // the kernel's spawner: its identity, and the Fly token sealed to it (infra/setup.py kernel-fly-token)
        self.setup_route("GET /setup/kernel/spawner/identity", |r, w, _| {
            let Some(k) = &r.kernel else {
                crate::nethttp::write_error(w, 503, "this box runs no kernel");
                return;
            };
            match k.call("spawner", "GET", "/identity", None) {
                Err(e) => write_err(w, &e),
                Ok(b) => {
                    w.set_header("Content-Type", "application/json");
                    w.write(&b);
                }
            }
        });
        self.spawner_relay("POST /setup/kernel/spawner/fly-token", "/fly-token");
        // the spawner's AWS key, sealed to it the same way (infra/setup.py kernel-aws-credentials)
        self.spawner_relay(
            "POST /setup/kernel/spawner/aws-credentials",
            "/aws-credentials",
        );
        // the fabric hermit's tokens for the spawner's fabric runner (infra/setup.py kernel-fabric-credentials)
        self.spawner_relay(
            "POST /setup/kernel/spawner/fabric-credentials",
            "/fabric-credentials",
        );

        // ---- setting the core up: Reset and Recover (the app, with the master key) -----------------------------
        self.app("GET /api/core/identity", |r, w, req| {
            r.relay_for(w, req, "GET", "/identity", None)
        });
        // the claim also carries the app's device-key countersignature: the core ignores it; the router keeps it for
        // the setup session (claimdevice.rs), which trusts a new master key only with it
        self.app("POST /api/core/claim", |r, w, req| {
            let b = req.read_body(16 << 20);
            r.keep_claim_device(&b);
            let Some(c) = r.core_for(req) else {
                crate::nethttp::write_error(w, 404, "there is no next core");
                return;
            };
            match c.raw("POST", "/claim", Some(&b)) {
                Err(e) => {
                    crate::logf!("core POST /claim: {e:#}");
                    write_json(
                        w,
                        503,
                        &json!({"error": "the core isn't running", "coreDown": true}),
                    );
                }
                Ok((status, out)) => {
                    if status == 200 {
                        r.keep_core_cert(&b); // claimdevice.rs: the master's signature on this core
                    }
                    w.set_header("Content-Type", "application/json");
                    w.write_header(status);
                    w.write(&out);
                }
            }
        });
        self.setup_route("GET /setup/core-cert", |r, w, req| {
            if let Err(e) = r.check_setup_sig(
                &req.method,
                &req.path,
                &req.header("X-Setup-Time"),
                &req.header("X-Setup-Sig"),
                b"",
            ) {
                crate::nethttp::write_error(w, 401, &format!("{e:#}"));
                return;
            }
            match r.core_cert() {
                None => crate::nethttp::write_error(
                    w,
                    404,
                    "no claim kept for the running core (empty, or claimed elsewhere)",
                ),
                Some(b) => {
                    w.set_header("Content-Type", "application/json");
                    w.write(&b);
                }
            }
        });
        self.setup_route("GET /setup/claim-device", |r, w, _| {
            write_json(w, 200, &r.claim_devices())
        });
        // claim and wipe: signed by the master key and checked by the core, so any of Deyao's logins may relay them
        self.app("POST /api/core/wipe", |r, w, req| {
            let b = req.read_body(16 << 20);
            r.relay_for(w, req, "POST", "/wipe", Some(&b)); // nextcore.rs: ?core=next sets the next core up
        });
        crate::backups::register_backups(self);
        crate::kernelline::register_kernel(self);
        crate::fabricops::register_fabric_ops(self); // the fabric hermit's operator page, read only
        crate::roster::register_roster(self);
        crate::linestate::register_line_state(self);
        self.app("GET /api/policy", |r, w, _| write_json(w, 200, &r.policy));
        // the web page's build (its index.html, which names its hashed files): an open tab asks now and then, and
        // loads itself again when the answer is no longer the one it was loaded from (app/src/lib/build.ts)
        let web_build = std::fs::read(std::path::Path::new(&r.cfg.web_dir).join("index.html"))
            .map(|b| hex::encode(Sha256::digest(&b))[..12].to_string())
            .unwrap_or_default();
        self.app("GET /api/build", move |_, w, _| {
            write_json(w, 200, &json!({"build": web_build}))
        });

        // ---- sign-in -----------------------------------------------------------------------------------
        self.app("GET /api/auth/start", |_, w, req| {
            let redirect = req.query("redirect");
            if !redirect.starts_with("jarvis2://") {
                crate::nethttp::write_error(w, 400, "only jarvis2:// redirects");
                return;
            }
            let mut tok = req.header("Cf-Access-Jwt-Assertion");
            if tok.is_empty() {
                tok = req.header("cf-access-token");
            }
            let loc: String = format!(
                "{redirect}#token={}",
                url::form_urlencoded::byte_serialize(tok.as_bytes()).collect::<String>()
            );
            crate::util::redirect(w, req, &loc, 302);
        });

        // ---- state ---------------------------------------------------------------------------------------
        self.app("GET /api/state", |r, w, _| {
            let key = r.core.key();
            let mut core_info = json!({"up": key.is_ok(), "none": r.cfg.no_core});
            if let Ok(k) = &key {
                core_info["signingKey"] = json!(k.get("signingKey"));
                core_info["agreementKey"] = json!(k.get("agreementKey"));
            }
            let (mut sessions, mut approvals) = r.st.do_(|d| {
                let ss: Vec<(GoTime, Map<String, Value>)> = d
                    .sessions
                    .values()
                    .map(|s| (s.created, session_view(s, d)))
                    .collect();
                let aa: Vec<Approval> = d.approvals.values().cloned().collect();
                (ss, aa)
            });
            sessions.sort_by_key(|a| std::cmp::Reverse(a.0));
            approvals.sort_by_key(|a| a.created);
            let mut out: Map<String, Value> = Map::new();
            out.insert(
                "sessions".into(),
                Value::Array(
                    sessions
                        .into_iter()
                        .map(|(_, v)| Value::Object(v))
                        .collect(),
                ),
            );
            out.insert("approvals".into(), json!(approvals));
            out.insert("core".into(), core_info);
            for h in crate::features::state_hooks() {
                h(r, &mut out);
            }
            write_json(w, 200, &out);
        });
        self.app("GET /api/sizes", |_, w, _| {
            let sizes: Vec<Value> = ["small", "medium", "large"]
                .iter()
                .map(|s| json!({"id": s, "label": crate::sizes::size_label(s)}))
                .collect();
            write_json(w, 200, &json!({"sizes": sizes}));
        });
        self.app("GET /api/regions", |r, w, _| {
            let regions: Vec<Value> = crate::regions::SESSION_REGIONS
                .iter()
                .map(|(id, label)| json!({"id": id, "label": label}))
                .collect();
            let runners: Vec<Value> = crate::awsrunner::session_runners()
                .iter()
                .map(|g| json!({"id": g.id, "label": g.label}))
                .collect();
            write_json(
                w,
                200,
                &json!({"regions": regions, "default": r.cfg.region, "runners": runners,
                "defaultRunner": crate::awsrunner::default_runner()}),
            );
        });
        self.app("GET /api/records", |r, w, _| {
            let recs: Vec<Record> = r.st.do_(|d| d.records.clone());
            write_json(w, 200, &json!({"records": recs}));
        });

        // ---- grants (grants.rs) and the terminal (terminal.rs) ----------------------------------------------
        self.app("GET /api/holders", |r, w, _| match r.holder_public_keys() {
            Err(e) => write_err(w, &e),
            Ok(p) => write_json(w, 200, &json!({"holders": p})),
        });
        self.app("POST /api/sessions/{id}/grants/draft", |r, w, req| {
            #[derive(Deserialize, Default)]
            #[serde(default)]
            struct In {
                holder: String,
                kind: String,
                minutes: i64,
                until: GoTime,
            }
            let i: In = decode_body(req, 1 << 16);
            match r.draft_grant(
                &req.path_value("id"),
                &i.holder,
                &i.kind,
                i.minutes,
                i.until,
            ) {
                Err(e) => write_err(w, &e),
                Ok(text) => write_json(w, 200, &json!({"text": text})),
            }
        });
        self.app("POST /api/sessions/{id}/grants", |r, w, req| {
            let i: Doc = decode_body(req, 1 << 16);
            match r.add_grant(&req.path_value("id"), Some(&i)) {
                Err(e) => write_err(w, &e),
                Ok(g) => write_json(w, 200, &g),
            }
        });
        // the line's latest core-signed succession cert: the phone's grant page reads the line, its own key and the
        // stores from it (the router can't forge it)
        self.app("GET /api/sessions/{id}/cert", |r, w, req| {
            let id = req.path_value("id");
            match r
                .st
                .do_(|d| d.sessions.get(&id).and_then(|s| s.cert.clone()))
            {
                None => {
                    crate::nethttp::write_error(w, 404, "the session has no certified machine yet")
                }
                Some(c) => write_json(w, 200, &c),
            }
        });
        self.app("GET /api/sessions/{id}/grants", |r, w, req| {
            write_json(w, 200, &json!({"grants": r.grants(&req.path_value("id"))}));
        });
        self.app("DELETE /api/grants/{gid}", |r, w, req| {
            r.forget_grant(&req.path_value("gid"));
            write_json(w, 200, &json!({"ok": true}));
        });
        self.app("POST /api/sessions/{id}/exec", |r, w, req| {
            #[derive(Deserialize, Default)]
            #[serde(default)]
            struct In {
                cmd: String,
                timeout: i64,
            }
            let i: In = decode_body(req, 1 << 20);
            let t = Duration::from_secs(i.timeout.clamp(5, 600) as u64);
            match r.exec(&req.path_value("id"), "terminal", &i.cmd, t) {
                Err(e) => write_err(w, &e),
                Ok(res) => write_json(w, 200, &res),
            }
        });
        self.app("GET /api/sessions/{id}/terminal", |r, w, req| {
            match r.term_snapshot(&req.path_value("id")) {
                Err(e) => write_err(w, &e),
                Ok(s) => write_json(w, 200, &s),
            }
        });
        crate::termpage::register_term_page(self); // the terminal as a web page (the iPhone app shows it in a web view)
        self.app("POST /api/sessions/{id}/terminal", |r, w, req| {
            #[derive(Deserialize, Default)]
            #[serde(default)]
            struct In {
                text: String,
                keys: Vec<String>,
                #[serde(alias = "Cols")]
                cols: i64,
                #[serde(alias = "Rows")]
                rows: i64,
            }
            let i: In = decode_body(req, 1 << 16);
            let id = req.path_value("id");
            let res = if i.cols > 0 {
                r.term_resize(&id, i.cols, i.rows)
            } else {
                r.term_input(&id, &i.text, &i.keys)
            };
            match res {
                Err(e) => write_err(w, &e),
                Ok(()) => write_json(w, 200, &json!({"ok": true})),
            }
        });

        // ---- sessions ------------------------------------------------------------------------------------
        self.app("POST /api/sessions", |r, w, req| {
            let b = req.read_body(1 << 20);
            let mut i: crate::flows::NewSession = match jarvis_go::unmarshal(&b) {
                Ok(i) => i,
                Err(e) => {
                    write_err(w, &anyhow!("bad JSON: {e}"));
                    return;
                }
            };
            if i.request_id.is_empty() {
                i.request_id = crate::util::rand_id();
            }
            let mut args = json!({"label": i.label, "harness": i.harness, "stores": i.stores, "model": i.model,
                "permissionMode": i.permission_mode, "size": i.size});
            if !i.region.is_empty() {
                args["region"] = json!(i.region);
            }
            if !i.runner.is_empty() {
                args["runner"] = json!(i.runner);
            }
            if !i.repos.is_empty() {
                args["repos"] = json!(i.repos);
            }
            if !i.content.is_empty() {
                args["content"] = json!(i.content);
            }
            if !i.prompt.is_empty() {
                args["prompt"] = json!(format!("({} characters)", i.prompt.chars().count()));
            }
            i.origin = Some(crate::inbox::Origin {
                caller: crate::inbox::app_caller(req),
                call: crate::inbox::ApiCall {
                    method: "POST".into(),
                    path: "/api/sessions".into(),
                    args: args.as_object().cloned().unwrap_or_default(),
                },
                via_call: crate::apicalls::via_call(req),
                ..Default::default()
            });
            let rid = i.request_id.clone();
            match r.create_session(i) {
                Err(e) => crate::schedule::schedule_err(w, &e),
                Ok(id) => {
                    r.expect_followup(req, &id); // apicalls.rs: its new-session approval (unless already linked)
                    write_json(w, 200, &json!({"id": id, "requestId": rid}));
                }
            }
        });
        self.app("POST /api/sessions/{id}/pause", |r, w, req| {
            match r.pause(&req.path_value("id")) {
                Err(e) => write_err(w, &e),
                Ok(()) => write_json(w, 200, &json!({"ok": true})),
            }
        });
        self.app("POST /api/sessions/{id}/resume", |r, w, req| {
            #[derive(Deserialize, Default)]
            #[serde(default)]
            struct In {
                upgrade: bool,
                /// delivered once the session is back (schedule.rs)
                prompt: String,
                #[serde(flatten)]
                opts: crate::sessionops::ResumeOptions,
            }
            let i: In = decode_body(req, 1 << 16);
            let id = req.path_value("id");
            let res = crate::sessionapi::clean_resume_prompt(&i.prompt).and_then(|p| {
                r.apply_resume_options(&id, i.opts.clone())?; // sessionops.rs: size, model, apiProxy
                Ok(p)
            });
            let prompt = match res {
                Err(e) => {
                    write_err(w, &e);
                    return;
                }
                Ok(p) => p,
            };
            r.note_origin(
                &id,
                crate::inbox::Origin {
                    caller: crate::inbox::app_caller(req),
                    call: crate::inbox::ApiCall {
                        method: "POST".into(),
                        path: req.path.clone(),
                        args: json!({"upgrade": i.upgrade})
                            .as_object()
                            .cloned()
                            .unwrap_or_default(),
                    },
                    via_call: crate::apicalls::via_call(req),
                    ..Default::default()
                },
            );
            r.expect_followup(req, &id); // apicalls.rs: an approved call's sheet waits for the resume's approval
            match r.resume_with_prompt(&id, i.upgrade, &prompt) {
                Err(e) => write_err(w, &e),
                Ok(()) => write_json(w, 200, &json!({"ok": true})),
            }
        });
        self.app("POST /api/sessions/{id}/destroy", |r, w, req| {
            match r.destroy_with(&req.path_value("id"), req.query("force") == "1") {
                Err(e) => write_err(w, &e),
                Ok(()) => write_json(w, 200, &json!({"ok": true})),
            }
        });

        // ---- approvals -----------------------------------------------------------------------------------
        self.app("GET /api/approvals", |r, w, _| {
            let mut out: Vec<Approval> = r.st.do_(|d| d.approvals.values().cloned().collect());
            out.sort_by_key(|a| a.created);
            write_json(w, 200, &json!({"approvals": out}));
        });
        self.app("POST /api/approvals/{id}/respond", |r, w, req| {
            #[derive(Deserialize, Default)]
            #[serde(default)]
            struct In {
                signature: String,
            }
            let i: In = decode_body(req, 1 << 16);
            match r.respond(&req.path_value("id"), &i.signature) {
                Err(e) => write_err(w, &e),
                Ok((cert, sid)) => write_json(w, 200, &json!({"answer": cert, "session": sid})),
            }
        });
        self.app("POST /api/approvals/{id}/reject", |r, w, req| {
            // an approval no longer waiting: what was asked for holds, 200 {ok, gone} as every other deny
            crate::inbox::write_denied(w, r.reject(&req.path_value("id")));
        });

        // ---- the core, relayed unchanged ------------------------------------------------------------------
        for p in [
            "stores",
            "stores/create",
            "stores/mark-sensitive",
            "unlock/begin",
            "lock",
            "unlocked",
            "store-key",
        ] {
            let path = format!("/{p}");
            self.app(&format!("POST /api/core{path}"), move |r, w, req| {
                let b = req.read_body(1 << 20);
                r.relay_stores(w, req, "POST", &path, &b); // nextcore.rs: X-Jarvis2-Core: next
            });
        }
        // an unlock for one running session's cert: its machine pulls again (storedocs.rs unlock_arrived)
        self.app("POST /api/core/unlock/finish", |r, w, req| {
            let b = req.read_body(1 << 20);
            let Some(c) = r.stores_for(req) else {
                crate::nethttp::write_error(w, 404, "there is no next core");
                return;
            };
            match c.raw("POST", "/unlock/finish", Some(&b)) {
                Err(e) => {
                    crate::logf!("core POST /unlock/finish: {e:#}");
                    write_json(
                        w,
                        503,
                        &json!({"error": "the core isn't running", "coreDown": true}),
                    );
                }
                Ok((status, out)) => {
                    if status == 200 {
                        r.unlock_arrived(&out);
                    }
                    w.set_header("Content-Type", "application/json");
                    w.write_header(status);
                    w.write(&out);
                }
            }
        });

        // ---- machines --------------------------------------------------------------------------------------
        self.m("GET /m/kernel/boot", |r, w, _, machine, _| {
            match r.kernel_boot(machine) {
                Err(e) => crate::nethttp::write_error(w, 404, &format!("{e:#}")),
                Ok(out) => write_json(w, 200, &out),
            }
        });
        self.m("GET /m/cert", |r, w, _, machine, _| {
            let (cert, pred) = r.st.do_(|d| {
                let cert = d.certs.get(machine).cloned();
                let mut pred = None;
                if let Some(c) = &cert {
                    #[derive(Deserialize, Default)]
                    #[serde(default)]
                    struct C {
                        #[serde(rename = "predecessorId")]
                        pred_id: String,
                    }
                    let c: C = c.decode().unwrap_or_default();
                    if !c.pred_id.is_empty() && c.pred_id != machine {
                        pred = d.certs.get(&c.pred_id).cloned();
                    }
                }
                (cert, pred)
            });
            match cert {
                None => crate::nethttp::write_error(w, 404, "no cert yet"),
                Some(c) => write_json(w, 200, &json!({"cert": c, "predecessorCert": pred})),
            }
        });
        self.m("GET /m/snapshot", |r, w, req, machine, _| {
            let (s, signed) = match r.snapshot_for(machine) {
                // snapdirect.rs
                Err(why) => return crate::nethttp::write_error(w, 404, &why),
                Ok(x) => x,
            };
            match r.snap_open(&s) {
                Err(e) => crate::nethttp::write_error(w, 404, &format!(": {e:#}")),
                Ok(rd) => {
                    if signed {
                        w.set_header("X-Snapshot-Sig", &s.sig);
                    }
                    w.set_header("Content-Type", "application/octet-stream");
                    let size = rd.size;
                    crate::util::serve_content(w, req, s.committed_at, rd, size);
                }
            }
        });
        crate::awsrunner::register_aws_peers(self); // the m-gateways' list of AWS machines
        crate::snapstream::register_snap_stream(self); // the final snapshot streamed, committed, carried or failed
        crate::snapprogress::register_snap_progress(self); // the final snapshot's progress
        crate::snapdirect::register_snap_direct(self); // the final snapshot and a boot's straight to and from the bucket
        let r2 = r.clone();
        let h = r.require_machine_stream(Arc::new(move |w, req, machine, tmp| {
            let r = &r2;
            if !req.header("X-Snapshot-None").is_empty() {
                let _ = std::fs::remove_file(tmp);
                // a machine still booting has nothing to snapshot: the waiting pause or destroy goes on at once
                crate::logf!(
                    "machine {machine}: nothing to snapshot ({})",
                    req.header("X-Snapshot-None")
                );
                r.snapshot_arrived(machine);
                write_json(w, 200, &json!({"ok": true}));
                return;
            }
            let sig = req.header("X-Snapshot-Sig");
            if sig.is_empty() {
                let _ = std::fs::remove_file(tmp);
                crate::nethttp::write_error(w, 400, "X-Snapshot-Sig missing");
                return;
            }
            let res = std::fs::File::open(tmp)
                .map_err(anyhow::Error::from)
                .and_then(|mut f| r.snap_put_whole(machine, &mut f, &sig)); // snapstore.rs: into the bucket, committed
            let _ = std::fs::remove_file(tmp);
            match res {
                Err(e) => write_err(w, &e),
                Ok(()) => {
                    r.snapshot_arrived(machine);
                    write_json(w, 200, &json!({"ok": true}));
                }
            }
        }));
        self.machine.handle("POST /m/snapshot", h);
        self.m("POST /m/pull-secrets", |r, w, _, machine, _| {
            let started = |r: &Router| {
                r.st.do_(|dd| {
                    let sid = dd.machines.get(machine).cloned().unwrap_or_default();
                    if let Some(s) = dd.sessions.get_mut(&sid)
                        && s.machine_id == machine
                        && s.state == "initialising"
                    {
                        s.state = "started".into();
                        s.error.clear();
                    }
                })
            };
            if r.is_kernel_machine(machine) {
                // kernelline.rs: the kernel's secrets, with the line's grant
                let res = r.kernel_pull(machine);
                r.note_secrets_pull(machine, res.as_ref().err());
                match res {
                    Err(e) => write_err(w, &e),
                    Ok(d) => {
                        crate::vouch::mark_pulled(machine);
                        started(r);
                        write_json(w, 200, &d);
                    }
                }
                return;
            }
            let Some(cert) = r.st.do_(|d| d.certs.get(machine).cloned()) else {
                crate::nethttp::write_error(w, 404, "no cert");
                return;
            };
            // carry.rs: the line's carried secrets go with the pull; a pull that goes through answers the next blob
            let release = crate::carry::carry_lock(machine);
            let res = r.core.call(
                "/pull-secrets",
                &json!({"cert": cert, "carry": r.carry_for_pull(machine, &cert)}),
            );
            if let Ok(d) = &res {
                r.pulled(machine, &cert, d);
                crate::vouch::mark_pulled(machine); // vouch.rs: a pause waits briefly for such a machine's boot
            }
            drop(release);
            r.note_secrets_pull(machine, res.as_ref().err()); // the app says which locked store the machine waits on
            match res {
                Err(e) => write_err(w, &e),
                Ok(d) => {
                    started(r);
                    write_json(w, 200, &d);
                }
            }
        });
        self.m("GET /m/commands", |r, w, _, machine, _| {
            // mq.rs: the machine's oldest untaken row, waiting up to 50 s for one (rust/machine/src/supervisor.rs
            // COMMANDS_WAIT: the machine gives a poll up 60 s past that)
            let empty: Vec<Value> = vec![];
            match r.mq_next(
                &crate::ctx::Ctx::background(),
                machine,
                Duration::from_secs(50),
            ) {
                Err(_) if w.gone() => {} // the machine went (or this replica stops)
                Err(e) => write_err(w, &e),
                Ok(None) => write_json(w, 200, &json!({"commands": empty, "execs": empty})),
                Ok(Some(it)) if it.kind == "command" => {
                    let c: String = jarvis_go::unmarshal(&it.body).unwrap_or_default();
                    write_json(w, 200, &json!({"commands": [c], "execs": empty}));
                }
                Ok(Some(it)) if it.kind == "exec" => {
                    let e: crate::grants::ExecItem =
                        jarvis_go::unmarshal(&it.body).unwrap_or_default();
                    write_json(w, 200, &json!({"commands": empty, "execs": [e]}));
                }
                Ok(Some(it)) => {
                    let d: crate::vouch::Delivery =
                        jarvis_go::unmarshal(&it.body).unwrap_or_default();
                    write_json(
                        w,
                        200,
                        &json!({"commands": empty, "execs": empty, "deliveries": [d]}),
                    );
                }
            }
        });
        self.m("POST /m/exec-result", |r, w, _, _, body| {
            let res: crate::grants::ExecResult = jarvis_go::unmarshal(body).unwrap_or_default();
            r.exec_result(res);
            write_json(w, 200, &json!({"ok": true}));
        });
        self.m("GET /m/holders", |r, w, _, _, _| {
            match r.holder_public_keys() {
                Err(e) => write_err(w, &e),
                Ok(p) => write_json(w, 200, &p),
            }
        });
        self.m("POST /m/kernel/downgrade", |r, w, _, machine, body| {
            #[derive(Deserialize, Default)]
            #[serde(default)]
            struct In {
                keep: Option<Vec<String>>,
            }
            let keep = match jarvis_go::unmarshal::<In>(body) {
                Ok(In { keep: Some(k) }) => k,
                _ => {
                    crate::nethttp::write_error(w, 400, "{keep: [stores]}");
                    return;
                }
            };
            match r.kernel_downgrade(machine, &keep) {
                Err(e) => write_err(w, &e),
                Ok(()) => write_json(w, 200, &json!({"ok": true, "keep": keep})),
            }
        });
        self.m("POST /m/add-store", |r, w, _, machine, body| {
            #[derive(Deserialize, Default)]
            #[serde(default)]
            struct In {
                store: String,
            }
            let i: In = jarvis_go::unmarshal(body).unwrap_or_default();
            match r.add_store(machine, &i.store) {
                Err(e) => write_err(w, &e),
                Ok(()) => write_json(w, 200, &json!({"ok": true})),
            }
        });
        self.m("POST /m/downgrade", |r, w, _, machine, body| {
            #[derive(Deserialize, Default)]
            #[serde(default)]
            struct In {
                stores: Vec<String>,
                #[serde(rename = "newEncryptionKey")]
                new_encryption_key: String,
                #[serde(rename = "newSigningKey")]
                new_signing_key: String,
            }
            let i: In = jarvis_go::unmarshal(body).unwrap_or_default();
            match r.downgrade_begin(
                machine,
                &i.stores,
                &i.new_encryption_key,
                &i.new_signing_key,
            ) {
                Err(e) => write_err(w, &e),
                Ok(ch) => write_json(w, 200, &json!({"challenge": ch})),
            }
        });
        self.m("POST /m/downgrade/finish", |r, w, _, machine, body| {
            #[derive(Deserialize, Default)]
            #[serde(default)]
            struct In {
                challenge: Option<Doc>,
                signature: String,
            }
            let i: In = jarvis_go::unmarshal(body).unwrap_or_default();
            match r.downgrade_finish(machine, i.challenge.as_ref(), &i.signature) {
                Err(e) => write_err(w, &e),
                Ok(cert) => write_json(w, 200, &json!({"cert": cert})),
            }
        });

        // ---- the web page ------------------------------------------------------------------------------------
        let web_dir = r.cfg.web_dir.clone();
        let h = r.require_deyao(Arc::new(move |w, req| {
            crate::util::serve_web(w, req, &web_dir)
        }));
        self.public.handle("GET /", h);
    }
}
