//! Paired devices for Deyao's builds of the OpenClaw and Paseo apps (Jarvis 1's lib/devices.js, PARITY "Device
//! pairing"): each app pairs ONCE and then lists the sessions it can drive (GET /api/remotes) and starts a paused one
//! (POST /api/sessions/:id/start), with no Access login of its own.
//!
//!   - Pairing: the app opens GET /api/devices/pair?state=…&name=…&model=…&app=openclaw|paseo in the system sign-in
//!     sheet, where Access logs Deyao in (the Jarvis 4 app's own Access app: his email only). The router mints a
//!     Cloudflare Access service token for that one device (CF_DEVICE_TOKENS_API: a Cloudflare token that can manage
//!     Access service tokens and nothing else) and hands its credentials back through the app's own URL scheme (302
//!     <scheme>://paired?state=…&id=…&clientId=…&clientSecret=…), which only the app that opened the sheet gets. The
//!     secret is never stored; the router keeps the device's name, its service token's id and client id.
//!   - Use: the Access app "Jarvis 4 devices" (infra/cloudflare.py --devices) covers only /api/remotes and
//!     /api/sessions/*/start, and admits Deyao's email or any service token of the account (ACCESS_DEVICES_AUD). The
//!     router then admits a service token only when its client id (the JWT's common_name) is a paired device's. The
//!     same device token passes the session hosts' Access (<id>-s.deyaochen.com admits any service token), where the
//!     apps reach the OpenClaw gateway, the Paseo daemon and the CloudCLI server.
//!   - Revoke: DELETE /api/devices/:id deletes the service token at Cloudflare and forgets the device.
//!
//! The apps' server URL is a constant in each fork (DE0CH/openclaw JarvisConfig.baseURL, DE0CH/paseo app.config.js
//! jarvis.url); it must name this host (docs/RUNBOOK.md "Device pairing").

use crate::content::{ContentErr, content_write_err};
use crate::http::{AccessClaims, AppFn, Registrar};
use crate::nethttp::{Req, W, write_json};
use crate::router::{BadReq, Router};
use anyhow::{Result, anyhow};
use jarvis_go::GoTime;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::{Arc, LazyLock, Mutex, RwLock};

/// the apps that pair, each with the URL scheme its pairing answer goes to
pub fn device_scheme(app: &str) -> &'static str {
    match app {
        "openclaw" => "openclaw-de0ch",
        "paseo" => "paseo-de0ch",
        _ => "",
    }
}

static PAIR_STATE_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"^[A-Za-z0-9_-]{16,64}$").unwrap_or_else(|_| unreachable!())
});

pub static CF_API_BASE: LazyLock<RwLock<String>> =
    LazyLock::new(|| RwLock::new("https://api.cloudflare.com/client/v4".into()));
pub const CF_ACCOUNT: &str = "ee3b4deef856baf11e1a67b242438325";
/// a client stuck in a pairing loop made 28 tokens in a minute (Jarvis 1, 2026-09-28)
pub const PAIR_EVERY: time::Duration = time::Duration::seconds(30);
/// lastSeenAt is written at most this often
pub const DEVICE_SEEN_GAP: time::Duration = time::Duration::minutes(5);

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Device {
    pub id: String,
    pub name: String,
    pub model: String,
    pub app: String,
    #[serde(rename = "createdAt")]
    pub created_at: GoTime,
    #[serde(rename = "lastSeenAt")]
    pub last_seen_at: GoTime,
    #[serde(rename = "serviceTokenId")]
    pub service_token_id: String,
    /// the service token's client id (not a secret: the JWT's common_name)
    #[serde(rename = "clientId")]
    pub client_id: String,
}

/// what the app sees (no token ids)
pub fn device_view(d: &Device) -> Value {
    json!({"id": d.id, "name": d.name, "model": d.model, "app": d.app, "createdAt": d.created_at, "lastSeenAt": d.last_seen_at})
}

// ---- Cloudflare: Access service tokens ------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct CfServiceToken {
    pub id: String,
    pub client_id: String,
    pub client_secret: String,
}

pub fn cf_call(method: &str, path: &str, body: Option<&Value>) -> Result<Value> {
    let tok = std::env::var("CF_DEVICE_TOKENS_API").unwrap_or_default();
    if tok.is_empty() {
        return Err(anyhow!(
            "the router has no CF_DEVICE_TOKENS_API: it can't mint device tokens"
        ));
    }
    let base = CF_API_BASE
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let mut rb = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()?
        .request(
            reqwest::Method::from_bytes(method.as_bytes())?,
            format!("{base}/accounts/{CF_ACCOUNT}{path}"),
        )
        .header("Authorization", format!("Bearer {tok}"))
        .header("Content-Type", "application/json")
        .header("User-Agent", "jarvis2-router");
    if let Some(b) = body {
        rb = rb.body(jarvis_go::marshal(b));
    }
    let resp = rb.send()?;
    let status = resp.status().as_u16();
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct J {
        success: bool,
        errors: Option<Box<serde_json::value::RawValue>>,
        result: Value,
    }
    let j: J =
        serde_json::from_slice(&crate::util::read_limited(resp, 1 << 20).unwrap_or_default())
            .unwrap_or_default();
    if !j.success {
        let e = j.errors.map(|e| e.get().to_string()).unwrap_or_default();
        return Err(anyhow!(
            "Cloudflare {method} {path}: HTTP {status} {}",
            jarvis_go::fmt::clip_bytes(&e, 200)
        ));
    }
    Ok(j.result)
}

pub type MintFn = fn(&str) -> Result<CfServiceToken>;
pub type DeleteFn = fn(&str) -> Result<()>;

fn mint_device_token_cf(name: &str) -> Result<CfServiceToken> {
    let v = cf_call(
        "POST",
        "/access/service_tokens",
        Some(&json!({"name": name, "duration": "forever"})),
    )?;
    let t: CfServiceToken = serde_json::from_value(v).unwrap_or_default();
    if t.id.is_empty() || t.client_id.is_empty() || t.client_secret.is_empty() {
        return Err(anyhow!("Cloudflare answered no service token"));
    }
    Ok(t)
}

fn delete_device_token_cf(id: &str) -> Result<()> {
    match cf_call(
        "DELETE",
        &format!("/access/service_tokens/{}", jarvis_go::fmt::path_escape(id)),
        None,
    ) {
        Err(e) => {
            let m = format!("{e:#}");
            if m.contains("HTTP 404") || m.to_lowercase().contains("not found") {
                return Ok(()); // already gone
            }
            Err(e)
        }
        Ok(_) => Ok(()),
    }
}

/// tests swap Cloudflare out
pub static MINT_DEVICE_TOKEN: RwLock<MintFn> = RwLock::new(mint_device_token_cf);
pub static DELETE_DEVICE_TOKEN: RwLock<DeleteFn> = RwLock::new(delete_device_token_cf);

// ---- pairing --------------------------------------------------------------------------------------------------

static PAIR_MU: Mutex<()> = Mutex::new(());

pub fn clean_device_text(s: &str, n: usize) -> String {
    s.trim()
        .chars()
        .filter(|c| !((*c as u32) < 0x20 || *c as u32 == 0x7f))
        .take(n)
        .collect()
}

impl Router {
    /// a new device of app (openclaw | paseo) → its id and the service token's credentials
    pub fn pair_device(
        &self,
        name: &str,
        model: &str,
        app: &str,
        now: GoTime,
    ) -> Result<(Device, CfServiceToken)> {
        if device_scheme(app).is_empty() {
            return Err(crate::router::bad(format!("unknown app: {app}")));
        }
        let _g = PAIR_MU.lock().unwrap_or_else(|e| e.into_inner());
        let newest = self.st.do_(|d| {
            d.devices
                .values()
                .map(|x| x.created_at)
                .max()
                .unwrap_or_default()
        });
        if now.sub(&newest) < PAIR_EVERY {
            return Err(ContentErr {
                status: 429,
                msg: "a device was paired less than 30 s ago — try again shortly".into(),
            }
            .into());
        }
        let mut name = clean_device_text(name, 60);
        if name.is_empty() {
            name = "device".into();
        }
        let mint = *MINT_DEVICE_TOKEN.read().unwrap_or_else(|e| e.into_inner());
        let tok = mint(&format!("jarvis2-device {app} {name}"))?;
        let dev = Device {
            id: hex::encode(crate::util::rand_bytes(8)),
            name: name.clone(),
            model: clean_device_text(model, 40),
            app: app.to_string(),
            created_at: now.utc(),
            last_seen_at: now.utc(),
            service_token_id: tok.id.clone(),
            client_id: tok.client_id.clone(),
        };
        self.st.do_(|d| {
            d.devices.insert(dev.id.clone(), dev.clone());
        });
        crate::logf!("[devices] paired {} ({app}, {name})", dev.id);
        Ok((dev, tok))
    }

    pub fn revoke_device(&self, id: &str) -> Result<()> {
        let Some(dev) = self.st.do_(|d| d.devices.get(id).cloned()) else {
            return Ok(()); // already unpaired: what was asked for holds
        };
        let del = *DELETE_DEVICE_TOKEN
            .read()
            .unwrap_or_else(|e| e.into_inner());
        del(&dev.service_token_id)?;
        self.st.do_(|d| {
            d.devices.remove(id);
        });
        crate::logf!("[devices] revoked {id} ({}, {})", dev.app, dev.name);
        Ok(())
    }

    /// the paired device whose service token has this client id (and notes it was seen)
    pub fn device_of_client(&self, client_id: &str, now: GoTime) -> Option<Device> {
        if client_id.is_empty() {
            return None;
        }
        self.st.do_(|d| {
            let mut out = None;
            for x in d.devices.values_mut() {
                if x.client_id == client_id {
                    if now.sub(&x.last_seen_at) > DEVICE_SEEN_GAP {
                        x.last_seen_at = now.utc();
                    }
                    out = Some(x.clone());
                }
            }
            out
        })
    }

    /// Deyao's own Access login, or a paired device's service token; the JWT's audience is the Jarvis 4 app or the
    /// devices' Access app (ACCESS_DEVICES_AUD)
    pub fn require_deyao_or_device(self: &Arc<Self>, f: AppFn) -> AppFn {
        let r = self.clone();
        Arc::new(move |w, req| {
            if !r.cfg.no_access && !r.deyao_or_device(&req.header("Cf-Access-Jwt-Assertion")) {
                write_json(w, 403, &json!({"error": "Access login required"}));
                return;
            }
            f(w, req)
        })
    }

    pub fn deyao_or_device(&self, tok: &str) -> bool {
        for aud in [
            self.cfg.app_aud.clone(),
            std::env::var("ACCESS_DEVICES_AUD").unwrap_or_default(),
        ] {
            if aud.is_empty() {
                continue;
            }
            let Ok(c) = self.access().verify(tok, &aud) else {
                continue;
            };
            return self.admit_claims(&c, GoTime::now());
        }
        false
    }

    /// who called a devices route, for the Inbox (require_deyao_or_device admitted it): hermit-jarvis is the chat (Deyao
    /// typing there), any other service token a paired app, an email login Deyao on the web
    pub fn device_caller(&self, req: &Req) -> crate::inbox::Caller {
        let tok = req.header("Cf-Access-Jwt-Assertion");
        let kind = |k: &str| crate::inbox::Caller {
            kind: k.into(),
            ..Default::default()
        };
        for aud in [
            self.cfg.app_aud.clone(),
            std::env::var("ACCESS_DEVICES_AUD").unwrap_or_default(),
        ] {
            if aud.is_empty() {
                continue;
            }
            let Ok(c) = self.access().verify(&tok, &aud) else {
                continue;
            };
            let h = std::env::var("HERMIT_CLIENT_ID").unwrap_or_default();
            return if !c.email.is_empty() {
                kind("web")
            } else if !h.is_empty() && c.common_name == h {
                kind("chat")
            } else {
                kind("device")
            };
        }
        kind("web") // no Access in front (a test router, NoAccess)
    }

    /// POST /api/remotes {harness, requestId}: a new session of that harness with the defaults (what the app's New
    /// session makes with nothing picked: the harness's stores, model and account, no prompt), proposed into the Inbox
    /// as the app's New session is, so it starts only once Deyao approves it there. requestId makes it idempotent while
    /// the session exists (a repeat answers the same session). → {id, state}; 400 for a harness that is not one of these
    /// apps'.
    pub fn propose_remote(self: &Arc<Self>, w: &mut W, req: &mut Req) {
        #[derive(serde::Deserialize, Default)]
        #[serde(default)]
        struct In {
            harness: String,
            #[serde(rename = "requestId")]
            request_id: String,
        }
        let b = req.read_body(1 << 16);
        let i: In = match serde_json::Deserializer::from_slice(&b)
            .into_iter::<serde_json::Value>()
            .next()
        {
            Some(Ok(v)) => {
                jarvis_go::unmarshal(jarvis_go::marshal(&v).as_bytes()).unwrap_or_default()
            }
            Some(Err(e)) => return write_json(w, 400, &json!({"error": format!("bad JSON: {e}")})),
            None => return write_json(w, 400, &json!({"error": "bad JSON: EOF"})),
        };
        if !crate::remote::remote_harness(&i.harness) {
            return write_json(
                w,
                400,
                &json!({"error": "harness must be openclaw, opencode, paseo-claude, aviary or dsh"}),
            );
        }
        if i.request_id.is_empty() || i.request_id.len() > 200 {
            return write_json(w, 400, &json!({"error": "requestId: 1 to 200 characters"}));
        }
        let mut args = serde_json::Map::new();
        args.insert("harness".into(), json!(i.harness));
        let ns = crate::flows::NewSession {
            harness: i.harness.clone(),
            request_id: i.request_id.clone(),
            origin: Some(crate::inbox::Origin {
                caller: self.device_caller(req),
                call: crate::inbox::ApiCall {
                    method: "POST".into(),
                    path: "/api/remotes".into(),
                    args,
                },
                ..Default::default()
            }),
            ..Default::default()
        };
        let id = match self.create_session(ns) {
            Err(e) => return crate::sessionapi::schedule_err(w, &e),
            Ok(id) => id,
        };
        let state = self.st.do_(|d| {
            d.sessions
                .get(&id)
                .map(|s| s.state.clone())
                .unwrap_or_default()
        });
        write_json(w, 200, &json!({"id": id, "state": state}));
    }

    /// Deyao's email, or no email and a paired device's client id, or hermit-jarvis's (HERMIT_CLIENT_ID: the aviary
    /// harness's hermit, a server in the services tenant; its own Access service token hermit-jarvis, named in
    /// k8s/cluster/router/router.yaml as the health probe's is; aviary/README.md "Its credential")
    pub fn admit_claims(&self, c: &AccessClaims, now: GoTime) -> bool {
        if !c.email.is_empty() {
            return c.email.eq_ignore_ascii_case(&self.cfg.allowed_email);
        }
        if let Ok(h) = std::env::var("HERMIT_CLIENT_ID")
            && !h.is_empty()
            && c.common_name == h
        {
            return true;
        }
        self.device_of_client(&c.common_name, now).is_some()
    }
}

fn values_encode(v: &BTreeMap<&str, String>) -> String {
    v.iter()
        .map(|(k, x)| {
            format!(
                "{}={}",
                jarvis_go::fmt::query_escape(k),
                jarvis_go::fmt::query_escape(x)
            )
        })
        .collect::<Vec<_>>()
        .join("&")
}

pub fn register_devices(reg: &mut Registrar) {
    // the pairing page: Deyao's own login only (app() admits his email, never a service token)
    reg.app("GET /api/devices/pair", |r, w, req| {
        let (state, app_id) = (req.query("state"), req.query("app"));
        if !PAIR_STATE_RE.is_match(&state) {
            return write_json(w, 400, &json!({"error": "missing or malformed state"}));
        }
        let scheme = device_scheme(&app_id);
        if scheme.is_empty() {
            return write_json(w, 400, &json!({"error": format!("unknown app: {app_id}")}));
        }
        let mut back = BTreeMap::from([("state", state.clone())]);
        match r.pair_device(
            &req.query("name"),
            &req.query("model"),
            &app_id,
            GoTime::now(),
        ) {
            Err(e) => {
                let status = if let Some(ce) = e.downcast_ref::<ContentErr>() {
                    ce.status
                } else if e.downcast_ref::<BadReq>().is_some() {
                    400
                } else {
                    500
                };
                back.insert("error", format!("{e:#}"));
                back.insert("status", status.to_string());
            }
            Ok((dev, tok)) => {
                back.insert("id", dev.id);
                back.insert("clientId", tok.client_id);
                back.insert("clientSecret", tok.client_secret);
            }
        }
        w.set_header("Cache-Control", "no-store");
        crate::util::redirect(
            w,
            req,
            &format!("{scheme}://paired?{}", values_encode(&back)),
            302,
        );
    });
    reg.app("GET /api/devices", |r, w, _| {
        let out: Vec<Value> = r.st.do_(|d| {
            let mut list: Vec<&Device> = d.devices.values().collect();
            list.sort_by_key(|a| a.created_at);
            list.into_iter().map(device_view).collect()
        });
        write_json(w, 200, &json!({"devices": out}));
    });
    reg.app("DELETE /api/devices/{id}", |r, w, req| {
        match r.revoke_device(&req.path_value("id")) {
            Err(e) => content_write_err(w, &e),
            Ok(()) => write_json(w, 200, &json!({"ok": true})),
        }
    });
    // the apps: their sessions, and Start for a paused one (a resume on the same image: no phone step)
    let device_route =
        |reg: &mut Registrar, pattern: &str, f: fn(&Arc<Router>, &mut W, &mut Req)| {
            reg.app_patterns.insert(pattern.to_string(), true); // Deyao's too (apicalls.rs)
            let r = reg.r.clone();
            let r2 = r.clone();
            let h = r.require_deyao_or_device(Arc::new(move |w, req| f(&r2, w, req)));
            reg.handle(pattern, h);
        };
    device_route(reg, "GET /api/remotes", |r, w, req| r.remotes(w, req));
    // a new session of a harness with the defaults, proposed into the Inbox like the app's New session (hermit-jarvis,
    // for a new conversation in the chat: Deyao, 2026-11-18); on the same path, so the same Access app
    device_route(reg, "POST /api/remotes", |r, w, req| {
        r.propose_remote(w, req)
    });
    // whose machine signed a request for a service outside Jarvis 4 (machinesig.rs; hermit-jarvis)
    device_route(reg, "POST /api/machine-signatures/verify", |r, w, req| {
        r.verify_machine_signature(w, req)
    });
    // the next fire of an aviary session's chat schedules (schedule.rs ChatSchedule; hermit-jarvis), on the devices'
    // Access app as the signature check is: hermit-jarvis's service token reaches only its paths
    device_route(reg, "PUT /api/sessions/{id}/chat-schedule", |r, w, req| {
        r.put_chat_schedule(w, req)
    });
    device_route(reg, "POST /api/sessions/{id}/start", |r, w, req| {
        match r.resume_with_prompt(&req.path_value("id"), false, "") {
            Err(e) => crate::schedule::schedule_err(w, &e),
            Ok(()) => write_json(w, 202, &json!({"ok": true})),
        }
    });
}
