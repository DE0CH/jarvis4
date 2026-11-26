//! Remote access to a Paseo (OpenCode, Claude Code) or OpenClaw session (Jarvis 1's remoteInfo,
//! /api/sessions/:id/remote and /api/remotes). These harnesses publish their front end through the session's own
//! cf-tunnel origin https://<session id>-s.deyaochen.com/ (behind Cloudflare Access, Deyao's login):
//!   opencode, paseo-claude  the Paseo daemon's web UI; the daemon also prints a pairing offer for the Paseo app (its
//!             relay is end-to-end encrypted, the link IS the secret)
//!   openclaw  the OpenClaw gateway: Control UI over HTTPS and the app's WebSocket on the same origin; the gateway
//!             token (~/.openclaw/jarvis-remote.json, written by harness-openclaw.sh) is the secret
//!   dsh       DeepSeek Harness web (harness-dsh.sh): its web UI on the same origin; Cloudflare Access is its only
//!             gate (dsh-front.js hands dsh's launch token to a request Access admitted; nothing for the router to read)
//!   aviary    no front end of its own: its conversation is in Jarvis 4's chat web app at chat.deyaochen.com (aviary's
//!             pigeon and magpie, DE0CH/deyao-ai), so its remote is that conversation's page there (aviary_conv_url:
//!             the id from the machine's status, nothing to read)
//! The router reads those secrets on demand through a grant for holder "remote" (grants.rs): its own key, so Deyao can
//! let the router read a session's remote without giving it the terminal. Never in /api/state.
//!
//! The tunnel agent on the machine needs an Access service token: the store `tunnel` (CF_ACCESS_CLIENT_ID/SECRET = the
//! token jarvis2-tunnel, which the cf-tunnel Worker confines to registering agents for Jarvis 4 session ids), brought
//! by these harnesses through the policy. The Worker also wants a proof for that one id, which the router
//! (JARVIS2_TUNNEL_KEY) hands each machine for its own session id only (GET /m/tunnel-proof → TUNNEL_AGENT_SECRET, sent
//! by agent.js as x-agent-secret), so one session can't take over another's tunnel id: proof = hex
//! HMAC-SHA256(key, "jarvis2-tunnel:" + id).
//!
//! GET /api/remotes also admits Deyao's paired OpenClaw and Paseo apps and hermit-jarvis (devices.rs).

use crate::harness::paseo_harness;
use crate::http::Registrar;
use crate::registry::Registry;
use crate::router::Router;
use crate::types::Session;
use hmac::{Hmac, Mac};
use jarvis_nethttp::{Req, W, write_error, write_json};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::Sha256;
use std::collections::BTreeMap;
use std::sync::{Arc, LazyLock, Mutex, RwLock};
use std::time::{Duration, Instant};

pub const REMOTE_HOLDER: &str = "remote";

pub fn remote_harness(h: &str) -> bool {
    matches!(
        h,
        "opencode" | "openclaw" | "paseo-claude" | "aviary" | "dsh"
    )
}

/// A dsh session's link is the persistent dsh web UI (DE0CH/deyao-ai dsh-web), which reaches the session's origin
/// itself with its own service token and stays up while the machine is paused
pub fn dsh_web_url(id: &str) -> String {
    format!("https://dsh.deyaochen.com/s/{id}/")
}

/// the remote is only the session's origin, Cloudflare Access its gate (nothing to read)
fn web_origin_harness(h: &str) -> bool {
    h == "dsh"
}

/// Jarvis 4's chat web app, where an aviary session's conversation is (DE0CH/aviary jarvis/hermit/README.md)
pub const CHAT_URL: &str = "https://chat.deyaochen.com/";

/// the session's own conversation in the chat. The machine reports its id (the gateway's conversationId, the
/// registry's sessionId); pigeon names its one host srv_conversations and a conversation's workspace wks_<id>
/// (DE0CH/aviary crates/pigeon/src/paseo/mapping.rs), the app's page for it is /h/<host>/workspace/<workspace>. Before
/// the machine names a conversation (the gateway's placeholder "aviary"), the chat's front page.
pub fn aviary_conv_url(reg: Option<&Registry>) -> String {
    match reg.and_then(|g| uuid::Uuid::parse_str(&g.session_id).ok()) {
        Some(id) => format!(
            "{CHAT_URL}h/srv_conversations/workspace/wks_{}",
            id.hyphenated()
        ),
        None => CHAT_URL.into(),
    }
}

/// the commands the remote holder runs (bash -lc as the session user)
const PASEO_PAIR_CMD: &str = r#"export PATH="$HOME/.local/bin:/usr/local/bin:$PATH" PASEO_HOME="$HOME/.paseo"; paseo daemon pair --json"#;
const OPENCLAW_REMOTE: &str = r#"cat "$HOME/.openclaw/jarvis-remote.json""#;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct RemoteInfo {
    #[serde(rename = "webUrl")]
    pub web_url: String,
    pub harness: String,
    /// a Paseo harness
    #[serde(rename = "pairUrl", skip_serializing_if = "String::is_empty")]
    pub pair_url: String,
    /// a Paseo harness
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub relay: bool,
    /// openclaw: the gateway's WebSocket
    #[serde(skip_serializing_if = "String::is_empty")]
    pub url: String,
    /// openclaw: the gateway token
    #[serde(skip_serializing_if = "String::is_empty")]
    pub token: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub error: String,
    /// the machine refused the remote holder; a phone grant or standing rule for "remote" opens it
    #[serde(rename = "needsGrant", skip_serializing_if = "String::is_empty")]
    pub needs_grant: String,
}

pub fn tunnel_host(id: &str) -> String {
    format!(
        "{id}{}",
        crate::router::env("SESSION_TUNNEL_SUFFIX", "-s.deyaochen.com")
    )
}

/// a paseo offer costs a ~200 MB node run on the machine: one per machine per minute
static REMOTE_CACHE: LazyLock<Mutex<BTreeMap<String, (Instant, RemoteInfo)>>> =
    LazyLock::new(Default::default);

/// what the holder's command printed → the remote of that harness
pub fn parse_remote(harness: &str, id: &str, stdout: &str) -> RemoteInfo {
    let web = format!("https://{}/", tunnel_host(id));
    let mut info = RemoteInfo {
        web_url: web.clone(),
        harness: harness.into(),
        ..Default::default()
    };
    if paseo_harness(harness) {
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct Pair {
            url: String,
            #[serde(rename = "relayEnabled")]
            relay_enabled: bool,
        }
        let pair = stdout
            .find('{')
            .and_then(|i| jarvis_go::unmarshal::<Pair>(&stdout.as_bytes()[i..]).ok());
        match pair.filter(|p| !p.url.is_empty()) {
            None => info.error = "the Paseo daemon is not up yet — try again in a moment".into(),
            Some(p) => {
                info.pair_url = p.url;
                info.relay = p.relay_enabled;
            }
        }
        return info;
    }
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Rec {
        token: String,
    }
    match jarvis_go::unmarshal::<Rec>(stdout.trim().as_bytes())
        .ok()
        .filter(|r| !r.token.is_empty())
    {
        None => info.error = "the OpenClaw gateway is not up yet — try again in a moment".into(),
        Some(rec) => {
            info.web_url = format!("{web}#token={}", jarvis_go::fmt::query_escape(&rec.token));
            info.url = format!("wss://{}", tunnel_host(id));
            info.token = rec.token;
        }
    }
    info
}

/// tests: the key instead of JARVIS2_TUNNEL_KEY
pub static TUNNEL_KEY: RwLock<Option<String>> = RwLock::new(None);

/// the key the tunnel proofs are made with (JARVIS2_TUNNEL_KEY)
pub fn tunnel_key() -> String {
    TUNNEL_KEY
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
        .unwrap_or_else(|| std::env::var("JARVIS2_TUNNEL_KEY").unwrap_or_default())
}

pub fn tunnel_proof(key: &str, id: &str) -> String {
    if key.is_empty() {
        return String::new();
    }
    let Ok(mut h) = Hmac::<Sha256>::new_from_slice(key.as_bytes()) else {
        return String::new();
    };
    h.update(format!("jarvis2-tunnel:{id}").as_bytes());
    hex::encode(h.finalize().into_bytes())
}

impl Router {
    /// a started Paseo/OpenClaw session's remote, read through the remote holder (a dsh or aviary session's is only an
    /// address: nothing to read)
    pub fn remote_info(&self, s: &Session) -> RemoteInfo {
        if s.harness == "aviary" {
            let reg = self.st.do_(|d| {
                d.sessions
                    .get(&s.id)
                    .and_then(|x| x.live.as_ref())
                    .and_then(|l| l.reg.clone())
            });
            return RemoteInfo {
                web_url: aviary_conv_url(reg.as_ref()),
                harness: s.harness.clone(),
                ..Default::default()
            };
        }
        if s.harness == "dsh" {
            return RemoteInfo {
                web_url: dsh_web_url(&s.id),
                harness: s.harness.clone(),
                ..Default::default()
            };
        }
        if web_origin_harness(&s.harness) {
            return RemoteInfo {
                web_url: format!("https://{}/", tunnel_host(&s.id)),
                harness: s.harness.clone(),
                ..Default::default()
            };
        }
        if let Some((at, info)) = REMOTE_CACHE
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&s.machine_id)
            && at.elapsed() < Duration::from_secs(60)
        {
            return info.clone();
        }
        let (cmd, wait) = if paseo_harness(&s.harness) {
            (PASEO_PAIR_CMD, Duration::from_secs(30))
        } else {
            (OPENCLAW_REMOTE, Duration::from_secs(15))
        };
        let res = match self.exec(&s.id, REMOTE_HOLDER, cmd, wait) {
            Err(e) => {
                let needs = if crate::peer::is_grant_refusal(Some(&e)) {
                    REMOTE_HOLDER.to_string()
                } else {
                    String::new()
                };
                return RemoteInfo {
                    web_url: format!("https://{}/", tunnel_host(&s.id)),
                    harness: s.harness.clone(),
                    error: format!("{e:#}"),
                    needs_grant: needs,
                    ..Default::default()
                };
            }
            Ok(res) => res,
        };
        let info = parse_remote(&s.harness, &s.id, &res.stdout);
        if info.error.is_empty() {
            REMOTE_CACHE
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(s.machine_id.clone(), (Instant::now(), info.clone()));
        }
        info
    }

    /// GET /api/remotes?harness=openclaw|opencode|paseo-claude|paseo|aviary|dsh → {sessions: [{id, title, state, model,
    /// harness, account, + url, token, webUrl (openclaw) | pairUrl (a Paseo harness) | webUrl (aviary, dsh) — only on a started
    /// session whose front end is up, else error}]}. harness=paseo: every session a Paseo daemon fronts (opencode and
    /// paseo-claude), what the Paseo app lists; harness=aviary: what hermit-jarvis lists (paused ones too, and one whose
    /// resume waits for Deyao's approval, as paused; a new one waiting for approval as approval).
    pub fn remotes(self: &Arc<Self>, w: &mut W, req: &mut Req) {
        let harness = req.query("harness");
        if !remote_harness(&harness) && harness != "paseo" {
            return write_error(
                w,
                400,
                "harness must be openclaw, opencode, paseo-claude, paseo, aviary or dsh",
            );
        }
        let matches = |h: &str| h == harness || (harness == "paseo" && paseo_harness(h));
        let mut all: Vec<Session> = self.st.do_(|d| {
            d.sessions
                .values()
                // "approval" with no pause behind it: a new session waiting for Deyao's approval, listed as "approval"
                // (hermit-jarvis proposes one for a new conversation in the chat and holds its first message until it is
                // up: POST /api/remotes). One that was paused and waits for its resume's approval (a restart onto a newer
                // image) is listed as paused. A session missing here is a destroyed (or denied) one to hermit-jarvis,
                // which then ends its conversation
                .filter(|s| matches(&s.harness) && s.state != "destroying")
                .map(|s| {
                    let mut x = s.clone();
                    if x.state == "approval" && x.paused_at.is_some() {
                        x.state = "paused".into();
                    }
                    x
                })
                .collect()
        });
        all.sort_by_key(|a| std::cmp::Reverse(a.created));
        let out: Vec<Value> = std::thread::scope(|sc| {
            let hs: Vec<_> = all
                .iter()
                .map(|s| {
                    let harness = harness.as_str();
                    sc.spawn(move || {
                        let mut o = Map::new();
                        o.insert("id".into(), json!(s.id));
                        o.insert("title".into(), json!(crate::titles::session_title(s)));
                        o.insert("state".into(), json!(s.state));
                        o.insert("model".into(), json!(s.model));
                        o.insert("harness".into(), json!(s.harness));
                        o.insert("account".into(), json!(s.claude_account));
                        if s.state != "started" || s.machine_id.is_empty() {
                            return Value::Object(o);
                        }
                        let info = self.remote_info(s);
                        if !info.error.is_empty() {
                            o.insert("error".into(), json!(info.error));
                            if !info.needs_grant.is_empty() {
                                o.insert("needsGrant".into(), json!(info.needs_grant));
                            }
                            match harness {
                                "openclaw" => {
                                    o.insert("url".into(), Value::Null);
                                    o.insert("token".into(), Value::Null);
                                }
                                "aviary" | "dsh" => {
                                    o.insert("webUrl".into(), Value::Null);
                                }
                                _ => {
                                    o.insert("pairUrl".into(), Value::Null);
                                }
                            }
                            return Value::Object(o);
                        }
                        match harness {
                            "openclaw" => {
                                o.insert("url".into(), json!(info.url));
                                o.insert("token".into(), json!(info.token));
                                o.insert("webUrl".into(), json!(info.web_url));
                            }
                            "aviary" | "dsh" => {
                                o.insert("webUrl".into(), json!(info.web_url));
                            }
                            _ => {
                                o.insert("pairUrl".into(), json!(info.pair_url));
                            }
                        }
                        Value::Object(o)
                    })
                })
                .collect();
            hs.into_iter()
                .map(|h| h.join().unwrap_or(Value::Null))
                .collect()
        });
        w.set_header("Cache-Control", "no-store");
        // `accounts`: the Claude accounts a session's model can run on, for a front end that offers them beside the
        // models (hermit-jarvis: the chat's model menu, one entry "Opus 5.5 · chendeyao-uk" per account); the other
        // apps ignore it
        write_json(
            w,
            200,
            &json!({"sessions": out, "accounts": self.accounts().chat_rows()}),
        );
    }
}

pub fn register_remote(reg: &mut Registrar) {
    reg.app("GET /api/sessions/{id}/remote", |r, w, req| {
        let id = req.path_value("id");
        let Some(s) = r.st.do_(|d| d.sessions.get(&id).cloned()) else {
            return write_error(w, 404, "no such session");
        };
        if !remote_harness(&s.harness) {
            return write_error(
                w,
                400,
                "only Paseo, OpenClaw, dsh and aviary sessions have a remote here — a Claude session is in the Claude app",
            );
        }
        if s.state != "started" || s.machine_id.is_empty() {
            return write_error(w, 409, &format!("session is {}", s.state));
        }
        let info = r.remote_info(&s);
        w.set_header("Cache-Control", "no-store");
        let status = if !info.needs_grant.is_empty() {
            403
        } else if !info.error.is_empty() {
            503
        } else {
            200
        };
        write_json(w, status, &info);
    });
    // GET /api/remotes: devices.rs (Deyao, or a paired OpenClaw/Paseo app)
    // the machine's proof for registering its own session's tunnel id (boot: TUNNEL_AGENT_SECRET)
    reg.m("GET /m/tunnel-proof", |r, w, _, machine, _| {
        let sid = match r.machine_session(machine) {
            Ok(s) => s,
            Err(e) => return write_error(w, 403, &format!("{e:#}")),
        };
        let p = tunnel_proof(&tunnel_key(), &sid);
        if p.is_empty() {
            return write_error(w, 404, "the router has no JARVIS2_TUNNEL_KEY");
        }
        write_json(w, 200, &json!({"proof": p, "id": sid}));
    });
}
