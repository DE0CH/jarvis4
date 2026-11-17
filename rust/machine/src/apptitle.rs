//! The Claude app's own title of this session: the conversation's Remote Control entry on claude.ai, which follows
//! Deyao's renames in the app. The machine reads it with its own Claude login and sends only the title with its status
//! report (status.rs), so no token leaves it. The entry is the registry's bridgeSessionId (session_<key>); the API is
//! GET /v1/code/sessions/cse_<key>, else the list.

use crate::{gojson, paths};
use anyhow::{Result, anyhow, bail};
use serde::Deserialize;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const CODE_SESSIONS_URL: &str = "https://api.anthropic.com/v1/code/sessions";
const APP_TITLE_TTL: Duration = Duration::from_secs(60);

fn strip_bridge(b: &str) -> String {
    let b = b.strip_prefix("cse_").unwrap_or(b);
    b.strip_prefix("session_").unwrap_or(b).to_string()
}

/// the Remote Control entry of claude's host process (the registry entry with a bridgeSessionId, oldest first), without
/// its "session_"/"cse_" prefix
pub fn host_bridge() -> String {
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct E {
        #[serde(rename = "bridgeSessionId")]
        bridge: String,
        #[serde(rename = "startedAt")]
        started_at: i64,
    }
    let dir = std::path::Path::new(paths::CLAUDE_HOME).join(".claude/sessions");
    let mut es: Vec<E> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
        .filter_map(|e| std::fs::read(e.path()).ok())
        .filter_map(|b| gojson::unmarshal::<E>(&b).ok())
        .filter(|e| !e.bridge.is_empty())
        .collect();
    es.sort_by_key(|e| e.started_at);
    es.first()
        .map(|e| strip_bridge(&e.bridge))
        .unwrap_or_default()
}

/// the session's Claude OAuth access token (never logged or sent anywhere but Anthropic)
pub fn claude_access_token() -> String {
    let p = std::path::Path::new(paths::CLAUDE_HOME).join(".claude/.credentials.json");
    std::fs::read(p)
        .map(|b| crate::claudelogin::access_token(&b))
        .unwrap_or_default()
}

fn code_sessions_get<T: serde::de::DeserializeOwned>(url: &str, tok: &str) -> (u16, Result<T>) {
    let auth = format!("Bearer {tok}");
    let r = crate::https::get(
        url,
        &[
            ("Authorization", &auth),
            ("anthropic-version", "2023-06-01"),
            ("anthropic-beta", "ccr-byoc-2025-07-29,oauth-2025-04-20"),
            ("Accept", "application/json"),
            ("User-Agent", "jarvis-machine/1"),
        ],
        Duration::from_secs(15),
        4 << 20,
    );
    match r {
        Err(e) => (0, Err(e)),
        Ok((200, b)) => (200, gojson::unmarshal(&b).map_err(|e| anyhow!("{e}"))),
        Ok((st, _)) => (st, Err(anyhow!("code sessions: HTTP {st}"))),
    }
}

/// one entry of /v1/code/sessions
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct CodeSession {
    pub id: String,
    pub title: String,
    /// connected | disconnected: what the Claude app shows
    pub connection_status: String,
}

/// GET /v1/code/sessions/cse_<key>, whose entry comes inside "response_shape" (seen 2026-10-25), or bare as before
pub fn fetch_code_session(key: &str, tok: &str) -> (CodeSession, u16, Result<()>) {
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct R {
        id: String,
        title: String,
        connection_status: String,
        response_shape: Option<CodeSession>,
    }
    let (st, r) = code_sessions_get::<R>(&format!("{CODE_SESSIONS_URL}/cse_{key}"), tok);
    match r {
        Ok(r) => {
            let s = r.response_shape.unwrap_or(CodeSession {
                id: r.id,
                title: r.title,
                connection_status: r.connection_status,
            });
            (s, st, Ok(()))
        }
        Err(e) => (CodeSession::default(), st, Err(e)),
    }
}

/// the entry's title on claude.ai ("" when it has none yet)
pub fn fetch_app_title(key: &str, tok: &str) -> Result<String> {
    let (one, st, r) = fetch_code_session(key, tok);
    match r {
        Ok(()) => return Ok(one.title),
        Err(e) if st != 404 && st != 405 => return Err(e),
        Err(_) => {}
    }
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct List {
        data: Vec<CodeSession>,
    }
    let (_, list) = code_sessions_get::<List>(&format!("{CODE_SESSIONS_URL}?limit=100"), tok);
    for s in list?.data {
        if strip_bridge(&s.id) == key {
            return Ok(s.title);
        }
    }
    bail!("the session's Remote Control entry isn't listed")
}

/// the title, read at most once a minute; a failed read keeps the last title of the same entry
#[derive(Default)]
pub struct AppTitler {
    inner: Mutex<(String, String, Option<Instant>)>,
}

impl AppTitler {
    pub fn current(&self) -> String {
        let key = host_bridge();
        if key.is_empty() {
            return String::new();
        }
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if key == g.0 && g.2.is_some_and(|a| a.elapsed() < APP_TITLE_TTL) {
            return g.1.clone();
        }
        if key != g.0 {
            *g = (key.clone(), String::new(), None);
        }
        g.2 = Some(Instant::now());
        let tok = claude_access_token();
        if tok.is_empty() {
            return g.1.clone();
        }
        if let Ok(t) = fetch_app_title(&key, &tok)
            && !t.trim().is_empty()
        {
            g.1 = t.trim().to_string();
        }
        g.1.clone()
    }
}
