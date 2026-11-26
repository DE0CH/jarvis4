//! The harnesses and their models (Jarvis 1's MODELS / HARNESSES in selfhost/jarvis/server.js). A model belongs to one
//! harness: the New-session request carries both; the harness is signed (the cert's options, SESSION_HARNESS on the
//! machine), the model is not (SESSION_MODEL in the machine env, read by the harness script):
//!
//! ```text
//! claude        Claude Code on the Claude subscription (`claude --model <id>`), the Claude app
//! opencode      OpenCode on OpenRouter (`openrouter/<slug>`), driven by a Paseo daemon: the Paseo app + web UI
//! openclaw      claw-code inside an OpenClaw gateway (`openclaw/<Claude model id>`), Claude subscription: the OpenClaw
//!               app + Control UI
//! paseo-claude  Claude Code driven by a Paseo daemon (`paseo/<Claude model id>`), Claude subscription through
//!               api-proxy.js (so an account switch needs no restart, accountswap.rs): the Paseo app + web UI
//! aviary        Claude Code driven by DE0CH/aviary's supervisor (`aviary/<model id>`), the same supervisor YYC AI's
//!               sandboxes run, with Jarvis 4's own pigeon, magpie and hermit (DE0CH/aviary jarvis/hermit/README.md); Claude
//!               subscription, or GLM 5.3 on OpenRouter (z.ai's own host), through the machine's aviary-gateway: the
//!               chat web app at chat.deyaochen.com
//! dsh           DeepSeek Harness (Deyao's fork DE0CH/deepseek-harness) on OpenRouter, routed only to DeepSeek's own
//!               endpoint (`dsh/<OpenRouter slug>`; only the dated slugs have one): its web UI on the session's origin
//! ```
//!
//! The OpenCode list is Jarvis 1's curated one (every slug checked for tool calling on OpenRouter; prices are $/M
//! tokens in/out at curation).

use crate::http::Registrar;
use crate::router::Router;
use anyhow::{Result, anyhow};
use jarvis_nethttp::write_json;
use serde::Serialize;
use serde_json::json;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ModelChoice {
    pub id: &'static str,
    pub label: &'static str,
    pub harness: &'static str,
}

const fn m(id: &'static str, label: &'static str, harness: &'static str) -> ModelChoice {
    ModelChoice { id, label, harness }
}

pub const MODEL_CATALOG: &[ModelChoice] = &[
    m("claude-opus-5-5", "Opus 5.5", "claude"),
    m("claude-fable-5-2", "Fable 5.2", "claude"),
    m(
        "openrouter/z-ai/glm-5.3",
        "GLM 5.3 — $0.90 / $2.82",
        "opencode",
    ),
    m(
        "openrouter/moonshotai/kimi-k3",
        "Kimi K3 — $1.70 / $8.50",
        "opencode",
    ),
    m(
        "openrouter/deepseek/deepseek-v4-pro-0813",
        "DeepSeek V4 Pro — $0.66 / $1.98",
        "opencode",
    ),
    m(
        "openrouter/deepseek/deepseek-v4.1-flash",
        "DeepSeek V4.1 Flash — $0.15 / $0.60",
        "opencode",
    ),
    m(
        "openrouter/qwen/qwen3-coder-next",
        "Qwen3 Coder Next — $0.12 / $0.80",
        "opencode",
    ),
    m(
        "openrouter/minimax/minimax-m3",
        "MiniMax M3 — $0.30 / $1.20",
        "opencode",
    ),
    m("openclaw/claude-opus-5-5", "Opus 5.5", "openclaw"),
    m("openclaw/claude-fable-5-2", "Fable 5.2", "openclaw"),
    m("paseo/claude-opus-5-5", "Opus 5.5", "paseo-claude"),
    m("paseo/claude-fable-5-2", "Fable 5.2", "paseo-claude"),
    m("aviary/claude-opus-5-5", "Opus 5.5", "aviary"),
    m("aviary/claude-fable-5-2", "Fable 5.2", "aviary"),
    m("aviary/z-ai/glm-5.3", "GLM 5.3 — $1.40 / $4.40", "aviary"),
    m(
        "aviary/deepseek/deepseek-v4.1-flash-1017",
        "DeepSeek V4.1 Flash — $0.30 / $1.20",
        "aviary",
    ),
    m(
        "aviary/moonshotai/kimi-k3.1-pro",
        "Kimi K3.1 Pro — $2.00 / $10.00",
        "aviary",
    ),
    m(
        "dsh/deepseek/deepseek-v4-pro-0813",
        "DeepSeek V4 Pro — $0.66 / $1.98",
        "dsh",
    ),
    m(
        "dsh/deepseek/deepseek-v4.1-flash-1017",
        "DeepSeek V4.1 Flash — $0.15 / $0.60",
        "dsh",
    ),
];

/// the first model of each harness is its default: Opus 5.5 for the Claude ones (Deyao, 2026-11-17)
pub const HARNESS_INFO: &[(&str, &str, &str)] = &[
    ("claude", "Claude Code", "Claude subscription · Claude app"),
    ("opencode", "OpenCode · OpenRouter", "Paseo app + web UI"),
    (
        "openclaw",
        "claw-code · OpenClaw",
        "Claude subscription · OpenClaw app + Control UI",
    ),
    (
        "paseo-claude",
        "Claude Code · Paseo",
        "Claude subscription · Paseo app + web UI",
    ),
    (
        "aviary",
        "Claude Code · aviary",
        "Claude subscription or OpenRouter · chat.deyaochen.com",
    ),
    (
        "dsh",
        "DeepSeek Harness · OpenRouter",
        "DeepSeek V4 on DeepSeek's endpoint · web UI",
    ),
];

/// a Paseo daemon fronts the session (its app pairs with the daemon, its web UI is the session's tunnel origin):
/// OpenCode on OpenRouter, or Claude Code
pub fn paseo_harness(h: &str) -> bool {
    h == "opencode" || h == "paseo-claude"
}

/// Claude Code reaches the API only through api-proxy.js, which sends the session's current Claude login per request
/// (session-image harness-paseo-claude.sh; harness-aviary.sh's aviary-gateway): a running session switches accounts
/// with no restart
pub fn proxy_login_harness(h: &str) -> bool {
    h == "paseo-claude" || h == "aviary"
}

pub fn default_model(harness: &str) -> &'static str {
    MODEL_CATALOG
        .iter()
        .find(|m| m.harness == harness)
        .map(|m| m.id)
        .unwrap_or("")
}

/// the model a new session of this harness runs. Empty, or another harness's model (the iPhone shell picks the
/// harness after the form picked a model), → the harness's default; an id that isn't in the list is refused, as in
/// Jarvis 1, so a typo can't start a session on a model that doesn't exist.
pub fn session_model(harness: &str, model: &str) -> Result<String> {
    if model.is_empty() {
        return Ok(default_model(harness).into());
    }
    match MODEL_CATALOG.iter().find(|m| m.id == model) {
        Some(m) if m.harness != harness => Ok(default_model(harness).into()),
        Some(_) => Ok(model.into()),
        None => Err(anyhow!(
            "unknown model {} (GET /api/models lists them)",
            jarvis_go::fmt::go_quote(model)
        )),
    }
}

impl Router {
    /// the harness of a new session that names none, and the one New session opens on: aviary (Deyao, 2026-11-13)
    /// where the policy offers it, else Claude Code
    pub fn default_harness(&self) -> &'static str {
        if self.policy.harnesses.contains_key("aviary") {
            "aviary"
        } else {
            "claude"
        }
    }
}

/// GET /api/models[?harness=x] → {models: [{id, label, harness}], default, defaults: {harness: id}, harnesses}
pub fn register_harnesses(reg: &mut Registrar) {
    reg.app("GET /api/models", |r, w, req| {
        let h = req.query("harness");
        let offered =
            |name: &str| r.policy.harnesses.is_empty() || r.policy.harnesses.contains_key(name);
        let out: Vec<&ModelChoice> = MODEL_CATALOG
            .iter()
            .filter(|m| offered(m.harness)) // a harness the policy doesn't offer
            .filter(|m| h.is_empty() || m.harness == h)
            .collect();
        let mut defaults = BTreeMap::new();
        let mut harnesses = BTreeMap::new();
        for (name, label, detail) in HARNESS_INFO {
            if offered(name) {
                defaults.insert(*name, default_model(name));
                harnesses.insert(*name, json!({"label": label, "detail": detail}));
            }
        }
        let def = if h.is_empty() {
            default_model(r.default_harness())
        } else {
            default_model(&h)
        };
        write_json(
            w,
            200,
            &json!({"models": out, "default": def, "defaults": defaults, "harnesses": harnesses,
                "defaultHarness": r.default_harness()}),
        );
    });
}
