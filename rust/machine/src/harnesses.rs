//! The harnesses a session can run (the cert's options.harness; router/harness.go has the list Deyao picks from):
//!   claude        the `claude --remote-control` host in tmux (harness-claude.sh); Jarvis's messages go in through
//!                 its channel
//!   opencode      OpenCode driven by a Paseo daemon (harness-opencode.sh)
//!   openclaw      claw-code inside an OpenClaw gateway (harness-openclaw.sh)
//!   paseo-claude  Claude Code driven by a Paseo daemon, its Claude calls through api-proxy.js with the session's
//!                 current Claude login
//!   aviary        Claude Code driven by DE0CH/aviary's supervisor, its Claude calls through the machine's
//!                 aviary-gateway with the session's current Claude login (aviary/README.md)
//!   dsh           DeepSeek Harness web: its own agent loop on OpenRouter, its web UI
//! The last five take prompts through /usr/local/bin/harness-send and publish their own front end through the
//! session's tunnel (so they take CF_ACCESS_* as "publish it").

/// the harness takes Jarvis's messages through harness-send (not a Claude host's channel)
pub fn via_harness_send(h: &str) -> bool {
    matches!(
        h,
        "opencode" | "openclaw" | "paseo-claude" | "aviary" | "dsh"
    )
}

/// Claude Code is the agent, so its hooks (the worker count, workers.rs) run
pub fn runs_claude_code(h: &str) -> bool {
    matches!(h, "" | "claude" | "paseo-claude" | "aviary")
}

/// Claude Code holds no login of its own and the proxy sends ~/.claude/.credentials.json's access token per request,
/// so a new account's pair takes effect at the next request with nothing restarted (claudelogin.rs)
pub fn proxy_login(h: &str) -> bool {
    matches!(h, "paseo-claude" | "aviary")
}

/// this machine's harness from its cert ("" when it can't be read)
pub fn cert_harness() -> String {
    crate::grants::current_cert()
        .map(|c| c.options.harness)
        .unwrap_or_default()
}
