package main

// The harnesses a session can run (the cert's options.harness; router/harness.go has the list Deyao picks from):
//   claude        the `claude --remote-control` host in tmux (harness-claude.sh); Jarvis's messages go in through
//                 its channel
//   opencode      OpenCode driven by a Paseo daemon (harness-opencode.sh)
//   openclaw      claw-code inside an OpenClaw gateway (harness-openclaw.sh)
//   paseo-claude  Claude Code driven by a Paseo daemon (harness-paseo-claude.sh), its Claude calls through
//                 api-proxy.js with the session's current Claude login
//   cloudcli      Claude Code driven by the CloudCLI fork (harness-cloudcli.sh), through api-proxy.js the same way
// The last four take prompts through /usr/local/bin/harness-send and publish their own front end through the
// session's tunnel (so they take CF_ACCESS_* as "publish it").

// viaHarnessSend: the harness takes Jarvis's messages through harness-send (not a Claude host's channel)
func viaHarnessSend(h string) bool {
	return h == "opencode" || h == "openclaw" || h == "paseo-claude" || h == "cloudcli"
}

// runsClaudeCode: Claude Code is the agent, so its hooks (the worker count, workers.go) run
func runsClaudeCode(h string) bool {
	return h == "" || h == "claude" || h == "paseo-claude" || h == "cloudcli"
}

// proxyLogin: Claude Code holds no login of its own (a placeholder token, no refresh token) and api-proxy.js sends
// ~/.claude/.credentials.json's access token per request, so a new account's pair takes effect at the next request
// with nothing restarted (claudelogin.go)
func proxyLogin(h string) bool { return h == "paseo-claude" || h == "cloudcli" }

// certHarness: this machine's harness from its cert ("" when it can't be read)
var certHarness = func() string {
	c, err := currentCert()
	if err != nil {
		return ""
	}
	return c.Options.Harness
}
