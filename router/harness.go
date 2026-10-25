package main

// The harnesses and their models (Jarvis 1's MODELS / HARNESSES in selfhost/jarvis/server.js). A model belongs to
// one harness: the New-session request carries both; the harness is signed (the cert's options, SESSION_HARNESS on
// the machine), the model is not (SESSION_MODEL in the machine env, read by the harness script):
//   claude    Claude Code on the Claude subscription (`claude --model <id>`), the Claude app
//   opencode  OpenCode on OpenRouter (`openrouter/<slug>`), driven by a Paseo daemon: the Paseo app + web UI
//   openclaw  claw-code inside an OpenClaw gateway (`openclaw/<Claude model id>`), Claude subscription: the
//             OpenClaw app + Control UI
//   paseo-claude  Claude Code driven by a Paseo daemon (`paseo/<Claude model id>`), Claude subscription through
//             api-proxy.js (so an account switch needs no restart, accountswap.go): the Paseo app + web UI
//   cloudcli  Claude Code driven by Deyao's CloudCLI fork (`cloudcli/<Claude model id>`), Claude subscription through
//             api-proxy.js like paseo-claude: the Jarvis 4 Chat app (the YYC AI app's code) + the chat web UI
//   dsh       DeepSeek Harness (Deyao's fork DE0CH/deepseek-harness) on OpenRouter, routed only to DeepSeek's own
//             endpoint (`dsh/<OpenRouter slug>`; only the dated slugs have one): its web UI on the session's origin
// The OpenCode list is Jarvis 1's curated one (every slug checked for tool calling on OpenRouter; prices are $/M
// tokens in/out at curation).

import (
	"fmt"
	"net/http"
)

type ModelChoice struct {
	ID      string `json:"id"`
	Label   string `json:"label"`
	Harness string `json:"harness"`
}

var modelCatalog = []ModelChoice{
	{"claude-opus-5-5", "Opus 5.5", "claude"},
	{"claude-fable-5-1", "Fable 5.1", "claude"},
	{"openrouter/z-ai/glm-5.3", "GLM 5.3 — $0.90 / $2.82", "opencode"},
	{"openrouter/moonshotai/kimi-k3", "Kimi K3 — $1.70 / $8.50", "opencode"},
	{"openrouter/deepseek/deepseek-v4-pro-0813", "DeepSeek V4 Pro — $0.66 / $1.98", "opencode"},
	{"openrouter/deepseek/deepseek-v4.1-flash", "DeepSeek V4.1 Flash — $0.15 / $0.60", "opencode"},
	{"openrouter/qwen/qwen3-coder-next", "Qwen3 Coder Next — $0.12 / $0.80", "opencode"},
	{"openrouter/minimax/minimax-m3", "MiniMax M3 — $0.30 / $1.20", "opencode"},
	{"openclaw/claude-opus-5-5", "Opus 5.5", "openclaw"},
	{"openclaw/claude-fable-5-1", "Fable 5.1", "openclaw"},
	{"paseo/claude-opus-5-5", "Opus 5.5", "paseo-claude"},
	{"paseo/claude-fable-5-1", "Fable 5.1", "paseo-claude"},
	{"cloudcli/claude-opus-5-5", "Opus 5.5", "cloudcli"},
	{"cloudcli/claude-fable-5-1", "Fable 5.1", "cloudcli"},
	{"dsh/deepseek/deepseek-v4-pro-0813", "DeepSeek V4 Pro — $0.66 / $1.98", "dsh"},
	{"dsh/deepseek/deepseek-v4.1-flash-1017", "DeepSeek V4.1 Flash — $0.15 / $0.60", "dsh"},
}

// the first model of each harness is its default
var harnessInfo = map[string]map[string]string{
	"claude":       {"label": "Claude Code", "detail": "Claude subscription · Claude app"},
	"opencode":     {"label": "OpenCode · OpenRouter", "detail": "Paseo app + web UI"},
	"openclaw":     {"label": "claw-code · OpenClaw", "detail": "Claude subscription · OpenClaw app + Control UI"},
	"paseo-claude": {"label": "Claude Code · Paseo", "detail": "Claude subscription · Paseo app + web UI"},
	"cloudcli":     {"label": "Claude Code · CloudCLI", "detail": "Claude subscription · Jarvis 4 Chat app + web UI"},
	"dsh":          {"label": "DeepSeek Harness · OpenRouter", "detail": "DeepSeek V4 on DeepSeek's endpoint · web UI"},
}

// paseoHarness: a Paseo daemon fronts the session (its app pairs with the daemon, its web UI is the session's tunnel
// origin): OpenCode on OpenRouter, or Claude Code
func paseoHarness(h string) bool { return h == "opencode" || h == "paseo-claude" }

// proxyLoginHarness: Claude Code reaches the API only through api-proxy.js, which sends the session's current Claude
// login per request (session-image harness-paseo-claude.sh, harness-cloudcli.sh): a running session switches accounts
// with no restart
func proxyLoginHarness(h string) bool { return h == "paseo-claude" || h == "cloudcli" }

func defaultModel(harness string) string {
	for _, m := range modelCatalog {
		if m.Harness == harness {
			return m.ID
		}
	}
	return ""
}

// sessionModel: the model a new session of this harness runs. Empty, or another harness's model (the iPhone shell
// picks the harness after the form picked a model), → the harness's default; an id that isn't in the list is
// refused, as in Jarvis 1, so a typo can't start a session on a model that doesn't exist.
func sessionModel(harness, model string) (string, error) {
	if model == "" {
		return defaultModel(harness), nil
	}
	for _, m := range modelCatalog {
		if m.ID == model {
			if m.Harness != harness {
				return defaultModel(harness), nil
			}
			return model, nil
		}
	}
	return "", fmt.Errorf("unknown model %q (GET /api/models lists them)", model)
}

// GET /api/models[?harness=x] → {models: [{id, label, harness}], default, defaults: {harness: id}, harnesses}
func (r *Router) registerHarnesses(app appRoute) {
	app("GET /api/models", func(w http.ResponseWriter, req *http.Request) {
		h := req.URL.Query().Get("harness")
		out := []ModelChoice{}
		for _, m := range modelCatalog {
			if _, ok := r.policy.Harnesses[m.Harness]; !ok && len(r.policy.Harnesses) > 0 {
				continue // a harness the policy doesn't offer
			}
			if h == "" || m.Harness == h {
				out = append(out, m)
			}
		}
		defaults, harnesses := map[string]string{}, map[string]map[string]string{}
		for name, info := range harnessInfo {
			if _, ok := r.policy.Harnesses[name]; ok || len(r.policy.Harnesses) == 0 {
				defaults[name], harnesses[name] = defaultModel(name), info
			}
		}
		def := defaultModel("claude")
		if h != "" {
			def = defaultModel(h)
		}
		writeJSON(w, 200, map[string]any{"models": out, "default": def, "defaults": defaults, "harnesses": harnesses})
	})
}
