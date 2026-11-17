package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The stand-in answers as Anthropic's API does: JSON bodies say so. Claude Code 2.1.325 checks a model it switches to
// with a non-streamed call and parses the body by its content type; Go's sniffed text/plain made it fail with
// "Unable to validate model: undefined is not an object (evaluating '….usage.input_tokens')", so every turn whose
// generation switched model failed before it started (2026-11-17, aviary-0dc00f0f0b02's replica).
func TestModelStandInRepliesAreJSON(t *testing.T) {
	cases := []struct{ name, path, body string }{
		{"a model check (not streamed)", "/model/v1/messages",
			`{"model":"claude-fable-5-2","max_tokens":1,"system":"You are Claude Code, Anthropic's official CLI for Claude.","messages":[{"role":"user","content":"Hi"}]}`},
		{"count_tokens", "/model/v1/messages/count_tokens", `{"model":"claude-fable-5-2","messages":[]}`},
	}
	for _, c := range cases {
		req := httptest.NewRequest(http.MethodPost, c.path, strings.NewReader(c.body))
		req.Header.Set("User-Agent", "claude-cli/2.1.325 (external, sdk-cli)")
		w := httptest.NewRecorder()
		serveModel(w, req)
		if w.Code != 200 {
			t.Fatalf("%s: HTTP %d %s", c.name, w.Code, w.Body)
		}
		if ct := w.Header().Get("Content-Type"); ct != "application/json" {
			t.Errorf("%s: Content-Type %q, want application/json", c.name, ct)
		}
		var out map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Errorf("%s: not JSON: %v", c.name, err)
		}
		if c.path == "/model/v1/messages" {
			if u, _ := out["usage"].(map[string]any); u["input_tokens"] == nil {
				t.Errorf("%s: no usage.input_tokens: %s", c.name, w.Body)
			}
		}
	}
}
