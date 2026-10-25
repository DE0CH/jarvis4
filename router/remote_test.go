package main

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSessionModel(t *testing.T) {
	cases := []struct{ harness, in, want string }{
		{"claude", "", "claude-opus-5-5"},
		{"claude", "claude-fable-5-1", "claude-fable-5-1"},
		{"opencode", "", "openrouter/z-ai/glm-5.3"},
		{"opencode", "openrouter/moonshotai/kimi-k3", "openrouter/moonshotai/kimi-k3"},
		{"opencode", "claude-opus-5-5", "openrouter/z-ai/glm-5.3"}, // the shell picked another harness than the form's model
		{"openclaw", "claude-fable-5-1", "openclaw/claude-opus-5-5"},
		{"openclaw", "openclaw/claude-fable-5-1", "openclaw/claude-fable-5-1"},
		{"paseo-claude", "", "paseo/claude-opus-5-5"},
		{"paseo-claude", "paseo/claude-fable-5-1", "paseo/claude-fable-5-1"},
		{"paseo-claude", "claude-fable-5-1", "paseo/claude-opus-5-5"},
	}
	for _, c := range cases {
		if got, err := sessionModel(c.harness, c.in); err != nil || got != c.want {
			t.Errorf("%s %q: %q %v, want %q", c.harness, c.in, got, err, c.want)
		}
	}
	if _, err := sessionModel("claude", "claude-opus-typo"); err == nil {
		t.Fatal("an unknown model must be refused")
	}
}

func TestModelsList(t *testing.T) {
	r := newTestRouter(t)
	r.policy.Harnesses = map[string]HarnessPolicy{"claude": {}, "opencode": {}}
	get := func(q string) map[string]any {
		w := httptest.NewRecorder()
		r.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/api/models"+q, nil))
		out := map[string]any{}
		json.Unmarshal(w.Body.Bytes(), &out)
		return out
	}
	all := get("")
	for _, m := range all["models"].([]any) {
		if m.(map[string]any)["harness"] == "openclaw" {
			t.Fatal("a harness outside the policy is listed")
		}
	}
	if _, ok := all["harnesses"].(map[string]any)["openclaw"]; ok || all["default"] != "claude-opus-5-5" {
		t.Fatalf("%v", all)
	}
	oc := get("?harness=opencode")
	ms := oc["models"].([]any)
	if len(ms) != 6 || oc["default"] != "openrouter/z-ai/glm-5.3" {
		t.Fatalf("%v", oc)
	}
	for _, m := range ms {
		if !strings.HasPrefix(m.(map[string]any)["id"].(string), "openrouter/") {
			t.Fatalf("%v", m)
		}
	}
}

func TestParseRemote(t *testing.T) {
	i := parseRemote("opencode", "s0123456789abcdef", "starting…\n{\"url\":\"https://app.paseo.sh/#offer=x\",\"relayEnabled\":true}\n")
	if i.PairURL != "https://app.paseo.sh/#offer=x" || !i.Relay || i.WebURL != "https://s0123456789abcdef-s.deyaochen.com/" || i.Error != "" {
		t.Fatalf("%+v", i)
	}
	if i := parseRemote("opencode", "s1", "daemon not running"); i.Error == "" || i.PairURL != "" {
		t.Fatalf("%+v", i)
	}
	i = parseRemote("openclaw", "s1", `{"token":"a/b+c"}`)
	if i.Token != "a/b+c" || i.URL != "wss://s1-s.deyaochen.com" || i.WebURL != "https://s1-s.deyaochen.com/#token=a%2Fb%2Bc" {
		t.Fatalf("%+v", i)
	}
	if i := parseRemote("openclaw", "s1", ""); i.Error == "" || i.Token != "" {
		t.Fatalf("%+v", i)
	}
}

// fakeMachine answers the router's holder commands for one machine the way the machine would
func fakeMachine(t *testing.T, r *Router, machine string, answer func(holder, cmd string) ExecResult) (stop func()) {
	done := make(chan struct{})
	pub, _ := r.HolderPublicKeys()
	go func() {
		for {
			select {
			case <-done:
				return
			default:
			}
			if b, ok := mqWaitKind(r, machine, "exec", 50*time.Millisecond); ok {
				var e execItem
				json.Unmarshal(b, &e)
				var req struct{ ID, Holder, Cmd string }
				json.Unmarshal([]byte(e.Request), &req)
				name := ""
				for n, k := range pub {
					if k == req.Holder {
						name = n
					}
				}
				res := answer(name, req.Cmd)
				res.ID = req.ID
				r.execResult(res)
			}
		}
	}()
	return func() { close(done) }
}

func addHarnessSession(r *Router, id, harness, state, machine string) {
	addSession(r, id, state, machine, false)
	r.st.Do(func(d *persisted) {
		d.Sessions[id].Harness = harness
		d.Sessions[id].Model = defaultModel(harness)
		d.Sessions[id].Created = time.Now()
	})
}

func TestRemotePage(t *testing.T) {
	r := newTestRouter(t)
	addHarnessSession(r, "sOC", "openclaw", "started", "mOC")
	addHarnessSession(r, "sOP", "opencode", "started", "mOP")
	addHarnessSession(r, "sCL", "claude", "started", "mCL")
	addHarnessSession(r, "sPA", "opencode", "paused", "")
	addHarnessSession(r, "sPC", "paseo-claude", "started", "mPC")
	calls := 0
	defer fakeMachine(t, r, "mOC", func(holder, cmd string) ExecResult {
		calls++
		if holder != "remote" || cmd != openclawRemote {
			return ExecResult{Error: "unexpected " + holder + ": " + cmd}
		}
		return ExecResult{Stdout: `{"token":"tok123"}`}
	})()
	defer fakeMachine(t, r, "mOP", func(holder, cmd string) ExecResult {
		return ExecResult{Error: "the remote holder is not on this session's allow list and no phone grant is given"}
	})()
	defer fakeMachine(t, r, "mPC", func(holder, cmd string) ExecResult {
		if holder != "remote" || cmd != paseoPairCmd {
			return ExecResult{Error: "unexpected " + holder + ": " + cmd}
		}
		return ExecResult{Stdout: `{"url":"https://app.paseo.sh/#offer=pc","relayEnabled":true}`}
	})()
	h := r.Handler()
	get := func(path string) (int, map[string]any) {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		out := map[string]any{}
		json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	code, out := get("/api/sessions/sOC/remote")
	if code != 200 || out["token"] != "tok123" || out["url"] != "wss://sOC-s.deyaochen.com" || out["webUrl"] != "https://sOC-s.deyaochen.com/#token=tok123" {
		t.Fatalf("%d %v", code, out)
	}
	if get("/api/sessions/sOC/remote"); calls != 1 {
		t.Fatalf("not cached: %d calls", calls)
	}
	if code, out = get("/api/sessions/sOP/remote"); code != 403 || out["needsGrant"] != "remote" {
		t.Fatalf("%d %v", code, out)
	}
	if code, _ = get("/api/sessions/sCL/remote"); code != 400 {
		t.Fatalf("claude: %d", code)
	}
	if code, _ = get("/api/sessions/sPA/remote"); code != 409 {
		t.Fatalf("paused: %d", code)
	}
	if code, _ = get("/api/sessions/nope/remote"); code != 404 {
		t.Fatalf("missing: %d", code)
	}

	code, out = get("/api/remotes?harness=opencode")
	ss := out["sessions"].([]any)
	if code != 200 || len(ss) != 2 {
		t.Fatalf("%d %v", code, out)
	}
	byID := map[string]map[string]any{}
	for _, s := range ss {
		byID[s.(map[string]any)["id"].(string)] = s.(map[string]any)
	}
	if p := byID["sPA"]; p["state"] != "paused" || p["error"] != nil || p["model"] != "openrouter/z-ai/glm-5.3" {
		t.Fatalf("%v", p)
	}
	if o := byID["sOP"]; o["needsGrant"] != "remote" || o["error"] == nil {
		t.Fatalf("%v", o)
	}
	code, out = get("/api/remotes?harness=openclaw")
	if s := out["sessions"].([]any)[0].(map[string]any); code != 200 || s["token"] != "tok123" || s["title"] != "label sOC" {
		t.Fatalf("%d %v", code, out)
	}
	// Claude Code · Paseo: the Paseo pairing offer; listed on its own and with every Paseo session (harness=paseo)
	if code, out = get("/api/sessions/sPC/remote"); code != 200 || out["pairUrl"] != "https://app.paseo.sh/#offer=pc" || out["webUrl"] != "https://sPC-s.deyaochen.com/" {
		t.Fatalf("%d %v", code, out)
	}
	if code, out = get("/api/remotes?harness=paseo-claude"); code != 200 || len(out["sessions"].([]any)) != 1 {
		t.Fatalf("%d %v", code, out)
	}
	code, out = get("/api/remotes?harness=paseo")
	got := map[string]string{}
	for _, s := range out["sessions"].([]any) {
		got[s.(map[string]any)["id"].(string)] = s.(map[string]any)["harness"].(string)
	}
	if code != 200 || len(got) != 3 || got["sPC"] != "paseo-claude" || got["sOP"] != "opencode" || got["sPA"] != "opencode" {
		t.Fatalf("%d %v", code, out)
	}
	if code, _ = get("/api/remotes?harness=claude"); code != 400 {
		t.Fatalf("claude remotes: %d", code)
	}
}

// Claude Code · CloudCLI: its remote is its origin (Access is the gate), read from nothing on the machine; the
// Jarvis 4 Chat app lists the sessions with harness=cloudcli
func TestCloudCLIRemote(t *testing.T) {
	r := newTestRouter(t)
	addHarnessSession(r, "sCC", "cloudcli", "started", "mCC")
	addHarnessSession(r, "sCP", "cloudcli", "paused", "")
	addHarnessSession(r, "sPC", "paseo-claude", "started", "mPC")
	defer fakeMachine(t, r, "mCC", func(holder, cmd string) ExecResult {
		return ExecResult{Error: "the router ran " + holder + ": " + cmd + " on a cloudcli session"}
	})()
	h := r.Handler()
	get := func(path string) (int, map[string]any) {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		out := map[string]any{}
		json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	if code, out := get("/api/sessions/sCC/remote"); code != 200 || out["webUrl"] != "https://sCC-s.deyaochen.com/" || out["harness"] != "cloudcli" || out["token"] != nil || out["pairUrl"] != nil {
		t.Fatalf("%d %v", code, out)
	}
	code, out := get("/api/remotes?harness=cloudcli")
	ss := out["sessions"].([]any)
	if code != 200 || len(ss) != 2 {
		t.Fatalf("%d %v", code, out)
	}
	byID := map[string]map[string]any{}
	for _, s := range ss {
		byID[s.(map[string]any)["id"].(string)] = s.(map[string]any)
	}
	if s := byID["sCC"]; s["webUrl"] != "https://sCC-s.deyaochen.com/" || s["model"] != "cloudcli/claude-opus-5-5" || s["error"] != nil {
		t.Fatalf("%v", s)
	}
	if s := byID["sCP"]; s["state"] != "paused" || s["webUrl"] != nil {
		t.Fatalf("%v", s)
	}
	if !proxyLoginHarness("cloudcli") || !harnessSend["cloudcli"] || deviceSchemes["jarvis4chat"] != "dev.de0ch.jarvis4chat" {
		t.Fatal("cloudcli: an account switch through the API proxy, harness-send and the Jarvis 4 Chat app's pairing")
	}
}

func TestTunnelProof(t *testing.T) {
	a, b := tunnelProof("k", "s0000000000000001"), tunnelProof("k", "s0000000000000002")
	if len(a) != 64 || a == b || a != tunnelProof("k", "s0000000000000001") || tunnelProof("", "s1") != "" {
		t.Fatal("proof")
	}
	r := newTestRouter(t)
	addSession(r, "sA", "started", "mA", false)
	m := newTestMachine(r, "mA")
	other := newTestMachine(r, "mX") // started by the core, but no running session
	h := r.MachineHandler()
	t.Setenv("JARVIS2_TUNNEL_KEY", "")
	if code, _ := m.do(t, h, "GET", "/m/tunnel-proof", ""); code != 404 {
		t.Fatalf("no key: %d", code)
	}
	t.Setenv("JARVIS2_TUNNEL_KEY", "k")
	code, out := m.do(t, h, "GET", "/m/tunnel-proof", "")
	if code != 200 || out["proof"] != tunnelProof("k", "sA") || out["id"] != "sA" {
		t.Fatalf("%d %v", code, out)
	}
	if code, _ := other.do(t, h, "GET", "/m/tunnel-proof", ""); code != 403 {
		t.Fatalf("a machine without a session got a proof: %d", code)
	}
}

func TestRemoteHolderExists(t *testing.T) {
	r := newTestRouter(t)
	pub, err := r.HolderPublicKeys()
	if err != nil || pub["remote"] == "" || pub["remote"] == pub["terminal"] {
		t.Fatal("holder remote")
	}
}
