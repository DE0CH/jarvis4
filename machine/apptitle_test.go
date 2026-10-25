package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fakeHome(t *testing.T) string {
	t.Helper()
	old := claudeHome
	claudeHome = t.TempDir()
	t.Cleanup(func() { claudeHome = old })
	for _, d := range []string{".claude/sessions", ".claude/projects/-home-claude-workspace"} {
		os.MkdirAll(filepath.Join(claudeHome, d), 0o755)
	}
	return claudeHome
}

func TestAppTitle(t *testing.T) {
	home := fakeHome(t)
	var calls []string
	var authOK = true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		calls = append(calls, req.URL.RequestURI())
		authOK = authOK && req.Header.Get("Authorization") == "Bearer tok-1" && strings.Contains(req.Header.Get("anthropic-beta"), "oauth-2025-04-20")
		switch req.URL.Path {
		case "/v1/code/sessions/cse_abc":
			w.Write([]byte(`{"id":"cse_abc","title":"Renamed by Deyao"}`))
		case "/v1/code/sessions/cse_wrapped": // the shape of 2026-10-25
			w.Write([]byte(`{"response_shape":{"id":"cse_wrapped","title":"Inside the shape","connection_status":"connected"}}`))
		case "/v1/code/sessions/cse_old":
			w.WriteHeader(404)
		case "/v1/code/sessions":
			w.Write([]byte(`{"data":[{"id":"cse_x","title":"other"},{"id":"cse_old","title":"From the list"}]}`))
		default:
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()
	oldURL, oldTTL := codeSessionsURL, appTitleTTL
	codeSessionsURL, appTitleTTL = srv.URL+"/v1/code/sessions", time.Hour
	defer func() { codeSessionsURL, appTitleTTL = oldURL, oldTTL }()

	a := &appTitler{}
	if a.current() != "" || len(calls) != 0 {
		t.Fatal("no claude yet: no title, no call")
	}
	os.WriteFile(filepath.Join(home, ".claude/sessions/1.json"), []byte(`{"pid":1,"startedAt":5,"bridgeSessionId":"session_abc"}`), 0o600)
	os.WriteFile(filepath.Join(home, ".claude/sessions/2.json"), []byte(`{"pid":2,"startedAt":9}`), 0o600)
	if a.current() != "" || len(calls) != 0 {
		t.Fatal("no credentials: no call")
	}
	os.WriteFile(filepath.Join(home, ".claude/.credentials.json"), []byte(`{"claudeAiOauth":{"accessToken":"tok-1","refreshToken":"r"}}`), 0o600)
	a.at = time.Time{} // the TTL would otherwise hold the empty answer
	if got := a.current(); got != "Renamed by Deyao" {
		t.Fatalf("title %q (%v)", got, calls)
	}
	n := len(calls)
	a.current()
	if len(calls) != n {
		t.Fatal("not cached")
	}
	// a new Remote Control entry (a resume): read again; 404 on the single read → the list
	os.WriteFile(filepath.Join(home, ".claude/sessions/1.json"), []byte(`{"pid":1,"startedAt":5,"bridgeSessionId":"cse_old"}`), 0o600)
	if got := a.current(); got != "From the list" {
		t.Fatalf("title %q (%v)", got, calls)
	}
	os.WriteFile(filepath.Join(home, ".claude/sessions/1.json"), []byte(`{"pid":1,"startedAt":5,"bridgeSessionId":"session_wrapped"}`), 0o600)
	if got := a.current(); got != "Inside the shape" {
		t.Fatalf("title %q (%v)", got, calls)
	}
	if s, _, err := fetchCodeSession("wrapped", "tok-1"); err != nil || s.ConnectionStatus != "connected" {
		t.Fatalf("connection status: %+v %v", s, err)
	}
	if !authOK {
		t.Fatal("the request lacked the token or the beta header")
	}
	// a failed read keeps the last title of the same entry
	a.at = time.Time{}
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { w.WriteHeader(500) })
	if got := a.current(); got != "Inside the shape" {
		t.Fatalf("after a failure %q", got)
	}
}

func TestLiveSyncOnce(t *testing.T) {
	home := fakeHome(t)
	dir := filepath.Join(home, ".claude/projects/-home-claude-workspace")
	sent := map[string]string{}
	l := &liveSyncer{sent: map[string]time.Time{}, send: func(name string, body []byte) error { sent[name] = string(body); return nil }}
	os.WriteFile(filepath.Join(dir, "aaaa.jsonl"), []byte(`{"type":"user"}`+"\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "relay.jsonl"), []byte(`{"type":"user","message":{"content":"You are a delivery relay for Jarvis"}}`), 0o600)
	os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("x"), 0o600)
	if n := l.once(); n != 1 || sent["aaaa.jsonl"] == "" || len(sent) != 1 {
		t.Fatalf("first pass: %d %v", n, sent)
	}
	if n := l.once(); n != 0 {
		t.Fatal("an unchanged file was sent again")
	}
	later := time.Now().Add(time.Minute)
	os.WriteFile(filepath.Join(dir, "aaaa.jsonl"), []byte("a\nb\n"), 0o600)
	os.Chtimes(filepath.Join(dir, "aaaa.jsonl"), later, later)
	if n := l.once(); n != 1 || sent["aaaa.jsonl"] != "a\nb\n" {
		t.Fatalf("changed file: %d %q", n, sent["aaaa.jsonl"])
	}
	// a failed send is tried again on the next pass
	fail := true
	l.send = func(name string, body []byte) error {
		if fail {
			return os.ErrDeadlineExceeded
		}
		sent[name] = string(body)
		return nil
	}
	os.WriteFile(filepath.Join(dir, "bbbb.jsonl"), []byte("x\n"), 0o600)
	if l.once() != 0 {
		t.Fatal("counted a failed send")
	}
	fail = false
	if l.once() != 1 || sent["bbbb.jsonl"] != "x\n" {
		t.Fatal("not retried")
	}
	old := vouchedPath
	vouchedPath = filepath.Join(t.TempDir(), "vouched.json")
	t.Cleanup(func() { vouchedPath = old })
	t.Setenv("JARVIS2_LIVE_SYNC_SECONDS", "20") // the env: ignored
	if liveSyncInterval() != 300*time.Second {
		t.Fatal("the env set the interval")
	}
	writeVouched(Vouched{Ex: FormatExceptions{LiveSyncSeconds: 20}, Cert: Cert{}})
	if liveSyncInterval() != 20*time.Second {
		t.Fatal("interval")
	}
}
