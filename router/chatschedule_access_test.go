package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// accessToken mints an Access JWT the router's verifier accepts (its team's key seeded in the cache).
func accessToken(t *testing.T, team string, claims map[string]any) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	accessMu.Lock()
	accessCache[team] = &accessKeys{team: team, keys: map[string]*rsa.PublicKey{"k1": &key.PublicKey}, fetched: time.Now()}
	accessMu.Unlock()
	t.Cleanup(func() { accessMu.Lock(); delete(accessCache, team); accessMu.Unlock() })
	enc := func(v any) string { b, _ := json.Marshal(v); return base64.RawURLEncoding.EncodeToString(b) }
	claims["iss"], claims["exp"] = "https://"+team, time.Now().Add(time.Hour).Unix()
	signing := enc(map[string]string{"alg": "RS256", "kid": "k1"}) + "." + enc(claims)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// hermit-jarvis reaches the router with its own service token on the "Jarvis 4 devices" Access app (aviary/src/jarvis.rs):
// its chat-schedule report must be served there, as the signature check is, not as an app route (Deyao's email only).
// It was an app route at first, and every report was refused (2026-11-18).
func TestHermitReachesTheChatScheduleReport(t *testing.T) {
	r := newTestRouter(t)
	r.cfg.NoAccess, r.cfg.AccessTeam, r.cfg.AppAUD = false, "team.example", "app-aud"
	t.Setenv("ACCESS_DEVICES_AUD", "devices-aud")
	t.Setenv("HERMIT_CLIENT_ID", "hermit.access")
	addSession(r, "s1", "paused", "", false)
	r.st.Do(func(d *persisted) { d.Sessions["s1"].Harness = "aviary" })
	put := func(tok string) int {
		req := httptest.NewRequest("PUT", "/api/sessions/s1/chat-schedule", strings.NewReader(`{"nextAt": "2026-11-21T14:00:00Z"}`))
		req.Header.Set("Cf-Access-Jwt-Assertion", tok)
		w := httptest.NewRecorder()
		r.Handler().ServeHTTP(w, req)
		return w.Code
	}
	if c := put(accessToken(t, "team.example", map[string]any{"aud": "devices-aud", "common_name": "hermit.access"})); c != 200 {
		t.Fatalf("hermit-jarvis's report answered %d", c)
	}
	wakes := false
	r.st.Do(func(d *persisted) { wakes = willWake(d, "s1") })
	if !wakes {
		t.Fatal("the report was not kept")
	}
	// another service token of the account is refused
	if c := put(accessToken(t, "team.example", map[string]any{"aud": "devices-aud", "common_name": "other.access"})); c != 403 {
		t.Fatalf("a stranger's token answered %d", c)
	}
}
