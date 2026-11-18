package main

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

// The chat's model menu picks a Claude account for a session ("Opus 5.5 · chendeyao-uk"): hermit-jarvis calls this
// route on the devices' Access app (devices.go), as it does the signature check and the chat-schedule report. The
// router answers at once with the account's uuid; the machine's gateway waits for its own proof of the new pair.
func TestHermitSwitchesASessionsClaudeAccount(t *testing.T) {
	r, _, _, expA, _ := twoAccounts(t)
	shortSwapWaits(t)
	r.cfg.NoAccess, r.cfg.AccessTeam, r.cfg.AppAUD = false, "team.example", "app-aud"
	t.Setenv("ACCESS_DEVICES_AUD", "devices-aud")
	t.Setenv("HERMIT_CLIENT_ID", "hermit.access")
	addSession(r, "s1", "started", "m1", false)
	r.st.Do(func(d *persisted) {
		d.Sessions["s1"].Harness = "aviary"
		d.Sessions["s1"].ClaudeAccount = "claude-a"
	})
	setReg(r, "s1", func(g *Registry) {
		g.HostPid, g.CredsExpiresAt, g.AccountSection = 100, expA, true
	})
	do := func(tok, body string) (int, map[string]any) {
		req := httptest.NewRequest("POST", "/api/remotes/s1/account", strings.NewReader(body))
		req.Header.Set("Cf-Access-Jwt-Assertion", tok)
		w := httptest.NewRecorder()
		r.Handler().ServeHTTP(w, req)
		return w.Code, bodyOf(w)
	}
	hermit := accessToken(t, "team.example", map[string]any{"aud": "devices-aud", "common_name": "hermit.access"})

	// the account it is already on: nothing to do, and the chat's menu learns the account's uuid
	if code, out := do(hermit, `{"account":"a"}`); code != 200 || out["unchanged"] != true || out["accountUuid"] != "acct-1" {
		t.Fatalf("unchanged: %d %v", code, out)
	}
	// the switch: accepted, the session moves, the machine is told
	code, out := do(hermit, `{"account":"claude-b"}`)
	if code != 202 || out["from"] != "claude-a" || out["to"] != "claude-b" || out["accountUuid"] != "acct-2" {
		t.Fatalf("switch: %d %v", code, out)
	}
	var got string
	r.st.Do(func(d *persisted) { got = d.Sessions["s1"].ClaudeAccount })
	if got != "claude-b" {
		t.Fatalf("the session's account is %s", got)
	}
	if c, ok := takeCmd(r, "m1"); !ok || c != "claude-account" {
		t.Fatal("the machine wasn't told")
	}
	// another service token of the account has no business here
	other := accessToken(t, "team.example", map[string]any{"aud": "devices-aud", "common_name": "other.access"})
	if code, _ := do(other, `{"account":"a"}`); code != 403 {
		t.Fatalf("a stranger's token answered %d", code)
	}

	// what the chat's menu is made from: the session's account, and every signed-in account, the default first
	req := httptest.NewRequest("GET", "/api/remotes?harness=aviary", nil)
	// minted again: a token minting replaces the team's key (accessToken), so the stranger's made hermit's stale
	req.Header.Set("Cf-Access-Jwt-Assertion", accessToken(t, "team.example", map[string]any{"aud": "devices-aud", "common_name": "hermit.access"}))
	w := httptest.NewRecorder()
	r.Handler().ServeHTTP(w, req)
	var list struct {
		Sessions []struct{ ID, Account string }
		Accounts []struct {
			Store, Name, Email, AccountUUID string
			Default                         bool
		}
	}
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil || w.Code != 200 {
		t.Fatalf("remotes: %d %s", w.Code, w.Body)
	}
	if len(list.Sessions) != 1 || list.Sessions[0].Account != "claude-b" {
		t.Fatalf("sessions: %+v", list.Sessions)
	}
	if len(list.Accounts) != 2 || list.Accounts[0].Name != "a" || !list.Accounts[0].Default || list.Accounts[1].Name != "b" ||
		list.Accounts[1].AccountUUID != "acct-2" || list.Accounts[1].Store != "claude-b" {
		t.Fatalf("accounts: %+v", list.Accounts)
	}
}

// bodyOf: the JSON a handler wrote
func bodyOf(w *httptest.ResponseRecorder) map[string]any {
	out := map[string]any{}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		return map[string]any{}
	}
	return out
}
