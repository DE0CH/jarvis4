package main

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

// hermit-jarvis proposes a new session for a new conversation in the chat (Deyao, 2026-11-18): POST /api/remotes, on
// the devices Access app with its own service token. It waits in the Inbox as the app's New session does (named as
// Deyao's, from the chat), a repeat of its requestId answers the same session, the list shows it as "approval" (so
// hermit-jarvis holds the conversation's first message rather than taking it for denied), and a denial removes it.
func TestHermitProposesANewSession(t *testing.T) {
	newFakeAnthropic(t)
	rg := newRig(t)
	r := rg.r
	r.policy = Policy{Harnesses: map[string]HarnessPolicy{"aviary": {Stores: []string{"tunnel"}, ClaudeAccount: true}}}
	r.cfg.NoAccess, r.cfg.AccessTeam, r.cfg.AppAUD = false, "team.example", "app-aud"
	t.Setenv("ACCESS_DEVICES_AUD", "devices-aud")
	t.Setenv("HERMIT_CLIENT_ID", "hermit.access")
	t.Cleanup(func() { // the new session's approval is filed in the background: let it land before the dir goes
		waitFor(t, "the approvals filed", func() bool {
			var waiting []string
			r.st.Do(func(d *persisted) {
				for _, s := range d.Sessions {
					if s.State == "approval" {
						waiting = append(waiting, s.ID)
					}
				}
			})
			for _, id := range waiting {
				if approvalOf(rg, id) == nil {
					return false
				}
			}
			return true
		})
	})
	if err := r.updateRepos(func([]RepoEntry) []RepoEntry {
		return []RepoEntry{{URL: "https://github.com/DE0CH/claude-env.git"}}
	}); err != nil {
		t.Fatal(err)
	}
	h := r.Handler()
	call := func(method, path, client, body string) (int, map[string]any) {
		tok := accessToken(t, "team.example", map[string]any{"aud": "devices-aud", "common_name": client})
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Cf-Access-Jwt-Assertion", tok)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		out := map[string]any{}
		json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	code, out := call("POST", "/api/remotes", "hermit.access", `{"harness": "aviary", "requestId": "chat:c1"}`)
	id, _ := out["id"].(string)
	if code != 200 || id == "" || out["state"] != "approval" {
		t.Fatalf("the proposal: %d %v", code, out)
	}
	// the app's New session with nothing touched: claude-env (its CLAUDE.md) and the default store
	r.st.Do(func(d *persisted) {
		s := d.Sessions[id]
		if s == nil || s.Harness != "aviary" || s.Repos != "https://github.com/DE0CH/claude-env.git" ||
			!containsAll(s.Stores, []string{"default", "github-claude-env"}) || containsString(s.Stores, "identity") {
			t.Fatalf("the proposed session: %+v", s)
		}
	})
	if code, again := call("POST", "/api/remotes", "hermit.access", `{"harness": "aviary", "requestId": "chat:c1"}`); code != 200 || again["id"] != id {
		t.Fatalf("a repeat answers the same session: %d %v", code, again)
	}
	var approval string
	waitFor(t, "its approval in the Inbox", func() (ok bool) {
		a := approvalOf(rg, id)
		if a == nil {
			return false
		}
		approval = a.ID
		r.st.Do(func(d *persisted) {
			ok = a.Origin != nil && a.Origin.Caller.Kind == "chat" && callerText(d, a.Origin.Caller) == "Deyao, from the chat (a new conversation)"
		})
		return
	})
	listed := func() map[string]any {
		code, out := call("GET", "/api/remotes?harness=aviary", "hermit.access", "")
		if code != 200 {
			t.Fatalf("the list: %d %v", code, out)
		}
		for _, s := range out["sessions"].([]any) {
			if m := s.(map[string]any); m["id"] == id {
				return m
			}
		}
		return nil
	}
	if s := listed(); s == nil || s["state"] != "approval" {
		t.Fatalf("listed while it waits: %v", s)
	}
	if err := r.Reject(approval); err != nil {
		t.Fatal(err)
	}
	if s := listed(); s != nil {
		t.Fatalf("a denied session is gone from the list: %v", s)
	}
	// another service token of the account is refused, and a harness that is not one of the apps'
	if code, _ := call("POST", "/api/remotes", "other.access", `{"harness": "aviary", "requestId": "chat:c2"}`); code != 403 {
		t.Fatalf("a stranger's token answered %d", code)
	}
	if code, _ := call("POST", "/api/remotes", "hermit.access", `{"harness": "claude", "requestId": "chat:c3"}`); code != 400 {
		t.Fatalf("a claude session answered %d", code)
	}
	if code, _ := call("POST", "/api/remotes", "hermit.access", `{"harness": "aviary"}`); code != 400 {
		t.Fatalf("no requestId answered %d", code)
	}
}

// A session from the chat is the app's New session with nothing touched (Deyao, 2026-11-18: the first one started
// with no CLAUDE.md, as it had no repo): the store `default` and DE0CH/claude-env with its key's store, never a
// sensitive store.
func TestNewSessionDefaultsAreTheAppsPrePicks(t *testing.T) {
	env := RepoEntry{Name: "claude-env", URL: "https://github.com/DE0CH/claude-env.git", Repo: "DE0CH/claude-env", Store: "github-claude-env"}
	other := RepoEntry{Name: "jarvis4", URL: "https://github.com/DE0CH/jarvis4.git", Repo: "DE0CH/jarvis4", Store: "github-jarvis4"}
	rows := []StoreRow{{Name: "default"}, {Name: "github-claude-env"}, {Name: "github-jarvis4"}, {Name: "identity", Sensitive: true}}
	stores, repos := newSessionDefaults(rows, []RepoEntry{other, env})
	if strings.Join(stores, ",") != "default,github-claude-env" || repos != env.URL {
		t.Fatalf("defaults: %v %q", stores, repos)
	}
	// a sensitive default store, or a sensitive (or missing) key store: never pre-picked, nor the repo it would clone
	rows = []StoreRow{{Name: "default", Sensitive: true}, {Name: "github-claude-env", Sensitive: true}}
	if stores, repos := newSessionDefaults(rows, []RepoEntry{env}); len(stores) != 0 || repos != "" {
		t.Fatalf("sensitive: %v %q", stores, repos)
	}
	if stores, repos := newSessionDefaults([]StoreRow{{Name: "default"}}, nil); strings.Join(stores, ",") != "default" || repos != "" {
		t.Fatalf("no repos on the list: %v %q", stores, repos)
	}
}
