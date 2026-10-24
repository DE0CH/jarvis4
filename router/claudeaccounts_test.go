package main

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// signIn: an account's sign-in through the app routes, as Deyao does it (start → the page → paste code#state)
func signIn(t *testing.T, r *Router, startPath, startBody string) (int, map[string]any) {
	t.Helper()
	code, out := appDo(t, r, "POST", startPath, startBody)
	if code != 200 {
		return code, out
	}
	u, _ := url.Parse(out["url"].(string))
	store := out["store"].(string)
	return appDo(t, r, "POST", "/api/claude-accounts/"+store+"/code", `{"code":"abc#`+u.Query().Get("state")+`"}`)
}

// Add, Re-login, Make default, Remove (DECISIONS 185)
func TestClaudeAccountsManage(t *testing.T) {
	f := newFakeAnthropic(t)
	r := newTestRouter(t)
	if code, out := appDo(t, r, "GET", "/api/claude-accounts", ""); code != 200 || out["default"] != "" || len(out["accounts"].([]any)) != 0 {
		t.Fatal(code, out)
	}
	if code, _ := appDo(t, r, "POST", "/api/claude-accounts", `{"name":"Bad Name!"}`); code != 400 {
		t.Fatal("a name that can't be a store name was taken")
	}
	// the first account: signed in, and the default
	code, out := signIn(t, r, "/api/claude-accounts", `{"name":"main"}`)
	if code != 200 || out["store"] != "claude-main" || out["email"] != "acct-1@example.com" {
		t.Fatal(code, out)
	}
	// Add of a name that exists is its sign-in
	if code, out := appDo(t, r, "POST", "/api/claude-accounts", `{"name":"claude-main"}`); code != 200 || out["store"] != "claude-main" {
		t.Fatal("the same name twice", code, out)
	}
	// a second slot signed in to the same Claude account: the fresh grant lands in that account's own store
	if code, out := signIn(t, r, "/api/claude-accounts", `{"name":"work"}`); code != 200 || out["store"] != "claude-main" || !strings.Contains(out["note"].(string), "added as a new account, claude-main") {
		t.Fatal("the same Claude account in two slots", code, out)
	}
	f.accounts["new"] = "acct-2"
	if code, out := signIn(t, r, "/api/claude-accounts/claude-work/login", ""); code != 200 || out["email"] != "acct-2@example.com" {
		t.Fatal(code, out)
	}
	// a Re-login into an account as another Claude account: kept as that account's own, claude-work unchanged
	f.accounts["new"] = "acct-3"
	if code, out := signIn(t, r, "/api/claude-accounts/claude-work/login", ""); code != 200 || out["store"] != "claude-acct-3" {
		t.Fatal("a Re-login as another account", code, out)
	}
	if h := r.accounts().hub("claude-work"); accountUUID(h.current().Account) != "acct-2" {
		t.Fatal("a Re-login switched an account's Claude account")
	}
	if code, _ := appDo(t, r, "DELETE", "/api/claude-accounts/claude-acct-3", ""); code != 200 {
		t.Fatal("remove")
	}
	_, out = appDo(t, r, "GET", "/api/claude-accounts", "")
	rows := out["accounts"].([]any)
	if out["default"] != "claude-main" || len(rows) != 2 || rows[1].(map[string]any)["store"] != "claude-work" ||
		rows[1].(map[string]any)["email"] != "acct-2@example.com" || rows[0].(map[string]any)["default"] != true ||
		strings.Contains(jsonString(out), "at-new") {
		t.Fatal(out)
	}
	// usage per account
	if code, out := appDo(t, r, "GET", "/api/claude-accounts/claude-work/usage", ""); code != 200 || out["store"] != "claude-work" || len(out["limits"].([]any)) != 1 {
		t.Fatal(code, out)
	}
	// Remove: refused while a session uses it (a session keeps its account for its life), never moving the session
	addSession(r, "s1", "paused", "", false)
	r.st.Do(func(d *persisted) { d.Sessions["s1"].ClaudeAccount = "claude-main" })
	if code, out := appDo(t, r, "DELETE", "/api/claude-accounts/claude-main", ""); code != 409 || !strings.Contains(out["error"].(string), "s1") {
		t.Fatal("removed an account a session uses", code, out)
	}
	r.st.Do(func(d *persisted) {
		if d.Sessions["s1"].ClaudeAccount != "claude-main" {
			t.Fatal("the session was moved to another account")
		}
		delete(d.Sessions, "s1")
	})
	// the default can go: the next account becomes the default
	if code, out := appDo(t, r, "DELETE", "/api/claude-accounts/claude-main", ""); code != 200 || out["default"] != "claude-work" || r.accounts().hub("claude-main") != nil {
		t.Fatal("remove the default", code, out)
	}
	if _, err := os.Stat(filepath.Join(r.cfg.DataDir, "claude-accounts", "claude-main.json")); !os.IsNotExist(err) {
		t.Fatal("a removed account's pair stayed on the volume")
	}
	// the routes of the one shared login act on the default account
	if code, out := appDo(t, r, "GET", "/api/claude-login", ""); code != 200 || out["store"] != "claude-work" {
		t.Fatal(code, out)
	}
	// a router restart reads the accounts back
	r2 := NewRouter(Config{NoAccess: true, DataDir: r.cfg.DataDir}, r.st, nil, Policy{})
	if h := r2.accounts().hub("claude-work"); h == nil || accountUUID(h.current().Account) != "acct-2" || r2.accounts().defaultStore() != "claude-work" {
		t.Fatal("not read back")
	}
}

// the clean cut: the one shared login becomes the account claude-<email name>, and the sessions holding the old
// store `claude` use it
func TestClaudeAccountsMigrateSharedLogin(t *testing.T) {
	st, err := testState(t, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	exp := time.Now().Add(8 * time.Hour).UnixMilli()
	old, _ := json.Marshal(loginFile{Credentials: pairOf("a", exp), Account: `{"oauthAccount":{"accountUuid":"acct-1","emailAddress":"chendeyao.uk@gmail.com"}}`})
	os.WriteFile(filepath.Join(st.dir, "claude-login.json"), old, 0o600)
	st.Do(func(d *persisted) {
		d.Sessions["s1"] = &Session{ID: "s1", State: "started", MachineID: "m1", Harness: "claude", Stores: []string{"claude", "default"}}
		d.Sessions["s2"] = &Session{ID: "s2", State: "paused", Harness: "opencode", Stores: []string{"openrouter"}}
		d.Records = append(d.Records, &Record{Session: Session{ID: "s0", Harness: "claude", Stores: []string{"claude"}}})
		d.Machines["m1"] = "s1"
	})
	r := NewRouter(Config{NoAccess: true, DataDir: st.dir}, st, nil, Policy{})
	a := r.accounts()
	h := a.hub("claude-chendeyao-uk")
	if h == nil || h.current().ExpiresAt != exp || a.defaultStore() != "claude-chendeyao-uk" || a.jarvis1Hub() != h {
		t.Fatalf("%+v %s", h, a.defaultStore())
	}
	r.st.Do(func(d *persisted) {
		if d.Sessions["s1"].ClaudeAccount != "claude-chendeyao-uk" || d.Sessions["s2"].ClaudeAccount != "" || d.Records[0].ClaudeAccount != "claude-chendeyao-uk" {
			t.Fatalf("%+v %+v %+v", d.Sessions["s1"], d.Sessions["s2"], d.Records[0])
		}
	})
	if _, err := os.Stat(filepath.Join(st.dir, "claude-login.json")); !os.IsNotExist(err) {
		t.Fatal("the old file is still there: the next start would migrate again")
	}
	// the running session's machine keeps its pair coming
	m := newTestMachine(r, "m1")
	if code, out := m.do(t, r.MachineHandler(), "GET", "/m/claude-login?have=0", ""); code != 200 || !strings.Contains(out["credentials"].(string), "at-a") {
		t.Fatal(code, out)
	}
}

func TestSlugAndStoreNames(t *testing.T) {
	for in, want := range map[string]string{"chendeyao.uk@gmail.com": "chendeyao-uk", "A_B..c@x": "a-b-c", "@x": ""} {
		if got := slugFromEmail(in); got != want {
			t.Errorf("%q → %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{"work": "claude-work", "claude-work": "claude-work", "Work": "claude-work", "": "", "a--b": "", "claude-": "", "x y": ""} {
		if got := accountStoreName(in); got != want {
			t.Errorf("%q → %q, want %q", in, got, want)
		}
	}
}

// a new session gets the account it names, else the default; a harness without one gets none; the old store is refused
func TestNewSessionClaudeAccount(t *testing.T) {
	newFakeAnthropic(t)
	rg := newRig(t)
	r := rg.r
	r.policy = Policy{Harnesses: map[string]HarnessPolicy{"claude": {Stores: []string{"tunnel"}, ClaudeAccount: true}, "opencode": {Stores: []string{"openrouter"}}}}
	acct := func(id string) (s string) {
		r.st.Do(func(d *persisted) { s = d.Sessions[id].ClaudeAccount })
		return
	}
	t.Cleanup(func() { // each new session's approval is filed in the background: let it land before the dir goes
		waitFor(t, "the approvals filed", func() (ok bool) {
			r.st.Do(func(d *persisted) {
				n := 0
				for _, s := range d.Sessions {
					if s.State == "approval" {
						n++
					}
				}
				ok = len(d.Approvals) >= n
			})
			return
		})
	})
	// no account at all (a new box): it starts logged out
	if id, err := r.CreateSession(NewSession{Label: "x", Harness: "claude"}); err != nil || acct(id) != "" {
		t.Fatal("a Claude session with no account at all", err)
	}
	// bypass is the only start mode (Deyao, 2026-10-22): unnamed → bypass, bypass → bypass, anything else refused
	mode := func(id string) (m string) {
		r.st.Do(func(d *persisted) { m = d.Sessions[id].PermissionMode })
		return
	}
	if id, err := r.CreateSession(NewSession{Label: "m", Harness: "claude"}); err != nil || mode(id) != "bypass" {
		t.Fatal("no mode named", err, mode(id))
	}
	if id, err := r.CreateSession(NewSession{Label: "m", Harness: "claude", PermissionMode: "bypass"}); err != nil || mode(id) != "bypass" {
		t.Fatal("bypass named", err)
	}
	if _, err := r.CreateSession(NewSession{Label: "m", Harness: "claude", PermissionMode: "auto"}); err == nil || !strings.Contains(err.Error(), "only start mode") {
		t.Fatal("auto must be refused", err)
	}
	r.accounts().add("main")
	r.accounts().add("work")
	id, err := r.CreateSession(NewSession{Label: "x", Harness: "claude"})
	if err != nil || acct(id) != "claude-main" {
		t.Fatal(err, acct(id))
	}
	id, err = r.CreateSession(NewSession{Label: "y", Harness: "claude", Account: "work"})
	if err != nil || acct(id) != "claude-work" {
		t.Fatal(err, acct(id))
	}
	if _, err := r.CreateSession(NewSession{Label: "z", Harness: "claude", Account: "nope"}); err == nil {
		t.Fatal("an unknown account was taken")
	}
	// the old shared store is dropped, not refused: the session gets its account instead
	id, err = r.CreateSession(NewSession{Label: "z", Harness: "claude", Stores: []string{"claude"}})
	var zs []string
	r.st.Do(func(d *persisted) { zs = d.Sessions[id].Stores })
	if err != nil || containsStr(zs, "claude") || acct(id) == "" {
		t.Fatal("the old store: ", err, zs, acct(id))
	}
	id, err = r.CreateSession(NewSession{Label: "o", Harness: "opencode"})
	if err != nil || acct(id) != "" {
		t.Fatal(err, acct(id))
	}
	// an account named for a harness that takes none changes nothing
	if id, err := r.CreateSession(NewSession{Label: "o", Harness: "opencode", Account: "work"}); err != nil || acct(id) != "" {
		t.Fatal("an account for a harness that takes none", err, acct(id))
	}
	// the app's, the web page's and jarvis-request's body names it as "account"
	var ns NewSession
	json.Unmarshal([]byte(`{"label":"w","harness":"claude","account":"claude-work"}`), &ns)
	if id, err = r.CreateSession(ns); err != nil || acct(id) != "claude-work" {
		t.Fatal(err, acct(id))
	}
	// every made session's approval is filed in the background: let them land before the temp dir goes
	waitFor(t, "the approvals", func() bool {
		n := 0
		r.st.Do(func(d *persisted) { n = len(d.Approvals) })
		return n >= 5
	})
}

// the account goes into the signed settings only with SIGN_CLAUDE_ACCOUNT=1 (older phone apps refuse the key)
func TestClaudeAccountSignedWhenAsked(t *testing.T) {
	newFakeAnthropic(t)
	rg, vc := v2Rig(t)
	r := rg.r
	r.policy = Policy{Harnesses: map[string]HarnessPolicy{"claude": {ClaudeAccount: true}}}
	r.accounts().add("main")
	config := func() SessionConfig {
		var c SessionConfig
		opts, _ := vc.last("/succession")["options"].(map[string]any)
		if opts == nil || json.Unmarshal([]byte(opts["config"].(string)), &c) != nil {
			t.Fatalf("no config in %v", vc.last("/succession"))
		}
		return c
	}
	if _, err := r.CreateSession(NewSession{Label: "a", Prompt: "p", Harness: "claude"}); err != nil || config().ClaudeAccount != "" {
		t.Fatal("signed without the switch", err)
	}
	t.Setenv("SIGN_CLAUDE_ACCOUNT", "1")
	if _, err := r.CreateSession(NewSession{Label: "b", Prompt: "p", Harness: "claude"}); err != nil || config().ClaudeAccount != "claude-main" {
		t.Fatal("not signed with the switch", err, config())
	}
	waitFor(t, "the approvals", func() bool {
		n := 0
		r.st.Do(func(d *persisted) { n = len(d.Approvals) })
		return n >= 2
	})
}
