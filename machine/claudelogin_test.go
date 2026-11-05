package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func pairJSON(exp int64) string {
	return fmt.Sprintf(`{"claudeAiOauth":{"accessToken":"a%d","refreshToken":"r%d","expiresAt":%d}}`, exp, exp, exp)
}

// fakeLoginRouter: the router's /m/claude-login
type fakeLoginRouter struct {
	mu      sync.Mutex
	srv     *httptest.Server
	answers []routerLogin // served in turn, the last one repeated
	polls   []string      // the query of each poll
	pushes  []string
	none    bool // the session has no Claude account (404 noAccount)
}

func newFakeLoginRouter(t *testing.T) (*fakeLoginRouter, *client) {
	f := &fakeLoginRouter{}
	key := newKey()
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if strings.HasPrefix(req.URL.Path, "/m/") { // signed as the router checks it (router/http.go requireMachine)
			body, _ := io.ReadAll(req.Body)
			req.Body = io.NopCloser(bytes.NewReader(body))
			sum := sha256.Sum256(body)
			msg := req.Method + " " + req.URL.Path + " " + req.Header.Get("X-Time") + " " + hex.EncodeToString(sum[:])
			if !verify(key.pub(), []byte(msg), req.Header.Get("X-Sig")) {
				w.WriteHeader(401)
				return
			}
		}
		switch {
		case req.URL.Path == "/m/claude-login" && req.Method == "GET" && f.none:
			w.WriteHeader(404)
			w.Write([]byte(`{"error":"this session has no Claude account","noAccount":true}`))
		case req.URL.Path == "/m/claude-login" && req.Method == "GET":
			f.polls = append(f.polls, req.URL.RawQuery)
			a := f.answers[0]
			if len(f.answers) > 1 {
				f.answers = f.answers[1:]
			}
			json.NewEncoder(w).Encode(a)
		case req.URL.Path == "/m/claude-login" && req.Method == "POST":
			var b map[string]string
			json.NewDecoder(req.Body).Decode(&b)
			f.pushes = append(f.pushes, b["credentials"])
			w.Write([]byte(`{"stored":false}`))
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f, &client{base: f.srv.URL, me: "m1", sig: key.k, http: f.srv.Client()}
}

const acctRecord = `{"oauthAccount":{"accountUuid":"acct-1","emailAddress":"x"}}`

const acct2Record = `{"oauthAccount":{"accountUuid":"acct-2","emailAddress":"y"},"userID":"u2"}`

// a new session's Claude login comes from the router at boot (its Claude account's), whatever the account: no grant,
// no store key; a session the router names no account for gets none
func TestSessionClaudeLoginAtBoot(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	f, c := newFakeLoginRouter(t)
	f.answers = []routerLogin{{Credentials: pairJSON(2000), Account: acctRecord, ExpiresAt: 2000}}
	oldStart := startCredsSync
	defer func() { startCredsSync = oldStart }()
	started := 0
	startCredsSync = func() { started++ }

	f.none = true
	if acct := sessionClaudeLogin(c); acct != "" || started != 0 {
		t.Fatal("no Claude account for the session: nothing to do")
	}
	if _, err := os.Stat(credsPath()); err == nil {
		t.Fatal("a session with no account got a credentials file")
	}
	f.none = false
	acct := sessionClaudeLogin(c)
	if started != 1 || !strings.Contains(acct, "acct-1") {
		t.Fatalf("started %d account %q", started, acct)
	}
	b, err := os.ReadFile(credsPath())
	if err != nil || expiresAt(b) != 2000 {
		t.Fatalf("credentials file: %v %s", err, b)
	}
	if fi, _ := os.Stat(credsPath()); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
	if localAccount() != "acct-1" {
		t.Fatal("~/.claude.json didn't take the account")
	}
	// a resumed pair of the same account that expires later is kept
	os.WriteFile(credsPath(), []byte(pairJSON(3000)), 0o600)
	sessionClaudeLogin(c)
	if b, _ := os.ReadFile(credsPath()); expiresAt(b) != 3000 {
		t.Fatalf("a later pair was replaced: %s", b)
	}
	// a resume after a Re-login to another account: the restored ~/.claude.json takes the new account, other keys kept
	os.WriteFile(home(t)+"/.claude.json", []byte(`{"oauthAccount":{"accountUuid":"acct-1"},"projects":{"x":1}}`), 0o600)
	f.answers = []routerLogin{{Credentials: pairJSON(2500), Account: acct2Record, ExpiresAt: 2500}}
	sessionClaudeLogin(c)
	j, _ := os.ReadFile(home(t) + "/.claude.json")
	if localAccount() != "acct-2" || !strings.Contains(string(j), `"projects"`) || !strings.Contains(string(j), `"u2"`) {
		t.Fatalf("~/.claude.json: %s", j)
	}
}

// a switch to another account reaches a running machine: the router's pair wins even though the pair here (the old
// account's, refreshed by its own claude) expires later, and both files change under the running claude
func TestCredsSyncAccountSwitch(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	f, c := newFakeLoginRouter(t)
	os.MkdirAll(home(t)+"/.claude", 0o700)
	os.WriteFile(home(t)+"/.claude.json", []byte(acctRecord), 0o600)
	os.WriteFile(credsPath(), []byte(pairJSON(9000)), 0o600)
	quietAfterSwitch(t)
	s := &syncer{c: c, pushed: []byte(pairJSON(9000))}

	// the first answer only tells the router's account (its pair expires sooner than ours)
	f.answers = []routerLogin{{Account: acct2Record, ExpiresAt: 4000}, {Credentials: pairJSON(4000), Account: acct2Record, ExpiresAt: 4000}}
	if err := s.step(); err != nil {
		t.Fatal(err)
	}
	if err := s.step(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.polls[0], "have=9000") || !strings.Contains(f.polls[1], "have=0") {
		t.Fatalf("polls %v", f.polls)
	}
	if b, _ := os.ReadFile(credsPath()); expiresAt(b) != 4000 {
		t.Fatalf("the other account's pair wasn't taken: %s", b)
	}
	if localAccount() != "acct-2" {
		t.Fatal("~/.claude.json's oauthAccount wasn't switched")
	}
	if _, err := os.Stat(lockDir()); err == nil {
		t.Fatal("the CLI's refresh lock was left taken")
	}
	// in step again: the usual expiry rule
	f.answers = []routerLogin{{Account: acct2Record, ExpiresAt: 4000}}
	s.step()
	if !strings.Contains(f.polls[2], "have=4000") {
		t.Fatalf("polls %v", f.polls)
	}
}

// lessons/74 on the machine: a refresh notice takes the CLI's lock and acknowledges; the new pair is written, then the
// lock released; a failed refresh releases it
func TestCredsSyncLockProtocol(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	f, c := newFakeLoginRouter(t)
	os.MkdirAll(home(t)+"/.claude", 0o700)
	os.WriteFile(credsPath(), []byte(pairJSON(1000)), 0o600)
	s := &syncer{c: c, pushed: []byte(pairJSON(1000))}

	f.answers = []routerLogin{{ExpiresAt: 1000, Gen: 1, Preparing: true}}
	if err := s.step(); err != nil {
		t.Fatal(err)
	}
	if s.lockGen != 1 {
		t.Fatal("no lock taken")
	}
	if _, err := os.Stat(lockDir()); err != nil {
		t.Fatal("the CLI's lock dir isn't there")
	}
	f.answers = []routerLogin{{Credentials: pairJSON(5000), ExpiresAt: 5000, Gen: 1}}
	if err := s.step(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.polls[1], "ack=1") || !strings.Contains(f.polls[1], "have=1000") {
		t.Fatalf("the second poll must acknowledge: %v", f.polls)
	}
	if b, _ := os.ReadFile(credsPath()); expiresAt(b) != 5000 {
		t.Fatal("the new pair wasn't written")
	}
	if _, err := os.Stat(lockDir()); err == nil || s.lockGen != 0 {
		t.Fatal("the lock wasn't released after the write")
	}
	if len(f.pushes) != 0 {
		t.Fatal("the router's own pair was pushed back", f.pushes)
	}
	// a failed refresh: preparing, then not preparing with no newer pair → released
	f.answers = []routerLogin{{ExpiresAt: 5000, Gen: 2, Preparing: true}}
	s.step()
	f.answers = []routerLogin{{ExpiresAt: 5000, Gen: 2}}
	s.step()
	if _, err := os.Stat(lockDir()); err == nil || s.lockGen != 0 {
		t.Fatal("a failed refresh left the lock")
	}
	// a lock the CLI holds (it is refreshing itself) is never removed by us
	os.Mkdir(lockDir(), 0o700)
	f.answers = []routerLogin{{ExpiresAt: 5000, Gen: 3, Preparing: true}}
	s.step()
	f.answers = []routerLogin{{ExpiresAt: 5000, Gen: 3}}
	s.step()
	if _, err := os.Stat(lockDir()); err != nil {
		t.Fatal("the CLI's own lock was removed")
	}
	os.Remove(lockDir())
	// the session's claude refreshed by itself: its newer pair is pushed
	os.WriteFile(credsPath(), []byte(pairJSON(9000)), 0o600)
	f.answers = []routerLogin{{ExpiresAt: 5000}}
	s.step()
	if len(f.pushes) != 1 || expiresAt([]byte(f.pushes[0])) != 9000 {
		t.Fatal("the session's own refresh wasn't pushed", f.pushes)
	}
	// a lock held past lockHoldMax is released before the next poll (which then acknowledges nothing)
	f.answers = []routerLogin{{ExpiresAt: 9000, Gen: 4, Preparing: true}}
	s.step()
	if s.lockGen != 4 {
		t.Fatal("no lock for gen 4")
	}
	old := lockHoldMax
	lockHoldMax = 0
	defer func() { lockHoldMax = old }()
	f.answers = []routerLogin{{ExpiresAt: 9000}}
	s.step()
	if !strings.Contains(f.polls[len(f.polls)-1], "ack=0") || s.lockGen != 0 {
		t.Fatal("a stale lock wasn't released before the poll", f.polls[len(f.polls)-1])
	}
	if _, err := os.Stat(lockDir()); err == nil {
		t.Fatal("the stale lock is still there")
	}
}

func home(t *testing.T) string {
	h, _ := os.UserHomeDir()
	return h
}

func TestTakeIfLater(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if took, err := takeIfLater([]byte(`{}`)); took || err == nil {
		t.Fatal("a pair without expiresAt is refused")
	}
	if took, _ := takeIfLater([]byte(pairJSON(10))); !took {
		t.Fatal("no file: taken")
	}
	if took, _ := takeIfLater([]byte(pairJSON(10))); took {
		t.Fatal("same expiry: kept")
	}
	if took, _ := takeIfLater([]byte(pairJSON(11))); !took {
		t.Fatal("later: taken")
	}
}

// quietAfterSwitch: afterSwitch's waits made short and its outside world faked (no Anthropic, no tmux)
func quietAfterSwitch(t *testing.T) {
	saved := []time.Duration{recheckAfter, rcDropWait, rcMenuWait, rcUpWait, switchPoll}
	oldProfile, oldPane, oldKeys := profileOf, paneText, sendKeys
	recheckAfter, rcDropWait, rcMenuWait, rcUpWait, switchPoll = 10*time.Millisecond, 50*time.Millisecond, 50*time.Millisecond, 50*time.Millisecond, 5*time.Millisecond
	profileOf = func(string) (string, string, error) { return "acct-2", "acct-2@example.com", nil }
	paneText = func() string { return "" }
	sendKeys = func(...string) error { return nil }
	t.Cleanup(func() {
		recheckAfter, rcDropWait, rcMenuWait, rcUpWait, switchPoll = saved[0], saved[1], saved[2], saved[3], saved[4]
		profileOf, paneText, sendKeys = oldProfile, oldPane, oldKeys
	})
}

// after the files changed: the token's account is checked and its proof written for the status; an old record
// written back by claude is set again; Remote Control, stopped by Claude Code, is enabled again through its menu
func TestAfterSwitchProofAndRemoteControl(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	os.MkdirAll(home(t)+"/.claude/sessions", 0o700)
	quietAfterSwitch(t)
	rcDropWait, rcMenuWait, rcUpWait = 3*time.Second, 3*time.Second, 3*time.Second
	reg := func(bridge string) {
		b, _ := json.Marshal(map[string]any{"status": "idle", "pid": os.Getpid(), "bridgeSessionId": bridge})
		os.WriteFile(home(t)+"/.claude/sessions/1.json", b, 0o600)
	}
	reg("cse_old")
	os.WriteFile(home(t)+"/.claude.json", []byte(acctRecord), 0o600) // claude's profile fetch put the old record back
	var mu sync.Mutex
	pane, keys := "", []string{}
	paneText = func() string { mu.Lock(); defer mu.Unlock(); return pane }
	sendKeys = func(a ...string) error {
		mu.Lock()
		defer mu.Unlock()
		keys = append(keys, strings.Join(a, " "))
		switch strings.Join(a, " ") {
		case "Enter":
			if strings.Contains(pane, rcEnableText) {
				pane = ""
				reg("cse_new")
			} else if len(keys) == 2 {
				pane = "Remote Control\n ❯ 1. " + rcEnableText + "  Opens a secure connection"
			}
		}
		return nil
	}
	go func() {
		time.Sleep(100 * time.Millisecond)
		mu.Lock()
		pane = "signed-in claude.ai account or " + rcChangedText + " on this machine — run /remote-control"
		mu.Unlock()
	}()
	l := routerLogin{Credentials: pairJSON(4000), Account: acct2Record}
	done := make(chan struct{})
	go func() { afterSwitch(l, nil); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("afterSwitch hung")
	}
	if b, err := os.ReadFile(accountProof()); err != nil || !strings.Contains(string(b), `"acct-2"`) {
		t.Fatalf("proof: %v %s", err, b)
	}
	if localAccount() != "acct-2" {
		t.Fatal("the old record written back by claude stayed")
	}
	if strings.Join(keys, "|") != "-l /remote-control|Enter|Enter" || liveBridge() != "cse_new" {
		t.Fatalf("keys %q, bridge %s", keys, liveBridge())
	}
}

// the installed token turns out to be another account's: no proof, nothing typed
func TestAfterSwitchWrongAccount(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	os.MkdirAll(home(t)+"/.claude", 0o700)
	quietAfterSwitch(t)
	profileOf = func(string) (string, string, error) { return "acct-9", "other@example.com", nil }
	typed := false
	sendKeys = func(...string) error { typed = true; return nil }
	afterSwitch(routerLogin{Credentials: pairJSON(4000), Account: acct2Record}, nil)
	if _, err := os.Stat(accountProof()); err == nil || typed {
		t.Fatal("a proof for the wrong account, or keys typed")
	}
}

// boot writes the Claude login marker seconds after "booted": the supervisor starts the sync whenever it appears
func TestCredsSyncStartsWhenTheMarkerComesLate(t *testing.T) {
	d := t.TempDir()
	oldOn, oldPoll, oldRun := claudeLoginOn, markerPoll, runCredsSync
	defer func() { claudeLoginOn, markerPoll, runCredsSync = oldOn, oldPoll, oldRun; credsSyncOn.Store(false) }()
	claudeLoginOn, markerPoll = d+"/claude-login", 10*time.Millisecond
	started := make(chan struct{}, 2)
	runCredsSync = func() { credsSyncOn.Store(true); started <- struct{}{} }
	done := make(chan struct{})
	go func() { startCredsSyncOnMarker(); close(done) }()
	time.Sleep(100 * time.Millisecond) // booted, no marker yet
	select {
	case <-started:
		t.Fatal("started with no marker")
	default:
	}
	os.WriteFile(claudeLoginOn, []byte("1"), 0o644)
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("the sync never started once the marker came")
	}
	<-done
	// already running (the "claude-account" command started it): nothing more
	startCredsSyncOnMarker()
	select {
	case <-started:
		t.Fatal("started twice")
	case <-time.After(50 * time.Millisecond):
	}
}

// the router's pair (no refresh token: forMachine) is never pushed back, even on the first step after boot
func TestCredsSyncNoPushWithoutRefreshToken(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	f, c := newFakeLoginRouter(t)
	os.MkdirAll(home(t)+"/.claude", 0o700)
	os.WriteFile(credsPath(), []byte(`{"claudeAiOauth":{"accessToken":"a1","expiresAt":1000}}`), 0o600)
	s := &syncer{c: c}
	f.answers = []routerLogin{{ExpiresAt: 1000}}
	if err := s.step(); err != nil {
		t.Fatal(err)
	}
	if len(f.pushes) != 0 {
		t.Fatal("the router's pair was pushed back", f.pushes)
	}
}
