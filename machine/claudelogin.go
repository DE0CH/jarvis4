package main

// The Claude login: the OAuth pair of the session's Claude account, kept and refreshed by the router
// (router/claudelogin.go, claudeaccounts.go: one account per session, picked when it is made and fixed). A session
// with an account (the router says so: /m/claude-login answers 404 noAccount otherwise) takes the pair at boot over the
// signed /m channel and keeps in step for the machine's life (credsSync, the supervisor's Claude login sync): a long poll that answers
// with a newer pair, or with "a refresh is coming" — then credsSync takes the CLI's own refresh lock
// (~/.claude/.oauth_refresh.lock, lessons/74) until the new pair is written, so a claude process that gets a 401 in
// between waits and adopts it instead of burning its refresh token.
//
// The router's pair is taken whatever its account (DECISIONS 116, 185, 202: trust the router). When it belongs to
// another account than the one on this machine (Deyao switched the session's account, POST /api/sessions/{id}/account,
// or re-logged its account as another Claude account), the switch happens UNDER the running claude, which is just a
// process reading files (switchInPlace): under the CLI's refresh lock the new pair replaces ~/.claude/.credentials.json
// and the account record replaces ~/.claude.json's oauthAccount, both atomically. Claude Code stats the credentials
// file before every API request and re-reads it when it changed, and watches ~/.claude.json, so its next request goes
// out on the new account: no restart, no --resume; background shells, agents and monitors keep running. Then
// (afterSwitch): the installed token's account is checked with Anthropic's profile endpoint and reported in the status
// (__ACCOUNT__, the router's proof the switch took), and Remote Control, which Claude Code stops when the account under
// it changes ("signed-in claude.ai account or organization changed"), is started again by typing /remote-control into
// the host and choosing "Enable Remote Control".

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

var (
	credsPollWait = 50 * time.Second
	credsRetry    = 10 * time.Second
	lockHoldMax   = 45 * time.Second // a lock held for a refresh that never answered is released (the CLI's own stale limit is 60 s)
)

type routerLogin struct {
	Credentials string `json:"credentials"`
	Account     string `json:"account"`
	ExpiresAt   int64  `json:"expiresAt"`
	Gen         int64  `json:"gen"`
	Preparing   bool   `json:"preparing"`
}

func credsPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".claude", ".credentials.json")
}

func expiresAt(raw []byte) int64 {
	var d struct {
		O struct {
			ExpiresAt int64 `json:"expiresAt"`
		} `json:"claudeAiOauth"`
	}
	json.Unmarshal(raw, &d)
	return d.O.ExpiresAt
}

func accessToken(raw []byte) string {
	var d struct {
		O struct {
			AccessToken string `json:"accessToken"`
		} `json:"claudeAiOauth"`
	}
	json.Unmarshal(raw, &d)
	return d.O.AccessToken
}

func recordAccount(account string) string {
	var d struct {
		O struct {
			UUID string `json:"accountUuid"`
		} `json:"oauthAccount"`
	}
	json.Unmarshal([]byte(account), &d)
	return d.O.UUID
}

// localAccount: the account of the login on this machine (~/.claude.json's); "" = not known
func localAccount() string {
	home, _ := os.UserHomeDir()
	b, _ := os.ReadFile(filepath.Join(home, ".claude.json"))
	return recordAccount(string(b))
}

// takeRouterPair: write the router's pair; one for another account than this machine's always wins, and is switched
// to under the running claude (switchInPlace)
func takeRouterPair(l routerLogin) (took, switched bool, err error) {
	ra, la := recordAccount(l.Account), localAccount()
	if ra == "" || la == "" || ra == la {
		took, err = takeIfLater([]byte(l.Credentials))
		return took, false, err
	}
	if err = switchInPlace(l); err != nil {
		return false, false, err
	}
	return true, true, nil
}

// errNoAccount: the router says this session has no Claude account (404; 403 from a router before accounts)
var errNoAccount = errors.New("this session has no Claude account")

// fetchLogin: one poll; the path is signed as every /m call, the query (numbers only) travels beside it as on the
// session API proxy (apiproxy.go)
func fetchLogin(c *client, have, ack int64, wait time.Duration) (routerLogin, error) {
	var l routerLogin
	status, _, b, err := c.signedDo("GET", "/m/claude-login", "/m/claude-login", fmt.Sprintf("have=%d&ack=%d&wait=%d", have, ack, int(wait.Seconds())), nil, "")
	if err != nil {
		return l, err
	}
	if status == 404 || status == 403 {
		return l, errNoAccount
	}
	if status != 200 {
		return l, fmt.Errorf("GET /m/claude-login: HTTP %d", status)
	}
	return l, json.Unmarshal(b, &l)
}

// sessionClaudeLogin: a session's first Claude login, at boot, before the harness starts (Deyao, 2026-10-11: a new
// session logs in by itself, no grant, no Face ID). Returns the account record (~/.claude.json oauthAccount) for
// CLAUDE_ACCOUNT, "" when there is none. A session the router names no account for (opencode, a run task) skips it.
func sessionClaudeLogin(c *client) string {
	var l routerLogin
	var err error
	for i := 0; i < 3; i++ { // a short retry: the harness starts right after, logged in or not (credsSync catches up)
		if l, err = fetchLogin(c, 0, 0, 0); err == nil && l.Credentials == "" {
			err = errors.New("the router holds no Claude login for this session's account")
		}
		if err == nil || errors.Is(err, errNoAccount) {
			break
		}
		time.Sleep(2 * time.Second)
	}
	if errors.Is(err, errNoAccount) {
		log.Printf("claude login: none (the session has no Claude account)")
		return ""
	}
	if err != nil {
		log.Printf("claude login: at boot: %v (credsSync keeps trying)", err)
		startCredsSync()
		return ""
	}
	// the host hasn't started: its ~/.claude.json takes the account now (the entrypoint merges CLAUDE_ACCOUNT too)
	if recordAccount(l.Account) != "" && recordAccount(l.Account) != localAccount() {
		if err := mergeAccount(l.Account); err != nil {
			log.Printf("claude login: ~/.claude.json: %v", err)
		}
	}
	switch took, werr := takeIfLater([]byte(l.Credentials)); {
	case werr != nil:
		log.Printf("claude login: writing the credentials file: %v", werr)
	case took:
		log.Printf("claude login: took the router's pair at boot")
	default:
		log.Printf("claude login: the pair here expires as late or later; kept")
	}
	startCredsSync()
	return l.Account
}

// mergeAccount: the account record's keys (oauthAccount, userID) into ~/.claude.json, the rest kept
func mergeAccount(account string) error {
	var rec map[string]any
	if err := json.Unmarshal([]byte(account), &rec); err != nil {
		return err
	}
	home, _ := os.UserHomeDir()
	p := filepath.Join(home, ".claude.json")
	cur := map[string]any{}
	if b, err := os.ReadFile(p); err == nil {
		json.Unmarshal(b, &cur)
	}
	for k, v := range rec {
		cur[k] = v
	}
	b, _ := json.Marshal(cur)
	return writeAtomic(p, b)
}

// startCredsSync: tells supervisor-normal to run credsSync for the machine's life (its Claude login sync component,
// supervisor.go): boot (or an account switch) leaves claudeLoginOn, supervisor-normal starts it once booted. A var so tests don't.
var startCredsSync = func() {
	if err := os.WriteFile(claudeLoginOn, []byte("1"), 0o644); err != nil {
		log.Printf("claude login: %v", err)
		return
	}
	log.Printf("claude login: the supervisor keeps the pair in step (long poll on the router)")
}

var claudeLoginOn = dir + "/claude-login"

var (
	markerPoll   = 2 * time.Second
	runCredsSync = func() { credsSync() } // tests: a stand-in
)

// startCredsSyncOnMarker: credsSync as soon as boot leaves claudeLoginOn. Boot writes it after bootedPath (its login
// fetch takes seconds), so it is watched for the machine's life, not looked at once when booted: a supervisor that
// looked once, before the marker, never kept the pair in step, and the session lost its login at the account's next
// refresh (YYC AI on Jarvis 3, 2026-10-20). A session with no account never gets the marker: a stat every 2 s.
func startCredsSyncOnMarker() {
	for !credsSyncOn.Load() {
		if _, err := os.Stat(claudeLoginOn); err == nil {
			go runCredsSync()
			return
		}
		time.Sleep(markerPoll)
	}
}

// writeAtomic: 0600, through a rename
func writeAtomic(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".new"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// takeIfLater: write the pair unless the file here already expires as late or later; atomic, 0600
func takeIfLater(creds []byte) (bool, error) {
	ne := expiresAt(creds)
	if ne == 0 {
		return false, errors.New("the pair has no expiresAt")
	}
	if cur, err := os.ReadFile(credsPath()); err == nil && expiresAt(cur) >= ne {
		return false, nil
	}
	return true, writeAtomic(credsPath(), creds)
}

// ---- the CLI's refresh lock (Jarvis 1's LOCK_PY / UNLOCK_PY, lib/claudelogin.js) ----------------------------------

func lockDir() string { return filepath.Join(filepath.Dir(credsPath()), ".oauth_refresh.lock") }
func lockMark() string {
	return filepath.Join(filepath.Dir(credsPath()), ".jarvis-refresh-lock")
}

type lockMarker struct {
	Ino   uint64 `json:"ino"`
	Mtime int64  `json:"mtime"`
}

func lockID(fi os.FileInfo) lockMarker {
	m := lockMarker{Mtime: fi.ModTime().UnixNano()}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		m.Ino = st.Ino
	}
	return m
}

// releaseLock: removes the lock only while it is still the one this machine made (a lock the CLI re-took after
// ours went stale has another inode or mtime)
func releaseLock() {
	b, err := os.ReadFile(lockMark())
	if err != nil {
		return
	}
	var m lockMarker
	json.Unmarshal(b, &m)
	if fi, err := os.Stat(lockDir()); err == nil && lockID(fi) == m {
		os.Remove(lockDir())
	}
	os.Remove(lockMark())
}

// takeLock: "locked", or "busy" (a claude process is refreshing right now)
func takeLock() string {
	releaseLock() // one left from an earlier run that never got its pair
	os.MkdirAll(filepath.Dir(lockDir()), 0o700)
	if err := os.Mkdir(lockDir(), 0o700); err != nil {
		return "busy"
	}
	fi, err := os.Stat(lockDir())
	if err != nil {
		return "busy"
	}
	b, _ := json.Marshal(lockID(fi))
	os.WriteFile(lockMark(), b, 0o600)
	return "locked"
}

// ---- credsSync ------------------------------------------------------------------------------------------------------

// credsSync: the machine's side of the router's login protocol, for the machine's life
func credsSync() {
	if !credsSyncOn.CompareAndSwap(false, true) {
		return
	}
	c, err := newClient()
	if err != nil {
		log.Printf("claude login: credsSync can't run: %v", err)
		return
	}
	s := &syncer{c: c}
	for {
		if err := s.step(); err != nil {
			log.Printf("claude login: %v", err)
			time.Sleep(credsRetry)
		}
	}
}

type syncer struct {
	c         *client
	pushed    []byte    // the content last pushed or taken
	routerAcc string    // the account of the router's login, from its last answer
	lockGen   int64     // the router's refresh this machine holds the CLI lock for (0: none)
	lockedAt  time.Time // when it took it
}

func (s *syncer) release() {
	if s.lockGen != 0 {
		releaseLock()
		s.lockGen = 0
	}
}

// step: push this machine's own newer pair (its claude refreshed by itself), then one long poll and its answer
func (s *syncer) step() error {
	local, _ := os.ReadFile(credsPath())
	if s.lockGen != 0 && time.Since(s.lockedAt) > lockHoldMax {
		log.Printf("claude login: no pair %s after the refresh notice: lock released", lockHoldMax)
		s.release()
	}
	if len(local) > 0 && !bytes.Equal(local, s.pushed) && s.lockGen == 0 {
		var out map[string]any
		if err := s.c.json("POST", "/m/claude-login", map[string]string{"credentials": string(local)}, &out); err != nil {
			log.Printf("claude login: push: %v", err)
		}
		s.pushed = local
	}
	have := expiresAt(local)
	if la := localAccount(); s.routerAcc != "" && la != "" && s.routerAcc != la {
		have = 0 // the router holds another account's login: asked for whatever its expiry
	}
	l, err := fetchLogin(s.c, have, s.lockGen, credsPollWait)
	if err != nil {
		return fmt.Errorf("poll: %w", err)
	}
	s.routerAcc = recordAccount(l.Account)
	switch {
	case l.Credentials != "" && l.ExpiresAt > have:
		took, switched, err := takeRouterPair(l)
		s.release() // after the write: a claude process waiting on the lock re-reads the file and adopts the pair
		if err != nil {
			return fmt.Errorf("writing the credentials file: %w", err)
		}
		if took {
			s.pushed = []byte(l.Credentials)
			log.Printf("claude login: took the router's newer pair")
		}
		if switched {
			go afterSwitch(l, s.c) // the account check and Remote Control, while the poll goes on
		}
	case l.Preparing && l.Gen != s.lockGen:
		s.release()
		if took := takeLock(); took == "locked" {
			s.lockGen, s.lockedAt = l.Gen, time.Now()
		} else {
			// a claude process is refreshing right now (no marker of ours: release() leaves its lock alone);
			// acknowledge anyway so the router doesn't wait for us
			s.lockGen, s.lockedAt = l.Gen, time.Now()
		}
	case !l.Preparing && s.lockGen != 0:
		s.release() // the refresh is over (failed): the pair here stays
	}
	return nil
}

// ---- an account switch, under the running claude ----------------------------------------------------------------

var (
	credsSyncOn    atomic.Bool // credsSync runs (once per machine)
	switchLockWait = 15 * time.Second
	switchPoll     = time.Second
	recheckAfter   = 15 * time.Second // a profile fetch claude began with the old token may write the old record back
	rcDropWait     = 90 * time.Second // for Claude Code to stop Remote Control once the account under it changed
	rcMenuWait     = 3 * time.Minute  // for the /remote-control menu (a host in a turn shows it after the turn)
	rcUpWait       = 90 * time.Second
	profileTries   = 5

	oauthProfileURL = "https://api.anthropic.com/api/oauth/profile"
	profileHTTP     = &http.Client{Timeout: 20 * time.Second}
	paneText        = func() string {
		out, _ := sessionCommand(nil, "tmux", "capture-pane", "-p", "-t", "claude").Output()
		return string(out)
	}
	sendKeys = func(args ...string) error {
		return sessionCommand(nil, "tmux", append([]string{"send-keys", "-t", "claude"}, args...)...).Run()
	}
)

const (
	rcChangedText = "account or organization changed" // Claude Code's notice when it stops Remote Control for it
	rcEnableText  = "Enable Remote Control"           // the /remote-control menu's first choice (claude 2.1.304)
)

// accountProof: the account of the installed token as Anthropic's profile endpoint names it, written once checked;
// the status reports it (__ACCOUNT__), which is how the router knows the switch took
func accountProof() string { return filepath.Join(filepath.Dir(credsPath()), ".jarvis-account") }

// switchInPlace: the new account's pair and record, under the CLI's refresh lock so no refresh of the old account is
// cut in half
func switchInPlace(l routerLogin) error {
	locked := false
	for end := time.Now().Add(switchLockWait); ; time.Sleep(200 * time.Millisecond) {
		if takeLock() == "locked" {
			locked = true
			break
		}
		if time.Now().After(end) {
			break
		}
	}
	if locked {
		defer releaseLock()
	} else {
		log.Printf("claude login: the CLI's refresh lock stayed taken for %s: switching anyway", switchLockWait)
	}
	os.Remove(accountProof()) // the old account's
	if err := writeAtomic(credsPath(), []byte(l.Credentials)); err != nil {
		return err
	}
	if err := mergeAccount(l.Account); err != nil {
		return fmt.Errorf("~/.claude.json: %w", err)
	}
	log.Printf("claude login: switched to the Claude account %s under the running claude (credentials and oauthAccount; its next request goes out on it)", recordEmail(l.Account))
	return nil
}

func recordEmail(account string) string {
	var d struct {
		O struct {
			Email string `json:"emailAddress"`
		} `json:"oauthAccount"`
	}
	json.Unmarshal([]byte(account), &d)
	if d.O.Email == "" {
		return recordAccount(account)
	}
	return d.O.Email
}

// afterSwitch: the installed token's account checked with Anthropic, the record kept, Remote Control back
func afterSwitch(l routerLogin, c *client) {
	want := recordAccount(l.Account)
	oldBridge := liveBridge()
	checked := false
	for i := 0; i < profileTries && !checked; i++ {
		uuid, email, err := profileOf(accessToken([]byte(l.Credentials)))
		switch {
		case err != nil:
			log.Printf("claude login: checking the installed token's account: %v", err)
			time.Sleep(5 * time.Second)
		case uuid != want:
			log.Printf("claude login: the installed token belongs to %s, not the account the router named", email)
			return
		default:
			b, _ := json.Marshal(map[string]any{"accountUuid": uuid, "email": email, "at": time.Now().Unix()})
			if err := writeAtomic(accountProof(), b); err != nil {
				log.Printf("claude login: %v", err)
			}
			log.Printf("claude login: the installed token is %s's (Anthropic's profile)", email)
			checked = true
		}
	}
	time.Sleep(recheckAfter)
	if localAccount() != want {
		if err := mergeAccount(l.Account); err != nil {
			log.Printf("claude login: ~/.claude.json: %v", err)
		} else {
			log.Printf("claude login: ~/.claude.json had the old account again (claude's own profile fetch): set again")
		}
	}
	if proxyLogin(certHarness()) { // harnesses.go: Claude Code · Paseo, no Remote Control; api-proxy.js sends the new pair
		log.Printf("claude login: the harness's API proxy sends the new account's login from its next request (no Remote Control here)")
		return
	}
	enableRemoteControl(oldBridge)
}

// profileOf: the account Anthropic's profile endpoint names for a token
var profileOf = func(token string) (uuid, email string, err error) {
	req, _ := http.NewRequest("GET", oauthProfileURL, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("anthropic-beta", "oauth-2025-04-20")
	req.Header.Set("User-Agent", "jarvis-machine/1")
	resp, err := profileHTTP.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", "", fmt.Errorf("profile: HTTP %d", resp.StatusCode)
	}
	var p struct {
		Account struct {
			UUID  string `json:"uuid"`
			Email string `json:"email"`
		} `json:"account"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&p); err != nil || p.Account.UUID == "" {
		return "", "", errors.New("profile: no account in the answer")
	}
	return p.Account.UUID, p.Account.Email, nil
}

// enableRemoteControl: Claude Code stops Remote Control when the account under it changes; typing /remote-control and
// choosing "Enable Remote Control" starts it again for the new account (a new entry in that account's Claude app, the
// same conversation). Nothing to do when there was none before the switch.
func enableRemoteControl(oldBridge string) {
	if oldBridge == "" {
		log.Printf("claude login: no Remote Control before the switch: nothing to bring back")
		return
	}
	if !waitUntil(rcDropWait, func() bool {
		return strings.Contains(paneText(), rcChangedText) || liveBridge() != oldBridge
	}) {
		log.Printf("claude login: Remote Control is still up %s after the switch: left as it is", rcDropWait)
		return
	}
	if b := liveBridge(); b != "" && b != oldBridge {
		log.Printf("claude login: Remote Control came back by itself")
		return
	}
	log.Printf("claude login: Claude Code stopped Remote Control for the account change: typing /remote-control")
	rcTyping.Lock() // rcwatch.go
	defer rcTyping.Unlock()
	if err := sendKeys("-l", "/remote-control"); err == nil {
		time.Sleep(300 * time.Millisecond)
		err = sendKeys("Enter")
	}
	if !waitUntil(rcMenuWait, func() bool { return strings.Contains(paneText(), rcEnableText) }) {
		log.Printf("claude login: the /remote-control menu didn't show within %s", rcMenuWait)
		return
	}
	sendKeys("Enter") // its first choice, selected: Enable Remote Control
	if waitUntil(rcUpWait, func() bool { b := liveBridge(); return b != "" && b != oldBridge }) {
		log.Printf("claude login: Remote Control is up again under the new account")
	} else {
		log.Printf("claude login: Remote Control didn't come up within %s of choosing Enable", rcUpWait)
	}
}

func waitUntil(d time.Duration, ok func() bool) bool {
	for end := time.Now().Add(d); ; time.Sleep(switchPoll) {
		if ok() {
			return true
		}
		if time.Now().After(end) {
			return false
		}
	}
}

// liveBridge: the Remote Control session id of the live claude host, from claude's own session registry
// (~/.claude/sessions/*.json, what the status reports); "" = none
func liveBridge() string {
	home, _ := os.UserHomeDir()
	files, _ := filepath.Glob(filepath.Join(home, ".claude", "sessions", "*.json"))
	for _, f := range files {
		var e struct {
			Pid             int    `json:"pid"`
			BridgeSessionID string `json:"bridgeSessionId"`
		}
		b, err := os.ReadFile(f)
		if err != nil || json.Unmarshal(b, &e) != nil || e.BridgeSessionID == "" || e.Pid == 0 {
			continue
		}
		if syscall.Kill(e.Pid, 0) == nil {
			return e.BridgeSessionID
		}
	}
	return ""
}

// claudeAccountCmd: the router switched the session's Claude account (supervisor-core's command "claude-account"; the
// long poll brings the pair, credsSync switches): a session that had no account leaves the marker, and
// supervisor-normal starts its sync (startCredsSyncOnMarker)
func claudeAccountCmd() {
	log.Printf("claude login: the router switched this session's Claude account")
	if _, err := os.Stat(claudeLoginOn); err != nil {
		startCredsSync()
	}
}
