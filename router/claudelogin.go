package main

// The Claude login of one Claude account (Jarvis 1's lib/oauth.js, lib/claudelogin.js, /api/credentials, /api/usage
// and its Re-login, moved here; docs/DECISIONS.md 115-121, 185). Each account is a Claude key store of the router's
// own, `claude-<name>` (claudeaccounts.go): one hub per account, its pair on the router's volume
// (claude-accounts/<store>.json, 0600), and this router is its ONLY refresher. A refresh revokes the previous access
// token at once, so there is one refresher: this router. Jarvis 1, while it still runs, only follows one account
// (reads its pair from here).
//
// Who takes an account's pair, all with the same long poll (GET …/claude-login?have=&ack=&wait=):
//   - a session machine whose session uses that account (Session.ClaudeAccount, fixed when the session is made;
//     /m/claude-login, signed with its machine key);
//   - Jarvis 1, while it still runs, for its own sessions (/peer/claude-login, behind a path-scoped Access app that
//     admits one service token, JARVIS1_LOGIN_CLIENT_ID). Jarvis 2 never calls Jarvis 1.
// The refresh protocol keeps lessons/74's guarantee (a session that gets a 401 mid-refresh waits for the new pair
// instead of burning its refresh token): before refreshing, the hub answers every waiting poll with
// {preparing, gen}; each participant takes the CLI's refresh lock (~/.claude/.oauth_refresh.lock) and polls again
// with ack=gen; the hub waits for every participant seen in the last 2 minutes (at most 10 s), refreshes,
// writes the pair to its volume, then answers every poll with it; a participant writes the file and releases the
// lock. A failed refresh answers {preparing: false}: participants release.
//
// Pushes (a participant whose claude refreshed by itself, e.g. while the router was down): newer expiresAt wins,
// and the pair's account must be the hub's (checked with Anthropic's profile endpoint). A Re-login (Deyao's own
// action) must be the hub's account too, once it has one (claudeaccounts.go checks it).

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The Claude Code CLI's own OAuth parameters (read from claude 2.1.296: dn().TOKEN_URL, CLAUDE_AI_AUTHORIZE_URL,
// MANUAL_REDIRECT_URL, CLIENT_ID, the scopes of `claude auth login --claudeai`; lessons/39). Vars: tests point
// them at stand-ins.
var (
	oauthTokenURL     = "https://platform.claude.com/v1/oauth/token"
	oauthAuthorizeURL = "https://claude.com/cai/oauth/authorize"
	oauthRedirectURL  = "https://platform.claude.com/oauth/code/callback"
	oauthProfileURL   = "https://api.anthropic.com/api/oauth/profile"
	oauthUsageURL     = "https://api.anthropic.com/api/oauth/usage"
	oauthClientID     = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
	oauthScopes       = []string{"org:create_api_key", "user:profile", "user:inference", "user:sessions:claude_code", "user:mcp_servers", "user:file_upload", "user:plugins"}
	loginHTTP         = &http.Client{Timeout: 30 * time.Second}
)

const (
	loginFreshMargin = 30 * time.Minute // refresh when less is left (Jarvis 1's FRESH_MARGIN_MS)
	loginRetry       = 5 * time.Minute  // after a failed refresh, don't hammer the endpoint
	loginAckWait     = 10 * time.Second // the longest a refresh waits for participants to take their locks
	loginSeenWindow  = 2 * time.Minute  // a participant counts while it polled this recently
	loginPollMax     = 55 * time.Second // under Cloudflare's 100 s proxy timeout (Jarvis 1 polls through it)
	loginPendingTTL  = 15 * time.Minute // a Re-login's code must come within this
)

var (
	errNoPair    = errors.New("no Claude login stored: Re-login")
	errNotNewer  = errors.New("not newer than the stored pair")
	errOtherAcct = errors.New("the pair belongs to another Claude account than the stored one")
)

type loginFail struct {
	At        time.Time `json:"at"`
	Error     string    `json:"error"`
	ExpiresAt int64     `json:"expiresAt"` // of the pair whose refresh failed
	Rejected  bool      `json:"rejected"`  // the token endpoint said no (not a network error): only a Re-login helps
	Notified  bool      `json:"notified"`  // the dead-login DM went out for this pair
}

type pendingLogin struct {
	Verifier string    `json:"verifier"`
	State    string    `json:"state"`
	At       time.Time `json:"at"`
}

// loginFile: claude-login.json on the router's volume
type loginFile struct {
	Credentials string        `json:"credentials,omitempty"` // ~/.claude/.credentials.json
	Account     string        `json:"account,omitempty"`     // ~/.claude.json's {oauthAccount, userID}
	Source      string        `json:"source,omitempty"`      // where the stored pair came from
	UpdatedAt   time.Time     `json:"updatedAt"`
	RefreshedAt time.Time     `json:"refreshedAt"`
	Fail        *loginFail    `json:"fail,omitempty"`
	Pending     *pendingLogin `json:"pending,omitempty"`
}

type loginHub struct {
	path      string
	store     string // the account's key store, claude-<name>
	mu        sync.Mutex
	f         loginFile
	changed   chan struct{} // closed and replaced on every change (pair, phase, acks)
	gen       int64
	preparing bool
	acks      map[string]int64
	seen      map[string]time.Time
	refreshMu sync.Mutex // one refresh (or Re-login exchange) at a time
	usage     struct {
		at   time.Time
		body map[string]any
	}
	dm func(string)
	// check: a Re-login's account (uuid) may land in this hub (claudeaccounts.go: the hub's own account, and no other
	// hub's); nil = any
	check func(uuid string) error
	// elsewhere: the hub a sign-in that check turned away belongs in instead (the account's own hub, or a new one), so
	// a fresh grant is never thrown away; nil = refuse
	elsewhere func(uuid, email string) (*loginHub, error)
}

func newLoginHub(path, store string) *loginHub {
	h := &loginHub{path: path, store: store, changed: make(chan struct{}), acks: map[string]int64{}, seen: map[string]time.Time{}}
	if b, err := os.ReadFile(h.path); err == nil {
		if err := json.Unmarshal(b, &h.f); err != nil {
			log.Printf("[login] %s unreadable: %v", h.path, err)
		}
	}
	return h
}

// save: atomic, 0600, synced (a refreshed pair must survive a crash right after: the old refresh token is dead)
func (h *loginHub) save() error {
	b, _ := json.MarshalIndent(h.f, "", " ")
	tmp := h.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp, h.path)
}

func (h *loginHub) broadcastLocked() {
	close(h.changed)
	h.changed = make(chan struct{})
}

// ---- the pair's shape -------------------------------------------------------------------------------------------

type oauthPair struct {
	AccessToken  string   `json:"accessToken"`
	RefreshToken string   `json:"refreshToken"`
	ExpiresAt    int64    `json:"expiresAt"`
	Scopes       []string `json:"scopes"`
}

func parsePair(credentials string) (oauthPair, map[string]any, error) {
	var d map[string]any
	if err := json.Unmarshal([]byte(credentials), &d); err != nil {
		return oauthPair{}, nil, errors.New("credentials are not JSON")
	}
	raw, _ := json.Marshal(d["claudeAiOauth"])
	var p oauthPair
	json.Unmarshal(raw, &p)
	if p.AccessToken == "" || p.RefreshToken == "" || p.ExpiresAt == 0 {
		return oauthPair{}, nil, errors.New("credentials must be a ~/.claude/.credentials.json object with claudeAiOauth.{accessToken,refreshToken,expiresAt}")
	}
	return p, d, nil
}

func credsExpiry(raw string) int64 {
	var d struct {
		O struct {
			ExpiresAt int64 `json:"expiresAt"`
		} `json:"claudeAiOauth"`
	}
	json.Unmarshal([]byte(raw), &d)
	return d.O.ExpiresAt
}

func accountUUID(account string) string {
	var d struct {
		O struct {
			UUID string `json:"accountUuid"`
		} `json:"oauthAccount"`
	}
	json.Unmarshal([]byte(account), &d)
	return d.O.UUID
}

func accountEmail(account string) string {
	var d struct {
		O struct {
			Email string `json:"emailAddress"`
		} `json:"oauthAccount"`
	}
	json.Unmarshal([]byte(account), &d)
	return d.O.Email
}

// ---- Anthropic's endpoints ----------------------------------------------------------------------------------------

type oauthProfile struct {
	Account struct {
		UUID        string `json:"uuid"`
		Email       string `json:"email"`
		DisplayName string `json:"display_name"`
		FullName    string `json:"full_name"`
		CreatedAt   string `json:"created_at"`
	} `json:"account"`
	Organization struct {
		UUID                  string         `json:"uuid"`
		OrganizationType      string         `json:"organization_type"`
		RateLimitTier         string         `json:"rate_limit_tier"`
		BillingType           string         `json:"billing_type"`
		HasExtraUsageEnabled  bool           `json:"has_extra_usage_enabled"`
		SubscriptionCreatedAt string         `json:"subscription_created_at"`
		CCOnboardingFlags     map[string]any `json:"cc_onboarding_flags"`
	} `json:"organization"`
}

func fetchProfile(accessToken string) (oauthProfile, error) {
	var p oauthProfile
	req, _ := http.NewRequest("GET", oauthProfileURL, nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("anthropic-beta", "oauth-2025-04-20")
	req.Header.Set("User-Agent", "jarvis2-router/1")
	resp, err := loginHTTP.Do(req)
	if err != nil {
		return p, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 200 {
		return p, fmt.Errorf("profile: HTTP %d", resp.StatusCode)
	}
	if err := json.Unmarshal(b, &p); err != nil || p.Account.UUID == "" {
		return p, errors.New("profile: no account in the answer")
	}
	return p, nil
}

// tokenCall: one POST to the token endpoint; rejected = a 4xx other than 429 (the grant is dead or the code wrong)
func tokenCall(body map[string]any) (map[string]any, bool, error) {
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", oauthTokenURL, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "jarvis2-router/1")
	resp, err := loginHTTP.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var j map[string]any
	json.Unmarshal(out, &j)
	if resp.StatusCode != 200 || j["access_token"] == nil {
		why := fmt.Sprint(j["error_description"])
		if why == "<nil>" || why == "" {
			why = fmt.Sprint(j["error"])
		}
		if why == "<nil>" {
			why = ""
		}
		rejected := resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != 429
		return nil, rejected, fmt.Errorf("token endpoint HTTP %d %s", resp.StatusCode, strings.TrimSpace(why)) // never the body: it may hold tokens
	}
	return j, false, nil
}

func jnum(v any) int64 {
	switch x := v.(type) {
	case float64:
		return int64(x)
	case string:
		n, _ := strconv.ParseInt(x, 10, 64)
		return n
	}
	return 0
}

// oauthRefresh: the stored pair refreshed (the CLI's own request: grant_type refresh_token, its scopes); the
// answer keeps every other field of the credentials file
func oauthRefresh(credentials string) (string, bool, error) {
	p, d, err := parsePair(credentials)
	if err != nil {
		return "", false, err
	}
	body := map[string]any{"grant_type": "refresh_token", "refresh_token": p.RefreshToken, "client_id": oauthClientID}
	if len(p.Scopes) > 0 {
		body["scope"] = strings.Join(p.Scopes, " ")
	}
	j, rejected, err := tokenCall(body)
	if err != nil {
		return "", rejected, err
	}
	o, _ := d["claudeAiOauth"].(map[string]any)
	o["accessToken"] = j["access_token"]
	if rt, _ := j["refresh_token"].(string); rt != "" {
		o["refreshToken"] = rt
	}
	exp := jnum(j["expires_in"])
	if exp <= 0 {
		exp = 3600
	}
	o["expiresAt"] = time.Now().UnixMilli() + exp*1000
	if rte := jnum(j["refresh_token_expires_in"]); rte > 0 {
		o["refreshTokenExpiresAt"] = time.Now().UnixMilli() + rte*1000
	}
	if sc, _ := j["scope"].(string); sc != "" {
		o["scopes"] = strings.Fields(sc)
	}
	d["claudeAiOauth"] = o
	out, _ := json.Marshal(d)
	return string(out), false, nil
}

// ---- reading and offering ----------------------------------------------------------------------------------------

type loginView struct {
	Credentials string
	Account     string
	ExpiresAt   int64
}

func (h *loginHub) current() loginView {
	h.mu.Lock()
	defer h.mu.Unlock()
	return loginView{h.f.Credentials, h.f.Account, credsExpiry(h.f.Credentials)}
}

// offer: a pair from somewhere (a push, Jarvis 1, a Re-login). Stored only when it expires later than the stored
// one (force: a Re-login, which always wins) and, unless switchOK, only for the stored account (Anthropic's
// profile answers whose the access token is). account "" keeps the stored account record.
func (h *loginHub) offer(credentials, account, source string, switchOK, force bool) (bool, error) {
	p, _, err := parsePair(credentials)
	if err != nil {
		return false, err
	}
	cur := h.current()
	if !force && p.ExpiresAt <= cur.ExpiresAt {
		return false, errNotNewer
	}
	if want := accountUUID(cur.Account); !switchOK && want != "" {
		prof, err := fetchProfile(p.AccessToken)
		if err != nil {
			return false, fmt.Errorf("checking the pair's account: %w", err)
		}
		if prof.Account.UUID != want {
			return false, errOtherAcct
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if !force && p.ExpiresAt <= credsExpiry(h.f.Credentials) { // another offer landed meanwhile
		return false, errNotNewer
	}
	old := h.f
	h.f.Credentials, h.f.Source, h.f.UpdatedAt = credentials, source, time.Now().UTC()
	if account != "" {
		h.f.Account = account
	}
	h.f.Fail = nil
	if err := h.save(); err != nil {
		h.f = old
		return false, err
	}
	h.usage.body = nil
	h.broadcastLocked()
	log.Printf("[login] %s: stored a newer Claude pair from %s (valid until %s)", h.store, source, time.UnixMilli(p.ExpiresAt).UTC().Format(time.RFC3339))
	return true, nil
}

// ---- the long poll ------------------------------------------------------------------------------------------------

type loginAnswer struct {
	Credentials string `json:"credentials,omitempty"` // only when it expires later than the caller's `have`
	Account     string `json:"account,omitempty"`
	ExpiresAt   int64  `json:"expiresAt"`
	Gen         int64  `json:"gen"`
	Preparing   bool   `json:"preparing"`
}

// poll: answers at once when the stored pair expires later than `have`, when a refresh is being prepared that the
// caller hasn't acknowledged (ack != gen), or when the caller holds a lock for a refresh that is over (ack != 0, not
// preparing); else waits up to `wait` for one of those.
func (h *loginHub) poll(ctx context.Context, who string, have, ack int64, wait time.Duration) loginAnswer {
	timer := time.NewTimer(min(wait, loginPollMax))
	defer timer.Stop()
	for {
		h.mu.Lock()
		h.seen[who] = time.Now()
		if h.preparing && ack == h.gen && h.acks[who] != ack {
			h.acks[who] = ack
			h.broadcastLocked()
		}
		exp := credsExpiry(h.f.Credentials)
		a := loginAnswer{Account: h.f.Account, ExpiresAt: exp, Gen: h.gen, Preparing: h.preparing}
		newer := exp > have && h.f.Credentials != ""
		if newer {
			a.Credentials = h.f.Credentials
		}
		ready := newer || (h.preparing && ack != h.gen) || (!h.preparing && ack != 0)
		ch := h.changed
		h.mu.Unlock()
		if ready || wait <= 0 {
			return a
		}
		select {
		case <-ch:
		case <-timer.C:
			return a
		case <-ctx.Done():
			return a
		}
	}
}

// ---- the refresh --------------------------------------------------------------------------------------------------

// refresh: the router's own refresh, when less than loginFreshMargin is left or forced
func (h *loginHub) refresh(force bool) (bool, error) {
	h.refreshMu.Lock()
	defer h.refreshMu.Unlock()
	h.mu.Lock()
	creds := h.f.Credentials
	if creds == "" {
		h.mu.Unlock()
		return false, errNoPair
	}
	exp := credsExpiry(creds)
	left := time.Until(time.UnixMilli(exp))
	if !force && left > loginFreshMargin {
		h.mu.Unlock()
		return false, nil
	}
	if fl := h.f.Fail; !force && fl != nil && fl.ExpiresAt == exp && time.Since(fl.At) < loginRetry {
		h.mu.Unlock()
		if !fl.Rejected && left > 0 {
			return false, nil
		}
		return false, fmt.Errorf("the Claude login has run out and its refresh was refused (%s): Re-login", fl.Error)
	}
	if fl := h.f.Fail; !force && fl != nil && fl.Rejected && fl.ExpiresAt == exp {
		h.mu.Unlock() // a dead grant: only a Re-login (or a newer pushed pair) helps
		return false, fmt.Errorf("the Claude login's refresh was refused (%s): Re-login", fl.Error)
	}
	// 1. prepare: every participant takes its CLI's refresh lock and acknowledges
	h.gen++
	gen := h.gen
	h.preparing = true
	var want []string
	for who, at := range h.seen {
		if time.Since(at) < loginSeenWindow {
			want = append(want, who)
		}
	}
	h.broadcastLocked()
	h.mu.Unlock()
	acked := h.waitAcks(gen, want, loginAckWait)

	// 2. refresh, and keep the answer before anything else (the old refresh token is dead from here on)
	newCreds, rejected, err := oauthRefresh(creds)
	h.mu.Lock()
	defer h.mu.Unlock()
	h.preparing = false
	defer h.broadcastLocked() // participants get the pair, or release their locks
	if err != nil {
		h.f.Fail = &loginFail{At: time.Now().UTC(), Error: err.Error(), ExpiresAt: exp, Rejected: rejected}
		h.save()
		log.Printf("[login] %s: refresh failed (%d/%d participants locked): %v", h.store, acked, len(want), err)
		if rejected && h.dm != nil {
			h.f.Fail.Notified = true
			h.save()
			go h.dm(deadLoginMessage(h.store, accountEmail(h.f.Account), err.Error()))
		}
		return false, err
	}
	if credsExpiry(newCreds) > credsExpiry(h.f.Credentials) { // a pushed or re-logged pair that expires later wins
		h.f.Credentials, h.f.Source = newCreds, "refresh"
	}
	h.f.Fail, h.f.RefreshedAt, h.f.UpdatedAt = nil, time.Now().UTC(), time.Now().UTC()
	if err := h.save(); err != nil {
		log.Printf("[login] writing the refreshed pair to the volume failed: %v", err)
	}
	h.usage.body = nil
	log.Printf("[login] %s: refreshed (%d/%d participants locked); valid until %s", h.store, acked, len(want), time.UnixMilli(credsExpiry(newCreds)).UTC().Format(time.RFC3339))
	return true, nil
}

func deadLoginMessage(store, email, why string) string {
	if len(why) > 200 {
		why = why[:200]
	}
	who := store
	if email != "" {
		who += " (" + email + ")"
	}
	return "🔑 The Claude login of " + who + " has run out: refreshing it was refused (" + why + "). Only a new sign-in fixes it: Jarvis 2 → Settings → Claude accounts → " + store + " → Re-login. Its sessions stuck on “Please run /login” are resumed once that is done."
}

// waitAcks: until every participant in want acknowledged gen, or d passed; returns how many did
func (h *loginHub) waitAcks(gen int64, want []string, d time.Duration) int {
	deadline := time.After(d)
	for {
		h.mu.Lock()
		n := 0
		for _, w := range want {
			if h.acks[w] == gen {
				n++
			}
		}
		ch := h.changed
		h.mu.Unlock()
		if n == len(want) {
			return n
		}
		select {
		case <-ch:
		case <-deadline:
			return n
		}
	}
}

// drain: waits for a refresh in flight (SIGTERM): its answer must reach the volume
func (h *loginHub) drain(d time.Duration) {
	done := make(chan struct{})
	go func() { h.refreshMu.Lock(); h.refreshMu.Unlock(); close(done) }()
	select {
	case <-done:
	case <-time.After(d):
	}
}

// ---- Re-login (the CLI's manual OAuth flow: the browser shows "code#state", Deyao pastes it) -----------------

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (h *loginHub) startLogin() (string, error) {
	v, s := make([]byte, 32), make([]byte, 32)
	rand.Read(v)
	rand.Read(s)
	p := &pendingLogin{Verifier: b64url(v), State: b64url(s), At: time.Now().UTC()}
	sum := sha256.Sum256([]byte(p.Verifier))
	q := url.Values{}
	q.Set("code", "true")
	q.Set("client_id", oauthClientID)
	q.Set("response_type", "code")
	q.Set("redirect_uri", oauthRedirectURL)
	q.Set("scope", strings.Join(oauthScopes, " "))
	q.Set("code_challenge", b64url(sum[:]))
	q.Set("code_challenge_method", "S256")
	q.Set("state", p.State)
	h.mu.Lock()
	defer h.mu.Unlock()
	h.f.Pending = p
	if err := h.save(); err != nil {
		return "", err
	}
	// the CLI's order of parameters (URL.searchParams.append), so the page looks like the CLI's
	order := []string{"code", "client_id", "response_type", "redirect_uri", "scope", "code_challenge", "code_challenge_method", "state"}
	parts := make([]string, 0, len(order))
	for _, k := range order {
		parts = append(parts, url.QueryEscape(k)+"="+url.QueryEscape(q.Get(k)))
	}
	return oauthAuthorizeURL + "?" + strings.Join(parts, "&"), nil
}

// finishLogin: the pasted "code#state" → the CLI's exchange (authorization_code, the manual redirect, PKCE) → the
// profile (subscription, rate tier, the account record) → stored, whatever the account (Deyao's own action)
func (h *loginHub) finishLogin(pasted string) (email, store string, err error) {
	target, email, err := h.finishLoginTo(pasted)
	if err != nil {
		return "", "", err
	}
	return email, target.store, nil
}

// finishLoginTo: the exchange, then the pair stored in this hub, or (another Claude account than this hub's) in the
// hub of that account, made if there is none: the store asked for keeps its own account (DECISIONS 190)
func (h *loginHub) finishLoginTo(pasted string) (*loginHub, string, error) {
	pasted = strings.TrimSpace(pasted)
	code, state, _ := strings.Cut(pasted, "#")
	h.mu.Lock()
	p := h.f.Pending
	h.mu.Unlock()
	if p == nil || time.Since(p.At) > loginPendingTTL {
		return nil, "", errors.New("no sign-in in progress (or it is older than 15 minutes): press Re-login again")
	}
	if code == "" || state == "" {
		return nil, "", errors.New("paste the whole code shown after sign-in (it has a # in it)")
	}
	if state != p.State {
		return nil, "", errors.New("that code belongs to another sign-in: press Re-login again")
	}
	h.refreshMu.Lock() // not while a refresh is out
	defer h.refreshMu.Unlock()
	j, _, err := tokenCall(map[string]any{"grant_type": "authorization_code", "code": code, "redirect_uri": oauthRedirectURL,
		"client_id": oauthClientID, "code_verifier": p.Verifier, "state": state})
	if err != nil {
		return nil, "", err
	}
	at, _ := j["access_token"].(string)
	o := map[string]any{"accessToken": at, "refreshToken": j["refresh_token"], "expiresAt": time.Now().UnixMilli() + max(jnum(j["expires_in"]), 60)*1000}
	if rte := jnum(j["refresh_token_expires_in"]); rte > 0 {
		o["refreshTokenExpiresAt"] = time.Now().UnixMilli() + rte*1000
	}
	scopes := oauthScopes
	if sc, _ := j["scope"].(string); sc != "" {
		scopes = strings.Fields(sc)
	}
	o["scopes"] = scopes
	acct := map[string]any{}
	if prof, err := fetchProfile(at); err == nil {
		sub := map[string]string{"claude_max": "max", "claude_pro": "pro", "claude_enterprise": "enterprise", "claude_team": "team"}[prof.Organization.OrganizationType]
		if sub != "" {
			o["subscriptionType"] = sub
		}
		if prof.Organization.RateLimitTier != "" {
			o["rateLimitTier"] = prof.Organization.RateLimitTier
		}
		oa := map[string]any{"accountUuid": prof.Account.UUID, "emailAddress": prof.Account.Email, "organizationUuid": prof.Organization.UUID,
			"hasExtraUsageEnabled": prof.Organization.HasExtraUsageEnabled}
		for k, v := range map[string]string{"displayName": prof.Account.DisplayName, "fullName": prof.Account.FullName, "billingType": prof.Organization.BillingType,
			"accountCreatedAt": prof.Account.CreatedAt, "subscriptionCreatedAt": prof.Organization.SubscriptionCreatedAt} {
			if v != "" {
				oa[k] = v
			}
		}
		acct["oauthAccount"] = oa
	} else {
		log.Printf("[login] %s: Re-login: profile: %v (stored without the account record)", h.store, err)
		if a, _ := j["account"].(map[string]any); a != nil {
			oa := map[string]any{"accountUuid": a["uuid"], "emailAddress": a["email_address"]}
			if org, _ := j["organization"].(map[string]any); org != nil {
				oa["organizationUuid"] = org["uuid"]
			}
			acct["oauthAccount"] = oa
		}
	}
	creds, _ := json.Marshal(map[string]any{"claudeAiOauth": o})
	account := ""
	if len(acct) > 0 {
		b, _ := json.Marshal(acct)
		account = string(b)
	}
	target := h
	if h.check != nil {
		if err := h.check(accountUUID(account)); err != nil {
			if h.elsewhere == nil {
				return nil, "", err
			}
			t, terr := h.elsewhere(accountUUID(account), accountEmail(account))
			if terr != nil {
				return nil, "", fmt.Errorf("%v (keeping it as its own account failed too: %v)", err, terr)
			}
			log.Printf("[login] %s: the sign-in is %s, kept in %s instead", h.store, accountEmail(account), t.store)
			target = t
		}
	}
	h.mu.Lock()
	h.f.Pending = nil
	h.mu.Unlock()
	if target != h {
		target.refreshMu.Lock()
		defer target.refreshMu.Unlock()
	}
	if _, err := target.offerLocked(string(creds), account, "relogin"); err != nil {
		return nil, "", err
	}
	return target, accountEmail(account), nil
}

// offerLocked: offer for a Re-login, with refreshMu already held (force, any account)
func (h *loginHub) offerLocked(credentials, account, source string) (bool, error) {
	return h.offer(credentials, account, source, true, true)
}

// ---- the usage quota (Jarvis 1's /api/usage) ----------------------------------------------------------------------

func (h *loginHub) usageQuota(force bool) (int, map[string]any) {
	h.mu.Lock()
	if !force && h.usage.body != nil && time.Since(h.usage.at) < time.Minute {
		b := cloneMap(h.usage.body)
		h.mu.Unlock()
		b["cached"] = true
		return 200, b
	}
	creds := h.f.Credentials
	h.mu.Unlock()
	fail := func(status int, msg string, needLogin bool) (int, map[string]any) {
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.usage.body != nil && !needLogin {
			b := cloneMap(h.usage.body)
			b["cached"], b["stale"], b["error"] = true, true, msg
			return 200, b
		}
		out := map[string]any{"error": msg}
		if needLogin {
			out["needLogin"] = true
		}
		return status, out
	}
	p, _, err := parsePair(creds)
	if err != nil {
		return fail(409, "no Claude login stored: Re-login", true)
	}
	req, _ := http.NewRequest("GET", oauthUsageURL, nil)
	req.Header.Set("Authorization", "Bearer "+p.AccessToken)
	req.Header.Set("anthropic-beta", "oauth-2025-04-20")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "jarvis2-router/1")
	resp, err := loginHTTP.Do(req)
	if err != nil {
		return fail(502, "usage endpoint: "+err.Error(), false)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return fail(409, fmt.Sprintf("Claude refused the access token (HTTP %d): Re-login", resp.StatusCode), true)
	}
	if resp.StatusCode != 200 {
		return fail(502, fmt.Sprintf("usage endpoint HTTP %d", resp.StatusCode), false)
	}
	var j struct {
		Limits []struct {
			Kind     string  `json:"kind"`
			Group    string  `json:"group"`
			Percent  float64 `json:"percent"`
			Severity string  `json:"severity"`
			Resets   string  `json:"resets_at"`
			Active   bool    `json:"is_active"`
			Scope    struct {
				Model *struct {
					ID          string `json:"id"`
					DisplayName string `json:"display_name"`
				} `json:"model"`
				Surface string `json:"surface"`
			} `json:"scope"`
		} `json:"limits"`
		Extra *struct {
			Enabled      bool    `json:"is_enabled"`
			MonthlyLimit any     `json:"monthly_limit"`
			UsedCredits  any     `json:"used_credits"`
			Utilization  any     `json:"utilization"`
			Currency     string  `json:"currency"`
			Decimals     float64 `json:"decimal_places"`
			Disabled     any     `json:"disabled_reason"`
			LimitReached bool    `json:"spend_limit_reached"`
		} `json:"extra_usage"`
	}
	if err := json.Unmarshal(b, &j); err != nil {
		return fail(502, "usage endpoint: not JSON", false)
	}
	limits := []map[string]any{}
	for _, l := range j.Limits {
		var model any
		if l.Scope.Model != nil {
			model = l.Scope.Model.DisplayName
			if model == "" {
				model = l.Scope.Model.ID
			}
		}
		var surface, resets any
		if l.Scope.Surface != "" {
			surface = l.Scope.Surface
		}
		if l.Resets != "" {
			resets = l.Resets
		}
		limits = append(limits, map[string]any{"kind": l.Kind, "group": l.Group, "percent": l.Percent, "severity": l.Severity,
			"resetsAt": resets, "model": model, "surface": surface, "active": l.Active})
	}
	body := map[string]any{"fetchedAt": time.Now().UTC().Format(time.RFC3339), "limits": limits, "extraUsage": nil}
	if x := j.Extra; x != nil {
		body["extraUsage"] = map[string]any{"enabled": x.Enabled, "monthlyLimit": x.MonthlyLimit, "usedCredits": x.UsedCredits, "utilization": x.Utilization,
			"currency": x.Currency, "decimalPlaces": x.Decimals, "disabledReason": x.Disabled, "spendLimitReached": x.LimitReached}
	}
	h.mu.Lock()
	h.usage.at, h.usage.body = time.Now(), body
	h.mu.Unlock()
	out := cloneMap(body)
	out["cached"] = false
	return 200, out
}

func cloneMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m)+3)
	for k, v := range m {
		out[k] = v
	}
	return out
}

// ---- status (no secrets) --------------------------------------------------------------------------------------------

func (h *loginHub) status() map[string]any {
	h.mu.Lock()
	defer h.mu.Unlock()
	exp := credsExpiry(h.f.Credentials)
	parts := []map[string]any{}
	for who, at := range h.seen {
		if time.Since(at) < loginSeenWindow {
			parts = append(parts, map[string]any{"id": who, "seen": at.UTC()})
		}
	}
	sort.Slice(parts, func(i, j int) bool { return parts[i]["id"].(string) < parts[j]["id"].(string) })
	out := map[string]any{"store": h.store, "hasLogin": h.f.Credentials != "", "expiresAt": nullIfZero(exp),
		"expired": exp != 0 && exp < time.Now().UnixMilli(), "email": accountEmail(h.f.Account), "accountUuid": accountUUID(h.f.Account), "source": h.f.Source,
		"updatedAt": nullIfZeroTime(h.f.UpdatedAt), "refreshedAt": nullIfZeroTime(h.f.RefreshedAt), "participants": parts,
		"loginInProgress": h.f.Pending != nil && time.Since(h.f.Pending.At) < loginPendingTTL, "preparing": h.preparing}
	if fl := h.f.Fail; fl != nil && fl.ExpiresAt == exp {
		out["error"], out["rejected"] = fl.Error, fl.Rejected
		out["needLogin"] = fl.Rejected || exp < time.Now().UnixMilli()
	}
	if h.f.Credentials == "" {
		out["needLogin"] = true
	}
	return out
}

func nullIfZero(n int64) any {
	if n == 0 {
		return nil
	}
	return n
}

func nullIfZeroTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}

// drainLogins: waits for every account's refresh in flight (SIGTERM, a move's freeze): its answer must reach the volume
func (r *Router) drainLogins(d time.Duration) {
	for _, h := range r.accounts().all() {
		h.drain(d)
	}
}

// ---- loops ----------------------------------------------------------------------------------------------------------

// loginLoop: refresh every account's login when due (checked every minute)
func (r *Router) loginLoop() {
	for {
		for _, h := range r.accounts().all() {
			if _, err := h.refresh(false); err != nil && !errors.Is(err, errNoPair) {
				log.Printf("[login] %s: %v", h.store, err)
			}
		}
		r.syncAccountStores() // claudestores.go: each account's pair into its core store
		time.Sleep(time.Minute)
	}
}

// ---- routes ---------------------------------------------------------------------------------------------------------

func pollArgs(req *http.Request) (have, ack int64, wait time.Duration) {
	q := req.URL.Query()
	have, _ = strconv.ParseInt(q.Get("have"), 10, 64)
	ack, _ = strconv.ParseInt(q.Get("ack"), 10, 64)
	ws, _ := strconv.Atoi(q.Get("wait"))
	return have, ack, time.Duration(ws) * time.Second
}

// machineAccount: the session this machine runs and the hub of its Claude account; nil when the session has none (or
// the account was removed)
func (r *Router) machineAccount(machine string) (string, *loginHub) {
	var sid, store string
	r.st.Do(func(d *persisted) {
		if s := d.Sessions[d.Machines[machine]]; s != nil && s.MachineID == machine {
			sid, store = s.ID, s.ClaudeAccount
		}
	})
	if sid == "" || store == "" {
		return sid, nil
	}
	return sid, r.accounts().hub(store)
}

type pushBody struct {
	Credentials json.RawMessage `json:"credentials"`
	Account     json.RawMessage `json:"account"`
	Relogin     bool            `json:"relogin"`
}

// asString: a JSON string, or any other JSON value as its text (Jarvis 1 accepted both)
func asString(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	return string(raw)
}

func (r *Router) pushAnswer(w http.ResponseWriter, h *loginHub, body []byte, source string, switchOK bool) {
	var b pushBody
	if err := json.Unmarshal(body, &b); err != nil {
		writeJSON(w, 400, map[string]string{"error": "body must be {credentials, account?}"})
		return
	}
	creds, account := asString(b.Credentials), asString(b.Account)
	if source == "jarvis1" && b.Relogin {
		switchOK = true
	}
	stored, err := h.offer(creds, account, source, switchOK, source == "jarvis1" && b.Relogin)
	switch {
	case errors.Is(err, errNotNewer):
		writeJSON(w, 200, map[string]any{"stored": false, "reason": "not newer than the stored credentials", "expiresAt": h.current().ExpiresAt})
		return
	case err != nil:
		status := 400
		if errors.Is(err, errOtherAcct) {
			status = 403
		}
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"stored": stored, "expiresAt": credsExpiry(creds)})
}

func (r *Router) registerClaudeLogin(app appRoute, m machineRoute, public publicRoute) {
	acc := r.accounts()
	noAccount := func(w http.ResponseWriter) {
		writeJSON(w, 404, map[string]any{"error": "this session has no Claude account", "noAccount": true})
	}
	// ---- session machines (the session's own account) ----
	machinePoll := func(w http.ResponseWriter, req *http.Request, machine string, _ []byte) {
		_, h := r.machineAccount(machine)
		if h == nil {
			noAccount(w)
			return
		}
		have, ack, wait := pollArgs(req)
		a, ok := r.pollWithSwitch(req.Context(), machine, h, have, ack, wait) // accountswap.go: a switch cuts it short
		if !ok {
			noAccount(w)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, 200, a)
	}
	machinePush := func(w http.ResponseWriter, req *http.Request, machine string, body []byte) {
		sid, h := r.machineAccount(machine)
		if h == nil {
			noAccount(w)
			return
		}
		r.pushAnswer(w, h, body, "session "+sid, false)
	}
	m("GET /m/claude-login", machinePoll)
	m("POST /m/claude-login", machinePush)
	// session images from before 2026-10-13 (their push-claude-credentials, through the machine's $JARVIS_URL proxy)
	m("GET /m/api/credentials", func(w http.ResponseWriter, req *http.Request, machine string, _ []byte) {
		_, h := r.machineAccount(machine)
		if h == nil {
			noAccount(w)
			return
		}
		cur := h.current()
		if cur.Credentials == "" {
			writeJSON(w, 409, map[string]any{"error": "no Claude login stored: Re-login", "needLogin": true})
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, 200, map[string]any{"credentials": cur.Credentials, "account": cur.Account, "expiresAt": cur.ExpiresAt})
	})
	m("POST /m/api/credentials", machinePush)

	// ---- Jarvis 1 (its sessions take the pair from here once it follows): one Access service token, one account ----
	peer := r.requireClient(os.Getenv("ACCESS_PEER_AUD"), os.Getenv("JARVIS1_LOGIN_CLIENT_ID"))
	peerHub := func(w http.ResponseWriter) *loginHub {
		h := acc.jarvis1Hub()
		if h == nil {
			writeJSON(w, 409, map[string]any{"error": "no Claude account is followed by Jarvis 1", "needLogin": true})
		}
		return h
	}
	public("GET /peer/claude-login", peer(func(w http.ResponseWriter, req *http.Request) {
		if h := peerHub(w); h != nil {
			have, ack, wait := pollArgs(req)
			w.Header().Set("Cache-Control", "no-store")
			writeJSON(w, 200, h.poll(req.Context(), "jarvis1", have, ack, wait))
		}
	}))
	public("POST /peer/claude-login", peer(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(io.LimitReader(req.Body, 1<<20))
		if h := peerHub(w); h != nil {
			r.pushAnswer(w, h, b, "jarvis1", false)
		}
	}))
	public("GET /peer/claude-login/status", peer(func(w http.ResponseWriter, req *http.Request) {
		if h := peerHub(w); h != nil {
			writeJSON(w, 200, h.status())
		}
	}))

	r.registerClaudeAccounts(app, public) // claudeaccounts.go: the app's and the setup session's routes
}

// requireClient: exactly one Access service token (its client id = the JWT's common_name) on a path-scoped Access
// app (aud); no email login
func (r *Router) requireClient(aud, clientID string) func(http.HandlerFunc) http.Handler {
	return func(fn http.HandlerFunc) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if !r.cfg.NoAccess {
				if aud == "" || clientID == "" {
					writeJSON(w, 503, map[string]string{"error": "the router has no Access audience / client id for this path"})
					return
				}
				c, err := r.access().verify(req.Header.Get("Cf-Access-Jwt-Assertion"), aud)
				if err != nil || c.Email != "" || c.CommonName != clientID {
					writeJSON(w, 403, map[string]string{"error": "Access service token required"})
					return
				}
			}
			fn(w, req)
		})
	}
}

// resumeStuckLogins: after a Re-login, the next autopilot tick delivers "continue" to sessions stuck on
// "Please run /login" (autopilot.go plans it from the stored pair's expiry)
func (r *Router) resumeStuckLogins() { r.autopilotTick() }
