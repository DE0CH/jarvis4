package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func pairOf(tag string, exp int64) string {
	return fmt.Sprintf(`{"claudeAiOauth":{"accessToken":"at-%s","refreshToken":"rt-%s","expiresAt":%d,"scopes":["user:inference","user:profile"],"subscriptionType":"max"}}`, tag, tag, exp)
}

// fakeAnthropic: the token, profile and usage endpoints. Each access token "at-<tag>" belongs to the account
// named by accounts[tag] (default "acct-1"); a refresh of "rt-<tag>" answers "at-<tag>'".
type fakeAnthropic struct {
	srv       *httptest.Server
	mu        sync.Mutex
	refreshes []map[string]any
	exchanges []map[string]any
	reject    bool
	accounts  map[string]string
	onRefresh func()
}

func newFakeAnthropic(t *testing.T) *fakeAnthropic {
	f := &fakeAnthropic{accounts: map[string]string{}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/token":
			var b map[string]any
			json.NewDecoder(req.Body).Decode(&b)
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.reject {
				w.WriteHeader(400)
				w.Write([]byte(`{"error":"invalid_grant","error_description":"Refresh token not found or invalid"}`))
				return
			}
			switch b["grant_type"] {
			case "refresh_token":
				f.refreshes = append(f.refreshes, b)
				if f.onRefresh != nil {
					f.onRefresh()
				}
				tag := strings.TrimPrefix(b["refresh_token"].(string), "rt-") + "'"
				json.NewEncoder(w).Encode(map[string]any{"access_token": "at-" + tag, "refresh_token": "rt-" + tag, "expires_in": 28800, "scope": "user:inference user:profile"})
			case "authorization_code":
				f.exchanges = append(f.exchanges, b)
				json.NewEncoder(w).Encode(map[string]any{"access_token": "at-new", "refresh_token": "rt-new", "expires_in": 28800, "scope": "user:inference user:profile user:sessions:claude_code"})
			}
		case "/profile":
			tag := strings.TrimPrefix(strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer "), "at-")
			f.mu.Lock()
			acct := f.accounts[strings.TrimRight(tag, "'")]
			f.mu.Unlock()
			if acct == "" {
				acct = "acct-1"
			}
			json.NewEncoder(w).Encode(map[string]any{"account": map[string]any{"uuid": acct, "email": acct + "@example.com", "display_name": "D"},
				"organization": map[string]any{"uuid": "org-1", "organization_type": "claude_max", "rate_limit_tier": "default_claude_max_20x"}})
		case "/usage":
			if req.Header.Get("Authorization") == "" {
				w.WriteHeader(401)
				return
			}
			w.Write([]byte(`{"limits":[{"kind":"session","group":"g","percent":12,"severity":"ok","resets_at":"2026-10-13T05:00:00Z","is_active":true,"scope":{"model":{"id":"m","display_name":"Opus"}}}],"extra_usage":{"is_enabled":false,"disabled_reason":"off"}}`))
		}
	}))
	t.Cleanup(f.srv.Close)
	saved := []string{oauthTokenURL, oauthProfileURL, oauthUsageURL}
	oauthTokenURL, oauthProfileURL, oauthUsageURL = f.srv.URL+"/token", f.srv.URL+"/profile", f.srv.URL+"/usage"
	t.Cleanup(func() { oauthTokenURL, oauthProfileURL, oauthUsageURL = saved[0], saved[1], saved[2] })
	return f
}

const acct1 = `{"oauthAccount":{"accountUuid":"acct-1","emailAddress":"acct-1@example.com"}}`

// ownRouter: a router with one Claude account, claude-a (the default)
func ownRouter(t *testing.T) (*Router, *loginHub) {
	r := newTestRouter(t)
	h, err := r.accounts().add("a")
	if err != nil {
		t.Fatal(err)
	}
	return r, h
}

func TestLoginOfferNewerWinsAndAccount(t *testing.T) {
	f := newFakeAnthropic(t)
	_, h := ownRouter(t)
	now := time.Now().UnixMilli()
	if ok, err := h.offer(pairOf("a", now+1000), acct1, "seed", true, false); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if ok, err := h.offer(pairOf("b", now+500), "", "push", false, false); ok || err != errNotNewer {
		t.Fatal("an older pair must not replace a newer one", ok, err)
	}
	f.accounts["c"] = "acct-2"
	if ok, err := h.offer(pairOf("c", now+2000), "", "push", false, false); ok || err != errOtherAcct {
		t.Fatal("another account's pair must be refused", ok, err)
	}
	if ok, err := h.offer(pairOf("d", now+3000), "", "push", false, false); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if cur := h.current(); cur.ExpiresAt != now+3000 || accountUUID(cur.Account) != "acct-1" {
		t.Fatalf("%+v", cur)
	}
	// sealed in the database (no refresh token in the clear there), and read back by a new hub (a router restart)
	var body []byte
	h.st.sdb.db.pool.QueryRow(context.Background(), "SELECT body FROM sealed_docs WHERE name = $1", h.name).Scan(&body)
	if len(body) == 0 || strings.Contains(string(body), "refresh") {
		t.Fatalf("the sealed row: %d bytes", len(body))
	}
	h2 := newLoginHub(h.st, h.name, h.store)
	if c := h2.current(); c.ExpiresAt != now+3000 {
		t.Fatalf("%+v", c)
	}
	if h.offer("{}", "", "push", false, false); h.current().ExpiresAt != now+3000 {
		t.Fatal("a malformed pair changed the store")
	}
}

// two replicas on one database: a pair one stores (the leader's refresh) reaches the other's waiting polls at once
// (the reload stopgap), instead of the other serving the revoked pair until it restarts
func TestLoginReplicaReloads(t *testing.T) {
	newFakeAnthropic(t)
	r1, h1 := ownRouter(t)
	now := time.Now().Add(8 * time.Hour).UnixMilli()
	h1.offer(pairOf("a", now), acct1, "seed", true, false)
	st2, err := OpenState(context.Background(), r1.st.sdb.db, t.TempDir(), r1.st.seal)
	if err != nil {
		t.Fatal(err)
	}
	r2 := NewRouter(Config{NoAccess: true, DataDir: st2.dir, WebDir: t.TempDir()}, st2, nil, Policy{})
	h2 := r2.accounts().hubs[h1.store]
	if h2 == nil || h2.current().ExpiresAt != now {
		t.Fatalf("the second replica's hub: %+v", h2)
	}
	time.Sleep(200 * time.Millisecond) // its LISTEN is up
	got := make(chan loginAnswer, 1)
	go func() { got <- h2.poll(context.Background(), "m:x", now, 0, 10*time.Second) }()
	time.Sleep(100 * time.Millisecond)
	if ok, err := h1.offer(pairOf("b", now+1000), "", "refresh", false, false); !ok || err != nil {
		t.Fatal(ok, err)
	}
	select {
	case a := <-got:
		if a.ExpiresAt != now+1000 || !strings.Contains(a.Credentials, "at-b") {
			t.Fatalf("the other replica answered %+v", a)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the other replica's poll never got the new pair")
	}
}

// the lessons/74 protocol: participants lock before the refresh, the refresh waits for them, then all get the pair
func TestLoginRefreshProtocol(t *testing.T) {
	f := newFakeAnthropic(t)
	_, h := ownRouter(t)
	exp := time.Now().Add(10 * time.Minute).UnixMilli() // inside the margin: due
	h.offer(pairOf("a", exp), acct1, "seed", true, false)

	ctx := context.Background()
	// two participants, each seen (polling with have = the current expiry)
	for _, who := range []string{"m:1", "jarvis1"} {
		if a := h.poll(ctx, who, exp, 0, 0); a.Credentials != "" || a.Preparing {
			t.Fatalf("%s: nothing new yet: %+v", who, a)
		}
	}
	var locked atomic.Int32
	f.onRefresh = func() {
		if locked.Load() != 2 {
			t.Errorf("refreshed with %d of 2 participants locked", locked.Load())
		}
	}
	var wg sync.WaitGroup
	got := make([]loginAnswer, 2)
	for i, who := range []string{"m:1", "jarvis1"} {
		wg.Add(1)
		go func(i int, who string) {
			defer wg.Done()
			a := h.poll(ctx, who, exp, 0, 30*time.Second) // waits for the prepare
			if !a.Preparing {
				t.Errorf("%s: expected a prepare: %+v", who, a)
				return
			}
			locked.Add(1)                                         // the participant took its CLI lock
			got[i] = h.poll(ctx, who, exp, a.Gen, 30*time.Second) // acknowledges and waits for the pair
		}(i, who)
	}
	time.Sleep(50 * time.Millisecond)
	start := time.Now()
	ok, err := h.refresh(false)
	if !ok || err != nil {
		t.Fatal(ok, err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("the refresh waited out the ack timeout although both acknowledged")
	}
	wg.Wait()
	for i, a := range got {
		if !strings.Contains(a.Credentials, "at-a'") || a.Preparing || a.ExpiresAt <= exp {
			t.Fatalf("participant %d: %+v", i, a)
		}
	}
	if len(f.refreshes) != 1 || f.refreshes[0]["refresh_token"] != "rt-a" || f.refreshes[0]["scope"] != "user:inference user:profile" {
		t.Fatalf("%v", f.refreshes)
	}
	// not due again
	if ok, _ := h.refresh(false); ok {
		t.Fatal("refreshed a fresh pair")
	}
}

// a refused refresh: participants are told to release; the dead login is DMed once, not retried
func TestLoginRefreshRejected(t *testing.T) {
	f := newFakeAnthropic(t)
	_, h := ownRouter(t)
	var dms atomic.Int32
	h.dm = func(string) { dms.Add(1) }
	exp := time.Now().Add(time.Minute).UnixMilli()
	h.offer(pairOf("a", exp), acct1, "seed", true, false)
	h.poll(context.Background(), "m:1", exp, 0, 0)
	f.reject = true
	done := make(chan loginAnswer)
	go func() {
		a := h.poll(context.Background(), "m:1", exp, 0, 10*time.Second)
		done <- h.poll(context.Background(), "m:1", exp, a.Gen, 10*time.Second)
	}()
	time.Sleep(50 * time.Millisecond)
	if _, err := h.refresh(false); err == nil {
		t.Fatal("expected the refusal")
	}
	if a := <-done; a.Preparing || a.Credentials != "" {
		t.Fatalf("the participant must be told to release: %+v", a)
	}
	// it answers at once while the participant still says it holds a lock (ack != 0, not preparing)
	if a := h.poll(context.Background(), "m:1", exp, 1, 10*time.Second); a.Preparing {
		t.Fatalf("%+v", a)
	}
	n := len(f.refreshes)
	if _, err := h.refresh(false); err == nil || len(f.refreshes) != n {
		t.Fatal("a refused grant must not be retried", err)
	}
	time.Sleep(20 * time.Millisecond)
	if dms.Load() != 1 {
		t.Fatalf("%d DMs", dms.Load())
	}
	if st := h.status(); st["needLogin"] != true || st["rejected"] != true {
		t.Fatalf("%v", st)
	}
	// a newer pair (a Re-login, a push) clears it
	h.offer(pairOf("b", time.Now().Add(8*time.Hour).UnixMilli()), "", "relogin", true, true)
	if st := h.status(); st["needLogin"] == true {
		t.Fatalf("%v", st)
	}
}

func TestLoginRelogin(t *testing.T) {
	f := newFakeAnthropic(t)
	r, h := ownRouter(t)
	code, out := appDo(t, r, "POST", "/api/claude-login/start", "")
	if code != 200 {
		t.Fatal(code, out)
	}
	u, _ := url.Parse(out["url"].(string))
	q := u.Query()
	if u.Host != "claude.com" || q.Get("client_id") != oauthClientID || q.Get("redirect_uri") != oauthRedirectURL || q.Get("code_challenge_method") != "S256" ||
		q.Get("scope") != strings.Join(oauthScopes, " ") || q.Get("state") == "" || q.Get("code") != "true" {
		t.Fatalf("%s", u)
	}
	if code, _ := appDo(t, r, "POST", "/api/claude-login/code", `{"code":"abc#wrong"}`); code != 400 {
		t.Fatal("another sign-in's state must be refused")
	}
	code, out = appDo(t, r, "POST", "/api/claude-login/code", `{"code":"abc#`+q.Get("state")+`"}`)
	if code != 200 || out["email"] != "acct-1@example.com" {
		t.Fatal(code, out)
	}
	x := f.exchanges[0]
	if x["code"] != "abc" || x["redirect_uri"] != oauthRedirectURL || x["code_verifier"] == "" || x["state"] != q.Get("state") {
		t.Fatalf("%v", x)
	}
	cur := h.current()
	var d struct {
		O map[string]any `json:"claudeAiOauth"`
	}
	json.Unmarshal([]byte(cur.Credentials), &d)
	if d.O["accessToken"] != "at-new" || d.O["subscriptionType"] != "max" || d.O["rateLimitTier"] != "default_claude_max_20x" || accountUUID(cur.Account) != "acct-1" {
		t.Fatalf("%v %s", d.O, cur.Account)
	}
	if code, _ := appDo(t, r, "POST", "/api/claude-login/code", `{"code":"abc#`+q.Get("state")+`"}`); code != 400 {
		t.Fatal("a code is used once")
	}
	// status and usage, with no secret in either
	code, st := appDo(t, r, "GET", "/api/claude-login", "")
	if code != 200 || st["email"] != "acct-1@example.com" || strings.Contains(fmt.Sprint(st), "at-new") {
		t.Fatal(code, st)
	}
	code, us := appDo(t, r, "GET", "/api/usage", "")
	if code != 200 || len(us["limits"].([]any)) != 1 || us["limits"].([]any)[0].(map[string]any)["model"] != "Opus" {
		t.Fatal(code, us)
	}
}

// machines: only one whose session uses the account gets its pair; its push is account-checked
func TestLoginMachineRoutes(t *testing.T) {
	f := newFakeAnthropic(t)
	r, h := ownRouter(t)
	exp := time.Now().Add(8 * time.Hour).UnixMilli()
	h.offer(pairOf("a", exp), acct1, "seed", true, false)
	addSession(r, "sA", "started", "mA", false)
	addSession(r, "sB", "started", "mB", false)
	r.st.Do(func(d *persisted) { d.Sessions["sA"].ClaudeAccount = "claude-a" })
	ma, mb := newTestMachine(r, "mA"), newTestMachine(r, "mB")
	mh := r.MachineHandler()
	if code, out := mb.do(t, mh, "GET", "/m/claude-login?have=0", ""); code != 404 || out["noAccount"] != true {
		t.Fatal("a machine whose session has no account got a pair", code, out)
	}
	code, out := ma.do(t, mh, "GET", "/m/claude-login?have=0", "")
	if code != 200 || !strings.Contains(out["credentials"].(string), "at-a") || accountUUID(out["account"].(string)) != "acct-1" {
		t.Fatal(code, out)
	}
	code, out = ma.do(t, mh, "GET", fmt.Sprintf("/m/claude-login?have=%d", exp), "")
	if code != 200 || out["credentials"] != nil {
		t.Fatal("no pair when the caller's is as new", code, out)
	}
	// a push of the machine's own refresh: newer, same account → stored
	b, _ := json.Marshal(map[string]string{"credentials": pairOf("b", exp+1000)})
	if code, out = ma.do(t, mh, "POST", "/m/claude-login", string(b)); code != 200 || out["stored"] != true {
		t.Fatal(code, out)
	}
	f.accounts["c"] = "acct-evil"
	b, _ = json.Marshal(map[string]string{"credentials": pairOf("c", exp+5000)})
	if code, _ = ma.do(t, mh, "POST", "/m/claude-login", string(b)); code != 403 || h.current().ExpiresAt != exp+1000 {
		t.Fatal("another account's pair was stored", code)
	}
	// Jarvis 1's session script, through $JARVIS_URL
	if code, out = ma.do(t, mh, "GET", "/m/api/credentials", ""); code != 200 || out["expiresAt"].(float64) != float64(exp+1000) {
		t.Fatal(code, out)
	}
}

// the peer route (Jarvis 1): the same poll; a Re-login pushed from Jarvis 1 may switch the account
func TestLoginPeer(t *testing.T) {
	f := newFakeAnthropic(t)
	r, h := ownRouter(t)
	exp := time.Now().Add(8 * time.Hour).UnixMilli()
	h.offer(pairOf("a", exp), acct1, "seed", true, false)
	code, out := appDo(t, r, "GET", "/peer/claude-login?have=0", "")
	if code != 200 || !strings.Contains(out["credentials"].(string), "at-a") {
		t.Fatal(code, out)
	}
	f.accounts["z"] = "acct-2"
	b, _ := json.Marshal(map[string]any{"credentials": pairOf("z", exp+10), "account": `{"oauthAccount":{"accountUuid":"acct-2"}}`})
	if code, _ := appDo(t, r, "POST", "/peer/claude-login", string(b)); code != 403 {
		t.Fatal("a plain push of another account must be refused")
	}
	b, _ = json.Marshal(map[string]any{"credentials": pairOf("z", exp-10), "account": `{"oauthAccount":{"accountUuid":"acct-2"}}`, "relogin": true})
	if code, out := appDo(t, r, "POST", "/peer/claude-login", string(b)); code != 200 || out["stored"] != true || accountUUID(h.current().Account) != "acct-2" {
		t.Fatal("a Re-login through Jarvis 1 wins", code, out)
	}
	// the setup status is the setup session's (signed): a router with Access refuses anyone else
	r2 := NewRouter(Config{DataDir: t.TempDir(), AppAUD: "a", SetupAUD: "s"}, r.st, nil, Policy{})
	if code, _ := appDo(t, r2, "GET", "/setup/claude-login", ""); code != 403 {
		t.Fatal(code)
	}
	if code, _ := appDo(t, r2, "GET", "/peer/claude-login", ""); code != 503 && code != 403 {
		t.Fatal(code)
	}
}

// a machine that signed its poll's path with the query (the session image of 2026-10-13 01:30-03:00) is answered too
func TestLoginPollSignedWithQuery(t *testing.T) {
	newFakeAnthropic(t)
	r, h := ownRouter(t)
	h.offer(pairOf("a", time.Now().Add(8*time.Hour).UnixMilli()), acct1, "seed", true, false)
	addSession(r, "sA", "started", "mA", false)
	r.st.Do(func(d *persisted) { d.Sessions["sA"].ClaudeAccount = "claude-a" })
	m := newTestMachine(r, "mA")
	req := httptest.NewRequest("GET", "/m/claude-login?have=0&ack=0&wait=0", nil)
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	sum := sha256.Sum256(nil)
	sig, _ := signP256(m.key, []byte("GET /m/claude-login?have=0&ack=0&wait=0 "+ts+" "+hex.EncodeToString(sum[:])))
	req.Header.Set("X-Machine", "mA")
	req.Header.Set("X-Time", ts)
	req.Header.Set("X-Sig", sig)
	w := httptest.NewRecorder()
	r.MachineHandler().ServeHTTP(w, req)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "at-a") {
		t.Fatal(w.Code, w.Body.String())
	}
}
