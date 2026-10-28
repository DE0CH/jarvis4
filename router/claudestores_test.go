package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// accountCore: a core with the router writer (core/keys.go): its store key is a real point, so a write can be opened
type accountCore struct {
	mu      sync.Mutex
	key     key
	store   *ecdh.PrivateKey
	created []string
	writes  []map[string]any
	refuse  bool // a core from before the router writer
}

func (c *accountCore) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()
	b, _ := io.ReadAll(req.Body)
	var in map[string]any
	json.Unmarshal(b, &in)
	switch req.URL.Path {
	case "/key":
		writeJSON(w, 200, map[string]string{"signingKey": c.key.pub()})
	case "/identity":
		writeJSON(w, 200, map[string]any{"signingKey": c.key.pub(), "state": c.key.doc(map[string]any{"kind": "core-state", "master": "M", "phone": map[string]string{"agreementKey": "P"}})})
	case "/store-key":
		writeJSON(w, 200, c.key.doc(map[string]any{"kind": "store-key", "phone": "P", "storeKey": base64.StdEncoding.EncodeToString(c.store.PublicKey().Bytes())}))
	case "/stores/create":
		c.created = append(c.created, in["name"].(string))
		writeJSON(w, 200, c.key.doc(map[string]any{"kind": "store-created", "name": in["name"]}))
	case "/stores/write-key":
		if c.refuse {
			writeJSON(w, 400, map[string]string{"error": "writer: setup or machine"})
			return
		}
		c.writes = append(c.writes, in)
		writeJSON(w, 200, c.key.doc(map[string]any{"kind": "key-written", "store": in["store"], "key": in["key"]}))
	default:
		http.NotFound(w, req)
	}
}

// open: a written key's value, with the store key's private half (what the phone's share and the core do together)
func (c *accountCore) open(t *testing.T, x map[string]any) string {
	t.Helper()
	wr := x["wrapped"].(map[string]any)
	eb, _ := base64.StdEncoding.DecodeString(wr["e"].(string))
	e, _ := ecdh.P256().NewPublicKey(eb)
	sh, _ := c.store.ECDH(e)
	k, _ := hkdf.Key(sha256.New, sh, nil, "jarvis2/store-data-key", 32)
	dk := gcmOpen(t, k, wr["wrapped"].(string), nil)
	return string(gcmOpen(t, dk, x["data"].(string), []byte(x["store"].(string)+"\n"+x["key"].(string))))
}

func gcmOpen(t *testing.T, key []byte, b64 string, aad []byte) []byte {
	t.Helper()
	raw, _ := base64.StdEncoding.DecodeString(b64)
	block, _ := aes.NewCipher(key)
	g, _ := cipher.NewGCM(block)
	out, err := g.Open(nil, raw[:g.NonceSize()], raw[g.NonceSize():], aad)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// Each Claude account is its core store claude-<name>: the router writes its pair and record there when they change
// (writer "router", no Inbox refresh), once per change and core, and again for a new core; a removed account's keys go.
func TestTheRouterWritesEachAccountIntoItsCoreStore(t *testing.T) {
	newFakeAnthropic(t)
	r := newTestRouter(t)
	sk, _ := ecdh.P256().GenerateKey(rand.Reader)
	c := &accountCore{key: newTestKey(), store: sk}
	cs := httptest.NewServer(c)
	defer cs.Close()
	r.core = &CoreClient{base: cs.URL, http: http.DefaultClient}
	if code, out := signIn(t, r, "/api/claude-accounts", `{"name":"main"}`); code != 200 {
		t.Fatal(code, out)
	}
	r.syncAccountStores()
	c.mu.Lock()
	if len(c.created) != 1 || c.created[0] != "claude-main" || len(c.writes) != 2 {
		t.Fatalf("created %v, writes %v", c.created, c.writes)
	}
	cur := r.accounts().hub("claude-main").current()
	got := map[string]string{}
	for _, x := range c.writes {
		if x["writer"] != "router" || x["store"] != "claude-main" || x["sig"] != nil {
			t.Fatalf("write %v", x)
		}
		got[x["key"].(string)] = c.open(t, x)
	}
	c.mu.Unlock()
	// the store gets the pair as sessions do: without the refresh token (only the router refreshes)
	if got["CLAUDE_CREDENTIALS"] != forMachine(cur.Credentials) || strings.Contains(got["CLAUDE_CREDENTIALS"], "refreshToken") || got["CLAUDE_ACCOUNT"] != cur.Account {
		t.Fatalf("got %v", got)
	}
	// nothing changed: nothing written; no Inbox refresh was filed for the write
	r.syncAccountStores()
	c.mu.Lock()
	n := len(c.writes)
	c.mu.Unlock()
	if n != 2 {
		t.Fatalf("written again with nothing changed: %d", n)
	}
	r.st.Do(func(d *persisted) {
		if len(d.Approvals) != 0 {
			t.Fatalf("a refresh was filed: %v", d.Approvals)
		}
	})
	// a new core (another key): written again
	c.mu.Lock()
	c.key = newTestKey()
	c.mu.Unlock()
	r.syncAccountStores()
	c.mu.Lock()
	n = len(c.writes)
	c.mu.Unlock()
	if n != 4 {
		t.Fatalf("a new core didn't get the account: %d writes", n)
	}
	// removed: its keys are deleted from its store
	r.forgetAccountStore("claude-main")
	c.mu.Lock()
	defer c.mu.Unlock()
	if last := c.writes[len(c.writes)-1]; len(c.writes) != 6 || last["delete"] != true || last["writer"] != "router" {
		t.Fatalf("writes %v", c.writes)
	}
}

// A core from before the router writer refuses: the account stays the router's, tried again later, nothing breaks
func TestACoreWithoutTheRouterWriterIsTriedAgainLater(t *testing.T) {
	newFakeAnthropic(t)
	r := newTestRouter(t)
	sk, _ := ecdh.P256().GenerateKey(rand.Reader)
	c := &accountCore{key: newTestKey(), store: sk, refuse: true}
	cs := httptest.NewServer(c)
	defer cs.Close()
	r.core = &CoreClient{base: cs.URL, http: http.DefaultClient}
	signIn(t, r, "/api/claude-accounts", `{"name":"main"}`)
	r.syncAccountStores()
	accountStoreMu.Lock()
	st := accountStores["claude-main"]
	accountStoreMu.Unlock()
	if st == nil || st.written != "" || st.retry.IsZero() {
		t.Fatalf("state %+v", st)
	}
}
