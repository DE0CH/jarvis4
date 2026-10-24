package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DE0CH/jarvis4/kernel/kerneltest"
	"github.com/DE0CH/jarvis4/kernel/sig"
)

// rosterRig: a router (Access off, a setup key) on the real kernel, every Deployment of it at kerneltest's servers
// (secrets-blue = kerneltest's secrets, secrets-green = a second, empty secrets)
func rosterRig(t *testing.T) (*Router, http.Handler, *kerneltest.Kernel, key) {
	st, err := testState(t, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	setup := newTestKey()
	r := NewRouter(Config{NoAccess: true, DataDir: st.dir, SetupKey: setup.pub(), WebDir: t.TempDir()}, st, nil, Policy{})
	k := kerneltest.Start(t, map[string]string{"JARVIS2_URL": "http://router"})
	_, green := k.Secrets2(t)
	r.wireKernel(&KernelClient{url: func(role string) string {
		switch role {
		case "secrets-blue":
			return k.URLFor("secrets")
		case "secrets-green":
			return green
		}
		return k.URLFor(role)
	}, http: http.DefaultClient, ids: map[string]sig.Identity{}})
	rosterDMed.Store(false)
	return r, r.Handler(), k, setup
}

func rdo(t *testing.T, h http.Handler, method, path string, body any, setup *key) (int, map[string]any) {
	t.Helper()
	var b []byte
	if body != nil {
		b, _ = json.Marshal(body)
	}
	req := httptest.NewRequest(method, path, strings.NewReader(string(b)))
	if setup != nil {
		ts := fmt.Sprint(time.Now().Unix())
		sum := sha256.Sum256(b)
		s, _ := signP256(setup.k, []byte(method+" "+path+" "+ts+" "+hex.EncodeToString(sum[:])))
		req.Header.Set("X-Setup-Time", ts)
		req.Header.Set("X-Setup-Sig", s)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	out := map[string]any{}
	json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// rosterOf: the components' identities as the setup session reads them, as sig.RosterPayload makes the payload
func rosterOf(t *testing.T, k *kerneltest.Kernel) string {
	ids := []sig.Identity{}
	for _, role := range []string{"secrets", "spawner", "notary", "notarizer", "mover", "merger", "identity", "gullible", "minter"} {
		ids = append(ids, k.Identity(role))
	}
	p, err := sig.RosterPayload("blue", ids)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// the roster's way: the app registers its root key, the setup session reads it and files the components' identities,
// the app fetches the filing and signs it with the root key, the router posts it to every component and keeps it
func TestRosterFlow(t *testing.T) {
	r, h, k, setup := rosterRig(t)
	if c, out := rdo(t, h, "GET", "/api/kernel", nil, nil); c != 200 || out["roster"].(map[string]any)["state"] != "none" {
		t.Fatalf("before: %d %v", c, out)
	}
	if c, _ := rdo(t, h, "POST", "/api/kernel/root-key", map[string]string{"rootKey": "AAAA"}, nil); c != 400 {
		t.Fatalf("a bad root key: %d", c)
	}
	if c, _ := rdo(t, h, "GET", "/setup/kernel/root-key", nil, &setup); c != 404 {
		t.Fatalf("no root key yet: %d", c)
	}
	if c, _ := rdo(t, h, "POST", "/api/kernel/root-key", map[string]string{"rootKey": k.Root.PublicKey()}, nil); c != 200 {
		t.Fatalf("root key: %d", c)
	}
	if c, _ := rdo(t, h, "GET", "/setup/kernel/root-key", nil, nil); c != 401 {
		t.Fatalf("unsigned setup call: %d", c)
	}
	if c, out := rdo(t, h, "GET", "/setup/kernel/root-key", nil, &setup); c != 200 || out["rootKey"] != k.Root.PublicKey() {
		t.Fatalf("setup root key: %d %v", c, out)
	}

	payload := rosterOf(t, k)
	ss, _ := signP256(setup.k, []byte(payload))
	other := newTestKey()
	bad, _ := signP256(other.k, []byte(payload))
	if c, _ := rdo(t, h, "POST", "/setup/kernel/roster", map[string]string{"copy": "blue", "payload": payload, "setupSig": bad}, &setup); c != 403 {
		t.Fatalf("a roster signed by another key: %d", c)
	}
	spaced := strings.Replace(payload, `,"copy"`, `, "copy"`, 1)
	if c, _ := rdo(t, h, "POST", "/setup/kernel/roster", map[string]string{"copy": "blue", "payload": spaced, "setupSig": ss}, &setup); c != 400 {
		t.Fatalf("a payload not in RosterPayload's form: %d", c)
	}
	if c, out := rdo(t, h, "POST", "/setup/kernel/roster", map[string]string{"copy": "blue", "payload": payload, "setupSig": ss}, &setup); c != 200 {
		t.Fatalf("filing: %d %v", c, out)
	}
	if _, out := rdo(t, h, "GET", "/api/kernel", nil, nil); out["roster"].(map[string]any)["state"] != "pending" {
		t.Fatalf("after the filing: %v", out)
	}
	c, out := rdo(t, h, "GET", "/api/kernel/roster/pending", nil, nil)
	if c != 200 || out["payload"] != payload || out["setupSig"] != ss || out["copy"] != "blue" {
		t.Fatalf("pending: %d %v", c, out)
	}

	// a signature by another key is refused before anything is posted
	if c, _ := rdo(t, h, "POST", "/api/kernel/roster", map[string]string{"payload": payload, "rootSig": bad}, nil); c != 403 {
		t.Fatalf("not the root key: %d", c)
	}
	rs, _ := k.Root.Sign([]byte(payload))
	c, out = rdo(t, h, "POST", "/api/kernel/roster", map[string]string{"payload": payload, "rootSig": rs}, nil)
	if c != 200 {
		t.Fatalf("roster: %d %v", c, out)
	}
	res := out["results"].(map[string]any)
	for _, dep := range []string{"notary", "notarizer", "mover", "merger", "spawner", "identity", "gullible", "minter", "secrets-blue"} {
		if res[dep] != "taken" {
			t.Fatalf("%s: %v", dep, res[dep])
		}
	}
	if s, _ := res["secrets-green"].(string); !strings.HasPrefix(s, "standby, not named") {
		t.Fatalf("the next secrets (empty, its own keys): %v", res["secrets-green"])
	}
	c, out = rdo(t, h, "GET", "/api/kernel/roster", nil, nil)
	if c != 200 || out["payload"] != payload || out["sig"] != rs {
		t.Fatalf("current: %d %v", c, out)
	}
	if _, out := rdo(t, h, "GET", "/api/kernel", nil, nil); out["roster"].(map[string]any)["state"] != "current" {
		t.Fatalf("after the roster: %v", out)
	}
	if c, _ := rdo(t, h, "GET", "/api/kernel/roster/pending", nil, nil); c != 404 {
		t.Fatalf("the filing stays after it was signed: %d", c)
	}

	// a component restarts: new keys, no roster; the router posts the roster again, the component refuses it, and the
	// roster is stale until a new one is signed (one DM)
	var dms atomic.Int32
	dmHook = func(string) { dms.Add(1) }
	t.Cleanup(func() { dmHook = nil })
	k.Restart(t, "mover")
	r.rosterCheck()
	r.rosterCheck()
	_, out = rdo(t, h, "GET", "/api/kernel", nil, nil)
	ro := out["roster"].(map[string]any)
	stale, _ := ro["stale"].([]any)
	if ro["state"] != "stale" || len(stale) != 1 || !strings.HasPrefix(stale[0].(string), "roster stale: component mover restarted") {
		t.Fatalf("after mover's restart: %v", ro)
	}
	if dms.Load() != 1 {
		t.Fatalf("DMs: %d", dms.Load())
	}

	// the setup session files a new roster and the app signs it: current again, mover holds it
	payload2 := rosterOf(t, k)
	ss2, _ := signP256(setup.k, []byte(payload2))
	if c, _ := rdo(t, h, "POST", "/setup/kernel/roster", map[string]string{"copy": "blue", "payload": payload2, "setupSig": ss2}, &setup); c != 200 {
		t.Fatalf("second filing: %d", c)
	}
	rs2, _ := k.Root.Sign([]byte(payload2))
	if c, out := rdo(t, h, "POST", "/api/kernel/roster", map[string]string{"payload": payload2, "rootSig": rs2}, nil); c != 200 || out["results"].(map[string]any)["mover"] != "taken" {
		t.Fatalf("second roster: %d %v", c, out)
	}
	if _, out := rdo(t, h, "GET", "/api/kernel", nil, nil); out["roster"].(map[string]any)["state"] != "current" {
		t.Fatalf("after the new roster: %v", out)
	}
	if c, out := rdo(t, h, "GET", "/setup/kernel/roster", nil, &setup); c != 200 || out["secretsServing"] != "blue" || out["current"] == nil {
		t.Fatalf("setup roster: %d %v", c, out)
	}
}

// a component that answers it has no roster gets the current one posted, and the call is made again
func TestKernelCallRepostsTheRoster(t *testing.T) {
	var held atomic.Bool
	var posts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch {
		case req.URL.Path == "/roster":
			posts.Add(1)
			held.Store(true)
			writeJSON(w, 200, map[string]string{"kind": "roster-taken"})
		case !held.Load():
			writeJSON(w, 503, map[string]string{"kind": "error", "error": sig.ErrNoRoster.Error()})
		default:
			writeJSON(w, 200, map[string]string{"ok": "yes"})
		}
	}))
	defer srv.Close()
	k := &KernelClient{url: func(string) string { return srv.URL }, http: http.DefaultClient, ids: map[string]sig.Identity{}}
	if _, err := k.call("mover", "POST", "/move", map[string]any{}); err == nil || !isNoRoster(err) {
		t.Fatalf("no roster to post yet: %v", err)
	}
	k.roster = func() *sig.Doc { return &sig.Doc{Payload: "{}", Sig: "x"} }
	b, err := k.call("mover", "POST", "/move", map[string]any{})
	if err != nil || !strings.Contains(string(b), "yes") || posts.Load() != 1 {
		t.Fatalf("after the re-post: %v %s posts=%d", err, b, posts.Load())
	}

	// a component that refuses it (restarted: new keys) makes the roster stale, and the call fails saying so
	refuse := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/roster" {
			writeJSON(w, 403, map[string]string{"error": "the roster doesn't name this notary's keys"})
			return
		}
		writeJSON(w, 503, map[string]string{"error": sig.ErrNoRoster.Error()})
	}))
	defer refuse.Close()
	var stale string
	k2 := &KernelClient{url: func(string) string { return refuse.URL }, http: http.DefaultClient, ids: map[string]sig.Identity{},
		roster: k.roster, onStale: func(dep, msg string) { stale = msg }}
	if _, err := k2.call("notary", "POST", "/challenge", map[string]any{}); err == nil || !strings.Contains(err.Error(), "roster stale: component notary restarted") {
		t.Fatalf("refused: %v", err)
	}
	if !strings.HasPrefix(stale, "roster stale: component notary restarted") {
		t.Fatalf("stale: %q", stale)
	}
}
