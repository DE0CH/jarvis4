package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// carryCore: a core that answers pulls and forwards with carry blobs (old = a core that predates them: no carry
// in its answers, 404 on /carry/forward)
type carryCore struct {
	mu    sync.Mutex
	old   bool
	calls []map[string]any
}

func (c *carryCore) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	b, _ := io.ReadAll(req.Body)
	in := map[string]any{"path": req.URL.Path}
	json.Unmarshal(b, &in)
	in["path"] = req.URL.Path
	c.mu.Lock()
	c.calls = append(c.calls, in)
	old := c.old
	c.mu.Unlock()
	doc := func(v map[string]any) {
		p, _ := json.Marshal(v)
		json.NewEncoder(w).Encode(map[string]string{"payload": string(p), "sig": "s"})
	}
	switch {
	case req.URL.Path == "/pull-secrets" && old:
		doc(map[string]any{"kind": "secrets"})
	case req.URL.Path == "/pull-secrets":
		doc(map[string]any{"kind": "secrets", "carry": "blob-after-pull-" + in["carry"].(string)})
	case req.URL.Path == "/carry/forward" && !old:
		doc(map[string]any{"kind": "carry", "carry": "forwarded-" + in["carry"].(string)})
	default:
		http.NotFound(w, req)
	}
}

func (c *carryCore) last() map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls[len(c.calls)-1]
}

func carryRouter(t *testing.T, old bool) (*Router, *carryCore) {
	r := newTestRouter(t)
	cc := &carryCore{old: old}
	s := httptest.NewServer(cc)
	t.Cleanup(s.Close)
	r.core = &CoreClient{base: s.URL, http: http.DefaultClient}
	return r, cc
}

func certDoc(machine, pred string) *Doc {
	p, _ := json.Marshal(map[string]any{"kind": "succession-cert", "predecessorId": pred, "machine": map[string]string{"id": machine}})
	return &Doc{Payload: string(p), Sig: "s"}
}

func TestTheRouterKeepsAndForwardsTheCarriedSecrets(t *testing.T) {
	r, cc := carryRouter(t, false)
	// m1's first pull: no blob yet; the answer's blob is kept for m1
	if b := r.carryForPull("m1", certDoc("m1", "")); b != "" {
		t.Fatalf("a blob before any pull: %q", b)
	}
	d, err := r.core.Call("/pull-secrets", map[string]any{"cert": certDoc("m1", ""), "carry": ""})
	if err != nil {
		t.Fatal(err)
	}
	r.pulled("m1", certDoc("m1", ""), d)
	if r.readCarry("m1") != "blob-after-pull-" {
		t.Fatalf("kept %q", r.readCarry("m1"))
	}
	// a resume: m2 certified as m1's successor → forwarded to m2, m1's dropped
	r.forwardCarry("m1", certDoc("m2", "m1"), "m2")
	if f := cc.last(); f["path"] != "/carry/forward" || f["carry"] != "blob-after-pull-" {
		t.Fatalf("forward: %v", f)
	}
	if r.readCarry("m2") != "forwarded-blob-after-pull-" || r.readCarry("m1") != "" {
		t.Fatalf("m2 %q, m1 %q", r.readCarry("m2"), r.readCarry("m1"))
	}
	// m2's pull sends its own blob
	if b := r.carryForPull("m2", certDoc("m2", "m1")); b != "forwarded-blob-after-pull-" {
		t.Fatalf("pull sends %q", b)
	}
	// a successor whose forward didn't happen sends its predecessor's
	r.saveCarry("m3", "m3-blob")
	if b := r.carryForPull("m4", certDoc("m4", "m3")); b != "m3-blob" {
		t.Fatalf("pull sends %q", b)
	}
	// destroy: finish drops the blobs with the snapshots
	addSession(r, "s1", "paused", "", false)
	r.st.Do(func(d *persisted) { d.Machines["m2"] = "s1" })
	r.finish("s1", nil)
	if r.readCarry("m2") != "" {
		t.Fatal("the blob outlived the session")
	}
}

func TestACoreWithoutCarriedSecretsChangesNothing(t *testing.T) {
	r, _ := carryRouter(t, true)
	d, err := r.core.Call("/pull-secrets", map[string]any{"cert": certDoc("m1", ""), "carry": ""})
	if err != nil {
		t.Fatal(err)
	}
	r.pulled("m1", certDoc("m1", ""), d)
	if r.readCarry("m1") != "" {
		t.Fatal("kept a blob from a core that has none")
	}
	r.saveCarry("m1", "x")
	r.forwardCarry("m1", certDoc("m2", "m1"), "m2") // 404: ignored
	if r.readCarry("m2") != "" || r.readCarry("m1") != "x" {
		t.Fatal("a failed forward moved or dropped a blob")
	}
}
