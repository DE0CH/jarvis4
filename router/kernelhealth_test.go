package main

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/DE0CH/jarvis4/kernel/sig"
)

// the kernel's health on the real kernel: no roster → unhealthy; the root key's roster held by every component →
// healthy (the other copy, idle, doesn't count: it is shown down); a component that restarted (no roster), one that holds another
// roster, one that doesn't answer → unhealthy, each named
func TestKernelHealth(t *testing.T) {
	r, h, k, _ := rosterRig(t)
	r.cfg.NoCore = true
	// roles answered elsewhere
	var mu sync.Mutex
	override := map[string]string{}
	base := r.kernel.url
	r.kernel.url = func(role string) string {
		mu.Lock()
		defer mu.Unlock()
		if u, ok := override[role]; ok {
			return u
		}
		return base(role)
	}
	state := func() map[string]any {
		out := map[string]any{}
		for _, hook := range stateHooks {
			hook(r, out)
		}
		kv, _ := out["kernel"].(map[string]any)
		return kv
	}
	if kv := state(); kv == nil || kv["checked"] != false {
		t.Fatalf("before the first check: %v", kv)
	}
	if hc := r.kernelHealthCheck(); hc.Healthy || !slices.Equal(hc.Problems, []string{"No signed kernel roster"}) {
		t.Fatalf("no roster: %+v", hc)
	}
	if kv := state(); kv["checked"] != true || kv["healthy"] != false {
		t.Fatalf("api/state after the check: %v", kv)
	}
	healthz := func() (int, string) {
		mux := http.NewServeMux()
		r.registerHealthz(mux.Handle)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil))
		return rec.Code, rec.Body.String()
	}
	if c, b := healthz(); c != 503 || !strings.Contains(b, "No signed kernel roster") || strings.Contains(b, `"core"`) {
		t.Fatalf("healthz, no roster: %d %s", c, b)
	}

	rdo(t, h, "POST", "/api/kernel/root-key", map[string]string{"rootKey": k.Root.PublicKey()}, nil)
	payload := rosterOf(t, k, "blue")
	rs, _ := k.Root.Sign([]byte(payload))
	if c, out := rdo(t, h, "POST", "/api/kernel/roster", map[string]string{"payload": payload, "rootSig": rs}, nil); c != 200 {
		t.Fatalf("roster: %d %v", c, out)
	}
	if hc := r.kernelHealthCheck(); !hc.Healthy || len(hc.Problems) != 0 {
		t.Fatalf("every component holds the roster: %+v", hc)
	}
	if kv := state(); kv["healthy"] != true {
		t.Fatalf("api/state healthy: %v", kv)
	}
	// (this rig's router has no database connected: the db part alone keeps it at 503 here)
	if c, b := healthz(); !strings.Contains(b, `"kernel":"healthy"`) || (c != 200) != strings.Contains(b, "no database") {
		t.Fatalf("healthz, healthy kernel (no core): %d %s", c, b)
	}
	_, out := rdo(t, h, "GET", "/api/kernel", nil, nil)
	if out["health"].(map[string]any)["healthy"] != true {
		t.Fatalf("GET /api/kernel health: %v", out)
	}
	copies := out["health"].(map[string]any)["copies"].(map[string]any)
	blue, green := copies["blue"].(map[string]any), copies["green"].(map[string]any)
	if blue["serving"] != true || green["serving"] != false || blue["components"].(map[string]any)["notary-blue"] != "ok" ||
		green["components"].(map[string]any)["notary-green"] != "down" {
		t.Fatalf("both copies: %v", copies)
	}

	// mover restarts (fresh keys, no roster); merger answers another roster; notary doesn't answer
	k.Restart(t, "mover")
	other := httptest.NewServer(nil)
	other.Close()
	otherRoster := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, sig.Doc{Payload: `{"kind":"kernel-roster","copy":"green"}`, Sig: "x"})
	}))
	defer otherRoster.Close()
	mu.Lock()
	override["notary-blue"], override["merger-blue"] = other.URL, otherRoster.URL
	mu.Unlock()
	hc := r.kernelHealthCheck()
	want := []string{"notary-blue not answering", "mover-blue holding no roster", "merger-blue not holding the current roster"}
	if hc.Healthy || !slices.Equal(hc.Problems, want) {
		t.Fatalf("broken components: %q", hc.Problems)
	}
	if c, b := healthz(); c != 503 || !strings.Contains(b, "notary-blue not answering") {
		t.Fatalf("healthz, broken components: %d %s", c, b)
	}

	// the router's re-post makes the roster stale (mover refuses it: new keys); the stale roster is named
	mu.Lock()
	clear(override)
	mu.Unlock()
	r.rosterCheck()
	hc = r.kernelHealthCheck()
	if hc.Healthy || len(hc.Problems) == 0 || hc.Problems[0] != "Kernel roster stale: mover-blue restarted" {
		t.Fatalf("stale: %q", hc.Problems)
	}
	if !strings.Contains(strings.Join(hc.Problems, "|"), "mover-blue holding no roster") {
		t.Fatalf("mover still holds none: %q", hc.Problems)
	}

	// a router with no kernel
	if hc := (&Router{}).kernelHealthCheck(); hc.Healthy || hc.Problems[0] != "No kernel on this box" {
		t.Fatalf("no kernel: %+v", hc)
	}
	// a router with a core says nothing about the kernel in api/state
	r.cfg.NoCore = false
	if kv := state(); kv != nil {
		t.Fatalf("a core box: %v", kv)
	}
}

// every component down: one line, not nine names
func TestKernelHealthAllDown(t *testing.T) {
	r, _, _, _ := rosterRig(t)
	down := httptest.NewServer(nil)
	down.Close()
	r.kernel.url = func(string) string { return down.URL }
	hc := r.kernelHealthCheck()
	if !slices.Equal(hc.Problems, []string{"No signed kernel roster", "No kernel component answering"}) {
		t.Fatalf("all down: %q", hc.Problems)
	}
}
