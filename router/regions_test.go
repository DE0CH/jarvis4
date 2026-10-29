package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

// a session's region goes into every spawn of its machine (the router's default when it has none); New session
// refuses a region it doesn't offer (regions.go)
func TestASessionStartsInItsRegion(t *testing.T) {
	rg, k := kernelRig(t)
	var mu sync.Mutex
	var spawned []string
	rg.r.kernel.http = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if strings.HasSuffix(req.URL.Path, "/spawn") && req.Body != nil {
			b, _ := io.ReadAll(req.Body)
			req.Body = io.NopCloser(bytes.NewReader(b))
			var in struct {
				Region string `json:"region"`
			}
			_ = json.Unmarshal(b, &in)
			mu.Lock()
			spawned = append(spawned, in.Region)
			mu.Unlock()
		}
		return http.DefaultTransport.RoundTrip(req)
	})}
	if _, err := rg.r.CreateSession(NewSession{Label: "x", Harness: "claude", Region: "hkg"}); err == nil || !strings.Contains(err.Error(), "region") {
		t.Fatalf("an unknown region: %v", err)
	}
	spawnedIn := func(region string) {
		t.Helper()
		waitFor(t, "a spawn in "+region, func() bool {
			mu.Lock()
			defer mu.Unlock()
			return len(spawned) > 0 && spawned[len(spawned)-1] == region
		})
	}
	sid := kernelStartIn(t, rg, k, NewSession{Label: "near Hong Kong", Harness: "claude", Region: "sin"})
	spawnedIn("sin")
	if s := kernelSession(rg, sid); s.Region != "sin" || rg.r.regionOf(&s) != "sin" {
		t.Fatalf("session region %q", s.Region)
	}
	kernelStart(t, rg, k, "default")
	spawnedIn("lhr")
}

func TestTheRegionsList(t *testing.T) {
	r := newTestRouter(t)
	r.cfg.Region = "lhr"
	code, out := appDo(t, r, "GET", "/api/regions", "")
	regions, _ := out["regions"].([]any)
	if code != 200 || out["default"] != "lhr" || len(regions) != len(sessionRegions) || regions[1].(map[string]any)["id"] != "sin" {
		t.Fatalf("%d %v", code, out)
	}
}
