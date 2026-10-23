package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// GET /setup/services: search's counts and a search's hit count through the router's service path, a check on the
// watch runner; only for the setup key
func TestSetupServices(t *testing.T) {
	var gotQ string
	svc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/status":
			json.NewEncoder(w).Encode(map[string]any{"ok": true, "chunks": 12, "vectorsLoaded": 12, "indexer": map[string]any{"x": 1},
				"replica": map[string]any{"pod": "search-a", "role": "writer", "memory": 1}})
		case "/search":
			gotQ = req.URL.Query().Get("q")
			json.NewEncoder(w).Encode(map[string]any{"hits": []any{map[string]any{"snippet": "secret words"}, map[string]any{}}, "total": 7})
		}
	}))
	defer svc.Close()
	t.Setenv("SEARCH_URL", svc.URL)
	old := runCheckHook
	runCheckHook = func(w *Watch) (*checkResult, error) { return &checkResult{Exit: 0, Stdout: "watch runner ok\n"}, nil }
	defer func() { runCheckHook = old }()
	st, err := testState(t, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	setup := newTestKey()
	r := NewRouter(Config{NoAccess: true, DataDir: st.dir, SetupKey: setup.pub(), WebDir: t.TempDir()}, st, nil, Policy{})
	h := r.Handler()
	if c, _ := rdo(t, h, "GET", "/setup/services", nil, nil); c != 401 {
		t.Fatalf("unsigned: %d", c)
	}
	c, out := rdo(t, h, "GET", "/setup/services?q=pause", nil, &setup)
	if c != 200 || gotQ != "pause" {
		t.Fatalf("%d %q %v", c, gotQ, out)
	}
	s := out["search"].(map[string]any)
	st0 := s["status"].(map[string]any)["body"].(map[string]any)
	if st0["chunks"].(float64) != 12 || st0["indexer"] != nil || st0["replica"].(map[string]any)["pod"] != "search-a" {
		t.Fatalf("status: %v", st0)
	}
	if b := s["search"].(map[string]any)["body"].(map[string]any); b["hits"].(float64) != 2 || b["total"].(float64) != 7 || b["snippet"] != nil {
		t.Fatalf("search: %v", s["search"])
	}
	if w := out["watch"].(map[string]any)["run"].(map[string]any); w["exit"].(float64) != 0 || w["stdout"] != "watch runner ok" {
		t.Fatalf("watch: %v", w)
	}
}
