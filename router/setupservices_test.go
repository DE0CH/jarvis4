package main

import (
	"testing"
)

// GET /setup/services: a check on the watch runner; only for the setup key
func TestSetupServices(t *testing.T) {
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
	c, out := rdo(t, h, "GET", "/setup/services", nil, &setup)
	if c != 200 || out["search"] != nil {
		t.Fatalf("%d %v", c, out)
	}
	if w := out["watch"].(map[string]any)["run"].(map[string]any); w["exit"].(float64) != 0 || w["stdout"] != "watch runner ok" {
		t.Fatalf("watch: %v", w)
	}
}
