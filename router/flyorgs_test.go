package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// a fake Machines API: org → apps, app → machines (raw Fly JSON, env included) and volumes; records the tokens used
func fakeFlyOrgs(t *testing.T, orgTokens map[string]string, apps map[string][]string, machines map[string][]map[string]any, volumes map[string][]map[string]any) (*httptest.Server, func() []string) {
	var mu sync.Mutex // the overview asks for every app's machines and volumes in parallel
	var seen []string
	appOrg := map[string]string{}
	for org, as := range apps {
		for _, a := range as {
			appOrg[a] = org
		}
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		auth := req.Header.Get("Authorization")
		mu.Lock()
		seen = append(seen, req.URL.Path+" "+auth)
		mu.Unlock()
		org := req.URL.Query().Get("org_slug")
		if req.URL.Path == "/v1/apps" {
			if auth != "Bearer "+orgTokens[org] {
				w.WriteHeader(403)
				w.Write([]byte(`{"error":"unauthorized"}`))
				return
			}
			list := []map[string]string{}
			for _, a := range apps[org] {
				list = append(list, map[string]string{"name": a, "status": "deployed"})
			}
			json.NewEncoder(w).Encode(map[string]any{"apps": list})
			return
		}
		parts := strings.Split(strings.TrimPrefix(req.URL.Path, "/v1/apps/"), "/")
		if auth != "Bearer "+orgTokens[appOrg[parts[0]]] {
			w.WriteHeader(403)
			return
		}
		switch parts[1] {
		case "machines":
			json.NewEncoder(w).Encode(append([]map[string]any{}, machines[parts[0]]...))
		case "volumes":
			json.NewEncoder(w).Encode(append([]map[string]any{}, volumes[parts[0]]...))
		}
	}))
	t.Cleanup(srv.Close)
	return srv, func() []string { mu.Lock(); defer mu.Unlock(); return append([]string{}, seen...) }
}

func rawM(id, state, created string) map[string]any {
	return map[string]any{"id": id, "name": "n-" + id, "state": state, "region": "arn", "created_at": created,
		"config": map[string]any{"image": "img", "guest": map[string]any{"cpu_kind": "shared", "cpus": 2, "memory_mb": 2048},
			"env": map[string]string{"SECRET_THING": "TOPSECRET"}}}
}

func TestFlyOrgsOverviewEveryOrgReadOnly(t *testing.T) {
	now := time.Now().UTC()
	old := now.Add(-48 * time.Hour).Format(time.RFC3339)
	srv, seen := fakeFlyOrgs(t, map[string]string{"jarvis2-370": "tok-j2", "other": "tok-k", "personal": "tok-p"},
		map[string][]string{"jarvis2-370": {"jarvis4-sessions", "zz-stray"}, "other": {"other-sessions"}, "personal": {"de0ch-claude-sessions"}},
		map[string][]map[string]any{"zz-stray": {rawM("st1", "started", old)}, "other-sessions": {rawM("k1", "stopped", old), rawM("k2", "started", old)},
			"de0ch-claude-sessions": {rawM("p1", "started", old), rawM("p2", "stopped", old)}},
		map[string][]map[string]any{"zz-stray": {{"id": "vol_1", "state": "created", "size_gb": 1, "created_at": old},
			{"id": "vol_deleted", "state": "pending_destroy", "size_gb": 10, "created_at": old}}})
	oldBase := flyAPIBase
	defer func() { flyAPIBase = oldBase }()
	flyAPIBase = srv.URL
	t.Setenv("FLY_ORG_READ_TOKENS", `{"jarvis2-370":"tok-j2","other":"tok-k"}`)
	t.Setenv("FLY_PERSONAL_READ_TOKEN", "tok-p")

	r := newTestRouter(t)
	addSession(r, "s1", "running", "m-cur", false)
	own := []flyMachineDetail{flyM("m-cur", "started", old, prodURL), flyM("m-orphan", "stopped", old, prodURL)}
	orgs, cerr := r.flyOrgsOverview(own, now)
	if cerr != "" {
		t.Fatal(cerr)
	}
	if len(orgs) != 3 || orgs[0].Org != "jarvis2-370" || orgs[1].Org != "other" || orgs[2].Org != "personal" || orgs[2].Via != "fly" {
		t.Fatalf("orgs %+v", orgs)
	}
	j2 := orgs[0]
	if len(j2.Apps) != 2 || !j2.Apps[0].Own || j2.Apps[0].App != "jarvis4-sessions" || len(j2.Apps[0].Machines) != 2 {
		t.Fatalf("own org %+v", j2)
	}
	if m := j2.Apps[0].Machines[1]; m.ID != "m-orphan" && j2.Apps[0].Machines[0].ID != "m-orphan" {
		t.Fatalf("own machines %+v", j2.Apps[0].Machines)
	}
	stray := j2.Apps[1]
	// a deleted volume (pending_destroy: Fly purges it, unbilled) is not listed, so not a leak
	if stray.Own || stray.Machines[0].Attention == "" || stray.Machines[0].NoDestroy == "" || len(stray.Volumes) != 1 || stray.Volumes[0].Attention == "" {
		t.Fatalf("stray app %+v", stray)
	}
	k := orgs[1].Apps[0]
	att := map[string]string{}
	for _, m := range k.Machines {
		att[m.ID] = m.Attention
	}
	// an app no Jarvis runs sessions in: its started machine stands out too
	if !strings.HasPrefix(att["k1"], "Stopped") || !strings.HasPrefix(att["k2"], "In an app no Jarvis") {
		t.Fatalf("other %+v", att)
	}
	p := orgs[2].Apps[0]
	pa := map[string]string{}
	for _, m := range p.Machines {
		pa[m.ID] = m.Attention
	}
	if p.Own || p.Label != "Jarvis 1 sessions" || len(p.Machines) != 2 || pa["p1"] != "" || !strings.HasPrefix(pa["p2"], "Stopped") || p.Machines[0].NoDestroy == "" {
		t.Fatalf("personal %+v", p)
	}
	// own: m-orphan stopped (1) · stray machine + volume (2) · k1, k2 (2) · p2 (1)
	if n := flyAttentionCount(orgs); n != 6 {
		t.Fatalf("attention %d", n)
	}
	b, _ := json.Marshal(orgs)
	if strings.Contains(string(b), "TOPSECRET") || strings.Contains(string(b), "SECRET_THING") {
		t.Fatal("a machine's env left the router")
	}
	// each org is read with its own token, and never with another org's
	for _, s := range seen() {
		if (strings.Contains(s, "other-sessions") && !strings.HasSuffix(s, "tok-k")) ||
			(strings.Contains(s, "de0ch-claude-sessions") && !strings.HasSuffix(s, "tok-p")) {
			t.Fatalf("wrong token: %s", s)
		}
	}
}

func TestFlyOrgsOverviewFailuresAreShown(t *testing.T) {
	now := time.Now().UTC()
	srv, _ := fakeFlyOrgs(t, map[string]string{"other": "right"}, map[string][]string{"other": {}}, nil, nil)
	oldBase := flyAPIBase
	defer func() { flyAPIBase = oldBase }()
	flyAPIBase = srv.URL
	t.Setenv("FLY_ORG_READ_TOKENS", `{"other":"wrong"}`)
	t.Setenv("FLY_PERSONAL_READ_TOKEN", "")
	r := newTestRouter(t)
	orgs, _ := r.flyOrgsOverview(nil, now)
	if len(orgs) != 3 {
		t.Fatalf("%+v", orgs)
	}
	if orgs[0].Error == "" || len(orgs[0].Apps) != 1 || !orgs[0].Apps[0].Own { // no own-org token: the sessions app alone, said so
		t.Fatalf("own %+v", orgs[0])
	}
	if !strings.Contains(orgs[1].Error, "403") {
		t.Fatalf("other %+v", orgs[1])
	}
	if orgs[2].Org != "personal" || !strings.Contains(orgs[2].Error, "FLY_PERSONAL_READ_TOKEN") {
		t.Fatalf("personal %+v", orgs[2])
	}
	t.Setenv("FLY_ORG_READ_TOKENS", "{bad")
	if _, cerr := r.flyOrgsOverview(nil, now); !strings.Contains(cerr, "not valid JSON") {
		t.Fatal(cerr)
	}
}

// an app Jarvis 4 itself runs (the log shipper) says what it is and what it costs, and its machine isn't flagged
func TestFlyOrgsOverviewOwnInfraApp(t *testing.T) {
	now := time.Now().UTC()
	old := now.Add(-48 * time.Hour).Format(time.RFC3339)
	ship := rawM("ls1", "started", old)
	ship["config"].(map[string]any)["guest"] = map[string]any{"cpu_kind": "shared", "cpus": 1, "memory_mb": 256}
	srv, _ := fakeFlyOrgs(t, map[string]string{"jarvis2-370": "tok-j2"},
		map[string][]string{"jarvis2-370": {"jarvis4-sessions", "jarvis2-log-shipper"}},
		map[string][]map[string]any{"jarvis2-log-shipper": {ship}}, nil)
	oldBase := flyAPIBase
	defer func() { flyAPIBase = oldBase }()
	flyAPIBase = srv.URL
	t.Setenv("FLY_ORG_READ_TOKENS", `{"jarvis2-370":"tok-j2"}`)
	t.Setenv("FLY_PERSONAL_READ_TOKEN", "")
	r := newTestRouter(t)
	orgs, _ := r.flyOrgsOverview(nil, now)
	var a *flyAppView
	for i := range orgs[0].Apps {
		if orgs[0].Apps[i].App == "jarvis2-log-shipper" {
			a = &orgs[0].Apps[i]
		}
	}
	// shared-cpu-1x 256 MB at budget.go's lhr rates: 8.465e-7 × 3600 × 1.134615385 × 730 h
	want := "Jarvis 4's log shipper: sends the session machines' logs to Grafana Cloud · USD 2.52/month"
	if a == nil || a.Label != want || len(a.Machines) != 1 || a.Machines[0].Attention != "" {
		t.Fatalf("log shipper %+v", a)
	}
	// a stopped one is still flagged (the Stopped line), and costs nothing started
	if got := attentionOf("stopped", old, false, "", "jarvis2-log-shipper", now); !strings.HasPrefix(got, "Stopped") {
		t.Fatalf("stopped: %q", got)
	}
	if got := ownAppLabel("x", nil); got != "x" {
		t.Fatalf("no machines: %q", got)
	}
}
