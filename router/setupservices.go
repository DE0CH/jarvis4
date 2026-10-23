package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"time"
)

// GET /setup/services (the setup session; infra/setup.py services): the shared services as the router reaches them,
// for an operator with no way into the cluster. Transcript search: its /status (counts, the replica that answered)
// and one keyword search (?q=, default "jarvis") through the same path the app's /api/search takes; the watch
// runner: a check script that only prints, through the same call a watch's check makes. Nothing is written. The
// setup signature covers the query too.
func (r *Router) setupServices(w http.ResponseWriter, req *http.Request) {
	if err := r.checkSetupSig(req.Method, req.URL.RequestURI(), req.Header.Get("X-Setup-Time"), req.Header.Get("X-Setup-Sig"), nil); err != nil {
		writeJSON(w, 401, map[string]string{"error": err.Error()})
		return
	}
	q := req.URL.Query().Get("q")
	if q == "" {
		q = "jarvis"
	}
	base, _ := serviceBase("search")
	get := func(path string) map[string]any {
		t0 := time.Now()
		out := map[string]any{}
		hreq, _ := http.NewRequestWithContext(req.Context(), "GET", base+path, nil)
		resp, err := searchClient.Do(hreq)
		out["ms"] = time.Since(t0).Milliseconds()
		if err != nil {
			out["error"] = err.Error()
			return out
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		out["status"] = resp.StatusCode
		var v any
		if json.Unmarshal(b, &v) != nil {
			out["body"] = trimTo(string(b), 300)
		} else {
			out["body"] = v
		}
		return out
	}
	status := get("/status")
	if m, ok := status["body"].(map[string]any); ok { // counts and the replica only, not the indexer's details
		keep := map[string]any{}
		for _, k := range []string{"ok", "chunks", "sessions", "files", "vectors", "vectorsLoaded", "span", "embedModel"} {
			keep[k] = m[k]
		}
		if rp, ok := m["replica"].(map[string]any); ok {
			keep["replica"] = map[string]any{"pod": rp["pod"], "role": rp["role"], "kubernetes": rp["kubernetes"]}
		}
		status["body"] = keep
	}
	search := get("/search?" + url.Values{"q": {q}, "mode": {"keyword"}, "limit": {"3"}, "rerank": {"false"}}.Encode())
	if m, ok := search["body"].(map[string]any); ok { // how many hits, not their text
		hits, _ := m["hits"].([]any)
		search["body"] = map[string]any{"hits": len(hits), "total": m["total"], "tookMs": m["tookMs"]}
	}
	t0 := time.Now()
	watch := map[string]any{}
	res, err := runCheckHook(&Watch{Name: "setup-services-check", Script: "echo watch runner ok; exit 0"})
	watch["ms"] = time.Since(t0).Milliseconds()
	if err != nil {
		watch["error"] = err.Error()
	} else {
		watch["exit"], watch["stdout"], watch["timedOut"] = res.Exit, trimTo(res.Stdout, 200), res.TimedOut
	}
	writeJSON(w, 200, map[string]any{"replica": routerID, "search": map[string]any{"url": base, "status": status, "query": q, "search": search},
		"watch": map[string]any{"url": watchRunnerURL(), "run": watch}})
}
