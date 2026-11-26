package main

// The fabric's operator page (Deyao, 2026-11-20: "I should be able to see the machines and scaler view just like that
// in YYC AI"): the fabric hermit's own /ops/ page and its snapshot, the page YYC AI's admins open on their hermit (the
// same build: status, hosts and their slots, live and frozen sandboxes, the scaler, errors). YYC AI reaches it through
// pigeon as an admin of its catalogue; the fabric hermit has no pigeon, so the router asks it with hermit's admin
// token, behind Deyao's Access login like every app route. Read only: GET of the page and of the snapshot it polls
// (its script fetches "snapshot?tz=…" relative to the page, so both live under one prefix).

import (
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// fabricOpsPaths: the app's paths and the fabric hermit's (hermit-api routes OPS_PAGE, OPS_SNAPSHOT)
var fabricOpsPaths = map[string]string{
	"GET /api/fabric/ops/":         "/ops/",
	"GET /api/fabric/ops/snapshot": "/ops/snapshot",
}

// the page's own headers that come through (its CSP and referrer policy; hermit ops.rs page_headers)
var fabricOpsHeaders = []string{"Content-Type", "Content-Security-Policy", "Referrer-Policy", "Cache-Control"}

func (r *Router) registerFabricOps(app appRoute) {
	for pattern, path := range fabricOpsPaths {
		app(pattern, r.fabricOps(path))
	}
}

// fabricOpsClient: the calls to the fabric hermit (a var: tests)
var fabricOpsClient = &http.Client{Timeout: 30 * time.Second}

func (r *Router) fabricOps(path string) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		base, token := strings.TrimRight(os.Getenv("FABRIC_HERMIT_URL"), "/"), os.Getenv("FABRIC_HERMIT_ADMIN_TOKEN")
		if base == "" || token == "" {
			writeJSON(w, 503, map[string]string{"error": "this router has no fabric operator page (FABRIC_HERMIT_URL, FABRIC_HERMIT_ADMIN_TOKEN)"})
			return
		}
		u := base + path
		if q := req.URL.RawQuery; q != "" {
			u += "?" + q
		}
		out, _ := http.NewRequestWithContext(req.Context(), "GET", u, nil)
		out.Header.Set("Authorization", "Bearer "+token)
		out.Header.Set("Aviary-Protocol", "hermit-core=1")
		resp, err := fabricOpsClient.Do(out)
		if err != nil {
			writeJSON(w, 502, map[string]string{"error": "the fabric hermit did not answer: " + err.Error()})
			return
		}
		defer resp.Body.Close()
		for _, h := range fabricOpsHeaders {
			if v := resp.Header.Get(h); v != "" {
				w.Header().Set(h, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, io.LimitReader(resp.Body, 16<<20))
	}
}
