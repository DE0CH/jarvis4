package main

// GET /healthz: the external uptime probe (Grafana Synthetic Monitoring, docs/RUNBOOK.md "Logs, metrics and alerts").
// Behind its own path-scoped Access app (jarvis4.deyaochen.com/healthz, ACCESS_HEALTH_AUD) that admits exactly one
// service token (HEALTH_CLIENT_ID), which the probe holds; no email login. 200 only while this router serves and its
// core serves; 503 names what isn't (a core that is empty after a reboot waits for Deyao's Recover). It reads nothing
// secret and changes nothing.

import (
	"net/http"
	"os"
)

func (r *Router) registerHealthz(public publicRoute) {
	public("GET /healthz", r.requireClient(os.Getenv("ACCESS_HEALTH_AUD"), os.Getenv("HEALTH_CLIENT_ID"))(func(w http.ResponseWriter, req *http.Request) {
		serving, _, err := coreServing(r.core)
		switch {
		case err != nil:
			writeJSON(w, 503, map[string]any{"ok": false, "router": "serving", "core": "unreachable"})
		case serving != "serving":
			writeJSON(w, 503, map[string]any{"ok": false, "router": "serving", "core": orEmptyCore(serving)})
		default:
			writeJSON(w, 200, map[string]any{"ok": true, "router": "serving", "core": "serving"})
		}
	}))
}
