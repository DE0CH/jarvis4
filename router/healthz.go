package main

// GET /healthz: an uptime check behind its own Access service token (the Grafana probe that called it is gone, DECISIONS 237).
// Behind its own path-scoped Access app (jarvis4.deyaochen.com/healthz, ACCESS_HEALTH_AUD) that admits exactly one
// service token (HEALTH_CLIENT_ID), which the probe holds; no email login. 200 only while this router serves and its
// core serves (and its database answers, with this router's schema, and takes every record write); 503 names what isn't (a core that is empty after a reboot waits for Deyao's Recover). It reads nothing
// secret and changes nothing. A router with no core (NO_CORE=1, Jarvis 4) answers for the kernel instead: 200 while
// its last check found the kernel healthy (kernelhealth.go), 503 with "kernel": [what is wrong].

import (
	"net/http"
	"os"
)

func (r *Router) registerHealthz(public publicRoute) {
	public("GET /healthz", r.requireClient(os.Getenv("ACCESS_HEALTH_AUD"), os.Getenv("HEALTH_CLIENT_ID"))(func(w http.ResponseWriter, req *http.Request) {
		db := r.dbStatus(req.Context())
		dbText := "ok"
		if !db.OK {
			dbText = db.Error
		}
		if r.cfg.NoCore {
			r.kernelHealthz(w, db.OK, dbText)
			return
		}
		serving, _, err := coreServing(r.core)
		switch {
		case err != nil:
			writeJSON(w, 503, map[string]any{"ok": false, "router": "serving", "core": "unreachable", "db": dbText})
		case serving != "serving":
			writeJSON(w, 503, map[string]any{"ok": false, "router": "serving", "core": orEmptyCore(serving), "db": dbText})
		case !db.OK:
			writeJSON(w, 503, map[string]any{"ok": false, "router": "serving", "core": "serving", "db": dbText})
		default:
			writeJSON(w, 200, map[string]any{"ok": true, "router": "serving", "core": "serving", "db": dbText})
		}
	}))
}

// kernelHealthz: /healthz on a router with no core
func (r *Router) kernelHealthz(w http.ResponseWriter, dbOK bool, dbText string) {
	h := r.kernelHealthNow.Load()
	switch {
	case h == nil:
		writeJSON(w, 503, map[string]any{"ok": false, "router": "serving", "kernel": []string{"not checked yet"}, "db": dbText})
	case !h.Healthy:
		writeJSON(w, 503, map[string]any{"ok": false, "router": "serving", "kernel": h.Problems, "db": dbText})
	case !dbOK:
		writeJSON(w, 503, map[string]any{"ok": false, "router": "serving", "kernel": "healthy", "db": dbText})
	default:
		writeJSON(w, 200, map[string]any{"ok": true, "router": "serving", "kernel": "healthy", "db": dbText})
	}
}
