package main

import (
	"net/http"
	"time"
)

// GET /setup/services (the setup session; infra/setup.py services): the watch runner as the router reaches it, for an
// operator with no way into the cluster: a check script that only prints, through the same call a watch's check makes.
// Nothing is written. Transcript search is not Jarvis's (DE0CH/services, search.deyaochen.com).
func (r *Router) setupServices(w http.ResponseWriter, req *http.Request) {
	if err := r.checkSetupSig(req.Method, req.URL.RequestURI(), req.Header.Get("X-Setup-Time"), req.Header.Get("X-Setup-Sig"), nil); err != nil {
		writeJSON(w, 401, map[string]string{"error": err.Error()})
		return
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
	writeJSON(w, 200, map[string]any{"replica": routerID, "watch": map[string]any{"url": watchRunnerURL(), "run": watch}})
}
