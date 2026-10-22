package main

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, err error) {
	var gn *GrantNeeded
	if errors.As(err, &gn) {
		writeJSON(w, 403, map[string]any{"error": err.Error(), "needsGrant": gn.Holder, "phoneGrant": gn.Phone})
		return
	}
	var ce *CoreError
	if errors.As(err, &ce) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(ce.Status)
		w.Write(ce.Body) // the core's signed error, unchanged
		return
	}
	status := 400
	switch {
	case errors.Is(err, errDraining):
		status = 503 // drain.go: "router updating, try again shortly", shown as is
	case errors.Is(err, errBusy):
		status = 409
	}
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

// MachineHandler: /m only, for the listener that only Fly's private network reaches
func (r *Router) MachineHandler() http.Handler {
	r.handlers()
	return r.gatedMachine(r.machineMux) // movegate.go
}

// Handler: the public listener behind cloudflared — the app, the web page and setup
func (r *Router) Handler() http.Handler {
	r.handlers()
	return r.gated(r.publicMux) // movegate.go
}

func (r *Router) handlers() {
	r.muxOnce.Do(r.buildHandlers)
}

func (r *Router) buildHandlers() {
	mux, mmux := http.NewServeMux(), http.NewServeMux()
	r.publicMux, r.machineMux = mux, mmux
	r.appPatterns = map[string]bool{}
	app := func(pattern string, fn http.HandlerFunc) {
		r.appPatterns[pattern] = true
		mux.Handle(pattern, r.requireDeyao(fn))
	}
	m := func(pattern string, fn func(w http.ResponseWriter, req *http.Request, machine string, body []byte)) {
		mmux.Handle(pattern, r.requireMachine(fn))
	}
	// setup: the setup session's Access token AND its key's signature (checked here, by the router: the
	// core's store calls are open, the router decides who uses them)
	setup := func(pattern, method, corePath string) {
		mux.Handle(pattern, r.requireSetup(func(w http.ResponseWriter, req *http.Request) {
			b, _ := io.ReadAll(io.LimitReader(req.Body, 1<<20))
			if err := r.checkSetupSig(req.Method, req.URL.Path, req.Header.Get("X-Setup-Time"), req.Header.Get("X-Setup-Sig"), b); err != nil {
				writeJSON(w, 401, map[string]string{"error": err.Error()})
				return
			}
			if method == "GET" {
				b = nil
			}
			r.relay(w, method, corePath, b)
		}))
	}
	r.registerFeatures(app, m, mux.Handle)
	r.registerStoreDocs(app, m, mux) // storedocs.go: every store's keys, what they are for, and writing one key
	r.registerRestore(app, mux)      // storerestore.go: a store's versions and putting one back (phone-signed)
	r.registerActions(m)             // actions.go: each session's actions, on its machine key
	r.registerNextCore(mux)          // nextcore.go: the flip to the next core
	r.registerHealthz(mux.Handle)    // healthz.go: the external uptime probe
	// the router's own health, for an operator with no way into the box: secret NAMES present, image, core up
	mux.Handle("GET /setup/status", r.requireSetup(func(w http.ResponseWriter, req *http.Request) {
		if err := r.checkSetupSig(req.Method, req.URL.Path, req.Header.Get("X-Setup-Time"), req.Header.Get("X-Setup-Sig"), nil); err != nil {
			writeJSON(w, 401, map[string]string{"error": err.Error()})
			return
		}
		present := []string{}
		for _, k := range []string{"LOBSTER_TOKEN", "STORAGEBOX_HOST", "STORAGEBOX_USER", "STORAGEBOX_PASSWORD", "FLY_READ_TOKEN",
			"JARVIS2_TUNNEL_KEY",
			"GITHUB_READ_TOKEN", "BACKUP_READ_ACCESS_KEY", "BACKUP_READ_SECRET_KEY", "FLY_ORG_READ_TOKENS",
			"FLY_PERSONAL_READ_TOKEN", "FLY_VOLUME_TOKEN", "BROWSERBASE_API_KEY", "CF_DEVICE_TOKENS_API"} {
			if os.Getenv(k) != "" {
				present = append(present, k)
			}
		}
		_, coreErr := r.core.Key()
		// what the repo picker's token sees, as counts only: a token with no permission picked lists public repos
		// only (private 0), the "No match." in Settings → Repos
		gh := map[string]any{}
		if repos, _, err := r.GitHubRepos(false); err != nil {
			gh["error"] = err.Error()
		} else {
			priv := 0
			for _, x := range repos {
				if x.Private {
					priv++
				}
			}
			gh["total"], gh["private"] = len(repos), priv
		}
		// the Machines view's orgs, as counts only (flyorgs.go): each org's source and error, apps, machines, flagged
		flyOrgs := []map[string]any{}
		ownMs, _ := listFlyMachines()
		orgs, _ := r.flyOrgsOverview(ownMs, time.Now())
		for _, o := range orgs {
			apps, machines := []string{}, 0
			for _, a := range o.Apps {
				apps = append(apps, a.App)
				machines += len(a.Machines)
			}
			flyOrgs = append(flyOrgs, map[string]any{"org": o.Org, "via": o.Via, "error": o.Error, "apps": apps, "machines": machines,
				"attention": flyAttentionCount([]flyOrgView{o})})
		}
		writeJSON(w, 200, map[string]any{"secrets": present, "sessionImage": r.cfg.SessionImage, "coreUp": coreErr == nil, "version": os.Getenv("VERSION"), "githubRepos": gh, "flyOrgs": flyOrgs,
			"move": moveStatusNow(), "backup": backupStatus(), "core": r.nextCoreStatus(), "process": processStatus(),
			"volumeSweep": volumeSweepStatus(), "db": r.dbStatus(req.Context())})
	}))
	setup("GET /setup/identity", "GET", "/identity")
	setup("POST /setup/stores", "POST", "/stores")
	setup("POST /setup/stores/create", "POST", "/stores/create")
	setup("POST /setup/stores/mark-sensitive", "POST", "/stores/mark-sensitive")
	// the core's Fly token, sealed to the core (after a Reset; a Recover brings it from the backups)
	setup("POST /setup/fly-token", "POST", "/fly-token")
	// the kernel's spawner (kernelline.go): its identity, and the Fly token sealed to it (infra/setup.py kernel-fly-token)
	mux.Handle("GET /setup/kernel/spawner/identity", r.requireSetup(func(w http.ResponseWriter, req *http.Request) {
		if r.kernel == nil {
			writeJSON(w, 503, map[string]string{"error": "this box runs no kernel"})
			return
		}
		b, err := r.kernel.call("spawner", "GET", "/identity", nil)
		if err != nil {
			writeErr(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(b)
	}))
	mux.Handle("POST /setup/kernel/secrets/flip", r.requireSetup(func(w http.ResponseWriter, req *http.Request) {
		c, err := r.FlipSecrets() // kernel.go: the standby secrets serves from now on
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]string{"serving": "secrets-" + c})
	}))
	mux.Handle("POST /setup/kernel/spawner/fly-token", r.requireSetup(func(w http.ResponseWriter, req *http.Request) {
		var in json.RawMessage
		if r.kernel == nil || json.NewDecoder(io.LimitReader(req.Body, 1<<16)).Decode(&in) != nil {
			writeJSON(w, 400, map[string]string{"error": "{sealed}, on a box with a kernel"})
			return
		}
		b, err := r.kernel.call("spawner", "POST", "/fly-token", in)
		if err != nil {
			writeErr(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(b)
	}))

	// ---- setting the core up: Reset and Recover (the app, with the master key) -----------------------------
	app("GET /api/core/identity", func(w http.ResponseWriter, req *http.Request) { r.relayFor(w, req, "GET", "/identity", nil) })
	// claim and wipe: signed by the master key and checked by the core, so any of Deyao's logins may relay them (the
	// app's device-header check protected nothing: refusal audit, DECISIONS 189)
	device := func(pattern, corePath string) {
		app(pattern, func(w http.ResponseWriter, req *http.Request) {
			b, _ := io.ReadAll(io.LimitReader(req.Body, 16<<20))
			r.relayFor(w, req, "POST", corePath, b) // nextcore.go: ?core=next sets the next core up
		})
	}
	// the claim also carries the app's device-key countersignature (deviceKey, deviceSig over the statement): the
	// core ignores it; the router keeps it for the setup session (claimdevice.go), which trusts a new master key
	// only with it
	app("POST /api/core/claim", func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(io.LimitReader(req.Body, 16<<20))
		r.keepClaimDevice(b)
		c := r.coreFor(req) // nextcore.go: ?core=next Recovers the next core
		if c == nil {
			writeJSON(w, 404, map[string]string{"error": "there is no next core"})
			return
		}
		status, out, err := c.Raw("POST", "/claim", b)
		if err != nil {
			log.Printf("core POST /claim: %v", err)
			writeJSON(w, 503, map[string]any{"error": "the core isn't running", "coreDown": true})
			return
		}
		if status == 200 {
			r.keepCoreCert(b) // claimdevice.go: the master's signature on this core, kept by the router
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		w.Write(out)
	})
	mux.Handle("GET /setup/core-cert", r.requireSetup(func(w http.ResponseWriter, req *http.Request) {
		if err := r.checkSetupSig(req.Method, req.URL.Path, req.Header.Get("X-Setup-Time"), req.Header.Get("X-Setup-Sig"), nil); err != nil {
			writeJSON(w, 401, map[string]string{"error": err.Error()})
			return
		}
		b := r.coreCert()
		if b == nil {
			writeJSON(w, 404, map[string]string{"error": "no claim kept for the running core (empty, or claimed elsewhere)"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(b)
	}))
	mux.Handle("GET /setup/claim-device", r.requireSetup(func(w http.ResponseWriter, req *http.Request) {
		writeJSON(w, 200, r.claimDevices())
	}))
	device("POST /api/core/wipe", "/wipe")
	r.registerBackups(app)
	r.registerKernel(app)      // kernelline.go
	r.registerRoster(app, mux) // roster.go
	r.registerLineState(app)
	app("GET /api/policy", func(w http.ResponseWriter, req *http.Request) { writeJSON(w, 200, r.policy) })

	// ---- sign-in -----------------------------------------------------------------------------------
	app("GET /api/auth/start", func(w http.ResponseWriter, req *http.Request) {
		redirect := req.URL.Query().Get("redirect")
		if !strings.HasPrefix(redirect, "jarvis2://") {
			writeJSON(w, 400, map[string]string{"error": "only jarvis2:// redirects"})
			return
		}
		tok := req.Header.Get("Cf-Access-Jwt-Assertion")
		if tok == "" {
			tok = req.Header.Get("cf-access-token")
		}
		http.Redirect(w, req, redirect+"#token="+url.QueryEscape(tok), http.StatusFound)
	})

	// ---- state ---------------------------------------------------------------------------------------
	app("GET /api/state", func(w http.ResponseWriter, req *http.Request) {
		key, err := r.core.Key()
		coreInfo := map[string]any{"up": err == nil}
		if err == nil {
			coreInfo["signingKey"], coreInfo["agreementKey"] = key["signingKey"], key["agreementKey"]
		}
		var sessions []map[string]any
		var approvals []*Approval
		r.st.Do(func(d *persisted) {
			for _, s := range d.Sessions {
				sessions = append(sessions, sessionView(s, d))
			}
			for _, a := range d.Approvals {
				approvals = append(approvals, a)
			}
		})
		sort.Slice(sessions, func(i, j int) bool {
			return sessions[i]["created"].(time.Time).After(sessions[j]["created"].(time.Time))
		})
		sort.Slice(approvals, func(i, j int) bool { return approvals[i].Created.Before(approvals[j].Created) })
		out := map[string]any{"sessions": orEmpty(sessions), "approvals": orEmptyA(approvals), "core": coreInfo}
		for _, h := range stateHooks {
			h(r, out)
		}
		writeJSON(w, 200, out)
	})
	app("GET /api/sizes", func(w http.ResponseWriter, req *http.Request) {
		writeJSON(w, 200, map[string]any{"sizes": []map[string]string{
			{"id": "small", "label": sizeLabel("small")}, {"id": "medium", "label": sizeLabel("medium")}, {"id": "large", "label": sizeLabel("large")}}})
	})
	app("GET /api/records", func(w http.ResponseWriter, req *http.Request) {
		var recs []*Record
		r.st.Do(func(d *persisted) { recs = append(recs, d.Records...) })
		if recs == nil {
			recs = []*Record{}
		}
		writeJSON(w, 200, map[string]any{"records": recs})
	})

	// ---- grants (grants.go) and the terminal (terminal.go) ----------------------------------------------
	app("GET /api/holders", func(w http.ResponseWriter, req *http.Request) {
		pub, err := r.HolderPublicKeys()
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"holders": pub})
	})
	app("POST /api/sessions/{id}/grants/draft", func(w http.ResponseWriter, req *http.Request) {
		var in struct {
			Holder  string    `json:"holder"`
			Kind    string    `json:"kind"`
			Minutes int       `json:"minutes"`
			Until   time.Time `json:"until"`
		}
		json.NewDecoder(io.LimitReader(req.Body, 1<<16)).Decode(&in)
		text, err := r.DraftGrant(req.PathValue("id"), in.Holder, in.Kind, in.Minutes, in.Until)
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]string{"text": text})
	})
	app("POST /api/sessions/{id}/grants", func(w http.ResponseWriter, req *http.Request) {
		var in Doc
		json.NewDecoder(io.LimitReader(req.Body, 1<<16)).Decode(&in)
		g, err := r.AddGrant(req.PathValue("id"), &in)
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, 200, g)
	})
	// the line's latest core-signed succession cert: the phone's grant page reads the line, its own key and the
	// stores from it (the router can't forge it)
	app("GET /api/sessions/{id}/cert", func(w http.ResponseWriter, req *http.Request) {
		var c *Doc
		r.st.Do(func(d *persisted) {
			if s := d.Sessions[req.PathValue("id")]; s != nil {
				c = s.Cert
			}
		})
		if c == nil {
			writeJSON(w, 404, map[string]string{"error": "the session has no certified machine yet"})
			return
		}
		writeJSON(w, 200, c)
	})
	app("GET /api/sessions/{id}/grants", func(w http.ResponseWriter, req *http.Request) {
		writeJSON(w, 200, map[string]any{"grants": r.Grants(req.PathValue("id"))})
	})
	app("DELETE /api/grants/{gid}", func(w http.ResponseWriter, req *http.Request) {
		r.ForgetGrant(req.PathValue("gid"))
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
	app("POST /api/sessions/{id}/exec", func(w http.ResponseWriter, req *http.Request) {
		var in struct {
			Cmd     string `json:"cmd"`
			Timeout int    `json:"timeout"`
		}
		json.NewDecoder(io.LimitReader(req.Body, 1<<20)).Decode(&in)
		res, err := r.Exec(req.PathValue("id"), "terminal", in.Cmd, time.Duration(max(5, min(in.Timeout, 600)))*time.Second)
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, 200, res)
	})
	app("GET /api/sessions/{id}/terminal", func(w http.ResponseWriter, req *http.Request) {
		snap, err := r.TermSnapshot(req.PathValue("id"))
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, 200, snap)
	})
	r.registerTermPage(app) // termpage.go: the terminal as a web page (the iPhone app shows it in a web view)
	app("POST /api/sessions/{id}/terminal", func(w http.ResponseWriter, req *http.Request) {
		var in struct {
			Text       string   `json:"text"`
			Keys       []string `json:"keys"`
			Cols, Rows int
		}
		json.NewDecoder(io.LimitReader(req.Body, 1<<16)).Decode(&in)
		var err error
		if in.Cols > 0 {
			err = r.TermResize(req.PathValue("id"), in.Cols, in.Rows)
		} else {
			err = r.TermInput(req.PathValue("id"), in.Text, in.Keys)
		}
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	})

	// ---- sessions ------------------------------------------------------------------------------------
	app("POST /api/sessions", func(w http.ResponseWriter, req *http.Request) {
		var in NewSession
		if err := json.NewDecoder(io.LimitReader(req.Body, 1<<20)).Decode(&in); err != nil {
			writeErr(w, fmt.Errorf("bad JSON: %v", err))
			return
		}
		if in.RequestID == "" {
			in.RequestID = randID()
		}
		args := map[string]any{"label": in.Label, "harness": in.Harness, "stores": in.Stores, "model": in.Model, "permissionMode": in.PermissionMode, "size": in.Size}
		if in.Repos != "" {
			args["repos"] = in.Repos
		}
		if len(in.Content) > 0 {
			args["content"] = in.Content
		}
		if in.Prompt != "" {
			args["prompt"] = fmt.Sprintf("(%d characters)", len([]rune(in.Prompt)))
		}
		in.Origin = &Origin{Caller: appCaller(req), Call: APICall{Method: "POST", Path: "/api/sessions", Args: args}, ViaCall: viaCall(req)}
		id, err := r.CreateSession(in)
		if err != nil {
			scheduleErr(w, err)
			return
		}
		r.expectFollowup(req, id) // apicalls.go: its new-session approval (unless already linked)
		writeJSON(w, 200, map[string]any{"id": id, "requestId": in.RequestID})
	})
	app("POST /api/sessions/{id}/pause", func(w http.ResponseWriter, req *http.Request) {
		if err := r.Pause(req.PathValue("id")); err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
	app("POST /api/sessions/{id}/resume", func(w http.ResponseWriter, req *http.Request) {
		var in struct {
			Upgrade bool   `json:"upgrade"`
			Prompt  string `json:"prompt"` // delivered once the session is back (schedule.go)
			ResumeOptions
		}
		json.NewDecoder(io.LimitReader(req.Body, 1<<16)).Decode(&in)
		prompt, err := cleanResumePrompt(in.Prompt)
		if err == nil {
			err = r.applyResumeOptions(req.PathValue("id"), in.ResumeOptions) // sessionops.go: size, model, apiProxy
		}
		if err != nil {
			writeErr(w, err)
			return
		}
		r.noteOrigin(req.PathValue("id"), Origin{Caller: appCaller(req), Call: APICall{Method: "POST", Path: req.URL.Path, Args: map[string]any{"upgrade": in.Upgrade}}, ViaCall: viaCall(req)})
		r.expectFollowup(req, req.PathValue("id")) // apicalls.go: an approved call's sheet waits for the resume's approval, if any
		if err := r.resumeWithPrompt(req.PathValue("id"), in.Upgrade, prompt); err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
	app("POST /api/sessions/{id}/destroy", func(w http.ResponseWriter, req *http.Request) {
		if err := r.DestroyWith(req.PathValue("id"), req.URL.Query().Get("force") == "1"); err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	})

	// ---- approvals -----------------------------------------------------------------------------------
	app("GET /api/approvals", func(w http.ResponseWriter, req *http.Request) {
		var out []*Approval
		r.st.Do(func(d *persisted) {
			for _, a := range d.Approvals {
				out = append(out, a)
			}
		})
		sort.Slice(out, func(i, j int) bool { return out[i].Created.Before(out[j].Created) })
		writeJSON(w, 200, map[string]any{"approvals": orEmptyA(out)})
	})
	app("POST /api/approvals/{id}/respond", func(w http.ResponseWriter, req *http.Request) {
		var in struct {
			Signature string `json:"signature"`
		}
		json.NewDecoder(io.LimitReader(req.Body, 1<<16)).Decode(&in)
		cert, sid, err := r.Respond(req.PathValue("id"), in.Signature)
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"answer": cert, "session": sid})
	})
	app("POST /api/approvals/{id}/reject", func(w http.ResponseWriter, req *http.Request) {
		if err := r.Reject(req.PathValue("id")); err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	})

	// ---- the core, relayed unchanged ------------------------------------------------------------------
	for _, p := range []string{"stores", "stores/create", "stores/mark-sensitive", "unlock/begin", "lock", "unlocked", "store-key"} {
		path := "/" + p
		app("POST /api/core"+path, func(w http.ResponseWriter, req *http.Request) {
			b, _ := io.ReadAll(io.LimitReader(req.Body, 1<<20))
			r.relayFor(w, req, "POST", path, b) // nextcore.go: X-Jarvis2-Core: next (store-key for Recover alongside)
		})
	}

	// an unlock for one running session's cert: its machine pulls again (storedocs.go unlockArrived)
	app("POST /api/core/unlock/finish", func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(io.LimitReader(req.Body, 1<<20))
		c := r.coreFor(req)
		if c == nil {
			writeJSON(w, 404, map[string]string{"error": "there is no next core"})
			return
		}
		status, out, err := c.Raw("POST", "/unlock/finish", b)
		if err != nil {
			log.Printf("core POST /unlock/finish: %v", err)
			writeJSON(w, 503, map[string]any{"error": "the core isn't running", "coreDown": true})
			return
		}
		if status == 200 {
			r.unlockArrived(out)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		w.Write(out)
	})

	// ---- machines --------------------------------------------------------------------------------------
	m("GET /m/kernel/boot", func(w http.ResponseWriter, req *http.Request, machine string, _ []byte) {
		out, err := r.kernelBoot(machine) // kernelline.go
		if err != nil {
			writeJSON(w, 404, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, out)
	})
	m("GET /m/cert", func(w http.ResponseWriter, req *http.Request, machine string, _ []byte) {
		var cert, pred *Doc
		r.st.Do(func(d *persisted) {
			cert = d.Certs[machine]
			if cert != nil {
				var c struct {
					PredID string `json:"predecessorId"`
				}
				cert.Decode(&c)
				if c.PredID != "" && c.PredID != machine {
					pred = d.Certs[c.PredID]
				}
			}
		})
		if cert == nil {
			writeJSON(w, 404, map[string]string{"error": "no cert yet"})
			return
		}
		writeJSON(w, 200, map[string]any{"cert": cert, "predecessorCert": pred})
	})
	m("GET /m/snapshot", func(w http.ResponseWriter, req *http.Request, machine string, _ []byte) {
		var pred string
		r.st.Do(func(d *persisted) {
			if st := d.Started[machine]; st != nil && st.KernelPred != "" { // kernelline.go: the source's machine
				pred = st.KernelPred
				return
			}
			if st := d.Started[machine]; st != nil && st.KernelCert != nil {
				pred = "restore" // a kernel line's first machine: the archived snapshot its source names, if any (below)
				return
			}
			if cert := d.Certs[machine]; cert != nil {
				var c struct {
					PredID string `json:"predecessorId"`
				}
				cert.Decode(&c)
				pred = c.PredID
			}
		})
		if pred == "restore" {
			s := r.restoreFilesFor(machine) // restore.go: only a restoring line's first machine
			if s == nil {
				writeJSON(w, 404, map[string]string{"error": "no predecessor"})
				return
			}
			rd, err := r.snapOpen(req.Context(), s)
			if err != nil {
				writeJSON(w, 404, map[string]string{"error": "no predecessor: " + err.Error()})
				return
			}
			defer rd.Close()
			w.Header().Set("Content-Type", "application/gzip")
			http.ServeContent(w, req, "", s.CommittedAt, rd)
			return
		}
		if pred == "" {
			writeJSON(w, 404, map[string]string{"error": "no predecessor"})
			return
		}
		s := r.snap(pred)
		if s == nil || s.State != "committed" {
			writeJSON(w, 404, map[string]string{"error": "no snapshot"})
			return
		}
		rd, err := r.snapOpen(req.Context(), s)
		if err != nil {
			writeJSON(w, 404, map[string]string{"error": "no snapshot: " + err.Error()})
			return
		}
		defer rd.Close()
		w.Header().Set("X-Snapshot-Sig", s.Sig)
		w.Header().Set("Content-Type", "application/gzip")
		http.ServeContent(w, req, "", s.CommittedAt, rd)
	})
	// the snapshot streams to the volume (a session's workspace can be several GB; the router has 1 GiB of memory):
	// hashed on the way, the machine's request signature checked against that hash, then put in place
	r.registerSnapStream(mmux, m) // snapstream.go: the final snapshot streamed, committed, carried or failed
	r.registerSnapProgress(m)     // snapprogress.go: the final snapshot's progress, into the session's waiting line
	mmux.Handle("POST /m/snapshot", r.requireMachineStream(func(w http.ResponseWriter, req *http.Request, machine, tmp string) {
		if req.Header.Get("X-Snapshot-None") != "" {
			os.Remove(tmp)
			// a machine still booting has nothing to snapshot: the waiting pause or destroy goes on at once
			log.Printf("machine %s: nothing to snapshot (%s)", machine, req.Header.Get("X-Snapshot-None"))
			r.snapshotArrived(machine)
			writeJSON(w, 200, map[string]bool{"ok": true})
			return
		}
		sig := req.Header.Get("X-Snapshot-Sig")
		if sig == "" {
			os.Remove(tmp)
			writeJSON(w, 400, map[string]string{"error": "X-Snapshot-Sig missing"})
			return
		}
		f, err := os.Open(tmp)
		if err == nil {
			err = r.snapPutWhole(machine, f, sig) // snapstore.go: into the bucket, committed
			f.Close()
		}
		os.Remove(tmp)
		if err != nil {
			writeErr(w, err)
			return
		}
		r.snapshotArrived(machine)
		writeJSON(w, 200, map[string]bool{"ok": true})
	}))
	m("POST /m/pull-secrets", func(w http.ResponseWriter, req *http.Request, machine string, body []byte) {
		if r.isKernelMachine(machine) { // kernelline.go: the kernel's secrets, with the line's grant
			d, err := r.kernelPull(machine)
			r.noteSecretsPull(machine, err)
			if err != nil {
				writeErr(w, err)
				return
			}
			markPulled(machine)
			r.st.Do(func(dd *persisted) {
				if s := dd.Sessions[dd.Machines[machine]]; s != nil && s.MachineID == machine && s.State == "initialising" {
					s.State, s.Error = "started", ""
				}
			})
			writeJSON(w, 200, d)
			return
		}
		var cert *Doc
		r.st.Do(func(d *persisted) { cert = d.Certs[machine] })
		if cert == nil {
			writeJSON(w, 404, map[string]string{"error": "no cert"})
			return
		}
		// carry.go: the line's carried secrets go with the pull; a pull that goes through answers the next blob
		release := carryLock(machine)
		d, err := r.core.Call("/pull-secrets", map[string]any{"cert": cert, "carry": r.carryForPull(machine, cert)})
		if err == nil {
			r.pulled(machine, cert, d)
			markPulled(machine) // vouch.go: a pause waits briefly for such a machine's boot to finish
		}
		release()
		r.noteSecretsPull(machine, err) // the app says which locked store the machine waits on, and offers to unlock it
		if err != nil {
			writeErr(w, err)
			return
		}
		r.st.Do(func(d *persisted) {
			if s := d.Sessions[d.Machines[machine]]; s != nil && s.MachineID == machine && s.State == "initialising" {
				s.State, s.Error = "started", ""
			}
		})
		writeJSON(w, 200, d)
	})
	m("GET /m/commands", func(w http.ResponseWriter, req *http.Request, machine string, _ []byte) {
		// mq.go: the machine's oldest untaken row, waiting up to 50 s for one
		it, err := r.mqNext(req.Context(), machine, 50*time.Second)
		switch {
		case err != nil && req.Context().Err() != nil:
			if r.frozenNow() { // movegate.go: a handover — "nothing", so the machine polls again at once (the next leader)
				w.Header().Set("Connection", "close")
				writeJSON(w, 200, map[string]any{"commands": []string{}, "execs": []execItem{}})
			}
		case err != nil:
			writeErr(w, err)
		case it == nil:
			writeJSON(w, 200, map[string]any{"commands": []string{}, "execs": []execItem{}})
		case it.Kind == "command":
			var c string
			json.Unmarshal(it.Body, &c)
			writeJSON(w, 200, map[string]any{"commands": []string{c}, "execs": []execItem{}})
		case it.Kind == "exec":
			var e execItem
			json.Unmarshal(it.Body, &e)
			writeJSON(w, 200, map[string]any{"commands": []string{}, "execs": []execItem{e}})
		default:
			var d Delivery
			json.Unmarshal(it.Body, &d)
			writeJSON(w, 200, map[string]any{"commands": []string{}, "execs": []execItem{}, "deliveries": []Delivery{d}})
		}
	})
	m("POST /m/exec-result", func(w http.ResponseWriter, req *http.Request, machine string, body []byte) {
		var res ExecResult
		json.Unmarshal(body, &res)
		r.execResult(res)
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
	m("GET /m/holders", func(w http.ResponseWriter, req *http.Request, machine string, _ []byte) {
		pub, err := r.HolderPublicKeys()
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, 200, pub)
	})
	m("POST /m/kernel/downgrade", func(w http.ResponseWriter, req *http.Request, machine string, body []byte) {
		var in struct {
			Keep []string `json:"keep"`
		}
		if json.Unmarshal(body, &in) != nil || in.Keep == nil {
			writeJSON(w, 400, map[string]string{"error": "{keep: [stores]}"})
			return
		}
		if err := r.kernelDowngrade(machine, in.Keep); err != nil { // kernelline.go
			writeErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "keep": in.Keep})
	})
	m("POST /m/add-store", func(w http.ResponseWriter, req *http.Request, machine string, body []byte) {
		var in struct {
			Store string `json:"store"`
		}
		json.Unmarshal(body, &in)
		if err := r.AddStore(machine, in.Store); err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
	m("POST /m/downgrade", func(w http.ResponseWriter, req *http.Request, machine string, body []byte) {
		var in struct {
			Stores           []string `json:"stores"`
			NewEncryptionKey string   `json:"newEncryptionKey"`
			NewSigningKey    string   `json:"newSigningKey"`
		}
		json.Unmarshal(body, &in)
		ch, err := r.DowngradeBegin(machine, in.Stores, in.NewEncryptionKey, in.NewSigningKey)
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"challenge": ch})
	})
	m("POST /m/downgrade/finish", func(w http.ResponseWriter, req *http.Request, machine string, body []byte) {
		var in struct {
			Challenge *Doc   `json:"challenge"`
			Signature string `json:"signature"`
		}
		json.Unmarshal(body, &in)
		cert, err := r.DowngradeFinish(machine, in.Challenge, in.Signature)
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"cert": cert})
	})
	// ---- the web page ------------------------------------------------------------------------------------
	web := http.FileServer(http.Dir(r.cfg.WebDir))
	mux.Handle("GET /", r.requireDeyao(func(w http.ResponseWriter, req *http.Request) {
		p := filepath.Join(r.cfg.WebDir, filepath.Clean("/"+req.URL.Path))
		if fi, err := os.Stat(p); err != nil || fi.IsDir() {
			if _, err := os.Stat(p + ".html"); err == nil {
				req.URL.Path += ".html"
			} else if _, err := os.Stat(filepath.Join(p, "index.html")); err != nil {
				req.URL.Path = "/" // a client-side route
			}
		}
		web.ServeHTTP(w, req)
	}))
}

func (r *Router) relay(w http.ResponseWriter, method, path string, body []byte) {
	status, b, err := r.core.Raw(method, path, body)
	if err != nil {
		// no core to talk to (its pod is restarting, e.g. after a wipe): a state, not a fault — the app waits
		// and shows it as a plain note (coreDown)
		log.Printf("core %s %s: %v", method, path, err)
		writeJSON(w, 503, map[string]any{"error": "the core isn't running", "coreDown": true})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(b)
}

// checkSetupSig: a setup call is signed by the setup key over "<METHOD> <path> <unix time> <sha256hex body>",
// within two minutes, each signature once
func (r *Router) checkSetupSig(method, path, t, sig string, body []byte) error {
	if r.cfg.NoAccess && r.cfg.SetupKey == "" {
		return nil // CI without a setup key
	}
	ts, err := strconv.ParseInt(t, 10, 64)
	if err != nil {
		return fmt.Errorf("setup signature required")
	}
	if d := time.Since(time.Unix(ts, 0)); d > 2*time.Minute || d < -2*time.Minute {
		return fmt.Errorf("X-Setup-Time too far off")
	}
	sum := sha256.Sum256(body)
	msg := fmt.Sprintf("%s %s %d %s", method, path, ts, hex.EncodeToString(sum[:]))
	if r.cfg.SetupKey == "" || !verifyP256(r.cfg.SetupKey, []byte(msg), sig) {
		return fmt.Errorf("bad setup signature")
	}
	r.setupMu.Lock()
	defer r.setupMu.Unlock()
	for k, at := range r.setupSeen {
		if time.Since(at) > 5*time.Minute {
			delete(r.setupSeen, k)
		}
	}
	if _, ok := r.setupSeen[sig]; ok {
		return fmt.Errorf("setup signature already used")
	}
	r.setupSeen[sig] = time.Now()
	return nil
}

func sessionView(s *Session, d *persisted) map[string]any {
	guest := sizeLabel(s.Size)
	name := s.Label
	if name == "" {
		name = s.Title
	}
	v := map[string]any{
		"serverTitle": s.AppTitle, "userTitle": s.UserTitle, "title": sessionTitle(*s), "liveSync": s.LiveSync,
		"id": s.ID, "machineId": nullIfEmpty(s.MachineID), "released": s.MachineID == "" && s.State == "paused",
		"name": name, "state": s.State, "status": s.Status, "error": s.Error, "created": s.Created, "region": "",
		"environment": strings.Join(s.Stores, ","), "stores": s.Stores, "content": orEmptyS(s.Content), "harness": s.Harness, "label": s.Label, "aiTitle": s.Title,
		"model": s.Model, "permissionMode": s.PermissionMode, "guest": guest, "size": s.Size, "pausedAt": s.PausedAt,
		"image": s.Image, "createRequestId": s.RequestID, "repos": s.Repos, "discordChannel": s.DiscordChannel,
		"waiting": s.Waiting, "lockedStore": s.LockedStore, "carryLost": s.CarryLost, "oldCore": s.OldCore, "claudeAccount": nullIfEmpty(s.ClaudeAccount),
		"kernel": s.Kernel != nil, // kernelline.go: its stores unlock in the kernel's secrets
	}
	liveView(s, v)
	snapshotView(s, v) // snapsafe.go
	diskView(s, v)     // disk.go
	scheduleView(d, s.ID, v)
	messagesView(d, s.ID, v) // messages.go
	opsView(s, v)
	return v
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func orEmpty(s []map[string]any) []map[string]any {
	if s == nil {
		return []map[string]any{}
	}
	return s
}

func orEmptyA(s []*Approval) []*Approval {
	if s == nil {
		return []*Approval{}
	}
	return s
}

// ---- Cloudflare Access: the router checks the JWT itself too ---------------------------------------------

func (r *Router) requireDeyao(fn http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if !r.cfg.NoAccess {
			tok := req.Header.Get("Cf-Access-Jwt-Assertion")
			claims, err := r.access().verify(tok, r.cfg.AppAUD)
			if err != nil || !strings.EqualFold(claims.Email, r.cfg.AllowedEmail) {
				writeJSON(w, 403, map[string]string{"error": "Access login required"})
				return
			}
		}
		fn(w, req)
	})
}

// requireSetup: the setup session's Access service token (app jarvis4.deyaochen.com/setup); the core then
// checks the setup key's own signature, so this gate only keeps strangers away from the code
func (r *Router) requireSetup(fn http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if !r.cfg.NoAccess {
			if _, err := r.access().verify(req.Header.Get("Cf-Access-Jwt-Assertion"), r.cfg.SetupAUD); err != nil {
				writeJSON(w, 403, map[string]string{"error": "Access service token required"})
				return
			}
		}
		fn(w, req)
	})
}

// requireMachine: no Access here — this listener is reachable only over Fly's private network; every
// machineTimeSkew: how far a machine's X-Time may be from the router's clock, as the request arrives (a var: tests)
var machineTimeSkew = 120 * time.Second

// request must be signed by a machine the core started
func (r *Router) requireMachine(fn func(w http.ResponseWriter, req *http.Request, machine string, body []byte)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// the time is checked as the request arrives, before its body is read: a large body over a slow link (a
		// 20 MB live transcript) took over 2 min to arrive and was refused as too old (2026-10-21)
		machine, t, sig := req.Header.Get("X-Machine"), req.Header.Get("X-Time"), req.Header.Get("X-Sig")
		ts, _ := strconv.ParseInt(t, 10, 64)
		if d := time.Since(time.Unix(ts, 0)); d > machineTimeSkew || d < -machineTimeSkew {
			writeJSON(w, 401, map[string]string{"error": "X-Time too far off"})
			return
		}
		body, err := io.ReadAll(io.LimitReader(req.Body, 4<<30))
		if err != nil {
			writeErr(w, err)
			return
		}
		var key string
		r.st.Do(func(d *persisted) {
			if s := d.Started[machine]; s != nil {
				key = s.SigningKey
			}
		})
		sum := sha256.Sum256(body)
		msg := req.Method + " " + req.URL.Path + " " + t + " " + hex.EncodeToString(sum[:])
		// a signature over the path WITH its query is as good (it binds more): the session image of 2026-10-13
		// 01:30-03:00 signed its Claude login polls that way
		withQuery := req.Method + " " + req.URL.Path + "?" + req.URL.RawQuery + " " + t + " " + hex.EncodeToString(sum[:])
		if key == "" || !(verifyP256(key, []byte(msg), sig) || (req.URL.RawQuery != "" && verifyP256(key, []byte(withQuery), sig))) {
			writeJSON(w, 401, map[string]string{"error": "not signed by a machine the core started"})
			return
		}
		fn(w, req, machine, body)
	})
}

// snapshotMax: the largest snapshot the router takes (the volume is the limit; a machine's disk is 16 GB)
const snapshotMax = 32 << 30

// requireMachineStream: requireMachine for a large body — streamed to a temp file on the volume while it is hashed,
// then the signature (over that hash) checked; fn gets the file's path and must move or remove it
func (r *Router) requireMachineStream(fn func(w http.ResponseWriter, req *http.Request, machine, tmp string)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		machine, t, sig := req.Header.Get("X-Machine"), req.Header.Get("X-Time"), req.Header.Get("X-Sig")
		ts, _ := strconv.ParseInt(t, 10, 64)
		if d := time.Since(time.Unix(ts, 0)); d > machineTimeSkew || d < -machineTimeSkew {
			writeJSON(w, 401, map[string]string{"error": "X-Time too far off"})
			return
		}
		var key string
		r.st.Do(func(d *persisted) {
			if s := d.Started[machine]; s != nil {
				key = s.SigningKey
			}
		})
		if key == "" { // before reading a byte: only a machine the core started may write to the volume
			writeJSON(w, 401, map[string]string{"error": "not signed by a machine the core started"})
			return
		}
		scratch := filepath.Join(r.cfg.DataDir, "tmp")
		os.MkdirAll(scratch, 0o700)
		f, err := os.CreateTemp(scratch, ".upload-*")
		if err != nil {
			writeErr(w, err)
			return
		}
		tmp := f.Name()
		h := sha256.New()
		var body io.Reader = req.Body
		if req.URL.Path == "/m/snapshot" {
			body = movedReader{req.Body, r, machine} // snapwait.go: the final snapshot's bytes arriving are progress
		}
		n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(body, snapshotMax+1))
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err == nil && n > snapshotMax {
			err = fmt.Errorf("body over %d bytes", int64(snapshotMax))
		}
		if err != nil {
			os.Remove(tmp)
			writeErr(w, err)
			return
		}
		msg := req.Method + " " + req.URL.Path + " " + t + " " + hex.EncodeToString(h.Sum(nil))
		if !verifyP256(key, []byte(msg), sig) {
			os.Remove(tmp)
			writeJSON(w, 401, map[string]string{"error": "not signed by a machine the core started"})
			return
		}
		fn(w, req, machine, tmp)
	})
}

func verifyP256(pubRaw string, payload []byte, sigB64 string) bool {
	b, err := base64.StdEncoding.DecodeString(pubRaw)
	if err != nil {
		return false
	}
	pk, err := ecdh.P256().NewPublicKey(b)
	if err != nil {
		return false
	}
	der, _ := x509.MarshalPKIXPublicKey(pk)
	k, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return false
	}
	ek, ok := k.(*ecdsa.PublicKey)
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if !ok || err != nil {
		return false
	}
	h := sha256.Sum256(payload)
	return ecdsa.VerifyASN1(ek, h[:], sig)
}

type accessClaims struct {
	Aud        any    `json:"aud"`
	Email      string `json:"email"`
	CommonName string `json:"common_name"` // a service token's client id (no email)
	Exp        int64  `json:"exp"`
	Iss        string `json:"iss"`
}

type accessKeys struct {
	mu      sync.Mutex
	team    string
	keys    map[string]*rsa.PublicKey
	fetched time.Time
}

var accessCache = map[string]*accessKeys{}
var accessMu sync.Mutex

func (r *Router) access() *accessKeys {
	accessMu.Lock()
	defer accessMu.Unlock()
	a := accessCache[r.cfg.AccessTeam]
	if a == nil {
		a = &accessKeys{team: r.cfg.AccessTeam}
		accessCache[r.cfg.AccessTeam] = a
	}
	return a
}

func (a *accessKeys) key(kid string) (*rsa.PublicKey, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if k := a.keys[kid]; k != nil && time.Since(a.fetched) < time.Hour {
		return k, nil
	}
	resp, err := http.Get("https://" + a.team + "/cdn-cgi/access/certs")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var set struct {
		Keys []struct{ Kid, N, E string } `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return nil, err
	}
	a.keys, a.fetched = map[string]*rsa.PublicKey{}, time.Now()
	for _, k := range set.Keys {
		n, err1 := base64.RawURLEncoding.DecodeString(k.N)
		e, err2 := base64.RawURLEncoding.DecodeString(k.E)
		if err1 != nil || err2 != nil {
			continue
		}
		a.keys[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
	}
	if k := a.keys[kid]; k != nil {
		return k, nil
	}
	return nil, errors.New("unknown Access key")
}

func (a *accessKeys) verify(tok, aud string) (*accessClaims, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return nil, errors.New("no Access token")
	}
	hb, err1 := base64.RawURLEncoding.DecodeString(parts[0])
	pb, err2 := base64.RawURLEncoding.DecodeString(parts[1])
	sig, err3 := base64.RawURLEncoding.DecodeString(parts[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return nil, errors.New("bad token")
	}
	var h struct{ Alg, Kid string }
	json.Unmarshal(hb, &h)
	if h.Alg != "RS256" {
		return nil, errors.New("bad alg")
	}
	k, err := a.key(h.Kid)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(k, crypto.SHA256, sum[:], sig); err != nil {
		return nil, errors.New("bad token signature")
	}
	var c accessClaims
	if err := json.Unmarshal(pb, &c); err != nil {
		return nil, err
	}
	if time.Now().Unix() > c.Exp {
		return nil, errors.New("token expired")
	}
	if c.Iss != "https://"+a.team {
		return nil, errors.New("wrong issuer")
	}
	ok := false
	switch v := c.Aud.(type) {
	case string:
		ok = v == aud
	case []any:
		for _, x := range v {
			ok = ok || x == aud
		}
	}
	if !ok {
		return nil, errors.New("wrong audience")
	}
	return &c, nil
}
