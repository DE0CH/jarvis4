package main

// The kernel's roster (docs/PLAN-cluster.md "The roster"): the kernel's components make fresh keys at every start and
// the root key (the Jarvis 4 app's) vouches for them in one signed document. The router only carries it:
//
//	POST /api/kernel/root-key      {rootKey}: the app registers its root key's public half (base64 X9.63); kept as
//	                               pending until the setup session commits it (keys/root.pub, the kernel's ConfigMap)
//	GET  /setup/kernel/root-key    {rootKey} (setup-signed): what infra/setup.py kernel-root-key commits
//	GET  /setup/kernel/roster      {current, secretsServing, status, health} (setup-signed): the current roster, the secrets colour
//	                               that serves (whose identity the roster names), and the kernel's health (kernelhealth.go)
//	POST /setup/kernel/roster      {copy, payload, setupSig} (setup-signed): the components' identities as the setup
//	                               session read them through kernel-id.deyaochen.com, signed by the setup key; pending
//	GET  /api/kernel/roster/pending {copy, payload, setupSig}: what the app shows and the root key signs
//	POST /api/kernel/roster        {payload, rootSig}: the root key's roster: posted to every component's POST /roster
//	                               and kept; the answer names what each component said
//	GET  /api/kernel/roster        the current roster, what each component said, and what is stale
//
// A component that restarts has new keys and no roster: the router posts the current roster again when it says so
// (kernel.go callSeq, and rosterLoop every minute); the component refuses it (it names the old keys), and the roster
// is stale until Deyao signs a new one: GET /api/kernel says "roster stale: component X restarted", and Deyao gets one DM.

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/DE0CH/jarvis4/kernel/sig"
)

// rosterTargets: every kernel Deployment the roster goes to (KERNEL_URL's %s)
var rosterTargets = []string{"notary", "notarizer", "mover", "merger", "spawner", "identity", "gullible", "secrets-blue", "secrets-green"}

// RosterFiling: the setup session's roster, waiting for the root key
type RosterFiling struct {
	Copy     string    `json:"copy"`
	Payload  string    `json:"payload"`
	SetupSig string    `json:"setupSig"`
	At       time.Time `json:"at"`
}

// RosterCurrent: the root key's roster as it was posted
type RosterCurrent struct {
	Copy    string            `json:"copy"`
	Payload string            `json:"payload"`
	Sig     string            `json:"sig"`
	At      time.Time         `json:"at"`
	Results map[string]string `json:"results"`         // Deployment → "taken", or what it answered
	Stale   map[string]string `json:"stale,omitempty"` // Deployment → "roster stale: component X restarted (…)"
}

// rosterDMed: the stale roster was DMed (once per roster)
var rosterDMed atomic.Bool

// currentRoster: the root key's roster the components hold (nil: none yet)
func (r *Router) currentRoster() *sig.Doc {
	var d *sig.Doc
	r.st.Do(func(p *persisted) {
		if c := p.KernelRoster; c != nil {
			d = &sig.Doc{Payload: c.Payload, Sig: c.Sig}
		}
	})
	return d
}

// nextSecrets: the secrets Deployment that doesn't serve (it may refuse a roster: empty, or Recovered with other keys)
func (r *Router) nextSecrets() string {
	if r.kernel == nil {
		return ""
	}
	return r.kernel.secretsRole("secrets-next")
}

// rosterStale: a component refused the current roster (kernel.go postRoster)
func (r *Router) rosterStale(dep, msg string) {
	if dep == r.nextSecrets() {
		r.st.Do(func(p *persisted) {
			if c := p.KernelRoster; c != nil {
				c.Results[dep] = "standby, not named: " + msg
			}
		})
		return
	}
	first := false
	r.st.Do(func(p *persisted) {
		c := p.KernelRoster
		if c == nil {
			return
		}
		if c.Stale == nil {
			c.Stale = map[string]string{}
		}
		if _, ok := c.Stale[dep]; !ok {
			first = true
		}
		c.Stale[dep] = msg
		c.Results[dep] = msg
	})
	if first {
		log.Printf("kernel: %s", msg)
	}
	if rosterDMed.CompareAndSwap(false, true) {
		r.DM("🔴 Jarvis 4 needs you — " + msg + ". The kernel needs a new roster: the setup session runs infra/setup.py kernel-roster, then Settings → Kernel → Sign roster.")
	}
}

// distributeRoster: d to every component; what each said
func (r *Router) distributeRoster(d sig.Doc) map[string]string {
	res := map[string]string{}
	for _, dep := range rosterTargets {
		_, _, err := r.kernel.do(dep, dep, "POST", "/roster", map[string]sig.Doc{"roster": d})
		var ke *KernelError
		switch {
		case err == nil:
			res[dep] = "taken"
		case errors.As(err, &ke) && dep == r.nextSecrets():
			res[dep] = "standby, not named: " + ke.Msg // the next secrets: empty, or Recovered with other keys
		case errors.As(err, &ke):
			res[dep] = "refused: " + ke.Msg
		default:
			res[dep] = "unreachable: " + err.Error()
		}
	}
	return res
}

// rosterStatus: GET /api/kernel's roster part
func (r *Router) rosterStatus() map[string]any {
	out := map[string]any{"state": "none"}
	r.st.Do(func(p *persisted) {
		out["rootKey"] = p.KernelRootKey != ""
		out["pending"] = p.KernelRosterPending != nil
		if p.KernelRosterPending != nil {
			out["state"] = "pending"
		}
		c := p.KernelRoster
		if c == nil {
			return
		}
		out["copy"], out["id"], out["at"], out["results"] = c.Copy, sig.Doc{Payload: c.Payload}.ID(), c.At, c.Results
		stale := []string{}
		for _, m := range c.Stale {
			stale = append(stale, m)
		}
		sort.Strings(stale)
		out["stale"] = stale
		switch {
		case len(stale) > 0:
			out["state"] = "stale"
		case p.KernelRosterPending == nil:
			out["state"] = "current"
		}
	})
	return out
}

// rosterLoop: every component holds the current roster; one that lost it (a restart) gets it again, or the roster is
// stale (postRoster says so)
func (r *Router) rosterLoop(every time.Duration) {
	for {
		time.Sleep(every)
		awaitLead() // leaderlease.go
		r.rosterCheck()
	}
}

func (r *Router) rosterCheck() {
	d := r.currentRoster()
	if r.kernel == nil || d == nil {
		return
	}
	for _, dep := range rosterTargets {
		b, _, err := r.kernel.do(dep, dep, "GET", "/roster", nil)
		if err == nil {
			var held sig.Doc
			if json.Unmarshal(b, &held) == nil && held.Payload == d.Payload {
				continue
			}
		} else if !isNoRoster(err) {
			continue // unreachable (not deployed, restarting): the next round
		}
		if err := r.kernel.postRoster(dep, *d); err == nil {
			log.Printf("kernel: %s had no roster (a restart?); it took the current one again", dep)
			r.kernel.forget(strings.TrimPrefix(dep, "secrets-"))
		}
	}
}

// validRootKey: a P-256 public key, base64 X9.63 (65 bytes, uncompressed)
func validRootKey(k string) bool {
	b, err := base64.StdEncoding.DecodeString(k)
	if err != nil || len(b) != 65 || b[0] != 4 {
		return false
	}
	_, err = ecdh.P256().NewPublicKey(b)
	return err == nil
}

// checkFiledRoster: payload is a roster for copy, in the exact form sig.RosterPayload makes (what both keys sign)
func checkFiledRoster(copy, payload string) error {
	if copy != "blue" && copy != "green" {
		return errors.New("copy: blue or green")
	}
	var ro sig.Roster
	if err := sig.StrictJSON([]byte(payload), &ro); err != nil {
		return errors.New("payload: not a roster: " + err.Error())
	}
	if ro.Kind != "kernel-roster" || ro.Copy != copy || len(ro.Members) == 0 {
		return errors.New("payload: not a kernel roster for this copy")
	}
	roles := []string{}
	for _, m := range ro.Members {
		if m.Role == "" || m.SigningKey == "" || m.AgreementKey == "" {
			return errors.New("payload: a member without keys")
		}
		roles = append(roles, m.Role)
	}
	want := []string{"gullible", "identity", "merger", "mover", "notarizer", "notary", "secrets", "spawner"}
	if !slices.Equal(roles, want) {
		return errors.New("payload: the members must be exactly " + strings.Join(want, ", ") + ", sorted")
	}
	canon, err := sig.RosterPayload(copy, ro.Members)
	if err != nil || canon != payload {
		return errors.New("payload: not in sig.RosterPayload's exact form")
	}
	return nil
}

func (r *Router) registerRoster(app func(string, http.HandlerFunc), mux *http.ServeMux) {
	setupSigned := func(fn func(w http.ResponseWriter, req *http.Request, body []byte)) http.Handler {
		return r.requireSetup(func(w http.ResponseWriter, req *http.Request) {
			b, _ := io.ReadAll(io.LimitReader(req.Body, 1<<20))
			if err := r.checkSetupSig(req.Method, req.URL.Path, req.Header.Get("X-Setup-Time"), req.Header.Get("X-Setup-Sig"), b); err != nil {
				writeJSON(w, 401, map[string]string{"error": err.Error()})
				return
			}
			fn(w, req, b)
		})
	}
	app("POST /api/kernel/root-key", func(w http.ResponseWriter, req *http.Request) {
		var in struct {
			RootKey string `json:"rootKey"`
		}
		if json.NewDecoder(io.LimitReader(req.Body, 1<<16)).Decode(&in) != nil || !validRootKey(in.RootKey) {
			writeJSON(w, 400, map[string]string{"error": "{rootKey}: a P-256 public key, base64 X9.63"})
			return
		}
		r.st.Do(func(p *persisted) { p.KernelRootKey = in.RootKey })
		log.Printf("kernel: the app registered its root key %s…", in.RootKey[:16])
		writeJSON(w, 200, map[string]any{"ok": true})
	})
	mux.Handle("GET /setup/kernel/root-key", setupSigned(func(w http.ResponseWriter, req *http.Request, _ []byte) {
		var k string
		r.st.Do(func(p *persisted) { k = p.KernelRootKey })
		if k == "" {
			writeJSON(w, 404, map[string]string{"error": "the app hasn't registered its root key yet (Settings → Kernel)"})
			return
		}
		writeJSON(w, 200, map[string]string{"rootKey": k})
	}))
	mux.Handle("GET /setup/kernel/roster", setupSigned(func(w http.ResponseWriter, req *http.Request, _ []byte) {
		serving := "blue"
		if r.kernel != nil {
			serving = strings.TrimPrefix(r.kernel.secretsRole("secrets"), "secrets-")
		}
		out := map[string]any{"current": nil, "secretsServing": serving, "status": r.rosterStatus(), "health": r.kernelHealthView()}
		if d := r.currentRoster(); d != nil {
			out["current"] = d
		}
		writeJSON(w, 200, out)
	}))
	mux.Handle("POST /setup/kernel/roster", setupSigned(func(w http.ResponseWriter, req *http.Request, b []byte) {
		var in struct {
			Copy     string `json:"copy"`
			Payload  string `json:"payload"`
			SetupSig string `json:"setupSig"`
		}
		if json.Unmarshal(b, &in) != nil {
			writeJSON(w, 400, map[string]string{"error": "{copy, payload, setupSig}"})
			return
		}
		if err := checkFiledRoster(in.Copy, in.Payload); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		if r.cfg.SetupKey == "" || !verifyP256(r.cfg.SetupKey, []byte(in.Payload), in.SetupSig) {
			writeJSON(w, 403, map[string]string{"error": "setupSig: not the setup key's signature over the payload"})
			return
		}
		r.st.Do(func(p *persisted) {
			p.KernelRosterPending = &RosterFiling{Copy: in.Copy, Payload: in.Payload, SetupSig: in.SetupSig, At: time.Now().UTC()}
		})
		log.Printf("kernel: a roster for copy %s is filed, waiting for the root key", in.Copy)
		writeJSON(w, 200, map[string]any{"ok": true, "id": sig.Doc{Payload: in.Payload}.ID()})
	}))
	app("GET /api/kernel/roster/pending", func(w http.ResponseWriter, req *http.Request) {
		var f *RosterFiling
		r.st.Do(func(p *persisted) {
			if p.KernelRosterPending != nil {
				x := *p.KernelRosterPending
				f = &x
			}
		})
		if f == nil {
			writeJSON(w, 404, map[string]string{"error": "no roster filed (the setup session runs infra/setup.py kernel-roster)"})
			return
		}
		writeJSON(w, 200, f)
	})
	app("GET /api/kernel/roster", func(w http.ResponseWriter, req *http.Request) {
		var c *RosterCurrent
		r.st.Do(func(p *persisted) {
			if p.KernelRoster != nil {
				x := *p.KernelRoster
				c = &x
			}
		})
		if c == nil {
			writeJSON(w, 404, map[string]string{"error": "no roster signed yet"})
			return
		}
		writeJSON(w, 200, map[string]any{"copy": c.Copy, "payload": c.Payload, "sig": c.Sig, "at": c.At, "results": c.Results,
			"status": r.rosterStatus()})
	})
	app("POST /api/kernel/roster", func(w http.ResponseWriter, req *http.Request) {
		var in struct {
			Payload string `json:"payload"`
			RootSig string `json:"rootSig"`
		}
		if json.NewDecoder(io.LimitReader(req.Body, 1<<20)).Decode(&in) != nil || in.Payload == "" || in.RootSig == "" {
			writeJSON(w, 400, map[string]string{"error": "{payload, rootSig}"})
			return
		}
		if r.kernel == nil {
			writeJSON(w, 503, map[string]string{"error": "this box runs no kernel yet"})
			return
		}
		var root string
		r.st.Do(func(p *persisted) { root = p.KernelRootKey })
		if root == "" {
			writeJSON(w, 409, map[string]string{"error": "no root key registered (POST /api/kernel/root-key first)"})
			return
		}
		d := sig.Doc{Payload: in.Payload, Sig: in.RootSig}
		ro, err := sig.OpenRoster(d, root)
		if err == nil {
			err = checkFiledRoster(ro.Copy, in.Payload)
		}
		if err != nil {
			writeJSON(w, 403, map[string]string{"error": err.Error()})
			return
		}
		res := r.distributeRoster(d)
		r.st.Do(func(p *persisted) {
			p.KernelRoster = &RosterCurrent{Copy: ro.Copy, Payload: in.Payload, Sig: in.RootSig, At: time.Now().UTC(), Results: res}
			p.KernelRosterPending = nil
		})
		rosterDMed.Store(false)
		for dep, msg := range res { // one that restarted after the setup session read its identity
			if m, ok := strings.CutPrefix(msg, "refused: "); ok {
				r.rosterStale(dep, "roster stale: component "+dep+" restarted ("+m+")")
			}
		}
		for _, role := range append(slices.Clone(rosterTargets), "secrets", "secrets-next") {
			r.kernel.forget(role) // identities are read again (the roster may name new keys)
		}
		log.Printf("kernel: the root key's roster %s posted: %v", d.ID()[:12], res)
		r.kernelHealthCheck() // kernelhealth.go: the app's warning follows the new roster at once
		writeJSON(w, 200, map[string]any{"ok": true, "id": d.ID(), "results": res})
	})
}
