package main

// The kernel's roster (docs/PLAN-cluster.md "The roster"): the kernel's components make fresh keys at every start and
// the root key (the Jarvis 4 app's) vouches for them in one signed document per kernel copy. The router only carries
// it:
//
//	POST /api/kernel/root-key      {rootKey}: the app registers its root key's public half (base64 X9.63); kept as
//	                               pending until the setup session commits it (keys/root.pub, the kernel's ConfigMap)
//	GET  /setup/kernel/root-key    {rootKey} (setup-signed): what infra/setup.py kernel-root-key commits
//	GET  /setup/kernel/roster      {current, serving, next, retiredInUse, flip, status, health} (setup-signed): the
//	                               serving copy's roster, which copy serves, the other copy's while it takes over, the
//	                               retired keys of the current roster that something a line holds is signed by (the
//	                               next roster names them again), the copy flip under way, and the kernel's health
//	POST /setup/kernel/roster      {copy, payload, setupSig} (setup-signed): the components' identities as the setup
//	                               session read them through kernel-id.deyaochen.com, signed by the setup key; pending
//	GET  /api/kernel/roster/pending {copy, payload, setupSig}: what the app shows and the root key signs
//	POST /api/kernel/roster        {payload, rootSig}: the root key's roster, posted to every component of its copy and
//	                               kept; the answer names what each component said. A roster of the serving copy (a
//	                               component restarted: it names the old keys as retired) replaces the current one; a
//	                               roster of the other copy (a release landed there) starts the copy flip
//	                               (kernelflip.go)
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
	"fmt"
	"io"
	"log"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/DE0CH/jarvis4/kernel/doc"
	"github.com/DE0CH/jarvis4/kernel/sig"
)

// kernelRoles: every component of a copy (a roster names exactly these, sorted)
var kernelRoles = []string{"gullible", "identity", "merger", "minter", "mover", "notarizer", "notary", "secrets", "spawner"}

// rosterTargets: a copy's Deployments, which its roster goes to (KERNEL_URL's %s)
func rosterTargets(copy string) []string {
	out := []string{}
	for _, r := range kernelRoles {
		out = append(out, r+"-"+copy)
	}
	return out
}

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

func (c *RosterCurrent) doc() sig.Doc { return sig.Doc{Payload: c.Payload, Sig: c.Sig} }

// roster: the payload read (the router checked the root key's signature when it took it)
func (c *RosterCurrent) roster() sig.Roster {
	var ro sig.Roster
	json.Unmarshal([]byte(c.Payload), &ro)
	return ro
}

// rosterDMed: the stale roster was DMed (once per roster)
var rosterDMed atomic.Bool

// currentRoster: the root key's roster the serving copy holds (nil: none yet)
func (r *Router) currentRoster() *sig.Doc {
	var d *sig.Doc
	r.st.Do(func(p *persisted) {
		if c := p.KernelRoster; c != nil {
			x := c.doc()
			d = &x
		}
	})
	return d
}

// rosterOfCopy: the roster a copy's components should hold: the serving copy's, or the other copy's while it takes
// over (nil: none)
func (r *Router) rosterOfCopy(copy string) *RosterCurrent {
	var c *RosterCurrent
	r.st.Do(func(p *persisted) {
		switch {
		case p.KernelRoster != nil && p.KernelRoster.Copy == copy:
			c = p.KernelRoster
		case p.KernelRosterNext != nil && p.KernelRosterNext.Copy == copy:
			c = p.KernelRosterNext
		}
		if c != nil {
			x := *c
			c = &x
		}
	})
	return c
}

// rosterStale: a component refused its copy's roster (kernel.go postRoster)
func (r *Router) rosterStale(dep, msg string) {
	first := false
	r.st.Do(func(p *persisted) {
		c := p.KernelRoster
		if n := p.KernelRosterNext; n != nil && n.Copy == copyOf(dep) {
			c = n
		}
		if c == nil || c.Copy != copyOf(dep) {
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

// distributeRoster: d to every component of its copy; what each said
func (r *Router) distributeRoster(d sig.Doc, copy string) map[string]string {
	res := map[string]string{}
	for _, dep := range rosterTargets(copy) {
		_, _, err := r.kernel.do(dep, dep, "POST", "/roster", map[string]sig.Doc{"roster": d})
		var ke *KernelError
		switch {
		case err == nil:
			res[dep] = "taken"
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
	out := map[string]any{"state": "none", "serving": r.servingCopy()}
	r.st.Do(func(p *persisted) {
		out["rootKey"] = p.KernelRootKey != ""
		out["pending"] = p.KernelRosterPending != nil
		if p.KernelRosterPending != nil {
			out["state"] = "pending"
		}
		if n := p.KernelRosterNext; n != nil {
			out["next"] = map[string]any{"copy": n.Copy, "id": n.doc().ID(), "at": n.At, "results": n.Results}
		}
		c := p.KernelRoster
		if c == nil {
			return
		}
		out["copy"], out["id"], out["at"], out["results"] = c.Copy, c.doc().ID(), c.At, c.Results
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

// rosterLoop: every component holds its copy's roster; one that lost it (a restart) gets it again, or the roster is
// stale (postRoster says so)
func (r *Router) rosterLoop(every time.Duration) {
	for {
		time.Sleep(every)
		awaitLead() // leaderlease.go
		r.rosterCheck()
	}
}

func (r *Router) rosterCheck() {
	if r.kernel == nil {
		return
	}
	for _, copy := range kernelCopies {
		c := r.rosterOfCopy(copy)
		if c == nil {
			continue // the copy that doesn't serve, idle: it holds whatever it held
		}
		d := c.doc()
		for _, dep := range rosterTargets(copy) {
			b, _, err := r.kernel.do(dep, dep, "GET", "/roster", nil)
			if err == nil {
				var held sig.Doc
				if json.Unmarshal(b, &held) == nil && held.Payload == d.Payload {
					continue
				}
			} else if !isNoRoster(err) {
				continue // unreachable (scaled down, restarting): the next round
			}
			if err := r.kernel.postRoster(dep, d); err == nil {
				log.Printf("kernel: %s had no roster (a restart?); it took its copy's again", dep)
				r.kernel.forget(dep)
			}
		}
	}
}

// retiredInUse: the current roster's retired keys that something a line holds is signed by (its grant, its certs and
// their notarizations): the next roster names them as retired again; the others can go
func (r *Router) retiredInUse() []sig.Identity {
	type held struct {
		role string
		d    sig.Doc
	}
	var ro sig.Roster
	var docs []held
	r.st.Do(func(p *persisted) {
		if p.KernelRoster == nil {
			return
		}
		ro = p.KernelRoster.roster()
		for _, s := range p.Sessions {
			l := s.Kernel
			if l == nil {
				continue
			}
			if g := l.Grant; g != nil && (g.By == "mover" || g.By == "merger") {
				docs = append(docs, held{g.By, g.Grant})
			}
			for _, c := range []*sig.Doc{l.SourceCert, l.MachineCert} {
				if c != nil {
					if cc, err := doc.PeekCert(*c); err == nil {
						docs = append(docs, held{cc.Signer, *c})
					}
				}
			}
			for _, nz := range []*sig.Doc{l.SourceNz, l.MachineNz} {
				if nz != nil {
					docs = append(docs, held{"notarizer", *nz})
				}
			}
		}
	})
	out := []sig.Identity{}
	for _, m := range ro.Retired {
		for _, h := range docs {
			if h.role == m.Role && sig.Verify(m.SigningKey, []byte(h.d.Payload), h.d.Sig) {
				out = append(out, m)
				break
			}
		}
	}
	return out
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

// checkFiledRoster: payload is a roster for copy, in the exact form sig.Roster.Payload makes (what both keys sign):
// one member per role, retired keys of any role but secrets, secretsBoot a secrets identity
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
	if !slices.Equal(roles, kernelRoles) {
		return errors.New("payload: the members must be exactly " + strings.Join(kernelRoles, ", ") + ", sorted")
	}
	for _, m := range ro.Retired {
		if !slices.Contains(kernelRoles, m.Role) || m.Role == "secrets" || m.SigningKey == "" || m.AgreementKey == "" {
			return errors.New("payload: a retired member that isn't a kernel component's keys (never secrets)")
		}
	}
	if b := ro.SecretsBoot; b != nil && (b.Role != "secrets" || b.SigningKey == "" || b.AgreementKey == "") {
		return errors.New("payload: secretsBoot: a secrets identity")
	}
	canon, err := ro.Payload()
	if err != nil || canon != payload {
		return errors.New("payload: not in sig.Roster.Payload's exact form")
	}
	return nil
}

// checkTakeover: ro, a roster of the copy that doesn't serve, can take over from cur: it names the same secrets, an
// empty one to take over (secretsBoot), and retires every other member of cur
func checkTakeover(ro sig.Roster, cur sig.Roster) error {
	if ro.SecretsBoot == nil {
		return errors.New("a roster of the copy that doesn't serve names its empty secrets (secretsBoot): it takes over from the serving one")
	}
	a, _ := ro.Member("secrets")
	b, _ := cur.Member("secrets")
	if a != b {
		return errors.New("a roster of the copy that doesn't serve names the serving copy's secrets (the keys the kit derives)")
	}
	for _, m := range cur.Members {
		if m.Role != "secrets" && !slices.Contains(ro.Retired, m) {
			return fmt.Errorf("a roster of the copy that doesn't serve retires every serving member: not the %s", m.Role)
		}
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
		out := map[string]any{"current": nil, "serving": r.servingCopy(), "retiredInUse": r.retiredInUse(), "status": r.rosterStatus(),
			"health": r.kernelHealthView(), "flip": r.flipStatus()}
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
		out, code, err := r.takeRoster(in.Payload, in.RootSig)
		if err != nil {
			writeJSON(w, code, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, out)
	})
}

// takeRoster: the root key's roster: the serving copy's (or the very first) replaces the current one; the other
// copy's starts the copy flip once every one of its components took it
func (r *Router) takeRoster(payload, rootSig string) (map[string]any, int, error) {
	var root string
	var cur *RosterCurrent
	var flipping bool
	r.st.Do(func(p *persisted) {
		root, cur = p.KernelRootKey, p.KernelRoster
		flipping = p.KernelFlip != nil && len(p.KernelFlip.Handoffs) > 0
	})
	if root == "" {
		return nil, 409, errors.New("no root key registered (POST /api/kernel/root-key first)")
	}
	d := sig.Doc{Payload: payload, Sig: rootSig}
	ro, err := sig.OpenRoster(d, root)
	if err == nil {
		err = checkFiledRoster(ro.Copy, payload)
	}
	if err != nil {
		return nil, 403, err
	}
	serving := r.servingCopy()
	next := cur != nil && ro.Copy != serving
	if next {
		if flipping {
			// a component of the copy taking over restarted mid-flip: the frozen components hand their state to the
			// newer roster too (one that took a handoff already serves and takes no other)
			log.Printf("kernel: a newer %s roster during the flip: the handoffs are made again for it", ro.Copy)
		}
		if err := checkTakeover(ro, cur.roster()); err != nil {
			return nil, 403, err
		}
	} else if ro.SecretsBoot != nil {
		return nil, 403, errors.New("the serving copy's roster names its own secrets, no secretsBoot")
	}
	res := r.distributeRoster(d, ro.Copy)
	rc := &RosterCurrent{Copy: ro.Copy, Payload: payload, Sig: rootSig, At: time.Now().UTC(), Results: res}
	r.st.Do(func(p *persisted) {
		if next {
			p.KernelRosterNext = rc
		} else {
			if p.KernelRoster == nil {
				p.KernelCopy = ro.Copy // the first roster names the copy that serves
			}
			p.KernelRoster = rc
		}
		p.KernelRosterPending = nil
	})
	rosterDMed.Store(false)
	for dep, msg := range res { // one that restarted after the setup session read its identity
		if m, ok := strings.CutPrefix(msg, "refused: "); ok {
			r.rosterStale(dep, "roster stale: component "+dep+" restarted ("+m+")")
		}
	}
	r.kernel.forgetAll() // identities are read again (the roster may name new keys)
	log.Printf("kernel: the root key's roster %s for %s posted: %v", d.ID()[:12], ro.Copy, res)
	out := map[string]any{"ok": true, "id": d.ID(), "results": res}
	if next { // kernelflip.go: it starts once every component of both copies is where the flip needs it

		r.startFlip(ro.Copy, d.ID())
		out["flip"] = ro.Copy
	}
	r.kernelHealthCheck() // kernelhealth.go: the app's warning follows the new roster at once
	return out, 200, nil
}
