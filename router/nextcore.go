package main

// The next core (blue/green; Deyao, 2026-10-15; docs/DESIGN.md "Core continuity", DECISIONS). A core release no
// longer empties the core the sessions use: the new core runs NEXT to the serving one (NEXT_CORE_URL), Deyao
// Recovers it ahead of time with the same kit as a STANDBY ("Recover alongside" in the app's Reset-or-Recover page,
// every core call with ?core=next or "X-Jarvis2-Core: next"), and the router then FLIPS: drain → POST /handoff to the
// serving core (it answers its FINAL line state and from then on refuses every call) → POST /takeover with that
// state to the standby (it serves nothing before, and takes only a final state at least as new as the one it was
// Recovered with) → every later core call goes to it. The cores themselves guarantee that at
// most one of them serves; the router only chooses when.
//
// The flip is POST /setup/core/flip (setup-signed), or by itself with FLIP_AUTO=1 once the next core is a standby
// (Recovered alongside). Which core serves is kept in the state (activeCore), so a restarted router talks to the same one.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"
)

// coreHandoff: what the router asks of the cores for a flip (core continuity's contract).
type coreHandoff interface {
	// Finalize: the serving core seals a FINAL line state and refuses every call from then on
	Finalize(c *CoreClient) (json.RawMessage, error)
	// Adopt: a next core (Recovered with the same kit) takes that final state and serves from then on
	Adopt(c *CoreClient, final json.RawMessage) error
}

// httpHandoff: the core's endpoints (core continuity, DESIGN "Core continuity", DECISIONS 173):
//
//	POST /handoff  (no body) to the serving core → the FINAL line state {head, sealed}; head is core-signed
//	               {"kind": "line-state-head", seq, final: true, sha256, at}. From then on that core answers 409
//	               "this core is handed-off" to everything but GET /identity, GET /line-state and POST /handoff (which
//	               repeats the same final state).
//	POST /takeover {lineState: {head, sealed}} to a standby core (Recovered with "standby": true, same kit) → it takes
//	               the lines and the stores over and serves: signed {"kind": "took-over", lineSeq, stores}; 403 for a
//	               state that isn't final, from other keys, or older than the one it was Recovered with.
type httpHandoff struct{}

func (httpHandoff) Finalize(c *CoreClient) (json.RawMessage, error) {
	status, b, err := c.Raw("POST", "/handoff", nil)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("core POST /handoff: HTTP %d %s", status, trimBody(b))
	}
	return json.RawMessage(b), nil
}

func (httpHandoff) Adopt(c *CoreClient, final json.RawMessage) error {
	body, _ := json.Marshal(map[string]json.RawMessage{"lineState": final})
	status, b, err := c.Raw("POST", "/takeover", body)
	if err != nil {
		return err
	}
	if status != 200 {
		return fmt.Errorf("core POST /takeover: HTTP %d %s", status, trimBody(b))
	}
	return nil
}

func trimBody(b []byte) string {
	if len(b) > 300 {
		b = b[:300]
	}
	return string(b)
}

// nextCores: the router's side (one per router)
type nextCores struct {
	next    *CoreClient // nil without NEXT_CORE_URL
	handoff coreHandoff
	flipMu  sync.Mutex
	final   json.RawMessage
}

var nc = struct {
	sync.Mutex
	m map[*Router]*nextCores
}{m: map[*Router]*nextCores{}}

// nextOf: this router's next-core side (made on first use)
func (r *Router) nextOf() *nextCores {
	nc.Lock()
	defer nc.Unlock()
	n := nc.m[r]
	if n == nil {
		n = &nextCores{handoff: httpHandoff{}}
		if u := os.Getenv("NEXT_CORE_URL"); u != "" {
			n.next = &CoreClient{base: u, http: &http.Client{Timeout: 15 * time.Minute}}
		}
		nc.m[r] = n
	}
	return n
}

// setNextCore: tests and main (the URL and the handoff)
func (r *Router) setNextCore(url string, h coreHandoff) {
	n := r.nextOf()
	if url != "" {
		n.next = &CoreClient{base: url, http: &http.Client{Timeout: 15 * time.Minute}}
	}
	if h != nil {
		n.handoff = h
	}
}

// applyActiveCore: at start, talk to the core the state says serves (a flip before a restart)
func (r *Router) applyActiveCore() {
	n := r.nextOf()
	if n.next == nil {
		return
	}
	var active string
	r.st.Do(func(d *persisted) { active = d.ActiveCore })
	if active != "" && active == n.next.URL() {
		cur := r.core.URL()
		r.core.SetURL(active)
		n.next.SetURL(cur)
		log.Printf("core: %s serves (flipped before), next is %s", active, cur)
	}
}

// coreFor: the core a request names (?core=next or X-Jarvis2-Core: next), nil when it names a next core there isn't
func (r *Router) coreFor(req *http.Request) *CoreClient {
	if req.URL.Query().Get("core") == "next" || req.Header.Get("X-Jarvis2-Core") == "next" {
		return r.nextOf().next
	}
	return r.core
}

// relayFor: relay to the core the request names
func (r *Router) relayFor(w http.ResponseWriter, req *http.Request, method, path string, body []byte) {
	c := r.coreFor(req)
	if c == nil {
		writeJSON(w, 404, map[string]string{"error": "there is no next core"})
		return
	}
	if c == r.core {
		r.relay(w, method, path, body)
		return
	}
	status, b, err := c.Raw(method, path, body)
	if err != nil {
		writeJSON(w, 503, map[string]any{"error": "the next core isn't running", "coreDown": true})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(b)
}

// storesFor: where a request's store call goes — the next core when it names one, else the stores' keeper
// (storeCore: the kernel's serving secrets on a box with no core); nil when it names a next core there isn't
func (r *Router) storesFor(req *http.Request) *CoreClient {
	if c := r.coreFor(req); c != r.core {
		return c
	}
	return r.storeCore()
}

// relayStores: a store call relayed to storesFor
func (r *Router) relayStores(w http.ResponseWriter, req *http.Request, method, path string, body []byte) {
	if r.secretsStores == nil {
		r.relayFor(w, req, method, path, body)
		return
	}
	c := r.storesFor(req)
	if c == nil {
		writeJSON(w, 404, map[string]string{"error": "there is no next core"})
		return
	}
	r.relayTo(w, c, method, path, body)
}

// coreServing: what c's signed state says it does — "serving", "standby" (Recovered alongside, waiting for a
// takeover), "handed-off" ("" for an empty core) — and its signing key
func coreServing(c *CoreClient) (serving, key string, err error) {
	v, err := coreView(c)
	return v.serving, v.key, err
}

// coreInfo: a core's identity as the flip reads it
type coreInfo struct {
	serving string // serving | standby | handed-off | "" (empty)
	key     string // its signing key: the same for every Recover with the same kit
	lineSeq int    // its newest line state's number
}

func coreView(c *CoreClient) (coreInfo, error) {
	status, b, err := c.Raw("GET", "/identity", nil)
	if err != nil {
		return coreInfo{}, err
	}
	if status != 200 {
		return coreInfo{}, fmt.Errorf("core /identity: HTTP %d", status)
	}
	var id struct {
		SigningKey string `json:"signingKey"`
		State      Doc    `json:"state"`
	}
	if err := json.Unmarshal(b, &id); err != nil {
		return coreInfo{}, err
	}
	var st struct {
		Master  any    `json:"master"`
		Serving string `json:"serving"`
		LineSeq int    `json:"lineSeq"`
	}
	id.State.Decode(&st)
	if m, _ := st.Master.(string); m == "" {
		return coreInfo{key: id.SigningKey}, nil
	}
	if st.Serving == "" {
		st.Serving = "serving" // a core from before continuity
	}
	return coreInfo{serving: st.Serving, key: id.SigningKey, lineSeq: st.LineSeq}, nil
}

// drainWatchEvery: how often the flip's drain looks at the next core again
var drainWatchEvery = 30 * time.Second

// standbyGone: why the next core is no longer the standby it was before the drain ("" = it still is). A core release
// restarts it empty (the outage of 2026-10-22: CI pinned a new core into the standby while the flip drained), a wipe
// or a Recover with another kit gives it another key.
func standbyGone(c *CoreClient, key string) string {
	v, err := coreView(c)
	switch {
	case err != nil:
		return "the next core doesn't answer: " + err.Error()
	case v.serving != "standby":
		return fmt.Sprintf("the next core is %s now, no longer a standby", orEmptyCore(v.serving))
	case v.key != key:
		return "the next core has another signing key now (Recovered again, with another kit?)"
	}
	return ""
}

// FlipCore: the next core serves from now on (see the top of the file). A flip whose takeover already happened (the
// next core serves and the current one is handed off) is finished instead (finishFlip).
func (r *Router) FlipCore(drainMax time.Duration) error {
	n := r.nextOf()
	n.flipMu.Lock()
	defer n.flipMu.Unlock()
	if n.next == nil {
		return errors.New("there is no next core (NEXT_CORE_URL)")
	}
	nv, err := coreView(n.next)
	if err != nil {
		return fmt.Errorf("the next core: %w", err)
	}
	if nv.serving == "serving" {
		return r.finishFlip(n, nv)
	}
	if nv.serving != "standby" {
		return fmt.Errorf("the next core is %q, not a standby: Recover it alongside first (the app's Reset-or-Recover page, next core)", orEmptyCore(nv.serving))
	}
	log.Printf("[flip] draining before the core flip")
	// the drain can take up to drainMax (29 minutes): it ends early once the next core stops being this standby
	abort, stop, gone, every := make(chan struct{}), make(chan struct{}), make(chan string, 1), drainWatchEvery
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(every):
			}
			if w := standbyGone(n.next, nv.key); w != "" {
				gone <- w
				close(abort)
				return
			}
		}
	}()
	r.drainUntil(drainMax, abort)
	close(stop)
	defer r.Undrain()
	// and once more after it: the serving core is handed off only to the standby that was checked before the drain
	var why string
	select {
	case why = <-gone:
	default:
		why = standbyGone(n.next, nv.key)
	}
	if why != "" && n.final == nil {
		log.Printf("[flip] aborted, the serving core goes on: %s", why)
		r.DM("Jarvis 4: the core flip was aborted after its drain, nothing was handed off and the serving core goes on: " + why + ". Recover the next core alongside again for a new flip.")
		return fmt.Errorf("flip aborted, the serving core goes on: %s", why)
	}
	final := n.final
	if final == nil {
		final, err = n.handoff.Finalize(r.core)
		if err != nil {
			return fmt.Errorf("finalizing the serving core: %w", err)
		}
		n.final = final
		r.st.WriteDoc("core-final.json", final) // kept beside the records (statedb.go), for a retry
	}
	if err := n.handoff.Adopt(n.next, final); err != nil {
		// the old core is handed-off for good and can't serve: nothing serves until a takeover goes through (the final
		// state is kept for the retry; POST /handoff on the old core repeats it too)
		log.Printf("[flip] THE NEXT CORE REFUSED THE TAKEOVER: NO CORE SERVES (retry the flip): %v", err)
		r.DM("Jarvis 4: the core flip failed half way — the old core is handed off and the next one refused the takeover, so no core serves. Retry: POST /setup/core/flip. " + err.Error())
		return fmt.Errorf("the next core refused the takeover (the old one is handed off: retry the flip): %w", err)
	}
	r.switchCores(n)
	return nil
}

// finishFlip: the next core serves while the current one is handed off — a takeover went through the next core's own
// Recover (its bundle carried the final state the current core sealed) rather than the flip's POST /takeover. The router
// switches to it only if it has the handed-off core's signing key (the same kit) and a line state at least as new as the
// final state the router kept.
func (r *Router) finishFlip(n *nextCores, nv coreInfo) error {
	cv, err := coreView(r.core)
	if err != nil {
		return fmt.Errorf("the next core serves, but the current core doesn't answer (is it handed off?): %w", err)
	}
	if cv.serving != "handed-off" {
		return fmt.Errorf("both cores say they serve (current %s, next serving): nothing changed, look at both before anything else", orEmptyCore(cv.serving))
	}
	if nv.key != cv.key {
		return errors.New("the next core serves with another signing key than the handed-off one (another kit): nothing changed")
	}
	if n.final != nil {
		var fs struct {
			Head Doc `json:"head"`
		}
		var h struct {
			Seq int `json:"seq"`
		}
		json.Unmarshal(n.final, &fs)
		fs.Head.Decode(&h)
		if nv.lineSeq < h.Seq {
			return fmt.Errorf("the next core serves line state %d, older than the final state %d the current core handed off: nothing changed", nv.lineSeq, h.Seq)
		}
	}
	log.Printf("[flip] the next core took the final state over by its own Recover: finishing the flip")
	r.switchCores(n)
	return nil
}

// switchCores: every later core call goes to the next core, and the state says so (activeCore), so a restarted router
// talks to it too. The final state is no longer needed.
func (r *Router) switchCores(n *nextCores) {
	cur, nxt := r.core.URL(), n.next.URL()
	r.core.SetURL(nxt)
	n.next.SetURL(cur)
	n.final = nil
	r.st.DeleteDoc("core-final.json")
	r.st.Do(func(d *persisted) { d.ActiveCore = nxt })
	log.Printf("[flip] %s serves now; %s is final (the next release goes there)", nxt, cur)
}

// nextCoreLoop: FLIP_AUTO=1 flips once the next core is a standby, and finishes a flip whose takeover already happened
func (r *Router) nextCoreLoop(every, drainMax time.Duration) {
	for {
		awaitLead() // leaderlease.go
		r.nextCoreTick(drainMax)
		time.Sleep(every)
	}
}

func (r *Router) nextCoreTick(drainMax time.Duration) {
	n := r.nextOf()
	if n.next == nil || os.Getenv("FLIP_AUTO") != "1" {
		return
	}
	serving, _, err := coreServing(n.next)
	if err != nil {
		return
	}
	if serving == "serving" {
		// a takeover by the next core's own Recover: finished only while the current core is handed off
		if cur, _, err := coreServing(r.core); err != nil || cur != "handed-off" {
			return
		}
	} else if serving != "standby" {
		return
	}
	if err := r.FlipCore(drainMax); err != nil {
		log.Printf("[flip] automatic flip: %v", err)
	}
}

func orEmptyCore(s string) string {
	if s == "" {
		return "empty"
	}
	return s
}

// nextCoreStatus: for the setup status: each core's URL, serving value and identity
func (r *Router) nextCoreStatus() map[string]any {
	n := r.nextOf()
	view := func(c *CoreClient) map[string]any {
		v := map[string]any{"url": c.URL()}
		serving, key, err := coreServing(c)
		if err != nil {
			v["error"] = err.Error()
		} else {
			v["serving"], v["identity"] = orEmptyCore(serving), key
		}
		return v
	}
	out := map[string]any{"current": view(r.core)}
	r.st.Do(func(d *persisted) { out["activeCore"] = d.ActiveCore })
	if n.next != nil {
		nx := view(n.next)
		nx["finalPending"] = n.final != nil
		out["next"] = nx
	}
	return out
}

// GET /api/state's core.next: the app learns there is a next core (and what it is) and offers Recover alongside for
// it, every call for it with X-Jarvis2-Core: next
func init() {
	stateHooks = append(stateHooks, func(r *Router, out map[string]any) {
		n := r.nextOf()
		if n.next == nil {
			return
		}
		core, _ := out["core"].(map[string]any)
		if core == nil {
			return
		}
		nx := map[string]any{"up": false}
		if serving, key, err := coreServing(n.next); err == nil {
			nx["up"], nx["serving"], nx["signingKey"] = true, orEmptyCore(serving), key
		}
		core["next"] = nx
	})
}

// registerNextCore: the flip route
func (r *Router) registerNextCore(mux *http.ServeMux) {
	mux.Handle("POST /setup/core/flip", r.requireSetup(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(io.LimitReader(req.Body, 1<<16))
		if err := r.checkSetupSig(req.Method, req.URL.Path, req.Header.Get("X-Setup-Time"), req.Header.Get("X-Setup-Sig"), b); err != nil {
			writeJSON(w, 401, map[string]string{"error": err.Error()})
			return
		}
		max, _ := strconv.Atoi(env("DRAIN_SECONDS", "1740"))
		if err := r.FlipCore(time.Duration(max) * time.Second); err != nil {
			writeJSON(w, 409, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, r.nextCoreStatus())
	}))
}
