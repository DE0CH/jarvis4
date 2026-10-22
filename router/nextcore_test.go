package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// handoffCore: a core as the handoff contract describes it (core continuity): serving | standby | handed-off
type handoffCore struct {
	mu        sync.Mutex
	serving   string // "" = empty
	key       string // its signing key ("K" unless a test sets another)
	seq       int
	handoffs  int
	takeovers []string
	srv       *httptest.Server
}

func newHandoffCore(t *testing.T, serving string, seq int) *handoffCore {
	f := &handoffCore{serving: serving, seq: seq, key: "K"}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		switch r.Method + " " + r.URL.Path {
		case "GET /identity":
			st := map[string]any{"kind": "core-state", "master": nil}
			if f.serving != "" {
				st["master"], st["serving"], st["lineSeq"] = "M", f.serving, f.seq
			}
			p, _ := json.Marshal(st)
			json.NewEncoder(w).Encode(map[string]any{"signingKey": f.key, "state": Doc{Payload: string(p), Sig: "s"}})
		case "POST /handoff":
			if f.serving != "serving" && f.serving != "handed-off" {
				http.Error(w, `{"error":"not serving"}`, 409)
				return
			}
			f.serving = "handed-off"
			f.handoffs++
			head, _ := json.Marshal(map[string]any{"kind": "line-state-head", "seq": f.seq, "final": true})
			json.NewEncoder(w).Encode(map[string]any{"head": Doc{Payload: string(head), Sig: "s"}, "sealed": "SEALED"})
		case "POST /takeover":
			b, _ := io.ReadAll(r.Body)
			var in struct {
				LineState struct {
					Head   Doc    `json:"head"`
					Sealed string `json:"sealed"`
				} `json:"lineState"`
			}
			json.Unmarshal(b, &in)
			var h struct {
				Seq   int  `json:"seq"`
				Final bool `json:"final"`
			}
			in.LineState.Head.Decode(&h)
			if f.serving != "standby" || !h.Final || h.Seq < f.seq || in.LineState.Sealed != "SEALED" {
				http.Error(w, `{"error":"refused"}`, 403)
				return
			}
			f.serving, f.seq = "serving", h.Seq
			f.takeovers = append(f.takeovers, string(b))
			json.NewEncoder(w).Encode(Doc{Payload: `{"kind":"took-over"}`, Sig: "s"})
		default:
			if f.serving == "handed-off" {
				http.Error(w, `{"error":"this core is handed-off"}`, 409)
				return
			}
			io.WriteString(w, `{"payload":"{}","sig":"s"}`)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *handoffCore) state() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.serving
}

func TestFlipToStandbyCore(t *testing.T) {
	r := newTestRouter(t)
	cur, next := newHandoffCore(t, "serving", 7), newHandoffCore(t, "", 0)
	r.core = &CoreClient{base: cur.srv.URL, http: http.DefaultClient}
	r.setNextCore(next.srv.URL, httpHandoff{})

	if err := r.FlipCore(time.Second); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("an empty next core can't take over: %v", err)
	}
	if cur.state() != "serving" {
		t.Fatal("a refused flip must not hand the serving core off")
	}
	next.mu.Lock()
	next.serving, next.seq = "standby", 5 // Deyao Recovered it alongside
	next.mu.Unlock()
	if err := r.FlipCore(time.Second); err != nil {
		t.Fatal(err)
	}
	if cur.state() != "handed-off" || next.state() != "serving" {
		t.Fatalf("after the flip: old %s, next %s", cur.state(), next.state())
	}
	if r.core.URL() != next.srv.URL || r.nextOf().next.URL() != cur.srv.URL {
		t.Fatal("the router must talk to the new core now")
	}
	if r.draining() {
		t.Fatal("the flip must end its drain")
	}
	var active string
	r.st.Do(func(d *persisted) { active = d.ActiveCore })
	if active != next.srv.URL {
		t.Fatalf("activeCore %q", active)
	}
	// a restarted router (same env: CORE_URL = the old one, NEXT_CORE_URL = the new one) talks to the active one
	r2 := NewRouter(r.cfg, r.st, &CoreClient{base: cur.srv.URL, http: http.DefaultClient}, Policy{})
	r2.setNextCore(next.srv.URL, nil)
	r2.applyActiveCore()
	if r2.core.URL() != next.srv.URL {
		t.Fatal("a restart must keep the flipped core")
	}
	st := r.nextCoreStatus()
	if st["current"].(map[string]any)["serving"] != "serving" || st["next"].(map[string]any)["serving"] != "handed-off" {
		t.Fatalf("status %v", st)
	}
	// the handed-off core is never flipped back to
	if err := r.FlipCore(time.Second); err == nil {
		t.Fatal("a handed-off core can't take over")
	}
}

// A takeover refused after the handoff: no core serves; the final state is kept and a retry goes through.
func TestFlipRetryAfterRefusedTakeover(t *testing.T) {
	r := newTestRouter(t)
	cur, next := newHandoffCore(t, "serving", 7), newHandoffCore(t, "standby", 9) // recovered NEWER than the final: refused
	r.core = &CoreClient{base: cur.srv.URL, http: http.DefaultClient}
	r.setNextCore(next.srv.URL, httpHandoff{})
	if err := r.FlipCore(time.Second); err == nil {
		t.Fatal("a takeover of an older state must be refused")
	}
	if cur.state() != "handed-off" || r.core.URL() != cur.srv.URL {
		t.Fatal("the old core is handed off and the router still points at it")
	}
	next.mu.Lock()
	next.seq = 7
	next.mu.Unlock()
	if err := r.FlipCore(time.Second); err != nil {
		t.Fatal(err)
	}
	if next.state() != "serving" || cur.handoffs != 1 {
		t.Fatalf("retry: next %s, handoffs %d (the kept final state is reused)", next.state(), cur.handoffs)
	}
}

func TestCoreForNext(t *testing.T) {
	r := newTestRouter(t)
	r.core = &CoreClient{base: "http://cur", http: http.DefaultClient}
	req := httptest.NewRequest("GET", "/api/core/identity?core=next", nil)
	if r.coreFor(req) != nil {
		t.Fatal("no next core configured: nil")
	}
	r.setNextCore("http://next", nil)
	if c := r.coreFor(req); c == nil || c.URL() != "http://next" {
		t.Fatal("?core=next")
	}
	req = httptest.NewRequest("GET", "/api/core/identity", nil)
	req.Header.Set("X-Jarvis2-Core", "next")
	if c := r.coreFor(req); c.URL() != "http://next" {
		t.Fatal("header")
	}
	if c := r.coreFor(httptest.NewRequest("GET", "/api/core/identity", nil)); c.URL() != "http://cur" {
		t.Fatal("default")
	}
}

// The box move carries the core along: the old box's core hands off in the freeze, the new box's standby takes over
// before the new router serves.
func TestMoveCarriesTheCore(t *testing.T) {
	g := newMoveRig(t)
	cur, next := newHandoffCore(t, "serving", 3), newHandoffCore(t, "standby", 3)
	g.r.core = &CoreClient{base: cur.srv.URL, http: http.DefaultClient}
	g.sender.handoff = httpHandoff{}
	g.joiner.handoff, g.joiner.core = httpHandoff{}, &CoreClient{base: next.srv.URL, http: http.DefaultClient}
	g.joiner.at = time.Now()
	if !g.joiner.candidate(g.lockB, g.srvB.URL, g.pubB, make(chan os.Signal)) {
		t.Fatal("no move")
	}
	if cur.state() != "handed-off" || next.state() != "serving" || len(next.takeovers) != 1 {
		t.Fatalf("old core %s, new core %s", cur.state(), next.state())
	}
	g.pubB.set(g.serveB)
	g.joiner.finish()
}

func (f *handoffCore) set(fn func(f *handoffCore)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

// catchDMs: the DMs sent while a test runs
func catchDMs(t *testing.T) func() []string {
	var mu sync.Mutex
	var dms []string
	old := dmHook
	dmHook = func(s string) { mu.Lock(); dms = append(dms, s); mu.Unlock() }
	t.Cleanup(func() { dmHook = old })
	return func() []string { mu.Lock(); defer mu.Unlock(); return append([]string(nil), dms...) }
}

// The outage of 2026-10-22: a core release restarted the standby (empty) while the flip drained. The drain ends early
// and nothing is handed off: the serving core goes on, and Deyao hears why.
func TestFlipAbortsWhenTheStandbyGoesDuringTheDrain(t *testing.T) {
	old := drainWatchEvery
	drainWatchEvery = 20 * time.Millisecond
	defer func() { drainWatchEvery = old }()
	dms := catchDMs(t)
	r := newTestRouter(t)
	cur, next := newHandoffCore(t, "serving", 7), newHandoffCore(t, "standby", 7)
	r.core = &CoreClient{base: cur.srv.URL, http: http.DefaultClient}
	r.setNextCore(next.srv.URL, httpHandoff{})
	done, err := r.begin("s1", "pause") // a lifecycle action that outlasts the flip's drain
	if err != nil {
		t.Fatal(err)
	}
	defer done()
	go func() {
		time.Sleep(50 * time.Millisecond)
		next.set(func(f *handoffCore) { f.serving, f.seq = "", 0 }) // CI pinned a new core into it: empty
	}()
	start := time.Now()
	err = r.FlipCore(time.Minute)
	if err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("the flip must abort: %v", err)
	}
	if time.Since(start) > 10*time.Second {
		t.Fatal("the drain must end as soon as the standby goes, not at its maximum")
	}
	if cur.state() != "serving" || cur.handoffs != 0 || r.core.URL() != cur.srv.URL {
		t.Fatalf("the serving core must go on: %s, %d handoffs", cur.state(), cur.handoffs)
	}
	if r.draining() {
		t.Fatal("an aborted flip must undrain")
	}
	if d := dms(); len(d) != 1 || !strings.Contains(d[0], "aborted") {
		t.Fatalf("DMs %q", d)
	}
}

// The standby changes in a way the watch doesn't see in time (here: Recovered again with another kit just before the
// drain ends): the check after the drain still refuses the handoff.
func TestFlipRechecksTheStandbyAfterTheDrain(t *testing.T) {
	old := drainWatchEvery
	drainWatchEvery = time.Hour
	defer func() { drainWatchEvery = old }()
	dms := catchDMs(t)
	r := newTestRouter(t)
	cur, next := newHandoffCore(t, "serving", 7), newHandoffCore(t, "standby", 7)
	r.core = &CoreClient{base: cur.srv.URL, http: http.DefaultClient}
	r.setNextCore(next.srv.URL, httpHandoff{})
	done, err := r.begin("s1", "pause")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		// once the drain has begun (the standby was checked before it), the standby changes, then the pause ends
		for !r.draining() {
			time.Sleep(time.Millisecond)
		}
		next.set(func(f *handoffCore) { f.key = "OTHER" })
		done()
	}()
	if err := r.FlipCore(time.Minute); err == nil || !strings.Contains(err.Error(), "signing key") {
		t.Fatalf("the flip must abort: %v", err)
	}
	if cur.state() != "serving" || cur.handoffs != 0 || next.state() != "standby" {
		t.Fatalf("nothing may be handed off: current %s, next %s", cur.state(), next.state())
	}
	if r.draining() || len(dms()) != 1 {
		t.Fatalf("undrained %v, DMs %q", !r.draining(), dms())
	}
	// the same standby once more: the flip goes through
	next.set(func(f *handoffCore) { f.key = "K" })
	if err := r.FlipCore(time.Minute); err != nil {
		t.Fatal(err)
	}
	if next.state() != "serving" || r.core.URL() != next.srv.URL {
		t.Fatal("the flip after it must go through")
	}
}

// The takeover happened by the next core's own Recover (its bundle carried the final state): the router finishes the
// flip — the automatic tick and POST /setup/core/flip alike — and keeps it over a restart.
func TestFinishAFlipTheNextCoreTookOverByRecover(t *testing.T) {
	r := newTestRouter(t)
	cur, next := newHandoffCore(t, "serving", 7), newHandoffCore(t, "standby", 9) // refused: older than its Recover
	r.core = &CoreClient{base: cur.srv.URL, http: http.DefaultClient}
	r.setNextCore(next.srv.URL, httpHandoff{})
	catchDMs(t)
	if err := r.FlipCore(time.Second); err == nil {
		t.Fatal("the takeover must be refused")
	}
	if _, ok := r.st.ReadDoc("core-final.json"); !ok {
		t.Fatal("the final state is kept")
	}
	// another kit's core serving there: not switched to
	next.set(func(f *handoffCore) { f.serving, f.seq, f.key = "serving", 7, "OTHER" })
	if err := r.FlipCore(time.Second); err == nil || r.core.URL() != cur.srv.URL {
		t.Fatalf("another kit's core must not be switched to: %v", err)
	}
	// an older line state than the final one: not switched to
	next.set(func(f *handoffCore) { f.seq, f.key = 6, "K" })
	if err := r.FlipCore(time.Second); err == nil || r.core.URL() != cur.srv.URL {
		t.Fatalf("an older line state must not be switched to: %v", err)
	}
	// Recovered (restarted empty, then Recover with the kit: the bundle had the final state) → it serves
	next.set(func(f *handoffCore) { f.seq = 7 })
	t.Setenv("FLIP_AUTO", "1")
	r.nextCoreTick(time.Second)
	if r.core.URL() != next.srv.URL || r.nextOf().next.URL() != cur.srv.URL {
		t.Fatal("the automatic tick must finish the flip")
	}
	if len(next.takeovers) != 0 {
		t.Fatal("no takeover call: it already serves")
	}
	var active string
	r.st.Do(func(d *persisted) { active = d.ActiveCore })
	if active != next.srv.URL || r.nextOf().final != nil {
		t.Fatalf("activeCore %q, final kept %v", active, r.nextOf().final != nil)
	}
	if _, ok := r.st.ReadDoc("core-final.json"); ok {
		t.Fatal("core-final.json must go")
	}
	if r.nextCoreStatus()["activeCore"] != next.srv.URL {
		t.Fatal("the status shows activeCore")
	}
	// a restarted router with the env unchanged talks to the new core
	r2 := NewRouter(r.cfg, r.st, &CoreClient{base: cur.srv.URL, http: http.DefaultClient}, Policy{})
	r2.setNextCore(next.srv.URL, nil)
	r2.applyActiveCore()
	if r2.core.URL() != next.srv.URL {
		t.Fatal("a restart must keep the finished flip")
	}
	// nothing more to finish: the tick leaves it alone (the handed-off core is next now)
	r.nextCoreTick(time.Second)
	if r.core.URL() != next.srv.URL {
		t.Fatal("a second tick must change nothing")
	}
}

// Both cores serving (the next one Recovered on its own while the current one never handed off): no switch.
func TestNoFinishWhileTheCurrentCoreServes(t *testing.T) {
	r := newTestRouter(t)
	cur, next := newHandoffCore(t, "serving", 7), newHandoffCore(t, "serving", 7)
	r.core = &CoreClient{base: cur.srv.URL, http: http.DefaultClient}
	r.setNextCore(next.srv.URL, httpHandoff{})
	t.Setenv("FLIP_AUTO", "1")
	r.nextCoreTick(time.Second)
	if err := r.FlipCore(time.Second); err == nil || !strings.Contains(err.Error(), "both cores") {
		t.Fatalf("%v", err)
	}
	if r.core.URL() != cur.srv.URL {
		t.Fatal("no switch while the current core serves")
	}
}
