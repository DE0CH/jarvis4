package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// A handover with long polls in flight: none of them waits for its own timeout. The machine's /m/commands answers
// "nothing" at once (it polls again, at the next leader); an unanswered GET is handed to the next leader; anything
// else gets 503 with Connection: close.
func TestHandoverEndsLongPollsAtOnce(t *testing.T) {
	r := newTestRouter(t)
	m := newTestMachine(r, "m1")
	mh := r.MachineHandler()

	block := make(chan struct{})
	pub := http.NewServeMux()
	pub.HandleFunc("GET /peer/claude-login", func(w http.ResponseWriter, req *http.Request) {
		select {
		case <-req.Context().Done():
		case <-block:
			io.WriteString(w, "old")
		}
	})
	pub.HandleFunc("GET /api/claude-login", func(w http.ResponseWriter, req *http.Request) {
		<-req.Context().Done()
		io.WriteString(w, "what it has") // the Claude login's poll answers what it has
	})
	pub.HandleFunc("POST /act", func(w http.ResponseWriter, req *http.Request) {
		<-r.handingOver() // a call in flight that isn't a long poll runs to its end: it answers after the freeze began
		select {
		case <-req.Context().Done():
			io.WriteString(w, "cancelled")
		default:
			io.WriteString(w, "done")
		}
	})
	ph := r.gated(pub)
	next := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { io.WriteString(w, "next leader") }))
	defer next.Close()

	type res struct {
		code int
		body string
		hdr  http.Header
		end  time.Time
	}
	run := func(f func() res) chan res {
		ch := make(chan res, 1)
		go func() { ch <- f() }()
		return ch
	}
	cmds := run(func() res {
		code, out := m.do(t, mh, "GET", "/m/commands", "")
		return res{code: code, body: strings.TrimSpace(strings.Join([]string{toJSON(out)}, "")), end: time.Now()}
	})
	pubReq := func(method, path string) func() res {
		return func() res {
			w := httptest.NewRecorder()
			ph.ServeHTTP(w, httptest.NewRequest(method, path, nil))
			return res{w.Code, w.Body.String(), w.Header(), time.Now()}
		}
	}
	poll, act, login := run(pubReq("GET", "/peer/claude-login")), run(pubReq("POST", "/act")), run(pubReq("GET", "/api/claude-login"))
	// all four are inside a handler before the freeze (a fixed sleep let a slow one arrive after it, under load)
	inFlight(t, r, 4)

	start := time.Now()
	r.freezeRequests(proxyTo("http://self", next.URL), 5*time.Second)
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("the freeze waited %s for the requests in flight", d)
	}
	c := <-cmds
	if took := c.end.Sub(start); c.code != 200 || !strings.Contains(c.body, `"commands":[]`) || took > 2*time.Second {
		t.Fatalf("/m/commands: %d %s %s after the freeze began", c.code, c.body, took)
	}
	p := <-poll
	if p.code != 200 || p.body != "next leader" {
		t.Fatalf("an unanswered GET must go to the next leader: %d %q", p.code, p.body)
	}
	if l := <-login; l.body != "what it has" || l.hdr.Get("Connection") != "close" {
		t.Fatalf("an answer during the freeze must close its connection: %q %v", l.body, l.hdr)
	}
	a := <-act
	if a.code != 200 || a.body != "done" || a.hdr.Get("Connection") != "close" {
		t.Fatalf("a POST in flight runs to its end (and closes its connection): %d %v %s", a.code, a.hdr, a.body)
	}
	// the machines' listener still serves what reaches it after the freeze (until its peer goes); its long poll answers
	if code, out := m.do(t, mh, "GET", "/m/commands", ""); code != 200 || !strings.Contains(toJSON(out), `"commands":[]`) {
		t.Fatalf("/m/commands after the freeze: %d %v", code, out)
	}
	// a request that reaches a public handler after the freeze goes to the next leader
	w := httptest.NewRecorder()
	r.gated(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "x") })).ServeHTTP(w, httptest.NewRequest("GET", "/x", nil))
	if w.Body.String() != "next leader" {
		t.Fatalf("after the freeze: %q", w.Body.String())
	}
	// an aborted move serves again
	r.thawRequests()
	poll = run(pubReq("GET", "/peer/claude-login"))
	inFlight(t, r, 1)
	close(block)
	if p := <-poll; p.body != "old" {
		t.Fatalf("after a thaw: %q", p.body)
	}
}

// inFlight: until n requests are inside a gated handler
func inFlight(t *testing.T, r *Router, n int) {
	t.Helper()
	waitFor(t, fmt.Sprintf("%d requests in flight", n), func() bool {
		r.gate.mu.Lock()
		defer r.gate.mu.Unlock()
		return r.gate.reqs == n
	})
}

func toJSON(m map[string]any) string {
	var b strings.Builder
	for k, v := range m {
		b.WriteString(`"` + k + `":`)
		switch x := v.(type) {
		case []any:
			if len(x) == 0 {
				b.WriteString("[]")
			} else {
				b.WriteString("[…]")
			}
		default:
			b.WriteString("?")
		}
		b.WriteString(",")
	}
	return b.String()
}

// Deliveries at a handover: the ones in flight finish (their state change lands before the freeze), new ones are
// errSkip (the scheduler tries again on its next tick, in the next leader), an abort lets them through again.
func TestHandoverDeliveries(t *testing.T) {
	r := newTestRouter(t)
	release := make(chan struct{})
	var finished atomic.Bool
	done, err := r.beginDelivery()
	if err != nil {
		t.Fatal(err)
	}
	go func() { <-release; finished.Store(true); done() }()
	stopped := make(chan struct{})
	go func() { r.stopDeliveries(5 * time.Second); close(stopped) }()
	time.Sleep(100 * time.Millisecond)
	if _, err := r.beginDelivery(); !errors.Is(err, errSkip) {
		t.Fatalf("a new delivery during the handover: %v (want errSkip)", err)
	}
	select {
	case <-stopped:
		t.Fatal("stopDeliveries returned with one in flight")
	default:
	}
	close(release)
	<-stopped
	if !finished.Load() {
		t.Fatal("the delivery in flight must finish first")
	}
	r.resumeDeliveries()
	if d, err := r.beginDelivery(); err != nil {
		t.Fatal(err)
	} else {
		d()
	}
}

// A wakeup due while the router was handing over fires on the next leader's first tick, not a tick later.
func TestScheduleTicksAtStart(t *testing.T) {
	r := newTestRouter(t)
	addSession(r, "s1", "started", "m1", false)
	var delivered atomic.Int32
	old := deliverVouchedHook
	deliverVouchedHook = func(r *Router, sid string, d Delivery) error { delivered.Add(1); return nil }
	defer func() { deliverVouchedHook = old }()
	r.st.Do(func(d *persisted) {
		s := sched(d, "s1")
		s.Wakeups["w"] = &Wakeup{Name: "w", At: time.Now().Add(-2 * time.Second).UnixMilli(), ArmedAt: 1, Signed: &SignedRequest{}}
	})
	r.leaseOnce() // leaderlease.go: this replica leads
	go r.scheduleLoop()
	deadline := time.Now().Add(3 * time.Second)
	for delivered.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if delivered.Load() != 1 {
		t.Fatalf("a wakeup due at start must fire at once (delivered %d)", delivered.Load())
	}
}

func TestScheduleSleepsUntilNextDue(t *testing.T) {
	r := newTestRouter(t)
	addSession(r, "s1", "started", "m1", false)
	now := time.Now()
	if d := r.untilNextDue(now, 30*time.Second); d < 30*time.Second || d > 31*time.Second {
		t.Fatalf("nothing armed: %s", d)
	}
	r.st.Do(func(d *persisted) {
		sched(d, "s1").Wakeups["w"] = &Wakeup{Name: "w", At: now.Add(5 * time.Second).UnixMilli(), ArmedAt: 1}
	})
	if d := r.untilNextDue(now, 30*time.Second); d < 5*time.Second || d > 5100*time.Millisecond {
		t.Fatalf("a wakeup in 5 s: sleep %s", d)
	}
	r.st.Do(func(d *persisted) { sched(d, "s1").Wakeups["w"].At = now.Add(-time.Minute).UnixMilli() })
	if d := r.untilNextDue(now, 30*time.Second); d < 30*time.Second {
		t.Fatalf("one overdue retries on the ticks: %s", d)
	}
}

// every 5xx the public listener answers is logged with its path and the start of its body
func TestGateLogs5xx(t *testing.T) {
	r := newTestRouter(t)
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	h := r.gated(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/bad" {
			writeJSON(w, 502, map[string]string{"error": "the backup bucket refused GET: SlowDown"})
			return
		}
		writeJSON(w, 200, map[string]string{"ok": "yes"})
	}))
	for _, p := range []string{"/ok", "/bad"} {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", p, nil))
	}
	out := buf.String()
	if !strings.Contains(out, `[5xx] GET /bad: 502 {"error":"the backup bucket refused GET: SlowDown"}`) || strings.Contains(out, "/ok") {
		t.Fatalf("log: %q", out)
	}
}
