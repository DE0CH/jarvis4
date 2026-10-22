package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func newTestRouter(t *testing.T) *Router {
	t.Helper()
	st, err := testState(t, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return NewRouter(Config{NoAccess: true, DataDir: st.dir, WebDir: t.TempDir()}, st, nil, Policy{})
}

func addSession(r *Router, id, state, machine string, sensitive bool) {
	payload, _ := json.Marshal(map[string]any{"line": "L" + id, "sensitive": sensitive})
	r.st.Do(func(d *persisted) {
		d.Sessions[id] = &Session{ID: id, State: state, MachineID: machine, Label: "label " + id, Harness: "claude", Cert: &Doc{Payload: string(payload)}}
		if machine != "" {
			d.Machines[machine] = id
		}
	})
}

func body(s string) map[string]any {
	m := map[string]any{}
	json.Unmarshal([]byte(s), &m)
	return m
}

func TestNormalizeWakeup(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	w, err := normalizeWakeup(body(`{"delaySeconds": 3600, "prompt": "  do\n  it  "}`), now)
	if err != nil || w.Name != "default" || w.At != now.Add(time.Hour).UnixMilli() || w.Prompt != "do it" || w.ArmedAt != now.UnixMilli() {
		t.Fatalf("%+v %v", w, err)
	}
	w, err = normalizeWakeup(body(`{"at": "2026-10-10T08:00:00Z", "prompt": "x", "name": "hotel-1"}`), now)
	if err != nil || w.Name != "hotel-1" || w.At != time.Date(2026, 10, 10, 8, 0, 0, 0, time.UTC).UnixMilli() {
		t.Fatalf("%+v %v", w, err)
	}
	if w, err = normalizeWakeup(body(`{"at": 1791633600000, "prompt": "x"}`), now); err != nil || w.At != 1791633600000 {
		t.Fatalf("ms epoch: %+v %v", w, err)
	}
	// a time already past is due now: it fires at once
	if w, err = normalizeWakeup(body(`{"at": "2026-10-01T00:00:00Z", "prompt": "x"}`), now); err != nil || w.At != now.UnixMilli() {
		t.Fatalf("past: %+v %v", w, err)
	}
	// up to 400 days, as far as a cron's until
	if _, err = normalizeWakeup(body(`{"delaySeconds": 8000000, "prompt": "x"}`), now); err != nil {
		t.Fatalf("93 days: %v", err)
	}
	for _, b := range []string{
		`{"delaySeconds": 60}`, `{"prompt": "x"}`, `{"delaySeconds": -1, "prompt": "x"}`,
		`{"delaySeconds": 40000000, "prompt": "x"}`, `{"delaySeconds": 60, "prompt": "x", "name": "bad name"}`, `{"at": "tomorrow", "prompt": "x"}`,
		`{"delaySeconds": 60, "prompt": "` + strings.Repeat("a", 3501) + `"}`,
	} {
		if _, err := normalizeWakeup(body(b), now); err == nil {
			t.Fatalf("%s should be refused", b)
		}
	}
}

func TestNormalizeCronAndAdvance(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	c, err := normalizeCron(body(`{"name": "tix", "prompt": "check", "time": "12:00", "tz": "Asia/Shanghai"}`), now)
	// 12:00 in Shanghai = 04:00 UTC; today's is past → tomorrow's
	if err != nil || c.NextAt != time.Date(2026, 10, 10, 4, 0, 0, 0, time.UTC).UnixMilli() || c.Every != 86400 || c.TZ != "Asia/Shanghai" {
		t.Fatalf("%+v %v", c, err)
	}
	c, err = normalizeCron(body(`{"name": "d", "prompt": "p", "everySeconds": 21600, "until": "2026-12-10T00:00:00Z"}`), now)
	if err != nil || c.NextAt != now.Add(6*time.Hour).UnixMilli() || c.Until == nil {
		t.Fatalf("%+v %v", c, err)
	}
	for _, b := range []string{`{"prompt": "p"}`, `{"name": "a", "prompt": "p", "everySeconds": 60}`, `{"name": "a", "prompt": "p", "tz": "Mars/Base"}`,
		`{"name": "a", "prompt": "p", "time": "25:00"}`, `{"name": "a", "prompt": "p", "until": "2026-10-09T13:00:00Z"}`} {
		if _, err := normalizeCron(body(b), now); err == nil {
			t.Fatalf("%s should be refused", b)
		}
	}
	// a first firing already past: the next slot of its period
	c, err = normalizeCron(body(`{"name": "d", "prompt": "p", "everySeconds": 3600, "at": "`+now.Add(-90*time.Minute).Format(time.RFC3339)+`"}`), now)
	if err != nil || c.NextAt != now.Add(30*time.Minute).UnixMilli() {
		t.Fatalf("past first firing: %+v %v", c, err)
	}
	// a session unreachable for 3.5 periods fires once and moves to the next occurrence after now
	c = &Cron{Every: 3600, NextAt: now.UnixMilli()}
	next, ok := advanceCron(c, now.Add(210*time.Minute))
	if !ok || next != now.Add(4*time.Hour).UnixMilli() {
		t.Fatalf("next %v", time.UnixMilli(next).UTC())
	}
	u := now.Add(30 * time.Minute).UnixMilli()
	c.Until = &u
	if _, ok := advanceCron(c, now.Add(time.Minute)); ok {
		t.Fatal("past until: the cron ends")
	}
}

type fakeDelivery struct {
	mu    sync.Mutex
	texts []string
	after []string
	err   error
}

// install: deliveries recorded as "<session>: <kind> <the signed request's payload> [run n]"
func (f *fakeDelivery) install(t *testing.T) {
	old := deliverVouchedHook
	deliverVouchedHook = func(r *Router, sid string, d Delivery) error {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.err != nil {
			return f.err
		}
		x := sid + ": " + d.Kind + " " + d.Request.Body
		if d.Run > 0 {
			x += fmt.Sprintf(" run %d", d.Run)
		}
		f.texts = append(f.texts, x)
		return nil
	}
	t.Cleanup(func() { deliverVouchedHook = old })
}

// installPeer: a resume prompt (its own delivery kind), recorded as "<session>: <text>"
func (f *fakeDelivery) installPeer(t *testing.T) {
	old := deliverVouchedHook
	deliverVouchedHook = func(r *Router, sid string, d Delivery) error {
		f.mu.Lock()
		defer f.mu.Unlock()
		if d.Kind != "resume-prompt" {
			t.Errorf("a %s delivery", d.Kind)
		}
		f.texts = append(f.texts, sid+": "+d.Text)
		return nil
	}
	t.Cleanup(func() { deliverVouchedHook = old })
}

// signed: a wakeup or cron as the session's own signed request (its payload is the test's label)
func signed(label string) *SignedRequest { return &SignedRequest{Body: label} }

func (f *fakeDelivery) got() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string{}, f.texts...)
}

// captureDM: the DMs sent from now on; the func reads them under the hook's lock (a DM is sent from a handler's or
// a flow's goroutine, which an answer over a real connection doesn't order before the test's read for the race detector)
func captureDM(t *testing.T) func() []string {
	var mu sync.Mutex
	var dms []string
	old := dmHook
	dmHook = func(s string) { mu.Lock(); dms = append(dms, s); mu.Unlock() }
	t.Cleanup(func() { dmHook = old })
	return func() []string { mu.Lock(); defer mu.Unlock(); return append([]string{}, dms...) }
}

// waitIdle: the tick's goroutines are done
func waitIdle(t *testing.T) {
	for i := 0; i < 200; i++ {
		schedRun.init()
		schedRun.mu.Lock()
		n := len(schedRun.busy)
		schedRun.mu.Unlock()
		if n == 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("tick still busy")
}

func TestWakeupFiresOnceAndClears(t *testing.T) {
	r := newTestRouter(t)
	f := &fakeDelivery{}
	f.install(t)
	addSession(r, "s1", "started", "m1", false)
	now := time.Now()
	r.ArmWakeup("s1", &Wakeup{Name: "default", At: now.Add(-time.Second).UnixMilli(), Prompt: "go", ArmedAt: 1, Signed: signed("go")})
	r.ArmWakeup("s1", &Wakeup{Name: "later", At: now.Add(time.Hour).UnixMilli(), Prompt: "not yet", ArmedAt: 2, Signed: signed("later")})
	r.ArmWakeup("s1", &Wakeup{Name: "named", At: now.Add(-time.Second).UnixMilli(), Prompt: "x", ArmedAt: 3, Signed: signed("x")})
	r.scheduleTick(now)
	waitIdle(t)
	r.scheduleTick(now)
	waitIdle(t)
	got := f.got()
	if len(got) != 2 || !contains(got, "s1: wakeup go") || !contains(got, "s1: wakeup x") {
		t.Fatalf("delivered %q", got)
	}
	ws, _ := r.ListWakeups("s1")
	if len(ws) != 1 || ws[0].Name != "later" {
		t.Fatalf("left %+v", ws)
	}
	if p := r.PendingSchedule("s1"); len(p) != 1 || p[0] != "wakeup later" {
		t.Fatalf("pending %v", p)
	}
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

func TestWakeupRearmedDuringFireIsKept(t *testing.T) {
	r := newTestRouter(t)
	addSession(r, "s1", "started", "m1", false)
	old := deliverVouchedHook
	deliverVouchedHook = func(r *Router, sid string, d Delivery) error {
		r.ArmWakeup("s1", &Wakeup{Name: "default", At: time.Now().Add(time.Hour).UnixMilli(), Prompt: "new", ArmedAt: 99, Signed: signed("new")})
		return nil
	}
	t.Cleanup(func() { deliverVouchedHook = old })
	r.ArmWakeup("s1", &Wakeup{Name: "default", At: time.Now().Add(-time.Second).UnixMilli(), Prompt: "old", ArmedAt: 1, Signed: signed("old")})
	r.scheduleTick(time.Now())
	waitIdle(t)
	ws, _ := r.ListWakeups("s1")
	if len(ws) != 1 || ws[0].Prompt != "new" {
		t.Fatalf("%+v", ws)
	}
}

func TestWakeupFailuresBackOffThenDrop(t *testing.T) {
	r := newTestRouter(t)
	dms := captureDM(t)
	f := &fakeDelivery{err: errors.New("peer message not delivered: boom")}
	f.install(t)
	addSession(r, "s2", "started", "m2", false)
	r.ArmWakeup("s2", &Wakeup{Name: "default", At: time.Now().Add(-time.Second).UnixMilli(), Prompt: "go", ArmedAt: 1, Signed: signed("go")})
	at := time.Now()
	for i := 0; i < scheduleMaxAttempt; i++ {
		r.scheduleTick(at)
		waitIdle(t)
		at = at.Add(9 * time.Minute) // past every backoff
	}
	if ws, _ := r.ListWakeups("s2"); len(ws) != 0 {
		t.Fatalf("dropped after %d attempts: %+v", scheduleMaxAttempt, ws)
	}
	if len(dms()) != 1 || !strings.Contains(dms()[0], "could not be delivered") {
		t.Fatalf("dms %q", dms())
	}
}

func TestCronFiresAndAdvances(t *testing.T) {
	r := newTestRouter(t)
	f := &fakeDelivery{}
	f.install(t)
	addSession(r, "s5", "started", "m5", false)
	now := time.Now()
	r.ArmCron("s5", &Cron{Name: "daily", Prompt: "do", Every: 86400, TZ: "UTC", NextAt: now.Add(-time.Minute).UnixMilli(), ArmedAt: 1, Signed: signed("daily")})
	r.scheduleTick(now)
	waitIdle(t)
	got := f.got()
	if len(got) != 1 || got[0] != "s5: cron daily run 1" {
		t.Fatalf("%q", got)
	}
	cs, _ := r.ListCrons("s5")
	if len(cs) != 1 || cs[0].Runs != 1 || cs[0].NextAt <= now.UnixMilli() || cs[0].LastFiredAt == nil {
		t.Fatalf("%+v", cs[0])
	}
}

func TestResumePrompt(t *testing.T) {
	r := newTestRouter(t)
	f := &fakeDelivery{}
	f.installPeer(t)
	addSession(r, "s6", "resuming", "", false)
	r.SetResumePrompt("s6", "carry on\nwith B")
	r.scheduleTick(time.Now())
	waitIdle(t)
	if len(f.got()) != 0 {
		t.Fatal("not before the session is started")
	}
	r.st.Do(func(d *persisted) { d.Sessions["s6"].State = "started" })
	r.scheduleTick(time.Now())
	waitIdle(t)
	if got := f.got(); len(got) != 1 || got[0] != "s6: carry on\nwith B" {
		t.Fatalf("%q", got)
	}
	// a start that failed drops it
	addSession(r, "s7", "resuming", "", false)
	r.SetResumePrompt("s7", "x")
	r.st.Do(func(d *persisted) { d.Sessions["s7"].State = "paused" })
	r.scheduleTick(time.Now())
	waitIdle(t)
	r.st.Do(func(d *persisted) { d.Sessions["s7"].State = "started" })
	r.scheduleTick(time.Now())
	waitIdle(t)
	if len(f.got()) != 1 {
		t.Fatal("a dropped resume prompt never turns up later")
	}
}

func TestScheduleGoesWithItsSession(t *testing.T) {
	r := newTestRouter(t)
	addSession(r, "s8", "started", "m8", false)
	r.ArmWakeup("s8", &Wakeup{Name: "default", At: time.Now().Add(time.Hour).UnixMilli(), Prompt: "x", ArmedAt: 1})
	if !r.ScheduleDueWithin("s8", 2*time.Hour) || r.ScheduleDueWithin("s8", time.Minute) {
		t.Fatal("due within")
	}
	r.finish("s8", nil)
	r.scheduleTick(time.Now())
	r.st.Do(func(d *persisted) {
		if d.Schedules["s8"] != nil {
			t.Fatal("the schedule outlived its session")
		}
	})
	if err := r.ArmWakeup("gone", &Wakeup{Name: "default"}); !errors.Is(err, errNoSession) {
		t.Fatal(err)
	}
}

// the autopilot asks the scheduler's veto while it holds the state lock: the veto must not take it again
// (it did, and the first tick with a started session froze the whole router)
func TestAutopilotVetoDoesNotDeadlock(t *testing.T) {
	r := newTestRouter(t)
	addSession(r, "s9", "started", "m9", false)
	r.st.Do(func(d *persisted) {
		d.Sessions["s9"].Live = &Liveness{Reg: &Registry{Status: "idle"}, LastReport: time.Now()}
	})
	r.ArmWakeup("s9", &Wakeup{Name: "default", At: time.Now().Add(5 * time.Minute).UnixMilli(), Prompt: "x", ArmedAt: 1})
	done := make(chan struct{})
	go func() { r.autopilotTick(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("autopilotTick deadlocked on the scheduler's veto")
	}
}
