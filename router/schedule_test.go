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

// a cron run that fails every attempt (Fly's org machine limit on the resume) is skipped and marked missed; Run now
// then delivers that same run, counts it, clears the mark and leaves the next occurrence at least half a period away
// (Deyao, 2026-11-17)
func TestCronSkippedIsMissedThenRunNow(t *testing.T) {
	r := newTestRouter(t)
	dms := captureDM(t)
	f := &fakeDelivery{err: errors.New(`the session didn't start (state "failed" start: kernel spawner: HTTP 502 fly create: POST /machines: HTTP 422 {"error":"Your organization has reached its machine limit. Please contact billing@fly.io"})`)}
	f.install(t)
	addSession(r, "s6", "paused", "", false)
	r.ArmCron("s6", &Cron{Name: "check", Prompt: "do", Every: 3600, TZ: "UTC", NextAt: time.Now().Add(-time.Minute).UnixMilli(), ArmedAt: 1, Signed: signed("check")})
	// Fly's machine limit is a known error: the first failure skips the run, marks it missed in its own words and DMs
	// at once (Deyao, 2026-11-17: "it shouldn't tell me after five failed attempts")
	r.scheduleTick(time.Now())
	waitIdle(t)
	cs, _ := r.ListCrons("s6")
	if len(cs) != 1 || cs[0].Missed == nil || cs[0].Missed.Run != 1 || cs[0].Missed.Error != flyLimitText || cs[0].Runs != 0 || cs[0].NextAt <= time.Now().UnixMilli() {
		t.Fatalf("not marked missed at once: %+v", cs)
	}
	if v := cronView(cs[0]); v["missed"] == nil {
		t.Fatalf("view without missed: %v", v)
	}
	if len(dms()) != 1 || !strings.Contains(dms()[0], "Fly's machine limit is reached") || !strings.Contains(dms()[0], "Run now") || strings.Contains(dms()[0], "attempts") || strings.Contains(dms()[0], "422") {
		t.Fatalf("dms %q", dms())
	}
	if len(f.got()) != 0 {
		t.Fatalf("delivered %q", f.got())
	}

	f.mu.Lock()
	f.err = nil
	f.mu.Unlock()
	if code, out := appDo(t, r, "POST", "/api/sessions/s6/crons/check/run", ""); code != 202 {
		t.Fatalf("run now: %d %v", code, out)
	}
	waitIdle(t)
	if got := f.got(); len(got) != 1 || got[0] != "s6: cron check run 1" {
		t.Fatalf("delivered %q", got)
	}
	cs, _ = r.ListCrons("s6")
	if cs[0].Missed != nil || cs[0].Runs != 1 || cs[0].LastFiredAt == nil || cs[0].NextAt < time.Now().Add(30*time.Minute).UnixMilli() {
		t.Fatalf("after run now: %+v", cs[0])
	}
	// right after, the session would refuse a repeat: refused upfront, nothing delivered
	if code, out := appDo(t, r, "POST", "/api/sessions/s6/crons/check/run", ""); code != 409 || !strings.Contains(fmt.Sprint(out["error"]), "half its period") {
		t.Fatalf("too soon: %d %v", code, out)
	}
	if code, _ := appDo(t, r, "POST", "/api/sessions/s6/crons/nope/run", ""); code != 404 {
		t.Fatalf("unknown cron: %d", code)
	}
	if len(f.got()) != 1 {
		t.Fatalf("delivered again: %q", f.got())
	}
}

// Run now on a wakeup not yet due: delivered at once and done, as its own firing would be
func TestRunNowWakeup(t *testing.T) {
	r := newTestRouter(t)
	f := &fakeDelivery{}
	f.install(t)
	addSession(r, "s7", "started", "m7", false)
	r.ArmWakeup("s7", &Wakeup{Name: "later", At: time.Now().Add(time.Hour).UnixMilli(), Prompt: "go", ArmedAt: 1, Signed: signed("later")})
	if code, out := appDo(t, r, "POST", "/api/sessions/s7/wakeups/later/run", ""); code != 202 {
		t.Fatalf("run now: %d %v", code, out)
	}
	waitIdle(t)
	if got := f.got(); len(got) != 1 || got[0] != "s7: wakeup later" {
		t.Fatalf("delivered %q", got)
	}
	if ws, _ := r.ListWakeups("s7"); len(ws) != 0 {
		t.Fatalf("left %+v", ws)
	}
}

// a Run now that fails is DMed and marks the run missed; the cron's schedule is left as it was
func TestRunNowFailureMarksMissed(t *testing.T) {
	r := newTestRouter(t)
	dms := captureDM(t)
	f := &fakeDelivery{err: errors.New("the session didn't start")}
	f.install(t)
	addSession(r, "s8", "paused", "", false)
	next := time.Now().Add(2 * time.Hour).UnixMilli()
	r.ArmCron("s8", &Cron{Name: "d", Prompt: "do", Every: 86400, TZ: "UTC", NextAt: next, ArmedAt: 1, Runs: 3, Signed: signed("d")})
	if err := r.RunNow("s8", "c", "d"); err != nil {
		t.Fatal(err)
	}
	waitIdle(t)
	cs, _ := r.ListCrons("s8")
	if cs[0].Missed == nil || cs[0].Missed.Run != 4 || cs[0].Runs != 3 || cs[0].NextAt != next {
		t.Fatalf("%+v", cs[0])
	}
	if len(dms()) != 1 || !strings.Contains(dms()[0], "Run now") {
		t.Fatalf("dms %q", dms())
	}
}

// a session whose start failed at Fly's machine limit is resumed by Run now, then gets the delivery
func TestRunNowResumesAFailedSession(t *testing.T) {
	r := newTestRouter(t)
	f := &fakeDelivery{}
	f.install(t)
	addSession(r, "s9", "failed", "", false)
	resumed := 0
	old := runNowResumeHook
	runNowResumeHook = func(r *Router, sid string) error {
		resumed++
		r.st.Do(func(d *persisted) { d.Sessions[sid].State = "started" })
		return nil
	}
	t.Cleanup(func() { runNowResumeHook = old })
	r.ArmCron("s9", &Cron{Name: "rel", Prompt: "check", Every: 1800, TZ: "UTC", NextAt: time.Now().Add(-time.Hour).UnixMilli(), ArmedAt: 1, Signed: signed("rel")})
	if err := r.RunNow("s9", "c", "rel"); err != nil {
		t.Fatal(err)
	}
	waitIdle(t)
	if got := f.got(); resumed != 1 || len(got) != 1 || got[0] != "s9: cron rel run 1" {
		t.Fatalf("resumed %d, delivered %q", resumed, got)
	}
}

// An aviary session's wakeups are magpie's schedules (Deyao, 2026-11-17): hermit-jarvis reports the next one, and the
// router counts it as armed (a paused session keeps its runners, its card shows it) without ever firing it.
func TestChatScheduleCountsAsArmed(t *testing.T) {
	r := newTestRouter(t)
	addSession(r, "s1", "paused", "", false)
	addSession(r, "s2", "running", "", false)
	r.st.Do(func(d *persisted) { d.Sessions["s1"].Harness = "aviary" })
	// the real clock: ScheduleDueWithin reads it (a fixed date here failed every run from 13:00 UTC that day on)
	now := time.Now()
	at := now.Add(5 * time.Hour)
	wakes := func(sid string) (w bool) { r.st.Do(func(d *persisted) { w = willWake(d, sid) }); return }
	if wakes("s1") {
		t.Fatal("nothing armed yet")
	}
	if err := r.SetChatSchedule("s1", &at, now); err != nil {
		t.Fatal(err)
	}
	if !wakes("s1") {
		t.Fatal("a chat schedule is an armed wakeup")
	}
	// the session's own retire waits for it, and auto-pause leaves the session running when it is due soon
	if p := r.PendingSchedule("s1"); len(p) != 1 {
		t.Fatalf("pending: %v", p)
	}
	if r.ScheduleDueWithin("s1", time.Hour) {
		t.Fatal("due in 5 h, not within 1 h")
	}
	soon := time.Now().Add(5 * time.Minute)
	if err := r.SetChatSchedule("s1", &soon, now); err != nil || !r.ScheduleDueWithin("s1", 10*time.Minute) {
		t.Fatalf("due in 5 min: %v", err)
	}
	if err := r.SetChatSchedule("s1", &at, now); err != nil {
		t.Fatal(err)
	}
	v := map[string]any{}
	r.st.Do(func(d *persisted) { scheduleView(d, "s1", v) })
	if v["chatScheduleIso"] != iso(at.UnixMilli()) {
		t.Fatalf("view: %v", v)
	}
	// none armed any more: forgotten, and the schedule entry with it
	if err := r.SetChatSchedule("s1", nil, now); err != nil {
		t.Fatal(err)
	}
	if wakes("s1") {
		t.Fatal("cleared")
	}
	r.st.Do(func(d *persisted) {
		if d.Schedules["s1"] != nil {
			t.Fatal("an empty schedule is dropped")
		}
	})
	// only an aviary session has them; an unknown session is 404's error
	if err := r.SetChatSchedule("s2", &at, now); err == nil {
		t.Fatal("a claude session has no chat schedules")
	}
	if err := r.SetChatSchedule("nope", &at, now); !errors.Is(err, errNoSession) {
		t.Fatalf("unknown session: %v", err)
	}
}

// knownError: Fly's machine limit in its own words, anything else as it is
func TestKnownErrorFlyLimit(t *testing.T) {
	if got := knownError(errors.New(`start: kernel spawner: HTTP 502 fly create: POST /machines: HTTP 422 {"error":"Your organization has reached its machine limit. Please contact billing@fly.io"}`)); got != flyLimitText {
		t.Fatal(got)
	}
	if !flyMachineLimit(errors.New("start: " + flyLimitText)) {
		t.Fatal("the known text no longer reads as the machine limit")
	}
	if got := knownError(errors.New("boom")); got != "boom" {
		t.Fatal(got)
	}
}
