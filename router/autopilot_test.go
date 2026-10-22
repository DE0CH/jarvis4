package main

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

const sampleRaw = `{"pid":846,"sessionId":"aaaaaaaa-1111","name":"fix the build","nameSource":"derived","status":"shell","statusUpdatedAt":1791533106447,"startedAt":2,"bridgeSessionId":"session_x"}
{"pid":900,"sessionId":"bbbbbbbb-2222","name":"relay","status":"busy","startedAt":1}
__TITLES__
{"type":"ai-title","aiTitle":"Fix the build","sessionId":"aaaaaaaa-1111"}
__BG__
846 0
0
__ONESHOT__
__AUTH__
aaaaaaaa-1111 uuid-login-1
__CREDS__
1791539182634
__REFUSAL__
{"type":"system","subtype":"model_refusal_fallback","originalModel":"claude-opus-5-5","fallbackModel":"claude-fable-5-1","apiRefusalCategory":"cyber","uuid":"u2","timestamp":"2026-10-09T10:00:02.000Z"}
{"type":"assistant","uuid":"u1","timestamp":"2026-10-09T10:00:01.000Z","message":{"model":"<synthetic>","stop_reason":"refusal","stop_details":{"category":"cyber"},"content":[{"type":"text","text":"API Error: Opus 5.5's safeguards flagged this message"}]}}
`

func TestParseRegistry(t *testing.T) {
	g := parseRegistry(sampleRaw)
	if g == nil {
		t.Fatal("nil")
	}
	if g.SessionID != "aaaaaaaa-1111" || g.LiveName != "fix the build" || g.AiTitle != "Fix the build" {
		t.Fatalf("host: %+v", g)
	}
	if g.Status != "idle" || g.BgTasks != 1 { // "shell" folds into idle + ≥ 1 background job
		t.Fatalf("status %q bg %d", g.Status, g.BgTasks)
	}
	if g.AuthFailed != "uuid-login-1" || g.CredsExpiresAt != 1791539182634 || g.SessionsInside != 2 || g.OneShotDone {
		t.Fatalf("login/inside: %+v", g)
	}
	if len(g.Refusals) != 2 || g.Refusals[0].Kind != "refusal" || g.Refusals[0].Model != "Opus 5.5" || g.Refusals[1].To != "claude-fable-5-1" {
		t.Fatalf("refusals: %+v", g.Refusals)
	}
	if !strings.Contains(downgradeText("x", g.Refusals), "switched it to claude-fable-5-1") {
		t.Fatal(downgradeText("x", g.Refusals))
	}
	if !strings.Contains(downgradeText("x", g.Refusals[:1]), "Opus 5.5's safeguards flagged a message (cyber) and the turn stopped") {
		t.Fatal(downgradeText("x", g.Refusals[:1]))
	}
}

func TestParseRegistryWorkers(t *testing.T) {
	if g := parseRegistry(sampleRaw); g.Workers != nil {
		t.Fatalf("an image without the count: %+v", g.Workers)
	}
	raw := sampleRaw + "__WORKERS__\n" +
		`{"workersOf":"bbbbbbbb-2222","at":5,"subagents":7,"jobs":{}}` + "\n" +
		`{"workersOf":"aaaaaaaa-1111","at":9,"subagents":2,"jobs":{"shell":3,"monitor":1,"Bad Type!":4,"zero":0},"listed":{"b1":"shell"}}` + "\n"
	g := parseRegistry(raw)
	if g.Workers == nil || g.Workers.Subagents != 2 || g.Workers.At != 9 || len(g.Workers.Jobs) != 2 || g.Workers.Jobs["shell"] != 3 || g.Workers.Jobs["monitor"] != 1 {
		t.Fatalf("workers %+v", g.Workers)
	}
	if len(g.Refusals) != 2 {
		t.Fatalf("the workers section broke the refusals: %+v", g.Refusals)
	}
	s := &Session{State: "started", MachineID: "m", Live: &Liveness{Reg: g, LastReport: time.Now()}}
	v := map[string]any{}
	liveView(s, v)
	if w, _ := v["workers"].(*Workers); w == nil || w.Subagents != 2 {
		t.Fatalf("state view %v", v["workers"])
	}
}

func TestParseRegistryEmptyAndOneShot(t *testing.T) {
	if parseRegistry("__TITLES__\n__BG__\n__ONESHOT__\n__AUTH__\n__CREDS__\n__REFUSAL__\n") != nil {
		t.Fatal("no claude inside should be nil")
	}
	g := parseRegistry("__TITLES__\n{\"type\":\"ai-title\",\"aiTitle\":\"Job\",\"sessionId\":\"z\"}\n__BG__\n__ONESHOT__\ndone 2026-10-09\n__AUTH__\n__CREDS__\n__REFUSAL__\n")
	if g == nil || !g.OneShotDone || g.AiTitle != "Job" {
		t.Fatalf("one-shot: %+v", g)
	}
	if s, n := normalize("busy", 2); s != "busy" || n != 2 {
		t.Fatal(s, n)
	}
}

type fakeLocks map[string]bool

func (f fakeLocks) busy(id string) bool { return f[id] }

func running(id string, live *Liveness) *persisted {
	return &persisted{Sessions: map[string]*Session{id: {ID: id, MachineID: "m1", State: "started", Harness: "claude", Live: live}}}
}

func report(l *Liveness, now time.Time, g *Registry) { l.Reg, l.LastReport = g, now }

func kinds(a []pilotAction) string {
	var k []string
	for _, x := range a {
		k = append(k, x.Kind)
	}
	return strings.Join(k, ",")
}

func TestAutoPause(t *testing.T) {
	c, now := defaultPilot, time.Now()
	l := &Liveness{}
	d := running("s1", l)
	idle := &Registry{Status: "idle", StatusUpdatedAt: 5}
	none := fakeLocks{}
	veto := func(string) bool { return false }
	report(l, now, idle)
	if a := planTick(d, now, nil, c, none.busy, veto); kinds(a) != "" {
		t.Fatalf("first idle tick: %s", kinds(a))
	}
	now2 := now.Add(c.IdlePause)
	report(l, now2, idle)
	if a := planTick(d, now2, nil, c, none.busy, veto); !strings.Contains(kinds(a), "pause") {
		t.Fatalf("after an hour: %s", kinds(a))
	}
	// a lifecycle action holds it: no pause
	if a := planTick(d, now2, nil, c, fakeLocks{"s1": true}.busy, veto); strings.Contains(kinds(a), "pause") {
		t.Fatal("paused a busy session")
	}
	// busy resets the clock
	report(l, now2, &Registry{Status: "busy"})
	planTick(d, now2, nil, c, none.busy, veto)
	if !l.IdleSince.IsZero() {
		t.Fatal("busy should reset the idle clock")
	}
	// background jobs are work
	report(l, now2, &Registry{Status: "idle", BgTasks: 1})
	planTick(d, now2, nil, c, none.busy, veto)
	if !l.IdleSince.IsZero() {
		t.Fatal("background jobs should reset the idle clock")
	}
	// switched off
	l.AutoPauseOff = true
	report(l, now, idle)
	planTick(d, now, nil, c, none.busy, veto)
	report(l, now2, idle)
	if a := planTick(d, now2, nil, c, none.busy, veto); strings.Contains(kinds(a), "pause") {
		t.Fatal("auto-pause off but paused")
	}
	// vetoed (a wakeup due soon)
	l.AutoPauseOff = false
	l.IdleSince = now
	if a := planTick(d, now2, nil, c, none.busy, func(string) bool { return true }); strings.Contains(kinds(a), "pause") {
		t.Fatal("vetoed but paused")
	}
	// paused sessions forget their clocks and their report
	l.IdleSince = now
	d.Sessions["s1"].State, d.Sessions["s1"].MachineID = "paused", ""
	planTick(d, now2, nil, c, none.busy, veto)
	if !l.IdleSince.IsZero() || l.Reg != nil {
		t.Fatal("paused session kept its clock or report")
	}
}

func TestOneShotDestroysOnce(t *testing.T) {
	now := time.Now()
	l := &Liveness{OneShot: true, AutoPauseOff: true}
	d := running("s1", l)
	report(l, now, &Registry{OneShotDone: true})
	no := func(string) bool { return false }
	if a := planTick(d, now, nil, defaultPilot, no, no); kinds(a) != "destroy" {
		t.Fatalf("got %s", kinds(a))
	}
	if a := planTick(d, now, nil, defaultPilot, no, no); kinds(a) != "" {
		t.Fatalf("second tick: %s", kinds(a))
	}
}

func TestStaleWaitingEscapeOnce(t *testing.T) {
	c, now := defaultPilot, time.Now()
	c.Attention = 1000 * time.Hour // keep the DMs out of this test
	l := &Liveness{}
	d := running("s1", l)
	no := func(string) bool { return false }
	w := &Registry{Status: "waiting", StatusUpdatedAt: 7}
	report(l, now, w)
	planTick(d, now, nil, c, no, no)
	later := now.Add(c.WaitingCancel)
	report(l, later, w)
	a := planTick(d, later, nil, c, no, no)
	if !strings.Contains(kinds(a), "escape") {
		t.Fatalf("got %s", kinds(a))
	}
	if a := planTick(d, later, nil, c, no, no); strings.Contains(kinds(a), "escape") {
		t.Fatal("escaped twice in one episode")
	}
	// refused before: backing off
	l.waiting.cancelled = false
	l.grantRetry = map[string]time.Time{"status": later.Add(time.Minute)}
	if a := planTick(d, later, nil, c, no, no); strings.Contains(kinds(a), "escape") {
		t.Fatal("escaped while backing off from a refusal")
	}
}

func TestAttentionDM(t *testing.T) {
	c, now := defaultPilot, time.Now()
	l := &Liveness{}
	d := running("s1", l)
	d.Sessions["s1"].Label = "Build"
	no := func(string) bool { return false }
	idle := &Registry{Status: "idle", StatusUpdatedAt: 1}
	report(l, now, idle)
	planTick(d, now, nil, c, no, no)
	t5 := now.Add(c.Attention)
	report(l, t5, idle)
	a := planTick(d, t5, nil, c, no, no)
	if len(a) != 1 || a[0].Kind != "dm" || !strings.Contains(a[0].Text, "is idle") {
		t.Fatalf("got %+v", a)
	}
	if a := planTick(d, t5, nil, c, no, no); strings.Contains(kinds(a), "dm") {
		t.Fatal("pinged twice")
	}
	// muted idle ping
	l.settled, l.NotifyIdleOff = nil, true
	planTick(d, now, nil, c, no, no)
	if a := planTick(d, t5, nil, c, no, no); strings.Contains(kinds(a), "dm") {
		t.Fatal("idle ping is muted")
	}
	// no report for a while = dead, which still pings
	l.LastReport = now.Add(-time.Hour)
	l.settled = nil
	planTick(d, now, nil, c, no, no)
	a = planTick(d, t5, nil, c, no, no)
	if len(a) != 1 || !strings.Contains(a[0].Text, "isn't running a live Claude session") {
		t.Fatalf("dead: %+v", a)
	}
}

func TestStallNudgeRepeats(t *testing.T) {
	c, now := defaultPilot, time.Now()
	l := &Liveness{AutoPauseOff: true}
	d := running("s1", l)
	no := func(string) bool { return false }
	g := &Registry{Status: "idle", BgTasks: 2, StatusUpdatedAt: 3}
	report(l, now, g)
	planTick(d, now, nil, c, no, no)
	for i := 1; i <= 2; i++ {
		at := now.Add(time.Duration(i) * c.StallNudge)
		report(l, at, g)
		a := planTick(d, at, nil, c, no, no)
		found := false
		for _, x := range a {
			if x.Kind == "nudge" && strings.HasPrefix(x.Text, "Jarvis watchdog: this session has been idle for 15 min while 2 background jobs have") {
				found = true
			}
		}
		if !found {
			t.Fatalf("nudge %d: %+v", i, a)
		}
	}
	// a turn (statusUpdatedAt changed) restarts the clock
	g2 := &Registry{Status: "idle", BgTasks: 2, StatusUpdatedAt: 4}
	at := now.Add(3 * c.StallNudge)
	report(l, at, g2)
	if a := planTick(d, at, nil, c, no, no); strings.Contains(kinds(a), "nudge") {
		t.Fatal("nudged right after a turn")
	}
}

// the router never writes a login (Deyao, 2026-10-14); a session with a Claude account stuck on "Please run /login"
// gets "continue" once, after its pair is in step with its account's
func TestLoginContinueOnly(t *testing.T) {
	c, now := defaultPilot, time.Now()
	exp := now.Add(time.Hour).UnixMilli()
	stored := map[string]int64{"claude-a": exp, "claude-b": now.Add(-time.Minute).UnixMilli()}
	l := &Liveness{AutoPauseOff: true}
	d := running("s1", l)
	d.Sessions["s1"].ClaudeAccount = "claude-a"
	no := func(string) bool { return false }
	// behind the shared pair: nothing (the machine catches up by itself)
	report(l, now, &Registry{Status: "busy", CredsExpiresAt: exp - 1})
	if a := planTick(d, now, stored, c, no, no); strings.Contains(kinds(a), "login") {
		t.Fatalf("a login action for a session behind: %+v", a)
	}
	// stuck while still behind: wait for its pair
	report(l, now, &Registry{Status: "idle", CredsExpiresAt: 0, AuthFailed: "u1"})
	if a := planTick(d, now, stored, c, no, no); strings.Contains(kinds(a), "login") {
		t.Fatalf("continue before the pair caught up: %+v", a)
	}
	// in step and stuck: "continue", once per error
	report(l, now, &Registry{Status: "idle", CredsExpiresAt: exp, AuthFailed: "u1"})
	a := planTick(d, now, stored, c, no, no)
	if len(a) != 1 || a[0].Kind != "login" || a[0].Repair != "u1" {
		t.Fatalf("continue: %+v", a)
	}
	l.loginBusy = false
	if a := planTick(d, now.Add(time.Hour), stored, c, no, no); strings.Contains(kinds(a), "login") {
		t.Fatal("continued the same error twice")
	}
	// its account's pair itself expired: nothing
	report(l, now, &Registry{Status: "idle", CredsExpiresAt: exp, AuthFailed: "u2"})
	d.Sessions["s1"].ClaudeAccount = "claude-b"
	if a := planTick(d, now, stored, c, no, no); strings.Contains(kinds(a), "login") {
		t.Fatal("acted on an expired account pair")
	}
	// no Claude account: no login at all, nothing to continue
	l2 := &Liveness{AutoPauseOff: true}
	d2 := running("s2", l2)
	report(l2, now, &Registry{Status: "idle", CredsExpiresAt: exp, AuthFailed: "u3"})
	if a := planTick(d2, now, stored, c, no, no); strings.Contains(kinds(a), "login") {
		t.Fatalf("a session without a Claude account: %+v", a)
	}
}

func TestDowngradeOnceAndDialog(t *testing.T) {
	c, now := defaultPilot, time.Now()
	c.Attention = 1000 * time.Hour
	l := &Liveness{AutoPauseOff: true}
	d := running("s1", l)
	no := func(string) bool { return false }
	ev := []Refusal{{Kind: "refusal", At: now.UnixMilli(), UUID: "u1", Model: "Opus 5.5"}}
	report(l, now, &Registry{Status: "busy", Refusals: ev})
	a := planTick(d, now, nil, c, no, no)
	if len(a) != 1 || !strings.Contains(a[0].Text, "safeguards flagged") {
		t.Fatalf("got %+v", a)
	}
	if a := planTick(d, now, nil, c, no, no); len(a) != 0 {
		t.Fatal("reported twice")
	}
	// an old event (before the lookback) isn't reported
	l2 := &Liveness{AutoPauseOff: true}
	d2 := running("s2", l2)
	report(l2, now, &Registry{Status: "busy", Refusals: []Refusal{{Kind: "refusal", At: routerStarted.Add(-time.Hour).UnixMilli()}}})
	if a := planTick(d2, now, nil, c, no, no); len(a) != 0 {
		t.Fatal("reported an old refusal")
	}
	// waiting: the pane is checked once per waiting episode
	report(l2, now, &Registry{Status: "waiting", StatusUpdatedAt: 9})
	if a := planTick(d2, now, nil, c, no, no); kinds(a) != "dialog" {
		t.Fatalf("dialog check: %s", kinds(a))
	}
	if a := planTick(d2, now, nil, c, no, no); kinds(a) != "" {
		t.Fatal("checked the pane twice")
	}
	if !promptOnScreen("\x1b[1mOpus 5.5's Safeguards flagged\x1b[0m this message") {
		t.Fatal("promptOnScreen")
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func TestToggleRoutesAndView(t *testing.T) {
	st, err := LoadState(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	r := NewRouter(Config{}, st, nil, Policy{})
	mux := http.NewServeMux()
	r.registerAutopilot(func(p string, fn http.HandlerFunc) { mux.HandleFunc(p, fn) },
		func(p string, fn func(http.ResponseWriter, *http.Request, string, []byte)) {})
	st.Do(func(d *persisted) {
		d.Sessions["s1"] = &Session{ID: "s1", State: "started", MachineID: "m1", Live: &Liveness{IdleSince: time.Now()}}
	})
	call := func(path, body string) int {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest("POST", path, strings.NewReader(body)))
		return w.Code
	}
	if c := call("/api/sessions/s1/auto-pause", `{"on":false}`); c != 200 {
		t.Fatal(c)
	}
	if c := call("/api/sessions/s1/notify-idle", `{"enabled":false}`); c != 200 {
		t.Fatal(c)
	}
	if c := call("/api/sessions/nope/auto-pause", `{"on":true}`); c != 404 {
		t.Fatal(c)
	}
	st.Do(func(d *persisted) {
		s := d.Sessions["s1"]
		if !s.Live.AutoPauseOff || !s.Live.NotifyIdleOff || !s.Live.IdleSince.IsZero() {
			t.Fatalf("%+v", s.Live)
		}
		s.Live.AutoPauseOff = false
		s.Live.IdleSince = time.Now().Add(-10 * time.Minute)
		s.Live.Reg, s.Live.LastReport = &Registry{Status: "idle", AiTitle: "T"}, time.Now()
		v := sessionView(s, d)
		ms, ok := v["pauseInMs"].(int64)
		if v["autoPause"] != "on" || v["notifyIdle"] != "off" || v["aiTitle"] != "T" || !ok || ms < 49*60*1000 || ms > 50*60*1000 {
			t.Fatalf("view: %v", v)
		}
	})
}

func TestOneShotEnv(t *testing.T) {
	on := false
	s := &Session{Live: newLiveness(NewSession{OneShot: true})}
	e := map[string]string{}
	liveEnv(s, e)
	if e["SESSION_ONE_SHOT"] != "1" || !s.Live.AutoPauseOff {
		t.Fatal(e, s.Live)
	}
	if l := newLiveness(NewSession{AutoPause: &on}); !l.AutoPauseOff || l.OneShot {
		t.Fatal(l)
	}
	if l := newLiveness(NewSession{}); l.AutoPauseOff {
		t.Fatal("auto-pause is on by default")
	}
}

func TestAttentionDMNamesTheAppTitle(t *testing.T) {
	c, now := defaultPilot, time.Now()
	l := &Liveness{}
	d := running("s1", l)
	d.Sessions["s1"].AppTitle = "Bilingual Japanese news"
	no := func(string) bool { return false }
	idle := &Registry{Status: "idle", StatusUpdatedAt: 1, LiveName: "workspace-c1", NameSource: "derived"}
	report(l, now, idle)
	planTick(d, now, nil, c, no, no)
	report(l, now.Add(c.Attention), idle)
	a := planTick(d, now.Add(c.Attention), nil, c, no, no)
	if len(a) != 1 || !strings.Contains(a[0].Text, "“Bilingual Japanese news”") {
		t.Fatalf("got %+v", a)
	}
	if n := sessionName(&Session{ID: "s2"}, idle); n != "workspace-c1" {
		t.Fatalf("with nothing else the derived name still beats the id, got %q", n)
	}
}

func TestAttentionDMNotRepeatedAfterRestart(t *testing.T) {
	c, now := defaultPilot, time.Now()
	l := &Liveness{}
	d := running("s1", l)
	no := func(string) bool { return false }
	idle := &Registry{Status: "idle", StatusUpdatedAt: 7}
	report(l, now, idle)
	planTick(d, now, nil, c, no, no)
	report(l, now.Add(c.Attention), idle)
	if a := planTick(d, now.Add(c.Attention), nil, c, no, no); !strings.Contains(kinds(a), "dm") {
		t.Fatalf("no first ping: %+v", a)
	}
	// a router restart: only the persisted fields survive
	l2 := &Liveness{AttentionSent: l.AttentionSent}
	d2 := running("s1", l2)
	for _, at := range []time.Time{now.Add(2 * c.Attention), now.Add(4 * c.Attention)} {
		report(l2, at, idle)
		if a := planTick(d2, at, nil, c, no, no); strings.Contains(kinds(a), "dm") {
			t.Fatalf("same idle episode pinged again after a restart: %+v", a)
		}
	}
	// a new turn that settles again is a new episode
	report(l2, now.Add(5*c.Attention), &Registry{Status: "busy", StatusUpdatedAt: 8})
	planTick(d2, now.Add(5*c.Attention), nil, c, no, no)
	idle2 := &Registry{Status: "idle", StatusUpdatedAt: 9}
	report(l2, now.Add(6*c.Attention), idle2)
	planTick(d2, now.Add(6*c.Attention), nil, c, no, no)
	report(l2, now.Add(7*c.Attention), idle2)
	if a := planTick(d2, now.Add(7*c.Attention), nil, c, no, no); !strings.Contains(kinds(a), "dm") {
		t.Fatalf("a new idle episode wasn't pinged: %+v", a)
	}
}

func TestAutoPauseClockSurvivesRestart(t *testing.T) {
	c, now := defaultPilot, time.Now()
	no := func(string) bool { return false }
	l := &Liveness{}
	d := running("s1", l)
	idle := &Registry{Status: "idle", StatusUpdatedAt: 3}
	report(l, now, idle)
	planTick(d, now, nil, c, no, no)
	// restarts every few minutes: only the persisted fields survive each one
	for at := now; at.Before(now.Add(c.IdlePause)); at = at.Add(10 * time.Minute) {
		l = &Liveness{IdleSince: l.IdleSince, IdleStatusAt: l.IdleStatusAt, AttentionSent: l.AttentionSent}
		d = running("s1", l)
		report(l, at, idle)
		if strings.Contains(kinds(planTick(d, at, nil, c, no, no)), "pause") {
			t.Fatal("paused early")
		}
	}
	report(l, now.Add(c.IdlePause), idle)
	if !strings.Contains(kinds(planTick(d, now.Add(c.IdlePause), nil, c, no, no)), "pause") {
		t.Fatal("an hour idle across restarts didn't pause")
	}
	// a turn the router never saw (busy and idle again between reports) restarts the hour
	l2 := &Liveness{IdleSince: now.Add(-2 * c.IdlePause), IdleStatusAt: 3}
	d2 := running("s1", l2)
	report(l2, now, &Registry{Status: "idle", StatusUpdatedAt: 4})
	if strings.Contains(kinds(planTick(d2, now, nil, c, no, no)), "pause") {
		t.Fatal("paused right after an unseen turn")
	}
}

// a "status" refusal from a waiting episode stops showing once the session is no longer waiting
func TestStatusRefusalClearsAfterWaiting(t *testing.T) {
	c, now := defaultPilot, time.Now()
	c.Attention = 1000 * time.Hour
	l := &Liveness{AutoPauseOff: true}
	d := running("s1", l)
	no := func(string) bool { return false }
	report(l, now, &Registry{Status: "waiting", StatusUpdatedAt: 3})
	planTick(d, now, nil, c, no, no)
	l.NeedsGrant, l.grantRetry = "status", map[string]time.Time{"status": now.Add(time.Hour)}
	planTick(d, now, nil, c, no, no)
	if l.NeedsGrant != "status" {
		t.Fatal("cleared while still waiting")
	}
	report(l, now, &Registry{Status: "busy", StatusUpdatedAt: 4})
	planTick(d, now, nil, c, no, no)
	if l.NeedsGrant != "" || !l.mayExec("status", now) {
		t.Fatalf("still offered: %q", l.NeedsGrant)
	}
	// another holder's refusal stays
	l.NeedsGrant = "archive"
	planTick(d, now, nil, c, no, no)
	if l.NeedsGrant != "archive" {
		t.Fatal("cleared another holder's refusal")
	}
}

// the stall watchdog's 15 minutes survive router restarts (frequent deploys used to restart them, so no nudge came)
func TestStallClockSurvivesRestart(t *testing.T) {
	c, now := defaultPilot, time.Now()
	c.Attention = 1000 * time.Hour
	no := func(string) bool { return false }
	l := &Liveness{AutoPauseOff: true}
	d := running("s1", l)
	stuck := &Registry{Status: "idle", BgTasks: 1, StatusUpdatedAt: 5}
	report(l, now, stuck)
	planTick(d, now, nil, c, no, no)
	for at := now.Add(5 * time.Minute); at.Before(now.Add(c.StallNudge)); at = at.Add(5 * time.Minute) {
		l = &Liveness{AutoPauseOff: true, Stall: l.Stall} // a restart: only the persisted fields survive
		d = running("s1", l)
		report(l, at, stuck)
		if strings.Contains(kinds(planTick(d, at, nil, c, no, no)), "nudge") {
			t.Fatal("nudged early")
		}
	}
	at := now.Add(c.StallNudge)
	report(l, at, stuck)
	if !strings.Contains(kinds(planTick(d, at, nil, c, no, no)), "nudge") {
		t.Fatal("15 min stalled across restarts didn't nudge")
	}
}

// Claude Code keeps "busy" while background jobs run after the turn: the pushed screen tells a running turn apart
func TestStallNudgeWhileBusyWithJobs(t *testing.T) {
	c, now := defaultPilot, time.Now()
	c.Attention = 1000 * time.Hour
	no := func(string) bool { return false }
	l := &Liveness{AutoPauseOff: true}
	d := running("s1", l)
	busy := &Registry{Status: "busy", BgTasks: 10, StatusUpdatedAt: 9}
	idleScreen := "────── title ─\n❯ \n──────\n  ⏵⏵ bypass permissions on\n  ◯ general-purpose (+1) 8h 9m · ↓ 391k tokens\n"
	turnScreen := "\x1b[33m✢\x1b[0m Unfurling… (22s · thought for 12s)\n  ⎿  Tip\n❯ \n"
	if !turnOnScreen(turnScreen) || turnOnScreen(idleScreen) || turnOnScreen("✻ Worked for 3m 2s\n❯ \n") {
		t.Fatal("turnOnScreen")
	}
	at := func(m int) time.Time { return now.Add(time.Duration(m) * time.Minute) }
	push := func(m int, sc string) { l.screen = &pushedScreen{snap: TermSnap{Screen: sc}, at: at(m)} }
	push(0, idleScreen)
	report(l, now, busy)
	planTick(d, now, nil, c, no, no)
	push(15, idleScreen)
	report(l, at(15), busy)
	if !strings.Contains(kinds(planTick(d, at(15), nil, c, no, no)), "nudge") {
		t.Fatal("busy with jobs and no turn on screen for 15 min: no nudge")
	}
	// a turn running restarts the clock
	push(20, turnScreen)
	report(l, at(20), busy)
	planTick(d, at(20), nil, c, no, no)
	if l.Stall != nil {
		t.Fatal("a running turn kept the clock")
	}
	// no fresh screen (a router restart): the clock is kept, nothing decided
	push(21, idleScreen)
	report(l, at(21), busy)
	planTick(d, at(21), nil, c, no, no)
	kept := l.Stall
	l.screen = nil
	report(l, at(22), busy)
	planTick(d, at(22), nil, c, no, no)
	if l.Stall != kept || kept == nil {
		t.Fatal("no screen dropped the clock")
	}
}

// a booted machine whose Claude never came up (2026-10-20: Claude Code stuck on its "Settings Error" prompt) fails
// after HarnessUp with what its screen shows; a host that came up, a busy session or a router-restart without the
// clock are left alone
func TestHarnessNeverCameUp(t *testing.T) {
	c, now := defaultPilot, time.Now()
	c.Attention = 1000 * time.Hour
	l := &Liveness{}
	d := running("s1", l)
	s := d.Sessions["s1"]
	s.Booted = "m1"
	no := func(string) bool { return false }
	report(l, now, nil) // the machine reports, no Claude host in the registry
	l.BootedAt = now
	l.screen = &pushedScreen{snap: TermSnap{Screen: "\x1b[1mSettings Error\x1b[0m\n\n /etc/claude-code/managed-settings.json\n   └ Settings file could not be read: EACCES: permission denied, stat\n\n ❯ 1. Fix with Claude\n   2. Exit and fix manually\n   3. Continue without these settings\n"}, at: now}
	if a := planTick(d, now.Add(c.HarnessUp-time.Second), nil, c, no, no); strings.Contains(kinds(a), "harness-stuck") {
		t.Fatal("failed before HarnessUp")
	}
	if a := planTick(d, now.Add(c.HarnessUp), nil, c, fakeLocks{"s1": true}.busy, no); strings.Contains(kinds(a), "harness-stuck") {
		t.Fatal("failed a session a lifecycle action holds")
	}
	a := planTick(d, now.Add(c.HarnessUp), nil, c, no, no)
	if len(a) != 1 || a[0].Kind != "harness-stuck" || a[0].Machine != "m1" {
		t.Fatalf("got %+v", a)
	}
	for _, want := range []string{"didn't come up within 4 min", "Settings Error", "EACCES: permission denied", "3. Continue without these settings", "Resume starts it again"} {
		if !strings.Contains(a[0].Text, want) {
			t.Fatalf("%q lacks %q", a[0].Text, want)
		}
	}
	// the router fails it: state failed with the reason, once
	r := newTestRouter(t)
	r.st.Do(func(p *persisted) {
		p.Sessions["s1"] = &Session{ID: "s1", State: "started", MachineID: "m1", Booted: "m1", Harness: "claude", Live: &Liveness{}}
	})
	r.harnessStuck(a[0])
	var st, er string
	r.st.Do(func(p *persisted) { st, er = p.Sessions["s1"].State, p.Sessions["s1"].Error })
	if st != "failed" || !strings.Contains(er, "Settings Error") {
		t.Fatalf("state %q error %q", st, er)
	}
	// a host that came up: nothing
	l2 := &Liveness{BootedAt: now, HostUp: "m1"}
	d2 := running("s2", l2)
	d2.Sessions["s2"].Booted = "m1"
	report(l2, now, &Registry{Status: "busy"})
	if a := planTick(d2, now.Add(time.Hour), nil, c, no, no); strings.Contains(kinds(a), "harness-stuck") {
		t.Fatal("failed a session whose host came up")
	}
	// another harness, or no boot clock (booted under a router from before the check): nothing
	l3 := &Liveness{}
	d3 := running("s3", l3)
	d3.Sessions["s3"].Booted = "m1"
	report(l3, now, nil)
	if a := planTick(d3, now.Add(time.Hour), nil, c, no, no); strings.Contains(kinds(a), "harness-stuck") {
		t.Fatal("failed a session with no boot clock")
	}
	l3.BootedAt = now
	d3.Sessions["s3"].Harness = "opencode"
	if a := planTick(d3, now.Add(time.Hour), nil, c, no, no); strings.Contains(kinds(a), "harness-stuck") {
		t.Fatal("failed another harness")
	}
}

// /m/status keeps the harness check's clock: the boot time of the machine, and whether its host came up
func TestStatusSetsHarnessClock(t *testing.T) {
	r := newTestRouter(t)
	addSession(r, "s1", "started", "m1", false)
	m := newTestMachine(r, "m1")
	post := func(raw string) {
		t.Helper()
		if code, out := m.do(t, r.MachineHandler(), "POST", "/m/status", jsonString(map[string]string{"raw": raw})); code != 200 {
			t.Fatalf("status: %d %v", code, out)
		}
	}
	post("")
	var l Liveness
	r.st.Do(func(p *persisted) { l = *p.Sessions["s1"].Live })
	if l.BootedAt.IsZero() || l.HostUp != "" {
		t.Fatalf("after an empty report: %+v", l)
	}
	first := l.BootedAt
	post(sampleRaw)
	r.st.Do(func(p *persisted) { l = *p.Sessions["s1"].Live })
	if l.HostUp != "m1" || !l.BootedAt.Equal(first) {
		t.Fatalf("after a host: %+v", l)
	}
}

// a session the harness check failed resumes on the newest image when its own is older; any other failure, or the
// newest image itself, resumes as it is
func TestHarnessRetryUpgrade(t *testing.T) {
	cert := &Doc{Payload: `{"machine":{"id":"m1","image":"ghcr.io/de0ch/jarvis4-session@sha256:aaa"}}`}
	newest := "ghcr.io/de0ch/jarvis4-session:sha-1@sha256:bbb"
	s := Session{State: "failed", Cert: cert, StuckImage: "ghcr.io/de0ch/jarvis4-session@sha256:aaa"}
	if !harnessRetryUpgrade(s, newest) {
		t.Fatal("not upgraded")
	}
	s.State = "paused" // a resume-upgrade nobody approved: still the stuck image
	if !harnessRetryUpgrade(s, newest) {
		t.Fatal("not upgraded after a lapsed approval")
	}
	if harnessRetryUpgrade(s, "ghcr.io/de0ch/jarvis4-session:sha-0@sha256:aaa") {
		t.Fatal("upgraded onto its own image")
	}
	s.StuckImage = ""
	if harnessRetryUpgrade(s, newest) {
		t.Fatal("upgraded with no mark")
	}
	// the router marks it when it fails the session, and a host that comes up clears it
	r := newTestRouter(t)
	addSession(r, "s1", "started", "m1", false)
	r.st.Do(func(p *persisted) { p.Sessions["s1"].Cert, p.Sessions["s1"].Booted = cert, "m1" })
	r.harnessStuck(pilotAction{Kind: "harness-stuck", Session: "s1", Machine: "m1", Text: harnessStuckText(time.Minute, "")})
	var got Session
	r.st.Do(func(p *persisted) { got = *p.Sessions["s1"] })
	if got.State != "failed" || got.StuckImage != "ghcr.io/de0ch/jarvis4-session@sha256:aaa" {
		t.Fatalf("%+v", got)
	}
	r.st.Do(func(p *persisted) { p.Sessions["s1"].State = "started" })
	m := newTestMachine(r, "m1")
	m.do(t, r.MachineHandler(), "POST", "/m/status", jsonString(map[string]string{"raw": sampleRaw}))
	r.st.Do(func(p *persisted) { got = *p.Sessions["s1"] })
	if got.StuckImage != "" {
		t.Fatal("a host that came up kept the mark")
	}
}
