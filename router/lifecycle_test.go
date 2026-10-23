package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func supPush(t *testing.T, r *Router, m testMachine, lines ...string) int {
	t.Helper()
	ls := []map[string]string{}
	for _, l := range lines {
		ls = append(ls, map[string]string{"at": time.Now().UTC().Format(time.RFC3339Nano), "text": l})
	}
	code, _ := m.do(t, r.MachineHandler(), "POST", "/m/supervisor-log", jsonString(map[string]any{"lines": ls}))
	return code
}

// the machine pushes its lines; the app reads them in the session's events, after a cursor; a machine of no session
// is refused
func TestSupervisorLogPushAndRead(t *testing.T) {
	r := newTestRouter(t)
	addSession(r, "sA", "started", "mA", false)
	m := newTestMachine(r, "mA")
	if c := supPush(t, r, m, "supervisor started (oom_score_adj -1000)", "guard: exec allowed"); c != 200 {
		t.Fatal(c)
	}
	if c := supPush(t, r, m, strings.Repeat("x", 3000)); c != 200 {
		t.Fatal(c)
	}
	es, next, v := eventsOf(t, r, "sA", "")
	if len(es) != 3 || v["machine"] != "mA" || next != "3.0" {
		t.Fatalf("%v", v)
	}
	if l := es[2]; len(l["text"].(string)) > supLogMaxLine+4 || l["machine"] != "mA" || l["source"] != "supervisor" || l["key"] != "s3" {
		t.Fatal("a long line wasn't clipped")
	}
	es, _, _ = eventsOf(t, r, "sA", "2.0")
	if len(es) != 1 || es[0]["key"] != "s3" {
		t.Fatalf("after: %v", es)
	}
	stray := newTestMachine(r, "mX") // started by the core, but no session's
	if c := supPush(t, r, stray, "hello"); c != 404 {
		t.Fatalf("a machine of no session: %d", c)
	}
	too := make([]string, supLogMaxLines+1)
	if c := supPush(t, r, m, too...); c != 400 {
		t.Fatalf("too many lines: %d", c)
	}
	// a paused session keeps its log
	r.st.Do(func(d *persisted) { d.Sessions["sA"].State, d.Sessions["sA"].MachineID = "paused", "" })
	if es, _, _ := eventsOf(t, r, "sA", ""); len(es) != 3 {
		t.Fatalf("paused: %v", es)
	}
	// the seq goes on after a router restart (read back from the file)
	r2 := NewRouter(r.cfg, r.st, nil, Policy{})
	r2.st.Do(func(d *persisted) { d.Sessions["sA"].MachineID = "mA" })
	if err := r2.appendSupLog("sA", "mA", []SupLine{{At: nowText(), Text: "after restart"}}); err != nil {
		t.Fatal(err)
	}
	if es, next, _ := eventsOf(t, r2, "sA", ""); len(es) != 4 || next != "4.0" {
		t.Fatalf("%v %s", es, next)
	}
}

// past the cap the file keeps its newer half and says so
func TestSupervisorLogCap(t *testing.T) {
	r := newTestRouter(t)
	addSession(r, "sA", "started", "mA", false)
	old := supLogMaxFile
	supLogMaxFile = 4000
	t.Cleanup(func() { supLogMaxFile = old })
	for i := 0; i < 100; i++ {
		r.appendSupLog("sA", "mA", []SupLine{{At: nowText(), Text: fmt.Sprintf("line %03d", i)}})
	}
	if n := r.st.LogBytes("sA", logSupervisor); n > 4000+200 {
		t.Fatalf("log %d bytes", n)
	}
	ls := r.readSupLog("sA")
	if !strings.Contains(ls[0].Text, "oldest lines were dropped") || ls[len(ls)-1].Text != "line 099" {
		t.Fatalf("first %q last %q", ls[0].Text, ls[len(ls)-1].Text)
	}
	for i := 1; i < len(ls); i++ {
		if ls[i].Seq <= ls[i-1].Seq {
			t.Fatal("seq not increasing after a cut")
		}
	}
}

// lcFakeFly: events and logs per machine, as Fly answers them (events repeat on every poll)
type lcFakeFly struct {
	mu     sync.Mutex
	events map[string][]flyEvent
	logs   map[string][]flyLogLine
	calls  int
	refuse bool
}

func useFakeFly(t *testing.T, r *Router) *lcFakeFly {
	f := &lcFakeFly{events: map[string][]flyEvent{}, logs: map[string][]flyLogLine{}}
	r.lc.flyEvents = func(m string) ([]flyEvent, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.calls++
		return append([]flyEvent{}, f.events[m]...), nil
	}
	r.lc.flyLogs = func(m, next string) ([]flyLogLine, string, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.refuse {
			return nil, next, &flyLogsRefused{403}
		}
		ls := f.logs[m]
		i := 0
		fmt.Sscan(next, &i)
		return append([]flyLogLine{}, ls[i:]...), fmt.Sprint(len(ls)), nil
	}
	r.lc.flyOn = func() bool { return true }
	r.lc.pollEvery, r.lc.tail = 20*time.Millisecond, 100*time.Millisecond
	return f
}

func (f *lcFakeFly) event(m, typ, status string, at time.Time) {
	f.mu.Lock()
	f.events[m] = append(f.events[m], flyEvent{Type: typ, Status: status, Source: "flyd", Timestamp: at.UnixMilli()})
	f.mu.Unlock()
}

func (f *lcFakeFly) log(m, provider, msg string, at time.Time) {
	f.mu.Lock()
	f.logs[m] = append(f.logs[m], flyLogLine{ID: fmt.Sprint(len(f.logs[m])), Timestamp: at.UTC().Format(time.RFC3339Nano), Message: msg, Provider: provider})
	f.mu.Unlock()
}

// eventsOf: GET …/events (after: a cursor, "" for the newest)
func eventsOf(t *testing.T, r *Router, session, after string, q ...string) ([]map[string]any, string, map[string]any) {
	t.Helper()
	target := "/api/sessions/" + session + "/events"
	if after != "" {
		target += "?after=" + after
	} else if len(q) > 0 {
		target += "?" + q[0]
	}
	code, v := appDo(t, r, "GET", target, "")
	if code != 200 {
		t.Fatalf("events: %d %v", code, v)
	}
	es := []map[string]any{}
	for _, e := range v["events"].([]any) {
		es = append(es, e.(map[string]any))
	}
	next, _ := v["next"].(string)
	return es, next, v
}

// opEntries: the session's latest operation (its kind, state, running, from the stream's start and end marks) and
// the whole stream
func opEntries(t *testing.T, r *Router, session string) (map[string]any, []map[string]any) {
	t.Helper()
	es, _, v := eventsOf(t, r, session, "")
	op := map[string]any{"running": v["running"] != nil}
	for _, e := range es {
		switch e["mark"] {
		case "start":
			op = map[string]any{"running": v["running"] != nil, "kind": e["op"], "id": e["opId"], "state": "running"}
		case "end":
			if e["opId"] == op["id"] {
				op["state"], op["text"] = e["state"], e["text"]
			}
		}
	}
	if op["kind"] == nil {
		t.Fatalf("no operation in %v", es)
	}
	return op, es
}

func texts(es []map[string]any) string {
	var b strings.Builder
	for _, e := range es {
		fmt.Fprintf(&b, "%s|%s\n", e["source"], e["text"])
	}
	return b.String()
}

// a pause is one operation: the router's steps, Fly's events (each once, though Fly repeats them) and its platform
// log lines (not the app's stdout), and the supervisor's lines, in time order
func TestPauseRecordsItsLifecycleLog(t *testing.T) {
	rg := newRig(t)
	rg.r.cfg.NoAccess = true
	fly := useFakeFly(t, rg.r)
	rg.r.lc.tail = 10 * time.Second // the tail polls on after the pause (a loaded test box is slow)
	runningM2(rg, false)
	rg.writeSnapshot(t, "m2", rg.files)
	m := testMachine{"m2", rg.mkey.k}
	now := time.Now()
	fly.event("m2", "exit", "stopped", now)
	fly.event("m2", "destroy", "destroyed", now.Add(10*time.Millisecond))
	fly.log("m2", "runner", "Machine destroyed", now.Add(20*time.Millisecond))
	fly.log("m2", "app", "[jarvis2] stdout of the machine", now.Add(20*time.Millisecond))
	supPush(t, rg.r, m, "supervisor: snapshot committed")
	if err := rg.r.Pause("s1"); err != nil {
		t.Fatal(err)
	}
	if err := rg.r.waitState("s1", "paused", 5*time.Second); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "Fly read three times", func() bool { fly.mu.Lock(); defer fly.mu.Unlock(); return fly.calls >= 3 })
	op, es := opEntries(t, rg.r, "s1")
	all := texts(es)
	if op["kind"] != "pause" || op["state"] != "done" || op["running"] != false || !strings.HasPrefix(op["text"].(string), "Pause done after ") {
		t.Fatalf("op %v", op)
	}
	for _, want := range []string{"router|the machine's final snapshot is already here", "router|asked the core to destroy the machine on Fly",
		"router|the core confirmed the machine destroyed on Fly", "fly|Fly: machine exit → stopped (flyd)", "fly|Fly: machine destroy → destroyed (flyd)",
		"fly|Fly runner: Machine destroyed", "supervisor|supervisor: snapshot committed"} {
		if strings.Count(all, want) != 1 {
			t.Fatalf("%q %d times in\n%s", want, strings.Count(all, want), all)
		}
	}
	if strings.Contains(all, "stdout of the machine") {
		t.Fatal("the app's own stdout came in from Fly")
	}
	for i := 1; i < len(es); i++ {
		if parseAt(es[i]["at"].(string)).Before(parseAt(es[i-1]["at"].(string))) {
			t.Fatalf("not in time order:\n%s", all)
		}
	}
}

// Fly's logs API refusing the read-only token: one note, then events only
func TestFlyLogsRefusedFallsBackToEvents(t *testing.T) {
	r := newTestRouter(t)
	r.cfg.NoAccess = true
	fly := useFakeFly(t, r)
	fly.mu.Lock()
	fly.refuse = true
	fly.mu.Unlock()
	addSession(r, "sA", "started", "mA", false)
	h := r.lcBegin("sA", "pause")
	h.machine("mA")
	fly.event("mA", "start", "started", time.Now())
	time.Sleep(100 * time.Millisecond)
	h.end("done", "")
	time.Sleep(150 * time.Millisecond)
	_, es := opEntries(t, r, "sA")
	all := texts(es)
	if strings.Count(all, "HTTP 403 for the router's read-only token") != 1 || strings.Count(all, "start → started") != 1 {
		t.Fatalf("%s", all)
	}
}

// the dedupe: the same Fly event seen on every poll is kept once; an event from before the operation isn't
func TestFlyEventDedupe(t *testing.T) {
	r := newTestRouter(t)
	fly := useFakeFly(t, r)
	r.lc.pollEvery = time.Hour // polled by hand
	addSession(r, "sA", "started", "mA", false)
	fly.event("mA", "launch", "created", time.Now().Add(-time.Hour))
	h := r.lcBegin("sA", "boot")
	h.machine("mA")
	fly.event("mA", "start", "started", time.Now())
	for i := 0; i < 3; i++ {
		r.lcPollOnce(h.run)
	}
	_, entries := r.lcRead("sA")
	got := entries[h.run.op.ID]
	if len(got) != 1 || !strings.Contains(got[0].Text, "start → started") {
		t.Fatalf("%+v", got)
	}
}

// the merge: router and Fly entries and the supervisor lines of the op's machines in its window, by time
func TestLifecycleMergeOrder(t *testing.T) {
	r := newTestRouter(t)
	t0 := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	at := func(s int) string { return t0.Add(time.Duration(s) * time.Second).Format(time.RFC3339Nano) }
	op := LcOp{ID: "o", Started: at(0), Ended: at(10), State: "done", Machines: []string{"m1"}}
	own := []LcEntry{{At: at(1), Source: "router", Text: "r1"}, {At: at(5), Source: "fly", Text: "f5"}, {At: at(3), Source: "fly", Text: "f3"}}
	sup := []SupLine{{At: at(-60), Machine: "m1", Text: "too early"}, {At: at(-2), Machine: "m1", Text: "s-2"}, {At: at(4), Machine: "m1", Text: "s4"},
		{At: at(4), Machine: "m9", Text: "other machine"}, {At: at(35), Machine: "m1", Text: "s35"}, {At: at(60), Machine: "m1", Text: "too late"}}
	var got []string
	for _, e := range r.lcOpLog(op, own, sup) {
		got = append(got, e.Text)
	}
	if strings.Join(got, ",") != "s-2,r1,f3,s4,f5,s35" {
		t.Fatalf("%v", got)
	}
}

// Destroy: the supervisor log and every operation (the destroy's too, up to its upload) go into the archive, then
// out of the database
func TestDestroyArchivesTheLogs(t *testing.T) {
	rg := newRig(t)
	rg.r.cfg.NoAccess = true
	runningM2(rg, false)
	rg.writeSnapshot(t, "m2", rg.files)
	m := testMachine{"m2", rg.mkey.k}
	supPush(t, rg.r, m, "supervisor started")
	if err := rg.r.Destroy("s1"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the record", func() bool { return rg.r.record("s1") != nil && rg.r.record("s1").Archive != nil })
	files, _ := rg.dav.archive(t, rg.r.record("s1").Archive.File)
	sup := string(files["jarvis2/supervisor-log.jsonl"])
	if !strings.Contains(sup, "supervisor started") {
		t.Fatalf("supervisor log %q", sup)
	}
	var ops []map[string]any
	if err := json.Unmarshal(files["jarvis2/lifecycle.json"], &ops); err != nil || len(ops) != 1 || ops[0]["kind"] != "destroy" {
		t.Fatalf("lifecycle.json %v %v", err, ops)
	}
	b, _ := json.Marshal(ops[0]["entries"])
	if !strings.Contains(string(b), "uploading the archive") || !strings.Contains(string(b), "supervisor started") {
		t.Fatalf("entries %s", b)
	}
	if l, _ := rg.r.st.ReadLog("s1", logSupervisor); len(l) > 0 {
		t.Fatal("the supervisor log stayed in the database")
	}
	if l, _ := rg.r.st.ReadLog("s1", logLifecycle); len(l) > 0 {
		t.Fatal("the lifecycle log stayed in the database")
	}
}

// the supervisor's pause/resume of the Claude process: queued for the machine, and an operation of its own
func TestHarnessPauseQueuesTheCommand(t *testing.T) {
	r := newTestRouter(t)
	addSession(r, "sA", "started", "mA", false)
	if code, v := appDo(t, r, "POST", "/api/sessions/sA/harness", `{"action":"pause"}`); code != 200 || v["command"] != "pause-harness" {
		t.Fatalf("%d %v", code, v)
	}
	if c, ok := takeCmd(r, "mA"); !ok {
		t.Fatal("nothing queued")
	} else if c != "pause-harness" {
		t.Fatal(c)
	}
	if code, _ := appDo(t, r, "POST", "/api/sessions/sA/harness", `{"action":"stop"}`); code != 400 {
		t.Fatal(code)
	}
	appDo(t, r, "POST", "/api/sessions/sA/harness", `{"action":"resume"}`)
	if c, _ := waitCmd(r, "mA", 5*time.Second); c != "resume-harness" {
		t.Fatal(c)
	}
	op, es := opEntries(t, r, "sA")
	if op["kind"] != "harness-resume" || !strings.Contains(texts(es), "sent the supervisor resume-harness") {
		t.Fatalf("%v %v", op, es)
	}
	r.st.Do(func(d *persisted) { d.Sessions["sA"].MachineID = "" })
	if code, _ := appDo(t, r, "POST", "/api/sessions/sA/harness", `{"action":"pause"}`); code != 409 {
		t.Fatal(code)
	}
}

// an operation left open by a crash is closed as cut off at the next leader's start
func TestLifecycleCutOff(t *testing.T) {
	r := newTestRouter(t)
	r.cfg.NoAccess = true
	addSession(r, "sA", "started", "mA", false)
	r.lcBegin("sA", "pause")
	r2 := NewRouter(r.cfg, r.st, nil, Policy{})
	r2.lcCutOff()
	op, _ := opEntries(t, r2, "sA")
	if op["state"] != "cut off" || !strings.Contains(op["text"].(string), "the router restarted while it ran") {
		t.Fatalf("%v", op)
	}
}

// the session's one stream: the supervisor's lines from every machine and each operation's start, steps, Fly entries
// and end, all in time order; the cursor gives only what was written since, also an entry that sorts before others
func TestSessionEventsOneStream(t *testing.T) {
	r := newTestRouter(t)
	addSession(r, "sA", "started", "m1", false)
	t0 := time.Now().UTC().Add(-time.Minute)
	at := func(s int) string { return t0.Add(time.Duration(s) * time.Second).Format(time.RFC3339Nano) }
	r.appendSupLog("sA", "m0", []SupLine{{At: at(0), Text: "s0 old machine"}})
	op := LcOp{ID: "o1", Session: "sA", Kind: "pause", Started: at(1), State: "running", Machines: []string{"m1"}}
	r.lcWrite("sA", lcRec{Op: &op})
	r.lcWrite("sA", lcRec{OpID: "o1", Entry: &LcEntry{At: at(2), Source: "router", Text: "r2"}})
	r.appendSupLog("sA", "m1", []SupLine{{At: at(3), Text: "s3"}})
	r.lcWrite("sA", lcRec{OpID: "o1", Entry: &LcEntry{At: at(4), Source: "fly", Machine: "m1", Text: "f4"}})

	es, next, v := eventsOf(t, r, "sA", "")
	if got := strings.Join(keysTexts(es), ","); got != "s0 old machine,Pause started,r2,s3,f4" {
		t.Fatalf("%s", got)
	}
	if run, _ := v["running"].(map[string]any); run == nil || run["kind"] != "pause" || run["id"] != "o1" {
		t.Fatalf("running %v", v["running"])
	}
	if es[1]["mark"] != "start" || es[1]["op"] != "pause" || es[2]["op"] != "pause" || es[2]["source"] != "router" ||
		es[3]["source"] != "supervisor" || es[3]["op"] != nil || es[4]["source"] != "fly" || es[4]["machine"] != "m1" {
		t.Fatalf("%v", es)
	}
	if next != "2.3" {
		t.Fatalf("next %s", next)
	}
	// nothing new: nothing
	if es, n2, _ := eventsOf(t, r, "sA", next); len(es) != 0 || n2 != next {
		t.Fatalf("%v %s", es, n2)
	}
	// later: a Fly event read late (it happened before s3), a supervisor line, and the end
	r.lcWrite("sA", lcRec{OpID: "o1", Entry: &LcEntry{At: at(2) /* sorts before s3 */, Source: "fly", Text: "f2 late"}})
	r.appendSupLog("sA", "m1", []SupLine{{At: at(6), Text: "s6"}})
	op.State, op.Ended, op.Error = "failed", at(7), "the snapshot never came"
	r.lcWrite("sA", lcRec{Op: &op})
	es, next, v = eventsOf(t, r, "sA", next)
	if got := strings.Join(keysTexts(es), ","); got != "f2 late,s6,Pause failed after 6 s: the snapshot never came" {
		t.Fatalf("%s", got)
	}
	if v["running"] != nil || es[2]["mark"] != "end" || es[2]["state"] != "failed" || next != "3.5" {
		t.Fatalf("%v %s", v, next)
	}
	// the whole stream again, in time order, and the newest only with a limit
	es, _, _ = eventsOf(t, r, "sA", "")
	if got := strings.Join(keysTexts(es), ","); got != "s0 old machine,Pause started,r2,f2 late,s3,f4,s6,Pause failed after 6 s: the snapshot never came" {
		t.Fatalf("%s", got)
	}
	es, _, v = eventsOf(t, r, "sA", "", "limit=2")
	if got := strings.Join(keysTexts(es), ","); got != "s6,Pause failed after 6 s: the snapshot never came" || v["more"] != true {
		t.Fatalf("%s %v", got, v["more"])
	}
	// a backlog of supervisor lines comes limit at a time
	if es, _, _ := eventsOf(t, r, "sA", "0.5"); len(es) != 3 {
		t.Fatalf("%v", es)
	}
	if code, _ := appDo(t, r, "GET", "/api/sessions/sA/events?after=1.5&limit=1", ""); code != 200 {
		t.Fatal(code)
	}
	if _, v := appDo(t, r, "GET", "/api/sessions/sA/events?after=0.5&limit=1", ""); v["more"] != true || v["next"] != "1.5" {
		t.Fatalf("%v", v)
	}
	if code, _ := appDo(t, r, "GET", "/api/sessions/sA/events?after=nonsense", ""); code != 400 {
		t.Fatal(code)
	}
	if code, _ := appDo(t, r, "GET", "/api/sessions/nope/events", ""); code != 404 {
		t.Fatal(code)
	}
	// the old separate views are gone (no API answer: the web page's files)
	for _, p := range []string{"supervisor-log", "lifecycle", "lifecycle/o1"} {
		if _, v := appDo(t, r, "GET", "/api/sessions/sA/"+p, ""); len(v) != 0 {
			t.Fatalf("%s still answers", p)
		}
	}
}

func keysTexts(es []map[string]any) []string {
	out := []string{}
	for _, e := range es {
		out = append(out, e["text"].(string))
	}
	return out
}

// an operation stays current until its end record is written: whoever sees none running (a test's TempDir cleanup, the
// app) finds its end in the file and nothing of it still being written (TestAHandoverStartsTheNext… failed its TempDir
// cleanup under load; DECISIONS 213). The file lock held here stands for a slow write.
func TestAnOperationEndsOnceItsRecordIsWritten(t *testing.T) {
	r := newTestRouter(t)
	addSession(r, "sA", "started", "mA", false)
	op := r.lcBegin("sA", "boot")
	r.lc.file.Lock()
	ended := make(chan struct{})
	go func() { op.end("done", ""); close(ended) }()
	for i := 0; i < 50; i++ { // the old order dropped it from current at once, with its record still to write
		if r.lcCurrent("sA") == nil {
			r.lc.file.Unlock()
			t.Fatal("no running operation while its end record is still unwritten")
		}
		time.Sleep(2 * time.Millisecond)
	}
	r.lc.file.Unlock()
	<-ended
	if r.lcCurrent("sA") != nil {
		t.Fatal("the operation is still current after its end")
	}
	if o, _ := opEntries(t, r, "sA"); o["state"] != "done" {
		t.Fatalf("%v", o)
	}
}
