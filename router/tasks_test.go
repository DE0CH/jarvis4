package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---- templates ------------------------------------------------------------------------------------------

func TestParseTemplate(t *testing.T) {
	tm, err := parseTemplate("x", []byte(`{"title":"X","fields":[{"name":"a"},{"name":"s","type":"select","options":["p",{"value":"q","label":"Q","sub":"qq"}]},
		{"name":"k","type":"select","optionsFrom":"stores"}]}`), []string{"run.sh"})
	if err != nil {
		t.Fatal(err)
	}
	if tm.Run != "run.sh" || tm.TimeoutSeconds != 600 || tm.Size != "small" || tm.Fields[0].Type != "text" || tm.Fields[0].Label != "a" ||
		tm.Fields[1].Options[1].Label != "Q" || tm.Fields[1].Options[0].Label != "p" || tm.Fields[2].OptionsFrom != "stores" {
		t.Fatalf("%+v", tm)
	}
	p, err := parseTemplate("p", []byte(`{"title":"P"}`), []string{"prompt.md"})
	if err != nil || p.Prompt != "prompt.md" || p.Run != "" {
		t.Fatalf("%+v %v", p, err)
	}
	for _, c := range []struct{ name, spec string }{
		{"Bad", `{"title":"x"}`},
		{"x", `{}`},
		{"x", `{"title":"x","run":"other.py"}`},
		{"x", `{"title":"x","run":"run.sh","prompt":"prompt.md"}`},
		{"x", `{"title":"x","timeoutSeconds":5}`},
		{"x", `{"title":"x","size":"huge"}`},
		{"x", `{"title":"x","stores":["core"]}`},
		{"x", `{"title":"x","fields":[{"name":"a"},{"name":"a"}]}`},
		{"x", `{"title":"x","fields":[{"name":"a","type":"radio"}]}`},
		{"x", `{"title":"x","fields":[{"name":"a","type":"select"}]}`},
		{"x", `{"title":"x","fields":[{"name":"a","type":"select","optionsFrom":"environments"}]}`},
		{"x", `{"title":"x","fields":[{"name":"k","type":"select","optionsFrom":"stores","secretKeys":["AES_KEY"]}]}`},
	} {
		if _, err := parseTemplate(c.name, []byte(c.spec), []string{"run.sh", "prompt.md"}); err == nil && c.spec != `{"title":"x"}` {
			t.Errorf("accepted %s %s", c.name, c.spec)
		}
	}
	// run.sh and prompt.md both present, neither named: the script wins
	if x, err := parseTemplate("x", []byte(`{"title":"x"}`), []string{"run.sh", "prompt.md"}); err != nil || x.Run != "run.sh" {
		t.Fatalf("%+v %v", x, err)
	}
}

// the repo's own templates are all valid
func TestRepoTemplates(t *testing.T) {
	ts := readTemplates("../tasks")
	if len(ts) == 0 {
		t.Fatal("no templates in tasks/")
	}
	for _, tm := range ts {
		if tm.Error != "" {
			t.Errorf("%s: %s", tm.Name, tm.Error)
		}
	}
}

func TestCheckParamsAndStores(t *testing.T) {
	tm, _ := parseTemplate("x", []byte(`{"title":"X","stores":["base"],"fields":[
		{"name":"msg","required":true},{"name":"n","type":"number","default":3},{"name":"on","type":"checkbox"},
		{"name":"pick","type":"select","options":["a","b"],"default":"a"},
		{"name":"keys","type":"select","optionsFrom":"stores"},{"name":"more","type":"multiselect","optionsFrom":"stores"},
		{"name":"size","type":"select","optionsFrom":"sizes"}]}`), []string{"run.sh"})
	tm = withOptions(tm)
	if _, err := checkParams(tm, map[string]any{}); err == nil {
		t.Fatal("a required field passed empty")
	}
	p, err := checkParams(tm, map[string]any{"msg": "hi", "on": "true", "keys": "aes", "more": []any{"x", "x", "base"}, "size": "large", "junk": 1})
	if err != nil {
		t.Fatal(err)
	}
	if p["n"] != 3.0 || p["on"] != true || p["pick"] != "a" || p["junk"] != nil || len(p["more"].([]string)) != 2 {
		t.Fatalf("%v", p)
	}
	if got := lineStores(tm, p); strings.Join(got, ",") != "aes,base,x" {
		t.Fatalf("%v", got)
	}
	for _, in := range []map[string]any{
		{"msg": "x", "pick": "c"}, {"msg": "x", "n": "z"}, {"msg": "x", "keys": "Bad Name"}, {"msg": "x", "keys": "core"}, {"msg": "x", "size": "huge"},
	} {
		if _, err := checkParams(tm, in); err == nil {
			t.Errorf("accepted %v", in)
		}
	}
	if paramEnv([]string{"a", "b"}) != "a,b" || paramEnv(2.5) != "2.5" || paramEnv(true) != "true" || paramEnv(nil) != "" {
		t.Fatal("paramEnv")
	}
}

func TestDueSlot(t *testing.T) {
	now := time.Date(2026, 10, 9, 8, 30, 0, 0, time.UTC)
	s := &TaskSchedule{Time: "08:00", TZ: "UTC", Enabled: true, Since: now.Add(-48 * time.Hour).UnixMilli()}
	slot, ok := dueSlot(s, now)
	if !ok || !slot.Equal(time.Date(2026, 10, 9, 8, 0, 0, 0, time.UTC)) {
		t.Fatalf("%v %v", slot, ok)
	}
	s.LastSlot = slot.UnixMilli()
	if _, ok := dueSlot(s, now); ok {
		t.Fatal("fired the same slot twice")
	}
	s.LastSlot = 0
	s.Since = now.Add(-10 * time.Minute).UnixMilli() // made after the slot
	if _, ok := dueSlot(s, now); ok {
		t.Fatal("a schedule made after the slot fired it")
	}
	s.Since = 0
	if _, ok := dueSlot(s, now.Add(3*time.Hour)); ok {
		t.Fatal("a slot missed by more than the grace period fired")
	}
	s.Enabled = false
	if _, ok := dueSlot(s, now); ok {
		t.Fatal("a disabled schedule fired")
	}
	// a zone with DST: 08:00 London on a summer day is 07:00 UTC
	l := &TaskSchedule{Time: "08:00", TZ: "Europe/London", Enabled: true}
	if slot, ok := dueSlot(l, time.Date(2026, 7, 1, 7, 5, 0, 0, time.UTC)); !ok || slot.UTC().Hour() != 7 {
		t.Fatalf("%v %v", slot, ok)
	}
	if n, err := nextSlot(l, time.Date(2026, 7, 1, 7, 5, 0, 0, time.UTC)); err != nil || n.Day() != 2 {
		t.Fatalf("%v %v", n, err)
	}
}

// ---- the lifecycle, with the session flows faked ------------------------------------------------------

type fakeLine struct {
	mu    sync.Mutex
	calls []string
	r     *Router
	n     int
	fail  error // resume answers this
	// approve: the phone approved and the machine is up (started, a new machine id)
	approve func(id string)
	env     map[string]string // the last resume's machine env
}

func (f *fakeLine) log(s string) { f.mu.Lock(); f.calls = append(f.calls, s); f.mu.Unlock() }
func (f *fakeLine) got() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.Join(f.calls, " ")
}

// install: CreateSession makes a session waiting for approval; resume starts a machine; pause releases it
func (f *fakeLine) install(t *testing.T, sensitive bool) {
	old := taskOps
	oldKick := taskKick
	taskKick = func(*Router) {}
	t.Cleanup(func() { taskOps, taskKick = old, oldKick })
	taskOps.create = func(r *Router, in NewSession) (string, error) {
		id := "s" + randID()
		r.st.Do(func(d *persisted) {
			d.Sessions[id] = &Session{ID: id, State: "approval", Harness: in.Harness, Stores: in.Stores, Size: in.Size, Label: in.Label, RequestID: in.RequestID}
		})
		f.log("create:" + in.Harness + ":" + strings.Join(in.Stores, ","))
		return id, nil
	}
	cert, _ := json.Marshal(map[string]any{"line": "L", "sensitive": sensitive})
	f.approve = func(id string) {
		r := f.r
		f.n++
		m := "m" + string(rune('0'+f.n))
		r.st.Do(func(d *persisted) {
			s := d.Sessions[id]
			s.State, s.MachineID, s.Cert, s.Image = "started", m, &Doc{Payload: string(cert)}, "img@1"
			d.Machines[m] = id
		})
	}
	taskOps.resume = func(r *Router, id string, upgrade bool) error {
		if f.fail != nil {
			return f.fail
		}
		f.log("resume")
		var s Session
		r.st.Do(func(d *persisted) { s = *d.Sessions[id] })
		f.env = r.machineEnv(&s)
		f.approve(id)
		return nil
	}
	taskOps.pause = func(r *Router, id string) error {
		f.log("pause")
		r.st.Do(func(d *persisted) {
			if s := d.Sessions[id]; s != nil {
				s.State, s.MachineID = "paused", ""
			}
		})
		return nil
	}
	taskOps.destroy = func(r *Router, id string) error {
		f.log("destroy")
		r.st.Do(func(d *persisted) { delete(d.Sessions, id) })
		return nil
	}
	taskOps.reject = func(r *Router, a string) error {
		f.log("reject")
		r.st.Do(func(d *persisted) {
			if ap := d.Approvals[a]; ap != nil {
				delete(d.Sessions, ap.Session)
				delete(d.Approvals, a)
			}
		})
		return nil
	}
}

func newTaskRig(t *testing.T, sensitive bool) (*Router, *fakeLine) {
	t.Helper()
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "job"), 0o755)
	os.WriteFile(filepath.Join(dir, "job", "task.json"), []byte(`{"title":"Job","stores":["base"],"timeoutSeconds":60,"fields":[
		{"name":"msg","required":true},{"name":"key","type":"select","optionsFrom":"stores"}]}`), 0o644)
	os.WriteFile(filepath.Join(dir, "job", "run.sh"), []byte("echo hi\n"), 0o755)
	old := tasksDir
	tasksDir = dir
	t.Cleanup(func() { tasksDir = old })
	r := newTestRouter(t)
	f := &fakeLine{r: r}
	f.install(t, sensitive)
	return r, f
}

func (r *Router) instance(id string) TaskInstance {
	var i TaskInstance
	r.st.Do(func(d *persisted) {
		if x := tasksOf(d).Instances[id]; x != nil {
			i = *x
			i.Runs = nil
			for _, y := range x.Runs {
				c := *y
				i.Runs = append(i.Runs, &c)
			}
		}
	})
	return i
}

func (r *Router) sessionOf(id string) Session {
	var s Session
	r.st.Do(func(d *persisted) {
		if x := d.Sessions[id]; x != nil {
			s = *x
		}
	})
	return s
}

func TestTaskLifecycle(t *testing.T) {
	r, f := newTaskRig(t, true) // a sensitive line: no grant is ever needed
	dms := captureDM(t)
	code, out := appDo(t, r, "POST", "/api/tasks/instances", `{"template":"job","name":"Nightly","params":{"msg":"hello world","key":"aes"}}`)
	if code != 200 || out["state"] != "approval" {
		t.Fatalf("%d %v", code, out)
	}
	id := out["id"].(string)
	if f.got() != "create:task:job:aes,base" {
		t.Fatalf("%s", f.got())
	}
	inst := r.instance(id)
	// a run asked for while the phone hasn't approved waits, queued, for the approved line (dropped here again)
	if code, out := appDo(t, r, "POST", "/api/tasks/instances/"+id+"/run", `{}`); code != 200 || r.instance(id).Runs[0].Phase != "queued" {
		t.Fatalf("a run before the approval: %d %v", code, out)
	} else if err := r.StopRun(out["name"].(string)); err != nil {
		t.Fatal(err)
	}
	// the phone approves: the first machine boots with no run, reports ready, and is paused
	f.approve(inst.Session)
	m1 := r.sessionOf(inst.Session).MachineID
	if err := r.taskResult(m1, TaskResult{}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "paused after the ready boot", func() bool { return r.sessionOf(inst.Session).State == "paused" })
	if r.instance(id).ReadyAt == nil {
		t.Fatal("not marked ready")
	}
	// run now: queued, then the tick resumes the line with the run in its env
	code, out = appDo(t, r, "POST", "/api/tasks/instances/"+id+"/run", `{}`)
	if code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	runID := out["name"].(string)
	r.tasksTick(time.Now())
	if !strings.Contains(f.got(), "resume") || f.env["JARVIS2_TASK_RUN"] != runID || f.env["PARAM_MSG"] != "hello world" ||
		f.env["TASK_TRIGGER"] != "manual" || !strings.Contains(f.env["TASK_PARAMS"], `"key":"aes"`) || f.env["SESSION_PROMPT"] != "" {
		t.Fatalf("%s %v", f.got(), f.env)
	}
	r.tasksTick(time.Now())
	if x := r.instance(id).Runs[0]; x.Phase != "running" || x.StartedAt == nil {
		t.Fatalf("%+v", x)
	}
	// another machine can't report for it
	if err := r.taskResult("m-other", TaskResult{Run: runID}); err == nil {
		t.Fatal("a stranger reported")
	}
	m2 := r.sessionOf(inst.Session).MachineID
	if err := r.taskResult(m2, TaskResult{Run: runID, ExitCode: 0, Log: "line 1\nline 2\n", Output: "result"}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "paused after the run", func() bool { return r.sessionOf(inst.Session).State == "paused" })
	x := r.instance(id).Runs[0]
	if x.Phase != "succeeded" || *x.ExitCode != 0 || x.Tail != "line 1\nline 2" || x.Machine != m2 || x.Image != "img@1" {
		t.Fatalf("%+v", x)
	}
	code, out = appDo(t, r, "GET", "/api/tasks/runs/"+runID, "")
	if code != 200 || out["log"] != "line 1\nline 2\n" || out["output"] != "result" {
		t.Fatalf("%d %v", code, out)
	}
	if len(dms()) != 0 {
		t.Fatalf("a manual success DMed: %v", dms())
	}
	// overview
	code, out = appDo(t, r, "GET", "/api/tasks", "")
	if code != 200 || len(out["templates"].([]any)) != 1 || len(out["instances"].([]any)) != 1 {
		t.Fatalf("%d %v", code, out)
	}
	iv := out["instances"].([]any)[0].(map[string]any)
	if iv["state"] != "ready" || iv["lastRun"].(map[string]any)["phase"] != "succeeded" {
		t.Fatalf("%v", iv)
	}
	code, out = appDo(t, r, "GET", "/api/tasks/instances/"+id+"/runs", "")
	if code != 200 || len(out["runs"].([]any)) != 2 { // the run, and the one stopped before the approval
		t.Fatalf("%d %v", code, out)
	}
}

func makeReadyTask(t *testing.T, r *Router, f *fakeLine) (id, sid string) {
	t.Helper()
	v, err := r.CreateTask(instanceIn{Template: "job", Name: "T", Params: map[string]any{"msg": "m"}})
	if err != nil {
		t.Fatal(err)
	}
	id = v["id"].(string)
	sid = r.instance(id).Session
	f.approve(sid)
	if err := r.taskResult(r.sessionOf(sid).MachineID, TaskResult{}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "ready", func() bool { return r.sessionOf(sid).State == "paused" })
	return id, sid
}

func TestScheduledRunFailsAndDMs(t *testing.T) {
	r, f := newTaskRig(t, false)
	dms := captureDM(t)
	id, sid := makeReadyTask(t, r, f)
	now := time.Now().UTC()
	hhmm := now.Add(-time.Minute).Format("15:04")
	code, out := appDo(t, r, "POST", "/api/tasks/schedules", `{"instance":"`+id+`","time":"`+hhmm+`","tz":"UTC"}`)
	if code != 200 || out["nextAt"] == nil {
		t.Fatalf("%d %v", code, out)
	}
	// a new schedule never fires a slot already past (since = now): make it older
	r.st.Do(func(d *persisted) {
		for _, s := range tasksOf(d).Schedules {
			s.Since = now.Add(-time.Hour).UnixMilli()
		}
	})
	r.tasksTick(now) // fires: a queued run
	r.tasksTick(now) // starts it
	r.tasksTick(now) // and it's running
	i := r.instance(id)
	if len(i.Runs) != 1 || i.Runs[0].Trigger != "schedule" || i.Runs[0].Phase != "running" || f.env["TASK_TRIGGER"] != "schedule" {
		t.Fatalf("%+v", i.Runs)
	}
	r.tasksTick(now.Add(time.Minute)) // the same slot doesn't fire again
	if n := len(r.instance(id).Runs); n != 1 {
		t.Fatalf("%d runs", n)
	}
	if err := r.taskResult(r.sessionOf(sid).MachineID, TaskResult{Run: i.Runs[0].ID, ExitCode: 3, Log: "boom\n"}); err != nil {
		t.Fatal(err)
	}
	x := r.instance(id).Runs[0]
	if x.Phase != "failed" || x.Reason != "exit code 3" {
		t.Fatalf("%+v", x)
	}
	if len(dms()) != 1 || !strings.Contains(dms()[0], "Scheduled task “T” (daily "+hhmm+" UTC) failed — exit code 3") || !strings.Contains(dms()[0], "boom") {
		t.Fatalf("%v", dms())
	}
	waitFor(t, "paused", func() bool { return r.sessionOf(sid).State == "paused" })
}

func TestTimeoutLostAndResumeFailure(t *testing.T) {
	r, f := newTaskRig(t, false)
	dms := captureDM(t)
	id, sid := makeReadyTask(t, r, f)
	// no result long past the timeout: timed out, and the line is paused
	run, _ := r.StartRun(id, "schedule", "", nil, false)
	r.tasksTick(time.Now())
	r.tasksTick(time.Now())
	r.tasksTick(time.Now().Add(time.Hour))
	if x := r.instance(id).run(run.ID); x.Phase != "timedout" {
		t.Fatalf("%+v", x)
	}
	r.tasksTick(time.Now().Add(time.Hour))
	waitFor(t, "paused", func() bool { return r.sessionOf(sid).State == "paused" })
	// the session paused under a run that never reported (budget cap): lost
	run, _ = r.StartRun(id, "manual", "", nil, false)
	r.tasksTick(time.Now())
	r.tasksTick(time.Now())
	r.st.Do(func(d *persisted) { d.Sessions[sid].State, d.Sessions[sid].MachineID = "paused", "" })
	r.tasksTick(time.Now())
	if x := r.instance(id).run(run.ID); x.Phase != "lost" {
		t.Fatalf("%+v", x)
	}
	// a resume the core refuses: failed; a busy line: back in the queue
	f.fail = errors.New("store locked")
	run, _ = r.StartRun(id, "manual", "", nil, false)
	r.tasksTick(time.Now())
	if x := r.instance(id).run(run.ID); x.Phase != "failed" || !strings.Contains(x.Reason, "store locked") {
		t.Fatalf("%+v", x)
	}
	f.fail = errBusy
	run, _ = r.StartRun(id, "manual", "", nil, false)
	r.tasksTick(time.Now())
	if x := r.instance(id).run(run.ID); x.Phase != "queued" || r.instance(id).Active != "" {
		t.Fatalf("%+v", x)
	}
	f.fail = nil
	r.tasksTick(time.Now())
	if r.instance(id).Active != run.ID {
		t.Fatal("the requeued run didn't start")
	}
	if len(dms()) != 1 || !strings.Contains(dms()[0], "timed out") {
		t.Fatalf("%v", dms())
	}
}

func TestStopAndQueueLimit(t *testing.T) {
	r, f := newTaskRig(t, false)
	id, sid := makeReadyTask(t, r, f)
	a, _ := r.StartRun(id, "manual", "", nil, false)
	for k := 0; k < taskMaxQueued-1; k++ {
		if _, err := r.StartRun(id, "manual", "", nil, false); err != nil {
			t.Fatal(err)
		}
	}
	if code, _ := appDo(t, r, "POST", "/api/tasks/instances/"+id+"/run", `{}`); code != 409 {
		t.Fatalf("queue limit: %d", code)
	}
	r.tasksTick(time.Now()) // a starts
	if r.instance(id).Active != a.ID {
		t.Fatal("not started")
	}
	if code, _ := appDo(t, r, "POST", "/api/tasks/runs/"+a.ID+"/stop", ""); code != 200 {
		t.Fatal(code)
	}
	if x := r.instance(id).run(a.ID); x.Phase != "stopped" || r.instance(id).Active != "" {
		t.Fatalf("%+v", x)
	}
	// the machine's late report for the stopped run doesn't revive it; the line is paused
	r.taskResult(r.sessionOf(sid).MachineID, TaskResult{Run: a.ID})
	waitFor(t, "paused", func() bool { return r.sessionOf(sid).State == "paused" })
	if x := r.instance(id).run(a.ID); x.Phase != "stopped" {
		t.Fatalf("%+v", x)
	}
	if code, _ := appDo(t, r, "POST", "/api/tasks/runs/"+a.ID+"/stop", ""); code != 200 { // already over: done
		t.Fatal("a second stop refused")
	}
}

// A change of picked stores files the new line for the phone itself; the instance (name, schedules, runs) stays and
// the old line goes.
func TestEditOfStoresFilesANewLine(t *testing.T) {
	r, f := newTaskRig(t, false)
	id, sid := makeReadyTask(t, r, f)
	r.saveSchedule("", map[string]any{"instance": id, "time": "07:00"})
	code, out := appDo(t, r, "PUT", "/api/tasks/instances/"+id, `{"params":{"msg":"new","key":"aes"}}`)
	i := r.instance(id)
	if code != 200 || i.Session == sid || strings.Join(i.Stores, ",") != "aes,base" || out["state"] != "approval" {
		t.Fatalf("%d %v %+v", code, out, i)
	}
	doomed := false
	r.st.Do(func(d *persisted) { doomed = containsString(tasksOf(d).Doomed, sid) })
	if !doomed {
		t.Fatal("the old line wasn't let go")
	}
	n := 0
	r.st.Do(func(d *persisted) {
		for _, x := range tasksOf(d).Schedules {
			if x.Instance == id {
				n++
			}
		}
	})
	if n != 1 {
		t.Fatalf("schedules %d", n)
	}
}

// A run asked for on a line that is gone files a new line for the phone and waits for it, queued.
func TestARunOnAGoneLineFilesANewOne(t *testing.T) {
	r, f := newTaskRig(t, false)
	id, sid := makeReadyTask(t, r, f)
	r.st.Do(func(d *persisted) { delete(d.Sessions, sid) })
	run, err := r.StartRun(id, "manual", "", nil, false)
	i := r.instance(id)
	if err != nil || run.Phase != "queued" || i.Session == sid || i.Session == "" || r.sessionOf(i.Session).State != "approval" {
		t.Fatalf("%v %+v %+v", err, run, i)
	}
}

func TestEditKeepsStores(t *testing.T) {
	r, f := newTaskRig(t, false)
	id, sid := makeReadyTask(t, r, f)
	code, out := appDo(t, r, "PUT", "/api/tasks/instances/"+id, `{"name":"Renamed","params":{"msg":"new"},"size":"large"}`)
	if code != 200 || out["name"] != "Renamed" || out["params"].(map[string]any)["msg"] != "new" {
		t.Fatalf("%d %v", code, out)
	}
	if r.sessionOf(sid).Size != "large" {
		t.Fatal("size not passed to the line")
	}
	if code, _ := appDo(t, r, "POST", "/api/tasks/instances", `{"template":"job","name":"x","params":{"msg":"m"},"hide":["msg"]}`); code != 400 {
		t.Fatal("hidden values accepted")
	}
	if code, _ := appDo(t, r, "POST", "/api/tasks/instances", `{"template":"nope","name":"x"}`); code != 400 {
		t.Fatal("unknown template accepted")
	}
}

func TestDeleteTask(t *testing.T) {
	r, f := newTaskRig(t, false)
	// waiting for approval: the approval is dropped
	v, _ := r.CreateTask(instanceIn{Template: "job", Name: "A", Params: map[string]any{"msg": "m"}})
	pend := r.instance(v["id"].(string)).Session
	r.st.Do(func(d *persisted) { d.Approvals["ap1"] = &Approval{ID: "ap1", Kind: "new-session", Session: pend} })
	// a ready one with a schedule: its line is destroyed by the tick
	id, sid := makeReadyTask(t, r, f)
	r.saveSchedule("", map[string]any{"instance": id, "time": "07:00"})
	if code, _ := appDo(t, r, "DELETE", "/api/tasks/instances/"+v["id"].(string), ""); code != 200 {
		t.Fatal(code)
	}
	if code, _ := appDo(t, r, "DELETE", "/api/tasks/instances/"+id, ""); code != 200 {
		t.Fatal(code)
	}
	r.tasksTick(time.Now())
	if !strings.Contains(f.got(), "reject") || !strings.Contains(f.got(), "destroy") {
		t.Fatalf("%s", f.got())
	}
	r.st.Do(func(d *persisted) {
		ts := tasksOf(d)
		if len(ts.Instances) != 0 || len(ts.Schedules) != 0 || d.Sessions[sid] != nil || d.Sessions[pend] != nil {
			t.Fatalf("%+v", ts)
		}
	})
	r.tasksTick(time.Now())
	r.st.Do(func(d *persisted) {
		if len(tasksOf(d).Doomed) != 0 {
			t.Fatal("doomed list not emptied")
		}
	})
	if code, _ := appDo(t, r, "DELETE", "/api/tasks/instances/"+id, ""); code != 404 {
		t.Fatal(code)
	}
}

func TestGoneLineAndReapprove(t *testing.T) {
	r, f := newTaskRig(t, false)
	id, sid := makeReadyTask(t, r, f)
	run, _ := r.StartRun(id, "manual", "", nil, false)
	r.st.Do(func(d *persisted) { delete(d.Sessions, sid) }) // destroyed from the Sessions tab
	r.tasksTick(time.Now())
	i := r.instance(id)
	if i.Session != "" || i.run(run.ID).Phase != "failed" {
		t.Fatalf("%+v", i)
	}
	code, out := appDo(t, r, "POST", "/api/tasks/instances/"+id+"/approve", "")
	if code != 200 || out["state"] != "approval" || out["session"] == sid {
		t.Fatalf("%d %v", code, out)
	}
	if code, _ := appDo(t, r, "POST", "/api/tasks/instances/"+id+"/approve", ""); code != 409 {
		t.Fatal("re-approved a line waiting for the phone")
	}
}

func TestTaskLinesSkipAutopilot(t *testing.T) {
	now := time.Now()
	d := running("sT", &Liveness{})
	d.Sessions["sT"].Harness = "task:job"
	// no live claude in a task machine: no "dead" DM, no auto-pause
	acts := planTick(d, now, nil, defaultPilot, fakeLocks{}.busy, func(string) bool { return false })
	acts = append(acts, planTick(d, now.Add(time.Hour), nil, defaultPilot, fakeLocks{}.busy, func(string) bool { return false })...)
	if len(acts) != 0 {
		t.Fatalf("%v", kinds(acts))
	}
}

func TestTaskSchedulesAPI(t *testing.T) {
	r, f := newTaskRig(t, false)
	id, _ := makeReadyTask(t, r, f)
	for _, b := range []string{`{"instance":"nope","time":"07:00"}`, `{"instance":"` + id + `","time":"7am"}`, `{"instance":"` + id + `","time":"07:00","tz":"Mars/Base"}`, `{"instance":"` + id + `"}`} {
		if code, _ := appDo(t, r, "POST", "/api/tasks/schedules", b); code < 400 {
			t.Errorf("accepted %s", b)
		}
	}
	code, out := appDo(t, r, "POST", "/api/tasks/schedules", `{"instance":"`+id+`","time":"7:05"}`)
	if code != 200 || out["time"] != "07:05" || out["tz"] != "Europe/London" || out["enabled"] != true {
		t.Fatalf("%d %v", code, out)
	}
	sid := out["id"].(string)
	code, out = appDo(t, r, "PUT", "/api/tasks/schedules/"+sid, `{"enabled":false}`)
	if code != 200 || out["enabled"] != false || out["nextAt"] != nil || out["time"] != "07:05" {
		t.Fatalf("%d %v", code, out)
	}
	if code, _ := appDo(t, r, "DELETE", "/api/tasks/schedules/"+sid, ""); code != 200 {
		t.Fatal(code)
	}
	if code, _ := appDo(t, r, "DELETE", "/api/tasks/schedules/"+sid, ""); code != 404 {
		t.Fatal(code)
	}
}

func TestRunsPruned(t *testing.T) {
	r, f := newTaskRig(t, false)
	id, _ := makeReadyTask(t, r, f)
	r.st.Do(func(d *persisted) {
		i := tasksOf(d).Instances[id]
		for k := 0; k < taskKeepRuns+5; k++ {
			x := &TaskRun{ID: "old" + string(rune('a'+k)), Phase: "succeeded"}
			r.objPutBytes(runKey(x.ID, ".log"), []byte("l"))
			i.Runs = append(i.Runs, x)
		}
		i.Runs = append([]*TaskRun{{ID: "q", Phase: "queued"}}, i.Runs...)
		r.pruneRuns(i)
		if len(i.Runs) != taskKeepRuns+1 {
			t.Fatalf("%d", len(i.Runs))
		}
	})
	if _, err := r.objGetBytes(runKey("old"+string(rune('a'+taskKeepRuns+1)), ".log")); err == nil {
		t.Fatal("a pruned run's log stayed")
	}
}

func TestLockedStoreFailsTheStart(t *testing.T) {
	r, f := newTaskRig(t, true)
	dms := captureDM(t)
	id, sid := makeReadyTask(t, r, f)
	run, _ := r.StartRun(id, "schedule", "", nil, false)
	r.tasksTick(time.Now())
	// the machine is up but can't pull a locked store: it stays initialising
	r.st.Do(func(d *persisted) { d.Sessions[sid].State = "initialising" })
	r.tasksTick(time.Now())
	if x := r.instance(id).run(run.ID); x.Phase != "starting" || !strings.Contains(x.Waiting, "locked store") {
		t.Fatalf("%+v", x)
	}
	r.tasksTick(time.Now().Add(taskStartMax + time.Minute))
	if x := r.instance(id).run(run.ID); x.Phase != "failed" || !strings.Contains(x.Reason, "locked store") {
		t.Fatalf("%+v", x)
	}
	r.tasksTick(time.Now().Add(taskStartMax + 2*time.Minute)) // and the line is paused
	waitFor(t, "paused", func() bool { return r.sessionOf(sid).State == "paused" })
	if len(dms()) != 1 || !strings.Contains(dms()[0], "locked store") {
		t.Fatalf("%v", dms())
	}
}

func TestContentFieldsGoToTheLine(t *testing.T) {
	tm, err := parseTemplate("x", []byte(`{"title":"X","fields":[
		{"name":"store","type":"select","optionsFrom":"content","required":true},
		{"name":"more","type":"multiselect","optionsFrom":"content"},
		{"name":"keystore","type":"select","optionsFrom":"stores"}]}`), []string{"run.py"})
	if err != nil {
		t.Fatal(err)
	}
	tm = withOptions(tm)
	if _, err := checkParams(tm, map[string]any{"store": "../x"}); err == nil {
		t.Fatal("a bad content store name passed")
	}
	p, err := checkParams(tm, map[string]any{"store": "proton-email", "more": []any{"notes", "proton-email"}, "keystore": "keys"})
	if err != nil {
		t.Fatal(err)
	}
	if c := lineContent(tm, p); len(c) != 2 || c[0] != "notes" || c[1] != "proton-email" {
		t.Fatalf("content %v", c)
	}
	if s := lineStores(tm, p); len(s) != 1 || s[0] != "keys" {
		t.Fatalf("stores %v", s)
	}
	if c := lineContent(tm, map[string]any{"store": ""}); c != nil {
		t.Fatalf("none picked: %v", c)
	}
}
