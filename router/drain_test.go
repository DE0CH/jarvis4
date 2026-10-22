package main

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// SIGTERM's drain (drain.go): a pause in flight finishes (its machine's snapshot still lands), every new lifecycle
// action is refused with 503 "router updating, try again shortly", reads are served, and the drain ends once the
// pause is done
func TestDrainLetsInFlightFinishAndRefusesNew(t *testing.T) {
	rg := newRig(t)
	unsignSnap(rg.r, "m1") // m1 runs: it hasn't sent its final snapshot yet
	r := rg.r
	r.cfg.NoAccess = true
	r.cfg.SnapshotStall = 30 * time.Second
	r.st.Do(func(d *persisted) {
		s := d.Sessions["s1"]
		s.State, s.MachineID, s.Booted, s.Cert = "started", "m1", "m1", rg.cert
		s.Live = &Liveness{LastReport: time.Now()} // reporting: the pause waits for its snapshot
		d.Sessions["s2"] = &Session{ID: "s2", State: "paused", Cert: rg.cert}
		d.Sessions["s3"] = &Session{ID: "s3", State: "started", MachineID: "m3", Cert: rg.cert}
		d.Approvals["a1"] = &Approval{ID: "a1", Kind: "new-session", Session: "s2", Created: time.Now().UTC()}
	})
	if err := r.Pause("s1"); err != nil { // waits for m1's snapshot
		t.Fatal(err)
	}
	drained := make(chan bool, 1)
	go func() { drained <- r.Drain(20 * time.Second) }()
	waitFor(t, "draining", r.draining)

	// new actions: refused, with the text the apps show as is
	for name, err := range map[string]error{
		"pause":   r.Pause("s3"),
		"resume":  r.Resume("s2", false),
		"destroy": r.Destroy("s3"),
	} {
		if !errors.Is(err, errDraining) || err.Error() != drainingMsg {
			t.Fatalf("%s during the drain: %v", name, err)
		}
	}
	if _, _, err := r.Respond("a1", "sig"); !errors.Is(err, errDraining) {
		t.Fatalf("approval answer during the drain: %v", err)
	}
	r.st.Do(func(d *persisted) {
		if d.Approvals["a1"] == nil {
			t.Error("the refused answer used up the approval")
		}
	})
	rg.core.mu.Lock()
	for _, c := range rg.core.calls {
		if c == "/approve/by-phone" || c == "/succession" {
			t.Errorf("the core was asked %s during the drain", c)
		}
	}
	rg.core.mu.Unlock()
	code, out := appDo(t, r, "POST", "/api/sessions/s3/pause", "")
	if code != 503 || out["error"] != drainingMsg {
		t.Fatalf("HTTP pause during the drain: %d %v", code, out)
	}
	// automatic callers (scheduler, tasks, watches) see a busy session and try again later
	if !errors.Is(errDraining, errBusy) {
		t.Fatal("errDraining isn't an errBusy")
	}
	// reads go on
	if code, _ := appDo(t, r, "GET", "/api/state", ""); code != 200 {
		t.Fatalf("GET /api/state during the drain: %d", code)
	}

	select {
	case <-drained:
		t.Fatal("the drain ended with the pause still waiting for its snapshot")
	case <-time.After(200 * time.Millisecond):
	}
	r.snapshotArrived("m1") // the machine's report (/m/snapshot) during the drain
	select {
	case ok := <-drained:
		if !ok {
			t.Fatal("drain gave up")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the drain didn't end after the pause finished")
	}
	r.st.Do(func(d *persisted) {
		if s := d.Sessions["s1"]; s.State != "paused" {
			t.Errorf("the in-flight pause ended %s (%s)", s.State, s.Error)
		}
		if s := d.Sessions["s3"]; s.State != "started" {
			t.Errorf("the refused pause touched s3: %s", s.State)
		}
	})
}

// a job that chains actions (restart, upgrade) runs to its end through a drain that began between its steps, and
// the drain waits for it; a drain past its limit reports so
func TestDrainWaitsForAJobsLaterSteps(t *testing.T) {
	r := &Router{}
	endJob, err := r.beginJob("s1", "restart")
	if err != nil {
		t.Fatal(err)
	}
	drained := make(chan bool, 1)
	go func() { drained <- r.Drain(5 * time.Second) }()
	waitFor(t, "draining", r.draining)
	step, err := r.begin("s1", "starting") // the job's resume
	if err != nil {
		t.Fatalf("the job's own step was refused: %v", err)
	}
	if _, err := r.begin("s2", "pausing"); !errors.Is(err, errDraining) {
		t.Fatalf("another session's action: %v", err)
	}
	step()
	select {
	case <-drained:
		t.Fatal("drained with the job running")
	case <-time.After(100 * time.Millisecond):
	}
	endJob()
	endJob() // twice is harmless
	if !<-drained {
		t.Fatal("drain gave up")
	}
	if _, err := r.begin("s1", "starting"); !errors.Is(err, errDraining) {
		t.Fatalf("after the job: %v", err)
	}

	r2 := &Router{}
	done, _ := r2.begin("s9", "pausing")
	defer done()
	if r2.Drain(50 * time.Millisecond) {
		t.Fatal("a drain past its limit reported success")
	}
}

// a start waiting out Fly's machine limit doesn't hold a drain for hours: it ends at once
func TestDrainEndsAMachineLimitWait(t *testing.T) {
	c := &splitCore{key: newTestKey(), limit: 1 << 30, bodies: map[string]map[string]any{}}
	r := splitRouter(t, c)
	res := make(chan error, 1)
	go func() { _, err := r.startMachine("img", ""); res <- err }()
	waitFor(t, "the limit wait", func() bool { return c.count("/start") >= 1 })
	go r.Drain(time.Second)
	select {
	case err := <-res:
		if !errors.Is(err, errLimitDraining) || !strings.Contains(err.Error(), "start it again") {
			t.Fatalf("%v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the machine-limit wait went on through the drain")
	}
	if _, err := r.startMachine("img", ""); !errors.Is(err, errLimitDraining) {
		t.Fatalf("a wait began during the drain: %v", err)
	}
}
