package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// a pause or destroy never waits on a machine that can't snapshot: one that never got past boot isn't asked at
// all; one that answers "nothing to snapshot" (X-Snapshot-None, a machine still booting) ends the wait at once;
// while it does wait, the session says what it waits on
func TestLastSnapshotNeverWaitsOnABootingMachine(t *testing.T) {
	rg := newRig(t)
	r := rg.r
	r.cfg.SnapshotStall = 30 * time.Second
	unsignSnap(r, "m1") // m1 runs: it hasn't sent its final snapshot yet
	running := func(booted string) {
		r.st.Do(func(d *persisted) {
			s := d.Sessions["s1"]
			s.State, s.MachineID, s.Booted, s.Cert = "started", "m1", booted, rg.cert
			s.Live = &Liveness{LastReport: time.Now()}
		})
	}

	// never booted (e.g. looping on a locked store): no wait at all
	running("")
	t0 := time.Now()
	if err := r.Pause("s1"); err != nil {
		t.Fatal(err)
	}
	if err := r.waitState("s1", "paused", 5*time.Second); err != nil {
		t.Fatalf("a never-booted machine held the pause: %v", err)
	}
	if d := time.Since(t0); d > 5*time.Second {
		t.Fatalf("pause took %s", d)
	}

	// booted: asked, and the session shows what it waits on until the machine answers "nothing to snapshot"
	running("m1")
	if err := r.Pause("s1"); err != nil {
		t.Fatal(err)
	}
	var waiting string
	for i := 0; i < 50 && waiting == ""; i++ {
		time.Sleep(20 * time.Millisecond)
		r.st.Do(func(d *persisted) { waiting = d.Sessions["s1"].Waiting })
	}
	if waiting != "waiting for the machine's last snapshot" {
		t.Fatalf("waiting = %q", waiting)
	}
	r.snapshotArrived("m1") // what POST /m/snapshot with X-Snapshot-None does
	if err := r.waitState("s1", "paused", 5*time.Second); err != nil {
		t.Fatalf("the answer didn't end the wait: %v", err)
	}
	r.st.Do(func(d *persisted) { waiting = d.Sessions["s1"].Waiting })
	if waiting != "" {
		t.Fatalf("still waiting: %q", waiting)
	}
	// booted but silent (its machine stopped or gone): not asked and not waited for; without a volume it can't be
	// backed up, so it is kept (snapsafe.go), at once
	running("m1")
	r.st.Do(func(d *persisted) { d.Sessions["s1"].Live.LastReport = time.Now().Add(-10 * time.Minute) })
	t0 = time.Now()
	if err := r.Pause("s1"); err != nil {
		t.Fatal(err)
	}
	if err := r.waitState("s1", "failed", 5*time.Second); err != nil || time.Since(t0) > 5*time.Second {
		t.Fatalf("a silent machine held the pause: %v", err)
	}
	r.st.Do(func(d *persisted) {
		if s := d.Sessions["s1"]; s.MachineID != "m1" || !strings.Contains(s.SnapshotFailed, "silent since") {
			t.Fatalf("not kept: %+v", s)
		}
	})
	if waitText(10*time.Minute) != "10 min" {
		t.Fatal(waitText(10 * time.Minute))
	}
}

// waitState returns once the action that reached the state has ended, not the moment it sets the state: a pause marks
// the session paused before its lifecycle record and unlock run, and a caller that acted at once (the next pause, a
// handover's resume) met errBusy (the flake in TestLastSnapshotNeverWaitsOnABootingMachine)
func TestWaitStateWaitsForTheActionToEnd(t *testing.T) {
	rg := newRig(t)
	r := rg.r
	unlock, err := r.lock("s1", "pausing")
	if err != nil {
		t.Fatal(err)
	}
	r.setState("s1", "paused", "")
	got := make(chan error, 1)
	go func() { got <- r.waitState("s1", "paused", 10*time.Second) }()
	select {
	case err := <-got:
		t.Fatalf("waitState returned while the pause still held the session: %v", err)
	case <-time.After(3 * opsPoll):
	}
	if !r.busy("s1") {
		t.Fatal("busy() doesn't see the held lock")
	}
	unlock()
	if err := <-got; err != nil {
		t.Fatal(err)
	}
	if r.busy("s1") {
		t.Fatal("still busy after the unlock")
	}
	// the next action takes the session at once; asking busy() never makes it fail
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				r.busy("s1") // the app's state and the task runner ask this all the time
			}
		}
	}()
	for i := 0; i < 2000; i++ {
		u, err := r.lock("s1", "pausing")
		if err != nil {
			t.Fatalf("lock %d: %v", i, err)
		}
		u()
		u() // a second call is a no-op, never another action's release
	}
}

// a crash cut actions off (no goroutine runs them any more): at start each such session becomes a plain one with
// the reason, nothing is run again by itself, and Deyao's retry works from there (Deyao, 2026-10-13)
func TestCutOffActionsEndWithAReason(t *testing.T) {
	rg := newRig(t)
	r := rg.r
	r.st.Do(func(d *persisted) {
		s := d.Sessions["s1"]
		s.State, s.MachineID, s.Cert = "starting", "", rg.cert       // a resume: its line is still there
		d.Sessions["sNew"] = &Session{ID: "sNew", State: "starting"} // a new line's first start
		d.Sessions["sP"] = &Session{ID: "sP", State: "pausing", MachineID: "m2", Cert: rg.cert, Waiting: "x"}
		d.Sessions["sD"] = &Session{ID: "sD", State: "destroying", MachineID: "m3", Cert: rg.cert}
		d.Sessions["sR"] = &Session{ID: "sR", State: "resuming", Cert: rg.cert}
		d.Sessions["sOK"] = &Session{ID: "sOK", State: "started", MachineID: "m4", Cert: rg.cert}
	})
	r.endCutOff()
	want := map[string]string{"s1": "paused", "sR": "paused", "sNew": "failed", "sP": "failed", "sD": "failed", "sOK": "started"}
	r.st.Do(func(d *persisted) {
		for id, st := range want {
			s := d.Sessions[id]
			if s.State != st {
				t.Errorf("%s: %s, want %s", id, s.State, st)
			}
			if st != "started" && !strings.Contains(s.Error, "cut off by a router crash") {
				t.Errorf("%s: error %q", id, s.Error)
			}
			if s.Waiting != "" {
				t.Errorf("%s: still waiting %q", id, s.Waiting)
			}
		}
	})
	rg.core.mu.Lock()
	calls := len(rg.core.calls)
	rg.core.mu.Unlock()
	if calls != 0 {
		t.Fatalf("the core was called (something ran again): %v", rg.core.calls)
	}
	// the retry: the cut-off resume resumes again
	if err := r.Resume("s1", false); err != nil {
		t.Fatal(err)
	}
	for until := time.Now().Add(10 * time.Second); time.Now().Before(until); time.Sleep(20 * time.Millisecond) {
		if unlock, err := r.lock("s1", "test"); err == nil {
			unlock()
			break
		}
	}
}

// state.json from before the drain kept "pendingStart" on a resuming session: it loads (the field is dropped)
func TestOldPendingStartIsDropped(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "state.json"), []byte(`{"sessions":{"s1":{"id":"s1","state":"resuming","pendingStart":{"upgrade":true,"machine":"m9"}}}}`), 0o600)
	st, err := testState(t, dir)
	if err != nil {
		t.Fatal(err)
	}
	st.Do(func(d *persisted) {})
	b, _ := os.ReadFile(filepath.Join(dir, "state.json"))
	if strings.Contains(string(b), "pendingStart") {
		t.Fatalf("pendingStart kept: %s", b)
	}
}
