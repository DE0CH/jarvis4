package main

import (
	"io"
	"strings"
	"testing"
	"time"
)

// the wait has no overall limit (DECISIONS 214): a snapshot whose progress reports keep moving is waited for well past
// the stall window, and arrives
func TestASnapshotMakingProgressIsWaitedFor(t *testing.T) {
	rg := newRig(t)
	rg.r.cfg.SnapshotStall = time.Second // ten report intervals: a slow CI runner's hiccup isn't a stall
	runningM2(rg, false)
	if err := rg.r.Pause("s1"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "asked", func() bool { return rg.r.snapshotAwaited("m2") })
	m := testMachine{"m2", rg.mkey.k}
	for i := 1; i <= 30; i++ { // 3 s, three stall windows
		body := jsonString(map[string]any{"phase": "uploading", "done": i * 1000, "total": 100000, "sent": i * 500, "elapsedMs": i * 100})
		if code, _ := m.do(t, rg.r.MachineHandler(), "POST", "/m/snapshot-progress", body); code != 200 {
			t.Fatal(code)
		}
		time.Sleep(100 * time.Millisecond)
		if s := sessionS1(rg); s.State != "pausing" {
			t.Fatalf("after %d reports the session is %s: %s", i, s.State, s.SnapshotFailed)
		}
	}
	rg.writeSnapshot(t, "m2", rg.files)
	rg.r.snapshotArrived("m2")
	if err := rg.r.waitActionEnd("s1", "paused"); err != nil {
		t.Fatal(err)
	}
}

// a live machine repeating the same numbers makes no progress: the wait ends after the stall window
func TestRepeatedProgressNumbersStall(t *testing.T) {
	rg := newRig(t)
	captureDM(t)
	rg.r.cfg.SnapshotStall = 300 * time.Millisecond
	runningM2(rg, false)
	if err := rg.r.Pause("s1"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "asked", func() bool { return rg.r.snapshotAwaited("m2") })
	m := testMachine{"m2", rg.mkey.k}
	body := jsonString(map[string]any{"phase": "uploading", "done": 1000, "total": 100000, "sent": 500, "elapsedMs": 100})
	t0 := time.Now()
	for i := 0; i < 30 && sessionS1(rg).State == "pausing"; i++ {
		m.do(t, rg.r.MachineHandler(), "POST", "/m/snapshot-progress", body)
		time.Sleep(50 * time.Millisecond)
	}
	if err := rg.r.waitActionEnd("s1", "failed"); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(t0); d > time.Second {
		t.Fatalf("the stall took %s", d)
	}
	if s := sessionS1(rg); !strings.Contains(s.SnapshotFailed, "made no progress") || s.MachineID != "m2" {
		t.Fatalf("%+v", s)
	}
	if rg.r.snapshotAwaited("m2") {
		t.Fatal("still awaited after the wait ended")
	}
}

// the snapshot's bytes arriving at the router are progress (a machine with no progress reports, or a slow network)
func TestStreamedBytesKeepTheWaitGoing(t *testing.T) {
	rg := newRig(t)
	r := rg.r
	done := r.awaitSnapshot("m9")
	pr, pw := io.Pipe()
	go func() {
		for i := 0; i < 10; i++ {
			pw.Write([]byte("x"))
			time.Sleep(100 * time.Millisecond)
		}
		pw.Close()
	}()
	quietMax := time.Duration(0)
	go io.Copy(io.Discard, movedReader{pr, r, "m9"})
	for i := 0; i < 10; i++ {
		time.Sleep(100 * time.Millisecond)
		quietMax = max(quietMax, r.snapshotQuiet("m9"))
	}
	if quietMax > 250*time.Millisecond {
		t.Fatalf("quiet for %s while bytes arrived", quietMax)
	}
	r.snapshotArrived("m9")
	if err := r.waitSnapshot("m9", done); err != nil {
		t.Fatal(err)
	}
}

// a machine that stops reporting during its snapshot (gone) ends the wait after silentAfter, not the stall window
func TestAMachineGoneSilentDuringItsSnapshot(t *testing.T) {
	rg := newRig(t)
	captureDM(t)
	rg.r.cfg.SnapshotStall = time.Minute
	old := silentAfter
	silentAfter = 300 * time.Millisecond
	t.Cleanup(func() { silentAfter = old })
	runningM2(rg, false) // its last report is fresh: it is asked
	t0 := time.Now()
	if err := rg.r.Pause("s1"); err != nil {
		t.Fatal(err)
	}
	if err := rg.r.waitActionEnd("s1", "failed"); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(t0); d > 5*time.Second {
		t.Fatalf("took %s", d)
	}
	if s := sessionS1(rg); !strings.Contains(s.SnapshotFailed, "went silent during its snapshot") {
		t.Fatalf("%+v", s)
	}
}
