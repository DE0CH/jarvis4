package main

// A failed session comes back with one tap and can always be destroyed (Deyao, 2026-10-15; DECISIONS 181): Resume of
// a failed session that still has a machine finishes its pause first; a kill that failed on the way is tried again; a
// destroy goes past a snapshot the core refuses, a machine Fly no longer has, and (Destroy anyway) any kill failure;
// the core calls that wait inside the running core outlast its own worst case.

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

func fastKills(t *testing.T) {
	step := killTransientStep
	killTransientStep = time.Millisecond
	t.Cleanup(func() { killTransientStep = step })
}

func failedWithMachine(rg *rig, msg string) {
	rg.r.st.Do(func(d *persisted) {
		s := d.Sessions["s1"]
		s.State, s.Error, s.MachineID = "failed", msg, "m1"
		s.Cert = v2Cert(rg, "m1", `{"v":1}`)
		d.Started["m1"] = &Started{ID: "m1", SigningKey: rg.mkey.pub()}
	})
}

func sessionOf(rg *rig) (s Session) {
	rg.r.st.Do(func(d *persisted) {
		if x := d.Sessions["s1"]; x != nil {
			s = *x
		}
	})
	return
}

func callOrder(vc *v2Core) []string {
	vc.mu.Lock()
	defer vc.mu.Unlock()
	return append([]string{}, vc.order...)
}

// "Draft reply to image" (2026-10-15): its pause's kill timed out at Fly. One tap: the kill again, then the resume.
func TestResumeOfAFailedSessionWithAMachineFinishesThePauseFirst(t *testing.T) {
	fastKills(t)
	rg, vc := v2Rig(t)
	failedWithMachine(rg, `kill: core: fly destroy: Delete "…?force=true": context deadline exceeded`)
	vc.killErrs = []coreRefusal{{502, "fly destroy: context deadline exceeded (Client.Timeout exceeded while awaiting headers)"}}
	if err := rg.r.Resume("s1", false); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the resume asked the core", func() bool { return vc.last("/approve/by-dead-machine") != nil })
	calls := callOrder(vc)
	kills := 0
	for _, c := range calls {
		if c == "/kill" {
			kills++
		}
	}
	if kills != 2 || slices.Index(calls, "/succession") < slices.Index(calls, "/kill") {
		t.Fatalf("the kill (tried again) before the resume's challenge: %v", calls)
	}
	if snap, _ := vc.last("/kill")["snapshot"].(map[string]any); snap == nil || snap["required"] != true {
		t.Fatalf("the finished pause's kill names the snapshot and keeps the machine without it: %v", vc.last("/kill"))
	}
	if in := vc.last("/succession"); in["predecessor"] == nil {
		t.Fatalf("the resume continues the line: %v", in)
	}
	waitFor(t, "idle", func() bool { _, err := rg.r.lock("s1", "test-end"); return err == nil })
	if s := sessionOf(rg); s.MachineID == "m1" {
		t.Fatalf("the killed machine is still the session's: %+v", s)
	}
}

// a kill the core refuses (not a failure on the way) leaves the session failed with the error: nothing resumes
func TestResumeOfAFailedSessionWhoseKillIsRefusedStaysFailed(t *testing.T) {
	fastKills(t)
	rg, vc := v2Rig(t)
	failedWithMachine(rg, "kill: core: the snapshot isn't signed by machine m1's current key")
	vc.killErrs = []coreRefusal{{403, "the snapshot isn't signed by machine m1's current key"}}
	if err := rg.r.Resume("s1", false); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "idle", func() bool { _, err := rg.r.lock("s1", "test-end"); return err == nil })
	s := sessionOf(rg)
	if s.State != "failed" || !strings.Contains(s.Error, "current key") || s.MachineID != "m1" || vc.last("/succession") != nil {
		t.Fatalf("%s %q %s, succession %v", s.State, s.Error, s.MachineID, vc.last("/succession"))
	}
	if strings.Contains(s.Error, "Destroy anyway") {
		t.Fatalf("a resume's error offers Destroy anyway: %q", s.Error)
	}
}

func TestAKillThatFailedOnTheWayIsTriedAgain(t *testing.T) {
	fastKills(t)
	rg, vc := v2Rig(t)
	vc.killErrs = []coreRefusal{{502, "fly destroy: timeout"}, {502, "fly did not confirm m1 destroyed"}}
	if _, err := rg.r.killUntilDestroyed(map[string]any{"machine": "m1"}); err != nil {
		t.Fatal(err)
	}
	// a refusal is final
	vc.killErrs = []coreRefusal{{403, "the snapshot isn't signed by machine m1's current key"}, {502, "x"}}
	if _, err := rg.r.killUntilDestroyed(map[string]any{"machine": "m1"}); err == nil || !refusedSnapshot(err) {
		t.Fatalf("a refusal tried again: %v", err)
	}
	// and the tries end
	vc.killErrs = []coreRefusal{{502, "a"}, {502, "b"}, {502, "c"}, {502, "d"}, {502, "e"}, {502, "f"}}
	if _, err := rg.r.killUntilDestroyed(map[string]any{"machine": "m1"}); err == nil {
		t.Fatal("killed after every try failed")
	}
}

func destroyed(rg *rig) bool {
	ok := false
	rg.r.st.Do(func(d *persisted) { ok = d.Sessions["s1"] == nil && len(d.Records) > 0 && d.Records[0].ID == "s1" })
	return ok
}

func gone(t *testing.T, g bool, err error) {
	was := flyMachineGone
	flyMachineGone = func(string) (bool, error) { return g, err }
	t.Cleanup(func() { flyMachineGone = was })
}

// "Powerpoint generator" (2026-10-15): the core refuses the snapshot; a destroy restores nothing, so it kills without it
func TestADestroyGoesPastARefusedSnapshot(t *testing.T) {
	fastKills(t)
	gone(t, false, errors.New("no Fly reader"))
	rg, vc := v2Rig(t)
	failedWithMachine(rg, "kill: core: the snapshot isn't signed by machine m1's current key")
	vc.killErrs = []coreRefusal{{403, "the snapshot isn't signed by machine m1's current key"}}
	body := snapBytes(rg.r, "m1")
	if err := rg.r.Destroy("s1"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "destroyed", func() bool { return destroyed(rg) })
	vc.mu.Lock()
	kills := vc.bodies["/kill"]
	vc.mu.Unlock()
	if len(kills) != 2 || kills[0]["snapshot"] == nil || kills[1]["snapshot"] != nil {
		t.Fatalf("kills %v", kills)
	}
	// the router's snapshot is archived as is, marked; a restore of it is refused for now
	var rec *Record
	rg.r.st.Do(func(d *persisted) { rec = d.Records[0] })
	if rec.Archive == nil || rec.Archive.Unverified != snapshotFromEarlierCore || rec.SnapshotNote != snapshotFromEarlierCore {
		t.Fatalf("record %+v archive %+v", rec, rec.Archive)
	}
	files, _ := rg.dav.archive(t, rec.Archive.File)
	if got := files["jarvis2/snapshot.tar.gz"]; len(body) == 0 || string(got) != string(body) {
		t.Fatalf("the snapshot isn't archived whole (%d of %d bytes)", len(got), len(body))
	}
	if !strings.Contains(string(files["session.json"]), `"snapshotUnverified": "`+snapshotFromEarlierCore) {
		t.Fatalf("session.json: %s", files["session.json"])
	}
	// restorable like any archive: checked by checkRestoreFiles and the restoring machine, not refused for its mark
	if _, err := rg.r.RestoreRecord("s1", ""); err != nil && strings.Contains(err.Error(), "waits for the core release") {
		t.Fatalf("restore: %v", err)
	}
}

// a destroy whose kill keeps failing: failed with the hint (the apps offer Destroy anyway), unless Fly says the
// machine is gone; Destroy anyway destroys it and leaves the machine to the Machines tab
func TestADestroyWhoseKillKeepsFailing(t *testing.T) {
	fastKills(t)
	fail := func(vc *v2Core) {
		vc.killErrs = nil
		for i := 0; i < 2*(killTransientTries+1); i++ {
			vc.killErrs = append(vc.killErrs, coreRefusal{502, "fly destroy: context deadline exceeded"})
		}
	}
	gone(t, false, nil)
	rg, vc := v2Rig(t)
	failedWithMachine(rg, "kill: core: fly destroy: timeout")
	fail(vc)
	rg.r.Destroy("s1")
	waitFor(t, "idle", func() bool { _, err := rg.r.lock("s1", "test-end"); return err == nil })
	if s := sessionOf(rg); s.State != "failed" || !strings.HasPrefix(s.Error, "kill: ") || !strings.HasSuffix(s.Error, destroyAnywayHint) {
		t.Fatalf("%s %q", s.State, s.Error)
	}

	rg2, vc2 := v2Rig(t)
	failedWithMachine(rg2, "kill: …")
	fail(vc2)
	if err := rg2.r.DestroyWith("s1", true); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "destroyed anyway", func() bool { return destroyed(rg2) })
	rg2.r.st.Do(func(d *persisted) {
		if d.Started["m1"] != nil {
			t.Fatal("the router still takes the abandoned machine's calls")
		}
		old := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
		if why := orphanRefusal(d, flyMachineDetail{ID: "m1", State: "stopped", CreatedAt: old}, time.Now()); why != "" {
			t.Fatalf("the abandoned machine can't be destroyed from the Machines tab: %s", why)
		}
	})

	gone(t, true, nil)
	rg3, vc3 := v2Rig(t)
	failedWithMachine(rg3, "kill: …")
	fail(vc3)
	rg3.r.Destroy("s1")
	waitFor(t, "destroyed: Fly has no such machine", func() bool { return destroyed(rg3) })
}

// a live session's machine is never an orphan; a paused one's destroyed machine isn't listed at all
func TestAMachineOfALiveSessionIsNoOrphan(t *testing.T) {
	rg, _ := v2Rig(t)
	failedWithMachine(rg, "kill: …")
	rg.r.st.Do(func(d *persisted) {
		old := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
		if why := orphanRefusal(d, flyMachineDetail{ID: "m1", State: "started", CreatedAt: old}, time.Now()); !strings.Contains(why, "belongs to session s1") {
			t.Fatalf("%q", why)
		}
	})
}

// a machine the router started that no session names any more (its cert still kept) is an orphan Deyao may destroy
func TestAnUnnamedStartedMachineIsAnOrphan(t *testing.T) {
	rg, _ := v2Rig(t)
	rg.r.st.Do(func(d *persisted) {
		d.Certs["m-left"] = &Doc{Payload: "{}"}
		old := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
		if why := orphanRefusal(d, flyMachineDetail{ID: "m-left", State: "stopped", CreatedAt: old}, time.Now()); why != "" {
			t.Fatalf("%q", why)
		}
	})
}

// 2026-10-15 "start: core /start: … Client.Timeout exceeded": the running core waits inside /start and /kill for up
// to ≈ 34 min; the router waits longer, so it always hears the core's answer
func TestTheRouterOutwaitsTheRunningCoresStartAndKill(t *testing.T) {
	liveCoreStart := 90*time.Second + 10*90*time.Second + 90*time.Second + 10*(90+3)*time.Second
	liveCoreKill := 90*time.Second + 20*(90+1)*time.Second
	if coreCallTimeout("/start") <= liveCoreStart || coreCallTimeout("/kill") <= liveCoreKill {
		t.Fatalf("start %s (core up to %s), kill %s (core up to %s)", coreCallTimeout("/start"), liveCoreStart, coreCallTimeout("/kill"), liveCoreKill)
	}
	if coreCallTimeout("/succession") != coreCallDefault {
		t.Fatal("other calls keep the default")
	}
}
