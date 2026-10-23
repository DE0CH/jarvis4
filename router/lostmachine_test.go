package main

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/DE0CH/jarvis4/kernel/kerneltest"
)

// lostRig: a kernel line running on its first machine (booted, its secrets pulled), the router reading the fake Fly
func lostRig(t *testing.T, keysOnVolume bool) (*rig, *kerneltest.Kernel, string, *kerneltest.FakeMachine) {
	rg, k := kernelRig(t)
	old := listFlyMachines
	t.Cleanup(func() { listFlyMachines = old })
	listFlyMachines = func() ([]flyMachineDetail, error) {
		out := []flyMachineDetail{}
		for id := range k.Fly.Machines {
			m := k.Fly.Machine(id)
			if m.State != "destroyed" { // Fly lists a destroyed machine for a while; gone is the harder case
				out = append(out, flyMachineDetail{ID: id, State: m.State})
			}
		}
		return out, nil
	}
	rg.r.lc.flyEvents = func(machine string) ([]flyEvent, error) {
		e := flyEvent{Type: "exit", Status: "stopped", Source: "user", Timestamp: time.Date(2026, 10, 22, 9, 30, 0, 0, time.UTC).UnixMilli()}
		e.Request = &struct {
			ExitEvent *struct {
				ExitCode      int  `json:"exit_code"`
				OOMKilled     bool `json:"oom_killed"`
				RequestedStop bool `json:"requested_stop"`
			} `json:"exit_event"`
		}{}
		return []flyEvent{{Type: "launch", Status: "created", Timestamp: e.Timestamp - 1000}, e}, nil
	}
	rg.r.lc.flyLogs = func(string, string) ([]flyLogLine, string, error) { return nil, "", nil }
	sid, err := rg.r.CreateSession(NewSession{Label: "lost one", Harness: "claude"})
	if err != nil {
		t.Fatal(err)
	}
	var a *Approval
	waitFor(t, "the approval", func() bool {
		rg.r.st.Do(func(d *persisted) {
			for _, x := range d.Approvals {
				if x.Session == sid {
					a = x
				}
			}
		})
		return a != nil
	})
	signature, _ := k.Phone.Sign([]byte(a.Challenge.Payload))
	if _, _, err := rg.r.Respond(a.ID, signature); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the machine", func() bool { s := kernelSession(rg, sid); return s.MachineID != "" && s.Kernel.MachineCert != nil })
	m1 := k.Fly.Machine(kernelSession(rg, sid).MachineID)
	h := rg.r.MachineHandler()
	if code, body := kdo(t, h, m1, "POST", "/m/pull-secrets", "{}"); code != 200 {
		t.Fatal(code, string(body))
	}
	report := `{"raw":""}`
	if keysOnVolume {
		report = `{"raw":"","keysOnVolume":"1"}`
	}
	if code, body := kdo(t, h, m1, "POST", "/m/status", report); code != 200 {
		t.Fatal(code, string(body))
	}
	if s := kernelSession(rg, sid); s.State != "started" || s.Booted != m1.ID {
		t.Fatalf("%s %s", s.State, s.Booted)
	}
	return rg, k, sid, m1
}

func eventsText(r *Router, sid string) string {
	evs, _, _, _ := r.sessionEvents(sid, true, 0, 0, eventsReadMax)
	var b strings.Builder
	for _, e := range evs {
		b.WriteString(e.Text + "\n")
	}
	return b.String()
}

// a machine stopped outside Jarvis (fly machine stop): on the second look the session says so — when, Fly's event,
// that its volume is kept and nothing is lost — in its error, its lost record, its events and /setup/sessions; Resume
// starts the same machine again through the spawner (no new machine, no new cert), and it goes on once it reports in
func TestAMachineStoppedOutsideJarvisResumesInPlace(t *testing.T) {
	rg, k, sid, m1 := lostRig(t, true)
	seen := map[string]int{}
	rg.r.lostTick(seen)
	if kernelSession(rg, sid).State != "started" {
		t.Fatal("a running machine was taken for lost")
	}
	k.Fly.Stop(m1.ID)
	rg.r.lostTick(seen)
	if kernelSession(rg, sid).State != "started" {
		t.Fatal("lost on one look")
	}
	rg.r.lostTick(seen)
	s := kernelSession(rg, sid)
	if s.State != "failed" || s.Lost == nil || !s.Lost.InPlace || s.Lost.Volume == "" || s.Lost.FlyState != "stopped" || s.FailedAt == nil {
		t.Fatalf("%s %+v", s.State, s.Lost)
	}
	for _, want := range []string{"Its machine " + m1.ID + " stopped outside Jarvis at 2026-10-22 09:30:00 UTC", "Fly: machine exit → stopped (user)",
		"Nothing is lost: its volume " + s.Lost.Volume + " is kept", "Resume starts the same machine again"} {
		if !strings.Contains(s.Error, want) {
			t.Fatalf("%q lacks %q", s.Error, want)
		}
	}
	defer func() {
		if t.Failed() {
			t.Log(eventsText(rg.r, sid))
		}
	}()
	waitFor(t, "the event", func() bool {
		t := eventsText(rg.r, sid)
		return strings.Contains(t, "Machine lost failed") && strings.Contains(t, ": Its machine "+m1.ID+" stopped outside Jarvis")
	})
	if strings.Contains(eventsText(rg.r, sid), "Session failed") {
		t.Fatal("the failure was written twice")
	}
	rg.r.cfg.NoAccess = true
	code, out := inboxDo(t, rg.r, "GET", "/setup/sessions", "", false)
	var row map[string]any
	for _, x := range out["sessions"].([]any) {
		if x.(map[string]any)["id"] == sid {
			row = x.(map[string]any)
		}
	}
	if code != 200 || row["error"] != s.Error || row["failedAt"] == nil || row["lost"].(map[string]any)["inPlace"] != true {
		t.Fatalf("%d %v", code, row)
	}
	// ✱ the next look leaves it alone
	rg.r.lostTick(seen)
	before := len(k.Fly.Machines)
	if err := rg.r.Resume(sid, false); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "started again", func() bool { return k.Fly.Starts == 1 && kernelSession(rg, sid).State == "initialising" })
	s = kernelSession(rg, sid)
	if s.MachineID != m1.ID || s.Lost != nil || s.Error != "" || s.FailedAt != nil || len(k.Fly.Machines) != before || m1.State != "started" {
		t.Fatalf("%+v machines %d", s, len(k.Fly.Machines))
	}
	// the same machine reports in and pulls with the grant it had: it goes on
	h := rg.r.MachineHandler()
	if code, body := kdo(t, h, m1, "POST", "/m/status", `{"raw":"","keysOnVolume":"1"}`); code != 200 {
		t.Fatal(code, string(body))
	}
	if code, body := kdo(t, h, m1, "POST", "/m/pull-secrets", "{}"); code != 200 {
		t.Fatal(code, string(body))
	}
	if st := kernelSession(rg, sid).State; st != "started" {
		t.Fatal(st)
	}
	waitFor(t, "the resume's end", func() bool {
		return strings.Contains(eventsText(rg.r, sid), "the machine reported in again") && strings.Contains(eventsText(rg.r, sid), "Resume done")
	})
}

// a machine that can't start again (destroyed outside Jarvis; or an image that keeps no keys on its volume): the
// session says the newest signed snapshot is kept; Resume kills it into the line's next source and a new machine
// restores that snapshot
func TestALostMachineResumesFromTheNewestSnapshot(t *testing.T) {
	for _, destroyed := range []bool{false, true} {
		rg, k, sid, m1 := lostRig(t, false)
		tarball := makeTar(t, rg.files)
		sum := sha256.Sum256(tarball)
		snapSig, _ := m1.Sig.Sign([]byte(hex.EncodeToString(sum[:])))
		putSnap(t, rg.r, m1.ID, tarball, snapSig)
		if destroyed {
			k.Fly.Destroy(m1.ID) // listed no more: "gone"
		} else {
			k.Fly.Stop(m1.ID)
		}
		seen := map[string]int{}
		rg.r.lostTick(seen)
		rg.r.lostTick(seen)
		s := kernelSession(rg, sid)
		if s.State != "failed" || s.Lost == nil || s.Lost.InPlace {
			t.Fatalf("%s %+v", s.State, s.Lost)
		}
		want := "predates starting a machine again"
		if destroyed {
			want = "is gone from Fly"
		}
		if !strings.Contains(s.Error, want) || !strings.Contains(s.Error, "The newest signed snapshot (machine "+m1.ID+"'s") {
			t.Fatal(s.Error)
		}
		if err := rg.r.Resume(sid, false); err != nil {
			t.Fatal(err)
		}
		waitFor(t, "a new machine", func() bool {
			s := kernelSession(rg, sid)
			return s.MachineID != "" && s.MachineID != m1.ID && s.Kernel.MachineCert != nil
		})
		if k.Fly.Starts != 0 || k.Fly.Machine(m1.ID).State != "destroyed" {
			t.Fatal("the lost machine wasn't killed")
		}
		m2 := k.Fly.Machine(kernelSession(rg, sid).MachineID)
		if code, body := kdo(t, rg.r.MachineHandler(), m2, "GET", "/m/snapshot", ""); code != 200 || string(body) != string(tarball) {
			t.Fatalf("the newest snapshot: %d", code)
		}
	}
}

// ✱ a machine Jarvis is pausing (its job holds the session) isn't lost; nor is one that is only stopping
func TestJarvisOwnStopIsNotLost(t *testing.T) {
	rg, k, sid, m1 := lostRig(t, true)
	k.Fly.Stop(m1.ID)
	done, err := rg.r.lock(sid, "pausing")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	rg.r.lostTick(seen)
	rg.r.lostTick(seen)
	done()
	if s := kernelSession(rg, sid); s.Lost != nil || s.State == "failed" {
		t.Fatal("Jarvis's own action taken for a lost machine")
	}
	if !machineDown("gone") || machineDown("stopping") || machineDown("started") {
		t.Fatal("machineDown")
	}
}

// every failed session says why and since when, however it failed; a failure outside any operation is in the events
func TestAFailedSessionSaysWhy(t *testing.T) {
	r := newTestRouter(t)
	addSession(r, "sK", "approval", "", false)
	r.setState("sK", "failed", "start: the spawner has no Fly token")
	var s Session
	r.st.Do(func(d *persisted) { s = *d.Sessions["sK"] })
	if s.FailedAt == nil || s.Error != "start: the spawner has no Fly token" {
		t.Fatalf("%+v", s)
	}
	waitFor(t, "the event", func() bool {
		return strings.Contains(eventsText(r, "sK"), "Session failed: start: the spawner has no Fly token")
	})
	if strings.Contains(eventsText(r, "sK"), "Session started") {
		t.Fatal("a failure shown as a start")
	}
	code, out := inboxDo(t, r, "GET", "/setup/sessions", "", false)
	row := out["sessions"].([]any)[0].(map[string]any)
	if code != 200 || row["error"] != "start: the spawner has no Fly token" || row["failedAt"] == nil {
		t.Fatalf("%d %v", code, row)
	}
	// a path that gives no reason still leaves one
	r.st.Do(func(d *persisted) { d.Sessions["sK"].State, d.Sessions["sK"].Error = "paused", "" })
	r.st.Do(func(d *persisted) { d.Sessions["sK"].State = "failed" })
	r.st.Do(func(d *persisted) { s = *d.Sessions["sK"] })
	if s.Error != noReason || s.FailedAt == nil {
		t.Fatalf("%+v", s)
	}
	// not failed any more: no failedAt
	r.setState("sK", "paused", "")
	r.st.Do(func(d *persisted) { s = *d.Sessions["sK"] })
	if s.FailedAt != nil {
		t.Fatal("failedAt kept")
	}
	// the app's view
	var v map[string]any
	r.setState("sK", "failed", "boom")
	r.st.Do(func(d *persisted) { v = sessionView(d.Sessions["sK"], d) })
	if v["error"] != "boom" || v["failedAt"] == nil {
		t.Fatal(v)
	}
}
