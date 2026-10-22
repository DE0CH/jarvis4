package main

// A handover starts the next machine once the old one has been told to stop, without waiting for Fly to report the old
// one destroyed; the cert still waits for the kill, which names the final snapshot (handover.go, DECISIONS 193).

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// slowFlyCore: v2Core whose kill of the old machine (m1) answers "not destroyed yet" killsLeft times (Fly slow to
// report it destroyed), whose start makes m2 and whose certify certifies it. events: what happened, in order.
type slowFlyCore struct {
	*v2Core
	mu        sync.Mutex
	killsLeft int
	refuse    bool // approve_by_dead_machine refuses (the resume goes to the phone)
	// withKill: Fly answers m1's kills only once m2's start has reached it, and reports m1 destroyed only once m2 is up.
	// The start and the first kill are sent together, so which one reaches the core first is the scheduler's pick;
	// a router that waited for a kill's answer (or Fly's report) before starting m2 would never see m1 destroyed.
	withKill bool
	sawStart chan struct{} // closed when the start came
	sawInit  bool
	events   []string
	killed   []map[string]any // the bodies of the kills that went through
}

func (c *slowFlyCore) event(e string) {
	c.mu.Lock()
	c.events = append(c.events, e)
	c.mu.Unlock()
}

func (c *slowFlyCore) log() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string{}, c.events...)
}

func (c *slowFlyCore) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	raw, _ := io.ReadAll(req.Body)
	req.Body = io.NopCloser(bytes.NewReader(raw))
	var b map[string]any
	json.Unmarshal(raw, &b)
	k := c.v2Core.key
	switch req.URL.Path {
	case "/start":
		c.event("start " + b["size"].(string))
		c.mu.Lock()
		select {
		case <-c.sawStart:
		default:
			close(c.sawStart)
		}
		c.mu.Unlock()
		writeJSON(w, 200, k.doc(map[string]any{"kind": "created", "id": "m2", "image": b["image"]}))
		return
	case "/init":
		c.event("started m2")
		c.mu.Lock()
		c.sawInit = true
		c.mu.Unlock()
		writeJSON(w, 200, k.doc(map[string]any{"kind": "started", "machine": map[string]string{"id": "m2", "requested": "x", "image": "x"}}))
		return
	case "/approve/by-dead-machine":
		if c.refuse {
			writeJSON(w, 403, k.doc(map[string]any{"error": "store set, image or options differ from the predecessor's (or a one-time input is asked for)"}))
			return
		}
		ch, _ := b["challenge"].(map[string]any)
		var p struct {
			Request map[string]any `json:"request"`
		}
		json.Unmarshal([]byte(ch["payload"].(string)), &p)
		writeJSON(w, 200, k.doc(map[string]any{"kind": "approval", "nonce": strings.Repeat("b", 64), "request": p.Request}))
		return
	case "/certify":
		c.event("certify " + b["machine"].(string))
		writeJSON(w, 200, k.doc(map[string]any{"kind": "succession-cert", "predecessorId": "m1", "line": "m1",
			"machine": map[string]string{"id": b["machine"].(string), "image": "x"}}))
		return
	case "/kill":
		m := b["machine"].(string)
		if m == "m1" && c.withKill {
			select {
			case <-c.sawStart:
			case <-time.After(10 * time.Second): // the router waits for this kill's answer before it starts m2
			}
		}
		c.mu.Lock()
		slow := m == "m1" && (c.killsLeft > 0 || c.withKill && !c.sawInit)
		if slow && c.killsLeft > 0 {
			c.killsLeft--
		}
		c.mu.Unlock()
		if slow {
			c.event("destroying " + m)
			writeJSON(w, 409, k.doc(map[string]any{"error": "machine " + m + " is destroying, not destroyed yet"}))
			return
		}
		sum := ""
		if s, ok := b["snapshot"].(map[string]any); ok {
			sum, _ = s["sha256"].(string)
		}
		c.mu.Lock()
		c.killed = append(c.killed, b)
		c.mu.Unlock()
		c.event("destroyed " + m)
		writeJSON(w, 200, k.doc(map[string]any{"kind": "killed", "id": m, "snapshot": sum}))
		return
	}
	c.v2Core.ServeHTTP(w, req)
}

func slowFlyRig(t *testing.T, killsLeft int) (*rig, *slowFlyCore) {
	rg, vc := v2Rig(t)
	c := &slowFlyCore{v2Core: vc, killsLeft: killsLeft, sawStart: make(chan struct{})}
	cs := httptest.NewServer(c)
	t.Cleanup(cs.Close)
	rg.r.core = &CoreClient{base: cs.URL, http: http.DefaultClient}
	step, istep := killStep, initStep
	killStep, initStep = 10*time.Millisecond, time.Millisecond
	t.Cleanup(func() { killStep, initStep = step, istep })
	return rg, c
}

func index(events []string, e string) int { return slices.Index(events, e) }

// a failed session that still has its machine (its snapshot already sent): Resume finishes the pause; Fly takes 30
// kill calls to report m1 destroyed, and m2 is created and up before that, certified only after
func TestAHandoverStartsTheNextMachineBeforeFlyReportsTheOldOneDestroyed(t *testing.T) {
	fastKills(t)
	rg, c := slowFlyRig(t, 30)
	c.withKill = true
	failedWithMachine(rg, "kill: core: fly destroy: timeout")
	if err := rg.r.Resume("s1", false); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "certify", func() bool { return index(c.log(), "certify m2") >= 0 })
	ev := c.log()
	destroyed, started := index(ev, "destroyed m1"), index(ev, "started m2")
	if index(ev, "start medium") < 0 || started < 0 || destroyed < 0 || started > destroyed {
		t.Fatalf("m2 is up before Fly reports m1 destroyed: %v", ev)
	}
	if index(ev, "start medium") > index(ev, "destroying m1") {
		t.Fatalf("m2's start goes with the first kill, not after Fly's report: %v", ev)
	}
	if index(ev, "certify m2") < destroyed {
		t.Fatalf("the cert waits for the kill: %v", ev)
	}
	n := 0
	for _, e := range ev {
		if strings.HasPrefix(e, "start ") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("one start (the spare taken), got %d: %v", n, ev)
	}
	// the kill that let the cert through named the final snapshot
	c.mu.Lock()
	k := c.killed[0]
	c.mu.Unlock()
	if snap, _ := k["snapshot"].(map[string]any); k["machine"] != "m1" || snap == nil || snap["sha256"] == "" || snap["required"] != true {
		t.Fatalf("the kill that let the cert through names the final snapshot: %v", k)
	}
	waitFor(t, "m2 is the session's", func() bool { return sessionOf(rg).MachineID == "m2" })
	// the resume's action has ended (its lock is released after its deferred end): its operation goes on until m2
	// reports in (startAndCertify took it over), so nothing writes into an operation that is already over
	waitFor(t, "the resume's action ended", func() bool { return !rg.r.busy("s1") })
	if rg.r.lcCurrent("s1") == nil {
		t.Fatal("the resume's operation ended before its machine reported in")
	}
	booted(t, rg, "m2")
}

// booted: m2 reports in, so the start's lifecycle operation ends (and writes nothing after the test)
func booted(t *testing.T, rg *rig, machine string) {
	rg.r.st.Do(func(d *persisted) { d.Sessions["s1"].Booted = machine })
	waitFor(t, "the operation's end", func() bool { return rg.r.lcCurrent("s1") == nil })
	waitFor(t, "the job's end", func() bool { return rg.r.ops.busyOf("s1") == nil })
	waitFor(t, "idle", func() bool {
		u, err := rg.r.lock("s1", "test-end")
		if err == nil {
			u()
		}
		return err == nil
	})
}

// Upgrade: the bigger machine starts right after "free", while the old one snapshots and Fly destroys it
func TestUpgradeStartsTheBiggerMachineWhileTheOldOneStops(t *testing.T) {
	fastKills(t)
	old := opsPoll
	opsPoll = time.Millisecond
	t.Cleanup(func() { opsPoll = old })
	rg, c := slowFlyRig(t, 30)
	rg.r.st.Do(func(d *persisted) {
		s := d.Sessions["s1"]
		s.State, s.MachineID, s.Cert = "started", "m1", v2Cert(rg, "m1", `{"v":1}`)
		d.Started["m1"] = &Started{ID: "m1", SigningKey: rg.mkey.pub()}
	})
	if _, err := rg.r.Upgrade("s1"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the spare's start", func() bool { return index(c.log(), "start large") >= 0 })
	if index(c.log(), "destroyed m1") >= 0 || index(c.log(), "destroying m1") >= 0 {
		t.Fatalf("the bigger machine starts while the old one is still there (after free): %v", c.log())
	}
	for end := time.Now().Add(20 * time.Second); index(c.log(), "certify m2") < 0; { // memFreeWait (5 s), then the pause
		if time.Now().After(end) {
			t.Fatalf("no certify: %v", c.log())
		}
		time.Sleep(20 * time.Millisecond)
	}
	ev := c.log()
	if index(ev, "certify m2") < index(ev, "destroyed m1") || strings.Count(strings.Join(ev, "|"), "start ") != 1 {
		t.Fatalf("one start, the cert after the kill: %v", ev)
	}
	if s := sessionOf(rg); s.Size != "large" {
		t.Fatalf("size %q", s.Size)
	}
	waitFor(t, "m2 is the session's", func() bool { return sessionOf(rg).MachineID == "m2" })
	booted(t, rg, "m2")
}

// the resume goes to the phone (the core won't answer it by itself): the spare isn't used and is destroyed
func TestASpareIsDestroyedWhenTheResumeGoesToThePhone(t *testing.T) {
	fastKills(t)
	rg, c := slowFlyRig(t, 5)
	c.refuse = true
	failedWithMachine(rg, "kill: core: fly destroy: timeout")
	if err := rg.r.Resume("s1", false); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the spare destroyed", func() bool { return index(c.log(), "destroyed m2") >= 0 })
	if index(c.log(), "certify m2") >= 0 {
		t.Fatalf("certified the spare: %v", c.log())
	}
	waitFor(t, "the approval", func() bool { return sessionOf(rg).State != "resuming" })
	if s := sessionOf(rg); s.State != "approval" {
		t.Fatalf("the resume waits for the phone: %s %q", s.State, s.Error)
	}
	// the resume sets "approval" a moment before it ends (its lifecycle record, then the unlock; DECISIONS 212): wait
	// for it, or its last write lands in t.TempDir while it is being removed (CI run 39533784239)
	waitFor(t, "the resume's action ended", func() bool { return !rg.r.busy("s1") })
}

// the old machine is still answering: the spare starts once the snapshot command (the stop) was sent, never before;
// the snapshot never comes, so the old machine is kept, nothing is killed or certified, and the spare goes
func TestTheSpareStartsAtTheStopAndGoesWhenTheOldMachineIsKept(t *testing.T) {
	fastKills(t)
	rg, c := slowFlyRig(t, 0)
	failedWithMachine(rg, "kill: core: fly destroy: timeout")
	sentFirst := make(chan bool, 1)
	spareStarted = func(sid string) {
		cmd, _ := takeCmd(rg.r, "m1")
		sentFirst <- cmd == "snapshot"
	}
	t.Cleanup(func() { spareStarted = nil })
	rg.r.st.Do(func(d *persisted) {
		s := d.Sessions["s1"]
		s.Booted = "m1"
		if s.Live == nil {
			s.Live = &Liveness{}
		}
		s.Live.LastReport = time.Now()
	})
	removeSnapshot(rg, "m1")
	if err := rg.r.Resume("s1", false); err != nil {
		t.Fatal(err)
	}
	select {
	case ok := <-sentFirst:
		if !ok {
			t.Fatal("the spare started before the snapshot command was sent")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no spare")
	}
	waitFor(t, "the spare destroyed", func() bool { return index(c.log(), "destroyed m2") >= 0 })
	ev := c.log()
	if index(ev, "destroyed m1") >= 0 || index(ev, "certify m2") >= 0 {
		t.Fatalf("the kept machine is killed or the spare certified: %v", ev)
	}
	if s := sessionOf(rg); s.MachineID != "m1" || s.State != "failed" {
		t.Fatalf("kept: %s %s %q", s.MachineID, s.State, s.Error)
	}
}

// a spare that asks for another machine than the start (here: another disk) isn't used
func TestASpareForAnotherMachineIsNotTaken(t *testing.T) {
	rg, c := slowFlyRig(t, 0)
	rg.r.launchSpare("s1", &nextMachine{Image: "img@sha256:" + strings.Repeat("1", 64), Size: "medium", DiskGB: 20})
	if d := rg.r.takeSpare("s1", nextMachine{Image: "img@sha256:" + strings.Repeat("1", 64), DiskGB: 30}); d != nil {
		t.Fatal("took a spare with another disk")
	}
	waitFor(t, "the spare destroyed", func() bool { return index(c.log(), "destroyed m2") >= 0 })
	rg.r.launchSpare("s1", &nextMachine{Image: "img@sha256:" + strings.Repeat("1", 64), Size: "", DiskGB: 20})
	if d := rg.r.takeSpare("s1", nextMachine{Image: "img@sha256:" + strings.Repeat("1", 64), Size: "medium", DiskGB: 20}); d == nil {
		t.Fatal("the same machine (\"\" = medium) wasn't taken")
	}
}

// a spare older than spareMaxAge is destroyed rather than certified: its machine would have stopped waiting
func TestAnOldSpareIsDestroyed(t *testing.T) {
	old := spareMaxAge
	spareMaxAge = 50 * time.Millisecond
	t.Cleanup(func() { spareMaxAge = old })
	rg, c := slowFlyRig(t, 0)
	rg.r.launchSpare("s1", &nextMachine{Image: "img@sha256:" + strings.Repeat("1", 64)})
	waitFor(t, "the old spare destroyed", func() bool { return index(c.log(), "destroyed m2") >= 0 })
	if d := rg.r.takeSpare("s1", nextMachine{Image: "img@sha256:" + strings.Repeat("1", 64)}); d != nil {
		t.Fatal("took an expired spare")
	}
}

func removeSnapshot(rg *rig, machine string) {
	rg.r.snapDrop(machine)
}
