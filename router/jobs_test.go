package main

import (
	"context"
	"strings"
	"testing"
	"time"
)

// deadJob: a running job of session sid whose holder died (its lease ran out)
func deadJob(t *testing.T, r *Router, sid, kind, args string) {
	t.Helper()
	if _, err := r.pool().pool.Exec(context.Background(), `INSERT INTO jobs (id, session_id, kind, args, state, owner, lease_until)
		VALUES ($1, $2, $3, $4, 'running', 'a-dead-replica', now() - interval '1 second')`, randID(), sid, kind, args); err != nil {
		t.Fatal(err)
	}
}

// one running job per session on every replica alike: a second action is refused with what runs
func TestOneJobPerSession(t *testing.T) {
	rg := newRig(t)
	deadJob(t, rg.r, "s1", "resuming-elsewhere", "{}")
	rg.r.pool().pool.Exec(context.Background(), "UPDATE jobs SET lease_until = now() + interval '1 hour' WHERE session_id = 's1'")
	if err := rg.r.Pause("s1"); err == nil || !strings.Contains(err.Error(), "resuming-elsewhere") {
		t.Fatalf("a second action: %v", err)
	}
	if !rg.r.busy("s1") {
		t.Fatal("not busy")
	}
}

// a pause whose replica died is carried on by another and reaches paused; a destroy likewise reaches its record; a
// kind with no steps of its own is cut off as before
func TestAJobWhoseHolderDiedIsCarriedOn(t *testing.T) {
	rg := newRig(t)
	runningM2(rg, false)
	rg.writeSnapshot(t, "m2", rg.files) // the machine had sent its final snapshot before its replica died
	rg.r.setState("s1", "pausing", "")
	deadJob(t, rg.r, "s1", "pausing", "{}")
	rg.r.jobsTick()
	if err := rg.r.waitActionEnd("s1", "paused"); err != nil {
		t.Fatal(err)
	}
	if rg.r.busy("s1") {
		t.Fatal("the carried-on job didn't end")
	}

	rg2 := newRig(t)
	rg2.r.setState("s1", "destroying", "")
	deadJob(t, rg2.r, "s1", "destroying", `{"force":true}`)
	rg2.r.jobsTick()
	waitFor(t, "the record", func() bool { return rg2.r.record("s1") != nil })

	rg3 := newRig(t)
	rg3.r.st.Do(func(d *persisted) { d.Sessions["s1"].State, d.Sessions["s1"].MachineID = "resuming", "" })
	deadJob(t, rg3.r, "s1", "starting", "{}")
	rg3.r.jobsTick()
	if s := sessionS1(rg3); s.State != "failed" || !strings.Contains(s.Error, "cut off") {
		t.Fatalf("%+v", s)
	}
}

// one replica leads at a time: a second takes the lease only once the first's has run out
func TestSchedulerLease(t *testing.T) {
	r := newTestRouter(t)
	old := routerID
	t.Cleanup(func() { routerID = old; leadUntil.Store(0) })
	routerID = "replica-a"
	if !r.leaseOnce() {
		t.Fatal("the first replica didn't take the lease")
	}
	routerID, _ = "replica-b", leadUntil.Swap(0)
	if r.leaseOnce() {
		t.Fatal("a second replica took a lease the first holds")
	}
	r.pool().pool.Exec(context.Background(), "UPDATE leader SET until = now() - interval '1 second'")
	if !r.leaseOnce() {
		t.Fatal("the second replica didn't take the lapsed lease")
	}
}

// a kernel start carried on while the first holder's spawn is still out: the spawner answers the repeated spawn of the
// source with the machine it already made, so the line gets exactly one machine; and a start the records show done
// (initialising) leaves nothing to do
func TestAKernelStartCarriedOn(t *testing.T) {
	rg, k := kernelRig(t)
	k.Fly.Booting = true // machines stay "starting": the first spawn waits in its init loop
	sid, err := rg.r.CreateSession(NewSession{Label: "carried", Harness: "claude"})
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
	waitFor(t, "the first spawn", func() bool { return len(k.Fly.Machines) == 1 })
	if !rg.r.busy(sid) {
		t.Fatal("the start isn't a job")
	}
	// the holder "died": another replica carries the start on from the records (state starting, no machine yet)
	done := make(chan bool)
	go func() { rg.r.kernelContinue(sid, func() { done <- true }) }()
	time.Sleep(300 * time.Millisecond)
	for id := range k.Fly.Machines {
		k.Fly.Up(id)
	}
	<-done
	waitFor(t, "initialising", func() bool { s := kernelSession(rg, sid); return s.MachineID != "" && s.Kernel.MachineCert != nil })
	if n := len(k.Fly.Machines); n != 1 {
		t.Fatalf("%d machines for one start", n)
	}
	// nothing left to do: carrying it on again spawns nothing
	rg.r.kernelContinue(sid, func() {})
	if n := len(k.Fly.Machines); n != 1 {
		t.Fatalf("%d machines after a second carry-on", n)
	}
}

// a permission-mode switch whose holder died is run again by another replica
func TestAModeSwitchCarriedOn(t *testing.T) {
	r := newTestRouter(t)
	addSession(r, "sA", "started", "mA", false)
	stop := make(chan struct{})
	defer close(stop)
	cmds := answerExecs(r, "mA", 0, stop)
	deadJob(t, r, "sA", "mode", `{"mode":"auto"}`)
	r.jobsTick()
	waitFor(t, "the switch", func() bool {
		var m string
		r.st.Do(func(d *persisted) { m = d.Sessions["sA"].PermissionMode })
		return m == "auto" && !r.busy("sA")
	})
	if len(*cmds) != 1 {
		t.Fatalf("commands %v", *cmds)
	}
}
