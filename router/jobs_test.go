package main

import (
	"context"
	"strings"
	"testing"
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
