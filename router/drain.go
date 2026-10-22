package main

// Draining on SIGTERM (Deyao, 2026-10-13). The router runs as one pod with strategy Recreate, so a rollout ends the
// old pod before the new one starts. Every lifecycle action (pause, resume, destroy, a start after the phone's
// approval, a permission-mode switch, a restart or upgrade job) runs in a goroutine of the router that began it; a
// rollout used to cut those off half way (a new session's first start after Face ID failed with "start cut off by a
// router restart" and needed a second approval).
//
// Now each such goroutine is tracked here: lock() (flows.go) and Respond() begin one, the goroutine ends it. On
// SIGTERM the router stops beginning new ones — the caller gets 503 "router updating, try again shortly" (writeErr),
// and a scheduler/autopilot/task tick sees errBusy and tries again on its next tick, i.e. in the next pod — while
// everything already running finishes. Reads, the machines' reports (/m: status, snapshots — a pause in flight needs
// its snapshot) and the Claude login's long polls go on being served throughout. Then the process exits.
// k8s/control/apps/router/router.yaml gives the drain terminationGracePeriodSeconds (DRAIN_SECONDS under it). A pause
// waits for its snapshot as long as it makes progress (snapwait.go), so a snapshot still uploading when the drain gives
// up is cut off with the old pod like any other action (the session goes failed and keeps its machine; Pause again).
//
// A crash (OOM, node reboot, a drain past the grace period) still cuts actions off; endCutOff (below) turns what
// it left behind into a plain failed or paused session with the reason, and Deyao runs the action again. Nothing
// is redone by itself (Deyao, 2026-10-13: no save-to-disk-and-redo).

import (
	"errors"
	"log"
	"sync"
	"time"
)

// errDraining: the router is updating. It is an errBusy too, so every automatic caller that already backs off a
// busy session (schedule.go, vouch.go, tasks.go, watches) treats it as "try again later", not as a failure.
var errDraining error = drainingErr{}

type drainingErr struct{}

func (drainingErr) Error() string {
	return drainingMsg
}

// drainingMsg: what a refused action hears during a drain (its start is matched by e2e and leader.go's own 503)
const drainingMsg = "router updating, try again shortly: the actions already running finish first, then the new router takes new ones (usually within a minute or two, at most 29 minutes behind a long pause)"

func (drainingErr) Is(target error) bool { return target == errBusy }

type drainState struct {
	mu       sync.Mutex
	draining bool
	started  chan struct{} // closed when the drain begins
	wg       sync.WaitGroup
	next     int
	inflight map[int]string // what is running, for the drain's log
	jobs     map[string]int // session → running multi-step jobs (restart, upgrade): their own steps still begin
}

// begin: a lifecycle goroutine starts (what: for the log). Refused while draining, unless the session has a job of
// its own running that this is a step of (a restart's resume after its pause). done ends it; call it exactly once.
func (r *Router) begin(session, what string) (done func(), err error) {
	d := &r.drain
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.draining && d.jobs[session] == 0 {
		return nil, errDraining
	}
	if d.inflight == nil {
		d.inflight, d.jobs = map[int]string{}, map[string]int{}
	}
	d.next++
	n := d.next
	d.inflight[n] = what + " " + session
	d.wg.Add(1)
	var once sync.Once
	return func() {
		once.Do(func() {
			d.mu.Lock()
			delete(d.inflight, n)
			d.mu.Unlock()
			d.wg.Done()
		})
	}, nil
}

// beginJob: a multi-step job (restart, upgrade) that chains lifecycle actions on one session: tracked as a whole,
// and its own steps may begin during a drain, so a drain that starts between its pause and its resume still lets
// it finish rather than leaving the session paused half way.
func (r *Router) beginJob(session, what string) (done func(), err error) {
	end, err := r.begin(session, what)
	if err != nil {
		return nil, err
	}
	d := &r.drain
	d.mu.Lock()
	d.jobs[session]++
	d.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			d.mu.Lock()
			if d.jobs[session]--; d.jobs[session] <= 0 {
				delete(d.jobs, session)
			}
			d.mu.Unlock()
			end()
		})
	}, nil
}

// Undrain: lifecycle actions are taken again (move.go: a move that was aborted after its freeze had drained)
func (r *Router) Undrain() {
	d := &r.drain
	d.mu.Lock()
	if d.draining {
		d.draining = false
		d.started = nil
		log.Printf("drain ended: lifecycle actions are taken again")
	}
	d.mu.Unlock()
}

func (d *drainState) startedCh() chan struct{} {
	if d.started == nil {
		d.started = make(chan struct{})
	}
	return d.started
}

// sleepUnlessDraining: sleeps for t; true = a drain began (now or during the sleep)
func (r *Router) sleepUnlessDraining(t time.Duration) bool {
	r.drain.mu.Lock()
	ch := r.drain.startedCh()
	r.drain.mu.Unlock()
	select {
	case <-ch:
		return true
	case <-time.After(t):
		return false
	}
}

func (r *Router) draining() bool {
	r.drain.mu.Lock()
	defer r.drain.mu.Unlock()
	return r.drain.draining
}

// Drain: refuse new lifecycle actions, then wait (at most max) for the running ones. true = all finished.
func (r *Router) Drain(max time.Duration) bool {
	return r.drainUntil(max, nil)
}

// drainUntil: Drain that also stops waiting once abort closes (nextcore.go: the flip's standby went away); false then.
// It stays draining either way: the caller undrains.
func (r *Router) drainUntil(max time.Duration, abort <-chan struct{}) bool {
	d := &r.drain
	d.mu.Lock()
	if !d.draining {
		close(d.startedCh())
	}
	d.draining = true
	running := make([]string, 0, len(d.inflight))
	for _, w := range d.inflight {
		running = append(running, w)
	}
	d.mu.Unlock()
	log.Printf("draining: new lifecycle actions are refused; waiting for %d running: %v", len(running), running)
	done := make(chan struct{})
	go func() { d.wg.Wait(); close(done) }()
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	deadline := time.After(max)
	for {
		select {
		case <-done:
			log.Printf("drained")
			return true
		case <-tick.C:
			d.mu.Lock()
			log.Printf("draining: still running: %v", d.inflight)
			d.mu.Unlock()
		case <-abort:
			d.mu.Lock()
			log.Printf("drain aborted; still running: %v", d.inflight)
			d.mu.Unlock()
			return false
		case <-deadline:
			d.mu.Lock()
			log.Printf("drain gave up after %s; cut off: %v", max, d.inflight)
			d.mu.Unlock()
			return false
		}
	}
}

// errLimitDraining: a start waiting out Fly's machine limit when the drain began. The wait (up to machineLimitWait)
// would hold the rollout for hours, so the start ends instead (Deyao starts it again; DECISIONS).
var errLimitDraining = errors.New("the Fly org is at its machine limit and the router is updating: start it again")

// endCutOff: at start, sessions a crash left in the middle of an action that no job holds (jobs.go: a job whose
// holder died is carried on by jobsLoop instead) become plain sessions with the reason; Deyao runs the action again. A
// cut-off resume's line is still there (the core marks the predecessor used only at certify), so it is paused again; a
// new line's start, a pause or a destroy is failed. A machine the cut-off start had made, never certified, holds no
// secret and shows on the Machines tab with no session (attention), where Deyao can destroy it.
func (r *Router) endCutOff() {
	var ids []string
	r.st.Do(func(d *persisted) {
		for id := range d.Sessions {
			ids = append(ids, id)
		}
	})
	for _, id := range ids {
		if !r.jobBusy(id) {
			r.cutOffSession(id)
		}
	}
}

// cutOffSession: a session in the middle of an action nobody runs any more, made a plain one with the reason
func (r *Router) cutOffSession(id string) {
	r.st.Do(func(d *persisted) {
		s := d.Sessions[id]
		if s == nil {
			return
		}
		why := ""
		switch s.State {
		case "resuming", "starting":
			if s.hasLine() && s.MachineID == "" {
				s.State, s.Error = "paused", "the resume was cut off by a router crash: resume it again"
			} else {
				s.State, s.Error = "failed", "the start was cut off by a router crash: start it again"
			}
			why = s.Error
		case "pausing":
			s.State, s.Error = "failed", "the pause was cut off by a router crash (the machine may still run): pause it again"
			why = s.Error
		case "destroying":
			s.State, s.Error = "failed", "the destroy was cut off by a router crash: destroy it again"
			why = s.Error
		}
		if why != "" {
			s.Waiting = ""
			log.Printf("session %s: %s", id, why)
		}
	})
}
