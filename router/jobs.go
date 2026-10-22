package main

// A session's lifecycle action is a job (docs/STATE.md 3, step 7): a row of `jobs`, at most one running per session
// (a unique index: the clash is the 409 "in the middle of another action" on every replica alike), held by the replica
// that runs it under a lease it renews every jobLease/3. A replica that dies (a crash, a kill past the grace period)
// stops renewing; once the lease has run out, any replica's jobsLoop claims the job and carries it on:
//
//	pausing     run again (pauseRun): the final snapshot is the one the machine signed (it signs only one), the kill
//	            answers the same cert
//	destroying  run again (destroyRun): the kill as above, the archive skips what it holds, the line's burn is kept
//	            (a one-shot's report hook doesn't survive: its DM is lost, the destroy isn't)
//	starting    a kernel line's start or resume: carried on from where the records say it is (kernelContinue)
//	mode        the permission-mode switch run again (setting the mode it already has is a no-op)
//	account     the machine told again, the switch checked as a fresh one
//	anything else (an old-core line's start or resume: Jarvis 4 runs no old core): cut off as before (endCutOff), the
//	            session failed or paused with the reason, for Deyao to run again
//
// An approved add-store on a kernel line is answered within its request (kernelline.go respondKernelAdd): a replica
// that dies fails the request, and the app sends the same signatures again (every step of it is safe to repeat).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// jobLease: how long a job's holder may go silent before another replica carries it on (a var: tests shorten it)
var jobLease = 60 * time.Second

// routerID: this process, as a job's owner
var routerID = func() string {
	h, _ := os.Hostname()
	return h + "-" + randID()
}()

type jobRow struct {
	ID, Session, Kind string
	Args              json.RawMessage
	Since             time.Time
}

func (r *Router) jobCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 10*time.Second)
}

// jobStart: the session's running job, held by this replica (errBusy when another runs)
func (r *Router) jobStart(session, kind string, args any) (string, error) {
	a, _ := json.Marshal(args)
	if args == nil {
		a = []byte("{}")
	}
	id := randID()
	ctx, cancel := r.jobCtx()
	defer cancel()
	_, err := r.pool().pool.Exec(ctx, `INSERT INTO jobs (id, session_id, kind, args, state, owner, lease_until)
		VALUES ($1, $2, $3, $4, 'running', $5, now() + $6::interval)`, id, session, kind, a, routerID, fmt.Sprintf("%d milliseconds", jobLease.Milliseconds()))
	var pe *pgconn.PgError
	if errors.As(err, &pe) && pe.Code == "23505" {
		var k string
		var since time.Time
		if r.pool().pool.QueryRow(ctx, "SELECT kind, created_at FROM jobs WHERE session_id = $1 AND state = 'running'", session).Scan(&k, &since) == nil {
			return "", fmt.Errorf("%w: %s, running since %s; try again once it ends (/api/state shows it as busy)", errBusy, k, since.UTC().Format("15:04:05 UTC"))
		}
		return "", errBusy
	}
	return id, err
}

// jobHold: the lease renewed until the returned end is called with the job's outcome
func (r *Router) jobHold(id string) func(state, errMsg string) {
	stop := make(chan struct{})
	go func() {
		t := time.NewTicker(jobLease / 3)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				ctx, cancel := r.jobCtx()
				r.pool().pool.Exec(ctx, "UPDATE jobs SET lease_until = now() + $2::interval, updated_at = now() WHERE id = $1 AND owner = $3 AND state = 'running'",
					id, fmt.Sprintf("%d milliseconds", jobLease.Milliseconds()), routerID)
				cancel()
			}
		}
	}()
	var once sync.Once
	return func(state, errMsg string) {
		once.Do(func() {
			close(stop)
			if state == "abandoned" {
				return // the lease is left to lapse: jobsLoop carries it on
			}
			ctx, cancel := r.jobCtx()
			defer cancel()
			if _, err := r.pool().pool.Exec(ctx, "UPDATE jobs SET state = $2, error = $3, updated_at = now() WHERE id = $1 AND state = 'running'", id, state, errMsg); err != nil {
				log.Printf("job %s: ending it: %v", id, err)
			}
		})
	}
}

// jobBusy: the session has a running job (on any replica)
func (r *Router) jobBusy(session string) bool {
	ctx, cancel := r.jobCtx()
	defer cancel()
	var b bool
	r.pool().pool.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM jobs WHERE session_id = $1 AND state = 'running')", session).Scan(&b)
	return b
}

// jobClaimExpired: a running job whose holder stopped renewing, now this replica's (nil: none)
func (r *Router) jobClaimExpired() (*jobRow, error) {
	ctx, cancel := r.jobCtx()
	defer cancel()
	var j jobRow
	err := r.pool().pool.QueryRow(ctx, `UPDATE jobs SET owner = $1, lease_until = now() + $2::interval, attempts = attempts + 1, updated_at = now()
		WHERE id = (SELECT id FROM jobs WHERE state = 'running' AND lease_until < now() ORDER BY lease_until FOR UPDATE SKIP LOCKED LIMIT 1)
		RETURNING id, session_id, kind, args, created_at`, routerID, fmt.Sprintf("%d milliseconds", jobLease.Milliseconds())).Scan(&j.ID, &j.Session, &j.Kind, &j.Args, &j.Since)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return nil, nil
		}
		return nil, err
	}
	return &j, nil
}

// jobsLoop: every few seconds, jobs whose holder died are carried on here
func (r *Router) jobsLoop(every time.Duration) {
	for {
		time.Sleep(every)
		r.jobsTick()
	}
}

func (r *Router) jobsTick() {
	for {
		j, err := r.jobClaimExpired()
		if err != nil {
			log.Printf("jobs: %v", err)
			return
		}
		if j == nil {
			return
		}
		r.carryOn(j)
	}
}

// carryOn: a job another replica held when it died
func (r *Router) carryOn(j *jobRow) {
	end := r.jobHold(j.ID)
	var s Session
	r.st.Do(func(d *persisted) {
		if x := d.Sessions[j.Session]; x != nil {
			s = *x
		}
	})
	log.Printf("jobs: carrying on %s of session %s (its holder stopped renewing)", j.Kind, j.Session)
	unlock := r.jobUnlock(j.Session, j.Kind, end)
	switch {
	case s.ID == "":
		unlock()
	case j.Kind == "pausing" && s.State == "pausing" && s.MachineID != "":
		op := r.lcBegin(j.Session, "pause")
		op.machine(s.MachineID)
		op.note("", "carried on by another router replica: its holder stopped (the pause runs again from the snapshot)")
		go r.pauseRun(j.Session, s.MachineID, nil, unlock, op)
	case j.Kind == "starting" && s.Kernel != nil:
		go r.kernelContinue(j.Session, unlock)
	case j.Kind == "mode" && s.State == "started":
		var a struct{ Mode string }
		json.Unmarshal(j.Args, &a)
		wj, err := r.ops.startJob(j.Session, "permission-mode")
		if err != nil {
			unlock()
			return
		}
		go r.modeRun(j.Session, a.Mode, wj, unlock)
	case j.Kind == "account" && s.State == "started":
		var a struct {
			Store, Harness string
			Continue       bool
		}
		json.Unmarshal(j.Args, &a)
		wj, err := r.ops.startJob(j.Session, "account")
		if err != nil {
			unlock()
			return
		}
		// the account is already the session's (set before the job began): the machine is told again and its switch
		// is checked as a fresh one (what ran before isn't known here)
		r.send(s.MachineID, "claude-account")
		go func() {
			defer unlock()
			to := r.accounts().hub(a.Store)
			if to == nil {
				r.ops.phase(wj, "failed", fmt.Errorf("no Claude account %s", a.Store))
				return
			}
			if err := r.runAccountSwitch(wj, j.Session, s.MachineID, a.Harness, Registry{}, to, a.Continue); err != nil {
				r.ops.phase(wj, "failed", err)
				return
			}
			r.ops.phase(wj, "done", nil)
		}()
	case j.Kind == "destroying" && s.State == "destroying":
		var a struct{ Force bool }
		json.Unmarshal(j.Args, &a)
		op := r.lcBegin(j.Session, "destroy")
		op.machine(s.MachineID)
		op.note("", "carried on by another router replica: its holder stopped (the destroy runs again)")
		go r.destroyRun(j.Session, s, destroyOpts{force: a.Force}, unlock, op)
	default:
		r.cutOffSession(j.Session)
		end("failed", "cut off: its holder stopped")
		r.ops.setBusy(j.Session, "")
	}
}

// jobUnlock: what an action calls when it ends (the job done, the busy mark gone)
func (r *Router) jobUnlock(session, kind string, end func(string, string)) func() {
	r.ops.setBusy(session, kind)
	var once sync.Once
	return func() {
		once.Do(func() {
			r.ops.setBusy(session, "")
			if stateWriteFailing.Load() {
				// a Do gave up (state.go): this job's last change may be lost, so it isn't marked done; its lease
				// lapses and a replica carries it on
				end("abandoned", "")
				return
			}
			end("done", "")
		})
	}
}

// myRunningJobs: the jobs this replica holds now
func (r *Router) myRunningJobs() int {
	ctx, cancel := r.jobCtx()
	defer cancel()
	var n int
	r.pool().pool.QueryRow(ctx, "SELECT count(*) FROM jobs WHERE owner = $1 AND state = 'running'", routerID).Scan(&n)
	return n
}
