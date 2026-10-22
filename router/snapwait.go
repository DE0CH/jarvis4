package main

// How long a pause or destroy waits for the machine's final snapshot (DECISIONS 214): for as long as the snapshot
// makes progress, with no overall limit (a large upload or a bad network may take very long). The wait ends when
//
//   - the snapshot arrives (committed, carried over, "nothing to snapshot"), or the machine reports it failed;
//   - nothing has moved for SnapshotStall (SNAPSHOT_STALL_SECONDS, default 10 min): the stream is stuck, or the
//     supervisor is stuck before it (the freeze, the repos' state);
//   - nothing has moved for silentAfter (3 min) and the machine's last status report is older than that too: the
//     machine is gone (its supervisor reports at least every 60 s, also while the session is frozen).
//
// What counts as progress: the snapshot command being sent (the clock starts), every read of the snapshot's body as
// it arrives at the router (POST /m/snapshot-stream, or the whole-file POST /m/snapshot of an older image), and a
// progress report (POST /m/snapshot-progress, snapprogress.go) whose numbers moved (phase, bytes read, measured,
// sent). A report that repeats the same numbers is a live machine making no progress, so it doesn't count.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"
)

// The wait itself is a row of snapshot_waits (mq.go's migration): the replica that streams the snapshot in, or takes a
// progress report, moves it; the one that waits reads it. Progress from the stream is written at most every snapMoveEvery.

// snapWaitToken: the wait a pause started (a later wait for the same machine replaces it)
type snapWaitToken string

// snapMoveEvery: the stream's progress is written at most this often (a read of the body happens many times a second)
var snapMoveEvery = 100 * time.Millisecond

var snapMoveMu sync.Mutex
var snapMoveAt = map[string]time.Time{} // machine → when this replica last wrote its progress

func (r *Router) swExec(sql string, args ...any) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := r.pool().pool.Exec(ctx, sql, args...)
	return err
}

func (r *Router) awaitSnapshot(machine string) snapWaitToken {
	tok := randID()
	r.swExec(`INSERT INTO snapshot_waits (machine_id, token, moved_at) VALUES ($1, $2, now())
		ON CONFLICT (machine_id) DO UPDATE SET token = $2, moved_at = now(), progress = NULL, done = false, error = ''`, machine, tok)
	return snapWaitToken(tok)
}

func (r *Router) snapshotArrived(machine string) {
	r.swExec("UPDATE snapshot_waits SET done = true WHERE machine_id = $1", machine)
	r.swExec("SELECT pg_notify('mq', $1)", "w:"+machine)
}

// stopAwaiting: the wait ended without the snapshot (a late one still lands as the machine's snapshot, which the next
// pause finds), so later progress reports aren't shown any more
func (r *Router) stopAwaiting(machine string, tok snapWaitToken) {
	r.swExec("DELETE FROM snapshot_waits WHERE machine_id = $1 AND token = $2", machine, string(tok))
}

// snapshotMoved: a sign of progress on the machine's awaited snapshot (no-op when none is awaited)
func (r *Router) snapshotMoved(machine string) {
	snapMoveMu.Lock()
	if time.Since(snapMoveAt[machine]) < snapMoveEvery {
		snapMoveMu.Unlock()
		return
	}
	snapMoveAt[machine] = time.Now()
	snapMoveMu.Unlock()
	r.swExec("UPDATE snapshot_waits SET moved_at = now() WHERE machine_id = $1", machine)
}

// snapshotReported: a progress report; it counts as progress only when its numbers moved
func (r *Router) snapshotReported(machine string, p SnapProgress) {
	b, _ := json.Marshal(p)
	r.swExec("UPDATE snapshot_waits SET progress = $2, moved_at = now() WHERE machine_id = $1 AND progress IS DISTINCT FROM $2::jsonb", machine, string(b))
}

// snapWaitRow: the wait's state (ok false: none for this token)
func (r *Router) snapWaitRow(machine string) (moved time.Time, done bool, ok bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := r.pool().pool.QueryRow(ctx, "SELECT moved_at, done FROM snapshot_waits WHERE machine_id = $1", machine).Scan(&moved, &done)
	return moved, done, err == nil
}

// snapshotQuiet: how long the awaited snapshot has shown no progress
func (r *Router) snapshotQuiet(machine string) time.Duration {
	if moved, _, ok := r.snapWaitRow(machine); ok {
		return time.Since(moved)
	}
	return 0
}

func (r *Router) snapshotAwaited(machine string) bool {
	_, done, ok := r.snapWaitRow(machine)
	return ok && !done
}

// waitSnapshot: until the snapshot arrives (nil), or it stalls or the machine is gone (the error says which)
func (r *Router) waitSnapshot(machine string, tok snapWaitToken) error {
	stall := r.cfg.SnapshotStall
	if stall <= 0 {
		stall = 10 * time.Minute
	}
	poll := min(max(stall/20, 10*time.Millisecond), time.Second)
	ch, cancel := r.notes.sub("w:" + machine)
	defer cancel()
	tick := time.NewTicker(poll)
	defer tick.Stop()
	for {
		moved, done, ok := r.snapWaitRow(machine)
		if ok && done {
			return nil // the row stays (a reported failure is read from it next); the next wait resets it
		}
		quiet := time.Duration(0)
		if ok {
			quiet = time.Since(moved)
		}
		if quiet >= stall {
			r.stopAwaiting(machine, tok)
			return fmt.Errorf("the machine's snapshot made no progress for %s", waitText(quiet))
		}
		if quiet >= silentAfter {
			if last := r.lastReport(machine); time.Since(last) >= silentAfter {
				r.stopAwaiting(machine, tok)
				return fmt.Errorf("the machine went silent during its snapshot (last report %s, no progress for %s)",
					last.UTC().Format("2006-01-02 15:04 UTC"), waitText(quiet))
			}
		}
		select {
		case <-ch:
		case <-tick.C:
		}
	}
}

// lastReport: when the machine's supervisor last reported its status (zero: never, or not the session's machine)
func (r *Router) lastReport(machine string) (t time.Time) {
	r.st.Do(func(d *persisted) {
		if s := d.Sessions[d.Machines[machine]]; s != nil && s.MachineID == machine && s.Live != nil {
			t = s.Live.LastReport
		}
	})
	return
}

// movedReader: a snapshot body as it arrives; every read is progress
type movedReader struct {
	r       io.Reader
	router  *Router
	machine string
}

func (m movedReader) Read(b []byte) (int, error) {
	n, err := m.r.Read(b)
	if n > 0 {
		m.router.snapshotMoved(m.machine)
	}
	return n, err
}
