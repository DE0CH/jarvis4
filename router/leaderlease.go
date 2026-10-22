package main

// The scheduler lease (docs/STATE.md 4, step 8): the periodic loops (wakeups and crons, leases, watches, the budget
// caps, the Inbox and outcomes, messages, tasks, the Claude logins' refresh, the volume sweep, Discord, the autopilot,
// the roster, the next core, the queue sweep) run on one replica only: the one holding the row `scheduler` of
// `leader`, taken for 30 s and renewed every 10 s. Each loop waits at the top of every round until this replica leads
// (awaitLead). A replica that loses the database stops leading when its last renewal runs out (5 s before the row's,
// so two never lead at once). Jobs (jobs.go) and the machines' long polls run on every replica.

import (
	"context"
	"log"
	"sync/atomic"
	"time"
)

const (
	leaseFor   = 30 * time.Second
	leaseRenew = 10 * time.Second
	leaseSafe  = 5 * time.Second
)

// leadUntil: until when this replica leads (unix nanos; 0: it doesn't)
var leadUntil atomic.Int64

func leads() bool { return time.Now().UnixNano() < leadUntil.Load() }

// leaseOnce: take or renew the lease; whether this replica leads now
func (r *Router) leaseOnce() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	var holder string
	err := r.pool().pool.QueryRow(ctx, `INSERT INTO leader (name, holder, until) VALUES ('scheduler', $1, now() + interval '30 seconds')
		ON CONFLICT (name) DO UPDATE SET holder = $1, until = excluded.until WHERE leader.until < now() OR leader.holder = $1
		RETURNING holder`, routerID).Scan(&holder)
	if err != nil || holder != routerID {
		if leads() && err != nil && err.Error() != "no rows in result set" {
			log.Printf("leader: renewing: %v (leading until the lease runs out)", err)
		}
		return leads()
	}
	was := leads()
	leadUntil.Store(start.Add(leaseFor - leaseSafe).UnixNano())
	if !was {
		log.Printf("leader: this replica (%s) runs the scheduler", routerID)
	}
	return true
}

// leaseLoopScheduler: the lease, for the life of the process
func (r *Router) leaseLoopScheduler() {
	for {
		r.leaseOnce()
		time.Sleep(leaseRenew)
	}
}

// awaitLead: returns once this replica leads (at once when it does)
func awaitLead() {
	for !leads() {
		time.Sleep(time.Second)
	}
}
