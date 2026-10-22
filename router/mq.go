package main

// The machines' queue in the database (docs/STATE.md 5, step 6): what waits for a machine (a supervisor command, a
// holder-signed exec, an attested delivery) is a row of machine_queue; the machine's long poll (GET /m/commands) takes
// the oldest untaken row (FOR UPDATE SKIP LOCKED: two polls never take the same one) on whichever replica it reaches,
// and an exec's or a delivery's answer comes back on that row. Waiting is LISTEN/NOTIFY on one channel, mq (payload
// m:<machine> for a new row, a:<ref> for an answer, w:<machine> for a snapshot wait), with a short poll beside it so a
// lost notification only delays.

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

// mqRecheck: how often a waiter looks again without a notification
var mqRecheck = 2 * time.Second

// broker: this replica's waiters, woken by the database's notifications
type broker struct {
	mu   sync.Mutex
	subs map[string]map[chan struct{}]bool
}

func (b *broker) sub(key string) (chan struct{}, func()) {
	ch := make(chan struct{}, 1)
	b.mu.Lock()
	if b.subs == nil {
		b.subs = map[string]map[chan struct{}]bool{}
	}
	if b.subs[key] == nil {
		b.subs[key] = map[chan struct{}]bool{}
	}
	b.subs[key][ch] = true
	b.mu.Unlock()
	return ch, func() {
		b.mu.Lock()
		delete(b.subs[key], ch)
		if len(b.subs[key]) == 0 {
			delete(b.subs, key)
		}
		b.mu.Unlock()
	}
}

func (b *broker) fire(key string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for ch := range b.subs[key] {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

func (b *broker) fireAll() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, m := range b.subs {
		for ch := range m {
			select {
			case ch <- struct{}{}:
			default:
			}
		}
	}
}

// listenLoop: LISTEN mq on a connection of its own, for the life of the database (reconnecting; every waiter looks
// again after a reconnect, since notifications in between are lost)
func (db *DB) listenLoop(b *broker) {
	for {
		select {
		case <-db.done:
			return
		default:
		}
		err := func() error {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go func() {
				select {
				case <-db.done:
					cancel()
				case <-ctx.Done():
				}
			}()
			c, err := db.pool.Acquire(ctx)
			if err != nil {
				return err
			}
			defer c.Release()
			if _, err := c.Exec(ctx, "LISTEN mq"); err != nil {
				return err
			}
			b.fireAll()
			for {
				n, err := c.Conn().WaitForNotification(ctx)
				if err != nil {
					return err
				}
				b.fire(n.Payload)
			}
		}()
		select {
		case <-db.done:
			return
		case <-time.After(time.Second):
		}
		if err != nil {
			log.Printf("mq: listening: %v (again)", err)
		}
	}
}

// mqItem: one taken row
type mqItem struct {
	Kind string
	Body json.RawMessage
}

func (r *Router) mqCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 10*time.Second)
}

// mqPut: a row for the machine (bounded: at most max untaken of its kind; 0 = no bound) → false when full
func (r *Router) mqPut(machine, kind, ref string, body any, max int) (bool, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return false, err
	}
	ctx, cancel := r.mqCtx()
	defer cancel()
	ok := true
	err = pgx.BeginFunc(ctx, r.pool().pool, func(tx pgx.Tx) error {
		if max > 0 {
			var n int
			if err := tx.QueryRow(ctx, "SELECT count(*) FROM machine_queue WHERE machine_id = $1 AND kind = $2 AND taken_at IS NULL",
				machine, kind).Scan(&n); err != nil {
				return err
			}
			if n >= max {
				ok = false
				return nil
			}
		}
		if _, err := tx.Exec(ctx, "INSERT INTO machine_queue (machine_id, kind, ref, body) VALUES ($1, $2, $3, $4)", machine, kind, ref, b); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, "SELECT pg_notify('mq', $1)", "m:"+machine)
		return err
	})
	return ok && err == nil, err
}

// mqTake: the machine's oldest untaken row (nil: none)
func (r *Router) mqTake(machine string) (*mqItem, error) {
	ctx, cancel := r.mqCtx()
	defer cancel()
	var it mqItem
	err := r.pool().pool.QueryRow(ctx, `UPDATE machine_queue SET taken_at = now() WHERE id = (SELECT id FROM machine_queue
		WHERE machine_id = $1 AND taken_at IS NULL ORDER BY id LIMIT 1 FOR UPDATE SKIP LOCKED) RETURNING kind, body`, machine).Scan(&it.Kind, &it.Body)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return &it, err
}

// mqNext: the machine's next row, waiting up to wait (nil: none came)
func (r *Router) mqNext(ctx context.Context, machine string, wait time.Duration) (*mqItem, error) {
	ch, cancel := r.notes.sub("m:" + machine)
	defer cancel()
	end := time.NewTimer(wait)
	defer end.Stop()
	for {
		it, err := r.mqTake(machine)
		if it != nil || err != nil {
			return it, err
		}
		select {
		case <-ch:
		case <-time.After(mqRecheck):
		case <-end.C:
			return nil, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// mqAnswer: the answer to a row (by its ref), for whoever waits for it
func (r *Router) mqAnswer(ref string, answer any) error {
	if ref == "" {
		return errors.New("no ref")
	}
	b, _ := json.Marshal(answer)
	ctx, cancel := r.mqCtx()
	defer cancel()
	return pgx.BeginFunc(ctx, r.pool().pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "UPDATE machine_queue SET answered_at = now(), answer = $2 WHERE ref = $1 AND answered_at IS NULL", ref, b); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, "SELECT pg_notify('mq', $1)", "a:"+ref)
		return err
	})
}

// mqAwait: the answer to the row ref, waiting up to wait (nil: none came); done: stop early
func (r *Router) mqAwait(ref string, wait time.Duration, done <-chan struct{}) (json.RawMessage, error) {
	ch, cancel := r.notes.sub("a:" + ref)
	defer cancel()
	end := time.NewTimer(wait)
	defer end.Stop()
	for {
		ctx, c := r.mqCtx()
		var ans json.RawMessage
		err := r.pool().pool.QueryRow(ctx, "SELECT answer FROM machine_queue WHERE ref = $1 AND answered_at IS NOT NULL", ref).Scan(&ans)
		c()
		if err == nil {
			return ans, nil
		} else if err != pgx.ErrNoRows {
			return nil, err
		}
		select {
		case <-ch:
		case <-time.After(mqRecheck):
		case <-end.C:
			return nil, nil
		case <-done:
			return nil, nil
		}
	}
}

// mqForget: the row ref gone (its caller stopped waiting: a later answer has nobody to go to)
func (r *Router) mqForget(ref string) {
	ctx, cancel := r.mqCtx()
	defer cancel()
	r.pool().pool.Exec(ctx, "DELETE FROM machine_queue WHERE ref = $1", ref)
}

// mqSweep: rows older than a day go (taken or not: a machine that never polled is long gone)
func (r *Router) mqSweepLoop() {
	for {
		time.Sleep(time.Hour)
		ctx, cancel := r.mqCtx()
		r.pool().pool.Exec(ctx, "DELETE FROM machine_queue WHERE created_at < now() - interval '1 day'")
		cancel()
	}
}
