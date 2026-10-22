package main

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// mqTakeKind: the machine's oldest untaken row of this kind (the tests play the machine for one kind at a time)
func mqTakeKind(r *Router, machine, kind string) (json.RawMessage, bool) {
	var b json.RawMessage
	err := r.pool().pool.QueryRow(context.Background(), `UPDATE machine_queue SET taken_at = now() WHERE id = (SELECT id FROM machine_queue
		WHERE machine_id = $1 AND kind = $2 AND taken_at IS NULL ORDER BY id LIMIT 1 FOR UPDATE SKIP LOCKED) RETURNING body`, machine, kind).Scan(&b)
	if err == pgx.ErrNoRows || err != nil {
		return nil, false
	}
	return b, true
}

func mqWaitKind(r *Router, machine, kind string, wait time.Duration) (json.RawMessage, bool) {
	for end := time.Now().Add(wait); ; time.Sleep(5 * time.Millisecond) {
		if b, ok := mqTakeKind(r, machine, kind); ok || time.Now().After(end) {
			return b, ok
		}
	}
}

// takeCmd: the machine's next supervisor command, if one waits now
func takeCmd(r *Router, machine string) (string, bool) {
	b, ok := mqTakeKind(r, machine, "command")
	var c string
	json.Unmarshal(b, &c)
	return c, ok
}

func waitCmd(r *Router, machine string, wait time.Duration) (string, bool) {
	b, ok := mqWaitKind(r, machine, "command", wait)
	var c string
	json.Unmarshal(b, &c)
	return c, ok
}

// the queue through the database: a row is taken once (two polls never get the same one), the answer reaches the
// waiter by its notification, and a bounded kind refuses past its bound
func TestMachineQueue(t *testing.T) {
	r := newTestRouter(t)
	for i := 0; i < 10; i++ {
		r.send("m1", "snapshot")
	}
	n := 0
	for {
		if _, ok := takeCmd(r, "m1"); !ok {
			break
		}
		n++
	}
	if n != 8 {
		t.Fatalf("%d commands queued, want the bound of 8", n)
	}
	r.mqPut("m1", "exec", "x1", execItem{Request: "{}"}, 16)
	got := make(chan *mqItem, 2)
	for i := 0; i < 2; i++ {
		go func() { it, _ := r.mqNext(context.Background(), "m1", time.Second); got <- it }()
	}
	a, b := <-got, <-got
	if (a == nil) == (b == nil) {
		t.Fatalf("two polls: %v %v (want exactly one row)", a, b)
	}
	done := make(chan json.RawMessage, 1)
	go func() { ans, _ := r.mqAwait("x1", 5*time.Second, nil); done <- ans }()
	time.Sleep(50 * time.Millisecond)
	start := time.Now()
	r.mqAnswer("x1", ExecResult{ID: "x1", Code: 3})
	ans := <-done
	var res ExecResult
	json.Unmarshal(ans, &res)
	if res.Code != 3 || time.Since(start) > mqRecheck {
		t.Fatalf("answer %s after %s (the notification should beat the recheck)", ans, time.Since(start))
	}
}
