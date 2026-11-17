package main

import (
	"bytes"
	"context"
	"log"
	"strings"
	"testing"
	"time"
)

// the log says what the Do's cost: how many, the reloads after another replica's change, the size of the records
func TestStateLoadIsLogged(t *testing.T) {
	url := testDBURL(t)
	ctx := context.Background()
	open := func() *State {
		db, err := OpenDB(ctx, url)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(db.Close)
		st, err := OpenState(ctx, db, t.TempDir(), testSeal)
		if err != nil {
			t.Fatal(err)
		}
		return st
	}
	a, b := open(), open()
	var buf bytes.Buffer
	out, old := log.Writer(), doLoadEvery
	log.SetOutput(&buf)
	doLoadEvery = time.Hour
	t.Cleanup(func() { log.SetOutput(out); doLoadEvery = old })
	a.Do(func(d *persisted) { d.Sessions["s1"] = &Session{ID: "s1", State: "started"} })
	b.Do(func(d *persisted) {}) // reads a's change first
	b.Do(func(d *persisted) {})
	if buf.Len() != 0 {
		t.Fatalf("said before its time: %s", buf.String())
	}
	if l := b.load; l.n != 2 || l.reloads != 1 || l.writes != 0 || l.rows != 1 || l.bytes == 0 {
		t.Fatalf("b's load: %+v", l)
	}
	doLoadEvery = 0
	b.Do(func(d *persisted) { d.Sessions["s2"] = &Session{ID: "s2"} })
	if got := buf.String(); !strings.Contains(got, "state: last ") || !strings.Contains(got, "3 changes asked for") ||
		!strings.Contains(got, "1 reloads") || !strings.Contains(got, "1 writes") || !strings.Contains(got, "the records are 2 rows") {
		t.Fatalf("the log: %q", got)
	}
	if b.load.n != 0 {
		t.Fatalf("not started again: %+v", b.load)
	}
}
