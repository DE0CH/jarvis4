package main

import (
	"bytes"
	"context"
	"log"
	"reflect"
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
		!strings.Contains(got, "1 reloads") || !strings.Contains(got, "1 writes") || !strings.Contains(got, "the records are 2 rows") ||
		!strings.Contains(got, "asked most by statestats_test.go:") {
		t.Fatalf("the log: %q", got)
	}
	if b.load.n != 0 {
		t.Fatalf("not started again: %+v", b.load)
	}
}

// a replica behind reads only what the others changed, and ends with exactly the records a full reload gives: rows
// added, changed and deleted, the records list, settings set and cleared, a session's cert
func TestStateCatchUp(t *testing.T) {
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
	same := func(what string) {
		t.Helper()
		var got rows
		b.Do(func(d *persisted) { got, _ = rowsOf(d) })
		var fresh persisted
		if err := b.sdb.load(ctx, b.sdb.db.pool, &fresh); err != nil {
			t.Fatal(err)
		}
		initMaps(&fresh)
		for id, c := range fresh.SessCerts {
			if x := fresh.Sessions[id]; x != nil {
				x.Cert = c
			}
		}
		want, _ := rowsOf(&fresh)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: the caught-up copy differs from the database's:\n got %v\nwant %v", what, got, want)
		}
		if !reflect.DeepEqual(b.sdb.written, want) {
			t.Fatalf("%s: what b takes the database to hold differs:\n got %v\nwant %v", what, b.sdb.written, want)
		}
	}
	cert := &Doc{Payload: `{"kind":"succession-cert"}`, Sig: "c2ln"}
	b.Do(func(d *persisted) {}) // b's copy is of a version now
	a.Do(func(d *persisted) {
		d.Sessions["s1"] = &Session{ID: "s1", State: "started", Cert: cert}
		d.Sessions["s2"] = &Session{ID: "s2", State: "paused"}
		d.Machines["m1"] = "s1"
		d.Records = append(d.Records, &Record{Session: Session{ID: "r0"}}, &Record{Session: Session{ID: "r1"}}, &Record{Session: Session{ID: "r2"}})
		d.KernelCopy = "green"
		d.Budget = &BudgetState{}
	})
	a.Do(func(d *persisted) { d.Sessions["s1"].State = "pausing" })
	same("added")
	b.Do(func(d *persisted) {
		if s := d.Sessions["s1"]; s == nil || s.State != "pausing" || s.Cert == nil || s.Cert.Sig != "c2ln" || d.KernelCopy != "green" || len(d.Records) != 3 {
			t.Fatalf("b after a's changes: %+v", d.Sessions["s1"])
		}
	})
	if b.load.catchUps != 1 || b.load.reloads != 1 { // the one reload: its first Do
		t.Fatalf("b caught up %d times and reloaded %d times", b.load.catchUps, b.load.reloads)
	}
	a.Do(func(d *persisted) {
		delete(d.Sessions, "s2")
		delete(d.Machines, "m1")
		d.Sessions["s1"].Cert = nil
		d.Records = append(d.Records[:1], d.Records[2:]...)
		d.KernelCopy = ""
		d.Budget = nil
	})
	same("deleted and cleared")
	b.Do(func(d *persisted) {
		if d.Sessions["s2"] != nil || d.Sessions["s1"].Cert != nil || len(d.Records) != 2 || d.Records[1].Session.ID != "r2" || d.KernelCopy != "" || d.Budget != nil {
			t.Fatalf("b after a's deletes: %+v %+v", d.Sessions, d.Records)
		}
	})
	// b's own change after a catch-up writes only that change, and a sees it the same way
	b.Do(func(d *persisted) { d.Sessions["s1"].DiskGB = 7 })
	a.Do(func(d *persisted) {
		if d.Sessions["s1"].DiskGB != 7 {
			t.Fatal("a doesn't see b's change")
		}
	})
	if a.load.catchUps != 1 {
		t.Fatalf("a caught up %d times", a.load.catchUps)
	}
	// a version whose changes nobody listed (a router from before state_changes): everything is read again
	before := b.load.reloads
	if _, err := a.sdb.db.pool.Exec(ctx, `UPDATE sessions SET doc = jsonb_set(doc, '{label}', '"old router"') WHERE id = 's1'`); err != nil {
		t.Fatal(err)
	}
	if _, err := a.sdb.db.pool.Exec(ctx, "UPDATE state_version SET v = v + 1 WHERE id = 1"); err != nil {
		t.Fatal(err)
	}
	b.Do(func(d *persisted) {
		if d.Sessions["s1"].Label != "old router" {
			t.Fatal("an unlisted change was missed")
		}
	})
	if b.load.reloads != before+1 {
		t.Fatalf("an unlisted version was caught up, not reloaded (%d reloads, %d before)", b.load.reloads, before)
	}
	same("after an unlisted version")
	// the list is kept short
	var n int
	if err := a.sdb.db.pool.QueryRow(ctx, "SELECT count(*) FROM state_changes WHERE tbl = $1", changesMarker).Scan(&n); err != nil || n == 0 || n > changesKept {
		t.Fatalf("%d versions listed (%v)", n, err)
	}
}
