package main

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/DE0CH/jarvis4/kernel/gv"
)

// the records survive a restart: every kind of field (a map, the records list, a settings row) written by Do is what a
// new State reads back; a deleted record and a cleared setting are gone
func TestStateInPostgres(t *testing.T) {
	url := testDBURL(t)
	ctx := context.Background()
	open := func() (*State, *DB) {
		db, err := OpenDB(ctx, url)
		if err != nil {
			t.Fatal(err)
		}
		st, err := OpenState(ctx, db, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		return st, db
	}
	st, db := open()
	cert := &Doc{Payload: `{"kind":"succession-cert"}`, Sig: "c2ln"}
	st.Do(func(d *persisted) {
		d.Sessions["s1"] = &Session{ID: "s1", State: "started", MachineID: "m1", Label: "one", Created: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), Cert: cert}
		d.Sessions["s2"] = &Session{ID: "s2", State: "paused"}
		d.Records = append(d.Records, &Record{Session: Session{ID: "s0", State: "destroyed"}}, &Record{Session: Session{ID: "s9"}})
		d.Machines["m1"] = "s1"
		d.KernelSecrets = "green"
		d.KernelRoot = &gv.Signed{By: "root"}
		d.Outcomes["s1"] = []*Outcome{{ID: "o1", Session: "s1"}}
	})
	st.Do(func(d *persisted) {
		delete(d.Sessions, "s2")
		d.Records = d.Records[:1]
		d.KernelRoot = nil
	})
	var hot string
	db.pool.QueryRow(ctx, "SELECT state FROM sessions WHERE machine_id = 'm1'").Scan(&hot)
	if hot != "started" {
		t.Fatalf("hot column: %q", hot)
	}
	db.Close()

	st2, db2 := open()
	defer db2.Close()
	var a, b persisted
	st.Do(func(d *persisted) { a = *d })
	st2.Do(func(d *persisted) { b = *d })
	if !reflect.DeepEqual(a.Sessions["s1"], b.Sessions["s1"]) || b.Sessions["s1"].Cert == nil || b.Sessions["s2"] != nil {
		t.Fatalf("sessions: %+v", b.Sessions)
	}
	if len(b.Records) != 1 || b.Records[0].ID != "s0" || b.Machines["m1"] != "s1" || b.KernelSecrets != "green" || b.KernelRoot != nil ||
		len(b.Outcomes["s1"]) != 1 {
		t.Fatalf("read back: %+v", b)
	}
}

// the first start imports state.json (renamed after); a later start ignores one beside the database
func TestStateImport(t *testing.T) {
	url := testDBURL(t)
	ctx := context.Background()
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "state.json"), []byte(`{"sessions":{"s1":{"id":"s1","state":"paused","label":"old"}},
		"records":[{"id":"s0"}],"sessionCerts":{"s1":{"payload":"p","sig":"s"}},"kernelSecrets":"green","budget":{"month":"2026-10"}}`), 0o600)
	db, err := OpenDB(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	st, err := OpenState(ctx, db, dir)
	if err != nil {
		t.Fatal(err)
	}
	st.Do(func(d *persisted) {
		if d.Sessions["s1"].Label != "old" || d.Sessions["s1"].Cert == nil || len(d.Records) != 1 || d.KernelSecrets != "green" || d.Budget == nil {
			t.Fatalf("imported: %+v", d)
		}
	})
	if _, err := os.Stat(filepath.Join(dir, "state.json.imported")); err != nil {
		t.Fatal("state.json wasn't renamed after the import")
	}
	os.WriteFile(filepath.Join(dir, "state.json"), []byte(`{"sessions":{"sX":{"id":"sX"}}}`), 0o600)
	st2, err := OpenState(ctx, db, dir)
	if err != nil {
		t.Fatal(err)
	}
	st2.Do(func(d *persisted) {
		if d.Sessions["sX"] != nil || d.Sessions["s1"] == nil {
			t.Fatalf("a second state.json was read: %v", d.Sessions)
		}
	})
	if _, err := os.Stat(filepath.Join(dir, "state.json.stale")); err != nil {
		t.Fatal("the second state.json wasn't set aside")
	}
}

// a write the database refuses is kept and written again once it can be; the status says so meanwhile
func TestStateWriteRetried(t *testing.T) {
	url := testDBURL(t)
	ctx := context.Background()
	db, err := OpenDB(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	st, err := OpenState(ctx, db, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	r := &Router{st: st}
	r.db.Store(db)
	db.pool.Exec(ctx, "ALTER TABLE sessions RENAME TO sessions_away")
	st.Do(func(d *persisted) { d.Sessions["s1"] = &Session{ID: "s1", State: "started"} })
	if err, _ := st.StoreError(); err == nil || r.dbStatus(ctx).OK {
		t.Fatal("a failed write isn't reported")
	}
	db.pool.Exec(ctx, "ALTER TABLE sessions_away RENAME TO sessions")
	waitFor(t, "the retry", func() bool { err, _ := st.StoreError(); return err == nil })
	var n int
	db.pool.QueryRow(ctx, "SELECT count(*) FROM sessions WHERE id = 's1'").Scan(&n)
	if n != 1 || !r.dbStatus(ctx).OK {
		t.Fatalf("after the retry: %d rows, %+v", n, r.dbStatus(ctx))
	}
}

// the small documents: read and written in the database; a file of one on the volume is imported once and set aside
func TestRouterDocs(t *testing.T) {
	url := testDBURL(t)
	ctx := context.Background()
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "repos.json"), []byte(`[{"url":"https://github.com/DE0CH/b.git"}]`), 0o600)
	db, err := OpenDB(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	st, err := OpenState(ctx, db, dir)
	if err != nil {
		t.Fatal(err)
	}
	if b, ok := st.ReadDoc("repos.json"); !ok || !strings.Contains(string(b), "DE0CH/b") {
		t.Fatalf("imported: %s %v", b, ok)
	}
	if _, err := os.Stat(filepath.Join(dir, "repos.json.imported")); err != nil {
		t.Fatal("repos.json wasn't set aside after the import")
	}
	if _, ok := st.ReadDoc("store-docs.json"); ok {
		t.Fatal("a document nobody wrote")
	}
	st.WriteDoc("store-docs.json", []byte(`{"a":{}}`))
	st.WriteDoc("store-docs.json", []byte(`{"b":{}}`))
	os.WriteFile(filepath.Join(dir, "store-docs.json"), []byte(`{"old":{}}`), 0o600)
	st2, err := OpenState(ctx, db, dir)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := st2.ReadDoc("store-docs.json"); string(b) != `{"b":{}}` {
		t.Fatalf("after a restart: %s (a stale file beside the database must not win)", b)
	}
	r := &Router{st: st2}
	if rs := r.Repos(); len(rs) != 1 || rs[0].Repo != "DE0CH/b" {
		t.Fatalf("repos: %+v", rs)
	}
}

// the logs on the volume (lifecycle/, supervisor-log/, input-log.jsonl) are imported once, in order, then set aside
func TestLogFilesImported(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "lifecycle"), 0o700)
	os.MkdirAll(filepath.Join(dir, "supervisor-log"), 0o700)
	os.WriteFile(filepath.Join(dir, "lifecycle", "s1.jsonl"), []byte("{\"op\":{\"id\":\"o1\"}}\n{\"opId\":\"o1\",\"entry\":{\"text\":\"b\"}}\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "supervisor-log", "s1.jsonl"), []byte("{\"seq\":1,\"text\":\"one\"}\nnot json\n{\"seq\":2,\"text\":\"two\"}\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "input-log.jsonl"), []byte("{\"payload\":\"p\",\"sig\":\"s\"}\n"), 0o600)
	st, err := testState(t, dir)
	if err != nil {
		t.Fatal(err)
	}
	lc, _ := st.ReadLog("s1", logLifecycle)
	sup, _ := st.ReadLog("s1", logSupervisor)
	in, _ := st.ReadLog("", logInput)
	if len(lc) != 2 || len(sup) != 2 || len(in) != 1 || !strings.Contains(string(sup[1]), "two") {
		t.Fatalf("imported %d %d %d", len(lc), len(sup), len(in))
	}
	for _, p := range []string{"lifecycle.imported", "supervisor-log.imported", "input-log.jsonl.imported"} {
		if _, err := os.Stat(filepath.Join(dir, p)); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
	}
	r := &Router{st: st, lc: newLifecycle(), sup: &supLogs{next: map[string]int64{}}}
	if ls := r.readSupLog("s1"); len(ls) != 2 || ls[1].Seq != 2 {
		t.Fatalf("%+v", ls)
	}
}
