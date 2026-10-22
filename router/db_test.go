package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
)

// testDBURL: a fresh schema of TEST_DATABASE_URL's database for this test (dropped after it), as a DATABASE_URL whose
// connections use only it. The router's tests need Postgres: CI runs a service container (images.yml); a session runs
// one locally (docs/STATE.md "Tests").
func testDBURL(t testing.TB) string {
	t.Helper()
	base := os.Getenv("TEST_DATABASE_URL")
	if base == "" {
		t.Fatal("TEST_DATABASE_URL isn't set: the router's tests need a Postgres (e.g. postgres://postgres@127.0.0.1:5432/postgres?sslmode=disable)")
	}
	b := make([]byte, 6)
	rand.Read(b)
	schema := "t_" + hex.EncodeToString(b)
	ctx := context.Background()
	c, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatalf("TEST_DATABASE_URL: %v", err)
	}
	if _, err := c.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	c.Close(ctx)
	t.Cleanup(func() {
		c, err := pgx.Connect(context.Background(), base)
		if err == nil {
			c.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
			c.Close(context.Background())
		}
	})
	sep := "?"
	if strings.Contains(base, "?") {
		sep = "&"
	}
	return base + sep + "search_path=" + schema
}

func TestMigrations(t *testing.T) {
	url := testDBURL(t)
	ctx := context.Background()
	// two routers starting together: each migration applied once
	var wg sync.WaitGroup
	dbs := make([]*DB, 2)
	errs := make([]error, 2)
	for i := range dbs {
		wg.Add(1)
		go func() { defer wg.Done(); dbs[i], errs[i] = OpenDB(ctx, url) }()
	}
	wg.Wait()
	for i := range dbs {
		if errs[i] != nil {
			t.Fatal(errs[i])
		}
		defer dbs[i].Close()
	}
	st := dbs[0].Status(ctx)
	want := len(must(migrations()))
	if !st.OK || !st.Primary || st.Schema != want {
		t.Fatalf("status: %+v", st)
	}
	n := 0
	dbs[0].pool.QueryRow(ctx, "SELECT count(*) FROM schema_migrations").Scan(&n)
	if n != want {
		t.Fatalf("schema_migrations has %d rows, want %d", n, want)
	}
	// a database at a newer schema than this router knows: refused
	dbs[0].pool.Exec(ctx, "INSERT INTO schema_migrations (version, name) VALUES (9999, '9999_future.sql')")
	if _, err := OpenDB(ctx, url); err == nil || !strings.Contains(err.Error(), "newer") {
		t.Fatalf("a newer schema: %v", err)
	}
	if (*DB)(nil).Status(ctx).OK {
		t.Fatal("no database reads as ok")
	}
}
