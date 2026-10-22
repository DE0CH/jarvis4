package main

// The router's database (docs/STATE.md, step 6): Postgres at DATABASE_URL (the Cluster jarvis4-db, role router; Secret
// router-db, infra/router-secrets.py --box cluster --part db). Schema changes are the embedded migrations/NNNN_*.sql,
// applied in order at start under a Postgres advisory lock (so two replicas starting together apply each once), each in
// its own transaction with its row in schema_migrations. GET /healthz and /setup/status report what Status says.

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"log"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// migrationLock: the advisory lock key the migrations run under ("jarvis4-migrate")
const migrationLock = 0x6a3473_6d6967

type DB struct {
	pool *pgxpool.Pool
}

type migration struct {
	version int
	name    string
	sql     string
}

func migrations() ([]migration, error) {
	ents, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		return nil, err
	}
	var ms []migration
	for _, e := range ents {
		n, _, ok := strings.Cut(e.Name(), "_")
		v, err := strconv.Atoi(n)
		if !ok || err != nil || !strings.HasSuffix(e.Name(), ".sql") {
			return nil, fmt.Errorf("migrations/%s: not NNNN_name.sql", e.Name())
		}
		b, _ := migrationsFS.ReadFile("migrations/" + e.Name())
		ms = append(ms, migration{v, e.Name(), string(b)})
	}
	sort.Slice(ms, func(i, j int) bool { return ms[i].version < ms[j].version })
	for i, m := range ms {
		if m.version != i+1 {
			return nil, fmt.Errorf("migrations: %s out of sequence (want %04d)", m.name, i+1)
		}
	}
	return ms, nil
}

// OpenDB: a pool on url, the migrations applied
func OpenDB(ctx context.Context, url string) (*DB, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("DATABASE_URL: %v", err)
	}
	cfg.MaxConns = 8
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	db := &DB{pool: pool}
	if err := db.migrate(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return db, nil
}

func (db *DB) Close() { db.pool.Close() }

func (db *DB) migrate(ctx context.Context) error {
	ms, err := migrations()
	if err != nil {
		return err
	}
	c, err := db.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer c.Release()
	if _, err := c.Exec(ctx, "SELECT pg_advisory_lock($1)", migrationLock); err != nil {
		return err
	}
	defer c.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", migrationLock)
	if _, err := c.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version int PRIMARY KEY, name text NOT NULL,
		applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return err
	}
	have := 0
	if err := c.QueryRow(ctx, "SELECT coalesce(max(version), 0) FROM schema_migrations").Scan(&have); err != nil {
		return err
	}
	if have > len(ms) {
		return fmt.Errorf("the database is at schema %d, newer than this router's %d: refusing to run an older router on it", have, len(ms))
	}
	for _, m := range ms[have:] {
		err := pgx.BeginFunc(ctx, c, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, m.sql); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, "INSERT INTO schema_migrations (version, name) VALUES ($1, $2)", m.version, m.name)
			return err
		})
		if err != nil {
			return fmt.Errorf("migration %s: %w", m.name, err)
		}
		log.Printf("db: applied migration %s", m.name)
	}
	return nil
}

// DBStatus: what /healthz and /setup/status show
type DBStatus struct {
	OK       bool        `json:"ok"`
	Primary  bool        `json:"primary"`
	Schema   int         `json:"schema"`
	Want     int         `json:"want"`
	Replicas []DBReplica `json:"replicas"`
	Error    string      `json:"error,omitempty"`
}

type DBReplica struct {
	Name     string   `json:"name"`
	State    string   `json:"state"`
	Sync     string   `json:"sync"`
	ReplayMs *float64 `json:"replayLagMs"` // null when the role can't see it (pg_read_all_stats) or none yet
}

// Status: the primary reachable, the schema version, each replica's replay lag (as the primary sees it)
func (db *DB) Status(ctx context.Context) DBStatus {
	ms, _ := migrations()
	st := DBStatus{Want: len(ms), Replicas: []DBReplica{}}
	if db == nil {
		st.Error = "no database (DATABASE_URL unset, or not connected yet)"
		return st
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var recovery bool
	if err := db.pool.QueryRow(ctx, "SELECT pg_is_in_recovery(), coalesce((SELECT max(version) FROM schema_migrations), 0)").Scan(&recovery, &st.Schema); err != nil {
		st.Error = err.Error()
		return st
	}
	st.Primary = !recovery
	rows, err := db.pool.Query(ctx, `SELECT coalesce(application_name, ''), coalesce(state, ''), coalesce(sync_state, ''),
		extract(epoch FROM replay_lag) * 1000 FROM pg_stat_replication`)
	if err == nil {
		for rows.Next() {
			var r DBReplica
			if rows.Scan(&r.Name, &r.State, &r.Sync, &r.ReplayMs) == nil {
				st.Replicas = append(st.Replicas, r)
			}
		}
		rows.Close()
	}
	switch {
	case !st.Primary:
		st.Error = "connected to a replica, not the primary"
	case st.Schema != st.Want:
		st.Error = fmt.Sprintf("schema %d, this router wants %d", st.Schema, st.Want)
	default:
		st.OK = true
	}
	return st
}

// connectDB: the database at url, connected (and migrated) in the background, retried until it answers; nothing waits
// for it yet (docs/STATE.md step 2: nothing is stored there)
func (r *Router) connectDB(url string) {
	if url == "" {
		log.Printf("db: DATABASE_URL unset: no database")
		return
	}
	go func() {
		for wait := time.Second; ; wait = min(2*wait, time.Minute) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			db, err := OpenDB(ctx, url)
			cancel()
			if err == nil {
				r.db.Store(db)
				log.Printf("db: connected, schema %d", len(must(migrations())))
				return
			}
			log.Printf("db: %v (again in %s)", err, wait)
			time.Sleep(wait)
		}
	}()
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

// dbStatus: the database's status, or why there is none
func (r *Router) dbStatus(ctx context.Context) DBStatus {
	return r.db.Load().Status(ctx)
}
