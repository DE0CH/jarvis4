package main

// Each session's two logs in the database (docs/STATE.md step 4): the lifecycle log (lifecycle.go: its operations and
// their entries) and the supervisor's lines (supervisorlog.go), rows of session_log in the order they were written.
// They were jsonl files on the volume; the files are imported once at start (importLogFiles) and set aside.

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	logLifecycle  = "lifecycle"
	logSupervisor = "supervisor"
	logInput      = "input" // the old core's input log (vouch.go), session ""
)

func (s *State) logCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 20*time.Second)
}

// AppendLog: lines (JSON each) onto a session's log
func (s *State) AppendLog(session, kind string, lines ...[]byte) error {
	if s == nil || s.sdb == nil {
		return fmt.Errorf("logs: no database")
	}
	ctx, cancel := s.logCtx()
	defer cancel()
	b := &pgx.Batch{}
	for _, l := range lines {
		b.Queue("INSERT INTO session_log (session_id, kind, line) VALUES ($1, $2, $3)", session, kind, l)
	}
	return s.sdb.db.pool.SendBatch(ctx, b).Close()
}

// ReadLog: a session's log, oldest first
func (s *State) ReadLog(session, kind string) ([][]byte, error) {
	if s == nil || s.sdb == nil {
		return nil, fmt.Errorf("logs: no database")
	}
	ctx, cancel := s.logCtx()
	defer cancel()
	rows, err := s.sdb.db.pool.Query(ctx, "SELECT line FROM session_log WHERE session_id = $1 AND kind = $2 ORDER BY n", session, kind)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out [][]byte
	for rows.Next() {
		var b []byte
		if err := rows.Scan(&b); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// TailLog: a session's newest n lines, oldest first
func (s *State) TailLog(session, kind string, n int) ([][]byte, error) {
	if s == nil || s.sdb == nil {
		return nil, fmt.Errorf("logs: no database")
	}
	ctx, cancel := s.logCtx()
	defer cancel()
	rows, err := s.sdb.db.pool.Query(ctx, `SELECT line FROM (SELECT n, line FROM session_log WHERE session_id = $1 AND kind = $2
		ORDER BY n DESC LIMIT $3) t ORDER BY n`, session, kind, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out [][]byte
	for rows.Next() {
		var b []byte
		if err := rows.Scan(&b); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// LogBytes: the size of a session's log (its lines' JSON)
func (s *State) LogBytes(session, kind string) int64 {
	if s == nil || s.sdb == nil {
		return 0
	}
	ctx, cancel := s.logCtx()
	defer cancel()
	var n int64
	s.sdb.db.pool.QueryRow(ctx, "SELECT coalesce(sum(octet_length(line::text)), 0) FROM session_log WHERE session_id = $1 AND kind = $2", session, kind).Scan(&n)
	return n
}

// ReplaceLog: a session's log becomes lines (one transaction)
func (s *State) ReplaceLog(session, kind string, lines [][]byte) error {
	if s == nil || s.sdb == nil {
		return fmt.Errorf("logs: no database")
	}
	ctx, cancel := s.logCtx()
	defer cancel()
	return pgx.BeginFunc(ctx, s.sdb.db.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "DELETE FROM session_log WHERE session_id = $1 AND kind = $2", session, kind); err != nil {
			return err
		}
		b := &pgx.Batch{}
		for _, l := range lines {
			b.Queue("INSERT INTO session_log (session_id, kind, line) VALUES ($1, $2, $3)", session, kind, l)
		}
		return tx.SendBatch(ctx, b).Close()
	})
}

// DropLog: a session's log gone (its archive holds it)
func (s *State) DropLog(session, kind string) {
	if s == nil || s.sdb == nil {
		return
	}
	ctx, cancel := s.logCtx()
	defer cancel()
	if _, err := s.sdb.db.pool.Exec(ctx, "DELETE FROM session_log WHERE session_id = $1 AND kind = $2", session, kind); err != nil {
		log.Printf("logs: dropping %s's %s log: %v", session, kind, err)
	}
}

// LogSessions: the sessions that have a log of this kind
func (s *State) LogSessions(kind string) []string {
	if s == nil || s.sdb == nil {
		return nil
	}
	ctx, cancel := s.logCtx()
	defer cancel()
	rows, err := s.sdb.db.pool.Query(ctx, "SELECT DISTINCT session_id FROM session_log WHERE kind = $1", kind)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			out = append(out, id)
		}
	}
	return out
}

// importLogFiles: lifecycle/*.jsonl and supervisor-log/*.jsonl into session_log, once (a session whose log has rows
// already keeps them), then the directories set aside (.imported)
func importLogFiles(ctx context.Context, db *DB, dir string) error {
	for kind, sub := range map[string]string{logLifecycle: "lifecycle", logSupervisor: "supervisor-log"} {
		d := filepath.Join(dir, sub)
		ents, err := os.ReadDir(d)
		if os.IsNotExist(err) {
			continue
		} else if err != nil {
			return err
		}
		n := 0
		for _, e := range ents {
			session, ok := strings.CutSuffix(e.Name(), ".jsonl")
			if !ok || e.IsDir() {
				continue
			}
			b, err := os.ReadFile(filepath.Join(d, e.Name()))
			if err != nil {
				return err
			}
			err = pgx.BeginFunc(ctx, db.pool, func(tx pgx.Tx) error {
				var have bool
				if err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM session_log WHERE session_id = $1 AND kind = $2)", session, kind).Scan(&have); err != nil || have {
					return err
				}
				for _, l := range strings.Split(string(b), "\n") {
					if strings.TrimSpace(l) == "" || !jsonOK(l) {
						continue
					}
					if _, err := tx.Exec(ctx, "INSERT INTO session_log (session_id, kind, line) VALUES ($1, $2, $3)", session, kind, l); err != nil {
						return err
					}
				}
				n++
				return nil
			})
			if err != nil {
				return fmt.Errorf("import %s/%s: %v", sub, e.Name(), err)
			}
		}
		if err := os.Rename(d, d+".imported"); err != nil {
			return err
		}
		log.Printf("logs: %s: %d session logs imported into the database", d, n)
	}
	p := filepath.Join(dir, "input-log.jsonl")
	if b, err := os.ReadFile(p); err == nil {
		err = pgx.BeginFunc(ctx, db.pool, func(tx pgx.Tx) error {
			var have bool
			if err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM session_log WHERE session_id = '' AND kind = $1)", logInput).Scan(&have); err != nil || have {
				return err
			}
			for _, l := range strings.Split(string(b), "\n") {
				if strings.TrimSpace(l) != "" && jsonOK(l) {
					if _, err := tx.Exec(ctx, "INSERT INTO session_log (session_id, kind, line) VALUES ('', $1, $2)", logInput, l); err != nil {
						return err
					}
				}
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("import %s: %v", p, err)
		}
		os.Rename(p, p+".imported")
		log.Printf("logs: %s imported into the database", p)
	}
	return nil
}

func jsonOK(s string) bool { return json.Valid([]byte(s)) }
