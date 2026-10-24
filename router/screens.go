package main

// The machine's pushed pane (machine/screen.go), one row per session in session_screens: the router runs as replicas
// and the push reaches any of them, so it lives in the database, not in a replica's memory; and apart from the
// versioned records, so a push every 2 s doesn't make every replica read the whole state again.

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

// PutScreen: the session's latest pane, from its running machine
func (s *State) PutScreen(session, machine string, snap TermSnap) error {
	if s.sdb == nil {
		return errors.New("screens: no database")
	}
	b, _ := json.Marshal(snap)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := s.sdb.db.pool.Exec(ctx, `INSERT INTO session_screens (session_id, machine_id, snap, at) VALUES ($1, $2, $3, now())
		ON CONFLICT (session_id) DO UPDATE SET machine_id = excluded.machine_id, snap = excluded.snap, at = excluded.at`, session, machine, b)
	return err
}

// Screen: the latest pane this machine of the session pushed, and how long ago (ok=false: none from that machine)
func (s *State) Screen(session, machine string) (TermSnap, time.Duration, bool) {
	if s.sdb == nil {
		return TermSnap{}, 0, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var b []byte
	var age float64
	err := s.sdb.db.pool.QueryRow(ctx, `SELECT snap, extract(epoch FROM now() - at) FROM session_screens WHERE session_id = $1 AND machine_id = $2`,
		session, machine).Scan(&b, &age)
	var snap TermSnap
	if err != nil || json.Unmarshal(b, &snap) != nil {
		return TermSnap{}, 0, false
	}
	return snap, time.Duration(age * float64(time.Second)), true
}

// DropScreen: a session that ended (destroyed) leaves no pane behind
func (s *State) DropScreen(session string) {
	if s.sdb == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s.sdb.db.pool.Exec(ctx, `DELETE FROM session_screens WHERE session_id = $1`, session)
}

func init() {
	onDestroy = append(onDestroy, func(r *Router, s Session) { r.st.DropScreen(s.ID) })
}
