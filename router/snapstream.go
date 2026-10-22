package main

// The final snapshot without free disk on the machine (snapsafe.go): the machine streams its tar.gz straight into
// the request body as it makes it (machine/main.go uploadSnapshot), so it needs no room for a local copy.
//
//	POST /m/snapshot-stream   the body, streamed into the bucket (snapstore.go) and hashed on the way. The request is signed
//	                          over the constant body marker "stream" (the hash isn't known before the bytes), so the
//	                          router checks the machine before it takes a byte. → {sha256, bytes}: the hash the router
//	                          computed, kept as the machine's pending snapshot.
//	POST /m/snapshot-commit   {sha256, sig}: the machine compares the router's hash with its own, signs it with its
//	                          current key (the one signature of its life, as before) and commits; the router checks the
//	                          signature and that the pending file has that hash, then puts it in place: the snapshot.
//	POST /m/snapshot-failed   {error}: the machine couldn't take it; the waiting pause stops waiting at once.
//	POST /m/snapshot-carry    {sha256, sig}: a machine asked while it is still booting has no state of its own: its
//	                          state is its predecessor's snapshot, the one its cert names. It signs that hash; the
//	                          router links the predecessor's file as this machine's snapshot, so the line goes on
//	                          from it instead of losing it (and the machine stops booting).
//
// POST /m/snapshot (a whole file signed over its hash) stays for older images.

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"time"
)

const streamMarker = "stream"

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// setSnapshotError: the failure the machine reported for its snapshot, kept on its wait (snapwait.go) for the waiter
func (r *Router) setSnapshotError(machine, msg string) {
	r.swExec(`INSERT INTO snapshot_waits (machine_id, token, moved_at, error) VALUES ($1, '', now(), $2)
		ON CONFLICT (machine_id) DO UPDATE SET error = $2`, machine, msg)
}

// snapshotError: the failure the machine reported for its snapshot (taken: read once)
func (r *Router) snapshotError(machine string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var msg string
	if err := r.pool().pool.QueryRow(ctx, "UPDATE snapshot_waits w SET error = '' FROM (SELECT error FROM snapshot_waits WHERE machine_id = $1 FOR UPDATE) old WHERE w.machine_id = $1 RETURNING old.error", machine).Scan(&msg); err != nil || msg == "" {
		return nil
	}
	return fmt.Errorf("the machine's snapshot failed: %s", msg)
}

func (r *Router) machineKey(machine string) (key string) {
	r.st.Do(func(d *persisted) {
		if s := d.Started[machine]; s != nil {
			key = s.SigningKey
		}
	})
	return
}

func (r *Router) registerSnapStream(mmux *http.ServeMux, m machineRoute) {
	mmux.Handle("POST /m/snapshot-stream", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		machine, t, sig := req.Header.Get("X-Machine"), req.Header.Get("X-Time"), req.Header.Get("X-Sig")
		ts, _ := strconv.ParseInt(t, 10, 64)
		if d := time.Since(time.Unix(ts, 0)); d > machineTimeSkew || d < -machineTimeSkew {
			writeJSON(w, 401, map[string]string{"error": "X-Time too far off"})
			return
		}
		key := r.machineKey(machine)
		if key == "" || !verifyP256(key, []byte(req.Method+" "+req.URL.Path+" "+t+" "+streamMarker), sig) {
			writeJSON(w, 401, map[string]string{"error": "not signed by a machine the core started"})
			return
		}
		// snapstore.go: straight into the bucket, hashed on the way (snapwait.go: every read is progress)
		sum, n, err := r.snapStream(req.Context(), machine, movedReader{req.Body, r, machine})
		if err != nil {
			log.Printf("machine %s: snapshot stream: %v", machine, err)
			writeErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"sha256": sum, "bytes": n})
	}))
	m("POST /m/snapshot-commit", func(w http.ResponseWriter, req *http.Request, machine string, body []byte) {
		var in struct{ Sha256, Sig string }
		if json.Unmarshal(body, &in) != nil || !hex64.MatchString(in.Sha256) || in.Sig == "" {
			writeJSON(w, 400, map[string]string{"error": "{sha256, sig}"})
			return
		}
		if s := r.snap(machine); s == nil || s.Sha256 != in.Sha256 {
			writeJSON(w, 409, map[string]string{"error": "no streamed snapshot with that sha256"})
			return
		}
		if !verifyP256(r.machineKey(machine), []byte(in.Sha256), in.Sig) {
			writeJSON(w, 403, map[string]string{"error": "the snapshot isn't signed by the machine's current key"})
			return
		}
		if err := r.snapCommit(machine, in.Sha256, in.Sig); err != nil {
			writeErr(w, err)
			return
		}
		log.Printf("machine %s: snapshot committed (%s)", machine, in.Sha256[:12])
		r.snapshotArrived(machine)
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
	m("POST /m/snapshot-failed", func(w http.ResponseWriter, req *http.Request, machine string, body []byte) {
		var in struct{ Error string }
		json.Unmarshal(body, &in)
		msg := in.Error
		if len(msg) > 500 {
			msg = msg[:500]
		}
		if msg == "" {
			msg = "no reason given"
		}
		log.Printf("machine %s: its snapshot failed: %s", machine, msg)
		r.setSnapshotError(machine, msg)
		r.snapshotArrived(machine)
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
	m("POST /m/snapshot-carry", func(w http.ResponseWriter, req *http.Request, machine string, body []byte) {
		var in struct{ Sha256, Sig string }
		if json.Unmarshal(body, &in) != nil || !hex64.MatchString(in.Sha256) || in.Sig == "" {
			writeJSON(w, 400, map[string]string{"error": "{sha256, sig}"})
			return
		}
		var pred, named string
		r.st.Do(func(d *persisted) {
			if c := d.Certs[machine]; c != nil {
				var x struct {
					PredID   string `json:"predecessorId"`
					Snapshot string `json:"snapshot"`
				}
				c.Decode(&x)
				pred, named = x.PredID, x.Snapshot
			}
		})
		if pred == "" || named == "" || named != in.Sha256 {
			writeJSON(w, 409, map[string]string{"error": "the cert names no predecessor snapshot with that sha256"})
			return
		}
		if !verifyP256(r.machineKey(machine), []byte(in.Sha256), in.Sig) {
			writeJSON(w, 403, map[string]string{"error": "the snapshot isn't signed by the machine's current key"})
			return
		}
		if err := r.snapCarry(machine, pred, in.Sha256, in.Sig); err != nil {
			writeJSON(w, 409, map[string]string{"error": "the predecessor's snapshot: " + err.Error()})
			return
		}
		log.Printf("machine %s: still booting; its predecessor %s's snapshot carried over", machine, pred)
		r.snapshotArrived(machine)
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
}
