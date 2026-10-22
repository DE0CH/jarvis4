package main

// Live transcript sync (Jarvis 1's session-image/sync-live-transcripts): while a session runs, its machine sends
// each conversation transcript that changed (every LIVE_SYNC_SECONDS, default 300) to POST /m/live-transcript,
// and the router puts it on the Storage Box with its own credentials at
//
//	claude-records/.live/<session id>/<conversation uuid>.jsonl
//
// — Jarvis 1's layout, so Jarvis 1's transcript search (its indexer reads .live/<id>/) covers Jarvis 4 sessions
// that are still running. The session id is the router's (s…), stable across the session's machines. On
// destroy the archive takes every copy the snapshot doesn't hold, and only then does the router delete the copies it
// archived (livearchive.go); one it didn't archive stays.
//
// No grant: the machine sends its own transcripts (as it sends its status report and its pause snapshots, which
// hold the same transcripts), so no router feature runs anything in it; Storage Box credentials stay on the
// router. docs/DECISIONS.md 38.

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"sync"
	"time"
)

// LiveSync: what the router last did with a session's transcripts (shown in /api/state as liveSync)
type LiveSync struct {
	At     time.Time        `json:"at"`
	Files  map[string]int64 `json:"files"`  // conversation file → bytes last received
	Stored bool             `json:"stored"` // false: received but not written (no Storage Box, or RECORDS_OFF)
	Error  string           `json:"error,omitempty"`
}

const liveRoot = recordsRoot + "/.live"

// a transcript's file name, as claude names them (<uuid>.jsonl); anything else is refused
var liveNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.jsonl$`)

// liveSyncMaxBytes: a bigger transcript isn't sent (the machine checks the same limit)
const liveSyncMaxBytes = 256 << 20

var liveDirs sync.Map // session id → its .live dir exists on the box

func liveDir(sid string) string { return liveRoot + "/" + sid }

func init() {
	// how often the machine looks for changed transcripts (unsigned machine env; the e2e test shortens it)
	envHooks = append(envHooks, func(_ *Router, s *Session, e map[string]string) {
		if n, err := strconv.Atoi(os.Getenv("LIVE_SYNC_SECONDS")); err == nil && n > 0 {
			e["JARVIS2_LIVE_SYNC_SECONDS"] = strconv.Itoa(n)
		}
	})
}

// liveTranscript: POST /m/live-transcript, header X-Name = the file's name, body = the whole file
func (r *Router) liveTranscript(w http.ResponseWriter, req *http.Request, machine string, body []byte) {
	sid, err := r.machineSession(machine)
	if err != nil {
		writeJSON(w, 403, map[string]string{"error": err.Error()})
		return
	}
	name := req.Header.Get("X-Name")
	if !liveNameRE.MatchString(name) {
		writeJSON(w, 400, map[string]string{"error": "X-Name must be a transcript's file name (<uuid>.jsonl)"})
		return
	}
	if len(body) > liveSyncMaxBytes {
		writeJSON(w, 413, map[string]string{"error": fmt.Sprintf("larger than %d bytes", liveSyncMaxBytes)})
		return
	}
	box := r.box()
	stored, werr := false, error(nil)
	if box != nil && !recordsOff() {
		dir := liveDir(sid)
		if _, ok := liveDirs.Load(sid); !ok {
			werr = box.Mkcols(dir)
			if werr == nil {
				liveDirs.Store(sid, true)
			}
		}
		if werr == nil {
			werr = box.PutBytes(dir+"/"+name, body)
		}
		if werr != nil {
			liveDirs.Delete(sid) // the dir may have gone (a purge): make it again next time
		}
		stored = werr == nil
	}
	r.st.Do(func(d *persisted) {
		s := d.Sessions[sid]
		if s == nil {
			return
		}
		if s.LiveSync == nil {
			s.LiveSync = &LiveSync{}
		}
		if s.LiveSync.Files == nil {
			s.LiveSync.Files = map[string]int64{}
		}
		s.LiveSync.At, s.LiveSync.Stored, s.LiveSync.Error = time.Now().UTC(), stored, ""
		s.LiveSync.Files[name] = int64(len(body))
		if werr != nil {
			s.LiveSync.Error = werr.Error()
		}
	})
	if werr != nil {
		log.Printf("[livesync] %s %s: %v", sid, name, werr)
		writeJSON(w, 502, map[string]string{"error": "Storage Box: " + werr.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "stored": stored})
}
