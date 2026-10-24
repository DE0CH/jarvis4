package main

// Live transcript sync (Jarvis 1's session-image/sync-live-transcripts): every JARVIS2_LIVE_SYNC_SECONDS
// (default 300) each conversation transcript under ~/.claude/projects that changed since its last copy goes to
// the router (POST /m/live-transcript, X-Name = its file name, the whole file — the Storage Box's WebDAV has
// no append), which puts it at claude-records/.live/<session id>/ for transcript search (DE0CH/services)
// (router/livesync.go). The machine holds no Storage Box credentials. Jarvis's peer-message relays ("You are a
// delivery relay…") are plumbing and are skipped, as in Jarvis 1.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

const liveSyncMaxBytes = 256 << 20 // the router refuses more

type liveSyncer struct {
	mu    sync.Mutex
	sent  map[string]time.Time // file → the modification time last sent
	send  func(name string, body []byte) error
	state string // where sent is kept ("" = memory only)
}

// liveSentPath: what was sent, on the tmpfs: supervisor-normal's live sync writes it, supervisor-core's teardown
// reads it, so the teardown sends only what changed since the last pass
var liveSentPath = dir + "/live-sent.json"

var (
	liveOnce sync.Once
	live     *liveSyncer // this process's one syncer
)

// liveSyncerFor: this process's syncer, sending through c
func liveSyncerFor(c *client) *liveSyncer {
	liveOnce.Do(func() {
		live = &liveSyncer{sent: map[string]time.Time{}, state: liveSentPath, send: func(name string, body []byte) error {
			b, _, status, err := c.raw("POST", "/m/live-transcript", body, "X-Name", name)
			if err != nil {
				return err
			}
			if status != 200 {
				return fmt.Errorf("HTTP %d %s", status, bytes.TrimSpace(b[:min(len(b), 200)]))
			}
			return nil
		}}
		if b, err := os.ReadFile(liveSentPath); err == nil {
			json.Unmarshal(b, &live.sent)
		}
	})
	return live
}

// mainTranscripts, subagentTranscripts: the conversations' files, and their subagents' (<conversation>/subagents/)
func mainTranscripts() []string {
	f, _ := filepath.Glob(filepath.Join(claudeHome, ".claude/projects/*/*.jsonl"))
	return f
}

func subagentTranscripts() []string {
	f, _ := filepath.Glob(filepath.Join(claudeHome, ".claude/projects/*/*/subagents/*.jsonl"))
	return f
}

func liveSyncInterval() time.Duration {
	if n := readVouchedInt("liveSyncSeconds"); n >= 5 { // vouch.go: a format exception from /m/config
		return time.Duration(n) * time.Second
	}
	return 300 * time.Second
}

// once: one pass over the conversations' transcripts; the number sent
func (l *liveSyncer) once() int { return l.pass(mainTranscripts()) }

// pass: each of files that changed since its last copy, the newest first; the number sent
func (l *liveSyncer) pass(files []string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	defer l.save()
	type cand struct {
		path string
		fi   os.FileInfo
	}
	var cs []cand
	for _, f := range files {
		fi, err := os.Stat(f)
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		cs = append(cs, cand{f, fi})
	}
	sort.SliceStable(cs, func(i, j int) bool { return cs[i].fi.ModTime().After(cs[j].fi.ModTime()) })
	n := 0
	for _, c := range cs {
		f, fi := c.path, c.fi
		if t, ok := l.sent[f]; ok && !fi.ModTime().After(t) {
			continue
		}
		if fi.Size() > liveSyncMaxBytes {
			l.sent[f] = fi.ModTime()
			log.Printf("live sync: %s is %d bytes, over the limit; not sent", filepath.Base(f), fi.Size())
			continue
		}
		body, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		if bytes.Contains(body[:min(len(body), 4000)], []byte("You are a delivery relay")) {
			l.sent[f] = fi.ModTime()
			continue
		}
		if err := l.send(filepath.Base(f), body); err != nil {
			log.Printf("live sync: %s: %v", filepath.Base(f), err)
			continue // tried again next pass
		}
		l.sent[f] = fi.ModTime()
		n++
	}
	return n
}

// save: sent to l.state (l.mu held)
func (l *liveSyncer) save() {
	if l.state == "" {
		return
	}
	b, _ := json.Marshal(l.sent)
	if err := writeAtomic(l.state, b); err != nil {
		log.Printf("live sync: %v", err)
	}
}

// liveSync: supervisor-normal's live transcript sync (started once booted)
func liveSync(c *client) {
	l := liveSyncerFor(c)
	every := liveSyncInterval()
	for {
		time.Sleep(every)
		l.once()
	}
}
