package main

// The final snapshot's progress (router/snapprogress.go). Before streaming it, the supervisor measures what the
// snapshot holds (the same walk, sizes only: "measuring"), then counts the bytes read into the tar.gz as it goes
// ("uploading", or "writing" for the whole-file path of an older router). Every progressPostEvery it reports the
// numbers to the router (POST /m/snapshot-progress), which shows them as the session's status line ("pausing:
// uploading snapshot 1.2/3.4 GB, 40 MB/s, 55 s left"); every progressLogEvery it writes a line into its own log. A
// router without the route (404) or a failed report never holds the snapshot up.

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

var (
	progressPostEvery = 3 * time.Second
	progressLogEvery  = 10 * time.Second
)

// snapProgress: the running snapshot's numbers (all bytes: done/total uncompressed file bytes, sent the tar.gz bytes)
type snapProgress struct {
	phase             atomic.Value // string
	done, total, sent atomic.Int64
	started           atomic.Int64 // unix ms the phase began
	stop              chan struct{}
	wg                sync.WaitGroup
	report            func(map[string]any) error
	logf              func(string, ...any)
	lastLog, lastPost time.Time
	reportOff         bool
	tickMu            sync.Mutex
}

// curProgress: the progress writeSnapshot counts into (nil: none)
var curProgress atomic.Pointer[snapProgress]

func (p *snapProgress) setPhase(phase string) {
	p.phase.Store(phase)
	p.started.Store(time.Now().UnixMilli())
}

func (p *snapProgress) numbers() map[string]any {
	ph, _ := p.phase.Load().(string)
	return map[string]any{"phase": ph, "done": p.done.Load(), "total": p.total.Load(), "sent": p.sent.Load(),
		"elapsedMs": max(int64(0), time.Now().UnixMilli()-p.started.Load())}
}

// line: the log line ("snapshot: uploading 1.2/3.4 GB (35%), 0.6 GB sent, 40 MB/s, 55 s left")
func (p *snapProgress) line() string {
	ph, _ := p.phase.Load().(string)
	done, total, sent := p.done.Load(), p.total.Load(), p.sent.Load()
	if ph == "measuring" {
		return fmt.Sprintf("snapshot: measuring, %s so far", gb(total))
	}
	total = max(total, done)
	s := fmt.Sprintf("snapshot: %s %s/%s", ph, gb(done), gb(total))
	if total > 0 {
		s += fmt.Sprintf(" (%d%%)", done*100/total)
	}
	s += ", " + gb(sent) + " compressed sent"
	if el := float64(time.Now().UnixMilli()-p.started.Load()) / 1000; el >= 1 && done > 0 {
		rate := float64(done) / el
		s += fmt.Sprintf(", %.0f MB/s", rate/1e6)
		if total > done {
			s += fmt.Sprintf(", %.0f s left", float64(total-done)/rate)
		}
	}
	return s
}

func gb(n int64) string { return fmt.Sprintf("%.2f GB", float64(n)/1e9) }

// tick: post and log when their time has come (force: both now)
func (p *snapProgress) tick(force bool) {
	p.tickMu.Lock()
	defer p.tickMu.Unlock()
	now := time.Now()
	if !p.reportOff && (force || now.Sub(p.lastPost) >= progressPostEvery) {
		p.lastPost = now
		if err := p.report(p.numbers()); err != nil {
			p.reportOff = true // an older router, or none: the log still has it
			p.logf("snapshot progress: not reported to the router (%v); only logged", err)
		}
	}
	if force || now.Sub(p.lastLog) >= progressLogEvery {
		p.lastLog = now
		p.logf("%s", p.line())
	}
}

// startProgress: measure, then report until stopped. The caller sets the phase it counts and calls end.
func startProgress(c *client) *snapProgress {
	p := &snapProgress{stop: make(chan struct{}), logf: log.Printf}
	p.report = func(m map[string]any) error { return c.json("POST", "/m/snapshot-progress", m, nil) }
	return beginProgress(p)
}

func beginProgress(p *snapProgress) *snapProgress {
	p.setPhase("measuring")
	p.lastLog, p.lastPost = time.Now(), time.Now()
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-p.stop:
				return
			case <-t.C:
				p.tick(false)
			}
		}
	}()
	measureSnapshot(&p.total)
	p.tick(true)
	curProgress.Store(p)
	return p
}

// end: the last numbers, logged (and reported), then the reporter stops
func (p *snapProgress) end(err error) {
	if p == nil {
		return
	}
	curProgress.CompareAndSwap(p, nil)
	close(p.stop)
	p.wg.Wait()
	if err != nil {
		p.logf("%s; failed: %v", p.line(), err)
		return
	}
	el := float64(time.Now().UnixMilli()-p.started.Load()) / 1000
	p.logf("snapshot: %s done, %s read, %s compressed in %.0f s", p.phase.Load(), gb(p.done.Load()), gb(p.sent.Load()), el)
}

// measureSnapshot: the bytes of the regular files writeSnapshot will read (the same walk, sizes only), counted into n
// as it goes so a long walk shows too
func measureSnapshot(n *atomic.Int64) {
	home, _ := os.UserHomeDir()
	for _, rel := range statePaths() {
		root := filepath.Join(home, rel)
		if _, err := os.Lstat(root); err != nil {
			continue
		}
		filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			name, _ := filepath.Rel(home, p)
			if skipInSnapshot(name) {
				if fi.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if fi.Mode().IsRegular() {
				n.Add(fi.Size())
			}
			return nil
		})
	}
}

// countReader: a file's bytes as writeSnapshot reads them, into the running progress
type countReader struct {
	r io.Reader
	p *snapProgress
}

func (c countReader) Read(b []byte) (int, error) {
	n, err := c.r.Read(b)
	c.p.done.Add(int64(n))
	return n, err
}
