package main

// The stall watch (Deyao, 2026-10-24: "a simple watch from the supervisor, nothing outside the image"): a component of
// the supervisor that looks at its own session's Claude host every stallEvery. When the host has background jobs
// running and no turn, and nothing has changed (its statusUpdatedAt) for stallAfter, the supervisor sends the
// watchdog's text into the harness through the Jarvis channel itself, and again every stallAfter while it lasts. The
// router takes no part: it used to run this clock from replica memory, which a database reload wiped, so the nudge
// never came.
//
// Claude Code (2.1.29x) keeps the host's status "busy" while background jobs run after the turn ended, so a "busy"
// host counts as waiting on its jobs when the pane shows no turn running (no spinner line); with no pane (a harness
// without the tmux session `claude`), a busy host never starts the clock.

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	stallEvery = 10 * time.Second
	stallAfter = 15 * time.Minute
)

// hostStatus: the session's Claude host as its registry file says, with its background jobs
type hostStatus struct {
	ok       bool
	status   string // idle | busy | waiting | shell …
	statusAt int64  // statusUpdatedAt (ms): changes with every turn
	jobs     int
	pid      int64
	bridge   string // its Remote Control entry ("" = none)
}

// stallClock: since when the host has waited on its jobs alone, on which turn
type stallClock struct {
	statusAt int64
	since    time.Time
}

// stallStep: one look → whether to nudge now, and for how many minutes it has waited
func stallStep(c *stallClock, h hostStatus, screen string, screenOK bool, now time.Time) (bool, int) {
	if !h.ok || h.jobs <= 0 {
		*c = stallClock{}
		return false, 0
	}
	jobsOnly := h.status == "idle" || h.status == "shell"
	if h.status == "busy" {
		if !screenOK {
			return false, 0 // can't tell a running turn from a finished one: the clock stays as it is
		}
		jobsOnly = !turnOnScreen(screen)
	}
	if !jobsOnly {
		*c = stallClock{}
		return false, 0
	}
	if c.since.IsZero() || c.statusAt != h.statusAt {
		*c = stallClock{statusAt: h.statusAt, since: now}
		return false, 0
	}
	if stalled := now.Sub(c.since); stalled >= stallAfter {
		c.since = now
		return true, int(stalled.Round(time.Minute) / time.Minute)
	}
	return false, 0
}

// spinnerLine: Claude Code's working line ("✻ Thinking… (12s · esc to interrupt)")
var (
	spinnerLine = regexp.MustCompile(`(?m)^\s*\S\s+[A-Z][\p{L}-]*…\s*\(\d`)
	ansiSeq     = regexp.MustCompile(`\x1b\[[0-9;?]*[A-Za-z]`)
)

func turnOnScreen(screen string) bool {
	return spinnerLine.MatchString(ansiSeq.ReplaceAllString(screen, ""))
}

// stallText: the watchdog's message (Jarvis 1's lib/stall.js nudgeText)
func stallText(jobs, minutes int) string {
	j := fmt.Sprintf("%d background jobs have", jobs)
	if jobs == 1 {
		j = "1 background job has"
	}
	return fmt.Sprintf("Jarvis watchdog: this session has been idle for %d min while %s been running, and none has finished or woken you. ", minutes, j) +
		"Check on them now: read their output, and if a job is hung or no longer needed, stop it and continue the task another way. " +
		"If a job is legitimately still running, make sure it will end on its own (a timeout or deadline), then end your turn — this check repeats while the state lasts. " +
		"This is an automated message from Jarvis."
}

// claudeSessions: claude's registry dir (a var so tests can move it)
var claudeSessions = "/home/claude/.claude/sessions"

// readHost: the Remote Control host's registry entry (else the first one) and its background jobs: the shells it has
// running (as the status report counts them) or the hook-fed count (workers.go), whichever is more
func readHost() hostStatus {
	files, _ := filepath.Glob(filepath.Join(claudeSessions, "*.json"))
	type entry struct {
		PID       int64  `json:"pid"`
		SessionID string `json:"sessionId"`
		Status    string `json:"status"`
		StatusAt  int64  `json:"statusUpdatedAt"`
		StartedAt int64  `json:"startedAt"`
		Bridge    string `json:"bridgeSessionId"`
	}
	var es []entry
	for _, f := range files {
		var e entry
		if b, err := os.ReadFile(f); err == nil && json.Unmarshal(b, &e) == nil && e.PID > 0 {
			es = append(es, e)
		}
	}
	if len(es) == 0 {
		return hostStatus{}
	}
	sort.SliceStable(es, func(i, j int) bool { return es[i].StartedAt < es[j].StartedAt })
	h := es[0]
	for _, e := range es {
		if e.Bridge != "" {
			h = e
			break
		}
	}
	jobs := shellJobs(h.PID)
	if w := workers.get(h.SessionID); w != nil {
		n := 0
		for _, c := range w.Jobs {
			n += c
		}
		jobs = max(jobs, n)
	}
	return hostStatus{ok: true, status: h.Status, statusAt: h.StatusAt, jobs: jobs, pid: h.PID, bridge: h.Bridge}
}

// shellJobs: the background shells claude runs (its children running a shell snapshot), as status.go's __BG__ counts
var shellJobs = func(pid int64) int {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, _ := rescueCommand(ctx, "pgrep", "-c", "-P", strconv.FormatInt(pid, 10), "-f", "shell-snapshots").Output()
	n, _ := strconv.Atoi(strings.TrimSpace(string(out)))
	return n
}

// stallWatch: the supervisor's loop (started by supervise once booted); a one-shot session finishes by itself and
// never gets the nudge
func stallWatch() {
	if readVouchedBool("oneShot") {
		return
	}
	var c stallClock
	for ; ; time.Sleep(stallEvery) {
		if fileExists(harnessPausedPath) { // paused, or stopped for the final snapshot: not stalled
			continue
		}
		screen, _, screenOK := readScreen() // screen.go
		nudge, minutes := stallStep(&c, readHost(), screen, screenOK, time.Now())
		if !nudge {
			continue
		}
		h := readHost()
		cert, err := currentCert()
		if err != nil {
			log.Printf("stall watch: no cert: %v", err)
			continue
		}
		if err := sendToHarness(cert.Options.Harness, liveMode(cert), "jarvis", stallText(h.jobs, minutes)); err != nil {
			log.Printf("stall watch: the nudge wasn't taken: %v", err)
			continue
		}
		log.Printf("stall watch: nudged (idle %d min with %d background jobs)", minutes, h.jobs)
	}
}
