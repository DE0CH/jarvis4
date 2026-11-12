package main

// The live dashboard's Jarvis 4 panel (Deyao, 2026-11-12: "a panel for my jarvis 4 status, i just need to know
// limited information like if session is working, idle, or with background"): the leading replica POSTs his running
// sessions every livePushEvery to LIVE_PUSH_URL with the header X-Jarvis-Secret: LIVE_PUSH_SECRET (Secret
// router-secrets-livepush, infra/router-secrets.py --part livepush; unset = off). Jarvis 4 holds the dashboard's write
// secret; the dashboard holds nothing of Jarvis 4's. Each session is only its title, a state, two counts and since
// when; at most liveMax, the most active first, with the total running.

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"regexp"
	"sort"
	"time"
)

const (
	livePushEvery = 5 * time.Second
	liveMax       = 16 // the most the dashboard's biggest layout shows
)

type liveSession struct {
	Name      string `json:"name"`
	State     string `json:"state"` // working | waiting | background | idle | booting
	Jobs      int    `json:"jobs"`
	Subagents int    `json:"subagents"`
	Since     int64  `json:"since,omitempty"` // ms: the status's last change (statusUpdatedAt; changes every turn)
}

type liveDocument struct {
	At       int64         `json:"at"`
	Total    int           `json:"total"`
	Sessions []liveSession `json:"sessions"`
}

// Claude Code's working line ("✻ Thinking… (12s · esc to interrupt)"), as machine/stall.go reads it
var (
	liveSpinner = regexp.MustCompile(`(?m)^\s*\S\s+[A-Z][\p{L}-]*…\s*\(\d`)
	liveANSI    = regexp.MustCompile(`\x1b\[[0-9;?]*[A-Za-z]`)
)

// liveRank: the order on the panel, the most active first
var liveRank = map[string]int{"waiting": 0, "working": 1, "background": 2, "booting": 3, "idle": 4}

// liveStateOf: a running session's state. Claude Code keeps a host "busy" while background jobs run after its turn
// ended (machine/stall.go), so a busy host with jobs or subagents and no working line on its pane is "background".
// screen: its pushed pane ("" when none is fresh).
func liveStateOf(g *Registry, fresh bool, screen string) (state string, jobs, subagents int) {
	if g == nil || !fresh || g.Status == "" {
		return "booting", 0, 0
	}
	jobs = g.BgTasks
	if g.Workers != nil {
		n := 0
		for _, v := range g.Workers.Jobs {
			n += v
		}
		jobs, subagents = max(jobs, n), g.Workers.Subagents
	}
	switch g.Status {
	case "waiting":
		return "waiting", jobs, subagents
	case "idle":
		if jobs > 0 || subagents > 0 {
			return "background", jobs, subagents
		}
		return "idle", jobs, subagents
	case "busy":
		if (jobs > 0 || subagents > 0) && screen != "" && !liveSpinner.MatchString(liveANSI.ReplaceAllString(screen, "")) {
			return "background", jobs, subagents
		}
	}
	return "working", jobs, subagents
}

// liveDoc: the push's body (the screens are read outside the state lock: a database read each)
func (r *Router) liveDoc(now time.Time) liveDocument {
	type row struct {
		s    liveSession
		id   string
		busy bool
	}
	var rows []row
	r.st.Do(func(d *persisted) {
		for _, s := range d.Sessions {
			if s.State != "started" || s.MachineID == "" {
				continue
			}
			l, fresh := s.Live, false
			var g *Registry
			if l != nil && l.Reg != nil {
				g, fresh = l.Reg, now.Sub(l.LastReport) <= defaultPilot.StaleReport
			}
			st, jobs, sub := liveStateOf(g, fresh, "")
			x := liveSession{Name: sessionTitle(*s), State: st, Jobs: jobs, Subagents: sub}
			if g != nil && fresh && g.StatusUpdatedAt > 0 {
				x.Since = g.StatusUpdatedAt
			}
			rows = append(rows, row{s: x, id: s.ID, busy: g != nil && fresh && g.Status == "busy" && (jobs > 0 || sub > 0)})
		}
	})
	for i := range rows {
		if !rows[i].busy {
			continue
		}
		if snap, ok := r.pushedScreen(rows[i].id); ok && !liveSpinner.MatchString(liveANSI.ReplaceAllString(snap.Screen, "")) {
			rows[i].s.State = "background"
		}
	}
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i].s, rows[j].s
		if liveRank[a.State] != liveRank[b.State] {
			return liveRank[a.State] < liveRank[b.State]
		}
		return a.Since > b.Since
	})
	doc := liveDocument{At: now.UnixMilli(), Total: len(rows), Sessions: []liveSession{}}
	for i := 0; i < len(rows) && i < liveMax; i++ {
		doc.Sessions = append(doc.Sessions, rows[i].s)
	}
	return doc
}

// startLivePush: the loop, on the leading replica only (leaderlease.go); off without LIVE_PUSH_URL / LIVE_PUSH_SECRET
func (r *Router) startLivePush() {
	url, secret := os.Getenv("LIVE_PUSH_URL"), os.Getenv("LIVE_PUSH_SECRET")
	if url == "" || secret == "" {
		return
	}
	c := &http.Client{Timeout: 10 * time.Second}
	go func() {
		failing := false
		for range time.Tick(livePushEvery) {
			if !leads() {
				continue
			}
			err := livePost(c, url, secret, r.liveDoc(time.Now()))
			if (err != nil) != failing {
				failing = err != nil
				if failing {
					log.Printf("live push: %v", err)
				} else {
					log.Printf("live push: working again")
				}
			}
		}
	}()
}

type liveHTTPError int

func (e liveHTTPError) Error() string { return "HTTP " + http.StatusText(int(e)) }

func livePost(c *http.Client, url, secret string, doc liveDocument) error {
	b, _ := json.Marshal(doc)
	req, err := http.NewRequest("POST", url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Jarvis-Secret", secret)
	res, err := c.Do(req)
	if err != nil {
		return err
	}
	res.Body.Close()
	if res.StatusCode != 200 {
		return liveHTTPError(res.StatusCode)
	}
	return nil
}
