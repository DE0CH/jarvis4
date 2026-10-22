package main

// The final snapshot's progress (machine/snapprogress.go): while the supervisor makes and uploads the snapshot of a
// pause, destroy or Upgrade, it reports numbers every few seconds:
//
//	POST /m/snapshot-progress  {phase: "measuring" | "uploading" | "writing", done, total /* uncompressed bytes */,
//	                            sent /* compressed bytes sent so far */, elapsedMs /* since the phase began */}
//
// The router builds the words from the numbers itself (no machine text reaches the app) and puts them in the
// session's `waiting` (the status line the app and web show: "pausing: uploading snapshot 1.2/3.4 GB, 40 MB/s,
// 55 s left"), only while a snapshot of that machine is awaited, and a line into the running operation's lifecycle
// log at most every progressNoteEvery.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// SnapProgress: one report
type SnapProgress struct {
	Phase     string `json:"phase"`
	Done      int64  `json:"done"`
	Total     int64  `json:"total"`
	Sent      int64  `json:"sent"`
	ElapsedMs int64  `json:"elapsedMs"`
}

var progressNoteEvery = 20 * time.Second

var progressNotes sync.Map // machine → time.Time of the last lifecycle note

// snapProgressText: "uploading snapshot 1.2/3.4 GB, 40 MB/s, 55 s left" ("" for a report that makes no sense)
func snapProgressText(p SnapProgress) string {
	if p.Done < 0 || p.Total < 0 || p.Sent < 0 || p.ElapsedMs < 0 {
		return ""
	}
	switch p.Phase {
	case "measuring":
		return "measuring the snapshot (" + byteText(p.Total, p.Total) + " so far)"
	case "uploading", "writing":
	default:
		return ""
	}
	total := max(p.Total, p.Done)
	what := "uploading snapshot"
	if p.Phase == "writing" {
		what = "writing snapshot"
	}
	s := what + " " + byteRatio(p.Done, total)
	if total > 0 {
		s += fmt.Sprintf(" (%d%%)", p.Done*100/total)
	}
	if p.ElapsedMs >= 1000 && p.Done > 0 {
		rate := float64(p.Done) / (float64(p.ElapsedMs) / 1000)
		s += ", " + byteText(int64(rate), int64(rate)) + "/s"
		if left := float64(total-p.Done) / rate; total > p.Done {
			s += ", " + leftText(time.Duration(left*float64(time.Second))) + " left"
		}
	}
	return s
}

// byteText: n in the unit `scale` calls for (GB from 1 GB, else MB, else KB)
func byteText(n, scale int64) string {
	switch {
	case scale >= 1e9:
		return fmt.Sprintf("%.1f GB", float64(n)/1e9)
	case scale >= 1e6:
		return fmt.Sprintf("%.0f MB", float64(n)/1e6)
	}
	return fmt.Sprintf("%.0f KB", float64(n)/1e3)
}

// byteRatio: "1.2/3.4 GB"
func byteRatio(done, total int64) string {
	t := byteText(total, total)
	d := byteText(done, total)
	for _, u := range []string{" GB", " MB", " KB"} {
		if len(d) > len(u) && d[len(d)-len(u):] == u {
			d = d[:len(d)-len(u)]
		}
	}
	return d + "/" + t
}

// leftText: "55 s", "3 min 20 s"
func leftText(d time.Duration) string {
	sec := int(d.Round(time.Second) / time.Second)
	if sec < 60 {
		return fmt.Sprintf("%d s", sec)
	}
	if sec%60 == 0 {
		return fmt.Sprintf("%d min", sec/60)
	}
	return fmt.Sprintf("%d min %d s", sec/60, sec%60)
}

func (r *Router) registerSnapProgress(m machineRoute) {
	m("POST /m/snapshot-progress", func(w http.ResponseWriter, req *http.Request, machine string, body []byte) {
		var p SnapProgress
		if json.Unmarshal(body, &p) != nil {
			writeJSON(w, 400, map[string]string{"error": "{phase, done, total, sent, elapsedMs}"})
			return
		}
		text := snapProgressText(p)
		if text == "" {
			writeJSON(w, 400, map[string]string{"error": "phase: measuring | uploading | writing; numbers ≥ 0"})
			return
		}
		var sid string
		r.st.Do(func(d *persisted) {
			if s := d.Sessions[d.Machines[machine]]; s != nil && s.MachineID == machine {
				sid = s.ID
			}
		})
		if sid == "" || !r.snapshotAwaited(machine) {
			writeJSON(w, 200, map[string]bool{"ok": false}) // nothing waits on it: not shown
			return
		}
		r.snapshotReported(machine, p) // snapwait.go: numbers that moved keep the wait going
		r.setWaiting(sid, text)
		now := time.Now()
		if last, ok := progressNotes.Load(machine); !ok || now.Sub(last.(time.Time)) >= progressNoteEvery {
			progressNotes.Store(machine, now)
			r.lcNote(sid, machine, text)
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
}
