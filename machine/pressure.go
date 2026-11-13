package main

// The pressure watch (Deyao, 2026-11-12: "a jarvis watcher (similar to the idle/stall watcher) that says disk
// pressure/memory pressure, do not upgrade; discord Deyao if upgrade is necessary or recommended"): a component of
// the supervisor, beside the stall watch. Every pressureEvery it reads its own machine's memory and disk and decides
// by the router's rules (router/memory.go, router/disk.go: the episode Deyao is DMed about) whether the machine is
// short of memory or of disk. A process the harness's own memory guard killed counts too (the aviary supervisor
// kills the biggest process before the kernel would, within seconds: none of the router's three signs ever shows,
// and an aviary session lost `npm ci` twice with nothing said, 2026-11-13). A new episode is told to the session's harness through the Jarvis channel at once, and
// again every pressureAgain while it lasts. The text tells the session not to upgrade by itself: a bigger machine or
// disk is Deyao's decision, asked for over Discord. The router takes no part.

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	pressureEvery    = 30 * time.Second
	pressureAgain    = 15 * time.Minute
	pressureMemClear = 15 * time.Minute // router/memory.go memClear

	// router/memory.go
	pressurePSIFullPct  = 10.0
	pressureLowAvailPct = 5.0
	// router/disk.go
	pressureDiskLowPct   = 10.0
	pressureDiskLowKb    = 1024 * 1024
	pressureDiskClearPct = 20.0
	pressureDiskClearKb  = 2048 * 1024
)

// pressureEpisode: one kind of pressure (memory or disk): whether an episode runs, when the session was last told,
// since when the machine has been healthy again
type pressureEpisode struct {
	on      bool
	told    time.Time
	healthy time.Time
}

// step: one look → whether to tell the session now. under: the machine is short now; healthy: it is clear (for
// memory the opposite of under, for the disk a higher mark); the episode ends after clear of healthy looks.
func (e *pressureEpisode) step(under, healthy bool, now time.Time, clear time.Duration) bool {
	if under {
		e.healthy = time.Time{}
		if !e.on || now.Sub(e.told) >= pressureAgain {
			e.on, e.told = true, now
			return true
		}
		return false
	}
	if !e.on {
		return false
	}
	if !healthy {
		e.healthy = time.Time{}
		return false
	}
	if e.healthy.IsZero() {
		e.healthy = now
	}
	if now.Sub(e.healthy) >= clear {
		*e = pressureEpisode{}
	}
	return false
}

// untold: the harness didn't take the message: it is due again at the next look
func (e *pressureEpisode) untold() { e.told = time.Time{} }

// pressureWatch: the two episodes, the kernel's oom_kill count at the last look, and how far the harness's memory
// guard's log has been read
type pressureWatch struct {
	mem, disk pressureEpisode
	oomKills  *int64
	guard     guardLog
}

// guardLogPath: where a harness with its own memory guard logs its kills: the aviary supervisor's log
// (harness-aviary.sh; JSON lines, `"msg":"memory guard killed"` with `comm` and `rss` in bytes). Missing on every
// other harness.
var guardLogPath = func() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".aviary", "supervisor.out")
}

// guardLog: the guard's log read up to offset; started says the first look is over (what the log held before it is
// not news)
type guardLog struct {
	offset  int64
	started bool
}

// kills: the guard's kills logged since the last look, as "npm ci at 3.1 GB". A log that got shorter (a new one) is
// read from its start.
func (g *guardLog) kills() []string {
	f, err := os.Open(guardLogPath())
	if err != nil {
		return nil
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil
	}
	if !g.started {
		g.started, g.offset = true, st.Size()
		return nil
	}
	if st.Size() < g.offset {
		g.offset = 0
	}
	if _, err := f.Seek(g.offset, io.SeekStart); err != nil {
		return nil
	}
	b, err := io.ReadAll(io.LimitReader(f, 4<<20))
	if err != nil {
		return nil
	}
	// only whole lines: one still being written is read at the next look
	end := strings.LastIndexByte(string(b), '\n') + 1
	g.offset += int64(end)
	var out []string
	for _, l := range strings.Split(string(b[:end]), "\n") {
		if !strings.Contains(l, "memory guard killed") {
			continue
		}
		var e struct {
			Msg  string  `json:"msg"`
			Comm string  `json:"comm"`
			Rss  float64 `json:"rss"`
		}
		if json.Unmarshal([]byte(l), &e) != nil || e.Msg != "memory guard killed" {
			continue
		}
		out = append(out, fmt.Sprintf("%s at %.1f GB", e.Comm, e.Rss/(1<<30)))
	}
	return out
}

// memReason: why the machine is short of memory now ("" when it is not), as router/memory.go observe decides
func (w *pressureWatch) memReason(s memSample) string {
	reason := ""
	guardKills := w.guard.kills()
	switch {
	case len(guardKills) > 0:
		reason = fmt.Sprintf("the session's memory guard killed %s for lack of memory", strings.Join(guardKills, ", "))
	case w.oomKills != nil && s.OOMKills != nil && *s.OOMKills > *w.oomKills:
		n := *s.OOMKills - *w.oomKills
		reason = fmt.Sprintf("the kernel killed %d process%s for lack of memory", n, map[bool]string{true: "", false: "es"}[n == 1])
	case s.PSIFull60 != nil && *s.PSIFull60 >= pressurePSIFullPct:
		reason = fmt.Sprintf("it is thrashing (stalled on memory %.0f%% of the last minute)", *s.PSIFull60)
	case s.TotalKb > 0 && 100*float64(s.AvailKb)/float64(s.TotalKb) < pressureLowAvailPct:
		reason = "it is almost out of memory"
	}
	if s.OOMKills != nil {
		w.oomKills = s.OOMKills
	}
	return reason
}

// memDetail: the numbers and the biggest processes (router/memory.go describeMem)
func memDetail(s memSample) string {
	var top []string
	for _, p := range s.Top {
		if p.RssKb > 100*1024 {
			top = append(top, fmt.Sprintf("%s %.1f GB", p.Comm, float64(p.RssKb)/1048576))
		}
	}
	out := fmt.Sprintf("%d MB free of %.1f GB", s.AvailKb/1024, float64(s.TotalKb)/1048576)
	if len(top) > 0 {
		out += " (biggest: " + strings.Join(top, ", ") + ")"
	}
	return out
}

// diskPressure: the disk that counts (the volume when there is one, else the root): low, clear again, the numbers
func diskPressure(s diskSample) (low, clear bool, detail string) {
	fs, where := s.Root, "its machine's disk"
	if s.Data != nil && s.Data.TotalKb > 0 {
		fs, where = s.Data, "its volume"
	}
	if fs == nil || fs.TotalKb <= 0 {
		return false, true, ""
	}
	pct := 100 * float64(fs.AvailKb) / float64(fs.TotalKb)
	low = pct < pressureDiskLowPct || fs.AvailKb < pressureDiskLowKb
	clear = pct >= pressureDiskClearPct && fs.AvailKb >= pressureDiskClearKb
	return low, clear, fmt.Sprintf("%.1f GB free of %.1f GB on %s", float64(fs.AvailKb)/1048576, float64(fs.TotalKb)/1048576, where)
}

// pressureText: the watchdog's message; kind is "memory" or "disk"
func pressureText(kind, reason, detail string) string {
	free := "stop processes you no longer need (leftover browsers, finished servers, parallel builds)"
	more := "an upgrade to a bigger machine"
	if kind == "disk" {
		free = "remove files you made and no longer need (build output, caches, downloads)"
		more = "more disk or an upgrade"
	}
	return fmt.Sprintf("Jarvis watchdog: %s pressure on this session's machine: %s (%s). ", kind, reason, detail) +
		"Do not upgrade the machine yourself. Free what you safely can, " + free + ", and carry on with the task. " +
		"If " + more + " is necessary or recommended, Discord Deyao and say why; he decides. " +
		"This check repeats every 15 min while the pressure lasts. This is an automated message from Jarvis."
}

// pressureWatchLoop: the supervisor's loop (started by supervise once booted)
func pressureWatchLoop() {
	var w pressureWatch
	for ; ; time.Sleep(pressureEvery) {
		if fileExists(harnessPausedPath) { // paused, or stopped for the final snapshot: nobody to tell
			continue
		}
		var texts []string
		var told []*pressureEpisode
		now := time.Now()
		if s, err := readMemory(); err == nil {
			reason := w.memReason(s)
			if w.mem.step(reason != "", reason == "", now, pressureMemClear) {
				texts, told = append(texts, pressureText("memory", reason, memDetail(s))), append(told, &w.mem)
			}
		}
		if s, err := readDisk(); err == nil {
			low, clear, detail := diskPressure(s)
			if w.disk.step(low, clear, now, 0) {
				texts, told = append(texts, pressureText("disk", "it is almost out of disk", detail)), append(told, &w.disk)
			}
		}
		if len(texts) == 0 {
			continue
		}
		cert, err := currentCert()
		for i, text := range texts {
			if err == nil {
				err = sendToHarness(cert.Options.Harness, liveMode(cert), "jarvis", text)
			}
			if err != nil {
				log.Printf("pressure watch: the message wasn't taken: %v", err)
				told[i].untold()
				continue
			}
			log.Printf("pressure watch: told the session (%s)", strings.SplitN(text, ". ", 2)[0])
		}
	}
}
