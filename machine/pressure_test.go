package main

import (
	"strings"
	"testing"
	"time"
)

// the supervisor's pressure watch: a new episode is told at once, again every 15 min while it lasts, never while
// healthy; a memory episode ends after 15 healthy minutes, a disk one once the disk is clear again
func TestPressureEpisode(t *testing.T) {
	t0 := time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC)
	at := func(m int) time.Time { return t0.Add(time.Duration(m) * time.Minute) }
	var e pressureEpisode
	if e.step(false, true, at(0), pressureMemClear) {
		t.Fatal("told while healthy")
	}
	if !e.step(true, false, at(1), pressureMemClear) {
		t.Fatal("a new episode wasn't told")
	}
	if e.step(true, false, at(2), pressureMemClear) {
		t.Fatal("told again within 15 min")
	}
	if !e.step(true, false, at(16), pressureMemClear) {
		t.Fatal("not told again after 15 min under pressure")
	}
	// healthy for less than the clear time, then under again: the same episode, no new message before its 15 min
	e.step(false, true, at(17), pressureMemClear)
	if e.step(true, false, at(20), pressureMemClear) {
		t.Fatal("a dip inside the episode was told as a new one")
	}
	// healthy for the clear time: the episode ends, the next one is told at once
	e.step(false, true, at(21), pressureMemClear)
	e.step(false, true, at(36), pressureMemClear)
	if !e.step(true, false, at(37), pressureMemClear) {
		t.Fatal("a new episode after a clear one wasn't told")
	}
	// a message the harness didn't take is due again at the next look
	e.untold()
	if !e.step(true, false, at(38), pressureMemClear) {
		t.Fatal("an untaken message wasn't sent again")
	}
	// between the low and the clear marks (not under, not healthy) nothing is told and the episode stays
	var d pressureEpisode
	d.step(true, false, at(0), 0)
	if d.step(false, false, at(1), 0) || !d.on {
		t.Fatal("the disk episode ended before the disk was clear")
	}
	d.step(false, true, at(2), 0)
	if d.on {
		t.Fatal("a clear disk didn't end the episode")
	}
}

// the reasons are the router's (router/memory.go, router/disk.go), so the session hears of the episode Deyao is DMed
func TestPressureReasons(t *testing.T) {
	n := func(v int64) *int64 { return &v }
	f := func(v float64) *float64 { return &v }
	var w pressureWatch
	ok := memSample{TotalKb: 4 << 20, AvailKb: 2 << 20, OOMKills: n(3), PSIFull60: f(0)}
	if r := w.memReason(ok); r != "" {
		t.Fatalf("healthy memory: %q", r)
	}
	killed := ok
	killed.OOMKills = n(5)
	if r := w.memReason(killed); !strings.Contains(r, "killed 2 processes") {
		t.Fatalf("oom kills: %q", r)
	}
	if r := w.memReason(killed); r != "" {
		t.Fatalf("the same kills counted twice: %q", r)
	}
	thrash := killed
	thrash.PSIFull60 = f(12)
	if r := w.memReason(thrash); !strings.Contains(r, "thrashing") {
		t.Fatalf("psi: %q", r)
	}
	low := killed
	low.AvailKb = 100 << 10
	if r := w.memReason(low); !strings.Contains(r, "almost out of memory") {
		t.Fatalf("low memory: %q", r)
	}
	// the disk that counts is the volume when there is one
	root := &diskFS{TotalKb: 8 << 20, AvailKb: 4 << 20}
	if low, clear, _ := diskPressure(diskSample{Root: root}); low || !clear {
		t.Fatal("a half-empty disk is low or not clear")
	}
	if low, _, d := diskPressure(diskSample{Root: root, Data: &diskFS{TotalKb: 10 << 20, AvailKb: 512 << 10}}); !low || !strings.Contains(d, "volume") {
		t.Fatalf("a full volume: %v %q", low, d)
	}
	if low, clear, _ := diskPressure(diskSample{Root: &diskFS{TotalKb: 10 << 20, AvailKb: 1536 << 10}}); low || clear {
		t.Fatal("between the marks the disk is neither low nor clear")
	}
}

// the text says what Deyao asked for (2026-11-12): which pressure, not to upgrade, Discord him when one is needed
func TestPressureText(t *testing.T) {
	m := pressureText("memory", "it is almost out of memory", "100 MB free of 4.0 GB")
	for _, want := range []string{"Jarvis watchdog: memory pressure", "100 MB free of 4.0 GB", "Do not upgrade", "Discord Deyao", "This is an automated message from Jarvis."} {
		if !strings.Contains(m, want) {
			t.Fatalf("%q is missing %q", m, want)
		}
	}
	if d := pressureText("disk", "it is almost out of disk", "0.5 GB free of 10.0 GB on its volume"); !strings.Contains(d, "Jarvis watchdog: disk pressure") || !strings.Contains(d, "Do not upgrade") {
		t.Fatalf("disk text: %q", d)
	}
}
