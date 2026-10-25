package main

import (
	"encoding/json"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// rcStep: only an outage that outlasts rcDownAfter, seen between turns, is revived, and again only after rcRetryWait
func TestRCStep(t *testing.T) {
	t0 := time.Unix(1_000_000, 0)
	at := func(m float64) time.Time { return t0.Add(time.Duration(m * float64(time.Minute))) }
	up := rcLook{hostUp: true, bridge: "session_a", server: "connected", idle: true}
	gone := rcLook{hostUp: true, bridge: "session_a", server: "disconnected", idle: true}
	off := rcLook{hostUp: true, idle: true}
	var c rcClock
	for m, l := range []rcLook{up, gone, gone, gone} {
		if rcStep(&c, l, at(float64(m))) {
			t.Fatalf("revived at %d min", m)
		}
	}
	if !rcStep(&c, gone, at(4)) {
		t.Fatal("down 3 min between turns: not revived")
	}
	if rcStep(&c, gone, at(5)) || rcStep(&c, gone, at(13.5)) {
		t.Fatal("revived again before rcRetryWait")
	}
	if !rcStep(&c, gone, at(14.5)) {
		t.Fatal("still down after rcRetryWait: not revived again")
	}

	c = rcClock{}
	busy := off
	busy.idle = false
	for m, l := range []rcLook{off, busy, busy, busy, busy} {
		if rcStep(&c, l, at(float64(m))) {
			t.Fatalf("revived in a turn at %d min", m)
		}
	}
	if !rcStep(&c, off, at(5)) {
		t.Fatal("Remote Control off on the host, turn over: not revived")
	}

	for _, l := range []rcLook{{}, {hostUp: true, bridge: "session_a", idle: true}} { // no host; claude.ai unknown
		c = rcClock{}
		for m := 0; m < 20; m++ {
			if rcStep(&c, l, at(float64(m))) {
				t.Fatalf("%+v revived", l)
			}
		}
	}
	c = rcClock{}
	for m, l := range []rcLook{gone, gone, up, gone, gone, gone} { // a blip resets the clock
		if rcStep(&c, l, at(float64(m))) {
			t.Fatalf("revived at %d min after the blip", m)
		}
	}
}

// the menu as Claude Code 2.1.310 draws it, under a conversation that quotes the same words
const rcMenuOn = `❯ Disconnect this session, please

● Done.
▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔
   Remote Control
   This session is available in the Claude mobile app and at https://claude.ai/code/session_x.
     Disconnect this session
     Show QR code   Scan with your phone to open this session
   ❯ Continue
   Enter to select · Esc to continue`

// the menu of a host with Remote Control off (2.1.310)
const rcMenuOff = `❯ /remote-control
  ⎿  Remote Control disconnected.
────────────────────────────────────────
 Remote Control
   Take this session with you and pick up right where you left off on any device.
   /remote-control.
   ❯ 1. Enable Remote Control  Opens a secure connection to claude.ai.
     2. Never mind             You can always enable it later with /remote-control.`

func TestRCMenu(t *testing.T) {
	m := openMenu(rcMenuOn)
	if d, ok := menuDistance(m, rcDisconnectText); !ok || d != -2 {
		t.Fatalf("distance %d %v", d, ok)
	}
	off := openMenu(rcMenuOff)
	if d, ok := menuDistance(off, rcEnableText); !ok || d != 0 {
		t.Fatalf("off menu: distance %d %v", d, ok)
	}
	if openMenu("❯ Disconnect this session\n") != "" || openMenu("Remote Control\n❯ Disconnect this session\n") != "" {
		t.Fatal("no dialog open: the conversation's text taken for a menu")
	}
	if _, ok := menuDistance(m, rcEnableText); ok {
		t.Fatal("a choice the menu lacks was found")
	}
}

// cursorUp: the menu with its cursor one choice higher
func cursorUp(menu string) string {
	ls := strings.Split(menu, "\n")
	for i, l := range ls {
		if strings.HasPrefix(l, "   ❯ ") && i > 0 && strings.HasPrefix(ls[i-1], "     ") {
			ls[i], ls[i-1] = "     "+l[len("   ❯ "):], "   ❯ "+ls[i-1][5:]
			break
		}
	}
	return strings.Join(ls, "\n")
}

// reviving as Claude Code 2.1.310 does it: a held entry is disconnected (two lines up in its menu), and the next
// /remote-control enables at once; a host with Remote Control off gets the Enable menu
func TestReviveRemoteControl(t *testing.T) {
	for _, tc := range []struct{ held, keys string }{
		{"session_old", "-l /remote-control|Enter|Up|Up|Enter|-l /remote-control|Enter"},
		{"", "-l /remote-control|Enter|Enter"},
	} {
		t.Setenv("HOME", t.TempDir())
		os.MkdirAll(home(t)+"/.claude/sessions", 0o700)
		quietAfterSwitch(t)
		saved := rcStepWait
		rcStepWait, rcUpWait = 2*time.Second, 2*time.Second
		t.Cleanup(func() { rcStepWait = saved })
		reg := func(bridge string) {
			b, _ := json.Marshal(map[string]any{"status": "idle", "pid": os.Getpid(), "bridgeSessionId": bridge})
			os.WriteFile(home(t)+"/.claude/sessions/1.json", b, 0o600)
		}
		reg(tc.held)
		var mu sync.Mutex
		pane, typed, justOff, keys := "❯ ", false, false, []string{}
		paneText = func() string { mu.Lock(); defer mu.Unlock(); return pane }
		sendKeys = func(a ...string) error {
			mu.Lock()
			defer mu.Unlock()
			k := strings.Join(a, " ")
			keys = append(keys, k)
			m := openMenu(pane)
			switch {
			case k == "-l /remote-control":
				typed = true
			case k == "Up":
				pane = cursorUp(pane)
			case k == "Enter" && typed && justOff:
				typed, pane = false, "❯ "
				reg("session_new")
			case k == "Enter" && typed:
				typed, pane = false, rcMenuOff
				if liveBridge() != "" {
					pane = rcMenuOn
				}
			case k == "Enter":
				if d, ok := menuDistance(m, rcDisconnectText); ok && d == 0 {
					reg("")
					justOff = true
				} else if d, ok := menuDistance(m, rcEnableText); ok && d == 0 {
					reg("session_new")
				}
				pane = "❯ "
			}
			return nil
		}
		done := make(chan struct{})
		go func() { reviveRemoteControl(tc.held); close(done) }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("revive hung")
		}
		if got := strings.Join(keys, "|"); got != tc.keys || liveBridge() != "session_new" {
			t.Fatalf("held %q: keys %s, bridge %q", tc.held, got, liveBridge())
		}
	}
}
