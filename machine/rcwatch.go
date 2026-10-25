package main

// The Remote Control watch (Deyao, 2026-10-25: "Remote Control in a session is not always reliable"; "not jarvis do,
// supervisor do"): a component of the supervisor that looks at its own session's Claude host every rcEvery. Remote
// Control is down when the host has no Remote Control entry (the CLI tore its bridge down or gave up retrying), or
// its entry is "disconnected" on claude.ai (what the Claude app shows) while the machine itself reaches Anthropic.
// Claude Code reconnects by itself after a blip (a cut of about a minute comes back within seconds of the network),
// so only an outage that lasts rcDownAfter counts. Then, between turns, the supervisor types /remote-control into
// the host: an entry the CLI still holds is disconnected first ("Disconnect this session"), and "Enable Remote
// Control" makes a fresh connection with the same conversation. A revive that didn't take is tried again after
// rcRetryWait. The router takes no part.

import (
	"log"
	"strings"
	"sync"
	"syscall"
	"time"
)

var (
	rcEvery     = time.Minute
	rcDownAfter = 3 * time.Minute
	rcRetryWait = 10 * time.Minute
	rcStepWait  = 30 * time.Second // for the menu, typed between turns
)

const rcDisconnectText = "Disconnect this session" // the /remote-control menu of a host that has Remote Control on

// rcTyping: one typist into the host at a time (this watch, an account switch's enableRemoteControl)
var rcTyping sync.Mutex

// rcLook: one look at the host
type rcLook struct {
	hostUp bool   // the host's process is alive
	bridge string // its Remote Control entry ("" = Remote Control is off on the host)
	server string // the entry's connection_status on claude.ai ("" = not known)
	idle   bool   // between turns: what is typed runs at once and lands in no dialog
}

// rcClock: since when Remote Control has been down, and when it was last revived
type rcClock struct{ since, tried time.Time }

// rcStep: one look → whether to revive now
func rcStep(c *rcClock, l rcLook, now time.Time) bool {
	if !l.hostUp || (l.bridge != "" && (l.server == "" || l.server == "connected")) {
		*c = rcClock{}
		return false
	}
	if c.since.IsZero() {
		c.since = now
		return false
	}
	if now.Sub(c.since) < rcDownAfter || !l.idle || (!c.tried.IsZero() && now.Sub(c.tried) < rcRetryWait) {
		return false
	}
	c.tried = now
	return true
}

// lookRC: the host as its registry file says, and its entry as claude.ai says
func lookRC() rcLook {
	h := readHost() // stall.go
	if !h.ok || h.pid <= 0 || syscall.Kill(int(h.pid), 0) != nil {
		return rcLook{}
	}
	l := rcLook{hostUp: true, bridge: h.bridge, idle: h.status == "idle"}
	if h.status == "busy" { // busy with background jobs only, as the stall watch tells it
		screen, _, ok := readScreen()
		l.idle = ok && !turnOnScreen(screen)
	}
	if key := strings.TrimPrefix(strings.TrimPrefix(h.bridge, "cse_"), "session_"); key != "" {
		if tok := claudeAccessToken(); tok != "" {
			if s, _, err := fetchCodeSession(key, tok); err == nil {
				l.server = s.ConnectionStatus
			}
		}
	}
	return l
}

// rcWatch: the supervisor's loop (started by supervise once booted), for the harness that is a Remote Control host
func rcWatch() {
	var c rcClock
	for ; ; time.Sleep(rcEvery) {
		if fileExists(harnessPausedPath) { // paused, or stopped for the final snapshot
			c = rcClock{}
			continue
		}
		if h := certHarness(); h != "" && h != "claude" {
			continue
		}
		l := lookRC()
		if !rcStep(&c, l, time.Now()) {
			continue
		}
		log.Printf("remote control: down for %s (entry %q, claude.ai: %q): typing /remote-control",
			time.Since(c.since).Round(time.Second), l.bridge, l.server)
		reviveRemoteControl(l.bridge)
	}
}

// reviveRemoteControl: disconnect the entry the host still holds, then enable Remote Control again
func reviveRemoteControl(held string) {
	if !rcTyping.TryLock() {
		log.Printf("remote control: an account switch is typing into the host: left to it")
		return
	}
	defer rcTyping.Unlock()
	if held != "" && !rcChoose(rcDisconnectText, func() bool { return liveBridge() == "" }) {
		log.Printf("remote control: the host still holds its entry after Disconnect")
		return
	}
	if rcChoose(rcEnableText, func() bool { return liveBridge() != "" }) {
		log.Printf("remote control: up again (%s)", liveBridge())
	} else {
		log.Printf("remote control: no entry after choosing Enable")
	}
}

// rcChoose: type /remote-control and choose the line of its menu that says want, until done; a command that does it
// with no menu (Enable, right after a Disconnect) is done too. Escape only ever goes to the open menu
func rcChoose(want string, done func() bool) bool {
	if err := sendKeys("-l", "/remote-control"); err != nil {
		log.Printf("remote control: typing: %v", err)
		return false
	}
	time.Sleep(300 * time.Millisecond)
	sendKeys("Enter")
	escape := func() {
		if openMenu(paneText()) != "" {
			sendKeys("Escape")
		}
	}
	if !waitUntil(rcStepWait, func() bool { return done() || strings.Contains(openMenu(paneText()), want) }) {
		log.Printf("remote control: the /remote-control menu didn't offer %q within %s", want, rcStepWait)
		escape()
		return false
	}
	if done() {
		return true
	}
	for i := 0; i < 8; i++ {
		d, ok := menuDistance(openMenu(paneText()), want)
		switch {
		case !ok:
			i = 8
		case d == 0:
			sendKeys("Enter")
			return waitUntil(rcUpWait, done)
		case d < 0:
			sendKeys("Up")
		default:
			sendKeys("Down")
		}
		time.Sleep(200 * time.Millisecond)
	}
	log.Printf("remote control: couldn't select %q in the menu", want)
	escape()
	return false
}

// openMenu: the /remote-control dialog at the bottom of the pane, from its title line ("Remote Control" alone; its
// border differs by state), else "" — the conversation above it may quote any menu text
func openMenu(pane string) string {
	ls := strings.Split(pane, "\n")
	for i := len(ls) - 1; i >= 0; i-- {
		if strings.TrimSpace(ls[i]) == "Remote Control" {
			m := strings.Join(ls[i:], "\n")
			if _, ok := menuDistance(m, ""); ok {
				return m
			}
			return ""
		}
	}
	return ""
}

// menuDistance: lines from the menu's cursor ("❯") to the choice that says want (negative = above it)
func menuDistance(menu, want string) (int, bool) {
	cur, at := -1, -1
	for i, line := range strings.Split(menu, "\n") {
		if strings.HasPrefix(line, "  ") && strings.HasPrefix(strings.TrimSpace(line), "❯") { // the cursor is indented
			cur = i
		}
		if strings.Contains(line, want) {
			at = i
		}
	}
	return at - cur, cur >= 0 && at >= 0
}
