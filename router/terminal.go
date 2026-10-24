package main

// The live terminal (Jarvis 1's lib/tty.js over grants instead of Fly exec): the harness runs in tmux session
// `claude` inside the machine. Viewing is the pane the machine's supervisor uploads itself (machine/screen.go),
// never a command run in the machine; typing and resizing are commands under the "terminal" holder's grant.

import (
	"errors"
	"strconv"
	"strings"
	"time"
)

func shq(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

type TermSnap struct {
	Screen string `json:"screen"`
	Cursor string `json:"cursor"`       // x,y,width,height,visible
	At     string `json:"at,omitempty"` // when the machine pushed it
}

// pushedScreen: a machine's screen push counts while its heartbeat (30 s) can still be on time
const screenFresh = 45 * time.Second

// pushedScreen: the latest pane the session's running machine pushed itself (machine/screen.go; screens.go), if it
// is fresh
func (r *Router) pushedScreen(session string) (TermSnap, bool) {
	snap, age, ok := r.latestScreen(session)
	if !ok || age >= screenFresh {
		return TermSnap{}, false
	}
	snap.At = time.Now().Add(-age).UTC().Format(time.RFC3339)
	return snap, true
}

// latestScreen: the last pane the session's running machine pushed, however old
func (r *Router) latestScreen(session string) (TermSnap, time.Duration, bool) {
	var machine string
	r.st.Do(func(d *persisted) {
		if s := d.Sessions[session]; s != nil {
			machine = s.MachineID
		}
	})
	if machine == "" {
		return TermSnap{}, 0, false
	}
	return r.st.Screen(session, machine)
}

// TermSnapshot: the pane the session's running machine last uploaded, however old (At says when). Viewing needs no
// grant and runs nothing in the machine (Deyao, 2026-10-12, 2026-10-24: "The supervisor should just upload it").
func (r *Router) TermSnapshot(session string) (TermSnap, error) {
	snap, age, ok := r.latestScreen(session)
	if !ok {
		return TermSnap{}, errors.New("no screen from the machine yet: its supervisor sends the harness's pane every 2 s once the harness runs")
	}
	snap.At = time.Now().Add(-age).UTC().Format(time.RFC3339)
	return snap, nil
}

// allowed tmux key names for TermInput (anything else is sent as literal text)
var tmuxKeys = map[string]bool{"Enter": true, "Escape": true, "Tab": true, "BTab": true, "BSpace": true, "Up": true, "Down": true,
	"Left": true, "Right": true, "C-c": true, "C-d": true, "C-j": true, "C-o": true, "C-r": true, "C-u": true, "PageUp": true, "PageDown": true}

func (r *Router) TermInput(session, text string, keys []string) error {
	var cmd []string
	if text != "" {
		if len(text) > 4000 {
			text = text[:4000]
		}
		cmd = append(cmd, "tmux send-keys -t claude -l -- "+shq(text))
	}
	for _, k := range keys {
		if !tmuxKeys[k] {
			return errors.New("unknown key " + k)
		}
		cmd = append(cmd, "tmux send-keys -t claude "+k)
	}
	if len(cmd) == 0 {
		return nil
	}
	_, err := r.Exec(session, "terminal", strings.Join(cmd, " && "), 15*time.Second)
	return err
}

func (r *Router) TermResize(session string, cols, rows int) error {
	if cols < 20 || cols > 400 || rows < 5 || rows > 200 {
		return errors.New("bad size")
	}
	_, err := r.Exec(session, "terminal", "tmux resize-window -t claude -x "+strconv.Itoa(cols)+" -y "+strconv.Itoa(rows), 15*time.Second)
	return err
}
