package main

// Auto-accept (Deyao, 2026-11-04: "the supervisor can see the terminal screen, just make it auto accept prompts like
// that"): a session in bypass mode still gets some tool permission dialogs. Claude Code asks about commands it can't
// check (a background agent's `bash -c` building variable names), and those wait for a click nobody is there for. While
// the session's live mode is bypass, the supervisor reads its own tmux pane every acceptEvery, and when the bottom of
// the pane is a tool permission dialog ("Do you want to proceed?" with "❯ 1. Yes" focused) it presses Enter, which
// takes the focused "1. Yes" (allow once; it never picks "always allow" or a mode switch). A session in auto mode
// is left alone: its prompts are Deyao's to answer.
//
// Only Claude Code's tool permission questions count (acceptQuestion). The workspace trust dialog, the API key
// question, a plan's approval and AskUserQuestion's choices have other wording or another focused option, so they
// are never answered here. Each accept is logged with the dialog's first lines.

import (
	"crypto/sha256"
	"log"
	"regexp"
	"strings"
	"time"
)

const acceptEvery = 2 * time.Second

// acceptQuestion: the tool permission questions (Claude Code 2.1.318: Bash and other tools "Do you want to
// proceed?", Edit "Do you want to make this edit to X?", Write "Do you want to create X?", WebFetch "Do you want to
// allow Claude to fetch this content?")
var acceptQuestion = regexp.MustCompile(`^\s*Do you want to (proceed\?|make this edit to .+\?|create .+\?|allow Claude to fetch this content\?)\s*$`)

// acceptYes: the focused first option
var acceptYes = regexp.MustCompile(`^\s*❯\s*1\.\s*Yes\s*$`)

// acceptFooter: the dialog's last line
var acceptFooter = regexp.MustCompile(`^\s*Esc to cancel\b`)

// permissionDialog: whether the pane ends in a tool permission dialog with "1. Yes" focused, and the dialog's text
// (from its header) for the log. The question must be followed directly by the focused Yes, and the footer must be
// the pane's last non-blank line, so a dialog quoted in the conversation above never counts.
func permissionDialog(screen string) (bool, string) {
	lines := strings.Split(ansiSeq.ReplaceAllString(screen, ""), "\n")
	last := len(lines) - 1
	for last >= 0 && strings.TrimSpace(lines[last]) == "" {
		last--
	}
	if last < 2 || !acceptFooter.MatchString(lines[last]) {
		return false, ""
	}
	for i := last - 1; i >= 0 && i >= last-40; i-- {
		if !acceptQuestion.MatchString(lines[i]) {
			continue
		}
		if !acceptYes.MatchString(lines[i+1]) {
			return false, ""
		}
		start := i
		for start > 0 && start > i-12 && !strings.HasPrefix(strings.TrimSpace(lines[start-1]), "────") {
			start--
		}
		return true, strings.TrimSpace(strings.Join(lines[start:i+1], "\n"))
	}
	return false, ""
}

// acceptStep: one look → whether to press Enter now. The same dialog (by its text) is pressed at most twice, so a
// screen that doesn't change after Enter doesn't get Enter forever.
type acceptState struct {
	last  [32]byte
	tries int
}

func acceptStep(s *acceptState, mode, screen string) (bool, string) {
	if mode != "bypass" {
		*s = acceptState{}
		return false, ""
	}
	ok, what := permissionDialog(screen)
	if !ok {
		*s = acceptState{}
		return false, ""
	}
	h := sha256.Sum256([]byte(screen))
	if h == s.last {
		if s.tries >= 2 {
			return false, ""
		}
	} else {
		s.last, s.tries = h, 0
	}
	s.tries++
	return true, what
}

// autoAccept: the supervisor's loop (started by supervise once booted)
func autoAccept() {
	var s acceptState
	for ; ; time.Sleep(acceptEvery) {
		if fileExists(harnessPausedPath) {
			continue
		}
		cert, err := currentCert()
		if err != nil {
			continue
		}
		mode := liveMode(cert)
		if mode != "bypass" {
			s = acceptState{}
			continue
		}
		press, what := acceptStep(&s, mode, paneText())
		if !press {
			continue
		}
		// read again right before pressing: the dialog may have gone (answered from the app or the web) in between
		if ok, _ := permissionDialog(paneText()); !ok {
			continue
		}
		if err := sendKeys("Enter"); err != nil {
			log.Printf("auto-accept: Enter wasn't sent: %v", err)
			continue
		}
		log.Printf("auto-accept (bypass): allowed once: %q", what)
	}
}
