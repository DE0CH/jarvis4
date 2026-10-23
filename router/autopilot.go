package main

// What the router does by itself with a running session, from the status its machine reports (registry.go):
// Jarvis 1's autoPauseTick and oneShotTick (server.js) over grants instead of Fly exec.
//
//   auto-pause      idle (no background jobs) for 1 h → Pause; per-session off switch
//   one-shot        the supervisor's ~/.claude/.one-shot-done marker → Destroy
//   stale prompt    "waiting" for 1 h → Escape in the tmux pane (holder "status")
//   attention DMs   idle / waiting / dead for 5 min → one DM per episode; the idle one can be muted
//   downgrade DM    a new safeguard refusal or refusal fallback in a transcript, or the "switch model?" dialog
//   stall nudge     idle with background jobs for 15 min → Jarvis 1's watchdog text as a peer message
//   login           a session with a Claude account stopped on "Please run /login" and its pair is in step with
//                   its account's again → deliver "continue" (the router never writes a login)
//
// One tick at a time (a single loop). The decisions are made under the state lock by planTick (pure, tested);
// the actions run outside it. A command the machine refuses (no grant) is recorded as the session's
// needsGrant and not retried for grantRetry.

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// Liveness: a session's reported status, its settings, and the loop's clocks (unexported: in memory only, as
// in Jarvis 1, so a router restart just restarts them)
type Liveness struct {
	AutoPauseOff    bool   `json:"autoPauseOff,omitempty"`
	NotifyIdleOff   bool   `json:"notifyIdleOff,omitempty"`
	OneShot         bool   `json:"oneShot,omitempty"`
	NeedsGrant      string `json:"needsGrant,omitempty"` // a holder the machine refused; the app offers a grant
	DowngradeSeenAt int64  `json:"downgradeSeenAt,omitempty"`
	// the settled episode already DMed ("idle:<statusUpdatedAt>"), so a router restart doesn't ping it again
	// the auto-pause clock: idle since when, on which turn (statusUpdatedAt) — kept across a router restart, so
	// frequent deploys don't keep restarting the hour
	IdleSince     time.Time `json:"idleSince,omitempty"`
	IdleStatusAt  int64     `json:"idleStatusAt,omitempty"`
	AttentionSent string    `json:"attentionSent,omitempty"`
	Reg           *Registry `json:"registry,omitempty"`
	LastReport    time.Time `json:"lastReport,omitempty"`
	// the harness check: when the running machine first reported (it had booted), and the machine whose Claude host
	// has reported since (a live Remote Control host in the registry). Kept across a router restart.
	BootedAt time.Time `json:"bootedAt,omitempty"`
	HostUp   string    `json:"hostUp,omitempty"`

	waiting         *waitEpisode
	settled         *settledEpisode
	Stall           *stallClock `json:"stall,omitempty"`
	loginRepaired   *repairMark
	loginBusy       bool
	grantRetry      map[string]time.Time // holder → not before
	oneShotFiring   bool
	dialogCheckedAt int64 // statusUpdatedAt of the waiting episode whose pane was checked for the dialog
	dialogReported  bool
	screen          *pushedScreen // the pane the machine pushes itself (machine/screen.go); in memory only
	mem             *memState     // memory.go: the starvation watch of the running machine; in memory only
	disk            *diskState    // disk.go: the disk watch of the running machine; in memory only
	// the stall watchdog's last nudge: when and how it ended ("" = delivered), for GET /setup/sessions
	NudgeAt    time.Time `json:"nudgeAt,omitempty"`
	NudgeError string    `json:"nudgeError,omitempty"`
}

type waitEpisode struct {
	at        time.Time
	statusAt  int64
	cancelled bool
}

type settledEpisode struct {
	kind     string
	since    time.Time
	notified bool
}

// stallClock: kept across a router restart (like the auto-pause clock), so frequent deploys don't keep restarting
// the 15 minutes and the nudge never comes (Deyao, 2026-10-12: "the 15 minute background nudge is also gone")
type stallClock struct {
	At       time.Time `json:"at"`
	StatusAt int64     `json:"statusAt"`
}

type repairMark struct {
	uuid string
	at   time.Time
}

type pilotConfig struct {
	IdlePause, WaitingCancel, Attention, StallNudge, StaleReport, GrantRetry, RepairEvery, DowngradeLookback time.Duration
	HarnessUp                                                                                                time.Duration
}

var defaultPilot = pilotConfig{
	IdlePause: time.Hour, WaitingCancel: time.Hour, Attention: 5 * time.Minute, StallNudge: 15 * time.Minute,
	StaleReport: 3 * time.Minute, GrantRetry: 10 * time.Minute, RepairEvery: 10 * time.Minute, DowngradeLookback: 15 * time.Minute,
	HarnessUp: 4 * time.Minute,
}

const pilotTick = 30 * time.Second

var routerStarted = time.Now()

// autoPauseVeto: another feature (the scheduler: a wakeup or cron due soon) can hold off an auto-pause. It runs
// inside the tick's r.st.Do, so it gets the locked state and must not take the lock itself.
var autoPauseVeto func(d *persisted, session string) bool

// ---- create, env and view hooks ---------------------------------------------------------------------------

func newLiveness(in NewSession) *Liveness {
	return &Liveness{OneShot: in.OneShot, AutoPauseOff: in.OneShot || (in.AutoPause != nil && !*in.AutoPause)}
}

func init() {
	envHooks = append(envHooks, func(_ *Router, s *Session, e map[string]string) { liveEnv(s, e) })
}

// liveEnv: what the machine's env needs (harness-claude.sh reads SESSION_ONE_SHOT)
func liveEnv(s *Session, e map[string]string) {
	if s.Live != nil && s.Live.OneShot {
		e["SESSION_ONE_SHOT"] = "1"
	}
}

// liveOptions: what the phone sees on the new-session approval
func liveOptions(s *Session, o map[string]string) {
	if s.Live != nil && s.Live.OneShot {
		o["oneShot"] = "1"
	}
	if s.Live != nil && s.Live.AutoPauseOff {
		o["autoPause"] = "off"
	}
}

// cleanAppTitle: one line, at most 200 characters (it names a Discord channel and an archive folder)
func cleanAppTitle(t string) string {
	t = strings.Join(strings.Fields(t), " ")
	if r := []rune(t); len(r) > 200 {
		t = string(r[:200])
	}
	return t
}

func onOff(off bool) string {
	if off {
		return "off"
	}
	return "on"
}

// liveView: the status fields of /api/state, named as in Jarvis 1 (called under the state lock)
func liveView(s *Session, v map[string]any) {
	l := s.Live
	if l == nil {
		l = &Liveness{}
	}
	v["autoPause"], v["notifyIdle"], v["oneShot"] = onOff(l.AutoPauseOff), onOff(l.NotifyIdleOff), l.OneShot
	v["needsGrant"] = l.NeedsGrant
	if !l.LastReport.IsZero() {
		v["lastReport"] = l.LastReport
	}
	memView(s, v) // memory.go: memAlert, memory
	if s.State != "started" || s.MachineID == "" || l.Reg == nil || time.Since(l.LastReport) > defaultPilot.StaleReport {
		return
	}
	g := l.Reg
	v["status"], v["aiTitle"], v["liveName"], v["nameSource"] = g.Status, g.AiTitle, g.LiveName, g.NameSource
	v["bgTasks"], v["statusUpdatedAt"], v["bridgeSessionId"], v["sessionId"] = g.BgTasks, g.StatusUpdatedAt, g.BridgeSessionID, g.SessionID
	v["authFailed"], v["credsExpiresAt"], v["sessionsInside"] = g.AuthFailed, g.CredsExpiresAt, g.SessionsInside
	v["oneShotDone"], v["refusals"] = g.OneShotDone, orEmptyR(g.Refusals)
	if g.Workers != nil {
		v["workers"] = g.Workers // registry.go: subagents and background jobs running now
	}
	if !l.AutoPauseOff && !l.IdleSince.IsZero() && idleEligible(g) {
		v["pauseInMs"] = max(int64(0), time.Until(l.IdleSince.Add(defaultPilot.IdlePause)).Milliseconds())
	}
}

func orEmptyR(r []Refusal) []Refusal {
	if r == nil {
		return []Refusal{}
	}
	return r
}

// ---- routes -----------------------------------------------------------------------------------------------

func (r *Router) registerAutopilot(app appRoute, m machineRoute) {
	m("POST /m/status", func(w http.ResponseWriter, req *http.Request, machine string, body []byte) {
		var in struct {
			Raw      string `json:"raw"`
			AppTitle string `json:"appTitle"` // the Claude app's title of the Remote Control entry (machine/apptitle.go)
		}
		json.Unmarshal(body, &in)
		reg := parseRegistry(in.Raw)
		appTitle := cleanAppTitle(in.AppTitle)
		r.st.Do(func(d *persisted) {
			s := d.Sessions[d.Machines[machine]]
			if s == nil || s.MachineID != machine {
				return
			}
			if s.Live == nil {
				s.Live = &Liveness{}
			}
			s.Live.Reg, s.Live.LastReport = reg, time.Now().UTC()
			if s.Booted != machine || s.Live.BootedAt.IsZero() {
				s.Live.BootedAt = s.Live.LastReport // the harness check's clock (planTick)
			}
			s.Booted = machine // its agent reports only once the machine has booted (machine/main.go)
			if reg != nil {
				s.Live.HostUp, s.StuckImage = machine, ""
			}
			s.Status = ""
			if reg != nil {
				s.Status = reg.Status
				if reg.AiTitle != "" {
					s.Title = reg.AiTitle
				}
				if reg.NameSource != "" && reg.NameSource != "derived" && reg.LiveName != "" {
					s.UserTitle = reg.LiveName // Deyao named it himself (Jarvis 1's pickTitle userName)
				}
			}
			if appTitle != "" {
				s.AppTitle = appTitle // kept while paused, as Jarvis 1's paused record keeps the title the app showed
			}
		})
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
	// the read-only terminal: the machine's own capture of its pane (machine/screen.go), kept in memory
	m("POST /m/screen", func(w http.ResponseWriter, req *http.Request, machine string, body []byte) {
		var in TermSnap
		json.Unmarshal(body, &in)
		r.st.Do(func(d *persisted) {
			s := d.Sessions[d.Machines[machine]]
			if s == nil || s.MachineID != machine {
				return
			}
			if s.Live == nil {
				s.Live = &Liveness{}
			}
			s.Live.screen = &pushedScreen{snap: in, at: time.Now()}
		})
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
	toggle := func(field string) http.HandlerFunc {
		return func(w http.ResponseWriter, req *http.Request) {
			var in struct {
				On      *bool `json:"on"`
				Enabled *bool `json:"enabled"` // Jarvis 1's name
			}
			json.NewDecoder(io.LimitReader(req.Body, 1<<16)).Decode(&in)
			on := true
			if in.On != nil {
				on = *in.On
			} else if in.Enabled != nil {
				on = *in.Enabled
			}
			found := false
			r.st.Do(func(d *persisted) {
				s := d.Sessions[req.PathValue("id")]
				if s == nil {
					return
				}
				found = true
				if s.Live == nil {
					s.Live = &Liveness{}
				}
				if field == "autoPause" {
					s.Live.AutoPauseOff, s.Live.IdleSince = !on, time.Time{}
				} else {
					s.Live.NotifyIdleOff = !on
				}
			})
			if !found {
				writeJSON(w, 404, map[string]string{"error": "no such session"})
				return
			}
			writeJSON(w, 200, map[string]any{"ok": true, field: onOff(!on)})
		}
	}
	app("POST /api/sessions/{id}/auto-pause", toggle("autoPause"))
	app("POST /api/sessions/{id}/notify-idle", toggle("notifyIdle"))
}

// ---- the loop ---------------------------------------------------------------------------------------------

type pilotAction struct {
	Kind    string // dm | escape | dialog | nudge | login | continue | pause | destroy | harness-stuck
	Session string
	Machine string // harness-stuck: the machine whose harness never came up
	Text    string // dm, nudge
	Repair  string // login: the uuid of the "Please run /login" reply being repaired
	// login: the machine keeps its account's pair in step (machine/claudelogin.go): no write, only
	// "continue" for a session stuck on "Please run /login"
	Name    string
	Jobs    int // nudge: the numbers its text is built from (the image builds the same text: vouch.go)
	Minutes int
}

func (r *Router) startAutopilot() {
	go func() {
		for range time.Tick(pilotTick) {
			if leads() { // leaderlease.go
				r.autopilotTick()
			}
		}
	}()
}

func (r *Router) autopilotTick() {
	running := false
	r.st.Do(func(d *persisted) {
		for _, s := range d.Sessions {
			running = running || (s.State == "started" && s.MachineID != "")
		}
	})
	if !running {
		return
	}
	storedExp := r.loginExpiries()
	var acts []pilotAction
	r.st.Do(func(d *persisted) {
		acts = planTick(d, time.Now(), storedExp, defaultPilot, r.busy, func(id string) bool { return autoPauseVeto != nil && autoPauseVeto(d, id) })
		for _, t := range memSilentTick(d, time.Now().UTC()) { // memory.go: a starving machine that went silent
			acts = append(acts, pilotAction{Kind: "dm", Text: t})
		}
	})
	for _, a := range acts {
		r.runAction(a)
	}
}

func idleEligible(g *Registry) bool { return g != nil && g.Status == "idle" && g.BgTasks == 0 }

// attentionKind: the state a session settled into, or "" while it works. nil = no live claude inside.
func attentionKind(g *Registry) string {
	switch {
	case g != nil && g.Status == "waiting":
		return "waiting"
	case g != nil && g.Status == "idle" && g.BgTasks == 0:
		return "idle"
	case g != nil && g.Status != "":
		return ""
	}
	return "dead"
}

// attentionKey: one settled episode — its kind and the turn it settled on (a new turn is a new episode)
func attentionKey(kind string, g *Registry) string {
	var at int64
	if g != nil {
		at = g.StatusUpdatedAt
	}
	return fmt.Sprintf("%s:%d", kind, at)
}

// sessionName: the name a session's DMs carry — its card/channel title (sessionTitle: the app's title, Deyao's own
// name, the label), else the live AI title, else the CLI's derived Remote Control name ("workspace-c1"), last
func sessionName(s *Session, g *Registry) string {
	names := []string{s.AppTitle, s.UserTitle, s.Label}
	if g != nil {
		names = append(names, g.AiTitle)
	}
	names = append(names, s.Title)
	if g != nil {
		names = append(names, g.LiveName)
	}
	for _, n := range names {
		if n = strings.TrimSpace(n); n != "" {
			return n
		}
	}
	return s.ID
}

func (l *Liveness) mayExec(holder string, now time.Time) bool {
	return l.grantRetry == nil || !now.Before(l.grantRetry[holder])
}

// planTick: one pass over the sessions; it moves the clocks and returns what to do. Called under the state lock.
func planTick(d *persisted, now time.Time, storedExp map[string]int64, c pilotConfig, busy, veto func(string) bool) []pilotAction {
	var out []pilotAction
	add := func(a pilotAction) { out = append(out, a) }
	for id, s := range d.Sessions {
		if s.Live == nil {
			s.Live = &Liveness{}
		}
		l := s.Live
		if s.State != "started" || s.MachineID == "" {
			l.IdleSince, l.waiting, l.settled, l.Stall, l.dialogCheckedAt, l.dialogReported = time.Time{}, nil, nil, nil, 0, false
			l.screen = nil
			if s.MachineID == "" {
				l.Reg = nil // paused: the next machine reports afresh
			}
			continue
		}
		if isTaskHarness(s.Harness) {
			continue // a task line runs a script, not a harness: tasks.go pauses it once the run reports
		}
		g := l.Reg
		if l.LastReport.IsZero() || now.Sub(l.LastReport) > c.StaleReport {
			g = nil // no report lately: the machine (or its agent) isn't answering
		}
		operating := busy(id)
		name := sessionName(s, g)

		// the harness check: a booted machine whose Claude never came up (no live host in the registry) for HarnessUp
		// is failed with what its screen shows (2026-10-20: an unreadable /etc/claude-code left every new session
		// on Claude Code's "Settings Error" prompt, shown as "booting…" for ever). Resume tries again on a new machine.
		if s.Harness == "claude" && !operating && c.HarnessUp > 0 && l.HostUp != s.MachineID && s.Booted == s.MachineID &&
			!l.BootedAt.IsZero() && now.Sub(l.BootedAt) >= c.HarnessUp {
			screen := ""
			if l.screen != nil {
				screen = l.screen.snap.Screen
			}
			add(pilotAction{Kind: "harness-stuck", Session: id, Machine: s.MachineID, Name: name, Text: harnessStuckText(c.HarnessUp, screen)})
			continue
		}

		// "continue" after a start that took a new Claude account (accountswap.go), once its host is up and idle
		if s.Ops != nil && s.Ops.ContinueAfterStart && !operating && g != nil && l.HostUp == s.MachineID &&
			g.BridgeSessionID != "" && g.Status == "idle" {
			s.Ops.ContinueAfterStart = false
			add(pilotAction{Kind: "continue", Session: id, Name: name})
		}

		// one-shot: the prompt is done → destroy
		if l.OneShot && g != nil && g.OneShotDone && !l.oneShotFiring && !operating {
			l.oneShotFiring = true
			add(pilotAction{Kind: "destroy", Session: id, Name: name})
			continue
		}

		// "needs you" / idle / dead DM, once per settled episode
		if operating || l.OneShot {
			l.settled = nil
		} else if kind := attentionKind(g); kind == "" {
			l.settled, l.AttentionSent = nil, ""
		} else if key := attentionKey(kind, g); l.settled == nil || l.settled.kind != kind {
			l.settled = &settledEpisode{kind: kind, since: now, notified: l.AttentionSent == key}
		} else if !l.settled.notified && now.Sub(l.settled.since) >= c.Attention {
			l.settled.notified, l.AttentionSent = true, key
			if !(kind == "idle" && l.NotifyIdleOff) {
				add(pilotAction{Kind: "dm", Session: id, Text: attentionText(kind, name)})
			}
		}

		// model downgrade: new refusal events in the transcripts, or the "switch model?" dialog on screen
		if g != nil && !operating {
			since := max(l.DowngradeSeenAt, routerStarted.Add(-c.DowngradeLookback).UnixMilli())
			if ev := freshRefusals(g.Refusals, since); len(ev) > 0 {
				l.DowngradeSeenAt = ev[len(ev)-1].At
				l.dialogReported = true
				add(pilotAction{Kind: "dm", Session: id, Text: downgradeText(name, ev)})
			} else if g.Status != "waiting" {
				l.dialogCheckedAt, l.dialogReported = 0, false
			} else if !l.dialogReported && l.dialogCheckedAt != g.StatusUpdatedAt && l.mayExec("status", now) {
				l.dialogCheckedAt = g.StatusUpdatedAt
				add(pilotAction{Kind: "dialog", Session: id, Name: name})
			}
		}

		// stall nudge: idle with background jobs, no turn for StallNudge → a peer message, repeated every StallNudge.
		// Claude Code (2.1.29x) keeps the status "busy" while background jobs run after the turn ended, so a
		// "busy" session counts as waiting on its jobs when its pushed screen shows no turn running (no spinner)
		jobsOnly := g != nil && g.BgTasks > 0 && g.Status == "idle"
		unsure := false
		if g != nil && g.BgTasks > 0 && g.Status == "busy" {
			if l.screen == nil || now.Sub(l.screen.at) >= screenFresh {
				unsure = true // no recent screen (a machine without the push, or just after a router restart): keep the clock
			} else {
				jobsOnly = !turnOnScreen(l.screen.snap.Screen)
			}
		}
		if unsure && !operating && !l.OneShot {
			// leave l.Stall as it is
		} else if operating || l.OneShot || c.StallNudge <= 0 || !jobsOnly {
			l.Stall = nil
		} else if l.Stall == nil || l.Stall.StatusAt != g.StatusUpdatedAt {
			l.Stall = &stallClock{At: now, StatusAt: g.StatusUpdatedAt}
		} else if stalled := now.Sub(l.Stall.At); stalled >= c.StallNudge {
			l.Stall.At = now
			add(pilotAction{Kind: "nudge", Session: id, Text: nudgeText(g.BgTasks, stalled), Jobs: g.BgTasks, Minutes: int(stalled.Round(time.Minute) / time.Minute)})
		}

		// Claude login: a session with a Claude account keeps that account's pair in step by itself
		// (machine/claudelogin.go); the router writes nothing (Deyao, 2026-10-14: no login repair). A turn that stopped on
		// "Please run /login" gets "continue" once the session's pair is in step again.
		if exp := storedExp[s.ClaudeAccount]; g != nil && !operating && !l.loginBusy && s.ClaudeAccount != "" &&
			exp > now.UnixMilli() && g.CredsExpiresAt >= exp && g.Status == "idle" {
			if u := g.AuthFailed; u != "" && (l.loginRepaired == nil || (l.loginRepaired.uuid != u && now.Sub(l.loginRepaired.at) >= c.RepairEvery)) {
				l.loginRepaired = &repairMark{uuid: u, at: now}
				l.loginBusy = true
				add(pilotAction{Kind: "login", Session: id, Repair: u, Name: name})
			}
		}

		// a prompt unanswered for WaitingCancel → Escape (once per waiting episode)
		if g == nil || g.Status != "waiting" || operating {
			l.waiting = nil
			// "status" is only wanted while a prompt waits (the dialog check, the Escape): once the session has
			// moved on, a refusal from that episode is moot, so the card stops offering a grant for it (2026-10-12:
			// a short question left "The machine turned away status" on a session that was running fine)
			if g != nil && l.NeedsGrant == "status" {
				l.NeedsGrant = ""
				delete(l.grantRetry, "status")
			}
		} else if l.waiting == nil || l.waiting.statusAt != g.StatusUpdatedAt {
			l.waiting = &waitEpisode{at: now, statusAt: g.StatusUpdatedAt}
		} else if !l.waiting.cancelled && now.Sub(l.waiting.at) >= c.WaitingCancel && l.mayExec("status", now) {
			l.waiting.cancelled = true
			add(pilotAction{Kind: "escape", Session: id, Name: name})
		}

		// auto-pause after IdlePause of plain idle
		if l.AutoPauseOff || l.OneShot || veto(id) || !idleEligible(g) {
			l.IdleSince = time.Time{}
			continue
		}
		if l.IdleSince.IsZero() || l.IdleStatusAt != g.StatusUpdatedAt {
			l.IdleSince, l.IdleStatusAt = now, g.StatusUpdatedAt // a turn the router didn't see starts the hour again
		}
		if now.Sub(l.IdleSince) >= c.IdlePause && !operating {
			add(pilotAction{Kind: "pause", Session: id, Name: name})
		}
	}
	return out
}

func attentionText(kind, name string) string {
	switch kind {
	case "waiting":
		return fmt.Sprintf("🟠 Session “%s” needs you — Claude is waiting for your input.", name)
	case "idle":
		return fmt.Sprintf("🟢 Session “%s” is idle — Claude finished and is waiting.", name)
	}
	return fmt.Sprintf("🔴 Session “%s” isn't running a live Claude session — it may have died or need a re-login.", name)
}

// nudgeText: Jarvis 1's lib/stall.js nudgeText
// turnOnScreen: Claude Code's spinner line is on the pane — a turn is running ("✢ Unfurling… (22s · thought for
// 12s)"); a session only waiting on background jobs shows none
var spinnerLine = regexp.MustCompile(`(?m)^\s*\S\s+[A-Z][\p{L}-]*…\s*\(\d`)

func turnOnScreen(screen string) bool {
	return spinnerLine.MatchString(ansiSeq.ReplaceAllString(screen, ""))
}

func nudgeText(bgTasks int, stalled time.Duration) string {
	jobs := fmt.Sprintf("%d background jobs have", bgTasks)
	if bgTasks == 1 {
		jobs = "1 background job has"
	}
	return fmt.Sprintf("Jarvis watchdog: this session has been idle for %d min while %s been running, and none has finished or woken you. ", int(stalled.Round(time.Minute)/time.Minute), jobs) +
		"Check on them now: read their output, and if a job is hung or no longer needed, stop it and continue the task another way. " +
		"If a job is legitimately still running, make sure it will end on its own (a timeout or deadline), then end your turn — this check repeats while the state lasts. " +
		"This is an automated message from Jarvis."
}

// freshRefusals: events newer than since (ms), de-duplicated by uuid
func freshRefusals(ev []Refusal, since int64) []Refusal {
	seen := map[string]bool{}
	var out []Refusal
	for _, e := range ev {
		if e.At <= since || (e.UUID != "" && seen[e.UUID]) {
			continue
		}
		seen[e.UUID] = true
		out = append(out, e)
	}
	return out
}

// downgradeText: lib/downgrade.js message — a fallback (the model actually changed) wins
func downgradeText(name string, ev []Refusal) string {
	cat := func(e Refusal) string {
		if e.Category != "" {
			return " (" + e.Category + ")"
		}
		return ""
	}
	or := func(a, b string) string {
		if a != "" {
			return a
		}
		return b
	}
	for i := len(ev) - 1; i >= 0; i-- {
		if e := ev[i]; e.Kind == "fallback" {
			return fmt.Sprintf("🟡 Session “%s”: %s's safeguards flagged a message%s — Claude Code switched it to %s.", name, or(e.From, "the model"), cat(e), or(e.To, "a fallback model"))
		}
	}
	e := ev[len(ev)-1]
	return fmt.Sprintf("🟡 Session “%s”: %s's safeguards flagged a message%s and the turn stopped (no fallback model).", name, or(e.Model, "the model"), cat(e))
}

var ansiSeq = regexp.MustCompile(`\x1b\[[0-9;?]*[A-Za-z]`)

func stripANSI(s string) string { return ansiSeq.ReplaceAllString(s, "") }

func promptOnScreen(screen string) bool {
	return strings.Contains(strings.ToLower(stripANSI(screen)), "safeguards flagged")
}

// ---- running the actions ----------------------------------------------------------------------------------

// harnessStuckText: the failed session's error — the wait and the last lines of the pane (what blocks it, usually a
// prompt Claude Code put up before its Remote Control host)
func harnessStuckText(wait time.Duration, screen string) string {
	msg := harnessStuckPrefix + " within " + waitText(wait) + " of boot (Claude Code never reported a live Remote Control host)"
	var lines []string
	for _, l := range strings.Split(stripANSI(screen), "\n") {
		if l = strings.Join(strings.Fields(l), " "); l != "" && strings.Trim(l, "─━-—╌ ") != "" {
			lines = append(lines, l)
		}
	}
	if len(lines) > 8 {
		lines = lines[len(lines)-8:]
	}
	tail := strings.Join(lines, " / ")
	if r := []rune(tail); len(r) > 500 {
		tail = "…" + string(r[len(r)-500:])
	}
	if tail != "" {
		msg += "; its screen ends: " + tail
	} else {
		msg += "; no screen from it"
	}
	return msg + ". Resume starts it again on a new machine."
}

// harnessStuckPrefix: how the harness check's error begins (Resume reads it: harnessRetryUpgrade)
const harnessStuckPrefix = "the harness didn't come up"

// harnessRetryUpgrade: a session the harness check failed resumes on the newest session image when its own is older
// (the phone approves it, as any newer image): retrying the image whose Claude never came up would hang again
// (also after a resume-upgrade nobody approved: the mark stays until a Claude host comes up)
func harnessRetryUpgrade(s Session, newest string) bool {
	if s.StuckImage == "" || s.Cert == nil || newest == "" {
		return false
	}
	own := imageDigest(certImage(s.Cert, s.Image))
	return own == imageDigest(s.StuckImage) && own != imageDigest(newest)
}

// harnessStuck: fail the session (the machine stays until a Resume finishes its pause, or a Destroy), log it in the
// lifecycle, DM once
func (r *Router) harnessStuck(a pilotAction) {
	failed := false
	r.st.Do(func(d *persisted) {
		s := d.Sessions[a.Session]
		if s == nil || s.State != "started" || s.MachineID != a.Machine || (s.Live != nil && s.Live.HostUp == a.Machine) {
			return
		}
		s.State, s.Error, failed = "failed", a.Text, true
		s.StuckImage = certImage(s.Cert, s.Image)
	})
	if !failed {
		return
	}
	log.Printf("session %s: failed: %s", a.Session, a.Text)
	h := r.lcBegin(a.Session, "harness-check")
	h.machine(a.Machine)
	h.note(a.Machine, a.Text)
	h.end("failed", a.Text)
	r.DM(fmt.Sprintf("🔴 Session “%s” didn't come up: %s", a.Name, a.Text))
}

func (r *Router) runAction(a pilotAction) {
	switch a.Kind {
	case "harness-stuck":
		r.harnessStuck(a)
	case "dm":
		r.DM(a.Text)
	case "pause":
		if err := r.Pause(a.Session); err != nil {
			log.Printf("[autopause] %s: %v", a.Session, err)
			return
		}
		log.Printf("[autopause] paused idle session %s (%s)", a.Session, a.Name)
		r.st.Do(func(d *persisted) {
			if s := d.Sessions[a.Session]; s != nil && s.Live != nil {
				s.Live.IdleSince = time.Time{}
			}
		})
	case "destroy":
		if err := r.finishOneShot(a.Session); err != nil { // oneshot.go: forced, DMs about lost work
			log.Printf("[oneshot] %s: %v", a.Session, err)
			r.st.Do(func(d *persisted) {
				if s := d.Sessions[a.Session]; s != nil && s.Live != nil {
					s.Live.oneShotFiring = false // the next tick looks again
				}
			})
			return
		}
		log.Printf("[oneshot] %s (%s) finished its prompt; destroying", a.Session, a.Name)
	case "escape":
		go func() {
			_, err := r.execAs(a.Session, "status", "tmux send-keys -t claude Escape", 20*time.Second)
			if err != nil {
				log.Printf("[autopause] %s: cancelling the stale prompt failed: %v", a.Session, err)
				r.st.Do(func(d *persisted) {
					if s := d.Sessions[a.Session]; s != nil && s.Live != nil && s.Live.waiting != nil {
						s.Live.waiting.cancelled = false
					}
				})
				return
			}
			log.Printf("[autopause] %s (%s): cancelled a prompt unanswered for %s", a.Session, a.Name, defaultPilot.WaitingCancel)
		}()
	case "dialog":
		go func() {
			// the machine's own pushed pane first (no grant); a machine without the screen push needs the status grant
			snap, ok := r.pushedScreen(a.Session)
			screen := snap.Screen
			if !ok {
				res, err := r.execAs(a.Session, "status", "tmux capture-pane -p -t claude", 20*time.Second)
				if err != nil {
					return
				}
				screen = res.Stdout
			}
			if !promptOnScreen(screen) {
				return
			}
			r.st.Do(func(d *persisted) {
				if s := d.Sessions[a.Session]; s != nil && s.Live != nil {
					s.Live.dialogReported = true
				}
			})
			r.DM(fmt.Sprintf("🟡 Session “%s”: the safeguards flagged a message — Claude Code is asking whether to switch to another model.", a.Name))
		}()
	case "nudge":
		go func() {
			err := r.DeliverCanned(a.Session, Delivery{Kind: "nudge", Jobs: a.Jobs, Minutes: a.Minutes}, a.Text)
			r.st.Do(func(d *persisted) {
				if s := d.Sessions[a.Session]; s != nil && s.Live != nil {
					s.Live.NudgeAt, s.Live.NudgeError = time.Now().UTC(), ""
					if err != nil {
						s.Live.NudgeError = err.Error()
					}
				}
			})
			if err != nil {
				log.Printf("[stall] nudge for %s failed (retried next interval): %v", a.Session, err)
				return
			}
			log.Printf("[stall] %s nudged", a.Session)
		}()
	case "continue":
		go func() {
			if err := r.DeliverCanned(a.Session, Delivery{Kind: "continue"}, "continue"); err != nil {
				log.Printf("[account] %s (%s): \"continue\" after the start on its new Claude account failed: %v", a.Session, a.Name, err)
				return
			}
			log.Printf("[account] %s (%s): \"continue\" delivered after the start on its new Claude account", a.Session, a.Name)
		}()
	case "login":
		go func() {
			defer r.st.Do(func(d *persisted) {
				if s := d.Sessions[a.Session]; s != nil && s.Live != nil {
					s.Live.loginBusy = false
				}
			})
			r.repairLogin(a)
		}()
	}
}

// execAs: r.Exec, recording a refusal as the session's needsGrant (and backing off) and clearing it on success
func (r *Router) execAs(session, holder, cmd string, timeout time.Duration) (ExecResult, error) {
	res, err := r.Exec(session, holder, cmd, timeout)
	if err != nil && res.Error != "" {
		r.noteRefusal(session, holder, err)
	} else if err == nil {
		r.st.Do(func(d *persisted) {
			if s := d.Sessions[session]; s != nil && s.Live != nil {
				delete(s.Live.grantRetry, holder)
				if s.Live.NeedsGrant == holder {
					s.Live.NeedsGrant = ""
				}
			}
		})
	}
	return res, err
}

// noteRefusal: the machine refused (or the delivery through a grant failed): the app offers a grant, and the
// loop leaves that holder alone for GrantRetry
func (r *Router) noteRefusal(session, holder string, err error) {
	if err == nil || !strings.Contains(err.Error(), "refused") {
		return
	}
	r.st.Do(func(d *persisted) {
		if s := d.Sessions[session]; s != nil && s.Live != nil {
			if s.Live.grantRetry == nil {
				s.Live.grantRetry = map[string]time.Time{}
			}
			s.Live.grantRetry[holder] = time.Now().Add(defaultPilot.GrantRetry)
			s.Live.NeedsGrant = holder
		}
	})
}
