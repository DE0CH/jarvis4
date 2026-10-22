package main

// Switching a session's Claude account (Deyao, 2026-10-20: "I ran out of usage on the chendeyao.uk account; swap its
// session to chendeyao000"). A session's account (Session.ClaudeAccount) is picked when it is made; this moves it to
// another account the router holds, keeping the conversation.
//
//   POST /api/sessions/{id}/account {account, continue}
//
// Paused or failed: the account is changed on the session and its next start takes the new account's pair (boot's
// /m/claude-login); with `continue`, "continue" is typed into its chat once that start's Claude host is up and idle
// (SessionOps.ContinueAfterStart, autopilot.go). A resume onto the newest image (resume-upgrade) keeps both.
//
// Running (the claude harness): a background job shown as the session's `wake` ({kind: "account", phase}), holding
// the session's lock so nothing else acts on it meanwhile. The switch is transparent (Deyao, 2026-10-20: the harness
// is just a process, so the files it reads change under it): no restart, no --resume, background shells, agents and
// monitors keep running.
//
//  1. switching          the session's account changes; every /m/claude-login long poll of the machine is woken, so
//                        its Claude login sync asks the new account's hub at once (the machine also gets the command
//                        "claude-account"); from now on the sync follows the new account and the machine is one of
//                        its participants for refreshes
//  2. taking the login   until the machine's status reports the new account's pair on disk (credsExpiresAt): the
//                        supervisor installed it and the account record under the running claude, under the CLI's
//                        refresh lock (machine/claudelogin.go switchInPlace); claude's next request uses it
//  3. checking the account  until the status's __ACCOUNT__ names the new account: Anthropic's profile endpoint, asked
//                        by the machine with the installed token
//  4. Remote Control     Claude Code stops Remote Control when the account under it changes; the supervisor types
//                        /remote-control and chooses Enable: until the host reports a new Remote Control session.
//                        Not coming back is reported on the job (Claude itself works), not a failure.
//  5. delivering continue  with `continue`: "continue" into its chat as the canned delivery the login repair uses
//                        (a core-attested delivery; into a session holding a sensitive store it waits in the Inbox for
//                        Deyao to deliver, messages.go).
//
// Claude Code · Paseo (proxyLoginHarness, harness.go) is switched while running the same way, minus step 4: its
// Claude Code holds only a placeholder token and reaches the API through api-proxy.js, which sends the pair on disk
// per request, so step 2 is the switch (the next request goes out on the new account, a turn in flight included)
// and there is no Remote Control. Its "continue" waits until the agent is idle (harness-send: Paseo's send would
// interrupt a running turn).
//
// A session image from before 2026-10-20 (no __ACCOUNT__ in its status) restarts its host on the new account instead
// (its harness merges the record at start, --resume): the machine does it once the host is idle; after
// swapRestartWait the router kills the host's tmux session through the "terminal" holder (as the in-place
// permission-mode switch does) and waits for it to come back.
//
// No core change and no Face ID of its own: the login travels over the router's machine-signed long poll as it always
// has. With CLAUDE_STORE_IN_CERT=1 (certs name the account's store) a running session's switch also files the
// add-store of the new account's store through the existing add-store flow (Face ID in the Inbox), so its cert names
// it; a paused session is refused there (resume it first), since its next cert comes from its line as it is.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

var (
	swapLoginWait   = 2 * time.Minute // for the machine to report the new account's pair on disk
	swapRestartWait = 2 * time.Minute // older images: for the machine to restart the host by itself, before the router does
	swapUpWait      = 3 * time.Minute // for the relaunched host to come up (and settle idle, for "continue")
	swapCheckWait   = 2 * time.Minute // for the machine's word that Anthropic names the new account for the token
	swapRCWait      = 5 * time.Minute // for Remote Control to come back (a host in a turn shows the menu after it)
	swapPoll        = 2 * time.Second
	swapKillCmd     = "tmux kill-session -t claude"
)

// accountSwitches: closed and replaced whenever a session's account changes, so a machine's long poll held on its old
// account's hub returns and the next one asks the new account's
var (
	acctSwitchMu sync.Mutex
	acctSwitchCh = make(chan struct{})
)

func accountSwitched() <-chan struct{} {
	acctSwitchMu.Lock()
	defer acctSwitchMu.Unlock()
	return acctSwitchCh
}

func signalAccountSwitch() {
	acctSwitchMu.Lock()
	close(acctSwitchCh)
	acctSwitchCh = make(chan struct{})
	acctSwitchMu.Unlock()
}

// pollWithSwitch: a machine's long poll on its account's hub, cut short when any session's account changes; then the
// session's account is looked up again and, when it changed, answered from the new account's hub at once
func (r *Router) pollWithSwitch(ctx context.Context, machine string, h *loginHub, have, ack int64, wait time.Duration) (loginAnswer, bool) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	sw := accountSwitched()
	go func() {
		select {
		case <-sw:
			cancel()
		case <-ctx.Done():
		}
	}()
	a := h.poll(ctx, "m:"+machine, have, ack, wait)
	if _, now := r.machineAccount(machine); now != nil && now != h {
		return now.poll(context.Background(), "m:"+machine, have, 0, 0), true
	} else if now == nil {
		return a, false
	}
	return a, true
}

type accountSwitchIn struct {
	Account  string `json:"account"`
	Continue bool   `json:"continue"`
}

// accountSwitchDoes: what the call does, as the Inbox shows it beside the caller (an API-call request's `does`)
func accountSwitchDoes(d *persisted, sid string, body string) string {
	var in accountSwitchIn
	json.Unmarshal([]byte(body), &in)
	to := accountStoreName(in.Account)
	if to == "" {
		to = in.Account
	}
	from, title := "(none)", sid
	if s := d.Sessions[sid]; s != nil {
		title = sessionTitle(*s)
		if s.ClaudeAccount != "" {
			from = s.ClaudeAccount
		}
	}
	out := fmt.Sprintf("Switch session “%s” (%s) from Claude account %s to %s: its Claude restarts on the same conversation", title, sid, from, to)
	if s := d.Sessions[sid]; s != nil && proxyLoginHarness(s.Harness) {
		out = fmt.Sprintf("Switch session “%s” (%s) from Claude account %s to %s: its next request goes out on the new account, nothing restarts", title, sid, from, to)
	}
	if in.Continue {
		out += ", then “continue” is typed into its chat"
	}
	return out
}

// SwitchAccount: the session's Claude account → store (see the file comment)
func (r *Router) SwitchAccount(req *http.Request, id string, in accountSwitchIn) (map[string]any, error) {
	store := accountStoreName(in.Account)
	if store == "" || r.accounts().hub(store) == nil {
		return nil, bad("no Claude account %q (Settings → Claude accounts lists them)", in.Account)
	}
	to := r.accounts().hub(store)
	if to.current().Credentials == "" {
		return nil, bad("the Claude account %s has no login: Re-login it in Settings → Claude accounts first", store)
	}
	var s Session
	r.st.Do(func(d *persisted) {
		if x := d.Sessions[id]; x != nil {
			s = *x
		}
	})
	if s.ID == "" {
		return nil, errNoSession
	}
	harness := s.Harness
	if harness == "" {
		harness = "claude"
	}
	if h, ok := r.policy.Harnesses[harness]; s.ClaudeAccount == "" && !(ok && h.ClaudeAccount) {
		return nil, bad("the session's harness (%s) takes no Claude account", harness)
	}
	from := s.ClaudeAccount
	if from == store {
		return map[string]any{"ok": true, "unchanged": true, "account": store}, nil
	}
	setAccount := func() {
		r.st.Do(func(d *persisted) {
			if x := d.Sessions[id]; x != nil {
				x.ClaudeAccount = store
			}
		})
		signalAccountSwitch()
		log.Printf("[account] %s: Claude account %s → %s", id, orNone(from), store)
	}
	if s.MachineID == "" {
		if s.State != "paused" && s.State != "failed" {
			return nil, fmt.Errorf("session is %s: switch its account once it is running, paused or failed", s.State)
		}
		if claudeStoreInCert && !containsStr(s.Stores, store) {
			return nil, bad("this session's cert names its Claude account's store: resume it first, then switch (the switch adds %s to its cert)", store)
		}
		setAccount()
		r.st.Do(func(d *persisted) {
			if x := d.Sessions[id]; x != nil {
				if x.Ops == nil {
					x.Ops = &SessionOps{}
				}
				x.Ops.ContinueAfterStart = in.Continue
			}
		})
		return map[string]any{"ok": true, "nextStart": true, "from": nullIfEmpty(from), "to": store, "continue": in.Continue}, nil
	}
	if harness != "claude" && !proxyLoginHarness(harness) {
		return nil, fmt.Errorf("session is running the %s harness: pause it, switch its account, then resume it", harness)
	}
	if s.State != "started" {
		return nil, fmt.Errorf("session is %s: switch its account once it is running, paused or failed", s.State)
	}
	unlock, err := r.lockArgs(id, "account", map[string]any{"store": store, "harness": harness, "continue": in.Continue})
	if err != nil {
		return nil, err
	}
	j, err := r.ops.startJob(id, "account")
	if err != nil {
		unlock()
		return nil, err
	}
	out := map[string]any{"started": true, "kind": "account", "from": nullIfEmpty(from), "to": store}
	if claudeStoreInCert && !containsStr(s.Stores, store) {
		o := Origin{Caller: appCaller(req), Call: APICall{Method: req.Method, Path: req.URL.Path, Args: map[string]any{"account": store}}, ViaCall: viaCall(req)}
		why := fmt.Sprintf("Session “%s” (%s) now uses the Claude account %s: its cert names the account's store, so this adds %s to it.", sessionTitle(s), id, store, store)
		if aid, err := r.addStoreApproval(s.MachineID, store, o, why, ""); err != nil {
			log.Printf("[account] %s: the add-store of %s: %v (the switch goes on: the login travels over the long poll)", id, store, err)
		} else {
			out["addStore"] = aid
		}
	}
	var before Registry // what runs now: its host and Remote Control
	if g, _ := r.liveReg(id, s.MachineID); g != nil {
		before = *g
	}
	setAccount()
	r.send(s.MachineID, "claude-account") // machine/supervisor.go (images from 2026-10-20; older ones log it as unknown)
	go func() {
		defer unlock()
		err := r.runAccountSwitch(j, id, s.MachineID, harness, before, to, in.Continue)
		if err != nil {
			log.Printf("[account] %s: %v", id, err)
			r.ops.phase(j, "failed", err)
			return
		}
		log.Printf("[account] %s: now on %s", id, store)
		r.ops.phase(j, "done", nil)
	}()
	return out, nil
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

// liveReg: the machine's latest status, while it is still the session's machine
func (r *Router) liveReg(id, machine string) (*Registry, bool) {
	var g *Registry
	ok := false
	r.st.Do(func(d *persisted) {
		if s := d.Sessions[id]; s != nil && s.MachineID == machine && s.State == "started" {
			ok = true
			if s.Live != nil && s.Live.Reg != nil {
				c := *s.Live.Reg
				g = &c
			}
		}
	})
	return g, ok
}

// waitReg: polls the machine's status until cond holds; errGone when the machine stopped being the session's
func (r *Router) waitReg(id, machine string, d time.Duration, cond func(*Registry) bool) (*Registry, error) {
	end := time.Now().Add(d)
	for {
		g, ok := r.liveReg(id, machine)
		if !ok {
			return nil, errors.New("the session's machine went away")
		}
		if g != nil && cond(g) {
			return g, nil
		}
		if time.Now().After(end) {
			return g, errSwapTimeout
		}
		time.Sleep(swapPoll)
	}
}

var errSwapTimeout = errors.New("timed out")

func (r *Router) runAccountSwitch(j *wakeJob, id, machine, harness string, before Registry, to *loginHub, cont bool) error {
	r.ops.phase(j, "switching", nil)
	if before.HostPid == 0 { // no status since this router started: the next report says what runs now
		if g, err := r.waitReg(id, machine, swapLoginWait, func(g *Registry) bool { return g.HostPid != 0 }); err == nil {
			before = *g
		}
	}
	want := accountUUID(to.current().Account)

	r.ops.phase(j, "taking the login", nil)
	g, err := r.waitReg(id, machine, swapLoginWait, func(g *Registry) bool {
		exp := to.current().ExpiresAt
		return exp > 0 && g.CredsExpiresAt == exp
	})
	if err != nil {
		return fmt.Errorf("the machine didn't take %s's login: %w", to.store, err)
	}
	log.Printf("[account] %s: the machine took %s's login", id, to.store)

	if g.AccountSection {
		r.ops.phase(j, "checking the account", nil)
		if _, err := r.waitReg(id, machine, swapCheckWait, func(g *Registry) bool { return want != "" && g.AccountProof == want }); err != nil {
			return fmt.Errorf("the machine didn't confirm %s's token with Anthropic: %w", to.store, err)
		}
		log.Printf("[account] %s: the installed token is %s's (Anthropic's profile, asked by the machine)", id, to.store)
		if before.BridgeSessionID != "" && !proxyLoginHarness(harness) { // Claude Code · Paseo has no Remote Control
			r.ops.phase(j, "Remote Control", nil)
			if _, err := r.waitReg(id, machine, swapRCWait, func(g *Registry) bool {
				return g.BridgeSessionID != "" && g.BridgeSessionID != before.BridgeSessionID
			}); err != nil {
				r.ops.note(j, fmt.Sprintf("Remote Control didn't come back within %s: type /remote-control in the session's terminal", swapRCWait))
				log.Printf("[account] %s: Remote Control didn't come back within %s", id, swapRCWait)
			} else {
				log.Printf("[account] %s: Remote Control is up again under %s", id, to.store)
			}
		}
	} else if err := r.restartOldImageHost(j, id, machine, before.HostPid, to, cont); err != nil {
		return err
	}
	if !cont {
		return nil
	}
	r.ops.phase(j, "delivering continue", nil)
	if err := r.DeliverCanned(id, Delivery{Kind: "continue"}, "continue"); err != nil {
		return fmt.Errorf("delivering \"continue\": %w", err)
	}
	log.Printf("[account] %s: \"continue\" delivered", id)
	return nil
}

// restartOldImageHost: a session image from before the switch under a running claude restarts its host on the new
// account (its harness merges the record at start): by itself once idle, else through the terminal holder
func (r *Router) restartOldImageHost(j *wakeJob, id, machine string, oldPid int64, to *loginHub, cont bool) error {
	r.ops.phase(j, "restarting Claude", nil)
	restarted := func(g *Registry) bool { return g.HostPid != 0 && g.HostPid != oldPid }
	if _, err := r.waitReg(id, machine, swapRestartWait, restarted); errors.Is(err, errSwapTimeout) {
		log.Printf("[account] %s: an older image's host wasn't restarted within %s: restarting it through the terminal holder", id, swapRestartWait)
		res, err := r.execAs(id, "terminal", swapKillCmd, 30*time.Second)
		if err == nil && res.Code != 0 && !strings.Contains(res.Stderr, "can't find session") {
			err = fmt.Errorf("exited %d: %s", res.Code, clip(res.Stderr+res.Stdout, 200))
		}
		if err != nil {
			return fmt.Errorf("restarting Claude (holder terminal): %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("restarting Claude: %w", err)
	}
	up := func(g *Registry) bool {
		return restarted(g) && g.BridgeSessionID != "" && (!cont || g.Status == "idle")
	}
	if _, err := r.waitReg(id, machine, swapUpWait, up); err != nil {
		return fmt.Errorf("Claude didn't come back up under %s: %w", to.store, err)
	}
	log.Printf("[account] %s: Claude is back up under %s", id, to.store)
	return nil
}

func (r *Router) registerAccountSwitch(app appRoute) {
	app("POST /api/sessions/{id}/account", func(w http.ResponseWriter, req *http.Request) {
		var in accountSwitchIn
		if err := json.NewDecoder(io.LimitReader(req.Body, 1<<16)).Decode(&in); err != nil && err != io.EOF {
			writeErr(w, fmt.Errorf("bad JSON: %v", err))
			return
		}
		out, err := r.SwitchAccount(req, req.PathValue("id"), in)
		if err != nil {
			scheduleErr(w, err)
			return
		}
		code := 200
		if out["started"] == true {
			code = 202
		}
		writeJSON(w, code, out)
	})
}

// callDoes: an API-call request's effect in words, for the routes whose path and body alone don't say it plainly;
// "" for the rest
func callDoes(d *persisted, p RequestParams) string {
	if p.Method != "POST" {
		return ""
	}
	path, _, _ := strings.Cut(p.Path, "?")
	if rest, ok := strings.CutPrefix(path, "/api/sessions/"); ok {
		if sid, ok := strings.CutSuffix(rest, "/account"); ok && sid != "" && !strings.Contains(sid, "/") {
			return accountSwitchDoes(d, sid, p.Body)
		}
	}
	return ""
}
