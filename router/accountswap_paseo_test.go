package main

import (
	"strings"
	"testing"
)

// Claude Code · Paseo: a running session switches accounts with no restart. Once the machine reports the new pair on
// disk and Anthropic's word on its account, the switch is done: no host restart and no Remote Control is waited for,
// nothing is executed
func TestAccountSwitchProxyHarnessNoRestart(t *testing.T) {
	r, _, _, expA, expB := twoAccounts(t)
	shortSwapWaits(t)
	addSession(r, "sP", "started", "mP", false)
	r.st.Do(func(d *persisted) {
		d.Sessions["sP"].ClaudeAccount, d.Sessions["sP"].Harness = "claude-a", "paseo-claude"
	})
	setReg(r, "sP", func(g *Registry) {
		g.HostPid, g.CredsExpiresAt, g.BridgeSessionID, g.Status = 100, expA, "paseo:sP", "busy"
	})
	stop := make(chan struct{})
	defer close(stop)
	cmds := answerExecs(r, "mP", 0, stop)

	code, out := appDo(t, r, "POST", "/api/sessions/sP/account", `{"account":"claude-b"}`)
	if code != 202 || out["to"] != "claude-b" {
		t.Fatal(code, out)
	}
	if c, ok := takeCmd(r, "mP"); !ok || c != "claude-account" {
		t.Fatal("the machine wasn't told")
	}
	waitFor(t, "taking the login", func() bool { j := r.ops.jobView("sP"); return j != nil && j["phase"] == "taking the login" })
	setReg(r, "sP", func(g *Registry) { g.CredsExpiresAt, g.AccountSection = expB, true }) // same host pid: nothing restarted
	waitFor(t, "checking the account", func() bool { j := r.ops.jobView("sP"); return j != nil && j["phase"] == "checking the account" })
	setReg(r, "sP", func(g *Registry) { g.AccountProof = "acct-2" }) // the bridge stays "paseo:sP": no Remote Control phase
	waitFor(t, "the switch done", func() bool { j := r.ops.jobView("sP"); return j != nil && j["phase"] == "done" })
	if len(*cmds) != 0 {
		t.Fatal("an exec for a proxy-login switch", *cmds)
	}
	if r.ops.busyOf("sP") != nil {
		t.Fatal("the session stayed locked")
	}
	r.st.Do(func(d *persisted) {
		if d.Sessions["sP"].ClaudeAccount != "claude-b" {
			t.Fatal("the account didn't change")
		}
		if got := callDoes(d, RequestParams{Method: "POST", Path: "/api/sessions/sP/account", Body: `{"account":"a"}`}); !strings.Contains(got, "nothing restarts") {
			t.Fatal(got)
		}
	})
}

// the other non-claude harnesses are still refused while running
func TestAccountSwitchOpenClawStillRefused(t *testing.T) {
	r, _, _, expA, _ := twoAccounts(t)
	addSession(r, "sO", "started", "mO", false)
	r.st.Do(func(d *persisted) { d.Sessions["sO"].ClaudeAccount, d.Sessions["sO"].Harness = "claude-a", "openclaw" })
	setReg(r, "sO", func(g *Registry) { g.CredsExpiresAt = expA })
	if code, out := appDo(t, r, "POST", "/api/sessions/sO/account", `{"account":"claude-b"}`); code == 202 || !strings.Contains(out["error"].(string), "pause it") {
		t.Fatal(code, out)
	}
}
