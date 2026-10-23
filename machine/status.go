package main

// The session's live status, reported by the machine itself (Jarvis 1 read it by Fly exec every tick:
// readRegistry's REG_CMD in jarvis/server.js, with lib/claudelogin.js and lib/downgrade.js REG_SECTIONs). The
// supervisor runs the same shell locally every 10 s and POSTs the raw output to /m/status when it changed, and at
// least once a minute as a heartbeat; the router parses it (router/registry.go). It prints claude's registry
// files, ai-title lines, background-job counts, the one-shot marker, transcript ids ending on "Please run
// /login", the credentials file's expiry, refusal entries, the checked account of an account switch, then the subagent/background-job counts the supervisor holds (workers.go), and the keeper's harness record (starts, last end) — never a token.

import (
	"context"
	"encoding/json"
	"log"
	"time"
)

const regCmd = `for f in /home/claude/.claude/sessions/*.json; do cat "$f" 2>/dev/null; echo; done; echo __TITLES__; ` +
	`for f in /home/claude/.claude/projects/*/*.jsonl; do t=$(grep -h '"type":"ai-title"' "$f" 2>/dev/null | tail -1); [ -n "$t" ] && echo "$t"; done; ` +
	`echo __BG__; for f in /home/claude/.claude/sessions/*.json; do p=$(grep -o '"pid":[0-9]*' "$f" | head -1 | cut -d: -f2); [ -n "$p" ] && echo "$p $(pgrep -c -P "$p" -f shell-snapshots 2>/dev/null || echo 0)"; done; ` +
	`echo __ONESHOT__; cat /home/claude/.claude/.one-shot-done 2>/dev/null; ` +
	// __AUTH__ / __CREDS__ (lib/claudelogin.js REG_SECTION)
	`echo __AUTH__; for f in $(ls -t /home/claude/.claude/projects/*/*.jsonl 2>/dev/null | head -3); do ` +
	`l=$(tail -c 400000 "$f" 2>/dev/null | grep '"type":"assistant"' | tail -1); ` +
	`case "$l" in *'"error":"authentication_failed"'*) ` +
	`echo "$(basename "$f" .jsonl) $(printf %s "$l" | grep -o '"uuid":"[^"]*"' | head -1 | cut -d'"' -f4)";; esac; done; ` +
	`echo __CREDS__; grep -o '"expiresAt":[0-9]*' /home/claude/.claude/.credentials.json 2>/dev/null | head -1 | cut -d: -f2; ` +
	// __REFUSAL__ (lib/downgrade.js REG_SECTION)
	`echo __REFUSAL__; for f in /home/claude/.claude/projects/*/*.jsonl; do grep -h -E '"stop_reason":"refusal"|"subtype":"model_refusal_fallback"' "$f" 2>/dev/null | tail -4; done; ` +
	// __ACCOUNT__: the installed token's account as Anthropic named it after a switch (claudelogin.go afterSwitch)
	`echo __ACCOUNT__; cat /home/claude/.claude/.jarvis-account 2>/dev/null; echo; ` +
	`true`

const (
	statusEvery     = 10 * time.Second
	statusHeartbeat = 60 * time.Second
	statusMaxBytes  = 256 << 10
)

func readStatus() string {
	ctx, cancel := context.WithTimeout(context.Background(), statusEvery)
	defer cancel()
	out, _ := rescueCommand(ctx, "bash", "-c", regCmd).Output()
	// __WORKERS__: the subagent and background-job count per conversation, held by the supervisor (workers.go)
	out = append(out, "__WORKERS__\n"+workers.report()...)
	// __HARNESS__: the keeper's record of the harness: its starts, and how and when it last ended (keeper.go)
	if h := readHarnessState(); h != nil {
		b, _ := json.Marshal(h)
		out = append(out, "\n__HARNESS__\n"+string(b)+"\n"...)
	}
	if len(out) > statusMaxBytes {
		out = out[:statusMaxBytes]
	}
	return string(out)
}

// statusReporter: the supervisor's status loop (started by supervise once booted)
func statusReporter(c *client) {
	var last, lastTitle string
	var sent time.Time
	titles := &appTitler{} // apptitle.go: the Claude app's title of this session
	for ; ; time.Sleep(statusEvery) {
		raw, title := readStatus(), titles.current()
		if raw == last && title == lastTitle && time.Since(sent) < statusHeartbeat {
			continue
		}
		if err := c.json("POST", "/m/status", map[string]string{"raw": raw, "appTitle": title}, nil); err != nil {
			log.Printf("status report failed: %v", err)
			continue
		}
		last, lastTitle, sent = raw, title, time.Now()
	}
}
