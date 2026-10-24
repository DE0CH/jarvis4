#!/bin/bash
# Launcher for a session whose harness is Claude Code driven by Paseo (SESSION_HARNESS=paseo-claude), exec'd by
# harness-claude.sh in place of the `claude --remote-control` host.
#
#   Claude Code    the agent loop: the image's own unmodified `claude` binary, run by the Paseo daemon through the
#                  Claude Agent SDK (Paseo's bundled SDK binary is a link to it: base/Dockerfile). It loads the
#                  working dir's CLAUDE.md (imports included), skills, settings, hooks and MCP servers itself
#                  (the SDK's settingSources user/project/local). Model = SESSION_MODEL ("paseo/<Claude model id>").
#   Paseo daemon   the front end: Deyao's Paseo app over Paseo's end-to-end-encrypted relay (pairing link on the
#                  Remote page) and the daemon's web UI behind Cloudflare Access through the cf-tunnel on the
#                  session's own origin https://<session id>-s.deyaochen.com/ (paseo-front.js), as for OpenCode.
#   api-proxy.js   every Claude call goes through it (ANTHROPIC_BASE_URL; logged into ~/artifacts/api-log) and it
#                  sends the session's CURRENT Claude login (~/.claude/.credentials.json, which jarvis-machine
#                  keeps in step with the router: machine/claudelogin.go), read fresh per request. That is what
#                  makes an account switch transparent: the machine writes the new account's pair and the next
#                  request goes out on it, mid-turn included, with nothing restarted (router/accountswap.go).
#
# Claude Code never holds a refresh token here: it runs with CLAUDE_CODE_OAUTH_TOKEN = a placeholder, so its
# credentials are {accessToken: placeholder, refreshToken: null, expiresAt: null}. It has nothing to refresh
# with, and on a 401 it keeps the user-supplied token instead of adopting or refreshing the stored one (verified
# on 2.1.304, DECISIONS 204). The router stays the only refresher of every account (DECISIONS 185).
#
# Everything Jarvis reads from a session keeps the shape a Claude session has (see harness-opencode.sh):
#   ~/.claude/sessions/paseo.json      status shim: idle | busy | waiting, from Paseo's own agent files; its
#                                      sessionId is the main agent's Claude conversation id, so the subagent /
#                                      background-job count (the workers hook, which Claude Code runs here too)
#                                      and the titles match it
#   ~/.claude/projects/<slug>/*.jsonl  conversations: Claude Code's own transcripts
#   tmux session `claude`              the Terminal panel: `paseo logs -f` of the main agent
# Prompts are delivered with /usr/local/bin/harness-send (Jarvis execs it), not keystrokes.
set -u
WD="${1:-$HOME/workspace}"
SESSION=claude
export HOME=/home/claude
export PATH="$HOME/.local/bin:/usr/local/bin:/usr/bin:/bin"
# the session's secrets are already in this env (boot took them from the supervisor; RAM only)

export PASEO_HOME="$HOME/.paseo"
MACHINE="${SESSION_ID:-${FLY_MACHINE_ID:-$(hostname)}}"
WEB_HOST="$MACHINE-s.deyaochen.com"   # the tunnel's own origin (cf-tunnel/worker.js)
STATE="$HOME/.claude"; mkdir -p "$STATE/sessions" "$PASEO_HOME"
MODEL="${SESSION_MODEL:-paseo/claude-opus-5-5}"; MODEL="${MODEL#paseo/}"
LABEL="${SESSION_LABEL:-}"
PROXY_PORT=8788
CREDS="$STATE/.credentials.json"

perm_mode() { cat "$STATE/.permission-mode" 2>/dev/null || printf '%s' "${SESSION_PERMISSION_MODE:-auto}"; }
# Jarvis's modes → Claude Code's: auto = the auto-mode classifier, bypass = bypassPermissions
paseo_mode() { [ "$(perm_mode)" = bypass ] && echo bypassPermissions || echo auto; }

# Daemon settings by env (see harness-opencode.sh). Voice/dictation off (~1 GB of speech models otherwise).
export PASEO_RELAY_ENABLED=true PASEO_WEB_UI_ENABLED=true
export PASEO_DICTATION_ENABLED=false PASEO_VOICE_MODE_ENABLED=false
export PASEO_CORS_ORIGINS="https://app.paseo.sh,https://$WEB_HOST"
export PASEO_HOSTNAMES="$WEB_HOST,localhost,127.0.0.1"

# Claude Code's login: the proxy's. The placeholder is never sent upstream (api-proxy swaps it); the scopes and
# plan are the real login's, so Claude Code offers what the account has. Claude Code scrubs the token from its
# tools' env (ANTHROPIC_BASE_URL stays), so a `claude -p` in a Bash tool goes through the proxy but logs in from
# ~/.claude/.credentials.json like any claude on the machine.
# Any other Anthropic credential would win over the OAuth token and be billed elsewhere: none reaches the daemon.
claude_env() {
  unset ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN
  export ANTHROPIC_BASE_URL="http://127.0.0.1:$PROXY_PORT"
  export CLAUDE_CODE_OAUTH_TOKEN="jarvis-api-proxy-placeholder"
  local scopes plan tier
  read -r plan tier scopes < <(python3 - "$CREDS" <<'PY' 2>/dev/null
import json, sys
try: o = json.load(open(sys.argv[1]))["claudeAiOauth"]
except Exception: o = {}
print(o.get("subscriptionType") or "-", o.get("rateLimitTier") or "-", " ".join(o.get("scopes") or []) or "-")
PY
)
  [ "${scopes:--}" != - ] && export CLAUDE_CODE_OAUTH_SCOPES="$scopes"
  [ "${plan:--}" != - ] && export CLAUDE_CODE_SUBSCRIPTION_TYPE="$plan"
  [ "${tier:--}" != - ] && export CLAUDE_CODE_RATE_LIMIT_TIER="$tier"
  return 0
}

# The proxy: the session's current Claude login on every call (logged).
run_proxy() {
  ( while true; do API_PROXY_PORT=$PROXY_PORT API_PROXY_CLAUDE_AUTH=1 node /usr/local/lib/api-proxy.js
      echo "[paseo-claude] api-proxy exited; restarting in 1 s"; sleep 1; done ) >> "$PASEO_HOME/api-proxy.out" 2>&1 &
  for _ in $(seq 1 40); do curl -s -o /dev/null "http://127.0.0.1:$PROXY_PORT/" && break; sleep 0.25; done
}

daemon_up() { paseo daemon status 2>/dev/null | grep -q 'Connected Daemon *reachable'; }

# The daemon in the foreground of a restart loop (it dies -> it comes back; its agents are on disk and resume
# their Claude conversations). Stops for good once a one-shot is done.
run_daemon() {
  while [ ! -e "$STATE/.one-shot-done" ]; do
    claude_env
    paseo daemon start --foreground >> "$PASEO_HOME/daemon.out" 2>&1
    echo "[paseo-claude] paseo daemon exited ($?); restarting"; sleep 3
  done
}

# The web UI behind Cloudflare Access (as harness-opencode.sh).
run_tunnel() {
  [ -n "${CF_ACCESS_CLIENT_ID:-}" ] && [ -n "${CF_ACCESS_CLIENT_SECRET:-}" ] || { echo "[paseo-claude] no CF_ACCESS_* in the secrets; web UI not published"; return 0; }
  ( while true; do PASEO_PUBLIC_HOST="$WEB_HOST:443" node /usr/local/lib/paseo-front.js; sleep 3; done ) >> "$PASEO_HOME/front.out" 2>&1 &
  ( while true; do TUNNEL_ID="$MACHINE" TUNNEL_TARGET="http://127.0.0.1:6768" node /usr/local/lib/cf-tunnel-agent.js; sleep 3; done ) >> "$PASEO_HOME/tunnel.out" 2>&1 &
  echo "[paseo-claude] web UI: https://$WEB_HOST/"
}

# First prompt (+ attachments), once per machine, same marker as the claude path.
send_first_prompt() {
  local marker="$STATE/.first-prompt-sent" f="$STATE/first-prompt.txt" imgf="$STATE/first-prompt-images.txt"
  [ -n "${SESSION_PROMPT:-}" ] || [ -n "${SESSION_ATTACHMENTS_JSON:-}" ] || return 0
  [ -e "$marker" ] && return 0
  for _ in $(seq 1 90); do daemon_up && break; sleep 2; done
  daemon_up || { echo "[paseo-claude] first prompt NOT sent: daemon never came up"; return 0; }
  if [ -n "${SESSION_ATTACHMENTS_JSON:-}" ]; then
    (umask 077; /usr/local/bin/session-attachments "$f" "$imgf")
  else
    (umask 077; printf '%s' "$SESSION_PROMPT" > "$f"); : > "$imgf"
  fi
  [ -s "$f" ] || [ -s "$imgf" ] || { echo "[paseo-claude] first prompt NOT sent (nothing to send)"; return 0; }
  [ -s "$f" ] || printf 'See the attached image(s).' > "$f"
  for _ in 1 2 3 4 5; do
    if /usr/local/bin/harness-send --images "$imgf" < "$f" >> "$PASEO_HOME/inbox.out" 2>&1; then
      touch "$marker"; echo "[paseo-claude] first prompt sent ($(wc -c < "$f") bytes)"; return 0
    fi
    sleep 10
  done
  echo "[paseo-claude] first prompt NOT sent (paseo run failed; see $PASEO_HOME/inbox.out)"
}

# Status shim, from Paseo's own agent files (never the paseo CLI: a ~200 MB node run per call). As
# harness-opencode.sh, plus: sessionId = the main agent's Claude conversation id (persistence.sessionId).
shim_loop() {
  while true; do
    python3 - "$MACHINE" "$LABEL" <<'PY'
import glob, json, os, sys, time
from datetime import datetime
machine, label = sys.argv[1], sys.argv[2]
state, home = os.path.expanduser("~/.claude"), os.environ["PASEO_HOME"]
try: pid = int(json.load(open(os.path.join(home, "paseo.pid"))).get("pid") or 0); os.kill(pid, 0)
except Exception: sys.exit(0)  # daemon not up (yet): no registry entry -> "booting…" on the dashboard
agents = []
for f in glob.glob(os.path.join(home, "agents", "*", "*.json")):
    try: a = json.load(open(f))
    except Exception: continue
    if not a.get("internal") and not a.get("archivedAt"): agents.append(a)
def ms(t):
    try: return int(datetime.fromisoformat(str(t).replace("Z", "+00:00")).timestamp() * 1000)
    except Exception: return 0
waiting = any(a.get("requiresAttention") and a.get("attentionReason") == "permission" for a in agents)
running = any(a.get("lastStatus") in ("running", "initializing") for a in agents)
status = "waiting" if waiting else "busy" if running else "idle"
try: main = open(os.path.join(state, ".paseo-agent")).read().strip()
except Exception: main = ""
m = next((a for a in agents if a.get("id") == main), {})
name = m.get("title") or label
conv = (m.get("persistence") or {}).get("sessionId") or (m.get("runtimeInfo") or {}).get("sessionId") or main or "paseo"
last_user = max([ms(a.get("lastUserMessageAt")) for a in agents] or [0])
path = os.path.join(state, "sessions", "paseo.json")
try: prev = json.load(open(path))
except Exception: prev = {}
now = int(time.time() * 1000)
changed = prev.get("status") != status or prev.get("pid") != pid or last_user > (prev.get("lastActivityMs") or 0)
entry = {"pid": pid, "sessionId": conv, "name": name, "nameSource": "harness", "harness": "paseo-claude",
         "status": status, "statusUpdatedAt": now if changed else prev.get("statusUpdatedAt", now),
         "lastActivityMs": max(last_user, prev.get("lastActivityMs") or 0),
         "startedAt": prev.get("startedAt") if prev.get("pid") == pid else now,
         "bridgeSessionId": "paseo:" + machine, "agents": len(agents)}
if entry != prev:
    tmp = path + ".tmp"; json.dump(entry, open(tmp, "w")); os.replace(tmp, path)
PY
    sleep 5
  done
}

# Prompts Jarvis queued with `harness-send --queue` (wakeups, watches, the stall nudge, "continue" after an
# account switch, Deyao's resume prompt): oldest first, each only once the main agent is idle (Paseo's send would
# interrupt a running turn), retried, set aside after 20 failed tries.
inbox_loop() {
  local inbox="$STATE/harness-inbox" f tries rc
  mkdir -p "$inbox/failed"
  while true; do
    for f in "$inbox"/*.txt; do
      [ -f "$f" ] || continue
      /usr/local/bin/harness-send < "$f" > /dev/null 2>> "$PASEO_HOME/inbox.err"; rc=$?
      if [ "$rc" = 0 ]; then
        rm -f "$f" "$f.tries"; echo "[paseo-claude] delivered a queued prompt ($(basename "$f"))"
      elif [ "$rc" = 75 ]; then
        break   # the agent is mid-turn: this one goes in once it is idle (not a failed try)
      else
        tries=$(( $(cat "$f.tries" 2>/dev/null || echo 0) + 1 )); echo "$tries" > "$f.tries"
        [ "$tries" -ge 20 ] && { mv "$f" "$inbox/failed/"; rm -f "$f.tries"; echo "[paseo-claude] gave up on a queued prompt ($(basename "$f"))"; }
        break   # keep the order: retry this one before the next
      fi
    done
    sleep 3
  done
}

# One-shot: done = idle, after a turn that started later than the prompt, for 60 s straight.
one_shot_watch() {
  [ "${SESSION_ONE_SHOT:-}" = "1" ] || return 0
  local marker="$STATE/.one-shot-done" sent="$STATE/.first-prompt-sent" sent_ms idle_since=0 st ts now
  [ -e "$marker" ] && return 0
  while [ ! -e "$sent" ]; do sleep 5; done
  sent_ms=$(( $(stat -c %Y "$sent") * 1000 ))
  echo "[one-shot] prompt sent; watching for completion"
  while true; do
    sleep 3
    read -r st ts < <(python3 -c 'import json,os;d=json.load(open(os.path.expanduser("~/.claude/sessions/paseo.json")));print(d.get("status",""),int(d.get("statusUpdatedAt") or 0))' 2>/dev/null) || { idle_since=0; continue; }
    now=$(date +%s)
    if [ "$st" = idle ] && [ "${ts:-0}" -gt "$sent_ms" ]; then
      [ "$idle_since" = 0 ] && idle_since=$now
      if [ $((now - idle_since)) -ge 60 ]; then
        printf 'done %s idle=60s bg=0\n' "$(date -u +%FT%TZ)" > "$marker"
        rm -f "$STATE/sessions/paseo.json"
        paseo daemon stop >/dev/null 2>&1 || true
        echo "[one-shot] done; waiting for Jarvis to archive + destroy this machine"
        return 0
      fi
    else idle_since=0; fi
  done
}

# The Terminal panel: follow the main agent's activity; before there is one, say how to connect.
tmux_pane() {
  tmux kill-session -t "$SESSION" 2>/dev/null || true
  tmux new-session -d -s "$SESSION" -x 120 -y 40 -c "$WD" \
    "while true; do id=\$(cat $STATE/.paseo-agent 2>/dev/null); if [ -n \"\$id\" ]; then paseo logs -f \"\$id\"; else clear; echo 'Claude Code ($MODEL) via Paseo — no agent yet.'; echo 'Web UI: https://$WEB_HOST/   ·   iPhone: the Paseo app (Remote on the session card)'; fi; sleep 5; done"
}

# An in-place permission-mode switch: every Claude agent of this daemon takes the new mode (paseo agent mode;
# no daemon restart, so a running turn isn't cut off). Agents created later get it from harness-send.
apply_mode() {
  local mode a; mode="$(paseo_mode)"
  for a in $(python3 - <<'PY'
import glob, json, os
for f in glob.glob(os.path.join(os.environ["PASEO_HOME"], "agents", "*", "*.json")):
    try: a = json.load(open(f))
    except Exception: continue
    if a.get("provider") == "claude" and not a.get("internal") and not a.get("archivedAt"): print(a["id"])
PY
); do
    paseo agent mode "$a" "$mode" --json >/dev/null 2>&1 && echo "[paseo-claude] agent $a → $mode" || echo "[paseo-claude] agent $a: mode switch failed"
  done
}

echo "[paseo-claude] harness up in $WD (model: $MODEL, perm: $(perm_mode), name: ${LABEL:-auto})"
run_proxy
run_daemon &
run_tunnel
tmux_pane
send_first_prompt &
inbox_loop &
one_shot_watch &
shim_loop &
# set-permission-mode kills the tmux session: apply the new mode to the agents and bring the pane back; then keep
# the machine alive for as long as Jarvis wants it.
while true; do
  if ! tmux has-session -t "$SESSION" 2>/dev/null && [ ! -e "$STATE/.one-shot-done" ]; then
    echo "[paseo-claude] terminal pane gone (permission-mode switch?); applying mode $(paseo_mode)"
    tmux_pane; apply_mode
  fi
  sleep 5
done
