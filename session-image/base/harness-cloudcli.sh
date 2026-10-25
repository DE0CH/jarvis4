#!/bin/bash
# Launcher for a session whose harness is Claude Code driven by CloudCLI (SESSION_HARNESS=cloudcli), exec'd by
# harness-claude.sh in place of the `claude --remote-control` host.
#
#   Claude Code    the agent loop: the image's own unmodified `claude`, run by the CloudCLI server through the Claude
#                  Agent SDK in the session's workspace, with the machine's settings, CLAUDE.md, skills, hooks and MCP
#                  servers (settingSources user/project/local). Model = SESSION_MODEL ("cloudcli/<Claude model id>").
#   CloudCLI       the front end: Deyao's fork DE0CH/claudecodeui in local Jarvis mode (JARVIS_LOCAL_WORKSPACE): the
#                  same server and chat protocol as YYC AI, so the "Jarvis 4 Chat" iPhone app (DE0CH/pwa-shell-ios,
#                  the YYC AI app's code) and the chat-only web UI both work, through the cf-tunnel on the session's own
#                  origin https://<session id>-s.deyaochen.com/ behind Cloudflare Access. It runs from the runtime
#                  bundle (cloudcli-runtime: Node, the fork, a portable PostgreSQL), fetched on first use.
#   PostgreSQL     the fork's state (conversation rows, names, drafts) in ~/.cloudcli/pg on a unix socket. NOT in the
#                  pause snapshot (a live data folder can't be copied safely): after a resume the server builds its
#                  rows again from Claude Code's transcripts, which are.
#   api-proxy.js   every Claude call goes through it (ANTHROPIC_BASE_URL; logged into ~/artifacts/api-log) and it
#                  sends the session's CURRENT Claude login, read fresh per request, so an account switch needs no
#                  restart (as harness-paseo-claude.sh).
#
# Everything Jarvis reads from a session keeps the shape a Claude session has (see harness-opencode.sh):
#   ~/.claude/sessions/cloudcli.json   status shim: idle | busy from the server's main conversation
#                                      (GET /api/jarvis/main); sessionId = its Claude conversation id
#   ~/.claude/projects/<slug>/*.jsonl  conversations: Claude Code's own transcripts
#   tmux session `claude`              the Terminal panel: the server's log
# Prompts are delivered with /usr/local/bin/harness-send (Jarvis execs it): POST /api/jarvis/deliver, a turn of the
# main conversation (made by the first prompt).
set -u
WD="${1:-$HOME/workspace}"
SESSION=claude
export HOME=/home/claude
export PATH="$HOME/.local/bin:/usr/local/bin:/usr/bin:/bin"
# the session's secrets are already in this env (boot took them from the supervisor; RAM only)

MACHINE="${SESSION_ID:-${FLY_MACHINE_ID:-$(hostname)}}"
WEB_HOST="$MACHINE-s.deyaochen.com"   # the tunnel's own origin (cf-tunnel/worker.js)
STATE="$HOME/.claude"; mkdir -p "$STATE/sessions"
CC="$HOME/.cloudcli"; mkdir -p "$CC/run"; chmod 700 "$CC" "$CC/run"
MODEL="${SESSION_MODEL:-cloudcli/claude-opus-5-5}"; MODEL="${MODEL#cloudcli/}"
LABEL="${SESSION_LABEL:-}"
PORT=3001 PROXY_PORT=8788
CREDS="$STATE/.credentials.json"
API="http://127.0.0.1:$PORT"

# Jarvis's modes → the server's (it reads the file at every turn, so set-permission-mode needs no restart)
perm_mode() { cat "$STATE/.permission-mode" 2>/dev/null || printf '%s' "${SESSION_PERMISSION_MODE:-bypass}"; }
model_label() { case "$1" in claude-opus-5-5) echo "Opus 5.5";; claude-fable-5-1) echo "Fable 5.1";; *) echo "$1";; esac; }

# Claude Code's login: the proxy's (harness-paseo-claude.sh claude_env, which explains the placeholder)
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

run_proxy() {
  ( while true; do API_PROXY_PORT=$PROXY_PORT API_PROXY_CLAUDE_AUTH=1 node /usr/local/lib/api-proxy.js
      echo "[cloudcli] api-proxy exited; restarting in 1 s"; sleep 1; done ) >> "$CC/api-proxy.out" 2>&1 &
  for _ in $(seq 1 40); do curl -s -o /dev/null "http://127.0.0.1:$PROXY_PORT/" && break; sleep 0.25; done
}

# The runtime bundle (fetched once per bundle version; a few seconds)
RT=""
for i in 1 2 3 4 5; do RT="$(/usr/local/bin/cloudcli-runtime 2>> "$CC/runtime.err")" && break; RT=""; sleep $((i * 5)); done
[ -n "$RT" ] || { echo "[cloudcli] the runtime bundle could not be fetched (see $CC/runtime.err)"; }
PGBIN="$RT/postgres/bin"; export LD_LIBRARY_PATH="$RT/postgres/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

# PostgreSQL on a unix socket only (no TCP), trust for this user: nothing but this machine's user reaches ~/.cloudcli
run_postgres() {
  if [ ! -s "$CC/pg/PG_VERSION" ]; then
    rm -rf "$CC/pg"
    "$PGBIN/initdb" -D "$CC/pg" -U claude -A trust -E UTF8 --no-instructions >> "$CC/postgres.out" 2>&1 \
      || { echo "[cloudcli] initdb failed (see $CC/postgres.out)"; return 1; }
  fi
  rm -f "$CC/pg/postmaster.pid"   # a snapshot never has it; a crash may leave it
  ( while true; do
      "$PGBIN/postgres" -D "$CC/pg" -c listen_addresses= -c unix_socket_directories="$CC/run" \
        -c shared_buffers=32MB -c max_connections=40 -c fsync=on >> "$CC/postgres.out" 2>&1
      echo "[cloudcli] postgres exited ($?); restarting in 2 s" >> "$CC/postgres.out"; sleep 2
    done ) &
  for _ in $(seq 1 60); do [ -S "$CC/run/.s.PGSQL.5432" ] && return 0; sleep 0.5; done
  echo "[cloudcli] postgres did not come up (see $CC/postgres.out)"
}

# The CloudCLI server in a restart loop. Its state outside Postgres: ~/.claude (transcripts, ~/.claude/cloudcli-assets
# for uploaded pictures; both in the snapshot) and ~/uploads (attachments for Claude Code).
run_server() {
  local jwt; jwt="$(cat "$CC/jwt-secret" 2>/dev/null)"
  [ -n "$jwt" ] || { jwt="$(python3 -c 'import secrets;print(secrets.token_hex(32))')"; (umask 077; printf '%s' "$jwt" > "$CC/jwt-secret"); }
  while [ ! -e "$STATE/.one-shot-done" ]; do
    claude_env
    ( cd "$RT/app" && env NODE_ENV=production HOST=127.0.0.1 SERVER_PORT=$PORT \
        DATABASE_URL="postgresql://claude@localhost/postgres?host=$CC/run" DATABASE_SCHEMA=cloudcli JWT_SECRET="$jwt" \
        JARVIS_LOCAL_WORKSPACE="$WD" JARVIS_LOCAL_UPLOADS="$HOME/uploads" \
        JARVIS_LOCAL_PERMISSION_FILE="$STATE/.permission-mode" JARVIS_LOCAL_PERMISSION_MODE="$(perm_mode)" \
        JARVIS_CC_OWNER=deyao@jarvis4.local JARVIS_OWNER_FIRST_NAME=Deyao JARVIS_PRODUCT_NAME="${LABEL:-Jarvis 4}" \
        JARVIS_MODEL="$MODEL" JARVIS_MODEL_LABEL="$(model_label "$MODEL")" JARVIS_LOCALE=en \
        CLAUDE_CLI_PATH="$(command -v claude || echo /home/claude/.local/bin/claude)" \
        "$RT/node/bin/node" --max-old-space-size=512 dist-server/server/index.js ) >> "$CC/server.out" 2>&1
    echo "[cloudcli] server exited ($?); restarting in 3 s" >> "$CC/server.out"; sleep 3
  done
}

server_up() { curl -s -o /dev/null -m 3 -w '%{http_code}' "$API/health" 2>/dev/null | grep -q 200; }

# The web UI and the app's API behind Cloudflare Access (as harness-opencode.sh)
run_tunnel() {
  [ -n "${CF_ACCESS_CLIENT_ID:-}" ] && [ -n "${CF_ACCESS_CLIENT_SECRET:-}" ] || { echo "[cloudcli] no CF_ACCESS_* in the secrets; not published"; return 0; }
  ( while true; do TUNNEL_ID="$MACHINE" TUNNEL_TARGET="$API" node /usr/local/lib/cf-tunnel-agent.js; sleep 3; done ) >> "$CC/tunnel.out" 2>&1 &
  echo "[cloudcli] web UI and app: https://$WEB_HOST/"
}

# First prompt (+ attachments), once per machine, same marker as the claude path
send_first_prompt() {
  local marker="$STATE/.first-prompt-sent" f="$STATE/first-prompt.txt" imgf="$STATE/first-prompt-images.txt"
  [ -n "${SESSION_PROMPT:-}" ] || [ -n "${SESSION_ATTACHMENTS_JSON:-}" ] || return 0
  [ -e "$marker" ] && return 0
  for _ in $(seq 1 90); do server_up && break; sleep 2; done
  server_up || { echo "[cloudcli] first prompt NOT sent: the server never came up"; return 0; }
  if [ -n "${SESSION_ATTACHMENTS_JSON:-}" ]; then
    (umask 077; /usr/local/bin/session-attachments "$f" "$imgf")
  else
    (umask 077; printf '%s' "$SESSION_PROMPT" > "$f"); : > "$imgf"
  fi
  [ -s "$f" ] || [ -s "$imgf" ] || { echo "[cloudcli] first prompt NOT sent (nothing to send)"; return 0; }
  [ -s "$f" ] || printf 'See the attached image(s).' > "$f"
  for _ in 1 2 3 4 5; do
    if /usr/local/bin/harness-send --images "$imgf" < "$f" >> "$CC/inbox.out" 2>&1; then
      touch "$marker"; echo "[cloudcli] first prompt sent ($(wc -c < "$f") bytes)"; return 0
    fi
    sleep 10
  done
  echo "[cloudcli] first prompt NOT sent (see $CC/inbox.out)"
}

# Status shim, from the server's main conversation (one curl every 5 s)
shim_loop() {
  while true; do
    curl -s -m 4 "$API/api/jarvis/main" 2>/dev/null | python3 -c '
import json, os, sys, time
machine, label = sys.argv[1], sys.argv[2]
try: m = json.load(sys.stdin)
except Exception: sys.exit(0)  # server not up (yet): no registry entry -> "booting…" on the dashboard
state = os.path.expanduser("~/.claude")
path = os.path.join(state, "sessions", "cloudcli.json")
try: prev = json.load(open(path))
except Exception: prev = {}
status = "busy" if m.get("status") == "busy" else "idle"
now = int(time.time() * 1000)
pid = 0
try: pid = int(open(os.path.expanduser("~/.cloudcli/server.pid")).read().strip())
except Exception: pass
changed = prev.get("status") != status
entry = {"pid": pid, "sessionId": m.get("providerSessionId") or m.get("sessionId") or "cloudcli",
         "name": label or m.get("title") or "", "nameSource": "harness", "harness": "cloudcli",
         "status": status, "statusUpdatedAt": now if changed else prev.get("statusUpdatedAt", now),
         "lastActivityMs": now if (changed and status == "busy") else prev.get("lastActivityMs", now),
         "startedAt": prev.get("startedAt", now), "bridgeSessionId": "cloudcli:" + machine}
if entry != prev:
    tmp = path + ".tmp"; json.dump(entry, open(tmp, "w")); os.replace(tmp, path)
' "$MACHINE" "$LABEL"
    sleep 5
  done
}

# Prompts Jarvis queued with `harness-send --queue`: oldest first, each once the main conversation is idle (75 = busy,
# not a failed try), retried, set aside after 20 failed tries (as harness-paseo-claude.sh)
inbox_loop() {
  local inbox="$STATE/harness-inbox" f tries rc
  mkdir -p "$inbox/failed"
  while true; do
    for f in "$inbox"/*.txt; do
      [ -f "$f" ] || continue
      /usr/local/bin/harness-send < "$f" > /dev/null 2>> "$CC/inbox.err"; rc=$?
      if [ "$rc" = 0 ]; then
        rm -f "$f" "$f.tries"; echo "[cloudcli] delivered a queued prompt ($(basename "$f"))"
      elif [ "$rc" = 75 ]; then
        break
      else
        tries=$(( $(cat "$f.tries" 2>/dev/null || echo 0) + 1 )); echo "$tries" > "$f.tries"
        [ "$tries" -ge 20 ] && { mv "$f" "$inbox/failed/"; rm -f "$f.tries"; echo "[cloudcli] gave up on a queued prompt ($(basename "$f"))"; }
        break
      fi
    done
    sleep 3
  done
}

# One-shot: done = idle, after a turn that started later than the prompt, for 60 s straight
one_shot_watch() {
  [ "${SESSION_ONE_SHOT:-}" = "1" ] || return 0
  local marker="$STATE/.one-shot-done" sent="$STATE/.first-prompt-sent" sent_ms idle_since=0 st ts now
  [ -e "$marker" ] && return 0
  while [ ! -e "$sent" ]; do sleep 5; done
  sent_ms=$(( $(stat -c %Y "$sent") * 1000 ))
  echo "[one-shot] prompt sent; watching for completion"
  while true; do
    sleep 3
    read -r st ts < <(python3 -c 'import json,os;d=json.load(open(os.path.expanduser("~/.claude/sessions/cloudcli.json")));print(d.get("status",""),int(d.get("statusUpdatedAt") or 0))' 2>/dev/null) || { idle_since=0; continue; }
    now=$(date +%s)
    if [ "$st" = idle ] && [ "${ts:-0}" -gt "$sent_ms" ]; then
      [ "$idle_since" = 0 ] && idle_since=$now
      if [ $((now - idle_since)) -ge 60 ]; then
        printf 'done %s idle=60s bg=0\n' "$(date -u +%FT%TZ)" > "$marker"
        rm -f "$STATE/sessions/cloudcli.json"
        pkill -u "$(id -u)" -f "$RT/node/bin/node .*dist-server/server/index.js" || true
        echo "[one-shot] done; waiting for Jarvis to archive + destroy this machine"
        return 0
      fi
    else idle_since=0; fi
  done
}

# The Terminal panel: the server's log
tmux_pane() {
  tmux kill-session -t "$SESSION" 2>/dev/null || true
  tmux new-session -d -s "$SESSION" -x 120 -y 40 -c "$WD" \
    "echo 'Claude Code ($MODEL) via CloudCLI — Jarvis 4 Chat app, or https://$WEB_HOST/'; tail -n 200 -F $CC/server.out"
}

echo "[cloudcli] harness up in $WD (model: $MODEL, perm: $(perm_mode), name: ${LABEL:-auto})"
mkdir -p "$HOME/uploads"
run_proxy
run_postgres
run_server &
echo $! > "$CC/server-loop.pid"
run_tunnel
tmux_pane
send_first_prompt &
inbox_loop &
one_shot_watch &
shim_loop &
# set-permission-mode kills the tmux session: the server reads the mode file at every turn, so only the pane comes
# back; then keep the machine alive for as long as Jarvis wants it
while true; do
  if ! tmux has-session -t "$SESSION" 2>/dev/null && [ ! -e "$STATE/.one-shot-done" ]; then
    echo "[cloudcli] terminal pane gone (permission-mode switch?); the server takes mode $(perm_mode) at the next turn"
    tmux_pane
  fi
  pgrep -u "$(id -u)" -f "dist-server/server/index.js" | head -1 > "$CC/server.pid" 2>/dev/null || true
  sleep 5
done
