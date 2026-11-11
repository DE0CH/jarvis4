#!/bin/bash
# Supervisor for a session whose harness is claw-code inside an OpenClaw gateway (SESSION_HARNESS=openclaw),
# exec'd by harness-claude.sh in place of the `claude --remote-control` host.
#
#   claw-code      the agent loop (Deyao's fork DE0CH/claw-code, the editable Rust Claude Code), run per turn
#                  by the openclaw-claw-harness plugin; model = SESSION_MODEL ("openclaw/<Claude model id>").
#   OpenClaw       the gateway (Deyao's fork DE0CH/openclaw) = the front end: its Control UI and Deyao's
#                  OpenClaw app, both through the cf-tunnel on the session's own origin
#                  https://<session id>-s.deyaochen.com/ behind Cloudflare Access, plus the gateway token.
#   api-proxy.js   every Claude call goes through it (logged into ~/artifacts/api-log) and it sends the
#                  session's own Claude login (~/.claude/.credentials.json, kept fresh by Jarvis).
#
# Everything Jarvis reads from a session keeps the shape a Claude session has (see harness-opencode.sh):
#   ~/.claude/sessions/openclaw.json    status shim, written by the claw-code plugin per turn (statusFile)
#   ~/.claude/projects/<slug>/*.jsonl   conversations (openclaw-transcript)
#   tmux session `claude`               the Terminal panel: `openclaw tui` on the main session
#   ~/.openclaw/jarvis-remote.json      {token}: the gateway token, what GET /api/remotes hands Deyao's OpenClaw app
# Prompts are delivered with /usr/local/bin/harness-send (Jarvis execs it), not keystrokes.
set -u
WD="${1:-$HOME/workspace}"
SESSION=claude
export HOME=/home/claude
export PATH="$HOME/.local/bin:/usr/local/bin:/usr/bin:/bin"
# the session's secrets are already in this env (boot took them from the supervisor; RAM only)

MACHINE="${SESSION_ID:-${FLY_MACHINE_ID:-$(hostname)}}"
WEB_HOST="$MACHINE-s.deyaochen.com"
STATE="$HOME/.claude"; mkdir -p "$STATE/sessions"
export OPENCLAW_STATE_DIR="$HOME/.openclaw"; mkdir -p "$OPENCLAW_STATE_DIR"; chmod 700 "$OPENCLAW_STATE_DIR"
MODEL="${SESSION_MODEL:-openclaw/claude-fable-5-2}"; MODEL="${MODEL#openclaw/}"
PORT=18789 PROXY_PORT=8788
REMOTE="$OPENCLAW_STATE_DIR/jarvis-remote.json"
LOG="$OPENCLAW_STATE_DIR"
export SESSION_LABEL="${SESSION_LABEL:-}"

perm_mode() { cat "$STATE/.permission-mode" 2>/dev/null || printf '%s' "${SESSION_PERMISSION_MODE:-auto}"; }

# openclaw.json, written whole by this script (no `openclaw onboard`: it hung under memory pressure). Every
# start re-applies what Jarvis owns — model, claw-code as its runtime, the proxy, the origin, the permission
# mode — onto whatever else the file holds (settings changed in the Control UI survive). The gateway token
# is minted once and kept in jarvis-remote.json (what GET /api/remotes hands Deyao's OpenClaw app).
write_config() {
  [ -f "$REMOTE" ] || (umask 077; python3 -c 'import json,secrets;print(json.dumps({"token":secrets.token_urlsafe(32)}))' > "$REMOTE")
  python3 - "$MODEL" "$WD" "$WEB_HOST" "$PORT" "$PROXY_PORT" "$(perm_mode)" "$REMOTE" "$OPENCLAW_STATE_DIR/openclaw.json" <<'PY'
import json, os, sys
model, wd, host, port, proxy, perm, remote, path = sys.argv[1:9]
token = json.load(open(remote))["token"]
try: cfg = json.load(open(path))
except Exception: cfg = {}
def merge(a, b):
    for k, v in b.items():
        if isinstance(v, dict) and isinstance(a.get(k), dict): merge(a[k], v)
        else: a[k] = v
    return a
claude_models = ["claude-fable-5-2", "claude-opus-5-5"]
merge(cfg, {
  "agents": {"defaults": {"workspace": wd, "model": {"primary": "anthropic/" + model},
                          "models": {"anthropic/" + m: {"agentRuntime": {"id": "claw-code"}} for m in set(claude_models + [model])}}},
  "gateway": {"mode": "local", "auth": {"mode": "token", "token": token}, "port": int(port), "bind": "loopback",
              "tailscale": {"mode": "off"}, "controlUi": {"allowedOrigins": [f"https://{host}"]},
              # the cf-tunnel agent is a same-host proxy: it forwards Cloudflare's X-Real-IP (the client) and no
              # X-Forwarded-For; without these the gateway answers 403 proxy_attribution_required
              "trustedProxies": ["127.0.0.1/32", "::1/128"], "allowRealIpFallback": True},
  "update": {"checkOnStart": False},
  "plugins": {"load": {"paths": ["/usr/local/lib/openclaw-claw-harness"]},
              "entries": {
                "claw-code": {"enabled": True, "config": {"command": "/usr/local/bin/claw",
                  "statusFile": os.path.expanduser("~/.claude/sessions/openclaw.json"),
                  "permissionMode": "bypass" if perm == "bypass" else "ask",
                  "env": {"ANTHROPIC_BASE_URL": f"http://127.0.0.1:{proxy}", "ANTHROPIC_AUTH_TOKEN": "placeholder-swapped-by-api-proxy"}}}}},
})
tmp = path + ".tmp"
with open(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f: json.dump(cfg, f, indent=2)
os.replace(tmp, path)
PY
}

# The Claude login for every model call (logged).
run_proxy() {
  ( while true; do API_PROXY_PORT=$PROXY_PORT API_PROXY_CLAUDE_AUTH=1 node /usr/local/lib/api-proxy.js; sleep 1; done ) >> "$LOG/api-proxy.out" 2>&1 &
}

gateway_up() { curl -s -o /dev/null -m 3 "http://127.0.0.1:$PORT/" ; }

# The gateway in the foreground of a restart loop; stops for good once a one-shot is done. While
# ~/.openclaw/.hold exists it stays down: Jarvis's pause/destroy snapshot (lib/archive.js) sets it, stops the
# gateway with SIGTERM so it releases its owner lease and closes its SQLite state, tars ~/.openclaw, and
# removes it. A snapshot of a RUNNING gateway carries its lease, and the restored gateway then refuses to start
# for 5 minutes ("Another Gateway owner lease is still active").
run_gateway() {
  while [ ! -e "$STATE/.one-shot-done" ]; do
    while [ -e "$OPENCLAW_STATE_DIR/.hold" ]; do sleep 1; done
    write_config
    (cd "$WD" && exec openclaw gateway run --port "$PORT" --allow-unconfigured) >> "$LOG/gateway.out" 2>&1 &
    echo $! > "$LOG/gateway.pid"; wait $!
    echo "[openclaw] gateway exited ($?); restarting"; sleep 3
  done
}

# Control UI + the app's WebSocket behind Cloudflare Access: this session's own tunnel (id = session id).
run_tunnel() {
  [ -n "${CF_ACCESS_CLIENT_ID:-}" ] && [ -n "${CF_ACCESS_CLIENT_SECRET:-}" ] || { echo "[openclaw] no CF_ACCESS_* in the secrets; front end not published"; return 0; }
  ( while true; do TUNNEL_ID="$MACHINE" TUNNEL_TARGET="http://127.0.0.1:$PORT" node /usr/local/lib/cf-tunnel-agent.js; sleep 3; done ) >> "$LOG/tunnel.out" 2>&1 &
  echo "[openclaw] Control UI: https://$WEB_HOST/"
}

# First prompt (+ attachments), once per machine, same marker as the claude path.
send_first_prompt() {
  local marker="$STATE/.first-prompt-sent" f="$STATE/first-prompt.txt" imgf="$STATE/first-prompt-images.txt"
  [ -n "${SESSION_PROMPT:-}" ] || [ -n "${SESSION_ATTACHMENTS_JSON:-}" ] || return 0
  [ -e "$marker" ] && return 0
  for _ in $(seq 1 120); do gateway_up && break; sleep 2; done
  gateway_up || { echo "[openclaw] first prompt NOT sent: gateway never came up"; return 0; }
  if [ -n "${SESSION_ATTACHMENTS_JSON:-}" ]; then (umask 077; /usr/local/bin/session-attachments "$f" "$imgf")
  else (umask 077; printf '%s' "$SESSION_PROMPT" > "$f"); : > "$imgf"; fi
  [ -s "$f" ] || [ -s "$imgf" ] || { echo "[openclaw] first prompt NOT sent (nothing to send)"; return 0; }
  [ -s "$f" ] || printf 'See the attached image(s).' > "$f"
  for _ in 1 2 3 4 5; do
    if /usr/local/bin/harness-send --images "$imgf" < "$f" >> "$LOG/inbox.out" 2>&1; then
      touch "$marker"; echo "[openclaw] first prompt sent ($(wc -c < "$f") bytes)"; return 0
    fi
    sleep 10
  done
  echo "[openclaw] first prompt NOT sent (chat.send failed; see $LOG/inbox.out)"
}

# Prompts Jarvis queued with `harness-send --queue`: oldest first, retried, set aside after 20 tries.
inbox_loop() {
  local inbox="$STATE/harness-inbox" f tries
  mkdir -p "$inbox/failed"
  while true; do
    for f in "$inbox"/*.txt; do
      [ -f "$f" ] || continue
      if /usr/local/bin/harness-send < "$f" >> "$LOG/inbox.out" 2>&1; then
        rm -f "$f" "$f.tries"; echo "[openclaw] delivered a queued prompt ($(basename "$f"))"
      else
        tries=$(( $(cat "$f.tries" 2>/dev/null || echo 0) + 1 )); echo "$tries" > "$f.tries"
        [ "$tries" -ge 20 ] && { mv "$f" "$inbox/failed/"; rm -f "$f.tries"; echo "[openclaw] gave up on a queued prompt ($(basename "$f"))"; }
        break
      fi
    done
    sleep 3
  done
}

# Transcripts every ~60 s (one gateway read per pass).
transcript_loop() {
  while true; do sleep 60; /usr/local/bin/openclaw-transcript "$WD" 2>> "$LOG/transcript.err"; done
}

# One-shot: done = idle, after a turn that started later than the prompt, for 60 s straight.
one_shot_watch() {
  [ "${SESSION_ONE_SHOT:-}" = "1" ] || return 0
  local marker="$STATE/.one-shot-done" sent="$STATE/.first-prompt-sent" sent_ms idle_since=0 st ts now
  [ -e "$marker" ] && return 0
  while [ ! -e "$sent" ]; do sleep 5; done
  sent_ms=$(( $(stat -c %Y "$sent") * 1000 ))
  while true; do
    sleep 3
    read -r st ts < <(python3 -c 'import json,os;d=json.load(open(os.path.expanduser("~/.claude/sessions/openclaw.json")));print(d.get("status",""),int(d.get("statusUpdatedAt") or 0))' 2>/dev/null) || { idle_since=0; continue; }
    now=$(date +%s)
    if [ "$st" = idle ] && [ "${ts:-0}" -gt "$sent_ms" ]; then
      [ "$idle_since" = 0 ] && idle_since=$now
      if [ $((now - idle_since)) -ge 60 ]; then
        /usr/local/bin/openclaw-transcript "$WD" 2>/dev/null
        printf 'done %s idle=60s bg=0\n' "$(date -u +%FT%TZ)" > "$marker"
        rm -f "$STATE/sessions/openclaw.json"
        echo "[one-shot] done; waiting for Jarvis to archive + destroy this machine"
        return 0
      fi
    else idle_since=0; fi
  done
}

# The Terminal panel: OpenClaw's own TUI on the main session.
tmux_pane() {
  tmux kill-session -t "$SESSION" 2>/dev/null || true
  tmux new-session -d -s "$SESSION" -x 120 -y 40 -c "$WD" \
    "export PATH=$PATH OPENCLAW_STATE_DIR=$OPENCLAW_STATE_DIR; while true; do if curl -s -o /dev/null -m 3 http://127.0.0.1:$PORT/; then openclaw tui; else clear; echo 'claw-code ($MODEL) in OpenClaw — gateway starting…'; echo 'Control UI: https://$WEB_HOST/   ·   iPhone: the OpenClaw app lists this session'; fi; sleep 5; done"
}

write_config
echo "[openclaw] harness up in $WD (model: $MODEL, perm: $(perm_mode), name: ${SESSION_LABEL:-auto})"
run_proxy
run_gateway &
run_tunnel
tmux_pane
send_first_prompt &
inbox_loop &
one_shot_watch &
transcript_loop &
# An in-place permission-mode switch (set-permission-mode kills the tmux session): restart the gateway
# (run_gateway rewrites the config before it starts again) and bring the pane back; then keep the machine
# alive for as long as Jarvis wants it.
while true; do
  if ! tmux has-session -t "$SESSION" 2>/dev/null && [ ! -e "$STATE/.one-shot-done" ]; then
    echo "[openclaw] terminal pane gone (permission-mode switch?); reloading"
    kill "$(cat "$LOG/gateway.pid" 2>/dev/null)" 2>/dev/null; tmux_pane
  fi
  sleep 5
done
