#!/bin/bash
# Supervisor for a session whose harness is OpenCode on OpenRouter (SESSION_HARNESS=opencode),
# exec'd by harness-claude.sh in place of the `claude --remote-control` host.
#
#   OpenCode      the agent loop; LLM = OpenRouter, model = SESSION_MODEL ("openrouter/<slug>"),
#                 key = OPENROUTER_API from the session's secrets.
#   Paseo daemon  drives OpenCode and is the remote control: its iPhone/desktop app pairs over
#                 Paseo's end-to-end-encrypted relay (the pairing link is on the dashboard card),
#                 and its web UI is published behind Cloudflare Access through the cf-tunnel on
#                 the session's own origin https://<session id>-s.deyaochen.com/ (paseo-front.js
#                 presents that public host to the daemon).
#
# Everything the JARVIS reads from a session is kept in the shape a Claude session has, so the
# dashboard, auto-pause, attention DMs, the stall watchdog, one-shot, the pause snapshot, the
# Destroy archive and the transcript search need no second code path:
#   ~/.claude/sessions/<pid>.json       status shim: idle | busy | waiting (from `paseo ls`)
#   ~/.claude/projects/<slug>/*.jsonl   conversations (opencode-transcript.py)
#   tmux session `claude`               what the dashboard's Terminal panel mirrors
#   ~/.claude/.first-prompt-sent, .one-shot-done, .permission-mode   same markers
# Prompts are delivered with /usr/local/bin/harness-send (Jarvis execs it), not keystrokes.
set -u
WD="${1:-$HOME/workspace}"
SESSION=claude
export HOME=/home/claude
export PATH="$HOME/.local/bin:/usr/local/bin:/usr/bin:/bin"
# the session's secrets are already in this env (boot took them from the supervisor; RAM only)

export PASEO_HOME="$HOME/.paseo"
export OPENROUTER_API_KEY="${OPENROUTER_API_KEY:-${OPENROUTER_API:-}}"
# the SESSION id (stable across the machines a paused session is re-created on): the tunnel id,
# so the web-UI link survives a pause; a session's first machine has no SESSION_ID (its id is the session id)
MACHINE="${SESSION_ID:-${FLY_MACHINE_ID:-$(hostname)}}"
WEB_HOST="$MACHINE-s.deyaochen.com"   # the tunnel's own origin (cf-tunnel/worker.js)
STATE="$HOME/.claude"; mkdir -p "$STATE/sessions" "$PASEO_HOME" "$HOME/.config/opencode"
MODEL="${SESSION_MODEL:-openrouter/z-ai/glm-5.3}"
LABEL="${SESSION_LABEL:-}"
[ -n "$OPENROUTER_API_KEY" ] || echo "[opencode] WARN no OPENROUTER_API in this session's secret stores — the model calls will fail"

# Daemon settings by env (flags/env are launch overrides; config.json keeps its defaults).
# Voice/dictation off: they make the daemon download ~1 GB of speech models on first start.
export PASEO_RELAY_ENABLED=true PASEO_WEB_UI_ENABLED=true
export PASEO_DICTATION_ENABLED=false PASEO_VOICE_MODE_ENABLED=false
export PASEO_CORS_ORIGINS="https://app.paseo.sh,https://$WEB_HOST"
export PASEO_HOSTNAMES="$WEB_HOST,localhost,127.0.0.1"

perm_mode() { cat "$STATE/.permission-mode" 2>/dev/null || printf '%s' "${SESSION_PERMISSION_MODE:-auto}"; }

# OpenCode config: the model picked on the dashboard is the default everywhere (Paseo agents get
# it explicitly; this covers a plain `opencode` run in the terminal). Permission mode: "bypass"
# = allow everything; "auto" = OpenCode's own defaults (asks before leaving the working dir etc.
# — a pending ask shows as "waiting" on the dashboard and in the Paseo app).
# Project context: OpenCode loads CLAUDE.md but not the files it @imports, so
# opencode-instructions.py lists those as `instructions` (rebuilt on every write).
write_config() {
  python3 - "$MODEL" "$(perm_mode)" "$(/usr/local/bin/opencode-instructions.py "$WD" 2>/dev/null)" <<'PY'
import json, os, sys
model, perm = sys.argv[1], sys.argv[2]
p = os.path.expanduser("~/.config/opencode/opencode.json")
try: d = json.load(open(p))
except Exception: d = {}
try: ctx = json.loads(sys.argv[3])
except Exception: ctx = {}
d.pop("instructions", None)
d.update(ctx)
d["$schema"] = "https://opencode.ai/config.json"
d["model"] = model
d["autoupdate"] = False
d["share"] = "disabled"
if perm == "bypass": d["permission"] = "allow"
else: d.pop("permission", None)
json.dump(d, open(p, "w"), indent=1)
PY
}

daemon_up() { paseo daemon status 2>/dev/null | grep -q 'Connected Daemon *reachable'; }

# The daemon runs in the foreground of a restart loop (it dies -> it comes back; agents and
# their OpenCode sessions are on disk and reattach). Stops for good once a one-shot is done.
run_daemon() {
  while [ ! -e "$STATE/.one-shot-done" ]; do
    write_config
    paseo daemon start --foreground >> "$PASEO_HOME/daemon.out" 2>&1
    echo "[opencode] paseo daemon exited ($?); restarting"; sleep 3
  done
}

# The web UI behind Cloudflare Access: front proxy (public host for the UI's connection hint)
# + this session's own tunnel, id = the session id (what Jarvis keys sessions by).
run_tunnel() {
  [ -n "${CF_ACCESS_CLIENT_ID:-}" ] && [ -n "${CF_ACCESS_CLIENT_SECRET:-}" ] || { echo "[opencode] no CF_ACCESS_* in the secrets; web UI not published"; return 0; }
  ( while true; do PASEO_PUBLIC_HOST="$WEB_HOST:443" node /usr/local/lib/paseo-front.js; sleep 3; done ) >> "$PASEO_HOME/front.out" 2>&1 &
  ( while true; do TUNNEL_ID="$MACHINE" TUNNEL_TARGET="http://127.0.0.1:6768" node /usr/local/lib/cf-tunnel-agent.js; sleep 3; done ) >> "$PASEO_HOME/tunnel.out" 2>&1 &
  echo "[opencode] web UI: https://$WEB_HOST/"
}

# First prompt (+ attachments: images go in as --image, other files as paths in the text).
# Same once-per-machine marker as the claude path; a restored/resumed machine never re-sends.
send_first_prompt() {
  local marker="$STATE/.first-prompt-sent" f="$STATE/first-prompt.txt" imgf="$STATE/first-prompt-images.txt"
  [ -n "${SESSION_PROMPT:-}" ] || [ -n "${SESSION_ATTACHMENTS_JSON:-}" ] || return 0
  [ -e "$marker" ] && return 0
  for _ in $(seq 1 90); do daemon_up && break; sleep 2; done
  daemon_up || { echo "[opencode] first prompt NOT sent: daemon never came up"; return 0; }
  if [ -n "${SESSION_ATTACHMENTS_JSON:-}" ]; then
    (umask 077; /usr/local/bin/session-attachments "$f" "$imgf")
  else
    (umask 077; printf '%s' "$SESSION_PROMPT" > "$f"); : > "$imgf"
  fi
  [ -s "$f" ] || [ -s "$imgf" ] || { echo "[opencode] first prompt NOT sent (nothing to send)"; return 0; }
  [ -s "$f" ] || printf 'See the attached image(s).' > "$f"
  if /usr/local/bin/harness-send --images "$imgf" < "$f"; then
    touch "$marker"; echo "[opencode] first prompt sent ($(wc -c < "$f") bytes)"
  else
    echo "[opencode] first prompt NOT sent (paseo run failed)"
  fi
}

# Status shim + transcript export, one loop. The registry entry is the daemon's, shaped like
# claude's: status, pid, statusUpdatedAt (moves on every status change AND every new turn, the
# "had a turn" signal one-shot and the stall watchdog rely on), name = the main agent's title.
shim_loop() {
  local n=0
  while true; do
    python3 - "$MACHINE" "$LABEL" <<'PY'
# Reads Paseo's own agent files (the daemon keeps lastStatus / attentionReason current in
# ~/.paseo/agents/*/*.json) — NOT the paseo CLI: a CLI call is a ~200 MB node process that takes
# seconds on a shared vCPU, and polling with it starved a 2-vCPU machine (load 6, execs timing out).
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
name = next((a.get("title") for a in agents if a.get("id") == main and a.get("title")), "") or label
# newest user message across agents = "a turn started", even when two polls both see idle
last_user = max([ms(a.get("lastUserMessageAt")) for a in agents] or [0])
path = os.path.join(state, "sessions", "paseo.json")
try: prev = json.load(open(path))
except Exception: prev = {}
now = int(time.time() * 1000)
changed = prev.get("status") != status or prev.get("pid") != pid or last_user > (prev.get("lastActivityMs") or 0)
entry = {"pid": pid, "sessionId": main or "paseo", "name": name, "nameSource": "harness", "harness": "opencode",
         "status": status, "statusUpdatedAt": now if changed else prev.get("statusUpdatedAt", now),
         "lastActivityMs": max(last_user, prev.get("lastActivityMs") or 0),
         "startedAt": prev.get("startedAt") if prev.get("pid") == pid else now,
         "bridgeSessionId": "paseo:" + machine, "agents": len(agents)}
if entry != prev:
    tmp = path + ".tmp"; json.dump(entry, open(tmp, "w")); os.replace(tmp, path)
PY
    n=$((n+1))
    # transcripts every ~60 s (a no-op unless an agent file changed; an export is one `opencode` run)
    [ $((n % 12)) = 0 ] && python3 /usr/local/bin/opencode-transcript.py "$WD" 2>> "$PASEO_HOME/transcript.err"
    sleep 5
  done
}

# Prompts Jarvis queued with `harness-send --queue` (wakeups, watches, Deyao's
# resume prompt): deliver oldest first; a failed delivery stays for the next pass (the daemon may
# still be coming up), and is set aside after 20 tries so it cannot block the ones behind it.
inbox_loop() {
  local inbox="$STATE/harness-inbox" f tries
  mkdir -p "$inbox/failed"
  while true; do
    for f in "$inbox"/*.txt; do
      [ -f "$f" ] || continue
      if /usr/local/bin/harness-send < "$f" > /dev/null 2>> "$PASEO_HOME/inbox.err"; then
        rm -f "$f" "$f.tries"; echo "[opencode] delivered a queued prompt ($(basename "$f"))"
      else
        tries=$(( $(cat "$f.tries" 2>/dev/null || echo 0) + 1 )); echo "$tries" > "$f.tries"
        [ "$tries" -ge 20 ] && { mv "$f" "$inbox/failed/"; rm -f "$f.tries"; echo "[opencode] gave up on a queued prompt ($(basename "$f"))"; }
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
        python3 /usr/local/bin/opencode-transcript.py "$WD" 2>/dev/null
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
    "while true; do id=\$(cat $STATE/.paseo-agent 2>/dev/null); if [ -n \"\$id\" ]; then paseo logs -f \"\$id\"; else clear; echo 'OpenCode ($MODEL) via Paseo — no agent yet.'; echo 'Web UI: https://$WEB_HOST/   ·   iPhone: Pair from the dashboard card'; fi; sleep 5; done"
}

write_config
echo "[opencode] harness up in $WD (model: $MODEL, perm: $(perm_mode), name: ${LABEL:-auto})"
run_daemon &
run_tunnel
tmux_pane
send_first_prompt &
inbox_loop &
one_shot_watch &
shim_loop &
# An in-place permission-mode switch (set-permission-mode kills the tmux session): rewrite the
# OpenCode config and restart the daemon so its agents pick the new mode up; then keep the
# machine alive for as long as Jarvis wants it.
while true; do
  if ! tmux has-session -t "$SESSION" 2>/dev/null && [ ! -e "$STATE/.one-shot-done" ]; then
    echo "[opencode] terminal pane gone (permission-mode switch?); reloading"
    write_config; paseo daemon stop >/dev/null 2>&1 || true   # run_daemon brings it back
    tmux_pane
  fi
  sleep 5
done
