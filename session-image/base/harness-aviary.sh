#!/bin/bash
# Launcher for a session whose harness is aviary (SESSION_HARNESS=aviary), exec'd by harness-claude.sh in place of the
# `claude --remote-control` host: the session is an aviary sandbox (DE0CH/jarvis4 aviary/README.md).
#
#   Claude Code    the agent: the image's own claude, driven by DE0CH/aviary's supervisor (the same build YYC AI's
#                  sandboxes run), in the session's workspace with its CLAUDE.md, skills, settings and hooks (the
#                  descriptor's claude.projectSettings). Model = SESSION_MODEL ("aviary/<Claude model id>").
#   supervisor     supervisor-keeper as PID 1 of its own PID + mount namespace (aviary-sandbox, as root): ~/.claude is
#                  magpie's (FUSE), so the conversation lives in magpie and a resume picks it up from there.
#   aviary-gateway the machine's half of the sandbox gateway on 127.0.0.1:3128: boots the sandbox with hermit-jarvis
#                  (signed with the machine key), sends Claude's calls to Anthropic with the session's CURRENT Claude
#                  login (an account switch needs no restart), magpie/hermit to chat-gw.deyaochen.com.
#   front end      Jarvis 4's chat web app, https://chat.deyaochen.com (aviary's pigeon + magpie, DE0CH/services).
#
# Everything Jarvis reads from a session keeps the shape a Claude session has (see harness-opencode.sh):
#   ~/.claude/sessions/aviary.json     status shim: idle | busy from the supervisor's health (the gateway's /jarvis/state)
#   ~/.claude/projects/-home-claude-workspace/*.jsonl  a copy of the conversation's transcripts out of magpie, every
#                                      30 s, for live sync, snapshots, archives and transcript search
#   tmux session `claude`              the Terminal panel: the gateway's and the supervisor's logs
# Prompts are delivered with /usr/local/bin/harness-send (Jarvis execs it): the gateway's POST /jarvis/deliver, a turn
# of the conversation as Deyao (409 while a turn runs → 75, retried by the inbox loop).
set -u
WD="${1:-$HOME/workspace}"
SESSION=claude
export HOME=/home/claude
export PATH="$HOME/.local/bin:/usr/local/bin:/usr/bin:/bin"
# the session's secrets are already in this env (boot took them from the supervisor; RAM only)

STATE="$HOME/.claude"; mkdir -p "$STATE/sessions"
A="$HOME/.aviary"; mkdir -p "$A"; chmod 700 "$A"
BOOT="$A/boot.env"
MODEL="${SESSION_MODEL:-aviary/claude-opus-5-5}"
LABEL="${SESSION_LABEL:-}"
MACHINE="${SESSION_ID:-${FLY_MACHINE_ID:-$(hostname)}}"
GW=http://127.0.0.1:3128
MIRROR="$STATE/projects/-home-claude-workspace"
# the image's digest for the descriptor (Fly's FLY_IMAGE_REF names it), else a placeholder
IMAGE="sha256:$(printf '%064d' 0)"
case "${FLY_IMAGE_REF:-}" in *@sha256:*) IMAGE="sha256:${FLY_IMAGE_REF##*@sha256:}" ;; esac

gw_up() { curl -s -o /dev/null -m 3 --noproxy '*' "$GW/jarvis/state" 2>/dev/null; }

# A component's output: its file under ~/artifacts/aviary (the Terminal panel) and the machine's log (Fly → Grafana,
# `{box="fly"} |= "[aviary-gateway]"`); neither component logs a secret's value
logs() { tee -a "$A/$1.out" | sed -u "s/^/[aviary-$1] /"; }

# The machine's half of the gateway, in a restart loop (a restart keeps the sandbox: hermit knows the machine)
run_gateway() {
  [ -n "${AVIARY_GW_ACCESS_ID:-}" ] && [ -n "${AVIARY_GW_ACCESS_SECRET:-}" ] || {
    echo "[aviary] no AVIARY_GW_ACCESS_* in the secrets (store aviary): the gateway cannot start"; return 1; }
  ( while true; do
      env POD_NAME="$MACHINE" AVIARY_GW_URL="${AVIARY_GW_URL:-https://chat-gw.deyaochen.com}" AVIARY_BOOT_FILE="$BOOT" AVIARY_IMAGE="$IMAGE" \
        SESSION_MODEL="$MODEL" /usr/local/bin/aviary-gateway
      echo "[aviary] gateway exited ($?); restarting in 2 s"; sleep 2
    done ) 2>&1 | logs gateway &
}

# The supervisor, in a restart loop (its keeper restarts the supervisor itself; this restarts the keeper)
run_supervisor() {
  # the boot can come late (chat-gw or hermit down, the gateway retrying): wait for it however long it takes
  local n=0
  until [ -s "$BOOT" ]; do
    n=$((n + 1)); [ "$n" = 120 ] && echo "[aviary] the sandbox has not booted after 2 min; still waiting (see $A/gateway.out)"
    sleep 1
  done
  [ "$n" -ge 120 ] && echo "[aviary] the sandbox booted"
  ( while [ ! -e "$STATE/.one-shot-done" ]; do
      sudo -n /usr/local/bin/aviary-sandbox "$BOOT"
      echo "[aviary] supervisor-keeper exited ($?); restarting in 3 s"; sleep 3
    done ) 2>&1 | logs supervisor &
}

keeper_pid() { pgrep -o -x supervisor-kee 2>/dev/null || pgrep -o -f '^/usr/local/bin/supervisor-keeper$' 2>/dev/null; }

# Status shim, from the supervisor's health as the gateway last read it (every 3 s)
shim_loop() {
  while true; do
    curl -s -m 3 --noproxy '*' "$GW/jarvis/state" 2>/dev/null | python3 -c '
import json, os, sys, time
machine, label = sys.argv[1], sys.argv[2]
try: s = json.load(sys.stdin)
except Exception: sys.exit(0)  # gateway not up (yet): no registry entry -> "booting…" on the dashboard
if not s.get("ready"): sys.exit(0)
path = os.path.expanduser("~/.claude/sessions/aviary.json")
try: prev = json.load(open(path))
except Exception: prev = {}
status = "busy" if s.get("busy") else "idle"
now = int(time.time() * 1000)
changed = prev.get("status") != status
entry = {"pid": os.getppid(), "sessionId": s.get("conversationId") or "aviary",
         "name": label or prev.get("name", ""), "nameSource": "harness", "harness": "aviary",
         "status": status, "statusUpdatedAt": now if changed else prev.get("statusUpdatedAt", now),
         "lastActivityMs": now if (changed and status == "busy") else prev.get("lastActivityMs", now),
         "startedAt": prev.get("startedAt", now), "bridgeSessionId": "aviary:" + machine}
if entry != prev:
    tmp = path + ".tmp"; json.dump(entry, open(tmp, "w")); os.replace(tmp, path)
' "$MACHINE" "$LABEL"
    sleep 3
  done
}

# The conversation's transcripts out of magpie's FUSE (visible in the supervisor's mount namespace only) into the
# place Jarvis reads a Claude session's from, every 30 s, as the agent's user (the FUSE mount is its)
mirror_loop() {
  mkdir -p "$MIRROR"
  while true; do
    sleep 30
    pid="$(keeper_pid)"; [ -n "$pid" ] || continue
    sudo -n nsenter --target "$pid" --mount --setuid 1000 --setgid 1000 \
      sh -c 'src=/home/sandbox/.claude/projects/-workspace; [ -d "$src" ] || exit 0
             for f in "$src"/*.jsonl; do [ -f "$f" ] || continue; d="$1/$(basename "$f")"
               if [ ! -f "$d" ] || [ "$f" -nt "$d" ]; then cp "$f" "$d.tmp" && mv "$d.tmp" "$d"; fi; done' \
      _ "$MIRROR" 2>> "$A/mirror.err" || true
  done
}

# First prompt (+ attachments), once per machine, same marker as the claude path
send_first_prompt() {
  local marker="$STATE/.first-prompt-sent" f="$STATE/first-prompt.txt" imgf="$STATE/first-prompt-images.txt"
  [ -n "${SESSION_PROMPT:-}" ] || [ -n "${SESSION_ATTACHMENTS_JSON:-}" ] || return 0
  [ -e "$marker" ] && return 0
  # wait for the supervisor however long the boot takes (the same reasons as run_supervisor)
  until curl -s -m 3 --noproxy '*' "$GW/jarvis/state" 2>/dev/null | grep -q '"ready":true'; do sleep 2; done
  if [ -n "${SESSION_ATTACHMENTS_JSON:-}" ]; then
    (umask 077; /usr/local/bin/session-attachments "$f" "$imgf")
  else
    (umask 077; printf '%s' "$SESSION_PROMPT" > "$f"); : > "$imgf"
  fi
  [ -s "$f" ] || [ -s "$imgf" ] || { echo "[aviary] first prompt NOT sent (nothing to send)"; return 0; }
  [ -s "$f" ] || printf 'See the attached image(s).' > "$f"
  # retried until it lands: HARNESS_SEND_ID makes a repeat the same turn (magpie's idempotency key)
  local tries=0
  until HARNESS_SEND_ID="first-prompt-$MACHINE" /usr/local/bin/harness-send --images "$imgf" < "$f" >> "$A/inbox.out" 2>&1; do
    tries=$((tries + 1)); [ "$tries" = 30 ] && echo "[aviary] first prompt not sent after 30 tries; still trying (see $A/inbox.out)"
    sleep 10
  done
  touch "$marker"; echo "[aviary] first prompt sent ($(wc -c < "$f") bytes)"
}

# Prompts Jarvis queued with `harness-send --queue`: oldest first, each once the conversation is idle (75 = busy, not a
# failed try), retried, set aside after 20 failed tries (as harness-paseo-claude.sh)
inbox_loop() {
  local inbox="$STATE/harness-inbox" f tries rc
  mkdir -p "$inbox/failed"
  while true; do
    for f in "$inbox"/*.txt; do
      [ -f "$f" ] || continue
      HARNESS_SEND_ID="$(basename "$f" .txt)" /usr/local/bin/harness-send < "$f" > /dev/null 2>> "$A/inbox.err"; rc=$?
      if [ "$rc" = 0 ]; then
        rm -f "$f" "$f.tries"; echo "[aviary] delivered a queued prompt ($(basename "$f"))"
      elif [ "$rc" = 75 ]; then
        break
      else
        tries=$(( $(cat "$f.tries" 2>/dev/null || echo 0) + 1 )); echo "$tries" > "$f.tries"
        [ "$tries" -ge 20 ] && { mv "$f" "$inbox/failed/"; rm -f "$f.tries"; echo "[aviary] gave up on a queued prompt ($(basename "$f"))"; }
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
    read -r st ts < <(python3 -c 'import json,os;d=json.load(open(os.path.expanduser("~/.claude/sessions/aviary.json")));print(d.get("status",""),int(d.get("statusUpdatedAt") or 0))' 2>/dev/null) || { idle_since=0; continue; }
    now=$(date +%s)
    if [ "$st" = idle ] && [ "${ts:-0}" -gt "$sent_ms" ]; then
      [ "$idle_since" = 0 ] && idle_since=$now
      if [ $((now - idle_since)) -ge 60 ]; then
        printf 'done %s idle=60s bg=0\n' "$(date -u +%FT%TZ)" > "$marker"
        rm -f "$STATE/sessions/aviary.json"
        echo "[one-shot] done; waiting for Jarvis to archive + destroy this machine"
        return 0
      fi
    else idle_since=0; fi
  done
}

# The Terminal panel: the gateway's and the supervisor's logs
tmux_pane() {
  tmux kill-session -t "$SESSION" 2>/dev/null || true
  tmux new-session -d -s "$SESSION" -x 120 -y 40 -c "$WD" \
    "echo 'Claude Code (${MODEL#aviary/}) under the aviary supervisor — https://chat.deyaochen.com'; tail -n 200 -F $A/gateway.out $A/supervisor.out"
}

echo "[aviary] harness up in $WD (model: $MODEL, name: ${LABEL:-auto})"
run_gateway
run_supervisor &
tmux_pane
send_first_prompt &
inbox_loop &
one_shot_watch &
shim_loop &
mirror_loop &
while true; do
  if ! tmux has-session -t "$SESSION" 2>/dev/null && [ ! -e "$STATE/.one-shot-done" ]; then
    tmux_pane
  fi
  sleep 5
done
