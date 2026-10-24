#!/bin/bash
# harness-claude.sh: the Claude harness's launcher (the entrypoint execs it). It is NOT the supervisor: that is
# jarvis-machine's (machine/supervisor.go), which talks to the router, under the keeper (machine/keeper.go), Fly's
# main child, which starts this launcher and starts it again if it ever ends. This one only
# keeps a `claude --remote-control` host alive in a tmux session.
# tmux lets the Claude app spawn extra sessions inside this same container/env.
set -u
WD="${1:-$HOME/workspace}"
SESSION=claude
export PATH="$HOME/.local/bin:/usr/local/bin:/usr/bin:/bin"
export HOME=/home/claude

# the session's secrets are already in this env (boot took them from the supervisor; RAM only), so claude and
# every Bash tool it spawns have them

# Another harness than the Claude-app host: its own launcher. opencode = an OpenRouter model
# under OpenCode + Paseo; paseo-claude = Claude Code driven by Paseo (the Paseo app + web UI);
# openclaw = claw-code as the agent loop inside an OpenClaw gateway.
[ "${SESSION_HARNESS:-claude}" = "opencode" ] && exec /usr/local/bin/harness-opencode.sh "$WD"
[ "${SESSION_HARNESS:-claude}" = "paseo-claude" ] && exec /usr/local/bin/harness-paseo-claude.sh "$WD"
[ "${SESSION_HARNESS:-claude}" = "openclaw" ] && exec /usr/local/bin/harness-openclaw.sh "$WD"

# Pre-accept two interactive dialogs that would otherwise block the tmux-TTY remote-control
# host forever (a blocked host never writes its session registry, so the dashboard shows
# "booting…" indefinitely, no bridge session appears in the app, and the first prompt is
# never sent):
#   1. the per-folder "Do you trust the files in this folder?" prompt, and
#   2. the "WARNING: Claude Code running in Bypass Permissions mode … Yes, I accept" dialog
#      that `--dangerously-skip-permissions` shows on a TTY. In cli 2.1.270 that dialog is
#      gated by `skipDangerousModePermissionPrompt` in ~/.claude/settings.json (the key the
#      dialog itself writes on "Yes, I accept"); the legacy ~/.claude.json
#      `bypassPermissionsModeAccepted` flag does NOT suppress it.
trust_dirs() {
  python3 - "$WD" <<'PY'
import json,os,sys
wd=sys.argv[1]; p=os.path.expanduser("~/.claude.json")
try: d=json.load(open(p))
except Exception: d={}
proj=d.setdefault("projects",{})
for path in {wd, os.path.expanduser("~/workspace"), os.path.expanduser("~")}:
    e=proj.setdefault(path,{})
    e["hasTrustDialogAccepted"]=True
    e["hasCompletedProjectOnboarding"]=True
    e.setdefault("allowedTools",[])
json.dump(d,open(p,"w"))
# Pre-accept the bypass-permissions warning via the settings key the CLI actually checks, and
# make every launch a Remote Control one (remoteControlAtStartup: "Start Remote Control bridge
# automatically each session"), so a host started by any path — fresh, resume, watchdog
# restart — has the bridge on even if a launch form ever drops the flag.
sp=os.path.expanduser("~/.claude/settings.json")
try: s=json.load(open(sp))
except Exception: s={}
s["skipDangerousModePermissionPrompt"]=True
s["remoteControlAtStartup"]=True
os.makedirs(os.path.dirname(sp),exist_ok=True)
json.dump(s,open(sp,"w"))
PY
}

start() {
  trust_dirs
  tmux kill-session -t "$SESSION" 2>/dev/null || true
  # Name the Remote Control session after Jarvis's label so the Claude app shows the
  # same name as the dashboard (instead of the auto "<hostname>-random-words").
  # SESSION_LABEL is in the machine env; the inner shell expands it (single quotes here).
  export SESSION_LABEL="${SESSION_LABEL:-}"
  # Model: default to Opus 5.5 (overridable via the machine env).
  export SESSION_MODEL="${SESSION_MODEL:-claude-opus-5-5}"
  # Permission mode: "auto" (default classifier auto-approve) or "bypass"
  # (--dangerously-skip-permissions). Defaults to auto.
  # ASSERT the mode explicitly on EVERY launch, including --resume. Passing nothing for
  # auto let a resumed/restored session inherit a persisted bypass state from ~/.claude.json
  # (a Started/Restored auto session came up in Bypass Permissions mode); an explicit
  # `--permission-mode auto` overrides whatever was remembered, so the launched mode always
  # matches SESSION_PERMISSION_MODE. Bypass keeps --dangerously-skip-permissions (whose
  # TTY warning is pre-accepted via skipDangerousModePermissionPrompt above).
  # Effective mode: an in-place override file (written by /usr/local/bin/set-permission-mode) wins
  # over the boot env var. That is how Jarvis switches auto<->bypass on a RUNNING machine
  # WITHOUT a Fly restart: it drops the file + kills the claude tmux session, and the watchdog
  # below relaunches here in the new mode — so /tmp, tunnels, browser logins and background jobs
  # all survive. A real machine restart (pause/wake) wipes the file, but wakeMachine re-asserts
  # SESSION_PERMISSION_MODE from the persisted metadata, so the mode is still right after a wake.
  SESSION_PERMISSION_MODE="$(cat "$HOME/.claude/.permission-mode" 2>/dev/null || printf '%s' "${SESSION_PERMISSION_MODE:-auto}")"
  case "$SESSION_PERMISSION_MODE" in
    bypass) SESSION_PERMISSION_MODE=bypass; export SESSION_PERM_FLAG="--dangerously-skip-permissions" ;;
    *)      SESSION_PERMISSION_MODE=auto;   export SESSION_PERM_FLAG="--permission-mode auto" ;;
  esac
  export SESSION_PERMISSION_MODE
  # Resume the conversation if there is a transcript on disk: on a pause/Start wake the
  # entrypoint restored the pause snapshot into ~/.claude/projects/ (a Fly stop wipes the rootfs,
  # so that is the only way one gets here), and on a host-crash restart of the claude process the
  # transcript is simply still there. Newest CONVERSATION wins: a transcript the pre-2026-09-22
  # jarvis's peer-message relay left (`claude -p` "You are a delivery relay…", carried along by
  # old snapshots) is plumbing, never the thing to resume — it was, once (lessons/60). Nothing on
  # disk -> fresh session. All ids are uuids, so the unquoted expansions below are safe.
  export SESSION_RESUME_FLAG=""
  local rid="" latest="" f
  for f in $(ls -t "$HOME"/.claude/projects/*/*.jsonl 2>/dev/null); do
    if head -c 4000 "$f" | grep -q 'You are a delivery relay'; then echo "[harness-claude] skipping relay transcript $(basename "$f")"; continue; fi
    latest="$f"; break
  done
  [ -n "$latest" ] && rid="$(basename "$latest" .jsonl)"
  [ -n "$rid" ] && export SESSION_RESUME_FLAG="--resume $rid"
  # --remote-control on EVERY launch form, resume included. With a resumed transcript the CLI
  # reads the bridge session it recorded there ({"type":"bridge-session",...}) and REATTACHES to
  # it — same entry in the Claude app, same claude.ai/code/session_… id (verified 2026-09-15 with
  # --debug-file: "[bridge:repl] Reattaching to persisted bridge session cse_… (fresh-mint
  # fallback, restored_owner_match)" → "[remote-bridge] Reattaching to session cse_…", ~10 h
  # after the pause). Only if the server no longer holds that session does it mint a fresh one
  # (a new app entry with the conversation intact) — still Remote Control, never off. What DOES
  # leave Remote Control off on a resume is dead OAuth credentials ("Remote Control requires a
  # claude.ai subscription … --rc flag ignored", TUI "Not logged in"): Jarvis injects the
  # current pair into the machine env on every Start (wakeMachine in jarvis/server.js).
  # --remote-control <name> names it in the Claude app; --name sets the local display name (the
  # session registry the dashboard reads), so both start identical. No label => let the Claude
  # session auto-generate (and later refine) its own title.
  # Resuming WITHOUT a label: name the Remote Control entry after the title the Claude app showed
  # at pause (SESSION_RESUME_TITLE, from Jarvis's record), else the transcript's last title.
  # When the old entry can't be reattached — expired after a long pause, or owned by the account
  # used before an account switch — the CLI mints a fresh one, and unnamed the app titles it after the first
  # new message (the Start prompt): the conversation "lost" its title. Only --remote-control is
  # named, not --name, so the local title stays auto (and the app can still refine it).
  export SESSION_RC_TITLE=""
  if [ -z "$SESSION_LABEL" ] && [ -n "$rid" ]; then
    SESSION_RC_TITLE="${SESSION_RESUME_TITLE:-}"
    [ -n "$SESSION_RC_TITLE" ] || SESSION_RC_TITLE="$(python3 - "$latest" <<'PY' 2>/dev/null
import json, sys
t = ""
for line in open(sys.argv[1], encoding="utf-8", errors="replace"):
    if '"custom-title"' not in line and '"ai-title"' not in line: continue
    try: d = json.loads(line)
    except Exception: continue
    t = d.get("customTitle") or d.get("aiTitle") or t
print(t.replace("\n", " ")[:200])
PY
)"
  fi
  if [ -n "$SESSION_LABEL" ]; then
    CMD='claude --remote-control "$SESSION_LABEL" --name "$SESSION_LABEL" --model "$SESSION_MODEL" $SESSION_PERM_FLAG $SESSION_RESUME_FLAG'
  elif [ -n "$SESSION_RC_TITLE" ]; then
    CMD='claude --remote-control "$SESSION_RC_TITLE" --model "$SESSION_MODEL" $SESSION_PERM_FLAG $SESSION_RESUME_FLAG'
  else
    CMD='claude --remote-control --model "$SESSION_MODEL" $SESSION_PERM_FLAG $SESSION_RESUME_FLAG'
  fi
  # fixed 120x40 window: the dashboard's terminal panel mirrors this pane (tmux capture-pane)
  # through the API proxy when it is on (explicit, in case the tmux server predates the export)
  [ -n "${ANTHROPIC_BASE_URL:-}" ] && CMD="ANTHROPIC_BASE_URL=$ANTHROPIC_BASE_URL $CMD"
  # The Jarvis channel (session-image/bin/jarvis-channel): how Jarvis's own messages reach claude, since Claude Code
  # refuses every cross-session peer message here (/etc/claude-code/managed-settings.json). It is a local channel
  # server, so it loads with --dangerously-load-development-channels, whose warning is confirmed below.
  local chan=0
  if [ -f /etc/claude-code/jarvis-channel.json ]; then
    chan=1
    CMD="$CMD --mcp-config /etc/claude-code/jarvis-channel.json --dangerously-load-development-channels server:jarvis"
  fi
  tmux new-session -d -s "$SESSION" -x 120 -y 40 -c "$WD" "$CMD"
  # confirm the development-channels warning ("1. I am using this for local development" is preselected) before
  # anything else types into the pane (the first prompt waits for /rc active, which comes after it)
  if [ "$chan" = 1 ]; then
    local i pane
    for i in $(seq 1 60); do
      pane="$(tmux capture-pane -p -t "$SESSION" 2>/dev/null)"
      if grep -q 'Loading development channels' <<< "$pane"; then
        tmux send-keys -t "$SESSION" Enter; echo "[harness-claude] confirmed the Jarvis channel"; break
      fi
      grep -Eq 'remote-control is active|/rc active' <<< "$pane" && break
      sleep 1
    done
  fi
  echo "[harness-claude] started remote-control host in $WD (name: ${SESSION_LABEL:-${SESSION_RC_TITLE:-auto}}, model: $SESSION_MODEL, perm: ${SESSION_PERMISSION_MODE:-auto}, resume: ${rid:-none})"
}

# First prompt (optional, SESSION_PROMPT from the machine env): once the remote-control host
# is up, type it into the input and press Enter, so the session starts working immediately.
# TYPED as literal keystrokes (`send-keys -l`), with Ctrl+J for the newlines so a multi-line
# prompt stays one message instead of submitting at the first newline — NOT pasted: the CLI
# (2.1.278+) wraps a bracketed paste in <pasted_content> tags and the model then treats the
# prompt as pasted data, not as the user's instruction (verified). Exactly once per
# machine (marker file), so a host restart or a machine reboot never re-sends it.
# NOTE: `claude --remote-control … "<prompt>"` (the positional prompt) is silently ignored
# by the CLI in remote-control mode (verified 2.1.270) — hence the keystrokes.
# Attachments (SESSION_ATTACHMENTS_JSON, optional): photos/files the user picked in the New
# Session form, staged on the Storage Box (see jarvis/lib/uploads.js). Download them into
# ~/uploads and build the two buffers that reproduce a "drop a file in the chat":
#  - a TEXT buffer (typed): the prose prompt + the paths of any non-image files (Claude reads
#    those); and
#  - an IMAGE buffer (pasted): the bare paths of the image files, which the TUI turns into inline
#    [Image #N] attachments (verified: a paste consisting only of image paths attaches them).
# Writes the text buffer to $1 and the image buffer to $2. Also deletes the staging dir. Reads
# creds from the SESSION_ATTACH_* env; never echoes them.
prepare_attachments() { /usr/local/bin/session-attachments "$1" "$2"; }

# Type the file $1 into the host's input box as literal keystrokes: line by line, Ctrl+J between
# lines (a newline in the box; Enter would submit), tabs as spaces (Tab triggers completion).
type_text() {
  local line first=1
  while IFS= read -r line || [ -n "$line" ]; do
    [ -n "$first" ] || tmux send-keys -t "$SESSION" C-j || return 1
    first=
    [ -z "$line" ] || tmux send-keys -t "$SESSION" -l -- "${line//$'\t'/  }" || return 1
  done < "$1"
}

send_first_prompt() {
  local marker="$HOME/.claude/.first-prompt-sent" f="$HOME/.claude/first-prompt.txt" imgf="$HOME/.claude/first-prompt-images.txt" i ready=0
  [ -n "${SESSION_PROMPT:-}" ] || [ -n "${SESSION_ATTACHMENTS_JSON:-}" ] || return 0
  [ -e "$marker" ] && return 0
  for i in $(seq 1 90); do   # up to ~3 min for the host to come up
    if tmux capture-pane -p -t "$SESSION" 2>/dev/null | grep -Eq 'remote-control is active|/rc active'; then ready=1; break; fi
    sleep 2
  done
  [ "$ready" = 1 ] || { echo "[harness-claude] first prompt NOT sent: host never became ready"; return 0; }
  sleep 3   # let the input box settle
  # Build the text + image buffers (attachments need a downloaded copy first; the plain case is
  # just the prose).
  if [ -n "${SESSION_ATTACHMENTS_JSON:-}" ]; then
    (umask 077; prepare_attachments "$f" "$imgf")
  else
    (umask 077; printf '%s' "$SESSION_PROMPT" > "$f"); : > "$imgf"
  fi
  # Type the text, then paste the image paths (a paste of only image paths becomes [Image #N]), Enter.
  local ok=1
  if [ -s "$f" ]; then type_text "$f" && sleep 1 || ok=0; fi
  if [ -s "$imgf" ]; then [ -s "$f" ] && tmux send-keys -t "$SESSION" C-j; tmux load-buffer -b firstpromptimg "$imgf" && tmux paste-buffer -p -d -b firstpromptimg -t "$SESSION" && sleep 1 || ok=0; fi
  if [ "$ok" = 1 ] && { [ -s "$f" ] || [ -s "$imgf" ]; }; then
    tmux send-keys -t "$SESSION" Enter
    touch "$marker"
    echo "[harness-claude] first prompt sent (text $(wc -c < "$f" 2>/dev/null || echo 0) bytes$([ -s "$imgf" ] && echo ", +images"))"
    return 0
  fi
  echo "[harness-claude] first prompt NOT sent (nothing to type or typing failed)"
}

# One-shot session (SESSION_ONE_SHOT=1 from the machine env): the first prompt is the whole
# job. Once it has been pasted, watch claude's own session registry (~/.claude/sessions/<pid>.json,
# the same file the dashboard reads) and treat the job as DONE when the host is idle with a
# status change (statusUpdatedAt) LATER than the moment the prompt was sent — i.e. a turn ran
# and ended — and stays idle for a sustained stretch: 60 s with no background jobs, or 15 min
# when background jobs (child shells of the claude pid) are still around, since a finishing
# background job re-wakes claude (a `run_in_background` Bash re-invokes it on exit). The
# timestamp, not "was busy seen", is the evidence: a short job's busy window (a few seconds)
# can fall entirely between two polls (hit on the first e2e test — a 7 s job never looked busy
# to a 10 s poll). "waiting" (a question/permission prompt for Deyao) is NOT done: the session
# stays up so he can answer it from the app; it finishes once the answer's turn ends. Then claude is told to exit (/exit, then
# the tmux session is killed if it lingers) and the marker ~/.claude/.one-shot-done is written.
# The JARVIS does the rest: its one-shot loop sees the marker via the registry exec, archives
# the transcript + ~/artifacts to the Storage Box, and destroys the machine (force: even with
# uncommitted/unpushed work — it DMs Deyao on Discord when that was the case). This launcher
# therefore stays up after claude exits (the watchdog below does not relaunch
# once the marker exists); nothing here talks to Jarvis.
ONE_SHOT_IDLE_S=60
ONE_SHOT_IDLE_BG_S=900
one_shot_status() {  # prints "<status> <pid> <statusUpdatedAt ms>" for the remote-control host, or nothing
  python3 - <<'PY'
import glob,json,os
es=[]
for f in glob.glob(os.path.expanduser("~/.claude/sessions/*.json")):
    try: es.append(json.load(open(f)))
    except Exception: pass
es.sort(key=lambda e: e.get("startedAt") or 0)
h=next((e for e in es if e.get("bridgeSessionId")), es[0] if es else None)
if h: print(h.get("status",""), h.get("pid",""), int(h.get("statusUpdatedAt") or h.get("updatedAt") or 0))
PY
}
one_shot_watch() {
  local marker="$HOME/.claude/.one-shot-done" sent="$HOME/.claude/.first-prompt-sent"
  local sent_ms idle_since=0 st pid ts bg now need
  [ "${SESSION_ONE_SHOT:-}" = "1" ] || return 0
  [ -e "$marker" ] && return 0
  while [ ! -e "$sent" ]; do sleep 5; done
  # the marker is touched right after Enter; a turn that ends after this moment is the job
  sent_ms=$(( $(stat -c %Y "$sent") * 1000 ))
  echo "[one-shot] prompt sent; watching for completion"
  while true; do
    sleep 3
    st=""; pid=""; ts=0
    read -r st pid ts < <(one_shot_status) || true
    now=$(date +%s)
    case "$st" in
      idle|shell)  # "shell" = claude's status for idle with background shells still running
        # idle from before the prompt (or re-written without a turn): not done yet
        [ "${ts:-0}" -gt "$sent_ms" ] || { idle_since=0; continue; }
        [ "$idle_since" = 0 ] && idle_since=$now
        bg=$(pgrep -c -P "${pid:-0}" -f shell-snapshots 2>/dev/null || echo 0)
        [ "$st" = shell ] && [ "${bg:-0}" -lt 1 ] && bg=1
        need=$ONE_SHOT_IDLE_S; [ "${bg:-0}" -gt 0 ] && need=$ONE_SHOT_IDLE_BG_S
        if [ $((now - idle_since)) -ge "$need" ]; then
          echo "[one-shot] done (idle ${need}s, background jobs: ${bg:-0}); exiting claude"
          printf 'done %s idle=%ss bg=%s\n' "$(date -u +%FT%TZ)" "$need" "${bg:-0}" > "$marker"
          tmux send-keys -t "$SESSION" Escape 2>/dev/null; sleep 1
          tmux send-keys -t "$SESSION" -l -- '/exit' 2>/dev/null; sleep 1
          tmux send-keys -t "$SESSION" Enter 2>/dev/null
          for _ in $(seq 1 15); do pgrep -u "$(id -u)" -f 'claude .*--model' >/dev/null 2>&1 || break; sleep 1; done
          tmux kill-session -t "$SESSION" 2>/dev/null || true
          echo "[one-shot] claude exited; waiting for Jarvis to archive + destroy this machine"
          return 0
        fi ;;
      *) idle_since=0 ;;   # busy / waiting (needs Deyao) / unknown: not done, not counting
    esac
  done
}

# API proxy (SESSION_API_PROXY=1, Jarvis's per-session "API proxy" option, default on): a transparent
# local proxy logs every API request/response into ~/artifacts/api-log (api-proxy.js), and claude
# reaches the API through it (ANTHROPIC_BASE_URL, inherited by everything claude starts). Kept alive
# by this loop; without the option nothing here runs and claude talks to the API directly.
if [ "${SESSION_API_PROXY:-}" = 1 ]; then
  export API_PROXY_PORT="${API_PROXY_PORT:-8788}"
  ( while true; do node /usr/local/lib/api-proxy.js >> "$HOME/.claude/api-proxy.log" 2>&1
      echo "[harness-claude] api-proxy exited; restarting in 1 s" >> "$HOME/.claude/api-proxy.log"; sleep 1; done ) &
  for _ in $(seq 1 40); do curl -s -o /dev/null "http://127.0.0.1:$API_PROXY_PORT/" && break; sleep 0.25; done
  export ANTHROPIC_BASE_URL="http://127.0.0.1:$API_PROXY_PORT"
  echo "[harness-claude] api proxy on 127.0.0.1:$API_PROXY_PORT (log: ~/artifacts/api-log)"
fi
# A restart by the keeper (JARVIS_HARNESS_START > 1: this launcher died, the machine didn't): a Claude host still
# running in tmux is kept as it is (its turn goes on); only a dead one is started again, resuming the newest
# conversation as a reboot would.
if [ "${JARVIS_HARNESS_START:-1}" -gt 1 ] 2>/dev/null && pgrep -u "$(id -u)" -f 'claude .*--model' >/dev/null 2>&1; then
  echo "[harness-claude] restart ${JARVIS_HARNESS_START}: the remote-control host is still running; keeping it"
else
  start
fi
send_first_prompt &
one_shot_watch &
# The Claude login (pushing a pair claude refreshed by itself, taking the router's) and the live transcript copy
# are jarvis-machine's (machine/claudelogin.go, the agent's live sync): nothing here.
while true; do
  # Liveness by a token present in every launch form (--model is always passed; the
  # launcher processes don't contain it).
  if [ -e "$HOME/.claude/.one-shot-done" ]; then :   # one-shot finished: claude stays down, Jarvis destroys the machine
  elif ! pgrep -u "$(id -u)" -f 'claude .*--model' >/dev/null 2>&1; then
    echo "[harness-claude] host gone; restarting"
    start
  fi
  sleep 5   # short poll so an in-place permission-mode switch (kills claude) relaunches promptly
done
