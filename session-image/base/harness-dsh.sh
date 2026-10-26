#!/bin/bash
# Supervisor for a session whose harness is DeepSeek Harness on OpenRouter (SESSION_HARNESS=dsh),
# exec'd by harness-claude.sh in place of the `claude --remote-control` host.
#
#   dsh web        Deyao's fork DE0CH/deepseek-harness, from the runtime bundle (dsh-runtime: Node + the fork,
#                  fetched on first use, pinned by sha256). The agent loop, its session logs and the web UI all run
#                  here; LLM = OpenRouter (OPENROUTER_API from the `openrouter` store), routed only to DeepSeek's own
#                  endpoint, model = SESSION_MODEL ("dsh/<OpenRouter slug>"). Home: ~/.dsh (in the pause snapshot).
#   dsh-front.js   the web UI's front (port 6770): what the cf-tunnel agent targets on the session's own origin
#                  https://<session id>-s.deyaochen.com/ (Cloudflare Access); it hands dsh's launch token to a page
#                  load Access already admitted. The persistent dsh UI (DE0CH/services) reaches sessions through it.
#   Instructions   the workspace CLAUDE.md with its @imports (dsh's agent-instructions, expandImports in the fork) and
#   and skills     the Claude Code skill roots (<workdir>/.claude/skills, ~/.claude/skills): dsh-profile-patch.py
#                  writes them into every agent preset at each boot, from this dsh version's own --dump-config.
#
# Everything the JARVIS reads from a session keeps the shape a Claude session has (as harness-opencode.sh):
#   ~/.claude/sessions/dsh.json         status shim: idle | busy | waiting (dsh's projection cache)
#   ~/.claude/projects/<slug>/*.jsonl   conversations (dsh-transcript.py)
#   tmux session `claude`               the Terminal panel: dsh web's log
# Prompts are delivered with /usr/local/bin/harness-send (Jarvis execs it) -> dsh-send.py: a prompt into the main
# conversation (~/.claude/.dsh-session, made by the first prompt).
set -u
WD="${1:-$HOME/workspace}"
SESSION=claude
export HOME=/home/claude
export PATH="$HOME/.local/bin:/usr/local/bin:/usr/bin:/bin"
# the session's secrets are already in this env (boot took them from the supervisor; RAM only)

MACHINE="${SESSION_ID:-${FLY_MACHINE_ID:-$(hostname)}}"
WEB_HOST="$MACHINE-s.deyaochen.com"   # the tunnel's own origin (cf-tunnel/worker.js)
STATE="$HOME/.claude"; mkdir -p "$STATE/sessions"
# a machine image before 2026-10-26 bind-mounted this file's path as a directory, and a snapshot may carry it
[ -d "$STATE/.dsh-session" ] && rmdir "$STATE/.dsh-session" 2>/dev/null && echo "[dsh] removed the empty directory left at ~/.claude/.dsh-session"
export DSH_HOME="$HOME/.dsh"; mkdir -p "$DSH_HOME"
RUN="$HOME/.dsh-run"; mkdir -p "$RUN"; chmod 700 "$RUN"
export DSH_PORT=3080 FRONT_PORT=6770
MODEL="${SESSION_MODEL:-dsh/deepseek/deepseek-v4-pro-0813}"; SLUG="${MODEL#dsh/}"
LABEL="${SESSION_LABEL:-}"
export OPENROUTER_API_KEY="${OPENROUTER_API_KEY:-${OPENROUTER_API:-}}"
unset DEEPSEEK_API_KEY   # only the OpenRouter route: dsh's own DeepSeek routes stay without a key
[ -n "$OPENROUTER_API_KEY" ] || echo "[dsh] WARN no OPENROUTER_API in this session's secret stores — the model calls will fail"
# the models this harness offers (router/harness.go): the picker shows both, SESSION_MODEL is the default
MODELS='[{"id":"deepseek/deepseek-v4-pro-0813","name":"DeepSeek V4 Pro"},{"id":"deepseek/deepseek-v4.1-flash-1017","name":"DeepSeek V4.1 Flash"}]'

RT=""
for i in 1 2 3 4 5; do RT="$(/usr/local/bin/dsh-runtime 2>> "$RUN/runtime.err")" && break; RT=""; sleep $((i * 5)); done
[ -n "$RT" ] || echo "[dsh] the runtime bundle could not be fetched (see $RUN/runtime.err)"
dsh() { "$RT/node/bin/node" "$RT/app/node_modules/@deepseek-ai/dsh/lib/bin.js" "$@"; }

# Jarvis's modes -> dsh's permission mode (DSH_PERMISSION_MODE: its sandbox-policy and approval rows read it when dsh
# web starts). bypass = danger-full-access, approval never; anything else = workspace-write, approval ask. A Fly
# machine has no usable sandbox backend, so under workspace-write every shell command asks to escalate and waits for
# an answer in the web UI (dsh-send connects with interactions=none and never answers).
perm_mode() { cat "$STATE/.permission-mode" 2>/dev/null || printf '%s' "${SESSION_PERMISSION_MODE:-auto}"; }
dsh_perm() { [ "$(perm_mode)" = bypass ] && echo danger-full-access || echo workspace-write; }

# The profile patch: generated from this dsh's own tree with the patch emptied first, so it always fits the version
write_profile() {
  local prof="$DSH_HOME/profiles/web"
  # dsh makes the profile from its template on first use; the patch must be a YAML list ([] = none)
  [ -f "$prof/package.json" ] || dsh --profile web --dump-config > /dev/null 2>> "$RUN/dump.err"
  mkdir -p "$prof"; printf '[]\n' > "$prof/cordis.patch.yml"
  dsh --profile web --dump-config > "$RUN/dump.yml" 2>> "$RUN/dump.err" || { echo "[dsh] dump-config failed: $(tail -n 1 "$RUN/dump.err" | cut -c1-300)"; return 1; }
  python3 /usr/local/bin/dsh-profile-patch.py "$RUN/dump.yml" "$MODELS" "$SLUG" "$WD/.claude/skills" "$HOME/.claude/skills" \
    > "$prof/cordis.patch.yml.tmp" && mv "$prof/cordis.patch.yml.tmp" "$prof/cordis.patch.yml"
}

# dsh web in the foreground of a restart loop; each start prints a fresh launch token, kept (0600) for the front
# and dsh-send.py. Stops for good once a one-shot is done.
run_dsh() {
  cd "$WD" || return 1
  local started rc
  while [ ! -e "$STATE/.one-shot-done" ]; do
    write_profile
    started=$(date +%s)
    DSH_PERMISSION_MODE="$(dsh_perm)" dsh --profile web --no-open --port "$DSH_PORT" --public-url "https://$WEB_HOST/" --trusted-host "$WEB_HOST" 2>&1 \
      | while IFS= read -r line; do
          case "$line" in
            *"dsh web:"*token=*) t="${line##*token=}"; t="${t%%[&[:space:]]*}"; (umask 077; printf '%s' "$t" > "$RUN/token.tmp") && mv "$RUN/token.tmp" "$RUN/token"
                                 echo "dsh web: up on 127.0.0.1:$DSH_PORT (token kept in $RUN/token)"
                                 echo "[dsh] dsh web is up on 127.0.0.1:$DSH_PORT" >&2 ;;
            *) printf '%s\n' "$line" ;;
          esac
        done >> "$RUN/web.out"
    rc=${PIPESTATUS[0]}
    # the supervisor log gets the exit and dsh's last line (keeper: tagged lines only, secrets redacted)
    echo "[dsh] dsh web exited (code $rc) after $(( $(date +%s) - started )) s; restarting in 3 s; its last line: $(grep -v '^\[dsh\]' "$RUN/web.out" | tail -n 1 | cut -c1-300)"
    echo "[dsh] dsh web exited; restarting in 3 s" >> "$RUN/web.out"; sleep 3
  done
}

dsh_up() { [ -s "$RUN/token" ] && curl -s -o /dev/null -m 3 "http://127.0.0.1:$DSH_PORT/" ; }

run_tunnel() {
  ( while true; do node /usr/local/lib/dsh-front.js; sleep 2; done ) >> "$RUN/front.out" 2>&1 &
  [ -n "${CF_ACCESS_CLIENT_ID:-}" ] && [ -n "${CF_ACCESS_CLIENT_SECRET:-}" ] || { echo "[dsh] no CF_ACCESS_* in the secrets; web UI not published"; return 0; }
  ( while true; do TUNNEL_ID="$MACHINE" TUNNEL_TARGET="http://127.0.0.1:$FRONT_PORT" node /usr/local/lib/cf-tunnel-agent.js; sleep 3; done ) >> "$RUN/tunnel.out" 2>&1 &
  echo "[dsh] web UI: https://$WEB_HOST/"
}

# First prompt (+ attachments: images as paths, other files as paths in the text); once per machine line.
send_first_prompt() {
  local marker="$STATE/.first-prompt-sent" f="$STATE/first-prompt.txt" imgf="$STATE/first-prompt-images.txt"
  [ -n "${SESSION_PROMPT:-}" ] || [ -n "${SESSION_ATTACHMENTS_JSON:-}" ] || return 0
  [ -e "$marker" ] && return 0
  for _ in $(seq 1 120); do dsh_up && break; sleep 2; done
  dsh_up || { echo "[dsh] first prompt NOT sent: dsh web never came up"; return 0; }
  if [ -n "${SESSION_ATTACHMENTS_JSON:-}" ]; then
    (umask 077; /usr/local/bin/session-attachments "$f" "$imgf")
  else
    (umask 077; printf '%s' "$SESSION_PROMPT" > "$f"); : > "$imgf"
  fi
  [ -s "$f" ] || [ -s "$imgf" ] || { echo "[dsh] first prompt NOT sent (nothing to send)"; return 0; }
  [ -s "$f" ] || printf 'See the attached image(s).' > "$f"
  if /usr/local/bin/harness-send --images "$imgf" < "$f"; then
    touch "$marker"; echo "[dsh] first prompt sent ($(wc -c < "$f") bytes)"
  else
    echo "[dsh] first prompt NOT sent (dsh-send failed)"
  fi
}

# Status shim + transcript export. busy = an open turn in any conversation; waiting = an open user question or a
# pending approval; statusUpdatedAt moves on every status change and every new turn (one-shot, the stall watchdog).
shim_loop() {
  local n=0 err last_err=""
  while true; do
    err=$(python3 - "$MACHINE" "$LABEL" "$MODEL" 2>&1 >/dev/null <<'PY'
import glob, json, os, sys, time
machine, label, model = sys.argv[1], sys.argv[2], sys.argv[3]
home, state = os.environ["DSH_HOME"], os.path.expanduser("~/.claude")
if not os.path.exists(os.path.expanduser("~/.dsh-run/token")): sys.exit(0)  # not up yet: "booting…"
busy = waiting = False; last_turn = 0; title = ""
main = open(os.path.join(state, ".dsh-session")).read().strip() if os.path.exists(os.path.join(state, ".dsh-session")) else ""
for f in glob.glob(os.path.join(home, "storages", "session_projcache", "sessions", "*.json")):
    try: rows = json.load(open(f))["record"]["rows"]
    except Exception: continue
    raw = lambda k: (rows.get(k) or {}).get("val")
    v = lambda k: raw(k) if isinstance(raw(k), dict) else {}
    try:  # one field in a shape this shim doesn't know never stops the status (a crash here = "booting…" for ever)
        if v("turnBoundary").get("openTurnStartSeq") is not None: busy = True
        last_turn = max(last_turn, (rows.get("turnBoundary") or {}).get("seq") or 0)
        if ((v("userQuestions").get("questions") or {}).get("active")) or v("approvalState").get("pending"): waiting = True
        t = raw("title")  # dsh keeps the title as a plain string
        if os.path.basename(f)[:-5] == main: title = str((t.get("title") if isinstance(t, dict) else t) or "") or title
    except Exception as e:
        print(f"{os.path.basename(f)}: {e!r}", file=sys.stderr)
status = "waiting" if waiting else "busy" if busy else "idle"
path = os.path.join(state, "sessions", "dsh.json")
try: prev = json.load(open(path))
except Exception: prev = {}
now = int(time.time() * 1000)
changed = prev.get("status") != status or last_turn > (prev.get("lastTurnSeq") or 0)
entry = {"pid": os.getppid(), "sessionId": main or "dsh", "name": title or label, "nameSource": "harness", "harness": "dsh",
         "model": model, "status": status, "statusUpdatedAt": now if changed else prev.get("statusUpdatedAt", now),
         "lastTurnSeq": max(last_turn, prev.get("lastTurnSeq") or 0), "startedAt": prev.get("startedAt", now),
         "bridgeSessionId": "dsh:" + machine}
if entry != prev:
    tmp = path + ".tmp"; json.dump(entry, open(tmp, "w")); os.replace(tmp, path)
PY
)
    if [ -n "$err" ] && [ "$err" != "$last_err" ]; then echo "[dsh] status shim: $(printf '%s' "$err" | tail -n 1 | cut -c1-300)"; fi
    last_err="$err"
    n=$((n+1))
    [ $((n % 12)) = 0 ] && SESSION_MODEL="$MODEL" python3 /usr/local/bin/dsh-transcript.py "$WD" 2>> "$RUN/transcript.err"
    sleep 5
  done
}

# Prompts Jarvis queued with `harness-send --queue`: oldest first, a failure retried, set aside after 20 tries.
inbox_loop() {
  local inbox="$STATE/harness-inbox" f tries
  mkdir -p "$inbox/failed"
  while true; do
    for f in "$inbox"/*.txt; do
      [ -f "$f" ] || continue
      if /usr/local/bin/harness-send < "$f" > /dev/null 2>> "$RUN/inbox.err"; then
        rm -f "$f" "$f.tries"; echo "[dsh] delivered a queued prompt ($(basename "$f"))"
      else
        tries=$(( $(cat "$f.tries" 2>/dev/null || echo 0) + 1 )); echo "$tries" > "$f.tries"
        [ "$tries" -ge 20 ] && { mv "$f" "$inbox/failed/"; rm -f "$f.tries"; echo "[dsh] gave up on a queued prompt ($(basename "$f"))"; }
        break
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
    read -r st ts < <(python3 -c 'import json,os;d=json.load(open(os.path.expanduser("~/.claude/sessions/dsh.json")));print(d.get("status",""),int(d.get("statusUpdatedAt") or 0))' 2>/dev/null) || { idle_since=0; continue; }
    now=$(date +%s)
    if [ "$st" = idle ] && [ "${ts:-0}" -gt "$sent_ms" ]; then
      [ "$idle_since" = 0 ] && idle_since=$now
      if [ $((now - idle_since)) -ge 60 ]; then
        SESSION_MODEL="$MODEL" python3 /usr/local/bin/dsh-transcript.py "$WD" 2>/dev/null
        printf 'done %s idle=60s bg=0\n' "$(date -u +%FT%TZ)" > "$marker"
        rm -f "$STATE/sessions/dsh.json"
        echo "[one-shot] done; waiting for Jarvis to archive + destroy this machine"
        return 0
      fi
    else idle_since=0; fi
  done
}

tmux_pane() {
  tmux kill-session -t "$SESSION" 2>/dev/null || true
  tmux new-session -d -s "$SESSION" -x 120 -y 40 -c "$WD" \
    "echo 'DeepSeek Harness ($SLUG) — web UI: https://$WEB_HOST/'; touch $RUN/web.out; tail -n 200 -F $RUN/web.out"
}

echo "[dsh] harness up in $WD (model: $SLUG, perm: $(perm_mode) = $(dsh_perm), name: ${LABEL:-auto})"
[ -n "$RT" ] && run_dsh &
run_tunnel
tmux_pane
send_first_prompt &
inbox_loop &
one_shot_watch &
shim_loop &
while true; do
  if ! tmux has-session -t "$SESSION" 2>/dev/null && [ ! -e "$STATE/.one-shot-done" ]; then tmux_pane; fi
  sleep 5
done
