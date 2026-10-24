#!/bin/bash
# replica-setup.sh MSG — the setup session's answer to one message from the phone replica's UI test (ReplicaUITests,
# through ios/ci/replica-host.py's /relay), printed on stdout. It runs on the same runner as the test stack
# (ios/ci/replica-stack.sh; its W/env points infra/setup.py at it):
#   reset-done  after the app's Reset: the stores written with infra/setup.py (dummy values; the harness's tunnel;
#               github-deploy-keys = the replica test repo's token; the core's Fly token, 6 h) → "filled"
#   repo-added  the test repo has its one deploy key now (the app shows the repo added) → "ok"
#   repo-check  …and none left after the app removed it → "ok"
#   inbox-setup-add / inbox-setup-remove   infra/setup.py request add-repo / remove-repo for the test repo → "ok"
#   inbox-session:<sid>:<holder>           jarvis-request grant <holder> run inside that session's machine (flyctl exec)
#   inbox-batch:<sid>                      jarvis-request batch (two grants, one summary) inside that session's machine
#   session-file:<sid>:<name>              the image attached on New session is on that session's machine (the
#                                          machine's hash-checked copy, or the harness's ~/uploads copy)
#   done        the end → "ok"
# Env: REPLICA_ENV (the stack's W/env), REPLICA_FLY_TOKEN, REPLICA_REPO (DE0CH/<name>), REPLICA_REPO_TOKEN (that repo's
# Administration token: its deploy keys).
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "${REPLICA_ENV:?}"
W="$REPLICA_W"; L="$W/setup.log"
S() { "$REPLICA_PY" -B "$ROOT/infra/setup.py" "$@"; }
keys() { GH_TOKEN="$REPLICA_REPO_TOKEN" gh api "repos/$REPLICA_REPO/keys" -q 'length' 2>/dev/null || echo "?"; }
machine_of() { # the router's record of the session's current machine, up to 90 s
  local m=""
  for _ in $(seq 1 18); do
    m=$(S sessions 2>>"$L" | awk -v s="$1" '$1 == s && $2 != "-" {print $2}')
    [ -n "$m" ] && break; sleep 5
  done
  printf '%s' "$m"
}
fexec() { FLY_API_TOKEN="$REPLICA_FLY_TOKEN" flyctl machine exec "$1" -a jarvis4-sessions "$2"; }
msg="${1:?usage: replica-setup.sh MSG}"
echo "$(date -u +%H:%M:%S) $msg" >> "$L"
case "$msg" in
  reset-done)
    rnd=$(openssl rand -hex 6)
    printf '%s' "$REPLICA_REPO_TOKEN" > "$W/deploy-keys.tok"; chmod 600 "$W/deploy-keys.tok"
    if ( set -e
         export RH_PLAIN="plain-$rnd" RH_SECRET="secret-$rnd" CF_ACCESS_CLIENT_ID="tunnel-id-$rnd" CF_ACCESS_CLIENT_SECRET="tunnel-secret-$rnd"
         export JARVIS_NOT_SENSITIVE=rh-plain
         S pin-master
         S create rh-plain
         S write rh-plain RH_PLAIN --explain 'RH_PLAIN=replica test value (not secret)'
         S write rh-secret RH_SECRET --explain 'RH_SECRET=replica test value in a sensitive store'
         S write tunnel CF_ACCESS_CLIENT_ID CF_ACCESS_CLIENT_SECRET --explain 'CF_ACCESS_CLIENT_ID=replica dummy tunnel id' --explain 'CF_ACCESS_CLIENT_SECRET=replica dummy tunnel secret'
         S write github-deploy-keys GITHUB_DEPLOY_KEYS_TOKEN=file:"$W/deploy-keys.tok" --explain 'GITHUB_DEPLOY_KEYS_TOKEN=the replica test repo token (deploy keys only)'
         S backup-core "$W/fly.tok"
         S stores ) >> "$L" 2>&1; then echo filled; else echo "fill failed: $(tail -3 "$L" | tr '\n' ' ')"; fi ;;
  repo-added) n=$(keys); if [ "$n" = 1 ]; then touch "$W/key-seen"; echo ok; else echo "keys=$n"; fi ;;
  repo-check) left=$(keys)
    if [ -e "$W/key-seen" ] && [ "$left" = 0 ]; then echo ok; else echo "seen=$([ -e "$W/key-seen" ] && echo yes || echo no) left=$left"; fi ;;
  inbox-setup-add) S request add-repo "$REPLICA_REPO" --why "replica: Claude asks for the test repo" >> "$L" 2>&1 && echo ok || echo "request failed: $(tail -1 "$L")" ;;
  inbox-setup-remove) S request remove-repo "$REPLICA_REPO" --why "replica: Claude asks to remove it (deny this)" >> "$L" 2>&1 && echo ok || echo "request failed: $(tail -1 "$L")" ;;
  inbox-session:*)
    IFS=: read -r _ sid holder <<<"$msg"; m=$(machine_of "$sid")
    if [ -n "$m" ] && fexec "$m" "/usr/local/bin/jarvis-request grant $holder --minutes 5 --why replica-the-session-asks-for-$holder" >> "$L" 2>&1; then echo ok
    else echo "session request failed (machine ${m:-none}): $(tail -2 "$L" | tr '\n' ' ')"; fi ;;
  inbox-batch:*) # not status: the grants step later forgets ITS status grant by the row's identifier
    sid=${msg#inbox-batch:}; m=$(machine_of "$sid"); o="$W/batch.out"
    # flyctl exec exits 0 whatever the command did: the router's batch id is the proof
    if [ -n "$m" ] && fexec "$m" "/usr/local/bin/jarvis-request batch --summary replica-the-session-asks-for-two-grants --item grant,holder=archive,minutes=5 --item grant,holder=remote,minutes=5" > "$o" 2>&1 \
         && grep -q '"id": "b' "$o"; then cat "$o" >> "$L"; echo ok
    else cat "$o" >> "$L"; echo "session batch failed (machine ${m:-none}): $(tail -2 "$o" | tr '\n' ' ')"; fi ;;
  session-file:*)
    IFS=: read -r _ sid name <<<"$msg"
    if [[ ! "$name" =~ ^[A-Za-z0-9._-]+$ ]]; then echo "bad name"; exit 0; fi
    found=""; m=""
    for _ in $(seq 1 18); do
      m=$(machine_of "$sid")
      [ -n "$m" ] && found=$(fexec "$m" "find /root /home -maxdepth 3 -type f -name $name -size +0c" 2>>"$L" | tr -d "\r" | grep -E "/(\.jarvis-uploads|uploads)/$name\$" || true)
      [ -n "$found" ] && break; sleep 10
    done
    if [ -n "$found" ]; then echo "ok $(echo $found)"; else echo "not on the machine (${m:-none}): $(tail -2 "$L" | tr '\n' ' ')"; fi ;;
  done) echo ok ;;
  *) echo "unknown: $msg" ;;
esac
