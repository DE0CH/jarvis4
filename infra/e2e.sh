#!/bin/bash
# e2e.sh — the end-to-end test against real Fly machines, from a session: builds the core and the router,
# runs them here (ports 28090/28080) with a throwaway box key, a throwaway WireGuard peer of the Fly org
# (jarvis2-e2e) and the session image, so the machines reach this router over Fly's private network as they reach
# the box's; the test sets its core up with the public TEST master key (e2e/testdata).
# Leaves nothing behind but the core's and router's logs (in $E2E_LOGS, default /tmp/jarvis2-e2e-logs): the
# peer is removed, the processes stopped. Never touches the production core.
#   JARVIS2_FLY_TOKEN   the jarvis2-370 org token
#   E2E_CORE_FLY_TOKEN  optional: the token the test core gets instead (infra/fly-token.sh: narrowed as production's)
#   E2E_CORE_REF: run against the core of that git ref instead of this tree's
#   E2E_ONLY=jarvis1-import: after the core's setup, only the Jarvis 1 import step (a fake paused session on 127.0.0.1:${PP}070)
#   E2E_ONLY=drain: after the first session is up, only the drain: SIGTERM to the router with a pause in flight
#   E2E_ONLY=restore: after the core's setup, only the restore of a store to an earlier version (no machines)
#   E2E_ONLY=continuity: the core set up from the master key's seed, a running and a paused session, then the core
#     restarted and Recovered with the same kit and the router's line state: the sessions go on (e2e/continuity.go)
#   E2E_ONLY=move: a second router (its own /data, ports ${PP}180/${PP}181) moves the router over from the first while
#     a session machine runs, the WireGuard peer moving along (router/move.go; e2e/move.go): the gaps are measured
# Always with Jarvis 1 unreachable (e2e/nojarvis1.go): the router runs in its own mount namespace (sudo unshare) whose
#   /etc/hosts sends jarvis.deyaochen.com to a listener that fails the test on any connection; each machine gets it
#   blackholed too; search, the watch runner and the Storage Box are local stand-ins
#   E2E_PEER (default jarvis2-e2e), E2E_PORT (default 28 → 28090/28080): another peer and ports let two runs go at once
set -euo pipefail
: "${JARVIS2_FLY_TOKEN:?}"
PEER="${E2E_PEER:-jarvis2-e2e}"; PP="${E2E_PORT:-28}"
[ "$PEER" != jarvis2-box ] || { echo "E2E_PEER jarvis2-box is production's" >&2; exit 1; }
# sweep: destroy every machine in jarvis4-sessions whose JARVIS2_URL names THIS run's peer (earlier runs' leftovers at the
# start, this run's own at the end, on success, failure or interruption). Never one naming another peer: production's
# machines name jarvis2-box. An earlier run's bare volume (its machine gone) can't be told from production's and is
# left (docs/RUNBOOK.md "Leftover volumes"); cleanup deletes this run's own from its records (infra/run-volumes.py).
sweep() {
  curl -fsS -H "Authorization: Bearer $JARVIS2_FLY_TOKEN" https://api.machines.dev/v1/apps/jarvis4-sessions/machines 2>/dev/null \
    | python3 -I -c '
import json, sys
want = "http://" + sys.argv[1] + "._peer.internal:8081"
for m in json.load(sys.stdin):
    if m.get("state") != "destroyed" and ((m.get("config") or {}).get("env") or {}).get("JARVIS2_URL") == want:
        print(m["id"], " ".join(x.get("volume", "") for x in ((m.get("config") or {}).get("mounts") or [])))' "$PEER" \
    | while read -r m vols; do
        curl -fsS -o /dev/null -X DELETE -H "Authorization: Bearer $JARVIS2_FLY_TOKEN" \
          "https://api.machines.dev/v1/apps/jarvis4-sessions/machines/$m?force=true" && echo "e2e: destroyed leftover machine $m ($PEER)"
        # its state volume (core/volumes.go): a force destroy leaves it behind, unattached
        for v in $vols; do
          for _ in 1 2 3 4 5 6; do
            curl -fsS -o /dev/null -X DELETE -H "Authorization: Bearer $JARVIS2_FLY_TOKEN" \
              "https://api.machines.dev/v1/apps/jarvis4-sessions/volumes/$v" && { echo "e2e: deleted its volume $v"; break; }
            sleep 5
          done
        done
      done || true
}
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
W="$(mktemp -d)"; chmod 700 "$W"
PIDS=(); SUDO_PIDS=()
cleanup() {
  mkdir -p "${E2E_LOGS:-/tmp/jarvis2-e2e-logs}" && cp "$W"/*.log "${E2E_LOGS:-/tmp/jarvis2-e2e-logs}/" 2>/dev/null || true
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
  [ -s "$W/core.pid" ] && kill "$(cat "$W/core.pid")" 2>/dev/null || true
  for p in "${SUDO_PIDS[@]}"; do sudo -n pkill -P "$p" 2>/dev/null || true; sudo -n kill "$p" 2>/dev/null || true; done
  [ -e "$W/router-b" ] && { pkill -f "$W/router-b" 2>/dev/null; sudo -n pkill -f "$W/router-b" 2>/dev/null; } || true
  sweep
  # this run's volumes whose machine is already gone (a kill whose delete failed, a core restarted mid-run): only ids
  # this run's routers and cores recorded, never another run's or production's (infra/run-volumes.py)
  FLY_TOKEN="$JARVIS2_FLY_TOKEN" python3 -I "$ROOT/infra/run-volumes.py" "$W/data/state.json" "$W/data-b/state.json" \
    "$W/core.log" || true
  FLY_API_TOKEN="$JARVIS2_FLY_TOKEN" flyctl wireguard remove jarvis2-370 "$PEER" >/dev/null 2>&1 || true
  rm -rf "$W"
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP
sweep

# E2E_CORE_REF: build the core from that git ref instead
if [ -n "${E2E_CORE_REF:-}" ]; then
  git -C "$ROOT" worktree add -q --detach "$W/core-src" "$E2E_CORE_REF"
  (cd "$W/core-src/core" && go build -o "$W/core" .)
  git -C "$ROOT" worktree remove --force "$W/core-src"
else
  (cd "$ROOT/core" && go build -o "$W/core" .)
fi
(cd "$ROOT/router" && go build -o "$W/router" .)
python3 - "$W" <<'PY'
import base64, sys
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization as s
k = ec.generate_private_key(ec.SECP256R1())   # a throwaway box key
w = sys.argv[1]
open(f"{w}/box-key.pem", "wb").write(k.private_bytes(s.Encoding.PEM, s.PrivateFormat.PKCS8, s.NoEncryption()))
open(f"{w}/box.pub", "w").write(base64.b64encode(k.public_key().public_bytes(s.Encoding.X962, s.PublicFormat.UncompressedPoint)).decode())
PY
# the test's policy: harnesses bring no stores; claude runs on a Claude account (the e2e seeds claude-e2e)
echo '{"harnesses":{"claude":{"stores":[],"claudeAccount":true},"opencode":{"stores":[]}}}' > "$W/policy.json"
FLY_API_TOKEN="$JARVIS2_FLY_TOKEN" flyctl wireguard remove jarvis2-370 "$PEER" >/dev/null 2>&1 || true
(umask 077; FLY_API_TOKEN="$JARVIS2_FLY_TOKEN" flyctl wireguard create jarvis2-370 lhr "$PEER" "$W/wg.conf" >/dev/null)

# the test router must never reach Deyao's Discord, the Storage Box or Jarvis 1: none of their keys go in (its env is
# only what router-env below names)
mkdir -p "$W/data" "$W/web"
# the core sets the router's address in every machine it makes (core/vouch.go), from its own deployment
BOX_KEY_FILE="$W/box-key.pem" ADDR=127.0.0.1:${PP}090 MACHINE_URL="http://$PEER._peer.internal:8081" "$W/core" > "$W/core.log" 2>&1 & PIDS+=($!)
echo $! > "$W/core.pid"
# E2E_ONLY=continuity restarts the core mid-run (e2e/continuity.go): the running one ends, an empty one takes its port
cat > "$W/core-restart" <<SH
#!/bin/sh
kill \$(cat "$W/core.pid") 2>/dev/null; sleep 1
BOX_KEY_FILE="$W/box-key.pem" ADDR=127.0.0.1:${PP}090 MACHINE_URL="http://$PEER._peer.internal:8081" nohup "$W/core" >> "$W/core.log" 2>&1 &
echo \$! > "$W/core.pid"
for i in \$(seq 1 30); do curl -sf http://127.0.0.1:${PP}090/identity > /dev/null && exit 0; sleep 0.5; done
exit 1
SH
chmod 700 "$W/core-restart"
# the core starts only the session image pinned by its linux/amd64 digest
E2E_SESSION_IMAGE="$("$ROOT/infra/image-digest.sh" "${E2E_SESSION_IMAGE:-ghcr.io/de0ch/jarvis4-session:latest}")"
# stand-ins for the box's other services (e2e/nojarvis1.go serves them): search, the watch runner, and the Storage Box
# (WebDAV over TLS with a throwaway certificate the router trusts through SSL_CERT_FILE, beside the system roots)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj /CN=127.0.0.1 \
  -addext subjectAltName=IP:127.0.0.1 -keyout "$W/dav.key" -out "$W/dav.crt" 2>/dev/null
cat /etc/ssl/certs/ca-certificates.crt "$W/dav.crt" > "$W/roots.pem"
# the backup bucket: rclone's S3 server (it checks SigV4) on a local directory; the router adds key backups there
# (router/storedocs.go) with the stand-in's key, as it does with its BACKUP_READ_* credential on Hetzner
mkdir -p "$W/s3/jarvis2-backup-de0ch"
S3_SECRET="$(openssl rand -hex 16)"
rclone serve s3 --addr 127.0.0.1:${PP}074 --auth-key "e2e,$S3_SECRET" "$W/s3" > "$W/s3.log" 2>&1 & PIDS+=($!)
# E2E_ONLY=move: the first router is the sender (its move listener on ${PP}082), the second (router-b) the joiner
MOVE_ENV=""
if [ "${E2E_ONLY:-}" = move ]; then
  MOVE_KEY="$(openssl rand -hex 16)"
  MOVE_ENV="MOVE_KEY=$MOVE_KEY MOVE_ADDR=127.0.0.1:${PP}082"
fi
# the router's records (router/statedb.go): a fresh database on the throwaway Postgres (router-b shares it, as a moved
# router does)
DBURL="$("$ROOT/infra/test-postgres.sh" fresh "e2e_${PP}")"
cat > "$W/router-env" <<ENV
#!/bin/sh
exec env -i PATH="$PATH" HOME="$HOME" DATABASE_URL="$DBURL" OBJECTS_MEMORY=1 \\
  CORE_URL=http://127.0.0.1:${PP}090 NO_ACCESS=1 RECORDS_OFF=1 LIVE_SYNC_SECONDS=20 ADDR=127.0.0.1:${PP}080 DATA_DIR="$W/data" WEB_DIR="$W/web" \\
  WG_CONFIG="$W/wg.conf" MACHINE_URL="http://$PEER._peer.internal:8081" POLICY_FILE="$W/policy.json" TASKS_DIR="$ROOT/tasks" \\
  SESSION_IMAGE="$E2E_SESSION_IMAGE" JARVIS1_PAUSED_URL="http://127.0.0.1:${PP}070/" \\
  STORAGEBOX_HOST=127.0.0.1:${PP}073 STORAGEBOX_USER=e2e STORAGEBOX_PASSWORD=e2e SSL_CERT_FILE="$W/roots.pem" \\
  SEARCH_URL=http://127.0.0.1:${PP}071 WATCH_URL=http://127.0.0.1:${PP}072 \\
  BACKUP_ENDPOINT=http://127.0.0.1:${PP}074 BACKUP_READ_ACCESS_KEY=e2e BACKUP_READ_SECRET_KEY="$S3_SECRET" \\
  $MOVE_ENV "$W/router"
ENV
chmod 700 "$W/router-env"
# Jarvis 4 runs without Jarvis 1: the router runs in its own mount namespace whose /etc/hosts sends every Jarvis 1
# hostname to 127.0.0.2, where a listener (root: ports 80/443) logs any connection to $W/j1-hits.log; the test fails
# on any line there (e2e/nojarvis1.go). The test blackholes the same hostnames on every session machine.
J1_HOSTS="jarvis.deyaochen.com"
{ cat /etc/hosts; for h in $J1_HOSTS; do echo "127.0.0.2 $h"; done; } > "$W/hosts"
: > "$W/j1-hits.log"
cat > "$W/j1-listener.py" <<'PY'
import socket, sys, threading, time
log = sys.argv[1]
def serve(port):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("127.0.0.2", port)); s.listen(16)
    while True:
        c, a = s.accept()
        with open(log, "a") as f: f.write(f"{time.strftime('%H:%M:%S')} connection to Jarvis 1 port {port} from {a}\n")
        c.close()
for p in (80, 443): threading.Thread(target=serve, args=(p,), daemon=True).start()
while True: time.sleep(3600)
PY
sudo -n python3 -I "$W/j1-listener.py" "$W/j1-hits.log" & SUDO_PIDS+=($!)
# the router: unshare (root) bind-mounts the hosts file, then setpriv drops back to this user before the router runs
sudo -n unshare -m --propagation private sh -c 'mount --bind "$0" /etc/hosts && exec setpriv --reuid="$1" --regid="$2" --clear-groups "$3"' \
  "$W/hosts" "$(id -u)" "$(id -g)" "$W/router-env" > "$W/router.log" 2>&1 & SUDO_PIDS+=($!)
ROUTER_PID=""
for _ in $(seq 1 30); do
  for p in /proc/[0-9]*; do [ "$(readlink "$p/exe" 2>/dev/null)" = "$W/router" ] && ROUTER_PID="${p#/proc/}"; done
  [ -n "$ROUTER_PID" ] && break; sleep 0.5
done
[ -n "$ROUTER_PID" ] || { echo "the router didn't start"; cat "$W/router.log"; exit 1; }
PIDS+=("$ROUTER_PID")
for h in $J1_HOSTS; do
  grep -qx "127.0.0.2 $h" "/proc/$ROUTER_PID/root/etc/hosts" || { echo "the router's /etc/hosts doesn't blackhole $h"; exit 1; }
done
grep -q 'jarvis.deyaochen.com' /etc/hosts && { echo "the blackhole leaked into this session's own /etc/hosts"; exit 1; }
if [ "${E2E_ONLY:-}" = move ]; then
  cp "$W/router" "$W/router-b"; mkdir -p "$W/data-b"
  # router-b-start MOVE_AT: the joiner, in the same blackholed namespace; its peer comes with the move (no WG_CONFIG)
  cat > "$W/router-b-env" <<ENV
#!/bin/sh
exec env -i PATH="$PATH" HOME="$HOME" DATABASE_URL="$DBURL" OBJECTS_MEMORY=1 \\
  CORE_URL=http://127.0.0.1:${PP}090 NO_ACCESS=1 RECORDS_OFF=1 LIVE_SYNC_SECONDS=20 ADDR=127.0.0.1:${PP}180 MACHINE_ADDR=127.0.0.1:${PP}181 \\
  DATA_DIR="$W/data-b" WEB_DIR="$W/web" MACHINE_URL="http://$PEER._peer.internal:8081" POLICY_FILE="$W/policy.json" TASKS_DIR="$ROOT/tasks" \\
  SESSION_IMAGE="$E2E_SESSION_IMAGE" JARVIS1_PAUSED_URL="http://127.0.0.1:${PP}070/" \\
  STORAGEBOX_HOST=127.0.0.1:${PP}073 STORAGEBOX_USER=e2e STORAGEBOX_PASSWORD=e2e SSL_CERT_FILE="$W/roots.pem" \\
  SEARCH_URL=http://127.0.0.1:${PP}071 WATCH_URL=http://127.0.0.1:${PP}072 \\
  BACKUP_ENDPOINT=http://127.0.0.1:${PP}074 BACKUP_READ_ACCESS_KEY=e2e BACKUP_READ_SECRET_KEY="$S3_SECRET" \\
  MOVE_FROM=http://127.0.0.1:${PP}082 MOVE_PUBLIC=http://127.0.0.1:${PP}080 MOVE_SELF=http://127.0.0.1:${PP}180 MOVE_KEY=$MOVE_KEY \\
  MOVE_AT="\$(cat "$W/move-at")" "$W/router-b"
ENV
  chmod 700 "$W/router-b-env"
  cat > "$W/router-b-start" <<SH
#!/bin/sh
echo "\$1" > "$W/move-at"
sudo -n unshare -m --propagation private sh -c 'mount --bind "\$0" /etc/hosts && exec setpriv --reuid="\$1" --regid="\$2" --clear-groups "\$3"' \
  "$W/hosts" "$(id -u)" "$(id -g)" "$W/router-b-env" > "$W/router-b.log" 2>&1 &
SH
  chmod 700 "$W/router-b-start"
  : > "$W/router-b.log"
fi
sleep 3
(cd "$ROOT/e2e" && E2E_ROUTER_B_START="$W/router-b-start" E2E_ROUTER_B=http://127.0.0.1:${PP}180 E2E_ROUTER_B_LOG="$W/router-b.log" E2E_CORE_RESTART="$W/core-restart" E2E_ROUTER_PID="$ROUTER_PID" E2E_ROUTER_LOG="$W/router.log" E2E_DATA_DIR="$W/data" E2E_DATABASE_URL="$DBURL" OBJECTS_MEMORY=1 E2E_ROUTER=http://127.0.0.1:${PP}080 E2E_CORE=http://127.0.0.1:${PP}090 E2E_MASTER_KEY_FILE="$ROOT/e2e/testdata/master-test.pem" E2E_BOX_PUB="$(cat "$W/box.pub")" \
  E2E_JARVIS1_ADDR=127.0.0.1:${PP}070 E2E_FLY_TOKEN="$JARVIS2_FLY_TOKEN" E2E_CORE_FLY_TOKEN="${E2E_CORE_FLY_TOKEN:-$JARVIS2_FLY_TOKEN}" \
  E2E_PEER="$PEER" E2E_J1_HITS="$W/j1-hits.log" E2E_SEARCH_ADDR=127.0.0.1:${PP}071 E2E_WATCH_ADDR=127.0.0.1:${PP}072 \
  E2E_DAV_ADDR=127.0.0.1:${PP}073 E2E_DAV_CERT="$W/dav.crt" E2E_DAV_KEY="$W/dav.key" E2E_S3_DIR="$W/s3/jarvis2-backup-de0ch" go run .) || { echo "--- router log"; tail -40 "$W/router.log"; exit 1; }
