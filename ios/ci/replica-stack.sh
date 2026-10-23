#!/bin/bash
# replica-stack.sh — the phone replica's throwaway Jarvis 4, on the macOS runner itself (ios.yml job `replica`):
# the real core and router built from this commit (no fakefly), real Fly session machines in jarvis4-sessions, and
# the machines' way back to the router over a WireGuard peer of the Fly org that the router runs in userspace (as
# production's does, router/wg.go). Everything is this run's own and throwaway:
#   - a box key and a setup key (ios/ci/standin.py keys): the Release build reads their public halves from the keys
#     branch the job pushes (JarvisKeysRef, KeySource.swift);
#   - the backup bucket on rclone's S3 server at 127.0.0.1:18098 (it checks SigV4);
#   - the WireGuard peer jarvis4-replica-<RUN>, the core's Fly token (infra/fly-token.sh, 6 hours) and the router's
#     read-only one (infra/fly-read-token.sh), both narrowed from REPLICA_FLY_TOKEN;
#   - the core on 127.0.0.1:8090, started again whenever it ends (a Reset or the app's restart-and-recover wipes it,
#     and Kubernetes starts an empty one in production), the router on 127.0.0.1:18080 with production's session image
#     and its signatures (k8s/cluster/router), the policy in policy/stores.json and its web page.
# The router runs NO_ACCESS=1 on the loopback address: the simulator talks to it directly, there is no Cloudflare in
# front (app/DECISIONS.md "The phone replica").
#
#   replica-stack.sh up W      bring it up (W: the run's work directory, mode 700); writes W/env for the setup answers
#   replica-stack.sh down W    this run's machines and their volumes, its peer, the processes; idempotent. Also the
#                              run's volumes whose machine is already gone (infra/run-volumes.py: only ids this run's
#                              router state and core log name, so never production's)
#   replica-stack.sh sweep     every earlier replica run's leftovers (machines naming a jarvis4-replica-* peer, and
#                              those peers): one run at a time (ios.yml's concurrency group), so none is in flight.
#                              NOT an earlier run's bare volume (its machine gone): Fly keeps no label on a volume and
#                              every core names its volumes jarvis4_state, so it can't be told from production's
#                              (docs/RUNBOOK.md "Leftover volumes"); `down` deletes them while the run's records exist
# Env: REPLICA_FLY_TOKEN (an org token of jarvis2-370: peers, machines, exec), REPLICA_RUN (digits and dashes).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CMD="${1:?usage: replica-stack.sh up|down W | sweep}"
: "${REPLICA_FLY_TOKEN:?}"
export JARVIS2_FLY_TOKEN="$REPLICA_FLY_TOKEN"   # what infra/fly-token.sh and fly-read-token.sh narrow
ORG=jarvis2-370; APP=jarvis4-sessions; MAPI=https://api.machines.dev/v1/apps/$APP

# machines whose router address names a peer matching the regex $1, then their volumes (a force destroy leaves a
# machine's state volume behind, core/volumes.go)
destroy_machines() {
  curl -fsS -H "Authorization: Bearer $REPLICA_FLY_TOKEN" "$MAPI/machines" | python3 -I -c '
import json, re, sys
want = re.compile(r"^http://(" + sys.argv[1] + r")\._peer\.internal:8081$")
for m in json.load(sys.stdin):
    if m.get("state") != "destroyed" and want.match(((m.get("config") or {}).get("env") or {}).get("JARVIS2_URL", "")):
        print(m["id"], " ".join(x.get("volume", "") for x in ((m.get("config") or {}).get("mounts") or [])))' "$1" \
  | while read -r m vols; do
      curl -fsS -o /dev/null -X DELETE -H "Authorization: Bearer $REPLICA_FLY_TOKEN" "$MAPI/machines/$m?force=true" \
        && echo "machine $m destroyed"
      for v in $vols; do
        for _ in 1 2 3 4 5 6; do
          curl -fsS -o /dev/null -X DELETE -H "Authorization: Bearer $REPLICA_FLY_TOKEN" "$MAPI/volumes/$v" \
            && { echo "its volume $v deleted"; break; }
          sleep 5
        done
      done
    done
}

if [ "$CMD" = sweep ]; then
  destroy_machines 'jarvis4-replica-[0-9-]+'
  FLY_API_TOKEN="$REPLICA_FLY_TOKEN" flyctl wireguard list "$ORG" --json 2>/dev/null \
    | python3 -I -c 'import json,re,sys;[print(n) for n in (p.get("Name") or p.get("name") or "" for p in (json.load(sys.stdin) or [])) if re.fullmatch(r"jarvis4-replica-[0-9-]+", n)]' \
    | while read -r p; do FLY_API_TOKEN="$REPLICA_FLY_TOKEN" flyctl wireguard remove "$ORG" "$p" >/dev/null 2>&1 && echo "peer $p removed"; done
  exit 0
fi

W="${2:?usage: replica-stack.sh up|down W}"
RUN="${REPLICA_RUN:?}"
case "$RUN" in ''|*[!0-9-]*) echo "REPLICA_RUN must be digits and dashes"; exit 2 ;; esac
PEER="jarvis4-replica-$RUN"
MURL="http://$PEER._peer.internal:8081"

if [ "$CMD" = down ]; then
  set +e
  for f in "$W"/*.pid; do [ -s "$f" ] && kill "$(cat "$f")" 2>/dev/null; done
  pkill -f "$W/core" 2>/dev/null; pkill -f "$W/router" 2>/dev/null
  destroy_machines "$(printf '%s' "$PEER" | sed 's/[.-]/\\&/g')"
  FLY_TOKEN="$REPLICA_FLY_TOKEN" python3 -I "$ROOT/infra/run-volumes.py" "$W/data/state.json" "$W/core.log"
  FLY_API_TOKEN="$REPLICA_FLY_TOKEN" flyctl wireguard remove "$ORG" "$PEER" >/dev/null 2>&1 && echo "peer $PEER removed"
  for f in "$W/fly.tok" "$W/fly-read" "$W/wg.conf" "$W/box-key.pem" "$W/setup-key.pem"; do [ -f "$f" ] && rm -P "$f" 2>/dev/null || rm -f "$f"; done
  exit 0
fi

[ "$CMD" = up ] || { echo "usage: replica-stack.sh up|down W | sweep"; exit 2; }
mkdir -p "$W" "$HOME/.jarvis2" && chmod 700 "$W" "$HOME/.jarvis2"
python3 -m venv "$W/venv" && "$W/venv/bin/pip" -q install cryptography boto3
PY="$W/venv/bin/python -B"
$PY "$ROOT/ios/ci/standin.py" keys "$W"
command -v rclone >/dev/null || brew install rclone
command -v flyctl >/dev/null || brew install flyctl

echo "== the backup bucket (rclone's S3 server, this run's key)"
S3_SECRET="$(openssl rand -hex 16)"
mkdir -p "$W/s3/jarvis2-backup-replica"
nohup rclone serve s3 --addr 127.0.0.1:18098 --auth-key "replica,$S3_SECRET" "$W/s3" > "$W/s3.log" 2>&1 & echo $! > "$W/s3.pid"

echo "== the WireGuard peer $PEER (the machines reach the router as $PEER._peer.internal)"
FLY_API_TOKEN="$REPLICA_FLY_TOKEN" flyctl wireguard remove "$ORG" "$PEER" >/dev/null 2>&1 || true
(umask 077; FLY_API_TOKEN="$REPLICA_FLY_TOKEN" flyctl wireguard create "$ORG" lhr "$PEER" "$W/wg.conf" >/dev/null)

echo "== the core's Fly token (narrowed as production's, 6 hours) and the router's read-only one"
FLY_TOKEN_HOURS=6 bash "$ROOT/infra/fly-token.sh" "$W/fly.tok"
bash "$ROOT/infra/fly-read-token.sh" "$W/fly-read"

echo "== the core and the router, built from this commit"
(cd "$ROOT/core" && go build -o "$W/core" .)
(cd "$ROOT/router" && go build -o "$W/router" .)
cat > "$W/core-loop.sh" <<EOF
#!/bin/bash
# the core, started again whenever it ends (a wipe), as Kubernetes does
while true; do BOX_KEY_FILE="$W/box-key.pem" MACHINE_URL="$MURL" ADDR=127.0.0.1:8090 "$W/core" >> "$W/core.log" 2>&1; sleep 1; done
EOF
chmod 700 "$W/core-loop.sh"
nohup "$W/core-loop.sh" > /dev/null 2>&1 & echo $! > "$W/core-loop.pid"
for _ in $(seq 30); do curl -sf -o /dev/null http://127.0.0.1:8090/identity && break; sleep 1; done
curl -sf -o /dev/null http://127.0.0.1:8090/identity || { echo "the core didn't come up"; tail -20 "$W/core.log"; exit 1; }

# production's session image, its signature and the earlier pins' (the phone checks them against keys/ci.pub)
RY="$ROOT/k8s/cluster/router/router.yaml"
val() { sed -n "s/.*name: $1, value: \"\([^\"]*\)\".*/\1/p" "$RY" | head -1; }
SIMG="$(val SESSION_IMAGE)"; SSIG="$(val SESSION_IMAGE_SIG)"
[ -n "$SIMG" ] && [ -n "$SSIG" ] || { echo "no SESSION_IMAGE / SESSION_IMAGE_SIG in $RY"; exit 1; }
mkdir -p "$W/data"
DBURL="$(bash "$ROOT/infra/test-postgres.sh" fresh router_replica)"  # the router's records (router/statedb.go)
cat > "$W/router.sh" <<EOF
#!/bin/sh
# the router's whole env: nothing of production's (no Discord, Storage Box, Jarvis 1 or Claude keys)
exec env -i PATH="$PATH" HOME="$HOME" \\
  DATABASE_URL="$DBURL" ROUTER_THROWAWAY=1 NO_ACCESS=1 RECORDS_OFF=1 CORE_URL=http://127.0.0.1:8090 ADDR=127.0.0.1:18080 MACHINE_ADDR=127.0.0.1:18081 \\
  DATA_DIR="$W/data" WEB_DIR="$ROOT/web" TASKS_DIR="$ROOT/tasks" POLICY_FILE="$ROOT/policy/stores.json" \\
  SESSION_IMAGE="$SIMG" SESSION_IMAGE_SIG="$SSIG" SESSION_IMAGE_SIGS_FILE="$ROOT/k8s/cluster/router/session-image-sigs.txt" \\
  FLY_REGION=lhr MACHINE_URL="$MURL" FLY_READ_TOKEN="\$(cat "$W/fly-read")" \\
  SETUP_KEY="$(cat "$W/keys/setup.pub")" \\
  BACKUP_ENDPOINT=http://127.0.0.1:18098 BACKUP_BUCKET=jarvis2-backup-replica BACKUP_READ_ACCESS_KEY=replica BACKUP_READ_SECRET_KEY="$S3_SECRET" \\
  "$W/router"
EOF
chmod 700 "$W/router.sh"
nohup "$W/router.sh" > "$W/router.log" 2>&1 & echo $! > "$W/router.pid"
for _ in $(seq 30); do curl -sf -o /dev/null http://127.0.0.1:18080/api/state && break; sleep 1; done
curl -sf -o /dev/null http://127.0.0.1:18080/api/state || { echo "the router didn't come up"; tail -20 "$W/router.log"; exit 1; }
# the machines' WireGuard peer runs in the gateway (router/mgateway.go), as on the cluster, passing /m to the router
(env -i PATH="$PATH" HOME="$HOME" WG_CONFIGS="$W/wg.conf" POD_NAME=m-gateway-0 M_GATEWAY_TO=http://127.0.0.1:18081 HEALTH_ADDR=127.0.0.1:18082 \
  nohup "$W/router" m-gateway > "$W/m-gateway.log" 2>&1 & echo $! > "$W/m-gateway.pid")
for _ in $(seq 20); do grep -q "WireGuard peer from" "$W/m-gateway.log" && break; sleep 1; done
grep -q "WireGuard peer from" "$W/m-gateway.log" || { echo "the gateway has no WireGuard peer"; tail -20 "$W/m-gateway.log"; exit 1; }

# what the setup answers (ios/ci/replica-setup.sh) need: setup.py pointed at this stack
cat > "$W/env" <<EOF
export JARVIS2_URL=http://127.0.0.1:18080 JARVIS2_KEYS_DIR="$W/keys" JARVIS2_BACKUP_BUCKET=jarvis2-backup-replica
export JARVIS2_SETUP_KEY="\$(cat "$W/setup-key.pem")" JARVIS2_SETUP_ACCESS_ID=none JARVIS2_SETUP_ACCESS_SECRET=none
export HETZNER_S3_ENDPOINT=http://127.0.0.1:18098 HETZNER_S3_REGION=fsn1 HETZNER_S3_ACCESS_KEY=replica HETZNER_S3_SECRET_KEY="$S3_SECRET"
export REPLICA_W="$W" REPLICA_PY="$W/venv/bin/python"
EOF
chmod 600 "$W/env"
echo "ok: core :8090, router :18080, peer $PEER, session image $SIMG"
