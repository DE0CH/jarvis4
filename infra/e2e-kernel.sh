#!/bin/bash
# e2e-kernel.sh — a kernel line's life on real Fly machines, from a session (docs/PLAN-grants.md stage 9): builds the
# eight kernel components and the router, runs them here with a throwaway box key (each component on its own loopback
# address, named <role>.kernel.e2e in the router's /etc/hosts, KERNEL_URL=http://%s.kernel.e2e:8080), a throwaway
# WireGuard peer of the Fly org (jarvis2-e2e-kernel) and the session image, so the machines the spawner makes reach
# this router over Fly's private network as they reach the box's. e2e/kernel plays the iPhone (e2e/kernel/main.go).
# Leaves nothing behind but the logs (in $E2E_LOGS, default /tmp/jarvis2-e2e-kernel-logs): every machine naming this
# run's peer is destroyed with its volume, the peer removed, the processes stopped. Never touches production.
#   JARVIS2_FLY_TOKEN   the jarvis2-370 org token (the spawner's here, and the sweep's)
#   E2E_SESSION_IMAGE   the session image (default ghcr.io/de0ch/jarvis4-session:latest), pinned by digest here
set -euo pipefail
: "${JARVIS2_FLY_TOKEN:?}"
PEER=jarvis2-e2e-kernel
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
W="$(mktemp -d)"; chmod 700 "$W"
PIDS=(); SUDO_PIDS=()
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
          "https://api.machines.dev/v1/apps/jarvis4-sessions/machines/$m?force=true" && echo "e2e-kernel: destroyed leftover machine $m"
        for v in $vols; do
          for _ in 1 2 3 4 5 6; do
            curl -fsS -o /dev/null -X DELETE -H "Authorization: Bearer $JARVIS2_FLY_TOKEN" \
              "https://api.machines.dev/v1/apps/jarvis4-sessions/volumes/$v" && { echo "e2e-kernel: deleted its volume $v"; break; }
            sleep 5
          done
        done
      done || true
}
cleanup() {
  mkdir -p "${E2E_LOGS:-/tmp/jarvis2-e2e-kernel-logs}" && cp "$W"/*.log "${E2E_LOGS:-/tmp/jarvis2-e2e-kernel-logs}/" 2>/dev/null || true
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
  for p in "${SUDO_PIDS[@]}"; do sudo -n pkill -P "$p" 2>/dev/null || true; sudo -n kill "$p" 2>/dev/null || true; done
  sweep
  FLY_API_TOKEN="$JARVIS2_FLY_TOKEN" flyctl wireguard remove jarvis2-370 "$PEER" >/dev/null 2>&1 || true
  rm -rf "$W"
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP
sweep

for r in notary notarizer mover merger spawner identity gullible secrets; do (cd "$ROOT/kernel" && go build -o "$W/$r" "./cmd/$r"); done
(cd "$ROOT/core" && go build -o "$W/core" .)
(cd "$ROOT/router" && go build -o "$W/router" .)
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$W/box-key.pem" 2>/dev/null
echo '{"harnesses":{"claude":{"stores":[],"claudeAccount":true},"opencode":{"stores":[]}}}' > "$W/policy.json"
FLY_API_TOKEN="$JARVIS2_FLY_TOKEN" flyctl wireguard remove jarvis2-370 "$PEER" >/dev/null 2>&1 || true
(umask 077; FLY_API_TOKEN="$JARVIS2_FLY_TOKEN" flyctl wireguard create jarvis2-370 lhr "$PEER" "$W/wg.conf" >/dev/null)
MURL="http://$PEER._peer.internal:8081"

# the kernel: each component on 127.0.1.<n>:8080, its state in its own directory
{ cat /etc/hosts; } > "$W/hosts"
n=1
for r in notary notarizer mover merger spawner identity gullible secrets; do
  mkdir -p "$W/k-$r"
  extra=""; [ "$r" = spawner ] && extra="KERNEL_MACHINE_URL=$MURL"
  env KERNEL_BOX_KEY="$W/box-key.pem" KERNEL_DATA="$W/k-$r" KERNEL_ADDR="127.0.1.$n:8080" $extra "$W/$r" > "$W/kernel-$r.log" 2>&1 & PIDS+=($!)
  echo "127.0.1.$n $r.kernel.e2e" >> "$W/hosts"
  n=$((n+1))
done
# the old core beside it (the router still needs one)
BOX_KEY_FILE="$W/box-key.pem" ADDR=127.0.0.1:29090 MACHINE_URL="$MURL" "$W/core" > "$W/core.log" 2>&1 & PIDS+=($!)
E2E_SESSION_IMAGE="$("$ROOT/infra/image-digest.sh" "${E2E_SESSION_IMAGE:-ghcr.io/de0ch/jarvis4-session:latest}")"
mkdir -p "$W/data" "$W/web"
DBURL="$("$ROOT/infra/test-postgres.sh" fresh e2e_kernel)"  # the router's records (router/statedb.go)
cat > "$W/router-env" <<ENV
#!/bin/sh
exec env -i PATH="$PATH" HOME="$HOME" DATABASE_URL="$DBURL" OBJECTS_MEMORY=1 \\
  CORE_URL=http://127.0.0.1:29090 KERNEL_URL=http://%s.kernel.e2e:8080 NO_ACCESS=1 RECORDS_OFF=1 ADDR=127.0.0.1:29080 DATA_DIR="$W/data" WEB_DIR="$W/web" \\
  WG_CONFIG="$W/wg.conf" MACHINE_URL="$MURL" POLICY_FILE="$W/policy.json" TASKS_DIR="$ROOT/tasks" SESSION_IMAGE="$E2E_SESSION_IMAGE" "$W/router"
ENV
chmod 700 "$W/router-env"
# the router in its own mount namespace, whose /etc/hosts names the kernel's components
sudo -n unshare -m --propagation private sh -c 'mount --bind "$0" /etc/hosts && exec setpriv --reuid="$1" --regid="$2" --clear-groups "$3"' \
  "$W/hosts" "$(id -u)" "$(id -g)" "$W/router-env" > "$W/router.log" 2>&1 & SUDO_PIDS+=($!)
for _ in $(seq 1 40); do curl -sf http://127.0.0.1:29080/api/kernel > /dev/null && break; sleep 0.5; done
(cd "$ROOT/e2e" && E2E_ROUTER=http://127.0.0.1:29080 E2E_SPAWNER=http://127.0.1.5:8080 E2E_DATA_DIR="$W/data" E2E_DATABASE_URL="$DBURL" OBJECTS_MEMORY=1 \
  E2E_MASTER_KEY_FILE="$ROOT/e2e/testdata/master-test.pem" E2E_FLY_TOKEN="$JARVIS2_FLY_TOKEN" go run ./kernel)
