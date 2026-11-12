#!/bin/bash
# e2e-aviary.sh — the aviary harness end to end, from a session, with no Inbox and nothing of production's touched: the
# kernel's line and a router on this session (as infra/e2e-kernel.sh: a throwaway box key, the public TEST master key,
# e2e/aviary playing the iPhone), the chat stack beside them (hermit-jarvis built from this tree, magpie from its
# pinned image, a TLS Postgres, an S3 stand-in), a stand-in model, and real Fly machines on the session image, which
# reach the router and hermit-jarvis's gateway listener over two throwaway WireGuard peers of the Fly org.
#
#   e2e/aviary: the kernel set up; a Claude account with a fake login; a session with the harness aviary and a first
#   prompt; its machine boots a sandbox through hermit-jarvis, the supervisor runs Claude Code, whose model calls go
#   through the machine's gateway to the stand-in model (a tool call that runs a shell command in the sandbox, then
#   an answer); magpie holds the conversation (checked through magpie's admin API); a wakeup arrives as a later turn;
#   the session is destroyed.
#
# Where things are (all on this session; magpie in its own network namespace, its ports being hermit-jarvis's):
#   router 127.0.0.1:${PP}080 (machines' port ${PP}081), kernel components 127.0.1.1-9:28080 (8080 is hermit-jarvis's, on every address), Postgres 127.0.0.1:${PP}432
#   and 10.88.0.1 (TLS; the router's records, hermit's and magpie's databases), S3 10.88.0.1:${PP}900 (rclone serve s3),
#   magpie 10.88.0.2:8080 (as `http://magpie` to hermit-jarvis), hermit-jarvis 0.0.0.0:8080/8081/8082/9090 (as
#   `http://hermit` to magpie), the stand-in model + the gateway listener's front 127.0.0.1:${PP}085 (e2e/aviary).
#   Machines: http://<peer>._peer.internal:8081 → the router; http://<peer>-chat._peer.internal:8081 → hermit-jarvis's
#   gateway listener, /model/… → the stand-in model (the test store `aviary-gw` names both: AVIARY_GW_URL,
#   AVIARY_MODEL_URL).
#
#   JARVIS2_FLY_TOKEN   the jarvis2-370 org token (the spawner's, the sweep's, the WireGuard peers')
#   E2E_SESSION_IMAGE   the session image (default ghcr.io/de0ch/jarvis4-session:latest), pinned by digest here
#   E2E_ONLY=chat       only the chat stack, kept up until interrupted (debugging; no Fly token needed)
#   E2E_LOGS            where the logs go (default /tmp/jarvis4-e2e-aviary-logs)
# Leaves nothing behind but the logs: every machine naming this run's peer is destroyed with its volume, the peers
# removed, the processes stopped, the namespace and the NAT rules gone. Needs sudo (namespaces, NAT, chroot).
set -euo pipefail
# one run at a time on a machine (its ports, namespace and NAT rules are fixed)
exec 9> /tmp/jarvis4-e2e-aviary.lock
flock -n 9 || { echo "e2e-aviary: another run holds /tmp/jarvis4-e2e-aviary.lock"; exit 1; }
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ONLY="${E2E_ONLY:-}"
[ "$ONLY" = chat ] || : "${JARVIS2_FLY_TOKEN:?}"
PEER=jarvis2-e2e-aviary; CPEER=jarvis2-e2e-aviary-chat; PP=31
LOGS="${E2E_LOGS:-/tmp/jarvis4-e2e-aviary-logs}"
CACHE="${E2E_CACHE:-$HOME/.cache/jarvis4-e2e}"   # the magpie image's root filesystem, rclone
# magpie of the aviary release the session image pins (session-image/aviary.json: aviary-<sha12> → magpie:<sha12>)
REL="$(python3 -I -c 'import json,sys;print(json.load(open(sys.argv[1]))["release"])' "$ROOT/session-image/aviary.json")"
MAGPIE_IMAGE="ghcr.io/de0ch/magpie:${REL#aviary-}@$(crane digest "ghcr.io/de0ch/magpie:${REL#aviary-}")"
W="$(mktemp -d)"; chmod 755 "$W"
# How the machines reach this run. On a Fly machine of the sessions' org (a session): straight over Fly's private
# network, to this machine's own 6PN address (the router's machines' port and e2e/aviary's front listen there; both
# answer only signed or throwaway requests). Elsewhere: two throwaway WireGuard peers of the org, each served by
# `router m-gateway` (as production's machines reach the router).
if [ -n "${FLY_MACHINE_ID:-}" ] && [ -n "${FLY_APP_NAME:-}" ]; then
  HOST6="$(getent hosts "$FLY_MACHINE_ID.vm.$FLY_APP_NAME.internal" | awk '{print $1; exit}')"
  MURL="http://$FLY_MACHINE_ID.vm.$FLY_APP_NAME.internal:${PP}081"; CURL="http://$FLY_MACHINE_ID.vm.$FLY_APP_NAME.internal:${PP}085"
  MADDR="[$HOST6]:${PP}081"; FRONT="[$HOST6]:${PP}085"
else
  HOST6=""; MURL="http://$PEER._peer.internal:8081"; CURL="http://$CPEER._peer.internal:8081"
  MADDR="127.0.0.1:${PP}081"; FRONT="127.0.0.1:${PP}085"
fi
NS=e2e-aviary-mag
PIDS=(); SUDO_PIDS=()

sweep() {
  [ -n "${JARVIS2_FLY_TOKEN:-}" ] || return 0
  curl -fsS -H "Authorization: Bearer $JARVIS2_FLY_TOKEN" https://api.machines.dev/v1/apps/jarvis4-sessions/machines 2>/dev/null \
    | python3 -I -c '
import json, sys
want = sys.argv[1]
for m in json.load(sys.stdin):
    if m.get("state") != "destroyed" and ((m.get("config") or {}).get("env") or {}).get("JARVIS2_URL") == want:
        print(m["id"], " ".join(x.get("volume", "") for x in ((m.get("config") or {}).get("mounts") or [])))' "$MURL" \
    | while read -r m vols; do
        curl -fsS -o /dev/null -X DELETE -H "Authorization: Bearer $JARVIS2_FLY_TOKEN" \
          "https://api.machines.dev/v1/apps/jarvis4-sessions/machines/$m?force=true" && echo "e2e-aviary: destroyed machine $m"
        for v in $vols; do
          for _ in 1 2 3 4 5 6; do
            curl -fsS -o /dev/null -X DELETE -H "Authorization: Bearer $JARVIS2_FLY_TOKEN" \
              "https://api.machines.dev/v1/apps/jarvis4-sessions/volumes/$v" && break; sleep 5
          done
        done
      done
}
nat() { # the NAT rules this run adds, removed again at the end (-D)
  local op=$1
  sudo -n iptables -t nat "$op" PREROUTING -i e2e-avm0 -p tcp --dport 80 -j REDIRECT --to-ports 8080 2>/dev/null || true
  sudo -n ip netns exec "$NS" iptables -t nat "$op" PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports 8080 2>/dev/null || true
}
cleanup() {
  set +e
  mkdir -p "$LOGS"; cp "$W"/*.log "$LOGS"/ 2>/dev/null
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
  for p in "${SUDO_PIDS[@]}"; do sudo -n pkill -P "$p" 2>/dev/null; sudo -n kill "$p" 2>/dev/null; done
  sleep 1
  sweep
  if [ -n "${JARVIS2_FLY_TOKEN:-}" ]; then
    for p in "$PEER" "$CPEER"; do FLY_API_TOKEN="$JARVIS2_FLY_TOKEN" flyctl wireguard remove jarvis2-370 "$p" >/dev/null 2>&1; done
  fi
  nat -D
  sudo -n ip netns del "$NS" 2>/dev/null; sudo -n ip link del e2e-avm0 2>/dev/null
  TEST_PG_DIR="$W/pg" TEST_PG_PORT="${PP}432" "$ROOT/infra/test-postgres.sh" stop
  sudo -n rm -rf "$W"
  echo "e2e-aviary: logs in $LOGS"
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP
sweep

# ---- builds
export PATH="/opt/cargo/bin:$HOME/.cargo/bin:$PATH"
( cd "$ROOT/aviary" && CARGO_INCREMENTAL=0 cargo build --release --locked --bin hermit-jarvis )
HERMIT_BIN="$(cd "$ROOT/aviary" && cargo metadata --format-version 1 --no-deps | python3 -c 'import json,sys;print(json.load(sys.stdin)["target_directory"])')/release/hermit-jarvis"
mkdir -p "$CACHE"
if [ ! -x "$CACHE/rclone" ]; then
  curl -fsSL -o "$W/rclone.zip" https://downloads.rclone.org/rclone-current-linux-amd64.zip
  python3 -I -c 'import zipfile,sys;z=zipfile.ZipFile(sys.argv[1]);n=[x for x in z.namelist() if x.endswith("/rclone")][0];open(sys.argv[2],"wb").write(z.read(n))' "$W/rclone.zip" "$CACHE/rclone"
  chmod +x "$CACHE/rclone"; rm -f "$W/rclone.zip"
fi
MROOT="$CACHE/magpie-${MAGPIE_IMAGE##*sha256:}"
if [ ! -x "$MROOT/usr/local/bin/magpie" ]; then
  sudo -n rm -rf "$MROOT.tmp"; mkdir -p "$MROOT.tmp"
  crane export "$MAGPIE_IMAGE" - | sudo -n tar -x -C "$MROOT.tmp"
  sudo -n mv "$MROOT.tmp" "$MROOT"
fi

# ---- the network namespace for magpie: 10.88.0.1 (here) ↔ 10.88.0.2 (magpie)
sudo -n ip netns del "$NS" 2>/dev/null || true; sudo -n ip link del e2e-avm0 2>/dev/null || true
sudo -n ip netns add "$NS"
sudo -n ip link add e2e-avm0 type veth peer name e2e-avm1
sudo -n ip link set e2e-avm1 netns "$NS"
sudo -n ip addr add 10.88.0.1/30 dev e2e-avm0; sudo -n ip link set e2e-avm0 up
sudo -n ip netns exec "$NS" ip addr add 10.88.0.2/30 dev e2e-avm1
sudo -n ip netns exec "$NS" ip link set e2e-avm1 up
sudo -n ip netns exec "$NS" ip link set lo up
nat -A   # `http://hermit` (port 80) from magpie → hermit-jarvis's 8080 here; `http://magpie` (80) → magpie's 8080

# ---- Postgres (TLS) and S3
export TEST_PG_DIR="$W/pg" TEST_PG_PORT="${PP}432" TEST_PG_LISTEN="127.0.0.1,10.88.0.1" TEST_PG_TRUST="10.88.0.0/30"
"$ROOT/infra/test-postgres.sh" fresh magpie > /dev/null
HERMIT_DB="$("$ROOT/infra/test-postgres.sh" fresh hermit | sed 's/sslmode=disable/sslmode=require/')"
ROUTER_DB="$("$ROOT/infra/test-postgres.sh" fresh router)"
MAGPIE_DB="postgres://postgres@10.88.0.1:${PP}432/magpie?sslmode=require"
S3K="e2e$(openssl rand -hex 8)"; S3S="$(openssl rand -hex 24)"
mkdir -p "$W/s3/magpie"
"$CACHE/rclone" serve s3 --addr "10.88.0.1:${PP}900" --auth-key "$S3K,$S3S" --force-path-style=true "$W/s3" > "$W/s3.log" 2>&1 & PIDS+=($!)

# ---- the chat stack's keys (as DE0CH/services infra/chat-keys.py makes them)
tok() { openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n'; }
declare -A K
for pair in PIGEON_MAGPIE PIGEON_HERMIT PIGEON_MODEL GATEWAY_MAGPIE GATEWAY_HERMIT HERMIT_MAGPIE MAGPIE_HERMIT ADMIN_MAGPIE ADMIN_HERMIT; do K[$pair]="$(tok)"; done
ADMIN_MAGPIE="${K[ADMIN_MAGPIE]}"

# magpie: its image's root, in the namespace, as its image's user, `http://hermit` = 10.88.0.1
sudo -n sh -c "printf '127.0.0.1 localhost\n10.88.0.1 hermit\n' > '$MROOT/etc/hosts'; mkdir -p '$MROOT/tmp'; chmod 1777 '$MROOT/tmp'"
cat > "$W/magpie-env" <<ENV
POD_NAME=magpie-e2e
MAGPIE_DATABASE_URL=$MAGPIE_DB
MAGPIE_S3_ENDPOINT=http://10.88.0.1:${PP}900
MAGPIE_S3_REGION=us-east-1
MAGPIE_S3_BUCKET=magpie
MAGPIE_S3_ACCESS_KEY_ID=$S3K
MAGPIE_S3_SECRET_ACCESS_KEY=$S3S
MAGPIE_ACCEPT_PIGEON=${K[PIGEON_MAGPIE]}
MAGPIE_ACCEPT_GATEWAY=${K[GATEWAY_MAGPIE]}
MAGPIE_ACCEPT_HERMIT=${K[HERMIT_MAGPIE]}
MAGPIE_ACCEPT_ADMIN=${K[ADMIN_MAGPIE]}
MAGPIE_TOKEN_HERMIT=${K[MAGPIE_HERMIT]}
ENV
sudo -n ip netns exec "$NS" env -i PATH=/usr/local/bin:/usr/bin:/bin $(cat "$W/magpie-env") \
  /usr/sbin/chroot --userspec=10001:10001 "$MROOT" /usr/local/bin/magpie serve > "$W/magpie.log" 2>&1 & SUDO_PIDS+=($!)

# hermit-jarvis: here, `http://magpie` = 10.88.0.2 (its own /etc/hosts, a private mount namespace)
{ cat /etc/hosts; echo "10.88.0.2 magpie"; } > "$W/hosts-hermit"
cat > "$W/hermit-env" <<ENV
POD_NAME=hermit-e2e
HERMIT_DATABASE_URL=$HERMIT_DB
HERMIT_TOKEN_KEYS=1:$(tok)
HERMIT_JARVIS_URL=http://127.0.0.1:${PP}080
HERMIT_JARVIS_ACCESS_ID=e2e
HERMIT_JARVIS_ACCESS_SECRET=e2e
HERMIT_OWNER=e2e@example.com
HERMIT_ACCESS_TEAM=e2e.cloudflareaccess.com
HERMIT_ACCESS_AUD=e2e
HERMIT_ACCEPT_PIGEON=${K[PIGEON_HERMIT]}
HERMIT_ACCEPT_MAGPIE=${K[MAGPIE_HERMIT]}
HERMIT_ACCEPT_GATEWAY=${K[GATEWAY_HERMIT]}
HERMIT_ACCEPT_ADMIN=${K[ADMIN_HERMIT]}
MODEL_ACCEPT_PIGEON=${K[PIGEON_MODEL]}
HERMIT_TOKEN_MAGPIE=${K[HERMIT_MAGPIE]}
GATEWAY_TOKEN_MAGPIE=${K[GATEWAY_MAGPIE]}
GATEWAY_TOKEN_HERMIT=${K[GATEWAY_HERMIT]}
ENV
sudo -n unshare -m --propagation private sh -c 'mount --bind "$0" /etc/hosts && exec setpriv --reuid="$1" --regid="$2" --clear-groups env -i PATH=/usr/bin:/bin $(cat "$3") "$4"' \
  "$W/hosts-hermit" "$(id -u)" "$(id -g)" "$W/hermit-env" "$HERMIT_BIN" > "$W/hermit.log" 2>&1 & SUDO_PIDS+=($!)

ready() { # ready NAME URL
  for _ in $(seq 1 90); do curl -sf -o /dev/null -m 2 "$2" && { echo "e2e-aviary: $1 ready"; return 0; }; sleep 1; done
  echo "e2e-aviary: $1 never became ready ($2)"; tail -20 "$W/$1.log"; exit 1
}
ready magpie http://10.88.0.2:9090/readyz
ready hermit http://127.0.0.1:9090/readyz

if [ "$ONLY" = chat ]; then
  echo "e2e-aviary: chat stack up (Ctrl-C ends it): magpie 10.88.0.2:8080 (admin token in $W/magpie-env), hermit 127.0.0.1:8080"
  echo "$W"; wait
fi

# ---- the kernel's line and the router (as infra/e2e-kernel.sh), the machines' peers through `router m-gateway`
for r in notary notarizer mover merger spawner identity gullible minter secrets; do (cd "$ROOT/kernel" && go build -o "$W/$r" "./cmd/$r"); done
(cd "$ROOT/router" && go build -o "$W/router" .)
(cd "$ROOT/e2e" && go build -o "$W/e2e-aviary" ./aviary)
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$W/box-key.pem" 2>/dev/null
# the root key (the app's, in production): the components check their roster against it; e2e/aviary signs with it
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$W/root-key.pem" 2>/dev/null
KERNEL_ROOT="$(openssl pkey -in "$W/root-key.pem" -pubout -outform DER 2>/dev/null | tail -c 65 | base64 -w0)"
echo '{"harnesses":{"aviary":{"stores":["aviary-gw"],"claudeAccount":true}}}' > "$W/policy.json"
if [ -z "$HOST6" ]; then
  for p in "$PEER" "$CPEER"; do FLY_API_TOKEN="$JARVIS2_FLY_TOKEN" flyctl wireguard remove jarvis2-370 "$p" >/dev/null 2>&1 || true; done
  (umask 077; FLY_API_TOKEN="$JARVIS2_FLY_TOKEN" flyctl wireguard create jarvis2-370 lhr "$PEER" "$W/wg.conf" >/dev/null)
  (umask 077; FLY_API_TOKEN="$JARVIS2_FLY_TOKEN" flyctl wireguard create jarvis2-370 lhr "$CPEER" "$W/wg-chat.conf" >/dev/null)
fi

cp /etc/hosts "$W/hosts"
n=1; KADDRS=""
for r in notary notarizer mover merger spawner identity gullible minter secrets; do
  mkdir -p "$W/k-$r"
  extra=""; [ "$r" = spawner ] && extra="KERNEL_MACHINE_URL=$MURL"; [ "$r" = secrets ] && extra="KERNEL_MINTER_URL=http://127.0.1.8:28080"
  env KERNEL_ROOT="$KERNEL_ROOT" KERNEL_BOX_KEY="$W/box-key.pem" KERNEL_DATA="$W/k-$r" KERNEL_ADDR="127.0.1.$n:28080" $extra \
    "$W/$r" > "$W/kernel-$r.log" 2>&1 & PIDS+=($!)
  echo "127.0.1.$n $r-blue.kernel.e2e" >> "$W/hosts"
  KADDRS="$KADDRS$r=http://127.0.1.$n:28080,"
  n=$((n+1))
done
SESSION_IMAGE="$("$ROOT/infra/image-digest.sh" "${E2E_SESSION_IMAGE:-ghcr.io/de0ch/jarvis4-session:latest}")"
mkdir -p "$W/data" "$W/web"
cat > "$W/router-env" <<ENV
exec env -i PATH="$PATH" HOME="$HOME" DATABASE_URL="$ROUTER_DB" ROUTER_THROWAWAY=1 \\
  KERNEL_URL=http://%s.kernel.e2e:28080 NO_ACCESS=1 RECORDS_OFF=1 ADDR=127.0.0.1:${PP}080 MACHINE_ADDR=$MADDR \\
  DATA_DIR="$W/data" WEB_DIR="$W/web" MACHINE_URL="$MURL" POLICY_FILE="$W/policy.json" TASKS_DIR="$ROOT/tasks" \\
  SESSION_IMAGE="$SESSION_IMAGE" "$W/router"
ENV
chmod 700 "$W/router-env"
sudo -n unshare -m --propagation private sh -c 'mount --bind "$0" /etc/hosts && exec setpriv --reuid="$1" --regid="$2" --clear-groups "$3"' \
  "$W/hosts" "$(id -u)" "$(id -g)" "$W/router-env" > "$W/router.log" 2>&1 & SUDO_PIDS+=($!)
# off Fly, the machines' peers: the router's machines' port, and hermit-jarvis's gateway listener behind e2e/aviary's front
if [ -z "$HOST6" ]; then
  POD_NAME=m-gateway-0 WG_CONFIGS="$W/wg.conf" M_GATEWAY_TO="http://127.0.0.1:${PP}081" HEALTH_ADDR="127.0.0.1:${PP}082" \
    "$W/router" m-gateway > "$W/m-gateway.log" 2>&1 & PIDS+=($!)
  POD_NAME=m-gateway-0 WG_CONFIGS="$W/wg-chat.conf" M_GATEWAY_TO="http://127.0.0.1:${PP}085" HEALTH_ADDR="127.0.0.1:${PP}083" \
    "$W/router" m-gateway > "$W/m-gateway-chat.log" 2>&1 & PIDS+=($!)
fi
ready router "http://127.0.0.1:${PP}080/api/kernel"

# in the background + wait: a signal ends the run (and cleans up) at once, not after the driver's current wait
(exec env E2E_ROUTER="http://127.0.0.1:${PP}080" E2E_SPAWNER=http://127.0.1.5:28080 E2E_DATABASE_URL="$ROUTER_DB" \
  ROUTER_THROWAWAY=1 E2E_DATA_DIR="$W/data" E2E_MASTER_KEY_FILE="$ROOT/e2e/testdata/master-test.pem" E2E_ROOT_KEY_FILE="$W/root-key.pem" E2E_KERNEL="$KADDRS" E2E_FLY_TOKEN="$JARVIS2_FLY_TOKEN" \
  E2E_FRONT_ADDR="$FRONT" E2E_HERMIT_GW=http://127.0.0.1:8081 E2E_CHAT_URL="$CURL" \
  E2E_MAGPIE=http://10.88.0.2:8080 E2E_MAGPIE_ADMIN="$ADMIN_MAGPIE" "$W/e2e-aviary") & DRIVER=$!; PIDS+=($DRIVER)
wait "$DRIVER"
