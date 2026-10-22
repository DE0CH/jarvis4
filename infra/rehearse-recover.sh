#!/bin/bash
# rehearse-recover.sh — the Recover path end to end on a REAL throwaway box, built the way production is built
# as production's control box (infra/cloudflare.py, infra/create.sh BOX_KIND=control, infra/cloud-init.sh, Flux applying
# ./k8s/control/apps with the production images),
# in the Hetzner project "runners", never the jarvis2 project. It never touches the production box, core, router,
# tunnel, Access apps, WireGuard peer or bucket.
#
#   1. its own Cloudflare tunnel + hostname + Access app + service token, its own versioned bucket, a Fly token for
#      the core that expires by itself (6 h), then the box (create.sh) — waits for the core
#   2. Reset with the TEST kit (the public test master key, e2e/testdata), stores written by infra/setup.py
#      (dummy values; not sensitive, sensitive, created-then-marked, the harness's stores, the core's Fly token),
#      and the backups checked in the bucket
#   3. a power failure: the server is hard-reset (Hetzner "reset") → a new, empty core → Recover → every store and
#      its sensitivity back → a session starts on Fly with them (values checked on the machine) → destroyed
#   4. the app's own restart: the kit ends the core (wipe), Kubernetes starts a new, empty one → Recover
#   5. a full rebuild: the server is deleted and create.sh makes a new one (new box key, new peer) → Recover →
#      a session with the stores again
#   6. teardown (also on any failure): servers, firewall, WireGuard peer, the rehearsal cores' Fly machines,
#      Cloudflare tunnel/DNS/Access app/token, every object version and the bucket, the work dir. `teardown` as
#      the only argument runs just that (after a crash); KEEP=1 skips it (then run it yourself).
#
# The app's side (Reset, Recover, unlock, approving a session) is the shell's own CoreSetup/CoreCrypto in
# ios/interop's Rehearse target (needs a swift.org toolchain on Linux: SWIFT_BIN, default ~/swift/*/usr/bin).
#
# Test-only differences from production: infra/rehearsal-box.sh (the router runs NO_ACCESS=1 behind an
# Access app for the rehearsal's service token only). The kit is the public TEST master key, so the bucket holds
# nothing secret: dummy values, and a Fly token narrowed as production's AND expiring after 6 h.
#
# Env: HCLOUD_TOKEN (project runners), JARVIS2_FLY_TOKEN, JARVIS2_SETUP_KEY, CF_JARVIS2_INFRA_TOKEN, CLOUDFLARE_API,
#      HETZNER_S3_* (the admin key of project Cloud Code). Optional: REHEARSAL_NAME (default jarvis2-rehearsal),
#      REHEARSAL_REF (the commit Flux applies; default origin/main), SERVER_TYPE (cx23), SKIP_REBUILD=1.
# Prints no secret. Logs: $REHEARSAL_LOGS (default /tmp/jarvis2-rehearsal-logs).
set -euo pipefail
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/rehearsal-box.sh"
SWIFT_BIN="${SWIFT_BIN:-$(ls -d "$HOME"/swift/*/usr/bin 2>/dev/null | tail -1)}"
if [ "${1:-}" = teardown ]; then teardown; exit 0; fi
[ "${KEEP:-}" = 1 ] || trap teardown EXIT

step "the app's side (swift build)"
(cd "$ROOT/ios/interop" && PATH="$SWIFT_BIN:$PATH" swift build --product Rehearse 2>&1 | tail -1)
RH="$ROOT/ios/interop/.build/debug/Rehearse"

prepare
export REHEARSE_BASE="https://$HOST/" REHEARSE_ACCESS_ID="$SETUP_ACCESS_ID" REHEARSE_ACCESS_SECRET="$SETUP_ACCESS_SECRET"
export REHEARSE_KEYS="$W/keys" REHEARSE_MASTER_PEM="$ROOT/e2e/testdata/master-test.pem" REHEARSE_PHONE="$W/phone.json"

wait_empty() { # → the new empty core's key, recorded for teardown
  "$RH" wait-empty "${1:-}" | tee "$W/wait.out"
  k=$(awk '/^CORE /{print $2}' "$W/wait.out"); echo "$k" >> "$W/cores"; CORE="$k"
}
on_machine() { # on_machine MACHINE CMD → stdout (Machines API exec, the org token)
  python3 - "$1" "$2" <<'PY'
import json, os, sys, urllib.request
req = urllib.request.Request(f"https://api.machines.dev/v1/apps/jarvis4-sessions/machines/{sys.argv[1]}/exec", method="POST",
    data=json.dumps({"command": ["sh", "-c", sys.argv[2]], "timeout": 60}).encode(),
    headers={"Authorization": "Bearer " + os.environ["JARVIS2_FLY_TOKEN"], "Content-Type": "application/json"})
print(json.load(urllib.request.urlopen(req, timeout=90)).get("stdout", "").strip())
PY
}
session_check() { # a session with rh-plain + rh-secret (+ the harness's tunnel): the values on the machine
  "$RH" session rh-plain rh-secret | tee "$W/session.out"
  local sid m
  sid=$(awk '/^SESSION /{print $2}' "$W/session.out"); m=$(awk '/^MACHINE /{print $2}' "$W/session.out")
  for kv in "RH_PLAIN=$V_PLAIN" "RH_SECRET=$V_SECRET" "CF_ACCESS_CLIENT_ID=$V_TUNNEL"; do
    got=""
    for i in $(seq 1 12); do
      got=$(on_machine "$m" "session-secret --keys ${kv%%=*} --exec env | grep -E '^${kv%%=*}=' | grep -c -F '${kv#*=}' || true" 2>/dev/null || true)  # that key's line holds that value (the supervisor's RAM copy)
      [ "$got" = 1 ] && break; sleep 5
    done
    [ "$got" = 1 ] || { echo "FAIL ${kv%%=*} isn't on machine $m with the written value"; exit 1; }
    echo "ok   ${kv%%=*} is on machine $m with the value written before the failure"
  done
  got=$(on_machine "$m" "session-secret --names | grep -cx RH_MARKED || true")
  [ "$got" = 0 ] || { echo "FAIL a store that wasn't picked is on the machine"; exit 1; }
  echo "ok   rh-marked (not picked) is not on the machine"
  "$RH" destroy "$sid"
}

step "the box (infra/create.sh in project runners)"
make_box
echo "server $(server_id) up at $(date -u +%FT%TZ)" | tee -a "$LOGS/servers.log"
wait_empty

step "Reset with the test kit, then the stores (infra/setup.py, dummy values)"
"$RH" reset
rnd=$(python3 -c "import secrets;print(secrets.token_hex(6))")
export V_PLAIN="plain-$rnd" V_SECRET="secret-$rnd" V_MARKED="marked-$rnd" V_TUNNEL="tunnel-id-$rnd"
export RH_PLAIN="$V_PLAIN" RH_SECRET="$V_SECRET" RH_MARKED="$V_MARKED" \
  CF_ACCESS_CLIENT_ID="$V_TUNNEL" CF_ACCESS_CLIENT_SECRET="tunnel-secret-$rnd"
S="python3 $ROOT/infra/setup.py"
export JARVIS2_NOT_SENSITIVE=rh-plain,rh-marked
$S pin-master # a throwaway box and bucket: its own Reset is the one to trust
$S create rh-plain
$S create rh-marked
$S write rh-plain RH_PLAIN --explain 'RH_PLAIN=rehearsal test value'
$S write rh-secret RH_SECRET --explain 'RH_SECRET=rehearsal test value'
$S write rh-marked RH_MARKED --explain 'RH_MARKED=rehearsal test value'
$S mark-sensitive rh-marked
$S write tunnel CF_ACCESS_CLIENT_ID CF_ACCESS_CLIENT_SECRET --explain 'CF_ACCESS_CLIENT_ID=rehearsal dummy tunnel id' --explain 'CF_ACCESS_CLIENT_SECRET=rehearsal dummy tunnel secret'
$S backup-core "$W/fly.tok"
$S stores
python3 - "$W/expect.json" <<'PY'
import json, os, sys
e = lambda sens, **v: {"sensitive": sens, "values": v}
json.dump({"stores": {
    "rh-plain": e(False, RH_PLAIN=os.environ["RH_PLAIN"]),
    "rh-secret": e(True, RH_SECRET=os.environ["RH_SECRET"]),
    "rh-marked": e(True, RH_MARKED=os.environ["RH_MARKED"]),
    "tunnel": e(True, CF_ACCESS_CLIENT_ID=os.environ["CF_ACCESS_CLIENT_ID"], CF_ACCESS_CLIENT_SECRET=os.environ["CF_ACCESS_CLIENT_SECRET"]),
}}, open(sys.argv[1], "w"))
PY
chmod 600 "$W/expect.json"

step "the backups are in the bucket"
python3 - "$BUCKET" <<'PY'
import os, sys, boto3
b = sys.argv[1]
s3 = boto3.client("s3", endpoint_url=os.environ["HETZNER_S3_ENDPOINT"], region_name=os.environ["HETZNER_S3_REGION"],
                  aws_access_key_id=os.environ["HETZNER_S3_ACCESS_KEY"], aws_secret_access_key=os.environ["HETZNER_S3_SECRET_KEY"])
keys = sorted(o["Key"] for o in s3.list_objects_v2(Bucket=b).get("Contents", []))
want = {f"stores/{n}.json" for n in ["rh-plain", "rh-secret", "rh-marked", "tunnel", "core"]} | {"sensitive/rh-marked.json"}
missing = want - set(keys)
print("objects:", keys)
if missing:
    sys.exit(f"FAIL missing backups: {sorted(missing)}")
print("ok   every store's backup and the sensitive marker are in", b)
PY

step "failure 1: the server loses power (Hetzner hard reset) → Recover → a session"
# Linux writes dirty pages back within ~30 s: a power cut seconds after the images were pulled leaves them
# truncated on disk ("exec /router: exec format error" for ever after; seen in the first run, 8 s after the pull),
# which only a rebuild cures. That is a box failing at its very start, not the failure rehearsed here, so wait.
sleep 90
hz POST "/servers/$(server_id)/actions/reset" >/dev/null
OLD="$CORE"; sleep 20
wait_empty "$OLD"
"$RH" recover "$W/expect.json"
session_check

step "a session stuck at boot on a locked store is destroyed at once (no wait for a snapshot)"
"$RH" stuck rh-marked

step "failure 2: the app's restart (the kit ends the core; Kubernetes starts a new one) → Recover"
"$RH" wipe
wait_empty "$CORE"
"$RH" recover "$W/expect.json"

if [ "${SKIP_REBUILD:-}" != 1 ]; then
  step "failure 3: the box is gone (server deleted) → a new box (new box key, new peer) → Recover → a session"
  hz DELETE "/servers/$(server_id)" >/dev/null
  echo "server deleted at $(date -u +%FT%TZ)" | tee -a "$LOGS/servers.log"
  for i in $(seq 1 30); do [ "$(hz GET "/servers?label_selector=rehearsal=$NAME" | python3 -c "import json,sys;print(len(json.load(sys.stdin)['servers']))")" = 0 ] && break; sleep 5; done
  cp "$W/keys/box.pub" "$W/box-old.pub"
  make_box
  cmp -s "$W/box-old.pub" "$W/keys/box.pub" && { echo "FAIL the new box has the old box key"; exit 1; }
  echo "server $(server_id) up at $(date -u +%FT%TZ) (new box key)" | tee -a "$LOGS/servers.log"
  wait_empty
  "$RH" recover "$W/expect.json"
  session_check
fi

step "REHEARSAL PASSED"
