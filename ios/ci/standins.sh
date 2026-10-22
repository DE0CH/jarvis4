#!/bin/bash
# CI stand-ins for the app's tests (app.yml interop + simulator), all on 127.0.0.1 and all throwaway:
#   - a box key and a setup key (standin.py keys); their public halves served at :18099 in place of GitHub
#     (the CI build only — KeySource.swift);
#   - the backup bucket on rclone's S3 server at :18098 (it checks SigV4), seeded with infra/setup.py's own
#     code, encrypted to the public TEST master key; read keys in W/s3.env (ACCESS_KEY=/SECRET_KEY=), which the
#     router gets as BACKUP_READ_*; every bucket's objects also in W/backups.json; W/s3-fresh.sh puts the
#     seeded bucket back (each walkthrough attempt starts from it);
#   - the core (fakefly) and router binaries at W/core, W/router, and W/core-loop.sh, which runs the core again
#     whenever it ends (as Kubernetes does: a wipe ends the core and a new, empty one takes its place).
#     Unless NO_CORE=1 the core (:8090, empty) and a router (:18080, or ROUTER_PORT; reading the stand-in bucket) are
#     started.
# usage: standins.sh W
set -euo pipefail
W="$1"; ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
mkdir -p "$W"
python3 -m venv "$W/venv" && "$W/venv/bin/pip" -q install cryptography boto3
command -v rclone >/dev/null || brew install rclone
PY="$W/venv/bin/python -B"
$PY "$ROOT/ios/ci/standin.py" keys "$W"

secret=$(openssl rand -hex 16)
printf 'ACCESS_KEY=ciaccess\nSECRET_KEY=%s\n' "$secret" > "$W/s3.env"
mkdir -p "$W/s3"
nohup rclone serve s3 --addr 127.0.0.1:18098 --auth-key "ciaccess,$secret" "$W/s3" > "$W/s3.log" 2>&1 & echo $! > "$W/s3.pid"
nohup "$W/venv/bin/python" -m http.server --bind 127.0.0.1 --directory "$W/keys" 18099 > "$W/keys-server.log" 2>&1 &
for i in $(seq 30); do curl -s -o /dev/null http://127.0.0.1:18098/ && curl -sf -o /dev/null http://127.0.0.1:18099/box.pub && break; sleep 1; done
HETZNER_S3_ENDPOINT=http://127.0.0.1:18098 HETZNER_S3_REGION=fsn1 HETZNER_S3_ACCESS_KEY=ciaccess HETZNER_S3_SECRET_KEY="$secret" \
  $PY "$ROOT/ios/ci/standin.py" seed "$W"
# the seeded bucket, kept: W/s3-fresh.sh puts it back before each walkthrough attempt. A bucket a failed attempt left
# behind holds that attempt's backups and the router's line state (keys/_jarvis2/line-state.json), which names the
# fake Fly's machine ids; the next attempt's fresh core numbers its machines from fake000001 again, so the Recover that
# brings that line state back makes the core refuse to certify the new session ("not a started machine without a line")
rm -rf "$W/s3-seeded" && cp -R "$W/s3" "$W/s3-seeded"
cat > "$W/s3-fresh.sh" <<'EOF'
#!/bin/bash
# the stand-in bucket back to its seeded state: rclone stopped (it caches the directory), the files put back, started
# again with the same keys; usage: s3-fresh.sh (W is this script's directory)
W="$(cd "$(dirname "$0")" && pwd)"; . "$W/s3.env"
kill "$(cat "$W/s3.pid")" 2>/dev/null || true; sleep 1
rm -rf "$W/s3" && cp -R "$W/s3-seeded" "$W/s3"
nohup rclone serve s3 --addr 127.0.0.1:18098 --auth-key "$ACCESS_KEY,$SECRET_KEY" "$W/s3" >> "$W/s3.log" 2>&1 & echo $! > "$W/s3.pid"
for i in $(seq 30); do curl -s -o /dev/null http://127.0.0.1:18098/ && exit 0; sleep 1; done
echo "the stand-in bucket didn't come back" >&2; exit 1
EOF
chmod +x "$W/s3-fresh.sh"

(cd "$ROOT/core" && go build -tags fakefly -o "$W/core" .)
(cd "$ROOT/router" && go build -o "$W/router" .)
cat > "$W/core-loop.sh" <<EOF
#!/bin/bash
# the core, started again whenever it ends (a wipe); log to \$1
while true; do BOX_KEY_FILE="$W/box-key.pem" MACHINE_URL=http://ci-router._peer.internal:8081 ADDR=127.0.0.1:8090 "$W/core" >> "\$1" 2>&1; sleep 1; done
EOF
chmod +x "$W/core-loop.sh"
# the router's env for the stand-in bucket (sourced by app.yml)
printf 'BACKUP_READ_ACCESS_KEY=ciaccess\nBACKUP_READ_SECRET_KEY=%s\nBACKUP_ENDPOINT=http://127.0.0.1:18098\nBACKUP_BUCKET=jarvis2-backup-ci\n' "$secret" > "$W/router-backup.env"
if [ "${NO_CORE:-}" != 1 ]; then
  BOX_KEY_FILE="$W/box-key.pem" MACHINE_URL=http://ci-router._peer.internal:8081 ADDR=127.0.0.1:8090 nohup "$W/core" > "$W/core.log" 2>&1 &
  for i in $(seq 30); do curl -sf -o /dev/null http://127.0.0.1:8090/identity && break; sleep 1; done
  mkdir -p "$W/router-data" "$W/web"
  echo '{"harnesses":{"claude":{"stores":["claude-login"]}}}' > "$W/policy.json"
  DBURL="$(bash "$ROOT/infra/test-postgres.sh" fresh router_standins)"  # the router's records (router/statedb.go)
  (set -a; . "$W/router-backup.env"; set +a
   DATABASE_URL="$DBURL" OBJECTS_MEMORY=1 NO_ACCESS=1 CORE_URL=http://127.0.0.1:8090 DATA_DIR="$W/router-data" WEB_DIR="$W/web" POLICY_FILE="$W/policy.json" TASKS_DIR="$ROOT/tasks" \
     ADDR=127.0.0.1:${ROUTER_PORT:-18080} MACHINE_ADDR=127.0.0.1:$((${ROUTER_PORT:-18080}+1)) nohup "$W/router" > "$W/router.log" 2>&1 &)
  for i in $(seq 30); do curl -sf -o /dev/null http://127.0.0.1:${ROUTER_PORT:-18080}/api/state && break; sleep 1; done
  echo "core and router up"
fi
