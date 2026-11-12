#!/usr/bin/env bash
# test-postgres.sh — a throwaway Postgres for a router outside the cluster (CI's stand-ins, the e2e scripts, a
# session's tests): the router keeps its records in Postgres (router/statedb.go, docs/STATE.md).
#
#   infra/test-postgres.sh fresh NAME   a new, empty database NAME (dropped first if it exists) on the throwaway server,
#                                       started on first use; prints its DATABASE_URL
#   infra/test-postgres.sh url          the server's base URL (database postgres), started on first use
#   infra/test-postgres.sh stop
#
# The server: a cluster under ${TEST_PG_DIR:-${TMPDIR:-/tmp}/jarvis4-test-pg} on 127.0.0.1:${TEST_PG_PORT:-55439}, trust auth,
# from whatever Postgres binaries are here (pg_config, Homebrew's postgresql@18/17/16, Debian's /usr/lib/postgresql),
# installed with Homebrew or apt when there are none. TLS on (a self-signed certificate) for aviary's services; the router's
# URL says sslmode=disable.
set -euo pipefail
D="${TEST_PG_DIR:-${TMPDIR:-/tmp}/jarvis4-test-pg}"
PORT="${TEST_PG_PORT:-55439}"
LISTEN="${TEST_PG_LISTEN:-127.0.0.1}"  # e.g. "127.0.0.1,10.88.0.1": a network namespace's clients too (infra/e2e-aviary.sh)
TRUST="${TEST_PG_TRUST:-}"             # a CIDR trusted besides loopback (the e2e's namespaces), added to pg_hba.conf once
BASE="postgres://postgres@127.0.0.1:$PORT"

bindir() {
  local b
  if command -v pg_config > /dev/null && b="$(pg_config --bindir)" && [ -x "$b/initdb" ]; then echo "$b"; return; fi
  if command -v brew > /dev/null; then
    for v in 18 17 16; do b="$(brew --prefix "postgresql@$v" 2>/dev/null)/bin"; [ -x "$b/initdb" ] && { echo "$b"; return; }; done
  fi
  b="$(ls -d /usr/lib/postgresql/*/bin 2>/dev/null | sort -V | tail -1)"
  [ -n "$b" ] && [ -x "$b/initdb" ] && { echo "$b"; return; }
  return 1
}

start() {
  "$B/pg_isready" -q -h 127.0.0.1 -p "$PORT" && return
  if [ ! -f "$D/PG_VERSION" ]; then
    mkdir -p "$D"
    "$B/initdb" -D "$D" -U postgres -A trust > "$D.initdb.log"
  fi
  if [ -n "$TRUST" ] && ! grep -q " $TRUST " "$D/pg_hba.conf"; then echo "host all all $TRUST trust" >> "$D/pg_hba.conf"; fi
  # TLS with a self-signed certificate: aviary's services (the e2e's magpie, hermit-jarvis) require it and verify nothing
  [ -f "$D/server.key" ] || openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 -subj /CN=test-postgres \
    -keyout "$D/server.key" -out "$D/server.crt" 2>/dev/null
  chmod 600 "$D/server.key"
  "$B/pg_ctl" -D "$D" -w -l "$D.log" -o "-p $PORT -c listen_addresses=$LISTEN -k $D -c fsync=off -c ssl=on" start > /dev/null
}

B="$(bindir)" || {
  if command -v brew > /dev/null; then brew install -q postgresql@17 >&2; else sudo apt-get update -qq >&2 && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq postgresql >&2; fi
  B="$(bindir)"
}
case "${1:-}" in
  fresh)
    [ -n "${2:-}" ] || { echo "fresh NAME" >&2; exit 2; }
    start
    PGOPTIONS="-c client_min_messages=warning" "$B/psql" -q "$BASE/postgres" -c "DROP DATABASE IF EXISTS \"$2\" WITH (FORCE)" -c "CREATE DATABASE \"$2\"" > /dev/null
    echo "$BASE/$2?sslmode=disable" ;;
  url) start; echo "$BASE/postgres?sslmode=disable" ;;
  stop) "$B/pg_ctl" -D "$D" -m fast stop > /dev/null || true ;;
  *) sed -n '2,13p' "$0"; exit 2 ;;
esac
