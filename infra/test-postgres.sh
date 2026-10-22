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
# installed with Homebrew or apt when there are none.
set -euo pipefail
D="${TEST_PG_DIR:-${TMPDIR:-/tmp}/jarvis4-test-pg}"
PORT="${TEST_PG_PORT:-55439}"
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
  "$B/pg_ctl" -D "$D" -w -l "$D.log" -o "-p $PORT -c listen_addresses=127.0.0.1 -k $D -c fsync=off" start > /dev/null
}

B="$(bindir)" || {
  if command -v brew > /dev/null; then brew install -q postgresql@17 >&2; else sudo apt-get install -y -qq postgresql >&2; fi
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
