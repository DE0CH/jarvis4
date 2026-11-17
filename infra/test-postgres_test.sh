#!/usr/bin/env bash
# infra/test-postgres.sh: a fresh database takes pgvector (`create extension vector`), as magpie's migration 0042
# does in the replica (aviary 045adf3d; the replica's Postgres had no pgvector, 2026-11-17).
#   bash infra/test-postgres_test.sh
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
url=$(bash "$here/test-postgres.sh" fresh pgvector_check)
B=$(dirname "$(command -v psql 2>/dev/null || ls -d /usr/lib/postgresql/*/bin/psql | sort -V | tail -1)")
if ! out=$("$B/psql" -X -q -v ON_ERROR_STOP=1 "${url%%\?*}" -c "create extension if not exists vector" \
  -tAc "select '[1,2]'::vector <-> '[1,3]'::vector" 2>&1); then
  echo "FAIL: pgvector in a fresh database: $out" >&2; exit 1
fi
[ "$(tail -1 <<< "$out")" = 1 ] || { echo "FAIL: vector distance: $out" >&2; exit 1; }
echo "test-postgres: pgvector ok"
