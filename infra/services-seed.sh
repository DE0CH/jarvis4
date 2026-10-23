#!/bin/bash
# services-seed.sh — the one-time seed of Jarvis 4's shared services (k8s/cluster/services): copy the indexes' copies
# Jarvis 2 keeps on the Storage Box (claude-records/.jarvis2-services/) into Jarvis 4's own directory
# (claude-records/.jarvis4-services/), server side (WebDAV COPY, nothing downloaded), so the new volumes seed from them and
# the embeddings are never paid twice. Run it right before `services` is listed in
# k8s/cluster/kustomization.yaml (a fresh copy means less to reindex). Never overwrites: a file Jarvis 4's services
# already wrote stays (Overwrite: F); Jarvis 2's directory is only read.
#   search.db.gz            the transcript search index
# The iCloud index's copy is not seeded: it is not part of Jarvis (Deyao, 2026-10-22; k8s/cluster/services).
# Needs STORAGEBOX_HOST / STORAGEBOX_USER / STORAGEBOX_PASSWORD (infra store; or run it under session-secret --keys … --exec).
set -euo pipefail
: "${STORAGEBOX_HOST:?}" "${STORAGEBOX_USER:?}" "${STORAGEBOX_PASSWORD:?}"
B="https://$STORAGEBOX_HOST/claude-records"
dav() { curl -sS -o /dev/null -w '%{http_code}' -u "$STORAGEBOX_USER:$STORAGEBOX_PASSWORD" "$@"; }
c="$(dav -X MKCOL "$B/.jarvis4-services/")"
case "$c" in 201|405) ;; *) echo "MKCOL .jarvis4-services: HTTP $c"; exit 1 ;; esac
for f in search.db.gz; do
  c="$(dav -X COPY -H "Destination: $B/.jarvis4-services/$f" -H "Overwrite: F" "$B/.jarvis2-services/$f")"
  case "$c" in
    201|204) echo "ok: $f copied" ;;
    412) echo "ok: $f already in .jarvis4-services (kept)" ;;
    *) echo "COPY $f: HTTP $c"; exit 1 ;;
  esac
done
