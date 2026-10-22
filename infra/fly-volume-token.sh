#!/bin/bash
# fly-volume-token.sh OUT — the router's volume sweep token (router/volsweep.go, DECISIONS 195): JARVIS2_FLY_TOKEN
# narrowed (Fly macaroon caveats) to DELETE on app jarvis4-sessions AND delete on volumes (Volumes {"" (any id): "d"}).
# The Volumes caveat refuses every access that names no volume (Fly's resset: ErrResourceUnspecified), so the token
# can't list, read, create, start, stop, update, exec or delete machines, read the app, its secrets or any other app,
# delete the app, or create, extend or snapshot a volume: only DELETE /v1/apps/jarvis4-sessions/volumes/<id>.
# Tested 2026-10-20 with the same caveats on a throwaway app (DECISIONS 195 lists every call): all refused (403 /
# GraphQL "Not authorized"), an unattached volume deleted (200), an attached one refused by Fly (412). Listing is the
# read-only FLY_READ_TOKEN's job. Written to OUT (mode 600), never printed; infra/router-secrets.py --part flyvolumes
# puts it in the router's secrets.
set -euo pipefail
: "${JARVIS2_FLY_TOKEN:?}"
OUT="${1:?usage: fly-volume-token.sh OUT}"
APPID="$(curl -s https://api.fly.io/graphql -H "Authorization: Bearer $JARVIS2_FLY_TOKEN" -H "Content-Type: application/json" \
  -d '{"query":"{ app(name:\"jarvis4-sessions\"){ internalNumericId } }"}' | python3 -c "import json,sys;print(json.load(sys.stdin)['data']['app']['internalNumericId'])")"
CAV="$(mktemp)"; trap 'rm -f "$CAV"' EXIT
printf '[{"type":"Apps","body":{"apps":{"%s":"d"}}},{"type":"Volumes","body":{"volumes":{"":"d"}}}]' "$APPID" > "$CAV"
(umask 077; FLY_API_TOKEN="$JARVIS2_FLY_TOKEN" flyctl tokens attenuate -f "$CAV" > "$OUT")
echo "ok: volume-delete-only token in $OUT"
