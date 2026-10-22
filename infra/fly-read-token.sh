#!/bin/bash
# fly-read-token.sh OUT — the router's Fly token (budget cap, "Also on Fly"): JARVIS2_FLY_TOKEN narrowed to READ
# on app jarvis4-sessions and nothing else (Fly macaroon caveat Apps {id: "r"}; exec needs more than read).
# Written to OUT (mode 600), never printed; infra/router-secrets.py puts it in the router's secrets.
set -euo pipefail
: "${JARVIS2_FLY_TOKEN:?}"
OUT="${1:?usage: fly-read-token.sh OUT}"
APPID="$(curl -s https://api.fly.io/graphql -H "Authorization: Bearer $JARVIS2_FLY_TOKEN" -H "Content-Type: application/json" \
  -d '{"query":"{ app(name:\"jarvis4-sessions\"){ internalNumericId } }"}' | python3 -c "import json,sys;print(json.load(sys.stdin)['data']['app']['internalNumericId'])")"
CAV="$(mktemp)"; trap 'rm -f "$CAV"' EXIT
printf '[{"type":"Apps","body":{"apps":{"%s":"r"}}}]' "$APPID" > "$CAV"
(umask 077; FLY_API_TOKEN="$JARVIS2_FLY_TOKEN" flyctl tokens attenuate -f "$CAV" > "$OUT")
echo "ok: read-only token in $OUT"
