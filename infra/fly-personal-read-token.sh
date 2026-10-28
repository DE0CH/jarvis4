#!/bin/bash
# fly-personal-read-token.sh OUT — the router's read-only token for Fly org personal (the Machines view lists its apps:
# Jarvis 1's de0ch-claude-sessions). FLY_PERSONAL_ORG_TOKEN (an org token of
# personal, e.g. the setup session's FLY_API_TOKEN) attenuated offline with the caveat Organization {id, mask "r"}: it
# can list and read, never create, change or exec. A Fly read token still returns every machine's config, env
# included (docs/DECISIONS.md 138). Written to OUT (mode 600), never printed; then
#   infra/router-secrets.py --part flypersonal FLY_PERSONAL_READ_TOKEN=file:OUT
set -euo pipefail
: "${FLY_PERSONAL_ORG_TOKEN:?an org token of personal}"
OUT="${1:?usage: fly-personal-read-token.sh OUT}"
ORGID="$(FLY_API_TOKEN="$FLY_PERSONAL_ORG_TOKEN" flyctl tokens debug 2>/dev/null | python3 -c '
import json, sys
for m in json.load(sys.stdin):
    for c in m["caveats"]:
        if c["type"] == "Organization":
            print(c["body"]["id"]); sys.exit()
sys.exit("no Organization caveat: not an org token")')"
CAV="$(mktemp)"; trap 'rm -f "$CAV"' EXIT
printf '[{"type":"Organization","body":{"id":%s,"mask":"r"}}]' "$ORGID" > "$CAV"
(umask 077; FLY_API_TOKEN="$FLY_PERSONAL_ORG_TOKEN" flyctl tokens attenuate -f "$CAV" > "$OUT")
T="$(cat "$OUT")"
apps=$(curl -s -H "Authorization: $T" "https://api.machines.dev/v1/apps?org_slug=personal" | python3 -c 'import json,sys;print(len(json.load(sys.stdin)["apps"]))')
create=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "Authorization: $T" -H 'Content-Type: application/json' -d '{"config":{"image":"nginx"},"skip_launch":true}' "https://api.machines.dev/v1/apps/de0ch-claude-sessions/machines")
[ "$create" = 403 ] || { echo "the token could create a machine (HTTP $create)"; rm -f "$OUT"; exit 1; }
echo "ok: read-only token for org personal in $OUT ($apps apps listed, create refused)"
