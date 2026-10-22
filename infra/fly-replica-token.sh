#!/bin/bash
# fly-replica-token.sh OUT — the phone replica's Fly token (GitHub environment `replica`, secret REPLICA_FLY_TOKEN;
# docs/RUNBOOK.md "The phone replica"): JARVIS2_FLY_TOKEN narrowed (Fly macaroon caveat IfPresent) to everything on
# app jarvis4-sessions (machines, volumes, exec; ios/ci/replica-stack.sh and replica-setup.sh), the org's WireGuard
# peers (feature wg: the run's own peer) and READ on anything else in the org. Tested 2026-10-20: machines and volumes
# of jarvis4-sessions listed, another app's machines refused (403), a peer created and removed, an app create refused,
# infra/fly-token.sh and fly-read-token.sh narrow it further and their tokens work. No expiry (a CI secret); it dies
# with JARVIS2_FLY_TOKEN. Written to OUT (mode 600), never printed; set it with
#   gh secret set REPLICA_FLY_TOKEN --env replica -R DE0CH/jarvis4 < OUT
set -euo pipefail
: "${JARVIS2_FLY_TOKEN:?}"
OUT="${1:?usage: fly-replica-token.sh OUT}"
APPID="$(curl -s https://api.fly.io/graphql -H "Authorization: Bearer $JARVIS2_FLY_TOKEN" -H "Content-Type: application/json" \
  -d '{"query":"{ app(name:\"jarvis4-sessions\"){ internalNumericId } }"}' | python3 -c "import json,sys;print(json.load(sys.stdin)['data']['app']['internalNumericId'])")"
CAV="$(mktemp)"; trap 'rm -f "$CAV"' EXIT
printf '[{"type":"IfPresent","body":{"ifs":[{"type":"Apps","body":{"apps":{"%s":"rwcdC"}}},{"type":"FeatureSet","body":{"features":{"wg":"rwcdC"}}}],"else":"r"}}]' "$APPID" > "$CAV"
(umask 077; FLY_API_TOKEN="$JARVIS2_FLY_TOKEN" flyctl tokens attenuate -f "$CAV" > "$OUT")
echo "ok: replica token in $OUT"
