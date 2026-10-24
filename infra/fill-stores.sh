#!/bin/bash
# fill-stores.sh — after a Reset (docs/RUNBOOK.md "After a Reset"): fill every store in the core and its backup
# (sealed to the master key the core was set up with), minting or rotating every token whose value lived only in
# the old stores and backups, then delete the local copies. Values are never printed.
#
#   github-deploy-keys GITHUB_DEPLOY_KEYS_TOKEN   a new fine-grained PAT jarvis2-deploy-keys: all repositories, Repository
#                      "Administration: read and write" only (sensitive). The core makes each repo's deploy key with it
#                      when Deyao adds the repo in the app; the repos' own stores (github-<repo>) are made there, one
#                      Face ID each, never here. Its line is in the layout file, valued from the file minted below.
#   claude             (no keys)                      a cert naming it gets the router's Claude login; made empty, not
#                      sensitive
#   tunnel             CF_ACCESS_CLIENT_ID/SECRET     Access service token jarvis2-tunnel, rotated
#   core               FLY_API_TOKEN              a fresh infra/fly-token.sh
#   default, identity, infra, money, devices, work, jarvis1   Deyao's own stores by kind: the keys are listed in
#                      claude-env .claude/skills/jarvis2/stores.txt (values from this session's env)
#   openrouter         OPENROUTER_API
#
# Needs: CLOUDFLARE_API, JARVIS2_FLY_TOKEN, JARVIS2_SETUP_*, HETZNER_S3_*, the env values above, and claude-env's
# github-web skill (GITHUB_WEB_DIR, default ~/workspace/claude-env/.claude/skills/github-web; its pat-create-all
# deletes the same-name token first, so the old PAT is revoked).
set -euo pipefail
cd "$(dirname "$0")/.."
LAYOUT="${STORES_LAYOUT:-$HOME/workspace/claude-env/.claude/skills/jarvis2/stores.txt}"
# the values as the supervisor holds them now (a store added after this shell started): re-run with exactly the keys
# this script uses, by name (session-secret; there is no request for all keys)
if [ -z "${FILL_STORES_KEYS_IN_ENV:-}" ]; then
  keys="CLOUDFLARE_API JARVIS2_FLY_TOKEN LOBSTER_TOKEN OPENROUTER_API EXA_API JARVIS2_SETUP_KEY JARVIS2_SETUP_ACCESS_ID
    JARVIS2_SETUP_ACCESS_SECRET HETZNER_S3_ENDPOINT HETZNER_S3_REGION HETZNER_S3_ACCESS_KEY HETZNER_S3_SECRET_KEY
    $(grep -v '^#' "$LAYOUT" | cut -s -d' ' -f2- | tr ' ' '\n' | grep -v '=')"
  exec env FILL_STORES_KEYS_IN_ENV=1 session-secret --keys "$(printf '%s\n' $keys | sort -u | paste -sd,)" --exec bash "$0" "$@"
fi
D=~/.jarvis2; mkdir -p "$D"; chmod 700 "$D"
GW="${GITHUB_WEB_DIR:-$HOME/workspace/claude-env/.claude/skills/github-web}"
for v in CLOUDFLARE_API JARVIS2_FLY_TOKEN LOBSTER_TOKEN OPENROUTER_API EXA_API; do
  [ -n "${!v:-}" ] || { echo "missing env $v"; exit 1; }
done
trap 'shred -u "$D"/fly.tok "$D"/gh-*.token "$D"/j2tunnel.* 2>/dev/null || true' EXIT

(cd "$GW" && NODE_PATH="$(npm root -g)" node github_web.js pat-create-all jarvis2-deploy-keys "$D/gh-deploy-keys.token" Administration=write)

# the deploy-keys PAT: it lists a repo's deploy keys (Administration) and can't write refs (no Contents)
python3 - <<'EOF'
import json, os, urllib.request, urllib.error
t = open(os.path.expanduser("~/.jarvis/gh-deploy-keys.token")).read().strip()
def code(method, path, body=None):
    req = urllib.request.Request("https://api.github.com" + path, method=method, data=json.dumps(body).encode() if body else None,
                                 headers={"Authorization": "Bearer " + t, "User-Agent": "probe", "Accept": "application/vnd.github+json"})
    try:
        return urllib.request.urlopen(req).status
    except urllib.error.HTTPError as e:
        return e.code
assert code("GET", "/repos/DE0CH/jarvis2/keys") == 200, "the deploy-keys PAT can't list deploy keys"
assert code("POST", "/repos/DE0CH/jarvis2/git/refs", {"ref": "refs/heads/zz-probe", "sha": "0" * 40}) in (403, 404), "the deploy-keys PAT can write refs"
print("ok: the deploy-keys PAT manages deploy keys and can't push")
EOF

# the tunnel's Access service token: a new client secret, the same client id (policies keep working)
python3 - <<'EOF'
import json, os, urllib.request
API = "https://api.cloudflare.com/client/v4/accounts/ee3b4deef856baf11e1a67b242438325/access/service_tokens"
H = {"Authorization": "Bearer " + os.environ["CLOUDFLARE_API"], "User-Agent": "curl/8", "Content-Type": "application/json"}
call = lambda m, u: json.load(urllib.request.urlopen(urllib.request.Request(u, method=m, headers=H)))
toks = {t["name"]: t for t in call("GET", API + "?per_page=200")["result"]}
os.umask(0o077)
D = os.path.expanduser("~/.jarvis")
for name, f in [("jarvis2-tunnel", "j2tunnel")]:
    t = toks[name]
    r = call("POST", f"{API}/{t['id']}/rotate")["result"]
    assert r["client_id"] == t["client_id"]
    open(f"{D}/{f}.id", "w").write(r["client_id"])
    open(f"{D}/{f}.secret", "w").write(r["client_secret"])
    print(f"ok: {name} rotated")
EOF
sleep 5
# jarvis2-tunnel passes Access (the Worker then confines it)
c() { curl -s -o /dev/null -w "%{http_code}" -H "CF-Access-Client-Id: $(cat "$D/$1.id")" -H "CF-Access-Client-Secret: $(cat "$D/$1.secret")" "$2"; }
[ "$(c j2tunnel https://tunnel.deyaochen.com/__status/x)" = 403 ] || { echo "a rotated Access token doesn't behave"; exit 1; }

bash infra/fly-token.sh "$D/fly.tok"

S="python3 infra/setup.py"
$S identity | grep -q '^set up' || { echo "the core is empty: Reset in the app first"; exit 1; }
# not sensitive: created first (a store the core never created is sensitive); a store that exists is kept
have="$($S stores | cut -d' ' -f1)"
for n in default openrouter tunnel shopping; do
  grep -qx "$n" <<<"$have" || $S create "$n"
done
# Deyao's own stores, by kind, from the layout file (key names only; private, in claude-env): each line is
# "<store> KEY…", values from this session's env. Only `default` and `shopping` are created (not sensitive); the rest are sensitive.
grep -v '^#' "$LAYOUT" | while read -r store keys; do
  [ -n "$store" ] || continue
  # shellcheck disable=SC2086
  $S write "$store" $keys
done
$S write openrouter OPENROUTER_API
$S write tunnel CF_ACCESS_CLIENT_ID=file:$D/j2tunnel.id CF_ACCESS_CLIENT_SECRET=file:$D/j2tunnel.secret
$S backup-core "$D/fly.tok"
$S stores
echo "ok: every store written to the core and backed up; local copies deleted"
