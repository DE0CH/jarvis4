# rehearsal-box.sh — sourced by infra/rehearse-recover.sh: a throwaway Jarvis 2 control box built the way production's
# is (infra/cloudflare.py, infra/create.sh BOX_KIND=control, infra/cloud-init.sh, Flux applying ./k8s/control/apps at a
# pinned commit with the production images), in the Hetzner project "runners", never touching production. No services
# box and no Hetzner Network (PRIVATE_IP=none): search, the iCloud index and watches don't answer on it. See that script's header for what
# it tests, and docs/RUNBOOK.md "Rehearsing Recover".
#
# One Access app on the hostname whose only policy is the service token NAME; the router runs NO_ACCESS=1 (the test
# client can't hold Deyao's email login), so the edge is the only gate. MACHINE_URL → the peer NAME, BACKUP_BUCKET → a bucket of its own, RECORDS_OFF=1 and Discord off (no Storage
# Box or Discord keys on a test box), no secrets Kustomization (encrypted to production's age key); the router's
# backup read key is the admin S3 key, in user-data only (a narrowed one is Console-only), and its FLY_READ_TOKEN a
# fresh read-only narrowing of JARVIS2_FLY_TOKEN (infra/fly-read-token.sh), as production's. All of it rides in the box's
# user-data (cloud-init's SYNC_YAML/EXTRA_MANIFEST), none in git.
# Env: HCLOUD_TOKEN (project runners), JARVIS2_FLY_TOKEN, JARVIS2_SETUP_KEY, CF_JARVIS2_INFRA_TOKEN, CLOUDFLARE_API,
#      HETZNER_S3_*. Optional: REHEARSAL_NAME (the base name, default jarvis2-rehearsal), REHEARSAL_RUN (the run id,
#      digits; default the unix time), REHEARSAL_REF (the commit Flux applies; default origin/main), SERVER_TYPE (cx23),
#      REHEARSAL_LOGS, KEEP=1 (no teardown on exit).
#
# One run at a time per base name, and every run's resources are its own: the box, firewall, WireGuard peer, tunnel,
# hostname, Access apps, service token and bucket are all named NAME = <base>-<run id> (the box also carries the label
# rehearsal-base=<base>). A run refuses to start while another run of the same base has a server, bucket or tunnel
# (a run in flight, or one's leftovers: `<script> teardown <run id>` removes exactly that run's), and teardown only
# ever removes its own run's resources. (Two parallel runs with one shared name each deleted the other's token and
# bucket, 2026-10-13.)
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE="${REHEARSAL_NAME:-jarvis2-rehearsal}"
case "$BASE" in jarvis2-rehearsal*) ;; *) echo "REHEARSAL_NAME must start with jarvis2-rehearsal"; exit 2 ;; esac
# `<script> teardown <run id>`: that run's resources only
if [ "${1:-}" = teardown ]; then
  [ -n "${2:-}" ] || { echo "usage: $0 teardown <run id> (the digits after $BASE- in its names)"; exit 2; }
  REHEARSAL_RUN="$2"
fi
RUN="${REHEARSAL_RUN:-$(date +%s)}"
case "$RUN" in ''|*[!0-9]*) echo "REHEARSAL_RUN must be digits"; exit 2 ;; esac
export REHEARSAL_RUN="$RUN"
# the run's own name for everything (a new bucket name per run, too: Hetzner's S3 refuses a name for a while after
# its bucket was deleted)
NAME="$BASE-$RUN"; HOST="$NAME.deyaochen.com"; BUCKET="$NAME"
: "${HCLOUD_TOKEN:?}" "${JARVIS2_FLY_TOKEN:?}" "${JARVIS2_SETUP_KEY:?}" "${CF_JARVIS2_INFRA_TOKEN:?}" "${CLOUDFLARE_API:?}"
: "${HETZNER_S3_ENDPOINT:?}" "${HETZNER_S3_REGION:?}" "${HETZNER_S3_ACCESS_KEY:?}" "${HETZNER_S3_SECRET_KEY:?}"
LOGS="${REHEARSAL_LOGS:-/tmp/jarvis2-rehearsal-logs}"; mkdir -p "$LOGS"
mkdir -p "$HOME/.jarvis2"
# one run per base at a time on this machine (others() below covers other machines)
if [ "${1:-}" != teardown ]; then
  exec 9>"$HOME/.jarvis2/$BASE.lock"
  flock -n 9 || { echo "another $BASE run (or its teardown) is still going on this machine"; exit 1; }
fi
W="${REHEARSAL_WORK:-$HOME/.jarvis2/$NAME}"; mkdir -p "$W"; chmod 700 "$W"
H="https://api.hetzner.cloud/v1"
step() { echo; echo "######## $* ($(date -u +%H:%M:%S))"; }

hz() { # hz METHOD PATH [JSON]
  curl -sS -X "$1" "$H$2" -H "Authorization: Bearer $HCLOUD_TOKEN" -H "Content-Type: application/json" ${3:+-d "$3"}
}

# another run of the same base (in flight, or its leftovers): its servers, buckets and tunnels, one per line; empty
# when there's none
others() {
  BASE="$BASE" NAME="$NAME" python3 - <<'PY'
import json, os, re, urllib.request, boto3
base, name = os.environ["BASE"], os.environ["NAME"]
# another run's: <base>-<digits>, or <base> alone (a run from before run ids)
other = lambda n: n != name and re.fullmatch(re.escape(base) + r"(-[0-9]+)?", n) is not None
def get(url, token):
    req = urllib.request.Request(url, headers={"Authorization": "Bearer " + token, "User-Agent": "jarvis2-infra/1"})
    return json.load(urllib.request.urlopen(req))
H = "https://api.hetzner.cloud/v1/servers?label_selector="
for sel in ("rehearsal-base=" + base, "rehearsal=" + base):
    for s in get(H + sel, os.environ["HCLOUD_TOKEN"])["servers"]:
        if other(s["labels"].get("rehearsal", "")): print(f"server {s['name']} ({s['id']})")
s3 = boto3.client("s3", endpoint_url=os.environ["HETZNER_S3_ENDPOINT"], region_name=os.environ["HETZNER_S3_REGION"],
                  aws_access_key_id=os.environ["HETZNER_S3_ACCESS_KEY"], aws_secret_access_key=os.environ["HETZNER_S3_SECRET_KEY"])
for b in s3.list_buckets()["Buckets"]:
    if other(b["Name"]): print(f"bucket {b['Name']}")
acct = "ee3b4deef856baf11e1a67b242438325"
for t in get(f"https://api.cloudflare.com/client/v4/accounts/{acct}/cfd_tunnel?is_deleted=false&per_page=1000",
             os.environ["CF_JARVIS2_INFRA_TOKEN"])["result"]:
    if other(t["name"]): print(f"tunnel {t['name']}")
PY
}
refuse_if_others() {
  local o; o=$(others) || { echo "couldn't check for other $BASE runs"; exit 1; }
  [ -z "$o" ] && return 0
  echo "another $BASE run has resources (a run in flight, or its leftovers: 'teardown <run id>' removes one run's):"
  echo "$o" | sed 's/^/  /'
  exit 1
}

teardown() {
  set +e
  step "teardown ($NAME)"
  if declare -F teardown_extra >/dev/null; then teardown_extra; fi
  for id in $(hz GET "/servers?label_selector=rehearsal=$NAME" | python3 -c "import json,sys;print(' '.join(str(s['id']) for s in json.load(sys.stdin)['servers']))"); do
    hz DELETE "/servers/$id" >/dev/null && echo "server $id deleted"
  done
  for i in $(seq 1 20); do
    fw=$(hz GET "/firewalls?name=$NAME" | python3 -c "import json,sys;f=json.load(sys.stdin)['firewalls'];print(f[0]['id'] if f else '')")
    [ -z "$fw" ] && break
    hz DELETE "/firewalls/$fw" | grep -q '"error"' || { echo "firewall $NAME deleted"; break; }
    sleep 5
  done
  FLY_API_TOKEN="$JARVIS2_FLY_TOKEN" flyctl wireguard remove jarvis2-370 "$NAME" >/dev/null 2>&1 && echo "WireGuard peer $NAME removed"
  # the session machines the rehearsal's cores started (each machine names its core: JARVIS2_CORE_KEY; cores file)
  if [ -s "$W/cores" ]; then
    FLY_API_TOKEN="$JARVIS2_FLY_TOKEN" flyctl machines list -a jarvis2-sessions --json 2>/dev/null | python3 -c "
import json,sys
cores=set(open(sys.argv[1]).read().split())
for m in json.load(sys.stdin):
    if (m.get('config',{}).get('env') or {}).get('JARVIS2_CORE_KEY') in cores: print(m['id'])" "$W/cores" | while read -r m; do
      FLY_API_TOKEN="$JARVIS2_FLY_TOKEN" flyctl machines destroy -a jarvis2-sessions --force "$m" >/dev/null 2>&1 && echo "Fly machine $m destroyed"
    done
  fi
  REHEARSAL="$NAME" python3 "$ROOT/infra/cloudflare.py" --delete
  python3 - "$BUCKET" <<'PY'
import os, sys, boto3
s3 = boto3.client("s3", endpoint_url=os.environ["HETZNER_S3_ENDPOINT"], region_name=os.environ["HETZNER_S3_REGION"],
                  aws_access_key_id=os.environ["HETZNER_S3_ACCESS_KEY"], aws_secret_access_key=os.environ["HETZNER_S3_SECRET_KEY"])
# this run's bucket only
for b in [x["Name"] for x in s3.list_buckets()["Buckets"] if x["Name"] == sys.argv[1]]:
    n = 0
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=b):
        for v in page.get("Versions", []) + page.get("DeleteMarkers", []):
            s3.delete_object(Bucket=b, Key=v["Key"], VersionId=v["VersionId"]); n += 1
    s3.delete_bucket(Bucket=b)
    print(f"bucket {b}: {n} object versions and the bucket deleted")
PY
  [ -d "$W" ] && find "$W" -type f -exec shred -u {} + 2>/dev/null; rm -rf "$W"
  echo "teardown done"
}

# prepare: Cloudflare, the bucket, the core's Fly token, the box's Flux sync and Secrets, the env for setup.py
prepare() {
  REF="${REHEARSAL_REF:-$(git -C "$ROOT" ls-remote https://github.com/DE0CH/jarvis2 refs/heads/main | cut -f1)}"
  echo "rehearsal $NAME: https://$HOST/, bucket $BUCKET, Flux at commit $REF"
  refuse_if_others

  step "Cloudflare: tunnel, hostname, Access, service token ($NAME)"
  REHEARSAL="$NAME" python3 "$ROOT/infra/cloudflare.py" "$W/cloudflare.env"
  set -a; . "$W/cloudflare.env"; set +a   # SETUP_ACCESS_ID/SECRET, TUNNEL_TOKEN; not printed

  step "the bucket $BUCKET (versioned, as production's)"
  python3 - "$BUCKET" <<'PY'
import os, sys, time, boto3
b = sys.argv[1]
s3 = boto3.client("s3", endpoint_url=os.environ["HETZNER_S3_ENDPOINT"], region_name=os.environ["HETZNER_S3_REGION"],
                  aws_access_key_id=os.environ["HETZNER_S3_ACCESS_KEY"], aws_secret_access_key=os.environ["HETZNER_S3_SECRET_KEY"])
s3.create_bucket(Bucket=b)
for i in range(30):   # a new bucket can take a few seconds to be found
    try:
        s3.put_bucket_versioning(Bucket=b, VersioningConfiguration={"Status": "Enabled"}); break
    except s3.exceptions.NoSuchBucket:
        time.sleep(2)
else:
    sys.exit(f"bucket {b} never appeared")
print(f"ok: {b}")
PY
  # two runs started together both passed the first check: now each sees the other's bucket, and both stop
  refuse_if_others

  step "the core's Fly token (narrowed as production's, expiring in 6 h)"
  FLY_TOKEN_HOURS=6 bash "$ROOT/infra/fly-token.sh" "$W/fly.tok"

  # the box's Flux sync: production's ./k8s/control/apps at commit REF, one Kustomization per app as production's
  # (k8s/flux/control.yaml), with the test's router and core env (no secrets Kustomization)
  core_patch() { cat <<P
    - target: { kind: Deployment, name: core-$1, namespace: jarvis2-core }
      patch: |
        apiVersion: apps/v1
        kind: Deployment
        metadata: { name: core-$1, namespace: jarvis2-core }
        spec:
          template:
            spec:
              containers:
                - name: core
                  env:
                    - { name: MACHINE_URL, value: "http://$NAME._peer.internal:8081" }
P
  }
  ks() { cat <<K
---
apiVersion: kustomize.toolkit.fluxcd.io/v1
kind: Kustomization
metadata: { name: control-$1, namespace: flux-system }
spec:
  interval: 1m
  retryInterval: 30s
  timeout: 5m
  sourceRef: { kind: GitRepository, name: jarvis2 }
  path: ./k8s/control/apps/$1
  prune: true
  wait: false
  serviceAccountName: flux-applier
K
  }
  { cat <<EOF
apiVersion: source.toolkit.fluxcd.io/v1
kind: GitRepository
metadata: { name: jarvis2, namespace: flux-system }
spec:
  interval: 1m
  url: https://github.com/DE0CH/jarvis4
  ref: { commit: $REF }
EOF
    ks edge
    ks core; echo "  patches:"; core_patch green; core_patch blue
    ks router; cat <<EOF
  patches:
    - target: { kind: Deployment, name: router, namespace: jarvis2-router }
      patch: |
        apiVersion: apps/v1
        kind: Deployment
        metadata: { name: router, namespace: jarvis2-router }
        spec:
          template:
            spec:
              containers:
                - name: router
                  env:
                    - { name: MACHINE_URL, value: "http://$NAME._peer.internal:8081" }
                    - { name: BACKUP_BUCKET, value: "$BUCKET" }
                    - { name: RECORDS_OFF, value: "1" }
                    - { name: DISCORD_SESSION_CHANNELS, value: "off" }
                    - { name: NO_ACCESS, value: "1" }
EOF
  } > "$W/sync.yaml"
  # the router's read-only Fly token (budget cap, Also on Fly, the Machines tab), as production's router has it
  "$ROOT/infra/fly-read-token.sh" "$W/fly-read" >/dev/null
  (umask 077; FLY_READ_FILE="$W/fly-read" python3 - > "$W/extra.yaml" <<'PY'
import json, os
print(json.dumps({"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
                  "metadata": {"name": "router-secrets-backup", "namespace": "jarvis2-router"},
                  "stringData": {"BACKUP_READ_ACCESS_KEY": os.environ["HETZNER_S3_ACCESS_KEY"],
                                 "BACKUP_READ_SECRET_KEY": os.environ["HETZNER_S3_SECRET_KEY"],
                                 "FLY_READ_TOKEN": open(os.environ["FLY_READ_FILE"]).read().strip()}}))
PY
  )
  rm -f "$W/fly-read"
  mkdir -p "$W/keys"; cp "$ROOT/keys/setup.pub" "$W/keys/setup.pub"
  # what setup.py and create.sh's wait need, pointed at the test box
  export JARVIS2_URL="https://$HOST" JARVIS2_BACKUP_BUCKET="$BUCKET" JARVIS2_KEYS_DIR="$W/keys"
  export JARVIS2_SETUP_ACCESS_ID="$SETUP_ACCESS_ID" JARVIS2_SETUP_ACCESS_SECRET="$SETUP_ACCESS_SECRET"
}

make_box() {
  # the project's server limit (or a just-deleted server still counted): wait and try again
  for i in $(seq 1 10); do
    make_box_once > "$W/make.out" 2>&1 && { cat "$W/make.out"; return 0; }
    cat "$W/make.out"
    # the project's IP/server limit, or no room in the location just now ("error during placement")
    grep -q "primary_ip_limit\|resource_limit_exceeded\|resource_unavailable" "$W/make.out" || return 1
    echo "the project's IP/server limit or Hetzner's placement: trying again in 30 s"; sleep 30
  done
  return 1
}
make_box_once() {
  BOX_KIND=control PRIVATE_IP=none HCLOUD_PROJECT_TOKEN="$HCLOUD_TOKEN" WG_PEER="$NAME" CF_ENV="$W/cloudflare.env" KEYS_OUT="$W/keys" FIREWALL="$NAME" \
    LABELS="{\"role\":\"$NAME\",\"rehearsal\":\"$NAME\",\"rehearsal-base\":\"$BASE\",\"session\":\"${SESSION_ID:-none}\"}" \
    SYNC_YAML_FILE="$W/sync.yaml" EXTRA_MANIFEST_FILE="$W/extra.yaml" SERVER_TYPE="${SERVER_TYPE:-cx23}" \
    bash "$ROOT/infra/create.sh" "$NAME" 2>&1 | tee -a "$LOGS/create.log"
  [ "${PIPESTATUS[0]}" = 0 ] || return 1
  # the app checks the core against box.pub (production: keys/box-next.pub becomes keys/box.pub in git)
  mv "$W/keys/box-next.pub" "$W/keys/box.pub"
}
server_id() { hz GET "/servers?label_selector=rehearsal=$NAME" | python3 -c "import json,sys;print(json.load(sys.stdin)['servers'][0]['id'])"; }
