#!/bin/bash
# cluster-node.sh — add a k3s AGENT node to Jarvis 4's one cluster (docs/PLAN-cluster.md), in one command, with nothing
# done by hand on any host (no node has SSH; the cluster changes only through git):
#
#   infra/cluster-node.sh add NAME [TYPE]      e.g. infra/cluster-node.sh add jarvis2-cluster-2 cx43
#
# Needs HETZNER_JARVIS2_MOCK_API (the Hetzner project "jarvis2", which owns jarvis2-cluster-1 and the Network
# "jarvis2"), GITHUB_TOKEN (push to DE0CH/jarvis4) and GRAFANA_READ_TOKEN (to see Flux apply and the node join); run
# from a clean, up-to-date clone of DE0CH/jarvis4 (main). Values never print.
#
# What it does:
#  1. picks the node's private address (the first free 10.77.0.N, N >= 5) and its k3s0 address 10.254.254.N
#  2. git: a bootstrap token (expires in 4 h) as a SOPS Secret kube-system/bootstrap-token-<id>
#     (k8s/cluster/nodes/join-token.enc.yaml), the node in k8s/cluster/nodes/node-net.yaml's NODES, `nodes` in
#     k8s/cluster/kustomization.yaml; pushes and waits until Flux has applied that commit and node-net has run on the
#     server (its route to 10.254.254.0/24 and its private guard opened to the new node)
#  3. the Network's routes: each node's k3s0 /32 via its private address (10.254.254.1 via 10.77.0.4, …). These routes
#     sit on the Network Jarvis 2's boxes share; they change nothing for them (their 10.254.254.1 is local to each)
#  4. the server: TYPE (default cx43) in fsn1, IPv6 only, the firewall "jarvis2" (no inbound rules), label
#     role=jarvis2-cluster, attached to the Network at its address before it boots; user-data = infra/warp-host.sh +
#     infra/cluster-node-init.sh (WARP for IPv4, the private guard, k3s agent with node label jarvis4/pool=services)
#  5. waits until the server's k3s logs the node, then takes the join token out of git (Flux prunes it)
# Afterwards: Jarvis 4's shared services may go on (infra/services-seed.sh, then `services` in
# k8s/cluster/kustomization.yaml). The node ships its logs and metrics to Grafana by itself (the Alloy DaemonSet
# k8s/cluster/obs, label node="NAME").
set -euo pipefail
cd "$(dirname "$0")/.."
: "${HETZNER_JARVIS2_MOCK_API:?}" "${GITHUB_TOKEN:?}" "${GRAFANA_READ_TOKEN:?}"
[ "${1:-}" = add ] && [ -n "${2:-}" ] || { sed -n '2,25p' "$0"; exit 1; }
NAME="$2" TYPE="${3:-cx43}"
NETWORK=12741004 FIREWALL=11759046 LOCATION=fsn1 GATEWAY=10.77.0.1
SERVER_PRIV=10.77.0.4 SERVER_K3S=10.254.254.1
K3S_VERSION="$(grep -oE 'K3S_VERSION=v[^ ]+' infra/cloud-init.sh | head -1 | cut -d= -f2)"
export HCLOUD_TOKEN="$HETZNER_JARVIS2_MOCK_API"
LOKI="https://logs-prod-012.grafana.net/loki/api/v1/query_range"

[ -z "$(git status --porcelain)" ] || { echo "the clone has local changes"; exit 1; }
git pull -q --rebase origin main
hcloud server describe "$NAME" >/dev/null 2>&1 && { echo "a server $NAME exists already"; exit 1; }

# 1. addresses
used="$(hcloud server list -o json | python3 -c 'import json,sys; print(" ".join(p["ip"] for s in json.load(sys.stdin) for p in s["private_net"]))')"
N=5; while echo " $used " | grep -q " 10.77.0.$N "; do N=$((N+1)); done
PRIV="10.77.0.$N" K3S_IP="10.254.254.$N"
echo "node $NAME ($TYPE): private $PRIV, k3s0 $K3S_IP"

loki() {  # loki QUERY SINCE_UNIX → the matching lines (newest 200)
  curl -s -u "1833850:$GRAFANA_READ_TOKEN" -G "$LOKI" --data-urlencode "query=$1" --data-urlencode "start=${2}000000000" \
    --data-urlencode limit=200 | python3 -c 'import json,sys; [print(l) for s in json.load(sys.stdin).get("data",{}).get("result",[]) for _,l in s["values"]]'
}
push() {
  git commit -qam "$1"
  for i in 1 2 3 4 5; do
    git push -q "https://x-access-token:${GITHUB_TOKEN}@github.com/DE0CH/jarvis4.git" HEAD:main 2>/dev/null && return 0
    git pull -q --rebase origin main
  done
  echo "push failed"; exit 1
}
wait_flux() {  # until Flux reports a revision containing $1 applied (a later commit counts too; max 10 min)
  local since rev; since=$(($(date +%s) - 60))
  for i in $(seq 1 60); do
    for rev in $(loki '{box="cluster", namespace="flux-system"} |= "Reconciliation finished" |= "\"name\":\"cluster\""' "$since" \
                 | grep -oE 'main@sha1:[0-9a-f]{40}' | cut -d: -f2 | sort -u); do
      git fetch -q origin main
      git merge-base --is-ancestor "$1" "$rev" 2>/dev/null && return 0
    done
    sleep 10
  done
  echo "Flux didn't apply $1 within 10 min"; exit 1
}

# 2. git: the join token, node-net, the nodes tree
TID="$(python3 -c 'import secrets,string; a=string.ascii_lowercase+string.digits; print("".join(secrets.choice(a) for _ in range(6)))')"
TSEC_FILE="$(mktemp -p /dev/shm)"; trap 'shred -u "$TSEC_FILE" 2>/dev/null || true' EXIT
python3 -c 'import secrets,string; a=string.ascii_lowercase+string.digits; print("".join(secrets.choice(a) for _ in range(16)), end="")' > "$TSEC_FILE"
EXP="$(date -u -d '+4 hours' +%FT%TZ)"
python3 - "$TID" "$TSEC_FILE" "$EXP" "$NAME" <<'PY'
import json, os, subprocess, sys
tid, secf, exp, name = sys.argv[1:5]
doc = {"apiVersion": "v1", "kind": "Secret", "type": "bootstrap.kubernetes.io/token",
       "metadata": {"name": "bootstrap-token-" + tid, "namespace": "kube-system"},
       "stringData": {"token-id": tid, "token-secret": open(secf).read(), "expiration": exp,
                      "description": "infra/cluster-node.sh: " + name + " joins", "usage-bootstrap-authentication": "true",
                      "usage-bootstrap-signing": "true", "auth-extra-groups": "system:bootstrappers:k3s:default-node-token"}}
tmp = "/dev/shm/join-token-" + tid + ".yaml"
fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w") as f:
    json.dump(doc, f)
try:
    enc = subprocess.run(["sops", "--encrypt", "--age", open("keys/cluster-age.pub").read().strip(), "--encrypted-regex",
                          "^(data|stringData)$", "--input-type", "yaml", "--output-type", "yaml", tmp],
                         check=True, capture_output=True).stdout
finally:
    os.remove(tmp)
open("k8s/cluster/nodes/join-token.enc.yaml", "wb").write(enc)
PY
python3 - "$PRIV" "$K3S_IP" <<'PY'
import re, sys
priv, k3s = sys.argv[1:3]
f = "k8s/cluster/nodes/node-net.yaml"; s = open(f).read()
m = re.search(r"  NODES: \|\n((?:    \S+ \S+\n)+)", s)
if f"    {priv} {k3s}\n" not in m.group(1):
    s = s[:m.end(1)] + f"    {priv} {k3s}\n" + s[m.end(1):]
open(f, "w").write(s)
f = "k8s/cluster/nodes/kustomization.yaml"; s = open(f).read()
if "join-token.enc.yaml" not in s:
    s = s.replace("resources: [node-net.yaml]", "resources: [node-net.yaml, join-token.enc.yaml]")
open(f, "w").write(s)
f = "k8s/cluster/kustomization.yaml"; s = open(f).read()
m = re.search(r"resources: \[([^\]]*)\]", s)
items = [x.strip() for x in m.group(1).split(",")]
if "nodes" not in items:
    s = s[:m.start()] + "resources: [" + ", ".join(items + ["nodes"]) + "]" + s[m.end():]
open(f, "w").write(s)
PY
git add k8s/cluster/nodes/join-token.enc.yaml
kubectl kustomize k8s/cluster >/dev/null
push "cluster: node $NAME ($PRIV) joins: its join token (expires $EXP) and its addresses in node-net"
REV="$(git rev-parse HEAD)"
echo "pushed $REV; waiting for Flux"
wait_flux "$REV"
sleep 75   # node-net's next round on the server
echo "Flux applied it"

# 3. the Network's routes to each node's k3s0 address
python3 - "$NETWORK" "$SERVER_K3S" "$SERVER_PRIV" "$K3S_IP" "$PRIV" <<'PY'
import json, os, sys, urllib.request
net, pairs = sys.argv[1], list(zip(sys.argv[2::2], sys.argv[3::2]))
H = {"Authorization": "Bearer " + os.environ["HCLOUD_TOKEN"], "Content-Type": "application/json"}
def call(m, p, b=None):
    r = urllib.request.Request("https://api.hetzner.cloud/v1" + p, method=m, headers=H, data=json.dumps(b).encode() if b else None)
    return json.load(urllib.request.urlopen(r))
have = {(r["destination"], r["gateway"]) for r in call("GET", f"/networks/{net}")["network"]["routes"]}
for dst, gw in pairs:
    if (dst + "/32", gw) not in have:
        call("POST", f"/networks/{net}/actions/add_route", {"destination": dst + "/32", "gateway": gw})
        print("route", dst + "/32", "via", gw)
PY

# 4. the server
UD="$(mktemp -p /dev/shm)"; trap 'shred -u "$TSEC_FILE" "$UD" 2>/dev/null || true' EXIT
{
  echo '#!/bin/bash'
  cat infra/warp-host.sh
  printf 'K3S_NODE_IP=%q K3S_URL=%q K3S_TOKEN=%q NODE_LABELS=%q\n' "$K3S_IP" "https://$SERVER_K3S:6443" "$TID.$(cat "$TSEC_FILE")" "jarvis4/pool=services"
  printf 'PEERS=%q GATEWAY=%q PRIVATE_PREFIX=%q K3S_RANGE=%q K3S_VERSION=%q\n' \
    "$(sed -n '/  NODES: |/,/^  [A-Z]/p' k8s/cluster/nodes/node-net.yaml | grep -E '^    [0-9]' | tr -s ' \n' ' ')" "$GATEWAY" "10.77." "10.254.254.0/24" "$K3S_VERSION"
  cat infra/cluster-node-init.sh
} > "$UD"
hcloud server create --name "$NAME" --type "$TYPE" --image ubuntu-24.04 --location "$LOCATION" --without-ipv4 \
  --firewall "$FIREWALL" --label role=jarvis2-cluster --start-after-create=false --user-data-from-file "$UD" >/dev/null
hcloud server attach-to-network "$NAME" --network "$NETWORK" --ip "$PRIV" >/dev/null
hcloud server poweron "$NAME" >/dev/null
echo "server $NAME started; waiting for it to join (up to 15 min)"

# 5. joined → the token leaves git
since=$(($(date +%s) - 60)) ok=
for i in $(seq 1 90); do
  if loki '{box="cluster"} |= "node-password secret '"$NAME"'.node-password"' "$since" | grep -q .; then ok=1; break; fi
  sleep 10
done
[ -n "$ok" ] || { echo "no sign of $NAME joining in the server's logs after 15 min; the join token stays until it expires ($EXP)"; exit 1; }
echo "$NAME joined"
git pull -q --rebase origin main
git rm -q k8s/cluster/nodes/join-token.enc.yaml
sed -i 's/resources: \[node-net.yaml, join-token.enc.yaml\]/resources: [node-net.yaml]/' k8s/cluster/nodes/kustomization.yaml
push "cluster: $NAME joined; its join token leaves git (Flux deletes the Secret)"
echo "ok: $NAME is a node of the cluster (label jarvis4/pool=services)"
