#!/bin/bash
# fabric-gateway.sh — the fabric's sandbox gateway (docs/PLAN-fabric.md "Infra"): the plain Hetzner server
# jarvis4-fabric-gw, the one box every fabric sandbox's traffic passes, so it only passes packets: WireGuard (the AWS
# hosts' hub), sandboxd's fixed rules and sandboxd in gateway mode as a systemd unit (DE0CH/aviary
# fabric/host/gateway-setup.sh, crates/sandboxd/docs/HOST.md "Gateway on a plain server"). No cluster node, no
# container runtime. Jarvis 4's boxes have no SSH, so the server sets itself up from its cloud-init: the WireGuard key
# and TLS files are in its user data (Hetzner shows user data only to the project's token), and it fetches the bundle
# (sandboxd of the release in k8s/cluster/fabric/gateway.release, aviary's two scripts of that release,
# k8s/cluster/fabric/gateway-host.json) from the fabric bucket through a presigned URL: IPv6 only, and GitHub's
# release downloads have no IPv6.
#
#   infra/fabric-gateway.sh create     firewall jarvis4-fabric-gw (udp 51821 and ICMP in, nothing else), the server
#                                      (cx23, fsn1, Ubuntu 24.04, IPv6 only, Network jarvis2 at 10.77.0.250) and the
#                                      Network's route 10.204.0.0/15 -> 10.77.0.250
#   infra/fabric-gateway.sh replace    a new server in its place (a new release or host.json): the old one deleted
#                                      first, the new one made with the same key (the hosts keep it); every fabric
#                                      sandbox's network is away meanwhile (minutes)
#   infra/fabric-gateway.sh status     the server, its IPv6 (hermit.json fabric.gateway.endpoint) and the route
#
# Env: HETZNER_JARVIS2_MOCK_API; HETZNER_S3_ACCESS_KEY/_SECRET_KEY/_ENDPOINT/_REGION (the bucket); FABRIC_CA_CRT,
# FABRIC_GATEWAY_CRT, FABRIC_GATEWAY_KEY, FABRIC_GATEWAY_WG_KEY. Values never print.
set -euo pipefail
cd "$(dirname "$0")/.."
NAME=jarvis4-fabric-gw NETWORK=12741004 ADDR=10.77.0.250 ROUTE=10.204.0.0/15 TYPE=cx23 LOCATION=fsn1
BUCKET=jarvis4-fabric-6fdff6
: "${HETZNER_JARVIS2_MOCK_API:?}"
export HCLOUD_TOKEN="$HETZNER_JARVIS2_MOCK_API"

s3() {
  AWS_ACCESS_KEY_ID="$HETZNER_S3_ACCESS_KEY" AWS_SECRET_ACCESS_KEY="$HETZNER_S3_SECRET_KEY" \
    AWS_DEFAULT_REGION="$HETZNER_S3_REGION" aws --endpoint-url "$HETZNER_S3_ENDPOINT" "$@"
}

bundle_url() {  # the bundle in the bucket → a presigned URL (6 h)
  local rel t
  rel="$(tr -d ' \n' < k8s/cluster/fabric/gateway.release)"
  [[ $rel =~ ^aviary-[0-9a-f]{12}$ ]] || { echo "k8s/cluster/fabric/gateway.release is not aviary-<sha12>" >&2; exit 1; }
  t="$(mktemp -d)"; mkdir -p "$t/fabric/host"
  for f in gateway-setup.sh fetch-sandboxd.sh; do
    curl -fsSL -o "$t/fabric/host/$f" "https://raw.githubusercontent.com/DE0CH/aviary/$rel/fabric/host/$f"
  done
  bash "$t/fabric/host/fetch-sandboxd.sh" "$t/fabric" "$rel" >/dev/null
  cp k8s/cluster/fabric/gateway-host.json "$t/fabric/host.json"
  tar -cz -C "$t" fabric > "$t/bundle.tgz"
  s3 s3 cp --quiet "$t/bundle.tgz" "s3://$BUCKET/boot/gateway-$rel.tgz" >&2
  rm -rf "$t"
  s3 s3 presign "s3://$BUCKET/boot/gateway-$rel.tgz" --expires-in 21600
}

user_data() {  # cloud-init: the keys, the bundle, gateway-setup.sh
  : "${FABRIC_CA_CRT:?}" "${FABRIC_GATEWAY_CRT:?}" "${FABRIC_GATEWAY_KEY:?}" "${FABRIC_GATEWAY_WG_KEY:?}"
  local url="$1"
  cat <<UD
#!/bin/bash
set -eu
exec > /var/log/fabric-gateway-setup.log 2>&1
systemctl disable --now ssh.socket ssh.service 2>/dev/null || true
install -d -m 700 /etc/sbx /etc/sbx/tls
umask 077
cat > /etc/sbx/wg.key <<'K'
$FABRIC_GATEWAY_WG_KEY
K
cat > /etc/sbx/tls/ca.crt <<'K'
$FABRIC_CA_CRT
K
cat > /etc/sbx/tls/host.crt <<'K'
$FABRIC_GATEWAY_CRT
K
cat > /etc/sbx/tls/host.key <<'K'
$FABRIC_GATEWAY_KEY
K
umask 022
for i in \$(seq 1 30); do curl -fsSL -o /root/bundle.tgz '$url' && break; sleep 10; done
rm -rf /root/fabric && tar -xzf /root/bundle.tgz -C /root
SBX_HOST_JSON=/root/fabric/host.json bash /root/fabric/host/gateway-setup.sh
cat /root/fabric/bin/RELEASE > /etc/sbx/release
echo "fabric gateway up: \$(cat /etc/sbx/release)"
UD
}

firewall() {
  hcloud firewall describe "$NAME" >/dev/null 2>&1 && return
  local rules; rules="$(mktemp)"
  cat > "$rules" <<'J'
[{"direction":"in","protocol":"udp","port":"51821","source_ips":["0.0.0.0/0","::/0"],"description":"WireGuard from the fabric's AWS hosts"},
 {"direction":"in","protocol":"icmp","source_ips":["0.0.0.0/0","::/0"]}]
J
  hcloud firewall create --name "$NAME" --rules-file "$rules" >/dev/null
  rm -f "$rules"
}

create() {
  hcloud server describe "$NAME" >/dev/null 2>&1 && { echo "a server $NAME exists already (replace)"; exit 1; }
  firewall
  local ud; ud="$(mktemp)"; chmod 600 "$ud"
  user_data "$(bundle_url)" > "$ud"
  # attached to the Network at ADDR before it boots (sandboxd takes its private address at start)
  hcloud server create --name "$NAME" --type "$TYPE" --location "$LOCATION" --image ubuntu-24.04 --start-after-create=false \
    --without-ipv4 --firewall "$NAME" --label role=jarvis4-fabric-gw --user-data-from-file "$ud" >/dev/null
  rm -f "$ud"
  hcloud server attach-to-network "$NAME" --network "$NETWORK" --ip "$ADDR" >/dev/null
  hcloud server poweron "$NAME" >/dev/null
  hcloud network describe "$NETWORK" -o json | jq -e --arg r "$ROUTE" '.routes[] | select(.destination == $r)' >/dev/null \
    || hcloud network add-route "$NETWORK" --destination "$ROUTE" --gateway "$ADDR" >/dev/null
  status
}

status() {
  hcloud server describe "$NAME" -o json | jq -r '"\(.name) \(.status) \(.public_net.ipv6.ip) private \(.private_net[0].ip // "-")"'
  hcloud network describe "$NETWORK" -o json | jq -c --arg r "$ROUTE" '[.routes[] | select(.destination == $r)]'
}

case "${1:-}" in
  create) create ;;
  replace) hcloud server delete "$NAME" >/dev/null; create ;;
  status) status ;;
  *) sed -n '2,23p' "$0"; exit 2 ;;
esac
