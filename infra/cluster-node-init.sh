# Jarvis 4: an extra node's bootstrap (infra/cluster-node.sh prepends a shebang, the variables and infra/warp-host.sh).
# Blank Ubuntu → IPv6-only host with WARP for IPv4 → k3s AGENT joined to the one cluster over the Hetzner Network. After
# this the node takes changes only from git (Flux on the cluster; k8s/cluster/nodes/node-net.yaml keeps its network):
# no SSH, nothing inbound on the public side (the Hetzner firewall "jarvis2" has no rules), the user-data shredded.
# Injected: K3S_NODE_IP   this node's k3s0 address (10.254.254.<last octet of its private address>)
#           K3S_URL       https://<the server's k3s0 address>:6443 (the server's certificate names it)
#           K3S_TOKEN     a bootstrap token (<id>.<secret>, expires in hours; k8s/cluster/nodes/join-token.enc.yaml)
#           NODE_LABELS   space-separated k=v (e.g. jarvis4/pool=services)
#           PEERS         every node's private and k3s0 addresses (the private guard admits them)
#           GATEWAY PRIVATE_PREFIX K3S_RANGE   as in k8s/cluster/nodes/node-net.yaml
#           K3S_VERSION   the server's k3s version (infra/cloud-init.sh)
set -uo pipefail
export DEBIAN_FRONTEND=noninteractive
exec > >(tee -a /var/log/jarvis2-bootstrap.log) 2>&1
echo "=== jarvis4 node bootstrap $(date -u +%FT%TZ) ==="
apt-get update -y && apt-get install -y --no-install-recommends ca-certificates curl gnupg
[ -n "${DEBUG_SSH:-}" ] || systemctl disable --now ssh.socket ssh.service 2>/dev/null || true

warp_host_setup || exit 1   # infra/warp-host.sh, with K3S_NODE_IP set above

# no pod reaches the metadata address (it keeps serving this user-data: the join token)
cat > /etc/systemd/system/jarvis2-no-metadata.service <<'UNIT'
[Unit]
Description=Jarvis 4: pods never reach 169.254.169.254
Before=k3s-agent.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'iptables -t raw -C PREROUTING -d 169.254.169.254 -j DROP 2>/dev/null || iptables -t raw -I PREROUTING -d 169.254.169.254 -j DROP'
[Install]
WantedBy=multi-user.target
UNIT
mkdir -p /var/log/journal /etc/systemd/journald.conf.d
printf '[Journal]\nStorage=persistent\nSystemMaxUse=2G\n' > /etc/systemd/journald.conf.d/jarvis2.conf
systemctl restart systemd-journald
printf 'Unattended-Upgrade::Automatic-Reboot "false";\n' > /etc/apt/apt.conf.d/52jarvis2-no-reboot

# the private guard, as on the server (infra/cloud-init.sh): new connections in on the private interface only from the
# other nodes; node-net (k8s/cluster/nodes) keeps the list from then on
cat > /usr/local/sbin/jarvis2-private-guard <<'GUARD'
#!/bin/sh
for i in $(seq 1 30); do IF="$(ip -o -4 addr show | awk -v p=" $(cat /etc/jarvis2/private-prefix)" 'index($0, p) {print $2; exit}')"; [ -n "$IF" ] && break; sleep 2; done
[ -n "$IF" ] || { echo "no private interface"; exit 0; }
iptables -t mangle -N JARVIS2-PRIVATE 2>/dev/null || iptables -t mangle -F JARVIS2-PRIVATE
iptables -t mangle -A JARVIS2-PRIVATE -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
for a in $(cat /etc/jarvis2/private-allow 2>/dev/null); do iptables -t mangle -A JARVIS2-PRIVATE -s "$a" -j RETURN; done
iptables -t mangle -A JARVIS2-PRIVATE -j DROP
iptables -t mangle -C PREROUTING -i "$IF" -j JARVIS2-PRIVATE 2>/dev/null || iptables -t mangle -I PREROUTING -i "$IF" -j JARVIS2-PRIVATE
# the other nodes' k3s0 addresses over the Network's gateway (node-net keeps it too)
ip route replace "$(cat /etc/jarvis2/k3s-range)" via "$(cat /etc/jarvis2/gateway)" dev "$IF" onlink
echo "private guard on $IF: new connections only from $(cat /etc/jarvis2/private-allow 2>/dev/null)"
GUARD
chmod 755 /usr/local/sbin/jarvis2-private-guard
mkdir -p /etc/jarvis2
printf '%s\n' $PEERS > /etc/jarvis2/private-allow
printf '%s' "$PRIVATE_PREFIX" > /etc/jarvis2/private-prefix
printf '%s' "$K3S_RANGE" > /etc/jarvis2/k3s-range
printf '%s' "$GATEWAY" > /etc/jarvis2/gateway
cat > /etc/systemd/system/jarvis2-private-guard.service <<'UNIT'
[Unit]
Description=Jarvis 4: on the private Network, only answers and the other nodes come in
After=network-online.target
Wants=network-online.target
Before=k3s-agent.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/jarvis2-private-guard
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload && systemctl enable --now jarvis2-no-metadata.service jarvis2-private-guard.service

# warp-host.sh wrote node-ip, flannel-iface and resolv-conf; the agent adds its labels and the same reservations as the server
{
  echo "node-label:"; for l in $NODE_LABELS; do echo "- $l"; done
  cat <<'K3S'
kubelet-arg:
- system-reserved=cpu=200m,memory=256Mi
- kube-reserved=cpu=200m,memory=256Mi
- eviction-hard=memory.available<200Mi,nodefs.available<10%
- eviction-minimum-reclaim=memory.available=100Mi
K3S
} >> /etc/rancher/k3s/config.yaml
curl -sfL https://get.k3s.io | INSTALL_K3S_VERSION="$K3S_VERSION" K3S_URL="$K3S_URL" K3S_TOKEN="$K3S_TOKEN" INSTALL_K3S_EXEC="agent" sh - || exit 1
for i in $(seq 1 60); do systemctl is-active -q k3s-agent && break; sleep 5; done
systemctl is-active k3s-agent
# the user-data held the join token: gone from disk (the metadata service keeps it until it expires; pods can't reach it)
rm -f /var/lib/cloud/instance/user-data.txt /var/lib/cloud/instance/user-data.txt.i /var/lib/cloud/instance/scripts/part-* 2>/dev/null
echo "=== jarvis4 node bootstrap done $(date -u +%FT%TZ) ==="
