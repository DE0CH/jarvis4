# Jarvis 4 box bootstrap (create.sh prepends a shebang and the variables). Blank Ubuntu → single-node k3s
# → Flux reconciling the box's tree (k8s/flux/<BOX_KIND>.yaml) from the public repo. After this the box takes changes only from git:
# no SSH, no k8s API from outside (the firewall has no inbound rules at all), no admin token. A box that
# git can't fix is replaced, not repaired. Secrets (the tunnel token, the router's WireGuard peer, the box key, the age key) arrive
# in user-data and become k8s Secrets here; the user-data is shredded at the end.
# create.sh also puts infra/warp-host.sh (warp_host_setup) ahead of this file.
# Injected: BOX_KIND  control | services (docs/DESIGN.md "The boxes") | cluster (docs/PLAN-cluster.md: the one cluster's
#           first node; git manages all of it through k8s/cluster, so no bootstrap, tunnel, peer or box key here)
#           TUNNEL_TOKEN WG_CONF (the wg-quick file of `fly wireguard create`) BOX_KEY (the box key, PEM) — not on
#           the services box; on the control box WG_CONF may be empty (a router move brings the peer's config along)
#           AGE_KEY (Flux decrypts the box's SOPS secrets with it)
#           PRIVATE_ALLOW  control box: private addresses allowed in besides answers (empty: none), space-separated
#           SYNC_YAML, EXTRA_MANIFEST  empty in production; a rehearsal box (infra/rehearse-recover.sh) sets them:
#           its own Flux sync (the same ./k8s/control/apps with documented patches) in place of
#           k8s/flux/control.yaml, and the Secrets that sync can't get from git
set -uo pipefail
export DEBIAN_FRONTEND=noninteractive
BOX_KIND="${BOX_KIND:-}" PRIVATE_ALLOW="${PRIVATE_ALLOW:-}"
case "$BOX_KIND" in control|services|cluster) ;; *) echo "BOX_KIND is control, services or cluster"; exit 1 ;; esac
exec > >(tee -a /var/log/jarvis2-bootstrap.log) 2>&1
echo "=== jarvis2 bootstrap $(date -u +%FT%TZ) ==="
apt-get update -y && apt-get install -y --no-install-recommends ca-certificates curl git gnupg
[ -n "${DEBUG_SSH:-}" ] || systemctl disable --now ssh.socket ssh.service 2>/dev/null || true   # a throwaway debug box keeps it (create.sh DEBUG_SSH_PUB)

# The box is IPv6-only (create.sh: no primary IPv4; Deyao, 2026-10-13): IPv4 out through Cloudflare WARP, k3s on an IPv4
# of a dummy interface (infra/warp-host.sh, which create.sh puts ahead of this file). Before anything fetches from GitHub.
warp_host_setup || exit 1

# no pod reaches the metadata address (it keeps serving this user-data: the box key, the age key): dropped in the raw
# table before any of k3s's own rules see it, at every boot, whatever a namespace's NetworkPolicy says (R1 audit)
cat > /etc/systemd/system/jarvis2-no-metadata.service <<'UNIT'
[Unit]
Description=Jarvis 4: pods never reach 169.254.169.254
Before=k3s.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'iptables -t raw -C PREROUTING -d 169.254.169.254 -j DROP 2>/dev/null || iptables -t raw -I PREROUTING -d 169.254.169.254 -j DROP'
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload && systemctl enable --now jarvis2-no-metadata.service

# journald keeps its files across reboots: after a hard reset Alloy ships the previous boot's last minutes
mkdir -p /var/log/journal /etc/systemd/journald.conf.d
printf '[Journal]\nStorage=persistent\nSystemMaxUse=2G\n' > /etc/systemd/journald.conf.d/jarvis2.conf
systemctl restart systemd-journald
# never an unplanned reboot for updates (a control-box reboot empties the core); security updates still install
printf 'Unattended-Upgrade::Automatic-Reboot "false";\n' > /etc/apt/apt.conf.d/52jarvis2-no-reboot
# the Hetzner Network (10.77.0.0/24): the router calls the services box's NodePorts on it, and nothing else may
# come in. Packets arriving on the private interface: answers to our own connections pass, new ones only from
# PRIVATE_ALLOW (services box: the control box's router; control box: none) — in mangle PREROUTING,
# before k3s's NodePort DNAT, at every boot.
cat > /usr/local/sbin/jarvis2-private-guard <<'GUARD'
#!/bin/sh
for i in $(seq 1 30); do IF="$(ip -o -4 addr show | awk '/ 10\.77\./{print $2; exit}')"; [ -n "$IF" ] && break; sleep 2; done
[ -n "$IF" ] || { echo "no private interface"; exit 0; }
iptables -t mangle -N JARVIS2-PRIVATE 2>/dev/null || iptables -t mangle -F JARVIS2-PRIVATE
iptables -t mangle -A JARVIS2-PRIVATE -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
for a in $(cat /etc/jarvis2/private-allow 2>/dev/null); do iptables -t mangle -A JARVIS2-PRIVATE -s "$a" -j RETURN; done
iptables -t mangle -A JARVIS2-PRIVATE -j DROP
iptables -t mangle -C PREROUTING -i "$IF" -j JARVIS2-PRIVATE 2>/dev/null || iptables -t mangle -I PREROUTING -i "$IF" -j JARVIS2-PRIVATE
echo "private guard on $IF: new connections only from $(cat /etc/jarvis2/private-allow 2>/dev/null)"
GUARD
chmod 755 /usr/local/sbin/jarvis2-private-guard
mkdir -p /etc/jarvis2
if [ "$BOX_KIND" = services ]; then echo "10.77.0.2" > /etc/jarvis2/private-allow; else echo "$PRIVATE_ALLOW" > /etc/jarvis2/private-allow; fi
cat > /etc/systemd/system/jarvis2-private-guard.service <<'UNIT'
[Unit]
Description=Jarvis 4: on the private Network, only answers and the allowed peers come in
After=network-online.target
Wants=network-online.target
Before=k3s.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/jarvis2-private-guard
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload && systemctl enable --now jarvis2-private-guard.service
# NodePorts only on the private address; memory kept back for the system so the kubelet evicts before the kernel
# thrashes (DECISIONS 171's lesson)
cat >> /etc/rancher/k3s/config.yaml <<'K3S'
kube-proxy-arg:
- nodeport-addresses=10.77.0.0/24
kubelet-arg:
- system-reserved=cpu=200m,memory=256Mi
- kube-reserved=cpu=200m,memory=256Mi
- eviction-hard=memory.available<200Mi,nodefs.available<10%
- eviction-minimum-reclaim=memory.available=100Mi
K3S

# pinned versions: no lookup of a "latest" (update.k3s.io served a self-signed certificate on 2026-10-10 and every
# unpinned bootstrap failed: "Finding release for channel stable … Download failed"); bump them here
K3S_VERSION=v1.36.5+k3s1 FLUX_VERSION=2.9.6
curl -sfL https://get.k3s.io | INSTALL_K3S_VERSION="$K3S_VERSION" INSTALL_K3S_EXEC="server --disable traefik$([ "$BOX_KIND" != cluster ] || echo " --cluster-init")" sh - || exit 1  # cluster: embedded etcd, so more nodes and control planes can join
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
for i in $(seq 1 60); do kubectl get nodes 2>/dev/null | grep -q ' Ready' && break; sleep 5; done

curl -s https://fluxcd.io/install.sh | FLUX_VERSION="$FLUX_VERSION" bash || exit 1
# only the two controllers Jarvis 4 uses (no Helm, no notifications): less memory on a cx23 control box
flux install --components source-controller,kustomize-controller --timeout 5m || exit 1
if [ "$BOX_KIND" != cluster ]; then  # the cluster: Flux applies k8s/cluster as the controller (git manages it all)
  # a Kustomization that names no service account applies as the powerless `default`, never as the controller
  kubectl -n flux-system patch deployment kustomize-controller --type=json \
    -p='[{"op":"add","path":"/spec/template/spec/containers/0/args/-","value":"--default-service-account=default"}]'
fi
kubectl -n flux-system rollout status deployment/kustomize-controller --timeout=120s

git clone --depth 1 https://github.com/DE0CH/jarvis2.git /root/jarvis2 || exit 1
[ "$BOX_KIND" = cluster ] || kubectl apply -k "/root/jarvis2/k8s/bootstrap-$BOX_KIND" || exit 1
if [ "$BOX_KIND" = control ]; then
  kubectl -n jarvis2-edge create secret generic tunnel-token --from-literal=token="$TUNNEL_TOKEN"
  if [ -n "${WG_CONF:-}" ]; then
    printf '%s\n' "$WG_CONF" > /root/wg.conf
    kubectl -n jarvis2-router create secret generic router-wg --from-file=wg.conf=/root/wg.conf
    shred -u /root/wg.conf
  fi
  printf '%s\n' "$BOX_KEY" > /root/box-key.pem
  kubectl -n jarvis2-core create secret generic core-box-key --from-file=box-key.pem=/root/box-key.pem
  kubectl -n jarvis2-kernel create secret generic kernel-box-key --from-file=box-key.pem=/root/box-key.pem
  shred -u /root/box-key.pem
fi
printf '%s\n' "$AGE_KEY" > /root/age.agekey
kubectl -n flux-system create secret generic sops-age --from-file=age.agekey=/root/age.agekey
shred -u /root/age.agekey
if [ -n "${EXTRA_MANIFEST:-}" ]; then
  printf '%s\n' "$EXTRA_MANIFEST" > /root/extra.yaml
  kubectl apply -f /root/extra.yaml; shred -u /root/extra.yaml
fi
if [ -n "${SYNC_YAML:-}" ]; then
  printf '%s\n' "$SYNC_YAML" | kubectl apply -f - || exit 1
elif [ "$BOX_KIND" = cluster ]; then
  kubectl apply -f /root/jarvis2/k8s/cluster/flux-sync.yaml || exit 1  # Flux keeps it from then on (it is in k8s/cluster)
else
  kubectl apply -f "/root/jarvis2/k8s/flux/$BOX_KIND.yaml" || exit 1
fi
# Grafana Alloy on the host (infra/alloy/box.alloy): pinned, from Grafana's apt repo (IPv6), its module from git,
# its credentials from the k8s Secret jarvis2-obs/alloy (Flux decrypts it; a timer copies it to the host)
ALLOY_VERSION=1.20.1-1  # the apt version (Grafana appends -1)
mkdir -p /etc/apt/keyrings
curl -fsSL https://apt.grafana.com/gpg.key | gpg --yes --dearmor -o /etc/apt/keyrings/grafana.gpg
echo "deb [signed-by=/etc/apt/keyrings/grafana.gpg] https://apt.grafana.com stable main" > /etc/apt/sources.list.d/grafana.list
apt-get update -y && apt-get install -y "alloy=$ALLOY_VERSION" && apt-mark hold alloy
cat > /etc/alloy/config.alloy <<ALLOY
// stub (infra/cloud-init.sh): the module is infra/alloy/box.alloy on main, pulled every 5 min
import.git "jarvis2" {
repository     = "https://github.com/DE0CH/jarvis2"
revision       = "main"
path           = "infra/alloy/box.alloy"
pull_frequency = "5m"
}
jarvis2.main "box" {
box = "$BOX_KIND"
}
ALLOY
mkdir -p /etc/systemd/system/alloy.service.d
cat > /etc/systemd/system/alloy.service.d/jarvis2.conf <<'UNIT'
[Unit]
ConditionPathExists=/etc/alloy/grafana.env
[Service]
# root: it reads /var/log/pods, the journal and containerd's socket
User=root
EnvironmentFile=/etc/alloy/grafana.env
MemoryMax=300M
OOMScoreAdjust=-900
Restart=always
RestartSec=10
UNIT
cat > /usr/local/sbin/jarvis2-alloy-creds <<'CREDS'
#!/bin/sh
# copies the Secret jarvis2-obs/alloy (GRAFANA_*) to /etc/alloy/grafana.env; restarts Alloy when it changed
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
new="$(kubectl -n jarvis2-obs get secret alloy -o json 2>/dev/null | python3 -c 'import base64,json,sys; d=json.load(sys.stdin)["data"]; print("\n".join(k+"="+base64.b64decode(v).decode() for k,v in sorted(d.items())))')" || exit 0
[ -n "$new" ] || exit 0
umask 077
if [ "$new" != "$(cat /etc/alloy/grafana.env 2>/dev/null)" ]; then
printf '%s\n' "$new" > /etc/alloy/grafana.env
systemctl daemon-reload; systemctl enable alloy >/dev/null 2>&1; systemctl restart alloy
fi
CREDS
chmod 700 /usr/local/sbin/jarvis2-alloy-creds
cat > /etc/systemd/system/jarvis2-alloy-creds.service <<'UNIT'
[Unit]
Description=Jarvis 4: Alloy's Grafana credentials from the cluster
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/jarvis2-alloy-creds
UNIT
cat > /etc/systemd/system/jarvis2-alloy-creds.timer <<'UNIT'
[Unit]
Description=Jarvis 4: refresh Alloy's Grafana credentials
[Timer]
OnBootSec=1min
OnUnitActiveSec=5min
[Install]
WantedBy=timers.target
UNIT
systemctl daemon-reload && systemctl enable --now jarvis2-alloy-creds.timer
rm -rf /root/jarvis2
echo "bootstrap COMPLETE $(date -u +%FT%TZ)" > /var/log/jarvis2-bootstrap.done
shred -u /var/lib/cloud/instance/user-data.txt* 2>/dev/null || true
