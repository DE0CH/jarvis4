#!/bin/bash
# convert-ipv6.sh — turn an existing Jarvis 4 box (built with a public IPv4) into an IPv6-only one with Cloudflare WARP
# for the outgoing IPv4 (infra/warp-host.sh), keeping its disk: the box key, age key, k8s Secrets and Flux state stay,
# so nothing is re-minted. The box reboots twice, so the core restarts EMPTY: Deyao Recovers afterwards, as after a
# power failure. Only with Deyao's go for production (docs/RUNBOOK.md "Converting the box to IPv6-only").
#
#   1. graceful shutdown (power off after 3 min)
#   2. the primary IPv4 is unassigned and deleted (Hetzner allows that only while the server is off)
#   3. rescue mode with a throwaway SSH key; boot; SSH in over IPv6; on the box's disk: infra/warp-host.sh as
#      /usr/local/sbin/jarvis2-warp-host.sh + a oneshot unit that runs it at every boot before k3s
#   4. reboot into the box's own system: the unit installs and connects WARP, writes /etc/rancher/k3s/config.yaml
#      (node-ip on the dummy interface k3s0), then k3s starts with it
#   5. waits until the core answers through the tunnel (setup.py identity, as create.sh does)
# Env: HCLOUD_PROJECT_TOKEN (default HETZNER_JARVIS2_MOCK_API), SERVER_LABEL (default role=jarvis2), CONFIRM=yes,
#      SKIP_WAIT=1 (a test box without a core), and what setup.py identity needs (JARVIS2_URL, JARVIS2_SETUP_ACCESS_ID/SECRET, JARVIS2_KEYS_DIR as for create.sh).
# The throwaway key is deleted on exit; the rescue system is single-use (Hetzner turns it off after one boot).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export HCLOUD_PROJECT_TOKEN="${HCLOUD_PROJECT_TOKEN:-${HETZNER_JARVIS2_MOCK_API:-}}"
: "${HCLOUD_PROJECT_TOKEN:?}"
[ "${CONFIRM:-}" = yes ] || { echo "the box reboots and its core restarts empty (Recover afterwards): CONFIRM=yes to go"; exit 2; }
SEL="${SERVER_LABEL:-role=jarvis2}"
API=https://api.hetzner.cloud/v1
hz() { curl -sS -f -X "$1" "$API$2" -H "Authorization: Bearer $HCLOUD_PROJECT_TOKEN" -H "Content-Type: application/json" ${3:+-d "$3"}; }
j() { python3 -c "import json,sys;d=json.load(sys.stdin);print($1)"; }
wait_action() { for i in $(seq 1 120); do st=$(hz GET "/actions/$1" | j "d['action']['status']"); [ "$st" = success ] && return 0; [ "$st" = error ] && { echo "action $1 failed"; return 1; }; sleep 3; done; return 1; }
status() { hz GET "/servers/$SID" | j "d['server']['status']"; }

SID=$(hz GET "/servers?label_selector=$SEL" | j "' '.join(str(s['id']) for s in d['servers'])")
[ -n "$SID" ] && [ "${SID// /}" = "$SID" ] || { echo "need exactly one server with label $SEL, got: '$SID'"; exit 1; }
V4=$(hz GET "/servers/$SID" | j "(d['server']['public_net']['ipv4'] or {}).get('id') or ''")
V6=$(hz GET "/servers/$SID" | j "d['server']['public_net']['ipv6']['ip'].split('/')[0]+'1'")
echo "server $SID, IPv6 $V6, primary IPv4 id: ${V4:-none}"

K="$(mktemp -d)"; KID=""
cleanup() { [ -n "$KID" ] && hz DELETE "/ssh_keys/$KID" >/dev/null 2>&1; rm -rf "$K"; }
trap cleanup EXIT
ssh-keygen -q -t ed25519 -N "" -C jarvis2-convert -f "$K/k"
KID=$(hz POST /ssh_keys "{\"name\":\"jarvis2-convert-$(date +%s)\",\"public_key\":\"$(cat "$K/k.pub")\"}" | j "d['ssh_key']['id']")

echo "1. shutdown"
if [ "$(status)" != off ]; then
  hz POST "/servers/$SID/actions/shutdown" >/dev/null
  for i in $(seq 1 36); do [ "$(status)" = off ] && break; sleep 5; done
  [ "$(status)" = off ] || { echo "no clean shutdown after 3 min: power off"; wait_action "$(hz POST "/servers/$SID/actions/poweroff" | j "d['action']['id']")"; }
fi
echo "2. the primary IPv4"
if [ -n "$V4" ]; then
  wait_action "$(hz POST "/primary_ips/$V4/actions/unassign" | j "d['action']['id']")"
  hz DELETE "/primary_ips/$V4" >/dev/null && echo "primary IP $V4 deleted"
fi
echo "3. rescue"
wait_action "$(hz POST "/servers/$SID/actions/enable_rescue" "{\"type\":\"linux64\",\"ssh_keys\":[$KID]}" | j "d['action']['id']")"
wait_action "$(hz POST "/servers/$SID/actions/poweron" | j "d['action']['id']")"
S=(ssh -q -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -i "$K/k" "root@$V6")
for i in $(seq 1 60); do "${S[@]}" true 2>/dev/null && break; sleep 5; done
"${S[@]}" 'set -e; mkdir -p /mnt/r; lsblk -o NAME,FSTYPE,LABEL,SIZE; d=$(blkid -L cloudimg-rootfs || true); [ -n "$d" ] || d=$(lsblk -lnpo NAME,FSTYPE | awk "\$2==\"ext4\"{print \$1}" | head -n 1); echo "root: $d"; mount "$d" /mnt/r; test -x /mnt/r/usr/local/bin/k3s; echo "root mounted, k3s found"'
"${S[@]}" 'cat > /mnt/r/usr/local/sbin/jarvis2-warp-host.sh' < "$HERE/warp-host.sh"
"${S[@]}" 'set -e; R=/mnt/r
cat > $R/etc/systemd/system/jarvis2-warp-host.service <<"UNIT"
[Unit]
Description=Jarvis 4: IPv4 out through Cloudflare WARP, k3s on its dummy-interface IPv4 (infra/warp-host.sh)
Wants=network-online.target
After=network-online.target
Before=k3s.service
[Service]
Type=oneshot
RemainAfterExit=yes
TimeoutStartSec=15min
ExecStart=/bin/bash -c ". /usr/local/sbin/jarvis2-warp-host.sh && warp_host_setup"
[Install]
WantedBy=multi-user.target
UNIT
mkdir -p $R/etc/systemd/system/multi-user.target.wants $R/etc/systemd/system/k3s.service.d
ln -sf /etc/systemd/system/jarvis2-warp-host.service $R/etc/systemd/system/multi-user.target.wants/jarvis2-warp-host.service
printf "[Unit]\nWants=jarvis2-warp-host.service\nAfter=jarvis2-warp-host.service\n" > $R/etc/systemd/system/k3s.service.d/10-warp.conf
sync; umount $R; echo "unit installed"'
echo "4. reboot into the box's system"
"${S[@]}" 'reboot' || true
[ "${SKIP_WAIT:-}" = 1 ] && { echo "5. skipped (SKIP_WAIT=1: a test box without a core)"; exit 0; }
echo "5. waiting for the core through the tunnel"
for i in $(seq 1 90); do
  python3 "$HERE/setup.py" identity >/dev/null 2>&1 && { echo "up: the core answers through the tunnel and its identity checks (it is a new, empty core: Recover)"; exit 0; }
  sleep 10
done
echo "not up after 15 min"; exit 1
