#!/bin/bash
# box-logs.sh SERVER_ID — read the logs of a box that doesn't come up (no SSH, no k8s API, no Alloy yet), through
# Hetzner's rescue system: a throwaway SSH key, rescue mode, a reset, SSH in over IPv6, the box's root disk mounted
# read-only, then its bootstrap log (/var/log/jarvis2-bootstrap.log), cloud-init's output and the last of the journal
# (k3s, warp-svc, alloy; persistent on the two-box layout) are printed; then the box reboots into its own system.
#   HCLOUD_PROJECT_TOKEN   the project's token (production: HETZNER_JARVIS2_MOCK_API; rehearsals: HETZNER_RUNNERS_ROUTER_TOKEN)
#   CONFIRM=yes            required: the box RESETS twice. A control box's cores come back empty (Recover); never for a
#                          box that serves, only one that never came up or is already lost.
# A box that does come up ships the same logs to Grafana (infra/alloy/box.alloy): look there first.
set -euo pipefail
SID="${1:?usage: box-logs.sh SERVER_ID}"
: "${HCLOUD_PROJECT_TOKEN:?}"
[ "${CONFIRM:-}" = yes ] || { echo "the box resets (twice); CONFIRM=yes to go"; exit 2; }
API=https://api.hetzner.cloud/v1
hz() { curl -sS --fail-with-body -X "$1" "$API$2" -H "Authorization: Bearer $HCLOUD_PROJECT_TOKEN" -H "Content-Type: application/json" ${3:+-d "$3"}; }
j() { python3 -c "import json,sys;d=json.load(sys.stdin);print($1)"; }
wait_action() { for i in $(seq 1 120); do st=$(hz GET "/actions/$1" | j "d['action']['status']"); [ "$st" = success ] && return 0; [ "$st" = error ] && { echo "action $1 failed"; return 1; }; sleep 3; done; return 1; }
V6=$(hz GET "/servers/$SID" | j "d['server']['public_net']['ipv6']['ip'].split('/')[0]+'1'")
NAME=$(hz GET "/servers/$SID" | j "d['server']['name']")
echo "server $SID ($NAME), $V6"
K="$(mktemp -d)"; KID=""
cleanup() { [ -n "$KID" ] && hz DELETE "/ssh_keys/$KID" >/dev/null 2>&1; rm -rf "$K"; }
trap cleanup EXIT
ssh-keygen -q -t ed25519 -N "" -C jarvis2-box-logs -f "$K/k"
KID=$(hz POST /ssh_keys "{\"name\":\"jarvis2-box-logs-$(date +%s)\",\"public_key\":\"$(cat "$K/k.pub")\"}" | j "d['ssh_key']['id']")
# the box's firewall lets nothing in: a rescue SSH needs port 22 for the length of this script
FWS=$(hz GET "/servers/$SID" | j "' '.join(str(f['id']) for f in d['server']['public_net'].get('firewalls',[]))")
for f in $FWS; do
  RULES=$(hz GET "/firewalls/$f" | python3 -c "import json,sys;print(json.dumps(json.load(sys.stdin)['firewall']['rules']))")
  echo "$f $RULES" >> "$K/fw"
  hz POST "/firewalls/$f/actions/set_rules" "{\"rules\":$(python3 -c "import json,sys;r=json.loads(sys.argv[1]);r=r if any(x.get('port')=='22' for x in r) else r+[{'direction':'in','protocol':'tcp','port':'22','source_ips':['::/0']}];print(json.dumps(r))" "$RULES")}" >/dev/null
done
restore_fw() { [ -f "$K/fw" ] && while read -r f r; do hz POST "/firewalls/$f/actions/set_rules" "{\"rules\":$r}" >/dev/null; done < "$K/fw"; }
trap 'restore_fw; cleanup' EXIT
wait_action "$(hz POST "/servers/$SID/actions/enable_rescue" "{\"type\":\"linux64\",\"ssh_keys\":[$KID]}" | j "d['action']['id']")"
wait_action "$(hz POST "/servers/$SID/actions/reset" | j "d['action']['id']")"
S=(ssh -q -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -i "$K/k" "root@$V6")
for i in $(seq 1 60); do "${S[@]}" true 2>/dev/null && break; sleep 5; done
"${S[@]}" 'set -e; mkdir -p /mnt/r; d=$(blkid -L cloudimg-rootfs || true); [ -n "$d" ] || d=$(lsblk -lnpo NAME,FSTYPE | awk "\$2==\"ext4\"{print \$1}" | head -n 1); mount -o ro "$d" /mnt/r
echo "===== /var/log/jarvis2-bootstrap.log (last 120 lines)"; tail -n 120 /mnt/r/var/log/jarvis2-bootstrap.log 2>&1 || true
echo "===== bootstrap done marker"; cat /mnt/r/var/log/jarvis2-bootstrap.done 2>&1 || true
echo "===== cloud-init-output.log (last 60)"; tail -n 60 /mnt/r/var/log/cloud-init-output.log 2>&1 || true
for p in /mnt/r/var/log/pods/flux-system_kustomize-controller* /mnt/r/var/log/pods/jarvis2-*; do [ -d "$p" ] || continue; echo "===== pod log $(basename $p) (last 30)"; tail -q -n 30 $p/*/*.log 2>/dev/null | cut -c1-3000; done
if [ -d /mnt/r/var/log/journal ]; then for u in k3s warp-svc alloy jarvis2-private-guard; do echo "===== journal $u (last 40)"; journalctl -D /mnt/r/var/log/journal -u $u -n 40 --no-pager 2>&1 || true; done; fi'
echo "rebooting into the box's own system"
wait_action "$(hz POST "/servers/$SID/actions/reset" | j "d['action']['id']")"
