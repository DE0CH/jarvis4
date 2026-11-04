#!/usr/bin/env bash
# The session machines' AMI per region: Flatcar (flatcar.json) with the pinned session image already pulled, so a new
# instance's session unit finds it on disk and `docker pull <digest>` downloads nothing (~3 min saved: the 2.9 GB pull).
# Run by .github/workflows/aws.yml with the jarvis4-infra key, before tofu (region/main.tf picks the AMI tagged
# jarvis4_session_image=<the pinned image>). No new trust: the same CI builds and pins the image, and the account that
# could swap an AMI can already swap the template's Flatcar.
#
#   bake.sh bake <region> <image>    bakes and tests the AMI for <image> unless the region has one; prints its id
#   bake.sh prune <region>           deregisters every baked AMI (and snapshot) but the template's default version's
#
# bake: a builder instance (the session template, Flatcar's AMI, t3.large, stop on shutdown) whose Ignition pulls the
# image, re-arms Ignition (/boot/flatcar/first_boot: the next boot reads its own user-data, as a fresh Flatcar does),
# removes itself and powers off; its disk becomes the AMI (tag jarvis4_bake). A test instance from that AMI (t3.medium,
# as a small session) then reports on the console: Ignition ran (its unit ran at all), the image is there, how long
# `docker run` takes, and how far GetConsoleOutput's newest output lags the console. Only then the AMI gets the tag tofu
# reads; a failed test deregisters it.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
TEMPLATE=jarvis4-session
BAKE_TAG=jarvis4_bake
IMAGE_TAG=jarvis4_session_image

log() { echo "[$region] $*" >&2; }
# a failure is an annotation too (a public repo's annotations read without a login; its logs don't)
errf=$(mktemp)
aws() { command aws "$@" 2> >(tee -a "$errf" >&2); }
fail() { log "$*"; echo "::error::[${region:-}] $*" | tr '\n' ' '; echo; }
set -E
trap 'sleep 1; fail "line $LINENO: $BASH_COMMAND failed: $(tail -c 600 "$errf" | tr "\n" " ")"' ERR
# the run's summary, and a notice (annotations read without a login; summaries don't)
summary() {
  echo "::notice::$*"
  [ -n "${GITHUB_STEP_SUMMARY:-}" ] && echo "$*" >>"$GITHUB_STEP_SUMMARY" || true
}

# ignition <unit script>: an Ignition config running the script once at boot as root (update-engine masked, as the
# session's own config does)
ignition() {
  jq -cn --arg script "$1" '{
    ignition: {version: "3.4.0"},
    storage: {files: [{path: "/opt/jarvis4-bake/run.sh", mode: 493,
      contents: {source: ("data:," + ($script | @uri))}}]},
    systemd: {units: [
      {name: "update-engine.service", mask: true},
      {name: "locksmithd.service", mask: true},
      {name: "jarvis4-bake.service", enabled: true, contents: "[Unit]\nAfter=docker.service network-online.target\nRequires=docker.service\nWants=network-online.target\n[Service]\nType=oneshot\nTimeoutStartSec=0\nExecStart=/opt/jarvis4-bake/run.sh\n[Install]\nWantedBy=multi-user.target\n"}
    ]}}'
}

# console <instance>: its newest serial console output (--latest works on a running instance only; a stopped one's is
# the output EC2 kept at its shutdown)
console() {
  local o
  o=$(aws ec2 get-console-output --region "$region" --instance-id "$1" --latest --query Output --output text 2>/dev/null || true)
  if [ -z "$o" ] || [ "$o" = None ]; then
    o=$(aws ec2 get-console-output --region "$region" --instance-id "$1" --query Output --output text 2>/dev/null || true)
  fi
  tr -d '\r' <<<"$o"
}

# run <ami> <type> <shutdown> <user-data file> <name>: an instance from the session template (its network, IMDSv2), no
# jarvis4_source tag (the spawner and the router see only tagged instances); prints its id
run() {
  aws ec2 run-instances --region "$region" --launch-template "LaunchTemplateName=$TEMPLATE" --image-id "$1" \
    --instance-type "$2" --instance-initiated-shutdown-behavior "$3" --user-data "fileb://$4" \
    --block-device-mappings '[{"DeviceName":"/dev/xvda","Ebs":{"VolumeSize":20,"VolumeType":"gp3","Encrypted":true,"DeleteOnTermination":true}}]' \
    --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$5},{Key=$BAKE_TAG,Value=$image}]" \
    --query 'Instances[0].InstanceId' --output text
}

state() { aws ec2 describe-instances --region "$region" --instance-ids "$1" --query 'Reservations[0].Instances[0].State.Name' --output text; }

drop_ami() {
  local snaps
  snaps=$(aws ec2 describe-images --region "$region" --image-ids "$1" --query 'Images[0].BlockDeviceMappings[].Ebs.SnapshotId' --output text 2>/dev/null || true)
  aws ec2 deregister-image --region "$region" --image-id "$1" || true
  for s in $snaps; do [ "$s" = None ] || aws ec2 delete-snapshot --region "$region" --snapshot-id "$s" || true; done
}

bake() {
  region=$1 image=$2
  [[ $image =~ ^ghcr\.io/de0ch/jarvis4-session(:[a-z0-9.-]+)?@sha256:[0-9a-f]{64}$ ]] || { fail "not a pinned session image: $image"; exit 1; }
  have=$(aws ec2 describe-images --region "$region" --owners self --filters "Name=tag:$IMAGE_TAG,Values=$image" Name=state,Values=available --query 'Images[0].ImageId' --output text)
  if [[ $have == ami-* ]]; then log "baked already: $have"; echo "$have"; return; fi
  flatcar=$(jq -r --arg r "$region" '.amis[$r]' "$here/flatcar.json")
  tmp=$(mktemp -d)
  instances=() ami="" tagged=""
  # leaves nothing behind: its instances, and an AMI that didn't pass the test boot
  trap 'for i in "${instances[@]}"; do aws ec2 terminate-instances --region "$region" --instance-ids "$i" >/dev/null 2>&1 || true; done; [ -n "$ami" ] && [ -z "$tagged" ] && drop_ami "$ami"; rm -rf "$tmp"' EXIT

  # 1. the builder
  ignition "#!/bin/bash
say() { echo \"JARVIS4-BAKE \$*\" > /dev/ttyS0; }
t0=\$(date +%s)
if docker pull '$image' >/dev/null && docker image inspect '$image' >/dev/null; then
  say \"pulled in \$(( \$(date +%s) - t0 ))s\"
  systemctl disable jarvis4-bake.service
  rm -rf /etc/systemd/system/jarvis4-bake.service /opt/jarvis4-bake /etc/machine-id /var/log/journal/*
  touch /boot/flatcar/first_boot
  sync
  say OK
else
  say FAILED
fi
systemctl poweroff" >"$tmp/builder.ign"
  b=$(run "$flatcar" t3.large stop "$tmp/builder.ign" jarvis4-bake)
  instances+=("$b")
  log "builder $b from Flatcar $flatcar"
  # its console is read while it runs (a stopped instance's came back empty); the test boot below is what decides
  t0=$(date +%s) seen=""
  until [ "$(state "$b")" = stopped ]; do
    [ $(($(date +%s) - t0)) -lt 1800 ] || { fail "the builder didn't stop in 30 min: $(console "$b" | tail -25)"; exit 1; }
    o=$(console "$b")
    [ -n "$o" ] && seen=$o
    sleep 10
  done
  grep -q 'JARVIS4-BAKE FAILED' <<<"$seen" && { fail "the builder's pull failed: $(tail -25 <<<"$seen")"; exit 1; }
  log "builder up to stopped: $(($(date +%s) - t0)) s; $(grep -o 'JARVIS4-BAKE [a-zA-Z0-9 ]*' <<<"$seen" | tr '\n' ';' || true)"

  # 2. the AMI (no tofu tag yet)
  ami=$(aws ec2 create-image --region "$region" --instance-id "$b" --name "jarvis4-session-$(date -u +%Y%m%d-%H%M%S)" \
    --description "Flatcar $(jq -r .version "$here/flatcar.json") + $image" \
    --tag-specifications "ResourceType=image,Tags=[{Key=$BAKE_TAG,Value=$image}]" "ResourceType=snapshot,Tags=[{Key=$BAKE_TAG,Value=$image}]" \
    --query ImageId --output text)
  log "AMI $ami"
  t0=$(date +%s)
  until [ "$(aws ec2 describe-images --region "$region" --image-ids "$ami" --query 'Images[0].State' --output text)" = available ]; do
    [ $(($(date +%s) - t0)) -lt 2400 ] || { fail "$ami not available in 40 min"; exit 1; }
    sleep 20
  done
  aws ec2 terminate-instances --region "$region" --instance-ids "$b" >/dev/null

  # 3. the test boot: Ignition again (this unit runs at all), the image on disk, docker run's time, the console's lag
  ignition "#!/bin/bash
say() { echo \"JARVIS4-TEST \$*\" > /dev/ttyS0; }
say \"unit at uptime \$(cut -d' ' -f1 /proc/uptime)s\"
if docker image inspect '$image' >/dev/null 2>&1; then p=yes; else p=no; fi
a=\$(date +%s.%N); docker run --rm --network none --entrypoint true '$image' >/dev/null 2>&1; r=\$?; z=\$(date +%s.%N)
say \"present=\$p run=\$(awk \"BEGIN{printf \\\"%.1f\\\", \$z - \$a}\")s exit=\$r\"
for i in \$(seq 1 36); do say \"tick \$(date +%s)\"; sleep 5; done
systemctl poweroff" >"$tmp/test.ign"
  launched=$(date +%s)
  v=$(run "$ami" t3.medium terminate "$tmp/test.ign" jarvis4-bake-test)
  instances+=("$v")
  report="" lag=""
  for _ in $(seq 1 60); do
    sleep 5
    out=$(console "$v")
    if [ -z "$report" ] && grep -q 'JARVIS4-TEST present=' <<<"$out"; then
      u=$(grep -o 'JARVIS4-TEST unit at uptime [0-9.]*s' <<<"$out" | tail -1 || true)
      p=$(grep -o 'JARVIS4-TEST present=.*' <<<"$out" | tail -1 || true)
      report="$u; $p; seen $(($(date +%s) - launched)) s after launch"
    fi
    last=$(grep -o 'JARVIS4-TEST tick [0-9]*' <<<"$out" | tail -1 | awk '{print $3}' || true)
    if [ -n "$last" ]; then
      l=$(($(date +%s) - last))
      { [ -z "$lag" ] || [ "$l" -lt "$lag" ]; } && lag=$l
      [ -n "$report" ] && break
    fi
  done
  [ -n "$report" ] || { fail "the test boot reported nothing (Ignition didn't run again?): $(tail -25 <<<"$out")"; exit 1; }
  log "test: $report; the console's newest output lags it by >= ${lag:-?} s"
  summary "- $region: $ami, $report; console lag >= ${lag:-?} s"
  grep -q 'present=yes' <<<"$report" && grep -q 'exit=0' <<<"$report" || { fail "the image isn't usable on $ami: $report"; exit 1; }

  aws ec2 create-tags --region "$region" --resources "$ami" --tags "Key=$IMAGE_TAG,Value=$image"
  tagged=1
  echo "$ami"
}

prune() {
  region=$1
  keep=$(aws ec2 describe-launch-template-versions --region "$region" --launch-template-name "$TEMPLATE" --versions '$Default' --query 'LaunchTemplateVersions[0].LaunchTemplateData.ImageId' --output text)
  for ami in $(aws ec2 describe-images --region "$region" --owners self --filters "Name=tag-key,Values=$BAKE_TAG" --query 'Images[].ImageId' --output text); do
    [ "$ami" = "$keep" ] && continue
    log "deregistering $ami (the template boots $keep)"
    drop_ami "$ami"
  done
}

case "${1:-}" in
bake) bake "$2" "$3" ;;
prune) prune "$2" ;;
*) sed -n '2,17p' "$0" >&2; exit 2 ;;
esac
