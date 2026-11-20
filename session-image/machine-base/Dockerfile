# Jarvis 4's machine base (docs/PLAN-one-image.md, Deyao 2026-11-20): what a session machine runs AROUND the agent, and
# nothing for the agent itself. The agent's tools live in one image, DE0CH/aviary's sandbox image, which aviary-sandbox
# enters as the agent's root (side by side: aviary's image is carried as a folder, on the volume or in the fabric image,
# never stacked on this one). session-image/Dockerfile puts Jarvis 4's machine side on top of this exactly as on the
# legacy base (build arg BASE), giving ghcr.io/de0ch/jarvis4-session:machine-sha-<commit> (images.yml job `machine`).
# The legacy base (session-image/base/Dockerfile, every tool baked in) stays as it is for the legacy `fly` runner.
# Built with session-image/base as its context: the launchers and helpers below are those files, unchanged.
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
# what the machine side and the aviary harness call: git and ssh (repos, deploy keys; jarvis-ssh's sshd), sudo (the
# harness's mounts, aviary-sandbox), python3 (pull-secrets, session-secret, content-sync, jarvis-request, aviary-home),
# tmux (the Terminal panel), curl and jq, procps/psmisc/lsof/iproute2 for looking at a machine, zstd and tar,
# wireguard-tools (an AWS machine's way to the router), less and nano for a person on the ssh
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl git openssh-client openssh-server sudo python3 tmux jq procps psmisc lsof iproute2 \
      zstd less nano wireguard-tools \
 && rm -rf /var/lib/apt/lists/*
# Node.js 22: the tunnel agent (cf-tunnel-agent.js: the session's page and jarvis-ssh)
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
 && apt-get install -y nodejs && rm -rf /var/lib/apt/lists/* && node --version
# crane: aviary-sandbox fetches aviary's sandbox image onto the volume with it (a fly-preload volume already has it)
RUN curl -fsSL "https://github.com/google/go-containerregistry/releases/download/v0.22.1/go-containerregistry_Linux_x86_64.tar.gz" \
  | tar -xz -C /usr/local/bin crane && crane version
# user claude, uid 1000 (the sandbox's agent is uid 1000 too), passwordless sudo
RUN userdel -r ubuntu 2>/dev/null; useradd -m -u 1000 -s /bin/bash claude \
 && echo 'claude ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/90-claude \
 && chmod 0440 /etc/sudoers.d/90-claude
# the session's helpers and the launchers (session-image/base, unchanged): harness-claude.sh dispatches on
# SESSION_HARNESS. A harness other than aviary runs inside aviary's image (session-entrypoint → aviary-sandbox --run,
# docs/PLAN-one-image.md), the launchers and these helpers bound in; set-permission-mode and harness-send also act from
# the machine's side (through the shared /tmp: tmux's socket). The other harnesses' runtimes come with their move.
COPY pull-secrets session-secret content-sync harness-claude.sh harness-aviary.sh aviary-home jarvis-ssh \
     set-permission-mode harness-send session-attachments /usr/local/bin/
COPY cf-tunnel-agent.js /usr/local/lib/cf-tunnel-agent.js
COPY sshd_config /etc/ssh/jarvis_sshd_config
COPY ssh-ca.pub /etc/ssh/jarvis-ca.pub
RUN rm -f /etc/ssh/ssh_host_* && echo chendeyao000 > /etc/ssh/jarvis-principals \
 && chmod 755 /usr/local/bin/pull-secrets /usr/local/bin/session-secret /usr/local/bin/content-sync \
      /usr/local/bin/harness-claude.sh /usr/local/bin/harness-aviary.sh /usr/local/bin/aviary-home /usr/local/bin/jarvis-ssh \
      /usr/local/bin/set-permission-mode /usr/local/bin/harness-send /usr/local/bin/session-attachments
# the mark session-entrypoint reads: on this base a harness other than aviary runs inside aviary's image
# (aviary-sandbox --run; docs/PLAN-one-image.md)
RUN mkdir -p /etc/jarvis && echo "the agent's tools are aviary's sandbox image" > /etc/jarvis/machine-base
USER claude
WORKDIR /home/claude
ENV PATH=/home/claude/.local/bin:/usr/local/bin:/usr/bin:/bin
# no ENTRYPOINT: session-image/Dockerfile's is jarvis-machine boot
