# Jarvis 4 session image: the base (session-image/base/: tools, harnesses, entrypoint, supervisor, carried over from
# Jarvis 1's session image) with Jarvis 4's machine side in front of it. jarvis2-machine is the entry point: it makes the machine's key pairs, waits
# for the core's init (which prints them), takes the core's key from its Fly config (the core sets it), checks the succession cert, restores the predecessor's snapshot, pulls the secrets,
# then runs the base's entrypoint as its child (the keeper: machine/keeper.go). The base is pinned by digest in BASE below; moving it is a visible commit (the
# images workflow's pin job writes it after building a changed session-image/base/, and builds this image from that
# new base in the same run through --build-arg BASE).
ARG BASE=ghcr.io/de0ch/jarvis4-session:base-sha-f20627d5fd29@sha256:1cbb3c2faabb370d27277e9f532768ff15b98526072ecae770bdeb71f5ed0983
FROM golang:1.25-bookworm AS build
WORKDIR /src/machine
COPY kernel/ /src/kernel/
COPY machine/ ./
RUN CGO_ENABLED=0 go build -trimpath -o /out/jarvis2-machine .

FROM ${BASE}
COPY --from=build /out/jarvis2-machine /usr/local/bin/jarvis2-machine
# task templates (tasks/<name>/, router/tasks.go): a task line's machine runs one of these instead of a harness;
# the image digest in the line's cert fixes which code that is
COPY tasks/ /opt/jarvis2/tasks/
# jarvis2-request: a session asks Deyao for something that needs his Face ID (an Inbox request, router/inbox.go)
COPY --chmod=755 session-image/bin/jarvis2-request /usr/local/bin/jarvis2-request
# peer messages (docs/DESIGN.md "Peer messages"): Claude Code refuses every direct cross-session message
# (managed settings: crossSessionInbound refuse); sessions talk through Jarvis (jarvis2-message), and Jarvis's own
# messages reach claude through the Jarvis channel (an MCP channel server harness-claude.sh loads)
COPY --chmod=755 session-image/bin/jarvis2-message session-image/bin/jarvis-channel session-image/bin/jarvis-channel-send /usr/local/bin/
USER root
# Only vouched inputs shape a machine (docs/DESIGN.md "Inputs to a machine"):
#  - the image's own ENV, recorded here, is the env jarvis2-machine keeps (everything the machine's config adds
#    besides the core's key and the router's address is dropped at boot: machine/vouch.go cleanEnv);
#  - the OpenClaw runtime bundle is pinned by sha256, not only by URL.
RUN mkdir -p /opt/jarvis2 && env | grep -Ev '^(HOSTNAME|HOME|PWD|OLDPWD|SHLVL|_|TERM|USER|LOGNAME|SHELL)=' | sort > /opt/jarvis2/image.env
COPY session-image/openclaw-runtime.json /opt/jarvis2/openclaw-runtime.json
COPY --chmod=755 session-image/bin/openclaw /usr/local/bin/openclaw
# Claude Code's managed settings (crossSessionInbound refuse) and the Jarvis channel's MCP config. The directory is made
# first: a COPY --chmod=644 that creates it gives the DIRECTORY 644 too (no search bit), and then Claude Code, as user
# claude, stops at its "Settings Error … EACCES" prompt before Remote Control comes up: every new session stuck on
# "booting…" (2026-10-20). The check below (as claude) fails the build if anything here is unreadable again.
RUN install -d -m 755 -o root -g root /etc/claude-code
COPY --chmod=644 session-image/claude-code/managed-settings.json session-image/claude-code/jarvis-channel.json /etc/claude-code/
# the one command the core runs through Fly (core/fly.go initPath): no arguments; it prints this machine's
# public keys and lets boot go on
RUN printf '#!/bin/sh\nexec /usr/local/bin/jarvis2-machine init\n' > /usr/local/bin/jarvis2-init \
 && chmod 755 /usr/local/bin/jarvis2-init \
 && ln -s /usr/local/bin/jarvis2-machine /usr/local/bin/jarvis2 \
 && chmod -R a+rX,go-w /opt/jarvis2/tasks
USER claude
# what the harness reads as user claude must be readable by it (see /etc/claude-code above): every directory searchable,
# every file readable, the JSON valid, the channel server runnable
RUN set -e; for d in $(find /etc/claude-code -type d); do [ -r "$d" ] && [ -x "$d" ] || { echo "unreadable dir $d" >&2; exit 1; }; done; \
    for f in $(find /etc/claude-code -type f); do [ -r "$f" ] || { echo "unreadable file $f" >&2; exit 1; }; done; \
    for f in /etc/claude-code/*.json; do python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$f"; done; \
    for b in jarvis2-machine jarvis2-request jarvis2-message jarvis-channel jarvis-channel-send; do [ -x /usr/local/bin/$b ] || { echo "not runnable: $b" >&2; exit 1; }; done; \
    ls /etc/claude-code/managed-settings.d >/dev/null 2>&1 || [ ! -e /etc/claude-code/managed-settings.d ]
# The entry point runs as root: jarvis2-machine boot is the keeper (machine/keeper.go), Fly's main child for the
# machine's whole life, which the session (user claude) can't signal; it starts the boot steps and the harness as
# user claude and the supervisor's worker as root with claude's file access (DECISIONS 2026-10-21).
USER root
ENTRYPOINT ["/usr/local/bin/jarvis2-machine", "boot"]
