# The fabric image (docs/PLAN-fabric.md): what a session machine on aviary's fabric runs as its gVisor sandbox. The
# session image, unchanged, plus aviary's sandbox image unpacked at /opt/aviary-sandbox (aviary-sandbox's bind mode:
# gVisor refuses the overlay it makes on a Fly or AWS machine) and the entrypoint that fetches the machine's env.
# Built by images.yml after the session image, with:
#   SESSION   the session image just built (ghcr.io/de0ch/jarvis4-session@sha256:…)
#   SANDBOX   aviary's sandbox image as session-image/aviary.json pins it (ghcr.io/de0ch/hermit-sandbox@sha256:…)
# and session-image/fabric/aviary-sandbox.config written by the workflow from `crane config $SANDBOX`.
ARG SESSION
ARG SANDBOX
FROM ${SANDBOX} AS sandbox
FROM ${SESSION}
USER root
COPY --from=sandbox / /opt/aviary-sandbox/
COPY --chmod=644 session-image/fabric/aviary-sandbox.config /opt/aviary-sandbox.config
COPY --chmod=755 session-image/fabric/fabric-entrypoint /usr/local/bin/fabric-entrypoint
ENV AVIARY_SANDBOX_IMAGE_DIR=/opt/aviary-sandbox
# the machine gives its harness the image's env as image.env lists it (rust/machine vouch.rs clean_env), written by the
# session image before this ENV: written again here. The harness runs aviary-sandbox through sudo, which keeps only
# the env sudoers lets through: the setting is one of them, or aviary-sandbox never sees the directory and fetches
# the image instead (tar failing inside gVisor; the fabric replica, 2026-11-18). Both checked here.
RUN env | grep -Ev '^(HOSTNAME|HOME|PWD|OLDPWD|SHLVL|_|TERM|USER|LOGNAME|SHELL)=' | sort > /opt/jarvis/image.env \
 && grep -qx 'AVIARY_SANDBOX_IMAGE_DIR=/opt/aviary-sandbox' /opt/jarvis/image.env \
 && echo 'Defaults env_keep += "AVIARY_SANDBOX_IMAGE_DIR"' > /etc/sudoers.d/aviary-sandbox-image \
 && chmod 440 /etc/sudoers.d/aviary-sandbox-image \
 && sudo -n env | grep -qx 'AVIARY_SANDBOX_IMAGE_DIR=/opt/aviary-sandbox'
ENTRYPOINT ["/usr/local/bin/fabric-entrypoint"]
