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
ENTRYPOINT ["/usr/local/bin/fabric-entrypoint"]
