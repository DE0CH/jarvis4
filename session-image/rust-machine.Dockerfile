# The Rust jarvis-machine's candidate (rust/machine, the port of machine/): the session image production runs, with
# only /usr/local/bin/jarvis-machine swapped for the Rust build, so the e2e replica checks exactly that swap
# (.github/workflows/rust-machine-replica.yml). Deleted with machine/ when session-image/Dockerfile builds rust/machine.
ARG SESSION
FROM rust:1.99.1-bookworm AS build
WORKDIR /src/rust
COPY rust/ ./
RUN cargo build --release --locked -p jarvis-machine && install -D target/release/jarvis-machine /out/jarvis-machine

FROM ${SESSION}
COPY --from=build /out/jarvis-machine /usr/local/bin/jarvis-machine
RUN /usr/local/bin/jarvis-machine 2>&1 | grep -q "usage: jarvis-machine"
