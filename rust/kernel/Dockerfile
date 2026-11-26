# built from the repo root: the kernel's nine components (rust/kernel), one binary each
FROM rust:1.99.1-bookworm AS build
WORKDIR /src/rust
COPY rust/ ./
# no `cargo test` here: the images workflow's test job runs the kernel's tests before this build
RUN cargo build --release --locked -p jarvis-kernel && mkdir /out && \
    for r in notary notarizer mover merger spawner identity gullible minter secrets; do \
      install target/release/$r /out/$r || exit 1; done

# no shell, no package manager: the nine binaries, glibc and CA roots only; each Deployment runs one (DESIGN "Target
# design")
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /out/ /kernel/
USER nonroot
