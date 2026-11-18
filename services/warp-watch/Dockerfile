# warp-watch (src/lib.rs): the build runs its tests; the image is busybox, whose nsenter reaches the host's warp-cli.
# Build context = this directory (.github/workflows/services.yml).
FROM rust:1.99-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo test --locked --release && cargo build --locked --release

FROM busybox:1.37.0@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e
COPY --from=build /src/target/release/warp-watch /warp-watch
ENTRYPOINT ["/warp-watch"]
