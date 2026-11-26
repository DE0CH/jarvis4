# built from the repo root: the router (rust/router) + the app's web export (web/, made by the workflow first)
FROM rust:1.99.1-bookworm AS build
WORKDIR /src/rust
COPY rust/ ./
# the router recovers a panicking request (a refused state write answers 503): its own profile, panic = "unwind"
RUN cargo build --profile router --locked -p jarvis-router && install -D target/router/router /out/router

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /out/router /router
COPY web/ /web/
COPY policy/stores.json /policy/stores.json
# task templates, for the Tasks forms (the session image carries its own copy, which is what runs)
COPY tasks/ /tasks/
USER nonroot
ENTRYPOINT ["/router"]
