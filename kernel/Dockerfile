FROM golang:1.25-bookworm AS build
WORKDIR /src
COPY . .
# no `go test` here: the images workflow's test job runs the kernel's tests before this build
RUN mkdir /out && \
    for r in notary notarizer mover merger spawner identity gullible secrets; do \
      CGO_ENABLED=0 go build -trimpath -o /out/$r ./cmd/$r || exit 1; done

# no shell, no package manager: the eight binaries and CA roots only; each Deployment runs one (DESIGN "Target design")
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/ /kernel/
USER nonroot
