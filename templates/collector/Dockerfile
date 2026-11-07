# Build the collector
FROM golang:1.26 AS builder
ARG TARGETOS
ARG TARGETARCH
# VERSION is the version that the collector reports in GetInfo. vexplain stores evidence at it, so a new version
# replaces what an old one delivered.
ARG VERSION=0.1.0

WORKDIR /workspace
# Copy the Go Modules manifests, and cache the dependencies before the source, so that a change to the source
# doesn't download them again. This needs the project without the replace line of go.mod: see the README.
COPY go.mod go.sum ./
RUN go mod download

COPY *.go ./
# The GOARCH has no default value, so that the binary is built for the platform of the build.
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -ldflags "-X main.version=${VERSION}" -o collector .

# Use distroless as the minimal base image to package the collector. The static image holds no shell and no package
# manager, and its nonroot tag runs as user 65532. Refer to https://github.com/GoogleContainerTools/distroless.
FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=builder /workspace/collector /collector
# vexplain runs the container as non-root, with a read-only root filesystem and no capabilities, so the collector
# writes nothing outside the volumes that its runtime config mounts.
USER 65532:65532
# The collector API, with mutual TLS, and /healthz, /readyz and /metrics.
EXPOSE 9443 8081

ENTRYPOINT ["/collector"]
