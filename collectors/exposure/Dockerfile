# Build the exposure collector. The build runs from the root of the repository, the context that `make docker-build`
# gives it: the collector's module replaces the SDK with the repository's directory sdk.
FROM golang:1.26 AS builder
ARG TARGETOS
ARG TARGETARCH
# VERSION is the version that the collector reports in GetInfo.
ARG VERSION=0.1.0

# The workspace lists every module of the repository, and the collector needs only its own and the SDK, which the
# replace line of its go.mod names.
ENV GOWORK=off

WORKDIR /workspace
# Copy the Go Modules manifests of the collector and of the SDK, and cache the dependencies before the source, so
# that a change to the source doesn't download them again.
COPY sdk/go.mod sdk/go.sum sdk/
COPY collectors/exposure/go.mod collectors/exposure/go.sum collectors/exposure/
RUN cd collectors/exposure && go mod download

# Copy the Go source (relies on .dockerignore to filter)
COPY sdk/ sdk/
COPY collectors/exposure/ collectors/exposure/

# The GOARCH has no default value, so that the binary is built for the platform of the build.
RUN cd collectors/exposure && CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -ldflags "-X main.version=${VERSION}" -o /workspace/exposure ./cmd/exposure

# Use distroless as the minimal base image to package the collector. The static image holds no shell and no package
# manager, and its nonroot tag runs as user 65532. Refer to https://github.com/GoogleContainerTools/distroless.
FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=builder /workspace/exposure /exposure
# vexplain runs the container as non-root, with a read-only root filesystem and no capabilities: the collector writes
# nothing.
USER 65532:65532
# The collector API, with mutual TLS, and /healthz, /readyz and /metrics.
EXPOSE 9443 8081

ENTRYPOINT ["/exposure"]
