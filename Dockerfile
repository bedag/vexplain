# Build the manager binary
FROM golang:1.26 AS builder
ARG TARGETOS
ARG TARGETARCH

WORKDIR /workspace
# The manager builds in the workspace of go.work, as it builds and is tested in development: the workspace holds the
# operator, the SDK and every collector, and picks one version of each module that they share. So the manifests of the
# workspace come first, with those of each module that it uses, and go mod download caches what the workspace needs
# before the source is copied, so that a change to the source doesn't download it again. A module that go.work lists
# and this doesn't copy fails the download.
COPY go.work go.work.sum go.mod go.sum ./
COPY sdk/go.mod sdk/go.sum sdk/
COPY collectors/exposure/go.mod collectors/exposure/go.sum collectors/exposure/
COPY collectors/matcher/go.mod collectors/matcher/go.sum collectors/matcher/
COPY collectors/scanner/go.mod collectors/scanner/go.sum collectors/scanner/
COPY collectors/workloads/go.mod collectors/workloads/go.sum collectors/workloads/
COPY templates/collector/go.mod templates/collector/go.sum templates/collector/
RUN go mod download

# Copy the Go source (relies on .dockerignore to filter)
COPY . .

# Build
# the GOARCH has no default value to allow the binary to be built according to the host where the command
# was called. For example, if we call make docker-build in a local env which has the Apple Silicon M1 SO
# the docker BUILDPLATFORM arg will be linux/arm64 when for Apple x86 it will be linux/amd64. Therefore,
# by leaving it empty we can ensure that the container and binary shipped on it will have the same platform.
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -a -o manager cmd/main.go

# Use distroless as minimal base image to package the manager binary
# Refer to https://github.com/GoogleContainerTools/distroless for more details
FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=builder /workspace/manager .
USER 65532:65532

ENTRYPOINT ["/manager"]
