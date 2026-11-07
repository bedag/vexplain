# Build the scanner collector, and the scan that its scan Jobs run, which are one binary. The build runs from the root
# of the repository, the context that `make docker-build` gives it: the collector's module replaces the SDK with the
# repository's directory sdk.
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
COPY collectors/scanner/go.mod collectors/scanner/go.sum collectors/scanner/
RUN cd collectors/scanner && go mod download

# Copy the Go source (relies on .dockerignore to filter)
COPY sdk/ sdk/
COPY collectors/scanner/ collectors/scanner/

# The GOARCH has no default value, so that the binary is built for the platform of the build.
RUN cd collectors/scanner && CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -ldflags "-X main.version=${VERSION}" -o /workspace/scanner ./cmd

# A scan Job mounts its scratch volume at /work. The image has the directory too, owned by the user that the scanner
# runs as, so that a scan also runs without the volume.
RUN mkdir -p /out/work

# Download the pinned Syft release for the target architecture, and check it against the SHA-256 that the release's
# checksums file (syft_<version>_checksums.txt) gives for it.
FROM golang:1.26 AS syft
ARG TARGETARCH
ARG SYFT_VERSION=1.55.0
ARG SYFT_SHA256_AMD64=bb65249542db5fedeeb4d3f9b018b75e7264dbfbbb10486f044581a92f90490d
ARG SYFT_SHA256_ARM64=929bd163db2d7cd2255d3bcb8967208079813d7b46b0c952f7b794d8e2c7d304
RUN set -eu; \
    case "${TARGETARCH}" in \
      amd64) sha256="${SYFT_SHA256_AMD64}" ;; \
      arm64) sha256="${SYFT_SHA256_ARM64}" ;; \
      *) echo "no SHA-256 of Syft for the architecture '${TARGETARCH}'" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/syft.tar.gz \
      "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_${TARGETARCH}.tar.gz"; \
    echo "${sha256}  /tmp/syft.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/syft.tar.gz -C /tmp syft; \
    install -m 0755 /tmp/syft /syft

# Use distroless as the minimal base image to package the collector and Syft. The static image holds no shell and no
# package manager, and its nonroot tag runs as user 65532, the user that the scan Jobs run as. Refer to
# https://github.com/GoogleContainerTools/distroless.
FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=builder /workspace/scanner /scanner
COPY --from=syft /syft /usr/local/bin/syft
COPY --from=builder --chown=65532:65532 /out/work /work
# vexplain runs the collector's container as non-root, with a read-only root filesystem and no capabilities, and so
# does the scan Job's container.
USER 65532:65532
# The collector API, with mutual TLS, and /healthz, /readyz and /metrics.
EXPOSE 9443 8081

# The collector's Deployment runs serve, the image's command, and a scan Job runs the subcommand scan, with its
# arguments in place of the command.
ENTRYPOINT ["/scanner"]
CMD ["serve"]
