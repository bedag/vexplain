# Build the vulnerabilities collector. The build runs from the root of the repository, the context that `make docker-build`
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
COPY collectors/vulnerabilities/go.mod collectors/vulnerabilities/go.sum collectors/vulnerabilities/
RUN cd collectors/vulnerabilities && go mod download

# Copy the Go source (relies on .dockerignore to filter)
COPY sdk/ sdk/
COPY collectors/vulnerabilities/ collectors/vulnerabilities/

# The GOARCH has no default value, so that the binary is built for the platform of the build.
RUN cd collectors/vulnerabilities && CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -ldflags "-X main.version=${VERSION}" -o /workspace/vulnerabilities ./cmd

# The Collector's runtime config mounts a volume at /db, which is where the vulnerabilities collector keeps its database. The image has
# the directory too, owned by the user that the vulnerabilities collector runs as, so that a plain `docker run` can seed it from
# /opt/grype-db.
RUN mkdir -p /out/db

# Download the pinned Grype release for the target architecture, and check it against the SHA-256 that
# the release's checksums file (grype_<version>_checksums.txt) gives for it.
#
# With --build-arg WITH_DB=true the stage also downloads the vulnerability database, into /opt/grype-db,
# for a cluster whose pods have no internet, such as kind. It is not /db, because the volume that the
# Deployment mounts there would hide it: the vulnerabilities collector copies it to /db at start, when the Collector's setting
# seedDatabase names it. Docker caches the layer, so a rebuild of the same inputs keeps the database of the first
# build. Use --no-cache for a newer one.
#
# The database is the same for every architecture, so this stage runs on the build platform, and a
# cross-build needs no emulation: it runs the release for the build architecture, and only unpacks the
# one for the target architecture.
FROM --platform=$BUILDPLATFORM golang:1.26 AS grype
ARG BUILDARCH
ARG TARGETARCH
ARG WITH_DB=false
ARG GRYPE_VERSION=0.121.0
ARG GRYPE_SHA256_AMD64=64e07133d3486115de647a66581461dccf5c732748a0a3119077395565f15519
ARG GRYPE_SHA256_ARM64=86f570f75ca947ea3dd6486309232bcff6d78e44ba081ae75ab14eab72be3dae
RUN set -eu; \
    fetch() { \
      case "$1" in \
        amd64) sha256="${GRYPE_SHA256_AMD64}" ;; \
        arm64) sha256="${GRYPE_SHA256_ARM64}" ;; \
        *) echo "no SHA-256 of Grype for the architecture '$1'" >&2; exit 1 ;; \
      esac; \
      curl -fsSL -o "/tmp/grype-$1.tar.gz" \
        "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_$1.tar.gz"; \
      echo "${sha256}  /tmp/grype-$1.tar.gz" | sha256sum -c -; \
      mkdir -p "/grype/$1"; \
      tar -xzf "/tmp/grype-$1.tar.gz" -C "/grype/$1" --no-same-owner grype; \
    }; \
    mkdir -p /opt/grype-db; \
    fetch "${TARGETARCH}"; \
    if [ "${WITH_DB}" = true ]; then \
      [ "${BUILDARCH}" = "${TARGETARCH}" ] || fetch "${BUILDARCH}"; \
      GRYPE_CHECK_FOR_APP_UPDATE=false GRYPE_DB_CACHE_DIR=/opt/grype-db "/grype/${BUILDARCH}/grype" db update; \
    fi

# Use distroless as the minimal base image to package the collector and Grype
# Refer to https://github.com/GoogleContainerTools/distroless for more details
FROM gcr.io/distroless/static:nonroot
ARG TARGETARCH
WORKDIR /
COPY --from=builder /workspace/vulnerabilities /vulnerabilities
COPY --from=grype /grype/${TARGETARCH}/grype /usr/local/bin/grype
COPY --from=builder --chown=65532:65532 /out/db /db
COPY --from=grype --chown=65532:65532 /opt/grype-db /opt/grype-db
# vexplain runs the collector's container as non-root, with a read-only root filesystem and no capabilities.
USER 65532:65532
# The collector API, with mutual TLS, and /healthz, /readyz and /metrics.
EXPOSE 9443 8081

ENTRYPOINT ["/vulnerabilities"]
