# The source of the e2e tests. The build runs from the root of the repository, as the collectors' builds do. The
# stand-in's source is part of the operator's module, so that it is vetted and linted with it, and the build makes a
# module of its own around it, which needs the SDK alone and replaces it with the repository's directory sdk.
FROM golang:1.26 AS builder
ARG TARGETOS
ARG TARGETARCH
# VERSION is the version that the stand-in reports in GetInfo.
ARG VERSION=0.1.0

ENV GOWORK=off

WORKDIR /workspace
COPY sdk/ sdk/
COPY test/e2e/images/dmz-stand-in/main.go dmz-stand-in/
RUN cd dmz-stand-in && go mod init dmz-stand-in && \
    go mod edit -require=github.com/bedag/vexplain/sdk@v0.0.0 -replace=github.com/bedag/vexplain/sdk=../sdk && \
    go mod tidy
RUN cd dmz-stand-in && CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -ldflags "-X main.version=${VERSION}" -o /workspace/dmz-stand-in-bin .

FROM gcr.io/distroless/static:nonroot
COPY --from=builder /workspace/dmz-stand-in-bin /dmz-stand-in
USER 65532:65532
ENTRYPOINT ["/dmz-stand-in"]
