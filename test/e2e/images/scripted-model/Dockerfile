# The scripted model of the e2e tests: an OpenAI-compatible endpoint over TLS that answers from a script, so that the
# agent judges cases without a real model. It uses the standard library alone, and the base images of the manager's
# build, which the suite has built just before.
FROM golang:1.26 AS builder
WORKDIR /workspace
COPY main.go .
RUN CGO_ENABLED=0 go build -o scripted-model main.go

FROM gcr.io/distroless/static:nonroot
COPY --from=builder /workspace/scripted-model /scripted-model
USER 65532:65532
ENTRYPOINT ["/scripted-model"]
