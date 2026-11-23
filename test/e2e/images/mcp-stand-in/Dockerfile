# The MCP server of the e2e tests: a stand-in for a wiki's, on the Go SDK. Its source is part of the operator's module,
# so that it is vetted and linted with it, and the build makes a module of its own around it, which needs the SDK
# alone: the version is the one that the operator's go.mod requires. It uses the base images of the manager's build,
# which the suite has built just before.
FROM golang:1.26 AS builder
WORKDIR /workspace
COPY main.go .
RUN go mod init mcp-stand-in && go mod edit -require=github.com/modelcontextprotocol/go-sdk@v1.8.0 && go mod tidy
RUN CGO_ENABLED=0 go build -o mcp-stand-in .

FROM gcr.io/distroless/static:nonroot
COPY --from=builder /workspace/mcp-stand-in /mcp-stand-in
USER 65532:65532
ENTRYPOINT ["/mcp-stand-in"]
