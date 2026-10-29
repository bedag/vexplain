# 0007 Collectors compiled in; built-in agent tools plus MCP plug-ins with declared evidence kinds

- **Status:** Accepted
- **Date:** 2026-10-29

## Context

Incoming data will change. Adding a source in a year must not require a redesign. The operator should use existing tools rather than reimplement them.

## Decision

- **All data comes in through collectors.** Each wraps an existing tool or API, is compiled into the operator behind a Go interface, and is configured as a `Collector` resource (a union by `type`). The rules and the agent only use what collectors deliver.
- **The agent has a base set of built-in tools:**
  - advisory lookup
  - SBOM query
  - `govulncheck`
  - symbol and linkage scan
  - runtime profile summary
  - exposure summary
  - config read
  - sandbox request
- **More agent tools plug in as MCP servers,** registered as `ToolServer` resources. No operator release is needed.
- **Every tool declares the evidence kind it produces.** The validator lets only known kinds support "not affected". Unknown or external kinds can push only towards "affected" or "unclear", unless an admin maps them to a known kind.

## Consequences

- New collectors need an operator release; new agent tools don't.
- A missing or unhealthy collector means missing evidence. Verdicts that would need it degrade to "unclear".
