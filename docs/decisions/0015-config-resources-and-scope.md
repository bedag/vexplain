# 0015 Configuration split into small resources; scope by label selectors; admin-set cluster name

- **Status:** Accepted
- **Date:** 2026-10-29

## Context

The API practices (0012) favour small resources with a clear purpose over one large object. Admins need to limit what gets analysed and to name the cluster for metrics.

## Decision

- **`OperatorConfig`** (cluster-scoped singleton) holds:
  - mode: `Hub`, `Spoke` or `HubAndSpoke`, as an open enum. The hub's cluster normally runs `HubAndSpoke`, and the roles stay separate, so `Hub` only is always possible (0021).
  - `clusterName`, set by the admin and used as the `cluster` metrics label
  - the hub connection
  - **scope**: include and exclude by namespace and pod label selectors
  - global daily budgets and the kill switch
  - sandbox settings, including the pull-credential mode (0008)
  - `ownerAttribution`: allowlists of namespace and workload label and annotation keys (0020)
- **`Collector`** (cluster-scoped, one per source) is a union by `type`, with its own health status. From phase 2 it has a `state` (`Enabled` / `Disabled`). The operator creates default collectors by API discovery and never overwrites them, so `Disabled` is the way to turn one off (0006).
- **`ToolServer`** (cluster-scoped, hub) registers an MCP server, the tools allowed from it, and the evidence kind each tool produces.
  - MCP already defines how tools are called. This resource only records our trust decisions, which no existing resource carries.
  - kagent's `RemoteMCPServer` is similar but would add a dependency and has no evidence kinds.
- **`AgentProfile`** (cluster-scoped, hub) is one `default` profile plus optional overrides per assessment type. It holds the per-run limits, the allowed tools and the prompt guidance source (see 0016).
- **`ModelConfig`** (cluster-scoped, hub) holds the LLM connection (see 0017).
- **`ReviewPolicy`** (cluster-scoped, hub) holds the auto-acceptance rules.
- **Fields arrive with the phase that uses them.** Phase 1's `OperatorConfig` has only `clusterName` and `scope`. Mode, hub connection, budgets, kill switch, sandbox settings and `ownerAttribution` come later as optional fields, which is a non-breaking change.

## Consequences

- Each resource can evolve and be versioned on its own, and each has a single controller.
- `OperatorConfig` with `spec: {}` plus the default collectors and profile gives a working base setup.
