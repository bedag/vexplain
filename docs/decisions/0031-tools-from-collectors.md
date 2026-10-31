# 0031 The agent's tools come from collectors; an MCP server is a collector that serves only the agent

- **Status:** Proposed on 2026-10-31. The direction is the owner's; the write-up waits for the owner's review.
- **Date:** 2026-10-31
- **Supersedes:** 0007's built-in tools and MCP plug-ins, and the `ToolServer` of 0015.
- **Design:** [collectors, evidence and rules](../design/2026-10-31-collectors-evidence-rules.md), section 5.10.

## Context

- 0007 gave the agent a fixed set of built-in tools, plus plug-in tools from MCP servers registered as `ToolServer`s.
- Most built-in tools are views of what collectors deliver, or work that a collector does on request.
- The owner sees one pattern for everything that ends up as evidence.
- MCP is the standard for tool calls, and many tools ship an MCP server. An MCP call carries arguments that a model chose, and its output is text that a model reads.

## Decision

- **The agent's tools are:**
  - queries over stored evidence, built into vexplain
  - the operations that collectors declare, each with its parameter schema as the tool's input
- **An MCP server is a collector that serves only the agent.**
  - It is either a `Collector` with `interface: MCP` and a package that vexplain deploys, or a server elsewhere that its `Collector` names by URL. That server's credentials are in a labelled Secret in the operator's namespace, as 0017 requires for the LLM key.
  - Its `Collector` lists which of the server's tools are allowed, and the evidence type each produces.
  - Its output goes into the agent's ledger, and never to the rules.
- **`ToolServer` is dropped.** It was planned for after v1 and never built.
- **0007's rule on evidence stays:** evidence that the validator doesn't know pushes only towards "affected" or "unclear", unless the admin maps it to a known type.

## Consequences

- A collector's author gets agent support without extra work.
- One kind of resource, `Collector`, installs everything that vexplain learns from.
- **Rejected:**
  - making every MCP server implement vexplain's API, which would throw away what MCP already defines
  - making collectors speak MCP, which is built for interactive calls, not for typed evidence
