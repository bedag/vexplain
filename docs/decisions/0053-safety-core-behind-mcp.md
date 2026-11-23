# 0053 The agent's safety core sits behind vexplain's own MCP server; the runner can be replaced

- **Status:** Accepted on 2026-11-16. The decisions are the owner's, from the phase 4 discussion, and the owner accepted the write-up on 2026-11-16. On 2026-11-20 the safety core and the runner moved out of the manager into agent workers (0057).
- **Date:** 2026-11-16
- **Refines:** the agent loop (main design 6.6) and 0031 (the agent's tools come from collectors).
- **Design:** [the agent on image cases](../design/2026-11-16-agent-on-cases.md), sections 4.2, 5.5, 5.6 and 5.7.

## Context

- **The loop has two layers:**
  - the safety rules: the case file, the tools, the ledger, `submit_verdict` and the validator;
  - the runner: calling the model, passing tool calls on, limits.
- **The options for the runner:**
  - our own, on phase 1's hardened LLM client;
  - a Go framework, such as Google's ADK for Go or CloudWeGo's Eino;
  - kagent, which runs agents as Kubernetes resources and speaks A2A.
- **The owner asked for longevity,** not speed, and wants industry patterns: MCP for tools, A2A for agents.

## Decision

- **vexplain's own MCP server holds the safety core,** in-process in the manager, through the official Go SDK's in-memory transport. kagent serves its built-in tools from an MCP server of its own in the same way.
- **Every tool call passes through it, and it writes the ledger itself.** The validator checks claims against what vexplain recorded, whoever ran the loop.
- **It serves:**
  - the core tools;
  - `search_tools`;
  - the collectors' operations and MCP collectors' tools that the profile allows;
  - `submit_verdict` and `submit_no_verdict`.

  A rejected verdict comes back as the tool's result: the one repair attempt.
- **Trust stays per tool.** A foreign MCP server's output is external evidence (0031).
- **Our own runner comes first,** on phase 1's client. A kagent runner over A2A can follow as an option, used only where kagent is installed.
- **A collector's operation becomes a tool only when the profile allows it.** A collector isn't always a tool.
- **In phase 4, the validator accepts "not affected" only as `VulnerableCodeNotPresent` or `Fixed`,** resting on a fixed version from the vulnerability database and the installed version in the SBOM (owner, 2026-11-16). Main design 6.7's other justifications wait for their evidence. A guard that holds because evidence may be incomplete holds against the agent too (`holdAgainst: All`).

## Consequences

- **What a replaced runner keeps:** the ledger, the validator and the strictness of "not affected" stay in vexplain.
- **What a kagent runner would take over:** the token limits, the final summary, the LLM key and replay. vexplain still sets a deadline per case.
- **The same server can later be exposed** for other assistants.
- **Rejected:**
  - **a Go framework,** which runs in our process like our own runner and adds no boundary, but a large, fast-moving dependency and a model adapter to check against 6.11;
  - **kagent as the only runner,** a hard dependency on another operator, which the main design rejects for Kubescape (4.2).

**Precedents:** MCP and A2A, as the standard points where tools and agents connect; kagent's tool server; MCP gateways.
