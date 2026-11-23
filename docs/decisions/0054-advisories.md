# 0054 Advisories: the vulnerability database first, then pages fetched from allowlisted domains, checked twice

- **Status:** Accepted on 2026-11-16. The decisions are the owner's, from the phase 4 discussion, and the owner accepted the write-up on 2026-11-16. On 2026-11-20 the default allowlist left out `www.cve.org`, and took `go.dev` ([phase 4's fixes](../design/2026-11-20-phase4-live-fixes.md), 2.1).
- **Date:** 2026-11-16
- **Refines:** the advisory lookup of the main design (6.6.3) and of the rules design (5.10).
- **Design:** [the agent on image cases](../design/2026-11-16-agent-on-cases.md), sections 4.3 and 5.8.

## Context

- **`vulnerabilities` already holds Grype's database,** built from NVD, GitHub's advisories, OSV and the distros' feeds, with references to the real advisories.
- **A fetch limited to allowlisted domains is common,** as in Anthropic's web fetch tool. But when the model writes the URL, a domain that hosts anyone's pages can carry data out, as Claude Code's CVE-2026-54316 did. A report of July 2026 also chained links out of fetched pages.
- **The agent knows the fleet's weak spots,** and pages are text that anyone can write (main design 6.6.3).

## Decision

- **`vulnerabilities` gets an operation, `describe`,** that returns what its database holds for a finding ID: the description, CVSS, the fixed versions, the known-exploited entry, EPSS and the references. Its findings gain EPSS.
- **A new collector, `advisories`,** in the hub's role, owns what goes to the internet when the agent asks. In phase 4 it has one operation, `fetch`:
  - vexplain's MCP server forwards only a URL that came out of a trusted result in the case, never one the model wrote, one found in a fetched page, or one from a foreign MCP server;
  - the collector checks every request and every redirect: https only, an allowlisted host, a capped size and a timeout.
- **A fetched page is external evidence.** `Fixed` and `NotAffected` rest on known types, such as `describe`'s fixed versions.
- **Lookups per source** (OSV, the distros' trackers, Vulnrichment) come later, by finding ID.

## Consequences

- The agent reads the real advisory behind a thin description, without taking a URL from the model.
- Egress is visible: `advisories` reaches only its allowlisted hosts. An air-gapped cluster runs without it.
- **Rejected:**
  - **an MCP fetch server with a domain allowlist alone,** which leaves the model's URL as a way out;
  - **one tool that tries the database and then the internet,** which would hide where an answer came from.
