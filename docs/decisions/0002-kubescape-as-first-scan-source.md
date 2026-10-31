# 0002 Kubescape as an optional collector and part of v1; built-in Syft/Grype as the base

- **Status:** Accepted (revised 2026-10-29: changed from a hard dependency to an optional collector; in design revision 5, part of v1 as its own phase after the built-in collectors). Changed by 0029 (proposed on 2026-10-31): Kubescape support becomes a collector package.
- **Date:** 2026-10-29

## Context

The operator doesn't scan itself. It needs SBOMs, vulnerability findings and, ideally, runtime information (which libraries a workload loads).

Kubescape provides all three: Syft/Grype underneath, plus application profiles. But it is a large component whose footprint and stability on hosted control planes are unknown. A hard dependency would make the operator unusable wherever Kubescape isn't installed.

## Decision

- **The operator works without Kubescape.** A built-in `Scanner` collector embeds existing tools and scans the digests actually running in the cluster:
  - Syft for SBOMs with file ownership
  - Grype for CVE matching
  - `govulncheck`
  - `debug/elf`
- **Kubescape is an optional `Collector` and part of v1 (owner's decision).**
  - It is built in its own phase (3), after the built-in collectors are tested.
  - As the first collector for a third-party source, it also proves how such a source plugs in.
  - It adds runtime profiles and can replace the built-in CVE matching. The built-in scanner then only runs the analysis Kubescape doesn't provide: symbol search, linkage, `govulncheck`.
- **No Kubescape types are embedded in our API.** The collector copies only the fields it needs into our own types.

## Consequences

- Kubescape's resource use and outage behaviour are measured in phase 3.
- Without Kubescape there's no runtime evidence. Evidence kinds that need it are missing, so verdicts degrade to "unclear", never to "not affected".
- The Grype vulnerability database must be updated through the proxy.
- Application profiles may contain exec arguments with secrets, so they are redacted before reaching the agent.
