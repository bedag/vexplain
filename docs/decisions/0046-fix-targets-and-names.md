# 0046 Fix targets come from the `vulnerabilities` collector; collectors are named after what they deliver

- **Status:** Accepted on 2026-11-08 (decided by the owner).
- **Date:** 2026-11-08
- **Refines:**
  - 0024: the next step's target follows each ecosystem's version order;
  - 0038: its narrow order for update targets;
  - 0022: the matcher.
- **Design:** [the collector model](../design/2026-11-08-collector-model.md), sections 4.4 and 5.9.

## Context

- **Fix versions were Grype's strings,** unordered.
  - 0038's narrow comparison names a target only where the order is unambiguous.
  - It leaves out Go modules, whose versions start with a `v`.
- **The owner had suggested a `remediation` collector.**
- **The owner found the names "matcher" and "exposure" misleading.**

## Decision

- **The matcher names an ecosystem-correct fix target for each package,** ordered with Grype's own version comparators: deb, rpm, apk, Go, Python, Maven and more.
- **Findings carry their aliases,** such as GO and GHSA IDs.
- **The database:**
  - it refreshes on a declared schedule, with run now (0040);
  - it survives restarts;
  - its version and age show on the `Collector` and as a metric.
- **Collectors are named after what they deliver:**
  - the matcher becomes `vulnerabilities`;
  - `exposure` becomes `network-reach`.

## Consequences

- **Go modules get update targets.** The report's own comparison goes.
- **The renames change `Collector` names, packages and docs.** There is no compatibility promise before v1.
- **Rejected:**
  - a `remediation` collector: it would add a step to every chain, and separate an ecosystem's version rules from the advisories they apply to;
  - the name "reachability", which would clash with code reachability.
