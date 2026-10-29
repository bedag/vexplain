# 0003 Hub-and-spoke topology, starting with one cluster as both

- **Status:** Accepted. The roles are refined by 0021.
- **Date:** 2026-10-29

## Context

The same image digest runs in many clusters. In the owner's real export of one past CVE, deduplicating by image cut the rows to about a third.

Investigating or reviewing the same digest once per cluster wastes tokens and SOC time. The options considered:

- independent clusters
- hub and spokes
- sharing VEX through registry attestations

## Decision

One operator binary, with two strictly separate roles (0021) and three modes:

- **`HubAndSpoke`:** the normal setup for the hub's cluster. It decides for all clusters, and as a spoke it also observes, executes tasks for and reports on its own workloads.
- **`Spoke`:** every other cluster. It observes, executes the hub's tasks, and renders the results in its own cluster.
- **`Hub`:** the hub without a local spoke. It's always possible, because the roles stay separate, even if it will rarely be used.

Spokes reach the hub through its Kubernetes API with a narrowly scoped service account. Development starts with the hub's cluster alone.

## Consequences

- Each digest + CVE is investigated and reviewed once.
- Spoke-to-hub network access and credentials are needed from phase 6 (multi-cluster).
- If the hub is down, no new verdicts arrive. Spokes keep rendering from the last result sheets they read.
- Rejected:
  - independent clusters: duplicate work and duplicate reviews
  - registry attestations: needs write access to registries, plus syncing reviews back
