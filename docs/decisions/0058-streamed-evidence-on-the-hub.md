# 0058 Streamed evidence of `Hub` scope reaches the hub's store, which keeps each record current

- **Status:** Accepted on 2026-11-22. Proposed on 2026-11-20, and revised with the design's drafts 2 and 3: presence goes to the hub with exposure, and the type `entry-point` is gone. The direction is the owner's: exposure is evidence on the hub, the store keeps streamed records current, and the hub joins presence and exposure without ImageInventory's workload references. The details are the designer's, and the owner accepted the write-up on 2026-11-22. Amended on 2026-11-22 while planning: an event counts as equal only when the collector's version is the same too, since the hub asks again while a record's version differs from its Collector's. Amended on 2026-11-23 by the final review of the build: the spoke stores presence and exposure only when their data follows the core's schema, and an event that doesn't deletes its record, as one that the store refuses does (design 5.4).
- **Date:** 2026-11-20
- **Refines:**
  - 0032: each type declares its scope, and now a stream's evidence follows it too;
  - 0004: the store's one door stays, and a record changes in place;
  - 0021: the spokes write what they observe, and the hub reads it.
- **Design:** [entry points](../design/2026-11-20-entry-points.md), sections 4.1, 4.4, 5.3 and 5.4.

## Context

- **Exposure and presence are evidence,** but `network-reach` and `workloads` declare them `Spoke`, so they stay in each cluster's memory.
- **The owner wants the CVE playbook's rules to join them on the hub** with the sources' answers (0059), without ImageInventory's workload references, which stop at 100 per cluster.
- **The store has three gaps:**
  - only evidence from asked operations reaches it;
  - it writes a record once per collector version, and keeps the old record without a word when a changed event comes from the same version;
  - it keys a record on its subject, its type and the Collector's name, so two clusters' presence of one image would overwrite each other.
- **Phase 3b's spikes found** that replacing changed evidence by a delete and a create leaves a gap: 11 of 12 changes ran into it.

## Options considered

| Option | Costs |
|---|---|
| A record of its own on the hub, which the spokes write | A kind of its own for a collector's data, which 0032 gives to evidence |
| Entry points inside presence | Copies every workload's entry points into each image it runs |
| ImageInventory's workload references for the join | At most 100 workloads per cluster, and the owner wants ImageInventory left out |
| **Streamed evidence follows its scope, and the store writes in place (chosen)** | **Every workload's exposure and every image's presence are written to the hub, and updated when they change** |

## Decision

- **A spoke stores every streamed event of a `Hub`-scoped type,** as its executor stores what an operation returns.
  - A snapshot stores each of its events, and deletes the collector's records of that type from the cluster that the snapshot doesn't hold.
  - A change stores its event, and a tombstone deletes its record.
  - `Forget` deletes the collector's records from the cluster.
- **The store writes a record in place whenever its event differs,** whatever the collector's version. An equal event writes nothing, apart from an answer that the hub asked for, whose time is rewritten once it is older than half its `maxAge` (0059). A record's subject, type and source never change.
- **A streamed record's key and label name its cluster.** Evidence that an operation returns keeps its key, so nothing stored is renamed.
- **The store's watchers see changes in place.**
- **`network-reach` declares exposure, and `workloads` declares presence, with the scope `Hub`.** The spoke still reads both in memory, for its reports and ImageInventory.

## Consequences

- **The hub holds every workload's exposure and every image's presence in each cluster,** so that the CVE playbook's exposure rules join them (0059).
- **Presence on the hub carries the labels that owner attribution allows.** The agent design's 5.14 kept the workloads' labels on the spokes.
- **The write rate and the number of Evidence objects grow** with the clusters' workloads and pods, since presence changes whenever a pod starts, stops or moves. Both are measured against 0004's triggers. Presence without its pods is the option if the rate is too high.
- **Phase 3b's call for evidence updated in place is settled here.**
- **Rejected:**
  - a record of its own, entry points inside presence, and ImageInventory's references, as above;
  - replacing a changed record by a delete and a create, which leaves a gap.

**Precedent:** Red Hat Advanced Cluster Security's Sensor sends each deployment's exposure to Central. Kyverno updates its PolicyReports in place.
