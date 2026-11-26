# 0063 The hub copies its spokes' records into its own stores

- **Status:** Accepted on 2026-11-24. Proposed on 2026-11-23. The decision is the owner's, from the brainstorm of phase
  6 on 2026-11-23. The details marked **[call]** are the designer's. Revised on 2026-11-24, before acceptance: the hub
  also copies the spokes' namespace labels, for the metrics it renders (0065), and no answers, since it scans every
  image itself (0066). The owner accepted the write-up with the design on 2026-11-24. Amended on 2026-11-26 after the
  final review: an entry that a spoke's presence moved to another name under the cluster's identity, as after a rename
  on the spoke, keeps the hub's copy until the check stops the copier with `ClusterNameMismatch` (design 5.3). An
  image's digest kind is the highest that its clusters report, while several run it (design 5.5).
- **Date:** 2026-11-23
- **Refines:**
  - 0004: the copies go through its one door, and are measured against its triggers;
  - 0058: a remote cluster's streamed records reach the hub through the hub's copy, not through the spoke's sink.
- **Design:** [remote spokes](../design/2026-11-23-remote-spokes.md), sections 4.5, 5.5 and 5.13.

## Context

- **Each spoke keeps its records in its own store,** as a standalone install does: its presence, its exposure and its
  other streamed evidence.
- **Each image's presence goes to the hub as a streamed record since 0058,** with every workload that runs it. The
  remote metrics (0065) are rendered from those records, and need the namespaces' labels for the playbooks'
  namespace match.
- **The hub's readers expect those records in the hub's stores.** The assessor, the summaries and the cases read
  them, and so do the agent's workers, in pods of their own (0057).
- **The hub makes lasting decisions:** cases, verdicts, and investigations that cost tokens.

## Options considered

| Option | Costs |
|---|---|
| **The hub copies each spoke's records into its own stores (chosen)** | The hub's etcd holds and writes every cluster's records |
| The hub reads them live, through caches fed by watches | Every reader of `ImageInventory` changes. The workers would need the manager's memory through a new internal API. After the hub restarts, a spoke is unknown until its watch has caught up |
| A collector for collectors: a built-in collector per spoke copies its evidence | The collector protocol would have to speak for other collectors, and the hub role's stream would need a new sink |

## Decision

- **Per `Spoke`, the hub watches the spoke's records and copies them** into its own stores, through the interfaces that
  the in-process spoke uses today:
  - streamed records of `Hub` scope, keyed with the spoke's cluster, presence's among them;
  - presence entries;
  - the labels of the spoke's namespaces, into records of the hub's own **[call]**.
- **It copies only the types that the spoke's `Collector`s declare `Hub` now,** and only records of the `Spoke`'s
  cluster and cluster ID.
- **A spoke that drops out keeps its copies.** Only deleting its `Spoke` deletes them.
- **Deleting a `Collector` on the hub's own cluster** deletes its streamed records of that cluster only **[call]**.
- **The copies are measured with several spokes** against 0004's triggers. Once a trigger fires, the data moves to an
  aggregated API with its own database.

## Consequences

- **The hub's readers don't change,** and a spoke that can't be reached never reads as "doesn't run it any more".
- **The hub's etcd grows with the fleet.** The first limit expected is one image's `ImageInventory`, which holds an
  entry for every cluster that runs it.
- **The hub's write rate includes every cluster's presence changes,** which follow its pods (0058).
- **A spoke that is reinstalled while its `Spoke` exists** has its copies dropped, and copied again once the new
  install runs (design 5.11).
- **Rejected:**
  - reading live, as above;
  - a collector for collectors, for now. It may come back if keeping the spokes' credentials in the manager proves too
    risky.

**Precedents:** Red Hat ACS's Central and ACM's search keep a durable, central copy of each cluster's state.
