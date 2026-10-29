# 0019 `ImageInventory` records per-cluster presence: counts plus bounded workload references

- **Status:** Accepted (owner agreed, and asked for back-tracking to workloads; the cap of 100 is the designer's call)
- **Date:** 2026-10-29

## Context

The design keeps workload details on the spoke and image facts on the hub. But the SOC reviews `VexStatement`s on the hub and has to inform the owners of the affected workloads, so the hub needs a way back to them.

The first version of the phase-1 plan stored every workload name and the pod count in the hub's `ImageInventory`. Pod counts turn every autoscaling event into an etcd write. Unbounded lists grow without limit for images that run everywhere, such as sidecars.

## Decision

- **Per-cluster entries:** `ImageInventory.status.clusters` is a list keyed by cluster name, one entry per cluster where the digest runs. Each entry holds:
  - the cluster ID
  - `namespaceCount` and `workloadCount`
  - `workloads`: references (API group, kind, namespace, name) to the first 100 workloads, sorted. Each one is also the address of that workload's `WorkloadReport`. The list was cut off whenever it is shorter than `workloadCount`.
  - the repositories the digest was pulled from
  - when it was first seen there
- **The complete list lives on the spoke.** Every `WorkloadReport` carries a label per image digest (phase 2), so one label query lists all of them (see 0020).
- **Owner details** stay in `WorkloadReport`s and in the owner info metric (0020), not in the hub object. That way a change to a namespace's labels doesn't rewrite every image object in that namespace.
- **What isn't stored:** pod counts and a regularly refreshed "last seen" time. An entry is only written when it really changes.
- **One writer per entry:** each spoke writes only its own entry, as its "eyes" report (0021). From phase 6 (multi-cluster), this uses server-side apply with one field manager per cluster.
- **Removal:** a cluster's entry is removed when the digest stops running there, matched by cluster name or cluster ID, so a rename can't leave an orphan. The object is deleted when no entries remain. Phase 2 may add a retention period.
- **What counts as running:** every existing pod counts, whatever its phase. Ephemeral debug containers don't count.

## Consequences

- In the owner's real export of one past CVE, no image ran in more than about 60 workloads of one cluster, and most ran in very few, so 100 covers it completely.
- The worst case is about 10 KB per cluster entry. Phase 1's size indicator gives a first look; real sizes come from a real cluster (0004).
- Write churn follows real changes: workloads appearing or disappearing, not scaling.
