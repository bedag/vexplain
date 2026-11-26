# 0064 A `Spoke` record on the hub for each remote cluster

- **Status:** Accepted on 2026-11-24. Proposed on 2026-11-23. The owner agreed on 2026-11-23 that the hub keeps a record
  per spoke, and that the hub chooses producers and checks freshness from it. The record's shape and the rules across
  clusters are the designer's calls. Revised on 2026-11-24, before acceptance: image evidence comes from the hub's own
  collectors, since the hub scans every image itself (0066). The owner accepted the write-up with the design on
  2026-11-24. Amended on 2026-11-26 after the final review: a `Spoke` whose spoke names its cluster otherwise is
  refused with `ClusterNameMismatch`, and a first contact with an identity that another `Spoke` records, with
  `IdentityInUse` (design 5.3).
- **Date:** 2026-11-23
- **Refines:**
  - 0043: a remote cluster's labels live on its `Spoke`, as the [collector model](../design/2026-11-08-collector-model.md)
    5.6 planned;
  - [collectors, evidence and rules](../design/2026-10-31-collectors-evidence-rules.md) 5.6: the hub reads each spoke's
    collectors into its `Spoke`.
- **Design:** [remote spokes](../design/2026-11-23-remote-spokes.md), sections 4.7, 5.3, 5.7 and 5.8.

## Context

- **The hub chooses producers and checks evidence's freshness from its own `Collector`s.** A remote spoke's collectors
  are invisible to it.
- **Earlier designs promised a record of each spoke on the hub for phase 6.** It was to hold the cluster's labels, set
  on the hub so that a spoke can't choose the lenient playbook, and the spoke's collectors.

## Decision

- **A `Spoke` (config group, cluster-scoped) describes one remote cluster.** Its name is the cluster's name **[call]**.
  - **`spec.labels`:** the cluster's labels, for a playbook's cluster match.
  - **`spec.credentialsSecretRef`:** the Secret with the API server's address, its CA bundle and the token (0062).
  - **`status.clusterID`:** the UID of the spoke's `kube-system` namespace, recorded at the first contact. A later
    contact that finds another UID stops copying until an admin clears it.
  - **`status.collectors`:** each `Collector` on the spoke, with its version, the types it produces and their scopes,
    its operations and roles, and whether it is Ready.
  - **Conditions** `Connected`, `Synced` and `Ready`, and the times of the last sync and of the token's expiry.
- **The hub's own cluster keeps its labels in its `OperatorConfig`,** and has no `Spoke` **[call]**.
- **Across clusters** **[call]**:
  - image evidence comes from the hub's own collectors (0066), so no image waits for a collector that can't reach it;
  - a workload's evidence comes from the collectors of its own cluster, and a source counts for every workload;
  - a pin matches the collector of that name in the workload's cluster;
  - a playbook judges an image when at least one cluster that runs it matches, and its cases count only those
    clusters' workloads.

## Consequences

- **A spoke's labels can't be changed from the spoke.**
- **A collector that runs in one cluster** never holds up, nor multiplies the inputs of, another cluster's workloads.
- **Rejected:** a record that the spoke writes about itself, as Open Cluster Management's agent registers its
  `ManagedCluster`. That would need a credential for the hub on the spoke (0060).

**Precedents:** Open Cluster Management's `ManagedCluster`, Karmada's `Cluster`, and SIG Multicluster's
`ClusterProfile`, which keeps secrets out of the record too.
