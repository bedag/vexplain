# 0060 The hub connects to its spokes and pulls; spokes hold no credential for the hub

- **Status:** Accepted on 2026-11-24. Proposed on 2026-11-23. The decision is the owner's, from the brainstorm of phase
  6 on 2026-11-23. Revised on 2026-11-24, before acceptance: the hub writes nothing into a spoke, since it scans every
  image itself (0066). The owner accepted the write-up with the design on 2026-11-24.
- **Date:** 2026-11-23
- **Changes:** 0021: where it says that spokes open every connection, and where it rejects the hub fetching data from
  the spokes. The hub still decides, and the spokes are its eyes.
- **Design:** [remote spokes](../design/2026-11-23-remote-spokes.md), sections 1, 4.1, 5.4 and 5.5.

## Context

- **0021 had each spoke write into the hub's Kubernetes API,** and read its tasks and the result sheets there. The
  hub held no credentials for the spokes.
- **With remote spokes, every spoke would hold a credential for the hub.** RBAC can't narrow a read of the
  cluster-scoped inventory kinds by label. So any spoke could read the whole fleet's inventory, which maps where
  every vulnerable image runs and how exposed it is. It could also rewrite another cluster's presence, or the shared
  evidence that settles findings in every cluster.
- **Isolating the spokes on the hub would take** a namespace per spoke, admission rules on what each spoke writes,
  and a registration flow.
- **The owner treats the hub as a critical, production-grade system** wherever it runs, and so as at least as trusted
  as its most sensitive spoke.

## Options considered

| Option | Costs |
|---|---|
| Spokes connect to the hub, and push (0021) | Every spoke holds a credential for the hub; the hub needs isolation between spokes |
| **The hub connects to each spoke, and pulls (chosen)** | The hub holds a narrow credential per spoke, and must reach each spoke's API server |

## Decision

- **The hub reads each spoke's records from the spoke's own API server.** It writes nothing into a spoke, apart from
  renewing its own token there (0062).
- **No spoke holds a credential for the hub.** A spoke watches only its own cluster.
- **The hub is trusted at least as much as its most sensitive spoke.**

## Consequences

- **Isolation between spokes on the hub needs nothing,** since no spoke has access to it.
- **The hub holds a credential per spoke** (0062), and must reach each spoke (0061).
- **A break-in on the hub** reaches the spokes' vexplain records and namespace labels, which the hub holds anyway. It
  can't write into a spoke, and reaches nothing else in it (design 5.14).
- **Rejected:**
  - spokes pushing into the hub, as 0021 had it;
  - a namespace per spoke on the hub ([phase 3a's fixes](../design/2026-11-15-phase3a-fixes.md), 2.6), which no
    spoke needs once none writes to the hub.

**Precedents:** Argo CD's classic mode, Karmada's push mode and Cluster API connect from the center to each cluster.
So do the controllers built on SIG Multicluster's ClusterProfile API and multicluster-runtime.
