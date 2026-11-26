# 0061 The hub reaches each spoke's API server directly, behind one seam; a tunnel comes later

- **Status:** Accepted on 2026-11-24. Proposed on 2026-11-23. The decision is the owner's, from the brainstorm of phase
  6 on 2026-11-23. The owner accepted the write-up with the design on 2026-11-24.
- **Date:** 2026-11-23
- **Design:** [remote spokes](../design/2026-11-23-remote-spokes.md), sections 4.2 and 5.4.

## Context

- **When the hub pulls (0060), it needs a network path** to each spoke's API server.
- **A cluster that allows no connection in** needs a tunnel that the spoke opens and the hub calls through.
- **The owner's clusters allow the direct path:** the hub can already reach their API servers.

## Options considered

| Option | Costs |
|---|---|
| **Directly, to the spoke's API server (chosen)** | Needs a network path from the hub to each API server |
| A tunnel built into vexplain's manager, as Rancher, k3s, Clusternet and GitLab's agent build theirs | A tunnel protocol of our own to secure and maintain |
| Konnectivity's proxy server and agent, as Kubernetes control planes and Open Cluster Management's cluster-proxy run them | Two more components, with their own certificates and routing |

## Decision

- **The hub connects directly to each spoke's API server,** and always verifies its certificate against the CA bundle
  in the spoke's Secret.
- **One function builds a spoke's client** from its `Spoke` and Secret. It is the seam where a tunnel, or another
  source of tokens, fits in later.
- **A cluster that the hub can't reach gets Konnectivity later,** behind that seam.

## Consequences

- **No extra components.** It works on kind, where the clusters share one Docker network.
- **For other adopters,** direct access needs nothing extra. A later Konnectivity option would ship its proxy server
  and agent as an optional part of the install.
  - A hub on Open Cluster Management could use the cluster-proxy that the platform already runs.
  - A control plane's own Konnectivity can't be used, since it carries only its API server's calls.
- **Rejected:**
  - a tunnel built into vexplain, which nobody needs yet, and which would be our own protocol;
  - Konnectivity now, whose two components nobody needs yet.

**Precedents:** Argo CD, Karmada's push mode and Cluster API connect directly to each cluster's API server.
