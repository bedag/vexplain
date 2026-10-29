# 0006 Exposure from dedicated collectors per source; it changes urgency, never the verdict

- **Status:** Accepted (revised 2026-10-29 in design revision 5: one dedicated collector per source, at the owner's request)
- **Date:** 2026-10-29

## Context

Attackers come from outside. Workloads not reachable through ingress-type resources are much better protected. Network policies tell how far a workload is reachable inside the cluster.

Each source has its own settings, failure modes and optional dependencies. For example, Gateway API and Cilium are only present in some clusters.

## Decision

- **Exposure is computed deterministically by dedicated `Collector`s (0015), one per source:**

  | Collector | Source | Default |
  |---|---|---|
  | `Ingress` | Ingress and IngressClass | on |
  | `Service` | Services of type LoadBalancer and NodePort | on |
  | `GatewayAPI` | HTTPRoute, TLSRoute and GRPCRoute, followed to their Gateways | on if the CRDs exist |
  | `NetworkPolicy` | Kubernetes NetworkPolicy | on |
  | `CiliumPolicy` | CiliumNetworkPolicy and CiliumClusterwideNetworkPolicy | on if the CRDs exist |

  - The route kinds stay in one `GatewayAPI` collector, because they come from one installation and share the logic of following routes to their Gateways.
  - Cilium is separate because its policy model differs.
- **Internal reach** is one of: same namespace only, specific peers, several namespaces, or the whole cluster.
- **Indirect reach** (designer's call): reachable, one hop away, from an externally exposed workload.
- **What counts as external** is set per collector, for example by ingress class, gateway or load-balancer annotation. The default treats everything as external, which errs towards higher urgency.
- **Exposure changes urgency, never the verdict.** "Not exposed" alone can never produce "not affected".
- The agent sees how a digest's instances are exposed and may express exposure-dependent conditions.

## Consequences

- The full NetworkPolicy/RBAC reviewer stays a separate, later idea. These collectors cover what triage needs.
- Default collectors are created by API discovery. `state: Disabled` turns one off for good.
