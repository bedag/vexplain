# 0048 `network-reach` builds on family collectors through evidence subscriptions

- **Status:** Accepted on 2026-11-08 (decided by the owner). It is built in phase 3b and judged on the next live run.
- **Date:** 2026-11-08
- **Refines:**
  - 0006: exposure from dedicated collectors per source, which 0029 merged into one;
  - 0032: evidence types, which can now be subscribed to.
- **Design:** [the collector model](../design/2026-11-08-collector-model.md), sections 4.5, 5.2 and 5.9.

## Context

- **The exposure collector joins up to fourteen kinds,** and its facts about policies and routes serve no other playbook.
- **The owner wants collectors for each family:** NetworkPolicies with Cilium's, Ingresses, and the Gateway API. Then their own playbooks can judge those resources, and the same collectors serve several use cases.
- **The first live run showed** that exposure needs platform settings before anything else can be judged.

## Options considered

| Option | Costs |
|---|---|
| One collector, as today | Its facts about policies and routes serve nothing else |
| Family collectors, with exposure reading the kinds itself and sharing the parsing code | Reuse only through code; two readers of the same kinds |
| **Family collectors, with `network-reach` building on their evidence (chosen)** | A new kind of trigger, and a join that depends on other collectors |

## Decision

- **Phase 3a: settings first.**
  - `trustedPeers`, matched by namespace labels, pod labels and service accounts. It is empty by default, and the trusted peers are listed in the evidence.
  - Separate settings for host network, host ports and NodePort Services.
  - The evidence names the peers that widened reach, and what the collector couldn't see.
  - Then a re-run on a live cluster.
- **Phase 3b: the split.**
  - **The family collectors:** `network-policies` (NetworkPolicy and Cilium's policies), `ingresses` and `gateway-api`. They are triggered (0040), report facts about their own objects, and ship with the first playbook about them.
  - **Evidence subscriptions:** a collector names the types it subscribes to, and the spoke forwards evidence of those types, as Knative's Triggers route CloudEvents by type.
  - **`network-reach` subscribes to them,** and keeps reading pods, Services and EndpointSlices itself. Without a family collector, it assumes the widest reach.
- **Built properly, not as a spike.** It is judged on the next live run.

## Consequences

- **The same facts serve reach and their own playbooks.**
- **Trusted peers lower reach on the admin's word,** so the evidence lists them. Reach changes urgency, never a verdict (0006).
- **A missing family collector errs towards caution.**
- **Rejected:**
  - a throwaway spike, since the owner chose to build it;
  - sharing code only.
