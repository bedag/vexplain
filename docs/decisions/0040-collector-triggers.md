# 0040 Collectors declare their triggers; a trigger runtime serves those whose evidence is about the object that changed

- **Status:** Accepted on 2026-11-08 (decided by the owner). Field names and the name of the run-now annotation are the designer's calls.
- **Date:** 2026-11-08
- **Refines:** 0029, under which a collector either watched the cluster itself or was asked per subject. Evidence on demand (the design of collectors, evidence and rules, section 5.6) stays as it is.
- **Design:** [the collector model](../design/2026-11-08-collector-model.md), sections 4.1, 5.2 and 5.3.

## Context

- **When a collector ran was its own code.** The base collectors watched the cluster with informers inside their gRPC servers, and the matcher kept its own six-hour timer. The admin saw none of it, couldn't filter it, and couldn't start a run.
- **The owner's view:** the collector knows which resources it needs, so it should state its own triggers, filtered with CEL, plus schedules for sources outside the cluster. "Run now" belongs to collectors, and playbooks run continuously. Collectors stay gRPC servers.

## Options considered

| Option | Gains | Costs |
|---|---|---|
| A: each collector watches, with the SDK doing the work | No new platform part | Collectors not written in Go rebuild the runtime. Every collector holds cluster-wide read access, and the admin's filter is only honoured. A CVE in the runtime means rebuilding every collector. |
| B: the spoke watches for every collector, and serves joins through `requires` | One model | It rewrites exposure and workloads. Exposure's inputs can't be narrowed anyway. Ruled out by the owner. |
| **C (chosen): B for collectors whose evidence is about the object that changed; the stream for the rest** | Thin collectors in any language, with no cluster rights; an enforced filter; one watch per kind | Two models; a shared point of failure |

## Decision

- **Four kinds of trigger:**
  1. **cluster events,** declared in `GetCapabilities` like an admission webhook's rules: resources with operations, and CEL `matchConditions` over `object` and `oldObject`;
  2. **evidence on demand,** unchanged;
  3. **schedules,** declared by the author with a cron default;
  4. **evidence subscriptions** (0048).
- **The admin narrows triggers on the `Collector`, never widens them,** as a `ValidatingAdmissionPolicyBinding` narrows its policy. The admin can also change schedules. `OperatorConfig`'s scope applies on top.
- **Run now** is an annotation on the `Collector`, as Flux's `reconcile.fluxcd.io/requestedAt`. A schedule fires at once, and an event trigger delivers every matching object again.
- **Where watching lives:** a trigger runtime on the spoke serves collectors whose evidence is about the object that changed. Collectors where one change alters evidence about other objects keep their own watch and the `Watch` stream.
- **The trigger runtime's first version:**
  - its own Deployment, which may only list and watch;
  - one watch per kind, which checks the author's filter, the admin's filter and the scope;
  - the latest state of each object, with retries and back-off;
  - a full delivery whenever a collector starts;
  - evidence dropped when its object goes away;
  - trigger health on the `Collector`'s status.
- **No admission webhooks.** vexplain stays out of the API server's request path.

## Consequences

- **Triggered collectors are thin.** They get no API token, and the admin's filter is enforced, not honoured.
- **Two models to document and test,** and the trigger runtime is a shared point of failure. The scaling measures are recorded as options, each with its signal (the collector model, section 9).
- **The matcher's timer becomes a declared schedule** (0046).
- **Rejected:** A, B, admission webhooks.
