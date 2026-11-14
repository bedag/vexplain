# 0042 One report per resource: `ResourceReport`, with actions and their locations

- **Status:** Accepted on 2026-11-08 (decided by the owner). The location of an action is the designer's call.
- **Date:** 2026-11-08
- **Refines:**
  - 0009, 0038 and 0039: the report becomes one kind for every resource, with actions per rule and their locations;
  - 0025: a verdict covers one finding about any subject.

  It confirms 0021 for every resource.
- **Design:** [the collector model](../design/2026-11-08-collector-model.md), sections 4.2, 4.3, 5.7 and 5.8.

## Context

- **Only workloads got a report.** A collector couldn't report on a ConfigMap, a Certificate or a NetworkPolicy.
- **The owner's purpose for a report:** tell a resource's owner where the resource falls short of the platform's security requirements, so that they can decide with full information and see what they could improve. Examples are a workload that can be breached, a ConfigMap holding secrets, a RoleBinding granting too much, and a NetworkPolicy that allows everything.
- **Phase 2b left the cross-image merge open:** two images of one workload merged into one action per package.

## Options considered

| Option | Gains | Costs |
|---|---|---|
| **One kind for every resource (chosen)** | Collector authors never define a kind; the shape of OpenReports | Generic columns |
| A kind per use case, as Trivy Operator has | Columns per use case | Third parties can't add kinds |
| `WorkloadReport` with sections, plus a generic kind for the rest | Workloads keep their kind | Two kinds for one purpose |

## Decision

- **`ResourceReport`, with a cluster-scoped twin, `ClusterResourceReport`.**
  - There is one report per resource. It is owned by the resource, rendered on the spoke, and holds every matching playbook's results.
  - `WorkloadReport` becomes a workload's `ResourceReport`.
  - 0038's summary and 0039's columns carry over, made generic.
- **Results are actions.** The steps:
  - `Update`;
  - `Change`, for the resource itself;
  - `Mitigate`;
  - `Investigate`.

  An action carries:
  - its step and title;
  - its location;
  - its severity, and for CVEs its urgency;
  - its requirement (the playbook and rule);
  - its reason;
  - its findings;
  - details.
- **Every action names its location in the resource,** as a field path, such as a container, `data.KEY` or `spec.ingress[0]`. Items of a list that have names are named. CVE actions merge only within one image.
- **Judging stays on the hub** for every resource (0021). A finding is judged once for each playbook that matches its subject. The hub keeps verdicts per subject and playbook, and the spoke renders.
- **The hub's data kinds are generalized, and collectors don't add kinds of their own.**
  - Verdict sheets are one kind for every subject and playbook.
  - Resources that live in one cluster need no inventory.
  - Only artifacts that run in many places keep one. `ImageInventory` becomes generic when the second artifact type arrives.
- **An action maps onto an OpenReports result.** `Affected` becomes `fail`, `UnderInvestigation` becomes `warn`, and `NotAffected` and `Fixed` become `pass`. The adapter still comes after v1 (0038).
- **Exceptions,** which accept a finding on purpose, come in phase 4 or later, after real-world tests.

## Consequences

- **A collector author never defines a report kind.**
- **The cross-image merge goes away.** Presence must name containers for it (the collector model, section 5.9).
- **`WorkloadReport`'s typed columns become generic** ones, such as steps and severities.
- **Rejected:**
  - a kind per use case;
  - judging one-cluster resources on their spoke, which would put judging logic in two places and break 0021.
