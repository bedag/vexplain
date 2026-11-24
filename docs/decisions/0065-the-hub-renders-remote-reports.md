# 0065 The hub renders each remote cluster's reports and metrics into its own namespace, until the reports' redesign

- **Status:** Accepted on 2026-11-24. Proposed on 2026-11-24. The decision is the owner's, from the brainstorm of phase
  6. It replaces the draft of 2026-11-23, under which remote spokes had no reports until the reports' redesign. The
  details marked **[call]** are the designer's. The owner accepted the write-up with the design on 2026-11-24.
- **Date:** 2026-11-24
- **Changes:**
  - 0021: a remote spoke's mouth, its reports, is rendered on the hub;
  - 0042: a remote cluster's reports live in the hub's operator namespace, with their cluster and namespace.
- **Design:** [remote spokes](../design/2026-11-23-remote-spokes.md), sections 4.6, 5.9 and 5.13.

## Context

- **The SOC's view of the fleet is why remote spokes exist** (owner). The board's per-workload series come from the
  reports: the worklist of open cases, the namespaces' owners, the findings per namespace, the funnel, and each
  playbook's counts per cluster.
- **A spoke's renderer reads the facts, the sheets and the playbooks from the hub.** When the hub pulls (0060), no
  spoke can read the hub.
- **The owner plans to redesign the reports after phase 6:** an output directive per playbook, rendered on the hub and
  pushed into each cluster.
- **The hub holds each image's presence record of every cluster** (0058), with every workload that runs it. The
  `ImageInventory` entries list at most 100 workloads per image, too few for a workload's report.

## Options considered

| Option | Costs |
|---|---|
| No reports on remote spokes until the reports' redesign (draft 1) | The SOC's board shows only the hub's own cluster |
| The hub copies the sheets, facts and playbooks into each spoke, so that the spoke renders | Copies of `ImageInventory` and `ImageVerdicts`, the two kinds the owner wants to drop, plus write access on every spoke |
| The hub renders the reports into each spoke's namespaces | The whole of the reports' redesign, plus write access on every spoke |
| **The hub renders each remote cluster's reports and metrics into its own namespace (chosen)** | The hub copies each spoke's namespace labels too (0063). Every remote report lands in the hub's etcd |

## Decision

- **Per `Spoke`, the hub runs the renderer of a standalone install.** It reads:
  - the copies of that cluster's presence records, exposure and namespace labels;
  - the hub's facts, sheets and playbooks;
  - the `Spoke`'s labels and the hub's urgency table.
- **It reads only copies,** so a spoke that can't be reached keeps its reports and its series, also across a restart
  of the hub **[call]**.
- **It writes that cluster's `ResourceReport`s into the hub's operator namespace.** A report there names its
  workload's cluster and namespace, in its spec and as labels **[call]**. The renderer deletes a report when its
  workload leaves the copies, and deleting the `Spoke` deletes them all.
- **It exports today's report metrics under that cluster's name,** and writes each playbook's counts for that cluster.
- **The hub's own cluster keeps its reports in its own namespaces,** as today.
- **The SOC works from the hub,** where the investigations, the cases, the reports and every metric cover the fleet.

## Consequences

- **The board covers the fleet without changes.**
- **A remote cluster's workload owners see no reports in their own namespaces** until the redesign pushes them there.
- **Every remote report lands in the hub's etcd,** which the measurement covers against 0004's triggers.
- **The renderer runs on the hub too,** wired per `Spoke`. It reaches the hub's state only through the stores, so
  0021's separation holds.
- **Rejected:** the three other options, as above.

**Precedent:** Red Hat ACS's Central shows each secured cluster's findings from the copy it holds.
