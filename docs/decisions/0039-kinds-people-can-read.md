# 0039 Kinds that people can read: summaries, columns and categories

- **Status:** Accepted on 2026-11-07 (decided by the owner, after the first run on a real cluster). Amended on 2026-11-07 while it was built: an image's open findings are its worst manifest's; a report shows its pending images by default, and its workload's kind and name and its mitigations with `-o wide`.
- **Date:** 2026-11-07
- **Refines:** 0012's "troubleshooting takes one command", for the data kinds that phase 2b added.
- **Design:** [main design](../design/2026-10-29-vexplain-design.md), sections 6.1 and 6.2.

## Context

- **vexplain's kinds come in three layers:**
  - **configuration,** written by people: `OperatorConfig`, `Collector`, `CollectorRuntimeConfig`, `Playbook`, `Rule` and `ModelConfig`;
  - **data,** written only by vexplain: `Evidence`, `ImageInventory` and `ImageVerdicts`;
  - **views,** read by people in each namespace: `WorkloadReport` (0038).
- **`kubectl get` showed little of use** for the data kinds: `ImageInventory` showed its digest twice and every platform, and nothing answered "how bad is image X". A list column can't add up a list, so the answers must be fields of the status.
- **Most clusters run one platform,** so a platform column is noise for them.

## Decision

- **Categories:** every kind takes the category `vexplain`, and the data kinds also `vexplain-data`, so `kubectl get vexplain` lists everything and `kubectl get vexplain-data` the data. None takes `all`, so `kubectl get all` stays as it is.
- **`ImageVerdicts`, the sheet of a manifest, gains a summary** that the hub writes with the sheet, from every finding before the sheet's cut: open findings, of them fixable (a fixed version is known) and held (a rule's hold decided them), settled findings, and the findings left out. Its columns: open, fixable, held, settled, omitted, age.
- **`ImageInventory`, the record of an image, gains a summary** that the hub writes from the image's sheets, facts and clusters' entries:
  - the image's name, the first of its repositories;
  - its workloads and namespaces, over every cluster;
  - its scan state: `Scanned`, `Pending`, or the reason of its failure;
  - its open and fixable findings: the most that any of its manifests' sheets counts, since an image's platforms almost always share their findings, and adding them up would count a CVE once for each platform.

  Its columns: image, workloads, namespaces, scan state, open, fixable, age, and platforms only with `-o wide`. The digest column goes: the object's name is the digest.
- **`WorkloadReport`'s columns** read its summary (0038): exposure, highest urgency, updates, to investigate, critical, known exploited, pending images, age; and, with `-o wide`, mitigations, and the workload's kind and name, since a name too long for a report's own is hashed.
- **Platforms stay in the resources;** every platform column has priority 1, so it shows only with `-o wide`.

## Consequences

- One object answers "how bad is image X", and one list answers "which images are worst".
- The hub writes one more field on two kinds, whenever what the summary reads changes.
- **Rejected:** columns over lists with JSONPath filters, which can't count or add, and a separate summary kind, which would be one more object to keep in step.
