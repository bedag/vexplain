# 0004 CRDs first; bulky data in its own API group; design for a cheap switch, decide on real data

- **Status:** Accepted (revised 2026-10-29: own domain, three groups (0018); in design revision 5, no early verdict and a cheap switch, at the owner's request)
- **Date:** 2026-10-29

## Context

Several thousand images, around-the-clock scans and continuous new CVEs produce a lot of data and constant change. etcd handles that poorly: there is a limit of about 1.5 MB per object. Kubescape solved the same problem with an aggregated API server for its SBOM storage.

Neither kind nor a synthetic load can tell whether CRDs hold up. That takes a real cluster over time: real scan churn, the rescans after each update of the vulnerability database, and a normal week's write rate.

A custom API server is not needed to share data across clusters. The hub's normal API already does that.

## Decision

- **API groups** follow the kubebuilder sample pattern `<group>.vexplain.bedag.ch`:
  - admin-owned kinds in `config`
  - assessments and results in `triage`
  - bulky, derived data in `inventory`
- **Start with CRDs and design for a cheap switch:**
  - **One door:** only the storage interfaces (`inventory.Store`, and later one per bulky kind) touch inventory objects.
  - **Bulky data is derived data.** Presence comes from the spokes and facts from rescans, so a backend switch means rebuilding, not migrating. Data that can't be rebuilt, such as reviews (`VexStatement`), is small and stays in CRDs.
  - **No reliance on CRD-only behaviour for correctness.** The storage interface validates what the CEL rules check.
  - **A stable group and version,** so an aggregated API server can take over the `inventory` group without clients noticing.
- **Measure from phase 1, decide on real data.** The operator exports object sizes and write rates, next to the API server's and etcd's own metrics. The decision is made once a real test cluster has run long enough, not at a fixed phase.
- **Triggers** (designer's call, to be revisited with real numbers):
  - any inventory object above 512 KiB
  - a sustained write rate above 5 per second
  - inventory objects above 10% of etcd's database size

## Consequences

- **Lean CRDs:** summaries, verdicts and references.
- **Two options when a trigger fires:**
  - an aggregated API server with its own database, as Kubescape does
  - keeping the CRDs lean and moving the bulky payloads (SBOMs, CVE lists) to object storage referenced by digest

  Neither is built until a trigger fires.
