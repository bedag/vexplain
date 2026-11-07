# 0038 A workload's report lists actions, with a summary that answers "is it impacted?"

- **Status:** Accepted on 2026-11-07 (decided by the owner, after the first run on a real cluster). Amended on 2026-11-07 while it was built: an update names its target only where the version order is unambiguous, reading a release suffix by the package's type; the summary counts the images that have no verdict yet; an action counts the digests that it leaves out; an action takes the most urgent value of its CVEs across sheets.
- **Date:** 2026-11-07
- **Refines:** 0009's report, which listed every open finding. The format stays vexplain's own `WorkloadReport`; an adapter to OpenReports comes after v1.
- **Design:** [main design](../design/2026-10-29-vexplain-design.md), sections 6.2 and 6.10.

## Context

- **A report listed every open CVE of every image that its workload runs,** one line each. On a real cluster that meant hundreds of lines for a single workload, mostly the same package with another CVE, and an image's list repeated in every workload that runs it. Nobody can read that, and it isn't the decision that a namespace owner makes.
- **The decision is "is my workload impacted, and what do I do?"** What a person does is update a package, mitigate, or have it investigated, and one update fixes every CVE of that package that the new version fixes.
- **The complete per-CVE signal already exists elsewhere:** `vexplain_open_case` has one series for each workload, digest and CVE, for every open finding, for alerts and dashboards; and the sheets (`ImageVerdicts`) hold every finding of each manifest, which the report names by its digest labels.
- **Formats elsewhere:** Trivy Operator keeps its own `VulnerabilityReport`, and a community adapter copies it into the Policy Working Group's `PolicyReport`. Kyverno writes OpenReports (`openreports.io`, the successor of `PolicyReport`) behind an alpha flag. A typed kind of our own keeps our columns and fields; an action maps one to one onto an OpenReports result, so the adapter stays simple.

## Decision

- **A report's results are actions.** The open findings of the workload's images are grouped by package, installed version and next step (`Update`, `Mitigate` or `Investigate`, as 0024 decides it for each finding). So a package whose CVEs a newer version partly fixes gives one update, and one action for the CVEs that no version fixes.
- **An action carries:**
  - its step, and the package's name, type and installed version;
  - for an update, the highest fixed version among its CVEs, but only where that order is unambiguous: each CVE names one fixed version, and every version involved is plain dotted numbers with at most a release suffix that the package's type orders after the plain version: `-rN` for apk, `-N` for deb and rpm, `.elN` for rpm. Other types, such as npm, Go modules, Cargo and RubyGems, read `-N` as a pre-release, so they take plain dotted numbers only. Epochs, pre-releases, tildes, fixes on several branches and mixed forms name no target, since a wrong one is worse than none; each CVE's fixed versions stay in the sheets;
  - the highest severity and the highest urgency of its CVEs, and whether one of them is known to be exploited; where two images' sheets differ about one CVE, the action takes the more urgent value, and counts it as known exploited if either sheet does;
  - the number of its CVEs, and the IDs of the first 5, most urgent first, then most severe;
  - the digests of the images in which it was found, at most 8, and the number of those left out.
- **At most 256 actions,** most urgent first, then most severe, then by package. The summary counts the rest.
- **A summary in the report's status** answers "impacted?" without reading the actions, and feeds the list columns:
  - the findings by status, counted as the metrics count them: an open finding once for each vulnerability and package of the workload, a settled one once for each manifest, from the sheets;
  - the number of actions, of updates, of mitigations and of investigations, and of actions left out;
  - the highest urgency, the number of open findings of `Critical` severity, and the number known to be exploited;
  - the workload's images that have no verdict yet, over every image it runs: how many are `Pending` (no sheet yet, or a scan that failed) and how many `Incomplete` (a sheet that left findings out). A report whose images aren't settled never reads as clean: its default columns show them.
- **Reach:** besides the SSVC exposure, the report shows the workload's internal reach (`Namespace`, `Peers`, `Namespaces` or `Cluster`) and whether it is indirectly exposed, from the exposure evidence. Which frontend makes it so needs a field of the exposure type, and comes later.
- **What stays out:** settled findings appear only in the summary's counts; the load check's notes, which are per CVE, stay in the sheets.

## Consequences

- A report shrinks to the decisions it asks for, and an image's detail lives once, in its sheets.
- Searching reports for one CVE finds it only among an action's first 5 IDs; `vexplain_open_case` is the complete answer to "which workloads does CVE-X hit".
- `WorkloadReport`'s status changes shape: `findings` and `omitted` give way to `actions` and `summary`. The API is `v1alpha1` and nothing is released, so the change needs no conversion; an install upgrades fresh.
- **Rejected:**
  - **One line per CVE, trimmed by a bound:** it trims the wrong thing, and still repeats the package.
  - **Every CVE ID in each action:** complete, but the metric already is; 5 and a count keep an action readable.
  - **OpenReports as the stored format now:** its CRDs are alpha and rarely installed; an adapter after v1 serves those who use it.
