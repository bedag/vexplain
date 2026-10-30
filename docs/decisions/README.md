# Decision records

One short file per decision, numbered in order, kept in the repository.

- **Status:** `Accepted` (decided or confirmed by the owner) or `Proposed` (designer's call, waiting for confirmation).
- **Changes:** a record that changes later gets a note in its status line, or a new record that refines or supersedes it.

| # | Decision | Status |
|---|---|---|
| [0001](0001-build-cve-triage-operator.md) | Build a CVE triage operator with an embedded investigator agent | Accepted |
| [0002](0002-kubescape-as-first-scan-source.md) | Kubescape as an optional collector and part of v1; built-in Syft/Grype as the base | Accepted |
| [0003](0003-hub-and-spoke.md) | Hub-and-spoke topology, starting with one cluster as both (roles refined by 0021) | Accepted |
| [0004](0004-crds-first-storage-gate.md) | CRDs first; bulky data in its own group; designed for a cheap switch, decided on real data | Accepted |
| [0005](0005-review-policy.md) | Agent "not affected" needs human review by default; auto-acceptance configurable | Accepted |
| [0006](0006-exposure-collectors.md) | Exposure from dedicated collectors per source; it changes urgency, never the verdict (urgency refined by 0024) | Accepted |
| [0007](0007-extension-points.md) | Collectors compiled in; built-in agent tools plus MCP plug-ins with declared evidence kinds | Accepted |
| [0008](0008-sandbox-runs.md) | Sandbox runs on demand, off by default, part of v1; `SandboxRun` in any namespace; pull credentials copied or admin-provided | Accepted |
| [0009](0009-namespace-reports-and-outputs.md) | Namespaced workload reports without a review gate; metrics as counts plus open cases | Accepted |
| [0010](0010-rule-results-not-reviewed-per-finding.md) | Rule-settled results are not reviewed per finding | Accepted |
| [0011](0011-image-identity-and-content.md) | Image identity from running pods (reported digest); scanning by platform manifest digest; content pulled by digest from any registry (pulls refined by 0022) | Accepted |
| [0012](0012-kubebuilder-and-api-practices.md) | kubebuilder and the team's API design practices | Accepted |
| [0013](0013-llm-and-data.md) | An on-prem model through an OpenAI-compatible endpoint; workload metadata may be sent | Accepted |
| [0014](0014-no-verdict-summary-and-events.md) | Every "no verdict" comes with a summary; key situations emit Events | Accepted |
| [0015](0015-config-resources-and-scope.md) | Configuration split into small resources; scope by label selectors; admin-set cluster name | Accepted |
| [0016](0016-agent-profile-and-editable-prompt.md) | One default `AgentProfile` with optional overrides; editable guidance through a ConfigMap; the core stays in the binary | Accepted |
| [0017](0017-model-config.md) | LLM connection in a `ModelConfig` resource, referenced from `AgentProfile`; HTTPS only, labelled Secrets | Accepted |
| [0018](0018-name-and-api-groups.md) | Name `vexplain`; three API groups under `vexplain.bedag.ch` | Accepted |
| [0019](0019-inventory-presence-counts.md) | `ImageInventory` records per-cluster presence: counts plus bounded workload references | Accepted |
| [0020](0020-owner-attribution.md) | Owner attribution from allowlisted labels and annotations, resolved on the spoke | Accepted |
| [0021](0021-hub-decides-spokes-observe.md) | The hub decides; spokes observe, execute and render; spokes open every connection (scan results refined by 0022) | Accepted |
| [0022](0022-scan-jobs-and-hub-matcher.md) | Scans run as a Job per image on the spoke; CVE matching runs once, at the hub | Accepted |
| [0023](0023-write-once-package-lists.md) | Package lists kept write-once per platform manifest digest, compressed, in their own inventory kind; CVE matches only in the verdict sheet | Accepted |
| [0024](0024-ssvc-urgency.md) | Urgency follows SSVC's deployer tree; a fix decides the next step, never the verdict | Accepted |
