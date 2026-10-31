# Decision records

One short file per decision, numbered in order, kept in the repository.

- **Status:** `Accepted` (decided or confirmed by the owner) or `Proposed` (designer's call, waiting for confirmation).
- **Changes:** a record that changes later gets a note in its status line, or a new record that refines or supersedes it.

| # | Decision | Status |
|---|---|---|
| [0001](0001-build-cve-triage-operator.md) | Build a CVE triage operator with an embedded investigator agent | Accepted |
| [0002](0002-kubescape-as-first-scan-source.md) | Kubescape as an optional collector and part of v1; built-in Syft/Grype as the base (Kubescape becomes a collector package, 0029) | Accepted |
| [0003](0003-hub-and-spoke.md) | Hub-and-spoke topology, starting with one cluster as both (roles refined by 0021) | Accepted |
| [0004](0004-crds-first-storage-gate.md) | CRDs first; bulky data in its own group; designed for a cheap switch, decided on real data | Accepted |
| [0005](0005-review-policy.md) | Agent "not affected" needs human review by default; auto-acceptance configurable | Accepted |
| [0006](0006-exposure-collectors.md) | Exposure from dedicated collectors per source; it changes urgency, never the verdict (urgency refined by 0024; one collector package, installed means enabled, 0029) | Accepted |
| [0007](0007-extension-points.md) | Collectors compiled in; built-in agent tools plus MCP plug-ins with declared evidence kinds (superseded by 0029, 0031 and 0032) | Accepted |
| [0008](0008-sandbox-runs.md) | Sandbox runs on demand, off by default, part of v1; `SandboxRun` in any namespace; pull credentials copied or admin-provided (the sandbox becomes a collector, 0029 and 0030) | Accepted |
| [0009](0009-namespace-reports-and-outputs.md) | Namespaced workload reports without a review gate; metrics as counts plus open cases | Accepted |
| [0010](0010-rule-results-not-reviewed-per-finding.md) | Rule-settled results are not reviewed per finding (scope refined by 0025) | Accepted |
| [0011](0011-image-identity-and-content.md) | Image identity from running pods (reported digest); scanning by platform manifest digest; content pulled by digest from any registry (pulls refined by 0022) | Accepted |
| [0012](0012-kubebuilder-and-api-practices.md) | kubebuilder and the team's API design practices (`Collector` installs a package, 0029) | Accepted |
| [0013](0013-llm-and-data.md) | An on-prem model through an OpenAI-compatible endpoint; workload metadata may be sent | Accepted |
| [0014](0014-no-verdict-summary-and-events.md) | Every "no verdict" comes with a summary; key situations emit Events | Accepted |
| [0015](0015-config-resources-and-scope.md) | Configuration split into small resources; scope by label selectors; admin-set cluster name (`Collector` installs a package; `CollectorRuntimeConfig`, `Playbook` and `Rule` added; `ToolServer` dropped; 0029 to 0034) | Accepted |
| [0016](0016-agent-profile-and-editable-prompt.md) | One default `AgentProfile` with optional overrides; editable guidance through a ConfigMap; the core stays in the binary (playbooks name the profile, 0034) | Accepted |
| [0017](0017-model-config.md) | LLM connection in a `ModelConfig` resource, referenced from `AgentProfile`; HTTPS only, labelled Secrets | Accepted |
| [0018](0018-name-and-api-groups.md) | Name `vexplain`; three API groups under `vexplain.bedag.ch` | Accepted |
| [0019](0019-inventory-presence-counts.md) | `ImageInventory` records per-cluster presence: counts plus bounded workload references | Accepted |
| [0020](0020-owner-attribution.md) | Owner attribution from allowlisted labels and annotations, resolved on the spoke (by the `workloads` collector, 0029) | Accepted |
| [0021](0021-hub-decides-spokes-observe.md) | The hub decides; spokes observe, execute and render; spokes open every connection (scan results refined by 0022; spokes run collectors, and the hub asks for evidence, 0029 and 0032) | Accepted |
| [0022](0022-scan-jobs-and-hub-matcher.md) | Scans run as a Job per image on the spoke; CVE matching runs once, at the hub (`govulncheck` moved out by 0027; the scanner and the matcher become collectors, 0029 and 0030) | Accepted |
| [0023](0023-write-once-package-lists.md) | Package lists kept write-once per platform manifest digest, compressed, in their own inventory kind; CVE matches only in the verdict sheet (one evidence store per subject, type and source, 0032) | Accepted |
| [0024](0024-ssvc-urgency.md) | Urgency follows SSVC's deployer tree; a fix decides the next step, never the verdict | Accepted |
| [0025](0025-verdicts-cover-one-finding.md) | A rule's verdict covers one finding, a CVE in one package of one image; `ImageVerdicts` keyed on the platform manifest digest | Accepted |
| [0026](0026-load-check-definition.md) | What the load check searches and skips; "removed in a later layer" means files gone, database entry left (settling withdrawn by 0028; the load check becomes a default `Rule`, 0033) | Accepted |
| [0027](0027-govulncheck-collector.md) | `govulncheck` becomes its own collector, after phase 2a (a collector with a part in each role, 0029) | Accepted |
| [0028](0028-load-check-settles-nothing.md) | The load check records its evidence and settles nothing; a verdict on loading returns with runtime evidence, a stated confidence and a policy (the way back becomes a `Rule`, 0032 and 0033) | Accepted |
| [0029](0029-collector-packages.md) | A collector is a package that implements one gRPC API; installed means enabled; vexplain's own collectors too | Proposed |
| [0030](0030-collector-runtime-config.md) | A runtime config shapes the Deployment a collector runs in | Proposed |
| [0031](0031-tools-from-collectors.md) | The agent's tools come from collectors; an MCP server is a collector that serves only the agent | Proposed |
| [0032](0032-evidence-as-cloudevents.md) | Evidence travels as CloudEvents; collectors define their own types and subjects; each type declares its scope | Proposed |
| [0033](0033-rules-in-cel.md) | Rules are reusable steps that decide about one finding in CEL | Proposed |
| [0034](0034-playbooks.md) | A playbook describes each use case: its subjects, findings, evidence, rules, and what goes to the agent | Proposed |
