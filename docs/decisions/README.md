# Decision records

One short file per decision, numbered in order, kept in the repository.

- **Status:** `Accepted` (decided or confirmed by the owner) or `Proposed` (designer's call, waiting for confirmation).
- **Changes:** a record that changes later gets a note in its status line, or a new record that refines or supersedes it.

| # | Decision | Status |
|---|---|---|
| [0001](0001-build-cve-triage-operator.md) | Build a CVE triage operator with an embedded investigator agent | Accepted |
| [0002](0002-kubescape-as-first-scan-source.md) | Kubescape as an optional collector and part of v1; built-in Syft/Grype as the base (Kubescape becomes a collector package, 0029; Kubescape moves after phase 4, 0049) | Accepted |
| [0003](0003-hub-and-spoke.md) | Hub-and-spoke topology, starting with one cluster as both (roles refined by 0021) | Accepted |
| [0004](0004-crds-first-storage-gate.md) | CRDs first; bulky data in its own group; designed for a cheap switch, decided on real data (the hub's copies of its spokes' records measured against it, 0063) | Accepted |
| [0005](0005-review-policy.md) | Agent "not affected" needs human review by default; auto-acceptance configurable | Accepted |
| [0006](0006-exposure-collectors.md) | Exposure from dedicated collectors per source; it changes urgency, never the verdict (urgency refined by 0024; one collector package, installed means enabled, 0029; host ports, the host network and external IPs count too, design 6.4; exposure is split into family collectors again, under `network-reach`, 0048; exposure rules on the hub decide it for cases, 0059) | Accepted |
| [0007](0007-extension-points.md) | Collectors compiled in; built-in agent tools plus MCP plug-ins with declared evidence kinds (superseded by 0029, 0031 and 0032) | Accepted |
| [0008](0008-sandbox-runs.md) | Sandbox runs on demand, off by default, part of v1; `SandboxRun` in any namespace; pull credentials copied or admin-provided (the sandbox becomes a collector, 0029 and 0030; the scanner takes the sandbox's two modes for pull credentials, 0047) | Accepted |
| [0009](0009-namespace-reports-and-outputs.md) | Namespaced workload reports without a review gate; metrics as counts plus open cases (`ResourceReport` for every resource, 0042) | Accepted |
| [0010](0010-rule-results-not-reviewed-per-finding.md) | Rule-settled results are not reviewed per finding (scope refined by 0025) | Accepted |
| [0011](0011-image-identity-and-content.md) | Image identity from running pods (reported digest); scanning by platform manifest digest; content pulled by digest from any registry (pulls refined by 0022; the images of remote clusters scanned on the hub, 0066) | Accepted |
| [0012](0012-kubebuilder-and-api-practices.md) | kubebuilder and the team's API design practices (`Collector` installs a package, 0029) | Accepted |
| [0013](0013-llm-and-data.md) | An on-prem model through an OpenAI-compatible endpoint; workload metadata may be sent | Accepted |
| [0014](0014-no-verdict-summary-and-events.md) | Every "no verdict" comes with a summary; key situations emit Events | Accepted |
| [0015](0015-config-resources-and-scope.md) | Configuration split into small resources; scope by label selectors; admin-set cluster name (`Collector` installs a package; `CollectorRuntimeConfig`, `Playbook` and `Rule` added; `ToolServer` dropped; 0029 to 0034) | Accepted |
| [0016](0016-agent-profile-and-editable-prompt.md) | One default `AgentProfile` with optional overrides; editable guidance through a ConfigMap; the core stays in the binary (playbooks name the profile, 0034) | Accepted |
| [0017](0017-model-config.md) | LLM connection in a `ModelConfig` resource, referenced from `AgentProfile`; HTTPS only, labelled Secrets | Accepted |
| [0018](0018-name-and-api-groups.md) | Name `vexplain`; three API groups under `vexplain.bedag.ch` | Accepted |
| [0019](0019-inventory-presence-counts.md) | `ImageInventory` records per-cluster presence: counts plus bounded workload references | Accepted |
| [0020](0020-owner-attribution.md) | Owner attribution from allowlisted labels and annotations, resolved on the spoke (by the `workloads` collector, 0029) | Accepted |
| [0021](0021-hub-decides-spokes-observe.md) | The hub decides; spokes observe, execute and render; spokes open every connection (scan results refined by 0022; spokes run collectors, and the hub asks for evidence, 0029 and 0032; one-cluster resources are judged on the hub too, 0042; the hub decides exposure for its cases, 0059; the hub connects to its spokes, scans every image and renders the remote metrics, 0060, 0065 and 0066) | Accepted |
| [0022](0022-scan-jobs-and-hub-matcher.md) | Scans run as a Job per image on the spoke; CVE matching runs once, at the hub (`govulncheck` moved out by 0027; the scanner and the matcher become collectors, 0029 and 0030; the matcher becomes `vulnerabilities` and consumes `sbom`, 0044 and 0046; a remote cluster's images scanned on the hub with the admin's logins, 0066) | Accepted |
| [0023](0023-write-once-package-lists.md) | Package lists kept write-once per platform manifest digest, compressed, in their own inventory kind; CVE matches only in the verdict sheet (one evidence store per subject, type and source, 0032) | Accepted |
| [0024](0024-ssvc-urgency.md) | Urgency follows SSVC's deployer tree; a fix decides the next step, never the verdict (KEV holds a finding open, 0035; fix targets follow each ecosystem's version order, 0046; a workload whose exposure rule misses an input is Unknown, 0059) | Accepted |
| [0025](0025-verdicts-cover-one-finding.md) | A rule's verdict covers one finding, a CVE in one package of one image; `ImageVerdicts` keyed on the platform manifest digest (a verdict covers one finding of any subject, 0042 and 0043) | Accepted |
| [0026](0026-load-check-definition.md) | What the load check searches and skips; "removed in a later layer" means files gone, database entry left (settling withdrawn by 0028; the load check becomes a default `Rule`, 0033) | Accepted |
| [0027](0027-govulncheck-collector.md) | `govulncheck` becomes its own collector, after phase 2a (a collector with a part in each role, 0029; govulncheck waits until the other collectors are settled, collector model 5.9) | Accepted |
| [0028](0028-load-check-settles-nothing.md) | The load check records its evidence and settles nothing; a verdict on loading returns with runtime evidence, a stated confidence and a policy (the way back becomes a `Rule`, 0032 and 0033) | Accepted |
| [0029](0029-collector-packages.md) | A collector is a package that implements one gRPC API; installed means enabled; vexplain's own collectors too (collectors declare triggers and ship permissions, 0040 and 0041) | Accepted |
| [0030](0030-collector-runtime-config.md) | A runtime config shapes the Deployment a collector runs in | Accepted |
| [0031](0031-tools-from-collectors.md) | The agent's tools come from collectors; an MCP server is a collector that serves only the agent | Accepted |
| [0032](0032-evidence-as-cloudevents.md) | Evidence travels as CloudEvents; collectors define their own types and subjects; each type declares its scope (the `sbom` type, `maxAge`, subscriptions, 0044, 0045 and 0048; exposure and presence `Hub`-scoped, host and address subjects, 0058 and 0059) | Accepted |
| [0033](0033-rules-in-cel.md) | Rules are reusable steps that decide about one finding in CEL (a rule that confirms names a step, a title and a severity, 0043; or it decides one workload's exposure, 0059) | Accepted |
| [0034](0034-playbooks.md) | A playbook describes each use case: its subjects, findings, evidence, rules, and what goes to the agent (playbooks match on types, run several at once, show the fleet picture, 0043) | Accepted |
| [0035](0035-known-exploited-holds.md) | Known exploited holds a finding open; urgency carries the exploitation | Accepted |
| [0036](0036-status-for-kstatus.md) | Status that kstatus can read: `observedGeneration`, `Reconciling` and `Stalled` on every reconciled kind; a playbook that isn't Ready raises an event and a gauge | Accepted |
| [0037](0037-collectors-proxy-from-runtime-config.md) | A collector's proxy comes from its runtime config, not from the operator; pods a collector creates take environment variables from its settings | Accepted |
| [0038](0038-reports-as-actions.md) | A workload's report lists actions, one for each package and step, with a summary that answers "is it impacted?" (actions per rule, with locations, 0042) | Accepted |
| [0039](0039-kinds-people-can-read.md) | Kinds that people can read: summaries in the status, columns that read them, and categories (`ResourceReport`, 0042) | Accepted |
| [0040](0040-collector-triggers.md) | Collectors declare their triggers; a trigger runtime serves those whose evidence is about the object that changed | Accepted |
| [0041](0041-shipped-permissions.md) | Collectors ship their permissions; vexplain grants them under a ceiling and a deny list | Accepted |
| [0042](0042-resource-reports.md) | One report per resource: `ResourceReport`, with actions and their locations | Accepted |
| [0043](0043-playbook-matching.md) | Playbooks name types, take optional entries and a match, run several at once, and show the fleet picture (pipelines list exposure rules too, 0059; a remote cluster's labels on its `Spoke`, 0064) | Accepted |
| [0044](0044-sbom-type.md) | A neutral `sbom` type between scanners and the matcher | Accepted |
| [0045](0045-evidence-max-age.md) | Evidence `maxAge` is set where evidence is produced (built with the sources' answers, 0059) | Accepted |
| [0046](0046-fix-targets-and-names.md) | Fix targets come from the `vulnerabilities` collector; collectors are named after what they deliver | Accepted |
| [0047](0047-scanner-pull-credentials.md) | The scanner's pull credentials: `CopyFromWorkload` and `AdminProvided` (the hub's logins for remote clusters' images, 0066) | Accepted |
| [0048](0048-network-reach-on-family-collectors.md) | `network-reach` builds on family collectors through evidence subscriptions (entry points come before the re-cut, 0058 and 0059) | Accepted |
| [0049](0049-kubescape-after-the-agent.md) | Kubescape moves after the agent | Accepted |
| [0050](0050-agent-before-generalization.md) | The agent's work on cases comes before the generalization of phase 3b | Accepted |
| [0051](0051-investigations.md) | An `Investigation` runs the agent on a playbook's cases: once, on a schedule, or continuously; its status is the answer; a cap counts cases | Accepted |
| [0052](0052-verdicts-belong-to-the-case.md) | A verdict belongs to the case; the hub creates an `Assessment` only for cases that are selected (`runsIn` groups the workloads by exposure, outside the inputs, 0059) | Accepted |
| [0053](0053-safety-core-behind-mcp.md) | The agent's safety core sits behind vexplain's own MCP server; the runner can be replaced (both run in agent workers, 0057) | Accepted |
| [0054](0054-advisories.md) | Advisories: the vulnerability database first, then pages fetched from allowlisted domains, checked twice | Accepted |
| [0055](0055-agent-context.md) | The agent's context stays small: tools found by search, bounded results, limits that fit the model | Accepted |
| [0056](0056-phase-4-scope.md) | Phase 4's scope: one existing MCP server, no auto-acceptance, dashboards after the agent; company knowledge is phase 5, sandbox runs after it | Accepted |
| [0057](0057-agent-workers.md) | The agent runs in its own workers, which claim cases through the API; the manager keeps choosing them | Accepted |
| [0058](0058-streamed-evidence-on-the-hub.md) | Streamed evidence of `Hub` scope reaches the hub's store, which keeps each record current; exposure and presence become `Hub`-scoped (a remote cluster's records reach the hub through its copy, 0063) | Accepted |
| [0059](0059-exposure-rules-on-the-hub.md) | Exposure rules decide each workload's exposure on the hub, from presence, exposure and the sources' answers (an address that two clusters name gets no source's answer, remote spokes 5.10) | Accepted |
| [0060](0060-the-hub-pulls.md) | The hub connects to its spokes and pulls; spokes hold no credential for the hub | Accepted |
| [0061](0061-direct-access-behind-one-seam.md) | The hub reaches each spoke's API server directly, behind one seam; a tunnel comes later | Accepted |
| [0062](0062-the-hubs-credential-for-a-spoke.md) | The hub's credential for a spoke: a narrow service account whose short-lived token the hub renews | Accepted |
| [0063](0063-the-hub-copies-spoke-records.md) | The hub copies its spokes' records into its own stores | Accepted |
| [0064](0064-a-spoke-record-on-the-hub.md) | A `Spoke` record on the hub for each remote cluster | Accepted |
| [0065](0065-the-hub-renders-remote-reports.md) | The hub renders each remote cluster's reports and metrics into its own namespace, until the reports' redesign (amended: metrics and counts only, no report objects) | Accepted |
| [0066](0066-the-hub-scans-every-image.md) | The hub scans every image itself, from its registry; spokes don't scan | Accepted |
