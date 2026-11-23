# 0051 An `Investigation` runs the agent on a playbook's cases: once, on a schedule, or continuously

- **Status:** Accepted on 2026-11-16. The decisions are the owner's, from the phase 4 discussion, and the owner accepted the write-up on 2026-11-16. On 2026-11-20 the status came to count only the selected cases, and to show their tokens ([phase 4's fixes](../design/2026-11-20-phase4-live-fixes.md), 2.5). Later on 2026-11-20 its agent settings moved under `spec.agent`, which added the investigation's guidance and `judgePolicy` ([the investigation's guidance](../design/2026-11-20-investigation-guidance.md)). On 2026-11-21 the guidance became fixed for the investigation's life, and a judgement came to name its investigation by `investigationRef`, with its uid ([phase 4's fixes](../design/2026-11-20-phase4-live-fixes.md), 7.5 and 7.6).
- **Date:** 2026-11-16
- **Refines:** 0034 (what goes to the agent), the collector model's decision that the agent gets a playbook's output only on demand (its section 1), and the main design's budgets and kill switch (6.2, 6.10).
- **Design:** [the agent on image cases](../design/2026-11-16-agent-on-cases.md), sections 4.1, 5.2, 5.3 and 5.11.

## Context

- **The rules leave most findings open.** One or two workers on an on-prem model can't judge them all, and new CVEs keep coming.
- **The SOC's job:** find where the fleet is affected by a CVE, where to start, and whom to contact.
- **The owner wants control over tokens,** and fully automatic runs where the SOC is sure that some cases should always be checked.
- **Where triggers live elsewhere:**
  - OASIS CACAO's playbooks have no trigger; an orchestrator runs them.
  - Kubernetes separates definition and run: Tekton's Pipeline and PipelineRun, Job and CronJob.
  - Microsoft Sentinel and Cortex XSIAM moved triggers into separate automation rules.
  - Kyverno's background scans and k8sgpt keep their results current in one object.

## Decision

- **The playbook says what may go to the agent:** `spec.agent` with `profileRef`, the `evidence` that goes with each case, and `matchConditions`, named CEL as the investigation's are. The playbook that vexplain ships sends what no rule settled. It holds no trigger.
- **An `Investigation` runs it.** Namespaced, in the `triage` group, in any namespace, guarded by RBAC alone. It names one playbook, and selects cases by `vulnerabilities`, names matched against IDs and aliases, and `matchConditions`, as ValidatingAdmissionPolicy names its CEL. CEL sees `finding`, `subject` and `impact`, as rules see `finding` and their inputs; evidence stays with the rules.
- **Its trigger is `Once`, `Schedule` (cron) or `Continuous`.** There is no separate rule kind: verdicts live in the cases, so a run has nothing of its own to keep.
- **Its status is the answer:** the impact, the progress, OpenReports' summary counts, and the first 20 results, most urgent first, in 0042's action shape, with owners, as Gatekeeper caps a constraint's violations. Cases aren't referenced one by one: each `Assessment` is labelled with its vulnerability and subject. There is no index kind for "where does CVE-X run".
- **The hub learns where a subject runs per namespace** (owner, 2026-11-16): each cluster's presence gains its namespaces, each with the owner values that owner attribution allows and the workloads by exposure, capped by a setting of `OperatorConfig`, 100 by default. Workload labels stay on the spoke, and owner values never reach the model.
- **`maxCases` caps the cases judged.** What the cap leaves shows as skipped, and the cap reached is a condition reason and an Event.
- **No operator-wide daily budget.** `OperatorConfig.spec.agent.state` (`Enabled` or `Disabled`) switches the whole integration, with the reason and Event `AgentDisabled`.

## Consequences

- Tokens are spent only where the SOC asks, or where it set a standing condition.
- The same kind serves playbooks for other resources later, since its keys are generic.
- Whoever may create an `Investigation` may spend tokens and read where findings run across the fleet. vexplain's roles for it aren't aggregated into `edit` and `admin`.
- **Rejected:**
  - **the trigger on the playbook,** which mixes the admin's definition with the SOC's runs;
  - **a separate rule kind,** a kind more for runs with no outcome of their own;
  - **an index kind per CVE,** which wouldn't fit other use cases;
  - **a daily budget now,** which needs counting across runs and days.

**Precedents:** OASIS CACAO; Tekton's PipelineRun; CronJob's `schedule`; ValidatingAdmissionPolicy's `matchConditions`; OpenReports' `summary` and `results`.
