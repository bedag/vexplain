# 0018 Name `vexplain`; three API groups under `vexplain.bedag.ch`

- **Status:** Accepted
- **Date:** 2026-10-29

## Context

"Triage" was too broad: it is also used for incidents and alerts, and it doesn't say what gets triaged. What sets the project apart is that it decides whether a workload is affected, explains why with evidence, and records the result as VEX.

Admins, the SOC and namespace owners each write different kinds. Grouping by kind type alone made RBAC and versioning harder than it needs to be.

## Decision

- **Name:** `vexplain` (VEX + explain), used for the project, the repository and the binary. There is no `-operator` suffix, because the operator is the product. There is no `-agent` suffix either: in Kubernetes "agent" usually means a node daemon, and the LLM agent is only one part.
- **Module:** `github.com/bedag/vexplain`. **Domain:** `vexplain.bedag.ch`.
- **Groups**, split by who writes them:
  - `config.vexplain.bedag.ch` (admins): `OperatorConfig`, `Collector`, `ModelConfig`, `AgentProfile`, `ToolServer`, `ReviewPolicy`
  - `triage.vexplain.bedag.ch` (the operator; the SOC reviews `VexStatement`; namespace owners read `WorkloadReport` and create `SandboxRun`): `Assessment`, `VexStatement`, `WorkloadReport`, `SandboxRun`
  - `inventory.vexplain.bedag.ch` (the operator only, bulky): `ImageInventory`, `ImageVerdicts`
- **`TriageConfig` is renamed `OperatorConfig`.** It is still a singleton named `default`.
- **Prefixes:** metrics use `vexplain_`, environment variables use `VEXPLAIN_`, and the operator namespace is `vexplain-system`.

## Consequences

- RBAC can be granted per group: admins get `config.*`, the SOC gets write access to `VexStatement`s, and namespace owners get read access to their reports.
- Each group can move to `v1beta1` on its own schedule.
- Renaming a group later is a breaking change, so these names are fixed before anything is installed on a shared cluster.
