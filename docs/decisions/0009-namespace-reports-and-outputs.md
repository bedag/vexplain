# 0009 Namespaced workload reports without a review gate; metrics as counts plus open cases

- **Status:** Accepted (revised 2026-10-29: framed per namespace, not tied to any tenancy model; owner info metric instead of `metricsGroupLabel`, see 0020)
- **Date:** 2026-10-29

## Context

The SOC is the primary user and works in Grafana. Whoever runs workloads in a namespace should see results for those workloads, but the end users of those services should not. The operator must not depend on how a platform groups namespaces (teams, customers, projects) or on any multi-tenancy tool.

A metric series for every image × CVE pair would make Prometheus cardinality explode.

## Decision

- **Reports:** one `WorkloadReport` per workload, stored in the workload's namespace. Anyone RBAC allows to read that namespace sees it right away, with no review gate. Each report is clearly marked "agent verdict, not reviewed". It contains no evidence ledger and no detail about other namespaces. We learn from use and adjust.
- **Metrics:** exported on every cluster. The `cluster` label comes from `OperatorConfig.spec.clusterName`, which the admin sets. The central metrics stack combines the clusters.
  - Counts by cluster, namespace, verdict, urgency and review state.
  - Funnel stages.
  - One `vexplain_open_case` series per case that still needs action, including the image digest, so a `VexStatement` leads straight to its affected workloads.
  - Owner labels go into one info metric, `vexplain_namespace_owner_info`, which dashboards join on cluster and namespace. They are not added to every series (see 0020). This replaces the earlier `metricsGroupLabel`.
  - Hub health: assessments, rejections, tokens, latency, queue, budget.
- **Events:** the set listed in 0014.
- **Dashboards** are expected to be the main interface for everyone with permission.

## Consequences

- Settled findings never become individual series. Their detail lives in the resources.
- Grouping namespaces into teams or customers is optional configuration, never a requirement.
