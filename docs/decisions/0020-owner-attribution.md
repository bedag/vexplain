# 0020 Owner attribution from allowlisted labels and annotations, resolved on the spoke

- **Status:** Accepted (confirmed by the owner on 2026-10-29)
- **Date:** 2026-10-29

## Context

To act on a `VexStatement`, the SOC must know whom to inform for each affected workload. There's no single standard label for "owner": platforms use team labels, owner or contact annotations, or the recommended `app.kubernetes.io/part-of`. The established *mechanism* is an admin-configured allowlist of label and annotation keys. kube-state-metrics uses exactly that with `--metric-labels-allowlist` and `--metric-annotations-allowlist`, and dashboards join `kube_namespace_labels` on the namespace.

## Decision

- **`OperatorConfig.spec.ownerAttribution`** (phase 2) holds:
  - `namespaceLabels`
  - `namespaceAnnotations`
  - `workloadLabels`

  All three are allowlists of keys. They are empty by default, so nothing is copied unless an admin says so.
- **The spoke resolves the values,** because only the spoke can see its namespaces and workloads. It copies them into:
  - each `WorkloadReport`
  - one info metric, `vexplain_namespace_owner_info{cluster, namespace, <allowlisted keys>} 1`. Keys are sanitised into Prometheus label names, with the prefix `label_` or `annotation_`, as kube-state-metrics does it.
- **Dashboards join** the open-case metric with the owner info metric on `cluster, namespace`. Where kube-state-metrics already exports the same namespace labels, joining `kube_namespace_labels` works too.
- **Back-tracking path:** `VexStatement` → digest → open cases in Grafana, or `WorkloadReport`s on the spoke found by digest label, or the hub's workload references (0019) → owner attribution.
- **This replaces `metricsGroupLabel`.** One info metric with all allowlisted keys is the more general form, and it keeps owner labels out of every other series.

## Consequences

- Owner data is copied, never interpreted. vexplain doesn't send notifications; informing people stays with the SOC or with later integrations.
- The info metric has one series per namespace, which is cheap.
- Annotations can hold contact data such as e-mail addresses. They are only copied when allowlisted, and they never reach the LLM.
