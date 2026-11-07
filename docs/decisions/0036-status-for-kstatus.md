# 0036 Status that kstatus can read: `observedGeneration`, `Reconciling` and `Stalled`

- **Status:** Accepted on 2026-11-07 (decided by the owner).
- **Date:** 2026-11-07
- **Refines:** 0012's "`metav1.Condition` with `observedGeneration`, set early".
- **Design:** [main design](../design/2026-10-29-vexplain-design.md), section 6.1.

## Context

- **GitOps tools read health with kstatus.** Flux, kpt, Config Sync and the kubectl tooling built on cli-utils compute whether a resource is in progress, current or failed with [kstatus](https://github.com/kubernetes-sigs/cli-utils/blob/master/pkg/kstatus/README.md). kstatus reads:
  - `status.observedGeneration`: when it differs from `metadata.generation`, the controller hasn't acted on the latest change;
  - two conditions of "abnormal-true" polarity: `Reconciling` (the controller works towards the desired state) and `Stalled` (it can't get there without a change). Their absence means all is well.
- **vexplain's kinds have only `Ready`,** of positive polarity, and an `observedGeneration` on each condition. kstatus uses `Ready` only as a fallback, and reads `Ready=False` as "in progress", never as "failed". So a `Collector` that is broken for good would show as forever reconciling.
- **A playbook that misses a collector or a rule** runs fail closed: no finding becomes `NotAffected` or `Fixed`, and every finding stays open. Only its `Ready` condition says why, on a cluster-scoped object that few people look at.

## Decision

- **Every kind that a controller of vexplain reconciles carries, in its status:**
  - `observedGeneration`: the generation that the controller last acted on, written at the end of each reconcile;
  - `Ready`, as now: of positive polarity, for people and for `kubectl wait`;
  - `Reconciling`, `True` while the controller works towards the current generation, or waits on something that passes, such as a rollout or the grace for health after a start;
  - `Stalled`, `True` when it can't go on without a change, with the reason that `Ready` gives.
- **`Reconciling` and `Stalled` are present only while `True`,** as kstatus expects and as Flux's controllers do. One helper sets the three conditions together, so they never contradict:
  - `Ready=True` has neither.
  - `Stalled=True` comes with `Ready=False`.
  - `Reconciling=True` comes with `Ready` `False` or `Unknown`.
- **Kinds that no controller reconciles are left out:**
  - `CollectorRuntimeConfig`, which the deployer only reads; a `Collector` reports a bad one as `RuntimeConfigInvalid`;
  - kinds whose status is data that vexplain writes: `Evidence`, `ImageInventory`, `ImageVerdicts` and `WorkloadReport`.

  kstatus reads these as current.
- **New kinds get it too.** A test lists every CRD of the install as either reconciled, and so held to this decision, or left out, with the reason. A CRD in neither list fails the test.
- **A playbook that isn't `Ready` is visible:**
  - a `Warning` event on the `Playbook`, when it turns not `Ready` and when its reason changes;
  - the gauge `vexplain_playbook_ready{cluster, playbook}`, 1 or 0.

## Consequences

- Flux, kpt and Config Sync show a stuck `Collector`, `Playbook`, `Rule`, `OperatorConfig` or `ModelConfig` as failed, and one that is working as in progress.
- Argo CD judges health with its own checks per kind. With these conditions, a short custom health check maps them.
- Every controller writes one more field and up to two more conditions.
- **Rejected:**
  - **`Ready` alone:** kstatus can't tell stuck from busy.
  - **`Reconciling` and `Stalled` always present, as `False`:** kstatus accepts it, but "absence means normal" is its documented pattern, and conditions that are always `False` are noise in `kubectl describe`.
