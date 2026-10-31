# 0030 A runtime config shapes the Deployment a collector runs in

- **Status:** Proposed on 2026-10-31. The direction is the owner's; the write-up waits for the owner's review.
- **Date:** 2026-10-31
- **Refines:** 0022, whose scan pod is fixed in code, and 0008, whose sandbox pod settings now come through the sandbox collector.
- **Design:** [collectors, evidence and rules](../design/2026-10-31-collectors-evidence-rules.md), sections 5.4 and 5.8.

## Context

- **The 2a scan pod is fixed in code,** except for four numbers in the `scanner` Collector: concurrency, timeout, memory and workspace. Its pull policy, CPU, node placement, runtime class and labels can't be changed.
  - Namespaces with a CPU quota, or a policy that requires CPU limits, can reject it.
  - An injected service-mesh sidecar can keep its pod from finishing.
- **The owner's position:** what the collectors run should be configurable in general, with `IfNotPresent` kept as the default pull policy. The sandbox should use the same mechanism.
- **Crossplane's `DeploymentRuntimeConfig`** replaced `ControllerConfig`'s fixed list of fields with full templates, which Crossplane merges onto its defaults. It doesn't restrict what the templates set.

## Decision

- **`CollectorRuntimeConfig`** (config group, cluster-scoped) holds a Deployment template and the metadata of the collector's service account. A `Collector` references one. Otherwise `default` applies, which the operator creates empty and never overwrites.
- **Templates are merged onto hardened defaults** as a strategic merge patch. The collector's container is named `collector`.
- **Everything can be changed.** Writing a `Collector` or a `CollectorRuntimeConfig` amounts to creating pods in vexplain's namespace. So write access to both is only for people trusted with that namespace, and vexplain's install and documentation say so.
- **vexplain sets the contract's fields last:** the image, the certificates, the port and the contract's environment variables.
- **The pods a collector creates itself,** such as scan Jobs and sandbox pods, are configured through its settings. The SDK defines a standard pod template for them, so that every collector that creates pods takes the same shape.

## Consequences

- For the scanner and the sandbox alike, these become configurable:
  - the pull policy
  - CPU requests and limits
  - node placement and priority
  - labels and annotations
  - a runtime class such as gVisor or Kata
- The 2a scanner's settings move into the scanner collector's own settings. Its Deployment's resources come from the runtime config.
- **Rejected:**
  - a fixed list of fields, as Tekton's pod template and Crossplane's old `ControllerConfig` have, because every new need would mean an API change
  - restricting templates in code, which only protects anything if people who aren't trusted with vexplain's namespace can write them
