# 0029 A collector is a package that implements one gRPC API; installed means enabled

- **Status:** Proposed on 2026-10-31. The direction is the owner's; the write-up waits for the owner's review.
- **Date:** 2026-10-31
- **Supersedes:** 0007's decision that collectors are "compiled into the operator behind a Go interface", and its consequence that new collectors need an operator release.
- **Refines:** 0002, 0006, 0008, 0012, 0015, 0020, 0021, 0022 and 0027, as the [design of collectors, evidence and rules](../design/2026-10-31-collectors-evidence-rules.md) lists in its section 10.
- **Design:** collectors, evidence and rules, sections 5.2 to 5.4, 5.6, 5.9, 5.11 and 5.12.

## Context

- 0007 compiled every collector into the operator. A new source needs new API fields, Go code and an operator release. Phases 2b and 3 would build six more collectors that way.
- The owner wants collectors to be pluggable, vexplain's own included, so that the project scales and lasts, and so that platforms built on Kubernetes can bring their own sources.
- **Practice elsewhere:**
  - Crossplane installs its providers and functions as OCI packages. The resource that references a package is its installation, and its core ships none of them.
  - Crossplane's core never handles a provider's credentials. Each provider reads its own.
  - CSI drivers implement one gRPC spec, with a controller part and a node part, and describe themselves through an identity service.
  - Kubernetes took years to move its in-tree volume plugins and cloud providers out of its core.

## Decision

- **A collector is an OCI image** that implements vexplain's gRPC API, `vexplain.collector.v1alpha1`, and describes itself through the API's identity service. One image holds one collector. Tag or digest is the installer's call.
- **A `Collector` resource installs it, and installed means enabled.** Deleting it removes it, and there is no `state` field. Its Deployment and service account are named after it, so they survive upgrades.
- **vexplain's own collectors are packages too,** each in this repository, released with the operator. vexplain's install ships them as `Collector` manifests. The operator creates none at run time.
- **Collectors take care of what they need.** For example, the scanner reads pull secrets and runs its own scan Jobs. vexplain doesn't dictate how a collector works. The SDK offers helpers that nobody has to use.
- **Each collector declares its roles:** spoke, hub, or a part in each. vexplain calls each collector in its own cluster. The hub asks spokes for evidence of a type, not for a collector (0021).
- **The pod watch moves into the `workloads` collector,** which applies the scope and the owner allowlists that vexplain passes it.
- **Installing a collector means trusting it.** The playbooks and their rules decide what its evidence may settle (0033, 0034). vexplain grants no permissions: its install binds the built-ins' roles, and an admin binds the others'.
- **An SDK in Go, conformance tests and a template project** let others build collectors.
- **Left out until there's a need:** dependencies between packages, revision history, CRDs installed from packages, signature checks by vexplain, and an index of packages.

## Consequences

- A new collector no longer needs an operator release.
- vexplain owns a protocol: its versions, its compatibility tests and its certificates. `v1alpha1` makes no compatibility promise.
- Phase 2b starts by moving `workloads`, `scanner` and `matcher` into packages, before the exposure collector.
- Each collector costs one long-running pod per role, plus whatever it starts itself.
- The operator no longer reads pods, nodes, Secrets or service accounts outside its namespace.
- **Rejected:**
  - controllers that write vexplain's CRDs, because every observation would pass through etcd (0004)
  - images run per request for everything, because watching collectors and quick queries don't fit
  - built-ins compiled in behind the same interface, because they would never use the path that others depend on
  - a separate resource per installed package, with several `Collector`s per package, because installed should simply mean enabled
  - MCP as the collector API, because it's built for interactive tool calls

## Sources

- Crossplane's documentation on packages, providers, `DeploymentRuntimeConfig` and composition functions.
- The Container Storage Interface spec, its identity service, and its `csi-sanity` conformance tests.
- HashiCorp Vault's plugin system and plugin catalog.
- KEDA's external scalers.
- The Kubernetes enhancement proposals for CSI migration and for removing the in-tree cloud providers.
