# 0012 kubebuilder, and the team's API design practices

- **Status:** Accepted
- **Date:** 2026-10-29

## Context

The operator exposes a Kubernetes API that namespace owners, the SOC, dashboards and possibly other controllers will read and write. Once an object exists, every field is a promise. The Kubernetes API conventions and "Changing the API" documents, and the team's internal guidelines built on them, collect the practices for evolving such an API without breaking changes.

## Decision

- **Scaffold and maintain the operator with kubebuilder** (Go, controller-runtime, controller-gen, envtest) as a multi-group project, starting at `v1alpha1`. API versions are independent of the release SemVer.
- **Apply these practices:**
  - Review the generated schema after every type change, and run `kube-api-linter` in CI.
  - One controller per CRD. Small resources that reference each other instead of one big object.
  - Copy foreign types (Kubescape, Syft, Grype, OpenVEX) into our own; don't embed them.
  - Declarative `spec`; `status` as its own subresource.
  - `metav1.Condition` with `observedGeneration`, set early.
  - Optional fields by default; `spec: {}` should work.
  - Open, documented enums instead of booleans, with unknown values handled explicitly.
  - `listType=map` lists instead of maps; nesting instead of prefixes; unions with a `type` discriminator.
  - Units in field names; no floats in `spec`.
  - `…Ref` fields stay within the same namespace.
  - Strict validation from the start: CEL for cross-field rules, `oldSelf` for immutable fields.
  - Avoid conversion webhooks.
  - Keep a glossary.

## Consequences

- The configuration is split into `OperatorConfig`, `Collector`, `ModelConfig`, `AgentProfile`, `ToolServer` and `ReviewPolicy` (see 0015–0017).
- Fields are only added when a phase uses them. "No" can be revisited; "yes" is forever.
- Breaking changes require a new API version, not just a major release bump.
