# 0016 One default `AgentProfile` with optional overrides; editable guidance through a ConfigMap; the core stays in the binary

- **Status:** Accepted (revised 2026-10-29 in design revision 5: one default profile instead of one per assessment type, at the owner's request; the override mechanics are the designer's call)
- **Date:** 2026-10-29

## Context

The system prompt should be editable without rebuilding the operator and without overloading `OperatorConfig`. At the same time, the loop and the validator depend on parts of the prompt: the tool contract, the verdict schema and the evidence rules. An edit must not be able to break those.

One profile per assessment type isn't maintainable. Most settings are the same for every type.

## Decision

- **One `AgentProfile` named `default`** serves every assessment. The operator creates it at start with the embedded guidance. This follows Kubernetes' "default class" pattern, as with the default `StorageClass` or `IngressClass`.
- **Overrides:**
  - Another profile can claim types with `spec.assessmentTypes` (for example `[BinaryIdentification]`).
  - It only sets what differs; unset fields come from `default`.
  - The effective profile is resolved when an assessment starts, and recorded in its status.
  - At most one override per type. A second one reports `Ready=False`, reason `Conflict`, and is ignored.
- **A profile holds:**
  - limits: `maxSteps`, `maxTokens`, `timeoutSeconds`, `toolTimeoutSeconds`, and the reserved budget for the no-verdict summary
  - the allowed built-in tools and `ToolServer`s
  - the guidance source
  - `modelRef` (0017)
- **The prompt has two layers:**
  - **Core:** operator-owned, versioned and embedded in the binary, not editable.
  - **Guidance:** editable and appended after the core: house knowledge, priorities, style, examples.
- **The guidance source is a union:**
  - `type: Embedded` is the default text.
  - `type: ConfigMap` uses `configMapRef: {name, key}`, which must point to the operator's namespace.
  - The enum is open.
- **If the source is missing or invalid:** the profile reports `Ready=False`, the assessments it serves wait, and an `AgentProfileInvalid` event is emitted. There is no silent fallback.
- **Every `Assessment` records** the effective profile, the core version, the guidance hash and the ConfigMap's `resourceVersion`.

## Consequences

- Most installations only ever touch `default`.
- Prompt tuning needs no release. The replay harness should run before a new guidance is rolled out.
- Changing the guidance doesn't re-run past assessments.
- The validator remains the safety net, whatever the guidance says.
