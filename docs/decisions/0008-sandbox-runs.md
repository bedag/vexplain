# 0008 Sandbox runs available on demand, off by default

- **Status:** Accepted (revised 2026-10-29: `SandboxRun` can be created in any namespace; part of v1, built in phase 5, at the owner's request). Changed by 0029 and 0030 (proposed on 2026-10-31): the sandbox becomes a collector that runs its own pods, configured through its settings.
- **Date:** 2026-10-29

## Context

For "unclear" cases, starting the image and watching what it loads can add evidence. This is the only place where the operator creates workloads.

## Decision

- **`SandboxRun` is namespaced and can be created in any namespace** by anyone RBAC allows. It references a workload **in the same namespace**, so no one can sandbox an image from a namespace they can't access. This follows the API practice that references stay in the namespace.
- **The sandbox pod runs in the operator's namespace of the same cluster.** It uses the referenced workload's pull credentials. The result is attached as evidence to the `Assessment` for that digest.
- **Off by default.** An admin can enable it, and separately allow the agent to request runs, for example for "unclear" cases.
- **Part of v1.** It's built in phase 5, after the agent and before multi-cluster. A sandbox run is a spoke task, so it uses the same task path the hub later uses for remote spokes.
- **Guardrails:**
  - no network, no service account token, no secrets
  - tight resource and time limits; deleted afterwards
  - a sandboxed runtime class (gVisor/Kata) when available
  - the spec is immutable
- **Evidence weight:** "loaded" is strong evidence for "affected". "Not loaded" is weak, because the sandbox runs without real config or traffic, and it can never alone produce "not affected".

## Consequences

- The non-goal narrows to "no writes to analysed workloads".
- How the sandbox observes loaded libraries is left to the implementation.
- **Pull credentials, decided by the owner:** a pod can only use `imagePullSecrets` from its own namespace. The admin picks one of two modes in the sandbox settings:
  - **`CopyFromWorkload`:** the operator copies the workload's pull secrets into short-lived Secrets in its own namespace. Each copy is owned by the sandbox pod and deleted with it.
  - **`AdminProvided`:** the admin puts pull Secrets into the operator's namespace and lists them.

  Rejected: pinning the sandbox to a node that already has the image, because it would bypass the kubelet's credential check for pulled images. Also rejected: running the sandbox in the workload's namespace.
