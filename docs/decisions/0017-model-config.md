# 0017 LLM connection in a `ModelConfig` resource, referenced from `AgentProfile`

- **Status:** Accepted. Supersedes the "environment variables" part of 0013. Revised 2026-10-29 in design revision 4: HTTPS only, labelled Secrets; confirmed by the owner. Refined 2026-10-30 in design revision 6 (proposed): no redirects, and the key goes over plain http only to a loopback host.
- **Date:** 2026-10-29

## Context

0013 put the LLM endpoint, key and model in environment variables. Now that `AgentProfile` exists (0016), the owner asked whether the LLM settings should move there too. The model connection is a separate concern:

- several profiles may share one model
- a profile may switch to another model
- the API key belongs in a Secret, not in a profile

## Decision

- **A cluster-scoped `ModelConfig`** on the hub holds:
  - `provider`: an open enum, `OpenAICompatible` for now
  - `endpoint` (HTTPS only) and `model`
  - `apiKeySecretRef: {name, key}`, pointing to a Secret in the operator's namespace that carries the label `vexplain.bedag.ch/llm-api-key: "true"`. The operator never loads unlabelled Secrets, so writing a `ModelConfig` can't be used to send other Secrets from that namespace to an endpoint of one's choosing.
    - This is defence in depth. Only admins write `ModelConfig`s, so on its own the risk would be acceptable.
    - It is kept because the namespace will also hold copied pull secrets of namespace owners (0008), which `ModelConfig` writers shouldn't be able to reach. It costs one label.
    - It's an established pattern: Argo CD only considers repository-credential Secrets labelled `argocd.argoproj.io/secret-type`. A label-filtered cache also keeps unrelated Secrets out of the operator's memory.
  - `requestTimeoutSeconds`, `maxConcurrentRequests`, and `temperatureMilli` (no floats in spec)
- **`AgentProfile.spec.modelRef`** names the `ModelConfig` to use.
- **Status:** the controller probes the endpoint and reports `Ready`, the last error and the observed latency. If a `ModelConfig` isn't ready, the profiles using it pause and a `ModelUnavailable` event is emitted.
- **Every `Assessment`** records the `ModelConfig` name, endpoint and model.
- **Proxy settings stay as process-wide environment variables** (`HTTPS_PROXY`, `NO_PROXY`).
- **For local development,** the operator may create a default `ModelConfig` from `VEXPLAIN_LLM_*` variables at startup, but only if none exists.

## Consequences

- Changing or trying a model means editing or adding one resource. No restart or redeploy is needed.
- Different assessment types can use different models.
- The same pattern as kagent (`ModelConfig`) and k8sgpt (backend config), without depending on either.
- The API key is read only to authenticate LLM calls. It is never logged or put in a prompt.
