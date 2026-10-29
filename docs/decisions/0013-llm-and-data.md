# 0013 An on-prem model through an OpenAI-compatible endpoint; workload metadata may be sent

- **Status:** Accepted (revised 2026-10-29: configuration moved from env vars to `ModelConfig`, see 0017)
- **Date:** 2026-10-29

## Context

The agent needs an LLM with tool calling. Case files contain namespace and workload names, file paths from images, container args and ConfigMap keys.

## Decision

- **Model:** an on-prem model, reached over HTTPS with API-key authentication. Which model is a deployment choice, set in a `ModelConfig`. It must support tool calls and structured JSON output.
- **Configuration:** endpoint, model and API key reference live in a `ModelConfig` resource (see 0017), not in environment variables. The client honours `HTTPS_PROXY` and `NO_PROXY`.
- **What may be sent:** namespace and workload names may go to the model, so no pseudonymization layer is needed. Secret values, pull secrets and env var values are never sent.
- **Throughput and parallelism are unknown.** The operator records latency and tokens per call and starts with 1–2 workers. Budgets are tuned from these measurements.

## Consequences

- If the model or its endpoint changes, the replay harness is rerun before switching.
- Model and prompt versions are recorded in every `Assessment`.
