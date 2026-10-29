# 0014 Every "no verdict" comes with a summary; key situations emit Events

- **Status:** Accepted
- **Date:** 2026-10-29

## Context

Hitting a limit must never produce a guess. But a bare "no verdict" leaves the reviewer starting from scratch. Some situations also need attention right away, not just a metric.

## Decision

- **The agent can end with `submit_no_verdict`.** It states why it stopped, what it established (citing evidence), and what evidence would settle the case.
- **When a hard limit trips**, the operator makes one final call without tools, from a small reserved budget, to get that summary. If that call fails too, the status records which limit tripped.
- **The summary is stored in the `Assessment` status** and shown to the reviewer.
- **Kubernetes Events** are emitted for:

| Event | When |
|---|---|
| `VerdictRejected` | The validator rejected a verdict after the repair attempt |
| `NoVerdict` | The agent reached no verdict |
| `BudgetExhausted` | The daily budget is used up |
| `KillSwitchActive` | The agent is switched off |
| `VerdictProposed` | A verdict is waiting for review |
| `CollectorUnhealthy` | A collector is failing |
| `SandboxRunFailed` | A sandbox run failed |
| `AgentProfileInvalid` | A profile's guidance source is missing or invalid (0016) |
| `ModelUnavailable` | An LLM endpoint fails its probe (0017) |

## Consequences

- Each no-verdict costs a small fixed extra token budget.
- The no-verdict rate and how useful the summaries are become evaluation metrics.
