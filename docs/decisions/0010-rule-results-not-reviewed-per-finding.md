# 0010 Rule-settled results are not reviewed per finding

- **Status:** Accepted (revised 2026-10-29 in design revision 5: all rules run on the hub, see 0021)
- **Date:** 2026-10-29

## Context

Rules will settle most of the flagged findings. Requiring a human review for each would recreate the flood the system exists to remove. Every spoke still needs the outcome, to render its reports.

## Decision

- **No `VexStatement` and no per-finding review** for rule-settled results. The rules themselves are reviewed once, as code.
- **All rules run on the hub** (0021). Their outcomes, with rule name and reason, go into the per-digest `ImageVerdicts` sheet that spokes render from.
- **`VexStatement` is reserved for agent and human statements.** Accepted ones are reflected in the same sheet.

## Consequences

- A wrong rule affects many findings at once, so rules need tests and the planted test images.
- The review load stays small, and every spoke renders from the same result.
