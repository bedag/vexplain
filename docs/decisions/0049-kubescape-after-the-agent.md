# 0049 Kubescape moves after the agent

- **Status:** Accepted on 2026-11-07 (decided by the owner).
- **Date:** 2026-11-08
- **Refines:** 0002 (Kubescape as an optional collector), the main design's phase 3, and the phases of the design of collectors, evidence and rules (sections 5.12 and 6).
- **Design:** [the collector model](../design/2026-11-08-collector-model.md), section 6; [main design](../design/2026-10-29-vexplain-design.md), section 7.

## Context

- **Phase 3 was to build the Kubescape collector.**
- **The first live run showed** that the collectors already built, and the model around them, needed work first: reports for every resource, triggers, permissions and playbooks.

## Decision

- **Kubescape comes after the agent (phase 4).** It stays an optional collector and part of v1 (0002).
- **Phase 3 is the collector model,** and the review of each built-in collector.

## Consequences

- **The Kubescape collector is built on the new model.** Its SBOMs can feed `vulnerabilities` through the `sbom` type (0044).
