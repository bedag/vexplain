# 0005 Agent "not affected" needs human review by default; auto-acceptance configurable

- **Status:** Accepted
- **Date:** 2026-10-29

## Context

A `VexStatement` does more than report: it silences a finding. A mistaken agent "not affected" shared through the hub would suppress that CVE for that image in every cluster. That is the most dangerous error this system can make.

## Decision

- **Agent-made "not affected" or `fixed` starts as `Proposed`.** Both silence a finding, so both get this treatment. Until accepted, it counts as "probably not affected, unreviewed": still visible, lower priority, not suppressed.
- **Reviewing means editing the `VexStatement` on the hub.** How it gets edited (GitOps, kubectl) is out of scope.
- **Auto-acceptance is configurable per class of case** in a `ReviewPolicy` resource (see 0015). Examples of conditions an admin can combine:
  - severity below a threshold
  - not on KEV
  - not externally exposed
  - strong evidence present, such as the vulnerable symbols being absent
  - completeness above a threshold
- **Justifications based on adversary control or mitigations are never auto-accepted** (designer's call).
- **Auto-acceptance that relies on workload facts lapses by itself.** Exposure is one example. A statement is image-level, while exposure is per workload and can change, so the fact is recorded as a condition on the statement. Spokes re-check it per workload, and the statement stops applying where the condition no longer holds (design revision 4).

## Consequences

- Every review is a labelled data point. Per-class agreement rates are the evidence for switching on auto-acceptance for that class.
- At the start, the SOC carries the review load. The aim is to shrink it as the agent proves itself.
