# 0033 Rules are reusable steps that decide about one finding in CEL

- **Status:** Proposed on 2026-10-31. The direction is the owner's; the write-up waits for the owner's review.
- **Date:** 2026-10-31
- **Refines:** design 6.5, whose rules are compiled into the hub, and 0026 and 0028, whose load check becomes a default rule. The first principle (design 1) is unchanged; the core now keeps it for every rule.
- **Design:** [collectors, evidence and rules](../design/2026-10-31-collectors-evidence-rules.md), section 5.7.

## Context

- **The 2a rules are Go code in the hub:** known exploited, the completeness guard, removed in a later layer, and the load check's hint. A new rule needs a release.
- **The owner wants admins to compose rules from any collectors' evidence,** with the default rules applied on install and able to move out later, to be maintained on their own.
- **Playbooks (0034) describe each use case** and run rules as their steps, as Crossplane's Compositions run functions.
- **CEL** is what Kubernetes itself uses for logic inside resources: ValidatingAdmissionPolicy and CRD validation rules. Kyverno has added CEL policies too.
- **Crossplane's Compositions** started with declarative patches inside the resource, and later added functions for logic that the patches couldn't express.

## Decision

- **`Rule`** (config group, cluster-scoped, at the hub) is a reusable step: one decision about one finding, in CEL.
  - It names the inputs it needs, each with a name and a type. A playbook that uses the rule supplies evidence under those names, so one rule can serve several playbooks.
  - It concludes `Tracked`, `NeedsAssessment`, `Suppressed` with an OpenVEX status and justification, or `Hint`.
  - How much coverage is enough is the rule's to decide, in CEL.
- **The hub's admins write rules.** Each subject gets one verdict across all clusters (0021, 0025).
- **The core keeps one guarantee, whatever a rule says:**
  - A rule applies to a finding only when every input it names is present.
  - Its verdict lays out what it rested on and what it couldn't check.
  - Missing evidence never settles anything.
  - A rule that holds or tracks, but can't be evaluated for a finding, fails closed: no suppression applies to that finding.
- **When several steps apply, the most cautious outcome wins:** `Tracked`, then `NeedsAssessment`, then `Suppressed`. Hints add up. The order of the steps doesn't change the result.
- **The default rules are today's four,** written in CEL and installed with the default playbook. The completeness guard's threshold moves here from `OperatorConfig.spec.rules`.
- **Later, without changing what exists:** a `Rule` may reference a `Function` package for logic that CEL can't express, and rules may ship as OCI packages.

## Consequences

- A new rule needs no release.
- 0028's way back becomes a rule that an admin adds to the container playbook.
- Phase 2b proves with the 2a measurement that the default rules keep all 15 answers.
- **Rejected:**
  - rules that only name logic compiled into the hub, because the logic would stay out of the resource
  - rules that name collectors themselves, because a rule then couldn't serve another playbook with other collectors
  - a policy that decides which collectors count, separate from the playbooks, because it would blur who decides what
