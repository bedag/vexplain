# 0034 A playbook describes each use case: its subjects, findings, evidence, rules, and what goes to the agent

- **Status:** Proposed on 2026-10-31. The direction is the owner's; the write-up waits for the owner's review.
- **Date:** 2026-10-31
- **Refines:** design 6.5 and 6.6, whose flow knows only container images, and 0016, whose profile overrides claimed assessment types.
- **Design:** [collectors, evidence and rules](../design/2026-10-31-collectors-evidence-rules.md), sections 5.1 and 5.7.

## Context

- **The flow around the rules is built into the core,** and it knows only container images: presence, scan, match, rules, then the agent.
- **The owner wants each use case described as a resource,** like a Crossplane Composition:
  - which collectors feed it
  - how their data is grouped per subject and workload
  - what is sent to the agent
- **CVEs in container images are one use case.** Virtual machines or databases would be others, with other collectors.
- **Names:**
  - SOAR tools call this a playbook: for one type of case, which sources to enrich it from, which checks to run, and when to hand it to an analyst. CISA's Vulnerability Response Playbook covers the same ground for vulnerabilities.
  - A `Pipeline` kind would clash with Tekton's, and a `Composition` kind with Crossplane's, on clusters that run them.

## Decision

- **`Playbook`** (config group, cluster-scoped, at the hub) describes one use case. The hub's admins write it.
  - `spec.subjects`: where its subjects come from, as a `Collector` and a type
  - `spec.findings`: the `Collector` its findings come from
  - `spec.evidence`: the evidence it gathers for each subject, each with a name, a `Collector` and a type
  - `spec.pipeline`: its steps, each a `Rule` (0033), as a Crossplane Composition lists its functions
  - `spec.agent`: the `AgentProfile` that its leftover findings go to, and which evidence goes into their case file
- **The default playbook, `container-cves`,** is today's flow. vexplain's install applies it with the default rules. Later, a Helm value can leave them out.
- **A playbook names its agent profile.** Profile overrides no longer claim assessment types (0016). Each `Assessment` records its playbook.
- **The wiring is the trust.** A playbook uses only the collectors it names.

## Consequences

- A new use case needs collectors and a playbook, not code in the core.
- The container playbook keeps the `ImageVerdicts` sheets. A playbook for another kind of subject needs a sheet for that subject, which is decided when the first one comes.
- 0028's way back becomes a rule that an admin adds to the container playbook, with the runtime collectors as evidence.
- **Rejected:**
  - rules alone, around a container flow built into the core, because every other use case would need code
  - `Pipeline`, `Composition` and `Policy` as names, for the clashes above and because vexplain already has `ReviewPolicy`
