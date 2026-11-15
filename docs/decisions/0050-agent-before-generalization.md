# 0050 The agent's work on cases comes before the generalization

- **Status:** Accepted on 2026-11-15 (decided by the owner).
- **Date:** 2026-11-15
- **Refines:** 0001 (the agent investigates what the rules leave), 0034 (what goes to the agent), and the phases of the main design (section 7) and of the collector model (section 6).
- **Design:** [main design](../design/2026-10-29-vexplain-design.md), sections 1, 6.6, 6.10 and 7; [the collector model](../design/2026-11-08-collector-model.md), section 6; [phase 3a's fixes](../design/2026-11-15-phase3a-fixes.md).

## Context

- **Where vexplain is heading** (owner, 2026-11-15):
  - a framework that turns too much security data into what needs doing;
  - collectors deliver evidence from anywhere, rules rule out what doesn't apply, and playbooks combine them into use cases;
  - an agent assists the SOC, and owners see their own reports;
  - the SOC must be able to work without the agent.
- **Phase 3b was to generalize the collecting side next:**
  - a trigger runtime and evidence subscriptions;
  - family collectors;
  - findings about resources other than images, with reports for them.

  Four throwaway spikes tested this on a live cluster. Section 6 of the collector model lists what they found.
- **Nobody has used the output yet.** No agent exists, and the SOC hasn't worked with the reports. The hardest problems the spikes found came from the generalizing machinery, not from a use case:
  - replacing evidence leaves a gap;
  - a restart of the trigger runtime widens reach;
  - a missing family collector has to be read as the widest case.
- **The output's shape is the open question of the generalization.** What does a playbook's author configure? How do subjects relate across use cases? Where does a fleet's data live? Only the agent and the SOC can show what they need.

## Decision

- **Cases first.** The agent's first job is a verdict per case, where the rules stop: one CVE in one image's platform manifest, investigated once wherever it runs (main design, 6.6). Later, the same for one weakness in one resource.
- **The plan across the fleet is a view over the cases,** not something the agent writes (main design, 6.10):
  - it groups the open cases by fix and by owner, most urgent first;
  - it's recomputed whenever a verdict changes, and costs no tokens;
  - it also sets the order of the agent's queue.

  The agent writes the plan up for the SOC later.
- **The new order of the phases:**
  1. phase 3a's fixes, from its live run;
  2. phase 4: the agent on image cases, with the plan view, and the SOC using both;
  3. phase 3b, re-cut from what the agent and the SOC turned out to need, with the spikes' findings as input.
- **Kubescape stays after the agent** (0049).

## Consequences

- **Policies, routes and other resources are judged later** than planned.
- **The output model and the relationships between subjects are designed once,** against real use.
- **Phase 3a's fixes stop waiting for phase 3b.** They correct the image cases that the agent will judge.

## Alternatives

- **Phase 3b first, as planned.** It generalizes before anything consumes the output, so the output would be designed twice.
- **The plan across the fleet first.** A plan over unjudged cases is "patch everything", which is the cost the project exists to cut (main design, section 1).

**Precedent:** a walking skeleton, after Alistair Cockburn: one thin path through every layer before any layer gets thick.
