# 0024 Urgency follows SSVC's deployer tree; a fix decides the next step, never the verdict

- **Status:** Accepted (decided by the owner on 2026-10-30). The input mappings marked **[call]** are designer's calls, to be revisited with real cases.
- **Date:** 2026-10-30
- **Refines:** 0006, by giving urgency a scale and its inputs. It also replaces the design's rule "fix available and the image is due for an update → next step update" (6.5).

## Context

- **The old rule was incomplete.** The design's rule table sent a finding straight to "update" when "a fix is available and the image is due for an update". It never said what makes an image due.
- **The owner's view:** what decides between "update soon" and "it can wait" is how exposed the workload is, and how big the risk is if it isn't fixed. Something minor on a workload that isn't exposed can wait. A big risk on an exposed workload gets updated soon.
- **That is urgency, not a verdict.** The design keeps the two apart: exposure changes urgency, never the verdict (0006).
- **If every available fix meant "update",** nothing could ever be deferred. Then the headline metric, the patches that could have been deferred with evidence that holds up, would mean nothing.
- **SSVC is the established model for this decision.** SSVC is Stakeholder-Specific Vulnerability Categorization, from CERT/CC, and CISA uses an adaptation of it.
  - Its tree for whoever applies patches combines four inputs: exploitation, system exposure, whether an attack can be automated, and impact.
  - It ends in one of four actions:
    - **Defer:** no action for now
    - **Scheduled:** in regular maintenance
    - **Out-of-cycle:** faster than usual
    - **Immediate:** drop everything

## Decision

- **Verdicts and urgency stay separate.**
  - The rules settle verdicts only: affected, not affected or unclear.
  - Neither an available fix nor exposure ever changes a verdict.
- **Urgency is SSVC's deployer outcome:** Defer, Scheduled, Out-of-cycle or Immediate. It is decided for each workload.
- **The inputs map onto what vexplain already collects:**
  - **Exploitation:** active when the CVE is on KEV. Otherwise proof of concept or none, from the advisory data.
  - **System exposure [call]:**

    | SSVC value | Exposure |
    |---|---|
    | open | the workload is exposed externally (6.4) |
    | controlled | indirect, one hop behind an exposed workload, or reachable from beyond its namespace |
    | small | reachable only from its own namespace |
  - **Automatable [call]:** derived from the CVE's attack vector, attack complexity and need for user interaction, until the agent can judge it per case.
  - **Impact [call]:** derived from the advisory's technical impact. How much a workload matters can come later, from allowlisted labels (6.14).
  - **The decision table:** SSVC's published deployer table is the default, and an admin can adjust it.
- **A fix decides the next step:** on a finding that is affected or unclear, the next step depends on whether a fix exists.
  - **A fix exists:** the next step is "update to the fixed version", with the urgency from the tree.
  - **No fix exists:** the next step is mitigation, or investigation. The agent investigates these first, starting with Immediate and Out-of-cycle.
- **KEV stays a rule:** a CVE on KEV is treated as affected without spending agent time, because patching is cheaper than investigating. Its urgency comes from the tree, where active exploitation weighs heavily.
- **Where urgency is computed:**
  - **The hub** orders the residual for the agent by urgency, using the highest exposure any spoke reported. EPSS orders the cases of equal urgency.
  - **Each spoke** renders the urgency of each of its workloads from the hub's verdict and its own local exposure (5.1). The result goes into `WorkloadReport`s, metrics and events.

## Consequences

- **The 2a measurement:** phase 2a measures the residual at the verdict level. That is everything the rules can't settle, labelled with severity and whether a fix exists. Urgency needs the exposure collectors, so it arrives with phase 2b.
- **Deferred patches become countable.** A patch is deferred when the tree puts the update at Defer or Scheduled, or when the agent shows the workload isn't affected.
- **`WorkloadReport`'s urgency** uses SSVC's four outcomes, which security teams already know.
- **Rejected:**
  - **"Every available fix means update."** Nothing could ever be deferred.
  - **Thresholds on the CVSS score alone.** They ignore exposure and exploitation, which is the reason SSVC exists.
  - **A scale of our own.** It would be one more vocabulary for the same four steps.

## Sources

- [CERT/CC SSVC](https://github.com/CERTCC/SSVC)
- [CISA's SSVC decision tree (SecurityWeek)](https://www.securityweek.com/cisa-releases-decision-tree-model-help-companies-prioritize-vulnerability-patching/)
- [SSVC's deployer outcomes explained (PwC Japan)](https://www.pwc.com/jp/ja/knowledge/column/awareness-cyber-security/stakeholder-specific-vulnerability-categorization.html)
