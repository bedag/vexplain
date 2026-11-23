# vexplain — What the agent is asked (draft)

- **Status:** draft, for the owner's review. Nothing here is accepted or built.
  - Section 2 holds what the owner agreed to add to the prompt on 2026-11-20.
  - Section 3 is the owner's new wish of 2026-11-20. It needs data that vexplain doesn't have yet.
  - Section 4 lists the questions for the owner.
- **Date:** 2026-11-20
- **Author:** Joshua Leuenberger
- **Extends:** [the agent on image cases](2026-11-16-agent-on-cases.md) (5.2, 5.6, 5.12) and [phase 4's fixes](2026-11-20-phase4-live-fixes.md). The fixes make the core prompt `v5`, and the second live run's rules make it `v6` ([fixes, section 5](2026-11-20-phase4-live-fixes.md#5-core-v6-after-the-second-live-run)), the third's `v7` (section 6), and the fourth's `v8` (section 7), so this would be `v9`.

---

## 1. Intent

The first live run showed that the agent answers one question: is the installed version vulnerable. Where a fix exists, the matcher already knows the answer, and a rule now says it (fixes, 2.7). The agent's work pays where no fix helps today. There, the SOC asks other questions, which the agent isn't asked:
- does anything load the package;
- how exposed is the workload, and how urgent is it;
- is the distribution's release at its end of life;
- why won't the distribution fix it;
- what mitigates it now.

Where a case is `Affected`, the SOC also asks what that means for an attacker: can one reach it, and from where.

**The agent design's research says the same** (4.4): SP 800-40 and SSVC say that a known fix is applied, and that analysis pays where none exists.

## 2. The SOC's questions, where no fix helps

**Which cases:** the agent condition already sends the cases that rules leave open. With `fix-available` shipped, those are the cases with:
- no fix;
- a fix that the distribution won't ship (`wont-fix`);
- a fix state that is unknown;
- a binary matched by its CPE.

**What the prompt adds,** one question each, each answered from evidence or said to be unchecked:
1. **What loads the package.**
   - From the rules' notes, such as load-check's "reached by /usr/bin/curl", and the image's contents.
   - No note and no evidence means "not checked", never "not loaded".
2. **Exposure and urgency.**
   - From `runsIn`: the workloads by exposure, the highest exposure, and the highest urgency.
   - The summary names the most exposed workload's exposure.
3. **The release's end of life.**
   - Grype's database names the distribution's release, but not its end of life. A source is open (question 4.2).
4. **The distribution's reason not to fix.**
   - From the distribution's tracker, through `fetch`. Debian's tracker, for example, notes "minor issue" or "no DSA".
   - The answer cites the page.
5. **Mitigation.**
   - What lowers the risk now, such as a configuration, a removed binary or a network policy.
   - It comes with the step Mitigate.
   - The agent proposes it; nothing applies it.

**The outcome** may then carry a step that the agent chose: Update, Change, Mitigate or Investigate. Today the step comes from urgency alone, and the agent's `nextStep` is free text. Which one wins is question 4.3.

## 3. Exploitability, where a case is `Affected`

**The owner's wish:** for an `Affected` case, say what it means for exploitability, such as whether an attacker can reach the workload from outside, through the DMZ.

**What it needs:**
1. **An agent condition that also sends some `Affected` cases.** For example:
   ```
   finding.status == "UnderInvestigation"
   || (finding.status == "Affected" && (finding.knownExploited || impact.highestExposure == "Open"))
   ```
   This costs tokens on cases whose verdict is known. It pays only if the answer changes what the SOC does first.
2. **Data on where a workload is published from.**
   - Today `network-reach` gives each workload's exposure: whether a Service, an Ingress or a Gateway reaches it.
   - It doesn't say what lies in front of the cluster. Only the organization's own infrastructure knows that, so a collector of the organization's own delivers it, from outside this repository.
3. **The generic hook, in this repository.** It is the collector model as it stands (0031):
   - **A lookup as an agent tool.** A collector's operation, such as "what publishes this host, and from where", is found by `search_tools` and called like `describe`. Its answer is in the ledger, and claims can cite it. Nothing in vexplain names the operation or its values.
   - **Facts for rules and urgency.** The same collector can deliver its facts as evidence of a type it declares. Rules read it through their inputs, and urgency's exposure could read it the same way. Which of its fields urgency reads is open (question 4).
   - vexplain ships no such collector, and no names of networks or zones **[call]**.
4. **What the agent says:**
   - whether the vulnerable package is reachable from outside, and through what, as far as the lookup's answer shows;
   - what an attacker would need, from the record's description and CVSS vector.

   `Affected` stays the status. The answer goes into the summary and, as OpenVEX's `impact_statement`, into a statement for review **[call]**.

## 4. Questions for the owner

1. **Which cases go to the agent** for section 3: known exploited, exposure `Open`, both, or a playbook's own condition?
2. **Where the end of life comes from** (2.3):
   - a public source, such as endoflife.date, fetched like an advisory;
   - or the vulnerabilities collector, from a table that ships with it.
3. **Who chooses the step:** the agent, within what evidence allows, or urgency alone, as today, with the agent's step beside it?
4. **Urgency:** may a collector's facts change a workload's exposure, and so its urgency, or do they only inform the agent? If they may, urgency needs a generic way to read them, such as a field that the collector's evidence type names.
   - *Answered on 2026-11-22 by the design of [entry points](2026-11-20-entry-points.md) (0059):* yes. Exposure rules read the collectors' evidence on the hub, and urgency follows.
5. **The cost:** how many tokens may a case of section 3 spend, against the cases of section 2?
