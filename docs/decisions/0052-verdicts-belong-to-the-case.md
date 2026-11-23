# 0052 A verdict belongs to the case; the hub creates an `Assessment` only for cases that are selected

- **Status:** Accepted on 2026-11-16. The decisions are the owner's, from the phase 4 discussion, and the owner accepted the write-up on 2026-11-16. Refined on 2026-11-22 by 0059: `runsIn` groups the workloads by exposure and by the rules that decided it, outside the case's inputs.
- **Date:** 2026-11-16
- **Refines:** the main design's `Assessment` (6.2), the queue (6.6) and 0050's cases.
- **Design:** [the agent on image cases](../design/2026-11-16-agent-on-cases.md), section 5.4.

## Context

- **0050:** the agent's first job is a verdict per case, one CVE in one platform manifest, judged once wherever it runs.
- **Investigations select cases (0051).** Several may select the same case, and several playbooks may meet it (collector model 5.7).
- **The agents of SOC tools attach their verdict to the item,** not to the run, and offer a "re-run": Defender's and Google's triage agents. k8sgpt writes a `Result` per finding.

## Decision

- **The hub creates an `Assessment` when an investigation selects a case without a fresh verdict,** and reuses a fresh one. A person never creates one.
- **One per case, cluster-scoped, on the hub.** A case is one vulnerability in one subject, and covers every finding of it there; the most cautious package decides. Its spec is immutable, and the investigations' caps bound how many exist.
- **Fresh until its inputs change:** the case's findings, by ID and package, and the data of its case file's evidence, so a scanner release that finds the same facts changes nothing. A stale verdict's `VexStatement` turns `Superseded`, and the next investigation that selects the case judges it again. An investigation may ask for verdicts younger than a maximum age.
- **One queue on the hub:** most urgent first, then known exploited, EPSS and spread. A case that two investigations want is judged once.
- **The case holds a short summary.** The full reasoning and tool output, the ledger, live in the bulky store (0004).

## Consequences

- Tokens are spent once per case, however many investigations ask.
- A new prompt or model doesn't re-judge past cases (main design 6.6.1).
- **Rejected:**
  - **verdicts on the investigation,** which would judge the same case again for every request;
  - **the ledger in the case's status,** which can pass etcd's limits.
