# 0021 The hub decides; spokes observe, execute and render; spokes open every connection

- **Status:** Accepted (confirmed by the owner on 2026-10-29, with two amendments: the "mouth", and the hub's cluster normally running both roles while the roles stay separate). Refined by 0022 on 2026-10-30: a spoke's scan returns the package list, and the hub matches the CVEs once. Changed by 0029 and 0032 (proposed on 2026-10-31): spokes run collectors, and the hub asks them for evidence of a type instead of assigning tasks.
- **Date:** 2026-10-29
- **Refines:** 0003

## Context

0003 chose hub and spokes, but it still gave spokes local rules, a local prioritiser and the job of asking the hub questions. That spreads decisions across every cluster, and it lets many spokes ask about the same digest. The owner wants the opposite:

- the spokes collect, and act as the hub's eyes and hands
- the hub dedupes, decides and assesses
- generalised results live on the hub, workload-specific reports on the spokes
- no 100 spokes asking the same question

## Decision

- **The hub makes every decision:**
  - one record per digest across all clusters
  - image facts once per digest
  - all rules, prioritisation, budget and kill switch
  - agent, validator, review policy and `VexStatement`s
- **The result sheet:** the hub publishes `ImageVerdicts`, one per digest. It holds the rule outcome or accepted statement per CVE, with conditions.
- **Spokes have three jobs:**
  - **Eyes:** collectors, and reporting presence and summaries per digest. Everything in scope, unfiltered.
  - **Hands:** executing tasks the hub assigns: scanning a digest with the cluster's own pull credentials, gathering workload facts for agent tools, sandbox runs.
  - **Mouth:** says the results in its own cluster, rendering `WorkloadReport`s, metrics and events from the result sheet. That includes checking conditions per workload and turning verdict plus local exposure into urgency. This is deterministic rendering, not deciding.
- **No spoke ever asks a question.** The hub derives its work from reported presence, so dedupe is built into the structure.
- **Spokes open every connection,** to the hub's Kubernetes API, with a narrowly scoped service account. They write their own presence entries and task results, and read their own tasks and the result sheets. The hub never holds credentials for a spoke.
- **Modes `Hub`, `Spoke` and `HubAndSpoke`.**
  - The hub's cluster normally runs `HubAndSpoke`, because its own workloads need scanning too, and that's the expected setup.
  - The roles still stay strictly separate, so the hub's cluster can always be switched to `Hub` only.
  - Hub code reaches spoke capabilities only through the same Go interfaces it uses for remote spokes (presence store, task executor, result sheets), never through a local shortcut.
- **Same interfaces in one process:** in `HubAndSpoke`, both roles run in one process behind those interfaces. Until multi-cluster (phase 6), that's the only cluster. Phase 6 puts a transport behind the interfaces for remote spokes, without changing the flow.

## Consequences

- **This is an established pattern.** Open Cluster Management's agent pulls its work from the hub, and Argo CD's agent mode exists for the same reason. A compromised hub can't reach into the clusters, and spokes only need egress to the hub, through the proxy.
- **The open question about pulling images in a multi-cluster setup is resolved:** the hub asks one spoke that runs the digest to scan it.
- **Tool calls that need cluster facts become tasks** with a round trip to a spoke. In single-cluster mode, that's an in-process call.
- **`Assessment`s are created only by the hub.** They no longer carry "requesting clusters".
- **Rejected:** the hub fetching data from the spokes. It would need credentials for every cluster.
