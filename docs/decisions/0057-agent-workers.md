# 0057 The agent runs in its own workers, which claim cases through the API

- **Status:** Accepted on 2026-11-20. The owner chose the pull model after the live run, and accepted this write-up on 2026-11-20. Amended on 2026-11-20 while it was built: only the workers' code reads the LLM key. The manager's role still gets and lists the Secrets of the operator's namespace, for its own certificates, and the workers' role reaches the authority's key there too, since RBAC can't narrow a read by label ([design 3.5's amendment](../design/2026-11-20-phase4-live-fixes.md#35-certificates-roles-and-the-network)).
- **Date:** 2026-11-20
- **Refines:** 0053 (where the safety core and the runner run) and 0052 (the queue of cases).
- **Design:** [the agent on image cases](../design/2026-11-16-agent-on-cases.md), sections 5, 5.4, 5.5 and 5.13.

## Context

- **The agent ran inside the manager** (0053): the runner, vexplain's MCP server with the safety core, and the queue of cases, on the leader.
- **The live run showed what that costs:**
  - The manager restarted several times when renewing its leader lease timed out. Each restart dropped the cases in progress, and they were judged again, spending their tokens again.
  - A case holds its tool answers, of up to megabytes, in the manager's memory.
  - The manager held the LLM key and the egress to the model.
- **The owner wants to scale the agent apart from the manager,** and to keep a failing agent from affecting the manager (owner, 2026-11-20).
- **The options:**
  - Keep it in the manager.
  - Push: the manager keeps its queue and calls an agent service over the collector API's mutual TLS.
  - Pull: workers claim cases through the Kubernetes API.

## Decision

- **Agent workers run in their own Deployment,** with their own replicas, resources and service account. Each runs the runner and the safety core in-process, as 0053 describes, and writes the ledger and the case's outcome itself.
- **The manager keeps choosing.** Investigations select cases, and the hub creates their `Assessment`s as `Queued`, as 0052 says. The queue's order (design 5.3 and 5.4) becomes a value that the hub writes in each `Assessment`'s status, so the queue lives in the API and survives a restart of either side.
- **A worker claims a case** by moving its `Assessment` from `Queued` to `Judging` in one status update, naming itself and when its lease ends. The update carries the object's `resourceVersion`, so of two workers that try, one wins, as with a Kubernetes `Lease`.
- **The claim is a lease.**
  - The worker renews it while it judges.
  - The hub's sweep returns a case whose lease ran out to `Queued`. That counts as an attempt that may have spent tokens, under the retry rules of 0052's amendment.
- **`ModelConfig.maxConcurrentRequests` stays the endpoint's limit across all workers.** A worker claims a case only while fewer cases of that `ModelConfig` are `Judging` than the limit. The endpoint's 429 and the existing backoff absorb a brief overshoot.
- **The key moves with the model calls.**
  - Only the workers' service account reads the LLM key, and only their pods reach the model endpoint.
  - The `ModelConfig`'s probe runs on the workers' elected leader. Every worker claims cases.
- **The workers reach the collectors** with a client certificate from vexplain's own authority, as the manager does. The collectors' NetworkPolicy lets them in.
- **Their own image, from the same release.**
  - The workers run `cmd/agent` in an image of their own, built from the same commit and tagged like the manager's and the collectors'. Each pod carries only its own code and dependencies, so a scan of the manager doesn't report the agent's libraries, nor the other way round. cert-manager ships its controller, webhook and cainjector this way.
  - The case file and `Assessment`'s status are shared, so manager and workers run the same version, and a release upgrades both.
  - The owner left this to the designer (2026-11-20).

## Consequences

- **A manager restart leaves running cases alone.** A failed worker loses only its own cases, which go back to the queue when their leases end.
- **Scaling the agent means more replicas,** within the endpoint's limit.
- **The manager no longer reads the LLM key** or reaches the model.
- **New in the API:** the queue's order and the claim (worker and lease end) in `Assessment`'s status, validated with CEL, arriving with the plan that builds this.
- **The sweep withdraws and returns cases by their leases,** not by an in-memory queue.
- **The workers get their own role,** generated from markers like the manager's. They also get a client certificate, and a rule in the collectors' NetworkPolicy.
- **0053's boundary stays.** The safety core is still vexplain's MCP server, now in the workers. A kagent runner later would reach it over the network.
- **Rejected:**
  - **Keeping the agent in the manager:** no isolation, and scaling only within one pod on the leader.
  - **Push over the collector API:** the limit stays simple, but a manager restart still breaks running calls unless the agent writes its outcome itself, and spreading calls over replicas needs balancing on the client.

**Precedents:**
- Kyverno split its admission, background, reports and cleanup controllers into their own Deployments (1.10), to scale them apart and keep their failures apart.
- Argo CD runs manifest generation in its repo-server, scaled apart from the application controller.
- Kubernetes' `Lease` claims with the object's `resourceVersion`.
- Kueue keeps workloads queued as objects and admits them by priority.
