# 0059 Exposure rules decide each workload's exposure on the hub, from presence, exposure and the sources' answers

- **Status:** Accepted on 2026-11-22. Proposed on 2026-11-21, and revised with the design's draft 3. The direction is the owner's: no kind and no playbook for this use case, the CVE playbook's rules join the evidence on the hub, the evidence and the rules are the interface, node ports and host ports name the nodes' addresses, Kubernetes' names, and cases first, with ImageInventory's counts for where an image runs. The details are the designer's, and the owner accepted the write-up on 2026-11-22. Amended on 2026-11-23 while building: adding an exposure rule never lowers a value that another rule concluded, nor a failure's Unknown, where the precedent said that an exposure rule can only raise an exposure; a new rule can lower the Unknown of a workload that no rule applies to, and one that brings a workload past 4 combinations of producers makes it Unknown (design 5.6). Amended on 2026-11-23 by the final review of the build: a `Collector` counts as a producer of an exposure rule's input only while it declares the type, with the scope `Hub` unless it is a source of it, and a pinned one that doesn't count is a missing input, as for finding rules (design 5.6). Refined on 2026-11-24 by the [remote spokes](../design/2026-11-23-remote-spokes.md) design, 5.10: an address that two clusters name gets no source's answer.
- **Date:** 2026-11-21
- **Refines:**
  - 0006: exposure comes from the collectors' evidence, and exposure rules decide it; it still changes urgency only;
  - 0021: the hub decides exposure for its cases, and the spokes keep their own for the reports until a later step;
  - 0024: a workload with a missing input is Unknown, which urgency counts as Open;
  - 0032: host and address subjects are shared across clusters on purpose;
  - 0033: a rule decides about one finding, or about one workload's exposure;
  - 0043: a playbook's pipeline lists exposure rules, whose inputs come from the workload and its entry points;
  - 0045: `maxAge` is built, with its override on the `Collector`;
  - 0052: the case file's `runsIn` groups the workloads by exposure and by the rules that decided it, outside the case's inputs.
- **Design:** [entry points](../design/2026-11-20-entry-points.md), sections 4.2 to 4.6 and 5.1 to 5.12.

## Context

- **`network-reach` sees only the cluster.** Every Ingress of a counted class, every LoadBalancer Service, every route, node port and host port makes a workload Open today, whether the internet reaches it or only the organization's own network does.
- **What sits in front of a cluster differs by platform:** a DMZ's reverse proxies, a firewall's address translation. Only a collector of the organization's own can say what it publishes. One exists already, and it answers about hosts and addresses.
- **The design's first two drafts were rejected by the owner:**
  - draft 1 decided each workload in a fixed table on the hub, and wrote a kind of its own;
  - draft 2 made each entry point a finding of a playbook of its own, judged into verdict sheets for any subject.
- **The owner's direction:**
  - no kind and no playbook for this use case;
  - the CVE playbook combines the evidence with CEL, so that its case file says where an image runs, in names that rules give;
  - the rules run on the hub, which does the join, without ImageInventory.

## Options considered

| Option | Costs |
|---|---|
| The hub decides each workload in a fixed table, and writes a kind of its own (draft 1) | A kind and an engine for one use case |
| Entry points are findings of a playbook of their own, judged into verdict sheets for any subject (draft 2) | A playbook and a kind for one use case, and the CVE playbook can't combine the evidence |
| A table of named conditions in each playbook | Each playbook copies the CEL, and a source can only document a snippet |
| Exposure rules on the spokes | The hub decides (0021), and the spokes would need the sources' answers |
| **Exposure rules, `Rule`s that conclude an exposure, listed in the CVE playbook and run by the hub when it computes a case (chosen)** | **`Rule` gets a second kind of outcome, presence goes to the hub, and the reports keep today's exposure until a later step** |

## Decision

- **Entry points in exposure.** `network-reach` reports each workload's entry points under `external.entryPoints`, in Kubernetes' names:
  - `addresses`, `port`, `protocol`, `objectRef` and `parentRef`, and nothing more about the object until a rule reads it;
  - `subjects`, which the sources are asked about.

  A node port names every node's addresses, and a host port names those of the nodes its pods run on. Ways in that can't be checked are listed under `unchecked`.
- **Subjects:** `host/<name>` and `address/<ip>[:<port>]`, which the SDK normalizes.
- **Presence names each workload's subject,** so that presence and exposure join on the hub. Both become `Hub`-scoped (0058).
- **A source is a collector whose hub operation takes `hosts` and `addresses`, 1 to 64 points.**
  - It answers each point in a type of its own.
  - It declares a `maxAge`, or its admin sets one.
  - The hub asks it about every entry point, and again when its version changes or an answer reaches half its `maxAge`. It never asks a source about a manifest.
- **Exposure rules:** a `Rule` may conclude `outcome.exposure`, which is Open, Controlled or Small, instead of a status.
  - Its CEL sees its inputs only. Each input is the workload's record of that type or, for a source's type, a map from the workload's entry-point subjects to the answers.
  - The highest value wins, in the order Open, Unknown, Controlled, Small.
  - A rule with a missing input or a failing CEL counts as Unknown, and so does a workload that no rule applies to.
- **vexplain ships three exposure rules** that do what the spoke's mapping does today, and `container-cves` lists them. A source ships two, and the admin swaps the default Open rule for them.
- **Cases first.** The hub runs the exposure rules when it computes a case's impact and builds its case file, and stores nothing.
  - A case's counts, highest exposure, urgency and order follow from them.
  - The case file groups the workloads by exposure and by the rules that decided it.
  - ImageInventory stays where cases learn where an image runs, for now. A workload that it counts and presence doesn't name is Unknown, so that a cluster's presence that hasn't reached the hub never lowers urgency.
- **The spokes keep their own exposure** for the reports, their urgency, the metrics and ImageInventory, until a later step carries the hub's result to them.
- **`maxAge` (0045) is built.**

## Consequences

- **With a source, a case's urgency drops for workloads that the internet doesn't reach,** and the case file names the rules that said so. In today's urgency table, that changes only findings on the known-exploited list.
- **A report can show Open where its case shows Controlled,** until the later step. The report is on the safe side.
- **That the sources cover every way in from the internet is the admin's assumption,** made by swapping the default rule.
- **A virtual IP in front of the nodes that no Kubernetes object names isn't asked about.**
- **The organization's collector works without a change to its code.** Its admin sets its `maxAge` and applies its two rules.
- **Rejected:**
  - draft 1's table and kind, and draft 2's playbook of entry points and its sheets (owner);
  - a table of conditions in each playbook;
  - rules on the spokes (owner);
  - a field on the playbook's evidence that says what the evidence is about (owner): the rule and the producer already say it;
  - the name "reachability", which 0046 keeps for code reachability.

**Precedent:** SSVC's system exposure, where *open* is "Internet or another widely accessible network". Kubernetes RBAC is additive, so a new rule never takes away what another grants, as a new exposure rule never lowers a value that another rule concluded, nor a failure's Unknown. A ValidatingAdmissionPolicy evaluates CEL and fails closed by default.
