# The agent

The agent judges the cases that deterministic rules leave open: one vulnerability in one image. It proposes a verdict, citing the evidence it gathered, and people review it. This guide covers what an admin sets: the `AgentProfile`, the model's context window and the switch that turns the agent off. It also says how a case is judged, and where its outcome shows.

The [design of the agent on image cases](design/2026-11-16-agent-on-cases.md) gives the reasons, with decision records [0016](decisions/0016-agent-profile-and-editable-prompt.md) and [0055](decisions/0055-agent-context.md).

> **Where this stands.** The agent judges the cases that investigations select, with vexplain's own runner. Its verdicts show in the sheets and reports, and its "not affected" and "fixed" become `VexStatement`s that people review.

## The profile

An `AgentProfile` holds what the agent works with: the model, the editable guidance of its prompt, its limits on one case and the tools it may use. The operator creates the profile named `default` at start when it is missing, and never changes one that exists, so an admin's edits stay. [The sample](../config/samples/config_v1alpha1_agentprofile.yaml) shows every field.

```yaml
apiVersion: config.vexplain.bedag.ch/v1alpha1
kind: AgentProfile
metadata:
  name: default
spec:
  modelRef:
    name: default          # the ModelConfig of the model
  guidance:
    type: Embedded         # Embedded (default) | ConfigMap
  tools:
  - collector: vulnerabilities
    operations: [describe] # absent: every operation of the collector in the hub's role
  - collector: advisories
    operations: [fetch]    # offers no tool where advisories isn't installed
```

### The prompt

The prompt has two layers:
- **The core** is the operator's: the agent's role, its tools, the evidence rules and the rule that "not affected" needs strong evidence. It is embedded in the binary and versioned, because the loop and the validator depend on it. Nobody can edit it.
- **The guidance** follows it: house knowledge, priorities and style. It adds to the core, and can't change its rules.

An investigation may add guidance of its own after them, for the cases judged for it: see [what an investigation tells the agent](#what-an-investigation-tells-the-agent).

The guidance that the operator ships says where to look first and how to write a summary. To replace it, keep the text in a ConfigMap in the operator's namespace, such as one that kustomize's `configMapGenerator` makes from a file in git:

```yaml
  guidance:
    type: ConfigMap
    configMapRef:
      name: agent-guidance
      key: guidance.md
```

A ConfigMap that is missing, or holds no text under the key, makes the profile `Ready=False` with the reason `GuidanceMissing`, and records an `AgentProfileInvalid` event. The operator never falls back to the embedded text. A ConfigMap in any other namespace is never read.

A changed guidance applies to the cases that start after it. Cases already judged keep theirs.

### The limits

Tokens are estimated as bytes / 4.

| Field | Default | Range | Bounds |
|---|---|---|---|
| `maxSteps` | 15 | 1–50 | model calls with tools in a case |
| `maxTokens` | 300000 | 1000–10000000 | tokens that a case spends, prompt and completion, as the endpoint reports them |
| `timeoutSeconds` | 900 | 30–7200 | a whole case |
| `toolTimeoutSeconds` | 120 | 1–1800 | each tool call |
| `reservedTokens` | 4000 | 0–32768 | the one call that asks for a summary when a limit trips |
| `toolResultMaxTokens` | 4000 | 256–32768 | what the model sees of a tool result; the ledger keeps all of it |
| `caseFileMaxTokens` | 16000 | 1000–131072 | the case file in the first request |

A case that hits a limit ends with "no verdict" and a summary, never with a guess.

## The model's context window

A `ModelConfig` states the window of its model, from the model's documentation:

```yaml
spec:
  contextWindowTokens: 200000   # 1024–10000000
```

The profile is `Ready` only when its worst case fits in it. The worst case is the most that one request of a case could hold:

```text
core prompt + guidance + an investigation's guidance at its cap (4096 bytes, about 1024 tokens)
  + caseFileMaxTokens + the core tools + 4000 (tools found by search)
  + maxSteps × (toolResultMaxTokens + 4096) + reservedTokens
```

Each step of a case asks the model for an answer of at most 4096 tokens, which stays in the conversation, so the worst case counts one for every step.

The status shows it as `worstCaseContextTokens`, and `kubectl get agentprofiles` shows it in the column `Worst case`. The default limits need a window of at least about 149000 tokens; a model with a smaller window needs smaller limits, such as a lower `maxSteps` or `toolResultMaxTokens`. A profile over the window is `Ready=False` with the reason `ExceedsContextWindow`. Without a stated window the reason is `ContextWindowUnknown`.

| Reason of `Ready=False` | Means |
|---|---|
| `GuidanceMissing` | The ConfigMap of the guidance is missing from the operator's namespace, or holds no text under the key. |
| `ModelConfigMissing` | The ModelConfig that `modelRef` names doesn't exist. |
| `ContextWindowUnknown` | That ModelConfig states no `contextWindowTokens`. |
| `ExceedsContextWindow` | `worstCaseContextTokens` is above it. |
| `UnknownValue` | The guidance's `type` is one that this version of the operator doesn't know. |

Whether the model's endpoint answers is the `ModelConfig`'s own `Ready` condition, not the profile's. Its probe looks for `spec.model` in the endpoint's `/models` exactly as it is listed there, so set `model` to the listed ID: a gateway may list its models with a prefix, such as its provider's name, and accept chat requests without it. A model that isn't listed is `Ready=False` with the reason `ModelNotFound`.

## Measuring a model on saved cases

`agent-replay` measures tokens, steps and peak context on judged cases against a model of your choice, before anything goes live and without the cluster's tools. `export` reads a judged case through your kubeconfig and only reads from the cluster:

```sh
go run ./cmd/agent-replay export --assessment NAME --out cases [--kubeconfig FILE] [--namespace vexplain-system]
```

It saves `cases/NAME/` with the case and its evidence, the validator's case, the profile's limits and guidance, the guidance of the investigation that the case was judged for, and the forwarded tool calls of the case's `Ledger` with their outputs and trust. Owner values are left out, and no secret is saved. Keep the saved cases outside the repository.

`run` judges every saved case again with the runner and vexplain's MCP server. A forwarded tool answers a call with the same tool and arguments from the recording, and any other call with the tool error `not recorded`; the core tools run again on the case file.

```sh
VEXPLAIN_LLM_API_KEY=... go run ./cmd/agent-replay run --cases cases --endpoint URL --model NAME --context-window N
```

It prints a JSON line for each case, then one for the total: `steps`, `promptTokens`, `completionTokens`, `peakContextTokens`, `outcome` (the verdict's status, or the no-verdict's reason), `rejections` (verdicts that the validator rejected), and `error` where the endpoint failed the case. Without `--context-window` the fit check is off. The key comes only from the environment, and the output names neither it nor the endpoint.

A replay shows the model less of the tools than a live case: the Ledger keeps no definitions of the tools, so a search lists them with a plain description, and the replay doesn't know which of them fetch: it answers a fetch as any other call, from the recording, and never fetches.

## What a verdict needs

The agent calls a collector's operation as a tool named `<collector>__<operation>`, such as `vulnerabilities__describe`, when the profile grants it and it runs in the hub's role. A spoke's operation is never a tool, and neither is one that produces the SBOM type, such as the scanner's `scan`, which the hub asks for itself. Each call ends after `toolTimeoutSeconds`.

`vulnerabilities__describe` is listed from the first step, when the profile grants it, and counts towards the limits of loaded tools; every other operation is found by `search_tools`. When the agent asks `describe` about an ID of the case (the vulnerability's, or a finding's ID or alias), the core adds the case's other IDs to `aliases`, after those the agent gave and up to 8, so that the ecosystem's own record answers too. The ledger records the arguments as they went to the collector.

A fetch, such as `advisories__fetch`, takes only a URL that a reference of `vulnerabilities__describe` named in this case, in an answer of known trust ([design 5.8](design/2026-11-16-agent-on-cases.md#58-advisories-0054)). The allowed hosts, such as `github.com`, host anyone's pages, so a URL that the model wrote, or found in a page or another tool's output, could carry the case's data out. The URLs compare with the ASCII letters of their scheme and host in any case, without their fragment, and with their path and query as written, and the fetch takes the reference as the answer wrote it, never the model's spelling. Any other URL is refused before a request: the ledger records the call, with a tool error that doesn't repeat the URL, and `vexplain_agent_tool_refusals_total` counts it. Every operation that produces pages counts as a fetch, whatever its collector's name, and a page is of external trust.

After an answer of `describe`, the core names the hosts of its references that the granted fetch can't reach, by that collector's `allowedDomains`, or the default ([collectors](collectors.md)), so that the agent spends no step on them. It runs the fetch's own check of a URL, which `sdk/hosts` holds, and says how many other references the fetch refuses for their form, and why, such as "only https URLs are fetched", without repeating them. The answer in the ledger stays as the collector wrote it. A host that a proxy refuses can't be known before a fetch: drop it from `allowedDomains` until the proxy opens it.

A call that repeats an earlier call of the case, the same tool with the same arguments in any order, isn't run again when the earlier one didn't fail. Its answer names the earlier ledger ID, it adds no entry, and it still counts as a step, so a loop of repetitions ends at `maxSteps`. A call that failed may run again, since a collector or a page may fail only for a moment, and so does `search_tools`, which may find other tools later in the case, as when a collector comes back.

Before a verdict is recorded, a validator checks it against a table that is part of the operator, which nobody can edit. A false "not affected" is the worst error, so a verdict that silences a finding, `NotAffected` or `Fixed`, needs strong evidence. Anything weaker stays open.

| Status | Needs |
|---|---|
| Every status | Each claim cites ledger IDs that exist. With an investigation's guidance, the summary and the claims stand on the evidence that they cite (`Explainable`): they don't name the guidance, nor repeat 8 words of it in a row, compared as words, ignoring case, except where the entries that they cite hold the same words. A claim cites its own entries; the summary, those of every claim. So a claim may quote the file that the guidance said to check, and a tracker's own "no guidance for". The next step may name the guidance's mitigation; the summary says only that the step is a mitigation. |
| `Affected`, `UnderInvestigation` | Nothing more. |
| `NotAffected` | The justification `VulnerableCodeNotPresent`, and what `Fixed` needs. Other justifications need evidence that comes later, such as a symbol scan. |
| `Fixed` | For every package of the case, a cited answer of `vulnerabilities__describe` in which a provider says `fixedForInstalled: Yes` in its records of the case's vulnerability or of one of its aliases, and nothing in the ledger that says `No`. The answer was asked about the package as the SBOM has it: its name, version, type, distribution and purl. No rule holds a finding of the case against the agent (`agentHolds`). |

- **Only `describe`'s answers count** towards `NotAffected` and `Fixed`. A fetched page, an MCP collector's output or a failed call is of external trust, and never does.
- **A `No` always counts.** A `No` in the shape of `describe`'s answer holds the case open, cited or not, whatever its trust, whatever vulnerability its records are of, with or without the purl, and in an output of several answers.
- **One repair.** A rejected verdict goes back to the agent with the problems. A second rejection ends the case without a verdict, with the reason `ValidatorRejected`.

## Where the agent runs

The agent runs in workers of its own, the `Deployment` `vexplain-agent` of 2 replicas, apart from the manager ([0057](decisions/0057-agent-workers.md)):
- The manager selects the cases of the investigations, queues them in the `Assessment`s' status and sweeps the queue. It never calls the model, and doesn't read the LLM key.
- Every worker claims cases from the queue and judges them, each with the runner, vexplain's MCP server with its safety core and the validator, and writes the ledger and the outcome. A worker names itself in its claims by its pod's name.
- The workers' leader, which they elect through the `Lease` `agent.vexplain.bedag.ch`, runs the `ModelConfig` controller, which probes the model. The `Lease` serves the probe alone: a worker that loses it stops probing and campaigns again, and its claims and the cases it judges go on.
- More replicas judge more cases at once only up to the `ModelConfig`'s `maxConcurrentRequests`, which counts the cases of every worker.
- A worker that fails loses only its own cases: they go back to the queue when their leases end. A restart of the manager leaves the cases in progress alone.
- With the workers scaled to 0, nothing says so: investigations stay `Judging`, and each `ModelConfig`'s status keeps its last probe.

The workers read these Secrets, all in the operator's namespace:
- the `ModelConfig`'s API key, in a Secret that carries the label `vexplain.bedag.ch/llm-api-key: "true"`. Their cache holds only such Secrets;
- the headers of the MCP collectors, in the Secrets labelled `vexplain.bedag.ch/mcp-headers: "true"`, when they call such a tool;
- `vexplain-agent-client-tls`, the client certificate under the name `vexplain-agent` with which they call the collectors. The manager issues it from the collectors' authority and renews it with 30 days left. The workers' code never reads the authority's key, but their role can (design 3.5), so a compromised worker could sign a certificate.

Their role, `agent-role`, comes from the markers of their own packages: `internal/agent/worker`, `internal/agent/models`, which holds the `ModelConfig` controller, and `cmd/agent`. It may read every Secret of the operator's namespace, since Kubernetes can't narrow a read by a label.

## What an investigation tells the agent

An `Investigation` says at its top level which cases to judge, and when. Under `spec.agent` it says how the agent works on them:

```yaml
spec:
  playbookRef: {name: container-cves}
  vulnerabilities: [CVE-2026-0001]
  agent:
    maxCases: 20                    # required, 1–1000
    verdictMaxAgeSeconds: 604800    # optional
    judgePolicy: IfJudgedElsewhere  # IfStale (default) | IfJudgedElsewhere | Always
    guidance: |
      Only images built with the HTTP/2 module are affected. A dynamic module is a file such as
      ngx_http_v2_module.so. The mitigation is to switch off http2 in the server blocks.
```

**`guidance`** is what a person knows about the investigation's vulnerabilities: what to check, and what mitigates them. It holds at most 4096 bytes. A case gets the guidance of the investigation that the queue's `investigationRef` names, read when the case starts; an investigation that is gone, that wants the case no more, or that has none, gives none, and so does an object of the same namespace and name with another `uid`: a recreated investigation is another one, and a case that an earlier object queued, and that a worker judges now, gets none of its guidance. A case that waits unclaimed is charged to the current object when it queues the case, and gets its guidance. It follows the profile's guidance under the heading "This investigation's guidance". It is never evidence: no claim can cite it, and a "not affected" still needs `describe`'s Yes. A verdict must be explainable from its claims and their evidence alone, also once the investigation is gone, so its summary and claims don't use the guidance, as the validator checks. The guidance can't change once the investigation exists, nor be added or removed: other guidance takes a new investigation. So a verdict judged for an investigation, which the `Assessment`'s `status.investigationRef` names, with its `uid`, was judged with the guidance that it has. Guidance that the evidence can check, such as "affected only if this module is in the image", is better a Rule.

**`judgePolicy`** says when a selected case is judged. A case is judged once, and every investigation that selects it reuses a fresh verdict, whoever it was judged for, unless the policy says otherwise:

| `judgePolicy` | A selected case is judged when |
|---|---|
| `IfStale` | it has no fresh verdict: its inputs changed, or, with `verdictMaxAgeSeconds`, the verdict is older |
| `IfJudgedElsewhere` | as `IfStale`, or its fresh verdict was judged for another investigation, or for none |
| `Always` | it has no verdict judged for this investigation in this run: at or after the run's `startTime` |

- `Always` judges each selected case once in each run: a `Once` investigation at its creation and at each change of its spec, a `Schedule` one at each tick.
- A `Continuous` investigation takes only `IfStale`, and the schema refuses the others with it: its run never ends, so two such investigations that share a case would judge it in turn until a cap runs out.
- Every judgement counts against `maxCases`. A case judged again asks for an outcome one second past the verdict that is there, in its `judgedAfter`, so that the worker doesn't take that verdict as the answer. Two investigations with `IfJudgedElsewhere` that share a case judge it in turn, each against its own cap.
- An `investigationRef` holds the investigation's `namespace`, `name` and `uid`, and a verdict is judged for the object that the `uid` names. An investigation recreated under the same name, as a migration or a sync does, is another one: under `IfStale` it reuses the earlier object's verdicts and counts them in `judgedElsewhere`, under `IfJudgedElsewhere` it judges them again, its `usage` sums only what was judged for it, and a request of the earlier object in a case's queue gives way to its own. A case that the earlier object charged and that waits unclaimed is charged to the current one, against its cap, even where the cap has no room left, so `charged` can pass `maxCases` by such cases; a judgement under way stays charged to the earlier object.
- While the investigation can't hand a case over, at the cap or after its run, a verdict that the policy declines still shows, with its verdict, and isn't over the cap.

**`status.cases.judgedElsewhere`** counts the selected cases whose fresh verdict, which the investigation shows, was judged for another investigation, or for none, or for an earlier object of its name: reused, judged in this run, or declined while its case can't be handed over. Those are the verdicts that this investigation's guidance didn't shape. When the count changes and is above 0, the investigation records the event `JudgedElsewhere`, which names up to 5 of the cases' `Assessment`s. Its first sentence says how many of them were judged for an earlier object: "N selected cases reuse a verdict that was judged for an earlier NAME." when all were, "N selected cases reuse a verdict that was judged for another investigation, or for none; E of them for an earlier NAME." when some were, and, when none was, "N selected cases reuse a verdict that was judged for another investigation, or for none." The event's advice follows the policy. With `IfStale`, an investigation with guidance adds: "Set spec.agent.judgePolicy to IfJudgedElsewhere to judge them with this investigation's guidance." With `IfJudgedElsewhere` or `Always`, a case counts as judged elsewhere only where the run couldn't hand it over. While the run hands cases over, that is for want of room under the cap, and the event advises raising `spec.agent.maxCases`. While it doesn't, because the run is closed, the investigation is disabled or the agent is switched off, the event names the cases without advice, as it does with `IfStale` and no guidance.

**A fresh cap.** A recreated investigation starts a new run with a fresh cap, and judges up to `maxCases` again. A migration, a rename and a sync that replaces the object all recreate it. An apply that changes nothing keeps the run and its cap. A changed spec of a `Once` investigation starts a new run too, so raising its `maxCases` judges its cases again under `Always`.

An investigation stored before `spec.agent` existed reads back without it. It is `Ready=False` and `Stalled`, with the reason `AgentSettingsMissing`, and judges nothing until it is applied again with `spec.agent`.

## How a case is judged

**The queue.** An `Investigation` hands the cases that it selects to one queue, and says at each reconcile which cases it still wants. The queue lives in the API, in each case's `Assessment` (decision 0057), so it survives a restart:
- `status.queue` holds the case while it waits or is judged: the `playbook` whose case file goes with it, `investigationRef`, the investigation that queued it, whose cap the judgement under way counts against, the `requests` of the investigations that want it, each with its `investigationRef` and `trigger`, one for each namespace and name, the latest `judgedAfter` of them, its place in the tiers (`order`: `urgencyRank`, `knownExploited`, `epssPermille`, `resources`), where it runs (`runsIn`, below), `queuedTime`, and the `failures`, `misses` and `notBefore` of its retries.
- The outcome moves the queue's `investigationRef` to `status.investigationRef`, which names the investigation that the judgement whose `usage` the status holds was made for, whose cap it counts against. A case queued again and withdrawn unjudged keeps it.
- The most urgent tier goes first: urgency, then a known-exploited vulnerability, then EPSS, then the workloads that run the image. Within a tier, a case that an investigation of the trigger `Once` wants, which a person asked for, goes first, and then the first come.
- A worker claims a case in one status update of its `Assessment`: `Ready=False` with the reason `Judging`, and `status.claim`, which names the worker, by its pod's name, and when its lease ends, 60 seconds ahead. The update carries the `Assessment`'s `resourceVersion`, so of two workers that try, one wins. The worker renews the lease every 20 seconds while it judges, and stops once the claim names another worker, or, after a renewal that failed, once the next renewal would come no sooner than its lease's end. It writes the outcome, which clears `queue` and `claim`, only while the claim names it.
- A case that two investigations want is judged once. A waiting case that no investigation wants any more, because its investigation went, is disabled or selects it no more, leaves the queue unjudged, and its `Assessment` is `Ready=False` with the reason `Withdrawn`; a case in progress finishes. An investigation that selects a withdrawn case later charges it as a new one.
- A worker rebuilds the case from its sheet and the inventory when it claims it, so a case is judged on its current findings. A case that no sheet holds any more is withdrawn. Before it starts, the agent reads its `Assessment` from the API server: one that holds the outcome of the case's current inputs already isn't judged again, and is `Ready` with the reason `Judged`.
- Each finding of the case file names its package's `purl` and `distro`, from the image's SBOM: the purl's `distro` qualifier, else the SBOM's distribution for an OS package, such as `debian-12`. A finding whose package has none shows neither.
- A case counts the workloads of the clusters that its playbook's `match.clusters` selects, by each cluster's labels: the hub's own cluster's, in its `OperatorConfig`, and each spoke's, in its `Spoke` ([remote spokes](remote-spokes.md)). Without a cluster selector, every cluster counts. So the case file's `runsIn`, the case's tier in the queue and its investigation's results cover every matching cluster that runs the image, and only those. The queue holds the clusters in `runsIn.clusters` for the workers, which can't read a spoke's labels and rebuild the case with them: where several playbooks select the case, the union of their matching clusters, and none where every cluster counts, as when one of them has no cluster selector.
- The case file's `runsIn` says where the image runs: its clusters, its first namespaces, its workloads and the urgent ones, `workloadsByExposure`, `highestExposure`, `highestUrgency`, and `exposure`, the workloads grouped by their exposure and the rules that decided it:

  ```json
  "exposure": [
    {"exposure": "Open", "rules": ["published-or-unchecked"], "workloads": 1,
     "first": ["workload/cluster-a/team-b/Deployment.apps/admin"]},
    {"exposure": "Unknown", "missing": ["dmz"], "workloads": 1,
     "first": ["workload/cluster-b/team-c/Deployment.apps/api"]},
    {"exposure": "Controlled", "rules": ["exposed-not-published", "reachable-in-cluster"], "workloads": 1,
     "first": ["workload/cluster-a/team-a/Deployment.apps/shop"]}
  ]
  ```

  - The hub decides each workload's exposure with the exposure rules of the investigation's playbook, from presence, exposure and the sources' answers on the hub, each time an investigation hands the case over, and `status.queue.runsIn` holds the result for the workers, which keep no view of exposure. Where several playbooks select the case, the hub takes the view of each playbook that the `Assessment` names in `status.playbooks` and that still selects it, from its own sheet, matching clusters and exposure rules, and the most urgent of them by the queue's tiers sets `order` and `runsIn`, whichever playbook's investigation hands the case over. So a playbook that stops selecting the case stops shaping its entry. `runsIn` holds `highestExposure`, `highestUrgency`, `urgentWorkloads`, `clusters` and the groups of `exposure`, whose counts the case file's `workloadsByExposure` sums. An investigation's `status.results[].exposure` names each case's highest, as its own playbook decides it.
  - The rules' names are the explanation, in the words of the admin who wrote them. An `Unknown` group names in `rules` the rules that couldn't be evaluated, and in `missing` the evidence that they lacked, or that was past its `maxAge`. A workload that ImageInventory counts and that presence on the hub doesn't name, as in a cluster whose presence hasn't reached the hub yet, is `Unknown` and has no subject to show.
  - The groups come Open first, then Unknown, Controlled and Small, at most 16, each with its first 5 workloads by subject, never by their labels. Over its cap, the case file cuts the groups after the namespaces, the least exposed first.
  - `runsIn` lies outside the case's inputs, so a change of exposure never makes a verdict stale.
- The case file comes from the `Assessment`'s case-file playbook. When that playbook is gone, has lost its agent section, or has no sheet of the image, the case takes the playbook of an investigation that selected it, and the `Assessment` records it.
- A case whose image no workload of a matching cluster runs is never selected, with the reason `not running`. `status.cases.total` counts the selected cases, `overTheCap` those of them that the cap keeps from the agent, and `notSelected` the cases in scope that a condition doesn't hold for or that run in no matching cluster. `summary.skip` counts the cases over the cap.
- `status.usage` sums the `promptTokens` and `completionTokens` of the `Assessment`s whose top-level `investigationRef` names the investigation, with its `uid`, and that were judged at or after the run's `startTime`. It shows 0 and 0 once the run has started and nothing was charged yet. A case that still waits has spent nothing, so its `queue.investigationRef` doesn't count.
- As many cases run at once as the default profile's `ModelConfig` allows in `maxConcurrentRequests`, counted over the claims of every worker.
- A case waits in the queue, with its `Assessment` `Ready=False` and the reason `Queued`, while the agent is switched off, or its profile or its `ModelConfig` isn't `Ready`. While the agent is switched off, or the default profile's `ModelConfig` isn't `Ready`, the workers claim no case. A case whose own profile or `ModelConfig` isn't `Ready` is claimed, `Judging`, and handed back each time a worker tries, every 10 seconds. It is never ended without a verdict for that.
- A request to the model that fails for the endpoint's sake hands the case back to the queue with nothing written: no answer, a timeout, HTTP 429 or a server error, and also 401, 403 and 404, which the `ModelConfig`'s probe reports. It is tried again after 10 seconds, doubled for each failure in a row, at most 10 minutes, for as long as the failure lasts. An attempt that fails after a request of it completed, or whose first request timed out, got a 2xx answer that isn't a chat completion or broke off, or got a gateway's timeout (HTTP 504), may have spent tokens: after five such attempts in a row, the case ends without a verdict, with the reason `ModelError`. A wait for another reason, such as a `ModelConfig` that isn't `Ready`, doesn't start the count again.
- An outcome that the API server refuses to write is a failure too: the case is judged again later, and the fifth failure in a row ends it without a verdict, `ModelError`, saying that its outcome couldn't be written.
- Every 30 seconds, from 90 seconds after the manager starts, the hub sweeps the queue:
  - a case whose worker's lease ended more than 30 seconds ago waits again, and counts a failure, since the worker may have spent tokens on it. Five failures end the case without a verdict, `ModelError`;
  - the requests of investigations that are gone are removed, and a waiting case that no request is left on is withdrawn;
  - an `Assessment` that is `Queued` or `Judging` without a queue, as an earlier version left it, is withdrawn. The first sweep waits for the investigations' first reconciles, which queue such a case again: withdrawn first, it would be charged again.

**The runner.** For one case, it sends the core prompt, the profile's guidance and the guidance of the investigation that the case was queued for, then the case file, and offers the core tools. `describe` is offered from the first request, and a tool that `search_tools` finds from the next request on. Each tool call goes to vexplain's MCP server, which records it in the ledger, and the model sees at most `toolResultMaxTokens` of each result. A step's answer is at most 4096 tokens, and the runner makes at most 8 tool calls of one answer; the rest get a tool error. A call whose arguments aren't a JSON object gets a tool error that quotes them, and the conversation replays it with `{}`, since some endpoints refuse a request that replays malformed arguments.

The case ends when the agent submits a verdict or no verdict, or at a limit:
- `maxSteps` model calls with tools;
- `maxTokens`: the next step isn't made when the tokens that the endpoint reported so far, twice the next request's estimate and `reservedTokens` would pass it, so that the step and the final call both fit;
- `timeoutSeconds`;
- `ContextLimit`: the next request, with room for its answer, would no longer fit the `ModelConfig`'s `contextWindowTokens`.

At a limit the runner makes one final call without tools, which may answer with up to `reservedTokens`, for a summary in two parts, which start with the lines "Established:" and "Would settle:". The runner splits them at that label, else at the first blank line, and leaves out headings. Where that leaves nothing established, the whole summary is, and what would settle the case is "Not said apart in the summary." To fit the context window, it leaves out the latest tool results. The case ends without a verdict, with the limit as its reason. If even that call fails, the case records the limit alone. A request that the endpoint refuses as such, with another HTTP 4xx such as 400, ends the case without a verdict, with the reason `ModelError`.

**The outcome.** When a case ends, its worker writes its `Ledger`, with the `Assessment`'s name, and then the `Assessment`'s status:

| Field | Holds |
|---|---|
| `verdict` | The status, the justification of `NotAffected`, the summary, the next step and the claims with their ledger IDs |
| `noVerdict` | The reason (`GaveUp`, `ValidatorRejected`, `MaxSteps`, `MaxTokens`, `Timeout`, `ContextLimit`, `ModelError`) and the summary. A verdict that the validator rejected shows as what the agent proposed, and why it was rejected. |
| `validation` | `Passed` or `Rejected`, and the repairs |
| `inputHash` | What the verdict rests on: while it matches the case's current inputs, investigations reuse the verdict. It hashes facts only: the findings by vulnerability ID and package name, version and type, and of the case file's evidence, for an SBOM its distribution, its packages by name, version, type and purl, and the catalogers that failed, for the image contents everything but how the scan ran, and for any other type its whole data. A rescan, or a scanner release, that finds the same facts keeps it |
| `ledgerRef`, `runner`, `model` | The ledger, the runner, the profile, the model, the core prompt's version and the guidance's hash |
| `usage` | Model calls, tokens, the peak context and the duration |
| `judgedTime` | When the agent recorded the outcome |

`Ready` is `False` with the reason `Judging` while the agent works on the case, and `True` with the reason `Judged` once the outcome is written. A case without a verdict records the event `NoVerdict`, and one whose verdict the validator rejected twice records `VerdictRejected`.

**Metrics.** They carry states and counts, never text:

| Metric | Labels |
|---|---|
| `vexplain_agent_cases_total` | `outcome`: the verdict's status, or `NoVerdict`; starts at 0 for each outcome |
| `vexplain_agent_no_verdicts_total` | `reason`; starts at 0 for each reason |
| `vexplain_agent_rejections_total` | `check` of the validator, the repaired rejections too; starts at 0 for each check |
| `vexplain_agent_tool_refusals_total` | `tool`, `reason`: `UntrustedURL` for a fetch of a URL that no trusted result of the case named |
| `vexplain_agent_tokens_total` | `kind`: `prompt` or `completion`; starts at 0 for both |
| `vexplain_agent_case_duration_seconds` | |
| `vexplain_investigation_cases` | `namespace`, `investigation`, `state`: `total`, `queued`, `inProgress`, `charged`, `judged`, `reused`, `overTheCap`, `judgedElsewhere`, `notSelected` |
| `vexplain_investigation_vulnerability_info` | `namespace`, `investigation`, `cve`: 1 for each `vulnerabilityID` of `status.results`, and each ID of `spec.vulnerabilities` that no result names, ignoring case; an investigation without `vulnerabilities` names only the CVEs of its results |
| `vexplain_investigation_agent_tokens_total` | `namespace`, `investigation`, `kind`: `prompt` or `completion`; the tokens of the judgements charged to the investigation, from 0 when its first judgement starts |
| `vexplain_investigation_agent_seconds_total` | `namespace`, `investigation`; the time that the agent spent on the judgements charged to the investigation |

The agent's workers start the four counters at 0 once they know the cluster's name, so that `increase()` sees the first case. The tool refusals start on their first count, since their tools and reasons aren't known beforehand.

## Where a verdict shows, and its review

A verdict holds for every finding of the case's vulnerability in the image, and shows in every sheet of the image while it is fresh: while its `inputHash` is that of the case's current findings and case file. The sheet's finding names it in its `agent` field: the `Assessment`, the status, the justification and, for `NotAffected` and `Fixed`, the statement and its review. Where the verdict changed the finding's status, `agent.ruleStatus` keeps the rules' status, which the case conditions of investigations read as `finding.status`, so a condition on the status selects the same cases with or without a verdict. `finding.rule` and `finding.justification` are the sheet's, after the verdict: where the verdict, or an accepted statement, decided the status, the rule is left out and the justification is the statement's, so a condition on them can change with a verdict or a review.
- **`Affected` and `UnderInvestigation`** apply directly: they are one more outcome beside the rules', and the most cautious still wins.
- **`NotAffected` and `Fixed`** become a `VexStatement` of their own in `Proposed`, named after the `Assessment` and the verdict, which the verdict names in `statement`, with the event `VerdictProposed` on the `Assessment`. Until a person accepts it, it changes nothing but the `agent` field: the finding stays open, and the report's action counts it in `agentProposed`.
- **Reviewing** means setting the statement's `spec.review.state` to `Accepted` or `Rejected`, with a `comment`. Who did it is in the API server's audit log. The rest of a statement never changes. Bind `vexplain-triage-vexstatement-reviewer-role` to the reviewers with a `ClusterRoleBinding`.
- **An accepted statement that stands** settles its findings as its status, with no rule and the reason `accepted VEX statement <name>`, unless a rule holds a finding against the agent (`holdAgainst: All`).
- **When the inputs change**, as with a new package version, the `Assessment` turns `Ready=False` with the reason `Stale`, and its statement `Superseded`: it settles nothing, the finding opens again, and the next investigation that selects the case has it judged again. A new verdict gets a statement of its own; the earlier one stays, `Superseded`, with its review. The hub deletes no statement.
- **An investigation's result** for the case keeps the sheet's `status`, `step` and `result`, and shows the agent's fresh verdict in `verdict` and its statement's review in `review` beside them, so an unreviewed `NotAffected` never reads as `pass`.
- **A case goes with the last sheet of its image:** its `Assessment`, its `Ledger` and the outputs of its tool calls. Its `VexStatement` stays, since a review can't be rebuilt.

`vexplain_vex_statements` counts the statements by `review`: `Proposed`, `Accepted`, `Rejected`, or `Superseded` for one that no longer stands.

## Switching the agent off

```yaml
apiVersion: config.vexplain.bedag.ch/v1alpha1
kind: OperatorConfig
metadata:
  name: default
spec:
  agent:
    state: Disabled   # Enabled (default) | Disabled
```

`Disabled` switches the whole integration off: no model is called, cases in progress go back to the queue with nothing written, and investigations still show where a vulnerability runs. A case that goes back records the event `AgentDisabled` on the `OperatorConfig`. While it is off, an investigation keeps handing the cases that wait to the queue, so that they wait on their current findings. Switched on again, the agent judges them.
