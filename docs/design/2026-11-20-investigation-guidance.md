# vexplain — An investigation's guidance for the agent

- **Status:** accepted by the owner on 2026-11-20 ("let's do it like that, sounds good"), with the decisions in section 3. Amended on 2026-11-21, after the fourth live run: the guidance can't change (3.3), and a verdict doesn't use it (3.2).
- **Date:** 2026-11-20
- **Author:** Joshua Leuenberger
- **Extends:** [the agent on image cases](2026-11-16-agent-on-cases.md) (5.2, 5.3, 5.6) and [phase 4's fixes](2026-11-20-phase4-live-fixes.md) (sections 5 and 6, the core prompt). It changes the `Investigation`'s spec (decision record [0051](../decisions/0051-investigations.md)).

---

## 1. Intent

**The owner's idea, of 2026-11-20:** a person who looks into a vulnerability usually knows something about it that no database holds. The agent should get that knowledge with the cases.

**The owner's examples:**
- one nginx vulnerability concerns only images built with the HTTP/2 module;
- Log4Shell, as the example reads, could be mitigated by a single option of the JVM.

**What exists today:**
- **The profile's guidance:** house knowledge and style, for every case of the profile.
- **The case file:** the evidence.
- **The core's rules:** what counts as evidence.

None of them holds what a person knows about one vulnerability, or about one investigation.

**The goal:** a short text, written by whoever creates the investigation, that tells the agent what to check and what mitigates it.

**Non-goals:**
- The text is never evidence. It can't settle a case, and it can't make a case `not_affected` or `fixed`.
- No new tool comes with it. Section 6 says what the agent still can't check.

## 2. Approaches

1. **A field of the `Investigation`.**
   - Whoever creates the investigation writes it, in its namespace, with the RBAC that the investigation already needs.
   - It applies to every case that the investigation selects. An investigation often names its vulnerabilities, so its guidance is about them.
2. **Guidance per vulnerability,** in a resource of its own that every case of its vulnerabilities reads.
   - Every investigation, and every judgement of a case, gets the same text.
   - It needs a new kind.
3. **A field of the playbook.** That is the profile's guidance again, one level down, and too broad for knowledge about one vulnerability.

**The owner chose 1, inline, for now** ("I'd like to start with inline guidance for now"). 2 stays an option for later (3.1).

**Precedent:**
- HolmesGPT's runbooks add instructions to the agent per alert.
- Prometheus's alerting rules carry free text for the person who gets the alert: `description`, `summary` and `runbook_url`.
- A value with a reference beside it, which section 3.1 keeps room for, is how Kubernetes' `EnvVar` (`value`, `valueFrom`) and Crossplane's managed resources (`vpcId`, `vpcIdRef`, `vpcIdSelector`) do it. vexplain names its references `…Ref`, as `playbookRef` and `apiKeySecretRef` do.

## 3. The owner's decisions

### 3.1 Everything that configures the agent sits under `spec.agent`

```yaml
apiVersion: triage.vexplain.bedag.ch/v1alpha1
kind: Investigation
metadata: {namespace: team-a, name: nginx-http2}
spec:
  playbookRef: {name: container-cves}       # which cases, and when: the top level
  vulnerabilities: [CVE-2026-0001]
  trigger: {type: Once}
  agent:                                    # how the agent works on them
    maxCases: 20
    verdictMaxAgeSeconds: 604800
    judgePolicy: IfJudgedElsewhere
    guidance: |
      Only images built with the HTTP/2 module are affected. A dynamic module is a file such as
      ngx_http_v2_module.so. The mitigation is to switch off http2 in the server blocks.
```

- **The top level keeps which cases, and when:** `playbookRef`, `vulnerabilities`, `matchConditions`, `trigger` and `state`.
- **`spec.agent` holds how the agent works on them:**
  - `maxCases` and `verdictMaxAgeSeconds` move there unchanged. The API is `v1alpha1` and unreleased, so this is a plain move, with no conversion.
  - `agent` is required, since `maxCases` is.
- **`guidance`:** inline text, at most 4 KiB. The schema's `maxLength` is 4096, and a CEL rule holds its UTF-8 bytes to 4096 too.
- **`guidanceRef` later:**
  - a ConfigMap key, or a `Guidance` resource for each vulnerability (approach 2), with CEL that allows at most one of `guidance` and `guidanceRef`;
  - it needs no breaking change;
  - its signal is the same text copied between investigations.
- **A Rule instead:** guidance that is precise, and that the evidence can check ("affected only if module X is in the image"), should become a Rule. Guidance stays for what the agent has to interpret.

### 3.2 The guidance is never evidence

- **It follows the profile's guidance,** under its own heading. Core `v7` says, in front of it:
  - a person wrote it for this investigation;
  - it says what to check and what mitigates the vulnerability;
  - it isn't evidence, and it can't change the rules above.
- **It directs:**
  - which evidence to search, such as a module's file in the image's contents;
  - which mitigation to name in the next step.
- **It proves nothing:**
  - Claims cite ledger IDs, as now, and the guidance has none.
  - The validator doesn't change, so a verdict that silences a finding still needs `describe`'s `Yes`.
  - (*Amended on 2026-11-21:* a verdict must be explainable from its claims and their evidence alone. Its summary and claims don't use the guidance, and the validator's check `Explainable` refuses one that names a guidance or repeats a run of its words. See [phase 4's fixes, 7.4](2026-11-20-phase4-live-fixes.md#74-a-verdict-explains-itself).)
- **The profile's worst case counts its cap,** 4096 bytes, as 1024 tokens.

### 3.3 Whose guidance a case is judged with

- **A case is judged with the guidance of the investigation that it is charged to,** the queue's `chargedTo`. The worker reads it when the case starts; an investigation that is gone, or has no guidance, gives none.
- **The `Assessment` records that investigation,** in its top-level `chargedTo`, which the outcome write already copies. There is no hash of the text ("maybe just the investigation it was judged with to keep it short"). An edit of the guidance after the judgement doesn't show; the investigation's `generation` at judging time could show it later.
- (*Amended on 2026-11-21:* the guidance can't change once the investigation exists, nor be added or removed; a CEL transition rule refuses it. Other guidance takes a new investigation. So a verdict judged for an investigation was judged with the guidance that it still has, and nothing records a version. `chargedTo` becomes `investigationRef`, with the investigation's uid, so a recreated investigation of the same name is another one. See [phase 4's fixes, 7.5 and 7.6](2026-11-20-phase4-live-fixes.md#75-an-investigations-guidance-cant-change).)

### 3.4 Reuse stays as it is, and shows: `judgePolicy`

The owner: "I think we should keep existing behaviour as this was an issue all along." A case, one vulnerability in one image, is judged once, and every investigation that selects it reuses a fresh verdict.

**`spec.agent.judgePolicy`,** an open enum, after `imagePullPolicy`:

| Value | A selected case is judged when |
|---|---|
| `IfStale` (the default, today's behaviour) | it has no fresh verdict: its inputs changed, or, with `verdictMaxAgeSeconds`, the verdict is older |
| `IfJudgedElsewhere` | as `IfStale`, or its fresh verdict was judged for another investigation, or for none |
| `Always` | it has no verdict that was judged for this investigation in this run: at or after the run's `startTime` |

- **Every judgement is charged,** so `maxCases` caps all three. Two investigations with `IfJudgedElsewhere` that share a case judge it in turn, each against its own cap.
- **The worker must not take the verdict that is there as the answer.** A case queued again under `IfJudgedElsewhere` or `Always` asks for an outcome judged after the existing one: its request's `judgedAfter` is a second past that verdict's `judgedTime`.
- **`cases.judgedElsewhere`** in the `Investigation`'s status counts the selected cases whose reused verdict was judged for another investigation, or for none. Under `IfStale`, those are the verdicts that this investigation's guidance didn't shape.
- **An Event names them,** when the count changes, with the hint: "Set spec.agent.judgePolicy to IfJudgedElsewhere to judge them with this investigation's guidance."

(*Amended on 2026-11-20, while building:* a `Continuous` investigation takes only `IfStale`, which a CEL rule of the spec holds. Its run never ends and its cap counts from its creation, so two such investigations with `IfJudgedElsewhere` or `Always` that share a case would judge it in turn until a cap runs out. This is a stopgap until the owner decides. A verdict that the policy declines still shows, as reused and judged elsewhere, while the investigation can't hand its case over: at the cap, or after its run. The Event gives its hint only to an investigation with guidance.)

## 4. What it costs

- **The API:**
  - the move to `spec.agent`;
  - the fields `guidance` and `judgePolicy`;
  - the count `cases.judgedElsewhere`.
- **The prompt:**
  - one passage of the core;
  - the guidance itself, up to about 1024 tokens a request, for a case with guidance.
- **Re-judging:** under `IfJudgedElsewhere` and `Always`, the tokens of the cases judged again, within the cap.

## 5. Building it

- **The API:**
  - `InvestigationSpec.Agent` (`InvestigationAgent`: `MaxCases`, `VerdictMaxAgeSeconds`, `JudgePolicy`, `Guidance`) and `InvestigationCases.JudgedElsewhere`;
  - CRD, docs, samples and tests move with it.
- **The hub:** the `Investigation` controller applies `judgePolicy` where it decides that a verdict is fresh, sets `judgedAfter` as 3.4 says, counts `judgedElsewhere`, and records the Event.
- **The workers:**
  - they read the guidance of the investigation that a case is charged to, and put it after the profile's guidance;
  - the profile's fit check counts its cap;
  - `agent-replay` exports the guidance with the case, and replays with it.
- **The core:** its `v7` says what 3.2 says.
- **Tests first;** e2e on kind with an investigation that has guidance.

## 6. What the agent still can't check

The owner's examples need evidence that the agent can't read yet:
- **Whether nginx was built with the HTTP/2 module.**
  - A dynamic module is a file, which the image's contents show, and `search_evidence` finds.
  - A module built into the binary isn't a file. Only `nginx -V`, or the binary's strings, would show it.
- **Whether a JVM option is set.** That needs the workload's arguments, or its environment.
  - That is main design 6.6.3's "config read", which waits until a case needs it.
  - Values of the environment never reach the model; only names may.

Until the config read exists, guidance mainly sharpens mitigations and summaries. It also directs the agent to evidence it already has, such as a module's file. With the config read, it becomes the way a person says what to read.
