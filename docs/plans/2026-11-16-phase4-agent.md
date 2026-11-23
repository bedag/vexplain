# vexplain — Phase 4: the agent on image cases, Implementation Plan

> **For agents:** follow `AGENTS.md`. Implement this plan task by task, test first. A task is done when its tests pass, it is committed and it has been reviewed; only then start the next one. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** the SOC asks for investigations, and the agent judges the cases they select:
- `Investigation`s, once, on a schedule or continuously, whose status says where a CVE runs, how far the judging got, and where to start;
- one `Assessment` per case, judged once, reused while fresh;
- the safety core behind vexplain's own MCP server, with the ledger and the validator, and our own runner;
- `describe` on `vulnerabilities`, `fetch` on a new `advisories` collector, and MCP collectors;
- agent verdicts in the sheets and reports, and `VexStatement`s that a person reviews.

Then the owner's live run, and the SOC's view on its data.

**Architecture:**
- **New kinds:** `AgentProfile` (config), `Investigation`, `Assessment` and `VexStatement` (triage), `Ledger` (inventory).
- **The hub** selects cases (`internal/agent/cases`), queues them (`internal/agent/queue`), and judges each through a runner (`internal/agent/runner`) that talks to the model through `internal/llm` and to vexplain's MCP server (`internal/agent/core`) through the Go SDK's in-memory transport. The core writes the ledger and runs the validator (`internal/agent/validator`).
- **The Assessor** merges agent verdicts and accepted statements into the sheets; the spoke renders them.
- **The spoke** reports namespaces with owner values and workloads by exposure into `ImageInventory`.
- **Collectors:** `vulnerabilities` gains `describe` and EPSS; `advisories` is new; an MCP collector is a `Collector` that names a server.

**Tech Stack:** as in phase 3a, plus:
- `github.com/modelcontextprotocol/go-sdk` (the official Go SDK, its current v1 release), in the root module;
- `golang.org/x/net/html` in the new `advisories` module, to turn a page into text;
- grype's own `version` package, which `collectors/vulnerabilities` already depends on, for `describe`.

**Spec:**
- `docs/design/2026-11-16-agent-on-cases.md` (revision 1, accepted on 2026-11-16), with decision records 0051 to 0056;
- the main design (revision 17), sections 6.6 to 6.7 and 6.9, as amended there;
- phase 3a's fixes plan (`docs/plans/2026-11-15-phase3a-fixes.md`) and its "As built" section, which describe what exists.

**Branch:** `feat/phase4-agent`, from `docs/phase4-agent`, which holds the design. The two are stacked until the design merges.

**Not in this plan:**
- company knowledge (phase 5), sandbox runs, `ReviewPolicy`, an operator-wide budget, clearing old tool results, symbol search, lookups per advisory source, the config read, verdict conditions, and the kagent runner (design, sections 2 and 9);
- the two items that phase 3a's plan carried forward "for phase 4": backing off while a collector isn't ready, and `ScanFailed` for recurring `Internal` refusals. The design doesn't name them (see "Decisions for the owner").

## Decisions made in this plan

The design leaves these to the builder, or the code showed them while planning. Each is decided here so that implementers don't guess.

1. **What CEL's `finding` is** (design 5.3, amended while planning): the finding as rules see it, `evidence.Match` with its JSON names (`vulnerabilityID`, `aliases`, `packageType`, `severity`, `fixState`, `knownExploited`…), plus `status`, `rule`, `justification` and `epssPermille` from the sheet. It is built from the sheet with `rules.Matches`. So `knownExploited` is a boolean, as in the rules, and the shipped example reads `finding.knownExploited || finding.epssPermille >= 100`.
2. **The case CEL lives in `internal/rules/engine`** (`conditions.go`), because it reuses the unexported `program` and `refuseCalls`: the same cost limit (1,000,000), the same refused functions, and a bound of 100 ms per case. Its variables are maps (`cel.MapType(cel.StringType, cel.DynType)`), built from JSON. An expression that fails at evaluation doesn't select the case.
3. **`subject`** is `{manifestDigest, repositories, platform}`. **`impact`** is `{clusters, namespaces, resources, highestExposure, highestUrgency}`.
4. **Urgency on the hub** uses `urgency.Decide(urgency.FromFinding(f, exposure), overrides)` once per exposure level that a namespace has, with the hub's own `OperatorConfig` overrides. In phase 4 hub and spoke are one process, so this is the spoke's table. A fleet's differing tables go to phase 6 ("Carried forward").
5. **Namespaces in presence (5.14):** `ClusterPresence.namespaces`, each `{name, owner, workloadsByExposure}`.
   - `owner` is a list of `inventoryv1alpha1.OwnerValue`, copied from triage's type with the sources `NamespaceLabel` and `NamespaceAnnotation`, as the groups already copy `SSVCExposure`. Values keep triage's limit of 256 characters.
   - `workloadsByExposure` is `{open, controlled, small, unknown}`, counts of the workloads in that namespace that run the image (the design's sketch wrote the keys capitalized).
   - The cap is `OperatorConfig.spec.presence.maxNamespaces`: default 100, minimum 1, maximum 1000. The namespaces are sorted by name, and the store also drops namespaces from the end while the cluster's entry is over 256 KiB as JSON, so that a namespace with long annotations can't fail the whole write. `namespaceCount` keeps the total.
6. **`holdAgainst`** is `Rule.spec.outcome.holdAgainst`, `Rules` (default) or `All`, allowed only with `Affected` or `UnderInvestigation`. The engine records each rule with `All` that holds a finding in the sheet's `Finding.agentHolds` (set, at most 8), whichever rule wins.
7. **`describe` decides "fixed for the installed version" itself,** with grype's version comparison. The validator then never compares versions, and never trusts the model to. `describe(vulnerabilityID, packages)` answers per provider: the description, CVSS, the fixed versions per distribution or ecosystem, KEV, EPSS, the references, and for each package of the case `fixedForInstalled: Yes|No|Unknown`. It runs the pinned grype's `db search` commands against the collector's database, offline.
8. **The validator's table in phase 4** (`internal/agent/validator/table.go`):
   - every claim cites ledger IDs that exist;
   - `NotAffected` takes only the justification `VulnerableCodeNotPresent`, and `NotAffected` and `Fixed` need, for every package of the case, a cited `vulnerabilities__describe` entry whose answer says `fixedForInstalled: Yes` from the provider of the package's distribution or ecosystem;
   - a finding with `agentHolds` refuses `NotAffected` and `Fixed`;
   - entries of external trust (fetched pages, MCP collectors) never count towards `NotAffected` or `Fixed`;
   - `Affected` and `UnderInvestigation` need claims that cite IDs, and nothing more.
9. **Tool names** are `<collector>__<operation>`, since OpenAI-compatible tool names allow only `[a-zA-Z0-9_-]`, at most 64 characters. The core tools are `search_evidence`, `read_evidence`, `search_tools`, `submit_verdict` and `submit_no_verdict`.
   - **`search_evidence(name, query)`** searches one of the case file's evidence entries, flattened into `path = value` lines, case-insensitively, and returns at most 200 lines. It is generic, so it serves every use case.
   - **`search_tools(query)`** matches names and descriptions and returns at most 5 tools. A case loads at most 8 tools.
   - **The core offers only operations whose role is `Hub`.** Spoke operations, such as `scan`, are never tools in phase 4.
10. **The profile's tools** are `spec.tools`, a list of `{collector, operations}`. `operations` is optional: empty means every hub operation of a package collector, or every tool on an MCP collector's list.
11. **Tokens are estimated as bytes / 4** for every cap (`toolResultMaxTokens`, `caseFileMaxTokens`, the fit check). Budgets count the endpoint's reported usage. A tool result is cut at `4 × toolResultMaxTokens` bytes, on a line boundary.
12. **The fit check:** `core prompt + guidance + caseFileMaxTokens + core tools' schemas + 4000 (tools found by search) + maxSteps × toolResultMaxTokens + reservedTokens ≤ contextWindowTokens`. The profile's status shows the left side as `worstCaseContextTokens`.
13. **The profile's limits and defaults:**

    | Field | Default | Range |
    |---|---|---|
    | `maxSteps` | 15 | 1–50 |
    | `maxTokens` (prompt + completion, the whole case) | 300000 | 1000–10000000 |
    | `timeoutSeconds` | 900 | 30–7200 |
    | `toolTimeoutSeconds` | 120 | 1–1800 |
    | `reservedTokens` | 4000 | 0–32768 |
    | `toolResultMaxTokens` | 4000 | 256–32768 |
    | `caseFileMaxTokens` | 16000 | 1000–131072 |

    `ModelConfig.spec.contextWindowTokens`: optional, 1024–10000000.
14. **The ledger:** an `inventory` kind `Ledger`, one per `Assessment`, with the same name, written once at the end of a case through `inventory.LedgerStore`.
    - Each entry is `{id, tool, arguments (cut at 4096 characters), durationMilliseconds, trust (Known|External), outputRef, outputBytes, shownBytes, outputSHA256, preview (512 characters)}`.
    - Full outputs go into the evidence store at once, as the type `ch.bedag.vexplain.agent.tool-output.v1alpha1`, with the `Assessment` as subject. So the evidence store's cap applies to them, and an output over it is stored cut, with `outputBytes` the real size.
    - What the model saw is the first `shownBytes` of the output, so the ledger rebuilds it.
15. **Names and labels of a case:**
    - An `Assessment`, its `Ledger` and its `VexStatement` are named `<id>-<hash>`: the vulnerability ID in lower case, with every character outside `[a-z0-9-]` turned into `-` and cut to 200, then the first 16 hex characters of `sha256(vulnerabilityID + "@" + manifestDigest)`.
    - Labels: `vexplain.bedag.ch/vulnerability` (the ID, with characters outside `[A-Za-z0-9._-]` turned into `_`, cut to 63) and `vexplain.bedag.ch/digest` (the first 63 hex characters of the manifest digest, as 6.14).
16. **`inputHash`** is the SHA-256 of canonical JSON: the case's findings sorted by package ID, each `{vulnerabilityID, package: {id, name, version, type}}`, and for each case-file evidence name, the SHA-256 of its decompressed data, from each producer, sorted.
17. **The queue is in memory** (`internal/agent/queue`), ordered by the tiers of design 5.3 and then `Once` first and first come. Investigations are the source of truth for what is queued: after a restart, their reconciles queue their pending cases again. A case in progress at a restart is judged again; nothing is written until a case ends.
18. **The case file's playbook** is the playbook of the first investigation that queued the case. The `Assessment` records it in `status.caseFilePlaybook`, and lists every playbook whose investigation reused it in `status.playbooks`.
19. **`VexStatement`:** cluster-scoped, on the hub, named as its `Assessment`. The spec holds `subject`, `vulnerabilityID`, `status`, `justification`, `origin: Agent`, `assessmentRef` and `inputHash`, all immutable, and `review: {state: Proposed|Accepted|Rejected, comment}`, which reviewers edit. Its conditions are kstatus's three plus `Superseded`.
20. **The sheet's finding gains `agent`:** `{assessment, status, justification, review}`.
    - An agent's `Affected` or `UnderInvestigation` joins the rules as one more outcome, so the most cautious still wins.
    - An accepted statement that isn't superseded settles the finding as its status, with `rule` unset and the reason `accepted VEX statement <name>`.
    - A proposed one changes nothing but `agent`.
21. **The report's action gains `agentProposed`:** how many of its vulnerabilities have an agent "not affected" or "fixed" waiting for review. The printer column shows it.
22. **The cron parser moves** from `internal/controller/config/collector_schedules.go` to a new `internal/schedule` package (`Parse(expression string) (cron.Schedule, error)`), shared by collectors and investigations.
23. **The `advisories` collector** is a module of its own, `collectors/advisories`, as the other collectors are, in the hub's role. Its settings are `{allowedDomains, maxBytes (default 1048576), timeoutSeconds (default 20)}`. The default list is the advisory hosts of the distributions and ecosystems that Grype's providers cite, checked against the references in the database.
24. **An MCP collector:** `Collector.spec.mcp: {url, headersFrom, tools}`, exactly one of `package` and `mcp`.
    - `headersFrom` lists Secrets in the operator's namespace with the label `vexplain.bedag.ch/mcp-headers: "true"`; each key of a Secret is a header's name.
    - `tools` is required, 1 to 64 names.
    - The collector controller deploys nothing for it. It connects, lists the server's tools, and is `Ready` when every listed tool exists, or `Ready=False` with the reason `ToolsMissing`.
25. **Hard links stay as they are.** No phase 3a behaviour changes here, except the sheet, the report and presence fields above.

## Decisions for the owner

1. **The validator trusts `describe`'s comparison, not the model's** (decision 7). `describe` compares the installed version with each provider's fixed version, as grype does when it matches. Without it, the validator would have to compare versions itself, or let the model say it. Is that the reading of "resting on describe's fixed version" that you want?
2. **The model's smoke test (Task 11):** you run `llm-smoke` yourself, with the key in your shell, and paste the result line. The key then never reaches the session that builds the code, or a file. You can also hand the key over as an environment variable, which the plan allows, but never in a file.
3. **Phase 3a's two "for phase 4" items stay out** (backing off while a collector isn't ready, and `ScanFailed` for recurring refusals). They aren't in the design. They can be a small task before the live run if you want them.
4. **The task order differs from the design's section 6** in one way: the small, independent pieces (namespaces, guards, EPSS, `describe`) come first, since later tasks build on them.
5. **The defaults of decision 13,** especially `maxTokens` 300000 per case and `maxSteps` 15. They are tested against the replay set before the live run (Task 13).

## Global Constraints

- **AGENTS.md binds:** design first, test first, kind only, no private data and no figures from real platforms, no AI attribution, and comments that state their own reason and never cite a ruling of a ledger.
- **Phases 1 to 3a still bind,** as amended by their "As built" sections: API conventions, kube-api-linter, RBAC from markers, wiring through `setup.Register`, tests and commits.
- **Before each commit:** `make manifests generate && make proto-check && make lint && make test`.
- **e2e:** one `make test-e2e`, on kind, at the end of each task that changes a CRD, the install, a collector or the manager.
- **The API is `v1alpha1` and unreleased:** fields are added or changed without conversion. A fresh install.
- **Safety (AGENTS.md):**
  - read-only towards workloads;
  - the LLM key and MCP headers never appear in logs, status, events, metrics, errors, evidence or the ledger;
  - secret values, environment values and owner values never reach the model;
  - a false "not affected" is the worst error: nothing from a runner, a fetched page or an MCP collector moves a verdict towards it;
  - hitting a limit means "no verdict", with a summary.
- **Names:**
  - kinds: `AgentProfile` (config, cluster), `Investigation` (triage, namespaced), `Assessment` and `VexStatement` (triage, cluster), `Ledger` (inventory, cluster); category `vexplain`, and `vexplain-data` for `Ledger`;
  - the default profile is named `default`;
  - condition reasons: `AgentNotAllowed`, `AgentDisabled`, `CapReached`, `ExceedsContextWindow`, `ContextWindowUnknown`, `ToolsMissing`, `InvalidCondition`, `PlaybookNotFound`, `Judging`, `Queued`, `Stale`;
  - events: `RunStarted`, `RunFinished`, `TickSkipped`, `CapReached`, `AgentDisabled`, `VerdictProposed`, `VerdictRejected`, `NoVerdict`, `AgentProfileInvalid`;
  - the labels `vexplain.bedag.ch/vulnerability`, `vexplain.bedag.ch/digest` and `vexplain.bedag.ch/mcp-headers`;
  - the evidence types `ch.bedag.vexplain.agent.tool-output.v1alpha1` and `ch.bedag.vexplain.advisories.page.v1alpha1`.
- **Values:** those of decisions 5, 9, 13, 14 and 15; `Investigation`: at most 100 `vulnerabilities`, 16 `matchConditions`, `maxCases` 1–1000, 20 results, a reason of 256 characters, owners of 5 namespaces; an `Assessment`'s summary at most 2048 bytes.
- **Metrics** start with `vexplain_` and carry `cluster`. They carry states and counts, never text.
- **Commits:** Conventional Commits, signed, no AI attribution, never on `main`.
- **Repository hygiene:** neutral names, such as `cluster-a`, `team-a` and `artifacts.example`. Real case files stay in `.superpowers/phase4/cases/`, which git ignores.

## Review Focus

1. **A finding keyed by its GHSA ID, an investigation that names the CVE:** the alias selects it, as one case, and the agent works with the finding's own `vulnerabilityID` (Task 7).
2. **A URL that the model wrote, or that came from a fetched page or an MCP collector:** the core refuses it before any request, and the ledger records the refusal (Task 15).
3. **A tool result far over `toolResultMaxTokens`, every step:** the peak context stays under the profile's worst case, and at a limit the case ends with "no verdict" and a summary, never a verdict (Task 11).
4. **A manager restart in the middle of a case:** the case is queued again by its investigation, nothing half-written remains, and no second `VexStatement` appears (Task 11).
5. **An accepted statement whose image is scanned again with another package version:** the statement turns `Superseded`, and the finding reopens in the sheet and in the report (Task 12).

---

## File Structure

```text
api/config/v1alpha1/
  agentprofile_types.go          # Task 5 (new)
  modelconfig_types.go           # Task 5: contextWindowTokens
  operatorconfig_types.go        # Tasks 1, 5: spec.presence, spec.agent
  rule_types.go                  # Task 2: outcome.holdAgainst
  playbook_types.go              # Task 6: spec.agent
  collector_types.go             # Task 16: spec.mcp
api/triage/v1alpha1/
  investigation_types.go         # Tasks 7, 8 (new)
  assessment_types.go            # Task 7 (new)
  vexstatement_types.go          # Task 12 (new)
  resourcereport_types.go        # Task 12: agentProposed
api/inventory/v1alpha1/
  imageinventory_types.go        # Task 1: namespaces
  imageverdicts_types.go         # Tasks 2, 3, 12: agentHolds, epssPermille, agent
  ledger_types.go                # Task 9 (new)
sdk/evidence/                    # Task 3: EPSS in Match and its schema
internal/schedule/               # Task 8 (new, from internal/controller/config)
internal/rules/engine/           # Tasks 2, 6: agentHolds; conditions.go (new)
internal/rules/sheet.go          # Tasks 2, 3, 12
internal/inventory/              # Tasks 1, 9: namespaces in crdstore.go; ledger.go (new)
internal/spoke/                  # Tasks 1, 12: presence.go, render.go
internal/agent/
  profile/                       # Task 5: the effective profile
  cases/                         # Task 7: selection, impact, order, inputHash
  verdict/                       # Task 9: verdicts, claims, problems (a leaf, shared by core and validator)
  ledger/                        # Task 9
  casefile/                      # Task 9
  core/                          # Tasks 9, 10, 15, 16: the MCP server
  validator/                     # Task 10
  prompt/                        # Task 11: core.md (v1), guidance.md
  runner/                        # Task 11
  queue/                         # Task 11
internal/controller/config/      # Tasks 5, 16: agentprofile_controller.go, the MCP collector
internal/controller/hub/         # Tasks 7, 8, 11, 12: investigation.go, assessment.go, assessor.go
internal/collectorclient/mcp.go  # Task 16 (new)
internal/metrics/metrics.go      # Tasks 11, 12
internal/setup/setup.go          # every task that adds a controller
collectors/vulnerabilities/      # Tasks 3, 4: EPSS; internal/describe (new)
collectors/advisories/           # Task 14 (new module)
cmd/agent-replay/                # Task 13 (new)
config/                          # samples, rbac, rules/completeness-guard.yaml, playbooks/container-cves.yaml,
                                 # collectors/advisories.yaml, the default AgentProfile
docs/collectors.md, docs/agent.md (new), README.md
test/e2e/                        # Tasks 1, 7, 12, 14, 16; images/mcp-stand-in (new)
```

## Task order

`make test` stays green after every task.
- **Tasks 1 to 4:** what the agent reads: namespaces, guards, EPSS, `describe`.
- **Tasks 5 and 6:** the profile, the fit check, the playbook's agent section and the case CEL.
- **Tasks 7 and 8:** investigations and cases, without the agent.
- **Tasks 9 and 10:** the safety core: case file, ledger, MCP server, validator.
- **Task 11:** the runner and the queue; the agent judges.
- **Task 12:** verdicts into sheets, statements, review and reports.
- **Task 13:** the replay harness.
- **Tasks 14 to 16:** `advisories`, the fetch's checks, MCP collectors.
- **Task 17:** the live run, with the owner.
- **Task 18:** the SOC's view, on the live run's data.

### Task 1: Namespaces with owners and exposure in presence (5.14)

**Files:**
- `api/config/v1alpha1/operatorconfig_types.go` (`spec.presence.maxNamespaces`), `api/inventory/v1alpha1/imageinventory_types.go` (`NamespacePresence`, `OwnerValue`, `ExposureCounts`);
- `internal/settings/effective.go`; `internal/inventory/store.go` (`Observation.Namespaces`) and `crdstore.go`; `internal/spoke/presence.go`;
- tests: `internal/controller/config/operatorconfig_api_test.go`, `internal/controller/inventory/imageinventory_api_test.go`, `internal/inventory/crdstore_test.go`, `internal/spoke/presence_test.go`, `test/e2e/e2e_test.go`;
- `docs/collectors.md` (the workloads section), `config/samples/config_v1alpha1_operatorconfig.yaml`.

**Interfaces:**
- **Produces:** `inventory.Observation.Namespaces []inventory.NamespaceObservation{Name string; Owner []inventoryv1alpha1.OwnerValue; ByExposure map[inventoryv1alpha1.SSVCExposure]int32}`; `settings.Effective.MaxNamespaces int`.

- [ ] **Step 1: Write the failing tests.**
  - **API:** `maxNamespaces` defaults to 100, refuses 0 and 1001; `namespaces` takes `{name, owner, workloadsByExposure}` and refuses an owner value over 256 characters.
  - **Spoke, in `presence_test.go`:** `TestPresenceNamesTheNamespacesWithTheirOwnersAndExposure`: two workloads in `team-a` (one `Open`, one `Controlled`) and one in `team-b` (`Small`), with allowlisted namespace labels and an annotation, give two namespaces sorted by name, the owner values with their sources, and the counts per level. Workload labels never appear.
  - **Store, in `crdstore_test.go`:**
    - `TestTheNamespacesAreCappedAndCounted`: 5 namespaces and a cap of 3 keep the first 3 by name, and `namespaceCount` is 5;
    - `TestAClusterEntryOverItsSizeDropsNamespacesFromTheEnd`: namespaces whose annotations make the entry pass 256 KiB are dropped from the end until it fits, and the write succeeds.
- [ ] **Step 2: Run** `make test`, and see them fail.
- [ ] **Step 3: Implement.** `observation(digest)` groups the delivered workloads by namespace and reads `NamespaceLabels`, `NamespaceAnnotations` and `exposure.Of(w)`; the store copies, sorts, caps and trims.
- [ ] **Step 4: Verify** with the gate, and `make test-e2e`, where the e2e image's `ImageInventory` names its namespace with the counts.
- [ ] **Step 5: Commit:** `feat(inventory): name each cluster's namespaces with owners and exposure`

### Task 2: A guard can hold against the agent (5.5)

**Files:**
- `api/config/v1alpha1/rule_types.go` (`HoldAgainst`), `api/inventory/v1alpha1/imageverdicts_types.go` (`Finding.AgentHolds`);
- `internal/rules/engine/engine.go` (`Finding.AgentHolds`, recorded in `apply`), `internal/rules/sheet.go`, `internal/controller/hub/rule_controller.go`;
- `config/rules/completeness-guard.yaml` and its copy in `config/samples/config_v1alpha1_playbook.yaml`;
- tests: `internal/controller/config/rule_api_test.go`, `internal/rules/engine/engine_test.go`, `internal/rules/engine/defaults_test.go`, `internal/rules/sheet_test.go`.

**Interfaces:**
- **Produces:** `engine.Finding.AgentHolds []string`; the sheet's `Finding.agentHolds`.

- [ ] **Step 1: Write the failing tests.**
  - **API:** `holdAgainst: All` is accepted with `UnderInvestigation` and `Affected`, refused with `NotAffected` or without a status, and defaults to `Rules`.
  - **Engine:**
    - `TestARuleThatHoldsAgainstAllIsRecordedEvenWhenAnotherWins`: the completeness guard (`All`) and an `Affected` rule both apply; the finding is `Affected`, and `AgentHolds` is `[completeness-guard]`;
    - `TestAHoldAgainstRulesIsNotRecorded`: `known-exploited` holds, and `AgentHolds` is empty;
    - a rule with `All` that fails to evaluate is recorded too, since it fails closed.
  - **Defaults:** the shipped completeness guard has `All`, and `known-exploited` has none.
- [ ] **Step 2: Run** `go test ./internal/rules/... ./internal/controller/config/...`, and see them fail.
- [ ] **Step 3: Implement** in `apply` and `fail`, and in `rules.Findings`.
- [ ] **Step 4: Verify** with the gate.
- [ ] **Step 5: Commit:** `feat(rules): let a guard hold a finding against the agent`

### Task 3: EPSS in the findings (5.8)

**Files:**
- `sdk/evidence/types.go` (`Match.EPSSPermille *int32`, JSON `epssPermille`; `Match.EPSSDate string`, JSON `epssDate`), the findings schema in `sdk/evidence/schemas/`, `types_test.go`;
- `collectors/vulnerabilities/internal/grype/grype.go` (parse `vulnerability.epss`), `internal/match/targets.go`, their tests and `testdata/grype-output.json`;
- `api/inventory/v1alpha1/imageverdicts_types.go` (`Finding.EPSSPermille`, 0–1000), `internal/rules/sheet.go` and `sheet_test.go`.

- [ ] **Step 1: Write the failing tests.**
  - `TestEPSSBecomesPermille`: the testdata's `0.82641` gives 826 (rounded down), with its date; a match without EPSS gives none; two entries take the one for the match's vulnerability ID.
  - The schema refuses 1001; the sheet carries the value, and `rules.Matches` gives it back.
- [ ] **Step 2: Run** the vulnerabilities module's, the SDK's and `go test ./internal/rules/...`, and see them fail.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Verify** with the gate.
- [ ] **Step 5: Commit:** `feat(vulnerabilities): carry EPSS in per mille`

### Task 4: `describe` on `vulnerabilities` (5.8)

**Files:**
- `collectors/vulnerabilities/internal/describe/` (new: `operation.go`, `parse.go`, `compare.go`, tests, `testdata/`), `internal/grype/grype.go` (a `Search` method), `cmd/main.go` (register the operation);
- `sdk/evidence/` (the type `ch.bedag.vexplain.vulnerabilities.description.v1alpha1` and its schema);
- `docs/collectors.md`.

**Interfaces:**
- **Produces:** the operation `describe`, role `Hub`, with the parameter schema `{vulnerabilityID: string (required), packages: [{name, version, type, purl, distro}] (at most 16)}`. Its one event's data: `{vulnerabilityID, aliases, description, cvss, knownExploited, epssPermille, epssDate, references: [url], providers: [{provider, namespace, fixState, fixedVersions, packages: [{name, fixedForInstalled: Yes|No|Unknown}]}]}`.

- [ ] **Step 1: Capture fixtures.** With the pinned grype (0.121.0), run its `db search` commands for one Debian CVE, one Go module GHSA and one unknown ID against a small database, and keep their JSON in `testdata/`. Record the commands in `parse.go`'s comment.
- [ ] **Step 2: Write the failing tests.**
  - `TestDescribeNamesEveryProvider`: the Debian fixture gives the description, its references, and the Debian provider with its fixed version.
  - `TestTheInstalledVersionIsComparedByTheDistributionsRules`: `libbrotli1` `1.0.9-2+deb11u1` against a fix in `1.0.9-2+deb11u1` gives `Yes`; `1.0.9-2` gives `No`; a provider for another distribution gives `Unknown` for the package.
  - `TestAnAliasFindsTheVulnerability`: the GHSA ID finds its CVE.
  - `TestAnUnknownIDIsAFailureNotAnEmptyAnswer`: a `Failure` with the reason `NotFound`.
  - `TestDescribeNeedsNoNetwork`: it runs with egress refused.
- [ ] **Step 3: Run** `cd collectors/vulnerabilities && go test ./...`, and see them fail.
- [ ] **Step 4: Implement** with `Grype.Search` and grype's version comparison for each package's format.
- [ ] **Step 5: Verify** with the gate and `make test-e2e`, where the e2e calls `describe` through the collector client.
- [ ] **Step 6: Commit:** `feat(vulnerabilities): describe a vulnerability from the database`

### Task 5: `AgentProfile`, the context window and switching the agent off (5.6, 5.11)

**Files:**
- `api/config/v1alpha1/agentprofile_types.go` (new), `modelconfig_types.go` (`contextWindowTokens`), `operatorconfig_types.go` (`spec.agent.state`);
- `internal/agent/prompt/` (new: `prompt.go` with `//go:embed core.md guidance.md`, `CoreVersion = "v1"`, and their token estimates); `internal/agent/profile/` (new: `effective.go` and tests);
- `internal/controller/config/agentprofile_controller.go` (new) and its tests; `internal/setup/setup.go` (the controller, and creating `default` at start);
- `config/samples/config_v1alpha1_agentprofile.yaml`, `config/rbac` (markers), `PROJECT`, `docs/agent.md` (new).

**Interfaces:**
- **Produces:** `configv1alpha1.AgentProfile{Spec: {modelRef, guidance: {type: Embedded|ConfigMap, configMapRef: {name, key}}, limits: AgentLimits, tools: []AgentToolGrant{collector, operations}}}`; `prompt.Core() string`, `prompt.Guidance() string`; `profile.Resolve(ctx context.Context, c client.Reader, name string) (profile.Effective, error)`, where `Effective` holds the limits with defaults, the guidance text, its hash and the ConfigMap's `resourceVersion`, the grants, and the `ModelConfig`.

- [ ] **Step 1: Write the failing tests.**
  - **API:** the defaults and ranges of decision 13; `configMapRef` is required exactly when `type` is `ConfigMap`; a grant needs a `collector`.
  - **Controller:**
    - `TestTheDefaultProfileIsCreatedAtStart`, with the embedded guidance;
    - `TestAProfileWithoutAContextWindowIsNotReady`: `ContextWindowUnknown`;
    - `TestAProfileOverTheWindowIsNotReady`: a window of 50000 with the defaults gives `ExceedsContextWindow`, and `worstCaseContextTokens` is shown; a window of 131072 is `Ready`;
    - `TestAMissingGuidanceConfigMapIsNotReady`: `Ready=False` and the event `AgentProfileInvalid`, with no fallback to the embedded text;
    - a `ConfigMap` outside the operator's namespace is refused.
  - **`OperatorConfig`:** `spec.agent.state` defaults to `Enabled`.
- [ ] **Step 2: Run** `go test ./internal/controller/config/...`, and see them fail.
- [ ] **Step 3: Implement.** `core.md` holds the role, the tool contract, the submit schemas, the evidence rules and the lopsided "not affected" rule (main design 6.6.1). `guidance.md` is short: where to look first, and how to write the summary. The controller watches `ModelConfig`s and `ConfigMap`s.
- [ ] **Step 4: Verify** with the gate and `make test-e2e`, where `default` is `Ready=False` with `ContextWindowUnknown` until the e2e's `ModelConfig` states a window.
- [ ] **Step 5: Commit:** `feat(api): add AgentProfile, the context window and the agent's switch`

### Task 6: The playbook's agent section and the case CEL (5.2, 5.3)

**Files:**
- `api/config/v1alpha1/playbook_types.go` (`PlaybookAgent{profileRef, evidence, matchConditions}`), `common_types.go` (`MatchCondition{name, expression}`);
- `internal/rules/engine/conditions.go` (new) and `conditions_test.go`;
- `internal/controller/hub/playbook_controller.go` (readiness), `config/playbooks/container-cves.yaml`, `config/samples/config_v1alpha1_playbook.yaml`;
- tests: `internal/controller/config/playbook_api_test.go`, `internal/controller/hub/playbook_controller_test.go`.

**Interfaces:**
- **Produces:** `engine.Condition{Name, Expression string}`; `engine.CompileConditions(conds []Condition) (*Conditions, error)`; `(*Conditions).Match(c engine.Case) (ok bool, failed string, err error)`; `engine.Case{Finding, Subject, Impact map[string]any}`.

- [ ] **Step 1: Write the failing tests.**
  - **API:** `agent.evidence` must name entries of `spec.evidence` (CEL on the spec); `matchConditions` is a map by `name`, at most 16, each expression at most 4096 characters.
  - **Engine:**
    - `TestTheShippedExampleSelectsEmergencyMitigation`: `(finding.knownExploited || finding.epssPermille >= 100) && impact.highestExposure == "Open" && finding.fixState != "Fixed"` selects a known-exploited, open, unfixed case, and not a fixed one;
    - `TestEvidenceIsNotAVariable`: an expression naming `sbom` doesn't compile;
    - `TestAFailingExpressionDoesNotSelect`: `finding.epssPermille >= 100` on a finding without EPSS gives `ok=false` with the condition's name and the error;
    - the refused functions and the cost limit hold, as for rules.
  - **Playbook controller:** a playbook whose conditions don't compile is `Ready=False`, reason `Invalid`, with the condition's name.
- [ ] **Step 2: Run** `go test ./internal/rules/... ./internal/controller/...`, and see them fail.
- [ ] **Step 3: Implement.** The shipped `container-cves` playbook gets `agent: {profileRef: {name: default}, evidence: [contents, sbom], matchConditions: [{name: unsettled, expression: 'finding.status == "UnderInvestigation"'}]}`.
- [ ] **Step 4: Verify** with the gate.
- [ ] **Step 5: Commit:** `feat(api): add the playbook's agent section and the case CEL`

### Task 7: `Investigation` and `Assessment`: cases, impact and status (5.3, 5.4)

**Files:**
- `api/triage/v1alpha1/investigation_types.go` and `assessment_types.go` (new);
- `internal/agent/cases/` (new: `select.go`, `impact.go`, `order.go`, `hash.go`, `names.go` and tests);
- `internal/controller/hub/investigation.go` (new) and tests; `internal/setup/setup.go`;
- `config/rbac`: `triage_investigation_editor_role.yaml` and `_viewer_role.yaml`, not aggregated into `edit` and `admin`; `config/samples/triage_v1alpha1_investigation.yaml`;
- tests: `internal/controller/triage/{investigation,assessment}_api_test.go`, `test/e2e/e2e_test.go`.

**Interfaces:**
- **Consumes:** `engine.CompileConditions` (Task 6); `inventory.Store`, `inventory.VerdictsStore`; `urgency.Decide`.
- **Produces:**
  - `cases.Case{ManifestDigest, VulnerabilityID string; Findings []inventoryv1alpha1.Finding; Subject Subject; Impact Impact}`; `cases.Impact{Clusters, Namespaces, Resources, UrgentResources int32; HighestExposure; HighestUrgency; Owners []NamespaceOwners}`;
  - `cases.Select(ctx, sheets inventory.VerdictsStore, inv inventory.Store, sel Selection) ([]Case, []Skipped, error)`, where `Selection` holds the playbook, the vulnerabilities, both condition sets and the urgency overrides;
  - `cases.Less(a, b Case) bool` (the tiers); `cases.Name(vulnerabilityID, manifestDigest string) string`; `cases.Labels(...)`; `cases.InputHash(findings, evidence) string`;
  - the `cases.Queue` interface that Task 11 implements: `Add(c cases.Case, r cases.Request)` and `Pending(investigation types.NamespacedName) (queued, inProgress int)`, where `cases.Request{Investigation types.NamespacedName; Playbook string; Once bool}`.

- [ ] **Step 1: Write the failing API tests.**
  - **`Investigation`:** `maxCases` is required, 1–1000; `vulnerabilities` at most 100; `trigger.schedule` is required exactly when `type` is `Schedule`, and must parse as five fields; `state` defaults to `Enabled`.
  - **`Assessment`:** the spec is immutable (`self == oldSelf`); `subject` is a union by `type`, with `ContainerImage` now.
- [ ] **Step 2: Write the failing case tests.**
  - `TestAnAliasSelectsTheCase` (Review Focus 1): a finding with ID `GHSA-xxxx` and the alias `CVE-2026-0001`, and `vulnerabilities: [CVE-2026-0001]`, give one case, whose `VulnerabilityID` is `GHSA-xxxx`.
  - `TestOneCaseCoversEveryPackageOfItsVulnerability`: one CVE in two packages of one manifest is one case with two findings.
  - `TestBothConditionSetsMustHold`: the playbook's and the investigation's.
  - `TestAConditionThatFailsSkipsOnlyItsCase`: the case shows as skipped with the condition's name; the others are selected.
  - `TestTheOrderIsByTiers`: `Immediate` before `OutOfCycle`; within a tier, known exploited first, then higher EPSS, then more resources.
  - `TestImpactCountsTheUrgentResources`: a namespace with 2 `Open` and 1 `Small` workloads of a known-exploited CVE gives `urgentResources` from `urgency.Decide` for each level.
  - `TestTheNameIsStableAndValid`: `RHSA-2026:1234` gives a valid name and label, and two IDs that differ only in such a character differ in the hash.
  - `TestTheInputHashIgnoresEPSSAndTheDatabase`: changing EPSS, CVSS, KEV or the database version keeps the hash; another package version changes it.
- [ ] **Step 3: Write the failing controller tests** (envtest, with a fake queue):
  - `TestAnInvestigationShowsImpactWithoutTheAgent`: with the agent switched off, `impact`, `cases.total`, `summary` and the first 20 `results` come from the sheets, with owners of the first 5 namespaces, and the condition `Stalled` with `AgentDisabled`.
  - `TestTheCapLeavesTheRestSkipped`: 3 cases and `maxCases: 2` queue the 2 most urgent, `skip` counts 1 with the reason "over the cap", and `Ready` has the reason `CapReached` and an event.
  - `TestAFreshAssessmentIsReused`: an `Assessment` with the current `inputHash` and a verdict counts as `reused`, and isn't queued.
  - `TestAPlaybookWithoutAgentIsNotAllowed`: `Stalled`, `AgentNotAllowed`.
  - `TestAnAssessmentIsCreatedOncePerCase`: two investigations that select one case create one `Assessment`, with both playbooks.
  - `TestTheResultsAreAtMost20`: 25 cases give 20 results and `omitted: 5`.
  - `TestAnInvestigationThatCantRunIsStalled`: an unknown playbook gives `PlaybookNotFound`, and an expression that doesn't compile gives `InvalidCondition` with its name.
- [ ] **Step 4: Run** `go test ./internal/agent/... ./internal/controller/...`, and see them fail.
- [ ] **Step 5: Implement.** The controller lists the playbook's sheets through `VerdictsStore.Each`, reads impact through `ManifestReferences` and `Get`, and watches `ImageVerdicts`, `Assessment`s and the `OperatorConfig`, debounced to one reconcile per 30 seconds per investigation.
- [ ] **Step 6: Verify** with the gate and `make test-e2e`, where an investigation for the e2e image's known-exploited CVE shows its impact with the agent switched off.
- [ ] **Step 7: Commit:** `feat(triage): add Investigation and Assessment, with cases and impact`

### Task 8: Triggers, state and the age of a verdict (5.3)

**Files:**
- `internal/schedule/` (new, from `internal/controller/config/collector_schedules.go`'s parser), and that file;
- `internal/controller/hub/investigation.go` and tests.

- [ ] **Step 1: Write the failing tests,** with a fake clock:
  - `TestOnceRunsAgainOnlyWhenTheSpecChanges`;
  - `TestAScheduleSkipsATickWhileARunIsGoing`: the event `TickSkipped`, and `lastScheduleTime` unchanged;
  - `TestContinuousQueuesANewlyMatchingCase`: a sheet that gains a matching finding queues its case; the cap counts every case judged since creation;
  - `TestADisabledInvestigationQueuesNothingAndKeepsItsStatusCurrent`;
  - `TestAVerdictOlderThanTheMaxAgeIsJudgedAgain`;
  - `TestRunStartedAndRunFinishedAreEvents`, with `startTime` and `completionTime`.
- [ ] **Step 2: Run,** and see them fail.
- [ ] **Step 3: Implement.** The collector's schedules use `schedule.Parse` too.
- [ ] **Step 4: Verify** with the gate.
- [ ] **Step 5: Commit:** `feat(triage): run investigations once, on a schedule or continuously`

### Task 9: The case file, the ledger and vexplain's MCP server (5.4, 5.5, 5.7)

**Files:**
- `go.mod` (the MCP Go SDK);
- `api/inventory/v1alpha1/ledger_types.go` (new), `internal/inventory/ledger.go` (new: `LedgerStore` and its CRD implementation);
- `internal/agent/casefile/`, `internal/agent/verdict/`, `internal/agent/ledger/` (new), `internal/agent/core/` (new: `server.go`, `session.go`, `evidence_tools.go`, `search_tools.go`, `submit.go` and tests);
- `sdk/evidence/` (the tool-output type and schema).

**Interfaces:**
- **Consumes:** `cases.Case` (Task 7); `evidence.Store`; `profile.Effective` (Task 5).
- **Produces:**
  - `casefile.Build(c cases.Case, evidence map[string][]json.RawMessage, maxBytes int) (CaseFile, error)`: the finding with its packages and aliases, the subject, where it runs (clusters, namespace names, workloads by exposure, no owner values), the rules' status and reason, and the evidence names it can search. Over `maxBytes`, the evidence names stay and the summary is cut, never silently: the case file says what was cut.
  - `verdict.Verdict{Status, Justification, Step, Summary string…; Claims []verdict.Claim}`, `verdict.Claim{Text string; Evidence []string}`, `verdict.NoVerdict{Reason, Why, Established, WouldSettle string}`, `verdict.Problem{Check, Message string}`, in the leaf package `internal/agent/verdict`;
  - `core.Validator` interface: `Validate(v verdict.Verdict, l *ledger.Ledger) []verdict.Problem`;
  - `core.NewSession(deps core.Deps, c cases.Case, file casefile.CaseFile, p profile.Effective) *core.Session`; `(*Session).Server() *mcp.Server`; `(*Session).Outcome() core.Outcome` (the verdict or no verdict, and the ledger);
  - `ledger.Ledger` with `Add(tool string, args json.RawMessage, out []byte, trust Trust, d time.Duration) Entry` and `Entry(id string) (Entry, bool)`;
  - `inventory.LedgerStore{Put(ctx, l *inventoryv1alpha1.Ledger) error; Get(ctx, name string) (*inventoryv1alpha1.Ledger, error); Delete(ctx, name string) error}`.

- [ ] **Step 1: Write the failing tests,** each through a client session over the in-memory transport:
  - `TestTheSessionListsOnlyTheCoreTools`: the five core tools, and nothing else until a search.
  - `TestSearchEvidenceFindsLinesOfTheNamedEvidence`: `search_evidence(sbom, libbrotli)` returns the matching `path = value` lines, at most 200, and an unknown name is a tool error.
  - `TestEveryCallGoesIntoTheLedgerWhole`: a result of 100 KiB is stored whole as evidence; the model gets the first `4 × toolResultMaxTokens` bytes, cut on a line, with `ev-1` and how to read on.
  - `TestReadEvidencePagesThroughAnEntry`.
  - `TestTheCaseFileCarriesNoOwnerValues`: owner labels and annotations from impact don't appear in the case file's JSON.
  - `TestTheLedgerIsWrittenOnceAtTheEnd`, with outputs' references and previews, and no arguments over 4096 characters.
  - `TestSubmitNoVerdictNeedsItsThreeParts`: why, what was established (citing IDs), what would settle it.
- [ ] **Step 2: Run** `go test ./internal/agent/... ./internal/inventory/...`, and see them fail.
- [ ] **Step 3: Implement.** `submit_verdict` hands the verdict to `core.Validator`, which Task 10 implements; until then a test double. `core` never imports `validator`, so the two don't cycle.
- [ ] **Step 4: Verify** with the gate.
- [ ] **Step 5: Commit:** `feat(agent): add the case file, the ledger and vexplain's MCP server`

### Task 10: The validator, and collector operations as tools (5.5, 5.7)

**Files:**
- `internal/agent/validator/` (new: `validator.go`, `table.go` and tests);
- `internal/agent/core/` (`collector_tools.go`: search, forwarding, trust), `internal/agent/core/submit.go`;
- `docs/agent.md` (the table).

**Interfaces:**
- **Consumes:** `collectorclient.Pool.Invoke`; the profile's grants (Task 5); the ledger (Task 9).
- **Produces:** `validator.New(c validator.Case) core.Validator`, where `validator.Case` holds the case's packages, their distribution or ecosystem, and `agentHolds`; it returns `verdict.Problem`s.

- [ ] **Step 1: Write the failing validator tests,** one per row of decision 8:
  - `TestAClaimMustCiteAnEntryThatExists`;
  - `TestNotAffectedNeedsDescribeToSayFixedForEveryPackage`: two packages, `describe` says `Yes` for one: rejected;
  - `TestNotAffectedTakesOnlyVulnerableCodeNotPresent`;
  - `TestAFetchedPageNeverSupportsNotAffected`: the same verdict citing only a fetched page is rejected;
  - `TestAHoldAgainstAllRejectsNotAffectedAndFixed`, and lets `Affected` through;
  - `TestOneRepair`: the first rejection comes back as the tool's result with the problems; a second ends the case with "no verdict", reason `ValidatorRejected`, and the event `VerdictRejected`.
- [ ] **Step 2: Write the failing tool tests:**
  - `TestSearchToolsFindsAGrantedHubOperation`: `vulnerabilities__describe` is found, with its parameter schema; `scanner__scan` isn't, since it is a spoke operation;
  - `TestAnOperationOutsideTheGrantIsRefused`;
  - `TestAToolCallIsForwardedAndItsTrustRecorded`: a fake `Invoke` answers; the ledger entry has the trust `Known` for a declared type;
  - `TestAToolThatTimesOutEndsAsAToolError`, after `toolTimeoutSeconds`;
  - at most 8 tools load in one case.
- [ ] **Step 3: Run,** and see them fail.
- [ ] **Step 4: Implement.**
- [ ] **Step 5: Verify** with the gate.
- [ ] **Step 6: Commit:** `feat(agent): validate verdicts and forward collector operations`

### Task 11: The runner and the queue: the agent judges (5.4, 5.6, 5.11)

**Files:**
- `internal/agent/runner/` (new: `builtin.go`, `context.go` and tests), `internal/agent/queue/` (new: `queue.go`, `workers.go` and tests);
- `internal/controller/hub/assessment.go` (new: writes the outcome, the status and the events), `internal/setup/setup.go`;
- `internal/metrics/metrics.go`: `vexplain_agent_cases_total{cluster, outcome}`, `vexplain_agent_no_verdicts_total{cluster, reason}`, `vexplain_agent_rejections_total{cluster, check}`, `vexplain_agent_tokens_total{cluster, kind}`, `vexplain_agent_case_duration_seconds{cluster}`, `vexplain_investigation_cases{cluster, namespace, investigation, state}`;
- `docs/measurements/2026-phase1.md` (the smoke test's result), `docs/agent.md`.

**Interfaces:**
- **Consumes:** `llm.Client.Complete`; `core.Session` (Tasks 9, 10); `cases.Less` and the `Queue` interface (Task 7).
- **Produces:** `runner.Builtin{Client *llm.Client}` with `Run(ctx context.Context, s *mcp.ClientSession, in runner.Input) runner.Result`, where `Input` holds the prompt, the case file and the limits, and `Result` the usage, steps, the peak context in tokens and which limit tripped; `queue.New(workers func() int, judge Judge) *Queue`, a manager runnable.

- [ ] **Step 0: The model's smoke test, with the owner.** The owner runs `go run ./cmd/llm-smoke --endpoint … --model …` with `VEXPLAIN_LLM_API_KEY` in their shell, and gives the result line and the model's context window. At least 18 of 20 is the go; record it in `docs/measurements/2026-phase1.md`, without the endpoint's or the model's name. Below that, stop and decide with the owner.
- [ ] **Step 1: Write the failing runner tests,** against a scripted endpoint (as `cmd/llm-smoke`'s fixtures do):
  - `TestTheRunnerStartsWithTheCoreToolsAndLoadsFoundOnes`: after a `search_tools` result, the next request lists the found tool;
  - `TestAToolResultOverTheCapIsCutForTheModel` (Review Focus 3): every request stays under the profile's `worstCaseContextTokens`;
  - `TestAtTheStepLimitOneFinalCallWithoutTools`: the summary goes to `submit_no_verdict`, with reason `MaxSteps`;
  - `TestWhenTheFinalCallFailsTheLimitIsRecorded`;
  - `TestTheTokenBudgetAndTheTimeoutAreLimitsToo`: `MaxTokens`, `Timeout`;
  - `TestMalformedArgumentsGetAToolErrorAndEmptyArgumentsInTheHistory` (main design 6.6).
- [ ] **Step 2: Write the failing queue tests:**
  - `TestTheQueueServesTiersThenOnceFirst`;
  - `TestOneCaseThatTwoInvestigationsWantIsJudgedOnce`;
  - `TestTheWorkersAreTheModelsConcurrentRequests`;
  - `TestSwitchingTheAgentOffReturnsCasesInProgressWithNothingWritten`, with the event `AgentDisabled` on the `OperatorConfig`;
  - `TestARestartQueuesThePendingCasesAgain` (Review Focus 4): a manager stopped mid-case leaves the `Assessment` without a verdict and without a ledger; after the start its investigation queues it again, and it is judged once.
- [ ] **Step 3: Run** `go test ./internal/agent/... ./internal/controller/hub/...`, and see them fail.
- [ ] **Step 4: Implement.** The assessment writer sets the `Assessment`'s status (verdict or no verdict, validation, `inputHash`, `ledgerRef`, runner, model, usage, `judgedTime`), writes the ledger, and emits `NoVerdict` or `VerdictRejected`.
- [ ] **Step 5: Verify** with the gate and `make test-e2e`, where a scripted model in the e2e cluster judges the e2e image's case to `Affected`, and a second case ends with "no verdict" at the step limit.
- [ ] **Step 6: Commit:** `feat(agent): judge cases with our own runner`

### Task 12: Verdicts into the sheets, statements and review (5.4, 5.10)

**Files:**
- `api/triage/v1alpha1/vexstatement_types.go` (new), `api/inventory/v1alpha1/imageverdicts_types.go` (`Finding.Agent`), `api/triage/v1alpha1/resourcereport_types.go` (`agentProposed`);
- `internal/controller/hub/assessment.go` (statements, staleness), `assessor.go` (the merge), `janitor.go` (clean-up), `internal/rules/sheet.go`;
- `internal/spoke/render.go`;
- `internal/metrics/metrics.go`: `vexplain_vex_statements{cluster, review}`;
- `config/rbac`: `triage_vexstatement_reviewer_role.yaml`, which may update `VexStatement`s;
- tests: `internal/controller/triage/vexstatement_api_test.go`, `internal/controller/hub/{assessment,assessor}_test.go`, `internal/spoke/render_test.go`, `test/e2e/e2e_test.go`.

**Interfaces:**
- **Consumes:** the `Assessment`s of Task 11; `cases.InputHash`.
- **Produces:** `triagev1alpha1.VexStatement`; the sheet's `Finding.Agent{Assessment string; Status VEXStatus; Justification *VEXJustification; Review *ReviewState}`.

- [ ] **Step 1: Write the failing tests.**
  - **API:** a `VexStatement`'s spec is immutable except `review`; `review.state` defaults to `Proposed`.
  - **Hub:**
    - `TestAnAgentNotAffectedBecomesAProposedStatement`, with the event `VerdictProposed`;
    - `TestAnAgentAffectedAppliesDirectly`: the sheet's finding turns `Affected` and names the agent;
    - `TestAProposedStatementChangesNothingButTheAgentField`;
    - `TestAnAcceptedStatementSettlesTheFinding`, with the reason `accepted VEX statement <name>`;
    - `TestAStatementGoesStaleWithItsInputs` (Review Focus 5): a new package version marks the `Assessment` `Stale` and the statement `Superseded`; the finding reopens; the next investigation that selects the case judges it again;
    - `TestARejectedStatementLeavesTheFindingOpen`;
    - `TestAnAssessmentAndItsLedgerGoWithTheirSheets`: when the Janitor deletes a manifest's last sheet, its `Assessment`s, `Ledger`s and tool outputs go too, and its `VexStatement`s stay.
  - **Spoke:** `TestAnActionCountsItsUnreviewedAgentVerdicts`: `agentProposed`.
- [ ] **Step 2: Run,** and see them fail.
- [ ] **Step 3: Implement.** The Assessor reads the manifest's `Assessment`s and `VexStatement`s by the digest label when it writes a sheet, and is woken when they change.
- [ ] **Step 4: Verify** with the gate and `make test-e2e`, where a scripted "fixed" verdict becomes a proposed statement, a reviewer accepts it, and the report drops the action.
- [ ] **Step 5: Commit:** `feat(triage): add VexStatement, and bring verdicts into sheets and reports`

### Task 13: The replay harness (5.6, 8)

**Files:** `cmd/agent-replay/` (new: `main.go`, `export.go`, `replay.go` and tests), `docs/agent.md`.

**Interfaces:**
- **Produces:**
  - `agent-replay export --assessment NAME --out DIR`: reads the `Assessment`, its `Ledger` and their outputs through the user's kubeconfig, and writes the case file and the recorded outputs.
  - `agent-replay run --cases DIR --endpoint … --model …`, with `VEXPLAIN_LLM_API_KEY`: judges each saved case with the runner and a core whose tools answer from the recordings (the same tool and arguments; anything else is a tool error, "not recorded"), and prints per case the steps, tokens, peak context, outcome and validator rejections.

- [ ] **Step 1: Write the failing tests:** an exported case replays against a scripted endpoint to the same outcome; an unrecorded call is a tool error; the output never names the endpoint or prints the key.
- [ ] **Step 2: Run,** and see them fail.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Verify** with the gate. The replay against the owner's model, on cases from the kind cluster and the owner's saved cases, is part of Task 17's preparation.
- [ ] **Step 5: Commit:** `feat(agent): add the replay harness`

### Task 14: The `advisories` collector and `fetch` (5.8)

**Files:**
- `collectors/advisories/` (new module: `cmd/main.go`, `internal/fetch/` with `fetch.go`, `text.go` and tests, `Dockerfile`), `go.work`;
- `sdk/evidence/` (the page type and its schema);
- `config/collectors/advisories.yaml`, its runtime config in `config/collectors/runtimeconfigs.yaml`, `config/collectors/kustomization.yaml`;
- `docs/collectors.md`, `Makefile` (its image).

**Interfaces:**
- **Produces:** the operation `fetch`, role `Hub`, with the parameter schema `{url: string}`; its event's data `{url, finalURL, contentType, text, truncated}`.

- [ ] **Step 1: Write the failing tests,** against `httptest` TLS servers:
  - `TestOnlyHTTPSToAnAllowedHost`: `http://`, an unlisted host, an IP address and a userinfo URL are refused before a connection;
  - `TestEveryRedirectHopIsChecked`: a redirect from an allowed host to an unlisted one is refused;
  - `TestThePageIsCappedAndTimed`: over `maxBytes` the text is cut and `truncated` is true; past the timeout, a failure;
  - `TestHTMLBecomesText`: scripts and styles are dropped, links keep their text.
- [ ] **Step 2: Run** `cd collectors/advisories && go test ./...`, and see them fail.
- [ ] **Step 3: Implement,** through the proxy that its runtime config sets (0037).
- [ ] **Step 4: Verify** with the gate and `make test-e2e`, where `advisories` is installed and refuses a host that isn't on its list.
- [ ] **Step 5: Commit:** `feat(advisories): fetch pages from allowlisted hosts`

### Task 15: The fetch takes only trusted URLs (5.8)

**Files:** `internal/agent/core/collector_tools.go` and `fetch_test.go`; `internal/metrics/metrics.go` (`vexplain_agent_tool_refusals_total{cluster, tool, reason}`).

- [ ] **Step 1: Write the failing tests** (Review Focus 2):
  - `TestAFetchTakesAURLFromDescribe`: a reference that `describe` returned in this case is forwarded;
  - `TestAFetchRefusesAURLTheModelWrote`, `…AURLFromAFetchedPage` and `…AURLFromAnMCPCollector`: refused before any request, recorded in the ledger as refused, and counted;
  - a URL from another case's `describe` is refused;
  - a fetched page's entry has the trust `External`.
- [ ] **Step 2: Run,** and see them fail.
- [ ] **Step 3: Implement.** The session keeps the URLs of trusted results, compared after normalizing scheme and host case and dropping the fragment.
- [ ] **Step 4: Verify** with the gate.
- [ ] **Step 5: Commit:** `feat(agent): fetch only what a trusted result linked to`

### Task 16: MCP collectors (5.9)

**Files:**
- `api/config/v1alpha1/collector_types.go` (`spec.mcp`, the union with `package`);
- `internal/collectorclient/mcp.go` (new), `internal/controller/config/collector_controller.go`, `internal/agent/core/collector_tools.go`;
- `test/e2e/images/mcp-stand-in/` (new: a small server on the Go SDK with the tools `search`, `get_page` and `delete_page`), `test/e2e/e2e_test.go`;
- `config/samples/config_v1alpha1_collector_mcp.yaml`, `docs/collectors.md`.

**Interfaces:**
- **Produces:** `collectorclient.MCPPool` with `Tools(ctx, collector string) ([]mcp.Tool, error)` and `Call(ctx, collector, tool string, args json.RawMessage) (string, error)`; headers from the labelled Secrets, never logged.

- [ ] **Step 1: Write the failing tests.**
  - **API:** exactly one of `package` and `mcp`; `mcp.tools` is required, 1 to 64; `url` is https.
  - **Controller:** a server that lists every allowed tool is `Ready`; one that lacks one is `Ready=False`, `ToolsMissing`; a Secret without the label isn't read.
  - **Core:**
    - `TestAToolOffTheCollectorsListIsNeverCalled`: `delete_page` is neither found nor called, whatever the profile says;
    - `TestAnMCPToolsOutputIsExternal`;
    - `TestTheHeadersNeverReachTheLedgerOrTheLog`.
- [ ] **Step 2: Run,** and see them fail.
- [ ] **Step 3: Implement** over MCP's Streamable HTTP client transport.
- [ ] **Step 4: Verify** with the gate and `make test-e2e`, where the stand-in serves the agent's `search`, and `delete_page` stays unreachable.
- [ ] **Step 5: Commit:** `feat(collectors): add MCP collectors`

### Task 17: The live run, with the owner (design 6, item 7)

This task isn't for an agent. Before it:
- the replay harness runs the owner's saved cases against the owner's model, and the defaults of decision 13 are checked against the peak context and the tokens per case;
- the owner picks an existing MCP server, and writes its `Collector` and the guidance that says where company knowledge lives.

The owner installs the branch's images on the shared cluster, with the cluster settings of phase 3a's fixes, section 3, and checks:
- **the settings of phase 3a's fixes, section 3,** each with its check, and section 4's list;
- **an investigation for a CVE the SOC cares about:** its impact, where to start, whom to contact, and the agent's verdicts and summaries;
- **design section 8's list:** tokens and steps per case, the peak context, latency, the no-verdict rate and reasons, validator rejections by check, the guards' rejections (`holdAgainst: All`) and whether a reviewer agrees, fetches and refusals, the MCP server's results against the caps, and the size and write rate of ledgers and evidence in etcd;
- **reviews:** the owner accepts or rejects the proposed statements.

The findings stay in the owner's private notes. Only what changes the next phase goes into "Carried forward", in neutral words.

### Task 18: The SOC's view (design 5.12, 6, item 8)

The action metric (main design 6.10), with its series count measured first, and the dashboards: the plan, the agent's output and the open cases. They are designed from Task 17's data, as an addendum to this plan that the owner approves before it is built.

## As built

Where the build differs from the text above, the build is right. Each difference was decided and reviewed while the plan ran, or in the review of the whole branch and its fix wave. The design has amendment notes, dated 2026-11-17, where the build changed it: in 5.3, 5.4, 5.5, 5.8 and 5.9.

### Namespaces in presence (Task 1)

- **Owner values are cut, and their keys checked,** as triage's owner attribution does, so a long annotation can't fail the whole write of an image's inventory.

### Guards against the agent (Task 2)

- **A step that can't run records itself in `agentHolds`** when it holds a finding: a rule that is missing or isn't `Ready`. Whom it would hold against is unknown, so it holds against the agent too.

### EPSS (Task 3)

- **The per mille is EPSS × 1000, rounded down.** An EPSS entry counts only for its own vulnerability ID; otherwise the finding has none.

### `describe` (Task 4)

- **Every namespace of a provider that speaks for the package's release is judged together, and `No` wins,** rather than Grype's fallback from a release to its major version.
- **A Debian version without an epoch has epoch 0,** as dpkg reads it.
- **A range without a constraint** holds every version when it names no fix, or when no range of its row has a constraint. A row that mixes such a range naming a fix with constrained ranges is `Unknown` (fix wave and the finishing review).
- **Each provider's answer rests on its records of one vulnerability ID, and names it** (Task 10's review). Records of the IDs that a record names are found too, but never pooled into another ID's answer.
- **`describe` runs inside the collector's matcher,** under its database's lock, and its answer echoes each package as it was asked: name, version, type, distribution and purl. The validator compares them with the case's.
- **The fixtures are real rows of Grype's database,** such as a fix in Debian 12.
- **Both searches run with `--limit 0`** (first live case). Grype's default of 5000 rows makes it fail for a vulnerability that more rows list, and a row that a limit dropped could hide a `No`. No filter narrows the search either.
- **Go's standard library is accepted as Syft writes it** (first live case): the purl reads as `go-module` `stdlib`, and the asked version is `go` plus the purl's version. It is kept as asked, which Grype compares without the `go`. Every other package stays as strict as before.

### Profiles and the switch (Task 5)

- **`profile.Resolve` takes the operator's namespace,** for the guidance's ConfigMap. A profile has two more reasons for `Ready=False`: `GuidanceMissing` and `ModelConfigMissing`.
- **A profile's `Ready` doesn't depend on its `ModelConfig`'s.** The agent checks the `ModelConfig` before each case, and the case waits while it isn't `Ready`.
- **The default profile grants `vulnerabilities`' `describe`** (Task 10) **and `advisories`' `fetch`** (Task 14). Without `describe`, the agent could never reach `Fixed` or `NotAffected`.

### The case CEL (Tasks 6 and 7)

- **`finding.fixState` keeps the source's spellings,** such as `fixed` and `not-fixed`, and the shipped example tests EPSS with `has()`.
- **The finding is built from the sheet without the rules' exactness check,** so a finding with more scores or fixed versions than a sheet shows is still selected: conditions only select.
- **`finding.status` is the rules' own status** (Task 12), which `agent.ruleStatus` keeps where a verdict changed it. `finding.rule` and `finding.justification` are the sheet's, after the verdict.
- **Two findings of one image whose IDs alias each other are two cases.** A canonical case ID can come later.

### `Investigation` (Tasks 7 and 8, and the fix wave)

- **`Ready` is `True` with the reason `Judged`** once every selected case is judged, reused or skipped.
- **The cap counts hand-offs.** `status.cases.charged` counts each case that the investigation handed to the queue in the run, and in the life of a `Continuous` investigation. A run's start sets it to 0. A case that another investigation queued first isn't charged here; a stale case judged again is charged again, and so is a withdrawn case selected later. `judged`, `queued` and `inProgress` only report. A reconcile that fails after the queue took cases keeps their charges.
- **`judged` counts the cases whose outcome was recorded at or after the run's start, whoever queued them, and `reused` the fresh ones recorded before.**
- **A held case,** one whose `Assessment` is `Queued` or `Judging`, is handed to the queue again at each reconcile while the run is open, whatever the room and the agent's switch: the queue takes its newest findings, and takes it again after a restart. An investigation stalled because the agent is off keeps its cases; other stalls drop them.
- **A skipped tick runs once the running run ends,** as a CronJob under `Forbid` catches up the latest missed schedule.
- **A result keeps the sheet's status, step and result,** and shows the agent's fresh verdict in `verdict` and its statement's review in `review` beside them (fix wave).
- **A condition that fails on a case** skips it, and `Ready`'s message says how many cases it skipped, and names the first error (fix wave).
- **Every investigation is reconciled again within 5 minutes,** so that its impact follows the inventory (fix wave).

### The case file, the ledger and the server (Task 9)

- **A tool listing is never evidence:** `search_tools`' results are recorded of external trust.
- **The tools that a case loads take at most 16000 bytes of definitions,** and `submit_no_verdict`'s fields have maximum lengths, so that together they fit the summary of 2048 characters.
- **The outputs of the tool calls are stored with their ledger entry as their source,** such as `ev-3`, so a `Collector` can't be named like one (Task 16).

### The validator and the tools (Task 10)

- **A Yes counts only for the package as the case has it:** its name, version, type and distribution, and the SBOM's purl exactly, in records of the case's vulnerability or one of its aliases.
- **Every package needs a Yes from some provider, and a No from none.** A No in the shape of `describe`'s answer always counts: cited or not, of any trust, in records of any vulnerability, with or without the purl, and in an output of several answers.
- **The core prompt says so.** It is in its version `v3`: `v2` added the aliases and the purl, and `v3` the distribution (fix wave).
- **Core `v4` adds an "Affected" section** (first live case). `affected` needs a `fixedForInstalled: No` of `describe` for a package of the case, or a finding whose fixed version is above the installed one, and a failed tool doesn't stop an `affected` that other evidence shows. `describe`'s description names the ecosystem's own IDs, such as GHSA and GO, as aliases to describe.

### The runner and the queue (Task 11)

- **Each step asks for at most 4096 tokens,** and the runner makes at most 8 tool calls of one answer. The fit check counts both.
- **`maxTokens` holds strictly:** the next step isn't made when the tokens so far, twice the next request's estimate and `reservedTokens` would pass it, so the final call's prompt is inside the budget through the factor of two.
- **`ContextLimit`:** the case ends at a limit when the next request, with room for its answer, the larger of 4096 tokens and `reservedTokens`, would no longer fit `contextWindowTokens`.
- **The queue follows the investigations.** Each reconcile names the cases that it still wants. A waiting case that nobody wants leaves the queue unjudged, and its `Assessment` is `Ready=False`, `Withdrawn`. A case is tried on the newest findings that it was handed, also when they came while it was in progress (fix wave).
- **Before a case starts, its `Assessment` is read past the cache.** One that holds the outcome of its current inputs isn't judged again, and is `Ready` with the reason `Judged` (fix wave).
- **Failures:**
  - A request that fails for the endpoint's sake hands the case back with nothing written, tried again after 10 seconds, doubled for each failure, at most 10 minutes. 401, 403 and 404 hand it back too, since the `ModelConfig`'s probe reports them. Another 4xx ends the case without a verdict, `ModelError`.
  - An attempt that may have spent tokens counts: a request of it completed, or its first request timed out, got a 2xx that isn't a chat completion or broke off, or got a gateway's 504 (fix wave). So does an outcome that the API server refuses to write. The fifth since the case came into the queue ends it without a verdict, `ModelError`; a wait for another reason doesn't start the count again (fix wave).
- **The agent switched off, or the manager stopping,** hands a case in progress back with nothing written, even during the final call.
- **A sweep,** 90 seconds after the start and then every 10 minutes, withdraws every `Queued` or `Judging` `Assessment` that the queue doesn't hold, as after a crash.
- **The case file's playbook falls back** to a playbook of an investigation that selected the case and can serve it, when the recorded one is gone, has no agent section or no sheet of the image. The `Assessment` records it.
- **`cases.Request` carries `JudgedAfter`,** so that an investigation with `verdictMaxAgeSeconds` takes no older outcome.
- **`nextStep` is free text,** not the design's step enum: an investigation's `step` follows the sheet.
- **The sample, the tests and the docs state a neutral context window of 200000 tokens.**

### Verdicts into the sheets (Task 12)

- **A statement per verdict,** named after the `Assessment` and the first 10 hex characters of the SHA-256 of its `inputHash`, status and justification. A superseded statement stays, with its review, and the hub deletes none. This supersedes decision 19's one statement per `Assessment`. The same verdict on the same inputs maps to the earlier statement.
- **`agent.ruleStatus` keeps the rules' status** where the verdict or an accepted statement changed it.
- **A verdict applies to a sheet only while it is fresh against the case file as the same reconcile writes it.** Each sheet's basis holds the set of fresh cases. The case-file playbooks' sheets are assessed first, and again until that set stops changing, so no sheet settles through a statement that the same reconcile supersedes. A case file that can't be read makes its verdict not fresh.

### A sheet that can't be written (Task 12b, and the fix wave)

- **A sheet that settles a finding through an accepted statement, or leaves findings out, is deleted when it can't be written:** when its evidence can't be read or decoded, its rules can't be evaluated, or the API server refuses the write for another reason than a conflict.

### The input hash (fix wave)

- **`inputHash` rests on facts only:** the findings by vulnerability ID and package name, version and type, without the package's ID; of an SBOM, its distribution, its packages by name, version, type and purl, sorted, and the catalogers that failed; of the scanner's image contents, its data without a producer, descriptor or source; of any other type, its whole data. This supersedes decision 16. A rescan, or a scanner release, that finds the same facts keeps the hash.

### Advisories (Tasks 14 and 15)

- **An allowlist entry matches its host exactly, or, with a leading dot, its subdomains,** after IDNA, on port 443 only. A host with an empty label, such as a trailing dot, is refused.
- **A page's text drops control and format characters,** zero-width, bidi, the Tags block and variation selectors among them, so hidden characters can't carry instructions to the model.
- **The fetch takes the trusted reference itself,** never the model's string. URLs compare ignoring the ASCII case of the scheme and the host, and the fragment; a host that differs beyond ASCII case is refused.
- **An operation counts as a fetch by the type of evidence that it produces,** whatever its collector's name. An MCP collector's tools never fetch for vexplain: a server that fetches URLs is its deployer's responsibility, and its output stays of external trust.

### MCP collectors (Task 16)

- **`spec.mcp.tools` is required,** 1 to 64 names, each of 61 characters at most, and `<collector>__<tool>` of 64 at most.
- **The headers come from Secrets labelled `vexplain.bedag.ch/mcp-headers: "true"`.** A value of 8 bytes or more is withheld from every output and error, the longest first, and a redirect never carries the headers.
- **The URL is an https URL with a host,** and `spec.package` became optional, since an MCP collector has none.
- **Each call opens a session of its own.**

### Tests

- **The e2e suite has 46 specs.**
- **No test calls a real model.** The hub's tests and the e2e suite script the model over https.

## Carried forward

### For phase 6

- **Urgency on the hub uses the hub's own table** (decision 4). A fleet whose spokes change the table needs it per cluster.
- **Presence in one image's `ImageInventory` grows with its clusters** (5.14); measure it with the fleet.
- **Every reconcile of an investigation reads and hashes the case files' evidence again.** Measure it before a fleet, and keep the hashes if it costs.

### The cap and the queue

- **A held case can be charged to nobody** in a window around a restart: a crash between `Queue.Add` and the status write, or a run that a spec change restarts in a reconcile that then fails, leaves its cases held and uncharged.
- **Two playbooks whose investigations share a case can have it judged again in turn,** each on its own case file.
- **A transient outage of a case file's evidence marks its `Assessment` stale,** and an investigation may queue it again, within the cap.
- **Statements accumulate,** one per verdict. They are reviews, so a retention rule needs the owner.
- **The queue withdraws in the investigation's reconcile,** one write per case, and the sweep lists the `Assessment`s without pages.

### The agent's failures

- **Other gateway statuses than 504 that may have billed a request,** such as 502, count as spent tokens only when a request of the attempt completed.
- **A verdict that was written, but seen as failed,** can be replaced by a `ModelError` at the fifth failure; the retirement doesn't check the outcome first. A retirement that the API server refuses too is judged again.
- **The retirement's message mixes failures of the model and of the write.**

### The validator and `describe`

- **The validator reads the documents of an output until the first that isn't JSON,** so a `No` after foreign text in the same output is missed. `describe`'s own outputs are single documents; read line by line to close it.
- **Within a case, the references of every vulnerability that the model asks `describe` about become trusted URLs.**
- **`describe` runs two Grype processes per call,** without a bound on concurrent calls.
- **Ubuntu's ESM namespaces never speak for a release's package,** so a system with ESM fixes gets no answer.
- **An RPM without an epoch takes the fix's,** as Grype does, which an epoch bump within a release could fool.

### The input hash

- **The image contents name packages by the SBOM's package IDs.** A scanner release that numbers packages anew changes their hash, and every verdict on them goes stale once.

### MCP collectors

- **`spec.settings` isn't refused on an MCP collector,** where it does nothing.
- **One slow server can hold up the tool search of a case:** give each grant a deadline, or list in parallel.
- **The pool's guards are untested:** the cap of 16 MiB on an answer, the later Secret winning a header, and the refusal of a tool off the list at the pool's level.
- **A value under 8 bytes, or an echo in another form,** isn't withheld; the label on the Secret is the first protection.

### Tests and form

- **Untested:** the 100 ms bound of a case condition; a package without a purl in `describe`; a window that shrinks after a profile is `Ready`.
- **The default number of namespaces is declared twice,** in the store and in the settings.
- **`TickSkipped` is recorded at every reconcile** while a tick is skipped, not once per tick.
