# vexplain — Phase 4's fixes and the agent workers, Implementation Plan

> **For agents:** follow `AGENTS.md`. Implement this plan task by task, test first. A task is done when its tests pass, it is committed and it has been reviewed; only then start the next one. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** fix what phase 4's first live run found, and move the agent into workers of its own:
- `fetch` names why it failed;
- `describe` answers for the asked packages, with their aliases, from the first step;
- the case file names each finding's purl and distribution;
- the summary's first sentence carries the answer;
- the `Investigation` counts its selected cases and its tokens;
- selection skips images that run nowhere;
- a default rule settles cases with a known fix;
- the metrics can be scraped from the install;
- the agent workers of 0057.

Then the deploy session runs the fixes live.

**Architecture:**
- **The collectors:** `advisories` reads its proxy's refusals; `vulnerabilities`' `describe` lists only the entries that answer.
- **The safety core** lists `describe` from the first step, and the case file reads each finding's package in the SBOM.
- **The hub:** selection skips cases whose image runs nowhere, and its queue moves into the `Assessment`s' status.
- **Workers in their own `Deployment`** (`cmd/agent`) claim cases with a lease, and judge them with the code that moves out of the manager.

**Tech Stack:** as in phase 4, with no new dependency.

**Spec:**
- `docs/design/2026-11-20-phase4-live-fixes.md`, with decision record 0057;
- the agent design (`docs/design/2026-11-16-agent-on-cases.md`, revision 2), where it points there;
- phase 4's plan (`docs/plans/2026-11-16-phase4-agent.md`) and its "As built" section, which describe what exists.

**Branch:** `feat/phase4-agent`, which isn't pushed. Phase 4 isn't released, and its branch is squashed before any push.

**Not in this plan:**
- what the agent is asked (`docs/design/2026-11-20-what-the-agent-is-asked.md`, a draft for the owner);
- reports that show the agent's verdict;
- the live run, which the deploy session does on the images this plan builds.

## Decisions made in this plan

The design leaves these to the builder, or the code showed them while planning.

1. **0057's files are committed first,** with the design note and this plan, as the record that the build implements.
2. **The proxy's refusal** is read through `http.Transport.OnProxyConnectResponse`, which returns a typed error that keeps the status. Every other cause is read with `errors.As`:
   - `*net.DNSError`;
   - `*tls.CertificateVerificationError` or `x509` errors;
   - `*net.OpError` with `Op == "proxyconnect"`.
3. **`describe`'s listed entries** come from today's `providersOf`, which already marks the entries that answer (`entry.answers`). Each entry that doesn't answer goes into a count per provider.
4. **The step-one tool** is loaded by `NewSession`, through `Session.load`, after the core tools. `load` already applies the limits and the fetch handling.
5. **The case file's finding** is `caseFinding{Finding (inlined), PURL, Distro}`. The SBOM lookup that `ValidatorCase` does moves into one function that both use.
6. **The queue's label** is the prefix of `cases.Labels` plus `/queued`, set to `"true"` while the status holds a `queue`.
7. **The workers' code** moves from `internal/controller/hub/assessment.go` (`Agent`: `Judge`, `prepare`, `caseFile`, `sbomOf`, `run`, `watchSwitch`, `disabled`, `write`, `setReady`, `handBack`) into `internal/agent/worker`. Its RBAC markers move with it. The manager keeps `Sweep`, `withdraw` and the assessor.
8. **controller-gen runs twice** in `make manifests`:
   - `rbac:roleName=manager-role` over every package but `internal/agent/worker` and `cmd/agent`;
   - `rbac:roleName=agent-role` over those two, into `config/rbac/agent`.

## Decisions for the owner

The owner approved the plan on 2026-11-20, with each of these as recommended.

1. **`fix-available` wins over `removed-in-later-layer`** (design 2.7). A removed package that a fix is known for reads `Affected`, not `NotAffected`.
   - The plan ships the rule as it runs live.
   - The other way is to exclude removed packages, which makes the rule need the image's contents and SBOM.
2. **`describe`'s aliases come from the case's findings,** as a parameter that the safety core fills itself. The owner chose this on 2026-11-20, over Grype's library in the collector (design 2.2).
3. **The monitoring is switched on through kubebuilder's `[PROMETHEUS]` section,** commented out by default, and the e2e suite installs the Prometheus Operator to check it (design 2.8). The owner decided this on 2026-11-20.
4. **The workers' client certificate is a Secret the manager issues.** The workers never hold the authority's key (design 3.5).
5. **2 worker replicas by default** (design 3.6).

## Global Constraints

- **AGENTS.md binds:**
  - design first, test first, kind only;
  - no private data and no figures from real platforms;
  - no AI attribution;
  - comments that state their own reason and never cite a ruling of a ledger.
- **Phase 4 still binds,** as amended by its "As built" section:
  - API conventions and kube-api-linter;
  - RBAC from markers;
  - wiring through `setup.Register`;
  - tests and commits.
- **Before each commit:** `make manifests generate && make proto-check && make lint && make test`.
- **e2e:** one `make test-e2e`, on kind, at the end of each task that changes a CRD, the install, the manager or the workers.
- **No real model calls:** fakes and the scripted model only.
- **No internet in unit tests.** The e2e suite fetches only pinned public releases: base images, and the Prometheus Operator's bundle. Grype fixtures are made with `--network none` from the local image, as `describe/parse.go` shows.
- **The API is `v1alpha1` and unreleased:** fields change without conversion.
- **Names:**
  - the `Investigation`'s `cases.overTheCap`, `cases.notSelected`, `usage.promptTokens` and `usage.completionTokens`;
  - the `Assessment`'s `chargedTo`, `queue` (`playbook`, `requests[]{namespace, name, once}`, `judgedAfter`, `order{urgencyRank, knownExploited, epssPermille, resources}`, `queuedTime`, `failures`, `misses`, `notBefore`) and `claim` (`worker`, `leaseEndTime`);
  - the skip reason "not running";
  - the rule `fix-available`;
  - `describe`'s parameter `aliases` and its answer's `otherProviders[]{provider, entries}`;
  - the case file's `purl` and `distro`;
  - the Secret `vexplain-agent-client-tls`, with the certificate's name `vexplain-agent`;
  - the role `agent-role`;
  - the `Deployment` `vexplain-agent`, labelled `app.kubernetes.io/component: agent`;
  - the lease name `agent.vexplain.bedag.ch`;
  - the image variable `AGENT_IMG ?= agent:latest`, and the `Dockerfile` targets `manager` and `agent`;
  - in `config/prometheus`: `metrics-scraper` (ServiceAccount and ClusterRoleBinding), `metrics-scraper-token`, and the ServiceMonitors `controller-manager`, `agent` and `collectors`.
- **Values:**
  - the Accept header: `text/html, application/json;q=0.9`;
  - `describe`:
    - at most 8 aliases;
    - at most 8 entries listed for each asked package that no entry answers for;
  - core prompt `v5`;
  - the lease: 60 s, renewed every 20 s;
  - the sweep: every 30 s, with 30 s of grace past a lease's end;
  - 2 worker replicas.
- **Unchanged values:**
  - 5 failures that spent tokens end a case;
  - the backoff: 10 s, doubled, at most 10 min;
  - the result reason: at most 256 characters;
  - the janitor's 24 h.
- **Error texts to the model** are fixed words. They never hold an error's own text, a URL of the proxy, or a credential.
- **Commits:** Conventional Commits, no AI attribution, never on `main`, never pushed. Stage paths by name.
- **Repository hygiene:**
  - neutral names, such as `team-a` and `artifacts.example`;
  - no endpoint, model name, cluster name or live figure.

## Review Focus

1. **A manager restart, or an investigation deleted, while a worker judges:**
   - the worker finishes and writes its outcome;
   - the sweep never touches a case whose lease is live (Tasks 6, 8).
2. **A lease renewal that conflicts with the hub's write of `requests`:**
   - the worker re-reads, and keeps judging;
   - only a claim that names another worker stops it (Task 6).
3. **`describe` for a package that only NVD's CPE lists,** such as a binary with a `pkg:generic` purl: the answer lists NVD's entry, and says `Unknown` (Task 2).
4. **A vulnerability with thousands of entries that answer for no asked package:** the answer stays small, and holds counts only (Task 2).
5. **A proxy that answers `CONNECT` with 407:**
   - the message names the status;
   - neither the proxy's URL nor its credentials appear (Task 1).

---

## File Structure

```text
collectors/advisories/internal/fetch/        # Task 1
collectors/vulnerabilities/internal/describe/ # Task 2 (+ testdata)
collectors/vulnerabilities/internal/match/testdata/capabilities.json  # Task 2
sdk/evidence/types.go                         # Task 2: otherProviders
internal/agent/core/                          # Task 3: describe from the first step
internal/agent/casefile/                      # Task 3: purl and distro
internal/agent/prompt/{core.md,guidance.md,prompt.go}  # Task 3
config/rules/fix-available.yaml, config/playbooks/container-cves.yaml  # Task 4
api/triage/v1alpha1/investigation_types.go    # Tasks 5, 9
internal/agent/cases/select.go                # Task 5
internal/controller/hub/investigation.go      # Tasks 5, 9
api/triage/v1alpha1/assessment_types.go       # Task 6
internal/agent/queue/ -> internal/controller/hub/queue.go (the API queue)  # Task 6
internal/agent/worker/                        # Tasks 6, 7: the claim loop, then the judge
cmd/agent/                                    # Task 7
internal/collector/certs/                     # Task 7: the workers' client certificate
internal/setup/                               # Tasks 6, 7
config/agent/, config/rbac/agent/, config/network-policy/  # Task 7
Dockerfile, Makefile                          # Task 7
config/prometheus/                            # Task 10
test/e2e/                                     # Tasks 5 to 10
README.md, docs/agent.md, docs/collectors.md  # each task, for what it changes
```

## Task order

`make test` stays green after every task, and the e2e suite after each task that runs it.
- **Tasks 1 to 4:** the collectors, the prompt and the rule. Each stands alone.
- **Task 5:** the counts and "not running".
- **Task 6:** the queue moves into the API, and a claim loop judges inside the manager for now.
- **Task 7:** the workers' own binary, image and install. The manager stops judging.
- **Task 8:** the e2e checks of 0057.
- **Task 9:** the tokens on the `Investigation`.
- **Task 10:** the monitoring.
- **Task 11:** the "As built" section, the images, and the hand-off to the deploy session.

---

### Task 0: The record

- [ ] Commit `docs/decisions/0057-agent-workers.md`, the edits to 0053, the decisions index and the agent design, `docs/design/2026-11-20-phase4-live-fixes.md`, `docs/design/2026-11-20-what-the-agent-is-asked.md` and this plan: `docs: decide on agent workers, and plan phase 4's live fixes`.
- [ ] The agent design's sections 5.3, 5.4, 5.7 and 5.8 each get one line: "(*Amended on 2026-11-20:* see [phase 4's fixes](2026-11-20-phase4-live-fixes.md), 2.x.)"
- [ ] The status lines of the decisions that the fixes refine each get a note, as AGENTS.md asks:
  - 0051: the counts are over the selected cases, and the status shows tokens;
  - 0055: `describe` is listed from the first step;
  - 0054: the default allowlist leaves out `www.cve.org`, and holds `go.dev`.

### Task 1: `fetch` names its cause; the Accept header and the allowlist (design 2.1)

**Files:** `collectors/advisories/internal/fetch/fetch.go`, `fetch_test.go`, `docs/collectors.md`.

- [ ] **Write the failing tests** in `fetch_test.go`:
  - `TestARequestAcceptsHTMLAndJSON`: a fake host records the request. Assert `Accept == "text/html, application/json;q=0.9"`.
  - `TestAProxysRefusalIsNamed`: a fake proxy (`httptest`) answers `CONNECT` with 403, then with 407. Assert:
    - reason `FetchFailed`;
    - the message `"the proxy refused the host, with HTTP status 403"`, and `407` for the second;
    - the message doesn't contain the proxy's host and port.
  - `TestAFailureNamesItsCause`, as a table:
    - an unreachable proxy gives `"the proxy could not be reached"`;
    - a name that doesn't resolve gives `"the host's name does not resolve"`;
    - a host with a certificate from an unknown authority gives `"the host's certificate is not trusted"`;
    - a closed port gives `"the host could not be reached"`.
  - `TestTheDefaultListHoldsTheAdvisoryHosts` gains:
    - `www.cve.org` is refused, with `NotAllowed`;
    - `go.dev` is allowed.
- [ ] **Run** `cd collectors/advisories && go test ./internal/fetch/`. Expected: FAIL.
- [ ] **Implement:**
  - set the header next to `User-Agent`;
  - set `OnProxyConnectResponse` on the cloned transport in `New`, returning `proxyRefused{status}` for a status that isn't 2xx;
  - `causeOf(err error) string` maps the error to the texts above, and is used where "the page could not be fetched" is written today;
  - in `defaultAllowedDomains`, remove `www.cve.org` and add `go.dev`, with the comment "Go's vulnerability database cites its issues".
- [ ] **Run the test again.** Expected: PASS.
- [ ] **Docs:** in `docs/collectors.md`, the allowlist and the failure texts.
- [ ] **Gate, then commit:** `fix(advisories): accept HTML and JSON, and say why a fetch failed`.

### Task 2: `describe` answers for the asked packages (design 2.2)

**Files:**
- `collectors/vulnerabilities/internal/describe/{operation.go,compare.go,parse.go,describe_test.go}`;
- `describe/testdata/` (new fixtures);
- `sdk/evidence/types.go` and its schema test;
- `collectors/vulnerabilities/internal/match/testdata/capabilities.json`;
- `docs/collectors.md`.

**Interfaces:** `evidence.Description` gains `OtherProviders []ProviderCount` (`json:"otherProviders,omitempty"`), with `ProviderCount{Provider string; Entries int32}`.

- [ ] **Fixtures:** made as `parse.go`'s comment shows, with `--network none`:
  - busybox's CVE-2022-48174 with `--provider nvd`;
  - a vulnerability that Debian lists for several releases, with `--provider debian`.

  Add each command to the comment.
- [ ] **Write the failing tests** in `describe_test.go`:
  - **`TestOnlyTheEntriesThatAnswerAreListed`:** with the Debian fixture, asking for one package of `debian-12`:
    - `Providers` holds only the entries of `debian:distro:debian:12` that name it;
    - `OtherProviders` counts the rest by provider;
    - the sum of listed and counted entries equals the full count.
  - **`TestNoAnswerIsLeftOut`:** over every fixture and every asked package of the existing tests, every `Yes` and `No` that the full answer (today's `providersOf`) holds is in the listed entries.
  - **`TestAnUnansweredPackageListsTheEntriesThatNameIt`:** busybox `1.36.1`, type `binary`, purl `pkg:generic/busybox@1.36.1`:
    - no `InvalidInput`;
    - NVD's entry is listed, with `fixedForInstalled: Unknown`;
    - at most 8 entries are listed for it.
  - **`TestAGenericPurlMustMatchTheAskedPackage`:** `pkg:generic/busybox@1.36.0` asked as `1.36.1` gives `InvalidInput`.
  - **`TestTheAliasesAreSearchedInTheSameCall`:**
    - `vulnerabilityID: CVE-2026-78663`, `aliases: [GO-2026-6612]`, with the Go fixtures;
    - the fake Grype is called once for the records and once for the rows, with both IDs;
    - stdlib `go1.27.1` answers `No`.
  - **`TestAliasesAreBounded`:**
    - 9 aliases give `InvalidInput`;
    - an alias that doesn't match the ID pattern gives `InvalidInput`.
  - **`TestTheAnswerStaysSmall`:** 10,000 synthetic rows that answer for no asked package give an answer under 4 KB.
  - **`TestTheDescriptionIsTheAnsweringProvidersFirst`:** with the GHSA fixtures, the description is GitHub's for a Go module that `github:language:go` answers for.
- [ ] **Run** `cd collectors/vulnerabilities && go test ./internal/describe/`. Expected: FAIL.
- [ ] **Implement:**
  - In `providersOf`:
    - keep the entries with `answers`;
    - for each asked package that none answers for, keep at most 8 entries for which `in.names(e.fix.Package)`, in today's order;
    - count the rest per provider.
  - `aliases` in `parameters`: at most 8, each matching the ID pattern. They are added to the IDs of the first search.
  - `installedOf`: for a purl of type `generic`, accept a package whose name and version equal the purl's, and keep the asked type.
  - The description and references as the design says.
  - The `Operation.Description` names `aliases` and the counted entries.
- [ ] **Regenerate the golden** `capabilities.json` with the test's update flag, and check the diff.
- [ ] **Run the test again.** Expected: PASS. Also run `cd sdk && go test ./...`.
- [ ] **Docs:** `docs/collectors.md`'s `describe` paragraph.
- [ ] **Gate, then commit:** `fix(vulnerabilities): describe lists the entries that answer, with aliases and generic purls`.

### Task 3: `describe` from the first step; each finding's purl and distribution; the prompt (design 2.3, 2.4)

**Files:**
- `internal/agent/core/{session.go,core_test.go}`;
- `internal/agent/casefile/{casefile.go,casefile_test.go}`;
- `internal/controller/hub/assessment.go` (pass the SBOM to `Build`);
- `internal/agent/prompt/{core.md,guidance.md,prompt.go,prompt_test.go}`;
- the runner's tests and `test/e2e/images/scripted-model` where they script `search_tools` first;
- `docs/agent.md`.

**Interfaces:** `casefile.Build(c cases.Case, data …, packages map[string]casefile.Package, maxBytes int)`, with `Package{PURL, Distro string}` keyed by the finding's package ID.

- [ ] **Write the failing tests:**
  - **`TestTheCoreAddsTheCasesAliasesToDescribe`** (`core_test.go`):
    - the case's findings carry `GO-2026-6612` and `GHSA-aaaa-bbbb-cccc`, with the alias `CVE-2026-78663`;
    - the agent calls `vulnerabilities__describe` with `vulnerabilityID: CVE-2026-78663` and no `aliases`;
    - the collector receives `aliases: [GHSA-aaaa-bbbb-cccc, GO-2026-6612]`, sorted, without the asked ID;
    - aliases that the agent gave are kept, and the whole list stops at 8;
    - a call with an ID that isn't the case's gets nothing added;
    - the ledger entry holds the arguments as sent.
  - **`TestTheSessionListsDescribeFromTheStart`** (replaces `TestTheSessionListsOnlyTheCoreTools`):
    - a forwarder that offers `vulnerabilities__describe` and `advisories__fetch`;
    - the first tool list holds the five core tools and `vulnerabilities__describe`, and not `advisories__fetch`;
    - a profile whose grants leave out `describe` lists the five only.
  - **`TestTheCaseFileNamesEachFindingsPurlAndDistro`:**
    - a finding of a `deb` package in an SBOM of `debian` `12` gives `purl` and `distro: debian-12`;
    - a Go module gives its purl and no `distro`.
  - **`prompt_test.go`:**
    - `CoreVersion == "v5"`;
    - core.md holds `vulnerabilities__describe` "is listed from the start";
    - guidance.md holds "first sentence", "statusNotes", "runsIn" and "aliases".
- [ ] **Run** `go test ./internal/agent/...`. Expected: FAIL.
- [ ] **Implement:**
  - `NewSession` loads `vulnerabilities__describe` after the core tools, when the forwarder offers it.
  - `CollectorTools.Call` adds the case's IDs to `describe`'s `aliases`, as design 2.2 says, before the call and the ledger entry.
  - `Build` wraps each finding.
  - `assessment.go` passes the SBOM's packages, from the function that `ValidatorCase` now shares.
  - core.md: one sentence in the tools section.
  - `CoreVersion = "v5"`.
  - guidance.md, as design 2.4 says, in the file's style:
    - "Where to look first": `describe` with `aliases` and purls, then `statusNotes` and `runsIn`;
    - "The summary": the first sentence, then the reason, and versions only from evidence.
- [ ] **Update the scripts** that call `search_tools` before `describe`. A script that searches for another tool keeps its search.
- [ ] **Run the test again.** Expected: PASS.
- [ ] **Docs:** `docs/agent.md`, on the step-one tools and the case file.
- [ ] **Gate, then commit:** `fix(agent): list describe from the start, name purls in the case file, and sharpen the summary`.

### Task 4: The rule `fix-available` (design 2.7)

**Files:**
- `config/rules/fix-available.yaml`, `config/rules/kustomization.yaml`;
- `config/playbooks/container-cves.yaml`, `config/samples/config_v1alpha1_playbook.yaml`;
- `internal/rules/engine/defaults_test.go`;
- the e2e and fixture tests that count the default steps;
- `README.md`.

- [ ] **Write the failing tests** in `defaults_test.go`:
  - the pinned resources end with `fix-available.yaml`;
  - `TestFixAvailable`, as a table over findings:
    - `fixState: fixed`, `fixTarget: 1.2.4`, type `deb` gives `Affected`, with the reason `fixed in 1.2.4`;
    - `fixTarget` empty gives no outcome;
    - type `binary` gives no outcome;
    - `fixState: not-fixed` gives no outcome;
  - `container-cves` holds five steps, `fix-available` last.
- [ ] **Run** `go test ./internal/rules/...`. Expected: FAIL.
- [ ] **Implement** the rule exactly as design 2.7 shows, with a comment that says why binaries are left out, and add it to the pipeline.
- [ ] **Run the test again.** Expected: PASS. Then update every test that counts four default steps.
- [ ] **Docs:** the README's list of default rules.
- [ ] **Gate, then commit:** `feat(rules): ship fix-available, which settles findings with a known fix`.

### Task 5: The `Investigation` counts its selected cases; selection skips images that run nowhere (design 2.5, 2.6)

**Files:**
- `api/triage/v1alpha1/investigation_types.go` (generated files follow);
- `internal/agent/cases/{select.go,cases_test.go}`;
- `internal/controller/hub/{investigation.go,investigation_test.go}`;
- `internal/controller/triage/investigation_api_test.go`;
- `test/e2e/e2e_test.go`, where it reads `cases`;
- `docs/agent.md`.

**Interfaces:**
- `InvestigationCases` loses `Skipped`, and gains `OverTheCap` and `NotSelected` (`*int32`, `Minimum=0`).
- `cases.Skipped` gains nothing: its `Reason` is "not running".

- [ ] **Write the failing tests:**
  - **`TestACaseWhoseImageRunsNowhereIsNotSelected`** (`cases_test.go`):
    - a sheet whose manifest has no inventory gives a skip with the reason `not running`;
    - the conditions aren't evaluated for it: a condition that would fail isn't counted as failed.
  - **`TestTheCountsAreOverTheSelectedCases`** (`investigation_test.go`):
    - 10 cases in scope: 3 are rejected by a condition, 2 run nowhere, and 5 are selected, with `maxCases` 2;
    - `total` is 5, `overTheCap` 3, `notSelected` 5, `charged` 2;
    - `summary.skip` is 3.
  - **The API test:** a status with `skipped` is pruned, and a negative `overTheCap` is refused.
- [ ] **Run** `go test ./internal/agent/cases/ ./internal/controller/hub/`. Expected: FAIL.
- [ ] **Implement:**
  - `Select` rejects on `c.Impact.Resources == 0` before the conditions;
  - `show()` sets `total`, `overTheCap` and `notSelected`;
  - `summary.Skip` counts only the over-the-cap results.
- [ ] **Run** `make manifests generate`, then the tests. Expected: PASS.
- [ ] **Docs:** `docs/agent.md`, on the counts.
- [ ] **Gate, `make test-e2e`, then commit:** `fix(hub): count an investigation's selected cases, and skip images that run nowhere`.

### Task 6: The queue moves into the API (design 3.1 to 3.3)

**Files:**
- `api/triage/v1alpha1/assessment_types.go` (generated files follow);
- `internal/controller/hub/queue.go` (new: the API queue);
- `internal/controller/hub/assessment.go` (the sweep);
- `internal/agent/worker/{claim.go,claim_test.go}` (new);
- `internal/agent/queue/` (deleted once nothing uses it);
- `internal/setup/setup.go`;
- the envtest suites.

**Interfaces:**
- `hub.APIQueue` implements `cases.Queue` over the `Assessment`s' status.
- `worker.Loop{Client, APIReader, Name string, Limit func() int, Judge Judge, Lease, Renew time.Duration}` has `Start(ctx) error`.
- `worker.Judge`: `func(ctx, c cases.Case, r cases.Request, failures int) Result`. The `Result` values are today's queue results.

- [ ] **Write the failing tests:**
  - **API (envtest):**
    - a status with a `claim` and no `queue` is refused;
    - `requests` refuses two entries with the same namespace and name;
    - a negative `failures` is refused.
  - **`hub/queue_test.go`:**
    - `TestAddQueuesOnceAndChargesTheFirst`:
      - two investigations `Add` the same case: the first `Add` returns true, and the second false;
      - `requests` holds both;
      - `chargedTo` names the first;
      - `Ready` is `Queued`, and the queued label is set.
    - `TestKeepWithdrawsACaseThatNoOneWants`: after `Keep(first, nil)` and `Keep(second, nil)`, the case is `Withdrawn`, `queue` is cleared and the label is removed.
    - `TestKeepLeavesACaseInProgress`: a case with a live `claim` keeps its claim when its last request leaves.
    - `TestPendingCountsQueuedAndJudging`.
  - **`worker/claim_test.go`:**
    - `TestTheFirstCaseInOrderIsClaimed`: three queued cases of different tiers. The claim goes to the most urgent, and `claim.worker` is the loop's name.
    - `TestOneOfTwoClaimsWins`: two loops claim the same case. One judge runs, and the other loop claims the next case.
    - `TestTheLimitHoldsAcrossWorkers`: with a limit of 1 and a case already `Judging` by another worker, nothing is claimed.
    - `TestTheLeaseIsRenewed`: a judge that blocks for 3 renewals finds `leaseEndTime` moved forward 3 times.
    - `TestAConflictOnRenewalKeepsTheClaim`: a hub write to `requests` between renewals doesn't stop the judge.
    - `TestAClaimByAnotherWorkerStopsTheJudge`: the judge's context ends.
    - `TestAFailedJudgementBacksOff`:
      - `Failed` counts `failures` and `misses`, and sets `notBefore` 10 s ahead, then 20 s;
      - `Retry` counts `misses` only.
  - **The sweep:**
    - `TestALapsedLeaseGoesBack`: a lease that ended 31 s ago is `Queued` again, with `failures` +1;
    - `TestALiveLeaseIsLeftAlone`;
    - `TestARequestOfAGoneInvestigationIsRemoved`.
- [ ] **Run** `go test ./internal/controller/hub/ ./internal/agent/worker/`. Expected: FAIL.
- [ ] **Implement:**
  - the status types, with CEL, exactly as design 3.1 shows;
  - `APIQueue`, with status updates on conflict retry;
  - the loop: list by the queued label from the cache, sort with `cases.CompareTiers`, then `once`, then `queuedTime`;
  - the claim and the renewal;
  - the sweep by leases, every 30 s;
  - the wiring in `setup.registerHub`: the manager runs one `worker.Loop` with `Agent.Judge`, named after its pod, until Task 7;
  - delete `internal/agent/queue`.
- [ ] **Run** `make manifests generate`, then the tests. Expected: PASS.
- [ ] **Gate, `make test-e2e`, then commit:** `feat(agent): queue cases in the Assessments' status, claimed with a lease`.

### Task 7: The workers' own binary, image and install (design 3.4 to 3.6)

**Files:**
- `internal/agent/worker/` (the judge, moved from `hub/assessment.go`, with its RBAC markers);
- `internal/controller/config/modelconfig_controller.go` (its Secret marker moves);
- `cmd/agent/{main.go,main_test.go}`;
- `internal/collector/certs/` (`EnsureClient`);
- `internal/setup/` (the manager stops judging; the workers' `Register`);
- `Dockerfile`, `Makefile`, `.dockerignore`;
- `config/agent/`, `config/rbac/agent/`, `config/rbac/kustomization.yaml`, `config/rbac/manager_secrets_rolebinding.yaml`;
- `config/default/kustomization.yaml`, `config/network-policy/{collectors.yaml,allow-metrics-traffic.yaml}`;
- `test/e2e/{e2e_suite_test.go,config/kustomization.yaml,e2e_test.go}`;
- `README.md`, `docs/agent.md`, `AGENTS.md` (the images).

- [ ] **Write the failing tests:**
  - **`certs`:** `TestTheAgentsClientCertificateIsASecret`:
    - `EnsureClient` writes `vexplain-agent-client-tls`, with `tls.crt`, `tls.key` and `ca.crt`;
    - the leaf has the name `vexplain-agent` and client use only;
    - it is renewed 30 days before its end;
    - the Secret holds no authority key.
  - **`cmd/agent`:** `TestRunServesUntilItsContextEnds`, as the collectors' `main_test.go` does.
  - **`setup`:**
    - `TestTheManagerNoLongerJudges`: the manager's runnables hold no `worker.Loop`;
    - `TestTheWorkersRunTheProbeOnTheirLeaderOnly`.
  - **Generated RBAC** (a test over `config/rbac`):
    - `manager-role` holds no `watch` on `secrets`. The `ModelConfig` controller's marker moved to the workers, so the rules on `secrets` left are those of the manager's own code: its certificates, and the MCP collectors' check if it stays in the manager;
    - `agent-role` holds `assessments/status` update and `secrets` `get`, `list` and `watch` in `vexplain-system`.
  - **`setup`:** `TestTheManagersCacheHoldsNoLLMKey`: `CacheOptions` no longer selects the LLM key's label.
  - **e2e** (`e2e_test.go`):
    - the policy spec ("only the manager's pods reach the collectors on 9443") also lets the workers' pods in;
    - the no-restart spec covers the worker pods;
    - the agent specs pass with the scripted model behind the workers.
- [ ] **Run** `go test ./internal/... ./cmd/...`. Expected: FAIL.
- [ ] **Implement:**
  - move the judge, as decision 7 says;
  - `cmd/agent/main.go`:
    - a controller-runtime manager whose leader election (`agent.vexplain.bedag.ch`) covers only the `ModelConfig` controller;
    - the loop on every replica, named by `POD_NAME`;
    - metrics on `:8443` with the manager's authentication filter;
    - health on `:8081`;
  - the cache: the labelled Secrets of the operator's namespace, as the manager's cache has them, plus `vexplain-agent-client-tls`;
  - the pool reads the client certificate from that Secret, and rereads it when it changes;
  - `Dockerfile`: one builder stage builds `manager` and `agent`, and the final stages `manager` and `agent`;
  - `Makefile`:
    - `AGENT_IMG`;
    - `docker-build` and `docker-push` with `--target`;
    - `set-images` for `config/agent`;
    - `build` builds both binaries;
    - `manifests` runs controller-gen twice (decision 8);
  - `config/agent`:
    - the `Deployment`, 2 replicas, `POD_NAME` and `POD_NAMESPACE` from the downward API;
    - the manager's security context and probes;
    - its `ServiceAccount` and metrics `Service`;
  - the policies: a `from` entry for `app.kubernetes.io/component: agent`;
  - e2e:
    - `imageVariables` gains `AGENT_IMG`;
    - the image is loaded into kind;
    - `editedKustomizations` gains `config/agent`;
    - the model CA's mount moves to `vexplain-agent`.
- [ ] **Run** `make manifests generate`, then the tests. Expected: PASS.
- [ ] **Docs:**
  - the README: the images and the workers;
  - `docs/agent.md`: where the agent runs, and the Secrets it reads;
  - AGENTS.md: the image list.
- [ ] **Gate, `make test-e2e`, then commit:** `feat(agent): run the agent in its own workers`.

### Task 8: The e2e checks of 0057 (design 3.6)

**Files:** `test/e2e/e2e_test.go`, `test/e2e/images/scripted-model` (a delay on request, if it has none).

- [ ] **Write the specs:**
  - "a manager restart leaves a judged case alone":
    - the scripted model holds a case's answer for 20 s;
    - the manager's pod is deleted meanwhile;
    - the case is judged once, by its first claim, and its `failures` stays 0.
  - "a worker's death returns its case":
    - the worker that holds the claim is deleted while the model holds the answer;
    - within lease + grace + one sweep, the case is `Queued` again with `failures` 1, then judged by the other worker.
  - "two workers judge each case once": with 2 replicas and 4 cases, each case's ledger holds one judgement.
- [ ] **Run** `make test-e2e`. Expected: the new specs fail before any fix that they need, and pass after.
- [ ] **Gate, then commit:** `test(e2e): check the agent workers' claims and leases`.

### Task 9: The `Investigation`'s tokens (design 2.5)

**Files:** `api/triage/v1alpha1/investigation_types.go`, `internal/controller/hub/{investigation.go,investigation_test.go}`, `docs/agent.md`.

**Interfaces:** `InvestigationStatus.Usage *InvestigationUsage{PromptTokens, CompletionTokens *int64}`.

- [ ] **Write the failing test** `TestTheTokensOfTheChargedCasesAreSummed`:
  - three judged `Assessment`s, two `chargedTo` the investigation and one to another, with usage 100/10, 200/20 and 400/40;
  - `usage` is 300/30;
  - an `Assessment` judged before the run's `startTime` doesn't count.
- [ ] **Run** `go test ./internal/controller/hub/`. Expected: FAIL.
- [ ] **Implement:**
  - sum in `show()` from the cache;
  - add a field index on `status.chargedTo` if the list is slow in the test with 1,000 Assessments.
- [ ] **Run the test again.** Expected: PASS.
- [ ] **Gate, `make test-e2e`, then commit:** `feat(hub): show the tokens that an investigation's cases spent`.

### Task 10: Monitoring from the install (design 2.8)

**Files:** `config/prometheus/`, `config/default/kustomization.yaml` (the `[PROMETHEUS]` section), `config/network-policy/allow-metrics-traffic.yaml`, `test/utils/utils.go` (`InstallPrometheusOperator`, `UninstallPrometheusOperator`), `test/e2e/{e2e_suite_test.go,config/kustomization.yaml,e2e_test.go}`, `README.md`, a test over the rendered YAML.

- [ ] **Write the failing test** `TestTheMonitoringRendersWithoutAFile`. It renders `config/prometheus` with the kustomize that the Makefile pins, and checks:
  - the three ServiceMonitors;
  - no `bearerTokenFile`;
  - the manager's and the agent's endpoints read `authorization.credentials` from `vexplain-metrics-scraper-token`;
  - the binding names `vexplain-metrics-reader`;
  - no label outside `app.kubernetes.io/*`.
- [ ] **Run the test.** Expected: FAIL.
- [ ] **Implement** as design 2.8 says:
  - the `[PROMETHEUS]` line in `config/default` stays commented;
  - `InstallPrometheusOperator` applies the Prometheus Operator's `bundle.yaml` of a pinned release, as kubebuilder's scaffold did, and `UninstallPrometheusOperator` removes it.
- [ ] **e2e:**
  - `BeforeSuite` installs the Prometheus Operator, unless it is there already. `AfterSuite` removes it, if the suite installed it;
  - the e2e overlay includes `config/prometheus`;
  - a spec checks that the three `ServiceMonitor`s exist, and that the scraper's token from its Secret gets `/metrics` from the manager and from a worker.
- [ ] **Docs:** the README, on uncommenting the `[PROMETHEUS]` line where the Prometheus Operator runs, and on the namespace label.
- [ ] **Gate, `make test-e2e`, then commit:** `feat(config): ship ServiceMonitors that work without a token file`.

### Task 11: As built, the images and the hand-off

- [ ] Write this plan's "As built" section: what differed from it, and why.
- [ ] Run `make docker-build VERSION=<git describe>` for the seven images.
- [ ] Tell the deploy session:
  - the commit and the image names;
  - the new `Deployment` and its Secret;
  - that `config/prometheus` is applied apart;
  - that `fix-available` ships in the defaults, so the live copy of the rule can go.
- [ ] Commit: `docs: record phase 4's live fixes as built`.

## As built

Where the build differs from the text above, the build is right. Each difference was decided and reviewed while the plan ran. The design has amendment notes, dated 2026-11-20, where the build changed it: in 3.1, 3.2, 3.3 and 3.5.

### `describe` (Task 2)

- **A package is also found under NVD's CPE of its product,** `cpe:2.3:<part>:<vendor>:<product>:…`, since NVD lists some packages, such as BusyBox, by CPE alone.

### The case file and the core (Task 3)

- **The safety core fills `aliases` in `Session.load`'s handler for `describe`,** from the case's findings, before the call reaches the collector.
- **`agent-replay` exports the case's packages to `packages.json`,** so a replayed case file holds the same purl and distribution as the hub's.

### Selection (Task 5)

- **Only an investigation's selection leaves out a case whose image runs nowhere** (`cases.Selection.SkipNotRunning`). Rebuilding a known case, for the judge, the assessor or an export, never does. So a case queued before its image stopped is still judged once.

### The queue in the API (Task 6)

- **The API has no bools,** as kube-api-linter asks:
  - `requests[].trigger` (`Once`, `Schedule` or `Continuous`) replaces `once`;
  - `order.knownExploited` is `Listed` or `NotListed`.

  A case that a `Once` request wants still comes first in its tier.
- **There is no queued label,** so decision 6 is void. A status update can't change labels, so the outcome and the label could never be one write. The workers' cache holds every `Assessment`, as the manager's does, and they pick those whose status holds a `queue`. Nobody needs `patch` on `Assessment`s.
- **`queue.chargedTo` holds the charge while a case waits.** The outcome write copies it to the top-level `chargedTo`, which so names the investigation charged for the judgement whose `usage` the status holds. A case queued again and withdrawn unjudged leaves the top-level field alone.
- **The outcome write and the hand-back check the claim:** they write only while the claim names the worker, with the object's `resourceVersion`.
- **A worker stops its judgement once the clock passes the last lease end it wrote,** without a later renewal, as client-go's leader election does. Each renewal gets 10 s, less than the sweep's 30 s of grace.
- **After a failed renewal, a worker stops once its next renewal would come no sooner than the last lease end it wrote.** Waiting for that renewal, which may hang for its 10 s, could leave the judgement running until shortly before the sweep may hand the case on, so the clocks of the nodes would decide. Stopping a renewal earlier keeps the 30 s of grace for them.
- **A worker claims nothing while no case can start:** the agent is switched off, or the default profile's `ModelConfig` isn't `Ready`, the checks of `prepare` that hold for every case. It reads them from the cache before each round of claims. Otherwise it claimed every waiting case, one after the other, only for the judge to hand it back: two status writes and a sheet's read per case every 10 s, for as long as the agent stayed off. A case whose own profile or `ModelConfig` isn't `Ready` is still claimed and handed back.
- **A lapsed lease counts as a failure:** a miss and the backoff, as 0057's "under the retry rules" says.
- **A case with 5 failures is ended by the next judge,** as design 3.3 says.
- **The first sweep waits 90 s after the manager starts,** as the sweep in the manager did. The investigations' first reconciles queue again the cases that the version before held without a `queue`: withdrawn first, such a case was charged again, past the cap of a `Once` investigation that used it up, and twice against a `Continuous` one's. A lease that lapsed before the start is swept up to 90 s later.
- **The sweep is the hub queue's,** `hub.APIQueue`. The status helpers that both sides use are in `internal/agent/cases`, so the manager never imports the workers' code. The claim's Go type is `QueueClaim`.

### The workers' binary and install (Task 7)

- **Each binary links only its own code,** which `TestEachBinaryLinksOnlyItsOwnCode` pins. So decision 7 grew:
  - the judge moved into `internal/agent/worker`;
  - the `ModelConfig` controller into `internal/agent/models`;
  - the workers' wiring into `internal/agent/worker/setup`.

  Both binaries share the prompt, profile and ledger packages. Three small helpers are copied rather than shared.
- **A worker's name is `POD_NAME`,** from the downward API, or else the host's name.
- **The workers' client certificate has a cache of its own,** which selects the one Secret by name. One cache selects one kind by one label, and the LLM keys' label can't include it.
- **The manager issues the client certificate from a runnable of its leader,** at each collector resync (30 s), so it doesn't wait for a `Collector` to exist.
- **The workers' metrics have a `NetworkPolicy` of their own,** `allow-agent-metrics-traffic`, since one pod selector can't take both `Deployment`s without widening it.
- **The workers' role can read every Secret of the operator's namespace,** the authority's key included, since RBAC can't narrow `get` or `list` by label. The owner accepted this on 2026-11-20, so decision for the owner 4 holds for the workers' code, not for their rights (design 3.5). The role also creates and deletes any `Evidence`, for the tool outputs that the ledger points to, as the manager's did.
- **The `Lease` markers grant `get`, `create` and `update`,** which client-go's lock uses: `get` and `update` on `agent.vexplain.bedag.ch` alone, by `resourceNames`, since the manager's `Lease` is in the same namespace, and `create` in a rule of its own, which a name can't narrow.
- **The workers' manager elects no leader.** The `ModelConfig` controller runs under a client-go `LeaderElector` of its own, on the `Lease` `agent.vexplain.bedag.ch`, with controller-runtime's timings. A controller can't start twice, so each term builds one anew, with `controller.NewUnmanaged` and its watches, and stops it with the term. Losing the `Lease` stops the probe, and the worker campaigns again. Under controller-runtime's own election, the loss ended the process, and the replica's judgements with it, whose cases then waited for their leases and counted a failure each. With `--leader-elect=false`, as in the tests, the controller runs directly.
- **The judge's tests are in `internal/agent/worker/judge_test.go`,** on `worker.Agent` with an API server's fake, and the `ModelConfig` specs in the config suite, which needs that suite's controllers and fixtures.

### The e2e checks of 0057 (Task 8)

- **A worker's death is a `SIGKILL` of its container,** on the kind node, and then its pod is deleted, so that its name can't come back. A worker sent `SIGTERM` hands its case back with no failure, so deleting the pod alone is no death.
- **The scripted model holds a case's first answer for 45 s,** not 20: longer than a pod's 30 s grace, and shorter than the model's 60 s request timeout.
- **The planted images give 2 cases of the unexploited vulnerability,** not 4.

### The investigation's tokens (Task 9)

- **No index serves `chargedTo`.** Listing 1,000 `Assessment`s from the cache took a few milliseconds in the test.

### Monitoring (Task 10)

- **`config/prometheus/kustomizeconfig.yaml`** makes the name prefix reach the `ServiceMonitor`s' token Secret and the token Secret's `ServiceAccount` annotation.
- **The rendering test is `hack/monitoring_test.go`.** It needs `bin/kustomize`, so `make test` builds it first.
- **The e2e suite installs the Prometheus Operator v0.77.1,** and checks that the collectors' `ServiceMonitor` exists. It scrapes the manager and a worker with the scraper's token.

## Carried forward

### The queue and the workers

- **The claim gate reads the default profile's `ModelConfig`.** A playbook whose profile names another `ModelConfig` waits while the default's isn't `Ready`. The workers log nothing while the gate is closed.
- **The gate doesn't read the default `AgentProfile`'s own `Ready`.** A default profile that isn't `Ready`, such as one whose guidance is missing, still claims and hands back its cases every 10 s, if its `ModelConfig` is `Ready`.
- **Each lost term of the probe's Lease leaves two event handlers** on the shared informers, since controller-runtime never removes a source's handler. A cache per term, or one controller that idles while it doesn't lead, would close it.
- **`APIQueue.Add` reads past the cache on every investigation reconcile,** one GET per held case.
- **The claim loop lists every `Assessment` each second,** and each investigation reconcile lists them all, for `Keep`, `Pending` and the tokens. No index serves `chargedTo` or the requests.
- **`setReady(Judging)`, and `setReady(Judged)` on an existing outcome, don't check the claim.**
- **A worker sent `SIGTERM` hands its cases back without a failure,** so a rollout of the workers spends the tokens of every case in progress again. Draining within a longer grace period would keep them.
- **Nothing signals that cases wait and no worker claims them,** as with the workers scaled to 0.
- **The client certificate has a cache of its own;** the API reader would do.
- **The workers' resources copy the manager's;** no measurement covers them yet.
- **The manager's role keeps `update` on `modelconfigs/status`,** which it no longer uses.

### `describe` and the core

- **Aliases that the agent gives beyond 8 pass through,** and the collector refuses the call.
- **Each case loads `describe` with one more capabilities round trip.**
- **The `pkg:generic/` prefix check is case-sensitive;** it fails closed.
- **core.md's example of a found tool is still `vulnerabilities__describe`,** which is now a core tool.

### Investigations

- **`status.usage` is set only where the investigation judges.** Check that an early return, such as the agent switched off, leaves no stale sum.

### Build and docs

- **`make docker-buildx` builds only the manager's target.**
- **`go test ./...` needs `make kustomize` first,** for `hack/monitoring_test.go`.
- **docs/agent.md lists `cmd/agent` among the packages whose markers make `agent-role`;** it holds none now.
- **Stale comments** in .github/workflows/test-e2e.yml:35 and .dockerignore:21, and long lines in authority.go:104, config/network-policy/collectors.yaml:2, config/rules/kustomization.yaml:1 and the README.

### Tests and form

- **The e2e workers' specs:**
  - the restart spec needs the manager back within the model's 45 s hold, and passes `get pods -o name` to `delete`, which holds for one replica;
  - the death spec reads `failures == 1` while the case waits;
  - their `BeforeAll` depends on an earlier spec deleting the model namespace;
  - the scripted model ignores a `HOLD` it can't parse.
- **Untested:**
  - a renewal landing between the sweep's list and its write;
  - `Wait`'s retry delay, and the limit across rounds (`TestTheLimitHoldsAcrossWorkers` passes against a stub that claims nothing);
  - a same-named investigation in another namespace, and a judged `Assessment` with no usage;
  - case-insensitive alias dedup, and exactly 8 aliases;
  - every case not running.
- **Form:**
  - `TestDescribeNamesEveryProvider`'s name, and `complete_test.go`'s doc comment;
  - `select.go:79-83` reads backwards;
  - `worker.requestOf` and `hub.requestOf` share a name;
  - `internal/agent/models` shows 0% coverage, since its specs run in the config suite;
  - the pinning test's list for the manager omits `internal/agent/core` and the validator.

### After the live runs: core `v7` and the investigation's guidance

- **While the agent is switched off,** a verdict that `judgePolicy` declines shows as reused and judged elsewhere, while a stale case shows as one to judge. Hand it over by `open && (held || room > 0)`, as a stale case.
- **`describe`'s note counts a refused reference** each time it appears, so its count can be high.
- **A labelled heading of "would settle", written first,** loses its own line's text in the summary at a limit. The facts are kept.
- **Two Continuous investigations can't apply their guidance to a case they share:** `judgePolicy` other than `IfStale` is refused with `Continuous`, until a rule says which of them judges it.
- **Two specs fail now and then,** outside this work: internal/controller/inventory's "reads Evidence and ImageVerdicts from the API server" (the assessor deletes the sheet mid-spec), and triage's "prunes a status with skipped cases" (a status conflict with the controller).

## The final improvement round, after the fourth live run

Builds design section 7. Two tasks, in separate files, then one review, the gate and one `make test-e2e`. The owner asked for the round on 2026-11-21.

### Task R1: Core `v8` (design 7.1)

- **Files:** internal/agent/prompt/core.md, guidance.md and prompt.go (`CoreVersion = "v8"`); internal/agent/casefile/casefile.go (`Search`); internal/agent/core/server.go (the schema and description of `search_evidence`); their tests; docs/agent.md's line on `search_evidence`.
- **Tests first:**
  - the prompt holds a term of each of the three rules, and the guidance names the provider's advisory before the image's evidence;
  - `Search` with `wget|curl` returns the lines that hold either, ignoring case, and counts them once; a query without `|` matches as before; empty terms, as in `a||b`, are ignored, and a query of only `|` matches nothing;
  - the fit check's count of the core tools' schemas still matches their size.

### Task R2: The board's series and the event (design 7.2 and 7.3)

- **Files:** internal/spoke/render.go and metrics.go (`openCase`, the labels); internal/controller/hub/metrics.go (the states, the info series); internal/metrics/metrics.go and the agent's worker or command (the counters at 0); internal/controller/hub/investigation.go (`judgedElsewhereEvent`); api/triage/v1alpha1/investigation_types.go (`maxCases`' doc) and the CRDs; docs/agent.md's metrics table and investigation section; the e2e check of `vexplain_open_case`.
- **Tests first:**
  - an open case's series carries `exposure`, `known_exploited` and `action`, and two packages with one CVE and different steps give two series;
  - `vexplain_investigation_cases` has `judgedElsewhere` and `charged`;
  - the info series names each ID of `spec.vulnerabilities` and of `status.results` once, and an investigation that goes has none;
  - a worker that knows its cluster exposes each known value of the four counters at 0, and the manager's registry has none of them;
  - the event under each policy: `IfStale` with guidance advises `IfJudgedElsewhere`, `IfJudgedElsewhere` and `Always` advise raising `maxCases`, `IfStale` without guidance advises nothing.

### Task R3: A verdict explains itself, and the guidance can't change (design 7.4 and 7.5)

- **Files:** internal/agent/validator (the check `Explainable`, `Case.Guidance`); the worker and cmd/agent-replay, which build the validator's case; internal/agent/prompt/core.md (rule 3 of `v8`, before it ships); api/triage/v1alpha1/investigation_types.go (the transition rule) and the CRDs; docs/agent.md.
- **Tests first:**
  - a summary or a claim that says "guidance", in any case, is refused; a next step that does isn't;
  - a summary or a claim with a run of 8 words of the investigation's guidance is refused, across case and punctuation; 7 words aren't; a case without an investigation's guidance isn't checked;
  - the worker and the replay give the validator the guidance that the case was judged with;
  - the envtest API suite: guidance can't change, be added or be removed on an update; an investigation without guidance can change other fields; one stored without `spec.agent` can get it with guidance.

### Task R4: `investigationRef`, with the investigation's uid (design 7.6)

- **Files:** api/triage/v1alpha1/assessment_types.go and the CRDs; internal/controller/hub (queue.go, investigation.go: the requests, `judgedFor`, `spent`, the event); internal/agent/worker (claim.go, judge.go: the guidance's uid check); cmd/agent-replay/export.go; the tests of each, the envtest API suite and the e2e; docs/agent.md.
- **Tests first:**
  - the schema requires `uid` in each reference, and takes the renamed fields;
  - a recreated investigation of the same name: `IfStale` reuses the earlier object's verdict and counts it judged elsewhere, `IfJudgedElsewhere` queues it again, `usage` counts only this object's;
  - a request of an earlier object of the same name gives way to the current one's;
  - the worker gives no guidance where the object that it reads has another uid;
  - the event names "an earlier <name>" when only the uid differs.

### Task R5: A binary at an upstream version that a distribution fixed (design 7.7)

- **Files:** internal/agent/prompt/core.md and its test. Core `v8` takes the rule, since it hasn't shipped.
- **Tests first:** the core holds the rule's terms: a package without a distribution, a release of its own upstream version, the patch as the exception, a fix in another upstream version as no evidence, and a version range in prose as no evidence.

### Task R6: Tokens and time per investigation (design 7.8)

- **Files:** internal/metrics/metrics.go (two counters); internal/agent/worker/judge.go; docs/agent.md's metrics table.
- **Tests first:** the investigation's series exist at 0 while its judgement runs, and grow by its tokens and time; a judgement counts for the investigation that its cap is charged to, also where another keeps the case queued.

### After the fourth live run: the final round

- **A frequent term can fill the 200 lines** of a search with several terms, and hide a rarer term's lines. The live run shows whether the cut needs a count per term.
- **The check `Explainable` compares words, not meaning.** A paraphrase of the guidance passes; only the core's rule keeps it out. A model could get the guidance's words into an entry on purpose, such as a collector's answer that repeats its arguments, and cite it.
- **A takeover that the cache doesn't show yet isn't charged:** the reconcile decides from its cache whether an earlier object charged a held case, and `Add` from the API server. The investigation then under-charges by that case, as after a crash.
- **`requests` is an atomic list,** so the schema no longer refuses two requests of one investigation; the hub's `Add` keeps one. A CEL rule could check it, at a cost for 64 items.
- **The transition rule on `spec.agent`** isn't tested for an object stored before `spec.agent` existed, since the current schema can't store one. Kubernetes skips a transition rule without an old value, so such an object may get its guidance on the apply that adds `spec.agent`.
- **The event's test** lives in the hub's metrics tests.
- **Two worker tests set guidance on a stored investigation,** which the API now refuses; the fake client doesn't check CEL. Create the investigation with its guidance instead, once the fixture takes it.
