# vexplain — Remote spokes, Implementation Plan

> **For agents:** follow `AGENTS.md`. Implement this plan task by task, test first. A task is done when its tests pass, it is committed and it has been reviewed; only then start the next one. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** one hub serves a fleet of clusters:
- a cluster runs `Hub`, `Spoke` or `HubAndSpoke`;
- the hub reads each spoke's API server with a narrow token that it renews, and copies the spoke's presence, exposure and namespace labels into its own stores;
- the hub scans every image of the fleet once, from its registry;
- the hub renders each remote cluster's metrics and counts, so the SOC sees the fleet on its board.

**Architecture:**
- **Modes:** a `--mode` flag splits `setup.Register`. A `Collector` whose roles the mode doesn't run turns `WrongRole`.
- **Scanning (0066):** the scanner takes the hub role, and scans the platforms that a request names, with or without pods. A request names the platforms that run the image in any cluster.
- **`Spoke` and `internal/remote` (0061 to 0064):** the record, the one seam that builds a spoke's client, the token's renewal into a Secret of the hub's own, and the copier: a spoke's streamed records, presence entries, collectors and namespace labels, into the hub's stores.
- **The rules across clusters (0064, design 5.7, 5.8, 5.10):** a workload's evidence comes from its own cluster's collectors; a playbook judges an image when one cluster that runs it matches; an address that two clusters name gets no source's answer.
- **Rendering (0065):** the renderer reads what runs through an interface. The hub renders each remote cluster from the copies into a metrics source of its own, and writes no report objects for it.

**Tech Stack:** as in phase 4 and the entry points: Go 1.26, kubebuilder, controller-runtime, cel-go, CloudEvents, buf. No new dependency: controller-runtime's `cluster` package caches a spoke, and client-go's `TokenRequest` renews a token.

**Spec:**
- `docs/design/2026-11-23-remote-spokes.md`, accepted on 2026-11-24, with decision records 0060 to 0066;
- the main design's revision 19, and the notes that phase 6 added to 0004, 0011, 0021, 0022, 0042, 0043, 0047, 0058 and 0059;
- the entry points plan's "As built" and "Carried forward", which describe what exists.

**Branch:** `feat/phase6-remote-spokes`, from `main` (`78c0b36`), with the design's and this plan's commit (Task 0). The pull request opens after the live review, once every follow-up is in the to-do list (owner, 2026-11-24).

**Not in this plan** (design section 2, and the deferred items handed to the main session):
- report objects for a remote cluster (owner, 2026-11-24: metrics only), and the reports' redesign;
- scanning on a spoke for a registry that only it reaches, with answers bound to the image and a trust order;
- Konnectivity, federated identity, spokes that register themselves, urgency tables per cluster, per-network subjects;
- the live run on the owner's clusters, which the main session runs with the owner after the hand-over (Task 21).

## Decisions made in this plan

The design leaves these to the builder, or the code showed them while planning.

1. **The mode is the flag `--mode`,** with `Hub`, `Spoke` and `HubAndSpoke`, the default. `setup.Options` gains `Mode`. Today `cmd/main.go` fills `Options` only from the environment (`optionsFromEnvironment`).
2. **`WrongRole` is built now.** `collectorclient.Usable` already names it "from phase 6" (`pool.go:244`). A `Collector` whose recorded roles include none that the mode runs turns Ready False with `WrongRole`, and gets no stream and no request. It still runs once, since its roles are known only from its answer.
3. **The scanner takes the hub role,** and so does its operation `scan`. `collectorclient.OperationFor` requires the hub role, and the executor calls with `ROLE_HUB`. The executor only ever asks the scanner, so nothing else moves.
4. **A scan's parameters gain `platforms`,** at most 16, each `os/arch[/variant]`, and `pods` stays optional:
   - the scanner scans the request's platforms together with those of its pods' nodes;
   - without pods it pulls with the admin's logins only, since `Credentials` reads a pod today without a nil check;
   - `NotRunning` stays for a request that names neither a pod that runs the digest nor a platform.
5. **`tasks.Request` gains `Platforms`:** every `status.clusters[].platforms` of the image's `ImageInventory`, sorted and unique, as `repositoriesOf` gathers the repositories. The executor scans an image that no local pod runs when the request names platforms.
6. **The admin's Secret has the keys `server`, `ca.crt` and `token`.** The hub's own Secret is `spoke-<name>-token`, with the key `token`, labelled `vexplain.bedag.ch/spoke`, and owned by the `Spoke`.
7. **The hub finds the ServiceAccount to renew in its token's claims** (`kubernetes.io.serviceaccount.{name,namespace}`), decoded without a check: the spoke's API server checks the request anyway. So the admin's Secret needs no more keys.
8. **The token lives 24 hours,** and is renewed at half its lifetime by its `exp` claim. The flag `--spoke-token-lifetime` sets it for tests, from 10 minutes, `TokenRequest`'s least.
9. **On the spoke:** the ServiceAccount `vexplain-hub`, the ClusterRole `vexplain-hub-reader`, and a Role of the same name in the operator's namespace, all from markers in `internal/remote/hubaccess`, generated into `config/rbac/hub-access/` as the workers' role is into `config/rbac/agent/`. AGENTS.md allows RBAC only from markers, and a namespaced marker gives the Role the ClusterRole's name.
10. **One cache per spoke:** a controller-runtime `cluster.Cluster` on the seam's `rest.Config`, started by the `Spoke`'s controller and stopped when the `Spoke` or its Secret changes. It watches `Evidence` with the cluster label, `ImageInventory`, `Collector`s, and the namespaces' metadata.
11. **A copied entry keeps the spoke's counts.** `inventory.Observation` gains `WorkloadCount`, which wins over the listed workloads when set, and the copier sets `MaxNamespaces` to 1000. Today `Observe` counts the listed workloads, at most 100, and keeps 100 namespaces by default.
12. **The hub's copies of namespace labels are streamed records:**
    - the subject `namespace/<cluster>/<name>`;
    - the type `ch.bedag.vexplain.namespace.v1alpha1`, with the data `{labels: [{key, value}]}`;
    - the source `vexplain`, put `InCluster`.

    The store's snapshots, its cap and its deletions serve them as they serve every streamed record.
13. **A remote cluster gets no report objects** (owner, 2026-11-24). The hub renders what each remote workload's report would say, and keeps only its series and the playbooks' counts. So the local renderer, whose sweep deletes every report it can't find in local presence (`reports.go:239-306`), needs no change, and no remote report lands in the hub's etcd.
14. **One controller renders every remote cluster** (`remote-reports`), with each cluster's state apart: its view of what runs, its namespace labels, and its series. The design's "a renderer per `Spoke`" is this state. controller-runtime has no way to stop one controller among others.
15. **The remote series have one metrics source,** `remote-reports`, keyed by cluster, namespace and report. A deleted `Spoke`'s series go with it. `metrics.SetSource` has no removal, and `ReportsCollector` keys by namespace and name only.
16. **The gauge of running images counts every cluster in one round:** the hub's own, and each `Spoke` by its `status.clusterID`. Today each round resets the gauge (`gauge.go:71`), so a second updater would wipe the first's series.
17. **A remote collector's readiness is a series of the hub's:** `vexplain_collector_ready` from each `Spoke`'s `status.collectors`.
18. **`DeleteBySource` deletes a source's asked evidence, and its streamed records of the store's own cluster only.** The store knows its cluster already (`NewCRDStore`'s `cluster func() string`), so its signature stays.
19. **The upgrade's dip, as the code shows it** (to be confirmed by Task 2's reproduction):
    - after any start, the assessor's memory of what each sheet rests on is empty, so every sheet counts as changed (`assessor.go` ~:201-204);
    - when the first match then fails because the matcher restarts or loads its database, each sheet that can't stand in for a match is deleted (~:967-968, :1252-1258);
    - those sheets come back only as the matcher answers. The fix: a match that fails because its findings producer can't answer never deletes a sheet.
20. **A workload's producers are kept per cluster** in `PlaybookExposure`, with each remote producer's `maxAge` from its `Spoke`. The `Spoke` mirrors each type's effective `maxAge`, the `Collector`'s `spec.produces` override included. Today `caseExposures.maxAge` reads only local `Collector`s, so a remote record would never expire.
21. **The workers learn a case's matching clusters from its `Assessment`** (`status.queue.runsIn.clusters`), as they learn its exposure today. They need no right to read `Spoke`s.
22. **An ambiguous address is a state of `vexplain_entry_points`,** `ambiguous`, next to its states for answered and unanswered points. The design's "the hub counts such addresses per cluster" needs no metric of its own.
23. **The two clusters' end-to-end test is a `Describe` of the one suite.** `setup-test-e2e` creates both kind clusters, and the `Describe` deploys `Hub` and `Spoke` on them, then removes both, so it doesn't depend on the order of the suite's other containers.
24. **The remote renderer reads what runs from the hub's exposure view** (`internal/exposure.View`), which already holds every cluster's presence and exposure from the store's watch. The view keeps each presence record's data, which `holdOf` drops today (~:285-298), and the measurement adds the manager's memory.

## Decisions for the owner

The owner approved the plan on 2026-11-24, with these answers:
1. **The branch:** `feat/phase6-remote-spokes` from `main`, with the design's and this plan's commit. The pull request opens after the live review, once every follow-up is in the to-do list.
2. **The live run:** the main session runs it with the owner after the hand-over (Task 21). Test and prod become spokes through their own install paths, prod through the CI pipeline's manual steps.
3. **Execution:** subagent-driven.
4. **Remote reports: metrics only.** A remote cluster gets its series and counts, and no report objects, since the reporting is reworked right after phase 6 (decision 13).

## Global Constraints

- **AGENTS.md binds:**
  - design first, test first, kind only;
  - no private data and no figures from real platforms;
  - no AI attribution;
  - comments that state their own reason and never cite a ruling kept outside the repository.
- **Phase 4 and the entry points still bind,** as amended by their "As built" sections:
  - API conventions and kube-api-linter;
  - RBAC from markers;
  - the two binaries apart (`TestEachBinaryLinksOnlyItsOwnCode`), and 0021's separation: spoke code reaches the hub's state only through the shared interfaces;
  - tests and commits.
- **Before each commit:** `make manifests generate && make proto-check && make lint && make test`.
- **e2e:** `make test-e2e`, on kind, at the end of each task that changes a CRD, the install, a collector or the hub. The hub's kubeconfig is `bin/kind-e2e.kubeconfig`, and from Task 18 the spoke's is `bin/kind-e2e-spoke.kubeconfig`.
- **Tests with two clusters** run two envtest API servers in one process, never a real cluster.
- **No real model calls:** the scripted model only.
- **No internet in unit tests.**
- **The API is `v1alpha1` and unreleased:** fields change without conversion.
- **Names:**
  - the flag `--mode`, with `Hub`, `Spoke` and `HubAndSpoke`, and `setup.Options.Mode`;
  - the reason `WrongRole`;
  - the scanner's role `hub`, and its parameter `platforms`; `tasks.Request.Platforms`;
  - `Spoke` (group `config`, cluster-scoped): `spec.labels`, `spec.credentialsSecretRef.name`, `status.clusterID`, `status.collectors[]{name, version, ready, capabilities}`, `status.lastSyncTime`, `status.tokenExpirationTime`;
  - its conditions `Connected` and `Synced`, beside `Ready`, `Reconciling` and `Stalled`, and the reasons `Unreachable`, `CredentialsInvalid`, `IdentityChanged`, `TokenExpired` and `Syncing`;
  - the admin's Secret's keys `server`, `ca.crt` and `token`; the hub's Secret `spoke-<name>-token`, with the key `token` and the label `vexplain.bedag.ch/spoke`;
  - on a spoke: the ServiceAccount `vexplain-hub`, the ClusterRole `vexplain-hub-reader`, and the Role `vexplain-hub-reader` in the operator's namespace;
  - the package `internal/remote`;
  - the subject `namespace/<cluster>/<name>`, the type `ch.bedag.vexplain.namespace.v1alpha1` and the source `vexplain`;
  - the controller `remote-reports`, and the metrics source of the same name;
  - the metrics `vexplain_spoke_records_refused_total{cluster, reason}` and `vexplain_remote_images_without_presence{cluster}`, and the state `ambiguous` of `vexplain_entry_points`;
  - `Assessment.status.queue.runsIn.clusters`, and `cases.Selection.Clusters`;
  - the installs `config/hub` and `config/spoke`; `config/default` stays `HubAndSpoke`.
- **Values:**
  - a token lives 86,400 seconds, and is renewed at half its lifetime; `--spoke-token-lifetime` takes 10 minutes at least;
  - a scan names at most 16 platforms;
  - a copied entry keeps up to 1000 namespaces, and the spoke's workload count;
  - TLS to a spoke is always verified against `ca.crt`. Nothing turns that off.
- **Commits:** Conventional Commits, no AI attribution, never on `main`, never pushed. Stage paths by name.
- **Repository hygiene:**
  - neutral names, such as `cluster-a`, `cluster-b`, `team-a` and `app.example`;
  - addresses from the documentation ranges: `192.0.2.0/24`, `198.51.100.0/24` and `2001:db8::/32`;
  - never the name of a company, a cluster or a host of the owner's.

## Review Focus

1. **A spoke that can't be reached when the hub starts:** its series render from the copies at once (Task 16).
2. **A Secret that points at another cluster:** the `Spoke` turns `IdentityChanged`, and nothing is copied under its name (Tasks 8 and 10).
3. **The admin's Secret applied again with its expired bootstrap token:** the hub keeps using its own token (Task 8).
4. **An image of a registry that the hub has no login for:** its facts say `Unauthorized` and name the registry, and no case reads it as clean (Tasks 5 and 6).
5. **Two clusters with a workload of the same namespace and name:** their series stay apart (Task 15).

---

## File Structure

```text
cmd/{main.go,main_test.go}                                     # Tasks 4, 8
internal/setup/{mode.go,setup.go,register_test.go,install_test.go}   # Tasks 4, 8, 9, 10, 16, 17
internal/controller/config/{collector_controller.go,spoke_controller.go,collector_api_test.go}   # Tasks 1, 3, 4, 8, 10
internal/rules/engine/{exposure_test.go,engine_test.go}        # Task 1
internal/controller/hub/{assessor.go,janitor.go,playbook_controller.go,investigation.go}   # Tasks 2, 6, 12, 13
internal/evidence/crdstore.go                                  # Task 3
internal/collectorclient/pool.go                               # Tasks 4, 5
collectors/scanner/internal/scan/                              # Task 5
internal/tasks/tasks.go, internal/spoke/executor.go            # Tasks 4, 5, 6
api/config/v1alpha1/{spoke_types.go,collector_types.go}       # Tasks 4, 7
api/triage/v1alpha1/assessment_types.go                        # Task 13
internal/remote/                                               # Tasks 8, 10, 11, 16
internal/remote/hubaccess/, config/rbac/hub-access/            # Task 9
internal/inventory/{store.go,crdstore.go,gauge.go}             # Tasks 10, 16
sdk/subject/, sdk/evidence/                                    # Task 11
internal/exposure/{view.go,cases.go,metrics.go}                # Tasks 11, 12, 14, 16
internal/settings/clusters.go, internal/agent/cases/, internal/agent/worker/claim.go, cmd/agent-replay/   # Task 13
internal/spoke/{reports.go,render.go,presence.go,exposure.go,metrics.go,counts.go,running.go,remote_reports.go}   # Tasks 15, 16
config/hub/, config/spoke/                                     # Task 17
Makefile, test/e2e/, test/utils/                               # Tasks 2, 9, 18
hack/measure-6/, docs/measurements/2026-phase6.md              # Task 19
README.md, docs/collectors.md, docs/agent.md, docs/remote-spokes.md   # Tasks 5, 17, 20
```

## Task order

`make test` stays green after every task, and the e2e suite after each task that runs it.
- **Task 0:** the record.
- **Tasks 1 to 3:** run 6's lessons: the flaky tests, the upgrade's dip, and a `Collector`'s deletion.
- **Task 4:** the modes, and `WrongRole`.
- **Tasks 5 and 6:** the scanner serves the hub, then a request names the platforms.
- **Tasks 7 to 9:** the `Spoke` API, connecting with the token, and the hub's access on a spoke.
- **Tasks 10 and 11:** the copier, then the namespace labels.
- **Tasks 12 to 14:** the rules across clusters: producers, the cluster match, and ambiguous addresses.
- **Tasks 15 and 16:** the renderer's inputs, then the remote metrics.
- **Task 17:** the installs per mode, and the guide to adding a spoke.
- **Task 18:** end to end, on two kind clusters.
- **Task 19:** the measurement, on three kind clusters.
- **Task 20:** the docs, and "As built".
- **Task 21:** the hand-over.

---

### Task 0: The record

- [ ] **Commit** the design, its records, the notes in earlier records and designs, and this plan, on `docs/phase6-remote-spokes`: `docs: design and plan phase 6, remote spokes`.
- [ ] **Create `feat/phase6-remote-spokes`** from `main` (`78c0b36`), and pick that commit onto it.
- [ ] **Run** `make test` on it. Expected: PASS, as `main` left it, apart from the two flaky tests that Task 1 fixes.

### Task 1: The two flaky tests (design 5.12)

**Files:**
- `internal/controller/config/collector_api_test.go` (~:451-459);
- `internal/rules/engine/{exposure_test.go,engine_test.go}`.

- [ ] **The update conflict:** the spec "refuses to turn a Collector of a package into one of an MCP server, or back" sends an `Update` with the create's resource version. The manager's finalizer or status write may bump it first, and then the API server answers 409 before it validates. Send a merge patch (`client.MergeFrom(base)`) instead, which carries no resource version. The transition rule `has(oldSelf.mcp) == has(self.mcp)` still refuses it with 422.
- [ ] **The cost limit:** the entry "it hits the cost limit" of `TestAFailingRuleCountsAsUnknown` may pass the 1-second run bound under `-race` or load, and then counts as a time-out. Give that subtest `t.Cleanup(engine.SetBounds(time.Hour, time.Hour))`. Do the same in the two tests with the same latent race: `engine_test.go` ~:358-362 ("cost limit exceeded") and ~:658-668 (`TimedOut` 0 and `Timely()`).
- [ ] **Run** `go test -race -count=20 ./internal/rules/engine/`, and the envtest suite of `internal/controller/config/` three times. Expected: PASS every time.
- [ ] **Gate, then commit:** `test: take the races out of two flaky tests`.

### Task 2: The results' dip after an upgrade (design 5.12, decision 19)

**Files:**
- `internal/controller/hub/{assessor.go,assessor_test.go}`;
- `test/e2e/e2e_test.go` (a context "Upgrade").

- [ ] **Write the failing e2e spec**, `Context("Upgrade")`, once an investigation has results:
  - restart the manager and the `vulnerabilities` collector at once (`kubectl rollout restart` of both Deployments), as an upgrade does;
  - every 10 seconds for 10 minutes, read the number of `ImageVerdicts`, the investigation's `status.cases.total`, and the sum of `vexplain_open_case`;
  - expect none of the three to fall below its value before the restart, once the manager's metrics answer again.
- [ ] **Run** it. Expected: FAIL. Write down which of the three dips, and for how long.
  - If the sheets stay and only the series dip, or the verdicts turn stale, stop and report: that is another cause (the report series that start empty, or an input hash that changed between builds), and its fix is decided then.
- [ ] **Write the failing unit test** `TestAMatcherThatCannotAnswerAfterAStartKeepsTheSheets` (assessor_test.go): a sheet that omits findings, an assessor with an empty memory, and a findings producer that answers `NotReady`. Expected: the sheet stays, and the manifest is asked again after the `NotReady` wait.
- [ ] **Implement:** a match that fails because its findings producer can't answer (it can't be reached, or answers `NotReady`) never deletes a sheet. The sheet keeps its findings until a match succeeds. Any other failed match keeps today's rule.
- [ ] **Run** the unit test, then the e2e spec. Expected: PASS.
- [ ] **Gate, run `make test-e2e`, then commit:** `fix(hub): keep the sheets while the matcher can't answer after a start`.

### Task 3: Deleting a `Collector` keeps the other clusters' records (design 5.5, decision 18)

**Files:**
- `internal/evidence/{store.go,crdstore.go,crdstore_test.go}`;
- `internal/controller/config/collector_controller_test.go`.

**Interfaces:**
- Produces: `Store.DeleteBySource(ctx context.Context, source string) error`, unchanged in its signature. It deletes the source's asked evidence (no cluster label), and its streamed records of the store's own cluster only.

- [ ] **Write the failing tests:**
  - **`TestDeleteBySourceKeepsOtherClustersRecords`** (crdstore_test.go) replaces the claim of `TestDeleteBySourceRemovesOnlyThatCollectorsRecords` that every cluster's records go:
    - records of `scanner`: one asked, one streamed in `cluster-a` (the store's own), one streamed in `cluster-b`;
    - one record of another source;
    - after `DeleteBySource("scanner")`, only `cluster-b`'s and the other source's remain.
  - **`collector_controller_test.go`** (~:343): deleting a `Collector` leaves a record of its name in `cluster-b`.
- [ ] **Run** them. Expected: FAIL.
- [ ] **Implement:**
  - list the metadata twice, with the selectors `vexplain.bedag.ch/collector=<source>,!vexplain.bedag.ch/cluster` and `vexplain.bedag.ch/collector=<source>,vexplain.bedag.ch/cluster=<own>`;
  - delete as today;
  - update `DeleteBySource`'s doc.
- [ ] **Run** them again. Expected: PASS.
- [ ] **Gate, then commit:** `fix(evidence): a collector's deletion keeps other clusters' records`.

### Task 4: Modes, and `WrongRole` (design 5.1, decisions 1 and 2)

**Files:**
- `cmd/{main.go,main_test.go}`;
- `internal/setup/{mode.go,mode_test.go}` (new), `internal/setup/{setup.go,register_test.go}`;
- `internal/spoke/executor.go` (no presence in `Hub`);
- `internal/controller/config/{collector_controller.go,collector_controller_test.go}`;
- `api/config/v1alpha1/collector_types.go` (the reason);
- `internal/collectorclient/pool.go` (`Usable`'s doc);
- `docs/collectors.md` (roles and modes).

**Interfaces:**
- Produces:
  - `type setup.Mode string`, with `ModeHub = "Hub"`, `ModeSpoke = "Spoke"` and `ModeHubAndSpoke = "HubAndSpoke"`;
  - `func setup.ParseMode(s string) (Mode, error)`. The empty string is `HubAndSpoke`;
  - `func (m Mode) Runs(role configv1alpha1.CollectorRole) bool`;
  - `setup.Options.Mode Mode`;
  - `configv1alpha1.ReasonWrongRole = "WrongRole"`;
  - `CollectorReconciler.Runs func(configv1alpha1.CollectorRole) bool`. A nil `Runs` runs every role;
  - `spoke.NewExecutor` takes a nil `*Presence`: no local pods, and no wait for presence.
- What each mode starts in `Register`:

  | Part | `Hub` | `Spoke` | `HubAndSpoke` |
  |---|---|---|---|
  | `OperatorConfig`, the stores, the collector pool and the deployer | yes | yes | yes |
  | presence, exposure, the store sink, and the spoke role's streams | no | yes | yes |
  | the hub role's streams (the findings collector) | yes | no | yes |
  | the executor | yes | no | yes |
  | the reports renderer | no | no | yes |
  | the hub's controllers and the agent's certificate | yes | no | yes |
  | the gauge of running images | yes | yes | yes |
  | the `Spoke` controller and the remote renderer (Tasks 8 to 16) | yes | no | yes |

- [ ] **Write the failing tests:**
  - **`TestParseMode`** (mode_test.go): the three names and the empty string; `hub` is refused, since case matters.
  - **`TestEachModeRunsItsRoles`:** `Hub` runs only `Hub`, `Spoke` only `Spoke`, and `HubAndSpoke` both.
  - **`TestEachModeStartsItsParts`** (register_test.go), with `testenv.Start(setup.Options{Mode: …})`:
    - in `Spoke`, a presence snapshot of `workloads` writes an `ImageInventory` entry, and no `ImageVerdicts` appear;
    - in `Hub`, a `Playbook` turns Ready, and no presence entry is written.
  - **`TestACollectorOfARoleTheModeDoesNotRunIsWrongRole`** (collector_controller_test.go): with `Runs` for `Hub`, a collector whose capabilities name only the spoke role turns Ready False with `WrongRole`, and `collectorclient.Usable` says false.
  - **`cmd/main_test.go`:** `--mode=Spoke` gives `Options{OperatorNamespace: …, Mode: ModeSpoke}`, and a mode that doesn't parse fails the start.
- [ ] **Run** them. Expected: FAIL.
- [ ] **Implement:**
  - the flag `--mode` in `cmd/main.go`, with the default `HubAndSpoke`;
  - `Register` starts the parts in the table, and passes `opts.Mode.Runs` to the `CollectorReconciler`;
  - the reconciler sets `WrongRole` after it records the capabilities;
  - `Usable`'s doc loses "(from phase 6)".
- [ ] **Run** them again. Expected: PASS, and the whole suite passes as before, since `HubAndSpoke` is today's behaviour.
- [ ] **Gate, run `make test-e2e`, then commit:** `feat: the modes Hub, Spoke and HubAndSpoke, and WrongRole`.

### Task 5: The scanner serves the hub, and scans the platforms a request names (0066, design 5.6, decisions 3 and 4)

**Files:**
- `collectors/scanner/internal/scan/{operation.go,credentials.go,platforms.go,operation_test.go,credentials_test.go,platforms_internal_test.go,testdata/capabilities.json}`;
- `internal/collectorclient/{pool.go,pool_test.go}`;
- `internal/spoke/{executor.go,executor_test.go}`;
- `internal/setup/chain/capabilities_test.go`;
- `docs/collectors.md`.

**Interfaces:**
- Produces:
  - **the scanner's `Capabilities`:** `Roles: [RoleHub]`, and the operation `scan` with `Role: RoleHub`;
  - **the operation's parameters:**
    - `repositories`: required, 1 to 256, as today;
    - `platforms`: optional, 1 to 16, each matching `^[a-z0-9]+/[a-z0-9_]+(/[a-z0-9]+)?$`;
    - `pods`: optional, at most 16, as today;
    - in Go: `type parameters struct { Repositories []string; Platforms []string; Pods []podRef }`;
  - **`CredentialSource.Credentials(ctx, pod *corev1.Pod, repository string, admin []string)`** takes a nil `pod`, and then gives only the admin's logins;
  - **`collectorclient.OperationFor`** requires the hub role, and the executor calls with `collectorv1alpha1.Role_ROLE_HUB`.

- [ ] **Write the failing tests:**
  - **`TestTheScanOfPlatformsWithoutPodsTakesTheAdminsLogins`** (operation_test.go): with `{repositories: [localhost:5001/app], platforms: [linux/amd64, linux/arm64]}` and no pods, the Job is created with both platforms, and its Secret holds only the admin's login.
  - **`TestTheScanJoinsThePodsAndTheRequestsPlatforms`:** a pod on a `linux/amd64` node and `platforms: [linux/arm64]` scan both, each once.
  - **`TestTheScanFailsWhenItNamesNeitherARunningPodNorAPlatform`**, renamed from `TestTheScanFailsWhenNoPodOfTheRequestRunsTheDigest`: `NotRunning`.
  - **`TestCredentialsWithoutAPodAreTheAdminsOnly`** (credentials_test.go).
  - **`TestOperationForNeedsTheHubRole`** (pool_test.go): a collector in the spoke role only can't be asked.
  - **`TestTheCapabilitiesAreTheGoldenFile`:** rewrite the golden file with `-update`, and check that it names the hub role.
- [ ] **Run** them. Expected: FAIL.
- [ ] **Implement:**
  - the scan's platforms are the request's, joined with those of its pods' nodes, sorted and unique;
  - without pods, the scan pulls from the first repository, or its mirror;
  - a result's manifests keep today's check: each must be of a platform that the scan asked for.
- [ ] **Run** them again, then `make test`. Expected: PASS. The executor's tests and `internal/setup/chain` follow the new role.
- [ ] **Docs:** in `docs/collectors.md`, the scanner's role and its `platforms`.
- [ ] **Gate, run `make test-e2e`, then commit:** `feat(scanner): serve the hub, and scan the platforms a request names`.

### Task 6: A request names the platforms that run the image anywhere (0066, design 5.6, decision 5)

**Files:**
- `internal/tasks/tasks.go`;
- `internal/controller/hub/{assessor.go,assessor_test.go}`;
- `internal/spoke/{executor.go,executor_test.go}`.

**Interfaces:**
- Consumes: Task 5's `platforms`.
- Produces:
  - `tasks.Request.Platforms []string`;
  - `func platformsOf(obj *inventoryv1alpha1.ImageInventory) []string` (assessor.go, beside `repositoriesOf`): every `status.clusters[].platforms`, sorted and unique, at most 16;
  - **what the executor sends:** `{repositories, platforms, pods}`, with the local pods when the image runs in the hub's own cluster.
    - It asks the scanner when the request names platforms, even when no local pod runs the image.
    - With neither platforms nor local pods, it does what it does today: nothing.

- [ ] **Write the failing tests:**
  - **`TestARequestNamesThePlatformsOfEveryCluster`** (assessor_test.go): entries of `cluster-a` on `linux/amd64` and of `cluster-b` on `linux/arm64` give `Platforms: [linux/amd64, linux/arm64]`.
  - **`TestAnImageThatNoLocalPodRunsIsScannedForTheRequestsPlatforms`** (executor_test.go): without presence, the scanner gets the platforms and no pods.
  - **`TestTheLocalPodsComeWithThePlatforms`:** with presence, it gets both.
  - **`TestARefusedPullLeavesTheFactsFailedWithTheRegistry`:**
    - the scanner answers `Unauthorized` with the registry named;
    - the facts record that failure, and no evidence is stored, so the image gets no sheet. It has no verdict, and doesn't look clean.
- [ ] **Run** them. Expected: FAIL.
- [ ] **Implement.**
- [ ] **Run** them again, then `make test`. Expected: PASS.
- [ ] **Gate, run `make test-e2e`, then commit:** `feat(hub): ask for every platform that runs an image in any cluster`.

### Task 7: The `Spoke` API (0064, design 5.2, 5.3)

**Files:**
- `api/config/v1alpha1/{spoke_types.go,zz_generated.deepcopy.go}`, and `config/crd/` (generated);
- `config/rbac/`: the kind's admin, editor and viewer roles, as the other kinds of `config` have;
- `config/samples/config_v1alpha1_spoke.yaml`;
- `internal/controller/config/spoke_api_test.go` (new, envtest).

**Interfaces:**
- Produces:
```go
type SpokeSpec struct {
	Labels               map[string]LabelValue `json:"labels,omitempty"`               // as OperatorConfig.clusterLabels: MaxProperties 32, and its two CEL rules
	CredentialsSecretRef SecretReference       `json:"credentialsSecretRef,omitzero"` // +required: the admin's Secret, in the operator's namespace
}
type SpokeCollector struct {
	Name         string                 `json:"name,omitempty"`         // +required
	Version      *string                `json:"version,omitempty"`
	Ready        metav1.ConditionStatus `json:"ready,omitempty"`        // True, False or Unknown
	Capabilities *CollectorCapabilities `json:"capabilities,omitempty"` // each produced type with its effective maxAgeSeconds
}
type SpokeStatus struct {
	Conditions          []metav1.Condition `json:"conditions,omitempty"` // listType=map, key type, MaxItems 8
	ObservedGeneration  *int64             `json:"observedGeneration,omitempty"`
	ClusterID           *string            `json:"clusterID,omitempty"`
	Collectors          []SpokeCollector   `json:"collectors,omitempty"` // listType=map, key name, MaxItems 64
	LastSyncTime        *metav1.Time       `json:"lastSyncTime,omitempty"`
	TokenExpirationTime *metav1.Time       `json:"tokenExpirationTime,omitempty"`
}
```
  - `ConditionConnected = "Connected"`, `ConditionSynced = "Synced"`, and the reasons `ReasonUnreachable`, `ReasonCredentialsInvalid`, `ReasonIdentityChanged`, `ReasonTokenExpired` and `ReasonSyncing`;
  - markers: cluster-scoped, `categories=vexplain`, the status subresource, and the print columns Ready, Reason, Last sync and Age, as `ModelConfig` has them.

- [ ] **Write the failing envtest specs** (spoke_api_test.go):
  - a `Spoke` without `credentialsSecretRef` is refused;
  - a label that `OperatorConfig.clusterLabels` refuses is refused here too;
  - a name longer than 63 characters, or one that isn't a DNS label, is refused, since it is the cluster's name;
  - `status.clusterID` may be set and cleared, but not changed to another value.
- [ ] **Run** them. Expected: FAIL.
- [ ] **Implement** the type, with these CEL rules, then run `make manifests generate`:
  - on the kind: `self.metadata.name.size() <= 63 && self.metadata.name.matches('^[a-z0-9]([-a-z0-9]*[a-z0-9])?$')`;
  - on the status: `!has(oldSelf.clusterID) || !has(self.clusterID) || self.clusterID == oldSelf.clusterID`.
- [ ] **Run** them again. Expected: PASS.
- [ ] **Gate, then commit:** `feat(api): the Spoke record`.

### Task 8: Connecting to a spoke: the seam and the token (0061, 0062, design 5.4, decisions 6 to 8)

**Files:**
- `internal/remote/{connect.go,connect_test.go,token.go,token_test.go,suite_test.go}` (new; two envtest API servers);
- `internal/controller/config/{spoke_controller.go,spoke_controller_test.go}` (new);
- `internal/setup/setup.go`, and `cmd/main.go` (`--spoke-token-lifetime`).

**Interfaces:**
- Consumes: Task 7's `Spoke`.
- Produces:
  - **`func remote.Config(ctx context.Context, c client.Reader, namespace string, spoke *configv1alpha1.Spoke) (*rest.Config, error)`, the one seam:**
    - it reads the admin's Secret (`server`, `ca.crt`, `token`) and the hub's own (`spoke-<name>-token`);
    - TLS is verified against `ca.crt`;
    - the token is the hub's own while it is valid, else the admin's;
  - **`func remote.TokenSecretName(spoke string) string`;**
  - **the renewer:**
    - `type remote.Renewer struct { Client client.Client; Namespace string; Lifetime time.Duration; Now func() time.Time; Request TokenRequester }`;
    - `func (r *Renewer) Renew(ctx context.Context, spoke *configv1alpha1.Spoke, cfg *rest.Config) (expires time.Time, err error)`;
    - `type remote.TokenRequester func(ctx context.Context, cfg *rest.Config, namespace, serviceAccount string, seconds int64) (token string, expires time.Time, err error)`. The default calls the spoke's `TokenRequest`;
    - the ServiceAccount to renew comes from the current token's claims, `kubernetes.io.serviceaccount.{name,namespace}`;
  - **`SpokeReconciler`** (`internal/controller/config`) handles:
    - the finalizer `vexplain.bedag.ch/spoke`;
    - the identity, and `Connected`;
    - the renewal at half the token's lifetime, `TokenExpired`, and `status.tokenExpirationTime`;
    - Ready, Reconciling and Stalled, for kstatus;
  - **`setup.Options.SpokeTokenLifetime time.Duration`**, from `--spoke-token-lifetime`: 24 hours by default, and at least 10 minutes.

- [ ] **Write the failing tests**, with two envtest API servers, "hub" and "spoke":
  - **`TestTheSeamVerifiesTheSpokesCertificate`:** a `ca.crt` of another CA fails with an x509 error, and nothing turns the check off.
  - **`TestTheHubKeepsItsOwnTokenWhenTheAdminsSecretIsAppliedAgain`:** the admin's Secret is written again with its expired bootstrap token, and the hub still connects with its own.
  - **`TestTheRenewedTokenGoesIntoTheHubsOwnSecret`:** the admin's Secret is unchanged, and the hub's Secret has the label `vexplain.bedag.ch/spoke` and is owned by the `Spoke`.
  - **`TestTheTokenIsRenewedAtHalfItsLifetime`**, with a fake clock and a fake `TokenRequester`.
  - **`TestAnExpiredTokenMarksTheSpokeTokenExpired`.**
  - **`TestAnotherClusterIDStopsTheSpoke`:** the first contact records the spoke's `kube-system` UID. A Secret that then points at another API server gives `Connected` False with `IdentityChanged`.
  - **`TestASpokeThatCannotBeReachedIsUnreachable`.**
- [ ] **Run** them. Expected: FAIL.
- [ ] **Implement:**
  - the reconciler requeues at the renewal time, and checks the connection every minute;
  - if envtest's API server doesn't serve `TokenRequest`, the real call is covered by the end-to-end test (Task 18).
- [ ] **Run** them again. Expected: PASS.
- [ ] **Gate, then commit:** `feat(remote): connect to a spoke, and renew its token`.

### Task 9: The hub's access on a spoke (0062, design 5.4, decision 9)

**Files:**
- `internal/remote/hubaccess/rbac.go` (new: markers only);
- `Makefile`: in `manifests`, `$(CONTROLLER_GEN) rbac:roleName=hub-reader paths=./internal/remote/hubaccess/... output:rbac:artifacts:config=config/rbac/hub-access`, with that package left out of the manager's packages;
- `config/rbac/hub-access/{role.yaml,service_account.yaml,cluster_role_binding.yaml,role_binding.yaml,kustomization.yaml}`, where `role.yaml` is generated, the ClusterRole and the Role both;
- `internal/setup/install_test.go`.

**Interfaces:**
- Produces, on a spoke, after the name prefix:
  - the ServiceAccount `vexplain-hub`;
  - the ClusterRole `vexplain-hub-reader`: `get`, `list` and `watch` on `evidences`, `imageinventories`, `collectors`, `operatorconfigs` and `namespaces`, and nothing else;
  - the Role `vexplain-hub-reader` in the operator's namespace, from a marker with `namespace=` and `resourceNames=vexplain-hub`: `create` on `serviceaccounts/token` for `vexplain-hub` only.

- [ ] **Write the failing test** **`TestTheHubsAccessOnASpokeOnlyReads`** (install_test.go):
  - the ClusterRole has only those verbs on those resources;
  - the Role has only that `create`;
  - the manager's role is unchanged.
- [ ] **Run** it. Expected: FAIL.
- [ ] **Implement,** then run `make manifests`.
- [ ] **Run** it again. Expected: PASS.
- [ ] **Gate, then commit:** `feat(rbac): the hub's read-only access on a spoke`.

### Task 10: Copying a spoke's records (0063, design 5.5, decisions 10 and 11)

**Files:**
- `internal/remote/{copier.go,copier_test.go}` (new);
- `internal/controller/config/spoke_controller.go`: the cache, `Synced`, `status.lastSyncTime`, `status.collectors`, and the finalizer;
- `internal/inventory/{store.go,crdstore.go,crdstore_test.go}` (`Observation.WorkloadCount`);
- `internal/metrics/metrics.go` (`vexplain_spoke_records_refused_total`).

**Interfaces:**
- Consumes: Task 8's `remote.Config`.
- Produces:
  - **`inventory.Observation.WorkloadCount int32`:** when it is above 0, it is the entry's count, over the listed workloads;
  - **`type remote.Copier`**, one per `Spoke`, with `func remote.NewCopier(spoke, clusterID string, hubEvidence evidence.Store, hubInventory inventory.Store, spokeCluster cluster.Cluster) *Copier` and `func (c *Copier) Sync(ctx context.Context) error`. What it copies:
    - **streamed records:** each spoke `Evidence` with the label `vexplain.bedag.ch/cluster=<spoke>`, whose source's `Collector` declares its type `Hub` in its recorded capabilities, goes to `Put(ctx, source, version, event, InCluster(spoke))` on the hub, and its deletion to `Delete`;
    - **after each sync of the spoke's caches,** per source and type, `DeleteStreamed(ctx, spoke, source, type, keep)`, keeping what the spoke holds;
    - **entries:** each `ImageInventory` entry of the spoke's cluster and cluster ID goes to `Observe(ctx, digest, obs)` with `WorkloadCount` and `MaxNamespaces: 1000`. An entry that is gone goes to `Forget(ctx, digest, spoke, clusterID)`;
    - **a type that the spoke no longer declares `Hub`** has its copies deleted;
  - **`Spoke.status.collectors`:** each produced type with its effective `maxAgeSeconds`, from `collectorclient.MaxAge` on the spoke's `Collector`;
  - **`vexplain_spoke_records_refused_total{cluster, reason}`,** with the reasons `cluster`, `clusterID`, `scope` and `invalid`;
  - **the finalizer** deletes every copy of the cluster: `DeleteStreamed` per source and type with nothing kept, and `Forget` of every entry.

- [ ] **Write the failing tests**, with two envtest API servers:
  - `TestTheHubCopiesASpokesStreamedRecordsUnderItsCluster`;
  - `TestTheHubCopiesOnlyTypesTheSpokeDeclaresHub`;
  - `TestARecordOfAnotherClusterIsRefusedAndCounted`;
  - `TestAnEntryOfAnotherClusterIDIsRefused`;
  - `TestAnIdentityChangedSpokeCopiesNothing`;
  - `TestACopiedEntryKeepsItsWorkloadCountAbove100`: an entry that lists 100 of its 250 workloads;
  - `TestASyncDeletesWhatTheSpokeNoLongerHolds`;
  - `TestAnUnchangedSyncWritesNothing`: the store's write counter stays;
  - `TestAnUnreachableSpokeKeepsItsCopies`: the spoke's API server stops, the copies stay, and `Connected` is False;
  - `TestDeletingTheSpokeDeletesItsCopies`;
  - `TestTheSpokesCollectorsAreMirroredWithTheirEffectiveMaxAge`: a `spec.produces` override wins.
- [ ] **Run** them. Expected: FAIL.
- [ ] **Implement:**
  - the `Spoke` controller starts a `cluster.Cluster` on the seam's config, with `Evidence` limited to the cluster label and namespaces as metadata only;
  - it stops that cluster when the `Spoke` or its Secret changes;
  - informer events drive the copies, and `Synced` turns True after the first round.
- [ ] **Run** them again. Expected: PASS.
- [ ] **Gate, then commit:** `feat(remote): copy a spoke's records into the hub's stores`.

### Task 11: The spoke's namespace labels (design 5.5, decision 12)

**Files:**
- `sdk/subject/{subject.go,subject_test.go}`;
- `sdk/evidence/{types.go,schemas/ch.bedag.vexplain.namespace.v1alpha1.json}`;
- `internal/remote/{namespaces.go,copier_test.go}`;
- `internal/exposure/{view.go,view_test.go}`.

**Interfaces:**
- Produces:
  - `subject.KindNamespace = "namespace"`, and `func subject.Namespace(cluster, name string) (string, error)`, which gives `namespace/<cluster>/<name>`, each a DNS label;
  - `evidence.TypeNamespace = "ch.bedag.vexplain.namespace.v1alpha1"`, with `type NamespaceLabels struct { Labels []KeyValue \`json:"labels"\` }`;
  - the copier puts one record per spoke namespace, from the source `vexplain`, `InCluster(spoke)`, and takes a snapshot of them after each sync;
  - `func (v *View) NamespaceLabels(cluster, namespace string) (map[string]string, bool)`.

- [ ] **Write the failing tests:**
  - `TestNamespaceSubjects`: the subject's round trip, and what it refuses;
  - `TestTheHubCopiesTheSpokesNamespaceLabels`: a label's change rewrites the record, and a deleted namespace deletes it;
  - `TestTheViewHoldsNamespaceLabelsPerCluster`.
- [ ] **Run** them. Expected: FAIL.
- [ ] **Implement.**
- [ ] **Run** them again. Expected: PASS.
- [ ] **Gate, then commit:** `feat(remote): copy a spoke's namespace labels`.

### Task 12: A workload's evidence comes from its own cluster's collectors (0064, design 5.7, decision 20)

**Files:**
- `internal/exposure/{cases.go,cases_test.go}`;
- `internal/controller/hub/{investigation.go,playbook_controller.go,playbook_controller_test.go}`.

**Interfaces:**
- Produces:
  - **`exposure.PlaybookExposure.Producers map[string]map[string][]string`:** the producers' names, by piece and then by cluster, pins included. A source counts for every cluster, under the key `""`;
  - **`exposure.PlaybookExposure.MaxAges map[[3]string]time.Duration`,** keyed by cluster, collector and type, from the local `Collector`s and from each `Spoke`'s `status.collectors`. `caseExposures.maxAge` reads it instead of the local `Collector`;
  - **the check's order:** `checkPlaybook` finds `workloadEvidence` before `checkProducers`;
  - **`need`** counts a workload type's producers in every cluster: the local `Collector`s, and those that each `Spoke` lists. An image type counts only the local ones, as today;
  - **the playbook controller watches `Spoke`s,** and checks each playbook again when a `Spoke`'s collectors change.

- [ ] **Write the failing tests:**
  - **`TestAWorkloadReadsOnlyItsOwnClustersProducers`** (cases_test.go):
    - `network-reach` runs in `cluster-a` only;
    - a workload of `cluster-b` gets one missing input, not one input per producer of `cluster-a`;
    - the rules' combinations don't grow.
  - **`TestARemoteRecordExpiresByItsSpokesMaxAge`.**
  - **`TestAPlaybookIsReadyWhenASpokeProducesItsWorkloadType`** (playbook_controller_test.go): exposure is produced only on a `Spoke`, and the scanner runs locally.
  - **`TestAPlaybookIsNotReadyWhenOnlyASpokeProducesAnImageType`.**
- [ ] **Run** them. Expected: FAIL.
- [ ] **Implement:**
  - `playbookExposure` (investigation.go ~:541-573) builds the producers per cluster with `countsForExposure`;
  - `inputsOf` (cases.go ~:134-160) takes those of `parsed.Workload.Cluster`, and the sources.
- [ ] **Run** them again. Expected: PASS.
- [ ] **Gate, then commit:** `feat(hub): a workload's evidence comes from its own cluster's collectors`.

### Task 13: A playbook's cluster match, per cluster (design 5.8, decision 21)

**Files:**
- `internal/controller/hub/{playbook_controller.go,assessor.go,janitor.go}`, and their tests;
- `internal/settings/{clusters.go,clusters_test.go}` (new);
- `internal/agent/cases/{select.go,impact.go,impact_test.go}`;
- `api/triage/v1alpha1/assessment_types.go` (`status.queue.runsIn.clusters`);
- `internal/agent/worker/{claim.go,claim_test.go}`, and `cmd/agent-replay/export.go`.

**Interfaces:**
- Produces:
  - **`func settings.ClusterLabels(ctx context.Context, r client.Reader) (map[string]map[string]string, error)`:** the labels of the hub's own cluster (from `OperatorConfig`) and of each `Spoke`, by the cluster's name;
  - **`func judgesIn(playbook *configv1alpha1.Playbook, labels map[string]map[string]string, clusters []string) bool`:** true when one of the clusters matches. `judges` stays, for one cluster;
  - **the subject's clusters:** the assessor's and the janitor's `judging` take them. For an image, they are its `status.clusters`. For a manifest, they are the clusters of each digest whose facts name it, on the manifest's platform, as `runsOn` does;
  - **`cases.Selection.Clusters []string`:** nil counts every cluster. Otherwise `presenceOf` skips the other entries (impact.go ~:75, before `runsOn`);
  - **the matching clusters in the queue:** the hub writes them into `Assessment.status.queue.runsIn.clusters`, and the worker and `agent-replay` select with them.

- [ ] **Write the failing tests:**
  - `TestJudgesInMatchesWhenOneClusterMatches`;
  - `TestASheetStaysWhileOneMatchingClusterRunsTheImage`: the assessor and the janitor agree;
  - `TestACaseCountsOnlyTheMatchingClustersWorkloads` (impact_test.go);
  - `TestAnImageThatRunsOnlyInClustersThatDoNotMatchIsNotRunningForThePlaybook`, with `SkipNotRunning`;
  - `TestTheWorkerSelectsTheQueuedClusters` (claim_test.go).
- [ ] **Run** them. Expected: FAIL.
- [ ] **Implement,** then run `make manifests generate`.
- [ ] **Run** them again. Expected: PASS.
- [ ] **Gate, run `make test-e2e`, then commit:** `feat(hub): judge an image by the clusters that run it`.

### Task 14: An address that two clusters name gets no answer (design 5.10, decision 22)

**Files:** `internal/exposure/{view.go,cases.go,metrics.go}`, and their tests.

**Interfaces:**
- Produces:
  - `func (v *View) Ambiguous() map[string][]string`: each `address/` subject that two or more clusters' exposure names, with those clusters. Host names never count;
  - `caseExposures.answers` treats an ambiguous address as unanswered (`Present: false`), so the rules get no answer for it;
  - the state `ambiguous` of `vexplain_entry_points`, per cluster.

- [ ] **Write the failing tests:**
  - `TestAnAddressThatTwoClustersNameIsAmbiguous`;
  - `TestAHostThatTwoClustersNameIsNot`;
  - `TestAnAmbiguousAddressGivesTheRulesNoAnswer`: a source that answers `Internal` for it doesn't lower the exposure;
  - `TestAmbiguousAddressesAreCountedPerCluster`.
- [ ] **Run** them. Expected: FAIL.
- [ ] **Implement** in `byCluster` (view.go ~:431-454), `answers` (cases.go ~:166-182) and `measure` (metrics.go ~:35-62).
- [ ] **Run** them again. Expected: PASS.
- [ ] **Gate, then commit:** `feat(exposure): no answer for an address that two clusters name`.

### Task 15: The renderer reads what runs through an interface (0065, design 5.9)

**Files:** `internal/spoke/{reports.go,render.go,presence.go,exposure.go,metrics.go,running.go}`, and their tests; `running.go` is new.

**Interfaces:**
- Produces:
  - **`type spoke.Running interface`**, which `*Presence` implements:
    - `KnowsWhatRuns(ctx context.Context) (bool, error)`;
    - `RunningReports() []types.NamespacedName`;
    - `Running(namespace, report string) (RunningWorkload, bool)`;
    - `Workloads(image string) []sdkevidence.PresenceWorkload`;
    - `ExposureKnown(ctx context.Context) (bool, error)`;
    - `ExposureOf(w sdkevidence.PresenceWorkload) WorkloadExposure`;
  - **`func spoke.IndexRunning(images map[string]sdkevidence.Presence) map[types.NamespacedName]RunningWorkload`:** what `runningLocked` builds today, as a function;
  - **`func spoke.WorkloadExposureOf(records ...sdkevidence.Exposure) WorkloadExposure`:** what `Exposure.ForReport` decides today, as a function;
  - **`ReportsCollector`** keyed by cluster, namespace and report, with `func (c *ReportsCollector) Forget(cluster string)`.

- [ ] **Write the failing tests:**
  - `TestIndexRunningIsWhatPresenceIndexes`: the same events give the same index both ways;
  - `TestTwoClustersSeriesOfTheSameWorkloadStayApart`: a workload of the same namespace and name in `cluster-a` and `cluster-b` gives two sets of series, and `Forget("cluster-b")` drops only its own.
- [ ] **Run** them. Expected: FAIL.
- [ ] **Implement:** the renderer takes a `Running`, and `*Presence` keeps its behaviour. The existing renderer tests pass unchanged.
- [ ] **Run** them again, then `make test`. Expected: PASS.
- [ ] **Gate, then commit:** `refactor(spoke): the renderer reads what runs through an interface`.

### Task 16: The hub renders each remote cluster's metrics (0065, design 5.9, decisions 13 to 17 and 24)

**Files:**
- `internal/remote/{running.go,running_test.go,metrics.go}` (new);
- `internal/exposure/{view.go,view_test.go}`;
- `internal/spoke/{remote_reports.go,remote_reports_test.go}` (new), and `internal/spoke/counts.go`;
- `internal/inventory/{gauge.go,gauge_test.go}`;
- `internal/setup/setup.go`.

**Interfaces:**
- Consumes: Task 11's `View.NamespaceLabels`, and Task 15's `Running`, `IndexRunning` and `WorkloadExposureOf`.
- Produces:
  - **the view keeps presence's data,** and gains:
    - `func (v *View) PresenceIn(cluster string) map[string]sdkevidence.Presence`;
    - `func (v *View) ExposuresOf(workload string) []sdkevidence.Exposure`;
  - **`func remote.RunningIn(view *exposure.View, cluster string) spoke.Running`:** what runs in a remote cluster, from the view. It knows what runs once the view has read the store, whether or not the spoke can be reached;
  - **the controller `remote-reports`:**
    - `type spoke.RemoteReports`;
    - `func spoke.NewRemoteReports(mgr ctrl.Manager, clusters func(ctx context.Context) ([]RemoteCluster, error), store inventory.Store, verdicts inventory.VerdictsStore, playbooks inventory.Playbooks, counts inventory.CountsStore) *RemoteReports`;
    - `type RemoteCluster struct { Name string; Labels map[string]string; Running Running; NamespaceLabels func(namespace string) (map[string]string, bool) }`;
  - **what the controller renders:**
    - what each remote workload's report would say, in memory only, and its series under the cluster's name;
    - it forgets a workload's series when the workload leaves the copies, and every series of a deleted `Spoke`;
    - it uses the `Spoke`'s labels for `playbooksFor`, and the hub's urgency table;
    - the metrics source `remote-reports`, and each remote cluster's counts (`writeCounts(ctx, cluster)`);
  - **`GaugeUpdater.Clusters func(ctx context.Context) ([]Cluster, error)`,** with `type Cluster struct{ Name, ID string }`: one reset per round, then a series per cluster;
  - **`type remote.SpokesCollector`,** the metrics source `spokes`: `vexplain_collector_ready{cluster, collector}` from each `Spoke`'s `status.collectors`;
  - **`vexplain_remote_images_without_presence{cluster}`:** the images with an entry of the cluster, but no copy of its presence record.

- [ ] **Write the failing tests:**
  - `TestARemoteWorkloadGetsItsSeries`: `vexplain_open_case{cluster="cluster-b"}`, and no `ResourceReport` is written;
  - `TestARemoteClustersSeriesUseTheSpokesLabelsAndNamespaceLabels`: one playbook that matches only `cluster-b`, and one that matches a namespace label;
  - `TestARemoteWorkloadsSeriesGoWithIt`;
  - `TestDeletingTheSpokeDeletesItsSeriesAndCounts`;
  - `TestRemoteSeriesRenderFromTheCopiesAfterAStart`: no spoke can be reached;
  - `TestTheGaugeCountsEveryCluster`;
  - `TestARemoteImageWithoutPresenceIsCounted`;
  - `TestARemoteCollectorsReadinessIsASeries`.
- [ ] **Run** them. Expected: FAIL.
- [ ] **Implement:** a request names a cluster, a namespace and a report, which the controller finds in the clusters' views.
- [ ] **Run** them again. Expected: PASS.
- [ ] **Gate, run `make test-e2e`, then commit:** `feat: the hub renders each remote cluster's reports and metrics`.

### Task 17: The installs per mode, and the guide to adding a spoke (design 5.1, 5.11)

**Files:**
- `config/hub/kustomization.yaml` (new): `config/default` with `--mode=Hub`, without the `workloads` and `network-reach` `Collector`s;
- `config/spoke/kustomization.yaml` (new):
  - the CRDs, the manager with `--mode=Spoke`, the manager's role, and `config/rbac/hub-access`;
  - only the `workloads` and `network-reach` `Collector`s;
  - no agent, no rules and no playbooks;
- `internal/setup/install_test.go`;
- `docs/remote-spokes.md` (new), and `README.md`.

- [ ] **Write the failing test** **`TestEachInstallRunsItsMode`** (install_test.go, from `kustomize build`):
  - `config/hub` passes `--mode=Hub` and has no `workloads`;
  - `config/spoke` passes `--mode=Spoke`, has the hub's access, and has neither the scanner nor the agent;
  - `config/default` passes no mode.
- [ ] **Run** it. Expected: FAIL.
- [ ] **Implement** the two overlays.
- [ ] **Docs:** `docs/remote-spokes.md`, for the admin:
  - the three modes, and which install runs each;
  - adding a spoke:
    - install `config/spoke`;
    - create a token with `kubectl create token vexplain-hub -n vexplain-system --duration=1h`;
    - on the hub, create the Secret with `server`, `ca.crt` and `token`, and the `Spoke` with the cluster's name and labels;
    - add a login for each registry of the spoke's images to the scanner's `adminPullSecrets`;
  - what the hub may do on a spoke, and how to revoke it;
  - removing a spoke, reinstalling one, and turning a standalone install into a spoke (design 5.11); spokes are upgraded after the hub;
  - where the remote series are, and what a spoke that can't be reached keeps;
  - an example NetworkPolicy that keeps the hub's scan Jobs to DNS and the registries' addresses.
- [ ] **Run** the test again. Expected: PASS.
- [ ] **Gate, then commit:** `feat(install): installs per mode, and the guide to adding a spoke`.

### Task 18: End to end, on two kind clusters (design section 6, decision 23)

**Files:**
- `Makefile`: `setup-test-e2e` and `cleanup-test-e2e` add a second kind cluster, `vexplain-test-e2e-spoke`, on the same Docker network. It has the kubeconfig `bin/kind-e2e-spoke.kubeconfig`, and the local registry's `hosts.toml` on its nodes;
- `test/e2e/{remote_test.go,helpers_test.go}`, where `remote_test.go` is new;
- `test/e2e/config-hub/` and `test/e2e/config-spoke/` (new): overlays on `config/hub` and `config/spoke`, with the e2e patches: the registry's mirror and login, the offline database, and `--spoke-token-lifetime=10m`;
- `test/utils/utils.go`: load an image into a named cluster.

- [ ] **Write the e2e specs:** `Describe("Remote spokes", Ordered)`. It deploys `config-hub` on the hub's cluster and `config-spoke` on the spoke's in `BeforeAll`, and undeploys both in `AfterAll`. The specs:
  - **Adding the spoke:**
    - the Secret holds the spoke's API server as the hub's nodes reach it on the Docker network, its CA, and a token from `kubectl create token`;
    - the `Spoke` turns Ready and `Synced`.
  - **A Deployment on the spoke,** with an image of the local registry, gets a case on the hub, through an investigation.
  - **The hub scans its image** with the test's login, though no pod on the hub runs it: the facts are `Succeeded`, and the scan Job ran on the hub.
  - **The spoke's workload's series** appear on the hub: `vexplain_open_case{cluster="<spoke>"}`.
  - **The hub's account can't write on the spoke:** `kubectl auth can-i --as=system:serviceaccount:vexplain-system:vexplain-hub create evidences` says no, and so does `patch` on `imageinventories`.
  - **The token renews:** within 6 minutes, `status.tokenExpirationTime` moves on, and the admin's Secret is unchanged.
  - **The spoke can't be reached:**
    - with the spoke's control plane stopped (`docker stop`), the `Spoke` turns `Connected` False;
    - its copies, its case and its series stay, also across a restart of the hub's manager.
  - **The spoke is back:** after `docker start`, the `Spoke` turns Ready.
  - **Deleting the `Spoke`** removes its copies and its series.
- [ ] **Run** `make test-e2e`. Expected: PASS, the existing specs included.
- [ ] **Commit:** `test(e2e): a hub and a spoke on two kind clusters`.

### Task 19: The measurement, on three kind clusters (design 5.13)

**Files:**
- `hack/measure-6/main.go` (new), with `hack/internal/localcluster` for each cluster;
- `Makefile` (`measure-6`);
- `docs/measurements/2026-phase6.md` (new).

- [ ] **Build the setup:**
  - a hub (`config/hub`) and two spokes (`config/spoke`), on kind;
  - on each spoke, `hack/inventory-load` deploys 300 workloads over 60 images, 20 of which run on both spokes;
  - the hub has the registry's login.
- [ ] **Measure** each of these against 0004's triggers (any object above 512 KiB, a sustained write rate above 5 per second, inventory above 10% of etcd's size):
  - the `Evidence` objects and their bytes, with the presence records apart, and the largest presence record against the evidence store's cap;
  - the largest `ImageInventory`;
  - the hub's write rate, idle and during a rollout of 50 workloads on one spoke;
  - the series of `vexplain_open_case` on the hub;
  - the hub manager's memory;
  - the scans: how many, how long, and their Jobs' CPU and memory;
  - the time to `Synced` after a restart of the hub's manager.
- [ ] **Write** `docs/measurements/2026-phase6.md`: the setup, the figures, and what each says about 0004's triggers. The figures are kind's, so they may live in the repository.
- [ ] **Commit:** `docs(measurements): the hub's storage and load with two spokes`.

### Task 20: The docs, and "As built"

- [ ] **Docs:**
  - `README.md`: the modes, and a short "Remote spokes" section that links to `docs/remote-spokes.md`;
  - `docs/collectors.md`: roles and `WrongRole`, the scanner in the hub role, and its `platforms`;
  - `docs/agent.md`: an investigation's cases cover every matching cluster.
- [ ] **"As built":** fill in the section below: what differs from the plan, and what the live run needs (Task 21).
- [ ] **Commit:** `docs: remote spokes, as built`.

### Task 21: The hand-over (design 5.11 and 5.13)

The main session runs the live run with the owner. This build only prepares it.

- [ ] **Write the hand-over** in the shared notes, outside the repository:
  - the branch and its last commit. The pull request opens after the live review, once every follow-up, from "Carried forward" and the live run, is in the to-do list through the main session;
  - **before the live run:**
    - the dev hub's install (`HubAndSpoke`), and the registry logins on the hub's scanner;
    - for each of test and prod: the uninstall, the `config/spoke` install through its own path (prod through the CI pipeline's manual steps), the token, and the `Spoke`;
  - what to measure live, from Task 19's list. Live figures stay outside the repository.
- [ ] **Tell the owner,** in short, what must be done before the live run.

---

## As built

Filled in while the plan runs (Task 20). Where the build differs from the text above, the build is right. Each difference is decided and reviewed while the plan runs.

## Carried forward

Filled in while the plan runs: what the build leaves open, each with where it lives in the code, for the design and architecture session after phase 6.
