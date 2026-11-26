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
19. **The upgrade's dip is version skew in presence,** found by Task 2's upgrade on kind from `f3998d3` (2026-11-25). A newer collector's field failed the older manager's presence schema, presence forgot every image, and the `ImageInventory` objects went with their facts. The fix is decision 0067, whose direction the owner chose: readers tolerate fields they don't know, and presence never forgets what it can't read. The restart mechanism that this decision first named, where a failed first match after a start deletes a sheet that can't stand in for a match, is real in the code but wasn't seen live. It is carried forward for the owner.
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

### Task 2: Presence and exposure across versions (0067, design 5.12, decision 19)

The upgrade on kind from `f3998d3` to the branch head reproduced run 6's dip (decision 19). This task builds 0067.

**Files:**
- `sdk/evidence/schemas/{ch.bedag.vexplain.presence.v1alpha1.json,ch.bedag.vexplain.exposure.v1alpha1.json}`, and the SDK's tests of them;
- `internal/spoke/{presence.go,presence_test.go,store_sink.go,store_sink_test.go}`;
- `internal/metrics/metrics.go`, for a counter of the refusals if none counts them yet;
- `docs/collectors.md`: the rule for new fields of a core type.

**Interfaces:**
- Produces:
  - the core's schemas of presence and exposure accept fields they don't know, at every level;
  - **presence:** a snapshot with an event it refuses keeps that collector's last readable snapshot, and doesn't count as its snapshot for `KnowsWhatRuns`. A refused upsert or tombstone changes nothing. Each refusal is counted;
  - **the store sink:** an off-schema presence event keeps its stored record, and an off-schema exposure event deletes its record, as today.

- [ ] **Write the failing tests:**
  - `TestAPresenceEventWithFieldsItDoesNotKnowIsAccepted`: an event as a newer collector sends it, with a field it doesn't know on the workload and on a pod;
  - `TestARefusedSnapshotForgetsNothing`: after a readable snapshot, one whose events fail the schema, as an older collector's without `subject`. Every image keeps its entry and its facts, and the refusals are counted;
  - `TestARefusedSnapshotDoesNotCountForKnowsWhatRuns`;
  - `TestAnOffSchemaPresenceEventKeepsItsRecord` and `TestAnOffSchemaExposureEventDeletesItsRecord` (store_sink_test.go);
  - a regression test from the reproduction's events: the new collector's presence, as the old manager refused it.
- [ ] **Run** them. Expected: FAIL.
- [ ] **Implement.**
- [ ] **Run** them again, then `make test`. Expected: PASS.
- [ ] **Docs:** in `docs/collectors.md`, the rule for new fields of a core type.
- [ ] **Gate, run `make test-e2e`, then commit:** `fix: presence across versions never forgets what it can't read`.

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

Where the build differs from the text above, the build is right. Each difference was decided and reviewed while the plan ran. The design of remote spokes holds the build's amendments, each marked inline *Amended on 2026-11-25 (build)* or *Amended on 2026-11-26 (final review)* and named in its status line. Decision 0067 is the build's own, the status lines of 0062, 0063, 0064, 0066 and 0067 say what the build changed in them, and the older designs note where their text predates 0060 and 0062. `git log -p 78c0b36..HEAD -- docs/design docs/decisions` shows each.

### Run 6's lessons, and the flaky tests (Tasks 1 to 3)

- **`go test -race -count=20 ./internal/rules/engine/` takes about 12 minutes, and needs `-timeout 40m`.** The race run found a third test with the same 1-second bound, `TestAnEvaluationWithinTheCostLimitIsEvaluated`, which got the same long bounds.
- **Presence counts each event that it can't read in `vexplain_presence_refused_total{cluster, collector}`,** which the plan's names don't list. A count that grows says that the cluster's presence may be stale.
- **The store sink's records follow the images of each snapshot, also of one that presence can't read.** An off-schema presence event keeps its record, as 0067 says, but an image that such a snapshot leaves out loses its record, while presence keeps the image until a snapshot that it can read leaves it out too.
- **The upgrade's regression test, `TestTheUpgradeOnKindKeepsEveryImageAndItsFacts`, reads a fixture rebuilt from the reproduction's inventory with neutral names** (`internal/spoke/testdata/upgrade-presence.json`): the reproduction's events weren't recorded.
- **Three more flaky tests are fixed in their tests.** The hub suite's spec that installs a deleted `Collector` again waits until it is gone, since the deployer's finalizer deletes the evidence before it lets the `Collector` go. The spoke suite's helper waits, bounded, for its manager's cache, which a test read before it started. The inventory suite's spec of the client options runs on an API server of its own, where the suite's assessor can't delete its sheet.

### The modes (Task 4)

- **The modes' specs are a Ginkgo suite of their own, `internal/setup/modes` (`TestModes`),** in place of `TestEachModeStartsItsParts` in `register_test.go`. It starts one manager after another in one process, which `testenv.AgainInProcess` allows for that suite alone, so that every other suite still refuses a duplicate controller name.
- **`ReasonWrongRole` is in `common_types.go`,** with the Collector's other reasons, and the CRD doesn't change.
- **`WrongRole` wins over whatever else a check finds, and the collector records no last success,** so that its status isn't written again at each resync. Its capabilities stay recorded.
- **A collector of both roles is used in either mode:** its streams follow the roles that the mode runs, and its schedules, which carry no role, run wherever it is usable.

### The scanner and the platforms (Tasks 5 and 6)

- **The scanner's `scan` is never one of the agent's tools.** In the hub role it would meet the agent's rule for tools, so the agent leaves out an operation that produces the SBOM type: scans are the hub's executor's, and the agent's tools stay as they were.
- **`OperationFor` takes an operation in the hub role that isn't a source's,** not any operation of a collector in the hub role. A source's operation answers about entry points, which the asker asks it. An operation without a role, as an older operator recorded it, runs in the collector's.
- **A scan refuses more than 16 platforms before it starts a Job,** once it has joined the request's with those of its pods' nodes (`Internal`). The hub's request names the first 16 of an image's platforms, sorted, and logs the others, which get no scan.
- **Without a pod, a scan tries up to 4 of the request's repositories until one pulls** (`pullOrder`): those whose registry, or its mirror, the admin's logins cover, then the others, each in sorted order. Only a failed pull moves on, and when every try fails, the first one's failure is the result. The plan pulled from the first repository alone, so an image that a fleet's clusters pull through different names failed on a name that the hub can't reach. A spoke can still fail an image's scan for the fleet by naming 4 repositories that the scan tries before the one that serves it, as design 5.6 says.
- **A request that waits takes the newest platforms with the newest repositories,** and the scan's parameters leave out an empty list of platforms or pods, which the scanner's schema refuses.

### The Spoke, the connection and the token (Tasks 7 to 9)

- **`SpokeCollector.ready` is a pointer,** as kube-api-linter asks of an optional field. `Spoke` joins the linter's exemption of `Spec` and `Status`, and the CRDs that the conditions test checks, as every kind does.
- **When True, `Connected` and `Synced` have reasons of their own, `Connected` and `Synced`,** which the plan's list lacks. The refusals below add four more.
- **The hub checks each spoke every minute, and renews the token at the check once it is due,** at half its lifetime by its claims, not at a requeue at the renewal time. A token is renewed at most a minute late, which leaves 4 of 10 minutes at the shortest lifetime.
- **The ServiceAccount to renew is in the token's claims `kubernetes.io.namespace` and `kubernetes.io.serviceaccount.name`, or else in its subject, `system:serviceaccount:<namespace>:<name>`.** They are read without a check of the signature, since the spoke's API server checks the request. A token that names none can't be renewed: `CredentialsInvalid`.
- **A token that the spoke refuses with a 401 isn't valid, whatever its expiry says.** The hub then connects with the admin's token, and renews from it at once, so that a spoke whose ServiceAccount was made anew works again with a new bootstrap token.
- **The hub's own token goes only to the server and the CA bundle that it was issued for.** Its Secret keeps both, the bundle as a SHA-256 of its certificates (`ca.sha256`), and the hub sends its own token only while the admin's Secret names the same: the same certificates in another PEM text, and the same URL in another case, with or without port 443 or a slash at its end, count as the same. So a token that renews itself never goes to another address, nor with a CA that someone who steers the traffic swapped in. A moved API server, or a rotated CA, needs a new bootstrap token: a call of the build, for the owner to confirm.
- **No token reaches what the hub shows.** A check withholds the tokens that it sent, and each part of one, from its messages. The seam drops the spoke's warnings, and the spoke cache's lists and watches pass each error of the spoke's API server on as its code alone, since a spoke's text can echo what the hub sent. The messages may name the server, which is no credential.
- **Every call that the hub makes to a spoke, and each read and write of a spoke's Secrets, runs with a logger that drops client-go's debug lines** (`remote.Quiet`), whatever the manager's `--zap-log-level`: from level 4 they carry a spoke's answers, and from 8 the bodies, a renewed token among them. Lines up to level 3, and errors, still go.
- **The seam takes only an https `server` without user information, trims the whitespace around it and the token, and refuses a `ca.crt` without a PEM certificate.** It refuses an admin's Secret that has the name of the hub's own, and a Secret of that name that the `Spoke` doesn't own, so that the hub writes no other Secret.
- **Each call of a check is bounded at 10 seconds, with a REST mapper that needs no discovery.** client-go sends discovery without a context, so a spoke that hung there would hold every other check.
- **A spoke's identity must be a UUID,** as an API server gives `kube-system`'s UID. Another answer is `CredentialsInvalid`, and the hub records none: a pattern on `status.clusterID` would have the API server quote the value, which is the spoke's text.
- **The check refuses a `Spoke` in five cases, each `Connected` False and `Stalled`:** the hub copies nothing more for it, and keeps the copies that it made. In the check's order:
  - one named like the hub's own cluster (`NameInUse`), before any contact: its copies would take the keys of the hub's own records;
  - one whose Secret reaches the hub's own cluster (`OwnCluster`);
  - another identity than the recorded one (`IdentityChanged`), as the plan has it;
  - at a first contact, an identity that another `Spoke` records (`IdentityInUse`): a cluster has one `Spoke`, since two would replace each other's entries;
  - a spoke whose `OperatorConfig` names its cluster otherwise, or that has none and so is `local` (`ClusterNameMismatch`): its records carry that name, and the copier would read their absence under the `Spoke`'s name as "runs nothing". The hub reads the name with its grant on `operatorconfigs`.
- **A refused `Spoke` renews no token,** as design 5.3 says: one that stays refused for longer than its token lives, a day, turns `TokenExpired`, and needs a new bootstrap token besides the fix.
- **The `Spoke`'s admin role may patch `spokes/status`,** so that an admin can clear `status.clusterID` to accept another cluster behind a `Spoke`.

### The copier and the namespace labels (Tasks 10 and 11)

- **The hub forgets a spoke's entry by the `Spoke`'s name alone** (`Forget(ctx, digest, spoke, "")`), not by the plan's `clusterID` too: every copy carries the name, and an identity can be another cluster's, as another `Spoke`'s or the hub's own. Neither a round nor the deletion forgets an entry of the hub's own identity under the `Spoke`'s name, as the hub's own from before a rename.
- **A check starts the cache anew when the config that it verified differs from the cache's,** as after a renewal or a change of the Secret, where the plan stopped it when the `Spoke` or its Secret changed: the manager's cache holds no Secret. The cache starts on the config that the check verified, never on a Secret read again. While the identity stays, the copier goes on over the new cache with its memory, so its next round copies only what changed and `Synced` holds. A new cache that doesn't sync within the 2-minute grace turns `Synced` False.
- **`status.lastSyncTime` is when the copy last became current, as at the end of a copier's first round, or last took a change of the spoke.** A check that finds nothing new writes nothing. Accepting another identity clears it until the new cluster's first round ends.
- **A record that the hub's API server refuses (`Invalid` or `BadRequest`) counts as `invalid`, by its type's rule:** a presence copy stays, as 0067 has it, and another type's goes. One such record no longer stops every round.
- **A refused record or entry is logged with the tokens that the hub holds for the spoke withheld:** the admin's, the hub's own, and the one that the check sent, which the check hands the copier while the spoke is connected. A refused record's key, and an entry's digest, are the spoke's text, which can echo a token that the spoke issued.
- **The copier keeps the hub's copy of an entry of the spoke's identity under another name,** counted as `cluster`. After a rename on the spoke, its presence moves each entry to the new name, and the check stops the copier within a minute (`ClusterNameMismatch`), so that the cluster's images never read as running nowhere meanwhile.
- **A change of the hub's `OperatorConfig` brings a check of every `Spoke`,** so that one that now has the hub's own name stops copying at once.
- **An image's digest kind is the highest that its clusters report** (a repository digest, then a reference, then an image ID) while several run it, and a cluster that runs it alone sets its own. Each `Observe` set it before, so one spoke could mark an image not pullable for the whole fleet.
- **A namespace's labels are bounded at 1000, each key of up to 317 characters and each value of up to 63.** Past the bound, the namespace's copy is refused as `invalid` and deleted, so its labels read as unknown, never cut. A spoke's `Collector` named `vexplain`, the source of the hub's own copies, is refused, since its records would share their keys.
- **The view takes a namespace's labels only from the source `vexplain`,** and `NamespaceLabels`' false means that they are unknown, never that there are none.

### The rules across clusters (Tasks 12 to 14)

- **A playbook's subjects count their producers in every cluster,** as a workload type does: a `Hub` runs no presence of its own, and judges its spokes'. Findings and image types count the local `Collector`s only (0066).
- **A pin counts per cluster:** a pinned `Collector` that doesn't count in one cluster makes the input missing there alone (`PlaybookExposure.Absent`). `NewCaseExposures` reads no `Collector`, since the producers' max ages come with the playbook's exposure.
- **The assessor's two controllers watch `Spoke`s, as the playbook controller does,** so that a `Spoke` that makes a playbook `Ready` has its images asked about and matched, and a change of a `Spoke`'s labels reaches the sheets.
- **The playbook controller checks a playbook again at each of its events, its own status writes included.** A check that read the cached playbook without the controller's last write wrote nothing, and the write's event was dropped, so a stale `Ready` could stay.
- **The assessor assesses an image's manifests again when its presence or facts change** (`Assessor.images()`). The scan stores the evidence before the facts, so without it a new image got no sheet; and a manifest is judged once its image runs in a matching cluster.
- **A subject that no cluster runs is judged by the hub's own cluster's labels,** as before this plan, so that a manifest of a platform that no node runs any more keeps its sheets and its cases.
- **A cluster that no `OperatorConfig` or `Spoke` names counts only for a playbook without a cluster selector.**
- **A case that several playbooks select is queued with the views of those that still select it.** The most urgent view, by the queue's tiers, gives `order` and `runsIn`, and `runsIn.clusters` is the union of their matching clusters, or absent when one of them has no cluster selector. A playbook that stops selecting the case stops shaping its entry at the next hand-over. Their results add up and the most cautious counts, as 0043 has it, and design 5.8 has the call. It closes the entry points' carried-forward point that only the queue's playbook wrote a waiting case's `order` and `runsIn`.
- **The agent's case file counts the workloads past the most urgent view's as Unknown** (`LayRunsIn`), since the worker counts the union's workloads while the queue holds one view's groups. Its highest exposure rises to Unknown where the view's is lower, and its urgency stays the view's.
- **`runsIn.clusters` names at most 256 clusters; past that, none, which counts every cluster.**
- **A case is queued before its `Assessment` says `Queued`,** so that a failure between the two can't leave a case queued and uncharged against `maxCases`.
- **The investigation controller doesn't watch `Spoke`s:** an investigation follows the inventory every `impactRefresh`, 5 minutes, and a `Spoke`'s labels reach it then.
- **An address is ambiguous by its IP, whatever its port:** every subject of an IP that two clusters' exposure names gets no source's answer. The view computes it again only after a workload's exposure changed. Its state of `vexplain_entry_points` is `ambiguous` alone, apart from answered and unanswered, and the asker still asks the sources about it.

### The renderer and the remote metrics (Tasks 15 and 16)

- **The local renderer keys its series by its cluster's name, and remembers the name that it set them under,** so that a rename moves them. `NewReports` still takes `*Presence`, for its callbacks.
- **A remote cluster is rendered once its `Spoke` records an identity and a time of a current copy** (`status.clusterID` and `status.lastSyncTime`), whether or not the spoke can be reached. A first round's copies land in no order, so an earlier render showed a workload's exposure from some of its collectors, lower than Unknown. A cluster that stops being copied, as while an admin accepts another identity, has its series forgotten until its copy is current again.
- **`RunningIn` takes whether the copy was current, and each cluster keeps one index of what runs in it,** built again only after its presence changes.
- **The view calls the renderer through a function that setup wires (`View.OnChange`), and `internal/remote` imports `internal/spoke` for `RunningIn`,** as design 5.9 notes. Beyond the plan's interfaces: `remote.Spokes` and `remote.Clusters`, `spoke.EachOnce`, `inventory.Store.DigestsByCluster`, `metrics.CollectorReady` and `SpokeReconciler.Counts`.
- **The renderer renders no `Spoke` refused as `NameInUse` or `OwnCluster`, none of the hub's own name, and none that is being deleted.** One refused as `ClusterNameMismatch` or `IdentityChanged` keeps the series of its copies.
- **While a `Spoke`'s copy isn't current, the renderer asks for the clusters again every 2 seconds,** and renders none of the other clusters again.
- **Deleting a `Spoke` also deletes its cluster's counts, and the series of the store's writes of its entries,** which covers a `Spoke` deleted while the hub was down, which the renderer never knew.
- **A scrape of the remote series leaves out any of the hub's own name, and has none when it can't read that name:** one name under two renderers would fail the whole scrape.
- **`vexplain_remote_images_without_presence` is absent until the view has read the store,** as after a start, and on a replica that isn't the leader. `vexplain_collector_ready` has one description for the hub's own collectors and its spokes', which one scrape needs.

### The installs and the guide (Task 17)

- **The agent workers' roles ship with the agent** (`config/agent` takes `config/rbac/agent`), so that an install without the agent binds no role to a ServiceAccount that it doesn't create.
- **The scanner's defaults of the collectors' ceilings are in `config/rbac/scanner`:** `vexplain-scanner-defaults`, the scanner's cluster-wide `get` of pods, nodes, Secrets and ServiceAccounts, and `vexplain-collector-namespaced-defaults`. `config/default` takes them and `config/spoke` doesn't, so that a spoke's manager holds no read of Secrets outside its namespace and no write of Jobs, as 0066's note says. The role's name lies outside `vexplain-collector-*`, which the Collectors' grants take. `config/default` grants what it granted before.
- **`config/spoke` also ships the collectors' NetworkPolicies and the manager's metrics,** whose counters of presence and of the store sink exist only on a spoke. It leaves out the rules and the playbooks by kind, and the hub's other defaults by name, so that a new default has to be named there to stay out.
- **`make undeploy` deletes the `Spoke`s first,** while the manager runs, as it deletes the `Collector`s: a `Spoke` left behind would hold its CRD's deletion for ever.
- **The guide goes past the plan's list:** the install commands and the spoke's `OperatorConfig`; the token through a file, and a Secret created or replaced with `--dry-run=client -o yaml | kubectl apply`; revoking by deleting the ServiceAccount, since deleting only its bindings invalidates no token, as design 5.4 and 0062 now say; re-granting and reinstalling; the hub's refusals, and clearing `status.clusterID`; the proxy; the manager's log level; switching an install to `config/hub`; and the series to watch.

### End to end (Task 18)

- **Task 18 was built in two parts:** its harness and its specs before Task 16, and the remote series' checks after it.
- **The e2e patches are a shared component, `test/e2e/offline`,** which `test/e2e/config`, `config-hub` and `config-spoke` use, and `test/e2e/config` renders as before. The spoke is `cluster-a`, and the hub keeps `local`.
- **The scan's spec shows that the hub scans an image that no pod of the hub runs, not that it used the test's login:** the e2e registry asks for none. Unit tests check that a scan without a pod pulls with the admin's logins alone.
- **The hub's account is checked over every row of vexplain's kinds in `kubectl auth can-i --list` on the spoke:** get, list and watch only, beside the plan's two asks.
- **The admin's token lives 10 minutes in the suite,** as the hub's does, so that the renewal comes within 6 minutes.
- **The suite reads the hub's metrics with a token mounted into the curl pod, and prints no token.** It has 69 specs, and takes about 40 of its 60 minutes.
- **The e2e suite ran at the end of each task that the Global Constraints name, Tasks 7 and 8 included,** whose steps don't say so. The runs of Tasks 10, 13 and 17, which a hung container engine cut short, ran once on the combined branch.

### The measurement (Task 19)

- **The setup replaced the plan's.** `hack/inventory-load` writes made-up `ImageInventory` objects while the operator is stopped, and a kind node runs about 110 pods by default. So each spoke runs 100 real Deployments over 30 small images that the tool builds into the local registry, 10 of them on both spokes, on nodes of 200 pods. The doc projects, from the bytes measured per workload, entry and namespace, where the store's cap and 0004's 512 KiB would be reached, and marks each projected figure. `docs/measurements/2026-phase6.md` has the setup and the figures.
- **The tool also counts the requests that write the inventory group's objects, by resource and verb.** `make cleanup-measure-6`, like `make cleanup-test-e2e`, keeps the e2e registry while a cluster of the e2e or of `measure-6` uses it, and `hack/internal/docker` serves `measure-2a` too.

### The docs (Task 20)

- **Task 20 was split in two:** the docs beside Task 18's second part, and these two sections after the final whole-branch review, so that they record its fixes.
- **The docs also correct what the code contradicted:** `docs/collectors.md`'s spoke that opened the connection to the hub, and its `Collector` whose deletion took every cluster's records; `docs/agent.md`'s spoke operation `scan`, and its known limit of the queue, which Task 13 removed.

### The file structure

- **Beyond the plan's files:** `internal/setup/modes/`, `internal/testenv/spoke.go`, `config/rbac/agent/kustomization.yaml`, `config/rbac/scanner/`, `config/spoke/{metrics_service.yaml,manager_metrics_patch.yaml}`, `test/e2e/offline/`, `hack/internal/docker/`, and `hack/measure-6/{config-spoke-b,kind-config.yaml}`. `ReasonWrongRole` is in `api/config/v1alpha1/common_types.go`.

### The images

- **Three change:** the manager (`IMG`), the agent workers (`AGENT_IMG`) and the scanner (`SCANNER_IMG`). `workloads` and `network-reach` change only the schema of presence and of exposure that they declare, which accepts fields that it doesn't know, and which the manager only compiles. `vulnerabilities` and `advisories` do what they did. `make docker-build` builds all seven from one commit, as before, and each collector reports that commit as its version.

### Before the live run

**Deploy together,** from this branch's last commit, the hub first and then the spokes: the manager, the agent workers and the scanner, with `workloads` and `network-reach` of the same commit.
- The hub asks a scanner only through an operation of the hub role: until the new scanner has recorded its role, the hub scans nothing, and an older scanner is `WrongRole` in `Hub` mode.
- The workers count the workloads of the clusters in `runsIn.clusters`, which the new manager writes, and those past the queued view as Unknown.
- The manager's role gains the `Spoke`s, their status and their finalizers. The workers' roles come with `config/agent`, and the scanner's defaults of the ceilings with `config/rbac/scanner`, with the same rights as before.
- An upgrade from `main` changes no field of presence or exposure, so the order in which the manager and the collectors roll doesn't matter for them; 0067 lets later upgrades go in either order. Each record of `workloads` and `network-reach` is written once more, under their new version.
- **One order matters:** `kubectl apply` of an upgraded install applies the trimmed `vexplain-collector-defaults` before it creates `vexplain-scanner-defaults`. A check of the scanner in between finds its rules outside the ceiling, turns it `PermissionsNotAllowed` and takes its grant back, until its next check, within the collectors' resync of 30 seconds.

**The CRDs that change** come first, with `make install`, or with the rest of `make deploy`. A manager of the hub role watches `Spoke`s, so it needs the new CRD before it starts:
- `Spoke`, new: group `config`, cluster-scoped;
- `Assessment`: `status.queue.runsIn.clusters`. A queue that an earlier version wrote has none, which counts every cluster.

**The installs** (`docs/remote-spokes.md`, "The modes"):
- `config/default` stays `HubAndSpoke`, and serves spokes too. An upgrade in place keeps its effective rights.
- `config/hub` is `config/default` with `--mode=Hub`, without the `workloads` and `network-reach` `Collector`s. An install switched in place follows the guide's order: those two `Collector`s are deleted first, while it still runs `HubAndSpoke`, or the hub's own entries and reports stay for good.
- `config/spoke` runs the manager with `--mode=Spoke`, `workloads` and `network-reach`, the hub's access (`vexplain-hub`, `vexplain-hub-reader`), the collectors' NetworkPolicies and the manager's metrics. It runs no scanner, no agent, and no rules or playbooks. An install of `main` that becomes a spoke is uninstalled first, with `make undeploy`, and installed as `config/spoke`, as the guide's "Turn a standalone install into a spoke" says: the uninstall removes its records and its reviews (`VexStatement`s), and a switch in place would leave old reports behind.

**What the admin creates,** by the steps of the guide's "Adding a spoke":
- on each spoke: the install with its images, the `OperatorConfig` whose `clusterName` is the `Spoke`'s name (step 1), and a token of `vexplain-hub` (step 2);
- on the hub: the Secret with `server`, `ca.crt` and `token` (step 3), and the `Spoke` with the cluster's labels (step 4);
- the logins of the hub's scanner (step 5). The hub scans every image of the fleet, so its `adminPullSecrets` need a login for each registry of every spoke's images, at most 16 Secrets. The pull secrets of a spoke's workloads never leave the spoke, and a registry without a login fails in the image's facts, `Unauthorized`, with the registry named.
- The hub's own `clusterName` differs from every `Spoke`'s name, and no `Spoke`'s Secret names the hub's own API server. The hub's manager reaches each spoke's API server directly, or through the proxy that its `HTTPS_PROXY` names.

**Operating notes:**
- **The owner confirms the pin's call:** a moved API server, or a rotated CA, needs a new bootstrap token in the admin's Secret (step 3).
- **Revoke by deleting the ServiceAccount `vexplain-hub` on the spoke.** The hub falls back to the admin's token only on a 401. Deleting the bindings gives 403s, and the hub's token works again once they return.
- **A refused `Spoke`** (`NameInUse`, `OwnCluster`, `ClusterNameMismatch`, `IdentityInUse`, `IdentityChanged`) is `Connected` False and `Stalled`, copies nothing and renews no token: refused for longer than a day, it ends at `TokenExpired`, and needs a new token too. The guide's "When the hub refuses a spoke" says what to do for each.
- **The pin's hash changed format with the last fixes of this branch:** a hub's own Secret written by an earlier build of the branch is set aside once, which needs the admin's token valid, or a new one. Installs of `main` have none.
- **The hub checks one `Spoke` at a time,** every minute, each call bounded at 10 seconds: several spokes that can't be reached delay the others' checks and renewals.
- **`lastSyncTime` is when the copy last became current or changed:** a quiet spoke keeps an old one while `Synced` is True.
- **A spoke that can't be reached keeps its copies, its cases and its series,** also across a restart of the hub, which renders them from the copies. A remote cluster's series appear once its copy is current, and go with its `Spoke`, whose deletion takes its copies, counts and series, and the hub's own token Secret.
- **An address whose IP two clusters' exposure names gets no source's answer,** so clusters that reuse private ranges have such addresses `Unknown`, which counts as `Open`. `vexplain_entry_points{state="ambiguous"}` counts them.
- **A scan names at most 16 platforms:** an image that runs on more has the others left out, and logged.
- **A `Hub` has no presence of its own:** its playbooks are `Ready` on the presence producers that the `Spoke`s list.
- **A spoke's own counters,** of presence's refusals and of its store sink, are on the spoke's metrics endpoint, which `config/spoke` serves.
- **Keep the hub's manager below `--zap-log-level` 8 outside a debugging session.** Its calls to a spoke, and its reads and writes of a spoke's Secrets, log none of client-go's debug lines, whatever the level. Its other calls do: from 4 the debug lines of its calls to its own API server, and from 8 their bodies, among them the copies of the spokes' records and the other Secrets of `vexplain-system`, such as the collectors' certificates. A refusal's log line shows a token that the hub holds for the spoke, or a part of one, as `[withheld]`.

**What to measure** is Task 19's list, on the live hub and spokes: the `Evidence` objects and their bytes, presence apart, and the largest presence record; the largest `ImageInventory`; the hub's write rate, idle and during a rollout; the series of `vexplain_open_case`; the hub manager's memory; the scans; and the time to `Synced` after a restart of the hub's manager. Live figures stay outside the repository, which gets only what they decide. What `docs/measurements/2026-phase6.md` found worth watching at scale:
- an image's `ImageInventory` grows with the clusters that run it, and is about 60% managed fields: of what the spokes add, it reaches 512 KiB first;
- the hub's writes while workloads arrive and roll: a new pod's image comes and goes under its reference's digest, which the writes counted by verb tell apart;
- `vexplain_open_case` grows with the workloads times their open findings, on the hub's one endpoint;
- the hub manager's memory, which holds each spoke's `Evidence` in a cache, and decoded in the view;
- `vexplain_spoke_records_refused_total{reason="cluster"}`, which a spoke whose name drifts raises.

## Carried forward

### Open design points, for the owner

- **After a restart, a first match that fails, as while a matcher loads its database, still deletes the sheets that can't stand in for a match** (`unmatched`, assessor.go ~:1291-1315): after a start, what a sheet rests on always counts as changed. Run 6's dip turned out to be version skew, which 0067 fixed, so this path is parked: keeping the sheet trades the dip for stale verdicts, and holding its findings open for noise.
- **The hub renders a remote cluster once its copy was current, which doesn't prove that each exposure collector on the spoke has sent its first snapshot** (`copies.KnowsWhatRuns` and `ExposureKnown`, remote/running.go ~:69-72). A spoke with two exposure collectors, one not yet delivered, gives its workloads the other's exposure, which can read lower than Unknown would. The default install has one, `network-reach`, whose missing record reads Unknown. Closing it needs a marker per collector on the spoke, copied to the hub.
- **The hub sets its own token aside only on a 401** (spoke_controller.go ~:477). A 403, as when the hub's account lost its bindings on the spoke, leaves it on its own token, which works again when the bindings return. The guide revokes by deleting the ServiceAccount; whether the hub should also react to a 403 is open.
- **Each starting pod makes a short-lived image keyed by its reference** (`ReferenceDigest`, sdk/workloads/digest.go ~:154-162): a container has no image ID until it starts. The spoke writes it, and the hub copies it, marks it not pullable, and deletes it once the pod reports its image's digest, which the measurement's writes by verb fit. It predates phase 6, and the copy doubles it on the hub. A fix is a design call: hold back a container that is still being created, or key it by the digest that its spec names.
- **A refused `Spoke` renews no token** (`connect`, spoke_controller.go ~:492-520), so one refused for longer than its token lives ends at `TokenExpired`. Renewing for a mismatched name whose identity is the recorded one would avoid it, at the cost of renewing for a cluster that the hub refuses.

### The modes and the installs

- **A `Hub`'s collector ceiling keeps the list and watch defaults of `workloads` and `network-reach`** (`vexplain-collector-defaults`, config/rbac/collector.yaml): pods, nodes, Services, the Gateway API and Cilium, in the whole cluster, though a hub runs neither. Splitting them out, as the scanner's are for spokes, would narrow it.
- **An upgrade from before the scanner's role split applies the trimmed `vexplain-collector-defaults` before it creates `vexplain-scanner-defaults`,** and a check of the scanner in between takes its grant back until its next resync. Low risk; an upgrade note, or applying the new role first, would avoid it.
- **A spoke's install ships the NetworkPolicy of the agent's metrics, and the collectors' policy admits the agent's pods** (config/network-policy), for workers that a spoke doesn't run.
- **`--spoke-token-lifetime`'s floor of 10 minutes is checked at the flag only** (cmd/main.go ~:67-70): `Register` takes any lifetime.
- **`registerStreams` checks `hubSink != nil`, though `NewStreams` drops nil sinks** (setup.go ~:523-525).
- **`Register`'s doc and `docs/collectors.md`'s table of the modes don't say that `Hub` renders no report of its own cluster** (setup.go ~:248-252, collectors.md ~:491).

### The scanner and the requests

- **Past 16 platforms, the hub's request names the first 16 in sorted order** (`platformsOf`, assessor.go ~:768-784, marked `shortcut:`): the others' manifests get no evidence, and are only logged.
- **A scan without a pod reads the admin's Secrets once for each repository of the request, up to 256, until it has four that they cover** (`pullOrder`, operation.go ~:486-487, marked `shortcut:`).
- **The `platforms` parameter's items have no `maxLength`, and the schema repeats `platformPattern` as text** (operation.go ~:110-111, ~:190-196). No test refuses an off-pattern platform of a request.
- **`maxPlatforms` repeats the schema's `maxItems: 16`, and `maxManifests`** (operation.go ~:525, ~:87).
- **`Invoke` joins the pods' and the request's platforms, with `errNoPlatform`'s exception, in compound cases** (operation.go ~:414-424): `platforms.go` would keep one rule and give the join a unit test of its own.
- **The agent leaves out the scan because its operation produces the SBOM type** (collector_tools.go ~:237-240): a rule by the type, not by the operation.
- **`docs/collectors.md`'s "The scanner, for one" lost what it follows** (~:345): the paragraph on the scanner's role now stands between it and the rule that it illustrates.

### The connection and the token

- **One worker checks every `Spoke` in turn** (spoke_controller.go ~:744-764, controller-runtime's default), each call bounded at 10 seconds: several spokes that can't be reached delay the others' checks and renewals. Raise its concurrency for a fleet of many spokes.
- **At a first contact, and after a fallback to the admin's token, the spoke's cache starts on the admin's token, and again on the hub's own once it holds one** (`follow`, spoke_controller.go ~:303-312): a second full list of the spoke's records.
- **`remote.Tokens` adds two reads of the hub's API server per check, a minute, for each connected `Spoke`** (connect.go ~:201-222, spoke_controller.go ~:306): the admin's Secret and the hub's own, for the tokens that the copier withholds.
- **From `--zap-log-level` 8, the manager's other calls log their request and response bodies, the Secrets of its own namespace among them** (cmd/main.go ~:121-127): `remote.Quiet` (connect.go ~:248-262) covers only the calls to a spoke and the reads and writes of a spoke's Secrets. It predates phase 6, and the guide says so.
- **A failed write of the hub's own Secret during a renewal reads as a failed call to the spoke** (spoke_controller.go ~:520-526, marked `shortcut:`), though its message says which.
- **`Renew` writes whatever Secret has its name, in the window after `Config`'s check of its owner** (token.go ~:107-121).

### The copier

- **After a renewal, the copier no longer withholds the hub's previous own token from its refusals' log lines** (`follow`, spoke_controller.go ~:303-312), though that token stays valid until it expires: each check hands the copier the tokens that the hub holds then. A Secret that a check can't read leaves its token out until the next check, a minute later.
- **The copier's tally counts a `Put` that the store skipped as unchanged** (copier.go ~:695), so a spoke's namespace whose metadata changes without its labels moves `lastSyncTime` and writes the `Spoke`'s status.
- **The guard against forgetting the hub's own entries reads the entry outside the store's conflict retry** (`forget`, copier.go ~:923-941). Right after an admin renames the hub's cluster onto an existing `Spoke`'s name, an entry that the hub writes in between can be forgotten. Narrow (an admin's error, a one-minute window); move the check into the store.
- **After a rename on the spoke, the copier's guard keeps only entries** (`copyEntry`, copier.go ~:790-819): until the check stops the copier, within a minute, an image that the spoke stops running under the new name is forgotten as under the old one. The records keep their old name on the spoke, so their copies stay.
- **`finalize` stops the copier before `DeleteCopies`,** so a deletion that fails is retried with the `Spoke`'s listed collectors alone (spoke_controller.go ~:265-273). That widens the window of `DeleteCopies`' `shortcut:` (copier.go ~:901-903): the copies of a type that the copier copied just before the hub stopped, and that the spoke dropped before the hub listed it, stay.
- **A full round reads each of the hub's images to find the cluster's entries** (copier.go ~:767-769, marked `shortcut:`), at a copier's start, after a failed round, and when the spoke's `Hub` types change. A door that lists a cluster's images would replace it.
- **A spoke with more than 64 `Collector`s has them all copied, and only the first 64 listed** (copier.go ~:592-594, marked `shortcut:`): the others' evidence counts for no producer of the hub's.
- **The cache of a spoke's namespaces keeps their annotations** (`NewCluster`, copier.go ~:118-126): about 2 KB a namespace, once managed fields are stripped. A transform that keeps only the labels would do, if a fleet shows the cost.

### The rules across clusters

- **An investigation scoped by an alias groups under a finding's ID only the findings that carry the alias** (`inScope`, cases/select.go ~:121-136), while the worker groups every finding of that ID (claim.go ~:312-313). When a vulnerability's findings carry different aliases per package, the two input hashes differ, the verdict never reads fresh, and the case is queued again up to its cap. Narrow; it predates phase 6.
- **The rule and agent profile controllers filter their own status writes with `GenerationChangedPredicate`** (rule_controller.go ~:279, agentprofile_controller.go ~:198), as the playbook controller did. A check can read the cached object without the controller's last write, write nothing, and that write's event is dropped, so a status can stay stale. Check whether these two depend on other objects the same way.
- **An unmet pin is recorded only for the clusters that a check visits** (investigation.go ~:582-596, cases.go ~:137): a workload of another cluster, as from orphaned copies or an old cluster name, sees none. Not reachable with the default rules.
- **Each check of a playbook deep-copies every `Spoke`** (playbook_controller.go ~:183-186).
- **The assessor assesses an image's manifests at each event of its `ImageInventory` but a summary's** (`images()`, assessor.go ~:1641): an unchanged sheet costs no evaluation, but each assess reads the playbooks' checks, the evidence's metadata and the cases.
- **`viewOf` counts a playbook whose agent section or `matchConditions` no longer hold** (investigation.go ~:992-1016), which errs towards urgency.
- **Each hand-over selects every other playbook's view anew** (`asQueued`, investigation.go ~:963-971): a memo per reconcile would do.
- **The Unknown remainder of the agent's case file is as exact as the queue is fresh** (`LayRunsIn`, cases/queue.go ~:107-109): the union's count, less the queue's order, can change between the queueing and the claim, though never below zero.
- **The worker and `agent-replay` repeat the read of `runsIn.clusters`** (claim.go ~:301-302, export.go ~:107-108): a helper in `cases` would give `agent-replay` the worker's tested code.
- **The comments of the cap of 256 clusters give the inventory's bound as its reason** (cases/queue.go ~:55, ~:64-65), where the list is the union of the matching clusters.
- **No comment says that a `Spoke`'s labels reach the investigations through `impactRefresh`** (investigation.go ~:1281-1310).
- **`vexplain_entry_points`' help text and `measure`'s comment say "an address" where the state is an IP's** (metrics.go ~:204-206, exposure/metrics.go ~:32-35).
- **`Ambiguous` shares one list of clusters among the subjects of an IP,** read-only by convention (view.go ~:626-640).

### Presence and the stores

- **The sink validates each presence event twice, at an upsert and in a snapshot** (store_sink.go ~:251-262, ~:483-490). It costs little.
- **`Presence.refuse` reads the cluster's name for each refused event, on the stream's goroutine** (presence.go ~:395-406), each read bounded at 10 seconds: read it once per snapshot.
- **`StoreSink.refuse(…, kept bool)` does two jobs** (store_sink.go ~:504-516).
- **`DeleteBySource` parses its first selector from a string, and returns its error unwrapped** (evidence/crdstore.go ~:448-450). It can't fail, since `source` is checked first.

### The renderer

- **After an accepted change of identity, the former identity's `PlaybookClusterStatus` counts stay until the new cluster's sweep settles, and for good if it never syncs** (remote_reports.go ~:322-330, ~:542-552).
- **Renaming the hub's cluster away from a `Spoke`'s name can delete that `Spoke`'s counts** (counts.go ~:161-167), and the remote renderer's memory of what it wrote skips them until their totals change (remote_reports.go ~:550).
- **`lastSyncTime` and the view's copies aren't ordered:** a first round's sweep can render a workload before the view holds all of its exposure copies, for milliseconds.
- **The view keeps decoded presence for the hub's own cluster too, which nothing on the hub reads** (view.go ~:348-366): measure the memory first.
- **`cloneWorkload` is duplicated** (remote/running.go ~:134, spoke/presence.go ~:560).
- **Small things of the renderers:** `ReportsCollector.set` takes the cluster twice, as an argument and in the series (metrics.go ~:178); `said` shadows its type (exposure.go ~:154), and `shown` is shadowed (exposure.go ~:323, metrics_internal_test.go ~:569); the `cluster` field stands above `mu` (reports.go ~:102-103); `ReportsCollector`'s doc says "one entry for each report" (metrics.go ~:160-161); and running.go aliases the SDK's evidence `sdkevidence` (~:27), against `evidence` elsewhere in the package.

### Tests

- **Flaky under load:**
  - the hub suite's "reuses a verdict judged elsewhere under IfStale, counts it, and names up to 5 such cases in an event" (investigation_test.go ~:1353): two JudgedElsewhere events where one was expected, once in five runs. The event is emitted once a reconcile, with a count that changes, so two can exist;
  - `internal/spoke`'s `TestAfterAStartNothingIsForgottenOrDeletedBeforeEveryPresenceCollectorHasSentItsSnapshot` (reports_test.go ~:598), a test of a snapshot's timing: it failed once under the gate's parallel load, and passed alone. It already waits for its cache;
  - `internal/agent/worker`'s `TestAnEndpointDownFromTheFirstRequestNeverEndsTheCase` (judge_test.go ~:1581): Judging where Queued was expected, once under the gate's parallel load; 8 of 8 alone. Untouched since phase 4;
  - the assessor's spec "asks for an image's evidence, and matches its manifest, once a Spoke lists the producer that the playbook lacked" (assessor_test.go ~:227) still rests on timing; the playbook's spec "checks a playbook again when its status is written" (playbook_controller_test.go ~:323) stands in for the race with an outside write.
- **Untested:**
  - `DeleteBySource` of a store whose own cluster is empty;
  - that an executor without presence waits for no snapshot: its test (executor_test.go ~:1038-1052) covers `invoke`'s guard only, though its comment claims both;
  - that a `WrongRole` collector's capabilities stay recorded (collector_controller_test.go ~:1489);
  - `platformsOf`'s cap at 16, and a waiting request replaced with the newest platforms. The refused pull's test checks "no evidence" on one manifest's record only (executor_test.go ~:1019-1036);
  - the grace of an unreachable spoke: its spec moves `Connected`'s time 3 minutes back, so it doesn't pin the 2 minutes (spoke_controller_test.go ~:313-344);
  - a failed list of the `Spoke`s in the playbook's check;
  - the local renderer's rename branch (reports.go ~:467-472);
  - a relabelled `Spoke` looked at again, and a render again after an exposure copy changes;
  - that a case is queued before its `Assessment` says `Queued`: the hub suite has no seam that fails `asQueued` after the record;
  - the spec of two playbooks in both orders passes if either investigation hands over the union (investigation_test.go ~:901): it needs a `Consistently`;
  - the switch of a `config/default` install to `config/hub` in place, which the guide gives from the code, not from a run;
  - in the e2e suite, that the hub's scan used the admin's login, since the e2e registry asks for none;
  - `hack/measure-6`'s code that talks to the clusters, which only its runs cover.
- **Form:**
  - the plan's names of the modes' and the Spoke controller's tests are Ginkgo specs of other names (modes_test.go ~:239-265, spoke_controller_test.go);
  - exposure_test.go's comment (~:468) names the cost limit, though the long bounds apply to every row;
  - presence_test.go (~:678-679) says that the collector "sent" `testdata/upgrade-presence.json`, which is rebuilt from an inventory;
  - capabilities_test.go (~:109-111) depends on the golden file's indentation;
  - the hub suite's wait for a deleted `Collector` uses a throwaway `Get` (playbook_controller_test.go ~:220-223);
  - the specs of a bad `Spoke` name assert only `Not(Succeed())`, not the CEL rule's message (spoke_api_test.go ~:78);
  - the check that the manager's role stays asserts only that it has no `serviceaccounts/token` rule, so the Makefile's exclusion is unpinned (install_test.go ~:172-175), and the test's constants `verbCreate` and `readVerbs` changed two older tests;
  - `TestIndexRunningIsWhatPresenceIndexes` compares the images and `Workload.Name` only, with one collector (presence_test.go ~:733-758);
  - the hub suite's `Spoke` of cluster-b lists the names of the local workloads, network-reach and vm collectors too, which its comment doesn't say (suite_test.go ~:149-152);
  - the test spoke's helper says that a manager that never starts fails "at once", but a `Start` error waits for the bound, and a failed `require` leaks the manager (fixtures_test.go ~:285-306);
  - three comments run past 120 columns, unlike their neighbours (result/platform.go ~:29, pool.go ~:263, connect.go ~:83);
  - PROJECT lists `Spoke` between `Playbook` and `Rule`;
  - the e2e helper's variable `token` holds a volume source's JSON (helpers_test.go ~:97), and the e2e suite takes about 40 of its 60 minutes (Makefile ~:177);
  - in `hack/measure-6`, a stray write inside the quiet minute extends a phase's span to it (writes.go `lastChange`, ~:194-196), which errs long; and `make cleanup-measure-6` under the default names doesn't keep the registry for e2e clusters of other names, as the doc says.
