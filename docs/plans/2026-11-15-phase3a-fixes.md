# vexplain — Phase 3a's fixes Implementation Plan

> **For agents:** follow `AGENTS.md`. Implement this plan task by task, test first. A task is done when its tests pass, it is committed and it has been reviewed; only then start the next one. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** fix what phase 3a's live run found, before the agent (phase 4) judges image cases on top of it:
- completeness that counts a file once;
- failed catalogers that hold only their own packages;
- a reason for every image without a verdict;
- a quiet manager;
- a numeric urgency rank;
- `PlaybookClusterStatus`;
- the evidence store's cap as a setting;
- a certificate authority that survives restarts.

Then comes the owner's live run, with the cluster settings.

**Architecture:** no new component.
- **The scanner** keeps hard links when it unpacks an image, and names the package types of a failed cataloger. The completeness guard reads them.
- **The manager's evidence store** reads its cap from `OperatorConfig`.
- **The spoke's renderer** reads the scan failures it already has.
- **The certificate authority** lives in a Secret.

**Tech Stack:** as in phase 3a, with no new dependency. The registry's name comes from go-containerregistry, which the root module already uses.

**Spec:**
- `docs/design/2026-11-15-phase3a-fixes.md`, with decision record 0050;
- the collector model (revision 10) and the main design (revision 16), where they point to it;
- phase 3a's plan (`docs/plans/2026-11-08-phase3a-collector-model.md`) and its "As built" section, which describe what exists.

**Branch:** `feat/phase3a-fixes`, from `docs/agent-first`, which holds the design revision. The two are stacked until the design merges.

**Not in this plan:**
- the SOC's view (the action metric, the plan dashboard and the CVE lookup) and the agent, which are phase 4;
- everything of phase 3b;
- exceptions.

## Decisions made in this plan

The design leaves these to the builder, or the code showed them while planning. Each is decided here so that implementers don't guess.

1. **Hard links stay links (2.1).** Today the scanner's unpacker turns a tar hard link into a copy, so the analyzer can't tell the two apart.
   - The unpacker makes a real link (`os.Link`).
   - A later entry at a linked path replaces the path, and never writes through the shared file.
   - The analyzer counts a file once per device and inode.
   - Symlinks don't change: they are never read as ELF files, and a listed symlink owns only itself.
2. **The failed catalogers' package types (2.2)** go into a new optional field of the `sbom` type: `catalogerFailures`, a list of `{cataloger, packageTypes}`.
   - `failedCatalogers` stays next to it.
   - The scanner maps the catalogers of the Syft version it pins. A name it doesn't know gets no types, and so holds everything.
   - The package types are Syft's names: the same as an SBOM package's `type` and a finding's `packageType`.
3. **Five reasons for an image without a verdict (2.3):** `Waiting`, `PullRefused`, `TooLarge`, `ScanFailed` and `NoDigest`.
   - `ScanFailed` is a failure that is neither a refused pull nor over the cap (the design's amendment).
   - Every reason but `Waiting` makes the image `Unscannable`.
4. **The registry** in a refused pull's message is the host of the image's reference, as the workload names it, parsed with go-containerregistry.
5. **A collector that isn't ready (2.4)** answers `NotReady`.
   - The hub's findings call returns `ErrCollectorNotReady`.
   - The assessor tries the manifest again after 30 seconds, without returning an error.
   - It logs once per collector, until that collector matches again.
6. **The urgency rank (2.5)** is `urgencyRank`:
   - 1 for `Immediate`, 2 for `OutOfCycle`, 3 for `Scheduled` and 4 for `Defer`;
   - 0 for an outcome the renderer doesn't know, which it already treats as the most urgent.

   Sorting in ascending order puts the most urgent first.
7. **The rename (2.6)** gives the types `PlaybookClusterStatus`, `PlaybookClusterStatusSpec`, `PlaybookClusterStatusStatus` and `PlaybookClusterStatusList`. Gatekeeper names `ConstraintPodStatusStatus` the same way. Go names about counts (`CountsStore`, `TallyOf`, `playbookCountsOf`) stay.
8. **The cap (2.7)** is `OperatorConfig`'s `spec.evidence.maxCompressedBytes`: default 786432, minimum 65536, maximum 2097152.
   - An Evidence object's `data` may then hold 2796204 base64 characters.
   - The scanner's copy of the cap goes (the design's amendment).
   - The limit before compression, 64 MiB, stays.
9. **Raising the cap retries (2.7).**
   - A `TooLarge` failure records its size and the cap it failed against.
   - When the cap in force is larger, the hub retries the failure at once.
   - A change of `OperatorConfig` wakes the manifests that have such a failure.
   - The metric is a counter, `vexplain_evidence_too_large_total`. The event `EvidenceTooLarge` goes on the image's `ImageInventory`.
10. **The authority's Secret (2.8)** is `vexplain-collector-ca`, of type `Opaque`, with the keys `ca.crt` and `ca.key`. It is read through the API reader, as the leaf Secrets are. In its last 90 days the authority is replaced like a missing one (the design's amendment).

## Decisions for the owner

1. **The cost of 2.8, stated precisely.**
   - With the authority's key in a Secret, the scanner could read it, since it may get any Secret by name. It could then sign a client certificate as the manager and call every collector.
   - Today it can read only the collectors' server keys. Phase 2b kept the key in memory for this reason.
   - The plan keeps your decision. The alternative is to keep the key in memory, and have the manager wait quietly through the gap after a restart, as it waits for a collector that isn't ready.
2. **A fifth reason, `ScanFailed`** (decision 3).
3. **The authority is replaced once every 10 years, with a gap,** rather than both authorities being trusted for a while (decision 10).
4. **The cap stops at 2 MiB** (decision 8), the most that the API server takes in a request.

## Global Constraints

- **AGENTS.md binds:** design first, test first, kind only, no private data and no figures from real platforms, no AI attribution, and comments that state their own reason and never cite a ruling of a ledger.
- **Phases 1 to 3a still bind,** as amended by their "As built" sections: API conventions, kube-api-linter, RBAC from markers, wiring through `setup.Register`, tests and commits.
- **Before each commit:** `make manifests generate && make proto-check && make lint && make test`.
- **e2e:** one `make test-e2e`, on kind, at the end of each task that changes a CRD, the install or the manager.
- **The API is `v1alpha1` and unreleased:** fields are added or changed without conversion.
- **A fresh install** (owner, 2026-11-08). The README says that a cluster with phase 3a deletes the CRD `playbookcounts.inventory.vexplain.bedag.ch` first.
- **Names:**
  - the kind `PlaybookClusterStatus`, with the resource `playbookclusterstatuses`, in `inventory.vexplain.bedag.ch`, in the categories `vexplain` and `vexplain-data`;
  - the image reasons `Waiting`, `PullRefused`, `TooLarge`, `ScanFailed` and `NoDigest`;
  - the Secret `vexplain-collector-ca`;
  - the event reason `EvidenceTooLarge`;
  - the metric `vexplain_evidence_too_large_total{cluster, collector}`.
- **Values:**
  - the cap: default 786432, minimum 65536, maximum 2097152 bytes compressed;
  - an Evidence object's `data`: at most 2796204 characters;
  - `urgencyRank`: from 0 to 4;
  - a `NotReady` match: tried again after 30 seconds.
- **Unchanged values:** certificates last 90 days and are renewed 30 days before their end; the authority lasts 10 years; the completeness guard's threshold is 90 %.
- **Metrics** start with `vexplain_` and carry `cluster`.
- **Keys and secrets:** pull secrets and the authority's key never appear in logs, status, events, metrics, errors or evidence.
- **Commits:** Conventional Commits, signed, no AI attribution, never on `main`.
- **Repository hygiene:** neutral names, such as `cluster-a`, `team-a` and `artifacts.example`.

## Review Focus

1. **A later layer that writes over, or deletes, one name of a hard-linked file:** the other names keep the old content, and the counts follow (Task 2).
2. **An SBOM from a producer that names failed catalogers without their types:** every finding stays held (Task 3).
3. **A cap lowered below what is already stored:** stored evidence stays readable, and only new writes are refused (Task 4).
4. **An image whose producers failed in different ways:** the report shows one reason, in a fixed order: `PullRefused`, then `TooLarge`, then `ScanFailed` (Task 6).
5. **An authority Secret that can't be read,** such as a key that doesn't parse: it is replaced like a missing one, with a log line that names the Secret and never its content (Task 9).

---

## File Structure

```text
api/inventory/v1alpha1/
  playbookclusterstatus_types.go   # Task 1 (from playbookcounts_types.go)
  evidence_types.go                # Task 4: data's maximum
  imageinventory_types.go          # Task 4: a failure's size and cap
api/config/v1alpha1/operatorconfig_types.go   # Task 4: spec.evidence
api/triage/v1alpha1/resourcereport_types.go   # Tasks 6, 7: image reasons, urgencyRank
sdk/evidence/                      # Task 3: catalogerFailures in the sbom type
collectors/scanner/internal/pull/    # Task 2: hard links
collectors/scanner/internal/analyze/ # Tasks 2, 3: files once per inode; catalogers.go (new)
collectors/scanner/internal/result/  # Task 3: coverage
collectors/scanner/internal/scan/    # Tasks 3, 4: coverage, the cap's copy goes
config/rules/completeness-guard.yaml # Task 3
internal/evidence/                 # Task 4: the cap as an option, TooLargeError
internal/settings/                 # Task 4
internal/spoke/                    # Tasks 1, 4, 5, 6, 7, 8: counts, executor, renderer, reports
internal/controller/hub/           # Tasks 1, 5, 8: fleet, retries, NotReady
internal/collector/certs/          # Task 9
internal/metrics/metrics.go        # Task 5
README.md, docs/collectors.md      # each task, for what it changes
test/e2e/                          # Tasks 1, 9
```

## Task order

`make test` stays green after every task.
- **Task 1:** the rename first, since later tasks touch the same files.
- **Tasks 2 and 3:** the scanner and the completeness guard.
- **Tasks 4 and 5:** the cap.
- **Tasks 6 and 7:** the report.
- **Task 8:** the quiet manager.
- **Task 9:** the certificate authority.
- **Task 10:** the live run, with the owner.

### Task 1: `PlaybookCounts` becomes `PlaybookClusterStatus` (2.6)

**Files:**
- **Move:**
  - `api/inventory/v1alpha1/playbookcounts_types.go` → `playbookclusterstatus_types.go`;
  - `config/rbac/inventory_playbookcounts_viewer_role.yaml` → `inventory_playbookclusterstatus_viewer_role.yaml`;
  - `internal/controller/inventory/playbookcounts_api_test.go` → `playbookclusterstatus_api_test.go`.
- **Modify:**
  - **Code:** `internal/inventory/counts.go` (types and RBAC markers), `internal/setup/setup.go`, `internal/controller/hub/fleet.go`, `internal/spoke/counts.go` and the comment in `internal/spoke/render.go`.
  - **Config and build:** `PROJECT`, `.golangci.yml` (the kube-api-linter exclusion), and the `kustomization.yaml` files in `config/crd`, `config/rbac` and `config/samples`.
  - **Docs:** `README.md`.
- **Regenerate:** `zz_generated.deepcopy.go`, the CRD (`inventory.vexplain.bedag.ch_playbookclusterstatuses.yaml`; delete the old file) and `config/rbac/role.yaml`.
- **Tests:**
  - `internal/controller/hub/{fleet,metrics}_test.go`;
  - `internal/spoke/counts_test.go`;
  - `internal/conditions/{crds,readable}_test.go`;
  - `internal/setup/install_test.go`;
  - `test/e2e/e2e_test.go`.

Behaviour doesn't change. Phase 3a's plan keeps the old name as history.

- [ ] **Step 1: Update the tests to the new names.** `install_test.go` lists `playbookclusterstatuses` and `playbookclusterstatuses/status`, and the e2e reads `PlaybookClusterStatus`.
- [ ] **Step 2: Run `make test`,** and see them fail.
- [ ] **Step 3: Rename,** keeping the markers' categories, columns and name rule. The README's upgrade note says to delete the old CRD first.
- [ ] **Step 4: Verify** with the gate and `make test-e2e`.
- [ ] **Step 5: Commit:** `refactor(api): rename PlaybookCounts to PlaybookClusterStatus`

### Task 2: The scanner counts each file once (2.1)

**Files:**
- `collectors/scanner/internal/pull/extract.go` and `extract_test.go`;
- `collectors/scanner/internal/analyze/analyze.go`, `elf.go` and `analyze_test.go`;
- `docs/collectors.md` (one line on completeness).

- [ ] **Step 1: Write the failing tests.**
  - **In `extract_test.go`:**
    - `TestAHardLinkInsideTheRootIsALink`: a layer with `bin/busybox` and the hard links `bin/ls` and `bin/cat` unpacks to three names of one file (`os.SameFile`). This replaces the assertion "A hard link inside the root is a copy" in `TestExtractKeepsEverythingInsideDir`.
    - `TestALaterLayerThatWritesAtALinkedPathLeavesTheOtherName`: layer 1 has `bin/busybox` with content A, and `bin/ls` linked to it. Layer 2 writes `bin/ls` with content B. Then `bin/busybox` reads A, `bin/ls` reads B, and they aren't the same file.
    - The same case with a whiteout of `bin/busybox` in layer 2: `bin/ls` still reads A.
  - **In `analyze_test.go`,** with a helper `testRoot.hardLink(name, target)` that calls `os.Link`:
    - `TestHardLinksToAnOwnedELFFileCountOnce`: an apk root where the package `busybox` owns `bin/busybox`, with five hard links to it, gives `ELFSummary{Total: 1, Owned: 1}` and completeness 100.
    - `TestHardLinksToAnUnownedELFFileCountOnce`: an unowned ELF file with three hard links gives `Total: 1, Owned: 0`, and `Unowned` holds its first path in walk order.
    - `TestACopyOfAnOwnedBinaryStaysUnowned`: an owned ELF file plus a byte-identical copy that no package lists gives `Total: 2, Owned: 1`, `Unowned: [the copy]` and completeness 50.
    - `TestThePackageFactsCountAHardLinkedFileOnce`.

  The symlink tests stay as they are.
- [ ] **Step 2: Run** `cd collectors/scanner && go test ./internal/pull ./internal/analyze`, and see them fail.
- [ ] **Step 3: Implement.**
  - **`(u *unpacker) hardLink`** links to the target with `os.Link`, under the existing checks that keep it inside the root. A target that isn't written yet stays pending, as today. A copy is only the fallback if `os.Link` fails: two files never count fewer unowned than one.
  - **Writing a file, a symlink or a directory at an existing path** removes the path first.
  - **`walk`** records each regular file's device and inode, through `syscall.Stat_t`.
  - **`readELFFiles`** returns one `elfFile` per inode, with its paths in walk order. Its owners are the union of its paths' owners.
  - **`elfSummary`** lists the first path of an unowned file, and **`packageFacts`** counts a file once.
- [ ] **Step 4: Verify** with `cd collectors/scanner && go test ./...`, then the gate.
- [ ] **Step 5: Commit:** `fix(scanner): count a hard-linked file once`

### Task 3: A failed cataloger holds only its package types (2.2)

**Files:**
- **The SDK:** `sdk/evidence/types.go`, `sdk/evidence/schemas/ch.bedag.vexplain.sbom.v1alpha1.json` and `types_test.go`.
- **The scanner:**
  - `collectors/scanner/internal/analyze/syft.go`, `catalogers.go` (new) and `analyze_test.go`;
  - `internal/result/result.go` and `result_test.go`;
  - `internal/scan/operation.go` (the comment near the coverage) and `operation_test.go`.
- **The guard:** `config/rules/completeness-guard.yaml` and its copy in `config/samples/config_v1alpha1_playbook.yaml`.
- **Tests and docs:** `internal/rules/engine/defaults_test.go` and `docs/collectors.md`.

**Interfaces:**
- **Produces:** `evidence.CatalogerFailure{Cataloger string; PackageTypes []string}` (JSON `cataloger`, and `packageTypes` with `omitempty`), and `evidence.SBOM.CatalogerFailures []CatalogerFailure` (JSON `catalogerFailures`, `omitempty`).
- **In the scanner:** `packageTypesOf(cataloger string) []string`.

- [ ] **Step 1: Write the failing tests.**
  - **The scanner:**
    - `TestAFailedCatalogerNamesItsPackageTypes`: a Syft document whose unknowns name `dotnet-deps-binary-cataloger` gives `CatalogerFailures: [{dotnet-deps-binary-cataloger, [dotnet]}]`, and `FailedCatalogers` keeps the name. A cataloger missing from the table gives an entry with no types.
    - `TestTheCoverageIsTheCompletenessEvenWhenACatalogerFailed` replaces `TestTheCoverageIsTheCompletenessUnlessACatalogerFailed`.
    - `TestAFailedCatalogerKeepsTheCoverageOfBothEventsOfItsManifest` replaces `…GivesBothEventsOfItsManifestTheCoverageZero`. The `sbom` event lists the failure.
  - **The SDK:** the schema takes `catalogerFailures`, and refuses an entry without `cataloger`.
  - **The rules engine,** with coverage 100 and `scanOf` extended to take failed catalogers:
    - a `dotnet` finding with a failed `dotnet` cataloger is held (`UnderInvestigation`), and the reason names the package type;
    - a `deb` finding with only that failure isn't held by the guard;
    - a failure with no known types holds every finding;
    - an SBOM with `failedCatalogers` and no `catalogerFailures`, as another producer writes it, holds every finding;
    - with no failure, coverage 89 is held and 90 isn't, as today.
- [ ] **Step 2: Run** the scanner's, the SDK's and `go test ./internal/rules/...`, and see them fail.
- [ ] **Step 3: Implement.**
  - **`catalogers.go`:** a table of the image catalogers of the Syft version the scanner pins, and the package types each emits. For example: `dotnet-deps-binary-cataloger` → `dotnet`, `dpkg-db-cataloger` → `deb`, `go-module-binary-cataloger` → `go-module`, `java-archive-cataloger` → `java-archive` and `jenkins-plugin`. Check each against the pinned Syft.
  - **`failedCatalogers`** fills both fields.
  - **`Scanned.Coverage()`** returns `Completeness()`. The comments that said a failure means 0 change with it.
  - **The guard** takes `sbom` as a second input. Its condition, in both copies:

    ```yaml
    condition: >-
      contents.coverage < 90 ||
      (has(sbom.data.failedCatalogers) && sbom.data.failedCatalogers.exists(n,
        !(has(sbom.data.catalogerFailures) && sbom.data.catalogerFailures.exists(f,
            f.cataloger == n && has(f.packageTypes) && size(f.packageTypes) > 0)) ||
        sbom.data.catalogerFailures.exists(f,
            f.cataloger == n && has(f.packageTypes) && finding.packageType in f.packageTypes)))
    ```

    Its reason keeps today's text for coverage. Otherwise it names the finding's package type, or says that a cataloger whose package types are unknown failed.
- [ ] **Step 4: Verify** with the same tests, then the gate.
- [ ] **Step 5: Commit:** `fix(scanner,rules): hold only the findings of a failed cataloger's package types`

### Task 4: The evidence store's cap is a setting (2.7)

**Files:**
- **The API:** `api/config/v1alpha1/operatorconfig_types.go`, `api/inventory/v1alpha1/evidence_types.go` and `imageinventory_types.go`.
- **Settings:** `internal/settings/effective.go` and `effective_test.go`.
- **The store:** `internal/evidence/store.go`, `crdstore.go`, `crdstore_test.go` and `facts.go`.
- **Wiring and the executor:** `internal/setup/setup.go`, `internal/spoke/executor.go` and `executor_test.go`.
- **The scanner:** `collectors/scanner/internal/scan/operation.go` and `operation_test.go`.
- **Other tests:** `internal/controller/inventory/evidence_api_test.go`, `internal/controller/config/operatorconfig_api_test.go`, and `hack/measure-2a/main.go`.
- **Docs and samples:** `config/samples/config_v1alpha1_operatorconfig.yaml` and `README.md`.

**Interfaces:**
- **Produces:**
  - `OperatorConfigSpec.Evidence *EvidenceSettings`, with `MaxCompressedBytes *int64` (`+kubebuilder:default=786432`, minimum 65536, maximum 2097152);
  - `settings.Effective.EvidenceMaxCompressedBytes int64`;
  - `evidence.DefaultMaxCompressedBytes = 786432`, renamed from `MaxCompressedBytes`;
  - `NewCRDStore(c, informers, cluster, opts ...Option)` with `evidence.WithMaxCompressedBytes(func() int64) Option`, read at each `Put`;
  - `evidence.TooLargeError{Bytes, Cap int64; Compressed bool}`, with `Is(ErrTooLarge)`;
  - `ScanFailure.SizeBytes` and `CapBytes` (`*int64`, minimum 0), set only for `TooLarge`.

- [ ] **Step 1: Write the failing tests.**
  - **Settings:** an absent field gives 786432, and a set field is read. The API refuses 65535 and 2097153.
  - **The store:**
    - with the cap at 1048576, an event of 900 KiB compressed is stored;
    - with the default cap, the same event is refused with a `TooLargeError` that has `Cap: 786432`, and `errors.Is(err, ErrTooLarge)` holds;
    - after the cap is lowered, stored evidence is still read (Review Focus 3).
  - **The Evidence API:** `data` of 2796204 characters is accepted, and one more is refused.
  - **The executor:** the store's `TooLargeError` gives the failure `TooLarge`, with `sizeBytes`, `capBytes` and a message that names both.
  - **The scanner:** an SBOM over 786432 bytes compressed is emitted. Only an answer that the transport can't carry (16 MiB) fails as `TooLarge`.
- [ ] **Step 2: Run** `make test`, and see them fail.
- [ ] **Step 3: Implement.**
  - **Setup** passes `WithMaxCompressedBytes`, which reads the settings at each call, as the cluster's name is read.
  - **The README** gets a section "The evidence store's cap": the field, its default, its maximum and why, and that past about 1.1 MiB etcd's limit for a request must be raised as well, as kind allows.
  - **The sample `OperatorConfig`** shows the field.
- [ ] **Step 4: Verify** with the gate and `make test-e2e`.
- [ ] **Step 5: Commit:** `feat(evidence): make the evidence store's cap a setting`

### Task 5: A raised cap retries; a metric and an event (2.7)

**Files:**
- `internal/controller/hub/assessor.go` and `assessor_test.go`;
- `internal/metrics/metrics.go`;
- `internal/spoke/executor.go` and `executor_test.go`, and the tests that call `NewExecutor`;
- `internal/setup/setup.go`;
- `README.md`.

**Interfaces:**
- **Consumes:** `ScanFailure.SizeBytes` and `CapBytes`, and `settings.Effective.EvidenceMaxCompressedBytes` (Task 4).
- **Produces:** `NewExecutor(pool, c, presence, store, facts, recorder events.EventRecorder)`, and `metrics.EvidenceTooLargeTotal`.

- [ ] **Step 1: Write the failing tests.**
  - **The hub:**
    - an image failed `TooLarge` with `capBytes` 786432. While the cap stays at 786432, it waits out its back-off as today;
    - once the cap is 1048576, its manifest is requested again at once;
    - a change of `OperatorConfig` wakes exactly the manifests that have a `TooLarge` failure.
  - **The executor:** a refusal raises `vexplain_evidence_too_large_total{cluster, collector}`. It also records a Warning event `EvidenceTooLarge` on the image's `ImageInventory`, which names the collector, the size and the cap.
- [ ] **Step 2: Run** `make test`, and see them fail.
- [ ] **Step 3: Implement.**
  - **`retryAfter`** takes the cap in force.
  - **The assessor's `SetupWithManager`** watches `OperatorConfig`, and maps a change to the manifests with a `TooLarge` failure.
  - **Setup** passes `mgr.GetEventRecorder(eventSource)` to the executor.
  - **The counter** is registered in `init()`, next to `EvidenceDroppedTotal`.
- [ ] **Step 4: Verify** with the gate.
- [ ] **Step 5: Commit:** `feat: retry the images over the cap when it is raised, and count them`

### Task 6: Every image without a verdict says why (2.3)

**Files:**
- `api/triage/v1alpha1/resourcereport_types.go`;
- `internal/spoke/render.go`, `render_test.go` and `reports.go`;
- `internal/controller/triage/resourcereport_api_test.go`;
- `test/e2e/e2e_test.go`;
- `README.md`.

**Interfaces:**
- **Produces:**
  - `ResourceImage.Reason *ResourceImageReason`, an enum of `Waiting`, `PullRefused`, `TooLarge`, `ScanFailed` and `NoDigest`;
  - `ResourceImage.Message *string`, at most 256 characters;
  - a CEL rule: `reason` is set exactly when `state` is `Pending` or `Unscannable`, and `Waiting` goes only with `Pending`.

| The renderer sees | State | Reason | Message |
|---|---|---|---|
| no digest (an image ID or a reference) | `Unscannable` | `NoDigest` | `the runtime reports no digest for this image` |
| a failure `Unauthorized`, `NotFound` or `NotPullable` | `Unscannable` | `PullRefused` | `<registry> refused the pull: <reason>` |
| a failure `TooLarge` | `Unscannable` | `TooLarge` | `<sizeBytes> bytes compressed; the evidence store's cap is <capBytes> bytes` |
| any other failure | `Unscannable` | `ScanFailed` | `<reason>: <the failure's message>`, cut to 256 |
| no failure, and the evidence or sheets aren't complete | `Pending` | `Waiting` | none |

- When several producers failed, the first reason in the order `PullRefused`, `TooLarge`, `ScanFailed` decides.
- `pendingImages` counts `Pending` and `unscannableImages` counts `Unscannable`, over every image, as today.
- The registry is `name.ParseReference(ref)`'s `Context().RegistryStr()`. A reference that doesn't parse is named whole.

- [ ] **Step 1: Write the failing tests.**
  - One `render_test.go` test for each row of the table.
  - `TestASummaryCountsTheImagesThatHaveNoVerdictYet` now expects `Unauthorized` to count as unscannable, with `pendingImages` 0.
  - Producers that failed in different ways (Review Focus 4).
  - The API test refuses a reason without a state that takes one, and `Waiting` with `Unscannable`.
- [ ] **Step 2: Run** `make test`, and see them fail.
- [ ] **Step 3: Implement.** `reportImages` reads `facts.Failures`, which it holds already. The doc comments of `pendingImages` and `unscannableImages` change with it.
- [ ] **Step 4: Verify** with the gate and `make test-e2e`.
- [ ] **Step 5: Commit:** `fix(spoke): say why an image has no verdict`

### Task 7: A numeric urgency rank (2.5)

**Files:**
- `api/triage/v1alpha1/resourcereport_types.go`;
- `internal/spoke/render.go` and `render_test.go`;
- `internal/controller/triage/resourcereport_api_test.go`;
- `README.md`.

**Interfaces:**
- **Produces:**
  - `ResourceSummary.UrgencyRank *int32` (JSON `urgencyRank`, minimum 0, maximum 4);
  - the rule `has(self.urgencyRank) == has(self.highestUrgency)` on `ResourceSummary`;
  - a printer column `Urgency Rank` at priority 1.

- [ ] **Step 1: Write the failing tests.**
  - **Each outcome's rank:** `Immediate` 1, `OutOfCycle` 2, `Scheduled` 3, `Defer` 4, and an unknown outcome 0.
  - **No urgency, no rank.**
  - **The API test** refuses a rank without an urgency, and an urgency without a rank.

  The `summaryOf` helper in `render_test.go` sets the rank too.
- [ ] **Step 2: Run** `make test`, and see them fail.
- [ ] **Step 3: Implement** in `summaryOf`, from the order that `rank()` already uses.
- [ ] **Step 4: Verify** with the gate and `make test-e2e`.
- [ ] **Step 5: Commit:** `feat(triage): give the report's summary a numeric urgency rank`

### Task 8: The manager waits quietly, and skips namespaces being deleted (2.4)

**Files:**
- `internal/controller/hub/findings.go`, `findings_test.go`, `assessor.go` and `assessor_test.go`;
- `internal/spoke/reports.go`, `namespaces.go` and `reports_test.go`.

**Interfaces:**
- **Produces:** `hub.ErrCollectorNotReady`, which `Find`'s error matches with `errors.Is` when the failure's reason is `NotReady`.

- [ ] **Step 1: Write the failing tests.**
  - **`findings_test.go`:** a `NotReady` failure gives an error that matches `ErrCollectorNotReady`.
  - **`assessor_test.go`:**
    - a match that fails with `NotReady` gives `ctrl.Result{RequeueAfter: 30 * time.Second}` and no error, and keeps the sheet;
    - a test log sink sees one line per collector until a match succeeds, and a later `NotReady` logs again.
  - **`reports_test.go`,** on envtest: a namespace with a finalizer is deleted, so it stays with a deletion timestamp.
    - A new workload there gets no report, and the reconcile returns no error.
    - A report that is already there is still updated.
- [ ] **Step 2: Run** `make test`, and see them fail.
- [ ] **Step 3: Implement.**
  - **`Find`** wraps the sentinel.
  - **`assess`** returns the requeue, logging once, with a guarded map on the `Assessor` as its other remembered state does.
  - **`render`** skips creating a report when the namespace's metadata, which it already reads, has a deletion timestamp.
- [ ] **Step 4: Verify** with the gate.
- [ ] **Step 5: Commit, twice:**
  - `fix(hub): wait quietly for a collector that isn't ready`
  - `fix(spoke): create no report in a namespace being deleted`

### Task 9: The collectors' certificate authority survives a restart (2.8)

**Files:**
- `internal/collector/certs/authority.go` (the code, and the package doc, which said the key never goes into a Secret), `authority_test.go` and `export_test.go`;
- the tests that build an authority: `internal/collectorclient/{main_test,pool_test}.go`, `internal/spoke/{executor,presence}_test.go` and `internal/controller/config/collector_controller_test.go`;
- `internal/settings/effective.go` (the deny list's comment);
- `test/e2e/e2e_test.go`;
- `README.md` (the security section).

**Interfaces:**
- **Produces:** the Secret `vexplain-collector-ca`, of type `Opaque`, in the operator's namespace, with `ca.crt` and `ca.key` as PEM.

- [ ] **Step 1: Write the failing tests.** Three tests are inverted:
  - `TestTheAuthorityIsKeptInASecretAndLoadedAfterARestart` replaces `…CreatedOncePerProcessAndKeptInMemory`. The first `EnsureServer` creates the Secret. After `restart()`, the same authority is loaded, no server Secret is written again, and the old certificates still handshake.
  - `TestARestartIssuesNothingNew` replaces `TestARestartIssuesANewAuthorityAndEveryServerCertificateAgain`.
  - `TestOnlyTheAuthoritysSecretHoldsItsKey` replaces `TestNoSecretHoldsTheKeyOfTheAuthority`.

  And four are new:
  - `TestTwoManagersStartingAtOnceShareOneAuthority`: a create that loses with `AlreadyExists` (through `interceptor.Funcs`) loads the winner's Secret.
  - `TestAnAuthorityInItsLast90DaysIsReplaced`: every leaf is issued again under the new authority.
  - `TestAnUnreadableAuthoritySecretIsReplaced` (Review Focus 5). `TestNoPrivateKeyIsLogged` stays.
  - **e2e:** a restart of the manager rewrites no collector's TLS Secret, and a match right after it succeeds.
- [ ] **Step 2: Run** `go test ./internal/collector/certs/` and `make test`, and see them fail.
- [ ] **Step 3: Implement.** `ensureCA` loads the Secret through the reader, creates it if absent, and on `AlreadyExists` reads it again. The manager's RBAC already allows `get`, `create` and `update` on Secrets in its namespace. The package doc and the README say that the key is in that Secret, and that a collector that may get Secrets there by name could read it.
- [ ] **Step 4: Verify** with the gate and `make test-e2e`.
- [ ] **Step 5: Commit:** `fix(certs): keep the collectors' certificate authority across restarts`

### Task 10: The live run, with the owner (sections 3 and 4)

This task isn't for an agent. The owner installs the branch's images on the shared cluster, after deleting the CRD `playbookcounts.inventory.vexplain.bedag.ch`, and checks:
- **the cluster settings of section 3,** each with its check: trusted peers, `adminPullSecrets`, the database across a restart, and the test namespaces scoped out;
- **section 4's list:**
  - the completeness guard's holds;
  - every image without a verdict, with its reason;
  - the manager's log at start;
  - a manager restart without failed matches;
  - the cap raised for the large Java image.

The findings stay in the owner's private notes. Only what changes phase 4's plan goes into "Carried forward", in neutral words.

## As built

Where the build differs from the text above, the build is right. Each difference was decided and reviewed while the plan ran, or in the review of the whole plan and its fix wave. The design's section 2 has amendment notes where the build changed it.

### Hard links (Task 2)

- **The unpacker writes the layers from the top down, and the first entry at a path wins.** So an upper layer's entry replaces a lower one's, and directories merge, as before. A hard link whose target an upper layer hides gets its own layer's content.
- **A hard link's target is resolved inside the root,** as every other path is, so a link can't reach outside it. When `os.Link` fails, the unpacker copies the file.
- **A link is charged its file's size** against the unpack limit, as the copy was, since Syft reads every name of a file.

### Failed catalogers (Task 3)

- **Two catalogers hold more types:**
  - `dotnet-deps-binary-cataloger` holds `dotnet` and `npm`, since it also reads `libman.json`;
  - `java-archive-cataloger` also holds `UnknownPackage`, for `.far` archives.
- **The table is tied to the Syft version it was checked against,** `checkedSyftVersion`:
  - a test fails when the scanner's Dockerfile pins another version;
  - an SBOM from another version names no package types, so its failures hold every finding.
- **The guard takes `sbom` as an input,** and a missing `sbom` holds every finding. It also holds when:
  - an entry of `catalogerFailures` has no types, or the finding's type, even without `failedCatalogers`;
  - the finding has no `packageType`.
- **The guard's condition lives in one place,** `config/rules/completeness-guard.yaml`. The sample playbook only names the rule, so the task's "both copies" were one.
- **The failure stays visible.** An image's facts list its failed catalogers, read from either field of the `sbom` evidence, and its report shows the image as `Incomplete`. The facts decode only the catalogers' names. A malformed SBOM is refused where it is matched, so it still gets no verdict.

### The cap (Tasks 4 and 5)

- **The cap's maximum is 1500000 bytes,** and an Evidence object's `data` holds at most 2000000 characters. The API server sends etcd at most 2 MiB in one request, metadata included. Decision 8 said 2097152 and 2796204.
- **An answer is stored whole or not at all:** every event's compressed size is checked against the cap before the first write.
- **`TooLarge` has more than one cause.**
  - Over the store's cap, the message gives both sizes.
  - The scanner's own bounds also give `TooLarge`: its workspace, the 16 MiB limit of a message, a scan log over 8 MiB and a result over 64 MiB. For these, the message says what the collector said.

  Raising the cap helps only the first.
- **No new watch:**
  - the `OperatorConfig` watch already wakes every image;
  - only a `TooLarge` failure under the raised cap skips its back-off.
- **The event carries the `ImageInventory`'s UID,** so `kubectl describe` shows it.

### Images without a verdict (Task 6)

- **A failure that may pass leaves the image `Pending`,** with the reason `Waiting` and the last error as its message. These failures are `PullFailed`, `TimedOut`, `Internal` and `NoEvidence`.
- **`CatalogFailed`, `NoMatchingPlatform` and unknown reasons give `ScanFailed`.**
- **A failure that won't pass beats one that may.**

  Decision 3 and the task's table said that every reason but `Waiting` is `Unscannable`. The design's section 2.3 binds.
- **A failure beside a complete set of manifests** leaves the image `Ready`.
- **The registry of a refused pull** comes from the image's repository, which presence now records for every image (`RunningImage.Ref`, without the tag).

### The urgency rank (Task 7)

- **As planned.** A report without a highest urgency has no rank, and the README says that `kubectl` sorts those first.

### Waiting quietly (Task 8)

- **The quiet retry applies only when every error of a joined error is `NotReady`.** Anything else is returned as an error.

### The authority (Task 9)

- **A client loads the authority at its first handshake** (`ClientTLS(ctx)`). After a restart, the collectors' streams connect before the deployer has loaded it.
- **The README says that the operator owns `vexplain-collector-ca`,** and that nobody should create or edit it. Rotating the authority means deleting the Secret and restarting the manager, with a gap of about a minute.

### Tests

- **The e2e suite has 40 specs.**
- **The cert-manager spec skips an image without facts:** an image that is `Unscannable`, and one whose scan failed for a reason that may pass.

### After the deploy

- **The owner renamed the playbook's `failing` count to `actionable`** (the design's section 2.9).

## Carried forward

### For phase 4

- **While a collector isn't ready, every manifest that needs it is tried again every 30 seconds.** A large hub retries them all together. Back off, or wake them when the collector is ready.
- **`Internal` also covers refusals that recur at every attempt:** a refusal of the store, the facts' limits, and an answer that breaks the collector's contract. They read `Waiting`, with their error, until the cause is gone. Give them `ScanFailed`.

### The scanner (`collectors/scanner`)

- **Name hits and reachers still work by name:**
  - `outside` leaves out only the entry's own path;
  - reachers use the owners of one path, not of every name of the file.
- **Inode numbers that collide across devices could merge two files.** Group by device and inode only when a file has more than one link.
- **Untested:**
  - the link escape inside `os.Root.Link`;
  - a new path whose parent leaves the root through a symlink;
  - the copy when `os.Link` fails.
- **`nothingFound`** is tied to the Syft version by the Dockerfile test alone, with no check at run time.
- **The guard's reason names the typed failure,** even when an unknown one also holds the finding.
- **Stale comments:** `internal/scan/operation.go` still says that the scanner fails evidence over the store's cap. It checks only the 16 MiB limit of a message.
- **Naming and form:**
  - `pendingCopy` and "pending copies" still say copies;
  - `Extract`'s doc has long lines;
  - `minimalAPKRoot` lacks `t.Helper()`.

### The evidence store (`internal/evidence`)

- **The facts refuse a success that names more than 32 failed catalogers, or a name over 128 bytes,** while the `sbom` schema takes both. A producer's oversized SBOM is refused at every retry. Truncate, or bound the schema the same way.
- **The facts take each name from `catalogerFailures` without checking that it isn't empty,** though they refuse an empty name. Only a producer that breaks the `sbom` schema hits this, and its image then waits, with its error, at every retry.
- **Past the 64 MiB limit, `sizeBytes` and `capBytes` take the uncompressed size and 64 MiB,** while their doc says compressed. Behind the 16 MiB limit of a message, this can't happen today.
- **The cap's setting:**
  - a failed settings read drops a raised cap to 786432, with only a log line;
  - the default is written in four places, and only the settings' copy says that it must match.
- **Long doc lines** in `evidence_types.go` and the generated CRD.

### The spoke (`internal/spoke`)

- **The executor's cap check:**
  - each event is compressed for the check, and again when it is stored. Compress it once;
  - a cap lowered between the check and a write can still store part of an answer.
- **The `EvidenceTooLarge` event reads the `ImageInventory` through the cache.** A miss drops the event and leaves a log line, once per refusal.
- **The registry named is the first, in lexical order, of an image's repositories.** A mirrored image's message may name another registry than the one that refused.
- **`TooLarge`'s docs name only three causes.** The README and the API docs leave out the scan log's and the result's bounds.
- **The executor:**
  - its test doesn't pin the counter's `cluster` label;
  - the event's regarding object has no TypeMeta, since the recorder takes the kind from the scheme, and no comment says so;
  - `executorEnv` lost its doc comment.
- **Tests:**
  - no render test mixes failed catalogers with `Unscannable`, or counts the new states past 32 entries;
  - `summaryOf` derives the rank again from a map;
  - no API test admits the ranks 0 and 4;
  - `reports_test.go` sleeps 1 s for the metadata cache, and reads a global error metric that parallel tests could raise.
- **Form:**
  - `noDigestMessage` sits between a doc comment and its function;
  - `namespaces.go`'s error text still says "labels";
  - `overCap`'s doc says that the store refuses a size it can't measure, while the store returns an error that is logged and asked again. Gzip into memory can't fail;
  - `Render`'s doc doesn't say how a failed scan maps to `Unscannable`, or to `Pending` with `Waiting`.

### The hub (`internal/controller/hub`)

- **`onlyNotReady` doesn't honour a custom `Is`** on a wrapper of several errors.
- **Two branches of `assess` return the same error.**

### The inventory (`internal/inventory`)

- **Line width:** the `Tally` comment in `counts.go` and two README lines about it run past the width.

### The certificates (`internal/collector/certs`)

- **`parseCA` takes a CA certificate without `CertSign`.** Check its own signature instead (`CheckSignatureFrom`).
- **A failed replacement in the authority's last 90 days blocks `ClientTLS` and `EnsureServer`,** though the authority in memory is still valid.
- **An immutable `vexplain-collector-ca`, or one that isn't `Opaque`,** blocks every `EnsureServer` until it is deleted. Deleting the Secret takes effect at the next start.
- **Untested:** the `Conflict` path, and a client's first load racing `EnsureServer`.

### Decisions for the owner

- **The owner accepted the plan's four decisions on 2026-11-15,** with the plan:
  - the key stays in a Secret, with 2.8's cost stated;
  - `ScanFailed`;
  - the replacement with a gap;
  - the cap stops at 2 MiB.
- **The cap's maximum was set while building, not by the owner:** 1500000 bytes rather than 2 MiB, since the API server sends etcd at most 2 MiB in a request, metadata included.
- **The cluster settings of section 3** are checked in the live run (Task 10).
