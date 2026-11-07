# Phase 2b live fixes: reports people can read

**Goal:** after the first run on a real cluster, make what vexplain produces readable before anything is built on it: reports as actions with a summary, data kinds with summaries and columns, and the fixes that the platform asked for.

**Architecture:** the spoke's renderer groups a workload's open findings into actions (0038). The hub writes summaries on the sheets and on the image records, which list columns read (0039). The platform fixes change defaults and docs only.

**Tech stack:** Go, kubebuilder and controller-runtime, envtest, kind.

**Spec:** decisions [0038](../decisions/0038-reports-as-actions.md) and [0039](../decisions/0039-kinds-people-can-read.md), and the main design's sections 6.1, 6.2 and 6.10 as they now read. Built on the branch of phase 2b, after its follow-ups (0036, 0037).

## Global Constraints

- AGENTS.md binds: design first, test first, kind only, no private data and no figures from real platforms, no AI attribution, comments that state their own reason.
- `make manifests generate && make proto-check && make lint && make test` before each commit; one e2e run at the end of each task that changes the install or the manager.
- The API is `v1alpha1` and unreleased: a field may change shape without conversion. The README's upgrade note says that a fresh install is needed.
- Bounds of 0038: 256 actions per report, 5 CVE IDs per action, 8 digests per action.
- A summary counts as the metrics count: an open finding once for each vulnerability and package of a workload, a settled one once for each manifest.

## Review Focus

1. **A finding that drops out:** every open finding of a workload is in exactly one action, or counted as left out; nothing is lost between the candidates, the actions and the summary.
2. **Counts that disagree:** the report's summary and `vexplain_findings` agree for the same workload.
3. **The summaries' writer racing the presence entries:** the hub's write of `ImageInventory`'s summary and a spoke's write of its cluster entry never undo each other.
4. **A summary that goes stale:** a sheet that changes, an image that stops running, or a failure that clears updates the summaries that read it.
5. **Seccomp that blocks pods:** the explicit profiles must not stop a runtime config or the scanner's settings from running their pods.

---

### Task 1: Platform fixes

**Files:** `config/manager/manager.yaml`; the collector's default Deployment in `internal/controller/config`; `sdk/jobs` (scan Jobs); `config/collectors/runtimeconfigs.yaml`; `docs/collectors.md`, `README.md`; `internal/controller/config/modelconfig_controller.go`.

- **Seccomp:** `RuntimeDefault` set explicitly at pod level and at container level for the manager, every collector's Deployment and every scan Job, so strict Pod Security policies (Kyverno's included) accept them. Tests: the default Deployment and a scan Job carry both; a runtime config that sets its own profile still wins, as templates do.
- **The matcher's memory:** limit 3Gi in its runtime config, with the reason in a comment (Grype holds its database in memory while it matches), and no figure from a real cluster.
- **Node placement:** a short section in `docs/collectors.md`, and a line in the README: the manager through a kustomize patch, the collectors through their runtime config's `deploymentTemplate`, and scan pods through the scanner's `scanPod.nodeSelector` and `tolerations`.
- **`ModelConfig`'s grace:** a new generation while it is already `Reconciling` with the same reason restarts its 2-minute grace (drop `Reconciling` before `SetReady` when the generation changed). Test first.
- **Commit:** `fix(deploy): set seccomp explicitly, give the matcher room, and say how to place pods`; `fix(config): restart a ModelConfig's grace at a new generation`.

### Task 2: Reports as actions (0038)

**Files:** `api/triage/v1alpha1/workloadreport_types.go`; `internal/spoke/render.go`, `reports.go`, `exposure.go`, `metrics.go`; their tests; `internal/controller/triage` API tests.

**Interfaces:**
- `WorkloadReportStatus` keeps `conditions`, `images`, `owner` and `exposure`, drops `findings` and `omitted`, and gains:
  - `actions []ReportAction` (at most 256; `listType=atomic`), where `ReportAction` has `step` (`NextStep`), `package` (`ReportPackage`: name, type, installed version), `fixedVersion` (`*string`, only for `Update`), `severity`, `urgency`, `knownExploited` (`KnownExploited`), `vulnerabilities` (`int32`), `vulnerabilityIDs` (at most 5), `digests` (at most 8);
  - `summary *ReportSummary` with `affected`, `underInvestigation`, `notAffected`, `fixed`, `actions`, `updates`, `mitigations`, `investigations`, `omittedActions`, `highestUrgency` (`*SSVCOutcome`), `critical`, `knownExploited` (each `*int32`, minimum 0);
  - `reach *ReportReach` with `internalReach` (an enum of the exposure type's four values) and `indirect` (an enum, `Indirect` or `NotIndirect`, as the API rules forbid booleans).
- Columns, from the summary: exposure, highest urgency, updates, to investigate (`investigations`), critical, known exploited, age; mitigations with priority 1.
- `Exposure` keeps each workload's internal reach and indirect flag beside its SSVC exposure, the widest over collectors (`Namespace`, `Peers`, `Namespaces`, `Cluster`) and indirect when any collector says so, and `Render` takes them through its exposure argument.

**Steps:**
- [ ] **Tests first:**
  - 3 findings of one package and version, 2 with fixed versions `1.2` and `1.4` and one without: one `Update` to `1.4` with 2 vulnerabilities, and one `Investigate` (or `Mitigate` for `Affected`) with 1.
  - An action keeps the highest severity and urgency of its CVEs, and is marked known-exploited when one of them is.
  - 7 CVEs in one action list 5 IDs, most urgent then most severe, with `vulnerabilities: 7`.
  - 300 actions give 256, most urgent first, and `omittedActions: 44`.
  - The summary's counts equal `vexplain_findings` for the same workload, settled ones included.
  - The same package found in two images gives one action with both digests.
  - Reach and indirect come from the exposure evidence; without evidence, `reach` is absent.
  - The load check's notes don't appear in the report; settled findings appear only in the summary.
  - The 1 MiB bound still holds at every maximum.
- [ ] **Implement** the grouping in `render.go` from the candidates that it already builds, keeping its byte bound; drop what `findings` needed.
- [ ] **Metrics:** `vexplain_findings` and `vexplain_open_case` keep reading the candidates and sheets, unchanged; check that nothing read `status.findings`.
- [ ] **Commit:** `feat(spoke): report actions with a summary, not one line per finding`.

### Task 3: Kinds people can read (0039)

**Files:** every `*_types.go` (categories, columns); `api/inventory/v1alpha1/imageverdicts_types.go` and `imageinventory_types.go` (summaries); `internal/controller/hub` (the sheet's summary, and a summary controller for `ImageInventory`); `internal/rules` if the sheet builder computes the counts.

**Interfaces:**
- Categories: `vexplain` on every kind; `vexplain-data` also on `Evidence`, `ImageInventory` and `ImageVerdicts`.
- `ImageVerdictsStatus.summary` with `open`, `fixable`, `held`, `settled`, `omitted` (`*int32`), written with the sheet from every finding before its cut. `held` counts the open findings that a rule decided; `fixable` those with a fixed version.
- `ImageInventoryStatus.summary` with `image` (the first repository, sorted), `workloads`, `namespaces` (over every cluster), `scanState` (`Scanned`, `Pending`, or the failure's reason), `open`, `fixable` (over its manifests' sheets). The hub writes it whenever a sheet of its manifests, its facts or a cluster's entry changes, by a patch of that field alone, so it never undoes a spoke's entry.
- Columns as 0039 lists them; every platform column `priority=1`; `ImageInventory` drops its digest column.

**Steps:**
- [ ] **Tests first:**
  - a sheet's summary from findings of every kind, also past its cut;
  - an image's summary over two manifests and two clusters;
  - it changes when a sheet changes, when an image stops running in a cluster, and when a failure clears;
  - a spoke's `Observe` racing the summary's write keeps both (Review Focus 3);
  - the CRDs carry the categories and columns (extend the CRD test of 0036, or a new one beside it).
- [ ] **Implement.**
- [ ] **Commit:** `feat(api): give the data kinds summaries, columns and categories`.

### Task 4: Alignment

**Files:** `test/e2e`, `docs/collectors.md`, `README.md`, the API docs of the changed kinds.

- [ ] e2e spec 24 reads the actions and the summary: the `linked` image's report has an action for brotli's package with `CVE-2026-111497` among its IDs, known exploited, and an `Investigate` action for libxml2; its summary counts them. Spec 25's label query and spec 27's metric stay.
- [ ] A spec checks `kubectl get vexplain-data` lists the data kinds, and that `ImageInventory`'s summary names the image and its workloads.
- [ ] The README's section on reports shows an example report: its summary and two actions.
- [ ] Run `make setup-test-e2e && make test-e2e` once: all specs pass.
- [ ] **Commit:** `test(e2e): read reports as actions, and the data kinds' summaries`; `docs: show a report as actions`.

## As built

Where the build differs from the text above, the build is right. Each difference was decided and reviewed while the plan ran, or in the review of the whole plan and its fix wave. Decisions 0038 and 0039 were amended on their status lines where the build changed them.

### Platform fixes (Task 1)

- `RuntimeDefault` seccomp is set at the pod and at the container for the manager, every collector's Deployment and every scan Job. A runtime config's own profile still wins; since the container's setting wins over the pod's, a runtime config sets its profile on the container `collector` (`docs/collectors.md` says so).
- A `ModelConfig` edited while its endpoint is failing restarts its 2-minute grace.

### Reports as actions (Task 2)

- `WorkloadReport`'s status holds `actions`, `summary` and `reach`; `findings`, `omitted` and `counts` are gone, with the triage types that only they used. The object's name still says the workload; with `-o wide`, the workload's kind and name show too, for a name that had to be hashed.
- **An update's target** is named only where the version order is unambiguous: each CVE of the action has one fixed version, and every version is plain dotted numbers, with a release suffix only for the package types that order it after the plain version: `-rN` for apk, `-N` for deb and rpm, `.elN` for rpm. npm, Go modules, Cargo, RubyGems and the rest read `-N` as a pre-release, so they take plain numbers only. Otherwise the action is an update without a target, and each CVE's fixed versions stay in the sheets.
- **Across images:** where two images' sheets differ about one CVE of an action, the action takes the more urgent urgency and severity, and counts the CVE as known exploited if either sheet lists it.
- **The summary** also counts the image entries without a verdict: `pending` (no sheet yet, or a scan that failed) and `incomplete` (a sheet that left findings out), over every image, past the 32 listed. The default columns show pending image entries, so a workload whose images aren't settled never reads as clean.
- An action lists at most 8 digests and counts the rest (`omittedDigests`).
- The metrics read the renderer's candidates and sheets, never the report's status, so the summary and `vexplain_findings` agree. Where an image's variants give one CVE different verdicts, `vexplain_open_case` has one series for each, as its help says.

### Kinds people can read (Task 3)

- `Store.Source()` delivers no update that changes only `ImageInventory`'s summary, so a summary write doesn't re-render every report of the image. The summary controller remembers what it last wrote for each object.
- An image's `open` and `fixable` are the most that any of its manifests' sheets counts. A sheet's `fixable` follows the reports' update step: a fix state of `Fixed` or a listed fixed version.
- The scan state is `Scanned` when every manifest has a verdict, else the reason of a failure, else `Pending`. A reason spelt `Scanned` or `Pending` shows as `Internal`, so it can't pass for a state.
- The hub writes the summary by a merge patch of `status.summary` alone. Every other writer checks the resourceVersion, so neither side undoes the other.

### Alignment (Task 4)

- **A node's platform and an image's variants:** a node names no variant, so the renderer matches its platform to manifests of any variant, by the rule the hub uses (`inventory.PlatformCovers`, shared). An exact listing is read alone; otherwise every covering manifest is read. Before, an image listed only under `linux/arm64/v8` showed no findings on an arm64 node.
- The e2e suite has 29 specs. The spec of a variant-only image checks its premise and skips, with the reason, on a host where no image lists its manifest only under a variant, such as an amd64 runner. The unit tests cover the matching on every host.

## Carried forward

### Before merge, or at the latest on the PR

- **An update's target across images:** where two images of one workload share a package of one name, version and type, such as a Debian image and an Ubuntu one, their sheets merge into one action, and a fixed version from one sheet can become the target although the other sheet knows no fix, or knows another. The safe rule: name a target only when every sheet's fixed versions for a CVE agree. A few lines in `internal/spoke/render.go`'s merge, with tests in both orders.
- **"Pending Images" counts image entries** (one for each image and platform), while the column's name and the kind's doc say images.

### The spoke's reports and metrics (`internal/spoke`)

- The highest fixed version by each ecosystem's own rules belongs in a collector; the review of the collectors after phase 2 takes it up.
- An exact platform listing suppresses variant-only manifests of the same platform.
- A status missing summary fields gets CEL "no such key" errors beside "Required value".

### The hub's summaries (`internal/controller/hub`)

- A burst of sheet rewrites, such as after a database update, reconciles an image once for each sheet, each time reading every sheet uncached, with one worker and no debounce.
- The failure shown is the first by source name, not filtered by the playbook; `Scanned` hides a newer failure.
- A hand edit of a summary isn't corrected until a restart or a new object.

### Decisions for the owner

- The review of the collectors and their roles, after phase 2: the matcher's fix targets (in the matcher, or a `remediation` collector), the exposure collector's platform settings (trusted peers, ports) and whether to split it, then `govulncheck`. Kubescape moves after the agent.
- The items of phase 2b's own "Decisions for the owner" stand.
