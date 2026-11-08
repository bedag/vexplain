# vexplain — Phase 3a (The collector model's core, and today's collectors) Implementation Plan

> **For agents:** follow `AGENTS.md`. Implement this plan task by task, test first. A task is done when its tests pass, it is committed and it has been reviewed; only then start the next one. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** On one kind cluster, running as hub and spoke at once, the operator:
- grants each collector the permissions it ships, within the admin's ceiling and outside the deny list (0041)
- runs the schedules that collectors declare, with run now on the `Collector` (0040)
- runs several playbooks at once, which name types, take optional entries and a match, and show the fleet picture (0043)
- renders one `ResourceReport` per workload in place of `WorkloadReport`, whose actions name their container (0042)
- feeds `vulnerabilities`, the renamed matcher, from the neutral `sbom` type, with ecosystem-correct fix targets and aliases, and a database that survives restarts and shows its age (0044, 0046)
- gives the scanner admin-provided pull credentials and failures that say what failed (0047), and gives `network-reach`, the renamed exposure collector, trusted peers and host settings (0048)

Then it runs again on a live cluster, with the owner, before phase 3b.

**Architecture:**
- **Collectors** stay gRPC servers.
  - They also declare schedules, which the operator fires through a new `Fire` call.
  - They report their sources' versions through `GetInfo`.
  - The operator turns their declared permissions into RBAC that the `Collector` owns.
- **Hub:**
  - For each image in presence, a playbook judges its manifests when it is Ready and its cluster match covers a cluster where the image runs. Every such playbook does so, and each gets its own sheet per manifest.
  - Inputs are read from every producer of their type.
- **Spoke:**
  - It renders one `ResourceReport` per workload. The report holds the results of the playbooks whose namespace match covers the workload's namespace, with an action per package and image that lists the containers running it.
  - After rendering, it writes each playbook's counts for its cluster (`PlaybookCounts`), which the hub sums into the Playbook's status.
- **Hub and spoke** still meet only through `tasks.Executor` and the stores (0021).

**Tech Stack:** as in phase 2b, plus:
- `github.com/robfig/cron/v3`, the cron parser that Kubernetes' CronJob controller uses, for schedules
- `github.com/anchore/grype` v0.121.0, as a library in `collectors/vulnerabilities`, for its version comparators only. The Grype CLI stays at the same version.

**Spec:**
- `docs/design/2026-11-08-collector-model.md` (sections 5 and 6), and records 0040–0049
- the design of collectors, evidence and rules, and the main design (revision 15), where their notes point to it
- phase 2b's plan (`docs/plans/2026-10-31-phase2b-collectors.md`) and its "As built" section, which describe what exists

**Branch:** `feat/phase3a-collector-model`, from `docs/phase3-design`, which holds the design and the E2E fix. The two are stacked until the design merges.

**Not in this plan (phase 3b and later):**
- the trigger runtime, cluster-event triggers and evidence subscriptions; the family collectors, and `network-reach` built on them
- findings about resources other than images:
  - their verdict sheets;
  - actions per confirming rule;
  - findings that start passing;
  - configuration justifications;
  - `ClusterResourceReport`.
- `maxAge`, since no type of phase 3a changes under its subject
- govulncheck, Kubescape, exceptions, human impact per cluster stage, and the options in design section 9

## Decisions made in this plan

The design leaves these to the builder. Each is decided here so that implementers don't guess. The owner checks them when reviewing the plan.

1. **The renames come first (Task 1).**
   - `collectors/matcher` becomes `collectors/vulnerabilities`, with the module `github.com/bedag/vexplain/collectors/vulnerabilities`.
   - `collectors/exposure` becomes `collectors/network-reach`, with the module `github.com/bedag/vexplain/collectors/network-reach`.
   - The images, the Makefile variables (`VULNERABILITIES_IMG`, `NETWORK_REACH_IMG`, `VULNERABILITIES_DB`) and the `Collector` names follow.
   - The core type `ch.bedag.vexplain.exposure.v1alpha1` and the Go names around it keep their names: exposure is the type, and only the collector is renamed.
2. **Core types change only by optional fields, within v1alpha1:**
   - presence gains containers and `digestKind: Reference`;
   - findings gain `id`, `title`, `aliases`, `fixTarget` and `updateTarget`;
   - exposure gains `widenedBy` and `unseen`.

   The operator checks every event against its own copy of the schemas (`additionalProperties: false`). So each schema change ships in the same task as the collector that emits it. v1alpha1 carries no compatibility promise, and the operator and the built-in collectors are released together.
3. **The `sbom` type** is `ch.bedag.vexplain.sbom.v1alpha1`: about a manifest, scope `Hub`, with the `platform` and `coverage` extensions.
   - Its data holds the distro, the packages (ID, name, version, type, purl, CPEs), the producer and the failed catalogers.
   - The scanner's `image-contents` keeps its file facts, ELF facts, libraries and preload, and loses its SBOM.
   - `vulnerabilities` turns `sbom` into a minimal Syft JSON document and runs `grype sbom:` as before, so its matches don't change.
4. **Fix targets** use Grype's own version package at v0.121.0.
   - A match's `fixTarget` is the lowest fixed version above the installed one, in the format of the package's type.
   - Its `updateTarget` is the highest `fixTarget` among its package's matches in the manifest.
   - A version that doesn't parse gives no target.
   - The renderer's own order goes.
5. **Aliases** come from Grype's `relatedVulnerabilities`: at most 8, sorted.
6. **Schedules:**
   - `GetCapabilitiesResponse.schedules` (field 8) declares them. The new RPC `Evidence.Fire` fires one by name.
   - `Fire` starts the work and returns within 10 seconds. The collector reports what changed through `SourceChanged`, as before.
   - The operator runs five-field cron expressions in UTC. After a restart it doesn't catch up on missed fires.
7. **Sources come from `GetInfo`** (`GetInfoResponse.sources`), which the `Collector`'s reconcile already calls every 30 seconds. They don't come from `SourceChanged`, because only the collector controller writes a `Collector`'s status.
8. **Run now** is the annotation `vexplain.bedag.ch/run-now`.
   - Any new value fires every schedule of the `Collector` once.
   - `status.lastHandledRunNow` records the value.
   - The controller's predicate also passes changes of this annotation.
9. **The database lives on a PersistentVolumeClaim:** `vexplain-collector-vulnerabilities-db`, `ReadWriteOnce`, 8Gi, mounted at `/db`, with the Deployment strategy `Recreate`. Both are set in the default install's runtime config, which an admin can change. Seeding stays optional.
10. **Permissions:**
    - **The objects:**
      - The install ships the ceiling, `vexplain-collector`: an aggregated ClusterRole on the label `rbac.vexplain.bedag.ch/aggregate-to-collector: "true"`, bound to the manager's service account. The name leaves "ceiling" implied (owner).
      - It also ships `vexplain-collector-defaults`, which holds the built-ins' rules and carries that label.
      - The operator grants `vexplain-collector-<name>`: a ClusterRole and a ClusterRoleBinding, plus a Role and a RoleBinding in its namespace. All four are labelled `vexplain.bedag.ch/collector: <name>` and owned by the `Collector`. They bind the Deployment's actual service account.
      - A `Collector` named `defaults` is refused by CEL, since its grants would take the name of the defaults.
    - **The manager's rights:** it may manage roles and bindings, but never holds `escalate` or `bind`. Kubernetes' escalation check therefore enforces the ceiling.
    - **The modes:** `OperatorConfig.spec.collectors.permissions` is `Grant` (the default) or `Check`. `Check` keeps 2b's behaviour: SubjectAccessReviews only, and `MissingPermissions`.
    - **The static `config/collectors/rbac` goes.**
11. **Cluster labels** live in `OperatorConfig.spec.clusterLabels`, with at most 32 entries, until phase 6. They are never passed to collectors, since a change would reopen every stream.
12. **The Playbook API:**
    - `subjects: {type}`
    - `findings: {type, collectors?}`
    - `evidence[]: {name, type, collectors?, optional?}`
    - `match?: {clusters?, namespaces?}`

    The `collector` fields go. Names are DNS-1123 labels of at most 63 characters, since sheet names include them. The reason `Conflict` goes.
13. **Several producers:**
    - The pipeline is evaluated once per combination of producers over a playbook's inputs, for at most 4 combinations. Beyond 4, every finding is held `UnderInvestigation`.
    - The results merge by the engine's rule: the most cautious wins.
14. **Sheets per playbook:**
    - `ImageVerdicts.spec.playbook` is immutable. The name is `<sha256-…>.<playbook>`.
    - Labels: `vexplain.bedag.ch/playbook: <playbook>`, and `manifest.vexplain.bedag.ch/<first 63 hex digits>: ""`.
    - The janitor lists sheets by label.
    - `ImageInventory`'s summary takes the sheet with the most open findings.
15. **Namespace matching** happens on the spoke, through a metadata-only Namespace informer, which needs the RBAC `list` and `watch` on `namespaces`.
16. **`ResourceReport`** is a view that vexplain writes, so it has no conditions; 0036 asks for them on reconciled kinds. `WorkloadReport` and everything around it go.
17. **Locations** are field paths, with list items named:
    - `spec.containers[<name>]`, or `spec.initContainers[<name>]`, for a Pod;
    - `spec.jobTemplate.spec.template.spec.…` for a CronJob;
    - `spec.template.spec.…` for every other kind.
18. **Images without a digest:**
    - **Presence keys them** by `image/sha256:<SHA-256 of the image reference>`, with `digestKind: Reference` and the reference in `repositories`.
    - **The hub treats them as it treats image IDs:** not pullable.
    - **The report shows both kinds as `Unscannable`,** not `Pending`.
19. **The fleet picture** uses a new kind, `PlaybookCounts` (inventory group, cluster-scoped). There is one per playbook and cluster, named `<playbook>.<cluster>` and owned by the Playbook. The spoke writes it, and the playbook controller sums it.
20. **The scanner's credentials:**
    - The workload's pull secrets come first (`CopyFromWorkload`), then the Secrets listed in `adminPullSecrets` (`AdminProvided`).
    - The Job's Secret holds one Docker config per source, in that order, and the scan's keychain tries each until a pull succeeds.
21. **Failed catalogers** set both events' coverage to 0 and are named in `sbom.data.failedCatalogers`. The completeness guard then holds every finding.

## Decisions for the owner

These plan calls change what admins see, so they're listed for the owner's check:
1. **The database's PersistentVolumeClaim** in the default install (decision 9).
2. **A new kind, `PlaybookCounts`,** for the fleet picture (decision 19).
3. **The `Grant` and `Check` modes** for permissions in `OperatorConfig` (decision 10).
4. **Images without a digest** keyed by the SHA-256 of their reference (decision 18).
5. **`ImageInventory`'s summary** from the worst playbook (decision 14).

## Global Constraints

- **Phases 1, 2a and 2b still bind,** as amended by their "As built" sections: names, API conventions, kube-api-linter, RBAC from markers (bindings in `config/rbac`), wiring through `setup.Register`, tests, and commits.
- **Collectors:**
  - names `workloads`, `scanner`, `vulnerabilities` and `network-reach`;
  - Deployments, Services and service accounts named `vexplain-collector-<name>`.
- **The collector API:**
  - gRPC package `vexplain.collector.v1alpha1`;
  - new: `GetCapabilitiesResponse.schedules = 8`, `GetInfoResponse.sources`, `rpc Fire` in `Evidence`;
  - `make proto-check` stays green.
- **Types:**
  - new: `ch.bedag.vexplain.sbom.v1alpha1` (manifest, Hub);
  - presence, findings and exposure change only by optional fields;
  - `image-contents` loses its SBOM.
- **RBAC names:**
  - the ceiling `vexplain-collector`, with the aggregation label `rbac.vexplain.bedag.ch/aggregate-to-collector: "true"`, and `vexplain-collector-defaults`, which carries it;
  - granted objects named `vexplain-collector-<name>`, with the label `vexplain.bedag.ch/collector: <name>`;
  - no `Collector` named `defaults`.
- **The default deny list:** `{apiGroups: [""], resources: [secrets], verbs: [list, watch]}`.
- **Annotation:** `vexplain.bedag.ch/run-now`. **New reasons:** `PermissionsNotAllowed`, `TriggersInvalid`.
- **Schedules:** five-field cron, UTC. `Fire` returns within 10 seconds.
- **Names:**
  - Playbook names are DNS-1123 labels of at most 63 characters;
  - sheet names are `<sha256-…>.<playbook>`.
- **`ResourceReport` limits:**
  - at most 256 actions, 32 images and 8 locations per action;
  - names `<kind>-<name>`, hashed when too long, as before.
- **Statuses:** OpenVEX's, unchanged.
- **Size limits,** as in 2b:
  - compressed evidence at most 786432 bytes;
  - at most 2048 findings and 1 MiB per sheet;
  - gRPC messages at most 16 MiB.
- **Pull secrets** are read with `get` only. They never appear in logs, status, events, metrics, errors or evidence. Failures name Secrets, never their content.
- **Metrics** start with `vexplain_` and carry the label `cluster`. A metric about a namespaced object also carries the object's `namespace`, as kube-state-metrics and cert-manager do. Prometheus shows it as `exported_namespace` when the scrape adds its own `namespace` (owner).
- **A fresh install** (owner, 2026-11-08): phase 3a assumes no existing install, and adds no migration from 2b.
- **Testing** happens only on a local kind cluster with its own kubeconfig.
- **Commits:** Conventional Commits, signed, no AI attribution, never on `main`.
- **Repository hygiene:**
  - neutral names, such as `cluster-a`, `team-a` and `artifacts.example`;
  - no figures from the live cluster.

## Review Focus

1. **A runtime config changes a collector's service account.** The grant binds the Deployment's actual account, the same one the SubjectAccessReview checks, never the default name (Task 5).
2. **A built-in declares rights on kinds the cluster doesn't serve,** such as the Gateway API or Cilium. The defaults must still cover every declared rule, or the collector stops on a cluster without those kinds (Task 5).
3. **A namespace's labels change.** Its reports are rendered again with the playbooks that now match (Task 13).
4. **A package type that Grype's versions don't know, or a version that doesn't parse,** gives no target, never a wrong one (Task 8).
5. **Run now while a collector isn't Ready.** The annotation waits, and fires once when the collector is Ready, never twice (Task 4).

---

## File Structure

```text
api/config/v1alpha1/
  operatorconfig_types.go     # Task 2: clusterLabels, collectors (permissions, deniedPermissions)
  collector_types.go          # Tasks 3, 4: schedules, sources, triggers, schedule status, lastHandledRunNow
  common_types.go             # Tasks 4, 5: TriggersInvalid, PermissionsNotAllowed, AnnotationRunNow
  playbook_types.go           # Tasks 10, 11, 14: types, collectors, optional, match, summary, clusters
api/inventory/v1alpha1/
  imageverdicts_types.go      # Tasks 8, 11: targets and aliases; spec.playbook
  playbookcounts_types.go     # Task 14 (new)
api/triage/v1alpha1/
  resourcereport_types.go     # Task 12 (new); workloadreport_types.go goes in Task 13
sdk/proto/.../collector.proto # Task 3: schedules, sources, Fire
sdk/collector/                # Task 3: Schedule, Firer, Source, Sourcer
sdk/evidence/                 # Tasks 6, 7, 8, 16: presence, sbom, findings, exposure fields
sdk/workloads/digest.go       # Task 6: containers
sdk/jobs/job.go               # Task 15: several Docker configs
internal/settings/effective.go                 # Task 2
internal/controller/config/
  collector_schedules.go      # Task 4 (new)
  collector_rbac.go, collector_ceiling.go      # Task 5 (new)
internal/controller/hub/      # Tasks 10, 11, 14: types, producers, playbooks, sheets, fleet
internal/inventory/           # Tasks 11, 14: sheets per playbook, counts
internal/rules/engine/        # Tasks 8, 10: targets kept in the merge, producer combinations
internal/spoke/               # Tasks 6, 13, 14, 16: containers, ResourceReport, locations, namespaces, counts
collectors/vulnerabilities/   # Tasks 1, 7, 8, 9 (from collectors/matcher)
collectors/network-reach/     # Tasks 1, 16 (from collectors/exposure)
collectors/scanner/           # Tasks 6, 7, 15
collectors/workloads/         # Task 6
config/rbac/collector_ceiling.yaml             # Task 5 (new); config/collectors/rbac goes
config/collectors/vulnerabilities-db.yaml      # Task 9 (new)
config/playbooks/, config/rules/, config/samples/  # Tasks 1, 7, 10
docs/collectors.md, README.md                  # Tasks 3, 5, 9, 15, 16, 17
test/e2e/                     # Tasks 1, 17
```

## Task order

`make test` stays green after every task.
- **Tasks 1–5:** the renames, then the platform: `OperatorConfig`, the API for schedules and sources, schedules and run now, and shipped permissions.
- **Tasks 6–9:** the evidence: presence with containers, the `sbom` type, and `vulnerabilities` (fix targets, its database).
- **Tasks 10–14:**
  - playbooks: types, producers, several at once, sheets per playbook;
  - `ResourceReport` and its rendering;
  - the fleet picture.
- **Tasks 15–16:** the scanner and `network-reach`.
- **Task 17:** install, docs, e2e and the measurement.
- **Task 18:** the live re-run, with the owner.

### Task 1: The renames

**Files:**
- Move:
  - `collectors/matcher` → `collectors/vulnerabilities`;
  - `collectors/exposure` → `collectors/network-reach`.

  Each gets its new module path. Go package names inside stay.
- Modify:
  - **Build:** `go.work`; the root `Dockerfile`; the `Makefile`: image variables, `docker-build`, `docker-push`, `set-images`, and the submodule loops.
  - **Config:**
    - `config/collectors/*` (`vulnerabilities.yaml` and `network-reach.yaml` from `matcher.yaml` and `exposure.yaml`; the runtime config's name);
    - `config/playbooks/container-cves.yaml`;
    - `config/samples/config_v1alpha1_playbook.yaml`: also drop its `exposure` entry, since the hub can never read a Spoke-scoped type;
    - `test/e2e/config/kustomization.yaml`.
  - **Code:** the names and comments in `internal/setup/setup.go`, `internal/spoke/{exposure,presence,router}.go`, `internal/controller/hub/{assessor,findings}.go` and `hack/measure-2a/main.go`.
  - **CI and docs:** `.github/workflows/test-e2e.yml`, `README.md`, `docs/collectors.md`.
- Delete: the empty directories `cmd/matcher` and `cmd/scanner`.
- Test: e2e (`builtInCollectors` lists `workloads`, `scanner`, `vulnerabilities`, `network-reach`), `internal/setup/chain_test.go`, and the hub and spoke fixtures that name the collectors.

Behaviour doesn't change.

- [ ] **Step 1: Update the tests and fixtures to the new names.**
- [ ] **Step 2: Run `make test`,** and see them fail where the old names are still built in.
- [ ] **Step 3: Move and rename.**
- [ ] **Step 4: Verify** with `make manifests generate && make proto-check && make lint && make test`. `make docker-build` builds the images `vulnerabilities` and `network-reach`.
- [ ] **Step 5: Commit:** `refactor: rename the matcher to vulnerabilities, and exposure to network-reach`

### Task 2: `OperatorConfig`: cluster labels, the deny list and the permissions mode

**Files:**
- Modify:
  - `api/config/v1alpha1/operatorconfig_types.go`;
  - `internal/settings/effective.go`;
  - `internal/controller/config/operatorconfig_controller.go`;
  - `config/samples/config_v1alpha1_operatorconfig.yaml`.
- Test: `internal/controller/config/operatorconfig_api_test.go` (envtest), `internal/settings/effective_test.go`, `internal/collectorclient/streams_test.go`

**Interfaces:**
- Produces:
  - `OperatorConfigSpec.ClusterLabels map[string]string`: at most 32 entries, with label keys and values checked in CEL.
  - `OperatorConfigSpec.Collectors *CollectorPolicy`:
    - `Permissions PermissionsMode`: `Grant`, the default, or `Check`;
    - `DeniedPermissions []PermissionRule`, at most 32.
  - `PermissionRule{APIGroups, Resources, Verbs []string}`: each list has at least one entry, and `*` is allowed.
  - `settings.Effective` gains `ClusterLabels`, `PermissionsMode` and `DeniedPermissions`.
  - `settings.DefaultDeniedPermissions`, the list given in the Global Constraints, which `Load` uses when `deniedPermissions` is absent. An empty list that the admin sets means "deny nothing".

- [ ] **Step 1: Write the failing tests:**
  - **The API (envtest):**
    - a full config passes;
    - CEL refuses 33 labels, an invalid label key or value, a deny rule without a verb, and an unknown mode.
  - **`Load`:**
    - it gives the default deny list when the field is absent;
    - it gives the admin's list when one is present, an empty one too;
    - it gives the cluster labels as set.
  - **`ClusterContext`** sends no cluster labels to collectors.
- [ ] **Step 2: Run them and see them fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Verify** with `make manifests generate && make lint && make test`.
- [ ] **Step 5: Commit:** `feat(config): cluster labels, the deny list and the permissions mode in OperatorConfig`

### Task 3: The collector API: schedules, `Fire` and sources

**Files:**
- Modify:
  - `sdk/proto/vexplain/collector/v1alpha1/collector.proto` (`make proto` regenerates `sdk/api`);
  - `sdk/collector/{identity,evidence,server}.go`;
  - `sdk/conformance/conformance.go`;
  - `api/config/v1alpha1/collector_types.go`;
  - `internal/controller/config/{collector_answers,collector_controller}.go`;
  - `internal/collectorclient/invoke.go`;
  - `docs/collectors.md`.
- Test: `sdk/collector/*_test.go`, `sdk/conformance/conformance_test.go`, `internal/controller/config/collector_answers_test.go`, `internal/collectorclient/invoke_test.go`

**Interfaces:**
- **Proto:**
  - `message Schedule { string name = 1; string cron = 2; }`, and `repeated Schedule schedules = 8` in `GetCapabilitiesResponse`.
  - `message Source { string name = 1; string version = 2; google.protobuf.Timestamp built_time = 3; }`, and `repeated Source sources` in `GetInfoResponse`, at its next free number.
  - `rpc Fire(FireRequest) returns (FireResponse)` in `Evidence`.
  - `FireRequest { string schedule = 1; bytes settings = 2; Context context = 3; }` and an empty `FireResponse`.
- **SDK:**
  - `type Schedule struct{ Name, Cron string }`, and `Capabilities.Schedules []Schedule`.
  - `type Source struct{ Name, Version string; BuiltTime time.Time }` and `type Sourcer interface{ Sources() []Source }`, which is optional. `GetInfo` reports the sources.
  - `type FireRequest struct{ Schedule string; Settings json.RawMessage; Context Context }` and `type Firer interface{ Fire(ctx context.Context, req FireRequest) error }`.
  - `checkCapabilities` refuses a schedule without a name, a duplicate name, and an empty cron.
  - `newServer` refuses schedules without a `Firer`, and a `Firer` without schedules, as it does for `Watches`.
- **The operator:**
  - `CollectorCapabilities.Schedules []CollectorSchedule{Name, Cron string}`, at most 8.
  - `CollectorStatus.Sources []CollectorSource{Name, Version string; BuiltTime metav1.Time}`, at most 8. They are taken from `GetInfo` and written only when they change.
  - `func (p *Pool) Fire(ctx context.Context, collector string, req *collectorv1alpha1.FireRequest) error`, with a 10-second deadline.

- [ ] **Step 1: Write the failing tests:**
  - **The SDK:**
    - the capability checks above;
    - `Serve` refuses a mismatch between schedules and `Firer`;
    - `GetInfo` reports a `Sourcer`'s sources.
  - **Conformance:**
    - a collector with schedules answers `Fire` for each of them within 10 seconds;
    - `Fire` with an unknown schedule fails with `InvalidArgument`;
    - sources have a name and a version.
  - **The operator:**
    - capabilities and sources are mirrored into the status;
    - `Pool.Fire` times out after 10 seconds.
- [ ] **Step 2: Run them and see them fail.**
- [ ] **Step 3: Implement,** then run `make proto`.
- [ ] **Step 4: Verify** with `make proto-check && make lint && make test`.
- [ ] **Step 5: Commit:** `feat(sdk): schedules, Fire and sources in the collector API`

### Task 4: Schedules and run now in the operator

**Files:**
- Create: `internal/controller/config/collector_schedules.go`, with its test.
- Modify:
  - `api/config/v1alpha1/{collector,common}_types.go`;
  - `internal/controller/config/collector_controller.go` (predicate, status);
  - `internal/setup/setup.go`;
  - `internal/metrics`;
  - `go.mod`, adding `github.com/robfig/cron/v3`.
- Test: `collector_schedules_test.go` (unit, with a fake clock), and `collector_api_test.go` (envtest).

**Interfaces:**
- Consumes: Task 3's `Pool.Fire`, `CollectorCapabilities.Schedules` and `CollectorStatus.Sources`.
- Produces:
  - `CollectorSpec.Triggers []CollectorTrigger`: at most 8, a list map by name. `CollectorTrigger{Name string; Schedule *string}` overrides the declared schedule of that name.
  - `CollectorStatus.Schedules []ScheduleStatus{Name, Schedule string; LastFireTime *metav1.Time; LastFailure *string}`, and `CollectorStatus.LastHandledRunNow *string`.
  - `configv1alpha1.AnnotationRunNow = "vexplain.bedag.ch/run-now"` and `ReasonTriggersInvalid`.
  - `type Scheduler struct`, a `manager.Runnable` with `Sync(c *configv1alpha1.Collector)`, which the controller calls after each reconcile.
  - The gauge `vexplain_collector_source_age_seconds{cluster, collector, source}`, read from `status.sources[].builtTime`.
- **Behaviour:**
  - The effective schedules of every Ready collector run. A fire calls `Pool.Fire`, and its time and any failure go to `status.schedules`.
  - A collector that isn't Ready isn't fired.
  - An unknown trigger name, or a cron that doesn't parse, gives `Ready=False` with the reason `TriggersInvalid`.
  - A new value of the run-now annotation fires every schedule once, then sets `lastHandledRunNow`. If a fire fails, `lastHandledRunNow` stays as it was, and the next reconcile tries again.

- [ ] **Step 1: Write the failing tests:**
  - **Firing:**
    - a declared schedule fires at its time and sets `lastFireTime`;
    - `spec.triggers` overrides the schedule;
    - an unknown name or a bad cron gives `TriggersInvalid`.
  - **Run now:**
    - the annotation fires every schedule once and sets `lastHandledRunNow`;
    - the same value again fires nothing;
    - a failed fire records `lastFailure` and leaves `lastHandledRunNow` unset;
    - a collector that isn't Ready isn't fired, and once it's Ready, one fire follows.
  - **The gauge** reads `builtTime`.
- [ ] **Step 2: Run them and see them fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Verify** with `make manifests generate && make lint && make test`.
- [ ] **Step 5: Commit:** `feat(config): run collectors' schedules, and run now`

### Task 5: Shipped permissions under the ceiling and the deny list

**Files:**
- Create:
  - `internal/controller/config/collector_rbac.go`, which grants;
  - `internal/controller/config/collector_ceiling.go`, which checks coverage;
  - `config/rbac/collector.yaml`, with the ceiling `vexplain-collector`, its binding to the manager's service account, and `vexplain-collector-defaults`.
- Modify:
  - `internal/controller/config/{collector_controller,collector_permissions}.go`: `ask` grants after reading the capabilities and before the SubjectAccessReview check;
  - `api/config/v1alpha1/common_types.go`: `ReasonPermissionsNotAllowed`, and the doc of `MissingPermissions`;
  - `api/config/v1alpha1/collector_types.go`: CEL refuses the name `defaults`;
  - `internal/setup/setup.go`: `CacheOptions.ByObject` for ClusterRole, ClusterRoleBinding, Role and RoleBinding, selected by the label `vexplain.bedag.ch/collector`; the comment on the operator's own rights;
  - `sdk/collector/identity.go`, its doc: vexplain grants;
  - `config/rbac/kustomization.yaml`, `config/default`;
  - `docs/collectors.md`.
- Delete: `config/collectors/rbac/`
- Test: `collector_ceiling_test.go` (unit), `collector_rbac_test.go` (envtest), and a YAML test for the defaults.

**Interfaces:**
- Consumes: Task 2's `settings.Effective`.
- Produces:
  - `func covered(ceiling []rbacv1.PolicyRule, denied []configv1alpha1.PermissionRule, rule *collectorv1alpha1.PolicyRule) (ok bool, guard string)`. The guard is `"ceiling"` or `"deny list"`.
    - `*` in a ceiling rule covers any group, resource or verb.
    - A deny rule refuses a declared rule when they overlap in group, resource and verb.
  - `func (r *CollectorReconciler) grant(ctx context.Context, obj *configv1alpha1.Collector, account string, rules []*collectorv1alpha1.PolicyRule) error`.
    - It creates or updates the four objects of decision 10.
    - It drops rules that the collector no longer declares, and deletes objects that hold no rule.
    - It binds `account`, the Deployment's `serviceAccountName`, which a runtime config may change.
- **Behaviour:**
  - **In `Grant` mode:**
    - a rule outside the ceiling, or a denied rule, gives `Ready=False` with `PermissionsNotAllowed`, which names the rules and the guard; nothing is granted;
    - a `Forbidden` from the API server on a create or update gives the same reason, with its message;
    - then 2b's SubjectAccessReview check runs as before.
  - **In `Check` mode,** nothing is granted.
  - **The manager's markers** gain `get`, `list`, `watch`, `create`, `update`, `patch` and `delete` on `clusterroles`, `clusterrolebindings`, `roles` and `rolebindings`. They never gain `escalate` or `bind`.
  - **The defaults** hold exactly the union of the built-ins' declared rules: the scanner's cluster-wide `get` on Secrets, but no `list` or `watch` on them.

- [ ] **Step 1: Write the failing tests:**
  - **`covered` (unit):**
    - exact, `*` and partial matches;
    - a deny overlap wins over the ceiling;
    - the default deny list refuses `list secrets` and allows `get secrets`.
  - **Grants (envtest, where the manager runs as admin, so the pre-check is what refuses):**
    - a collector's rules become the four objects, with label and owner;
    - a rule dropped from its capabilities disappears;
    - a runtime config that changes the service account gets that account bound;
    - a `Collector` named `defaults` is refused (CEL);
    - a rule outside the ceiling gives `PermissionsNotAllowed` naming the rule and "ceiling", and a denied rule names "deny list";
    - `Check` mode creates nothing and reports `MissingPermissions`;
    - the objects carry the `Collector`'s owner reference (envtest has no garbage collector).
  - **The defaults (YAML):** they cover every rule each built-in collector declares, those on optional kinds included, and no rule beyond.
- [ ] **Step 2: Run them and see them fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Verify** with `make manifests generate && make lint && make test`. The kind e2e for this task is in Task 17.
- [ ] **Step 5: Commit:** `feat(config): grant collectors' shipped permissions under a ceiling and a deny list`

### Task 6: Presence names containers; images without a digest

**Files:**
- Modify:
  - **SDK:** `sdk/evidence/types.go` and `sdk/evidence/schemas/ch.bedag.vexplain.presence.v1alpha1.json`, `sdk/workloads/digest.go` (`PodImages`), and `sdk/conformance/presence.go`.
  - **Collectors:** `collectors/workloads/internal/presence/{watcher,build}.go`, and the scanner's use of `PodImages` in `collectors/scanner/internal/scan/operation.go`.
  - **Operator:** `internal/spoke/presence.go` and `internal/controller/hub/assessor.go`.
- Test: `sdk/evidence/types_test.go`, `sdk/workloads/digest_test.go`, the workloads collector's tests, `internal/spoke/presence_test.go`, and the hub's assessor tests

**Interfaces:**
- Produces:
  - **Containers:** `PresencePod.Containers []PresenceContainer`, at most 32, with `PresenceContainer{Name, Kind string}`. The kind is `Container`, `InitContainer`, or `Sidecar` (an init container with `restartPolicy: Always`).
  - **Images without a digest:**
    - `evidence.DigestKindReference = "Reference"`;
    - such an image's subject is `image/sha256:<SHA-256 of the image reference from the pod spec>`, and its `Repositories` holds the reference.
  - **`PodImages`:** `workloads.PodImages(pod) (images []ImageRef, unparsable []string)`.
    - Each `ImageRef` gains `Containers []ContainerRef{Name, Kind string}`.
    - A container without an image ID gives an `ImageRef` of kind `Reference`, where today it is skipped as pending.
  - **The spoke:** `spoke.RunningImage{Digest string; Platforms []string; Containers []sdkworkloads.ContainerRef; Kind string}`, where `Kind` is presence's `digestKind`.
- **Behaviour:**
  - The workloads collector's cache keeps each container's image reference, and each init container's `restartPolicy` (`trimPod`).
  - The hub treats `Reference` as it treats `ImageID`: not pullable, never asked for evidence.

- [ ] **Step 1: Write the failing tests:**
  - **The presence schema** accepts containers and `Reference`, and refuses an unknown container kind.
  - **`PodImages`:**
    - names each container and its kind;
    - keeps two containers of one digest under one `ImageRef`;
    - gives a `Reference` image for a container without an image ID.
  - **Downstream:**
    - the workloads collector emits containers;
    - the spoke's `Running` lists containers per image;
    - the assessor marks a `Reference` image not pullable.
  - **Conformance** for presence collectors accepts containers.
- [ ] **Step 2: Run them and see them fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Verify** with `make lint && make test`.
- [ ] **Step 5: Commit:** `feat(presence): name the containers that run each image, and keep images without a digest`

### Task 7: The `sbom` type

**Files:**
- Create: `sdk/evidence/schemas/ch.bedag.vexplain.sbom.v1alpha1.json`
- Modify:
  - **SDK:** `sdk/evidence/{evidence,types}.go`.
  - **The scanner:**
    - `collectors/scanner/internal/result/result.go`: `Manifest` loses `SBOM`;
    - `collectors/scanner/internal/scan/operation.go`: the capabilities produce both types, and `eventsOf` emits both events per manifest;
    - the analysis that builds the reduced SBOM in `collectors/scanner/cmd/main.go` and `internal/analyze`.
  - **`vulnerabilities`:** `collectors/vulnerabilities/internal/match/operation.go` consumes `TypeSBOM`, and `sbomOf` builds a minimal Syft JSON document from `data.packages`.
  - **Rules and playbook:**
    - `config/rules/{removed-in-later-layer,load-check}.yaml` and `config/samples/config_v1alpha1_rule.yaml` take the input `sbom` and read `sbom.data.packages`;
    - `config/playbooks/container-cves.yaml` gets the evidence entry `sbom`.
  - **Fixtures:** `internal/testenv/imagecontents`, the hub's fixtures, and `hack/measure-2a`.
- Test: the SDK's type tests, the scanner's operation tests, `vulnerabilities`' operation tests, `internal/rules/engine/defaults_test.go` (golden files), and the hub's assessor tests

**Interfaces:**
- Produces:
  - `evidence.TypeSBOM = "ch.bedag.vexplain.sbom.v1alpha1"`
  - `type SBOM struct{ Distro *Distro; Packages []SBOMPackage; Producer Producer; FailedCatalogers []string }`, with:
    - `Distro{ID, Version string}`;
    - `SBOMPackage{ID, Name, Version, Type, PURL string; CPEs []string}`;
    - `Producer{Name, Version string}`.
- **Behaviour:**
  - A scan gives two events per manifest, `sbom` and `image-contents`, with the same coverage.
  - The hub asks for `sbom`, the type `vulnerabilities` consumes. The scanner's answer brings `image-contents` with it.
  - The rules that read the SBOM check `sbom.data.packages.exists_one(p, p.id == finding.packageID)`.

- [ ] **Step 1: Write the failing tests:**
  - **The SDK:** the schema accepts a sample and refuses an unknown field.
  - **The scanner:**
    - an invocation returns both events per manifest, each under the size cap, with the same coverage;
    - the 2a fixture's SBOM arrives unchanged in `sbom.data.packages`.
  - **`vulnerabilities`:** an `sbom` input gives the same matches as the old `image-contents` input gave for the same fixture (golden).
  - **The rules:** the defaults' golden files give the same verdicts with the new input.
  - **The hub:** an image goes from presence to `sbom` and `image-contents` evidence, then to findings and a sheet.
- [ ] **Step 2: Run them and see them fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Verify** with `make lint && make test`.
- [ ] **Step 5: Commit:** `feat(evidence): a neutral sbom type between the scanner and vulnerabilities`

### Task 8: `vulnerabilities`: fix targets, aliases and the envelope

**Files:**
- Create: `collectors/vulnerabilities/internal/match/targets.go`, with its test.
- Modify:
  - **SDK:** `sdk/evidence/types.go` and the findings schema.
  - **`vulnerabilities`:**
    - `collectors/vulnerabilities/go.mod`: `github.com/anchore/grype v0.121.0`;
    - `collectors/vulnerabilities/internal/grype/grype.go`: it parses `relatedVulnerabilities`.
  - **The operator:**
    - `internal/rules/engine/engine.go`: the merge keeps the new fields;
    - `api/inventory/v1alpha1/imageverdicts_types.go`: `Finding` gains `FixTarget`, `UpdateTarget` and `Aliases`;
    - `internal/rules/sheet.go`;
    - `internal/spoke/render.go`: an update's target is `updateTarget`, and `plainVersion`, `releaseSuffixes`, `updateTarget` and their helpers go.
- Test: `targets_test.go`, the Grype parsing tests, the engine's merge tests, and `render_test.go`

**Interfaces:**
- Produces:
  - `Match` gains:
    - `ID` (`<vulnerabilityID>/<packageID>`);
    - `Title` (`<vulnerabilityID> in <packageName> <packageVersion>`);
    - `Aliases` (at most 8, sorted);
    - `FixTarget` and `UpdateTarget` (each at most 128 characters).
  - `func fixTarget(format version.Format, installed string, fixed []string) string` gives the lowest fixed version above `installed`. It is empty when `installed` doesn't parse, or when no fixed version parses and lies above it.
  - `func setUpdateTargets(matches []evidence.Match)` sets each match's `UpdateTarget` to the highest `FixTarget` among its package's matches in the manifest.
  - A package type maps to Grype's `version.Format` as Grype maps it.

- [ ] **Step 1: Write the failing tests:**
  - **`fixTarget`:**
    - deb: installed `1.2-3`, fixes `1.2-4` and `1.3-1`, gives `1.2-4`;
    - apk with `-r` suffixes, and rpm with `.el` suffixes;
    - Go: installed `v1.2.3`, fixes `v1.2.5` and `v1.3.0`, gives `v1.2.5`;
    - Python (PEP 440) and Maven;
    - an unparsable fixed version is skipped;
    - a type Grype doesn't know gives no target;
    - no fix above the installed version gives none.
  - **`setUpdateTargets`:** two CVEs in one package, with targets `1.2.5` and `1.2.7`, give `1.2.7` on both.
  - **Aliases:** a Grype fixture's `relatedVulnerabilities` become `aliases`.
  - **Downstream:**
    - the engine's merge and the sheet keep targets and aliases;
    - an update takes `updateTarget`, and a finding without one names no target.
- [ ] **Step 2: Run them and see them fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Verify** with `make manifests generate && make lint && make test`.
- [ ] **Step 5: Commit:** `feat(vulnerabilities): ecosystem-correct fix targets and aliases`

### Task 9: `vulnerabilities`: the database on a schedule, persistent, with its age

**Files:**
- Create: `config/collectors/vulnerabilities-db.yaml`, the PVC.
- Modify:
  - **`vulnerabilities`:**
    - `collectors/vulnerabilities/internal/match/{database,operation}.go`: the database's upkeep moves out of `Watch` into a maintainer that `main` starts; `Fire`; `Sources()`;
    - its `cmd/main.go`.
  - **Install:**
    - `config/collectors/{kustomization,runtimeconfigs}.yaml`: `/db` from the PVC, strategy `Recreate`;
    - `test/e2e/config/kustomization.yaml`.
  - `docs/collectors.md`.
- Test: the database and operation tests, and conformance

**Interfaces:**
- Consumes: Task 3's `Schedule`, `Firer` and `Sourcer`, and Task 4's scheduler.
- Produces:
  - **Capabilities:** `Schedules: []collector.Schedule{{Name: "database", Cron: "0 */6 * * *"}}`.
  - **`Fire`** on `database` starts an update in online mode and returns. A fire during an update does nothing.
  - **`Sources()`** returns `{Name: "grype-db", Version: <the database's version>, BuiltTime: <its build time>}` once a database is loaded.
  - **Settings:**
    - `updateIntervalSeconds` goes, since `spec.triggers` changes the schedule now;
    - `databaseUpdates` (`Online` or `Offline`) and `seedDatabase` stay.
- **Behaviour:**
  - **At start,** the maintainer loads `/db`, else seeds it, else updates it (online).
  - **`Watch` only reports:** an empty snapshot, then `SourceChanged` for each new database version, on every open stream.
  - **Offline,** `Fire` does nothing.

- [ ] **Step 1: Write the failing tests:**
  - **Updates:**
    - `Fire` starts an update, and a new version emits `SourceChanged` on every open stream;
    - two Watches share one maintainer;
    - Offline ignores `Fire`.
  - **Sources:** they report the version and the build time.
  - **Persistence:** a restart with a database on `/db` loads it without a download.
  - **Settings:** they refuse `updateIntervalSeconds`.
  - **Conformance** passes with the schedule.
- [ ] **Step 2: Run them and see them fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Verify** with `make lint && make test`.
- [ ] **Step 5: Commit:** `feat(vulnerabilities): keep the database across restarts, and refresh it on a schedule`

### Task 10: Playbooks name types; optional entries; several producers

**Files:**
- Modify:
  - **The API:** `api/config/v1alpha1/{playbook,common}_types.go`.
  - **The hub:**
    - `internal/controller/hub/playbook_controller.go`: `checkPlaybook`, `checkCollectors` (which becomes `checkProducers`), `checkPipeline`;
    - `internal/controller/hub/assessor.go`: `consumed`, `keyOf`, `evidenceOf`, `inputsOf`, `assess`;
    - `internal/controller/hub/rule_controller.go`.
  - **The engine:** `internal/rules/engine/engine.go`.
  - **Config:** `config/playbooks/container-cves.yaml` and `config/samples/config_v1alpha1_playbook.yaml`.
- Test: `playbook_api_test.go`, `playbook_controller_test.go`, the assessor tests, `engine_test.go`, and `rule_controller_test.go`

**Interfaces:**
- Produces:
  - **The entries:**
    - `PlaybookSource{Type string; Collectors []string}`;
    - `PlaybookFindings{Type string; Collectors []string}`, whose type defaults to the findings type;
    - `PlaybookEvidence{Name, Type string; Collectors []string; Optional bool}`.

    `Collectors`, at most 8, pins the producers; empty means every installed producer of the type.
  - **Validation and display:**
    - CEL: Playbook names are DNS-1123 labels of at most 63 characters;
    - print columns: Subjects and Findings (the types, priority 1), Ready, Reason, Age.
  - **The engine:** `engine.Evaluate(steps []*Compiled, inputs map[string][]Input, matches []evidence.Match) Result` evaluates each combination of producers, at most 4. With more, every finding is `UnderInvestigation` with the reason "more than 4 combinations of producers".
- **Behaviour:**
  - **Required and optional entries:**
    - a required entry with no Ready producer gives `Ready=False` with `TypeNotProduced`;
    - an optional one keeps the playbook Ready. Its rules see the input as missing: a settling rule doesn't apply, a holding rule holds, and the rule's `Evaluated` condition doesn't count it.
  - **The assessor:**
    - it asks for the types that the findings producers consume;
    - it reads each entry's type from every producer, pinned or not, keyed `{subject, type, source}`;
    - findings from several producers merge per (vulnerability, package), as the engine already does.
  - **`container-cves` becomes:**
    - subjects of the presence type, and findings of the findings type;
    - the evidence entries `contents` (`image-contents`) and `sbom`;
    - the same four rules.

- [ ] **Step 1: Write the failing tests:**
  - **The API:**
    - a playbook with types and pins passes;
    - a name over 63 characters is refused;
    - the sample passes.
  - **The controller:**
    - a required type without a producer gives `TypeNotProduced`;
    - an optional one leaves the playbook Ready;
    - pins restrict the producers.
  - **The assessor:**
    - two producers of one type give two evaluations, and the most cautious wins: a finding that one producer's evidence settles and the other's doesn't stays open;
    - a missing optional input holds a finding that a holding rule covers, and lets no settling rule apply.
  - **The engine:**
    - two inputs with two producers each give four evaluations;
    - five combinations hold every finding.
  - **The rule controller:** `Evaluated` stays True when only optional inputs were missing.
- [ ] **Step 2: Run them and see them fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Verify** with `make manifests generate && make lint && make test`.
- [ ] **Step 5: Commit:** `feat(playbooks): name types, take optional entries, and read every producer`

### Task 11: Several playbooks at once: the cluster match, and sheets per playbook

**Files:**
- Modify:
  - **The API:** `api/config/v1alpha1/playbook_types.go` (`Match`) and `api/inventory/v1alpha1/imageverdicts_types.go` (`spec.playbook`, and the name's CEL).
  - **Inventory:** `internal/inventory/{names,verdicts}.go`.
  - **The hub:** `internal/controller/hub/{assessor,playbook_controller,janitor,summaries}.go`.
  - **The spoke:** `internal/spoke/{reports,render,metrics}.go`, which reads the sheets through `List`.
  - **Tests and tools:** `test/e2e/helpers_test.go` (sheets by name) and `hack/measure-2a`.
- Test: `imageverdicts_api_test.go`, `internal/inventory/verdicts_test.go`, and the assessor, janitor and summaries tests

**Interfaces:**
- Consumes: Task 2's cluster labels, and Task 10's playbook types.
- Produces:
  - **`PlaybookSpec.Match *PlaybookMatch{Clusters, Namespaces *metav1.LabelSelector}`.** An absent selector matches everything.
  - **`ImageVerdictsSpec.Playbook string`,** immutable.
    - The name is `inventory.SheetName(manifest, playbook string) string`, which is `<NameForDigest(manifest)>.<playbook>`.
    - The labels are those of decision 14.
  - **`inventory.VerdictsStore`:**
    - `Get(ctx, manifest, playbook string)`;
    - `Put(ctx, manifest, playbook string, status)`;
    - `Delete(ctx, manifest, playbook string)`;
    - `List(ctx, manifest string) ([]inventoryv1alpha1.ImageVerdicts, error)`.
- **Behaviour:**
  - **Which playbooks judge an image:** every Ready playbook over presence whose cluster selector matches the labels of a cluster where the image runs. Until phase 6 there is one cluster, whose labels are `OperatorConfig.spec.clusterLabels`.
  - **The assessor's state** (`assessed`, `changedAt`, `Evaluations`) is kept per manifest and playbook.
  - **The janitor** lists sheets by the manifest label. It deletes the sheets of deleted playbooks, and of playbooks whose cluster match no longer covers the image.
  - **Two playbooks over presence both run,** so the reason `Conflict` goes.
  - **The manager's RBAC** on `imageverdicts` gains `list` and `watch`.
  - **Until Task 13,** the spoke renders from the sheet of the oldest playbook, as before.

- [ ] **Step 1: Write the failing tests:**
  - **The API:**
    - the name must equal `<digest name>.<playbook>`;
    - `spec.playbook` is immutable.
  - **Matching:**
    - two playbooks give two sheets per manifest;
    - a playbook whose cluster selector doesn't match gives none;
    - changing the cluster labels so a playbook no longer matches removes its sheets.
  - **Clean-up:**
    - deleting a playbook deletes its sheets;
  - **The image summary** takes the worse sheet.
- [ ] **Step 2: Run them and see them fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Verify** with `make manifests generate && make lint && make test`.
- [ ] **Step 5: Commit:** `feat(playbooks): run several at once, matched by cluster, with sheets per playbook`

### Task 12: The `ResourceReport` kind

**Files:**
- Create:
  - `api/triage/v1alpha1/resourcereport_types.go`;
  - `config/rbac/triage_resourcereport_{admin,editor,viewer}_role.yaml`;
  - `internal/controller/triage/resourcereport_api_test.go`.
- Modify:
  - `PROJECT`, `config/crd/kustomization.yaml` and `config/rbac/kustomization.yaml`;
  - `internal/conditions/{crds,readable}_test.go` and `internal/controller/config/typepattern_api_test.go`;
  - `.golangci.yml`.

`WorkloadReport` stays until Task 13, when the renderer switches.

**Interfaces:**
- Produces `triagev1alpha1.ResourceReport`: namespaced, in the category `vexplain`, with:
  - **`spec.resource{APIGroup *string; Kind, Name string}`,** immutable.
  - **`status.images`,** at most 32:
    - `Digest *string`, absent for `Reference`;
    - `Reference *string`;
    - `ManifestDigests`;
    - `State`: `Pending`, `Ready`, `Incomplete` or `Unscannable`;
    - `Containers []string`.
  - **`status.actions`,** at most 256:
    - `Step`: `Update`, `Change`, `Mitigate` or `Investigate`;
    - `Title`, at most 256 characters;
    - `Locations`, 1 to 8, each at most 256 characters;
    - `Severity` and `Urgency *SSVCOutcome`;
    - `Requirement{Playbook string; Rule *string}`;
    - `Reason *string`;
    - for vulnerabilities: `Package`, `FixedVersion` (only on `Update`), `Vulnerabilities`, `VulnerabilityIDs` (1 to 5), `KnownExploited`, `Digests` (1 to 8) and `OmittedDigests`.
  - **`status.summary`:**
    - `Actions`, `Updates`, `Changes`, `Mitigations`, `Investigations` and `OmittedActions`;
    - `HighestSeverity` and `HighestUrgency`;
    - `Critical` and `KnownExploited`;
    - `PendingImages` and `UnscannableImages`.

    0038's CEL rules carry over:
    - the steps add up to the actions;
    - `omittedActions` is at most `actions`;
    - `highestUrgency` is set exactly when a vulnerability action exists.
  - **`status.owner`, `status.exposure` and `status.reach`,** as in `WorkloadReport`.
  - **Columns:** Kind and Resource (priority 1), Exposure, Highest Urgency, Actions, Critical, Known Exploited, Pending, Age.

- [ ] **Step 1: Write the failing tests:** each of the kind's CEL rules, as `workloadreport_api_test.go` does for its own:
  - an `Unscannable` image without a digest passes;
  - `fixedVersion` only on `Update`;
  - the steps add up;
  - locations number 1 to 8.
- [ ] **Step 2: Run them and see them fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Verify** with `make manifests generate && make lint && make test`.
- [ ] **Step 5: Commit:** `feat(triage): the ResourceReport kind`

### Task 13: Rendering `ResourceReport`s: namespaces, containers and locations

**Files:**
- Create: `internal/spoke/namespaces.go` (a metadata-only Namespace informer) and `internal/spoke/locations.go`.
- Modify: `internal/spoke/{render,reports,metrics,presence}.go` and `internal/setup/setup.go`.
- Delete: `api/triage/v1alpha1/workloadreport_types.go`, its CRD and roles, `internal/controller/triage/workloadreport_api_test.go`, and every remaining reference to it, as listed in Task 12.
- Test: `render_test.go`, `reports_test.go`, `metrics_test.go`, `locations_test.go` and `namespaces_test.go`

**Interfaces:**
- Consumes:
  - Task 6's containers;
  - Task 8's `updateTarget`;
  - Task 11's sheets per playbook and `Match.Namespaces`;
  - Task 12's kind.
- Produces:
  - `func Location(kind string, c sdkworkloads.ContainerRef) string`, which gives the paths of decision 17.
  - `func playbooksFor(nsLabels, clusterLabels map[string]string, playbooks []configv1alpha1.Playbook) []configv1alpha1.Playbook`.
- **Behaviour:**
  - **Which playbooks:** a workload's report holds the results of the playbooks whose cluster selector matches the cluster's labels and whose namespace selector matches its namespace's labels. Each action names its playbook as its requirement.
  - **Merging:**
    - candidates merge per (vulnerability, package) within one image digest, never across digests;
    - actions group per (step, package name, version, type, digest);
    - each action lists the locations of every container that runs its digest, at most 8.
  - **Images:** images of kind `ImageID` or `Reference` show as `Unscannable`, not `Pending`.
  - **Metrics:** `vexplain_open_case` gains the label `kind`. Its source reads `ResourceReport`s.
  - **The spoke's RBAC:** `list` and `watch` on `namespaces`, and `ResourceReport` in place of `WorkloadReport`.

- [ ] **Step 1: Write the failing tests:**
  - **Merging and locations:**
    - two containers of one digest give one action with both locations;
    - two images with the same package and version give separate actions, each with its own target, since 2b's merge is gone;
    - locations for a Deployment, a CronJob, a Pod, an init container and a sidecar.
  - **Playbooks:**
    - a playbook whose namespace selector excludes the namespace adds nothing to that report;
    - a matching one adds its actions, and names itself;
    - a change of a namespace's labels renders its reports again.
  - **Images:** an image ID and a reference image show as `Unscannable`, and count in `unscannableImages`.
  - **Lifecycle:** reports are created, updated and deleted as before.
- [ ] **Step 2: Run them and see them fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Verify** with `make manifests generate && make lint && make test`.
- [ ] **Step 5: Commit:** `feat(reports): ResourceReport, with actions per container and the namespace match`

### Task 14: The fleet picture

**Files:**
- Create:
  - `api/inventory/v1alpha1/playbookcounts_types.go`;
  - `internal/spoke/counts.go`;
  - `internal/controller/hub/fleet.go`.
- Modify:
  - `api/config/v1alpha1/playbook_types.go`: the status's `summary` and `clusters`;
  - `internal/controller/hub/{playbook_controller,metrics}.go`;
  - `internal/inventory`: a counts store;
  - `internal/setup/setup.go`;
  - `PROJECT`, and the CRD and RBAC kustomizations.
- Test: the API tests (envtest), `counts_test.go`, `fleet_test.go` and `metrics_test.go`

**Interfaces:**
- Produces:
  - **`PlaybookCounts`** (`inventory.vexplain.bedag.ch/v1alpha1`, cluster-scoped, in the categories `vexplain` and `vexplain-data`):
    - named `<playbook>.<cluster>`, and owned by its Playbook;
    - `spec{Playbook, Cluster string}`;
    - `status{Judged, Failing int32; Actions ActionCounts; Severities SeverityCounts; UpdatedTime metav1.Time}`;
    - `ActionCounts{Updates, Changes, Mitigations, Investigations int32}` and `SeverityCounts{Critical, High, Medium, Low, Unknown int32}`.
  - **The Playbook's status:**
    - `Summary *FleetSummary{Clusters, Judged, Failing int32; Actions ActionCounts; Severities SeverityCounts}`;
    - `Clusters []ClusterCounts`: at most 16, the most failing first.
    - Two new columns: Judged and Failing.
  - **Hub metrics:**
    - `vexplain_playbook_resources{cluster, playbook, state}`, where `state` is `judged` or `failing`;
    - `vexplain_playbook_actions{cluster, playbook, step}`;
    - `vexplain_rule_findings{playbook, rule, status}`: the findings each rule decided, by status, over the current sheets.
- **Behaviour:**
  - **The spoke:** after each render, it writes each playbook's counts for its cluster, but only when they change:
    - the resources it judged, meaning those holding the playbook's results;
    - the resources failing, meaning those with at least one action;
    - the actions, by step and by severity.
  - **The playbook controller** sums the counts into the status.

- [ ] **Step 1: Write the failing tests:**
  - **The spoke** writes counts per playbook, and writes again only when they change.
  - **The hub:**
    - it sums the counts of two clusters;
    - it lists them most failing first, capped at 16.
  - **The metrics** read the counts and the sheets.
- [ ] **Step 2: Run them and see them fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Verify** with `make manifests generate && make lint && make test`.
- [ ] **Step 5: Commit:** `feat(playbooks): the fleet picture`

### Task 15: The scanner: pull credentials, failures, coverage and metrics

**Files:**
- Modify:
  - **The scanner:**
    - `collectors/scanner/internal/scan/{credentials,operation,settings}.go`;
    - `collectors/scanner/cmd/main.go`: the scan's keychain, failed catalogers, and the metrics registry;
    - `collectors/scanner/internal/result/result.go` and `collectors/scanner/internal/analyze/syft.go`.
  - **The SDK:** `sdk/jobs/job.go`, whose Secret holds several configs.
  - **The hub:** `internal/controller/hub/assessor.go`, where a settings change clears the back-off of its producer's failures.
  - `docs/collectors.md`.
- Test: the scanner's tests, `sdk/jobs/job_test.go`, and the assessor tests

**Interfaces:**
- Produces:
  - **The setting `adminPullSecrets []string`,** at most 16: names of `kubernetes.io/dockerconfigjson` Secrets in the operator's namespace.
  - **`jobs.Spec.DockerConfigs [][]byte`,** which replaces the single config. The Secret's keys are `config-0.json`, `config-1.json`, and so on, in order.
  - **The scan's keychain,** `orderedKeychain`, which tries each config for a registry until a pull succeeds.
  - **The failure `Unauthorized`,** with the message `registry <host>: no credentials worked: <the Secrets' names>`.
  - **`SBOM.FailedCatalogers`.**
  - **Metrics:** `vexplain_scanner_scans_total{cluster, result}` and the histogram `vexplain_scanner_scan_duration_seconds`, on the health port.
  - **`maxConcurrentScans`** defaults to 4.
  - **`TooLarge`** needs nothing more here. Task 7's split keeps each event under the cap, and its tests check that.

- [ ] **Step 1: Write the failing tests:**
  - **Credentials:**
    - the workload's credentials go first, then the admin's;
    - the Job's Secret holds the configs in that order;
    - a pull that fails with every config gives `Unauthorized`, naming the registry and the Secrets, never their content.
  - **Coverage:** a failed language cataloger gives coverage 0 and is named.
  - **Metrics:** they count the results.
  - **The hub:** a settings change asks again at once for a failed image.
- [ ] **Step 2: Run them and see them fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Verify** with `make lint && make test`.
- [ ] **Step 5: Commit:** `feat(scanner): admin-provided pull credentials, failures that say what failed, and metrics`

### Task 16: `network-reach`: trusted peers, host settings, and what widened reach

**Files:**
- Modify:
  - **The SDK:** `sdk/evidence/types.go` and the exposure schema.
  - **The collector:** `collectors/network-reach/internal/exposure/{external,reach,build,cilium}.go`.
  - **The spoke and the report:** `internal/spoke/{exposure,render}.go` and `api/triage/v1alpha1/resourcereport_types.go`, where `ReportReach` gains `WidenedBy` and `Unseen`.
  - `docs/collectors.md`.
- Test: the collector's tests, the spoke's tests, and the `ResourceReport` API test

**Interfaces:**
- Produces:
  - **Settings:**
    - `trustedPeers []TrustedPeer{NamespaceSelector, PodSelector *metav1.LabelSelector; ServiceAccount *{Namespace, Name string}}`: at most 32 entries, each setting at least one field;
    - `hostNetwork`, `hostPorts` and `nodePorts`, each `External` (the default) or `Internal`. `nodePorts` now covers only NodePort Services.
  - **`Exposure.WidenedBy []Widening{Kind, Namespace, Name string; Rule *int32; Reason string}`,** at most 8: what set the widest reach, such as a NetworkPolicy's rule, or "no policy in the namespace".
  - **`Exposure.Unseen []string`,** at most 8, sorted: `AdminNetworkPolicy`, `CalicoNetworkPolicy`, `ipBlock`, `unknownParentRef`.
- **Behaviour:**
  - **Trusted peers:**
    - a peer that a trusted entry matches never widens reach;
    - a trusted frontend still makes its backends indirectly exposed, since a trusted ingress controller still exposes what it routes to.
  - **Host network:** `hostNetwork: Internal` keeps host-network pods from counting as exposed. Their internal reach stays `Cluster`.
  - **The report** shows `widenedBy` and `unseen` under `reach`. Reach changes urgency, never a verdict (0006).

- [ ] **Step 1: Write the failing tests:**
  - **Trusted peers:**
    - a policy that admits a trusted namespace no longer widens reach, and `Small` can occur;
    - a trusted service account (Cilium) does the same;
    - a trusted ingress controller still marks its backends indirect.
  - **Host settings:** the three settings each act alone.
  - **`widenedBy`:** it names the rule that set `Cluster`, and "no policy" for a namespace without one.
  - **`unseen`:** it lists an `ipBlock` peer and an unknown parentRef.
- [ ] **Step 2: Run them and see them fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Verify** with `make manifests generate && make lint && make test`.
- [ ] **Step 5: Commit:** `feat(network-reach): trusted peers, host settings, and what widened reach`

### Task 17: Install, docs, e2e and the measurement

**Files:**
- Modify:
  - **Install:** `config/default`, `config/collectors` and `config/rbac`.
  - **Docs:**
    - `README.md`: install, the ceiling, `Grant` and `Check`, and the database's PVC;
    - `docs/collectors.md`: shipped permissions, schedules and `Fire`, sources, the `sbom` type, `adminPullSecrets`, and `network-reach`'s settings.
  - **Tests and tools:** `test/e2e/*` and `hack/measure-2a`.
- Test: e2e on kind, and the measurement

- [ ] **Step 1: Write the e2e specs:**
  - **Permissions:**
    - every collector is Ready with RBAC that the operator granted, and the four objects carry owner references;
    - removing a rule from `vexplain-collector-defaults` gives the affected collector `PermissionsNotAllowed`, and restoring it brings the collector back.
  - **Run now:** the annotation on `vulnerabilities` fires its schedule, and `lastHandledRunNow` follows.
  - **Reports:**
    - a `ResourceReport` for a workload with two containers names both;
    - a second playbook limited to one namespace adds its actions only there;
    - `PlaybookCounts` and the Playbook's summary appear.
  - **`network-reach`:** a trusted namespace changes a workload's reach.
  - **The e2e config** keeps the database offline, seeded, on the PVC.
- [ ] **Step 2: Run them** with `make test-e2e`, and see the new specs fail where the install still lacks something.
- [ ] **Step 3: Fix the install.**
- [ ] **Step 4: Run the measurements:**
  - **The verdicts** (`hack/measure-2a`): the same as phase 2b's run, since the `sbom` split changes nothing.
  - **Presence at scale,** on kind with a synthetic load of 2000 pods in 200 workloads: the snapshot's size, and the time a rebuild takes, recorded in `docs/measurements/` (design 5.9).
- [ ] **Step 5: Commit:** `test(e2e): phase 3a on kind`, and `docs: phase 3a`

### Task 18: The live re-run, with the owner

This task isn't for an agent. The owner deploys the branch's images to the live dev cluster, as on 2026-11-07, and checks design section 8's list for 3a:
- whether `Small` exposure appears with trusted peers set, and what still widens reach;
- reports with actions per container;
- the scanner's credentials with `adminPullSecrets`;
- the database's persistence across a restart, and its age;
- evidence sizes after the `sbom` split, against 0004's gate.

The findings stay in the owner's private notes. Only what changes the plan for 3b goes into "Carried forward", in neutral words.

## As built

Written when the plan is done.

## Carried forward

Written when the plan is done.
