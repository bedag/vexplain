# vexplain — Phase 2a (The hub decides from scans) Implementation Plan

> **For agents:** follow `AGENTS.md`. Implement this plan task by task, test first. A task is done when its tests pass, it is committed and it has been reviewed; only then start the next one. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** On one kind cluster, running as hub and spoke at once, the operator:
- scans every running image it can pull, in a throwaway Job with the pod's own pull credentials (0022)
- keeps each platform manifest's evidence once, compressed (0023)
- matches the packages against one vulnerability database at the hub, and matches again when the database updates (0022)
- settles every finding it can with deterministic rules, each finding scoped to one package (0025, 0026), in an `ImageVerdicts` sheet
- measures the residual on Brotli on kind, against known answers (design section 9)

**Architecture:**
- **Spoke (hands).** A scan runner turns scan requests into Jobs in the operator's namespace.
  - Each Job runs our scanner image. It pulls the image by digest, unpacks each platform's filesystem, runs the Syft CLI, analyses ELF linkage and library names, and prints one compressed result line.
  - The runner reads that line from the pod log. It writes the evidence through `inventory.PackagesStore`, and the facts through `inventory.Store`.
- **Hub (decisions):**
  - A scheduler asks for scans through `tasks.Executor`.
  - A verdicts controller sends each manifest's reduced SBOM to the matcher, applies `rules.Evaluate`, and writes the sheet through `inventory.VerdictsStore`.
  - A poller starts a new round of matching when the database changes.
  - A janitor removes evidence and sheets that no digest refers to any more.
- **The matcher** is a small HTTP service of ours around the Grype CLI, holding the one database. It runs as its own Deployment.
- **One process, two roles.** Hub and spoke share one process (`HubAndSpoke`), as in phase 1. They meet only through `tasks.Executor` and the inventory stores.

**Tech Stack:**
- Go 1.26, kubebuilder v4.15 (controller-runtime v0.24)
- go-containerregistry, for pulling, unpacking and the Kubernetes keychain
- Syft and Grype as pinned upstream CLIs
- `debug/elf`, and an Aho–Corasick matcher
- envtest with Ginkgo/Gomega, and testify
- kind with a local registry

**Spec:**
- `docs/design/2026-10-29-vexplain-design.md`, revision 11. Phase 2a is section 7. Sections 6.2, 6.3, 6.5, 6.11, 6.12 and 9 matter most.
- Decision records 0004, 0010, 0011, 0021 and 0022–0027.
- Phase 1's plan (`docs/plans/2026-10-29-phase1-foundations.md`):
  - Its "As built" section describes what exists.
  - Its "Carried forward" items due "at the start of phase 2" are Tasks 1 and 4.
  - Mirror pods move to 2b.
- **Not in this plan** (phase 2b or later):
  - the exposure collectors, `Collector.state` and discovery
  - urgency (0024), `WorkloadReport`, rendering, metrics and events
  - mirror pods
  - the `Govulncheck` collector (0027)
  - the check of each pod's environment for `LD_PRELOAD` (decision 11 below)
  - Chainsaw
  - phase 1's real-cluster fixes
  - pull credentials that an admin adds (0022, design 6.12). The kind setup pulls anonymously from its local registry, so they come with the first real cluster.
  - the gauge of skipped containers that phase 1's "Carried forward" says to consider

## Decisions made in this plan

The design leaves these to the builder. Each is decided here, so implementers don't guess. The owner checks them when reviewing this plan.

1. **Syft and Grype run as their upstream CLIs,** pinned by version and SHA-256 in `Dockerfile.scanner` and `Dockerfile.matcher`.
   - Our code lives in the main module: `cmd/scanner` and `cmd/matcher`, plus scanner-only and matcher-only packages.
   - No `github.com/anchore/*` module enters `go.mod`. That meets 0022's goal of keeping the operator free of Syft's and Grype's dependencies without separate Go modules, and 0022 gets a note saying so.
   - The CLIs are tested upstream, and their JSON is stable across versions.
2. **`ImagePackages` holds all of a manifest's evidence,** not just the package list. That means the reduced SBOM, the load evidence per library (0026), the file presence per package, the preload flags and the ELF summary. 0026's evidence has to outlive the scan, so that later rules can use it without pulling again. 0023 gets a note.
3. **The evidence is in `spec`,** and CEL makes `spec` immutable (`self == oldSelf`). The API server enforces "written once". A new scanner image replaces an object by deleting it and creating it again.
4. **Size limits.**
   - Compressed evidence may be at most 786432 bytes (768 KiB), which is 1 MiB as base64, below etcd's 1.5 MiB per request. Larger evidence is a failed scan with reason `TooLarge`, so the digest counts as unscanned.
   - A sheet keeps at most 2048 findings. `NeedsAssessment` and `Tracked` come first, so only `Suppressed` ones can ever be left out, and `omittedFindings` counts them.
   - The measurement reports both sizes against 0004's 512 KiB trigger.
5. **The order of the rules for each finding:**
   1. KEV
   2. the completeness guard
   3. removed in a later layer
   4. the load check
   5. `NeedsAssessment`

   KEV wins over every suppression: an actively exploited CVE is patched, not argued about.
6. **The load check applies only to a package whose owned ELF files are all shared libraries with a soname.**
   - A package that owns an executable can be run, so the check doesn't apply to it.
   - Neither does it apply to a package that owns no library, such as a language package. Those findings are `NeedsAssessment`.
7. **`DT_NEEDED` is resolved by soname across the whole image.**
   - Every library whose soname, or file name, matches a needed entry counts as reached.
   - There is no emulation of the linker's search paths. Over-reaching only makes the residual bigger.
8. **Library names:**
   - The versioned and unversioned names match as plain substrings.
   - The bare name, such as `brotlidec`, needs a non-identifier byte, or the start or end of the file, on each side. A bare name that hits every file just keeps that package unsettled, which is safe.
9. **A non-empty `/etc/ld.so.preload` blocks the load check,** like `LD_PRELOAD`.
10. **The completeness guard's threshold** is `OperatorConfig.spec.rules.minCompletenessPercent`, default 90, because it is a hub rule. Phase 2a's measurement reports completeness per case, so the owner can tune it.
11. **The pod-level check of 0026 is a condition on the finding.**
    - The check: no pod sets `LD_PRELOAD` or `LD_AUDIT`.
    - A suppression by the load check carries the condition `NoPreloadEnvironment`. 2b's renderer checks it for each workload: the design's "check the conditions per workload".
    - Phase 2a has no renderer, and none of the measurement's pods set either variable.
    - Whether `envFrom` must count is a question for 2b, because the operator never reads workload Secrets. 0026 gets a note.
12. **Which platforms get scanned:** those of the nodes that run the digest's pods, read from the node labels `kubernetes.io/os` and `kubernetes.io/arch`. When no pod is scheduled yet, the platforms of all nodes.
13. **Scan pods are never inventoried.** Pods with the label `vexplain.bedag.ch/task` are the operator's own, and the pod index skips them.
14. **Results travel in the pod log:** one line, `vexplain-scan-result v1 <base64(gzip(json))>`, or `vexplain-scan-error v1 <Reason>`. Trivy Operator returns its results through the Job log the same way. The pod gets no API access.
15. **The matcher** is reached over plain HTTP inside the cluster. A NetworkPolicy lets only the manager pods in, and it holds no secrets.
16. **KEV status comes from Grype's JSON output** when the pinned Grype version provides it. Otherwise the matcher reads CISA's KEV feed once a day, through the proxy.
17. **Evidence and sheets that no digest refers to** are deleted after a 24-hour grace. The grace lives in memory, so a restart starts it again; that errs towards keeping them.
18. **Rescans and retries.**
    - A digest is scanned again when the configured scanner image changes.
    - A failed scan is retried after 1 hour, doubling up to 24 hours.
    - `NotPullable`, an image ID, is never retried.
19. **e2e stays on Ginkgo in 2a.** Chainsaw stays a separate, later decision.

## Global Constraints

- **Phase 1 still binds.** Its Global Constraints still hold, as amended by its "As built" section: names, API conventions, kube-api-linter, RBAC from markers, wiring through `setup.Register`, tests and commits. The groups stay `config` and `inventory`; `triage` arrives in 2b.
- **One door (0004, 0023).** Only the stores in `internal/inventory` read, write or watch `ImageInventory`, `ImagePackages` and `ImageVerdicts`. The measurement tool reads them through those stores too.
- **Role separation (0021).**
  - **Hub packages** (`internal/controller/hub`, `internal/rules`, `internal/matchapi`) never import **spoke packages** (`internal/controller/scan`, `internal/controller/inventory`, `internal/scan/analyze`, `internal/scan/pull`), and the reverse holds too.
  - They share `internal/inventory`, `internal/scan/result`, `internal/tasks` and the API types.
  - `internal/setup` wires both roles.
- **Verdicts (0025, 0026).**
  - A finding is a CVE in one package of one platform manifest.
  - A rule's "not affected" covers that package only.
  - Anything short of a rule's full evidence is `NeedsAssessment`. A false "not affected" is the worst possible error.
- **Scan pods (0022):**
  - `automountServiceAccountToken: false` and `enableServiceLinks: false`
  - user 65532, a read-only root filesystem, no privilege escalation, all capabilities dropped, and the `RuntimeDefault` seccomp profile
  - memory limit, scratch size and deadline from the `scanner` Collector, and at most `maxConcurrentScans` running at once
  - the credentials for the one image in a Secret owned by the Job
- **Pull secrets** are read with `get` only, through the uncached `APIReader`, and only to build a scan Job's credentials. They never appear in logs, status, events, metrics, errors or the scan result.
- **Syft and Grype** are the upstream release binaries. Each is pinned to its latest stable release, by version and SHA-256 for each architecture, when its task is built.
- **Outbound HTTP** honours `HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY`. Scan Jobs get the manager's values.
- **Size limits:**
  - `inventory.MaxEvidenceBytes = 786432`
  - at most 2048 findings per sheet
  - `MaxItems=16` platforms per digest
- **Metrics** start with `vexplain_` and carry the label `cluster`, the effective cluster name.
- **Testing** happens only on a local kind cluster with its own kubeconfig (AGENTS.md). No test or tool touches any other cluster.
- **Repository hygiene (AGENTS.md):**
  - Nothing from the owner's export enters the repository.
  - Public Docker Hub images may appear as ordinary test images, with nothing saying where they came from.
  - The business-case CVE ID `CVE-2026-111497` may appear in tests (owner, 2026-10-30).

## Review Focus

1. **Hostile or broken image content.** This covers tar entries with `..`, absolute paths, symlinks or hard links that point out of the root, device files, huge files, and an image bigger than the scratch volume.
   - Unpacking must stay inside the work directory and skip devices.
   - It must stop with `TooLarge`, and the Job must never die without a result or error line.
   - Tests in Task 6.
2. **Registry credentials.** The cases:
   - pull secrets on the pod
   - pull secrets on its service account
   - a Secret the pod names but that doesn't exist
   - an anonymous public image
   - a 401

   A failure ends with a fixed reason (`Unauthorized`). The credentials never appear outside the Job's Secret, and that Secret is owned by the Job. Tests in Task 8.
3. **Multi-arch images.** An index can hold `linux/amd64`, `linux/arm64/v8` and an attestation manifest (`unknown/unknown`).
   - Only the nodes' platforms are scanned, and attestations are skipped.
   - A single-manifest image works too.
   - Tests in Task 6.
4. **The matcher is down, slow or not ready, or its database changes mid-round.**
   - No sheet is ever written from a failed match, and no sheet flips to empty.
   - A database change re-matches only sheets with an older version.
   - Tests in Tasks 7 and 10.
5. **Digests change under a scan:**
   - **A digest disappears mid-scan.** Facts never create an `ImageInventory`, so its result is dropped.
   - **Two digests share a manifest.** The janitor keeps evidence that one of them still refers to.
   - **An image ID can't be pulled.** It gets `NotPullable` without a Job.
   - Tests in Tasks 4, 8 and 10.

---

## File Structure

```
vexplain/
├── api/config/v1alpha1/
│   ├── collector_types.go       + Scanner type and ScannerCollectorSpec
│   └── operatorconfig_types.go  + Rules (minCompletenessPercent)
├── api/inventory/v1alpha1/
│   ├── imageinventory_types.go  + ImageFacts in status
│   ├── imagepackages_types.go   new: write-once evidence per platform manifest (0023)
│   └── imageverdicts_types.go   new: the result sheet per platform manifest (0025)
├── internal/tasks/tasks.go      the hub's way to ask a spoke for work (Executor, ScanRequest)
├── internal/scan/
│   ├── result/                  the scan result format: types, codec, log line (stdlib only)
│   ├── analyze/                 scanner only: ownership, ELF linkage, names, preload
│   └── pull/                    scanner only: resolve platforms, pull, unpack safely
├── internal/inventory/
│   ├── crdstore.go              + merging status writes, SetFacts, ManifestReferences
│   ├── packages.go              new: PackagesStore (write-once, compressed)
│   └── verdicts.go              new: VerdictsStore (writes on change)
├── internal/matchapi/           the matcher's wire types and client (hub side)
├── internal/matcher/            matcher only: HTTP server around the Grype CLI, database, KEV
├── internal/controller/scan/    spoke: queue, runner, Jobs, credentials, logs
├── internal/rules/              hub: Evaluate, sheet ordering and cap
├── internal/controller/hub/     hub: scheduler, verdicts, database poller, janitor
├── cmd/scanner/main.go, Dockerfile.scanner
├── cmd/matcher/main.go, Dockerfile.matcher
├── config/matcher/              Deployment, Service, NetworkPolicy
├── test/e2e/                    + local registry, scan specs, planted images
├── hack/measure-2a/             the Brotli measurement: cases, planted images, tool
└── docs/measurements/2026-phase2a.md
```

---

### Task 1: Phase 1 gaps due at the start of phase 2

**Files:**
- Modify:
  - `internal/scope/matcher.go`
  - `internal/controller/config/operatorconfig_controller.go`
  - `internal/controller/config/collector_controller.go`
  - `internal/workloads/digest.go`
  - `config/samples/kustomization.yaml`
- Test: their existing test files

**Interfaces:**
- Produces:
  - `workloads.TaskLabel = "vexplain.bedag.ch/task"`. A pod with this label is a task pod of the operator, and `IndexPodDigests` returns no digests for it.
  - `scope.New` rejects an empty exclude selector.

- [ ] **Step 1: Write the failing tests**
  - `TestNewRejectsAnEmptyExclude`: `scope.New` with `ExcludeNamespaces: &metav1.LabelSelector{}` returns an error that contains `excludeNamespaces`, and the same goes for `ExcludePods`. A nil exclude still means "exclude nothing".
  - **OperatorConfig controller:** the scope is validated through `scope.New`.
    - An empty exclude gives `Ready=False`, with the existing reason for an invalid scope and `scope.New`'s error as the message. This is a fake-client spec, because CEL keeps the case out of envtest.
    - So does an unparsable selector.
  - **Collector controller (fake-client spec):** `lastSuccessTime` survives a restart of the operator.
    - A Collector has `status.lastSuccessTime = T`, and the registry has no report: after a reconcile, it is still `T`.
    - After `ReportSuccess`, it is the new time.
  - `TestIndexPodDigestsSkipsTaskPods`: a running pod with `vexplain.bedag.ch/task: scan` and a valid `imageID` gives `nil`.
- [ ] **Step 2: Run them and see them fail**, with `go test ./internal/scope/ ./internal/workloads/` and `make test`.
- [ ] **Step 3: Implement**
  - `scope.New`: refuse a non-nil exclude selector without terms.
  - The OperatorConfig controller: validate through `scope.New` and drop its own selector checks.
  - The Collector controller: keep the stored `lastSuccessTime` while the registry has no success.
  - `IndexPodDigests`: return `nil` for task pods.
  - `config/samples/kustomization.yaml`: drop the ImageInventory sample, and keep the file as documentation.
- [ ] **Step 4: Verify**
  - `make manifests generate && make lint && make test` passes.
  - `bin/kustomize build config/samples` lists the four remaining objects.
- [ ] **Step 5: Commit**: `fix: close the phase 1 gaps due at the start of phase 2`

### Task 2: API types for phase 2a

**Files:**
- Modify:
  - `api/config/v1alpha1/collector_types.go` and `operatorconfig_types.go`
  - `api/inventory/v1alpha1/imageinventory_types.go`
  - `internal/collector/defaults.go`
  - `internal/settings/effective.go`
  - `config/samples/kustomization.yaml`
- Create:
  - `api/inventory/v1alpha1/imagepackages_types.go` and `imageverdicts_types.go`
  - `config/samples/config_v1alpha1_collector_scanner.yaml`
- Generated: the CRDs and the deepcopy code
- Test:
  - CRD specs in both envtest suites
  - `internal/collector`
  - `internal/settings`

**Interfaces:**
- Produces: the types below, plus:
  - `settings.Effective.Rules settings.Rules`, where `type Rules struct{ MinCompletenessPercent int32 }`. It is 90 when `spec.rules` or its field is unset.
  - `collector.EnsureDefaults` also creates the Collector `scanner` (type `Scanner`, `scanner: {}`).

**`config` group:**
```go
// +kubebuilder:validation:Enum=Workloads;Scanner
type CollectorType string
const CollectorTypeScanner CollectorType = "Scanner"

// ScannerCollectorSpec holds the settings of the built-in Scanner: how its scan Jobs run.
type ScannerCollectorSpec struct {
	// maxConcurrentScans is how many scan Jobs may run at once.
	// +optional
	// +kubebuilder:default=2
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=32
	MaxConcurrentScans *int32 `json:"maxConcurrentScans,omitempty"`
	// scanTimeoutSeconds is how long a scan Job may run before it is stopped.
	// +optional
	// +kubebuilder:default=1800
	// +kubebuilder:validation:Minimum=60
	// +kubebuilder:validation:Maximum=21600
	ScanTimeoutSeconds *int32 `json:"scanTimeoutSeconds,omitempty"`
	// memoryLimitMebibytes is the memory limit of a scan Job's container.
	// +optional
	// +kubebuilder:default=2048
	// +kubebuilder:validation:Minimum=256
	// +kubebuilder:validation:Maximum=65536
	MemoryLimitMebibytes *int32 `json:"memoryLimitMebibytes,omitempty"`
	// workspaceMebibytes is the size of the scratch volume an image is unpacked into, and so the
	// largest unpacked image a scan accepts.
	// +optional
	// +kubebuilder:default=10240
	// +kubebuilder:validation:Minimum=1024
	// +kubebuilder:validation:Maximum=1048576
	WorkspaceMebibytes *int32 `json:"workspaceMebibytes,omitempty"`
}
// CollectorSpec gains `Scanner *ScannerCollectorSpec json:"scanner,omitempty"` (+optional), and its
// CEL rule gains: has(self.scanner) == (self.type == 'Scanner').

// Rules holds the settings of the hub's rules.
type Rules struct {
	// minCompletenessPercent is the share of an image's ELF files that packages must account for
	// before any rule may settle a finding in it as not affected (design 6.5, the guard).
	// +optional
	// +kubebuilder:default=90
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=100
	MinCompletenessPercent *int32 `json:"minCompletenessPercent,omitempty"`
}
// OperatorConfigSpec gains `Rules *Rules json:"rules,omitempty"` (+optional).
```

**`inventory` group: facts on `ImageInventory`.** Every string gets a `MaxLength`, and every digest the `^sha256:[a-f0-9]{64}$` pattern:
```go
// ScanFailureReason says why the last scan of a digest failed. Open enum; more values may follow.
// +kubebuilder:validation:Enum=NotPullable;PullFailed;Unauthorized;NotFound;NoMatchingPlatform;TooLarge;CatalogFailed;TimedOut;Internal
type ScanFailureReason string

type PlatformFacts struct {
	Platform            string // os/architecture[/variant]; Pattern `^[a-z0-9]+/[a-z0-9_]+(/[a-z0-9]+)?$`
	ManifestDigest      string // its evidence: ImagePackages; its findings: ImageVerdicts
	CompletenessPercent *int32 // 0–100, rounded down
	ELFFiles            *int32 // json "elfFiles"
	Packages            *int32
}
type ScanFailure struct {
	Reason   ScanFailureReason
	Time     *metav1.Time
	Attempts *int32 // failed scans in a row, ≥ 1
}
type ImageFacts struct {
	ScannerImage string          // of the last successful scan, MaxLength 512, optional
	ScannedTime  *metav1.Time    // when the last successful scan finished, optional
	Platforms    []PlatformFacts // +listType=map +listMapKey=platform, MaxItems=16
	Failure      *ScanFailure    // the last failure since the last success; empty after a success
}
// ImageInventoryStatus gains `Facts *ImageFacts json:"facts,omitempty"`. The scanning spoke writes it.
// Print columns: Scanned (.status.facts.scannedTime, date), Failure (.status.facts.failure.reason).
```

**`ImagePackages`** (new, cluster-scoped, no status):
```go
// +kubebuilder:validation:Enum=GzipJSON
type EvidenceEncoding string
const EvidenceEncodingGzipJSON EvidenceEncoding = "GzipJSON"

// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="ImagePackages are written once; replace one by deleting and creating it"
type ImagePackagesSpec struct {
	ManifestDigest    string           // the platform manifest that was scanned
	Platform          string           // same pattern as PlatformFacts.Platform
	ScannerImage      string           // MinLength 1, MaxLength 512
	ScannedTime       *metav1.Time
	Encoding          EvidenceEncoding
	Evidence          []byte           // gzip JSON of result.Manifest; MaxLength 1048576 (as base64)
	UncompressedBytes *int64           // ≥ 0
}
// Root type: spec only. Name rule as for ImageInventory:
// self.metadata.name == self.spec.manifestDigest.replace(':', '-').
// Print columns: Platform, Scanned, Age.
```

**`ImageVerdicts`** (new, cluster-scoped):
```go
// Open enums; more values may follow.
// +kubebuilder:validation:Enum=Suppressed;Tracked;NeedsAssessment
type Outcome string
// +kubebuilder:validation:Enum=KnownExploited;CompletenessGuard;RemovedInLaterLayer;LoadCheck
type Rule string
// +kubebuilder:validation:Enum=ComponentNotPresent;VulnerableCodeNotInExecutePath
type Justification string
// +kubebuilder:validation:Enum=NoPreloadEnvironment
type FindingCondition string
// +kubebuilder:validation:Enum=Critical;High;Medium;Low;Negligible;Unknown
type Severity string
// +kubebuilder:validation:Enum=Fixed;NotFixed;WontFix;Unknown
type FixState string

type PackageReference struct {
	ID      string // the package's ID in the evidence; MaxLength 64
	Name    string // MaxLength 253
	Version string // MaxLength 128
	Type    string // apk, deb, rpm, go-module, npm, …; MaxLength 32
}
// +kubebuilder:validation:XValidation:rule="has(self.justification) == (self.outcome == 'Suppressed')",message="justification is set exactly for a suppressed finding"
type Finding struct {
	VulnerabilityID string             // MaxLength 64
	Package         PackageReference
	Outcome         Outcome
	Rule            Rule               // optional: the rule that decided, or blocked a suppression
	Justification   Justification      // optional; OpenVEX's label, in CamelCase
	Conditions      []FindingCondition // optional, +listType=set, MaxItems=4
	Reason          string             // optional, MaxLength 256, e.g. "reached by /usr/bin/curl"
	Severity        Severity
	FixState        FixState
	FixedVersions   []string           // optional, +listType=atomic, MaxItems=8, items MaxLength 128
}
type FindingCounts struct{ Suppressed, Tracked, NeedsAssessment *int32 }
type ImageVerdictsSpec struct {
	ManifestDigest string // immutable (CEL self == oldSelf)
}
type ImageVerdictsStatus struct {
	DatabaseVersion string         // optional, MaxLength 128
	ScannerImage    string         // optional, MaxLength 512
	Findings        []Finding      // optional, +listType=atomic, MaxItems=2048
	OmittedFindings *int32         // optional, ≥ 0
	Counts          *FindingCounts // optional
}
// Root type with status subresource. Name rule as for ImagePackages.
// Print columns: Suppressed, Tracked, NeedsAssessment (the counts), Database, Age.
```
- Follow kube-api-linter for marker spelling, pointers and doc comments. Every field gets a doc comment starting with its JSON name, as in phase 1.

- [ ] **Step 1: Write the failing tests**
  - **Envtest, config suite:**
    - A `scanner` Collector with `scanner: {}` gets the four defaults (2, 1800, 2048, 10240).
    - `type: Scanner` without `scanner`, or `workloads` with `type: Scanner`, is rejected.
    - `minCompletenessPercent: 101` is rejected.
  - **Envtest, inventory suite:**
    - Updating an `ImagePackages` spec is rejected with the message above.
    - A name other than the digest is rejected.
    - A `Suppressed` finding without a justification is rejected, and so is a `NeedsAssessment` finding with one.
    - `ImageInventory` takes `status.facts` through the status subresource.
  - `TestEnsureDefaultsCreatesWorkloadsAndScanner`.
  - `TestLoadDefaultsRules` (nil `rules` → 90) and `TestLoadReadsRules` (55 → 55).
- [ ] **Step 2: Run them and see them fail.**
- [ ] **Step 3: Implement the types, the defaults and `settings.Rules`**, and add the scanner sample to the samples kustomization.
- [ ] **Step 4: Verify** with `make manifests generate && make lint && make test`.
- [ ] **Step 5: Commit**: `feat(api): Scanner collector, scan facts, ImagePackages and ImageVerdicts`

### Task 3: The scan result format

**Files:**
- Create:
  - `internal/scan/result/result.go`
  - `internal/scan/result/codec.go`
  - `internal/scan/result/result_test.go`

**Interfaces:**
- Produces (standard library only, so both the scanner and the operator import it):
```go
const SchemaVersion = 1
const ResultPrefix = "vexplain-scan-result v1 "
const ErrorPrefix = "vexplain-scan-error v1 "

type Result struct {
	SchemaVersion int        `json:"schemaVersion"`
	Image         string     `json:"image"` // repository@digest that was scanned
	Manifests     []Manifest `json:"manifests"`
}
type Manifest struct {
	Platform  string          `json:"platform"` // os/architecture[/variant]
	Digest    string          `json:"digest"`   // the platform manifest digest
	SBOM      json.RawMessage `json:"sbom"`     // Syft JSON without file lists (Task 5)
	Packages  []PackageFacts  `json:"packages"`
	ELF       ELFSummary      `json:"elf"`
	Libraries []Library       `json:"libraries"`
	Preload   Preload         `json:"preload"`
}
type PackageFacts struct {
	ID              string `json:"id"`              // the package's ID in SBOM
	FilesListed     int    `json:"filesListed"`     // files its package database lists
	FilesPresent    int    `json:"filesPresent"`    // of those, present in the final filesystem
	SharedLibraries int    `json:"sharedLibraries"` // owned ELF files with a soname
	OtherELFFiles   int    `json:"otherElfFiles"`   // owned ELF files without one (executables, plugins)
}
type ELFSummary struct {
	Total   int      `json:"total"`
	Owned   int      `json:"owned"`
	Unowned []string `json:"unowned,omitempty"` // the first 100 paths, sorted
}
type Library struct {
	Path         string   `json:"path"`
	Soname       string   `json:"soname"`
	PackageID    string   `json:"packageId,omitempty"` // the owning package; empty when none
	ReachedBy    []string `json:"reachedBy,omitempty"` // the first 20, sorted
	ReachedCount int      `json:"reachedCount"`
	NameHits     []string `json:"nameHits,omitempty"`  // the first 20, sorted
	NameHitCount int      `json:"nameHitCount"`
}
type Preload struct {
	LDPreload      bool `json:"ldPreload"`      // the image configuration sets LD_PRELOAD
	LDAudit        bool `json:"ldAudit"`        // … LD_AUDIT
	EtcLdSoPreload bool `json:"etcLdSoPreload"` // /etc/ld.so.preload exists and isn't empty
}
type ErrorReason string // the ScanFailureReason values of Task 2, except NotPullable and TimedOut

func (m Manifest) Completeness() int32 // floor(100·Owned/Total); 100 when Total is 0
func Encode(r Result) (string, error)  // ResultPrefix + base64(gzip(json))
func EncodeError(reason ErrorReason) string
// Parse finds the one result or error line in a scan pod's log. Exactly one of the result and
// the reason is set when err is nil. More than maxBytes of decompressed JSON is an error.
func Parse(log string, maxBytes int64) (*Result, ErrorReason, error)
// EncodeManifest returns the gzip JSON of one manifest and its uncompressed size, for ImagePackages.
func EncodeManifest(m Manifest) ([]byte, int64, error)
func DecodeManifest(b []byte, maxBytes int64) (Manifest, error)
```

- [ ] **Step 1: Write the failing tests**
  - Round trips of `Encode`/`Parse` and `EncodeManifest`/`DecodeManifest`.
  - `Parse` finds the result line among stderr-like noise.
  - `Parse` returns the reason of an error line.
  - `Parse` fails on:
    - no line
    - two lines
    - an unknown version prefix
    - bad base64
    - a gzip bomb over `maxBytes`. That error never quotes the input.
  - `Completeness` is 100 for zero ELF files, 75 for 3 of 4, and 66 for 2 of 3.
- [ ] **Step 2: Run them and see them fail.**
- [ ] **Step 3: Implement.** Decoding reads through `io.LimitReader(gzipReader, maxBytes+1)`.
- [ ] **Step 4: Verify** with `go test ./internal/scan/result/` and `make lint`.
- [ ] **Step 5: Commit**: `feat(scan): the scan result format`

### Task 4: The inventory stores

**Files:**
- Modify:
  - `internal/inventory/store.go`
  - `internal/inventory/crdstore.go`
  - `internal/metrics/metrics.go`
- Create:
  - `internal/inventory/packages.go`
  - `internal/inventory/verdicts.go`
  - their tests

**Interfaces:**
- Consumes:
  - the types of Task 2
  - `result.Manifest`, `result.EncodeManifest` and `result.DecodeManifest` (Task 3)
- Produces:
```go
// Store gains:
	// SetFacts replaces the facts of an existing object. It never creates one: when the digest
	// has no object it returns false and writes nothing. It writes nothing when nothing changes.
	SetFacts(ctx context.Context, digest string, facts *inventoryv1alpha1.ImageFacts) (bool, error)
	// ManifestReferences returns the reported digests whose facts name the platform manifest.
	ManifestReferences(ctx context.Context, manifestDigest string) ([]string, error)

const MaxEvidenceBytes = 786432
var ErrEvidenceTooLarge = errors.New("the scan evidence is too large to store")

type PackagesInfo struct {
	Platform, ScannerImage               string
	ScannedTime                          time.Time
	CompressedBytes, UncompressedBytes   int64
}
type PackagesStore interface {
	Get(ctx context.Context, manifestDigest string) (*result.Manifest, *PackagesInfo, error) // nil, nil, nil if absent
	// Put stores one manifest's evidence. It creates the object, does nothing when an object from
	// the same scanner image exists, and replaces (delete, then create) one from another image.
	// Compressed evidence over MaxEvidenceBytes returns ErrEvidenceTooLarge and writes nothing.
	Put(ctx context.Context, scannerImage string, scannedTime time.Time, m result.Manifest) error
	Delete(ctx context.Context, manifestDigest string) error // no error if absent
	Digests(ctx context.Context) ([]string, error)
	Source() source.Source // one request per created or deleted object, named NameForDigest(manifest digest)
}
func NewCRDPackagesStore(c client.Client, informers cache.Cache) PackagesStore

type VerdictsStore interface {
	Get(ctx context.Context, manifestDigest string) (*inventoryv1alpha1.ImageVerdicts, error)
	// Put creates the sheet if needed, and writes its status only when it differs from the stored one.
	Put(ctx context.Context, manifestDigest string, status inventoryv1alpha1.ImageVerdictsStatus) error
	Delete(ctx context.Context, manifestDigest string) error
}
func NewCRDVerdictsStore(c client.Client) VerdictsStore
```
- New metrics, measured like phase 1's `measure` (the length of the JSON of the object as written):
  - `vexplain_packages_object_bytes{cluster}`: histogram, buckets `prometheus.ExponentialBuckets(1024, 2, 12)`
  - `vexplain_verdicts_object_bytes{cluster}`: the same buckets
  - `vexplain_packages_writes_total{cluster,op}` and `vexplain_verdicts_writes_total{cluster,op}`, with op `create|update|delete`

- [ ] **Step 1: Write the failing tests.** These are fake-client specs, using controller-runtime's interceptors to inject errors.
  - **Phase 1 carry-ins:**
    - `Observe` keeps `status.facts`, and every other status field it doesn't own: `withEntry` starts from `current.DeepCopy()`.
    - `Observe` keeps a known `DigestKind` when the observation has none.
    - `Observe` retries when the object is deleted between its read and its status write. On `NotFound`, it creates the object again on the next round.
    - `Forget` returns nil when its status write meets `NotFound`.
  - **`SetFacts`:**
    - It never creates: an absent digest gives `(false, nil)`, and no object appears.
    - It keeps `clusters`.
    - The same facts twice give one write. Assert the delta of the write counter.
    - It retries on a conflict.
  - **`ManifestReferences`:** two digests whose facts name the same manifest are both returned. When the informers are not nil, the method uses a field index; when they are nil, it lists.
  - **`PackagesStore`:**
    - `Put` creates the object with `GzipJSON`, sizes and time.
    - `Put` again with the same image doesn't write.
    - `Put` with another image replaces the object, so `Get` shows the new image.
    - `Put` with evidence over the limit returns `ErrEvidenceTooLarge` and writes nothing.
    - `Get` decodes the evidence. An absent object gives `nil, nil, nil`.
    - `Delete` of an absent object is fine.
  - **`VerdictsStore`:** `Put` creates the object and writes the status. An unchanged status writes nothing, and a change writes once.
  - The size histograms are observed on writes.
- [ ] **Step 2: Run them and see them fail.**
- [ ] **Step 3: Implement**
  - `isRaced` stays for `Observe`, which additionally treats `NotFound` on its status write as raced.
  - `SetFacts` updates only `status.facts`, through `retry.RetryOnConflict`.
  - Name every object with `NameForDigest`.
  - Add the RBAC markers for the new kinds next to their stores:
    - `imagepackages`: create, delete, get, list, watch
    - `imageverdicts`: create, delete, get, list, watch
    - `imageverdicts/status`: update
- [ ] **Step 4: Verify** with `make manifests generate && make lint && make test`.
- [ ] **Step 5: Commit**: `feat(inventory): scan facts, write-once evidence and verdict sheets behind their stores`

### Task 5: Evidence analysis

**Files:**
- Create: `internal/scan/analyze/`
  - `analyze.go`
  - `syft.go`, which parses and reduces Syft JSON
  - `elf.go`
  - `reach.go`
  - `names.go`
  - `analyze_test.go`
  - `testdata/`:
    - small ELF fixtures
    - `gen.sh`, which builds those fixtures with gcc in a container
    - Syft JSON fixtures

**Interfaces:**
- Consumes: the `result` types (Task 3)
- Produces:
  - `analyze.Analyze(rootfs string, syftJSON []byte, imageEnv []string) (result.Manifest, error)`. It fills everything except `Platform` and `Digest`, which the caller sets.
  - It is scanner-only code. The manager never imports it.

**Rules the code follows:**
- **Ownership.**
  - A file is owned when it appears in an OS package's file list in the Syft metadata (`files[].path` for dpkg, apk and rpm), or among the `locations` of any Syft package, such as a Go binary or a JAR.
  - Symlinks in a file list count as owned, but they are never scanned for content.
- **ELF files** are the regular files that start with `\x7fELF` and that `debug/elf` parses. A file it can't parse doesn't count as ELF.
  - A shared library is one with `DT_SONAME`.
  - `PackageFacts.SharedLibraries` and `OtherELFFiles` count them per owning package.
- **Reach** (decision 7):
  - Map every soname, and every library's file name, to its files.
  - Walk `DT_NEEDED` backwards from each library.
  - `ReachedBy` holds the ELF files, outside the library's own package, from which it can be reached. They are sorted, and only the first 20 are kept.
- **Names** (0026, decision 8).
  - A soname like `libbrotlidec.so.1` gives three names:
    - itself
    - `libbrotlidec.so`
    - `brotlidec`, with boundaries
  - One pass over every regular file finds them all, with `github.com/petar-dambovaliev/aho-corasick`.
  - Hits don't count in:
    - the owning package's files
    - `/var/lib/dpkg/**`, `/lib/apk/db/**`, `/var/lib/rpm/**` and `/usr/lib/sysimage/rpm/**`
    - `/etc/ld.so.cache`
- **Files present.** For each OS package, compare its listed files with the filesystem. A symlink counts as present.
- **Preload:**
  - `imageEnv` entries named `LD_PRELOAD` or `LD_AUDIT` set the flags. Split at the first `=`, and keep no value.
  - A non-empty `/etc/ld.so.preload` sets `EtcLdSoPreload`.
- **The reduced SBOM** is Syft's JSON without `files` lists in package metadata, and without `artifactRelationships` and `files`. It keeps every other field, including `source`/`sourceVersion` and `originPackage`, which Grype matches on.
- **Go build info** needs nothing extra. Syft's Go cataloger reports each Go binary's modules as packages, and Grype matches them at module level (0027).

- [ ] **Step 1: Write the failing tests.** Each test builds a root filesystem in `t.TempDir()` from the fixtures.
  - **The fixtures:**
    - `/usr/lib/libbrotlicommon.so.1.0.9` (soname `libbrotlicommon.so.1`)
    - `/usr/lib/libbrotlidec.so.1.0.9` (soname `libbrotlidec.so.1`, which needs `libbrotlicommon.so.1`)
    - the symlinks to both
    - `/usr/bin/user`, which needs `libbrotlidec.so.1`
    - `/usr/bin/other`
    - `/app/load.py`, which contains `ctypes.util.find_library("brotlidec")`
    - `/lib/apk/db/installed` and `/etc/ld.so.cache`, both of which contain the names
  - **The tests:**
    - `TestOwnershipFromPackageFileLists`: the libraries are owned by `brotli-libs`, and `/usr/bin/user` isn't owned. Check `ELF.Total` and `ELF.Owned`.
    - `TestReachThroughDTNeeded`: `libbrotlidec` is reached by `/usr/bin/user`. So is `libbrotlicommon`, through it. `libbrotlidec` itself doesn't count, because it's the same package.
    - `TestNamesOfASoname`: gives the three names above.
    - `TestNameHitsSkipOwnFilesPackageDatabasesAndLinkerCache`: the only hit is `/app/load.py`.
    - `TestBareNameNeedsBoundaries`: `xbrotlidecx` isn't a hit, but `"brotlidec"` is. A plain `libbrotlidec.so` substring is a hit.
    - `TestFilesPresentPerPackage`: 3 files listed, 1 present.
    - `TestPreloadFromImageEnvAndEtc`: the value `/x` of `LD_PRELOAD=/x` appears nowhere in the encoded result.
    - `TestReducedSBOMKeepsMatchingFieldsAndDropsFileLists`.
    - `TestListsAreCappedAndCounted`: 25 reaching binaries give 20 paths and a count of 25.
    - `TestSymlinksAreNeverReadForContent`: a symlink to a file outside the root is neither followed nor read.
- [ ] **Step 2: Run them and see them fail.**
- [ ] **Step 3: Implement** `Analyze`.
- [ ] **Step 4: Verify** with `go test ./internal/scan/analyze/` and `make lint`.
- [ ] **Step 5: Commit**: `feat(scan): analyse ownership, linkage, library names and preload in an unpacked image`

### Task 6: The scanner

**Files:**
- Create:
  - `internal/scan/pull/resolve.go`, `extract.go` and their tests
  - `cmd/scanner/main.go` and `main_test.go`
  - `Dockerfile.scanner`

**Interfaces:**
- Consumes: `analyze.Analyze` (Task 5), and `result.Encode` and `EncodeError` (Task 3)
- Produces:
```go
package pull
type Target struct {
	Platform string   // os/architecture[/variant]
	Digest   string   // the platform manifest digest
	Image    v1.Image
}
var ErrNoMatchingPlatform, ErrTooLarge error
// Resolve returns what to scan of ref. For an index, it returns the entries whose platform matches
// one of platforms: os and architecture always, and the variant when the request gives one. It
// skips unknown/unknown (attestations). For a single manifest, it returns that manifest with the
// platform of its config.
func Resolve(ctx context.Context, ref name.Digest, platforms []string, opts ...remote.Option) ([]Target, error)
// Extract unpacks img's flattened filesystem into dir. It keeps every path inside dir and doesn't
// follow symlinks. It skips devices and FIFOs, turns hard links into copies, gives files and
// directories modes a non-root user can read, and stops with ErrTooLarge after maxBytes.
func Extract(img v1.Image, dir string, maxBytes int64) error
```
- **`cmd/scanner`** (`run(ctx, args, getenv, stdout, stderr) int`, testable like `cmd/llm-smoke`):
  - **Flags:**
    - `--image repo@sha256:…`
    - `--platform` (repeatable)
    - `--work /work`
    - `--max-bytes`
    - `--syft /usr/local/bin/syft`
  - **Credentials** come from `authn.DefaultKeychain`, which reads `$DOCKER_CONFIG/config.json`.
  - **For each target:**
    1. Extract the filesystem.
    2. Run `syft scan dir:<root> -o syft-json=<file> --quiet` with `SYFT_CHECK_FOR_APP_UPDATE=false`.
    3. Run `analyze.Analyze` with the image config's `Env`.
    4. Remove the unpacked filesystem.
  - **Output:**
    - On success, one result line to stdout, then exit 0.
    - On failure, one error line, then exit 1.
    - Progress goes to stderr.
    - No line ever contains credentials or an error's text.
  - **Error reasons:**
    - 401 or 403 → `Unauthorized`
    - 404 → `NotFound`
    - any other pull error → `PullFailed`
    - `ErrNoMatchingPlatform` → `NoMatchingPlatform`
    - `ErrTooLarge` → `TooLarge`
    - Syft failing → `CatalogFailed`
    - anything else → `Internal`
- **`Dockerfile.scanner`:**
  - Build `/scanner` with `CGO_ENABLED=0`.
  - Download the pinned Syft release for `TARGETARCH`, and verify its SHA-256 (build args `SYFT_VERSION`, `SYFT_SHA256_AMD64`, `SYFT_SHA256_ARM64`).
  - The final stage is `gcr.io/distroless/static:nonroot`, with `/usr/local/bin/syft` and `/scanner`, and `ENTRYPOINT ["/scanner"]`.

- [ ] **Step 1: Write the failing tests,** against go-containerregistry's in-process `pkg/registry`.
  - **Platforms:** an index with `linux/amd64`, `linux/arm64/v8` and `unknown/unknown`:
    - `linux/amd64` gives one target.
    - `linux/arm64` matches `arm64/v8`.
    - `linux/s390x` gives `ErrNoMatchingPlatform`.
    - A single manifest gives its config's platform.
  - **Authentication:** a registry behind basic auth works with a `DOCKER_CONFIG` holding the right credentials, and gives `Unauthorized` with wrong ones.
  - **Unpacking:** layers holding `../escape`, `/abs/path`, a symlink to `/etc/passwd`, a hard link to `../x`, a character device, a file over the limit, and a whiteout give:
    - nothing outside `dir`
    - the symlink kept and not followed
    - the hard link outside refused
    - the device skipped
    - `ErrTooLarge`
    - the whiteout applied
  - **`run`**, with a fake Syft script passed through `--syft`:
    - It prints exactly one result line and exits 0.
    - A pull failure prints an error line and exits 1.
    - A marker string in the credentials file appears in neither stdout nor stderr.
- [ ] **Step 2: Run them and see them fail.**
- [ ] **Step 3: Implement** `Resolve`, `Extract`, `run` and the Dockerfile.
- [ ] **Step 4: Verify**
  - `go test ./internal/scan/pull/ ./cmd/scanner/` and `make lint` pass.
  - `docker build -f Dockerfile.scanner -t scanner:dev .` succeeds.
  - `docker run --rm scanner:dev --image docker.io/library/alpine@sha256:<digest> --platform linux/amd64` prints a result line. The implementer pins the digest when building this task.
- [ ] **Step 5: Commit**: `feat(scan): the scanner image`

### Task 7: The matcher

**Files:**
- Create:
  - `internal/matchapi/api.go`, `client.go` and their tests
  - `internal/matcher/grype.go`, `server.go`, `kev.go` (only if needed, decision 16), their tests, and `testdata/grype-output.json`
  - `cmd/matcher/main.go`
  - `Dockerfile.matcher`

**Interfaces:**
- Produces:
```go
package matchapi // hub side; the manager imports only this
type Match struct {
	VulnerabilityID string   `json:"vulnerabilityId"`
	PackageID       string   `json:"packageId"`      // the SBOM's package ID, as Grype reports it
	Severity        string   `json:"severity"`       // Grype's: Critical, High, Medium, Low, Negligible, Unknown
	FixState        string   `json:"fixState"`       // Grype's: fixed, not-fixed, wont-fix, unknown
	FixedVersions   []string `json:"fixedVersions,omitempty"`
	KnownExploited  bool     `json:"knownExploited"`
}
type MatchResponse struct {
	DatabaseVersion string  `json:"databaseVersion"`
	Matches         []Match `json:"matches"`
}
type Database struct {
	Version string    `json:"version"`
	Built   time.Time `json:"built"`
}
var ErrNotReady, ErrUnavailable error // fixed texts; never a body
type Client struct {
	BaseURL string
	HTTP    *http.Client // nil means no proxy (the matcher is always in the hub's own cluster) and a 2-minute timeout
}
func (c *Client) Match(ctx context.Context, sbom json.RawMessage) (MatchResponse, error) // POST /v1/match {"sbom": …}
func (c *Client) Database(ctx context.Context) (Database, error)                       // GET /v1/database

package matcher // matcher only
type Grype interface {
	Match(ctx context.Context, sbomPath string) ([]matchapi.Match, error)
	Update(ctx context.Context) error
	Status(ctx context.Context) (matchapi.Database, error)
}
func NewGrype(binary, dbDir string) Grype // runs the CLI with GRYPE_DB_AUTO_UPDATE=false, GRYPE_CHECK_FOR_APP_UPDATE=false, GRYPE_DB_CACHE_DIR=dbDir
func NewServer(g Grype, maxConcurrent int) *Server
func (s *Server) Handler() http.Handler // /v1/match, /v1/database, /healthz, /readyz
```
- **`cmd/matcher` flags:**
  - `--listen :8080`
  - `--grype /usr/local/bin/grype`
  - `--db-dir /db`
  - `--offline`: use the database already in `--db-dir`, and never update
  - `--update-interval 6h`
  - `--max-concurrent 2`
- **Readiness.** The server answers 503 with `Retry-After: 30` until a database is loaded.
- **Updates** run `grype db update` through the proxy. After each one, `grype db status -o json` gives the version.
- **Errors.** Grype's stderr is logged at debug level only. It never enters an error or a response.
- **`Dockerfile.matcher`:**
  - Download the pinned Grype release and verify its SHA-256.
  - With `--build-arg WITH_DB=true`, run `grype db update` at build time into `/db`. That's for kind, where pods have no internet.
  - The final stage is distroless nonroot, with `ENTRYPOINT ["/matcher"]`.

- [ ] **Step 1: Capture the golden output.** Run the pinned Grype once in Docker on a small SBOM of Alpine's `brotli-libs`, and save it as `testdata/grype-output.json`. Read its field for known exploitation. If there is none, implement `kev.go` (decision 16). Either way, say which in the report.
- [ ] **Step 2: Write the failing tests**
  - **The CLI wrapper,** with a fake `grype` script that prints the golden file:
    - It parses the IDs, severity, fix state and versions, package IDs and KEV.
    - It passes the three environment variables.
    - A failing CLI gives an error without its stderr.
  - **The server:**
    - `POST /v1/match` gives 200 with the matches.
    - Before a database is loaded: 503 with `Retry-After`.
    - Bad JSON: 400.
    - A third concurrent request waits for a slot, and gives 503 when its context ends.
    - `GET /v1/database` works.
  - **The client:**
    - 503 maps to `ErrNotReady`, and a connection error to `ErrUnavailable`.
    - No error contains a response body.
  - **KEV, only if `kev.go` exists:** the feed is read from an `httptest` server, and matches on it set `KnownExploited`.
- [ ] **Step 3: Run them and see them fail.**
- [ ] **Step 4: Implement.**
- [ ] **Step 5: Verify**
  - `go test ./internal/matchapi/ ./internal/matcher/` and `make lint` pass.
  - `docker build -f Dockerfile.matcher --build-arg WITH_DB=true -t matcher:dev .` succeeds.
  - `docker run --rm -p 8080:8080 matcher:dev --offline` answers `/readyz` with 200.
- [ ] **Step 6: Commit**: `feat(matcher): one vulnerability database at the hub, behind a small HTTP API`

### Task 8: The spoke runs scans

**Files:**
- Create:
  - `internal/tasks/tasks.go`
  - `internal/controller/scan/`:
    - `queue.go`
    - `runner.go`
    - `job.go`
    - `credentials.go`
    - `logs.go`
    - `platforms.go`
    - tests, including a Ginkgo envtest suite through `testenv.Start`
- Modify: `internal/setup/setup.go`, `internal/testenv`

**Interfaces:**
- Consumes:
  - `workloads.TaskLabel` and `PodDigestIndex` (Task 1, phase 1)
  - `inventory.Store.SetFacts` and `PackagesStore` (Task 4)
  - `result.Parse` (Task 3)
  - the `scanner` Collector settings (Task 2)
- Produces:
```go
package tasks
type ScanRequest struct {
	Digest       string   // a repository digest
	Repositories []string // where it was pulled from, as the presence entries say
}
// Executor is how the hub asks a spoke for work. RequestScan returns at once; the result arrives
// through the stores. Asking again for a digest that is being scanned changes nothing.
type Executor interface {
	RequestScan(ctx context.Context, req ScanRequest) error
}

package scan // spoke
const DigestLabel = "vexplain.bedag.ch/digest" // the first 63 hex digits; the full digest is in the annotation of the same name
type Queue struct{ … }                         // the in-process Executor of HubAndSpoke
func NewQueue() *Queue
func (q *Queue) RequestScan(ctx context.Context, req tasks.ScanRequest) error
type LogReader interface {
	ScanLog(ctx context.Context, namespace, pod string) (string, error) // container "scanner", LimitBytes 8 MiB
}
type CredentialSource interface {
	// DockerConfig returns the config.json for pulling repository with pod's credentials.
	DockerConfig(ctx context.Context, pod *corev1.Pod, repository string) ([]byte, error)
}
func NewKeychainCredentials(cs kubernetes.Interface) CredentialSource // go-containerregistry pkg/authn/kubernetes
type Runner struct { … } // fields as needed; built by setup.Register
```
- `setup.Options` gains:
  - `ScannerImage string`. An empty value disables scanning, and the Scanner reports the failure "no scanner image is configured".
  - `ScanQueue *scan.Queue`
  - `ScanLogs scan.LogReader`
  - `ScanCredentials scan.CredentialSource`
  - `ProxyEnv []corev1.EnvVar`

  Nil means the production default, as with `CollectorRegistry`.

**What the runner does for a request:**
1. **Skip duplicates.** If a Job with the digest's label exists, it waits for that Job.
2. **Respect the limit.** If `maxConcurrentScans` scan Jobs are active, it requeues after 30 seconds.
3. **Find a pod and credentials.**
   - It looks up a pod that runs the digest, through the pod index.
   - It builds the credentials for its repository, using the pod's namespace, pull secrets and service account. That goes through `APIReader` with `get`.
   - With no such pod, the digest no longer runs here, so the runner drops the request.
4. **Pick the platforms** by decision 12, with `get` on Nodes.
5. **Create the Job**, with the settings of the Global Constraints, the request's digest and repository as `--image`, and one `--platform` each.
   - **Labels:** the Job and its pod template carry `vexplain.bedag.ch/task: scan` and `DigestLabel`, and the full digest in the annotation.
   - **The container** is named `scanner`.
   - **Volumes:**
     - `/work`: an `emptyDir` with `sizeLimit` = `workspaceMebibytes` Mi
     - `/creds`: the Secret
     - `/tmp`: an `emptyDir`
   - **Environment:** `DOCKER_CONFIG=/creds`, plus the proxy variables.
   - **Deadline and cleanup:** `activeDeadlineSeconds` is `scanTimeoutSeconds`, `backoffLimit` is 0, and `ttlSecondsAfterFinished` is 3600.
   - **Then the Secret.** Create the `Opaque` Secret holding `config.json`, owned by the Job as controller. It doesn't carry the LLM key label.
6. **When the scan pod succeeds:**
   1. `Parse` its log.
   2. `PackagesStore.Put` each manifest.
   3. `SetFacts` with the platforms and their counts and completeness, the scanner image, the time, and no failure.
   4. Delete the Job, propagating in the background.
   5. `ReportSuccess(Scanner)`.
7. **When the scan fails** (the pod failed, or the Job hit its deadline, which gives `TimedOut`):
   1. Read the error line if there is one. Without one, the reason is `Internal`.
   2. `SetFacts` keeps the earlier platforms and sets `failure` with `attempts + 1`.
   3. Delete the Job.
   4. `ReportFailure`.

   `ErrEvidenceTooLarge` from the store counts as a failure with reason `TooLarge`.
8. **When the digest has gone**, `SetFacts` returns false. The runner then writes nothing and deletes the Job.
- **The runner watches pods with `TaskLabel=scan`** through the existing pod informer, and reads Jobs through `APIReader`. It needs no new cache, and the metadata watch of Jobs from phase 1 stays as it is.
- **RBAC markers:**
  - **Namespaced** (`namespace=vexplain-system`), into the Role that phase 1's RoleBinding already binds:
    - `batch/jobs`: create, delete, get, list, watch
    - `secrets`: create
    - `pods/log`: get
  - **Cluster-wide:**
    - `secrets` and `serviceaccounts`: get (design 6.11)
    - `nodes`: get

- [ ] **Step 1: Write the failing tests**
  - **Envtest.** envtest runs no Job controller, so each test creates the scan pod itself and sets its phase. A fake `LogReader` returns the log.
    - **A request makes a Job and its Secret,** with every field above. That includes `automountServiceAccountToken: false`, the security context, the resources, the deadline and the arguments. The Secret is owned by the Job, and `config.json` holds the `CredentialSource`'s bytes.
    - **A second request for the same digest** makes no second Job.
    - **With `maxConcurrentScans: 1`,** two requests give one Job, and the second Job starts after the first finishes.
    - **A successful scan:**
      - Both manifests have `ImagePackages`.
      - The `ImageInventory` facts match the result.
      - The Job is gone.
      - The registry shows a success for Scanner.
    - **An error line `Unauthorized`** sets `failure.reason Unauthorized` with `attempts 1`, keeps the earlier platforms, and deletes the Job.
    - **A Job past its deadline, with no log,** gives `TimedOut`.
    - **Evidence too large** gives `TooLarge`.
    - **A digest deleted during the scan:** no `ImageInventory` comes back, and the Job is gone.
    - **A scan pod with an `imageID`** creates no `ImageInventory`.
  - **Credentials** (fake clientset):
    - pull secrets on the pod
    - pull secrets on its service account
    - both together
    - an anonymous pull, which gives `{"auths":{}}`
    - a Secret named by the pod that doesn't exist

    The bytes never appear in the captured logs.
  - **Platforms:**
    - Pods on an arm64 node give `linux/arm64`.
    - A pending pod is ignored.
    - With no scheduled pod, the platforms of all nodes are used.
- [ ] **Step 2: Run them and see them fail.**
- [ ] **Step 3: Implement**, and wire the runner and queue into `setup.Register`.
- [ ] **Step 4: Verify** with `make manifests generate && make lint && make test`. Check that the Role now holds the namespaced rules.
- [ ] **Step 5: Commit**: `feat(scan): the spoke runs scans as Jobs and stores their evidence`

### Task 9: The rules

**Files:**
- Create: `internal/rules/rules.go`, `rules_test.go`

**Interfaces:**
- Consumes: `result.Manifest` (Task 3), `matchapi.Match` (Task 7) and the Task 2 enums
- Produces:
```go
type Settings struct{ MinCompletenessPercent int32 }
// Evaluate turns one manifest's matches into findings, in the order of decision 5, each scoped to
// its package (0025). It is pure: the same input always gives the same output.
func Evaluate(ev result.Manifest, matches []matchapi.Match, s Settings) []inventoryv1alpha1.Finding
// Sheet orders findings (NeedsAssessment, then Tracked, then Suppressed; then severity from Critical
// down; then vulnerability ID; then package ID), keeps the first 2048, and counts them.
func Sheet(findings []inventoryv1alpha1.Finding) (kept []inventoryv1alpha1.Finding, omitted int32, counts inventoryv1alpha1.FindingCounts)
```
- **Mapping:**
  - Grype's severities map one to one.
  - `fixed`, `not-fixed`, `wont-fix` and `unknown` map to `Fixed`, `NotFixed`, `WontFix` and `Unknown`.
  - `Package` comes from the evidence's SBOM entry for `PackageID`, giving its name, version and type.

- [ ] **Step 1: Write the failing tests** (a table)

| Case | Input | Outcome / Rule / Justification |
|---|---|---|
| KEV wins | `KnownExploited`, the load check would pass | `Tracked` / `KnownExploited` |
| Guard | completeness 80, minimum 90, library unreached | `NeedsAssessment` / `CompletenessGuard`, reason `completeness 80% is below 90%` |
| Removed in a later layer | `FilesListed 3, FilesPresent 0` | `Suppressed` / `RemovedInLaterLayer` / `ComponentNotPresent` |
| Unreached library package | libraries only, `ReachedCount 0`, `NameHitCount 0`, no preload | `Suppressed` / `LoadCheck` / `VulnerableCodeNotInExecutePath`, conditions `[NoPreloadEnvironment]` |
| Reached | `ReachedBy ["/usr/bin/curl"]` | `NeedsAssessment` / `LoadCheck`, reason `reached by /usr/bin/curl` |
| Name hit | `NameHits ["/app/load.py"]` | `NeedsAssessment` / `LoadCheck`, reason `named in /app/load.py` |
| Preload | `LDPreload` or `LDAudit` or `EtcLdSoPreload` | `NeedsAssessment` / `LoadCheck`, reason `the image preloads libraries` |
| Owns an executable | `OtherELFFiles 1` | `NeedsAssessment`, no rule |
| Owns no library | a language package | `NeedsAssessment`, no rule |
| Unknown package ID | a match for an ID the evidence doesn't have | `NeedsAssessment`, no rule |

  - Severity, fix state and fixed versions are carried through.
  - `Sheet` orders as specified, keeps 2048 of 2100 findings, and omits 52 `Suppressed` ones.
  - `Evaluate` is deterministic: shuffled matches give the same result.
- [ ] **Step 2: Run them and see them fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Verify** with `go test ./internal/rules/` and `make lint`.
- [ ] **Step 5: Commit**: `feat(rules): settle findings per package with KEV, the guard, removal and the load check`

### Task 10: The hub

**Files:**
- Create: `internal/controller/hub/`
  - `scheduler.go`
  - `verdicts.go`
  - `dbpoller.go`
  - `janitor.go`
  - tests, including a Ginkgo envtest suite
- Modify: `internal/setup/setup.go`, `cmd/main.go`

**Interfaces:**
- Consumes:
  - `tasks.Executor` (Task 8)
  - the stores (Task 4)
  - `rules.Evaluate` and `rules.Sheet` (Task 9)
  - `matchapi.Client` (Task 7)
  - `settings.Load` (Task 2)
- Produces:
```go
package hub
type Matcher interface { // *matchapi.Client satisfies it
	Match(ctx context.Context, sbom json.RawMessage) (matchapi.MatchResponse, error)
	Database(ctx context.Context) (matchapi.Database, error)
}
```
- `setup.Options` gains:
  - `ScanExecutor tasks.Executor`. Nil means `ScanQueue`.
  - `MatcherURL string`
  - `Matcher hub.Matcher`. Nil means a `matchapi.Client` for `MatcherURL`. With neither set, verdicts are off, which is logged once.
  - Intervals:
    - `ScanRetryBase`, default 1h
    - `MatcherPollInterval`, default 10m
    - `JanitorInterval`, default 1h
    - `UnreferencedGrace`, default 24h
- `cmd/main.go` reads `VEXPLAIN_SCANNER_IMAGE` and `VEXPLAIN_MATCHER_URL`. `ProxyEnv` holds the manager's `HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY`, in either case.

**Behaviour:**
- **The scheduler** reconciles `ImageInventory` objects through `Store.Source()`.
  - An `ImageID` gets facts with `failure NotPullable` once, and is never requested.
  - A `RepoDigest` is requested with its repositories in two cases:
    - It has no facts, or facts from another scanner image.
    - Its last failure has waited out its backoff: `ScanRetryBase × 2^(attempts−1)`, at most 24h.
  - Otherwise it gets `RequeueAfter` the remaining backoff.
- **The verdicts controller** reconciles each platform manifest through `PackagesStore.Source()`, and through enqueues from the poller.
  1. Read the evidence and the sheet. If the sheet already has the current database version and scanner image, stop.
  2. Otherwise call `Match` with the evidence's SBOM, then `rules.Evaluate` and `rules.Sheet`, and `VerdictsStore.Put` the database version, scanner image, findings, omitted count and counts.
  3. If the matcher fails, write nothing, and requeue with the controller's rate limiter.
- **The poller** (a `manager.Runnable`) reads `Database()` every `MatcherPollInterval`. When the version differs from the last one it read, it enqueues every `PackagesStore` digest once.
- **The janitor** (a `manager.Runnable`) runs every `JanitorInterval`.
  - It deletes the `ImagePackages` and `ImageVerdicts` of every manifest that `ManifestReferences` has shown as unreferenced for at least `UnreferencedGrace`.
  - It remembers since when, in memory.

- [ ] **Step 1: Write the failing tests**
  - **Scheduler** (with a recording executor):
    - A repository digest without facts gives one request carrying the repositories.
    - Current facts give none.
    - A changed scanner image gives one.
    - With `attempts 2` failed at T, there is no request before T+2h, and one after.
    - An image ID gets `NotPullable` and never a request.
    - A deleted object gives nothing.
  - **Verdicts** (with a fake matcher):
    - New evidence gives a sheet whose findings come from the rules.
    - A current sheet means no `Match` call.
    - A matcher error leaves the sheet unchanged and requeues.
    - A new database version re-matches, and writes only when the findings change.
    - `minCompletenessPercent` from the `OperatorConfig` is applied.
  - **Poller:** it records the first version, and on a change it enqueues each digest once.
  - **Janitor:**
    - Evidence unreferenced past the grace is deleted, together with its sheet.
    - Evidence still referenced by another digest is kept.
    - Evidence inside the grace is kept.
  - **Wiring:**
    - An empty `ScannerImage` gives no requests, and the Scanner Collector reports "no scanner image is configured".
    - With no matcher, there are no sheets, and no errors loop.
  - **The whole chain in envtest:**
    1. presence
    2. request
    3. the runner, with a fake log
    4. the evidence
    5. the fake matcher
    6. the sheet
- [ ] **Step 2: Run them and see them fail.**
- [ ] **Step 3: Implement**, and wire everything into `setup.Register` and `cmd/main.go`.
- [ ] **Step 4: Verify** with `make manifests generate && make lint && make test`.
- [ ] **Step 5: Commit**: `feat(hub): schedule scans, match once, and keep the verdict sheets current`

### Task 11: Deployment and e2e on kind

**Files:**
- Create:
  - `config/matcher/deployment.yaml`, `service.yaml`, `networkpolicy.yaml` and `kustomization.yaml`
  - `test/e2e/kind-config.yaml`
  - `test/e2e/images/installed-not-linked/Dockerfile` and `test/e2e/images/linked/Dockerfile`
- Modify:
  - `config/default/kustomization.yaml`
  - `config/manager/manager.yaml`
  - `Makefile`
  - `.github/workflows/test-e2e.yml`
  - `test/e2e/e2e_suite_test.go` and `e2e_test.go`

**Interfaces:**
- **Makefile:**
  - `SCANNER_IMG ?= scanner:latest` and `MATCHER_IMG ?= matcher:latest`
  - `MATCHER_DB ?= false`, which becomes the build argument `WITH_DB`
  - `docker-build` builds all three images, and `make deploy IMG=… SCANNER_IMG=… MATCHER_IMG=…` sets all three.
  - The e2e targets use their own kubeconfig: `E2E_KUBECONFIG ?= $(LOCALBIN)/kind-e2e.kubeconfig`, exported as `KUBECONFIG` (AGENTS.md).
- **The manager** gets `VEXPLAIN_SCANNER_IMAGE` and `VEXPLAIN_MATCHER_URL`. The URL is the matcher Service's in-cluster address. Kustomize carries the scanner image into the env value, for example through `replacements`.
- **The local registry** follows kind's documented recipe:
  - a registry container at `localhost:5001`, connected to the `kind` network
  - the containerd `config_path` in `kind-config.yaml`
  - a `hosts.toml` for `localhost:5001`

  `make setup-test-e2e` sets it up, and `make cleanup-test-e2e` removes it.

- [ ] **Step 1: Deploy the matcher**
  - **The matcher's Deployment:**
    - 1 replica
    - non-root, with a read-only root filesystem
    - an `emptyDir` at `/db`
    - requests of 200m CPU and 512Mi memory, and a limit of 2Gi memory
    - readiness on `/readyz`
  - **Its Service** on port 8080.
  - **Its NetworkPolicy** allows ingress only from the manager pods (`control-plane: controller-manager`).
  - The manager's env, and the Makefile variables.
  - `make deploy` renders all three images. Check with `bin/kustomize build config/default`.
- [ ] **Step 2: Write the failing e2e specs**
  - **Planted images** (decision 13): pin an Alpine release whose `brotli-libs` the pinned Grype flags for a Brotli CVE, for example Alpine 3.12 with CVE-2020-8927. The implementer confirms the release and pins its digest.
    - `installed-not-linked` adds only `brotli-libs`.
    - `linked` also adds the `brotli` CLI.
  - **Before the suite:** build and load all three images, with `MATCHER_DB=true`. Build the planted images and push them to `localhost:5001`.
  - **The specs:**
    1. A Deployment of `installed-not-linked` gets, within 5 minutes, an `ImageVerdicts` whose `brotli-libs` finding is `Suppressed` / `LoadCheck` with `NoPreloadEnvironment`.
    2. A Deployment of `linked` gets `NeedsAssessment` for `brotli-libs`, with a reason naming `/usr/bin/brotli`.
    3. After both, no scan Job is left in `vexplain-system`, and no scan Secret either; garbage collection removes it.
    4. No `ImageInventory` has the scanner image's digest.
    5. The `ImageInventory` of each planted digest has `facts.platforms` and no failure.
- [ ] **Step 3: Run them and see them fail**, then make them pass.
  - Run `make test-e2e` with `CERT_MANAGER_INSTALL_SKIP=true`, on a kind cluster created with the proxy variables unset and its own kubeconfig.
  - The workflow builds all three images with `MATCHER_DB=true`, and sets `CERT_MANAGER_INSTALL_SKIP=true`, which is phase 1's carried-forward item.
- [ ] **Step 4: Verify** with `make manifests generate && make lint && make test`, and `make test-e2e` passing from a clean start. The cluster and registry are deleted afterwards.
- [ ] **Step 5: Commit**: `test: deploy the matcher and prove the scan path end to end on kind`

### Task 12: Measure the residual on Brotli

**Files:**
- Create:
  - `hack/measure-2a/main.go` and `main_test.go`
  - `hack/measure-2a/cases.yaml`
  - `hack/measure-2a/images/<case>/Dockerfile`
  - `docs/measurements/2026-phase2a.md`

**Input from the controller:** the Docker Hub images among the owner's export.
- The controller reads only the export's image column, keeps the Docker Hub references, and passes the list in this task's context.
- The implementer never opens the export.
- The repository holds those images as ordinary cases, with nothing saying where they came from.

**Interfaces:**
- **`cases.yaml`:**
```yaml
targetCVE: CVE-2026-111497
approved: false             # the owner sets this to true after reviewing every expected answer
cases:
  - name: installed-not-linked
    build: images/installed-not-linked   # or image: docker.io/library/…@sha256:…
    expected: Suppressed                  # for the target CVE's finding on the Brotli library package:
                                          # Suppressed | NeedsAssessment | Tracked | NotFound | NoPackage
    basis: "apk info shows brotli-libs; readelf finds no DT_NEEDED on it; no file names it"
```
  - `NotFound` means a copy the scanner can't see, which is a blind spot (0025).
  - `NoPackage` means the image has no Brotli at all.
- **The tool:** `go run ./hack/measure-2a --cases hack/measure-2a/cases.yaml --registry localhost:5001`
  - It refuses an API server that isn't on a loopback address, like `hack/inventory-load`.
  - It reads the evidence and sheets through the stores.

- [ ] **Step 1: Write the cases.** The answers are worked out independently: from package versions, `readelf -d`, and a search for the library names in each image, never from the rule under test. Each case gets its `basis`.
  - **The planted cases:**
    - `installed-not-linked`
    - `linked`, with the `brotli` CLI
    - `linked-curl`, if the Alpine release's curl links Brotli
    - `removed-files`: install, then delete the library files in a later layer
    - `bare-name`: Python, with `find_library("brotlidec")`
    - `preload-env`: `ENV LD_PRELOAD=/usr/lib/libbrotlidec.so.1`
    - `static-copy`: a binary statically linked with Brotli, in `scratch`
    - `scratch`: no packages
    - `backported`: only if Debian ships a fixed backport for the target CVE; otherwise left out, with a note
  - **The public cases:** the controller's list, plus the official `node` image, whose bundled copy is a blind spot.
- [ ] **Step 2: Write the failing tests for the tool's evaluation:**
  - comparing expected and actual answers
  - totals by outcome, by severity and by fix state
  - flagging a false "not affected": expected not `Suppressed`, but `Suppressed`
- [ ] **Step 3: Implement the tool.**
  1. Build or copy each image into the registry by digest.
  2. Deploy one Deployment per case in namespace `measure-2a`.
  3. Wait for each case's sheets, with a timeout per case.
  4. Print:
     - each case's expected and actual answer
     - totals for every finding, and for the target CVE's, by outcome, severity and fix state
     - completeness per case
     - evidence sizes, compressed and uncompressed, and sheet sizes, against 512 KiB
     - scan durations
  5. Exit 1 on any false "not affected".
- [ ] **Step 4: Run it** on kind, with its own kubeconfig, against the operator deployed by Task 11's setup.
- [ ] **Step 5: Write `docs/measurements/2026-phase2a.md`:**
  - the method
  - the cases with their basis
  - the residual at the verdict level on the test set
  - the known-answer check
  - completeness
  - sizes against decision 0004's triggers
  - what it doesn't show

  The doc:
  - says "provisional until the owner approves the known answers" while `approved: false`
  - holds no figure from the owner's platform, and no time per case
  - says the value figure (residual × time per case) is given to the owner outside the repository
- [ ] **Step 6: Commit**: `test: measure the residual on Brotli against known answers`

---

## As built

Where the build differs from the text above, the build is right. Each difference was decided and reviewed while the plan ran, or in the review of the whole phase after it.

### Decisions of this plan

- **Decision 4, the size limits:**
  - A sheet is cut at 1 MiB of its findings' JSON as well as at 2048 findings. At the schema's maxima 2048 findings take about 4 MB, over etcd's limit for one request, and the API server would refuse the whole sheet.
  - A sheet's order is `Tracked`, then `NeedsAssessment`, then `Suppressed`, and a cut leaves out its end: the `Suppressed` findings first, then the least severe `NeedsAssessment` ones, and `Tracked` findings last. A vulnerability that is known to be exploited is patched, not argued about, so its findings are the last to go.
  - So, unlike the text above, open findings can be left out: by the cut at 1 MiB, or when a manifest has more than 2048 of them. `omittedFindings` counts every finding that is left out, and `counts` covers every finding, so the residual stays exact. An `omittedFindings` above `counts.suppressed` means that the sheet doesn't list every open finding.
  - A scan log of 8 MiB or more, and a result of more than 64 MiB once decoded, give `TooLarge`, as evidence too large to store does. The matcher refuses a request of more than 64 MiB.
- **Decision 5 stands:** known exploitation still decides before every other rule. Whether it should only raise the urgency is open (Carried forward).
- **Decision 6, the packages that the load check applies to:**
  - The check also needs one `Library` entry for each shared library that the package owns. Otherwise the evidence doesn't cover the package, and the finding stays open with the reason "the library evidence is incomplete".
  - "Removed in a later layer" and the load check need the package's entry in the SBOM. "Removed" also needs at least one listed file: packages that aren't OS packages list none.
  - A package ID that the evidence has twice, or that is empty, counts as absent.
  - The known-exploited rule and the completeness guard apply before the evidence is looked up, because neither needs it.
- **Decision 9:** an `/etc/ld.so.preload` that isn't a regular file, or that sits in a loop of links, counts as set. Both err towards keeping a finding open.
- **Decision 11:** the image's configuration sets `LD_PRELOAD` or `LD_AUDIT` in its environment, or in its command (`Entrypoint` or `Cmd`), as a shell form that sets the variable for the program it starts does. Only the presence counts, in both.
- **Decision 12, the platforms:**
  - The operator reads Nodes with `get` and `list`, since "the platforms of all nodes" needs a list.
  - All nodes' platforms are scanned when the scheduled pods give none, and it is an error when no node gives one either.
  - A request names platforms as node labels do, without a variant. `result.PlatformMatches` holds the one rule by which `Resolve` and the runner match them, and a single-manifest image's result is valid whatever its platform.
- **Decision 13:** the task label counts only on pods in the operator's namespace (`workloads.IsTaskPod`, and the index from `workloads.PodDigestIndexer(operatorNamespace)` in place of `IndexPodDigests`). Otherwise anyone who can create pods could hide a workload from triage with the label. Only admins create pods in the operator's namespace.
- **Decision 14, the result in the log:**
  - Only a pod that succeeded delivers a result, and only after full checks: it names the image that was asked for, byte for byte; it has 1 to 16 manifests with unique platforms; every digest and platform has its pattern; every platform matches a requested one, but for a single manifest; and every SBOM is a JSON object with members. A result that fails a check is a failed scan with the reason `Internal`, because a line in a log carries no proof of where it came from.
  - The scanner prints only its own fixed lines, never Syft's output: a file name in an image could hold a forged result line.
  - A scan pod that left no log, because its container never ran or its log is gone, gives `Internal`, so that the failure is recorded and not lost. A Job past its deadline gives `TimedOut`.
- **Decision 16:** Grype's output has a field for known exploitation, so there is no `kev.go`.
- **Decision 17, the janitor:**
  - It deletes the evidence of a manifest only when the object is older than the grace, has been unreferenced for the whole grace, and `ManifestReferences` still finds no reference just before the delete. A spoke may just have stored evidence whose facts it hasn't written yet.
  - It takes the scan time as the evidence's age, and deletes the sheet before the evidence.
  - A sheet never outlives its evidence: the verdicts controller deletes the sheet of evidence that is gone, because a match under way can write a sheet just after the janitor deleted it.
- **Decision 18, rescans and retries:**
  - A failure's backoff counts before the scanner image. A digest that fails under a new scanner keeps the old image in its facts, and would otherwise be asked for at every reconcile.
  - The scheduler looks at a digest again `ScanRetryBase` after each request, so that a request that was dropped, or a scan that was lost outside the runner, is asked for again.
  - It asks again for a digest whose facts name a manifest without evidence. It reads that from the cache, and confirms it with the API server: evidence can go without an event that the scheduler watches.
  - Without a scanner image, the scheduler doesn't start.

### Phase 1's gaps (Task 1)

- An invalid scope's condition message is `scope.New`'s error, which names the first selector at fault.

### API (Task 2)

- The Collector controller knows the type `Scanner` and its spec, so the default `scanner` Collector shows healthy.
- Where the plan's snippets differ from kube-api-linter in pointers and types, the code follows the linter: `ScanFailure.Attempts` is `int32`, and the optional strings and enums are pointers. A narrow exclusion in `.golangci.yml` covers `Finding.conditions`, which lists enum values and not status conditions.
- A finding's package version is optional, since a package can lack one; its ID, name and type stay required. The matcher's `Match` carries the package's name, version and type, so that a finding of an ID that the evidence lacks still has a whole package.
- `FindingCounts` count every finding, those that a sheet leaves out included.
- The enums have documented constants: the reasons, outcomes, rules, justifications, the condition, severities and fix states.
- `ImagePackages` has no status, so the scaffolded helper roles have no `imagepackages/status`.

### The result format (Task 3)

- `Encode` stamps `SchemaVersion`, and `Parse` refuses any other version and any reason outside the seven. `EncodeError` writes `Internal` for any other reason.
- `Completeness()` gives 0 for counts that can't be true, which trips the guard.

### The stores (Task 4)

- The constructors take the name of the cluster as a function, read at each write, for the label of their metrics: `NewCRDStore(c, informers, cluster)`, `NewCRDPackagesStore(c, informers, cluster)` and `NewCRDVerdictsStore(c, cluster)`. A write isn't counted while the name can't be read.
- `setup.Register` registers the field index of the manifest digests (`inventory.ManifestDigestIndex` and `IndexManifestDigests`), as it does phase 1's pod index. `ManifestReferences` uses it when the store has informers, and lists otherwise.
- Neither the evidence nor the sheets are in the hub's cache. `setup.ClientOptions` makes the manager's client read both from the API server, and the evidence is watched as metadata only. A cache would hold every manifest's evidence, up to 768 KiB compressed each, and every sheet, in memory.
- `PackagesStore` gains `Exists`, which reads the metadata cache and asks the API server when the cache holds none, and `CachedDigests`, which reads the metadata cache. `Digests` asks the API server.
- The role on `imageverdicts` is get, create and delete, and update on the status: the store never lists or watches sheets. 2b adds what its renderer needs.
- `SetFacts` compares times to the second, and returns `(false, nil)` when the object goes before its status write. `VerdictsStore.Put` retries as `Observe` does. `Source` drops an update unless the UID changed. `Get` refuses any encoding but `GzipJSON`.

### The analysis (Task 5)

- An ELF file that `debug/elf` can't parse, or that makes it panic, counts as an ELF file without a soname, as does one without a readable dynamic section. ld.so reads only the program headers, so such a file can still load. It adds no reach.
- Path resolution clamps `..` at the image's root, as the kernel does inside a container's root. Only a loop of more than 40 links resolves to nothing.
- The name search also leaves out ldconfig's `/var/cache/ldconfig/aux-cache`, as part of the linker cache, and a soname that holds a path also gives the names of its base name (0026's status).
- A package database that Syft didn't catalog fails the scan as `CatalogFailed` (`analyze.ErrCatalogIncomplete`). Syft exits 0 when a cataloger fails, which would leave an image without packages, and so without findings.
- A library that two packages own gets an entry for each. Only files count as listed or present, not apk's directories. Syft JSON of another schema major than 16 is refused.
- `Analyze` takes the image's configuration as `analyze.ImageConfig`, its environment and its command, instead of the environment alone.

### The scanner (Task 6)

- Syft runs as `syft scan dir:<root> --base-path <root> --override-default-catalogers image -o syft-json=<file> --quiet`, beside the root and with a minimal environment:
  - Without `--base-path`, absolute links resolve against the scanner's own filesystem.
  - A directory scan's default catalogers miss installed npm, gem and Rust packages.
  - An SBOM inside the root would name every library, and a `.syft.yaml` in the working directory would configure Syft.
- Unpacking never writes through a link. An entry below a link of a layer above, or below a file, is skipped, as an overlay hides it, and so is an entry below a link of its own layer.
- An entry below a link of a layer below goes where the link leads, inside the root, and the link stays, as containerd's applier places it when it unpacks a layer onto the layers below. Whiteouts and opaque whiteouts below the link go the same way, except that what the link's own layer unpacked there before the link stays, which errs towards a file that is present. A layer that a tool assembled from files, rather than a snapshot's diff, can write `lib/...` over a merged-usr base where `lib` links to `usr/lib`: its files land in `usr/lib`, and the files that the base's packages list below `/lib` stay present, where they would otherwise read as removed in a later layer. The unpacker keeps the paths it decided as a tree, so that what a layer above put below `lib` moves to where the link leads in one step.
- A link that such entries go through fails the scan as `Internal` when it leads out of the root, passes through more than 40 links, or meets something that isn't a directory, and so does an entry that meets another one where the link leads, other than two directories.
- A hard link takes its content from its own layer, which is read a second time when a layer above hid the file. A hard link to anything else, `../x` included, fails the scan as `Internal`, where the plan said "refused".
- A PAX global header is ignored, as container runtimes ignore it. A layer with two entries for one path, other than two directories, fails the scan as `Internal`, rather than keep the first while containerd keeps the last. A directory that unpacking made above an entry counts as an entry of its layer, so a later file of the layer at that path fails too: containerd would replace the directory with it, and the file could be an ELF file that reaches a library.
- Reasons: a read error while unpacking is `PullFailed`, a write error `Internal`; 401, 403 and 404 map the same way for blobs and configurations; bad flags give an `Internal` line, exit 1 and no usage text; a panic gives an `Internal` line without its value; a failure after the context ended is `Internal`.
- `Resolve` takes the first index entry of each platform, as the runtime does. A schema 1 manifest, one of an unknown kind, and a single manifest without an OS or architecture give `NoMatchingPlatform`.
- `--max-bytes` counts disk blocks, as the kubelet does. `Result.Image` is the `--image` argument verbatim.
- `--registry-mirror host=url` pulls the same digest from a mirror (see Task 8).
- Syft is pinned at v1.55.0.

### The matcher (Task 7)

- A database baked into the image lives at `/opt/grype-db`, and `--seed-db` copies it into an empty `/db` at start, whenever loading fails then. The matcher sets `GRYPE_DB_VALIDATE_AGE=false`. 0022's status says why.
- Grype runs with `--by-cve`: findings, the known-exploited list and the worklist are keyed by CVE. An advisory without a CVE keeps its own ID.
- `Database.Version` is the schema version and the build time, so that it changes with the content: the schema version alone is the same across the daily builds.
- Matches and updates never overlap, under a read-write lock. A failed update keeps the old database, and `--offline` never updates. A matcher without a database tries its update again after a minute.
- A request over 64 MiB gets 413, bad JSON 400, and every error carries a fixed text. The write timeout allows the client's two minutes and one more. The client refuses a 200 without `databaseVersion` or `matches`, caps an answer at 64 MiB, and tells a cancelled context from `ErrUnavailable`.
- `MatchRequest`, `MaxRequestBytes` and `DefaultTimeout` are exported, and `Server` exports `Load` and `Update`.
- Grype is pinned at v0.121.0.

### The spoke's scans (Task 8)

- **Pull secrets** are read through a typed clientset, which go-containerregistry's Kubernetes keychain takes. It reads with get only, and caches no Secret.
  - A Docker Hub secret keyed `docker.io` is found, as the kubelet finds it.
  - A scan gets one credential per registry, the first that matches, the pod's before its service account's.
  - The keys of `config.json` follow the default keychain, and a round-trip test pins them.
  - `pkg/authn/kubernetes` is pinned at `v0.0.0-20260224031529-85f2bf5f7303`, the newest that doesn't need k8s.io v0.37. Move it when controller-runtime moves to v0.37.
- **Scan pods:**
  - `fsGroup` 65532 and Secret mode 0440, so that the scanner, which isn't root, can read the credentials.
  - The memory request equals the limit.
  - The environment is exactly `DOCKER_CONFIG` and the proxy variables. It never has `DOCKER_AUTH_CONFIG`, which the Docker CLI would read as one more source of credentials.
  - The scanner gets `--work /work` and `--max-bytes` at three quarters of the workspace. The rest is for Syft's temporary files, its home and the SBOM, because a pod that fills its workspace is evicted and leaves no line.
  - The Secret is created after the Job and owned by it, without blocking the Job's deletion. If it can't be created, the Job is deleted and the request is tried again.
  - Job names are `scan-` with the first 12 hex digits of the digest and 5 random characters.
  - The scanner and the matcher are pulled `IfNotPresent`, because kind loads images without a registry.
- **The runner:**
  - A request that finds every slot taken waits `Options.ScanSlotWait`, 30 seconds by default, and reads the Jobs through the API reader, as the plan says. Its cost is carried forward.
  - Registry mirrors: `Options.ScanRegistryMirrors`, which `cmd/main.go` reads from `VEXPLAIN_SCAN_REGISTRY_MIRRORS`, become `--registry-mirror`. Inside a pod, `localhost:5001` is the pod itself, so the end-to-end tests and the measurement map it to the registry's address on the kind network. Production leaves it empty.
  - It reads a Job's pods through the API reader right after the Job, which adds `pods: list` to the operator's Role: a fresh Job seen with a stale pod cache would record a successful scan as `Internal`.
  - It watches the scan Jobs' metadata through phase 1's informer, and counts a failure once for each Job.
  - "No scanner image is configured" is the runner's report, and the scheduler sends no request then.
  - `Register` refuses a scanner image of more than 512 characters, and a `ProxyEnv` name that isn't a proxy variable. The recorded scanner image comes from the Job.

### The rules (Task 9)

- Matches of one vulnerability and package make one finding: known exploited if any match says so, the most severe severity, the strongest fix state and the union of the fixed versions. Grype reports duplicates across its matchers. `Evaluate` returns the findings sorted by vulnerability, then package.
- A reason names the first path in path order. Reach wins over a name, and a name over preload. A count without paths still keeps a finding open. An SBOM that can't be read takes the packages from the matches, and settles nothing.
- Every finding fits the schema. The reason is cut to 256 bytes on a character's boundary, the fixed versions to the first 8 of at most 128 characters, and the ID, name, version and type to their maxima. An empty ID, name or type becomes `unknown`. Every character that isn't printable becomes U+FFFD: image content reaches the sheet, and `kubectl` prints it as it is.
- An empty fix state, or any value outside Grype's four, maps to `Unknown`.

### The hub (Task 10)

- A sheet is written only when its findings change. The verdicts controller remembers in memory, for each manifest, what its last match depended on: the database version, the scanner image, the scan time and the minimum completeness. It matches again only when one of them changed. A restart matches every manifest once, and writes only the sheets that changed.
- When the findings, the omitted count and the counts equal the stored sheet's, the stored database version and scanner image stay. So `status.databaseVersion` is the version of the match that last changed the findings, and a sheet keeps its older scanner image when a rescan finds the same.
- A change of the OperatorConfig maps to the manifests in the cache of the evidence, so that a failed list can't lose it.
- The poller's first successful read has every manifest that was matched against another version matched again.
- The verdicts controller runs two matches at once, as many as the matcher serves at once by default.
- `Register` refuses a malformed `MatcherURL`. The wiring specs are an envtest suite of `internal/setup`.
- A successful match without matches replaces a sheet: the database now finds nothing.

### Deployment and e2e (Task 11)

- The matcher's Deployment also mounts an emptyDir at `/tmp`, because its root filesystem is read-only and it writes the SBOMs there. It has 8Gi of ephemeral storage, 8Gi for `/db`, where a seed and an update both land, and 1Gi for `/tmp`.
- `config/matcher` is the production form: it updates online, and seeds nothing. The end-to-end overlay `test/e2e/config` (`DEPLOY_CONFIG`) runs it with `--offline --seed-db=/opt/grype-db`.
- The scanner image reaches the manager's environment through kustomize's images transformer (`kustomizeconfig.yaml`). The metrics patch applies to the manager only.
- The local registry is the container `vexplain-e2e-registry`. Cleanup removes it and the kind cluster `vexplain-test-e2e`, by name, and nothing else. `setup-test-e2e` creates the cluster with the proxy variables unset: kind copies them into the nodes, where a proxy on localhost is the node itself.
- The load-check specs use libxml2's CVE-2024-56171. The pinned Grype finds only CVE-2026-111497 on `brotli-libs`, which is known exploited and so always `Tracked`, and a spec of its own shows that in both planted images.
- The suite has image names of its own, runs `go test -timeout 60m`, and has a spec for what the NetworkPolicy denies. `make deploy` edits the kustomizations of the manager and the matcher in place, and the suite puts them back.

### The measurement (Task 12)

- Each case has two answers: as the rules are built (`expected`), and without the known-exploited override (`expectedWithoutKEV`), which the tool computes from the stored evidence. Before it does, it rebuilds every finding of the sheet and demands it back, or stops. The second column is input to the open question about known exploitation.
- A case's answer is the target CVE's finding on the package of the Brotli library, which `package` names on a distribution other than Alpine, Debian and Ubuntu. Findings on other Brotli packages are listed, and don't decide.
- Public cases are pinned by index digest, and each case's container runs a command that keeps it alive and starts no server. `linked-curl` runs on Alpine 3.13, whose curl links Brotli, and `backported` is in, since Debian ships a fixed backport of the CVE.
- `hack/internal/localcluster` holds the guard of both tools in `hack/`. It refuses unless `KUBECONFIG` is set, the name of its current context starts with `kind-`, the API server is on a loopback address, and the cluster sets no `proxy-url`. A loopback check alone accepted a developer's default kubeconfig, and a tunnel to a remote cluster, and a proxy carries the requests to wherever it is, whatever the server's address. kind never writes a `proxy-url`.

### Accepted as they are

- Grype's default ignore rules, such as for kernel headers, and the matcher's own suppressions remove matches before the rules see them. That is Grype's matching, which the design embeds.
- Copies that the scanner can't see, in static, bundled or packed binaries, are the blind spot that 0025 accepts.
- A pull through a registry mirror takes the credentials of the mirror's host. Mirrors serve the end-to-end tests and the measurement only.
- Whether the NetworkPolicy is enforced depends on the CNI. The end-to-end tests show it on kindnet only.
- The cost of the name search on very large images is bounded by the Job's deadline, and the plan sets no target for it.
- The matcher runs one replica without a PodDisruptionBudget, as the plan says.
- A distroless dpkg database without file lists settles nothing, which is the safe direction.

## Carried forward

These are the known gaps of phase 2a, each under the point by which it must be closed. The first task of phase 2b closes the items due at its start, as Task 1 did for phase 1's.

### At the start of phase 2b

- **The sheet's contract for its readers:** its order; that an `omittedFindings` above `counts.suppressed` means that the sheet doesn't list every open finding, and must be shown as incomplete; and that a sheet without `counts` or `databaseVersion` means "no verdict yet", never "no findings". Decide too whether a cut into open findings should rather be a "no verdict" with a summary.
- **Platforms that start running a digest after its first scan** are never scanned: the platforms are picked at scan time, and the scheduler never looks at them again. In a cluster of two architectures, the pods of the second get no sheet until the scanner image changes, which is safe but silent. It needs a design note, for example a presence entry that reports its pods' platforms, since 2b looks sheets up by the node's platform.
- **`NoPreloadEnvironment`** must cover `envFrom`, and a pod's `command` and `args` that set `LD_PRELOAD` or `LD_AUDIT` inline, as the image's own command does now.
- **Untrusted text:** reasons and package metadata in sheets come from image content. The renderer and the agent treat them as data, never as instructions.
- **Known exploitation, as an override or as urgency:** decide with the measurement's second column. If it changes: a decision record that refines plan decision 5; the rules and the verdict format, with a marker on each finding and no `Tracked` from it; the end-to-end spec of it; the measurement's two columns; and a sheet's order. Two checks then become must-haves: a library entry that repeats must count as "the library evidence is incomplete", and "removed in a later layer" must also check that the package owns no ELF file.
- **Catalogers:** a failed cataloger of packages that aren't OS packages still drops them silently; read Syft's `unknowns`. The databases of opkg, alpm, portage and nix aren't checked.
- **Low completeness:** a manifest with low completeness and no findings must show as "inventory incomplete", never as clean.
- **The gauge of skipped containers** that phase 1's "Carried forward" asks to consider.
- **The Scanner's health:** the report "no scanner image is configured" doesn't stick. A later error replaces it, and a leftover Job's success shows the Scanner healthy.
- **Small gaps:**
  - The OperatorConfig's condition message isn't cut to the length that the rest of its package uses, and no test pins the refusal text of an empty selector or the order of refusals.
  - The docs of `PackageReference.id` and `version` don't say that the ID may be one the evidence lacks, or that no version and an empty one are the same.
  - `VerdictsStore.Put` doesn't state what it does with a changed `databaseVersion` alone, and no test changes only that.
  - No test covers `SetFacts(nil)`, or shows that a partial `Forget` keeps the facts.
  - The hub's chain spec doesn't see the sheet go before it comes back.
- **Comments that cite a decision kept outside the repository:** add a check before each commit. A comment states its reason itself.

### With the owner's decision on the load check

These five change the scan output, so every image is scanned again once the scanner image changes. Settle them as one record that refines 0026, with a planted case for each gap, before the measurement runs again, so that it runs once more and not twice.

- **Names that a program assembles at run time:** APR-util loads its plug-ins by a name that it builds from a format string, so no file holds the name that the search looks for. The measurement's 8 suppressions are of this kind. A proposal: a library outside the directories that ld.so searches by name stays open, from its recorded path and the image's search directories (the built-in ones and `/etc/ld.so.conf(.d)`); and a printf-style string that matches a library's file name counts as a reference.
- **Other ways to reach a library that the three names miss:** a link whose base name doesn't hold the soname, a file name that doesn't hold it, and references inside archives, such as a JNI library in a JAR that links the system's OpenSSL, or a zipapp or PEX that calls `dlopen`. 0026 counts an archive as another copy, but such an archive refers to the distribution's copy.
- **The owning package's own files** are left out of the search, so its own loader scripts aren't seen.
- **The image's command** is searched for `LD_PRELOAD=` and `LD_AUDIT=` only, not for library names.
- **A package database reached through a linked directory,** such as apk's under `/lib -> usr/lib`, isn't left out of the name search, though the check of the catalog follows the link. It then names every library, so nothing in the image settles, which is safe. Resolve the database directories the same way.

These four need no record. They are in the scanner's code too, so they can go with the same change. The ELF item holds two fixes that only a crafted file or a failed read reaches, and a test gap. The others are test gaps, doc items, a detail of the codec that leaves the JSON equal, and a fix to a script.

- **ELF:** the first `DT_SONAME` is taken, from the section headers, where ld.so keeps the last, from the program headers; only crafted files differ. A read error on the ELF magic makes a file "not ELF" instead of failing the scan. The branch of a recovered panic has no test.
- **The result format:** the codec escapes the SBOM's JSON, which is equal as JSON and not byte for byte; set `SetEscapeHTML(false)`, or say so in the docs. The test that no error quotes the log has no case without a line.
- **The unpacker:** a hard link that a layer above hides is skipped without its target being checked, which the doc of `Extract` doesn't say and no test pins. The 401 and 404 of blob and configuration fetches are covered only indirectly.
- **`gen.sh`** writes its fixtures as root on a Linux host, so its cleanup fails there.

### Before the measurement runs again

- Run it on a fresh cluster, with the scanner, the rules and the tool as built now, and refresh the doc's figures, which predate the last fixes. The doc stays provisional, and `approved: false` stays, until the owner approves the known answers. The independent working of the known answers isn't in the repository; the owner approves their basis.
- `answerOf` lets a `Tracked` in one platform manifest hide a `Suppressed` in another. Compare per manifest before a run with more than one platform.
- The check of the rebuild compares outcome, rule, justification, conditions and reason only. Compare whole findings, since severity, fix state and fixed versions feed the tables too.
- `printSizes` prints a failed encoding as `0 B (0%)`; print `-`, as `printScans` does.
- `backported` pins `libbrotli1` from the live Debian archive, so its build breaks once the archive moves on. Switch to snapshot.debian.org then.
- On that cluster, run the mutation of the spec that no scan pod is inventoried: only three of the eight end-to-end specs of Task 11 were seen to fail first.

### Before the first run on a real cluster

- **The matcher's freshness:** a gauge of the database's build time, or a health check, at the hub. Grype's age check is off, so a stale database silently misses newer CVEs. With a database loaded, a failed update waits a whole interval.
- **The slot wait** costs uncached LISTs of Jobs for each waiting request every 30 seconds, and a real cluster's first start has every digest wait at once. Free waiting requests when a slot frees, or count slots from the shared cache.
- **Decision 0004's first trigger fired:** `keycloak`'s evidence is 98% of `MaxEvidenceBytes`. A larger image fails as `TooLarge`, and `TooLarge` and `NoMatchingPlatform` are tried again up to daily, since decision 18 spares only `NotPullable`. Both are the owner's decision under 0004.
- **Credentials that an admin adds** (0022, design 6.12). With them: a scan gets one credential per registry, where the kubelet tries each.
- **Scan Jobs** have no CPU request or limit.
- **Entries that take no space,** such as devices, FIFOs, whiteouts and hidden paths, grow the unpacker's memory without bound in one layer, and a pod that dies without a line records `Internal`. Cap their number, with `TooLarge`.
- **An OCI 1.1 artifact** with the image media type and a real platform can win `Resolve`'s first entry for a platform, and fail the scan as `PullFailed`. Skip entries that have an `artifactType`.
- **The matcher:** Grype's output goes into an unbounded buffer, which should stop at 64 MiB. A match that waits behind an update keeps its slot after its client left. A crash while seeding leaves a `.seed-*` file in `/db`. The poller's first read usually fails at a fresh start, and the next one waits a whole interval.
- **The runner:**
  - Its check that a container never ran depends on the kubelet's container ID.
  - A 400 from the log read also covers a transient error of the runtime, which costs one `Internal` failure.
  - The failure path reads the earlier facts from the cache, which can lag.
  - No test covers a finished Job that isn't deleted yet, or a Job being deleted. No test asserts the attempts of a pod that never ran, or sends a 400 through the real log reader.
- **The hub:**
  - The poller and the janitor list the evidence from the API server. Have them read the metadata cache, as the OperatorConfig's mapping now does.
  - The janitor decodes the whole evidence to read its scan time.
  - Shutdown logs `context canceled` as an error in the poller, the janitor and the verdicts controller.
  - The stores read the cluster's name with `context.Background()`; give it a short timeout.

### Before the first push

- The e2e workflow's step that frees disk, and its estimate of about 19 GB, are unchecked on a hosted runner.
- CI builds a fresh Grype database, and three end-to-end specs assert what that database says. On a failure, read the database version that the suite records.
- `Dockerfile.matcher` copies the binary before the database, so each change of the matcher's code makes the 3 GB layer of the database again. Copy Grype and the database first.
- The Makefile lets `E2E_REGISTRY` and `E2E_REGISTRY_PORT` be overridden, though the overlay, the suite and the kind configuration hard-code them. It reuses an old e2e cluster without checking containerd's `config_path`, so the first symptom is a timeout. `$(E2E_KUBECONFIG)` is unquoted, so a path with a space breaks setup and cleanup.

### Before the first install on a shared cluster

- `docker-buildx` builds only the manager, so a release for several architectures gets no scanner or matcher image.
- The Dockerfiles pin their base images by tag, not by digest.
- `config/manager/manager.yaml` hard-codes `vexplain-system` in `VEXPLAIN_MATCHER_URL`. Use the pod's namespace.

### In phase 6

- **Trust in the hub's writers:** `PackagesStore.Get` takes `uncompressedBytes`, which has no maximum in the schema, as the bound of its decoder. Anyone who can create `imagepackages` could make the hub inflate hundreds of MB, or forge evidence. Add a ceiling in the store and a maximum in the schema, with the transport.
- **Validation in the store** for `ImagePackages` and `ImageVerdicts`, as phase 1 carries for `ImageInventory`.
- **Scanner versions:** with spokes on different scanner images, evidence can switch back and forth between them. Decide which wins.
- **`Forget`** deletes an `ImageInventory` that has no entries, so another cluster's `Observe` loses to the local pod inventory.
- **Hub-only mode** is never exercised.

### If real images hit it

- A layer with two entries for one path, other than two directories, fails the scan as `Internal`. If real images have such layers, apply the last entry instead, as containerd does.

### If a 32-bit target is added

- `result_test.go` doesn't build for linux/386, and its comment on 32 bits is wrong.

### Style

Files that grew large (`analyze.go`, `runner.go`, `rules.go` and its tests, `e2e_test.go`, the measurement tool and its tests, and an API test of `ImageInventory`), code repeated across the stores, the tests, the scanner and the proxy settings, comments narrower or broader than the code, a few error, log, usage and assertion texts, and times compared with `==` are left to the next change of each file.
