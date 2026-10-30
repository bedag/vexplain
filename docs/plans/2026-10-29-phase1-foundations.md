# vexplain — Phase 1 (Foundations) Implementation Plan

> **For agents:** follow `AGENTS.md`. Implement this plan task by task, test first. A task is done when its tests pass, it is committed and it has been reviewed; only then start the next one. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A kubebuilder operator, running on one kind cluster as hub and spoke at once, that:
- knows which image digests are actually running, and in which workloads (the first 100 per cluster, plus counts)
- stores one lean `ImageInventory` per reported digest through a swappable storage interface
- starts measuring object sizes and write rates. That's an early indicator only; the storage decision waits for a real cluster (0004).
- reaches the on-prem LLM through a `ModelConfig`, and proves the model handles a two-turn tool-calling exchange

**Architecture:**
- The design has three API groups. Phase 1 creates two of them: `config` (admin-owned kinds) and `inventory` (bulky kinds), both at `v1alpha1`.
- A pod-inventory controller reconciles one reported digest at a time from a pod field index. It writes this cluster's presence entry through `inventory.Store`. That is the spoke's "eyes" report (0021). Hub and spoke share one process in this phase, and `inventory.Store` is the boundary that phase 6 (multi-cluster) puts a transport behind.
- The `OperatorConfig`, `Collector` and `ModelConfig` controllers each own exactly one CRD.
- The LLM client is plain `net/http` speaking the OpenAI chat-completions wire format. That keeps it free of SDK quirks with non-OpenAI servers.

**Tech Stack:** Go 1.26, kubebuilder v4.15 (controller-runtime, controller-gen, envtest, Ginkgo/Gomega), Prometheus via controller-runtime metrics, golangci-lint with kube-api-linter, kind.

**Spec:** `docs/design/2026-10-29-vexplain-design.md` (revision 5). Decision records: `docs/decisions/` 0001–0021; 0011, 0019 and 0021 matter most here. This plan covers **phase 1** of design section 7. Phases 2–7 get their own plans.

## Global Constraints

- **Names (0018):**
  - module `github.com/bedag/vexplain`, domain `vexplain.bedag.ch`
  - groups `config.vexplain.bedag.ch` and `inventory.vexplain.bedag.ch`; `triage` comes in phase 2 with `WorkloadReport`
  - metric prefix `vexplain_`, env prefix `VEXPLAIN_`
  - operator namespace `vexplain-system`
- **API conventions:**
  - Every kind is `v1alpha1`.
  - Status is a subresource. Conditions are `[]metav1.Condition` with `+listType=map` / `+listMapKey=type`, and each sets `ObservedGeneration`.
  - No floats in `spec`; units go in field names.
  - Enums are open: documented as "more values may follow". A controller meeting an unknown value sets `Ready=False`, reason `UnknownValue`, and never panics.
- **Fields arrive with the phase that uses them (0012, 0015).** Don't add design fields that phase 1 doesn't use.
- **kube-api-linter:**
  - Every API field gets a doc comment starting with its JSON name, plus `+required` or `+optional`. Strings get `MaxLength`, lists get `MaxItems`.
  - The type snippets below show the contract. Add whatever lint markers the linter demands.
  - Disabling a rule needs a comment in `.golangci.yml` saying why.
  - Every task that touches `api/` runs `make lint`.
- **References:** `…Ref` fields stay in the same namespace. Cluster-scoped kinds reference objects only in the operator namespace, read from env `POD_NAMESPACE` (default `vexplain-system`).
- **Role separation (0021):**
  - Phase 1 runs hub and spoke in one process (`HubAndSpoke`), but nothing may depend on that.
  - Spoke code (collectors, the pod inventory) reaches hub state only through `inventory.Store`. Hub code (`ModelConfig`, and later the rules and the agent) never calls spoke code directly.
  - This keeps `Hub`-only possible. The mode field itself arrives in phase 6, when it first changes behaviour.
- **RBAC comes from markers:**
  - Every rule comes from a `+kubebuilder:rbac` marker next to the code that needs it. `make manifests` generates `config/rbac/role.yaml`; nobody edits it by hand.
  - Markers generate only Roles and ClusterRoles, never bindings (kubebuilder book, RBAC markers). Bindings follow the scaffold's own `config/rbac` files. The only extra one is the RoleBinding for the namespaced Secret Role (Task 9).
  - kubebuilder's `--namespaced` mode would scaffold that binding, but it makes the whole manager namespace-scoped. That doesn't fit an operator that watches pods in all namespaces.
- **Read-only towards workloads:**
  - get/list/watch only, on pods, namespaces, ReplicaSets and Jobs. Nothing else is fetched (Task 4).
  - Secrets: get/list/watch, and only in the operator namespace.
- **Secret values** (the LLM API key) never appear in logs, status, events, metrics or error strings.
  - The key is held as `llm.Secret`, whose `String`, `MarshalJSON` and `MarshalLog` return `[redacted]`.
  - HTTP response bodies never go into errors, because some gateways echo the key they received.
  - A `ModelConfig` may only reference Secrets that carry the label `vexplain.bedag.ch/llm-api-key: "true"`. Otherwise anyone allowed to write `config.*` could have the operator send any Secret from its namespace to any host.
- **Outbound HTTP** honours `HTTPS_PROXY` and `NO_PROXY` (`http.ProxyFromEnvironment`).
- **Metrics** carry `cluster` = the effective `OperatorConfig.spec.clusterName` (default `local`).
- **Events:**
  - Recorded with `mgr.GetEventRecorderFor("vexplain")` (core/v1 Events).
  - The ClusterRole gets `create;patch` on `events` (`+kubebuilder:rbac:groups="",resources=events,verbs=create;patch`). The scaffold's leader-election Role only covers the operator namespace.
  - Events for cluster-scoped objects land in the `default` namespace (client-go's rule).
  - client-go merges repeated identical events into one object, so tests assert on its `count`, not on the number of objects.
- **Wiring:** controller setup lives in `internal/setup` as `setup.Register(mgr ctrl.Manager, opts setup.Options) error`. `cmd/main.go` and both envtest suites call it, so tests run the same watches, caches, field indexes and event recorder as production. `setup.Options` gains fields as tasks need them; intervals are fields, so tests can shorten them.
- **Controllers whose status changes on every reconcile** filter their primary resource with `predicate.GenerationChangedPredicate`. That way their own status writes don't retrigger them.
- **Tests:**
  - Unit tests use `testing` with testify's `require` (add the dependency).
  - Controller tests use the scaffold's Ginkgo/Gomega envtest suites, which start a manager through `setup.Register`.
  - Scaffolded controller tests and `config/samples` objects that no longer fit (a required field, a naming rule) are replaced in the task that adds the rule, not deleted.
  - Metric vectors are global, so tests assert deltas. Histograms are read by writing them into a `dto.Metric` (`testutil.ToFloat64` panics on histograms).
- **Environment:** phase 1 runs only on a local kind cluster. Shared clusters later get the operator only through the CI pipeline's manual steps.
- **No mention of any tenancy tool.** The operator works per namespace.
- **Commits** follow `AGENTS.md`: Conventional Commits, with no AI co-author trailers or attribution lines.

## Review Focus

1. **`imageID` formats and kinds.** Accepted: `docker-pullable://repo@sha256:…` and `repo@sha256:…` (repository digest), and bare `sha256:…` or `docker://sha256:…` (image ID, the config digest). The value is `""` while a pod is pending. Empty or unparsable values are skipped with no error loop. The kind is recorded, because an image ID can never be pulled. Tests in Tasks 4 and 7.
2. **The scope changes without any pod changing.** This happens through `OperatorConfig` or through a namespace's labels. The affected digests must leave the inventory within seconds. Tests in Task 7.
3. **Pod lifecycle edge cases:**
   - Finished CronJob/Job pods still count, so digests don't flap.
   - Ephemeral debug containers don't count.
   - A manually deleted `ImageInventory` comes back.
   - Renaming the cluster leaves no orphaned entry.

   Tests in Task 7.
4. **The LLM key's Secret is missing or lacks its label, the endpoint returns 401, or a gateway echoes the key in its error body.** `ModelConfig` shows `Ready=False` (`SecretNotFound` / `Unauthorized`) and emits `ModelUnavailable`. The key appears nowhere. Tests in Tasks 8 and 9; the e2e in Task 10 proves the RBAC for Secrets and events in a real cluster.
5. **The probe doesn't hammer the LLM endpoint.** A `ModelConfig` status write mustn't trigger the next probe, and an endpoint without `/models` must still be probed correctly. Tests in Tasks 8 and 9.

---

## File Structure

```
vexplain/
├── PROJECT, Makefile, go.mod, cmd/main.go         (scaffold; main wires everything)
├── api/config/v1alpha1/
│   ├── common_types.go          condition types/reasons, SecretKeyRef
│   ├── operatorconfig_types.go
│   ├── collector_types.go
│   └── modelconfig_types.go
├── api/inventory/v1alpha1/
│   └── imageinventory_types.go
├── internal/settings/
│   ├── effective.go             OperatorConfig → effective settings with defaults
│   └── clusterid.go             stable cluster identity (kube-system UID)
├── internal/scope/matcher.go     include/exclude label selectors
├── internal/workloads/
│   ├── digest.go                imageID parsing, pod → images, field index
│   └── owner.go                 pod → top-level owner
├── internal/inventory/
│   ├── names.go                 digest ↔ object name
│   ├── store.go                 Store interface + Observation
│   ├── crdstore.go              CRD-backed Store with size/write metrics
│   └── gauge.go                 periodic vexplain_images_running
├── internal/collector/
│   ├── registry.go              collector health registry
│   └── defaults.go              EnsureDefaults
├── internal/setup/setup.go       controller wiring shared by main and envtest suites
├── config/rbac/manager_secrets_rolebinding.yaml   binds the namespaced Secret Role
├── internal/metrics/metrics.go   all custom Prometheus metrics
├── internal/llm/
│   ├── client.go                chat completions with tools
│   ├── probe.go                 endpoint probe
│   └── observer.go              Prometheus observer
├── internal/controller/config/
│   ├── operatorconfig_controller.go
│   ├── collector_controller.go
│   └── modelconfig_controller.go
├── internal/controller/inventory/
│   └── podinventory_controller.go
├── cmd/llm-smoke/main.go         two-turn tool-calling check against the real model
├── hack/inventory-load/main.go   synthetic object-size indicator from a real CVE export
└── test/e2e/                     (scaffold) kind-based e2e
```

---

### Task 1: Repository, scaffold and API linting

**Files:**
- Create: the scaffold via kubebuilder
- Modify: `.golangci.yml` (kube-api-linter), `config/manager/manager.yaml` (`POD_NAMESPACE`)

**Interfaces:**
- Produces:
  - the module `github.com/bedag/vexplain`
  - packages `api/config/v1alpha1` (imported as `configv1alpha1`) and `api/inventory/v1alpha1` (imported as `inventoryv1alpha1`)
  - make targets `test`, `lint`, `manifests`, `generate`, `test-e2e`

- [ ] **Step 1: Scaffold.**
  - The repository already exists (`main`, with the docs committed). Work on a feature branch or worktree, never directly on `main`.
  - Run the commands in the repository root; kubebuilder allows the existing `docs/*.md` and `.git`.

```bash
kubebuilder init --domain vexplain.bedag.ch --repo github.com/bedag/vexplain --project-name vexplain
kubebuilder edit --multigroup=true
kubebuilder create api --group config --version v1alpha1 --kind OperatorConfig --namespaced=false --resource --controller
kubebuilder create api --group config --version v1alpha1 --kind Collector --namespaced=false --resource --controller
kubebuilder create api --group config --version v1alpha1 --kind ModelConfig --namespaced=false --resource --controller
kubebuilder create api --group inventory --version v1alpha1 --kind ImageInventory --namespaced=false --resource --controller=false
```

Expected: every command exits 0, and `PROJECT` lists 4 resources in 2 groups.

- [ ] **Step 2: Enable kube-api-linter** as a golangci-lint module plugin (custom-gcl build, per its README), scoped to `api/...`. If the v4.15 scaffold already wires it, keep that wiring.
- [ ] **Step 3: Add `POD_NAMESPACE` to the manager.** In `config/manager/manager.yaml`, add the env var from `fieldRef: metadata.namespace`.
- [ ] **Step 4: Create `internal/setup`.**
  - Move the scaffold's controller wiring from `cmd/main.go` into `setup.Register(mgr, setup.Options{OperatorNamespace string})`.
  - Make both envtest suites (`internal/controller/config`, `internal/controller/inventory`) start a manager with it in `BeforeSuite`, and stop it in `AfterSuite`.
  - The `inventory` group has no scaffolded controller suite, so create its `suite_test.go` modelled on the `config` one.
- [ ] **Step 5: Verify.** Run `make manifests generate && make lint && make test`. Expected: all pass.
- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "chore: scaffold vexplain with kubebuilder (config + inventory groups)"
```

---

### Task 2: `OperatorConfig` API, settings and controller

**Files:**
- Modify:
  - `api/config/v1alpha1/operatorconfig_types.go`
  - `internal/controller/config/operatorconfig_controller.go` and its test
- Create:
  - `api/config/v1alpha1/common_types.go`
  - `internal/settings/effective.go`, `internal/settings/clusterid.go`
  - `internal/settings/effective_test.go`

**Interfaces:**
- Produces:
  - `configv1alpha1.OperatorConfig`, a singleton named `default`.
  - `settings.Effective{ClusterName string; Scope *configv1alpha1.Scope}`
  - `settings.Load(ctx context.Context, r client.Reader) (settings.Effective, error)`: returns the defaults when the object is absent.
  - `settings.ClusterID(ctx context.Context, r client.Reader) (string, error)`: the UID of the `kube-system` namespace.
  - In `common_types.go`: `ConditionReady = "Ready"`, `ReasonValid = "Valid"`, `ReasonInvalid = "Invalid"`, `ReasonUnknownValue = "UnknownValue"`.

- [ ] **Step 1: Define the types** (this is the API contract; add lint markers as needed)

```go
// Scope selects which pods are analysed. An include selector that is absent or empty
// matches everything. Exclude selectors must not be empty: an empty selector would
// match everything and silently exclude the whole cluster.
// +kubebuilder:validation:XValidation:rule="!has(self.excludeNamespaces) || (has(self.excludeNamespaces.matchLabels) && size(self.excludeNamespaces.matchLabels) > 0) || (has(self.excludeNamespaces.matchExpressions) && size(self.excludeNamespaces.matchExpressions) > 0)",message="excludeNamespaces must not be empty"
// +kubebuilder:validation:XValidation:rule="!has(self.excludePods) || (has(self.excludePods.matchLabels) && size(self.excludePods.matchLabels) > 0) || (has(self.excludePods.matchExpressions) && size(self.excludePods.matchExpressions) > 0)",message="excludePods must not be empty"
type Scope struct {
	// +optional
	IncludeNamespaces *metav1.LabelSelector `json:"includeNamespaces,omitempty"`
	// +optional
	ExcludeNamespaces *metav1.LabelSelector `json:"excludeNamespaces,omitempty"`
	// +optional
	IncludePods *metav1.LabelSelector `json:"includePods,omitempty"`
	// +optional
	ExcludePods *metav1.LabelSelector `json:"excludePods,omitempty"`
}

type OperatorConfigSpec struct {
	// clusterName names this cluster in metrics and in inventory entries.
	// +optional
	// +kubebuilder:default=local
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`
	ClusterName string `json:"clusterName,omitempty"`
	// +optional
	Scope *Scope `json:"scope,omitempty"`
}
```

The type-level rule is `+kubebuilder:validation:XValidation:rule="self.metadata.name == 'default'",message="OperatorConfig is a singleton named 'default'"`. The status holds only `Conditions`. Print columns: Cluster, Ready.

- [ ] **Step 2: Write the failing tests**
  - `internal/settings/effective_test.go` (fake client):
    - `TestLoadDefaultsWhenAbsent`: `ClusterName == "local"`, `Scope == nil`.
    - `TestLoadReadsSpec`: `clusterName: cluster-a` gives `ClusterName == "cluster-a"`.
    - `TestClusterIDIsKubeSystemUID`: a `kube-system` namespace with UID `u-1` gives `"u-1"`. A missing `kube-system` returns an error.
  - envtest (replace the scaffolded test):
    - An `OperatorConfig` named `other` is rejected, with an error containing `singleton named 'default'`.
    - `default` with `spec: {}` gets `clusterName: local` defaulted and reaches `Ready=True`, reason `Valid`, `ObservedGeneration == metadata.generation`.
    - An invalid selector operator in `scope` gives `Ready=False`, reason `Invalid`.
    - `scope.excludeNamespaces: {}` is rejected with `excludeNamespaces must not be empty`. The same goes for `excludePods: {matchLabels: {}}`.
  - Replace the scaffolded sample with a valid `default` object.
- [ ] **Step 3: Run** `go test ./internal/settings/... && make test`. Expected: FAIL (undefined `settings.Load`; condition not set).
- [ ] **Step 4: Implement.**
  - `Load` applies the same defaults as the CRD when the object is absent.
  - The reconciler validates the selectors with `metav1.LabelSelectorAsSelector` and sets `Ready`.
- [ ] **Step 5: Run** `go test ./internal/settings/... && make lint && make test`. Expected: PASS
- [ ] **Step 6: Commit** `git commit -m "feat(api): OperatorConfig singleton, settings and cluster identity"`

---

### Task 3: Scope matcher

**Files:**
- Create: `internal/scope/matcher.go`, `internal/scope/matcher_test.go`

**Interfaces:**
- Consumes: `configv1alpha1.Scope`
- Produces:
  - `scope.New(s *configv1alpha1.Scope) (*scope.Matcher, error)`
  - `(*Matcher).Matches(nsLabels, podLabels map[string]string) bool`

- [ ] **Step 1: Write the failing table test** `TestMatches`:

| scope | ns labels | pod labels | want |
|---|---|---|---|
| nil | any | any | true |
| includeNamespaces `team=a` | `team=a` | – | true |
| includeNamespaces `team=a` | `team=b` | – | false |
| excludeNamespaces `vexplain=off` | `vexplain=off` | – | false |
| include `team=a` + exclude `vexplain=off` | `team=a,vexplain=off` | – | false (exclude wins) |
| includeNamespaces `{}` | `team=b` | – | true (an empty include matches all; an empty exclude is rejected by the API in Task 2) |
| excludePods `app=debug` | – | `app=debug` | false |
| includePods `tier=web` | – | `tier=api` | false |

Also `TestNewRejectsInvalidSelector`: an invalid operator returns an error.

- [ ] **Step 2: Run** `go test ./internal/scope/...`. Expected: FAIL
- [ ] **Step 3: Implement** with `metav1.LabelSelectorAsSelector`. A nil include matches all; any exclude match returns false.
- [ ] **Step 4: Run** `go test ./internal/scope/...`. Expected: PASS
- [ ] **Step 5: Commit** `git commit -m "feat(scope): include/exclude matcher for namespaces and pods"`

---

### Task 4: Reported digests and top-level owners

**Files:**
- Create:
  - `internal/workloads/digest.go`, `internal/workloads/owner.go`
  - `internal/workloads/digest_test.go`, `internal/workloads/owner_test.go`

**Interfaces:**
- Produces:
  - `workloads.ImageRef{Digest, Repository string}`, where `Digest` is `sha256:<64 hex>` and `Repository` is empty for an image ID. Method `(ImageRef) IsImageID() bool`.
  - `workloads.DigestFromImageID(imageID string) (workloads.ImageRef, bool)`
  - `workloads.PodImages(pod *corev1.Pod) (images []workloads.ImageRef, unparsable []string)`:
    - reads `status.initContainerStatuses` and `status.containerStatuses` only; ephemeral containers are skipped
    - `images` is deduplicated by digest (keeping the first repository seen) and sorted by digest
    - `unparsable` lists the names of containers whose `imageID` is non-empty but not parsable, so the caller can make them visible instead of dropping them silently; empty `imageID`s (pending) are not listed
  - `workloads.PodDigestIndex = "inventory.vexplain.bedag.ch/image-digests"` and `workloads.IndexPodDigests(obj client.Object) []string`
  - `workloads.WorkloadRef{APIGroup, Kind, Namespace, Name string}`: the API group is taken from the owner reference's `apiVersion`, and is empty for a bare pod
  - `workloads.ResolveOwner(ctx context.Context, r client.Reader, pod *corev1.Pod) (workloads.WorkloadRef, error)`

- [ ] **Step 1: Write the failing tests**

`TestDigestFromImageID` (h = 64 lowercase hex):

| input | ok | Digest | Repository |
|---|---|---|---|
| `docker-pullable://artifacts.example/lib/nginx@sha256:h` | true | `sha256:h` | `artifacts.example/lib/nginx` |
| `artifacts.example/lib/nginx@sha256:h` | true | `sha256:h` | `artifacts.example/lib/nginx` |
| `sha256:h` | true | `sha256:h` | `""` (image ID) |
| `docker://sha256:h` | true | `sha256:h` | `""` (image ID) |
| `""` | false | | |
| `nginx:1.27` | false | | |
| `repo@sha256:abc` (too short) | false | | |
| `repo@sha256:H` (uppercase hex) | false | | |

`TestPodImages`:
- an init and an app container with the same digest give `len(images) == 1`
- an ephemeral container's digest is not included
- a pending pod with an empty `imageID` gives `len(images) == 0` and `len(unparsable) == 0`
- a container with `imageID: "nginx:1.27"` gives `unparsable == ["<its name>"]`

`TestResolveOwner` (fake client):

| chain | result |
|---|---|
| Pod → ReplicaSet → Deployment `web` | `{apps, Deployment, ns, web}` |
| Pod → ReplicaSet → `argoproj.io` Rollout `r` | `{argoproj.io, Rollout, ns, r}`, with the Rollout not fetched |
| Pod → ReplicaSet without an owner | `{apps, ReplicaSet, ns, rs}` |
| Pod → Job → CronJob `c` | `{batch, CronJob, ns, c}` |
| Pod → StatefulSet `s` | `{apps, StatefulSet, ns, s}`, with the StatefulSet not fetched |
| Pod without an owner | `{"", Pod, ns, podName}` |
| Pod → ReplicaSet that no longer exists | `{apps, ReplicaSet, ns, rsName}`, no error |

- [ ] **Step 2: Run** `go test ./internal/workloads/...`. Expected: FAIL
- [ ] **Step 3: Implement**
  - Strip a `scheme://` prefix. If an `@` is present, the part after the last `@` is the digest and the part before it is the repository. Otherwise the whole value must be the digest. Require `sha256:` plus 64 lowercase hex.
  - `ResolveOwner` takes the pod's controller owner reference. Only when it is a ReplicaSet (`apps`) or a Job (`batch`) does it fetch that object and return *its* controller owner, without fetching that owner. This keeps RBAC to pods, ReplicaSets and Jobs, and makes Rollouts and other controllers work.
- [ ] **Step 4: Run** `go test ./internal/workloads/...`. Expected: PASS
- [ ] **Step 5: Commit** `git commit -m "feat(workloads): reported digests from pod status and top-level owners"`

---

### Task 5: `ImageInventory` API, Store and inventory metrics

**Files:**
- Modify: `api/inventory/v1alpha1/imageinventory_types.go`
- Create:
  - `internal/inventory/names.go`, `store.go`, `crdstore.go`, `crdstore_test.go`
  - `internal/metrics/metrics.go`

**Interfaces:**
- Consumes: `workloads.WorkloadRef` (Task 4)
- Produces:
  - `inventory.NameForDigest(digest string) string` (`sha256:<h>` → `sha256-<h>`) and `inventory.DigestForName(name string) (string, bool)`
  - The store:
    ```go
    type Observation struct {
        Cluster, ClusterID string
        DigestKind         inventoryv1alpha1.DigestKind
        Repositories       []string
        NamespaceCount     int32
        Workloads          []workloads.WorkloadRef // all of them; the store sorts and keeps the first 100
    }
    type Store interface {
        Get(ctx context.Context, digest string) (*inventoryv1alpha1.ImageInventory, error) // nil, nil if absent
        // Observe creates the object if needed and sets this cluster's entry. It removes any
        // other entry with the same ClusterID (a renamed cluster) and writes nothing if the
        // result is unchanged.
        Observe(ctx context.Context, digest string, obs Observation) error
        // Forget removes every entry whose cluster name is `cluster` or whose ClusterID is
        // `clusterID`. That also covers a rename that happened while the digest disappeared.
        // It deletes the object when no entries remain. No error if absent.
        Forget(ctx context.Context, digest, cluster, clusterID string) error
    }
    func NewCRDStore(c client.Client) Store
    ```
  - `internal/metrics`, registered with `ctrlmetrics.Registry` in `init()`:
    - `InventoryObjectBytes`: HistogramVec `vexplain_inventory_object_bytes{cluster}`, buckets `prometheus.ExponentialBuckets(1024, 2, 12)`
    - `InventoryWritesTotal`: CounterVec `vexplain_inventory_writes_total{cluster,op}`, with op `create|update|delete`. `create` counts object creations, `update` counts status writes, `delete` counts deletions.
    - `ImagesRunning`: GaugeVec `vexplain_images_running{cluster}`

- [ ] **Step 1: Define the types** (0011, 0019)

```go
// DigestKind says what the reported digest is. Open enum; more values may follow.
// +kubebuilder:validation:Enum=RepoDigest;ImageID
type DigestKind string

type ImageInventorySpec struct {
	// digest is the digest the container runtime reports for running containers:
	// a repository digest (often a multi-arch index) or an image ID.
	// +required
	// +kubebuilder:validation:Pattern=`^sha256:[a-f0-9]{64}$`
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="digest is immutable"
	Digest string `json:"digest"`
}

// WorkloadReference points to a workload, and so to its WorkloadReport (phase 2).
type WorkloadReference struct {
	// apiGroup is empty for the core group (bare pods).
	// +optional
	// +kubebuilder:validation:MaxLength=253
	APIGroup string `json:"apiGroup,omitempty"`
	// +required
	// +kubebuilder:validation:MaxLength=63
	Kind string `json:"kind"`
	// +required
	// +kubebuilder:validation:MaxLength=63
	Namespace string `json:"namespace"`
	// +required
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`
}

type ClusterPresence struct {
	// +required
	// +kubebuilder:validation:MaxLength=63
	Cluster string `json:"cluster"`
	// +required
	// +kubebuilder:validation:MaxLength=64
	ClusterID string `json:"clusterID"`
	// +required
	// +kubebuilder:validation:Minimum=0
	NamespaceCount int32 `json:"namespaceCount"`
	// +required
	// +kubebuilder:validation:Minimum=0
	WorkloadCount int32 `json:"workloadCount"`
	// workloads lists the first 100 workloads, sorted by namespace, kind and name. If it is
	// shorter than workloadCount, the full list comes from the cluster's WorkloadReports.
	// +optional
	// +listType=map
	// +listMapKey=namespace
	// +listMapKey=kind
	// +listMapKey=name
	// +kubebuilder:validation:MaxItems=100
	Workloads []WorkloadReference `json:"workloads,omitempty"`
	// +optional
	// +listType=set
	// +kubebuilder:validation:MaxItems=32
	Repositories []string `json:"repositories,omitempty"`
	// +required
	FirstSeenTime metav1.Time `json:"firstSeenTime"`
}

type ImageInventoryStatus struct {
	// +optional
	DigestKind DigestKind `json:"digestKind,omitempty"`
	// +optional
	// +listType=map
	// +listMapKey=cluster
	// +kubebuilder:validation:MaxItems=256
	Clusters []ClusterPresence `json:"clusters,omitempty"`
	// No conditions yet: nothing in phase 1 would set them. They arrive with the scanner.
}
```

The root rule is `+kubebuilder:validation:XValidation:rule="self.metadata.name == self.spec.digest.replace(':', '-')",message="name must be the digest with ':' replaced by '-'"`. Repository strings get `MaxLength=255` (via `+kubebuilder:validation:items:MaxLength`). Print columns: Digest, Kind, Clusters (`.status.clusters[*].cluster`), Age.

- [ ] **Step 2: Write the failing tests**
  - **Setup:** `crdstore_test.go`, with a fake client using `WithStatusSubresource(&inventoryv1alpha1.ImageInventory{})`.
  - **Metrics:** counters are read as deltas around each call; the histogram's sample count is read through `dto.Metric`.
  - **Notation:** `obs(a,2,3)` means cluster `a`, ID `id-a`, 2 namespaces, workloads `w1…w3` (Deployments in `ns1`), repository `r`.
  - `TestNamesRoundTrip`: `DigestForName(NameForDigest(d)) == d`; `DigestForName("foo")` returns `false`.
  - `TestObserveCreates`: `Observe(d, obs(a,2,3))` creates the object, with:
    - `spec.digest == d` and `status.digestKind == RepoDigest`
    - one entry `{a, id-a, namespaceCount 2, workloadCount 3, workloads [w1, w2, w3], [r]}`, with a non-zero `FirstSeenTime`
    - `create` +1 and `update` +1
  - `TestObserveSkipsUnchanged`: the same observation again, with the workloads in a different order, leaves `update` unchanged.
  - `TestObserveKeepsFirstSeen`: `obs(a,2,4)` adds `update` +1, with `FirstSeenTime` unchanged.
  - `TestObserveCapsWorkloads`: 150 workloads are stored as `workloadCount: 150` with the first 100 after sorting.
  - `TestObserveTwoClusters`: `a` then `b` gives two entries, sorted by cluster.
  - `TestObserveRenamedCluster`: after `obs(a,…)`, an observation for cluster `a2` with the same `id-a` leaves only the entry `a2`.
  - `TestObserveCapsRepositories`: 40 distinct repositories are stored as the first 32 after sorting. A write with more than 32 would be rejected by the schema.
  - `TestForget`:
    - with entries `a` and `b`, `Forget(d, "a", "id-a")` leaves `[b]`
    - `Forget(d, "b", "id-b")` deletes the object, with `delete` +1
    - `Forget` on an absent digest returns no error
  - `TestForgetByClusterID`: with an entry `a` (ID `id-a`), `Forget(d, "renamed", "id-a")` deletes the object.
  - `TestObjectBytesRecorded`: the histogram's sample count rises by one per create and per status write.
  - Replace the scaffolded `ImageInventory` sample: a valid one has `metadata.name` = the digest with `:` replaced by `-`.
- [ ] **Step 3: Run** `go test ./internal/inventory/...`. Expected: FAIL
- [ ] **Step 4: Implement.**
  - Create with the spec, then write the status through the status subresource.
  - Wrap read-modify-write in `retry.RetryOnConflict`.
  - Sort and deduplicate entries, workloads and repositories, and cap workloads at 100 and repositories at 32, before comparing.
  - Measure the object size as the `json.Marshal` length of the whole object.
- [ ] **Step 5: Run** `make manifests generate && make lint && go test ./internal/inventory/...`. Expected: PASS
- [ ] **Step 6: Commit** `git commit -m "feat(inventory): ImageInventory with per-cluster presence and CRD store"`

---

### Task 6: `Collector` API, defaults and health registry

**Files:**
- Modify:
  - `api/config/v1alpha1/collector_types.go`
  - `internal/controller/config/collector_controller.go` and its test
- Create:
  - `internal/collector/registry.go`, `internal/collector/defaults.go`
  - `internal/collector/registry_test.go`

**Interfaces:**
- Produces:
  - `CollectorType`, an open enum with `Workloads` only for now.
  - `CollectorSpec{Type CollectorType; Workloads *WorkloadsCollectorSpec}`. `WorkloadsCollectorSpec` is an empty struct reserved for settings.
  - Spec rule: `has(self.workloads) == (self.type == 'Workloads')`.
  - Root rule: `self.metadata.name == self.spec.type.lowerAscii()` (one `Collector` per type, named after it).
  - Status: `Conditions` plus `LastSuccessTime *metav1.Time`, taken from the registry. The design promises it, and it's what an admin checks first.
  - `setup.Options.CollectorResync time.Duration`: default 30s; tests use 1s.
  - `collector.Registry`:
    - `NewRegistry() *Registry`
    - `ReportSuccess(t configv1alpha1.CollectorType)`
    - `ReportFailure(t configv1alpha1.CollectorType, err error)`
    - `Health(t) (lastSuccess time.Time, lastErr error, known bool)`
  - `collector.EnsureDefaults(ctx context.Context, c client.Client) error`:
    - creates `Collector` `workloads` if it's missing, and never overwrites one
    - added in `cmd/main.go` with `mgr.Add(manager.RunnableFunc(...))`, so it runs after the caches sync, on the leader
  - Reasons: `Healthy`, `CollectorFailing`, `NoData`, `UnknownValue`.
  - Event `CollectorUnhealthy` (Warning).

- [ ] **Step 1: Write the failing tests**
  - Registry unit test:
    - an unknown type reports `known == false`
    - `ReportFailure` followed by `ReportSuccess` leaves `lastErr == nil`
  - envtest (replace the scaffolded test):
    - `EnsureDefaults` on an empty cluster creates `workloads`.
    - It leaves an existing `workloads` with a custom label untouched.
    - `type: Workloads` without `workloads: {}` is rejected.
    - A `Collector` named `foo` of type `Workloads` is rejected.
    - Health states:
      - no report yet gives `Ready=Unknown`, reason `NoData`
      - after `ReportSuccess`, `Ready=True`, reason `Healthy`, and `LastSuccessTime` is set
      - after `ReportFailure`, `Ready=False`, reason `CollectorFailing`, with a `CollectorUnhealthy` event in namespace `default` whose `count == 1`, even after several further resyncs

      Read events with a direct (uncached) client, using a field selector on `involvedObject.name`.
  - Replace the scaffolded sample with the valid `workloads` object.
- [ ] **Step 2: Run** `make test`. Expected: FAIL
- [ ] **Step 3: Implement.**
  - The reconciler maps `Health` to the condition and `LastSuccessTime`. Health reflects the last reported outcome, with no staleness timer.
  - It requeues every `CollectorResync` and filters with `GenerationChangedPredicate`.
  - It emits the event only on a transition to `False`. This is the first task that emits events, so it also adds the events RBAC marker from the Global Constraints.
  - Deleting `workloads` doesn't stop the inventory; `EnsureDefaults` recreates it at the next start. Document this on the type.
- [ ] **Step 4: Run** `make lint && make test`. Expected: PASS
- [ ] **Step 5: Commit** `git commit -m "feat(collector): Collector API, default workloads collector, health registry"`

---

### Task 7: Pod inventory controller

**Files:**
- Create:
  - `internal/controller/inventory/podinventory_controller.go` and its test (the suite exists since Task 1)
  - `internal/inventory/gauge.go` and its test
- Modify: `internal/setup/setup.go` (field index, controller, gauge runnable, registry), `internal/metrics/metrics.go`

**Interfaces:**
- Consumes:
  - `workloads.PodImages`, `IndexPodDigests`, `PodDigestIndex`, `ResolveOwner`
  - `scope.New`, `settings.Load`, `settings.ClusterID`
  - `inventory.Store`, `NameForDigest`, `DigestForName`
  - `collector.Registry`
  - `metrics.ImagesRunning`
- Produces:
  - `PodInventoryReconciler{Client client.Client; Store inventory.Store; Registry *collector.Registry}`, reconciling requests named `NameForDigest(digest)`.
  - `inventory.GaugeUpdater{Client client.Reader; Cluster func() string; ClusterID string; Interval time.Duration}`, a `manager.Runnable`. `setup.Options.GaugeInterval` defaults to 30s; tests use 1s.
  - `metrics.UnparsableImageIDsTotal`: CounterVec `vexplain_unparsable_image_ids_total{cluster}`, so an alert can fire when containers are being skipped.

- [ ] **Step 1: Write the failing tests** (envtest; set `imageID` with a pod status update, because envtest has no kubelet; delete pods with `GracePeriodSeconds(0)`):
  - A pod with digest D, owned through a ReplicaSet by Deployment `web`, gives `ImageInventory` `NameForDigest(D)` with:
    - `digestKind: RepoDigest`
    - `clusters == [{local, <kube-system UID>, namespaceCount 1, workloadCount 1, workloads [{apps, Deployment, <ns>, web}], [repo]}]`
  - Two pods of `web` plus a bare pod `p` in the same namespace give `workloadCount == 2`, with `workloads` containing `{apps, Deployment, <ns>, web}` and `{"", Pod, <ns>, p}`. One more pod in a second namespace gives `namespaceCount == 2`.
  - A pod in phase `Succeeded` still counts.
  - Empty and ephemeral images:
    - A pending pod with an empty `imageID` creates nothing.
    - A digest that only an ephemeral container reports creates nothing.
  - Deleting all pods on D deletes the object.
  - **Scope through `OperatorConfig`:** setting `excludeNamespaces` to match the pod's namespace deletes D's object within 10s, with no pod change.
  - **Scope through namespace labels:** with `excludeNamespaces: {matchLabels: {vexplain: "off"}}` already set (quoted: unquoted `off` is a YAML boolean), labelling the namespace `vexplain=off` deletes D's object within 10s.
  - **Self-healing:** deleting D's `ImageInventory` by hand while the pod runs recreates it within 10s.
  - **Rename:** changing `clusterName` from `local` to `kind-a` leaves exactly one entry, `kind-a`.
  - **CEL:**
    - creating an `ImageInventory` whose name doesn't match its digest is rejected
    - changing `spec.digest` is rejected
  - **Rename while the digest disappears:** this cluster renames itself after its pods on a digest are gone. Simulate it with an `ImageInventory` created by hand, with one entry under a former cluster name (`old-name`) carrying this cluster's ID, and no pods on its digest. It is deleted within 10s (`Forget` by cluster ID).
  - **Unparsable `imageID`:** a pod whose container reports `imageID: "nginx:1.27"` raises `vexplain_unparsable_image_ids_total{cluster="local"}` by at least 1 and creates no object.
  - **Health:** after a successful reconcile, `Registry.Health(Workloads)` reports success.
  - `GaugeUpdater` unit tests (fake client):
    - two objects with an entry for `local` and one for `other` set the gauge to 2 for `local`
    - after the cluster name changes from `local` to `kind-a`, no `{cluster="local"}` series is left
- [ ] **Step 2: Run** `make test`. Expected: FAIL
- [ ] **Step 3: Implement**
  - **Watches** (builder with `Named("podinventory")`):
    - Pods → one request per digest in `PodImages`. Old and new objects are both mapped on update. Containers in `unparsable` increment `UnparsableImageIDsTotal` and are logged with namespace, pod and container name.
    - Namespaces → the digests of all pods in that namespace (list from the cache).
    - `OperatorConfig` → every digest in the pod index plus every existing `ImageInventory`.
    - `ImageInventory` → its own name.
  - **Reconcile:**
    1. Resolve the digest with `DigestForName`. Ignore names that aren't digests.
    2. Load the settings, the cached cluster ID and the scope matcher. An invalid scope → `ReportFailure` and return the error.
    3. List pods with `client.MatchingFields{PodDigestIndex: digest}`, whatever their phase, and keep those whose namespace labels and pod labels match the scope.
    4. Count distinct namespaces, collect the distinct `ResolveOwner` results as `Observation.Workloads` (the store keeps the first 100), and collect the repositories. `DigestKind` is `ImageID` when the digest's `ImageRef` has no repository, otherwise `RepoDigest`.
    5. No pods: `Store.Forget(digest, clusterName, clusterID)`. Otherwise: `Store.Observe`.
    6. `ReportSuccess`.
  - **`GaugeUpdater`:** every `Interval`, list `ImageInventory` with `client.UnsafeDisableDeepCopy`. Call `ImagesRunning.Reset()`, then set the gauge for the current cluster name to the number of objects with an entry for this cluster's ID. The reset drops the series of a former cluster name.
  - **RBAC markers:**
    - get/list/watch on pods, namespaces, `apps` replicasets and `batch` jobs
    - get/list/watch on `config` operatorconfigs
    - full rights on `inventory` imageinventories and `imageinventories/status`
- [ ] **Step 4: Run** `make manifests && make lint && make test`. Expected: PASS
- [ ] **Step 5: Commit** `git commit -m "feat(inventory): reconcile reported digests into per-cluster presence with scope"`

---

### Task 8: LLM client

**Files:**
- Create:
  - `internal/llm/client.go`, `probe.go`, `observer.go`
  - `internal/llm/client_test.go`, `probe_test.go`, `observer_test.go`
- Modify: `internal/metrics/metrics.go` (LLM metrics)

**Interfaces:**
- Produces:
  ```go
  // Secret holds the API key. String, MarshalJSON and MarshalLog return "[redacted]";
  // only the HTTP layer converts it with string(s).
  type Secret string

  type Config struct {
      BaseURL, Model   string
      APIKey           Secret
      Timeout          time.Duration // ≤0 → 60s
      MaxConcurrent    int           // ≤0 → 1
      TemperatureMilli int32         // always sent, so 0 means 0.0, not "server default"
  }
  type Message struct {
      Role, Content string
      ToolCalls     []ToolCall
      ToolCallID    string
  }
  type Tool struct {
      Name, Description string
      Parameters        json.RawMessage // JSON schema
  }
  type ToolCall struct {
      ID, Name  string
      Arguments string // raw text as returned; may be invalid JSON, so the caller validates
  }
  type Request struct {
      Messages   []Message
      Tools      []Tool
      ToolChoice string // "", "auto", "required", "none"
      MaxTokens  int    // 0 = server default
  }
  type Usage struct{ PromptTokens, CompletionTokens int }
  type Response struct {
      Message      Message
      FinishReason string
      Usage        Usage
  }
  type Observation struct {
      Model    string
      Outcome  string // ok|error|unauthorized|timeout
      Duration time.Duration
      Usage    Usage
  }

  func New(cfg Config, opts ...Option) *Client
  func WithObserver(func(Observation)) Option
  func WithHTTPClient(*http.Client) Option
  func (c *Client) Complete(ctx context.Context, req Request) (*Response, error)
  func Probe(ctx context.Context, cfg Config, hc *http.Client) (latency time.Duration, err error)
  func PrometheusObserver(cluster func() string) func(Observation)

  var ErrUnauthorized, ErrModelNotFound, ErrUnreachable error
  ```
  - `Complete` posts to `{BaseURL}/chat/completions`.
  - `Probe` sends `GET {BaseURL}/models`:
    - 401/403 → `ErrUnauthorized`
    - 200 whose `data[].id` lacks `Model` → `ErrModelNotFound`
    - 404/405 (no models endpoint) → falls back to `Complete` with `MaxTokens: 1` and the message `"ping"`. There, 400 or 404 → `ErrModelNotFound` (LiteLLM answers an unknown model with 400), and 401/403 → `ErrUnauthorized`.
    - 429 anywhere → `nil`: the endpoint is up, just busy
    - network errors and 5xx → `ErrUnreachable`
  - Errors carry the status code and a short reason. They never carry response bodies or request headers.
  - The default transport uses `Proxy: http.ProxyFromEnvironment`.
  - `metrics` gains:
    - `LLMRequestsTotal{cluster,model,outcome}`
    - `LLMRequestDurationSeconds{cluster,model}`
    - `LLMTokensTotal{cluster,model,kind}`, with kind `prompt|completion`

- [ ] **Step 1: Write the failing tests** (`httptest.NewTLSServer`, with the client built via `WithHTTPClient(server.Client())`):
  - `TestCompleteSendsOpenAIRequest`. The server asserts:
    - `Authorization: Bearer k`
    - `model == "m"`
    - `temperature == 0.2` for `TemperatureMilli: 200`
    - `tools[0].type == "function"` and `tools[0].function.name == "lookup"`
    - `max_tokens` absent when `MaxTokens == 0`
  - `TestCompleteSendsZeroTemperature`: `TemperatureMilli: 0` sends `"temperature": 0`.
  - `TestNewAppliesDefaults`: a `Config` with zero `Timeout` and `MaxConcurrent` still completes a request against a fast server.
  - `TestSecretRedacts`: `fmt.Sprintf("%v %+v", cfg, cfg)` and `json.Marshal(cfg)` don't contain the key.
  - `TestCompleteParsesToolCalls`: a response with `tool_calls[0]{id:"c1", function:{name:"lookup", arguments:"{\"pkg\":\"brotli\"}"}}` gives `ToolCalls[0].Arguments == "{\"pkg\":\"brotli\"}"`. `Usage` comes from `usage.prompt_tokens` and `usage.completion_tokens`.
  - `TestCompleteReplaysToolCalls`:
    - the history contains an assistant tool call `{ID: "c1", Name: "lookup", Arguments: "{bad"}` and a `tool` message with `ToolCallID: "c1"`
    - the request body is valid JSON, with `tool_calls[0].type == "function"`, `tool_calls[0].function.name == "lookup"`, `"arguments":"{bad"` and `"tool_call_id":"c1"`
    - the client sends what it's given; never replaying invalid arguments is the agent loop's policy (design 6.6)
  - `TestCompleteUnauthorizedDoesNotLeakKey`: the server returns 401 with a body that echoes the received `Authorization` header. With key `secret-key-123`, `errors.Is(err, ErrUnauthorized)` holds, and `err.Error()` contains neither the key nor the body.
  - `TestCompleteRespectsMaxConcurrent`: with `MaxConcurrent: 1` and 3 parallel calls, the server's in-flight count never exceeds 1.
  - `TestCompleteTimeout`: when the server is slower than `Timeout`, the error wraps `context.DeadlineExceeded` and the observer sees `Outcome == "timeout"`.
  - `TestProbe`:

    | server | result |
    |---|---|
    | 200 with the model listed | `nil` |
    | 200 without the model | `ErrModelNotFound` |
    | 401 | `ErrUnauthorized` |
    | 503 | `ErrUnreachable` |
    | 404 on `/models`, 200 on chat | `nil` |
    | 404 on `/models`, 404 on chat | `ErrModelNotFound` |
    | 404 on `/models`, 400 on chat | `ErrModelNotFound` |
    | 429 on `/models` | `nil` |
  - `TestPrometheusObserver`: one `ok` observation with usage 10/5 increments `requests{outcome="ok"}` by 1, `tokens{kind="prompt"}` by 10 and `tokens{kind="completion"}` by 5.
- [ ] **Step 2: Run** `go test ./internal/llm/...`. Expected: FAIL
- [ ] **Step 3: Implement.**
  - `New` applies the defaults for values ≤0. A buffered-channel semaphore of that size enforces `MaxConcurrent`.
  - Error messages carry the status code, never response bodies or request headers.
  - The `tool` role carries `tool_call_id`. Assistant messages carry `tool_calls` with `type: "function"`.
- [ ] **Step 4: Run** `go test ./internal/llm/...`. Expected: PASS
- [ ] **Step 5: Commit** `git commit -m "feat(llm): OpenAI-compatible client, probe with fallback, Prometheus observer"`

---

### Task 9: `ModelConfig` API and probing controller

**Files:**
- Modify:
  - `api/config/v1alpha1/modelconfig_types.go`, `api/config/v1alpha1/common_types.go`
  - `internal/controller/config/modelconfig_controller.go` and its test
  - `internal/setup/setup.go`, `config/rbac/kustomization.yaml`
- Create: `config/rbac/manager_secrets_rolebinding.yaml`

**Interfaces:**
- Consumes: `llm.Probe`, `llm.Config`, `llm.Err*`; the operator namespace from `POD_NAMESPACE`
- Produces:
  - `configv1alpha1.ModelConfig`
  - `SecretKeyRef{Name, Key string}`
  - Reasons: `Available`, `SecretNotFound`, `Unauthorized`, `ModelNotFound`, `EndpointUnreachable`, `UnknownValue`
  - Event `ModelUnavailable`
  - `ModelConfigReconciler{…; HTTPClient *http.Client}`, filled from `setup.Options.HTTPClient` (nil → the proxy-aware default; tests pass the TLS test server's client)
  - `(*ModelConfigReconciler).ClientConfig(ctx context.Context, name string) (llm.Config, error)` for later phases
  - `configv1alpha1.LLMAPIKeyLabel = "vexplain.bedag.ch/llm-api-key"`: a referenced Secret must carry this label with value `"true"`

- [ ] **Step 1: Define the types** (add lint markers as needed)

```go
// Provider is an open enum; more values may follow.
// +kubebuilder:validation:Enum=OpenAICompatible
type Provider string

type ModelConfigSpec struct {
	// +optional
	// +kubebuilder:default=OpenAICompatible
	Provider Provider `json:"provider,omitempty"`
	// endpoint is the base URL. HTTPS only, because the API key travels with every request.
	// +required
	// +kubebuilder:validation:MaxLength=2048
	// +kubebuilder:validation:Pattern=`^https://`
	Endpoint string `json:"endpoint"`
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Model string `json:"model"`
	// apiKeySecretRef names a Secret in the operator namespace that carries the label
	// vexplain.bedag.ch/llm-api-key: "true". Unlabelled Secrets are treated as missing.
	// +required
	APIKeySecretRef SecretKeyRef `json:"apiKeySecretRef"`
	// +optional
	// +kubebuilder:default=60
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=600
	RequestTimeoutSeconds *int32 `json:"requestTimeoutSeconds,omitempty"`
	// +optional
	// +kubebuilder:default=2
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=64
	MaxConcurrentRequests *int32 `json:"maxConcurrentRequests,omitempty"`
	// +optional
	// +kubebuilder:default=200
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=2000
	TemperatureMilli *int32 `json:"temperatureMilli,omitempty"`
	// +optional
	// +kubebuilder:default=300
	// +kubebuilder:validation:Minimum=30
	// +kubebuilder:validation:Maximum=86400
	ProbeIntervalSeconds *int32 `json:"probeIntervalSeconds,omitempty"`
}

type ModelConfigStatus struct {
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
	// +optional
	LastProbeTime *metav1.Time `json:"lastProbeTime,omitempty"`
	// +optional
	LastProbeLatencyMilliseconds *int64 `json:"lastProbeLatencyMilliseconds,omitempty"`
}
```

Print columns: Endpoint, Model, Ready, Latency(ms).

- [ ] **Step 2: Write the failing envtest tests.**
  - **Setup:** replace the scaffolded test. The endpoint is an `httptest.NewTLSServer` that counts its hits, and the suite passes `server.Client()` as `setup.Options.HTTPClient`. Create the `vexplain-system` namespace first. Unless a case says otherwise, Secrets carry the label.

| case | expected |
|---|---|
| Secret present, model listed | `Ready=True`, reason `Available`, `LastProbeLatencyMilliseconds` set |
| Secret missing | `Ready=False`, reason `SecretNotFound`, and a `ModelUnavailable` event in `default` with `count == 1` after several requeues |
| Secret present but without the label | `Ready=False`, reason `SecretNotFound`; the message names the required label |
| Server returns 401 with a body echoing the key | `Ready=False`, reason `Unauthorized`; the key appears in no condition message, no event, and nothing logged (capture with a `logr` sink in the test) |
| Model not listed | reason `ModelNotFound` |
| `endpoint: http://…` | rejected by the API server |
| Secret created after the `ModelConfig` (initially `SecretNotFound`) | turns `Ready=True` within 10s |
| After `Ready=True` | the server's hit count stays the same for 5s, so status writes don't cause new probes |
| `Reconcile` called directly | returns `RequeueAfter == 300s` |

  - Replace the scaffolded sample with a valid `default` object (an `https` endpoint, plus a labelled Secret manifest next to it that has no real key).
- [ ] **Step 3: Run** `make test`. Expected: FAIL
- [ ] **Step 4: Implement.**
  - **Watches:**
    - `For(&ModelConfig{}, builder.WithPredicates(predicate.GenerationChangedPredicate{}))`
    - Secrets in the operator namespace, mapped to the `ModelConfig`s that reference them
  - **Probe:** 10s timeout, independent of `requestTimeoutSeconds`, so a reconcile worker is never blocked for long.
  - **Secret access:**
    - A namespaced `Role` comes from `+kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch,namespace=vexplain-system`.
    - controller-gen emits that Role, but nothing binds it, and the scaffold only binds the ClusterRole. Add `config/rbac/manager_secrets_rolebinding.yaml` (RoleBinding `manager-secrets-rolebinding` → Role `manager-role` → ServiceAccount `controller-manager`, in `vexplain-system`) and list it in `config/rbac/kustomization.yaml`. Without it, the Secret informer gets 403 in a real cluster, cache sync times out and the manager exits. envtest doesn't enforce RBAC, so only the e2e in Task 10 catches this.
    - `cache.Options.ByObject` limits the Secret informer to the operator namespace and to the label `vexplain.bedag.ch/llm-api-key=true`. Unlabelled Secrets are never loaded.
    - The controller also checks the label on the Secret it reads. That keeps the rule even if someone later changes the cache options.
  - **Event:** emitted only on a transition to not ready.
- [ ] **Step 5: Run** `make manifests && make lint && make test`. Expected: PASS
- [ ] **Step 6: Commit** `git commit -m "feat(model): ModelConfig with secret ref, safe probing and ModelUnavailable event"`

---

### Task 10: Tool-calling smoke test, e2e, early size indicator

**Files:**
- Create:
  - `cmd/llm-smoke/main.go`
  - `hack/inventory-load/main.go`
  - `config/samples/`: OperatorConfig `default`, Collector `workloads`, ModelConfig `default`
  - `docs/measurements/2026-phase1.md`
- Modify: `test/e2e/e2e_test.go`

**Interfaces:**
- Consumes: `llm.New`, `Complete`; `inventory.NewCRDStore`, `Observe`; all controllers.
- Produces:
  - a go/no-go on the model's tool calling
  - an early indicator of object sizes

- [ ] **Step 1: Write `llm-smoke`.**
  - **Flags:** `--endpoint`, `--model`, `--runs=20`. The key comes from env `VEXPLAIN_LLM_API_KEY`.
  - **Each run has two turns:**
    1. A system message and a user question about a Brotli package, with the tools `lookup_package(name string)` and `submit_answer(text string)`, and `ToolChoice: "auto"`. Expected: exactly one `lookup_package` call with JSON-parseable arguments.
    2. Send back the assistant message plus a `tool` message carrying the lookup result. Use `ToolChoice: "required"`. Expected: a `submit_answer` call with JSON-parseable arguments.
  - **Scoring:** a run is ok only if both turns are. Print `tool_call_ok=N/20 p50_ms=… p95_ms=…` and exit non-zero below 18/20.
  - **Config:** set `Timeout: 60s`, `MaxConcurrent: 1` and `TemperatureMilli: 200` explicitly, matching the `ModelConfig` defaults.
  - **Informational check** (doesn't affect scoring): replay one assistant tool call with `Arguments: "{bad"` and print whether the server accepts it. Some servers (vLLM) parse replayed arguments and answer 400. The result decides how strictly the phase-4 agent loop must sanitise its history (design 6.6).
- [ ] **Step 2: Run it against the real model**

Run: `VEXPLAIN_LLM_API_KEY=… go run ./cmd/llm-smoke --endpoint <url> --model <model>`

Expected: `tool_call_ok` ≥ 18/20. Record the output in `docs/measurements/2026-phase1.md`. Below that, stop and report to the owner, because the agent loop in phase 4 depends on it.

- [ ] **Step 3: Extend the e2e test** (kind)
  1. Deploy the operator. Its pod becoming ready proves that the Secret informer syncs, i.e. that the Secret RoleBinding from Task 9 works.
  2. Create a Deployment with one replica of the pinned image `nginx:1.27-alpine` and `imagePullPolicy: IfNotPresent`. Behind a proxy, preload it first with `kind load docker-image nginx:1.27-alpine`. With `:latest`, the default policy `Always` would pull anyway.
  3. Read the pod's `imageID` and compute its object name. Wait until that `ImageInventory` has an entry for `local` whose `workloads` contains `{apps, Deployment, <ns>, nginx}`. Don't assert the digest kind: a preloaded image may report an image ID.
  4. Delete the Deployment. The object is gone within 90s.
  5. The metrics endpoint contains `vexplain_images_running{cluster="local"}`.
  6. Create `ModelConfig` `e2e` pointing at a Secret that doesn't exist. Within 60s, a `ModelUnavailable` event for it exists in namespace `default`. That proves the events RBAC, which envtest can't check.

  Run: `make test-e2e`
  Expected: PASS

- [ ] **Step 4: Early size indicator on kind** (0004: this is an indicator only; the storage decision waits for a real cluster)
  - **`hack/inventory-load`** takes `--csv <path>`: the owner's real export of one past CVE. It is real platform data, so it stays out of the repository.
    - Each distinct `image` becomes a synthetic digest: `sha256:` plus the hex sha256 of the image string.
    - Each (image, cluster) pair becomes one `Observe`:
      - the cluster name from the CSV
      - `ClusterID` = sha256 of the cluster name
      - the distinct namespaces counted from the rows, and one workload reference per row (kind and name parsed from `workload`, for example `ReplicaSet/web-7d9c4b`; the API group is taken from the kind)
      - the repository = the image without its tag
  - **Run:**
    1. Run `make install`, with the operator **not running**. Otherwise it would `Forget` these pod-less digests.
    2. Run `go run ./hack/inventory-load --csv …`. Expected: one object per distinct image in the export, and one cluster entry per image and cluster pair.
    3. Repeat with `--scale=10`. Copy `i` of an image uses the digest `sha256(image + "#" + i)`, which keeps the digest pattern and the name rule valid. Expected: ten times as many objects.
  - **Record:**
    - object count
    - p50/p95/max/total bytes
    - the time `kubectl get imageinventories -o name` takes
    - the `llm-smoke` latencies from Step 2

    Flag any object above the 512 KiB trigger from 0004.
- [ ] **Step 5: Commit**

```bash
git add cmd/llm-smoke hack/inventory-load config/samples test/e2e docs/measurements
git commit -m "test: two-turn tool-calling smoke, e2e inventory lifecycle, early size indicator"
```

---

## As built

Where the build differs from the text above, the build is right. Each difference was decided and reviewed while the plan ran.

### Wiring and setup

- `EnsureDefaults` runs inside `setup.Register` as a manager runnable, not in `cmd/main.go`, so envtest runs it too.
- `setup.CacheOptions(operatorNamespace) cache.Options` limits the manager's Secret cache to labelled Secrets in the operator namespace.
  - `cmd/main.go` uses it.
  - Both envtest suites use it too, through the shared helper `internal/testenv`.
- `setup.Register` refuses an empty operator namespace, which a cache would read as every namespace.
- `setup.Options.CollectorRegistry`: the Collector controller and the pod inventory share one `collector.Registry`, and `Register` creates it when the field is nil.

### API and tooling

- kube-api-linter decides marker spelling and which fields are pointers, with `preferredDefaultMarker: kubebuilder:default`. Where the plan's type snippets differ in markers or pointers, the code follows the linter.
- kube-api-linter is pinned to a pseudo-version that builds into golangci-lint v2.12.2. The logtools plugin is pinned too, to `v0.11.0`.
- The envtest specs are external test packages (`config_test`, `inventory_test`), because `internal/setup` imports the controller packages.

### RBAC and events

- The RBAC markers name only the verbs that the code uses, but for two that keep the scaffold's `get;update;patch`: `collectors/status` and `operatorconfigs/status`, whose controllers only update.
  - Task 7's full rights on `imageinventories` became the store's `get`, `list`, `watch`, `create` and `delete`, and `update` on the status.
- Events go through events.k8s.io/v1 with `mgr.GetEventRecorder("vexplain")`, because controller-runtime v0.24.1 deprecates `GetEventRecorderFor`.
  - This replaces the core/v1 events in the Global Constraints, Task 6 and Task 9.
  - A repeated event is counted in its `series`, so the tests check that an event has no `series` where the plan says `count == 1`.
  - Events of cluster-scoped objects still land in `default`.

### Workloads and inventory

- `ResolveOwner` reads ReplicaSets and Jobs as metadata only (`PartialObjectMetadata`), so the cache holds no pod templates.
- The pod inventory watches ReplicaSets and Jobs as metadata. When one is created or deleted, or its controller changes, it re-enqueues the digests of the pods that it controls.
- Each entry's list of workloads has one item per namespace, kind and name. Workloads that differ only in API group collapse to the first by API group, and the workload count still counts all of them.
- In the operator, only the store reads, writes or watches inventory objects:
  - `inventory.Store` has `Get`, `Observe`, `Forget`, `Digests`, `CountForCluster` and `Source`.
  - `NewCRDStore(c, informers)` takes the manager's cache, or nil in a program that never watches.
  - `GaugeUpdater` reads through the store. Its fields are `Store`, `Cluster`, `ClusterID` and `Interval`: `Store` takes the place of the plan's `Client`.
- The pod inventory has an `APIReader` field. It reads the cluster ID from the API server, once.
- An invalid scope is a terminal error. The inventory stays unchanged until the `OperatorConfig` is fixed, and the fix re-enqueues every digest.
- The counter of unparsable image IDs counts a container once, when it becomes unparsable. A restart of the operator counts it again.
- Watch predicates, which let every creation and deletion through:
  - namespaces: label changes
  - `OperatorConfig`: generation changes
  - ReplicaSets and Jobs: changes of the controller owner

### LLM client

- `llm.Secret` is an opaque struct made with `llm.NewSecret`, not `type Secret string`, so no format verb reaches the key.
  - `Secret` and `Client` implement `fmt.Formatter`.
  - Tasks 9 and 10 use `llm.NewSecret`.
- The client never follows a redirect. A 3xx is a `*StatusError`, and `Probe` maps it to `ErrUnreachable`.
- The key is sent over plain http only to a loopback host: `localhost` in exact lowercase, matching Go's proxy bypass, or a loopback IP. Every other endpoint needs https. This holds for every caller, not only `ModelConfig`.
- `Timeout` bounds each HTTP exchange. Only the caller's context bounds the wait for a free slot, and a call that gets no slot makes no request.
- Errors:
  - 401 and 403 wrap `ErrUnauthorized`.
  - Network failures, 5xx answers, deadlines and URLs refused before any request wrap `ErrUnreachable`.
  - Cancellation wraps `context.Canceled`, and no sentinel.
  - Errors carry a status code or one of a few fixed reasons, never a body, a header or the key.
  - Proxy failures have their own reason. It covers `proxyconnect` errors and a hook on the default transport (`OnProxyConnectResponse`).
- `Probe` with a nil client uses the default proxy-aware client and records no observation.
- The metrics are `vexplain_llm_requests_total`, `vexplain_llm_request_duration_seconds` and `vexplain_llm_tokens_total`.
- Task 8's tests are split by concern, into more files than the plan lists.

### ModelConfig

- The print columns add `Reason` and `Age`.
- The Secret reference's `name` and `key` have validation patterns.
- The reconciler has a `ProbeTimeout` field, where zero means 10s.
- `truncate` lives in `messages.go`. It cuts condition messages and event notes to 1024 bytes, the longest note that the events API takes.

### Task 10

- A Ready pod doesn't prove that the Secret informer syncs, because `readyz` is a ping. Without the Secret RoleBinding the pod is Ready, and the manager exits about two minutes later, on the cache-sync timeout.
  - The e2e asserts that the ModelConfig controller started, and the `ModelUnavailable` event shows that it works.
  - This corrects Task 10's step 3.1. Task 9's text on a missing binding holds, but says neither that the pod is Ready meanwhile nor when the manager exits.
- `llm-smoke` uses `MaxConcurrent: 1`. The CRD default is 2, not 1 as Task 10 says. Its latencies are per request.
- `inventory-load --scale`: copy 0 has the synthetic digest of the image string itself, and copy `i` that of the image string with `#i` appended.
  - The tool refuses an API server that isn't on a loopback address.
  - After the load it measures the object sizes itself, with a list through its own client, not through the store.
- The e2e suite:
  - pulls its images and loads them into kind itself
  - selects events by the ModelConfig's UID
  - requires a gauge value of 1 or more
- The measurements doc holds only per-object sizes, growth ratios and list times: no counts, totals or names from the data it measured.
- The run against a real model is the owner's, and the doc says it is pending.

## Carried forward

These are the known gaps of phase 1, each under the point by which it must be closed.

### Before the first run on a real cluster

- **Memory:** the manager caches every Pod in the cluster, with managed fields.
  - Set `DefaultTransform: cache.TransformStripManagedFields()` in `setup.CacheOptions`.
  - Size the memory limit (the scaffold's 128Mi in `config/manager/manager.yaml`) from a measurement.
- **Pod watch:** it has no update predicate, so every status update of a pod reconciles all its digests again.
- **Readiness:** `readyz` is a ping. Add a check that waits for the cache to sync.
- **Logging:** `cmd/main.go` defaults to zap's development mode.
  - Default to production logging.
  - Make the e2e's `Starting workers` check match JSON logs too.

### Before the owner's real-endpoint check and phase 4

- Reach the real endpoint once through a `ModelConfig`: run the manager against kind with a labelled Secret, and confirm `Available`. `llm-smoke` alone exercises neither `/models`, nor the Secret, nor the trust store inside the cluster.
- Decide how the operator trusts an internal CA, as a CA bundle reference or a documented mount, together with proxy settings in `config/manager`.
- Key any cache of LLM clients by the `ModelConfig`'s name and generation and by the Secret's resourceVersion.
  - `Config ==` compares the key by pointer.
  - A rotated key must not be missed.
- A call that makes no request (an encoding failure, an invalid URL, a refused scheme) is still observed as `outcome="error"`. Fix it when phase 4 wires the observer: skip the observation, or reword the docs that call every observation a request: the doc comments of `WithObserver` and `Observation`, and the help of the LLM metrics.

### Before the first install on a shared cluster

- Reject userinfo, query and fragment in `ModelConfig.spec.endpoint`. Both a `Client` printed with `%p` or `%w` and the spec itself would show them.

### At the start of phase 2

- **The status writer:** `withEntry` rebuilds an `ImageInventory`'s status from scratch, but from phase 2 the same status also holds the image facts (design section 6.2). It must:
  - merge into the current status (`current.DeepCopy()`)
  - keep a known `DigestKind`
  - treat NotFound on the status write as a race in `Observe`, and as success in `Forget`
- Phase 2's writer of image facts must never create inventory objects.
- **Mirror pods:** static pods resolve to `{"", Node, <namespace>, <node>}`. Decide how they are attributed before `WorkloadReport` addresses workloads by namespace.
- **Empty exclude:** `scope.New` turns an empty exclude selector into "exclude everything", and only CEL prevents it.
  - Reject it in `scope.New`.
  - Validate `OperatorConfig` through `scope.New`, so the two can't drift.
- **Collector status:** each restart of the operator clears the Collector's `lastSuccessTime`. Keep the stored time until the registry reports a success.
- **Samples:** take the ImageInventory sample out of `config/samples/kustomization.yaml`, because the running operator deletes it at once. Keep the file as documentation.
- **Unparsable counter:** `vexplain_unparsable_image_ids_total` counts transitions, so an alert goes quiet while a container is still skipped. Consider a gauge of the containers skipped now.

### Before a second storage backend, or in phase 6

- **Validation:** the store must check what the schema checks today: the digest pattern, the field lengths and the 256-entry cap. The CRD store leaves them to the API server.
- `Store.Source()` is unfiltered, so every spoke would reconcile every digest of every cluster.
  - Filter it.
  - A remote transport must provide a filtered one.
- With several spokes, `Forget` can livelock.
  - Delete only when this writer removed the last entry.
  - Add a hub janitor for objects left with no entries.
- The schema allows 256 entries of up to 100 workloads each, which exceeds etcd's 1.5 MB per object. Cap the entries to fit, as part of decision 0004.
- Cluster names must be unique. Entries match by name or ID, so two clusters left at the default `local` overwrite each other.
