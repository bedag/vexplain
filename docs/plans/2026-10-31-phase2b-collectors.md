# vexplain — Phase 2b (Collectors as packages, playbooks, exposure and reports) Implementation Plan

> **For agents:** follow `AGENTS.md`. Implement this plan task by task, test first. A task is done when its tests pass, it is committed and it has been reviewed; only then start the next one. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** On one kind cluster, running as hub and spoke at once, the operator:
- installs its collectors as OCI packages and talks to them over one gRPC API, with `workloads`, `scanner`, `matcher` and `exposure` as the built-ins (0029, 0030)
- takes their evidence as CloudEvents, keeps what the hub collects, and asks for evidence on demand (0032)
- settles findings through the default `container-cves` playbook and its four default CEL rules, with the same answers as phase 2a (0033, 0034)
- renders a `WorkloadReport` per workload, with SSVC urgency from exposure, owner attribution, metrics and events (0024, 0009, 0014, 0020)

**Architecture:**
- **Collectors** are Deployments that the operator creates from `Collector` resources. Each serves the collector API over mTLS on port 9443, and health and metrics on port 8081. They live in their own Go modules under `collectors/`, built on the SDK in `sdk/`.
- **Spoke (eyes, hands, mouth):**
  - A stream manager watches the collectors that watch (`workloads`, `exposure`) and keeps their evidence in memory. Presence becomes `ImageInventory` presence entries through `inventory.Store`, as before.
  - An executor runs the hub's requests: it invokes the collectors that produce the type asked for (`scanner`), and writes the evidence through `evidence.Store`.
  - A renderer turns sheets and local exposure into `WorkloadReport`s, metrics and events.
- **Hub (decisions):** for each image in presence, an assessor gets what the playbook needs (evidence from the store, findings from `matcher`), runs the playbook's rules through the CEL engine, and writes the sheet through `inventory.VerdictsStore`.
- **One process, two roles,** as in 2a. Hub and spoke meet only through `tasks.Executor` and the stores.

**Tech Stack:**
- Go 1.26, kubebuilder v4 (controller-runtime v0.24.1, Kubernetes libraries v0.36.0)
- gRPC and protobuf, generated with `buf`
- the CloudEvents Go SDK, with its protobuf format
- cel-go, already in the module graph through the Kubernetes libraries, as a direct dependency
- a JSON Schema validator for collector settings and evidence schemas
- envtest with Ginkgo/Gomega, and testify
- kind with a local registry

**Spec:**
- `docs/design/2026-10-31-collectors-evidence-rules.md` and records 0029–0035. Sections 5 and 6 matter most.
- `docs/design/2026-10-29-vexplain-design.md`, revision 14: sections 6.4, 6.10 and 6.14, and records 0006, 0009, 0014, 0019, 0020 and 0024.
- Phase 2a's plan (`docs/plans/2026-10-30-phase2a-scanning.md`): its "As built" section describes what exists. Its "Carried forward" items due at the start of phase 2b are placed in Tasks 1, 7, 9, 12, 13 and 21.

**Not in this plan:**
- the agent, its tools, `Assessment`s, and the playbook's `agent` field (phase 4)
- the `kubescape`, `govulncheck`, `advisories` and `sandbox` collectors (phases 3 to 5; `govulncheck` in phase 3, by the owner's decision)
- MCP servers as collectors (after v1)
- packages for playbooks and rules, and `Function`s
- the `Hub`, `Spoke` and `HubAndSpoke` modes, the `WrongRole` reason, and transport between clusters (phase 6)
- 2a's carried-forward items "the scanner's own fixes", "before the measurement runs again", "before the first run on a real cluster" and later sections. They stay carried forward, under the collector their code moves to.
- 0004's storage decision, which is checked on a real cluster (design of collectors, section 8)

## Decisions made in this plan

The design leaves these to the builder. Each is decided here, so implementers don't guess. The owner checks them when reviewing this plan.

1. **Modules.**
   - The root module `github.com/bedag/vexplain` stays the operator.
   - `sdk/` is the module `github.com/bedag/vexplain/sdk`.
   - Each built-in collector is the module `github.com/bedag/vexplain/collectors/<name>`, under `collectors/<name>`, with its own `Dockerfile` and `replace github.com/bedag/vexplain/sdk => ../../sdk`.
   - A `go.work` at the root lists all of them, for development and for the image builds.
   - The operator imports `sdk`, and never a collector module.
2. **Code generation.** The API's proto is `sdk/proto/vexplain/collector/v1alpha1/collector.proto`. CloudEvents' `cloudevents.proto` is vendored under `sdk/proto/io/cloudevents/v1/`, with the `go_package` of the CloudEvents Go SDK's protobuf format, so the generated code uses that SDK's type. `buf`, `protoc-gen-go` and `protoc-gen-go-grpc` are pinned in the Makefile like the other tools. The generated code is committed under `sdk/api/collector/v1alpha1`, `make proto` regenerates it, and CI fails when it's stale.
3. **`data` is JSON for every type** (`datacontenttype: application/json`), so CEL reads every type the same way. gRPC compresses with gzip.
4. **Two extension attributes:** `coverage`, an integer from 0 to 100, and `platform`, as `os/arch[/variant]`. Every event about a manifest carries `platform`, so the facts can list manifests per platform without knowing the type.
5. **Subjects, exactly:**
   - `image/sha256:<64 hex>`: a reported digest
   - `manifest/sha256:<64 hex>`: a platform manifest
   - `workload/<cluster>/<namespace>/<Kind>[.<group>]/<name>`, such as `workload/cluster-a/team-a/Deployment.apps/web` or `workload/cluster-a/team-a/Pod/web-0`
6. **Presence is about images.** The `workloads` collector emits one presence event per reported digest. It lists every workload that runs the digest, with its UID, its pods and their nodes and platforms, and the allowlisted labels and annotations. That is the shape `ImageInventory` already has (0019), and it gives the container playbook its subjects. The design's table of core types said "workload" for presence; the owner confirmed the correction on 2026-10-31.
7. **One Deployment per `Collector`,** serving every role that the cluster runs. That refines design 5.4's "one per `Collector` and role": until phase 6 every cluster runs both roles in one process, so the two are the same.
8. **Health and metrics on a separate plain HTTP port,** 8081: `/healthz`, `/readyz` and `/metrics`. The kubelet's gRPC probes can't present a client certificate.
9. **The deployer copies the manager's proxy variables** into each collector's Deployment. The runtime config can override them.
10. **Evidence scoped to the spoke** (presence, exposure) is kept in memory from the collectors' streams, never stored. After a restart, a new stream's snapshot rebuilds it.
11. **Findings aren't stored as evidence.** The assessor invokes `match` and writes the result into the sheet, as 2a did. After a change to a rule or playbook, the assessor evaluates again from the sheet's findings and the stored evidence, without matching again. A sheet that left out findings (`omittedFindings` above 0) is matched again instead, because settled findings are left out first and couldn't be reopened from the sheet.
12. **One playbook per subjects source.** A second playbook with the same subjects collector and type isn't `Ready` (reason `Conflict`), so each manifest keeps one sheet.
13. **The sheet changes:**
    - `outcome` becomes `status`, with OpenVEX's values `Affected`, `UnderInvestigation`, `NotAffected` and `Fixed` (owner, 2026-10-31). `justification` is set exactly for `NotAffected`, and the counts and print columns follow.
    - `rule` becomes a `Rule`'s name, a string.
    - `statusNotes` lists each hint's rule and text: OpenVEX's `status_notes`.
    - `evidence` records what the sheet rested on: each input's name, source, type, collector version, time and coverage.
    - `findingsVersion` replaces `databaseVersion`, and `playbook` names the playbook. `scannerImage` goes; the evidence names each collector's version.
    - Each finding carries `knownExploited` and up to 4 CVSS vectors, which urgency needs (Task 20).
    - 2a's `LoadCheck` becomes the `load-check` hint. Its finding is `UnderInvestigation`, with no deciding rule and one status note.
    - A sheet that leaves out open findings is shown as incomplete, never as a "no verdict". That settles 2a's open question on the sheet's contract.
14. **The facts become generic:**
    - manifests per platform, from the `platform` extension
    - for each source and type: the collector's version, the time and the coverage
    - the last failure of each source: source, reason (an open vocabulary that starts with 2a's reasons), time and attempts, so that one collector's failure never resets another's backoff
15. **Evidence objects:** the kind `Evidence` in the inventory group.
    - Each is named `ev-` plus the first 40 hex digits of the SHA-256 of `subject|type|source`.
    - It is labelled with its source collector and with hashes of its subject and type, and carries its subject in the annotation `vexplain.bedag.ch/subject`.
    - Its `spec` is immutable, compressed with gzip, and capped at 786432 bytes, as 2a's evidence was.
16. **`OperatorConfig` changes.**
    - `spec.rules` goes. Its threshold moves into the `completeness-guard` rule.
    - New fields: `spec.ownerAttribution` (0020) and `spec.urgency.overrides` (0024). Reports show each evidence's coverage and never interpret it (spec 5.5), so no coverage threshold comes with them.
17. **Mirror pods:** a mirror pod is its own workload, of kind `Pod`, in its namespace.
18. **Indirect exposure, one hop:** a workload is indirectly exposed when the NetworkPolicies, and Cilium's policies where they exist, let some externally exposed workload of the cluster reach it.
19. **SSVC inputs** (0024; each unknown errs towards urgency):
    - **Exploitation:** `active` on KEV, otherwise `none`. There's no advisory source before phase 4.
    - **Automatable:** `yes` when the CVSS vector has `AV:N`, `AC:L`, `PR:N` and `UI:N`, or when no vector is known; otherwise `no`.
    - **Human impact:** `high` when the CVSS vector has `C:H`, `I:H` and `A:H`, or when no vector is known; otherwise `medium`.
    - **Exposure:** `open`, `controlled` or `small` (0024's table); unknown counts as `open`.
20. **The next step:** `Update` when a fixed version exists. Otherwise `Mitigate` for `Affected`, and `Investigate` for `UnderInvestigation`.
21. **A `WorkloadReport` is owned by its workload,** through an owner reference by UID, so Kubernetes deletes it with the workload. vexplain still writes nothing to workloads.
22. **The built-ins are installed by kustomize:** `config/collectors` (the `Collector` manifests, their RBAC and runtime configs), `config/rules` and `config/playbooks`. The operator creates none of them at run time, except the empty `default` runtime config that design 5.8 asks for. The Helm value that leaves them out comes with the Helm chart.

## Decisions for the owner

1. **Known exploited.** Decided by the owner on 2026-10-31: a hold (0035). `known-exploited` concludes `UnderInvestigation` with the reason `known exploited`, so no rule can settle the finding, and urgency carries the exploitation.
2. **When to build `govulncheck` (0027).** Decided by the owner on 2026-10-31: in phase 3, as a collector package.
3. **Presence is about images** (decision 6). Confirmed by the owner on 2026-10-31.

## Global Constraints

- **Phases 1 and 2a still bind.** Their Global Constraints hold, as amended by their "As built" sections: names, API conventions, kube-api-linter, RBAC from markers, wiring through `setup.Register`, tests and commits.
- **API groups:**
  - `config.vexplain.bedag.ch/v1alpha1`: `Collector`, `CollectorRuntimeConfig`, `Playbook`, `Rule` and `OperatorConfig`
  - `inventory.vexplain.bedag.ch/v1alpha1`: `ImageInventory`, `Evidence` and `ImageVerdicts`
  - `triage.vexplain.bedag.ch/v1alpha1`: `WorkloadReport`, the group's first kind
- **The collector API:** gRPC package `vexplain.collector.v1alpha1`, services `Identity` (`GetInfo`, `GetCapabilities`, `ValidateSettings`) and `Evidence` (`Watch`, `Invoke`), plus `grpc.health.v1`.
- **Ports:** 9443 for gRPC with mTLS, and 8081 for plain HTTP `/healthz`, `/readyz` and `/metrics`.
- **Names:**
  - the Deployment, Service and service account `vexplain-collector-<name>`
  - the TLS Secret `vexplain-collector-<name>-tls`
  - the CA Secret `vexplain-collector-ca`
  - the label `vexplain.bedag.ch/collector: <name>`
- **Certificates:** ECDSA P-256. The CA is valid for 10 years. Leaf certificates are valid for 90 days and renewed with 30 days left.
- **CloudEvents 1.0:**
  - attributes `id`, `source`, `specversion`, `type`, `subject`, `time`, `datacontenttype`, `dataschema` and `data`
  - extensions `coverage` and `platform`
- **The core's types:**
  - `ch.bedag.vexplain.presence.v1alpha1`, about an image, scope `Spoke`
  - `ch.bedag.vexplain.findings.v1alpha1`, about a manifest, scope `Hub`
  - `ch.bedag.vexplain.exposure.v1alpha1`, about a workload, scope `Spoke`
- **The scanner's type:** `ch.bedag.vexplain.scanner.image-contents.v1alpha1`, about a manifest, scope `Hub`. Its `data` is 2a's `result.Manifest` JSON unchanged, and its `coverage` is 2a's completeness.
- **The core reads no other type.** No package of the root module imports a collector module or parses a collector's type.
- **Size limits:** compressed evidence at most 786432 bytes; at most 2048 findings and 1 MiB per sheet; gRPC messages at most 16 MiB.
- **CEL:** a cost limit of 1,000,000 per evaluation, and at most 4096 characters per expression.
- **Statuses (OpenVEX):** `Affected`, `UnderInvestigation`, `NotAffected` and `Fixed`, exported as OpenVEX's `affected`, `under_investigation`, `not_affected` and `fixed`. The most cautious wins: `Affected`, then `UnderInvestigation`; of the two that settle a finding, `Fixed` goes before `NotAffected`. A rule without a status is a hint, and adds a status note; notes add up, at most 4 per finding.
- **The defaults:** the rules `known-exploited`, `completeness-guard` (90), `removed-in-later-layer` and `load-check`, and the playbook `container-cves`.
- **The runtime config's defaults:**
  - non-root, with the `RuntimeDefault` seccomp profile
  - no privilege escalation, a read-only root filesystem, and all capabilities dropped
  - `imagePullPolicy: IfNotPresent`
- **SSVC outcomes:** `Defer`, `Scheduled`, `OutOfCycle` and `Immediate`.
- **The scanner keeps 0022's isolation:** scan Jobs without an API token or LLM key, with the credentials for the one image in a Secret owned by the Job.
- **Pull secrets** are read only by the collectors that pull images, with `get` only. They never appear in logs, status, events, metrics, errors or evidence.
- **Metrics** start with `vexplain_` and carry the label `cluster`.
- **Testing** happens only on a local kind cluster with its own kubeconfig (AGENTS.md).
- **Commits:** Conventional Commits, signed, no AI attribution, never on `main`.
- **Repository hygiene (AGENTS.md):** neutral names such as `cluster-a`, `team-a` and `artifacts.example`. `CVE-2026-111497` may appear in tests.

## Review Focus

1. **A collector's stream breaks, or the collector restarts, in the middle of a snapshot.** The spoke keeps the last complete snapshot, never part of one. Presence entries don't flap, and nothing is forgotten until a new snapshot ends. Tests in Task 11.
2. **A rule can't be evaluated for one finding:** its CEL fails, hits the cost limit, or an input is missing. A rule that concludes `Affected` or `UnderInvestigation` then keeps that finding from `NotAffected` and `Fixed`, and the sheet says which rule and why. Tests in Task 8.
3. **A `Collector` is deleted, or renamed, while a playbook names it.** Its evidence goes, the playbook isn't `Ready`, and the findings it covers are held open, never settled. Tests in Tasks 9 and 12.
4. **Evidence over the cap.** The facts record `TooLarge`. No sheet comes from it, and no finding is settled. Tests in Tasks 7 and 14.
5. **Text from image content** (package names, versions, reasons) reaches sheets, reports and metric labels. It is shown as data, made printable and bounded, and never breaks a label. Tests in Tasks 8, 21 and 22.

---

## File Structure

```text
go.work                                   # Task 2: ., sdk, collectors/*
sdk/                                      # module github.com/bedag/vexplain/sdk
  proto/vexplain/collector/v1alpha1/collector.proto
  proto/io/cloudevents/v1/cloudevents.proto     # vendored
  buf.yaml, buf.gen.yaml
  api/collector/v1alpha1/                 # generated
  subject/                                # subject paths (Task 2)
  evidence/                               # CloudEvents helpers, core types, schemas (Task 2)
  collector/                              # the server side of the API (Task 3)
  conformance/                            # the conformance suite (Task 4)
  scope/                                  # moved from internal/scope (Task 13)
  workloads/                              # moved from internal/workloads (Task 13)
  podtemplate/                            # the standard pod template (Task 14)
  jobs/                                   # the scan-Job helper, from internal/controller/scan (Task 14)
collectors/
  workloads/ (Task 13)   scanner/ (Task 14)   matcher/ (Task 15)   exposure/ (Task 18)
templates/collector/                      # the template project (Task 4)
api/config/v1alpha1/                      # Collector, CollectorRuntimeConfig, Playbook, Rule (Task 5)
api/inventory/v1alpha1/                   # Evidence (Task 6); ImageInventory and ImageVerdicts changes (Tasks 7, 9 and 19)
api/triage/v1alpha1/                      # WorkloadReport (Task 6)
internal/collector/certs/                 # the CA and leaf certificates (Task 10)
internal/controller/config/collector_controller.go   # the deployer (Task 12)
internal/collectorclient/                 # pool, streams, invoke (Task 11)
internal/evidence/                        # Evidence store and facts writer (Task 7)
internal/spoke/                           # presence, executor, exposure, reports, metrics (Tasks 13, 14, 19, 21, 22)
internal/rules/engine/                    # the CEL engine (Task 8)
internal/text/                            # printable, bounded text, moved from internal/rules (Task 8)
internal/controller/hub/                  # playbooks, assessor, janitor (Task 9)
internal/urgency/                         # SSVC (Task 20)
config/rules/ (Task 8)   config/playbooks/ (Task 9)   config/collectors/ (Tasks 16, 18)
docs/collectors.md                        # how to build a collector (Task 4)
```

**Removed:** `internal/scan/*`, `cmd/scanner`, `cmd/matcher`, `internal/matcher`, `internal/matchapi`, `internal/controller/scan`, `internal/controller/inventory/podinventory_controller.go`, `internal/workloads`, `internal/scope`, `config/matcher`, `Dockerfile.scanner` and `Dockerfile.matcher`, and the `ImagePackages` kind. Each moves into a module above, or is replaced, in the task named beside it.

## Task order

The core's new machinery comes first, while 2a's collectors still run inside the operator. Then each collector moves into its package, one at a time, and `make test` stays green after every task:

- **Tasks 1–6:** the start of 2b, the SDK, and the new API kinds.
- **Tasks 7–9:** the evidence store, the CEL engine, and playbooks with the assessor. These replace 2a's evidence kind, rules and hub controllers. 2a's in-process scanner, pod inventory and HTTP matcher keep feeding them.
- **Tasks 10–15:** certificates, the collector client and the deployer. Then `workloads`, `scanner` and `matcher` move into packages, in that order, and each replaces its in-process predecessor.
- **Tasks 16–17:** install, e2e, and the measurement run again.
- **Tasks 18–23:** exposure, urgency, reports and metrics, and their e2e.

### Task 1: Phase 2a's gaps due at the start of phase 2b

The other items of 2a's list "at the start of phase 2b" are placed in the tasks that change their code: the sheet's contract (Tasks 9 and 21), a settled finding through the hub (Task 9), platforms that start running later (Task 9), untrusted text (Tasks 8 and 21), low completeness (Task 21), the gauge of skipped containers (Task 13), the scanner's health (Task 12), the store's small gaps (Task 7), and the other small gaps (Task 9). Known exploitation is decided: a hold (0035, Task 8). The catalogers stay with the scanner's own fixes.

**Files:**
- Create: `hack/check-comments.sh`
- Modify: `Makefile` (target `check-comments`, run by `lint`), `internal/controller/config/operatorconfig_controller.go` and its tests

- [ ] **Step 1: Write the failing tests.**
  - `check-comments.sh` fails on a Go comment that cites a ruling of the development ledger, by number or by name, and passes on the repository.
  - The `OperatorConfig` condition message is cut to the same length as the package's other messages.
  - The refusal text of an empty exclude selector is pinned, and so is the order of two refusals.
- [ ] **Step 2: Run them and see them fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Verify** with `make lint` and `make test`.
- [ ] **Step 5: Commit**: `chore: check comments for citations outside the repository, and pin OperatorConfig's refusals`

### Task 2: The workspace, the collector API and the SDK's types

**Files:**
- Create:
  - `go.work`, `sdk/go.mod`, `sdk/buf.yaml`, `sdk/buf.gen.yaml`
  - `sdk/proto/vexplain/collector/v1alpha1/collector.proto`
  - `sdk/proto/io/cloudevents/v1/cloudevents.proto`, vendored from the CloudEvents spec with its licence header
  - `sdk/api/collector/v1alpha1/` (generated)
  - `sdk/subject/subject.go` and its test
  - `sdk/evidence/evidence.go`, `types.go`, `schemas/*.json` and their tests
- Modify:
  - `Makefile`: the targets `proto` and `proto-check`, and `test`, `lint` and `fmt` over every module of `go.work`
  - `.dockerignore`: allow `go.work`, `sdk/`, `collectors/`, `templates/` and `*.json`
  - `.github/workflows/test.yml` and `lint.yml`: run `proto-check`

**Interfaces:**
- Produces, the API:

```proto
syntax = "proto3";
package vexplain.collector.v1alpha1;
option go_package = "github.com/bedag/vexplain/sdk/api/collector/v1alpha1;collectorv1alpha1";
import "io/cloudevents/v1/cloudevents.proto";

service Identity {
  rpc GetInfo(GetInfoRequest) returns (GetInfoResponse);
  rpc GetCapabilities(GetCapabilitiesRequest) returns (GetCapabilitiesResponse);
  rpc ValidateSettings(ValidateSettingsRequest) returns (ValidateSettingsResponse);
}
service Evidence {
  rpc Watch(WatchRequest) returns (stream WatchResponse);
  rpc Invoke(InvokeRequest) returns (stream InvokeResponse);
}

enum Role { ROLE_UNSPECIFIED = 0; ROLE_SPOKE = 1; ROLE_HUB = 2; }
enum Scope { SCOPE_UNSPECIFIED = 0; SCOPE_SPOKE = 1; SCOPE_HUB = 2; }

message GetInfoRequest {}
message GetInfoResponse { string name = 1; string version = 2; repeated string api_versions = 3; }

message GetCapabilitiesRequest {}
message EvidenceType { string type = 1; Scope scope = 2; string dataschema = 3; bytes schema = 4; }
message Operation {
  string name = 1; string description = 2; Role role = 3;
  repeated string produces = 4; repeated string consumes = 5; bytes parameter_schema = 6;
}
message PolicyRule {
  repeated string api_groups = 1; repeated string resources = 2; repeated string verbs = 3;
  bool namespaced = 4; // true: only in the collector's own namespace
}
message GetCapabilitiesResponse {
  repeated Role roles = 1; repeated EvidenceType produces = 2; repeated string consumes = 3;
  bool watches = 4; repeated Operation operations = 5; bytes settings_schema = 6;
  repeated PolicyRule permissions = 7;
}

message ValidateSettingsRequest { bytes settings = 1; }
message ValidateSettingsResponse { repeated string problems = 1; }

message Context {
  string cluster = 1; string operator_namespace = 2; string own_pod_label = 3;
  bytes scope = 4;             // OperatorConfig.spec.scope, as JSON
  bytes owner_attribution = 5; // OperatorConfig.spec.ownerAttribution, as JSON
}

message WatchRequest { Role role = 1; bytes settings = 2; Context context = 3; }
message SnapshotStart {}
message SnapshotEnd {}
message Tombstone { string type = 1; string subject = 2; }
message SourceChanged { repeated string subjects = 1; } // empty: every subject
message WatchResponse {
  oneof item {
    SnapshotStart snapshot_start = 1; io.cloudevents.v1.CloudEvent event = 2;
    Tombstone tombstone = 3; SnapshotEnd snapshot_end = 4; SourceChanged source_changed = 5;
  }
}

message InvokeRequest {
  string operation = 1; string subject = 2; bytes parameters = 3;
  repeated io.cloudevents.v1.CloudEvent inputs = 4; bytes settings = 5; Context context = 6; Role role = 7;
}
message Failure { string reason = 1; string message = 2; }
message InvokeResponse { oneof item { io.cloudevents.v1.CloudEvent event = 1; Failure failure = 2; } }
```

- Produces, in Go:

```go
package subject
type Kind string
const (KindImage Kind = "image"; KindManifest Kind = "manifest"; KindWorkload Kind = "workload")
type Workload struct{ Cluster, Namespace, Group, Kind, Name string }
type Subject struct{ Kind Kind; Digest string; Workload Workload; Raw string }
func Image(digest string) string
func Manifest(digest string) string
func ForWorkload(w Workload) string
// Parse reads a subject. A collector's own prefix parses as that Kind, with Raw set.
func Parse(s string) (Subject, error)

package evidence
const (
	TypePresence = "ch.bedag.vexplain.presence.v1alpha1"
	TypeFindings = "ch.bedag.vexplain.findings.v1alpha1"
	TypeExposure = "ch.bedag.vexplain.exposure.v1alpha1"
	ExtCoverage  = "coverage"
	ExtPlatform  = "platform"
)
type Option func(*cloudevents.Event)
func WithCoverage(percent int32) Option
func WithPlatform(platform string) Option
func WithTime(t time.Time) Option
func WithSource(source string) Option
// New builds an event: a random UUID, specversion 1.0, the time now unless WithTime,
// application/json, and the dataschema "urn:vexplain:schema:<type>".
func New(eventType, subject string, data any, opts ...Option) (cloudevents.Event, error)
func Coverage(e cloudevents.Event) (int32, bool)
func Platform(e cloudevents.Event) (string, bool)
// Validate checks the event, and that coverage is 0–100, platform is os/arch[/variant] and the subject parses.
func Validate(e cloudevents.Event) error
func ToProto(e cloudevents.Event) (*pb.CloudEvent, error)
func FromProto(p *pb.CloudEvent) (cloudevents.Event, error)
func Schema(eventType string) ([]byte, bool) // the core types' embedded JSON Schemas

type KeyValue struct{ Key, Value string }
type Presence struct {
	DigestKind   string             `json:"digestKind"`   // RepoDigest or ImageID
	Repositories []string           `json:"repositories,omitempty"`
	Workloads    []PresenceWorkload `json:"workloads"`
}
type PresenceWorkload struct {
	APIGroup, Kind, Namespace, Name, UID string
	Pods                                    []PresencePod
	Labels, NamespaceLabels, NamespaceAnnotations []KeyValue // allowlisted only
}
type PresencePod struct{ Name, Node, Platform string }
type Findings struct {
	Version string  `json:"version"` // the source's database version
	Matches []Match `json:"matches"`
}
type Match struct {
	VulnerabilityID, PackageID, PackageName, PackageVersion, PackageType, Severity, FixState string
	FixedVersions                                                                         []string
	KnownExploited                                                                        bool
	CVSS                                                                                  []CVSS
}
type CVSS struct{ Version, Vector string }
type Exposure struct {
	External      ExternalExposure `json:"external"`
	InternalReach string           `json:"internalReach"` // Namespace, Peers, Namespaces or Cluster
	Indirect      bool             `json:"indirect"`
}
type ExternalExposure struct {
	Exposed bool        `json:"exposed"`
	Via     []ObjectRef `json:"via,omitempty"` // at most 8
}
type ObjectRef struct{ APIGroup, Kind, Namespace, Name string }
```

  The JSON names are lower camel case throughout.

- [ ] **Step 1: Write the failing tests.**
  - `subject`: a table of round trips.
    - `Image("sha256:…")` gives `image/sha256:…`.
    - A Deployment in `apps` gives `workload/cluster-a/team-a/Deployment.apps/web`.
    - A core `Pod` has no group suffix.
    - `Ingress.networking.k8s.io` splits at the first dot.
    - `vm/cluster-a/db-1` parses as kind `vm`, with `Raw` set.
    - A digest that isn't `sha256:` and 64 lowercase hex digits is refused for `image/` and `manifest/`.
  - `evidence`:
    - `New` sets every attribute.
    - `Validate` refuses coverage 101, a platform `linux`, and an empty subject.
    - An event survives `ToProto` and `FromProto` equal.
    - A sample of each core type validates against its schema, and a sample with a wrong field type doesn't.
- [ ] **Step 2: Run them and see them fail.**
- [ ] **Step 3: Implement.** Pin `buf`, `protoc-gen-go`, `protoc-gen-go-grpc`, the CloudEvents Go SDK and the JSON Schema validator (`github.com/santhosh-tekuri/jsonschema/v6`) at their latest stable releases.
- [ ] **Step 4: Verify** with `make proto-check`, `make test` and `make lint`.
- [ ] **Step 5: Commit**: `feat(sdk): add the collector API, subjects and the core evidence types`

### Task 3: The SDK's server

**Files:**
- Create: `sdk/collector/server.go`, `identity.go`, `evidence.go`, `tls.go`, `health.go`, `settings.go`, and their tests

**Interfaces:**
- Consumes: Task 2
- Produces:

```go
package collector
const APIVersion = "v1alpha1"
type Role int   // RoleSpoke, RoleHub
type Scope int  // ScopeSpoke, ScopeHub
type Info struct{ Name, Version string }
type EvidenceType struct{ Type string; Scope Scope; Schema []byte }
type Operation struct {
	Name, Description  string
	Role               Role
	Produces, Consumes []string
	ParameterSchema    []byte
}
type Permission struct {
	APIGroups, Resources, Verbs []string
	Namespaced                  bool
}
type Capabilities struct {
	Roles          []Role
	Produces       []EvidenceType
	Consumes       []string
	Watches        bool
	Operations     []Operation
	SettingsSchema []byte
	Permissions    []Permission
}
type Context struct {
	Cluster, OperatorNamespace, OwnPodLabel string
	Scope, OwnerAttribution                 json.RawMessage
}
type WatchRequest struct{ Role Role; Settings json.RawMessage; Context Context }
type InvokeRequest struct {
	Operation, Subject   string
	Parameters, Settings json.RawMessage
	Inputs               []cloudevents.Event
	Context              Context
	Role                 Role
}
type Failure struct{ Reason, Message string }
type Sink interface {
	SnapshotStart() error
	Event(cloudevents.Event) error
	Tombstone(eventType, subject string) error
	SnapshotEnd() error
	SourceChanged(subjects ...string) error
}
type Collector interface { Info() Info; Capabilities() Capabilities }
type SettingsValidator interface { ValidateSettings(settings json.RawMessage) []string }
type Watcher interface { Watch(ctx context.Context, req WatchRequest, sink Sink) error }
type Invoker interface {
	Invoke(ctx context.Context, req InvokeRequest) ([]cloudevents.Event, *Failure, error)
}
type Options struct {
	GRPCAddress   string // ":9443"
	HealthAddress string // ":8081"
	TLSDir        string // "/run/vexplain/tls": tls.crt, tls.key, ca.crt
	Insecure      bool   // tests only
	Registry      prometheus.Registerer
}
// OptionsFromEnv reads VEXPLAIN_LISTEN, VEXPLAIN_HEALTH_LISTEN and VEXPLAIN_TLS_DIR.
func OptionsFromEnv() Options
func Serve(ctx context.Context, c Collector, opts Options) error
```

- **Behaviour:**
  - `GetInfo` answers with `Info` and the API versions `[v1alpha1]`.
  - `ValidateSettings` checks the settings against `SettingsSchema` first, then calls the collector's validator if it has one.
  - `Watch` and `Invoke` refuse invalid settings with `InvalidArgument`.
  - The sink enforces the stream's order:
    - `SnapshotStart` comes first, and `SnapshotEnd` follows it.
    - Events come only after a `SnapshotStart`, and tombstones only after the first `SnapshotEnd`.
    - Every event is validated, and its type must be one that the collector produces.
    - A violation ends the stream with `Internal`.
  - `Invoke` answers `Unimplemented` for an undeclared operation, and `InvalidArgument` for an input of a type the operation doesn't consume.
  - **TLS:** the server presents `tls.crt`, requires a client certificate signed by `ca.crt`, and loads the files again within 30 seconds of a change.
  - **gRPC:** gzip compression, and messages up to 16 MiB.
  - **Health:** the standard gRPC health service (`grpc.health.v1`) on the gRPC port, which the deployer checks (spec 5.3); `/healthz` while serving; `/readyz` once the gRPC listener is up and the certificates are loaded; `/metrics` with `vexplain_collector_requests_total{cluster, method, code}`, with `cluster` from the request's context, as the Global Constraints ask of every metric.

- [ ] **Step 1: Write the failing tests** over `bufconn`:
  - `GetInfo` and `GetCapabilities` round-trip, schemas included.
  - `ValidateSettings` reports a schema violation, and then the collector's own problem.
  - `Watch`: an event before `SnapshotStart`, an event of an undeclared type, and a tombstone before the first `SnapshotEnd` each end the stream with `Internal`. A well-ordered stream arrives whole.
  - `Invoke`: an undeclared operation gives `Unimplemented`, an unconsumed input type gives `InvalidArgument`, and a `Failure` arrives as the response's failure item.
  - TLS, over a real listener: a client without a certificate is refused; a client certificate from another CA is refused; after the files are replaced, a new connection sees the new server certificate.
  - `/readyz` answers 503 until the certificates load, then 200.
  - The standard gRPC health check answers `SERVING`.
- [ ] **Step 2: Run them and see them fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Verify** with `make test` and `make lint`.
- [ ] **Step 5: Commit**: `feat(sdk): serve the collector API with mTLS, health and settings checks`

### Task 4: The conformance suite, the template project and the guide

**Files:**
- Create:
  - `sdk/conformance/conformance.go` and its test (envtest, for the presence check)
  - `templates/collector/` with `go.mod` (module `example.com/collector-template`), `main.go`, `collector.go`, `collector_test.go`, `Dockerfile`, `Makefile` and `README.md`
  - `docs/collectors.md`
- Modify: `go.work`

**Interfaces:**
- Consumes: Tasks 2 and 3
- Produces:

```go
package conformance
type Reporter interface {
	Helper()
	Errorf(format string, args ...any)
	Fatalf(format string, args ...any)
	Run(name string, f func(Reporter)) bool
}
type Target struct {
	Dial            func(ctx context.Context) (*grpc.ClientConn, error)
	Settings        json.RawMessage
	InvalidSettings json.RawMessage // optional: settings the collector must refuse
	Context         collector.Context
	Invocations     []Invocation  // the operations to call, with a subject, parameters and inputs each
	Client          client.Client // optional: a Kubernetes client, which turns on the presence check
}
type Invocation struct {
	Operation, Subject string
	Parameters         json.RawMessage
	Inputs             []cloudevents.Event // evidence of the types the operation consumes
}
func Run(t *testing.T, target Target)
func RunWith(r Reporter, target Target)
```

- **What the suite checks:**
  - `GetInfo` has a name, a version and `v1alpha1`.
  - Every schema in `GetCapabilities` compiles.
  - Every type it produces is reverse-DNS and versioned: `^[a-z0-9-]+(\.[a-z0-9-]+)+\.v[0-9]+((alpha|beta)[0-9]+)?$`.
  - Every operation produces only declared types.
  - **A watching collector:** `Watch` starts with `SnapshotStart` and reaches `SnapshotEnd` within 60 seconds. A second `Watch` starts with a snapshot again.
  - Every event is valid, of a declared type, and its `data` validates against the type's schema.
  - Each invocation, with its `Inputs`, returns valid events, or a failure with a reason.
  - **A presence collector,** when the `Target` has a Kubernetes client: the suite creates pods in scope, out of scope and with vexplain's own label, sets their image IDs, and checks that the snapshot lists only the one in scope (spec 5.5 and 5.11).
  - `InvalidSettings`, when set, is refused.

- **The template project** is a minimal collector:
  - It watches, and emits `com.example.hello.v1alpha1` about `workload/…`.
  - Its test runs `conformance.Run` against the collector in-process.
  - Its `Dockerfile` builds on distroless static, as non-root.
  - Its `go.mod` replaces the SDK with `../../sdk`. The README says to drop that line when the project is copied out.
- **`docs/collectors.md`:**
  - It explains how a collector works: the API, types and scopes, subjects, coverage, settings, packaging, the `Collector` resource, RBAC, the runtime config and conformance.
  - It links to the design of collectors, evidence and rules for the reasons.

- [ ] **Step 1: Write the failing tests.** The suite passes a good fake collector, whose operation receives the invocation's `Inputs`. It reports one named failure each for a fake that:
  - emits an undeclared type
  - never sends `SnapshotEnd`
  - emits an event whose `data` breaks its schema
  - accepts `InvalidSettings`
  - lists the pod out of scope, or the one with vexplain's own label, in its presence snapshot (envtest)

  These run through `RunWith` with a recording `Reporter`.
- [ ] **Step 2: Run them and see them fail.**
- [ ] **Step 3: Implement** the suite, the template project and the guide.
- [ ] **Step 4: Verify** with `make test`, which includes the template project's conformance test, and `make lint`.
- [ ] **Step 5: Commit**: `feat(sdk): add the conformance suite, the template project and the guide`

### Task 5: API: collectors, runtime configs, playbooks and rules

`Collector` gets its new shape now, so that playbooks can name collectors from Task 9 on. Until each collector moves into its package (Tasks 13 to 15), the in-process code reads its settings from `spec.settings`. Nothing deploys a package before Task 12.

**Files:**
- Modify: `api/config/v1alpha1/collector_types.go` (rewrite), `operatorconfig_types.go`, `common_types.go`, `PROJECT`, and `internal/settings/effective.go` for the new fields
- Create: `api/config/v1alpha1/collectorruntimeconfig_types.go`, `playbook_types.go`, `rule_types.go`, `config/samples/*`
- Modify, to keep 2a's code working:
  - `internal/controller/scan/job.go`: `loadScannerSettings` reads the same four fields from `spec.settings`
  - `internal/collector/defaults.go`: `EnsureDefaults` goes, because the install creates the `Collector`s, and so does its call in `internal/setup/setup.go`
  - `internal/collector/registry.go`: health is kept by `Collector` name, since `CollectorType` goes; its reporters, `internal/controller/scan/runner.go` and `internal/controller/inventory/podinventory_controller.go`, report as `scanner` and `workloads`
  - `internal/controller/config/collector_controller.go`: health by `Collector` name, `workloads` and `scanner`
- Test: `internal/controller/config/*_api_test.go`, CRD schemas and CEL through envtest

**Interfaces:**
- Produces:

```go
type CollectorSpec struct {
	// +required, +kubebuilder:validation:MinLength=1, MaxLength=512
	Package          string                  `json:"package,omitempty"`
	RuntimeConfigRef *RuntimeConfigReference `json:"runtimeConfigRef,omitempty"`
	// +kubebuilder:pruning:PreserveUnknownFields, +kubebuilder:validation:Schemaless
	Settings *runtime.RawExtension `json:"settings,omitempty"`
}
type RuntimeConfigReference struct{ Name string `json:"name,omitempty"` } // +required
type CollectorStatus struct {
	Conditions      []metav1.Condition     // Ready
	PackageDigest   string
	Version         string                 // what GetInfo answered: the version that evidence is written at
	Capabilities    *CollectorCapabilities // what GetCapabilities answered, bounded
	LastSuccessTime *metav1.Time
}
type CollectorCapabilities struct {
	Roles      []CollectorRole     // Spoke, Hub; listType=set, at most 2
	Produces   []ProducedType      // {Type, Scope Spoke|Hub}; listType=map on type, at most 32
	Consumes   []string            // at most 32
	Watch      CollectorWatch      // Supported or NotSupported
	Operations []CollectorOperation // {Name, Produces, Consumes}; listType=map on name, at most 16
}

type CollectorRuntimeConfigSpec struct { // no status
	DeploymentTemplate     *runtime.RawExtension `json:"deploymentTemplate,omitempty"`     // preserve unknown
	ServiceAccountTemplate *runtime.RawExtension `json:"serviceAccountTemplate,omitempty"` // preserve unknown
}

type PlaybookSpec struct {
	Subjects PlaybookSource   `json:"subjects"` // {Collector, Type}
	Findings PlaybookFindings `json:"findings"` // {Collector}
	Evidence []PlaybookEvidence `json:"evidence,omitempty"` // {Name, Collector, Type}; listType=map on name, at most 16
	Pipeline []PlaybookStep     `json:"pipeline"`           // {Rule}; at least 1, at most 32
}
type PlaybookStatus struct{ Conditions []metav1.Condition } // Ready

type RuleSpec struct {
	Inputs    []RuleInput `json:"inputs,omitempty"` // {Name, Type}; listType=map on name, at most 8
	Match     string      `json:"match,omitempty"`  // CEL, at most 4096
	Condition string      `json:"condition"`        // CEL, at most 4096, required
	Outcome   RuleOutcome `json:"outcome"`
	Reason    string      `json:"reason,omitempty"` // CEL giving a string, at most 4096
}
type RuleOutcome struct {
	Status        VEXStatus        // Affected, UnderInvestigation, NotAffected or Fixed; none: a hint
	Justification VEXJustification // the five OpenVEX justifications: set exactly when Status is NotAffected
}
type RuleStatus struct{ Conditions []metav1.Condition } // Ready, and Evaluated: False with EvaluationErrors while findings can't be evaluated

// OperatorConfigSpec gains:
type OwnerAttribution struct {
	NamespaceLabels, NamespaceAnnotations, WorkloadLabels []string // at most 16 each, qualified names
}
type Urgency struct {
	// listType=map on exploitation, exposure, automatable and humanImpact; at most 72
	Overrides []UrgencyOverride `json:"overrides,omitempty"`
}
type UrgencyOverride struct {
	Exploitation SSVCExploitation // None, PublicPoC, Active
	Exposure     SSVCExposure     // Small, Controlled, Open; Unknown, which reports use, is refused here
	Automatable  SSVCAutomatable  // No, Yes
	HumanImpact  SSVCHumanImpact  // Low, Medium, High, VeryHigh
	Outcome      SSVCOutcome      // Defer, Scheduled, OutOfCycle, Immediate
}
```

- **Names:**
  - An input or evidence name is a CEL identifier: `^[a-z][a-zA-Z0-9]{0,62}$`.
  - A collector or rule name is a DNS-1123 label.
  - A type matches Task 4's pattern.
- **New condition reasons:**
  - `Progressing`, `PackageInvalid`, `IncompatibleAPI`, `SettingsInvalid`, `MissingPermissions` and `RuntimeConfigInvalid`
  - for playbooks: `CollectorMissing`, `TypeNotProduced`, `RuleMissing`, `RuleNotReady`, `InputMissing` and `Conflict`
  - for rules: `EvaluationErrors`
- `spec.rules` stays on `OperatorConfig` until Task 9 replaces its reader.

- [ ] **Step 1: Write the failing tests.**
  - A `Collector` without `package` is refused. Settings of any shape are kept.
  - The old `spec.type` is refused as an unknown field.
  - A `Rule` with `NotAffected` but no `justification`, or with a `justification` and another status, is refused. A rule without a status, a hint, is accepted.
  - An input name `1x` is refused.
  - A `Playbook` without a pipeline is refused.
  - An `UrgencyOverride` repeated on the same four keys is refused, and so is one with exposure `Unknown`.
  - The in-process scan runner reads `maxConcurrentScans: 3` from `spec.settings`.
  - Health that the in-process scanner reports shows on the `Collector` named `scanner`.
- [ ] **Step 2: Run them and see them fail.**
- [ ] **Step 3: Implement**, with `make manifests generate`.
- [ ] **Step 4: Verify** with `make test` and `make lint`.
- [ ] **Step 5: Commit**: `feat(api): add CollectorRuntimeConfig, Playbook and Rule, and give Collector its package shape`

### Task 6: API: evidence and workload reports

**Files:**
- Create:
  - `api/inventory/v1alpha1/evidence_types.go`
  - `api/triage/v1alpha1/` with `groupversion_info.go` and `workloadreport_types.go`, through `kubebuilder create api --group triage --version v1alpha1 --kind WorkloadReport --namespaced`
- Test: `internal/controller/inventory/evidence_api_test.go`, `internal/controller/triage/workloadreport_api_test.go`

**Interfaces:**
- Produces:

```go
type EvidenceSpec struct { // cluster-scoped; the whole spec immutable (CEL self == oldSelf)
	Subject          string           // at most 512
	Type             string           // at most 253
	Source           string           // the Collector's name
	CollectorVersion string           // at most 128
	Time             metav1.Time
	Coverage         *int32           // 0–100
	Platform         string           // os/arch[/variant], for manifests
	DataSchema       string           // at most 512
	Encoding         EvidenceEncoding // GzipJSON
	Data             []byte           // at most 1048576 base64 characters, which is 786432 bytes
	UncompressedBytes int64           // at most 67108864
}

type WorkloadReportSpec struct { // namespaced; spec immutable
	Workload WorkloadReference // {APIGroup, Kind, Name}
}
type WorkloadReportStatus struct {
	Conditions []metav1.Condition
	Images     []ReportImage   // {Digest, Platform, ManifestDigest, State: Pending, Ready or Incomplete, Coverage []ReportCoverage}; at most 32
	Findings   []ReportFinding // at most 1000; listType=atomic
	Omitted    int32           // actionable findings that didn't fit
	Counts     ReportCounts    // {Affected, UnderInvestigation, NotAffected, Fixed}
	Owner      []OwnerValue    // {Source: NamespaceLabel, NamespaceAnnotation or WorkloadLabel; Key; Value}; listType=map on source and key
	Exposure   SSVCExposure    // Small, Controlled, Open or Unknown
}
type ReportFinding struct {
	VulnerabilityID string
	Package         ReportPackage // {Name, Version, Type}
	Status          VEXStatus     // Affected or UnderInvestigation
	Urgency         SSVCOutcome
	NextStep        NextStep      // Update, Mitigate or Investigate
	FixedVersion    string
	ReviewState     ReviewState   // RuleSettled or Open; agent states arrive in phase 4
	Reason          string        // at most 256, printable
	StatusNotes     []ReportStatusNote // {Rule, Text}: the sheet's status notes; at most 4, printable
	Severity        string
}
type ReportCoverage struct { // each evidence's coverage by source, from the facts; listType=map on source and type; at most 32
	Source, Type string
	Coverage     int32 // 0–100
}
```

- **Sizes:** strings are bounded as in `ImageVerdicts`.
- The docs of both kinds say that their text comes from image content and is data. The docs of `coverage` say that the core shows it and never interprets it (spec 5.5).

- [ ] **Step 1: Write the failing tests.**
  - An `Evidence` can't be changed after it's created.
  - Coverage 101 is refused, and so is a platform `linux`.
  - `data` above the cap is refused.
  - A `WorkloadReport` can't change its workload.
  - 1001 findings are refused.
  - A report of 1 MiB, the size that Task 21 keeps it under, is accepted.
- [ ] **Step 2: Run them and see them fail.**
- [ ] **Step 3: Implement**, with `make manifests generate`.
- [ ] **Step 4: Verify** with `make test` and `make lint`.
- [ ] **Step 5: Commit**: `feat(api): add Evidence and WorkloadReport`

### Task 7: The evidence store, and generic facts

2a's in-process runner writes the scanner's evidence as CloudEvents through the new store. The hub reads it there, and `ImagePackages` goes.

**Files:**
- Create: `internal/evidence/store.go`, `crdstore.go`, `facts.go`, and their tests
- Modify:
  - `api/inventory/v1alpha1/imageinventory_types.go`: generic facts
  - `internal/inventory/store.go`: `SetFacts` takes the new facts
  - `internal/controller/scan/runner.go`: writes events, and facts through `evidence.FactsWriter`
  - `internal/controller/hub/{scheduler,verdicts,janitor}.go`: read the evidence store and the new facts
  - `internal/setup/setup.go`, `hack/measure-2a`
- Delete: `api/inventory/v1alpha1/imagepackages_types.go`, `internal/inventory/packages.go` and their tests

**Interfaces:**
- Consumes: Task 2's `evidence` package; Task 6's `Evidence`
- Produces:

```go
package evidence
type Key struct{ Subject, Type, Source string }
type Record struct {
	Key
	CollectorVersion string
	Event            cloudevents.Event
}
var ErrTooLarge = errors.New("the evidence is larger than the store's cap")
type Store interface {
	// Put stores an event once per key and collector version. A record of another version is
	// replaced; one of the same version is left as it is.
	Put(ctx context.Context, source, collectorVersion string, e cloudevents.Event) error
	Get(ctx context.Context, k Key) (*Record, error) // nil, nil when absent
	ListBySubject(ctx context.Context, subject string) ([]Record, error)
	DeleteSubject(ctx context.Context, subject string) error
	DeleteBySource(ctx context.Context, source string) error
	Subjects(ctx context.Context) ([]string, error)
	Source() source.Source // one request per created or deleted record, named by subject
}
func NewCRDStore(c client.Client, cache cache.Cache) Store
const MaxCompressedBytes = 786432

type FactsWriter interface {
	// Succeeded records the manifests per platform of an image, and each event's source, type,
	// version, time and coverage. It never creates an ImageInventory.
	Succeeded(ctx context.Context, image string, source, collectorVersion string, events []cloudevents.Event) error
	Failed(ctx context.Context, image string, source, reason, message string) error // keeps the facts, counts attempts
}
```

```go
// ImageFacts becomes:
type ImageFacts struct {
	Manifests []ManifestFact // {Platform, Digest}; at most 16
	Evidence  []EvidenceFact // {Source, Type, CollectorVersion, Time, Coverage}; listType=map on source and type; at most 32
	Failures  []ScanFailure  // {Source, Reason (string; 2a's reasons first), Message, Time, Attempts}; listType=map on source; at most 8
}
```

- [ ] **Step 1: Write the failing tests.**
  - `Put` then `Get` gives the same event.
  - A second `Put` of the same version writes nothing; another version replaces the record.
  - An event over the cap gives `ErrTooLarge` and writes nothing.
  - `DeleteBySource` removes only that collector's records.
  - `Succeeded` writes the manifests from the `platform` extension, and never creates an `ImageInventory`.
  - `Failed` keeps the earlier facts and adds one attempt.
  - 2a's store gaps: `SetFacts(nil)` is pinned, and a partial `Forget` keeps the facts.
  - The hub's chain spec runs through the new store and still writes the same sheet.
- [ ] **Step 2: Run them and see them fail.**
- [ ] **Step 3: Implement.** The CRD store compresses `data` with gzip. Records are named `ev-` plus the first 40 hex digits of the SHA-256 of `subject|type|source`, and labelled with the source and with hashes of the subject and type. Each carries its subject in the annotation `vexplain.bedag.ch/subject`, so that `Subjects()` and `Source()` work from a metadata-only cache: the name and labels are hashes, and the data is read uncached. The manager's client reads `Evidence` uncached, as 2a did for `ImagePackages`.
- [ ] **Step 4: Verify** with `make test` and `make lint`.
- [ ] **Step 5: Commit**: `feat(evidence): store evidence as CloudEvents, and keep generic facts`

### Task 8: The CEL rules engine and the default rules

**Files:**
- Create: `internal/rules/engine/engine.go`, `env.go`, `engine_test.go` and `defaults_test.go`
- Create: `config/rules/kustomization.yaml`, `known-exploited.yaml`, `completeness-guard.yaml`, `removed-in-later-layer.yaml` and `load-check.yaml`
- Create: `internal/text/text.go` and its test: 2a's printable-text helpers (`printable`, `required`, `cutChars` and `cutBytes`), moved out of `internal/rules/rules.go`, which Task 9 strips, into one package for this task and Task 21
- Modify: `internal/rules/rules.go`, which takes them from `internal/text`

**Interfaces:**
- Consumes: Task 5's `Rule`; Task 2's `evidence.Match`
- Produces:

```go
package engine
type Input struct {
	Present  bool
	Data     any // the event's data, decoded from JSON
	Coverage *int32
	Time     time.Time
	Source   string
}
type Compiled struct{ /* the rule's name, outcome and programs */ }
func Compile(r *configv1alpha1.Rule) (*Compiled, error) // a cost limit of 1,000,000 per evaluation
// Unavailable stands for a step whose rule is missing or not Ready. It can't be evaluated and might
// hold, so it keeps every finding from NotAffected and Fixed (fail closed, spec 5.7).
func Unavailable(name, reason string) *Compiled
type Note struct{ Rule, Text string } // OpenVEX's status_notes
type Finding struct {
	Match         evidence.Match           // merged per vulnerability and package, as 2a merged matches
	Status        configv1alpha1.VEXStatus // Affected, UnderInvestigation, NotAffected or Fixed
	Rule, Reason  string
	Justification configv1alpha1.VEXJustification
	Notes         []Note // from hints, at most 4
}
// Evaluate runs the steps for each finding, under the core's guarantee and the order of statuses.
// It is pure: the same input always gives the same output.
func Evaluate(steps []*Compiled, inputs map[string]Input, matches []evidence.Match) []Finding
```

- **The CEL environment:** the variable `finding`, with the fields of `evidence.Match` in lower camel case, and one variable per input name: `{data, coverage, time, source}`. An input without coverage has no `coverage` key.
- **The core's guarantee:**
  - A rule applies only when all its inputs are present.
  - **Fail closed:** when an `Affected` or `UnderInvestigation` rule can't be evaluated for a finding (an input is missing, its CEL errors, or it hits the cost limit), neither `NotAffected` nor `Fixed` applies to that finding. The finding records that rule, with the reason `could not be evaluated: <error>`, cut to 256 characters.
  - The same applies to every finding when the rule's `match` fails.
- **The order:** `Affected`, then `UnderInvestigation`, then `Fixed`, then `NotAffected`. Between two rules with the same status, the first by name decides. Notes add up, at most 4 per finding, the first by rule name.
- **Text** from evidence is made printable and cut to the schema's limits with 2a's helpers, now in `internal/text`.
- Task 9 turns these findings into the sheet's.

- [ ] **Step 1: Write the failing tests.**
  - `defaults_test.go` loads the four YAML files and replays 2a's decision table from 2a's Task 9, with the load check now a hint:

    | Case | Status / rule / note |
    |---|---|
    | KEV, even where "removed in a later layer" would settle it | `UnderInvestigation` / `known-exploited`, reason `known exploited` (0035) |
    | Completeness 80 | `UnderInvestigation` / `completeness-guard`, reason `completeness 80% is below 90%` |
    | `filesListed 3, filesPresent 0` | `NotAffected` / `removed-in-later-layer` / `ComponentNotPresent` |
    | Unreached library package | `UnderInvestigation`, note `load-check`: `nothing in the image reaches or names its libraries` |
    | Reached | note `reached by /usr/bin/curl` |
    | Named | note `named in /app/load.py` |
    | Preload | note `the image preloads libraries` |
    | A repeated library entry | note `the library evidence is incomplete` |
    | Owns an executable, or no library | `UnderInvestigation`, no rule, no note |
    | Unknown package ID | `UnderInvestigation`, no rule |

  - `engine_test.go`:
    - A guard whose CEL errors on one finding keeps a `NotAffected` rule from settling it. The finding records the guard and `could not be evaluated: …`.
    - The same happens when the guard's input is missing, and when it hits the cost limit.
    - A `NotAffected` rule whose CEL errors doesn't apply, and nothing else changes.
    - A failing `match` holds every finding.
    - An `Unavailable` step keeps every finding from `NotAffected` and `Fixed`, and each finding records it with `could not be evaluated: <reason>`.
    - The steps in reverse order give the same findings.
    - A package name with control characters is printable in the finding.
- [ ] **Step 2: Run them and see them fail.**
- [ ] **Step 3: Implement**, with `github.com/google/cel-go` as a direct dependency.
- [ ] **Step 4: Verify** with `make test` and `make lint`.
- [ ] **Step 5: Commit**: `feat(rules): evaluate CEL rules under the core's guarantee, and port 2a's rules to it`

### Task 9: Playbooks and the assessor

The assessor replaces 2a's scheduler, verdicts controller and database poller. It gets its findings through a `Findings` interface, from 2a's HTTP matcher until Task 15, and asks for evidence through the general request, which 2a's in-process runner serves until Task 14.

**Files:**
- Create: `internal/controller/hub/playbook_controller.go`, `assessor.go`, `findings.go`, `rule_controller.go`, and their tests (envtest)
- Create: `config/playbooks/kustomization.yaml`, `container-cves.yaml`
- Modify:
  - `internal/tasks/tasks.go`: `Request` replaces `ScanRequest`
  - `internal/controller/scan/queue.go`: serves `Request` for the scanner's type
  - `internal/controller/hub/janitor.go`
  - `api/inventory/v1alpha1/imageverdicts_types.go`: `outcome` becomes `status`, with the four statuses, and the counts follow; `justification` takes OpenVEX's five justifications, and is set exactly for `NotAffected`: both take the same values as `Rule`'s; `rule` becomes a string; each finding gains `statusNotes`, `knownExploited` and up to 4 CVSS vectors; the sheet gains `evidence`, `findingsVersion` and `playbook`; `databaseVersion` and `scannerImage` go; the docs of `PackageReference.id` and `version` say that the ID may be one the evidence lacks, and that no version and an empty one are the same
  - `internal/inventory/verdicts.go`: `VerdictsStore.Put` says what it does when only `findingsVersion` changes
  - `api/inventory/v1alpha1/imageinventory_types.go`: `ClusterPresence` gains `platforms`, at most 8, each `os/arch[/variant]`
  - `internal/inventory/store.go`: `Observation` gains `Platforms`
  - `internal/rules/rules.go`: 2a's Go rules go; `Sheet` stays, in `internal/rules/sheet.go`, and orders the new findings
  - `api/config/v1alpha1/operatorconfig_types.go`: `spec.rules` goes
  - `internal/settings`, `internal/setup/setup.go`
  - `hack/measure-2a`, its tests and `cases.yaml`: the tool moves to `engine.Evaluate` and the new sheet, and the answers to the statuses (below)
- Delete: `internal/controller/hub/scheduler.go`, `verdicts.go`, `dbpoller.go`, and 2a's Go rules

**Interfaces:**
- Consumes: Tasks 5, 7 and 8
- Produces:

```go
package tasks
type Request struct {
	Type, Subject string   // the type asked for, and an image subject
	Repositories  []string
}
type Executor interface { Request(ctx context.Context, r Request) error } // returns at once; results arrive through the stores

package hub
type Findings interface {
	// Find matches one manifest's evidence. The event is of a type the findings collector consumes.
	Find(ctx context.Context, collector string, input cloudevents.Event) (evidence.Findings, error)
	// Changed delivers the subjects to match again; an empty list means every subject.
	Changed() source.Source
}
```

- **The playbook controller** sets `Ready`:
  - `CollectorMissing` when a named `Collector` doesn't exist
  - `TypeNotProduced` when its status shows capabilities without the named type (until Task 12 there are none, so this check is skipped)
  - `RuleMissing` or `RuleNotReady` for a missing rule, or one that isn't `Ready`
  - `InputMissing` when a rule's input name isn't in `evidence`, or its type differs
  - `Conflict` for the newer of two playbooks with the same subjects
- **The rule controller** compiles each `Rule` and sets `Ready`. It sets `Evaluated` from the rule's count of findings that the assessor records as "could not be evaluated": `False` with the reason `EvaluationErrors` and the count in the message while the count isn't 0, and `True` otherwise (spec 5.7).
- **The assessor**, for each image in presence and each `Ready` playbook whose subjects are the presence type, which covers every image in `ImageInventory`:
  - An image ID gets the failure `NotPullable` once, as in 2a.
  - The evidence that the findings collector consumes and that the playbook names is asked for through `tasks.Executor` when the evidence store, not the facts, lacks it for a manifest at the current collector version. Retries follow 2a's backoff, at most daily.
    - Until Task 12 records capabilities, the HTTP matcher adapter declares the type it consumes: the scanner's.
    - The current collector version is the scanner image, as in 2a, until Task 14 makes it the `Collector`'s `status.version`, which its `GetInfo` reports.
  - **Platforms:** an image is asked for again when its presence entry's `platforms` lists a platform that its facts don't. Task 13's `spoke.Presence` fills the list from the pods' nodes; until then it stays empty, and an empty list means no new platform. This settles 2a's open question on platforms that start running later.
  - Then, for each manifest, it calls `Findings.Find`, then `engine.Evaluate` with the playbook's steps and named inputs, turns the result into the sheet's findings, orders them with `rules.Sheet`, and writes the sheet with:
    - `evidence`, one entry per input: name, source, type, `version` (the collector's), time, coverage
    - `findingsVersion` and `playbook`
  - A change to a rule or playbook evaluates again from the sheet's findings, without matching again, unless the sheet has `omittedFindings` above 0. Then it matches again (`Find`), because settled findings are left out first and couldn't be reopened from the sheet.
  - `Findings.Changed` matches again.
- **A playbook that isn't `Ready`** because a `Collector` or rule that it names is missing, or a rule isn't `Ready`, still has its sheets evaluated again from their findings. The missing collector's inputs are absent, and a missing or not-`Ready` rule is an `engine.Unavailable` step: it can't be evaluated and might hold, so it keeps the findings from `NotAffected` and `Fixed` (fail closed; spec 5.7 and 5.9). A playbook that is `TypeNotProduced` or `InputMissing` is evaluated again in the same way, with the affected inputs absent. Only a playbook in `Conflict` leaves its sheets alone.
- **The janitor** deletes evidence and sheets for manifests that no facts name, after 2a's grace.
- **The measurement tool** (`hack/measure-2a`) moves to `engine.Evaluate` and the new sheet here, because 2a's rules go and `make test` compiles it (`go vet ./...`):
  - It reads `Evidence` and the new sheets through the stores.
  - It builds the second column with `engine.Evaluate`, running the default rules with `knownExploited` cleared.
  - It checks first that evaluating the stored inputs again gives the stored sheet, as before.
  - `cases.yaml`'s answers take the statuses' names: `NeedsAssessment` becomes `UnderInvestigation`, and `Suppressed` becomes `NotAffected`. The first column's `Tracked` answers become `UnderInvestigation`, for the hold (0035). `NoPackage` and `NotFound` stay. `approved` stays `false` until the owner approves them.
- **`container-cves.yaml`:**
  - subjects: `workloads`, type `ch.bedag.vexplain.presence.v1alpha1`
  - findings: `matcher`
  - evidence: `contents` from `scanner`, type `ch.bedag.vexplain.scanner.image-contents.v1alpha1`
  - pipeline: the four default rules
- **The sheet's contract,** in the docs of `ImageVerdicts`:
  - the order of findings
  - an `omittedFindings` above the counts of `NotAffected` and `Fixed` findings means that the sheet leaves out open findings, and must be shown as incomplete
  - a sheet without `counts` or `findingsVersion` means "no verdict yet", never "no findings"

- [ ] **Step 1: Write the failing tests** (envtest):
  - **The chain:** an image with evidence and a fake `Findings` gives 2a's chain spec's sheet in the new names: the KEV finding `UnderInvestigation` by `known-exploited` (0035), the load check as a status note with no rule, and `Rule` names as strings, plus `evidence` and `playbook`.
  - **2a's small gaps:** a store test changes only `findingsVersion`, and the chain spec sees the sheet go, then come back.
  - **A settled finding through the hub:** the fixture keeps a package that a later layer removed, so `counts.notAffected` is 1.
  - **The playbook's `Ready`:**
    - deleting the scanner's `Collector` gives `CollectorMissing`, and drops `counts.notAffected` to 0, with the findings naming the missing input
    - a rule with an unknown input name gives `InputMissing`
    - a second playbook with the same subjects gives `Conflict`
  - **Changes to rules and findings:**
    - a changed rule threshold changes the sheet without a call to `Find`
    - on a sheet with `omittedFindings` above 0, a changed rule calls `Find`
    - `Changed` with no subjects matches every manifest again
  - **The rule's `Evaluated`:** a guard whose CEL errors on a finding gets `False`, reason `EvaluationErrors`, with the count, and `True` again once it evaluates without errors.
  - **Platforms:** a presence entry that lists a platform the facts don't asks for the image again, and an empty `platforms` asks for nothing more.
  - **The janitor:** it keeps evidence that one of two digests still names, and deletes it once neither does.
- [ ] **Step 2: Run them and see them fail.**
- [ ] **Step 3: Implement.** The HTTP matcher client of 2a implements `Findings` until Task 15. Its `Changed` polls the database's version, as 2a's poller did.
- [ ] **Step 4: Verify** with `make test` and `make lint`.
- [ ] **Step 5: Commit**: `feat(hub): assess images through playbooks, and ask for evidence by type`

### Task 10: The collectors' certificates

**Files:**
- Create: `internal/collector/certs/authority.go` and its test
- Modify: the RBAC markers, so the operator can update Secrets in its namespace

**Interfaces:**
- Produces:

```go
package certs
type Authority struct{ /* … */ }
// reader is the manager's API reader, which reads the CA and TLS Secrets; c writes them.
func NewAuthority(c client.Client, reader client.Reader, namespace string, now func() time.Time) *Authority
// EnsureCA loads the CA from the Secret vexplain-collector-ca, or creates it.
func (a *Authority) EnsureCA(ctx context.Context) error
// EnsureServer writes or renews vexplain-collector-<name>-tls (tls.crt, tls.key, ca.crt), with the
// names vexplain-collector-<name>.<namespace>.svc and .svc.cluster.local.
func (a *Authority) EnsureServer(ctx context.Context, collector string) (renewed bool, err error)
// ClientTLS gives the operator's client side: its own certificate, held in memory and renewed in
// time, and the CA as its roots.
func (a *Authority) ClientTLS() (*tls.Config, error)
func ServerName(collector, namespace string) string
```

- **Secrets are read through the manager's API reader.** The manager's cache holds only the Secrets labelled as LLM keys, and keeps that selector (design 6.11), so it never sees the CA and TLS Secrets.

- [ ] **Step 1: Write the failing tests.**
  - The CA is created once and reused.
  - A server certificate verifies against the CA, for its own name only.
  - With 31 days left, nothing changes; with 29, the server certificate is renewed.
  - A CA Secret that was deleted is created again, and every server Secret signed by the old CA is renewed.
  - The client certificate from `ClientTLS` verifies against the CA, and is renewed with 29 days left.
- [ ] **Step 2: Run them and see them fail.**
- [ ] **Step 3: Implement** with the standard library only.
- [ ] **Step 4: Verify** with `make test` and `make lint`.
- [ ] **Step 5: Commit**: `feat(collector): issue and renew the collectors' certificates`

### Task 11: The collector client and the stream manager

**Files:**
- Create: `internal/collectorclient/pool.go`, `streams.go`, `invoke.go`, and their tests (envtest, with in-process SDK servers)

**Interfaces:**
- Consumes: Tasks 3 and 10
- Produces:

```go
package collectorclient
type Pool struct{ Dialer func(ctx context.Context, address string) (net.Conn, error) /* tests replace it */ }
func NewPool(clientTLS func() (*tls.Config, error), namespace string) *Pool
func (p *Pool) Info(ctx context.Context, collector string) (*collectorv1alpha1.GetInfoResponse, error)
func (p *Pool) Capabilities(ctx context.Context, collector string) (*collectorv1alpha1.GetCapabilitiesResponse, error)
func (p *Pool) ValidateSettings(ctx context.Context, collector string, settings []byte) ([]string, error)
type Failure struct{ Reason, Message string }
func (p *Pool) Invoke(ctx context.Context, collector string, req *collectorv1alpha1.InvokeRequest) ([]cloudevents.Event, *Failure, error)
func (p *Pool) Health(ctx context.Context, collector string) error // the standard gRPC health check; nil when SERVING
func (p *Pool) Forget(collector string)

// Usable says whether streams and requests may use the collector: the deployer recorded its
// capabilities, and its Ready isn't False for PackageInvalid, IncompatibleAPI, SettingsInvalid,
// MissingPermissions, RuntimeConfigInvalid, WrongRole (from phase 6) or CollectorFailing. NoData,
// which is Unknown until the first health check, is usable.
func Usable(c *configv1alpha1.Collector) bool

type Sink interface {
	Snapshot(collector string, events []cloudevents.Event) // replaces what the collector delivered before
	Upsert(collector string, e cloudevents.Event)
	Remove(collector, eventType, subject string)
	SourceChanged(collector string, subjects []string)
	Forget(collector string) // drops what the collector delivered; called when its Collector goes
}
type Streams struct{ /* a manager.Runnable */ }
// NewStreams takes one sink per role: the spoke's Router serves Spoke (Task 13), and the hub's sink
// in internal/controller/hub serves Hub (Task 15).
func NewStreams(p *Pool, c client.Client, sinks map[configv1alpha1.CollectorRole]Sink, context func(ctx context.Context) (*collectorv1alpha1.Context, error)) *Streams
```

- **The pool** dials `vexplain-collector-<name>.<namespace>.svc:9443` with mTLS, checking the name from `certs.ServerName`. It uses gzip and messages up to 16 MiB.
- **The streams:**
  - For each usable `Collector` (`Usable`) that supports `Watch`, `Streams` keeps one `Watch` open per role it declares, with its `spec.settings` and the context. Only a collector that is unhealthy or incompatible gets no new requests (spec 5.9).
  - Each role's streams go to that role's sink. Hub and spoke meet only through `tasks.Executor` and the stores (0021), so a hub-only deployment stays possible.
  - The context is built from `OperatorConfig`: the cluster name, the operator's namespace, the task label, the scope and the owner allowlists.
  - Events between `SnapshotStart` and `SnapshotEnd` are held, and handed to `Sink.Snapshot` only at `SnapshotEnd`. A stream that breaks during a snapshot hands over nothing from it.
  - After a snapshot, changes pass through as they come.
  - A broken stream opens again after 1 second, doubling to at most 60 seconds, and starts with a new snapshot. It isn't a health failure.
  - A change to the settings, the context or the running digest restarts the stream.
  - A `Collector` that goes away has its stream stopped and its connection closed, and each sink's `Forget` drops what it delivered. That evidence isn't stored (decision 10), so `DeleteBySource` can't remove it, and spec 5.9 removes a deleted collector's evidence.
- **Health** comes only from the deployer's standard gRPC health check (Task 12). A `Failure` about one subject and a broken stream are no health failures, and neither touches evidence.

- [ ] **Step 1: Write the failing tests.**
  - A whole snapshot arrives as one `Snapshot` call.
  - **Review Focus 1:** a stream cut after two of three snapshot events hands over nothing, and the earlier snapshot stays. The next stream's snapshot replaces it.
  - A change to `spec.settings`, or to the scope in `OperatorConfig`, opens a new stream with the new values.
  - `Invoke` returns the events, or the failure.
  - A `Collector` with recorded capabilities and `Ready` Unknown (`NoData`) gets a stream; one that is `False` with `SettingsInvalid` doesn't.
  - A `Hub` stream's `SourceChanged` reaches the hub's sink, and a `Spoke` stream's snapshot the spoke's.
  - A deleted `Collector`'s stream stops, and each sink's `Forget` is called with its name.
  - A broken stream doesn't call the sink, and reports no health.
- [ ] **Step 2: Run them and see them fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Verify** with `make test` and `make lint`.
- [ ] **Step 5: Commit**: `feat(collectorclient): call collectors over mTLS and keep their streams`

### Task 12: The deployer

**Files:**
- Modify: `internal/controller/config/collector_controller.go` (rewritten)
- Create: `internal/controller/config/collector_deploy.go`, `collector_merge.go`, `collector_permissions.go`, and their tests (envtest, with RBAC authorization on for the permission checks)
- Modify: `internal/evidence/facts.go` and its test, for `FactsWriter.RemoveSource`
- Modify: the RBAC markers:
  - Deployments, Services, service accounts and Secrets in the operator's namespace, and creating `SubjectAccessReview`s
  - pods (`get;list;watch`) in the operator's namespace, since `status.packageDigest` comes from the pod's `imageID`
  - `collectors` (`update`), for the finalizer, and `collectorruntimeconfigs` (`get;list;watch`)

**Interfaces:**
- Consumes: Tasks 5, 7, 10 and 11
- Produces:

```go
package evidence
type FactsWriter interface {
	// Task 7's Succeeded and Failed, and:
	// RemoveSource removes a source's evidence entries, and a failure it reported, from every image's facts.
	RemoveSource(ctx context.Context, source string) error
}
```

- **For each `Collector`, the deployer keeps, all labelled `vexplain.bedag.ch/collector: <name>` and owned by the `Collector`:**
  - the TLS Secret, through `Authority.EnsureServer`
  - the service account, with the metadata of `serviceAccountTemplate`
  - a Service with the ports 9443 (`grpc`) and 8081 (`http`)
  - a Deployment, with one replica and the container `collector`:
    - the image from `spec.package`
    - the environment `VEXPLAIN_COLLECTOR_NAME`, `POD_NAMESPACE`, `VEXPLAIN_LISTEN=:9443`, `VEXPLAIN_HEALTH_LISTEN=:8081` and `VEXPLAIN_TLS_DIR=/run/vexplain/tls`, plus the manager's proxy variables
    - the TLS Secret mounted at `/run/vexplain/tls`
    - readiness `/readyz` and liveness `/healthz` on 8081
    - the hardened defaults of the Global Constraints
- **Secrets:** the deployer reads the CA and TLS Secrets through the manager's API reader, as the `Authority` does. The manager's cache holds only the Secrets labelled as LLM keys, and keeps that selector (design 6.11).
- **The runtime config:**
  - `deploymentTemplate` is merged onto that Deployment as a strategic merge patch.
  - Then the deployer sets the contract's fields again: the image, the TLS volume and its mount, the ports and the contract's environment.
  - A template that doesn't decode leaves everything as it was, and sets `Ready=False` with reason `RuntimeConfigInvalid`.
- **Once the Deployment is available:**
  - `GetInfo`: without `v1alpha1`, `Ready=False`, `IncompatibleAPI`.
  - A malformed `GetInfo` or `GetCapabilities` answer gives `Ready=False`, `PackageInvalid`: no name or version, a produced type without a schema (decision 0032), a schema that doesn't compile, a type outside Task 4's pattern, or more than `status.capabilities` holds.
  - `GetInfo`'s version goes into `status.version`, `GetCapabilities` into `status.capabilities`, and `status.packageDigest` comes from the pod's `imageID`.
  - The settings are checked against the schema and with `ValidateSettings`. Problems give `SettingsInvalid`, with the first problems in the message.
  - Each declared permission is checked with a `SubjectAccessReview` for the service account. What's missing gives `MissingPermissions`, listed in the message.
  - Otherwise the condition follows health: `NoData` (Unknown) until the first check, then `Healthy` or `CollectorFailing`.
    - The deployer runs the standard gRPC health check (spec 5.3) with `Pool.Health` at each resync, every 30 seconds as in 2a. Only that check sets `Healthy` or `CollectorFailing`.
    - The health registry isn't read any more. 2a's in-process collectors show no health until their packages take over (Tasks 13 and 14), and Task 14 deletes the registry with its last reporter.
    - A `Failure` about one subject goes to the facts, and a broken stream opens again: neither is a health failure.
    - A change to `False` emits `CollectorUnhealthy` on the `Collector` (0014). That closes 2a's "the scanner's health".
- **Deletion:** the finalizer `vexplain.bedag.ch/evidence` calls `evidence.Store.DeleteBySource`, removes the collector's entries from the facts with `FactsWriter.RemoveSource`, and calls `Pool.Forget`, then lets go (spec 5.9: deletion removes a collector's evidence). The owned objects go by garbage collection: each carries the `Collector` as its controller owner reference.
- **The `default` runtime config:** the operator creates it empty at start when it's missing, and never overwrites it. A `Collector` without `runtimeConfigRef` uses it.

- [ ] **Step 1: Write the failing tests.**
  - The Deployment has the hardened defaults and the contract's fields.
  - A template that sets a node selector, a CPU limit, a label and `imagePullPolicy: Always` has them applied. A template that sets the image or drops the TLS volume doesn't change those.
  - A template that doesn't decode gives `RuntimeConfigInvalid`.
  - Against an in-process collector:
    - its capabilities are recorded
    - a collector that speaks only `v9` gives `IncompatibleAPI`
    - a collector whose capabilities declare a type outside Task 4's pattern gives `PackageInvalid`
    - settings that break the schema give `SettingsInvalid`
    - a service account without a declared verb gives `MissingPermissions`
    - until its first health check it is `NoData`; a check that answers `NOT_SERVING` gives `CollectorFailing`, and one that answers `SERVING` again gives `Healthy`
  - A failing collector emits `CollectorUnhealthy` once, on the change.
  - **Review Focus 3:** deleting a `Collector` deletes its evidence and its entries in the facts. Its Deployment, Service, service account and Secret carry the `Collector` as their controller owner; their deletion is left to e2e spec 19, because envtest runs no garbage collector.
- [ ] **Step 2: Run them and see them fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Verify** with `make test` and `make lint`.
- [ ] **Step 5: Commit**: `feat(config): deploy collectors from their packages, shaped by a runtime config`

### Task 13: The `workloads` collector, and presence on the spoke

**Files:**
- Create:
  - `collectors/workloads/` with `go.mod`, `Dockerfile`, `cmd/workloads/main.go`, `internal/presence/watcher.go` and `build.go`, and their tests (envtest)
  - `sdk/workloads/`, moved from `internal/workloads`, with mirror pods added
  - `sdk/scope/`, moved from `internal/scope`
  - `internal/spoke/presence.go`, `router.go`, and their tests
- Delete: `internal/controller/inventory/podinventory_controller.go` and its tests, `internal/scope` and `internal/workloads`. The operator's pod index stays until Task 14, now through `sdk/workloads`.
- Modify:
  - `internal/setup/setup.go`, `go.work`, `Makefile` (the collector's image)
  - `internal/inventory/store.go`: `Observation` takes its workloads from `sdk/workloads`
  - `internal/controller/config/operatorconfig_controller.go`: the scope comes from `sdk/scope`
  - `hack/measure-2a` and `hack/inventory-load`: their imports of `internal/workloads` move to `sdk/workloads`, since `make test` compiles them

**Interfaces:**
- Consumes: Tasks 2, 3 and 11
- Produces:

```go
package spoke
// Presence implements collectorclient.Sink for the presence type. It writes presence entries
// through inventory.Store, and keeps the latest presence per image for the executor and the renderer.
type Presence struct{ /* … */ }
func NewPresence(store inventory.Store, cluster func(ctx context.Context) (name, id string, err error)) *Presence
func (p *Presence) Workloads(image string) []evidence.PresenceWorkload
func (p *Presence) Images() []string
// Router implements collectorclient.Sink for the Spoke role, and hands each event type to its
// consumer. It hands each snapshot to the consumer of every type that the collector declares, so an
// empty snapshot reaches them too. Task 19 adds exposure.
type Router struct{ /* … */ }
func NewRouter(c client.Reader, presence *Presence) *Router // c reads the types each Collector declares
```

- **The collector:**
  - **Capabilities:** role `Spoke`; it watches; it produces the presence type, with scope `Spoke`; its settings schema is an empty object.
  - **Permissions:** list and watch pods, namespaces and nodes, and the metadata of ReplicaSets and Jobs, across the cluster.
  - **Each event:**
    - one per reported digest, about `image/<digest>`
    - every workload in scope that runs the digest, with its UID, its pods, and each pod's node and platform (from the node's `kubernetes.io/os` and `kubernetes.io/arch` labels)
    - only the allowlisted labels and annotations
  - **What it applies from the context:** the scope, the owner allowlists, and the task label, which counts only in the operator's namespace.
  - **The snapshot and changes:** a snapshot at start, then an upsert for each digest whose presence changed, and a tombstone for one that no workload in scope runs any more.
  - **Mirror pods:** each is its own workload, of kind `Pod`.
  - **Its metrics:** `vexplain_containers_skipped{cluster, reason}` on `/metrics`, for an image ID it can't parse or doesn't have yet, with `cluster` from the context. This settles 2a's gauge of skipped containers.
- **The spoke:**
  - A snapshot calls `Store.Observe` for each image: the cluster and its ID, the digest kind, the repositories, the counts, the platforms of its pods (at most 8), and the first 100 workloads, sorted, as in 2a.
  - It calls `Store.Forget` for each image that the snapshot no longer has.
  - At its first complete snapshot after a start, it forgets this cluster's presence entries that the snapshot lacks. Entries that went stale while the operator was down would otherwise stay (e2e spec 4).
  - An upsert observes, and a tombstone forgets.
  - `Forget` drops the presence that a deleted collector delivered, and forgets the images that no other collector's presence names.

- [ ] **Step 1: Write the failing tests.**
  - **The collector:**
    - a Deployment's image lists the Deployment with its UID and its pods
    - a namespace that the scope excludes drops out
    - a scan pod in the operator's namespace is skipped
    - a mirror pod is its own workload
    - an allowlisted namespace label is copied, and another label isn't
    - `conformance.Run` passes against envtest, with its presence check
  - **The spoke:**
    - a snapshot creates the presence entries, with their pods' platforms
    - a second snapshot without an image forgets it
    - after a restart, the first complete snapshot forgets this cluster's entries that it lacks
    - an empty snapshot reaches `Presence` through the `Router`
    - `Forget` keeps the images that another presence collector names
    - a stream that never ends its snapshot forgets nothing
- [ ] **Step 2: Run them and see them fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Verify** with `make test` and `make lint`.
- [ ] **Step 5: Commit**: `feat(workloads): report presence from a collector package`

### Task 14: The `scanner` collector, and the spoke's executor

**Files:**
- Create:
  - `collectors/scanner/` with `go.mod`, `Dockerfile` (from `Dockerfile.scanner`, with Syft), `cmd/scanner/main.go` (the subcommands `serve` and `scan`), `internal/result`, `internal/pull` and `internal/analyze` (moved from `internal/scan`), `internal/scan/operation.go`, `credentials.go` and `platforms.go` (from `internal/controller/scan`), and their tests
  - `sdk/jobs/`, from `internal/controller/scan`'s Job, Secret, slot and log code
  - `sdk/podtemplate/`
  - `internal/spoke/executor.go` and its test
- Delete: `internal/scan`, `cmd/scanner`, `Dockerfile.scanner`, `internal/controller/scan`, the operator's pod index, its cluster-wide rights on pods (Task 12's in its own namespace stay), its rights on nodes, pull secrets, Jobs and `pods/log`, the options and variables `VEXPLAIN_SCANNER_IMAGE` and `VEXPLAIN_SCAN_REGISTRY_MIRRORS`, and `internal/collector/registry.go`, the health registry, with its last reporter
- Modify:
  - `go.work` and the `Makefile`: the module joins `go.work` and the test and lint targets, as the SDK did in Task 2, and `docker-build` builds the scanner from `collectors/scanner/Dockerfile`
  - `hack/measure-2a` and its tests: its imports of `internal/scan` go, and with them its column of line lengths, because `result.Encode` moves into the scanner's module and the core reads no collector type
  - `internal/controller/hub/assessor.go`: the current collector version (below)

**Interfaces:**
- Consumes: Tasks 3, 7, 9, 11 and 13
- Produces:

```go
package podtemplate
type PodTemplate struct {
	ImagePullPolicy   corev1.PullPolicy            `json:"imagePullPolicy,omitempty"` // IfNotPresent by default
	Resources         *corev1.ResourceRequirements `json:"resources,omitempty"`
	NodeSelector      map[string]string            `json:"nodeSelector,omitempty"`
	Tolerations       []corev1.Toleration          `json:"tolerations,omitempty"`
	Affinity          *corev1.Affinity             `json:"affinity,omitempty"`
	PriorityClassName string                       `json:"priorityClassName,omitempty"`
	RuntimeClassName  *string                      `json:"runtimeClassName,omitempty"`
	Labels            map[string]string            `json:"labels,omitempty"`
	Annotations       map[string]string            `json:"annotations,omitempty"`
}
func Schema() []byte // a JSON Schema fragment for a collector's settings
func (t PodTemplate) Apply(meta *metav1.ObjectMeta, spec *corev1.PodSpec, container string)

package jobs
type Spec struct {
	Name, Namespace, Image, Container string
	Args                              []string
	Env                               []corev1.EnvVar
	DockerConfig                      []byte // nil: no credentials
	Workspace                         resource.Quantity
	Deadline                          time.Duration
	Template                          podtemplate.PodTemplate
	Labels                            map[string]string
	ResultPrefix, ErrorPrefix         string
}
type Result struct{ Line, FailureReason string }
type Runner struct{ /* … */ }
func NewRunner(c client.Client, logs LogReader, namespace string) *Runner
// Run creates the Job, then its Secret owned by the Job; waits for it; reads its one line; deletes it.
func (r *Runner) Run(ctx context.Context, s Spec) (Result, error)
func (r *Runner) Active(ctx context.Context, labels map[string]string) (int, error)

package spoke
type Executor struct{ /* implements tasks.Executor */ }
func NewExecutor(pool *collectorclient.Pool, c client.Client, presence *Presence, store evidence.Store, facts evidence.FactsWriter) *Executor
```

- **The collector:**
  - **Capabilities:** role `Spoke`, and the operation `scan`. It consumes nothing, and produces `ch.bedag.vexplain.scanner.image-contents.v1alpha1` with scope `Hub`.
  - **Parameters:** `{repositories: [string], pods: [{namespace, name}]}`.
  - **Settings, with their defaults:**
    - `maxConcurrentScans` 2, from 1 to 32
    - `scanTimeoutSeconds` 1800, from 60 to 21600
    - `workspaceMebibytes` 10240, from 1024 to 1048576
    - `registryMirrors`, as `[{host, url}]`
    - `scanPod`, a `PodTemplate` whose default memory request and limit are 2 GiB
  - **Permissions:** `get` on pods, nodes, Secrets and service accounts across the cluster. In its own namespace: Jobs (create, get, list, watch, delete), Secrets (create, get, delete), pods (get, list) and `pods/log` (get).
- **`Invoke(scan)`:**
  - It checks that a named pod's status runs the digest.
  - It builds the credentials from that pod, as 2a did, and takes the platforms from the pods' nodes.
  - It waits for a slot, then runs the Job with its own image and the `scan` subcommand, with 2a's arguments.
  - It checks the result line as 2a did. Then it emits one event per manifest, about `manifest/<digest>`, with `platform`, `coverage` (2a's completeness), the time the scan ended, and `data` from `result.EncodeManifest`.
  - Evidence that compresses above the cap fails as `TooLarge` before it is emitted.
  - Other failures carry 2a's reasons.
- **The executor:**
  - It queues one request per type and subject.
  - It finds the usable collectors (`collectorclient.Usable`) that have an operation producing the type.
  - It adds up to 16 pods that run the image, from `Presence`.
  - Then it invokes the collector. Events go to `evidence.Store.Put`, with the collector's name and its `status.version`, and then to `FactsWriter.Succeeded`. A failure, or `ErrTooLarge`, goes to `FactsWriter.Failed`: a `Failure` about one subject goes to the facts, and is never a health failure.
  - At most 16 invokes run at once per collector.
- **The current collector version** becomes the `Collector`'s `status.version`, which its `GetInfo` reports, in place of 2a's scanner image. The assessor reads it from the `Collector`, so the hub calls no collector for it, and asks again for evidence that the store holds at another version.

- [ ] **Step 1: Write the failing tests.**
  - **The collector:**
    - 2a's scanner tests move with their code
    - with a fake Job runner, `scan` gives one event per manifest, with `platform` and `coverage`
    - **Review Focus 4:** evidence above the cap gives `TooLarge`
    - a 401 gives `Unauthorized`
    - a third invoke waits while two Jobs run
    - 2a's tests that the Job keeps 0022's isolation move to `sdk/jobs`
    - `maxConcurrentScans: 0` is refused
    - `scanPod.imagePullPolicy: Always` reaches the Job
    - `conformance.Run` passes
  - **The executor** (envtest, with an in-process scanner):
    - a request stores the events, with the `Collector`'s `status.version`, and writes the facts
    - a failure adds an attempt, and leaves the `Collector`'s `Ready` as it was
    - a collector with `Ready` Unknown (`NoData`) is invoked, and one with `CollectorFailing` isn't
    - `ErrTooLarge` from the store gives `TooLarge`
- [ ] **Step 2: Run them and see them fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Verify** with `make test` and `make lint`.
- [ ] **Step 5: Commit**: `feat(scanner): scan images from a collector package`

### Task 15: The `matcher` collector

**Files:**
- Create: `collectors/matcher/` with `go.mod`, `Dockerfile` (from `Dockerfile.matcher`), `cmd/matcher/main.go`, `internal/grype/` (from `internal/matcher`), `internal/match/operation.go`, and their tests
- Modify:
  - `internal/controller/hub/findings.go`, where the collector implementation replaces the HTTP one, and which holds the hub's `collectorclient.Sink` for the `Hub` role
  - `internal/setup/setup.go`: `NewStreams` takes the hub's sink for the `Hub` role
  - `config/default/kustomization.yaml`: `../matcher` goes, with `config/matcher`
  - `go.work` and the `Makefile`: the module joins `go.work` and the test and lint targets, as the SDK did in Task 2, and `docker-build` builds the matcher from `collectors/matcher/Dockerfile`
  - `hack/measure-2a` and its tests: no import of `internal/matchapi` is left
- Delete: `internal/matcher`, `internal/matchapi`, `cmd/matcher`, `Dockerfile.matcher`, `config/matcher`, and `VEXPLAIN_MATCHER_URL`

- **The collector:**
  - **Capabilities:** role `Hub`. It watches, only to signal its database's changes. Its operation `match` consumes the scanner's type and produces the findings type, with scope `Hub`.
  - **Settings, with their defaults:**
    - `updateIntervalSeconds` 21600
    - `maxConcurrent` 2, from 1 to 8
    - `databaseUpdates`: `Online` or `Offline`
    - `seedDatabase`, an optional path to a database baked into the image, copied into `/db` at start
  - **The `/db` and `/tmp` volumes** come from its runtime config, which the install ships (Task 16).
- **`Invoke(match)`:**
  - It runs Grype on the input's SBOM, and maps the result as 2a did: severities, fix states, fixed versions, and KEV from Grype's own field.
  - It also carries the CVSS vectors.
  - It sets `Version` to the database's version.
  - It returns one findings event about `manifest/<digest>`, with the scanner event's `platform`: `evidence.Validate` refuses an event about a manifest without one (decision 4).
  - Without a database, it fails with the reason `NotReady`.
- **`Watch`** sends an empty snapshot, then `SourceChanged` with no subjects whenever the database's version changes.
- **The operator:**
  - `hub.Findings` invokes `match` on the playbook's findings collector.
  - `Changed` comes from the hub's sink, which serves the `Hub` role's streams: the findings collector's `SourceChanged`. Hub and spoke meet only through `tasks.Executor` and the stores (0021), so a hub-only deployment stays possible.

- [ ] **Step 1: Write the failing tests.**
  - **The collector:**
    - 2a's Grype tests move with their code
    - `match` maps a Grype fixture, with KEV and CVSS vectors carried
    - without a database it fails with `NotReady`
    - a new database version emits `SourceChanged`
    - `conformance.Run` passes, with a fake Grype and a `match` invocation whose `Inputs` hold a scanner event
  - **The operator** (envtest, with in-process `scanner` and `matcher` collectors):
    - an image goes from presence to evidence, findings and a sheet
    - `SourceChanged` matches every manifest again
- [ ] **Step 2: Run them and see them fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Verify** with `make test` and `make lint`.
- [ ] **Step 5: Commit**: `feat(matcher): match evidence from a collector package`

### Task 16: Install, images and e2e

**Files:**
- Create:
  - `config/collectors/` with `kustomization.yaml`, `workloads.yaml`, `scanner.yaml`, `matcher.yaml`, `runtimeconfigs.yaml` (`matcher`, with its volumes and memory), `rbac/` (a ClusterRole, and Role where needed, per collector, bound to `vexplain-collector-<name>`), and `kustomizeconfig.yaml` (images in `Collector.spec.package`)
  - `config/network-policy/collectors.yaml`: only the manager may reach collector pods on 9443. Port 8081 stays open for probes and metrics.
- Modify:
  - `config/default/kustomization.yaml`: the collectors, rules and playbooks, and `../network-policy` enabled, which spec 16 needs
  - `config/manager/manager.yaml`: the namespace enforces Pod Security `restricted`, and the variables of the scanner and the matcher go
  - `Makefile`: `docker-build` builds the operator and every collector's image; `set-images` sets the `Collector` packages; the e2e setup loads them into kind
  - `Dockerfile`: builds through `go.work`
  - `test/e2e/config/kustomization.yaml`: the matcher's settings `Offline` with `seedDatabase`, and the scanner's `registryMirrors`
  - `test/e2e/e2e_test.go`, `e2e_suite_test.go`
  - `.github/workflows/test-e2e.yml`

**The e2e specs:**
1. The manager's pod runs.
2. Every built-in `Collector` is `Ready`, with its capabilities, and its Deployment runs.
3. The Secret cache synced (as before).
4. An `ImageInventory` that went stale before the start is deleted (as before).
5. A Deployment's image appears in its `ImageInventory`, through the `workloads` collector.
6. It goes when the Deployment is deleted.
7. A `ModelUnavailable` event is recorded (as before).
8. The metrics endpoint serves `vexplain_images_running` (as before).
9. In `installed-not-linked`, the libxml2 finding is `UnderInvestigation` with the `load-check` note "nothing in the image reaches or names its libraries".
10. In `linked`, the same finding's note is `reached by /usr/bin/xmlcatalog` or `xmllint`.
11. In both images, brotli-libs' `CVE-2026-111497` is held open by `known-exploited`: `UnderInvestigation`, reason `known exploited` (0035).
12. The facts show one linux platform, the pushed manifest, evidence from `scanner` with its coverage, and no failure.
13. Each sheet names `container-cves` and the evidence it rested on.
14. No scan Jobs or their Secrets are left.
15. Scan pods are never inventoried.
16. The manager can reach the collectors on 9443, and another pod can't.
17. Neither the manager nor any collector restarted.
18. The namespace enforces Pod Security `restricted`, and every collector pod was admitted.
19. A copy of `workloads` installed as `extra` gets a Deployment. Deleting it removes its Deployment, Service, service account and TLS Secret, through their owner references. The images it reported stay present, because `workloads` still names them: `Forget` drops only what `extra` delivered.

- [ ] **Step 1: Write the specs.**
- [ ] **Step 2: Run them and see the new ones fail** before the install changes.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Verify** with `make test-e2e`, all 19 specs.
- [ ] **Step 5: Commit**: `feat(deploy): install the built-in collectors, rules and playbook`

### Task 17: The measurement again

Task 9 moved the tool to `engine.Evaluate` and the new sheet, and Tasks 13 to 15 kept it compiling. This task takes the exit check, the run and the doc.

**Files:**
- Modify: `hack/measure-2a/main.go` (the exit check) and its tests, `docs/measurements/2026-phase2a.md`

- **The exit check** treats `Fixed` as it treats `NotAffected`: the tool exits with 1 when an answer is `NotAffected` or `Fixed` and the known answer is anything else, in either column.
- **`cases.yaml`** has the statuses' names since Task 9. `approved` stays `false` until the owner approves the answers.
- **The doc** gains the section "Run again in phase 2b". It has the two columns, totals by status and by note, and the evidence's size against the cap and the 512 KiB trigger. It says plainly what changed: the load check's answers are now status notes, and the statuses carry OpenVEX's names.

- [ ] **Step 1: Write the failing test:** a case answered `Fixed` whose known answer is anything else exits with 1, as one answered `NotAffected` does. See it fail.
- [ ] **Step 2: Adapt the exit check.**
- [ ] **Step 3: Run it on kind:** `KUBECONFIG=bin/kind-e2e.kubeconfig go run ./hack/measure-2a --cases hack/measure-2a/cases.yaml --registry localhost:5001`. Expected: 15 of 15 as expected, in both columns, and exit 0.
- [ ] **Step 4: Write the doc's section.**
- [ ] **Step 5: Commit**: `docs(measurement): run the measurement again through packages and playbooks`

### Task 18: The `exposure` collector

**Files:**
- Create: `collectors/exposure/` with `go.mod`, `Dockerfile`, `cmd/exposure/main.go`, `internal/exposure/watcher.go`, `external.go`, `reach.go` and `cilium.go`, and their tests (envtest, with the Gateway API's CRDs installed for its cases)
- Create: `config/collectors/exposure.yaml` and its RBAC
- Modify: `go.work`, `Makefile`

**Interfaces:**
- Consumes: Tasks 2, 3 and 13's `sdk/workloads`
- **Capabilities:** role `Spoke`; it watches; it produces the exposure type, with scope `Spoke`.
- **Settings, all empty by default, which counts everything as external (0006):**
  - `ingressClasses`: the classes whose Ingresses count as external
  - `gateways`: `[{namespace, name}]`, the Gateways whose routes count
  - `internalLoadBalancerAnnotations`: `[{key, value}]`; a LoadBalancer Service with one of them isn't external
  - `nodePorts`: `External` (the default) or `Internal`
- **Permissions:** list and watch, across the cluster, of:
  - pods, namespaces, Services and EndpointSlices
  - Ingresses and IngressClasses
  - NetworkPolicies
  - Gateways and HTTP, TLS and gRPC routes, when they exist
  - Cilium's two policy kinds, when they exist
  - the metadata of ReplicaSets and Jobs

**Behaviour:**
- **Discovery:** at start, and every 5 minutes, the collector checks API discovery for the Gateway API and Cilium, and starts or stops those watches. Finding which APIs exist is the collector's own business (0029).
- **External exposure:** a workload is exposed when its pods back one of these:
  - a Service of type LoadBalancer that isn't internal
  - a NodePort Service, unless `nodePorts` is `Internal`
  - a Service that a counted Ingress routes to
  - a Service that a route attached to a counted Gateway routes to

  `via` names the objects, at most 8.
- **Internal reach,** from the ingress policies that select the workload's pods:
  - `Namespace` when every allowed peer is in its own namespace
  - `Peers` for specific pods elsewhere
  - `Namespaces` for whole namespaces
  - `Cluster` when anything is allowed, or when no policy selects it

  A Cilium rule outside the supported subset, which is endpoint selectors and the `world` and `cluster` entities, counts as `Cluster`. That errs towards urgency.
- **Indirect exposure** (decision 18): another, externally exposed workload can reach this one. That means this workload's ingress allows the other's pods, and the other's egress policies, if any, allow this one. It covers one hop only.
- **Events:** one per workload in scope, about `workload/…`, with the scope and task label from the context. A snapshot comes first, then changes.

- [ ] **Step 1: Write the failing tests.**
  - **External exposure:**
    - a LoadBalancer Service makes its workload external, via that Service
    - the internal annotation doesn't
    - a NodePort Service with `nodePorts: Internal` doesn't
    - an Ingress of a counted class does, and one of another class doesn't
    - an HTTPRoute on a counted Gateway does
  - **Internal reach:**
    - no policy gives `Cluster`
    - a policy for its own namespace only gives `Namespace`
    - one peer in another namespace gives `Peers`
    - two namespaces give `Namespaces`
  - **Indirect exposure:**
    - a backend that an exposed frontend reaches is indirect
    - the backend's ingress policy blocking the frontend makes it not indirect
  - The Gateway API's CRDs installed after start are picked up within the discovery interval, which the test shortens.
  - `conformance.Run` passes.
- [ ] **Step 2: Run them and see them fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Verify** with `make test` and `make lint`.
- [ ] **Step 5: Commit**: `feat(exposure): report exposure from a collector package`

### Task 19: Exposure on the spoke

**Files:**
- Create: `internal/spoke/exposure.go` and its test
- Modify:
  - `api/inventory/v1alpha1/imageinventory_types.go`: `ClusterPresence` gains `exposure`
  - `internal/inventory/store.go`: `Observation` gains `Exposure`
  - `internal/spoke/presence.go`, `internal/setup/setup.go`
  - `internal/spoke/router.go`: it hands the exposure type to `Exposure`

**Interfaces:**
- Produces:

```go
package spoke
// Exposure implements collectorclient.Sink for the exposure type, and keeps each workload's
// exposure in memory. Forget drops what a deleted collector delivered.
type Exposure struct{ /* … */ }
func NewExposure() *Exposure
func (e *Exposure) Of(w evidence.PresenceWorkload) configv1alpha1.SSVCExposure // Unknown when no evidence
// ForImage gives the highest exposure of the workloads that run the image:
// Open, then Unknown, then Controlled, then Small.
func (e *Exposure) ForImage(workloads []evidence.PresenceWorkload) configv1alpha1.SSVCExposure
```

- **0024's mapping:**
  - external gives `Open`
  - indirect, or `Peers`, `Namespaces` or `Cluster`, gives `Controlled`
  - `Namespace` gives `Small`
  - no evidence gives `Unknown`
- **`Unknown` ranks above `Controlled`,** because it may be open.
- **The presence entry carries `ForImage`.** It is written only when it changes, as 0019 asks of presence entries.

- [ ] **Step 1: Write the failing tests.**
  - A table of the mapping.
  - An image run by an `Open` and a `Small` workload is `Open`.
  - `Unknown` and `Controlled` give `Unknown`.
  - A change of exposure rewrites the presence entry. The same exposure again writes nothing.
- [ ] **Step 2: Run them and see them fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Verify** with `make test` and `make lint`.
- [ ] **Step 5: Commit**: `feat(spoke): keep exposure per workload, and summarise it per image`

### Task 20: SSVC urgency

**Files:**
- Create: `internal/urgency/urgency.go`, `table.go` and `urgency_test.go`

**Interfaces:**
- Consumes: Tasks 5, 6 and 9 (each sheet finding's `knownExploited` and CVSS vectors)
- Produces:

```go
package urgency
type Inputs struct {
	Exploitation configv1alpha1.SSVCExploitation
	Exposure     configv1alpha1.SSVCExposure
	Automatable  configv1alpha1.SSVCAutomatable
	HumanImpact  configv1alpha1.SSVCHumanImpact
}
func FromFinding(f inventoryv1alpha1.Finding, exposure configv1alpha1.SSVCExposure) Inputs // decision 19
func Decide(in Inputs, overrides []configv1alpha1.UrgencyOverride) configv1alpha1.SSVCOutcome
func NextStep(f inventoryv1alpha1.Finding) triagev1alpha1.NextStep // decision 20
```

- **`table.go`** embeds SSVC's published deployer decision table, from CERT/CC's SSVC repository, row for row, with its version and source in a comment. `Exposure` `Unknown` is decided as `Open`.
- **An override** replaces the row with the same four inputs (0024: an admin can adjust the table).

- [ ] **Step 1: Write the failing tests.**
  - **`Decide`:**
    - `(None, Small, No, Low)` gives `Defer`
    - `(Active, Open, Yes, VeryHigh)` gives `Immediate`
    - a test compares every row with the published table's file
    - an override changes one row and nothing else
  - **`FromFinding`:**
    - KEV gives `Active`
    - `AV:N/AC:L/PR:N/UI:N` gives `Yes`
    - `AV:L` gives `No`
    - no vector gives `Yes` and `High`
    - `C:H/I:H/A:H` gives `High`, and anything less gives `Medium`
  - **`NextStep`:**
    - a fixed version gives `Update`
    - `Affected` without one gives `Mitigate`
    - `UnderInvestigation` without one gives `Investigate`
- [ ] **Step 2: Run them and see them fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Verify** with `make test` and `make lint`.
- [ ] **Step 5: Commit**: `feat(urgency): decide urgency with SSVC's deployer tree`

### Task 21: Workload reports

**Files:**
- Create: `internal/spoke/reports.go`, `render.go`, and their tests (envtest)
- Modify: `internal/setup/setup.go`, and the RBAC markers for `WorkloadReport`s and their status in every namespace

**Interfaces:**
- Consumes: Tasks 6, 9, 13, 19 and 20
- Produces:

```go
package spoke
// Render builds one workload's report from its sheets, exposure and owner values. It is pure.
func Render(w evidence.PresenceWorkload, sheets map[string]*inventoryv1alpha1.ImageVerdicts, facts map[string]*inventoryv1alpha1.ImageFacts, exposure configv1alpha1.SSVCExposure, cfg settings.Effective) triagev1alpha1.WorkloadReportStatus
```

- **One `WorkloadReport` per workload in presence,** in its namespace:
  - named `<kind in lower case>-<name>`, or a hash when that is longer than 253 characters
  - owned by the workload, through its UID (decision 21)
  - labelled `digest.vexplain.bedag.ch/<first 63 hex digits>` for each image it runs
- **Its images:** the manifest of each platform its pods run on, from the facts, with a state:
  - `Pending`: no sheet yet, or one without `counts` or `findingsVersion`
  - `Incomplete`: `omittedFindings` is above the counts of `NotAffected` and `Fixed` findings
  - otherwise `Ready`
- **Each image's coverage:** each evidence's coverage by source, `{source, type, coverage}`, from the facts. The core shows coverage and never interprets it (spec 5.5), and 0025 asks reports to show the completeness. So an image with low completeness and no findings is `Ready`, with its coverage, while the completeness guard still holds every finding below 90%. That settles 2a's open item on low completeness.
- **Its findings:**
  - only the `Affected` and `UnderInvestigation` findings of its sheets, each once per vulnerability and package
  - urgency from `urgency.Decide`, with the workload's exposure
  - the next step, the first fixed version, the review state (`RuleSettled` for a rule's `Affected`, otherwise `Open`), the reason, the status notes, which carry the load check's text, and the severity
  - ordered by urgency, `Immediate` first, then by severity and ID
  - at most 1000, and fewer when the status would pass 1 MiB: findings are cut by bytes in that order, as `rules.Sheet` does; `omitted` counts the rest
- **Also:**
  - `counts` covers every status
  - `owner` comes from presence's allowlisted values
  - `exposure` is the workload's
- **Text** from image content is made printable and bounded again here, with `internal/text` (2a's open item on untrusted text). The kind's docs say it is data.
- **Writes:** a report is written only when its status changes. A report whose workload left presence is deleted.

- [ ] **Step 1: Write the failing tests.**
  - **A workload with a sheet:**
    - it gets a report with its findings, urgency and next steps
    - its owner reference points to the workload's UID
    - its digest label is set
  - **Image states:**
    - a sheet without `counts` gives `Pending`
    - `omittedFindings` above the settled counts gives `Incomplete`
    - an image whose evidence has coverage 80 and no findings is `Ready`, and shows coverage 80 from `scanner`
  - **Review Focus 5:** a reason with control characters arrives printable.
  - A finding's `load-check` note arrives in its `statusNotes`.
  - 1001 findings give 1000, with `omitted` 1.
  - 1000 findings at the string limits are cut to keep the status under 1 MiB, and `omitted` counts the rest.
  - A workload that leaves presence loses its report.
- [ ] **Step 2: Run them and see them fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Verify** with `make test` and `make lint`.
- [ ] **Step 5: Commit**: `feat(spoke): render a WorkloadReport for each workload`

### Task 22: Metrics

**Files:**
- Create: `internal/spoke/metrics.go` and its test
- Modify: `internal/metrics/metrics.go`, `internal/spoke/reports.go`

**The series (design 6.10, 0009, 0020),** each with `cluster`:
- `vexplain_findings{namespace, verdict, urgency, review_state}`: a gauge of counts from the reports, with the status as `verdict`. A settled finding has `verdict="NotAffected"` or `verdict="Fixed"`, and `urgency="None"`.
- `vexplain_open_case{namespace, workload, digest, cve, verdict, urgency}` = 1, one for each finding a report lists.
- `vexplain_namespace_owner_info{namespace, label_<key>…, annotation_<key>…}` = 1, one per namespace, with the keys sanitised as kube-state-metrics does.
- `vexplain_funnel{stage}`, for the stages `Flagged`, `Settled`, `Affected` and `UnderInvestigation`, spelt as the API spells them, like `verdict`.
- `vexplain_collector_ready{collector}`: 1 or 0, from the `Ready` condition.

- [ ] **Step 1: Write the failing tests.**
  - Series appear with a report, and go with it.
  - A label value with a quote or a newline is sanitised.
  - The owner info has one series per namespace, with sanitised keys.
  - `collector_ready` follows the condition.
- [ ] **Step 2: Run them and see them fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Verify** with `make test` and `make lint`.
- [ ] **Step 5: Commit**: `feat(metrics): count findings and open cases, with owner info`

### Task 23: E2E for exposure, urgency and reports

**Files:**
- Modify: `test/e2e/e2e_test.go`, and the Makefile's e2e image loading

**The new specs:**

20. The `exposure` `Collector` is `Ready`.
21. A Deployment behind a NodePort Service is `Open` in its `WorkloadReport`. kind has no load balancer.
22. A Deployment whose NetworkPolicy allows only its namespace is `Small`.
23. A backend that an exposed frontend reaches is `Controlled`.
24. The `linked` image's report lists brotli's `CVE-2026-111497` as `UnderInvestigation`, held by `known-exploited`, with the urgency that the table gives for active exploitation and its exposure. It lists the libxml2 finding as `UnderInvestigation`, with `Investigate`.
25. `kubectl get workloadreports -A -l digest.vexplain.bedag.ch/<hex>` lists that report.
26. With `ownerAttribution.namespaceLabels: [team]`, the report and `vexplain_namespace_owner_info` carry `team`.
27. `vexplain_open_case` has a series for that CVE in that workload.
28. Deleting the Deployment deletes its report.

- [ ] **Step 1: Write the specs.**
- [ ] **Step 2: Run them and see them fail** where the behaviour is missing.
- [ ] **Step 3: Fix what they find.**
- [ ] **Step 4: Verify** with `make test-e2e`, all 28 specs.
- [ ] **Step 5: Commit**: `test(e2e): cover exposure, urgency and reports`

---

## As built

Written when the plan has been carried out.

## Carried forward

Written when the plan has been carried out. Phase 2a's items that this plan doesn't close move here then, each under the module that now holds its code.
