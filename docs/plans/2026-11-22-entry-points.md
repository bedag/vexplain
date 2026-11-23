# vexplain — Entry points and exposure rules on the hub, Implementation Plan

> **For agents:** follow `AGENTS.md`. Implement this plan task by task, test first. A task is done when its tests pass, it is committed and it has been reviewed; only then start the next one. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** a case's exposure, and so its urgency, follows whether the internet reaches the workloads that run its image:
- `network-reach` reports each workload's entry points;
- presence and exposure reach the hub's store, and stay current there;
- the hub asks each source about the entry points;
- exposure rules in `container-cves` decide each workload's exposure when the hub computes a case.

**Architecture:**
- **The SDK:** host and address subjects, entry points in exposure, each workload's subject in presence, the sources' parameters, and `maxAge` on a produced type.
- **The store (0058):** it writes a record in place when its event differs, keys a streamed record with its cluster, and its watch sees updates. A sink on the spoke stores the streamed events of `Hub`-scoped types.
- **The collectors:** `workloads` names each workload's subject. `network-reach` builds the entry points from Nodes, statuses, hosts and ports that it drops today. Both declare `Hub`.
- **The rules (0059):** a `Rule` may conclude `outcome.exposure`. The engine evaluates the exposure rules for each workload, and the assessor runs only the finding rules.
- **The hub:** `internal/exposure` keeps a view of presence, exposure and the answers, asks the sources, and decides each case's exposure for the investigations. The agent workers take a case's exposure from its `Assessment`.

**Tech Stack:** as in phase 4: Go 1.26, kubebuilder, controller-runtime, cel-go, CloudEvents, buf. No new dependency: `net/netip` handles addresses.

**Spec:**
- `docs/design/2026-11-20-entry-points.md`, accepted on 2026-11-22, with decision records 0058 and 0059;
- 0045 (`maxAge`), which this plan builds;
- phase 4's plans and their "As built" sections, which describe what exists.

**Branch:** `feat/entry-points`, from phase 4's head (`feat/phase4-agent`, `f3998d3`), with the design's commit (`2ebf0bb`) and this plan's commit picked onto it. It is merged into `feat/phase4-agent` once done (owner, 2026-11-22), and never pushed on its own.

**Not in this plan:**
- the clusters' reports taking the hub's exposure (design 5.9 and section 9);
- presence without pods, one type that every source shares, evidence about workloads that the hub asks for (design section 9);
- the organization's source's rules and `maxAge`, which live with that source;
- metrics of exposure by workload;
- the live check, which the main session runs with the owner.

## Decisions made in this plan

The design leaves these to the builder, or the code showed them while planning. Those that change a statement of the design are noted in its change log, under "While planning".

1. **"Equal" includes the collector's version.** The store writes nothing for an event with the same data, the same kept attributes and the same collector version. A new version with the same data rewrites the record's version only. The assessor asks again while a record's version differs from its Collector's (`whyFrom` in `assessor.go`), so it would otherwise ask forever.
2. **A streamed record keeps the naming of asked evidence.** `Key` gains `Cluster`, and an object's name hashes it only when it is set, so no stored record is renamed.
3. **The spoke stores streamed evidence through a sink of its own,** teed with the `Router` (`collectorclient.Tee`).
   - It queues its writes and retries them with back-off, so a slow store never holds up the streams. The Sink's calls carry no context and return no error (`streams.go:66-89`).
   - It tells a `Hub`-scoped type from the Collector's status, and keeps the last scopes it saw when the Collector can't be read.
4. **A presence without workloads deletes its record,** as the spoke's `Presence` reads it (`presence.go:249-262`).
5. **The answers don't store a source version** (design 5.5 said they would: a call changed).
   - The asker asks every entry point again after a start, and at once when a source's version changes.
   - With 5,000 entry points that is 79 calls, and an equal answer writes nothing.
6. **The Collector's status records what the hub needs:**
   - each operation's `role`, and its `parameters`: the names of its parameter schema's top-level properties;
   - each produced type's `maxAgeSeconds`.

   The hub knows a source by an operation in the hub role, without `consumes`, whose parameters include `hosts` or `addresses`. Today the status drops an operation's role and schema (`collector_answers.go:314-317`).
7. **`maxAge` is `maxAgeSeconds`,** from 60 seconds to 30 days.
   - The admin overrides it with the Collector's `spec.produces[]{type, maxAgeSeconds}`.
   - An override for a type that the collector doesn't produce sets `Ready` false, with the reason `ProducesInvalid`, as `TriggersInvalid` does for triggers.
   - Evidence past its `maxAge` is missing for every rule, and the assessor asks for it again.
8. **`holdAgainst` loses its default in the API.** The engine already applies `Rules` when the field is absent (`engine.go:176`), and the API's default would otherwise land on every exposure rule.
9. **Exposure rules never run in the assessor.**
   - The playbook check splits the pipeline by each rule's outcome.
   - Evidence that only exposure rules read is neither on the verdict sheets nor asked about for a manifest.
   - Editing an exposure rule doesn't re-evaluate the sheets.
   - A step whose rule is missing or not Ready keeps the playbook from being Ready, as today.
10. **The hub's view is in memory,** fed by the store's watch: presence by digest and cluster, exposure by workload, and the answers by subject. Evidence reads bypass the cache, so without the view the cases would read the API server for every workload of every case at each reconcile.
11. **The workers take a case's exposure from its `Assessment`.** The manager writes `status.queue.runsIn` when it queues a case, and the worker's case file uses it. The workers need no new permission, and no view of their own.
12. **A case counts its workloads per cluster entry of ImageInventory, as today.**
    - Presence names those workloads, and each named one gets the rules' exposure. The rest of the entry's count is Unknown.
    - The platform filter stays per cluster entry, as today's `runsOn`.
    - A workload named under two reported digests counts once in the exposure groups.
13. **A host port names the workload's own object,** as `via` does today, so that its record doesn't change at every rollout (design 5.1 said the pod).
14. **At most 256 addresses per entry point** (design 5.1 said 64). With 64, a node port would stay unchecked in every cluster of more than 32 nodes with two addresses each.
15. **Presence's `subject` is required, and `via` goes** (owner: the API is alpha, so older collectors need not pass). Events of a collector older than the manager are dropped as off-schema until it rolls; the hand-over says what to deploy together.
16. **Each investigation result names its case's highest exposure** (`status.results[].exposure`), so that the SOC and the e2e suite see it.
17. **A renamed cluster leaves its old streamed records.** The docs show how to delete them by label.

## Decisions for the owner

The owner approved the plan on 2026-11-22, with these answers:
1. **The branch:** `feat/entry-points` from phase 4's head, as recommended, merged into `feat/phase4-agent` once done.
2. **The live check:** the main session runs it with the owner, after this build's hand-over (Task 16). The hand-over says what must be done before it.
3. **Presence's `subject`:** required, with no care for older collectors, since the API is alpha (decision 15).
4. **Execution:** subagent-driven.

## Global Constraints

- **AGENTS.md binds:**
  - design first, test first, kind only;
  - no private data and no figures from real platforms;
  - no AI attribution;
  - comments that state their own reason and never cite a ruling kept outside the repository.
- **Phase 4 still binds,** as amended by its "As built" sections:
  - API conventions and kube-api-linter;
  - RBAC from markers;
  - the two binaries apart, with the workers' wiring in `internal/agent/worker/setup`;
  - tests and commits.
- **Before each commit:** `make manifests generate && make proto-check && make lint && make test`.
- **e2e:** one `make test-e2e`, on kind, at the end of each task that changes a CRD, the install, a collector or the hub. Its kubeconfig is `bin/kind-e2e.kubeconfig`.
- **No real model calls:** the scripted model only.
- **No internet in unit tests.**
- **The API is `v1alpha1` and unreleased:** fields change without conversion.
- **Names:**
  - subjects `host/<name>`, `address/<ip>` and `address/<ip>:<port>`;
  - exposure's `external.entryPoints[]{addresses, port, protocol, objectRef, parentRef, subjects}` and `external.unchecked`, with `HostNetwork`, `NoAddress`, `NotASubject`, `TooManyAddresses` and `TooManyEntryPoints`;
  - presence's `workloads[].subject`;
  - the sources' parameters `hosts` and `addresses`, and the reasons `InvalidInput` and `NotReady`;
  - `Rule`'s `spec.outcome.exposure` (`Open`, `Controlled`, `Small`), and its column `Exposure`;
  - the shipped rules `exposed-outside-cluster`, `reachable-in-cluster` and `own-namespace-only`;
  - for tests and examples: the source type `ch.example.dmz.publication.v1alpha1`, whose data has `publishedTo` (`Internet`, `Internal`, `None`), the input `dmz`, and the rules `published-or-unchecked` and `exposed-not-published`;
  - the Collector's `spec.produces[]{type, maxAgeSeconds}`, `status.capabilities.produces[].maxAgeSeconds`, `status.capabilities.operations[].role` and `.parameters`, and the reason `ProducesInvalid`;
  - the Evidence's `spec.cluster` and its label `vexplain.bedag.ch/cluster`;
  - the case file's `runsIn.exposure[]{exposure, rules, missing, workloads, first}`;
  - the Assessment's `status.queue.runsIn{highestExposure, highestUrgency, urgentWorkloads, exposure[]}`;
  - the investigation result's `exposure`;
  - the package `internal/exposure`.
- **Values:**
  - entry points: at most 32 per workload, 256 addresses each, and 8 `unchecked` reasons;
  - an Ingress's host is on 443 when an entry of its `tls` names it, a matching wildcard included, and on 80 otherwise. Its status addresses have no port;
  - a listener's protocol: `HTTP`, `HTTPS`, `TLS` and `TCP` give `TCP`; `UDP` gives `UDP`;
  - asking a source:
    - 1 to 64 points per call, and a refused call is split in halves;
    - after a failure, ask again after a minute, doubling up to 15 minutes;
    - an answer is refreshed at half its `maxAge`;
  - `maxAgeSeconds`: 60 to 2,592,000;
  - an exposure rule may take 1 s per workload, and all the workloads of one case together 30 s;
  - the case file: at most 16 exposure groups, with the first 5 workloads each;
  - the order of exposure: Open, Unknown, Controlled, Small.
- **Commits:** Conventional Commits, no AI attribution, never on `main`, never pushed. Stage paths by name.
- **Repository hygiene:**
  - neutral names, such as `cluster-a`, `team-a` and `app.example`;
  - addresses from the documentation ranges: `192.0.2.0/24`, `198.51.100.0/24` and `2001:db8::/32`;
  - never the name of a company or of its proxies.

## Review Focus

1. **A cluster whose presence hasn't reached the hub, such as right after an upgrade:** its workloads count as Unknown, from ImageInventory's count. The case is never "not running" (Task 13).
2. **An exposed workload whose source answered only some entry points, or whose answer is past its `maxAge`:** it is Unknown, never Controlled (Tasks 10 and 13).
3. **A spoke restart that sends every event again:** the store writes nothing, and no case's exposure changes (Tasks 4 and 5).
4. **A source that refuses one point of a call:** the other points still get their answers, and the refused one stays unanswered (Task 12).
5. **A node that joins or leaves:** the node ports' entry points change, and the hub asks about the new addresses (Tasks 8 and 12).

---

## File Structure

```text
sdk/subject/                                        # Task 1
sdk/evidence/{types.go,evidence.go,schemas/}        # Tasks 2, 8
sdk/collector/{identity.go,entrypoints.go}          # Tasks 2, 3
sdk/proto/vexplain/collector/v1alpha1/, sdk/api/    # Task 3
sdk/conformance/                                    # Task 3
api/config/v1alpha1/{collector_types.go,rule_types.go,common_types.go}       # Tasks 3, 9
api/inventory/v1alpha1/evidence_types.go            # Task 4
api/triage/v1alpha1/{assessment_types.go,investigation_types.go}             # Task 13
internal/controller/config/{collector_answers.go,collector_controller.go}   # Task 3
internal/collectorclient/{pool.go,streams.go}       # Tasks 3, 5
internal/evidence/                                  # Task 4
internal/spoke/store_sink.go                        # Task 5
collectors/workloads/internal/presence/             # Task 6
collectors/network-reach/internal/exposure/         # Tasks 7, 8
internal/rules/engine/{env.go,engine.go,exposure.go}  # Task 10
internal/controller/hub/{playbook_controller.go,assessor.go,rule_controller.go}  # Tasks 3, 11
config/rules/, config/playbooks/, config/samples/   # Task 11
internal/exposure/{view.go,asker.go,cases.go,metrics.go}                     # Tasks 12, 13
internal/controller/hub/{investigation.go,queue.go} # Task 13
internal/agent/{cases,casefile}/, internal/agent/worker/claim.go, internal/agent/prompt/guidance.md  # Task 13
cmd/agent-replay/                                   # Task 13
internal/setup/setup.go                             # Tasks 5, 12, 13
test/e2e/, test/e2e/images/dmz-stand-in/            # Tasks 6, 8, 14
README.md, docs/collectors.md, docs/agent.md        # each task, for what it changes
```

## Task order

`make test` stays green after every task, and the e2e suite after each task that runs it.
- **Tasks 1 to 3:** the SDK and the Collector's status. Each stands alone.
- **Tasks 4 and 5:** the store, then the spoke's sink.
- **Task 6:** presence goes to the hub.
- **Tasks 7 and 8:** `network-reach`'s caches, then its entry points; exposure goes to the hub.
- **Tasks 9 to 11:** the `Rule`'s API, the engine, then the split pipeline with the shipped rules.
- **Task 12:** the hub's view and the asker.
- **Task 13:** the cases, the `Assessment` and the case file.
- **Task 14:** end to end, with a stand-in source.
- **Task 15:** the docs and "As built".
- **Task 16:** the hand-over to the main session, which runs the live check with the owner.

---

### Task 0: The record

- [ ] **Commit this plan** on `docs/entry-points`: `docs: plan the entry points and exposure rules`.
- [ ] **Create `feat/entry-points`** from phase 4's head, and pick the design's commit and this plan's commit onto it.
- [ ] **Run** `make test` on it. Expected: PASS, as phase 4 left it.

### Task 1: Host and address subjects (design 5.2)

**Files:**
- `sdk/subject/{subject.go,subject_test.go}`;
- `docs/collectors.md` (the table of subjects).

**Interfaces:**
- Produces:
  - `subject.KindHost = "host"` and `subject.KindAddress = "address"`;
  - `func Host(name string) (string, error)`: `host/<name>` in normal form;
  - `func Address(addr string, port uint16) (string, error)`: `address/<ip>`, or `address/<ip>:<port>`; port 0 means none;
  - `Subject` gains `Host string`, `Addr netip.Addr` and `Port uint16`.

- [ ] **Write the failing tests** (`subject_test.go`):
  - **`TestHostIsNormalized`**, a table:
    - `Shop.App.Example.` gives `host/shop.app.example`;
    - `*.app.example` gives `host/*.app.example`;
    - each of these is refused with an error: `localhost`, `*.example`, `shop_app.example`, `-shop.app.example`, `shop..app.example`, `shop.*.example`, a label of 64 characters, 254 characters in all, and the empty string.
  - **`TestAddressIsNormalized`**, a table:
    - `::ffff:192.0.2.10` with port 0 gives `address/192.0.2.10`;
    - `2001:DB8::1` with port 443 gives `address/[2001:db8::1]:443`;
    - `192.0.2.10` with port 30443 gives `address/192.0.2.10:30443`;
    - refused: `fe80::1%eth0`, `192.0.2.256`, `shop.app.example`, and the empty string.
  - **`TestRoundTrip`** gains a host and two addresses, and `Parse` gives back `Host`, `Addr` and `Port`.
  - **`TestParseRefusesAHostOrAnAddressOutOfNormalForm`:** `host/Shop.app.example`, `host/shop.app.example.`, `host/localhost`, `address/::ffff:192.0.2.10`, `address/2001:db8::1:443`, `address/192.0.2.10:0`.
  - **`TestParseErrorsDoNotRepeatTheSubject`** gains both kinds.
- [ ] **Run** `cd sdk && go test ./subject/`. Expected: FAIL.
- [ ] **Implement** with `net/netip`:
  - a host is lower-cased and loses one trailing dot, and a leading `*.` is kept;
  - each label has only letters, digits and hyphens, no hyphen at either end, and at most 63 characters;
  - there are at least two labels after the wildcard, and at most 253 characters in all;
  - an address is unmapped, and has no zone;
  - `Parse` accepts only the normal form, so that subjects compare by their text.
- [ ] **Run the tests again.** Expected: PASS. Then run `make test`. `evidence.Validate`, the SDK's server and the streams parse subjects, but nothing sends these kinds yet.
- [ ] **Docs:** the table of subjects in `docs/collectors.md` gains both kinds, which repeat across clusters on purpose.
- [ ] **Gate, then commit:** `feat(sdk): host and address subjects in normal form`.

### Task 2: Entry points, the workload's subject, and the sources' parameters in the SDK (design 5.1, 5.3, 5.5)

**Files:**
- `sdk/evidence/{types.go,types_test.go,evidence_test.go}`;
- `sdk/evidence/schemas/ch.bedag.vexplain.exposure.v1alpha1.json`, `sdk/evidence/schemas/ch.bedag.vexplain.presence.v1alpha1.json`;
- `sdk/collector/{entrypoints.go,entrypoints_test.go}` (new);
- `docs/collectors.md` (exposure, presence, the sources' contract).

**Interfaces:**
- Consumes: `subject.Host` and `subject.Address` (Task 1).
- Produces:
  - `evidence.EntryPoint{Addresses []string "addresses"; Port *int32 "port,omitempty"; Protocol string "protocol,omitempty"; ObjectRef ObjectRef "objectRef"; ParentRef *ObjectRef "parentRef,omitempty"; Subjects []string "subjects"}`;
  - `ExternalExposure` gains `EntryPoints []EntryPoint "entryPoints,omitempty"` and `Unchecked []string "unchecked,omitempty"`. `Via` stays until Task 8, so that `network-reach` still builds;
  - the constants:
    - `UncheckedHostNetwork`, `UncheckedNoAddress`, `UncheckedNotASubject`, `UncheckedTooManyAddresses`, `UncheckedTooManyEntryPoints`;
    - `MaxEntryPoints = 32`, `MaxEntryPointAddresses = 256`, `MaxUnchecked = 8`;
  - `func EntryPointSubjects(addresses []string, port int32) (kept, subjects []string, refused int)`. An IP gives an address subject with the port, and a name gives a host subject without one. What neither accepts is refused, and left out of `kept`;
  - `PresenceWorkload.Subject string "subject,omitempty"`, optional until Task 6 makes it required, so that today's `workloads` keeps passing until then;
  - in `sdk/collector`:
    - `EntryPointParameters{Hosts []string "hosts,omitempty"; Addresses []string "addresses,omitempty"}`;
    - `EntryPointParameterSchema`, the parameters' JSON Schema as a string;
    - `MaxPointsPerCall = 64`;
    - `ReasonInvalidInput = "InvalidInput"` and `ReasonNotReady = "NotReady"`.

- [ ] **Write the failing tests:**
  - **`types_test.go`:**
    - `sampleExposure` gains two entry points, an Ingress host on 443 and a node port with two addresses, and `unchecked: [HostNetwork]`. `TestCoreTypesJSON` round-trips it.
    - `TestExposureSchemaRefuses` gains:
      - 33 entry points;
      - an entry point with 257 addresses, with no address, or with no subject;
      - port 0 or 65536, or protocol `HTTP`;
      - a subject of another kind;
      - an unknown `unchecked` value, or the same value twice.
    - `TestExposureSchemaAcceptsThirtyTwoEntryPoints`.
    - `samplePresence`'s workload gains `subject`, and `minimalPresence` stays without it. `TestPresenceSchemaRefuses` gains a subject of another kind.
    - `TestEntryPointSubjects`:
      - `[shop.app.example]` on 443 keeps the host, and gives `host/shop.app.example`;
      - `[198.51.100.11, 198.51.100.12]` on 30443 gives two address subjects with the port;
      - `[localhost, 192.0.2.10]` with port 0 keeps `192.0.2.10`, gives `address/192.0.2.10`, and refuses 1.
  - **`entrypoints_test.go`:**
    - the schema compiles;
    - it accepts `{hosts: [a]}`, `{addresses: [b]}` and both;
    - it refuses `{}`, 65 hosts, and an unknown property.
- [ ] **Run** `cd sdk && go test ./evidence/ ./collector/`. Expected: FAIL.
- [ ] **Implement:**
  - the types;
  - `$defs.entryPoint` in exposure's schema;
  - presence's `subject`, matching `^workload/`;
  - `EntryPointSubjects`, with `subject.Host` and `subject.Address`.

  The schema checks that a subject starts with `host/` or `address/`; the normal form is the SDK's to check.
- [ ] **Run the tests again.** Expected: PASS. Then run `make test`.
- [ ] **Docs:** `docs/collectors.md`: the entry points, presence's subject, and the sources' contract of design 5.5.
- [ ] **Gate, then commit:** `feat(sdk): entry points in exposure, the workload's subject in presence, and the sources' parameters`.

### Task 3: `maxAge`, and the Collector's record of its operations (0045, design 5.5, 5.10)

**Files:**
- `sdk/proto/vexplain/collector/v1alpha1/collector.proto`, and `sdk/api/` (generated);
- `sdk/collector/{identity.go,identity_test.go}`, `sdk/conformance/conformance.go`;
- `api/config/v1alpha1/{collector_types.go,common_types.go}` (generated files follow);
- `internal/controller/config/{collector_answers.go,collector_controller.go}` and their tests, `internal/controller/config/collector_api_test.go`;
- `internal/collectorclient/{pool.go,pool_test.go}`;
- `internal/controller/hub/{assessor.go,assessor_test.go}`;
- `docs/collectors.md`.

**Interfaces:**
- Produces:
  - in the proto, `EvidenceType.max_age_seconds = 5`, an `int64`;
  - `collector.EvidenceType.MaxAge time.Duration`. 0 means none; any other value is from 60 s to 30 days;
  - in the Collector's status:
    - `configv1alpha1.ProducedType.MaxAgeSeconds *int64`;
    - `CollectorOperation.Role *CollectorRole`;
    - `CollectorOperation.Parameters []string`, sorted, at most 16;
  - `configv1alpha1.CollectorSpec.Produces []ProducedTypeOverride{Type string; MaxAgeSeconds *int64}`: a map list keyed by `type`, at most 16 entries, each from 60 to 2,592,000;
  - `configv1alpha1.ReasonProducesInvalid`;
  - `func collectorclient.MaxAge(c *configv1alpha1.Collector, eventType string) time.Duration`: the override, else the declared default, else 0;
  - `func collectorclient.EntryPointSource(c *configv1alpha1.Collector, eventType string) (operation string, hosts, addresses bool)`. It finds the operation in the hub role, without `consumes`, that produces the type and takes `hosts` or `addresses`, and gives `""` when there is none.

- [ ] **Write the failing tests:**
  - **`identity_test.go`:** capabilities with a `maxAge` of 10 s are refused; one of 1 h passes, and reaches the proto's `max_age_seconds` as 3600.
  - **The tests of `collector_answers.go`:**
    - a collector's answer records `maxAgeSeconds` for its type;
    - it records `role` and `parameters` (`[addresses, hosts]`) for its operation;
    - a schema without properties gives no parameters.
  - **`collector_api_test.go`:** `spec.produces` refuses 59 and 2,592,001 seconds, two entries for one type, and an empty type.
  - **The Collector controller's test:** an override for a type that the collector doesn't produce sets `Ready` false with `ProducesInvalid`, and names the type.
  - **`pool_test.go`:**
    - `TestMaxAge`: the override, the default, and none;
    - `TestEntryPointSource`: an operation in the hub role that takes `hosts` is found. One in the spoke role is not, nor one that consumes, nor one whose parameter is `repositories`.
  - **`assessor_test.go`:** evidence about a manifest that is older than its type's `maxAge` is missing for the rules, and the assessor asks for it again.
- [ ] **Run** `make proto`, then `cd sdk && go test ./collector/`, then `go test ./internal/controller/config/ ./internal/collectorclient/ ./internal/controller/hub/`. Expected: FAIL.
- [ ] **Implement:**
  - the proto's field, `make proto`, `capabilitiesResponse`, `checkCapabilities`, and the conformance check;
  - `producedTypesOf` and `operationsOf` keep what they read: an operation's role, and the top-level property names of its parameter schema;
  - the override, and its check beside the triggers' check;
  - in the assessor:
    - `inputsOf` treats a record older than its `maxAge` as missing;
    - `whyFrom` asks for such a record again.
- [ ] **Run** `make manifests generate`, then the tests. Expected: PASS.
- [ ] **Docs:** `maxAge` and the Collector's `spec.produces`, in `docs/collectors.md`.
- [ ] **Gate, run `make test-e2e`, then commit:** `feat: maxAge on produced types, and the Collector's record of its operations`.

### Task 4: The store writes in place, and keys a streamed record with its cluster (0058, design 5.4)

**Files:**
- `internal/evidence/{store.go,crdstore.go,crdstore_test.go}`;
- `api/inventory/v1alpha1/evidence_types.go` (the CRD follows);
- `internal/controller/inventory/evidence_api_test.go`;
- `internal/agent/worker/judge.go` (its RBAC marker), and `config/rbac/` (generated);
- `internal/metrics/metrics.go`.

**Interfaces:**
- Produces:
  - `evidence.Key{Subject, Type, Source, Cluster string}`. `Cluster` is empty for the evidence that an operation returns;
  - `type PutOption`, `func InCluster(name string) PutOption` and `func RefreshAfter(d time.Duration) PutOption`;
  - `Store.Put(ctx context.Context, source, collectorVersion string, e cloudevents.Event, opts ...PutOption) error`;
  - `Store.Delete(ctx context.Context, k Key) error`;
  - `Store.DeleteStreamed(ctx context.Context, cluster, source, eventType string, keep func(Key) bool) error`;
  - `evidence.ClusterLabel = "vexplain.bedag.ch/cluster"`;
  - `EvidenceSpec.Cluster *string`, a DNS label.

- [ ] **Write the failing tests** (`crdstore_test.go`, with the fake client):
  - **`TestPutOfAnEqualEventWritesNothing`:** the same data and attributes and the same version, with another event ID and time.
  - **`TestPutOfAChangedEventUpdatesTheRecordInPlace`:** the same object, by its UID, holds the new data, and the write counts as `update`. It replaces `TestPutOfAnotherVersionReplacesTheRecord`.
  - **`TestPutOfANewVersionWithTheSameDataUpdatesTheVersion`:** `Version()` gives the new one.
  - **`TestRefreshAfterRewritesAnEqualRecordOnlyWhenItIsOlder`:** with `RefreshAfter(12h)`, a record 11 hours old is left alone, and one 13 hours old gets the new time.
  - **`TestTwoClustersKeepTheirOwnRecords`:** one subject, type and source, put `InCluster("cluster-a")` and `InCluster("cluster-b")`, gives two objects, each labelled with its cluster.
  - **`TestARecordWithoutAClusterKeepsItsName`:** the name is today's hash of the subject, the type and the source.
  - **`TestDeleteStreamedKeepsOtherClustersAndTypesAndWhatItKeeps`.**
  - **`TestSourceEnqueuesAnUpdateInPlace`:** it flips today's assertion that a change enqueues nothing. A change of labels alone still enqueues nothing.
  - **`evidence_api_test.go`** (envtest):
    - the data, the time and the version may change;
    - the subject, the type, the source and the cluster may not;
    - a cluster may be neither added nor removed.
- [ ] **Run** `go test ./internal/evidence/`, and the envtest suite of `internal/controller/inventory/`. Expected: FAIL.
- [ ] **Implement:**
  - `Put` reads the object and compares the data, the kept attributes and the version. When they differ, it updates the object with its resource version, and retries on a conflict;
  - the CEL rule on the spec: `self.subject == oldSelf.subject && self.type == oldSelf.type && self.source == oldSelf.source && has(self.cluster) == has(oldSelf.cluster) && (!has(self.cluster) || self.cluster == oldSelf.cluster)`;
  - `Source()`'s predicate passes an update that changes the generation;
  - the store's RBAC marker gains `update`, and so does the workers' (`judge.go`), since the agent's tool outputs go through `Put`;
  - the texts that say "written once" say "kept current".
- [ ] **Run** `make manifests generate`, then the tests. Expected: PASS. The executor's tests now show asked evidence of a new version updated in place.
- [ ] **Gate, run `make test-e2e`, then commit:** `feat(evidence): write a record in place, and key a streamed record with its cluster`.

### Task 5: The spoke stores streamed evidence of `Hub` scope (0058, design 5.4)

**Files:**
- `internal/spoke/{store_sink.go,store_sink_test.go}` (new);
- `internal/collectorclient/{streams.go,streams_test.go}` (`Tee`);
- `internal/setup/setup.go` (`registerStreams`), and `internal/setup/streams_test.go`;
- `internal/metrics/metrics.go`;
- `docs/collectors.md` (scope).

**Interfaces:**
- Consumes: `Store.Put` with `InCluster`, `Store.Delete` and `Store.DeleteStreamed` (Task 4).
- Produces:
  - `func collectorclient.Tee(sinks ...Sink) Sink`: each call reaches each sink, in order;
  - `func spoke.NewStoreSink(store evidence.Store, collectors client.Reader, cluster func(context.Context) (string, error)) *StoreSink`, which is a `collectorclient.Sink` and a `manager.Runnable`;
  - the counter `vexplain_evidence_streamed_refused_total{collector, type, reason}`.

- [ ] **Write the failing tests** (`store_sink_test.go`). They run on the spoke's envtest fixtures, with a Collector that declares one `Hub` and one `Spoke` type:
  - `TestASnapshotOfAHubScopedTypeIsStoredWithItsCluster`;
  - `TestASpokeScopedTypeIsNotStored`;
  - `TestASnapshotDeletesTheRecordsThatItNoLongerHolds`, of its collector, type and cluster only;
  - `TestAnUpsertAndATombstoneChangeOneRecord`;
  - `TestForgetDeletesOnlyThisClustersRecordsOfTheCollector`;
  - `TestAPresenceWithoutWorkloadsDeletesItsRecord`;
  - `TestASnapshotThatRepeatsEveryEventWritesNothing` (Review Focus 3): a second identical snapshot counts no write;
  - `TestAFailedWriteIsRetried`: the store fails the first write, and the record still arrives;
  - `TestAWriteThatIsTooLargeIsCountedAndDropped`;
  - `TestTheSinkNeverBlocksTheStream`: with the store stalled, `Upsert` returns at once;
  - in `streams_test.go`, `TestTeeCallsEachSinkInOrder`.
- [ ] **Run** `go test ./internal/spoke/ ./internal/collectorclient/`. Expected: FAIL.
- [ ] **Implement `StoreSink`:**
  - it keeps the wanted state by key: the last event, or a deletion;
  - a worker writes it from a rate-limited queue, waiting 1 s, then longer, up to 1 min;
  - after a snapshot's writes, it prunes with `DeleteStreamed` and the snapshot's keys;
  - it reads the scope of each collector's types from the Collector's status at each snapshot, and keeps the last scopes when the read fails;
  - the cluster is the OperatorConfig's name. Without one, the sink waits.
- [ ] **Wire it:** `registerStreams` gives the spoke role `Tee(router, storeSink)`, and adds the sink to the manager.
- [ ] **Run the tests again.** Expected: PASS.
- [ ] **Docs:** streamed evidence of `Hub` scope reaches the hub's store. A renamed cluster's old records are deleted with `kubectl delete evidences -l vexplain.bedag.ch/cluster=<old name>`.
- [ ] **Gate, run `make test-e2e`, then commit:** `feat(spoke): store streamed evidence of Hub scope on the hub`.

### Task 6: Presence names its workloads, and goes to the hub (design 5.3, 5.4)

**Files:**
- `collectors/workloads/internal/presence/{build.go,watcher.go}` and their tests;
- `sdk/evidence/{types.go,types_test.go}` and the presence schema: `subject` becomes required;
- the stand-ins that build presence:
  - `internal/setup/chain/collectors_test.go`;
  - `internal/setup/streams_test.go`;
  - `internal/spoke/{fixtures_test.go,presence_test.go}`;
  - `sdk/conformance/presence_test.go`;
  - `sdk/api/collector/v1alpha1/collector_test.go`;
- `test/e2e/e2e_test.go`;
- the collector's own docs.

- [ ] **Write the failing tests:**
  - **`build_test.go`:**
    - `TestADeploymentsImageListsTheDeploymentWithItsUIDAndItsPods` expects `subject: workload/cluster-a/<namespace>/Deployment.apps/<name>`;
    - a bare pod's subject is `workload/cluster-a/<namespace>/Pod/<name>`.
  - **`watcher_test.go`:**
    - `TestTheCapabilities` expects `ScopeHub`;
    - `TestAWatchRefusesAContextThatItCantRead` gains a context without a cluster.
  - **`sdk/evidence/types_test.go`:** `minimalPresence` gains `subject`, and `TestPresenceSchemaRefuses` gains a workload without one.
- [ ] **Run** `cd collectors/workloads && go test ./...` and `cd sdk && go test ./evidence/`. Expected: FAIL.
- [ ] **Implement:**
  - `rules` gains the cluster, and `rulesOf` refuses an empty one, as `network-reach`'s does;
  - `add` sets `Subject` with `subject.ForWorkload`;
  - `subject` becomes required in the presence schema, and its tag loses `omitempty`;
  - the type's scope is `Hub`;
  - the stand-ins follow.
- [ ] **Run the tests again, then `make test`.** Expected: PASS.
- [ ] **e2e:** `It("stores each image's presence on the hub, labelled with its cluster")`.
- [ ] **Gate, run `make test-e2e`, then commit:** `feat(workloads): name each workload's subject in presence, and store presence on the hub`.

### Task 7: `network-reach` keeps what entry points need (design 5.1)

**Files:**
- `collectors/network-reach/internal/exposure/{watcher.go,external.go,build.go}`;
- their tests: `fixtures_test.go`, `external_test.go`, `watcher_test.go`, `capabilities_test.go`, `permissions_test.go`;
- `testdata/capabilities.json`.

**Interfaces:**
- Produces, inside the package:
  - **a Node informer.** `trimNode` keeps the name and the `InternalIP` and `ExternalIP` addresses;
  - **`trimPod`** keeps `spec.nodeName` and each host port's protocol, and `podChanged` compares them;
  - **`trimService`** keeps every port's `port`, `protocol` and `nodePort`, and `status.loadBalancer.ingress[]{ip, hostname}`. `serviceChanged` compares them;
  - **`trimIngress`** keeps each rule's host with its backends, `spec.tls[].hosts`, and the status's addresses. `ingressChanged` compares them;
  - **`trimGateway`** keeps each listener's `hostname`, `port` and `protocol`, and `status.addresses`;
  - **`trimRoute`** keeps `spec.hostnames`;
  - **`attached`** returns the matching Gateways and listeners, not booleans;
  - **the routing step** holds the nodes' addresses, and a change of a node rebuilds every namespace.

- [ ] **Write the failing tests:**
  - **`fixtures_test.go`:** fixed nodes, created once, each with an `InternalIP` and an `ExternalIP` from `198.51.100.0/24`, written through the status.
  - **`watcher_test.go`:**
    - `TestTheCapabilities` expects `nodes` in the permissions;
    - `TestAChangeOfANodesAddressRebuilds`;
    - `TestAChangeOfALoadBalancersStatusAddressRebuilds`;
    - `TestAChangeOfAConditionInAStatusBuildsNothing`.
  - **`TestTheTrimsKeepWhatEntryPointsNeed`:** a table over the six trims.
  - **`capabilities_test.go`:** the golden file, regenerated with `-update`.
- [ ] **Run** `cd collectors/network-reach && go test ./...`. Expected: FAIL.
- [ ] **Implement** the informer, the trims, the change checks and `attached`'s matches. Exposure's output doesn't change yet.
- [ ] **Run the tests again.** Expected: PASS, with `via` as before.
- [ ] **Gate, then commit:** `feat(network-reach): keep the nodes, statuses, hosts and ports that entry points need`.

### Task 8: `network-reach` reports entry points, and exposure goes to the hub (design 5.1, 5.4)

**Files:**
- `collectors/network-reach/internal/exposure/{build.go,external.go,watcher.go}` and their tests, and `testdata/capabilities.json`;
- `sdk/evidence/{types.go,types_test.go,evidence.go}` and the exposure schema: `via` goes, and the scope's comments change;
- `test/e2e/e2e_test.go`;
- `docs/collectors.md`, and the collector's own docs.

**Interfaces:**
- Consumes:
  - from Task 2: `evidence.EntryPoint`, `EntryPointSubjects`, the `Unchecked*` constants and the caps;
  - the caches of Task 7.
- Produces: exposure with `external.entryPoints` and `external.unchecked`, of scope `Hub`. `ExternalExposure.Via` is gone.

- [ ] **Write the failing tests** (`external_test.go`). Each replaces the `via` assertions of today's test of the same way in:
  - **`TestALoadBalancerServiceNamesEachPortWithItsStatusAddresses`:**
    - a Service with ports 80 and 443 and the status address `192.0.2.10` gives two entry points, `address/192.0.2.10:80` and `address/192.0.2.10:443`;
    - without a status address, it gives `unchecked: [NoAddress]` and no entry point.
  - **`TestAServiceWithExternalIPsNamesEachPort`:** external IPs `192.0.2.20` and `192.0.2.21`, ports 80 and 443, give two entry points, each with both addresses.
  - **`TestANodePortNamesEveryNodesAddresses`:**
    - one entry point with the fixed nodes' addresses, sorted, the node port and `TCP`;
    - none when `nodePorts` is Internal.
  - **`TestAnIngressHostIsOn443WhenItsTLSNamesIt`:**
    - `shop.app.example` with `tls.hosts: [shop.app.example]` is on 443;
    - with `tls.hosts: ["*.app.example"]`, it is on 443 too;
    - without TLS, on 80;
    - the subject is `host/shop.app.example` in each case.
  - **`TestAnIngressWithoutAHostNamesItsStatusAddresses`:** an IP gives an address subject without a port, and a hostname gives a host subject. Without a status, `NoAddress`.
  - **`TestARouteNamesItsHostnamesAndItsGateway`:**
    - an HTTPRoute with `hostnames: [api.app.example]` on a listener of port 443 gives port 443, `TCP`, and a `parentRef` that names the Gateway;
    - a UDP listener gives `UDP`.
  - **`TestARouteWithoutHostnamesNamesTheListenersHostnameOrTheGatewaysAddresses`:** and `NotASubject` for a `NamedAddress`.
  - **`TestAHostPortNamesTheNodesOfItsPods`:** the workload's own object, the host port, and the addresses of the node that its pod runs on.
  - **`TestAPodOnItsNodesNetworkIsUncheckedWithoutAnEntryPoint`:** it is still exposed.
  - **`TestAnAddressTheSDKRefusesIsNotASubject`:** a status hostname of `localhost`.
  - **`TestAWorkloadPastThirtyTwoEntryPointsKeepsTheFirst`:** with `TooManyEntryPoints`.
  - **`TestAnEntryPointPastTwoHundredFiftySixAddressesKeepsTheFirst`:** a LoadBalancer status of 257 addresses, with `TooManyAddresses`.
  - **`TestANodeThatJoinsRewritesTheNodePortsEntryPoints`** (Review Focus 5).
  - **`TestIndirectExposureStaysAsItWas`:** today's indirect cases give the same `indirect`.
  - **`TestAnUnchangedWorkloadSendsNothing`:** entry points and addresses are sorted, so a rebuild without a change sends no event.
  - **`watcher_test.go`:** `TestTheCapabilities` expects `ScopeHub`.
  - **`sdk/evidence/types_test.go`:** `via` is refused.
- [ ] **Run** `cd collectors/network-reach && go test ./...` and `cd sdk && go test ./evidence/`. Expected: FAIL.
- [ ] **Implement:**
  - each workload keeps the objects that expose it, as it keeps `via` today, so `exposed()` and indirect exposure don't change;
  - the entry points are built from those objects, sorted by object, port and addresses, with the ports and protocols of design 5.1 and of the Global Constraints, and with the caps and the reasons;
  - the subjects come from `evidence.EntryPointSubjects`;
  - the scope is `Hub`, and `Via` and `via` leave the SDK.
- [ ] **Run the tests again, then `make test`.** Expected: PASS.
- [ ] **e2e:**
  - the "Exposure" context still passes;
  - add `It("stores each workload's exposure on the hub, with its node port's entry point")`.
- [ ] **Docs:** the entry points, in `docs/collectors.md` and the collector's own docs.
- [ ] **Gate, run `make test-e2e`, then commit:** `feat(network-reach): report each workload's entry points, and store exposure on the hub`.

### Task 9: A `Rule` may conclude an exposure (0059, design 5.6)

**Files:**
- `api/config/v1alpha1/{rule_types.go,common_types.go}` (generated files follow);
- `internal/controller/config/rule_api_test.go`;
- the README's section on rules.

**Interfaces:**
- Produces:
  - `RuleOutcome.Exposure *SSVCExposure` (`Small;Controlled;Open`);
  - `HoldAgainst` without a default;
  - the print column `Exposure`.

- [ ] **Write the failing tests** (`rule_api_test.go`):
  - an outcome `{exposure: Open}` is accepted, and stored without `holdAgainst`;
  - each of these is refused, with its message:
    - `exposure` with `status`, with `justification`, or with `holdAgainst`;
    - a rule with `exposure` and a `match`, or a `reason`;
    - `exposure: Unknown`;
  - the spec at line 101 now stores a hint as `{}`;
  - the spec at line 114 ("defaults holdAgainst to Rules") goes, since the engine's tests cover the default.
- [ ] **Run** the envtest suite of `internal/controller/config/`. Expected: FAIL.
- [ ] **Implement:**
  - the field;
  - the validation rules: on `RuleOutcome` for the first three, and on `RuleSpec`, guarded by `has(self.outcome)`, for `match` and `reason`;
  - the column;
  - the texts of `ConditionEvaluated`'s reasons say "findings or workloads".
- [ ] **Run** `make manifests generate`, then the tests. Expected: PASS. Until Task 10, the engine compiles such a rule as a hint, and nothing ships one yet.
- [ ] **Gate, then commit:** `feat(api): a Rule may conclude a workload's exposure`.

### Task 10: The engine decides a workload's exposure (design 5.6)

**Files:**
- `internal/rules/engine/{engine.go,env.go,export_test.go}`;
- `internal/rules/engine/{exposure.go,exposure_test.go}` (new).

**Interfaces:**
- Consumes: `RuleOutcome.Exposure` (Task 9).
- Produces:
  - `Input.Subjects map[string]Input`. When it isn't nil, the input's variable is a map from each subject to its record, and `Present` says that every subject has a fresh one;
  - `func (c *Compiled) Name() string`;
  - `func (c *Compiled) Exposure() configv1alpha1.SSVCExposure`, which is `""` for a finding rule;
  - `type WorkloadExposure struct{ Exposure configv1alpha1.SSVCExposure; Rules, Missing, Failed []string }`;
  - `type ExposureResult struct{ Workloads []WorkloadExposure; NotEvaluated, TimedOut map[string]int }`;
  - `func EvaluateExposure(steps []*Compiled, workloads []map[string][]Input) ExposureResult`.

- [ ] **Write the failing tests** (`exposure_test.go`). They use the rules of design 5.6, inline; Task 11 reads the shipped files:
  - **`TestTheDefaultRulesDoWhatTheSpokesMappingDoes`:** a table over exposed, indirect and each reach, with the values that `exposureValue` gives (`internal/spoke/exposure.go`).
  - **`TestTheTableOfDesign56`:** with a source's two rules, reading `dmz`, one row per row of the design's table. The Unknown rows name `dmz` in `Missing`.
  - **`TestTheHighestExposureWins`, `TestUnknownOutranksControlled` and `TestNoRuleIsUnknown`.**
  - **`TestAMissingInputCountsAsUnknown` and `TestAFailingRuleCountsAsUnknown`:** each is counted in `NotEvaluated`. A missing optional input isn't counted.
  - **`TestAnExposedWorkloadWithAMissingAnswerIsUnknown`** (Review Focus 2): one of two subjects is answered.
  - **`TestAWorkloadWithoutEntryPointsHasAnEmptyMap`.**
  - **`TestTheRulesThatConcludedTheWinningValueAreNamed`:** sorted.
  - **`TestEachProducerIsEvaluatedApart` and `TestMoreThanFourCombinationsIsUnknown`.**
  - **`TestAWorkloadPastTheBoundIsUnknown`:** with `SetBounds`.
  - **`TestCompileRefusesAnExposureRuleThatReadsFinding`.**
- [ ] **Run** `go test ./internal/rules/engine/`. Expected: FAIL.
- [ ] **Implement:**
  - a second environment, without `finding`;
  - `variable()` builds the map for an input with `Subjects`;
  - `EvaluateExposure` ranks Open, Unknown, Controlled, Small, and keeps the bounds: `runBound` for each rule and workload, and `callBound` for the call.
- [ ] **Run the tests again.** Expected: PASS.
- [ ] **Gate, then commit:** `feat(rules): evaluate exposure rules for a workload`.

### Task 11: Finding rules and exposure rules apart, and the shipped exposure rules (design 5.6, 5.7)

**Files:**
- `internal/controller/hub/{playbook_controller.go,assessor.go,rule_controller.go}`, and their tests: `suite_test.go`, `assessor_test.go`, `playbook_controller_test.go`;
- `config/rules/{exposed-outside-cluster,reachable-in-cluster,own-namespace-only}.yaml` (new), `config/rules/kustomization.yaml`;
- `config/playbooks/container-cves.yaml`, `config/samples/config_v1alpha1_playbook.yaml`;
- `internal/rules/engine/defaults_test.go`;
- `internal/setup/chain/{suite_test.go,chain_test.go}`;
- `hack/measure-2a/{main.go,main_test.go}`;
- the README's list of default rules.

**Interfaces:**
- Consumes: `Compiled.Exposure()` (Task 10).
- Produces:
  - `playbookCheck.exposureSteps []*engine.Compiled`;
  - `playbookCheck.workloadEvidence map[string]bool`: the names that only exposure rules read;
  - `Evaluations` records the exposure rules' counts under `"exposure/" + inventory.SheetName(manifest, playbook)`. The assessor forgets them with the sheet.

- [ ] **Write the failing tests:**
  - **`defaults_test.go`:**
    - `defaultSteps` lists eight files;
    - `TestTheDefaultPlaybookEndsWithTheExposureRules` replaces `TestTheDefaultPlaybookEndsWithFixAvailable`: eight steps, `fix-available` fifth, then the three;
    - `TestTheDefaultExposureRulesDoWhatTheSpokesMappingDoes` reads the shipped files.
  - **`playbook_controller_test.go`:**
    - a pipeline with both kinds gives five finding steps and three exposure steps;
    - `exposure` is workload evidence;
    - a not-Ready exposure rule keeps the playbook from being Ready, as a finding rule does.
  - **`assessor_test.go`:**
    - a playbook that names `exposure` and a source's type neither asks for them about a manifest nor lists them in a sheet's evidence;
    - editing an exposure rule re-evaluates no sheet;
    - the exposure rules never hold a finding.
  - **`chain_test.go` and the hub's suite:** the sheets' evidence stays `contents` and `sbom`.
- [ ] **Run** `go test ./internal/rules/engine/`, and the hub's and the chain's suites. Expected: FAIL.
- [ ] **Implement:**
  - the split in `checkPipeline`;
  - a basis of the finding steps only;
  - the assessor's `evidenceOf` and `producersByType`, over the evidence that finding rules read or that a findings producer consumes;
  - the three rules, exactly as design 5.6 shows them;
  - `rulesOf` in `hack/measure-2a` skips exposure rules;
  - `container-cves` gains `exposure`, as optional evidence, and the three steps. Its `agent.evidence` stays `[contents, sbom]`, so that a change of exposure never makes a verdict stale (design 5.8).
- [ ] **Run the tests again.** Expected: PASS.
- [ ] **Docs:** the README's list of default rules.
- [ ] **Gate, run `make test-e2e`, then commit:** `feat: ship the exposure rules, apart from the finding rules`.

### Task 12: The hub's view of exposure, and the asker (design 5.5, 5.8)

**Files:**
- `internal/exposure/{view.go,asker.go,metrics.go}` and their tests (new);
- `internal/setup/setup.go`, and the test in `internal/setup` of what each binary links;
- `internal/metrics/metrics.go`;
- `config/rbac/` (generated);
- `docs/collectors.md` (how the hub asks).

**Interfaces:**
- Consumes:
  - from Task 4: `Store.Put` with `RefreshAfter`, `Store.Source` and `Store.ListBySubject`;
  - from Task 3: `collectorclient.MaxAge` and `collectorclient.EntryPointSource`;
  - from Task 2: `collector.EntryPointParameters`, `MaxPointsPerCall` and the reasons;
  - from Task 1: `subject.Parse`.
- Produces:
  - `type Record struct{ Source string; Time time.Time; Data any }`;
  - `func NewView(store evidence.Store) *View`, with these methods:
    - `SetupWithManager(mgr ctrl.Manager) error`;
    - `Synced() bool`;
    - `Workloads(digest, cluster string) (subjects []string, known bool)`;
    - `Records(eventType, subject string) []Record`;
    - `EntryPoints() []string`;
  - `type Invoker interface{ Invoke(ctx context.Context, collector string, req *collectorv1alpha1.InvokeRequest, opts ...collectorclient.InvokeOption) ([]cloudevents.Event, *collectorclient.Failure, error) }`;
  - `func NewAsker(view *View, store evidence.Store, collectors client.Reader, pool Invoker, clusterContext func(context.Context) (*collectorv1alpha1.Context, error)) *Asker`, a `manager.Runnable`;
  - the metrics:
    - `vexplain_entry_points{cluster, state}`;
    - `vexplain_source_calls_total{collector, result}`;
    - `vexplain_source_answers_unasked_total{collector}`.

- [ ] **Write the failing tests.** The view runs on envtest, and the asker on a fake invoker and a fake clock.
  - **`view_test.go`:**
    - presence of one image in two clusters gives each cluster's subjects;
    - a workload without `subject` isn't named;
    - an update in place and a delete reach the view;
    - `Synced` waits for the first list;
    - the entry points are the union of every exposure's subjects.
  - **`asker_test.go`:**
    - `TestANewEntryPointIsAskedOfEachSource`: 70 hosts give two calls, of 64 and 6, with `hosts` only. A call's subject is its first point's;
    - `TestAnOperationThatTakesOnlyHostsIsNeverAskedAboutAddresses`;
    - `TestARefusedCallIsSplitInHalves` (Review Focus 4): the source refuses any call that holds `localhost`, and every other point gets its answer;
    - `TestAFailureWaitsAMinuteThenLonger`, up to 15 minutes;
    - `TestAnAnswerIsAskedAgainAtHalfItsMaxAge`, and stored with `RefreshAfter`;
    - `TestAChangeOfTheSourcesVersionAsksAgainAtOnce`;
    - `TestEveryEntryPointIsAskedAgainAfterAStart`;
    - `TestAnAnswerAboutASubjectThatWasntAskedIsDroppedAndCounted`;
    - `TestAnAnswerAboutAnEntryPointThatNoClusterNamesIsDeleted`;
    - `TestOnlySourcesOfAReadyPlaybooksTypeAreAsked`.
- [ ] **Run** `go test ./internal/exposure/`. Expected: FAIL.
- [ ] **Implement:**
  - the view, as a controller over `Store.Source()`. It keeps the raw data, and decodes it on demand;
  - the asker, as a loop that wakes on the view's changes, on the Collectors' status, and on its own timers;
  - both are wired into the manager's hub role only. The linking test shows that `cmd/agent` doesn't link `internal/exposure`.
- [ ] **Run the tests again.** Expected: PASS.
- [ ] **Docs:** how the hub asks a source, in `docs/collectors.md`.
- [ ] **Gate, run `make test-e2e`, then commit:** `feat(hub): keep a view of exposure, and ask the sources about entry points`.

### Task 13: Cases take their exposure from the rules (design 5.8)

**Files:**
- `internal/agent/cases/{cases.go,impact.go,select.go,cases_test.go}`;
- `internal/exposure/{cases.go,cases_test.go}` (new);
- `internal/controller/hub/{investigation.go,queue.go}` and their tests;
- `api/triage/v1alpha1/{assessment_types.go,investigation_types.go}` (generated files follow), and `internal/controller/triage/{assessment_api_test.go,investigation_api_test.go}`;
- `internal/agent/worker/claim.go` and its test;
- `internal/agent/casefile/{casefile.go,casefile_test.go}`;
- `internal/agent/prompt/guidance.md`;
- `cmd/agent-replay/{export.go,replay.go}` and their tests;
- `docs/agent.md`.

**Interfaces:**
- Consumes:
  - the view (Task 12);
  - `EvaluateExposure` (Task 10);
  - the playbook check's exposure steps and workload evidence (Task 11).
- Produces:
  - in `cases`:
    - `type Exposures interface{ Of(ctx context.Context, playbook, digest, cluster string) (workloads []WorkloadExposure, known bool, err error) }`;
    - `type WorkloadExposure struct{ Subject string; engine.WorkloadExposure }`;
    - `type ExposureGroup struct{ Exposure configv1alpha1.SSVCExposure; Rules, Missing []string; Workloads int32; First []string }`;
    - `Impact.Exposure []ExposureGroup`;
    - `Selection.Exposures Exposures`. When it is nil, the counts come from ImageInventory, as today;
  - in `internal/exposure`:
    - `type PlaybookExposure struct{ Steps []*engine.Compiled; Types map[string]string; Sources, Optional map[string]bool }`;
    - `type Playbooks func(ctx context.Context, name string) (PlaybookExposure, error)`;
    - `func NewCaseExposures(view *View, collectors client.Reader, playbooks Playbooks, record func(key string, notEvaluated map[string]int)) cases.Exposures`;
  - in the API:
    - `triagev1alpha1.QueueRunsIn{HighestExposure *SSVCExposure; HighestUrgency *SSVCOutcome; UrgentWorkloads *int32; Exposure []ExposureGroup}`, as `AssessmentQueue.RunsIn`. The triage group's own `ExposureGroup{Exposure SSVCExposure; Rules, Missing []string; Workloads *int32; First []string}` mirrors the one in `cases`, with at most 16 groups, 8 rules, 8 missing inputs and 5 subjects each;
    - `InvestigationResult.Exposure *SSVCExposure`;
  - the case file's `runsIn.exposure`.

- [ ] **Write the failing tests:**
  - **`cases_test.go`** (with a fake `Exposures`):
    - `TestACasesWorkloadsTakeTheirExposureFromTheRules`: two workloads, Controlled and Small, give the groups, a `highestExposure` of Controlled, and the urgency at Controlled;
    - `TestACaseCountsWorkloadsThatPresenceDoesntNameAsUnknown` (Review Focus 1):
      - an entry of 3 workloads with 1 named gives 2 Unknown;
      - with presence unknown for the cluster, all 3 are Unknown;
      - the case is never skipped as not running;
    - `TestAWorkloadUnderTwoDigestsCountsOnceInTheGroups`;
    - `TestTheGroupsKeepTheFirstFiveAndAtMostSixteen`;
    - `TestWithoutExposuresTheImpactIsAsToday`.
  - **`internal/exposure/cases_test.go`:**
    - each workload's inputs: `exposure` from the view, and a source's type as the map of the workload's entry points;
    - an answer past its `maxAge` is missing;
    - a playbook without exposure rules has every workload Unknown;
    - the counts in `NotEvaluated` reach the recorder under `exposure/` and the sheet's name.
  - **`investigation_test.go`:**
    - a result names its case's highest exposure;
    - the queued Assessment holds `runsIn`, and `runsIn` changes when the exposure does.
  - **The API tests:** `runsIn` and `exposure` accept the values and caps of the Global Constraints.
  - **`claim_test.go`:** the case file takes `runsIn` from the Assessment's queue, and without one it is as today.
  - **`casefile_test.go`:**
    - `runsIn.exposure` is shown;
    - it is cut after `runsIn.namespaces` when the case file is over its cap;
    - it names no labels.
  - **`cmd/agent-replay`:** an exported case keeps its exposure groups.
- [ ] **Run** `go test ./internal/agent/... ./internal/exposure/ ./cmd/agent-replay/`, and the hub's and triage's suites. Expected: FAIL.
- [ ] **Implement:**
  - `presenceOf` goes per cluster entry, as today, with `Exposures.Of` for the named workloads and Unknown for the rest;
  - `CaseExposures` builds each workload's inputs from the view and the playbook's exposure steps, and evaluates all the workloads of a case in one `EvaluateExposure`;
  - the investigation controller:
    - waits for `View.Synced()`;
    - gives `Select` its `Exposures`;
    - writes `results[].exposure` and the queue's `runsIn`;
  - the worker lays `runsIn` over the case's impact before `casefile.Build`;
  - `guidance.md` says what `runsIn.exposure` means: the rules' names say why.
- [ ] **Run** `make manifests generate`, then the tests. Expected: PASS.
- [ ] **Docs:** `runsIn.exposure`, in `docs/agent.md`.
- [ ] **Gate, run `make test-e2e`, then commit:** `feat: decide each case's exposure with the exposure rules`.

### Task 14: End to end, with a stand-in source (design section 6)

**Files:**
- `test/e2e/images/dmz-stand-in/{main.go,Dockerfile}` (new);
- `test/e2e/{e2e_suite_test.go,e2e_test.go,helpers_test.go}`.

**Interfaces:**
- Produces: a collector built with the SDK, from the repository's root as the collectors are:
  - in the hub role, with the operation `lookup` and `collector.EntryPointParameterSchema`;
  - the type `ch.example.dmz.publication.v1alpha1`, of scope `Hub`, with a `maxAge` of 1 hour and the data `{publishedTo}`;
  - the settings `{published: {<subject>: Internet | Internal}}`. Any other point is `None`;
  - as its source version, the hash of its settings.

- [ ] **Write the e2e specs:** `Describe("Entry points")`, ordered:
  - **Install** the stand-in with its two rules. `container-cves` takes its type, and swaps `exposed-outside-cluster` for its rules.
  - **A Deployment behind a NodePort Service is selected by an investigation:**
    - its exposure record names the kind node's address with the node port;
    - the stand-in is asked about it.
  - **The result's `exposure` is Controlled,** and the Assessment's `runsIn` names `exposed-not-published`.
  - **The stand-in's settings publish that subject to the `Internet`:** the result's `exposure` becomes Open within the investigation's next refresh, at most 5 minutes (`impactRefresh`), so the spec waits up to 6.
  - **With the stand-in scaled to zero,** a new workload behind a node port is Unknown.
  - **Scaled back,** it is Controlled.
  - **The sheets' evidence stays `contents` and `sbom`:** the existing spec.
- [ ] **Build** the stand-in in `BeforeSuite`, as the collectors are, and load it into kind.
- [ ] **Run** `make test-e2e`. Expected: PASS.
- [ ] **Commit:** `test(e2e): entry points with a stand-in source`.

### Task 15: The docs, and "As built"

- [ ] **Docs:**
  - `README.md`: the exposure rules, and a source in short;
  - `docs/collectors.md`: the subjects, the entry points, a source's contract, `maxAge`, and how the hub asks;
  - `docs/agent.md`: `runsIn.exposure`.
- [ ] **"As built":** this plan's section below:
  - what differs from the plan, and the images;
  - **before the live check:** what must be deployed together (the manager, the agent workers, `workloads` and `network-reach`, since older collectors' events no longer pass), which CRDs change, and what an organization's source needs: its `maxAge` in its Collector's `spec.produces`, its two rules, and the swap of `exposed-outside-cluster` in `container-cves`.
- [ ] **Commit:** `docs: entry points and exposure rules, as built`.

### Task 16: The hand-over (design sections 6 and 8)

The main session runs the live check with the owner (owner, 2026-11-22). This build only prepares it.

- [ ] **Write the hand-over** in the shared notes, outside the repository:
  - the branch and its last commit, ready to merge into `feat/phase4-agent`: a fast-forward when phase 4 hasn't moved;
  - "before the live check", from "As built";
  - what to measure, from design section 8: Evidence objects and write rates of presence, exposure and the answers, idle and during a rollout; the time from an Ingress's change to a case's new exposure; the workloads that go from Open to Controlled, and why the others stay Open; that a manager restart changes nothing; the calls after a change of the source's data;
  - that the figures are a real platform's, so they stay outside the repository, and the repository gets only what they decide.
- [ ] **Tell the owner** what must be done before the live check, in short.

---

## As built

Where the build differs from the text above, the build is right. Each difference was decided and reviewed while the plan ran. The design records the calls of Task 8 in its change log, under "While building", and Task 15 corrected design 4.2 and 5.6 and decision 0059: adding a rule never lowers a value that another rule concluded, nor a failure's Unknown. The design of collectors, evidence and rules has a revision 4 for its section 5.5.

### Subjects and entry points in the SDK (Tasks 1 and 2)

- **An IPv6 address is in brackets only when a port follows,** as design 5.2 says. `address/2001:db8::1:443` is a bare IPv6 address, so the plan's case that refused it was a defect; `address/[2001:db8::1]`, in brackets without a port, is refused instead. A zoned address is refused too.
- **`EntryPointSubjects` refuses every IP address when the port is outside 0 to 65535,** and counts it: a port cut to 16 bits would name another subject. Hosts carry no port.
- **`external.entryPoints` and `external.unchecked` are always written, `[]` when empty, and the schema requires both** (Task 11's first commit). With the plan's `omitempty`, a source's rules failed on the missing key, so that a source could never conclude `Controlled`.

### `maxAge` (Task 3)

- **`spec.produces[].maxAgeSeconds` is required, and no pointer,** as kube-api-linter asks.
- **The assessor treats a record past its `maxAge` as missing where it reads the evidence,** in `evidenceOf` rather than `inputsOf`, with the same effect.
- **A `maxAge` applies to the evidence that operations return.** The `Collector` refuses an override of a type that no operation of it returns as `ProducesInvalid`: the final review found that a `maxAge` on presence or exposure, whose records the spoke writes only when they change, would turn every unchanged workload `Unknown`.

### The store and the spoke's sink (Tasks 4 and 5)

- **The spoke's executor stores asked evidence of a type with a `maxAge` with `RefreshAfter` half of it,** so that an equal answer asked again gets a new time. Without it, the assessor would ask for a record past its `maxAge` forever. The record takes the new time only when the event is newer, to the second, since the record keeps whole seconds.
- **A write that finds its record deleted meanwhile tries again,** and creates it.
- **`Delete` checks the key's source and cluster,** as `DeleteStreamed` does, and refuses to delete another key's record.
- **The workers' role on `Evidence` is `get`, `create` and `update`.** `delete` went: nothing of the workers deletes evidence, which the manager's janitor does.
- **The sink stores each record at the version in its `Collector`'s status,** and waits while there is none, as it waits while the cluster has no name.
- **A snapshot that comes before the sink has read its collector's scopes waits,** with the changes after it, and the sink reads the `Collector` again, with the queue's back-off, until it can. Dropping it would leave presence or exposure off the hub until the next snapshot, possibly hours later.
- **An event that the store refuses deletes its key's record,** retried like any write, so that the hub reads the record as missing, never an older one as current. So does presence or exposure whose data doesn't follow the core's schema, which the sink checks as the Router does: the final review found that the sink stored it, and the hub's view decoded it without the schema. `vexplain_evidence_streamed_refused_total` has the reasons `TooLarge` and `Invalid`, and the label `cluster` too.
- **A snapshot's writes come before its prune,** for each collector in order, and a prune keeps what the collector holds when it runs.
- **Four workers write,** each the records of one collector at a time.

### `network-reach` (Tasks 7 and 8)

- **A pod keeps `spec.nodeName` only when it has a host port.**
- **Where design 5.1 was silent, the build errs towards `Open`,** as the design's change log records: a route through a parent of a kind that the collector doesn't read, a host port of a pod on a node without an address or on no node yet, a node port while a node has no address, a counted Service without a port, and a Gateway's `NamedAddress`.

### The rules (Tasks 9 to 11)

- **A step is an exposure step when its `Rule` concludes an exposure,** whether or not the rule compiles or is `Ready`. A missing rule, whose kind nothing says, is in both lists, and keeps the playbook from being `Ready`, as before.
- **An exposure rule's `Evaluated` condition counts workloads** in its message, where a finding rule's counts findings.

### The hub (Tasks 12 and 13)

- **The asker respects a playbook's pins of `Collector`s.** It reads the `Collector`s and the playbooks from the manager's cache every 5 seconds, and gives a call at most a minute.
- **A point that a source leaves unanswered waits on its own,** a minute after the first miss, doubling up to 15 minutes, beside the wait of a source whose call failed. Of several events about one point, the first counts.
- **The counters `vexplain_source_calls_total` and `vexplain_source_answers_unasked_total` have the label `cluster` too.**
- **A record that the view can't read or decode counts as read for `Synced`,** and is left out of the view, so that its workloads are Unknown. It is logged by its key, and counted in `vexplain_exposure_view_read_failures_total{cluster}`. Otherwise one bad record would hold up every investigation.
- **The view drops presence's workloads, and exposure, of another cluster than the one whose stream delivered the record,** and counts them as read failures: a check at the hub's trust boundary, before remote spokes come.
- **The store finds a subject's records in the metadata of its cache, and reads each by its name,** where the view's reads listed them through the API server, which can't select by a label without reading every `Evidence`, SBOMs included. The final review found the cost; a store without a cache, as the workers', still lists.
- **The view keeps of presence only the workloads that it names,** not its pods, containers, labels and annotations, which nothing on the hub reads. The final review found that it kept presence's whole data.
- **Only a change of a workload's exposure, or of an answer, wakes the asker,** not one of presence, which comes with every pod that starts or stops.
- **A record whose time lies more than a minute ahead of the hub's clock is missing for the exposure rules,** so that a source whose clock runs ahead can't keep its answers current past their `maxAge`.
- **A rule's `source` is the stored event's CloudEvents source,** for exposure rules as for finding rules. The view's `Record` keeps it as `EventSource`, beside the `Collector`'s name, and keeps the event's `Coverage` too.
- **`Exposures.Of` takes a playbook, a manifest and all its places,** and evaluates every workload of a case in one `EvaluateExposure`, each once.
- **The recorder of the exposure rules' counts takes the manifest and the playbook,** and only the hub's `ExposureEvaluations` builds their key, `exposure/<sheet name>`, which the assessor's forget and the tests use too.
- **A playbook's producers count for exposure rules as for finding rules:** the `Collector`s that it pins, or else every one that produces the type, each only while its capabilities declare the type, with the scope `Hub` unless it is a source of the type. A producer without a record is a missing input, and so is a pinned `Collector` that doesn't count, or an input that a rule takes with another type than the playbook's evidence. The final review found that the build read whatever the view held of such producers.
- **An `Unknown` group names in `rules` the rules that couldn't be evaluated.**
- **Once a case is in the queue, only an investigation of the queue's playbook writes its `order` and `runsIn`,** which the request that added the case wrote first. The final review found that two playbooks that select one case wrote both in turn at each reconcile, and that the case file could show the other playbook's exposure.
- **`agent-replay` exports a judged case without its exposure groups,** since its queue is gone with them: it counts the workloads by the inventory's exposure. Only a case that still waits keeps them.

### End to end (Task 14)

- **Each wait is bounded by its worst case,** not by the plan's 6 minutes: up to 8 minutes for `Open`, which spans the source's new version, the asker's pass and `impactRefresh`, and 9 for `Controlled` after the stand-in is scaled back.
- **The stand-in's source version is a hash of the settings that `ValidateSettings` saw,** since `GetInfo` carries none, so a new version shows at the `Collector`'s next resync, 30 seconds later.
- **The checks of `runsIn` rely on the ordered suite:** they run before the reports' specs, while no `ModelConfig` is `Ready`, so that the case still waits in the queue.
- **The suite takes about 12 minutes longer,** for its two waits on `impactRefresh`.

### The images

- **Four change:** the manager (`IMG`), the agent workers (`AGENT_IMG`), `workloads` (`WORKLOADS_IMG`) and `network-reach` (`NETWORK_REACH_IMG`). `scanner`, `vulnerabilities` and `advisories` do what they did; `make docker-build` builds all seven from one commit, as before.
- **The stand-in source is a test image only,** `test/e2e/images/dmz-stand-in`, which the e2e suite builds from the repository's root as `example.com/vexplain-dmz-stand-in:v0.0.1` and loads into kind.

### Before the live check

**Deploy together,** from this branch's last commit: the manager, the agent workers, `workloads` and `network-reach`.
- An older `workloads` sends presence without `subject`, and an older `network-reach` sends exposure with `via` and without `entryPoints` and `unchecked`. Both are off the new schemas, so the spoke drops them; and the older collectors declare both types `Spoke`, so the hub gets none.
- The workers take a case's exposure from its `Assessment`'s `status.queue.runsIn`, which the manager writes.
- The roles change with them: the manager and the workers update `Evidence` in place, and the workers no longer delete it.
- `network-reach` now lists and watches Nodes. The default ceilings allow it. Where `OperatorConfig`'s `spec.collectors.permissions` is `Check`, its service account needs that granted.
- The first deploy creates a record of every image's presence and every workload's exposure in each cluster, and each later version of `workloads` or `network-reach` rewrites each of its records once, since an equal event has the same collector version too.

**The CRDs that change** come first, with `make install`, or with the rest of `make deploy`:
- `Evidence`: `spec.cluster`;
- `Rule`: `spec.outcome.exposure`, and the column `Exposure`. `holdAgainst` has no default any more, which the engine still reads as `Rules`;
- `Collector`: `spec.produces[]{type, maxAgeSeconds}`, and in its status each type's `maxAgeSeconds` and each operation's `role` and `parameters`;
- `Assessment`: `status.queue.runsIn`;
- `Investigation`: `status.results[].exposure`.

**The default rules and playbook:** `config/rules` gains the three exposure rules, and `container-cves` takes `exposure`, as optional evidence, and runs them. A cluster whose rules and playbooks are applied apart from the install needs both.
- **An admin's own playbook without exposure rules has every workload `Unknown` after the upgrade** (design 5.7), which raises its cases' urgency to `Open`'s: it needs exposure rules of its own, such as the three that `container-cves` runs.

**An organization's source needs:**
- its `Collector`, `Ready`, whose status records its operation: in the role `Hub`, consuming nothing, producing its type, with the parameters `hosts`, `addresses` or both;
- a `maxAge` for its type: declared by the source, or set in its `Collector`'s `spec.produces[]{type, maxAgeSeconds}`. Without one, its answers never expire, and the hub asks about an answered entry point again only after a start or when the source's version changes;
- its two exposure rules, written for its type as `published-or-unchecked` and `exposed-not-published` are for the example type `ch.example.dmz.publication.v1alpha1` with the input `dmz` (`docs/collectors.md`, "Sources");
- the admin's change to `container-cves`: the source's type among its evidence, under the name that its rules read it by and required by default, and its two rules in place of `exposed-outside-cluster`. This comes last, once the `Collector` is `Ready` and the rules exist: a playbook that requires a type that no `Collector` produces, or names a missing rule, isn't `Ready`, and asks for no findings.

**Operating notes:**
- **Right after the deploy,** until a cluster's presence reaches the hub, the workloads that ImageInventory counts there are `Unknown`, which urgency counts as `Open`. A case is never taken for one that runs nowhere.
- **A change of exposure or of an answer reaches the investigations at their next refresh,** within `impactRefresh`, 5 minutes. A source's new version shows at the `Collector`'s next resync, 30 seconds, and the asker's next pass, within 5 seconds.
- **Deleting a `Collector` deletes its streamed records of every cluster,** with the rest of its evidence.
- **A renamed cluster leaves its old streamed records:** `kubectl delete evidences -l vexplain.bedag.ch/cluster=<old name>` removes them.
- **A call to a source carries the context that every collector call does:** the cluster's name, the operator's namespace, the label of vexplain's own pods, the scope's label selectors and the keys of owner attribution's allowlists, with the `Collector`'s settings. It names entry points only, never a workload or a namespace.
- **Producers are found among the hub's `Collector`s.** A streamed producer without a `Collector` of its name on the hub gives a missing input, so `Unknown`. Remote spokes are later work.
- **Presence joins by digest and cluster, not by the nodes' platform,** so in a cluster of mixed architectures a manifest's case also names the workloads that run the image's other platform: the safe side.

**Known gaps, by design:**
- **A DMZ proxy that forwards any host to a shared ingress controller** isn't caught while the hub asks about an Ingress's hosts by name. Design section 9 holds the option: a published address counts for every host behind it.
- **A virtual IP in front of the nodes that no Kubernetes object names** isn't asked about.

**What to measure** is design section 8. The figures are a real platform's, so they stay outside the repository, which gets only what they decide. `vexplain_evidence_writes_total{cluster, op}` counts the store's writes, and the labels `vexplain.bedag.ch/collector` and `vexplain.bedag.ch/cluster` count the `Evidence` objects of each collector and cluster.

Beside design section 8, the final review asked to measure:
- the time to `Synced` after a restart, and how long a snapshot takes to settle after one;
- the API reads of the view and of the store, their rate and their latency;
- the manager's memory;
- the largest presence records: an image that every pod runs is one record, rewritten at each pod's start or stop;
- the rewrites of exposure when nodes join or leave, since LoadBalancer Services allocate node ports;
- how many answer records node ports create: nodes × addresses × node ports.

## Carried forward

### The SDK and `network-reach`

- **`subject.Host` lower-cases with Unicode's rules before it checks for ASCII,** so a few letters outside ASCII, such as the Kelvin sign, become ASCII ones. A source may fold them otherwise.
- **An Ingress's `tls` entry without hosts** leaves every host of the Ingress on port 80, where the controller's default certificate may serve them on 443. Only the entry point's port is off: a host's subject has none.
- **A default backend gets only the Ingress's status addresses,** though controllers also serve it under the rules' hosts. A source that takes only hosts can't answer for it, which leaves its workload on the safe side.
- **`network-reach` keeps a node's addresses in the order of its status** (build.go ~:421-428), so that a reordering alone rebuilds every namespace.

### The store and the spoke's sink

- **Deleting a `Collector` deletes its streamed records of every cluster** (`DeleteBySource`). Revisit it with remote spokes.
- **The sink remembers only in memory which types a collector declared `Hub`.** After a restart, a downgrade that declares one `Spoke` again leaves its records. The exposure rules don't read them, since the `Collector` no longer counts as a producer of the type, but the view still holds them:
  - a downgraded `workloads`' presence still names the workloads of the cases, which can show a lower exposure than the workloads that run now;
  - a downgraded `network-reach`'s exposure still names entry points that the hub asks the sources about, and a source's input is built from them (`entryPointsOf`), so a rule that reads only a source's input can decide on them;
  - deleting the collector's records (`kubectl delete evidences -l vexplain.bedag.ch/collector=<name>`) clears them.
- **A change that `Streams` drops as invalid never reaches the sink** (`takeEvent` in streams.go), so the hub keeps the older record of its subject until the next snapshot.
- **A `maxAge` that a collector itself declares for a streamed type still applies,** and expires its current records, so its workloads turn `Unknown`. The SDK, the API and the docs say that a collector declares none. Only an admin's override is refused.
- **While a `Collector` records no version, the sink retries its writes in vain** until a snapshot reads one (store_sink.go ~:456).
- **`Delete`'s errors of a bad key, or of another key's record, aren't `ErrRefused`,** so a round of writes stops on them for good (crdstore.go ~:344-360). `Delete` also reads a record and then deletes it without a UID precondition.
- **New calls skip the back-off while rounds of writes fail,** which adds log lines during an outage of the API server. The log of a refused event omits its subject.
- **Presence is decoded on the stream's goroutine,** even while its type is `Spoke`. A degraded cache can hold a snapshot for about 20 seconds, two reads of the `Collector`. The sink's tidy-up forgets collectors without a `Hub` type, so that a failed read parks their snapshot.
- **The metrics' label `type` isn't a named constant.**
- **The `Evidence`'s `AGE` column shows when a record was created,** not its last write.

### The rules

- **`ReasonEvaluationErrors`' list of causes names findings only** (common_types.go ~:197-203).
- **`holdAgainst`'s doc comment has an overlong line** (rule_types.go ~:125-126), which the CRD's description carries.
- **Exposure rules still feed the inputs that the assessor counts as absent:** a mistyped input of an exposure rule evaluates the sheets again, and can hold a finding rule's input of the same name while the playbook is `InputMissing`.
- **A playbook's `exposure` entry that no exposure rule reads counts as evidence about manifests,** as any other entry: for the owner to decide.
- **More than 4 combinations of producers look like failing rules,** with no reason of their own. The inputs of the workloads past the call's bound are still converted to CEL, and the run's bound applies to each combination, as for findings.
- **`OperationFor` ignores an operation's role,** from before this plan.

### The hub

- **A failed read drops all of a subject's records from the view** (marked `shortcut:`), such as every cluster's presence of one image, not only the bad record. An invalid record is logged and counted again at every reconcile of its subject.
- **While a read of a workload's exposure fails, its entry points leave the view,** and the asker deletes their answers, to ask again once the read heals.
- **A source that refuses every point costs about 2N−1 calls per step of its back-off,** as each call is split down to single points.
- **The check for `InvalidArgument` is duplicated** in `internal/exposure` and `internal/agent/core/collector_tools.go`: one helper in `collectorclient` would do.
- **The `Unknown` group of the workloads that presence doesn't name has no `rules` and no `missing`,** and the model's guidance (guidance.md:5) doesn't say what that means.
- **The cases read the producers' `Collector`s, `maxAge`s and records for every piece of evidence,** manifest evidence included, for each manifest at each reconcile. Limit it to the exposure rules' inputs, and keep it for a pass.
- **`exposure.Of` uses `time.Now()`,** not the reconciler's clock.
- **The exposure rules' counts in `Evaluations` are dropped only with their sheet,** so a manifest whose cases no investigation evaluates any more keeps its last counts in the rules' `Evaluated` condition until the assessor deletes the sheet.
- **The worker sums `workloadsByExposure` from at most 16 groups** (marked `shortcut:`), so that past 16 it lacks the least exposed.
- **Only an investigation of the queue's playbook writes a waiting case's `order` and `runsIn`** (queue.go `Add`).
  - While none asks for the case, both keep their values for the rest of the wait. That happens when the playbook was deleted or renamed, or when only another playbook selects the case. A case that turns `Open` or known exploited meanwhile keeps its tier, and its case file keeps the old exposure.
  - A fix: record each request's playbook, and let a request write while no request of the queue's playbook is left.
  - The owner's call (2026-11-23): a known limit, documented in `docs/agent.md`, not fixed. It shows only with a renamed or deleted playbook or two playbooks on one case, and it touches only the queue's order and the case file's exposure, until the case is judged.
  - The phase-4 live-fixes design (~:205) and `take`'s comments (investigation.go ~:600, ~:674) still say that `Add` refreshes the order.
- **The view's reads scan every `Evidence`'s metadata in the cache for each subject** (crdstore.go ~:356), since the cache doesn't index labels. A field index on the subject hash, as ImageInventory has (setup.go ~:269), would make each read direct. The time to `Synced` after a restart shows the cost.
- **`ask`'s doc comment lists its checks "in that order" without the check of `spec.produces`** (collector_controller.go ~:411).

### Tests

- **From before this plan:** `network-reach`'s `TestAWatchNeedsNoMoreThanTheDeclaredPermissions` fails when it runs alone, since its TLSRoute informer misses the 1 s sync, and passes in the whole suite. Under `-race`, the engine's cost-limit cases pass the 1 s bound of a run and count as timed out, for findings too; `make test` doesn't use `-race`.
- **Timing:** the cost-limit case of the engine's `TestAFailingRuleCountsAsUnknown` (exposure_test.go ~:455) depends on the machine's speed under the real bound of 1 s, and `TestAChangeOfANodesAddressRebuilds` asserts a loose lower bound.
- **Untested:**
  - an interleaved refused address, and IPv6, in `EntryPointSubjects`' tests, whose case labelled 33 entry points builds 34;
  - `Forget` during a round of the sink's writes;
  - the asker before `Synced`, a host record of a collector that is no source surviving its clean-up, and the settings that its calls carry; the view's wake once synced;
  - an answer exactly at its `maxAge`, and a source's type with two producers of which one hasn't answered;
  - that `container-cves` takes `exposure` as optional, and that its `agent.evidence` stays `[contents, sbom]`;
  - an unpinned producer that declares exposure `Spoke`, the default playbook's case. The spec of a pinned one has no positive control;
  - that the view drops presence's data: `view_test.go` checks only that `Records` hides it.
- **Form:** the Rule API's `Unknown` test matches loosely on the field path; the exposure steps' classification is tested in four places; a misleading comment in assessor_test.go (~:2909); two computations of staleness, in the assessor and the cases, aren't shared; a doc line of about 140 characters, re-flowed in Task 3.
- **The e2e suite:** `AfterAll` deletes every `Assessment` of the libxml2 vulnerability in the cluster, where linked's case would do; a failing restore patch skips the rest of its clean-up, which the undeploy covers; the stand-in's `Sources()` reads `seen.Load()` without a nil check.
