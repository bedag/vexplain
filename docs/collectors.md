# How to write a collector

A collector is how evidence gets into vexplain. This guide explains how one works, and what you build to add your own: the API that it implements, the evidence it sends, the settings it takes, the image it ships as and the resources that install it.

The [design of collectors, evidence and rules](design/2026-10-31-collectors-evidence-rules.md) gives the reasons for each rule, and this guide links to its sections. The guide says what the contract is, and the design says why.

To start, copy the [template project](../templates/collector), a minimal collector with everything below in place: its README walks through the first hour.

> **Where this stands.** The SDK (`sdk/`), its conformance suite, the template, the `Collector` and `CollectorRuntimeConfig` resources, the deployer that reads them and the SDK's helpers for pods that a collector creates itself exist. vexplain's install ships four collectors of its own, in `config/collectors`: `workloads`, `scanner`, `vulnerabilities` and `network-reach`. The internal reach that `network-reach` reports reads only Kubernetes NetworkPolicies and Cilium's two policy kinds, so where another policy engine, such as admin network policies or another CNI's own kinds, allows more, a workload's reach may be wider than reported. Its evidence names, in `unseen`, SIG Network's admin and cluster network policies and Calico's policies when the cluster serves them. It neither reads nor names Antrea's own policies.

## What a collector is

**A collector is a gRPC server, shipped as an OCI image, that sends evidence to vexplain.**

- It implements one API, `vexplain.collector.v1alpha1`. Anyone may write a collector, in any language, and vexplain's own collectors use the same path ([0029](decisions/0029-collector-packages.md)).
- Evidence travels as [CloudEvents](https://cloudevents.io), and each collector brings its own types of it ([0032](decisions/0032-evidence-as-cloudevents.md)).
- A `Collector` resource installs the image, and installed means enabled. vexplain deploys it in its own namespace, calls it over mutual TLS and rotates its certificates.
- A collector takes care of what it needs, such as registry credentials, and says what it needs from the Kubernetes API. vexplain doesn't dictate how it works.

```mermaid
flowchart LR
  subgraph ns["The operator's namespace"]
    V["vexplain"]
    C["a collector<br/>one Deployment for each Collector,<br/>serving every role it takes"]
  end
  S["What the collector reads:<br/>the Kubernetes API, a database, a registry"]
  V -->|"GetInfo, GetCapabilities, ValidateSettings,<br/>Watch, Invoke: gRPC with mTLS on 9443"| C
  C -->|"evidence as CloudEvents"| V
  S --> C
```

vexplain calls each collector in its own cluster. The spoke opens the connection to the hub, and the hub holds no credentials for a spoke. See [design 5.2 to 5.4](design/2026-10-31-collectors-evidence-rules.md#52-collectors-and-their-packages).

## The API

| Service | Call | Does |
|---|---|---|
| Identity | `GetInfo` | The collector's name, its version, the API versions that it speaks and the versions of its own sources. It must list `v1alpha1`: vexplain uses the newest version that both sides know. |
| Identity | `GetCapabilities` | What the collector does: its roles, the types of evidence it produces with their scopes and schemas, the types it consumes, whether it watches, its operations, its schedules, the schema of its settings and the Kubernetes permissions it needs. |
| Identity | `ValidateSettings` | The problems with settings, beyond what their schema finds. None means that they are valid. |
| Evidence | `Watch` | A stream of the collector's evidence: a full snapshot, and then each change. |
| Evidence | `Invoke` | Runs one operation for one subject, and answers with events, a failure with a reason, or both. |
| Evidence | `Fire` | Runs one of the collector's schedules now, and answers within 10 seconds. |
| Health | the standard `grpc.health.v1` | `SERVING` or not. |

Every `Watch`, `Invoke` and `Fire` carries the collector's **settings** and vexplain's **context** for the cluster, so that a collector keeps no configuration state of its own. A change in either restarts the stream. The context holds:

| Field | Holds |
|---|---|
| `cluster` | The cluster's name. |
| `operator_namespace` | The namespace of vexplain's operator. |
| `own_pod_label` | The label that marks vexplain's own pods, such as its scan pods. It counts only in the operator's namespace. |
| `scope` | `OperatorConfig`'s `spec.scope`, as JSON: which pods vexplain analyses. |
| `owner_attribution` | `OperatorConfig`'s `spec.ownerAttribution`, as JSON: the labels and annotations that may be copied into evidence. |

### The stream of a Watch

```mermaid
sequenceDiagram
  participant V as vexplain
  participant C as collector
  V->>C: Watch(role, settings, context)
  C-->>V: SnapshotStart
  C-->>V: an event for each piece of evidence
  C-->>V: SnapshotEnd
  C-->>V: an event for evidence that is new or changed
  C-->>V: a tombstone for evidence that is gone
  C-->>V: SourceChanged, when a source of the collector's own changed
  Note over V,C: Every new stream starts with a new snapshot
```

- **A stream holds one snapshot.** It starts with `SnapshotStart`, sends an event for each piece of evidence that the collector has, and ends the snapshot with `SnapshotEnd` within a minute. Only a snapshot that ended is complete, so vexplain takes nothing of it before, and a stream that breaks in the middle leaves the last complete snapshot as it was.
- **Changes come after the snapshot:** an event for evidence that is new or changed, a tombstone for evidence of a type and a subject that is gone, and `SourceChanged` when a source of the collector's own changed, such as a vulnerability database. vexplain then invokes the collector's operations again, for the subjects that `SourceChanged` names, or for every subject when it names none.
- **Every new stream starts with a snapshot,** so that vexplain can reconnect at any time, as Envoy's state-of-the-world discovery and Kubernetes' list-and-watch do. A collector keeps no state per connection.
- **A `Watch` is for a role.** A collector that takes both roles gets one `Watch` for each.

### Failures

`Invoke` returns the events of its answer, or a **failure** with a reason: `Unauthorized`, `NotFound`, `TooLarge` and so on. A failure always has a reason, and a message that says more. vexplain records a failure for its subject, and never counts it against the collector's health. The reasons come from a vocabulary that vexplain defines and keeps open. It starts with the reasons of the image scans of phase 2a: `NotPullable`, `PullFailed`, `Unauthorized`, `NotFound`, `NoMatchingPlatform`, `TooLarge`, `CatalogFailed`, `TimedOut` and `Internal`. An answer to a request for evidence that holds neither evidence that the hub keeps nor a failure delivered nothing: vexplain records it as the failure `NoEvidence`.

After a failure, vexplain waits before it asks the collector about that subject again: an hour after the first failure, twice as long after each further failure in a row, a day at most, and an hour at most after `Unauthorized`, whose fix, such as a pull secret, is made where vexplain doesn't watch. Each failure records the generation of the `Collector` that its attempt ran under. A change of the `Collector`'s spec, such as its settings, raises the generation: vexplain then removes the failures of earlier generations from the subjects' facts and asks again at once, also after a restart, and the wait after the next failure starts again at an hour ([0047](decisions/0047-scanner-pull-credentials.md)). A failure of an earlier generation that comes later, such as that of a scan that was running during the change, holds no wait either. It asks each producer of a type only for its own evidence that is missing or stale, so one producer's failures never make the others work again.

A collector that can't answer for one subject says why with a failure, and keeps the gRPC error for what keeps it from answering at all.

### Limits

- A gRPC message is at most 16 MiB, both ways. vexplain compresses its calls with gzip, and a collector must accept that.
- vexplain's evidence store keeps a piece of evidence only up to its cap, compressed: `OperatorConfig`'s `spec.evidence.maxCompressedBytes`, 786432 bytes (768 KiB) by default and at most 1500000. Evidence over the cap fails as `TooLarge`, with no verdict, so bound the data of each type, and design for the default: a cluster may keep it.
- Each type documents what its `data` means, in its schema.
- **What a collector sends is bounded** ([design 5.9](design/2026-10-31-collectors-evidence-rules.md#59-trust-and-permissions)). A collector past a bound breaks the contract: vexplain ends the stream or the call, logs the collector and the bound, and counts it in `vexplain_collector_contract_breaks_total`, by the bound.

  | Bound | Is | Past it |
  |---|---|---|
  | `snapshot_time` | A snapshot ends within a minute of its `SnapshotStart`. | vexplain takes nothing of the snapshot, and opens the stream again after a pause. |
  | `snapshot_size` | The messages of a snapshot hold at most 64 MiB together. | The same. |
  | `answer_events` | An answer to `Invoke` holds at most 64 events, and fewer where the caller takes fewer: the hub takes one findings event from `match`. | vexplain reads no further, and takes none of the answer. An evidence request records the failure `Internal`. |
  | `answer_size` | The messages of an answer hold at most 128 MiB together: the scanner's answer about an image of 8 platforms holds a manifest's evidence in each of 8 messages of up to 16 MiB. | The same. |
  | `deadline` | An evidence request waits at most 103 hours for the answer: above the longest scan of the scanner, 6 hours, behind the scans of every other request that waits for one of its slots. | The request records the failure `TimedOut`. |

- **A `Watch` stays open after its snapshot,** until vexplain ends it. A stream that ends, breaks or breaks the contract opens again after a second, then after twice as long as the last time, and after a minute at most. Only a stream that stayed open for a minute past its snapshot starts the waits again from a second, so a `Watch` that returns after its snapshot is reopened ever more slowly, and never every second.

## With the Go SDK

The Go SDK, `github.com/bedag/vexplain/sdk`, is a module of its own, so that a collector doesn't import the operator's dependencies. It implements the API, and you write what the collector does:

```go
// A collector describes itself with Info and Capabilities. One that streams evidence also implements
// Watcher, one with operations Invoker, one with schedules Firer, one with sources of its own Sourcer,
// and one that checks its settings beyond their schema SettingsValidator. The template has the whole of this.
type hello struct{}

func (h *hello) Info() collector.Info { return collector.Info{Name: "hello", Version: "0.1.0"} }

func (h *hello) Capabilities() collector.Capabilities {
	return collector.Capabilities{
		Roles:    []collector.Role{collector.RoleSpoke},
		Produces: []collector.EvidenceType{{Type: eventType, Scope: collector.ScopeSpoke, Schema: []byte(helloSchema)}},
		Watches:  true,
	}
}

func (h *hello) Watch(ctx context.Context, req collector.WatchRequest, sink collector.Sink) error {
	// SnapshotStart, an Event for each piece of evidence, SnapshotEnd, and then the changes.
}

func main() {
	// Serve runs until ctx ends, which the template's main ties to SIGTERM.
	err := collector.Serve(ctx, &hello{}, collector.OptionsFromEnv())
}
```

`Serve` runs two servers: the collector API and the standard health service over mutual TLS on port 9443, and `/healthz`, `/readyz` and `/metrics` in plain HTTP on port 8081. It holds the collector to the contract, so that vexplain never gets what breaks it:

- It refuses to start a collector whose capabilities contradict themselves, that doesn't implement what they say, or whose settings schema or operation parameter schema doesn't compile. A collector with schedules must implement `Firer`, and one that implements `Firer` must declare schedules.
- It checks settings against their schema, and with `ValidateSettings`, before a `Watch`, an `Invoke` or a `Fire` runs, and an operation's parameters against the operation's schema.
- It answers `Fire` for a schedule that the collector didn't declare with `InvalidArgument`, and never calls the `Firer` for it.
- It holds a stream to its order, and checks that each event is valid evidence of a type that the capabilities list. A call that breaks the contract ends with an error, and the SDK tells the collector why.
- It ends the calls that a stop cut short with `Unavailable`, so that an answer that was cut short never looks complete.

The SDK does **not** check an event's data against its type's schema. The conformance suite does (below).

The deployer sets the environment that `OptionsFromEnv` reads, and its defaults are what the deployer sets:

| Variable | Is | Default |
|---|---|---|
| `VEXPLAIN_LISTEN` | where the collector API is served | `:9443` |
| `VEXPLAIN_HEALTH_LISTEN` | where `/healthz`, `/readyz` and `/metrics` are served | `:8081` |
| `VEXPLAIN_TLS_DIR` | where `tls.crt`, `tls.key` and `ca.crt` are | `/run/vexplain/tls` |

`/readyz` answers 503 until the TLS files load, and the SDK loads them again within 30 seconds of a change, so that a renewed certificate is served well before the old one expires. The deployer also sets `VEXPLAIN_COLLECTOR_NAME` and `POD_NAMESPACE`, for the collector's own use. Metrics of a collector's own go in the registry that it passes in `Options.Registry`; they start with `vexplain_` and carry the label `cluster`. The scanner's, for instance, are `vexplain_scanner_scans_total` and the histogram `vexplain_scanner_scan_duration_seconds`, by `cluster` and `result`: `Succeeded`, the reason of a failure, or `Error`.

## Evidence types and scopes

**A type** is the CloudEvents `type` of a kind of evidence, named in reverse-DNS by whoever defines it, with a version: `com.example.hello.v1alpha1`. The pattern is `^[a-z0-9-]+(\.[a-z0-9-]+)+\.v[0-9]+((alpha|beta)[0-9]+)?$`, which the SDK exports as `evidence.TypePattern`, with `evidence.ValidType` to check a name against it. A change that breaks the shape of the data needs a new version.

- **Each type has a JSON Schema** for its `data`, which the collector returns from `GetCapabilities`. The data is JSON, and the event's `datacontenttype` is `application/json`. Say in the schema what each field means, and what the `coverage` of the evidence counts: the people who write rules look it up there.
- **Each type has a scope,** as a CRD does:
  - `Hub` evidence goes to the hub, which collects it across clusters. Its subjects must be unique across clusters: an image digest is, and a virtual machine's subject includes its cluster.
  - `Hub` evidence that a collector streams reaches the hub's store too ([0058](decisions/0058-streamed-evidence-on-the-hub.md)). The spoke stores each event of a snapshot as a record keyed with its cluster, so that each cluster keeps its own, and deletes the collector's records of the type in its cluster that the snapshot doesn't hold. A change is stored, and a tombstone deletes its record. When the `Collector` goes, the spoke deletes its records in its cluster. An event that the store refuses, such as one over its cap, is dropped, and counted in `vexplain_evidence_streamed_refused_total`, by `cluster`, `collector`, `type` and `reason`, and so is presence or exposure whose data doesn't follow the core's schema, with the reason `Invalid`, as the spoke's own consumers drop it. The record of its subject is deleted, so that the hub never reads an older event as current: the hub lacks the record until the collector sends it again, in a change or a snapshot, and it fits. A streamed record carries the label `vexplain.bedag.ch/cluster`, and a renamed cluster leaves the records of its old name, which `kubectl delete evidences -l vexplain.bedag.ch/cluster=<old name>` deletes.
  - `Spoke` evidence stays in its cluster. A collector whose spoke evidence matters at the hub also produces a `Hub` type that summarises it.
- **A type can have a `maxAge`,** `EvidenceType.MaxAge` in the SDK (`max_age_seconds` in the API): how long evidence of the type stays current, from a minute to 30 days in whole seconds, or 0 for no limit ([0045](decisions/0045-evidence-max-age.md)). Evidence that is older is missing for the rules, and vexplain asks the collector for it again. The status records it, and an admin overrides it with `spec.produces` on the `Collector`. A `maxAge` applies to the evidence that operations return: vexplain can't ask a stream again, and stores a streamed record only when it changes, so a type that only a stream delivers, such as presence or exposure, declares none, and the `Collector` refuses an override of it as `ProducesInvalid`.
- **The SDK defines five core types,** with their schemas (`evidence.Schema`) and Go types, and a collector that produces one sends its data in that shape. The core reads four of them, and no other type:

  | Type | Subject | Scope | The core reads it for |
  |---|---|---|---|
  | `ch.bedag.vexplain.presence.v1alpha1` | an image | Hub | What runs where: the container playbook's subjects, scans and reports |
  | `ch.bedag.vexplain.findings.v1alpha1` | a platform manifest, or a collector's own subject | Hub | The findings that playbooks assess: a CVE in a package, with its version, fix and exploitation |
  | `ch.bedag.vexplain.exposure.v1alpha1` | a workload | Hub | Urgency |
  | `ch.bedag.vexplain.sbom.v1alpha1` | a platform manifest | Hub | Nothing itself: it is the package inventory that any producer can write and any consumer can read, below |
  | `ch.bedag.vexplain.vulnerabilities.description.v1alpha1` | a vulnerability, `vulnerability/<ID>` | Hub | The agent's verdicts: "fixed" and "not affected" rest on its `fixedForInstalled` (`describe`, below) |

- **Presence also reaches the hub as namespaces.** From the workloads of presence, the spoke writes into the image's inventory entry of its cluster each namespace that runs the image: its name, the values of the labels and annotations that `ownerAttribution` allows, and the workloads in it by exposure (`open`, `controlled`, `small`, `unknown`). The entry names the first `spec.presence.maxNamespaces` namespaces by name (100 by default, at most 1000) and fewer when it would pass 256 KiB; `namespaceCount` counts them all. Workload labels don't go there.
- **Everything else is the collector's own type.** The core passes it on without reading it. Rules and playbooks that name the type read it, and the agent reaches it through its tools.
- **Playbooks name types, not collectors** ([0043](decisions/0043-playbook-matching.md)). Every `Collector` that produces a type counts for a playbook that names it, unless the playbook's entry pins its producers by `Collector` name, so a collector that produces a type joins the playbooks that read it without a change of theirs. vexplain asks it for its evidence of each subject through an operation that produces the type. The evidence of each producer is evaluated apart, and the most cautious outcome wins: your evidence can hold a finding open, but never settle it against another producer's. A playbook names each type of evidence once. A collector that produces findings takes part in a playbook only when its `match` consumes a type of the playbook's evidence, and a playbook that no findings producer takes part in isn't `Ready`. Its match takes the piece of each type that it consumes, from every producer of it, and needs all of them, so what it consumes is required even where the playbook says `Optional`.

An event is built with `evidence.New(type, subject, data, options...)`: it sets the identifier, the time, the data's content type and the dataschema `urn:vexplain:schema:<type>`. The options set the source, which names the collector and its cluster or the hub (`/clusters/cluster-a/collectors/hello`), the time, the coverage and the platform. `evidence.Validate` is what the SDK and the conformance suite check an event with.

See [design 5.5](design/2026-10-31-collectors-evidence-rules.md#55-evidence-0032).

### The sbom type

`ch.bedag.vexplain.sbom.v1alpha1` is a subject's package inventory, with the producer's SBOM document when it has one ([0044](decisions/0044-sbom-type.md)). The `scanner` produces it for each platform manifest of an image, beside its own `image-contents`, and the `vulnerabilities` collector consumes it. Any other producer, such as a scanner of virtual machines' disks, or SBOMs attached to images in a registry, can feed the same consumers. `evidence.SBOM` is its Go type.

- **An event of it is about a manifest,** with `platform`, and its scope is `Hub`. Its `coverage` is the producer's: the scanner's is the share of the image's ELF files that packages own, where the hard links of one file are one file, as for its `image-contents`, whether or not one of Syft's catalogers failed.
- **Its data:**
  - `distro`: the distribution, in the words of os-release: `id`, and, where it has them, `version` (`VERSION_ID`), `codename` (`VERSION_CODENAME`) and `idLike` (`ID_LIKE`). A matcher picks the distribution's advisories by them: a derivative whose ID it doesn't know is the distribution that `idLike` names, and a release without a version, such as Debian's testing, is its codename. Leave it out when you found no distribution.
  - `packages`: each package with its `id`, `name`, `version`, `type`, `purl` and `cpes`, and an RPM's `modularityLabel`. `[]` when the subject has none, never `null`.
  - `producer`: its `name` and `version`, such as Syft at its version.
  - `failedCatalogers`: the catalogers of the producer that failed, whose packages the inventory may lack. The scanner names each cataloger that Syft reports as failed on a file where it found no package, such as `java-archive-cataloger` on an archive that it can't read, and leaves the coverage as it is. The completeness guard holds only the findings of the package types that the failed cataloger catalogs, which `catalogerFailures` lists. A cataloger's note that it found nothing to identify in a file, such as an empty dpkg status file or an archive that names no package, is no failure.
  - `catalogerFailures`: the same catalogers, each as `{cataloger, packageTypes}`, with the package types that it catalogs, as a package's `type` names them. A failure without `packageTypes` has types that the producer doesn't know, and the guard holds every finding for it, as it does for a producer that writes `failedCatalogers` alone. The scanner knows the types of the image catalogers of the Syft version that it pins, except for three that it leaves out on purpose, `binary-classifier-cataloger`, `graalvm-native-image-cataloger` and `php-interpreter-cataloger`, whose types it can't give: a failure of one of them holds every finding, and so does every failure in an SBOM that another version of Syft produced.
  - `document`: the producer's SBOM document. Its `format` is `syft-json`, `cyclonedx-json` or `spdx-json`, Syft's names of formats that Grype reads, and its `content` is the document itself, a JSON object. The scanner sends Syft's JSON without its file lists, as phase 2b did, and makes `packages` of the same document.
- **Each package has an ID of its own.** A match names its package by the ID, and rules join a finding to the package's other evidence by it, so an SBOM whose packages share an ID is no input to match.
- **Send your SBOM document when you have one.** `vulnerabilities` hands it to Grype as it is, so Grype matches all that the document holds, also what a later Grype reads more of. Keep `packages` beside it, each with the ID that the document gives it as Syft reads it: an artifact's `id` in Syft's JSON, a component's `bom-ref` in CycloneDX, and a package's `SPDXID` in SPDX, without its `SPDXRef-` prefix. A match names its package by that ID, and rules join a finding to the package by it. The rest of this list is what `vulnerabilities` reads when you send no document.
- **The type is Syft's,** such as `deb`, `rpm`, `apk`, `go-module` or `java-archive`, because the `vulnerabilities` collector hands the packages to Grype.
- **A package's purl names its source package and its distribution,** as Syft writes them, in the qualifiers `upstream` and `distro`, such as `pkg:deb/debian/libssl3@3.0.17-1~deb12u2?arch=amd64&distro=debian-12&upstream=openssl`. Debian, RPM-based and Alpine distributions track many vulnerabilities by the source package, such as `openssl` for `libssl3`, so a purl without `upstream` means missed vulnerabilities, which no coverage shows. Write `upstream` as Syft does:
  - a Debian package: the source package, and its version after `@` when the package's version differs from it;
  - an RPM: the file name of its source RPM, as the rpm database's `SOURCERPM` holds it: `<name>-<version>-<release>.src.rpm`, such as `openssl-3.0.7-27.el9.src.rpm`. Grype reads the source package's name and version from that form alone: a bare name gives no source package, and the vulnerabilities tracked by it are missed;
  - an Alpine package: its origin, when the origin is another package.

  A producer that has none of this writes the purl without the qualifier. Rewrite nothing that Syft wrote: `vulnerabilities` reads `upstream` as Grype reads the same values in Syft's own JSON, as below. For a Debian or an Alpine package, that keeps a source package of the package's own name, which Grype's purl input drops.
- **An RPM's `modularityLabel` names its module stream,** as Syft reads it from the rpm database, such as `nodejs:20:8090020240101000000:a1b2c3d4`: `""` for an RPM of no module stream, and absent when you don't know, as Syft doesn't for an rpm file. No purl that Syft writes carries it. RPM-based distributions publish advisories per module stream, and a matcher applies those of every stream to an RPM without a label: on AlmaLinux, Grype drops a vulnerability that AlmaLinux says a release fixed, so one stream's fix would hide the vulnerability of another.

**How `vulnerabilities` reads it.** With a document, it hands Grype the document as it is, as phase 2b did with Syft's JSON: the matches are then the document's by construction, and stay so when a later Grype reads more of it. A document that Grype can't read fails the match, and the packages are no fallback for it: a document built from them would drop, without saying so, what only the producer's document holds.

Without a document, it hands Grype a document of Syft's JSON that it makes of the data: each package under its ID, with its name, version, type, purl and CPEs, and the source package of an OS package from the purl's `upstream`, where Grype reads it from a Syft document: a Debian package's `source` and `sourceVersion`, an RPM's `sourceRpm`, and an Alpine package's `originPackage`, which is the package itself when the purl names none. An RPM's metadata has its `modularityLabel` too. The distribution is the data's `distro`. For the fixtures, Grype then reads the same packages as from Syft's own JSON, and gives the same matches: the collector's tests hold its document to Syft's JSON of fixtures with a source package of each kind and an RPM of a module stream, through Grype's own package provider. A few rare inputs still match less than from Syft's full document, which [0044](decisions/0044-sbom-type.md) lists: a producer that sends its document avoids them. What else Syft's JSON has, Grype reads only to drop matches, such as those of a package whose files an OS package owns, or those of a Go program's own module, or the document has it already, as an RPM's version has its epoch: without it, Grype finds no fewer vulnerabilities.

### The exposure type

`ch.bedag.vexplain.exposure.v1alpha1` is how far a workload can be reached ([0006](decisions/0006-exposure-collectors.md), [0048](decisions/0048-network-reach-on-family-collectors.md)). `network-reach` produces it, and the spoke turns it into SSVC's system exposure and the report's `reach`. Reach changes a finding's urgency, never its verdict. `evidence.Exposure` is its Go type.

- **An event of it is about a workload,** and its scope is `Hub`: the spoke stores each workload's exposure on the hub, which asks the sources whether they publish its entry points ([design 5.1](design/2026-11-20-entry-points.md#51-entry-points-in-exposure)). The spoke reads it too, for its reports.
- **Its data:**
  - `external.exposed`: whether something outside the cluster reaches the workload.
  - `external.entryPoints`: the ways in from outside, at most 32, sorted by `objectRef`, `port` and `addresses`. Each has `addresses` (host names or IP addresses, 1 to 256, sorted), a `port` and `protocol` (`TCP`, `UDP` or `SCTP`) where the way in has a port, the `objectRef` that opens it, a `parentRef` for a route's Gateway, and `subjects`, one for each address, in the same order. `evidence.EntryPointSubjects` computes the subjects: an IP address gives `address/<ip>[:<port>]`, a host name gives `host/<name>` without a port, since sources look hosts up by name, and an address that is neither is refused, which a collector reports as `NotASubject`.
  - `external.unchecked`: why a way in can't be asked about, sorted, at most 8: `HostNetwork`, a pod on its node's network; `NoAddress`, a way in without an address that the collector can name yet, as a load balancer's status without one; `NotASubject`, an address that the entry point leaves out; and `TooManyAddresses` and `TooManyEntryPoints`, where the first 256 addresses or 32 entry points, sorted, were kept. An exposed workload has at least one entry point or one reason. Both lists are always there, `[]` when empty, so that an exposure rule can read them.
  - `internalReach`: how far the rest of the cluster reaches it: `Namespace`, `Peers`, `Namespaces` or `Cluster`.
  - `indirect`: whether a workload that is exposed reaches it, one hop away.
  - `widenedBy`: what set the internal reach when it goes beyond the workload's namespace, at most 8. Each names an object by `kind`, `namespace` and `name`, the index of its ingress `rule` where one rule did, which for a Cilium policy runs across the ingress rules of its `spec` and then of each of its `specs`, and a `reason`, such as a NetworkPolicy's rule that lets in every pod of every namespace, or the Namespace for `no policy in the namespace`.
  - `unseen`: what the collector couldn't evaluate, sorted: `AdminNetworkPolicy`, where the cluster serves SIG Network's AdminNetworkPolicy or ClusterNetworkPolicy, and `CalicoNetworkPolicy`, where it serves Calico's policies, in `crd.projectcalico.org` or `projectcalico.org`: kinds of policy whose rules can let in what the network policies deny; `IPBlock`, a policy's peer that can hold any address; and `UnknownParentRef`, a route's parent of a kind that the collector doesn't read. `network-reach` finds those kinds through the API discovery, and needs no right to read them.
  - Antrea's own policies, `ClusterNetworkPolicy` and `NetworkPolicy` in `crd.antrea.io`, can let in what the network policies deny too. `network-reach` doesn't read them, and `unseen` doesn't name them.
- **What a collector can't evaluate never narrows reach.** It counts as letting anything in, or as facing outside, or it changes nothing, and `unseen` says that the workload may be reached further than the evidence says.

### The presence type's workloads

Each workload of `ch.bedag.vexplain.presence.v1alpha1` carries its `subject`, its workload subject with the cluster, such as `workload/cluster-a/team-a/Deployment.apps/web`. Presence and exposure join on it: presence links an image to the workloads that run it, and exposure is about each of them.

### Sources

A **source** is a collector whose operation takes entry points and answers about them. The SDK's `EntryPointParameters` are its parameters, and `EntryPointParameterSchema` their JSON Schema:

- `hosts`: host names, a leading `*.` allowed;
- `addresses`: IP addresses, each with or without a port, such as `192.0.2.10`, `192.0.2.10:443` or `[2001:db8::1]:443`;
- 1 to 64 points in the two lists together (`collector.MaxPointsPerCall`). The schema limits each list to 64, since JSON Schema can't limit two together, so the caller sends at most 64 in all.

The operation consumes nothing, which is how the hub knows that it answers about entry points.

- **It answers each distinct point with one event.** The subject is the point in normal form, with the port when the point had one. The time is when the source answered, as `evidence.New` sets it. "Not published" is an answer, not a failure.
- **It fails a whole call** with `InvalidInput` (`collector.ReasonInvalidInput`) when it can't read a point, and with `NotReady` (`collector.ReasonNotReady`) while its own data is stale or being rebuilt. The messages carry no values.
- **Its source version,** which `GetInfo` reports, changes when its data does.
- **It reads a point widely, so that it never answers too narrowly.** A wrong answer that is too narrow gives a wrong `Controlled` that vexplain can't notice:
  - an address is published when the source forwards traffic to it, as to an ingress controller's load balancer, not only when it is a front-end address of the source's own;
  - a host is published when any of the source's entries matches it, its wildcards included;
  - a wildcard point is published when any entry overlaps it;
  - an address without a port stands for every port.
- **It produces a type of its own,** of the scope `Hub`, such as the example type `ch.example.dmz.publication.v1alpha1`, whose data holds `publishedTo`: `Internet`, `Internal` or `None`.
- **Its type has a `maxAge`,** which the source declares, or its admin sets in the `Collector`'s `spec.produces`. An answer past it is missing for the rules. Without one, an answer never expires.
- **It ships two exposure rules for its type,** as manifests that its admin applies ([how](../README.md#how-exposed-a-workload-is)). In an exposure rule, an input of a type that a source produces is a map from each entry-point subject of the workload's exposure to the source's answer about it, each with the keys of any input: `data`, `time`, `source` and, where it has one, `coverage`. The input is missing while the workload's exposure isn't on the hub, or an entry point lacks an answer within its `maxAge`, and is an empty map for a workload without entry points. An input takes the playbook's evidence of its name and type. These are the rules of the end-to-end tests' stand-in source, which read its type as `dmz`:

  ```yaml
  apiVersion: config.vexplain.bedag.ch/v1alpha1
  kind: Rule
  metadata:
    name: published-or-unchecked
  spec:
    inputs:
    - {name: exposure, type: ch.bedag.vexplain.exposure.v1alpha1}
    - {name: dmz, type: ch.example.dmz.publication.v1alpha1}
    # Open unless every way in was asked about, and none is published to the internet.
    condition: |
      exposure.data.external.exposed && !(size(exposure.data.external.unchecked) == 0 &&
        size(exposure.data.external.entryPoints) > 0 &&
        exposure.data.external.entryPoints.all(e, e.subjects.all(s,
          dmz[s].data.publishedTo in ['Internal', 'None'])))
    outcome: {exposure: Open}
  ---
  apiVersion: config.vexplain.bedag.ch/v1alpha1
  kind: Rule
  metadata:
    name: exposed-not-published
  spec:
    inputs:
    - {name: exposure, type: ch.bedag.vexplain.exposure.v1alpha1}
    - {name: dmz, type: ch.example.dmz.publication.v1alpha1}
    condition: |
      exposure.data.external.exposed && size(exposure.data.external.unchecked) == 0 &&
        size(exposure.data.external.entryPoints) > 0 &&
        exposure.data.external.entryPoints.all(e, e.subjects.all(s,
          dmz[s].data.publishedTo in ['Internal', 'None']))
    outcome: {exposure: Controlled}
  ```

  - **`published-or-unchecked` errs towards `Open`:** an answer that it doesn't know counts as published, and so does a workload exposed without any entry point, or with a way in that can't be asked about.
  - **For an exposed workload, the two are each other's opposite,** so once every entry point is answered, exactly one of them applies. While an answer is missing, both count as `Unknown`.

**How the hub asks a source** ([design 5.5](design/2026-11-20-entry-points.md#55-sources)):

- **Which sources.** A `Collector` is asked as a source of a type while a `Ready` playbook takes the type as evidence, without pinning other `Collector`s for it, and while the collector can be used and has a version. Its operation is the first one in the hub role that consumes nothing, produces the type, and takes `hosts`, `addresses` or both.
- **About what.** Every entry point that a cluster's exposure names, and nothing else: no workload, namespace or manifest. A source is asked about hosts only when its operation takes `hosts`, and about addresses only when it takes `addresses`.
- **In calls of at most 64 points,** hosts and addresses together, in the order of their subjects. A call's subject is its first point's, and the points are in its parameters, with the hub's context and the `Collector`'s settings.
- **A refused call is split in halves.** A call that the source fails with `InvalidInput`, or whose parameters the operation's schema refuses, is asked again in two halves, and so on down to single points, so that every point that the source can read gets its answer. A point that the source refuses on its own stays unanswered, and is asked again after a minute, then after longer waits, as below, or when the source's version changes.
- **When.** About a new entry point; about every entry point after the operator starts, since the hub keeps no source version with an answer; about every entry point at once when the collector's version, or a source version in the `Collector`'s status, changes; and about an entry point whose answer reaches half its `maxAge`. The hub looks at the `Collector`s, the playbooks and the entry points every 5 seconds, and at once when a workload's exposure or an answer changes. A change of presence alone, which comes with every pod that starts or stops, doesn't make it look.
- **Failures.** A call that fails for another reason, such as `NotReady`, or that gets no answer, stops the hub asking the source: it asks again after a minute, then after 2, 4 and 8 minutes, and then every 15 minutes, until a call succeeds. The hub keeps the source's last reason and message, and logs them.
- **The answers.** Each event of an answer must be of the type that the hub asked for, and about a point of the call. The first about each point counts. The others are dropped, and counted. An answer is stored as evidence about its point, from the `Collector`, without a cluster, since the clusters share it. An equal answer writes nothing, unless the stored one is older than half its `maxAge`: it then gets the new answer's time, which keeps it current. An answer about an entry point that no cluster names any more is deleted.
- **Metrics:**
  - `vexplain_source_calls_total{cluster, collector, result}`, where `result` is `Succeeded`, `InvalidInput`, `NotReady`, `Failed` for another reason of the source, or `Error` for a call that got no answer;
  - `vexplain_source_answers_unasked_total{cluster, collector}`, the events that the hub dropped;
  - `vexplain_entry_points{cluster, state}`, the entry points that the exposure of each cluster names, where `cluster` is the cluster that names them: `answered` when every source asked about the entry point has answered it within its `maxAge`, `unanswered` otherwise, as when no source takes its kind, and `unchecked`, the reasons of `external.unchecked`, one for each workload that gives one;
  - `vexplain_exposure_view_read_failures_total{cluster}`, the reads of the hub's view of presence, exposure and answers that failed, such as one of a record that can't be decoded, and the records that the view read and left out because they aren't what their type says: presence or exposure whose data doesn't decode, and presence's workloads, or exposure, of another cluster than the one that streamed the record, which the view drops. The view logs each by its key, never its data. Until a read of the subject succeeds, its records are missing from the view, so its workloads count as Unknown, and the hub doesn't wait for them.

## Subjects

A **subject** says what a piece of evidence is about. It is a path with a prefix, and the prefix is its kind. The package `sdk/subject` builds and parses them.

| Subject | About | Built with |
|---|---|---|
| `image/sha256:<64 hex>` | a reported image digest, which can be an index | `subject.Image` |
| `manifest/sha256:<64 hex>` | the manifest of one platform of an image | `subject.Manifest` |
| `workload/<cluster>/<namespace>/<Kind>[.<group>]/<name>` | a workload, such as `workload/cluster-a/team-a/Deployment.apps/web` or `workload/cluster-a/team-a/Pod/web-0` | `subject.ForWorkload` |
| `host/<name>` | a host name in lowercase, with no trailing dot, such as `host/shop.app.example` or `host/*.app.example` | `subject.Host` |
| `address/<ip>[:<port>]` | an IP address, with its port when it has one, such as `address/192.0.2.10:30443`; an IPv6 address is in brackets only when a port follows, as in `address/[2001:db8::1]:443` against `address/2001:db8::1` | `subject.Address` |

- **A host or an address carries no cluster,** and repeats across clusters on purpose: the same name or address reaches workloads of several clusters. Both kinds parse only in normal form, so that subjects compare by their text.
- **A collector may add prefixes of its own,** such as `vm/<cluster>/<name>`. The core passes them on without interpreting them. Evidence of a `Hub` type needs subjects that are unique across clusters.
- **An event about a manifest carries `platform`** (below), so that the platforms of a digest can be listed without knowing the type. `evidence.Validate` refuses one without.
- A subject that doesn't parse makes the event invalid: a `Watch` that sends it ends with an error.

## Coverage and platform

Evidence can carry two **extension attributes**, besides the attributes that CloudEvents defines:

- **`coverage`** is a whole number from 0 to 100: how much of the subject the evidence covers. Each type documents what it counts. The scanner's, for example, is the share of an image's ELF files that packages own. The data says what the collector couldn't examine.
- **`platform`** is `os/arch` or `os/arch/variant`, such as `linux/amd64`: the platform that the evidence is about.

**vexplain shows and records coverage, and never interprets it.** How much is enough is the call of the rule that reads the evidence, and a rule settles a finding only when every input it names is present. So missing evidence never settles anything, and a collector never needs to hide what it couldn't see: it states it. Set the coverage with `evidence.WithCoverage` and the platform with `evidence.WithPlatform`.

## Settings

**Settings are the collector's own.** An admin writes them in `spec.settings` of the `Collector`, as an object of any shape. vexplain can't know a third party's settings, so it checks them against the schema that the collector returns from `GetCapabilities`, and with `ValidateSettings`, and reports `SettingsInvalid` when they fail. There is no admission webhook.

- **The schema stands alone.** It refers to nothing outside itself: vexplain compiles it from the capabilities, without the collector's files. A collector whose schema doesn't compile is `PackageInvalid`.
- **Without settings, the collector gets an empty object `{}`,** and a schema decides whether it needs any.
- **`ValidateSettings` is for what a schema can't check,** such as a combination of fields. It only sees settings that passed the schema. Return the problems as text, and none for valid settings.
- **Settings carry no secret values.** A `Collector`'s spec is readable by everyone who can read collectors. Credentials live in Secrets that the collector reads itself, with the permissions that it declares. Because of that, an error about settings can repeat a value: a schema error says what broke the schema, such as `at '/repeat': minimum: got 0, want 1`, and a `ValidateSettings` problem is the collector's own text. If a setting were a secret, its value would end up in `status` and in events.
- **A change in the settings restarts the stream.**

A collector that reads Secrets, such as registry pull secrets, reads them with `get` only, and keeps their values out of its logs, errors, metrics and evidence.

The scanner, for one, pulls an image with the logins of the pull secrets of a pod that runs it and of its service account (`CopyFromWorkload`), then with those of the Secrets of the type `kubernetes.io/dockerconfigjson` that its setting `adminPullSecrets` names in vexplain's namespace, at most 16 (`AdminProvided`, [0047](decisions/0047-scanner-pull-credentials.md)). It tries them in that order until the registry takes one, and only those for the registry that it pulls from, or for its mirror. When the registry takes none, the failure `Unauthorized` names, within the 256 characters that vexplain keeps of a message, the registry, then the Secrets of `adminPullSecrets` that don't exist or hold no login for the registry, such as one of another type, then the Secrets whose logins it tried, as many as fit, with a count of the rest. It names them, and never shows their content, such as `registry artifacts.example: no credentials worked; adminPullSecrets not found: registry-a; tried: team-a/regcred`.

`network-reach` counts everything that can face outside as external, unless its settings say otherwise ([design 6.4](design/2026-10-29-vexplain-design.md#64-exposure), [0048](decisions/0048-network-reach-on-family-collectors.md)):

- `ingressClasses`, `gateways` and `internalLoadBalancerAnnotations` name what counts of Ingresses, of the Gateway API's routes, and of load balancers.
- `nodePorts`, `hostPorts` and `hostNetwork` are each `External`, the default, or `Internal`, and each covers one way to be reached on a node's address: the node ports of Services, the host ports of pods, and the pods on their node's network. A pod on its node's network is reached from the whole cluster whatever `hostNetwork` says, since no policy of a pod applies to it.
- `trustedPeers` names the peers that the admin trusts, such as an ingress controller or monitoring, at most 32, empty by default. A peer of a policy's rule that an entry matches doesn't widen a workload's internal reach, so a workload that only its namespace and trusted peers, such as monitoring, reach is `Small`, unless an exposed workload reaches it. An entry sets at least one of `namespaceSelector`, `podSelector` and `serviceAccount` (`namespace` and `name`), and matches a peer when each field that it sets matches every pod that the peer can let in. A peer's selector must ask for what `podSelector` asks for, and a Cilium policy's for the service account. The selectors are Kubernetes label selectors, and an empty one matches everything: an entry of an empty `namespaceSelector` alone trusts every pod of the cluster.
- **Pair a `podSelector` with a `namespaceSelector`.** An entry's `podSelector` alone trusts pods of those labels in every namespace, where a `podSelector` alone in a NetworkPolicy's peer selects pods of the policy's own namespace. With it alone, a policy that lets in pods of those labels from other namespaces widens no reach, also for a pod that anyone labels so in a namespace of their own. With the `namespaceSelector` of the monitoring namespace beside it, only the pods there are trusted.
- **Trust only keeps a rule from widening reach,** and narrows no reach that something else sets. A workload that no policy selects, one on its node's network, and a rule that the collector can't read keep their reach, and a trusted workload that is exposed, such as an ingress controller, still makes the workloads that it reaches indirectly exposed.

What counts, as the settings say, gives a workload its entry points ([design 5.1](design/2026-11-20-entry-points.md#51-entry-points-in-exposure)). A way in that the settings call internal gives none:

- **A LoadBalancer Service:** one entry point for each port of the Service, on the IPs and hostnames of its status. Without them yet, `NoAddress`.
- **A Service's external IPs:** one entry point for each port of the Service, on all of them. A Service without a port, as a headless one may be, gives `NoAddress`.
- **A node port,** of a NodePort or a LoadBalancer Service: the InternalIP and ExternalIP addresses of every node, with the node port. A node that joins or leaves changes the entry point of every node port. While a node has neither address, such as one that its cloud controller hasn't initialised yet, every node port adds `NoAddress`.
- **An Ingress rule with a host:** the host, on 443 when an entry of the Ingress's `tls` names it, a wildcard that stands for its first label included, and on 80 otherwise.
- **An Ingress rule without a host, and a default backend:** the IPs and hostnames of the Ingress's status, without a port. Without them yet, `NoAddress`.
- **An HTTPRoute, GRPCRoute or TLSRoute:** for each listener that it attaches to, its `hostnames`, or without any the listener's `hostname`, or without that the addresses of the Gateway's status, each on the listener's port, with the Gateway as `parentRef`. `HTTP`, `HTTPS`, `TLS` and `TCP` listeners give `TCP`, and `UDP` listeners `UDP`. A `NamedAddress` of the Gateway is `NotASubject`. A route whose parent is of a kind that the collector doesn't read is reached on its hostnames, without a port, and without hostnames it is `NoAddress`.
- **A host port:** the workload's own object, with the host port, on the InternalIP and ExternalIP addresses of the nodes that its pods run on. A pod that no node runs yet is `NoAddress`.
- **A pod on its node's network:** no entry point, since it may listen on any port: `HostNetwork`.

## Operations

An **operation** is work that a collector does on demand, for one subject, through `Invoke`. The `vulnerabilities` collector's `match`, which finds the vulnerabilities in an image's contents, is one.

- **Each operation declares** its name, its description, its role, the types it produces, the types it consumes and the JSON Schema of its parameters. The SDK checks the parameters against the schema, and an operation without one takes any JSON. The agent sees each operation as a tool, named after the `Collector` and the operation, with the parameter schema as the tool's input schema ([0031](decisions/0031-tools-from-collectors.md)). A collector's author gets agent support without extra work.
- **An operation consumes evidence.** When it consumes a type, vexplain gets that type first and passes the events as `Inputs`: the `vulnerabilities` collector consumes the SBOM of a manifest, which the scanner delivers with the manifest's image contents. Each input is valid evidence of a type that the operation consumes.
- **It answers with events of the types it produces, a failure, or both.** An empty answer is allowed: it says nothing about the subject, and to a request for evidence it counts as the failure `NoEvidence`, after which vexplain waits before it asks again.
- **An operation runs in a role** that the collector takes.

vexplain invokes operations for each subject of a playbook, when a collector signals a change in a source of its own, and when the agent calls a tool. See [design 5.6](design/2026-10-31-collectors-evidence-rules.md#56-evidence-on-demand).

### `describe`: what the vulnerability database holds

The `vulnerabilities` collector's second operation, `describe`, is the agent's ([design 5.8](design/2026-11-16-agent-on-cases.md#58-advisories-0054)). It runs in the hub's role, consumes nothing, and answers with one event of `ch.bedag.vexplain.vulnerabilities.description.v1alpha1` about `vulnerability/<ID>`, whatever subject it runs for. Its parameters are a `vulnerabilityID`, at most 8 `aliases` (other IDs of the same vulnerability, searched with the ID in the same search), and at most 16 `packages`, each `{name, version, type, purl, distro}` as the SBOM has them.

- **It runs Grype's own searches of its database,** `grype db search vuln` and `grype db search --vuln`, offline and without Grype's limit of 5000 rows. Without a database it fails with `NotReady`, and an ID that the database doesn't hold fails with `NotFound`, never as an empty answer. When a record names an alias, such as the CVE of a GitHub advisory, it searches again with the aliases, one level deep. A language package's advisory is often listed under the ecosystem's own ID only, such as a GHSA or GO ID, so the agent's safety core adds the case's other IDs to `aliases`. Go's standard library is accepted as Syft writes it: version `go1.27.1` with the purl `pkg:golang/stdlib@1.27.1`. A `pkg:generic` purl, as Syft writes for a binary it recognizes, names no type: its name and version must be the package's, the asked type is kept, and it speaks for no distribution or ecosystem.
- **The answer** holds the description, the CVSS vectors, known exploitation, EPSS in per mille, the references, and for each provider, vulnerability ID, namespace and listed package (such as `debian`, `CVE-2026-0001`, `debian:distro:debian:12`, `brotli`) its fix state and fixed versions. The vulnerability ID is that of the records an entry rests on: the ID asked about, or an alias that the search found. A provider's records of one vulnerability say nothing of another's fix, so a provider that lists the package under two IDs answers under each. `providers` lists only the entries that answer for an asked package, and for each asked package that none answers for, at most 8 that name it, such as a binary's CPE entries in NVD. `otherProviders` counts the rest per provider, and an entry that is left out says `Unknown` for every asked package, so no `Yes` or `No` is hidden. With no package asked, every entry is counted and none listed. The description is the first that a listed entry's provider gives, and the references are those of the asked ID's records and of the listed entries' providers.
- **`fixedForInstalled` is `Yes`, `No` or `Unknown`** for each asked package in each entry. The validator of the agent's verdicts lets "fixed" and "not affected" rest on a `Yes` without comparing versions itself, so `describe` says `Yes` only when Grype's own reading leaves no doubt:
  - the namespace speaks for the package: the package's distribution and release, from the purl or `distro`, for an OS package, or its language, for a package of an ecosystem. NVD's CPEs speak for none;
  - the package is read as Grype reads its purl: under its own name and its source packages', from the qualifier `upstream`, each with its version. A `distro` that contradicts the purl's, or a purl of another package, is refused with `InvalidInput`;
  - every row of the provider under the entry's vulnerability ID that names the package, in every namespace of the provider that speaks for it (such as SLES 15 and its service pack 15.5, or Red Hat's release and its extended update streams, which share a namespace), is compared in the scheme of the row's type with Grype's own version comparison, ignoring the rows' qualifiers, which only narrow where a row applies. A missing epoch is 0, as dpkg reads it, except in an RPM, where it takes the other side's, as Grype's RPM matcher does by default. A range without a constraint holds every version when it names no fix, such as one that won't be fixed, or when no range of its row has a constraint, as Grype reads it. A range without a constraint that names a fix, in a row with constrained ranges, makes the row's answer `Unknown`: it holds the versions below its fix, which Grype doesn't read. One row whose range holds the installed version makes the answer `No`, in every entry of the provider, under the same vulnerability ID, that speaks for the package. `Yes` needs every such row to leave the version outside its ranges, at a fixed version or above;
  - anything else is `Unknown`: a version below every fix and in no range, versions that don't compare, a scheme that isn't the package type's, or a namespace of another distribution, release or ecosystem.

### `fetch`: advisory pages

The `advisories` collector owns what goes to the internet when the agent asks ([design 5.8](design/2026-11-16-agent-on-cases.md#58-advisories-0054), [0054](decisions/0054-advisories.md)). Its one operation, `fetch`, runs in the hub's role, consumes nothing, and answers with one event of `ch.bedag.vexplain.advisories.page.v1alpha1` about `page/<URL>`, whatever subject it runs for. Its one parameter is `url`.

- **Two checks.** vexplain's MCP server forwards only a URL that came out of a trusted result of the case, a reference of `describe` ([agent](agent.md#what-a-verdict-needs)). The collector checks every request, and every redirect, before it connects, and refuses with `NotAllowed`:
  - a URL that isn't `https`, names a user or a password, or a port other than 443;
  - an IP address, and a host that isn't on its allowlist. A host matches an entry exactly, or as a subdomain of an entry that starts with a dot: `.debian.org` matches `lists.debian.org`, and not `debian.org`. Names compare case-insensitively, after IDNA. There are no wildcards, and no empty labels: a name that starts or ends with a dot, or holds two in a row, is refused, in the settings as in a URL, but for the one dot that starts an entry for subdomains.
- **The answer** is `{url, finalURL, contentType, text, truncated}`: the URL asked for, the one that answered after the redirects (at most 5), the media type, and the text. An HTML page's text is what a browser shows: scripts, styles and hidden elements are dropped, each block is a line, and whitespace is collapsed. Links keep their text and lose their URLs, but a URL that a page shows as text stays in it: what keeps a page from handing the agent a URL to follow is the first check, since vexplain's MCP server never forwards a URL that only a page named. Plain text and JSON keep their text, collapsed. Control and format characters, such as zero-width ones, bidi controls and tags, and variation selectors are dropped, since a page shows them as nothing. The text is UTF-8, whatever the page's charset.
- **The limits.** It reads at most `maxBytes` of a page, and of its text: a page beyond is cut, with `truncated: true`. A fetch that takes longer than `timeoutSeconds`, with its redirects and the whole page, fails with `TimedOut`. A page that isn't there fails with `NotFound`, one that isn't text with `UnsupportedContent`, and any other answer than a page with `FetchFailed`. The failures' messages are fixed texts, which repeat nothing that the page gave.
- **A page is external evidence.** It explains, and can push towards "affected" or "unclear", but never shows that a package is fixed or not affected.
- **It reaches the hosts through the proxy that its runtime config sets** ([0037](decisions/0037-collectors-proxy-from-runtime-config.md)): the install's runtime config `advisories` sets none, and gives the pod no service account token. A cluster without internet runs without the collector, and the agent works from the vulnerability database alone.

| Setting | Default | Range |
|---|---|---|
| `allowedDomains` | the advisory hosts below | 1–64 entries |
| `maxBytes` | 1048576 (1 MiB) | 1024–2097152 |
| `timeoutSeconds` | 20 | 1–120 |

The default list holds the hosts of the advisories that Grype's providers cite, which each record of the vulnerability database names as its own reference: `nvd.nist.gov`, `www.cisa.gov` (the catalog of known exploited vulnerabilities), `github.com` (GitHub's advisory database), `pkg.go.dev` (Go's vulnerability database) and `go.dev` (which that database cites), `security-tracker.debian.org`, `ubuntu.com`, `access.redhat.com`, `errata.almalinux.org`, `security.alpinelinux.org`, `alas.aws.amazon.com`, `security.archlinux.org`, `images.chainguard.dev`, `bodhi.fedoraproject.org`, `linux.oracle.com`, `www.suse.com` and `security.secureos.io`. A list in the settings replaces it. The list and the matching are in the SDK's package `hosts`, which the agent's safety core reads too, to tell the agent which references it can't fetch.

A failed fetch says which step failed, in fixed words: `the proxy refused the host, with HTTP status N`, `the proxy could not be reached`, `the host's name does not resolve`, `the host's certificate is not trusted`, `the host could not be reached`, and for any other error `the page could not be fetched`. The error's own text, which names the proxy and the host, goes to the log only. A request accepts `text/html, application/json;q=0.9`.

## Schedules and sources

A **schedule** is work that a collector does at times that its capabilities declare, such as a refresh of a vulnerability database. The collector declares each with a name and a five-field cron expression, in UTC. vexplain's operator keeps the clock, and calls `Fire` with the schedule's name when the expression says so.

- **`Fire` starts the work and returns within 10 seconds.** Work that takes longer runs in the background. A collector with schedules implements `Firer`, and its `Fire` gets the schedule's name, the settings and the context. A name that the collector didn't declare never reaches it: the SDK answers `InvalidArgument`.
- **A source is something of the collector's own that its evidence depends on,** such as a vulnerability database. A collector with sources implements `Sourcer`, and `GetInfo` reports each as a name, a version and the time its data was built. The operator calls `GetInfo` at every check, so a collector answers with the versions that it has at that moment. A change in a version tells vexplain that the evidence that depends on the source may have changed.
- **The status mirrors both.** `status.capabilities.schedules` lists the schedules, and `status.sources` the sources, each at most 8. The operator writes the sources only when they change. The age of a source that says when its data was built is the metric `vexplain_collector_source_age_seconds`, by `cluster`, `collector` and `source`.

The operator fires a schedule only while the `Collector` is `Ready`, at the times of its cron expression, and doesn't catch up on times that passed while it didn't run. `status.schedules` lists each schedule with the expression that runs, the time of its last fire, and the error of that fire when it failed. On the `Collector`, an admin changes when a schedule runs, and runs it at once ([0040](decisions/0040-collector-triggers.md)):

- **`spec.triggers` changes when a schedule runs.** An entry names a schedule and gives a five-field cron expression, in UTC, that runs in place of the declared one. A trigger that names no schedule of the collector, or an expression that the operator can't run, makes the `Collector` `TriggersInvalid`.
- **The annotation `vexplain.bedag.ch/run-now` runs every schedule at once,** as Flux's `reconcile.fluxcd.io/requestedAt` does: give it a value that it hasn't had, such as the time. The operator fires each schedule once for the value, waiting until the `Collector` is `Ready`, and then records the value as `status.lastHandledRunNow`. A fire that fails is tried again, and the value is recorded only once every fire succeeded.

```bash
kubectl annotate --overwrite collector vulnerabilities vexplain.bedag.ch/run-now="$(date -u +%FT%TZ)"
```

The `vulnerabilities` collector is the built-in example of both. It declares the schedule `database`, every six hours, whose `Fire` starts an update of its Grype database in the background and returns, and does nothing while an update runs or with `databaseUpdates: Offline`. Its source `grype-db` reports the database's version and build time, so that the operator shows its age. The database lives on a volume claim at `/db`, so a restart loads it without a download. A collector learns its settings only from requests, so at start the collector loads what `/db` holds, and the first request that carries settings makes it seed `/db` from `seedDatabase`, or else update it online.

Conformance checks that each schedule has a name of its own and a cron expression, that `Fire` answers for each schedule within 10 seconds and refuses an unknown name with `InvalidArgument`, and that each source has a name and a version.

## Packaging

- **A package is an OCI image.** One image holds one collector, and a collector may cover several sources. The installer references it by tag or by digest, and vexplain records the digest that runs.
- **It runs as non-root,** on a base such as distroless static, and writes nothing outside the volumes that its runtime config mounts: vexplain runs it with a read-only root filesystem. vexplain's namespace enforces the restricted Pod Security Standard, so a pod that a runtime config weakens is refused.
- **It listens where `VEXPLAIN_LISTEN` and `VEXPLAIN_HEALTH_LISTEN` say,** by default on 9443 for the collector API with mutual TLS, and on 8081 for plain HTTP. It serves the certificate in `tls.crt` with its key, and requires a client certificate that the authority in `ca.crt` signed. vexplain's authority is a small one, which the operator keeps in the Secret `vexplain-collector-ca` of its namespace, and it rotates the certificates: each 30 days before it ends, and every one when the operator makes a new authority, as when that Secret is missing or the authority has 90 days left. The SDK's server loads its files again when they change. vexplain's install lets only the pods of the manager and of the agent workers connect to 9443, and any pod to 8081, and no pod to another port of a collector: a NetworkPolicy selects every pod with the label `vexplain.bedag.ch/collector`.
- **Its name and version** come from `GetInfo`. vexplain stores evidence at the version, so a new version replaces what an old one delivered.
- **Its evidence is listed with `kubectl get vexplain-data`,** with the images and the verdicts that it feeds: `Evidence` shows its source, type, coverage and age, so a collector that delivers nothing, or little, is visible without reading JSON.
- **The template builds all of this:** a `Dockerfile` on distroless static, as non-root, and a `Makefile` with `make docker-build`.

## The `Collector` resource

A `Collector` (`config.vexplain.bedag.ch/v1alpha1`, cluster-scoped) installs one collector, as a Crossplane `Provider` installs a provider. Installed means enabled.

```yaml
apiVersion: config.vexplain.bedag.ch/v1alpha1
kind: Collector
metadata:
  name: hello
spec:
  package: artifacts.example/collectors/hello:0.1.0
  runtimeConfigRef:
    name: default
  settings:
    greeting: Hello
```

| Field | Is |
|---|---|
| `spec.package` | The image. |
| `spec.runtimeConfigRef` | The `CollectorRuntimeConfig` to use. `default` if empty. |
| `spec.settings` | The collector's own settings, an object of any shape. |
| `spec.triggers` | Cron expressions that run in place of those of the schedules that the collector declares. |
| `spec.produces` | The `maxAgeSeconds` (60 to 2,592,000) of a type, in place of the one that the collector declares. A type that the collector doesn't produce, or that no operation of it returns, makes it `ProducesInvalid`. |
| `status.packageDigest` | The digest that runs. |
| `status.version` | The version that `GetInfo` answered. |
| `status.capabilities` | What `GetCapabilities` answered, bounded in size, with the schedules: for a type its declared `maxAgeSeconds`, for an operation its role and the names of its parameters (the first 16, sorted). |
| `status.sources` | The sources that `GetInfo` reported, each with its version and build time. |
| `status.schedules` | The schedules that the operator runs, each with its cron expression, its last fire and that fire's failure. |
| `status.lastHandledRunNow` | The value of the annotation `vexplain.bedag.ch/run-now` that the operator handled last. |
| `status.conditions` | `Ready`, with reasons such as `Healthy`, `CollectorFailing`, `NoData`, `PackageInvalid`, `IncompatibleAPI`, `WrongRole`, `TriggersInvalid`, `ProducesInvalid`, `SettingsInvalid`, `PermissionsNotAllowed`, `MissingPermissions`, `RuntimeConfigInvalid` and, for an MCP collector, `ToolsMissing`. |
| `status.lastSuccessTime` | When the collector last delivered. |

- **Deleting a `Collector` removes it,** with its Deployment, its Service, its service account and what vexplain granted it, and with the evidence that it delivered, the streamed records of every cluster included. There is no `state` field. A playbook that pins the deleted collector, or needs a type that no other `Collector` produces, isn't `Ready`, and no finding is settled on the evidence that went.
- **vexplain deploys one Deployment for each `Collector`, which serves every role the collector takes,** in the operator's namespace, with a Service and a service account named `vexplain-collector-<name>`, a TLS Secret `vexplain-collector-<name>-tls`, and the label `vexplain.bedag.ch/collector: <name>`. The names stay when you upgrade, so that the service account keeps its bindings. Because the Service's name must be a DNS label of at most 63 characters, a `Collector`'s name has at most 44.
- **Upgrading means changing `spec.package`,** and changing it back is the rollback.
- **A collector's health gates new requests, not what it already delivered.** One that is unhealthy or incompatible gets no new requests, and its `Ready` condition says so. Its evidence stays until the collector replaces it. A failure about one subject, and a stream that breaks, are no health failures. A collector's health doesn't stop a playbook: a playbook needs a producer of its subjects, a findings producer that takes part, and a producer of each piece of evidence that is required or that such a findings producer consumes, as the capabilities that the `Collector`s recorded say. While one producer fails, the playbook goes on with the stored evidence and the other producers. A subject of which the failing producer has no evidence of a type that a findings producer consumes has no match, and so no verdict, until it delivers.
- **vexplain's install ships its own collectors** as `Collector` manifests, in `config/collectors`, and the defaults of the ceilings cover what they declare. The operator creates none at run time, so a deleted built-in stays deleted.

See [design 5.2](design/2026-10-31-collectors-evidence-rules.md#52-collectors-and-their-packages) and [5.9](design/2026-10-31-collectors-evidence-rules.md#59-trust-and-permissions).

### Roles and modes

A collector declares its roles, `Spoke` for collecting next to the workloads and `Hub` for work in the hub's cluster. The manager's flag `--mode` says which roles it runs:

| `--mode` | Runs |
|---|---|
| `HubAndSpoke` (the default) | Both: what one cluster needs. |
| `Spoke` | The spoke role only: it collects in its own cluster, with presence and the streams of the spoke role, and no hub controller, no executor and no report renderer. |
| `Hub` | The hub role only: its controllers and the executor, with no presence. It collects nothing in its own cluster. |

A `Collector` whose roles the mode runs none of is `Ready` False with the reason `WrongRole`, and isn't used: a `Spoke` manager doesn't use a collector of the hub role only, and a `Hub` manager doesn't use one of the spoke role only. A collector that takes both roles runs in either mode, in the roles that the mode runs.

## MCP collectors

An MCP collector is a `Collector` that names an MCP server that runs elsewhere, such as a wiki's or a CMDB's, in place of a package. The agent may call the server's tools, and nothing else uses it. See [the design of the agent on image cases, 5.9](design/2026-11-16-agent-on-cases.md#59-mcp-collectors-0031-0056), and decisions [0031](decisions/0031-tools-from-collectors.md) and [0056](decisions/0056-phase-4-scope.md).

```yaml
apiVersion: config.vexplain.bedag.ch/v1alpha1
kind: Collector
metadata:
  name: wiki
spec:
  mcp:
    url: https://wiki-mcp.example/mcp
    headersFrom:
    - secretRef:
        name: wiki-mcp
    tools: [search, get_page]
```

| Field | Is |
|---|---|
| `spec.mcp.url` | The endpoint of the server's Streamable HTTP transport of MCP. HTTPS only. A server that speaks only stdio runs behind a proxy, which its deployer sets up. |
| `spec.mcp.headersFrom` | Secrets in the operator's namespace with the label `vexplain.bedag.ch/mcp-headers: "true"`. Each key of a Secret is a header's name, and its value, trimmed, the header's value. The operator reads no Secret without the label. |
| `spec.mcp.tools` | Required, 1 to 64 names: the only tools that vexplain may ever call on the server. |

- **A `Collector` has exactly one of `package` and `mcp`,** and never changes from one to the other. An MCP collector has no `runtimeConfigRef` and no `triggers`, and it has no use for `settings`. vexplain deploys and grants nothing for it.
- **Whoever deploys the server answers for its privileges.** vexplain doesn't judge what a tool does.
- **The list is what vexplain may ever call.** A tool off it is never offered to the agent, and its call is refused before any request, whatever an `AgentProfile` allows. A server that serves a listed tool under another schema is still allowed, by name. vexplain calls tools unattended, with arguments that a model picked from text that anyone can write, so a tool that writes, such as one that deletes a page, stays off the list unless that is meant.
- **The profile picks the collectors** that an agent uses, as for any collector's operations, and may narrow them to named tools: `{collector: wiki, operations: [search]}`. Without operations, every tool on the list.
- **The agent calls a tool as `<collector>__<tool>`,** within the profile's `toolTimeoutSeconds`, and its output is capped like any other tool result. An answer takes 16 MiB at most, and vexplain follows no redirect, which would take the headers elsewhere.
- **Its output is external evidence,** always: it can push a verdict only towards "affected" or "unclear". An MCP tool never counts as a fetch: a server that fetches pages answers for them, and nothing in its output becomes a URL that `advisories`' `fetch` may take.
- **The headers are secret.** They appear in no log, status, event, error, ledger entry or tool output. A value, or a word of one, of 8 bytes or more that a server echoes is withheld.
- **`Ready`** is `True` with `Healthy` while the server serves every tool on the list, `False` with `ToolsMissing`, naming the tools, while it lacks one, and `False` with `CollectorFailing` while it can't be reached, or a Secret of its headers doesn't exist or lacks the label. The operator checks it at every resync. Its status holds no capabilities: it streams nothing and runs no operation of the collector API.
- **A `Collector` isn't named like an entry of the agent's ledger,** such as `ev-3`. The outputs of the agent's tool calls are stored with their entry as their source, and deleting a `Collector` deletes the evidence of its name.

## RBAC

**A collector declares the Kubernetes permissions that it needs, and vexplain grants them, within limits that the admin sets** ([0041](decisions/0041-shipped-permissions.md)). In one sentence: *a collector gets what it declares if a ceiling allows it and the deny list doesn't forbid it.*

- **`Capabilities.Permissions`** lists them as RBAC rules: API groups, resources and verbs, and whether they hold in the collector's own namespace only. The list is what the collector needs, and no more.
- **vexplain grants them to the collector's service account,** the one that its Deployment runs as, which a runtime config may change:
  - a ClusterRole and a ClusterRoleBinding for what it needs in the whole cluster;
  - a Role and a RoleBinding in vexplain's namespace for what it needs there.

  All four are named `vexplain-collector-<name>`, carry the label `vexplain.bedag.ch/collector: <name>`, and are owned by the `Collector`, so they go with it. A rule that the collector no longer declares goes from them, and a role that would hold no rule goes with its binding.
- **vexplain then checks that the service account holds them,** with a `SubjectAccessReview` for each, a moment after it granted them, and reports what is missing as `MissingPermissions`: something besides RBAC may still refuse them, such as another authorizer.
- **A collector starts without its permissions** ([0041](decisions/0041-shipped-permissions.md)). vexplain learns them from `GetCapabilities`, so your collector answers `GetInfo` and `GetCapabilities` before anything is granted. It uses its permissions only for its work, which it gets once it is `Ready`. A read that is refused fails that piece of work, which is retried: it never stops the collector. A collector that needs a permission to start never starts, since vexplain can't grant what it hasn't read. The scanner, for instance, reads its own pod, whose image its scan Jobs run, only when its first scan needs it.

### The ceilings

The ceilings are the admin's hard limit. Each is an aggregated ClusterRole, whose rules the API server gathers from the ClusterRoles that carry its label, as Crossplane's `crossplane:allowed-provider-permissions` does.

| Ceiling | Covers | Label of the ClusterRoles that extend it |
|---|---|---|
| `vexplain-collector` | What a collector may get in the whole cluster. | `rbac.vexplain.bedag.ch/aggregate-to-collector: "true"` |
| `vexplain-collector-namespaced` | What a collector declares for its own namespace, vexplain's, such as the scanner's Jobs and their Secrets. | `rbac.vexplain.bedag.ch/aggregate-to-collector-namespaced: "true"` |

- **A rule for the collector's own namespace may fall under either ceiling,** and a rule for the whole cluster only under `vexplain-collector`.
- **vexplain's manager holds both ceilings,** `vexplain-collector` in the whole cluster, and `vexplain-collector-namespaced` in vexplain's namespace alone, through a RoleBinding, and it never holds the `escalate` or `bind` verbs of its own. Kubernetes lets someone create a role only when they hold its permissions, so the API server refuses a grant beyond what the manager holds. A ClusterRole that extends a ceiling extends what the manager holds as well, so keep `escalate`, `bind` and `impersonate` out of every ceiling.
- **For the manager's own rights, vexplain's check is the only guard.** The escalation check counts all that the manager holds, not only the ceilings, so it passes a grant of a right that the manager holds for its own work. Those rights include the writes on ClusterRoles and ClusterRoleBindings in the whole cluster, and on vexplain's own kinds, and, in vexplain's namespace, the rights on Roles, RoleBindings, Deployments, Services, ServiceAccounts and Secrets. vexplain checks each rule against the ceilings first, as the escalation check does: a star covers any API group, resource or verb, a subresource needs its own rule or `*/<subresource>`, and a rule that names some objects of a resource doesn't cover all of them.
- **What the manager can change in the whole cluster.** To grant, the manager may update and delete every ClusterRole and ClusterRoleBinding of the cluster, not only vexplain's. A delete isn't subject to the escalation check, and an update that narrows a role to rules that the manager holds passes it, so whoever controls the manager can remove or weaken any ClusterRole or ClusterRoleBinding, those of Kubernetes and of other software included. Nothing in the install limits those writes to vexplain's own objects.
- **The install's defaults,** `vexplain-collector-defaults` and `vexplain-collector-namespaced-defaults`, in `config/rbac/collector.yaml`, hold exactly what the built-in collectors declare, those on kinds that a cluster may not serve, such as the Gateway API's and Cilium's, included.
- **To install a collector that needs more,** add a ClusterRole that carries the label of the ceiling, with the rules that you allow. Name it anything but `vexplain-collector-<something>`, which vexplain's grants and the install use:

  ```yaml
  apiVersion: rbac.authorization.k8s.io/v1
  kind: ClusterRole
  metadata:
    name: hello-collector-ceiling
    labels:
      rbac.vexplain.bedag.ch/aggregate-to-collector: "true"
  rules:
    - apiGroups: [""]
      resources: ["configmaps"]
      verbs: ["get", "list", "watch"]
  ```

- **To narrow a ceiling,** change or delete a ClusterRole that extends it.

### The deny list

`OperatorConfig`'s `spec.collectors.deniedPermissions` lists the permissions that vexplain never grants a collector, whatever the ceilings allow. It is a second guard, and it wins, as an explicit deny does in AWS IAM.

```yaml
apiVersion: config.vexplain.bedag.ch/v1alpha1
kind: OperatorConfig
metadata:
  name: default
spec:
  collectors:
    deniedPermissions:
      - apiGroups: [""]
        resources: ["secrets"]
        verbs: ["list", "watch"]   # the default
```

- **The default is `list` and `watch` on Secrets,** because those reveal every Secret's contents (Kubernetes' RBAC good practices). The scanner's `get` on pull secrets keeps working.
- **A rule of the deny list refuses a declared rule when they share an API group, a resource and a verb,** a star standing for any, in a declared rule as in a rule of the list. An empty list denies nothing.

### What the defaults give any collector

The ceilings hold the defaults, and the defaults hold what the built-in collectors need. So any `Collector` that you install gets the same when it declares it:

- **`get` on every Secret in the cluster,** by its name. The scanner reads the pull secrets of the pods whose images it scans with it.
- **`create`, `get` and `delete` on the Secrets of vexplain's namespace,** where the LLM's API key, every collector's TLS key and the key of the collectors' certificate authority (`vexplain-collector-ca`) live. With that key, a collector could sign a client certificate as the operator and call every collector. The scanner writes the logins of its scan Jobs there.

An entry of the deny list closes each of them, for every collector, the scanner included:

| Entry of `deniedPermissions` | What it closes | What it costs the scanner |
|---|---|---|
| `{apiGroups: [""], resources: [secrets], verbs: [get]}` | Reading any Secret by its name, in the whole cluster and in vexplain's namespace | The scanner declares `get` on Secrets, so it isn't `Ready`, with `PermissionsNotAllowed`, and no image is scanned |
| `{apiGroups: [""], resources: [secrets], verbs: [create, delete]}` | Writing the Secrets of vexplain's namespace | The same: the scanner declares `create` and `delete` on them for its scan Jobs |

To keep the scanner and give another collector less, use the mode `Check`, and grant each collector by hand (below).

### When a rule isn't allowed

- **A collector that declares a rule outside the ceilings, or one that the deny list refuses, isn't `Ready`.** Its condition is `PermissionsNotAllowed`, which names each such rule and the guard that refuses it, `ceiling`, `namespaced ceiling` or `deny list`, and vexplain grants it none of its rules. A grant that the API server refuses gives the same reason, with the API server's message.
- **A grant holds only while every rule is allowed.** When you narrow a ceiling or extend the deny list, vexplain takes back the grant of a collector that now asks for too much at its next check of the collector, within 30 seconds, whether or not the collector answers. Once every rule is allowed again, it grants them again.

### The modes

`OperatorConfig`'s `spec.collectors.permissions` says what vexplain does with the permissions that a collector declares:

- **`Grant`, the default:** it grants them, as above.
- **`Check`:** it grants nothing, takes back what it granted before, and reports what the service account lacks as `MissingPermissions`, for a cluster whose RBAC is managed elsewhere. You bind the roles to the collector's service account yourself. Name them anything but `vexplain-collector-<name>`, which a later switch to `Grant` would take:

  ```yaml
  apiVersion: rbac.authorization.k8s.io/v1
  kind: ClusterRole
  metadata:
    name: hello-collector
  rules:
    - apiGroups: [""]
      resources: ["pods"]
      verbs: ["get", "list", "watch"]
  ---
  apiVersion: rbac.authorization.k8s.io/v1
  kind: ClusterRoleBinding
  metadata:
    name: hello-collector
  roleRef:
    apiGroup: rbac.authorization.k8s.io
    kind: ClusterRole
    name: hello-collector
  subjects:
    - kind: ServiceAccount
      name: vexplain-collector-hello
      namespace: vexplain-system
  ```

### Further rules

- **vexplain's own collectors stay read-only towards workloads:** they get, list and watch, never write to analysed workloads and never exec into pods. Installing a third-party collector means trusting it, and its admin knows what it does.
- **The operator itself reads no pods, nodes, Secrets or service accounts** outside its namespace. It holds the ceilings, which reach further, only because Kubernetes lets it grant no more than it holds. The collectors that need those permissions hold them.
- **A `Collector` can't be named `defaults`, `namespaced` or `namespaced-defaults`,** because its grants would take the names of the install's ceilings and defaults.
- **A grant that someone makes by hand,** outside vexplain, is the RBAC admin's business.

## The runtime config

A `CollectorRuntimeConfig` (`config.vexplain.bedag.ch/v1alpha1`, cluster-scoped) shapes the Deployment that a collector runs in, as Crossplane's `DeploymentRuntimeConfig` does ([0030](decisions/0030-collector-runtime-config.md)). A `Collector` names one in `spec.runtimeConfigRef`, and `default` applies when it names none: the operator creates it empty, and never overwrites it.

| Field | Shapes |
|---|---|
| `spec.deploymentTemplate` | The collector's Deployment. |
| `spec.serviceAccountTemplate` | The metadata of its service account, such as an annotation for a cloud identity. |

```yaml
apiVersion: config.vexplain.bedag.ch/v1alpha1
kind: CollectorRuntimeConfig
metadata:
  name: hello
spec:
  deploymentTemplate:
    spec:
      template:
        spec:
          nodeSelector:
            kubernetes.io/os: linux
          containers:
            - name: collector
              resources:
                limits:
                  memory: 256Mi
```

- **A collector's proxy is its runtime config's** ([0037](decisions/0037-collectors-proxy-from-runtime-config.md)). The operator passes none of its own environment to a collector, so a collector has no proxy unless its runtime config sets one. Set `HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY` on the container `collector` in `default`, which every collector that names no runtime config uses, or in a collector's own runtime config. A variable may come from a Secret in vexplain's namespace, so that the credentials of a proxy URL stay out of the config:

  ```yaml
  apiVersion: config.vexplain.bedag.ch/v1alpha1
  kind: CollectorRuntimeConfig
  metadata:
    name: default
  spec:
    deploymentTemplate:
      spec:
        template:
          spec:
            containers:
              - name: collector
                env:
                  - name: HTTPS_PROXY
                    valueFrom:
                      secretKeyRef:
                        name: proxy-settings
                        key: https-proxy
                  - name: NO_PROXY
                    value: .svc,.cluster.local
  ```

- **Templates are merged onto vexplain's defaults** as a strategic merge patch. The collector's container is named `collector`.
- **The defaults are hardened:** non-root with the `RuntimeDefault` seccomp profile at the pod and at the container, no privilege escalation, a read-only root filesystem, all capabilities dropped, and `imagePullPolicy: IfNotPresent`. The container requests `cpu: 10m` and `memory: 64Mi`, and has no limits: a runtime config sets them. A runtime config that needs another seccomp profile sets it on the container `collector`, since a container's own profile wins over the pod's: one set only at the pod doesn't reach it.
- **Everything can be changed,** and vexplain sets the contract's fields last: the image, the certificates, the ports and the contract's environment variables.
- **Write access to a `Collector` or a `CollectorRuntimeConfig` amounts to creating pods in vexplain's namespace,** which Kubernetes' RBAC good practices treat as access to every Secret and service account there. So it is only for people who are trusted with that namespace.
- **The pods that a collector creates itself,** such as scan Jobs, are not shaped by its runtime config. Its settings configure them, with the SDK's standard pod template, `sdk/podtemplate`, so that every collector that creates pods takes the same shape. Its `env` gives the pods' container environment variables, such as a proxy: at most 32, each with a `value` or from a key of a Secret in the pod's namespace (`valueFrom.secretKeyRef`), and none that the collector sets itself, such as the location of the credentials ([0037](decisions/0037-collectors-proxy-from-runtime-config.md)). The scanner takes it as `scanPod.env`, which is the only source of a scan pod's environment beyond the scanner's own contract. A scan pod's proxy comes from there, and never from the scanner's own environment, so a scan pod has none unless `scanPod.env` sets one:

  ```yaml
  apiVersion: config.vexplain.bedag.ch/v1alpha1
  kind: Collector
  metadata:
    name: scanner
  spec:
    settings:
      scanPod:
        env:
          - name: HTTPS_PROXY
            valueFrom:
              secretKeyRef:
                name: proxy-settings
                key: https-proxy
  ```

  The scanner sets `DOCKER_CONFIG` on a scan pod itself, so `scanPod.env` can't set that name; any other name is free.

  A collector that runs a throwaway Job for a task, as the scanner does for each scan, builds it with `sdk/jobs`, which keeps the Job isolated ([0022](decisions/0022-scan-jobs-and-hub-matcher.md)) and reads the one line that its pod prints: its pod gets no access to the Kubernetes API, runs as a user without privilege, with a read-only root filesystem, and meets the restricted Pod Security Standard that vexplain's namespace enforces, and the only credentials that it gets are the task's, in a Secret that the Job owns: a Docker config for each login, `config-0.json`, `config-1.json` and so on, in the order that the pod tries them.

### Placing pods on nodes

Each kind of pod takes its node placement from a different place:

| Pod | Where to set `nodeSelector` and `tolerations` |
|---|---|
| The manager | A kustomize patch of `config/manager/manager.yaml`, in the overlay of your install. |
| The agent workers | A kustomize patch of `config/agent/agent.yaml`, in the overlay of your install. |
| A collector | Its runtime config's `deploymentTemplate`, at `spec.template.spec`, as the example above shows for `nodeSelector`. |
| A scan pod of the scanner | The `Collector` `scanner`'s `settings.scanPod.nodeSelector` and `settings.scanPod.tolerations`. |

See [design 5.8](design/2026-10-31-collectors-evidence-rules.md#58-runtime-config-0030).

## Conformance

**The conformance suite runs a collector against the contract,** as CSI's `csi-sanity` does for storage drivers. Every collector of vexplain's own passes it in CI, and so should yours, before vexplain runs it. A version of the API reaches `v1` only together with the suite. The suite calls the collector over gRPC, as vexplain does, so it also tests collectors in other languages.

Serve the collector in a test, and run the suite against it:

```go
func TestConformance(t *testing.T) {
	conformance.Run(t, conformance.Target{
		Dial:            dialTheCollector,
		Settings:        json.RawMessage(`{"greeting": "Hello"}`),
		InvalidSettings: json.RawMessage(`{"greeting": ""}`),
		Context:         collector.Context{Cluster: "cluster-a"},
	})
}
```

The template's test serves its collector in the process of the test, on a `bufconn` listener, with `collector.Serve` and `Options.Insecure`, and `Dial` returns a connection to it. `Run` reports each check as a subtest of the `*testing.T` that it gets, named by its group and what it checks, such as `Watch/spoke/reaches SnapshotEnd in time`. `RunWith` takes any `Reporter`, the part of `testing.T` that the suite uses, which a test of the suite itself replaces with one that records.

| `Target` | Is |
|---|---|
| `Dial` | Connects to the collector. The suite closes the connection. |
| `Settings` | Valid settings, sent with every call. |
| `InvalidSettings` | Optional: settings that the collector must refuse. |
| `Context` | What vexplain tells the collector about its cluster. |
| `Invocations` | The operations to call, each with a subject, parameters and inputs: evidence of the types that the operation consumes. |
| `Client` | Optional: a Kubernetes client, which turns on the presence check. |

**What it checks:**

- `GetInfo` has a name, a version and `v1alpha1`, and `GetCapabilities` answers.
- Every schema in the capabilities compiles. Every type that the collector produces has a schema, matches `evidence.TypePattern`, so it is reverse-DNS and versioned, and has a scope. Every operation produces only declared types, and the collector takes a role.
- The `Settings` pass the schema and `ValidateSettings`, and `InvalidSettings`, when set, don't.
- For a collector that watches, for each role: `Watch` starts with `SnapshotStart` and reaches `SnapshotEnd` within 60 seconds, with only events in between, and a second `Watch` starts with a snapshot again.
- Every event of a snapshot is valid evidence, of a declared type, and its `data` validates against the schema of its type.
- Each invocation, with its `Inputs`, returns valid events, of types that its operation produces, or a failure with a reason.
- Each source that `GetInfo` reports has a name and a version.
- For a collector with schedules: each has a name of its own and a cron expression, `Fire` answers for each within 10 seconds, and `Fire` for a name that the collector didn't declare fails with `InvalidArgument`.

### The presence check

A collector that produces the presence type reads the pods of a cluster and the nodes they run on. It has to apply two things that vexplain tells it in its context, the **scope** and the **label of vexplain's own pods**, and to say on which node and platform each pod that it lists runs. The suite checks that it does, against a cluster for tests. It needs a Kubernetes client for that: `Target.Client`, a client of the cluster that the collector reads, such as an [envtest](https://book.kubebuilder.io/reference/envtest) API server or a kind cluster. A collector that produces the presence type and gets no client fails the check. Pass the client of a cluster for tests, and never of one that anyone uses: the suite creates nodes, namespaces and pods in it, and deletes them when it is done.

```go
env := &envtest.Environment{}
cfg, err := env.Start()
// ...
kubernetes, err := client.New(cfg, client.Options{})
// Start the collector with a client of the same cluster, and pass kubernetes as Target.Client.
```

The `scope` in the context is `OperatorConfig`'s `spec.scope`, as JSON. It has four optional label selectors:

```json
{
  "includeNamespaces": {"matchLabels": {"team": "a"}},
  "excludeNamespaces": {"matchExpressions": [{"key": "vexplain", "operator": "In", "values": ["off"]}]},
  "includePods": {"matchLabels": {"analyse": "true"}},
  "excludePods": {"matchExpressions": [{"key": "skip", "operator": "Exists"}]}
}
```

- A pod is in scope when its namespace passes the namespace selectors and the pod passes the pod selectors. An include selector that is absent or empty selects everything, and an exclude selector that is absent excludes nothing. **The exclude selector wins** over the include selector.
- **vexplain's own pods** carry the label that `own_pod_label` names, **in the operator's namespace.** The label counts only there: anyone who can create pods can set a label, so if it counted in every namespace, adding it would hide a workload from triage.

The suite sets a scope, an operator namespace and an own-pod label of its own, with names that are not vexplain's, so that a collector can't pass by having vexplain's label in its code. It creates two nodes, four namespaces and nine pods that run on the nodes, and sets each pod's container image ID through the status subresource, since envtest runs no kubelet. One node is `linux/amd64` and the other `linux/arm64`: they carry the labels `kubernetes.io/os: linux` and `kubernetes.io/arch: amd64` or `arm64`, which is where a collector reads the platform of a pod's node. Pods that must be listed run on each. Then the suite takes a snapshot, and checks that the collector:

- lists the pods that the scope selects;
- leaves out the pods that the scope excludes, by namespace and by pod, through the include selectors and the exclude selectors, and leaves them out of the workloads of an image that a pod in scope runs too;
- leaves out the pod that carries the own-pod label in the operator's namespace;
- lists a pod that carries the own-pod label in another namespace;
- lists a pod in the operator's namespace that doesn't carry the label: there, only a pod with the label is one of vexplain's own, and any other is a workload like the rest;
- gives, for each pod that it lists, the node that the pod itself runs on and that node's platform, `linux/amd64` or `linux/arm64`, in the `pods` of its workload: the hub uses the platforms of presence to notice an image that starts to run on a platform that it hasn't seen.

A collector that reads through a cache may not see a pod or its node that was created just now, so the suite takes another snapshot until the pods that must be listed are, with their nodes and platforms, within 30 seconds. A pod that must be left out and is listed fails at once.

## Before you ship

- [ ] The type names are reverse-DNS and versioned, each type has a scope and a schema, and each schema says what the coverage counts.
- [ ] The settings have a schema that stands alone, and no setting is a secret.
- [ ] The permissions in `Capabilities` are what the collector needs, and no more.
- [ ] Evidence about a manifest carries `platform`, and `Hub` evidence has subjects that are unique across clusters.
- [ ] The conformance test passes, with invalid settings and an invocation of each operation.
- [ ] The image runs as non-root with a read-only root filesystem, and `GetInfo` reports its version.

## Where to go next

- The [template project](../templates/collector) and its README.
- The [design of collectors, evidence and rules](design/2026-10-31-collectors-evidence-rules.md), especially [5.2 to 5.5](design/2026-10-31-collectors-evidence-rules.md#52-collectors-and-their-packages), [5.8 to 5.9](design/2026-10-31-collectors-evidence-rules.md#58-runtime-config-0030) and [5.11](design/2026-10-31-collectors-evidence-rules.md#511-sdk-template-and-conformance).
- The decision records [0029](decisions/0029-collector-packages.md), [0030](decisions/0030-collector-runtime-config.md), [0031](decisions/0031-tools-from-collectors.md) and [0032](decisions/0032-evidence-as-cloudevents.md).
- The packages of the SDK: `sdk/collector` (the server), `sdk/evidence` (events, the core's types and their schemas), `sdk/subject` and `sdk/conformance`.
