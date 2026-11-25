# vexplain
// TODO(user): Add simple overview of use/purpose

## Description
// TODO(user): An in-depth paragraph about your project and overview of use

## Getting Started

### Prerequisites
- go version v1.26+
- docker version 17.03+.
- kubectl version v1.32+.
- Access to a Kubernetes v1.32+ cluster. The CRD of `OperatorConfig` validates its fields with CEL's format library,
  which a CRD can use from Kubernetes 1.32.

### To Deploy on the cluster
**Build and push your images to the locations specified by `IMG`, `AGENT_IMG`, `WORKLOADS_IMG`, `SCANNER_IMG`,
`VULNERABILITIES_IMG`, `NETWORK_REACH_IMG` and `ADVISORIES_IMG`:**

The operator is two images from the same commit, the two targets of the root `Dockerfile`: the manager's (`IMG`), and
the agent workers' (`AGENT_IMG`), which judge the cases with the model in a Deployment of their own
([0057](docs/decisions/0057-agent-workers.md)). Each holds its own binary alone. Each built-in collector is an image of
its own, which its `Collector` installs as its package: `workloads` reports which workloads run which images, `scanner` scans an image in a Job that runs its
image, `vulnerabilities` matches what the scanner found against its vulnerability database, `network-reach` reports how far
each workload can be reached, and `advisories` fetches the advisory pages that the agent reads, from an allowlist of hosts.

```sh
make docker-build docker-push IMG=<some-registry>/vexplain:tag AGENT_IMG=<some-registry>/vexplain-agent:tag \
  WORKLOADS_IMG=<some-registry>/vexplain-workloads:tag SCANNER_IMG=<some-registry>/vexplain-scanner:tag \
  VULNERABILITIES_IMG=<some-registry>/vexplain-vulnerabilities:tag \
  NETWORK_REACH_IMG=<some-registry>/vexplain-network-reach:tag \
  ADVISORIES_IMG=<some-registry>/vexplain-advisories:tag
```

To place pods on nodes, set `nodeSelector` and `tolerations` for the manager and the agent workers through a kustomize patch, for the collectors in their runtime config's `deploymentTemplate`, and for scan pods in the scanner's `scanPod.nodeSelector` and `scanPod.tolerations` ([how](docs/collectors.md#placing-pods-on-nodes)).

Each collector reports `VERSION` as its version, which is the commit that `git describe` names unless you set it.
vexplain stores a collector's evidence at its version, so a collector rebuilt under a new version replaces what the
one before it delivered.

The install sets no proxy: vexplain can't know one, and the operator passes none of its own environment to a collector. Only the agent workers reach the model's endpoint: where that takes a proxy, set `HTTPS_PROXY` on the Deployment `vexplain-agent` through a kustomize patch, with `NO_PROXY` holding the cluster's own addresses, as the API server's. A collector gets a proxy from its runtime config, as [the guide to writing a collector](docs/collectors.md#the-runtime-config) shows. The vulnerabilities collector downloads its database through the proxy that its runtime config sets, so where it reaches its database only through a proxy, set one on the container `collector` in the `vulnerabilities` runtime config, and in `default` for the other collectors that need one. The advisories collector fetches pages from the internet for the agent, so set one in the `advisories` runtime config too where it reaches the advisory hosts only through a proxy, or delete the `Collector` `advisories` in a cluster without internet. The scan Jobs that the scanner creates are not shaped by a runtime config, and don't inherit the scanner's proxy: for registries that are reachable only through a proxy, set `settings.scanPod.env` on the `scanner` Collector, where a variable may come from a Secret too (`valueFrom.secretKeyRef`). For a cluster without internet,
`VULNERABILITIES_DB=true` bakes the database into the vulnerabilities image, of about 3.5 GB, and the `Collector` `vulnerabilities` then
takes the settings `databaseUpdates: Offline` and `seedDatabase: /opt/grype-db`, as `test/e2e/config` gives them.

**NOTE:** These images ought to be published in the personal registry you specified.
And it is required to have access to pull the image from the working environment.
Make sure you have the proper permission to the registry if the above commands don’t work.

**Install the CRDs into the cluster:**

```sh
make install
```

**Deploy the operator and its collectors to the cluster with the images specified above:**

```sh
make deploy IMG=<some-registry>/vexplain:tag AGENT_IMG=<some-registry>/vexplain-agent:tag \
  WORKLOADS_IMG=<some-registry>/vexplain-workloads:tag SCANNER_IMG=<some-registry>/vexplain-scanner:tag \
  VULNERABILITIES_IMG=<some-registry>/vexplain-vulnerabilities:tag \
  NETWORK_REACH_IMG=<some-registry>/vexplain-network-reach:tag \
  ADVISORIES_IMG=<some-registry>/vexplain-advisories:tag
```

The install, `config/default`, holds:

- the operator, in the namespace `vexplain-system`, which enforces the restricted Pod Security Standard: the manager,
  and the agent workers (`config/agent`), the Deployment `vexplain-agent` of 2 replicas, which claim the cases that
  investigations queue and judge them; their leader probes the models. Only the workers read the LLM key and reach
  the model ([the agent's guide](docs/agent.md#where-the-agent-runs))
- the `Collector`s `workloads`, `scanner`, `vulnerabilities`, `network-reach` and `advisories` (`config/collectors`), which the
  operator deploys as `vexplain-collector-<name>`, with the runtime configs of the vulnerabilities and advisories collectors and
  the volume claim of the vulnerability database
- the ceilings of what the operator grants a collector, and their defaults (`config/rbac/collector.yaml`)
- the default rules (`config/rules`): the finding rules `known-exploited`, `completeness-guard`, `removed-in-later-layer`,
  `load-check` and `fix-available`, and the exposure rules `exposed-outside-cluster`, `reachable-in-cluster` and
  `own-namespace-only`, which decide each workload's exposure as the spokes do; and the default playbook
  `container-cves` (`config/playbooks`)
- NetworkPolicies (`config/network-policy`): only the pods of the manager and of the agent workers reach the
  collectors' API on port 9443, and only the pods of namespaces labelled `metrics: enabled` reach their metrics

**What the collectors may do.** A collector declares the Kubernetes permissions that it needs, and the operator grants
them to the collector's service account, within two ceilings: `vexplain-collector` for the whole cluster, and
`vexplain-collector-namespaced` for vexplain's namespace ([0041](docs/decisions/0041-shipped-permissions.md)).

- Each ceiling is an aggregated ClusterRole. Their defaults, `vexplain-collector-defaults` and
  `vexplain-collector-namespaced-defaults`, hold exactly what the built-in collectors declare. A ClusterRole with the
  label `rbac.vexplain.bedag.ch/aggregate-to-collector: "true"` extends `vexplain-collector`, for a collector that
  needs more.
- `OperatorConfig`'s `spec.collectors.deniedPermissions` lists what the operator never grants, whatever the ceilings
  allow: `list` and `watch` on Secrets by default.
- `OperatorConfig`'s `spec.collectors.permissions` is `Grant`, the default, or `Check`. In `Check` the operator grants
  nothing, and reports what a collector's service account lacks as `MissingPermissions`, for a cluster whose RBAC is
  managed elsewhere.
- A collector that declares what the ceilings or the deny list don't allow isn't `Ready`, with the reason
  `PermissionsNotAllowed`, and gets nothing granted. [The guide to writing a collector](docs/collectors.md#rbac) has
  the details.
- The defaults give any `Collector` that you install what the scanner needs, when it declares it: `get` on every
  Secret in the cluster, by name, and `create`, `get` and `delete` on the Secrets of vexplain's namespace, where the
  LLM's API key, every collector's TLS key, the agent workers' client key and the key of the collectors' certificate
  authority live. The entries of
  the deny list that would close this refuse the scanner too
  ([what each costs](docs/collectors.md#what-the-defaults-give-any-collector)).
- The operator keeps the collectors' certificate authority in the Secret `vexplain-collector-ca` of its namespace, so
  that a restart keeps it and issues no collector's certificate again. A collector that may get Secrets in that
  namespace by name, as the defaults allow, could read its key, sign a client certificate as the operator, and call
  every collector. Where the cluster encrypts Secrets at rest, the key is encrypted on disk.
- The operator owns `vexplain-collector-ca`: don't create or edit it. A Secret of another type, or an immutable one,
  stops every call of a collector until it is deleted. To rotate the authority, for example after a suspected read of
  its key, delete the Secret and restart the manager: every collector's certificate is issued again, with a gap of
  about a minute.
- To grant, the manager may update and delete every ClusterRole and ClusterRoleBinding of the cluster, not only
  vexplain's. A delete isn't subject to Kubernetes' escalation check, and an update that narrows a role to rules that
  the manager holds passes it, so whoever controls the manager can remove or weaken any of them. For the rights that
  the manager holds for its own work, vexplain's own check is the only guard against granting them
  ([details](docs/collectors.md#the-ceilings)).

**The database's volume.** The vulnerabilities collector keeps its database on the volume claim
`vexplain-collector-vulnerabilities-db`, of 8 GiB and `ReadWriteOnce`, which the cluster's default storage class
provisions. A restart loads the database that the claim holds, and downloads nothing. Where the default class doesn't
fit, or the cluster has none, set `storageClassName` in `config/collectors/vulnerabilities-db.yaml` with a kustomize
patch. The collector updates the database every six hours, on its schedule `database`, and the annotation
`vexplain.bedag.ch/run-now` on its `Collector` runs that schedule at once ([how](docs/collectors.md#schedules-and-sources)).
`make undeploy` deletes the claim with the rest of the install.

> **NOTE**: If you encounter RBAC errors, you may need to grant yourself cluster-admin
privileges or be logged in as admin.

> **NOTE**: A cluster that has run phase 3a must delete the CRD `playbookcounts.inventory.vexplain.bedag.ch` before
installing: the kind is now `PlaybookClusterStatus`.

**Create instances of your solution**
You can apply the samples (examples) from the config/sample:

```sh
kubectl apply -k config/samples/
```

>**NOTE**: Ensure that the samples has default values to test it out.

### Reading what vexplain found

`kubectl get vexplain` lists every kind of vexplain, and `kubectl get vexplain-data` the data that its reports rest
on: `Evidence`, `ImageInventory`, `ImageVerdicts` and `PlaybookClusterStatus`. Each of them has columns that answer the first question of a
person, so no JSON is needed for it:

```sh
kubectl get resourcereports -A
# NAMESPACE   NAME             EXPOSURE     HIGHEST URGENCY   ACTIONS   CRITICAL   KNOWN EXPLOITED   PENDING   UNSCANNABLE   AGE
# team-a      deployment-web   Controlled   OutOfCycle        3         0          1                 0         0             3h

# Most urgent first: the rank is 1 for Immediate up to 4 for Defer, and sorts, as the names don't. A report with no
# vulnerability action has no rank, and kubectl sorts the rows without the field before all others, before Immediate.
kubectl get resourcereports -A --sort-by=.status.summary.urgencyRank

kubectl get imageinventories
# NAME           IMAGE                          WORKLOADS   NAMESPACES   SCAN STATE   OPEN   FIXABLE   AGE
# sha256-3f9c…   artifacts.example/team-a/web   1           1            Scanned      15     13        3h
```

An image is `Pending`, with the reason `Waiting`, until each playbook of its report has a verdict on it, so while a
report's `PENDING` is above 0 it isn't the whole answer yet: the `SCAN STATE` of those images' `ImageInventory` says
whether their scan still runs. An image whose last scan failed for a reason that may pass at the next attempt
(`PullFailed`, `TimedOut`, `Internal` or `NoEvidence`) waits too, and its `message` gives the last error. An image
that can't be scanned is `Unscannable` and gets no verdict until the cause is gone, so while a report's `UNSCANNABLE`
is above 0 it isn't the whole answer either. The image's `reason` and `message` in the report say why: `NoDigest` (an
image ID or an image without a digest), `PullRefused` (the registry refused the pull), `TooLarge` or `ScanFailed` (any
other failure, such as a failed catalog). `TooLarge` has three causes: the evidence is over the evidence store's cap,
and the `message` gives its size and the cap; the image unpacks to more than the scanner's workspace holds; or the
evidence is more than a message of the collector API holds, 16 MiB. Raising the evidence store's cap
([below](#the-evidence-stores-cap)) helps only the first. An image whose scan had a failed cataloger is `Incomplete`,
and its `message` names the cataloger. A workload in a namespace that no playbook's selectors select has no playbook
to judge its images, so they stay `Pending`, and its report never reads clean.

A workload's `ResourceReport` is a list of actions, most urgent first, and a summary that counts them. It holds the
results of every playbook whose selectors select the cluster and the workload's namespace, each action naming its
playbook as its requirement. An action is one package at one installed version in one image, and the next step for
it: `Update` where a version fixes it, `Mitigate` where it is affected and nothing fixes it, `Investigate` where no
rule has settled it and nothing fixes it. It names where it applies: the containers that run the image, as field
paths. The report of a workload `web` in the namespace `team-a` reads, in part:

```yaml
status:
  exposure: Controlled
  summary:
    actions: 3
    updates: 2
    changes: 0
    mitigations: 0
    investigations: 1
    omittedActions: 0
    highestSeverity: High
    highestUrgency: OutOfCycle
    urgencyRank: 2
    critical: 0
    knownExploited: 1
    pendingImages: 0
    unscannableImages: 0
  images:
  - digest: sha256:3f9c…
    manifestDigests: [sha256:8a41…]
    state: Ready
    containers: [web]
  actions:
  - step: Update
    title: Update libexample to 1.4.3
    locations: ["spec.template.spec.containers[web]"]
    severity: High
    urgency: OutOfCycle
    requirement: {playbook: container-cves}
    package: {name: libexample, version: 1.4.2, type: deb}
    fixedVersion: 1.4.3
    vulnerabilities: 1
    vulnerabilityIDs: [CVE-2026-0001]
    knownExploited: Listed
    digest: sha256:3f9c…
  - step: Investigate
    title: Investigate libother
    locations: ["spec.template.spec.containers[web]"]
    severity: Medium
    urgency: Scheduled
    requirement: {playbook: container-cves}
    package: {name: libother, version: 2.0.1, type: deb}
    vulnerabilities: 2
    vulnerabilityIDs: [CVE-2026-0002, CVE-2026-0003]
    knownExploited: NotListed
    digest: sha256:3f9c…
```

Actions merge only within one image: two images that hold the same package each have an action of their own, with
their own fixed version. A report lists at most 32 images, 256 actions, and 5 vulnerability IDs and 8 locations for
each action, and counts what it leaves out: `omittedActions` the actions, and an action's `vulnerabilities` its CVEs.

### How exposed a workload is

A finding's urgency follows how far the workload that runs it can be reached: SSVC's system exposure, `Open`,
`Controlled` or `Small`, or `Unknown`, which urgency counts as `Open`. Exposure changes urgency, never a verdict.

- **The reports on each cluster** take their `EXPOSURE` from what `network-reach` reports: whether something outside
  the cluster reaches the workload, and how far the rest of the cluster does.
- **The cases on the hub** take theirs from the exposure rules of their playbook: `Rule`s that conclude an exposure
  instead of a status ([0059](docs/decisions/0059-exposure-rules-on-the-hub.md)). `container-cves` runs the three that
  vexplain ships, which decide as the reports do:
  - `exposed-outside-cluster`: something outside the cluster reaches the workload, so it is `Open`;
  - `reachable-in-cluster`: it is reached beyond its namespace, or by an exposed workload one hop away, so it is
    `Controlled`;
  - `own-namespace-only`: only its own namespace reaches it, so it is `Small`.

  The highest value wins, in the order `Open`, `Unknown`, `Controlled`, `Small`. A rule that lacks its evidence, or
  fails, counts as `Unknown`, and so does a workload that no rule applies to. An investigation's results name each
  case's highest exposure, and the case file names the rules that decided it
  ([the agent's guide](docs/agent.md#how-a-case-is-judged)).

**A source of your own.** `network-reach` sees only the cluster: it can't tell whether the internet reaches a workload,
or only your own network does. A source can. It is a collector of your own that knows what is published, such as
what a DMZ's reverse proxies forward. `network-reach` names each exposed workload's entry points, the hosts and the
addresses with their ports through which it is reached from outside, and the hub asks each source about them
([what a source answers](docs/collectors.md#sources)). To use a source, in this order:

1. Install its `Collector`, and wait until it is `Ready`. Where it declares no `maxAge` for its type, set one in its
   `spec.produces`: without one, its answers never expire.
2. Apply its two exposure rules. For a type that says whether an entry point is published to the internet, one
   concludes `Open` unless every way in was asked about and none is published, and the other `Controlled` in
   exactly that case.
3. Add its type to the evidence of `container-cves`, under the name that its rules read it by, and put its two rules
   in place of `exposed-outside-cluster`.

A playbook isn't `Ready` while its evidence requires a type that no `Collector` produces, or its pipeline names a rule
that doesn't exist, and one that isn't `Ready` asks for no findings: hence the order. Taking out
`exposed-outside-cluster` assumes that the source knows every way in from the internet. Left in, it keeps every
exposed workload `Open`, the safe side. Without it, a workload whose entry point isn't answered yet, or whose answer
is past its `maxAge`, is `Unknown`, never lower. The reports keep their own exposure for now, so a case can say
`Controlled` where a workload's report still says `Open`.

### The evidence store's cap

The manager stores each collector's evidence compressed. `OperatorConfig` `spec.evidence.maxCompressedBytes` is the most
that one piece of evidence holds once compressed. It defaults to 786432 (768 KiB), and it is at least 65536 and at
most 1500000. The maximum is that low because the API server sends at most 2 MiB to etcd in one request, and the
`Evidence` object, whose data is base64 (at most 2000000 characters) and which carries its metadata, must fit in it. The
store reads the setting at each write, so a change applies to the next one. Evidence that is already stored is read
whatever the cap is. An image whose evidence is over the cap gets no verdict from that collector: its failure says
`TooLarge`, with `sizeBytes` and `capBytes`.

Each refusal raises the counter `vexplain_evidence_too_large_total{cluster, collector}` and a Warning event
`EvidenceTooLarge` on the image's `ImageInventory`, which names the collector, the size and the cap. Raising the cap above
the one that refused an image asks for its evidence again at once, without waiting out the back-off.

Streamed evidence of the scope `Hub` that is over the cap is dropped, logged with its size, and counted in
`vexplain_evidence_streamed_refused_total{cluster, collector, type, reason}` with the reason `TooLarge`. The hub lacks
its record until the collector sends it again, in a change or a snapshot, and it fits.

Past about 1.1 MiB compressed, etcd's own limit for a request, 1.5 MiB by default, must be raised as well (etcd's
`--max-request-bytes`, which kind allows through a `kubeadmConfigPatches` entry for etcd's `extraArgs`).

### Monitoring

Where the Prometheus Operator runs, uncomment the `[PROMETHEUS]` line of `config/default/kustomization.yaml`
(`#- ../prometheus`) before the install. The line is commented out because the `ServiceMonitor` kind needs the
Prometheus Operator's CRDs, and an install that includes it fails without them. `config/prometheus` then adds:

- `ServiceMonitor`s for the manager (`vexplain-controller-manager`), the agent workers (`vexplain-agent`) and the
  collectors (`vexplain-collectors`, on their port `http`, 8081)
- the service account `vexplain-metrics-scraper`, bound to `vexplain-metrics-reader`, and its token in the Secret
  `vexplain-metrics-scraper-token`, which the manager's and the workers' `ServiceMonitor`s send as their
  `authorization.credentials`, rather than reading `bearerTokenFile`, which managed Prometheus setups refuse. They skip
  the verification of the certificate that the manager signs itself.

The NetworkPolicies let in the scraper only from a namespace labelled `metrics: enabled`, so label the namespace of
the Prometheus that way. A Prometheus that selects `ServiceMonitor`s by label needs that label added to them, in an
overlay.

### Serving other clusters

`config/hub` and `config/spoke` install the manager in the modes `Hub` and `Spoke`, to serve several clusters from one hub. `config/default` stays the install of a single cluster. See [Remote spokes](docs/remote-spokes.md) for how to add a spoke.

### To Uninstall
**Delete the instances (CRs) from the cluster:**

```sh
kubectl delete -k config/samples/
```

**UnDeploy the operator and its collectors from the cluster:**

```sh
make undeploy
```

`make undeploy` deletes the `Collector`s first, while the operator runs: a `Collector` keeps the operator's finalizer
until the operator has removed the evidence that its collector delivered. It deletes the CRDs too, which
`config/default` holds.

**Delete the APIs(CRDs) from the cluster, when you installed them without deploying:**

```sh
make uninstall
```

## Project Distribution

Following the options to release and provide this solution to the users.

### By providing a bundle with all YAML files

1. Build the installer for the images built and published in the registry:

```sh
make build-installer IMG=<some-registry>/vexplain:tag AGENT_IMG=<some-registry>/vexplain-agent:tag \
  WORKLOADS_IMG=<some-registry>/vexplain-workloads:tag SCANNER_IMG=<some-registry>/vexplain-scanner:tag \
  VULNERABILITIES_IMG=<some-registry>/vexplain-vulnerabilities:tag \
  NETWORK_REACH_IMG=<some-registry>/vexplain-network-reach:tag \
  ADVISORIES_IMG=<some-registry>/vexplain-advisories:tag
```

**NOTE:** The makefile target mentioned above generates an 'install.yaml'
file in the dist directory. This file contains all the resources built
with Kustomize, which are necessary to install this project without its
dependencies.

2. Using the installer

Users can just run 'kubectl apply -f <URL for YAML BUNDLE>' to install
the project, i.e.:

```sh
kubectl apply -f https://raw.githubusercontent.com/<org>/vexplain/<tag or branch>/dist/install.yaml
```

The bundle holds the CRDs and the `Collector`s, rules and playbook of the kinds that they define. An apply that
creates the CRDs can report `no matches for kind` for those: apply the bundle again once the CRDs are established.

### By providing a Helm Chart

1. Build the chart using the optional helm plugin

```sh
kubebuilder edit --plugins=helm/v2-alpha
```

2. See that a chart was generated under 'dist/chart', and users
can obtain this solution from there.

**NOTE:** If you change the project, you need to update the Helm Chart
using the same command above to sync the latest changes. Furthermore,
if you create webhooks, you need to use the above command with
the '--force' flag and manually ensure that any custom configuration
previously added to 'dist/chart/values.yaml' or 'dist/chart/manager/manager.yaml'
is manually re-applied afterwards.

## Contributing
// TODO(user): Add detailed information on how you would like others to contribute to this project

**NOTE:** Run `make help` for more information on all potential `make` targets

More information can be found via the [Kubebuilder Documentation](https://book.kubebuilder.io/introduction.html)

## License

Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

