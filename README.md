# vexplain
// TODO(user): Add simple overview of use/purpose

## Description
// TODO(user): An in-depth paragraph about your project and overview of use

## Getting Started

### Prerequisites
- go version v1.26+
- docker version 17.03+.
- kubectl version v1.11.3+.
- Access to a Kubernetes v1.11.3+ cluster.

### To Deploy on the cluster
**Build and push your images to the locations specified by `IMG`, `WORKLOADS_IMG`, `SCANNER_IMG`, `MATCHER_IMG`
and `EXPOSURE_IMG`:**

The operator is one image, and each built-in collector is an image of its own, which its `Collector` installs as
its package: `workloads` reports which workloads run which images, `scanner` scans an image in a Job that runs its
image, `matcher` matches what the scanner found against its vulnerability database, and `exposure` reports how far
each workload can be reached.

```sh
make docker-build docker-push IMG=<some-registry>/vexplain:tag \
  WORKLOADS_IMG=<some-registry>/vexplain-workloads:tag SCANNER_IMG=<some-registry>/vexplain-scanner:tag \
  MATCHER_IMG=<some-registry>/vexplain-matcher:tag EXPOSURE_IMG=<some-registry>/vexplain-exposure:tag
```

To place pods on nodes, set `nodeSelector` and `tolerations` for the manager through a kustomize patch, for the collectors in their runtime config's `deploymentTemplate`, and for scan pods in the scanner's `scanPod.nodeSelector` and `scanPod.tolerations` ([how](docs/collectors.md#placing-pods-on-nodes)).

Each collector reports `VERSION` as its version, which is the commit that `git describe` names unless you set it.
vexplain stores a collector's evidence at its version, so a collector rebuilt under a new version replaces what the
one before it delivered.

The install sets no proxy: vexplain can't know one, and the operator passes none of its own environment to a collector. A collector gets a proxy from its runtime config, as [the guide to writing a collector](docs/collectors.md#the-runtime-config) shows. The matcher downloads its database through the proxy that its runtime config sets, so where it reaches its database only through a proxy, set one on the container `collector` in the `matcher` runtime config. An install that relied on the operator's proxy for its collectors must set it in the runtime configs now: the matcher's, and `default` for the others that need one. The scan Jobs that the scanner creates are not shaped by a runtime config, and no longer inherit the scanner's proxy: for registries that are reachable only through a proxy, set `settings.scanPod.env` on the `scanner` Collector, where a variable may come from a Secret too (`valueFrom.secretKeyRef`). For a cluster without internet,
`MATCHER_DB=true` bakes the database into the matcher's image, of about 3.5 GB, and the `Collector` `matcher` then
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
make deploy IMG=<some-registry>/vexplain:tag \
  WORKLOADS_IMG=<some-registry>/vexplain-workloads:tag SCANNER_IMG=<some-registry>/vexplain-scanner:tag \
  MATCHER_IMG=<some-registry>/vexplain-matcher:tag EXPOSURE_IMG=<some-registry>/vexplain-exposure:tag
```

The install, `config/default`, holds:

- the operator, in the namespace `vexplain-system`, which enforces the restricted Pod Security Standard
- the `Collector`s `workloads`, `scanner`, `matcher` and `exposure` (`config/collectors`), which the operator deploys as
  `vexplain-collector-<name>`, with the RBAC that each needs and the runtime config of the matcher
- the default rules (`config/rules`) and the default playbook `container-cves` (`config/playbooks`)
- NetworkPolicies (`config/network-policy`): only the manager's pods reach the collectors' API on port 9443, and
  only the pods of namespaces labelled `metrics: enabled` reach the manager's metrics

**Phase 2b needs a fresh install.** Undeploy an install of an earlier phase with the `make undeploy` of its own
commit before you deploy this one. Applied over an earlier install, this one leaves behind what it no longer has:

- the CRD `imagepackages.inventory.vexplain.bedag.ch` and its `ImagePackages` objects: the scanner's evidence is
  `Evidence` now
- the matcher of `config/matcher`, in `vexplain-system`: the Deployment and the Service `vexplain-matcher`, and the
  NetworkPolicy `vexplain-allow-manager-to-matcher`. The `Collector` `matcher` runs the matcher now
- `OperatorConfig.spec.rules.minCompletenessPercent`, which the API server prunes: the minimum completeness is the
  condition of the rule `completeness-guard` now, at 90%

The shape of a `WorkloadReport`'s status (actions and a summary) and the summaries and columns of the data kinds are
new in this phase too, and an install of an earlier phase can't be upgraded in place: install fresh.

> **NOTE**: If you encounter RBAC errors, you may need to grant yourself cluster-admin
privileges or be logged in as admin.

**Create instances of your solution**
You can apply the samples (examples) from the config/sample:

```sh
kubectl apply -k config/samples/
```

>**NOTE**: Ensure that the samples has default values to test it out.

### Reading what vexplain found

`kubectl get vexplain` lists everything that vexplain makes, and `kubectl get vexplain-data` the data that its
reports rest on: `Evidence`, `ImageInventory` and `ImageVerdicts`. Each of them has columns that answer the first
question of a person, so no JSON is needed for it:

```sh
kubectl get workloadreports -A
# NAMESPACE   NAME             EXPOSURE     HIGHEST URGENCY   UPDATES   TO INVESTIGATE   CRITICAL   KNOWN EXPLOITED   AGE
# team-a      deployment-web   Controlled   OutOfCycle        2         1                0          1                 3h

kubectl get imageinventories
# NAME           IMAGE                          WORKLOADS   NAMESPACES   SCAN STATE   OPEN   FIXABLE   AGE
# sha256-3f9c…   artifacts.example/team-a/web   1           1            Scanned      14     9         3h
```

A `WorkloadReport` is a list of actions for one workload, most urgent first, and a summary that counts them. An
action is one package at one installed version, and the next step for it: `Update` where a version fixes it,
`Mitigate` where it is affected and nothing fixes it, `Investigate` where no rule has settled it and nothing fixes
it. The report of a workload `web` in the namespace `team-a` reads, in part:

```yaml
status:
  exposure: Controlled
  summary:
    affected: 12
    underInvestigation: 3
    actions: 3
    updates: 2
    mitigations: 0
    investigations: 1
    omittedActions: 0
    highestUrgency: OutOfCycle
    critical: 0
    knownExploited: 1
  actions:
  - step: Update
    package: {name: libexample, version: 1.4.2, type: deb}
    fixedVersion: 1.4.3
    severity: High
    urgency: OutOfCycle
    knownExploited: Listed
    vulnerabilities: 1
    vulnerabilityIDs: [CVE-2026-0001]
    digests: [sha256:3f9c…]
  - step: Investigate
    package: {name: libother, version: 2.0.1, type: deb}
    severity: Medium
    urgency: Scheduled
    knownExploited: NotListed
    vulnerabilities: 2
    vulnerabilityIDs: [CVE-2026-0002, CVE-2026-0003]
    digests: [sha256:3f9c…]
```

The summary counts an open finding once for each vulnerability and package of the workload, as the metrics do. A
report lists at most 256 actions, 5 vulnerability IDs for each and 8 digests, and `omittedActions` counts the actions
that it leaves out.

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
make build-installer IMG=<some-registry>/vexplain:tag \
  WORKLOADS_IMG=<some-registry>/vexplain-workloads:tag SCANNER_IMG=<some-registry>/vexplain-scanner:tag \
  MATCHER_IMG=<some-registry>/vexplain-matcher:tag EXPOSURE_IMG=<some-registry>/vexplain-exposure:tag
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

