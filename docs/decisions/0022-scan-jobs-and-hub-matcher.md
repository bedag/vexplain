# 0022 Scans run as a Job per image on the spoke; CVE matching runs once, at the hub

- **Status:** Accepted (decided by the owner on 2026-10-30)
- **Date:** 2026-10-30
- **Refines:** 0011 and 0021. It settles the choice that design section 8 left to the builder: Syft and Grype as libraries in the operator, or as binaries in a Job.

## Context

The built-in `Scanner` (phase 2) needs an image's files for several checks:
- the SBOM with file ownership
- `DT_NEEDED` linkage and the search for library names
- Go build info and `govulncheck`

It also needs a vulnerability database to match the packages against.

Running all of that inside the operator has three problems:
- The operator would parse image content from anywhere in the same process that holds the LLM key and reads Secrets.
- One large image could run the operator out of memory, which stops every role it has.
- Syft and Grype bring large dependency trees into the module that controller-runtime pins.

Two projects solved the same problem and ended up splitting it the same way:
- **Trivy Operator** runs a Job per scan in its own namespace.
  - It copies the workload's pull secrets into a temporary Secret owned by the Job, and reads the result from the Job's log.
  - Downloading the database in every Job turned out to be its least efficient mode, so it added a Trivy server that holds one database for all Jobs.
- **Kubescape** builds SBOMs in a privileged agent on every node, and matches them in a long-running service, `kubevuln`.

Both keep the work on each image short-lived and isolated, and the vulnerability database in one long-running place.

The rescans after each update of the vulnerability database are the write load that decision 0004 worries about most.

## Decision

- **Spoke: a Job per image to scan, for everything that needs the image's files.**
  - The Job runs in the operator's namespace, from a scanner image of our own. The image holds Syft, `debug/elf` for linkage and library names, and `golang.org/x/vuln` for `govulncheck`.
  - It resolves the reported digest to the platform manifest digests of the nodes running it (0011), and scans each of them.
  - **Credentials:**
    - It pulls by digest, with the credentials for that one image in a short-lived Secret. The Job owns the Secret, so it is deleted with the Job.
    - The operator assembles the credentials the way the kubelet authenticates (0011): the pod's `imagePullSecrets`, those of its service account, and any the admin adds.
  - The pod has no access to the Kubernetes API (no service account token) and no LLM key. It writes one compact JSON result to its log, and the operator reads it from there.
  - Each Job has its own resource limits, and the number of scan Jobs running at once is bounded.
- **Hub: one long-running matcher holds Grype's vulnerability database.**
  - It matches each image's package list and gives the CVE matches to the hub's rules.
  - When the database updates, it matches the stored package lists again. No image is pulled again.
  - There is one database per hub, not one per scan or per cluster. The matcher updates it through the proxy.
  - It runs as its own Deployment next to the operator, so Grype's dependencies and memory stay out of the operator.
- **The scan result** that goes to the hub carries:
  - the platform manifest digests
  - the package list
  - completeness
  - linkage and library-name hits
  - the Go facts

  It carries no CVEs. The package list is kept for matching again, behind the storage interface (0004). Decision 0023 says where.

## Consequences

- **Isolation:**
  - Image content from anywhere is parsed only in throwaway pods, and those pods hold neither an API token nor the LLM key.
  - The operator's memory stays predictable. Scans scale out as Jobs, within the limit on how many run at once.
- **Two more things to build, ship and run:** the scanner image and the matcher.
  - They ship with the operator, at the same version.
  - They build as their own Go modules in this repository, so the operator's module never takes on Syft's or Grype's dependencies.
  - The `Scanner` is still a built-in collector in the sense of 0007: its code lives in the operator, and its tools run in an image of ours.
- **Pull credentials** are copied into the operator's namespace for as long as a scan runs.
  - That is the pattern 0008 already accepts for sandbox runs.
  - The label rule of 0017 keeps whoever writes a `ModelConfig` away from them.
- **RBAC:**
  - In its own namespace, the operator creates Jobs and Secrets and reads pod logs.
  - Elsewhere it reads pull secrets and service accounts with `get` only (design 6.11).
- **The matcher is a hub component,** so a cluster in `Spoke` mode runs none (phase 6).
- **Rejected:**
  - **Scanning inside the operator,** for the three reasons above.
  - **Downloading the database in every scan Job.** It's slow, and every database update would mean pulling every image again.
  - **Reading images on the node,** as Kubescape's node agent and Trivy's filesystem mode do. It avoids credentials, but it needs privileged access to every node, or root in the scan pod, as 0011 already found.

## Sources

- **Trivy Operator:**
  - [scanner configuration: Standalone, ClientServer, built-in Trivy server](https://aquasecurity.github.io/trivy-operator/latest/docs/vulnerability-scanning/trivy)
  - [private registries: copied pull secrets, results from the Job's log](https://aquasecurity.github.io/trivy-operator/latest/docs/vulnerability-scanning/private-registries)
- **Starboard, Trivy Operator's predecessor:**
  - [design: filesystem scanner on the workload's node](https://aquasecurity.github.io/starboard/v0.15.12/design/design_trivy_file_system_scanner/)
  - [design: scan Jobs in the workload's namespace](https://aquasecurity.github.io/starboard/latest/design/design_vuln_scan_job_in_same_namespace_of_workload/)
- **Kubescape:**
  - [CNCF self-assessment: operator, kubevuln, node agent, storage](https://tag-security.cncf.io/community/assessments/projects/kubescape/self-assessment/)
  - [kubevuln](https://github.com/kubescape/kubevuln)
  - [node-agent](https://github.com/kubescape/node-agent)
