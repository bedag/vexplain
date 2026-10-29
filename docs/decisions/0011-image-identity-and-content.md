# 0011 Image identity from running pods; content pulled by digest, registry-agnostic

- **Status:** Accepted (revised 2026-10-29 in design revision 4: reported digest vs. platform manifest digest, init containers; confirmed by the owner. Scanning moves to the spokes with 0021.)
- **Date:** 2026-10-29

## Context

The operator cares about what is actually running, not about any particular registry. Tags move, so a tag doesn't say what is running. Kubescape already holds SBOMs and vulnerability data, but it is optional (0002). Some checks (symbol search, linkage, `govulncheck`) need the image's files, which no Kubernetes resource contains.

The digest a container runtime reports isn't always the digest of what gets scanned:

- For a multi-arch image pulled by tag, the runtime reports the **index** digest, which covers several platforms.
- For an image without a repository digest (for example, loaded locally), it reports the **image ID**, the config digest. A registry can't fetch that.

## Decision

- **Identity:** the `Workloads` collector reads `imageID` from each pod's container and init-container statuses. Ephemeral debug containers are skipped. `ImageInventory` is keyed on this **reported digest** and records its kind: `RepoDigest` or `ImageID`.
- **What gets scanned:** from phase 2, the scanner resolves a repository digest, together with the platforms of the nodes running it, into **platform manifest digests**. Image facts and assessments are keyed on those, so two tags or indexes that point to the same manifest share one assessment.
- **Reuse before pulling:** when the `Kubescape` collector is on, its SBOMs and vulnerability manifests are used and no fresh scan runs.
- **Content, when needed, is pulled by digest from wherever the pod pulled it.** The operator authenticates the way the kubelet does: the pod's and service account's `imagePullSecrets`, through `go-containerregistry`'s `k8schain`. No registry is configured or special-cased. A digest is content-addressed, so the bytes are exactly what is running.
- **An image ID can't be pulled,** so its content stays unknown. That counts as "can't be shown", never as "not affected".
- **Pull secrets are used only to authenticate pulls.** They are never logged, stored or sent to the LLM.
- **Pulls happen once per digest,** and the result is cached.

## Consequences

- Works with any registry and any platform.
- **Multi-cluster:** pull credentials live where the workload runs. 0021 resolves this: the hub asks one spoke that runs the digest to scan it, so credentials never leave their cluster.
- Reading from the node's container runtime was considered and rejected: it needs a privileged DaemonSet on every node and fails once layers are garbage-collected.
