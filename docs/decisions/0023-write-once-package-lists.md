# 0023 Package lists are kept write-once per platform manifest digest, in their own inventory kind

- **Status:** Accepted (decided by the owner on 2026-10-30). The phase 2a plan keeps all of a manifest's scan evidence in `ImagePackages` (0026), not just the package list, so that later rules can use it without pulling again.
- **Date:** 2026-10-30
- **Refines:** 0022, by saying where the package list is kept. It applies 0004's "one storage interface per bulky kind".

## Context

0022 moves CVE matching to the hub, and the matcher matches again whenever the vulnerability database updates. That needs each image's package list after the scan.
- **Derived data:** package lists are bulky data that can always be rebuilt by scanning again (0004).
- **Not in `ImageInventory`:** every cluster rewrites `ImageInventory` on every change in presence. Package lists there would bloat each of those writes.

Projects that keep scan data in Kubernetes ran into etcd, with two problems: the size of an object, and churn, because every update of an object is a new revision in etcd.
- **Trivy Operator**
  - It keeps its reports as CRDs, split per container to stay under etcd's 1.5 MiB per object.
  - Reports are rewritten on every rescan. At scale that exhausted etcd, and users of managed clusters can't raise its limits.
  - It added optional storage on a volume, trimmed fields from reports, and gave reports an expiry time.
- **Kyverno**
  - It started with policy reports as CRDs.
  - It moved them to `reports-server`, an aggregated API server backed by Postgres, its own etcd or memory.
  - Its reasons: etcd's size ceiling, API server strain when reports churn, and poor querying. Reports can be regenerated, so they don't need etcd's guarantees.
- **Kubescape** keeps SBOMs and vulnerability data in its own aggregated API server, as files and SQLite on a volume, from the start.
- **Helm**
  - It stores each release gzipped in a Secret.
  - Secrets are capped at 1 MiB, so it added a SQL backend for larger releases.
- **Dependency-Track** keeps the component inventory in its own database and matches it again whenever its vulnerability feeds update. That is the model of 0022's matcher.

## Decision

- **A new kind in the `inventory` group, `ImagePackages`,** holds the package list of one platform manifest digest.
  - There is one object per platform manifest digest, named from the digest the way `ImageInventory` is.
  - It holds the list as gzip-compressed JSON, the way Helm stores a release, together with the version of the scanner that produced it.
- **The object is written once.** A manifest digest's content can't change, so the object is never updated. It is replaced only when a new scanner version scans the image again.
- **CVE matches live only in the `ImageVerdicts` sheet,** not in `ImageInventory`. After a database update, the hub writes only the sheets whose outcome changed.
- **References and the door:**
  - `ImageInventory`'s image facts refer to the `ImagePackages` of each platform manifest digest.
  - Only `ImagePackages`' own storage interface reads or writes it (0004).
  - It is deleted once no `ImageInventory` refers to it any more.
- **Measured, then decided:**
  - Phase 2a's measurement records the compressed sizes.
  - 0004's triggers apply to this kind as to every inventory object.
  - When one fires, the first move is the one Kyverno and Kubescape made: an aggregated API server for the `inventory` group, with its own database. Object storage referenced by digest stays the other option (0004).

## Consequences

- **No churn from package lists:** there is one write per manifest digest and scanner version.
- **The write load of a database update** is the verdict sheets that changed. That is what 0004's write-rate trigger watches.
- **Not readable with `kubectl`:** compressed JSON isn't readable directly, as with Helm's releases. The store decodes it, and a small read command can too.
- **Rejected:**
  - **Package lists in `ImageInventory`:** they would bloat every presence write.
  - **A volume on the matcher,** like Trivy Operator's optional storage. It would take the data out of the Kubernetes API, which is how spokes deliver their results (0021), and tie it to one pod.
  - **Our own aggregated API server now:** 0004 starts with CRDs and switches on real data, so building one before a trigger fires is premature.

## Sources

- Trivy Operator:
  - [settings, `alternateReportStorage`](https://aquasecurity.github.io/trivy-operator/latest/settings)
  - [FAQ: reports split per container](https://trivy.dev/v0.28.1/docs/kubernetes/operator/vulnerability-scanning/faq)
  - [issue: persisting reports outside the cluster](https://github.com/aquasecurity/trivy-operator/issues/441)
- Aqua: [solving Trivy's etcd exhaustion problem](https://aquasec.com/blog/when-security-scans-break-the-brain-solving-trivys-etcd-exhaustion-problem/)
- Kyverno:
  - [reports-server](https://github.com/kyverno/reports-server)
  - [CNCF: Kyverno's report server](https://www.cncf.io/online-programs/cloud-native-live-kyvernos-report-server-a-new-approach-to-policy-report-management/)
- Kubescape: [CNCF self-assessment](https://tag-security.cncf.io/community/assessments/projects/kubescape/self-assessment/)
- Helm:
  - [proposal on releases over 1 MiB](https://github.com/helm/community/pull/256)
  - [SQL storage backend](https://github.com/helm/helm/commit/1a003884c007068b8b023a09f292ed7b4c36237b)
- [OWASP Dependency-Track](https://owasp.org/dependencytrack)
