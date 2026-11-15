# vexplain — Phase 3a's fixes

- **Status:** accepted by the owner on 2026-11-15.
  - The owner accepted the fixes of sections 2.1 to 2.7 on 2026-11-14, after phase 3a's live run.
  - The owner decided section 2.8 on 2026-11-15, accepting its cost.
  - Section 3 is the designer's.
- **Date:** 2026-11-15
- **Author:** Joshua Leuenberger
- **Extends:** the [collector model](2026-11-08-collector-model.md) (phase 3a) and the [main design](2026-10-29-vexplain-design.md) from its revision 16. Decision record [0050](../decisions/0050-agent-before-generalization.md) puts this phase before the agent.

Statements marked **[call]** are the designer's, not the owner's. They are the first candidates to revisit.

---

## 1. Intent

Phase 3a's live run on a shared cluster mostly worked, but a few things read wrong or can't be read at all. This phase fixes them before the agent (phase 4) judges image cases on top. An agent built on wrong coverage, or on a gap in matching after every restart, would carry those errors into its verdicts.

- **Goals:** each fix below, and a live run that shows it.
- **Non-goals:**
  - a new use case;
  - the SOC's view (the action metric, the plan dashboard and the CVE lookup), which comes with the agent (main design, 6.10);
  - anything of phase 3b.
- **Anti-goal:** a fix that lets a finding settle on less evidence than before. Every fix holds at least as much as today, except where a failed part could never have shown the finding (2.1, 2.2).

## 2. The fixes

### 2.1 Coverage counts a file once, by its content

- **What the run showed:** in a busybox image, `/bin` holds about 400 links to one binary. Each link counted as an ELF file that no package owns, so completeness fell to 0, and the completeness guard held every finding of several images.
- **The fix:** the scanner counts a file once. A file is identified by its links, not by its content **[call]**:
  - a hard link or a symlink counts as the file it points to, so a link to an owned file is owned;
  - two separate files with the same content stay two files, so a copy of an owned binary stays unowned. Counting by content would loosen the guard.
- **The test that must hold:** an image with a copied, unowned binary keeps its completeness low.
- **Precedent:** `du` counts a hard-linked file once.

### 2.2 A failed cataloger holds only what it could have found

- **What the run showed:** the cataloger for .NET dependencies failed on some images and set their coverage to 0. That held all their findings, in images where no .NET code matters.
- **The fix:**
  - a failed cataloger holds only the findings in the package types it catalogs;
  - a cataloger that vexplain can't map to package types still holds everything, as today.
- **How [call]:**
  - the scanner names the package types of each failed cataloger in its evidence;
  - the completeness guard holds a finding when its package's type is among them;
  - a failed cataloger no longer sets the image's coverage to 0, and the image's state still lists it, so the failure stays visible.
- **Why it stays safe:** a finding that only the failed cataloger's packages could show never reads as settled.

### 2.3 Every image without a verdict says why

- **What the run showed:** images that the scanner couldn't pull (`Unauthorized`) read as `Pending` in their reports. Their owners waited for a scan that had already failed. The reason was only in the cluster-scoped inventory.
- **The fix:** the report names the reason for each image without a verdict:
  - waiting for its scan;
  - the pull was refused, with the registry;
  - over the evidence store's cap, with the size and the cap (2.7);
  - no digest.
- **The shape [call]:** each such image carries a reason (`Waiting`, `PullRefused`, `TooLarge` or `NoDigest`) and a message: the registry for a refused pull, and the size and the cap for `TooLarge`.
  - The scanner's refused pulls (no access, not found) read `PullRefused`. A transient error keeps `Waiting`, with the last error.
  - The renderer takes the reason from the image's inventory entry, where the scan's failure is today.
  - The registry's name is safe to show: the owner's own pod names it.
  - (*Amended on 2026-11-15, while planning:* a failure that is neither a refused pull nor over the cap, such as a failed catalog or no platform that matches, reads `ScanFailed`, with the failure's reason.)
- **The counts:** `unscannableImages` counts the failures, and `pendingImages` only the images still waiting.
- 0014 already asks that every "no verdict" comes with a summary.

### 2.4 The manager waits quietly, and skips namespaces being deleted

- **What the run showed:**
  - hundreds of errors at the manager's start, while a collector downloaded its database;
  - report creates refused in namespaces being deleted, many of them in one night, on a cluster whose test suites create and delete namespaces.
- **The fix:**
  - a collector that isn't ready yet is waited for, with back-off, and logged once;
  - the renderer skips a namespace whose deletion has begun. Its reports go with it.

### 2.5 A numeric urgency rank in the report's summary

- **What the run showed:** `kubectl --sort-by=.status.summary.highestUrgency` sorts by name, which only happens to match the urgency. `Defer` would sort first.
- **The fix:** the summary also carries the urgency as a number, so that sorting by it is reliable.
  - It's a new field next to `highestUrgency`, set exactly when that is set **[call]**.
  - It stays in `v1alpha1`, with no version bump.

### 2.6 `PlaybookCounts` becomes `PlaybookClusterStatus`

- **Why:** the kind reads like a view, but it's the spoke's transport of one playbook's counts for one cluster. The view is the `Playbook`'s status.
- **The fix:** rename the kind. It stays in the `vexplain-data` category.
  - Everything that names the kind follows: its short names, columns and RBAC, the `PROJECT` file, the tests and the docs.
  - The API group and the Go package stay.
  - A fresh install needs no migration. A live cluster drops the old CRD before the new install.
- **Precedents:**
  - Gatekeeper's `ConstraintPodStatus`: one status object per writer, aggregated into the constraint's status;
  - Kyverno's `EphemeralReport`, which its reports controller merges.
- **For a fleet (phase 6):** these objects go into a namespace per cluster on the hub, so that a spoke can only write its own, as Open Cluster Management and Karmada do.

### 2.7 The evidence store's cap is a setting, shown plainly

- **Why:** on phase 3a's test set, a large Java image's SBOM passed the cap, so the image got no verdict. The owner asked for a setting that a test can raise, and for the limit to be well visible (2026-11-14).
- **The fix:**
  - the cap is a field of `OperatorConfig` **[call]**, with today's 768 KiB, compressed, as the default;
  - an image over the cap says so in its report (2.3), with its size and the cap;
  - a metric counts the images over the cap, and an event on the image's `ImageInventory` entry names each one;
  - only the manager's evidence store enforces the cap, so only the manager reads the setting. (*Amended on 2026-11-15, while planning:* the scanner kept its own copy of the cap. That copy goes, and the scanner bounds only what its transport carries.);
  - raising the cap retries the images that were over the old one **[call]**.
- **Its bound:** etcd's limit for a request, 1.5 MiB by default. Evidence is stored as base64, so past about 1.1 MiB compressed, etcd's limit must be raised as well, as a kind cluster allows. (*Added on 2026-11-15, while planning:* the API server takes at most 3 MiB in a request, so the setting stops at 2 MiB.) (*Amended on 2026-11-15, while building:* the API server's client to etcd sends at most 2 MiB in a request, so the setting stops at 1,500,000 bytes, and an Evidence object's data at 2,000,000 characters.)

### 2.8 The collectors' certificate authority survives a restart

- **What a spike showed:** the manager makes a new certificate authority at every start, and reissues every collector's certificate. Until each collector reloads its files, matches fail, for about 90 s.
- **The fix** (owner, 2026-11-15, with the cost below):
  - the manager keeps the authority's key and certificate in a Secret in its own namespace, which only it uses;
  - at start it loads the authority, and makes a new one only when the Secret is missing or the authority is near its end;
  - collectors' certificates are renewed 30 days before they end, as today, and no longer at every start;
  - the manager already creates and updates Secrets in its namespace, for the collectors' certificates. It creates the authority's Secret only if it's absent, and a manager that loses that race loads the winner's **[call]**;
  - the authority lives for years, as today. Before its end, a new one is made, and both are trusted until every collector's certificate is reissued, as Kubernetes rotates its own CA with a bundle **[call]**. (*Amended on 2026-11-15, while planning:* the authority lives 10 years, so in its last 90 days it is replaced like a missing one, with one gap like today's. Trusting both comes if that gap matters.)
- **The cost:** the authority's key is stored at rest, and the manager isn't its only possible reader.
  - The scanner may get any Secret by name, to read pull secrets, so it could read this one too.
  - With the key, it could sign any certificate, including a client certificate as the manager, and with that call every collector. Today it can read only the collectors' server keys. Phase 2b kept the key in memory for this reason ([the design of collectors, evidence and rules](2026-10-31-collectors-evidence-rules.md), 5.3). (*Corrected on 2026-11-15, while planning.*)
  - etcd's encryption at rest, where the cluster has it, protects the key on disk.
- **Precedents:**
  - Gatekeeper and Kyverno keep the certificate authority of their webhooks in a Secret;
  - cert-manager's CA issuer reads its key from one.

## 3. The cluster settings, tested in this phase **[call]**

The owner planned a closer test of the cluster settings after phase 3b. Phase 3b now comes after the agent, so they are tested in this phase's live run, and the agent starts on realistic data. They are settings, so no code is expected. Each has its check:
- **Trusted peers:** reach narrower than `Namespaces` shows for workloads behind them.
- **`adminPullSecrets`:** the refused images get scanned.
- **The vulnerability database across a restart of its collector:** it isn't downloaded again.
- **Scoping out demo and test namespaces:** they get no reports. A single demo image made a large share of the actions.

## 4. Then a live run

The owner runs it on the shared cluster, as for phase 3a. The plan's tasks are tested on kind. Phase 4's plan starts after this run.

With the settings of section 3, the run checks:
- the completeness guard's holds, against phase 3a's run;
- every image without a verdict, with its reason;
- the manager's log at start;
- a manager restart without failed matches;
- the cap raised for the large Java image.

## 5. Left to the builder

- The rank's values, the cap's field name, and the name of the authority's Secret.
- Whether the store's limit before compression grows with the cap.
- The mapping from catalogers to package types.
