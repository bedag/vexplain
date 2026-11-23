# vexplain — Phase 4's fixes after the first live run, and the agent workers

- **Status:** accepted by the owner on 2026-11-20, with the plan that builds it.
  - The owner asked for every fix of section 2 on 2026-11-20, after phase 4's first live run.
  - Section 3 shapes the agent workers of decision record [0057](../decisions/0057-agent-workers.md), which the owner accepted on 2026-11-20.
  - Sections 5 and 6 add the core prompt's `v6` and `v7`, after the second and third live runs. The owner picked them on 2026-11-20.
  - Section 7 is the final improvement round after the fourth live run: core `v8`, the board's series and the investigation's event. The owner asked for it on 2026-11-21.
  - The shapes marked **[call]** are the designer's. They are the first candidates to revisit.
- **Date:** 2026-11-20
- **Author:** Joshua Leuenberger
- **Extends:** [the agent on image cases](2026-11-16-agent-on-cases.md) from its revision 2. Section 5.3 (the `Investigation`'s status), 5.4 (the queue), 5.5 (where the safety core runs), 5.7 (tools) and 5.8 (`describe` and `fetch`) point here for what changes.

---

## 1. Intent

The agent judged its first cases on a shared cluster. The machinery worked end to end. What the agent spent its tokens on, and what the SOC could read of the result, didn't:
- the tools gave the agent too little, or too much: a fetch that failed without a cause, and answers of `describe` of up to megabytes, of which the agent saw 16 KB;
- every case spent its first step finding `describe`, and further steps finding each package's purl in the SBOM;
- every result's reason read the same;
- the `Investigation`'s counts mixed the cases it selected with those it didn't;
- cases of images that run nowhere were judged;
- the agent judged cases whose fix the matcher already knew;
- the metrics had no working way to be scraped.

This note fixes those, and builds the agent workers of 0057.

- **Goals:** each fix of section 2, the workers of section 3, and a live run that shows them.
- **Non-goals:**
  - what the agent is asked, beyond the summary's first sentence. That is [its own draft](2026-11-20-what-the-agent-is-asked.md), for the owner's review;
  - reports that show the agent's verdict (main design 6.10);
  - a wider "not affected".
- **Anti-goals:**
  - an answer of `describe` that leaves out a `No` or a `Yes` for a package it was asked about;
  - a case that two workers judge at once, or one that no worker ever judges again after its worker died;
  - an error text that carries a proxy's address or credentials to the model.

## 2. The fixes

### 2.1 `fetch`: an Accept header, the cause of a failure, and the allowlist

- **What the run showed:**
  - a host answered 406 to a request without an `Accept` header, and to `*/*`;
  - when a proxy refused a host, the agent read only "the page could not be fetched";
  - `www.cve.org` serves a page that shows its text only through JavaScript, so a fetch of it holds no advisory.
- **The fix:**
  - Every request sends `Accept: text/html, application/json;q=0.9`. These are the types that `fetch` reads best.
  - A failed fetch names its cause, in fixed words. The error's own text never goes to the model, since it may hold the proxy's address with its credentials **[call]**:
    - "the proxy refused the host, with HTTP status N";
    - "the proxy could not be reached";
    - "the host's name does not resolve";
    - "the host's certificate is not trusted";
    - "the host could not be reached";
    - anything else stays "the page could not be fetched".

    A host's own non-2xx answer already names its status. The reasons (`FetchFailed`, `NotFound`, `TimedOut`, `NotAllowed`) stay as they are.
  - **How [call]:** the transport's `OnProxyConnectResponse` hook sees the proxy's answer to `CONNECT`, and turns a refusal into an error that keeps its status. Go's own error for it holds only the status text.
  - **The default allowlist:**
    - `www.cve.org` leaves it;
    - `go.dev` joins it, since Go's advisories cite its issue pages **[call]**. Its issue links redirect to `github.com`, which the list holds. Its change links redirect to a host that it doesn't hold, so `fetch` refuses them, as it refuses every hop to a host off the list.
  - A proxy that refuses a host on the default list is the platform's matter. The operator narrows `allowedDomains`, and the agent now reads why a fetch failed **[call]**.

### 2.2 `describe` answers for the packages it was asked about

- **What the run showed:**
  - An answer listed every provider's entry for the vulnerability: each release of each distribution, and each ecosystem. For a vulnerability of Go's standard library it reached megabytes, of which the agent saw the first 16 KB, the default page.
  - Two cases asked again by the vulnerability's Go or GitHub ID. Grype's records of those IDs name the CVE as an alias, but the CVE's own records don't name them, so a search by the CVE can't find them.
  - A package with a `pkg:generic` purl, as Syft writes for a binary it recognizes, was refused.
- **The fix:**
  - **`providers` lists the entries that answer.** An entry answers when it speaks for an asked package's distribution or ecosystem and names the package. Those are the entries whose `fixedForInstalled` can be `Yes` or `No`.
    - For an asked package that no entry answers for, the entries that name it are listed, at most 8 for each such package **[call]**. These are a binary's CPE entries in NVD, or another release's entry for a package whose own release no provider lists.
  - **`otherProviders` counts the rest:** for each provider, how many entries it has that the answer leaves out, sorted by provider. With no package asked, every entry is counted and none is listed **[call]**.
  - **It can't hide an answer.** An entry that is left out says `Unknown` for every asked package, by how `fixedForInstalled` is defined. A test pins this: every `Yes` and `No` of the full answer is in the listed entries.
  - **`description`** is the first that a listed entry's provider gives for the vulnerability. Where none gives one, it is chosen as today: the asked ID's records, NVD's first **[call]**.
  - **`references`** are those of the asked ID's records and of the listed entries' providers, each once **[call]**.
  - **A new parameter, `aliases`:** at most 8 other IDs of the same vulnerability, such as the IDs that the case's findings carry. `describe` searches them in the same search as the asked ID, as it already searches the aliases that the records name.
    - Grype's command line can't search by alias. Its library can, but that would put Grype's database driver into the collector. The case's findings carry the IDs, so asking for them costs nothing **[call]**.
    - **The safety core fills `aliases` itself** (owner, 2026-11-20). When the agent calls `describe` with an ID of the case, the core adds the case's findings' other IDs and aliases, up to 8, to those the agent gave. So the first call reaches the ecosystem's own record whether or not the agent names it. The ledger records the arguments as they went to the collector.
  - **A `pkg:generic` purl** names no package type. So a package asked with one is read by its name and version, which must equal the purl's, and keeps the type it was asked with. It speaks for no distribution or ecosystem, so each of its answers is `Unknown`, and the entries that name it are listed **[call]**.
  - `describe`'s description and schema change with this, and the golden capabilities file with them.

### 2.3 `describe` from the first step, and each finding's purl and distribution

- **What the run showed:**
  - every case spent its first step on `search_tools`, to find `describe`;
  - cases then searched the SBOM for their packages' purls, several times in one case.
- **The fix:**
  - **The safety core lists `vulnerabilities__describe` from the first step**, when the case's `AgentProfile` grants it, as if a search had found it. It counts towards the limits of loaded tools as a found tool does. Every other operation is still found by search (0055) **[call]**.
  - **The case file names each finding's `purl` and `distro`:**
    - They come from the SBOM's package that the finding names.
    - `distro` is read as the validator reads it: the purl's `distro` qualifier, else the SBOM's distribution for an OS package.
    - The sheets don't change. The case file wraps each finding with the two values **[call]**.
  - **The core prompt** says that `describe` is listed from the start. That makes it core `v5`. The draft on what the agent is asked would then be `v6`.

### 2.4 The guidance: a first sentence that carries the answer

- **What the run showed:**
  - The guidance said "start with the answer", so every first sentence read "The container image is affected by CVE-…". That sentence is the `Investigation`'s result reason.
  - The rules' notes in the case file, such as load-check's "reached by /usr/bin/curl", appeared in no summary.
  - Summaries named releases and versions that no evidence showed.
- **The fix,** in the shipped guidance:
  - **The summary's first sentence** names:
    - the package and its installed version;
    - the fixed version, or that there is none;
    - the step: update, change, mitigate or investigate.

    It holds no other period, since the reason ends at the first.
  - **Where to look first:** call `describe` with the case's vulnerability, the findings' other IDs as `aliases`, and each finding's package with its purl. Then read the findings' `statusNotes` and `runsIn`, and use them in the summary.
  - **Name a version or a release only where a tool's answer or the case file shows it.**
- The guidance is replaceable by an `AgentProfile`, and its hash is recorded, so it has no version of its own.

### 2.5 The `Investigation` counts the cases it selected, and its tokens

- **What the run showed:**
  - `cases.total` and `cases.skipped` counted every case of the named vulnerabilities, or of the playbook, before the conditions. So an investigation that selected a handful of cases read thousands, nearly all of them skipped.
  - The count of cases over the cap was only in an event.
  - Tokens were only per `Assessment`.
- **The fix,** in `status`:
  - **`cases.total`** counts the selected cases: those that every condition holds for, and whose image runs (2.6).
  - **`cases.skipped` gives way to two counts:**
    - `cases.overTheCap`: selected cases that the cap kept from the agent. They are part of `total`.
    - `cases.notSelected`: cases in scope that a condition doesn't hold for, or whose image runs nowhere. They are outside `total`.
  - **`summary.skip`** counts the results of type `skip`: the cases over the cap **[call]**.
  - **`usage`:** `promptTokens` and `completionTokens`, summed over the latest judgement of each case that the investigation charged, in this run, or since its creation for a `Continuous` one **[call]**.
    - It needs to know who charged a case. So the `Assessment`'s status names the investigation that charged it, in `chargedTo`, which section 3.1 adds.
    - A case judged again replaces its usage. So the sum counts each case's latest judgement, which the field's description says.
  - **The `Cases` column** shows `total`, now the selected cases.
- The API is `v1alpha1`, so the fields change without conversion. A cluster with the old status loses `skipped` on the next write.

### 2.6 Selection skips images that run nowhere

- **What the run showed:** cases of images that no workload runs any more were selected. One of them cost the most tokens of the run. The janitor keeps a gone image's sheet for 24 hours, and longer while its facts remain.
- **The fix:**
  - Selection leaves out a case whose `impact.resources` is 0, before the conditions, with the reason "not running". It counts in `notSelected`.
  - It applies to every playbook. A `Continuous` investigation selects the case again once a workload runs the image, such as the next run of a `CronJob`.
  - The janitor stays as it is.

### 2.7 A default rule: a fix is available

- **What the run showed:** the agent judged cases whose fix the matcher already knew. In each such case it said "affected", from the fixed version above the installed one, which the core prompt accepts as evidence.
- **The fix:**
  - The rule `fix-available` ships as the fifth default step of `container-cves`:
    ```yaml
    condition: finding.fixState == "fixed" && finding.fixTarget != "" && finding.packageType != "binary"
    outcome:
      status: Affected
    reason: "'fixed in ' + finding.fixTarget"
    ```
  - A binary that Syft recognizes is matched by its CPE, which may not hold, so the rule leaves it to the agent.
  - The playbook's agent condition, `finding.status == "UnderInvestigation"`, then leaves those cases out.
- **What it costs:**
  - `Affected` is the most cautious status, so it wins over the other rules (0043):
    - **`removed-in-later-layer`:** a package that a later layer removed, but whose record names a fix, reads `Affected` rather than `NotAffected`. The SOC is told to update a package that is gone. That is safe, but wrong.
    - **`completeness-guard`:** a finding that the guard holds, in a scan that isn't complete, reads `Affected` when a fix is known. The package was found, so this holds.
  - Excluding removed packages would make this rule read the image's contents and its SBOM, like `removed-in-later-layer`. It would then not apply where they are missing. The plan leaves the rule as it runs live, and asks the owner.

### 2.8 Monitoring from the install

- **What the run showed:**
  - The manager's `/metrics` wants a token. The shipped `ServiceMonitor` reads one with `bearerTokenFile`, which managed platforms refuse, since it reads a file of the scraper's own pod.
  - Nothing scraped the collectors.
- **The fix:** `config/prometheus` ships what works, with no platform's labels:
  - a `ServiceAccount` for the scraper;
  - its token `Secret`;
  - a `ClusterRoleBinding` to `vexplain-metrics-reader`;
  - three `ServiceMonitor`s:
    - the manager's, with `authorization.credentials` from that `Secret`, and `insecureSkipVerify` for the certificate that the manager signs itself;
    - the agent workers', the same way;
    - the collectors', on their port `http` (8081).
- **It is switched on the way kubebuilder ships it** (owner, 2026-11-20):
  - `config/default` names `config/prometheus` in its `[PROMETHEUS]` section, commented out as the scaffold has it. The `ServiceMonitor` kind needs the Prometheus Operator's CRDs, and an install that includes it fails without them.
  - Where the operator runs, the install uncomments that line. The README says so.
  - The e2e suite installs the Prometheus Operator, pinned, with the helper that kubebuilder's scaffold had for it (`InstallPrometheusOperator`). Its overlay switches the section on, so the `ServiceMonitor`s are applied and scraped there.
- **The network:**
  - The policy that lets the scraper reach port 8443 covers the agent workers too.
  - The README names the namespace label that it asks of the scraper's namespace.

## 3. The agent workers (0057)

0057 decides the split: the manager selects and orders cases, and workers in their own `Deployment` claim and judge them. This section gives the shapes.

### 3.1 The queue in the API

The `Queued` `Assessment`s are the queue. The hub writes what the in-memory queue held into each one's status, so the queue survives a restart of either side.

```yaml
status:
  chargedTo: {namespace: team-a, name: most-urgent}  # the investigation that queued it (2.5)
  queue:                                             # while it waits or is judged
    playbook: container-cves                          # whose case file goes with the case
    requests:                                         # the investigations that want it, at most 64
    - {namespace: team-a, name: most-urgent, once: true}
    judgedAfter: "2026-11-20T10:00:00Z"               # the latest of the requests'
    order: {urgencyRank: 1, knownExploited: true, epssPermille: 950, resources: 13}
    queuedTime: "2026-11-20T10:00:03Z"
    failures: 0                                       # judgements that failed after spending tokens
    misses: 0                                         # failures in a row, which the backoff doubles for
    notBefore: "2026-11-20T10:00:13Z"                 # a case handed back waits until then
  claim:                                              # while a worker judges it
    worker: vexplain-agent-7d9f4-x2k8q
    leaseEndTime: "2026-11-20T10:01:03Z"
```

- **The hub's queue keeps `cases.Queue`'s contract,** so the `Investigation` controller doesn't change:
  - `Add` writes the request into the status, and starts the queue with `Ready=False`, reason `Queued`, for a case that isn't queued yet. It refreshes `order` and `judgedAfter` either way.
  - `Keep` removes the investigation from the requests of the cases that it no longer names. A waiting case that no request is left on leaves the queue `Withdrawn`, as today.
  - `Pending` counts the cases whose requests name the investigation, from the manager's cache.
- **The order** is today's (design 5.3):
  - the tiers in `order`;
  - then a case that a `Once` request wants;
  - then `queuedTime`.

  The workers sort with the same function, `cases.CompareTiers`.
- **Validation (CEL):**
  - a `claim` needs a `queue`;
  - `requests` is a map keyed by namespace and name;
  - the counts are at least 0.

(*Amended on 2026-11-20, while building:* the API has no bools, so `requests[].trigger` (`Once`, `Schedule` or `Continuous`) replaces `once`, and `order.knownExploited` is `Listed` or `NotListed`. `queue.chargedTo` holds the charge while the case waits, and the outcome write copies it to the top-level `chargedTo`.)

### 3.2 The claim and its lease

- **A worker claims** the first case in order whose `notBefore` has passed. It does this only while fewer cases are `Judging` than the `ModelConfig`'s `maxConcurrentRequests`, counted over all workers from its cache.
- **The claim is one status update,** carrying the object's `resourceVersion`:
  - `Ready` becomes `Judging`;
  - `claim` names the worker, by its pod's name, and when its lease ends.

  Of two workers, one wins. The other reads the conflict, and tries the next case.
- **The lease lasts 60 seconds,** and the worker renews it every 20 seconds while it judges **[call]**.
- **A worker that ends a judgement** writes the outcome and clears `queue` and `claim` in the same update, as it writes the outcome today. A judgement that fails hands the case back:
  - `failures` and `misses` count as the in-memory queue counted them;
  - `notBefore` follows the backoff.
- **A worker that loses its lease** stops the judgement. A conflict on renewal re-reads the case, and only a claim that names another worker ends it. A worker that finds its case withdrawn or switched off stops as today.
- **The cases cache the workers watch** holds only the `Assessment`s with a `queue`, by a label the hub sets while a case is queued **[call]**.

  (*Amended on 2026-11-20, while building:* there is no label. A status update can't change labels, so the outcome and the label could never be one write. The workers' cache holds every `Assessment`, and they pick those whose status holds a `queue`. A worker also stops once the clock passes the last lease end it wrote, and each renewal gets 10 s, less than the sweep's grace.)

  (*Amended on 2026-11-20, while building:* a worker claims nothing while the agent is switched off, or the default profile's `ModelConfig` isn't `Ready`, rather than claim each waiting case for the judge to hand it back. After a renewal that failed, a worker stops once its next renewal would come no sooner than the last lease end it wrote, so that the sweep's grace stays for clocks that differ.)

### 3.3 The sweep

The manager's sweep runs every 30 seconds **[call]**:
- **A lease ended more than 30 seconds ago:** the case goes back to `Queued`, its claim cleared, and `failures` counts one, since the dead worker may have spent tokens. Five failures end the case with no verdict, `ModelError`, as today (0052's amendment).
- **A request whose investigation is gone:** it is removed, and a waiting case left with none is withdrawn.
- **A held case with no `queue`,** as an install before this one left it: it is withdrawn.

(*Amended on 2026-11-20, while building:* the first sweep waits 90 seconds after the manager starts, as the sweep in the manager did, so that the investigations' first reconciles queue again the cases that an install before this one held. Withdrawn first, such a case would be charged again.)

### 3.4 What runs where

- **The manager:**
  - investigations and selection;
  - the hub's queue in the API, and the sweep;
  - the assessor, which brings verdicts into the sheets and proposes statements;
  - the janitor.

  It no longer reads the LLM key, nor reaches the model.
- **The workers** run `cmd/agent`:
  - the claim loop on every replica;
  - the runner, the safety core, the validator, the ledger and the outcome's write, which move from the manager unchanged;
  - the `ModelConfig` controller and its probe, on the workers' leader only, under their own lease name.
- **A worker rebuilds the case** from the sheet and the inventory, as selection does, for the case's vulnerability and image. A case whose sheet is gone is withdrawn **[call]**.

### 3.5 Certificates, roles and the network

- **The workers' client certificate [call]:**
  - The manager issues it into the Secret `vexplain-agent-client-tls`, with the name `vexplain-agent`, and renews it as it renews the collectors' server certificates.
  - The workers' code reads only that Secret, never the authority's key.
  - The collectors trust the authority, so they accept it.

  (*Amended on 2026-11-20, while building:* the workers' role must read the labelled Secrets of the operator's namespace, and Kubernetes can't narrow `list` or `get` by label. So the role can also read the authority's key in that namespace, and a compromised worker could sign a certificate. The owner accepted this on 2026-11-20, rather than moving the authority's Secret into a namespace of its own.)
- **The workers' role** is generated from markers in their own package, as the manager's is, under the name `agent-role`. It holds:
  - reading the inventory, the sheets, the evidence, the playbooks, the profiles and the configuration;
  - writing ledgers, `Assessment` status, `ModelConfig` status and events;
  - creating and deleting `Evidence` for the outputs of tool calls, which the ledger points to. The role can't narrow this to those outputs, so the workers could write any `Evidence`, as the manager could when the agent ran inside it;
  - reading the labelled Secrets of the operator's namespace: the LLM key, the MCP collectors' credentials, and their client certificate;
  - their lease.

  The manager's code and cache no longer read the LLM key, and its role loses the `watch` on Secrets that the `ModelConfig` controller needed. It keeps `get` in the operator's namespace for its own certificates. Kubernetes can't narrow `get` by label, so this is where the separation ends **[call]**.
- **The network:**
  - The collectors' policy lets the workers' pods reach port 9443, by the label `app.kubernetes.io/component: agent`.
  - The metrics policy lets the scraper reach their port 8443.

### 3.6 The image and the install

- **One `Dockerfile` with two targets, `manager` and `agent`,** built from one builder stage. `make docker-build` builds both. Each image holds only its own binary, as 0057 says **[call]**.
- **`AGENT_IMG`** joins the image variables, and `config/agent` holds the `Deployment` `vexplain-agent`:
  - 2 replicas, so that a failed worker leaves another **[call]**;
  - its service account and metrics `Service`;
  - the same security settings as the manager's.
- **The e2e suite** runs the scripted model against the workers, and checks three things:
  - a manager restart leaves a judged case alone;
  - a worker's death returns its case through the lease;
  - two workers judge each case once.

## 4. Left to the builder

- The names of Go types and packages. The worker's code moves out of `internal/controller/hub` into a package of its own, so that its markers make their own role.
- How the hub's queue reads its cache, and whether an index serves `chargedTo` and the requests.
- The texts of events, logs and conditions, in the repository's style.
- Each fix's tests, test first, on kind for what touches the install.

## 5. Core `v6`, after the second live run

- **Status:** the owner picked this on 2026-11-20 ("Prompt v6 first"), after the second live run. Exposure, end of life and exploitability stay with the draft on [what the agent is asked](2026-11-20-what-the-agent-is-asked.md), which becomes `v7`.
- **What the run showed:**
  - No case fetched an advisory. In some, `describe` said `Unknown` for a package's own provider, and one case gave up naming that provider's advisory as what would settle it.
  - Next steps named versions that exist only for other releases, or that no evidence showed. They said "update" where the installed release has no fix.
  - One first sentence still read "The container image is affected by …", and one summary quoted a version range wrongly.
- **The core adds three rules,** which make it `v6`. They go into the core, not the guidance, since a profile's own guidance replaces the shipped one, and the result's reason and the review rest on them:
  1. **Fetch the provider's advisory before giving up.**
     - Where `describe` says `fixedForInstalled: Unknown` for a package, the agent finds `advisories__fetch` and fetches the advisory of that package's provider, from `describe`'s references.
     - It does this before it submits `under_investigation` or no verdict, and cites what the page says, or that the fetch failed.
     - A fetched page stays `External`, so it never settles `not_affected` or `fixed` (0031). It can inform `affected`, the summary and the next step, such as that a release gets no fix any more.
  2. **No fix for the release, no update.**
     - Where the installed distribution release has no fix, the next step is a mitigation: the vulnerable function, feature or configuration to turn off, remove or block. That is `fixState` `not-fixed`, `wont-fix` or `unknown`, or a `No` without a fixed version for that release.
     - The next step names no version that no cited evidence shows for that release.
  3. **Versions as the evidence writes them.**
     - Versions and ranges are quoted exactly.
     - The summary's first sentence names the package, its installed version, the distribution release and the outcome, never the image and the vulnerability alone.
- **The guidance** says the same where it says where to look first and how to write the summary.
- **The validator doesn't check a version that the next step names** against the cited answers **[call]**. Versions in free text can't be told reliably from releases, scores or IDs, and a false refusal costs the case a retry. The next live run shows whether the rule alone holds.

## 6. Core `v7`, after the third live run

- **Status:** the owner gave the go on 2026-11-20 ("Let's go for v7"), after core `v6` ran live. The draft on [what the agent is asked](2026-11-20-what-the-agent-is-asked.md) becomes `v8`.
- **What the run showed:**
  - `v6` made the agent fetch, and every first sentence and next step was specific. The tokens grew, though, mostly in two cases.
  - A binary without a distribution searched the SBOM and the image many times for one, repeating the same calls, and ran out of steps. The text that ended it put its established facts under "would settle".
  - Fetches went to hosts that can't answer: hosts off the allowlist, and hosts that the proxy refuses.
  - A case whose own distribution's tracker listed the installed release as vulnerable, with no fix, gave up. `v5` had left it `under_investigation`. Two similar cases ended one each way.
  - A summary named a provider's tracker as its source, though nothing was fetched; the source was the database.
- **The core adds five rules,** which make it `v7`:
  1. **The provider's advisory only where a provider exists.** The fetch rule of section 5 applies to a package that names a distribution, in the case file's `distro`, or an ecosystem, in its purl's type. A binary without either has no provider's advisory, and the agent doesn't look for a distribution in the SBOM or the image.
  2. **`affected` may rest on the package's own distribution's advisory,** fetched, that lists the installed version, or its release, as vulnerable, with no fix for that release. External evidence may push a case towards `affected` (0031). The next step is then a mitigation.
  3. **`under_investigation` or no verdict:**
     - `under_investigation` is for evidence that is consistent with `affected` but doesn't prove it, or that settles nothing either way.
     - No verdict is for a case that couldn't be checked: the tools it needed failed, or are missing.
  4. **The source as the ledger shows it.** `describe`'s answer comes from the vulnerability database. A provider's tracker is named as a source only where its page was fetched.
  5. **An investigation's guidance follows the profile's,** and isn't evidence ([the investigation's guidance](2026-11-20-investigation-guidance.md), 3.2).
- **The safety core and the runner change too:**
  1. **A repeated call is answered from the ledger.**
     - A call of a tool with the same arguments as an earlier call of the case that didn't fail isn't run again. Its answer names the earlier ledger ID, so the model reads that result again, or tries something else.
     - The repetition adds no ledger entry, and still counts as a step of the runner, so a loop of repetitions ends at `maxSteps`.
     - A call that failed may run again, since a fetch or a collector may fail only for a moment.
  2. **`describe`'s answer says which of its references can't be fetched.**
     - A line after the answer names the hosts of its references that the granted fetch tool can't reach, by that tool's allowlist. The answer itself stays as the collector wrote it, since the ledger records what the tool returned.
     - The allowlist is the fetching collector's `allowedDomains` setting, or its default. The default and the matching move into the SDK, so the collector and the safety core read them alike **[call]**.
     - A host that the proxy refuses isn't known before a fetch. An install drops it from the allowlist until the proxy opens it.
  3. **The text that a limit ends a case with** asks for two labelled parts, and the runner splits them at the label. A heading, such as "# What I established", no longer lands in the wrong part.
- **Later:** the lookup per source, which builds a distribution tracker's URL for the vulnerability as a trusted reference, stays a decision of its own. In one case of the run, no reference of `describe` pointed to the distribution's tracker.

## 7. Core `v8`, the board and the event, after the fourth live run

- **Status:** the owner asked for these on 2026-11-21, as the final improvement round of phase 4: "Besides the ones I have questions about, do all the others". The draft on [what the agent is asked](2026-11-20-what-the-agent-is-asked.md) becomes `v9`.
- **The owner's decisions of 2026-11-21** on the round's open points:
  - an investigation's guidance can't change, and no `Assessment` records its version (7.5);
  - a judgement names its investigation by `investigationRef`, with the investigation's uid (7.6);
  - a verdict must be explainable from its claims and their evidence alone, with a check (7.4);
  - the order in which `IfJudgedElsewhere` judges cases stays as it is;
  - a distribution's fix in a release of a binary's upstream version makes that version affected, unless evidence shows the patch; a version range in prose is no evidence (7.7);
  - tokens and time per investigation are counters of the worker, bound to the investigation that spent them (7.8).
- **Still with the owner,** and not part of this round: what a recreated investigation does with the verdicts judged for an earlier one of the same name.
- **What the run showed:**
  - No case gave up or ran to its step limit, and cases took fewer steps than with `v6`.
  - A case whose database answer was `Unknown` ended `under_investigation`, with a next step that told the analyst to check the distribution's tracker. The agent could have fetched it itself.
  - With guidance about exploitability, a case searched the image's evidence one term at a time, many times, and never settled the fix status. It was the run's most expensive case by far.
  - A summary stated the guidance's claims as facts, and cited a search of the image's files as evidence that a function isn't called.
  - On the board, the SOC saw where and how urgent, but not why a case is urgent, nor whether to update or mitigate: that took `kubectl`.
  - The event `JudgedElsewhere` advised setting `judgePolicy` to `IfJudgedElsewhere`, which was already set: the cap had no room.
  - Recreating the investigations, as a migration did, gave each a fresh cap, so they judged again.

### 7.1 Core `v8`

The core adds three rules, which make it `v8`:

1. **Fetch before deferring.**
   - Where `describe` says `fixedForInstalled: Unknown` for a package with a provider, and a reference of its answer is on that provider's host, such as `security.alpinelinux.org` for Alpine, the agent fetches it before it submits `under_investigation` or no verdict. Section 5's rule stays; this names the host to look for.
   - A next step names only what the agent can't do itself. "Check the tracker" is a next step only where no reference is on the provider's host, or the fetch failed, and the summary says which, citing it.
2. **Fix status before exploitability.**
   - The agent settles the fix status first: `describe`, then the provider's advisory. Only then does it search for how the image uses the vulnerable code, as guidance about exploitability asks.
   - That search stays short: several terms in one search, and at most three searches of the image's evidence for it.
   - `search_evidence` takes several terms in one query, separated by `|`, without the spaces around them. A line that holds any of them matches. A query without `|` matches as before **[call]**: a lookup of a literal `|` isn't needed in the case file's `path = value` lines.
   - No hard cap on searches **[call]**. A refusal could cut off the search that settles a case, and `maxSteps` already bounds a case. The next live run shows whether the rule holds.
3. **Say what a search can show.**
   - A search of the SBOM or of the image's files shows which packages and files are there. It never shows whether a function is called, so it isn't evidence that code is unused.
   - The investigation's guidance is context. The summary and the claims don't use it, as 7.4 says; the next step may name its mitigation.
- **The shipped guidance** moves the provider's advisory before the image's own evidence, in its order of where to look.

### 7.2 The board's series

- **`vexplain_open_case` says why and what.** It gains three labels, from what the case already holds, so no series is added:
  - `exposure`: the workload's SSVC exposure, `Small`, `Controlled`, `Open` or `Unknown`, as its report has it;
  - `known_exploited`: the finding's `knownExploited`, `Listed` or `NotListed`, and `NotListed` where the sheet says nothing **[call]**;
  - `action`: the step that the report gives the finding, `Update`, `Change`, `Mitigate` or `Investigate`.
  - Where two packages of an image give one CVE different steps, the CVE has a series for each, as it already has for verdicts and urgencies.
- **`vexplain_investigation_cases`** gains the states `judgedElsewhere` and `charged`, so the series holds every count of the status **[call]**.
- **`vexplain_investigation_vulnerability_info{cluster, namespace, investigation, cve} 1`** joins an investigation to its CVEs, so picking an investigation on the board picks them. It has one series for each `vulnerabilityID` of `status.results`, as the findings spell it, and each ID of `spec.vulnerabilities` that no result names, ignoring case as selection does **[call]**. The results add the findings' own IDs where the spec names an alias, such as a GHSA ID for a CVE. An investigation without `vulnerabilities` names only the CVEs of its first 20 results.
- **The agent's counters start at 0.** When a worker knows its cluster's name, it sets each known value of `vexplain_agent_cases_total`, `vexplain_agent_no_verdicts_total`, `vexplain_agent_rejections_total` and `vexplain_agent_tokens_total` to 0, so a board's `increase()` sees the first case. The tool refusals and the model requests have names that aren't known beforehand, and start on their first count. The manager doesn't set them: it judges no case, and its zeros would show beside the workers'.

### 7.3 The event `JudgedElsewhere`, and a fresh cap

- **The event's advice follows the policy:**
  - with `IfStale` and guidance, it advises `IfJudgedElsewhere`, as before;
  - with `IfJudgedElsewhere` or `Always`, the cases judged elsewhere are those that the run couldn't hand over. While the run hands cases over, that is for want of room, so it advises raising `spec.agent.maxCases`. While it doesn't, as when the run is closed, the investigation disabled or the agent switched off, room isn't what keeps the cases, so it gives no advice; a changed spec of a `Once` investigation, a higher cap among them, starts a new run all the same (*amended on 2026-11-21, after review*);
  - with `IfStale` and no guidance, it names the cases without advice.
- **A recreated investigation starts with a fresh cap.** `maxCases`' doc says so: a migration, a rename or a sync that replaces the object starts a new run, which judges up to `maxCases` again. An apply that changes nothing keeps the run and its cap, and a changed spec of a `Once` investigation starts a new run too. docs/agent.md says the same.

### 7.4 A verdict explains itself

- **The requirement.** A verdict is explainable from its summary, its claims and the ledger entries that they cite, alone. A reader needs nothing else: not the investigation, which may be gone, nor its guidance, which no ledger entry holds. The owner asked for this on 2026-11-21, with a check.
- **What already holds.** An `Assessment` and its `Ledger` belong to no investigation, so deleting one leaves them. The case's inputs don't include the guidance, so the verdict stays fresh. The validator's check `Citation` refuses a claim without a ledger ID, or with one that the ledger doesn't hold.
- **The core** says it: the summary and the claims don't use the guidance, not even as "the guidance says". Where the guidance names a mitigation, only the next step names it, and the summary says that the step is a mitigation.
- **The check `Explainable`,** in the validator, refuses a verdict of a case with an investigation's guidance whose summary or claims:
  - name the guidance, by the word "guidance", ignoring case, where no ledger entry holds that word; or
  - repeat a run of 8 words of the investigation's guidance that no ledger entry holds, compared as words of letters and digits, ignoring case **[call]**.
  - What the cited evidence holds, a claim may quote, even where the guidance names it too, such as a file that it says to check. A claim's evidence is the entries that it cites; the summary's, those that the claims cite. The word passes where the words around it, one each side, are the cited entries' own, as a tracker's "no guidance for" is. (*Amended on 2026-11-21, after two reviews:* a path or a purl splits into many words, so without this a claim that quotes the evidence that the guidance pointed to was refused; a tracker's own word "guidance" was too. An exemption from any entry of the ledger would let one page that speaks of guidance switch the check off for the whole verdict.)
  - The next step is left out: it names the guidance's mitigation, and the summary says only that the step is a mitigation.
  - Like every check, it tells the agent what to change, and the agent may repair the verdict once. A verdict refused twice ends the case without a verdict, `ValidatorRejected`.
- **Why a word check, and 8 words [call].** It catches the two ways run 4's summary leant on the guidance: stating it as fact, and attributing to it. It can't catch a paraphrase, nor repeat a guidance shorter than 8 words; the core's rule has to prevent those. Shorter runs would catch common phrases; the guidance is free text, and its sentences are rarely shorter. A case without an investigation's guidance has nothing that a deleted investigation could take with it, so the check doesn't apply.

### 7.5 An investigation's guidance can't change

- `spec.agent.guidance` can't change once the investigation exists, nor be added or removed. A CEL transition rule on `spec.agent` refuses it, with a message: create a new investigation for other guidance. An investigation stored without `spec.agent` may still get it, with guidance.
- So a verdict judged for an investigation was judged with the guidance that the investigation still has. No `Assessment` records a version of it. With 7.6, the uid of a verdict's `investigationRef` names the object, and so the guidance, that it was judged with.
- [The investigation's guidance](2026-11-20-investigation-guidance.md) says so in an amendment of 2026-11-21.

### 7.6 `investigationRef`, with the investigation's uid

- **The owner decided on 2026-11-21:** a judgement names its investigation by a reference with the investigation's uid, under the name `investigationRef`, as the Kubernetes API conventions name a reference (`{field}Ref`, such as `secretRef`). It replaces 7.5's "no UID".
- **The reference:** `InvestigationReference` holds `namespace`, `name` and `uid`, all required. `uid` is the investigation's `metadata.uid`.
- **Where it goes:**
  - `status.chargedTo` becomes `status.investigationRef`: the investigation that the judgement was made for, whose cap it counts against, and whose `usage` it adds to.
  - The queue's `chargedTo` becomes `queue.investigationRef`, with the same meaning for the judgement under way. The outcome moves it to the status, as before.
  - Each of the queue's `requests` holds an `investigationRef` and the `trigger`. The list is atomic, since a map's keys can't be nested; a request of an earlier object of the same namespace and name gives way to the current object's **[call]**.
- **What the uid changes:**
  - **Judged for this investigation** means that the `investigationRef` names its namespace, name and uid. A recreated investigation of the same name doesn't take the earlier object's verdicts as its own. Under `IfJudgedElsewhere` or `Always` it judges those cases again; under `IfStale` it reuses them, and counts them in `judgedElsewhere`.
  - **`usage`** sums only what was judged for this object.
  - **The worker** gives a case the guidance of the investigation that its `investigationRef` names only where the object that it reads has that uid. A case queued by an earlier object isn't judged with a later object's guidance; it gets none.
  - **A case that waits unclaimed,** charged to an earlier object, is charged to the current object when that queues it, against its cap, and is judged with its guidance **[call]**. The earlier object is gone and its judgement never began; otherwise a recreated investigation under `IfJudgedElsewhere` or `Always` would pay for the case twice, and the first judgement would have no guidance. A judgement under way stays charged to the object that it began for. (*Amended on 2026-11-21, after review.*)
  - **The event `JudgedElsewhere`** says which of the cases were judged for an earlier object of the same name: "judged for an earlier <name>".
- **No compatibility.** The API is `v1alpha1` and unreleased. Stored `Assessment`s with `chargedTo` aren't read back; an install starts clean. The owner: "Do not care about existing as we can always start clean with our current phase of development".

### 7.7 A binary at an upstream version that a distribution fixed

- **The owner approved this on 2026-11-21** ("Yes, send both"). Core `v8` hasn't shipped, so it takes the rule **[call]**.
- **What the run showed:** a binary without a distribution, such as `pkg:generic/busybox@1.36.1`, stayed `under_investigation` although a fetched tracker of a distribution listed the fix in releases of the same upstream version, such as `1.36.1-r1`. Its next step leaned on a version range in an advisory's prose.
- **The rule:**
  - Where a package's case file names neither a distribution nor an ecosystem, and a fetched advisory of a distribution fixed the vulnerability in a later release of the package's own upstream version, such as `1.36.1-r1` for `1.36.1`, that upstream version is vulnerable. The package is `affected`, unless evidence shows that it carries the patch, such as a vendor naming the fix.
  - A fix in the distribution's first release of that version, such as `1.36.1-r0` or Debian's `1.36.1-1`, came with the upstream version, and doesn't count **[call]**: the upstream release itself carried the fix. Counting it would call a fixed binary affected. (*Amended on 2026-11-21, after review.*)
  - The claims cite the version from the image and the distribution's fix record. The next step is a build of the package with the fix.
  - It doesn't apply to a distribution's own package, which `describe` answers for; nor to a fix only in another upstream version, which says nothing about this one; nor where evidence shows the patch.
  - A version range in an advisory's prose, such as "before 1.35", is no evidence for `not_affected`, nor a reason to stay `under_investigation`.
- **The v7 rule on a binary** stays: the agent doesn't look for a distribution in the SBOM or the image. A distribution's advisory among `describe`'s references may still show that the binary's upstream version is vulnerable.

### 7.8 Tokens and time per investigation

- **The owner approved this on 2026-11-21:** counters bound to the investigation that spent them, rather than a gauge of `status.usage`, which moves when another investigation judges a case again. A cost mustn't move.
- **New counters [call],** so the existing series keep their labels:
  - `vexplain_investigation_agent_tokens_total{cluster, namespace, investigation, kind}`: the tokens that the endpoint reported for the investigation's judgements, `prompt` or `completion`;
  - `vexplain_investigation_agent_seconds_total{cluster, namespace, investigation}`: the time that the agent spent judging its cases.
- **The investigation** is the one that the case's `queue.investigationRef` names when the judgement starts, by namespace and name: the one whose cap it is charged to, also where it wants the case no more. No uid label: a recreated investigation of the same name continues its series.
- **What counts:** every judgement, also one that goes back to the queue, as `vexplain_agent_tokens_total` counts it.
- **From 0:** a worker creates the investigation's series at 0 when a judgement for it starts, before it counts.
- **Kept until the worker restarts:** a counter of a deleted investigation stays, at its last value, in each worker that counted it.
