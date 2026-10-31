# Phase 2a measurements

Phase 2a ends with one measurement: how much of what the vulnerability database reports the deterministic rules settle, and how much they leave for a person. It runs on a test set of 15 images with known answers for one CVE, on a kind cluster.

**These results are provisional until the owner approves the known answers.** `hack/measure-2a/cases.yaml` says `approved: false`, and the owner sets it to `true` after reviewing every expected answer, with its basis. The review list is at the end of "The cases".

Every figure on this page is about the test set. None comes from a real platform, and none is a time per case. The value figure, the residual multiplied by the time that a case takes a person, is given to the owner outside this repository.

| What | Result on the test set |
|---|---|
| Known answers, as the rules are built | 15 of 15 as expected |
| Known answers, without the known-exploited override | 15 of 15 as expected |
| False "not affected" | none, in either column |
| Findings in the 15 manifests | 6,770 |
| Left for an assessment | 6,743 (99.6%) |
| Tracked, as known exploited | 19 |
| Suppressed by a rule | 8, none of them a known answer (see "What the rules suppressed outside the known answers") |
| Largest evidence, compressed | 771,627 B, which is 147% of the 512 KiB trigger of decision 0004 |

## Method

**The test set.** `hack/measure-2a/cases.yaml` lists the cases and the target CVE, CVE-2026-111497.

- Each case is an image with two expected answers for the finding of the target CVE in the package that holds the Brotli library: `brotli-libs` on Alpine, `libbrotli1` on Debian, and the name in the case's `package` field on any other distribution. A sheet with no such finding gives `None`.
- `expected` is the answer of the rules as built. They put a vulnerability that the catalog of known exploited vulnerabilities lists into `Tracked` before any other rule looks at it.
- `expectedWithoutKEV` is the answer of the rules without that override: what the later rules make of the evidence.
- `NotFound` and `NoPackage` both expect `None`. The tool can't tell them apart, because a copy that the scanner can't see leaves no trace. The cases' basis does: every `NotFound` is a blind spot, a case where Brotli is in the image and the scan has no finding for it.

**How the answers were worked out.** Without the rules under test, from each image itself:

- the package database (`apk`, `dpkg` or `rpm`) for the packages and their files
- `readelf -d` on every ELF file, followed transitively, for what needs a Brotli library
- a search of every file but the library's own, the package databases and the linker cache, for the library's versioned, unversioned and bare names
- the image configuration for `LD_PRELOAD`
- the pinned Grype and its database on the image, for whether the package is flagged and listed as known exploited

**The run.**

- `go run ./hack/measure-2a --cases hack/measure-2a/cases.yaml --registry localhost:5001` does the whole run. It refuses an API server and a registry that are not on a loopback address.
- It builds the planted images and copies the public ones, with their digests unchanged, into the local registry next to kind, so that pods pull for real and the scanner can pull again. An index is copied with all its platforms.
- It starts one Deployment per case in the namespace `measure-2a`. Each container runs `sleep`, so that no server of an image starts. A scan reads files and runs nothing, but the inventory sees images through pods.
- It waits for each case's scan, evidence and sheet, with a timeout per case, and reads them through the stores of `internal/inventory`. It reads the pods only to learn which digest the inventory holds. It exits with 1 on any false "not affected", in either column, and on any case without an answer.
- The operator is the one of the end-to-end setup: manager, scanner and matcher, with the matcher offline from the database in its image, version `v6.1.10+2026-10-30T06:23:28Z` (Grype 0.121.0, Syft 1.55.0). The cluster has one node, linux/arm64. The completeness guard stands at its default, 90%.

**The answer without the override** is not on the sheet, so the tool computes it from the stored evidence. For each finding that the known-exploited rule decided, it rebuilds the match with the flag off, takes the other fields from the finding, and runs `rules.Evaluate` on the evidence with the hub's settings.

- Before it does, it rebuilds every finding of the case's sheet as the sheet has it, runs the rules, and demands the sheet back: the same outcome, rule, justification, conditions and reason. A finding that doesn't come back stops the run with an error that names it, because the rebuild would have lost an input that the rules read, and the second column would be wrong with nobody seeing it.
- In this run all 6,770 findings came back as the sheets have them.

**To repeat it** (the cluster has its own kubeconfig, and the run never touches another):

```bash
make setup-test-e2e
export KUBECONFIG=$PWD/bin/kind-e2e.kubeconfig
make docker-build IMG=example.com/vexplain-manager:v0.0.1 SCANNER_IMG=example.com/vexplain-scanner:v0.0.1 \
  MATCHER_IMG=example.com/vexplain-matcher:v0.0.1 MATCHER_DB=true
for i in manager scanner matcher; do kind load docker-image --name vexplain-test-e2e example.com/vexplain-$i:v0.0.1; done
kubectl create ns vexplain-system
kubectl label ns vexplain-system pod-security.kubernetes.io/enforce=restricted
make deploy DEPLOY_CONFIG=test/e2e/config IMG=example.com/vexplain-manager:v0.0.1 \
  SCANNER_IMG=example.com/vexplain-scanner:v0.0.1 MATCHER_IMG=example.com/vexplain-matcher:v0.0.1
go run ./hack/measure-2a --cases hack/measure-2a/cases.yaml --registry localhost:5001
make cleanup-test-e2e
```

`make deploy` edits `config/manager/kustomization.yaml` and `config/matcher/kustomization.yaml` in place. Put them back before committing.

## The cases

Nine planted images, built from `hack/measure-2a/images/<case>`, and six public ones, pinned by digest. "Tracked" in the first column is the rules as built, and the second column is what the evidence alone says. `cases.yaml` has the full basis of each case.

| Case | Image | Expected | Without override | Basis |
|---|---|---|---|---|
| `installed-not-linked` | Alpine 3.12, `brotli-libs` | Tracked | Suppressed | No ELF file needs a Brotli library, no file names one, no preload |
| `linked` | Alpine 3.12, `brotli-libs` and the `brotli` command | Tracked | NeedsAssessment | `/usr/bin/brotli` needs all three libraries. The command package has a finding of its own |
| `linked-curl` | Alpine 3.13, `curl` | Tracked | NeedsAssessment | `curl` and `libcurl.so.4` need `libbrotlidec.so.1` |
| `removed-files` | Alpine 3.12, `brotli-libs`, files deleted in a later layer | Tracked | Suppressed | The package database lists six files and none is left |
| `bare-name` | Alpine 3.12, Python and `brotli-libs` | Tracked | NeedsAssessment | Only a script names the library, by its bare name, through `find_library("brotlidec")` |
| `preload-env` | Alpine 3.12, `brotli-libs` | Tracked | NeedsAssessment | The image sets `LD_PRELOAD` to the decoder library |
| `static-copy` | One static binary, in `scratch` | NotFound | NotFound | The binary holds Brotli's decoder, and no package lists it |
| `scratch` | One static binary that waits, in `scratch` | NoPackage | NoPackage | No packages, and no trace of Brotli |
| `backported` | Debian 12, `libbrotli1` 1.0.9-2+deb12u1 | NoPackage | NoPackage | Debian fixed the CVE inside the upstream release 1.0.9, and the database records the fix |
| `kogito-data-index` | Public, RHEL 8, linux/amd64 | Tracked | NeedsAssessment | `brotli` owns a command, and `curl`, `microdnf`, `libcurl`, `libdnf` and `librepo` need its libraries |
| `kogito-jobs-service` | Public, the same base | Tracked | NeedsAssessment | As `kogito-data-index` |
| `kogito-management-console` | Public, RHEL 9, linux/amd64 | Tracked | NeedsAssessment | `libbrotli` owns libraries only, and the Apache module `mod_brotli.so` needs two of them |
| `keycloak` | Public, Debian 12, linux/arm64 | Tracked | NeedsAssessment | `curl` and `libcurl` need `libbrotlidec.so.1` |
| `postgis` | Public, Debian 11, linux/amd64 | NotFound | NotFound | `libbrotli1` is there and 16 ELF files need it, but the database has no record of the CVE for Debian 11 |
| `node` | Public, the Debian 12 slim variant, linux/arm64 | NotFound | NotFound | No Brotli package, and the `node` binary bundles a copy of the decoder |

**Left out:** none. The curl of Alpine 3.12 doesn't link Brotli, so `linked-curl` is on Alpine 3.13, which the database flags the same way. Debian ships a fixed backport of the CVE (1.0.9-2+deb12u1), so `backported` is in.

**For the owner's review.** The judgment calls in the known answers:

- `postgis` is `NotFound`, though the package is installed and reached. The database has no record for Debian 11, so no finding exists. The answer says the data has a gap, where `node`'s says that a copy is invisible.
- `backported` is `NoPackage`, though Brotli is installed: the installed version carries the fix, so no affected package is present, and a finding would be a false positive.
- Every case in which the package is flagged expects `Tracked`, because the CVE is in the catalog of known exploited vulnerabilities.
- The second column rests on judgment in two places: whether a name in a file is a way to load a library (`bare-name`), and whether the image's own `LD_PRELOAD` is (`preload-env`).

## Known-answer check

| Case | As built: expected, actual | Without the override: expected, actual |
|---|---|---|
| `installed-not-linked` | Tracked, Tracked | Suppressed, Suppressed |
| `linked` | Tracked, Tracked | NeedsAssessment, NeedsAssessment |
| `linked-curl` | Tracked, Tracked | NeedsAssessment, NeedsAssessment |
| `removed-files` | Tracked, Tracked | Suppressed, Suppressed |
| `bare-name` | Tracked, Tracked | NeedsAssessment, NeedsAssessment |
| `preload-env` | Tracked, Tracked | NeedsAssessment, NeedsAssessment |
| `static-copy` | NotFound, None | NotFound, None |
| `scratch` | NoPackage, None | NoPackage, None |
| `backported` | NoPackage, None | NoPackage, None |
| `kogito-data-index` | Tracked, Tracked | NeedsAssessment, NeedsAssessment |
| `kogito-jobs-service` | Tracked, Tracked | NeedsAssessment, NeedsAssessment |
| `kogito-management-console` | Tracked, Tracked | NeedsAssessment, NeedsAssessment |
| `keycloak` | Tracked, Tracked | NeedsAssessment, NeedsAssessment |
| `postgis` | NotFound, None | NotFound, None |
| `node` | NotFound, None | NotFound, None |

Both columns match in all 15 cases, and neither has a false "not affected". Of the findings of the target CVE, 11 in all, the rules as built track every one. Without the override the evidence alone would suppress 2, in the two planted images where nothing loads the library (`installed-not-linked` by the load check, `removed-files` by the removed package), and would keep the other 9 open.

**The blind spots.** Three cases are `NotFound`: `static-copy`, `postgis` and `node`. In each of them Brotli is in the image and the sheet holds no finding for it, so the target CVE is invisible to the scan there.

**An open design question.** The second column is input to it: should a known-exploited vulnerability override the evidence that nothing loads the library, or only raise the urgency? Phase 2a keeps the override, and a finding that the catalog lists is `Tracked` whatever the image can load. Across all findings of the test set the catalog took 19; the evidence alone would suppress 2 of them, and keep 17 open for an assessment.

## The residual on the test set

The 15 manifests have 6,770 findings. The tables count the findings that the sheets list; none was left out.

| Outcome | Findings | Critical | High | Medium | Low | Negligible | Unknown |
|---|---|---|---|---|---|---|---|
| NeedsAssessment | 6,743 | 226 | 1,924 | 2,983 | 863 | 717 | 30 |
| Tracked | 19 | 8 | 11 | 0 | 0 | 0 | 0 |
| Suppressed | 8 | 0 | 0 | 6 | 2 | 0 | 0 |
| All | 6,770 | 234 | 1,935 | 2,989 | 865 | 717 | 30 |

| Outcome | Findings | Fixed | NotFixed | WontFix | Unknown |
|---|---|---|---|---|---|
| NeedsAssessment | 6,743 | 3,084 | 2,256 | 642 | 761 |
| Tracked | 19 | 11 | 0 | 0 | 8 |
| Suppressed | 8 | 8 | 0 | 0 | 0 |
| All | 6,770 | 3,103 | 2,256 | 642 | 769 |

**What decided each outcome.** The residual is what no rule settled.

| Outcome | Rule | Findings |
|---|---|---|
| NeedsAssessment | none applied | 4,225 |
| NeedsAssessment | LoadCheck kept it open | 2,518 |
| Tracked | KnownExploited | 19 |
| Suppressed | LoadCheck | 8 |

- No rule applied to 4,225 findings. They are in packages that the load check leaves out, such as a package that owns an executable or owns no shared library.
- The load check kept 2,518 findings open: something in the image reaches or names a library of the package, or the image preloads libraries. A system library, such as the C library or an SSL library, is reached by almost everything in an image.

**The target CVE.** 11 findings in the 15 manifests, all `Tracked`: 8 Critical and 3 High, 4 with a known fix and 7 with none. The planted Alpine images have 7 of them, whose fix state is unknown. The Debian and RHEL images have 4, each with the fixed version in the database.

**Without the known-exploited override**, the same 6,770 findings come to 6,760 for an assessment, none tracked, and 10 suppressed (9 by the load check and 1 by the removed package). The 19 that the catalog took are 11 of the target CVE and 8 of other known exploited vulnerabilities.

**By case.**

| Case | Findings | NeedsAssessment | Tracked | Suppressed |
|---|---|---|---|---|
| `installed-not-linked` | 103 | 102 | 1 | 0 |
| `linked` | 104 | 102 | 2 | 0 |
| `linked-curl` | 165 | 163 | 2 | 0 |
| `removed-files` | 103 | 102 | 1 | 0 |
| `bare-name` | 196 | 195 | 1 | 0 |
| `preload-env` | 103 | 102 | 1 | 0 |
| `static-copy` | 0 | 0 | 0 | 0 |
| `scratch` | 0 | 0 | 0 | 0 |
| `backported` | 222 | 222 | 0 | 0 |
| `kogito-data-index` | 822 | 821 | 1 | 0 |
| `kogito-jobs-service` | 822 | 821 | 1 | 0 |
| `kogito-management-console` | 874 | 865 | 1 | 8 |
| `keycloak` | 1,179 | 1,178 | 1 | 0 |
| `postgis` | 1,838 | 1,831 | 7 | 0 |
| `node` | 239 | 239 | 0 | 0 |

Most of the findings are in the base images, in packages that no rule here is about: an Alpine 3.12 image carries about a hundred, and the Debian and RHEL images several hundred each. The rules settled 27 of the 6,770: the 19 that the catalog lists, and 8 by the load check. The rest is the residual that the agent of a later phase is for.

## What the rules suppressed outside the known answers

The 8 suppressed findings of the whole run are in one image, `kogito-management-console`, in two packages: `apr-util-bdb` and `apr-util-openssl`, for four CVEs each (three Medium and one Low, all with a fix). The known answers cover none of them. The load check settled them as not affected, with the condition `NoPreloadEnvironment`.

- Both packages own plug-in libraries, `apr_dbm_db-1.so` and `apr_crypto_openssl-1.so`. They have sonames, and nothing needs them: no ELF file lists them.
- Apache's APR-util loads them with `dlopen`, by a name that it builds at run time from a format string (`apr_dbm_%s-1.so`, `apr_crypto_%s-1.so`). So no file of the image contains the name that the load check searches for.
- The image's Apache loads `mod_authn_dbm`, `mod_authz_dbm` and `mod_socache_dbm`, which open DBM databases through APR-util. A search of `/etc/httpd` and of the application's directory finds no directive that opens a DBM database, a DBD driver or a crypto session, so the image may never load these libraries. Whether it does depends on how it is used.

This is a pattern, and no confirmed false "not affected": a library that a program loads by a name that it assembles has no reference that a search can find. The question for the owner is whether a package whose libraries nothing references should be suppressed when it sits beside a program that loads plug-ins this way.

## Completeness

The completeness of a manifest is the share of its ELF files that packages own. The guard stops every suppression below 90%, the default of `OperatorConfig.spec.rules.minCompletenessPercent`.

| Case | ELF files | Owned by a package | Completeness |
|---|---|---|---|
| `installed-not-linked` | 19 | 19 | 100% |
| `linked` | 20 | 20 | 100% |
| `linked-curl` | 25 | 25 | 100% |
| `removed-files` | 16 | 16 | 100% |
| `bare-name` | 110 | 110 | 100% |
| `preload-env` | 19 | 19 | 100% |
| `static-copy` | 1 | 0 | 0% |
| `scratch` | 1 | 0 | 0% |
| `backported` | 697 | 697 | 100% |
| `kogito-data-index` | 428 | 428 | 100% |
| `kogito-jobs-service` | 428 | 428 | 100% |
| `kogito-management-console` | 641 | 641 | 100% |
| `keycloak` | 859 | 789 | 91% |
| `postgis` | 1,046 | 1,046 | 100% |
| `node` | 695 | 695 | 100% |

- The scanner counts a Go program that Syft lists as packages of its own (its modules) as owned, so its figures are a file or two above the counts of the package databases alone: `keycloak` 789 against 788, `kogito-management-console` 641 against 640, and `postgis` 1,046 against 1,044. The basis of the known answers gives the counts of the databases.
- 13 of 15 manifests are at 100%. `static-copy` and `scratch` have 0%, because their one ELF file belongs to no package. They have no package, so there is no finding that the guard could hold back.
- `keycloak` is at 91%, one point above the guard: the 70 files of its Java runtime are in no package database. It has no suppression, so the guard held nothing back there.
- The guard held no finding back in this run, with or without the override: no finding names it as its rule.

## Sizes against decision 0004's triggers

Decision 0004's first trigger is any inventory object above 512 KiB. An `ImagePackages` holds its evidence as base64, so the object is a third larger than the compressed evidence. A scan whose compressed evidence passes 768 KiB (`inventory.MaxEvidenceBytes`, 786,432 B) fails with the reason `TooLarge`. The sheet column is the JSON of the `ImageVerdicts` object.

| Case | Compressed evidence | As base64 | Decoded | Sheet | Packages | Findings |
|---|---|---|---|---|---|---|
| `installed-not-linked` | 5,947 B (1%) | 7,932 B (1%) | 33,821 B | 23,770 B (4%) | 15 | 103 |
| `linked` | 6,074 B (1%) | 8,100 B (1%) | 35,367 B | 23,981 B (4%) | 16 | 104 |
| `linked-curl` | 7,010 B (1%) | 9,348 B (1%) | 43,413 B | 36,190 B (6%) | 19 | 165 |
| `removed-files` | 5,879 B (1%) | 7,840 B (1%) | 33,101 B | 23,770 B (4%) | 15 | 103 |
| `bare-name` | 9,559 B (1%) | 12,748 B (2%) | 63,766 B | 42,386 B (8%) | 25 | 196 |
| `preload-env` | 5,944 B (1%) | 7,928 B (1%) | 33,820 B | 23,770 B (4%) | 15 | 103 |
| `static-copy` | 1,832 B (0%) | 2,444 B (0%) | 4,948 B | 1,081 B (0%) | 0 | 0 |
| `scratch` | 1,830 B (0%) | 2,440 B (0%) | 4,946 B | 1,081 B (0%) | 0 | 0 |
| `backported` | 26,903 B (5%) | 35,872 B (6%) | 307,703 B | 51,313 B (9%) | 89 | 222 |
| `kogito-data-index` | 164,460 B (31%) | 219,280 B (41%) | 2,052,369 B | 197,566 B (37%) | 418 | 822 |
| `kogito-jobs-service` | 133,125 B (25%) | 177,500 B (33%) | 1,711,840 B | 197,577 B (37%) | 378 | 822 |
| `kogito-management-console` | 44,884 B (8%) | 59,848 B (11%) | 466,765 B | 215,481 B (41%) | 148 | 874 |
| `keycloak` | 771,627 B (147% OVER) | 1,028,836 B (196% OVER) | 4,910,260 B | 285,841 B (54%) | 567 | 1,179 |
| `postgis` | 66,927 B (12%) | 89,236 B (17%) | 739,167 B | 472,940 B (90%) | 231 | 1,838 |
| `node` | 52,406 B (9%) | 69,876 B (13%) | 549,076 B | 55,025 B (10%) | 235 | 239 |

Percentages are of 512 KiB.

- **The first trigger fires.** The evidence of `keycloak` is 771,627 B compressed, and its `ImagePackages` object holds about 1 MiB of base64. Decision 0004 calls its triggers the designer's call, to be revisited with real numbers, and this is the first number of that kind.
- **`keycloak` is close to the limit.** Its compressed evidence is 98% of the 768 KiB that an `ImagePackages` can hold, so an image a little larger than it would fail with `TooLarge`. Its SBOM lists 567 packages, and its evidence is 4.9 MB before compression.
- **Sheets stay under the trigger.** The largest is `postgis` with 1,838 findings and 472,940 B, which is 90% of it. No sheet came near the limits of 2,048 findings and 1 MiB, and none left a finding out.
- The other two triggers, a sustained write rate above 5 per second and objects above 10% of etcd's database, are not measured here. The run writes each object once.

**The result line.** A scan prints one line, the base64 of the gzip of its result. The e2e covered no line over 16 KiB, the size at which a container runtime splits a log line. This run is the first to cover them. The line isn't stored, so the tool computes its length from the stored evidence, with the encoder of the scanner: the line of the whole result, with its newline.

| Case | Line |
|---|---|
| `kogito-data-index` | 219,365 B |
| `kogito-jobs-service` | 177,589 B |
| `kogito-management-console` | 59,957 B |
| `keycloak` | 1,028,981 B |
| `postgis` | 89,321 B |
| `node` | 70,021 B |

- All six lines are over 16 KiB, and `keycloak`'s is about 1 MiB. All six scans were read whole: the operator found the one line in the pod log, and stored the evidence.
- The planted images' lines run from 2,521 B to 35,945 B. Only `backported`, at 35,945 B, is above 16 KiB.
- As a check of the computation, the scanner image run by hand on the same images printed 1,028,981 B for `keycloak`, the same, and 70,017 B for `node`, four bytes less.

## What it doesn't show

- **A test set, not a sample.** 15 images chosen for known answers. The counts of findings say what the rules do to these images, and nothing about the images of a platform.
- **One CVE, one finding per case.** The known answers cover the target CVE in the library package of the 10 cases that have a finding there, and the lack of one in the other 5. The other 6,760 findings have no known answer, so the check can't call any of them a false "not affected". The 8 suppressions among them are described above.
- **Only the findings that a package database lists.** A copy that no package lists is invisible (`static-copy`, `node`), and so is a package that the database doesn't cover (`postgis`). Opening archives and searching binaries for embedded copies come later.
- **Names that a program builds at run time.** The load check can't see them, as the suppressions above show.
- **The pod's environment.** A finding that the load check suppresses carries the condition `NoPreloadEnvironment`. The check of each workload's pods for `LD_PRELOAD` belongs to the phase that renders the sheets.
- **One database and one node.** The numbers belong to the database `v6.1.10+2026-10-30T06:23:28Z`, and change with every build. The cluster had one linux/arm64 node, so no case has two platforms, and the linux/amd64 images were scanned as the platform that their configuration names, with their pods run through the emulation of the Docker host.
- **The scans' timing.** A figure for how long a scan or a case takes is not given here.
- **The residual's value.** Counting the residual is half of the value figure. The other half, the time that a person takes for a case, comes from the owner and stays outside the repository.
