# 0028 The load check records its evidence and settles nothing

- **Status:** Accepted on 2026-10-31.
  - The owner chose the direction ("evidence only") over refining the check.
  - The owner agreed the first principle's wording and the way back.
- **Date:** 2026-10-31
- **Supersedes in part:** 0026's rule that the load check settles a finding as "not affected". What the scan records under 0026 stands.
- **Changes in the design:**
  - section 1, the first principle
  - section 6.5, the Suppressed row and the Needs assessment row

## Context

- **The measurement.** On phase 2a's 15 test images, the load check settled 8 of 6,770 findings as "not affected", and none of them holds up.
  - All 8 are on two APR-util plug-ins. APR-util loads them under a name it builds at run time from a format string, such as `apr_dbm_%s-1.so`.
  - No file holds the full name, so 0026's search finds no reference.
  - Whether the image loads them can't be settled from its files.
- **More paths of the same shape.** Phase 2a's whole-branch review found these:
  - a library outside the dynamic linker's search path, which only a path that a program builds can load
  - a file name or link name that doesn't contain the soname
  - a reference inside a JAR or ZIP, such as a JNI library that links the system's OpenSSL
  - the owning package's own scripts
  - a name in the image's start command
  - a name in an environment value, which design 6.11 forbids reading
  - a name that comes from outside input
- **Each of these leads to a false "not affected",** the worst error (AGENTS.md).
  - Closing them statically needs new evidence fields, archive reading with limits, and more rules.
  - Even then, the last two remain.
- **What a static search can and can't measure.** It can say how much of the image it looked at. It can't say what a program does while it runs.
  - In the APR-util case, every file was searched, and the name still only exists in memory at run time.
- **Practice elsewhere:**
  - Trivy, Grype and Docker Scout don't mark a package "not affected" because nothing in the image seems to use it.
  - Tools that claim "not in use" observe what running processes load: Sysdig's in-use packages, RapidFort and SlimToolkit.
  - The UAPI Group's ELF dlopen metadata spec exists because tools that read `DT_NEEDED` miss `dlopen`.
- **The design plans runtime observations from phase 3.** Section 6.5 gives the example "library loaded in 0 of 12 observed instances".

## Options considered

- **Refine the check:** close each gap above.
  - It costs a full task: new evidence fields, archive reading, more rules, and planted images.
  - The last two gaps stay open.
- **Keep the evidence and settle nothing (chosen).**
  - It is a small change.
  - This rule can no longer produce a false "not affected".
  - As built, it gives up no correct suppression on the test set. Without the known-exploited override, it gives up one planted case.

## Decision

- **The load check settles nothing.**
  - Where it used to suppress, the finding stays `NeedsAssessment`, with rule `LoadCheck` and the reason "nothing in the image reaches or names its libraries".
  - Where something reaches or names a library, or the image preloads, the reason says so, as now.
- **The scan records the same evidence as 0026 defines.** Its format doesn't change.
- **The reason is a hint,** for people now and for the agent later.
  - Phase 2b may use it to order the worklist, never to settle a finding.
- **The hint's limits are laid out, not hidden.** The rule's documentation, and phase 2b's report text, say what the check can't see:
  - names that a program builds while it runs
  - plug-in paths
  - archives
  - environment values
  - outside input

  The reason in each finding stays short, because a sheet's size is limited.
- **These rules are unchanged:**
  - known exploited (`Tracked`)
  - the completeness guard
  - "removed in a later layer" (`Suppressed`, `component_not_present`), which the scanner's corrected unpacking keeps honest
- **The API keeps two values:**
  - The justification `vulnerable_code_not_in_execute_path`, which VEX statements use.
  - The condition `NoPreloadEnvironment`, which waits for a rule that suppresses on loading again.

## The way back

A verdict on loading can return, with a record of its own, once phase 3's runtime observations exist. That record follows the owner's principle: a verdict is highly likely to be true, and it says what it couldn't check.

- **Each such verdict states its confidence:** how much its evidence covers.
  - **Statically:** what share of the image the scan could examine.
  - **At run time:** for example, "loaded 0 times in 12 instances over 14 days".
- **A policy in the `OperatorConfig` decides whether that confidence is enough for a verdict.**
  - It may be stricter for exposed workloads and severe CVEs.
  - The completeness guard's `minCompletenessPercent` is the existing example of this pattern.
- **That record also decides** which of the static gaps above it closes first.

## Consequences

**The rules settle less.** On the test set:
- **As built:** 0 load-check suppressions, down from 8.
- **Without the known-exploited override:** 1 suppression, down from 10. That one is "removed in a later layer".

**The first principle changes.** The owner's wording, agreed on 2026-10-31:
- **Design section 1:** "Deterministic rules settle a finding only when the evidence makes the verdict highly likely, and each verdict lays out what it couldn't check."
- **AGENTS.md:** "deterministic rules settle a finding only when the evidence makes the verdict highly likely, and each verdict lays out what it couldn't check".
- **The design's sequence diagram:** "rules settle most CVEs" becomes "rules settle what the evidence makes highly likely".
- **Why:** the measurement found the rules settle 27 of 6,770 findings on its test set. Most findings are in packages that ship programs, or in language packages. The reduction comes from function-level evidence such as `govulncheck` (0027), from exposure, from runtime observation and from the agent. A fix also groups work: an image rebuild clears many findings at once (0024).

**What else changes:**
- the load check's outcome
- the e2e spec for an unreached library
- the measurement's expected answers: `installed-not-linked`, without the override, becomes `NeedsAssessment`
- the docs of the rule, of the condition and of the justification

**The measurement runs again** after this change, with the corrected unpacking.

**0026's remaining gaps move** from "with the owner's decision" to phase 3's carried-forward list. The record that brings a verdict on loading back takes them up.
