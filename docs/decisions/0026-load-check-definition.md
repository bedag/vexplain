# 0026 What the load check searches, what it skips, and what "removed in a later layer" means

- **Status:** Accepted (designer's calls, put to the owner on 2026-10-30 without objection). The phase 2a plan carries the pod-level check as the finding condition `NoPreloadEnvironment`. Phase 2b's renderer checks it for each workload, and decides then whether `envFrom` counts.
- **Date:** 2026-10-30
- **Refines:** the load check and the "removed in a later layer" rule of design 6.5 (revision 4). Each verdict covers one finding (0025).

## Context

- **The load check as written** (design 6.5): no ELF file reaches the vulnerable library through `DT_NEEDED`, followed transitively, and no file contains its soname, which catches `dlopen`. Taken literally, it can never pass for a distro library, because these always contain the soname:
  - the library's own files, and their symlinks
  - the package database: dpkg's `.list` and `.md5sums`, apk's `installed`, the rpm database
  - the linker cache, `/etc/ld.so.cache`
- **Other names can load the library:**
  - the unversioned name, such as `libbrotlidec.so`
  - the bare name, such as `brotlidec`, which Python's `ctypes.util.find_library` and Java's `System.loadLibrary` take
- **Preloading:** `LD_PRELOAD` and `LD_AUDIT` can load a library without any reference in the files.
- **The scan Job can't know the CVE.** It has to record the evidence for every library up front, and changing what it records later means pulling every image again.
- **Our scanner sees only the final filesystem.** So a package that a later layer deleted is never reported in the first place.

## Decision

- **The scan Job records, for every shared library in the image** (every ELF file with a soname):
  - the transitive `DT_NEEDED` paths that reach it
  - every file that contains its versioned soname, its unversioned name, or its bare name, except for:
    - the files of the package that owns the library, including their symlinks
    - the package databases
    - the linker cache
- **The load check settles a finding as "not affected" only when:**
  - no ELF file reaches the library through `DT_NEEDED`, followed transitively
  - no file outside those exceptions contains any of its three names
  - neither the image's configuration nor the pod sets `LD_PRELOAD` or `LD_AUDIT`. Only their presence is checked; their values are never read (design 6.11).
- **Archives such as JARs and wheels aren't opened in 2a.** A library bundled inside one is another copy, outside the finding (0025).
- **"Removed in a later layer"** means the package database still lists the package, but its files are gone from the final filesystem.
  - The scan Job records, for each package, whether its files are present.
  - The rule settles the finding as "not affected", with the justification `component_not_present`, for that package only (0025).

## Consequences

- **Every name searched can only make the residual bigger,** never settle a finding wrongly. A file that merely mentions the bare name blocks the rule. That errs on the safe side.
- **The scan result grows** by one list of hits per shared library. That is small next to the package list, and 2a's measurement records its size.
- **The output format of the scan Job is fixed here,** so later rules can use the same evidence without pulling again.
- **Opening archives** comes with the search for embedded copies (0025).
