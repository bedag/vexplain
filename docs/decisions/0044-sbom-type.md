# 0044 A neutral `sbom` type between scanners and the matcher

- **Status:** Accepted on 2026-11-08 (decided by the owner, for phase 3). Refined on 2026-11-08 (designer's call): a package's purl names its source package and distribution, which `vulnerabilities` reads as Grype's purl input does. Refined on 2026-11-08 (owner): the type also carries the producer's SBOM document, which `vulnerabilities` hands to Grype as it is. Amended on 2026-11-13 while phase 3a was built: the known limits of the document built from the packages, and of Syft with nested Java archives, in plain words (Consequences).
- **Date:** 2026-11-08
- **Refines:** 0022 (the matcher) and 0032 (evidence types). The matcher no longer consumes the scanner's own type.
- **Design:** [the collector model](../design/2026-11-08-collector-model.md), section 5.5.

## Context

- **The matcher consumed `scanner.image-contents`,** the scanner's own type, of which it read only the SBOM. Nothing else could feed it: not a scanner of virtual machines' disks, not SBOMs attached to images in registries, not another scanner.
- **The scanner's evidence came close to the size limit** of one object.

## Decision

- **A core type, `sbom`, holds a subject's package inventory:**
  - the distribution;
  - each package, with its ID, name, version, type, purl and CPEs;
  - a coverage field;
  - the producer.
- **The scanner produces it** next to its own `image-contents`, which keeps what only the scanner has: file ownership, ELF facts and coverage.
- **The type also carries the producer's SBOM document,** when it has one, in a standard format that the data names: Syft's JSON without file lists today, CycloneDX or SPDX from other producers (owner, refined 2026-11-08).
- **The matcher, now `vulnerabilities` (0046), consumes `sbom`.** It hands the document to Grype as it is, so its matches are the same as 2b's by construction. Without a document, it builds one from the packages.
- **Rules that read the SBOM,** such as `removed-in-later-layer`, take it as a second input. The default rules and playbook migrate.

## Consequences

- **Any SBOM source can feed the matcher:** a VM disk scanner, SBOMs attached to images in registries, or another scanner. Anchore splits its tools the same way: Syft makes SBOMs, and Grype matches any SBOM.
- **`image-contents` gets smaller,** and `sbom` is about as large as 2b's `image-contents` was, since it carries Syft's document. A manifest has two pieces of evidence instead of one.
- **The matcher is only as good as the producers' package identities.** Poor purls mean missed CVEs, so the type carries a coverage field.
- **Without a document, a purl names its source package and distribution,** in its `upstream` and `distro` qualifiers, as Syft writes them, and an RPM carries its modularity label (refined 2026-11-08). Debian, RPM-based and Alpine distributions track many CVEs by source package, and on AlmaLinux an RPM's module stream decides which advisories apply. A few rare inputs still match less than from Syft's full document: a Java archive whose manifest has a main `Name` attribute; an os-release whose `VERSION_ID` Grype can't parse, or whose `ID` is missing or unknown to Grype without a known `ID_LIKE`; Alpine packages where no distribution was found; and Root.io's Alpine packages, whose extra CPEs Grype derives from metadata. A producer that can send its document avoids them all.
- **Known limits, in plain words** (amended on 2026-11-13 while phase 3a was built):
  - **Root.io's Alpine packages.** Grype derives further CPEs for the packages whose names start with `rootio-` from their Alpine metadata, such as the package's URL. The document built from the packages lacks that metadata, so it misses the matches by those CPEs.
  - **A distribution that Grype knows by its name only.** Grype falls back to os-release's `NAME` when the `ID` is missing, or is one that it doesn't know and no `ID_LIKE` names one that it does. The type carries no `NAME`, so the document built from the packages gives Grype no distribution then, and its OS packages lose the matches that need one.
  - **Nested Java archives,** with or without a document. Syft drops its failure to catalog a JAR inside another JAR when the outer one has packages of its own, so the scanner names no failed cataloger and keeps the coverage. The coverage counts ELF files, which JARs aren't, so it can't show the packages that are missing either.
- **A new core type** to define and version.
- **Rejected:** waiting for the second SBOM source. The owner chose phase 3.
