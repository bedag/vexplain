# 0044 A neutral `sbom` type between scanners and the matcher

- **Status:** Accepted on 2026-11-08 (decided by the owner, for phase 3). Refined on 2026-11-08 (designer's call): a package's purl names its source package and distribution, which `vulnerabilities` reads as Grype's purl input does. Refined on 2026-11-08 (owner): the type also carries the producer's SBOM document, which `vulnerabilities` hands to Grype as it is.
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

- **Any SBOM source can feed the matcher:** a VM disk scanner, SBOM- **Without a document, a purl names its source package and distribution,** in its `upstream` and `distro` qualifiers, as Syft writes them, and an RPM carries its modularity label (refined 2026-11-08). Debian, RPM-based and Alpine distributions track many CVEs by source package, and on AlmaLinux an RPM's module stream decides which advisories apply. A few rare inputs still match less than from Syft's full document: a Java archive whose manifest has a main `Name` attribute; an os-release whose `VERSION_ID` Grype can't parse, or whose `ID` is missing or unknown to Grype without a known `ID_LIKE`; Alpine packages where no distribution was found; and Root.io's Alpine packages, whose extra CPEs Grype derives from metadata. A producer that can send its document avoids them all.
ts source package and distribution,** in its `upstream` and `distro` qualifiers, as Syft writes them (refined 2026-11-08). Debian, RPM-based and Alpine distributions track many CVEs by source package, and Grype reads the source package of an SBOM's package only from its metadata or, for purls, from that qualifier. `vulnerabilities` therefore rebuilds both from the purl, as Grype's own purl input does, so that its matches equal those from Syft's full document.
- **A new core type** to define and version.
- **Rejected:** waiting for the second SBOM source. The owner chose phase 3.
