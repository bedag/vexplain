# 0044 A neutral `sbom` type between scanners and the matcher

- **Status:** Accepted on 2026-11-08 (decided by the owner, for phase 3).
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
- **The matcher, now `vulnerabilities` (0046), consumes `sbom`.**
- **Rules that read the SBOM,** such as `removed-in-later-layer`, take it as a second input. The default rules and playbook migrate.

## Consequences

- **Any SBOM source can feed the matcher:** a VM disk scanner, SBOMs attached to images in registries, or another scanner. Anchore splits its tools the same way: Syft makes SBOMs, and Grype matches any SBOM.
- **Each piece of evidence gets smaller,** but a manifest has two of them instead of one.
- **The matcher is only as good as the producers' package identities.** Poor purls mean missed CVEs, so the type carries a coverage field.
- **A new core type** to define and version.
- **Rejected:** waiting for the second SBOM source. The owner chose phase 3.
