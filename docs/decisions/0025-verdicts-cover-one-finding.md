# 0025 A rule's verdict covers one finding: a CVE in one package of one image

- **Status:** Accepted (decided by the owner on 2026-10-30). Its example of the load check predates 0028 (2026-10-31): the load check now settles nothing, and what a verdict covers holds for every rule that settles one.
- **Date:** 2026-10-30
- **Refines:** 0010, by saying what a rule-settled result covers. It also says what key `ImageVerdicts` has (design 6.2).

## Context

A finding is a CVE that the matcher reports for one package of an image, such as Alpine's `brotli-libs`. A rule settles it with evidence about that package. The load check, for example, proves that nothing in the image can load that package's library.

The image can hold other copies of the same code, which the scan doesn't report:
- a statically linked copy in a copied binary, which is one of the planted test images (section 9)
- a copy built into a program the scanner already recognises. The everyday case is the official `node` images: they compile Brotli into the `node` binary, which the scanner lists only as `node`.

A "not affected" that covered the whole image would be false whenever such a copy exists. AGENTS.md calls that the worst possible error. Rule results also aren't reviewed one by one (0010), so a rule that overclaims does so for every image at once.

OpenVEX scopes a statement the same way: a product, here the image, can list `subcomponents`, the components "where the vulnerability originates". The status then applies to the products and components the statement lists.

## Decision

- **A rule's verdict covers one finding:** this CVE, in this package, in this image (platform manifest digest). It says nothing about other copies of the same code.
- **`ImageVerdicts` is keyed on the platform manifest digest,** like `ImagePackages` (0023) and assessments (0011).
  - There is one row per finding (CVE and package).
  - A database update rewrites one sheet per manifest whose outcome changed.
  - A spoke finds its sheet through `ImageInventory`, from the reported digest and the platform of its node.
- **Reports state the scope.** Next to each verdict they name the package it covers, and they show the image's completeness score.
- **The completeness guard stays.** Below the threshold, no rule settles a finding as "not affected".
- **Other copies are a known blind spot.**
  - The measurement counts a planted copy the scanner can't see as "not found", never as "not affected".
  - A search for embedded copies comes later, with the agent's tools. It looks for a library's symbols in every binary.
- **Assessments by the agent** (phase 4) still look at the whole image for a CVE, with that search among their tools. Their statements say which products and subcomponents they cover.

## Consequences

- A rule's "not affected" is exactly as strong as its evidence. It never covers code the scanner didn't see.
- **Reading a report:** "not affected" for a finding means that package's copy can't be reached. It doesn't mean the image is free of the bug. Reports must make that visible, and spokes render it per workload in phase 2b.
- **The residual** counts findings, not images.
- **Rejected:**
  - **Blocking the rule whenever any binary isn't owned by a package.** It's safe, but most application images would never settle.
  - **Searching for embedded copies in 2a.** That is new scanner work, close to the deferred `BinaryIdentification`, and the measurement doesn't need it.

## Sources

- [OpenVEX specification: products and subcomponents](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md)
- [Node.js bundled dependencies: `deps/brotli`](https://github.com/nodejs/node/tree/main/deps/brotli)
