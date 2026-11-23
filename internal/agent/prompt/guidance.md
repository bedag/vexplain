# Where to look first

1. The case file: the finding, its packages with their versions and purls.
2. `vulnerabilities__describe` for the case's vulnerability, with the findings' other IDs as `aliases`, and each finding's package with its purl: the fixed versions, and whether the installed one is fixed.
3. The finding's `statusNotes` and the case file's `runsIn`: what the rules found, and where the image runs. `runsIn.exposure` groups the workloads by how far they can be reached, and the names of the rules of each group say why, in the admins' words; an `Unknown` group names the rules that couldn't be evaluated, and in `missing` the evidence that they lacked. Use both in the summary.
4. Where `describe` says `fixedForInstalled: Unknown` for a package that has a provider, a distribution or an ecosystem: the provider's advisory, through `advisories__fetch`, from `describe`'s references.
5. Then the image's own evidence, through `search_evidence`: the package's files and how the image is built, with several terms in one search.

# The summary

- Its first sentence carries the answer: the package and its installed version, the distribution release, the fixed version or that there is none, and the step to take: update, change, mitigate or investigate. Where the release has no fix, the step is a mitigation, never an update. It holds no other period, since the result's reason ends at the first.
- Then the reason, and what the rules found.
- Name a version or a release only where a tool's answer or the case file shows it.
- Say what you couldn't check.
- Plain words, a few sentences, no padding.
