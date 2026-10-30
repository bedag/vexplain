# 0027 `govulncheck` becomes its own collector, after phase 2a

- **Status:** Accepted (decided by the owner on 2026-10-30)
- **Date:** 2026-10-30
- **Refines:** 0022 and design 6.3, which put `govulncheck` inside the `Scanner`.

## Context

`govulncheck` shows whether a Go binary contains the vulnerable functions of a Go CVE. Inside the `Scanner`, it can't keep 0022's promise to match again after a database update without pulling the image again, unless the work is split:
- the scan Job extracts each Go binary's symbol table
- the hub matches it against a second database, Go's vulnerability database, because Grype's has no symbol data

That split costs in two ways:
- **Size:** a large binary's symbol table can reach hundreds of KB even compressed, so an image with several Go binaries runs into 0004's size limits.
- **Staleness:** a result worked out inside the Job turns into a false "not affected" once a vulnerability entry gains symbols, unless the image is pulled again.

The Brotli measurement of phase 2a doesn't need `govulncheck`.

## Decision

- **`govulncheck` becomes a collector of its own, `Govulncheck`,** with its own Job and with Go's vulnerability database at the hub. Like every collector, it can be switched off and versioned on its own (0007).
- **It is built after phase 2a.** When exactly is planned with phase 2b.
- **Until then:**
  - the `Scanner` records Go build info: the module versions, which Grype matches at module level
  - no finding is settled by `govulncheck`, so the residual is bigger, never settled wrongly
- **The planted Go test images** (section 9) are measured with this collector, not in 2a.

## Consequences

- **The `Scanner` and phase 2a get smaller:** no second database, and no symbol tables in `ImagePackages`.
- **The `Govulncheck` collector must settle** how to store symbol tables within 0004's limits, and how to rescan when Go's database gains symbols.
- **One collector per source** stays the rule, as for exposure (0006).
