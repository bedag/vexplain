# 0045 Evidence `maxAge` is set where evidence is produced

- **Status:** Accepted on 2026-11-08. The direction is the owner's: set it where evidence is produced. The details are the designer's.
- **Date:** 2026-11-08
- **Refines:** 0032.
- **Design:** [the collector model](../design/2026-11-08-collector-model.md), section 5.5.

## Context

- **Some data changes under the same subject,** such as a virtual machine's disk. An image's contents never change under its digest.
- **Freshness had no home,** and a collector can't always notice that its source changed.

## Decision

- **The collector declares a default `maxAge` for each type it produces.** Its author knows whether the data can change under the same subject.
- **The admin overrides it on the `Collector`.** HTTP works the same way: the server that produced a response sets its `max-age`.
- **There is no default in `OperatorConfig`.**
- **A type without a `maxAge` doesn't expire.** Events, a new collector version or a source change refresh it, as today.
- **On expiry, the core asks again.** Until fresh evidence arrives, stale evidence never settles anything.
- **Option for later:** a playbook that asks for fresher evidence than the default, as an HTTP client can send its own `max-age`.

## Consequences

- **No type of phase 3 needs a `maxAge`.** The field comes with the first type that changes under its subject.
- **Rejected:**
  - an operator-wide default, which would re-ask evidence that never changes and re-scan every image on a timer;
  - a setting on rules, which are reused across playbooks, while freshness is a property of the data.
