# 0047 The scanner's pull credentials: `CopyFromWorkload` and `AdminProvided`

- **Status:** Accepted on 2026-11-08 (decided by the owner). Refined on 2026-11-12 (designer's calls): the back-off after a change, refused pulls, and logins for a mirror.
- **Date:** 2026-11-08
- **Refines:** 0011 and 0022, under which the scan Job gets a copy of the workload's credentials. It adopts 0008's two modes for the sandbox.
- **Design:** [the collector model](../design/2026-11-08-collector-model.md), section 5.9; [main design](../design/2026-10-29-vexplain-design.md), section 6.12.

## Context

- **The scanner read only the pod's and its service account's pull secrets.** Images that the nodes pull with their own credentials failed with `Unauthorized`, and the failure named nothing.
- **The design already allowed admins to add credentials,** and the sandbox already has two modes for this (0008).

## Decision

- **The same two modes as the sandbox, with the same names:**
  - **`CopyFromWorkload`** is today's behaviour: the workload's pull secrets are copied into a Secret that the scan Job owns (0022).
  - **`AdminProvided`** uses Secrets that the admin puts into the operator's namespace and lists in the scanner's settings. They are tried after the workload's.
- **A failure names the registry and the credentials it tried.**
- **A change to the settings asks again at once.** A change of the scanner's spec ends the back-off of its earlier failures, which the hub records with the generation they ran under (refined 2026-11-12).
- **A refused pull is asked again within an hour at the latest,** since its fix, a Secret, happens where vexplain doesn't watch (refined 2026-11-12).
- **Logins are looked up for the host the scan pulls from,** the mirror when one is set, so a registry's logins never reach its mirror (refined 2026-11-12).

## Consequences

- **One concept for the scanner and the sandbox,** and several logins per image.
- **The nodes' own credentials stay out of reach,** since a scan Job has no host access.
