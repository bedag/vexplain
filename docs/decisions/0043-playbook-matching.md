# 0043 Playbooks name types, take optional entries and a match, run several at once, and show the fleet picture

- **Status:** Accepted on 2026-11-08 (decided by the owner). Two parts are the designer's calls: optional entries, and where cluster labels live before multi-cluster. Refined on 2026-11-09 (designer's calls): who takes part, readiness, requests to each producer, and matches that need every producer's evidence.
- **Date:** 2026-11-08
- **Refines:**
  - 0034: playbooks;
  - 0033: a rule that confirms a finding names a step, a title and a severity;
  - 0015: the scope stays, as the boundary of what is collected.
- **Design:** [the collector model](../design/2026-11-08-collector-model.md), section 5.6.

## Context

- **A playbook named collectors,** and one missing collector stopped every verdict.
- **Only the oldest playbook over presence ran.**
- **One hub may serve spokes of several stages,** with stricter requirements for production (owner).
- **The admin wants the big picture for each playbook** on the hub (owner).

## Decision

- **Types, not collectors.**
  - Every producer of a type counts, unless an entry pins its producers by collector name.
  - Evidence from several producers is evaluated once per producer, and the most cautious outcome wins.
  - A findings producer takes part only when it consumes one of the playbook's evidence types (refined 2026-11-09).
  - A required entry, or one that a taking-part producer consumes, stops the playbook only when no installed collector declares its type; a producer's health never does, it only decides whether requests go to it.
  - The hub asks each producer whose evidence is missing or stale and that can be asked; each producer keeps its own back-off.
  - A match needs the evidence of every producer of what it consumes; until then the subject has no verdict. A playbook names each evidence type once.
- **Optional evidence entries,** as a pod refers to a ConfigMap with `optional: true`.
  - Without the entry's producer, the playbook stays Ready.
  - A missing input follows the engine's rule for errors: a rule that settles doesn't apply, and a rule that holds or confirms keeps the finding open.
- **A match:**
  - clusters, by labels that are set on the hub, never by a spoke about itself;
  - namespaces, by selectors.

  Until multi-cluster, the one cluster's labels sit in `OperatorConfig`. `OperatorConfig`'s scope stays as each cluster's collection boundary.
- **Where matching happens:** the hub matches clusters, and the spoke matches namespaces when it renders. Namespace labels stay in the cluster. Each spoke reports every playbook's counts for its cluster, for the fleet picture.
- **Several playbooks at once.** Their results add up, each naming its playbook. A stricter variant of a use case comes with an exclusion in the default playbook.
- **How findings start:**
  - suspected gaps, such as CVEs, start open and fail closed;
  - an inventory, such as every certificate, starts passing.

  A rule that errors keeps a finding open in both cases.
- **Actions come from each rule that confirms a finding.** Such a rule names its weakness (optionally with a CWE ID), a step, a title in CEL and a severity. CVE findings keep the merge, where the most cautious status wins, and 0024's step.
- **One vocabulary for every weakness:** OpenVEX's four statuses. A misconfiguration is a weakness just as a vulnerability is.
  - A `NotAffected` needs a justification that fits the kind of weakness: OpenVEX's five for vulnerabilities, and for configuration weaknesses the justifications of CycloneDX's VEX that fit configuration (`requires_configuration`, `requires_environment`, `protected_at_perimeter`, `protected_at_runtime`, `protected_by_mitigating_control`).
  - A resource without the weakness gets no statement.
- **A collector may ship suggested playbooks and rules** as manifests, which the admin applies.
- **The fleet picture:**
  - the Playbook's status holds the subjects it judged and those failing, by step and severity, and the same per cluster, capped;
  - the hub exports metrics per playbook and rule.

## Consequences

- **Checkers plug in without stopping a playbook.** A second producer of findings needs no playbook change.
- **Production and development can have different requirements.**
- **`kubectl get playbooks` on the hub reads like a fleet overview.**
- **Rejected:**
  - moving the scope entirely into playbooks, which would leave no collection boundary;
  - letting spokes report their own labels, which would let a spoke pick the lenient playbook.
