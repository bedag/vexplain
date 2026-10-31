# 0032 Evidence travels as CloudEvents; collectors define their own types and subjects; each type declares its scope

- **Status:** Proposed on 2026-10-31. The direction is the owner's; the write-up waits for the owner's review.
- **Date:** 2026-10-31
- **Supersedes:** 0007's evidence kinds, which the core defined.
- **Refines:** 0021, whose tasks become requests for evidence, and 0023, on where evidence is kept. It gives 0028's way back a place to state coverage.
- **Design:** [collectors, evidence and rules](../design/2026-10-31-collectors-evidence-rules.md), sections 5.1, 5.5 and 5.6.

## Context

- **The stores are typed per producer:** `ImagePackages` holds exactly one scanner's evidence per manifest. A second source of the same facts has nowhere to go.
- **The owner wants collectors to bring their own evidence types,** without the core defining or approving them, and their own kinds of subject, such as virtual machines.
- **0028's way back needs a stated confidence.**
- **Standards:**
  - CNCF's CloudEvents is the standard envelope for data that a producer emits. Its `type` is named by whoever defines it, its `source` names the producer, and its `dataschema` points to the data's schema. It has a protobuf format.
  - in-toto attestations fit supply-chain evidence, but every subject must have a digest, and workloads don't have one.
  - Kubernetes CRDs declare their own scope, `Cluster` or `Namespaced`.

## Decision

- **Every piece of evidence is a CloudEvent.** An optional `coverage` extension states a whole-number percentage of how much of the subject it covers. Each type documents what that percentage counts, and the core never interprets it. The scanner's coverage is 2a's completeness.
- **Collectors define their own types,** named in reverse-DNS and versioned, each with a JSON Schema.
- **The core reads four types of its own:** presence, findings, exposure, and a rule's result. It reads no other type.
- **Subjects** are paths with a prefix. vexplain defines `image/…`, `manifest/…` and `workload/…`, and a collector may add its own, such as `vm/…`, which the core passes on without interpreting.
- **Each type declares its scope,** as a CRD does: `Hub` evidence is collected at the hub across clusters, and its subjects must be unique across clusters. `Spoke` evidence stays in its cluster, and the spoke summarises presence and exposure per digest.
- **Evidence on demand:** vexplain invokes the operations that produce what each playbook needs for its subjects (0034). The hub asks spokes for evidence of a type, not for a collector.
- **Storage:**
  - A generic, compressed evidence store, keyed on subject, type and source, replaces `ImagePackages`.
  - Its interface is the contract, and its backend is 2a's CRDs, with 2a's size cap. The owner decided on 2026-10-31 that 0004's fired trigger is checked once vexplain runs on a real cluster.

## Consequences

- No core code knows a collector's types. Only the playbooks and rules that admins write name them.
- A new kind of subject needs no change in the core, only collectors and a playbook.
- `ImagePackages` is replaced in phase 2b. It is `v1alpha1`, and nothing outside vexplain uses it.
- Evidence about images can later be exported as in-toto attestations, to sign it or attach it to the image.
- **Rejected:**
  - evidence kinds defined by the core, because each new source would need the core to agree
  - routing evidence by its subject, because a collector's own subjects would need the core to know them
  - in-toto as the envelope, because of workload subjects
