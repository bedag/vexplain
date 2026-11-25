# 0067 Presence and exposure across versions: readers ignore fields they don't know, and presence never forgets what it can't read

- **Status:** Accepted on 2026-11-25. The direction is the owner's: presence never forgets what it can't read, and
  readers tolerate fields they don't know. The store's rule per type and the rule for new fields are the designer's
  calls, marked **[call]**.
- **Date:** 2026-11-25
- **Refines:** 0058: an off-schema presence event keeps its stored record; an off-schema exposure event still deletes
  its own.
- **Design:** [remote spokes](../design/2026-11-23-remote-spokes.md), section 5.12.

## Context

- **Run 6's results dipped after an upgrade,** and came back only as the images were scanned again.
- **An upgrade on kind from the old build to the new found the cause:**
  - the new `workloads` collector sends a field that the old manager's presence schema doesn't know (`subject`), and
    that schema refuses any field it doesn't know;
  - while the new collector streamed to the old manager, which still led, every presence event was refused;
  - presence took the refused snapshot for "nothing runs", forgot every image, and the `ImageInventory` objects went
    with their facts;
  - the new manager made them again without facts, so every case read "not running" until its image was scanned
    again.
- **The same happens the other way round:** a newer manager refuses an older collector's events that lack a field it
  requires.
- **Phase 6 makes such skew last longer.** Spokes are upgraded after the hub (design 5.12), a spoke on prod through
  the CI pipeline's manual steps, and the hub's copies pass the hub's own validation (0063). A collector released on
  its own schedule can lag or lead the manager too.

## Options considered

| Option | Costs |
|---|---|
| Strict schemas, and forget what can't be read (before) | Any change of a core type's format deletes presence and the images' facts, whichever side is upgraded first |
| Presence never forgets what it can't read | Presence can be stale while versions differ, never missing; a newer collector's data waits for the manager's upgrade |
| Readers ignore fields they don't know | A newer collector feeds an older manager fully; an older collector that lacks a required field is still refused, and forgotten |
| **Both, with new fields optional at first (chosen)** | A field that a reader doesn't know is stored, and ignored |

## Decision

- **Tolerance:** the core's schemas of presence and exposure accept fields they don't know, at every level, and
  readers ignore them.
- **Presence never forgets what it can't read:**
  - a snapshot with an event that presence refuses keeps that collector's last readable snapshot, and doesn't count
    as its snapshot for knowing what runs;
  - a refused upsert or tombstone changes nothing;
  - each refusal is counted.
- **The store, per type** **[call]**:
  - an off-schema presence event keeps the stored record, so a cluster's presence, on the spoke and in the hub's copy,
    never goes missing over it;
  - an off-schema exposure event still deletes its record, as 0058's amendment has it: the workload's exposure then
    reads Unknown, which never lowers an urgency.
- **A new field of a core type starts optional** **[call]**. It turns required only in a later release, once every
  producer sends it. Presence's `subject`, required since the entry points, stays required.

## Consequences

- **The hub, its spokes and their collectors can be upgraded in any order.** Presence may be stale while their
  versions differ, but nothing is forgotten and no facts are lost.
- **A field that a newer collector adds** is stored, and ignored by older readers.
- **A collector older than its manager** that lacks a required field still has its events refused. Its presence stays
  as it last was until the collector rolls.
- **Rejected:**
  - strict schemas that forget what they can't read, as before;
  - keeping the facts after an image's last entry goes, which would only shorten the dip.

**Precedents:**
- the tolerant reader: Postel's law, and Martin Fowler's "TolerantReader";
- Protocol Buffers, which skips the fields it doesn't know, and dropped `required` in proto3;
- Kubernetes' rules for API changes, where a new field is optional, and its version skew policy;
- the full compatibility of Confluent's Schema Registry, which lets readers and writers be upgraded in any order;
- Kubernetes' node lifecycle controller, which stops evicting when a whole zone turns NotReady at once, and Envoy's
  panic threshold: a mass disappearance is treated as a fault, not as the truth.
