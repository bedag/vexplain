# 0066 The hub scans every image itself, from its registry; spokes don't scan

- **Status:** Accepted on 2026-11-24. Proposed on 2026-11-24. The decision is the owner's, from the brainstorm of phase
  6. The details marked **[call]** are the designer's. The owner accepted the write-up with the design on 2026-11-24.
- **Date:** 2026-11-24
- **Changes:**
  - 0021: a remote spoke's hands, the scans, run in the hub's cluster;
  - 0011 and 0022: the scan of an image that runs only in a remote cluster gets no copy of its workloads' credentials.
- **Refines:**
  - 0047: the admin's logins (`AdminProvided`) are how the hub pulls the images of remote clusters;
  - 0060: the hub asks spokes for nothing, so it writes nothing into them.
- **Design:** [remote spokes](../design/2026-11-23-remote-spokes.md), sections 4.4, 5.6 and 5.14.

## Context

- **Draft 1 had the hub ask a cluster that runs an image to scan it,** through a request written into the spoke, and
  share the answer with every cluster.
- **A shared answer from a spoke lets a spoke that is broken into forge what an image contains** for the whole fleet,
  since one scan serves every cluster. Binding the answer to the image's index stops it forging other images, but not
  the images that the spoke runs itself.
- **Scans kept per cluster** would scan the same image in every cluster. The rules also evaluate at most 4
  combinations of producers, so per-cluster answers would soon hold every finding open.
- **The owner doesn't want the same image scanned in every cluster that runs it.**
- **The scanner already pulls with logins that an admin provides** (0047). It reads an image's files without running
  them, so it scans any platform on any node.

## Options considered

| Option | Costs |
|---|---|
| In a cluster that runs the image, which the hub asks (draft 1) | The hub writes requests into spokes. A spoke that is broken into can forge what an image contains for every cluster. Answers about different platforms must be merged |
| Each cluster scans its own images, as standalone installs do | The same image is scanned in every cluster, and per-cluster answers hold findings open |
| **The hub scans every image from its registry (chosen)** | The hub's cluster reaches every registry, with logins of its own, and carries the whole scan load |

## Decision

- **The hub's cluster scans every image that runs in the fleet.** The executor runs with the hub, in `Hub` and
  `HubAndSpoke`, and asks the hub's own collectors only.
- **A scan names the platforms that run the image in any cluster,** and pulls from the repositories that any cluster
  pulled it from.
- **It pulls with the admin's logins.** Where the image also runs in the hub's own cluster, the logins of a local pod's
  pull secrets come first, as today. A remote cluster's pull secrets never leave it.
- **The scanner takes the platforms to scan, with or without pods** **[call]**.
- **An image from a registry that the hub can't reach fails visibly** in its facts, with the registry named.
- **Spokes don't scan,** and send no scan results.

## Consequences

- **One scan per image for the fleet.**
- **No spoke can change what an image contains,** for any cluster.
- **The hub writes nothing into a spoke:** no request kind, and no merging of answers.
- **Spokes get lighter:** no scanner, no scan Jobs, and no cluster-wide reads of pods, nodes and pull secrets.
- **The hub's cluster reaches every registry of the fleet,** holds a login for each, and carries the whole scan load,
  which the measurement covers.
- **The hub's scan Jobs parse images that anyone who can deploy on any spoke chooses,** so their isolation matters
  more on the hub.
- **Scanning on a spoke,** for a registry that only that cluster reaches, comes later if a fleet needs it. It would
  bring the forging risk back, and with it binding each answer to the image's index and a trust order among
  clusters.
- **Rejected:**
  - scanning in a cluster that runs the image (draft 1);
  - each cluster scanning its own images.

**Precedents:** Red Hat ACS's Central scans the images of every secured cluster from their registries, and delegates
a scan to a secured cluster only for a registry that Central can't reach. Harbor and Quay scan each digest once, at the
registry.
