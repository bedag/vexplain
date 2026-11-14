# Phase 3a measurements

Phase 3a ends with two measurements:

| What | It informs | State |
|---|---|---|
| Presence at scale: the snapshot of the `workloads` collector, and the time of a rebuild | Whether presence can stay one event per image, built whole after each change (design 5.9 of the [collector model](../design/2026-11-08-collector-model.md)) | Measured on envtest, below |
| The verdicts on the test set of phase 2a, through the phase 3a install | Whether the `sbom` split changed an answer | Measured on kind, in [the phase 2a measurements](2026-phase2a.md#run-again-in-phase-3a), beside the earlier runs: 14 cases as in phase 2b, and `keycloak` without an answer, since its evidence passes the cap of the evidence store |

Every figure on this page is about a synthetic load. None comes from a real platform.

## Presence at scale

| What | Result |
|---|---|
| Load | 200 Deployments in 20 namespaces, 2,000 pods of two containers, 201 images |
| Snapshot | 201 events, 645,057 B: 0.96% of the 64 MiB bound |
| Largest event | 280,253 B: the proxy's, which every pod runs |
| A rebuild of the whole presence | median 8.0 ms, slowest 12.3 ms, of 20 |

### Method

**Not on kind.** Design 5.9 says that scale is measured on kind. This measurement runs against envtest's API server instead, which runs no kubelet and no controllers:

- a kind node runs at most 110 pods, and 2,000 pods that run take many GB of memory for their containers;
- the snapshot's size and the time of a rebuild depend on the objects that the collector reads, and not on running containers: the pods, their ReplicaSets and Deployments, their namespaces and their nodes.

So the method differs from the design's, and the measure is the same.

**The load.**

- 20 namespaces, each with 10 Deployments, and each Deployment with one ReplicaSet and 10 pods: 200 workloads and 2,000 pods.
- Each pod has two containers: the image of its Deployment, and a proxy that every pod runs, as a service mesh injects one. That makes 201 images, and the proxy's event lists all 200 workloads with their 10 pods each.
- The pods run on two nodes, one `linux/amd64` and one `linux/arm64`. The test writes the status of each pod as a kubelet would, through the status subresource: running, with an image ID for each container, which names the digest of its image.
- The scope of the Watch selects the 20 namespaces, and the owner attribution copies no label.

**What it measures.**

- **The snapshot:** the size of its messages as the operator counts them against its bound of 64 MiB, in protocol buffers: `SnapshotStart`, an event for each image, and `SnapshotEnd`.
- **A rebuild:** after each change of a pod, a namespace, a node or a workload, the collector waits a second for more changes, builds the whole presence again from its informers' cache, and sends what differs. The test times 20 builds: reading the cache, finding each pod's workload, and encoding the presence of each image as JSON, the data of its event. It gives the fastest, the median and the slowest. The time leaves out what follows a build: making an event of each image whose presence changed, and sending it in protocol buffers.

**The run.** `TestPresenceAtScale` in `collectors/workloads/internal/presence`, which `make test` skips. The variable `MEASURE_PRESENCE_SCALE` turns it on:

```bash
make setup-envtest
export KUBEBUILDER_ASSETS="$(bin/setup-envtest use 1.37.0 --bin-dir "$PWD/bin" -p path)"
cd collectors/workloads
MEASURE_PRESENCE_SCALE=1 go test ./internal/presence/ -run TestPresenceAtScale -count=1 -v
```

**The machine.** A laptop with an Apple M4 Pro of 14 cores and 48 GiB of memory, on macOS 26.5, with Go 1.26.8 and envtest's API server 1.37.0. Nothing else ran during the measurement.

### Results

Three runs, one after the other:

| Run | Snapshot | Largest event | From the Watch to `SnapshotEnd` | Rebuild: fastest, median, slowest |
|---|---|---|---|---|
| 1 | 645,057 B | 280,253 B | 132 ms | 7.1 ms, 8.1 ms, 11.9 ms |
| 2 | 644,856 B | 280,252 B | 129 ms | 7.2 ms, 7.9 ms, 12.1 ms |
| 3 | 645,057 B | 280,253 B | 128 ms | 7.1 ms, 8.0 ms, 12.3 ms |

- **The snapshot is about 1% of its bound.** The bound would be reached at about a hundred times this load. Most of the snapshot is the pods: each event names the pods that run its image, at most 16 of each workload, each with its node, its platform and its containers. The proxy's event is 43% of the snapshot by itself, since it lists every workload.
- **A rebuild takes about 8 ms,** and comes at most once a second, after the changes settle. At this scale it costs the collector less than 1% of a core while the cluster changes all the time.
- The snapshot sizes of two runs differ by 201 B, one byte for each event: an event's time takes a byte more or less in protocol buffers.

### What it doesn't show

- **A real cluster's API server.** The informers' list at start, and the rate of events in a busy cluster, which decide how often a rebuild comes, but not what it costs.
- **The memory of the informers' cache,** which keeps what the collector reads of each pod, and the metadata of the other kinds.
- **The operator's side:** the spoke holds a snapshot whole until its end, and writes the presence of each image into its `ImageInventory`. Phase 1 measured the size of those objects ([2026-phase1.md](2026-phase1.md#size-of-imageinventory-objects)).
- **Other shapes of load.** A cluster with many more images per pod, or a DaemonSet on many nodes, makes other events. An event lists at most 16 pods of a workload, one of each platform first, so a workload's share of an event stays bounded however many pods it has.
