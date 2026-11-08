/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package spoke_test

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/collector/certs"
	"github.com/bedag/vexplain/internal/collectorclient"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/spoke"
	"github.com/bedag/vexplain/sdk/collector"
	"github.com/bedag/vexplain/sdk/evidence"
	"github.com/bedag/vexplain/sdk/subject"
	"github.com/bedag/vexplain/sdk/workloads"
)

func TestASnapshotCreatesThePresenceEntriesWithTheirPodsPlatforms(t *testing.T) {
	c := newCluster()
	s := startSpoke(t, c)
	digest := newDigest(t)

	s.presence.Snapshot("workloads", []cloudevents.Event{presenceEvent(t, digest,
		running("team-b", apiName, linuxARM64), running("team-a", webName, linuxAMD64, linuxARM64))})

	entry := present(t, c, digest)
	require.Equal(t, c.id, entry.ClusterID)
	require.Equal(t, []string{linuxAMD64, linuxARM64}, entry.Platforms, "the platforms of its pods, each once")
	require.Equal(t, []string{repository}, entry.Repositories)
	require.Equal(t, ptr.To(int32(2)), entry.NamespaceCount)
	require.Equal(t, ptr.To(int32(2)), entry.WorkloadCount)
	require.Equal(t, []inventoryv1alpha1.WorkloadReference{
		{APIGroup: ptr.To("apps"), Kind: deployment, Namespace: "team-a", Name: webName},
		{APIGroup: ptr.To("apps"), Kind: deployment, Namespace: "team-b", Name: apiName},
	}, entry.Workloads, "the workloads, sorted")
	_, direct := startAPI(t)
	var obj inventoryv1alpha1.ImageInventory
	require.NoError(t, direct.Get(t.Context(), client.ObjectKey{Name: inventory.NameForDigest(digest)}, &obj))
	require.Equal(t, ptr.To(inventoryv1alpha1.DigestKindRepoDigest), obj.Status.DigestKind)
}

// apiName is a workload and a container of the tests, and regularContainer is the kind of a container that is neither
// an init container nor a sidecar.
const (
	apiName          = "api"
	regularContainer = "Container"
)

// referenceEvent returns the event of a presence collector about an image that has no digest, whose repositories hold
// its reference.
func referenceEvent(t *testing.T, digest, reference string, ws ...evidence.PresenceWorkload) cloudevents.Event {
	t.Helper()
	e, err := evidence.New(evidence.TypePresence, subject.Image(digest), evidence.Presence{
		DigestKind: evidence.DigestKindReference, Repositories: []string{reference}, Workloads: ws,
	}, evidence.WithSource("/clusters/cluster-a/collectors/workloads"))
	require.NoError(t, err)
	return e
}

// An image that has no digest is an entry of its own kind, keyed by the hash of its reference, which no registry
// serves.
func TestAnImageWithoutADigestIsAnEntryOfKindReference(t *testing.T) {
	c := newCluster()
	s := startSpoke(t, c)
	reference := "registry.example/team-a/app:1.0"
	digest := workloads.ReferenceDigest(reference)

	s.presence.Snapshot("workloads", []cloudevents.Event{referenceEvent(t, digest, reference,
		running("team-a", webName, linuxAMD64))})

	entry := present(t, c, digest)
	require.Equal(t, []string{reference}, entry.Repositories)
	_, direct := startAPI(t)
	var obj inventoryv1alpha1.ImageInventory
	require.NoError(t, direct.Get(t.Context(), client.ObjectKey{Name: inventory.NameForDigest(digest)}, &obj))
	require.Equal(t, ptr.To(inventoryv1alpha1.DigestKindReference), obj.Status.DigestKind)
}

// Running lists the containers that run each image of a workload, from the pods of the workload, each once and sorted,
// and the kind of each image's digest.
func TestRunningListsTheContainersOfEachImageAndItsKind(t *testing.T) {
	s := startSpoke(t, newCluster())
	app, mesh, reference := newDigest(t), newDigest(t), workloads.ReferenceDigest("registry.example/team-a/app:2.0")
	web := running("team-a", webName, linuxAMD64, linuxARM64)
	web.Pods[0].Containers = []evidence.PresenceContainer{{Name: webName, Kind: regularContainer}, {Name: apiName, Kind: regularContainer}}
	web.Pods[1].Containers = []evidence.PresenceContainer{{Name: webName, Kind: regularContainer}}
	proxy := running("team-a", webName, linuxAMD64)
	proxy.Pods[0].Containers = []evidence.PresenceContainer{{Name: "proxy", Kind: "Sidecar"}}
	pending := running("team-a", webName, linuxAMD64)
	pending.Pods[0].Containers = []evidence.PresenceContainer{{Name: "next", Kind: regularContainer}}
	s.presence.Snapshot("workloads", []cloudevents.Event{
		presenceEvent(t, app, web), presenceEvent(t, mesh, proxy),
		referenceEvent(t, reference, "registry.example/team-a/app:2.0", pending),
	})

	got, ok := s.presence.Running("team-a", spoke.ReportName(web))

	require.True(t, ok)
	byDigest := map[string]spoke.RunningImage{}
	for _, image := range got.Images {
		byDigest[image.Digest] = image
	}
	require.Equal(t, spoke.RunningImage{Digest: app, Platforms: []string{linuxAMD64, linuxARM64}, Kind: "RepoDigest",
		Containers: []workloads.ContainerRef{{Name: apiName, Kind: regularContainer}, {Name: webName, Kind: regularContainer}}},
		byDigest[app])
	require.Equal(t, []workloads.ContainerRef{{Name: "proxy", Kind: "Sidecar"}}, byDigest[mesh].Containers)
	require.Equal(t, spoke.RunningImage{Digest: reference, Platforms: []string{linuxAMD64}, Kind: "Reference",
		Containers: []workloads.ContainerRef{{Name: "next", Kind: regularContainer}}}, byDigest[reference])
}

// A presence entry lists the first 100 workloads, sorted, and counts them all, as in phase 2a.
func TestAnEntryListsTheFirstHundredWorkloadsAndCountsThemAll(t *testing.T) {
	c := newCluster()
	s := startSpoke(t, c)
	digest := newDigest(t)
	many := make([]evidence.PresenceWorkload, 0, 120)
	for i := range 120 {
		many = append(many, running("team-a", "web-"+string(rune('a'+i/26))+string(rune('a'+i%26)), linuxAMD64))
	}

	s.presence.Snapshot("workloads", []cloudevents.Event{presenceEvent(t, digest, many...)})

	entry := present(t, c, digest)
	require.Equal(t, ptr.To(int32(120)), entry.WorkloadCount)
	require.Len(t, entry.Workloads, 100)
	require.Equal(t, "web-aa", entry.Workloads[0].Name)
}

func TestASecondSnapshotWithoutAnImageForgetsIt(t *testing.T) {
	c := newCluster()
	s := startSpoke(t, c)
	kept, gone := newDigest(t), newDigest(t)
	web := running("team-a", webName, linuxAMD64)
	s.presence.Snapshot("workloads", []cloudevents.Event{presenceEvent(t, kept, web), presenceEvent(t, gone, web)})
	present(t, c, kept)
	present(t, c, gone)

	s.presence.Snapshot("workloads", []cloudevents.Event{presenceEvent(t, kept, web)})

	absent(t, c, gone)
	stays(t, c, kept, true)
}

// Presence is kept in memory, and a new process of the operator starts without it. Its first complete snapshot says
// what runs in the cluster: the entries of this cluster that it lacks went stale while the operator was down, and are
// forgotten. Another cluster's entries are that cluster's own.
func TestAfterARestartTheFirstCompleteSnapshotForgetsThisClustersEntriesThatItLacks(t *testing.T) {
	c, other := newCluster(), newCluster()
	stale, kept, theirs := newDigest(t), newDigest(t), newDigest(t)
	web := running("team-a", webName, linuxAMD64)
	before := startSpoke(t, c)
	before.presence.Snapshot("workloads", []cloudevents.Event{presenceEvent(t, stale, web), presenceEvent(t, kept, web)})
	present(t, c, stale)
	present(t, c, kept)
	observe(t, other, theirs)
	before.stop()

	after := startSpoke(t, c)
	stays(t, c, stale, true)
	after.presence.Snapshot("workloads", []cloudevents.Event{presenceEvent(t, kept, web)})

	absent(t, c, stale)
	stays(t, c, kept, true)
	stays(t, other, theirs, true)
}

// The store creates an object before it writes the first entry in it, so another cluster's object holds no entry for
// a moment, and Forget deletes an object that holds none. Presence forgets the entries of its own cluster only, and
// leaves such an object alone.
func TestPresenceLeavesAloneAnObjectWithoutAnEntryOfItsCluster(t *testing.T) {
	c := newCluster()
	s := startSpoke(t, c)
	s.presence.Snapshot("workloads", nil)
	digest := newDigest(t)
	_, direct := startAPI(t)

	require.NoError(t, direct.Create(t.Context(), &inventoryv1alpha1.ImageInventory{
		ObjectMeta: metav1.ObjectMeta{Name: inventory.NameForDigest(digest)},
		Spec:       inventoryv1alpha1.ImageInventorySpec{Digest: digest},
	}))

	require.Never(t, func() bool {
		err := direct.Get(t.Context(), client.ObjectKey{Name: inventory.NameForDigest(digest)},
			&inventoryv1alpha1.ImageInventory{})
		return apierrors.IsNotFound(err)
	}, quiet, tick, "the object stays, for the cluster that writes its entry")
}

// The controller follows the ImageInventory objects: an object that someone deleted, or whose entry someone changed,
// gets back the entry that presence says.
func TestAnEntryDeletedOrChangedByHandIsWrittenAgain(t *testing.T) {
	c := newCluster()
	s := startSpoke(t, c)
	digest := newDigest(t)
	s.presence.Snapshot("workloads", []cloudevents.Event{presenceEvent(t, digest, running("team-a", webName, linuxAMD64))})
	present(t, c, digest)
	_, direct := startAPI(t)
	key := client.ObjectKey{Name: inventory.NameForDigest(digest)}
	var first inventoryv1alpha1.ImageInventory
	require.NoError(t, direct.Get(t.Context(), key, &first))

	require.NoError(t, direct.Delete(t.Context(), &first))
	require.Eventually(t, func() bool {
		var again inventoryv1alpha1.ImageInventory
		return direct.Get(t.Context(), key, &again) == nil && again.UID != first.UID && len(again.Status.Clusters) == 1
	}, wait, tick, "the object comes back, with the entry")

	var changed inventoryv1alpha1.ImageInventory
	require.NoError(t, direct.Get(t.Context(), key, &changed))
	changed.Status.Clusters[0].Platforms = []string{"linux/s390x"}
	require.NoError(t, direct.Status().Update(t.Context(), &changed))
	require.Eventually(t, func() bool {
		entry := entryOf(t, c, digest)
		return entry != nil && slices.Equal(entry.Platforms, []string{linuxAMD64})
	}, wait, tick, "the entry is what presence says again")
}

// A renamed cluster keeps its ID. Its new name changes the context of the streams, which open again, and the entries
// take the new name with the snapshot that follows: none stays under the former one.
func TestARenamedClustersEntriesTakeItsNewNameAtTheNextSnapshot(t *testing.T) {
	var mu sync.Mutex
	c := newCluster()
	current := c
	s := startSpokeAs(t, func() cluster {
		mu.Lock()
		defer mu.Unlock()
		return current
	})
	digest := newDigest(t)
	events := []cloudevents.Event{presenceEvent(t, digest, running("team-a", webName, linuxAMD64))}
	s.presence.Snapshot("workloads", events)
	present(t, c, digest)

	renamed := cluster{name: c.name + "-renamed", id: c.id}
	mu.Lock()
	current = renamed
	mu.Unlock()
	s.presence.Snapshot("workloads", events)

	present(t, renamed, digest)
	absent(t, c, digest)
}

// After the snapshot, each change of a collector comes as it happens: an upsert observes, and a tombstone forgets.
func TestAnUpsertObservesAndATombstoneForgets(t *testing.T) {
	c := newCluster()
	s := startSpoke(t, c)
	digest := newDigest(t)
	s.presence.Snapshot("workloads", nil)

	s.presence.Upsert("workloads", presenceEvent(t, digest, running("team-a", webName, linuxAMD64)))
	require.Equal(t, []string{linuxAMD64}, present(t, c, digest).Platforms)

	s.presence.Upsert("workloads", presenceEvent(t, digest, running("team-a", webName, linuxAMD64, linuxARM64)))
	require.Eventually(t, func() bool {
		entry := entryOf(t, c, digest)
		return entry != nil && slices.Equal(entry.Platforms, []string{linuxAMD64, linuxARM64})
	}, wait, tick, "the entry follows the change")

	s.presence.Remove("workloads", evidence.TypePresence, presenceEvent(t, digest).Subject())
	absent(t, c, digest)
}

// Two collectors can report presence, such as two copies of the workloads collector. A Collector that goes takes what
// it delivered with it, and an image that the other still names stays.
func TestForgetKeepsTheImagesThatAnotherPresenceCollectorNames(t *testing.T) {
	c := newCluster()
	s := startSpoke(t, c)
	shared, onlyFirst := newDigest(t), newDigest(t)
	web := running("team-a", webName, linuxAMD64)
	s.presence.Snapshot("workloads", []cloudevents.Event{presenceEvent(t, shared, web), presenceEvent(t, onlyFirst, web)})
	s.presence.Snapshot("extra", []cloudevents.Event{presenceEvent(t, shared, web)})
	present(t, c, shared)
	present(t, c, onlyFirst)

	s.presence.Forget("workloads")

	absent(t, c, onlyFirst)
	stays(t, c, shared, true)

	s.presence.Forget("extra")
	absent(t, c, shared)
}

// Presence knows what a collector says runs only once the collector's first snapshot since the start has arrived. A
// wait for it wakes when the first snapshot of a collector arrives, and a collector that is forgotten needs a snapshot
// of its own again.
func TestPresenceTellsWhichCollectorsSnapshotsArrivedSinceTheStart(t *testing.T) {
	s := startSpoke(t, newCluster())
	digest := newDigest(t)
	both := []string{"workloads", "extra"}
	woken := func(arrival <-chan struct{}) bool {
		select {
		case <-arrival:
			return true
		default:
			return false
		}
	}

	known, arrival := s.presence.HasSnapshotsOf(both)
	require.False(t, known)
	require.False(t, woken(arrival))
	s.presence.Snapshot("workloads", []cloudevents.Event{presenceEvent(t, digest, running("team-a", webName, linuxAMD64))})
	require.True(t, woken(arrival), "the first snapshot of a collector wakes a wait")

	known, arrival = s.presence.HasSnapshotsOf(both)
	require.False(t, known, "the other collector's snapshot hasn't arrived")
	s.presence.Snapshot("workloads", nil)
	require.False(t, woken(arrival), "a later snapshot of a collector wakes nothing")
	s.presence.Snapshot("extra", nil)
	require.True(t, woken(arrival), "an empty snapshot is a snapshot")
	known, _ = s.presence.HasSnapshotsOf(both)
	require.True(t, known)

	s.presence.Forget("extra")
	known, _ = s.presence.HasSnapshotsOf(both)
	require.False(t, known, "a forgotten collector needs a snapshot of its own again")
	known, _ = s.presence.HasSnapshotsOf(nil)
	require.True(t, known, "without collectors, nothing is missing")
}

// The executor and the reports read what runs from presence: the workloads of an image, as the presence collectors
// report them, each once, and the images that any of them names.
func TestWorkloadsAndImagesKeepTheLatestPresenceOfEveryCollector(t *testing.T) {
	s := startSpoke(t, newCluster())
	a, b := newDigest(t), newDigest(t)
	web, api := running("team-a", webName, linuxAMD64), running("team-a", apiName, linuxARM64)
	s.presence.Snapshot("workloads", []cloudevents.Event{presenceEvent(t, a, web), presenceEvent(t, b, api)})
	s.presence.Snapshot("extra", []cloudevents.Event{presenceEvent(t, a, api, web)})

	require.Equal(t, slices.Sorted(slices.Values([]string{a, b})), s.presence.Images())
	require.Equal(t, []evidence.PresenceWorkload{api, web}, s.presence.Workloads(a))

	s.presence.Upsert("extra", presenceEvent(t, a, api))
	s.presence.Forget("workloads")
	require.Equal(t, []string{a}, s.presence.Images())
	require.Equal(t, []evidence.PresenceWorkload{api}, s.presence.Workloads(a))
	require.Empty(t, s.presence.Workloads(b))
}

// A stream that breaks, or never ends its snapshot, hands nothing of it over: presence keeps what it had, and so the
// first snapshot after a start, which never ends, forgets no entry that went stale before the start. Presence learns
// nothing of what runs until a snapshot ends.
func TestAStreamThatNeverEndsItsSnapshotForgetsNothing(t *testing.T) {
	c := newCluster()
	stale := newDigest(t)
	observe(t, c, stale)
	s := startSpoke(t, c)
	inSnapshot := newDigest(t)
	unending := &unendingSnapshot{events: []cloudevents.Event{presenceEvent(t, inSnapshot,
		running("team-a", webName, linuxAMD64))}}
	streamFrom(t, s, newCollector(t, evidence.TypePresence), unending)

	require.Eventually(t, unending.sent.Load, wait, tick, "the collector sends the start of its snapshot")
	stays(t, c, stale, true)
	stays(t, c, inSnapshot, false)
}

// unendingSnapshot is a presence collector whose snapshot never ends: its Watch sends SnapshotStart and its events,
// and then waits for its end.
type unendingSnapshot struct {
	events []cloudevents.Event
	sent   atomic.Bool
}

func (u *unendingSnapshot) Info() collector.Info {
	return collector.Info{Name: "unending", Version: "0.1.0"}
}

func (u *unendingSnapshot) Capabilities() collector.Capabilities {
	schema, _ := evidence.Schema(evidence.TypePresence)
	return collector.Capabilities{
		Roles:    []collector.Role{collector.RoleSpoke},
		Produces: []collector.EvidenceType{{Type: evidence.TypePresence, Scope: collector.ScopeSpoke, Schema: schema}},
		Watches:  true,
	}
}

func (u *unendingSnapshot) Watch(ctx context.Context, _ collector.WatchRequest, sink collector.Sink) error {
	if err := sink.SnapshotStart(); err != nil {
		return err
	}
	for _, e := range u.events {
		if err := sink.Event(e); err != nil {
			return err
		}
	}
	u.sent.Store(true)
	<-ctx.Done()
	return ctx.Err()
}

// streamFrom serves c with the SDK's server under the name of its Collector, over mutual TLS with certificates from an
// authority of the operator's, and runs the streams of the spoke s with its Router as the sink of the spoke role, as
// the operator does, until the test ends.
func streamFrom(t *testing.T, s *spokeOf, name string, c collector.Collector) {
	t.Helper()
	_, direct := startAPI(t)
	authority := certs.NewAuthority(direct, direct, operatorNamespace, time.Now)
	require.NoError(t, authority.EnsureCA(t.Context()))
	_, err := authority.EnsureServer(t.Context(), name)
	require.NoError(t, err)
	secret := &corev1.Secret{}
	require.NoError(t, direct.Get(t.Context(), client.ObjectKey{Namespace: operatorNamespace, Name: certs.SecretName(name)},
		secret))
	t.Cleanup(func() { assert.NoError(t, client.IgnoreNotFound(direct.Delete(context.Background(), secret))) })
	dir := t.TempDir()
	for _, file := range []string{corev1.TLSCertKey, corev1.TLSPrivateKeyKey, "ca.crt"} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, file), secret.Data[file], 0o600))
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	health, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := listener.Addr().String()
	serving, stopServing := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() {
		served <- collector.Serve(serving, c, collector.Options{TLSDir: dir, GRPCListener: listener, HealthListener: health})
	}()

	pool := collectorclient.NewPool(authority.ClientTLS, operatorNamespace)
	pool.Dialer = func(ctx context.Context, _ string) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, "tcp", address)
	}
	reader := s.manager.GetClient()
	streams := collectorclient.NewStreams(pool, reader,
		map[configv1alpha1.CollectorRole]collectorclient.Sink{
			configv1alpha1.CollectorRoleSpoke: spoke.NewRouter(reader, s.presence, s.exposure),
		}, collectorclient.ClusterContext(reader, operatorNamespace))
	ctx, stopStreams := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- streams.Start(ctx) }()
	t.Cleanup(func() {
		stopStreams()
		assert.NoError(t, <-done)
		pool.Forget(name)
		stopServing()
		assert.NoError(t, <-served)
	})
}
