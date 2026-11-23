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
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/go-logr/logr"
	"github.com/go-logr/logr/funcr"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	internalevidence "github.com/bedag/vexplain/internal/evidence"
	"github.com/bedag/vexplain/internal/metrics"
	"github.com/bedag/vexplain/internal/spoke"
	"github.com/bedag/vexplain/sdk/evidence"
	"github.com/bedag/vexplain/sdk/subject"
)

// The tests run a StoreSink over the evidence store of the API server of the tests, for a cluster and a Collector of
// their own, which declares presence with the scope Hub and exposure with the scope Spoke. They hand it what the
// streams of the collector would, and read the records from the API server.

// testStore is the evidence store of a test: the CRD store over the API server, which counts the sink's Puts, Deletes
// and prunes, fails or stalls a Put as put says, and fails as many of the next Deletes as failDeletes says.
type testStore struct {
	internalevidence.Store
	// put, when not nil, runs before each Put, and fails it with its error.
	put                 func(ctx context.Context, e cloudevents.Event) error
	puts, deletes       atomic.Int32
	prunes, failDeletes atomic.Int32
}

func (s *testStore) Delete(ctx context.Context, k internalevidence.Key) error {
	s.deletes.Add(1)
	if s.failDeletes.Add(-1) >= 0 {
		return errors.New("the API server can't be reached")
	}
	return s.Store.Delete(ctx, k)
}

func (s *testStore) Put(ctx context.Context, source, version string, e cloudevents.Event,
	opts ...internalevidence.PutOption) error {
	s.puts.Add(1)
	if s.put != nil {
		if err := s.put(ctx, e); err != nil {
			return err
		}
	}
	return s.Store.Put(ctx, source, version, e, opts...)
}

func (s *testStore) DeleteStreamed(ctx context.Context, cluster, source, eventType string,
	keep func(internalevidence.Key) bool) error {
	defer s.prunes.Add(1)
	return s.Store.DeleteStreamed(ctx, cluster, source, eventType, keep)
}

// logged keeps the lines that a logger writes, so that a test reads them.
type logged struct {
	mu    sync.Mutex
	lines []string
}

func (l *logged) logger() logr.Logger {
	return funcr.New(func(prefix, args string) {
		l.mu.Lock()
		defer l.mu.Unlock()
		l.lines = append(l.lines, prefix+" "+args)
	}, funcr.Options{})
}

func (l *logged) text() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

// sinkOf is a StoreSink under test, with its store, the cluster that it stores for, the Collector whose stream it
// takes, and what its worker logged.
type sinkOf struct {
	sink      *spoke.StoreSink
	store     *testStore
	cluster   string
	collector string
	logged    *logged
}

// startSink starts a StoreSink for a new cluster, over the evidence store of the API server with opts, whose Puts fail
// or stall as put says, when it isn't nil. Its Collector declares presence with the scope Hub and exposure with the
// scope Spoke. The sink stops when the test ends.
func startSink(t *testing.T, put func(context.Context, cloudevents.Event) error,
	opts ...internalevidence.Option) *sinkOf {
	t.Helper()
	return startSinkReading(t, func(r client.Reader) client.Reader { return r }, put, opts...)
}

// failingReads is a reader of the Collectors whose first reads fail, as a cache's do before it has synced. It counts
// the reads.
type failingReads struct {
	client.Reader
	// failures is how many reads are still to fail.
	failures, reads atomic.Int32
}

func (r *failingReads) Get(ctx context.Context, key client.ObjectKey, obj client.Object,
	opts ...client.GetOption) error {
	r.reads.Add(1)
	if r.failures.Add(-1) >= 0 {
		return errors.New("the cache isn't synced yet")
	}
	return r.Reader.Get(ctx, key, obj, opts...)
}

// startSinkReading is startSink whose sink reads the Collectors through what reader makes of the API server's client.
func startSinkReading(t *testing.T, reader func(client.Reader) client.Reader,
	put func(context.Context, cloudevents.Event) error, opts ...internalevidence.Option) *sinkOf {
	t.Helper()
	_, direct := startAPI(t)
	cluster := newCluster().name
	s := &sinkOf{
		store: &testStore{
			Store: internalevidence.NewCRDStore(direct, nil, func() string { return cluster }, opts...),
			put:   put,
		},
		cluster: cluster,
		collector: newCollectorOf(t,
			configv1alpha1.ProducedType{Type: evidence.TypePresence, Scope: configv1alpha1.EvidenceScopeHub},
			configv1alpha1.ProducedType{Type: evidence.TypeExposure, Scope: configv1alpha1.EvidenceScopeSpoke}),
		logged: &logged{},
	}
	s.sink = spoke.NewStoreSink(s.store, reader(direct), func(context.Context) (string, error) { return cluster, nil })
	ctx, cancel := context.WithCancel(logf.IntoContext(context.Background(), s.logged.logger()))
	done := make(chan error, 1)
	go func() { done <- s.sink.Start(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			assert.NoError(t, err, "Start returns nil once its context ends")
		case <-time.After(wait):
			assert.Fail(t, "the sink didn't stop")
		}
	})
	return s
}

// presenceKey returns the key of the sink's record of the presence of the image of digest.
func (s *sinkOf) presenceKey(digest string) internalevidence.Key {
	return internalevidence.Key{Subject: subject.Image(digest), Type: evidence.TypePresence, Source: s.collector,
		Cluster: s.cluster}
}

// record returns the record of the key, or nil when there is none.
func (s *sinkOf) record(t *testing.T, k internalevidence.Key) *internalevidence.Record {
	t.Helper()
	record, err := s.store.Get(context.Background(), k)
	require.NoError(t, err)
	return record
}

// stored waits until the record of the key holds the data of e, and returns it.
func (s *sinkOf) stored(t *testing.T, k internalevidence.Key, e cloudevents.Event) *internalevidence.Record {
	t.Helper()
	var record *internalevidence.Record
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		got, err := s.store.Get(context.Background(), k)
		if assert.NoError(c, err) && assert.NotNil(c, got) {
			assert.JSONEq(c, string(e.Data()), string(got.Event.Data()))
			record = got
		}
	}, wait, tick, "the record of %s holds the event's data", k.Subject)
	return record
}

// gone waits until there is no record of the key.
func (s *sinkOf) gone(t *testing.T, k internalevidence.Key) {
	t.Helper()
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		got, err := s.store.Get(context.Background(), k)
		assert.NoError(c, err)
		assert.Nil(c, got)
	}, wait, tick, "the record of %s is deleted", k.Subject)
}

// pruned waits until the sink has deleted what its collector doesn't hold n times. A round of the sink's writes ends
// with it, so what the round took is written by then.
func (s *sinkOf) pruned(t *testing.T, n int32) {
	t.Helper()
	require.Eventually(t, func() bool { return s.store.prunes.Load() >= n }, wait, tick, "the sink pruned %d times", n)
}

// writes returns how many writes of each op the evidence store counted in the sink's cluster.
func (s *sinkOf) writes() map[string]float64 {
	counts := map[string]float64{}
	for _, op := range []string{"create", "update", "delete"} {
		counts[op] = testutil.ToFloat64(metrics.EvidenceWritesTotal.WithLabelValues(s.cluster, op))
	}
	return counts
}

// putOthers stores records that a prune and Forget of the sink must leave, about e's subject, and returns their keys:
// another cluster's record of the collector, its record of another type in the cluster, another collector's record in
// the cluster, and the evidence that an operation of the collector returned, without a cluster.
func (s *sinkOf) putOthers(t *testing.T, e cloudevents.Event) []internalevidence.Key {
	t.Helper()
	ctx := context.Background()
	otherCluster, otherCollector := newCluster().name, "other-"+s.collector
	exposure := exposureEvent(t)
	require.NoError(t, s.store.Store.Put(ctx, s.collector, collectorVersion, e, internalevidence.InCluster(otherCluster)))
	require.NoError(t, s.store.Store.Put(ctx, s.collector, collectorVersion, exposure, internalevidence.InCluster(s.cluster)))
	require.NoError(t, s.store.Store.Put(ctx, otherCollector, collectorVersion, e, internalevidence.InCluster(s.cluster)))
	require.NoError(t, s.store.Store.Put(ctx, s.collector, collectorVersion, e))
	return []internalevidence.Key{
		{Subject: e.Subject(), Type: e.Type(), Source: s.collector, Cluster: otherCluster},
		{Subject: exposure.Subject(), Type: exposure.Type(), Source: s.collector, Cluster: s.cluster},
		{Subject: e.Subject(), Type: e.Type(), Source: otherCollector, Cluster: s.cluster},
		{Subject: e.Subject(), Type: e.Type(), Source: s.collector},
	}
}

// A snapshot stores each of its events of a type that the collector declares with the scope Hub, at the collector's
// version, keyed and labelled with the cluster, so that the hub reads it.
func TestASnapshotOfAHubScopedTypeIsStoredWithItsCluster(t *testing.T) {
	s := startSink(t, nil)
	digest := newDigest(t)
	e := presenceEvent(t, digest, running(teamA, "web", linuxAMD64))

	s.sink.Snapshot(s.collector, []cloudevents.Event{e})

	record := s.stored(t, s.presenceKey(digest), e)
	require.Equal(t, collectorVersion, record.CollectorVersion)
	require.Equal(t, e.ID(), record.Event.ID())
	_, direct := startAPI(t)
	var labelled inventoryv1alpha1.EvidenceList
	require.NoError(t, direct.List(t.Context(), &labelled, client.MatchingLabels{internalevidence.ClusterLabel: s.cluster}))
	require.Len(t, labelled.Items, 1)
	require.Equal(t, ptr.To(s.cluster), labelled.Items[0].Spec.Cluster)
}

// A snapshot that comes while the sink can't read its collector's scopes, as before the cache has synced after a start,
// waits with the changes after it, and the sink reads the Collector again after the queue's pause, until it can. Then
// the snapshot's records of a type of the scope Hub arrive with their cluster, a change after it too, and the records
// that it doesn't hold are deleted, as for any snapshot. Its type of the scope Spoke stays in the cluster.
func TestASnapshotWaitsUntilItsCollectorsScopesAreRead(t *testing.T) {
	// The snapshot's read fails, and so does the sink's first read after it, so that the change comes while the
	// snapshot waits.
	reader := &failingReads{}
	reader.failures.Store(2)
	s := startSinkReading(t, func(r client.Reader) client.Reader {
		reader.Reader = r
		return reader
	}, nil)
	stale, digest, later := newDigest(t), newDigest(t), newDigest(t)
	require.NoError(t, s.store.Store.Put(t.Context(), s.collector, collectorVersion,
		presenceEvent(t, stale, running(teamA, "old", linuxAMD64)), internalevidence.InCluster(s.cluster)))
	e := presenceEvent(t, digest, running(teamA, "web", linuxAMD64))
	laterEvent := presenceEvent(t, later, running(teamA, "api", linuxAMD64))
	exposure := exposureEvent(t)

	s.sink.Snapshot(s.collector, []cloudevents.Event{e, exposure})
	s.sink.Upsert(s.collector, laterEvent)

	record := s.stored(t, s.presenceKey(digest), e)
	require.Equal(t, int32(3), reader.reads.Load(), "the sink read the Collector until it could")
	require.Equal(t, s.cluster, record.Cluster)
	require.Equal(t, collectorVersion, record.CollectorVersion)
	s.stored(t, s.presenceKey(later), laterEvent)
	s.gone(t, s.presenceKey(stale))
	s.pruned(t, 1)
	require.Nil(t, s.record(t, internalevidence.Key{Subject: exposure.Subject(), Type: exposure.Type(),
		Source: s.collector, Cluster: s.cluster}))
}

// A type that the collector declares with the scope Spoke stays in the cluster: neither a snapshot nor a change of it is
// stored.
func TestASpokeScopedTypeIsNotStored(t *testing.T) {
	s := startSink(t, nil)
	digest := newDigest(t)
	exposure := exposureEvent(t)
	presence := presenceEvent(t, digest, running(teamA, "web", linuxAMD64))
	s.sink.Snapshot(s.collector, []cloudevents.Event{exposure, presence})
	s.stored(t, s.presenceKey(digest), presence)
	s.pruned(t, 1)

	s.sink.Upsert(s.collector, exposure)
	s.sink.Snapshot(s.collector, []cloudevents.Event{exposure, presence})
	s.pruned(t, 2)

	require.Nil(t, s.record(t, internalevidence.Key{Subject: exposure.Subject(), Type: exposure.Type(),
		Source: s.collector, Cluster: s.cluster}))
}

// A snapshot deletes the collector's records of the type in the cluster that it no longer holds, such as an image that
// stopped running while the stream was down. Every other record stays: another cluster's, another type's, another
// collector's, and the evidence that an operation returned.
func TestASnapshotDeletesTheRecordsThatItNoLongerHolds(t *testing.T) {
	s := startSink(t, nil)
	kept, stopped := newDigest(t), newDigest(t)
	keptEvent := presenceEvent(t, kept, running(teamA, "web", linuxAMD64))
	stoppedEvent := presenceEvent(t, stopped, running(teamA, "api", linuxAMD64))
	s.sink.Snapshot(s.collector, []cloudevents.Event{keptEvent, stoppedEvent})
	s.stored(t, s.presenceKey(stopped), stoppedEvent)
	s.pruned(t, 1)
	others := s.putOthers(t, stoppedEvent)

	s.sink.Snapshot(s.collector, []cloudevents.Event{keptEvent})

	s.gone(t, s.presenceKey(stopped))
	s.pruned(t, 2)
	s.stored(t, s.presenceKey(kept), keptEvent)
	for _, k := range others {
		require.NotNil(t, s.record(t, k), "%+v stays", k)
	}
}

// A collector that declares a type with the scope Spoke after it declared it with the scope Hub, as after a downgrade,
// keeps none of its records current any more: its next snapshot deletes them.
func TestATypeThatIsHubScopedNoMoreHasItsRecordsDeleted(t *testing.T) {
	s := startSink(t, nil)
	digest := newDigest(t)
	e := presenceEvent(t, digest, running(teamA, "web", linuxAMD64))
	s.sink.Snapshot(s.collector, []cloudevents.Event{e})
	s.stored(t, s.presenceKey(digest), e)
	_, direct := startAPI(t)
	var downgraded configv1alpha1.Collector
	require.NoError(t, direct.Get(t.Context(), client.ObjectKey{Name: s.collector}, &downgraded))
	downgraded.Status.Capabilities.Produces[0].Scope = configv1alpha1.EvidenceScopeSpoke
	require.NoError(t, direct.Status().Update(t.Context(), &downgraded))

	s.sink.Snapshot(s.collector, []cloudevents.Event{e})

	s.gone(t, s.presenceKey(digest))
	s.sink.Upsert(s.collector, e)
	require.Never(t, func() bool {
		record, err := s.store.Get(context.Background(), s.presenceKey(digest))
		return err != nil || record != nil
	}, quiet, tick, "a change of it isn't stored either")
}

// After the snapshot, a change stores its event in place of its record's, and a tombstone deletes its record: each
// changes the record of its subject, and no other.
func TestAnUpsertAndATombstoneChangeOneRecord(t *testing.T) {
	s := startSink(t, nil)
	changed, removed := newDigest(t), newDigest(t)
	removedEvent := presenceEvent(t, removed, running(teamA, "api", linuxAMD64))
	s.sink.Snapshot(s.collector, []cloudevents.Event{
		presenceEvent(t, changed, running(teamA, "web", linuxAMD64)), removedEvent,
	})
	s.stored(t, s.presenceKey(removed), removedEvent)

	moved := presenceEvent(t, changed, running(teamA, "web", linuxAMD64, linuxARM64))
	s.sink.Upsert(s.collector, moved)

	s.stored(t, s.presenceKey(changed), moved)
	require.Equal(t, removedEvent.ID(), s.record(t, s.presenceKey(removed)).Event.ID(), "the other record stays")

	s.sink.Remove(s.collector, evidence.TypePresence, subject.Image(removed))

	s.gone(t, s.presenceKey(removed))
	require.Equal(t, moved.ID(), s.record(t, s.presenceKey(changed)).Event.ID(), "the other record stays")
}

// Forget deletes the collector's records in the cluster, as when its Collector goes. Another cluster's records stay,
// and so do the records of other types and collectors, and the evidence that an operation returned.
func TestForgetDeletesOnlyThisClustersRecordsOfTheCollector(t *testing.T) {
	s := startSink(t, nil)
	digest := newDigest(t)
	e := presenceEvent(t, digest, running(teamA, "web", linuxAMD64))
	s.sink.Snapshot(s.collector, []cloudevents.Event{e})
	s.stored(t, s.presenceKey(digest), e)
	s.pruned(t, 1)
	others := s.putOthers(t, e)

	s.sink.Forget(s.collector)

	s.gone(t, s.presenceKey(digest))
	s.pruned(t, 2)
	for _, k := range others {
		require.NotNil(t, s.record(t, k), "%+v stays", k)
	}
}

// Presence that names no workload says that its image runs nowhere, as a tombstone does: a change of it deletes its
// record, and a snapshot stores none of it.
func TestAPresenceWithoutWorkloadsDeletesItsRecord(t *testing.T) {
	s := startSink(t, nil)
	runs, stops, idle := newDigest(t), newDigest(t), newDigest(t)
	runsEvent := presenceEvent(t, runs, running(teamA, "web", linuxAMD64))
	stopsEvent := presenceEvent(t, stops, running(teamA, "api", linuxAMD64))
	s.sink.Snapshot(s.collector, []cloudevents.Event{runsEvent, stopsEvent, presenceEvent(t, idle)})
	s.stored(t, s.presenceKey(stops), stopsEvent)
	s.pruned(t, 1)
	require.Nil(t, s.record(t, s.presenceKey(idle)), "a snapshot stores no presence without workloads")

	s.sink.Upsert(s.collector, presenceEvent(t, stops))

	s.gone(t, s.presenceKey(stops))
	s.stored(t, s.presenceKey(runs), runsEvent)
}

// Review Focus 3: a stream that opens again, as after a restart of the spoke, sends every event again in its snapshot.
// Each is equal to its record but for its ID and its time, so the store writes nothing, and the prune deletes nothing.
func TestASnapshotThatRepeatsEveryEventWritesNothing(t *testing.T) {
	s := startSink(t, nil)
	web, api := newDigest(t), newDigest(t)
	snapshot := func() []cloudevents.Event {
		return []cloudevents.Event{
			presenceEvent(t, web, running(teamA, "web", linuxAMD64)),
			presenceEvent(t, api, running(teamA, "api", linuxARM64)),
		}
	}
	first := snapshot()
	s.sink.Snapshot(s.collector, first)
	s.stored(t, s.presenceKey(web), first[0])
	s.stored(t, s.presenceKey(api), first[1])
	s.pruned(t, 1)
	before := s.writes()

	again := snapshot()
	require.NotEqual(t, first[0].ID(), again[0].ID(), "new events")
	s.sink.Snapshot(s.collector, again)
	s.pruned(t, 2)

	require.Equal(t, before, s.writes(), "nothing is written")
	require.Equal(t, first[0].ID(), s.record(t, s.presenceKey(web)).Event.ID(), "the record keeps its event")
}

// A snapshot deletes what it doesn't hold after it stores what it holds, and keeps the record of a change that came
// after it, though the change was written first: the store's deletion of what a snapshot doesn't hold checks nothing,
// so it would delete a fresh record.
func TestAPruneKeepsTheRecordOfAChangeAfterItsSnapshot(t *testing.T) {
	release := make(chan struct{})
	var stalled atomic.Bool
	s := startSink(t, func(ctx context.Context, _ cloudevents.Event) error {
		if !stalled.CompareAndSwap(false, true) {
			return nil
		}
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	gone, kept, later := newDigest(t), newDigest(t), newDigest(t)
	s.sink.Snapshot(s.collector, []cloudevents.Event{presenceEvent(t, gone, running(teamA, "old", linuxAMD64))})
	require.Eventually(t, func() bool { return s.store.puts.Load() == 1 }, wait, tick, "the store stalls the first write")
	keptEvent := presenceEvent(t, kept, running(teamA, "web", linuxAMD64))
	laterEvent := presenceEvent(t, later, running(teamA, "api", linuxAMD64))
	s.sink.Snapshot(s.collector, []cloudevents.Event{keptEvent})
	s.sink.Upsert(s.collector, laterEvent)

	close(release)

	s.pruned(t, 2)
	s.stored(t, s.presenceKey(kept), keptEvent)
	s.stored(t, s.presenceKey(later), laterEvent)
	s.gone(t, s.presenceKey(gone))
}

// A write that fails, as while the API server can't be reached, is tried again after a pause, and the record arrives.
func TestAFailedWriteIsRetried(t *testing.T) {
	var failed atomic.Bool
	s := startSink(t, func(context.Context, cloudevents.Event) error {
		if failed.CompareAndSwap(false, true) {
			return errors.New("the API server can't be reached")
		}
		return nil
	})
	digest := newDigest(t)
	e := presenceEvent(t, digest, running(teamA, "web", linuxAMD64))

	s.sink.Snapshot(s.collector, []cloudevents.Event{e})

	s.stored(t, s.presenceKey(digest), e)
	require.True(t, failed.Load(), "the first write failed")
	s.pruned(t, 1)
}

// An event over the store's cap would be refused at every attempt: it is dropped, counted, and logged without what it
// holds. The rest of the snapshot is stored, and the records that it doesn't hold are deleted all the same.
func TestAWriteThatIsTooLargeIsCountedAndDropped(t *testing.T) {
	const marker = "known-only-to-the-data"
	fits := presenceEvent(t, newDigest(t), running(teamA, "web", linuxAMD64))
	size, err := internalevidence.CompressedSize(fits.Data())
	require.NoError(t, err)
	many := make([]evidence.PresenceWorkload, 0, 32)
	for i := range cap(many) {
		many = append(many, running(teamA, fmt.Sprintf("%s-%d", marker, i), linuxAMD64))
	}
	large := presenceEvent(t, newDigest(t), many...)
	s := startSink(t, nil, internalevidence.WithMaxCompressedBytes(func() int64 { return int64(size) }))
	refused := func() float64 {
		return testutil.ToFloat64(metrics.EvidenceStreamedRefusedTotal.WithLabelValues(s.cluster, s.collector,
			evidence.TypePresence, "TooLarge"))
	}
	before := refused()

	s.sink.Snapshot(s.collector, []cloudevents.Event{large, fits})

	s.stored(t, internalevidence.Key{Subject: fits.Subject(), Type: fits.Type(), Source: s.collector, Cluster: s.cluster},
		fits)
	s.pruned(t, 1)
	require.Nil(t, s.record(t, internalevidence.Key{Subject: large.Subject(), Type: large.Type(), Source: s.collector,
		Cluster: s.cluster}))
	require.Equal(t, before+1, refused())
	require.Contains(t, s.logged.text(), "TooLarge")
	require.NotContains(t, s.logged.text(), marker)
}

// A record whose newer event the store refuses would read on the hub as what the collector says now, which it isn't:
// the refusal deletes the record, as a write that is tried again when it fails, and is counted once. The snapshot's
// prune keeps no record of the subject, and the next event of it that fits stores it again.
func TestARefusedEventDeletesTheRecordOfItsKey(t *testing.T) {
	digest := newDigest(t)
	fits := presenceEvent(t, digest, running(teamA, "web", linuxAMD64))
	size, err := internalevidence.CompressedSize(fits.Data())
	require.NoError(t, err)
	many := make([]evidence.PresenceWorkload, 0, 32)
	for i := range cap(many) {
		many = append(many, running(teamA, fmt.Sprintf("web-%d", i), linuxAMD64))
	}
	large := presenceEvent(t, digest, many...)
	s := startSink(t, nil, internalevidence.WithMaxCompressedBytes(func() int64 { return int64(size) }))
	refused := func() float64 {
		return testutil.ToFloat64(metrics.EvidenceStreamedRefusedTotal.WithLabelValues(s.cluster, s.collector,
			evidence.TypePresence, "TooLarge"))
	}
	s.sink.Snapshot(s.collector, []cloudevents.Event{fits})
	s.stored(t, s.presenceKey(digest), fits)
	s.pruned(t, 1)
	before := refused()
	s.store.failDeletes.Store(1)

	s.sink.Snapshot(s.collector, []cloudevents.Event{large})

	s.gone(t, s.presenceKey(digest))
	s.pruned(t, 2)
	require.Equal(t, before+1, refused(), "the refusal is counted once")
	require.Equal(t, int32(2), s.store.deletes.Load(), "the deletion that failed was tried again")

	again := presenceEvent(t, digest, running(teamA, "web", linuxAMD64))
	s.sink.Upsert(s.collector, again)

	s.stored(t, s.presenceKey(digest), again)
}

// Presence or exposure whose data doesn't follow the core's schema, which the spoke's own consumers drop, would read on
// the hub, which decodes it without the schema, as what the collector says now: the sink refuses it as the store refuses
// what it can't hold, so that the record of its subject is deleted, and missing for the hub's rules, and counts it as
// Invalid.
func TestPresenceOrExposureOffItsSchemaDeletesTheRecordOfItsKey(t *testing.T) {
	s := startSink(t, nil)
	reach := newCollectorOf(t, configv1alpha1.ProducedType{Type: evidence.TypeExposure, Scope: configv1alpha1.EvidenceScopeHub})
	digest := newDigest(t)
	presence, exposure := presenceEvent(t, digest, running(teamA, "web", linuxAMD64)), exposureEvent(t)
	exposureKey := internalevidence.Key{Subject: exposure.Subject(), Type: exposure.Type(), Source: reach, Cluster: s.cluster}
	s.sink.Snapshot(s.collector, []cloudevents.Event{presence})
	s.sink.Snapshot(reach, []cloudevents.Event{exposure})
	s.stored(t, s.presenceKey(digest), presence)
	s.stored(t, exposureKey, exposure)
	refused := func(collector, eventType string) float64 {
		return testutil.ToFloat64(metrics.EvidenceStreamedRefusedTotal.WithLabelValues(s.cluster, collector, eventType,
			"Invalid"))
	}
	before := refused(s.collector, evidence.TypePresence) + refused(reach, evidence.TypeExposure)

	withoutSubject := running(teamA, "web", linuxAMD64)
	withoutSubject.Subject = ""
	s.sink.Upsert(s.collector, presenceEvent(t, digest, withoutSubject))
	unknownReach, err := evidence.New(evidence.TypeExposure, exposure.Subject(), evidence.Exposure{InternalReach: "Galaxy"},
		evidence.WithSource(exposure.Source()))
	require.NoError(t, err)
	s.sink.Upsert(reach, unknownReach)

	s.gone(t, s.presenceKey(digest))
	s.gone(t, exposureKey)
	require.Equal(t, before+2, refused(s.collector, evidence.TypePresence)+refused(reach, evidence.TypeExposure))
}

// The sink never holds up a stream: with the store stalled, each change records what it wants and returns at once, and
// the newest change of a record replaces one that waits. Once the store goes on, the record holds the newest change.
func TestTheSinkNeverBlocksTheStream(t *testing.T) {
	release := make(chan struct{})
	s := startSink(t, func(ctx context.Context, _ cloudevents.Event) error {
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	digest := newDigest(t)
	s.sink.Snapshot(s.collector, []cloudevents.Event{presenceEvent(t, digest, running(teamA, "web", linuxAMD64))})
	require.Eventually(t, func() bool { return s.store.puts.Load() == 1 }, wait, tick, "the store stalls the first write")
	changes := []cloudevents.Event{
		presenceEvent(t, digest, running(teamA, "web", linuxAMD64, linuxARM64)),
		presenceEvent(t, digest, running(teamA, "web", linuxARM64)),
	}

	returned := make(chan struct{})
	go func() {
		defer close(returned)
		for _, e := range changes {
			s.sink.Upsert(s.collector, e)
		}
	}()
	select {
	case <-returned:
	case <-time.After(quiet):
		require.Fail(t, "Upsert waits for the store")
	}

	close(release)
	s.stored(t, s.presenceKey(digest), changes[1])
	require.Equal(t, int32(2), s.store.puts.Load(), "the newest change replaced the one before, which was never written")
}
