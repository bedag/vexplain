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

package exposure_test

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/go-logr/logr/testr"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlconfig "sigs.k8s.io/controller-runtime/pkg/config"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/evidence"
	"github.com/bedag/vexplain/internal/exposure"
	"github.com/bedag/vexplain/internal/metrics"
	"github.com/bedag/vexplain/internal/settings"
	sdkevidence "github.com/bedag/vexplain/sdk/evidence"
	"github.com/bedag/vexplain/sdk/subject"
)

// The view runs as the hub runs it: a controller of a manager, over the store's watch of an API server.

// writer returns a store that writes to the API server of the view's tests, and deletes every record when the test
// ends.
func writer(t *testing.T) evidence.Store {
	t.Helper()
	_, c := startAPI(t)
	t.Cleanup(func() {
		require.NoError(t, c.DeleteAllOf(context.Background(), &inventoryv1alpha1.Evidence{}))
	})
	return evidence.NewCRDStore(c, nil, func() string { return hub })
}

// startView starts a manager that runs a view of the API server's evidence, and stops it when the test ends. wrap,
// unless it is nil, changes the store that the view reads.
func startView(t *testing.T, wrap func(evidence.Store) evidence.Store) *exposure.View {
	t.Helper()
	cfg, c := startAPI(t)
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:  scheme,
		Metrics: metricsserver.Options{BindAddress: "0"},
		Logger:  testr.New(t),
		// Each test runs a manager of its own, whose controllers have the names of the others'.
		Controller: ctrlconfig.Controller{SkipNameValidation: ptr.To(true)},
	})
	require.NoError(t, err)
	// The view reads the records from the API server, as the hub's client does, and watches them through the cache.
	store := evidence.NewCRDStore(c, mgr.GetCache(), func() string { return hub })
	if wrap != nil {
		store = wrap(store)
	}
	view := exposure.NewView(store)
	require.NoError(t, view.SetupWithManager(mgr))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- mgr.Start(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			assert.NoError(t, err, "the manager stops once its context ends")
		case <-time.After(wait):
			assert.Fail(t, "the manager didn't stop")
		}
	})
	return view
}

// Presence reaches the hub as one record of each cluster that runs the image, which names that cluster's workloads. The
// view keeps those, and none of the rest of presence's data, such as its pods, which nothing on the hub reads.
func TestPresenceOfOneImageInTwoClustersGivesEachClustersSubjects(t *testing.T) {
	store := writer(t)
	view := startView(t, nil)
	digest := digestOf(1)
	putIn(t, store, workloadsCollector, clusterA, presenceEvent(t, digest, workload(clusterA, "web"),
		workload(clusterA, "api")))
	putIn(t, store, workloadsCollector, clusterB, presenceEvent(t, digest, workload(clusterB, "web")))

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		subjects, known := view.Workloads(digest, clusterA)
		assert.True(c, known)
		assert.Equal(c, []string{workload(clusterA, "api"), workload(clusterA, "web")}, subjects, "sorted")
		subjects, known = view.Workloads(digest, clusterB)
		assert.True(c, known)
		assert.Equal(c, []string{workload(clusterB, "web")}, subjects)
	}, wait, poll)
	require.Empty(t, view.Records(sdkevidence.TypePresence, subject.Image(digest)), "the view keeps no data of presence")
	subjects, known := view.Workloads(digest, "cluster-c")
	require.False(t, known, "a cluster whose presence of the image hasn't reached the hub")
	require.Empty(t, subjects)
	subjects, known = view.Workloads(digestOf(2), clusterA)
	require.False(t, known, "an image of which no cluster reports presence")
	require.Empty(t, subjects)
}

// A workload whose presence names no subject can't be joined to its exposure: the view doesn't name it, and the case
// counts it as Unknown.
func TestAWorkloadWithoutASubjectIsntNamed(t *testing.T) {
	store := writer(t)
	view := startView(t, nil)
	digest := digestOf(3)
	web := workload(clusterA, "web")
	putIn(t, store, workloadsCollector, clusterA, newEvent(t, sdkevidence.TypePresence, subject.Image(digest),
		map[string]any{"digestKind": sdkevidence.DigestKindRepoDigest, "workloads": []map[string]string{
			{"subject": web, "apiGroup": appsGroup, "kind": deployment, "namespace": teamA, "name": "web", "uid": "uid-1"},
			{"apiGroup": appsGroup, "kind": deployment, "namespace": teamA, "name": "old", "uid": "uid-2"},
		}}, workloadsCollector))

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		subjects, known := view.Workloads(digest, clusterA)
		assert.True(c, known)
		assert.Equal(c, []string{web}, subjects)
	}, wait, poll)
}

// The store writes a changed record in place, and the view's watch sees it, as it sees a delete. Records gives each
// record of a type about a subject with its producer, its event's source, time and coverage, and its data.
func TestAnUpdateInPlaceAndADeleteReachTheView(t *testing.T) {
	store := writer(t)
	view := startView(t, nil)
	web := workload(clusterA, "web")
	var data sdkevidence.Exposure
	require.NoError(t, json.Unmarshal(exposureEvent(t, web, []string{shop}).Data(), &data))
	putIn(t, store, networkReach, clusterA, newEvent(t, sdkevidence.TypeExposure, web, data, networkReach,
		sdkevidence.WithCoverage(80)))

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Equal(c, []string{shop}, view.EntryPoints())
	}, wait, poll)
	records := view.Records(sdkevidence.TypeExposure, web)
	require.Len(t, records, 1)
	require.Equal(t, networkReach, records[0].Source, "the Collector that delivered it")
	require.Equal(t, "/hub/collectors/"+networkReach, records[0].EventSource, "the source of its event")
	require.Equal(t, ptr.To(int32(80)), records[0].Coverage)
	require.False(t, records[0].Time.IsZero())
	require.Equal(t, []any{shop}, subjectsOf(t, records[0].Data), "the data, decoded")
	require.Empty(t, view.Records(sdkevidence.TypePresence, web), "no record of another type")

	putIn(t, store, networkReach, clusterA, exposureEvent(t, web, []string{shop, shopAddress}))
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Equal(c, []string{shopAddress, shop}, view.EntryPoints())
		if records := view.Records(sdkevidence.TypeExposure, web); assert.Len(c, records, 1) {
			assert.Equal(c, []any{shop, shopAddress}, subjectsOf(t, records[0].Data))
		}
	}, wait, poll)

	digest := digestOf(4)
	putIn(t, store, workloadsCollector, clusterA, presenceEvent(t, digest, web))
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		_, known := view.Workloads(digest, clusterA)
		assert.True(c, known)
	}, wait, poll)

	require.NoError(t, store.Delete(t.Context(), evidence.Key{Subject: web, Type: sdkevidence.TypeExposure,
		Source: networkReach, Cluster: clusterA}))
	require.NoError(t, store.Delete(t.Context(), evidence.Key{Subject: subject.Image(digest),
		Type: sdkevidence.TypePresence, Source: workloadsCollector, Cluster: clusterA}))
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Empty(c, view.EntryPoints())
		assert.Empty(c, view.Records(sdkevidence.TypeExposure, web))
		_, known := view.Workloads(digest, clusterA)
		assert.False(c, known)
	}, wait, poll)
}

// subjectsOf returns the subjects of the first entry point of exposure's data, as Records decodes it.
func subjectsOf(t *testing.T, data any) []any {
	t.Helper()
	doc, ok := data.(map[string]any)
	require.True(t, ok, "an object")
	external, ok := doc["external"].(map[string]any)
	require.True(t, ok, "external")
	entryPoints, ok := external["entryPoints"].([]any)
	require.True(t, ok, "external.entryPoints")
	require.NotEmpty(t, entryPoints)
	first, ok := entryPoints[0].(map[string]any)
	require.True(t, ok, "an entry point")
	subjects, ok := first["subjects"].([]any)
	require.True(t, ok, "its subjects")
	return subjects
}

// blocking is a store whose reads of one subject wait until release is closed.
type blocking struct {
	evidence.Store
	subject string
	release chan struct{}
}

func (b blocking) ListBySubject(ctx context.Context, about string) ([]evidence.Record, error) {
	if about == b.subject {
		select {
		case <-b.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return b.Store.ListBySubject(ctx, about)
}

// The cases wait for the view, so that a workload whose exposure the hub holds is never Unknown for want of reading
// it: the view is synced only once it has read every subject that the store held when it started.
func TestSyncedWaitsForTheFirstList(t *testing.T) {
	store := writer(t)
	digest := digestOf(5)
	web := workload(clusterA, "web")
	putIn(t, store, workloadsCollector, clusterA, presenceEvent(t, digest, web))
	putIn(t, store, networkReach, clusterA, exposureEvent(t, web, []string{shop}))
	release := make(chan struct{})
	view := startView(t, func(s evidence.Store) evidence.Store {
		return blocking{Store: s, subject: web, release: release}
	})

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		_, known := view.Workloads(digest, clusterA)
		assert.True(c, known, "the presence is read")
	}, wait, poll)
	require.Never(t, view.Synced, time.Second, poll, "synced while the exposure isn't read")
	require.Empty(t, view.EntryPoints())

	close(release)
	require.Eventually(t, view.Synced, wait, poll)
	require.Equal(t, []string{shop}, view.EntryPoints(), "everything that the store held is read once synced")
}

// A record that can't be decoded never holds up the cases that wait for the view: its subject counts as read, and has
// no records in the view, so that its workloads count as Unknown. The failure is counted, and a later write of the
// subject is read as usual.
func TestARecordThatCantBeReadDoesntHoldUpSynced(t *testing.T) {
	store := writer(t)
	_, direct := startAPI(t)
	digest := digestOf(6)
	web := workload(clusterA, "web")
	putIn(t, store, workloadsCollector, clusterA, presenceEvent(t, digest, web))
	putIn(t, store, networkReach, clusterA, exposureEvent(t, web, []string{shop}))
	corrupt(t, direct, web)
	failures := readFailures()
	view := startView(t, nil)

	require.Eventually(t, view.Synced, wait, poll, "the subject that can't be read counts as read")
	_, known := view.Workloads(digest, clusterA)
	require.True(t, known, "the other subjects are read")
	require.Empty(t, view.Records(sdkevidence.TypeExposure, web), "the subject has no records in the view")
	require.Empty(t, view.EntryPoints())
	require.Greater(t, readFailures(), failures, "the failed read is counted, under the cluster's name")

	putIn(t, store, networkReach, clusterA, exposureEvent(t, web, []string{shop, api}))
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Equal(c, []string{api, shop}, view.EntryPoints(), "the subject's next write is read")
		assert.Len(c, view.Records(sdkevidence.TypeExposure, web), 1)
	}, wait, poll)
}

// readFailures returns the count of the view's failed reads, under the cluster's name that the tests' API server
// gives: the default, since none sets an OperatorConfig.
func readFailures() float64 {
	return testutil.ToFloat64(metrics.ExposureViewReadFailuresTotal.WithLabelValues(settings.DefaultClusterName))
}

// Presence or exposure whose data is JSON, and isn't what its type says, is evidence that the hub can't use: the view
// leaves it out, which counts as missing, and counts it.
func TestEvidenceThatIsntWhatItsTypeSaysIsLeftOutAndCounted(t *testing.T) {
	store := writer(t)
	view := startView(t, nil)
	digest := digestOf(7)
	web := workload(clusterA, "web")
	failures := readFailures()
	putIn(t, store, workloadsCollector, clusterA, newEvent(t, sdkevidence.TypePresence, subject.Image(digest),
		map[string]any{"workloads": "x"}, workloadsCollector))
	putIn(t, store, networkReach, clusterA, newEvent(t, sdkevidence.TypeExposure, web,
		map[string]any{"external": "x"}, networkReach))

	require.Eventually(t, func() bool { return readFailures() >= failures+2 }, wait, poll, "each record is counted")
	_, known := view.Workloads(digest, clusterA)
	require.False(t, known, "the presence is missing")
	require.Empty(t, view.Records(sdkevidence.TypeExposure, web), "and so is the exposure")
	require.Empty(t, view.EntryPoints())
}

// A cluster's stream speaks for the workloads of that cluster only: a workload of another cluster that its presence
// names is left out, and so is its exposure of such a workload, and both are counted.
func TestPresenceNamesOnlyTheWorkloadsOfItsOwnCluster(t *testing.T) {
	store := writer(t)
	view := startView(t, nil)
	digest := digestOf(8)
	failures := readFailures()
	putIn(t, store, workloadsCollector, clusterA, presenceEvent(t, digest, workload(clusterA, "api"),
		workload(clusterB, "web")))

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		subjects, known := view.Workloads(digest, clusterA)
		assert.True(c, known)
		assert.Equal(c, []string{workload(clusterA, "api")}, subjects, "only cluster-a's own workload")
	}, wait, poll)
	subjects, known := view.Workloads(digest, clusterB)
	require.False(t, known, "cluster-a's presence says nothing of cluster-b")
	require.Empty(t, subjects)
	require.Greater(t, readFailures(), failures, "the workload of another cluster is counted")

	failures = readFailures()
	putIn(t, store, networkReach, clusterA, exposureEvent(t, workload(clusterB, "web"), []string{shop}))
	require.Eventually(t, func() bool { return readFailures() > failures }, wait, poll,
		"cluster-a's exposure of a workload of cluster-b is counted")
	require.Empty(t, view.Records(sdkevidence.TypeExposure, workload(clusterB, "web")), "and left out")
	require.Empty(t, view.EntryPoints())
}

// Presence changes with every pod that starts or stops, and the asker reads none of it, nor a namespace's labels: only a
// workload's exposure and the answers about hosts and addresses wake it.
func TestOnlyExposureAndAnswersWakeTheAsker(t *testing.T) {
	f := newFixture(t)
	changed := f.view.Changed()
	select {
	case <-changed: // The first list, which made the view synced.
	default:
	}

	putIn(t, f.store, workloadsCollector, clusterA, presenceEvent(t, digestOf(9), workload(clusterA, "web")))
	select {
	case <-changed:
		require.Fail(t, "presence woke the asker")
	default:
	}

	putIn(t, f.store, evidence.HubSource, clusterA, namespaceEvent(t, clusterA, "a"))
	select {
	case <-changed:
		require.Fail(t, "a namespace's labels woke the asker")
	default:
	}

	f.name(clusterA, "web", shop)
	select {
	case <-changed:
	default:
		require.Fail(t, "exposure didn't wake the asker")
	}

	require.NoError(t, f.store.Put(t.Context(), dmz, version, answerEvent(t, dmzType, shop, none, dmz, start)))
	select {
	case <-changed:
	default:
		require.Fail(t, "an answer didn't wake the asker")
	}
}

// corrupt replaces the data of the record about the subject with bytes that aren't gzip, as another writer could, so
// that the store can't decode the record.
func corrupt(t *testing.T, c client.Client, about string) {
	t.Helper()
	var list inventoryv1alpha1.EvidenceList
	require.NoError(t, c.List(t.Context(), &list))
	for i := range list.Items {
		if record := &list.Items[i]; record.Spec.Subject == about {
			record.Spec.Data = []byte("not gzip")
			require.NoError(t, c.Update(t.Context(), record))
			return
		}
	}
	require.Fail(t, "no record about the subject")
}

// An entry point that several workloads name, in one cluster or in several, is one entry point to ask about.
func TestTheEntryPointsAreTheUnionOfEveryExposuresSubjects(t *testing.T) {
	store := writer(t)
	view := startView(t, nil)
	putIn(t, store, networkReach, clusterA, exposureEvent(t, workload(clusterA, "web"), []string{shop, shopAddress}))
	putIn(t, store, networkReach, clusterA, exposureEvent(t, workload(clusterA, "api"), []string{api, shop}))
	putIn(t, store, networkReach, clusterB, exposureEvent(t, workload(clusterB, "web"), []string{shop, nodePort}))
	putIn(t, store, networkReach, clusterB, exposureEvent(t, workload(clusterB, "batch"), nil))

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Equal(c, []string{shopAddress, nodePort, api, shop}, view.EntryPoints(), "once each, sorted")
	}, wait, poll)

	// A source's answer about an entry point is a record of the view too, which names no entry point.
	at := time.Date(2026, 11, 22, 8, 0, 0, 0, time.UTC)
	require.NoError(t, store.Put(t.Context(), "dmz", version, answerEvent(t, dmzType, shop, none, "dmz", at)))
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		records := view.Records(dmzType, shop)
		if assert.Len(c, records, 1) {
			assert.Equal(c, exposure.Record{Source: "dmz", EventSource: "/hub/collectors/dmz", Time: at,
				Data: map[string]any{"publishedTo": none}}, records[0])
		}
	}, wait, poll)
	require.Equal(t, []string{shopAddress, nodePort, api, shop}, view.EntryPoints())
}

// An address that the exposure of two clusters names can't be tied to one cluster's network (design of remote spokes
// 5.10): the view names it, with the clusters, and not an address that one cluster names.
func TestAnAddressThatTwoClustersNameIsAmbiguous(t *testing.T) {
	store := writer(t)
	view := startView(t, nil)
	putIn(t, store, networkReach, clusterA, exposureEvent(t, workload(clusterA, "web"), []string{shopAddress, nodePort}))
	putIn(t, store, networkReach, clusterB, exposureEvent(t, workload(clusterB, "web"), []string{shopAddress}))

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Equal(c, map[string][]string{shopAddress: {clusterA, clusterB}}, view.Ambiguous(),
			"nodePort is named by one cluster only")
	}, wait, poll)
}

// An IP is ambiguous whatever its port (design of remote spokes 5.10): two clusters that name it with other ports, or
// one with a port and one without, make every subject of it ambiguous.
func TestAnAddressIsAmbiguousWhateverItsPort(t *testing.T) {
	store := writer(t)
	view := startView(t, nil)
	putIn(t, store, networkReach, clusterA, exposureEvent(t, workload(clusterA, "web"),
		[]string{"address/198.51.100.11:30443", "address/203.0.113.7"}))
	putIn(t, store, networkReach, clusterB, exposureEvent(t, workload(clusterB, "web"),
		[]string{"address/198.51.100.11:31080", "address/203.0.113.7:443"}))

	both := []string{clusterA, clusterB}
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Equal(c, map[string][]string{
			"address/198.51.100.11:30443": both, "address/198.51.100.11:31080": both,
			"address/203.0.113.7": both, "address/203.0.113.7:443": both,
		}, view.Ambiguous())
	}, wait, poll)
}

// What a cluster names can change: the view's answer follows it, and an address that one cluster stops naming isn't
// ambiguous any more.
func TestAmbiguityFollowsWhatTheClustersName(t *testing.T) {
	store := writer(t)
	view := startView(t, nil)
	putIn(t, store, networkReach, clusterA, exposureEvent(t, workload(clusterA, "web"), []string{shopAddress}))
	putIn(t, store, networkReach, clusterB, exposureEvent(t, workload(clusterB, "web"), []string{shopAddress}))
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Len(c, view.Ambiguous(), 1)
	}, wait, poll)

	putIn(t, store, networkReach, clusterB, exposureEvent(t, workload(clusterB, "web"), []string{shop}))
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Empty(c, view.Ambiguous())
	}, wait, poll)
}

// Host names are DNS names that mean the same everywhere, so two clusters naming one don't make it ambiguous. Both
// clusters also name an address, which shows that the view has read both exposures when the host is left out.
func TestAHostThatTwoClustersNameIsNot(t *testing.T) {
	store := writer(t)
	view := startView(t, nil)
	putIn(t, store, networkReach, clusterA, exposureEvent(t, workload(clusterA, "web"), []string{shop, shopAddress}))
	putIn(t, store, networkReach, clusterB, exposureEvent(t, workload(clusterB, "web"), []string{shop, shopAddress}))

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Equal(c, map[string][]string{shopAddress: {clusterA, clusterB}}, view.Ambiguous())
	}, wait, poll)
}

// The hub copies the labels of each spoke's namespaces into records of its own (decision 0063), and the view answers
// them per cluster: a namespace of the same name in two clusters has the labels of each. Only the hub's own copy under
// the namespace's cluster speaks for it: neither a collector's record of the type, nor the hub's copy under another
// cluster. Both are stored before the copies that the view answers with, so the view has read them when it answers.
func TestTheViewHoldsNamespaceLabelsPerCluster(t *testing.T) {
	store := writer(t)
	view := startView(t, nil)
	putIn(t, store, workloadsCollector, clusterA, namespaceEvent(t, clusterA, "forged"))
	putIn(t, store, evidence.HubSource, clusterA, namespaceEvent(t, clusterB, "forged"))
	putIn(t, store, evidence.HubSource, clusterA, namespaceEvent(t, clusterA, "a"))
	putIn(t, store, evidence.HubSource, clusterB, namespaceEvent(t, clusterB, "b"))

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		labels, known := view.NamespaceLabels(clusterA, teamA)
		assert.True(c, known)
		assert.Equal(c, map[string]string{teamLabel: "a"}, labels)
		labels, known = view.NamespaceLabels(clusterB, teamA)
		assert.True(c, known)
		assert.Equal(c, map[string]string{teamLabel: "b"}, labels)
	}, wait, poll)
	labels, known := view.NamespaceLabels(clusterA, "team-b")
	require.False(t, known, "a namespace that the hub holds no copy of")
	require.Nil(t, labels)
}

// namespaceEvent returns the hub's copy of the labels of the namespace team-a of the cluster, whose team is the value of
// its one label.
func namespaceEvent(t *testing.T, cluster, team string) cloudevents.Event {
	t.Helper()
	about, err := subject.Namespace(cluster, teamA)
	require.NoError(t, err)
	return newEvent(t, sdkevidence.TypeNamespace, about, sdkevidence.NamespaceLabels{
		Labels: []sdkevidence.KeyValue{{Key: teamLabel, Value: team}}}, evidence.HubSource)
}

// The cases ask for the ambiguous addresses once per workload and source, so the view computes them again only when a
// workload's exposure changed: the same map comes back until then.
func TestAmbiguousAddressesAreComputedAgainOnlyAfterAChange(t *testing.T) {
	store := writer(t)
	view := startView(t, nil)
	putIn(t, store, networkReach, clusterA, exposureEvent(t, workload(clusterA, "web"), []string{shopAddress}))
	putIn(t, store, networkReach, clusterB, exposureEvent(t, workload(clusterB, "web"), []string{shopAddress}))
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Len(c, view.Ambiguous(), 1)
	}, wait, poll)

	require.Equal(t, reflect.ValueOf(view.Ambiguous()).Pointer(), reflect.ValueOf(view.Ambiguous()).Pointer())

	old := view.Ambiguous()
	putIn(t, store, networkReach, clusterB, exposureEvent(t, workload(clusterB, "web"), []string{shop}))
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.NotEqual(c, reflect.ValueOf(old).Pointer(), reflect.ValueOf(view.Ambiguous()).Pointer())
	}, wait, poll)
	require.Len(t, old, 1, "a caller's map stays as it was")
}
