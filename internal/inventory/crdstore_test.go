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

package inventory_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/metrics"
	"github.com/bedag/vexplain/internal/workloads"
)

const (
	// digest is the digest of the object under test. No test creates an object for otherDigest.
	digest      = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	otherDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	clusterA = "cluster-a"
	clusterB = "cluster-b"
	idA      = "id-a"
	idB      = "id-b"

	repository = "artifacts.example/lib/app"

	// The workloads the tests use.
	namespace       = "ns1"
	otherNamespace  = "ns2"
	groupApps       = "apps"
	kindDeployment  = "Deployment"
	kindStatefulSet = "StatefulSet"
	nameWeb         = "web"

	// clusterLabel is the label that every inventory metric carries.
	clusterLabel = "cluster"
)

// --- fixtures ---

// newClient returns a fake client that keeps the status of an ImageInventory apart from the rest,
// as the API server does for a CRD with a status subresource. The funcs intercept calls, so a test
// can make a call fail or let another writer act in the middle of one.
func newClient(t *testing.T, funcs interceptor.Funcs) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, inventoryv1alpha1.AddToScheme(scheme))
	return fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&inventoryv1alpha1.ImageInventory{}).
		WithInterceptorFuncs(funcs).
		Build()
}

// newStore returns a store on a fresh fake client, and the client, for the checks that look behind
// the store.
func newStore(t *testing.T) (inventory.Store, client.Client) {
	t.Helper()
	return newStoreWith(t, interceptor.Funcs{})
}

func newStoreWith(t *testing.T, funcs interceptor.Funcs) (inventory.Store, client.Client) {
	t.Helper()
	c := newClient(t, funcs)
	// A store over a fake client never watches, so it needs no cache.
	return inventory.NewCRDStore(c, nil), c
}

func deployment(name string) workloads.WorkloadRef {
	return workloads.WorkloadRef{APIGroup: groupApps, Kind: kindDeployment, Namespace: namespace, Name: name}
}

func deploymentRef(name string) inventoryv1alpha1.WorkloadReference {
	return inventoryv1alpha1.WorkloadReference{
		APIGroup: ptr.To(groupApps), Kind: kindDeployment, Namespace: namespace, Name: name,
	}
}

// obs is the notation of the task: obs(cluster, id, namespaces, n) observes a cluster with the
// given ID, in which the workloads w1 to wn (Deployments in ns1) run the image from one repository.
func obs(cluster, id string, namespaces int32, n int) inventory.Observation {
	o := inventory.Observation{
		Cluster:        cluster,
		ClusterID:      id,
		DigestKind:     inventoryv1alpha1.DigestKindRepoDigest,
		Repositories:   []string{repository},
		NamespaceCount: namespaces,
	}
	for i := 1; i <= n; i++ {
		o.Workloads = append(o.Workloads, deployment("w"+strconv.Itoa(i)))
	}
	return o
}

// presence is the entry that obs(cluster, id, namespaces, n) should leave, without its time.
func presence(cluster, id string, namespaces, workloadCount int32, refs []inventoryv1alpha1.WorkloadReference,
	repositories ...string) inventoryv1alpha1.ClusterPresence {
	return inventoryv1alpha1.ClusterPresence{
		Cluster:        cluster,
		ClusterID:      id,
		NamespaceCount: ptr.To(namespaces),
		WorkloadCount:  ptr.To(workloadCount),
		Workloads:      refs,
		Repositories:   repositories,
	}
}

// firstN returns the references to the workloads w1 to wn.
func firstN(n int) []inventoryv1alpha1.WorkloadReference {
	var refs []inventoryv1alpha1.WorkloadReference
	for i := 1; i <= n; i++ {
		refs = append(refs, deploymentRef("w"+strconv.Itoa(i)))
	}
	return refs
}

// withoutTimes checks that every entry has a first-seen time, and returns the entries without it,
// so that a test can compare everything else they hold.
func withoutTimes(t *testing.T, entries []inventoryv1alpha1.ClusterPresence) []inventoryv1alpha1.ClusterPresence {
	t.Helper()
	out := slices.Clone(entries)
	for i := range out {
		require.NotNil(t, out[i].FirstSeenTime, "entry %q has no first-seen time", out[i].Cluster)
		require.False(t, out[i].FirstSeenTime.IsZero(), "entry %q has a zero first-seen time", out[i].Cluster)
		out[i].FirstSeenTime = nil
	}
	return out
}

func clusterNames(entries []inventoryv1alpha1.ClusterPresence) []string {
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Cluster)
	}
	return names
}

// stored reads the object behind the store, straight from the client.
func stored(t *testing.T, c client.Client) *inventoryv1alpha1.ImageInventory {
	t.Helper()
	obj := &inventoryv1alpha1.ImageInventory{}
	require.NoError(t, c.Get(t.Context(), client.ObjectKey{Name: inventory.NameForDigest(digest)}, obj))
	return obj
}

// mustGet reads the object of digest through the store, and fails the test when there is none.
func mustGet(t *testing.T, store inventory.Store) *inventoryv1alpha1.ImageInventory {
	t.Helper()
	got, err := store.Get(t.Context(), digest)
	require.NoError(t, err)
	require.NotNil(t, got, "the object exists")
	return got
}

// requireAbsent fails the test when the store holds an object for digest.
func requireAbsent(t *testing.T, store inventory.Store) {
	t.Helper()
	got, err := store.Get(t.Context(), digest)
	require.NoError(t, err)
	require.Nil(t, got, "the object is gone")
}

// backdate sets the first-seen time of a cluster's entry behind the store's back, so that a test
// can tell a kept time from a new one. It returns the time it set.
func backdate(t *testing.T, c client.Client, cluster string) metav1.Time {
	t.Helper()
	stamp := metav1.NewTime(time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC))
	obj := stored(t, c)
	for i := range obj.Status.Clusters {
		if obj.Status.Clusters[i].Cluster == cluster {
			obj.Status.Clusters[i].FirstSeenTime = &stamp
		}
	}
	require.NoError(t, c.Status().Update(t.Context(), obj))
	return stamp
}

// requireSameTime compares instants. A time that went through JSON comes back in the local zone,
// so require.Equal would not treat it as equal to the one that was written.
func requireSameTime(t *testing.T, want metav1.Time, got *metav1.Time) {
	t.Helper()
	require.NotNil(t, got)
	require.True(t, want.Equal(got), "want %s, got %s", want, got)
}

// addEntry is another writer: it adds an entry for a cluster to the stored object, without the
// store, and so changes the object's resourceVersion.
func addEntry(t *testing.T, c client.Client, cluster, id string) {
	t.Helper()
	obj := stored(t, c)
	obj.Status.DigestKind = ptr.To(inventoryv1alpha1.DigestKindRepoDigest)
	obj.Status.Clusters = append(obj.Status.Clusters, inventoryv1alpha1.ClusterPresence{
		Cluster:        cluster,
		ClusterID:      id,
		NamespaceCount: ptr.To(int32(1)),
		WorkloadCount:  ptr.To(int32(1)),
		FirstSeenTime:  ptr.To(metav1.Now()),
	})
	require.NoError(t, c.Status().Update(t.Context(), obj))
}

// --- metrics ---

// writeCounts is what the inventory metrics of one cluster have counted: the writes by op, and
// the number of samples in the histogram of object sizes.
type writeCounts struct {
	Create, Update, Delete float64
	Sizes                  uint64
}

func counter(t *testing.T, cluster, op string) float64 {
	t.Helper()
	var m dto.Metric
	require.NoError(t, metrics.InventoryWritesTotal.WithLabelValues(cluster, op).Write(&m))
	return m.GetCounter().GetValue()
}

// sizes reads the histogram of object sizes through a dto.Metric, because testutil.ToFloat64
// panics on histograms.
func sizes(t *testing.T, cluster string) (count uint64, sum float64) {
	t.Helper()
	observer, err := metrics.InventoryObjectBytes.GetMetricWithLabelValues(cluster)
	require.NoError(t, err)
	metric, ok := observer.(prometheus.Metric)
	require.True(t, ok, "a histogram is a metric")
	var m dto.Metric
	require.NoError(t, metric.Write(&m))
	return m.GetHistogram().GetSampleCount(), m.GetHistogram().GetSampleSum()
}

func readCounts(t *testing.T, cluster string) writeCounts {
	t.Helper()
	count, _ := sizes(t, cluster)
	return writeCounts{
		Create: counter(t, cluster, "create"),
		Update: counter(t, cluster, "update"),
		Delete: counter(t, cluster, "delete"),
		Sizes:  count,
	}
}

// counted runs call and returns what it added to the metrics of the cluster. The collectors are
// global, so a test can only look at the change around a call.
func counted(t *testing.T, cluster string, call func()) writeCounts {
	t.Helper()
	before := readCounts(t, cluster)
	call()
	after := readCounts(t, cluster)
	return writeCounts{
		Create: after.Create - before.Create,
		Update: after.Update - before.Update,
		Delete: after.Delete - before.Delete,
		Sizes:  after.Sizes - before.Sizes,
	}
}

// --- names ---

func TestNamesRoundTrip(t *testing.T) {
	name := inventory.NameForDigest(digest)
	require.Equal(t, "sha256-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", name)

	got, ok := inventory.DigestForName(name)
	require.True(t, ok)
	require.Equal(t, digest, got)

	_, ok = inventory.DigestForName("foo")
	require.False(t, ok)
}

func TestDigestForNameRejectsOtherNames(t *testing.T) {
	hex := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	for name, input := range map[string]string{
		"an empty name":                "",
		"a digest, which is no name":   "sha256:" + hex,
		"too short":                    "sha256-" + hex[1:],
		"too long":                     "sha256-" + hex + "a",
		"uppercase hex digits":         "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"a non-hex character":          "sha256-" + hex[1:] + "g",
		"another algorithm":            "sha512-" + hex,
		"text before the algorithm":    "x" + "sha256-" + hex,
		"text after the digest":        "sha256-" + hex + "x",
		"a name that has a dot":        "sha256-" + hex[1:] + ".",
		"the algorithm without digest": "sha256-",
	} {
		t.Run(name, func(t *testing.T) {
			got, ok := inventory.DigestForName(input)
			require.False(t, ok)
			require.Empty(t, got)
		})
	}
}

// --- Get ---

func TestGetReturnsNilWhenAbsent(t *testing.T) {
	store, _ := newStore(t)

	got, err := store.Get(t.Context(), otherDigest)

	require.NoError(t, err)
	require.Nil(t, got)
}

// --- Observe ---

func TestObserveCreates(t *testing.T) {
	store, _ := newStore(t)

	counts := counted(t, clusterA, func() {
		require.NoError(t, store.Observe(t.Context(), digest, obs(clusterA, idA, 2, 3)))
	})

	got := mustGet(t, store)
	require.Equal(t, inventory.NameForDigest(digest), got.Name)
	require.Equal(t, digest, got.Spec.Digest)
	require.Equal(t, ptr.To(inventoryv1alpha1.DigestKindRepoDigest), got.Status.DigestKind)
	require.Equal(t, []inventoryv1alpha1.ClusterPresence{
		presence(clusterA, idA, 2, 3, firstN(3), repository),
	}, withoutTimes(t, got.Status.Clusters))
	// The object is created, and then its status is written: two writes, and two sizes.
	require.Equal(t, writeCounts{Create: 1, Update: 1, Sizes: 2}, counts)
}

func TestObserveSkipsUnchanged(t *testing.T) {
	store, c := newStore(t)
	first := obs(clusterA, idA, 2, 3)
	first.Repositories = []string{"artifacts.example/lib/a", "artifacts.example/lib/b"}
	require.NoError(t, store.Observe(t.Context(), digest, first))
	version := stored(t, c).ResourceVersion

	// The same observation, with the workloads and the repositories in another order.
	again := obs(clusterA, idA, 2, 3)
	slices.Reverse(again.Workloads)
	again.Repositories = []string{"artifacts.example/lib/b", "artifacts.example/lib/a"}
	counts := counted(t, clusterA, func() {
		require.NoError(t, store.Observe(t.Context(), digest, again))
	})

	require.Equal(t, writeCounts{}, counts)
	require.Equal(t, version, stored(t, c).ResourceVersion, "nothing was written")
}

func TestObserveWritesWhenSomethingChanges(t *testing.T) {
	for name, change := range map[string]func(*inventory.Observation){
		"the namespace count": func(o *inventory.Observation) { o.NamespaceCount = 3 },
		"a workload is replaced": func(o *inventory.Observation) {
			o.Workloads[2] = deployment("w9")
		},
		"a workload is added": func(o *inventory.Observation) {
			o.Workloads = append(o.Workloads, deployment("w4"))
		},
		"a repository is added": func(o *inventory.Observation) {
			o.Repositories = append(o.Repositories, "artifacts.example/lib/other")
		},
		"the cluster ID": func(o *inventory.Observation) { o.ClusterID = "id-z" },
		"the digest kind": func(o *inventory.Observation) {
			o.DigestKind = inventoryv1alpha1.DigestKindImageID
		},
	} {
		t.Run(name, func(t *testing.T) {
			store, _ := newStore(t)
			require.NoError(t, store.Observe(t.Context(), digest, obs(clusterA, idA, 2, 3)))
			changed := obs(clusterA, idA, 2, 3)
			change(&changed)

			counts := counted(t, clusterA, func() {
				require.NoError(t, store.Observe(t.Context(), digest, changed))
			})
			require.Equal(t, writeCounts{Update: 1, Sizes: 1}, counts)

			// What was written is the new state: the same observation is now unchanged.
			counts = counted(t, clusterA, func() {
				require.NoError(t, store.Observe(t.Context(), digest, changed))
			})
			require.Equal(t, writeCounts{}, counts)
		})
	}
}

func TestObserveKeepsFirstSeen(t *testing.T) {
	store, c := newStore(t)
	require.NoError(t, store.Observe(t.Context(), digest, obs(clusterA, idA, 2, 3)))
	stamp := backdate(t, c, clusterA)

	counts := counted(t, clusterA, func() {
		require.NoError(t, store.Observe(t.Context(), digest, obs(clusterA, idA, 2, 4)))
	})

	require.Equal(t, writeCounts{Update: 1, Sizes: 1}, counts)
	entries := stored(t, c).Status.Clusters
	require.Len(t, entries, 1)
	require.Equal(t, ptr.To(int32(4)), entries[0].WorkloadCount, "the entry was rewritten")
	requireSameTime(t, stamp, entries[0].FirstSeenTime)
}

func TestObserveCapsWorkloads(t *testing.T) {
	store, c := newStore(t)
	// w001 to w150, so that the order of the names is the order of the numbers. They arrive in
	// reverse, so only a sort puts the first 100 in front.
	o := obs(clusterA, idA, 2, 0)
	for i := 150; i >= 1; i-- {
		o.Workloads = append(o.Workloads, deployment(fmt.Sprintf("w%03d", i)))
	}
	require.NoError(t, store.Observe(t.Context(), digest, o))

	entries := stored(t, c).Status.Clusters
	require.Len(t, entries, 1)
	require.Equal(t, ptr.To(int32(150)), entries[0].WorkloadCount, "the count is the whole")
	require.Len(t, entries[0].Workloads, 100)
	require.Equal(t, deploymentRef("w001"), entries[0].Workloads[0])
	require.Equal(t, deploymentRef("w100"), entries[0].Workloads[99])

	// A change behind the first 100 leaves the result as it was, so it writes nothing.
	for i := 101; i <= 150; i++ {
		o.Workloads[150-i] = deployment(fmt.Sprintf("z%03d", i))
	}
	counts := counted(t, clusterA, func() {
		require.NoError(t, store.Observe(t.Context(), digest, o))
	})
	require.Equal(t, writeCounts{}, counts)
}

func TestObserveCapsRepositories(t *testing.T) {
	store, c := newStore(t)
	o := obs(clusterA, idA, 2, 1)
	o.Repositories = nil
	for i := 40; i >= 1; i-- {
		o.Repositories = append(o.Repositories, fmt.Sprintf("artifacts.example/lib/r%02d", i))
	}
	require.NoError(t, store.Observe(t.Context(), digest, o))

	repositories := stored(t, c).Status.Clusters[0].Repositories
	require.Len(t, repositories, 32, "a write with more would be rejected by the schema")
	require.Equal(t, "artifacts.example/lib/r01", repositories[0])
	require.Equal(t, "artifacts.example/lib/r32", repositories[31])
}

func TestObserveSortsAndDedupes(t *testing.T) {
	store, c := newStore(t)
	o := obs(clusterA, idA, 2, 0)
	o.Workloads = []workloads.WorkloadRef{
		{APIGroup: groupApps, Kind: kindStatefulSet, Namespace: otherNamespace, Name: "db"},
		{APIGroup: groupApps, Kind: kindDeployment, Namespace: otherNamespace, Name: nameWeb},
		{Kind: "Pod", Namespace: namespace, Name: "p"},
		{APIGroup: groupApps, Kind: kindDeployment, Namespace: namespace, Name: nameWeb},
		{APIGroup: groupApps, Kind: kindDeployment, Namespace: namespace, Name: nameWeb},
		{APIGroup: "batch", Kind: "CronJob", Namespace: namespace, Name: "nightly"},
	}
	given := slices.Clone(o.Workloads)
	repoA, repoB := "a.example/x", "b.example/x"
	o.Repositories = []string{repoB, repoA, repoB}

	require.NoError(t, store.Observe(t.Context(), digest, o))

	entry := stored(t, c).Status.Clusters[0]
	require.Equal(t, ptr.To(int32(5)), entry.WorkloadCount, "six were given, one of them twice")
	require.Equal(t, []inventoryv1alpha1.WorkloadReference{
		{APIGroup: ptr.To("batch"), Kind: "CronJob", Namespace: namespace, Name: "nightly"},
		{APIGroup: ptr.To(groupApps), Kind: kindDeployment, Namespace: namespace, Name: nameWeb},
		{Kind: "Pod", Namespace: namespace, Name: "p"}, // the core group is left out
		{APIGroup: ptr.To(groupApps), Kind: kindDeployment, Namespace: otherNamespace, Name: nameWeb},
		{APIGroup: ptr.To(groupApps), Kind: kindStatefulSet, Namespace: otherNamespace, Name: "db"},
	}, entry.Workloads, "sorted by namespace, kind and name")
	require.Equal(t, []string{repoA, repoB}, entry.Repositories)
	require.Equal(t, given, o.Workloads, "the store does not reorder the caller's slice")
}

func TestObserveDedupesBeforeCapping(t *testing.T) {
	store, c := newStore(t)
	o := obs(clusterA, idA, 2, 1)
	o.Repositories = nil
	// 35 distinct repositories, each given twice. Capped first, the 70 would leave 16 distinct.
	for range 2 {
		for i := 1; i <= 35; i++ {
			o.Repositories = append(o.Repositories, fmt.Sprintf("artifacts.example/lib/r%02d", i))
		}
	}
	require.NoError(t, store.Observe(t.Context(), digest, o))

	repositories := stored(t, c).Status.Clusters[0].Repositories
	require.Len(t, repositories, 32)
	require.Equal(t, "artifacts.example/lib/r32", repositories[31])
}

// The schema keys the workloads by namespace, kind and name, and the API server rejects a list in
// which two entries share a key. Two workloads of different API groups can share it, for example
// the StatefulSets of two controllers. The count includes both, the list holds one of them: the one
// whose API group sorts first. The full list is on the cluster, as it is for any list that is cut.
func TestObserveKeepsOneWorkloadPerMapKey(t *testing.T) {
	store, c := newStore(t)
	o := obs(clusterA, idA, 1, 0)
	o.Workloads = []workloads.WorkloadRef{
		{APIGroup: "workloads.example", Kind: kindStatefulSet, Namespace: namespace, Name: "db"},
		{APIGroup: groupApps, Kind: kindStatefulSet, Namespace: namespace, Name: "db"},
		deployment(nameWeb),
	}
	require.NoError(t, store.Observe(t.Context(), digest, o))

	entry := stored(t, c).Status.Clusters[0]
	require.Equal(t, ptr.To(int32(3)), entry.WorkloadCount)
	require.Equal(t, []inventoryv1alpha1.WorkloadReference{
		deploymentRef(nameWeb),
		{APIGroup: ptr.To(groupApps), Kind: kindStatefulSet, Namespace: namespace, Name: "db"},
	}, entry.Workloads)

	// Whatever the order of the input, the same one is kept, so nothing is written again.
	slices.Reverse(o.Workloads)
	counts := counted(t, clusterA, func() {
		require.NoError(t, store.Observe(t.Context(), digest, o))
	})
	require.Equal(t, writeCounts{}, counts)
}

func TestObserveRecordsTheDigestKind(t *testing.T) {
	for name, tc := range map[string]struct {
		kind         inventoryv1alpha1.DigestKind
		repositories []string
		want         *inventoryv1alpha1.DigestKind
	}{
		"a repository digest": {
			kind: inventoryv1alpha1.DigestKindRepoDigest, repositories: []string{repository},
			want: ptr.To(inventoryv1alpha1.DigestKindRepoDigest),
		},
		"an image ID, which has no repository": {
			kind: inventoryv1alpha1.DigestKindImageID, repositories: nil,
			want: ptr.To(inventoryv1alpha1.DigestKindImageID),
		},
		"no kind, which is left out and never written as an empty value": {kind: "", want: nil},
	} {
		t.Run(name, func(t *testing.T) {
			store, c := newStore(t)
			o := obs(clusterA, idA, 1, 1)
			o.DigestKind, o.Repositories = tc.kind, tc.repositories

			require.NoError(t, store.Observe(t.Context(), digest, o))

			got := stored(t, c)
			require.Equal(t, tc.want, got.Status.DigestKind)
			require.Equal(t, tc.repositories, got.Status.Clusters[0].Repositories)
		})
	}
}

func TestObserveTwoClusters(t *testing.T) {
	for name, order := range map[string][]string{
		"a then b": {clusterA, clusterB},
		"b then a": {clusterB, clusterA},
	} {
		t.Run(name, func(t *testing.T) {
			store, c := newStore(t)
			for _, cluster := range order {
				require.NoError(t, store.Observe(t.Context(), digest, obs(cluster, "id-"+cluster, 2, 3)))
			}

			entries := stored(t, c).Status.Clusters
			require.Equal(t, []string{clusterA, clusterB}, clusterNames(entries), "sorted by cluster")
			require.Equal(t, "id-"+clusterA, entries[0].ClusterID)
			require.Equal(t, "id-"+clusterB, entries[1].ClusterID)
		})
	}
}

func TestObserveRenamedCluster(t *testing.T) {
	store, c := newStore(t)
	require.NoError(t, store.Observe(t.Context(), digest, obs(clusterA, idA, 2, 3)))
	require.NoError(t, store.Observe(t.Context(), digest, obs(clusterB, idB, 2, 3)))
	stamp := backdate(t, c, clusterA)

	// The same cluster, under a new name.
	counts := counted(t, "cluster-a2", func() {
		require.NoError(t, store.Observe(t.Context(), digest, obs("cluster-a2", idA, 2, 3)))
	})

	require.Equal(t, writeCounts{Update: 1, Sizes: 1}, counts, "the label is the cluster of the observation")
	entries := stored(t, c).Status.Clusters
	require.Equal(t, []string{"cluster-a2", clusterB}, clusterNames(entries), "the old entry is gone")
	require.Equal(t, idA, entries[0].ClusterID)
	requireSameTime(t, stamp, entries[0].FirstSeenTime) // it is the same cluster, so it was first seen then
	require.Equal(t, idB, entries[1].ClusterID, "another cluster is left alone")
}

// --- Observe: failures and other writers ---

func TestObserveRetriesAfterAConflict(t *testing.T) {
	armed := false
	store, c := newStoreWith(t, interceptor.Funcs{
		SubResourceUpdate: func(ctx context.Context, other client.Client, subResource string, obj client.Object,
			opts ...client.SubResourceUpdateOption) error {
			if armed {
				armed = false
				// Another writer changes the object between this write's read and the write.
				addEntry(t, other, clusterB, idB)
			}
			return other.SubResource(subResource).Update(ctx, obj, opts...)
		},
	})
	require.NoError(t, store.Observe(t.Context(), digest, obs(clusterA, idA, 2, 3)))

	armed = true
	counts := counted(t, clusterA, func() {
		require.NoError(t, store.Observe(t.Context(), digest, obs(clusterA, idA, 2, 4)))
	})

	require.False(t, armed, "the conflict happened")
	entries := stored(t, c).Status.Clusters
	require.Equal(t, []string{clusterA, clusterB}, clusterNames(entries), "the other writer's entry is kept")
	require.Equal(t, ptr.To(int32(4)), entries[0].WorkloadCount, "and so is this write")
	require.Equal(t, writeCounts{Update: 1, Sizes: 1}, counts, "a write that was refused is not counted")
}

func TestObserveRetriesAfterACreateRace(t *testing.T) {
	armed := true
	store, c := newStoreWith(t, interceptor.Funcs{
		Create: func(ctx context.Context, other client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			if armed {
				armed = false
				// Another writer creates the object between this write's read and its create.
				created := &inventoryv1alpha1.ImageInventory{}
				created.Name = obj.GetName()
				created.Spec.Digest = digest
				require.NoError(t, other.Create(ctx, created))
				addEntry(t, other, clusterB, idB)
			}
			return other.Create(ctx, obj, opts...)
		},
	})

	counts := counted(t, clusterA, func() {
		require.NoError(t, store.Observe(t.Context(), digest, obs(clusterA, idA, 2, 3)))
	})

	require.False(t, armed, "the race happened")
	require.Equal(t, []string{clusterA, clusterB}, clusterNames(stored(t, c).Status.Clusters))
	require.Equal(t, writeCounts{Update: 1, Sizes: 1}, counts, "this store created nothing")
}

func TestObserveRecoversFromAFailedStatusWrite(t *testing.T) {
	errStatus := errors.New("status write failed")
	fail := true
	store, c := newStoreWith(t, interceptor.Funcs{
		SubResourceUpdate: func(ctx context.Context, other client.Client, subResource string, obj client.Object,
			opts ...client.SubResourceUpdateOption) error {
			if fail {
				return errStatus
			}
			return other.SubResource(subResource).Update(ctx, obj, opts...)
		},
	})

	counts := counted(t, clusterA, func() {
		require.ErrorIs(t, store.Observe(t.Context(), digest, obs(clusterA, idA, 2, 3)), errStatus)
	})

	// The object exists with its spec and no status. That is no wedged state.
	half := stored(t, c)
	require.Equal(t, digest, half.Spec.Digest)
	require.Equal(t, inventoryv1alpha1.ImageInventoryStatus{}, half.Status, "the create carried no status")
	require.Equal(t, writeCounts{Create: 1, Sizes: 1}, counts)

	fail = false
	counts = counted(t, clusterA, func() {
		require.NoError(t, store.Observe(t.Context(), digest, obs(clusterA, idA, 2, 3)))
	})

	require.Equal(t, []string{clusterA}, clusterNames(stored(t, c).Status.Clusters))
	require.Equal(t, writeCounts{Update: 1, Sizes: 1}, counts, "the object is completed, not created again")
}

func TestReadErrorsAreReturned(t *testing.T) {
	errRead := errors.New("read failed")
	store, _ := newStoreWith(t, interceptor.Funcs{
		Get: func(context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption) error {
			return errRead
		},
	})

	got, err := store.Get(t.Context(), digest)
	require.ErrorIs(t, err, errRead, "a failed read is not an absent object")
	require.Nil(t, got)

	counts := counted(t, clusterA, func() {
		require.ErrorIs(t, store.Observe(t.Context(), digest, obs(clusterA, idA, 2, 3)), errRead)
		require.ErrorIs(t, store.Forget(t.Context(), digest, clusterA, idA), errRead)
	})
	require.Equal(t, writeCounts{}, counts, "nothing is written after a failed read")
}

// --- Forget ---

func TestForget(t *testing.T) {
	store, _ := newStore(t)
	require.NoError(t, store.Observe(t.Context(), digest, obs(clusterA, idA, 2, 3)))
	require.NoError(t, store.Observe(t.Context(), digest, obs(clusterB, idB, 2, 3)))

	counts := counted(t, clusterA, func() {
		require.NoError(t, store.Forget(t.Context(), digest, clusterA, idA))
	})
	require.Equal(t, []string{clusterB}, clusterNames(mustGet(t, store).Status.Clusters))
	require.Equal(t, writeCounts{Update: 1, Sizes: 1}, counts, "one entry less is a status write")

	counts = counted(t, clusterB, func() {
		require.NoError(t, store.Forget(t.Context(), digest, clusterB, idB))
	})
	requireAbsent(t, store) // no entry is left
	require.Equal(t, writeCounts{Delete: 1}, counts, "a deletion writes no status and measures no object")

	require.NoError(t, store.Forget(t.Context(), otherDigest, clusterA, idA), "an absent digest is no error")
}

func TestForgetByClusterID(t *testing.T) {
	store, _ := newStore(t)
	require.NoError(t, store.Observe(t.Context(), digest, obs(clusterA, idA, 2, 3)))

	mustGet(t, store) // the object is there before the cluster is forgotten

	// This cluster was renamed while its digest was gone. Its entry still carries its ID.
	require.NoError(t, store.Forget(t.Context(), digest, "renamed", idA))

	requireAbsent(t, store)
}

func TestForgetByName(t *testing.T) {
	store, _ := newStore(t)
	require.NoError(t, store.Observe(t.Context(), digest, obs(clusterA, idA, 2, 3)))

	mustGet(t, store) // the object is there before the cluster is forgotten

	// The name alone is enough, whatever ID the entry has.
	require.NoError(t, store.Forget(t.Context(), digest, clusterA, "another-id"))

	requireAbsent(t, store)
}

func TestForgetRemovesEveryMatch(t *testing.T) {
	store, _ := newStore(t)
	require.NoError(t, store.Observe(t.Context(), digest, obs("old-name", "id-x", 2, 3)))
	require.NoError(t, store.Observe(t.Context(), digest, obs(clusterA, idA, 2, 3)))
	require.NoError(t, store.Observe(t.Context(), digest, obs(clusterB, idB, 2, 3)))

	require.Len(t, mustGet(t, store).Status.Clusters, 3)

	// One entry matches by name, another by ID.
	require.NoError(t, store.Forget(t.Context(), digest, clusterA, "id-x"))

	require.Equal(t, []string{clusterB}, clusterNames(mustGet(t, store).Status.Clusters))
}

func TestForgetKeepsOtherClusters(t *testing.T) {
	store, c := newStore(t)
	require.NoError(t, store.Observe(t.Context(), digest, obs(clusterA, idA, 2, 3)))
	version := stored(t, c).ResourceVersion

	counts := counted(t, clusterB, func() {
		require.NoError(t, store.Forget(t.Context(), digest, clusterB, idB))
	})

	require.Equal(t, writeCounts{}, counts)
	require.Equal(t, version, stored(t, c).ResourceVersion, "there was nothing to remove, so nothing was written")
}

func TestForgetDeletesAnObjectWithoutEntries(t *testing.T) {
	store, c := newStore(t)
	// What a failed first write leaves behind: the spec and no status.
	require.NoError(t, c.Create(t.Context(), &inventoryv1alpha1.ImageInventory{
		ObjectMeta: metav1.ObjectMeta{Name: inventory.NameForDigest(digest)},
		Spec:       inventoryv1alpha1.ImageInventorySpec{Digest: digest},
	}))

	counts := counted(t, clusterA, func() {
		require.NoError(t, store.Forget(t.Context(), digest, clusterA, idA))
	})

	requireAbsent(t, store)
	require.Equal(t, writeCounts{Delete: 1}, counts)
}

// Forget deletes the object it has emptied only if it is still the object it read. Without that,
// an entry that another cluster added after the read would be deleted with the object.
func TestForgetDoesNotDeleteWhatChangedSinceTheRead(t *testing.T) {
	armed := false
	store, c := newStoreWith(t, interceptor.Funcs{
		Delete: func(ctx context.Context, other client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			if armed {
				armed = false
				addEntry(t, other, clusterB, idB)
			}
			return other.Delete(ctx, obj, opts...)
		},
	})
	require.NoError(t, store.Observe(t.Context(), digest, obs(clusterA, idA, 2, 3)))

	armed = true
	counts := counted(t, clusterA, func() {
		require.NoError(t, store.Forget(t.Context(), digest, clusterA, idA))
	})

	require.False(t, armed, "the other writer acted")
	require.Equal(t, []string{clusterB}, clusterNames(stored(t, c).Status.Clusters), "its entry survives")
	require.Equal(t, writeCounts{Update: 1, Sizes: 1}, counts, "the retry removed this cluster's entry only")
}

func TestForgetIgnoresAnObjectThatIsAlreadyGone(t *testing.T) {
	armed := false
	store, _ := newStoreWith(t, interceptor.Funcs{
		Delete: func(ctx context.Context, other client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			if armed {
				armed = false
				require.NoError(t, other.Delete(ctx, obj.DeepCopyObject().(client.Object)))
			}
			return other.Delete(ctx, obj, opts...)
		},
	})
	require.NoError(t, store.Observe(t.Context(), digest, obs(clusterA, idA, 2, 3)))

	armed = true
	counts := counted(t, clusterA, func() {
		require.NoError(t, store.Forget(t.Context(), digest, clusterA, idA))
	})

	require.False(t, armed)
	require.Equal(t, writeCounts{}, counts, "another writer deleted it, so this one counts no deletion")
}

// --- metrics ---

func TestObjectBytesRecorded(t *testing.T) {
	store, c := newStore(t)

	count, _ := sizes(t, clusterA)
	require.NoError(t, store.Observe(t.Context(), digest, obs(clusterA, idA, 2, 3)))
	created, createdSum := sizes(t, clusterA)
	require.Equal(t, count+2, created, "one sample for the create and one for the status write")

	// A write of the status adds one sample, and an unchanged observation none.
	require.NoError(t, store.Observe(t.Context(), digest, obs(clusterA, idA, 2, 4)))
	updated, updatedSum := sizes(t, clusterA)
	require.Equal(t, created+1, updated)
	require.NoError(t, store.Observe(t.Context(), digest, obs(clusterA, idA, 2, 4)))
	unchanged, _ := sizes(t, clusterA)
	require.Equal(t, updated, unchanged)

	// The sample is the size of the whole object as json.Marshal writes it, status included.
	raw, err := json.Marshal(stored(t, c))
	require.NoError(t, err)
	require.InDelta(t, float64(len(raw)), updatedSum-createdSum, 0, "the last sample is the stored object")
}

func TestMetricsAreRegistered(t *testing.T) {
	// A vector appears in the registry once it holds a series.
	metrics.InventoryWritesTotal.WithLabelValues(clusterA, "create")
	metrics.InventoryObjectBytes.WithLabelValues(clusterA)
	metrics.ImagesRunning.WithLabelValues(clusterA).Set(0)
	t.Cleanup(metrics.ImagesRunning.Reset)

	families, err := ctrlmetrics.Registry.Gather()
	require.NoError(t, err)
	byName := make(map[string]*dto.MetricFamily)
	for _, family := range families {
		byName[family.GetName()] = family
	}
	labelsOf := func(family *dto.MetricFamily) []string {
		labels := family.GetMetric()[0].GetLabel()
		names := make([]string, 0, len(labels))
		for _, label := range labels {
			names = append(names, label.GetName())
		}
		return names
	}

	writes := byName["vexplain_inventory_writes_total"]
	require.NotNil(t, writes)
	require.Equal(t, dto.MetricType_COUNTER, writes.GetType())
	require.ElementsMatch(t, []string{clusterLabel, "op"}, labelsOf(writes))

	objectBytes := byName["vexplain_inventory_object_bytes"]
	require.NotNil(t, objectBytes)
	require.Equal(t, dto.MetricType_HISTOGRAM, objectBytes.GetType())
	require.Equal(t, []string{clusterLabel}, labelsOf(objectBytes))
	buckets := objectBytes.GetMetric()[0].GetHistogram().GetBucket()
	bounds := make([]float64, 0, len(buckets))
	for _, bucket := range buckets {
		bounds = append(bounds, bucket.GetUpperBound())
	}
	require.Equal(t, prometheus.ExponentialBuckets(1024, 2, 12), bounds, "from 1 KiB to 2 MiB")

	running := byName["vexplain_images_running"]
	require.NotNil(t, running)
	require.Equal(t, dto.MetricType_GAUGE, running.GetType())
	require.Equal(t, []string{clusterLabel}, labelsOf(running))
}
