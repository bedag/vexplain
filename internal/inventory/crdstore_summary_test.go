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
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/cache/informertest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/inventory"
)

// These tests cover the summary of an ImageInventory (decision 0039), which the hub writes while each cluster writes
// its own entry and the spokes write the facts. SetSummary writes the summary alone, so that neither undoes the other.

// imageSummary returns the summary of an image that runs, was scanned, and has open findings.
func imageSummary() inventoryv1alpha1.ImageSummary {
	return inventoryv1alpha1.ImageSummary{
		Image:      ptr.To(repository),
		Workloads:  ptr.To(int32(3)),
		Namespaces: ptr.To(int32(2)),
		ScanState:  inventoryv1alpha1.ScanStateScanned,
		Open:       ptr.To(int32(5)),
		Fixable:    ptr.To(int32(2)),
	}
}

// setSummary writes the summary of digest through store, and fails the test unless the object exists.
func setSummary(t *testing.T, store inventory.Store, summary inventoryv1alpha1.ImageSummary) {
	t.Helper()
	found, err := store.SetSummary(t.Context(), digest, summary)
	require.NoError(t, err)
	require.True(t, found, "the digest has an object")
}

// The summary is written with a JSON merge patch of status.summary, which names nothing else of the object: no
// resourceVersion, so another writer's change can't make it fail, and no other field, so it undoes none.
func TestSetSummaryPatchesTheSummaryAloneAndKeepsTheRest(t *testing.T) {
	var patches []client.Patch
	var bodies []map[string]any
	store, c := newStoreWith(t, interceptor.Funcs{
		SubResourcePatch: func(ctx context.Context, other client.Client, subResource string, obj client.Object, patch client.Patch,
			opts ...client.SubResourcePatchOption) error {
			raw, err := patch.Data(obj)
			require.NoError(t, err)
			var body map[string]any
			require.NoError(t, json.Unmarshal(raw, &body))
			patches, bodies = append(patches, patch), append(bodies, body)
			return other.SubResource(subResource).Patch(ctx, obj, patch, opts...)
		},
	})
	require.NoError(t, store.Observe(t.Context(), digest, obs(clusterA, idA, 2, 3)))
	require.NoError(t, store.Observe(t.Context(), digest, obs(clusterB, idB, 1, 1)))
	putFacts(t, store, multiArch())
	before := stored(t, c).Status

	setSummary(t, store, imageSummary())

	require.Len(t, patches, 1, "one write")
	require.Equal(t, types.MergePatchType, patches[0].Type())
	require.Equal(t, []string{"status"}, keysOf(bodies[0]), "the patch names the status alone")
	status, ok := bodies[0]["status"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, []string{"summary"}, keysOf(status), "and of the status the summary alone")

	got := stored(t, c).Status
	require.Equal(t, ptr.To(imageSummary()), got.Summary)
	require.Equal(t, before.Clusters, got.Clusters, "the entries stay")
	requireSameFacts(t, before.Facts, got.Facts)
	require.Equal(t, before.DigestKind, got.DigestKind)
}

// keysOf returns the keys of a JSON object.
func keysOf(object map[string]any) []string {
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	return keys
}

// A summary replaces the one before it: what it leaves out goes, as a merge patch removes a field that it sets to null.
func TestSetSummaryRemovesWhatTheNewSummaryLeavesOut(t *testing.T) {
	store, c := newStore(t)
	require.NoError(t, store.Observe(t.Context(), digest, obs(clusterA, idA, 2, 3)))
	setSummary(t, store, imageSummary())

	pending := inventoryv1alpha1.ImageSummary{
		Workloads: ptr.To(int32(1)), Namespaces: ptr.To(int32(1)), ScanState: inventoryv1alpha1.ScanStatePending,
	}
	setSummary(t, store, pending)

	require.Equal(t, &pending, stored(t, c).Status.Summary, "no image, and no open or fixable findings")
}

// Only the presence of a digest creates its object.
func TestSetSummaryNeverCreatesAnObject(t *testing.T) {
	store, c := newStore(t)

	found, err := store.SetSummary(t.Context(), digest, imageSummary())

	require.NoError(t, err)
	require.False(t, found)
	var list inventoryv1alpha1.ImageInventoryList
	require.NoError(t, c.List(t.Context(), &list))
	require.Empty(t, list.Items)
}

// A digest can go away while the hub summarizes it. Its summary is then dropped, and is no error.
func TestSetSummaryDropsTheSummaryOfADigestDeletedUnderItsWrite(t *testing.T) {
	armed := false
	store, _ := newStoreWith(t, interceptor.Funcs{
		SubResourcePatch: func(ctx context.Context, other client.Client, subResource string, obj client.Object, patch client.Patch,
			opts ...client.SubResourcePatchOption) error {
			if armed {
				armed = false
				require.NoError(t, other.Delete(ctx, obj.DeepCopyObject().(client.Object)))
			}
			return other.SubResource(subResource).Patch(ctx, obj, patch, opts...)
		},
	})
	require.NoError(t, store.Observe(t.Context(), digest, obs(clusterA, idA, 2, 3)))

	armed = true
	found, err := store.SetSummary(t.Context(), digest, imageSummary())

	require.NoError(t, err)
	require.False(t, armed, "the object went under the write")
	require.False(t, found)
	requireAbsent(t, store)
}

// The write of a summary is a write of the store's cluster, the hub's.
func TestSetSummaryCountsItsWriteForTheClusterOfTheStore(t *testing.T) {
	store, _ := newStore(t)
	require.NoError(t, store.Observe(t.Context(), digest, obs(clusterB, idB, 2, 3)))

	counts := counted(t, clusterA, func() { setSummary(t, store, imageSummary()) })

	require.Equal(t, writeCounts{Update: 1, Sizes: 1}, counts)
}

// ---- the write of the summary and the other writers, which race it ----

// The hub writes the summary between the read of a spoke's Observe and its write. The write of the entry meets a
// conflict, and the next round reads the object again, with the summary, and keeps it.
func TestAnObserveThatMeetsAWriteOfTheSummaryKeepsTheSummary(t *testing.T) {
	armed, writes := false, 0
	store, c := newStoreWith(t, interceptor.Funcs{
		SubResourceUpdate: func(ctx context.Context, other client.Client, subResource string, obj client.Object,
			opts ...client.SubResourceUpdateOption) error {
			writes++
			if armed {
				armed = false
				// The hub's store writes through the same API server.
				found, err := inventory.NewCRDStore(other, nil, fixedCluster(clusterA)).SetSummary(ctx, digest, imageSummary())
				require.NoError(t, err)
				require.True(t, found)
			}
			return other.SubResource(subResource).Update(ctx, obj, opts...)
		},
	})
	require.NoError(t, store.Observe(t.Context(), digest, obs(clusterA, idA, 2, 3)))

	armed, writes = true, 0
	require.NoError(t, store.Observe(t.Context(), digest, obs(clusterB, idB, 1, 1)))

	require.False(t, armed, "the summary was written under the Observe")
	require.Equal(t, 2, writes, "the first write met a conflict, and the second read the object again")
	got := stored(t, c).Status
	require.Equal(t, []string{clusterA, clusterB}, clusterNames(got.Clusters), "the spoke's entry is written")
	require.Equal(t, ptr.To(imageSummary()), got.Summary, "the hub's summary stays")
}

// A spoke writes its entry between the hub's read of the object, from which it made the summary, and the hub's
// write of the summary. The write of the summary names nothing but the summary, and so keeps the entry. The summary
// is then the one of the object before the entry, and the change of the entry has the hub summarize the image again.
func TestAWriteOfTheSummaryThatMeetsAnObserveKeepsTheEntry(t *testing.T) {
	armed := false
	store, c := newStoreWith(t, interceptor.Funcs{
		SubResourcePatch: func(ctx context.Context, other client.Client, subResource string, obj client.Object, patch client.Patch,
			opts ...client.SubResourcePatchOption) error {
			if armed {
				armed = false
				spoke := inventory.NewCRDStore(other, nil, fixedCluster(clusterB))
				require.NoError(t, spoke.Observe(ctx, digest, obs(clusterB, idB, 1, 1)))
			}
			return other.SubResource(subResource).Patch(ctx, obj, patch, opts...)
		},
	})
	require.NoError(t, store.Observe(t.Context(), digest, obs(clusterA, idA, 2, 3)))

	armed = true
	setSummary(t, store, imageSummary())

	require.False(t, armed, "the spoke wrote its entry under the write of the summary")
	got := stored(t, c).Status
	require.Equal(t, []string{clusterA, clusterB}, clusterNames(got.Clusters), "the spoke's entry stays")
	require.Equal(t, ptr.To(imageSummary()), got.Summary, "and the summary is written")
}

// The facts are written as the entries are, by reading the object and writing its status, so a summary written
// between the two is kept as well.
func TestFactsThatMeetAWriteOfTheSummaryKeepTheSummary(t *testing.T) {
	armed, writes := false, 0
	store, c := newStoreWith(t, interceptor.Funcs{
		SubResourceUpdate: func(ctx context.Context, other client.Client, subResource string, obj client.Object,
			opts ...client.SubResourceUpdateOption) error {
			writes++
			if armed {
				armed = false
				found, err := inventory.NewCRDStore(other, nil, fixedCluster(clusterA)).SetSummary(ctx, digest, imageSummary())
				require.NoError(t, err)
				require.True(t, found)
			}
			return other.SubResource(subResource).Update(ctx, obj, opts...)
		},
	})
	require.NoError(t, store.Observe(t.Context(), digest, obs(clusterA, idA, 2, 3)))

	armed, writes = true, 0
	putFacts(t, store, multiArch())

	require.False(t, armed, "the summary was written under the write of the facts")
	require.Equal(t, 2, writes, "the first write met a conflict, and the second read the object again")
	got := stored(t, c).Status
	requireSameFacts(t, multiArch(), got.Facts)
	require.Equal(t, ptr.To(imageSummary()), got.Summary, "the hub's summary stays")
}

// ---- the Source ----

// Nothing that watches the objects reads their summary, and the hub writes it whenever what it reads changes, so a
// change of the summary alone delivers no request: every controller that watches would look at the image again for
// nothing, and the renderer would render the reports of each of its workloads again.
func TestSourceDeliversNoRequestForAChangeOfTheSummaryAlone(t *testing.T) {
	informers := &informertest.FakeInformers{Scheme: newScheme(t)}
	store := inventory.NewCRDStore(newClient(t, interceptor.Funcs{}), informers, fixedCluster(clusterA))
	queue := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[reconcile.Request]())
	t.Cleanup(queue.ShutDown)
	src, ok := store.Source().(source.SyncingSource)
	require.True(t, ok, "the source waits for the cache")
	require.NoError(t, src.Start(t.Context(), queue))
	require.NoError(t, src.WaitForSync(t.Context()))
	informer, err := informers.FakeInformerFor(t.Context(), &inventoryv1alpha1.ImageInventory{})
	require.NoError(t, err)

	object := inventoryOf(digest, [2]string{localCluster, localID})
	object.ResourceVersion = "1"
	summarized := object.DeepCopy()
	summarized.ResourceVersion = "2"
	summarized.Status.Summary = ptr.To(imageSummary())
	informer.Update(object, summarized)
	require.Zero(t, queue.Len(), "a change of the summary alone")

	resummarized := summarized.DeepCopy()
	resummarized.ResourceVersion = "3"
	resummarized.Status.Summary.Open = ptr.To(int32(6))
	informer.Update(summarized, resummarized)
	require.Zero(t, queue.Len(), "another change of the summary alone")

	for name, change := range map[string]func(*inventoryv1alpha1.ImageInventory){
		"an entry":                 func(o *inventoryv1alpha1.ImageInventory) { o.Status.Clusters[0].WorkloadCount = ptr.To(int32(7)) },
		"the facts":                func(o *inventoryv1alpha1.ImageInventory) { o.Status.Facts = multiArch() },
		"the summary and an entry": func(o *inventoryv1alpha1.ImageInventory) { o.Status.Summary.Open, o.Status.Clusters = nil, nil },
		"a label":                  func(o *inventoryv1alpha1.ImageInventory) { o.Labels = map[string]string{"team": "a"} },
	} {
		changed := resummarized.DeepCopy()
		changed.ResourceVersion = "4"
		change(changed)
		informer.Update(resummarized, changed)
		require.Equal(t, 1, queue.Len(), "a change of %s", name)
		got, _ := queue.Get()
		require.Equal(t, inventory.NameForDigest(digest), got.Name)
		queue.Done(got)
		queue.Forget(got)
	}

	informer.Update(resummarized, resummarized.DeepCopy())
	require.Equal(t, 1, queue.Len(), "a resync, which changes nothing, still delivers its request")
}
