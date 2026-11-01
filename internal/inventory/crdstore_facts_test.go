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
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/cache/informertest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/inventory"
)

// These tests cover what the store keeps of the evidence: SetFacts and UpdateFacts, which write the
// facts of a digest, and ManifestReferences, which finds the digests whose facts name a platform
// manifest.

const (
	// The platform manifests that the facts name. manifestOther is the manifest of another image,
	// and manifestUnknown one that no facts name.
	manifestAMD64   = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	manifestARM64   = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	manifestOther   = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
	manifestUnknown = "sha256:4444444444444444444444444444444444444444444444444444444444444444"

	// fourthDigest is a digest that only the tests of ManifestReferences use.
	fourthDigest = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"

	// scanner is the Collector whose evidence the facts record, and imageContents the type of it.
	scanner       = "scanner"
	imageContents = "ch.bedag.vexplain.scanner.image-contents.v1alpha1"
	// The versions of two releases of the scanner.
	scannerV1 = "1.0.0"
	scannerV2 = "2.0.0"
)

// scannedAt is when the scans of the tests finished: a whole second, as the API server stores a time.
var scannedAt = metav1.NewTime(time.Date(2026, time.October, 30, 12, 0, 0, 0, time.UTC))

// manifest returns the platform manifest of an image whose digest is manifestDigest.
func manifest(platform, manifestDigest string) inventoryv1alpha1.ManifestFact {
	return inventoryv1alpha1.ManifestFact{Platform: platform, Digest: manifestDigest}
}

// factsOf returns the facts of the evidence that the scanner at version delivered about the
// manifests.
func factsOf(version string, manifests ...inventoryv1alpha1.ManifestFact) *inventoryv1alpha1.ImageFacts {
	return &inventoryv1alpha1.ImageFacts{
		Manifests: manifests,
		Evidence: []inventoryv1alpha1.EvidenceFact{{
			Source: scanner, Type: imageContents, CollectorVersion: version, Time: ptr.To(scannedAt),
			Coverage: ptr.To(int32(96)),
		}},
	}
}

// multiArch returns the facts of the evidence about an index of two platforms.
func multiArch() *inventoryv1alpha1.ImageFacts {
	return factsOf(scannerV1, manifest("linux/amd64", manifestAMD64), manifest("linux/arm64/v8", manifestARM64))
}

// notPullable returns the facts of an image ID, which no registry serves: a failure, and no evidence
// behind it. The time has a fraction of a second, which the API server doesn't store.
func notPullable() *inventoryv1alpha1.ImageFacts {
	return &inventoryv1alpha1.ImageFacts{Failures: []inventoryv1alpha1.ScanFailure{{
		Source:   scanner,
		Reason:   inventoryv1alpha1.ScanFailureReasonNotPullable,
		Time:     ptr.To(metav1.NewTime(scannedAt.Add(500 * time.Millisecond))),
		Attempts: 1,
	}}}
}

// requireSameFacts compares facts as the store does, with equality.Semantic, which compares times as
// instants: a time that went through JSON comes back in the local zone.
func requireSameFacts(t *testing.T, want, got *inventoryv1alpha1.ImageFacts) {
	t.Helper()
	require.True(t, equality.Semantic.DeepEqual(want, got), "want %s\ngot  %s", asJSON(t, want), asJSON(t, got))
}

func asJSON(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	require.NoError(t, err)
	return string(raw)
}

// --- SetFacts ---

// A scan of a digest that is gone must not bring its object back: only the presence of a digest
// creates one.
func TestSetFactsNeverCreatesAnObject(t *testing.T) {
	store, c := newStore(t)

	var found bool
	counts := counted(t, clusterA, func() {
		var err error
		found, err = store.SetFacts(t.Context(), digest, multiArch())
		require.NoError(t, err)
	})

	require.False(t, found, "the digest has no object")
	var list inventoryv1alpha1.ImageInventoryList
	require.NoError(t, c.List(t.Context(), &list))
	require.Empty(t, list.Items, "no object appears")
	require.Equal(t, writeCounts{}, counts)
}

func TestSetFactsKeepsTheEntries(t *testing.T) {
	store, c := newStore(t)
	require.NoError(t, store.Observe(t.Context(), digest, obs(clusterA, idA, 2, 3)))
	require.NoError(t, store.Observe(t.Context(), digest, obs(clusterB, idB, 1, 1)))
	before := stored(t, c).Status

	found, err := store.SetFacts(t.Context(), digest, multiArch())

	require.NoError(t, err)
	require.True(t, found)
	after := stored(t, c).Status
	require.Equal(t, before.Clusters, after.Clusters, "the entries are as they were")
	require.Equal(t, before.DigestKind, after.DigestKind)
	requireSameFacts(t, multiArch(), after.Facts)
}

func TestSetFactsWritesOnlyAChange(t *testing.T) {
	store, c := newStore(t)
	require.NoError(t, store.Observe(t.Context(), digest, obs(clusterA, idA, 2, 3)))
	// A scan that failed after a success: the facts keep what the success recorded. The times have
	// a fraction of a second, which the API server doesn't store, so the same facts again are no
	// change.
	facts := multiArch()
	facts.Evidence[0].Time = ptr.To(metav1.NewTime(scannedAt.Add(250 * time.Millisecond)))
	facts.Failures = []inventoryv1alpha1.ScanFailure{{
		Source:   scanner,
		Reason:   inventoryv1alpha1.ScanFailureReasonUnauthorized,
		Time:     ptr.To(metav1.NewTime(scannedAt.Add(time.Hour + 750*time.Millisecond))),
		Attempts: 1,
	}, {
		Source:   "matcher",
		Reason:   inventoryv1alpha1.ScanFailureReasonNotFound,
		Time:     ptr.To(metav1.NewTime(scannedAt.Add(2*time.Hour + 500*time.Millisecond))),
		Attempts: 3,
	}}

	counts := counted(t, clusterA, func() {
		for range 2 {
			found, err := store.SetFacts(t.Context(), digest, facts)
			require.NoError(t, err)
			require.True(t, found, "the object exists, whether written or not")
		}
	})
	require.Equal(t, writeCounts{Update: 1, Sizes: 1}, counts, "the same facts twice give one write")
	version := stored(t, c).ResourceVersion

	retried := facts.DeepCopy()
	retried.Failures[0].Attempts = 2
	counts = counted(t, clusterA, func() {
		found, err := store.SetFacts(t.Context(), digest, retried)
		require.NoError(t, err)
		require.True(t, found)
	})
	require.Equal(t, writeCounts{Update: 1, Sizes: 1}, counts, "a change is written")
	require.NotEqual(t, version, stored(t, c).ResourceVersion)
	require.Equal(t, int32(2), stored(t, c).Status.Facts.Failures[0].Attempts)
}

// An image ID can't be pulled, so its facts are a failure without a scan behind it: no manifests
// and no evidence. The same facts again are no change either.
func TestSetFactsOfADigestThatCannotBePulled(t *testing.T) {
	store, c := newStore(t)
	imageID := obs(clusterA, idA, 1, 1)
	imageID.DigestKind, imageID.Repositories = inventoryv1alpha1.DigestKindImageID, nil
	require.NoError(t, store.Observe(t.Context(), digest, imageID))

	counts := counted(t, clusterA, func() {
		for range 2 {
			found, err := store.SetFacts(t.Context(), digest, notPullable())
			require.NoError(t, err)
			require.True(t, found)
		}
	})

	require.Equal(t, writeCounts{Update: 1, Sizes: 1}, counts, "the same facts twice give one write")
	requireSameFacts(t, &inventoryv1alpha1.ImageFacts{Failures: []inventoryv1alpha1.ScanFailure{{
		Source:   scanner,
		Reason:   inventoryv1alpha1.ScanFailureReasonNotPullable,
		Time:     ptr.To(scannedAt), // to the second
		Attempts: 1,
	}}}, stored(t, c).Status.Facts)
}

func TestSetFactsRetriesAfterAConflict(t *testing.T) {
	armed := false
	store, c := newStoreWith(t, interceptor.Funcs{
		SubResourceUpdate: func(ctx context.Context, other client.Client, subResource string, obj client.Object,
			opts ...client.SubResourceUpdateOption) error {
			if armed {
				armed = false
				// Another writer changes the object between this write's read and the write.
				addClusterB(t, other)
			}
			return other.SubResource(subResource).Update(ctx, obj, opts...)
		},
	})
	require.NoError(t, store.Observe(t.Context(), digest, obs(clusterA, idA, 2, 3)))

	armed = true
	var found bool
	counts := counted(t, clusterA, func() {
		var err error
		found, err = store.SetFacts(t.Context(), digest, multiArch())
		require.NoError(t, err)
	})

	require.False(t, armed, "the conflict happened")
	require.True(t, found)
	got := stored(t, c).Status
	require.Equal(t, []string{clusterA, clusterB}, clusterNames(got.Clusters), "the other writer's entry is kept")
	requireSameFacts(t, multiArch(), got.Facts)
	require.Equal(t, writeCounts{Update: 1, Sizes: 1}, counts, "a write that was refused is not counted")
}

// A digest can disappear while it is scanned. The facts of the scan are then dropped, and never
// bring the object back.
func TestSetFactsDropsTheFactsOfADigestDeletedUnderItsWrite(t *testing.T) {
	armed := false
	store, c := newStoreWith(t, deleteUnderStatusWrite(t, &armed))
	require.NoError(t, store.Observe(t.Context(), digest, obs(clusterA, idA, 2, 3)))

	armed = true
	var found bool
	counts := counted(t, clusterA, func() {
		var err error
		found, err = store.SetFacts(t.Context(), digest, multiArch())
		require.NoError(t, err, "a digest that went away is no error")
	})

	require.False(t, armed, "the object was deleted under the write")
	require.False(t, found, "the digest has no object any more")
	var list inventoryv1alpha1.ImageInventoryList
	require.NoError(t, c.List(t.Context(), &list))
	require.Empty(t, list.Items, "no object appears")
	require.Equal(t, writeCounts{}, counts)
}

// The writes of SetFacts carry the name of the store's cluster, which the store reads at each write,
// so that the label follows a rename. A write while the name can't be read is not counted.
func TestSetFactsLabelsItsWritesWithTheClusterOfTheStore(t *testing.T) {
	name := clusterA
	store := inventory.NewCRDStore(newClient(t, interceptor.Funcs{}), nil, func() string { return name })
	// The observation carries a cluster of its own, which labels the writes of Observe.
	require.NoError(t, store.Observe(t.Context(), digest, obs(clusterB, idB, 1, 1)))
	setFacts := func(coverage int32) {
		facts := multiArch()
		facts.Evidence[0].Coverage = ptr.To(coverage)
		found, err := store.SetFacts(t.Context(), digest, facts)
		require.NoError(t, err)
		require.True(t, found)
	}

	counts := counted(t, clusterA, func() { setFacts(1) })
	require.Equal(t, writeCounts{Update: 1, Sizes: 1}, counts)

	name = "cluster-a2"
	counts = counted(t, "cluster-a2", func() { setFacts(2) })
	require.Equal(t, writeCounts{Update: 1, Sizes: 1}, counts, "the name is read at each write")

	name = ""
	counts = counted(t, "", func() { setFacts(3) })
	require.Equal(t, writeCounts{}, counts, "no series for a cluster without a name")
	got, err := store.Get(t.Context(), digest)
	require.NoError(t, err)
	require.Equal(t, ptr.To(int32(3)), got.Status.Facts.Evidence[0].Coverage, "the facts are written all the same")
}

// Facts of nil clear the facts: the object goes back to what the presence of the digest alone
// says. Its entries stay, and an object without facts gets no write.
func TestSetFactsOfNilClearsTheFacts(t *testing.T) {
	store, c := newStore(t)
	require.NoError(t, store.Observe(t.Context(), digest, obs(clusterA, idA, 2, 3)))
	before := stored(t, c).Status

	counts := counted(t, clusterA, func() {
		found, err := store.SetFacts(t.Context(), digest, nil)
		require.NoError(t, err)
		require.True(t, found)
	})
	require.Equal(t, writeCounts{}, counts, "an object without facts is left as it is")

	putFacts(t, store, multiArch())
	counts = counted(t, clusterA, func() {
		found, err := store.SetFacts(t.Context(), digest, nil)
		require.NoError(t, err)
		require.True(t, found)
	})

	require.Equal(t, writeCounts{Update: 1, Sizes: 1}, counts)
	after := stored(t, c).Status
	require.Nil(t, after.Facts)
	require.Equal(t, before.Clusters, after.Clusters, "the entries are as they were")
}

// The facts belong to the digest, not to a cluster: one cluster that stops running the digest
// leaves them to the clusters that still run it.
func TestForgetOfOneClusterKeepsTheFacts(t *testing.T) {
	store, c := newStore(t)
	require.NoError(t, store.Observe(t.Context(), digest, obs(clusterA, idA, 2, 3)))
	require.NoError(t, store.Observe(t.Context(), digest, obs(clusterB, idB, 1, 1)))
	putFacts(t, store, multiArch())

	require.NoError(t, store.Forget(t.Context(), digest, clusterA, idA))

	got := stored(t, c).Status
	require.Equal(t, []string{clusterB}, clusterNames(got.Clusters))
	requireSameFacts(t, multiArch(), got.Facts)
}

// putFacts writes the facts of digest, which must have an object.
func putFacts(t *testing.T, store inventory.Store, facts *inventoryv1alpha1.ImageFacts) {
	t.Helper()
	found, err := store.SetFacts(t.Context(), digest, facts)
	require.NoError(t, err)
	require.True(t, found)
}

// --- UpdateFacts ---

// UpdateFacts hands its function a copy of the facts as they are, nil when there are none, and
// writes what the function makes of them.
func TestUpdateFactsWritesWhatItsFunctionMakesOfTheFacts(t *testing.T) {
	store, c := newStore(t)
	require.NoError(t, store.Observe(t.Context(), digest, obs(clusterA, idA, 2, 3)))
	var seen []*inventoryv1alpha1.ImageFacts

	found, err := store.UpdateFacts(t.Context(), digest, func(facts *inventoryv1alpha1.ImageFacts) (*inventoryv1alpha1.ImageFacts, error) {
		seen = append(seen, facts)
		return multiArch(), nil
	})
	require.NoError(t, err)
	require.True(t, found)
	found, err = store.UpdateFacts(t.Context(), digest, func(facts *inventoryv1alpha1.ImageFacts) (*inventoryv1alpha1.ImageFacts, error) {
		seen = append(seen, facts.DeepCopy())
		facts.Manifests = facts.Manifests[:1]
		return facts, nil
	})
	require.NoError(t, err)
	require.True(t, found)

	require.Len(t, seen, 2)
	require.Nil(t, seen[0], "an object without facts")
	requireSameFacts(t, multiArch(), seen[1])
	want := multiArch()
	want.Manifests = want.Manifests[:1]
	requireSameFacts(t, want, stored(t, c).Status.Facts)
}

func TestUpdateFactsWritesOnlyAChange(t *testing.T) {
	store, _ := newStore(t)
	require.NoError(t, store.Observe(t.Context(), digest, obs(clusterA, idA, 2, 3)))
	putFacts(t, store, multiArch())

	counts := counted(t, clusterA, func() {
		found, err := store.UpdateFacts(t.Context(), digest, func(facts *inventoryv1alpha1.ImageFacts) (*inventoryv1alpha1.ImageFacts, error) {
			// The same time, with a fraction of a second that the API server doesn't store.
			facts.Evidence[0].Time = ptr.To(metav1.NewTime(scannedAt.Add(250 * time.Millisecond)))
			return facts, nil
		})
		require.NoError(t, err)
		require.True(t, found, "the object exists, whether written or not")
	})

	require.Equal(t, writeCounts{}, counts)
}

// Facts never create an object: only the presence of a digest does.
func TestUpdateFactsNeverCreatesAnObject(t *testing.T) {
	store, c := newStore(t)
	called := false

	found, err := store.UpdateFacts(t.Context(), digest, func(*inventoryv1alpha1.ImageFacts) (*inventoryv1alpha1.ImageFacts, error) {
		called = true
		return multiArch(), nil
	})

	require.NoError(t, err)
	require.False(t, found)
	require.False(t, called, "there are no facts to update")
	var list inventoryv1alpha1.ImageInventoryList
	require.NoError(t, c.List(t.Context(), &list))
	require.Empty(t, list.Items)
}

// The function can refuse the facts that it is handed, such as when they would hold more than the
// API holds: UpdateFacts then writes nothing, and returns the error.
func TestUpdateFactsReturnsTheErrorOfItsFunctionAndWritesNothing(t *testing.T) {
	store, c := newStore(t)
	require.NoError(t, store.Observe(t.Context(), digest, obs(clusterA, idA, 2, 3)))
	putFacts(t, store, multiArch())
	version := stored(t, c).ResourceVersion
	errRefused := errors.New("the facts would hold too much")

	found, err := store.UpdateFacts(t.Context(), digest, func(*inventoryv1alpha1.ImageFacts) (*inventoryv1alpha1.ImageFacts, error) {
		return nil, errRefused
	})

	require.ErrorIs(t, err, errRefused)
	require.False(t, found)
	require.Equal(t, version, stored(t, c).ResourceVersion, "nothing was written")
}

// Another writer changes the facts between the read of UpdateFacts and its write. The write meets a
// conflict, and the next round hands the function the facts as the other writer left them, so that
// its change isn't lost.
func TestUpdateFactsAppliesItsFunctionAgainAfterAConflict(t *testing.T) {
	armed := false
	store, c := newStoreWith(t, interceptor.Funcs{
		SubResourceUpdate: func(ctx context.Context, other client.Client, subResource string, obj client.Object,
			opts ...client.SubResourceUpdateOption) error {
			if armed {
				armed = false
				written := stored(t, other)
				written.Status.Facts.Manifests = append(written.Status.Facts.Manifests, manifest("linux/s390x", manifestOther))
				require.NoError(t, other.Status().Update(ctx, written))
			}
			return other.SubResource(subResource).Update(ctx, obj, opts...)
		},
	})
	require.NoError(t, store.Observe(t.Context(), digest, obs(clusterA, idA, 2, 3)))
	putFacts(t, store, multiArch())
	rounds := 0

	armed = true
	found, err := store.UpdateFacts(t.Context(), digest, func(facts *inventoryv1alpha1.ImageFacts) (*inventoryv1alpha1.ImageFacts, error) {
		rounds++
		facts.Evidence[0].CollectorVersion = scannerV2
		return facts, nil
	})

	require.NoError(t, err)
	require.True(t, found)
	require.False(t, armed, "the other writer acted")
	require.Equal(t, 2, rounds, "the function ran again on the facts as they were then")
	want := factsOf(scannerV2, manifest("linux/amd64", manifestAMD64), manifest("linux/arm64/v8", manifestARM64),
		manifest("linux/s390x", manifestOther))
	requireSameFacts(t, want, stored(t, c).Status.Facts)
}

// --- ManifestReferences ---

// withFacts returns the ImageInventory of digest, with an entry of the local cluster and the facts.
func withFacts(digest string, facts *inventoryv1alpha1.ImageFacts) *inventoryv1alpha1.ImageInventory {
	obj := inventoryOf(digest, [2]string{localCluster, localID})
	obj.Status.Facts = facts
	return obj
}

// scannedObjects are the objects of the tests of ManifestReferences:
//   - digest, an index of two platforms
//   - otherDigest, the amd64 manifest of that index, which a pod reports by itself, so the two
//     digests share the manifest
//   - thirdDigest, another image
//   - fourthDigest, an image that was never scanned
func scannedObjects() []client.Object {
	return []client.Object{
		withFacts(digest, multiArch()),
		withFacts(otherDigest, factsOf(scannerV1, manifest("linux/amd64", manifestAMD64))),
		withFacts(thirdDigest, factsOf(scannerV1, manifest("linux/amd64", manifestOther))),
		inventoryOf(fourthDigest, [2]string{localCluster, localID}),
	}
}

func TestManifestReferences(t *testing.T) {
	cases := []struct {
		manifest string
		want     []string
	}{
		{manifest: manifestAMD64, want: []string{digest, otherDigest}},
		{manifest: manifestARM64, want: []string{digest}},
		{manifest: manifestOther, want: []string{thirdDigest}},
		{manifest: manifestUnknown, want: nil},
	}
	for name, informers := range map[string]cache.Cache{
		// A store without informers, such as one of a tool, reads through a client that may have no
		// cache, so no index either.
		"without informers, it lists every object": nil,
		// A store with informers reads through the manager's cache, where setup.Register registers
		// the index.
		"with informers, it lists through the index": &informertest.FakeInformers{},
	} {
		t.Run(name, func(t *testing.T) {
			var selectors []fields.Selector
			builder := fake.NewClientBuilder().WithScheme(newScheme(t)).WithObjects(scannedObjects()...).
				WithInterceptorFuncs(interceptor.Funcs{
					List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
						var options client.ListOptions
						options.ApplyOptions(opts)
						selectors = append(selectors, options.FieldSelector)
						return c.List(ctx, list, opts...)
					},
				})
			if informers != nil {
				builder = builder.WithIndex(&inventoryv1alpha1.ImageInventory{},
					inventory.ManifestDigestIndex, inventory.IndexManifestDigests)
			}
			store := inventory.NewCRDStore(builder.Build(), informers, fixedCluster(localCluster))

			for _, tc := range cases {
				got, err := store.ManifestReferences(t.Context(), tc.manifest)
				require.NoError(t, err)
				require.ElementsMatch(t, tc.want, got, tc.manifest)
			}

			require.Len(t, selectors, len(cases), "one list for each call")
			for i, tc := range cases {
				if informers == nil {
					require.Nil(t, selectors[i], "no field selector")
					continue
				}
				require.Equal(t, inventory.ManifestDigestIndex+"="+tc.manifest, selectors[i].String())
			}
		})
	}
}

func TestIndexManifestDigests(t *testing.T) {
	require.Equal(t, []string{manifestAMD64, manifestARM64}, inventory.IndexManifestDigests(withFacts(digest, multiArch())))

	require.Empty(t, inventory.IndexManifestDigests(withFacts(digest, notPullable())), "a scan that never succeeded names none")
	require.Empty(t, inventory.IndexManifestDigests(inventoryOf(digest)), "an object that was never scanned names none")
	require.Empty(t, inventory.IndexManifestDigests(&inventoryv1alpha1.Evidence{}), "nor does another kind")
}
