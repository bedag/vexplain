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

// These tests cover what the store keeps of the scans: SetFacts, which writes the facts of a
// digest, and ManifestReferences, which finds the digests whose facts name a platform manifest.

const (
	// The platform manifests that the facts name. manifestOther is the manifest of another image,
	// and manifestUnknown one that no facts name.
	manifestAMD64   = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	manifestARM64   = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	manifestOther   = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
	manifestUnknown = "sha256:4444444444444444444444444444444444444444444444444444444444444444"

	// fourthDigest is a digest that only the tests of ManifestReferences use.
	fourthDigest = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"

	// The images of two versions of the scanner.
	scannerV1 = "artifacts.example/vexplain-scanner:1.0"
	scannerV2 = "artifacts.example/vexplain-scanner:2.0"
)

// scannedAt is when the scans of the tests finished: a whole second, as the API server stores a time.
var scannedAt = metav1.NewTime(time.Date(2026, time.October, 30, 12, 0, 0, 0, time.UTC))

// platform returns the facts of a platform whose manifest is manifestDigest.
func platform(name, manifestDigest string) inventoryv1alpha1.PlatformFacts {
	return inventoryv1alpha1.PlatformFacts{
		Platform:            name,
		ManifestDigest:      manifestDigest,
		CompletenessPercent: ptr.To(int32(96)),
		ELFFiles:            ptr.To(int32(48)),
		Packages:            ptr.To(int32(112)),
	}
}

// factsOf returns the facts of a successful scan by scanner, of the platforms.
func factsOf(scanner string, platforms ...inventoryv1alpha1.PlatformFacts) *inventoryv1alpha1.ImageFacts {
	return &inventoryv1alpha1.ImageFacts{
		ScannerImage: ptr.To(scanner),
		ScannedTime:  ptr.To(scannedAt),
		Platforms:    platforms,
	}
}

// multiArch returns the facts of a scan of an index of two platforms.
func multiArch() *inventoryv1alpha1.ImageFacts {
	return factsOf(scannerV1, platform("linux/amd64", manifestAMD64), platform("linux/arm64/v8", manifestARM64))
}

// notPullable returns the facts of an image ID, which no registry serves: a failure, and no scan
// behind it. The time has a fraction of a second, which the API server doesn't store.
func notPullable() *inventoryv1alpha1.ImageFacts {
	return &inventoryv1alpha1.ImageFacts{Failure: &inventoryv1alpha1.ScanFailure{
		Reason:   inventoryv1alpha1.ScanFailureReasonNotPullable,
		Time:     ptr.To(metav1.NewTime(scannedAt.Add(500 * time.Millisecond))),
		Attempts: 1,
	}}
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
	// A scan that failed after a success: the facts keep the platforms. Both times have a fraction of
	// a second, which the API server doesn't store, so the same facts again are no change.
	facts := multiArch()
	facts.ScannedTime = ptr.To(metav1.NewTime(scannedAt.Add(250 * time.Millisecond)))
	facts.Failure = &inventoryv1alpha1.ScanFailure{
		Reason:   inventoryv1alpha1.ScanFailureReasonUnauthorized,
		Time:     ptr.To(metav1.NewTime(scannedAt.Add(time.Hour + 750*time.Millisecond))),
		Attempts: 1,
	}

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
	retried.Failure.Attempts = 2
	counts = counted(t, clusterA, func() {
		found, err := store.SetFacts(t.Context(), digest, retried)
		require.NoError(t, err)
		require.True(t, found)
	})
	require.Equal(t, writeCounts{Update: 1, Sizes: 1}, counts, "a change is written")
	require.NotEqual(t, version, stored(t, c).ResourceVersion)
	require.Equal(t, int32(2), stored(t, c).Status.Facts.Failure.Attempts)
}

// An image ID can't be pulled, so its facts are a failure without a scan behind it: no platforms,
// no scanner and no time of a scan. The same facts again are no change either.
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
	requireSameFacts(t, &inventoryv1alpha1.ImageFacts{Failure: &inventoryv1alpha1.ScanFailure{
		Reason:   inventoryv1alpha1.ScanFailureReasonNotPullable,
		Time:     ptr.To(scannedAt), // to the second
		Attempts: 1,
	}}, stored(t, c).Status.Facts)
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
	setFacts := func(packages int32) {
		facts := multiArch()
		facts.Platforms[0].Packages = ptr.To(packages)
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
	require.Equal(t, ptr.To(int32(3)), got.Status.Facts.Platforms[0].Packages, "the facts are written all the same")
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
		withFacts(otherDigest, factsOf(scannerV1, platform("linux/amd64", manifestAMD64))),
		withFacts(thirdDigest, factsOf(scannerV1, platform("linux/amd64", manifestOther))),
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
	require.Empty(t, inventory.IndexManifestDigests(&inventoryv1alpha1.ImagePackages{}), "nor does another kind")
}
