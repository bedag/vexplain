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
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllertest"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/scan/result"
)

// These tests cover the PackagesStore: the evidence of the scans, one object per platform manifest,
// written once.

const (
	// linuxAMD64 is the platform of the evidence of the tests.
	linuxAMD64 = "linux/amd64"
	// packageID is the ID in the SBOM of the package that the evidence and the sheets of the tests
	// are about.
	packageID = "pkg-1"
)

// packagesKind is the kind of the ImagePackages objects, which the metadata reads and the watch of
// the store name.
var packagesKind = inventoryv1alpha1.GroupVersion.WithKind("ImagePackages")

// newPackagesStore returns a PackagesStore over a fake client, and the client. Its writes are
// labelled with clusterA. It never watches, so it has no cache.
func newPackagesStore(t *testing.T, funcs interceptor.Funcs) (inventory.PackagesStore, client.Client) {
	t.Helper()
	c := newClient(t, funcs)
	return inventory.NewCRDPackagesStore(c, nil, fixedCluster(clusterA)), c
}

// evidence returns what a scan found in the platform manifest: a package that owns a shared
// library, which a program of the image loads.
func evidence(manifestDigest string) result.Manifest {
	return result.Manifest{
		Platform: linuxAMD64,
		Digest:   manifestDigest,
		SBOM:     json.RawMessage(`{"artifacts":[{"id":"pkg-1","name":"libexample1","version":"1.2.3-1","type":"deb"}]}`),
		Packages: []result.PackageFacts{{ID: packageID, FilesListed: 4, FilesPresent: 4, SharedLibraries: 1}},
		ELF:      result.ELFSummary{Total: 3, Owned: 3},
		Libraries: []result.Library{{
			Path:         "/usr/lib/libexample.so.1",
			Soname:       "libexample.so.1",
			PackageID:    packageID,
			ReachedBy:    []string{"/usr/bin/app"},
			ReachedCount: 1,
		}},
	}
}

// incompressible returns evidence whose SBOM is random text, which gzip can't compress below
// MaxEvidenceBytes.
func incompressible(t *testing.T, manifestDigest string) result.Manifest {
	t.Helper()
	// Random base64 holds 6 bits in each character, so gzip makes no less than the random bytes of
	// it: 9/8 of the limit.
	random := rand.New(rand.NewPCG(1, 2))
	raw := make([]byte, inventory.MaxEvidenceBytes*9/8)
	for i := range raw {
		raw[i] = byte(random.Uint32())
	}
	m := evidence(manifestDigest)
	m.SBOM = json.RawMessage(strconv.Quote(base64.StdEncoding.EncodeToString(raw)))
	compressed, _, err := result.EncodeManifest(m)
	require.NoError(t, err)
	require.Greater(t, len(compressed), inventory.MaxEvidenceBytes, "the evidence is over the limit")
	return m
}

// storedPackages reads the ImagePackages of a manifest behind the store, straight from the client.
func storedPackages(t *testing.T, c client.Client, manifestDigest string) *inventoryv1alpha1.ImagePackages {
	t.Helper()
	obj := &inventoryv1alpha1.ImagePackages{}
	require.NoError(t, c.Get(t.Context(), client.ObjectKey{Name: inventory.NameForDigest(manifestDigest)}, obj))
	return obj
}

// requireNoPackages fails the test when the store holds evidence of the manifest.
func requireNoPackages(t *testing.T, store inventory.PackagesStore, manifestDigest string) {
	t.Helper()
	m, info, err := store.Get(t.Context(), manifestDigest)
	require.NoError(t, err)
	require.Nil(t, m)
	require.Nil(t, info)
}

// replaceWith plays another writer that replaces the evidence of a manifest with that of scanner.
func replaceWith(t *testing.T, other client.Client, manifestDigest, scanner string) {
	t.Helper()
	obj := storedPackages(t, other, manifestDigest)
	require.NoError(t, other.Delete(t.Context(), obj))
	obj.ResourceVersion, obj.Spec.ScannerImage = "", scanner
	require.NoError(t, other.Create(t.Context(), obj))
}

// --- Put and Get ---

func TestPackagesPutCreatesTheEvidence(t *testing.T) {
	store, c := newPackagesStore(t, interceptor.Funcs{})
	m := evidence(manifestAMD64)

	count, sum := packagesCollectors.sizes(t, clusterA)
	counts := packagesCollectors.counted(t, clusterA, func() {
		require.NoError(t, store.Put(t.Context(), scannerV1, scannedAt.Time, m))
	})

	require.Equal(t, writeCounts{Create: 1, Sizes: 1}, counts)
	got := storedPackages(t, c, manifestAMD64)
	require.Equal(t, inventory.NameForDigest(manifestAMD64), got.Name)
	require.Equal(t, manifestAMD64, got.Spec.ManifestDigest)
	require.Equal(t, linuxAMD64, got.Spec.Platform)
	require.Equal(t, scannerV1, got.Spec.ScannerImage)
	requireSameTime(t, scannedAt, got.Spec.ScannedTime)
	require.Equal(t, inventoryv1alpha1.EvidenceEncodingGzipJSON, got.Spec.Encoding)
	_, size, err := result.EncodeManifest(m)
	require.NoError(t, err)
	require.Equal(t, ptr.To(size), got.Spec.UncompressedBytes, "the size of the JSON before compression")
	decoded, err := result.DecodeManifest(got.Spec.Evidence, size)
	require.NoError(t, err)
	require.Equal(t, m, decoded, "the evidence is the gzip JSON of the manifest")

	// The sample is the size of the whole object as json.Marshal writes it, evidence included.
	raw, err := json.Marshal(got)
	require.NoError(t, err)
	newCount, newSum := packagesCollectors.sizes(t, clusterA)
	require.Equal(t, count+1, newCount)
	require.InDelta(t, float64(len(raw)), newSum-sum, 0, "the sample is the stored object")
}

func TestPackagesGetDecodesTheEvidence(t *testing.T) {
	store, c := newPackagesStore(t, interceptor.Funcs{})
	m := evidence(manifestAMD64)
	require.NoError(t, store.Put(t.Context(), scannerV1, scannedAt.Time, m))

	got, info, err := store.Get(t.Context(), manifestAMD64)

	require.NoError(t, err)
	require.Equal(t, &m, got)
	require.NotNil(t, info)
	require.True(t, scannedAt.Time.Equal(info.ScannedTime), "scanned at %s", info.ScannedTime)
	stored := storedPackages(t, c, manifestAMD64)
	require.Equal(t, inventory.PackagesInfo{
		Platform:          linuxAMD64,
		ScannerImage:      scannerV1,
		ScannedTime:       info.ScannedTime, // compared above, as an instant
		CompressedBytes:   int64(len(stored.Spec.Evidence)),
		UncompressedBytes: *stored.Spec.UncompressedBytes,
	}, *info)
}

func TestPackagesGetOfAnAbsentManifest(t *testing.T) {
	store, _ := newPackagesStore(t, interceptor.Funcs{})

	requireNoPackages(t, store, manifestAMD64)
}

// The evidence of a manifest is written once. A scanner image that has written it writes nothing
// again, whoever asks: a rescan, or the scan of another digest that shares the manifest.
func TestPackagesPutWritesTheEvidenceOnce(t *testing.T) {
	store, c := newPackagesStore(t, interceptor.Funcs{})
	require.NoError(t, store.Put(t.Context(), scannerV1, scannedAt.Time, evidence(manifestAMD64)))
	first := storedPackages(t, c, manifestAMD64)

	counts := packagesCollectors.counted(t, clusterA, func() {
		require.NoError(t, store.Put(t.Context(), scannerV1, scannedAt.Add(time.Hour), evidence(manifestAMD64)))
	})

	require.Equal(t, writeCounts{}, counts)
	again := storedPackages(t, c, manifestAMD64)
	require.Equal(t, first.ResourceVersion, again.ResourceVersion, "nothing was written")
	requireSameTime(t, scannedAt, again.Spec.ScannedTime)
}

// The spec of an ImagePackages can't change, so the evidence of a new scanner replaces the object:
// it is deleted, then created again.
func TestPackagesPutWithAnotherScannerReplacesTheEvidence(t *testing.T) {
	var preconditions []*metav1.Preconditions
	store, c := newPackagesStore(t, interceptor.Funcs{
		Delete: func(ctx context.Context, other client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			var options client.DeleteOptions
			options.ApplyOptions(opts)
			preconditions = append(preconditions, options.Preconditions)
			return other.Delete(ctx, obj, opts...)
		},
	})
	require.NoError(t, store.Put(t.Context(), scannerV1, scannedAt.Time, evidence(manifestAMD64)))
	read := storedPackages(t, c, manifestAMD64)

	newer := evidence(manifestAMD64)
	newer.ELF.Total = 4 // the new scanner finds an ELF file more
	counts := packagesCollectors.counted(t, clusterA, func() {
		require.NoError(t, store.Put(t.Context(), scannerV2, scannedAt.Add(time.Hour), newer))
	})

	require.Equal(t, writeCounts{Create: 1, Delete: 1, Sizes: 1}, counts)
	require.Equal(t, []*metav1.Preconditions{{ResourceVersion: ptr.To(read.ResourceVersion)}}, preconditions,
		"only the object that was read is deleted")
	got, info, err := store.Get(t.Context(), manifestAMD64)
	require.NoError(t, err)
	require.Equal(t, scannerV2, info.ScannerImage)
	require.Equal(t, &newer, got)
}

// Another writer replaced the evidence after this Put read it, with the evidence of the same newer
// scanner. The delete of the object that was read meets a conflict, and the next round finds the
// evidence that it wanted to write.
func TestPackagesPutLeavesEvidenceReplacedSinceItsRead(t *testing.T) {
	armed := false
	store, c := newPackagesStore(t, interceptor.Funcs{
		Delete: func(ctx context.Context, other client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			if armed {
				armed = false
				replaceWith(t, other, manifestAMD64, scannerV2)
				// The precondition names the object that was read, and the API server refuses it.
				return apierrors.NewConflict(schema.GroupResource{Group: inventoryv1alpha1.GroupVersion.Group,
					Resource: "imagepackages"}, obj.GetName(), errors.New("the object has been replaced"))
			}
			return other.Delete(ctx, obj, opts...)
		},
	})
	require.NoError(t, store.Put(t.Context(), scannerV1, scannedAt.Time, evidence(manifestAMD64)))

	armed = true
	counts := packagesCollectors.counted(t, clusterA, func() {
		require.NoError(t, store.Put(t.Context(), scannerV2, scannedAt.Add(time.Hour), evidence(manifestAMD64)))
	})

	require.False(t, armed, "the other writer acted")
	require.Equal(t, writeCounts{}, counts, "the other writer replaced it: this one wrote nothing")
	require.Equal(t, scannerV2, storedPackages(t, c, manifestAMD64).Spec.ScannerImage)
}

// Another writer created the evidence between this Put's delete and its create. The create meets
// the object, and the next round finds the evidence that it wanted to write.
func TestPackagesPutLeavesEvidenceCreatedSinceItsDelete(t *testing.T) {
	armed := false
	store, c := newPackagesStore(t, interceptor.Funcs{
		Create: func(ctx context.Context, other client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			if armed {
				armed = false
				created, ok := obj.DeepCopyObject().(*inventoryv1alpha1.ImagePackages)
				require.True(t, ok)
				require.NoError(t, other.Create(ctx, created))
			}
			return other.Create(ctx, obj, opts...)
		},
	})
	require.NoError(t, store.Put(t.Context(), scannerV1, scannedAt.Time, evidence(manifestAMD64)))

	armed = true
	counts := packagesCollectors.counted(t, clusterA, func() {
		require.NoError(t, store.Put(t.Context(), scannerV2, scannedAt.Add(time.Hour), evidence(manifestAMD64)))
	})

	require.False(t, armed, "the other writer acted")
	require.Equal(t, writeCounts{Delete: 1}, counts, "this one deleted the old evidence, and created nothing")
	require.Equal(t, scannerV2, storedPackages(t, c, manifestAMD64).Spec.ScannerImage)
}

// Evidence over the limit can't be stored, and Put writes nothing: it neither creates an object nor
// deletes the evidence of an older scanner.
func TestPackagesPutRefusesEvidenceOverTheLimit(t *testing.T) {
	store, c := newPackagesStore(t, interceptor.Funcs{})
	require.NoError(t, store.Put(t.Context(), scannerV1, scannedAt.Time, evidence(manifestAMD64)))
	first := storedPackages(t, c, manifestAMD64)

	counts := packagesCollectors.counted(t, clusterA, func() {
		err := store.Put(t.Context(), scannerV2, scannedAt.Time, incompressible(t, manifestAMD64))
		require.ErrorIs(t, err, inventory.ErrEvidenceTooLarge)

		err = store.Put(t.Context(), scannerV2, scannedAt.Time, incompressible(t, manifestARM64))
		require.ErrorIs(t, err, inventory.ErrEvidenceTooLarge)
	})

	require.Equal(t, writeCounts{}, counts)
	require.Equal(t, first.ResourceVersion, storedPackages(t, c, manifestAMD64).ResourceVersion,
		"the evidence of the older scanner stays")
	requireNoPackages(t, store, manifestARM64)
}

// Evidence that doesn't encode is refused before anything is written.
func TestPackagesPutRefusesEvidenceThatDoesNotEncode(t *testing.T) {
	store, _ := newPackagesStore(t, interceptor.Funcs{})
	m := evidence(manifestAMD64)
	m.SBOM = json.RawMessage(`{"artifacts":`) // cut off

	counts := packagesCollectors.counted(t, clusterA, func() {
		require.Error(t, store.Put(t.Context(), scannerV1, scannedAt.Time, m))
	})

	require.Equal(t, writeCounts{}, counts)
	requireNoPackages(t, store, manifestAMD64)
}

// Only the store writes an ImagePackages, but another writer can, past the schema. Get decodes only
// what it can trust, and never reads more than the object says it holds.
func TestPackagesGetRefusesEvidenceItCannotRead(t *testing.T) {
	for name, tc := range map[string]struct {
		change func(*inventoryv1alpha1.ImagePackagesSpec)
		// want is the error of the decoder. Without one, the store refuses the object before it
		// decodes anything.
		want error
	}{
		"an encoding that this version doesn't know": {
			change: func(s *inventoryv1alpha1.ImagePackagesSpec) { s.Encoding = "Zstd" },
		},
		"no size of the decoded evidence": {
			change: func(s *inventoryv1alpha1.ImagePackagesSpec) { s.UncompressedBytes = nil },
		},
		"a size of zero": {
			change: func(s *inventoryv1alpha1.ImagePackagesSpec) { s.UncompressedBytes = ptr.To[int64](0) },
		},
		"a negative size": {
			change: func(s *inventoryv1alpha1.ImagePackagesSpec) { s.UncompressedBytes = ptr.To[int64](-1) },
		},
		"evidence that decodes to more than its size": {
			change: func(s *inventoryv1alpha1.ImagePackagesSpec) { *s.UncompressedBytes-- },
			want:   result.ErrTooLarge,
		},
		"evidence that is not gzip": {
			change: func(s *inventoryv1alpha1.ImagePackagesSpec) { s.Evidence = []byte("evidence") },
			want:   result.ErrMalformed,
		},
	} {
		t.Run(name, func(t *testing.T) {
			store, c := newPackagesStore(t, interceptor.Funcs{})
			require.NoError(t, store.Put(t.Context(), scannerV1, scannedAt.Time, evidence(manifestAMD64)))
			obj := storedPackages(t, c, manifestAMD64)
			tc.change(&obj.Spec)
			require.NoError(t, c.Update(t.Context(), obj)) // the fake client knows no schema

			got, info, err := store.Get(t.Context(), manifestAMD64)

			require.Error(t, err)
			if tc.want != nil {
				require.ErrorIs(t, err, tc.want)
			} else {
				require.NotErrorIs(t, err, result.ErrTooLarge, "refused before decoding")
				require.NotErrorIs(t, err, result.ErrMalformed, "refused before decoding")
			}
			require.Nil(t, got)
			require.Nil(t, info)
		})
	}
}

func TestPackagesReadErrorsAreReturned(t *testing.T) {
	errRead := errors.New("read failed")
	store, _ := newPackagesStore(t, interceptor.Funcs{
		Get: func(context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption) error {
			return errRead
		},
		List: func(context.Context, client.WithWatch, client.ObjectList, ...client.ListOption) error {
			return errRead
		},
	})

	_, _, err := store.Get(t.Context(), manifestAMD64)
	require.ErrorIs(t, err, errRead, "a failed read is not an absent manifest")
	counts := packagesCollectors.counted(t, clusterA, func() {
		require.ErrorIs(t, store.Put(t.Context(), scannerV1, scannedAt.Time, evidence(manifestAMD64)), errRead)
	})
	require.Equal(t, writeCounts{}, counts, "nothing is written after a failed read")
	_, err = store.Digests(t.Context())
	require.ErrorIs(t, err, errRead)
}

// --- Delete ---

func TestPackagesDelete(t *testing.T) {
	store, _ := newPackagesStore(t, interceptor.Funcs{})
	require.NoError(t, store.Put(t.Context(), scannerV1, scannedAt.Time, evidence(manifestAMD64)))

	counts := packagesCollectors.counted(t, clusterA, func() {
		require.NoError(t, store.Delete(t.Context(), manifestAMD64))
		require.NoError(t, store.Delete(t.Context(), manifestAMD64), "an absent manifest is no error")
	})

	require.Equal(t, writeCounts{Delete: 1}, counts, "only the delete that removed an object counts")
	requireNoPackages(t, store, manifestAMD64)
}

// --- the reads across objects, and the watch: metadata only ---

// The digests are in the names, so Digests reads the metadata of the objects and never their
// evidence.
func TestPackagesDigestsReadMetadataOnly(t *testing.T) {
	var listed []schema.GroupVersionKind
	store, _ := newPackagesStore(t, interceptor.Funcs{
		List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			_, metadataOnly := list.(*metav1.PartialObjectMetadataList)
			require.True(t, metadataOnly, "the list holds metadata only, not %T", list)
			listed = append(listed, list.GetObjectKind().GroupVersionKind())
			return c.List(ctx, list, opts...)
		},
	})
	empty, err := store.Digests(t.Context())
	require.NoError(t, err)
	require.Empty(t, empty)
	require.NoError(t, store.Put(t.Context(), scannerV1, scannedAt.Time, evidence(manifestAMD64)))
	require.NoError(t, store.Put(t.Context(), scannerV1, scannedAt.Time, evidence(manifestARM64)))

	digests, err := store.Digests(t.Context())

	require.NoError(t, err)
	require.ElementsMatch(t, []string{manifestAMD64, manifestARM64}, digests)
	listKind := inventoryv1alpha1.GroupVersion.WithKind("ImagePackagesList")
	require.Equal(t, []schema.GroupVersionKind{listKind, listKind}, listed)
}

// oneInformer is the cache of a Source under test. It hands out one fake informer, through which
// the test plays the events of a watch, and records what the Source asked to watch. It has what a
// source.Kind uses, and any other call panics on the nil cache.Cache inside.
type oneInformer struct {
	cache.Cache
	informer *controllertest.FakeInformer
	watched  []client.Object
}

func (o *oneInformer) GetInformer(_ context.Context, obj client.Object, _ ...cache.InformerGetOption) (cache.Informer, error) {
	o.watched = append(o.watched, obj)
	return o.informer, nil
}

func (o *oneInformer) WaitForCacheSync(context.Context) bool { return true }

// metadataOf returns the metadata of the ImagePackages of a manifest, as a watch of metadata
// delivers it.
func metadataOf(manifestDigest string, uid types.UID) *metav1.PartialObjectMetadata {
	obj := &metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{Name: inventory.NameForDigest(manifestDigest), UID: uid}}
	obj.SetGroupVersionKind(packagesKind)
	return obj
}

// drain returns the requests in the queue, and marks them done.
func drain(queue workqueue.TypedRateLimitingInterface[reconcile.Request]) []reconcile.Request {
	var requests []reconcile.Request
	for queue.Len() > 0 {
		request, _ := queue.Get()
		queue.Done(request)
		requests = append(requests, request)
	}
	return requests
}

// The source watches metadata only, so the cache never holds evidence. It delivers one request for
// each object that is created or deleted. An object never changes, so an update is a resync or a
// change of metadata, unless the UID changed: then the object was replaced while the watch was
// down, and the update stands for a deletion and a creation.
func TestPackagesSourceWatchesMetadataAndEnqueuesCreatesAndDeletes(t *testing.T) {
	informers := &oneInformer{informer: controllertest.NewFakeInformer(controllertest.Synced)}
	store := inventory.NewCRDPackagesStore(newClient(t, interceptor.Funcs{}), informers, fixedCluster(clusterA))
	queue := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[reconcile.Request]())
	t.Cleanup(queue.ShutDown)

	src := store.Source()
	require.NoError(t, src.Start(t.Context(), queue))
	syncing, ok := src.(source.SyncingSource)
	require.True(t, ok, "a source of a cache can be waited for")
	require.NoError(t, syncing.WaitForSync(t.Context()))

	require.Len(t, informers.watched, 1)
	watched, ok := informers.watched[0].(*metav1.PartialObjectMetadata)
	require.True(t, ok, "the source watches metadata only, not %T", informers.watched[0])
	require.Equal(t, packagesKind, watched.GroupVersionKind())

	object := metadataOf(manifestAMD64, "uid-1")
	want := []reconcile.Request{{NamespacedName: types.NamespacedName{Name: inventory.NameForDigest(manifestAMD64)}}}

	informers.informer.Add(object)
	require.Equal(t, want, drain(queue), "a created object")

	labelled := object.DeepCopy()
	labelled.Labels = map[string]string{"team": "team-a"}
	informers.informer.Update(object, labelled)
	informers.informer.Update(labelled, labelled)
	require.Empty(t, drain(queue), "a change of metadata, and a resync")

	replaced := metadataOf(manifestAMD64, "uid-2")
	informers.informer.Update(labelled, replaced)
	require.Equal(t, want, drain(queue), "a replacement seen across a gap in the watch")

	informers.informer.Delete(replaced)
	require.Equal(t, want, drain(queue), "a deleted object")
}
