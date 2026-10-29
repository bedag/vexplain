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
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/inventory"
)

// These tests cover the reads across all objects: Digests and CountForCluster. The tests of the
// writes, in crdstore_test.go, use one object at a time.

const (
	// thirdDigest is a digest that the tests of the writes don't use.
	thirdDigest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

	// The clusters of the reads across objects: this one, local, and another one.
	localCluster = "local"
	localID      = "id-local"
	otherCluster = "other"
	otherID      = "id-other"
)

// inventoryOf is the ImageInventory of digest, with an entry for each cluster in clusters, given as
// name and ID.
func inventoryOf(digest string, clusters ...[2]string) *inventoryv1alpha1.ImageInventory {
	obj := &inventoryv1alpha1.ImageInventory{
		ObjectMeta: metav1.ObjectMeta{Name: inventory.NameForDigest(digest)},
		Spec:       inventoryv1alpha1.ImageInventorySpec{Digest: digest},
		Status:     inventoryv1alpha1.ImageInventoryStatus{DigestKind: ptr.To(inventoryv1alpha1.DigestKindRepoDigest)},
	}
	for _, cluster := range clusters {
		entry := presence(cluster[0], cluster[1], 1, 1, nil, repository)
		entry.FirstSeenTime = ptr.To(metav1.Now())
		obj.Status.Clusters = append(obj.Status.Clusters, entry)
	}
	return obj
}

// storeOf returns a CRD store over a fake client that holds objs. The funcs intercept the calls of
// the client. The store never watches, so it has no cache.
func storeOf(t *testing.T, funcs interceptor.Funcs, objs ...client.Object) inventory.Store {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, inventoryv1alpha1.AddToScheme(scheme))
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).WithInterceptorFuncs(funcs).Build()
	return inventory.NewCRDStore(c, nil)
}

func TestDigestsReturnsTheDigestOfEveryObject(t *testing.T) {
	store := storeOf(t, interceptor.Funcs{},
		inventoryOf(digest, [2]string{localCluster, localID}),
		inventoryOf(otherDigest, [2]string{otherCluster, otherID}),
		// An object without entries is an object of the store all the same.
		inventoryOf(thirdDigest),
	)

	digests, err := store.Digests(t.Context())

	require.NoError(t, err)
	require.ElementsMatch(t, []string{digest, otherDigest, thirdDigest}, digests)
}

func TestDigestsOfAnEmptyStore(t *testing.T) {
	digests, err := storeOf(t, interceptor.Funcs{}).Digests(t.Context())

	require.NoError(t, err)
	require.Empty(t, digests)
}

func TestCountForClusterCountsTheObjectsWithAnEntryOfTheCluster(t *testing.T) {
	store := storeOf(t, interceptor.Funcs{},
		inventoryOf(digest, [2]string{localCluster, localID}),
		inventoryOf(otherDigest, [2]string{localCluster, localID}, [2]string{otherCluster, otherID}),
		// An entry under a former name of the cluster counts by its ID.
		inventoryOf(thirdDigest, [2]string{"old-name", localID}),
	)

	for _, tc := range []struct {
		clusterID string
		want      int
	}{
		{clusterID: localID, want: 3},
		{clusterID: otherID, want: 1},
		{clusterID: "id-unknown", want: 0},
	} {
		got, err := store.CountForCluster(t.Context(), tc.clusterID)

		require.NoError(t, err)
		require.Equal(t, tc.want, got, "objects with an entry of %s", tc.clusterID)
	}
}

func TestListsReturnAFailedRead(t *testing.T) {
	failure := errors.New("the cache is gone")
	store := storeOf(t, interceptor.Funcs{
		List: func(context.Context, client.WithWatch, client.ObjectList, ...client.ListOption) error {
			return failure
		},
	}, inventoryOf(digest, [2]string{localCluster, localID}))

	_, err := store.Digests(t.Context())
	require.ErrorIs(t, err, failure)

	_, err = store.CountForCluster(t.Context(), localID)
	require.ErrorIs(t, err, failure, "a failed read is never mistaken for no objects")
}

func TestListsDontCopyTheObjects(t *testing.T) {
	var copied []bool
	store := storeOf(t, interceptor.Funcs{
		List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			var options client.ListOptions
			options.ApplyOptions(opts)
			copied = append(copied, !ptr.Deref(options.UnsafeDisableDeepCopy, false))
			return c.List(ctx, list, opts...)
		},
	}, inventoryOf(digest, [2]string{localCluster, localID}))

	_, err := store.Digests(t.Context())
	require.NoError(t, err)
	_, err = store.CountForCluster(t.Context(), localID)
	require.NoError(t, err)

	// The objects never leave the store, so a cache can hand out its own, uncopied.
	require.Equal(t, []bool{false, false}, copied)
}
