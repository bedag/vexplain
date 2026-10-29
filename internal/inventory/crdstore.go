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

package inventory

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"slices"

	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/metrics"
	"github.com/bedag/vexplain/internal/workloads"
)

const (
	// maxWorkloads is the number of workloads an entry lists, and maxRepositories the number of
	// repositories. The schema allows no more (MaxItems), and rejects a write that has more.
	maxWorkloads    = 100
	maxRepositories = 32
)

// The values of the op label of metrics.InventoryWritesTotal.
const (
	opCreate = "create"
	opUpdate = "update"
	opDelete = "delete"
)

// crdStore keeps the ImageInventory objects as custom resources.
type crdStore struct {
	api client.Client
}

// NewCRDStore returns a Store that keeps its objects in the ImageInventory API, through c.
//
// Reads go through c too. A client that reads from a cache can return an object that a write has
// already changed. A write based on it fails with a conflict, and the store then reads again and
// retries.
func NewCRDStore(c client.Client) Store {
	return &crdStore{api: c}
}

func (s *crdStore) Get(ctx context.Context, digest string) (*inventoryv1alpha1.ImageInventory, error) {
	name := NameForDigest(digest)
	obj := &inventoryv1alpha1.ImageInventory{}
	if err := s.api.Get(ctx, client.ObjectKey{Name: name}, obj); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		// A failed read is never mistaken for an absent object.
		return nil, fmt.Errorf("read ImageInventory %q: %w", name, err)
	}
	return obj, nil
}

func (s *crdStore) Observe(ctx context.Context, digest string, obs Observation) error {
	entry := presenceOf(obs)
	// Every round reads the object again, so it merges into what is there now. A write that finds
	// the object changed (a conflict), or a create that finds it made meanwhile (it already
	// exists), is the sign of another writer. Neither is an error, as long as the next round works.
	return retry.OnError(retry.DefaultBackoff, isRaced, func() error {
		obj, err := s.Get(ctx, digest)
		if err != nil {
			return err
		}
		if obj == nil {
			if obj, err = s.create(ctx, digest, obs.Cluster); err != nil {
				return err
			}
		}
		status := withEntry(obj.Status, obs, entry)
		if equality.Semantic.DeepEqual(obj.Status, status) {
			return nil
		}
		obj.Status = status
		return s.writeStatus(ctx, obj, obs.Cluster)
	})
}

func (s *crdStore) Forget(ctx context.Context, digest, cluster, clusterID string) error {
	return retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		obj, err := s.Get(ctx, digest)
		if err != nil || obj == nil {
			return err
		}
		belongsToCluster := func(entry inventoryv1alpha1.ClusterPresence) bool {
			return sameCluster(entry, cluster, clusterID)
		}
		remaining := slices.DeleteFunc(slices.Clone(obj.Status.Clusters), belongsToCluster)
		switch {
		case len(remaining) == 0:
			return s.delete(ctx, obj, cluster)
		case len(remaining) == len(obj.Status.Clusters):
			return nil // None of the entries is this cluster's.
		}
		obj.Status.Clusters = remaining
		return s.writeStatus(ctx, obj, cluster)
	})
}

// isRaced says whether a failed write is worth another round of reading and merging: another writer
// changed the object since it was read, or created it since the read found none.
func isRaced(err error) bool {
	return apierrors.IsConflict(err) || apierrors.IsAlreadyExists(err)
}

// create makes the object of a digest with its spec and no status. The status is a subresource,
// so the API server would ignore one here: the caller writes it in a second call.
func (s *crdStore) create(ctx context.Context, digest, cluster string) (*inventoryv1alpha1.ImageInventory, error) {
	obj := &inventoryv1alpha1.ImageInventory{
		ObjectMeta: metav1.ObjectMeta{Name: NameForDigest(digest)},
		Spec:       inventoryv1alpha1.ImageInventorySpec{Digest: digest},
	}
	if err := s.api.Create(ctx, obj); err != nil {
		return nil, fmt.Errorf("create ImageInventory %q: %w", obj.Name, err)
	}
	countWrite(cluster, opCreate)
	measure(cluster, obj)
	return obj, nil
}

// writeStatus writes the status of an object that was read, so the API server refuses it if the
// object has changed since.
func (s *crdStore) writeStatus(ctx context.Context, obj *inventoryv1alpha1.ImageInventory, cluster string) error {
	if err := s.api.Status().Update(ctx, obj); err != nil {
		return fmt.Errorf("write status of ImageInventory %q: %w", obj.Name, err)
	}
	countWrite(cluster, opUpdate)
	measure(cluster, obj)
	return nil
}

// delete removes an object that was read, but only if it is still the object that was read.
// Without that precondition, an entry that another writer added since the read would be deleted
// with the object. An object that is already gone is what the caller wants, so it is no error.
func (s *crdStore) delete(ctx context.Context, obj *inventoryv1alpha1.ImageInventory, cluster string) error {
	err := s.api.Delete(ctx, obj, client.Preconditions{ResourceVersion: ptr.To(obj.ResourceVersion)})
	switch {
	case apierrors.IsNotFound(err):
		return nil
	case err != nil:
		return fmt.Errorf("delete ImageInventory %q: %w", obj.Name, err)
	}
	countWrite(cluster, opDelete)
	return nil
}

// countWrite counts a write that the API server accepted.
func countWrite(cluster, op string) {
	metrics.InventoryWritesTotal.WithLabelValues(cluster, op).Inc()
}

// measure records the size of an object that was just written: the length of the whole object as
// json.Marshal encodes it, which is close to what the storage holds for it.
func measure(cluster string, obj client.Object) {
	raw, err := json.Marshal(obj)
	if err != nil {
		return // A metric must not fail a write that went through.
	}
	metrics.InventoryObjectBytes.WithLabelValues(cluster).Observe(float64(len(raw)))
}

// presenceOf returns the entry that an observation describes, but for the time the digest was first
// seen. The entry holds what the schema allows and in an order that doesn't depend on the order of
// the input, so that the same facts always give the same entry, and an unchanged entry isn't
// written again.
func presenceOf(obs Observation) inventoryv1alpha1.ClusterPresence {
	// The workloads are sorted, which makes the cut at 100 deterministic, and deduplicated before
	// they are counted and cut. The sort is total, so every order of the same input gives the same
	// result.
	distinct := slices.Clone(obs.Workloads)
	slices.SortFunc(distinct, compareWorkloads)
	distinct = slices.Compact(distinct)

	// The schema keys the list by namespace, kind and name, and rejects a list in which two entries
	// share a key. Workloads of different API groups can share one, such as the StatefulSets of
	// two controllers. The list keeps the first of them, the one whose API group sorts first. The
	// count still counts every workload, and a list shorter than the count is cut anyway.
	listed := slices.CompactFunc(slices.Clone(distinct), func(a, b workloads.WorkloadRef) bool {
		return a.Namespace == b.Namespace && a.Kind == b.Kind && a.Name == b.Name
	})
	listed = listed[:min(len(listed), maxWorkloads)]
	references := make([]inventoryv1alpha1.WorkloadReference, 0, len(listed))
	for _, workload := range listed {
		references = append(references, inventoryv1alpha1.WorkloadReference{
			APIGroup:  nonEmpty(workload.APIGroup),
			Kind:      workload.Kind,
			Namespace: workload.Namespace,
			Name:      workload.Name,
		})
	}

	repositories := slices.Clone(obs.Repositories)
	slices.Sort(repositories)
	repositories = slices.Compact(repositories)
	repositories = repositories[:min(len(repositories), maxRepositories)]

	return inventoryv1alpha1.ClusterPresence{
		Cluster:        obs.Cluster,
		ClusterID:      obs.ClusterID,
		NamespaceCount: ptr.To(obs.NamespaceCount),
		WorkloadCount:  ptr.To(int32(len(distinct))),
		Workloads:      references,
		Repositories:   repositories,
	}
}

// compareWorkloads orders workloads by namespace, kind and name, and then by API group, which
// makes the order total.
func compareWorkloads(a, b workloads.WorkloadRef) int {
	return cmp.Or(
		cmp.Compare(a.Namespace, b.Namespace),
		cmp.Compare(a.Kind, b.Kind),
		cmp.Compare(a.Name, b.Name),
		cmp.Compare(a.APIGroup, b.APIGroup),
	)
}

// withEntry returns the status that results from setting the entry of the observing cluster in the
// current status. It drops the entries that belong to that cluster already, under its name or under
// a former one, and it sorts the entries by cluster.
func withEntry(current inventoryv1alpha1.ImageInventoryStatus, obs Observation,
	entry inventoryv1alpha1.ClusterPresence) inventoryv1alpha1.ImageInventoryStatus {
	clusters := make([]inventoryv1alpha1.ClusterPresence, 0, len(current.Clusters)+1)
	var firstSeen *metav1.Time
	for _, existing := range current.Clusters {
		if !sameCluster(existing, obs.Cluster, obs.ClusterID) {
			clusters = append(clusters, existing)
			continue
		}
		// A renamed cluster is the same cluster. It was first seen when the oldest of its entries
		// says, whatever its name was then.
		if t := existing.FirstSeenTime; t != nil && (firstSeen == nil || t.Before(firstSeen)) {
			firstSeen = t
		}
	}
	if firstSeen == nil {
		firstSeen = ptr.To(metav1.Now())
	}
	entry.FirstSeenTime = firstSeen
	clusters = append(clusters, entry)
	slices.SortFunc(clusters, func(a, b inventoryv1alpha1.ClusterPresence) int {
		return cmp.Compare(a.Cluster, b.Cluster)
	})
	return inventoryv1alpha1.ImageInventoryStatus{DigestKind: nonEmpty(obs.DigestKind), Clusters: clusters}
}

// sameCluster says whether an entry belongs to the cluster with this name and ID: it has the name,
// or it has the ID, which stays the same when the cluster is renamed.
func sameCluster(entry inventoryv1alpha1.ClusterPresence, cluster, clusterID string) bool {
	return entry.Cluster == cluster || entry.ClusterID == clusterID
}

// nonEmpty returns a pointer to v, or nil when v is empty. The schema marks these fields optional,
// so a value that says nothing is left out, and is never written as an empty string.
func nonEmpty[T ~string](v T) *T {
	if v == "" {
		return nil
	}
	return &v
}
