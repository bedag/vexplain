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
	"reflect"
	"regexp"
	"slices"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/source"

	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/metrics"
	"github.com/bedag/vexplain/sdk/workloads"
)

const (
	// maxWorkloads is the number of workloads an entry lists, maxRepositories the number of
	// repositories, and maxPlatforms the number of platforms. The schema allows no more (MaxItems), and
	// rejects a write that has more.
	maxWorkloads    = 100
	maxRepositories = 32
	maxPlatforms    = 8
	// maxPlatformLength is the most characters of a platform, as the schema allows.
	maxPlatformLength = 64
)

// platformPattern is the form of a platform that the schema takes: os/architecture, or
// os/architecture/variant.
var platformPattern = regexp.MustCompile(`^[a-z0-9]+/[a-z0-9_]+(/[a-z0-9]+)?$`)

// The values of the op label of the counters of writes, such as metrics.InventoryWritesTotal.
const (
	opCreate = "create"
	opUpdate = "update"
	opDelete = "delete"
)

// ManifestDigestIndex names the field index on ImageInventory objects whose keys are the manifest
// digests that their facts name. Register IndexManifestDigests under this name with the field
// indexer of the cache that a store reads from, before the cache starts, as setup.Register does. A
// store with informers lists through it in ManifestReferences.
const ManifestDigestIndex = "inventory.vexplain.bedag.ch/manifest-digests"

// IndexManifestDigests is the index function of ManifestDigestIndex. It returns the manifest
// digests that the facts of an ImageInventory name: one for each platform manifest of the image. It
// returns none for an object without facts, and for any other kind of object.
func IndexManifestDigests(obj client.Object) []string {
	inv, ok := obj.(*inventoryv1alpha1.ImageInventory)
	if !ok || inv.Status.Facts == nil {
		return nil
	}
	digests := make([]string, 0, len(inv.Status.Facts.Manifests))
	for _, manifest := range inv.Status.Facts.Manifests {
		digests = append(digests, manifest.Digest)
	}
	return digests
}

// crdStore keeps the ImageInventory objects as custom resources.
type crdStore struct {
	api client.Client
	// informers is the cache that Source watches through, or nil for a store that never watches.
	informers cache.Cache
	// cluster returns the name of this cluster, which labels the writes of SetFacts and UpdateFacts.
	cluster func() string
}

// The store reads an object, creates it, deletes it and writes its status. It never updates the
// object itself: the spec never changes, and the entries and the facts live in the status.
// +kubebuilder:rbac:groups=inventory.vexplain.bedag.ch,resources=imageinventories,verbs=get;create;delete
// +kubebuilder:rbac:groups=inventory.vexplain.bedag.ch,resources=imageinventories/status,verbs=update

// NewCRDStore returns a Store that keeps its objects in the ImageInventory API, through c.
//
// Reads go through c too. A client that reads from a cache can return an object that a write has
// already changed. A write based on it fails with a conflict, and the store then reads again and
// retries.
//
// Source watches through informers. Pass the manager's client and the manager's cache, so that the
// reads and the watch share the manager's one informer for ImageInventory objects. A caller that
// never watches, such as a test over a fake client or a test that only writes, passes nil: the
// other methods don't use it, and a Source started without a cache fails to start.
//
// With informers, ManifestReferences lists through the index ManifestDigestIndex, which the caller
// registers with the cache's field indexer before the cache starts. Without, it lists every object
// and picks those that name the manifest, which a client without a cache can serve.
//
// cluster returns the name of this cluster, the label of the metrics of the writes of SetFacts and
// UpdateFacts. The store reads it at each write, so that the label follows a rename. Observe and
// Forget label their writes with the cluster that they are given.
func NewCRDStore(c client.Client, informers cache.Cache, cluster func() string) Store {
	return &crdStore{api: c, informers: informers, cluster: cluster}
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
	// exists), is the sign of another writer. So is a status write that finds the object deleted
	// since the read, by the Forget of another cluster: the next round creates it again. None of
	// them is an error, as long as the next round works.
	return retry.OnError(retry.DefaultBackoff, isRacedOrDeleted, func() error {
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
		err = s.writeStatus(ctx, obj, cluster)
		if apierrors.IsNotFound(err) {
			// Another writer deleted the object since the read, and this cluster's entries with it.
			return nil
		}
		return err
	})
}

// SetFacts writes the facts alone, and leaves the entries and the digest kind as they are: those
// are Observe's and Forget's.
func (s *crdStore) SetFacts(ctx context.Context, digest string, facts *inventoryv1alpha1.ImageFacts) (bool, error) {
	return s.UpdateFacts(ctx, digest, func(*inventoryv1alpha1.ImageFacts) (*inventoryv1alpha1.ImageFacts, error) {
		return facts.DeepCopy(), nil
	})
}

// UpdateFacts writes the facts alone, as SetFacts does. Every round reads the object again, and hands
// update the facts as they are then.
func (s *crdStore) UpdateFacts(ctx context.Context, digest string,
	update func(*inventoryv1alpha1.ImageFacts) (*inventoryv1alpha1.ImageFacts, error)) (bool, error) {
	exists := false
	err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		obj, err := s.Get(ctx, digest)
		if err != nil {
			return err
		}
		exists = obj != nil
		if !exists {
			return nil
		}
		facts, err := update(obj.Status.Facts.DeepCopy())
		if err != nil {
			return err
		}
		stored := asStored(facts)
		if equality.Semantic.DeepEqual(obj.Status.Facts, stored) {
			return nil
		}
		obj.Status.Facts = stored
		err = s.writeStatus(ctx, obj, s.cluster())
		if apierrors.IsNotFound(err) {
			// The object was deleted since the read: the digest went away while its evidence was
			// collected. Facts never create an object, so they are dropped.
			exists = false
			return nil
		}
		return err
	})
	if err != nil {
		return false, err
	}
	return exists, nil
}

// The store lists the objects, and its Source watches them through an informer, which lists and
// watches.
// +kubebuilder:rbac:groups=inventory.vexplain.bedag.ch,resources=imageinventories,verbs=list;watch

func (s *crdStore) Digests(ctx context.Context) ([]string, error) {
	var list inventoryv1alpha1.ImageInventoryList
	// The objects are only read, and none leaves the store, so a cache needn't copy them.
	if err := s.api.List(ctx, &list, client.UnsafeDisableDeepCopy); err != nil {
		return nil, fmt.Errorf("list ImageInventory objects: %w", err)
	}
	digests := make([]string, 0, len(list.Items))
	for i := range list.Items {
		digests = append(digests, list.Items[i].Spec.Digest)
	}
	return digests, nil
}

func (s *crdStore) CountForCluster(ctx context.Context, clusterID string) (int, error) {
	var list inventoryv1alpha1.ImageInventoryList
	// The objects are only read, and none leaves the store, so a cache needn't copy them.
	if err := s.api.List(ctx, &list, client.UnsafeDisableDeepCopy); err != nil {
		return 0, fmt.Errorf("list ImageInventory objects: %w", err)
	}
	isThisCluster := func(entry inventoryv1alpha1.ClusterPresence) bool { return entry.ClusterID == clusterID }
	count := 0
	for i := range list.Items {
		if slices.ContainsFunc(list.Items[i].Status.Clusters, isThisCluster) {
			count++
		}
	}
	return count, nil
}

// ManifestReferences lists through the index when the store has informers: its client then reads
// from the manager's cache, which keeps the index. Without informers, the client may read from the
// API server, which knows no such index, so the store lists every object and picks those that name
// the manifest.
func (s *crdStore) ManifestReferences(ctx context.Context, manifestDigest string) ([]string, error) {
	var list inventoryv1alpha1.ImageInventoryList
	// The objects are only read, and none leaves the store, so a cache needn't copy them.
	opts := []client.ListOption{client.UnsafeDisableDeepCopy}
	if s.informers != nil {
		opts = append(opts, client.MatchingFields{ManifestDigestIndex: manifestDigest})
	}
	if err := s.api.List(ctx, &list, opts...); err != nil {
		return nil, fmt.Errorf("list the ImageInventory objects of manifest %q: %w", manifestDigest, err)
	}
	var digests []string
	for i := range list.Items {
		// After the index, every object names the manifest, and this keeps them all.
		if slices.Contains(IndexManifestDigests(&list.Items[i]), manifestDigest) {
			digests = append(digests, list.Items[i].Spec.Digest)
		}
	}
	return digests, nil
}

// The hub writes the summary of an object with a merge patch of its status.
// +kubebuilder:rbac:groups=inventory.vexplain.bedag.ch,resources=imageinventories/status,verbs=patch

// SetSummary writes the summary alone, with a JSON merge patch of status.summary (RFC 7386). The patch
// names no resourceVersion, so a write of an entry or of the facts since the caller read the object
// can't make it fail, and it names nothing but the summary, so it undoes no entry and no facts. The
// other writes of the store read the object and write its whole status with the resourceVersion that
// they read: one that meets the patch fails with a conflict, reads the object again, with the summary,
// and keeps it. A merge patch never creates an object, so the patch of an object that is gone meets
// NotFound, and writes nothing.
//
// The patch names every field of the summary, and sets each one that summary leaves out to null, which
// removes it: the summary replaces the stored one as a whole. The store doesn't read the object first,
// so it writes even a summary that is stored already; the caller compares, when it has read the object.
func (s *crdStore) SetSummary(ctx context.Context, digest string, summary inventoryv1alpha1.ImageSummary) (bool, error) {
	obj := &inventoryv1alpha1.ImageInventory{ObjectMeta: metav1.ObjectMeta{Name: NameForDigest(digest)}}
	patch, err := summaryPatch(summary)
	if err != nil {
		return false, fmt.Errorf("make the summary of ImageInventory %q: %w", obj.Name, err)
	}
	err = s.api.Status().Patch(ctx, obj, client.RawPatch(types.MergePatchType, patch))
	switch {
	case apierrors.IsNotFound(err):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("write the summary of ImageInventory %q: %w", obj.Name, err)
	}
	cluster := s.cluster()
	inventoryMetrics.countWrite(cluster, opUpdate)
	inventoryMetrics.measure(cluster, obj)
	return true, nil
}

// summaryFields lists the fields of a summary as JSON names them. Each is a number or a string, so a
// merge patch that names each of them replaces the summary as a whole.
var summaryFields = func() []string {
	summaryType := reflect.TypeFor[inventoryv1alpha1.ImageSummary]()
	names := make([]string, 0, summaryType.NumField())
	for field := range summaryType.Fields() {
		name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		names = append(names, name)
	}
	return names
}()

// summaryPatch returns the JSON merge patch that sets status.summary to summary, and nothing else: the
// fields that summary leaves out are null, so that the merge removes them.
func summaryPatch(summary inventoryv1alpha1.ImageSummary) ([]byte, error) {
	raw, err := json.Marshal(summary)
	if err != nil {
		return nil, err
	}
	fields := map[string]json.RawMessage{}
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}
	for _, name := range summaryFields {
		if _, ok := fields[name]; !ok {
			fields[name] = json.RawMessage("null")
		}
	}
	return json.Marshal(map[string]map[string]map[string]json.RawMessage{"status": {"summary": fields}})
}

// Source enqueues the name of an object for every event of it, as a controller's For does for its
// own kind, but for an update that changed the summary alone (changedBesidesTheSummary).
func (s *crdStore) Source() source.Source {
	return source.Kind[client.Object](s.informers, &inventoryv1alpha1.ImageInventory{}, &handler.EnqueueRequestForObject{},
		changedBesidesTheSummary())
}

// changedBesidesTheSummary passes every event but an update that changed the summary of an object and
// nothing else of it. Nothing that watches the objects reads the summary, and the hub writes it whenever
// what it reads changes: such an update would only have each controller that watches look at the image
// again for nothing, and the spoke's renderer render the reports of every workload that runs it again.
// An update that changes nothing, as a resync of the informer, still passes.
func changedBesidesTheSummary() predicate.Funcs {
	return predicate.Funcs{UpdateFunc: func(e event.UpdateEvent) bool {
		before, beforeOK := e.ObjectOld.(*inventoryv1alpha1.ImageInventory)
		after, afterOK := e.ObjectNew.(*inventoryv1alpha1.ImageInventory)
		if !beforeOK || !afterOK || equality.Semantic.DeepEqual(before.Status.Summary, after.Status.Summary) {
			return true
		}
		return !sameButTheSummary(before, after)
	}}
}

// sameButTheSummary reports whether two versions of an object differ in nothing but their summary,
// and what every write changes: the resourceVersion and the managed fields.
func sameButTheSummary(a, b *inventoryv1alpha1.ImageInventory) bool {
	// The copies are shallow: clearing a field of one leaves the object as it is.
	metaA, metaB := a.ObjectMeta, b.ObjectMeta
	metaA.ResourceVersion, metaB.ResourceVersion = "", ""
	metaA.ManagedFields, metaB.ManagedFields = nil, nil
	statusA, statusB := a.Status, b.Status
	statusA.Summary, statusB.Summary = nil, nil
	return equality.Semantic.DeepEqual(metaA, metaB) && equality.Semantic.DeepEqual(a.Spec, b.Spec) &&
		equality.Semantic.DeepEqual(statusA, statusB)
}

// isRaced says whether a failed write is worth another round of reading and merging: another writer
// changed the object since it was read, or created it since the read found none.
func isRaced(err error) bool {
	return apierrors.IsConflict(err) || apierrors.IsAlreadyExists(err)
}

// isRacedOrDeleted is isRaced for a write that creates its object when it finds none. There, a
// status write that finds the object deleted since the read is worth another round too, which
// creates the object again. The read of a round takes NotFound for no object, so a NotFound comes
// from a write.
func isRacedOrDeleted(err error) bool {
	return isRaced(err) || apierrors.IsNotFound(err)
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
	inventoryMetrics.countWrite(cluster, opCreate)
	inventoryMetrics.measure(cluster, obj)
	return obj, nil
}

// writeStatus writes the status of an object that was read, so the API server refuses it if the
// object has changed since.
func (s *crdStore) writeStatus(ctx context.Context, obj *inventoryv1alpha1.ImageInventory, cluster string) error {
	if err := s.api.Status().Update(ctx, obj); err != nil {
		return fmt.Errorf("write status of ImageInventory %q: %w", obj.Name, err)
	}
	inventoryMetrics.countWrite(cluster, opUpdate)
	inventoryMetrics.measure(cluster, obj)
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
	inventoryMetrics.countWrite(cluster, opDelete)
	return nil
}

// kindMetrics are the metrics of the writes to the objects of one kind: the writes by cluster and
// op, and the size of each object written, by cluster.
type kindMetrics struct {
	writes *prometheus.CounterVec
	sizes  *prometheus.HistogramVec
}

// inventoryMetrics are the metrics of the writes to ImageInventory objects.
var inventoryMetrics = kindMetrics{writes: metrics.InventoryWritesTotal, sizes: metrics.InventoryObjectBytes}

// countWrite counts a write that the API server accepted. A cluster whose name can't be read just
// now, "", gets no series, so its write is not counted.
func (m kindMetrics) countWrite(cluster, op string) {
	if cluster == "" {
		return
	}
	m.writes.WithLabelValues(cluster, op).Inc()
}

// measure records the size of an object that was just written: the length of the whole object as
// json.Marshal encodes it, which is close to what the storage holds for it. A cluster whose name
// can't be read just now, "", gets no series.
func (m kindMetrics) measure(cluster string, obj client.Object) {
	if cluster == "" {
		return
	}
	raw, err := json.Marshal(obj)
	if err != nil {
		return // A metric must not fail a write that went through.
	}
	m.sizes.WithLabelValues(cluster).Observe(float64(len(raw)))
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
		Platforms:      platformsOf(obs.Platforms),
		Exposure:       nonEmpty(obs.Exposure),
	}
}

// platformsOf returns the platforms that an entry lists: those of the observation that the schema
// takes, sorted, each once, and the first 8. A value from a node's label that is no platform is left
// out, so that it can't keep the entry from being written. None gives nil, which the entry leaves out.
func platformsOf(observed []string) []string {
	var platforms []string
	for _, platform := range observed {
		if len(platform) <= maxPlatformLength && platformPattern.MatchString(platform) {
			platforms = append(platforms, platform)
		}
	}
	slices.Sort(platforms)
	platforms = slices.Compact(platforms)
	return platforms[:min(len(platforms), maxPlatforms)]
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
// current status. It changes only what an observation owns. It drops the entries that belong to
// the observing cluster already, under its name or under a former one, adds the new entry, and
// sorts the entries by cluster. It records the digest kind when the observation knows it, and
// keeps the known one when it doesn't. The rest of the status, such as the facts of the scans,
// stays as it is.
func withEntry(current inventoryv1alpha1.ImageInventoryStatus, obs Observation,
	entry inventoryv1alpha1.ClusterPresence) inventoryv1alpha1.ImageInventoryStatus {
	status := current.DeepCopy()
	clusters := make([]inventoryv1alpha1.ClusterPresence, 0, len(status.Clusters)+1)
	var firstSeen *metav1.Time
	for _, existing := range status.Clusters {
		if !sameCluster(existing, obs.Cluster, obs.ClusterID) {
			clusters = append(clusters, existing)
			continue
		}
		if entry.Exposure == nil {
			entry.Exposure = existing.Exposure
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
	status.Clusters = clusters
	if kind := nonEmpty(obs.DigestKind); kind != nil {
		status.DigestKind = kind
	}
	return *status
}

// sameCluster says whether an entry belongs to the cluster with this name and ID: it has the name,
// or it has the ID, which stays the same when the cluster is renamed.
func sameCluster(entry inventoryv1alpha1.ClusterPresence, cluster, clusterID string) bool {
	return entry.Cluster == cluster || entry.ClusterID == clusterID
}

// asStored returns a copy of facts as the API server stores them: a metav1.Time keeps whole seconds
// only. Facts that differ from the stored ones in fractions of a second alone are the same facts,
// and are written as they will be read back.
func asStored(facts *inventoryv1alpha1.ImageFacts) *inventoryv1alpha1.ImageFacts {
	stored := facts.DeepCopy()
	if stored == nil {
		return nil
	}
	for i := range stored.Evidence {
		stored.Evidence[i].Time = toWholeSeconds(stored.Evidence[i].Time)
	}
	for i := range stored.Failures {
		stored.Failures[i].Time = toWholeSeconds(stored.Failures[i].Time)
	}
	return stored
}

// toWholeSeconds returns t without its fraction of a second.
func toWholeSeconds(t *metav1.Time) *metav1.Time {
	if t == nil {
		return nil
	}
	return ptr.To(t.Rfc3339Copy())
}

// nonEmpty returns a pointer to v, or nil when v is empty. The schema marks these fields optional,
// so a value that says nothing is left out, and is never written as an empty string.
func nonEmpty[T ~string](v T) *T {
	if v == "" {
		return nil
	}
	return &v
}
