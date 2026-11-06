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

// Package spoke is the spoke's side of the collectors: it takes what the streams of the collectors that take the
// spoke role deliver, keeps it in memory, and writes what the hub reads of it through the shared stores. Presence is
// what runs where. Hub and spoke meet only through those stores and the executor (decision 0021).
package spoke

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/go-logr/logr"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/sdk/evidence"
	"github.com/bedag/vexplain/sdk/subject"
	"github.com/bedag/vexplain/sdk/workloads"
)

// presenceSchema is the schema of the data of a presence event, which an event must follow to be read. It is the
// SDK's, which the SDK's own tests compile.
var presenceSchema = compileSchema(evidence.TypePresence)

// errNotPresence marks an event of another type than presence, which Presence leaves to other consumers.
var errNotPresence = errors.New("the event isn't presence")

// Presence implements collectorclient.Sink for the presence type. It writes presence entries
// through inventory.Store, and keeps the latest presence per image for the executor and the renderer.
//
// It keeps what each collector delivered, by image, in memory: presence stays on the spoke, and is never stored as
// evidence. An image that any collector names runs in the cluster, and its entry merges what every collector says
// of it. A controller writes the entries, so that a write that fails is tried again:
//   - A snapshot observes each image that it names, and forgets each that the collector named before and no
//     collector names now. An upsert observes its image, and a tombstone forgets it unless another collector names
//     it.
//   - Forget drops what a deleted collector delivered, and forgets the images that no other collector names.
//   - Until the first complete snapshot after a start, Presence knows nothing of what runs, and writes nothing. At
//     that snapshot, it forgets every entry of this cluster that no collector names: those went stale while the
//     operator was down. It tells which collectors' snapshots arrived since the start (HasSnapshotsOf), since it
//     knows what a collector says runs only from then.
//   - An entry holds the cluster's name and ID, the kind of the digest, its repositories, the number of namespaces
//     and of workloads that run it, the platforms of its pods, the first 100 workloads, sorted, as the store keeps
//     them, and the highest exposure of those workloads (Exposure.ForImage). The store writes nothing when the entry
//     is unchanged.
//   - The exposure of an image is written once every collector that streams exposure to the spoke has sent its first
//     snapshot since the start: those Exposure hasn't heard from would make a workload Unknown that is not. Until
//     then, an entry keeps the exposure that it had, and a new entry has none. With no such collector, Unknown is
//     written at once. A change of a workload's exposure, and the first snapshot of each collector, have the
//     controller look at the images that the workloads run.
//
// The controller also follows the ImageInventory objects, so that an object that someone deleted or changed gets
// its entry back.
type Presence struct {
	store     inventory.Store
	cluster   func(ctx context.Context) (name, id string, err error)
	exposure  *Exposure
	collector client.Reader
	log       logr.Logger

	mu sync.Mutex
	// delivered is what each collector delivered, by its name, then by the digest of the image.
	delivered map[string]map[string]evidence.Presence
	// complete is whether a complete snapshot arrived since the start, and completed is closed then. deferred
	// holds the images that the controller looked at before, which it looks at again then.
	complete  bool
	completed chan struct{}
	deferred  map[string]bool
	// changed is told of each image that presence changed, under the lock, and index is what runs, by workload,
	// until a change drops it.
	changed func(digest string)
	index   map[reportKey]*RunningWorkload
	// snapshotted holds the collectors whose snapshot arrived since the start, by name. arrived is closed,
	// and made anew, whenever the first snapshot of a collector arrives, so that a wait for one wakes.
	snapshotted map[string]bool
	arrived     chan struct{}
	// streaming is the set of collectors that streamed exposure to the spoke when a Collector last changed.
	streaming []string
	// queue is the controller's queue once it runs, and waiting holds the images to look at before.
	queue   workqueue.TypedRateLimitingInterface[reconcile.Request]
	waiting map[string]bool
}

// NewPresence returns the presence of the spoke, which writes the entries of this cluster through store. cluster
// gives the cluster's name and ID. exposure gives the exposure that each entry carries, and tells the presence when
// it changes. collectors reads the Collectors, to tell which collectors stream exposure to the spoke.
func NewPresence(store inventory.Store, cluster func(ctx context.Context) (name, id string, err error),
	exposure *Exposure, collectors client.Reader) *Presence {
	p := &Presence{
		store:       store,
		cluster:     cluster,
		exposure:    exposure,
		collector:   collectors,
		log:         ctrl.Log.WithName("spoke-presence"),
		delivered:   map[string]map[string]evidence.Presence{},
		completed:   make(chan struct{}),
		deferred:    map[string]bool{},
		snapshotted: map[string]bool{},
		arrived:     make(chan struct{}),
		waiting:     map[string]bool{},
	}
	exposure.watch(p.exposureChanged)
	return p
}

// exposureChanged looks again at the images that run a workload whose exposure changed, or at every image when all
// is set.
func (p *Presence) exposureChanged(changed map[workloadKey]bool, all bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	looked := map[string]bool{}
	for _, delivered := range p.delivered {
		for digest, presence := range delivered {
			if looked[digest] {
				continue
			}
			if all || slices.ContainsFunc(presence.Workloads, func(w evidence.PresenceWorkload) bool {
				return changed[keyOf(w)]
			}) {
				looked[digest] = true
				p.lookAt(digest)
			}
		}
	}
}

// collectorChanged looks again at every image when the collectors that stream exposure to the spoke are not the ones
// that they were: one is deleted, stops being usable or stops declaring exposure, or one begins. What an entry waited
// for has then changed, and nothing else would have it written. A change of a Collector that leaves the set as it is
// asks for nothing.
func (p *Presence) collectorChanged(ctx context.Context, _ client.Object) []reconcile.Request {
	var list configv1alpha1.CollectorList
	if err := p.collector.List(ctx, &list); err != nil {
		p.log.Error(err, "Could not list the Collectors to tell whether the collectors of exposure changed")
		return nil
	}
	set := slices.Sorted(slices.Values(streamingCollectors(&list, evidence.TypeExposure)))
	p.mu.Lock()
	defer p.mu.Unlock()
	if slices.Equal(set, p.streaming) {
		return nil
	}
	p.streaming = set
	var requests []reconcile.Request
	for _, digest := range p.imagesLocked() {
		requests = append(requests, requestFor(digest))
		p.touch(digest)
	}
	return requests
}

// exposureKnown reports whether every collector that streams exposure to the spoke has sent its first snapshot since
// the start, which is also so when there is none.
func (p *Presence) exposureKnown(ctx context.Context) (bool, error) {
	var list configv1alpha1.CollectorList
	if err := p.collector.List(ctx, &list); err != nil {
		return false, fmt.Errorf("list the Collectors to tell which stream exposure: %w", err)
	}
	return p.exposure.HasSnapshotsOf(streamingCollectors(&list, evidence.TypeExposure)), nil
}

// Snapshot replaces what the collector delivered with the presence of its snapshot. An event that can't be read is
// dropped: its image is missing from the snapshot.
func (p *Presence) Snapshot(collector string, events []cloudevents.Event) {
	images := map[string]evidence.Presence{}
	for _, e := range events {
		digest, presence, err := parse(e)
		if err != nil {
			p.drop(collector, err)
			continue
		}
		if len(presence.Workloads) > 0 {
			images[digest] = presence
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for digest := range p.delivered[collector] {
		p.lookAt(digest)
	}
	for digest := range images {
		p.lookAt(digest)
	}
	if len(images) == 0 {
		delete(p.delivered, collector)
	} else {
		p.delivered[collector] = images
	}
	if !p.snapshotted[collector] {
		p.snapshotted[collector] = true
		close(p.arrived)
		p.arrived = make(chan struct{})
	}
	if !p.complete {
		p.complete = true
		close(p.completed)
		for digest := range p.deferred {
			p.lookAt(digest)
		}
		clear(p.deferred)
	}
}

// Upsert takes the presence of an image after the snapshot. Presence that names no workload says that the image runs
// nowhere, as a tombstone does.
func (p *Presence) Upsert(collector string, e cloudevents.Event) {
	digest, presence, err := parse(e)
	if err != nil {
		p.drop(collector, err)
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(presence.Workloads) == 0 {
		p.removeLocked(collector, digest)
		return
	}
	if p.delivered[collector] == nil {
		p.delivered[collector] = map[string]evidence.Presence{}
	}
	p.delivered[collector][digest] = presence
	p.lookAt(digest)
}

// Remove takes a tombstone: the collector's presence of an image is gone.
func (p *Presence) Remove(collector, eventType, about string) {
	if eventType != evidence.TypePresence {
		return
	}
	parsed, err := subject.Parse(about)
	if err != nil || parsed.Kind != subject.KindImage {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.removeLocked(collector, parsed.Digest)
}

// SourceChanged does nothing: presence comes from the collectors' streams, and no operation of a collector makes it.
func (p *Presence) SourceChanged(string, []string) {}

// Forget drops what the collector delivered, because its Collector is gone, or it no longer delivers presence. Each
// image that it named is looked at again, and forgotten unless another collector names it. A collector of the name that
// delivers presence again starts with a snapshot of its own.
func (p *Presence) Forget(collector string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for digest := range p.delivered[collector] {
		p.lookAt(digest)
	}
	delete(p.delivered, collector)
	delete(p.snapshotted, collector)
}

// HasSnapshotsOf reports whether a snapshot of each of the collectors, by name, arrived since the start, so that
// Presence knows what each says runs. When one hasn't, it also returns a channel that is closed once the first
// snapshot of a collector arrives, after which the caller asks again.
func (p *Presence) HasSnapshotsOf(collectors []string) (bool, <-chan struct{}) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, collector := range collectors {
		if !p.snapshotted[collector] {
			return false, p.arrived
		}
	}
	return true, nil
}

// removeLocked drops the collector's presence of an image, and looks at the image again. The caller holds the lock.
func (p *Presence) removeLocked(collector, digest string) {
	images := p.delivered[collector]
	if _, ok := images[digest]; !ok {
		return
	}
	delete(images, digest)
	if len(images) == 0 {
		delete(p.delivered, collector)
	}
	p.lookAt(digest)
}

// lookAt has the controller look at an image, or keeps it for the controller until its queue exists. The caller
// holds the lock.
func (p *Presence) lookAt(digest string) {
	p.touch(digest)
	if p.queue == nil {
		p.waiting[digest] = true
		return
	}
	p.queue.Add(requestFor(digest))
}

// touch drops what runs, which an image's change makes stale, and tells the function that watches. The caller holds the
// lock, which the function must not take.
func (p *Presence) touch(digest string) {
	p.index = nil
	if p.changed != nil {
		p.changed(digest)
	}
}

// Complete reports whether the first complete snapshot since the start arrived, so that Presence knows what runs. When
// it hasn't, it also returns a channel that is closed once it does.
func (p *Presence) Complete() (bool, <-chan struct{}) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.complete {
		return true, nil
	}
	return false, p.completed
}

// drop logs an event that Presence can't read, unless it is of another type, which another consumer reads. The
// reason repeats nothing of the event, which the collector chose.
func (p *Presence) drop(collector string, err error) {
	if !errors.Is(err, errNotPresence) {
		p.log.Error(err, "Dropped a presence event that can't be read", "collector", collector)
	}
}

// parse reads a presence event: the digest of the image that it is about, and what runs it. Its data must follow the
// schema of presence, so that what reaches an entry is what the API takes.
func parse(e cloudevents.Event) (string, evidence.Presence, error) {
	if e.Type() != evidence.TypePresence {
		return "", evidence.Presence{}, errNotPresence
	}
	about, err := subject.Parse(e.Subject())
	if err != nil || about.Kind != subject.KindImage {
		return "", evidence.Presence{}, errors.New("its subject is no image")
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(e.Data()))
	if err != nil {
		return "", evidence.Presence{}, errors.New("its data isn't JSON")
	}
	if err := presenceSchema.Validate(doc); err != nil {
		return "", evidence.Presence{}, errors.New("its data doesn't follow the schema of presence")
	}
	var presence evidence.Presence
	if err := json.Unmarshal(e.Data(), &presence); err != nil {
		return "", evidence.Presence{}, errors.New("its data can't be read as presence")
	}
	return about.Digest, presence, nil
}

// Workloads returns the workloads that run the image of a digest, as the collectors report them, each once, sorted
// by namespace, kind, name, API group and UID. Where two collectors report the same workload, the one whose name
// sorts first says what it is. The caller may change what it gets.
func (p *Presence) Workloads(image string) []evidence.PresenceWorkload {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.workloadsLocked(image)
}

// workloadsLocked is Workloads for a caller that holds the lock.
func (p *Presence) workloadsLocked(image string) []evidence.PresenceWorkload {
	var found []evidence.PresenceWorkload
	seen := map[workloads.WorkloadRef]bool{}
	for _, collector := range slices.Sorted(maps.Keys(p.delivered)) {
		for _, w := range p.delivered[collector][image].Workloads {
			if ref := refOf(w); !seen[ref] {
				seen[ref] = true
				found = append(found, cloneWorkload(w))
			}
		}
	}
	slices.SortFunc(found, func(a, b evidence.PresenceWorkload) int {
		return cmp.Or(cmp.Compare(a.Namespace, b.Namespace), cmp.Compare(a.Kind, b.Kind), cmp.Compare(a.Name, b.Name),
			cmp.Compare(a.APIGroup, b.APIGroup), cmp.Compare(a.UID, b.UID))
	})
	return found
}

// RunningWorkload is a workload that runs images, as the collectors report it, and the images with the platforms of its
// pods. Where several collectors report it, the one whose name sorts first says what it is.
type RunningWorkload struct {
	Workload evidence.PresenceWorkload
	Images   []RunningImage
}

// reportKey names the report of a workload: its namespace and the report's name.
type reportKey struct{ namespace, name string }

// Running returns the workload whose report has the name in the namespace, with its images, or false when no workload
// of that report runs. The caller may change what it gets.
func (p *Presence) Running(namespace, report string) (RunningWorkload, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	running, ok := p.runningLocked()[reportKey{namespace, report}]
	if !ok {
		return RunningWorkload{}, false
	}
	out := RunningWorkload{Workload: cloneWorkload(running.Workload)}
	for _, image := range running.Images {
		out.Images = append(out.Images, RunningImage{Digest: image.Digest, Platforms: slices.Clone(image.Platforms)})
	}
	return out, true
}

// RunningReports returns the namespace and name of the report of each workload that runs, sorted.
func (p *Presence) RunningReports() []types.NamespacedName {
	p.mu.Lock()
	defer p.mu.Unlock()
	running := p.runningLocked()
	names := make([]types.NamespacedName, 0, len(running))
	for key := range running {
		names = append(names, types.NamespacedName{Namespace: key.namespace, Name: key.name})
	}
	slices.SortFunc(names, func(a, b types.NamespacedName) int {
		return cmp.Or(cmp.Compare(a.Namespace, b.Namespace), cmp.Compare(a.Name, b.Name))
	})
	return names
}

// runningLocked returns the workloads that run, by their reports. It builds them anew after a change, and keeps them
// until the next. A workload is the one that Workloads names first for the report: the report is named after the kind
// and the name, so another API group or UID with them has no report of its own. The caller holds the lock.
func (p *Presence) runningLocked() map[reportKey]*RunningWorkload {
	if p.index != nil {
		return p.index
	}
	index := map[reportKey]*RunningWorkload{}
	platforms := map[reportKey]map[string]map[string]bool{}
	for _, digest := range p.imagesLocked() {
		for _, w := range p.workloadsLocked(digest) {
			key := reportKey{w.Namespace, ReportName(w)}
			running, ok := index[key]
			if !ok {
				running = &RunningWorkload{Workload: w}
				index[key] = running
				platforms[key] = map[string]map[string]bool{}
			} else if refOf(running.Workload) != refOf(w) {
				continue
			}
			if platforms[key][digest] == nil {
				platforms[key][digest] = map[string]bool{}
				running.Images = append(running.Images, RunningImage{Digest: digest})
			}
			for _, pod := range w.Pods {
				if pod.Platform != "" {
					platforms[key][digest][pod.Platform] = true
				}
			}
		}
	}
	for key, running := range index {
		for i := range running.Images {
			running.Images[i].Platforms = slices.Sorted(maps.Keys(platforms[key][running.Images[i].Digest]))
		}
	}
	p.index = index
	return index
}

// Images returns the digests of the images that any collector says run, sorted.
func (p *Presence) Images() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.imagesLocked()
}

// imagesLocked is Images for a caller that holds the lock.
func (p *Presence) imagesLocked() []string {
	images := map[string]bool{}
	for _, delivered := range p.delivered {
		for digest := range delivered {
			images[digest] = true
		}
	}
	return slices.Sorted(maps.Keys(images))
}

// refOf names a workload of presence.
func refOf(w evidence.PresenceWorkload) workloads.WorkloadRef {
	return workloads.WorkloadRef{APIGroup: w.APIGroup, Kind: w.Kind, Namespace: w.Namespace, Name: w.Name,
		UID: types.UID(w.UID)}
}

// cloneWorkload returns a copy of a workload that shares no slice with it.
func cloneWorkload(w evidence.PresenceWorkload) evidence.PresenceWorkload {
	w.Pods = slices.Clone(w.Pods)
	w.Labels = slices.Clone(w.Labels)
	w.NamespaceLabels = slices.Clone(w.NamespaceLabels)
	w.NamespaceAnnotations = slices.Clone(w.NamespaceAnnotations)
	return w
}

// The controller writes the entries of this cluster through the store, and needs no right of its own.

// SetupWithManager sets up the controller that writes the entries, under the name of each digest's ImageInventory.
// It looks at an image whenever presence changes it, and whenever its object changes, and at every image when the
// collectors that stream exposure change.
func (p *Presence) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("spoke-presence").
		WatchesRawSource(p.store.Source()).
		Watches(&configv1alpha1.Collector{}, handler.EnqueueRequestsFromMapFunc(p.collectorChanged)).
		WatchesRawSource(source.Func(func(_ context.Context,
			queue workqueue.TypedRateLimitingInterface[reconcile.Request]) error {
			p.mu.Lock()
			defer p.mu.Unlock()
			p.queue = queue
			for digest := range p.waiting {
				queue.Add(requestFor(digest))
			}
			clear(p.waiting)
			return nil
		})).
		Complete(p)
}

// Reconcile writes the entry of this cluster for the digest of the request, from what the collectors say of it, or
// forgets it when none names it. The entry carries the image's exposure once exposureKnown. Until the first complete snapshot, it writes nothing, and looks at the image again
// then. A name that isn't the name of a digest is ignored.
func (p *Presence) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	digest, ok := inventory.DigestForName(req.Name)
	if !ok {
		return ctrl.Result{}, nil
	}
	observation, runs, known := p.observation(digest)
	if !known {
		return ctrl.Result{}, nil
	}
	name, id, err := p.cluster(ctx)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("read the cluster's name and ID: %w", err)
	}
	if !runs {
		return ctrl.Result{}, p.forget(ctx, digest, name, id)
	}
	observation.Cluster, observation.ClusterID = name, id
	known, err = p.exposureKnown(ctx)
	if err != nil {
		return ctrl.Result{}, err
	}
	if known {
		observation.Exposure = inventoryv1alpha1.SSVCExposure(p.exposure.ForImage(p.Workloads(digest)))
	}
	return ctrl.Result{}, p.store.Observe(ctx, digest, observation)
}

// forget removes this cluster's entry for digest, under its name or a former one, by its ID. An object without an
// entry of this cluster is another cluster's, and is left alone, also when it holds no entry yet: another cluster's
// Observe creates the object before it writes its entry, and Forget deletes an object that holds none.
func (p *Presence) forget(ctx context.Context, digest, name, id string) error {
	obj, err := p.store.Get(ctx, digest)
	if err != nil || obj == nil {
		return err
	}
	if !slices.ContainsFunc(obj.Status.Clusters, func(entry inventoryv1alpha1.ClusterPresence) bool {
		return entry.Cluster == name || entry.ClusterID == id
	}) {
		return nil
	}
	return p.store.Forget(ctx, digest, name, id)
}

// observation returns what every collector's presence says of the image of digest, without the cluster's name and
// ID, and whether any of them says that it runs. known is false until the first complete snapshot: Presence knows
// nothing of what runs then, and keeps the image to look at again once it does.
func (p *Presence) observation(digest string) (observation inventory.Observation, runs, known bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.complete {
		p.deferred[digest] = true
		return inventory.Observation{}, false, false
	}
	observation.DigestKind = inventoryv1alpha1.DigestKindImageID
	repositories, platforms, namespaces := map[string]bool{}, map[string]bool{}, map[string]bool{}
	seen := map[workloads.WorkloadRef]bool{}
	for _, delivered := range p.delivered {
		presence, ok := delivered[digest]
		if !ok {
			continue
		}
		if presence.DigestKind == string(inventoryv1alpha1.DigestKindRepoDigest) {
			observation.DigestKind = inventoryv1alpha1.DigestKindRepoDigest
		}
		for _, repository := range presence.Repositories {
			repositories[repository] = true
		}
		for _, w := range presence.Workloads {
			if ref := refOf(w); !seen[ref] {
				seen[ref] = true
				observation.Workloads = append(observation.Workloads, ref)
			}
			namespaces[w.Namespace] = true
			for _, pod := range w.Pods {
				if pod.Platform != "" {
					platforms[pod.Platform] = true
				}
			}
		}
	}
	// The store sorts the workloads and keeps the first 100, and keeps the platforms that the API takes, each once,
	// the first 8.
	observation.Repositories = slices.Sorted(maps.Keys(repositories))
	observation.Platforms = slices.Sorted(maps.Keys(platforms))
	observation.NamespaceCount = int32(len(namespaces))
	return observation, len(observation.Workloads) > 0, true
}

// requestFor returns the request of a digest, named after its ImageInventory.
func requestFor(digest string) reconcile.Request {
	return reconcile.Request{NamespacedName: types.NamespacedName{Name: inventory.NameForDigest(digest)}}
}
