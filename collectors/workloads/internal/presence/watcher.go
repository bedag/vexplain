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

// Package presence is the workloads collector: it reports which workloads run which image digests in its cluster,
// as vexplain's presence evidence, one event per digest. It applies what vexplain's context gives each Watch: the
// scope, the allowlists of owner attribution, and the label of vexplain's own pods, which counts only in vexplain's
// namespace. The design of collectors, evidence and rules gives the reasons, in
// docs/design/2026-10-31-collectors-evidence-rules.md, sections 5.4, 5.5 and 5.12.
package presence

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	toolscache "k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/bedag/vexplain/sdk/collector"
	"github.com/bedag/vexplain/sdk/evidence"
	"github.com/bedag/vexplain/sdk/subject"
)

const (
	// collectorName is the name that GetInfo reports.
	collectorName = "workloads"
	// defaultSettle is how long a Watch waits after a change for more, when Options don't say: the changes of a
	// rollout come in bursts, and one build serves a burst.
	defaultSettle = time.Second
)

// settingsSchema is the schema of the collector's settings: it has none. What it reports follows vexplain's context
// alone.
const settingsSchema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "description": "The workloads collector has no settings: what it reports follows the scope and the allowlists of owner attribution of vexplain's context.",
  "type": "object",
  "additionalProperties": false
}`

// permissions are what the collector reads in the whole cluster: the pods, their namespaces and nodes, and the
// ReplicaSets and Jobs that workloads.ResolveOwner looks through, which it reads as metadata. It needs no right on
// any other kind of workload, and writes nothing.
var permissions = []collector.Permission{
	{APIGroups: []string{corev1.GroupName}, Resources: []string{"pods", "namespaces", "nodes"}, Verbs: listAndWatch},
	{APIGroups: []string{appsv1.GroupName}, Resources: []string{"replicasets"}, Verbs: listAndWatch},
	{APIGroups: []string{batchv1.GroupName}, Resources: []string{"jobs"}, Verbs: listAndWatch},
}

// listAndWatch are the verbs that an informer needs: it lists, and then watches.
var listAndWatch = []string{"list", "watch"}

// Options configure a Watcher.
type Options struct {
	// Name is the name of the collector's Collector, which the source of its events names.
	Name string
	// Version is the version that GetInfo reports.
	Version string
	// Settle is how long a Watch waits after a change for more before it builds the presence again. Zero means a
	// second.
	Settle time.Duration
	// Skipped counts the containers that the Watches skip. Nil counts nothing.
	Skipped *Skipped
}

// Watcher is the workloads collector. It reads the cluster through informers that it shares between its Watches,
// and each Watch applies its own context.
type Watcher struct {
	informers cache.Cache
	opts      Options
	// watches numbers the Watches, so that the gauge tells them apart.
	watches atomic.Uint64
}

// NewWatcher returns the collector, which reads the cluster through informers.
func NewWatcher(informers cache.Cache, opts Options) *Watcher {
	if opts.Settle == 0 {
		opts.Settle = defaultSettle
	}
	return &Watcher{informers: informers, opts: opts}
}

// Info says that the collector is workloads, at its version.
func (w *Watcher) Info() collector.Info {
	return collector.Info{Name: collectorName, Version: w.opts.Version}
}

// Capabilities say that the collector takes the spoke role, where the pods are, and watches. It produces presence,
// which stays on the spoke, and has no operations and no settings.
func (w *Watcher) Capabilities() collector.Capabilities {
	presenceSchema, _ := evidence.Schema(evidence.TypePresence)
	return collector.Capabilities{
		Roles: []collector.Role{collector.RoleSpoke},
		Produces: []collector.EvidenceType{
			{Type: evidence.TypePresence, Scope: collector.ScopeSpoke, Schema: presenceSchema},
		},
		Watches:        true,
		SettingsSchema: []byte(settingsSchema),
		Permissions:    permissions,
	}
}

// Watch sends a snapshot of the presence of every digest that runs in the scope of its context, and then each change
// until ctx ends: an event for a digest whose presence changed, whole, and a tombstone for a digest that no workload
// in scope runs any more. A context whose scope or allowlists it can't read fully gets InvalidArgument, before the
// snapshot.
//
// Each change of a pod, a namespace, a node, a ReplicaSet or a Job that can change presence builds it again, after
// the Watch waits for more changes for Options.Settle, and the Watch sends what differs from what it sent.
func (w *Watcher) Watch(ctx context.Context, req collector.WatchRequest, sink collector.Sink) error {
	rl, err := rulesOf(req.Context)
	if err != nil {
		return status.Error(codes.InvalidArgument, "the context: "+err.Error())
	}
	// The Watch hears of the changes from the start, so that none between its snapshot and its first change is
	// lost. Subscribing waits until each informer has synced, so the snapshot sees the whole cluster.
	changes := make(chan struct{}, 1)
	unsubscribe, err := w.subscribe(ctx, changes)
	if err != nil {
		return err
	}
	defer unsubscribe()

	watch := w.watches.Add(1)
	defer w.opts.Skipped.forget(watch)
	source := "/clusters/" + req.Context.Cluster + "/collectors/" + w.opts.Name
	// What the informers held before this build is in it.
	drain(changes)
	sent, err := w.build(ctx, watch, req.Context.Cluster, rl)
	if err != nil {
		return err
	}
	if err := sendSnapshot(sink, source, sent); err != nil {
		return err
	}
	for {
		if err := w.settle(ctx, changes); err != nil {
			return err
		}
		next, err := w.build(ctx, watch, req.Context.Cluster, rl)
		if err != nil {
			return err
		}
		if err := sendChanges(sink, source, sent, next); err != nil {
			return err
		}
		sent = next
	}
}

// settle waits for a change, and then for Options.Settle more, until ctx ends.
func (w *Watcher) settle(ctx context.Context, changes chan struct{}) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-changes:
	}
	timer := time.NewTimer(w.opts.Settle)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
	}
	drain(changes)
	return nil
}

// drain takes a change that waits, if one does.
func drain(changes chan struct{}) {
	select {
	case <-changes:
	default:
	}
}

// build builds the presence of every digest in scope, encoded as the data of its event, and counts what it skipped
// for the gauge.
func (w *Watcher) build(ctx context.Context, watch uint64, cluster string, rl rules) (map[string][]byte, error) {
	built, err := build(ctx, w.informers, rl)
	if err != nil {
		return nil, err
	}
	w.opts.Skipped.set(watch, cluster, built.skipped)
	encoded := make(map[string][]byte, len(built.images))
	for digest, presence := range built.images {
		data, err := json.Marshal(presence)
		if err != nil {
			return nil, fmt.Errorf("encode the presence of %s: %w", digest, err)
		}
		encoded[digest] = data
	}
	return encoded, nil
}

// sendSnapshot sends the presence of every digest, as the snapshot of a Watch, in the order of the digests.
func sendSnapshot(sink collector.Sink, source string, images map[string][]byte) error {
	if err := sink.SnapshotStart(); err != nil {
		return err
	}
	for _, digest := range slices.Sorted(maps.Keys(images)) {
		if err := sendEvent(sink, source, digest, images[digest]); err != nil {
			return err
		}
	}
	return sink.SnapshotEnd()
}

// sendChanges sends what differs between the presence that a Watch sent and the next: an event for each digest whose
// presence is new or changed, and a tombstone for each digest that has none any more.
func sendChanges(sink collector.Sink, source string, sent, next map[string][]byte) error {
	for _, digest := range slices.Sorted(maps.Keys(next)) {
		if before, ok := sent[digest]; !ok || string(before) != string(next[digest]) {
			if err := sendEvent(sink, source, digest, next[digest]); err != nil {
				return err
			}
		}
	}
	for _, digest := range slices.Sorted(maps.Keys(sent)) {
		if _, ok := next[digest]; !ok {
			if err := sink.Tombstone(evidence.TypePresence, subject.Image(digest)); err != nil {
				return err
			}
		}
	}
	return nil
}

// sendEvent sends the presence of a digest, about image/<digest>.
func sendEvent(sink collector.Sink, source, digest string, data []byte) error {
	e, err := evidence.New(evidence.TypePresence, subject.Image(digest), json.RawMessage(data),
		evidence.WithSource(source))
	if err != nil {
		return err
	}
	return sink.Event(e)
}

// watchedKinds are the kinds whose changes can change presence, as the informers read them: pods whole, and the rest
// as metadata.
func watchedKinds() []client.Object {
	metadataKinds := []schema.GroupVersionKind{namespaceKind, nodeKind, replicaSetKind, jobKind}
	objects := make([]client.Object, 0, 1+len(metadataKinds))
	objects = append(objects, &corev1.Pod{})
	for _, kind := range metadataKinds {
		metadata := &metav1.PartialObjectMetadata{}
		metadata.SetGroupVersionKind(kind)
		objects = append(objects, metadata)
	}
	return objects
}

// subscribe has the informers tell changes of each kind that can change presence, and returns the function that
// ends that. It waits until each informer has synced.
func (w *Watcher) subscribe(ctx context.Context, changes chan struct{}) (func(), error) {
	var registered []func()
	unsubscribe := func() {
		for _, remove := range registered {
			remove()
		}
	}
	for _, obj := range watchedKinds() {
		informer, err := w.informers.GetInformer(ctx, obj)
		if err != nil {
			unsubscribe()
			return nil, fmt.Errorf("watch the %T objects: %w", obj, err)
		}
		changed := metadataChanged
		if _, isPod := obj.(*corev1.Pod); isPod {
			changed = podChanged
		}
		registration, err := informer.AddEventHandler(toolscache.ResourceEventHandlerFuncs{
			AddFunc: func(any) { notify(changes) },
			UpdateFunc: func(old, updated any) {
				if changed(old, updated) {
					notify(changes)
				}
			},
			DeleteFunc: func(any) { notify(changes) },
		})
		if err != nil {
			unsubscribe()
			return nil, fmt.Errorf("watch the %T objects: %w", obj, err)
		}
		registered = append(registered, func() { _ = informer.RemoveEventHandler(registration) })
	}
	return unsubscribe, nil
}

// notify tells a Watch of a change without waiting: one change that waits stands for any number of them.
func notify(changes chan struct{}) {
	select {
	case changes <- struct{}{}:
	default:
	}
}

// podChanged says whether an update of a pod can change presence: it changes what build reads of a pod. A pod's
// status changes often, as its probes pass or fail, and most of those changes don't.
func podChanged(old, updated any) bool {
	before, ok := old.(*corev1.Pod)
	after, alsoOK := updated.(*corev1.Pod)
	if !ok || !alsoOK {
		return true
	}
	_, mirrorBefore := before.Annotations[corev1.MirrorPodAnnotationKey]
	_, mirrorAfter := after.Annotations[corev1.MirrorPodAnnotationKey]
	return mirrorBefore != mirrorAfter || before.Spec.NodeName != after.Spec.NodeName ||
		before.Status.Phase != after.Status.Phase || !maps.Equal(before.Labels, after.Labels) ||
		!equality.Semantic.DeepEqual(metav1.GetControllerOfNoCopy(before), metav1.GetControllerOfNoCopy(after)) ||
		!slices.Equal(imageIDs(before), imageIDs(after))
}

// imageIDs returns the image IDs that the containers of a pod report, with their names.
func imageIDs(pod *corev1.Pod) []string {
	statuses := slices.Concat(pod.Status.InitContainerStatuses, pod.Status.ContainerStatuses)
	ids := make([]string, 0, len(statuses))
	for _, container := range statuses {
		ids = append(ids, container.Name+"="+container.ImageID)
	}
	return ids
}

// metadataChanged says whether an update of a namespace, a node, a ReplicaSet or a Job can change presence: it
// changes its labels, its annotations or its owner references. A node's status changes often, and doesn't.
func metadataChanged(old, updated any) bool {
	before, ok := old.(*metav1.PartialObjectMetadata)
	after, alsoOK := updated.(*metav1.PartialObjectMetadata)
	if !ok || !alsoOK {
		return true
	}
	return !maps.Equal(before.Labels, after.Labels) || !maps.Equal(before.Annotations, after.Annotations) ||
		!equality.Semantic.DeepEqual(before.OwnerReferences, after.OwnerReferences)
}

// Skipped is the gauge vexplain_containers_skipped, which counts the containers in the scope of a Watch whose image
// the collector can't report, by the cluster that the Watch's context names and by why: Unparsable for an image ID
// that is no digest, Pending for a container that has no image ID yet. An alert on it shows that running images go
// unanalysed. It has a value for each cluster while a Watch for it runs, from the last build of the newest such
// Watch, and none for a cluster that no Watch runs for: then the collector knows nothing about its containers.
type Skipped struct {
	desc *prometheus.Desc

	mu sync.Mutex
	// counts holds the counts of each Watch that runs, by its number, which grows with each Watch.
	counts map[uint64]skippedIn
}

// skippedIn is what one Watch counted, for the cluster that its context names.
type skippedIn struct {
	cluster string
	by      map[string]int
}

// NewSkipped returns the gauge, which a registry serves once it is registered.
func NewSkipped() *Skipped {
	return &Skipped{
		desc: prometheus.NewDesc("vexplain_containers_skipped",
			"The containers in scope whose image the workloads collector can't report, by the cluster that its context "+
				"names and by why: Unparsable for an image ID that isn't a digest, Pending for a container that has no "+
				"image ID yet.",
			[]string{"cluster", "reason"}, nil),
		counts: map[uint64]skippedIn{},
	}
}

// set records what the Watch numbered watch counted in its last build.
func (s *Skipped) set(watch uint64, cluster string, by map[string]int) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.counts[watch] = skippedIn{cluster: cluster, by: by}
}

// forget drops what the Watch numbered watch counted, once it has ended.
func (s *Skipped) forget(watch uint64) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.counts, watch)
}

// Describe describes the gauge to a registry.
func (s *Skipped) Describe(ch chan<- *prometheus.Desc) {
	ch <- s.desc
}

// Collect gives the value of the gauge for each cluster that a Watch runs for, and each reason, from the newest Watch
// for the cluster. A cluster that can't be a label's value, which isn't UTF-8, gives none, where a panic would stop
// every scrape.
func (s *Skipped) Collect(ch chan<- prometheus.Metric) {
	s.mu.Lock()
	newest := map[string]uint64{}
	for watch, counted := range s.counts {
		if watch > newest[counted.cluster] {
			newest[counted.cluster] = watch
		}
	}
	values := make(map[string]map[string]int, len(newest))
	for cluster, watch := range newest {
		values[cluster] = s.counts[watch].by
	}
	s.mu.Unlock()
	for _, cluster := range slices.Sorted(maps.Keys(values)) {
		for _, reason := range reasons {
			metric, err := prometheus.NewConstMetric(s.desc, prometheus.GaugeValue, float64(values[cluster][reason]),
				cluster, reason)
			if err == nil {
				ch <- metric
			}
		}
	}
}
