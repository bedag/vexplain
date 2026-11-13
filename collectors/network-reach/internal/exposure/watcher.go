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

// Package exposure is the network-reach collector: it reports how far each workload of its cluster can be reached, as
// vexplain's exposure evidence, one event per workload, about workload/<cluster>/<namespace>/<Kind>[.<group>]/<name>:
// whether something outside the cluster reaches it, and through which objects, how far its ingress policies let the
// rest of the cluster reach it and what set that, whether a workload that is exposed may reach it, one hop away, and
// what the collector couldn't evaluate. It applies the scope and the label of vexplain's own pods that vexplain's
// context gives each Watch, and finds out itself which of the optional APIs that it reads the cluster serves: the
// Gateway API and Cilium's policies, and the kinds of policy that it doesn't read. The design of collectors, evidence
// and rules gives the reasons, in docs/design/2026-10-31-collectors-evidence-rules.md, sections 5.2, 5.5 and 5.12,
// with decisions 0006, 0024 and 0048.
//
// Exposure changes urgency, never a verdict (decision 0006). So wherever the collector can't tell what an object
// means, it takes the meaning that makes the workload more exposed, and says so where it does: what it can't evaluate
// narrows no reach, and only the peers that the admin trusts keep a rule from widening it.
package exposure

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	toolscache "k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/bedag/vexplain/sdk/collector"
	"github.com/bedag/vexplain/sdk/evidence"
)

const (
	// collectorName is the name that GetInfo reports.
	collectorName = "network-reach"
	// defaultSettle is how long a Watch waits after a change for more, when Options don't say: the changes of a
	// rollout come in bursts, and one build serves a burst.
	defaultSettle = time.Second
	// defaultSyncTimeout is how long a Watch waits for the informers to sync, when Options don't say. The first list
	// of a large cluster's pods takes seconds.
	defaultSyncTimeout = time.Minute
	// defaultDiscoveryInterval is how often a Watch asks the cluster's API discovery which optional APIs it serves,
	// when Options don't say.
	defaultDiscoveryInterval = 5 * time.Minute
)

// permissions are what the collector reads in the whole cluster: the pods and their namespaces; the Services,
// EndpointSlices and Ingresses, and the Gateway API's Gateways and routes, which expose them; the NetworkPolicies and
// Cilium's policies, which decide how far they are reached; and the ReplicaSets and Jobs that workloads.ResolveOwner
// looks through. It reads the namespaces, ReplicaSets and Jobs as metadata, and the Gateway API's and Cilium's kinds
// only where the cluster serves them. It reads no other kind, and writes nothing.
var permissions = []collector.Permission{
	{APIGroups: []string{corev1.GroupName}, Resources: []string{"pods", "namespaces", "services"}, Verbs: listAndWatch},
	{APIGroups: []string{discoveryv1.GroupName}, Resources: []string{"endpointslices"}, Verbs: listAndWatch},
	{APIGroups: []string{networkingv1.GroupName}, Resources: []string{"ingresses", "networkpolicies"},
		Verbs: listAndWatch},
	{APIGroups: []string{gatewayGroup}, Resources: []string{gatewaysResource, httpRoutesResource, tlsRoutesResource,
		grpcRoutesResource}, Verbs: listAndWatch},
	{APIGroups: []string{ciliumGroup}, Resources: []string{ciliumPoliciesResource, clusterwidePoliciesResource},
		Verbs: listAndWatch},
	{APIGroups: []string{replicaSetKind.Group}, Resources: []string{"replicasets"}, Verbs: listAndWatch},
	{APIGroups: []string{jobKind.Group}, Resources: []string{"jobs"}, Verbs: listAndWatch},
}

// The resources of the optional kinds, as the API discovery and RBAC name them.
const (
	gatewaysResource            = "gateways"
	httpRoutesResource          = "httproutes"
	tlsRoutesResource           = "tlsroutes"
	grpcRoutesResource          = "grpcroutes"
	ciliumPoliciesResource      = "ciliumnetworkpolicies"
	clusterwidePoliciesResource = "ciliumclusterwidenetworkpolicies"
	adminPoliciesResource       = "adminnetworkpolicies"
	clusterPoliciesResource     = "clusternetworkpolicies"
	calicoPoliciesResource      = "networkpolicies"
)

// listAndWatch are the verbs that an informer needs: it lists, and then watches.
var listAndWatch = []string{"list", "watch"}

// Options configure a Watcher.
type Options struct {
	// Name is the name of the collector's Collector, which the source of its events names.
	Name string
	// Version is the version that GetInfo reports.
	Version string
	// Settle is how long a Watch waits after a change for more before it builds again. Zero means a second.
	Settle time.Duration
	// SyncTimeout is how long a Watch waits for the informers to sync before its snapshot, and for those of an
	// optional API that it starts to read. Zero means a minute.
	SyncTimeout time.Duration
	// DiscoveryInterval is how often a Watch asks the cluster's API discovery which optional APIs it serves. Zero
	// means five minutes.
	DiscoveryInterval time.Duration
}

// Watcher is the network-reach collector. It reads the cluster through informers that it shares between its Watches, and
// each Watch applies its own context and settings.
type Watcher struct {
	informers cache.Cache
	discovery discovery.DiscoveryInterface
	opts      Options

	// mu guards readers: how many Watches read each optional kind, by the version that they read it in. The
	// informer of an optional kind stops once no Watch reads it.
	mu      sync.Mutex
	readers map[schema.GroupVersionKind]int
	// builds counts the builds of every Watch, and recomputed the namespaces that they computed again, so that a test
	// tells a change that builds from one that doesn't, and how much of the cluster a build computed.
	builds, recomputed atomic.Int64
}

// NewWatcher returns the collector, which reads the cluster through informers of a cache with CacheOptions, and asks
// apis which optional APIs the cluster serves.
func NewWatcher(informers cache.Cache, apis discovery.DiscoveryInterface, opts Options) *Watcher {
	if opts.Settle == 0 {
		opts.Settle = defaultSettle
	}
	if opts.SyncTimeout == 0 {
		opts.SyncTimeout = defaultSyncTimeout
	}
	if opts.DiscoveryInterval == 0 {
		opts.DiscoveryInterval = defaultDiscoveryInterval
	}
	return &Watcher{informers: informers, discovery: apis, opts: opts, readers: map[schema.GroupVersionKind]int{}}
}

// CacheOptions are the options of the cache that a Watcher reads. Its transforms keep what the collector reads of
// each object and drop the rest, so that the cache of the whole cluster holds no more than it needs. Its reads fail on
// a kind without an informer, where they would start one: every Watch starts the informers that it reads, and an
// optional kind's informer stops when the cluster stops serving the kind.
func CacheOptions() cache.Options {
	return cache.Options{Scheme: clientgoscheme.Scheme, DefaultTransform: transform, ReaderFailOnMissingInformer: true}
}

// Info says that the collector is network-reach, at its version.
func (w *Watcher) Info() collector.Info {
	return collector.Info{Name: collectorName, Version: w.opts.Version}
}

// ValidateSettings returns what is wrong with settings that passed their schema: a selector of a trusted peer that
// Kubernetes refuses, as a Watch would read it.
func (w *Watcher) ValidateSettings(raw json.RawMessage) []string {
	if _, err := readSettings(raw); err != nil {
		return []string{err.Error()}
	}
	return nil
}

// Capabilities say that the collector takes the spoke role, where the workloads are, and watches. It produces
// exposure, which stays on the spoke, and has no operations.
func (w *Watcher) Capabilities() collector.Capabilities {
	exposureSchema, _ := evidence.Schema(evidence.TypeExposure)
	return collector.Capabilities{
		Roles: []collector.Role{collector.RoleSpoke},
		Produces: []collector.EvidenceType{
			{Type: evidence.TypeExposure, Scope: collector.ScopeSpoke, Schema: exposureSchema},
		},
		Watches:        true,
		SettingsSchema: []byte(settingsSchema),
		Permissions:    permissions,
	}
}

// Watch sends a snapshot of the exposure of every workload in the scope of its context, and then each change until
// ctx ends: an event for a workload whose exposure changed, whole, and a tombstone for a workload that is gone or
// left the scope. A context or settings that it can't read fully get InvalidArgument, before the snapshot. A Watch
// whose informers don't sync within Options.SyncTimeout gets Unavailable, naming the kind that didn't, as when the
// collector's service account lacks the right to list it, and so does one that can't ask the API discovery at its
// start.
//
// Every Options.DiscoveryInterval it asks the API discovery again, starts to read an optional kind that the cluster
// serves now, and stops reading one that it no longer serves. Each change that can change exposure builds again, after
// the Watch waits for more changes for Options.Settle, and the Watch sends what differs from what it sent.
func (w *Watcher) Watch(ctx context.Context, req collector.WatchRequest, sink collector.Sink) error {
	rl, err := rulesOf(req.Context)
	if err != nil {
		return status.Error(codes.InvalidArgument, "the context: "+err.Error())
	}
	s, err := readSettings(req.Settings)
	if err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	st := &stream{
		w: w, changes: make(chan struct{}, 1), dirty: &dirt{namespaces: map[string]bool{}},
		optional: map[schema.GroupKind]*subscription{},
	}
	defer st.close()
	// The Watch hears of the changes from the start, so that none between its snapshot and its first change is lost.
	if err := st.start(ctx); err != nil {
		return err
	}
	b := newBuilder(w, rl, s)
	source := "/clusters/" + rl.cluster + "/collectors/" + w.opts.Name
	// What the informers held before this build is in it.
	drain(st.changes)
	st.dirty.take()
	if err := b.build(ctx, st.available(), true, nil); err != nil {
		return err
	}
	sent, err := b.events()
	if err != nil {
		return err
	}
	if err := sendSnapshot(sink, source, sent); err != nil {
		return err
	}
	discoveries := time.NewTicker(w.opts.DiscoveryInterval)
	defer discoveries.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-discoveries.C:
			if err := st.rediscover(ctx); err != nil {
				return err
			}
			continue
		case <-st.changes:
		}
		if err := sleep(ctx, w.opts.Settle); err != nil {
			return err
		}
		drain(st.changes)
		all, dirty := st.dirty.take()
		if err := b.build(ctx, st.available(), all, dirty); err != nil {
			return err
		}
		next, err := b.events()
		if err != nil {
			return err
		}
		if err := sendChanges(sink, source, sent, next); err != nil {
			return err
		}
		sent = next
	}
}

// sleep waits for d, or until ctx ends.
func sleep(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// drain takes a change that waits, if one does.
func drain(changes chan struct{}) {
	select {
	case <-changes:
	default:
	}
}

// notify tells a Watch of a change without waiting: one change that waits stands for any number of them.
func notify(changes chan struct{}) {
	select {
	case changes <- struct{}{}:
	default:
	}
}

// sendSnapshot sends the exposure of every workload, as the snapshot of a Watch, in the order of the subjects.
func sendSnapshot(sink collector.Sink, source string, events map[string][]byte) error {
	if err := sink.SnapshotStart(); err != nil {
		return err
	}
	for _, about := range slices.Sorted(maps.Keys(events)) {
		if err := sendEvent(sink, source, about, events[about]); err != nil {
			return err
		}
	}
	return sink.SnapshotEnd()
}

// sendChanges sends what differs between the exposure that a Watch sent and the next: an event for each workload
// whose exposure is new or changed, and a tombstone for each workload that has none any more.
func sendChanges(sink collector.Sink, source string, sent, next map[string][]byte) error {
	for _, about := range slices.Sorted(maps.Keys(next)) {
		if before, ok := sent[about]; !ok || string(before) != string(next[about]) {
			if err := sendEvent(sink, source, about, next[about]); err != nil {
				return err
			}
		}
	}
	for _, about := range slices.Sorted(maps.Keys(sent)) {
		if _, ok := next[about]; !ok {
			if err := sink.Tombstone(evidence.TypeExposure, about); err != nil {
				return err
			}
		}
	}
	return nil
}

// sendEvent sends the exposure of a workload, about its subject.
func sendEvent(sink collector.Sink, source, about string, data []byte) error {
	e, err := evidence.New(evidence.TypeExposure, about, json.RawMessage(data), evidence.WithSource(source))
	if err != nil {
		return err
	}
	return sink.Event(e)
}

// dirt is what changed since a Watch's last build: the namespaces whose workloads a change can have changed, and all
// of them when a change can have changed every one.
type dirt struct {
	mu         sync.Mutex
	all        bool
	namespaces map[string]bool
}

// mark records a change in the namespace, or in every namespace for an empty one.
func (d *dirt) mark(namespace string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if namespace == "" {
		d.all = true
		return
	}
	d.namespaces[namespace] = true
}

// markAll records a change that can have changed every namespace.
func (d *dirt) markAll() { d.mark("") }

// take returns what changed, and forgets it.
func (d *dirt) take() (all bool, namespaces map[string]bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	all, namespaces = d.all, d.namespaces
	d.all, d.namespaces = false, map[string]bool{}
	return all, namespaces
}

// kind is a kind that the collector reads: what it reads it as, which of its updates can change exposure, and whether
// a change of one of its objects changes the workloads of the object's namespace alone, so that a build computes that
// namespace again. A change of any other kind changes what step 1 of a build reads, which tells what it touches.
type kind struct {
	kind    schema.GroupKind
	object  func() client.Object
	changed func(old, updated any) bool
	local   bool
}

// staticKinds are the kinds that every cluster serves.
func staticKinds() []kind {
	typed := func(obj client.Object) func() client.Object {
		return func() client.Object { return obj.DeepCopyObject().(client.Object) }
	}
	metadata := func(gvk schema.GroupVersionKind) func() client.Object {
		return func() client.Object {
			m := &metav1.PartialObjectMetadata{}
			m.SetGroupVersionKind(gvk)
			return m
		}
	}
	return []kind{
		{kind: podKind.GroupKind(), object: typed(&corev1.Pod{}), changed: podChanged, local: true},
		{kind: namespaceKind.GroupKind(), object: metadata(namespaceKind), changed: labelsChanged},
		{kind: serviceKind.GroupKind(), object: typed(&corev1.Service{}), changed: serviceChanged, local: true},
		{kind: endpointSliceKind.GroupKind(), object: typed(&discoveryv1.EndpointSlice{}), changed: endpointsChanged},
		{kind: ingressKind.GroupKind(), object: typed(&networkingv1.Ingress{}), changed: ingressChanged},
		{kind: policyKind.GroupKind(), object: typed(&networkingv1.NetworkPolicy{}), changed: policyChanged,
			local: true},
		{kind: replicaSetKind.GroupKind(), object: metadata(replicaSetKind), changed: ownersChanged, local: true},
		{kind: jobKind.GroupKind(), object: metadata(jobKind), changed: ownersChanged, local: true},
	}
}

// optionalKind is a kind of an API that not every cluster serves: its resource, which the API discovery names,
// whether a change of one of its objects changes its namespace alone, and, for a kind that the collector doesn't
// read, what the evidence's unseen names it.
type optionalKind struct {
	kind     schema.GroupKind
	resource string
	local    bool
	unseen   string
}

// optionalKinds are the kinds of the Gateway API and of Cilium that the collector reads where the cluster serves
// them, and the kinds of policy whose rules can let in what the policies that it reads deny, which it doesn't read:
// SIG Network's AdminNetworkPolicy, and its ClusterNetworkPolicy, which replaces it; and Calico's NetworkPolicy, in
// crd.projectcalico.org, whose CRD Calico installs where its API server serves projectcalico.org, and in
// projectcalico.org itself, which Calico serves as CRDs where it runs without that server. Where the cluster serves
// one of those, each workload may be reached further than the collector says, and its evidence names the kind among
// what the collector couldn't evaluate. The collector reads none of their objects, and needs no right to: the API
// discovery says which kinds the cluster serves.
var optionalKinds = []optionalKind{
	{kind: gatewayKind, resource: gatewaysResource},
	{kind: routeKinds[0], resource: httpRoutesResource},
	{kind: routeKinds[1], resource: tlsRoutesResource},
	{kind: routeKinds[2], resource: grpcRoutesResource},
	{kind: ciliumKind, resource: ciliumPoliciesResource, local: true},
	{kind: clusterwideKind, resource: clusterwidePoliciesResource},
	{kind: schema.GroupKind{Group: "policy.networking.k8s.io", Kind: "AdminNetworkPolicy"},
		resource: adminPoliciesResource, unseen: evidence.UnseenAdminNetworkPolicy},
	{kind: schema.GroupKind{Group: "policy.networking.k8s.io", Kind: "ClusterNetworkPolicy"},
		resource: clusterPoliciesResource, unseen: evidence.UnseenAdminNetworkPolicy},
	{kind: schema.GroupKind{Group: "crd.projectcalico.org", Kind: "NetworkPolicy"}, resource: calicoPoliciesResource,
		unseen: evidence.UnseenCalicoNetworkPolicy},
	{kind: schema.GroupKind{Group: "projectcalico.org", Kind: "NetworkPolicy"}, resource: calicoPoliciesResource,
		unseen: evidence.UnseenCalicoNetworkPolicy},
}

// unreadServed returns what the evidence's unseen names of the kinds of policy that the collector doesn't read and that
// the Watch found served, as available holds them.
func unreadServed(available map[schema.GroupKind]schema.GroupVersionKind) []string {
	var unseen []string
	for _, optional := range optionalKinds {
		if _, served := available[optional.kind]; served && optional.unseen != "" {
			unseen = append(unseen, optional.unseen)
		}
	}
	return unseen
}

// subscription is a Watch's reading of an optional kind, in a version, and the function that ends it.
type subscription struct {
	gvk  schema.GroupVersionKind
	stop func()
}

// stream is the state of one Watch: the changes that its informers tell it of, and what it reads.
type stream struct {
	w       *Watcher
	changes chan struct{}
	dirty   *dirt
	// removers remove the Watch's handlers of the static kinds' informers.
	removers []func()
	// optional are the optional kinds that the Watch reads.
	optional map[schema.GroupKind]*subscription
}

// syncing is an informer that a Watch waits for, with its kind.
type syncing struct {
	kind   schema.GroupKind
	synced toolscache.InformerSynced
}

// start has the informers of the static kinds, and of the optional kinds that the cluster serves, tell the Watch of
// changes, and waits until each has synced, for Options.SyncTimeout at most.
func (st *stream) start(ctx context.Context) error {
	var waits []syncing
	for _, k := range staticKinds() {
		informer, err := st.w.informers.GetInformer(ctx, k.object(), cache.BlockUntilSynced(false))
		if err != nil {
			return fmt.Errorf("watch the %s objects: %w", k.kind, err)
		}
		remove, err := st.handle(informer, k)
		if err != nil {
			return err
		}
		st.removers = append(st.removers, remove)
		waits = append(waits, syncing{kind: k.kind, synced: informer.HasSynced})
	}
	served, err := discover(st.w.discovery)
	if err != nil {
		return status.Errorf(codes.Unavailable, "find out which APIs the cluster serves: %v", err)
	}
	optional, err := st.subscribe(ctx, served)
	if err != nil {
		return err
	}
	return st.waitForSync(ctx, append(waits, optional...))
}

// rediscover asks the API discovery again which optional kinds the cluster serves, stops reading those that it no
// longer serves, or serves in another version, and starts to read the others that it serves. Each change of what the
// Watch reads, or of the kinds that it knows the cluster serves and doesn't read, changes every namespace. When the API
// discovery fails, the Watch reads what it read, and asks again at the next interval.
func (st *stream) rediscover(ctx context.Context) error {
	served, err := discover(st.w.discovery)
	if err != nil {
		logf.FromContext(ctx).Error(err, "Could not find out which APIs the cluster serves; the Watch reads what it "+
			"read, and asks again", "interval", st.w.opts.DiscoveryInterval)
		return nil
	}
	changed := false
	for kind, sub := range st.optional {
		if gvk, ok := served[kind]; !ok || gvk != sub.gvk {
			sub.stop()
			delete(st.optional, kind)
			changed = true
		}
	}
	before := len(st.optional)
	waits, err := st.subscribe(ctx, served)
	if err != nil {
		return err
	}
	if err := st.waitForSync(ctx, waits); err != nil {
		return err
	}
	if changed || len(st.optional) != before {
		st.dirty.markAll()
		notify(st.changes)
	}
	return nil
}

// subscribe has the informers of the optional kinds that the cluster serves, and that the Watch doesn't read yet,
// tell it of changes, and returns them, to wait for. A kind that the collector doesn't read gets no informer: the
// Watch only records that the cluster serves it.
func (st *stream) subscribe(ctx context.Context, served map[schema.GroupKind]schema.GroupVersionKind) ([]syncing,
	error) {
	var waits []syncing
	for _, optional := range optionalKinds {
		gvk, ok := served[optional.kind]
		if !ok || st.optional[optional.kind] != nil {
			continue
		}
		if optional.unseen != "" {
			st.optional[optional.kind] = &subscription{gvk: gvk, stop: func() {}}
			continue
		}
		obj := &unstructured.Unstructured{}
		obj.SetGroupVersionKind(gvk)
		informer, err := st.w.acquire(ctx, obj)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "watch the %s objects: %v", optional.kind, err)
		}
		remove, err := st.handle(informer, kind{kind: optional.kind, changed: specChanged, local: optional.local})
		if err != nil {
			st.w.release(obj)
			return nil, err
		}
		st.optional[optional.kind] = &subscription{gvk: gvk, stop: func() { remove(); st.w.release(obj) }}
		waits = append(waits, syncing{kind: optional.kind, synced: informer.HasSynced})
	}
	return waits, nil
}

// waitForSync waits until each informer has synced, for Options.SyncTimeout at most. An informer that can't list its
// kind, as when the collector's service account lacks the right, never syncs: the Watch then fails with Unavailable,
// naming the kind, where it would never send its snapshot while the collector's health check says SERVING. The
// informer of a static kind keeps trying, and that of an optional kind starts again with the next Watch, which finds
// it synced once the right is there.
func (st *stream) waitForSync(ctx context.Context, waits []syncing) error {
	syncCtx, cancel := context.WithTimeout(ctx, st.w.opts.SyncTimeout)
	defer cancel()
	for _, wait := range waits {
		if toolscache.WaitForCacheSync(syncCtx.Done(), wait.synced) {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		return status.Errorf(codes.Unavailable, "the cache of the %s objects didn't sync within %s: the collector's "+
			"service account may lack the right to list and watch them", wait.kind, st.w.opts.SyncTimeout)
	}
	return nil
}

// handle has the informer tell the Watch of each change of an object of the kind that can change exposure, and marks
// the object's namespace for a kind whose changes stay in it. It returns the function that ends that.
func (st *stream) handle(informer cache.Informer, k kind) (func(), error) {
	changed := func(obj any) {
		if k.local {
			st.dirty.mark(namespaceOf(obj))
		}
		notify(st.changes)
	}
	registration, err := informer.AddEventHandler(toolscache.ResourceEventHandlerFuncs{
		AddFunc: changed,
		UpdateFunc: func(old, updated any) {
			if k.changed(old, updated) {
				changed(updated)
			}
		},
		DeleteFunc: changed,
	})
	if err != nil {
		return nil, fmt.Errorf("watch the %s objects: %w", k.kind, err)
	}
	return func() { _ = informer.RemoveEventHandler(registration) }, nil
}

// available returns the optional kinds that the Watch reads, in the version that it reads them in, and those that it
// knows the cluster serves and doesn't read.
func (st *stream) available() map[schema.GroupKind]schema.GroupVersionKind {
	available := make(map[schema.GroupKind]schema.GroupVersionKind, len(st.optional))
	for kind, sub := range st.optional {
		available[kind] = sub.gvk
	}
	return available
}

// close ends what the Watch reads.
func (st *stream) close() {
	for _, remove := range st.removers {
		remove()
	}
	for _, sub := range st.optional {
		sub.stop()
	}
}

// acquire returns the informer of an optional kind, which it starts unless a Watch reads the kind already.
func (w *Watcher) acquire(ctx context.Context, obj *unstructured.Unstructured) (cache.Informer, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	informer, err := w.informers.GetInformer(ctx, obj, cache.BlockUntilSynced(false))
	if err != nil {
		return nil, err
	}
	w.readers[obj.GroupVersionKind()]++
	return informer, nil
}

// release says that a Watch no longer reads an optional kind, and stops its informer when no Watch does.
func (w *Watcher) release(obj *unstructured.Unstructured) {
	w.mu.Lock()
	defer w.mu.Unlock()
	gvk := obj.GroupVersionKind()
	if w.readers[gvk]--; w.readers[gvk] > 0 {
		return
	}
	delete(w.readers, gvk)
	_ = w.informers.RemoveInformer(context.Background(), obj)
}

// discover asks the cluster's API discovery which of the optional kinds it serves, and in which version: the version
// that the kind's group prefers, when it serves the kind, and else the first that does. A kind counts as served when
// it can be listed and watched. A kind that the collector doesn't read also counts as served when the discovery can't
// read the resources of a version of its group, as those of an aggregated API whose server is down: the group is
// there, and what the collector doesn't read narrows nothing.
func discover(apis discovery.DiscoveryInterface) (map[schema.GroupKind]schema.GroupVersionKind, error) {
	var (
		groups    *metav1.APIGroupList
		resources map[schema.GroupVersion]*metav1.APIResourceList
		failed    map[schema.GroupVersion]error
		err       error
	)
	if aggregated, ok := apis.(discovery.AggregatedDiscoveryInterface); ok {
		groups, resources, failed, err = aggregated.GroupsAndMaybeResources()
	} else {
		groups, err = apis.ServerGroups()
	}
	if err != nil {
		return nil, err
	}
	served := map[schema.GroupKind]schema.GroupVersionKind{}
	for _, group := range groups.Groups {
		if !slices.ContainsFunc(optionalKinds, func(o optionalKind) bool { return o.kind.Group == group.Name }) {
			continue
		}
		versions := []string{group.PreferredVersion.Version}
		for _, version := range group.Versions {
			if version.Version != group.PreferredVersion.Version {
				versions = append(versions, version.Version)
			}
		}
		for _, version := range versions {
			gv := schema.GroupVersion{Group: group.Name, Version: version}
			list, err := resourcesOf(apis, gv, resources, failed)
			if err != nil && unread(gv.Group) {
				for _, optional := range optionalKinds {
					if _, found := served[optional.kind]; !found && optional.kind.Group == gv.Group {
						served[optional.kind] = gv.WithKind(optional.kind.Kind)
					}
				}
				continue
			}
			if err != nil {
				return nil, err
			}
			for _, resource := range list {
				for _, optional := range optionalKinds {
					_, found := served[optional.kind]
					if !found && optional.kind.Group == gv.Group && optional.resource == resource.Name &&
						!slices.ContainsFunc(listAndWatch, func(verb string) bool {
							return !slices.Contains(resource.Verbs, verb)
						}) {
						served[optional.kind] = gv.WithKind(optional.kind.Kind)
					}
				}
			}
		}
	}
	return served, nil
}

// unread reports whether the collector reads none of the optional kinds of the group, and only notes that the cluster
// serves them.
func unread(group string) bool {
	return !slices.ContainsFunc(optionalKinds, func(o optionalKind) bool { return o.kind.Group == group && o.unseen == "" })
}

// resourcesOf returns the resources that the API discovery lists for a group version, from what the aggregated
// discovery returned, and else by asking for them. A group version that is gone has none.
func resourcesOf(apis discovery.DiscoveryInterface, gv schema.GroupVersion,
	resources map[schema.GroupVersion]*metav1.APIResourceList, failed map[schema.GroupVersion]error) (
	[]metav1.APIResource, error) {
	if err, ok := failed[gv]; ok {
		return nil, fmt.Errorf("discover %s: %w", gv, err)
	}
	if list, ok := resources[gv]; ok && list != nil {
		return list.APIResources, nil
	}
	list, err := apis.ServerResourcesForGroupVersion(gv.String())
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("discover %s: %w", gv, err)
	}
	return list.APIResources, nil
}

// namespaceOf returns the namespace of an object that an informer tells of, also when it tells of its deletion
// without the object's last state.
func namespaceOf(obj any) string {
	if tombstone, ok := obj.(toolscache.DeletedFinalStateUnknown); ok {
		if namespace, _, err := toolscache.SplitMetaNamespaceKey(tombstone.Key); err == nil {
			return namespace
		}
		obj = tombstone.Obj
	}
	if o, ok := obj.(metav1.Object); ok {
		return o.GetNamespace()
	}
	return ""
}

// podChanged says whether an update of a pod can change exposure: its labels, which Services and policies select it
// by; its controller, which names its workload; whether it is a mirror pod, which is a workload of its own; its
// service account, which Cilium's selectors can select; and whether it uses its node's network or has host ports,
// which expose it. A pod's status changes often, as its probes pass or fail, and exposure reads none of it.
func podChanged(old, updated any) bool {
	before, ok := old.(*corev1.Pod)
	after, alsoOK := updated.(*corev1.Pod)
	if !ok || !alsoOK {
		return true
	}
	_, mirrorBefore := before.Annotations[corev1.MirrorPodAnnotationKey]
	_, mirrorAfter := after.Annotations[corev1.MirrorPodAnnotationKey]
	return mirrorBefore != mirrorAfter || !maps.Equal(before.Labels, after.Labels) ||
		before.Spec.ServiceAccountName != after.Spec.ServiceAccountName ||
		before.Spec.HostNetwork != after.Spec.HostNetwork || !slices.Equal(hostPorts(before), hostPorts(after)) ||
		!equality.Semantic.DeepEqual(metav1.GetControllerOfNoCopy(before), metav1.GetControllerOfNoCopy(after))
}

// serviceChanged says whether an update of a Service can change exposure: its type, selector, node ports, external
// IPs, or annotations, which the settings can name as internal.
func serviceChanged(old, updated any) bool {
	before, ok := old.(*corev1.Service)
	after, alsoOK := updated.(*corev1.Service)
	return !ok || !alsoOK || before.Spec.Type != after.Spec.Type ||
		!maps.Equal(before.Spec.Selector, after.Spec.Selector) ||
		!equality.Semantic.DeepEqual(before.Spec.Ports, after.Spec.Ports) ||
		!slices.Equal(before.Spec.ExternalIPs, after.Spec.ExternalIPs) ||
		!maps.Equal(before.Annotations, after.Annotations)
}

// endpointsChanged says whether an update of an EndpointSlice can change exposure: its Service, or the pods that it
// names. The conditions of its endpoints change as pods become ready, and exposure reads none of them.
func endpointsChanged(old, updated any) bool {
	before, ok := old.(*discoveryv1.EndpointSlice)
	after, alsoOK := updated.(*discoveryv1.EndpointSlice)
	if !ok || !alsoOK {
		return true
	}
	beforeService, beforePods := slicePods(before)
	afterService, afterPods := slicePods(after)
	return beforeService != afterService || !slices.Equal(beforePods, afterPods)
}

// ingressChanged says whether an update of an Ingress can change exposure: its class, or the Services that it routes
// to. Its status changes as its load balancer gets an address, and exposure reads none of it.
func ingressChanged(old, updated any) bool {
	before, ok := old.(*networkingv1.Ingress)
	after, alsoOK := updated.(*networkingv1.Ingress)
	return !ok || !alsoOK || before.Annotations[ingressClassAnnotation] != after.Annotations[ingressClassAnnotation] ||
		!equality.Semantic.DeepEqual(before.Spec.IngressClassName, after.Spec.IngressClassName) ||
		!slices.Equal(ingressBackends(before), ingressBackends(after))
}

// policyChanged says whether an update of a NetworkPolicy can change exposure: its spec.
func policyChanged(old, updated any) bool {
	before, ok := old.(*networkingv1.NetworkPolicy)
	after, alsoOK := updated.(*networkingv1.NetworkPolicy)
	return !ok || !alsoOK || !equality.Semantic.DeepEqual(before.Spec, after.Spec)
}

// labelsChanged says whether an update of a namespace can change exposure: its labels, which the scope and the
// policies' namespace selectors read. Its annotations and status change on their own.
func labelsChanged(old, updated any) bool {
	before, after, ok := metadataOf(old, updated)
	return !ok || !maps.Equal(before.Labels, after.Labels)
}

// ownersChanged says whether an update of a ReplicaSet or a Job can change exposure: its owner references, which
// say its controller, and so the workload of its pods. Its annotations change often, as a ReplicaSet's at every
// scale, and exposure reads none of them.
func ownersChanged(old, updated any) bool {
	before, after, ok := metadataOf(old, updated)
	return !ok || !equality.Semantic.DeepEqual(before.OwnerReferences, after.OwnerReferences)
}

// specChanged says whether an update of an object of the Gateway API or of Cilium can change exposure: its spec, or
// its specs. Their controllers write their status often, and exposure reads none of it.
func specChanged(old, updated any) bool {
	before, ok := old.(*unstructured.Unstructured)
	after, alsoOK := updated.(*unstructured.Unstructured)
	return !ok || !alsoOK || !equality.Semantic.DeepEqual(before.Object["spec"], after.Object["spec"]) ||
		!equality.Semantic.DeepEqual(before.Object["specs"], after.Object["specs"])
}

// metadataOf returns the objects of an update as metadata, and false when they aren't, which counts as a change.
func metadataOf(old, updated any) (*metav1.PartialObjectMetadata, *metav1.PartialObjectMetadata, bool) {
	before, ok := old.(*metav1.PartialObjectMetadata)
	after, alsoOK := updated.(*metav1.PartialObjectMetadata)
	return before, after, ok && alsoOK
}

// transform keeps what the collector reads of an object of each kind that it reads, and drops the rest. It keeps
// each object's name, namespace, UID, resourceVersion and generation, which the informers need, and leaves alone
// what it doesn't know, such as the tombstone of a deletion.
func transform(obj any) (any, error) {
	switch o := obj.(type) {
	case *corev1.Pod:
		return trimPod(o), nil
	case *corev1.Service:
		return trimService(o), nil
	case *discoveryv1.EndpointSlice:
		return trimEndpointSlice(o), nil
	case *networkingv1.Ingress:
		return trimIngress(o), nil
	case *networkingv1.NetworkPolicy:
		return trimNetworkPolicy(o), nil
	case *metav1.PartialObjectMetadata:
		return trimMetadata(o), nil
	case *unstructured.Unstructured:
		switch o.GroupVersionKind().GroupKind() {
		case gatewayKind:
			return trimGateway(o), nil
		case routeKinds[0], routeKinds[1], routeKinds[2]:
			return trimRoute(o), nil
		case ciliumKind, clusterwideKind:
			return trimCilium(o), nil
		}
	}
	return obj, nil
}

// identity is what the informers need of an object's metadata.
func identity(m metav1.ObjectMeta) metav1.ObjectMeta {
	return metav1.ObjectMeta{
		Name: m.Name, Namespace: m.Namespace, UID: m.UID, ResourceVersion: m.ResourceVersion, Generation: m.Generation,
	}
}

// trimmedIdentity returns an unstructured object of u's kind with what the informers need of its metadata.
func trimmedIdentity(u *unstructured.Unstructured) *unstructured.Unstructured {
	trimmed := &unstructured.Unstructured{Object: map[string]any{}}
	trimmed.SetGroupVersionKind(u.GroupVersionKind())
	trimmed.SetName(u.GetName())
	trimmed.SetNamespace(u.GetNamespace())
	trimmed.SetUID(u.GetUID())
	trimmed.SetResourceVersion(u.GetResourceVersion())
	trimmed.SetGeneration(u.GetGeneration())
	return trimmed
}

// trimPod keeps what the collector reads of a pod: its labels, its owner references, whether it is a mirror pod, its
// service account, whether it uses its node's network, and its host ports, as the ports of one container.
func trimPod(pod *corev1.Pod) *corev1.Pod {
	trimmed := &corev1.Pod{ObjectMeta: identity(pod.ObjectMeta), Spec: corev1.PodSpec{
		ServiceAccountName: pod.Spec.ServiceAccountName, HostNetwork: pod.Spec.HostNetwork,
	}}
	if ports := hostPorts(pod); len(ports) > 0 {
		container := corev1.Container{}
		for _, port := range ports {
			container.Ports = append(container.Ports, corev1.ContainerPort{HostPort: port})
		}
		trimmed.Spec.Containers = []corev1.Container{container}
	}
	trimmed.Labels, trimmed.OwnerReferences = pod.Labels, pod.OwnerReferences
	if mirror, ok := pod.Annotations[corev1.MirrorPodAnnotationKey]; ok {
		trimmed.Annotations = map[string]string{corev1.MirrorPodAnnotationKey: mirror}
	}
	return trimmed
}

// trimMetadata keeps what the collector reads of an object that it reads as metadata: a namespace's labels, and a
// ReplicaSet's or a Job's owner references.
func trimMetadata(m *metav1.PartialObjectMetadata) *metav1.PartialObjectMetadata {
	trimmed := &metav1.PartialObjectMetadata{TypeMeta: m.TypeMeta, ObjectMeta: identity(m.ObjectMeta)}
	trimmed.Labels, trimmed.OwnerReferences = m.Labels, m.OwnerReferences
	return trimmed
}
