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

package remote

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/go-logr/logr"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/rest"
	toolscache "k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/cluster"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/collectorclient"
	"github.com/bedag/vexplain/internal/evidence"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/metrics"
	sdkevidence "github.com/bedag/vexplain/sdk/evidence"
	"github.com/bedag/vexplain/sdk/subject"
	"github.com/bedag/vexplain/sdk/workloads"
)

const (
	// maxCopiedNamespaces is how many namespaces a copied entry names at most: as many as the spoke's entry can, so that
	// the hub's copy keeps every one of them.
	maxCopiedNamespaces = 1000
	// maxListedCollectors is how many collectors a Spoke lists at most, as its schema allows.
	maxListedCollectors = 64
	// maxCollectorName is the length of the longest name of a Collector, as its schema allows, and so of a record's
	// source.
	maxCollectorName = 44
	// pause is how long the copier waits after a change on the spoke before the round that copies it, so that the
	// changes of a burst go in one round.
	pause = time.Second
	// firstRetry is how long the copier waits before a round again after one failed, the first time. Each wait after
	// that is twice the last, and maxRetry at most.
	firstRetry, maxRetry = time.Second, time.Minute
	// round is the one item of a copier's queue: a round copies whatever changed.
	round = "round"
)

// The reasons of vexplain_spoke_records_refused_total.
const (
	refusedCluster   = "cluster"
	refusedClusterID = "clusterID"
	refusedScope     = "scope"
	refusedInvalid   = "invalid"
)

// errNotSynced says that a round ended before the cache of the spoke synced: it copied nothing, and deleted nothing.
var errNotSynced = errors.New("the cache of the spoke hasn't synced")

// kinds maps the kinds of a spoke that the copier reads, which are cluster-scoped. A cache with it needs no discovery,
// whose requests client-go sends without a context, so that nothing waits on a spoke that hangs but the cache's lists
// and watches, which end with the copier.
var kinds = func() meta.RESTMapper {
	mapper := meta.NewDefaultRESTMapper(nil)
	for _, gvk := range []schema.GroupVersionKind{
		inventoryv1alpha1.GroupVersion.WithKind("Evidence"),
		inventoryv1alpha1.GroupVersion.WithKind("ImageInventory"),
		configv1alpha1.GroupVersion.WithKind("Collector"),
		namespaceKind,
	} {
		mapper.Add(gvk, meta.RESTScopeRoot)
	}
	return mapper
}()

// NewCluster returns the cluster of a spoke that cfg reaches, as the copier of the spoke of the name reads it: a cache
// of its Collectors, its ImageInventory objects, its Evidence of the spoke's cluster, which the label
// vexplain.bedag.ch/cluster selects, and the metadata of its namespaces, for their labels. A spoke keeps there what its
// streams store for the hub, so the cache holds those records whole, and of a namespace no more than its metadata. The
// cache knows its kinds without asking the spoke. Its lists and watches pass through withheldAnswers, so that no text
// that the spoke answers with reaches a log: such a text can carry the token that the hub sent. Start runs it until
// its context ends.
func NewCluster(cfg *rest.Config, spoke string, scheme *runtime.Scheme, log logr.Logger) (cluster.Cluster, error) {
	return cluster.New(cfg, func(o *cluster.Options) {
		o.Scheme, o.Logger = scheme, log
		o.MapperProvider = func(*rest.Config, *http.Client) (meta.RESTMapper, error) { return kinds, nil }
		o.Cache = cache.Options{
			ByObject: map[client.Object]cache.ByObject{
				&inventoryv1alpha1.Evidence{}: {Label: labels.SelectorFromSet(labels.Set{evidence.ClusterLabel: spoke})},
			},
			DefaultTransform:         cache.TransformStripManagedFields(),
			DefaultWatchErrorHandler: withheld(log),
			NewInformer: func(lw toolscache.ListerWatcher, obj runtime.Object, resync time.Duration,
				indexers toolscache.Indexers) toolscache.SharedIndexInformer {
				return toolscache.NewSharedIndexInformer(withheldAnswers{toolscache.ToListerWatcherWithContext(lw)}, obj,
					resync, indexers)
			},
		}
	})
}

// withheld logs that a list or a watch of the spoke failed, as client-go's own handler would: of an answer of the
// spoke's API server, its code alone, and of any other failure, nothing but that it failed. An answer's texts are the
// spoke's, and can carry the token that the hub sent; so can what a connection's error quotes of what the server sent.
// The Spoke's Connected condition says why a spoke can't be reached.
func withheld(log logr.Logger) toolscache.WatchErrorHandlerWithContext {
	return func(_ context.Context, r *toolscache.Reflector, err error) {
		var answer apierrors.APIStatus
		switch {
		case errors.Is(err, io.EOF), apierrors.IsResourceExpired(err), apierrors.IsGone(err):
			// The watch ended as watches do, and starts again.
		case errors.As(err, &answer):
			log.Info("The spoke's API server refused a list or a watch; the cache tries again", "type",
				r.TypeDescription(), "code", answer.Status().Code)
		default:
			log.Info("Could not list or watch the spoke; the cache tries again", "type", r.TypeDescription())
		}
	}
}

// withheldAnswers passes the lists and the watches of a cache of the spoke on, with each error that the spoke's API
// server answers reduced to its code: the error of a list, or of a watch's start, and an ERROR event inside a watch.
// client-go logs these errors, some of them itself, past any handler, and their texts are the spoke's: they can carry
// the token that the hub sent. What the cache's reflector decides by stays: the code, and whether the resource version
// that it asked for was too large.
type withheldAnswers struct {
	toolscache.ListerWatcherWithContext
}

// ListWithContext lists as the cache's own ListerWatcher does, with an answer that is an error reduced to its code.
func (w withheldAnswers) ListWithContext(ctx context.Context, options metav1.ListOptions) (runtime.Object, error) {
	list, err := w.ListerWatcherWithContext.ListWithContext(ctx, options)
	return list, withholdAnswer(err)
}

// WatchWithContext watches as the cache's own ListerWatcher does, with an answer that is an error, and each ERROR event
// of the watch, reduced to its code.
func (w withheldAnswers) WatchWithContext(ctx context.Context, options metav1.ListOptions) (watch.Interface, error) {
	watcher, err := w.ListerWatcherWithContext.WatchWithContext(ctx, options)
	if err != nil {
		return nil, withholdAnswer(err)
	}
	return withholdEvents(watcher), nil
}

// withheldEvents is a watch of the spoke whose ERROR events reach its reader reduced to their code. Its loop ends when
// the watch that it reads ends, or when Stop stops it, also while nobody reads it any more, as after the cache's
// reflector stopped it: a loop that waited to hand on an event would stay for good.
type withheldEvents struct {
	watcher watch.Interface
	result  chan watch.Event
	// stopped is closed by Stop, and ended once the loop has ended.
	stopped, ended chan struct{}
	stop           sync.Once
}

// withholdEvents returns watcher, with its ERROR events reduced to their code.
func withholdEvents(watcher watch.Interface) watch.Interface {
	w := &withheldEvents{watcher: watcher, result: make(chan watch.Event), stopped: make(chan struct{}),
		ended: make(chan struct{})}
	go w.loop()
	return w
}

// loop hands the events of the watch on, until the watch ends, or Stop stops it.
func (w *withheldEvents) loop() {
	defer close(w.ended)
	defer close(w.result)
	for {
		var e watch.Event
		select {
		case <-w.stopped:
			return
		case event, open := <-w.watcher.ResultChan():
			if !open {
				return
			}
			e = event
		}
		if e.Type == watch.Error {
			// An object that isn't a Status turns into an error that prints it, so it keeps no more than the code.
			e.Object = codeOf(apierrors.FromObject(e.Object))
		}
		select {
		case <-w.stopped:
			return
		case w.result <- e:
		}
	}
}

// ResultChan returns the channel of the watch's events, which closes when the watch ends.
func (w *withheldEvents) ResultChan() <-chan watch.Event {
	return w.result
}

// Stop stops the watch that it reads, and returns once its loop has ended.
func (w *withheldEvents) Stop() {
	w.stop.Do(func() {
		close(w.stopped)
		w.watcher.Stop()
	})
	<-w.ended
}

// List is ListWithContext, for a caller without a context.
func (w withheldAnswers) List(options metav1.ListOptions) (runtime.Object, error) {
	return w.ListWithContext(context.Background(), options)
}

// Watch is WatchWithContext, for a caller without a context.
func (w withheldAnswers) Watch(options metav1.ListOptions) (watch.Interface, error) {
	return w.WatchWithContext(context.Background(), options)
}

// withholdAnswer returns err, an answer of the spoke's API server, reduced to its code, and any other err as it is.
func withholdAnswer(err error) error {
	var answer apierrors.APIStatus
	if !errors.As(err, &answer) {
		return err
	}
	return &apierrors.StatusError{ErrStatus: *codeOf(err)}
}

// codeOf returns the Status of err, an answer of the spoke's API server, with its code alone, and the cause that the
// resource version asked for was too large, after which the reflector lists anew: no text that the spoke wrote. An
// error that is no answer gives no code.
func codeOf(err error) *metav1.Status {
	status := &metav1.Status{Status: metav1.StatusFailure}
	var answer apierrors.APIStatus
	if errors.As(err, &answer) {
		status.Code = answer.Status().Code
	}
	if apierrors.HasStatusCause(err, metav1.CauseTypeResourceVersionTooLarge) {
		status.Details = &metav1.StatusDetails{Causes: []metav1.StatusCause{
			{Type: metav1.CauseTypeResourceVersionTooLarge}}}
	}
	return status
}

// Copier copies the records of one spoke into the hub's stores (decision 0063, design 5.5), through the doors that the
// spoke's own sink and presence write through, and only what the spoke may say of itself:
//   - each streamed record of the spoke's cluster, of a type that the spoke's Collector of its source declares with the
//     scope Hub, goes into the hub's evidence store under the spoke's cluster, at the version of its collector;
//   - the entry of the spoke's cluster and identity of each image goes into the hub's inventory, with the spoke's count
//     of the workloads that run the image, of which it lists the first 100, and every namespace that it names;
//   - the labels of each of the spoke's namespaces go into a record of the hub's own, about namespace/<spoke>/<name>,
//     from the source evidence.HubSource and under the spoke's cluster, for the playbooks' namespace match of the
//     spoke's workloads; a namespace of labels that the type's schema doesn't hold is refused whole, never cut;
//   - the copy of what the spoke no longer stands for is deleted: of a record, an entry or a namespace that the spoke
//     deleted, of a type that it no longer declares with the scope Hub, and of a record that the hub's validation
//     refuses.
//
// A record or an entry of another cluster, an entry of another identity, a record of a type that the spoke doesn't
// declare with the scope Hub, and one that the hub's own validation refuses, as the spoke's sink checks it, are
// refused, counted in vexplain_spoke_records_refused_total, and logged without their data. The copier never writes a
// copy of another cluster, so a spoke can only misreport itself. Presence that the hub can't read keeps the copy that
// the hub has, as presence never forgets what it can't read (decision 0067), and so do an entry that the hub's schema
// refuses and an entry of the spoke's identity under another name, as after a rename on the spoke, until the check of
// the spoke stops the copier.
//
// The copier deletes only what its cache of the spoke, once synced, no longer holds: a cache that can't reach the spoke
// keeps what it last read, and a round that fails deletes nothing more, so a spoke that drops out keeps its copies.
type Copier struct {
	spoke, clusterID string
	// hubClusterID is the identity of the hub's own cluster, whose entries the copier never forgets.
	hubClusterID string
	hubEvidence  evidence.Store
	hubInventory inventory.Store
	spokeCache   cache.Cache
	log          logr.Logger

	// mu guards what the copier says of itself: the spoke's collectors as it last read them, as the Spoke lists them,
	// how its last round ended, if one did, whether one ended over the cache that it reads now, and when the copy last
	// became current or changed.
	mu         sync.Mutex
	collectors []configv1alpha1.SpokeCollector
	ended      bool
	failure    error
	current    bool
	copied     time.Time

	// What the last round that worked left, which only Sync reads and writes. primed says that the hub holds no copy of
	// the spoke's that the copier doesn't know: the last round worked, and so did each before it, the first of which read
	// everything.
	primed   bool
	declared map[pair]bool
	produced map[pair]bool
	records  map[string]seenRecord
	entries  map[string]seenEntry
	// namespaces holds what the last round left of each of the spoke's namespaces, by its name.
	namespaces map[string]seenRecord
}

// pair is a source and a type of the spoke's records.
type pair struct{ source, eventType string }

// seenRecord is what a round left of a record or a namespace of the spoke, by its object's name: the object's version,
// and the key of the hub's copy that stands for it, or the zero key when the hub keeps none.
type seenRecord struct {
	version string
	key     evidence.Key
}

// seenEntry is what a round left of the object of an image of the spoke: its version, and whether the hub keeps a copy
// of the spoke's entry of it.
type seenEntry struct {
	version string
	held    bool
}

// NewCopier returns the copier of the spoke of the name, whose identity the hub recorded as clusterID, which reads the
// spoke through spokeCluster, as NewCluster made it, and copies into the hub's stores hubEvidence and hubInventory.
func NewCopier(spoke, clusterID string, hubEvidence evidence.Store, hubInventory inventory.Store,
	spokeCluster cluster.Cluster) *Copier {
	return &Copier{spoke: spoke, clusterID: clusterID, hubEvidence: hubEvidence, hubInventory: hubInventory,
		spokeCache: spokeCluster.GetCache(), log: logf.Log.WithName("spoke-copier").WithValues("spoke", spoke)}
}

// Knows tells the copier the collectors that the Spoke lists, as the hub last read them, before Run or the first Sync.
// Its first round deletes the copies of each type that they produce, unless the spoke still declares the type with the
// scope Hub, so that the copies of a collector that the spoke dropped while the hub didn't follow go too.
func (c *Copier) Knows(collectors []configv1alpha1.SpokeCollector) {
	c.produced = pairsOf(collectors)
}

// HubCluster tells the copier the identity of the hub's own cluster, before Run or the first Sync. The copier never
// forgets an entry of that identity, whatever name it carries: see forget.
func (c *Copier) HubCluster(id string) {
	c.hubClusterID = id
}

// UseCluster has the copier read the spoke through another cache of the same cluster, as NewCluster made it for a new
// config, such as one with a renewed token. The copier keeps what it knows of its copies: its next round copies only
// what changed meanwhile, and deletes the copies of what the spoke deleted. Until a round ends over the new cache,
// Synced says that none has. Call it while the copier doesn't run.
func (c *Copier) UseCluster(spokeCluster cluster.Cluster) {
	c.spokeCache = spokeCluster.GetCache()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.current = false
}

// Collectors returns the spoke's collectors as the copier last read them, as the Spoke lists them, or nil before it
// read them. The caller may change what it gets.
func (c *Copier) Collectors() []configv1alpha1.SpokeCollector {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.collectors == nil {
		return nil
	}
	listed := make([]configv1alpha1.SpokeCollector, len(c.collectors))
	for i := range c.collectors {
		c.collectors[i].DeepCopyInto(&listed[i])
	}
	return listed
}

// Synced reports whether the copier's last round worked, and else why it failed, or nil before a round ended. current
// says whether a round has ended over the cache that the copier reads now: a copier that goes on over a new cache
// reports the last round over its former one until then.
func (c *Copier) Synced() (synced, current bool, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ended && c.failure == nil, c.current, c.failure
}

// Copied returns when the last round ended that made the copy current, as the first that works over a cache does, or
// the first after one that failed, or that copied a change of the spoke, or deleted a copy of what the spoke deleted.
// It is the zero time before such a round. A round that finds nothing new leaves it.
func (c *Copier) Copied() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.copied
}

// Run copies the spoke's records until ctx ends, and returns nil then. It runs a round of Sync once the cache of the
// spoke has synced, and again after each change that the cache sees, a moment after it, so that the changes of a burst
// go in one round, or after a pause that grows to a minute while rounds fail. It calls changed after each round that
// changed what Synced or Collectors return. Start the cache of the spoke beside it.
func (c *Copier) Run(ctx context.Context, changed func()) error {
	queue := workqueue.NewTypedRateLimitingQueue(
		workqueue.NewTypedItemExponentialFailureRateLimiter[string](firstRetry, maxRetry))
	defer queue.ShutDown()
	// While rounds fail, the next waits for its pause: a change on the spoke doesn't hurry it.
	var failing atomic.Bool
	soon := func() {
		if !failing.Load() {
			queue.AddAfter(round, pause)
		}
	}
	for _, obj := range []client.Object{&inventoryv1alpha1.Evidence{}, &inventoryv1alpha1.ImageInventory{},
		&configv1alpha1.Collector{}, namespaceMetadata()} {
		// A kind that the spoke doesn't let the hub list would hold the watches of the kinds after it: each round waits
		// for every kind's sync instead.
		informer, err := c.spokeCache.GetInformer(ctx, obj, cache.BlockUntilSynced(false))
		if err != nil {
			return fmt.Errorf("watch the spoke's %T: %w", obj, err)
		}
		if _, err := informer.AddEventHandler(toolscache.ResourceEventHandlerFuncs{
			AddFunc: func(any) { soon() }, UpdateFunc: func(any, any) { soon() }, DeleteFunc: func(any) { soon() },
		}); err != nil {
			return fmt.Errorf("watch the spoke's %T: %w", obj, err)
		}
	}
	queue.Add(round)
	defer context.AfterFunc(ctx, queue.ShutDown)()
	for {
		item, shutdown := queue.Get()
		if shutdown {
			return nil
		}
		before := c.outcome()
		if err := c.Sync(ctx); err != nil && ctx.Err() == nil {
			c.log.Error(err, "Could not copy the spoke's records; the copier tries again after a pause")
			failing.Store(true)
			queue.AddRateLimited(item)
		} else {
			failing.Store(false)
			queue.Forget(item)
		}
		queue.Done(item)
		if after := c.outcome(); after.synced != before.synced || after.current != before.current ||
			after.failure != before.failure || !equality.Semantic.DeepEqual(after.collectors, before.collectors) {
			changed()
		}
	}
}

// outcome is what the copier says of itself, which Run compares before and after a round.
type outcome struct {
	synced, current bool
	failure         string
	collectors      []configv1alpha1.SpokeCollector
}

// outcome returns what the copier says of itself now.
func (c *Copier) outcome() outcome {
	synced, current, err := c.Synced()
	o := outcome{synced: synced, current: current, collectors: c.Collectors()}
	if err != nil {
		o.failure = err.Error()
	}
	return o
}

// Sync runs a round of copying. A round waits until the cache of the spoke has synced, copies what changed on the spoke
// since the last round, and deletes the copies of what the spoke no longer holds. A record, an entry or a namespace that
// didn't change since the last round is left as it is. The first round, and a round after one that failed or after the
// spoke's Collectors changed which types they declare with the scope Hub, reads every record, entry and namespace
// instead, and deletes every copy of the spoke's cluster that the spoke doesn't stand for: of each source and type that
// the spoke's Collectors produce, or produced as the copier knew them, of the namespaces that the spoke doesn't hold,
// and the cluster's entry of each image that the spoke doesn't run. A round stops at the first write that fails. A
// round that ctx cuts short, as the end of its run does, leaves what Synced says, since the copies didn't fall behind
// for it. Once it began to write, the next round reads everything, as after a round that failed, since it may have made
// a copy that the copier doesn't know of. Sync isn't for two calls at the same time.
func (c *Copier) Sync(ctx context.Context) (err error) {
	copied := tally{records: map[string]int{}}
	defer func() {
		if err != nil && ctx.Err() != nil {
			return
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		if err == nil && (!c.ended || c.failure != nil || !c.current || copied.any()) {
			c.copied = time.Now()
		}
		c.ended, c.failure, c.current = true, err, true
	}()
	if !c.spokeCache.WaitForCacheSync(ctx) {
		return errNotSynced
	}
	declared, produced, listed, err := c.readCollectors(ctx)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.collectors = listed
	c.mu.Unlock()
	full := !c.primed || !maps.Equal(declared, c.declared)
	c.primed = false
	records, err := c.copyRecords(ctx, declared, full, &copied)
	if err != nil {
		return err
	}
	if full {
		pairs := maps.Clone(produced)
		maps.Copy(pairs, c.produced)
		err = c.prune(ctx, records, pairs)
	} else {
		err = c.deleteGone(ctx, c.records, records, &copied)
	}
	if err != nil {
		return err
	}
	entries, err := c.copyEntries(ctx, full, &copied)
	if err != nil {
		return err
	}
	namespaces, err := c.copyNamespaces(ctx, full, &copied)
	if err != nil {
		return err
	}
	c.declared, c.produced, c.records, c.entries, c.namespaces = declared, produced, records, entries, namespaces
	c.primed = true
	copied.report(c.log, full)
	return nil
}

// readCollectors reads the spoke's Collectors: the types that each declares with the scope Hub, every type that each
// produces, and the collectors as the Spoke lists them, by name. A Collector whose name can't be a record's source, as
// isCollectorName says, is left out, since the hub takes none of its records.
func (c *Copier) readCollectors(ctx context.Context) (declared, produced map[pair]bool,
	listed []configv1alpha1.SpokeCollector, err error) {
	var list configv1alpha1.CollectorList
	if err := c.spokeCache.List(ctx, &list); err != nil {
		return nil, nil, nil, fmt.Errorf("list the spoke's Collectors: %w", err)
	}
	slices.SortFunc(list.Items, func(a, b configv1alpha1.Collector) int { return cmp.Compare(a.Name, b.Name) })
	declared, produced, listed = map[pair]bool{}, map[pair]bool{}, []configv1alpha1.SpokeCollector{}
	for i := range list.Items {
		collector := &list.Items[i]
		if !isCollectorName(collector.Name) {
			continue
		}
		listed = append(listed, listedOf(collector))
		if collector.Status.Capabilities == nil {
			continue
		}
		for _, p := range collector.Status.Capabilities.Produces {
			produced[pair{collector.Name, p.Type}] = true
			if p.Scope == configv1alpha1.EvidenceScopeHub {
				declared[pair{collector.Name, p.Type}] = true
			}
		}
	}
	// shortcut: a spoke with more Collectors than a Spoke lists has the others copied and not listed, so their
	// evidence counts in no producer of the hub's; list them elsewhere if a fleet needs more.
	return declared, produced, listed[:min(len(listed), maxListedCollectors)], nil
}

// listedOf returns a collector as its Spoke lists it: its name, its version and whether it is Ready, and its
// capabilities, each type that it produces with the maxAge that applies to its evidence, its spec.produces override
// included, which the hub reads for the freshness of the spoke's records.
func listedOf(collector *configv1alpha1.Collector) configv1alpha1.SpokeCollector {
	listed := configv1alpha1.SpokeCollector{Name: collector.Name, Capabilities: collector.Status.Capabilities.DeepCopy()}
	// A Spoke takes no empty version.
	if version := ptr.Deref(collector.Status.Version, ""); version != "" {
		listed.Version = &version
	}
	if ready := meta.FindStatusCondition(collector.Status.Conditions, configv1alpha1.ConditionReady); ready != nil {
		listed.Ready = ptr.To(ready.Status)
	}
	if listed.Capabilities != nil {
		for i := range listed.Capabilities.Produces {
			produced := &listed.Capabilities.Produces[i]
			produced.MaxAgeSeconds = nil
			if maxAge := collectorclient.MaxAge(collector, produced.Type); maxAge > 0 {
				produced.MaxAgeSeconds = ptr.To(int64(maxAge / time.Second))
			}
		}
	}
	return listed
}

// copyRecords copies each of the spoke's records whose object changed since the last round, or each when full says so,
// and returns what the round leaves of them all.
func (c *Copier) copyRecords(ctx context.Context, declared map[pair]bool, full bool, copied *tally) (
	map[string]seenRecord, error) {
	var list inventoryv1alpha1.EvidenceList
	// The objects are only read, and none leaves the copier, so the cache needn't copy them.
	if err := c.spokeCache.List(ctx, &list, client.UnsafeDisableDeepCopy); err != nil {
		return nil, fmt.Errorf("list the spoke's records: %w", err)
	}
	records := make(map[string]seenRecord, len(list.Items))
	for i := range list.Items {
		obj := &list.Items[i]
		if before, ok := c.records[obj.Name]; ok && !full && before.version == obj.ResourceVersion {
			records[obj.Name] = before
			continue
		}
		key, err := c.copyRecord(ctx, obj, declared, copied)
		if err != nil {
			return nil, err
		}
		records[obj.Name] = seenRecord{version: obj.ResourceVersion, key: key}
	}
	return records, nil
}

// copyRecord copies the record of the spoke that obj holds, and returns the key of the hub's copy that stands for it,
// or the zero key when the hub keeps none: of a record that it refuses, but for presence that it can't read, or of
// another cluster, whose copies the copier never touches.
func (c *Copier) copyRecord(ctx context.Context, obj *inventoryv1alpha1.Evidence, declared map[pair]bool,
	copied *tally) (evidence.Key, error) {
	key := evidence.Key{Subject: obj.Spec.Subject, Type: obj.Spec.Type, Source: obj.Spec.Source,
		Cluster: ptr.Deref(obj.Spec.Cluster, "")}
	switch {
	case key.Cluster != c.spoke:
		// Its label names the spoke's cluster, and its key another.
		c.refuseRecord(refusedCluster, key)
		return evidence.Key{}, nil
	case !isCollectorName(key.Source):
		// The hub's store takes no such source, so the hub holds no copy of it either; or the hub keeps its own records
		// under it, which no record of the spoke's replaces.
		c.refuseRecord(refusedInvalid, key)
		return evidence.Key{}, nil
	case !declared[pair{key.Source, key.Type}]:
		c.refuseRecord(refusedScope, key)
		return evidence.Key{}, c.hubEvidence.Delete(ctx, key)
	}
	record, err := evidence.RecordOf(obj)
	if err == nil {
		err = checkCore(record.Event)
	}
	if err != nil {
		return c.refuseUnread(ctx, key)
	}
	return c.put(ctx, key, record.CollectorVersion, record.Event, copied)
}

// put puts the event into the hub's evidence store as the record of key, from the source of key and under the spoke's
// cluster, at the version, and returns key, or the zero key when the hub refuses it: a record that the hub's checks or
// its API server refuse is counted, and has the copy that the hub held deleted, but for presence, as refuseUnread says.
func (c *Copier) put(ctx context.Context, key evidence.Key, version string, e cloudevents.Event, copied *tally) (
	evidence.Key, error) {
	err := c.hubEvidence.Put(ctx, key.Source, version, e, evidence.InCluster(c.spoke))
	switch {
	case apierrors.IsInvalid(err), apierrors.IsBadRequest(err):
		// The hub's API server refuses it, as one of a schema that the store's own checks don't know: it would at every
		// round, and its text quotes the record.
		return c.refuseUnread(ctx, key)
	case errors.Is(err, evidence.ErrRefused), errors.Is(err, evidence.ErrTooLarge):
		// As the spoke's sink has it, the hub reads no older record as what the collector says now.
		c.refuseRecord(refusedInvalid, key)
		return evidence.Key{}, c.hubEvidence.Delete(ctx, key)
	case err != nil:
		return evidence.Key{}, err
	}
	copied.records[key.Type]++
	return key, nil
}

// refuseUnread refuses, as invalid, a record of the spoke that the hub can't read, or that its API server refuses, by
// its type's rule (decision 0067): presence keeps the copy that the hub has, since presence never forgets what it can't
// read, and any other type has its copy deleted, so that what the hub holds of it reads as missing, never as older
// evidence. It returns the key of the copy that the hub keeps, or the zero key.
func (c *Copier) refuseUnread(ctx context.Context, key evidence.Key) (evidence.Key, error) {
	c.refuseRecord(refusedInvalid, key)
	if key.Type == sdkevidence.TypePresence {
		return key, nil
	}
	return evidence.Key{}, c.hubEvidence.Delete(ctx, key)
}

// prune deletes the hub's copies of the spoke's records, of each source and type of pairs, that no record of the round
// stands for.
func (c *Copier) prune(ctx context.Context, records map[string]seenRecord, pairs map[pair]bool) error {
	held := make(map[evidence.Key]bool, len(records))
	for _, r := range records {
		if r.key != (evidence.Key{}) {
			held[r.key] = true
		}
	}
	for p := range pairs {
		if err := c.hubEvidence.DeleteStreamed(ctx, c.spoke, p.source, p.eventType,
			func(k evidence.Key) bool { return held[k] }); err != nil {
			return err
		}
	}
	return nil
}

// deleteGone deletes the hub's copy of each record or namespace that the last round left, as before holds them, and
// that the spoke no longer holds, as this round leaves them in now, and counts each in copied.
func (c *Copier) deleteGone(ctx context.Context, before, now map[string]seenRecord, copied *tally) error {
	for name, was := range before {
		if _, still := now[name]; !still && was.key != (evidence.Key{}) {
			if err := c.hubEvidence.Delete(ctx, was.key); err != nil {
				return err
			}
			copied.deleted++
		}
	}
	return nil
}

// copyEntries copies the spoke's entry of each image whose object changed since the last round, or of each when full
// says so, and deletes the cluster's entry of each image that the spoke no longer runs: of each image of the hub's when
// full says so. It returns what the round leaves of the spoke's images.
func (c *Copier) copyEntries(ctx context.Context, full bool, copied *tally) (map[string]seenEntry, error) {
	var list inventoryv1alpha1.ImageInventoryList
	// The objects are only read, and none leaves the copier, so the cache needn't copy them.
	if err := c.spokeCache.List(ctx, &list, client.UnsafeDisableDeepCopy); err != nil {
		return nil, fmt.Errorf("list the spoke's images: %w", err)
	}
	entries := make(map[string]seenEntry, len(list.Items))
	for i := range list.Items {
		obj := &list.Items[i]
		if before, ok := c.entries[obj.Spec.Digest]; ok && !full && before.version == obj.ResourceVersion {
			entries[obj.Spec.Digest] = before
			continue
		}
		held, err := c.copyEntry(ctx, obj, copied)
		if err != nil {
			return nil, err
		}
		entries[obj.Spec.Digest] = seenEntry{version: obj.ResourceVersion, held: held}
	}
	gone := slices.Collect(maps.Keys(c.entries))
	if full {
		// shortcut: reads each image's object of the hub's to find the cluster's entries, which costs a read per image
		// at each round that reads everything; a door that lists a cluster's images replaces it if the measurement
		// (design 5.13) shows the cost.
		all, err := c.hubInventory.Digests(ctx)
		if err != nil {
			return nil, err
		}
		gone = all
	}
	for _, digest := range gone {
		if !entries[digest].held && (full || c.entries[digest].held) {
			if err := forget(ctx, c.hubInventory, c.spoke, c.hubClusterID, digest); err != nil {
				return nil, err
			}
			// A round that reads everything looks at every image of the hub's, of which most have no entry to forget.
			if !full {
				copied.deleted++
			}
		}
	}
	return entries, nil
}

// copyEntry copies the spoke's entry of the image that obj holds, and reports whether the hub keeps a copy of it: of
// the entry of the spoke's cluster and identity, unless the hub's schema refused one that it didn't hold before. Any
// other entry is refused. An entry of the spoke's identity under another name, as the spoke's presence writes it once
// the spoke renamed its cluster, keeps the hub's copy: the check of the spoke stops the copier then
// (ClusterNameMismatch), and the cluster's images never read as running nowhere in between.
func (c *Copier) copyEntry(ctx context.Context, obj *inventoryv1alpha1.ImageInventory, copied *tally) (bool, error) {
	held := false
	for i := range obj.Status.Clusters {
		entry := &obj.Status.Clusters[i]
		switch {
		case entry.Cluster != c.spoke:
			c.refuseEntry(refusedCluster, obj.Spec.Digest)
			held = held || entry.ClusterID == c.clusterID
		case entry.ClusterID != c.clusterID:
			c.refuseEntry(refusedClusterID, obj.Spec.Digest)
		default:
			switch err := c.hubInventory.Observe(ctx, obj.Spec.Digest, observationOf(obj, entry)); {
			case apierrors.IsInvalid(err), apierrors.IsBadRequest(err):
				// The hub keeps the copy that it has, as presence keeps what it can't read (decision 0067).
				c.refuseEntry(refusedInvalid, obj.Spec.Digest)
			case err != nil:
				return false, err
			default:
				copied.entries++
			}
			held = true
		}
	}
	return held, nil
}

// observationOf returns what a spoke's entry of the image that obj holds says, for the hub's copy of it: the spoke's
// count of the workloads, of which the entry lists the first 100, and every namespace that it names.
func observationOf(obj *inventoryv1alpha1.ImageInventory,
	entry *inventoryv1alpha1.ClusterPresence) inventory.Observation {
	obs := inventory.Observation{
		Cluster:        entry.Cluster,
		ClusterID:      entry.ClusterID,
		DigestKind:     ptr.Deref(obj.Status.DigestKind, ""),
		Repositories:   entry.Repositories,
		Platforms:      entry.Platforms,
		NamespaceCount: ptr.Deref(entry.NamespaceCount, 0),
		MaxNamespaces:  maxCopiedNamespaces,
		Exposure:       ptr.Deref(entry.Exposure, ""),
		WorkloadCount:  ptr.Deref(entry.WorkloadCount, 0),
	}
	for _, w := range entry.Workloads {
		obs.Workloads = append(obs.Workloads, workloads.WorkloadRef{APIGroup: ptr.Deref(w.APIGroup, ""), Kind: w.Kind,
			Namespace: w.Namespace, Name: w.Name})
	}
	for _, n := range entry.Namespaces {
		counts := n.WorkloadsByExposure
		obs.Namespaces = append(obs.Namespaces, inventory.NamespaceObservation{Name: n.Name, Owner: n.Owner,
			ByExposure: map[inventoryv1alpha1.SSVCExposure]int32{
				inventoryv1alpha1.SSVCExposureOpen:       ptr.Deref(counts.Open, 0),
				inventoryv1alpha1.SSVCExposureControlled: ptr.Deref(counts.Controlled, 0),
				inventoryv1alpha1.SSVCExposureSmall:      ptr.Deref(counts.Small, 0),
				inventoryv1alpha1.SSVCExposureUnknown:    ptr.Deref(counts.Unknown, 0),
			}})
	}
	return obs
}

// refuseRecord counts a record of the spoke that the hub doesn't copy, for the reason, and logs it by its key, without
// its data or any text that refused it.
func (c *Copier) refuseRecord(reason string, k evidence.Key) {
	metrics.SpokeRecordsRefusedTotal.WithLabelValues(c.spoke, reason).Inc()
	c.log.Info("The hub refuses to copy a record of the spoke", "reason", reason, "subject", k.Subject, "type", k.Type,
		"source", k.Source, "cluster", k.Cluster)
}

// refuseEntry counts the entry of an image of the spoke that the hub doesn't copy, for the reason, and logs it without
// its data.
func (c *Copier) refuseEntry(reason, digest string) {
	metrics.SpokeRecordsRefusedTotal.WithLabelValues(c.spoke, reason).Inc()
	c.log.Info("The hub refuses to copy the entry of an image of the spoke", "reason", reason, "digest", digest)
}

// tally counts what a round copied: the records by type, and the entries, and the copies of what the spoke deleted that
// a round that follows the spoke's changes deleted.
type tally struct {
	records map[string]int
	entries int
	deleted int
}

// any says whether the round copied anything, or deleted a copy of what the spoke deleted.
func (t *tally) any() bool {
	return len(t.records) > 0 || t.entries > 0 || t.deleted > 0
}

// report logs what a round copied, if it copied anything: at the default level after a round that read everything, and
// verbosely after the others, which follow the spoke's changes.
func (t *tally) report(log logr.Logger, full bool) {
	if !t.any() {
		return
	}
	if !full {
		log = log.V(1)
	}
	log.Info("Copied the spoke's records into the hub's stores", "records", t.records, "entries", t.entries,
		"deleted", t.deleted)
}

// DeleteCopies deletes every copy of the spoke's records in the hub's stores, as when its Spoke is deleted: the records
// of the spoke's cluster of each source and type that the collectors produce, as the Spoke listed them or a copier last
// read them, the hub's records of the spoke's namespaces, and the cluster's entry of each image, with the image's object
// when no other cluster runs it. It forgets no entry of hubClusterID, the identity of the hub's own cluster: see forget.
func DeleteCopies(ctx context.Context, hubEvidence evidence.Store, hubInventory inventory.Store,
	spoke, hubClusterID string, collectors []configv1alpha1.SpokeCollector) error {
	// shortcut: the copies of a type of a collector that the copier copied just before the hub stopped, and that the
	// spoke dropped before the hub listed it, stay; that takes a stop between a copy and the next write of the Spoke's
	// status. Delete by the cluster's label alone if it shows.
	pairs := pairsOf(collectors)
	pairs[namespacePair] = true
	for p := range pairs {
		if err := hubEvidence.DeleteStreamed(ctx, spoke, p.source, p.eventType, nil); err != nil {
			return err
		}
	}
	digests, err := hubInventory.Digests(ctx)
	if err != nil {
		return err
	}
	for _, digest := range digests {
		if err := forget(ctx, hubInventory, spoke, hubClusterID, digest); err != nil {
			return err
		}
	}
	return nil
}

// forget deletes the spoke's entry of the image from the hub's inventory: the entry under the spoke's name, unless it
// has hubClusterID, the identity of the hub's own cluster. Such an entry is the hub's own, from before its cluster was
// renamed away from the spoke's name: the hub's presence moves it to the new name only as it next reconciles the image,
// and forgetting it would take the image's object, with its facts, if it was the last entry. forget names the entry by
// the spoke's name alone, which every copy carries, and by no identity, which no entry lacks: an identity could be
// another cluster's too, as when two Spokes name the same cluster.
func forget(ctx context.Context, hubInventory inventory.Store, spoke, hubClusterID, digest string) error {
	obj, err := hubInventory.Get(ctx, digest)
	if err != nil || obj == nil {
		return err
	}
	i := slices.IndexFunc(obj.Status.Clusters, func(e inventoryv1alpha1.ClusterPresence) bool {
		return e.Cluster == spoke
	})
	if i < 0 || obj.Status.Clusters[i].ClusterID == hubClusterID {
		return nil
	}
	return hubInventory.Forget(ctx, digest, spoke, "")
}

// pairsOf returns each source and type that the collectors produce, as a Spoke lists them.
func pairsOf(collectors []configv1alpha1.SpokeCollector) map[pair]bool {
	pairs := map[pair]bool{}
	for _, collector := range collectors {
		if !isCollectorName(collector.Name) || collector.Capabilities == nil {
			continue
		}
		for _, p := range collector.Capabilities.Produces {
			pairs[pair{collector.Name, p.Type}] = true
		}
	}
	return pairs
}

// isCollectorName says whether name can be the name of a Collector, and so a record's source: a DNS-1123 label of at
// most 44 characters, as their schemas have it, and not evidence.HubSource, under which the hub keeps its own records of
// the spoke's namespaces: a Collector of the spoke of that name would have its records replace them, and its types
// delete them. The hub checks it, since a spoke's API server is the spoke's to run, and the hub's evidence store deletes
// by no other source.
func isCollectorName(name string) bool {
	return name != evidence.HubSource && len(name) <= maxCollectorName && len(validation.IsDNS1123Label(name)) == 0
}

// coreSchemas are the SDK's schemas of presence, exposure and a namespace's labels, which the hub reads without a
// schema of their own, and coreSubjects the kind of subject that each is about.
var (
	coreSchemas = map[string]*jsonschema.Schema{
		sdkevidence.TypePresence:  compileSchema(sdkevidence.TypePresence),
		sdkevidence.TypeExposure:  compileSchema(sdkevidence.TypeExposure),
		sdkevidence.TypeNamespace: compileSchema(sdkevidence.TypeNamespace),
	}
	coreSubjects = map[string]subject.Kind{
		sdkevidence.TypePresence:  subject.KindImage,
		sdkevidence.TypeExposure:  subject.KindWorkload,
		sdkevidence.TypeNamespace: subject.KindNamespace,
	}
)

// errOffSchema says that evidence of a type of coreSchemas isn't about its kind of subject, or that its data doesn't
// follow the core's schema. It stands for the schema's own errors, which quote the data.
var errOffSchema = errors.New("the evidence doesn't follow the core's schema of its type")

// checkCore checks presence and exposure as the spoke's sink checks them before it stores them for the hub, and the
// labels of a namespace, which the hub copies itself: each is about its kind of subject, and its data follows the
// core's schema. Evidence of any other type passes.
func checkCore(e cloudevents.Event) error {
	core, ok := coreSchemas[e.Type()]
	if !ok {
		return nil
	}
	about, err := subject.Parse(e.Subject())
	if err != nil || about.Kind != coreSubjects[e.Type()] {
		return errOffSchema
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(e.Data()))
	if err != nil || core.Validate(doc) != nil {
		return errOffSchema
	}
	return nil
}

// compileSchema compiles the SDK's schema of the type. The SDK embeds it, so a failure is a defect of the build.
func compileSchema(eventType string) *jsonschema.Schema {
	raw, _ := sdkevidence.Schema(eventType)
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		panic(fmt.Sprintf("the SDK's schema of %s isn't JSON: %v", eventType, err))
	}
	compiler := jsonschema.NewCompiler()
	location := "urn:vexplain:schema:" + eventType
	if err := compiler.AddResource(location, doc); err != nil {
		panic(fmt.Sprintf("the SDK's schema of %s can't be added: %v", eventType, err))
	}
	return compiler.MustCompile(location)
}
