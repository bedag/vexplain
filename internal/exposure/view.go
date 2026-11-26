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

// Package exposure is the hub's side of exposure (design of entry points, sections 5.5 and 5.8): a view of what the
// clusters stream to the hub's store about the workloads that run each image and how far each can be reached, with
// the sources' answers about the entry points, and the asker, which asks the sources about the entry points and keeps
// their answers current.
package exposure

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/bedag/vexplain/internal/evidence"
	"github.com/bedag/vexplain/internal/metrics"
	"github.com/bedag/vexplain/internal/settings"
	sdkevidence "github.com/bedag/vexplain/sdk/evidence"
	"github.com/bedag/vexplain/sdk/subject"
)

// viewWorkers is how many subjects the view reads at once. Each read gets a subject's records from the API server, and
// after a start the view reads every subject that the store holds.
const viewWorkers = 4

// Record is a record that the view holds: the name of the Collector that delivered it, the source, the time and the
// coverage of its event, and its data, decoded from JSON as encoding/json decodes it into an any. EventSource is what a
// rule reads as an input's source, as it reads the source of evidence about a manifest.
type Record struct {
	Source      string
	EventSource string
	Time        time.Time
	Coverage    *int32
	Data        any
}

// View holds in memory what the hub reads of exposure from the evidence store: presence, which names the workloads
// that run each image in the cluster that streamed it; exposure, which names each workload's entry points; every record
// about a host or an address, which are the sources' answers; and the labels of each spoke's namespaces, which the hub
// copies (decision 0063). It keeps the data of exposure and of the answers as JSON, and decodes it when asked, and
// keeps presence decoded, which the remote renderer reads of each remote cluster (design of remote spokes 5.9).
//
// The store's reads of evidence go to the API server, so the view saves the hub a read of every workload of every case
// at each pass of the investigations. It is fed by the store's watch, and is safe for concurrent use.
type View struct {
	store evidence.Store
	// changed holds a value when the view changed since the asker last took it.
	changed chan struct{}
	// cluster returns the name of this cluster, which labels the count of failed reads, or "" when it can't be read.
	// It is nil for a view that SetupWithManager didn't set up, which counts nothing.
	cluster func(context.Context) string
	// told are told of each subject that the view holds anew: OnChange sets them before the manager starts.
	told []func(about string)

	mu sync.RWMutex
	// bySubject holds the records about each subject that the view keeps, in the order of ListBySubject. A subject's
	// slice is replaced whole, and never changed in place, so a reader may use it after it unlocks.
	bySubject map[string][]held
	// seen holds the subjects read before the first list, and pending those of the first list not read since: seen is
	// nil from the first list on, and pending nil before it.
	seen, pending map[string]bool
	synced        bool
	// exposureChanges counts the holds of a workload's subject, whose records are the exposure. ambiguous is what
	// Ambiguous computed at the count ambiguousAt, and is replaced whole, never changed in place.
	exposureChanges, ambiguousAt uint64
	ambiguous                    map[string][]string
	// presenceChanges counts, by cluster, the holds of an image's subject that changed what the cluster's records of
	// presence say of the image.
	presenceChanges map[string]uint64
}

// held is a record that the view keeps, with what it reads of the data at once: presence and the workload subjects that
// it names, the entry-point subjects and the number of unchecked reasons of exposure, or the labels of a namespace. It
// keeps the data of exposure and of the answers, which the rules read, as JSON, and none of a namespace, whose labels
// are all that the hub reads of it.
type held struct {
	evidence.Key
	// source, time and coverage are those of the record's event, and coverage is nil where it has none.
	source   string
	time     time.Time
	coverage *int32
	data     []byte
	// presence is what presence says, with only the workloads of the cluster that streamed it, which never changes
	// once held.
	presence  *sdkevidence.Presence
	workloads []string
	points    []string
	unchecked int
	labels    map[string]string
}

// NewView returns a view of the evidence in store. SetupWithManager feeds it.
func NewView(store evidence.Store) *View {
	return &View{store: store, changed: make(chan struct{}, 1), bySubject: map[string][]held{},
		seen: map[string]bool{}, presenceChanges: map[string]uint64{}}
}

// SetupWithManager reads the store into the view with a controller over the store's watch, and lists the store's
// subjects once the manager's caches have synced, so that Synced knows what there is to read. Both run on the leader,
// as the controllers that read the view do. The count of failed reads takes the cluster's name from the OperatorConfig
// in the manager's cache, at each failure, so that it follows a rename.
func (v *View) SetupWithManager(mgr ctrl.Manager) error {
	v.cluster = func(ctx context.Context) string {
		effective, err := settings.Load(ctx, mgr.GetClient())
		if err != nil {
			return ""
		}
		return effective.ClusterName
	}
	if err := mgr.Add(manager.RunnableFunc(v.firstList)); err != nil {
		return fmt.Errorf("add the first list of the view of exposure: %w", err)
	}
	return ctrl.NewControllerManagedBy(mgr).
		Named("hub-exposure-view").
		WithOptions(controller.Options{MaxConcurrentReconciles: viewWorkers}).
		WatchesRawSource(v.store.Source()).
		Complete(v)
}

// Reconcile reads the records about the subject of the request into the view, when the view keeps any of its kind.
//
// A read that fails, such as one of a record that can't be decoded, leaves the subject without records in the view,
// which counts as missing evidence, the safe side, and counts as read for Synced, so that it never holds up the cases
// that wait for the view. The failure is counted, and the controller logs its error, which names no data, and reads the
// subject again with its back-off, and at its next change. A record that is read, and isn't what its type says, is
// left out, whole or in part, counted, and logged by its key.
func (v *View) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	about := req.Name
	if !keeps(about) {
		return reconcile.Result{}, nil
	}
	records, err := v.store.ListBySubject(ctx, about)
	if err != nil {
		// shortcut: a read fails as a whole, so a record that can't be decoded takes the subject's other records with it;
		// a store method that lists a subject's records without decoding them would let the view leave out that one.
		v.countFailure(ctx)
		v.hold(about, nil)
		return reconcile.Result{}, fmt.Errorf("read the evidence about %s: %w", about, err)
	}
	var kept []held
	for i := range records {
		h, keep, problem := holdOf(&records[i])
		if problem != nil {
			k := records[i].Key
			v.countFailure(ctx)
			logf.FromContext(ctx).Error(problem, "The view of exposure leaves out evidence that isn't what its type says",
				"subject", k.Subject, "type", k.Type, "source", k.Source, "cluster", k.Cluster)
		}
		if keep {
			kept = append(kept, h)
		}
	}
	v.hold(about, kept)
	return reconcile.Result{}, nil
}

// hold makes kept the records about the subject in the view, notes that the subject was read, and tells those that
// OnChange set. It wakes the asker for a workload's exposure and for the answers about a host or an address, and when
// the view becomes synced. Presence, which changes with every pod that starts or stops, and a namespace's labels never
// wake it: the asker reads neither.
func (v *View) hold(about string, kept []held) {
	workload := strings.HasPrefix(about, string(subject.KindWorkload)+"/")
	v.mu.Lock()
	if strings.HasPrefix(about, string(subject.KindImage)+"/") {
		v.countPresenceChanges(v.bySubject[about], kept)
	}
	if len(kept) == 0 {
		delete(v.bySubject, about)
	} else {
		v.bySubject[about] = kept
	}
	if workload {
		v.exposureChanges++
	}
	synced := v.read(about)
	v.mu.Unlock()
	if synced || workload || isEntryPoint(about) {
		v.notify()
	}
	for _, f := range v.told {
		f(about)
	}
}

// countPresenceChanges moves the count of each cluster whose records of presence say another thing of an image in kept
// than they did in before: a record of another cluster about the same image moves none of it. v.mu is held.
func (v *View) countPresenceChanges(before, kept []held) {
	byCluster := func(records []held) map[string][]sdkevidence.Presence {
		out := map[string][]sdkevidence.Presence{}
		for _, h := range records {
			if h.Type == sdkevidence.TypePresence {
				out[h.Cluster] = append(out[h.Cluster], *h.presence)
			}
		}
		return out
	}
	was := byCluster(before)
	for cluster, now := range byCluster(kept) {
		if !reflect.DeepEqual(was[cluster], now) {
			v.presenceChanges[cluster]++
		}
		delete(was, cluster)
	}
	// What remains is of the clusters whose records of the image went.
	for cluster := range was {
		v.presenceChanges[cluster]++
	}
}

// OnChange has f told of each subject whose records the view holds anew, once a reader of the view sees them, so that
// what reads the view can look again at what the change concerns. f runs on the view's controller, so it must not
// block. Call it before the manager starts.
func (v *View) OnChange(f func(about string)) {
	v.told = append(v.told, f)
}

// countFailure counts a failed read, or a record that the view left out, whole or in part. A cluster whose name can't
// be read just now gets no series, so the failure isn't counted, but it is logged all the same.
func (v *View) countFailure(ctx context.Context) {
	if v.cluster == nil {
		return
	}
	if cluster := v.cluster(ctx); cluster != "" {
		metrics.ExposureViewReadFailuresTotal.WithLabelValues(cluster).Inc()
	}
}

// read notes that the subject was read, and reports whether that made the view synced. v.mu is held.
func (v *View) read(about string) bool {
	switch {
	case v.synced:
		return false
	case v.pending == nil:
		v.seen[about] = true
		return false
	default:
		delete(v.pending, about)
		v.synced = len(v.pending) == 0
		return v.synced
	}
}

// firstList lists the subjects that the store holds, through the cache that its watch fills, which a list waits for:
// those that the view keeps and hasn't read yet are what it reads before it is synced. A list that fails is tried
// again until ctx ends.
func (v *View) firstList(ctx context.Context) error {
	var subjects []string
	if err := wait.PollUntilContextCancel(ctx, resync, true, func(ctx context.Context) (bool, error) {
		listed, err := v.store.Subjects(ctx)
		if err != nil {
			logf.FromContext(ctx).Error(err, "Could not list the subjects of the evidence for the view of exposure; trying again")
			return false, nil
		}
		subjects = listed
		return true, nil
	}); err != nil {
		return nil // The manager is stopping.
	}
	v.mu.Lock()
	v.pending = map[string]bool{}
	for _, s := range subjects {
		if keeps(s) && !v.seen[s] {
			v.pending[s] = true
		}
	}
	v.seen = nil
	v.synced = len(v.pending) == 0
	v.mu.Unlock()
	v.notify()
	return nil
}

// notify tells the asker that the view changed, without waiting for it.
func (v *View) notify() {
	select {
	case v.changed <- struct{}{}:
	default:
	}
}

// keeps reports whether the view keeps records about the subject: an image's presence, a workload's exposure, a
// namespace's labels, and anything about a host or an address.
func keeps(about string) bool {
	parsed, err := subject.Parse(about)
	if err != nil {
		return false
	}
	switch parsed.Kind {
	case subject.KindImage, subject.KindWorkload, subject.KindHost, subject.KindAddress, subject.KindNamespace:
		return true
	}
	return false
}

// isEntryPoint reports whether a subject that the view keeps is a host or an address.
func isEntryPoint(about string) bool {
	return strings.HasPrefix(about, string(subject.KindHost)+"/") || strings.HasPrefix(about, string(subject.KindAddress)+"/")
}

// Why the view leaves out evidence that it reads, in fixed texts that repeat nothing of the data.
var (
	errNotPresence  = errors.New("the data isn't presence")
	errNotExposure  = errors.New("the data isn't exposure")
	errNotNamespace = errors.New("the data isn't the labels of a namespace")
	errNotJSON      = errors.New("the data isn't JSON")
	errOtherCluster = errors.New("the evidence names a workload that isn't one of the cluster that streamed it")
)

// holdOf returns what the view keeps of a record, and whether it keeps the record: not one of another type about an
// image or a workload, and of a namespace's labels only the hub's own copy. problem says why it left out what it should
// have kept, which is then missing, as the safe side has it: presence, exposure or a namespace's labels whose data
// doesn't decode, or presence's workloads, or exposure, of another cluster than the one that streamed the record, which
// the hub drops at its trust boundary, so that no cluster's stream speaks for another's workloads.
func holdOf(r *evidence.Record) (h held, keep bool, problem error) {
	h = held{Key: r.Key, source: r.Event.Source(), time: r.Event.Time(), data: r.Event.Data()}
	if coverage, ok := sdkevidence.Coverage(r.Event); ok {
		h.coverage = &coverage
	}
	switch {
	case r.Type == sdkevidence.TypePresence:
		var presence sdkevidence.Presence
		if json.Unmarshal(h.data, &presence) != nil {
			return held{}, false, errNotPresence
		}
		h.data = nil
		own := presence.Workloads[:0]
		for _, w := range presence.Workloads {
			// A workload without its subject can't be joined to its exposure either.
			if parsed, err := subject.Parse(w.Subject); err != nil || parsed.Kind != subject.KindWorkload ||
				parsed.Workload.Cluster != r.Cluster {
				problem = errOtherCluster
				continue
			}
			h.workloads = append(h.workloads, w.Subject)
			own = append(own, w)
		}
		presence.Workloads = own
		h.presence = &presence
	case r.Type == sdkevidence.TypeExposure:
		if parsed, err := subject.Parse(r.Subject); err != nil || parsed.Kind != subject.KindWorkload ||
			parsed.Workload.Cluster != r.Cluster {
			return held{}, false, errOtherCluster
		}
		var exposure sdkevidence.Exposure
		if json.Unmarshal(h.data, &exposure) != nil {
			return held{}, false, errNotExposure
		}
		for _, e := range exposure.External.EntryPoints {
			h.points = append(h.points, e.Subjects...)
		}
		h.unchecked = len(exposure.External.Unchecked)
	case r.Type == sdkevidence.TypeNamespace && r.Source == evidence.HubSource:
		var namespace sdkevidence.NamespaceLabels
		if json.Unmarshal(h.data, &namespace) != nil {
			return held{}, false, errNotNamespace
		}
		h.data, h.labels = nil, make(map[string]string, len(namespace.Labels))
		for _, l := range namespace.Labels {
			h.labels[l.Key] = l.Value
		}
	case !isEntryPoint(r.Subject):
		return held{}, false, nil
	}
	return h, true, problem
}

// Synced reports whether the view has read every subject that the store held when the view started. Until then, a
// record that the store holds may be missing from the view. A subject whose read failed counts as read: its records
// are missing until a read succeeds.
func (v *View) Synced() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.synced
}

// Workloads returns the subjects of the workloads that run the image of the digest in the cluster, as the presence
// that the cluster streams names them, sorted. known is false when the view holds no presence of the image from the
// cluster, such as before the cluster's presence reached the hub.
func (v *View) Workloads(digest, cluster string) (subjects []string, known bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	for _, h := range v.bySubject[subject.Image(digest)] {
		if h.Type == sdkevidence.TypePresence && h.Cluster == cluster {
			known = true
			subjects = append(subjects, h.workloads...)
		}
	}
	slices.Sort(subjects)
	return slices.Compact(subjects), known
}

// NamespaceLabels returns the labels of the namespace of the cluster, as the hub last copied them from the cluster's
// spoke, and false when the view holds no copy of them: for a namespace that the copy refused, such as one of more
// labels than a record holds, for one that isn't copied yet, and for the hub's own cluster, whose namespaces the hub
// reads itself. False means that the labels are unknown, never that there are none: a namespace without labels has a
// copy of none. Only the copy under the cluster speaks for its namespace. A caller may change the map that it gets.
func (v *View) NamespaceLabels(cluster, namespace string) (map[string]string, bool) {
	about, err := subject.Namespace(cluster, namespace)
	if err != nil {
		return nil, false
	}
	v.mu.RLock()
	kept := v.bySubject[about]
	v.mu.RUnlock()
	for _, h := range kept {
		if h.Type == sdkevidence.TypeNamespace && h.Cluster == cluster {
			return maps.Clone(h.labels), true
		}
	}
	return nil, false
}

// PresenceIn returns the presence of each image that runs in the cluster, by its digest, as the cluster's records of
// presence that the view holds say it: of an image, what every record of the cluster says of it, in the order of their
// sources, with only the cluster's own workloads. A workload that two records name is there twice. The digest is a
// repository digest where a record says so, else a reference where one says so, else an image ID where one says so.
// Presence's schema has each record name one of the three: of records that name none, the digest has no kind, which a
// reader takes for an image ID, as the spoke's presence does. A caller may change the map and the lists of each image,
// and only reads what a workload holds, such as its pods and its labels, which it shares with the view.
func (v *View) PresenceIn(cluster string) map[string]sdkevidence.Presence {
	v.mu.RLock()
	defer v.mu.RUnlock()
	images := map[string]sdkevidence.Presence{}
	for about, kept := range v.bySubject {
		digest, isImage := strings.CutPrefix(about, string(subject.KindImage)+"/")
		if !isImage {
			continue
		}
		if image, known := presenceOf(kept, cluster); known {
			images[digest] = image
		}
	}
	return images
}

// PresenceOf returns the presence of the image of the digest in the cluster, as PresenceIn gives it, and false when the
// view holds no record of the cluster's presence of the image.
func (v *View) PresenceOf(digest, cluster string) (sdkevidence.Presence, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return presenceOf(v.bySubject[subject.Image(digest)], cluster)
}

// presenceOf is what the records about an image, kept, say of its presence in the cluster, as PresenceIn gives it, and
// whether any is of the cluster's presence. The caller holds the view's lock.
func presenceOf(kept []held, cluster string) (image sdkevidence.Presence, known bool) {
	for _, h := range kept {
		if h.Type != sdkevidence.TypePresence || h.Cluster != cluster {
			continue
		}
		known = true
		image.Workloads = append(image.Workloads, h.presence.Workloads...)
		image.Repositories = append(image.Repositories, h.presence.Repositories...)
		if kindRank(h.presence.DigestKind) > kindRank(image.DigestKind) {
			image.DigestKind = h.presence.DigestKind
		}
	}
	return image, known
}

// PresenceChanges returns a count that moves whenever the view holds anew the presence of an image in the cluster, and
// stays while another cluster's moves. A reader that reads it before PresenceIn may keep what it made of PresenceIn
// until the count moves: what it made then misses no change.
func (v *View) PresenceChanges(cluster string) uint64 {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.presenceChanges[cluster]
}

// kindRank orders the kinds of a digest as the spoke's presence does when its collectors disagree: a repository digest,
// which a registry can serve, then a reference, then an image ID.
func kindRank(kind string) int {
	return slices.Index([]string{sdkevidence.DigestKindImageID, sdkevidence.DigestKindReference,
		sdkevidence.DigestKindRepoDigest}, kind)
}

// ExposuresOf returns the exposure of the workload of the subject that the view holds: one for each Collector that
// delivered one, in the order of their names. Each is decoded anew, so a caller may change it.
func (v *View) ExposuresOf(workload string) []sdkevidence.Exposure {
	v.mu.RLock()
	kept := v.bySubject[workload]
	v.mu.RUnlock()
	var exposures []sdkevidence.Exposure
	for _, h := range kept {
		var exposure sdkevidence.Exposure
		// holdOf kept only exposure whose data decodes.
		if h.Type == sdkevidence.TypeExposure && json.Unmarshal(h.data, &exposure) == nil {
			exposures = append(exposures, exposure)
		}
	}
	return exposures
}

// Records returns the records of the type about the subject that the view holds: one for each Collector that delivered
// one, and for each cluster of a streamed type, in the order of ListBySubject. Each decodes its data anew, so a caller
// may change it. Presence, whose data the view keeps decoded, has none: Workloads and PresenceIn give what it holds.
func (v *View) Records(eventType, about string) []Record {
	v.mu.RLock()
	kept := v.bySubject[about]
	v.mu.RUnlock()
	var records []Record
	for _, h := range kept {
		if h.Type != eventType || h.Type == sdkevidence.TypePresence {
			continue
		}
		if r, ok := h.record(); ok {
			records = append(records, r)
		}
	}
	return records
}

// recordOf returns the record of the type about the subject that the Collector of the name delivered through the
// cluster's stream, or, for the cluster "", through an operation, as the asker stores the sources' answers. It returns
// false when the view holds none.
func (v *View) recordOf(eventType, about, collector, cluster string) (Record, bool) {
	v.mu.RLock()
	kept := v.bySubject[about]
	v.mu.RUnlock()
	for _, h := range kept {
		if h.Type == eventType && h.Source == collector && h.Cluster == cluster {
			return h.record()
		}
	}
	return Record{}, false
}

// entryPointsOf returns the subjects that the entry points of the workload's exposure name, once each, sorted, and
// false when the view holds no exposure of the workload.
func (v *View) entryPointsOf(workload string) ([]string, bool) {
	v.mu.RLock()
	kept := v.bySubject[workload]
	v.mu.RUnlock()
	var points []string
	known := false
	for _, h := range kept {
		if h.Type == sdkevidence.TypeExposure {
			known = true
			points = append(points, h.points...)
		}
	}
	slices.Sort(points)
	return slices.Compact(points), known
}

// record returns the record with its data decoded anew, so that a caller may change it, and false for data that isn't
// JSON.
func (h held) record() (Record, bool) {
	var data any
	if json.Unmarshal(h.data, &data) != nil {
		// The store keeps JSON only, so this is no record that it wrote. It is missing, as the safe side has it.
		logf.Log.WithName("exposure-view").Error(errNotJSON, "The view of exposure leaves out evidence that isn't JSON",
			"subject", h.Subject, "type", h.Type, "source", h.Source, "cluster", h.Cluster)
		return Record{}, false
	}
	return Record{Source: h.Source, EventSource: h.source, Time: h.time, Coverage: h.coverage, Data: data}, true
}

// EntryPoints returns the subjects that the entry points of every workload's exposure name, once each, sorted.
func (v *View) EntryPoints() []string {
	v.mu.RLock()
	var points []string
	for _, kept := range v.bySubject {
		for _, h := range kept {
			points = append(points, h.points...)
		}
	}
	v.mu.RUnlock()
	slices.Sort(points)
	return slices.Compact(points)
}

// Ambiguous returns each address subject whose IP the exposure of two or more clusters names, with those clusters,
// sorted: the subjects of one IP are ambiguous whatever their port. Such an address can't be tied to one cluster's
// network, which a source's answer about it needs (design of remote spokes 5.10). A host name is a DNS name that means
// the same everywhere, so it is never ambiguous.
//
// The view computes it again only after a workload's exposure changed, so that a caller may ask for each workload. The
// map is shared: a caller only reads it.
func (v *View) Ambiguous() map[string][]string {
	v.mu.RLock()
	found, fresh := v.ambiguous, v.ambiguous != nil && v.ambiguousAt == v.exposureChanges
	v.mu.RUnlock()
	if fresh {
		return found
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.ambiguous == nil || v.ambiguousAt != v.exposureChanges {
		v.ambiguous, v.ambiguousAt = ambiguousIn(v.byClusterLocked()), v.exposureChanges
	}
	return v.ambiguous
}

// ambiguousIn returns what Ambiguous returns of what the exposure of the clusters names.
func ambiguousIn(clusters map[string]*named) map[string][]string {
	byIP := map[netip.Addr]map[string]bool{}
	subjects := map[netip.Addr][]string{}
	for cluster, n := range clusters {
		for _, p := range n.points {
			if s, err := subject.Parse(p); err == nil && s.Kind == subject.KindAddress {
				if byIP[s.Addr] == nil {
					byIP[s.Addr] = map[string]bool{}
				}
				byIP[s.Addr][cluster] = true
				subjects[s.Addr] = append(subjects[s.Addr], p)
			}
		}
	}
	found := map[string][]string{}
	for ip, named := range byIP {
		if len(named) < 2 {
			continue
		}
		list := slices.Sorted(maps.Keys(named))
		for _, p := range subjects[ip] {
			found[p] = list
		}
	}
	return found
}

// named is what the exposure of one cluster names: its entry points, once each, sorted, and its unchecked reasons, one
// for each workload that gives a reason.
type named struct {
	points    []string
	unchecked int
}

// byCluster returns what the exposure of each cluster names, by the cluster that streamed it.
func (v *View) byCluster() map[string]*named {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.byClusterLocked()
}

// byClusterLocked is byCluster, with v.mu held.
func (v *View) byClusterLocked() map[string]*named {
	clusters := map[string]*named{}
	for _, kept := range v.bySubject {
		for _, h := range kept {
			if h.Type != sdkevidence.TypeExposure {
				continue
			}
			n := clusters[h.Cluster]
			if n == nil {
				n = &named{}
				clusters[h.Cluster] = n
			}
			n.points = append(n.points, h.points...)
			n.unchecked += h.unchecked
		}
	}
	for _, n := range clusters {
		slices.Sort(n.points)
		n.points = slices.Compact(n.points)
	}
	return clusters
}

// answered returns the time of the answer of the Collector of the name about an entry point, of the type, and false
// when the view holds none.
func (v *View) answered(eventType, point, collector string) (time.Time, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	for _, h := range v.bySubject[point] {
		if h.Type == eventType && h.Source == collector && h.Cluster == "" {
			return h.time, true
		}
	}
	return time.Time{}, false
}

// answers returns the keys of the records about hosts and addresses that no cluster streamed, as the asker stores the
// sources' answers.
func (v *View) answers() []evidence.Key {
	v.mu.RLock()
	defer v.mu.RUnlock()
	var keys []evidence.Key
	for about, kept := range v.bySubject {
		if !isEntryPoint(about) {
			continue
		}
		for _, h := range kept {
			if h.Cluster == "" {
				keys = append(keys, h.Key)
			}
		}
	}
	return keys
}
