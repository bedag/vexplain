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

package exposure

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/utils/clock"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/collectorclient"
	"github.com/bedag/vexplain/internal/evidence"
	"github.com/bedag/vexplain/internal/metrics"
	"github.com/bedag/vexplain/internal/text"
	collectorv1alpha1 "github.com/bedag/vexplain/sdk/api/collector/v1alpha1"
	sdkcollector "github.com/bedag/vexplain/sdk/collector"
	"github.com/bedag/vexplain/sdk/subject"
)

const (
	// resync is how long the asker sleeps when nothing wakes it sooner. It then reads the Collectors and the playbooks
	// again, so it is how soon a source is asked after its version changed, it joined, or a playbook turned Ready, and
	// how finely the waits after a failure and before a refresh are kept.
	resync = 5 * time.Second
	// callTimeout bounds one call to a source.
	callTimeout = time.Minute
	// firstRetry and maxRetry bound the wait before a source is asked again after a failure, and a point after it went
	// unanswered: a minute after the first time, doubling, up to a quarter of an hour.
	firstRetry = time.Minute
	maxRetry   = 15 * time.Minute
	// maxReason and maxMessage are the most characters of a source's failure that the asker keeps and logs.
	maxReason  = 64
	maxMessage = 256
)

// The results of a call that the counter of calls names, beside the reasons InvalidInput and NotReady.
const (
	resultSucceeded = "Succeeded"
	resultFailed    = "Failed"
	resultError     = "Error"
)

// Invoker runs an operation of a collector, as the collector pool does.
type Invoker interface {
	Invoke(ctx context.Context, collector string, req *collectorv1alpha1.InvokeRequest,
		opts ...collectorclient.InvokeOption) ([]cloudevents.Event, *collectorclient.Failure, error)
}

// Asker asks the sources about the entry points that the clusters' exposure names, and keeps their answers current in
// the store (design of entry points, section 5.5). It is a manager.Runnable, which the manager runs on its leader.
//
// A source is a Collector with an operation in the hub role that consumes nothing, produces a type, and takes hosts,
// addresses or both. It is asked while a Ready playbook takes the type as evidence. The asker sends it entry points
// only, never a workload, a namespace or a manifest.
//
// It keeps in memory when it asked each source about each entry point, at which version of the source, and each
// source's last failure. It keeps no source version with an answer, so after a start it asks every entry point
// again: an equal answer writes nothing.
type Asker struct {
	view       *View
	store      evidence.Store
	collectors client.Reader
	pool       Invoker
	context    func(context.Context) (*collectorv1alpha1.Context, error)
	clock      clock.Clock

	// Only the loop reads and writes what follows. asked holds when each source was last asked about each entry point,
	// failures each source whose last call failed, and clusters the clusters that the gauge of entry points counts.
	asked    map[askKey]askState
	failures map[sourceKey]*failing
	clusters map[string]bool
}

// sourceKey names a source: a Collector, as a source of a type.
type sourceKey struct{ collector, eventType string }

// askKey names an entry point that a source is asked about.
type askKey struct {
	sourceKey
	subject string
}

// askState is when a source was last asked about an entry point, and what came of it.
type askState struct {
	// at is when, and version the source's version then.
	at      time.Time
	version string
	// misses is how many times in a row the source didn't answer, as when it refused the point.
	misses int
}

// failing is what the asker keeps of a source whose last call failed.
type failing struct {
	// count is how many calls in a row failed, and retryAt when the source is asked again.
	count   int
	retryAt time.Time
	// reason and message are the last failure's, as the source gave them, or Error for a call without an answer.
	reason, message string
}

// The asker reads the Collectors, to find the sources, and the playbooks, to find which types are asked for.
// +kubebuilder:rbac:groups=config.vexplain.bedag.ch,resources=collectors;playbooks,verbs=get;list;watch

// NewAsker returns an asker that reads the entry points and the answers from view, stores the answers in store, reads
// the Collectors and the playbooks through collectors, and calls the sources through pool, with the context that
// clusterContext builds.
func NewAsker(view *View, store evidence.Store, collectors client.Reader, pool Invoker,
	clusterContext func(context.Context) (*collectorv1alpha1.Context, error)) *Asker {
	return &Asker{view: view, store: store, collectors: collectors, pool: pool, context: clusterContext,
		clock: clock.RealClock{}, asked: map[askKey]askState{}, failures: map[sourceKey]*failing{}}
}

// Start asks until ctx ends, and then returns nil. It makes a pass at once, and again whenever the view changes, and
// after resync at the latest.
func (a *Asker) Start(ctx context.Context) error {
	ctx = logf.IntoContext(ctx, logf.FromContext(ctx).WithName("exposure-asker"))
	for {
		a.pass(ctx)
		timer := a.clock.NewTimer(resync)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-a.view.changed:
		case <-timer.C():
		}
		timer.Stop()
	}
}

// pass asks each source about the entry points that are due, deletes the answers about entry points that no cluster
// names, and counts the entry points. It waits for the view to be synced, since an entry point or an answer may be
// missing from it until then.
func (a *Asker) pass(ctx context.Context) {
	if !a.view.Synced() {
		return
	}
	collectors, sources, err := a.sources(ctx)
	if err != nil {
		logf.FromContext(ctx).Error(err, "Could not read the Collectors or the playbooks; the next pass tries again")
		return
	}
	points := pointsOf(a.view.EntryPoints())
	a.forget(sources, points)
	a.askAll(ctx, sources, points)
	if ctx.Err() != nil {
		return // The manager is stopping.
	}
	a.deleteUnnamed(ctx, collectors, points)
	a.measure(sources, points)
}

// source is a Collector that the asker asks about entry points, as a source of a type.
type source struct {
	sourceKey
	// operation is the operation that answers, and hosts and addresses say which points it takes.
	operation        string
	hosts, addresses bool
	// maxAge is how long an answer stays current, or 0 for no limit.
	maxAge time.Duration
	// collectorVersion is the collector's version, at which its answers are stored, and version what the source answers
	// at: a change asks every entry point again.
	collectorVersion, version string
	// settings are the Collector's settings, which every call carries.
	settings []byte
}

// takes reports whether the source is asked about the point.
func (s *source) takes(p point) bool {
	if p.host {
		return s.hosts
	}
	return s.addresses
}

// sources returns the Collectors, sorted by name, and the sources that are asked: for each type that a Ready
// playbook takes as evidence, each Collector that can be used, has a version, isn't pinned out, and has an operation
// that answers about entry points with the type.
func (a *Asker) sources(ctx context.Context) ([]configv1alpha1.Collector, []source, error) {
	var playbooks configv1alpha1.PlaybookList
	if err := a.collectors.List(ctx, &playbooks); err != nil {
		return nil, nil, fmt.Errorf("list the playbooks: %w", err)
	}
	var wanted []configv1alpha1.PlaybookEvidence
	for _, p := range playbooks.Items {
		if meta.IsStatusConditionTrue(p.Status.Conditions, configv1alpha1.ConditionReady) {
			wanted = append(wanted, p.Spec.Evidence...)
		}
	}
	var collectors configv1alpha1.CollectorList
	if err := a.collectors.List(ctx, &collectors); err != nil {
		return nil, nil, fmt.Errorf("list the Collectors: %w", err)
	}
	slices.SortFunc(collectors.Items, func(x, y configv1alpha1.Collector) int { return cmp.Compare(x.Name, y.Name) })
	var sources []source
	for i := range collectors.Items {
		c := &collectors.Items[i]
		collectorVersion := ptr.Deref(c.Status.Version, "")
		if !collectorclient.Usable(c) || collectorVersion == "" {
			continue
		}
		for _, eventType := range typesFor(wanted, c.Name) {
			operation, hosts, addresses := collectorclient.EntryPointSource(c, eventType)
			if operation == "" {
				continue
			}
			s := source{sourceKey: sourceKey{collector: c.Name, eventType: eventType}, operation: operation,
				hosts: hosts, addresses: addresses, maxAge: collectorclient.MaxAge(c, eventType),
				collectorVersion: collectorVersion, version: sourceVersion(c)}
			if c.Spec.Settings != nil {
				s.settings = slices.Clone(c.Spec.Settings.Raw)
			}
			sources = append(sources, s)
		}
	}
	return collectors.Items, sources, nil
}

// typesFor returns the types that the evidence asks of the Collector of the name, sorted: each type that it takes,
// unless its entry pins other Collectors.
func typesFor(wanted []configv1alpha1.PlaybookEvidence, collector string) []string {
	var types []string
	for _, e := range wanted {
		if len(e.Collectors) == 0 || slices.Contains(e.Collectors, collector) {
			types = append(types, e.Type)
		}
	}
	slices.Sort(types)
	return slices.Compact(types)
}

// sourceVersion returns what the Collector's sources answer at: the collector's version, and the versions of its own
// sources, which change when their data does.
func sourceVersion(c *configv1alpha1.Collector) string {
	versions := make([]string, 0, len(c.Status.Sources))
	for _, s := range c.Status.Sources {
		versions = append(versions, s.Name+"="+s.Version)
	}
	slices.Sort(versions)
	return ptr.Deref(c.Status.Version, "") + " " + strings.Join(versions, " ")
}

// point is an entry point that a source is asked about.
type point struct {
	subject string
	// host says whether it is a host, else an address, and value is the host name or the address, as the parameters
	// carry it.
	host  bool
	value string
}

// pointsOf returns the entry points of the subjects that are hosts or addresses, in the order of the subjects.
func pointsOf(subjects []string) []point {
	points := make([]point, 0, len(subjects))
	for _, s := range subjects {
		parsed, err := subject.Parse(s)
		switch {
		case err != nil:
		case parsed.Kind == subject.KindHost:
			points = append(points, point{subject: s, host: true, value: parsed.Host})
		case parsed.Kind == subject.KindAddress:
			points = append(points, point{subject: s, value: strings.TrimPrefix(s, string(subject.KindAddress)+"/")})
		}
	}
	return points
}

// forget drops what the asker keeps of the sources that aren't asked any more, and of the entry points that no
// cluster names, so that its memory follows them.
func (a *Asker) forget(sources []source, points []point) {
	current := make(map[sourceKey]bool, len(sources))
	for _, s := range sources {
		current[s.sourceKey] = true
	}
	named := make(map[string]bool, len(points))
	for _, p := range points {
		named[p.subject] = true
	}
	for k := range a.asked {
		if !current[k.sourceKey] || !named[k.subject] {
			delete(a.asked, k)
		}
	}
	for k := range a.failures {
		if !current[k] {
			delete(a.failures, k)
		}
	}
}

// askAll asks each source about the entry points that are due, in calls of at most MaxPointsPerCall, in the order of
// their subjects, unless the source failed and its wait isn't over.
func (a *Asker) askAll(ctx context.Context, sources []source, points []point) {
	var callContext *collectorv1alpha1.Context
	for i := range sources {
		src := &sources[i]
		if ctx.Err() != nil {
			return
		}
		if f := a.failures[src.sourceKey]; f != nil && a.clock.Now().Before(f.retryAt) {
			continue
		}
		due := a.due(src, points)
		if len(due) == 0 {
			continue
		}
		if callContext == nil {
			var err error
			if callContext, err = a.context(ctx); err != nil {
				logf.FromContext(ctx).Error(err, "Could not build the context of the calls to the sources; the next pass tries again")
				return
			}
		}
		for len(due) > 0 {
			n := min(len(due), sdkcollector.MaxPointsPerCall)
			if !a.ask(ctx, callContext, src, due[:n]) {
				break
			}
			due = due[n:]
		}
	}
}

// due returns the entry points that the source takes and that are due: not asked since the start, or since the
// source's version changed; answered, and the answer half its maxAge old; or not answered, and their wait over.
func (a *Asker) due(src *source, points []point) []point {
	now := a.clock.Now()
	var due []point
	for _, p := range points {
		if !src.takes(p) {
			continue
		}
		last, ok := a.asked[askKey{sourceKey: src.sourceKey, subject: p.subject}]
		if !ok || last.version != src.version {
			due = append(due, p)
			continue
		}
		answered, held := a.view.answered(src.eventType, p.subject, src.collector)
		switch {
		case !held:
			if !now.Before(last.at.Add(retryAfter(last.misses))) {
				due = append(due, p)
			}
		case src.maxAge > 0 && now.Sub(answered) >= src.maxAge/2 && now.Sub(last.at) >= src.maxAge/2:
			// Not asked more often than every half maxAge, even when the source's answers don't take a newer time.
			due = append(due, p)
		}
	}
	return due
}

// retryAfter returns the wait after the n-th failure in a row: a minute after the first, doubling, up to a quarter of
// an hour.
func retryAfter(n int) time.Duration {
	wait := firstRetry
	for i := 1; i < n && wait < maxRetry; i++ {
		wait *= 2
	}
	return min(wait, maxRetry)
}

// ask asks the source about the points in one call. A call that the source refuses as InvalidInput is asked again in
// two halves, down to single points, so that every point that the source can read gets its answer. It returns false
// when the source failed, or ctx ended, so that the pass asks the source nothing more.
func (a *Asker) ask(ctx context.Context, callContext *collectorv1alpha1.Context, src *source, points []point) bool {
	events, failure, err := a.call(ctx, callContext, src, points)
	if ctx.Err() != nil {
		return false // The manager is stopping: no failure of the source's.
	}
	cluster := callContext.GetCluster()
	switch {
	case refused(failure, err):
		metrics.SourceCallsTotal.WithLabelValues(cluster, src.collector, sdkcollector.ReasonInvalidInput).Inc()
		if len(points) == 1 {
			a.unanswered(src, points[0])
			return true
		}
		half := len(points) / 2
		return a.ask(ctx, callContext, src, points[:half]) && a.ask(ctx, callContext, src, points[half:])
	case err != nil || failure != nil:
		a.failed(ctx, cluster, src, failure, err)
		return false
	}
	metrics.SourceCallsTotal.WithLabelValues(cluster, src.collector, resultSucceeded).Inc()
	delete(a.failures, src.sourceKey)
	a.keep(ctx, cluster, src, points, events)
	return true
}

// call makes one call to the source about the points: their hosts and addresses are its parameters, and the first
// point's subject is its subject.
func (a *Asker) call(ctx context.Context, callContext *collectorv1alpha1.Context, src *source, points []point) (
	[]cloudevents.Event, *collectorclient.Failure, error) {
	var params sdkcollector.EntryPointParameters
	for _, p := range points {
		if p.host {
			params.Hosts = append(params.Hosts, p.value)
		} else {
			params.Addresses = append(params.Addresses, p.value)
		}
	}
	raw, err := json.Marshal(params)
	if err != nil {
		return nil, nil, fmt.Errorf("encode the parameters: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	return a.pool.Invoke(ctx, src.collector, &collectorv1alpha1.InvokeRequest{
		Operation:  src.operation,
		Subject:    points[0].subject,
		Parameters: raw,
		Settings:   src.settings,
		Context:    callContext,
		Role:       collectorv1alpha1.Role_ROLE_HUB,
	})
}

// refused reports whether a call was refused as InvalidInput: by the source, or by the schema of the operation's
// parameters, whose refusal the SDK's server sends as InvalidArgument.
func refused(failure *collectorclient.Failure, err error) bool {
	if failure != nil {
		return failure.Reason == sdkcollector.ReasonInvalidInput
	}
	var s interface{ GRPCStatus() *status.Status }
	return errors.As(err, &s) && s.GRPCStatus().Code() == codes.InvalidArgument &&
		strings.HasPrefix(s.GRPCStatus().Message(), "the parameters ")
}

// failed counts a call to the source that failed, keeps why, and makes the source wait before its next call.
func (a *Asker) failed(ctx context.Context, cluster string, src *source, failure *collectorclient.Failure, err error) {
	result := resultError
	if failure != nil {
		result = resultFailed
		if failure.Reason == sdkcollector.ReasonNotReady {
			result = sdkcollector.ReasonNotReady
		}
	}
	metrics.SourceCallsTotal.WithLabelValues(cluster, src.collector, result).Inc()
	f := a.failures[src.sourceKey]
	if f == nil {
		f = &failing{}
		a.failures[src.sourceKey] = f
	}
	f.count++
	wait := retryAfter(f.count)
	f.retryAt = a.clock.Now().Add(wait)
	log := logf.FromContext(ctx).WithValues("collector", src.collector, "type", src.eventType, "after", wait)
	if failure == nil {
		f.reason, f.message = resultError, ""
		log.Error(err, "A source gave no answer about entry points; it is asked again later")
		return
	}
	// The reason and the message are the source's text: printable, and cut, they go to the log.
	f.reason = text.CutChars(text.Printable(failure.Reason), maxReason)
	f.message = text.CutChars(text.Printable(failure.Message), maxMessage)
	log.Info("A source failed a call about entry points; it is asked again later", "reason", f.reason,
		"message", f.message)
}

// keep stores the answer of a call about the points: each event of the source's type about a point of the call, the
// first about each point. The other events are dropped, and counted. A point without a stored answer is unanswered.
func (a *Asker) keep(ctx context.Context, cluster string, src *source, points []point, events []cloudevents.Event) {
	open := make(map[string]bool, len(points))
	for _, p := range points {
		open[p.subject] = true
	}
	var opts []evidence.PutOption
	if src.maxAge > 0 {
		// An equal answer then takes the new time once the stored one is half its maxAge old, and so stays current.
		opts = append(opts, evidence.RefreshAfter(src.maxAge/2))
	}
	now := a.clock.Now()
	for _, e := range events {
		if e.Type() != src.eventType || !open[e.Subject()] {
			metrics.SourceAnswersUnaskedTotal.WithLabelValues(cluster, src.collector).Inc()
			continue
		}
		// The store's errors repeat nothing of the answer's data.
		if err := a.store.Put(ctx, src.collector, src.collectorVersion, e, opts...); err != nil {
			logf.FromContext(ctx).Error(err, "Could not store a source's answer; the entry point is asked again later",
				"collector", src.collector, "subject", e.Subject())
			continue
		}
		delete(open, e.Subject())
		a.asked[askKey{sourceKey: src.sourceKey, subject: e.Subject()}] = askState{at: now, version: src.version}
	}
	for _, p := range points {
		if open[p.subject] {
			a.unanswered(src, p)
		}
	}
}

// unanswered notes that the source was asked about the point and left it without an answer, so that the point waits
// before it is asked again, longer after each time in a row.
func (a *Asker) unanswered(src *source, p point) {
	key := askKey{sourceKey: src.sourceKey, subject: p.subject}
	misses := 1
	if last, ok := a.asked[key]; ok && last.version == src.version {
		misses = last.misses + 1
	}
	a.asked[key] = askState{at: a.clock.Now(), version: src.version, misses: misses}
}

// deleteUnnamed deletes the sources' answers about the entry points that no cluster names any more.
func (a *Asker) deleteUnnamed(ctx context.Context, collectors []configv1alpha1.Collector, points []point) {
	named := make(map[string]bool, len(points))
	for _, p := range points {
		named[p.subject] = true
	}
	for _, k := range a.view.answers() {
		if named[k.Subject] || !isAnswer(collectors, k) {
			continue
		}
		if err := a.store.Delete(ctx, k); err != nil {
			logf.FromContext(ctx).Error(err, "Could not delete an answer about an entry point that no cluster names; "+
				"the next pass tries again", "collector", k.Source, "subject", k.Subject)
		}
	}
}

// isAnswer reports whether the record of the key is a source's answer: its Collector has an operation that answers
// about entry points with the record's type.
func isAnswer(collectors []configv1alpha1.Collector, k evidence.Key) bool {
	i := slices.IndexFunc(collectors, func(c configv1alpha1.Collector) bool { return c.Name == k.Source })
	if i < 0 {
		return false
	}
	operation, _, _ := collectorclient.EntryPointSource(&collectors[i], k.Type)
	return operation != ""
}
