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

package collectorclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/cloudevents/sdk-go/binding/format/protobuf/v2/pb"
	cloudevents "github.com/cloudevents/sdk-go/v2"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/settings"
	collectorv1alpha1 "github.com/bedag/vexplain/sdk/api/collector/v1alpha1"
	"github.com/bedag/vexplain/sdk/evidence"
	subjectpath "github.com/bedag/vexplain/sdk/subject"
	"github.com/bedag/vexplain/sdk/workloads"
)

// The streams read the Collectors and the OperatorConfig through the manager's cache, which lists and watches them.
// +kubebuilder:rbac:groups=config.vexplain.bedag.ch,resources=collectors,verbs=get;list;watch
// +kubebuilder:rbac:groups=config.vexplain.bedag.ch,resources=operatorconfigs,verbs=get;list;watch

const (
	// firstRetry is how long a broken stream waits before it opens again, the first time, and after a stream that
	// stayed open for settledAfter past its snapshot. Each wait after that is twice the last, and maxRetry at most.
	firstRetry = time.Second
	maxRetry   = time.Minute
	// defaultResync is how often Streams reads the Collectors and the context again, and so how soon the streams
	// follow a change. The reads come from the manager's cache, and cost no call of the API server.
	defaultResync = 5 * time.Second
)

// apiRoles are the roles of the collector API, by the roles of a Collector. A role that isn't here, which a later
// version may add, gets no stream.
var apiRoles = map[configv1alpha1.CollectorRole]collectorv1alpha1.Role{
	configv1alpha1.CollectorRoleSpoke: collectorv1alpha1.Role_ROLE_SPOKE,
	configv1alpha1.CollectorRoleHub:   collectorv1alpha1.Role_ROLE_HUB,
}

// Sink takes what the streams of one role deliver. Streams calls it from the goroutine of each stream, so the streams
// of several collectors call it at once: a Sink is safe for concurrent use. The calls about one collector come one at
// a time, in the order that its stream delivered them, and Forget comes after the last of them. A stream that stops,
// as for a change of its settings, first waits for its call of the sink to return, so a call that takes long holds up
// every change of the streams.
//
// What reaches a sink is valid evidence of a type that the collector declares, with subjects that parse: Streams
// checks again what a collector sends, and drops the rest.
type Sink interface {
	// Snapshot hands over a whole snapshot of the collector: the events between SnapshotStart and SnapshotEnd, in
	// the order that the collector sent them, or none. It replaces what the collector delivered before. Nothing of
	// a snapshot reaches the sink before its end, and nothing of one that never ends.
	Snapshot(collector string, events []cloudevents.Event)
	// Upsert hands over a change after the snapshot: evidence that is new or changed.
	Upsert(collector string, e cloudevents.Event)
	// Remove says that the collector's evidence of the type about the subject is gone, as a tombstone does.
	Remove(collector, eventType, subject string)
	// SourceChanged says that a source of the collector's own changed, such as a vulnerability database, so that its
	// operations run again for the subjects, or for every subject when there are none.
	SourceChanged(collector string, subjects []string)
	// Forget drops what the collector delivered, because its Collector is gone, and a deleted collector's evidence
	// goes with it (design 5.9). The streams' evidence lives in memory only, so nothing else removes it.
	Forget(collector string)
}

// Streams keeps the streams of the collectors open, and hands what they deliver to the sinks. For each Collector that
// is Usable and that watches, it keeps a Watch open in each role that the Collector declares and that has a sink, with
// the Collector's spec.settings and the context of the cluster, and hands what the Watch delivers to that role's sink.
//
//   - A snapshot reaches the sink whole, at its end. A stream that breaks before hands over nothing of it, and the
//     sink keeps what it had.
//   - A snapshot that doesn't end within a minute of its SnapshotStart, or whose messages hold more than 64 MiB,
//     breaks the contract: its stream ends, and nothing of it reaches the sink. The log names the collector and the
//     bound, and the metric of contract breaks counts it.
//   - After the snapshot, each change reaches the sink as it comes.
//   - A stream that breaks, ends or breaks its contract opens again after a second, then after twice as long as the
//     last time, and after a minute at most, and starts with a new snapshot. A stream that stayed open for a minute
//     past its snapshot starts the waits again from a second. A broken stream is no health failure: the deployer's
//     health check alone decides a collector's health.
//   - A change to the settings, the context or the digest that runs opens a new stream in place of the old one.
//   - A collector that can't be used any more has its streams stopped, and what it delivered stays.
//   - A collector whose recorded capabilities no longer declare a Watch in a role, as after an upgrade, has its stream
//     in that role stopped, and the role's sink forgets what it delivered there: nothing delivers it any more.
//   - A Collector that goes, or is being deleted, has its streams stopped and its connection closed, and each sink
//     forgets what it delivered.
//
// Streams is a manager.Runnable, which the manager runs on its leader only, as it runs every runnable that doesn't
// say otherwise: the sinks keep what one process delivers.
type Streams struct {
	pool           *Pool
	client         client.Client
	sinks          map[configv1alpha1.CollectorRole]Sink
	clusterContext func(ctx context.Context) (*collectorv1alpha1.Context, error)
	resync         time.Duration
	bounds         streamBounds

	// The goroutine of Start alone uses the fields below.

	// collectors are the Collectors that the streams know, by name.
	collectors map[string]*watched
	// lastContext is the last context that could be built, which the streams keep while a new one can't be.
	lastContext *collectorv1alpha1.Context
}

// watched is a Collector that the streams know, by the UID that tells it from a Collector of the same name that was
// created after it, with its open streams by role, and the roles in which a stream of it was open since: the roles
// whose sinks may hold what it delivered.
type watched struct {
	uid        types.UID
	streams    map[configv1alpha1.CollectorRole]*stream
	delivering map[configv1alpha1.CollectorRole]bool
}

// NewStreams returns the streams of the collectors that p reaches, which reads the Collectors through c. sinks holds
// one sink per role: the spoke's Router serves Spoke, and the hub's sink serves Hub. A role without a sink gets no
// streams, so that a cluster that runs one role streams for that role only: hub and spoke meet only through the
// executor and the stores (decision 0021). clusterContext builds the context of every Watch, as ClusterContext does.
func NewStreams(p *Pool, c client.Client, sinks map[configv1alpha1.CollectorRole]Sink,
	clusterContext func(ctx context.Context) (*collectorv1alpha1.Context, error)) *Streams {
	served := make(map[configv1alpha1.CollectorRole]Sink, len(sinks))
	for role, sink := range sinks {
		if sink != nil {
			served[role] = sink
		}
	}
	return &Streams{
		pool:           p,
		client:         c,
		sinks:          served,
		clusterContext: clusterContext,
		resync:         defaultResync,
		bounds:         streamBounds{snapshotTime: maxSnapshotTime, snapshotBytes: maxSnapshotBytes, settledAfter: settledAfter},
		collectors:     map[string]*watched{},
	}
}

// streamBounds are the bounds of what a collector sends on a stream (design 5.9): how long its snapshot may take, and
// how much it may hold. settledAfter is how long a stream must stay open past its snapshot for the wait before its
// next opening to start again from a second.
type streamBounds struct {
	snapshotTime  time.Duration
	snapshotBytes int
	settledAfter  time.Duration
}

// ClusterContext returns the function that builds the context that every Watch carries: what vexplain tells its
// collectors about the cluster, so that a collector keeps no configuration of its own. It reads the OperatorConfig
// through r at each call, with the defaults of settings.Load, and gives
//   - the cluster's name
//   - operatorNamespace, the namespace of the operator
//   - the label that marks vexplain's own pods, workloads.TaskLabel, which counts only in the operator's namespace
//   - the scope, as JSON, or {} without one, which selects every pod
//   - the allowlists of owner attribution, as JSON, or {} without any, which copies nothing
func ClusterContext(r client.Reader, operatorNamespace string) func(context.Context) (*collectorv1alpha1.Context, error) {
	return func(ctx context.Context) (*collectorv1alpha1.Context, error) {
		effective, err := settings.Load(ctx, r)
		if err != nil {
			return nil, err
		}
		scope := effective.Scope
		if scope == nil {
			scope = &configv1alpha1.Scope{}
		}
		scopeJSON, err := json.Marshal(scope)
		if err != nil {
			return nil, fmt.Errorf("encode the scope: %w", err)
		}
		attribution, err := json.Marshal(effective.OwnerAttribution)
		if err != nil {
			return nil, fmt.Errorf("encode the allowlists of owner attribution: %w", err)
		}
		return &collectorv1alpha1.Context{
			Cluster:           effective.ClusterName,
			OperatorNamespace: operatorNamespace,
			OwnPodLabel:       workloads.TaskLabel,
			Scope:             scopeJSON,
			OwnerAttribution:  attribution,
		}, nil
	}
}

// Start keeps the streams until ctx ends. It reads the Collectors and the context at once, and again every few
// seconds, and opens and stops streams to match them. When ctx ends, it stops every stream, waits until none calls
// its sink any more, and returns nil. Stopping forgets nothing: the operator stops, and its sinks with it.
func (s *Streams) Start(ctx context.Context) error {
	ctx = logf.IntoContext(ctx, logf.FromContext(ctx).WithName("collector-streams"))
	ticker := time.NewTicker(s.resync)
	defer ticker.Stop()
	for {
		s.sync(ctx)
		select {
		case <-ctx.Done():
			s.stopAll()
			return nil
		case <-ticker.C:
		}
	}
}

// sync reads the Collectors and the context, and makes the streams match them.
func (s *Streams) sync(ctx context.Context) {
	log := logf.FromContext(ctx)
	var list configv1alpha1.CollectorList
	if err := s.client.List(ctx, &list); err != nil {
		// A failed read says nothing about which Collectors exist: no stream stops, and nothing is forgotten.
		log.Error(err, "Could not list the Collectors; the streams stay as they are")
		return
	}
	present := make(map[string]*configv1alpha1.Collector, len(list.Items))
	for i := range list.Items {
		if c := &list.Items[i]; c.DeletionTimestamp.IsZero() {
			present[c.Name] = c
		}
	}
	// A Collector is gone when it isn't there any more, when it is being deleted, and when another of the same name
	// took its place, as its UID tells.
	for name, w := range s.collectors {
		if c, ok := present[name]; !ok || c.UID != w.uid {
			s.forget(ctx, name, w)
		}
	}

	clusterContext, err := s.clusterContext(ctx)
	if err != nil {
		// The open streams keep the context that they have, and a new one opens with the last that could be built,
		// if there was one.
		log.Error(err, "Could not build the context of the collectors; the streams keep the last one")
		clusterContext = s.lastContext
	} else {
		s.lastContext = clusterContext
	}
	for name, c := range present {
		w, ok := s.collectors[name]
		if !ok {
			w = &watched{
				uid:        c.UID,
				streams:    map[configv1alpha1.CollectorRole]*stream{},
				delivering: map[configv1alpha1.CollectorRole]bool{},
			}
			s.collectors[name] = w
		}
		s.match(ctx, name, w, s.wanted(c, clusterContext))
		s.forgetUndeclared(ctx, name, w, c.Status.Capabilities)
	}
}

// wanted returns the streams that a Collector should have, by role, with what each opens with. A Collector that isn't
// usable or doesn't watch has none, and so does every Collector while there is no context. Otherwise a Collector has
// one in each role that it declares and that has a sink.
func (s *Streams) wanted(c *configv1alpha1.Collector,
	clusterContext *collectorv1alpha1.Context) map[configv1alpha1.CollectorRole]streamSpec {
	if clusterContext == nil || !Usable(c) || c.Status.Capabilities.Watch != configv1alpha1.CollectorWatchSupported {
		return nil
	}
	var collectorSettings []byte
	if c.Spec.Settings != nil {
		collectorSettings = c.Spec.Settings.Raw
	}
	produces := make([]string, 0, len(c.Status.Capabilities.Produces))
	for _, produced := range c.Status.Capabilities.Produces {
		produces = append(produces, produced.Type)
	}
	slices.Sort(produces)
	want := map[configv1alpha1.CollectorRole]streamSpec{}
	for _, role := range c.Status.Capabilities.Roles {
		apiRole, known := apiRoles[role]
		if _, served := s.sinks[role]; !known || !served {
			continue
		}
		want[role] = streamSpec{
			// Each stream has its own request, which nothing changes once it is open.
			request: &collectorv1alpha1.WatchRequest{
				Role:     apiRole,
				Settings: slices.Clone(collectorSettings),
				Context:  proto.CloneOf(clusterContext),
			},
			digest:   ptr.Deref(c.Status.PackageDigest, ""),
			produces: produces,
		}
	}
	return want
}

// match makes the streams of a Collector those that it should have: it stops the streams that it shouldn't have, and
// those that should open with something else, and opens those that it lacks.
func (s *Streams) match(ctx context.Context, name string, w *watched,
	want map[configv1alpha1.CollectorRole]streamSpec) {
	log := logf.FromContext(ctx)
	stale := make([]*stream, 0, len(w.streams))
	for role, st := range w.streams {
		spec, wanted := want[role]
		switch {
		case !wanted:
			log.Info("Stopping the stream of the collector: it can't be used now, or doesn't watch in the role",
				"collector", name, "role", role)
		case !st.spec.equal(spec):
			log.Info("Opening the stream of the collector again: what it opens with changed, the settings, the "+
				"context, the digest that runs or the types that the collector declares", "collector", name, "role", role)
		default:
			continue
		}
		stale = append(stale, st)
		delete(w.streams, role)
	}
	stopStreams(stale)
	for role, spec := range want {
		if _, open := w.streams[role]; !open {
			w.streams[role] = s.open(ctx, name, role, spec)
			w.delivering[role] = true
		}
	}
}

// forgetUndeclared makes the sink of each role in which a stream of a Collector was open forget what the collector
// delivered there, once its recorded capabilities don't declare a Watch in the role any more, as after an upgrade
// that stops it from watching, or from taking the role. Nothing delivers in the role then, and what it delivered would
// stay until its Collector goes. match has stopped the role's stream already, since it isn't wanted.
//
// Capabilities that aren't recorded say nothing, and forget nothing. A collector that only can't be used keeps what it
// delivered: its health gates new evidence, and not what it already delivered.
func (s *Streams) forgetUndeclared(ctx context.Context, name string, w *watched,
	caps *configv1alpha1.CollectorCapabilities) {
	if caps == nil {
		return
	}
	for role := range w.delivering {
		if caps.Watch == configv1alpha1.CollectorWatchSupported && slices.Contains(caps.Roles, role) {
			continue
		}
		delete(w.delivering, role)
		s.sinks[role].Forget(name)
		logf.FromContext(ctx).Info("Forgot what the collector delivered in the role: its capabilities don't declare a "+
			"Watch in it any more", "collector", name, "role", role)
	}
}

// forget stops the streams of a Collector that is gone, closes its connection, and then, when none of its streams can
// deliver more, makes each sink forget what it delivered.
func (s *Streams) forget(ctx context.Context, name string, w *watched) {
	open := make([]*stream, 0, len(w.streams))
	for _, st := range w.streams {
		open = append(open, st)
	}
	stopStreams(open)
	delete(s.collectors, name)
	s.pool.Forget(name)
	for _, sink := range s.sinks {
		sink.Forget(name)
	}
	logf.FromContext(ctx).Info("Forgot what the collector delivered: its Collector is gone", "collector", name)
}

// open starts a stream of the collector in the role, which keeps a Watch open until it is stopped.
func (s *Streams) open(ctx context.Context, collector string, role configv1alpha1.CollectorRole,
	spec streamSpec) *stream {
	log := logf.FromContext(ctx).WithValues("collector", collector, "role", role)
	ctx, cancel := context.WithCancel(logf.IntoContext(ctx, log))
	st := &stream{
		collector: collector,
		spec:      spec,
		sink:      s.sinks[role],
		pool:      s.pool,
		bounds:    s.bounds,
		cancel:    cancel,
		done:      make(chan struct{}),
	}
	log.Info("Watching the collector")
	go st.run(ctx)
	return st
}

// stopAll stops every stream, and waits until none calls its sink any more.
func (s *Streams) stopAll() {
	var open []*stream
	for _, w := range s.collectors {
		for _, st := range w.streams {
			open = append(open, st)
		}
	}
	stopStreams(open)
}

// stopStreams stops the streams, and waits until none of them calls its sink any more.
func stopStreams(streams []*stream) {
	for _, st := range streams {
		st.cancel()
	}
	for _, st := range streams {
		<-st.done
	}
}

// nextRetry returns how long a broken stream waits before it opens again, when it waited d the last time: twice as
// long, and maxRetry at most.
func nextRetry(d time.Duration) time.Duration {
	return min(2*d, maxRetry)
}

// streamSpec is what a stream opens with: its request, which holds its role, the collector's settings and the
// context; the digest that runs; and the types that the collector declares, sorted, which its events are checked
// against. A stream whose spec changes opens again.
type streamSpec struct {
	request  *collectorv1alpha1.WatchRequest
	digest   string
	produces []string
}

func (a streamSpec) equal(b streamSpec) bool {
	return proto.Equal(a.request, b.request) && a.digest == b.digest && slices.Equal(a.produces, b.produces)
}

// stream keeps one Watch of a collector open, in one role, and hands what it delivers to the role's sink.
type stream struct {
	collector string
	spec      streamSpec
	sink      Sink
	pool      *Pool
	bounds    streamBounds
	// cancel stops the stream, and done closes once it has stopped, after its last call of the sink.
	cancel context.CancelFunc
	done   chan struct{}
}

// run keeps the Watch open until ctx ends: it opens it again each time that it ends, after a pause.
func (st *stream) run(ctx context.Context) {
	defer close(st.done)
	pause := firstRetry
	for {
		delivered, err := st.watch(ctx)
		if ctx.Err() != nil {
			return
		}
		if !delivered.IsZero() && time.Since(delivered) >= st.bounds.settledAfter {
			pause = firstRetry
		}
		logEnd(ctx, err, pause)
		timer := time.NewTimer(pause)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		pause = nextRetry(pause)
	}
}

// logEnd logs why a stream ended, and when it opens again. The status of a call that broke is logged by its code
// only: its message can be the collector's text.
func logEnd(ctx context.Context, err error, pause time.Duration) {
	log := logf.FromContext(ctx)
	var order orderError
	var passed boundError
	switch {
	case errors.As(err, &passed):
		log.Info("The collector passed a bound of what it may send, which breaks the contract of its stream; it opens "+
			"again after a pause, with a new snapshot", "bound", passed.bound, "problem", passed.Error(), "pause", pause)
	case errors.As(err, &order):
		log.Info("The collector broke the order of its stream; it opens again after a pause, with a new snapshot",
			"problem", order.Error(), "pause", pause)
	case errors.Is(err, errStreamEnded):
		log.Info("The collector ended its stream; it opens again after a pause, with a new snapshot", "pause", pause)
	default:
		log.Info("The stream of the collector broke; it opens again after a pause, with a new snapshot",
			"code", status.Code(err).String(), "pause", pause)
	}
}

// position is how far a Watch has got: before its snapshot, in it, or after it.
type position int

const (
	beforeSnapshot position = iota
	inSnapshot
	afterSnapshot
)

// watchState is how far a Watch has got, with the events of its snapshot, which it holds until the snapshot ends, how
// much the messages of the snapshot held, and the clock of its time. delivered is when the snapshot reached the sink.
type watchState struct {
	at        position
	held      []cloudevents.Event
	bytes     int
	clock     snapshotClock
	delivered time.Time
}

// errStreamEnded is why a stream ends when the collector ends it without an error.
var errStreamEnded = errors.New("the collector ended the stream")

// orderError is how an item breaks the order of a stream: one snapshot, and the changes after it. It ends the stream.
type orderError string

func (e orderError) Error() string { return string(e) }

// watch opens one Watch and hands what it delivers to the sink, until it ends. It reports when its snapshot reached
// the sink, or the zero time when none did, and why it ended: the error of the call, a break of the stream's order, a
// bound that the collector passed, or the end of the stream that the collector chose.
func (st *stream) watch(ctx context.Context) (delivered time.Time, err error) {
	conn, err := st.pool.conn(st.collector)
	if err != nil {
		return time.Time{}, err
	}
	// The call ends when watch returns, as it does when the stream breaks its contract, and when its snapshot takes
	// too long, with that as the cause.
	callCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	call, err := collectorv1alpha1.NewEvidenceClient(conn).Watch(callCtx, st.spec.request)
	if err != nil {
		return time.Time{}, err
	}
	var state watchState
	defer state.clock.stop()
	for {
		resp, err := call.Recv()
		var passed boundError
		switch {
		case errors.Is(err, io.EOF):
			return state.delivered, errStreamEnded
		case ctx.Err() != nil:
			// The stream was stopped: what it receives now reaches no sink.
			return state.delivered, ctx.Err()
		case err != nil && errors.As(context.Cause(callCtx), &passed):
			return state.delivered, st.broke(passed)
		case err != nil:
			return state.delivered, err
		}
		if err := st.take(ctx, resp, &state, cancel); err != nil {
			if errors.As(err, &passed) {
				return state.delivered, st.broke(passed)
			}
			return state.delivered, err
		}
	}
}

// broke counts a bound that the collector passed, in the cluster of the stream's context, and returns it as why the
// stream ends, which logEnd logs.
func (st *stream) broke(passed boundError) error {
	CountBreak(st.spec.request.GetContext().GetCluster(), st.collector, passed.bound)
	return passed
}

// take hands an item of the stream to the sink, or holds it until the end of the snapshot, as the stream's order
// says. It returns how the item breaks the order, or a bound of the snapshot that it passes, which ends the stream. It
// drops an item that isn't valid, and logs that. cancel ends the call, once the snapshot that the item starts takes
// too long.
func (st *stream) take(ctx context.Context, resp *collectorv1alpha1.WatchResponse, state *watchState,
	cancel context.CancelCauseFunc) error {
	if state.at == inSnapshot {
		// Every message of the snapshot counts, valid or not: the stream holds or reads each.
		state.bytes += proto.Size(resp)
		if state.bytes > st.bounds.snapshotBytes {
			return boundError{bound: BoundSnapshotSize, why: fmt.Sprintf("the messages of the snapshot hold more than %d "+
				"bytes", st.bounds.snapshotBytes)}
		}
	}
	switch item := resp.GetItem().(type) {
	case *collectorv1alpha1.WatchResponse_SnapshotStart:
		if state.at != beforeSnapshot {
			return orderError("a second SnapshotStart came, and a stream holds one snapshot")
		}
		state.at, state.bytes = inSnapshot, proto.Size(resp)
		passed := boundError{bound: BoundSnapshotTime, why: fmt.Sprintf("the snapshot didn't end within %s of its start",
			st.bounds.snapshotTime)}
		state.clock.start(st.bounds.snapshotTime, func() { cancel(passed) })
	case *collectorv1alpha1.WatchResponse_Event:
		return st.takeEvent(ctx, item.Event, state)
	case *collectorv1alpha1.WatchResponse_SnapshotEnd:
		if state.at != inSnapshot {
			return orderError("SnapshotEnd came outside a snapshot")
		}
		if !state.clock.end() {
			// The snapshot's time passed as its end came: the clock has ended the call already.
			return boundError{bound: BoundSnapshotTime, why: fmt.Sprintf("the snapshot didn't end within %s of its start",
				st.bounds.snapshotTime)}
		}
		events := state.held
		state.at, state.held = afterSnapshot, nil
		st.sink.Snapshot(st.collector, events)
		state.delivered = time.Now()
		logf.FromContext(ctx).Info("Handed over a snapshot of the collector", "events", len(events))
	case *collectorv1alpha1.WatchResponse_Tombstone:
		if state.at != afterSnapshot {
			return orderError("a tombstone came before the end of the snapshot")
		}
		eventType, about := item.Tombstone.GetType(), item.Tombstone.GetSubject()
		if err := st.checkTombstone(eventType, about); err != nil {
			drop(ctx, "a tombstone", err)
			return nil
		}
		st.sink.Remove(st.collector, eventType, about)
	case *collectorv1alpha1.WatchResponse_SourceChanged:
		if state.at != afterSnapshot {
			return orderError("SourceChanged came before the end of the snapshot")
		}
		named := item.SourceChanged.GetSubjects()
		if err := checkSubjects(named); err != nil {
			// Without the subjects that don't parse, the change could name none, which means every subject.
			drop(ctx, "a SourceChanged", err)
			return nil
		}
		st.sink.SourceChanged(st.collector, slices.Clone(named))
	default:
		drop(ctx, "an item", errUnknownItem)
	}
	return nil
}

// takeEvent holds an event of the snapshot until its end, and hands an event after the snapshot to the sink at once.
func (st *stream) takeEvent(ctx context.Context, p *pb.CloudEvent, state *watchState) error {
	if state.at == beforeSnapshot {
		return orderError("an event came before SnapshotStart")
	}
	e, err := st.check(p)
	if err != nil {
		drop(ctx, "an event", err)
		return nil
	}
	if state.at == inSnapshot {
		state.held = append(state.held, e)
		return nil
	}
	st.sink.Upsert(st.collector, e)
	return nil
}

// Why the streams drop an item that a collector sent.
var (
	// errUndeclaredType drops an event or a tombstone of a type that the collector doesn't declare.
	errUndeclaredType = errors.New("its type isn't one that the collector declares")
	// errUnknownItem drops an item of a kind that this version of the API doesn't know.
	errUnknownItem = errors.New("it is of a kind that the API doesn't know")
)

// check converts an event that the collector sent, and checks it again: it is valid evidence, of a type that the
// collector declares. The SDK's server checks the same before it sends it, but a collector needn't be built with the
// SDK. The errors repeat nothing that the event holds.
func (st *stream) check(p *pb.CloudEvent) (cloudevents.Event, error) {
	e, err := evidence.FromProto(p)
	if err == nil {
		err = evidence.Validate(e)
	}
	if err != nil {
		return cloudevents.Event{}, fmt.Errorf("it isn't valid evidence: %w", err)
	}
	if !st.declares(e.Type()) {
		return cloudevents.Event{}, errUndeclaredType
	}
	return e, nil
}

// checkTombstone checks a tombstone: its type is one that the collector declares, and its subject parses.
func (st *stream) checkTombstone(eventType, about string) error {
	if !st.declares(eventType) {
		return errUndeclaredType
	}
	_, err := subjectpath.Parse(about)
	return err
}

// declares says whether the collector declares the type.
func (st *stream) declares(eventType string) bool {
	_, found := slices.BinarySearch(st.spec.produces, eventType)
	return found
}

// checkSubjects checks that each subject parses. subjectpath.Parse's errors don't repeat the subject.
func checkSubjects(named []string) error {
	for _, about := range named {
		if _, err := subjectpath.Parse(about); err != nil {
			return err
		}
	}
	return nil
}

// drop logs an item of a stream that isn't valid, which the stream drops: what it is, and why. Neither repeats what
// the collector chose, such as a subject, a type or an ID.
func drop(ctx context.Context, what string, why error) {
	logf.FromContext(ctx).Error(why, "Dropped an item of the collector's stream, which isn't valid", "item", what)
}
