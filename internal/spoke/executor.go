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

package spoke

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/collectorclient"
	"github.com/bedag/vexplain/internal/evidence"
	"github.com/bedag/vexplain/internal/metrics"
	"github.com/bedag/vexplain/internal/tasks"
	"github.com/bedag/vexplain/internal/text"
	collectorv1alpha1 "github.com/bedag/vexplain/sdk/api/collector/v1alpha1"
	sdkevidence "github.com/bedag/vexplain/sdk/evidence"
	"github.com/bedag/vexplain/sdk/subject"
)

const (
	// maxPods is how many of the pods that run an image a request names: enough for a collector to find one whose
	// pull secrets work, and to cover each platform that runs it, while the parameters stay small.
	maxPods = 16
	// maxInvokes is how many requests run at once for one collector. A collector bounds its own work further, as the
	// scanner does with its scan Jobs.
	maxInvokes = 16
	// maxMessageLength is the most characters of a failure's message that the facts hold.
	maxMessageLength = 256
	// reasonInternal is the reason of a failure for which the collector gave no reason of its own: an answer that
	// breaks the API's contract, an error, or evidence that a store refuses.
	reasonInternal = "Internal"
	// reasonTooLarge is the reason of evidence that the evidence store can't hold.
	reasonTooLarge = "TooLarge"
	// reasonTimedOut is the reason of a request that the collector didn't answer within its deadline.
	reasonTimedOut = "TimedOut"
	// reasonNoEvidence is the reason of an answer without any evidence that the hub keeps, and without a failure.
	reasonNoEvidence = "NoEvidence"
	// droppedScope and droppedSubject are why an event of an answer isn't stored, as the metric of dropped evidence
	// names them: its type stays on the spoke, or it is about neither a platform manifest nor the image of the request.
	droppedScope   = "scope"
	droppedSubject = "subject"
	// presenceRecheck is how often a request that waits for presence reads the Collectors again: a collector that
	// it waits for can go, or stop being usable, without a snapshot. The streams read them as often.
	presenceRecheck = 5 * time.Second
	// longestScan is the longest that a scan Job of the scanner collector may run: the most that its setting
	// scanTimeoutSeconds allows, 6 hours.
	longestScan = 6 * time.Hour
	// invokeDeadline is how long a request waits for a collector's answer, above the longest operation of the
	// built-in collectors: a scan that waits for a slot of the scanner behind the scans of the other requests that
	// run for it, at most maxInvokes at once, and behind those that a previous process of the operator left, each of
	// up to longestScan, then runs its own, and an hour more for the rest. That is 103 hours.
	invokeDeadline = (maxInvokes+1)*longestScan + time.Hour
)

// errPassedDeadline is why a call of a collector ends that didn't answer within the deadline of its request.
var errPassedDeadline = errors.New("the collector didn't answer within the deadline of the request")

// Executor implements tasks.Executor for the spoke: it runs the hub's requests for evidence about the images that
// run in its cluster, with the collectors there that the request names (design 5.6, decision 0043). Hub and spoke
// meet only through it and the stores (decision 0021).
//
//   - It asks only the collectors that a request names, the producers whose evidence the hub misses, and of them only
//     those that can be asked, as collectorclient.OperationFor says: usable, with a version, in the spoke role, and
//     with an operation that produces the type, as their Collectors' recorded capabilities say. So a producer whose
//     evidence is current isn't asked to deliver it again, and each producer's failures and waits stay its own.
//   - It queues one request per collector, operation and image, since one operation can produce several types, as
//     the scanner's scan produces both the SBOM and the contents of each manifest. A request for an operation that is
//     running changes nothing; one for a request that waits replaces it, with the newest repositories.
//   - Each collector runs the operation for the image, with the repositories of the request and up to 16 pods that
//     run the image, from Presence: one of each platform first, so that the collector covers every platform. An
//     image that no pod runs in the cluster gets nothing.
//   - Presence knows the pods only once each collector that streams presence to it has delivered its first snapshot
//     since the start. So a request waits for that before it runs, and so before it can find that no pod runs its
//     image: otherwise each start would drop the requests that come before the snapshot, and the hub asks again only
//     after its wait. While it waits, it is a request that waits to run, which a newer one replaces. Without a
//     collector that streams presence, nothing waits.
//   - At most 16 requests run at once for one collector.
//   - A request waits for a collector's answer at most invokeDeadline, above the longest operation of the built-in
//     collectors. A collector that doesn't answer within it breaks the contract (design 5.9): the call ends, the
//     request fails as TimedOut, which frees its slot and lets the request run again, and the log and the metric of
//     contract breaks say so.
//   - What a collector returns is checked against its Collector's recorded capabilities: an event of a type that the
//     operation doesn't produce breaks the contract, so none of the answer is stored, and the request fails.
//   - Only what the hub's evidence takes is stored: evidence of a type that the Collector declares with the scope Hub,
//     about a platform manifest or about the image of the request. Anything else of the answer, as an event of a
//     type that stays on the spoke, or one about another image or a workload, is dropped, logged and counted in
//     vexplain_evidence_dropped_total, and the rest is stored.
//   - The events go to evidence.Store.Put, under the Collector's name and at its status.version, and then to
//     FactsWriter.Succeeded. Evidence that the store can't hold fails the request as TooLarge, and a write that a
//     store refuses, which would be refused again at every attempt, as Internal. A request is about an image, so the
//     manifests that its events name are the image's, which replace those that its facts held.
//   - A failure goes to FactsWriter.Failed, with its text made printable and cut to what the facts hold: a Failure
//     about the image, an error with which the collector answered, and an answer that broke the contract. It is about
//     one subject, and never a health failure: the deployer's health check alone says whether a collector works. A
//     collector that couldn't be reached at all records nothing: that isn't the image's failure, and the hub asks
//     again after its wait. An answer with events and a Failure stores the events, and then records the failure. An
//     answer without either, or whose every event is dropped, delivered nothing: it is the failure NoEvidence, so that
//     the collector waits as after any failure, and isn't asked again and again for nothing.
//   - Nothing is written for a collector whose Collector is gone, is being deleted, or is another of the same name
//     by the time that its answer comes, so that no evidence comes after the deployer's finalizer has removed it.
//
// The hub asks again for what doesn't arrive, so a write that fails on its way is logged, and not tried again here.
// Executor is a manager.Runnable, which the manager runs on its leader, as it runs the hub's assessor that asks it.
type Executor struct {
	pool     *collectorclient.Pool
	client   client.Client
	presence *Presence
	store    evidence.Store
	facts    evidence.FactsWriter
	context  func(ctx context.Context) (*collectorv1alpha1.Context, error)
	// deadline is how long a request waits for a collector's answer: invokeDeadline.
	deadline time.Duration

	mu sync.Mutex
	// pending holds the requests that wait to run, and running the keys of those that run.
	pending map[requestKey]tasks.Request
	running map[requestKey]bool
	// slots holds a semaphore of maxInvokes for each collector, by its name.
	slots map[string]chan struct{}
	// ctx is the context of Start, nil before it, and stopped is set once it has ended.
	ctx     context.Context
	stopped bool
	wg      sync.WaitGroup
}

var _ tasks.Executor = (*Executor)(nil)

// requestKey is what runs for a request: an operation of a collector, about a subject.
type requestKey struct{ collector, operation, subject string }

// NewExecutor returns the spoke's executor, which invokes the collectors through pool, reads their Collectors and the
// cluster's context through c, the pods that run each image from presence, and writes what they return to store and
// facts.
func NewExecutor(pool *collectorclient.Pool, c client.Client, presence *Presence, store evidence.Store,
	facts evidence.FactsWriter) *Executor {
	return &Executor{
		pool:     pool,
		client:   c,
		presence: presence,
		store:    store,
		facts:    facts,
		context:  collectorclient.ClusterContext(c, pool.Namespace()),
		deadline: invokeDeadline,
		pending:  map[requestKey]tasks.Request{},
		running:  map[requestKey]bool{},
		slots:    map[string]chan struct{}{},
	}
}

// Request queues a request for evidence of a type about an image for each collector that it names and that can be
// asked for the type now, and returns at once: the evidence arrives through the stores. A collector that can't be
// asked is skipped: the hub asks again after its wait. It refuses a type that isn't one, a subject that isn't image/
// and a sha256 digest, and a request that names no repository to pull the image from, or no collector to ask. A read
// of a Collector that fails is an error, and the hub asks again.
func (e *Executor) Request(ctx context.Context, r tasks.Request) error {
	if !sdkevidence.ValidType(r.Type) {
		return fmt.Errorf("%q is no type of evidence", r.Type)
	}
	if about, err := subject.Parse(r.Subject); err != nil || about.Kind != subject.KindImage {
		return fmt.Errorf("can't collect evidence about %q: a request is about image/ and a sha256 digest", r.Subject)
	}
	if len(r.Repositories) == 0 || slices.Contains(r.Repositories, "") {
		return fmt.Errorf("can't collect evidence about %s: the request names no repository to pull it from", r.Subject)
	}
	if len(r.Collectors) == 0 {
		return fmt.Errorf("can't collect evidence about %s: the request names no collector to ask", r.Subject)
	}
	for _, name := range r.Collectors {
		p, ok, err := e.producerNamed(ctx, name, r.Type)
		if err != nil {
			return fmt.Errorf("read the Collector %s to ask it for evidence about %s: %w", name, r.Subject, err)
		}
		if !ok {
			logf.FromContext(ctx).V(1).Info("Asked no collector that can't be asked for the type now", "collector", name,
				"type", r.Type, "subject", r.Subject)
			continue
		}
		e.queue(requestKey{collector: p.name, operation: p.operation, subject: r.Subject},
			tasks.Request{Type: r.Type, Subject: r.Subject, Repositories: slices.Clone(r.Repositories), Collectors: []string{name}})
	}
	return nil
}

// queue queues the request under its key, unless the key's operation is running: one that waits is replaced, with the
// newest repositories.
func (e *Executor) queue(key requestKey, r tasks.Request) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.running[key] {
		return
	}
	_, waiting := e.pending[key]
	e.pending[key] = r
	if !waiting {
		e.dispatch(key)
	}
}

// Start runs the requests until ctx ends, those that came before it first, and returns nil once the requests that
// run have ended.
func (e *Executor) Start(ctx context.Context) error {
	e.mu.Lock()
	e.ctx = logf.IntoContext(ctx, ctrl.Log.WithName("spoke-executor"))
	for key := range e.pending {
		e.dispatch(key)
	}
	e.mu.Unlock()
	<-ctx.Done()
	e.mu.Lock()
	e.stopped = true
	e.mu.Unlock()
	e.wg.Wait()
	return nil
}

// dispatch runs the request of key, once Start runs and until it has ended. The caller holds the lock.
func (e *Executor) dispatch(key requestKey) {
	if e.ctx == nil || e.stopped {
		return
	}
	ctx := e.ctx
	e.wg.Go(func() { e.run(ctx, key) })
}

// run runs the request of key with its collector, and returns once the collector has answered. It waits first, until
// presence knows what runs, as awaitPresence says: the request stays one that waits to run until then.
func (e *Executor) run(ctx context.Context, key requestKey) {
	if !e.awaitPresence(ctx, key) {
		return
	}
	e.mu.Lock()
	r, ok := e.pending[key]
	delete(e.pending, key)
	if ok {
		e.running[key] = true
	}
	e.mu.Unlock()
	if !ok {
		return
	}
	defer func() {
		e.mu.Lock()
		defer e.mu.Unlock()
		delete(e.running, key)
	}()

	log := logf.FromContext(ctx).WithValues("type", r.Type, "subject", r.Subject, "collector", key.collector)
	e.invoke(logf.IntoContext(ctx, log), producer{name: key.collector}, r)
}

// awaitPresence waits until presence has the first snapshot, since the start, of each collector that streams presence
// to it, until ctx ends, and reports whether it has them. Without such a collector it doesn't wait. While it waits, it
// reads the Collectors again every presenceRecheck, as a collector that it waits for can go, or stop being usable,
// without a snapshot. A read that fails is tried again then: the request is kept. key names the request, for the log.
func (e *Executor) awaitPresence(ctx context.Context, key requestKey) bool {
	log := logf.FromContext(ctx).WithValues("collector", key.collector, "operation", key.operation, "subject", key.subject)
	logged := false
	for {
		// A nil channel wakes nothing: after a read that failed, only the next look does.
		var arrival <-chan struct{}
		var list configv1alpha1.CollectorList
		if err := e.client.List(ctx, &list); err != nil {
			log.Error(err, "Could not read the Collectors to tell whether presence knows what runs; the request waits")
		} else {
			var known bool
			if known, arrival = e.presence.HasSnapshotsOf(streamingCollectors(&list, sdkevidence.TypePresence)); known {
				return true
			}
		}
		if !logged {
			log.V(1).Info("Waiting until presence knows what runs in the cluster")
			logged = true
		}
		timer := time.NewTimer(presenceRecheck)
		select {
		case <-ctx.Done():
			timer.Stop()
			return false
		case <-arrival:
		case <-timer.C:
		}
		timer.Stop()
	}
}

// streamingCollectors returns the names of the collectors of the list that stream events of a type to the spoke's
// consumer of it: usable, watching in the spoke role, and declaring that they produce the type, as their Collectors'
// recorded capabilities say. These are the collectors whose streams the Router hands to that consumer.
func streamingCollectors(list *configv1alpha1.CollectorList, eventType string) []string {
	var names []string
	for i := range list.Items {
		c := &list.Items[i]
		if !collectorclient.Usable(c) || c.Status.Capabilities.Watch != configv1alpha1.CollectorWatchSupported ||
			!slices.Contains(c.Status.Capabilities.Roles, configv1alpha1.CollectorRoleSpoke) {
			continue
		}
		if slices.ContainsFunc(c.Status.Capabilities.Produces, func(p configv1alpha1.ProducedType) bool {
			return p.Type == eventType
		}) {
			names = append(names, c.Name)
		}
	}
	return names
}

// producer is a usable collector with an operation that produces a type, as its Collector says: its name and UID,
// the operation and what it produces, the types that it declares with the scope Hub, the collector's version and its
// settings.
type producer struct {
	name      string
	uid       types.UID
	operation string
	produces  []string
	hubTypes  map[string]bool
	version   string
	settings  []byte
}

// producerOf returns the producer of the type that c is, if it can be asked for it now, as
// collectorclient.OperationFor says: usable, in the spoke role, with a version and an operation that produces the
// type. Of several such operations, the first that the collector declares runs.
func producerOf(c *configv1alpha1.Collector, eventType string) (producer, bool) {
	op, ok := collectorclient.OperationFor(c, eventType)
	if !ok {
		return producer{}, false
	}
	p := producer{name: c.Name, uid: c.UID, operation: op.Name, produces: slices.Clone(op.Produces),
		hubTypes: map[string]bool{}, version: *c.Status.Version}
	for _, produced := range c.Status.Capabilities.Produces {
		if produced.Scope == configv1alpha1.EvidenceScopeHub {
			p.hubTypes[produced.Type] = true
		}
	}
	if c.Spec.Settings != nil {
		p.settings = slices.Clone(c.Spec.Settings.Raw)
	}
	return p, true
}

// parameters are what a request gives a collector's operation about an image: the repositories that it was pulled
// from, and pods that run it.
type parameters struct {
	Repositories []string `json:"repositories"`
	Pods         []podRef `json:"pods"`
}

// podRef names a pod.
type podRef struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

// invoke runs the request r with the collector of p, when one of its slots is free, and writes what it returns. It
// logs through the logger of ctx, which names the collector.
func (e *Executor) invoke(ctx context.Context, p producer, r tasks.Request) {
	log := logf.FromContext(ctx)
	release, ok := e.takeSlot(ctx, p.name)
	if !ok {
		return
	}
	defer release()
	// The Collector may have changed while the request waited for its slot.
	p, ok, err := e.producerNamed(ctx, p.name, r.Type)
	if err != nil || !ok {
		log.V(1).Info("The collector can't be asked any more", "error", err)
		return
	}
	about, _ := subject.Parse(r.Subject)
	pods := podsOf(e.presence.Workloads(about.Digest))
	if len(pods) == 0 {
		log.V(1).Info("No pod runs the image in this cluster: nothing to collect")
		return
	}
	params, err := json.Marshal(parameters{Repositories: r.Repositories, Pods: pods})
	if err != nil {
		log.Error(err, "Could not encode the parameters of the request")
		return
	}
	clusterContext, err := e.context(ctx)
	if err != nil {
		log.Error(err, "Could not build the context of the collectors; the hub asks again")
		return
	}
	// The executor's own timer ends a call past the deadline, with that as its cause, rather than a deadline that the
	// call carries: a collector that ends the call itself, as its copy of a carried deadline passes, could otherwise
	// pass for one that couldn't be reached.
	callCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	timer := time.AfterFunc(e.deadline, func() { cancel(errPassedDeadline) })
	defer timer.Stop()
	events, failure, err := e.pool.Invoke(callCtx, p.name, &collectorv1alpha1.InvokeRequest{
		Operation:  p.operation,
		Subject:    r.Subject,
		Parameters: params,
		Settings:   p.settings,
		Context:    clusterContext,
		Role:       collectorv1alpha1.Role_ROLE_SPOKE,
	})
	switch {
	case ctx.Err() != nil:
		return
	case err != nil && errors.Is(context.Cause(callCtx), errPassedDeadline):
		collectorclient.CountBreak(clusterContext.GetCluster(), p.name, collectorclient.BoundDeadline)
		log.Info("The collector didn't answer within the deadline of a request, which breaks the contract: the request "+
			"fails as TimedOut", "bound", collectorclient.BoundDeadline, "deadline", e.deadline.String())
		e.fail(ctx, p, about.Digest, reasonTimedOut,
			fmt.Sprintf("the collector didn't answer within the deadline of a request, %s", e.deadline))
		return
	case err != nil:
		e.failed(ctx, p, about.Digest, err)
		return
	}
	for _, ev := range events {
		if !slices.Contains(p.produces, ev.Type()) {
			e.fail(ctx, p, about.Digest, reasonInternal,
				"the collector returned evidence of a type that its operation doesn't produce, and none of it is kept")
			return
		}
	}
	events = hubEvidence(ctx, p, about.Digest, clusterContext.GetCluster(), events)
	// A failure alone is no success: it must not end the failures that the attempts count. An answer without either
	// delivered nothing, which is a failure of its own: the collector waits as after any, and the hub doesn't ask it
	// for nothing at each look.
	switch {
	case len(events) == 0 && failure == nil:
		e.fail(ctx, p, about.Digest, reasonNoEvidence, "the collector answered without any evidence about the image that "+
			"the hub keeps")
		return
	case len(events) > 0 && !e.keep(ctx, p, about.Digest, events):
		return
	}
	if failure != nil {
		e.fail(ctx, p, about.Digest, failure.Reason, failure.Message)
	}
}

// hubEvidence returns the events of an answer about the image that the hub's evidence takes: of a type that the
// Collector declares with the scope Hub, about a platform manifest or about the image. It drops the others, and logs
// and counts each, in the cluster, with why and without anything that the collector chose.
func hubEvidence(ctx context.Context, p producer, image, cluster string, events []cloudevents.Event) []cloudevents.Event {
	kept := make([]cloudevents.Event, 0, len(events))
	for _, ev := range events {
		var dropped string
		about, err := subject.Parse(ev.Subject())
		switch {
		case !p.hubTypes[ev.Type()]:
			dropped = droppedScope
		case err != nil || (about.Kind != subject.KindManifest && (about.Kind != subject.KindImage || about.Digest != image)):
			dropped = droppedSubject
		default:
			kept = append(kept, ev)
			continue
		}
		metrics.EvidenceDroppedTotal.WithLabelValues(cluster, p.name, dropped).Inc()
		logf.FromContext(ctx).Info("Dropped an event of the collector's answer, which the hub's evidence doesn't take: "+
			"the rest of the answer is stored", "reason", dropped)
	}
	return kept
}

// failed records the error with which a call of the collector ended, unless the collector couldn't be reached at all:
// then nothing is recorded, since that isn't the image's failure, and the hub asks again. An answer that breaks the
// API's contract is recorded with what breaks it, which the pool says in fixed texts. The code of the call is logged,
// and not its message, which is the collector's text.
func (e *Executor) failed(ctx context.Context, p producer, digest string, err error) {
	if errors.Is(err, collectorclient.ErrContract) {
		e.fail(ctx, p, digest, reasonInternal, err.Error())
		return
	}
	code := status.Code(err)
	switch code {
	case codes.Unavailable, codes.DeadlineExceeded, codes.Canceled:
		logf.FromContext(ctx).Info("The collector couldn't be reached; the hub asks again", "code", code.String())
		return
	}
	// The pool wraps the status that the collector answered with, whose message is the collector's own.
	message := "the collector answered with " + code.String()
	var answered interface{ GRPCStatus() *status.Status }
	if errors.As(err, &answered) && answered.GRPCStatus().Message() != "" {
		message += ": " + answered.GRPCStatus().Message()
	}
	e.fail(ctx, p, digest, reasonInternal, message)
}

// keep stores the events of p at its version, and records them in the facts of the image of digest, unless its
// Collector is gone. It reports whether it did. Evidence that the store can't hold is the failure TooLarge, and so is
// no evidence of the answer recorded in the facts. A write that a store refuses, which would be refused again at every
// attempt, is the failure Internal: so the attempts count, and the image waits as after any failure. A write that
// failed on its way is only logged, and the hub asks again.
func (e *Executor) keep(ctx context.Context, p producer, digest string, events []cloudevents.Event) bool {
	log := logf.FromContext(ctx)
	if !e.stillThere(ctx, p) {
		return false
	}
	for _, ev := range events {
		err := e.store.Put(ctx, p.name, p.version, ev)
		switch {
		case errors.Is(err, evidence.ErrTooLarge):
			e.fail(ctx, p, digest, reasonTooLarge, "a piece of the evidence is more than the evidence store holds")
			return false
		case refused(err):
			log.Info("The evidence store refuses what the collector delivered", "cause", err.Error())
			e.fail(ctx, p, digest, reasonInternal, "the evidence store refuses what the collector delivered")
			return false
		case err != nil:
			log.Error(err, "Could not store the evidence of the collector; the hub asks again")
			return false
		}
	}
	err := e.facts.Succeeded(ctx, digest, p.name, p.version, events)
	switch {
	case refused(err):
		log.Info("The facts can't hold what the collector delivered", "cause", err.Error())
		e.fail(ctx, p, digest, reasonInternal, "the facts can't hold what the collector delivered")
		return false
	case err != nil:
		log.Error(err, "Could not record the evidence of the collector in the facts; the hub asks again")
		return false
	}
	log.V(1).Info("Stored what the collector delivered", "events", len(events))
	return true
}

// refused reports whether a store refused a write, so that asking again changes nothing: with ErrRefused, or because
// the API server found the object invalid, or the request bad.
func refused(err error) bool {
	return errors.Is(err, evidence.ErrRefused) || apierrors.IsInvalid(err) || apierrors.IsBadRequest(err)
}

// fail records a failure of p about the image of digest in its facts, unless its Collector is gone. The message is
// the collector's text: it is made printable and cut to what the facts hold. The facts record a reason that isn't a
// word of their vocabulary as Internal.
func (e *Executor) fail(ctx context.Context, p producer, digest, reason, message string) {
	log := logf.FromContext(ctx)
	if !e.stillThere(ctx, p) {
		return
	}
	message = text.CutChars(text.Printable(message), maxMessageLength)
	err := e.facts.Failed(ctx, digest, p.name, reason, message)
	switch {
	case errors.Is(err, evidence.ErrRefused):
		log.Info("Dropped a failure of the collector, which the facts can't hold")
	case err != nil:
		log.Error(err, "Could not record a failure of the collector; the hub asks again")
	default:
		log.V(1).Info("Recorded a failure of the collector")
	}
}

// stillThere reports whether the Collector of p still exists, as the same one, and isn't being deleted. It is read
// just before each write, so that nothing is written after the deployer's finalizer has removed what the collector
// delivered. A read that fails writes nothing either: the hub asks again.
func (e *Executor) stillThere(ctx context.Context, p producer) bool {
	log := logf.FromContext(ctx)
	var c configv1alpha1.Collector
	if err := e.client.Get(ctx, client.ObjectKey{Name: p.name}, &c); err != nil {
		log.V(1).Info("Dropped what the collector returned: its Collector can't be read, or is gone", "error", err)
		return false
	}
	if c.UID != p.uid || !c.DeletionTimestamp.IsZero() {
		log.V(1).Info("Dropped what the collector returned: its Collector is being deleted, or is gone")
		return false
	}
	return true
}

// producerNamed reads the Collector of the name again, and returns the producer of the type that it is now.
func (e *Executor) producerNamed(ctx context.Context, name, eventType string) (producer, bool, error) {
	var c configv1alpha1.Collector
	if err := e.client.Get(ctx, client.ObjectKey{Name: name}, &c); err != nil {
		return producer{}, false, client.IgnoreNotFound(err)
	}
	p, ok := producerOf(&c, eventType)
	return p, ok, nil
}

// takeSlot waits for a free slot of the collector, until ctx ends. It returns the function that frees it, and false
// when ctx ended first.
func (e *Executor) takeSlot(ctx context.Context, collector string) (func(), bool) {
	e.mu.Lock()
	slot, ok := e.slots[collector]
	if !ok {
		slot = make(chan struct{}, maxInvokes)
		e.slots[collector] = slot
	}
	e.mu.Unlock()
	select {
	case slot <- struct{}{}:
		return func() { <-slot }, true
	case <-ctx.Done():
		return nil, false
	}
}

// podsOf returns up to maxPods of the pods of the workloads: first one of each platform, in the order of the
// workloads and their pods, so that a collector that scans the platforms of the pods' nodes covers each, and then the
// others in that order.
func podsOf(workloads []sdkevidence.PresenceWorkload) []podRef {
	type candidate struct {
		ref      podRef
		platform string
	}
	var all []candidate
	for _, w := range workloads {
		for _, pod := range w.Pods {
			all = append(all, candidate{ref: podRef{Namespace: w.Namespace, Name: pod.Name}, platform: pod.Platform})
		}
	}
	chosen := make([]podRef, 0, min(len(all), maxPods))
	taken := make([]bool, len(all))
	platforms := map[string]bool{}
	for i, c := range all {
		if len(chosen) < maxPods && !platforms[c.platform] {
			platforms[c.platform] = true
			taken[i] = true
			chosen = append(chosen, c.ref)
		}
	}
	for i, c := range all {
		if len(chosen) < maxPods && !taken[i] {
			chosen = append(chosen, c.ref)
		}
	}
	slices.SortStableFunc(chosen, func(a, b podRef) int {
		return cmp.Or(cmp.Compare(a.Namespace, b.Namespace), cmp.Compare(a.Name, b.Name))
	})
	return chosen
}
