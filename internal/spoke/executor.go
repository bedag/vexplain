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

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/collectorclient"
	"github.com/bedag/vexplain/internal/evidence"
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
	// breaks the API's contract, an error, or evidence that the facts can't hold.
	reasonInternal = "Internal"
	// reasonTooLarge is the reason of evidence that the evidence store can't hold.
	reasonTooLarge = "TooLarge"
)

// Executor implements tasks.Executor for the spoke: it runs the hub's requests for evidence about the images that
// run in its cluster, with the collectors there that produce the type asked for (design 5.6). Hub and spoke meet only
// through it and the stores (decision 0021).
//
//   - It queues one request per type and subject. A request for evidence that is being collected changes nothing;
//     one for a request that waits replaces it, with the newest repositories.
//   - It asks the collectors that are usable (collectorclient.Usable), take the spoke role, and have an operation
//     that produces the type, as their Collectors' recorded capabilities say. Each runs the operation for the image,
//     with the repositories of the request and up to 16 pods that run the image, from Presence: one of each platform
//     first, so that the collector covers every platform. An image that no pod runs in the cluster gets nothing.
//   - At most 16 requests run at once for one collector.
//   - What a collector returns is checked against its Collector's recorded capabilities: an event of a type that the
//     operation doesn't produce breaks the contract, so none of the answer is stored, and the request fails.
//   - The events go to evidence.Store.Put, under the Collector's name and at its status.version, and then to
//     FactsWriter.Succeeded. Evidence that the store can't hold fails the request as TooLarge. A request is about an
//     image, so the manifests that its events name are the image's, which replace those that its facts held.
//   - A failure goes to FactsWriter.Failed, with its text made printable and cut to what the facts hold: a Failure
//     about the image, an error with which the collector answered, and an answer that broke the contract. It is about
//     one subject, and never a health failure: the deployer's health check alone says whether a collector works. A
//     collector that couldn't be reached at all records nothing: that isn't the image's failure, and the hub asks
//     again after its wait. An answer with events and a Failure stores the events, and then records the failure.
//   - Nothing is written for a collector whose Collector is gone, is being deleted, or is another of the same name
//     by the time that its answer comes, so that no evidence comes after the deployer's finalizer has removed it.
//
// The hub asks again for what doesn't arrive, so a write that fails is logged, and not tried again here. Executor
// is a manager.Runnable, which the manager runs on its leader, as it runs the hub's assessor that asks it.
type Executor struct {
	pool     *collectorclient.Pool
	client   client.Client
	presence *Presence
	store    evidence.Store
	facts    evidence.FactsWriter
	context  func(ctx context.Context) (*collectorv1alpha1.Context, error)

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

// requestKey is what a request is for: a type of evidence about a subject.
type requestKey struct{ eventType, subject string }

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
		pending:  map[requestKey]tasks.Request{},
		running:  map[requestKey]bool{},
		slots:    map[string]chan struct{}{},
	}
}

// Request queues a request for evidence of a type about an image, and returns at once: the evidence arrives through
// the stores. It refuses a type that isn't one, a subject that isn't image/ and a sha256 digest, and a request that
// names no repository to pull the image from.
func (e *Executor) Request(_ context.Context, r tasks.Request) error {
	if !sdkevidence.ValidType(r.Type) {
		return fmt.Errorf("%q is no type of evidence", r.Type)
	}
	if about, err := subject.Parse(r.Subject); err != nil || about.Kind != subject.KindImage {
		return fmt.Errorf("can't collect evidence about %q: a request is about image/ and a sha256 digest", r.Subject)
	}
	if len(r.Repositories) == 0 || slices.Contains(r.Repositories, "") {
		return fmt.Errorf("can't collect evidence about %s: the request names no repository to pull it from", r.Subject)
	}
	key := requestKey{eventType: r.Type, subject: r.Subject}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.running[key] {
		return nil
	}
	_, waiting := e.pending[key]
	e.pending[key] = tasks.Request{Type: r.Type, Subject: r.Subject, Repositories: slices.Clone(r.Repositories)}
	if !waiting {
		e.dispatch(key)
	}
	return nil
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

// run runs the request of key with every collector that produces its type, at once, and returns once each has
// answered.
func (e *Executor) run(ctx context.Context, key requestKey) {
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

	log := logf.FromContext(ctx).WithValues("type", r.Type, "subject", r.Subject)
	var list configv1alpha1.CollectorList
	if err := e.client.List(ctx, &list); err != nil {
		log.Error(err, "Could not read the Collectors; the hub asks again")
		return
	}
	var wg sync.WaitGroup
	for i := range list.Items {
		if p, ok := producerOf(&list.Items[i], r.Type); ok {
			wg.Go(func() { e.invoke(logf.IntoContext(ctx, log.WithValues("collector", p.name)), p, r) })
		}
	}
	wg.Wait()
}

// producer is a usable collector with an operation that produces a type, as its Collector says: its name and UID,
// the operation and what it produces, the collector's version and its settings.
type producer struct {
	name      string
	uid       types.UID
	operation string
	produces  []string
	version   string
	settings  []byte
}

// producerOf returns the producer of the type that c is, if it is one: usable, in the spoke role, with a version and
// an operation that produces the type. Of several such operations, the first that the collector declares runs.
func producerOf(c *configv1alpha1.Collector, eventType string) (producer, bool) {
	if !collectorclient.Usable(c) || ptr.Deref(c.Status.Version, "") == "" ||
		!slices.Contains(c.Status.Capabilities.Roles, configv1alpha1.CollectorRoleSpoke) {
		return producer{}, false
	}
	for _, op := range c.Status.Capabilities.Operations {
		if !slices.Contains(op.Produces, eventType) {
			continue
		}
		p := producer{name: c.Name, uid: c.UID, operation: op.Name, produces: slices.Clone(op.Produces),
			version: *c.Status.Version}
		if c.Spec.Settings != nil {
			p.settings = slices.Clone(c.Spec.Settings.Raw)
		}
		return p, true
	}
	return producer{}, false
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
	events, failure, err := e.pool.Invoke(ctx, p.name, &collectorv1alpha1.InvokeRequest{
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
	// A failure alone is no success: it must not end the failures that the attempts count. An answer without either
	// is one, which delivered nothing.
	if (len(events) > 0 || failure == nil) && !e.keep(ctx, p, about.Digest, events) {
		return
	}
	if failure != nil {
		e.fail(ctx, p, about.Digest, failure.Reason, failure.Message)
	}
}

// failed records the error with which a call of the collector ended, unless the collector couldn't be reached at all:
// then nothing is recorded, since that isn't the image's failure, and the hub asks again. The code of the call is
// logged, and not its message, which is the collector's text.
func (e *Executor) failed(ctx context.Context, p producer, digest string, err error) {
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
// no evidence of the answer recorded in the facts.
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
		case err != nil:
			log.Error(err, "Could not store the evidence of the collector; the hub asks again")
			return false
		}
	}
	err := e.facts.Succeeded(ctx, digest, p.name, p.version, events)
	switch {
	case errors.Is(err, evidence.ErrRefused):
		// The error names what the facts can't hold in fixed texts.
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
