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
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/go-logr/logr"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/evidence"
	"github.com/bedag/vexplain/internal/metrics"
	sdkevidence "github.com/bedag/vexplain/sdk/evidence"
)

const (
	// storeWorkers is how many collectors' records the sink writes at once, so that a large snapshot of one collector
	// doesn't hold up the changes of another. The records of one collector are written by one worker at a time.
	storeWorkers = 4
	// firstStoreRetry is how long the sink waits before it writes a collector's records again after a failure, the
	// first time. Each wait after that is twice the last, and maxStoreRetry at most.
	firstStoreRetry = time.Second
	maxStoreRetry   = time.Minute
	// reasonInvalid is the reason of an event that the evidence store refuses because it doesn't fit what a record
	// holds, or of presence or exposure off the core's schema, beside reasonTooLarge for one over the store's cap.
	reasonInvalid = "Invalid"
)

// Why the sink waits before it writes a collector's records, as after a failed write.
var (
	errNoCluster      = errors.New("the cluster's name isn't known")
	errNoVersion      = errors.New("the Collector records no version of the collector")
	errNoCapabilities = errors.New("the Collector records no capabilities of the collector")
)

// StoreSink implements collectorclient.Sink for the spoke role, beside the Router: it stores in the evidence store each
// event that a collector streams of a type that it declares with the scope Hub, keyed and labelled with this cluster,
// so that the hub reads it as it reads the evidence that operations return (decision 0058). The Router still hands the
// same events to the spoke's own consumers.
//
//   - A snapshot stores each of its events of such a type, and deletes the collector's records of the type in this
//     cluster that it doesn't hold. It deletes every record of a type that the collector declared with the scope Hub
//     before and doesn't any more, as after a downgrade: nothing would keep them current. A change stores its event,
//     and a tombstone deletes its record. Presence that names no workload says that its image runs nowhere, as the
//     spoke's Presence reads it, and so deletes its record too.
//   - Forget deletes the collector's records in this cluster of each type that it declared with the scope Hub, as the
//     sink last read. The records of other clusters, and the evidence that operations returned, stay.
//   - The sink reads which types a collector declares with the scope Hub, and the version at which it stores the
//     collector's events, from its Collector at each snapshot. When it can't, it keeps what it read before. A snapshot
//     of a collector whose scopes it hasn't read since the start, or since Forget, waits instead, with the changes
//     after it, one state per collector, which a newer call changes as it would change stored records: the next
//     snapshot could be hours away. The sink then reads the Collector again at each round of the collector, after the
//     queue's pause, and once it can, it stores the snapshot as any other.
//   - No call waits for the store: each records what it wants of a record, its newest event or its deletion, which
//     replaces what an earlier call wanted and the sink hasn't written yet, and returns. A worker writes it later,
//     the records of one collector one at a time: what a snapshot or Forget deletes comes after the records that the
//     sink took with it, and leaves what any later call holds, so that it never deletes a newer record.
//   - A round of writes that fails waits a second before it is tried again, then twice as long each time, a minute at
//     most, and so do the writes while the cluster's name or the collector's version isn't known.
//   - An event that the store refuses, over its cap or more than a record holds, would be refused at every attempt: it
//     is dropped, logged without what it holds, and counted in vexplain_evidence_streamed_refused_total. So is presence
//     or exposure whose data doesn't follow the core's schema, which the spoke's own consumers can't read either. The
//     record of its subject is deleted, as any record, so that the hub never reads an older event as what the
//     collector says now: the hub lacks the record until an event of the subject fits. Presence off the schema keeps
//     its record instead, as the spoke's presence never forgets what it can't read (decision 0067): the hub reads the
//     cluster's presence as the collector last sent it in a form that fits, stale and never missing.
//   - The cluster is the one that the OperatorConfig names when the records are written. A renamed cluster leaves the
//     records of its old name, which the label vexplain.bedag.ch/cluster selects.
//
// StoreSink is a manager.Runnable, which the manager runs on its leader only, as it runs the streams that call it.
// What the sink hasn't written when the leader stops is lost with it: the next leader's streams start with snapshots.
type StoreSink struct {
	store      evidence.Store
	collectors client.Reader
	cluster    func(context.Context) (string, error)
	log        logr.Logger
	queue      workqueue.TypedRateLimitingInterface[string]

	mu sync.Mutex
	// streamed is what the sink knows of each collector's records, by the collector's name.
	streamed map[string]*collectorRecords
}

// collectorRecords is what the sink knows of one collector: its version, and its records by type, of each type that it
// declares with the scope Hub, or that has records to delete.
type collectorRecords struct {
	version string
	types   map[string]*typeRecords
	// scoped says that the sink read the collector's scopes since the start, and since the last Forget.
	scoped bool
	// waiting is a snapshot that came while the collector's scopes weren't known, with the changes after it: records
	// of every type, as if each were of the scope Hub, until a read of the Collector tells which are. Nil when none
	// waits.
	waiting map[string]*typeRecords
}

// learn records what a read of the collector's Collector gave: its version, and the types that it declares with the
// scope Hub, each of which gets records. The caller holds the lock.
func (c *collectorRecords) learn(version string, hub map[string]bool) {
	c.version, c.scoped = version, true
	for eventType, r := range c.types {
		r.hub = hub[eventType]
	}
	for eventType := range hub {
		if c.types[eventType] == nil {
			r := &typeRecords{hub: true}
			r.reset()
			c.types[eventType] = r
		}
	}
}

// recordsOf returns the records of the type that a call changes: those of the snapshot that waits for the collector's
// scopes, of any type, or else those of a type that the collector declares with the scope Hub, or nil. The caller
// holds the lock.
func (c *collectorRecords) recordsOf(eventType string) *typeRecords {
	if c.waiting != nil {
		r := c.waiting[eventType]
		if r == nil {
			r = &typeRecords{}
			r.reset()
			c.waiting[eventType] = r
		}
		return r
	}
	if r := c.types[eventType]; r != nil && r.hub {
		return r
	}
	return nil
}

// typeRecords are a collector's records of one type in this cluster, as the sink wants them.
type typeRecords struct {
	// hub says whether the collector declares the type with the scope Hub, as the sink last read.
	hub bool
	// held holds the subject of each record that the collector holds, as its calls so far say.
	held map[string]bool
	// wanted holds what the sink hasn't written yet, by subject: the event to store, or nil to delete the record.
	wanted map[string]*cloudevents.Event
	// prune says that the records that the collector doesn't hold are to be deleted.
	prune bool
}

// reset makes the records those of a collector that holds none, and so has every record deleted.
func (r *typeRecords) reset() {
	r.held, r.wanted, r.prune = map[string]bool{}, map[string]*cloudevents.Event{}, true
}

// NewStoreSink returns the sink that stores what the streams of the spoke role deliver of a type of the scope Hub in
// store. It reads the Collectors through collectors, and the cluster's name through cluster at each round of writes.
func NewStoreSink(store evidence.Store, collectors client.Reader,
	cluster func(context.Context) (string, error)) *StoreSink {
	return &StoreSink{
		store:      store,
		collectors: collectors,
		cluster:    cluster,
		log:        ctrl.Log.WithName("spoke-store-sink"),
		queue: workqueue.NewTypedRateLimitingQueue(
			workqueue.NewTypedItemExponentialFailureRateLimiter[string](firstStoreRetry, maxStoreRetry)),
		streamed: map[string]*collectorRecords{},
	}
}

// Snapshot replaces what the collector holds of each type that it declares with the scope Hub with the events of its
// snapshot, and has its records that the snapshot doesn't hold deleted, those of each type that it declared with the
// scope Hub before and doesn't any more included. A snapshot of a collector whose scopes the sink doesn't know waits
// until a read of its Collector tells them.
func (s *StoreSink) Snapshot(collector string, events []cloudevents.Event) {
	version, hub, err := s.declared(context.Background(), collector)
	// Telling empty presence decodes it, which needn't hold the lock.
	held := slices.DeleteFunc(slices.Clone(events), emptyPresence)
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.streamed[collector]
	if c == nil {
		c = &collectorRecords{types: map[string]*typeRecords{}}
		s.streamed[collector] = c
	}
	switch {
	case err == nil:
		c.learn(version, hub)
		c.waiting = nil
	case c.scoped:
		s.log.Error(err, "Could not read which types the collector declares with the scope Hub; the sink keeps what it "+
			"read before", "collector", collector)
	default:
		s.log.Error(err, "Could not read which types the collector declares with the scope Hub; its snapshot waits "+
			"until a read works", "collector", collector)
		c.waiting = map[string]*typeRecords{}
	}
	if c.waiting == nil {
		for _, r := range c.types {
			r.reset()
		}
	}
	for _, e := range held {
		if r := c.recordsOf(e.Type()); r != nil {
			r.held[e.Subject()] = true
			r.wanted[e.Subject()] = &e
		}
	}
	s.queue.Add(collector)
}

// declared reads the collector's version, and the types that it declares with the scope Hub, from its Collector's
// status, as the Router reads what it declares.
func (s *StoreSink) declared(ctx context.Context, collector string) (string, map[string]bool, error) {
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()
	var c configv1alpha1.Collector
	if err := s.collectors.Get(ctx, client.ObjectKey{Name: collector}, &c); err != nil {
		return "", nil, err
	}
	if c.Status.Capabilities == nil {
		return "", nil, errNoCapabilities
	}
	hub := map[string]bool{}
	for _, produced := range c.Status.Capabilities.Produces {
		if produced.Scope == configv1alpha1.EvidenceScopeHub {
			hub[produced.Type] = true
		}
	}
	return ptr.Deref(c.Status.Version, ""), hub, nil
}

// emptyPresence reports whether e is presence that names no workload, as the spoke's presence reads it. Presence that
// it can't read says nothing, and is no removal.
func emptyPresence(e cloudevents.Event) bool {
	_, presence, err := parse(e)
	return err == nil && len(presence.Workloads) == 0
}

// Upsert stores a change of a type that the collector declares with the scope Hub. Presence that names no workload
// deletes its record instead, as a tombstone does.
func (s *StoreSink) Upsert(collector string, e cloudevents.Event) {
	if emptyPresence(e) {
		s.Remove(collector, e.Type(), e.Subject())
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if c := s.streamed[collector]; c != nil {
		if r := c.recordsOf(e.Type()); r != nil {
			r.held[e.Subject()] = true
			r.wanted[e.Subject()] = &e
			s.wake(c, collector)
		}
	}
}

// Remove deletes the record of a tombstone of a type that the collector declares with the scope Hub.
func (s *StoreSink) Remove(collector, eventType, subject string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c := s.streamed[collector]; c != nil {
		if r := c.recordsOf(eventType); r != nil {
			delete(r.held, subject)
			r.wanted[subject] = nil
			s.wake(c, collector)
		}
	}
}

// wake queues the collector for a round of writes, unless its snapshot waits for its scopes: the queue brings it back
// after its pause, and a change doesn't hurry the read. The caller holds the lock.
func (s *StoreSink) wake(c *collectorRecords, collector string) {
	if c.waiting == nil {
		s.queue.Add(collector)
	}
}

// SourceChanged does nothing: it asks for a collector's operations to run again, and what the collector streams
// changes through its stream.
func (s *StoreSink) SourceChanged(string, []string) {}

// Forget deletes the collector's records in this cluster, of each type that it declared with the scope Hub as the
// sink last read, because its Collector is gone, or it doesn't stream in the spoke role any more. Its scopes are
// unknown again, and a snapshot that waits for them goes: nothing of it was stored.
func (s *StoreSink) Forget(collector string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.streamed[collector]
	if c == nil {
		return
	}
	c.scoped, c.waiting = false, nil
	for _, r := range c.types {
		r.hub = false
		r.reset()
	}
	s.queue.Add(collector)
}

// Start writes what the calls want, with storeWorkers workers, until ctx ends. It then stops the workers, and returns
// nil once none writes any more.
func (s *StoreSink) Start(ctx context.Context) error {
	ctx = logf.IntoContext(ctx, logf.FromContext(ctx).WithName("spoke-store-sink"))
	var workers sync.WaitGroup
	for range storeWorkers {
		workers.Go(func() {
			for {
				collector, shutdown := s.queue.Get()
				if shutdown {
					return
				}
				s.process(ctx, collector)
			}
		})
	}
	<-ctx.Done()
	s.queue.ShutDown()
	workers.Wait()
	return nil
}

// process writes what the calls want of the collector's records, and has the queue bring the collector back after a
// pause when that fails.
func (s *StoreSink) process(ctx context.Context, collector string) {
	defer s.queue.Done(collector)
	if err := s.write(ctx, collector); err != nil {
		if ctx.Err() == nil {
			logf.FromContext(ctx).Error(err, "Could not store what the collector streamed for the hub; trying again "+
				"after a pause", "collector", collector)
		}
		s.queue.AddRateLimited(collector)
		return
	}
	s.queue.Forget(collector)
}

// pending is what a call wants of a record: its event stored, or, without one, the record deleted.
type pending struct {
	eventType, subject string
	event              *cloudevents.Event
}

// write writes what the calls want of the collector's records: first each record that they want stored or deleted,
// then, of each type whose snapshot or Forget asks for it, the deletion of the records that the collector doesn't
// hold. It stops at the first write that fails, and keeps what it didn't do for the next round. A snapshot that waits
// for the collector's scopes is applied first, once a read of its Collector tells them.
func (s *StoreSink) write(ctx context.Context, collector string) error {
	if err := s.applyWaiting(ctx, collector); err != nil {
		return err
	}
	cluster, err := s.cluster(ctx)
	if err == nil && cluster == "" {
		err = errNoCluster
	}
	if err != nil {
		return err
	}
	version, records, prunes := s.take(collector)
	for i := range records {
		if err := s.writeRecord(ctx, cluster, collector, version, &records[i]); err != nil {
			s.restore(collector, records[i:], prunes)
			return err
		}
	}
	for i, eventType := range prunes {
		if err := s.store.DeleteStreamed(ctx, cluster, collector, eventType, s.holds(collector, eventType)); err != nil {
			s.restore(collector, nil, prunes[i:])
			return err
		}
	}
	s.tidy(collector)
	return nil
}

// applyWaiting reads the scopes of the collector whose snapshot waits for them, and applies the snapshot, with the
// changes after it, as a snapshot whose read worked: each type of the scope Hub gets what it holds, and every type's
// records that it doesn't hold are deleted. It does nothing when no snapshot waits.
func (s *StoreSink) applyWaiting(ctx context.Context, collector string) error {
	s.mu.Lock()
	c := s.streamed[collector]
	waits := c != nil && c.waiting != nil
	s.mu.Unlock()
	if !waits {
		return nil
	}
	version, hub, err := s.declared(ctx, collector)
	if err != nil {
		return fmt.Errorf("read which types the collector declares with the scope Hub: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c = s.streamed[collector]
	if c == nil || c.waiting == nil {
		// A snapshot whose read worked, or Forget, came while this read ran.
		return nil
	}
	c.learn(version, hub)
	for eventType, r := range c.types {
		r.reset()
		if w := c.waiting[eventType]; w != nil && r.hub {
			r.held, r.wanted = w.held, w.wanted
		}
	}
	c.waiting = nil
	return nil
}

// take hands over what the calls want of the collector's records and the sink hasn't written yet: the collector's
// version, the records to store or delete, and the types whose records that the collector doesn't hold are to be
// deleted.
func (s *StoreSink) take(collector string) (string, []pending, []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.streamed[collector]
	if c == nil {
		return "", nil, nil
	}
	var records []pending
	var prunes []string
	for eventType, r := range c.types {
		for subject, e := range r.wanted {
			records = append(records, pending{eventType: eventType, subject: subject, event: e})
		}
		r.wanted = map[string]*cloudevents.Event{}
		if r.prune {
			prunes = append(prunes, eventType)
			r.prune = false
		}
	}
	return c.version, records, prunes
}

// writeRecord stores the event of p in the cluster, under the collector's name and at its version, or deletes p's
// record. An event that the store refuses, which it would refuse at every attempt, is dropped, logged and counted, and
// p becomes the deletion of its record, which is written as any other: a record of an older event would read on the
// hub as what the collector says now, and missing evidence is no verdict, where stale evidence would be a guess.
// Presence off the core's schema keeps its record, as the spoke's presence keeps what it last read (decision 0067).
func (s *StoreSink) writeRecord(ctx context.Context, cluster, collector, version string, p *pending) error {
	if p.event != nil {
		if version == "" {
			return errNoVersion
		}
		err := checkCore(*p.event)
		kept := err != nil && p.eventType == sdkevidence.TypePresence
		if err == nil {
			err = s.store.Put(ctx, collector, version, *p.event, evidence.InCluster(cluster))
		}
		reason := reasonInvalid
		switch {
		case errors.Is(err, evidence.ErrTooLarge):
			reason = reasonTooLarge
		case !refused(err):
			return err
		}
		s.refuse(ctx, cluster, collector, p.eventType, p.subject, reason, err, kept)
		if kept {
			return nil
		}
		p.event = nil
	}
	return s.store.Delete(ctx, evidence.Key{Subject: p.subject, Type: p.eventType, Source: collector, Cluster: cluster})
}

// checkCore checks presence and exposure as the spoke's presence and exposure read them, against the core's schema,
// since the hub decodes both without it. It refuses what doesn't follow it, as the store refuses what a record can't
// hold. Its texts repeat nothing of the event.
func checkCore(e cloudevents.Event) error {
	var err error
	switch e.Type() {
	case sdkevidence.TypePresence:
		_, _, err = parse(e)
	case sdkevidence.TypeExposure:
		_, _, err = parseExposure(e)
	}
	if err != nil {
		return fmt.Errorf("%w: %w", evidence.ErrRefused, err)
	}
	return nil
}

// refuse counts and logs an event of the type about the subject that the store refuses, for the reason. Unless kept
// says that the record of the subject stays, which the collector then still holds, it has the collector hold no record
// of the subject, unless a later call wants something else of it: the event's record is to be deleted, and an event
// of the subject that fits brings it back.
func (s *StoreSink) refuse(ctx context.Context, cluster, collector, eventType, subject, reason string, err error,
	kept bool) {
	metrics.EvidenceStreamedRefusedTotal.WithLabelValues(cluster, collector, eventType, reason).Inc()
	log := logf.FromContext(ctx).WithValues("collector", collector, "type", eventType, "reason", reason)
	if errors.Is(err, evidence.ErrTooLarge) || errors.Is(err, evidence.ErrRefused) {
		// The store's own texts name sizes and attributes, and never what the event holds, as the API server's may.
		log = log.WithValues("cause", err.Error())
	}
	if kept {
		log.Info("The spoke refuses presence that the collector streamed for the hub off the core's schema; it is " +
			"dropped, and the record of its subject kept")
		return
	}
	log.Info("The evidence store refuses an event that the collector streamed for the hub; it is dropped, and the " +
		"record of its subject deleted")
	s.mu.Lock()
	defer s.mu.Unlock()
	if c := s.streamed[collector]; c != nil {
		if r := c.types[eventType]; r != nil {
			if _, replaced := r.wanted[subject]; !replaced {
				delete(r.held, subject)
			}
		}
	}
}

// restore gives back what a round didn't do: the records that it didn't write, unless a later call wants something
// else of them, and the prunes.
func (s *StoreSink) restore(collector string, records []pending, prunes []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.streamed[collector]
	if c == nil {
		return
	}
	for _, p := range records {
		r := c.types[p.eventType]
		if r == nil {
			continue
		}
		// An event of a record that the collector doesn't hold any more was followed by a call that deletes it.
		if _, replaced := r.wanted[p.subject]; replaced || (p.event != nil && !r.held[p.subject]) {
			continue
		}
		r.wanted[p.subject] = p.event
	}
	for _, eventType := range prunes {
		if r := c.types[eventType]; r != nil {
			r.prune = true
		}
	}
}

// holds returns whether the collector holds the record of a key of the type, which a prune keeps. It reads what the
// calls say when the prune asks, so that a prune keeps the record of a change that came after its snapshot.
func (s *StoreSink) holds(collector, eventType string) func(evidence.Key) bool {
	return func(k evidence.Key) bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		if c := s.streamed[collector]; c != nil {
			if r := c.types[eventType]; r != nil {
				return r.held[k.Subject]
			}
		}
		return false
	}
}

// tidy forgets the records of each type that the collector doesn't declare with the scope Hub any more, once nothing is
// left to write of them, and the collector, once it has no such type and no snapshot waits for its scopes.
func (s *StoreSink) tidy(collector string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.streamed[collector]
	if c == nil {
		return
	}
	for eventType, r := range c.types {
		if !r.hub && !r.prune && len(r.wanted) == 0 {
			delete(c.types, eventType)
		}
	}
	if len(c.types) == 0 && c.waiting == nil {
		delete(s.streamed, collector)
	}
}
