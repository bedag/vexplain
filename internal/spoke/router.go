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
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/go-logr/logr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/collectorclient"
	"github.com/bedag/vexplain/sdk/evidence"
)

// readTimeout bounds the Router's read of a Collector. A sink call that stopped streams wait for must never hang.
const readTimeout = 10 * time.Second

// Router implements collectorclient.Sink for the Spoke role, and hands each event type to its
// consumer. It hands each snapshot to the consumer of every type that the collector declares, so an
// empty snapshot reaches them too. Task 19 adds exposure.
//
// The snapshot of a collector reaches no consumer of a type that the collector doesn't declare: it says nothing about
// that type, and an empty one would make the consumer forget what other collectors delivered. Such a consumer forgets
// what the collector delivered of its type instead, which only a collector that stopped producing the type, as after
// an upgrade, had delivered. The Router reads what a collector declares from its Collector's recorded capabilities.
// When it can't, it hands each type that the snapshot holds to its consumer, and makes no consumer forget anything.
//
// After the snapshot, each change goes to the consumer of its type, and Forget to every consumer. What no consumer
// reads is dropped, and so is SourceChanged: the spoke runs no operation for it.
type Router struct {
	reader    client.Reader
	consumers map[string]collectorclient.Sink
	log       logr.Logger
}

// NewRouter returns the Router of the spoke role, which hands presence to presence. c reads the types each Collector
// declares.
func NewRouter(c client.Reader, presence *Presence) *Router {
	return &Router{
		reader:    c,
		consumers: map[string]collectorclient.Sink{evidence.TypePresence: presence},
		log:       ctrl.Log.WithName("spoke-router"),
	}
}

// Snapshot hands the events of each type that the collector declares to the consumer of the type, and makes the
// consumer of each type that it doesn't declare forget what it delivered.
func (r *Router) Snapshot(collector string, events []cloudevents.Event) {
	byType := map[string][]cloudevents.Event{}
	for _, e := range events {
		byType[e.Type()] = append(byType[e.Type()], e)
	}
	declared, err := r.declared(collector)
	if err != nil {
		r.log.Error(err, "Could not read which types the collector declares; its snapshot reaches the consumers of "+
			"the types that it holds, and none forgets anything", "collector", collector)
		for eventType, consumer := range r.consumers {
			if held := byType[eventType]; len(held) > 0 {
				consumer.Snapshot(collector, held)
			}
		}
		return
	}
	for eventType, consumer := range r.consumers {
		if declared[eventType] {
			consumer.Snapshot(collector, byType[eventType])
		} else {
			consumer.Forget(collector)
		}
	}
}

// declared returns the types that the collector's Collector declares that it produces, as the deployer recorded them.
func (r *Router) declared(collector string) (map[string]bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), readTimeout)
	defer cancel()
	var c configv1alpha1.Collector
	if err := r.reader.Get(ctx, client.ObjectKey{Name: collector}, &c); err != nil {
		return nil, err
	}
	declared := map[string]bool{}
	if c.Status.Capabilities != nil {
		for _, produced := range c.Status.Capabilities.Produces {
			declared[produced.Type] = true
		}
	}
	return declared, nil
}

// Upsert hands a change to the consumer of its type.
func (r *Router) Upsert(collector string, e cloudevents.Event) {
	if consumer, ok := r.consumers[e.Type()]; ok {
		consumer.Upsert(collector, e)
	}
}

// Remove hands a tombstone to the consumer of its type.
func (r *Router) Remove(collector, eventType, subject string) {
	if consumer, ok := r.consumers[eventType]; ok {
		consumer.Remove(collector, eventType, subject)
	}
}

// SourceChanged does nothing: a collector's operations run again for the hub, which reads SourceChanged from its own
// streams.
func (r *Router) SourceChanged(string, []string) {}

// Forget makes every consumer forget what the collector delivered.
func (r *Router) Forget(collector string) {
	for _, consumer := range r.consumers {
		consumer.Forget(collector)
	}
}
