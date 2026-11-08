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

package hub

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/cloudevents/sdk-go/binding/format/protobuf/v2/pb"
	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/collectorclient"
	"github.com/bedag/vexplain/internal/text"
	collectorv1alpha1 "github.com/bedag/vexplain/sdk/api/collector/v1alpha1"
	sdkevidence "github.com/bedag/vexplain/sdk/evidence"
)

// Findings is where the assessor gets the findings of a subject: from the findings producers of a playbook,
// each a findings collector. The findings aren't stored as evidence: the sheet holds what the rules made of
// them.
type Findings interface {
	// Find matches one manifest's evidence. The event is of a type the findings collector consumes.
	// An error means that there is no answer, and never that there are no findings.
	Find(ctx context.Context, collector string, input cloudevents.Event) (sdkevidence.Findings, error)
	// Changed delivers the subjects to match again; an empty list means every subject. A subject comes
	// as a request named by it, such as manifest/ and its digest, and every subject as one request with
	// an empty name.
	Changed() source.Source
}

// Invoker runs an operation of a collector: *collectorclient.Pool.
type Invoker interface {
	Invoke(ctx context.Context, collector string, req *collectorv1alpha1.InvokeRequest, opts ...collectorclient.InvokeOption) (
		[]cloudevents.Event, *collectorclient.Failure, error)
}

var _ Invoker = (*collectorclient.Pool)(nil)

const (
	// matchOperation is the operation of a findings collector that Find invokes.
	matchOperation = "match"
	// matchTimeout bounds one match: the vulnerabilities collector's own wait for a free place, and a match of a large SBOM that
	// takes a minute.
	matchTimeout = 10 * time.Minute
	// readTimeout bounds a read of a Collector from a call that has no context of its own: the sink's
	// SourceChanged, which streams wait for.
	readTimeout = 10 * time.Second
	// maxPendingSubjects is how many subjects a SourceChanged that came before the assessor started is kept
	// for: past it, the whole set is kept as "every subject".
	maxPendingSubjects = 1024
)

// CollectorFindings is the findings collectors of the playbooks, run from their packages (design 5.12). It matches through
// the operation match of a Collector in the hub role, and learns of its changes from the collector's stream, as the
// hub's collectorclient.Sink: it is the sink of the Hub role.
//
//   - Find invokes match with the evidence as its input, the Collector's settings and the context of the
//     cluster, and returns the findings event's data. A collector that can't be used now, a failure of the
//     collector, such as NotReady while it has no database, and an answer that isn't one findings event about the
//     subject, are errors: there is no answer. The call takes one event, and ends at a second.
//   - A SourceChanged of a collector that has the operation match, named by the stream's own collector argument and
//     never by an event's source, goes to Changed as every subject, or as the subjects that it names. It never
//     blocks: before the assessor started its source, it is kept and handed over then. What no one reads, a
//     snapshot, an upsert, a tombstone, is dropped: findings aren't evidence that the hub keeps.
type CollectorFindings struct {
	reader  client.Reader
	invoker Invoker
	context func(context.Context) (*collectorv1alpha1.Context, error)

	mu sync.Mutex
	// queue is the queue that Changed delivers into, once the assessor has started it. Until then, pendingAll and
	// pending hold what came.
	queue      workqueue.TypedRateLimitingInterface[reconcile.Request]
	pendingAll bool
	pending    map[string]struct{}
}

var (
	_ Findings             = (*CollectorFindings)(nil)
	_ collectorclient.Sink = (*CollectorFindings)(nil)
)

// NewCollectorFindings returns the findings collector, which reads Collectors through reader and invokes match through
// invoker, with the context that clusterContext builds, as the pool's streams build it.
func NewCollectorFindings(reader client.Reader, invoker Invoker,
	clusterContext func(context.Context) (*collectorv1alpha1.Context, error)) *CollectorFindings {
	return &CollectorFindings{reader: reader, invoker: invoker, context: clusterContext, pending: map[string]struct{}{}}
}

// errNotFindingsCollector is the cause of an error about a Collector that takes no hub role, or has no operation
// match: it is no findings collector, whatever its health.
var errNotFindingsCollector = errors.New("it is no findings collector")

// matchOf returns the operation match of the Collector's recorded capabilities, when it takes the hub role and has
// one, and says what is missing when it doesn't.
func matchOf(name string, c *configv1alpha1.Collector) (*configv1alpha1.CollectorOperation, error) {
	if c.Status.Capabilities == nil {
		return nil, fmt.Errorf("the Collector %s has recorded no capabilities yet", name)
	}
	if !slices.Contains(c.Status.Capabilities.Roles, configv1alpha1.CollectorRoleHub) {
		return nil, fmt.Errorf("the Collector %s takes no hub role: %w", name, errNotFindingsCollector)
	}
	for i := range c.Status.Capabilities.Operations {
		if op := &c.Status.Capabilities.Operations[i]; op.Name == matchOperation {
			return op, nil
		}
	}
	return nil, fmt.Errorf("the Collector %s has no operation %s: %w", name, matchOperation, errNotFindingsCollector)
}

// findingsCollector returns the Collector of the name when it can serve findings now: it can be used, takes the hub
// role, and its recorded capabilities have the operation match.
func (f *CollectorFindings) findingsCollector(ctx context.Context, name string) (*configv1alpha1.Collector,
	*configv1alpha1.CollectorOperation, error) {
	var c configv1alpha1.Collector
	if err := f.reader.Get(ctx, client.ObjectKey{Name: name}, &c); err != nil {
		return nil, nil, fmt.Errorf("read the Collector %s: %w", name, err)
	}
	if !collectorclient.Usable(&c) {
		return nil, nil, fmt.Errorf("the Collector %s can't be used", name)
	}
	op, err := matchOf(name, &c)
	if err != nil {
		return nil, nil, err
	}
	return &c, op, nil
}

// Find matches the evidence of a manifest through the operation match of the collector.
func (f *CollectorFindings) Find(ctx context.Context, collector string, input cloudevents.Event) (
	sdkevidence.Findings, error) {
	c, op, err := f.findingsCollector(ctx, collector)
	if err != nil {
		return sdkevidence.Findings{}, err
	}
	if !slices.Contains(op.Consumes, input.Type()) {
		return sdkevidence.Findings{}, fmt.Errorf("the Collector %s matches evidence of types %v, and not of type %s",
			collector, op.Consumes, input.Type())
	}
	if !slices.Contains(op.Produces, sdkevidence.TypeFindings) {
		return sdkevidence.Findings{}, fmt.Errorf("the operation %s of the Collector %s doesn't produce findings",
			matchOperation, collector)
	}
	encoded, err := sdkevidence.ToProto(input)
	if err != nil {
		return sdkevidence.Findings{}, fmt.Errorf("encode the evidence of %s: %w", input.Subject(), err)
	}
	clusterContext, err := f.context(ctx)
	if err != nil {
		return sdkevidence.Findings{}, fmt.Errorf("build the context of the collectors: %w", err)
	}
	req := &collectorv1alpha1.InvokeRequest{
		Operation: matchOperation,
		Subject:   input.Subject(),
		Inputs:    []*pb.CloudEvent{encoded},
		Context:   clusterContext,
		Role:      collectorv1alpha1.Role_ROLE_HUB,
	}
	if c.Spec.Settings != nil {
		req.Settings = slices.Clone(c.Spec.Settings.Raw)
	}
	ctx, cancel := context.WithTimeout(ctx, matchTimeout)
	defer cancel()
	// A match answers with one findings event: the call reads no further than a second.
	events, failure, err := f.invoker.Invoke(ctx, collector, req, collectorclient.MaxEvents(1))
	if err != nil {
		return sdkevidence.Findings{}, fmt.Errorf("match %s: %w", input.Subject(), err)
	}
	if failure != nil {
		// Only the reason is passed on: the message is the collector's text, which can quote an image's SBOM.
		return sdkevidence.Findings{}, fmt.Errorf("the Collector %s failed to match %s: %s", collector, input.Subject(),
			text.CutChars(text.Printable(failure.Reason), maxReasonLength))
	}
	return findingsOf(collector, input.Subject(), events)
}

// maxReasonLength is the most characters of a failure's reason that an error holds.
const maxReasonLength = 64

// errNoFindings is the error of an answer that isn't one findings event about the subject. Its text is fixed: the
// answer is the collector's.
var errNoFindings = errors.New("the answer is not one findings event about the subject")

// findingsSchema is the core's schema of findings, which the findings of an answer must follow to be read, as presence
// and exposure must on the spoke: a findings collector may declare a looser schema for the type, and findings without
// their matches would read as no findings.
var findingsSchema = compileFindingsSchema()

// compileFindingsSchema compiles the SDK's schema of findings. The SDK embeds it, so a failure is a defect of the
// build.
func compileFindingsSchema() *jsonschema.Schema {
	raw, _ := sdkevidence.Schema(sdkevidence.TypeFindings)
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		panic(fmt.Sprintf("the SDK's schema of findings isn't JSON: %v", err))
	}
	compiler := jsonschema.NewCompiler()
	url := "urn:vexplain:schema:" + sdkevidence.TypeFindings
	if err := compiler.AddResource(url, doc); err != nil {
		panic(fmt.Sprintf("the SDK's schema of findings can't be added: %v", err))
	}
	return compiler.MustCompile(url)
}

// findingsOf returns the findings that events hold: one event of the findings type, about the subject, whose data
// follows the core's schema of findings. Findings that don't follow it are no answer, and never no findings. The
// errors repeat nothing of the answer: a check's error would quote the data.
func findingsOf(collector, subject string, events []cloudevents.Event) (sdkevidence.Findings, error) {
	if len(events) != 1 || events[0].Type() != sdkevidence.TypeFindings || events[0].Subject() != subject {
		return sdkevidence.Findings{}, fmt.Errorf("the Collector %s matched %s: %w", collector, subject, errNoFindings)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(events[0].Data()))
	if err != nil {
		return sdkevidence.Findings{}, fmt.Errorf("the Collector %s matched %s: the findings are not JSON", collector,
			subject)
	}
	if err := findingsSchema.Validate(doc); err != nil {
		return sdkevidence.Findings{}, fmt.Errorf("the Collector %s matched %s: the findings don't follow the schema of "+
			"findings", collector, subject)
	}
	var found sdkevidence.Findings
	if err := json.Unmarshal(events[0].Data(), &found); err != nil {
		return sdkevidence.Findings{}, fmt.Errorf("the Collector %s matched %s: the findings are not JSON of their type",
			collector, subject)
	}
	return found, nil
}

// Changed is the source through which the assessor learns that subjects are to be matched again. When it starts, it
// delivers what a SourceChanged said before.
func (f *CollectorFindings) Changed() source.Source {
	return source.Func(func(_ context.Context, queue workqueue.TypedRateLimitingInterface[reconcile.Request]) error {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.queue = queue
		if f.pendingAll {
			queue.Add(reconcile.Request{})
		}
		for subject := range f.pending {
			queue.Add(reconcile.Request{NamespacedName: types.NamespacedName{Name: subject}})
		}
		f.pendingAll, f.pending = false, map[string]struct{}{}
		return nil
	})
}

// SourceChanged says that a findings collector's database changed: its subjects, or every subject when it names none.
// A collector that has no operation match is no findings collector, and its change means nothing here. When the
// Collector can't be read, the change counts: matching again is safe, and a change that is lost isn't.
func (f *CollectorFindings) SourceChanged(collector string, subjects []string) {
	ctx, cancel := context.WithTimeout(context.Background(), readTimeout)
	defer cancel()
	var c configv1alpha1.Collector
	if err := f.reader.Get(ctx, client.ObjectKey{Name: collector}, &c); err == nil {
		if _, err := matchOf(collector, &c); errors.Is(err, errNotFindingsCollector) {
			return
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.queue != nil {
		if len(subjects) == 0 {
			f.queue.Add(reconcile.Request{})
		}
		for _, subject := range subjects {
			f.queue.Add(reconcile.Request{NamespacedName: types.NamespacedName{Name: subject}})
		}
		return
	}
	if len(subjects) == 0 || len(f.pending)+len(subjects) > maxPendingSubjects {
		f.pendingAll, f.pending = true, map[string]struct{}{}
		return
	}
	for _, subject := range subjects {
		f.pending[subject] = struct{}{}
	}
}

// Snapshot, Upsert, Remove and Forget drop what they get: findings aren't evidence that the hub keeps.
func (f *CollectorFindings) Snapshot(string, []cloudevents.Event) {}
func (f *CollectorFindings) Upsert(string, cloudevents.Event)     {}
func (f *CollectorFindings) Remove(string, string, string)        {}
func (f *CollectorFindings) Forget(string)                        {}
