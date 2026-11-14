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

package collector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"

	"github.com/cloudevents/sdk-go/binding/format/protobuf/v2/pb"
	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	collectorv1alpha1 "github.com/bedag/vexplain/sdk/api/collector/v1alpha1"
	"github.com/bedag/vexplain/sdk/evidence"
	subjectpath "github.com/bedag/vexplain/sdk/subject"
)

// Context is what vexplain tells a collector about its cluster. Every Watch and Invoke carries it,
// with the settings, so that a collector keeps no configuration of its own. A change in either
// starts a new Watch.
//
// Cluster is the cluster's name, and OperatorNamespace the namespace of vexplain's operator.
// OwnPodLabel is the label that marks vexplain's own pods, such as its scan pods. It counts only in
// the operator's namespace. Scope is OperatorConfig's spec.scope, and OwnerAttribution its
// spec.ownerAttribution, which allowlists the labels and annotations of owner attribution, each as
// JSON.
type Context struct {
	Cluster, OperatorNamespace, OwnPodLabel string
	Scope, OwnerAttribution                 json.RawMessage
}

// WatchRequest is what a Watch is for: the role that the stream serves, the collector's settings and
// the context. The settings have passed their checks, and are an empty object when vexplain has none.
type WatchRequest struct {
	Role     Role
	Settings json.RawMessage
	Context  Context
}

// InvokeRequest is a run of an operation for one subject, such as image/sha256:<64 hex>.
//
// Parameters are the operation's parameters, as JSON. They have passed the operation's parameter
// schema, if it has one, and are an empty object when vexplain sends none. Settings are the
// collector's settings, which have passed their checks, as for a Watch. Inputs are evidence of the
// types that the operation consumes: each is valid evidence of such a type. Role is the role that
// runs the operation.
type InvokeRequest struct {
	Operation, Subject   string
	Parameters, Settings json.RawMessage
	Inputs               []cloudevents.Event
	Context              Context
	Role                 Role
}

// Failure says why an operation returned no evidence for its subject. Reason comes from a vocabulary
// that vexplain defines and keeps open, such as Unauthorized, NotFound or TooLarge. A failure always
// has one. Message says more. vexplain records a failure for its subject, and never counts it
// against the collector's health.
type Failure struct{ Reason, Message string }

// Sink is where a Watch sends its stream. A stream holds one snapshot: SnapshotStart, an event for
// each piece of evidence that the collector has, and SnapshotEnd. Then come the changes: an event for
// new or changed evidence, a tombstone for evidence that is gone, and SourceChanged.
//
// The sink holds the stream to this order, and checks each event: it is valid evidence
// (evidence.Validate) of a type that the collector produces. A call that breaks the order or fails
// the check ends the stream with the code Internal: the sink returns the reason, cancels the Watch's
// context, and refuses every later call. A sink is safe for concurrent use. Once the Watch has
// returned, it refuses every call.
type Sink interface {
	// SnapshotStart begins the snapshot. It comes first, and once.
	SnapshotStart() error
	// Event sends evidence: part of the snapshot, or a change after it.
	Event(cloudevents.Event) error
	// Tombstone says that the evidence of a type that the collector produces about a subject is gone.
	// It comes after the snapshot.
	Tombstone(eventType, subject string) error
	// SnapshotEnd ends the snapshot. Only a snapshot that ended is complete, so vexplain takes nothing
	// of it before.
	SnapshotEnd() error
	// SourceChanged says that a source of the collector's own changed, such as a vulnerability
	// database, so that vexplain invokes the collector's operations again: for the subjects, or for
	// every subject when there are none. It comes after the snapshot.
	SourceChanged(subjects ...string) error
}

// Watcher is a collector that streams its evidence.
//
// Watch sends a snapshot to the sink, then each change, until ctx ends, and returns then. Each Watch
// has its own stream and sink, and starts with a snapshot of its own, so that vexplain can reconnect
// at any time. An error that Watch returns ends the stream: a gRPC status keeps its code, and any
// other error reaches vexplain with the code Unknown.
type Watcher interface {
	Watch(ctx context.Context, req WatchRequest, sink Sink) error
}

// Invoker is a collector with operations.
//
// Invoke runs one operation for one subject. It returns evidence of the types that the operation
// produces, or a Failure with a reason, or both: vexplain then gets the events, and then the failure.
// When an event isn't valid evidence of such a type, or the failure has no reason, the call ends with
// the code Internal, and vexplain gets none of it. The error is for what keeps the collector from
// answering at all, and reaches vexplain as an error of Watch does. When Serve stops during the call,
// vexplain gets Unavailable, and none of the answer.
type Invoker interface {
	Invoke(ctx context.Context, req InvokeRequest) ([]cloudevents.Event, *Failure, error)
}

// FireRequest is a run of one of the collector's schedules: the schedule's name, the collector's
// settings, which have passed their checks as for a Watch, and the context.
type FireRequest struct {
	Schedule string
	Settings json.RawMessage
	Context  Context
}

// Firer is a collector with schedules.
//
// Fire runs the schedule that vexplain calls it for, one that the collector declared, and returns
// within 10 seconds. Work that takes longer starts in the background, and reports its outcome through
// the collector's sources and its evidence. An error that Fire returns reaches vexplain as an error
// of Watch does.
type Firer interface {
	Fire(ctx context.Context, req FireRequest) error
}

// errStopping is the cause of the end of a call's context when Serve stops.
var errStopping = errors.New("the collector is stopping")

// evidenceServer serves the Evidence service, and holds each call to what the collector declared.
type evidenceServer struct {
	collectorv1alpha1.UnimplementedEvidenceServer
	watcher    Watcher // nil for a collector that doesn't watch
	invoker    Invoker // nil for a collector without operations
	firer      Firer   // nil for a collector without schedules
	schedules  map[string]bool
	roles      []Role
	produces   map[string]bool // the types that the collector produces
	operations map[string]operation
	settings   *settingsCheck
	// stopping ends when Serve stops, and with it the context of every call.
	stopping context.Context
}

// operation is an operation that the collector declared, with the types that it produces and
// consumes as sets, and its parameter schema compiled.
type operation struct {
	role               Role
	produces, consumes map[string]bool
	parameters         *jsonschema.Schema // nil without a schema
}

func newOperation(op Operation) (operation, error) {
	name := fmt.Sprintf("the parameter schema of operation %q", op.Name)
	parameters, err := compileSchema(name, op.ParameterSchema)
	if err != nil {
		return operation{}, err
	}
	return operation{
		role:       op.Role,
		produces:   setOf(op.Produces),
		consumes:   setOf(op.Consumes),
		parameters: parameters,
	}, nil
}

func setOf(types []string) map[string]bool {
	set := make(map[string]bool, len(types))
	for _, t := range types {
		set[t] = true
	}
	return set
}

func (s *evidenceServer) Watch(req *collectorv1alpha1.WatchRequest,
	stream grpc.ServerStreamingServer[collectorv1alpha1.WatchResponse]) error {
	if s.watcher == nil {
		return status.Error(codes.Unimplemented, "the collector doesn't watch")
	}
	role := Role(req.GetRole())
	if !slices.Contains(s.roles, role) {
		return status.Errorf(codes.InvalidArgument, "the collector doesn't take the role %s", req.GetRole())
	}
	settings, err := s.settings.accept(req.GetSettings())
	if err != nil {
		return err
	}

	ctx, cancel := s.callContext(stream.Context())
	defer cancel(nil)
	out := &sink{stream: stream, produces: s.produces, cancel: cancel}
	err = s.watcher.Watch(ctx, WatchRequest{Role: role, Settings: settings, Context: contextOf(req.GetContext())}, out)
	if violation := out.end(); violation != nil {
		return status.Error(codes.Internal, "the collector broke the contract of its stream: "+violation.Error())
	}
	return callError(ctx, stream.Context(), err)
}

func (s *evidenceServer) Invoke(req *collectorv1alpha1.InvokeRequest,
	stream grpc.ServerStreamingServer[collectorv1alpha1.InvokeResponse]) error {
	op, ok := s.operations[req.GetOperation()]
	if !ok {
		return status.Errorf(codes.Unimplemented, "the collector has no operation %q", req.GetOperation())
	}
	// The operation's role is one that the collector takes, as Serve checked when it started.
	if role := Role(req.GetRole()); role != op.role {
		return status.Errorf(codes.InvalidArgument, "operation %q doesn't run in the role %s", req.GetOperation(),
			req.GetRole())
	}
	settings, err := s.settings.accept(req.GetSettings())
	if err != nil {
		return err
	}
	parameters, problems := checkJSON("parameters", op.parameters, req.GetParameters())
	if len(problems) > 0 {
		return invalidArgument("parameters", problems)
	}
	if _, err := subjectpath.Parse(req.GetSubject()); err != nil {
		return status.Error(codes.InvalidArgument, "the subject: "+err.Error())
	}
	inputs, err := op.inputs(req.GetInputs())
	if err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}

	ctx, cancel := s.callContext(stream.Context())
	defer cancel(nil)
	events, failure, err := s.invoker.Invoke(ctx, InvokeRequest{
		Operation:  req.GetOperation(),
		Subject:    req.GetSubject(),
		Parameters: parameters,
		Settings:   settings,
		Inputs:     inputs,
		Context:    contextOf(req.GetContext()),
		Role:       op.role,
	})
	if err := callError(ctx, stream.Context(), err); err != nil {
		return err
	}
	items, err := op.answer(events, failure)
	if err != nil {
		return status.Errorf(codes.Internal, "the collector's answer breaks the contract of operation %q: %v",
			req.GetOperation(), err)
	}
	for _, item := range items {
		if err := stream.Send(item); err != nil {
			return err
		}
	}
	return nil
}

func (s *evidenceServer) Fire(call context.Context, req *collectorv1alpha1.FireRequest) (
	*collectorv1alpha1.FireResponse, error) {
	if s.firer == nil {
		return nil, status.Error(codes.Unimplemented, "the collector has no schedules")
	}
	if !s.schedules[req.GetSchedule()] {
		return nil, status.Errorf(codes.InvalidArgument, "the collector has no schedule %q", req.GetSchedule())
	}
	settings, err := s.settings.accept(req.GetSettings())
	if err != nil {
		return nil, err
	}
	ctx, cancel := s.callContext(call)
	defer cancel(nil)
	err = s.firer.Fire(ctx, FireRequest{
		Schedule: req.GetSchedule(),
		Settings: settings,
		Context:  contextOf(req.GetContext()),
	})
	if err := callError(ctx, call, err); err != nil {
		return nil, err
	}
	return &collectorv1alpha1.FireResponse{}, nil
}

// callContext returns the context of one Watch or Invoke, which ends with the call, and when Serve
// stops. Its cancel function takes the cause.
func (s *evidenceServer) callContext(call context.Context) (context.Context, context.CancelCauseFunc) {
	ctx, cancel := context.WithCancelCause(call)
	stop := context.AfterFunc(s.stopping, func() { cancel(errStopping) })
	return ctx, func(cause error) {
		stop()
		cancel(cause)
	}
}

// callError turns what a collector's Watch or Invoke returned into the status of the call, nil to
// end it well. A call whose context the stop of Serve ended ends with Unavailable, whatever the
// collector returned: an answer or a stream that the stop cut short must not look complete. When
// the client went away, the collector's error most likely only says so, and the status says that
// instead.
func callError(ctx, call context.Context, err error) error {
	switch {
	case errors.Is(context.Cause(ctx), errStopping):
		return status.Error(codes.Unavailable, errStopping.Error())
	case err == nil:
		return nil
	case call.Err() != nil:
		return status.FromContextError(call.Err()).Err()
	default:
		return err
	}
}

func contextOf(c *collectorv1alpha1.Context) Context {
	return Context{
		Cluster:           c.GetCluster(),
		OperatorNamespace: c.GetOperatorNamespace(),
		OwnPodLabel:       c.GetOwnPodLabel(),
		Scope:             c.GetScope(),
		OwnerAttribution:  c.GetOwnerAttribution(),
	}
}

// inputs converts the inputs of an Invoke, and checks each: it is valid evidence, of a type that the
// operation consumes. An error names an input by its place, and repeats nothing of it.
func (op operation) inputs(inputs []*pb.CloudEvent) ([]cloudevents.Event, error) {
	events := make([]cloudevents.Event, 0, len(inputs))
	for i, input := range inputs {
		e, err := evidence.FromProto(input)
		if err == nil {
			err = evidence.Validate(e)
		}
		if err != nil {
			return nil, fmt.Errorf("input %d is not valid evidence: %w", i, err)
		}
		if !op.consumes[e.Type()] {
			return nil, fmt.Errorf("input %d is of a type that the operation doesn't consume", i)
		}
		events = append(events, e)
	}
	return events, nil
}

// answer checks what the collector's Invoke returned, and turns it into the items of the stream: the
// events, then the failure.
func (op operation) answer(events []cloudevents.Event, failure *Failure) ([]*collectorv1alpha1.InvokeResponse, error) {
	items := make([]*collectorv1alpha1.InvokeResponse, 0, len(events)+1)
	for i, e := range events {
		p, err := checkEvent(e, op.produces)
		if err != nil {
			return nil, fmt.Errorf("event %d %w", i, err)
		}
		items = append(items, &collectorv1alpha1.InvokeResponse{Item: &collectorv1alpha1.InvokeResponse_Event{Event: p}})
	}
	if failure != nil {
		if failure.Reason == "" {
			return nil, errors.New("its failure has no reason")
		}
		items = append(items, &collectorv1alpha1.InvokeResponse{Item: &collectorv1alpha1.InvokeResponse_Failure{
			Failure: &collectorv1alpha1.Failure{Reason: failure.Reason, Message: failure.Message},
		}})
	}
	return items, nil
}

// checkEvent checks that an event that the collector sends is valid evidence of one of the types, and
// converts it for the wire. Its errors say what the event is, after the word "event".
func checkEvent(e cloudevents.Event, types map[string]bool) (*pb.CloudEvent, error) {
	if err := evidence.Validate(e); err != nil {
		return nil, fmt.Errorf("is not valid evidence: %w", err)
	}
	if !types[e.Type()] {
		return nil, errors.New("is of a type that the capabilities don't list for it")
	}
	p, err := evidence.ToProto(e)
	if err != nil {
		// The error of the conversion repeats what the event holds, which the collector chose.
		return nil, errors.New("can't be converted to the API's CloudEvent")
	}
	return p, nil
}

// stage is how far a stream has got.
type stage int

const (
	beforeSnapshot stage = iota
	inSnapshot
	afterSnapshot
)

// errStreamEnded is what a sink answers once its Watch has returned.
var errStreamEnded = errors.New("the stream has ended")

// sink is the Sink of one Watch. It sends what keeps to the stream's contract, and remembers the
// first call that broke it.
type sink struct {
	stream   grpc.ServerStreamingServer[collectorv1alpha1.WatchResponse]
	produces map[string]bool
	// cancel ends the Watch's context, with the call that broke the contract as the cause.
	cancel context.CancelCauseFunc

	mu    sync.Mutex
	stage stage
	// violation is the first call that broke the contract.
	violation error
	// done is why the sink takes no more calls: a violation, a send that failed, or the end of the
	// Watch.
	done error
}

func (s *sink) SnapshotStart() error {
	return s.send(func(at stage) (*collectorv1alpha1.WatchResponse, stage, error) {
		if at != beforeSnapshot {
			return nil, at, errors.New("a second SnapshotStart, and a stream holds one snapshot")
		}
		return &collectorv1alpha1.WatchResponse{Item: &collectorv1alpha1.WatchResponse_SnapshotStart{
			SnapshotStart: &collectorv1alpha1.SnapshotStart{},
		}}, inSnapshot, nil
	})
}

func (s *sink) Event(e cloudevents.Event) error {
	// The check of the event itself doesn't depend on the stream, so it runs before the sink locks.
	p, invalid := checkEvent(e, s.produces)
	return s.send(func(at stage) (*collectorv1alpha1.WatchResponse, stage, error) {
		if at == beforeSnapshot {
			return nil, at, errors.New("an event came before SnapshotStart")
		}
		if invalid != nil {
			return nil, at, fmt.Errorf("an event %w", invalid)
		}
		return &collectorv1alpha1.WatchResponse{Item: &collectorv1alpha1.WatchResponse_Event{Event: p}}, at, nil
	})
}

func (s *sink) Tombstone(eventType, subject string) error {
	return s.send(func(at stage) (*collectorv1alpha1.WatchResponse, stage, error) {
		if at != afterSnapshot {
			return nil, at, errors.New("a tombstone came before the end of the snapshot")
		}
		if !s.produces[eventType] {
			return nil, at, errors.New("a tombstone is of a type that the collector doesn't produce")
		}
		if _, err := subjectpath.Parse(subject); err != nil {
			return nil, at, fmt.Errorf("the subject of a tombstone: %w", err)
		}
		return &collectorv1alpha1.WatchResponse{Item: &collectorv1alpha1.WatchResponse_Tombstone{
			Tombstone: &collectorv1alpha1.Tombstone{Type: eventType, Subject: subject},
		}}, at, nil
	})
}

func (s *sink) SnapshotEnd() error {
	return s.send(func(at stage) (*collectorv1alpha1.WatchResponse, stage, error) {
		switch at {
		case beforeSnapshot:
			return nil, at, errors.New("SnapshotEnd came before SnapshotStart")
		case afterSnapshot:
			return nil, at, errors.New("a second SnapshotEnd, and a stream holds one snapshot")
		}
		return &collectorv1alpha1.WatchResponse{Item: &collectorv1alpha1.WatchResponse_SnapshotEnd{
			SnapshotEnd: &collectorv1alpha1.SnapshotEnd{},
		}}, afterSnapshot, nil
	})
}

func (s *sink) SourceChanged(subjects ...string) error {
	return s.send(func(at stage) (*collectorv1alpha1.WatchResponse, stage, error) {
		if at != afterSnapshot {
			return nil, at, errors.New("SourceChanged came before the end of the snapshot")
		}
		for _, subject := range subjects {
			if _, err := subjectpath.Parse(subject); err != nil {
				return nil, at, fmt.Errorf("a subject of SourceChanged: %w", err)
			}
		}
		return &collectorv1alpha1.WatchResponse{Item: &collectorv1alpha1.WatchResponse_SourceChanged{
			SourceChanged: &collectorv1alpha1.SourceChanged{Subjects: subjects},
		}}, at, nil
	})
}

// send checks a call against the stream's contract and sends its item, under the sink's lock, so
// that the stream sees one call at a time. check gets the stage that the stream is at, and returns
// the call's item and the stage after it, or how the call breaks the contract.
func (s *sink) send(check func(at stage) (*collectorv1alpha1.WatchResponse, stage, error)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done != nil {
		return s.done
	}
	item, next, err := check(s.stage)
	if err != nil {
		s.violation, s.done = err, err
		s.cancel(err)
		return err
	}
	if err := s.stream.Send(item); err != nil {
		s.done = err
		return err
	}
	s.stage = next
	return nil
}

// end makes the sink refuse every later call, and returns the call that broke the contract, if one
// did.
func (s *sink) end() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done == nil {
		s.done = errStreamEnded
	}
	return s.violation
}
