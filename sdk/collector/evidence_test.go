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

package collector_test

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloudevents/sdk-go/binding/format/protobuf/v2/pb"
	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	collectorv1alpha1 "github.com/bedag/vexplain/sdk/api/collector/v1alpha1"
	"github.com/bedag/vexplain/sdk/collector"
	"github.com/bedag/vexplain/sdk/evidence"
	"github.com/bedag/vexplain/sdk/subject"
)

// notASubject has no prefix, so subject.Parse refuses it.
const notASubject = "web"

// call is one call that a collector makes on its sink.
type call func(collector.Sink) error

func send(e cloudevents.Event) call { return func(s collector.Sink) error { return s.Event(e) } }

func tombstone(eventType, what string) call {
	return func(s collector.Sink) error { return s.Tombstone(eventType, what) }
}

func sourceChanged(subjects ...string) call {
	return func(s collector.Sink) error { return s.SourceChanged(subjects...) }
}

var (
	snapshotStart call = collector.Sink.SnapshotStart
	snapshotEnd   call = collector.Sink.SnapshotEnd
)

// watching is a fake collector whose Watch makes the calls, then waits for its context to end.
func watching(calls ...call) *fakeCollector {
	return &fakeCollector{caps: capabilities(), watch: func(ctx context.Context, _ collector.WatchRequest,
		sink collector.Sink) error {
		for _, step := range calls {
			if err := step(sink); err != nil {
				return err
			}
		}
		<-ctx.Done()
		return ctx.Err()
	}}
}

func TestWatchDeliversAWellOrderedStreamWhole(t *testing.T) {
	first, second, change := newEvent(t, typeHello), newEvent(t, typeHello), newEvent(t, typeHello)
	c := watching(snapshotStart, send(first), send(second), snapshotEnd,
		send(change), tombstone(typeHello, workload), sourceChanged(subject.Image(digest)), sourceChanged())
	ended := make(chan error, 1)
	inner := c.watch
	c.watch = func(ctx context.Context, req collector.WatchRequest, sink collector.Sink) error {
		err := inner(ctx, req, sink)
		ended <- err
		return err
	}
	s := serve(t, c)

	ctx, cancel := context.WithCancel(callContext(t))
	stream, err := s.evidenceClient().Watch(ctx, watchRequest())
	require.NoError(t, err)
	items := make([]*collectorv1alpha1.WatchResponse, 8)
	for i := range items {
		items[i], err = stream.Recv()
		require.NoError(t, err)
	}
	require.NotNil(t, items[0].GetSnapshotStart())
	requireEvent(t, first, items[1].GetEvent())
	requireEvent(t, second, items[2].GetEvent())
	require.NotNil(t, items[3].GetSnapshotEnd())
	requireEvent(t, change, items[4].GetEvent())
	require.Equal(t, typeHello, items[5].GetTombstone().GetType())
	require.Equal(t, workload, items[5].GetTombstone().GetSubject())
	require.Equal(t, []string{subject.Image(digest)}, items[6].GetSourceChanged().GetSubjects())
	require.NotNil(t, items[7].GetSourceChanged())
	require.Empty(t, items[7].GetSourceChanged().GetSubjects(), "no subjects: every subject")

	cancel()
	select {
	case err := <-ended:
		require.ErrorIs(t, err, context.Canceled, "the collector's Watch ends with the stream")
	case <-time.After(wait):
		t.Fatal("the collector's Watch didn't end with the stream")
	}
}

func TestWatchEndsWithInternalWhenTheCollectorBreaksTheStreamsContract(t *testing.T) {
	event := newEvent(t, typeHello)
	tests := map[string][]call{
		"an event before SnapshotStart":                         {send(event)},
		"SnapshotEnd before SnapshotStart":                      {snapshotEnd},
		"a second SnapshotStart":                                {snapshotStart, snapshotEnd, snapshotStart},
		"a second SnapshotEnd":                                  {snapshotStart, snapshotEnd, snapshotEnd},
		"an event of a type that the collector doesn't produce": {snapshotStart, send(newEvent(t, typeUndeclared))},
		"an event that isn't valid evidence, about a manifest without a platform": {
			snapshotStart, send(eventAbout(t, typeHello, subject.Manifest(digest))),
		},
		"a tombstone before the first SnapshotEnd": {snapshotStart, send(event), tombstone(typeHello, workload)},
		"a tombstone of a type that the collector doesn't produce": {
			snapshotStart, snapshotEnd, tombstone(typeUndeclared, workload),
		},
		"a tombstone about what isn't a subject":     {snapshotStart, snapshotEnd, tombstone(typeHello, notASubject)},
		"SourceChanged before the first SnapshotEnd": {snapshotStart, sourceChanged()},
		"SourceChanged about what isn't a subject":   {snapshotStart, snapshotEnd, sourceChanged(notASubject)},
	}
	for name, calls := range tests {
		t.Run(name, func(t *testing.T) {
			refused := make(chan error, 1)
			c := &fakeCollector{caps: capabilities(), watch: func(ctx context.Context, _ collector.WatchRequest,
				sink collector.Sink) error {
				last := len(calls) - 1
				for _, step := range calls[:last] {
					if err := step(sink); err != nil {
						return err
					}
				}
				refused <- calls[last](sink)
				// A collector that carries on gets nowhere: these calls would make a stream of their own,
				// and the client sees none of them. Its context ends, and returning nil changes nothing.
				for _, step := range []call{snapshotStart, send(event), snapshotEnd} {
					_ = step(sink)
				}
				<-ctx.Done()
				return nil
			}}
			s := serve(t, c)

			stream, err := s.evidenceClient().Watch(callContext(t), watchRequest())
			require.NoError(t, err)
			items, err := receiveAll(stream)
			require.Equal(t, codes.Internal, status.Code(err), "%v", err)
			require.Len(t, items, len(calls)-1, "what came before the broken call arrives, and nothing after it")
			require.Error(t, <-refused, "the sink refuses the call that breaks the contract")
		})
	}
}

func TestWatchRefuses(t *testing.T) {
	tests := map[string]struct {
		caps collector.Capabilities
		req  func(*collectorv1alpha1.WatchRequest)
		code codes.Code
	}{
		"settings that break their schema": {
			req:  func(r *collectorv1alpha1.WatchRequest) { r.Settings = []byte(brokenSettings) },
			code: codes.InvalidArgument,
		},
		"settings that the collector refuses": {
			req:  func(r *collectorv1alpha1.WatchRequest) { r.Settings = []byte(refusedSettings) },
			code: codes.InvalidArgument,
		},
		"a role that the collector doesn't take": {
			req:  func(r *collectorv1alpha1.WatchRequest) { r.Role = collectorv1alpha1.Role_ROLE_HUB },
			code: codes.InvalidArgument,
		},
		"no role": {
			req:  func(r *collectorv1alpha1.WatchRequest) { r.Role = collectorv1alpha1.Role_ROLE_UNSPECIFIED },
			code: codes.InvalidArgument,
		},
		"a Watch of a collector that doesn't watch": {
			caps: func() collector.Capabilities { caps := capabilities(); caps.Watches = false; return caps }(),
			req:  func(*collectorv1alpha1.WatchRequest) {},
			code: codes.Unimplemented,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			caps := tc.caps
			if caps.Roles == nil {
				caps = capabilities()
			}
			var watched atomic.Int32
			s := serve(t, &fakeCollector{caps: caps, watch: func(context.Context, collector.WatchRequest,
				collector.Sink) error {
				watched.Add(1)
				return nil
			}})
			req := watchRequest()
			tc.req(req)

			stream, err := s.evidenceClient().Watch(callContext(t), req)
			require.NoError(t, err)
			_, err = receiveAll(stream)
			require.Equal(t, tc.code, status.Code(err), "%v", err)
			require.Zero(t, watched.Load(), "the collector's Watch isn't called")
		})
	}
}

func TestWatchHandsTheRequestToTheCollector(t *testing.T) {
	got := make(chan collector.WatchRequest, 1)
	s := serve(t, &fakeCollector{caps: capabilities(), watch: func(_ context.Context, req collector.WatchRequest,
		_ collector.Sink) error {
		got <- req
		return nil
	}})
	watch := func(t *testing.T, req *collectorv1alpha1.WatchRequest) collector.WatchRequest {
		t.Helper()
		stream, err := s.evidenceClient().Watch(callContext(t), req)
		require.NoError(t, err)
		_, err = receiveAll(stream)
		require.NoError(t, err)
		return <-got
	}

	t.Run("its role, settings and context", func(t *testing.T) {
		req := watch(t, watchRequest())
		require.Equal(t, collector.RoleSpoke, req.Role)
		require.JSONEq(t, validSettings, string(req.Settings))
		require.Equal(t, testContext(), req.Context)
	})
	t.Run("no settings, as an empty object", func(t *testing.T) {
		r := watchRequest()
		r.Settings = nil
		req := watch(t, r)
		require.JSONEq(t, `{}`, string(req.Settings))
	})
}

// testContext is protoContext as the collector receives it.
func testContext() collector.Context {
	return collector.Context{
		Cluster:           clusterA,
		OperatorNamespace: "vexplain-system",
		OwnPodLabel:       "vexplain.bedag.ch/task",
		Scope:             json.RawMessage(`{"namespaces": {"exclude": ["kube-system"]}}`),
		OwnerAttribution:  json.RawMessage(`{"namespaceLabels": ["team"]}`),
	}
}

func TestSinkTakesCallsFromSeveralGoroutines(t *testing.T) {
	const goroutines, each = 8, 16
	events := make([][]cloudevents.Event, goroutines)
	sent := map[string]bool{}
	for g := range events {
		for range each {
			e := newEvent(t, typeHello)
			events[g] = append(events[g], e)
			sent[e.ID()] = true
		}
	}
	s := serve(t, &fakeCollector{caps: capabilities(), watch: func(_ context.Context, _ collector.WatchRequest,
		sink collector.Sink) error {
		if err := sink.SnapshotStart(); err != nil {
			return err
		}
		errs := make(chan error, goroutines*each)
		var wg sync.WaitGroup
		for _, batch := range events {
			wg.Go(func() {
				for _, e := range batch {
					errs <- sink.Event(e)
				}
			})
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				return err
			}
		}
		return sink.SnapshotEnd()
	}})

	stream, err := s.evidenceClient().Watch(callContext(t), watchRequest())
	require.NoError(t, err)
	items, err := receiveAll(stream)
	require.NoError(t, err)
	require.Len(t, items, goroutines*each+2)
	require.NotNil(t, items[0].GetSnapshotStart())
	require.NotNil(t, items[len(items)-1].GetSnapshotEnd())
	received := map[string]bool{}
	for _, item := range items[1 : len(items)-1] {
		received[item.GetEvent().GetId()] = true
	}
	require.Equal(t, sent, received)
}

func TestSinkRefusesCallsOnceTheStreamHasEnded(t *testing.T) {
	kept := make(chan collector.Sink, 1)
	s := serve(t, &fakeCollector{caps: capabilities(), watch: func(_ context.Context, _ collector.WatchRequest,
		sink collector.Sink) error {
		kept <- sink
		return nil
	}})

	stream, err := s.evidenceClient().Watch(callContext(t), watchRequest())
	require.NoError(t, err)
	items, err := receiveAll(stream)
	require.NoError(t, err, "a Watch that returns nil ends the stream well")
	require.Empty(t, items)

	// The sink refuses the calls itself, and doesn't touch a stream whose handler has returned.
	sink := <-kept
	const ended = "the stream has ended"
	require.EqualError(t, sink.SnapshotStart(), ended)
	require.EqualError(t, sink.Event(newEvent(t, typeHello)), ended)
	require.EqualError(t, sink.SnapshotEnd(), ended)
}

func TestInvokeReturnsTheOperationsEvents(t *testing.T) {
	first, second := newEvent(t, typeHello), newEvent(t, typeHello)
	failure := &collector.Failure{Reason: "NotFound", Message: "the image is gone"}
	tests := map[string]struct {
		events  []cloudevents.Event
		failure *collector.Failure
	}{
		"events":                   {events: []cloudevents.Event{first, second}},
		"a failure":                {failure: failure},
		"an event, then a failure": {events: []cloudevents.Event{first}, failure: failure},
		"nothing":                  {},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			s := serve(t, &fakeCollector{caps: capabilities(), invoke: func(context.Context, collector.InvokeRequest) (
				[]cloudevents.Event, *collector.Failure, error) {
				return tc.events, tc.failure, nil
			}})

			stream, err := s.evidenceClient().Invoke(callContext(t), invokeRequest(t, newEvent(t, typeInput)))
			require.NoError(t, err)
			items, err := receiveAll(stream)
			require.NoError(t, err)

			length := len(tc.events)
			if tc.failure != nil {
				length++
			}
			require.Len(t, items, length)
			for i, e := range tc.events {
				requireEvent(t, e, items[i].GetEvent())
			}
			if tc.failure != nil {
				got := items[len(items)-1].GetFailure()
				require.NotNil(t, got, "the failure is the last item")
				require.Equal(t, tc.failure.Reason, got.GetReason())
				require.Equal(t, tc.failure.Message, got.GetMessage())
			}
		})
	}
}

func TestInvokeHandsTheRequestToTheCollector(t *testing.T) {
	input := newEvent(t, typeInput)
	// invoke sends r to a fake collector with caps, and returns the request that the collector gets.
	invoke := func(t *testing.T, caps collector.Capabilities, r *collectorv1alpha1.InvokeRequest) collector.InvokeRequest {
		t.Helper()
		got := make(chan collector.InvokeRequest, 1)
		s := serve(t, &fakeCollector{caps: caps, invoke: func(_ context.Context, req collector.InvokeRequest) (
			[]cloudevents.Event, *collector.Failure, error) {
			got <- req
			return nil, nil, nil
		}})
		stream, err := s.evidenceClient().Invoke(callContext(t), r)
		require.NoError(t, err)
		_, err = receiveAll(stream)
		require.NoError(t, err)
		return <-got
	}

	t.Run("its operation, subject, parameters, settings, inputs, context and role", func(t *testing.T) {
		req := invoke(t, capabilities(), invokeRequest(t, input))
		require.Equal(t, operationGreet, req.Operation)
		require.Equal(t, workload, req.Subject)
		require.JSONEq(t, parameters, string(req.Parameters))
		require.JSONEq(t, validSettings, string(req.Settings))
		require.Equal(t, []cloudevents.Event{input}, req.Inputs)
		require.Equal(t, testContext(), req.Context)
		require.Equal(t, collector.RoleSpoke, req.Role)
	})
	t.Run("no parameters, checked and handed over as an empty object", func(t *testing.T) {
		r := invokeRequest(t, input)
		r.Parameters = nil
		require.JSONEq(t, `{}`, string(invoke(t, capabilities(), r).Parameters))
	})
	t.Run("any JSON as the parameters of an operation without a schema", func(t *testing.T) {
		caps := capabilities()
		caps.Operations[0].ParameterSchema = nil
		r := invokeRequest(t, input)
		// The fake operation's schema would refuse this, as it isn't an object.
		r.Parameters = []byte(`[1, 2]`)
		require.JSONEq(t, `[1, 2]`, string(invoke(t, caps, r).Parameters))
	})
}

func TestInvokeRefuses(t *testing.T) {
	notACloudEvent := func(t *testing.T) *pb.CloudEvent {
		t.Helper()
		p, err := evidence.ToProto(newEvent(t, typeInput))
		require.NoError(t, err)
		// A URI with a control character in it doesn't parse.
		p.Attributes["ref"] = &pb.CloudEventAttributeValue{Attr: &pb.CloudEventAttributeValue_CeUri{CeUri: "\x7f"}}
		return p
	}
	bothRoles := capabilities()
	bothRoles.Roles = []collector.Role{collector.RoleSpoke, collector.RoleHub}
	needsName := capabilities()
	needsName.Operations[0].ParameterSchema = []byte(`{"type": "object", "required": ["name"]}`)
	withoutSchema := capabilities()
	withoutSchema.Operations[0].ParameterSchema = nil

	tests := map[string]struct {
		caps collector.Capabilities
		req  func(t *testing.T, r *collectorv1alpha1.InvokeRequest)
		code codes.Code
		// message is part of the status's message, if set.
		message string
	}{
		"an operation that the collector doesn't declare": {
			req:  func(_ *testing.T, r *collectorv1alpha1.InvokeRequest) { r.Operation = "wave" },
			code: codes.Unimplemented,
		},
		"an input of a type that the operation doesn't consume": {
			req: func(t *testing.T, r *collectorv1alpha1.InvokeRequest) {
				r.Inputs = invokeRequest(t, newEvent(t, typeInput), newEvent(t, typeHello)).GetInputs()
			},
			code: codes.InvalidArgument,
		},
		"an input that isn't valid evidence, about a manifest without a platform": {
			req: func(t *testing.T, r *collectorv1alpha1.InvokeRequest) {
				r.Inputs = invokeRequest(t, eventAbout(t, typeInput, subject.Manifest(digest))).GetInputs()
			},
			code: codes.InvalidArgument,
		},
		"an input that isn't a CloudEvent": {
			req:  func(t *testing.T, r *collectorv1alpha1.InvokeRequest) { r.Inputs = []*pb.CloudEvent{notACloudEvent(t)} },
			code: codes.InvalidArgument,
		},
		"settings that break their schema": {
			req:  func(_ *testing.T, r *collectorv1alpha1.InvokeRequest) { r.Settings = []byte(brokenSettings) },
			code: codes.InvalidArgument,
		},
		"settings that the collector refuses": {
			req:  func(_ *testing.T, r *collectorv1alpha1.InvokeRequest) { r.Settings = []byte(refusedSettings) },
			code: codes.InvalidArgument,
		},
		"a role that the collector doesn't take": {
			req:  func(_ *testing.T, r *collectorv1alpha1.InvokeRequest) { r.Role = collectorv1alpha1.Role_ROLE_HUB },
			code: codes.InvalidArgument,
		},
		"a role other than the operation's": {
			caps: bothRoles,
			req:  func(_ *testing.T, r *collectorv1alpha1.InvokeRequest) { r.Role = collectorv1alpha1.Role_ROLE_HUB },
			code: codes.InvalidArgument,
		},
		"what isn't a subject": {
			req:  func(_ *testing.T, r *collectorv1alpha1.InvokeRequest) { r.Subject = notASubject },
			code: codes.InvalidArgument,
		},
		"parameters that break their schema": {
			req:     func(_ *testing.T, r *collectorv1alpha1.InvokeRequest) { r.Parameters = []byte(`{"name": 1}`) },
			code:    codes.InvalidArgument,
			message: "the parameters are not valid: at '/name': got number, want string",
		},
		"no parameters, for an operation whose schema needs some": {
			caps:    needsName,
			req:     func(_ *testing.T, r *collectorv1alpha1.InvokeRequest) { r.Parameters = nil },
			code:    codes.InvalidArgument,
			message: "the parameters are not valid: at '': missing property 'name'",
		},
		"parameters that aren't JSON, even for an operation without a schema": {
			caps:    withoutSchema,
			req:     func(_ *testing.T, r *collectorv1alpha1.InvokeRequest) { r.Parameters = []byte(`{"name":`) },
			code:    codes.InvalidArgument,
			message: "the parameters are not valid: the parameters are not JSON",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			caps := tc.caps
			if caps.Roles == nil {
				caps = capabilities()
			}
			var invoked atomic.Int32
			s := serve(t, &fakeCollector{caps: caps, invoke: func(context.Context, collector.InvokeRequest) (
				[]cloudevents.Event, *collector.Failure, error) {
				invoked.Add(1)
				return nil, nil, nil
			}})
			req := invokeRequest(t, newEvent(t, typeInput))
			tc.req(t, req)

			stream, err := s.evidenceClient().Invoke(callContext(t), req)
			require.NoError(t, err)
			_, err = receiveAll(stream)
			require.Equal(t, tc.code, status.Code(err), "%v", err)
			require.Contains(t, status.Convert(err).Message(), tc.message)
			require.Zero(t, invoked.Load(), "the collector's Invoke isn't called")
		})
	}
}

func TestInvokeEndsWithInternalWhenTheCollectorBreaksTheOperationsContract(t *testing.T) {
	tests := map[string]struct {
		events  []cloudevents.Event
		failure *collector.Failure
	}{
		"an event of a type that the operation doesn't produce": {
			events: []cloudevents.Event{newEvent(t, typeHello), newEvent(t, typeInput)},
		},
		"an event that isn't valid evidence, about a manifest without a platform": {
			events: []cloudevents.Event{newEvent(t, typeHello), eventAbout(t, typeHello, subject.Manifest(digest))},
		},
		"a failure without a reason": {
			events:  []cloudevents.Event{newEvent(t, typeHello)},
			failure: &collector.Failure{Message: "it failed"},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			s := serve(t, &fakeCollector{caps: capabilities(), invoke: func(context.Context, collector.InvokeRequest) (
				[]cloudevents.Event, *collector.Failure, error) {
				return tc.events, tc.failure, nil
			}})

			stream, err := s.evidenceClient().Invoke(callContext(t), invokeRequest(t, newEvent(t, typeInput)))
			require.NoError(t, err)
			items, err := receiveAll(stream)
			require.Equal(t, codes.Internal, status.Code(err), "%v", err)
			require.Empty(t, items, "nothing of an answer that breaks the contract arrives")
		})
	}
}

func TestTheCollectorsOwnErrorReachesTheClient(t *testing.T) {
	tests := map[string]struct {
		err  error
		code codes.Code
	}{
		"a status keeps its code": {
			err:  status.Error(codes.FailedPrecondition, "the informer isn't synced"),
			code: codes.FailedPrecondition,
		},
		"another error is Unknown": {err: errors.New("listing the pods failed"), code: codes.Unknown},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			s := serve(t, &fakeCollector{
				caps: capabilities(),
				watch: func(context.Context, collector.WatchRequest, collector.Sink) error {
					return tc.err
				},
				invoke: func(context.Context, collector.InvokeRequest) ([]cloudevents.Event, *collector.Failure, error) {
					return nil, nil, tc.err
				},
			})
			want := status.Convert(tc.err).Message()

			watch, err := s.evidenceClient().Watch(callContext(t), watchRequest())
			require.NoError(t, err)
			_, err = receiveAll(watch)
			require.Equal(t, tc.code, status.Code(err), "%v", err)
			require.Equal(t, want, status.Convert(err).Message())

			invoke, err := s.evidenceClient().Invoke(callContext(t), invokeRequest(t, newEvent(t, typeInput)))
			require.NoError(t, err)
			_, err = receiveAll(invoke)
			require.Equal(t, tc.code, status.Code(err), "%v", err)
			require.Equal(t, want, status.Convert(err).Message())
		})
	}
}
