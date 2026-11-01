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

package collectorclient_test

import (
	"testing"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/bedag/vexplain/internal/collectorclient"
	collectorv1alpha1 "github.com/bedag/vexplain/sdk/api/collector/v1alpha1"
	"github.com/bedag/vexplain/sdk/collector"
	"github.com/bedag/vexplain/sdk/subject"
)

func TestInvokeReturnsTheEventsOrTheFailure(t *testing.T) {
	e := newEnv(t)
	one, two, four := event(t, 1), event(t, 2), event(t, 4)
	h := newHello(collector.RoleSpoke)
	h.greeter = func(req collector.InvokeRequest) ([]cloudevents.Event, *collector.Failure, error) {
		switch req.Subject {
		case subject.Image(digest(1)):
			return []cloudevents.Event{one, two}, nil, nil
		case subject.Image(digest(3)):
			return nil, &collector.Failure{Reason: "NotFound", Message: "no such image"}, nil
		default:
			return []cloudevents.Event{four}, &collector.Failure{Reason: "TooLarge", Message: "a manifest is too large"}, nil
		}
	}
	e.serve("hello-invoke", h)
	ctx := t.Context()

	events, failure, err := e.pool.Invoke(ctx, "hello-invoke", greeting(1))
	require.NoError(t, err)
	require.Nil(t, failure)
	require.Equal(t, ids(one, two), ids(events...))
	require.Equal(t, one.Data(), events[0].Data())
	require.Equal(t, one.Subject(), events[0].Subject())
	require.Equal(t, helloType, events[0].Type())

	events, failure, err = e.pool.Invoke(ctx, "hello-invoke", greeting(3))
	require.NoError(t, err)
	require.Empty(t, events)
	require.Equal(t, &collectorclient.Failure{Reason: "NotFound", Message: "no such image"}, failure)

	events, failure, err = e.pool.Invoke(ctx, "hello-invoke", greeting(4))
	require.NoError(t, err, "a collector may return events and a failure")
	require.Equal(t, ids(four), ids(events...))
	require.Equal(t, &collectorclient.Failure{Reason: "TooLarge", Message: "a manifest is too large"}, failure)
}

// brokenOff is a call that ends with an error after the first event of its answer.
const brokenOff = "a call that breaks off after an event"

func TestInvokeTakesNothingOfAnAnswerThatBreaksTheContract(t *testing.T) {
	e := newEnv(t)
	valid := event(t, 1)
	// The marks are text that the collector chose, which an error must not repeat.
	invalid := eventOf(t, helloType, "marker-subject", map[string]int{"n": 2})
	invalid.SetID("marker-id")
	undeclared := eventOf(t, "com.example.marker.v1alpha1", subject.Image(digest(3)), map[string]int{"n": 3})
	answers := map[string][]*collectorv1alpha1.InvokeResponse{
		"an event that isn't valid evidence": {answerEvent(t, valid), answerEvent(t, invalid)},
		"a failure without a reason":         {answerEvent(t, valid), answerFailure("", "marker-message")},
		"an event after the failure":         {answerFailure("NotFound", "gone"), answerEvent(t, valid)},
		"a second failure":                   {answerFailure("NotFound", "gone"), answerFailure("NotFound", "gone")},
		"an item that the API doesn't know":  {answerEvent(t, valid), {}},
		brokenOff:                            {answerEvent(t, valid)},
	}
	r := newRaw()
	r.answerWith(func(req *collectorv1alpha1.InvokeRequest) ([]*collectorv1alpha1.InvokeResponse, error) {
		if req.GetOperation() == brokenOff {
			return answers[req.GetOperation()], status.Error(codes.Unavailable, "marker-error")
		}
		return answers[req.GetOperation()], nil
	})
	e.serveRaw("hello-contract", r)

	for what := range answers {
		t.Run(what, func(t *testing.T) {
			events, failure, err := e.pool.Invoke(t.Context(), "hello-contract", &collectorv1alpha1.InvokeRequest{
				Operation: what,
				Subject:   subject.Image(digest(1)),
				Role:      collectorv1alpha1.Role_ROLE_SPOKE,
			})
			require.Error(t, err)
			require.Empty(t, events, "no part of the answer")
			require.Nil(t, failure)
			if what != brokenOff {
				require.NotContains(t, err.Error(), "marker", "the error repeats nothing that the collector chose")
			}
		})
	}

	// An event of a type that the operation doesn't produce is the caller's to refuse: the pool doesn't know what
	// the operation produces. What the pool refuses is evidence that isn't valid.
	r.answerWith(func(*collectorv1alpha1.InvokeRequest) ([]*collectorv1alpha1.InvokeResponse, error) {
		return []*collectorv1alpha1.InvokeResponse{answerEvent(t, undeclared)}, nil
	})
	events, _, err := e.pool.Invoke(t.Context(), "hello-contract", greeting(3))
	require.NoError(t, err)
	require.Equal(t, ids(undeclared), ids(events...))
}
