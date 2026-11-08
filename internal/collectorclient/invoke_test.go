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
	"context"
	"testing"
	"time"

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
			if what == brokenOff {
				require.NotErrorIs(t, err, collectorclient.ErrContract, "a call that broke off is the call's error")
				return
			}
			require.ErrorIs(t, err, collectorclient.ErrContract)
			require.NotContains(t, err.Error(), "marker", "the error repeats nothing that the collector chose")
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

// scheduleRefresh is the name of the schedule that the tests of Fire run.
const scheduleRefresh = "refresh"

func TestFireRunsAScheduleWithADeadlineOfTenSeconds(t *testing.T) {
	e := newEnv(t)
	r := newRaw()
	var got *collectorv1alpha1.FireRequest
	var remaining time.Duration
	r.fireWith(func(ctx context.Context, req *collectorv1alpha1.FireRequest) error {
		got = req
		deadline, ok := ctx.Deadline()
		require.True(t, ok, "the call has a deadline")
		remaining = time.Until(deadline)
		return nil
	})
	e.serveRaw("hello-fire", r)

	req := &collectorv1alpha1.FireRequest{
		Schedule: scheduleRefresh,
		Settings: []byte(`{"greeting": "hello"}`),
		Context:  &collectorv1alpha1.Context{Cluster: "cluster-a"},
	}
	require.NoError(t, e.pool.Fire(t.Context(), "hello-fire", req))

	require.Equal(t, scheduleRefresh, got.GetSchedule())
	require.JSONEq(t, `{"greeting": "hello"}`, string(got.GetSettings()))
	require.Equal(t, "cluster-a", got.GetContext().GetCluster())
	require.Equal(t, collectorclient.FireTimeout, 10*time.Second)
	require.Greater(t, remaining, 8*time.Second)
	require.LessOrEqual(t, remaining, collectorclient.FireTimeout)
}

func TestFireEndsWhenTheCallersContextEnds(t *testing.T) {
	e := newEnv(t)
	r := newRaw()
	r.fireWith(func(ctx context.Context, _ *collectorv1alpha1.FireRequest) error {
		<-ctx.Done()
		return ctx.Err()
	})
	e.serveRaw("hello-fire-slow", r)
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()

	err := e.pool.Fire(ctx, "hello-fire-slow", &collectorv1alpha1.FireRequest{Schedule: scheduleRefresh})

	require.Error(t, err)
	require.Contains(t, err.Error(), "hello-fire-slow")
}

func TestFireKeepsTheCodeOfTheCollectorsError(t *testing.T) {
	e := newEnv(t)
	r := newRaw()
	r.fireWith(func(context.Context, *collectorv1alpha1.FireRequest) error {
		return status.Error(codes.InvalidArgument, "no such schedule")
	})
	e.serveRaw("hello-fire-refuses", r)

	err := e.pool.Fire(t.Context(), "hello-fire-refuses", &collectorv1alpha1.FireRequest{Schedule: scheduleRefresh})

	require.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestFireOfACollectorThatIsNotInThePoolFails(t *testing.T) {
	e := newEnv(t)

	require.Error(t, e.pool.Fire(t.Context(), "nobody", &collectorv1alpha1.FireRequest{Schedule: scheduleRefresh}))
}
