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

package hub_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/bedag/vexplain/internal/controller/hub"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/matchapi"
)

// These tests cover the DatabasePoller: which version of the matcher's database it knows, and when
// it has every manifest matched again.

// newPoller returns a poller of a matcher whose database is v1, over the evidence of manifests on a
// fake client with funcs, and the queue of the controller that the poller enqueues into.
func newPoller(t *testing.T, funcs interceptor.Funcs, manifests ...string) (*hub.DatabasePoller, *fakeMatcher,
	workqueue.TypedRateLimitingInterface[reconcile.Request]) {
	t.Helper()
	packages := inventory.NewCRDPackagesStore(newClient(t, funcs), nil, cluster)
	for _, manifest := range manifests {
		require.NoError(t, packages.Put(t.Context(), scannerImage, t0, evidenceOf(manifest)))
	}
	matcher := newFakeMatcher()
	poller := &hub.DatabasePoller{Matcher: matcher, Packages: packages, Interval: time.Hour}
	queue := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[reconcile.Request]())
	t.Cleanup(queue.ShutDown)
	// The controller starts the poller's source, as it starts every source it watches.
	require.NoError(t, poller.Source().Start(t.Context(), queue))
	return poller, matcher, queue
}

// drain takes every request out of the queue, as the controller's workers would.
func drain(queue workqueue.TypedRateLimitingInterface[reconcile.Request]) []reconcile.Request {
	var requests []reconcile.Request
	for queue.Len() > 0 {
		req, _ := queue.Get()
		requests = append(requests, req)
		queue.Done(req)
	}
	return requests
}

// Until the first read, the controller matches every manifest, against whatever database the matcher
// has then. The first read has every manifest matched again, as a change does: the controller leaves
// those matched against the version that the poller read.
func TestPollerEnqueuesEveryManifestAtTheFirstRead(t *testing.T) {
	poller, _, queue := newPoller(t, interceptor.Funcs{}, digestOf(101), digestOf(102))
	require.Empty(t, poller.Version(), "no version is known before the first read")

	hub.Poll(poller, t.Context())

	require.Equal(t, v1, poller.Version())
	require.ElementsMatch(t, []reconcile.Request{requestFor(digestOf(101)), requestFor(digestOf(102))}, drain(queue))

	// The same version, read again, is no change.
	hub.Poll(poller, t.Context())
	require.Empty(t, drain(queue))
}

func TestPollerEnqueuesEveryManifestOnceWhenTheVersionChanges(t *testing.T) {
	poller, matcher, queue := newPoller(t, interceptor.Funcs{}, digestOf(101), digestOf(102))
	hub.Poll(poller, t.Context())
	drain(queue)

	matcher.set(v2)
	hub.Poll(poller, t.Context())

	require.Equal(t, v2, poller.Version())
	require.ElementsMatch(t, []reconcile.Request{requestFor(digestOf(101)), requestFor(digestOf(102))}, drain(queue))

	// The same version, read again, is no change.
	hub.Poll(poller, t.Context())
	require.Empty(t, drain(queue))
}

func TestPollerKeepsTheVersionItReadLastWhenTheMatcherFails(t *testing.T) {
	poller, matcher, queue := newPoller(t, interceptor.Funcs{}, digestOf(101))
	hub.Poll(poller, t.Context())
	drain(queue)

	matcher.failDatabase(matchapi.ErrUnavailable)
	hub.Poll(poller, t.Context())

	require.Equal(t, v1, poller.Version())
	require.Empty(t, drain(queue))

	// The next read that succeeds counts.
	matcher.failDatabase(nil)
	matcher.set(v2)
	hub.Poll(poller, t.Context())
	require.Equal(t, v2, poller.Version())
	require.Equal(t, []reconcile.Request{requestFor(digestOf(101))}, drain(queue))
}

// Until every manifest is enqueued, the controller must not take the matches of the old database for
// current: so the poller keeps the old version, and the next poll tries again.
func TestPollerTriesAgainAtTheNextPollWhenItCantListTheEvidence(t *testing.T) {
	var failList atomic.Bool
	poller, matcher, queue := newPoller(t, interceptor.Funcs{List: func(ctx context.Context, c client.WithWatch,
		list client.ObjectList, opts ...client.ListOption) error {
		if failList.Load() {
			return errors.New("the API server is unavailable")
		}
		return c.List(ctx, list, opts...)
	}}, digestOf(101))

	// The first read, too, counts only once it has enqueued the manifests.
	failList.Store(true)
	hub.Poll(poller, t.Context())
	require.Empty(t, poller.Version())
	require.Empty(t, drain(queue))
	failList.Store(false)
	hub.Poll(poller, t.Context())
	require.Equal(t, v1, poller.Version())
	require.Equal(t, []reconcile.Request{requestFor(digestOf(101))}, drain(queue))

	matcher.set(v2)
	failList.Store(true)
	hub.Poll(poller, t.Context())

	require.Equal(t, v1, poller.Version())
	require.Empty(t, drain(queue))

	failList.Store(false)
	hub.Poll(poller, t.Context())
	require.Equal(t, v2, poller.Version())
	require.Equal(t, []reconcile.Request{requestFor(digestOf(101))}, drain(queue))
}

// Before its controller starts, the poller has no queue. The controller matches every manifest when
// it starts, so a change that the poller reads before then needs no enqueue.
func TestPollerFollowsTheVersionBeforeItsControllerStarts(t *testing.T) {
	matcher := newFakeMatcher()
	poller := &hub.DatabasePoller{Matcher: matcher, Packages: inventory.NewCRDPackagesStore(
		newClient(t, interceptor.Funcs{}), nil, cluster), Interval: time.Hour}
	hub.Poll(poller, t.Context())

	matcher.set(v2)
	hub.Poll(poller, t.Context())

	require.Equal(t, v2, poller.Version())
}

func TestPollerRefusesANonPositiveInterval(t *testing.T) {
	for _, interval := range []time.Duration{0, -time.Minute} {
		poller := &hub.DatabasePoller{Matcher: newFakeMatcher(), Interval: interval}

		require.Error(t, poller.Start(t.Context()))
	}
}

func TestPollerReadsTheDatabaseAtOnceAndStopsWithItsContext(t *testing.T) {
	poller, _, _ := newPoller(t, interceptor.Funcs{})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- poller.Start(ctx) }()

	// The interval is an hour: only a read at once gets the version within the test.
	require.Eventually(t, func() bool { return poller.Version() == v1 }, 5*time.Second, 10*time.Millisecond)

	cancel()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("the poller did not stop when its context ended")
	}
}
