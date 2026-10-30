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

package scan

import (
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/tasks"
)

// These tests cover the queue between the hub's requests and the runner: what it keeps of a request,
// and when it hands the digest to the runner's work queue.

const (
	queuedDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	otherDigest  = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

// newWorkQueue returns a work queue like the one a controller hands its sources, and shuts it down
// when the test ends.
func newWorkQueue(t *testing.T) workqueue.TypedRateLimitingInterface[reconcile.Request] {
	t.Helper()
	q := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[reconcile.Request]())
	t.Cleanup(q.ShutDown)
	return q
}

// drain returns the requests that the work queue holds, in order.
func drain(q workqueue.TypedRateLimitingInterface[reconcile.Request]) []reconcile.Request {
	var requests []reconcile.Request
	for q.Len() > 0 {
		item, _ := q.Get()
		q.Done(item)
		requests = append(requests, item)
	}
	return requests
}

// requestOf is the request under which the runner reconciles digest.
func requestOf(digest string) reconcile.Request {
	return reconcile.Request{NamespacedName: types.NamespacedName{Name: inventory.NameForDigest(digest)}}
}

func TestQueueRefusesARequestItCannotScan(t *testing.T) {
	q := NewQueue()
	for _, req := range []tasks.ScanRequest{
		{Digest: "sha256:abc", Repositories: []string{appRepository}},
		{Digest: "artifacts.example/team-a/app@" + queuedDigest, Repositories: []string{appRepository}},
		{Digest: queuedDigest},
		{Digest: queuedDigest, Repositories: []string{""}},
	} {
		require.Error(t, q.RequestScan(t.Context(), req), "%+v", req)
	}
	_, ok := q.pending(queuedDigest)
	require.False(t, ok, "a refused request is not kept")
}

// The hub can ask before the runner has started, for instance while the manager waits for its
// caches. The queue keeps those requests, and hands them over when the runner starts.
func TestQueueHandsOverTheRequestsThatCameBeforeTheRunnerStarted(t *testing.T) {
	q, work := NewQueue(), newWorkQueue(t)
	require.NoError(t, q.RequestScan(t.Context(), tasks.ScanRequest{Digest: queuedDigest, Repositories: []string{appRepository}}))

	require.NoError(t, q.start(t.Context(), work))

	require.Equal(t, []reconcile.Request{requestOf(queuedDigest)}, drain(work))
	require.NoError(t, q.RequestScan(t.Context(), tasks.ScanRequest{Digest: otherDigest, Repositories: []string{"artifacts.example/team-a/tool"}}))
	require.Equal(t, []reconcile.Request{requestOf(otherDigest)}, drain(work), "a later request is handed over at once")
}

// Asking again for a digest keeps one request, with the repositories of the last one: the presence
// that it came from is the newest.
func TestQueueKeepsOneRequestPerDigest(t *testing.T) {
	q, work := NewQueue(), newWorkQueue(t)
	require.NoError(t, q.start(t.Context(), work))
	latest := []string{appRepository, "artifacts.example/mirror/app"}

	require.NoError(t, q.RequestScan(t.Context(), tasks.ScanRequest{Digest: queuedDigest,
		Repositories: []string{appRepository}}))
	require.NoError(t, q.RequestScan(t.Context(), tasks.ScanRequest{Digest: queuedDigest, Repositories: latest}))
	latest[0] = "changed by the caller"

	require.Equal(t, []reconcile.Request{requestOf(queuedDigest)}, drain(work))
	req, ok := q.pending(queuedDigest)
	require.True(t, ok)
	require.Equal(t, tasks.ScanRequest{Digest: queuedDigest,
		Repositories: []string{appRepository, "artifacts.example/mirror/app"}}, req)
}

func TestQueueForgetsARequestThatIsDone(t *testing.T) {
	q := NewQueue()
	require.NoError(t, q.RequestScan(t.Context(), tasks.ScanRequest{Digest: queuedDigest, Repositories: []string{appRepository}}))
	_, ok := q.pending(queuedDigest)
	require.True(t, ok)

	q.done(queuedDigest)

	_, ok = q.pending(queuedDigest)
	require.False(t, ok)
}
