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
	"context"
	"fmt"
	"regexp"
	"slices"
	"sync"

	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/tasks"
)

// digestPattern matches a sha256 digest: the algorithm, a colon and 64 lowercase hex digits.
var digestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

// Queue takes the hub's scan requests to the runner: it is the in-process tasks.Executor of a
// process that is hub and spoke at once. It keeps one request per digest, until the runner has
// started a scan Job for it or dropped it, and hands each digest to the runner's work queue.
//
// RequestScan never waits for the runner. The runner may start after the hub has asked, for
// instance while the manager waits for its caches, so the queue keeps those requests, and hands them
// over when the runner starts. A Queue is safe for concurrent use.
type Queue struct {
	mu sync.Mutex
	// requests holds the request of each digest that waits for a scan Job.
	requests map[string]tasks.ScanRequest
	// work is the runner's work queue, once the runner has started.
	work workqueue.TypedRateLimitingInterface[reconcile.Request]
}

var _ tasks.Executor = (*Queue)(nil)

// NewQueue returns a Queue that holds no request.
func NewQueue() *Queue {
	return &Queue{requests: map[string]tasks.ScanRequest{}}
}

// RequestScan asks for a scan of req.Digest, and returns at once. A request for a digest that
// already waits replaces it: the repositories of the last request count, because the presence that
// it came from is the newest. A request for a digest that is being scanned changes nothing: the
// runner drops it when it sees the digest's scan Job.
//
// It refuses, and keeps nothing of, a request whose digest isn't a sha256 digest, or that names no
// repository to pull the image from.
func (q *Queue) RequestScan(_ context.Context, req tasks.ScanRequest) error {
	if !digestPattern.MatchString(req.Digest) {
		return fmt.Errorf("can't scan %q: it isn't a sha256 digest", req.Digest)
	}
	if len(req.Repositories) == 0 || slices.Contains(req.Repositories, "") {
		return fmt.Errorf("can't scan %s: the request names no repository to pull it from", req.Digest)
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	q.requests[req.Digest] = tasks.ScanRequest{Digest: req.Digest, Repositories: slices.Clone(req.Repositories)}
	if q.work != nil {
		q.work.Add(requestFor(req.Digest))
	}
	return nil
}

// start hands the queue the runner's work queue, and puts every digest that waits into it. The
// runner's controller calls it as a source, once, when it starts.
func (q *Queue) start(_ context.Context, work workqueue.TypedRateLimitingInterface[reconcile.Request]) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.work = work
	for digest := range q.requests {
		work.Add(requestFor(digest))
	}
	return nil
}

// pending returns the request of digest that waits for a scan Job.
func (q *Queue) pending(digest string) (tasks.ScanRequest, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	req, ok := q.requests[digest]
	req.Repositories = slices.Clone(req.Repositories)
	return req, ok
}

// done forgets the request of digest: a scan Job answers it, or the runner dropped it.
func (q *Queue) done(digest string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	delete(q.requests, digest)
}

// requestFor returns the request under which the runner reconciles digest: the name of its
// ImageInventory, as everything that reconciles a digest names it.
func requestFor(digest string) reconcile.Request {
	return reconcile.Request{NamespacedName: types.NamespacedName{Name: inventory.NameForDigest(digest)}}
}
