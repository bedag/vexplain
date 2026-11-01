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
	"github.com/bedag/vexplain/internal/scan/result"
	"github.com/bedag/vexplain/internal/tasks"
	subjects "github.com/bedag/vexplain/sdk/subject"
)

// digestPattern matches a sha256 digest: the algorithm, a colon and 64 lowercase hex digits.
var digestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

// scanRequest is a scan that the hub asked for: the digest of an image, and the repositories to pull it
// from.
type scanRequest struct {
	// Digest is a repository digest: "sha256:" followed by 64 lowercase hex digits.
	Digest string
	// Repositories are where the digest was pulled from, as the presence entries of its
	// ImageInventory say. The runner pulls the image from one of them.
	Repositories []string
}

// Queue takes the hub's requests for the scanner's evidence to the runner: it is the in-process
// tasks.Executor of a process that is hub and spoke at once. The runner is this process's collector
// of the scanner's type, result.EvidenceType, and of no other. The queue keeps one scan per digest,
// until the runner has started a scan Job for it or dropped it, and hands each digest to the runner's
// work queue.
//
// Request never waits for the runner. The runner may start after the hub has asked, for instance
// while the manager waits for its caches, so the queue keeps those requests, and hands them over when
// the runner starts. A Queue is safe for concurrent use.
type Queue struct {
	mu sync.Mutex
	// requests holds the scan of each digest that waits for a scan Job.
	requests map[string]scanRequest
	// work is the runner's work queue, once the runner has started.
	work workqueue.TypedRateLimitingInterface[reconcile.Request]
}

var _ tasks.Executor = (*Queue)(nil)

// NewQueue returns a Queue that holds no request.
func NewQueue() *Queue {
	return &Queue{requests: map[string]scanRequest{}}
}

// Request asks for the scanner's evidence about the image that r names, and returns at once: a scan of
// its digest. A request for a digest that already waits replaces it: the repositories of the last
// request count, because the presence that it came from is the newest. A request for a digest that is
// being scanned changes nothing: the runner drops it when it sees the digest's scan Job.
//
// It refuses, and keeps nothing of, a request for another type than the scanner's, which nothing in
// this process produces, a request whose subject isn't image/ and a sha256 digest, and one that names
// no repository to pull the image from.
func (q *Queue) Request(_ context.Context, r tasks.Request) error {
	if r.Type != result.EvidenceType {
		return fmt.Errorf("can't deliver evidence of type %q: the scanner of this process delivers %s only",
			r.Type, result.EvidenceType)
	}
	about, err := subjects.Parse(r.Subject)
	if err != nil || about.Kind != subjects.KindImage {
		return fmt.Errorf("can't scan %q: it isn't image/ and a sha256 digest", r.Subject)
	}
	digest := about.Digest
	if len(r.Repositories) == 0 || slices.Contains(r.Repositories, "") {
		return fmt.Errorf("can't scan %s: the request names no repository to pull it from", digest)
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	q.requests[digest] = scanRequest{Digest: digest, Repositories: slices.Clone(r.Repositories)}
	if q.work != nil {
		q.work.Add(requestFor(digest))
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

// pending returns the scan of digest that waits for a scan Job.
func (q *Queue) pending(digest string) (scanRequest, bool) {
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
