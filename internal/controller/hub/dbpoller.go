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
	"context"
	"errors"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/workqueue"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	"github.com/bedag/vexplain/internal/inventory"
)

// DatabasePoller follows the version of the matcher's vulnerability database. It is a
// manager.Runnable: it reads the version at once and then every Interval, and when the version
// differs from the one it read last, it has every manifest matched again. It enqueues each manifest
// that has evidence, once, into the queue of the verdicts controller, which watches its Source.
//
// The version changes with each build of the database, so every daily build has every manifest
// matched again. The first read only records the version: the verdicts controller matches every
// manifest when it starts. A read that fails keeps the version that the poller read last, and so
// does a change that can't list the evidence, so that the next read tries again.
type DatabasePoller struct {
	// Matcher tells the version of its database.
	Matcher Matcher
	// Packages lists the manifests that have evidence.
	Packages inventory.PackagesStore
	// Interval is the time from the end of one read to the start of the next. It must be positive.
	Interval time.Duration

	mu sync.Mutex
	// version is the version of the database at the last read, or "" before the first.
	version string
	// queue is the queue of the verdicts controller, once the controller has started.
	queue workqueue.TypedRateLimitingInterface[reconcile.Request]
}

// Start reads the version of the matcher's database at once, and then every Interval, until ctx is
// done.
func (p *DatabasePoller) Start(ctx context.Context) error {
	if p.Interval <= 0 {
		return errors.New("the poller of the matcher's database needs a positive interval")
	}
	wait.UntilWithContext(ctx, p.poll, p.Interval)
	return nil
}

// Version returns the version of the matcher's database at the last read, or "" before the first.
func (p *DatabasePoller) Version() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.version
}

// Source is the source through which the verdicts controller gets the manifests to match again.
func (p *DatabasePoller) Source() source.Source {
	return source.Func(p.start)
}

// start hands the poller the queue of the verdicts controller, which calls it as a source, once, when
// it starts.
func (p *DatabasePoller) start(_ context.Context, queue workqueue.TypedRateLimitingInterface[reconcile.Request]) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.queue = queue
	return nil
}

// poll reads the version of the matcher's database, and has every manifest matched again when it
// has changed since the last read.
func (p *DatabasePoller) poll(ctx context.Context) {
	log := logf.FromContext(ctx).WithName("database-poller")
	database, err := p.Matcher.Database(ctx)
	if err != nil {
		// The errors of the matcher's client are fixed texts.
		log.Error(err, "Could not read the version of the matcher's database; the next poll tries again")
		return
	}
	last := p.Version()
	switch {
	case database.Version == last:
		return
	case last == "":
		p.changeTo(database.Version, nil)
		log.Info("Read the version of the matcher's database", "version", database.Version)
		return
	}
	manifests, err := p.Packages.Digests(ctx)
	if err != nil {
		log.Error(err, "Could not list the manifests to match against a new database; the next poll tries again",
			"version", database.Version)
		return
	}
	p.changeTo(database.Version, manifests)
	log.Info("The matcher's database changed: matching every manifest again",
		"from", last, "to", database.Version, "manifests", len(manifests))
}

// changeTo records the version of the database, and then enqueues the manifests. In that order, a
// reconcile that takes a manifest from the queue compares the manifest's last match with the new
// version. A reconcile that started before the change gets the manifest again: the queue holds it
// back while it is being reconciled.
func (p *DatabasePoller) changeTo(version string, manifests []string) {
	p.mu.Lock()
	p.version = version
	queue := p.queue
	p.mu.Unlock()
	if queue == nil {
		// The controller hasn't started. It matches every manifest when it does.
		return
	}
	for _, manifest := range manifests {
		queue.Add(requestFor(manifest))
	}
}
