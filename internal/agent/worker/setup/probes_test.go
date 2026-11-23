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

package setup

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

// within bounds how long the probes take to react in these tests.
const within = 10 * time.Second

// memoryLock is a Lease in memory, which a test can give to another holder or free. As the API server does with a
// resourceVersion, it refuses an update that rests on a version older than its own.
type memoryLock struct {
	mu     sync.Mutex
	record *resourcelock.LeaderElectionRecord
	// version counts the writes, and seen is the version that the elector read or wrote last.
	version, seen int
}

var leases = schema.GroupResource{Group: "coordination.k8s.io", Resource: "leases"}

func (l *memoryLock) Get(context.Context) (*resourcelock.LeaderElectionRecord, []byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.seen = l.version
	if l.record == nil {
		return nil, nil, apierrors.NewNotFound(leases, "probes")
	}
	record := *l.record
	raw, err := json.Marshal(record)
	return &record, raw, err
}

func (l *memoryLock) Create(_ context.Context, record resourcelock.LeaderElectionRecord) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.record != nil {
		return apierrors.NewAlreadyExists(leases, "probes")
	}
	l.write(record)
	return nil
}

func (l *memoryLock) Update(_ context.Context, record resourcelock.LeaderElectionRecord) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.record == nil || l.seen != l.version {
		return apierrors.NewConflict(leases, "probes", errors.New("the Lease changed"))
	}
	l.write(record)
	return nil
}

func (l *memoryLock) write(record resourcelock.LeaderElectionRecord) {
	l.record = &record
	l.version++
	l.seen = l.version
}

func (*memoryLock) RecordEvent(string) {}
func (*memoryLock) Identity() string   { return "worker-a" }
func (*memoryLock) Describe() string   { return "probes" }

// steal gives the Lease to another worker, for an hour.
func (l *memoryLock) steal() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.record = &resourcelock.LeaderElectionRecord{HolderIdentity: "worker-b", LeaseDurationSeconds: 3600,
		AcquireTime: metav1.Now(), RenewTime: metav1.Now()}
	l.version++
}

// free deletes the Lease.
func (l *memoryLock) free() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.record = nil
	l.version++
}

// running is a controller that hands the context of each start to the test, and runs until it ends.
type running chan context.Context

func (r running) Start(ctx context.Context) error {
	r <- ctx
	<-ctx.Done()
	return nil
}

func (running) Reconcile(context.Context, reconcile.Request) (reconcile.Result, error) {
	return reconcile.Result{}, nil
}
func (running) Watch(source.TypedSource[reconcile.Request]) error { return nil }
func (running) GetLogger() logr.Logger                            { return logr.Discard() }

// started returns the context of the next start of a controller.
func (r running) started(t *testing.T) context.Context {
	t.Helper()
	select {
	case ctx := <-r:
		return ctx
	case <-time.After(within):
		t.Fatal("no controller started")
		return nil
	}
}

// Losing the Lease stops the probes, and not the worker: Start runs on, and so does the claim loop, which the manager
// stops only when a runnable such as this one fails. The worker campaigns again, and probes again once it holds the
// Lease again, with a controller of its own.
func TestLosingTheLeaseStopsOnlyTheProbes(t *testing.T) {
	lock := &memoryLock{}
	controllers := make(running, 2)
	p := &probes{lock: lock, log: logr.Discard(), leaseDuration: time.Second, renewDeadline: 500 * time.Millisecond,
		retryPeriod: 50 * time.Millisecond, build: func() (controller.Controller, error) { return controllers, nil }}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- p.Start(ctx) }()

	first := controllers.started(t)
	lock.steal()
	select {
	case <-first.Done():
	case <-time.After(within):
		t.Fatal("the probes went on without the Lease")
	}
	select {
	case err := <-done:
		t.Fatalf("the probes' runnable stopped with the Lease: %v", err)
	case <-controllers:
		t.Fatal("a controller started without the Lease")
	case <-time.After(time.Second):
	}
	lock.free()
	second := controllers.started(t)

	cancel()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(within):
		t.Fatal("the probes didn't stop with their context")
	}
	require.Error(t, second.Err(), "the last term's controller stopped before Start returned")
}

// Without a lock, as in a test or a local run, the controller runs for as long as Start does.
func TestWithoutALockTheProbesRunDirectly(t *testing.T) {
	controllers := make(running, 1)
	p := &probes{log: logr.Discard(), build: func() (controller.Controller, error) { return controllers, nil }}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- p.Start(ctx) }()

	started := controllers.started(t)
	cancel()
	require.NoError(t, <-done)
	require.Error(t, started.Err())
}
