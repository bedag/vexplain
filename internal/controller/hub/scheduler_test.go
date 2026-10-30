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
	"errors"
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clocktesting "k8s.io/utils/clock/testing"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/controller/hub"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/tasks"
)

// These tests cover the Scheduler: which digests it asks a spoke to scan, and when.

// retryBase is how long a digest waits after its first failed scan.
const retryBase = time.Hour

// newScheduler returns a scheduler over a store on a fake client, with the store, the executor that
// records the scheduler's requests, and the scheduler's clock, which stands at t0.
func newScheduler(t *testing.T) (*hub.Scheduler, inventory.Store, *recordingExecutor, *clocktesting.FakePassiveClock) {
	t.Helper()
	store := inventory.NewCRDStore(newClient(t, interceptor.Funcs{}), nil, cluster)
	executor := &recordingExecutor{}
	clock := clocktesting.NewFakePassiveClock(t0)
	return &hub.Scheduler{
		Store:        store,
		Executor:     executor,
		ScannerImage: scannerImage,
		RetryBase:    retryBase,
		Clock:        clock,
	}, store, executor, clock
}

func TestSchedulerAsksForAScanOfARepositoryDigestWithoutFacts(t *testing.T) {
	scheduler, store, executor, _ := newScheduler(t)
	digest := digestOf(1)
	observe(t, store, digest, localCluster, repository)
	observe(t, store, digest, otherCluster, mirror, repository)

	res, err := scheduler.Reconcile(t.Context(), requestFor(digest))

	require.NoError(t, err)
	// Every repository that a cluster pulled the digest from, once, so that the spoke can pull the
	// image from the one that its pod used.
	require.Equal(t, []tasks.ScanRequest{{Digest: digest, Repositories: []string{repository, mirror}}}, executor.taken())
	// A request can get lost before a scan answers it, so the digest is looked at again.
	require.Equal(t, ctrl.Result{RequeueAfter: retryBase}, res)
}

func TestSchedulerAsksForNoScanOfADigestWithCurrentFacts(t *testing.T) {
	scheduler, store, executor, _ := newScheduler(t)
	digest := digestOf(1)
	observe(t, store, digest, localCluster, repository)
	setFacts(t, store, digest, scannedBy(scannerImage, digestOf(101)))

	res, err := scheduler.Reconcile(t.Context(), requestFor(digest))

	require.NoError(t, err)
	require.Empty(t, executor.taken())
	require.Equal(t, ctrl.Result{}, res)
}

func TestSchedulerAsksForAScanOfADigestThatAnotherScannerImageScanned(t *testing.T) {
	scheduler, store, executor, _ := newScheduler(t)
	digest := digestOf(1)
	observe(t, store, digest, localCluster, repository)
	setFacts(t, store, digest, scannedBy(olderScanner, digestOf(101)))

	res, err := scheduler.Reconcile(t.Context(), requestFor(digest))

	require.NoError(t, err)
	require.Equal(t, []tasks.ScanRequest{{Digest: digest, Repositories: []string{repository}}}, executor.taken())
	require.Equal(t, ctrl.Result{RequeueAfter: retryBase}, res)
}

func TestSchedulerWaitsOutTheBackoffOfFailedScans(t *testing.T) {
	tests := []struct {
		name string
		// lastSuccess is the scanner of the last successful scan, or "" for none.
		lastSuccess string
		attempts    int32
		wait        time.Duration
	}{
		{name: "one failure waits the base", lastSuccess: scannerImage, attempts: 1, wait: time.Hour},
		{name: "two failures wait twice the base", lastSuccess: scannerImage, attempts: 2, wait: 2 * time.Hour},
		{name: "each further failure doubles the wait", lastSuccess: scannerImage, attempts: 5, wait: 16 * time.Hour},
		{name: "the wait is a day at most", lastSuccess: scannerImage, attempts: 6, wait: 24 * time.Hour},
		{name: "any number of failures waits a day", lastSuccess: scannerImage, attempts: math.MaxInt32, wait: 24 * time.Hour},
		{name: "a digest that never succeeded waits too", attempts: 2, wait: 2 * time.Hour},
		// The facts name the scanner of the last success. A digest that fails under a new scanner
		// keeps the old name, and must not be asked for at every look.
		{name: "a failure waits whatever scanner succeeded last", lastSuccess: olderScanner, attempts: 2, wait: 2 * time.Hour},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheduler, store, executor, clock := newScheduler(t)
			digest := digestOf(1)
			observe(t, store, digest, localCluster, repository)
			setFacts(t, store, digest, failedAfter(tt.lastSuccess, tt.attempts, t0))

			clock.SetTime(t0.Add(tt.wait - time.Second))
			res, err := scheduler.Reconcile(t.Context(), requestFor(digest))
			require.NoError(t, err)
			require.Empty(t, executor.taken(), "no request before the wait is over")
			require.Equal(t, ctrl.Result{RequeueAfter: time.Second}, res, "the digest is looked at again when the wait is over")

			clock.SetTime(t0.Add(tt.wait))
			res, err = scheduler.Reconcile(t.Context(), requestFor(digest))
			require.NoError(t, err)
			require.Equal(t, []tasks.ScanRequest{{Digest: digest, Repositories: []string{repository}}}, executor.taken())
			require.Equal(t, ctrl.Result{RequeueAfter: retryBase}, res)
		})
	}
}

func TestSchedulerMarksAnImageIDNotPullableOnceAndNeverAsksForIt(t *testing.T) {
	scheduler, store, executor, clock := newScheduler(t)
	digest := digestOf(1)
	observe(t, store, digest, localCluster) // No repository: an image ID.
	notPullable := &inventoryv1alpha1.ImageFacts{Failure: &inventoryv1alpha1.ScanFailure{
		Reason:   inventoryv1alpha1.ScanFailureReasonNotPullable,
		Time:     ptr.To(metav1.NewTime(t0)),
		Attempts: 1,
	}}

	res, err := scheduler.Reconcile(t.Context(), requestFor(digest))

	require.NoError(t, err)
	require.Equal(t, ctrl.Result{}, res)
	require.Equal(t, notPullable, factsOf(t, store, digest))

	// Later looks change nothing: the failure keeps its time, and the digest is never asked for.
	clock.SetTime(t0.Add(48 * time.Hour))
	res, err = scheduler.Reconcile(t.Context(), requestFor(digest))
	require.NoError(t, err)
	require.Equal(t, ctrl.Result{}, res)
	require.Equal(t, notPullable, factsOf(t, store, digest))
	require.Empty(t, executor.taken())
}

func TestSchedulerDoesNothingForADigestWithoutAnObject(t *testing.T) {
	scheduler, _, executor, _ := newScheduler(t)

	for _, req := range []ctrl.Request{requestFor(digestOf(1)), {}} {
		res, err := scheduler.Reconcile(t.Context(), req)

		require.NoError(t, err)
		require.Equal(t, ctrl.Result{}, res)
	}
	require.Empty(t, executor.taken())
}

// The presence of a digest says what kind it is. Until it does, nobody knows whether the digest can
// be pulled, even with a repository.
func TestSchedulerAsksForNoScanOfADigestOfUnknownKind(t *testing.T) {
	scheduler, store, executor, _ := newScheduler(t)
	digest := digestOf(1)
	require.NoError(t, store.Observe(t.Context(), digest, inventory.Observation{
		Cluster: localCluster, ClusterID: localCluster + "-id", Repositories: []string{repository},
	}))

	res, err := scheduler.Reconcile(t.Context(), requestFor(digest))

	require.NoError(t, err)
	require.Equal(t, ctrl.Result{}, res)
	require.Empty(t, executor.taken())
}

// A spoke can't pull a repository digest without a repository, and refuses such a request.
func TestSchedulerAsksForNoScanOfARepositoryDigestWithoutARepository(t *testing.T) {
	scheduler, store, executor, _ := newScheduler(t)
	digest := digestOf(1)
	require.NoError(t, store.Observe(t.Context(), digest, inventory.Observation{
		Cluster: localCluster, ClusterID: localCluster + "-id", DigestKind: inventoryv1alpha1.DigestKindRepoDigest,
	}))

	res, err := scheduler.Reconcile(t.Context(), requestFor(digest))

	require.NoError(t, err)
	require.Equal(t, ctrl.Result{}, res)
	require.Empty(t, executor.taken())
}

func TestSchedulerReturnsTheErrorOfARequestThatFails(t *testing.T) {
	scheduler, store, executor, _ := newScheduler(t)
	digest := digestOf(1)
	observe(t, store, digest, localCluster, repository)
	executor.err = errors.New("the spoke is unreachable")

	_, err := scheduler.Reconcile(t.Context(), requestFor(digest))

	require.ErrorIs(t, err, executor.err)
}

// A scheduler without a scanner image would find every digest's facts stale, and one without a base
// would ask again at once after every failure.
func TestSchedulerRefusesToStartWithoutAScannerImageOrARetryBase(t *testing.T) {
	for name, scheduler := range map[string]*hub.Scheduler{
		"no scanner image":      {ScannerImage: "", RetryBase: retryBase},
		"no retry base":         {ScannerImage: scannerImage},
		"a negative retry base": {ScannerImage: scannerImage, RetryBase: -time.Hour},
	} {
		t.Run(name, func(t *testing.T) {
			require.Error(t, scheduler.SetupWithManager(nil))
		})
	}
}
