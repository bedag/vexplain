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
	"fmt"
	"slices"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/clock"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/tasks"
)

// maxRetryWait is the longest that a digest whose scans failed waits before it is asked for again.
const maxRetryWait = 24 * time.Hour

// Scheduler asks a spoke to scan each digest whose facts are missing or stale. It reconciles the
// ImageInventory objects, one per digest, which it reads and watches through the inventory store.
// In this order, the first that applies decides:
//   - an image ID gets facts that say it can't be pulled, once, and is never asked for: no registry
//     serves an image by its ID
//   - a repository digest without facts is asked for
//   - one whose scans failed is asked for again once its wait is over: RetryBase after the first
//     failure, doubled for each further failure in a row, a day at most
//   - one whose facts come from another scanner image than the spokes run now is asked for again
//   - one whose facts name a platform manifest without evidence is asked for again
//
// The wait counts whatever scanner image the facts name. They name the scanner of the last success,
// which a digest that fails under a new scanner keeps: without the wait, it would be asked for at
// every look.
//
// Facts that name a manifest say that its evidence exists. Evidence can go after its facts were
// written: the janitor can delete it while a scan reuses it, someone can delete it by hand, and a
// restore from a backup can leave it out. The manifest then gets no sheet, and nothing else would
// scan the digest again until the scanner image changes. Whether evidence exists comes from the
// metadata in the manager's cache, and from the API server when the cache has none: a scan stores
// its evidence just before its facts, so the facts can come before the cache has seen the evidence.
//
// A request names every repository that the digest was pulled from, so that the spoke can pull the
// image from the one that its pod used. After each request, and after each look at a digest whose
// facts are current, the scheduler looks at the digest again in RetryBase: a request can get lost
// before a scan answers it, and evidence can go without an event that the scheduler watches. It
// watches no deletion of evidence: a scan by another scanner image deletes the old evidence before it
// writes its facts, so in between the old facts would make the scheduler ask for a second scan.
//
// setup.Register builds it when a scanner image is configured. Without one, nothing can scan, and
// there is nothing to ask for.
type Scheduler struct {
	// Store keeps the ImageInventory objects: the presence of each digest, and the facts of its scans.
	Store inventory.Store
	// Packages says whether a platform manifest has evidence.
	Packages inventory.PackagesStore
	// Executor takes the requests to a spoke.
	Executor tasks.Executor
	// ScannerImage is the image of the scanner that the spokes run. Facts from another one are stale.
	// It must not be empty.
	ScannerImage string
	// RetryBase is how long a digest waits after its first failed scan, and how long the scheduler
	// waits after a request before it looks at the digest again. It must be positive.
	RetryBase time.Duration
	// Clock tells the time. Nil means the real clock.
	Clock clock.PassiveClock
}

// Reconcile asks for a scan of the digest of the request, or records that it can't be pulled, as
// the facts of the digest call for. A name that isn't the name of a digest is ignored, and so is a
// digest without an object.
func (s *Scheduler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	digest, ok := inventory.DigestForName(req.Name)
	if !ok {
		return ctrl.Result{}, nil
	}
	obj, err := s.Store.Get(ctx, digest)
	if err != nil || obj == nil {
		return ctrl.Result{}, err
	}
	switch ptr.Deref(obj.Status.DigestKind, "") {
	case inventoryv1alpha1.DigestKindImageID:
		return ctrl.Result{}, s.markNotPullable(ctx, digest, obj.Status.Facts)
	case inventoryv1alpha1.DigestKindRepoDigest:
		return s.schedule(ctx, obj)
	}
	// Until the presence of the digest says what kind it is, nobody knows whether it can be pulled.
	return ctrl.Result{}, nil
}

// schedule asks for a scan of the repository digest of obj when its facts are missing or stale.
func (s *Scheduler) schedule(ctx context.Context, obj *inventoryv1alpha1.ImageInventory) (ctrl.Result, error) {
	log := logf.FromContext(ctx).WithValues("digest", obj.Spec.Digest)
	facts := obj.Status.Facts
	var why string
	switch {
	case facts == nil:
		why = "it has never been scanned"
	case facts.Failure != nil:
		if wait := s.retryAfter(facts.Failure); wait > 0 {
			return ctrl.Result{RequeueAfter: wait}, nil
		}
		why = "its last scan failed, and its wait is over"
	case ptr.Deref(facts.ScannerImage, "") != s.ScannerImage:
		why = "another scanner image scanned it"
	default:
		missing, err := s.manifestWithoutEvidence(ctx, facts)
		if err != nil {
			return ctrl.Result{}, err
		}
		if missing == "" {
			return ctrl.Result{RequeueAfter: s.RetryBase}, nil
		}
		log.Info("The evidence of a manifest that the facts name is gone; asking for a scan again", "manifest", missing)
		why = "the evidence of a manifest is gone"
	}

	repositories := repositoriesOf(obj)
	if len(repositories) == 0 {
		// A spoke can't pull the image without a repository. The presence that names one is an event
		// of its own.
		log.V(1).Info("Asked for no scan: no repository to pull the image from")
		return ctrl.Result{}, nil
	}
	if err := s.Executor.RequestScan(ctx, tasks.ScanRequest{Digest: obj.Spec.Digest, Repositories: repositories}); err != nil {
		return ctrl.Result{}, fmt.Errorf("ask for a scan of %s: %w", obj.Spec.Digest, err)
	}
	log.V(1).Info("Asked for a scan", "because", why)
	return ctrl.Result{RequeueAfter: s.RetryBase}, nil
}

// manifestWithoutEvidence returns the first platform manifest that facts name and that has no
// evidence, or "" when each has evidence.
func (s *Scheduler) manifestWithoutEvidence(ctx context.Context, facts *inventoryv1alpha1.ImageFacts) (string, error) {
	for _, platform := range facts.Platforms {
		exists, err := s.Packages.Exists(ctx, platform.ManifestDigest)
		if err != nil {
			return "", fmt.Errorf("look for the evidence of manifest %s: %w", platform.ManifestDigest, err)
		}
		if !exists {
			return platform.ManifestDigest, nil
		}
	}
	return "", nil
}

// retryAfter returns how long a digest whose scans failed has still to wait before it is asked for
// again, or a duration of zero or less when its wait is over. The wait runs from the last failure.
func (s *Scheduler) retryAfter(failure *inventoryv1alpha1.ScanFailure) time.Duration {
	if failure.Time == nil {
		return 0
	}
	return failure.Time.Add(retryWait(s.RetryBase, failure.Attempts)).Sub(s.now())
}

// retryWait returns the wait after attempts failed scans in a row: base, doubled for each failure
// after the first, maxRetryWait at most.
func retryWait(base time.Duration, attempts int32) time.Duration {
	wait := base
	for failure := int32(1); failure < attempts && wait < maxRetryWait; failure++ {
		wait *= 2
	}
	return min(wait, maxRetryWait)
}

// markNotPullable records in the facts of digest, an image ID, that it can't be pulled, unless they
// say so already: the mark keeps the time it was first made.
func (s *Scheduler) markNotPullable(ctx context.Context, digest string, facts *inventoryv1alpha1.ImageFacts) error {
	if facts != nil && facts.Failure != nil && facts.Failure.Reason == inventoryv1alpha1.ScanFailureReasonNotPullable {
		return nil
	}
	marked := facts.DeepCopy()
	if marked == nil {
		marked = &inventoryv1alpha1.ImageFacts{}
	}
	marked.Failure = &inventoryv1alpha1.ScanFailure{
		Reason:   inventoryv1alpha1.ScanFailureReasonNotPullable,
		Time:     ptr.To(metav1.NewTime(s.now())),
		Attempts: 1,
	}
	if _, err := s.Store.SetFacts(ctx, digest, marked); err != nil {
		return fmt.Errorf("record that image ID %s can't be pulled: %w", digest, err)
	}
	logf.FromContext(ctx).Info("Recorded that an image ID can't be pulled, so it is never scanned", "digest", digest)
	return nil
}

// now returns the time of the scheduler's clock.
func (s *Scheduler) now() time.Time {
	if s.Clock == nil {
		return time.Now()
	}
	return s.Clock.Now()
}

// repositoriesOf returns the repositories that the presence of obj names, in every cluster: sorted,
// and each once.
func repositoriesOf(obj *inventoryv1alpha1.ImageInventory) []string {
	var repositories []string
	for _, entry := range obj.Status.Clusters {
		repositories = append(repositories, entry.Repositories...)
	}
	slices.Sort(repositories)
	return slices.Compact(repositories)
}

// SetupWithManager sets up the scheduler with the Manager. It refuses a scheduler without a scanner
// image, which would find the facts of every digest stale, and one without a positive RetryBase,
// which would ask again at once after every failure.
func (s *Scheduler) SetupWithManager(mgr ctrl.Manager) error {
	if s.ScannerImage == "" {
		return errors.New("the scan scheduler needs the image of the scanner that the spokes run")
	}
	if s.RetryBase <= 0 {
		return errors.New("the scan scheduler needs a positive wait after a failed scan")
	}
	return ctrl.NewControllerManagedBy(mgr).
		Named("hub-scheduler").
		// Every event of an ImageInventory, through the store, the only door to them: a new digest, a
		// change of its presence, and the facts that a scan writes.
		WatchesRawSource(s.Store.Source()).
		Complete(s)
}
