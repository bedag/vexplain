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

// Package scan is the spoke's Scanner: it runs the scans that the hub asks for, one Job per image
// digest in the operator's namespace (decision 0022), and stores what they found through the
// inventory stores, the only door to the inventory.
//
// A scan Job runs the scanner image without access to the Kubernetes API. It pulls the image with
// the credentials of a pod that runs it, from a Secret that the Job owns, and prints one line to its
// log: what it found, or why it failed. The runner reads that line back, checks it, and only then
// stores the evidence of each platform manifest through inventory.PackagesStore and the facts of the
// digest through inventory.Store.
//
// The hub reaches the runner only through tasks.Executor, which Queue implements for a process that
// is hub and spoke at once, and the stores (decision 0021).
package scan

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"math"
	"slices"
	"sync"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/collector"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/scan/result"
	"github.com/bedag/vexplain/internal/tasks"
	"github.com/bedag/vexplain/internal/workloads"
)

// defaultSlotWait is how long a request waits while every slot is taken, before it asks again.
const defaultSlotWait = 30 * time.Second

// ErrNoScannerImage is the failure that the Scanner reports while no scanner image is configured.
var ErrNoScannerImage = errors.New("no scanner image is configured")

// The runner creates its scan Jobs in its namespace, reads them from the API server, and deletes
// them once it has stored what they found. It watches their metadata through the manager's cache,
// which holds the metadata of every Job for the pod inventory. It creates the Secret of each Job.
// +kubebuilder:rbac:groups=batch,resources=jobs,verbs=create;delete;get;list;watch,namespace=vexplain-system
// +kubebuilder:rbac:groups="",resources=secrets,verbs=create,namespace=vexplain-system

// Runner runs the scans that the hub asks for through Queue, and stores what they found. It
// reconciles one digest at a time, named after its ImageInventory: it starts a scan Job for a
// request, follows the Job, and once the Job's pod has finished, records what the scan found or why
// it failed, deletes the Job, and reports the outcome as the health of the Scanner.
//
// setup.Register builds it.
type Runner struct {
	// Client creates and deletes the scan Jobs and their Secrets. It reads the pods and the scanner
	// Collector from the manager's cache.
	Client client.Client
	// APIReader reads the scan Jobs and the nodes from the API server, so that the count of the
	// running scans never misses a Job just created.
	APIReader client.Reader
	// Store keeps the facts of the digests, and Packages the evidence of the platform manifests.
	Store    inventory.Store
	Packages inventory.PackagesStore
	// Registry is where the runner reports the health of the Scanner.
	Registry *collector.Registry
	// Queue holds the hub's requests.
	Queue *Queue
	// Logs reads the logs of the scan pods, and Credentials builds the credentials of a scan.
	Logs        LogReader
	Credentials CredentialSource
	// OperatorNamespace is where the scan Jobs run. It must be the namespace that the pod index was
	// built for, with workloads.PodDigestIndexer, so that the index leaves out the scan pods.
	OperatorNamespace string
	// ScannerImage is the image that the scan Jobs run. Empty means that nothing can scan: the
	// runner drops every request.
	ScannerImage string
	// ProxyEnv holds the manager's proxy variables, which every scan Job gets.
	ProxyEnv []corev1.EnvVar
	// RegistryMirrors are the scanner's --registry-mirror arguments, each host=url.
	RegistryMirrors []string
	// SlotWait is how long a request waits while every slot is taken, before it asks again. Zero
	// means 30 seconds.
	SlotWait time.Duration

	// recorded holds the outcome of each finished Job whose facts are written, until the Job is
	// deleted. When a deletion fails, the retry deletes the Job without writing the facts again, so
	// that a failed scan counts once. Guarded by mu.
	mu       sync.Mutex
	recorded map[types.UID]recordedScan
}

// recordedScan is the outcome of a scan whose facts are written.
type recordedScan struct {
	// failure is what the Scanner reports for the scan: nil for a success.
	failure error
}

// Reconcile follows the scan of the digest of the request: it starts a scan Job for a request that
// waits, and records what a finished Job found. It reports any error as the health of the Scanner,
// and returns it, so that the request is retried. A name that isn't the name of a digest is ignored.
func (r *Runner) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	digest, ok := inventory.DigestForName(req.Name)
	if !ok {
		return ctrl.Result{}, nil
	}
	res, err := r.reconcileDigest(ctx, digest)
	if err != nil {
		r.Registry.ReportFailure(configv1alpha1.CollectorTypeScanner, err)
	}
	return res, err
}

// reconcileDigest follows the scan Jobs of digest, or starts one for a request that waits.
func (r *Runner) reconcileDigest(ctx context.Context, digest string) (ctrl.Result, error) {
	jobs, err := r.scanJobs(ctx, labelsOf(digest))
	if err != nil {
		return ctrl.Result{}, err
	}
	// The label holds the start of the digest, and the annotation all of it. A Job that is being
	// deleted has been dealt with, and scans no more.
	jobs = slices.DeleteFunc(jobs, func(job batchv1.Job) bool {
		return job.Annotations[DigestLabel] != digest || job.DeletionTimestamp != nil
	})
	if len(jobs) > 0 {
		// A request for a digest that is being scanned changes nothing: the running scan answers it.
		r.Queue.done(digest)
		for i := range jobs {
			if err := r.follow(ctx, digest, &jobs[i]); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}
	req, ok := r.Queue.pending(digest)
	if !ok {
		return ctrl.Result{}, nil
	}
	return r.start(ctx, req)
}

// start starts a scan Job for req, when a slot is free, and drops the request when there is
// nothing to scan.
func (r *Runner) start(ctx context.Context, req tasks.ScanRequest) (ctrl.Result, error) {
	log := logf.FromContext(ctx).WithValues("digest", req.Digest)
	if r.ScannerImage == "" {
		// Nothing can scan. The Scanner has said so since the start, and a request can't change it.
		r.Queue.done(req.Digest)
		return ctrl.Result{}, nil
	}

	settings, err := loadScannerSettings(ctx, r.Client)
	if err != nil {
		return ctrl.Result{}, err
	}
	active, err := r.activeScans(ctx)
	if err != nil {
		return ctrl.Result{}, err
	}
	if active >= int(settings.maxConcurrentScans) {
		return ctrl.Result{RequeueAfter: r.slotWait()}, nil
	}

	pods, err := r.podsRunning(ctx, req.Digest)
	if err != nil {
		return ctrl.Result{}, err
	}
	if len(pods) == 0 {
		// The digest runs nowhere in this cluster any more: there is nothing to scan it for, and no
		// pull secret to scan it with.
		log.Info("Dropped a scan request: no pod runs the digest")
		r.Queue.done(req.Digest)
		return ctrl.Result{}, nil
	}
	pod, repository := pullSource(pods, req)
	config, err := r.Credentials.DockerConfig(ctx, pod, repository)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("build the credentials to pull %s with pod %s/%s: %w",
			repository, pod.Namespace, pod.Name, err)
	}
	platforms, err := scanPlatforms(ctx, r.APIReader, pods)
	if err != nil {
		return ctrl.Result{}, err
	}

	job := newJob(jobSpec{
		name:            jobName(req.Digest),
		namespace:       r.OperatorNamespace,
		call:            scanCall{digest: req.Digest, image: repository + "@" + req.Digest, platforms: platforms},
		scannerImage:    r.ScannerImage,
		settings:        settings,
		proxyEnv:        r.ProxyEnv,
		registryMirrors: r.RegistryMirrors,
	})
	if err := r.Client.Create(ctx, job); err != nil {
		return ctrl.Result{}, fmt.Errorf("create scan Job %s: %w", job.Name, err)
	}
	// The Secret comes after the Job, which owns it. Without it, the Job's pod would wait for its
	// credentials until the deadline, so the Job goes, and the request is tried again.
	if err := r.Client.Create(ctx, newSecret(job, config)); err != nil {
		created := fmt.Errorf("create the Secret of scan Job %s: %w", job.Name, err)
		return ctrl.Result{}, errors.Join(created, r.deleteJob(ctx, job))
	}
	r.Queue.done(req.Digest)
	log.Info("Started a scan", "job", job.Name, "repository", repository, "platforms", platforms)
	return ctrl.Result{}, nil
}

// slotWait returns how long a request waits while every slot is taken.
func (r *Runner) slotWait() time.Duration {
	if r.SlotWait > 0 {
		return r.SlotWait
	}
	return defaultSlotWait
}

// follow does nothing while job runs, and once it has finished, records what it found, deletes it,
// and reports the outcome as the health of the Scanner.
func (r *Runner) follow(ctx context.Context, digest string, job *batchv1.Job) error {
	rec, recorded := r.recordedOf(job.UID)
	if !recorded {
		outcome, finished, err := r.outcomeOf(ctx, digest, job)
		if err != nil || !finished {
			return err
		}
		if outcome, err = r.record(ctx, digest, job, outcome); err != nil {
			return err
		}
		rec = recordedScan{failure: failureOf(digest, outcome)}
		r.remember(job.UID, rec)
	}
	if err := r.deleteJob(ctx, job); err != nil {
		return err
	}
	r.forget(job.UID)
	// A request that came while the digest was scanned is answered by this scan.
	r.Queue.done(digest)
	if rec.failure != nil {
		r.Registry.ReportFailure(configv1alpha1.CollectorTypeScanner, rec.failure)
	} else {
		r.Registry.ReportSuccess(configv1alpha1.CollectorTypeScanner)
	}
	return nil
}

// outcomeOf returns what job found, and reports whether it has finished:
//   - a Job past its deadline timed out, whatever its pod printed
//   - the log of a pod that succeeded holds the result, which must pass every check
//   - the log of a pod that failed holds why, in its error line
//   - a Job that finished without such a pod failed for a reason of its own
func (r *Runner) outcomeOf(ctx context.Context, digest string, job *batchv1.Job) (scanOutcome, bool, error) {
	call, _, ok := scanOf(job, digest)
	if !ok {
		return failedWith(inventoryv1alpha1.ScanFailureReasonInternal, "the Job doesn't say what it scans"), true, nil
	}
	if pastDeadline(job) {
		return failedWith(inventoryv1alpha1.ScanFailureReasonTimedOut, "the Job ran past its deadline"), true, nil
	}
	pod, err := r.finishedPod(ctx, job)
	if err != nil {
		return scanOutcome{}, false, err
	}
	if pod == nil {
		if jobFinished(job) {
			return failedWith(inventoryv1alpha1.ScanFailureReasonInternal, "the Job finished without a pod to read"), true, nil
		}
		return scanOutcome{}, false, nil
	}
	log, err := r.Logs.ScanLog(ctx, pod.Namespace, pod.Name)
	if err != nil {
		return scanOutcome{}, false, err
	}
	if pod.Status.Phase == corev1.PodSucceeded {
		return succeededScan(log, call), true, nil
	}
	return failedScan(log), true, nil
}

// record stores what a finished scan of digest found, and returns its outcome: on success, the
// evidence of each manifest, then the facts. Evidence that an ImagePackages can't hold fails the
// scan as TooLarge. On failure, the facts keep the platforms of the last successful scan, and count
// the failure. A digest that is gone gets nothing more: facts never bring an ImageInventory back.
func (r *Runner) record(ctx context.Context, digest string, job *batchv1.Job, outcome scanOutcome) (scanOutcome, error) {
	log := logf.FromContext(ctx).WithValues("digest", digest, "job", job.Name)
	_, scannerImage, _ := scanOf(job, digest)
	now := time.Now()
	if outcome.result != nil {
		tooLarge, err := r.storeEvidence(ctx, scannerImage, now, outcome.result.Manifests)
		if err != nil {
			return scanOutcome{}, err
		}
		if !tooLarge {
			found, err := r.Store.SetFacts(ctx, digest, successFacts(scannerImage, now, outcome.result.Manifests))
			if err != nil {
				return scanOutcome{}, err
			}
			if found {
				log.Info("Stored what a scan found", "manifests", len(outcome.result.Manifests))
			} else {
				log.Info("Dropped what a scan found: the digest is gone")
			}
			return outcome, nil
		}
		outcome = failedWith(inventoryv1alpha1.ScanFailureReasonTooLarge, "the evidence of a manifest is more than an ImagePackages holds")
	}

	log.Info("A scan failed", "reason", outcome.reason, "cause", outcome.why)
	earlier, err := r.Store.Get(ctx, digest)
	if err != nil {
		return scanOutcome{}, err
	}
	if earlier == nil {
		log.Info("Dropped the failure of a scan: the digest is gone")
		return outcome, nil
	}
	if _, err := r.Store.SetFacts(ctx, digest, failureFacts(earlier.Status.Facts, outcome.reason, now)); err != nil {
		return scanOutcome{}, err
	}
	return outcome, nil
}

// storeEvidence stores the evidence of each manifest, made by scannerImage at the time scanned. It
// reports true, and stores no more, at the first manifest whose evidence is more than an
// ImagePackages holds. The evidence stored before it stays: no digest's facts refer to it, and
// evidence that nothing refers to is removed.
func (r *Runner) storeEvidence(ctx context.Context, scannerImage string, scanned time.Time,
	manifests []result.Manifest) (tooLarge bool, err error) {
	for _, m := range manifests {
		err := r.Packages.Put(ctx, scannerImage, scanned, m)
		switch {
		case errors.Is(err, inventory.ErrEvidenceTooLarge):
			return true, nil
		case err != nil:
			return false, fmt.Errorf("store the evidence of manifest %s: %w", m.Digest, err)
		}
	}
	return false, nil
}

// successFacts returns the facts of a scan by scannerImage that finished at the time scanned and
// found manifests: one platform for each, sorted, and no failure.
func successFacts(scannerImage string, scanned time.Time, manifests []result.Manifest) *inventoryv1alpha1.ImageFacts {
	platforms := make([]inventoryv1alpha1.PlatformFacts, 0, len(manifests))
	for _, m := range manifests {
		platforms = append(platforms, inventoryv1alpha1.PlatformFacts{
			Platform:            m.Platform,
			ManifestDigest:      m.Digest,
			CompletenessPercent: ptr.To(m.Completeness()),
			// The checks of the result keep the count within an int32.
			ELFFiles: ptr.To(int32(m.ELF.Total)),
			Packages: ptr.To(int32(len(m.Packages))),
		})
	}
	slices.SortFunc(platforms, func(a, b inventoryv1alpha1.PlatformFacts) int { return cmp.Compare(a.Platform, b.Platform) })
	return &inventoryv1alpha1.ImageFacts{
		ScannerImage: ptr.To(scannerImage),
		ScannedTime:  ptr.To(metav1.NewTime(scanned)),
		Platforms:    platforms,
	}
}

// failureFacts returns the facts of a scan that failed for reason at the time failed: the facts of
// the last successful scan stay, and the failure counts one attempt more than the last one did.
func failureFacts(earlier *inventoryv1alpha1.ImageFacts, reason inventoryv1alpha1.ScanFailureReason,
	failed time.Time) *inventoryv1alpha1.ImageFacts {
	facts := earlier.DeepCopy()
	if facts == nil {
		facts = &inventoryv1alpha1.ImageFacts{}
	}
	attempts := int32(1)
	if earlier != nil && earlier.Failure != nil {
		attempts = earlier.Failure.Attempts
		if attempts < math.MaxInt32 {
			attempts++
		}
	}
	facts.Failure = &inventoryv1alpha1.ScanFailure{Reason: reason, Time: ptr.To(metav1.NewTime(failed)), Attempts: attempts}
	return facts
}

// failureOf returns what the Scanner reports for the outcome of a scan of digest: nil for a
// success, and the reason of a failure.
func failureOf(digest string, outcome scanOutcome) error {
	if outcome.result != nil {
		return nil
	}
	return fmt.Errorf("the scan of %s failed: %s", digest, outcome.reason)
}

// pastDeadline reports whether job ran past its activeDeadlineSeconds. The Job controller marks such
// a Job FailureTarget, then Failed once its pod is gone, both with the reason DeadlineExceeded.
func pastDeadline(job *batchv1.Job) bool {
	return slices.ContainsFunc(job.Status.Conditions, func(c batchv1.JobCondition) bool {
		return (c.Type == batchv1.JobFailed || c.Type == batchv1.JobFailureTarget) &&
			c.Status == corev1.ConditionTrue && c.Reason == batchv1.JobReasonDeadlineExceeded
	})
}

// jobFinished reports whether job has finished: it is Complete or Failed.
func jobFinished(job *batchv1.Job) bool {
	return slices.ContainsFunc(job.Status.Conditions, func(c batchv1.JobCondition) bool {
		return (c.Type == batchv1.JobComplete || c.Type == batchv1.JobFailed) && c.Status == corev1.ConditionTrue
	})
}

// finishedPod returns the pod of job that has finished, or nil while none has. A pod that succeeded
// comes before one that failed, since only its log holds a result. The pods come from the manager's
// cache, which holds every pod.
func (r *Runner) finishedPod(ctx context.Context, job *batchv1.Job) (*corev1.Pod, error) {
	var pods corev1.PodList
	if err := r.Client.List(ctx, &pods, client.InNamespace(job.Namespace),
		client.MatchingLabels{DigestLabel: job.Labels[DigestLabel]}); err != nil {
		return nil, fmt.Errorf("list the pods of scan Job %s: %w", job.Name, err)
	}
	var failed *corev1.Pod
	for i := range pods.Items {
		pod := &pods.Items[i]
		if !metav1.IsControlledBy(pod, job) {
			continue
		}
		switch pod.Status.Phase {
		case corev1.PodSucceeded:
			return pod, nil
		case corev1.PodFailed:
			failed = pod
		}
	}
	return failed, nil
}

// scanJobs lists the scan Jobs in the operator's namespace that carry labels, from the API server.
func (r *Runner) scanJobs(ctx context.Context, labels map[string]string) ([]batchv1.Job, error) {
	var list batchv1.JobList
	if err := r.APIReader.List(ctx, &list, client.InNamespace(r.OperatorNamespace), client.MatchingLabels(labels)); err != nil {
		return nil, fmt.Errorf("list the scan Jobs: %w", err)
	}
	return list.Items, nil
}

// activeScans counts the scan Jobs that hold a slot: those that haven't finished, and aren't being
// deleted.
func (r *Runner) activeScans(ctx context.Context) (int, error) {
	jobs, err := r.scanJobs(ctx, map[string]string{workloads.TaskLabel: scanTask})
	if err != nil {
		return 0, err
	}
	active := 0
	for i := range jobs {
		if jobs[i].DeletionTimestamp == nil && !jobFinished(&jobs[i]) {
			active++
		}
	}
	return active, nil
}

// podsRunning lists the pods that report digest, through the pod index of the manager's cache, which
// leaves out the operator's task pods.
func (r *Runner) podsRunning(ctx context.Context, digest string) ([]corev1.Pod, error) {
	var pods corev1.PodList
	if err := r.Client.List(ctx, &pods, client.MatchingFields{workloads.PodDigestIndex: digest}); err != nil {
		return nil, fmt.Errorf("list the pods that run %s: %w", digest, err)
	}
	return pods.Items, nil
}

// pullSource picks the pod whose credentials pull the image of req, and the repository to pull it
// from, one of the request's: those are what the presence entries took from the pods. A pod that
// pulled the digest from one of them comes first, with that repository, since its pull secrets are
// for that registry. Otherwise the first pod pulls from the request's first repository. The pods
// are taken in the order of their namespaces and names, so that the pick stays the same.
func pullSource(pods []corev1.Pod, req tasks.ScanRequest) (*corev1.Pod, string) {
	slices.SortFunc(pods, func(a, b corev1.Pod) int {
		return cmp.Or(cmp.Compare(a.Namespace, b.Namespace), cmp.Compare(a.Name, b.Name))
	})
	for i := range pods {
		images, _ := workloads.PodImages(&pods[i])
		for _, image := range images {
			if image.Digest == req.Digest && slices.Contains(req.Repositories, image.Repository) {
				return &pods[i], image.Repository
			}
		}
	}
	return &pods[0], req.Repositories[0]
}

// deleteJob deletes job, and lets the garbage collector delete its pod and its Secret.
func (r *Runner) deleteJob(ctx context.Context, job *batchv1.Job) error {
	err := r.Client.Delete(ctx, job, client.PropagationPolicy(metav1.DeletePropagationBackground))
	if client.IgnoreNotFound(err) != nil {
		return fmt.Errorf("delete scan Job %s: %w", job.Name, err)
	}
	return nil
}

// recordedOf returns the outcome of the Job with uid, if its facts are written.
func (r *Runner) recordedOf(uid types.UID) (recordedScan, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rec, ok := r.recorded[uid]
	return rec, ok
}

// remember keeps the outcome of the Job with uid, whose facts are written, until the Job is deleted.
func (r *Runner) remember(uid types.UID, rec recordedScan) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.recorded == nil {
		r.recorded = map[types.UID]recordedScan{}
	}
	r.recorded[uid] = rec
}

// forget drops the outcome of the Job with uid, which is deleted.
func (r *Runner) forget(uid types.UID) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.recorded, uid)
}

// SetupWithManager sets up the runner with the Manager. With no scanner image, it reports at once
// that the Scanner can't scan.
func (r *Runner) SetupWithManager(mgr ctrl.Manager) error {
	if r.ScannerImage == "" {
		r.Registry.ReportFailure(configv1alpha1.CollectorTypeScanner, ErrNoScannerImage)
	}
	scanTasks := builder.WithPredicates(predicate.NewPredicateFuncs(r.isScanTask))
	return ctrl.NewControllerManagedBy(mgr).
		Named("scan").
		// One reconcile at a time: the count of the running scans and the creation of the next Job
		// must not interleave with another's, or two requests could take the last slot.
		WithOptions(controller.Options{MaxConcurrentReconciles: 1}).
		WatchesRawSource(source.Func(r.Queue.start)).
		// A scan pod's phase says when its scan has finished. The pods come through the informer of
		// the pod inventory, which holds every pod.
		Watches(&corev1.Pod{}, handler.EnqueueRequestsFromMapFunc(r.digestOf), scanTasks).
		// A Job's status says when it ran past its deadline, which may come after its pod is gone, and
		// a Job whose pod is never created has no other event. The metadata changes with the status,
		// so the informer of the pod inventory, which holds the metadata of every Job, tells.
		Watches(&batchv1.Job{}, handler.EnqueueRequestsFromMapFunc(r.digestOf), builder.OnlyMetadata, scanTasks).
		Complete(r)
}

// isScanTask reports whether obj is a scan task of the operator: a scan Job or a scan pod in the
// operator's namespace.
func (r *Runner) isScanTask(obj client.Object) bool {
	return obj.GetNamespace() == r.OperatorNamespace && obj.GetLabels()[workloads.TaskLabel] == scanTask
}

// digestOf maps a scan Job, or a scan pod, to the digest that its annotation names.
func (r *Runner) digestOf(_ context.Context, obj client.Object) []reconcile.Request {
	digest := obj.GetAnnotations()[DigestLabel]
	if !digestPattern.MatchString(digest) {
		return nil
	}
	return []reconcile.Request{requestFor(digest)}
}
