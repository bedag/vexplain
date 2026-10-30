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

package scan_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/collector"
	"github.com/bedag/vexplain/internal/controller/scan"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/scan/result"
	"github.com/bedag/vexplain/internal/setup"
	"github.com/bedag/vexplain/internal/tasks"
	"github.com/bedag/vexplain/internal/workloads"
)

// These tests call Reconcile directly, against a fake client, for the paths that envtest can't
// reach on demand: a runner without a scanner image, API errors at a given write, a cache that lags
// the API server, logs that can't be read, and the wait for a free slot at its default length.

const (
	// runnerNamespace is the operator's namespace, where the scan Jobs run.
	runnerNamespace = "vexplain-system"
	// unitScannerImage is the scanner image of the runner under test.
	unitScannerImage = "scanner.example/vexplain-scanner:1.0"
	// unitRepository is where the workloads of the tests pull their image from.
	unitRepository = "artifacts.example/team-a/app"
	// unitDigest is the digest that the tests scan.
	unitDigest = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	// unitPlatform is the platform of the node that runs the tests' workload, and of their scans.
	unitPlatform = "linux/amd64"
)

// unitLogs are the logs of the scan pods, and the errors of reading them, by pod name. A pod that has
// neither has a log that can't be read for now.
type unitLogs struct {
	logs   map[string]string
	errors map[string]error
	// reads counts the reads, by pod name.
	reads map[string]int
}

func (l *unitLogs) ScanLog(_ context.Context, _, pod string) (string, error) {
	l.reads[pod]++
	if err, ok := l.errors[pod]; ok {
		return "", err
	}
	log, ok := l.logs[pod]
	if !ok {
		return "", errors.New("the kubelet can't be reached")
	}
	return log, nil
}

// set makes pod print log.
func (l *unitLogs) set(pod, log string) {
	l.logs[pod] = log
}

// fail makes the read of the log of pod fail with err.
func (l *unitLogs) fail(pod string, err error) {
	l.errors[pod] = err
}

// unitCredentials gives every scan the same config.json.
type unitCredentials struct{}

func (unitCredentials) DockerConfig(context.Context, *corev1.Pod, string) ([]byte, error) {
	return []byte(`{"auths":{}}`), nil
}

// unitFixture is a runner over a fake client, and what it reports into.
type unitFixture struct {
	runner *scan.Runner
	// client reads and writes the objects as the API server holds them.
	client   client.Client
	registry *collector.Registry
	queue    *scan.Queue
	logs     *unitLogs
}

// newUnitFixture returns a runner over a fake client that holds a node and objs. The runner's
// client, which stands for the manager's, passes every call through funcs; its API reader reads
// the objects as they are, as the API server would.
func newUnitFixture(t *testing.T, funcs interceptor.Funcs, objs ...client.Object) *unitFixture {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, setup.AddToScheme(scheme))
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: amd64Node, Labels: map[string]string{
		corev1.LabelOSStable: "linux", corev1.LabelArchStable: "amd64",
	}}}
	api := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(append(objs, node)...).
		WithStatusSubresource(&inventoryv1alpha1.ImageInventory{}, &batchv1.Job{}, &corev1.Pod{}).
		WithIndex(&corev1.Pod{}, workloads.PodDigestIndex, workloads.PodDigestIndexer(runnerNamespace)).
		Build()
	c := interceptor.NewClient(api, funcs)
	cluster := func() string { return "local" }
	f := &unitFixture{client: api, registry: collector.NewRegistry(), queue: scan.NewQueue(), logs: &unitLogs{
		logs: map[string]string{}, errors: map[string]error{}, reads: map[string]int{},
	}}
	f.runner = &scan.Runner{
		Client:            c,
		APIReader:         api,
		Store:             inventory.NewCRDStore(c, nil, cluster),
		Packages:          inventory.NewCRDPackagesStore(c, nil, cluster),
		Registry:          f.registry,
		Queue:             f.queue,
		Logs:              f.logs,
		Credentials:       unitCredentials{},
		OperatorNamespace: runnerNamespace,
		ScannerImage:      unitScannerImage,
	}
	return f
}

// reconcile reconciles unitDigest once.
func (f *unitFixture) reconcile(t *testing.T) (ctrl.Result, error) {
	t.Helper()
	return f.runner.Reconcile(t.Context(),
		ctrl.Request{NamespacedName: types.NamespacedName{Name: inventory.NameForDigest(unitDigest)}})
}

// request asks the runner's queue to scan unitDigest from unitRepository.
func (f *unitFixture) request(t *testing.T) {
	t.Helper()
	require.NoError(t, f.queue.RequestScan(t.Context(), tasks.ScanRequest{Digest: unitDigest, Repositories: []string{unitRepository}}))
}

// jobs returns the names of the Jobs in the operator's namespace.
func (f *unitFixture) jobs(t *testing.T) []string {
	t.Helper()
	var list batchv1.JobList
	require.NoError(t, f.client.List(t.Context(), &list, client.InNamespace(runnerNamespace)))
	names := make([]string, 0, len(list.Items))
	for _, job := range list.Items {
		names = append(names, job.Name)
	}
	return names
}

// workload returns a running pod that runs unitDigest, pulled from unitRepository.
func workload() *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "team-a", Name: appPod},
		Spec: corev1.PodSpec{NodeName: amd64Node,
			Containers: []corev1.Container{{Name: appContainer, Image: unitRepository + ":1.0"}}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{
			Name: appContainer, Image: unitRepository + ":1.0", ImageID: unitRepository + "@" + unitDigest,
		}}},
	}
}

// presence returns the ImageInventory of unitDigest, as the pod inventory creates it.
func presence() *inventoryv1alpha1.ImageInventory {
	return &inventoryv1alpha1.ImageInventory{
		ObjectMeta: metav1.ObjectMeta{Name: inventory.NameForDigest(unitDigest)},
		Spec:       inventoryv1alpha1.ImageInventorySpec{Digest: unitDigest},
	}
}

// scanJobOf returns a scan Job of digest, as the runner creates it, with a UID, which the fake client
// doesn't give, and its pod, which ended in phase.
func scanJobOf(digest string, phase corev1.PodPhase) (*batchv1.Job, *corev1.Pod) {
	labels := map[string]string{workloads.TaskLabel: scanTask, scan.DigestLabel: strings.TrimPrefix(digest, "sha256:")[:63]}
	annotations := map[string]string{scan.DigestLabel: digest}
	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Namespace: runnerNamespace, Name: "scan-dddddddddddd-x2k4p", UID: "job-uid",
			Labels: labels, Annotations: annotations},
		Spec: batchv1.JobSpec{Template: corev1.PodTemplateSpec{
			ObjectMeta: metav1.ObjectMeta{Labels: labels, Annotations: annotations},
			Spec: corev1.PodSpec{RestartPolicy: corev1.RestartPolicyNever, Containers: []corev1.Container{{
				Name:  scannerContainer,
				Image: unitScannerImage,
				Args:  []string{"--image", unitRepository + "@" + digest, "--platform", unitPlatform, "--work", "/work"},
			}}},
		}},
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: runnerNamespace, Name: job.Name + "-abcde", Labels: labels,
			Annotations: annotations, OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "batch/v1", Kind: "Job", Name: job.Name, UID: job.UID, Controller: ptr.To(true),
			}}},
		Spec: job.Spec.Template.Spec,
		Status: corev1.PodStatus{Phase: phase, ContainerStatuses: []corev1.ContainerStatus{{
			Name: scannerContainer, Image: unitScannerImage, State: scannerState(phase),
		}}},
	}
	return job, pod
}

// The Scanner can't scan without a scanner image, so the runner drops what it is asked, rather than
// keep it for a scanner image that only a restart can bring. The suite's specs check that the
// Scanner says why from the start.
func TestRunnerWithoutAScannerImageDropsEveryRequest(t *testing.T) {
	f := newUnitFixture(t, interceptor.Funcs{}, workload())
	f.runner.ScannerImage = ""
	f.request(t)

	res, err := f.reconcile(t)

	require.NoError(t, err)
	require.Equal(t, ctrl.Result{}, res)
	require.Empty(t, f.jobs(t))
	f.runner.ScannerImage = unitScannerImage
	_, err = f.reconcile(t)
	require.NoError(t, err)
	require.Empty(t, f.jobs(t), "the request was dropped, not kept for later")

	f.request(t)
	_, err = f.reconcile(t)
	require.NoError(t, err)
	require.Len(t, f.jobs(t), 1, "a new request, with a scanner image, starts a scan")
}

// A digest that no pod runs any more runs nowhere in this cluster: there is nothing to scan it for,
// and no pull secret to scan it with, so the request is dropped.
func TestRunnerDropsARequestForADigestThatNoPodRuns(t *testing.T) {
	f := newUnitFixture(t, interceptor.Funcs{})
	f.request(t)

	_, err := f.reconcile(t)
	require.NoError(t, err)
	require.Empty(t, f.jobs(t))

	require.NoError(t, f.client.Create(t.Context(), workload()))
	_, err = f.reconcile(t)
	require.NoError(t, err)
	require.Empty(t, f.jobs(t), "the request was dropped, not kept for later")

	f.request(t)
	_, err = f.reconcile(t)
	require.NoError(t, err)
	require.Len(t, f.jobs(t), 1, "a new request, once a pod runs the digest, starts a scan")
}

// A Job without its Secret has no credentials, so its pod would wait for them until its deadline. The
// runner deletes the Job, and keeps the request to try again.
func TestRunnerDeletesTheJobWhenItsSecretCannotBeCreated(t *testing.T) {
	secretFailures := 1
	f := newUnitFixture(t, interceptor.Funcs{
		Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			if _, ok := obj.(*corev1.Secret); ok && secretFailures > 0 {
				secretFailures--
				return apierrors.NewForbidden(schema.GroupResource{Resource: "secrets"}, obj.GetName(), errors.New("denied"))
			}
			return c.Create(ctx, obj, opts...)
		},
	}, workload())
	f.request(t)

	_, err := f.reconcile(t)
	require.Error(t, err)
	require.Empty(t, f.jobs(t), "the Job without its Secret is gone")
	_, lastErr, _ := f.registry.Health(configv1alpha1.CollectorTypeScanner)
	require.Error(t, lastErr, "a scan that can't start makes the Scanner unhealthy")

	_, err = f.reconcile(t)
	require.NoError(t, err)
	jobs := f.jobs(t)
	require.Len(t, jobs, 1, "the request was kept, and the retry starts the scan")
	var secret corev1.Secret
	require.NoError(t, f.client.Get(t.Context(), client.ObjectKey{Namespace: runnerNamespace, Name: jobs[0]}, &secret))
}

// A failed scan counts once, even when the Job that ran it can't be deleted at the first try: the
// retry deletes the Job without counting the failure again.
func TestRunnerCountsAFailedScanOnceWhenItsJobOutlivesAWrite(t *testing.T) {
	jobFailures := 1
	job, pod := scanJobOf(unitDigest, corev1.PodFailed)
	f := newUnitFixture(t, interceptor.Funcs{
		Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			if _, ok := obj.(*batchv1.Job); ok && jobFailures > 0 {
				jobFailures--
				return apierrors.NewServiceUnavailable("the API server is busy")
			}
			return c.Delete(ctx, obj, opts...)
		},
	}, presence(), job, pod)
	f.logs.set(pod.Name, "scanner: resolving the image\n"+result.EncodeError(result.ErrorReasonUnauthorized)+"\n")

	_, err := f.reconcile(t)
	require.Error(t, err)
	_, err = f.reconcile(t)
	require.NoError(t, err)

	require.Empty(t, f.jobs(t))
	var stored inventoryv1alpha1.ImageInventory
	require.NoError(t, f.client.Get(t.Context(), client.ObjectKey{Name: inventory.NameForDigest(unitDigest)}, &stored))
	require.NotNil(t, stored.Status.Facts)
	require.NotNil(t, stored.Status.Facts.Failure)
	require.Equal(t, inventoryv1alpha1.ScanFailureReasonUnauthorized, stored.Status.Facts.Failure.Reason)
	require.Equal(t, int32(1), stored.Status.Facts.Failure.Attempts)
	_, lastErr, _ := f.registry.Health(configv1alpha1.CollectorTypeScanner)
	require.ErrorContains(t, lastErr, "Unauthorized", "the Scanner reports the scan's failure once the Job is gone")
}

// While every slot is taken, a request waits 30 seconds before it asks again, unless the runner
// says otherwise.
func TestRunnerWaitsForAFreeSlot(t *testing.T) {
	busy, _ := scanJobOf("sha256:"+strings.Repeat("e", 64), corev1.PodRunning)
	scanner := &configv1alpha1.Collector{
		ObjectMeta: metav1.ObjectMeta{Name: scannerCollector},
		Spec: configv1alpha1.CollectorSpec{Type: configv1alpha1.CollectorTypeScanner,
			Scanner: &configv1alpha1.ScannerCollectorSpec{MaxConcurrentScans: ptr.To(int32(1))}},
	}
	f := newUnitFixture(t, interceptor.Funcs{}, workload(), busy, scanner)
	f.request(t)

	res, err := f.reconcile(t)
	require.NoError(t, err)
	require.Equal(t, ctrl.Result{RequeueAfter: 30 * time.Second}, res)
	require.Equal(t, []string{busy.Name}, f.jobs(t))

	f.runner.SlotWait = time.Second
	res, err = f.reconcile(t)
	require.NoError(t, err)
	require.Equal(t, ctrl.Result{RequeueAfter: time.Second}, res)
}

// failingCredentials can't build any credentials, as when the API server refuses to give the pull
// secrets.
type failingCredentials struct{}

func (failingCredentials) DockerConfig(context.Context, *corev1.Pod, string) ([]byte, error) {
	return nil, errors.New("the pull secrets can't be read")
}

// failureOf returns the failure in the facts of unitDigest, or nil when there is none.
func (f *unitFixture) failureOf(t *testing.T) *inventoryv1alpha1.ScanFailure {
	t.Helper()
	var stored inventoryv1alpha1.ImageInventory
	require.NoError(t, f.client.Get(t.Context(), client.ObjectKey{Name: inventory.NameForDigest(unitDigest)}, &stored))
	if stored.Status.Facts == nil {
		return nil
	}
	return stored.Status.Facts.Failure
}

// atDeadline marks job as the Job controller does when it runs past its deadline.
func atDeadline(job *batchv1.Job) {
	now := metav1.Now()
	job.Status = batchv1.JobStatus{StartTime: &now, Conditions: []batchv1.JobCondition{{
		Type: batchv1.JobFailureTarget, Status: corev1.ConditionTrue, Reason: batchv1.JobReasonDeadlineExceeded,
	}}}
}

// A Job past its deadline timed out, whatever its pod printed: a pod that succeeded at the deadline
// delivers nothing.
func TestRunnerTimesOutAJobPastItsDeadlineWhateverItsPodPrinted(t *testing.T) {
	job, pod := scanJobOf(unitDigest, corev1.PodSucceeded)
	atDeadline(job)
	f := newUnitFixture(t, interceptor.Funcs{}, presence(), job, pod)
	manifest := result.Manifest{
		Platform: unitPlatform,
		Digest:   "sha256:" + strings.Repeat("1", 64),
		SBOM:     []byte(`{"artifacts":[]}`),
	}
	line, err := result.Encode(result.Result{Image: unitRepository + "@" + unitDigest, Manifests: []result.Manifest{manifest}})
	require.NoError(t, err)
	f.logs.set(pod.Name, line+"\n")

	_, err = f.reconcile(t)

	require.NoError(t, err)
	require.Empty(t, f.jobs(t))
	failure := f.failureOf(t)
	require.NotNil(t, failure)
	require.Equal(t, inventoryv1alpha1.ScanFailureReasonTimedOut, failure.Reason)
	var evidence inventoryv1alpha1.ImagePackages
	err = f.client.Get(t.Context(), client.ObjectKey{Name: inventory.NameForDigest(manifest.Digest)}, &evidence)
	require.True(t, apierrors.IsNotFound(err), "nothing of the pod's result is stored: %v", err)
}

// A Job that finished without a pod whose log can be read, as when someone deleted the pod, can't
// say what it found.
func TestRunnerFailsAJobThatFinishedWithoutAPod(t *testing.T) {
	job, _ := scanJobOf(unitDigest, corev1.PodSucceeded)
	now := metav1.Now()
	job.Status = batchv1.JobStatus{StartTime: &now, CompletionTime: &now, Conditions: []batchv1.JobCondition{
		{Type: batchv1.JobSuccessCriteriaMet, Status: corev1.ConditionTrue},
		{Type: batchv1.JobComplete, Status: corev1.ConditionTrue},
	}}
	f := newUnitFixture(t, interceptor.Funcs{}, presence(), job)

	_, err := f.reconcile(t)

	require.NoError(t, err)
	require.Empty(t, f.jobs(t))
	require.Equal(t, inventoryv1alpha1.ScanFailureReasonInternal, f.failureOf(t).Reason)
}

// A scan Job of the digest whose arguments scan another image can't vouch for what it found.
func TestRunnerFailsAJobThatScansAnotherDigest(t *testing.T) {
	job, pod := scanJobOf(unitDigest, corev1.PodSucceeded)
	job.Spec.Template.Spec.Containers[0].Args[1] = unitRepository + "@sha256:" + strings.Repeat("e", 64)
	f := newUnitFixture(t, interceptor.Funcs{}, presence(), job, pod)

	_, err := f.reconcile(t)

	require.NoError(t, err)
	require.Empty(t, f.jobs(t))
	require.Equal(t, inventoryv1alpha1.ScanFailureReasonInternal, f.failureOf(t).Reason)
}

// The failure of a scan of a digest that is gone is no fact of any digest: nothing brings its
// ImageInventory back. The Job goes all the same, and the Scanner reports the failure.
func TestRunnerWritesNoFailureForADigestThatIsGone(t *testing.T) {
	job, pod := scanJobOf(unitDigest, corev1.PodFailed)
	f := newUnitFixture(t, interceptor.Funcs{}, job, pod)
	f.logs.set(pod.Name, result.EncodeError(result.ErrorReasonNotFound)+"\n")

	_, err := f.reconcile(t)

	require.NoError(t, err)
	require.Empty(t, f.jobs(t))
	var list inventoryv1alpha1.ImageInventoryList
	require.NoError(t, f.client.List(t.Context(), &list))
	require.Empty(t, list.Items)
	_, lastErr, _ := f.registry.Health(configv1alpha1.CollectorTypeScanner)
	require.ErrorContains(t, lastErr, "NotFound")
}

// Without credentials there is no scan Job, and the request waits for the next try.
func TestRunnerKeepsTheRequestWhenItsCredentialsCannotBeBuilt(t *testing.T) {
	f := newUnitFixture(t, interceptor.Funcs{}, workload())
	f.runner.Credentials = failingCredentials{}
	f.request(t)

	_, err := f.reconcile(t)
	require.ErrorContains(t, err, "the pull secrets can't be read")
	require.Empty(t, f.jobs(t))

	f.runner.Credentials = unitCredentials{}
	_, err = f.reconcile(t)
	require.NoError(t, err)
	require.Len(t, f.jobs(t), 1)
}

// laggingCache makes the runner's client, which reads pods from the manager's cache, see the scan
// pods as still running, as an informer that lags behind the API server does.
func laggingCache() interceptor.Funcs {
	return interceptor.Funcs{
		List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			if err := c.List(ctx, list, opts...); err != nil {
				return err
			}
			if pods, ok := list.(*corev1.PodList); ok {
				for i := range pods.Items {
					pods.Items[i].Status.Phase = corev1.PodRunning
					pods.Items[i].Status.ContainerStatuses[0].State = scannerState(corev1.PodRunning)
				}
			}
			return nil
		},
	}
}

// completed marks job as the Job controller does once its pod has succeeded.
func completed(job *batchv1.Job) {
	now := metav1.Now()
	job.Status = batchv1.JobStatus{StartTime: &now, CompletionTime: &now, Succeeded: 1, Conditions: []batchv1.JobCondition{
		{Type: batchv1.JobSuccessCriteriaMet, Status: corev1.ConditionTrue},
		{Type: batchv1.JobComplete, Status: corev1.ConditionTrue},
	}}
}

// The Job controller marks a Job Complete once it has seen its pod succeed, while the manager's cache
// may still hold that pod as running. A Job that the runner read from the API server is never
// compared with pods older than it, so the result of the scan is stored, and the Job isn't taken
// for one that finished without a pod.
func TestRunnerComparesAJobWithPodsNoOlderThanIt(t *testing.T) {
	job, pod := scanJobOf(unitDigest, corev1.PodSucceeded)
	completed(job)
	f := newUnitFixture(t, laggingCache(), presence(), job, pod)
	manifest := result.Manifest{
		Platform: unitPlatform,
		Digest:   "sha256:" + strings.Repeat("1", 64),
		SBOM:     []byte(`{"artifacts":[]}`),
	}
	line, err := result.Encode(result.Result{Image: unitRepository + "@" + unitDigest, Manifests: []result.Manifest{manifest}})
	require.NoError(t, err)
	f.logs.set(pod.Name, line+"\n")

	_, err = f.reconcile(t)

	require.NoError(t, err)
	require.Empty(t, f.jobs(t))
	require.Nil(t, f.failureOf(t))
	var evidence inventoryv1alpha1.ImagePackages
	require.NoError(t, f.client.Get(t.Context(), client.ObjectKey{Name: inventory.NameForDigest(manifest.Digest)}, &evidence))
	lastSuccess, lastErr, _ := f.registry.Health(configv1alpha1.CollectorTypeScanner)
	require.NoError(t, lastErr)
	require.False(t, lastSuccess.IsZero())
}

// A pod that failed before its container ran has no log, so it has no error line: the scan failed
// for a reason of its own, Internal. The failure is recorded and the Job goes, without waiting for
// a log that will never come.
func TestRunnerFailsAPodWhoseContainerNeverRan(t *testing.T) {
	cases := []struct {
		name   string
		status corev1.PodStatus
	}{
		{"a pod that the kubelet refused", corev1.PodStatus{Phase: corev1.PodFailed, Reason: "OutOfmemory",
			Message: "Pod was rejected: Node didn't have enough resource: memory"}},
		{"a container that never started", corev1.PodStatus{Phase: corev1.PodFailed, Reason: "Terminated",
			Message: "Pod was terminated in response to imminent node shutdown.",
			ContainerStatuses: []corev1.ContainerStatus{{Name: scannerContainer, Image: unitScannerImage,
				State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "ContainerCreating"}}}}}},
		{"a container that the kubelet lost", corev1.PodStatus{Phase: corev1.PodFailed,
			ContainerStatuses: []corev1.ContainerStatus{{Name: scannerContainer, Image: unitScannerImage,
				State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{
					ExitCode: 137, Reason: "ContainerStatusUnknown"}}}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			job, pod := scanJobOf(unitDigest, corev1.PodFailed)
			pod.Status = tc.status
			f := newUnitFixture(t, interceptor.Funcs{}, presence(), job, pod)

			_, err := f.reconcile(t)

			require.NoError(t, err)
			require.Empty(t, f.jobs(t))
			require.Equal(t, inventoryv1alpha1.ScanFailureReasonInternal, f.failureOf(t).Reason)
			require.Zero(t, f.logs.reads[pod.Name], "a container that never ran has no log to read")
		})
	}
}

// A container that ran, but whose log is gone, as after its node restarted, leaves no line either.
// The API server answers such a read with Bad Request, which no retry changes, so the scan failed
// as Internal, whatever the phase of its pod.
func TestRunnerFailsAPodWhoseLogIsGone(t *testing.T) {
	for _, phase := range []corev1.PodPhase{corev1.PodFailed, corev1.PodSucceeded} {
		t.Run(string(phase), func(t *testing.T) {
			job, pod := scanJobOf(unitDigest, phase)
			f := newUnitFixture(t, interceptor.Funcs{}, presence(), job, pod)
			f.logs.fail(pod.Name, apierrors.NewBadRequest(`container "scanner" in pod "`+pod.Name+`" is terminated`))

			_, err := f.reconcile(t)

			require.NoError(t, err)
			require.Empty(t, f.jobs(t))
			require.Equal(t, inventoryv1alpha1.ScanFailureReasonInternal, f.failureOf(t).Reason)
		})
	}
}

// A log that can't be read for now, as while the API server can't reach the kubelet, is read again
// later: the request is retried, the Job stays, and nothing is recorded yet.
func TestRunnerRetriesALogThatCannotBeReadForNow(t *testing.T) {
	job, pod := scanJobOf(unitDigest, corev1.PodFailed)
	f := newUnitFixture(t, interceptor.Funcs{}, presence(), job, pod)
	f.logs.fail(pod.Name, apierrors.NewServiceUnavailable("the kubelet can't be reached"))

	_, err := f.reconcile(t)

	require.Error(t, err)
	require.Len(t, f.jobs(t), 1)
	require.Nil(t, f.failureOf(t))
}
