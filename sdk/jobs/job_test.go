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

package jobs_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/bedag/vexplain/sdk/jobs"
	"github.com/bedag/vexplain/sdk/podtemplate"
)

// The tests run Jobs against an API server of envtest, which validates them as a cluster does. envtest runs no Job
// controller and no kubelet, so a test makes the pod of a Job itself, and writes its status and its log, as the Job
// controller and the kubelet would.

const (
	// wait bounds how long a test waits for what must happen, and tick is how often it looks.
	wait = 30 * time.Second
	tick = 20 * time.Millisecond
	// The Job of most tests: what it runs, and the prefixes of its lines.
	workerImage  = "artifacts.example/collectors/example:0.1.0"
	container    = "worker"
	resultPrefix = "example-result v1 "
	errorPrefix  = "example-error v1 "
	// taskLabel marks vexplain's own pods, and task is the value that the Jobs of the tests give it.
	taskLabel = "vexplain.bedag.ch/task"
	task      = "example"
	// team is the label that the template of the tests adds, and completed the reason of a Job that completed.
	team      = "team-a"
	completed = "CompletionsReached"
	// resultLine is the line of a Job that succeeded.
	resultLine = resultPrefix + "eyJmb3VuZCI6dHJ1ZX0="
)

// dockerConfigs are the Docker configs of the Job of most tests, each with one login, in the order that its pod tries
// them: the workload's, then one that an admin provides.
var dockerConfigs = [][]byte{
	[]byte(`{"auths":{"artifacts.example":{"username":"team-a-puller","password":"pull-secret-password"}}}`),
	[]byte(`{"auths":{"artifacts.example":{"username":"admin-puller","password":"admin-secret-password"}}}`),
}

// proxyEnv is the proxy of the collector, which its Jobs get.
var proxyEnv = []corev1.EnvVar{{Name: "HTTPS_PROXY", Value: "http://proxy.example:3128"}}

// api is the API server of the tests. It starts when the first test needs it, and TestMain stops it.
var api struct {
	once   sync.Once
	env    *envtest.Environment
	client client.Client
	err    error
}

func TestMain(m *testing.M) {
	code := m.Run()
	if api.env != nil {
		if err := api.env.Stop(); err != nil {
			fmt.Fprintln(os.Stderr, "stopping the API server:", err)
			code = 1
		}
	}
	os.Exit(code)
}

// startAPI returns a client of the API server, which it starts once.
func startAPI(t *testing.T) client.Client {
	t.Helper()
	api.once.Do(func() {
		api.env = &envtest.Environment{BinaryAssetsDirectory: assetsDirectory()}
		cfg, err := api.env.Start()
		if err == nil {
			api.client, err = client.New(cfg, client.Options{})
		}
		api.err = err
	})
	require.NoError(t, api.err,
		"start the API server: KUBEBUILDER_ASSETS names its binaries, which `make setup-envtest` fetches")
	return api.client
}

// assetsDirectory is where the binaries of the API server are when KUBEBUILDER_ASSETS, which `make test` sets, is
// not: the repository's bin/k8s, which `make setup-envtest` fills. The tests then also run from an editor.
func assetsDirectory() string {
	if os.Getenv("KUBEBUILDER_ASSETS") != "" {
		return ""
	}
	root := filepath.Join("..", "..", "bin", "k8s")
	entries, err := os.ReadDir(root)
	if err != nil {
		return ""
	}
	for _, entry := range entries {
		if entry.IsDir() {
			return filepath.Join(root, entry.Name())
		}
	}
	return ""
}

// fixture is a namespace of a test, where its runner runs its Jobs, with the logs of their pods.
type fixture struct {
	t         *testing.T
	client    client.Client
	namespace string
	logs      *podLogs
	runner    *jobs.Runner
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	c := startAPI(t)
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "vexplain-" + rand.String(6)}}
	require.NoError(t, c.Create(t.Context(), ns))
	t.Cleanup(func() { assert.NoError(t, c.Delete(context.Background(), ns)) })
	logs := &podLogs{logs: map[string]string{}}
	runner := jobs.NewRunner(c, logs, ns.Name)
	runner.Poll = tick
	return &fixture{t: t, client: c, namespace: ns.Name, logs: logs, runner: runner}
}

// spec returns the Spec of a Job of the test, named name, with credentials.
func (f *fixture) spec(name string) jobs.Spec {
	return jobs.Spec{
		Name:          name,
		Namespace:     f.namespace,
		Image:         workerImage,
		Container:     container,
		Args:          []string{"scan", "--image", "artifacts.example/team-a/app@sha256:" + strings.Repeat("a", 64)},
		Env:           proxyEnv,
		DockerConfigs: dockerConfigs,
		Workspace:     resource.MustParse("10Gi"),
		Deadline:      30 * time.Minute,
		Template: podtemplate.PodTemplate{
			ImagePullPolicy: corev1.PullAlways,
			Resources: &corev1.ResourceRequirements{
				Limits:   corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("2Gi")},
				Requests: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("2Gi")},
			},
			Labels: map[string]string{"team": team, taskLabel: "overridden"},
		},
		Labels:       map[string]string{taskLabel: task, "vexplain.bedag.ch/subject": "a"},
		ResultPrefix: resultPrefix,
		ErrorPrefix:  errorPrefix,
	}
}

// outcome is what a Run returned.
type outcome struct {
	result jobs.Result
	err    error
}

// start runs s in the background, and returns where its outcome arrives.
func (f *fixture) start(ctx context.Context, s jobs.Spec) <-chan outcome {
	done := make(chan outcome, 1)
	go func() {
		r, err := f.runner.Run(ctx, s)
		done <- outcome{r, err}
	}()
	return done
}

// expectJob waits until the Job of the name exists, and returns it.
func (f *fixture) expectJob(name string) *batchv1.Job {
	f.t.Helper()
	var job batchv1.Job
	require.EventuallyWithT(f.t, func(c *assert.CollectT) {
		assert.NoError(c, f.client.Get(f.t.Context(), client.ObjectKey{Namespace: f.namespace, Name: name}, &job))
	}, wait, tick)
	return &job
}

// expectGone waits until the Job of the name is gone.
func (f *fixture) expectGone(name string) {
	f.t.Helper()
	require.Eventually(f.t, func() bool {
		err := f.client.Get(f.t.Context(), client.ObjectKey{Namespace: f.namespace, Name: name}, &batchv1.Job{})
		return apierrors.IsNotFound(err)
	}, wait, tick, "the Job is deleted")
}

// finish makes the pod of job, as the Job controller would, and writes the status of a pod that ended in phase, as
// the kubelet would, with log as its log. A pod whose container never ran has no container ID, and no log.
func (f *fixture) finish(job *batchv1.Job, phase corev1.PodPhase, ran bool, log string) {
	f.t.Helper()
	template := job.Spec.Template.DeepCopy()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: job.Namespace, Name: job.Name + "-x2k4p", Labels: template.Labels, Annotations: template.Annotations,
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "batch/v1", Kind: "Job", Name: job.Name, UID: job.UID, Controller: ptr.To(true),
			}},
		},
		Spec: template.Spec,
	}
	require.NoError(f.t, f.client.Create(f.t.Context(), pod))
	f.logs.set(pod.Name, log)
	terminated := &corev1.ContainerStateTerminated{ExitCode: 0, Reason: "Completed"}
	if phase == corev1.PodFailed {
		terminated = &corev1.ContainerStateTerminated{ExitCode: 1, Reason: "Error"}
	}
	if ran {
		terminated.ContainerID = "containerd://" + strings.Repeat("c", 64)
	}
	pod.Status = corev1.PodStatus{Phase: phase, ContainerStatuses: []corev1.ContainerStatus{{
		Name: container, Image: workerImage, State: corev1.ContainerState{Terminated: terminated},
	}}}
	require.NoError(f.t, f.client.Status().Update(f.t.Context(), pod))
}

// setConditions writes the status of job with the conditions, as the Job controller does when it finishes it.
func (f *fixture) setConditions(job *batchv1.Job, conditions ...batchv1.JobCondition) {
	f.t.Helper()
	now := metav1.Now()
	for i := range conditions {
		conditions[i].Status = corev1.ConditionTrue
		conditions[i].LastProbeTime, conditions[i].LastTransitionTime = now, now
	}
	job.Status = batchv1.JobStatus{StartTime: &now, Conditions: conditions}
	if len(conditions) > 0 && conditions[len(conditions)-1].Type == batchv1.JobComplete {
		job.Status.CompletionTime = &now
		job.Status.Succeeded = 1
	}
	require.NoError(f.t, f.client.Status().Update(f.t.Context(), job))
}

// await returns the outcome of a Run, which must arrive.
func (f *fixture) await(done <-chan outcome) outcome {
	f.t.Helper()
	select {
	case o := <-done:
		return o
	case <-time.After(wait):
		require.FailNow(f.t, "Run didn't return")
		return outcome{}
	}
}

// podLogs is the log reader of the tests: the log of each pod, by name, as a test sets it. envtest runs no kubelet,
// so there are no real logs.
type podLogs struct {
	mu   sync.Mutex
	logs map[string]string
	// fails makes each read fail with the error, while it is set.
	fails error
	// read records the containers whose logs were read.
	read []string
}

func (l *podLogs) set(pod, log string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.logs[pod] = log
}

func (l *podLogs) failWith(err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.fails = err
}

func (l *podLogs) Log(_ context.Context, _, pod, container string) (string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.read = append(l.read, container)
	if l.fails != nil {
		return "", l.fails
	}
	return l.logs[pod], nil
}

// The Job keeps decision 0022's isolation: its pod runs without access to the API, as a user without privilege, with
// the credentials for its one image in a Secret that the Job owns, and with no other variable than those of the
// collector's proxy and the location of the credentials.
func TestRunMakesAJobWhosePodIsIsolated(t *testing.T) {
	f := newFixture(t)
	s := f.spec("task-0123456789ab-x2k4p")
	done := f.start(t.Context(), s)
	job := f.expectJob(s.Name)

	t.Log("labelling the Job and its pods with the labels of the Spec, which the template's don't replace")
	require.Equal(t, s.Labels, job.Labels)
	// The API server adds the labels of the Job's selector to its pods.
	for key, value := range map[string]string{taskLabel: task, "vexplain.bedag.ch/subject": "a", "team": team} {
		require.Equal(t, value, job.Spec.Template.Labels[key], key)
	}

	t.Log("bounding how long the Job runs, and how long it stays")
	require.Equal(t, ptr.To(int64(1800)), job.Spec.ActiveDeadlineSeconds)
	require.Equal(t, ptr.To(int32(0)), job.Spec.BackoffLimit)
	require.Equal(t, ptr.To(int32(3600)), job.Spec.TTLSecondsAfterFinished)

	t.Log("running one pod without access to the API, as a user without privilege")
	spec := job.Spec.Template.Spec
	require.Equal(t, corev1.RestartPolicyNever, spec.RestartPolicy)
	require.Equal(t, ptr.To(false), spec.AutomountServiceAccountToken)
	require.Equal(t, ptr.To(false), spec.EnableServiceLinks)
	require.Equal(t, &corev1.PodSecurityContext{
		RunAsNonRoot: ptr.To(true), RunAsUser: ptr.To(int64(65532)), RunAsGroup: ptr.To(int64(65532)),
		FSGroup:        ptr.To(int64(65532)),
		SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
	}, spec.SecurityContext)
	require.Len(t, spec.Containers, 1)
	c := spec.Containers[0]
	require.Equal(t, container, c.Name)
	require.Equal(t, workerImage, c.Image)
	require.Empty(t, c.Command, "the image's entrypoint runs")
	require.Equal(t, s.Args, c.Args)
	require.Equal(t, corev1.PullAlways, c.ImagePullPolicy, "the template's pull policy")
	require.Equal(t, *s.Template.Resources, c.Resources, "the template's resources")
	require.Equal(t, append([]corev1.EnvVar{{Name: "DOCKER_CONFIG", Value: "/creds"}}, proxyEnv...), c.Env)
	require.Equal(t, &corev1.SecurityContext{
		AllowPrivilegeEscalation: ptr.To(false), ReadOnlyRootFilesystem: ptr.To(true),
		Capabilities:   &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
		SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
	}, c.SecurityContext, "the profile at the container too, as strict policies ask")

	t.Log("mounting the workspace, the credentials and a temporary directory")
	mounts := map[string]corev1.VolumeMount{}
	for _, mount := range c.VolumeMounts {
		mounts[mount.MountPath] = mount
	}
	require.Len(t, mounts, 3)
	volumes := map[string]corev1.VolumeSource{}
	for _, volume := range spec.Volumes {
		volumes[volume.Name] = volume.VolumeSource
	}
	require.Len(t, volumes, 3)
	work := volumes[mounts["/work"].Name].EmptyDir
	require.NotNil(t, work)
	require.Equal(t, "10Gi", work.SizeLimit.String(), "the Spec's workspace")
	tmp := volumes[mounts["/tmp"].Name].EmptyDir
	require.NotNil(t, tmp)
	require.NotNil(t, tmp.SizeLimit, "a pod can't fill the node's disk through /tmp")
	require.Equal(t, "64Mi", tmp.SizeLimit.String())
	require.True(t, mounts["/creds"].ReadOnly)
	creds := volumes[mounts["/creds"].Name].Secret
	require.NotNil(t, creds)
	require.Equal(t, s.Name, creds.SecretName)
	require.Equal(t, ptr.To(int32(0o440)), creds.DefaultMode, "the pod's group reads the Secret")

	t.Log("putting the credentials into an Opaque Secret that the Job owns, and that the cache of LLM keys never holds")
	var secret corev1.Secret
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.NoError(c, f.client.Get(t.Context(), client.ObjectKey{Namespace: f.namespace, Name: s.Name}, &secret))
	}, wait, tick)
	require.Equal(t, corev1.SecretTypeOpaque, secret.Type)
	require.Equal(t, map[string][]byte{"config-0.json": dockerConfigs[0], "config-1.json": dockerConfigs[1]}, secret.Data,
		"one file of the directory that DOCKER_CONFIG names for each config, numbered in their order")
	require.True(t, metav1.IsControlledBy(&secret, job))
	require.Equal(t, s.Labels, secret.Labels)
	require.NotContains(t, secret.Labels, "vexplain.bedag.ch/llm-api-key")

	t.Log("reading the one line of the pod that succeeded, and deleting the Job")
	f.finish(job, corev1.PodSucceeded, true, "worker: starting\n"+resultLine+"\nworker: done\n")
	got := f.await(done)
	require.NoError(t, got.err)
	require.Equal(t, jobs.Result{Line: resultLine}, got.result)
	require.Equal(t, []string{container}, f.logs.read, "the log of the Spec's container")
	f.expectGone(s.Name)
}

// Without credentials, the Job has no Secret: its pod pulls nothing with them, and finds no DOCKER_CONFIG.
func TestRunWithoutCredentialsMakesNoSecret(t *testing.T) {
	f := newFixture(t)
	s := f.spec("task-anonymous")
	s.DockerConfigs = nil
	done := f.start(t.Context(), s)
	job := f.expectJob(s.Name)

	spec := job.Spec.Template.Spec
	require.Equal(t, proxyEnv, spec.Containers[0].Env)
	for _, volume := range spec.Volumes {
		require.Nil(t, volume.Secret, "volume %s", volume.Name)
	}
	err := f.client.Get(t.Context(), client.ObjectKey{Namespace: f.namespace, Name: s.Name}, &corev1.Secret{})
	require.True(t, apierrors.IsNotFound(err), "no Secret: %v", err)

	f.finish(job, corev1.PodSucceeded, true, resultLine+"\n")
	require.Equal(t, outcome{result: jobs.Result{Line: resultLine}}, f.await(done))
}

// A pod that failed says why in its error line, and nothing else that it prints counts.
func TestRunGivesTheReasonOfTheErrorLineOfAPodThatFailed(t *testing.T) {
	f := newFixture(t)
	s := f.spec("task-unauthorized")
	done := f.start(t.Context(), s)
	job := f.expectJob(s.Name)

	f.finish(job, corev1.PodFailed, true, "worker: pulling\n"+errorPrefix+"Unauthorized\n")

	require.Equal(t, outcome{result: jobs.Result{FailureReason: "Unauthorized"}}, f.await(done))
	f.expectGone(s.Name)
}

// A Job past its deadline timed out, whatever its pod printed: the Job controller ends the pod at the deadline, and
// its line can be cut short. The Job controller marks the Job FailureTarget at the deadline, and Failed once its pod
// is gone.
func TestRunTimesOutAJobPastItsDeadlineWhateverItsPodPrinted(t *testing.T) {
	for name, conditions := range map[string][]batchv1.JobConditionType{
		"FailureTarget":            {batchv1.JobFailureTarget},
		"FailureTarget and Failed": {batchv1.JobFailureTarget, batchv1.JobFailed},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			s := f.spec("task-deadline")
			done := f.start(t.Context(), s)
			job := f.expectJob(s.Name)
			var set []batchv1.JobCondition
			for _, condition := range conditions {
				set = append(set, batchv1.JobCondition{Type: condition, Reason: batchv1.JobReasonDeadlineExceeded,
					Message: "Job was active longer than specified deadline"})
			}
			f.setConditions(job, set...)

			f.finish(job, corev1.PodSucceeded, true, resultLine+"\n")

			require.Equal(t, outcome{result: jobs.Result{FailureReason: jobs.ReasonTimedOut}}, f.await(done))
			f.expectGone(s.Name)
		})
	}
}

// A Job whose deadline the Job controller marked before its pod finished times out, with no pod to read.
func TestRunTimesOutAJobPastItsDeadlineThatLeftNoPod(t *testing.T) {
	f := newFixture(t)
	s := f.spec("task-deadline-no-pod")
	done := f.start(t.Context(), s)
	job := f.expectJob(s.Name)

	f.setConditions(job, batchv1.JobCondition{Type: batchv1.JobFailureTarget, Reason: batchv1.JobReasonDeadlineExceeded},
		batchv1.JobCondition{Type: batchv1.JobFailed, Reason: batchv1.JobReasonDeadlineExceeded})

	require.Equal(t, outcome{result: jobs.Result{FailureReason: jobs.ReasonTimedOut}}, f.await(done))
	f.expectGone(s.Name)
}

// The log is the trust boundary: a line proves nothing about where it came from. So only the one line of a pod
// counts, a pod that succeeded delivers a result line and nothing else, and a pod that failed an error line and
// nothing else. Whatever doesn't fit fails with Internal, and a log at the limit can't hold a whole line.
func TestRunFailsWhatTheLogOfAFinishedPodDoesntProve(t *testing.T) {
	const internal = jobs.ReasonInternal
	cases := []struct {
		name   string
		phase  corev1.PodPhase
		ran    bool
		log    string
		reason string
	}{
		{"a pod that succeeded without a line", corev1.PodSucceeded, true, "worker: done\n", internal},
		{"a pod that succeeded with two lines", corev1.PodSucceeded, true, resultLine + "\n" + resultLine + "\n", internal},
		{"a pod that succeeded with an error line", corev1.PodSucceeded, true, errorPrefix + "NotFound\n", internal},
		{"a pod that failed with a result line", corev1.PodFailed, true, resultLine + "\n", internal},
		{"a pod that failed without a line, as an evicted one", corev1.PodFailed, true, "", internal},
		{"a pod that failed with an empty reason", corev1.PodFailed, true, errorPrefix + "\n", internal},
		{"a pod whose container never ran", corev1.PodFailed, false, errorPrefix + "NotFound\n", internal},
		{"a pod whose log reached the limit", corev1.PodSucceeded, true,
			strings.Repeat("worker: progress\n", 8<<20/len("worker: progress\n")+1)[:8<<20], jobs.ReasonTooLarge},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			s := f.spec("task-" + rand.String(8))
			done := f.start(t.Context(), s)
			job := f.expectJob(s.Name)

			f.finish(job, tc.phase, tc.ran, tc.log)

			require.Equal(t, outcome{result: jobs.Result{FailureReason: tc.reason}}, f.await(done))
			f.expectGone(s.Name)
		})
	}
}

// A line ends at a newline, which a carriage return may precede, and a line of the Job starts at the beginning of a
// line of the log.
func TestRunReadsTheLineAtTheStartOfALineOfTheLog(t *testing.T) {
	f := newFixture(t)
	s := f.spec("task-crlf")
	done := f.start(t.Context(), s)
	job := f.expectJob(s.Name)

	f.finish(job, corev1.PodSucceeded, true, "worker: "+errorPrefix+"Forged\r\n"+resultLine+"\r\n")

	require.Equal(t, outcome{result: jobs.Result{Line: resultLine}}, f.await(done))
}

// A Job that finished without a pod to read, as when someone deleted the pod, failed for a reason of its own.
func TestRunFailsAJobThatFinishedWithoutAPod(t *testing.T) {
	f := newFixture(t)
	s := f.spec("task-no-pod")
	done := f.start(t.Context(), s)
	job := f.expectJob(s.Name)

	f.setConditions(job, batchv1.JobCondition{Type: batchv1.JobSuccessCriteriaMet, Reason: completed},
		batchv1.JobCondition{Type: batchv1.JobComplete, Reason: completed})

	require.Equal(t, outcome{result: jobs.Result{FailureReason: jobs.ReasonInternal}}, f.await(done))
}

// A log that can't be read now is read again: only a Bad Request, the answer for a log that is gone, says that the
// pod has none.
func TestRunReadsALogAgainAfterAFailedRead(t *testing.T) {
	f := newFixture(t)
	s := f.spec("task-log-retry")
	f.logs.failWith(errors.New("the kubelet doesn't answer"))
	done := f.start(t.Context(), s)
	job := f.expectJob(s.Name)
	f.finish(job, corev1.PodSucceeded, true, resultLine+"\n")

	require.Eventually(t, func() bool {
		f.logs.mu.Lock()
		defer f.logs.mu.Unlock()
		return len(f.logs.read) >= 2
	}, wait, tick, "the log is read again")
	select {
	case o := <-done:
		require.FailNow(t, "Run returned while the log couldn't be read", "%+v", o)
	default:
	}
	f.logs.failWith(nil)

	require.Equal(t, outcome{result: jobs.Result{Line: resultLine}}, f.await(done))
}

func TestRunTakesALogThatIsGoneForNoLog(t *testing.T) {
	f := newFixture(t)
	s := f.spec("task-log-gone")
	f.logs.failWith(apierrors.NewBadRequest("the container is gone"))
	done := f.start(t.Context(), s)
	job := f.expectJob(s.Name)

	f.finish(job, corev1.PodSucceeded, true, resultLine+"\n")

	require.Equal(t, outcome{result: jobs.Result{FailureReason: jobs.ReasonInternal}}, f.await(done))
}

// Without its Secret, the Job's pod would wait for its credentials until the deadline. So the Job goes, and Run
// fails.
func TestRunDeletesTheJobWhenItsSecretCantBeCreated(t *testing.T) {
	f := newFixture(t)
	s := f.spec("task-secret-taken")
	require.NoError(t, f.client.Create(t.Context(), &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: f.namespace, Name: s.Name},
	}))

	_, err := f.runner.Run(t.Context(), s)

	require.Error(t, err)
	f.expectGone(s.Name)
}

// A Run whose context ends, as when the collector stops, deletes its Job: nobody would read what it found.
func TestRunDeletesTheJobWhenItsContextEnds(t *testing.T) {
	f := newFixture(t)
	s := f.spec("task-cancelled")
	ctx, cancel := context.WithCancel(t.Context())
	done := f.start(ctx, s)
	f.expectJob(s.Name)

	cancel()

	got := f.await(done)
	require.ErrorIs(t, got.err, context.Canceled)
	f.expectGone(s.Name)
}

// A Job that someone else deleted delivers nothing.
func TestRunFailsWhenTheJobIsGone(t *testing.T) {
	f := newFixture(t)
	s := f.spec("task-deleted")
	done := f.start(t.Context(), s)
	job := f.expectJob(s.Name)

	require.NoError(t, f.client.Delete(t.Context(), job, client.PropagationPolicy(metav1.DeletePropagationBackground)))

	require.Error(t, f.await(done).err)
}

func TestRunRefusesASpecThatItCantRun(t *testing.T) {
	f := newFixture(t)
	for name, change := range map[string]func(*jobs.Spec){
		"no name":                     func(s *jobs.Spec) { s.Name = "" },
		"no image":                    func(s *jobs.Spec) { s.Image = "" },
		"no container":                func(s *jobs.Spec) { s.Container = "" },
		"no deadline":                 func(s *jobs.Spec) { s.Deadline = 0 },
		"a deadline below one second": func(s *jobs.Spec) { s.Deadline = time.Millisecond },
		"no result prefix":            func(s *jobs.Spec) { s.ResultPrefix = "" },
		"no error prefix":             func(s *jobs.Spec) { s.ErrorPrefix = "" },
		"one prefix starting the other": func(s *jobs.Spec) {
			s.ResultPrefix, s.ErrorPrefix = "example ", "example error "
		},
		"a variable that names the credentials": func(s *jobs.Spec) {
			s.Env = append(s.Env, corev1.EnvVar{Name: "DOCKER_CONFIG", Value: "/elsewhere"})
		},
		"another namespace": func(s *jobs.Spec) { s.Namespace = team },
	} {
		t.Run(name, func(t *testing.T) {
			s := f.spec("task-refused")
			change(&s)

			_, err := f.runner.Run(t.Context(), s)

			require.Error(t, err)
			var made batchv1.JobList
			require.NoError(t, f.client.List(t.Context(), &made, client.InNamespace(f.namespace)))
			require.Empty(t, made.Items, "no Job")
		})
	}
}

// A Spec without a namespace runs in the runner's.
func TestRunRunsASpecWithoutANamespaceInTheRunners(t *testing.T) {
	f := newFixture(t)
	s := f.spec("task-own-namespace")
	s.Namespace = ""
	done := f.start(t.Context(), s)
	job := f.expectJob(s.Name)

	f.finish(job, corev1.PodSucceeded, true, resultLine+"\n")

	require.Equal(t, outcome{result: jobs.Result{Line: resultLine}}, f.await(done))
}

// The Jobs that hold a slot are those of the labels that haven't finished and aren't being deleted, in the runner's
// namespace, as the API server has them: a Job past its deadline holds its slot until it has failed.
func TestActiveCountsTheJobsThatHoldASlot(t *testing.T) {
	f := newFixture(t)
	other := newFixture(t)
	labels := map[string]string{taskLabel: task}
	create := func(fx *fixture, name string, labels map[string]string) *batchv1.Job {
		t.Helper()
		job := &batchv1.Job{
			ObjectMeta: metav1.ObjectMeta{Namespace: fx.namespace, Name: name, Labels: labels},
			Spec: batchv1.JobSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
				RestartPolicy: corev1.RestartPolicyNever,
				Containers:    []corev1.Container{{Name: container, Image: workerImage}},
			}}},
		}
		require.NoError(t, f.client.Create(t.Context(), job))
		return job
	}
	create(f, "running", labels)
	f.setConditions(create(f, "past-deadline", labels),
		batchv1.JobCondition{Type: batchv1.JobFailureTarget, Reason: batchv1.JobReasonDeadlineExceeded})
	f.setConditions(create(f, "complete", labels),
		batchv1.JobCondition{Type: batchv1.JobSuccessCriteriaMet, Reason: completed},
		batchv1.JobCondition{Type: batchv1.JobComplete, Reason: completed})
	f.setConditions(create(f, "failed", labels),
		batchv1.JobCondition{Type: batchv1.JobFailureTarget, Reason: batchv1.JobReasonBackoffLimitExceeded},
		batchv1.JobCondition{Type: batchv1.JobFailed, Reason: batchv1.JobReasonBackoffLimitExceeded})
	deleting := create(f, "deleting", labels)
	deleting.Finalizers = []string{"example.com/hold"}
	require.NoError(t, f.client.Update(t.Context(), deleting))
	require.NoError(t, f.client.Delete(t.Context(), deleting))
	t.Cleanup(func() {
		var held batchv1.Job
		if err := f.client.Get(context.Background(), client.ObjectKeyFromObject(deleting), &held); err == nil {
			held.Finalizers = nil
			assert.NoError(t, f.client.Update(context.Background(), &held))
		}
	})
	create(f, "other-task", map[string]string{taskLabel: "other"})
	create(other, "elsewhere", labels)

	active, err := f.runner.Active(t.Context(), labels)

	require.NoError(t, err)
	require.Equal(t, 2, active, "running and past-deadline")
}

func TestActiveReturnsAFailedList(t *testing.T) {
	failing := &listFailure{err: apierrors.NewServiceUnavailable("the API server is away")}
	runner := jobs.NewRunner(failing, &podLogs{}, "vexplain-system")

	_, err := runner.Active(t.Context(), map[string]string{taskLabel: task})

	require.Error(t, err)
}

// listFailure is a client whose every list fails.
type listFailure struct {
	client.Client
	err error
}

func (c *listFailure) List(context.Context, client.ObjectList, ...client.ListOption) error {
	return c.err
}
