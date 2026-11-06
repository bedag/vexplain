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

// Package jobs runs a throwaway Job for a collector, and reads the one line that its pod prints: the pattern of
// phase 2a's scans, which any collector can use, and none has to (decision 0022, and the design of collectors,
// evidence and rules, docs/design/2026-10-31-collectors-evidence-rules.md, section 5.4).
//
// The Job keeps decision 0022's isolation, whatever its Spec says:
//   - its pod has no access to the Kubernetes API: no service account token, and no service links
//   - it runs as a user without privilege, 65532, the user of distroless' nonroot images, with the RuntimeDefault
//     seccomp profile, a read-only root filesystem and no capabilities
//   - it writes to the workspace that the Spec sizes, and to /tmp, which holds 64 MiB: a pod's scratch files belong in
//     the workspace, so that neither volume can fill the node's disk
//   - the only credentials it gets are those of the Spec, for its one task, in a Secret that the Job owns, so that the
//     Secret goes with the Job; the Secret holds them as config.json, which the pod finds where DOCKER_CONFIG says
//   - its environment holds DOCKER_CONFIG and the variables of the Spec, and nothing else of the collector's
//
// The pod's log is the trust boundary: a line in it proves nothing about where it came from, and the pod may process
// content that someone crafted. So Run takes exactly one line of the Job, and only from a pod that succeeded a result
// line, and from one that failed an error line. What the line says is the collector's to check.
package jobs

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/bedag/vexplain/sdk/podtemplate"
)

// WorkspaceDir is where the container finds its workspace, an emptyDir of the size of the Spec's Workspace.
const WorkspaceDir = "/work"

// The reasons for which Run says that a Job failed, besides the reason of its error line. They are words of the
// vocabulary that vexplain keeps for failures, and keeps open.
const (
	// ReasonTimedOut is a Job that ran past its deadline.
	ReasonTimedOut = "TimedOut"
	// ReasonTooLarge is a pod whose log reached the most that Run reads, so that its line can't be whole.
	ReasonTooLarge = "TooLarge"
	// ReasonInternal is a pod that said nothing that Run can read, such as an evicted one, or said something that
	// contradicts how it ended, and a Job that finished without a pod to read.
	ReasonInternal = "Internal"
)

const (
	// user is the user, and the group, that the pod runs as: that of distroless' nonroot images. The Secret's files
	// belong to its group, so that the pod reads them.
	user int64 = 65532
	// The volumes of the pod, and where its container mounts them: the workspace, the credentials and a temporary
	// directory, since the root filesystem is read-only.
	workVolume  = "work"
	credsVolume = "creds"
	credsMount  = "/creds"
	tmpVolume   = "tmp"
	tmpMount    = "/tmp"
	// dockerConfigVariable names the directory of the credentials, and dockerConfigKey is their one file, the
	// config.json in which Docker's and go-containerregistry's keychains find them.
	dockerConfigVariable = "DOCKER_CONFIG"
	dockerConfigKey      = "config.json"
	// finishedSeconds is how long a finished Job stays when Run doesn't delete it, as when the collector stops.
	finishedSeconds = 3600
	// defaultPoll is how often Run looks at the Job, unless the Runner says otherwise.
	defaultPoll = 2 * time.Second
	// grace is how long after the Job's deadline Run still waits for it: the Job controller marks a Job that ran past
	// its deadline only once it has seen that, and its pod ends within its termination grace period.
	grace = 2 * time.Minute
	// cleanupTimeout bounds the deletion of a Job whose Run ends with its context.
	cleanupTimeout = 30 * time.Second
)

// tmpSize is the most that the pod's /tmp holds. A pod's scratch files belong in the workspace, as the scanner points
// TMPDIR and HOME there, so /tmp needs little, and the limit only keeps it from filling the node's disk.
var tmpSize = resource.MustParse("64Mi")

// Spec is what Run runs: one container in one pod of a Job.
type Spec struct {
	// Name names the Job and its Secret, and Namespace is the collector's own namespace, the runner's, which an empty
	// one stands for. Image is the image of the one container, which Container names, and Args its arguments: the
	// image's entrypoint runs.
	Name, Namespace, Image, Container string
	Args                              []string
	// Env holds the variables that the container gets besides DOCKER_CONFIG, such as the collector's proxy. It must
	// not set DOCKER_CONFIG, which is Run's.
	Env []corev1.EnvVar
	// DockerConfig is the config.json of the credentials that the pod gets, or nil for none, which gives no Secret.
	DockerConfig []byte // nil: no credentials
	// Workspace is the size of the emptyDir that the container finds at WorkspaceDir. Zero gives no workspace.
	Workspace resource.Quantity
	// Deadline is how long the Job may run, at least a second: the Job controller ends it then.
	Deadline time.Duration
	// Template shapes the pod: its pull policy, its resources, where it runs, and labels and annotations to add.
	Template podtemplate.PodTemplate
	// Labels are the labels of the Job, its pod and its Secret, which the template's don't replace. They should hold
	// the label that marks vexplain's own pods, which vexplain tells its collectors in their context, so that no
	// presence collector takes the pod for a workload.
	Labels map[string]string
	// ResultPrefix starts the line of a pod that succeeded, and ErrorPrefix the line of one that failed. Neither
	// starts the other.
	ResultPrefix, ErrorPrefix string
}

// Result is what a Job came to: the line of its pod that succeeded, or why it failed, and never both. Line is the
// whole line, with ResultPrefix, for the collector to check. FailureReason is the text of the error line after
// ErrorPrefix, which is the pod's, or one of the reasons of this package.
type Result struct{ Line, FailureReason string }

// Runner runs Jobs in a collector's namespace. It reads and writes through its client, which must read the API server
// and not a cache, so that a count of the Jobs never misses one just created. It is safe for concurrent use.
type Runner struct {
	// Poll is how often Run looks at its Job and the Job's pod. NewRunner sets 2 seconds.
	Poll time.Duration

	client    client.Client
	logs      LogReader
	namespace string
}

// NewRunner returns a Runner of the Jobs in namespace, which reads the logs of their pods through logs.
func NewRunner(c client.Client, logs LogReader, namespace string) *Runner {
	return &Runner{Poll: defaultPoll, client: c, logs: logs, namespace: namespace}
}

// Run creates the Job, then its Secret owned by the Job; waits for it; reads its one line; deletes it.
//
// It waits until the Job ran past its deadline, which is ReasonTimedOut, or until its pod has finished. It then reads
// the pod's log, and finds the line of the Job: a line that starts with ResultPrefix or ErrorPrefix. A pod that
// succeeded with one such line, a result line, gives Line, and one that failed with one, an error line, gives the
// FailureReason that follows ErrorPrefix. Anything else gives ReasonInternal, or ReasonTooLarge for a log that reached
// the most that a LogReader reads. A Job that the Job controller finished without a pod to read gives ReasonInternal
// too. A Job that nothing marks finished goes the same way as one past its deadline, two minutes after it.
//
// It returns an error for what keeps it from running the Job, such as a Spec that it can't run or a Job that it can't
// create, and for a Job that someone else deleted. A Secret that it can't create deletes the Job again: its pod would
// wait for its credentials until the deadline. A read that fails is tried again at the next look, until the Job's
// time is up.
//
// It deletes the Job when it returns, and lets the garbage collector delete the pod and the Secret: also when ctx
// ends, since nothing would read what the Job found. A Job that it can't delete goes an hour after it finished, with
// its Secret.
func (r *Runner) Run(ctx context.Context, s Spec) (Result, error) {
	if s.Namespace == "" {
		s.Namespace = r.namespace
	}
	if err := r.check(s); err != nil {
		return Result{}, err
	}
	job := newJob(s)
	if err := r.client.Create(ctx, job); err != nil {
		return Result{}, fmt.Errorf("create Job %s: %w", job.Name, err)
	}
	// The Secret comes after the Job, which owns it, so that the Secret goes with the Job.
	if s.DockerConfig != nil {
		if err := r.client.Create(ctx, newSecret(job, s.DockerConfig)); err != nil {
			return Result{}, errors.Join(fmt.Errorf("create the Secret of Job %s: %w", job.Name, err), r.delete(ctx, job))
		}
	}
	result, err := r.wait(ctx, job, s)
	// A Job that it can't delete goes by its TTL, an hour after it finished, with its Secret, and what it found
	// stands.
	_ = r.delete(ctx, job)
	return result, err
}

// check refuses a Spec that Run can't run.
func (r *Runner) check(s Spec) error {
	switch {
	case s.Name == "" || s.Image == "" || s.Container == "":
		return errors.New("a Job needs a name, an image and a container")
	case s.Namespace != r.namespace:
		return fmt.Errorf("the runner runs Jobs in %s, and not in %s", r.namespace, s.Namespace)
	case s.Deadline < time.Second:
		return errors.New("a Job needs a deadline of a second at least")
	case s.ResultPrefix == "" || s.ErrorPrefix == "":
		return errors.New("a Job needs the prefixes of its result line and of its error line")
	case strings.HasPrefix(s.ResultPrefix, s.ErrorPrefix) || strings.HasPrefix(s.ErrorPrefix, s.ResultPrefix):
		return errors.New("the prefix of the result line and that of the error line start one another")
	case slices.ContainsFunc(s.Env, func(e corev1.EnvVar) bool { return e.Name == dockerConfigVariable }):
		return errors.New("the environment of a Job sets " + dockerConfigVariable + ", which says where its credentials are")
	}
	return nil
}

// wait looks at job every Poll until its pod has finished, or its time is up, and returns what it came to.
func (r *Runner) wait(ctx context.Context, job *batchv1.Job, s Spec) (Result, error) {
	ticker := time.NewTicker(r.Poll)
	defer ticker.Stop()
	until := time.Now().Add(s.Deadline + grace)
	for {
		result, done, err := r.look(ctx, job, s)
		switch {
		case done:
			return result, err
		case time.Now().After(until):
			if err != nil {
				return Result{}, err
			}
			return Result{FailureReason: ReasonTimedOut}, nil
		}
		select {
		case <-ctx.Done():
			return Result{}, ctx.Err()
		case <-ticker.C:
		}
	}
}

// look looks at the Job once. It reports whether the Job is done, and with the result that it came to, or the error
// of a Job that is gone. A read that failed returns its error with done false, to be tried again.
func (r *Runner) look(ctx context.Context, job *batchv1.Job, s Spec) (Result, bool, error) {
	var now batchv1.Job
	if err := r.client.Get(ctx, client.ObjectKeyFromObject(job), &now); err != nil {
		if apierrors.IsNotFound(err) {
			return Result{}, true, fmt.Errorf("the Job %s is gone before it finished", job.Name)
		}
		return Result{}, false, fmt.Errorf("read Job %s: %w", job.Name, err)
	}
	if now.UID != job.UID || now.DeletionTimestamp != nil {
		return Result{}, true, fmt.Errorf("the Job %s is gone before it finished", job.Name)
	}
	if pastDeadline(&now) {
		return Result{FailureReason: ReasonTimedOut}, true, nil
	}
	pod, err := r.finishedPod(ctx, &now, s)
	if err != nil {
		return Result{}, false, err
	}
	if pod == nil {
		if finished(&now) {
			return Result{FailureReason: ReasonInternal}, true, nil
		}
		return Result{}, false, nil
	}
	if !ran(pod, s.Container) {
		// A container that never ran printed nothing, such as one of a pod that the kubelet refused.
		return Result{FailureReason: ReasonInternal}, true, nil
	}
	log, err := r.logs.Log(ctx, pod.Namespace, pod.Name, s.Container)
	switch {
	case apierrors.IsBadRequest(err):
		// The API server answers the read of a log that is gone with Bad Request, as the kubelet does for a container
		// that it no longer has, and a pod that has finished won't get one back.
		return Result{FailureReason: ReasonInternal}, true, nil
	case err != nil:
		return Result{}, false, err
	}
	return outcomeOf(pod.Status.Phase, log, s), true, nil
}

// outcomeOf returns what the log of a pod that ended in phase says, as Run describes it.
func outcomeOf(phase corev1.PodPhase, log string, s Spec) Result {
	if len(log) >= maxLogBytes {
		return Result{FailureReason: ReasonTooLarge}
	}
	var lines []string
	for text := range strings.SplitSeq(log, "\n") {
		text = strings.TrimSuffix(text, "\r")
		if strings.HasPrefix(text, s.ResultPrefix) || strings.HasPrefix(text, s.ErrorPrefix) {
			lines = append(lines, text)
		}
	}
	if len(lines) != 1 {
		return Result{FailureReason: ReasonInternal}
	}
	line := lines[0]
	switch phase {
	case corev1.PodSucceeded:
		if strings.HasPrefix(line, s.ResultPrefix) {
			return Result{Line: line}
		}
	case corev1.PodFailed:
		if reason, ok := strings.CutPrefix(line, s.ErrorPrefix); ok && reason != "" {
			return Result{FailureReason: reason}
		}
	}
	return Result{FailureReason: ReasonInternal}
}

// finishedPod returns the pod of job that has finished, or nil while none has. A pod that succeeded comes before one
// that failed, since only its log holds a result. The pods are read after the Job: the Job controller marks a Job
// finished once it has seen its pod finish.
func (r *Runner) finishedPod(ctx context.Context, job *batchv1.Job, s Spec) (*corev1.Pod, error) {
	var pods corev1.PodList
	if err := r.client.List(ctx, &pods, client.InNamespace(job.Namespace), client.MatchingLabels(s.Labels)); err != nil {
		return nil, fmt.Errorf("list the pods of Job %s: %w", job.Name, err)
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

// delete deletes job, and lets the garbage collector delete its pod and its Secret. It deletes it also when ctx has
// ended, within a bound of its own.
func (r *Runner) delete(ctx context.Context, job *batchv1.Job) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
	defer cancel()
	err := r.client.Delete(ctx, job, client.PropagationPolicy(metav1.DeletePropagationBackground),
		client.Preconditions{UID: &job.UID})
	if client.IgnoreNotFound(err) != nil && !apierrors.IsConflict(err) {
		return fmt.Errorf("delete Job %s: %w", job.Name, err)
	}
	return nil
}

// Active counts the Jobs with the labels in the runner's namespace that hold a slot: those that haven't finished and
// aren't being deleted, as the API server has them. A Job past its deadline holds its slot until it has failed, since
// its pod is still being stopped.
func (r *Runner) Active(ctx context.Context, labels map[string]string) (int, error) {
	var list batchv1.JobList
	if err := r.client.List(ctx, &list, client.InNamespace(r.namespace), client.MatchingLabels(labels)); err != nil {
		return 0, fmt.Errorf("list the Jobs: %w", err)
	}
	active := 0
	for i := range list.Items {
		if list.Items[i].DeletionTimestamp == nil && !finished(&list.Items[i]) {
			active++
		}
	}
	return active, nil
}

// pastDeadline reports whether job ran past its activeDeadlineSeconds. The Job controller marks such a Job
// FailureTarget, then Failed once its pod is gone, both with the reason DeadlineExceeded.
func pastDeadline(job *batchv1.Job) bool {
	return slices.ContainsFunc(job.Status.Conditions, func(c batchv1.JobCondition) bool {
		return (c.Type == batchv1.JobFailed || c.Type == batchv1.JobFailureTarget) &&
			c.Status == corev1.ConditionTrue && c.Reason == batchv1.JobReasonDeadlineExceeded
	})
}

// finished reports whether job has finished: it is Complete or Failed.
func finished(job *batchv1.Job) bool {
	return slices.ContainsFunc(job.Status.Conditions, func(c batchv1.JobCondition) bool {
		return (c.Type == batchv1.JobComplete || c.Type == batchv1.JobFailed) && c.Status == corev1.ConditionTrue
	})
}

// ran reports whether the container of pod has run, so that it can have a log, as the kubelet judges it: it runs, or
// ended with the ID of a container that the runtime started. A container that waited has no log to read.
func ran(pod *corev1.Pod, container string) bool {
	for _, status := range pod.Status.ContainerStatuses {
		if status.Name != container {
			continue
		}
		state, last := status.State, status.LastTerminationState
		return state.Running != nil ||
			(state.Terminated != nil && state.Terminated.ContainerID != "") ||
			(last.Terminated != nil && last.Terminated.ContainerID != "")
	}
	return false
}

// newJob returns the Job that s describes, with decision 0022's isolation, as the package's doc lists it. Its one pod
// mounts the workspace, the credentials when there are any, and a temporary directory. It runs once, and stays an hour
// once it has finished, should Run not delete it.
func newJob(s Spec) *batchv1.Job {
	container := corev1.Container{
		Name:  s.Container,
		Image: s.Image,
		Args:  slices.Clone(s.Args),
		Env:   slices.Clone(s.Env),
		SecurityContext: &corev1.SecurityContext{
			AllowPrivilegeEscalation: ptr.To(false),
			ReadOnlyRootFilesystem:   ptr.To(true),
			Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
		},
		VolumeMounts: []corev1.VolumeMount{{Name: tmpVolume, MountPath: tmpMount}},
	}
	volumes := []corev1.Volume{
		{Name: tmpVolume, VolumeSource: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{SizeLimit: ptr.To(tmpSize.DeepCopy())},
		}},
	}
	if !s.Workspace.IsZero() {
		container.VolumeMounts = append(container.VolumeMounts, corev1.VolumeMount{Name: workVolume, MountPath: WorkspaceDir})
		volumes = append(volumes, corev1.Volume{Name: workVolume, VolumeSource: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{SizeLimit: ptr.To(s.Workspace.DeepCopy())},
		}})
	}
	if s.DockerConfig != nil {
		container.Env = append([]corev1.EnvVar{{Name: dockerConfigVariable, Value: credsMount}}, container.Env...)
		container.VolumeMounts = append(container.VolumeMounts,
			corev1.VolumeMount{Name: credsVolume, MountPath: credsMount, ReadOnly: true})
		volumes = append(volumes, corev1.Volume{Name: credsVolume, VolumeSource: corev1.VolumeSource{
			Secret: &corev1.SecretVolumeSource{SecretName: s.Name, DefaultMode: ptr.To(int32(0o440))},
		}})
	}
	template := corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{Labels: maps.Clone(s.Labels)},
		Spec: corev1.PodSpec{
			RestartPolicy:                corev1.RestartPolicyNever,
			AutomountServiceAccountToken: ptr.To(false),
			EnableServiceLinks:           ptr.To(false),
			SecurityContext: &corev1.PodSecurityContext{
				RunAsNonRoot:   ptr.To(true),
				RunAsUser:      ptr.To(user),
				RunAsGroup:     ptr.To(user),
				FSGroup:        ptr.To(user),
				SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
			},
			Containers: []corev1.Container{container},
			Volumes:    volumes,
		},
	}
	s.Template.Apply(&template.ObjectMeta, &template.Spec, s.Container)
	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Name: s.Name, Namespace: s.Namespace, Labels: maps.Clone(s.Labels)},
		Spec: batchv1.JobSpec{
			ActiveDeadlineSeconds:   ptr.To(int64(s.Deadline / time.Second)),
			BackoffLimit:            ptr.To(int32(0)),
			TTLSecondsAfterFinished: ptr.To(int32(finishedSeconds)),
			Template:                template,
		},
	}
}

// newSecret returns the Secret that holds the credentials of job: an Opaque Secret with config as its one key, which
// the Job owns, so that it goes with the Job. It carries the labels of the Job and no other, so that no cache of
// labelled Secrets, such as the operator's of LLM keys, ever holds it.
func newSecret(job *batchv1.Job, config []byte) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      job.Name,
			Namespace: job.Namespace,
			Labels:    maps.Clone(job.Labels),
			// The owner reference doesn't block the deletion of the Job: that would take the right to update the Job's
			// finalizers, and the Job is deleted in the background anyway.
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: batchv1.SchemeGroupVersion.String(),
				Kind:       "Job",
				Name:       job.Name,
				UID:        job.UID,
				Controller: ptr.To(true),
			}},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{dockerConfigKey: config},
	}
}
