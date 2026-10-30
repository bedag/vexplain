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
	"maps"
	"strconv"
	"strings"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilrand "k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/workloads"
)

// DigestLabel marks the scan Jobs of a digest, their pods and their Secrets. A label value holds 63
// characters at most, so the label holds the first 63 hex digits of the digest; the annotation of
// the same name holds the whole digest.
const DigestLabel = "vexplain.bedag.ch/digest"

const (
	// scanTask is the value of workloads.TaskLabel on what the runner creates.
	scanTask = "scan"
	// scannerUser is the user, and the group, that the scanner image runs as. The image's workspace
	// belongs to it, and so must the Secret's files, for the scanner to read them.
	scannerUser int64 = 65532
	// The volumes of a scan pod, and where its container mounts them.
	workVolume  = "work"
	workMount   = "/work"
	credsVolume = "creds"
	credsMount  = "/creds"
	tmpVolume   = "tmp"
	tmpMount    = "/tmp"
	// dockerConfigKey is the one key of a scan's Secret: the config.json in which the scanner's
	// keychain finds its credentials, in the directory that DOCKER_CONFIG names.
	dockerConfigKey = "config.json"
	// finishedJobSeconds is how long a finished scan Job stays when the runner doesn't delete it,
	// for instance while the operator is down.
	finishedJobSeconds = 3600
	// scannerCollector is the name of the Collector that holds the settings of the scans.
	scannerCollector = "scanner"
)

// scannerSettings are the settings of the scanner Collector, with the defaults filled in.
type scannerSettings struct {
	maxConcurrentScans, scanTimeoutSeconds, memoryLimitMebibytes, workspaceMebibytes int32
}

// defaultScannerSettings are the settings of a scanner Collector that sets none, or that doesn't
// exist. They must equal the defaults of the Collector's schema, which the API server fills in.
var defaultScannerSettings = scannerSettings{
	maxConcurrentScans:   2,
	scanTimeoutSeconds:   1800,
	memoryLimitMebibytes: 2048,
	workspaceMebibytes:   10240,
}

// loadScannerSettings reads the settings of the scans from the scanner Collector, through r.
func loadScannerSettings(ctx context.Context, r client.Reader) (scannerSettings, error) {
	var scanner configv1alpha1.Collector
	if err := r.Get(ctx, client.ObjectKey{Name: scannerCollector}, &scanner); err != nil {
		if apierrors.IsNotFound(err) {
			// The operator creates the Collector at start, and again at the next start once deleted.
			return defaultScannerSettings, nil
		}
		return scannerSettings{}, fmt.Errorf("read the settings of the scans from Collector %q: %w", scannerCollector, err)
	}
	settings := defaultScannerSettings
	if spec := scanner.Spec.Scanner; spec != nil {
		settings.maxConcurrentScans = ptr.Deref(spec.MaxConcurrentScans, settings.maxConcurrentScans)
		settings.scanTimeoutSeconds = ptr.Deref(spec.ScanTimeoutSeconds, settings.scanTimeoutSeconds)
		settings.memoryLimitMebibytes = ptr.Deref(spec.MemoryLimitMebibytes, settings.memoryLimitMebibytes)
		settings.workspaceMebibytes = ptr.Deref(spec.WorkspaceMebibytes, settings.workspaceMebibytes)
	}
	return settings, nil
}

// jobSpec is what makes a scan Job.
type jobSpec struct {
	// name is the name of the Job and of its Secret, and namespace the operator's namespace.
	name, namespace string
	// call is what the Job asks the scanner for.
	call scanCall
	// scannerImage is the image that the Job runs.
	scannerImage string
	settings     scannerSettings
	// proxyEnv holds the manager's proxy variables, and registryMirrors the scanner's
	// --registry-mirror arguments.
	proxyEnv        []corev1.EnvVar
	registryMirrors []string
}

// jobName returns a name for a new scan Job of digest, and its Secret: the start of the digest, and
// a random suffix. The Secret is named in the Job's pod template, so the runner names both itself.
func jobName(digest string) string {
	return "scan-" + strings.TrimPrefix(digest, "sha256:")[:12] + "-" + utilrand.String(5)
}

// labelsOf returns the labels of what a scan of digest creates: a task of the operator, which the
// inventory never counts, of the digest.
func labelsOf(digest string) map[string]string {
	return map[string]string{workloads.TaskLabel: scanTask, DigestLabel: strings.TrimPrefix(digest, "sha256:")[:63]}
}

// newJob returns the scan Job that s describes. Its one pod has no access to the API, runs as the
// scanner's user with no privilege, and has a workspace, a memory limit and a deadline from the
// scanner Collector. It reads its credentials from the Secret of the same name, which the runner
// creates once the Job exists, and which only the scanner's group can read.
func newJob(s jobSpec) *batchv1.Job {
	labels := labelsOf(s.call.digest)
	annotations := map[string]string{DigestLabel: s.call.digest}
	memory := mebibytes(s.settings.memoryLimitMebibytes)
	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Name: s.name, Namespace: s.namespace, Labels: labels, Annotations: annotations},
		Spec: batchv1.JobSpec{
			ActiveDeadlineSeconds:   ptr.To(int64(s.settings.scanTimeoutSeconds)),
			BackoffLimit:            ptr.To(int32(0)),
			TTLSecondsAfterFinished: ptr.To(int32(finishedJobSeconds)),
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: maps.Clone(labels), Annotations: maps.Clone(annotations)},
				Spec: corev1.PodSpec{
					RestartPolicy:                corev1.RestartPolicyNever,
					AutomountServiceAccountToken: ptr.To(false),
					EnableServiceLinks:           ptr.To(false),
					SecurityContext: &corev1.PodSecurityContext{
						RunAsNonRoot:   ptr.To(true),
						RunAsUser:      ptr.To(scannerUser),
						RunAsGroup:     ptr.To(scannerUser),
						FSGroup:        ptr.To(scannerUser),
						SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
					},
					Containers: []corev1.Container{{
						Name:            scannerContainer,
						Image:           s.scannerImage,
						ImagePullPolicy: corev1.PullIfNotPresent,
						Args:            scannerArgs(s),
						// Exactly these: DOCKER_AUTH_CONFIG, for one, would be another source of
						// credentials, and its errors would go to the log.
						Env: append([]corev1.EnvVar{{Name: "DOCKER_CONFIG", Value: credsMount}}, s.proxyEnv...),
						Resources: corev1.ResourceRequirements{
							Limits:   corev1.ResourceList{corev1.ResourceMemory: memory},
							Requests: corev1.ResourceList{corev1.ResourceMemory: memory},
						},
						SecurityContext: &corev1.SecurityContext{
							AllowPrivilegeEscalation: ptr.To(false),
							ReadOnlyRootFilesystem:   ptr.To(true),
							Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
						},
						VolumeMounts: []corev1.VolumeMount{
							{Name: workVolume, MountPath: workMount},
							{Name: credsVolume, MountPath: credsMount, ReadOnly: true},
							{Name: tmpVolume, MountPath: tmpMount},
						},
					}},
					Volumes: []corev1.Volume{
						{Name: workVolume, VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{
							SizeLimit: ptr.To(mebibytes(s.settings.workspaceMebibytes)),
						}}},
						{Name: credsVolume, VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{
							SecretName:  s.name,
							DefaultMode: ptr.To(int32(0o440)),
						}}},
						{Name: tmpVolume, VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
					},
				},
			},
		},
	}
}

// scannerArgs returns the arguments of the scanner: the image, one --platform for each platform,
// the workspace and the most that the filesystem of a manifest may take in it, and the mirrors.
//
// The limit is three quarters of the workspace. It counts the unpacked filesystem alone, and Syft's
// temporary files, its home and the SBOM need the rest: a pod that fills its workspace is evicted,
// and an evicted pod leaves no line.
func scannerArgs(s jobSpec) []string {
	args := make([]string, 0, 2+2*len(s.call.platforms)+4+2*len(s.registryMirrors))
	args = append(args, "--image", s.call.image)
	for _, platform := range s.call.platforms {
		args = append(args, "--platform", platform)
	}
	maxBytes := int64(s.settings.workspaceMebibytes) << 20 * 3 / 4
	args = append(args, "--work", workMount, "--max-bytes", strconv.FormatInt(maxBytes, 10))
	for _, mirror := range s.registryMirrors {
		args = append(args, "--registry-mirror", mirror)
	}
	return args
}

// scanOf returns what job asked the scanner for, as its container's arguments say, and the image
// of the scanner that it runs. It reports false when the Job has no scanner container, names no
// scanner image, or doesn't scan digest. The runner reads them from the Job, and not from memory,
// so that a scan outlives a restart of the operator, or a change of its scanner image.
func scanOf(job *batchv1.Job, digest string) (call scanCall, scannerImage string, ok bool) {
	for _, container := range job.Spec.Template.Spec.Containers {
		if container.Name != scannerContainer {
			continue
		}
		call.digest = digest
		// Every argument of the scanner is a flag and its value.
		for i := 0; i+1 < len(container.Args); i += 2 {
			switch container.Args[i] {
			case "--image":
				call.image = container.Args[i+1]
			case "--platform":
				call.platforms = append(call.platforms, container.Args[i+1])
			}
		}
		ok = container.Image != "" && strings.HasSuffix(call.image, "@"+digest)
		return call, container.Image, ok
	}
	return scanCall{}, "", false
}

// newSecret returns the Secret that holds the credentials of job: an Opaque Secret with config as its
// one key, which the Job owns, so that it goes with the Job. It doesn't carry the label of the LLM
// API keys, so that no ModelConfig can name it, and the manager's cache never loads it.
func newSecret(job *batchv1.Job, config []byte) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      job.Name,
			Namespace: job.Namespace,
			Labels:    maps.Clone(job.Labels),
			// The owner reference doesn't block the deletion of the Job: that would take the right to
			// update the Job's finalizers, and the Job is deleted in the background anyway.
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

// mebibytes returns n MiB as a quantity.
func mebibytes(n int32) resource.Quantity {
	return *resource.NewQuantity(int64(n)<<20, resource.BinarySI)
}
