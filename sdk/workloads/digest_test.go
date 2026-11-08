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

package workloads_test

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/bedag/vexplain/sdk/workloads"
)

// The fixtures: the repository of the images that were pulled from one, the namespace of the
// operator, the label that marks a task pod, and the value that scan pods give it. The label is
// spelled out here and not read from workloads.TaskLabel, so that the tests pin the name that scan
// pods carry.
const (
	repository        = "artifacts.example/lib/nginx"
	operatorNamespace = "vexplain-system"
	taskLabel         = "vexplain.bedag.ch/task"
	scan              = "scan"
)

// The digests of the fixtures. hexDigits holds every hex digit, so a pattern that accepts only
// some of them fails. digestA, digestB and digestC differ from each other and sort in that order.
var (
	hexDigits = strings.Repeat("0123456789abcdef", 4)
	digest    = "sha256:" + hexDigits
	digestA   = "sha256:" + strings.Repeat("a", 64)
	digestB   = "sha256:" + strings.Repeat("b", 64)
	digestC   = "sha256:" + strings.Repeat("c", 64)
)

// The names of containers of the fixtures, and an image that no digest names.
const (
	setupName = "setup"
	initName  = "init"
	appImage  = "app:1"
)

// regular, initial and sidecar name a container of the kind.
func regular(name string) workloads.ContainerRef {
	return workloads.ContainerRef{Name: name, Kind: workloads.ContainerKindContainer}
}

func initial(name string) workloads.ContainerRef {
	return workloads.ContainerRef{Name: name, Kind: workloads.ContainerKindInitContainer}
}

func sidecar(name string) workloads.ContainerRef {
	return workloads.ContainerRef{Name: name, Kind: workloads.ContainerKindSidecar}
}

// status is the status of a container that reports imageID.
func status(name, imageID string) corev1.ContainerStatus {
	return corev1.ContainerStatus{Name: name, ImageID: imageID}
}

func TestDigestFromImageID(t *testing.T) {
	tests := []struct {
		name    string
		imageID string
		want    workloads.ImageRef // the zero value when ok is false
		ok      bool
	}{
		// What a container runtime reports, with the prefix of the runtime and without it.
		{
			name:    "a repository digest with the docker-pullable prefix",
			imageID: "docker-pullable://" + repository + "@" + digest,
			want:    workloads.ImageRef{Digest: digest, Repository: repository},
			ok:      true,
		},
		{
			name:    "a repository digest",
			imageID: repository + "@" + digest,
			want:    workloads.ImageRef{Digest: digest, Repository: repository},
			ok:      true,
		},
		{
			name:    "an image ID",
			imageID: digest,
			want:    workloads.ImageRef{Digest: digest},
			ok:      true,
		},
		{
			name:    "an image ID with the docker prefix",
			imageID: "docker://" + digest,
			want:    workloads.ImageRef{Digest: digest},
			ok:      true,
		},

		// Everything else is not a digest the operator can use. The caller makes such a value
		// visible, so it must never come out as a digest by accident.
		{name: "an empty value", imageID: ""},
		{name: "a tag", imageID: "nginx:1.27"},
		{name: "a digest that is too short", imageID: "repo@sha256:abc"},
		{name: "a digest with uppercase hex digits", imageID: "repo@sha256:" + strings.ToUpper(hexDigits)},
		{name: "a digest that is too long", imageID: repository + "@" + digest + "0"},
		{name: "a digest with a character that is not hex", imageID: repository + "@sha256:" + strings.Repeat("g", 64)},
		{name: "a digest of another algorithm", imageID: repository + "@sha512:" + strings.Repeat("a", 128)},
		// The same length as a sha256 digest, so that only the algorithm is wrong.
		{name: "a blake3 digest", imageID: repository + "@blake3:" + strings.Repeat("a", 64)},
		{name: "a repository digest without a repository", imageID: "@" + digest},
		{name: "a prefix and nothing else", imageID: "docker://"},
		{name: "a prefix and a tag", imageID: "docker://nginx:1.27"},

		// The part after the last @ is the digest, and everything before it is the repository.
		{
			name:    "the last @ separates the digest",
			imageID: "a@b@" + digest,
			want:    workloads.ImageRef{Digest: digest, Repository: "a@b"},
			ok:      true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := workloads.DigestFromImageID(tc.imageID)

			require.Equal(t, tc.ok, ok)
			require.Equal(t, tc.want, got)
		})
	}
}

// An image ID is the one digest that no registry can serve, so callers tell it apart by the
// missing repository.
func TestImageRefIsImageID(t *testing.T) {
	require.True(t, workloads.ImageRef{Digest: digest}.IsImageID())
	require.False(t, workloads.ImageRef{Digest: digest, Repository: repository}.IsImageID())
}

// podOf returns a pod whose spec has the containers, by name and image, and whose status reports the statuses.
func podOf(inits, containers []corev1.Container, initStatuses, statuses []corev1.ContainerStatus) *corev1.Pod {
	return &corev1.Pod{
		Spec: corev1.PodSpec{InitContainers: inits, Containers: containers},
		Status: corev1.PodStatus{
			InitContainerStatuses: initStatuses,
			ContainerStatuses:     statuses,
		},
	}
}

func TestPodImagesNamesTheContainers(t *testing.T) {
	always := corev1.ContainerRestartPolicyAlways
	t.Run("each container with its kind, and two containers of one digest under one image", func(t *testing.T) {
		pod := podOf(
			[]corev1.Container{{Name: setupName, Image: "init.example/setup:1"},
				{Name: "proxy", Image: "mesh.example/proxy:1", RestartPolicy: &always}},
			[]corev1.Container{{Name: web, Image: repository + ":1"}, {Name: "worker", Image: repository + ":1"}},
			[]corev1.ContainerStatus{
				status(setupName, "init.example/setup@"+digestC), status("proxy", "mesh.example/proxy@"+digestB),
			},
			[]corev1.ContainerStatus{status(web, repository+"@"+digestA), status("worker", repository+"@"+digestA)},
		)

		images, unparsable := workloads.PodImages(pod)

		require.Empty(t, unparsable)
		require.Equal(t, []workloads.ImageRef{
			{Digest: digestA, Repository: repository, Containers: []workloads.ContainerRef{
				regular(web), regular("worker")}},
			{Digest: digestB, Repository: "mesh.example/proxy", Containers: []workloads.ContainerRef{
				sidecar("proxy")}},
			{Digest: digestC, Repository: "init.example/setup", Containers: []workloads.ContainerRef{
				initial(setupName)}},
		}, images)
	})

	t.Run("an init container that restarts only on failure is no sidecar", func(t *testing.T) {
		onFailure := corev1.ContainerRestartPolicy("OnFailure")
		pod := podOf([]corev1.Container{{Name: setupName, Image: "x.example/setup:1", RestartPolicy: &onFailure}}, nil,
			[]corev1.ContainerStatus{status(setupName, "x.example/setup@"+digestA)}, nil)

		images, _ := workloads.PodImages(pod)

		require.Equal(t, []workloads.ContainerRef{initial(setupName)}, images[0].Containers)
	})

	t.Run("a container without an image ID runs an image of its reference", func(t *testing.T) {
		ref := "registry.example/team-a/app:1.0"
		pod := podOf(nil, []corev1.Container{{Name: web, Image: ref}}, nil, []corev1.ContainerStatus{status(web, "")})

		images, unparsable := workloads.PodImages(pod)

		require.Empty(t, unparsable)
		sum := sha256.Sum256([]byte(ref))
		want := "sha256:" + hex.EncodeToString(sum[:])
		require.Equal(t, want, workloads.ReferenceDigest(ref))
		require.Equal(t, []workloads.ImageRef{{Digest: want, Repository: ref, Reference: true,
			Containers: []workloads.ContainerRef{regular(web)}}}, images)
		require.False(t, images[0].IsImageID())
	})

	t.Run("a container that has no status yet is a reference too", func(t *testing.T) {
		pod := podOf(nil, []corev1.Container{{Name: web, Image: appImage}}, nil, nil)

		images, _ := workloads.PodImages(pod)

		require.Len(t, images, 1)
		require.True(t, images[0].Reference)
	})

	t.Run("an image ID that is no digest gives a reference and is listed as unparsable", func(t *testing.T) {
		pod := podOf(nil, []corev1.Container{{Name: web, Image: appImage}}, nil,
			[]corev1.ContainerStatus{status(web, appImage)})

		images, unparsable := workloads.PodImages(pod)

		require.Equal(t, []string{web}, unparsable)
		require.Len(t, images, 1)
		require.True(t, images[0].Reference)
		require.Equal(t, appImage, images[0].Repository)
	})

	t.Run("two containers of one reference share one image", func(t *testing.T) {
		pod := podOf(nil, []corev1.Container{{Name: "a", Image: appImage}, {Name: "b", Image: appImage}}, nil, nil)

		images, _ := workloads.PodImages(pod)

		require.Len(t, images, 1)
		require.Equal(t, []workloads.ContainerRef{regular("a"), regular("b")},
			images[0].Containers)
	})

	t.Run("an ephemeral container is not named", func(t *testing.T) {
		pod := podOf(nil, []corev1.Container{{Name: web, Image: appImage}}, nil,
			[]corev1.ContainerStatus{status(web, repository+"@"+digestA)})
		pod.Spec.EphemeralContainers = []corev1.EphemeralContainer{{
			EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug", Image: "dbg:1"},
		}}
		pod.Status.EphemeralContainerStatuses = []corev1.ContainerStatus{status("debug", "dbg.example/tools@"+digestC)}

		images, _ := workloads.PodImages(pod)

		require.Len(t, images, 1)
		require.Equal(t, []workloads.ContainerRef{regular(web)}, images[0].Containers)
	})
}

func TestPodImages(t *testing.T) {
	t.Run("an init and an app container with the same digest give one image", func(t *testing.T) {
		pod := &corev1.Pod{Status: corev1.PodStatus{
			InitContainerStatuses: []corev1.ContainerStatus{status(initName, repository+"@"+digestA)},
			ContainerStatuses:     []corev1.ContainerStatus{status(web, repository+"@"+digestA)},
		}}

		images, unparsable := workloads.PodImages(pod)

		require.Equal(t, []workloads.ImageRef{{Digest: digestA, Repository: repository, Containers: []workloads.ContainerRef{
			initial(initName), regular(web)}}}, images)
		require.Empty(t, unparsable)
	})

	// The init containers are read before the containers, so the repository of an init container
	// is the first one seen.
	t.Run("the image keeps the first repository seen", func(t *testing.T) {
		pod := &corev1.Pod{Status: corev1.PodStatus{
			InitContainerStatuses: []corev1.ContainerStatus{status(initName, repository+"@"+digestA)},
			ContainerStatuses:     []corev1.ContainerStatus{status(web, "mirror.example/lib/nginx@"+digestA)},
		}}

		images, _ := workloads.PodImages(pod)

		require.Equal(t, []workloads.ImageRef{{Digest: digestA, Repository: repository, Containers: []workloads.ContainerRef{
			initial(initName), regular(web)}}}, images)
	})

	t.Run("an ephemeral container is skipped", func(t *testing.T) {
		pod := &corev1.Pod{Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{status(web, repository+"@"+digestA)},
			EphemeralContainerStatuses: []corev1.ContainerStatus{
				status("debug", "debug.example/tools@"+digestC),
				// Neither does its imageID count as unparsable.
				status("debug-2", "busybox:1.37"),
			},
		}}

		images, unparsable := workloads.PodImages(pod)

		require.Equal(t, []workloads.ImageRef{{Digest: digestA, Repository: repository, Containers: []workloads.ContainerRef{
			regular(web)}}}, images)
		require.Empty(t, unparsable)
	})

	t.Run("a pending pod gives no images and nothing unparsable", func(t *testing.T) {
		pod := &corev1.Pod{Status: corev1.PodStatus{
			InitContainerStatuses: []corev1.ContainerStatus{status(initName, "")},
			ContainerStatuses:     []corev1.ContainerStatus{status(web, "")},
		}}

		images, unparsable := workloads.PodImages(pod)

		require.Empty(t, images)
		require.Empty(t, unparsable)
	})

	t.Run("a pod without a status gives no images and nothing unparsable", func(t *testing.T) {
		images, unparsable := workloads.PodImages(&corev1.Pod{})

		require.Empty(t, images)
		require.Empty(t, unparsable)
	})

	t.Run("a container whose imageID is not a digest is unparsable", func(t *testing.T) {
		pod := &corev1.Pod{Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{status(web, "nginx:1.27")},
		}}

		images, unparsable := workloads.PodImages(pod)

		require.Empty(t, images)
		require.Equal(t, []string{web}, unparsable)
	})

	// One container the operator can't read must neither hide the others nor be dropped silently.
	// The names come in the order the statuses were read, init containers first.
	t.Run("unparsable containers don't hide the other images", func(t *testing.T) {
		pod := &corev1.Pod{Status: corev1.PodStatus{
			InitContainerStatuses: []corev1.ContainerStatus{status(setupName, "nginx:1.27")},
			ContainerStatuses: []corev1.ContainerStatus{
				status(web, repository+"@"+digestA),
				status("sidecar", "busybox:1.37"),
				status("starting", ""),
			},
		}}

		images, unparsable := workloads.PodImages(pod)

		require.Equal(t, []workloads.ImageRef{{Digest: digestA, Repository: repository, Containers: []workloads.ContainerRef{
			regular(web)}}}, images)
		require.Equal(t, []string{setupName, "sidecar"}, unparsable)
	})

	t.Run("the images are sorted by digest", func(t *testing.T) {
		pod := &corev1.Pod{Status: corev1.PodStatus{
			InitContainerStatuses: []corev1.ContainerStatus{status(initName, "init.example/setup@"+digestC)},
			ContainerStatuses: []corev1.ContainerStatus{
				status(web, repository+"@"+digestB),
				status("sidecar", "sidecar.example/proxy@"+digestA),
			},
		}}

		images, _ := workloads.PodImages(pod)

		require.Equal(t, []workloads.ImageRef{
			{Digest: digestA, Repository: "sidecar.example/proxy", Containers: []workloads.ContainerRef{
				regular("sidecar")}},
			{Digest: digestB, Repository: repository, Containers: []workloads.ContainerRef{
				regular(web)}},
			{Digest: digestC, Repository: "init.example/setup", Containers: []workloads.ContainerRef{
				initial(initName)}},
		}, images)
	})

	t.Run("an image ID has no repository", func(t *testing.T) {
		pod := &corev1.Pod{Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{status(web, "docker://"+digestA)},
		}}

		images, unparsable := workloads.PodImages(pod)

		require.Equal(t, []workloads.ImageRef{{Digest: digestA, Containers: []workloads.ContainerRef{
			regular(web)}}}, images)
		require.True(t, images[0].IsImageID())
		require.Empty(t, unparsable)
	})
}

// A task pod is one that the operator runs for itself, such as a scan pod, in its own namespace.
// It runs images, but it is no workload of the cluster, so the inventory must never count it.
//
// Anyone who can create pods can set a label. So the label counts only in the operator's
// namespace, and a workload that carries it anywhere else is no task pod: otherwise, setting it
// would hide a workload from triage.
func TestIsTaskPod(t *testing.T) {
	statuses := []corev1.ContainerStatus{status("scanner", repository+"@"+digestA)}
	newPod := func(namespace string, podLabels map[string]string) *corev1.Pod {
		return &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Labels: podLabels},
			Status:     corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: statuses},
		}
	}

	tests := []struct {
		name      string
		namespace string
		labels    map[string]string
		task      bool
	}{
		{
			name:      "a running pod with the task label in the operator's namespace is a task pod",
			namespace: operatorNamespace,
			labels:    map[string]string{taskLabel: scan},
			task:      true,
		},
		{
			name:      "the value of the task label does not matter",
			namespace: operatorNamespace,
			labels:    map[string]string{taskLabel: ""},
			task:      true,
		},
		{
			name:      "a pod with the task label in another namespace is a workload",
			namespace: "team-a",
			labels:    map[string]string{taskLabel: scan},
		},
		{
			name:      "a namespace that only starts with the operator's is another namespace",
			namespace: operatorNamespace + "-b",
			labels:    map[string]string{taskLabel: scan},
		},
		// The same pod without the label is a workload, so the label and the namespace together make
		// the difference.
		{
			name:      "a pod with other labels in the operator's namespace is a workload",
			namespace: operatorNamespace,
			labels:    map[string]string{"app": "scanner", "vexplain.bedag.ch/other": scan},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.task, workloads.IsTaskPod(newPod(tc.namespace, tc.labels), operatorNamespace))
		})
	}

	// Without an operator namespace there are no task pods: the label must never hide a pod on a
	// guess, not even one that has no namespace either.
	t.Run("without an operator namespace, the label hides nothing", func(t *testing.T) {
		require.False(t, workloads.IsTaskPod(newPod("", map[string]string{taskLabel: scan}), ""))
	})
}

// vexplain names the label of its own pods in the context of a collector's Watch, so a collector reads
// it from there rather than from TaskLabel. Like the task label, it counts only in vexplain's namespace,
// and without a label or a namespace no pod is vexplain's own: nothing is hidden on a guess.
func TestIsOwnPod(t *testing.T) {
	const ownLabel = "example.com/own-pod"
	tests := []struct {
		name                     string
		label, operatorNamespace string
		namespace                string
		labels                   map[string]string
		want                     bool
	}{
		{
			name: "a pod with the label in the operator's namespace is vexplain's own", label: ownLabel,
			operatorNamespace: operatorNamespace, namespace: operatorNamespace, labels: map[string]string{ownLabel: scan},
			want: true,
		},
		{
			name: "the value of the label doesn't matter", label: ownLabel,
			operatorNamespace: operatorNamespace, namespace: operatorNamespace, labels: map[string]string{ownLabel: ""},
			want: true,
		},
		{
			name: "a pod with the label in another namespace isn't", label: ownLabel,
			operatorNamespace: operatorNamespace, namespace: "team-a", labels: map[string]string{ownLabel: scan},
		},
		{
			name: "a pod with another label in the operator's namespace isn't", label: ownLabel,
			operatorNamespace: operatorNamespace, namespace: operatorNamespace, labels: map[string]string{taskLabel: scan},
		},
		{
			name: "without a label, no pod is", operatorNamespace: operatorNamespace, namespace: operatorNamespace,
			labels: map[string]string{ownLabel: scan},
		},
		{
			name: "without an operator namespace, no pod is", label: ownLabel,
			labels: map[string]string{ownLabel: scan},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: tc.namespace, Labels: tc.labels}}

			require.Equal(t, tc.want, workloads.IsOwnPod(pod, tc.label, tc.operatorNamespace))
		})
	}
}
