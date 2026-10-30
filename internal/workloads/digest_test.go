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
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/bedag/vexplain/internal/workloads"
)

// repository is the repository of the images that were pulled from one.
const repository = "artifacts.example/lib/nginx"

// The digests of the fixtures. hexDigits holds every hex digit, so a pattern that accepts only
// some of them fails. digestA, digestB and digestC differ from each other and sort in that order.
var (
	hexDigits = strings.Repeat("0123456789abcdef", 4)
	digest    = "sha256:" + hexDigits
	digestA   = "sha256:" + strings.Repeat("a", 64)
	digestB   = "sha256:" + strings.Repeat("b", 64)
	digestC   = "sha256:" + strings.Repeat("c", 64)
)

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

func TestPodImages(t *testing.T) {
	t.Run("an init and an app container with the same digest give one image", func(t *testing.T) {
		pod := &corev1.Pod{Status: corev1.PodStatus{
			InitContainerStatuses: []corev1.ContainerStatus{status("init", repository+"@"+digestA)},
			ContainerStatuses:     []corev1.ContainerStatus{status("web", repository+"@"+digestA)},
		}}

		images, unparsable := workloads.PodImages(pod)

		require.Equal(t, []workloads.ImageRef{{Digest: digestA, Repository: repository}}, images)
		require.Empty(t, unparsable)
	})

	// The init containers are read before the containers, so the repository of an init container
	// is the first one seen.
	t.Run("the image keeps the first repository seen", func(t *testing.T) {
		pod := &corev1.Pod{Status: corev1.PodStatus{
			InitContainerStatuses: []corev1.ContainerStatus{status("init", repository+"@"+digestA)},
			ContainerStatuses:     []corev1.ContainerStatus{status("web", "mirror.example/lib/nginx@"+digestA)},
		}}

		images, _ := workloads.PodImages(pod)

		require.Equal(t, []workloads.ImageRef{{Digest: digestA, Repository: repository}}, images)
	})

	t.Run("an ephemeral container is skipped", func(t *testing.T) {
		pod := &corev1.Pod{Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{status("web", repository+"@"+digestA)},
			EphemeralContainerStatuses: []corev1.ContainerStatus{
				status("debug", "debug.example/tools@"+digestC),
				// Neither does its imageID count as unparsable.
				status("debug-2", "busybox:1.37"),
			},
		}}

		images, unparsable := workloads.PodImages(pod)

		require.Equal(t, []workloads.ImageRef{{Digest: digestA, Repository: repository}}, images)
		require.Empty(t, unparsable)
	})

	t.Run("a pending pod gives no images and nothing unparsable", func(t *testing.T) {
		pod := &corev1.Pod{Status: corev1.PodStatus{
			InitContainerStatuses: []corev1.ContainerStatus{status("init", "")},
			ContainerStatuses:     []corev1.ContainerStatus{status("web", "")},
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
			ContainerStatuses: []corev1.ContainerStatus{status("web", "nginx:1.27")},
		}}

		images, unparsable := workloads.PodImages(pod)

		require.Empty(t, images)
		require.Equal(t, []string{"web"}, unparsable)
	})

	// One container the operator can't read must neither hide the others nor be dropped silently.
	// The names come in the order the statuses were read, init containers first.
	t.Run("unparsable containers don't hide the other images", func(t *testing.T) {
		pod := &corev1.Pod{Status: corev1.PodStatus{
			InitContainerStatuses: []corev1.ContainerStatus{status("setup", "nginx:1.27")},
			ContainerStatuses: []corev1.ContainerStatus{
				status("web", repository+"@"+digestA),
				status("sidecar", "busybox:1.37"),
				status("starting", ""),
			},
		}}

		images, unparsable := workloads.PodImages(pod)

		require.Equal(t, []workloads.ImageRef{{Digest: digestA, Repository: repository}}, images)
		require.Equal(t, []string{"setup", "sidecar"}, unparsable)
	})

	t.Run("the images are sorted by digest", func(t *testing.T) {
		pod := &corev1.Pod{Status: corev1.PodStatus{
			InitContainerStatuses: []corev1.ContainerStatus{status("init", "init.example/setup@"+digestC)},
			ContainerStatuses: []corev1.ContainerStatus{
				status("web", repository+"@"+digestB),
				status("sidecar", "sidecar.example/proxy@"+digestA),
			},
		}}

		images, _ := workloads.PodImages(pod)

		require.Equal(t, []workloads.ImageRef{
			{Digest: digestA, Repository: "sidecar.example/proxy"},
			{Digest: digestB, Repository: repository},
			{Digest: digestC, Repository: "init.example/setup"},
		}, images)
	})

	t.Run("an image ID has no repository", func(t *testing.T) {
		pod := &corev1.Pod{Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{status("web", "docker://"+digestA)},
		}}

		images, unparsable := workloads.PodImages(pod)

		require.Equal(t, []workloads.ImageRef{{Digest: digestA}}, images)
		require.True(t, images[0].IsImageID())
		require.Empty(t, unparsable)
	})
}

func TestIndexPodDigests(t *testing.T) {
	t.Run("a pod is indexed by the digests of its images", func(t *testing.T) {
		pod := &corev1.Pod{Status: corev1.PodStatus{
			InitContainerStatuses: []corev1.ContainerStatus{status("init", repository+"@"+digestB)},
			ContainerStatuses: []corev1.ContainerStatus{
				status("web", repository+"@"+digestA),
				status("sidecar", repository+"@"+digestB),
				status("broken", "nginx:1.27"),
			},
			EphemeralContainerStatuses: []corev1.ContainerStatus{status("debug", repository+"@"+digestC)},
		}}

		require.Equal(t, []string{digestA, digestB}, workloads.IndexPodDigests(pod))
	})

	t.Run("a pending pod has no keys", func(t *testing.T) {
		pod := &corev1.Pod{Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{status("web", "")}}}

		require.Empty(t, workloads.IndexPodDigests(pod))
	})

	t.Run("an object that is not a pod has no keys", func(t *testing.T) {
		require.Nil(t, workloads.IndexPodDigests(&corev1.Namespace{}))
		require.Nil(t, workloads.IndexPodDigests(nil))
	})
}

// A task pod is one that the operator runs for itself, such as a scan pod. It runs images, but it
// is no workload of the cluster, so the inventory must never count it. The label key is spelled
// out and not read from workloads.TaskLabel, so that the test pins the name that scan pods carry.
func TestIndexPodDigestsSkipsTaskPods(t *testing.T) {
	statuses := []corev1.ContainerStatus{status("scanner", repository+"@"+digestA)}
	newPod := func(podLabels map[string]string) *corev1.Pod {
		return &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Labels: podLabels},
			Status:     corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: statuses},
		}
	}

	t.Run("a running pod with the task label has no keys", func(t *testing.T) {
		pod := newPod(map[string]string{"vexplain.bedag.ch/task": "scan"})

		require.Nil(t, workloads.IndexPodDigests(pod))
	})

	t.Run("the value of the task label does not matter", func(t *testing.T) {
		pod := newPod(map[string]string{"vexplain.bedag.ch/task": ""})

		require.Nil(t, workloads.IndexPodDigests(pod))
	})

	// The same pod without the label is indexed, so the label alone makes the difference.
	t.Run("a pod with other labels is indexed", func(t *testing.T) {
		pod := newPod(map[string]string{"app": "scanner", "vexplain.bedag.ch/other": "scan"})

		require.Equal(t, []string{digestA}, workloads.IndexPodDigests(pod))
	})
}
