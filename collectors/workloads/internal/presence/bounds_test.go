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

package presence

import (
	"fmt"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	toolscache "k8s.io/client-go/tools/cache"
	"k8s.io/utils/ptr"

	"github.com/bedag/vexplain/sdk/evidence"
	"github.com/bedag/vexplain/sdk/workloads"
)

// initContainer is the init container of the pod of a test.
const initContainer = "init"

// An event lists at most 16 pods of a workload: one of each platform that the workload runs on, and then the others
// by name. What reads the pods needs no more: the spoke's executor names at most 16 pods of an image in a request, one
// of each platform first, and the inventory and the reports read the platforms only. A workload of many replicas, such
// as a DaemonSet on every node, so adds no more to an event than one of 16. The workload, and its namespace, are
// listed all the same.
func TestAWorkloadListsAtMostSixteenOfItsPodsWithOneOfEachPlatform(t *testing.T) {
	ns := newNamespace(t, nil, nil).Name
	_, rs := deployment(t, ns)
	digest := newDigest()
	owner := controlledBy(rs, "apps/v1", "ReplicaSet")
	for i := range 20 {
		pod{namespace: ns, name: fmt.Sprintf("web-%02d", i), node: nodeAMD64, owner: owner}.run(t, digest)
	}
	pod{namespace: ns, name: "web-98", node: nodeBare, owner: owner}.run(t, digest)
	pod{namespace: ns, name: "web-99", node: nodeARM64, owner: owner}.run(t, digest)
	other := newNamespace(t, nil, nil).Name
	pod{namespace: other, name: toolPod, node: nodeAMD64}.run(t, digest)

	got := buildFor(t, contextFor("vexplain-system", everything, "")).images[digest]

	require.Len(t, got.Workloads, 2, "every workload that runs the image, in every namespace")
	i := slices.IndexFunc(got.Workloads, func(w evidence.PresenceWorkload) bool { return w.Namespace == ns })
	require.GreaterOrEqual(t, i, 0)
	names := make([]string, 0, len(got.Workloads[i].Pods))
	platforms := map[string]bool{}
	for _, p := range got.Workloads[i].Pods {
		names = append(names, p.Name)
		platforms[p.Platform] = true
	}
	want := make([]string, 0, maxPodsPerWorkload)
	for i := range 14 {
		want = append(want, fmt.Sprintf("web-%02d", i))
	}
	require.Equal(t, append(want, "web-98", "web-99"), names, "one of each platform, then the others by name")
	require.Equal(t, map[string]bool{platformAMD64: true, platformARM64: true, "": true}, platforms)
}

// A workload on more platforms than the bound keeps one pod of each: no platform that it runs on is lost.
func TestBoundPodsKeepsOneOfEachPlatform(t *testing.T) {
	pods := make([]evidence.PresencePod, 0, 40)
	for i := range 20 {
		pods = append(pods, evidence.PresencePod{Name: fmt.Sprintf("pod-%02d-a", i), Platform: fmt.Sprintf("linux/arch%02d", i)},
			evidence.PresencePod{Name: fmt.Sprintf("pod-%02d-b", i), Platform: fmt.Sprintf("linux/arch%02d", i)})
	}
	slices.SortFunc(pods, compareNames)

	kept := boundPods(pods)

	require.Len(t, kept, 20)
	for i, p := range kept {
		require.Equal(t, fmt.Sprintf("pod-%02d-a", i), p.Name)
	}
	require.Equal(t, pods[:3], boundPods(pods[:3]), "a workload within the bound keeps every pod")
}

// The collector's cache of pods keeps what presence reads of a pod, and nothing else: no environment variable, no
// command, no other annotation, no volume, none of the spec but the name and the image of each container and the
// restart policy of each init container, none of the status but the phase and what each container reports of its
// image. The cache of a whole cluster's pods would otherwise hold all of them.
func TestThePodCacheKeepsOnlyWhatPresenceReads(t *testing.T) {
	const secret = "marker-secret-value"
	always := corev1.ContainerRestartPolicyAlways
	owner := metav1.OwnerReference{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "web-5d8f9", UID: "uid-rs",
		Controller: ptr.To(true)}
	full := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: webPod, Namespace: team, UID: "uid-pod", ResourceVersion: "42", Generation: 3,
			Labels:          map[string]string{appLabel: web},
			Annotations:     map[string]string{corev1.MirrorPodAnnotationKey: "mirror", "example.com/note": secret},
			OwnerReferences: []metav1.OwnerReference{owner},
			ManagedFields:   []metav1.ManagedFieldsEntry{{Manager: "kubelet"}},
		},
		Spec: corev1.PodSpec{
			NodeName:           nodeAMD64,
			ServiceAccountName: "web",
			InitContainers: []corev1.Container{{Name: initContainer, Image: repository + ":1.0", RestartPolicy: &always,
				Env: []corev1.EnvVar{{Name: "TOKEN", Value: secret}}}},
			Containers: []corev1.Container{{Name: appContainer, Image: repository + ":1.0", Command: []string{secret},
				Env: []corev1.EnvVar{{Name: "PASSWORD", Value: secret}}}},
			Volumes: []corev1.Volume{{Name: "data"}},
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning, PodIP: "10.0.0.1", Message: secret,
			InitContainerStatuses: []corev1.ContainerStatus{{Name: initContainer, Image: repository + ":1.0",
				ImageID: repository + "@" + digestOf(1), RestartCount: 1}},
			ContainerStatuses: []corev1.ContainerStatus{{Name: appContainer, Image: repository + ":1.0",
				ImageID: repository + "@" + digestOf(2), Ready: true, RestartCount: 3}},
		},
	}

	trimmed, err := CacheOptions().DefaultTransform(full.DeepCopy())

	require.NoError(t, err)
	require.Equal(t, &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: webPod, Namespace: team, UID: "uid-pod", ResourceVersion: "42", Generation: 3,
			Labels:          map[string]string{appLabel: web},
			Annotations:     map[string]string{corev1.MirrorPodAnnotationKey: "mirror"},
			OwnerReferences: []metav1.OwnerReference{owner},
		},
		Spec: corev1.PodSpec{
			NodeName:       nodeAMD64,
			InitContainers: []corev1.Container{{Name: initContainer, Image: repository + ":1.0", RestartPolicy: &always}},
			Containers:     []corev1.Container{{Name: appContainer, Image: repository + ":1.0"}},
		},
		Status: corev1.PodStatus{
			Phase:                 corev1.PodRunning,
			InitContainerStatuses: []corev1.ContainerStatus{{Name: initContainer, ImageID: repository + "@" + digestOf(1)}},
			ContainerStatuses:     []corev1.ContainerStatus{{Name: appContainer, ImageID: repository + "@" + digestOf(2)}},
		},
	}, trimmed)
	require.NotContains(t, fmt.Sprintf("%#v", trimmed), secret)

	// What build reads of the pod is the same, trimmed or whole.
	trimmedPod := trimmed.(*corev1.Pod)
	wholeImages, wholeUnparsable := workloads.PodImages(full)
	trimmedImages, trimmedUnparsable := workloads.PodImages(trimmedPod)
	require.Equal(t, wholeImages, trimmedImages)
	require.Equal(t, wholeUnparsable, trimmedUnparsable)
	require.Equal(t, pending(full), pending(trimmedPod))
	require.False(t, podChanged(full, trimmedPod), "presence reads nothing of a pod that its trim drops")

	// Metadata loses its managed fields, as before, and what isn't an object, as the tombstone of a deletion, stays.
	metadata := &metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{Name: team,
		ManagedFields: []metav1.ManagedFieldsEntry{{Manager: "kubectl"}}}}
	stripped, err := CacheOptions().DefaultTransform(metadata)
	require.NoError(t, err)
	require.Empty(t, stripped.(*metav1.PartialObjectMetadata).ManagedFields)
	tombstone := toolscache.DeletedFinalStateUnknown{Key: team + "/" + webPod, Obj: full}
	left, err := CacheOptions().DefaultTransform(tombstone)
	require.NoError(t, err)
	require.Equal(t, tombstone, left)
}

// digestOf returns the n-th digest of a test that needs no unique one.
func digestOf(n int) string {
	return fmt.Sprintf("sha256:%064x", n)
}
