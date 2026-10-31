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
	"math"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/tasks"
)

// These tests cover what the runner decides on its own: the facts of a failed scan, where an image
// is pulled from, and which events name a digest.

// lastSuccess is the facts of the last successful scan of a digest.
func lastSuccess() *inventoryv1alpha1.ImageFacts {
	return &inventoryv1alpha1.ImageFacts{
		ScannerImage: ptr.To("scanner.example/vexplain-scanner:0.9"),
		ScannedTime:  ptr.To(metav1.NewTime(time.Date(2026, time.October, 1, 12, 0, 0, 0, time.UTC))),
		Platforms: []inventoryv1alpha1.PlatformFacts{{
			Platform: linuxAMD64, ManifestDigest: amd64Manifest,
			CompletenessPercent: ptr.To(int32(75)), ELFFiles: ptr.To(int32(4)), Packages: ptr.To(int32(1)),
		}},
	}
}

// A failure keeps what the last successful scan found, and counts one failure more than the facts
// did: the hub waits longer before it asks again after each one.
func TestFailureFactsCountTheFailuresInARow(t *testing.T) {
	failed := time.Date(2026, time.October, 30, 12, 0, 0, 0, time.UTC)
	earlier := lastSuccess()
	earlier.Failure = &inventoryv1alpha1.ScanFailure{
		Reason: inventoryv1alpha1.ScanFailureReasonPullFailed, Time: ptr.To(metav1.NewTime(failed.Add(-time.Hour))), Attempts: 2,
	}

	facts := failureFacts(earlier, inventoryv1alpha1.ScanFailureReasonUnauthorized, failed)

	want := lastSuccess()
	want.Failure = &inventoryv1alpha1.ScanFailure{
		Reason: inventoryv1alpha1.ScanFailureReasonUnauthorized, Time: ptr.To(metav1.NewTime(failed)), Attempts: 3,
	}
	require.Equal(t, want, facts)
	require.Equal(t, int32(2), earlier.Failure.Attempts, "the facts that were read stay as they were")
}

func TestFailureFactsOfAFirstFailure(t *testing.T) {
	failed := time.Date(2026, time.October, 30, 12, 0, 0, 0, time.UTC)

	require.Equal(t, &inventoryv1alpha1.ImageFacts{Failure: &inventoryv1alpha1.ScanFailure{
		Reason: inventoryv1alpha1.ScanFailureReasonTimedOut, Time: ptr.To(metav1.NewTime(failed)), Attempts: 1,
	}}, failureFacts(nil, inventoryv1alpha1.ScanFailureReasonTimedOut, failed), "a digest that was never scanned")

	want := lastSuccess()
	want.Failure = &inventoryv1alpha1.ScanFailure{
		Reason: inventoryv1alpha1.ScanFailureReasonTimedOut, Time: ptr.To(metav1.NewTime(failed)), Attempts: 1,
	}
	require.Equal(t, want, failureFacts(lastSuccess(), inventoryv1alpha1.ScanFailureReasonTimedOut, failed))
}

// The count stops at the largest that the API holds, rather than wrap around to a negative count,
// which the API would refuse.
func TestFailureFactsStopCountingAtTheLargestCount(t *testing.T) {
	earlier := &inventoryv1alpha1.ImageFacts{Failure: &inventoryv1alpha1.ScanFailure{
		Reason: inventoryv1alpha1.ScanFailureReasonInternal, Time: ptr.To(metav1.Now()), Attempts: math.MaxInt32,
	}}

	facts := failureFacts(earlier, inventoryv1alpha1.ScanFailureReasonInternal, time.Now())

	require.Equal(t, int32(math.MaxInt32), facts.Failure.Attempts)
}

// runningOn returns a pod in namespace that reports requestedDigest, pulled from repository.
func runningOn(namespace, name, repository string) corev1.Pod {
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{
			Name: "app", ImageID: repository + "@" + requestedDigest,
		}}},
	}
}

// The image is pulled from a repository of the request, with the credentials of a pod that pulled
// it from there: its pull secrets are for that registry.
func TestPullSourceIsAPodThatPulledFromARepositoryOfTheRequest(t *testing.T) {
	pods := []corev1.Pod{
		runningOn("team-a", "app-0", "mirror.example/team-a/app"),
		runningOn("team-b", "app-0", appRepository),
	}

	pod, repository := pullSource(pods, tasks.ScanRequest{
		Digest: requestedDigest, Repositories: []string{"other.example/team-a/app", appRepository},
	})

	require.Equal(t, "team-b", pod.Namespace)
	require.Equal(t, appRepository, repository)
}

// When no pod pulled the digest from a repository of the request, as when the presence came from
// another cluster, the first pod pulls from the request's first repository. The pick doesn't depend
// on the order in which the pods come.
func TestPullSourceFallsBackToTheFirstRepositoryOfTheRequest(t *testing.T) {
	request := tasks.ScanRequest{Digest: requestedDigest, Repositories: []string{appRepository, "mirror.example/team-a/app"}}
	pods := []corev1.Pod{
		runningOn("team-b", "app-0", "other.example/team-b/app"),
		runningOn("team-a", "app-1", "other.example/team-a/app"),
		runningOn("team-a", "app-0", "other.example/team-a/app"),
	}

	pod, repository := pullSource(pods, request)

	require.Equal(t, "team-a/app-0", pod.Namespace+"/"+pod.Name)
	require.Equal(t, appRepository, repository)
}

// A scan Job or pod whose annotation names no digest names no scan.
func TestDigestOfAScanTaskComesFromItsAnnotation(t *testing.T) {
	r := &Runner{OperatorNamespace: "vexplain-system"}
	pod := func(annotation string) *corev1.Pod {
		return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "vexplain-system", Name: "scan-0",
			Annotations: map[string]string{DigestLabel: annotation}}}
	}

	require.Equal(t, []reconcile.Request{requestFor(requestedDigest)}, r.digestOf(t.Context(), pod(requestedDigest)))
	require.Empty(t, r.digestOf(t.Context(), pod(requestedDigest[:70])))
	require.Empty(t, r.digestOf(t.Context(), &corev1.Pod{}))
}

// Only a container that the runtime started can have a log, as the kubelet sees it: one that waits,
// one that the kubelet lost track of, and one that has no status at all have none.
func TestScannerRanTellsWhetherTheScannerCanHaveALog(t *testing.T) {
	containerID := "containerd://" + strings.Repeat("c", 64)
	cases := []struct {
		name     string
		statuses []corev1.ContainerStatus
		ran      bool
	}{
		{"no status", nil, false},
		{"waiting", []corev1.ContainerStatus{{Name: scannerContainer,
			State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "ContainerCreating"}}}}, false},
		{"running", []corev1.ContainerStatus{{Name: scannerContainer,
			State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}}, true},
		{"terminated", []corev1.ContainerStatus{{Name: scannerContainer,
			State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 1, ContainerID: containerID}}}}, true},
		{"terminated, and lost by the kubelet", []corev1.ContainerStatus{{Name: scannerContainer,
			State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 137, Reason: "ContainerStatusUnknown"}}}}, false},
		{"terminated before, and lost since", []corev1.ContainerStatus{{Name: scannerContainer,
			State:                corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 137, Reason: "ContainerStatusUnknown"}},
			LastTerminationState: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 1, ContainerID: containerID}}}}, true},
		{"another container", []corev1.ContainerStatus{{Name: "sidecar",
			State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 0, ContainerID: containerID}}}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pod := &corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodFailed, ContainerStatuses: tc.statuses}}

			require.Equal(t, tc.ran, scannerRan(pod))
		})
	}
}
