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
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/bedag/vexplain/internal/scan/result"
	"github.com/bedag/vexplain/internal/tasks"
	sdkevidence "github.com/bedag/vexplain/sdk/evidence"
	subjects "github.com/bedag/vexplain/sdk/subject"
)

// These tests cover what the runner decides on its own: the evidence that it makes of a scan, where
// an image is pulled from, and which events name a digest.

// The scanner's evidence about each manifest is a CloudEvent of the scanner's type about the
// manifest, with its platform, its completeness as the coverage, the time the scan ended, and the
// manifest's JSON as the data. Its source is the scanner of this cluster.
func TestScanEventsAreTheScannersEvidenceAboutEachManifest(t *testing.T) {
	scanned := time.Date(2026, time.October, 30, 12, 0, 0, 0, time.UTC)
	amd64 := result.Manifest{
		Platform: linuxAMD64, Digest: amd64Manifest, SBOM: json.RawMessage(`{"artifacts":[{"id":"pkg-1"}]}`),
		Packages: []result.PackageFacts{{ID: "pkg-1", FilesListed: 2, FilesPresent: 2, SharedLibraries: 1}},
		ELF:      result.ELFSummary{Total: 4, Owned: 3},
	}
	arm64 := amd64
	arm64.Platform, arm64.Digest = "linux/arm64/v8", "sha256:"+strings.Repeat("2", 64)

	events, err := scanEvents("cluster-a", scanned, []result.Manifest{amd64, arm64})

	require.NoError(t, err)
	require.Len(t, events, 2)
	for i, m := range []result.Manifest{amd64, arm64} {
		e := events[i]
		require.NoError(t, sdkevidence.Validate(e), "the event is evidence")
		require.Equal(t, result.EvidenceType, e.Type())
		require.Equal(t, subjects.Manifest(m.Digest), e.Subject())
		require.Equal(t, "/clusters/cluster-a/collectors/scanner", e.Source())
		require.Equal(t, scanned, e.Time())
		platform, _ := sdkevidence.Platform(e)
		require.Equal(t, m.Platform, platform)
		coverage, _ := sdkevidence.Coverage(e)
		require.Equal(t, int32(75), coverage, "the completeness of the manifest")
		var data result.Manifest
		require.NoError(t, json.Unmarshal(e.Data(), &data))
		require.Equal(t, m, data, "the data is the manifest's JSON")
	}
	require.NotEqual(t, events[0].ID(), events[1].ID(), "each event has an id of its own")
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
