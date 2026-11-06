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

package main

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/bedag/vexplain/collectors/scanner/internal/result"
	"github.com/bedag/vexplain/sdk/collector"
)

// These tests cover the subcommands of the binary, and what serve reads from its environment and its own pod. The
// tests of scan are in main_test.go, and those of the collector that serve serves in internal/scan.

// A scan Job runs the binary with the subcommand scan, which is the scan of phase 2a.
func TestTheSubcommandScanScans(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := dispatch(context.Background(), []string{"scan", "--image", "not a reference"},
		func(string) string { return "" }, &stdout, &stderr)

	require.Equal(t, exitFailed, code)
	require.Equal(t, result.EncodeError(result.ErrorReasonInternal)+"\n", stdout.String(), "a bad flag fails the scan")
}

func TestAnUnknownSubcommandIsRefused(t *testing.T) {
	for _, args := range [][]string{nil, {"--image", "artifacts.example/team-a/app@sha256:0"}, {"watch"}} {
		var stdout, stderr bytes.Buffer

		code := dispatch(context.Background(), args, func(string) string { return "" }, &stdout, &stderr)

		require.Equal(t, exitUsage, code, "%q", args)
		require.Empty(t, stdout.String(), "stdout is the scan's line, and there is none")
		require.Contains(t, stderr.String(), "usage")
	}
}

// The collector reads the cluster that it runs in, and no other, so outside a cluster it doesn't start.
func TestServeOutsideAClusterFails(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")
	defer slog.SetDefault(slog.Default())
	slog.SetDefault(slog.New(slog.DiscardHandler))

	code := dispatch(context.Background(), []string{"serve"}, func(string) string { return "" }, &bytes.Buffer{},
		&bytes.Buffer{})

	require.Equal(t, exitFailed, code)
	require.Equal(t, exitUsage, dispatch(context.Background(), []string{"serve", "--port", "1"},
		func(string) string { return "" }, &bytes.Buffer{}, &bytes.Buffer{}))
}

// tagged is the image of the collector's container in its pod's spec, and runningDigest the digest that it runs.
// proxyContainer is another container of the pod.
const (
	tagged         = "artifacts.example/vexplain/scanner:0.2.0"
	proxyContainer = "proxy"
)

var runningDigest = "sha256:" + strings.Repeat("e", 64)

// collectorPod returns the collector's pod, with the statuses of its containers.
func collectorPod(statuses ...corev1.ContainerStatus) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "vexplain-system", Name: "vexplain-collector-scanner-5d8f9-x2k4p"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{
			{Name: proxyContainer, Image: "artifacts.example/proxy:1.0"},
			{Name: collectorContainer, Image: tagged},
		}},
		Status: corev1.PodStatus{ContainerStatuses: statuses},
	}
}

// The scan Jobs run the collector's own image, by the digest that the container named collector runs, as its status
// reports it: a tag can name another build on a node that cached an older one. Without a repository digest in the
// status, as for an image that was loaded onto the node, the reference of the pod's spec is all there is, and so it is
// when the status says nothing for as long as the collector waits.
func TestTheOwnImageIsTheDigestThatTheCollectorContainerRuns(t *testing.T) {
	digest := runningDigest
	podWith := collectorPod
	for name, tc := range map[string]struct {
		pod  *corev1.Pod
		want string
	}{
		"the repository digest that the container runs": {
			pod: podWith(
				corev1.ContainerStatus{Name: proxyContainer, ImageID: "artifacts.example/proxy@sha256:" + strings.Repeat("f", 64)},
				corev1.ContainerStatus{
					Name: collectorContainer, ImageID: "docker-pullable://artifacts.example/vexplain/scanner@" + digest,
				},
			),
			want: "artifacts.example/vexplain/scanner@" + digest,
		},
		"an image ID, which no registry serves": {
			pod:  podWith(corev1.ContainerStatus{Name: collectorContainer, ImageID: digest}),
			want: tagged,
		},
		"no status yet": {pod: podWith(), want: tagged},
	} {
		t.Run(name, func(t *testing.T) {
			c := fake.NewClientBuilder().WithObjects(tc.pod).Build()

			image, err := ownImage(t.Context(), c, tc.pod.Namespace, tc.pod.Name, 100*time.Millisecond)

			require.NoError(t, err)
			require.Equal(t, tc.want, image)
		})
	}
}

// The kubelet reports the image of a container that started a moment after it started, so the collector, which reads
// its pod as it starts, waits for the report.
func TestTheOwnImageWaitsForTheContainerToReportIt(t *testing.T) {
	pod := collectorPod()
	c := fake.NewClientBuilder().WithObjects(pod).WithStatusSubresource(pod).Build()
	go func() {
		time.Sleep(200 * time.Millisecond)
		pod.Status.ContainerStatuses = []corev1.ContainerStatus{
			{Name: collectorContainer, ImageID: "artifacts.example/vexplain/scanner@" + runningDigest},
		}
		_ = c.Status().Update(context.Background(), pod)
	}()

	image, err := ownImage(t.Context(), c, pod.Namespace, pod.Name, 10*time.Second)

	require.NoError(t, err)
	require.Equal(t, "artifacts.example/vexplain/scanner@"+runningDigest, image)
}

// Without its own pod, or the container named collector, the collector can't say what its scan Jobs run.
func TestTheOwnImageNeedsTheCollectorsPod(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "vexplain-system", Name: "vexplain-collector-scanner-5d8f9-x2k4p"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{
			{Name: proxyContainer, Image: "artifacts.example/proxy:1.0"},
		}},
	}
	c := fake.NewClientBuilder().WithObjects(pod).Build()

	_, err := ownImage(t.Context(), c, pod.Namespace, "another-pod", time.Second)
	require.Error(t, err)
	_, err = ownImage(t.Context(), c, pod.Namespace, pod.Name, time.Second)
	require.Error(t, err, "a pod without the container named collector")
}

// The scan Jobs get the collector's proxy, as far as it is set, and no other variable.
func TestTheScanJobsGetTheProxyVariablesOnly(t *testing.T) {
	environment := map[string]string{
		httpsProxyVariable: "http://proxy.example:3128",
		noProxyVariable:    "10.0.0.0/8,.cluster.local",
		"http_proxy":       "",
		"ALL_PROXY":        "socks5://proxy.example:1080",
		"PATH":             "/usr/bin",
	}

	env := proxyEnv(func(name string) string { return environment[name] })

	require.Equal(t, []corev1.EnvVar{
		{Name: httpsProxyVariable, Value: "http://proxy.example:3128"},
		{Name: noProxyVariable, Value: "10.0.0.0/8,.cluster.local"},
	}, env)
}

// Without the namespace that vexplain's deployer sets, there is nowhere to run the scan Jobs.
func TestServeNeedsItsNamespace(t *testing.T) {
	err := serve(t.Context(), nil, collector.Options{}, func(string) string { return "" })

	require.ErrorContains(t, err, namespaceVariable)
}
