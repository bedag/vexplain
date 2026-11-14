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
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/bedag/vexplain/collectors/scanner/internal/result"
	collectorv1alpha1 "github.com/bedag/vexplain/sdk/api/collector/v1alpha1"
	"github.com/bedag/vexplain/sdk/collector"
	"github.com/bedag/vexplain/sdk/subject"
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
	return collectorPodOf(tagged, statuses...)
}

// collectorPodOf returns the collector's pod, whose spec names image as the image of the container named collector,
// with the statuses of its containers.
func collectorPodOf(image string, statuses ...corev1.ContainerStatus) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "vexplain-system", Name: "vexplain-collector-scanner-5d8f9-x2k4p"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{
			{Name: proxyContainer, Image: "artifacts.example/proxy:1.0"},
			{Name: collectorContainer, Image: image},
		}},
		Status: corev1.PodStatus{ContainerStatuses: statuses},
	}
}

// The scan Jobs run the collector's own image, by the digest that the container named collector runs, as its status
// reports it: a tag can name another build on a node that cached an older one. They take the digest only under the
// repository that the pod's spec names, both normalized, since a node finds the digest there. A node that imported an
// image reports its digest under a repository that it made up, and a node may know an image under another name: the
// reference of the pod's spec is all there is then, as without a repository digest in the status, and when the status
// says nothing for as long as the collector waits.
func TestTheOwnImageIsTheDigestThatTheCollectorContainerRuns(t *testing.T) {
	digest := runningDigest
	collectorRuns := func(imageID string) []corev1.ContainerStatus {
		return []corev1.ContainerStatus{{Name: collectorContainer, ImageID: imageID}}
	}
	for name, tc := range map[string]struct {
		spec     string
		statuses []corev1.ContainerStatus
		want     string
	}{
		"the digest under the repository of the spec": {
			spec: tagged,
			statuses: []corev1.ContainerStatus{
				{Name: proxyContainer, ImageID: "artifacts.example/proxy@sha256:" + strings.Repeat("f", 64)},
				{Name: collectorContainer, ImageID: "docker-pullable://artifacts.example/vexplain/scanner@" + digest},
			},
			want: "artifacts.example/vexplain/scanner@" + digest,
		},
		"the digest under the repository of a short name, which the status names in full": {
			spec:     "scanner:e2e",
			statuses: collectorRuns("docker.io/library/scanner@" + digest),
			want:     "docker.io/library/scanner@" + digest,
		},
		"the digest that the spec names already": {
			spec:     "artifacts.example/vexplain/scanner@" + digest,
			statuses: collectorRuns("artifacts.example/vexplain/scanner@" + digest),
			want:     "artifacts.example/vexplain/scanner@" + digest,
		},
		"a digest under a repository that the node made up when it imported the image": {
			spec:     tagged,
			statuses: collectorRuns("docker.io/library/import-2026-11-06@" + digest),
			want:     tagged,
		},
		"a digest under another name that the node knows the image by": {
			spec:     tagged,
			statuses: collectorRuns("mirror.example/vexplain/scanner@" + digest),
			want:     tagged,
		},
		"an image ID, which no registry serves": {spec: tagged, statuses: collectorRuns(digest), want: tagged},
		"no status yet":                         {spec: tagged, want: tagged},
	} {
		t.Run(name, func(t *testing.T) {
			pod := collectorPodOf(tc.spec, tc.statuses...)
			c := fake.NewClientBuilder().WithObjects(pod).Build()

			image, err := ownImage(t.Context(), c, pod.Namespace, pod.Name, 100*time.Millisecond)

			require.NoError(t, err)
			require.Equal(t, tc.want, image)
		})
	}
}

// When the scan Jobs run the image of the pod's spec, though the status names a digest, the collector says why, and it
// says nothing when they run the digest.
func TestTheCollectorSaysWhyItsScanJobsRunTheImageOfItsSpec(t *testing.T) {
	image, why := runningImage(tagged, "artifacts.example/vexplain/scanner@"+runningDigest)
	require.Equal(t, "artifacts.example/vexplain/scanner@"+runningDigest, image)
	require.Empty(t, why)

	image, why = runningImage(tagged, "docker.io/library/import-2026-11-06@"+runningDigest)
	require.Equal(t, tagged, image)
	require.Contains(t, why, "another repository")

	image, why = runningImage(tagged, runningDigest)
	require.Equal(t, tagged, image)
	require.Contains(t, why, "no repository digest")
}

// The kubelet reports the image of a container that started a moment after it started, so the collector, which reads
// its pod when a scan first needs it, waits for the report.
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

// Without the namespace that vexplain's deployer sets, there is nowhere to run the scan Jobs.
func TestServeNeedsItsNamespace(t *testing.T) {
	err := serve(t.Context(), nil, collector.Options{}, func(string) string { return "" })

	require.ErrorContains(t, err, namespaceVariable)
}

// collectorNamespace is the namespace of the collector, which vexplain's deployer sets.
const collectorNamespace = "vexplain-system"

// The collector starts without its permissions: vexplain grants them once it has read what the collector declares
// (decision 0041). So it answers GetInfo and GetCapabilities with an API server that refuses it everything, without
// reading anything of the cluster, and a scan that fails on a refused read fails alone: the collector serves on.
func TestServeAnswersTheIdentityCallsWithoutAnyPermission(t *testing.T) {
	var requests atomic.Int32
	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w,
			`{"kind": "Status", "apiVersion": "v1", "status": "Failure", "reason": "Forbidden", "code": 403}`)
	}))
	t.Cleanup(apiServer.Close)
	defer slog.SetDefault(slog.Default())
	slog.SetDefault(slog.New(slog.DiscardHandler))
	listener := bufconn.Listen(1 << 20)
	health, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- serve(ctx, &rest.Config{Host: apiServer.URL},
			collector.Options{Insecure: true, GRPCListener: listener, HealthListener: health},
			func(name string) string { return map[string]string{namespaceVariable: collectorNamespace}[name] })
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return listener.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	identity := collectorv1alpha1.NewIdentityClient(conn)

	info, err := identity.GetInfo(ctx, &collectorv1alpha1.GetInfoRequest{})
	require.NoError(t, err)
	require.Equal(t, defaultName, info.GetName())
	caps, err := identity.GetCapabilities(ctx, &collectorv1alpha1.GetCapabilitiesRequest{})
	require.NoError(t, err)
	require.NotEmpty(t, caps.GetPermissions())
	require.Zero(t, requests.Load(), "the collector read nothing of the cluster")

	require.Len(t, caps.GetOperations(), 1)
	stream, err := collectorv1alpha1.NewEvidenceClient(conn).Invoke(ctx, &collectorv1alpha1.InvokeRequest{
		Operation: caps.GetOperations()[0].GetName(), Subject: subject.Image(runningDigest),
		Role: collectorv1alpha1.Role_ROLE_SPOKE, Settings: []byte(`{}`),
		Parameters: []byte(`{"repositories": ["artifacts.example/team-a/app"],
			"pods": [{"namespace": "team-a", "name": "app-0"}]}`),
	})
	require.NoError(t, err)
	_, err = stream.Recv()
	require.Error(t, err, "the scan reads the cluster, which refuses it")
	require.NotZero(t, requests.Load())
	_, err = identity.GetInfo(ctx, &collectorv1alpha1.GetInfoRequest{})
	require.NoError(t, err, "the collector serves on")
	select {
	case err := <-done:
		require.Fail(t, "the collector stopped", "%v", err)
	default:
	}
}

// The collector reads its own image the first time a scan needs it, and keeps it. A read that the API server refuses,
// before vexplain has granted the collector its permissions, fails that scan with what refused it, and the next scan
// reads again.
func TestTheOwnImageIsReadWhenAScanFirstNeedsItAndKept(t *testing.T) {
	pod := collectorPod(corev1.ContainerStatus{
		Name: collectorContainer, ImageID: "artifacts.example/vexplain/scanner@" + runningDigest,
	})
	refuse, reads := true, 0
	c := fake.NewClientBuilder().WithObjects(pod).WithInterceptorFuncs(interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object,
			opts ...client.GetOption) error {
			reads++
			if refuse {
				return apierrors.NewForbidden(corev1.Resource("pods"), key.Name, errors.New("no permission yet"))
			}
			return c.Get(ctx, key, obj, opts...)
		},
	}).Build()
	image := ownImageOnce(c, pod.Namespace, pod.Name)
	require.Zero(t, reads, "nothing is read before a scan needs the image")

	_, err := image(t.Context())
	require.True(t, apierrors.IsForbidden(err), err)
	require.ErrorContains(t, err, "read the collector's pod "+pod.Namespace+"/"+pod.Name)

	refuse = false
	got, err := image(t.Context())
	require.NoError(t, err)
	require.Equal(t, "artifacts.example/vexplain/scanner@"+runningDigest, got)
	read := reads
	got, err = image(t.Context())
	require.NoError(t, err)
	require.Equal(t, "artifacts.example/vexplain/scanner@"+runningDigest, got)
	require.Equal(t, read, reads, "the image is kept once read")
}
