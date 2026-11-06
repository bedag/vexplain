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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/encoding/gzip"
	"google.golang.org/grpc/test/bufconn"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/rand"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	collectorv1alpha1 "github.com/bedag/vexplain/sdk/api/collector/v1alpha1"
	"github.com/bedag/vexplain/sdk/collector"
	"github.com/bedag/vexplain/sdk/conformance"
)

// The tests run the collector as main does, with the cache and the registry that serve builds, against an API server
// of envtest. They call it over gRPC, as vexplain does, without TLS and on a listener that only the test reaches.

const (
	// wait bounds how long a test waits for what must happen, and tick is how often it looks.
	wait = 30 * time.Second
	tick = 50 * time.Millisecond
	// byTag is the image that a pod of the tests runs, by its tag, which its container reports as its image ID:
	// no digest.
	byTag = "artifacts.example/team-a/app:1.0"
)

// api is the API server of the tests. It starts when the first test needs it, and TestMain stops it.
var api struct {
	once   sync.Once
	env    *envtest.Environment
	cfg    *rest.Config
	client client.Client
	err    error
}

func TestMain(m *testing.M) {
	// The SDK's server logs through slog. Its lines would only crowd the output of a test that fails.
	slog.SetDefault(slog.New(slog.DiscardHandler))
	code := m.Run()
	if api.env != nil {
		if err := api.env.Stop(); err != nil {
			fmt.Fprintln(os.Stderr, "stopping the API server:", err)
			code = 1
		}
	}
	os.Exit(code)
}

// startAPI returns the configuration and a client of the API server, which it starts once.
func startAPI(t *testing.T) (*rest.Config, client.Client) {
	t.Helper()
	api.once.Do(func() {
		api.env = &envtest.Environment{BinaryAssetsDirectory: assetsDirectory()}
		api.cfg, api.err = api.env.Start()
		if api.err == nil {
			api.client, api.err = client.New(api.cfg, client.Options{Scheme: clientgoscheme.Scheme})
		}
	})
	require.NoError(t, api.err,
		"start the API server: KUBEBUILDER_ASSETS names its binaries, which `make setup-envtest` fetches")
	return api.cfg, api.client
}

// assetsDirectory is where the binaries of the API server are when KUBEBUILDER_ASSETS, which `make test` sets, is
// not: the repository's bin/k8s, which `make setup-envtest` fills. The tests then also run from an editor.
func assetsDirectory() string {
	if os.Getenv("KUBEBUILDER_ASSETS") != "" {
		return ""
	}
	root := filepath.Join("..", "..", "..", "..", "bin", "k8s")
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

// served is a collector that a test serves: how to dial it, and where its /metrics are.
type served struct {
	dial    func(ctx context.Context) (*grpc.ClientConn, error)
	metrics string
}

// serveCollector serves the collector against the API server of the tests until the test ends, as main serves it.
func serveCollector(t *testing.T) served {
	t.Helper()
	cfg, _ := startAPI(t)
	listener := bufconn.Listen(1 << 20)
	health, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	opts := collector.Options{Insecure: true, GRPCListener: listener, HealthListener: health}
	go func() { done <- serve(ctx, cfg, opts, "workloads") }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			assert.NoError(t, err, "serve returns nil once its context ends")
		case <-time.After(wait):
			assert.Fail(t, "the collector didn't stop")
		}
	})
	return served{
		dial: func(context.Context) (*grpc.ClientConn, error) {
			return grpc.NewClient("passthrough:///bufconn",
				grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
					return listener.DialContext(ctx)
				}),
				grpc.WithTransportCredentials(insecure.NewCredentials()))
		},
		metrics: "http://" + health.Addr().String() + "/metrics",
	}
}

// TestConformance runs the conformance suite of the SDK against the collector, with its presence check, which puts
// nodes, namespaces and pods in the API server, and checks that the collector applies the scope, leaves out
// vexplain's own pods and gives the node and the platform of each pod that it lists.
func TestConformance(t *testing.T) {
	_, c := startAPI(t)
	conformance.Run(t, conformance.Target{
		Dial: serveCollector(t).dial,
		// The collector has no settings.
		InvalidSettings: json.RawMessage(`{"interval": "1m"}`),
		Context:         collector.Context{Cluster: "cluster-a"},
		Client:          c,
	})
}

// The collector serves vexplain_containers_skipped on /metrics, for the cluster that the context names.
func TestTheGaugeOfSkippedContainersIsServedOnMetrics(t *testing.T) {
	_, c := startAPI(t)
	token := rand.String(6)
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "team-" + token, Labels: map[string]string{"run": token}}}
	require.NoError(t, c.Create(t.Context(), ns))
	t.Cleanup(func() { assert.NoError(t, c.Delete(context.Background(), ns)) })
	tagged := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns.Name, Name: "app-0"},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: byTag}}},
	}
	require.NoError(t, c.Create(t.Context(), tagged))
	tagged.Status.ContainerStatuses = []corev1.ContainerStatus{{
		Name: "app", Image: byTag, ImageID: byTag,
	}}
	require.NoError(t, c.Status().Update(t.Context(), tagged))
	s := serveCollector(t)

	conn, err := s.dial(t.Context())
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	stream, err := collectorv1alpha1.NewEvidenceClient(conn).Watch(ctx, &collectorv1alpha1.WatchRequest{
		Role: collectorv1alpha1.Role_ROLE_SPOKE,
		Context: &collectorv1alpha1.Context{
			Cluster: "cluster-a",
			Scope:   []byte(`{"includeNamespaces": {"matchLabels": {"run": "` + token + `"}}}`),
		},
	}, grpc.UseCompressor(gzip.Name))
	require.NoError(t, err)
	for {
		item, err := stream.Recv()
		require.NoError(t, err)
		if item.GetSnapshotEnd() != nil {
			break
		}
	}

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		body, err := scrape(t.Context(), s.metrics)
		if assert.NoError(c, err) {
			assert.Contains(c, body, `vexplain_containers_skipped{cluster="cluster-a",reason="Unparsable"} 1`)
		}
	}, wait, tick)
}

// scrape returns what the collector serves at url.
func scrape(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", errors.New(resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	return strings.TrimSpace(string(body)), err
}
