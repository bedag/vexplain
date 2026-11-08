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
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/rand"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/bedag/vexplain/sdk/collector"
	"github.com/bedag/vexplain/sdk/conformance"
)

// The tests run the collector as main does, with the cache that serve builds, against an API server of envtest. They
// call it over gRPC, as vexplain does, without TLS and on a listener that only the test reaches.

const (
	// wait bounds how long a test waits for the collector to stop.
	wait = 30 * time.Second
	// appLabel is the label that the Service of the tests selects its pod by, and web the name of the pod, of the
	// Service and of the label's value.
	appLabel, web = "app", "web"
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

// serveCollector serves the collector against the API server of the tests until the test ends, as main serves it,
// and returns how to dial it.
func serveCollector(t *testing.T) func(ctx context.Context) (*grpc.ClientConn, error) {
	t.Helper()
	cfg, _ := startAPI(t)
	listener := bufconn.Listen(1 << 20)
	health, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	opts := collector.Options{Insecure: true, GRPCListener: listener, HealthListener: health}
	go func() { done <- serve(ctx, cfg, opts, "network-reach") }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			assert.NoError(t, err, "serve returns nil once its context ends")
		case <-time.After(wait):
			assert.Fail(t, "the collector didn't stop")
		}
	})
	return func(context.Context) (*grpc.ClientConn, error) {
		return grpc.NewClient("passthrough:///bufconn",
			grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
				return listener.DialContext(ctx)
			}),
			grpc.WithTransportCredentials(insecure.NewCredentials()))
	}
}

// TestConformance runs the conformance suite of the SDK against the collector, in a cluster with a workload that a
// LoadBalancer Service exposes, so that the snapshot holds events whose data the suite checks against the schema of
// the exposure type.
func TestConformance(t *testing.T) {
	_, c := startAPI(t)
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "team-" + rand.String(6)}}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns.Name, Name: web, Labels: map[string]string{appLabel: web}},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "artifacts.example/team-a/app:1.0"}}},
	}
	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns.Name, Name: web},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeLoadBalancer, Selector: map[string]string{appLabel: web},
			Ports: []corev1.ServicePort{{Port: 80}},
		},
	}
	for _, obj := range []client.Object{ns, pod, service} {
		require.NoError(t, c.Create(t.Context(), obj))
	}

	conformance.Run(t, conformance.Target{
		Dial:            serveCollector(t),
		Settings:        json.RawMessage(`{"ingressClasses": ["public"], "nodePorts": "Internal"}`),
		InvalidSettings: json.RawMessage(`{"nodePorts": "Sometimes"}`),
		Context:         collector.Context{Cluster: "cluster-a"},
	})
}
