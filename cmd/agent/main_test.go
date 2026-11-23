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
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

// The workers run against an API server of envtest with the operator's CRDs, as main runs them against the cluster's,
// and serve until their context ends.
func TestRunServesUntilItsContextEnds(t *testing.T) {
	env := &envtest.Environment{CRDDirectoryPaths: []string{filepath.Join("..", "..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true, BinaryAssetsDirectory: assetsDirectory()}
	cfg, err := env.Start()
	require.NoError(t, err, "KUBEBUILDER_ASSETS names the API server's binaries, which `make setup-envtest` fetches")
	t.Cleanup(func() { require.NoError(t, env.Stop()) })
	config := func() (*rest.Config, error) { return cfg, err }
	environment := map[string]string{"POD_NAMESPACE": "vexplain-ops"}
	getenv := func(name string) string { return environment[name] }

	require.Equal(t, 2, run(t.Context(), []string{"--no-such-flag"}, getenv, config))
	require.Equal(t, 1, run(t.Context(), nil, getenv, func() (*rest.Config, error) {
		return nil, errors.New("no cluster")
	}))

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan int, 1)
	go func() {
		done <- run(ctx, []string{"--metrics-bind-address=0", "--health-probe-bind-address=0"}, getenv, config)
	}()
	select {
	case code := <-done:
		t.Fatalf("the workers stopped before their context ended, with %d", code)
	case <-time.After(time.Second):
	}
	cancel()
	select {
	case code := <-done:
		require.Zero(t, code)
	case <-time.After(30 * time.Second):
		require.FailNow(t, "the workers didn't stop with their context")
	}
}

// A worker that loses the Lease of the workers' leader goes on: the Lease serves the probe of the models alone, so its
// loss stops the probe and not the worker, whose claim loop and judgements need no leader. The worker campaigns again,
// and leads once the Lease is free.
func TestLosingTheLeaseLeavesTheWorkerRunning(t *testing.T) {
	env := &envtest.Environment{CRDDirectoryPaths: []string{filepath.Join("..", "..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true, BinaryAssetsDirectory: assetsDirectory()}
	cfg, err := env.Start()
	require.NoError(t, err, "KUBEBUILDER_ASSETS names the API server's binaries, which `make setup-envtest` fetches")
	t.Cleanup(func() { require.NoError(t, env.Stop()) })
	api, err := kubernetes.NewForConfig(cfg)
	require.NoError(t, err)
	const namespace = "vexplain-ops"
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}
	_, err = api.CoreV1().Namespaces().Create(t.Context(), ns, metav1.CreateOptions{})
	require.NoError(t, err)
	getenv := func(name string) string { return map[string]string{"POD_NAMESPACE": namespace}[name] }
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan int, 1)
	go func() {
		done <- run(ctx, []string{"--leader-elect", "--metrics-bind-address=0", "--health-probe-bind-address=0"}, getenv,
			func() (*rest.Config, error) { return cfg, nil })
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			t.Error("the worker didn't stop with its context")
		}
	})
	leases := api.CoordinationV1().Leases(namespace)
	holder := func() string {
		lease, err := leases.Get(t.Context(), leaderElectionID, metav1.GetOptions{})
		if err != nil {
			return ""
		}
		return ptr.Deref(lease.Spec.HolderIdentity, "")
	}
	require.Eventually(t, func() bool { return holder() != "" }, 30*time.Second, 100*time.Millisecond, "the worker leads")
	worker := holder()

	lease, err := leases.Get(t.Context(), leaderElectionID, metav1.GetOptions{})
	require.NoError(t, err)
	lease.Spec.HolderIdentity = ptr.To("another-worker")
	lease.Spec.LeaseDurationSeconds = ptr.To(int32(3600))
	lease.Spec.RenewTime = &metav1.MicroTime{Time: time.Now()}
	_, err = leases.Update(t.Context(), lease, metav1.UpdateOptions{})
	require.NoError(t, err)
	stopped := func() bool {
		events, err := api.CoreV1().Events(namespace).List(t.Context(), metav1.ListOptions{})
		require.NoError(t, err)
		return slices.ContainsFunc(events.Items, func(e corev1.Event) bool { return e.Message == worker+" stopped leading" })
	}
	require.Eventually(t, stopped, 30*time.Second, 100*time.Millisecond, "the worker loses the Lease")
	select {
	case code := <-done:
		done <- code
		t.Fatalf("the worker stopped when it lost the Lease, with %d", code)
	case <-time.After(3 * time.Second):
	}

	require.NoError(t, leases.Delete(t.Context(), leaderElectionID, metav1.DeleteOptions{}))
	require.Eventually(t, func() bool { return holder() == worker }, 30*time.Second, 100*time.Millisecond,
		"the worker leads again")
}

// assetsDirectory is where the binaries of the API server are when KUBEBUILDER_ASSETS, which `make test` sets, is
// not: the repository's bin/k8s, which `make setup-envtest` fills.
func assetsDirectory() string {
	if os.Getenv("KUBEBUILDER_ASSETS") != "" {
		return ""
	}
	root := filepath.Join("..", "..", "bin", "k8s")
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
