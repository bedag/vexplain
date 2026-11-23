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

package setup_test

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/agent/worker"
	"github.com/bedag/vexplain/internal/agent/worker/setup"
)

// These tests build the agent workers as cmd/agent does, and never start them: what Register adds to their manager
// says where each part runs. An API server of envtest maps the kinds of their caches and indexes.

const operatorNamespace = "vexplain-system"

// api is the API server of these tests. It starts when the first test needs it, and TestMain stops it.
var api struct {
	once sync.Once
	env  *envtest.Environment
	cfg  *rest.Config
	err  error
}

func TestMain(m *testing.M) {
	code := m.Run()
	if api.env != nil {
		if err := api.env.Stop(); err != nil {
			fmt.Fprintln(os.Stderr, "stopping the API server:", err)
			code = 1
		}
	}
	os.Exit(code)
}

// recording is a manager that keeps what is added to it.
type recording struct {
	ctrl.Manager
	added []manager.Runnable
}

func (r *recording) Add(runnable manager.Runnable) error {
	r.added = append(r.added, runnable)
	return r.Manager.Add(runnable)
}

// newManager returns a manager of the tests' API server with the workers' cache and client, which records what is
// added to it.
func newManager(t *testing.T) *recording {
	t.Helper()
	api.once.Do(func() {
		api.env = &envtest.Environment{CRDDirectoryPaths: []string{filepath.Join("..", "..", "..", "..", "config", "crd", "bases")},
			ErrorIfCRDPathMissing: true, BinaryAssetsDirectory: assetsDirectory()}
		api.cfg, api.err = api.env.Start()
	})
	require.NoError(t, api.err,
		"start the API server: KUBEBUILDER_ASSETS names its binaries, which `make setup-envtest` fetches")
	scheme := runtime.NewScheme()
	require.NoError(t, setup.AddToScheme(scheme))
	mgr, err := ctrl.NewManager(api.cfg, ctrl.Options{Scheme: scheme, Cache: setup.CacheOptions(operatorNamespace),
		Client: setup.ClientOptions(), Metrics: metricsserver.Options{BindAddress: "0"}})
	require.NoError(t, err)
	return &recording{Manager: mgr}
}

// assetsDirectory is where the binaries of the API server are when KUBEBUILDER_ASSETS, which `make test` sets, is
// not: the repository's bin/k8s, which `make setup-envtest` fills.
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

// Every replica of the workers claims cases, and probes the models only while it holds the workers' Lease, in an
// election of its own: nothing that Register adds waits for a leader of the manager, whose loss would stop the worker
// and its judgements with it.
func TestNothingOfTheWorkersWaitsForALeaderOfTheManager(t *testing.T) {
	mgr := newManager(t)
	require.NoError(t, setup.Register(mgr, setup.Options{OperatorNamespace: operatorNamespace,
		LeaderElectionID: "agent.vexplain.bedag.ch"}))

	var loops int
	for _, runnable := range mgr.added {
		elected, ok := runnable.(manager.LeaderElectionRunnable)
		require.True(t, ok && !elected.NeedLeaderElection(), "%T waits for a leader of the manager", runnable)
		if _, loop := runnable.(*worker.Loop); loop {
			loops++
		}
	}
	require.Equal(t, 1, loops, "one claim loop, on every replica")
}

// The workers alone read the LLM keys: their cache holds the labelled Secrets of the operator's namespace, and no
// other Secret.
func TestTheWorkersCacheHoldsTheLLMKeysOfTheirNamespace(t *testing.T) {
	var secrets []cache.ByObject
	for obj, by := range setup.CacheOptions(operatorNamespace).ByObject {
		if _, secret := obj.(*corev1.Secret); secret {
			secrets = append(secrets, by)
		}
	}
	require.Len(t, secrets, 1)
	require.True(t, secrets[0].Label.Matches(labels.Set{configv1alpha1.LLMAPIKeyLabel: "true"}))
	require.Equal(t, map[string]cache.Config{operatorNamespace: {}}, secrets[0].Namespaces)
}

// Register refuses an empty namespace before it uses the manager: to a cache, it means every namespace.
func TestRegisterRefusesAnEmptyOperatorNamespace(t *testing.T) {
	require.ErrorContains(t, setup.Register(nil, setup.Options{}), "operator namespace")
}
