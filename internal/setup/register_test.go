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
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/agent/worker"
	"github.com/bedag/vexplain/internal/exposure"
	"github.com/bedag/vexplain/internal/setup"
)

// These tests build the manager as its binary does, and never start it: what Register adds to it says what it runs. An
// API server of envtest maps the kinds of its cache and indexes.

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

// newManager returns a manager of the tests' API server with the cache options, which records what is added to it.
func newManager(t *testing.T, cacheOptions cache.Options) *recording {
	t.Helper()
	api.once.Do(func() {
		api.env = &envtest.Environment{CRDDirectoryPaths: []string{filepath.Join("..", "..", "config", "crd", "bases")},
			ErrorIfCRDPathMissing: true, BinaryAssetsDirectory: assetsDirectory()}
		api.cfg, api.err = api.env.Start()
	})
	require.NoError(t, api.err,
		"start the API server: KUBEBUILDER_ASSETS names its binaries, which `make setup-envtest` fetches")
	scheme := runtime.NewScheme()
	require.NoError(t, setup.AddToScheme(scheme))
	mgr, err := ctrl.NewManager(api.cfg, ctrl.Options{Scheme: scheme, Cache: cacheOptions, Client: setup.ClientOptions(),
		Metrics: metricsserver.Options{BindAddress: "0"},
		// The suite of this package registers the same controllers in its own manager.
		Controller: config.Controller{SkipNameValidation: ptr.To(true)}})
	require.NoError(t, err)
	return &recording{Manager: mgr}
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

// The workers judge the cases in a Deployment of their own (decision 0057): the manager queues the cases and sweeps
// the leases that ran out, and claims none.
func TestTheManagerNoLongerJudges(t *testing.T) {
	mgr := newManager(t, setup.CacheOptions(operatorNamespace))
	require.NoError(t, setup.Register(mgr, setup.Options{OperatorNamespace: operatorNamespace}))

	require.NotEmpty(t, mgr.added)
	for _, runnable := range mgr.added {
		_, loop := runnable.(*worker.Loop)
		require.False(t, loop, "the manager runs a claim loop")
	}
}

// Only the agent workers read the LLM key: no cache of the manager selects its label.
func TestTheManagersCacheHoldsNoLLMKey(t *testing.T) {
	key := labels.Set{configv1alpha1.LLMAPIKeyLabel: "true"}
	for obj, by := range setup.CacheOptions(operatorNamespace).ByObject {
		_, secret := obj.(*corev1.Secret)
		require.False(t, secret, "the manager's cache holds Secrets")
		require.False(t, by.Label != nil && by.Label.Matches(key), "the cache of %T selects the LLM key's label", obj)
	}
}

// The manager and the agent workers run images of their own, so that a scan of one doesn't report the other's code
// and libraries (decision 0057): the manager's binary links none of the agent's judging, its runner or the client of
// the model, and the workers' links none of the manager's controllers or its spoke.
func TestEachBinaryLinksOnlyItsOwnCode(t *testing.T) {
	const module = "github.com/bedag/vexplain/"
	deps := func(binary string) []string {
		list := exec.Command("go", "list", "-deps", "./"+binary)
		list.Dir = filepath.Join("..", "..")
		out, err := list.Output()
		require.NoError(t, err, "go list -deps ./%s", binary)
		var own []string
		for pkg := range strings.FieldsSeq(string(out)) {
			if name, ok := strings.CutPrefix(pkg, module); ok {
				own = append(own, name)
			}
		}
		require.NotEmpty(t, own)
		return own
	}

	managerDeps := deps("cmd")
	require.Contains(t, managerDeps, "internal/controller/hub")
	require.Contains(t, managerDeps, "internal/exposure")
	for _, pkg := range managerDeps {
		require.False(t, pkg == "internal/agent/worker" || strings.HasPrefix(pkg, "internal/agent/worker/") ||
			pkg == "internal/agent/runner" || pkg == "internal/agent/models" || pkg == "internal/llm",
			"the manager links %s", pkg)
	}

	workers := deps("cmd/agent")
	require.Contains(t, workers, "internal/agent/worker")
	for _, pkg := range workers {
		require.False(t, strings.HasPrefix(pkg, "internal/controller/") || pkg == "internal/spoke" ||
			pkg == "internal/exposure" || pkg == "internal/setup" || strings.HasPrefix(pkg, "internal/setup/"),
			"the agent workers link %s", pkg)
	}
}

// The hub asks the sources about the entry points: the manager runs the asker.
func TestTheManagerAsksTheSources(t *testing.T) {
	mgr := newManager(t, setup.CacheOptions(operatorNamespace))
	require.NoError(t, setup.Register(mgr, setup.Options{OperatorNamespace: operatorNamespace}))

	require.True(t, slices.ContainsFunc(mgr.added, func(r manager.Runnable) bool {
		_, asker := r.(*exposure.Asker)
		return asker
	}), "the manager runs no asker")
}
