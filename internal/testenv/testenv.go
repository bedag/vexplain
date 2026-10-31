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

// Package testenv starts what the envtest suites of the controller packages run against: an API
// server with the operator's CRDs, a direct client, and a manager built as cmd/main.go builds it,
// with the scheme of setup.AddToScheme, the cache of setup.CacheOptions and the controllers of
// setup.Register.
//
// It is for Ginkgo suites: Start fails the suite through Gomega. Only test files import it, so it
// never enters the manager binary.
package testenv

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/bedag/vexplain/internal/setup"
)

// stopTimeout bounds how long the stop of the manager, and of the API server, may take.
const stopTimeout = time.Minute

// Environment is a running API server with a manager.
type Environment struct {
	// Client reads and writes through the API server. It never reads from a cache, so a spec that
	// reads with it never sees a stale object.
	Client client.Client
	// Manager runs the controllers, wired by setup.Register as in production.
	Manager ctrl.Manager
}

// Start starts an API server with the CRDs of config/crd/bases, and a manager with the scheme and
// the cache options of cmd/main.go, wired by setup.Register with opts. The manager serves no
// metrics, because the suites of different packages run in parallel and must not share a port.
//
// Call it from BeforeSuite. It fails the suite when something doesn't start, and so does a
// manager that stops with an error. It registers the stop of the manager, and then of the API
// server, with DeferCleanup, so the suite needs no AfterSuite for them.
func Start(opts setup.Options) *Environment {
	ginkgo.GinkgoHelper()
	root := repositoryRoot()

	ginkgo.By("starting the API server")
	apiServer := &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join(root, "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
		// KUBEBUILDER_ASSETS, which `make test` sets, takes precedence. This lets the suites run
		// from an IDE once `make setup-envtest` has fetched the binaries.
		BinaryAssetsDirectory: firstDirectory(filepath.Join(root, "bin", "k8s")),
	}
	cfg, err := apiServer.Start()
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	ginkgo.DeferCleanup(func() {
		ginkgo.By("stopping the API server")
		gomega.Eventually(apiServer.Stop, stopTimeout, time.Second).Should(gomega.Succeed())
	})

	scheme := runtime.NewScheme()
	gomega.Expect(setup.AddToScheme(scheme)).To(gomega.Succeed())
	direct, err := client.New(cfg, client.Options{Scheme: scheme})
	gomega.Expect(err).NotTo(gomega.HaveOccurred())

	ginkgo.By("starting a manager with the production wiring")
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:  scheme,
		Cache:   setup.CacheOptions(opts.OperatorNamespace),
		Client:  setup.ClientOptions(),
		Metrics: metricsserver.Options{BindAddress: "0"},
	})
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	gomega.Expect(setup.Register(mgr, opts)).To(gomega.Succeed())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer ginkgo.GinkgoRecover()
		defer close(done)
		gomega.Expect(mgr.Start(ctx)).To(gomega.Succeed())
	}()
	// DeferCleanup runs the last registered first, so the manager stops before the API server.
	ginkgo.DeferCleanup(func() {
		ginkgo.By("stopping the manager")
		cancel()
		gomega.Eventually(done, stopTimeout).Should(gomega.BeClosed())
	})
	return &Environment{Client: direct, Manager: mgr}
}

// repositoryRoot returns the root of the repository: the nearest directory above the working
// directory that holds go.mod. go test runs a test in the directory of its package.
func repositoryRoot() string {
	ginkgo.GinkgoHelper()
	dir, err := os.Getwd()
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	for {
		_, err := os.Stat(filepath.Join(dir, "go.mod"))
		if err == nil {
			return dir
		}
		gomega.Expect(errors.Is(err, os.ErrNotExist)).To(gomega.BeTrue(), "look for go.mod in %s: %v", dir, err)
		parent := filepath.Dir(dir)
		gomega.Expect(parent).NotTo(gomega.Equal(dir), "no go.mod above the working directory")
		dir = parent
	}
}

// firstDirectory returns the first directory in path, or "" when it has none. setup-envtest
// keeps the binaries of each Kubernetes version in a directory of their own there.
func firstDirectory(path string) string {
	entries, err := os.ReadDir(path)
	if err != nil {
		return ""
	}
	for _, entry := range entries {
		if entry.IsDir() {
			return filepath.Join(path, entry.Name())
		}
	}
	return ""
}
