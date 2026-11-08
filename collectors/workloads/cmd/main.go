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

// Command workloads serves vexplain's workloads collector, which reports which workloads run which image digests in
// its cluster, for the spoke of vexplain that runs there.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/bedag/vexplain/collectors/workloads/internal/presence"
	"github.com/bedag/vexplain/sdk/collector"
)

// version is the version of the collector, which GetInfo reports. The build sets it.
var version = "0.1.0"

const (
	// nameVariable holds the name of the collector's Collector, which vexplain's deployer sets, and which the
	// source of the collector's events names.
	nameVariable = "VEXPLAIN_COLLECTOR_NAME"
	// defaultName is the name of the built-in Collector, when the variable says none.
	defaultName = "workloads"
)

func main() { os.Exit(run()) }

func run() int {
	// The context ends on SIGTERM, which is how Kubernetes stops a pod. serve then stops, and returns.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// The cache logs through controller-runtime's logger, and the SDK's server through slog: both go to slog.
	ctrllog.SetLogger(logr.FromSlogHandler(slog.Default().Handler()))

	// The collector reads the cluster that it runs in, with its own service account, and no other: it never reads a
	// kubeconfig.
	cfg, err := rest.InClusterConfig()
	if err != nil {
		slog.Error("The collector reads the cluster that it runs in, and runs in none", "error", err)
		return 1
	}
	name := os.Getenv(nameVariable)
	if name == "" {
		name = defaultName
	}
	// vexplain's deployer tells the collector where to listen, and where its TLS files are, in environment
	// variables, which OptionsFromEnv reads.
	if err := serve(ctx, cfg, collector.OptionsFromEnv(), name); err != nil {
		slog.Error("The collector failed", "error", err)
		return 1
	}
	return 0
}

// serve serves the collector, under the name of its Collector, until ctx ends. It reads the cluster of cfg through a
// cache of informers of its own, which its Watches share, and serves vexplain_containers_without_digest with the
// server's metrics. A cache that fails stops the collector: nothing that it reported would stay current.
func serve(ctx context.Context, cfg *rest.Config, opts collector.Options, name string) error {
	informers, err := cache.New(cfg, presence.CacheOptions())
	if err != nil {
		return fmt.Errorf("build the cache of the cluster: %w", err)
	}
	withoutDigest := presence.NewWithoutDigest()
	registry := prometheus.NewRegistry()
	if err := registry.Register(withoutDigest); err != nil {
		return fmt.Errorf("register the gauge of containers without a digest: %w", err)
	}
	opts.Registry = registry

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var (
		wg       sync.WaitGroup
		cacheErr error
	)
	wg.Go(func() {
		if err := informers.Start(ctx); err != nil {
			cacheErr = err
			cancel()
		}
	})
	watcher := presence.NewWatcher(informers, presence.Options{Name: name, Version: version, WithoutDigest: withoutDigest})
	serveErr := collector.Serve(ctx, watcher, opts)
	cancel()
	wg.Wait()
	if cacheErr != nil {
		return fmt.Errorf("the cache of the cluster: %w", cacheErr)
	}
	return serveErr
}
