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

// Package setup wires the controllers into a manager.
//
// cmd/main.go and the envtest suites of the controller packages all build their scheme with
// AddToScheme, their manager's cache with CacheOptions, and call Register, so tests run the same
// scheme, watches, caches and field indexes as production.
package setup

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/collector"
	configcontroller "github.com/bedag/vexplain/internal/controller/config"
	inventorycontroller "github.com/bedag/vexplain/internal/controller/inventory"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/settings"
	"github.com/bedag/vexplain/internal/workloads"
)

const (
	// defaultCollectorResync is how often the Collector controller reads the registry when Options
	// does not say.
	defaultCollectorResync = 30 * time.Second
	// defaultGaugeInterval is how often the gauge of running images counts again when Options does
	// not say.
	defaultGaugeInterval = 30 * time.Second
)

// eventSource is the name that the operator's events carry as their reporting controller.
const eventSource = "vexplain"

var (
	schemeBuilder = runtime.NewSchemeBuilder(
		clientgoscheme.AddToScheme,
		configv1alpha1.AddToScheme,
		inventoryv1alpha1.AddToScheme,
	)
	// AddToScheme adds every API that the operator uses to a scheme: the built-in kinds and the
	// operator's own groups. cmd/main.go and the envtest suites build their schemes with it, so a
	// new group is added in one place.
	AddToScheme = schemeBuilder.AddToScheme
)

// CacheOptions returns the options of the manager's cache. Its cache of Secrets holds only the
// Secrets of operatorNamespace that carry the label vexplain.bedag.ch/llm-api-key=true, the only
// Secrets that the operator reads. It never loads any other Secret, so their values stay out of
// the operator's memory, and the operator needs no right on Secrets outside its namespace.
//
// operatorNamespace must not be empty: to the cache, an empty namespace means every namespace.
// Register refuses an empty one.
func CacheOptions(operatorNamespace string) cache.Options {
	return cache.Options{
		ByObject: map[client.Object]cache.ByObject{
			&corev1.Secret{}: {
				Namespaces: map[string]cache.Config{operatorNamespace: {}},
				Label:      labels.SelectorFromSet(labels.Set{configv1alpha1.LLMAPIKeyLabel: "true"}),
			},
		},
	}
}

// Options configures Register.
type Options struct {
	// OperatorNamespace is the namespace the operator runs in. Cluster-scoped kinds reference
	// namespaced objects, such as Secrets, only in this namespace. It must not be empty, and it
	// must be the namespace that the manager's cache was given with CacheOptions.
	OperatorNamespace string
	// CollectorRegistry is where the collectors report their health, and where the Collector
	// controller reads it. Register creates one when it is nil. A test passes its own, to report
	// health the way a collector does.
	CollectorRegistry *collector.Registry
	// CollectorResync is how often the Collector controller reads the registry again for each
	// Collector. Zero means 30 seconds.
	CollectorResync time.Duration
	// GaugeInterval is how often the gauge of running images counts the ImageInventory objects
	// again. Zero means 30 seconds.
	GaugeInterval time.Duration
	// HTTPClient is the HTTP client of the probes of the ModelConfig controller. Nil means the
	// default client of the llm package, which honours HTTPS_PROXY and NO_PROXY. A test passes the
	// client of its TLS test server.
	HTTPClient *http.Client
}

// Register sets up every controller with the manager, and adds the start-up work that creates the
// default Collectors and the updater of the gauge of running images. It checks opts before it uses
// the manager.
func Register(mgr ctrl.Manager, opts Options) error {
	if opts.OperatorNamespace == "" {
		// To a cache, "" means every namespace, so the Secrets would come from the whole cluster.
		return errors.New("the operator namespace is empty")
	}
	registry := opts.CollectorRegistry
	if registry == nil {
		registry = collector.NewRegistry()
	}
	collectorResync := opts.CollectorResync
	if collectorResync == 0 {
		collectorResync = defaultCollectorResync
	}
	gaugeInterval := opts.GaugeInterval
	if gaugeInterval == 0 {
		gaugeInterval = defaultGaugeInterval
	}

	if err := (&configcontroller.OperatorConfigReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("set up the OperatorConfig controller: %w", err)
	}
	if err := (&configcontroller.CollectorReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Registry: registry,
		Recorder: mgr.GetEventRecorder(eventSource),
		Resync:   collectorResync,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("set up the Collector controller: %w", err)
	}
	if err := (&configcontroller.ModelConfigReconciler{
		Client:            mgr.GetClient(),
		Scheme:            mgr.GetScheme(),
		OperatorNamespace: opts.OperatorNamespace,
		Recorder:          mgr.GetEventRecorder(eventSource),
		HTTPClient:        opts.HTTPClient,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("set up the ModelConfig controller: %w", err)
	}
	// The pod inventory lists the pods that run a digest through this index.
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &corev1.Pod{},
		workloads.PodDigestIndex, workloads.IndexPodDigests); err != nil {
		return fmt.Errorf("index the pods by the digests they report: %w", err)
	}
	// One store, the only door to the ImageInventory objects: the pod inventory writes and watches
	// them through it, and the gauge counts them through it. The manager's client and cache keep
	// one informer for them.
	store := inventory.NewCRDStore(mgr.GetClient(), mgr.GetCache())
	if err := (&inventorycontroller.PodInventoryReconciler{
		Client:    mgr.GetClient(),
		APIReader: mgr.GetAPIReader(),
		Store:     store,
		// The same registry as the Collector controller's, which shows the health it reports.
		Registry: registry,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("set up the pod inventory controller: %w", err)
	}
	// A RunnableFunc doesn't implement LeaderElectionRunnable, so the manager starts it only on the
	// leader, once the caches have synced.
	if err := mgr.Add(manager.RunnableFunc(func(ctx context.Context) error {
		return collector.EnsureDefaults(ctx, mgr.GetClient())
	})); err != nil {
		return fmt.Errorf("add the start-up that creates the default Collectors: %w", err)
	}
	// Like the start-up above, the gauge runs on the leader only, the one replica that keeps the
	// inventory, so that a sum over replicas counts each image once.
	if err := mgr.Add(manager.RunnableFunc(func(ctx context.Context) error {
		return runImagesRunningGauge(ctx, mgr, store, gaugeInterval)
	})); err != nil {
		return fmt.Errorf("add the gauge of running images: %w", err)
	}
	return nil
}

// runImagesRunningGauge runs an inventory.GaugeUpdater over store until ctx is done.
//
// The updater counts the objects that hold this cluster's ID, which it takes as a plain value. So
// the ID is read first, through the API reader, which doesn't wait for a cache, and read again
// every interval until it can be. The cluster name is read at every round, from the cache, so
// that the gauge follows a rename.
func runImagesRunningGauge(ctx context.Context, mgr ctrl.Manager, store inventory.Store, interval time.Duration) error {
	log := logf.FromContext(ctx).WithName("images-running-gauge")
	var clusterID string
	if err := wait.PollUntilContextCancel(ctx, interval, true, func(ctx context.Context) (bool, error) {
		id, err := settings.ClusterID(ctx, mgr.GetAPIReader())
		if err != nil {
			log.Error(err, "Could not read the cluster ID; trying again")
			return false, nil
		}
		clusterID = id
		return true, nil
	}); err != nil {
		// The condition never fails, so the poll only ends with an error when ctx is done: the
		// manager is stopping, and so is the gauge.
		return nil
	}

	clusterName := func() string {
		effective, err := settings.Load(ctx, mgr.GetClient())
		if err != nil {
			log.Error(err, "Could not read the cluster name; the gauge keeps its value")
			return ""
		}
		return effective.ClusterName
	}
	return (&inventory.GaugeUpdater{
		Store:     store,
		Cluster:   clusterName,
		ClusterID: clusterID,
		Interval:  interval,
	}).Start(ctx)
}
