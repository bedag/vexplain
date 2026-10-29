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
// cmd/main.go and the envtest suites of the controller packages all call Register, so tests run
// the same watches, caches and field indexes as production.
package setup

import (
	"context"
	"fmt"
	"time"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/bedag/vexplain/internal/collector"
	configcontroller "github.com/bedag/vexplain/internal/controller/config"
)

// defaultCollectorResync is how often the Collector controller reads the registry when Options
// does not say.
const defaultCollectorResync = 30 * time.Second

// eventSource is the name that the operator's events carry as their reporting controller.
const eventSource = "vexplain"

// Options configures Register.
type Options struct {
	// OperatorNamespace is the namespace the operator runs in. Cluster-scoped kinds reference
	// namespaced objects, such as Secrets, only in this namespace.
	OperatorNamespace string
	// CollectorRegistry is where the collectors report their health, and where the Collector
	// controller reads it. Register creates one when it is nil. A test passes its own, to report
	// health the way a collector does.
	CollectorRegistry *collector.Registry
	// CollectorResync is how often the Collector controller reads the registry again for each
	// Collector. Zero means 30 seconds.
	CollectorResync time.Duration
}

// Register sets up every controller with the manager, and adds the start-up work that creates the
// default Collectors.
func Register(mgr ctrl.Manager, opts Options) error {
	registry := opts.CollectorRegistry
	if registry == nil {
		registry = collector.NewRegistry()
	}
	collectorResync := opts.CollectorResync
	if collectorResync == 0 {
		collectorResync = defaultCollectorResync
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
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("set up the ModelConfig controller: %w", err)
	}
	// A RunnableFunc doesn't implement LeaderElectionRunnable, so the manager starts it only on the
	// leader, once the caches have synced.
	if err := mgr.Add(manager.RunnableFunc(func(ctx context.Context) error {
		return collector.EnsureDefaults(ctx, mgr.GetClient())
	})); err != nil {
		return fmt.Errorf("add the start-up that creates the default Collectors: %w", err)
	}
	return nil
}
