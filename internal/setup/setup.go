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
	"fmt"

	ctrl "sigs.k8s.io/controller-runtime"

	configcontroller "github.com/bedag/vexplain/internal/controller/config"
)

// Options configures Register.
type Options struct {
	// OperatorNamespace is the namespace the operator runs in. Cluster-scoped kinds reference
	// namespaced objects, such as Secrets, only in this namespace.
	OperatorNamespace string
}

// Register sets up every controller with the manager.
func Register(mgr ctrl.Manager, opts Options) error {
	if err := (&configcontroller.OperatorConfigReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("set up the OperatorConfig controller: %w", err)
	}
	if err := (&configcontroller.CollectorReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("set up the Collector controller: %w", err)
	}
	if err := (&configcontroller.ModelConfigReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("set up the ModelConfig controller: %w", err)
	}
	return nil
}
