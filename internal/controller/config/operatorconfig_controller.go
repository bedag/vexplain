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

package config

import (
	"context"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/scope"
)

// OperatorConfigReconciler reconciles a OperatorConfig object
type OperatorConfigReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// The controller reads an OperatorConfig and writes only its status, so it holds no write access
// to the object itself and no finalizers right.
// +kubebuilder:rbac:groups=config.vexplain.bedag.ch,resources=operatorconfigs,verbs=get;list;watch
// +kubebuilder:rbac:groups=config.vexplain.bedag.ch,resources=operatorconfigs/status,verbs=get;update;patch

// Reconcile checks the OperatorConfig and records the result in its Ready condition. The
// condition is True with reason Valid, or False with reason Invalid and the error of scope.New as
// its message, which names the first selector at fault. The CRD schema cannot tell whether a
// label selector parses, so only this controller can.
//
// A deleted OperatorConfig needs no work: settings.Load falls back to the defaults.
func (r *OperatorConfigReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var operatorConfig configv1alpha1.OperatorConfig
	if err := r.Get(ctx, req.NamespacedName, &operatorConfig); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	ready := readyCondition(&operatorConfig)
	// Write only a change, so that a retry of an unchanged object costs no API call.
	if !meta.SetStatusCondition(&operatorConfig.Status.Conditions, ready) {
		return ctrl.Result{}, nil
	}
	if err := r.Status().Update(ctx, &operatorConfig); err != nil {
		// NotFound means the object was deleted since it was read. Any other error, a conflict
		// included, is returned, and controller-runtime retries with a back-off.
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	logf.FromContext(ctx).Info("Updated the Ready condition of the OperatorConfig",
		"status", ready.Status, "reason", ready.Reason, "message", ready.Message)
	return ctrl.Result{}, nil
}

// readyCondition is the Ready condition that the spec of operatorConfig deserves.
func readyCondition(operatorConfig *configv1alpha1.OperatorConfig) metav1.Condition {
	ready := metav1.Condition{
		Type:               configv1alpha1.ConditionReady,
		ObservedGeneration: operatorConfig.Generation,
	}
	// The scope is valid when scope.New accepts it. The pod inventory builds its matcher with the
	// same function, so the condition never says Valid for a scope that the inventory refuses.
	if _, err := scope.New(operatorConfig.Spec.Scope); err != nil {
		ready.Status = metav1.ConditionFalse
		ready.Reason = configv1alpha1.ReasonInvalid
		ready.Message = err.Error()
		return ready
	}
	ready.Status = metav1.ConditionTrue
	ready.Reason = configv1alpha1.ReasonValid
	ready.Message = "The configuration is valid."
	return ready
}

// SetupWithManager sets up the controller with the Manager.
func (r *OperatorConfigReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		// Only a new object or a changed spec needs a reconcile. The controller's own status
		// writes must not start another one.
		For(&configv1alpha1.OperatorConfig{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Named("config-operatorconfig").
		Complete(r)
}
