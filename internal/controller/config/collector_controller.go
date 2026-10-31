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
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/events"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/collector"
)

// eventReasonCollectorUnhealthy is the reason of the Warning event that a Collector gets when it
// turns to Ready=False.
const eventReasonCollectorUnhealthy = "CollectorUnhealthy"

// CollectorReconciler reconciles a Collector object
type CollectorReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	// Registry holds the health that the collectors report. The reconciler only reads it.
	Registry *collector.Registry
	// Recorder records the CollectorUnhealthy event.
	Recorder events.EventRecorder
	// Resync is how long the reconciler waits before it reads the health of a Collector again. A
	// report changes the registry and no object, so nothing else wakes the reconciler: this is how
	// fast the status follows a report. Zero means no resync, and the status then follows only
	// when the Collector itself changes.
	Resync time.Duration
}

// The controller reads a Collector and writes only its status, so it holds no write access to the
// object itself and no finalizers right. The default Collector is created by
// collector.EnsureDefaults, which carries its own marker.
// +kubebuilder:rbac:groups=config.vexplain.bedag.ch,resources=collectors,verbs=get;list;watch
// +kubebuilder:rbac:groups=config.vexplain.bedag.ch,resources=collectors/status,verbs=get;update;patch

// The events API files the CollectorUnhealthy event. The recorder creates the event, and patches
// it when the same event repeats.
// +kubebuilder:rbac:groups=events.k8s.io,resources=events,verbs=create;patch

// Reconcile maps the health that the registry holds for the type of a Collector to its Ready
// condition and its lastSuccessTime, and asks to be called again after the resync, because a
// report changes the registry without changing any object.
//
// The registry is empty after a restart of the operator. Until it holds a success, the
// lastSuccessTime that the status already has stays, so a restart doesn't erase it.
//
// On a transition to Ready=False it records a CollectorUnhealthy event. It does that once the
// status is written, so a write that fails is retried together with its event and no event is
// recorded for a status that never was.
//
// A deleted Collector needs no work, and is not requeued.
func (r *CollectorReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var obj configv1alpha1.Collector
	if err := r.Get(ctx, req.NamespacedName, &obj); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	ready, lastSuccess := r.observe(&obj)
	if lastSuccess == nil {
		// The registry has no success to report. A success from before a restart is still the last
		// one there was, and only a later success replaces it.
		lastSuccess = obj.Status.LastSuccessTime
	}
	wasFailing := meta.IsStatusConditionFalse(obj.Status.Conditions, configv1alpha1.ConditionReady)
	// Write only a change, so that the resync of a steady Collector costs no API call.
	conditionChanged := meta.SetStatusCondition(&obj.Status.Conditions, ready)
	timeChanged := !obj.Status.LastSuccessTime.Equal(lastSuccess)
	if !conditionChanged && !timeChanged {
		return ctrl.Result{RequeueAfter: r.Resync}, nil
	}
	obj.Status.LastSuccessTime = lastSuccess
	if err := r.Status().Update(ctx, &obj); err != nil {
		// NotFound means the object was deleted since it was read. Any other error, a conflict
		// included, is returned, and controller-runtime retries with a back-off.
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	// A new success time alone is not worth a line: with work going on, it changes at every resync.
	if conditionChanged {
		logf.FromContext(ctx).Info("Updated the Ready condition of the Collector",
			"status", ready.Status, "reason", ready.Reason, "message", ready.Message)
	}

	if ready.Status == metav1.ConditionFalse && !wasFailing {
		r.Recorder.Eventf(&obj, nil, corev1.EventTypeWarning,
			eventReasonCollectorUnhealthy, eventActionReconcile, "%s", ready.Message)
	}
	return ctrl.Result{RequeueAfter: r.Resync}, nil
}

// observe returns the Ready condition that obj deserves and the time of its last success, from
// the health that the registry holds for its type. The time is nil when the registry holds no
// success. That says nothing about the time that the status of obj already holds.
func (r *CollectorReconciler) observe(obj *configv1alpha1.Collector) (metav1.Condition, *metav1.Time) {
	ready := metav1.Condition{
		Type:               configv1alpha1.ConditionReady,
		ObservedGeneration: obj.Generation,
	}
	if !knownType(obj.Spec.Type) {
		// The CRD enum stops an unknown type at admission. One gets here when a newer CRD admitted
		// a type that this older operator doesn't run, so there is no health to ask for.
		ready.Status = metav1.ConditionFalse
		ready.Reason = configv1alpha1.ReasonUnknownValue
		ready.Message = truncate(fmt.Sprintf(
			"spec.type: %q is not a collector type that this version of the operator knows.", obj.Spec.Type))
		return ready, nil
	}

	lastSuccess, lastErr, known := r.Registry.Health(obj.Spec.Type)
	var successTime *metav1.Time
	if !lastSuccess.IsZero() {
		// The API keeps whole seconds. A finer time would never equal the stored one, and every
		// resync would write the status again.
		successTime = ptr.To(metav1.NewTime(lastSuccess.Truncate(time.Second)))
	}
	switch {
	case !known:
		ready.Status = metav1.ConditionUnknown
		ready.Reason = configv1alpha1.ReasonNoData
		ready.Message = "The collector has not reported since the operator started."
	case lastErr != nil:
		ready.Status = metav1.ConditionFalse
		ready.Reason = configv1alpha1.ReasonCollectorFailing
		ready.Message = truncate(lastErr.Error())
	default:
		ready.Status = metav1.ConditionTrue
		ready.Reason = configv1alpha1.ReasonHealthy
		ready.Message = "The last run of the collector succeeded."
	}
	return ready, successTime
}

// knownType says whether this version of the operator has a collector of type t.
func knownType(t configv1alpha1.CollectorType) bool {
	return t == configv1alpha1.CollectorTypeWorkloads || t == configv1alpha1.CollectorTypeScanner
}

// SetupWithManager sets up the controller with the Manager.
func (r *CollectorReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		// Only a new object or a changed spec needs a reconcile from an event. The controller's own
		// status writes must not start another one, and the resync covers a change of health.
		For(&configv1alpha1.Collector{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Named("config-collector").
		Complete(r)
}
