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
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/events"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/agent/profile"
	"github.com/bedag/vexplain/internal/conditions"
)

// eventReasonAgentProfileInvalid is the reason of the Warning event that an AgentProfile gets when it turns to
// Ready=False.
const eventReasonAgentProfileInvalid = "AgentProfileInvalid"

// AgentProfileReconciler reconciles an AgentProfile: it reads its guidance and its ModelConfig, and reports in the Ready
// condition whether a case can run with it, and in worstCaseContextTokens what its limits could put into one request.
type AgentProfileReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	// OperatorNamespace is the namespace of the operator, the only one in which a profile's ConfigMap can be.
	OperatorNamespace string
	// Recorder records the AgentProfileInvalid event.
	Recorder events.EventRecorder
}

// The controller reads the profiles and writes only their status. It creates the profile named default at its start,
// when it is missing, and never writes one again. It reads the ModelConfigs that the profiles name, and watches them.
// +kubebuilder:rbac:groups=config.vexplain.bedag.ch,resources=agentprofiles,verbs=get;list;watch;create
// +kubebuilder:rbac:groups=config.vexplain.bedag.ch,resources=modelconfigs,verbs=get;list;watch
// +kubebuilder:rbac:groups=config.vexplain.bedag.ch,resources=agentprofiles/status,verbs=update

// The guidance is read from the manager's cache, which holds the ConfigMaps of the operator's namespace only
// (setup.CacheOptions), so the rule is a Role in that namespace. config/rbac/manager_secrets_rolebinding.yaml binds it.
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch,namespace=vexplain-system

// Reconcile checks the AgentProfile and records the result in its Ready condition and its worstCaseContextTokens. A
// profile that isn't Ready is Stalled: each reason needs a change of the profile, of its ModelConfig or of its
// ConfigMap, which the controller watches, so it asks for no requeue.
//
// On a transition to Ready=False it records an AgentProfileInvalid event, once the status is written, so that a
// write that fails is retried together with its event.
//
// It returns the errors of reading the profile, its ConfigMap or its ModelConfig, other than NotFound, and of writing
// the status, so that the request is retried. A deleted profile needs no work.
func (r *AgentProfileReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var obj configv1alpha1.AgentProfile
	if err := r.Get(ctx, req.NamespacedName, &obj); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	effective, err := profile.Load(ctx, r.Client, r.OperatorNamespace, &obj)
	ready := metav1.Condition{
		Type:               configv1alpha1.ConditionReady,
		Status:             metav1.ConditionTrue,
		Reason:             configv1alpha1.ReasonValid,
		Message:            "The guidance can be read, and the limits fit the context window of the ModelConfig.",
		ObservedGeneration: obj.Generation,
	}
	progress := conditions.None
	var problem *profile.Problem
	switch {
	case errors.As(err, &problem):
		ready.Status = metav1.ConditionFalse
		ready.Reason = problem.Reason
		ready.Message = truncate(problem.Message)
		progress = conditions.Stalled
	case err != nil:
		return ctrl.Result{}, err
	}
	var worst *int64
	if effective.WorstCaseContextTokens > 0 {
		worst = ptr.To(effective.WorstCaseContextTokens)
	}

	wasFailing := meta.IsStatusConditionFalse(obj.Status.Conditions, configv1alpha1.ConditionReady)
	conditionChanged := conditions.SetReady(&obj.Status.Conditions, ready, progress)
	observedChanged := conditions.Observe(&obj.Status.ObservedGeneration, obj.Generation)
	worstChanged := !ptr.Equal(obj.Status.WorstCaseContextTokens, worst)
	if !conditionChanged && !observedChanged && !worstChanged {
		return ctrl.Result{}, nil
	}
	obj.Status.WorstCaseContextTokens = worst
	if err := r.Status().Update(ctx, &obj); err != nil {
		// NotFound means the object was deleted since it was read. Any other error, a conflict included, is returned,
		// and controller-runtime retries with a back-off.
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if conditionChanged {
		logf.FromContext(ctx).Info("Updated the Ready condition of the AgentProfile",
			"status", ready.Status, "reason", ready.Reason, "message", ready.Message)
	}
	if ready.Status == metav1.ConditionFalse && !wasFailing {
		r.Recorder.Eventf(&obj, nil, corev1.EventTypeWarning,
			eventReasonAgentProfileInvalid, eventActionReconcile, "%s", ready.Message)
	}
	return ctrl.Result{}, nil
}

// ensureDefaultAgentProfile creates the AgentProfile named default, with the embedded guidance, the ModelConfig named
// default, the operation describe of the collector vulnerabilities and the operation fetch of the collector advisories,
// when it is missing, and leaves one that exists as it is, whatever an admin made of it. Without describe, the agent
// can never show that a package has the fix. fetch reads the advisories that describe links to, and offers no tool
// where advisories isn't installed, as in a cluster without internet.
func ensureDefaultAgentProfile(ctx context.Context, c client.Client) error {
	err := c.Create(ctx, &configv1alpha1.AgentProfile{
		ObjectMeta: metav1.ObjectMeta{Name: profile.DefaultName},
		Spec: configv1alpha1.AgentProfileSpec{
			ModelRef: configv1alpha1.ModelConfigReference{Name: profile.DefaultName},
			Guidance: &configv1alpha1.AgentGuidance{Type: configv1alpha1.AgentGuidanceEmbedded},
			Tools: []configv1alpha1.AgentToolGrant{
				{Collector: "vulnerabilities", Operations: []string{"describe"}},
				{Collector: "advisories", Operations: []string{"fetch"}},
			},
		},
	})
	if apierrors.IsAlreadyExists(err) {
		return nil
	}
	return err
}

// profilesFor returns the requests of the profiles that refer to obj, a ModelConfig or a ConfigMap of the operator's
// namespace, which the manager's cache alone holds.
func (r *AgentProfileReconciler) profilesFor(refers func(*configv1alpha1.AgentProfile, string) bool) handler.MapFunc {
	return func(ctx context.Context, obj client.Object) []reconcile.Request {
		// There are a few profiles at most, so a list costs less than an index to keep.
		var list configv1alpha1.AgentProfileList
		if err := r.List(ctx, &list); err != nil {
			logf.FromContext(ctx).Error(err, "Could not list the AgentProfiles that may refer to an object",
				"object", client.ObjectKeyFromObject(obj).String())
			return nil
		}
		var requests []reconcile.Request
		for i := range list.Items {
			if refers(&list.Items[i], obj.GetName()) {
				requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKey{Name: list.Items[i].Name}})
			}
		}
		return requests
	}
}

// usesModel says whether p names the ModelConfig name.
func usesModel(p *configv1alpha1.AgentProfile, name string) bool { return p.Spec.ModelRef.Name == name }

// usesConfigMap says whether p takes its guidance from the ConfigMap name.
func usesConfigMap(p *configv1alpha1.AgentProfile, name string) bool {
	g := p.Spec.Guidance
	return g != nil && g.ConfigMapRef != nil && g.ConfigMapRef.Name == name
}

// SetupWithManager sets up the controller with the Manager, and the creation of the default profile at its start.
func (r *AgentProfileReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// A RunnableFunc runs on the leader only, once the caches have synced.
	if err := mgr.Add(manager.RunnableFunc(func(ctx context.Context) error {
		return createDefault(ctx, "agent-profile", func(ctx context.Context) error {
			return ensureDefaultAgentProfile(ctx, r.Client)
		})
	})); err != nil {
		return fmt.Errorf("add the creation of the default AgentProfile: %w", err)
	}
	return ctrl.NewControllerManagedBy(mgr).
		// The controller's own status writes start no reconcile.
		For(&configv1alpha1.AgentProfile{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		// A ModelConfig's window is in its spec. Its status, which its probes write, says nothing about a profile.
		Watches(&configv1alpha1.ModelConfig{}, handler.EnqueueRequestsFromMapFunc(r.profilesFor(usesModel)),
			builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		// A ConfigMap that appears, changes or goes away is checked at once.
		Watches(&corev1.ConfigMap{}, handler.EnqueueRequestsFromMapFunc(r.profilesFor(usesConfigMap))).
		Named("config-agentprofile").
		Complete(r)
}
