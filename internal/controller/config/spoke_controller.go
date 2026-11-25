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
	"crypto/tls"
	"errors"
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/conditions"
	"github.com/bedag/vexplain/internal/remote"
	"github.com/bedag/vexplain/internal/settings"
	"github.com/bedag/vexplain/internal/text"
)

// The controller reads the Spokes, adds and removes its finalizer, and writes their status.
// +kubebuilder:rbac:groups=config.vexplain.bedag.ch,resources=spokes,verbs=get;list;watch;update
// +kubebuilder:rbac:groups=config.vexplain.bedag.ch,resources=spokes/status,verbs=update

// The hub's own Secret of a spoke names its Spoke as its owner, which blocks the Spoke's deletion until the garbage
// collector has deleted it. A cluster that enforces the permissions of owner references allows that only to whoever may
// update the finalizers of Spokes.
// +kubebuilder:rbac:groups=config.vexplain.bedag.ch,resources=spokes/finalizers,verbs=update

// The controller reads the admin's Secret of each spoke, and the hub's own, through the API reader, and creates and
// updates the hub's own. Markers generate no bindings: config/rbac/manager_secrets_rolebinding.yaml binds the Role.
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;create;update,namespace=vexplain-system

const (
	// spokeFinalizer keeps a deleted Spoke until the hub has let go of the cluster. The hub's own Secret of the spoke
	// needs no step of its own: the Spoke owns it, so the garbage collector deletes it with the Spoke.
	spokeFinalizer = "vexplain.bedag.ch/spoke"
	// spokeCheck is how often the hub checks each spoke: its connection, and whether its token is due, so a token is
	// renewed at most this long after half its lifetime. The manager's cache holds no Secret, so this is also how soon
	// the hub reads a changed Secret.
	spokeCheck = time.Minute
	// spokeGrace is how long a spoke may stay unreachable while its Spoke is Reconciling. After it, the Spoke is
	// Stalled, so that a spoke that is gone for good never reads as in progress for ever (decision 0036). It is the
	// grace of a collector's health, and of a model endpoint.
	spokeGrace = 2 * time.Minute
)

// SpokeReconciler connects the hub to the spoke that each Spoke records (design 5.4): it builds the spoke's config
// through the seam, remote.Config, checks the cluster's identity, renews the hub's token at half its lifetime, and
// records what it found in the Spoke's status.
//
// The first contact records the spoke's identity, the UID of its kube-system namespace, in status.clusterID. A later
// contact that finds another UID stops there, with Connected False and IdentityChanged, until an admin clears the
// field: a Secret that points at another cluster never acts under this Spoke's name. Connected is False with
// TokenExpired when the hub holds no valid token, with CredentialsInvalid when the Secret can't be used or the spoke
// refuses it, and with Unreachable when the call fails otherwise. Ready says what Connected says. Unreachable is
// Reconciling within the grace, and Stalled after it; each other failure needs a change of the Secret, of the spoke or
// of the Spoke, and is Stalled at once.
type SpokeReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	// APIReader reads the admin's Secret of each spoke and the hub's own, which the manager's cache doesn't hold.
	APIReader client.Reader
	// OperatorNamespace is where both Secrets are.
	OperatorNamespace string
	// Renewer renews the hub's token for each spoke into the hub's own Secret.
	Renewer *remote.Renewer
}

// contact is what a check of a spoke found: its Connected condition, what a Connected that isn't True means for
// kstatus, and what the status records. A field that is nil leaves what the status holds.
type contact struct {
	status    metav1.ConditionStatus
	reason    string
	message   string
	progress  conditions.Progress
	clusterID *string
	expires   *time.Time
}

// Reconcile checks the connection to the spoke of a Spoke, records it, and asks to be called again after spokeCheck.
// It returns the errors of the hub's own API server, so that the request is tried again, and lets a deleted Spoke go.
func (r *SpokeReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var obj configv1alpha1.Spoke
	if err := r.Get(ctx, req.NamespacedName, &obj); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !obj.DeletionTimestamp.IsZero() {
		if controllerutil.RemoveFinalizer(&obj, spokeFinalizer) {
			return ctrl.Result{}, client.IgnoreNotFound(r.Update(ctx, &obj))
		}
		return ctrl.Result{}, nil
	}
	if controllerutil.AddFinalizer(&obj, spokeFinalizer) {
		if err := r.Update(ctx, &obj); err != nil {
			return ctrl.Result{}, client.IgnoreNotFound(err)
		}
	}
	found, err := r.connect(ctx, &obj)
	if err != nil {
		return ctrl.Result{}, err
	}
	// NotFound means the Spoke was deleted since it was read. Any other error, a conflict included, is returned, and
	// controller-runtime retries with a back-off.
	if err := r.record(ctx, &obj, found); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	return ctrl.Result{RequeueAfter: spokeCheck}, nil
}

// connect builds the spoke's config, checks the cluster's identity through it, and renews the token when it is due.
// It returns an error, and nothing found, only when the hub's own API server fails to give a Secret, which says
// nothing about the spoke.
func (r *SpokeReconciler) connect(ctx context.Context, obj *configv1alpha1.Spoke) (contact, error) {
	cfg, err := remote.Config(ctx, r.APIReader, r.OperatorNamespace, obj)
	var hubStatus apierrors.APIStatus
	switch {
	case errors.Is(err, remote.ErrTokenExpired):
		return failure(configv1alpha1.ReasonTokenExpired, err), nil
	case errors.As(err, &hubStatus) && !apierrors.IsNotFound(err):
		return contact{}, err
	case err != nil:
		return failure(configv1alpha1.ReasonCredentialsInvalid, err), nil
	}
	id, err := within(ctx, func(ctx context.Context) (string, error) {
		spoke, err := client.New(cfg, client.Options{Scheme: r.Scheme})
		if err != nil {
			return "", err
		}
		return settings.ClusterID(ctx, spoke)
	})
	if err != nil {
		return unreached(err), nil
	}
	if recorded := obj.Status.ClusterID; recorded != nil && *recorded != id {
		return failure(configv1alpha1.ReasonIdentityChanged, fmt.Errorf("the API server that the Secret names belongs "+
			"to the cluster %s, not to %s, which the hub recorded at its first contact; clear status.clusterID to "+
			"accept it", id, *recorded)), nil
	}
	expires, err := within(ctx, func(ctx context.Context) (time.Time, error) { return r.Renewer.Renew(ctx, obj, cfg) })
	if err != nil {
		// shortcut: a failed write of the hub's own Secret reads as a failed call to the spoke, though its message says
		// which; it needs the hub's API server down, and the next check tries again. Tell them apart if it shows.
		found := unreached(err)
		found.clusterID = &id
		return found, nil
	}
	return contact{status: metav1.ConditionTrue, reason: configv1alpha1.ReasonConnected, clusterID: &id,
		expires: &expires, message: "The hub reaches the spoke's API server, its token works, and the cluster is " +
			"the one that it first recorded."}, nil
}

// failure is a check that failed for reason, with the text of err. The controller is stalled: what failed needs a
// change of the Secret, of the spoke or of the Spoke.
func failure(reason string, err error) contact {
	return contact{status: metav1.ConditionFalse, reason: reason, message: err.Error(), progress: conditions.Stalled}
}

// unreached is a check whose call to the spoke failed. A spoke whose certificate doesn't verify against the Secret's
// CA bundle, or that refuses the token, needs a change of the Secret or of the spoke: CredentialsInvalid. Anything
// else may pass, as a spoke that restarts does: Unreachable, which is retried at each check.
func unreached(err error) contact {
	var verification *tls.CertificateVerificationError
	if errors.As(err, &verification) || apierrors.IsUnauthorized(err) || apierrors.IsForbidden(err) {
		return failure(configv1alpha1.ReasonCredentialsInvalid, err)
	}
	found := failure(configv1alpha1.ReasonUnreachable, err)
	found.progress = conditions.Reconciling
	return found
}

// record writes what found says into the status of obj, when it changes it.
func (r *SpokeReconciler) record(ctx context.Context, obj *configv1alpha1.Spoke, found contact) error {
	// The grace runs from when the hub lost the spoke: when Connected last turned False.
	lost := meta.FindStatusCondition(obj.Status.Conditions, configv1alpha1.ConditionConnected)
	if found.progress == conditions.Reconciling && lost != nil && lost.Status == metav1.ConditionFalse &&
		time.Since(lost.LastTransitionTime.Time) >= spokeGrace {
		found.progress = conditions.Stalled
	}
	connected := metav1.Condition{
		Type:   configv1alpha1.ConditionConnected,
		Status: found.status,
		Reason: found.reason,
		// The message can be the text of the spoke's API server.
		Message:            truncate(text.Printable(found.message)),
		ObservedGeneration: obj.Generation,
	}
	before := obj.Status.DeepCopy()
	changed := meta.SetStatusCondition(&obj.Status.Conditions, connected)
	conditions.SetReady(&obj.Status.Conditions, connected, found.progress)
	conditions.Observe(&obj.Status.ObservedGeneration, obj.Generation)
	if obj.Status.ClusterID == nil {
		obj.Status.ClusterID = found.clusterID
	}
	// The API keeps whole seconds.
	if found.expires != nil {
		expires := metav1.NewTime(found.expires.Truncate(time.Second))
		obj.Status.TokenExpirationTime = &expires
	}
	if equality.Semantic.DeepEqual(before, &obj.Status) {
		return nil
	}
	if err := r.Status().Update(ctx, obj); err != nil {
		return err
	}
	if changed {
		logf.FromContext(ctx).Info("Updated the Connected condition of the Spoke", "status", connected.Status,
			"reason", connected.Reason)
	}
	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *SpokeReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		// The controller's own status writes start no reconcile: the check every spokeCheck follows the spoke.
		For(&configv1alpha1.Spoke{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		// A failed reconcile is tried again within spokeCheck, so that the check keeps its pace.
		WithOptions(controller.Options{RateLimiter: retryLimiter(spokeCheck)}).
		Named("config-spoke").
		Complete(r)
}
