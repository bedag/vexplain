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
	"strings"
	"sync"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/events"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/collector/certs"
	"github.com/bedag/vexplain/internal/collectorclient"
	"github.com/bedag/vexplain/internal/conditions"
	"github.com/bedag/vexplain/internal/evidence"
	"github.com/bedag/vexplain/internal/text"
	collectorv1alpha1 "github.com/bedag/vexplain/sdk/api/collector/v1alpha1"
)

// The deployer reads the Collectors, adds and removes its finalizer, and writes their status.
// +kubebuilder:rbac:groups=config.vexplain.bedag.ch,resources=collectors,verbs=get;list;watch;update
// +kubebuilder:rbac:groups=config.vexplain.bedag.ch,resources=collectors/status,verbs=get;update;patch

// What the deployer makes for a Collector names it as its owner, which blocks the Collector's deletion until the
// garbage collector has deleted it. A cluster that enforces the permissions of owner references allows that only to
// whoever may update the finalizers of Collectors.
// +kubebuilder:rbac:groups=config.vexplain.bedag.ch,resources=collectors/finalizers,verbs=update

// The events API files the CollectorUnhealthy event. The recorder creates the event, and patches it when the same
// event repeats.
// +kubebuilder:rbac:groups=events.k8s.io,resources=events,verbs=create;patch

const (
	// eventReasonCollectorUnhealthy is the reason of the Warning event that a Collector gets when it turns to
	// Ready=False.
	eventReasonCollectorUnhealthy = "CollectorUnhealthy"
	// evidenceFinalizer keeps a deleted Collector until the deployer has deleted the evidence that the collector
	// delivered: deleting a collector removes its evidence (design 5.9).
	evidenceFinalizer = "vexplain.bedag.ch/evidence"
	// apiVersion is the version of the collector API that this operator speaks.
	apiVersion = "v1alpha1"
	// healthGrace is how long after the operator's start, or after a collector's certificate was issued again, a
	// call of the collector that fails says nothing about its health. Each start issues every certificate again, from
	// a new authority, and a collector refuses the operator until the kubelet has updated its mounted Secret, within
	// about a minute, and it has loaded the files, within 10 seconds more.
	healthGrace = 2 * time.Minute
	// callTimeout bounds each call of a collector, so that one that doesn't answer holds the deployer up no longer.
	callTimeout = 10 * time.Second
	// maxShownProblems is how many problems of the settings a condition's message gives.
	maxShownProblems = 3
	// lastSuccessRefresh is how old the last success time that a healthy collector's status holds may grow before the
	// deployer writes a newer one: the status isn't written at every resync for the time alone.
	lastSuccessRefresh = 5 * time.Minute
)

// CollectorReconciler is the deployer: it runs the collector that each Collector installs, from its package, and
// keeps its Ready condition, as design 5.2 to 5.4, 5.8 and 5.9 describe.
//
// For each Collector it keeps, in the operator's namespace, the collector's TLS Secret through the Authority, its
// service account, its Service and its Deployment, all labelled with the Collector's name and owned by the Collector,
// so that the garbage collector deletes them with it. A CollectorRuntimeConfig shapes the Deployment and the service
// account. Once the Deployment is available, the deployer asks the collector about itself, checks its settings and
// the permissions of its service account, and runs the standard gRPC health check, at every resync.
//
// Ready is Unknown with Progressing while the Deployment rolls out, and then False for the first thing that keeps the
// collector from being used: RuntimeConfigInvalid, IncompatibleAPI, PackageInvalid, SettingsInvalid or
// MissingPermissions. Otherwise it follows the health check: True with Healthy, or False with CollectorFailing. A
// collector that can't be reached, because the call fails or its Deployment has no available replica after its
// rollout, is failing too. Within the grace after a start, or after the collector's certificate was issued again,
// that leaves Ready Unknown, with NoData instead: the collector may not have loaded its new certificate yet. An error
// that keeps the deployer from checking the collector, and that trying again won't fix, or that keeps coming back for
// longer than the grace, counts as the collector not being reached, since Ready can't say that it works. A failed
// reconcile is tried again within a resync. A change to False records the CollectorUnhealthy event.
//
// A deleted Collector keeps the deployer's finalizer until the deployer has deleted the evidence that the collector
// delivered, removed its entries from the facts, deleted its TLS Secret, and closed the pool's connection to it.
//
// The deployer writes certificates, so it runs on the leader only, as every controller does: two processes would issue
// each other's certificates again and again.
type CollectorReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	// APIReader reads the TLS Secrets, which the manager's cache doesn't hold.
	APIReader client.Reader
	// Recorder records the CollectorUnhealthy event.
	Recorder events.EventRecorder
	// Authority issues the collectors' certificates, and Pool calls the collectors with the client certificate that it
	// issues to the operator. The streams and the executor share both.
	Authority *certs.Authority
	Pool      *collectorclient.Pool
	// Evidence and Facts hold what the collectors delivered, which the finalizer of a deleted Collector removes.
	Evidence evidence.Store
	Facts    evidence.FactsWriter
	// OperatorNamespace is where the collectors run.
	OperatorNamespace string
	// Resync is how long the deployer waits before it checks a collector again: its health check, its answers, its
	// settings and its permissions. Nothing else tells it of a change in health or permissions, so this is how fast
	// the condition follows one. It also renews the collector's certificate in time.
	Resync time.Duration
	// Now is the clock of the grace after a start or a new certificate, and of a success. Nil means time.Now.
	Now func() time.Time

	// mu guards started, issued, owned and failing.
	mu sync.Mutex
	// started is when this process's deployer first reconciled, and issued when it last issued each collector's
	// certificate: each starts a grace.
	started time.Time
	issued  map[string]time.Time
	// owned holds the collectors whose TLS Secret this process saw labelled and owned since it last issued it: until
	// then, the deployer reads the Secret at each check.
	owned map[string]bool
	// failing holds when each collector's reconciles started failing with errors that may pass, until one succeeds.
	failing map[string]time.Time
}

// Reconcile keeps the collector of a Collector running, and its status current, and asks to be called again after the
// resync. It deletes a deleted Collector's evidence before it lets the Collector go.
//
// It writes the status only when it changes, and records a CollectorUnhealthy event once the status that turned Ready
// False is written, so that a write that fails is retried together with its event.
func (r *CollectorReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var obj configv1alpha1.Collector
	if err := r.Get(ctx, req.NamespacedName, &obj); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	r.noteStart()
	if !obj.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, r.finalize(ctx, &obj)
	}
	if controllerutil.AddFinalizer(&obj, evidenceFinalizer) {
		if err := r.Update(ctx, &obj); err != nil {
			return ctrl.Result{}, client.IgnoreNotFound(err)
		}
	}
	found, err := r.check(ctx, &obj)
	switch {
	case err == nil:
		r.endFailures(obj.Name)
	case !transient(err) || r.failingPastGrace(obj.Name):
		// The deployer can't keep the collector running, or check it: trying again won't change that by itself, or
		// errors that might pass have gone on for longer than the grace. Ready says that the collector can't be
		// reached, rather than what the deployer last found. The error is returned all the same, and
		// controller-runtime tries again.
		found = found.with(r.unreachable(obj.Name, err))
		if recordErr := r.record(ctx, &obj, found); recordErr != nil {
			logf.FromContext(ctx).Error(recordErr, "Could not write the Ready condition of the Collector")
		}
	}
	if err != nil {
		return ctrl.Result{}, err
	}
	// NotFound means the Collector was deleted since it was read. Any other error, a conflict included, is returned,
	// and controller-runtime retries with a back-off.
	if err := r.record(ctx, &obj, found); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	return ctrl.Result{RequeueAfter: r.Resync}, nil
}

// transient says whether an error may pass when the reconcile is tried again: a conflict with another write, which the
// next read resolves, the API server being busy or not answering, as for a webhook that it can't call, or a call that
// broke off. Any other error stays until someone changes something, such as a refusal, a missing right, or an object
// that another controller owns. A transient error that keeps coming back counts as one that stays once it has gone on
// for longer than the grace (failingPastGrace).
func transient(err error) bool {
	var status apierrors.APIStatus
	if !errors.As(err, &status) {
		var owned *controllerutil.AlreadyOwnedError
		return !errors.As(err, &owned)
	}
	return apierrors.IsConflict(err) || apierrors.IsAlreadyExists(err) || apierrors.IsServerTimeout(err) ||
		apierrors.IsTimeout(err) || apierrors.IsTooManyRequests(err) || apierrors.IsServiceUnavailable(err) ||
		apierrors.IsInternalError(err) || apierrors.IsUnexpectedServerError(err)
}

// finding is what a check of a collector found: its Ready condition, what a Ready that isn't True means for kstatus,
// and what the status records of the collector. A field that is nil leaves what the status holds.
type finding struct {
	status       metav1.ConditionStatus
	reason       string
	message      string
	progress     conditions.Progress
	digest       *string
	version      *string
	capabilities *configv1alpha1.CollectorCapabilities
	// sources are what GetInfo reported. They are recorded when sourcesKnown, even when there are none.
	sources      []configv1alpha1.CollectorSource
	sourcesKnown bool
	succeeded    *time.Time
}

// refusal is why a collector can't be used: the reason of its Ready condition, which is False, and the message.
type refusal struct{ reason, message string }

func refuse(reason, format string, args ...any) *refusal {
	return &refusal{reason: reason, message: fmt.Sprintf(format, args...)}
}

// of returns found, refused for the reason of r. A refusal needs a change of the package, the spec, the permissions
// or the runtime config, so the deployer is stalled until then.
func (r *refusal) of(found finding) finding {
	found.status, found.reason, found.message = metav1.ConditionFalse, r.reason, r.message
	found.progress = conditions.Stalled
	return found
}

// check keeps what the collector of obj needs to run, and, once its Deployment has rolled out, asks the collector. It
// returns an error for what the deployer couldn't do, such as a write that the API server failed, with what it found
// until then; Reconcile decides whether the error says that the collector can't be reached. A write that the API
// server refuses is no error: it is RuntimeConfigInvalid.
func (r *CollectorReconciler) check(ctx context.Context, obj *configv1alpha1.Collector) (finding, error) {
	// The certificate comes first, whatever else fails: a running collector needs one that the authority of this
	// process issued, and one renewed in time.
	renewed, err := r.Authority.EnsureServer(ctx, obj.Name)
	if err != nil {
		return finding{}, fmt.Errorf("ensure the TLS Secret of collector %s: %w", obj.Name, err)
	}
	if renewed {
		r.noteIssued(obj.Name)
	}
	if !r.secretOwned(obj.Name) {
		if err := r.ownSecret(ctx, obj); err != nil {
			return finding{}, err
		}
		r.noteOwned(obj.Name)
	}

	shaped, refused, err := r.shapeOf(ctx, obj)
	if err != nil || refused != nil {
		return refusalOf(refused), err
	}
	deployment, refused, err := r.deploy(ctx, obj, shaped)
	if err != nil || refused != nil {
		return refusalOf(refused), err
	}
	switch inProgress, failure := rolloutOf(deployment); {
	case failure != nil:
		return r.unreachable(obj.Name, failure), nil
	case inProgress:
		return finding{status: metav1.ConditionUnknown, reason: configv1alpha1.ReasonProgressing,
			message: "The Deployment of the collector is rolling out.", progress: conditions.Reconciling}, nil
	}
	digest, err := r.runningDigest(ctx, obj)
	if err != nil {
		return finding{}, err
	}
	account := deployment.Spec.Template.Spec.ServiceAccountName
	if account == "" {
		account = "default"
	}
	found, err := r.ask(ctx, obj, account)
	found.digest = digest
	return found, err
}

// refusalOf returns the finding of a refusal, or nothing for none.
func refusalOf(refused *refusal) finding {
	if refused == nil {
		return finding{}
	}
	return refused.of(finding{})
}

// deploy writes the collector's service account, Service and Deployment, and returns the Deployment. A write of what
// the runtime config shapes that the API server refuses, as invalid, as a bad request, or as forbidden, such as by an
// admission webhook or a quota, is RuntimeConfigInvalid, with the API server's message, which says why: trying again
// changes nothing until the runtime config, the package or what refuses it changes.
func (r *CollectorReconciler) deploy(ctx context.Context, obj *configv1alpha1.Collector, shaped *shape) (
	*appsv1.Deployment, *refusal, error) {
	refusedWrite := func(err error) (*appsv1.Deployment, *refusal, error) {
		if apierrors.IsInvalid(err) || apierrors.IsBadRequest(err) || apierrors.IsForbidden(err) {
			return nil, refuse(configv1alpha1.ReasonRuntimeConfigInvalid,
				"The API server refuses to write what the runtime config shapes: %v", err), nil
		}
		return nil, nil, err
	}
	if err := r.applyServiceAccount(ctx, obj, shaped); err != nil {
		return refusedWrite(err)
	}
	if err := r.applyService(ctx, obj); err != nil {
		return nil, nil, err
	}
	deployment, err := r.applyDeployment(ctx, obj, shaped.deployment)
	if err != nil {
		return refusedWrite(err)
	}
	return deployment, nil, nil
}

// ask asks the collector what it is and what it can do, checks its settings and the permissions of its service
// account, and runs its health check, in that order: the first thing that keeps the collector from being used makes
// the finding. A call that fails is the collector failing, or nothing yet within the grace.
func (r *CollectorReconciler) ask(ctx context.Context, obj *configv1alpha1.Collector, account string) (finding, error) {
	name := obj.Name
	info, err := within(ctx, func(ctx context.Context) (*collectorv1alpha1.GetInfoResponse, error) {
		return r.Pool.Info(ctx, name)
	})
	if err != nil {
		return r.unreachable(name, err), nil
	}
	version, refused := checkInfo(info)
	if refused != nil {
		return refused.of(finding{}), nil
	}
	sources, refused := sourcesOf(info)
	if refused != nil {
		return refused.of(finding{}), nil
	}
	answer, err := within(ctx, func(ctx context.Context) (*collectorv1alpha1.GetCapabilitiesResponse, error) {
		return r.Pool.Capabilities(ctx, name)
	})
	if err != nil {
		return r.unreachable(name, err), nil
	}
	capabilities, declares, err := capabilitiesOf(answer, r.OperatorNamespace)
	if err != nil {
		return refuse(configv1alpha1.ReasonPackageInvalid, "The collector's answer to GetCapabilities is malformed: %v.", err).
			of(finding{}), nil
	}

	// What the package declares is recorded from here on, whatever keeps the collector from being used.
	found := finding{version: &version, capabilities: capabilities, sources: sources, sourcesKnown: true}
	problems, err := r.settingsProblems(ctx, obj, declares.settings)
	if err != nil {
		return found.with(r.unreachable(name, err)), nil
	}
	if len(problems) > 0 {
		return refuse(configv1alpha1.ReasonSettingsInvalid, "The settings are not valid: %s.", firstOf(problems)).of(found), nil
	}
	missing, err := r.missingPermissions(ctx, account, declares.permissions)
	if err != nil {
		return found, err
	}
	if len(missing) > 0 {
		return refuse(configv1alpha1.ReasonMissingPermissions,
			"The service account %s lacks permissions that the collector declares: %s.", account, strings.Join(missing, "; ")).
			of(found), nil
	}
	if _, err := within(ctx, func(ctx context.Context) (struct{}, error) { return struct{}{}, r.Pool.Health(ctx, name) }); err != nil {
		return found.with(r.unreachable(name, err)), nil
	}
	now := r.now()
	found.status, found.reason, found.succeeded = metav1.ConditionTrue, configv1alpha1.ReasonHealthy, &now
	found.message = "The collector answers its health check with SERVING."
	return found, nil
}

// with returns found with the Ready condition of condition, and what it means.
func (found finding) with(condition finding) finding {
	found.status, found.reason, found.message, found.progress = condition.status, condition.reason, condition.message,
		condition.progress
	return found
}

// within runs call with a context that ends after callTimeout.
func within[T any](ctx context.Context, call func(context.Context) (T, error)) (T, error) {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	return call(ctx)
}

// firstOf returns the first problems, joined, and how many more there are.
func firstOf(problems []string) string {
	shown := strings.Join(problems[:min(len(problems), maxShownProblems)], "; ")
	if more := len(problems) - maxShownProblems; more > 0 {
		shown += fmt.Sprintf("; and %d more", more)
	}
	return shown
}

// unreachable is what a check finds that can't reach the collector: a call of the collector that failed, a Deployment
// without an available replica after its rollout, or an error that keeps the deployer from checking. Within the grace
// after this process started, or after it issued the collector's certificate, the check says nothing: the collector
// may not have loaded its new certificate yet, and refuses the operator until it has. Ready is then Unknown, with
// NoData, and the deployer is reconciling: it waits on the grace. After, the collector is failing, and the deployer is
// stalled: the rollout and the grace are over, so what is left needs a change of the collector, its package or what
// it runs on, though the deployer still checks it at every resync. The error's message can be the collector's own
// text, as the message of the status that it answered with.
func (r *CollectorReconciler) unreachable(collector string, err error) finding {
	if r.inGrace(collector) {
		return finding{status: metav1.ConditionUnknown, reason: configv1alpha1.ReasonNoData, message: fmt.Sprintf(
			"The operator started, or issued the collector's certificate, less than %s ago, and a check that fails "+
				"within that grace says nothing about the collector yet. The last check: %v", healthGrace, err),
			progress: conditions.Reconciling}
	}
	return finding{status: metav1.ConditionFalse, reason: configv1alpha1.ReasonCollectorFailing, message: err.Error(),
		progress: conditions.Stalled}
}

// record writes what found says into the status of obj, when it changes it, and records the CollectorUnhealthy event
// when Ready turns False.
func (r *CollectorReconciler) record(ctx context.Context, obj *configv1alpha1.Collector, found finding) error {
	ready := metav1.Condition{
		Type:               configv1alpha1.ConditionReady,
		Status:             found.status,
		Reason:             found.reason,
		Message:            truncate(text.Printable(found.message)),
		ObservedGeneration: obj.Generation,
	}
	before := obj.Status.DeepCopy()
	wasFalse := meta.IsStatusConditionFalse(obj.Status.Conditions, configv1alpha1.ConditionReady)
	wasTrue := meta.IsStatusConditionTrue(obj.Status.Conditions, configv1alpha1.ConditionReady)
	conditionChanged := conditions.SetReady(&obj.Status.Conditions, ready, found.progress)
	conditions.Observe(&obj.Status.ObservedGeneration, obj.Generation)
	if found.digest != nil {
		obj.Status.PackageDigest = found.digest
	}
	if found.version != nil {
		obj.Status.Version = found.version
	}
	if found.capabilities != nil {
		obj.Status.Capabilities = found.capabilities
	}
	if found.sourcesKnown {
		obj.Status.Sources = found.sources
	}
	// A success is written when the collector turns healthy, and when the time that the status holds has grown old,
	// so that a healthy collector's status isn't written at every resync. The API keeps whole seconds.
	if found.succeeded != nil {
		at := metav1.NewTime(found.succeeded.Truncate(time.Second))
		if last := obj.Status.LastSuccessTime; !wasTrue || last == nil || at.Sub(last.Time) > lastSuccessRefresh {
			obj.Status.LastSuccessTime = &at
		}
	}
	if equality.Semantic.DeepEqual(before, &obj.Status) {
		return nil
	}
	if err := r.Status().Update(ctx, obj); err != nil {
		return err
	}
	// The message can be the collector's text, which the status shows: the log line names the condition only.
	if conditionChanged {
		logf.FromContext(ctx).Info("Updated the Ready condition of the Collector", "status", ready.Status, "reason", ready.Reason)
	}
	if ready.Status == metav1.ConditionFalse && !wasFalse {
		r.Recorder.Eventf(obj, nil, corev1.EventTypeWarning, eventReasonCollectorUnhealthy, eventActionReconcile,
			"%s", ready.Message)
	}
	return nil
}

// finalize deletes what the collector of a deleted Collector delivered: its evidence, and its entries and failures in
// the facts. It deletes the collector's TLS Secret itself, so that its key goes even when the Secret never got the
// Collector as its owner. It closes the pool's connection to the collector, and then lets the Collector go. The rest of
// what the deployer made for the collector goes by garbage collection, since the Collector owns it. A step that fails
// is returned, and the whole is tried again: each step does nothing the second time.
func (r *CollectorReconciler) finalize(ctx context.Context, obj *configv1alpha1.Collector) error {
	if !controllerutil.ContainsFinalizer(obj, evidenceFinalizer) {
		return nil
	}
	if err := r.Evidence.DeleteBySource(ctx, obj.Name); err != nil {
		return fmt.Errorf("delete the evidence of collector %s: %w", obj.Name, err)
	}
	if err := r.Facts.RemoveSource(ctx, obj.Name); err != nil {
		return err
	}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: r.OperatorNamespace, Name: certs.SecretName(obj.Name)}}
	if err := client.IgnoreNotFound(r.Delete(ctx, secret)); err != nil {
		return fmt.Errorf("delete the TLS Secret of collector %s: %w", obj.Name, err)
	}
	r.Pool.Forget(obj.Name)
	r.mu.Lock()
	delete(r.issued, obj.Name)
	delete(r.owned, obj.Name)
	delete(r.failing, obj.Name)
	r.mu.Unlock()
	controllerutil.RemoveFinalizer(obj, evidenceFinalizer)
	if err := r.Update(ctx, obj); err != nil {
		return client.IgnoreNotFound(err)
	}
	logf.FromContext(ctx).Info("Deleted the evidence of the collector, whose Collector is being deleted, and let it go")
	return nil
}

// now returns the time on the deployer's clock.
func (r *CollectorReconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// noteStart notes when this process's deployer first reconciled, which starts a grace for every collector.
func (r *CollectorReconciler) noteStart() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.started.IsZero() {
		r.started = r.now()
	}
}

// noteIssued notes that the collector's certificate was issued again, which starts a grace for it. The Authority may
// have created its Secret anew, without labels or owner, so the deployer reads it again.
func (r *CollectorReconciler) noteIssued(collector string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.issued == nil {
		r.issued = map[string]time.Time{}
	}
	r.issued[collector] = r.now()
	delete(r.owned, collector)
}

// noteOwned notes that the collector's TLS Secret has its labels and its owner.
func (r *CollectorReconciler) noteOwned(collector string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.owned == nil {
		r.owned = map[string]bool{}
	}
	r.owned[collector] = true
}

// failingPastGrace notes that a reconcile of the collector failed with an error that may pass, and says whether such
// errors have gone on, with no reconcile that succeeded, for the grace or longer.
func (r *CollectorReconciler) failingPastGrace(collector string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	since, failing := r.failing[collector]
	if !failing {
		if r.failing == nil {
			r.failing = map[string]time.Time{}
		}
		r.failing[collector] = now
		return false
	}
	return !now.Before(since.Add(healthGrace))
}

// endFailures notes that a reconcile of the collector succeeded, which ends a run of errors.
func (r *CollectorReconciler) endFailures(collector string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.failing, collector)
}

// secretOwned says whether this process saw the collector's TLS Secret labelled and owned since it last issued it.
func (r *CollectorReconciler) secretOwned(collector string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.owned[collector]
}

// inGrace says whether the collector is within the grace after this process's start, or after its certificate was
// last issued.
func (r *CollectorReconciler) inGrace(collector string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	since := r.started
	if issued := r.issued[collector]; issued.After(since) {
		since = issued
	}
	return r.now().Before(since.Add(healthGrace))
}

// firstRetry is how long the deployer waits before it tries a failed reconcile again, the first time, as
// controller-runtime does: a conflict with another write passes at once.
const firstRetry = 5 * time.Millisecond

// retryLimiter returns how long the deployer waits before it tries a failed reconcile again: controller-runtime's
// back-off, which doubles from firstRetry, but never longer than resync. A failed reconcile schedules no resync, and the
// back-off alone grows to 16 minutes, so a run of errors that turns a collector failing, and the end of it, would show
// late. Without a resync, it is controller-runtime's own back-off.
func retryLimiter(resync time.Duration) workqueue.TypedRateLimiter[reconcile.Request] {
	if resync <= 0 {
		return workqueue.DefaultTypedControllerRateLimiter[reconcile.Request]()
	}
	return workqueue.NewTypedItemExponentialFailureRateLimiter[reconcile.Request](firstRetry, resync)
}

// SetupWithManager sets up the controller with the Manager, and adds the creation of the default runtime config.
func (r *CollectorReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// A RunnableFunc runs on the leader only, once the caches have synced.
	if err := mgr.Add(manager.RunnableFunc(func(ctx context.Context) error {
		return createDefaultRuntimeConfig(ctx, r.Client)
	})); err != nil {
		return fmt.Errorf("add the creation of the default runtime config: %w", err)
	}
	return ctrl.NewControllerManagedBy(mgr).
		// The deployer's own writes of the status and of its finalizer change no generation, and start no reconcile.
		// A change of health starts none either: the resync follows it.
		For(&configv1alpha1.Collector{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		// A Deployment that becomes available, and anything that someone deletes, start one.
		Owns(&appsv1.Deployment{}).
		Owns(&corev1.Service{}).
		Owns(&corev1.ServiceAccount{}).
		Watches(&configv1alpha1.CollectorRuntimeConfig{}, handler.EnqueueRequestsFromMapFunc(r.collectorsShapedBy),
			builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		WithOptions(controller.Options{RateLimiter: retryLimiter(r.Resync)}).
		Named("config-collector").
		Complete(r)
}
