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
	"net/http"
	"strings"
	"time"

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
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/llm"
)

const (
	// eventReasonModelUnavailable is the reason of the Warning event that a ModelConfig gets when
	// it turns to Ready=False.
	eventReasonModelUnavailable = "ModelUnavailable"
	// defaultProbeTimeout bounds a whole probe, its fallback request included, whatever
	// requestTimeoutSeconds says, so that a reconcile worker is never blocked for long.
	defaultProbeTimeout = 10 * time.Second
)

// The defaults of the CRD, for a spec that the API server has not defaulted, such as that of an
// object built in code.
const (
	defaultRequestTimeoutSeconds int32 = 60
	defaultMaxConcurrentRequests int32 = 2
	defaultTemperatureMilli      int32 = 200
	defaultProbeIntervalSeconds  int32 = 300
)

// ModelConfigReconciler reconciles a ModelConfig object: it probes the endpoint, and reports in
// the Ready condition whether the model can be used. Later phases build their client from
// ClientConfig.
type ModelConfigReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	// OperatorNamespace is the namespace of the operator, the only one in which a ModelConfig's
	// Secret can be.
	OperatorNamespace string
	// Recorder records the ModelUnavailable event.
	Recorder events.EventRecorder
	// HTTPClient is the HTTP client of the probes. Nil means the default client of the llm
	// package, which honours HTTPS_PROXY and NO_PROXY.
	HTTPClient *http.Client
	// ProbeTimeout bounds each probe as a whole. Zero means 10 seconds.
	ProbeTimeout time.Duration
}

// The controller reads a ModelConfig and writes only its status, with an update, so it holds no
// write access to the object itself and no finalizers right.
// +kubebuilder:rbac:groups=config.vexplain.bedag.ch,resources=modelconfigs,verbs=get;list;watch
// +kubebuilder:rbac:groups=config.vexplain.bedag.ch,resources=modelconfigs/status,verbs=update

// The events API files the ModelUnavailable event. The recorder creates the event, and patches it
// when the same event repeats.
// +kubebuilder:rbac:groups=events.k8s.io,resources=events,verbs=create;patch

// Reconcile probes the endpoint of a ModelConfig and records the result in its Ready condition,
// its lastProbeTime and its lastProbeLatencyMilliseconds. Whatever the result, it asks to be
// called again after the probe interval, with no error, so that an endpoint that is down is not
// retried with the back-off of errors. A change of the spec or of the Secret brings a probe
// sooner.
//
// On a transition to Ready=False it records a ModelUnavailable event. It does that once the
// status is written, so that a write that fails is retried together with its event, and no event
// is recorded for a status that never was.
//
// It returns the errors of reading the ModelConfig, of reading the Secret other than NotFound, and
// of writing the status, so that the request is retried. A reconcile that is cancelled, as when
// the manager stops, writes nothing, because that says nothing about the model. A deleted
// ModelConfig needs no work, and is not requeued.
func (r *ModelConfigReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var obj configv1alpha1.ModelConfig
	if err := r.Get(ctx, req.NamespacedName, &obj); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	found, err := r.check(ctx, &obj)
	switch {
	case errors.Is(err, context.Canceled):
		return ctrl.Result{}, nil
	case err != nil:
		return ctrl.Result{}, err
	}
	requeue := ctrl.Result{RequeueAfter: probeInterval(&obj.Spec)}

	wasFailing := meta.IsStatusConditionFalse(obj.Status.Conditions, configv1alpha1.ConditionReady)
	// Write only a change. Every probe moves lastProbeTime, but a requeue that finds the Secret
	// still missing changes nothing.
	conditionChanged := meta.SetStatusCondition(&obj.Status.Conditions, found.ready)
	latencyChanged := !ptr.Equal(obj.Status.LastProbeLatencyMilliseconds, found.latencyMilliseconds)
	if !conditionChanged && !latencyChanged && found.probeTime == nil {
		return requeue, nil
	}
	if found.probeTime != nil {
		obj.Status.LastProbeTime = found.probeTime
	}
	obj.Status.LastProbeLatencyMilliseconds = found.latencyMilliseconds
	if err := r.Status().Update(ctx, &obj); err != nil {
		// NotFound means the object was deleted since it was read. Any other error, a conflict
		// included, is returned, and controller-runtime retries with a back-off.
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	// A new probe time alone is not worth a line: it changes at every probe.
	if conditionChanged {
		logf.FromContext(ctx).Info("Updated the Ready condition of the ModelConfig",
			"status", found.ready.Status, "reason", found.ready.Reason, "message", found.ready.Message)
	}

	if found.ready.Status == metav1.ConditionFalse && !wasFailing {
		r.Recorder.Eventf(&obj, nil, corev1.EventTypeWarning,
			eventReasonModelUnavailable, eventActionReconcile, "%s", found.ready.Message)
	}
	return requeue, nil
}

// probeResult is what the check of a ModelConfig found.
type probeResult struct {
	// ready is the Ready condition that the ModelConfig deserves.
	ready metav1.Condition
	// probeTime is when the probe ran. It is nil when no probe could run.
	probeTime *metav1.Time
	// latencyMilliseconds is how long the probe took, when it succeeded, and nil otherwise.
	latencyMilliseconds *int64
}

// failure returns p with Ready=False for reason, and the text of err as the message.
func (p probeResult) failure(reason string, err error) probeResult {
	p.ready.Status = metav1.ConditionFalse
	p.ready.Reason = reason
	p.ready.Message = truncate(err.Error())
	return p
}

// check probes the endpoint of obj with the key of its Secret, and returns what it found. No probe
// runs for a provider that this version doesn't know, nor for a Secret that can't be used.
//
// It returns an error, and nothing found, when it can't read the Secret for a reason other than
// NotFound, and when ctx is cancelled. Neither says anything about the model.
func (r *ModelConfigReconciler) check(ctx context.Context, obj *configv1alpha1.ModelConfig) (probeResult, error) {
	result := probeResult{ready: metav1.Condition{
		Type:               configv1alpha1.ConditionReady,
		ObservedGeneration: obj.Generation,
	}}

	cfg, err := r.clientConfig(ctx, obj)
	var (
		unknown  *unknownProviderError
		unusable *unusableSecretError
	)
	switch {
	case errors.As(err, &unknown):
		return result.failure(configv1alpha1.ReasonUnknownValue, err), nil
	case errors.As(err, &unusable):
		return result.failure(configv1alpha1.ReasonSecretNotFound, err), nil
	case err != nil:
		return probeResult{}, err
	}

	// The probe has a bound of its own, whatever requestTimeoutSeconds says: for each request, and
	// for the whole probe, the fallback request included.
	timeout := r.ProbeTimeout
	if timeout <= 0 {
		timeout = defaultProbeTimeout
	}
	cfg.Timeout = timeout
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	latency, err := llm.Probe(probeCtx, cfg, r.HTTPClient)
	if errors.Is(err, context.Canceled) {
		// The probe's own deadline is not this: it wraps llm.ErrUnreachable, and is the endpoint's.
		return probeResult{}, err
	}
	result.probeTime = ptr.To(metav1.Now())
	switch {
	case err == nil:
		result.ready.Status = metav1.ConditionTrue
		result.ready.Reason = configv1alpha1.ReasonAvailable
		result.ready.Message = "The last probe of the endpoint succeeded."
		result.latencyMilliseconds = ptr.To(latency.Milliseconds())
		return result, nil
	case errors.Is(err, llm.ErrUnauthorized):
		return result.failure(configv1alpha1.ReasonUnauthorized, err), nil
	case errors.Is(err, llm.ErrModelNotFound):
		return result.failure(configv1alpha1.ReasonModelNotFound, err), nil
	default:
		// llm.ErrUnreachable, and any other failure of a probe: no usable answer came.
		return result.failure(configv1alpha1.ReasonEndpointUnreachable, err), nil
	}
}

// ClientConfig returns the configuration of a client for the ModelConfig named name: its endpoint
// and model, the API key from its Secret, and its request settings.
//
// It reads the Secret with the same checks as a probe: the Secret must be in the operator's
// namespace, carry the label vexplain.bedag.ch/llm-api-key=true, and hold a value under the key
// once whitespace is trimmed. It returns an error for a Secret that fails them, and for a provider
// that this version of the operator doesn't know.
//
// It doesn't probe the endpoint, and doesn't look at the Ready condition: whether to use a model
// that isn't ready is the caller's call.
func (r *ModelConfigReconciler) ClientConfig(ctx context.Context, name string) (llm.Config, error) {
	var obj configv1alpha1.ModelConfig
	if err := r.Get(ctx, client.ObjectKey{Name: name}, &obj); err != nil {
		return llm.Config{}, fmt.Errorf("read the ModelConfig %q: %w", name, err)
	}
	return r.clientConfig(ctx, &obj)
}

// clientConfig is ClientConfig for an object that has been read.
func (r *ModelConfigReconciler) clientConfig(ctx context.Context, obj *configv1alpha1.ModelConfig) (llm.Config, error) {
	spec := &obj.Spec
	// The CRD enum stops an unknown provider at admission. One gets here when a newer CRD admitted
	// a provider that this older operator doesn't speak.
	if provider := ptr.Deref(spec.Provider, configv1alpha1.ProviderOpenAICompatible); provider !=
		configv1alpha1.ProviderOpenAICompatible {
		return llm.Config{}, &unknownProviderError{provider: provider}
	}
	key, err := r.apiKey(ctx, spec.APIKeySecretRef)
	if err != nil {
		return llm.Config{}, err
	}
	return llm.Config{
		BaseURL:          spec.Endpoint,
		Model:            spec.Model,
		APIKey:           key,
		Timeout:          seconds(ptr.Deref(spec.RequestTimeoutSeconds, defaultRequestTimeoutSeconds)),
		MaxConcurrent:    int(ptr.Deref(spec.MaxConcurrentRequests, defaultMaxConcurrentRequests)),
		TemperatureMilli: ptr.Deref(spec.TemperatureMilli, defaultTemperatureMilli),
	}, nil
}

// The API keys are read from the manager's cache, which holds only the Secrets of the operator's
// namespace that carry the label (setup.CacheOptions), so the rule is a Role in that namespace.
// Markers generate no bindings: config/rbac/manager_secrets_rolebinding.yaml binds it.
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch,namespace=vexplain-system

// apiKey reads the API key that ref names from its Secret in the operator's namespace. The key is
// an llm.Secret from the moment it is read, so that it never enters a log line, a condition, an
// event or an error.
//
// A Secret that doesn't exist, or doesn't carry the label with the value "true", gives an
// *unusableSecretError, and so does one that holds no value under the key once whitespace is
// trimmed. The manager's cache holds no unlabelled Secret, so a missing Secret and an unlabelled
// one look the same, and the error names both causes: a read past the cache to tell them apart
// would load Secrets that no ModelConfig may use. The label is checked here too, so that the rule
// holds even if the cache options change.
func (r *ModelConfigReconciler) apiKey(ctx context.Context, ref configv1alpha1.SecretKeyRef) (llm.Secret, error) {
	key := client.ObjectKey{Namespace: r.OperatorNamespace, Name: ref.Name}
	var secret corev1.Secret
	if err := r.Get(ctx, key, &secret); err != nil {
		if apierrors.IsNotFound(err) {
			return llm.Secret{}, notFoundOrUnlabelled(key)
		}
		return llm.Secret{}, fmt.Errorf("read the Secret %s: %w", key, err)
	}
	if secret.Labels[configv1alpha1.LLMAPIKeyLabel] != "true" {
		return llm.Secret{}, notFoundOrUnlabelled(key)
	}
	// A key with a newline at its end, as `echo key | base64` makes it, would be refused as a
	// header, and the probe would blame the endpoint.
	value := strings.TrimSpace(string(secret.Data[ref.Key]))
	if value == "" {
		return llm.Secret{}, &unusableSecretError{
			reason: fmt.Sprintf("the Secret %s holds no value under the key %q", key, ref.Key),
		}
	}
	return llm.NewSecret(value), nil
}

// notFoundOrUnlabelled is the error for a Secret that the operator can't read: one that doesn't
// exist, or doesn't carry the label.
func notFoundOrUnlabelled(key client.ObjectKey) error {
	return &unusableSecretError{reason: fmt.Sprintf(
		"the Secret %s does not exist, or does not carry the label %s=true that the operator requires",
		key, configv1alpha1.LLMAPIKeyLabel)}
}

// unusableSecretError says why a ModelConfig can't use the Secret that it names. It names the
// Secret, and the key or the label, and never a value.
type unusableSecretError struct{ reason string }

func (e *unusableSecretError) Error() string { return e.reason }

// unknownProviderError is the error for a provider that this version of the operator doesn't
// know.
type unknownProviderError struct{ provider configv1alpha1.Provider }

func (e *unknownProviderError) Error() string {
	return fmt.Sprintf("spec.provider: %q is not a provider that this version of the operator knows", e.provider)
}

// probeInterval is how long the controller waits before it probes the endpoint of spec again.
func probeInterval(spec *configv1alpha1.ModelConfigSpec) time.Duration {
	return seconds(ptr.Deref(spec.ProbeIntervalSeconds, defaultProbeIntervalSeconds))
}

// seconds returns n seconds.
func seconds(n int32) time.Duration { return time.Duration(n) * time.Second }

// modelConfigsFor maps a Secret to the requests of the ModelConfigs that name it. The manager's
// cache holds only the Secrets of the operator's namespace, and a request does no more than start
// a probe, which reads the Secret from that namespace alone.
func (r *ModelConfigReconciler) modelConfigsFor(ctx context.Context, secret client.Object) []reconcile.Request {
	// There are a few ModelConfigs at most, so a list costs less than an index to keep.
	var list configv1alpha1.ModelConfigList
	if err := r.List(ctx, &list); err != nil {
		logf.FromContext(ctx).Error(err, "Could not list the ModelConfigs that may use a Secret",
			"secret", client.ObjectKeyFromObject(secret).String())
		return nil
	}
	var requests []reconcile.Request
	for i := range list.Items {
		if list.Items[i].Spec.APIKeySecretRef.Name == secret.GetName() {
			requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKey{Name: list.Items[i].Name}})
		}
	}
	return requests
}

// SetupWithManager sets up the controller with the Manager.
func (r *ModelConfigReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		// Only a new object or a changed spec needs a reconcile from an event. The controller's own
		// status writes must not start another probe: the requeue brings the next one.
		For(&configv1alpha1.ModelConfig{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		// A Secret that appears, changes or goes away is probed at once, and not at the next
		// interval. The cache holds only labelled Secrets, so a Secret that loses its label goes
		// away, and one that gets it appears.
		Watches(&corev1.Secret{}, handler.EnqueueRequestsFromMapFunc(r.modelConfigsFor)).
		Named("config-modelconfig").
		Complete(r)
}
