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

package config_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	eventsv1 "k8s.io/api/events/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/events"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/yaml"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	configcontroller "github.com/bedag/vexplain/internal/controller/config"
	"github.com/bedag/vexplain/internal/llm"
)

const (
	// apiKeyField is the key of the data of the specs' Secrets that holds the API key.
	apiKeyField = "api-key"
	// modelUnavailable is the reason of the event that reports a model that can't be used.
	modelUnavailable = "ModelUnavailable"
	// labelSelector is how the messages name the label that a Secret must carry.
	labelSelector = "vexplain.bedag.ch/llm-api-key=true"
)

// usable are the labels of a Secret that a ModelConfig may use.
var usable = map[string]string{configv1alpha1.LLMAPIKeyLabel: "true"}

// apiKeySecret is a Secret in the operator namespace, named name, that holds value under
// apiKeyField and carries labels.
func apiKeySecret(name, value string, labels map[string]string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: operatorNamespace, Name: name, Labels: labels},
		Data:       map[string][]byte{apiKeyField: []byte(value)},
	}
}

// newModelConfig is a ModelConfig named name for model at the test endpoint, with the API key of
// the Secret secretName.
func newModelConfig(name, model, secretName string) *configv1alpha1.ModelConfig {
	return &configv1alpha1.ModelConfig{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: configv1alpha1.ModelConfigSpec{
			Endpoint:        llmServer.apiURL(),
			Model:           model,
			APIKeySecretRef: configv1alpha1.SecretKeyRef{Name: secretName, Key: apiKeyField},
		},
	}
}

// These specs run against the manager that the suite starts through setup.Register, so the
// controller, its watches and the manager's cache of Secrets are the production ones. The model
// endpoint answers by the key and the model of a request, so every spec uses a name, a Secret and
// a key of its own.
var _ = Describe("ModelConfig", func() {
	const (
		timeout  = 30 * time.Second
		interval = 100 * time.Millisecond
		// secretReaction bounds how long a ModelConfig takes to follow a change of its Secret.
		secretReaction = 10 * time.Second
		// quiet is how long a spec watches for a probe that must not happen.
		quiet = 5 * time.Second
	)

	// createSecret creates a Secret like apiKeySecret, and deletes it after the spec.
	createSecret := func(name, value string, labels map[string]string) *corev1.Secret {
		GinkgoHelper()
		secret := apiKeySecret(name, value, labels)
		Expect(k8sClient.Create(ctx, secret)).To(Succeed())
		DeferCleanup(func() {
			Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, secret))).To(Succeed())
		})
		return secret
	}

	// createModelConfig creates obj, and deletes it after the spec.
	createModelConfig := func(obj *configv1alpha1.ModelConfig) {
		GinkgoHelper()
		Expect(k8sClient.Create(ctx, obj)).To(Succeed())
		DeferCleanup(func() {
			Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, obj))).To(Succeed())
		})
	}

	// expectReady waits until the controller has set the Ready condition of the ModelConfig named
	// name, for its current generation, to status and reason, and returns the object and the
	// condition. It reads through k8sClient, a direct client, so it never sees a stale cache.
	expectReady := func(name string, status metav1.ConditionStatus, reason string,
		within time.Duration) (*configv1alpha1.ModelConfig, *metav1.Condition) {
		GinkgoHelper()
		var (
			got   *configv1alpha1.ModelConfig
			ready *metav1.Condition
		)
		Eventually(func(g Gomega) {
			// A new object for every read: a read into an old one would keep the fields that the
			// new version no longer has.
			var obj configv1alpha1.ModelConfig
			g.Expect(k8sClient.Get(ctx, client.ObjectKey{Name: name}, &obj)).To(Succeed())
			ready = meta.FindStatusCondition(obj.Status.Conditions, configv1alpha1.ConditionReady)
			g.Expect(ready).NotTo(BeNil())
			g.Expect(ready.ObservedGeneration).To(Equal(obj.Generation))
			g.Expect(ready.Status).To(Equal(status))
			g.Expect(ready.Reason).To(Equal(reason))
			got = &obj
		}, within, interval).Should(Succeed())
		return got, ready
	}

	// awaitCached waits until the manager's cache holds secret. A spec that creates its
	// ModelConfig after that knows that the event of the Secret can't start a probe of it.
	awaitCached := func(secret *corev1.Secret) {
		GinkgoHelper()
		Eventually(func() error {
			return k8sManager.GetClient().Get(ctx, client.ObjectKeyFromObject(secret), &corev1.Secret{})
		}, timeout, interval).Should(Succeed())
	}

	// unavailableEvents lists the ModelUnavailable events about the ModelConfig named name. It
	// reads through k8sClient, so that it never sees a stale cache. The events API files the events
	// of a cluster-scoped object in the namespace default.
	unavailableEvents := func(name string) func(g Gomega) []eventsv1.Event {
		return func(g Gomega) []eventsv1.Event {
			var list eventsv1.EventList
			g.Expect(k8sClient.List(ctx, &list,
				client.InNamespace(metav1.NamespaceDefault),
				client.MatchingFields{"regarding.name": name, "reason": modelUnavailable},
			)).To(Succeed())
			return list.Items
		}
	}

	Describe("validation by the API server", func() {
		DescribeTable("rejects",
			func(change func(*configv1alpha1.ModelConfig), field string) {
				obj := newModelConfig("invalid", listedModel, "invalid")
				change(obj)

				err := k8sClient.Create(ctx, obj)

				Expect(err).To(Satisfy(apierrors.IsInvalid))
				Expect(err).To(MatchError(ContainSubstring(field)))
			},
			Entry("an endpoint that is not https",
				func(obj *configv1alpha1.ModelConfig) { obj.Spec.Endpoint = "http://llm.example/v1" },
				"spec.endpoint"),
			Entry("a provider that no version knows",
				func(obj *configv1alpha1.ModelConfig) {
					obj.Spec.Provider = ptr.To(configv1alpha1.Provider("NoSuchProvider"))
				},
				"spec.provider"),
			Entry("a Secret key that a Secret can't have",
				func(obj *configv1alpha1.ModelConfig) { obj.Spec.APIKeySecretRef.Key = "api/key" },
				"spec.apiKeySecretRef.key"),
			Entry("a probe interval below 30 seconds",
				func(obj *configv1alpha1.ModelConfig) { obj.Spec.ProbeIntervalSeconds = ptr.To[int32](29) },
				"spec.probeIntervalSeconds"),
		)

		It("defaults the provider, the request settings and the probe interval", func() {
			obj := newModelConfig("defaults", listedModel, "defaults")

			Expect(k8sClient.Create(ctx, obj, client.DryRunAll)).To(Succeed())

			Expect(obj.Spec.Provider).To(HaveValue(Equal(configv1alpha1.ProviderOpenAICompatible)))
			Expect(obj.Spec.RequestTimeoutSeconds).To(HaveValue(BeEquivalentTo(60)))
			Expect(obj.Spec.MaxConcurrentRequests).To(HaveValue(BeEquivalentTo(2)))
			Expect(obj.Spec.TemperatureMilli).To(HaveValue(BeEquivalentTo(200)))
			Expect(obj.Spec.ProbeIntervalSeconds).To(HaveValue(BeEquivalentTo(300)))
		})

		It("accepts the sample and its Secret, which go together", func() {
			read := func(file string, into any) {
				GinkgoHelper()
				data, err := os.ReadFile(filepath.Join("..", "..", "..", "config", "samples", file))
				Expect(err).NotTo(HaveOccurred())
				Expect(yaml.UnmarshalStrict(data, into)).To(Succeed())
			}
			sample := &configv1alpha1.ModelConfig{}
			read("config_v1alpha1_modelconfig.yaml", sample)
			secret := &corev1.Secret{}
			read("config_v1alpha1_modelconfig_secret.yaml", secret)

			Expect(sample.Name).To(Equal("default"))
			Expect(sample.Spec.Endpoint).To(Equal("https://llm.example/v1"))
			Expect(sample.Spec.Model).To(Equal("model-a"))
			Expect(sample.Spec.APIKeySecretRef.Name).To(Equal(secret.Name))
			Expect(secret.StringData).To(HaveKey(sample.Spec.APIKeySecretRef.Key))
			Expect(secret.Namespace).To(Equal(operatorNamespace))
			Expect(secret.Labels).To(HaveKeyWithValue(configv1alpha1.LLMAPIKeyLabel, "true"))

			// A dry run: the sample's endpoint is not one to probe.
			Expect(k8sClient.Create(ctx, secret, client.DryRunAll)).To(Succeed())
			Expect(k8sClient.Create(ctx, sample, client.DryRunAll)).To(Succeed())
		})
	})

	Describe("the Ready condition", func() {
		It("is True with reason Available, with the probe's time and latency, for a listed model", func() {
			const key = "key-available"
			createSecret("available", key, usable)
			createModelConfig(newModelConfig("available", listedModel, "available"))

			got, _ := expectReady("available", metav1.ConditionTrue, configv1alpha1.ReasonAvailable, timeout)

			Expect(got.Status.LastProbeLatencyMilliseconds).To(HaveValue(BeNumerically(">=", 0)))
			Expect(got.Status.LastProbeTime).NotTo(BeNil())
			Expect(llmServer.Hits(key)).To(BeNumerically(">=", 1), "the probe carried the key of the Secret")
			Expect(unavailableEvents("available")(Default)).To(BeEmpty())
		})

		It("is False with reason SecretNotFound, and records one event, when the Secret is missing", func() {
			createModelConfig(newModelConfig("no-secret", listedModel, "no-such-secret"))

			got, ready := expectReady("no-secret", metav1.ConditionFalse, configv1alpha1.ReasonSecretNotFound, timeout)
			Expect(ready.Message).To(ContainSubstring(operatorNamespace + "/no-such-secret"))
			Expect(got.Status.LastProbeTime).To(BeNil(), "no probe could run")
			Expect(got.Status.LastProbeLatencyMilliseconds).To(BeNil())

			By("recording a Warning event in the namespace default")
			Eventually(unavailableEvents("no-secret"), timeout, interval).Should(HaveLen(1))
			event := unavailableEvents("no-secret")(Default)[0]
			Expect(event.Type).To(Equal(corev1.EventTypeWarning))
			Expect(event.Regarding).To(And(
				HaveField("Kind", "ModelConfig"),
				HaveField("Name", "no-secret"),
			))
			Expect(event.Note).To(Equal(ready.Message))

			By("recording no further event, however often the controller reconciles the ModelConfig")
			// The probe interval is 30 seconds at the least, so a spec can't wait for requeues. A
			// change of the spec reconciles the object at once, as a requeue does.
			for temperature := range int32(3) {
				var obj configv1alpha1.ModelConfig
				Expect(k8sClient.Get(ctx, client.ObjectKey{Name: "no-secret"}, &obj)).To(Succeed())
				patch := client.MergeFrom(obj.DeepCopy())
				obj.Spec.TemperatureMilli = ptr.To(temperature)
				Expect(k8sClient.Patch(ctx, &obj, patch)).To(Succeed())
				expectReady("no-secret", metav1.ConditionFalse, configv1alpha1.ReasonSecretNotFound, timeout)
			}
			Consistently(unavailableEvents("no-secret"), 2*time.Second, 250*time.Millisecond).Should(HaveLen(1))
			Expect(unavailableEvents("no-secret")(Default)[0].Series).To(BeNil(), "the event was recorded once")
		})

		It("is False with reason SecretNotFound, naming the label, for a Secret without the label", func() {
			const key = "key-unlabelled"
			secret := createSecret("unlabelled", key, nil)
			createModelConfig(newModelConfig("unlabelled", listedModel, "unlabelled"))

			_, ready := expectReady("unlabelled", metav1.ConditionFalse, configv1alpha1.ReasonSecretNotFound, timeout)
			Expect(ready.Message).To(And(
				ContainSubstring(operatorNamespace+"/unlabelled"),
				ContainSubstring(labelSelector),
			))
			Expect(llmServer.Hits(key)).To(BeZero(), "the key of an unlabelled Secret is never sent")

			By("turning True once the label is added")
			patch := client.MergeFrom(secret.DeepCopy())
			secret.Labels = usable
			Expect(k8sClient.Patch(ctx, secret, patch)).To(Succeed())
			expectReady("unlabelled", metav1.ConditionTrue, configv1alpha1.ReasonAvailable, secretReaction)
		})

		It("is False with reason Unauthorized when the endpoint rejects the key, and the key shows up nowhere", func() {
			createSecret("rejected", rejectedKey, usable)
			createModelConfig(newModelConfig("rejected", listedModel, "rejected"))

			got, ready := expectReady("rejected", metav1.ConditionFalse, configv1alpha1.ReasonUnauthorized, timeout)
			Expect(ready.Message).To(ContainSubstring("HTTP 401"))
			Eventually(unavailableEvents("rejected"), timeout, interval).Should(HaveLen(1))
			Expect(llmServer.Hits(rejectedKey)).To(BeNumerically(">=", 1), "the endpoint saw the key, and echoed it")

			By("finding the key in no condition, no status, no event and no line of the log")
			object, err := json.Marshal(got)
			Expect(err).NotTo(HaveOccurred())
			var all eventsv1.EventList
			Expect(k8sClient.List(ctx, &all)).To(Succeed())
			everyEvent, err := json.Marshal(all)
			Expect(err).NotTo(HaveOccurred())
			// The log has the controller's line about this condition, so the recorder works.
			Eventually(suiteLog.String, timeout, interval).Should(
				MatchRegexp(`Updated the Ready condition of the ModelConfig.*"name": "rejected".*"reason": "Unauthorized"`))
			// As it is, and base64 encoded as in the data of a Secret.
			for _, form := range []string{rejectedKey, base64.StdEncoding.EncodeToString([]byte(rejectedKey))} {
				Expect(string(object)).NotTo(ContainSubstring(form))
				Expect(string(everyEvent)).NotTo(ContainSubstring(form))
				Expect(suiteLog.String()).NotTo(ContainSubstring(form))
			}
		})

		It("is False with reason ModelNotFound when the endpoint doesn't list the model", func() {
			createSecret("missing-model", "key-missing-model", usable)
			createModelConfig(newModelConfig("missing-model", missingModel, "missing-model"))

			got, _ := expectReady("missing-model", metav1.ConditionFalse, configv1alpha1.ReasonModelNotFound, timeout)
			Expect(got.Status.LastProbeTime).NotTo(BeNil(), "a probe ran")
			Expect(got.Status.LastProbeLatencyMilliseconds).To(BeNil(), "a failed probe has no latency")
		})

		It("turns True within 10 seconds once the missing Secret is created", func() {
			createModelConfig(newModelConfig("late", listedModel, "late"))
			expectReady("late", metav1.ConditionFalse, configv1alpha1.ReasonSecretNotFound, timeout)

			createSecret("late", "key-late", usable)

			expectReady("late", metav1.ConditionTrue, configv1alpha1.ReasonAvailable, secretReaction)
		})

		It("trims the key, so that a value that ends in a newline works", func() {
			const key = "key-newline"
			createSecret("newline", key+"\n", usable)
			createModelConfig(newModelConfig("newline", listedModel, "newline"))

			expectReady("newline", metav1.ConditionTrue, configv1alpha1.ReasonAvailable, timeout)
			Expect(llmServer.Hits(key)).To(BeNumerically(">=", 1), "the key reached the endpoint without the newline")
		})

		It("probes once, and not again: its status writes don't start a probe", func() {
			const key = "key-quiet"
			awaitCached(createSecret("quiet", key, usable))
			createModelConfig(newModelConfig("quiet", listedModel, "quiet"))
			expectReady("quiet", metav1.ConditionTrue, configv1alpha1.ReasonAvailable, timeout)

			// The count starts before the object exists: the probe that its status write would
			// start comes within milliseconds, maybe before the spec sees Ready.
			Consistently(func() int { return llmServer.Hits(key) }, quiet, 250*time.Millisecond).Should(Equal(1),
				"one probe for the new object, and none for the status that it wrote")
		})

		It("asks to be reconciled again after the default probe interval, 300 seconds", func() {
			awaitCached(createSecret("direct", "key-direct", usable))
			obj := newModelConfig("direct", listedModel, "direct")
			createModelConfig(obj)
			Expect(obj.Spec.ProbeIntervalSeconds).To(HaveValue(BeEquivalentTo(300)), "the API server's default")
			// Once the manager has reconciled the object, it leaves it alone until the interval
			// is over, so it writes no status at the same time as the direct call below.
			expectReady("direct", metav1.ConditionTrue, configv1alpha1.ReasonAvailable, timeout)
			reconciler := &configcontroller.ModelConfigReconciler{
				Client:            k8sClient,
				Scheme:            k8sClient.Scheme(),
				OperatorNamespace: operatorNamespace,
				Recorder:          events.NewFakeRecorder(1),
				HTTPClient:        llmServer.Client(),
			}

			result, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKey{Name: "direct"}})

			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(ctrl.Result{RequeueAfter: 300 * time.Second}))
		})
	})

	Describe("the manager's cache of Secrets", func() {
		It("holds only the Secrets of the operator namespace that carry the label", func() {
			createSecret("cache-unlabelled", "key-cache-unlabelled", nil)
			elsewhere := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: metav1.NamespaceDefault, Name: "cache-elsewhere", Labels: usable},
				Data:       map[string][]byte{apiKeyField: []byte("key-cache-elsewhere")},
			}
			Expect(k8sClient.Create(ctx, elsewhere)).To(Succeed())
			DeferCleanup(func() {
				Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, elsewhere))).To(Succeed())
			})
			// Created last: once the cache holds it, it has seen the two Secrets above.
			createSecret("cache-labelled", "key-cache-labelled", usable)

			cached := func(g Gomega) []string {
				var list corev1.SecretList
				g.Expect(k8sManager.GetCache().List(ctx, &list)).To(Succeed())
				names := make([]string, 0, len(list.Items))
				for _, secret := range list.Items {
					names = append(names, secret.Namespace+"/"+secret.Name)
				}
				return names
			}
			Eventually(cached, timeout, interval).Should(ContainElement(operatorNamespace + "/cache-labelled"))
			Expect(cached(Default)).NotTo(ContainElement(operatorNamespace + "/cache-unlabelled"))
			Expect(cached(Default)).NotTo(ContainElement(metav1.NamespaceDefault + "/cache-elsewhere"))
		})
	})
})

// These specs call the reconciler directly, against a fake client, for the paths that envtest
// cannot reach on demand: a client that returns an unlabelled Secret, a provider that the CRD does
// not admit, a probe that times out or is cancelled, failed reads and writes, and what the
// controller does to the events. The model endpoint is the suite's.
var _ = Describe("ModelConfigReconciler", func() {
	const (
		name       = "model-config"
		secretName = "llm-api-key"
		// probeInterval is the probe interval of the specs' ModelConfig, and so the requeue.
		probeInterval = 45 * time.Second
	)

	var (
		groupResource = configv1alpha1.GroupVersion.WithResource("modelconfigs").GroupResource()
		request       = ctrl.Request{NamespacedName: client.ObjectKey{Name: name}}
		recorder      *events.FakeRecorder
		statusWrites  int
	)

	BeforeEach(func() {
		recorder = events.NewFakeRecorder(10)
		statusWrites = 0
	})

	// newObject is a ModelConfig for the listed model, with a probe interval of 45 seconds and a
	// generation that is not 0.
	newObject := func() *configv1alpha1.ModelConfig {
		obj := newModelConfig(name, listedModel, secretName)
		obj.Generation = 3
		obj.Spec.ProbeIntervalSeconds = ptr.To(int32(probeInterval / time.Second))
		return obj
	}

	// reconcilerFor returns a reconciler over a fake client that holds objs. Every status write
	// counts in statusWrites, and fails with updateErr when that is set. A read of a Secret fails
	// with secretErr when that is set.
	reconcilerFor := func(updateErr, secretErr error, objs ...client.Object) *configcontroller.ModelConfigReconciler {
		fakeClient := fake.NewClientBuilder().
			WithScheme(k8sClient.Scheme()).
			WithObjects(objs...).
			WithStatusSubresource(&configv1alpha1.ModelConfig{}).
			WithInterceptorFuncs(interceptor.Funcs{
				Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object,
					opts ...client.GetOption) error {
					if _, isSecret := obj.(*corev1.Secret); isSecret && secretErr != nil {
						return secretErr
					}
					return c.Get(ctx, key, obj, opts...)
				},
				SubResourceUpdate: func(ctx context.Context, c client.Client, subResource string,
					obj client.Object, opts ...client.SubResourceUpdateOption) error {
					statusWrites++
					if updateErr != nil {
						return updateErr
					}
					return c.SubResource(subResource).Update(ctx, obj, opts...)
				},
			}).Build()
		return &configcontroller.ModelConfigReconciler{
			Client:            fakeClient,
			Scheme:            fakeClient.Scheme(),
			OperatorNamespace: operatorNamespace,
			Recorder:          recorder,
			HTTPClient:        llmServer.Client(),
		}
	}

	// reconcile runs one reconcile of the request, which must not fail, and expects the next one
	// after the probe interval, whatever the outcome.
	reconcile := func(reconciler *configcontroller.ModelConfigReconciler) {
		GinkgoHelper()
		result, err := reconciler.Reconcile(ctx, request)
		Expect(err).NotTo(HaveOccurred())
		Expect(result).To(Equal(ctrl.Result{RequeueAfter: probeInterval}))
	}

	// stored returns the ModelConfig as the reconciler's client holds it, and its Ready condition.
	stored := func(reconciler *configcontroller.ModelConfigReconciler) (configv1alpha1.ModelConfig, *metav1.Condition) {
		GinkgoHelper()
		var got configv1alpha1.ModelConfig
		Expect(reconciler.Get(ctx, request.NamespacedName, &got)).To(Succeed())
		return got, meta.FindStatusCondition(got.Status.Conditions, configv1alpha1.ConditionReady)
	}

	// recordedEvents returns the events that the reconciler recorded since the last call, as
	// "<type> <reason> <note>".
	recordedEvents := func() []string {
		var got []string
		for {
			select {
			case event := <-recorder.Events:
				got = append(got, event)
			default:
				return got
			}
		}
	}

	Describe("Reconcile", func() {
		It("records an event for each transition to False, and none while it stays False or recovers", func() {
			reconciler := reconcilerFor(nil, nil, newObject())

			By("finding no Secret, again and again")
			for range 3 {
				reconcile(reconciler)
			}
			got, ready := stored(reconciler)
			Expect(ready).To(HaveField("Reason", configv1alpha1.ReasonSecretNotFound))
			Expect(ready).To(HaveField("ObservedGeneration", int64(3)))
			Expect(got.Status.LastProbeTime).To(BeNil())
			Expect(statusWrites).To(Equal(1), "the condition doesn't change, so there is nothing to write")
			Expect(recordedEvents()).To(ConsistOf("Warning " + modelUnavailable + " " + ready.Message))

			By("probing once the Secret is there, with no event for the recovery")
			Expect(reconciler.Create(ctx, apiKeySecret(secretName, "key-recovers", usable))).To(Succeed())
			reconcile(reconciler)
			got, ready = stored(reconciler)
			Expect(ready).To(HaveField("Status", metav1.ConditionTrue))
			Expect(ready).To(HaveField("Reason", configv1alpha1.ReasonAvailable))
			Expect(got.Status.LastProbeLatencyMilliseconds).NotTo(BeNil())
			Expect(got.Status.LastProbeTime).NotTo(BeNil())
			probedAt := *got.Status.LastProbeTime
			Expect(recordedEvents()).To(BeEmpty())

			By("recording an event again when the Secret goes, and clearing the latency")
			Expect(reconciler.Delete(ctx, apiKeySecret(secretName, "", nil))).To(Succeed())
			reconcile(reconciler)
			got, ready = stored(reconciler)
			Expect(ready).To(HaveField("Reason", configv1alpha1.ReasonSecretNotFound))
			Expect(got.Status.LastProbeLatencyMilliseconds).To(BeNil(), "no latency stands next to a failure")
			Expect(got.Status.LastProbeTime).To(HaveValue(Equal(probedAt)), "no probe ran since")
			Expect(recordedEvents()).To(ConsistOf(HavePrefix("Warning " + modelUnavailable + " ")))
		})

		It("is SecretNotFound for a Secret without the label, even when its client returns one", func() {
			const key = "key-fake-unlabelled"
			reconciler := reconcilerFor(nil, nil, newObject(), apiKeySecret(secretName, key, nil))

			reconcile(reconciler)

			_, ready := stored(reconciler)
			Expect(ready).To(HaveField("Reason", configv1alpha1.ReasonSecretNotFound))
			Expect(ready.Message).To(And(ContainSubstring(operatorNamespace+"/"+secretName), ContainSubstring(labelSelector)))
			Expect(llmServer.Hits(key)).To(BeZero())
		})

		It("is SecretNotFound for a label that is not \"true\"", func() {
			const key = "key-fake-false"
			reconciler := reconcilerFor(nil, nil, newObject(),
				apiKeySecret(secretName, key, map[string]string{configv1alpha1.LLMAPIKeyLabel: "false"}))

			reconcile(reconciler)

			_, ready := stored(reconciler)
			Expect(ready).To(HaveField("Reason", configv1alpha1.ReasonSecretNotFound))
			Expect(llmServer.Hits(key)).To(BeZero())
		})

		DescribeTable("is SecretNotFound, naming the key and never a value, for a Secret",
			func(data map[string][]byte) {
				secret := apiKeySecret(secretName, "", usable)
				secret.Data = data
				reconciler := reconcilerFor(nil, nil, newObject(), secret)

				reconcile(reconciler)

				_, ready := stored(reconciler)
				Expect(ready).To(HaveField("Reason", configv1alpha1.ReasonSecretNotFound))
				Expect(ready.Message).To(ContainSubstring(`"` + apiKeyField + `"`))
				Expect(ready.Message).NotTo(ContainSubstring("key-under-another-name"))
			},
			Entry("without the key", map[string][]byte{"other": []byte("key-under-another-name")}),
			Entry("with an empty value", map[string][]byte{apiKeyField: {}}),
			Entry("with a value of whitespace only", map[string][]byte{apiKeyField: []byte(" \t\n")}),
		)

		It("is False with reason UnknownValue for a provider it doesn't know, probes nothing, and records an event", func() {
			const key = "key-unknown-provider"
			obj := newObject()
			obj.Spec.Provider = ptr.To(configv1alpha1.Provider("NoSuchProvider"))
			reconciler := reconcilerFor(nil, nil, obj, apiKeySecret(secretName, key, usable))

			reconcile(reconciler)

			got, ready := stored(reconciler)
			Expect(ready).To(HaveField("Status", metav1.ConditionFalse))
			Expect(ready).To(HaveField("Reason", configv1alpha1.ReasonUnknownValue))
			Expect(ready.Message).To(ContainSubstring(`"NoSuchProvider"`))
			Expect(got.Status.LastProbeTime).To(BeNil())
			Expect(llmServer.Hits(key)).To(BeZero())
			Expect(recordedEvents()).To(ConsistOf(HavePrefix("Warning " + modelUnavailable + " ")))
		})

		It("is EndpointUnreachable when the probe runs out of time, and returns by then", func() {
			reconciler := reconcilerFor(nil, nil, newObject(), apiKeySecret(secretName, hangingKey, usable))
			reconciler.ProbeTimeout = 200 * time.Millisecond

			start := time.Now()
			reconcile(reconciler)

			Expect(time.Since(start)).To(BeNumerically("<", 5*time.Second))
			got, ready := stored(reconciler)
			Expect(ready).To(HaveField("Reason", configv1alpha1.ReasonEndpointUnreachable))
			Expect(ready.Message).To(ContainSubstring("timed out"))
			Expect(got.Status.LastProbeTime).NotTo(BeNil(), "a probe ran")
			Expect(got.Status.LastProbeLatencyMilliseconds).To(BeNil())
			Expect(recordedEvents()).To(ConsistOf(HavePrefix("Warning " + modelUnavailable + " ")))
		})

		It("writes nothing and records nothing when it is cancelled during the probe", func() {
			reconciler := reconcilerFor(nil, nil, newObject(), apiKeySecret(secretName, hangingKey, usable))
			probes := llmServer.Hits(hangingKey)
			cancelled, cancel := context.WithCancel(ctx)
			defer cancel()
			// Cancelled once the probe waits for its answer, as when the manager stops.
			go func() {
				for llmServer.Hits(hangingKey) == probes && cancelled.Err() == nil {
					time.Sleep(10 * time.Millisecond)
				}
				cancel()
			}()

			result, err := reconciler.Reconcile(cancelled, request)

			Expect(llmServer.Hits(hangingKey)).To(Equal(probes+1), "the probe was under way")
			Expect(err).NotTo(HaveOccurred(), "the endpoint did nothing wrong, and the manager is stopping")
			Expect(result).To(Equal(ctrl.Result{}))
			Expect(statusWrites).To(BeZero())
			Expect(recordedEvents()).To(BeEmpty())
		})

		It("does nothing for an object that is gone, and does not requeue", func() {
			result, err := reconcilerFor(nil, nil).Reconcile(ctx, request)

			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(ctrl.Result{}))
			Expect(statusWrites).To(BeZero())
		})

		It("returns an error that is not NotFound when it reads the Secret, so that the request is retried", func() {
			unavailable := apierrors.NewServiceUnavailable("the cache is not ready")

			_, err := reconcilerFor(nil, unavailable, newObject()).Reconcile(ctx, request)

			Expect(err).To(MatchError(unavailable))
			Expect(statusWrites).To(BeZero())
			Expect(recordedEvents()).To(BeEmpty())
		})

		It("is not an error when the object is deleted between the read and the status write", func() {
			gone := apierrors.NewNotFound(groupResource, name)

			result, err := reconcilerFor(gone, nil, newObject()).Reconcile(ctx, request)

			Expect(statusWrites).To(Equal(1), "the controller tried to write the status")
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(ctrl.Result{}))
			Expect(recordedEvents()).To(BeEmpty(), "a ModelConfig that is gone has nothing to be unavailable")
		})

		It("returns a failed status write, so that the request is retried, and records no event", func() {
			conflict := apierrors.NewConflict(groupResource, name, errors.New("the object was modified"))

			_, err := reconcilerFor(conflict, nil, newObject()).Reconcile(ctx, request)

			Expect(err).To(MatchError(conflict))
			Expect(recordedEvents()).To(BeEmpty(), "the event follows the status it announces, and the retry records it")
		})
	})

	Describe("ClientConfig", func() {
		It("returns the endpoint, the model, the trimmed key as an llm.Secret, and the request settings", func() {
			const key = "key-client-config"
			obj := newObject()
			obj.Spec.RequestTimeoutSeconds = ptr.To[int32](30)
			obj.Spec.MaxConcurrentRequests = ptr.To[int32](4)
			// Zero is a temperature, and not a default.
			obj.Spec.TemperatureMilli = ptr.To[int32](0)
			// Whether the model is ready is the caller's concern.
			obj.Status.Conditions = []metav1.Condition{{
				Type:               configv1alpha1.ConditionReady,
				Status:             metav1.ConditionFalse,
				Reason:             configv1alpha1.ReasonEndpointUnreachable,
				LastTransitionTime: metav1.Now(),
			}}
			reconciler := reconcilerFor(nil, nil, obj, apiKeySecret(secretName, "  "+key+"\n", usable))

			cfg, err := reconciler.ClientConfig(ctx, name)

			Expect(err).NotTo(HaveOccurred())
			Expect(cfg).To(Equal(llm.Config{
				BaseURL:          llmServer.apiURL(),
				Model:            listedModel,
				APIKey:           llm.NewSecret(key),
				Timeout:          30 * time.Second,
				MaxConcurrent:    4,
				TemperatureMilli: 0,
			}))
			Expect(llmServer.Hits(key)).To(BeZero(), "it doesn't probe")
		})

		It("takes the defaults of the CRD for the settings that are not set", func() {
			reconciler := reconcilerFor(nil, nil, newObject(), apiKeySecret(secretName, "key-defaults", usable))

			cfg, err := reconciler.ClientConfig(ctx, name)

			Expect(err).NotTo(HaveOccurred())
			Expect(cfg.Timeout).To(Equal(60 * time.Second))
			Expect(cfg.MaxConcurrent).To(Equal(2))
			Expect(cfg.TemperatureMilli).To(BeEquivalentTo(200))
		})

		// The entries build their objects when the spec runs: the endpoint's URL is not known before.
		DescribeTable("returns an error, and no key, for",
			func(objects func() []client.Object, message string) {
				cfg, err := reconcilerFor(nil, nil, objects()...).ClientConfig(ctx, name)

				Expect(err).To(MatchError(ContainSubstring(message)))
				Expect(cfg).To(BeZero())
			},
			Entry("a ModelConfig that doesn't exist",
				func() []client.Object {
					return []client.Object{apiKeySecret(secretName, "key-no-object", usable)}
				}, `"`+name+`"`),
			Entry("a missing Secret",
				func() []client.Object { return []client.Object{newObject()} },
				operatorNamespace+"/"+secretName),
			Entry("a Secret without the label",
				func() []client.Object {
					return []client.Object{newObject(), apiKeySecret(secretName, "key-no-label", nil)}
				}, labelSelector),
			Entry("a provider it doesn't know",
				func() []client.Object {
					obj := newObject()
					obj.Spec.Provider = ptr.To(configv1alpha1.Provider("NoSuchProvider"))
					return []client.Object{obj, apiKeySecret(secretName, "key-no-provider", usable)}
				}, `"NoSuchProvider"`),
		)
	})
})
