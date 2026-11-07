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
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/cli-utils/pkg/kstatus/status"
	"sigs.k8s.io/controller-runtime/pkg/client"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	collectorv1alpha1 "github.com/bedag/vexplain/sdk/api/collector/v1alpha1"
)

// kstatusOf computes the status that kstatus gives obj, as Flux, kpt and Config Sync compute it.
func kstatusOf(obj client.Object) status.Status {
	GinkgoHelper()
	result, err := status.Compute(unstructuredOf(obj))
	Expect(err).NotTo(HaveOccurred())
	return result.Status
}

// unstructuredOf returns obj as kstatus reads it.
func unstructuredOf(obj client.Object) *unstructured.Unstructured {
	GinkgoHelper()
	content, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
	Expect(err).NotTo(HaveOccurred())
	return &unstructured.Unstructured{Object: content}
}

// acted reports whether the controller has written the status of obj for its generation. An object whose
// status is still empty is Current to kstatus, which can't tell it from one that no controller reconciles.
func acted(obj client.Object) bool {
	GinkgoHelper()
	observed, found, err := unstructured.NestedInt64(unstructuredOf(obj).Object, "status", "observedGeneration")
	Expect(err).NotTo(HaveOccurred())
	return found && observed == obj.GetGeneration()
}

// expectKstatus waits until the controller has acted on the generation of the object of the key, and
// kstatus gives it the status, and returns the object.
func expectKstatus[T client.Object](obj T, key client.ObjectKey, want status.Status) T {
	GinkgoHelper()
	Eventually(func(g Gomega) {
		g.Expect(k8sClient.Get(ctx, key, obj)).To(Succeed())
		g.Expect(acted(obj)).To(BeTrue(), "the controller has acted on the generation")
		g.Expect(kstatusOf(obj)).To(Equal(want))
	}, deployTimeout, deployPoll).Should(Succeed())
	return obj
}

// expectConsistentConditions checks that the conditions of a status follow decision 0036: the status is at
// the object's generation, Ready=True has neither Reconciling nor Stalled, and either of them gives the
// reason and message of Ready.
func expectConsistentConditions(generation, observed int64, conditions []metav1.Condition) {
	GinkgoHelper()
	Expect(observed).To(Equal(generation), "status.observedGeneration")
	ready := meta.FindStatusCondition(conditions, configv1alpha1.ConditionReady)
	Expect(ready).NotTo(BeNil())
	reconciling := meta.FindStatusCondition(conditions, configv1alpha1.ConditionReconciling)
	stalled := meta.FindStatusCondition(conditions, configv1alpha1.ConditionStalled)
	Expect(reconciling == nil || stalled == nil).To(BeTrue(), "never both Reconciling and Stalled")
	for _, c := range []*metav1.Condition{reconciling, stalled} {
		if c == nil {
			continue
		}
		Expect(ready.Status).NotTo(Equal(metav1.ConditionTrue), "%s comes with a Ready that isn't True", c.Type)
		Expect(c.Status).To(Equal(metav1.ConditionTrue), "%s is present only while True", c.Type)
		Expect(c.Reason).To(Equal(ready.Reason), c.Type)
		Expect(c.Message).To(Equal(ready.Message), c.Type)
	}
	if stalled != nil {
		Expect(ready.Status).To(Equal(metav1.ConditionFalse), "Stalled comes with Ready=False")
	}
}

// The status of each kind of the package as kstatus computes it from the status that the production controllers
// write (decision 0036): Current once Ready, InProgress before the controller has acted on a new generation and
// while it waits on something that passes, and Failed while it can't go on without a change.
var _ = Describe("kstatus", func() {
	Describe("a Collector", func() {
		It("is InProgress while its Deployment rolls out and in the grace for health, Current once Healthy, and InProgress again for a new generation", func() {
			f := newFakeCollector()
			f.serve(false)
			name := newCollector(helloSpec(`{"greeting": "hello"}`))
			key := client.ObjectKey{Name: name}
			serveFake(name, f)

			got, _ := expectReady(name, metav1.ConditionUnknown, configv1alpha1.ReasonProgressing)
			Expect(kstatusOf(got)).To(Equal(status.InProgressStatus), "during the rollout")
			expectConsistentConditions(got.Generation, ptr.Deref(got.Status.ObservedGeneration, 0), got.Status.Conditions)
			Expect(meta.IsStatusConditionTrue(got.Status.Conditions, configv1alpha1.ConditionReconciling)).To(BeTrue())

			makeAvailable(name, runningDigest)
			got, _ = expectReady(name, metav1.ConditionUnknown, configv1alpha1.ReasonNoData)
			Expect(kstatusOf(got)).To(Equal(status.InProgressStatus), "in the grace for health")
			expectConsistentConditions(got.Generation, ptr.Deref(got.Status.ObservedGeneration, 0), got.Status.Conditions)
			Expect(meta.IsStatusConditionTrue(got.Status.Conditions, configv1alpha1.ConditionReconciling)).To(BeTrue())

			f.serve(true)
			got = expectKstatus(&configv1alpha1.Collector{}, key, status.CurrentStatus)
			expectConsistentConditions(got.Generation, ptr.Deref(got.Status.ObservedGeneration, 0), got.Status.Conditions)
			Expect(meta.IsStatusConditionTrue(got.Status.Conditions, configv1alpha1.ConditionReady)).To(BeTrue())

			By("changing the spec, which the deployer hasn't acted on when the API server answers")
			got.Spec.Settings = &runtime.RawExtension{Raw: []byte(`{"greeting": "hi"}`)}
			Expect(k8sClient.Update(ctx, got)).To(Succeed())
			Expect(kstatusOf(got)).To(Equal(status.InProgressStatus))
			expectKstatus(&configv1alpha1.Collector{}, key, status.CurrentStatus)
		})

		It("is Failed with an invalid package, and Stalled with the reason and message of Ready", func() {
			f := newFakeCollector()
			f.answer(func(_ *collectorv1alpha1.GetInfoResponse, caps *collectorv1alpha1.GetCapabilitiesResponse) {
				caps.Produces[0].Type = "Hello Type"
			})
			name := newCollector(helloSpec(""))
			serveFake(name, f)
			makeAvailable(name, runningDigest)

			got, ready := expectReady(name, metav1.ConditionFalse, configv1alpha1.ReasonPackageInvalid)

			Expect(kstatusOf(got)).To(Equal(status.FailedStatus))
			expectConsistentConditions(got.Generation, ptr.Deref(got.Status.ObservedGeneration, 0), got.Status.Conditions)
			stalled := meta.FindStatusCondition(got.Status.Conditions, configv1alpha1.ConditionStalled)
			Expect(stalled).NotTo(BeNil())
			Expect(stalled.Reason).To(Equal(ready.Reason))
		})
	})

	Describe("an OperatorConfig", func() {
		const singletonName = "default"
		key := client.ObjectKey{Name: singletonName}

		BeforeEach(func() {
			DeferCleanup(func() {
				Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, &configv1alpha1.OperatorConfig{
					ObjectMeta: metav1.ObjectMeta{Name: singletonName},
				}))).To(Succeed())
				Eventually(func() error {
					return k8sClient.Get(ctx, key, &configv1alpha1.OperatorConfig{})
				}, deployTimeout, deployPoll).Should(Satisfy(apierrors.IsNotFound))
			})
		})

		It("is Current once Ready, InProgress for a new generation, and Failed with an invalid scope", func() {
			Expect(k8sClient.Create(ctx, &configv1alpha1.OperatorConfig{
				ObjectMeta: metav1.ObjectMeta{Name: singletonName},
			})).To(Succeed())
			got := expectKstatus(&configv1alpha1.OperatorConfig{}, key, status.CurrentStatus)
			expectConsistentConditions(got.Generation, ptr.Deref(got.Status.ObservedGeneration, 0), got.Status.Conditions)

			got.Spec.Scope = &configv1alpha1.Scope{IncludeNamespaces: badSelector()}
			Expect(k8sClient.Update(ctx, got)).To(Succeed())
			Expect(kstatusOf(got)).To(Equal(status.InProgressStatus), "before the controller has acted")

			got = expectKstatus(&configv1alpha1.OperatorConfig{}, key, status.FailedStatus)
			expectConsistentConditions(got.Generation, ptr.Deref(got.Status.ObservedGeneration, 0), got.Status.Conditions)
			Expect(meta.FindStatusCondition(got.Status.Conditions, configv1alpha1.ConditionStalled)).To(
				HaveField("Reason", configv1alpha1.ReasonInvalid))
		})
	})

	Describe("a ModelConfig", func() {
		It("is Current once Available, InProgress for a new generation, and Failed without its Secret", func() {
			name := apiName("model")
			key := client.ObjectKey{Name: name}
			secret := apiKeySecret(name, "key-of-"+name, usable)
			createObject(secret)
			createObject(newModelConfig(name, listedModel, name))
			got := expectKstatus(&configv1alpha1.ModelConfig{}, key, status.CurrentStatus)
			expectConsistentConditions(got.Generation, ptr.Deref(got.Status.ObservedGeneration, 0), got.Status.Conditions)

			got.Spec.APIKeySecretRef.Name = name + "-missing"
			Expect(k8sClient.Update(ctx, got)).To(Succeed())
			Expect(kstatusOf(got)).To(Equal(status.InProgressStatus), "before the controller has acted")

			got = expectKstatus(&configv1alpha1.ModelConfig{}, key, status.FailedStatus)
			expectConsistentConditions(got.Generation, ptr.Deref(got.Status.ObservedGeneration, 0), got.Status.Conditions)
			Expect(meta.FindStatusCondition(got.Status.Conditions, configv1alpha1.ConditionStalled)).To(
				HaveField("Reason", configv1alpha1.ReasonSecretNotFound))
		})

		It("is InProgress, and Reconciling, while its endpoint can't be reached, since it probes again", func() {
			name := apiName("model")
			key := client.ObjectKey{Name: name}
			createObject(apiKeySecret(name, "key-of-"+name, usable))
			obj := newModelConfig(name, listedModel, name)
			// Nothing listens on port 1 of the loopback address, so the probe fails at once.
			obj.Spec.Endpoint = "https://127.0.0.1:1/v1"
			createObject(obj)

			got := expectKstatus(&configv1alpha1.ModelConfig{}, key, status.InProgressStatus)
			Eventually(func(g Gomega) {
				g.Expect(k8sClient.Get(ctx, key, got)).To(Succeed())
				g.Expect(meta.FindStatusCondition(got.Status.Conditions, configv1alpha1.ConditionReconciling)).To(
					HaveField("Reason", configv1alpha1.ReasonEndpointUnreachable))
			}, deployTimeout, deployPoll).Should(Succeed())
			expectConsistentConditions(got.Generation, ptr.Deref(got.Status.ObservedGeneration, 0), got.Status.Conditions)
		})
	})
})
