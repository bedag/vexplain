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

package hub_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/cli-utils/pkg/kstatus/status"
	"sigs.k8s.io/controller-runtime/pkg/client"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
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

// expectKstatus waits until the controller has acted on the generation of the object of the name, and
// kstatus gives it the status, and returns the object.
func expectKstatus[T client.Object](obj T, name string, want status.Status) T {
	GinkgoHelper()
	Eventually(func(g Gomega) {
		g.Expect(k8sClient.Get(ctx, client.ObjectKey{Name: name}, obj)).To(Succeed())
		g.Expect(acted(obj)).To(BeTrue(), "the controller has acted on the generation")
		g.Expect(kstatusOf(obj)).To(Equal(want))
	}, reaction, poll).Should(Succeed())
	return obj
}

// expectStalledAs checks that the conditions are at the generation, and that Stalled gives the reason and
// message of Ready, which is False, without Reconciling.
func expectStalledAs(generation, observed int64, conditions []metav1.Condition, reason string) {
	GinkgoHelper()
	Expect(observed).To(Equal(generation), "status.observedGeneration")
	ready := meta.FindStatusCondition(conditions, configv1alpha1.ConditionReady)
	stalled := meta.FindStatusCondition(conditions, configv1alpha1.ConditionStalled)
	Expect(ready).To(And(HaveField("Status", metav1.ConditionFalse), HaveField("Reason", reason)))
	Expect(stalled).NotTo(BeNil())
	Expect(stalled.Status).To(Equal(metav1.ConditionTrue))
	Expect(stalled.Reason).To(Equal(ready.Reason))
	Expect(stalled.Message).To(Equal(ready.Message))
	Expect(meta.FindStatusCondition(conditions, configv1alpha1.ConditionReconciling)).To(BeNil())
}

// expectSettled checks that the conditions are at the generation, Ready, and have neither Reconciling nor
// Stalled.
func expectSettled(generation, observed int64, conditions []metav1.Condition) {
	GinkgoHelper()
	Expect(observed).To(Equal(generation), "status.observedGeneration")
	Expect(meta.IsStatusConditionTrue(conditions, configv1alpha1.ConditionReady)).To(BeTrue())
	Expect(meta.FindStatusCondition(conditions, configv1alpha1.ConditionReconciling)).To(BeNil())
	Expect(meta.FindStatusCondition(conditions, configv1alpha1.ConditionStalled)).To(BeNil())
}

// The status of a Playbook and of a Rule as kstatus computes it from the status that the production
// controllers write (decision 0036).
var _ = Describe("kstatus", func() {
	It("has the default playbook and rules Current", func() {
		got := expectKstatus(&configv1alpha1.Playbook{}, playbookName, status.CurrentStatus)
		expectSettled(got.Generation, ptr.Deref(got.Status.ObservedGeneration, 0), got.Status.Conditions)
		for _, name := range []string{knownExploitedRule, guardRule, removedRule, loadCheckRule} {
			rule := expectKstatus(&configv1alpha1.Rule{}, name, status.CurrentStatus)
			expectSettled(rule.Generation, ptr.Deref(rule.Status.ObservedGeneration, 0), rule.Status.Conditions)
		}
	})

	It("has a Playbook that names a missing rule Failed, and InProgress for a new generation until the controller acts", func() {
		createRule(holdRule("kstatus-hold"))
		createPlaybook("vm-cves-kstatus", configv1alpha1.PlaybookSpec{
			Subjects: configv1alpha1.PlaybookSource{Collector: workloadsCollector, Type: vmType},
			Findings: configv1alpha1.PlaybookFindings{Collector: matcherCollector},
			Pipeline: []configv1alpha1.PlaybookStep{{Rule: "kstatus-hold"}},
		})
		got := expectKstatus(&configv1alpha1.Playbook{}, "vm-cves-kstatus", status.CurrentStatus)
		expectSettled(got.Generation, ptr.Deref(got.Status.ObservedGeneration, 0), got.Status.Conditions)

		got.Spec.Pipeline = append(got.Spec.Pipeline, configv1alpha1.PlaybookStep{Rule: "nowhere"})
		Expect(k8sClient.Update(ctx, got)).To(Succeed())
		Expect(kstatusOf(got)).To(Equal(status.InProgressStatus), "before the controller has acted")

		got = expectKstatus(&configv1alpha1.Playbook{}, "vm-cves-kstatus", status.FailedStatus)
		expectStalledAs(got.Generation, ptr.Deref(got.Status.ObservedGeneration, 0), got.Status.Conditions, configv1alpha1.ReasonRuleMissing)
	})

	It("has a Rule whose CEL doesn't compile Failed, and InProgress for a new generation until the controller acts", func() {
		createRule(holdRule("kstatus-rule"))
		got := expectKstatus(&configv1alpha1.Rule{}, "kstatus-rule", status.CurrentStatus)

		got.Spec.Condition = brokenCondition
		Expect(k8sClient.Update(ctx, got)).To(Succeed())
		Expect(kstatusOf(got)).To(Equal(status.InProgressStatus), "before the controller has acted")

		got = expectKstatus(&configv1alpha1.Rule{}, "kstatus-rule", status.FailedStatus)
		expectStalledAs(got.Generation, ptr.Deref(got.Status.ObservedGeneration, 0), got.Status.Conditions, configv1alpha1.ReasonInvalid)
	})
})
