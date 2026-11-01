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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/scan/result"
)

// vmType is the type of the evidence of a playbook for virtual machines, whose subjects no Collector
// of the suite delivers. Such a playbook takes no subjects of the default one, and never conflicts
// with it.
const vmType = "com.example.vm.v1alpha1"

// createPlaybook creates a playbook with the spec, and deletes it after the spec.
func createPlaybook(name string, spec configv1alpha1.PlaybookSpec) {
	GinkgoHelper()
	playbook := &configv1alpha1.Playbook{ObjectMeta: metav1.ObjectMeta{Name: name}, Spec: spec}
	Expect(k8sClient.Create(ctx, playbook)).To(Succeed())
	DeferCleanup(func() { Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, playbook))).To(Succeed()) })
}

// createRule creates a rule, and deletes it after the spec.
func createRule(rule *configv1alpha1.Rule) {
	GinkgoHelper()
	Expect(k8sClient.Create(ctx, rule)).To(Succeed())
	DeferCleanup(func() { Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, rule))).To(Succeed()) })
}

// holdRule returns a rule that holds every finding open, and needs the inputs.
func holdRule(name string, inputs ...configv1alpha1.RuleInput) *configv1alpha1.Rule {
	return &configv1alpha1.Rule{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: configv1alpha1.RuleSpec{
			Inputs:    inputs,
			Condition: "true",
			Outcome:   &configv1alpha1.RuleOutcome{Status: ptr.To(configv1alpha1.VEXStatusUnderInvestigation)},
		},
	}
}

// expectReady waits until the Ready condition of the playbook has the status and the reason, and
// returns it.
func expectReady(playbook string, status metav1.ConditionStatus, reason string) *metav1.Condition {
	GinkgoHelper()
	var ready *metav1.Condition
	Eventually(func(g Gomega) {
		ready = readyOf(&configv1alpha1.Playbook{}, playbook)(g)
		g.Expect(ready).NotTo(BeNil())
		g.Expect(ready.Status).To(Equal(status))
		g.Expect(ready.Reason).To(Equal(reason))
	}, reaction, poll).Should(Succeed())
	return ready
}

var _ = Describe("The playbook controller", func() {
	It("settles none of a playbook's findings once a Collector that it names is deleted, whose evidence goes with the sheet, and settles them again once it is back and has delivered again", func() {
		findings.set(v1, exampleMatch, otherMatch, goneMatch)
		digest, manifest := newDigest(), newDigest()
		runWorkload(newNamespace(), "app-0", digest)
		job := expectScanJob(digest)
		runScanPod(job, resultLog(digest, evidenceOf(manifest)))
		Eventually(manifestsOf(digest), reaction, poll).Should(Equal([]string{manifest}))
		settled := sheet(v1, contentsOf(manifest), counted{underInvestigation: 2, notAffected: 1}, otherReached, exampleUnreached, goneSettled)
		Eventually(statusOf(manifest), reaction, poll).Should(Equal(settled))

		By("deleting the scanner's Collector")
		Expect(k8sClient.Delete(ctx, collectorNamed(scanner))).To(Succeed())
		DeferCleanup(func() {
			Expect(client.IgnoreAlreadyExists(k8sClient.Create(ctx, collectorNamed(scanner)))).To(Succeed())
			expectReady(playbookName, metav1.ConditionTrue, configv1alpha1.ReasonValid)
		})

		ready := expectReady(playbookName, metav1.ConditionFalse, configv1alpha1.ReasonCollectorMissing)
		Expect(ready.Message).To(ContainSubstring(scanner))

		// The deployer's finalizer deletes the evidence that a deleted Collector delivered (design 5.9), and a sheet
		// whose evidence is gone goes with it: no verdict rests on evidence that is gone, so no finding stays settled.
		By("deleting the evidence of the deleted Collector, and the sheet that rested on it")
		Eventually(recordOf(manifest), reaction, poll).Should(BeNil())
		Eventually(statusOf(manifest), reaction, poll).Should(BeNil())

		By("settling the findings again once the Collector is back, and the spoke has scanned the image again")
		Expect(k8sClient.Create(ctx, collectorNamed(scanner))).To(Succeed())
		expectReady(playbookName, metav1.ConditionTrue, configv1alpha1.ReasonValid)
		runScanPod(expectScanJob(digest, job.Name), resultLog(digest, evidenceOf(manifest)))
		Eventually(recordOf(manifest), reaction, poll).ShouldNot(BeNil())
		Eventually(statusOf(manifest), reaction, poll).Should(Equal(
			sheet(v1, contentsOf(manifest), counted{underInvestigation: 2, notAffected: 1}, otherReached, exampleUnreached, goneSettled)))
	})

	It("says when a rule of the pipeline needs an input that the playbook doesn't supply", func() {
		createRule(holdRule("needs-sbom", configv1alpha1.RuleInput{Name: "sbom", Type: result.EvidenceType}))
		createRule(holdRule("needs-other-contents", configv1alpha1.RuleInput{Name: contents, Type: "com.example.contents.v1"}))
		createPlaybook("vm-cves-inputs", configv1alpha1.PlaybookSpec{
			Subjects: configv1alpha1.PlaybookSource{Collector: workloadsCollector, Type: vmType},
			Findings: configv1alpha1.PlaybookFindings{Collector: matcherCollector},
			Evidence: []configv1alpha1.PlaybookEvidence{{Name: contents, Collector: scanner, Type: result.EvidenceType}},
			Pipeline: []configv1alpha1.PlaybookStep{{Rule: guardRule}, {Rule: "needs-sbom"}, {Rule: "needs-other-contents"}},
		})

		ready := expectReady("vm-cves-inputs", metav1.ConditionFalse, configv1alpha1.ReasonInputMissing)

		Expect(ready.Message).To(ContainSubstring(`"needs-sbom"`))
		Expect(ready.Message).To(ContainSubstring(`"sbom"`))
		Expect(ready.Message).To(ContainSubstring(`"needs-other-contents"`), "an input of another type is missing too")
		Expect(ready.Message).NotTo(ContainSubstring(guardRule))
	})

	It("says when a rule of the pipeline is missing, or isn't Ready", func() {
		broken := holdRule("does-not-compile")
		broken.Spec.Condition = "finding."
		createRule(broken)
		createPlaybook("vm-cves-rules", configv1alpha1.PlaybookSpec{
			Subjects: configv1alpha1.PlaybookSource{Collector: workloadsCollector, Type: vmType},
			Findings: configv1alpha1.PlaybookFindings{Collector: matcherCollector},
			Pipeline: []configv1alpha1.PlaybookStep{{Rule: "does-not-compile"}},
		})
		ready := expectReady("vm-cves-rules", metav1.ConditionFalse, configv1alpha1.ReasonRuleNotReady)
		Expect(ready.Message).To(ContainSubstring(`"does-not-compile"`))

		update(&configv1alpha1.Playbook{}, "vm-cves-rules", func(playbook *configv1alpha1.Playbook) {
			playbook.Spec.Pipeline = append(playbook.Spec.Pipeline, configv1alpha1.PlaybookStep{Rule: "nowhere"})
		})
		ready = expectReady("vm-cves-rules", metav1.ConditionFalse, configv1alpha1.ReasonRuleMissing)
		Expect(ready.Message).To(ContainSubstring(`"nowhere"`))
	})

	It("says when a Collector doesn't produce a type that the playbook asks of it, as its capabilities show", func() {
		By("recording capabilities of the scanner that leave out its evidence")
		var collector configv1alpha1.Collector
		Expect(k8sClient.Get(ctx, client.ObjectKey{Name: scanner}, &collector)).To(Succeed())
		collector.Status.Capabilities = &configv1alpha1.CollectorCapabilities{
			Roles:    []configv1alpha1.CollectorRole{configv1alpha1.CollectorRoleSpoke},
			Produces: []configv1alpha1.ProducedType{{Type: "com.example.sbom.v1", Scope: configv1alpha1.EvidenceScopeHub}},
			Watch:    configv1alpha1.CollectorWatchNotSupported,
		}
		Expect(k8sClient.Status().Update(ctx, &collector)).To(Succeed())
		DeferCleanup(func() {
			Eventually(func(g Gomega) {
				var c configv1alpha1.Collector
				g.Expect(k8sClient.Get(ctx, client.ObjectKey{Name: scanner}, &c)).To(Succeed())
				c.Status.Capabilities = nil
				g.Expect(k8sClient.Status().Update(ctx, &c)).To(Succeed())
			}, reaction, poll).Should(Succeed())
			expectReady(playbookName, metav1.ConditionTrue, configv1alpha1.ReasonValid)
		})

		ready := expectReady(playbookName, metav1.ConditionFalse, configv1alpha1.ReasonTypeNotProduced)

		Expect(ready.Message).To(ContainSubstring(scanner))
		Expect(ready.Message).To(ContainSubstring(result.EvidenceType))
	})

	It("lets the older of two playbooks that take the same subjects run, and says that the newer is in conflict", func() {
		var original configv1alpha1.Playbook
		Expect(k8sClient.Get(ctx, client.ObjectKey{Name: playbookName}, &original)).To(Succeed())
		createPlaybook("container-cves-copy", *original.Spec.DeepCopy())

		ready := expectReady("container-cves-copy", metav1.ConditionFalse, configv1alpha1.ReasonConflict)

		Expect(ready.Message).To(ContainSubstring(`"` + playbookName + `"`))
		Consistently(readyOf(&configv1alpha1.Playbook{}, playbookName), quiet, poll).Should(
			HaveField("Status", metav1.ConditionTrue), "the older playbook keeps running")
	})

	// Presence names each image in every cluster, whatever Collector delivers it, and a manifest keeps
	// one sheet. Two playbooks whose subjects are of one type conflict, whatever their Collectors.
	It("puts the newer of two playbooks in conflict whose subjects are of the same type, from other Collectors", func() {
		var original configv1alpha1.Playbook
		Expect(k8sClient.Get(ctx, client.ObjectKey{Name: playbookName}, &original)).To(Succeed())
		spec := *original.Spec.DeepCopy()
		spec.Subjects.Collector = scanner
		Expect(spec.Subjects.Collector).NotTo(Equal(original.Spec.Subjects.Collector))
		createPlaybook("container-cves-elsewhere", spec)

		ready := expectReady("container-cves-elsewhere", metav1.ConditionFalse, configv1alpha1.ReasonConflict)

		Expect(ready.Message).To(ContainSubstring(`"` + playbookName + `"`))
		Consistently(readyOf(&configv1alpha1.Playbook{}, playbookName), quiet, poll).Should(
			HaveField("Status", metav1.ConditionTrue), "the older playbook keeps running")
	})
})
