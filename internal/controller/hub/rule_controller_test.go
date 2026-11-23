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
	"slices"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/require"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/controller/hub"
	"github.com/bedag/vexplain/internal/testenv/imagecontents"
	sdkevidence "github.com/bedag/vexplain/sdk/evidence"
)

// expectCondition waits until the condition of the rule has the status and the reason, and returns it.
func expectCondition(rule, conditionType string, status metav1.ConditionStatus, reason string) *metav1.Condition {
	GinkgoHelper()
	var condition *metav1.Condition
	Eventually(func(g Gomega) {
		condition = conditionOf(&configv1alpha1.Rule{}, rule, conditionType)(g)
		g.Expect(condition).NotTo(BeNil())
		g.Expect(condition.Status).To(Equal(status))
		g.Expect(condition.Reason).To(Equal(reason))
	}, reaction, poll).Should(Succeed())
	return condition
}

// addStep adds a step of the rule to the default playbook's pipeline, and takes it out again after the
// spec.
func addStep(rule string) {
	GinkgoHelper()
	update(&configv1alpha1.Playbook{}, playbookName, func(playbook *configv1alpha1.Playbook) {
		playbook.Spec.Pipeline = append(playbook.Spec.Pipeline, configv1alpha1.PlaybookStep{Rule: rule})
	})
	DeferCleanup(func() {
		update(&configv1alpha1.Playbook{}, playbookName, func(playbook *configv1alpha1.Playbook) {
			playbook.Spec.Pipeline = playbook.Spec.Pipeline[:len(playbook.Spec.Pipeline)-1]
		})
	})
}

// addEvidence adds the evidence to the default playbook, and takes it out again after the spec.
func addEvidence(e configv1alpha1.PlaybookEvidence) {
	GinkgoHelper()
	update(&configv1alpha1.Playbook{}, playbookName, func(playbook *configv1alpha1.Playbook) {
		playbook.Spec.Evidence = append(playbook.Spec.Evidence, e)
	})
	DeferCleanup(func() {
		update(&configv1alpha1.Playbook{}, playbookName, func(playbook *configv1alpha1.Playbook) {
			playbook.Spec.Evidence = slices.DeleteFunc(playbook.Spec.Evidence, func(other configv1alpha1.PlaybookEvidence) bool {
				return other.Name == e.Name
			})
		})
	})
}

var _ = Describe("The rule controller", func() {
	It("has the default rules Ready, and a rule whose CEL doesn't compile not Ready, with the error", func() {
		for _, rule := range []string{knownExploitedRule, guardRule, removedRule, loadCheckRule} {
			expectCondition(rule, configv1alpha1.ConditionReady, metav1.ConditionTrue, configv1alpha1.ReasonValid)
		}
		broken := holdRule("broken-condition")
		broken.Spec.Condition = "finding.packageID =="
		createRule(broken)

		ready := expectCondition("broken-condition", configv1alpha1.ConditionReady, metav1.ConditionFalse, configv1alpha1.ReasonInvalid)

		Expect(ready.Message).To(ContainSubstring("condition"))
		Expect(ready.ObservedGeneration).To(Equal(int64(1)))
	})

	It("counts the findings that a rule couldn't be evaluated for, and says when it evaluates without errors again", func() {
		// The guard's CEL fails for a finding in pkg-9: its evidence has no number where the rule reads
		// one. The spec's manifest is the only one with such a finding.
		const guard, errorFree = "errs-on-pkg-9", "false"
		rule := holdRule(guard, configv1alpha1.RuleInput{Name: contents, Type: imagecontents.Type})
		rule.Spec.Condition = "finding.packageID == 'pkg-9' ? int(contents.data.platform) > 0 : false"
		createRule(rule)
		expectCondition(guard, configv1alpha1.ConditionReady, metav1.ConditionTrue, configv1alpha1.ReasonValid)
		expectCondition(guard, configv1alpha1.ConditionEvaluated, metav1.ConditionTrue, configv1alpha1.ReasonNoEvaluationErrors)
		digest, manifest := newDigest(), newDigest()
		pkg9 := sdkevidence.Match{
			VulnerabilityID: "CVE-2026-0009", PackageID: "pkg-9", Severity: "Low", FixState: "unknown",
			PackageName: "lib9", PackageType: deb,
		}
		findings.setFor(manifest, exampleMatch, pkg9)
		addStep(guard)
		runAndScan(newNamespace(), "app-0", digest, evidenceOf(manifest))

		expectCondition(guard, configv1alpha1.ConditionEvaluated, metav1.ConditionFalse, configv1alpha1.ReasonEvaluationErrors)
		// The message gives the count, and claims no more: a sheet says why only where the finding shows the
		// verdict of a rule that held it open, and not for a hint or a rule that would settle it. An evaluation
		// before the scan's contents are stored counts every finding, so the count settles once they are.
		Eventually(func(g Gomega) {
			g.Expect(conditionOf(&configv1alpha1.Rule{}, guard, configv1alpha1.ConditionEvaluated)(g)).
				To(HaveField("Message", "1 finding couldn't be evaluated in the last evaluations."))
		}, reaction, poll).Should(Succeed())
		Eventually(statusOf(manifest), reaction, poll).Should(HaveField("Findings", ContainElement(And(
			HaveField("Package.ID", "pkg-9"),
			HaveField("Rule", ptr.To(guard)),
			HaveField("Reason", HaveValue(HavePrefix("could not be evaluated: condition:"))),
		))), "the guard held the finding open, and the sheet says why")

		changeRule(guard, func(spec *configv1alpha1.RuleSpec) { spec.Condition = errorFree })

		expectCondition(guard, configv1alpha1.ConditionEvaluated, metav1.ConditionTrue, configv1alpha1.ReasonNoEvaluationErrors)
	})

	// Evidence that the playbook takes as optional, and that no Collector produces, holds the findings that a rule
	// over it covers, but is no error of the rule: the playbook runs without it on purpose. Required, the same
	// evidence keeps the playbook from being Ready, and the findings that the rule couldn't be evaluated for count.
	It("keeps Evaluated True while only optional inputs of a rule are missing, and counts required ones", func() {
		const rule = "needs-extra-input"
		// The default playbook is Ready again once the spec has put it back.
		DeferCleanup(expectReady, playbookName, metav1.ConditionTrue, configv1alpha1.ReasonValid)
		createRule(holdRule(rule, configv1alpha1.RuleInput{Name: extra, Type: extraType}))
		expectCondition(rule, configv1alpha1.ConditionEvaluated, metav1.ConditionTrue, configv1alpha1.ReasonNoEvaluationErrors)
		addEvidence(configv1alpha1.PlaybookEvidence{Name: extra, Type: extraType, Requirement: ptr.To(configv1alpha1.EvidenceOptional)})
		addStep(rule)
		expectReady(playbookName, metav1.ConditionTrue, configv1alpha1.ReasonValid)
		digest, manifest := newDigest(), newDigest()
		findings.setFor(manifest, exampleMatch)
		runAndScan(newNamespace(), "app-0", digest, evidenceOf(manifest))

		Eventually(statusOf(manifest), reaction, poll).Should(HaveField("Findings", ConsistOf(And(
			HaveField("Rule", ptr.To(rule)),
			HaveField("Reason", ptr.To(`could not be evaluated: the input "extra" is missing`)),
		))), "the rule held the finding open, and the sheet says why")
		Consistently(conditionOf(&configv1alpha1.Rule{}, rule, configv1alpha1.ConditionEvaluated), quiet, poll).Should(And(
			HaveField("Status", metav1.ConditionTrue), HaveField("Reason", configv1alpha1.ReasonNoEvaluationErrors)))

		By("requiring the evidence")
		update(&configv1alpha1.Playbook{}, playbookName, func(playbook *configv1alpha1.Playbook) {
			i := slices.IndexFunc(playbook.Spec.Evidence, func(e configv1alpha1.PlaybookEvidence) bool { return e.Name == extra })
			playbook.Spec.Evidence[i].Requirement = ptr.To(configv1alpha1.EvidenceRequired)
		})

		// The sheets of the suite are evaluated again from their findings, so the rule's count covers every sheet that
		// is left.
		expectReady(playbookName, metav1.ConditionFalse, configv1alpha1.ReasonTypeNotProduced)
		expectCondition(rule, configv1alpha1.ConditionEvaluated, metav1.ConditionFalse, configv1alpha1.ReasonEvaluationErrors)
	})
})

// An exposure rule's Evaluated condition counts workloads, where a finding rule's counts findings. The cases record
// the workloads that a playbook's exposure rules couldn't be evaluated for under the name of the playbook's sheet of
// the manifest, after exposure/.
func TestTheEvaluatedConditionOfAnExposureRuleCountsWorkloads(t *testing.T) {
	c := newClient(t, interceptor.Funcs{})
	for _, rule := range unitRules(t) {
		require.NoError(t, c.Create(t.Context(), rule))
	}
	evaluations := hub.NewEvaluations()
	r := &hub.RuleReconciler{Client: c, Rules: hub.NewRules(), Evaluations: evaluations}
	evaluated := func(rule string) string {
		t.Helper()
		_, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: types.NamespacedName{Name: rule}})
		require.NoError(t, err)
		var obj configv1alpha1.Rule
		require.NoError(t, c.Get(t.Context(), client.ObjectKey{Name: rule}, &obj))
		condition := meta.FindStatusCondition(obj.Status.Conditions, configv1alpha1.ConditionEvaluated)
		require.NotNil(t, condition)
		return condition.Message
	}

	require.Equal(t, "The rule could be evaluated for every finding of its last evaluations.", evaluated(guardRule))
	require.Equal(t, "The rule could be evaluated for every workload of its last evaluations.",
		evaluated(exposedOutsideCluster))

	evaluations.Record(hub.ExposureEvaluations(digestOf(101), playbookName), map[string]int{exposedOutsideCluster: 1})
	require.Equal(t, "1 workload couldn't be evaluated in the last evaluations.", evaluated(exposedOutsideCluster))
	evaluations.Record(hub.ExposureEvaluations(digestOf(101), playbookName), map[string]int{exposedOutsideCluster: 2})
	require.Equal(t, "2 workloads couldn't be evaluated in the last evaluations.", evaluated(exposedOutsideCluster))
}
