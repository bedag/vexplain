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
	"os"
	"path/filepath"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
)

// justificationRule is the message of the rule that ties a justification to the status NotAffected.
const justificationRule = "justification is set exactly when status is NotAffected"

// These specs check the schema of the Rule against the API server: the shape of its inputs, the bounds
// of its CEL, and the OpenVEX status that it concludes, with the justification that goes with it.
var _ = Describe("Rule API", func() {
	// ruleNamed returns a rule that the schema accepts, and that settles a finding as not affected.
	ruleNamed := func(name string) *configv1alpha1.Rule {
		return &configv1alpha1.Rule{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec: configv1alpha1.RuleSpec{
				Inputs: []configv1alpha1.RuleInput{{Name: contentsName, Type: contentsType}},
				Condition: `contents.data.packages.exists(p, p.id == finding.packageId` +
					` && p.filesListed > 0 && p.filesPresent == 0)`,
				Outcome: &configv1alpha1.RuleOutcome{
					Status:        ptr.To(configv1alpha1.VEXStatus("NotAffected")),
					Justification: ptr.To(configv1alpha1.VEXJustification("ComponentNotPresent")),
				},
			},
		}
	}

	// withOutcome returns a rule with the outcome, and with the one input that the CEL of ruleNamed
	// needs.
	withOutcome := func(status, justification string) *configv1alpha1.Rule {
		rule := ruleNamed(apiName("outcome"))
		rule.Spec.Outcome = &configv1alpha1.RuleOutcome{}
		if status != "" {
			rule.Spec.Outcome.Status = ptr.To(configv1alpha1.VEXStatus(status))
		}
		if justification != "" {
			rule.Spec.Outcome.Justification = ptr.To(configv1alpha1.VEXJustification(justification))
		}
		return rule
	}

	It("keeps the rule of the design that settles a finding as not affected", func() {
		want := ruleNamed(apiName("removed-in-later-layer"))
		createObject(want)

		var got configv1alpha1.Rule
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(want), &got)).To(Succeed())
		Expect(got.Spec).To(Equal(want.Spec))
	})

	Describe("the outcome", func() {
		// A rule without a status is a hint: it settles nothing, and adds a status note to the finding.
		It("accepts a rule without a status, a hint", func() {
			createObject(withOutcome("", ""))
		})

		// A hint writes an empty outcome. Leaving the outcome out is an error, so that a rule never
		// settles nothing by accident.
		It("refuses a rule that leaves out its outcome", func() {
			rule := ruleNamed(apiName("no-outcome"))
			rule.Spec.Outcome = nil

			Expect(k8sClient.Create(ctx, rule)).To(refusedWith("spec.outcome: Required value"))
		})

		It("keeps the reason of a hint, which is the text of its status note", func() {
			rule := withOutcome("", "")
			rule.Spec.Reason = ptr.To(`"nothing in the image reaches its libraries"`)
			createObject(rule)

			var got configv1alpha1.Rule
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(rule), &got)).To(Succeed())
			Expect(got.Spec.Outcome).To(Equal(&configv1alpha1.RuleOutcome{}))
			Expect(got.Spec.Reason).To(HaveValue(Equal(`"nothing in the image reaches its libraries"`)))
		})

		DescribeTable("accepts the status that is not NotAffected, with no justification",
			func(status string) {
				createObject(withOutcome(status, ""))
			},
			Entry("Affected", "Affected"),
			Entry("UnderInvestigation", "UnderInvestigation"),
			Entry("Fixed", "Fixed"),
		)

		// The five justifications of OpenVEX, in CamelCase.
		DescribeTable("accepts NotAffected with the justification",
			func(justification string) {
				createObject(withOutcome("NotAffected", justification))
			},
			Entry("ComponentNotPresent", "ComponentNotPresent"),
			Entry("VulnerableCodeNotPresent", "VulnerableCodeNotPresent"),
			Entry("VulnerableCodeNotInExecutePath", "VulnerableCodeNotInExecutePath"),
			Entry("VulnerableCodeCannotBeControlledByAdversary", "VulnerableCodeCannotBeControlledByAdversary"),
			Entry("InlineMitigationsAlreadyExist", "InlineMitigationsAlreadyExist"),
		)

		It("refuses NotAffected without a justification", func() {
			Expect(k8sClient.Create(ctx, withOutcome("NotAffected", ""))).To(refusedWith(justificationRule))
		})

		DescribeTable("refuses a justification with the status",
			func(status string) {
				Expect(k8sClient.Create(ctx, withOutcome(status, "ComponentNotPresent"))).To(refusedWith(justificationRule))
			},
			Entry("Affected", "Affected"),
			Entry("UnderInvestigation", "UnderInvestigation"),
			Entry("Fixed", "Fixed"),
			Entry("none, which makes a hint", ""),
		)

		DescribeTable("refuses a status that is no status of OpenVEX, in the API's spelling",
			func(status string) {
				Expect(k8sClient.Create(ctx, withOutcome(status, ""))).To(refusedWith("spec.outcome.status"))
			},
			Entry("OpenVEX's own spelling", "not_affected"),
			Entry("lower camel case", "notAffected"),
			Entry("the status of phase 2a", "NeedsAssessment"),
			Entry("an unknown status", "Unknown"),
		)

		DescribeTable("refuses a justification that is no justification of OpenVEX, in the API's spelling",
			func(justification string) {
				Expect(k8sClient.Create(ctx, withOutcome("NotAffected", justification))).To(
					refusedWith("spec.outcome.justification"))
			},
			Entry("OpenVEX's own spelling", "component_not_present"),
			Entry("lower camel case", "componentNotPresent"),
			Entry("an unknown justification", "NoOneRunsIt"),
		)
	})

	Describe("the inputs", func() {
		// A rule's CEL reads each input as a variable, so a name is a CEL identifier.
		DescribeTable("refuses an input name that is no identifier, with",
			func(name string) {
				rule := ruleNamed(apiName("bad-input"))
				rule.Spec.Inputs[0].Name = name

				Expect(k8sClient.Create(ctx, rule)).To(refusedWith("spec.inputs[0].name"))
			},
			Entry("a digit first", "1x"),
			Entry("a capital first", "Contents"),
			Entry("an underscore", "image_contents"),
			Entry("a dash", "image-contents"),
			Entry("64 characters", "a"+strings.Repeat("b", 63)),
		)

		DescribeTable("accepts an input name that is an identifier, with",
			func(name string) {
				rule := ruleNamed(apiName("input"))
				rule.Spec.Inputs[0].Name = name

				createObject(rule)
			},
			Entry("one letter", "c"),
			Entry("camel case and a digit", "imageContents2"),
			Entry("63 characters", "a"+strings.Repeat("b", 62)),
		)

		DescribeTable("refuses an input that lacks",
			func(input map[string]any, field string) {
				spec := map[string]any{conditionField: celTrue, outcomeField: map[string]any{}, "inputs": []any{input}}

				err := k8sClient.Create(ctx, rawObject("Rule", apiName("bad-input"), spec))

				Expect(err).To(refusedWith(field))
			},
			Entry("a name", map[string]any{typeField: contentsType}, "spec.inputs[0].name: Required value"),
			Entry("a type", map[string]any{nameField: contentsName}, "spec.inputs[0].type: Required value"),
		)

		DescribeTable("refuses an input type outside the pattern of types, with",
			func(evidenceType string) {
				rule := ruleNamed(apiName("bad-type"))
				rule.Spec.Inputs[0].Type = evidenceType

				Expect(k8sClient.Create(ctx, rule)).To(refusedWith("spec.inputs[0].type"))
			},
			Entry("no version", "ch.bedag.vexplain.scanner.image-contents"),
			Entry("a capital letter", "ch.bedag.vexplain.Scanner.v1alpha1"),
			Entry("no dots", "contents"),
		)

		It("refuses two inputs of one name", func() {
			rule := ruleNamed(apiName("same-name"))
			rule.Spec.Inputs = append(rule.Spec.Inputs, configv1alpha1.RuleInput{Name: contentsName, Type: exposureType})

			Expect(k8sClient.Create(ctx, rule)).To(refusedWith("Duplicate value"))
		})

		It("accepts 8 inputs, and refuses 9", func() {
			rule := ruleNamed(apiName("many-inputs"))
			rule.Spec.Inputs = inputsNamed(8)
			createObject(rule)

			tooMany := ruleNamed(apiName("too-many-inputs"))
			tooMany.Spec.Inputs = inputsNamed(9)
			Expect(k8sClient.Create(ctx, tooMany)).To(refusedWith("spec.inputs: Too many"))
		})

		It("accepts a rule that needs no input", func() {
			rule := ruleNamed(apiName("no-input"))
			rule.Spec.Inputs = nil
			rule.Spec.Condition = "finding.knownExploited"

			createObject(rule)
		})
	})

	Describe("the CEL", func() {
		It("refuses a rule without a condition", func() {
			rule := ruleNamed(apiName("no-condition"))
			rule.Spec.Condition = ""

			Expect(k8sClient.Create(ctx, rule)).To(refusedWith("spec.condition: Required value"))
		})

		It("refuses a condition that is empty", func() {
			spec := map[string]any{conditionField: "", outcomeField: map[string]any{}}

			err := k8sClient.Create(ctx, rawObject("Rule", apiName("empty-condition"), spec))

			Expect(err).To(refusedWith("spec.condition"))
		})

		DescribeTable("refuses CEL of 4097 characters, and accepts 4096, in",
			func(set func(spec *configv1alpha1.RuleSpec, cel string), field string) {
				// The expression is a comment on a CEL line, and so stays valid CEL at any length.
				longest := celTrue + " // " + strings.Repeat("x", 4096-len(celTrue+" // "))
				rule := ruleNamed(apiName("long-cel"))
				set(&rule.Spec, longest)
				createObject(rule)

				tooLong := ruleNamed(apiName("too-long-cel"))
				set(&tooLong.Spec, longest+"x")
				Expect(k8sClient.Create(ctx, tooLong)).To(refusedWith(field))
			},
			Entry("the condition",
				func(spec *configv1alpha1.RuleSpec, cel string) { spec.Condition = cel }, "spec.condition"),
			Entry("the match",
				func(spec *configv1alpha1.RuleSpec, cel string) { spec.Match = ptr.To(cel) }, "spec.match"),
			Entry("the reason",
				func(spec *configv1alpha1.RuleSpec, cel string) { spec.Reason = ptr.To(cel) }, "spec.reason"),
		)

		DescribeTable("refuses a match or a reason that is empty, which is no CEL",
			func(field string) {
				spec := map[string]any{conditionField: celTrue, outcomeField: map[string]any{}, field: ""}

				err := k8sClient.Create(ctx, rawObject("Rule", apiName("empty-"+field), spec))

				Expect(err).To(refusedWith("spec." + field))
			},
			Entry("match", "match"),
			Entry("reason", "reason"),
		)

		It("keeps the match and the reason of a rule", func() {
			rule := ruleNamed(apiName("match-and-reason"))
			rule.Spec.Match = ptr.To(`finding.packageType == "apk"`)
			rule.Spec.Reason = ptr.To(`"removed in a later layer: " + finding.packageName`)
			createObject(rule)

			var got configv1alpha1.Rule
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(rule), &got)).To(Succeed())
			Expect(got.Spec.Match).To(Equal(rule.Spec.Match))
			Expect(got.Spec.Reason).To(Equal(rule.Spec.Reason))
		})
	})

	// A Rule's name goes into the pipeline of a playbook, and a step names a rule with a DNS-1123
	// label, so a Rule's name is one too.
	Describe("the name", func() {
		DescribeTable("refuses a name that is no DNS-1123 label",
			func(name string) {
				Expect(k8sClient.Create(ctx, ruleNamed(name))).To(refusedWith("a Rule is named with a DNS-1123 label"))
			},
			Entry("with a dot", "known.exploited"),
			Entry("of 64 characters", strings.Repeat("a", 64)),
		)

		It("accepts a name of 63 characters", func() {
			createObject(ruleNamed(strings.Repeat("a", 63)))
		})
	})

	Describe("the status", func() {
		It("takes the conditions Ready and Evaluated through the status subresource", func() {
			rule := ruleNamed(apiName("status"))
			createObject(rule)
			base := rule.DeepCopy()
			rule.Status.Conditions = []metav1.Condition{
				{
					Type: configv1alpha1.ConditionReady, Status: metav1.ConditionTrue, Reason: configv1alpha1.ReasonValid,
					ObservedGeneration: rule.Generation, LastTransitionTime: metav1.Now(),
				},
				{
					Type: configv1alpha1.ConditionEvaluated, Status: metav1.ConditionFalse,
					Reason: configv1alpha1.ReasonEvaluationErrors, Message: "3 findings could not be evaluated.",
					ObservedGeneration: rule.Generation, LastTransitionTime: metav1.Now(),
				},
			}

			// The answer of the API server is the object as it stored the patch. A read after it could
			// see what the rule controller of the suite's manager wrote since.
			Expect(k8sClient.Status().Patch(ctx, rule, client.MergeFrom(base))).To(Succeed())

			Expect(rule.Status.Conditions).To(HaveLen(2))
			Expect(rule.Status.Conditions[1].Type).To(Equal("Evaluated"))
			Expect(rule.Status.Conditions[1].Reason).To(Equal("EvaluationErrors"))
		})
	})

	It("accepts the sample", func() {
		data, err := os.ReadFile(filepath.Join("..", "..", "..", "config", "samples", "config_v1alpha1_rule.yaml"))
		Expect(err).NotTo(HaveOccurred())
		sample := &configv1alpha1.Rule{}
		Expect(yaml.UnmarshalStrict(data, sample)).To(Succeed())

		createObject(sample)

		Expect(sample.Spec.Condition).NotTo(BeEmpty())
	})
})

// inputsNamed returns n inputs of different names.
func inputsNamed(n int) []configv1alpha1.RuleInput {
	inputs := make([]configv1alpha1.RuleInput, n)
	for i := range inputs {
		inputs[i] = configv1alpha1.RuleInput{Name: "input" + strings.Repeat("x", i), Type: contentsType}
	}
	return inputs
}
