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

// These specs check the schema of the Playbook against the API server: its name, the types of its
// subjects, findings and evidence, the Collectors that it pins, and the rules of its pipeline.
var _ = Describe("Playbook API", func() {
	// containerPlaybook returns the playbook of the design for containers, which the schema accepts. It
	// names types, and pins no Collector, with the defaults that the API server gives.
	containerPlaybook := func(name string) *configv1alpha1.Playbook {
		return &configv1alpha1.Playbook{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec: configv1alpha1.PlaybookSpec{
				Subjects: configv1alpha1.PlaybookSource{Type: presenceType},
				Findings: configv1alpha1.PlaybookFindings{Type: ptr.To(findingsType)},
				Evidence: []configv1alpha1.PlaybookEvidence{
					{Name: contentsName, Type: contentsType, Requirement: ptr.To(configv1alpha1.EvidenceRequired)},
					{Name: exposureName, Type: exposureType, Requirement: ptr.To(configv1alpha1.EvidenceRequired)},
				},
				Pipeline: []configv1alpha1.PlaybookStep{
					{Rule: "known-exploited"}, {Rule: "completeness-guard"},
					{Rule: "removed-in-later-layer"}, {Rule: "load-check"},
				},
			},
		}
	}

	// rawSpec returns the spec of containerPlaybook as raw content, which a spec changes where a Go
	// struct couldn't say it.
	rawSpec := func() map[string]any {
		return map[string]any{
			subjectsField: map[string]any{typeField: presenceType},
			findingsField: map[string]any{typeField: findingsType},
			pipelineField: []any{map[string]any{"rule": "known-exploited"}},
		}
	}

	// stored reads the playbook as the API server stored it.
	stored := func(playbook *configv1alpha1.Playbook) configv1alpha1.Playbook {
		GinkgoHelper()
		var got configv1alpha1.Playbook
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(playbook), &got)).To(Succeed())
		return got
	}

	It("keeps the playbook of the design for containers", func() {
		want := containerPlaybook(apiName("container-cves"))
		createObject(want)

		Expect(stored(want).Spec).To(Equal(want.Spec))
	})

	// An entry pins its producers by the names of their Collectors. Without a pin, every Collector that
	// produces its type counts.
	It("keeps a playbook whose entries pin Collectors, and whose evidence is optional", func() {
		want := containerPlaybook(apiName("pinned"))
		want.Spec.Subjects.Collectors = []string{workloadsName}
		want.Spec.Findings.Collectors = []string{vulnerabilitiesName, "other-vulnerabilities"}
		want.Spec.Evidence[0].Collectors = []string{scannerName}
		want.Spec.Evidence[1].Collectors = []string{networkReachName}
		want.Spec.Evidence[1].Requirement = ptr.To(configv1alpha1.EvidenceOptional)
		createObject(want)

		Expect(stored(want).Spec).To(Equal(want.Spec))
	})

	It("defaults the findings to the type of vulnerabilities, and the evidence to required", func() {
		spec := rawSpec()
		spec[findingsField] = map[string]any{}
		spec["evidence"] = []any{map[string]any{nameField: contentsName, typeField: contentsType}}
		obj := rawObject("Playbook", apiName("defaults"), spec)
		createObject(obj)

		var got configv1alpha1.Playbook
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(obj), &got)).To(Succeed())
		Expect(got.Spec.Findings).To(Equal(configv1alpha1.PlaybookFindings{Type: ptr.To(findingsType)}))
		Expect(got.Spec.Evidence).To(ConsistOf(
			configv1alpha1.PlaybookEvidence{Name: contentsName, Type: contentsType, Requirement: ptr.To(configv1alpha1.EvidenceRequired)}))
	})

	// The names of the objects that hold a playbook's results take its name, so a Playbook is named with a
	// DNS-1123 label of at most 63 characters.
	Describe("the name", func() {
		DescribeTable("refuses a name that is no DNS-1123 label",
			func(name string) {
				Expect(k8sClient.Create(ctx, containerPlaybook(name))).To(refusedWith("a Playbook is named with a DNS-1123 label"))
			},
			Entry("with a dot", "container.cves"),
			Entry("of 64 characters", strings.Repeat("a", 64)),
		)

		It("accepts a name of 63 characters", func() {
			createObject(containerPlaybook(strings.Repeat("a", 63)))
		})
	})

	It("accepts a playbook without evidence, since a rule may need none", func() {
		playbook := containerPlaybook(apiName("no-evidence"))
		playbook.Spec.Evidence = nil

		createObject(playbook)
	})

	Describe("the pipeline", func() {
		It("refuses a Playbook without a pipeline", func() {
			playbook := containerPlaybook(apiName("no-pipeline"))
			playbook.Spec.Pipeline = nil

			Expect(k8sClient.Create(ctx, playbook)).To(refusedWith("spec.pipeline: Required value"))
		})

		It("refuses a pipeline without steps", func() {
			spec := rawSpec()
			spec[pipelineField] = []any{}

			err := k8sClient.Create(ctx, rawObject("Playbook", apiName("no-steps"), spec))

			Expect(err).To(refusedWith("spec.pipeline"))
		})

		It("refuses a step without a rule", func() {
			spec := rawSpec()
			spec[pipelineField] = []any{map[string]any{}}

			err := k8sClient.Create(ctx, rawObject("Playbook", apiName("no-rule"), spec))

			Expect(err).To(refusedWith("spec.pipeline[0].rule: Required value"))
		})

		It("accepts 32 steps, and refuses 33", func() {
			playbook := containerPlaybook(apiName("long-pipeline"))
			playbook.Spec.Pipeline = stepsNamed(32)
			createObject(playbook)

			tooLong := containerPlaybook(apiName("too-long-pipeline"))
			tooLong.Spec.Pipeline = stepsNamed(33)
			Expect(k8sClient.Create(ctx, tooLong)).To(refusedWith("spec.pipeline: Too many"))
		})

		// A step names a rule, and a Rule is named with a DNS-1123 label.
		DescribeTable("refuses a step that names a rule that can't exist, with",
			func(rule string) {
				playbook := containerPlaybook(apiName("bad-rule"))
				playbook.Spec.Pipeline = []configv1alpha1.PlaybookStep{{Rule: rule}}

				Expect(k8sClient.Create(ctx, playbook)).To(refusedWith("spec.pipeline[0].rule"))
			},
			Entry("an uppercase letter", "Known-Exploited"),
			Entry("a dot", "known.exploited"),
			Entry("an underscore", "known_exploited"),
			Entry("a dash at its end", "known-"),
			Entry("64 characters", strings.Repeat("a", 64)),
		)
	})

	Describe("the subjects and the findings", func() {
		It("refuses a Playbook without subjects", func() {
			playbook := containerPlaybook(apiName("no-subjects"))
			playbook.Spec.Subjects = configv1alpha1.PlaybookSource{}

			Expect(k8sClient.Create(ctx, playbook)).To(refusedWith("spec.subjects"))
		})

		It("refuses a Playbook without findings", func() {
			playbook := containerPlaybook(apiName("no-findings"))
			playbook.Spec.Findings = configv1alpha1.PlaybookFindings{}

			Expect(k8sClient.Create(ctx, playbook)).To(refusedWith("spec.findings"))
		})

		It("refuses subjects that lack a type", func() {
			spec := rawSpec()
			spec[subjectsField] = map[string]any{collectorsField: []any{workloadsName}}

			err := k8sClient.Create(ctx, rawObject("Playbook", apiName("bad-subjects"), spec))

			Expect(err).To(refusedWith("spec.subjects.type: Required value"))
		})

		// The pinned collectors are named by their Collector's name, a DNS-1123 label.
		DescribeTable("refuses a pinned collector that can't exist, with",
			func(collector string) {
				subjects := containerPlaybook(apiName("bad-subjects"))
				subjects.Spec.Subjects.Collectors = []string{collector}
				Expect(k8sClient.Create(ctx, subjects)).To(refusedWith("spec.subjects.collectors[0]"))

				findings := containerPlaybook(apiName("bad-findings"))
				findings.Spec.Findings.Collectors = []string{collector}
				Expect(k8sClient.Create(ctx, findings)).To(refusedWith("spec.findings.collectors[0]"))

				evidence := containerPlaybook(apiName("bad-evidence"))
				evidence.Spec.Evidence[0].Collectors = []string{collector}
				Expect(k8sClient.Create(ctx, evidence)).To(refusedWith("spec.evidence[0].collectors[0]"))
			},
			Entry("an uppercase letter", "Workloads"),
			Entry("a dot", "workloads.example"),
			Entry("a dash at its start", "-workloads"),
			Entry("no characters", ""),
			Entry("64 characters", strings.Repeat("a", 64)),
		)

		It("pins 8 collectors of an entry, and refuses 9, or one twice", func() {
			playbook := containerPlaybook(apiName("eight-pins"))
			playbook.Spec.Evidence[0].Collectors = collectorsNamed(8)
			createObject(playbook)

			tooMany := containerPlaybook(apiName("nine-pins"))
			tooMany.Spec.Subjects.Collectors = collectorsNamed(9)
			Expect(k8sClient.Create(ctx, tooMany)).To(refusedWith("spec.subjects.collectors: Too many"))

			twice := containerPlaybook(apiName("same-pin"))
			twice.Spec.Findings.Collectors = []string{vulnerabilitiesName, vulnerabilitiesName}
			Expect(k8sClient.Create(ctx, twice)).To(refusedWith("spec.findings.collectors[1]: Duplicate value"))
		})

		// The types match the pattern of the SDK: reverse-DNS, and versioned.
		DescribeTable("refuses a type outside the pattern of types, with",
			func(evidenceType string) {
				subjects := containerPlaybook(apiName("bad-subjects"))
				subjects.Spec.Subjects.Type = evidenceType
				Expect(k8sClient.Create(ctx, subjects)).To(refusedWith("spec.subjects.type"))

				findings := containerPlaybook(apiName("bad-findings"))
				findings.Spec.Findings.Type = ptr.To(evidenceType)
				Expect(k8sClient.Create(ctx, findings)).To(refusedWith("spec.findings.type"))

				evidence := containerPlaybook(apiName("bad-evidence"))
				evidence.Spec.Evidence[0].Type = evidenceType
				Expect(k8sClient.Create(ctx, evidence)).To(refusedWith("spec.evidence[0].type"))
			},
			Entry("no dots", "presence"),
			Entry("no version", "ch.bedag.vexplain.presence"),
			Entry("a version without a number", "ch.bedag.vexplain.presence.v"),
			Entry("a version with a suffix that is not alpha or beta", "ch.bedag.vexplain.presence.v1gamma1"),
			Entry("a capital letter", "ch.bedag.vexplain.Presence.v1alpha1"),
			Entry("an underscore", "ch.bedag.vexplain.presence_data.v1alpha1"),
		)

		DescribeTable("accepts a type of the pattern, with",
			func(evidenceType string) {
				playbook := containerPlaybook(apiName("type"))
				playbook.Spec.Subjects.Type = evidenceType
				playbook.Spec.Evidence[0].Type = evidenceType

				createObject(playbook)
			},
			Entry("a stable version", "com.example.hello.v2"),
			Entry("an alpha version", "com.example.hello.v1alpha1"),
			Entry("a beta version", "com.example.hello.v2beta1"),
			Entry("dashes in its labels", "ch.bedag.vexplain.scanner.image-contents.v1alpha1"),
		)

		It("refuses a type of 254 characters", func() {
			playbook := containerPlaybook(apiName("long-type"))
			playbook.Spec.Subjects.Type = "com." + strings.Repeat("a", 241) + ".v1alpha1"
			Expect(playbook.Spec.Subjects.Type).To(HaveLen(254))

			Expect(k8sClient.Create(ctx, playbook)).To(refusedWith("spec.subjects.type"))
		})
	})

	Describe("the evidence", func() {
		// The names of the evidence are the names that a rule's inputs use, and a rule's CEL reads them
		// as variables, so each is a CEL identifier.
		DescribeTable("refuses an evidence name that is no identifier, with",
			func(name string) {
				playbook := containerPlaybook(apiName("bad-name"))
				playbook.Spec.Evidence[0].Name = name

				Expect(k8sClient.Create(ctx, playbook)).To(refusedWith("spec.evidence[0].name"))
			},
			Entry("a digit first", "1x"),
			Entry("a capital first", "Contents"),
			Entry("an underscore", "image_contents"),
			Entry("a dash", "image-contents"),
			Entry("a dot", "contents.data"),
			Entry("64 characters", "a"+strings.Repeat("b", 63)),
		)

		DescribeTable("accepts an evidence name that is an identifier, with",
			func(name string) {
				playbook := containerPlaybook(apiName("name"))
				playbook.Spec.Evidence[0].Name = name

				createObject(playbook)
			},
			Entry("one letter", "c"),
			Entry("camel case and a digit", "imageContents2"),
			Entry("63 characters", "a"+strings.Repeat("b", 62)),
		)

		DescribeTable("refuses evidence that lacks",
			func(evidence map[string]any, field string) {
				spec := rawSpec()
				spec["evidence"] = []any{evidence}

				err := k8sClient.Create(ctx, rawObject("Playbook", apiName("bad-evidence"), spec))

				Expect(err).To(refusedWith(field))
			},
			Entry("a name", map[string]any{typeField: contentsType}, "spec.evidence[0].name: Required value"),
			Entry("a type", map[string]any{nameField: contentsName}, "spec.evidence[0].type: Required value"),
		)

		It("refuses a requirement that is neither Required nor Optional", func() {
			spec := rawSpec()
			spec["evidence"] = []any{map[string]any{nameField: contentsName, typeField: contentsType, "requirement": "Preferred"}}

			err := k8sClient.Create(ctx, rawObject("Playbook", apiName("bad-requirement"), spec))

			Expect(err).To(refusedWith("spec.evidence[0].requirement: Unsupported value"))
		})

		It("refuses two pieces of evidence of one name", func() {
			playbook := containerPlaybook(apiName("same-name"))
			playbook.Spec.Evidence[1].Name = playbook.Spec.Evidence[0].Name

			Expect(k8sClient.Create(ctx, playbook)).To(refusedWith("Duplicate value"))
		})

		// The match of a findings producer takes the one piece of each type that it consumes, so a playbook
		// names each type once.
		It("refuses two pieces of evidence of one type", func() {
			playbook := containerPlaybook(apiName("same-type"))
			playbook.Spec.Evidence[1].Type = playbook.Spec.Evidence[0].Type

			Expect(k8sClient.Create(ctx, playbook)).To(refusedWith("a playbook names each type of evidence once"))
		})

		It("accepts 16 pieces of evidence, and refuses 17", func() {
			playbook := containerPlaybook(apiName("much-evidence"))
			playbook.Spec.Evidence = evidenceNamed(16)
			createObject(playbook)

			tooMuch := containerPlaybook(apiName("too-much-evidence"))
			tooMuch.Spec.Evidence = evidenceNamed(17)
			Expect(k8sClient.Create(ctx, tooMuch)).To(refusedWith("spec.evidence: Too many"))
		})
	})

	Describe("the status", func() {
		It("takes the Ready condition through the status subresource", func() {
			playbook := containerPlaybook(apiName("status"))
			createObject(playbook)
			base := playbook.DeepCopy()
			playbook.Status.Conditions = []metav1.Condition{{
				Type: configv1alpha1.ConditionReady, Status: metav1.ConditionFalse,
				Reason: configv1alpha1.ReasonCollectorMissing, Message: `Collector "vulnerabilities" does not exist.`,
				ObservedGeneration: playbook.Generation, LastTransitionTime: metav1.Now(),
			}}

			// The answer of the API server is the object as it stored the patch. A read after it could
			// see what the playbook controller of the suite's manager wrote since.
			Expect(k8sClient.Status().Patch(ctx, playbook, client.MergeFrom(base))).To(Succeed())

			Expect(playbook.Status.Conditions).To(HaveLen(1))
			Expect(playbook.Status.Conditions[0].Reason).To(Equal("CollectorMissing"))
		})

		It("ignores a status that arrives with the spec", func() {
			playbook := containerPlaybook(apiName("status-on-create"))
			playbook.Status.Conditions = []metav1.Condition{{
				Type: configv1alpha1.ConditionReady, Status: metav1.ConditionTrue, Reason: configv1alpha1.ReasonValid,
				LastTransitionTime: metav1.Now(),
			}}

			// The answer of the API server is the object as it created it, before the playbook controller
			// of the suite's manager writes a condition of its own.
			createObject(playbook)

			Expect(playbook.Status.Conditions).To(BeEmpty())
		})
	})

	It("accepts the sample, which is the playbook for containers", func() {
		data, err := os.ReadFile(filepath.Join("..", "..", "..", "config", "samples", "config_v1alpha1_playbook.yaml"))
		Expect(err).NotTo(HaveOccurred())
		sample := &configv1alpha1.Playbook{}
		Expect(yaml.UnmarshalStrict(data, sample)).To(Succeed())

		createObject(sample)

		Expect(sample.Spec.Pipeline).NotTo(BeEmpty())
	})
})

// stepsNamed returns n steps that name different rules.
func stepsNamed(n int) []configv1alpha1.PlaybookStep {
	steps := make([]configv1alpha1.PlaybookStep, n)
	for i := range steps {
		steps[i] = configv1alpha1.PlaybookStep{Rule: "rule" + strings.Repeat("x", i)}
	}
	return steps
}

// evidenceNamed returns n pieces of evidence of different names and types.
func evidenceNamed(n int) []configv1alpha1.PlaybookEvidence {
	evidence := make([]configv1alpha1.PlaybookEvidence, n)
	for i := range evidence {
		evidence[i] = configv1alpha1.PlaybookEvidence{
			Name: "evidence" + strings.Repeat("x", i), Type: "com.example.evidence" + strings.Repeat("x", i) + ".v1",
		}
	}
	return evidence
}

// collectorsNamed returns the names of n different Collectors.
func collectorsNamed(n int) []string {
	names := make([]string, n)
	for i := range names {
		names[i] = "collector" + strings.Repeat("x", i)
	}
	return names
}
