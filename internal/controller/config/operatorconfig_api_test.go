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
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
)

// These specs check the two fields that the OperatorConfig gains in phase 2b: the allowlists of owner
// attribution, and the overrides of the table that decides urgency. The earlier fields have their own
// specs.
var _ = Describe("OperatorConfig API of owner attribution and urgency", func() {
	const (
		timeout  = 30 * time.Second
		interval = 100 * time.Millisecond
	)
	const (
		// singletonName is the only name that the CRD accepts.
		singletonName = "default"
		// ownerKey is a key of a label or an annotation that the allowlists name.
		ownerKey = "owner"
	)
	singleton := client.ObjectKey{Name: singletonName}

	// The singleton is cluster-scoped, and the specs of the OperatorConfig share it. Each spec starts
	// without it, and leaves without it.
	AfterEach(func() {
		Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, &configv1alpha1.OperatorConfig{
			ObjectMeta: metav1.ObjectMeta{Name: singleton.Name},
		}))).To(Succeed())
		Eventually(func() error {
			return k8sClient.Get(ctx, singleton, &configv1alpha1.OperatorConfig{})
		}, timeout, interval).Should(Satisfy(apierrors.IsNotFound))
	})

	// configWith returns the singleton with spec.
	configWith := func(spec configv1alpha1.OperatorConfigSpec) *configv1alpha1.OperatorConfig {
		return &configv1alpha1.OperatorConfig{ObjectMeta: metav1.ObjectMeta{Name: singleton.Name}, Spec: spec}
	}

	Describe("owner attribution", func() {
		// longestPrefix is the longest prefix of a key that Kubernetes accepts: a DNS name of 253
		// characters, of labels of 63 at most.
		longestPrefix := strings.Join([]string{
			strings.Repeat("a", 63), strings.Repeat("a", 63), strings.Repeat("a", 63), strings.Repeat("a", 61),
		}, ".")

		withAttribution := func(a configv1alpha1.OwnerAttribution) *configv1alpha1.OperatorConfig {
			return configWith(configv1alpha1.OperatorConfigSpec{OwnerAttribution: &a})
		}

		It("keeps the three allowlists", func() {
			want := configv1alpha1.OwnerAttribution{
				NamespaceLabels:      []string{ownerKey, "example.com/contact"},
				NamespaceAnnotations: []string{"contact"},
				WorkloadLabels:       []string{"app.kubernetes.io/part-of"},
			}
			Expect(k8sClient.Create(ctx, withAttribution(want))).To(Succeed())

			var got configv1alpha1.OperatorConfig
			Expect(k8sClient.Get(ctx, singleton, &got)).To(Succeed())
			Expect(got.Spec.OwnerAttribution).To(Equal(&want))
		})

		It("is optional, since nothing is copied unless an admin says so", func() {
			Expect(k8sClient.Create(ctx, configWith(configv1alpha1.OperatorConfigSpec{}))).To(Succeed())

			var got configv1alpha1.OperatorConfig
			Expect(k8sClient.Get(ctx, singleton, &got)).To(Succeed())
			Expect(got.Spec.OwnerAttribution).To(BeNil())
		})

		// Labels and annotations share the syntax of their keys: an optional DNS prefix and a slash, and
		// then a name.
		DescribeTable("refuses a key that is no qualified name, with",
			func(key string) {
				for field, attribution := range map[string]configv1alpha1.OwnerAttribution{
					"namespaceLabels":      {NamespaceLabels: []string{key}},
					"namespaceAnnotations": {NamespaceAnnotations: []string{key}},
					"workloadLabels":       {WorkloadLabels: []string{key}},
				} {
					err := k8sClient.Create(ctx, withAttribution(attribution))

					Expect(err).To(refusedWith("spec.ownerAttribution." + field + "[0]"))
				}
			},
			Entry("a space", "owner label"),
			Entry("a dash first", "-owner"),
			Entry("a dash last", "owner-"),
			Entry("two slashes", "example.com/owner/contact"),
			Entry("a capital in the prefix", "Example.com/owner"),
			Entry("an empty name after the prefix", "example.com/"),
			Entry("no characters at all", ""),
			Entry("318 characters, a name of 64 after the longest prefix", longestPrefix+"/"+strings.Repeat("b", 64)),
		)

		DescribeTable("accepts a key that is a qualified name, with",
			func(key string) {
				Expect(k8sClient.Create(ctx, withAttribution(configv1alpha1.OwnerAttribution{
					NamespaceLabels: []string{key},
				}))).To(Succeed())
			},
			Entry("a name only", ownerKey),
			Entry("capitals, dots, dashes and underscores in the name", "Team.Name_1-a"),
			Entry("a prefix", "kubernetes.io/metadata.name"),
		)

		DescribeTable("refuses an allowlist that",
			func(attribution configv1alpha1.OwnerAttribution, field string) {
				Expect(k8sClient.Create(ctx, withAttribution(attribution))).To(refusedWith(field))
			},
			Entry("lists a key twice",
				configv1alpha1.OwnerAttribution{NamespaceLabels: []string{ownerKey, ownerKey}}, "Duplicate value"),
			Entry("holds 17 keys",
				configv1alpha1.OwnerAttribution{NamespaceLabels: keysNamed(17)},
				"spec.ownerAttribution.namespaceLabels: Too many"),
			Entry("holds 17 annotation keys",
				configv1alpha1.OwnerAttribution{NamespaceAnnotations: keysNamed(17)},
				"spec.ownerAttribution.namespaceAnnotations: Too many"),
			Entry("holds 17 workload label keys",
				configv1alpha1.OwnerAttribution{WorkloadLabels: keysNamed(17)},
				"spec.ownerAttribution.workloadLabels: Too many"),
		)

		It("accepts 16 keys in each allowlist, and the longest key of 317 characters", func() {
			Expect(k8sClient.Create(ctx, withAttribution(configv1alpha1.OwnerAttribution{
				NamespaceLabels:      keysNamed(16),
				NamespaceAnnotations: keysNamed(16),
				WorkloadLabels:       append(keysNamed(15), longestPrefix+"/"+strings.Repeat("b", 63)),
			}))).To(Succeed())
		})
	})

	Describe("urgency", func() {
		withOverrides := func(overrides ...configv1alpha1.UrgencyOverride) *configv1alpha1.OperatorConfig {
			return configWith(configv1alpha1.OperatorConfigSpec{Urgency: &configv1alpha1.Urgency{Overrides: overrides}})
		}

		// override returns an override of SSVC's table: the outcome for one combination of its four
		// inputs.
		override := func(exploitation, exposure, automatable, humanImpact, outcome string) configv1alpha1.UrgencyOverride {
			return configv1alpha1.UrgencyOverride{
				Exploitation: configv1alpha1.SSVCExploitation(exploitation),
				Exposure:     configv1alpha1.SSVCExposure(exposure),
				Automatable:  configv1alpha1.SSVCAutomatable(automatable),
				HumanImpact:  configv1alpha1.SSVCHumanImpact(humanImpact),
				Outcome:      configv1alpha1.SSVCOutcome(outcome),
			}
		}

		It("keeps the overrides", func() {
			overrides := []configv1alpha1.UrgencyOverride{
				override("None", "Small", "No", "Low", "Defer"),
				override("Active", "Open", "Yes", "VeryHigh", "Immediate"),
			}
			Expect(k8sClient.Create(ctx, withOverrides(overrides...))).To(Succeed())

			var got configv1alpha1.OperatorConfig
			Expect(k8sClient.Get(ctx, singleton, &got)).To(Succeed())
			Expect(got.Spec.Urgency.Overrides).To(Equal(overrides))
		})

		// The names are the contract, so the spec spells each value out.
		It("accepts every value of the five enums", func() {
			Expect(k8sClient.Create(ctx, withOverrides(
				override("None", "Small", "No", "Low", "Defer"),
				override("PublicPoC", "Controlled", "Yes", "Medium", "Scheduled"),
				override("Active", "Open", "No", "High", "OutOfCycle"),
				override("None", "Small", "Yes", "VeryHigh", "Immediate"),
			))).To(Succeed())
		})

		It("refuses an override that repeats the four keys of another", func() {
			err := k8sClient.Create(ctx, withOverrides(
				override("Active", "Open", "Yes", "High", "Immediate"),
				override("Active", "Open", "Yes", "High", "Defer"),
			))

			Expect(err).To(refusedWith("Duplicate value"))
		})

		It("accepts overrides that differ in any one of the four keys", func() {
			Expect(k8sClient.Create(ctx, withOverrides(
				override("Active", "Open", "Yes", "High", "Immediate"),
				override("None", "Open", "Yes", "High", "Immediate"),
				override("Active", "Small", "Yes", "High", "Immediate"),
				override("Active", "Open", "No", "High", "Immediate"),
				override("Active", "Open", "Yes", "Low", "Immediate"),
			))).To(Succeed())
		})

		// The exposure of a report can be Unknown, when no exposure collector has said. An override
		// states a decision for a known exposure, and Unknown counts as Open anyway.
		It("refuses the exposure Unknown, which reports use", func() {
			err := k8sClient.Create(ctx, withOverrides(override("Active", "Unknown", "Yes", "High", "Immediate")))

			Expect(err).To(refusedWith("spec.urgency.overrides[0].exposure"))
		})

		DescribeTable("refuses a value of an enum that no version knows, in",
			func(change func(*configv1alpha1.UrgencyOverride), field string) {
				o := override("Active", "Open", "Yes", "High", "Immediate")
				change(&o)

				Expect(k8sClient.Create(ctx, withOverrides(o))).To(refusedWith(field))
			},
			Entry("the exploitation",
				func(o *configv1alpha1.UrgencyOverride) { o.Exploitation = "Maybe" }, "overrides[0].exploitation"),
			Entry("the exposure",
				func(o *configv1alpha1.UrgencyOverride) { o.Exposure = "Closed" }, "overrides[0].exposure"),
			Entry("the automatable",
				func(o *configv1alpha1.UrgencyOverride) { o.Automatable = "Maybe" }, "overrides[0].automatable"),
			Entry("the human impact",
				func(o *configv1alpha1.UrgencyOverride) { o.HumanImpact = "Very High" }, "overrides[0].humanImpact"),
			Entry("the outcome",
				func(o *configv1alpha1.UrgencyOverride) { o.Outcome = "Out-of-cycle" }, "overrides[0].outcome"),
		)

		DescribeTable("refuses an override that lacks",
			func(field string) {
				o := map[string]any{
					"exploitation": "Active", exposureName: "Open", "automatable": "Yes", "humanImpact": "High",
					outcomeField: "Immediate",
				}
				delete(o, field)
				spec := map[string]any{"urgency": map[string]any{overridesField: []any{o}}}
				obj := rawObject("OperatorConfig", singleton.Name, spec)

				Expect(k8sClient.Create(ctx, obj)).To(refusedWith("spec.urgency.overrides[0]." + field + ": Required value"))
			},
			Entry("an exploitation", "exploitation"),
			Entry("an exposure", exposureName),
			Entry("an automatable", "automatable"),
			Entry("a human impact", "humanImpact"),
			Entry("an outcome", outcomeField),
		)

		// SSVC's table has 3 values of exploitation, 3 of exposure, 2 of automatable and 4 of human
		// impact, so 72 combinations. The most that an admin can override is all of them.
		It("accepts an override for every one of the 72 combinations of the four inputs", func() {
			overrides := make([]configv1alpha1.UrgencyOverride, 0, 72)
			for _, exploitation := range []string{"None", "PublicPoC", "Active"} {
				for _, exposure := range []string{"Small", "Controlled", "Open"} {
					for _, automatable := range []string{"No", "Yes"} {
						for _, humanImpact := range []string{"Low", "Medium", "High", "VeryHigh"} {
							overrides = append(overrides, override(exploitation, exposure, automatable, humanImpact, "Scheduled"))
						}
					}
				}
			}
			Expect(overrides).To(HaveLen(72))

			Expect(k8sClient.Create(ctx, withOverrides(overrides...))).To(Succeed())
		})
	})
})

// keysNamed returns n different keys that are qualified names.
func keysNamed(n int) []string {
	keys := make([]string, n)
	for i := range keys {
		keys[i] = "example.com/key" + strings.Repeat("x", i)
	}
	return keys
}
