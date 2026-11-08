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
	"k8s.io/utils/ptr"
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
		// collectorsField is the field of the spec that holds the policy on collectors.
		collectorsField = "collectors"
		// secretsResource and verbList are parts of the permission rules of the specs.
		secretsResource = "secrets"
		verbList        = "list"
		verbWatch       = "watch"
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

	Describe("cluster labels and collector permissions", func() {
		denyRule := func(groups, resources, verbs []string) configv1alpha1.PermissionRule {
			return configv1alpha1.PermissionRule{APIGroups: groups, Resources: resources, Verbs: verbs}
		}
		labelsOf := func(n int) map[string]configv1alpha1.LabelValue {
			labels := make(map[string]configv1alpha1.LabelValue, n)
			for _, key := range keysNamed(n) {
				labels[key] = "v"
			}
			return labels
		}
		withLabels := func(labels map[string]configv1alpha1.LabelValue) *configv1alpha1.OperatorConfig {
			return configWith(configv1alpha1.OperatorConfigSpec{ClusterLabels: labels})
		}
		withCollectors := func(c configv1alpha1.CollectorPolicy) *configv1alpha1.OperatorConfig {
			return configWith(configv1alpha1.OperatorConfigSpec{Collectors: &c})
		}

		// denyListSpec is the raw spec of a deny list with rules, which is empty without any.
		denyListSpec := func(rules ...any) map[string]any {
			return map[string]any{collectorsField: map[string]any{"deniedPermissions": append([]any{}, rules...)}}
		}

		It("keeps a full config", func() {
			spec := configv1alpha1.OperatorConfigSpec{
				ClusterLabels: map[string]configv1alpha1.LabelValue{"example.com/env": "prod", "region": "", "tier": "a_b.c-d"},
				Collectors: &configv1alpha1.CollectorPolicy{
					Permissions: ptr.To(configv1alpha1.PermissionsModeCheck),
					DeniedPermissions: []configv1alpha1.PermissionRule{
						denyRule([]string{""}, []string{secretsResource}, []string{verbList, verbWatch}),
						denyRule([]string{"*"}, []string{"*"}, []string{"*"}),
					},
				},
			}
			Expect(k8sClient.Create(ctx, configWith(spec))).To(Succeed())

			var got configv1alpha1.OperatorConfig
			Expect(k8sClient.Get(ctx, singleton, &got)).To(Succeed())
			Expect(got.Spec.ClusterLabels).To(Equal(spec.ClusterLabels))
			Expect(got.Spec.Collectors).To(Equal(spec.Collectors))
		})

		It("is optional", func() {
			Expect(k8sClient.Create(ctx, configWith(configv1alpha1.OperatorConfigSpec{}))).To(Succeed())

			var got configv1alpha1.OperatorConfig
			Expect(k8sClient.Get(ctx, singleton, &got)).To(Succeed())
			Expect(got.Spec.ClusterLabels).To(BeNil())
			Expect(got.Spec.Collectors).To(BeNil())
		})

		It("keeps an empty deny list apart from an absent one", func() {
			spec := denyListSpec()
			Expect(k8sClient.Create(ctx, rawObject("OperatorConfig", singleton.Name, spec))).To(Succeed())

			var got configv1alpha1.OperatorConfig
			Expect(k8sClient.Get(ctx, singleton, &got)).To(Succeed())
			Expect(got.Spec.Collectors).NotTo(BeNil())
			Expect(got.Spec.Collectors.DeniedPermissions).NotTo(BeNil())
			Expect(got.Spec.Collectors.DeniedPermissions).To(BeEmpty())
		})

		It("accepts 32 labels and 32 deny rules", func() {
			rules := make([]configv1alpha1.PermissionRule, 32)
			for i := range rules {
				rules[i] = denyRule([]string{""}, []string{secretsResource}, []string{verbGet})
			}
			spec := configv1alpha1.OperatorConfigSpec{
				ClusterLabels: labelsOf(32), Collectors: &configv1alpha1.CollectorPolicy{DeniedPermissions: rules},
			}
			Expect(k8sClient.Create(ctx, configWith(spec))).To(Succeed())
		})

		It("refuses 33 labels", func() {
			Expect(k8sClient.Create(ctx, withLabels(labelsOf(33)))).To(refusedWith("spec.clusterLabels"))
		})

		It("refuses 33 deny rules", func() {
			rules := make([]configv1alpha1.PermissionRule, 33)
			for i := range rules {
				rules[i] = denyRule([]string{""}, []string{secretsResource}, []string{verbGet})
			}
			err := k8sClient.Create(ctx, withCollectors(configv1alpha1.CollectorPolicy{DeniedPermissions: rules}))

			Expect(err).To(refusedWith("spec.collectors.deniedPermissions: Too many"))
		})

		DescribeTable("refuses a label key that is no label key, with",
			func(key string) {
				err := k8sClient.Create(ctx, withLabels(map[string]configv1alpha1.LabelValue{key: "v"}))

				Expect(err).To(refusedWith("spec.clusterLabels", "every key must be a valid label key"))
			},
			Entry("a space", "env name"),
			Entry("a dash first", "-env"),
			Entry("two slashes", "example.com/a/b"),
			Entry("a capital in the prefix", "Example.com/env"),
			Entry("no name after the prefix", "example.com/"),
			Entry("an empty key", ""),
			Entry("a name of 64 characters", strings.Repeat("a", 64)),
		)

		DescribeTable("refuses a label value that is no label value, with",
			func(value string) {
				err := k8sClient.Create(ctx, withLabels(map[string]configv1alpha1.LabelValue{"env": configv1alpha1.LabelValue(value)}))

				// The schema bounds a value at 63 characters, and a rule checks its form.
				Expect(err).To(refusedWith("spec.clusterLabels"))
			},
			Entry("a space", "a b"),
			Entry("a dash first", "-a"),
			Entry("a dash last", "a-"),
			Entry("64 characters", strings.Repeat("a", 64)),
			Entry("a slash", "a/b"),
		)

		It("refuses an unknown mode", func() {
			err := k8sClient.Create(ctx, withCollectors(configv1alpha1.CollectorPolicy{Permissions: ptr.To(configv1alpha1.PermissionsMode("Allow"))}))

			Expect(err).To(refusedWith("spec.collectors.permissions"))
		})

		DescribeTable("refuses a deny rule that lacks",
			func(field string) {
				rule := map[string]any{"apiGroups": []any{""}, "resources": []any{secretsResource}, "verbs": []any{verbGet}}
				delete(rule, field)
				spec := denyListSpec(rule)

				err := k8sClient.Create(ctx, rawObject("OperatorConfig", singleton.Name, spec))

				Expect(err).To(refusedWith("spec.collectors.deniedPermissions[0]." + field + ": Required value"))
			},
			Entry("api groups", "apiGroups"),
			Entry("resources", "resources"),
			Entry("a verb", "verbs"),
		)

		DescribeTable("refuses a deny rule with an empty list of",
			func(field string) {
				rule := map[string]any{"apiGroups": []any{""}, "resources": []any{secretsResource}, "verbs": []any{verbGet}}
				rule[field] = []any{}
				spec := denyListSpec(rule)

				err := k8sClient.Create(ctx, rawObject("OperatorConfig", singleton.Name, spec))

				Expect(err).To(refusedWith("spec.collectors.deniedPermissions[0]." + field))
			},
			Entry("api groups", "apiGroups"),
			Entry("resources", "resources"),
			Entry("verbs", "verbs"),
		)
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

		// The exposure of a report can be Unknown, when no collector of exposure has said. An override
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
