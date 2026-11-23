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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/agent/profile"
)

// agentProfile returns an AgentProfile named name that uses the ModelConfig model, with spec as it is otherwise.
func agentProfile(name, model string, spec configv1alpha1.AgentProfileSpec) *configv1alpha1.AgentProfile {
	spec.ModelRef = configv1alpha1.ModelConfigReference{Name: model}
	return &configv1alpha1.AgentProfile{ObjectMeta: metav1.ObjectMeta{Name: name}, Spec: spec}
}

// These specs check the schema of the AgentProfile, and the fields that the ModelConfig and the OperatorConfig gain
// with it: the model's context window and the agent's switch.
var _ = Describe("AgentProfile API", func() {
	Describe("the limits", func() {
		It("default to the plan's values, and the guidance to the embedded text", func() {
			obj := agentProfile(apiName("defaults"), profile.DefaultName, configv1alpha1.AgentProfileSpec{})
			createObject(obj)

			var got configv1alpha1.AgentProfile
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(obj), &got)).To(Succeed())
			Expect(got.Spec.Guidance).To(Equal(&configv1alpha1.AgentGuidance{Type: configv1alpha1.AgentGuidanceEmbedded}))
			Expect(got.Spec.Limits).To(Equal(&configv1alpha1.AgentLimits{
				MaxSteps:            ptr.To[int32](15),
				MaxTokens:           ptr.To[int32](300000),
				TimeoutSeconds:      ptr.To[int32](900),
				ToolTimeoutSeconds:  ptr.To[int32](120),
				ReservedTokens:      ptr.To[int32](4000),
				ToolResultMaxTokens: ptr.To[int32](4000),
				CaseFileMaxTokens:   ptr.To[int32](16000),
			}))
		})

		// limits returns limits with every field at the end of its range that end names.
		limits := func(least bool) *configv1alpha1.AgentLimits {
			pick := func(low, high int32) *int32 {
				if least {
					return ptr.To(low)
				}
				return ptr.To(high)
			}
			return &configv1alpha1.AgentLimits{
				MaxSteps:            pick(1, 50),
				MaxTokens:           pick(1000, 10000000),
				TimeoutSeconds:      pick(30, 7200),
				ToolTimeoutSeconds:  pick(1, 1800),
				ReservedTokens:      pick(0, 32768),
				ToolResultMaxTokens: pick(256, 32768),
				CaseFileMaxTokens:   pick(1000, 131072),
			}
		}

		DescribeTable("hold every limit at the ends of its range",
			func(least bool) {
				createObject(agentProfile(apiName("range"), profile.DefaultName, configv1alpha1.AgentProfileSpec{Limits: limits(least)}))
			},
			Entry("the least", true),
			Entry("the most", false),
		)

		DescribeTable("refuse a limit outside its range",
			func(field string, change func(*configv1alpha1.AgentLimits)) {
				l := limits(true)
				change(l)
				obj := agentProfile(apiName("outside"), profile.DefaultName, configv1alpha1.AgentProfileSpec{Limits: l})
				Expect(k8sClient.Create(ctx, obj)).To(refusedWith("spec.limits." + field))
			},
			Entry("maxSteps below", "maxSteps", func(l *configv1alpha1.AgentLimits) { l.MaxSteps = ptr.To[int32](0) }),
			Entry("maxSteps above", "maxSteps", func(l *configv1alpha1.AgentLimits) { l.MaxSteps = ptr.To[int32](51) }),
			Entry("maxTokens below", "maxTokens", func(l *configv1alpha1.AgentLimits) { l.MaxTokens = ptr.To[int32](999) }),
			Entry("maxTokens above", "maxTokens", func(l *configv1alpha1.AgentLimits) { l.MaxTokens = ptr.To[int32](10000001) }),
			Entry("timeoutSeconds below", "timeoutSeconds", func(l *configv1alpha1.AgentLimits) { l.TimeoutSeconds = ptr.To[int32](29) }),
			Entry("timeoutSeconds above", "timeoutSeconds", func(l *configv1alpha1.AgentLimits) { l.TimeoutSeconds = ptr.To[int32](7201) }),
			Entry("toolTimeoutSeconds below", "toolTimeoutSeconds",
				func(l *configv1alpha1.AgentLimits) { l.ToolTimeoutSeconds = ptr.To[int32](0) }),
			Entry("toolTimeoutSeconds above", "toolTimeoutSeconds",
				func(l *configv1alpha1.AgentLimits) { l.ToolTimeoutSeconds = ptr.To[int32](1801) }),
			Entry("reservedTokens below", "reservedTokens", func(l *configv1alpha1.AgentLimits) { l.ReservedTokens = ptr.To[int32](-1) }),
			Entry("reservedTokens above", "reservedTokens",
				func(l *configv1alpha1.AgentLimits) { l.ReservedTokens = ptr.To[int32](32769) }),
			Entry("toolResultMaxTokens below", "toolResultMaxTokens",
				func(l *configv1alpha1.AgentLimits) { l.ToolResultMaxTokens = ptr.To[int32](255) }),
			Entry("toolResultMaxTokens above", "toolResultMaxTokens",
				func(l *configv1alpha1.AgentLimits) { l.ToolResultMaxTokens = ptr.To[int32](32769) }),
			Entry("caseFileMaxTokens below", "caseFileMaxTokens",
				func(l *configv1alpha1.AgentLimits) { l.CaseFileMaxTokens = ptr.To[int32](999) }),
			Entry("caseFileMaxTokens above", "caseFileMaxTokens",
				func(l *configv1alpha1.AgentLimits) { l.CaseFileMaxTokens = ptr.To[int32](131073) }),
		)
	})

	Describe("the guidance", func() {
		ref := &configv1alpha1.ConfigMapKeyRef{Name: "agent-guidance", Key: "guidance.md"}

		It("takes a ConfigMap with its reference", func() {
			createObject(agentProfile(apiName("configmap"), profile.DefaultName, configv1alpha1.AgentProfileSpec{
				Guidance: &configv1alpha1.AgentGuidance{Type: configv1alpha1.AgentGuidanceConfigMap, ConfigMapRef: ref}}))
		})

		DescribeTable("refuses a reference that doesn't go with the type",
			func(guidance *configv1alpha1.AgentGuidance) {
				obj := agentProfile(apiName("union"), profile.DefaultName, configv1alpha1.AgentProfileSpec{Guidance: guidance})
				Expect(k8sClient.Create(ctx, obj)).To(refusedWith("configMapRef is set exactly when type is ConfigMap"))
			},
			Entry("a ConfigMap without a reference", &configv1alpha1.AgentGuidance{Type: configv1alpha1.AgentGuidanceConfigMap}),
			Entry("the embedded text with a reference",
				&configv1alpha1.AgentGuidance{Type: configv1alpha1.AgentGuidanceEmbedded, ConfigMapRef: ref}),
		)
	})

	Describe("the tools", func() {
		It("keeps the grants, with and without operations", func() {
			tools := []configv1alpha1.AgentToolGrant{
				{Collector: "vulnerabilities", Operations: []string{"describe"}},
				{Collector: networkReachName},
			}
			obj := agentProfile(apiName("tools"), profile.DefaultName, configv1alpha1.AgentProfileSpec{Tools: tools})
			createObject(obj)

			var got configv1alpha1.AgentProfile
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(obj), &got)).To(Succeed())
			Expect(got.Spec.Tools).To(Equal(tools))
		})

		It("refuses a grant without a collector", func() {
			obj := rawObject("AgentProfile", apiName("grant"), map[string]any{
				"modelRef": map[string]any{nameField: profile.DefaultName},
				"tools":    []any{map[string]any{}},
			})
			Expect(k8sClient.Create(ctx, obj)).To(refusedWith("spec.tools[0].collector"))
		})
	})

	It("refuses a profile without a model", func() {
		obj := rawObject("AgentProfile", apiName("model"), map[string]any{})
		Expect(k8sClient.Create(ctx, obj)).To(refusedWith("spec.modelRef"))
	})

	// The sample is what an admin copies, and it shows the profile that the operator creates.
	It("accepts the sample", func() {
		data, err := os.ReadFile(filepath.Join("..", "..", "..", "config", "samples", "config_v1alpha1_agentprofile.yaml"))
		Expect(err).NotTo(HaveOccurred())
		sample := &configv1alpha1.AgentProfile{}
		Expect(yaml.UnmarshalStrict(data, sample)).To(Succeed())
		Expect(sample.Name).To(Equal(profile.DefaultName))
		Expect(sample.Spec.ModelRef.Name).To(Equal(profile.DefaultName))

		// The operator has created its own profile named default.
		sample.Name = apiName("sample")
		Expect(k8sClient.Create(ctx, sample, client.DryRunAll)).To(Succeed())
	})

	Describe("the model's context window", func() {
		withWindow := func(tokens int32) *configv1alpha1.ModelConfig {
			obj := newModelConfig(apiName("window"), listedModel, "window")
			obj.Spec.ContextWindowTokens = ptr.To(tokens)
			return obj
		}

		DescribeTable("holds a window from 1024 to 10000000 tokens",
			func(tokens int32) { Expect(k8sClient.Create(ctx, withWindow(tokens), client.DryRunAll)).To(Succeed()) },
			Entry("the least", int32(1024)),
			Entry("the most", int32(10000000)),
		)

		DescribeTable("refuses a window outside it",
			func(tokens int32) {
				Expect(k8sClient.Create(ctx, withWindow(tokens), client.DryRunAll)).To(refusedWith("spec.contextWindowTokens"))
			},
			Entry("one below", int32(1023)),
			Entry("one above", int32(10000001)),
		)

		It("is optional, with no default", func() {
			obj := newModelConfig(apiName("window"), listedModel, "window")
			Expect(k8sClient.Create(ctx, obj, client.DryRunAll)).To(Succeed())
			Expect(obj.Spec.ContextWindowTokens).To(BeNil())
		})
	})
})
