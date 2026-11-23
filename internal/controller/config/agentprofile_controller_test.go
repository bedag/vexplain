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
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	eventsv1 "k8s.io/api/events/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/agent/profile"
	"github.com/bedag/vexplain/internal/agent/prompt"
	configcontroller "github.com/bedag/vexplain/internal/controller/config"
)

// These specs run against the manager that the suite starts through setup.Register, so the controller, its watches
// and the manager's cache of ConfigMaps are the production ones. Each spec names its profile, its ModelConfig and its
// ConfigMap on its own, so no spec sees another's.
var _ = Describe("AgentProfile", func() {
	const (
		timeout  = 30 * time.Second
		interval = 100 * time.Millisecond
		// agentProfileInvalid is the reason of the event that reports a profile that can't be used.
		agentProfileInvalid = "AgentProfileInvalid"
		// guidanceKey is the key of the specs' ConfigMaps that holds the guidance.
		guidanceKey = "guidance.md"
		// fits and tooSmall are context windows that the default limits fit in, and don't.
		fits     = int32(200000)
		tooSmall = int32(50000)
	)

	// createModel creates a ModelConfig with the context window tokens, or none for nil, and returns its name.
	createModel := func(tokens *int32) string {
		GinkgoHelper()
		obj := newModelConfig(apiName("agent-model"), listedModel, "agent-model")
		obj.Spec.ContextWindowTokens = tokens
		createObject(obj)
		return obj.Name
	}

	// expectProfile waits until the controller has set the Ready condition of the profile named name, for its current
	// generation, to status and reason, and returns the profile and the condition. It reads through k8sClient, so it
	// never sees a stale cache.
	expectProfile := func(name string, status metav1.ConditionStatus, reason string) (
		*configv1alpha1.AgentProfile, *metav1.Condition) {
		GinkgoHelper()
		var (
			got   *configv1alpha1.AgentProfile
			ready *metav1.Condition
		)
		Eventually(func(g Gomega) {
			var obj configv1alpha1.AgentProfile
			g.Expect(k8sClient.Get(ctx, client.ObjectKey{Name: name}, &obj)).To(Succeed())
			ready = meta.FindStatusCondition(obj.Status.Conditions, configv1alpha1.ConditionReady)
			g.Expect(ready).NotTo(BeNil())
			g.Expect(ready.ObservedGeneration).To(Equal(obj.Generation))
			g.Expect(ready.Status).To(Equal(status))
			g.Expect(ready.Reason).To(Equal(reason))
			got = &obj
		}, timeout, interval).Should(Succeed())
		return got, ready
	}

	// expectStalled checks that a profile that isn't Ready is Stalled, with the reason of Ready: each reason needs a
	// change of the profile, of its ModelConfig or of its ConfigMap.
	expectStalled := func(obj *configv1alpha1.AgentProfile, reason string) {
		GinkgoHelper()
		stalled := meta.FindStatusCondition(obj.Status.Conditions, configv1alpha1.ConditionStalled)
		Expect(stalled).NotTo(BeNil())
		Expect(stalled.Reason).To(Equal(reason))
		Expect(obj.Status.ObservedGeneration).To(Equal(ptr.To(obj.Generation)))
	}

	// invalidEvents lists the AgentProfileInvalid events about the profile named name. The events API files the events
	// of a cluster-scoped object in the namespace default.
	invalidEvents := func(name string) func(g Gomega) []eventsv1.Event {
		return func(g Gomega) []eventsv1.Event {
			var list eventsv1.EventList
			g.Expect(k8sClient.List(ctx, &list, client.InNamespace(metav1.NamespaceDefault),
				client.MatchingFields{eventRegardingField: name, eventReasonField: agentProfileInvalid})).To(Succeed())
			return list.Items
		}
	}

	// fromConfigMap is the guidance of the ConfigMap named name.
	fromConfigMap := func(name string) *configv1alpha1.AgentGuidance {
		return &configv1alpha1.AgentGuidance{Type: configv1alpha1.AgentGuidanceConfigMap,
			ConfigMapRef: &configv1alpha1.ConfigMapKeyRef{Name: name, Key: guidanceKey}}
	}

	// guidanceConfigMap is a ConfigMap in namespace, named name, that holds text under guidanceKey.
	guidanceConfigMap := func(namespace, name, text string) *corev1.ConfigMap {
		return &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
			Data: map[string]string{guidanceKey: text}}
	}

	It("is created at start as default, with the embedded guidance, and an admin's edits stay", func() {
		key := client.ObjectKey{Name: profile.DefaultName}
		var created configv1alpha1.AgentProfile
		Eventually(func() error { return k8sClient.Get(ctx, key, &created) }, timeout, interval).Should(Succeed())
		Expect(created.Spec.ModelRef.Name).To(Equal(profile.DefaultName))
		Expect(created.Spec.Guidance).To(Equal(&configv1alpha1.AgentGuidance{Type: configv1alpha1.AgentGuidanceEmbedded}))
		Expect(created.Spec.Tools).To(Equal([]configv1alpha1.AgentToolGrant{
			{Collector: "vulnerabilities", Operations: []string{"describe"}},
			{Collector: advisoriesName, Operations: []string{"fetch"}}}),
			"describe, without which the agent can never show a fix, and fetch, which reads the advisories it links to")

		By("leaving a default that an admin changed as it is")
		// The controller writes the status of the profile meanwhile, so a write of the spec is tried again on a
		// conflict.
		setMaxSteps := func(n int32) {
			GinkgoHelper()
			Eventually(func() error {
				var changed configv1alpha1.AgentProfile
				if err := k8sClient.Get(ctx, key, &changed); err != nil {
					return err
				}
				changed.Spec.Limits.MaxSteps = ptr.To(n)
				return k8sClient.Update(ctx, &changed)
			}, timeout, interval).Should(Succeed())
		}
		setMaxSteps(20)
		DeferCleanup(func() { setMaxSteps(15) })
		Expect(configcontroller.EnsureDefaultAgentProfile(ctx, k8sClient)).To(Succeed())
		var kept configv1alpha1.AgentProfile
		Expect(k8sClient.Get(ctx, key, &kept)).To(Succeed())
		Expect(kept.Spec.Limits.MaxSteps).To(Equal(ptr.To[int32](20)))

		By("creating it again when it is missing")
		Expect(k8sClient.Delete(ctx, &kept)).To(Succeed())
		Eventually(func() error {
			return configcontroller.EnsureDefaultAgentProfile(ctx, k8sClient)
		}, timeout, interval).Should(Succeed())
		var again configv1alpha1.AgentProfile
		Expect(k8sClient.Get(ctx, key, &again)).To(Succeed())
		Expect(again.Spec.Limits.MaxSteps).To(Equal(ptr.To[int32](15)))
		Expect(again.Spec.Guidance.Type).To(Equal(configv1alpha1.AgentGuidanceEmbedded))
	})

	It("is not Ready, with ContextWindowUnknown, while its model states no context window", func() {
		model := createModel(nil)
		obj := agentProfile(apiName("no-window"), model, configv1alpha1.AgentProfileSpec{})
		createObject(obj)

		got, ready := expectProfile(obj.Name, metav1.ConditionFalse, configv1alpha1.ReasonContextWindowUnknown)
		Expect(ready.Message).To(ContainSubstring(model))
		expectStalled(got, configv1alpha1.ReasonContextWindowUnknown)
		Expect(got.Status.WorstCaseContextTokens).To(HaveValue(BeNumerically(">", 0)),
			"the worst case is known without a window, and tells an admin which window it needs")
	})

	It("is not Ready, with ExceedsContextWindow, over the window, and Ready once the window holds the worst case", func() {
		model := createModel(ptr.To(tooSmall))
		obj := agentProfile(apiName("window"), model, configv1alpha1.AgentProfileSpec{})
		createObject(obj)

		got, ready := expectProfile(obj.Name, metav1.ConditionFalse, configv1alpha1.ReasonExceedsContextWindow)
		expectStalled(got, configv1alpha1.ReasonExceedsContextWindow)
		worst := ptr.Deref(got.Status.WorstCaseContextTokens, 0)
		// The defaults: 16000 for the case file, 15 results of 4000, 4000 reserved and 4000 for the tools that a
		// search loads, besides the prompt and the core tools.
		Expect(worst).To(BeNumerically(">", 16000+15*(4000+4096)+4000+4000))
		Expect(ready.Message).To(ContainSubstring(strconv.FormatInt(worst, 10)))
		Expect(ready.Message).To(ContainSubstring(strconv.Itoa(int(tooSmall))))
		Eventually(invalidEvents(obj.Name), timeout, interval).Should(HaveLen(1))

		By("stating a window that the worst case fits in")
		var m configv1alpha1.ModelConfig
		Expect(k8sClient.Get(ctx, client.ObjectKey{Name: model}, &m)).To(Succeed())
		m.Spec.ContextWindowTokens = ptr.To(fits)
		Expect(k8sClient.Update(ctx, &m)).To(Succeed())

		got, _ = expectProfile(obj.Name, metav1.ConditionTrue, configv1alpha1.ReasonValid)
		Expect(got.Status.WorstCaseContextTokens).To(Equal(ptr.To(worst)))
		Expect(meta.FindStatusCondition(got.Status.Conditions, configv1alpha1.ConditionStalled)).To(BeNil())

		By("resolving the profile with its defaults and the embedded guidance")
		effective, err := profile.Resolve(ctx, k8sClient, operatorNamespace, obj.Name)
		Expect(err).NotTo(HaveOccurred())
		Expect(effective.Limits.MaxSteps).To(Equal(15))
		Expect(effective.Guidance).To(Equal(prompt.Guidance()))
		Expect(effective.GuidanceResourceVersion).To(BeEmpty())
		Expect(effective.Model.Name).To(Equal(model))
		Expect(effective.WorstCaseContextTokens).To(Equal(worst))
	})

	It("is not Ready while its guidance ConfigMap is missing, with no fallback to the embedded text", func() {
		model := createModel(ptr.To(fits))
		name := apiName("guidance")
		obj := agentProfile(apiName("guidance"), model, configv1alpha1.AgentProfileSpec{Guidance: fromConfigMap(name)})
		createObject(obj)

		got, ready := expectProfile(obj.Name, metav1.ConditionFalse, configv1alpha1.ReasonGuidanceMissing)
		Expect(ready.Message).To(ContainSubstring(operatorNamespace + "/" + name))
		expectStalled(got, configv1alpha1.ReasonGuidanceMissing)
		Expect(got.Status.WorstCaseContextTokens).To(BeNil(), "without its guidance the worst case isn't known")

		By("recording an AgentProfileInvalid event")
		Eventually(invalidEvents(obj.Name), timeout, interval).Should(HaveLen(1))
		event := invalidEvents(obj.Name)(Default)[0]
		Expect(event.Type).To(Equal(corev1.EventTypeWarning))
		Expect(event.Note).To(Equal(ready.Message))

		By("refusing to resolve it")
		_, err := profile.Resolve(ctx, k8sClient, operatorNamespace, obj.Name)
		Expect(err).To(HaveOccurred())

		By("taking the ConfigMap's text once it exists")
		const text = "Look at the image's SBOM first."
		configMap := guidanceConfigMap(operatorNamespace, name, text)
		createObject(configMap)
		expectProfile(obj.Name, metav1.ConditionTrue, configv1alpha1.ReasonValid)

		effective, err := profile.Resolve(ctx, k8sClient, operatorNamespace, obj.Name)
		Expect(err).NotTo(HaveOccurred())
		Expect(effective.Guidance).To(Equal(text))
		sum := sha256.Sum256([]byte(text))
		Expect(effective.GuidanceSHA256).To(Equal(hex.EncodeToString(sum[:])))
		Expect(effective.GuidanceResourceVersion).To(Equal(configMap.ResourceVersion))
	})

	It("refuses a ConfigMap outside the operator's namespace", func() {
		model := createModel(ptr.To(fits))
		name := apiName("elsewhere")
		createObject(guidanceConfigMap(metav1.NamespaceDefault, name, "Text from another namespace."))
		obj := agentProfile(apiName("elsewhere"), model, configv1alpha1.AgentProfileSpec{Guidance: fromConfigMap(name)})
		createObject(obj)

		_, ready := expectProfile(obj.Name, metav1.ConditionFalse, configv1alpha1.ReasonGuidanceMissing)
		Expect(ready.Message).To(ContainSubstring(operatorNamespace + "/" + name))
	})

	It("is not Ready while its ModelConfig is missing", func() {
		obj := agentProfile(apiName("no-model"), "no-such-model", configv1alpha1.AgentProfileSpec{})
		createObject(obj)

		got, ready := expectProfile(obj.Name, metav1.ConditionFalse, configv1alpha1.ReasonModelConfigMissing)
		Expect(ready.Message).To(ContainSubstring("no-such-model"))
		expectStalled(got, configv1alpha1.ReasonModelConfigMissing)
	})
})
