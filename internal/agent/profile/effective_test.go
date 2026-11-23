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

package profile_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/agent/profile"
	"github.com/bedag/vexplain/internal/agent/prompt"
)

const (
	namespace = "vexplain-system"
	modelName = "model-a"
	// configMapName is the ConfigMap of the guidance of the specs that read one.
	configMapName = "guidance"
	// configMapKey is the key of that ConfigMap that holds the guidance.
	configMapKey = "text"
)

// model is a ModelConfig named modelName with the context window tokens, or none for nil.
func model(tokens *int32) *configv1alpha1.ModelConfig {
	return &configv1alpha1.ModelConfig{
		ObjectMeta: metav1.ObjectMeta{Name: modelName},
		Spec:       configv1alpha1.ModelConfigSpec{ContextWindowTokens: tokens},
	}
}

// ready is a profile named name that uses modelName, whose status says it is Ready for its generation. A fake client
// applies no defaults of the CRD, so the spec stays as spec says.
func ready(name string, spec configv1alpha1.AgentProfileSpec) *configv1alpha1.AgentProfile {
	spec.ModelRef = configv1alpha1.ModelConfigReference{Name: modelName}
	return &configv1alpha1.AgentProfile{
		ObjectMeta: metav1.ObjectMeta{Name: name, Generation: 2},
		Spec:       spec,
		Status: configv1alpha1.AgentProfileStatus{Conditions: []metav1.Condition{{
			Type: configv1alpha1.ConditionReady, Status: metav1.ConditionTrue, Reason: configv1alpha1.ReasonValid,
			ObservedGeneration: 2,
		}}},
	}
}

// reader is a client that holds objs.
func reader(t *testing.T, objs ...client.Object) client.Reader {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, configv1alpha1.AddToScheme(scheme))
	require.NoError(t, corev1.AddToScheme(scheme))
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
}

// defaultWorstCase is the worst case of the default limits with the embedded guidance.
func defaultWorstCase() int64 { return worstCaseOf(prompt.Guidance()) }

// worstCaseOf is the worst case of the default limits with the profile's guidance: the system prompt with an
// investigation's guidance at its cap, maxSteps results at their cap, and as many answers of the model at the most that
// a step may write.
func worstCaseOf(guidance string) int64 {
	system := prompt.System(guidance, strings.Repeat("x", prompt.InvestigationGuidanceMaxBytes))
	return int64(prompt.EstimateTokens(system)) + 16000 + prompt.CoreToolSchemaTokens + profile.SearchedToolsTokens +
		15*(4000+4096) + 4000
}

func TestResolveAppliesTheDefaultsAndTheEmbeddedGuidance(t *testing.T) {
	c := reader(t, ready(profile.DefaultName, configv1alpha1.AgentProfileSpec{}), model(ptr.To[int32](200000)))

	got, err := profile.Resolve(context.Background(), c, namespace, profile.DefaultName)

	require.NoError(t, err)
	require.Equal(t, profile.Limits{
		MaxSteps: 15, MaxTokens: 300000, TimeoutSeconds: 900, ToolTimeoutSeconds: 120,
		ReservedTokens: 4000, ToolResultMaxTokens: 4000, CaseFileMaxTokens: 16000,
	}, got.Limits)
	require.Equal(t, prompt.Guidance(), got.Guidance)
	sum := sha256.Sum256([]byte(prompt.Guidance()))
	require.Equal(t, hex.EncodeToString(sum[:]), got.GuidanceSHA256)
	require.Empty(t, got.GuidanceResourceVersion)
	require.Equal(t, modelName, got.Model.Name)
	require.Equal(t, defaultWorstCase(), got.WorstCaseContextTokens)
	withoutInvestigation := int64(prompt.EstimateTokens(prompt.System(prompt.Guidance(), ""))) + 16000 +
		prompt.CoreToolSchemaTokens + profile.SearchedToolsTokens + 15*(4000+4096) + 4000
	require.GreaterOrEqual(t, got.WorstCaseContextTokens-withoutInvestigation, int64(1024),
		"an investigation's guidance counts at its cap, 4096 bytes")
}

func TestResolveKeepsTheLimitsAndToolsThatTheProfileSets(t *testing.T) {
	tools := []configv1alpha1.AgentToolGrant{{Collector: "vulnerabilities", Operations: []string{"describe"}}}
	p := ready("small", configv1alpha1.AgentProfileSpec{
		Limits: &configv1alpha1.AgentLimits{MaxSteps: ptr.To[int32](2), ToolResultMaxTokens: ptr.To[int32](1000),
			ReservedTokens: ptr.To[int32](0)},
		Tools: tools,
	})
	c := reader(t, p, model(ptr.To[int32](200000)))

	got, err := profile.Resolve(context.Background(), c, namespace, "small")

	require.NoError(t, err)
	require.Equal(t, 2, got.Limits.MaxSteps)
	require.Equal(t, 1000, got.Limits.ToolResultMaxTokens)
	require.Equal(t, 0, got.Limits.ReservedTokens, "a reserve of 0 is the admin's, not a missing value")
	require.Equal(t, 120, got.Limits.ToolTimeoutSeconds)
	require.Equal(t, tools, got.Tools)
	require.Equal(t, defaultWorstCase()-15*(4000+4096)-4000+2*(1000+4096), got.WorstCaseContextTokens)
}

func TestResolveReadsTheGuidanceFromItsConfigMapInTheOperatorsNamespace(t *testing.T) {
	const text = "Look at the SBOM first."
	p := ready("custom", configv1alpha1.AgentProfileSpec{Guidance: &configv1alpha1.AgentGuidance{
		Type: configv1alpha1.AgentGuidanceConfigMap, ConfigMapRef: &configv1alpha1.ConfigMapKeyRef{Name: configMapName, Key: configMapKey},
	}})
	configMap := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: configMapName},
		Data: map[string]string{configMapKey: text}}
	c := reader(t, p, model(ptr.To[int32](200000)), configMap)

	got, err := profile.Resolve(context.Background(), c, namespace, "custom")

	require.NoError(t, err)
	require.Equal(t, text, got.Guidance)
	require.NotEmpty(t, got.GuidanceResourceVersion)
	require.Equal(t, worstCaseOf(text), got.WorstCaseContextTokens)
}

func TestResolveRefusesAProfileThatIsNotReadyForItsGeneration(t *testing.T) {
	for name, change := range map[string]func(*configv1alpha1.AgentProfile){
		"not Ready":           func(p *configv1alpha1.AgentProfile) { p.Status.Conditions[0].Status = metav1.ConditionFalse },
		"an older Ready":      func(p *configv1alpha1.AgentProfile) { p.Status.Conditions[0].ObservedGeneration = 1 },
		"no condition at all": func(p *configv1alpha1.AgentProfile) { p.Status.Conditions = nil },
	} {
		t.Run(name, func(t *testing.T) {
			p := ready("waiting", configv1alpha1.AgentProfileSpec{})
			change(p)
			_, err := profile.Resolve(context.Background(), reader(t, p, model(ptr.To[int32](200000))), namespace, "waiting")
			require.ErrorContains(t, err, "waiting")
		})
	}
}

// Load is what the controller sets the Ready condition from. Each problem carries the reason of the condition.
func TestLoadNamesWhyAProfileCantBeUsed(t *testing.T) {
	inConfigMap := &configv1alpha1.AgentGuidance{Type: configv1alpha1.AgentGuidanceConfigMap,
		ConfigMapRef: &configv1alpha1.ConfigMapKeyRef{Name: configMapName, Key: configMapKey}}
	tests := map[string]struct {
		spec      configv1alpha1.AgentProfileSpec
		objs      []client.Object
		reason    string
		worstCase bool
		inMessage string
	}{
		"no window": {
			objs: []client.Object{model(nil)}, reason: configv1alpha1.ReasonContextWindowUnknown, worstCase: true,
			inMessage: modelName,
		},
		"a window below the worst case": {
			objs: []client.Object{model(ptr.To[int32](50000))}, reason: configv1alpha1.ReasonExceedsContextWindow,
			worstCase: true, inMessage: "50000",
		},
		"no ModelConfig": {reason: configv1alpha1.ReasonModelConfigMissing, worstCase: true, inMessage: modelName},
		"no ConfigMap": {
			spec: configv1alpha1.AgentProfileSpec{Guidance: inConfigMap},
			objs: []client.Object{model(ptr.To[int32](200000))}, reason: configv1alpha1.ReasonGuidanceMissing,
			inMessage: namespace + "/" + configMapName,
		},
		"a ConfigMap without the key": {
			spec: configv1alpha1.AgentProfileSpec{Guidance: inConfigMap},
			objs: []client.Object{model(ptr.To[int32](200000)), &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: configMapName}, Data: map[string]string{"other": "x"}}},
			reason: configv1alpha1.ReasonGuidanceMissing, inMessage: `"` + configMapKey + `"`,
		},
		"a ConfigMap with only blanks under the key": {
			spec: configv1alpha1.AgentProfileSpec{Guidance: inConfigMap},
			objs: []client.Object{model(ptr.To[int32](200000)), &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: configMapName}, Data: map[string]string{configMapKey: " \n"}}},
			reason: configv1alpha1.ReasonGuidanceMissing, inMessage: `"` + configMapKey + `"`,
		},
		"a ConfigMap of the same name in another namespace": {
			spec: configv1alpha1.AgentProfileSpec{Guidance: inConfigMap},
			objs: []client.Object{model(ptr.To[int32](200000)), &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: configMapName}, Data: map[string]string{configMapKey: "x"}}},
			reason: configv1alpha1.ReasonGuidanceMissing, inMessage: namespace + "/" + configMapName,
		},
		"a type of guidance that this version doesn't know": {
			spec: configv1alpha1.AgentProfileSpec{Guidance: &configv1alpha1.AgentGuidance{Type: "Inline"}},
			objs: []client.Object{model(ptr.To[int32](200000))}, reason: configv1alpha1.ReasonUnknownValue,
			inMessage: "Inline",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			p := ready("broken", tt.spec)

			got, err := profile.Load(context.Background(), reader(t, tt.objs...), namespace, p)

			var problem *profile.Problem
			require.True(t, errors.As(err, &problem), "%v", err)
			require.Equal(t, tt.reason, problem.Reason)
			require.Contains(t, problem.Message, tt.inMessage)
			require.Empty(t, got.Guidance, "a profile that can't be used is never given the embedded text instead")
			if tt.worstCase {
				require.Equal(t, defaultWorstCase(), got.WorstCaseContextTokens)
			} else {
				require.Zero(t, got.WorstCaseContextTokens)
			}
		})
	}
}
