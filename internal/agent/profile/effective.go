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

// Package profile resolves an AgentProfile into what a case runs with: its limits with their defaults, its guidance,
// its tool grants and its model, and checks that the limits fit the model's context window (decision 0055).
package profile

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/agent/prompt"
)

// DefaultName is the name of the profile that the operator creates at start, and of the ModelConfig that it uses.
const DefaultName = "default"

// SearchedToolsTokens is what the fit check sets aside for the definitions of the tools that a search loads.
const SearchedToolsTokens = 4000

// The defaults of the limits. They must equal the defaults of spec.limits in the CRD schema, which the API server
// applies; these serve an object that it didn't default, such as one of a fake client.
const (
	defaultMaxSteps            = 15
	defaultMaxTokens           = 300000
	defaultTimeoutSeconds      = 900
	defaultToolTimeoutSeconds  = 120
	defaultReservedTokens      = 4000
	defaultToolResultMaxTokens = 4000
	defaultCaseFileMaxTokens   = 16000
)

// Limits are a profile's limits on one case, with the defaults of the absent ones filled in. Their units are those of
// the AgentProfile's fields.
type Limits struct {
	MaxSteps            int
	MaxTokens           int
	TimeoutSeconds      int
	ToolTimeoutSeconds  int
	ReservedTokens      int
	ToolResultMaxTokens int
	CaseFileMaxTokens   int
}

// Effective is what a case runs with.
type Effective struct {
	// Name is the name of the AgentProfile.
	Name string
	// Limits are the profile's limits, with their defaults.
	Limits Limits
	// Guidance is the text of the guidance, GuidanceSHA256 its SHA-256 in hex, and GuidanceResourceVersion the
	// resourceVersion of the ConfigMap that held it, empty for the embedded text. A case records them.
	Guidance                string
	GuidanceSHA256          string
	GuidanceResourceVersion string
	// Tools are the profile's grants of collectors' tools, besides the core tools.
	Tools []configv1alpha1.AgentToolGrant
	// Model is the ModelConfig that the profile names. Whether its endpoint answers is its own Ready condition, which
	// the caller checks: a profile doesn't hold it.
	Model configv1alpha1.ModelConfig
	// WorstCaseContextTokens is the most tokens that one request of a case could hold under the limits.
	WorstCaseContextTokens int64
}

// Problem is why a case can't run with a profile: the reason and the message of the profile's Ready condition.
type Problem struct {
	Reason  string
	Message string
}

func (p *Problem) Error() string { return p.Message }

// Resolve returns what a case runs with under the AgentProfile named name. It returns an error when the profile isn't
// Ready for its current generation, and when Load does, so that a case never runs on a profile that the operator
// hasn't accepted. namespace is the operator's, where the ConfigMap of a guidance must be.
func Resolve(ctx context.Context, c client.Reader, namespace, name string) (Effective, error) {
	var p configv1alpha1.AgentProfile
	if err := c.Get(ctx, client.ObjectKey{Name: name}, &p); err != nil {
		return Effective{}, fmt.Errorf("read the AgentProfile %q: %w", name, err)
	}
	ready := meta.FindStatusCondition(p.Status.Conditions, configv1alpha1.ConditionReady)
	if ready == nil || ready.Status != metav1.ConditionTrue || ready.ObservedGeneration != p.Generation {
		return Effective{}, fmt.Errorf("the AgentProfile %q is not Ready", name)
	}
	return Load(ctx, c, namespace, &p)
}

// Load resolves p, whatever its status says, and checks that a case can run with it. A *Problem error says why one
// can't, with the reason of the profile's Ready condition. Other errors are failures to read, which say nothing about
// the profile.
//
// On a Problem it returns only the worst case, when the guidance could be read, so that the status can show it, and
// nothing that a case could run with: no guidance stands in for one that is missing.
func Load(ctx context.Context, c client.Reader, namespace string, p *configv1alpha1.AgentProfile) (Effective, error) {
	limits := LimitsOf(p.Spec.Limits)
	text, resourceVersion, err := GuidanceOf(ctx, c, namespace, p.Spec.Guidance)
	if err != nil {
		return Effective{}, err
	}
	worst := worstCase(limits, text)
	var model configv1alpha1.ModelConfig
	name := p.Spec.ModelRef.Name
	if err := c.Get(ctx, client.ObjectKey{Name: name}, &model); err != nil {
		if apierrors.IsNotFound(err) {
			return Effective{WorstCaseContextTokens: worst}, &Problem{Reason: configv1alpha1.ReasonModelConfigMissing,
				Message: fmt.Sprintf("the ModelConfig %q does not exist", name)}
		}
		return Effective{}, fmt.Errorf("read the ModelConfig %q: %w", name, err)
	}
	window := model.Spec.ContextWindowTokens
	if window == nil {
		return Effective{WorstCaseContextTokens: worst}, &Problem{Reason: configv1alpha1.ReasonContextWindowUnknown,
			Message: fmt.Sprintf("the ModelConfig %q states no contextWindowTokens, so whether the limits fit the model "+
				"is unknown; the worst case is %d tokens", name, worst)}
	}
	if worst > int64(*window) {
		return Effective{WorstCaseContextTokens: worst}, &Problem{Reason: configv1alpha1.ReasonExceedsContextWindow,
			Message: fmt.Sprintf("the worst case of the limits, %d tokens, is above the contextWindowTokens of the "+
				"ModelConfig %q, %d", worst, name, *window)}
	}
	sum := sha256.Sum256([]byte(text))
	return Effective{
		Name:                    p.Name,
		Limits:                  limits,
		Guidance:                text,
		GuidanceSHA256:          hex.EncodeToString(sum[:]),
		GuidanceResourceVersion: resourceVersion,
		Tools:                   p.Spec.Tools,
		Model:                   model,
		WorstCaseContextTokens:  worst,
	}, nil
}

// investigationGuidanceAtCap stands for the longest guidance that an investigation may give a case.
var investigationGuidanceAtCap = strings.Repeat("x", prompt.InvestigationGuidanceMaxBytes)

// LimitsOf returns l with the defaults of its absent fields.
func LimitsOf(l *configv1alpha1.AgentLimits) Limits {
	if l == nil {
		l = &configv1alpha1.AgentLimits{}
	}
	return Limits{
		MaxSteps:            int(ptr.Deref(l.MaxSteps, defaultMaxSteps)),
		MaxTokens:           int(ptr.Deref(l.MaxTokens, defaultMaxTokens)),
		TimeoutSeconds:      int(ptr.Deref(l.TimeoutSeconds, defaultTimeoutSeconds)),
		ToolTimeoutSeconds:  int(ptr.Deref(l.ToolTimeoutSeconds, defaultToolTimeoutSeconds)),
		ReservedTokens:      int(ptr.Deref(l.ReservedTokens, defaultReservedTokens)),
		ToolResultMaxTokens: int(ptr.Deref(l.ToolResultMaxTokens, defaultToolResultMaxTokens)),
		CaseFileMaxTokens:   int(ptr.Deref(l.CaseFileMaxTokens, defaultCaseFileMaxTokens)),
	}
}

// worstCase is the fit check's left side: the system prompt, with an investigation's guidance at its cap, the case file
// at its cap, the core tools, the tools that a search loads, maxSteps tool results at their cap and as many answers of
// the model at the most that a step may write, and the reserve.
func worstCase(l Limits, guidance string) int64 {
	return int64(prompt.EstimateTokens(prompt.System(guidance, investigationGuidanceAtCap))) +
		int64(l.CaseFileMaxTokens) + prompt.CoreToolSchemaTokens + SearchedToolsTokens +
		int64(l.MaxSteps)*int64(l.ToolResultMaxTokens+prompt.StepMaxTokens) + int64(l.ReservedTokens)
}

// GuidanceOf returns the text of g, and the resourceVersion of the ConfigMap that holds it, empty for the embedded
// text. An absent g is the embedded text, as the CRD's default says. The ConfigMap is read from namespace alone, so a
// cluster-scoped profile never reaches into another namespace.
func GuidanceOf(ctx context.Context, c client.Reader, namespace string, g *configv1alpha1.AgentGuidance) (
	text, resourceVersion string, err error) {
	if g == nil {
		return prompt.Guidance(), "", nil
	}
	switch g.Type {
	case configv1alpha1.AgentGuidanceEmbedded:
		return prompt.Guidance(), "", nil
	case configv1alpha1.AgentGuidanceConfigMap:
	default:
		// The CRD's enum stops it at admission: one gets here when a newer CRD admitted a type that this older
		// operator doesn't know.
		return "", "", &Problem{Reason: configv1alpha1.ReasonUnknownValue,
			Message: fmt.Sprintf("spec.guidance.type: %q is not a type that this version of the operator knows", g.Type)}
	}
	ref := g.ConfigMapRef
	if ref == nil {
		// The CRD's rule requires it with the type ConfigMap. An object that skipped the schema can lack it.
		return "", "", &Problem{Reason: configv1alpha1.ReasonGuidanceMissing,
			Message: "spec.guidance.configMapRef is not set"}
	}
	key := client.ObjectKey{Namespace: namespace, Name: ref.Name}
	var configMap corev1.ConfigMap
	if err := c.Get(ctx, key, &configMap); err != nil {
		if apierrors.IsNotFound(err) {
			return "", "", &Problem{Reason: configv1alpha1.ReasonGuidanceMissing,
				Message: fmt.Sprintf("the ConfigMap %s of the guidance does not exist", key)}
		}
		return "", "", fmt.Errorf("read the ConfigMap %s of the guidance: %w", key, err)
	}
	text = configMap.Data[ref.Key]
	if strings.TrimSpace(text) == "" {
		return "", "", &Problem{Reason: configv1alpha1.ReasonGuidanceMissing,
			Message: fmt.Sprintf("the ConfigMap %s of the guidance holds no text under the key %q", key, ref.Key)}
	}
	return text, configMap.ResourceVersion, nil
}
