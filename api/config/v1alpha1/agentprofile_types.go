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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// ModelConfigReference names a ModelConfig.
type ModelConfigReference struct {
	// name is the name of the ModelConfig.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
	Name string `json:"name,omitempty"`
}

// ConfigMapKeyRef points to one key of a ConfigMap in the operator's namespace. The config kinds are
// cluster-scoped, so the namespace is not part of the reference: it is always the operator's.
type ConfigMapKeyRef struct {
	// name is the name of the ConfigMap.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
	Name string `json:"name,omitempty"`
	// key is the key of the ConfigMap's data that holds the text.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[-._a-zA-Z0-9]+$`
	Key string `json:"key,omitempty"`
}

// AgentGuidanceType says where the editable guidance of an AgentProfile comes from. Open enum; more values may follow,
// such as Inline.
// +kubebuilder:validation:Enum=Embedded;ConfigMap
type AgentGuidanceType string

const (
	// AgentGuidanceEmbedded is the guidance that the operator ships in its binary.
	AgentGuidanceEmbedded AgentGuidanceType = "Embedded"
	// AgentGuidanceConfigMap is the text under a key of a ConfigMap in the operator's namespace.
	AgentGuidanceConfigMap AgentGuidanceType = "ConfigMap"
)

// AgentGuidance says where the editable part of the agent's prompt comes from. The guidance follows the core prompt,
// which the operator owns, and can't replace it.
// +kubebuilder:validation:XValidation:rule="has(self.configMapRef) == (self.type == 'ConfigMap')",message="configMapRef is set exactly when type is ConfigMap"
type AgentGuidance struct {
	// type is where the guidance comes from: Embedded, the text that the operator ships, or ConfigMap, the text that
	// configMapRef names. More values may follow.
	// +required
	Type AgentGuidanceType `json:"type,omitempty"`
	// configMapRef names the ConfigMap in the operator's namespace, and the key of its data, that hold the guidance.
	// It is set exactly when type is ConfigMap. A ConfigMap that is missing, or holds no text under the key, makes the
	// profile Ready=False: the operator never falls back to the embedded text.
	// +optional
	ConfigMapRef *ConfigMapKeyRef `json:"configMapRef,omitempty"`
}

// AgentLimits bound the agent's work on one case. Tokens are estimated as bytes / 4.
type AgentLimits struct {
	// maxSteps is the most model calls with tools that a case takes. It defaults to 15.
	// +optional
	// +kubebuilder:default=15
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=50
	MaxSteps *int32 `json:"maxSteps,omitempty"`
	// maxTokens is the most tokens that a case spends, prompt and completion of every request together, as the
	// endpoint reports them. It defaults to 300000.
	// +optional
	// +kubebuilder:default=300000
	// +kubebuilder:validation:Minimum=1000
	// +kubebuilder:validation:Maximum=10000000
	MaxTokens *int32 `json:"maxTokens,omitempty"`
	// timeoutSeconds bounds a whole case, in seconds. It defaults to 900.
	// +optional
	// +kubebuilder:default=900
	// +kubebuilder:validation:Minimum=30
	// +kubebuilder:validation:Maximum=7200
	TimeoutSeconds *int32 `json:"timeoutSeconds,omitempty"`
	// toolTimeoutSeconds bounds each tool call, in seconds. It defaults to 120.
	// +optional
	// +kubebuilder:default=120
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=1800
	ToolTimeoutSeconds *int32 `json:"toolTimeoutSeconds,omitempty"`
	// reservedTokens is the budget kept for the one call without tools that asks for the summary of a case that hit a
	// limit. It defaults to 4000.
	// +optional
	// +kubebuilder:default=4000
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=32768
	ReservedTokens *int32 `json:"reservedTokens,omitempty"`
	// toolResultMaxTokens is the most of a tool result that the model sees. The whole result goes into the ledger, and
	// the model reads on through read_evidence. It defaults to 4000.
	// +optional
	// +kubebuilder:default=4000
	// +kubebuilder:validation:Minimum=256
	// +kubebuilder:validation:Maximum=32768
	ToolResultMaxTokens *int32 `json:"toolResultMaxTokens,omitempty"`
	// caseFileMaxTokens is the most of the case file that the first request carries. It defaults to 16000.
	// +optional
	// +kubebuilder:default=16000
	// +kubebuilder:validation:Minimum=1000
	// +kubebuilder:validation:Maximum=131072
	CaseFileMaxTokens *int32 `json:"caseFileMaxTokens,omitempty"`
}

// AgentToolGrant lets the agent use tools of one collector.
type AgentToolGrant struct {
	// collector is the name of the Collector whose tools the agent may use.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Collector string `json:"collector,omitempty"`
	// operations are the operations of the collector that the agent may use. When it is absent or empty, the agent may
	// use every operation that a collector of a package runs in the hub's role, or every tool on the list of an MCP
	// collector.
	// +optional
	// +listType=set
	// +kubebuilder:validation:MaxItems=64
	// +kubebuilder:validation:items:MinLength=1
	// +kubebuilder:validation:items:MaxLength=63
	Operations []string `json:"operations,omitempty"`
}

// AgentProfileSpec holds what the agent works with: the model, the guidance, the limits and the tools.
type AgentProfileSpec struct {
	// modelRef names the ModelConfig of the model that the agent uses.
	// +required
	ModelRef ModelConfigReference `json:"modelRef,omitzero"`
	// guidance says where the editable part of the prompt comes from. It defaults to the embedded text.
	// +optional
	// +kubebuilder:default={type: Embedded}
	Guidance *AgentGuidance `json:"guidance,omitempty"`
	// limits bound the agent's work on one case. Each limit that is absent takes its default.
	// +optional
	// +kubebuilder:default={}
	Limits *AgentLimits `json:"limits,omitempty"`
	// tools are the collectors whose tools the agent may use, each named once, besides vexplain's core tools, which
	// it always has. When it is absent, the agent has the core tools only.
	// +optional
	// +listType=map
	// +listMapKey=collector
	// +kubebuilder:validation:MaxItems=32
	Tools []AgentToolGrant `json:"tools,omitempty"`
}

// AgentProfileStatus says whether the profile can be used.
type AgentProfileStatus struct {
	// conditions represent the current state of the AgentProfile.
	// The Ready condition says whether a case can run with the profile. It is True with reason Valid. It is False
	// with reason GuidanceMissing when the ConfigMap of the guidance doesn't exist in the operator's namespace or holds
	// no text under the key, ModelConfigMissing when the ModelConfig that modelRef names doesn't exist,
	// ContextWindowUnknown when that ModelConfig states no contextWindowTokens, ExceedsContextWindow when
	// worstCaseContextTokens is above it, and UnknownValue when the type of the guidance is one that this version of
	// the operator doesn't know. Whether the model's endpoint answers is the ModelConfig's own Ready condition.
	// Reconciling and Stalled are present only while True, and give the reason and message of Ready, so that kstatus
	// can tell a profile in progress from one that is stuck. Every reason of Ready False comes with Stalled: each needs
	// a change of the profile, of its ModelConfig or of its ConfigMap.
	// +optional
	// +listType=map
	// +listMapKey=type
	// +kubebuilder:validation:MaxItems=8
	Conditions []metav1.Condition `json:"conditions,omitempty"`
	// observedGeneration is the generation of the AgentProfile that the operator last acted on.
	// +optional
	// +kubebuilder:validation:Minimum=0
	ObservedGeneration *int64 `json:"observedGeneration,omitempty"`
	// worstCaseContextTokens is the most tokens that one request of a case could hold under the limits: the core
	// prompt, the guidance, the case file at its cap, the core tools, 4000 for tools that a search loads, maxSteps tool
	// results at their cap, and the reserved tokens. The profile is Ready only when it is at most the model's
	// contextWindowTokens. It is absent while the guidance can't be read.
	// +optional
	// +kubebuilder:validation:Minimum=0
	WorstCaseContextTokens *int64 `json:"worstCaseContextTokens,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories=vexplain
// +kubebuilder:printcolumn:name="Model",type=string,JSONPath=`.spec.modelRef.name`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Reason",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].reason`
// +kubebuilder:printcolumn:name="Worst case",type=integer,JSONPath=`.status.worstCaseContextTokens`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// AgentProfile holds what the agent works with: the model it uses, the editable guidance of its prompt, its limits on
// one case and the tools it may use. It is cluster-scoped and lives on the hub. The operator creates the profile named
// default at start when it is missing, and never changes one that exists.
//
// The operator reports in the status whether the limits fit the model's context window.
type AgentProfile struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines what the agent works with
	// +required
	Spec AgentProfileSpec `json:"spec"`

	// status defines the observed state of AgentProfile
	// +optional
	Status AgentProfileStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// AgentProfileList contains a list of AgentProfile
type AgentProfileList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []AgentProfile `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &AgentProfile{}, &AgentProfileList{})
		return nil
	})
}
