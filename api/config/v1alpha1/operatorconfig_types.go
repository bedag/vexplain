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

// Scope selects which pods are analysed. An include selector that is absent or empty
// matches everything. Exclude selectors must not be empty: an empty selector would
// match everything and silently exclude the whole cluster.
// +kubebuilder:validation:XValidation:rule="!has(self.excludeNamespaces) || (has(self.excludeNamespaces.matchLabels) && size(self.excludeNamespaces.matchLabels) > 0) || (has(self.excludeNamespaces.matchExpressions) && size(self.excludeNamespaces.matchExpressions) > 0)",message="excludeNamespaces must not be empty"
// +kubebuilder:validation:XValidation:rule="!has(self.excludePods) || (has(self.excludePods.matchLabels) && size(self.excludePods.matchLabels) > 0) || (has(self.excludePods.matchExpressions) && size(self.excludePods.matchExpressions) > 0)",message="excludePods must not be empty"
type Scope struct {
	// includeNamespaces limits the analysis to the namespaces whose labels match.
	// When it is absent or empty, every namespace is included.
	// +optional
	IncludeNamespaces *metav1.LabelSelector `json:"includeNamespaces,omitempty"`
	// excludeNamespaces removes the namespaces whose labels match, even when
	// includeNamespaces selects them. It must not be empty: an empty selector would match
	// every namespace and so exclude the whole cluster.
	// +optional
	ExcludeNamespaces *metav1.LabelSelector `json:"excludeNamespaces,omitempty"`
	// includePods limits the analysis to the pods whose labels match.
	// When it is absent or empty, every pod is included.
	// +optional
	IncludePods *metav1.LabelSelector `json:"includePods,omitempty"`
	// excludePods removes the pods whose labels match, even when includePods selects them.
	// It must not be empty: an empty selector would match every pod and so exclude the
	// whole cluster.
	// +optional
	ExcludePods *metav1.LabelSelector `json:"excludePods,omitempty"`
}

// Rules holds the settings of the hub's rules.
type Rules struct {
	// minCompletenessPercent is the share of an image's ELF files that packages must account for
	// before any rule may settle a finding in it as not affected. Below it, the completeness guard
	// blocks every such rule. It defaults to 90.
	// +optional
	// +kubebuilder:default=90
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=100
	MinCompletenessPercent *int32 `json:"minCompletenessPercent,omitempty"`
}

// OperatorConfigSpec defines the desired state of OperatorConfig.
// Every field is optional, so an empty spec gives a working base setup.
type OperatorConfigSpec struct {
	// clusterName names this cluster in metrics and in inventory entries.
	// It defaults to local.
	// +optional
	// +kubebuilder:default=local
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`
	ClusterName *string `json:"clusterName,omitempty"`
	// scope limits which pods are analysed. When it is absent, every pod is analysed.
	// +optional
	Scope *Scope `json:"scope,omitempty"`
	// rules holds the settings of the hub's rules. When it is absent, the rules use their defaults.
	// +optional
	Rules *Rules `json:"rules,omitempty"`
}

// OperatorConfigStatus defines the observed state of OperatorConfig.
type OperatorConfigStatus struct {
	// conditions represent the current state of the OperatorConfig.
	// The Ready condition says whether the operator accepted the configuration. It is True with
	// reason Valid, or False with reason Invalid and a message that names the field at fault.
	// +listType=map
	// +listMapKey=type
	// +kubebuilder:validation:MaxItems=8
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Cluster",type=string,JSONPath=`.spec.clusterName`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:validation:XValidation:rule="self.metadata.name == 'default'",message="OperatorConfig is a singleton named 'default'"

// OperatorConfig configures the operator. It is a cluster-scoped singleton named default.
// When it is absent, the operator uses the same defaults as for an empty spec.
type OperatorConfig struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of OperatorConfig
	// +required
	Spec OperatorConfigSpec `json:"spec"`

	// status defines the observed state of OperatorConfig
	// +optional
	Status OperatorConfigStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// OperatorConfigList contains a list of OperatorConfig
type OperatorConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []OperatorConfig `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &OperatorConfig{}, &OperatorConfigList{})
		return nil
	})
}
