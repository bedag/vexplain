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

// OwnerAttribution holds the allowlists of owner attribution: the keys of the labels and annotations
// that the operator copies from namespaces and workloads, so that whoever acts on a finding knows whom
// to inform. The allowlists are empty by default, so nothing is copied unless an admin names a key.
// Owner data is copied and never interpreted. Annotations can hold contact data such as e-mail
// addresses: they are copied only when allowlisted, and they never reach the language model.
type OwnerAttribution struct {
	// namespaceLabels are the keys of the namespace labels to copy.
	// +optional
	// +listType=set
	// +kubebuilder:validation:MaxItems=16
	// +kubebuilder:validation:items:MinLength=1
	// +kubebuilder:validation:items:MaxLength=317
	// +kubebuilder:validation:items:Pattern=`^([a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*/)?[A-Za-z0-9]([-A-Za-z0-9_.]*[A-Za-z0-9])?$`
	NamespaceLabels []string `json:"namespaceLabels,omitempty"`
	// namespaceAnnotations are the keys of the namespace annotations to copy.
	// +optional
	// +listType=set
	// +kubebuilder:validation:MaxItems=16
	// +kubebuilder:validation:items:MinLength=1
	// +kubebuilder:validation:items:MaxLength=317
	// +kubebuilder:validation:items:Pattern=`^([a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*/)?[A-Za-z0-9]([-A-Za-z0-9_.]*[A-Za-z0-9])?$`
	NamespaceAnnotations []string `json:"namespaceAnnotations,omitempty"`
	// workloadLabels are the keys of the workload labels to copy.
	// +optional
	// +listType=set
	// +kubebuilder:validation:MaxItems=16
	// +kubebuilder:validation:items:MinLength=1
	// +kubebuilder:validation:items:MaxLength=317
	// +kubebuilder:validation:items:Pattern=`^([a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*/)?[A-Za-z0-9]([-A-Za-z0-9_.]*[A-Za-z0-9])?$`
	WorkloadLabels []string `json:"workloadLabels,omitempty"`
}

// SSVCExploitation is the state of exploitation of a vulnerability, the first input of SSVC's deployer
// tree. Open enum; more values may follow.
// +kubebuilder:validation:Enum=None;PublicPoC;Active
type SSVCExploitation string

const (
	// SSVCExploitationNone means there is no sign that the vulnerability is exploited, and no public
	// proof of concept.
	SSVCExploitationNone SSVCExploitation = "None"
	// SSVCExploitationPublicPoC means a proof of concept is public.
	SSVCExploitationPublicPoC SSVCExploitation = "PublicPoC"
	// SSVCExploitationActive means the vulnerability is exploited, as when it is on CISA's catalog of
	// known exploited vulnerabilities.
	SSVCExploitationActive SSVCExploitation = "Active"
)

// SSVCExposure is how far a workload can be reached, the second input of SSVC's deployer tree. Open
// enum; more values may follow. The type holds the values of the table and Unknown, which a report
// shows, so each field that takes it lists the values that it accepts: an override of the table
// accepts the first three.
type SSVCExposure string

const (
	// SSVCExposureSmall means the workload is reachable only from its own namespace.
	SSVCExposureSmall SSVCExposure = "Small"
	// SSVCExposureControlled means the workload is reachable indirectly, one hop behind an exposed
	// workload, or from beyond its namespace.
	SSVCExposureControlled SSVCExposure = "Controlled"
	// SSVCExposureOpen means the workload is exposed externally.
	SSVCExposureOpen SSVCExposure = "Open"
	// SSVCExposureUnknown means no exposure is known, as when no collector has reported any. A report
	// shows it, and urgency counts it as Open, so that an unknown exposure errs towards urgency. An
	// override of the table can't name it.
	SSVCExposureUnknown SSVCExposure = "Unknown"
)

// SSVCAutomatable says whether an attack on the vulnerability can be automated, the third input of
// SSVC's deployer tree. Open enum; more values may follow.
// +kubebuilder:validation:Enum=No;Yes
type SSVCAutomatable string

const (
	// SSVCAutomatableNo means an attack can't be automated.
	SSVCAutomatableNo SSVCAutomatable = "No"
	// SSVCAutomatableYes means an attack can be automated.
	SSVCAutomatableYes SSVCAutomatable = "Yes"
)

// SSVCHumanImpact is how much harm a successful attack does to people, the fourth input of SSVC's
// deployer tree. Open enum; more values may follow.
// +kubebuilder:validation:Enum=Low;Medium;High;VeryHigh
type SSVCHumanImpact string

const (
	// SSVCHumanImpactLow is the lowest human impact.
	SSVCHumanImpactLow SSVCHumanImpact = "Low"
	// SSVCHumanImpactMedium is the human impact above low.
	SSVCHumanImpactMedium SSVCHumanImpact = "Medium"
	// SSVCHumanImpactHigh is the human impact above medium.
	SSVCHumanImpactHigh SSVCHumanImpact = "High"
	// SSVCHumanImpactVeryHigh is the highest human impact.
	SSVCHumanImpactVeryHigh SSVCHumanImpact = "VeryHigh"
)

// SSVCOutcome is the action that SSVC's deployer tree ends in, the urgency of an update. Open enum;
// more values may follow.
// +kubebuilder:validation:Enum=Defer;Scheduled;OutOfCycle;Immediate
type SSVCOutcome string

const (
	// SSVCOutcomeDefer means no action for now.
	SSVCOutcomeDefer SSVCOutcome = "Defer"
	// SSVCOutcomeScheduled means the action goes into regular maintenance.
	SSVCOutcomeScheduled SSVCOutcome = "Scheduled"
	// SSVCOutcomeOutOfCycle means the action comes faster than usual.
	SSVCOutcomeOutOfCycle SSVCOutcome = "OutOfCycle"
	// SSVCOutcomeImmediate means the action comes first, before anything else.
	SSVCOutcomeImmediate SSVCOutcome = "Immediate"
)

// UrgencyOverride replaces the outcome of SSVC's deployer table for one combination of its four
// inputs.
type UrgencyOverride struct {
	// exploitation is the state of exploitation that the override is for. More values may follow.
	// +required
	Exploitation SSVCExploitation `json:"exploitation,omitempty"`
	// exposure is the exposure that the override is for: Small, Controlled or Open. Unknown, which a
	// report shows when no exposure is known, is refused here, because urgency counts an unknown
	// exposure as Open, and an override for Open covers it. More values may follow.
	// +required
	// +kubebuilder:validation:Enum=Small;Controlled;Open
	Exposure SSVCExposure `json:"exposure,omitempty"`
	// automatable is whether an attack can be automated, which the override is for. More values may
	// follow.
	// +required
	Automatable SSVCAutomatable `json:"automatable,omitempty"`
	// humanImpact is the human impact that the override is for. More values may follow.
	// +required
	HumanImpact SSVCHumanImpact `json:"humanImpact,omitempty"`
	// outcome is the urgency that replaces the table's, for a finding with these four inputs. More
	// values may follow.
	// +required
	Outcome SSVCOutcome `json:"outcome,omitempty"`
}

// Urgency holds the changes that an admin makes to the table that decides the urgency of an update.
// The table is SSVC's published deployer table, which applies wherever an admin changes nothing.
type Urgency struct {
	// overrides replace the outcome of the table for the combinations of inputs that they name. Each
	// combination of the four inputs can be overridden once, and there are 72 of them.
	// +optional
	// +listType=map
	// +listMapKey=exploitation
	// +listMapKey=exposure
	// +listMapKey=automatable
	// +listMapKey=humanImpact
	// +kubebuilder:validation:MaxItems=72
	Overrides []UrgencyOverride `json:"overrides,omitempty"`
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
	// ownerAttribution holds the allowlists of the labels and annotations that the operator copies to
	// say whom to inform about a workload. When it is absent, nothing is copied.
	// +optional
	OwnerAttribution *OwnerAttribution `json:"ownerAttribution,omitempty"`
	// urgency holds the changes to the table that decides the urgency of an update. When it is
	// absent, SSVC's published deployer table applies unchanged.
	// +optional
	Urgency *Urgency `json:"urgency,omitempty"`
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
