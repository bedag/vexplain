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

// PlaybookSource says where the subjects of a playbook come from: the evidence of one type that one
// Collector delivers. Each subject of that evidence is assessed.
type PlaybookSource struct {
	// collector is the name of the Collector that delivers the evidence.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Collector string `json:"collector,omitempty"`
	// type is the type of the evidence, named in reverse-DNS with a version, such as
	// ch.bedag.vexplain.presence.v1alpha1. The playbook reads only the identifiers of its subjects
	// from it.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9-]+(\.[a-z0-9-]+)+\.v[0-9]+((alpha|beta)[0-9]+)?$`
	Type string `json:"type,omitempty"`
}

// PlaybookFindings says where the findings of a playbook come from: a Collector that produces the
// findings type, ch.bedag.vexplain.findings.v1alpha1.
type PlaybookFindings struct {
	// collector is the name of the Collector that produces the findings.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Collector string `json:"collector,omitempty"`
}

// PlaybookEvidence is evidence that a playbook gathers for each subject: one type from one Collector,
// under a name that the rules of the pipeline use for their inputs. It covers the subject itself and
// the workloads that run it, as presence links them.
type PlaybookEvidence struct {
	// name is what the rules of the pipeline call the evidence. It is a CEL identifier, because a
	// rule reads each of its inputs as a variable of that name.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z][a-zA-Z0-9]{0,62}$`
	Name string `json:"name,omitempty"`
	// collector is the name of the Collector that delivers the evidence.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Collector string `json:"collector,omitempty"`
	// type is the type of the evidence, named in reverse-DNS with a version, such as
	// ch.bedag.vexplain.scanner.image-contents.v1alpha1.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9-]+(\.[a-z0-9-]+)+\.v[0-9]+((alpha|beta)[0-9]+)?$`
	Type string `json:"type,omitempty"`
}

// PlaybookStep is one step of the pipeline of a playbook.
type PlaybookStep struct {
	// rule is the name of the Rule that the step runs.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Rule string `json:"rule,omitempty"`
}

// PlaybookSpec describes one use case: where its subjects and findings come from, what evidence it
// gathers, and the rules that settle each finding.
type PlaybookSpec struct {
	// subjects say where the subjects of the playbook come from: a Collector and a type. Each subject
	// of that evidence is assessed.
	// +required
	Subjects PlaybookSource `json:"subjects,omitzero"`
	// findings say where the findings of the playbook come from: a Collector that produces the
	// findings type.
	// +required
	Findings PlaybookFindings `json:"findings,omitzero"`
	// evidence is the evidence that the playbook gathers for each subject, each piece with a name, a
	// Collector and a type. The rules of the pipeline get the evidence under the names of their
	// inputs. A playbook whose rules need none has none.
	// +optional
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:MaxItems=16
	Evidence []PlaybookEvidence `json:"evidence,omitempty"`
	// pipeline is the steps of the playbook, each of which references a Rule. When several steps
	// apply to one finding, the most cautious status wins, so the order of the steps doesn't change
	// the result.
	// +required
	// +listType=atomic
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=32
	Pipeline []PlaybookStep `json:"pipeline,omitempty"`
}

// PlaybookStatus is what the operator found when it checked the playbook.
type PlaybookStatus struct {
	// conditions represent the current state of the Playbook.
	// The Ready condition says whether the playbook can be used. It is True with reason Valid when the
	// Collectors that it names exist and produce the types that it asks of them, and every step's
	// rule exists, is Ready, and gets the inputs that it needs, under the names that it uses. It is
	// False with one of these reasons otherwise, and a message that names what is at fault:
	// CollectorMissing, TypeNotProduced, RuleMissing, RuleNotReady, InputMissing, and Conflict for
	// the newer of two playbooks that take the same subjects.
	// +listType=map
	// +listMapKey=type
	// +kubebuilder:validation:MaxItems=8
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Subjects",type=string,JSONPath=`.spec.subjects.collector`
// +kubebuilder:printcolumn:name="Findings",type=string,JSONPath=`.spec.findings.collector`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Reason",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].reason`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// Playbook describes one use case, as a Composition describes one in Crossplane: where its subjects
// and findings come from, what evidence it gathers, and the pipeline of Rules that settle each
// finding. The hub's admins write playbooks. They live at the hub, because each subject gets one
// verdict across all clusters.
//
// A playbook uses only the collectors that it names, so no separate policy decides which collectors
// count. A second playbook with the same subjects, the same collector and type, isn't Ready, so that
// each subject keeps one verdict.
type Playbook struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the use case: its subjects, findings, evidence and pipeline
	// +required
	Spec PlaybookSpec `json:"spec"`

	// status defines the observed state of Playbook
	// +optional
	Status PlaybookStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// PlaybookList contains a list of Playbook
type PlaybookList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []Playbook `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &Playbook{}, &PlaybookList{})
		return nil
	})
}
