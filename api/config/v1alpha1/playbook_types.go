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

// PlaybookSource says where the subjects of a playbook come from: the evidence of one type, from every
// Collector that produces it, or from the Collectors that it pins. Each subject of that evidence is
// assessed.
type PlaybookSource struct {
	// type is the type of the evidence, named in reverse-DNS with a version, such as
	// ch.bedag.vexplain.presence.v1alpha1. The playbook reads only the identifiers of its subjects
	// from it.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9-]+(\.[a-z0-9-]+)+\.v[0-9]+((alpha|beta)[0-9]+)?$`
	Type string `json:"type,omitempty"`
	// collectors pins the producers of the subjects, by the names of their Collectors: each must exist
	// and declare the type for the playbook to be Ready. Empty means every Collector that produces the type. The
	// evidence of the subjects doesn't record which Collector reported a subject, as presence doesn't, so
	// the playbook assesses every subject of the type all the same: more than the pinned Collectors
	// report, which costs work, and settles nothing that the evidence of each subject doesn't.
	// +optional
	// +listType=set
	// +kubebuilder:validation:MaxItems=8
	// +kubebuilder:validation:items:MinLength=1
	// +kubebuilder:validation:items:MaxLength=63
	// +kubebuilder:validation:items:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Collectors []string `json:"collectors,omitempty"`
}

// PlaybookFindings says where the findings of a playbook come from: every Collector that produces the
// type of its findings, or the Collectors that it pins. The API server gives an empty one the default type.
//
// A findings producer takes part in the playbook only when it consumes some of the playbook's evidence:
// one that consumes none, as a checker of its own subjects, has nothing to add to the playbook, and is
// left out of it. Each one that takes part matches the evidence of each producer of what it consumes, and
// a match needs all of it: while any is missing, the subject has no verdict, since findings that only the
// missing evidence would show would get no statement.
// +kubebuilder:validation:MinProperties=1
type PlaybookFindings struct {
	// type is the type of the findings, named in reverse-DNS with a version. It defaults to the core's
	// type of findings, ch.bedag.vexplain.findings.v1alpha1: vulnerabilities in packages.
	// +optional
	// +kubebuilder:default=ch.bedag.vexplain.findings.v1alpha1
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9-]+(\.[a-z0-9-]+)+\.v[0-9]+((alpha|beta)[0-9]+)?$`
	Type *string `json:"type,omitempty"`
	// collectors pins the producers of the findings, by the names of their Collectors: each must exist
	// and declare the type for the playbook to be Ready. Empty means every Collector that produces the
	// type. The findings of several producers about one vulnerability in one package are one finding.
	// +optional
	// +listType=set
	// +kubebuilder:validation:MaxItems=8
	// +kubebuilder:validation:items:MinLength=1
	// +kubebuilder:validation:items:MaxLength=63
	// +kubebuilder:validation:items:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Collectors []string `json:"collectors,omitempty"`
}

// EvidenceRequirement says whether a playbook needs a piece of evidence to run. More values may follow.
// +kubebuilder:validation:Enum=Required;Optional
type EvidenceRequirement string

const (
	// EvidenceRequired means that the playbook isn't Ready without a producer of the evidence.
	EvidenceRequired EvidenceRequirement = "Required"
	// EvidenceOptional means that the playbook runs without the evidence, as a pod runs without a
	// ConfigMap that it refers to with optional: true. Its rules see the evidence as missing where it is.
	EvidenceOptional EvidenceRequirement = "Optional"
)

// PlaybookEvidence is evidence that a playbook gathers for each subject: one type, under a name that the
// rules of the pipeline use for their inputs, from every Collector that produces the type, or from the
// Collectors that it pins. It covers the subject itself and the workloads that run it, as presence links
// them.
//
// The evidence of each producer is evaluated apart, and the most cautious outcome wins, as it does between
// rules (decision 0043): the pipeline runs once for each combination of the producers of the evidence that
// its rules read, at most 4. With more, every finding is held open, unevaluated. vexplain asks each
// producer that can be asked for its own evidence of each subject, also of a type that only the rules
// read, and asks it again only when its evidence is missing or stale.
type PlaybookEvidence struct {
	// name is what the rules of the pipeline call the evidence. It is a CEL identifier, because a
	// rule reads each of its inputs as a variable of that name.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z][a-zA-Z0-9]{0,62}$`
	Name string `json:"name,omitempty"`
	// type is the type of the evidence, named in reverse-DNS with a version, such as
	// ch.bedag.vexplain.scanner.image-contents.v1alpha1.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9-]+(\.[a-z0-9-]+)+\.v[0-9]+((alpha|beta)[0-9]+)?$`
	Type string `json:"type,omitempty"`
	// collectors pins the producers of the evidence, by the names of their Collectors. Empty means every
	// Collector that produces the type. The evidence of a pinned Collector that doesn't exist, or doesn't
	// produce the type, is missing.
	// +optional
	// +listType=set
	// +kubebuilder:validation:MaxItems=8
	// +kubebuilder:validation:items:MinLength=1
	// +kubebuilder:validation:items:MaxLength=63
	// +kubebuilder:validation:items:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Collectors []string `json:"collectors,omitempty"`
	// requirement says whether the playbook needs the evidence: Required, the default, or Optional.
	// Required evidence without a producer, or with a pinned Collector that is missing or doesn't declare
	// the type, keeps the playbook from being Ready, and optional evidence never does. The rules see
	// evidence that is missing as missing either way: a rule that settles a finding doesn't apply, a rule that
	// holds it keeps it open, and a rule's Evaluated condition counts the finding only where required
	// evidence is missing.
	// +optional
	// +kubebuilder:default=Required
	Requirement *EvidenceRequirement `json:"requirement,omitempty"`
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

// PlaybookSpec describes one use case: the types of its subjects, findings and evidence, and the rules
// that settle each finding. Every Collector that produces a type counts, unless an entry pins its
// producers.
type PlaybookSpec struct {
	// subjects say where the subjects of the playbook come from: a type. Each subject of that evidence
	// is assessed.
	// +required
	Subjects PlaybookSource `json:"subjects,omitzero"`
	// findings say where the findings of the playbook come from: a type, which defaults to the core's
	// type of findings.
	// +required
	Findings PlaybookFindings `json:"findings,omitzero"`
	// evidence is the evidence that the playbook gathers for each subject, each piece with a name and a
	// type. The rules of the pipeline get the evidence under the names of their inputs. A playbook whose
	// rules need none has none.
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
	// The Ready condition says whether the playbook can be used. It is True with reason Valid when its
	// subjects, its findings and each piece of required evidence have a producer, each Collector that they
	// pin exists and declares the type, and every step's rule exists, is Ready, and gets the inputs that
	// it needs, under the names that it uses. A producer is a Collector whose capabilities, as it last
	// recorded them, declare the type, and that isn't being deleted. Its health plays no part: it only
	// decides whether the Collector is asked for work, and the playbook goes on with the stored evidence
	// and the other producers. It is False with one of these reasons otherwise, and a message that names what is at fault: CollectorMissing,
	// TypeNotProduced, RuleMissing, RuleNotReady, InputMissing, and Conflict for the newer of two
	// playbooks whose subjects are of the same type, whatever Collectors produce them.
	// Reconciling and Stalled are present only while True, and give the reason and message of Ready,
	// so that kstatus can tell a playbook in progress from one that is stuck. Stalled comes with every
	// reason of False, since each needs a change of the playbook or of what it names. Valid has
	// neither, and no reason has Reconciling.
	// +listType=map
	// +listMapKey=type
	// +kubebuilder:validation:MaxItems=8
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
	// observedGeneration is the generation of the Playbook that the operator last acted on.
	// +optional
	// +kubebuilder:validation:Minimum=0
	ObservedGeneration *int64 `json:"observedGeneration,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories=vexplain
// +kubebuilder:validation:XValidation:rule="size(self.metadata.name) <= 63 && self.metadata.name.matches('^[a-z0-9]([-a-z0-9]*[a-z0-9])?$')",message="a Playbook is named with a DNS-1123 label, which is at most 63 characters and has no dots"
// +kubebuilder:printcolumn:name="Subjects",type=string,JSONPath=`.spec.subjects.type`,priority=1
// +kubebuilder:printcolumn:name="Findings",type=string,JSONPath=`.spec.findings.type`,priority=1
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Reason",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].reason`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// Playbook describes one use case, as a Composition describes one in Crossplane: the types of its
// subjects, findings and evidence, and the pipeline of Rules that settle each finding. The hub's admins
// write playbooks. They live at the hub, because each subject gets one verdict across all clusters.
//
// A playbook names types, not collectors (decision 0043): every Collector that produces a type counts,
// unless an entry pins its producers, so a second producer of a type needs no change of the playbook.
// Installing a collector means trusting it. A second playbook whose subjects are of the same type,
// whatever collectors produce them, isn't Ready, so that each subject keeps one verdict.
//
// A playbook is named with a DNS-1123 label of at most 63 characters, so that its name fits into the
// names of the objects that hold its results.
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
