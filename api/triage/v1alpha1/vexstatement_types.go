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

// The condition of a VexStatement besides kstatus's three, and the reasons of its conditions and of an Assessment's.
const (
	// ConditionSuperseded is True when a VexStatement no longer stands: its case's inputs changed since, or its
	// Assessment holds another verdict, or none. A statement that is superseded settles nothing.
	ConditionSuperseded = "Superseded"
	// ReasonStale says that what a verdict rests on changed since: the case's findings or the data of its case file.
	ReasonStale = "Stale"
	// ReasonCurrent says that a VexStatement stands on its case's current inputs and on its Assessment's verdict.
	ReasonCurrent = "Current"
)

// ReviewState is where a person's review of a VexStatement stands. Open enum; more values may follow.
// +kubebuilder:validation:Enum=Proposed;Accepted;Rejected
type ReviewState string

const (
	// ReviewStateProposed means no person has reviewed the statement yet: it settles nothing.
	ReviewStateProposed ReviewState = "Proposed"
	// ReviewStateAccepted means a person accepted the statement: while it stands, it settles its findings.
	ReviewStateAccepted ReviewState = "Accepted"
	// ReviewStateRejected means a person rejected the statement: it settles nothing.
	ReviewStateRejected ReviewState = "Rejected"
)

// StatementOrigin says who made a VexStatement. Open enum; more values may follow.
// +kubebuilder:validation:Enum=Agent
type StatementOrigin string

const (
	// StatementOriginAgent is the agent, whose verdict on a case the hub proposed as the statement.
	StatementOriginAgent StatementOrigin = "Agent"
)

// AssessmentReference names the Assessment of a case.
type AssessmentReference struct {
	// name is the name of the Assessment.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name,omitempty"`
}

// VexStatementReview is a person's review of a statement. Who reviewed it is in the API server's audit log.
// +kubebuilder:validation:XValidation:rule="!has(self.state) || self.state == 'Proposed' || has(self.comment)",message="a review that accepts or rejects a statement says why in its comment"
type VexStatementReview struct {
	// state is where the review stands: Proposed until a person accepts or rejects the statement. More values may
	// follow.
	// +optional
	// +kubebuilder:default=Proposed
	State *ReviewState `json:"state,omitempty"`
	// comment says why the reviewer accepted or rejected the statement.
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=2048
	Comment *string `json:"comment,omitempty"`
}

// VexStatementSpec is the statement, which never changes, and its review, which reviewers edit.
// +kubebuilder:validation:XValidation:rule="self.status == 'NotAffected' || self.status == 'Fixed'",message="a VexStatement states NotAffected or Fixed"
// +kubebuilder:validation:XValidation:rule="has(self.justification) == (self.status == 'NotAffected')",message="justification is set exactly when status is NotAffected"
// +kubebuilder:validation:XValidation:rule="self.subject == oldSelf.subject && self.vulnerabilityID == oldSelf.vulnerabilityID && self.status == oldSelf.status && has(self.justification) == has(oldSelf.justification) && (!has(self.justification) || self.justification == oldSelf.justification) && self.origin == oldSelf.origin && self.assessmentRef == oldSelf.assessmentRef && self.inputHash == oldSelf.inputHash",message="only the review of a VexStatement can change: another statement is another VexStatement"
type VexStatementSpec struct {
	// subject is the subject of the case.
	// +required
	Subject AssessmentSubject `json:"subject,omitzero"`
	// vulnerabilityID is the ID of the vulnerability, as the subject's findings name it.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=64
	VulnerabilityID string `json:"vulnerabilityID,omitempty"`
	// status is what the statement says of every finding of the vulnerability in the subject: NotAffected or Fixed. More
	// values may follow.
	// +required
	Status VEXStatus `json:"status,omitempty"`
	// justification says why the case is NotAffected. It is set exactly then.
	// +optional
	Justification *VEXJustification `json:"justification,omitempty"`
	// origin says who made the statement: Agent. More values may follow.
	// +required
	Origin StatementOrigin `json:"origin,omitempty"`
	// assessmentRef names the Assessment whose verdict the statement is.
	// +required
	AssessmentRef AssessmentReference `json:"assessmentRef,omitzero"`
	// inputHash is the inputHash of the Assessment's verdict: what it rests on. Once the case's inputs differ, the
	// statement is superseded.
	// +required
	// +kubebuilder:validation:MinLength=71
	// +kubebuilder:validation:MaxLength=71
	// +kubebuilder:validation:Pattern=`^sha256:[a-f0-9]{64}$`
	InputHash string `json:"inputHash,omitempty"`
	// review is a person's review of the statement, the one part of it that reviewers edit. It starts Proposed.
	// +optional
	// +kubebuilder:default={}
	Review *VexStatementReview `json:"review,omitempty"`
}

// VexStatementStatus says whether the statement stands.
type VexStatementStatus struct {
	// conditions represent the current state of the VexStatement. Superseded is True once the statement no longer
	// stands, and False while it does. Ready is True while it stands, and False, with the reason Stale, once it is
	// superseded. Reconciling and Stalled are present only while True, and the hub sets neither.
	// +optional
	// +listType=map
	// +listMapKey=type
	// +kubebuilder:validation:MaxItems=8
	Conditions []metav1.Condition `json:"conditions,omitempty"`
	// observedGeneration is the generation of the VexStatement that the hub last acted on.
	// +optional
	// +kubebuilder:validation:Minimum=0
	ObservedGeneration *int64 `json:"observedGeneration,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories=vexplain
// +kubebuilder:printcolumn:name="Vulnerability",type=string,JSONPath=`.spec.vulnerabilityID`
// +kubebuilder:printcolumn:name="Status",type=string,JSONPath=`.spec.status`
// +kubebuilder:printcolumn:name="Review",type=string,JSONPath=`.spec.review.state`
// +kubebuilder:printcolumn:name="Superseded",type=string,JSONPath=`.status.conditions[?(@.type=="Superseded")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// VexStatement is an agent's verdict that would silence a case, NotAffected or Fixed, which a person reviews (design of
// the agent on image cases, 5.10). The hub proposes it, never a person, one for each verdict: it is named after the
// case's Assessment and the verdict (cases.StatementName), and labelled as the Assessment is. Until a person accepts
// it, it settles nothing; once accepted, it settles the case's findings while it stands. It is superseded once the
// case's inputs change, or its Assessment holds another verdict, and stays so, with its review: the hub deletes no
// statement, since reviews can't be rebuilt.
type VexStatement struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec is the statement and its review
	// +required
	Spec VexStatementSpec `json:"spec"`

	// status says whether the statement stands
	// +optional
	Status VexStatementStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// VexStatementList contains a list of VexStatement
type VexStatementList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []VexStatement `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &VexStatement{}, &VexStatementList{})
		return nil
	})
}
