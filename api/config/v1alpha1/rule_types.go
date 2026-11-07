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

// VEXStatus is what a rule concludes about a finding, in the words of OpenVEX. The API spells them in
// CamelCase, and OpenVEX in lower case with underscores. Open enum; more values may follow.
// +kubebuilder:validation:Enum=Affected;UnderInvestigation;NotAffected;Fixed
type VEXStatus string

const (
	// VEXStatusAffected is OpenVEX's affected: the vulnerability affects the component, and action
	// is needed.
	VEXStatusAffected VEXStatus = "Affected"
	// VEXStatusUnderInvestigation is OpenVEX's under_investigation. A rule that concludes it holds a
	// finding open, so that no rule can settle it as not affected or fixed.
	VEXStatusUnderInvestigation VEXStatus = "UnderInvestigation"
	// VEXStatusNotAffected is OpenVEX's not_affected: the vulnerability doesn't affect the component,
	// for the reason that the justification gives. It settles a finding.
	VEXStatusNotAffected VEXStatus = "NotAffected"
	// VEXStatusFixed is OpenVEX's fixed: a version of the component fixes the vulnerability. It
	// settles a finding.
	VEXStatusFixed VEXStatus = "Fixed"
)

// VEXJustification says why a component is not affected, in the words of OpenVEX, whose five
// justifications these are. The API spells them in CamelCase, and OpenVEX in lower case with
// underscores. Open enum; more values may follow.
// +kubebuilder:validation:Enum=ComponentNotPresent;VulnerableCodeNotPresent;VulnerableCodeNotInExecutePath;VulnerableCodeCannotBeControlledByAdversary;InlineMitigationsAlreadyExist
type VEXJustification string

const (
	// VEXJustificationComponentNotPresent is OpenVEX's component_not_present: the component is not
	// in the artifact.
	VEXJustificationComponentNotPresent VEXJustification = "ComponentNotPresent"
	// VEXJustificationVulnerableCodeNotPresent is OpenVEX's vulnerable_code_not_present: the
	// component is in the artifact, but the vulnerable code is not.
	VEXJustificationVulnerableCodeNotPresent VEXJustification = "VulnerableCodeNotPresent"
	// VEXJustificationVulnerableCodeNotInExecutePath is OpenVEX's vulnerable_code_not_in_execute_path:
	// the vulnerable code is in the artifact, but no execution path reaches it.
	VEXJustificationVulnerableCodeNotInExecutePath VEXJustification = "VulnerableCodeNotInExecutePath"
	// VEXJustificationVulnerableCodeCannotBeControlledByAdversary is OpenVEX's
	// vulnerable_code_cannot_be_controlled_by_adversary: the vulnerable code runs, but an attacker
	// can't control it to exploit the vulnerability.
	VEXJustificationVulnerableCodeCannotBeControlledByAdversary VEXJustification = "VulnerableCodeCannotBeControlledByAdversary"
	// VEXJustificationInlineMitigationsAlreadyExist is OpenVEX's inline_mitigations_already_exist:
	// the artifact has built-in protections that prevent the exploitation of the vulnerability.
	VEXJustificationInlineMitigationsAlreadyExist VEXJustification = "InlineMitigationsAlreadyExist"
)

// RuleInput is evidence that a rule needs: a name, and the type of the evidence.
type RuleInput struct {
	// name is what the CEL of the rule calls the input. It is a CEL identifier, because the rule reads
	// the input as a variable of that name, and the playbook that uses the rule supplies evidence
	// under it.
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
}

// RuleOutcome is what a rule concludes about a finding to which it applies. A rule without a status
// is a hint: it settles nothing, and adds only a status note to the finding, in the words of OpenVEX's
// status_notes.
// +kubebuilder:validation:XValidation:rule="has(self.justification) == (has(self.status) && self.status == 'NotAffected')",message="justification is set exactly when status is NotAffected"
type RuleOutcome struct {
	// status is the OpenVEX status that the rule concludes. Affected and UnderInvestigation hold a
	// finding open: UnderInvestigation says the rule doesn't know, and a finding that a rule holds
	// open can't be settled by any other. NotAffected and Fixed settle a finding, and need strong,
	// specific evidence. Without a status, the rule is a hint. More values may follow.
	// +optional
	Status *VEXStatus `json:"status,omitempty"`
	// justification says why the component is not affected. It is set exactly when status is
	// NotAffected. More values may follow.
	// +optional
	Justification *VEXJustification `json:"justification,omitempty"`
}

// RuleSpec is the decision that a rule makes about one finding, in CEL.
//
// The CEL sees the variable finding, which holds the finding, and one variable for each input, named
// after it, which holds the input's data, coverage, time and source. A rule applies to a finding only
// when every input it names is present.
//
// Each evaluation of an expression has a cost limit of 1,000,000, and the time is bounded as well: a
// rule's run on one finding, its match, its condition and its reason together, may take at most a
// second, and the evaluation of a playbook's rules for one subject at most 30 seconds. A rule whose CEL
// fails, hits the cost limit or runs past a bound can't be evaluated for the finding: a rule that
// settles a finding, with NotAffected or Fixed, then doesn't apply, and one that concludes Affected or
// UnderInvestigation fails closed, so that it keeps the finding open as UnderInvestigation. The operator
// refuses a rule that calls a function whose one call it can't bound, such as sort, distinct or join,
// and the rule isn't Ready.
type RuleSpec struct {
	// inputs are the evidence that the rule needs, each with a name and a type. A playbook that uses
	// the rule supplies evidence under those names.
	// +optional
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:MaxItems=8
	Inputs []RuleInput `json:"inputs,omitempty"`
	// match is CEL that gives true for the findings that the rule applies to. A rule without one
	// applies to every finding. When it fails, the rule can't be evaluated for any finding of the
	// subject.
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=4096
	Match *string `json:"match,omitempty"`
	// condition is CEL over the finding and the inputs that gives true when the rule applies.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=4096
	Condition string `json:"condition,omitempty"`
	// outcome is what the rule concludes when its condition holds. A rule that is a hint writes an
	// empty outcome, outcome: {}, so that leaving the field out is an error and never a hint by
	// accident.
	// +required
	Outcome *RuleOutcome `json:"outcome,omitempty"`
	// reason is CEL that gives the string that is recorded with the outcome, such as the reason of a
	// finding, or the text of the status note of a hint.
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=4096
	Reason *string `json:"reason,omitempty"`
}

// RuleStatus is what the operator found when it checked the rule.
type RuleStatus struct {
	// conditions represent the current state of the Rule.
	// The Ready condition says whether the rule can be used. It is True with reason Valid when its CEL
	// compiles, and False with reason Invalid, and the error as its message, when it doesn't.
	// The Evaluated condition says whether the rule's last evaluations had no errors. It is True with
	// reason NoEvaluationErrors when they had none, and False with reason EvaluationErrors, and the
	// number of findings in its message, while findings can't be evaluated: the CEL failed on them, hit
	// its cost limit or ran past a bound on time, an input was missing, the rule's match failed for a
	// finding of their subject, or a playbook ran the rule while it wasn't Ready.
	// Reconciling and Stalled are present only while True, and give the reason and message of Ready,
	// so that kstatus can tell a rule in progress from one that is stuck. Stalled comes with Invalid,
	// which needs a change of the rule. Valid has neither, and no reason has Reconciling. Evaluated
	// plays no part in them.
	// +listType=map
	// +listMapKey=type
	// +kubebuilder:validation:MaxItems=8
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
	// observedGeneration is the generation of the Rule that the operator last acted on.
	// +optional
	// +kubebuilder:validation:Minimum=0
	ObservedGeneration *int64 `json:"observedGeneration,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories=vexplain
// +kubebuilder:printcolumn:name="Status",type=string,JSONPath=`.spec.outcome.status`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Evaluated",type=string,JSONPath=`.status.conditions[?(@.type=="Evaluated")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// +kubebuilder:validation:XValidation:rule="size(self.metadata.name) <= 63 && self.metadata.name.matches('^[a-z0-9]([-a-z0-9]*[a-z0-9])?$')",message="a Rule is named with a DNS-1123 label, which is at most 63 characters and has no dots"

// Rule is a reusable step that decides about one finding, in CEL. Playbooks reference rules in their
// pipelines, so one rule can serve several playbooks, as one Crossplane function serves many
// Compositions. It is cluster-scoped, and lives at the hub.
//
// A Rule is named with a DNS-1123 label, because the steps of a playbook name the rules that they run.
//
// Whatever a rule says, the core keeps a guarantee. A rule applies to a finding only when every input
// it names is present, and missing evidence never settles anything. A rule that can't be evaluated
// fails closed. When several steps apply to one finding, the most cautious status wins: Affected
// first, then UnderInvestigation, and of the two that settle a finding, Fixed before NotAffected.
//
// A rule's run on one finding may take at most a second, and the evaluation of a playbook's rules for
// one subject at most 30 seconds. A rule past either bound can't be evaluated, so one that holds keeps
// the finding open. The operator refuses a rule that calls a function whose one call it can't bound,
// such as sort, distinct or join.
type Rule struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the decision that the rule makes
	// +required
	Spec RuleSpec `json:"spec"`

	// status defines the observed state of Rule
	// +optional
	Status RuleStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// RuleList contains a list of Rule
type RuleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []Rule `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &Rule{}, &RuleList{})
		return nil
	})
}
