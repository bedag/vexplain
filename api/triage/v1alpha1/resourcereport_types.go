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

// ResourceStep is what the owner of a resource does about an action (decision 0042): update to a fixed
// version, change the resource itself, mitigate a risk that has no fix, or investigate whether a finding
// applies. Open enum; more values may follow.
// +kubebuilder:validation:Enum=Update;Change;Mitigate;Investigate
type ResourceStep string

const (
	// ResourceStepUpdate means a fixed version exists, so the next step is to update to it.
	ResourceStepUpdate ResourceStep = "Update"
	// ResourceStepChange means the resource itself changes.
	ResourceStepChange ResourceStep = "Change"
	// ResourceStepMitigate means the risk is reduced without being fixed.
	ResourceStepMitigate ResourceStep = "Mitigate"
	// ResourceStepInvestigate means no rule has settled the finding, so the next step is to find out
	// whether it applies.
	ResourceStepInvestigate ResourceStep = "Investigate"
)

// ResourceImageState says how far the result for an image of a resource goes. Open enum; more values may
// follow.
// +kubebuilder:validation:Enum=Pending;Ready;Incomplete;Unscannable
type ResourceImageState string

const (
	// ResourceImageStatePending means there is no verdict on the image yet. It never means that the image
	// has no findings.
	ResourceImageStatePending ResourceImageState = "Pending"
	// ResourceImageStateReady means the result for the image is complete, except for the actions that the
	// limits of the report cut: the summary's omittedActions counts those.
	ResourceImageStateReady ResourceImageState = "Ready"
	// ResourceImageStateIncomplete means the result for the image leaves out findings that need action,
	// because it was too large.
	ResourceImageStateIncomplete ResourceImageState = "Incomplete"
	// ResourceImageStateUnscannable means the image can't be scanned, as one that has no digest, only a
	// reference. It is not Pending: no verdict will come.
	ResourceImageStateUnscannable ResourceImageState = "Unscannable"
)

// ResourceReference names the resource that a report is about. The resource is in the namespace of the
// report.
type ResourceReference struct {
	// apiGroup is the API group of the resource's kind. It is empty, or left out, for the core group.
	// +optional
	// +kubebuilder:validation:MaxLength=253
	APIGroup *string `json:"apiGroup,omitempty"`
	// kind is the kind of the resource, such as Deployment.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	Kind string `json:"kind,omitempty"`
	// name is the name of the resource.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name,omitempty"`
}

// ResourceReportSpec says which resource the report is about. It never changes.
// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="the resource of a ResourceReport can't change: delete the report to report on another resource"
type ResourceReportSpec struct {
	// resource is the resource that the report is about, in the namespace of the report.
	// +required
	Resource ResourceReference `json:"resource,omitzero"`
}

// ResourceImage says how far the result for one image of the resource goes. Only an image that is
// Unscannable can lack a digest.
// +kubebuilder:validation:XValidation:rule="has(self.digest) || self.state == 'Unscannable'",message="only an Unscannable image has no digest"
type ResourceImage struct {
	// digest is the digest that the container runtime reports for the image. It is absent for an image
	// that has only a reference.
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=71
	// +kubebuilder:validation:Pattern=`^sha256:[a-f0-9]{64}$`
	Digest *string `json:"digest,omitempty"`
	// ref is the image reference that the resource names, such as registry.example/team-a/web:1.2.
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=512
	Ref *string `json:"ref,omitempty"`
	// manifestDigests lists the digests of the manifests of the image that the resource runs, one for each
	// platform. Their result sheets are named after them, with ':' replaced by '-'. It is empty until a scan
	// has resolved the manifests.
	// +optional
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=8
	// +kubebuilder:validation:items:MinLength=1
	// +kubebuilder:validation:items:MaxLength=71
	// +kubebuilder:validation:items:Pattern=`^sha256:[a-f0-9]{64}$`
	ManifestDigests []string `json:"manifestDigests,omitempty"`
	// state says how far the result for the image goes. More values may follow.
	// +required
	State ResourceImageState `json:"state,omitempty"`
	// containers lists the names of the containers of the resource that run the image.
	// +optional
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=32
	// +kubebuilder:validation:items:MinLength=1
	// +kubebuilder:validation:items:MaxLength=63
	Containers []string `json:"containers,omitempty"`
}

// ResourceRequirement names the requirement that an action asks for: the rule of a playbook.
type ResourceRequirement struct {
	// playbook is the name of the Playbook.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Playbook string `json:"playbook,omitempty"`
	// rule is the name of the rule of the playbook that the resource fails. It is absent when no rule
	// settled the case.
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Rule *string `json:"rule,omitempty"`
}

// ResourceAction is one thing for the owners of the resource to do (decision 0042). It names where in the
// resource it applies. An action about vulnerabilities is about one package of one image, and carries the
// fields of vulnerabilities.
// +kubebuilder:validation:XValidation:rule="!has(self.fixedVersion) || self.step == 'Update'",message="only an Update has a fixedVersion"
// +kubebuilder:validation:XValidation:rule="has(self.vulnerabilities) == has(self.vulnerabilityIDs)",message="vulnerabilities and vulnerabilityIDs come together"
// +kubebuilder:validation:XValidation:rule="!has(self.vulnerabilities) || size(self.vulnerabilityIDs) <= self.vulnerabilities",message="vulnerabilityIDs lists no more IDs than vulnerabilities counts"
type ResourceAction struct {
	// step is what to do. More values may follow.
	// +required
	Step ResourceStep `json:"step,omitempty"`
	// title says what to do, in a short sentence.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=256
	Title string `json:"title,omitempty"`
	// locations name where in the resource the action applies, each a field path or the name of a
	// container, such as web or spec.ingress[0].
	// +required
	// +listType=atomic
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=8
	// +kubebuilder:validation:items:MinLength=1
	// +kubebuilder:validation:items:MaxLength=256
	Locations []string `json:"locations,omitempty"`
	// severity is the highest severity of the action's findings. More values may follow.
	// +required
	Severity Severity `json:"severity,omitempty"`
	// urgency is the highest urgency of the action's vulnerabilities for this resource. It is absent for
	// an action that is not about vulnerabilities. More values may follow.
	// +optional
	Urgency *SSVCOutcome `json:"urgency,omitempty"`
	// requirement is the requirement that the action asks for.
	// +required
	Requirement ResourceRequirement `json:"requirement,omitzero"`
	// reason says why the resource fails the requirement.
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=1024
	Reason *string `json:"reason,omitempty"`
	// package is the package that a vulnerability action is about, at its installed version.
	// +optional
	Package *ReportPackage `json:"package,omitempty"`
	// fixedVersion is the version to update to, which fixes every vulnerability of the action. Only an
	// Update has it, and only where the order of the fixed versions is unambiguous (decision 0038).
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=128
	FixedVersion *string `json:"fixedVersion,omitempty"`
	// vulnerabilities is the number of the action's vulnerabilities, each once.
	// +optional
	// +kubebuilder:validation:Minimum=1
	Vulnerabilities *int32 `json:"vulnerabilities,omitempty"`
	// vulnerabilityIDs lists the IDs of the first 5 of the action's vulnerabilities, such as CVE IDs: the
	// most urgent first, then the most severe, then by ID.
	// +optional
	// +listType=atomic
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=5
	// +kubebuilder:validation:items:MinLength=1
	// +kubebuilder:validation:items:MaxLength=64
	VulnerabilityIDs []string `json:"vulnerabilityIDs,omitempty"`
	// knownExploited is Listed when one of the action's vulnerabilities is known to be exploited. More
	// values may follow.
	// +optional
	KnownExploited *KnownExploited `json:"knownExploited,omitempty"`
	// digest is the digest of the one image that a vulnerability action is about: such actions merge only
	// within one image.
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=71
	// +kubebuilder:validation:Pattern=`^sha256:[a-f0-9]{64}$`
	Digest *string `json:"digest,omitempty"`
}

// ResourceSummary answers whether the resource is impacted, without the actions, and feeds the columns of
// the report. Its counts cover every action, those that the list leaves out included. An image without a
// verdict adds nothing to the actions, so the summary also counts the images that have none, and a report
// whose images aren't settled never reads as clean.
// +kubebuilder:validation:XValidation:rule="self.updates + self.changes + self.mitigations + self.investigations == self.actions",message="updates, changes, mitigations and investigations add up to actions"
// +kubebuilder:validation:XValidation:rule="self.omittedActions <= self.actions",message="omittedActions counts no more than actions"
type ResourceSummary struct {
	// actions is the number of the resource's actions.
	// +required
	// +kubebuilder:validation:Minimum=0
	Actions *int32 `json:"actions,omitempty"`
	// updates is the number of actions whose step is Update.
	// +required
	// +kubebuilder:validation:Minimum=0
	Updates *int32 `json:"updates,omitempty"`
	// changes is the number of actions whose step is Change.
	// +required
	// +kubebuilder:validation:Minimum=0
	Changes *int32 `json:"changes,omitempty"`
	// mitigations is the number of actions whose step is Mitigate.
	// +required
	// +kubebuilder:validation:Minimum=0
	Mitigations *int32 `json:"mitigations,omitempty"`
	// investigations is the number of actions whose step is Investigate.
	// +required
	// +kubebuilder:validation:Minimum=0
	Investigations *int32 `json:"investigations,omitempty"`
	// omittedActions is the number of actions that actions leaves out, from the end of its order, because
	// the report would pass its limits.
	// +required
	// +kubebuilder:validation:Minimum=0
	OmittedActions *int32 `json:"omittedActions,omitempty"`
	// highestSeverity is the highest severity of the actions. It is absent when there is none. More values
	// may follow.
	// +optional
	HighestSeverity *Severity `json:"highestSeverity,omitempty"`
	// highestUrgency is the highest urgency of the vulnerability actions. It is absent when there is
	// none. More values may follow.
	// +optional
	HighestUrgency *SSVCOutcome `json:"highestUrgency,omitempty"`
	// critical is the number of actions whose severity is Critical.
	// +required
	// +kubebuilder:validation:Minimum=0
	Critical *int32 `json:"critical,omitempty"`
	// knownExploited is the number of actions with a vulnerability that is known to be exploited.
	// +required
	// +kubebuilder:validation:Minimum=0
	KnownExploited *int32 `json:"knownExploited,omitempty"`
	// pendingImages is the number of the resource's images that have no verdict yet, Pending, counted over
	// every image that the resource runs, also those past the 32 that images lists. While it is above 0
	// the other counts aren't the whole answer.
	// +required
	// +kubebuilder:validation:Minimum=0
	PendingImages *int32 `json:"pendingImages,omitempty"`
	// unscannableImages is the number of the resource's images that can't be scanned, Unscannable,
	// counted as pendingImages counts.
	// +required
	// +kubebuilder:validation:Minimum=0
	UnscannableImages *int32 `json:"unscannableImages,omitempty"`
}

// ResourceReportStatus is the report: what vexplain found about the resource. The spoke's renderer
// writes it, and the owners of the resource read it. It is a view that vexplain writes, so it has no
// conditions.
// +kubebuilder:validation:XValidation:rule="!has(self.summary) || self.summary.omittedActions > 0 || has(self.summary.highestUrgency) == (has(self.actions) && self.actions.exists(a, has(a.vulnerabilities)))",message="highestUrgency is set exactly when a vulnerability action exists"
type ResourceReportStatus struct {
	// images lists the images that the resource runs, with how far the result for each goes. It lists at
	// most 32 entries; the summary counts every image.
	// +optional
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=32
	Images []ResourceImage `json:"images,omitempty"`
	// actions lists what the owners of the resource do: the most urgent first, then the most severe. It
	// holds at most 256 actions, and fewer when the status would pass 1 MiB: it leaves out the end of that
	// order, and the summary counts what it leaves out.
	// +optional
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=256
	Actions []ResourceAction `json:"actions,omitempty"`
	// summary says whether the resource is impacted: its actions by step, how severe and urgent they are,
	// and how many of its images have no verdict.
	// +optional
	Summary *ResourceSummary `json:"summary,omitempty"`
	// owner lists the values of the labels and annotations that an admin allowlisted to say whom to
	// inform about the resource, each from where it was copied. It holds at most 48 values.
	// +optional
	// +listType=map
	// +listMapKey=source
	// +listMapKey=key
	// +kubebuilder:validation:MaxItems=48
	Owner []OwnerValue `json:"owner,omitempty"`
	// exposure is how far the resource can be reached, which decides the urgency of each vulnerability
	// together with the finding itself. More values may follow.
	// +optional
	Exposure *SSVCExposure `json:"exposure,omitempty"`
	// reach is how far the rest of the cluster reaches the resource, as the exposure evidence says. It is
	// absent when no evidence says anything of the resource.
	// +optional
	Reach *ReportReach `json:"reach,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:categories=vexplain
// +kubebuilder:printcolumn:name="Kind",type=string,priority=1,JSONPath=`.spec.resource.kind`
// +kubebuilder:printcolumn:name="Resource",type=string,priority=1,JSONPath=`.spec.resource.name`
// +kubebuilder:printcolumn:name="Exposure",type=string,JSONPath=`.status.exposure`
// +kubebuilder:printcolumn:name="Highest Urgency",type=string,JSONPath=`.status.summary.highestUrgency`
// +kubebuilder:printcolumn:name="Actions",type=integer,JSONPath=`.status.summary.actions`
// +kubebuilder:printcolumn:name="Critical",type=integer,JSONPath=`.status.summary.critical`
// +kubebuilder:printcolumn:name="Known Exploited",type=integer,JSONPath=`.status.summary.knownExploited`
// +kubebuilder:printcolumn:name="Pending",type=integer,JSONPath=`.status.summary.pendingImages`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// ResourceReport is what vexplain found about one resource, for the people who own it: the actions that
// its findings ask for, each with its location in the resource, and a summary that says whether the
// resource is impacted (decision 0042). It is namespaced, in the namespace of its resource, so RBAC on
// that namespace decides who reads it. The operator writes it, and ties it to its resource with an owner
// reference. Its spec says which resource it is about, and never changes: the status is the report.
//
// The text of an action comes from image content and from resources, which anyone who builds an image or
// writes a resource can craft. It is data to show, and never an instruction to follow.
type ResourceReport struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec says which resource the report is about
	// +required
	Spec ResourceReportSpec `json:"spec"`

	// status is the report
	// +optional
	Status ResourceReportStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// ResourceReportList contains a list of ResourceReport
type ResourceReportList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []ResourceReport `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &ResourceReport{}, &ResourceReportList{})
		return nil
	})
}
