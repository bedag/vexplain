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

// This group defines its own enums, as the inventory group does, even where another group has the same
// idea under the same name. A group stays self-contained, and a field takes exactly the values that a
// report can hold: a report lists only two of OpenVEX's four statuses, and controller-gen can't narrow
// the enum of a type with the marker of a field.

// VEXStatus is what the rules concluded about a finding that a report lists, in the words of OpenVEX.
// The API spells them in CamelCase, and OpenVEX in lower case with underscores. A report lists only the
// findings that need action, so it takes two of OpenVEX's four statuses: the other two, NotAffected and
// Fixed, settle a finding, and only the counts of a report have them. Open enum; more values may follow.
// +kubebuilder:validation:Enum=Affected;UnderInvestigation
type VEXStatus string

const (
	// VEXStatusAffected is OpenVEX's affected: the vulnerability affects the component, and action is
	// needed.
	VEXStatusAffected VEXStatus = "Affected"
	// VEXStatusUnderInvestigation is OpenVEX's under_investigation: no rule has settled the finding, so
	// it is not known whether the vulnerability affects the component.
	VEXStatusUnderInvestigation VEXStatus = "UnderInvestigation"
)

// SSVCOutcome is the urgency of acting on a finding: the action that SSVC's deployer tree ends in. The
// operator decides it for each finding of a workload, from the finding and from how far the workload can
// be reached. Open enum; more values may follow.
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

// SSVCExposure is how far a workload can be reached, the second input of SSVC's deployer tree. Open
// enum; more values may follow.
// +kubebuilder:validation:Enum=Small;Controlled;Open;Unknown
type SSVCExposure string

const (
	// SSVCExposureSmall means the workload is reachable only from its own namespace.
	SSVCExposureSmall SSVCExposure = "Small"
	// SSVCExposureControlled means the workload is reachable indirectly, one hop behind an exposed
	// workload, or from beyond its namespace.
	SSVCExposureControlled SSVCExposure = "Controlled"
	// SSVCExposureOpen means the workload is exposed externally.
	SSVCExposureOpen SSVCExposure = "Open"
	// SSVCExposureUnknown means no exposure is known, as when no collector has reported any. Urgency
	// counts it as Open, so that an unknown exposure errs towards urgency.
	SSVCExposureUnknown SSVCExposure = "Unknown"
)

// NextStep is what the owner of a workload does about a finding. A fix decides it, and never the
// status of the finding. Open enum; more values may follow.
// +kubebuilder:validation:Enum=Update;Mitigate;Investigate
type NextStep string

const (
	// NextStepUpdate means a version of the package fixes the vulnerability, so the next step is to
	// update the package to it.
	NextStepUpdate NextStep = "Update"
	// NextStepMitigate means the finding is affected and no fix exists, so the next step is to reduce
	// the risk in another way.
	NextStepMitigate NextStep = "Mitigate"
	// NextStepInvestigate means no rule has settled the finding and no fix exists, so the next step is
	// to find out whether the vulnerability affects the workload.
	NextStepInvestigate NextStep = "Investigate"
)

// ReviewState says who vouches for the status of a finding. Open enum; more values may follow: the
// states of an agent's proposals, which people review, come with the agent.
// +kubebuilder:validation:Enum=RuleSettled;Open
type ReviewState string

const (
	// ReviewStateRuleSettled means a rule concluded the status. Rules are reviewed once, as code, and
	// not again for each finding that they settle.
	ReviewStateRuleSettled ReviewState = "RuleSettled"
	// ReviewStateOpen means no rule concluded the status, so no one vouches for it: it holds until an
	// assessment replaces it, and a person has reviewed nothing.
	ReviewStateOpen ReviewState = "Open"
)

// Severity is the severity that the vulnerability database gives a vulnerability. Open enum; more
// values may follow.
// +kubebuilder:validation:Enum=Critical;High;Medium;Low;Negligible;Unknown
type Severity string

const (
	// SeverityCritical is the highest severity.
	SeverityCritical Severity = "Critical"
	// SeverityHigh is the severity below critical.
	SeverityHigh Severity = "High"
	// SeverityMedium is the severity below high.
	SeverityMedium Severity = "Medium"
	// SeverityLow is the severity below medium.
	SeverityLow Severity = "Low"
	// SeverityNegligible is the lowest severity.
	SeverityNegligible Severity = "Negligible"
	// SeverityUnknown means the database gives no severity.
	SeverityUnknown Severity = "Unknown"
)

// ReportImageState says how far the result for an image of a workload goes. Open enum; more values may
// follow.
// +kubebuilder:validation:Enum=Pending;Ready;Incomplete
type ReportImageState string

const (
	// ReportImageStatePending means there is no verdict on the image yet: it has no result sheet, or its
	// sheet doesn't say yet what it found. It never means that the image has no findings.
	ReportImageStatePending ReportImageState = "Pending"
	// ReportImageStateReady means the result for the image is complete, so the report has every finding
	// of it that needs action, except the ones that the limits of the report cut: omitted counts those.
	ReportImageStateReady ReportImageState = "Ready"
	// ReportImageStateIncomplete means the result for the image leaves out findings that need action,
	// because it was too large, so the report may lack some of them.
	ReportImageStateIncomplete ReportImageState = "Incomplete"
)

// OwnerSource says where an owner value was copied from. Open enum; more values may follow.
// +kubebuilder:validation:Enum=NamespaceLabel;NamespaceAnnotation;WorkloadLabel
type OwnerSource string

const (
	// OwnerSourceNamespaceLabel means a label of the workload's namespace.
	OwnerSourceNamespaceLabel OwnerSource = "NamespaceLabel"
	// OwnerSourceNamespaceAnnotation means an annotation of the workload's namespace.
	OwnerSourceNamespaceAnnotation OwnerSource = "NamespaceAnnotation"
	// OwnerSourceWorkloadLabel means a label of the workload.
	OwnerSourceWorkloadLabel OwnerSource = "WorkloadLabel"
)

// WorkloadReference names the workload that a report is about. The workload is in the namespace of the
// report.
type WorkloadReference struct {
	// apiGroup is the API group of the workload's kind. It is empty, or left out, for the core group
	// (bare pods).
	// +optional
	// +kubebuilder:validation:MaxLength=253
	APIGroup *string `json:"apiGroup,omitempty"`
	// kind is the kind of the workload, such as Deployment.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	Kind string `json:"kind,omitempty"`
	// name is the name of the workload.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name,omitempty"`
}

// WorkloadReportSpec says which workload the report is about. It never changes.
// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="the workload of a WorkloadReport can't change: delete the report to report on another workload"
type WorkloadReportSpec struct {
	// workload is the workload that the report is about, in the namespace of the report.
	// +required
	Workload WorkloadReference `json:"workload,omitzero"`
}

// ReportCoverage is how much of an image one piece of its evidence covers, as the collector that
// delivered it says.
type ReportCoverage struct {
	// source is the name of the Collector that delivered the evidence. It is a DNS-1123 label of at
	// most 44 characters, as the name of a Collector is.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=44
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Source string `json:"source,omitempty"`
	// type is the type of the evidence, named in reverse-DNS with a version, such as
	// ch.bedag.vexplain.scanner.image-contents.v1alpha1.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9-]+(\.[a-z0-9-]+)+\.v[0-9]+((alpha|beta)[0-9]+)?$`
	Type string `json:"type,omitempty"`
	// coverage is how much of the image the evidence covers, as the whole-number percentage from 0 to
	// 100 that its collector gave it. The core shows it and never interprets it: each type says what it
	// counts.
	// +required
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=100
	Coverage *int32 `json:"coverage,omitempty"`
}

// ReportImage says how far the result for one image of the workload goes, and what its evidence
// covers.
type ReportImage struct {
	// digest is the digest that the container runtime reports for the image, as the pods of the
	// workload run it: a repository digest, which is often that of a multi-arch index, or an image ID.
	// The ImageInventory of the image has it as its digest.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=71
	// +kubebuilder:validation:Pattern=`^sha256:[a-f0-9]{64}$`
	Digest string `json:"digest,omitempty"`
	// platform is the platform that the pods of the workload run the image on, as os/architecture, or
	// os/architecture/variant when the node has one, such as linux/arm64/v8. It is absent when no pod
	// says which.
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=64
	// +kubebuilder:validation:Pattern=`^[a-z0-9]+/[a-z0-9_]+(/[a-z0-9]+)?$`
	Platform *string `json:"platform,omitempty"`
	// manifestDigest is the digest of the manifest of the image for the platform. The result sheet of
	// the manifest, an ImageVerdicts, is named after it, with ':' replaced by '-'. It is absent until a
	// scan has resolved the manifests of the image.
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=71
	// +kubebuilder:validation:Pattern=`^sha256:[a-f0-9]{64}$`
	ManifestDigest *string `json:"manifestDigest,omitempty"`
	// state says how far the result for the image goes. More values may follow.
	// +required
	State ReportImageState `json:"state,omitempty"`
	// coverage lists how much of the image each piece of its evidence covers, for each source and type.
	// The core shows the numbers and never interprets them: each type says what it counts. A low
	// coverage doesn't change the state of the image. An image whose evidence covers little, and that
	// has no findings, is Ready, and its coverage shows how little that says.
	// +optional
	// +listType=map
	// +listMapKey=source
	// +listMapKey=type
	// +kubebuilder:validation:MaxItems=32
	Coverage []ReportCoverage `json:"coverage,omitempty"`
}

// ReportPackage names the package of a finding: its name, version and type. The finding covers this
// package only, and no other copy of the vulnerable code in the image. Only the version can be absent.
type ReportPackage struct {
	// name is the name of the package.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name,omitempty"`
	// version is the version of the package. It is absent when the package has none.
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=128
	Version *string `json:"version,omitempty"`
	// type is the kind of package: apk, deb, rpm, go-module, npm and so on.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=32
	Type string `json:"type,omitempty"`
}

// ReportStatusNote is what a rule that settles nothing, a hint, added to a finding: OpenVEX's
// status_notes.
type ReportStatusNote struct {
	// rule is the name of the Rule that added the note. It is a DNS-1123 label of at most 63
	// characters, as the name of a Rule is.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Rule string `json:"rule,omitempty"`
	// text is what the rule says about the finding, such as "reached by /usr/bin/curl". It can come from
	// image content, and is data. The operator makes it printable.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=256
	Text string `json:"text,omitempty"`
}

// ReportFinding is one vulnerability in one package of an image of the workload that needs action:
// what the rules made of it, how urgent it is for this workload, and what to do about it.
type ReportFinding struct {
	// vulnerabilityID is the ID of the vulnerability, such as a CVE ID.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=64
	VulnerabilityID string `json:"vulnerabilityID,omitempty"`
	// package is the package that the vulnerability was found in. The finding covers this package
	// only, and no other copy of the vulnerable code in the image.
	// +required
	Package ReportPackage `json:"package,omitzero"`
	// status is what the rules concluded about the finding: Affected, or UnderInvestigation when no
	// rule has settled it. A report lists no other status. More values may follow.
	// +required
	Status VEXStatus `json:"status,omitempty"`
	// urgency is how urgent it is to act on the finding for this workload, as SSVC's deployer tree
	// decides it from the finding and the exposure of the workload. A fix never changes the status,
	// and exposure never does either: they change the urgency. More values may follow.
	// +required
	Urgency SSVCOutcome `json:"urgency,omitempty"`
	// nextStep is what the owner of the workload does about the finding: update to the fixed version
	// when there is one, otherwise mitigate an affected finding and investigate an unclear one. More
	// values may follow.
	// +required
	NextStep NextStep `json:"nextStep,omitempty"`
	// fixedVersion is the first version of the package that fixes the vulnerability. It is absent when
	// no fix is known.
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=128
	FixedVersion *string `json:"fixedVersion,omitempty"`
	// reviewState says who vouches for the status: a rule that concluded it, or no one yet. More values
	// may follow.
	// +required
	ReviewState ReviewState `json:"reviewState,omitempty"`
	// reason says in a few words why the rule that decided the status decided as it did, such as
	// "known exploited". It can come from image content, and is data. The operator makes it printable.
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=256
	Reason *string `json:"reason,omitempty"`
	// statusNotes lists what the rules that settle nothing, the hints, added to the finding. It holds
	// at most 4 notes. A hint never settles a finding, whatever it says: that nothing reaches or names
	// a library of the package is no proof that nothing loads it.
	// +optional
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=4
	StatusNotes []ReportStatusNote `json:"statusNotes,omitempty"`
	// severity is the severity that the vulnerability database gives the vulnerability. More values
	// may follow.
	// +required
	Severity Severity `json:"severity,omitempty"`
}

// ReportCounts counts the findings of a workload by status. It counts every finding of the workload's
// images, those that findings leaves out included, and the settled ones, NotAffected and Fixed, which a
// report never lists.
type ReportCounts struct {
	// affected is the number of findings with the status Affected.
	// +required
	// +kubebuilder:validation:Minimum=0
	Affected *int32 `json:"affected,omitempty"`
	// underInvestigation is the number of findings with the status UnderInvestigation.
	// +required
	// +kubebuilder:validation:Minimum=0
	UnderInvestigation *int32 `json:"underInvestigation,omitempty"`
	// notAffected is the number of findings with the status NotAffected.
	// +required
	// +kubebuilder:validation:Minimum=0
	NotAffected *int32 `json:"notAffected,omitempty"`
	// fixed is the number of findings with the status Fixed.
	// +required
	// +kubebuilder:validation:Minimum=0
	Fixed *int32 `json:"fixed,omitempty"`
}

// OwnerValue is the value of a label or an annotation that an admin allowlisted to say whom to inform
// about a workload. The operator copies it and never interprets it.
type OwnerValue struct {
	// source says where the value was copied from. More values may follow.
	// +required
	Source OwnerSource `json:"source,omitempty"`
	// key is the key of the label or the annotation.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=317
	// +kubebuilder:validation:Pattern=`^([a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*/)?[A-Za-z0-9]([-A-Za-z0-9_.]*[A-Za-z0-9])?$`
	Key string `json:"key,omitempty"`
	// value is the value of the label or the annotation, which may be empty. It is at most 256
	// characters. It comes from what the owners of the namespace and of the workload wrote, and is data.
	// +required
	// +kubebuilder:validation:MaxLength=256
	Value *string `json:"value,omitempty"`
}

// WorkloadReportStatus is the report: what vexplain found about the images that the workload runs. The
// spoke's renderer writes it, and the owners of the workload read it.
type WorkloadReportStatus struct {
	// conditions represent the current state of the report, as the conventions of Kubernetes have them:
	// each has a type, a status and the generation that it was observed at. The renderer sets none yet.
	// The images, the findings and the counts say what the report knows.
	// +listType=map
	// +listMapKey=type
	// +kubebuilder:validation:MaxItems=8
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
	// images lists the images that the workload runs, with how far the result for each goes and what
	// its evidence covers. It holds at most 32 images.
	// +optional
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=32
	Images []ReportImage `json:"images,omitempty"`
	// findings lists the findings that need action: those whose status is Affected or
	// UnderInvestigation, each once for a vulnerability and a package. The most urgent come first,
	// then the most severe, and within those they are ordered by ID. It holds at most 1000 findings,
	// and fewer when the status would pass 1 MiB: it leaves out the end of that order, and omitted
	// counts what it leaves out. A finding that is settled as NotAffected or Fixed is never listed, and
	// counts has it.
	// +optional
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=1000
	Findings []ReportFinding `json:"findings,omitempty"`
	// omitted is the number of findings that need action and that findings leaves out, from the end of
	// its order, because the report would pass its limits.
	// +optional
	// +kubebuilder:validation:Minimum=0
	Omitted *int32 `json:"omitted,omitempty"`
	// counts has the number of findings of each status. It counts every finding, those that findings
	// leaves out included.
	// +optional
	Counts *ReportCounts `json:"counts,omitempty"`
	// owner lists the values of the labels and annotations that an admin allowlisted to say whom to
	// inform about the workload, each from where it was copied. It holds at most 48 values: 16 keys for
	// each of the three sources.
	// +optional
	// +listType=map
	// +listMapKey=source
	// +listMapKey=key
	// +kubebuilder:validation:MaxItems=48
	Owner []OwnerValue `json:"owner,omitempty"`
	// exposure is how far the workload can be reached, which decides the urgency of each finding
	// together with the finding itself. More values may follow.
	// +optional
	Exposure *SSVCExposure `json:"exposure,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Kind",type=string,JSONPath=`.spec.workload.kind`
// +kubebuilder:printcolumn:name="Workload",type=string,JSONPath=`.spec.workload.name`
// +kubebuilder:printcolumn:name="Affected",type=integer,JSONPath=`.status.counts.affected`
// +kubebuilder:printcolumn:name="UnderInvestigation",type=integer,JSONPath=`.status.counts.underInvestigation`
// +kubebuilder:printcolumn:name="Exposure",type=string,JSONPath=`.status.exposure`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// WorkloadReport is what vexplain found about the images that one workload runs, for the people who
// own the workload: the findings that need action, each with its status, its urgency for this workload
// and its next step, and the counts of all findings. It is namespaced, in the namespace of its workload,
// so RBAC on that namespace decides who reads it, and it holds no detail about other namespaces. The
// operator writes it, and ties it to its workload with an owner reference. Its spec says which workload
// it is about, and never changes: the status is the report.
//
// A report carries one label for each image digest it holds, digest.vexplain.bedag.ch/ and the first 63
// hex digits of the digest, so one label query lists every workload that runs an image.
//
// The text of a finding, such as a package name, a version or a reason, comes from image content, and
// anyone who builds an image can craft that. It is data to show, and never an instruction to follow.
// The operator makes it printable and bounds its length before it writes it.
type WorkloadReport struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec says which workload the report is about
	// +required
	Spec WorkloadReportSpec `json:"spec"`

	// status is the report
	// +optional
	Status WorkloadReportStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// WorkloadReportList contains a list of WorkloadReport
type WorkloadReportList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []WorkloadReport `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &WorkloadReport{}, &WorkloadReportList{})
		return nil
	})
}
