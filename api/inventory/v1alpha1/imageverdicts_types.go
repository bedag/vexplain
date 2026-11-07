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

// This group defines its own enums, even where another group has the same idea under the same name:
// a group stays self-contained. The statuses and the justifications of a finding take the values of a
// Rule's in the config group, since a rule concludes them.

// VEXStatus is what the rules of a playbook concluded about a finding, in the words of OpenVEX. The API
// spells them in CamelCase, and OpenVEX in lower case with underscores. Open enum; more values may
// follow.
// +kubebuilder:validation:Enum=Affected;UnderInvestigation;NotAffected;Fixed
type VEXStatus string

const (
	// VEXStatusAffected is OpenVEX's affected: a rule concluded that the vulnerability affects the
	// package, and action is needed.
	VEXStatusAffected VEXStatus = "Affected"
	// VEXStatusUnderInvestigation is OpenVEX's under_investigation: no rule settled the finding, or a
	// rule holds it open, so it waits for an assessment.
	VEXStatusUnderInvestigation VEXStatus = "UnderInvestigation"
	// VEXStatusNotAffected is OpenVEX's not_affected: a rule settled the finding as not affected, for
	// the reason that the justification gives. It covers this package only, and no other copy of the
	// vulnerable code in the image.
	VEXStatusNotAffected VEXStatus = "NotAffected"
	// VEXStatusFixed is OpenVEX's fixed: a rule settled the finding, because the package holds the fix.
	VEXStatusFixed VEXStatus = "Fixed"
)

// VEXJustification says why a finding is not affected, in the words of OpenVEX, whose five
// justifications these are. The API spells them in CamelCase, and OpenVEX in lower case with
// underscores. Open enum; more values may follow.
// +kubebuilder:validation:Enum=ComponentNotPresent;VulnerableCodeNotPresent;VulnerableCodeNotInExecutePath;VulnerableCodeCannotBeControlledByAdversary;InlineMitigationsAlreadyExist
type VEXJustification string

const (
	// VEXJustificationComponentNotPresent is OpenVEX's component_not_present: the package's files are
	// not in the image.
	VEXJustificationComponentNotPresent VEXJustification = "ComponentNotPresent"
	// VEXJustificationVulnerableCodeNotPresent is OpenVEX's vulnerable_code_not_present: the package is
	// in the image, but the vulnerable code is not.
	VEXJustificationVulnerableCodeNotPresent VEXJustification = "VulnerableCodeNotPresent"
	// VEXJustificationVulnerableCodeNotInExecutePath is OpenVEX's vulnerable_code_not_in_execute_path:
	// the vulnerable code is in the image, but no execution path reaches it.
	VEXJustificationVulnerableCodeNotInExecutePath VEXJustification = "VulnerableCodeNotInExecutePath"
	// VEXJustificationVulnerableCodeCannotBeControlledByAdversary is OpenVEX's
	// vulnerable_code_cannot_be_controlled_by_adversary: the vulnerable code runs, but an attacker can't
	// control it to exploit the vulnerability.
	VEXJustificationVulnerableCodeCannotBeControlledByAdversary VEXJustification = "VulnerableCodeCannotBeControlledByAdversary"
	// VEXJustificationInlineMitigationsAlreadyExist is OpenVEX's inline_mitigations_already_exist: the
	// image has built-in protections that prevent the exploitation of the vulnerability.
	VEXJustificationInlineMitigationsAlreadyExist VEXJustification = "InlineMitigationsAlreadyExist"
)

// KnownExploited says whether the source of a finding lists its vulnerability as known to be
// exploited, such as on CISA's catalog of known exploited vulnerabilities. Urgency reads it. Open enum;
// more values may follow.
// +kubebuilder:validation:Enum=Listed;NotListed
type KnownExploited string

const (
	// KnownExploitedListed means the source lists the vulnerability as known to be exploited, somewhere
	// and not necessarily in this image.
	KnownExploitedListed KnownExploited = "Listed"
	// KnownExploitedNotListed means the source doesn't list the vulnerability as known to be exploited.
	KnownExploitedNotListed KnownExploited = "NotListed"
)

// FindingCondition is something that must hold for a settled finding to stand. The spoke that renders a
// sheet checks it for each workload. Open enum; more values may follow.
// +kubebuilder:validation:Enum=NoPreloadEnvironment
type FindingCondition string

const (
	// FindingConditionNoPreloadEnvironment means that no pod of the workload sets LD_PRELOAD or
	// LD_AUDIT, which would load a library that nothing in the image refers to. No rule sets it today:
	// it waits for a rule that settles a finding on loading again.
	FindingConditionNoPreloadEnvironment FindingCondition = "NoPreloadEnvironment"
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

// FixState says whether a fix for a vulnerability exists, as the vulnerability database knows. Open
// enum; more values may follow.
// +kubebuilder:validation:Enum=Fixed;NotFixed;WontFix;Unknown
type FixState string

const (
	// FixStateFixed means a version of the package fixes the vulnerability.
	FixStateFixed FixState = "Fixed"
	// FixStateNotFixed means no fix is known yet.
	FixStateNotFixed FixState = "NotFixed"
	// FixStateWontFix means the maintainers will not fix the vulnerability.
	FixStateWontFix FixState = "WontFix"
	// FixStateUnknown means the database doesn't say.
	FixStateUnknown FixState = "Unknown"
)

// PackageReference names the package of a finding: its ID, and its name, version and type, as the
// source of the finding gives them. Only the version can be absent.
type PackageReference struct {
	// id is the ID of the package in the SBOM that the finding was matched from, as the source of the
	// finding gives it. The evidence of the platform manifest may lack the ID: the source can name a
	// package that the evidence doesn't describe, and no rule then settles the finding by it.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=64
	ID string `json:"id,omitempty"`
	// name is the name of the package.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name,omitempty"`
	// version is the version of the package. It is absent when the package has none: no version and an
	// empty one are the same.
	// +optional
	// +kubebuilder:validation:MaxLength=128
	Version *string `json:"version,omitempty"`
	// type is the kind of package: apk, deb, rpm, go-module, npm and so on.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=32
	Type string `json:"type,omitempty"`
}

// StatusNote is what a rule that settles nothing, a hint, added to a finding: OpenVEX's status_notes.
type StatusNote struct {
	// rule is the name of the Rule that added the note. It is a DNS-1123 label of at most 63
	// characters, as the name of a Rule is.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Rule string `json:"rule,omitempty"`
	// text is what the rule says about the finding, such as "reached by /usr/bin/curl". It can come
	// from image content, and is data.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=256
	Text string `json:"text,omitempty"`
}

// CVSS is one score of a vulnerability, as the vector that it is calculated from, which the source of
// the finding gives. Either part is empty where the source gives none, so that the sheet holds what the
// rules read.
type CVSS struct {
	// version is the version of CVSS, such as 3.1. It may be empty.
	// +required
	// +kubebuilder:validation:MaxLength=16
	Version *string `json:"version,omitempty"`
	// vector is the vector of the score, such as CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H. It may be
	// empty.
	// +required
	// +kubebuilder:validation:MaxLength=256
	Vector *string `json:"vector,omitempty"`
}

// Finding is one vulnerability in one package of an image, and what the rules of a playbook made of it.
// +kubebuilder:validation:XValidation:rule="has(self.justification) == (self.status == 'NotAffected')",message="justification is set exactly for a finding that is NotAffected"
type Finding struct {
	// vulnerabilityID is the ID of the vulnerability, such as a CVE ID.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=64
	VulnerabilityID string `json:"vulnerabilityID,omitempty"`
	// package is the package that the vulnerability was found in. The finding covers this package
	// only, and no other copy of the vulnerable code in the image.
	// +required
	Package PackageReference `json:"package,omitzero"`
	// status is what the rules concluded about the finding: the most cautious status of the rules that
	// apply, and UnderInvestigation when none does. More values may follow.
	// +required
	Status VEXStatus `json:"status,omitempty"`
	// rule is the name of the Rule that decided the status, or that couldn't be evaluated and so held
	// the finding open. It is absent when no rule decided: the finding is then UnderInvestigation.
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Rule *string `json:"rule,omitempty"`
	// justification says why a finding that is NotAffected is not affected. It is set exactly when
	// status is NotAffected. More values may follow.
	// +optional
	Justification *VEXJustification `json:"justification,omitempty"`
	// conditions lists what must hold for a settled finding to stand. More values may follow.
	// +optional
	// +listType=set
	// +kubebuilder:validation:MaxItems=4
	Conditions []FindingCondition `json:"conditions,omitempty"`
	// reason says in a few words why the rule decided as it did, such as "known exploited", or why it
	// couldn't be evaluated. It can come from image content, and is data.
	// +optional
	// +kubebuilder:validation:MaxLength=256
	Reason *string `json:"reason,omitempty"`
	// statusNotes lists what the rules that settle nothing, the hints, added to the finding: OpenVEX's
	// status_notes. It holds at most 4, the first by the name of their rule. A hint never settles a
	// finding, whatever it says.
	// +optional
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=4
	StatusNotes []StatusNote `json:"statusNotes,omitempty"`
	// severity is the severity that the vulnerability database gives the vulnerability. More values
	// may follow.
	// +required
	Severity Severity `json:"severity,omitempty"`
	// fixState says whether a fix exists, as the vulnerability database knows. More values may
	// follow.
	// +required
	FixState FixState `json:"fixState,omitempty"`
	// fixedVersions lists the versions of the package that fix the vulnerability, sorted: the first 8.
	// +optional
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=8
	// +kubebuilder:validation:items:MaxLength=128
	FixedVersions []string `json:"fixedVersions,omitempty"`
	// knownExploited says whether the source of the finding lists the vulnerability as known to be
	// exploited. It raises the urgency of the finding, and settles nothing. More values may follow.
	// +required
	KnownExploited KnownExploited `json:"knownExploited,omitempty"`
	// cvss lists the scores of the vulnerability, the newest version of CVSS first: the 4 newest.
	// +optional
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=4
	CVSS []CVSS `json:"cvss,omitempty"`
}

// FindingCounts counts the findings of a sheet by status. It counts every finding of the manifest,
// those that findings leaves out included: the counts add up to the length of findings plus
// omittedFindings.
type FindingCounts struct {
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

// SheetSummary answers how bad the platform manifest is, and feeds the columns of its sheet (decision
// 0039). Like counts, it counts every finding of the manifest, those that findings leaves out included.
// +kubebuilder:validation:XValidation:rule="self.fixable <= self.open",message="fixable counts no more findings than open"
// +kubebuilder:validation:XValidation:rule="self.held <= self.open",message="held counts no more findings than open"
type SheetSummary struct {
	// open is the number of open findings: those whose status is Affected or UnderInvestigation.
	// +required
	// +kubebuilder:validation:Minimum=0
	Open *int32 `json:"open,omitempty"`
	// fixable is the number of open findings for which the source of the findings knows a fix: their fix
	// state is Fixed, or they list a fixed version. An update fixes them, which is the next step of their
	// actions in a WorkloadReport.
	// +required
	// +kubebuilder:validation:Minimum=0
	Fixable *int32 `json:"fixable,omitempty"`
	// held is the number of open findings that a rule decided, and so holds open, such as the rule of a
	// vulnerability known to be exploited, or the guard of the completeness of the evidence. No rule
	// decided the other open findings, which wait for an assessment.
	// +required
	// +kubebuilder:validation:Minimum=0
	Held *int32 `json:"held,omitempty"`
	// settled is the number of findings that a rule settled: those whose status is NotAffected or Fixed.
	// +required
	// +kubebuilder:validation:Minimum=0
	Settled *int32 `json:"settled,omitempty"`
	// omitted is the number of findings that findings leaves out, as omittedFindings says.
	// +required
	// +kubebuilder:validation:Minimum=0
	Omitted *int32 `json:"omitted,omitempty"`
}

// SheetEvidence is a piece of evidence that the playbook of a sheet names, and what of it the findings
// of the sheet rest on: the collector's version, the time and the coverage of the evidence about the
// platform manifest. Evidence that was missing has none of the three, and the rules that need it
// couldn't be evaluated.
type SheetEvidence struct {
	// name is the name under which the playbook supplies the evidence to its rules.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z][a-zA-Z0-9]{0,62}$`
	Name string `json:"name,omitempty"`
	// source is the name of the Collector that delivers the evidence.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Source string `json:"source,omitempty"`
	// type is the type of the evidence, named in reverse-DNS with a version, such as
	// ch.bedag.vexplain.scanner.image-contents.v1alpha1.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9-]+(\.[a-z0-9-]+)+\.v[0-9]+((alpha|beta)[0-9]+)?$`
	Type string `json:"type,omitempty"`
	// version is the version of the collector that delivered the evidence. It is absent when the
	// evidence was missing.
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=128
	Version *string `json:"version,omitempty"`
	// time is when the collector saw what the evidence is about. It is absent when the evidence was
	// missing.
	// +optional
	Time *metav1.Time `json:"time,omitempty"`
	// coverage is how much of the platform manifest the evidence covers, as the whole-number percentage
	// from 0 to 100 that its collector gave it. The core shows it and never interprets it: each type
	// says what it counts. It is absent when the evidence states none, or was missing.
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=100
	Coverage *int32 `json:"coverage,omitempty"`
}

// ImageVerdictsSpec identifies the platform manifest that an ImageVerdicts holds the findings of.
type ImageVerdictsSpec struct {
	// manifestDigest is the digest of the platform manifest. The evidence about it has the subject
	// manifest/ and the digest.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=71
	// +kubebuilder:validation:Pattern=`^sha256:[a-f0-9]{64}$`
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="manifestDigest is immutable"
	ManifestDigest string `json:"manifestDigest,omitempty"`
}

// ImageVerdictsStatus is the result sheet: the findings that the rules of a playbook made of the
// platform manifest. The hub writes it, and the spokes read it.
//
// A sheet without counts or findingsVersion says that there is no verdict yet, and never that there are
// no findings.
// +kubebuilder:validation:XValidation:rule="!has(self.summary) || (has(self.counts) && self.summary.open == self.counts.affected + self.counts.underInvestigation && self.summary.settled == self.counts.notAffected + self.counts.fixed)",message="the summary counts what counts counts: open is affected and underInvestigation, settled is notAffected and fixed"
// +kubebuilder:validation:XValidation:rule="!has(self.summary) || self.summary.omitted == (has(self.omittedFindings) ? self.omittedFindings : 0)",message="summary.omitted is omittedFindings"
type ImageVerdictsStatus struct {
	// playbook is the name of the Playbook whose rules made the findings.
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
	Playbook *string `json:"playbook,omitempty"`
	// findingsVersion is the version of the source of the findings, such as the vulnerability database,
	// at the match that last changed the sheet. The hub writes a sheet only when it changes, so a later
	// match that finds the same leaves this as it was.
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=128
	FindingsVersion *string `json:"findingsVersion,omitempty"`
	// evidence lists the evidence that the playbook names, and what of it the findings rest on: one entry
	// for each name, each with the version of the collector, the time and the coverage of the evidence
	// about the manifest, which a missing one lacks.
	// +optional
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:MaxItems=16
	Evidence []SheetEvidence `json:"evidence,omitempty"`
	// findings lists the findings in the order of the sheet: Affected first, then UnderInvestigation,
	// then Fixed, then NotAffected. Within a status, the findings that the source lists as known to be
	// exploited come first, then the most severe, and then they are ordered by vulnerability ID and
	// package ID. It holds at most 2048 findings and 1 MiB of their JSON, and leaves out the end of
	// that order: the settled findings go first, NotAffected and then Fixed, and then the least severe
	// open findings. omittedFindings counts the findings that are left out.
	// +optional
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=2048
	Findings []Finding `json:"findings,omitempty"`
	// omittedFindings is the number of findings that findings leaves out, from the end of the sheet's
	// order. The settled findings are the first to go, so it is more than counts.notAffected and
	// counts.fixed together only when open findings are left out as well: findings then doesn't list
	// every open finding of the manifest, and the sheet must be shown as incomplete.
	// +optional
	// +kubebuilder:validation:Minimum=0
	OmittedFindings *int32 `json:"omittedFindings,omitempty"`
	// counts has the number of findings of each status. It counts every finding, those that findings
	// leaves out included.
	// +optional
	Counts *FindingCounts `json:"counts,omitempty"`
	// summary answers how bad the manifest is, and feeds the columns of the sheet (decision 0039): its open
	// findings, of them those that are fixable and those that a rule holds, its settled findings, and the
	// findings that findings leaves out. The hub writes it with the sheet, from every finding before the
	// sheet's cut, so it agrees with counts and omittedFindings.
	// +optional
	Summary *SheetSummary `json:"summary,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories={vexplain,vexplain-data}
// +kubebuilder:printcolumn:name="Open",type=integer,JSONPath=`.status.summary.open`
// +kubebuilder:printcolumn:name="Fixable",type=integer,JSONPath=`.status.summary.fixable`
// +kubebuilder:printcolumn:name="Held",type=integer,JSONPath=`.status.summary.held`
// +kubebuilder:printcolumn:name="Settled",type=integer,JSONPath=`.status.summary.settled`
// +kubebuilder:printcolumn:name="Omitted",type=integer,JSONPath=`.status.summary.omitted`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// +kubebuilder:validation:XValidation:rule="self.metadata.name == self.spec.manifestDigest.replace(':', '-')",message="name must be the manifest digest with ':' replaced by '-'"

// ImageVerdicts is the result sheet of one platform manifest: for each vulnerability that the findings
// of a playbook name in a package of the image, what the playbook's rules made of it. The hub writes
// the status, and the spokes render from it. It is cluster-scoped. Its name is the manifest digest with
// ':' replaced by '-'.
//
// The sheet's contract for its readers: its findings come in the order that the status describes, the
// open ones first. An omittedFindings above the counts of NotAffected and Fixed findings together means
// that the sheet leaves out open findings, and must be shown as incomplete. A sheet without counts or
// findingsVersion means "no verdict yet", and never "no findings".
//
// The text of a finding, such as a package name, a version, a reason or a note, comes from image
// content and from the source of the findings, and anyone who builds an image can craft it. It is data
// to show, and never an instruction to follow. The hub makes it printable and bounds its length before
// it writes it.
type ImageVerdicts struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec identifies the platform manifest
	// +required
	Spec ImageVerdictsSpec `json:"spec"`

	// status holds the findings
	// +optional
	Status ImageVerdictsStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// ImageVerdictsList contains a list of ImageVerdicts
type ImageVerdictsList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []ImageVerdicts `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &ImageVerdicts{}, &ImageVerdictsList{})
		return nil
	})
}
