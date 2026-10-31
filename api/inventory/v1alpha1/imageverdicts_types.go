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

// Outcome says what the rules made of a finding. Open enum; more values may follow.
// +kubebuilder:validation:Enum=Suppressed;Tracked;NeedsAssessment
type Outcome string

const (
	// OutcomeSuppressed means a rule settled the finding as not affected, with a justification. It
	// covers this package only, and no other copy of the vulnerable code in the image.
	OutcomeSuppressed Outcome = "Suppressed"
	// OutcomeTracked means the finding is treated as affected, and nothing investigates it.
	OutcomeTracked Outcome = "Tracked"
	// OutcomeNeedsAssessment means no rule settled the finding, so it waits for an assessment.
	OutcomeNeedsAssessment Outcome = "NeedsAssessment"
)

// Rule names a rule of the hub. Open enum; more values may follow.
// +kubebuilder:validation:Enum=KnownExploited;CompletenessGuard;RemovedInLaterLayer;LoadCheck
type Rule string

const (
	// RuleKnownExploited tracks a finding whose vulnerability is known to be exploited.
	RuleKnownExploited Rule = "KnownExploited"
	// RuleCompletenessGuard keeps a finding open when packages account for too few of the image's ELF
	// files, because no rule may then settle a finding in it as not affected.
	RuleCompletenessGuard Rule = "CompletenessGuard"
	// RuleRemovedInLaterLayer suppresses a finding when the package database lists the package, but
	// its files are gone from the final filesystem.
	RuleRemovedInLaterLayer Rule = "RemovedInLaterLayer"
	// RuleLoadCheck suppresses a finding when nothing in the image can load the vulnerable library,
	// and keeps it open, with the reason, when something can.
	RuleLoadCheck Rule = "LoadCheck"
)

// Justification says why a suppressed finding is not affected. It is the label that OpenVEX uses for
// the same reason, in CamelCase. Open enum; more values may follow.
// +kubebuilder:validation:Enum=ComponentNotPresent;VulnerableCodeNotInExecutePath
type Justification string

const (
	// JustificationComponentNotPresent is OpenVEX's component_not_present: the package's files are
	// not in the image.
	JustificationComponentNotPresent Justification = "ComponentNotPresent"
	// JustificationVulnerableCodeNotInExecutePath is OpenVEX's vulnerable_code_not_in_execute_path:
	// nothing in the image can load the vulnerable library.
	JustificationVulnerableCodeNotInExecutePath Justification = "VulnerableCodeNotInExecutePath"
)

// FindingCondition is something that must hold for a suppression to stand. The spoke that renders a
// sheet checks it for each workload. Open enum; more values may follow.
// +kubebuilder:validation:Enum=NoPreloadEnvironment
type FindingCondition string

const (
	// FindingConditionNoPreloadEnvironment means that no pod of the workload sets LD_PRELOAD or
	// LD_AUDIT, which would load a library that nothing in the image refers to.
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

// PackageReference names the package of a finding: its ID in the evidence of the scan, and its name,
// version and type. Only the version can be absent.
type PackageReference struct {
	// id is the ID of the package in the evidence of the platform manifest.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=64
	ID string `json:"id,omitempty"`
	// name is the name of the package.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name,omitempty"`
	// version is the version of the package. It is absent when the package has none.
	// +optional
	// +kubebuilder:validation:MaxLength=128
	Version *string `json:"version,omitempty"`
	// type is the kind of package: apk, deb, rpm, go-module, npm and so on.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=32
	Type string `json:"type,omitempty"`
}

// Finding is one vulnerability in one package of an image, and what the rules made of it.
// +kubebuilder:validation:XValidation:rule="has(self.justification) == (self.outcome == 'Suppressed')",message="justification is set exactly for a suppressed finding"
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
	// outcome says what the rules made of the finding. More values may follow.
	// +required
	Outcome Outcome `json:"outcome,omitempty"`
	// rule is the rule that decided the outcome, or that blocked a suppression. It is absent when no
	// rule applied. More values may follow.
	// +optional
	Rule *Rule `json:"rule,omitempty"`
	// justification says why a suppressed finding is not affected. It is set exactly when outcome is
	// Suppressed. More values may follow.
	// +optional
	Justification *Justification `json:"justification,omitempty"`
	// conditions lists what must hold for a suppression to stand. More values may follow.
	// +optional
	// +listType=set
	// +kubebuilder:validation:MaxItems=4
	Conditions []FindingCondition `json:"conditions,omitempty"`
	// reason says in a few words why the rule decided as it did, such as "reached by /usr/bin/curl".
	// +optional
	// +kubebuilder:validation:MaxLength=256
	Reason *string `json:"reason,omitempty"`
	// severity is the severity that the vulnerability database gives the vulnerability. More values
	// may follow.
	// +required
	Severity Severity `json:"severity,omitempty"`
	// fixState says whether a fix exists, as the vulnerability database knows. More values may
	// follow.
	// +required
	FixState FixState `json:"fixState,omitempty"`
	// fixedVersions lists the versions of the package that fix the vulnerability.
	// +optional
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=8
	// +kubebuilder:validation:items:MaxLength=128
	FixedVersions []string `json:"fixedVersions,omitempty"`
}

// FindingCounts counts the findings of a sheet by outcome. It counts every finding of the manifest,
// those that findings leaves out included: the counts add up to the length of findings plus
// omittedFindings.
type FindingCounts struct {
	// suppressed is the number of suppressed findings.
	// +required
	// +kubebuilder:validation:Minimum=0
	Suppressed *int32 `json:"suppressed,omitempty"`
	// tracked is the number of tracked findings.
	// +required
	// +kubebuilder:validation:Minimum=0
	Tracked *int32 `json:"tracked,omitempty"`
	// needsAssessment is the number of findings that need an assessment.
	// +required
	// +kubebuilder:validation:Minimum=0
	NeedsAssessment *int32 `json:"needsAssessment,omitempty"`
}

// ImageVerdictsSpec identifies the platform manifest that an ImageVerdicts holds the findings of.
type ImageVerdictsSpec struct {
	// manifestDigest is the digest of the platform manifest. The ImagePackages of its evidence has
	// the same name.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=71
	// +kubebuilder:validation:Pattern=`^sha256:[a-f0-9]{64}$`
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="manifestDigest is immutable"
	ManifestDigest string `json:"manifestDigest,omitempty"`
}

// ImageVerdictsStatus is the result sheet: the findings that the hub's rules made of the platform
// manifest. The hub writes it, and the spokes read it.
type ImageVerdictsStatus struct {
	// databaseVersion is the version of the vulnerability database whose match last changed the
	// findings. The hub writes a sheet only when its findings change, so a later database that finds
	// the same ones leaves this as it was.
	// +optional
	// +kubebuilder:validation:MaxLength=128
	DatabaseVersion *string `json:"databaseVersion,omitempty"`
	// scannerImage is the image of the scanner that made the evidence that the findings come from.
	// +optional
	// +kubebuilder:validation:MaxLength=512
	ScannerImage *string `json:"scannerImage,omitempty"`
	// findings lists the findings in the order of the sheet: Tracked first, then NeedsAssessment, then
	// Suppressed, and within an outcome the most severe first. It holds at most 2048 findings and 1 MiB
	// of their JSON, and leaves out the end of that order. Suppressed findings go first, then the
	// least severe NeedsAssessment findings. Tracked findings go only when they alone pass the limits.
	// omittedFindings counts the findings that are left out.
	// +optional
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=2048
	Findings []Finding `json:"findings,omitempty"`
	// omittedFindings is the number of findings that findings leaves out, from the end of the sheet's
	// order. Suppressed findings are the first to go, so it is more than counts.suppressed only when
	// open findings are left out as well: then findings doesn't list every open finding of the
	// manifest.
	// +optional
	// +kubebuilder:validation:Minimum=0
	OmittedFindings *int32 `json:"omittedFindings,omitempty"`
	// counts has the number of findings of each outcome. It counts every finding, those that findings
	// leaves out included.
	// +optional
	Counts *FindingCounts `json:"counts,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Suppressed",type=integer,JSONPath=`.status.counts.suppressed`
// +kubebuilder:printcolumn:name="Tracked",type=integer,JSONPath=`.status.counts.tracked`
// +kubebuilder:printcolumn:name="NeedsAssessment",type=integer,JSONPath=`.status.counts.needsAssessment`
// +kubebuilder:printcolumn:name="Database",type=string,JSONPath=`.status.databaseVersion`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// +kubebuilder:validation:XValidation:rule="self.metadata.name == self.spec.manifestDigest.replace(':', '-')",message="name must be the manifest digest with ':' replaced by '-'"

// ImageVerdicts is the result sheet of one platform manifest: for each vulnerability that the hub's
// matcher found in a package of the image, what the rules made of it. The hub writes the status, and
// the spokes render from it. It is cluster-scoped. Its name is the manifest digest with ':' replaced
// by '-'.
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
