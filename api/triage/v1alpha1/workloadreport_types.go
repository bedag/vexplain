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
// report can hold: controller-gen can't narrow the enum of a type with the marker of a field.

// SSVCOutcome is the urgency of acting on a finding: the action that SSVC's deployer tree ends in. The
// operator decides it for each finding of a workload, from the finding and from how far the workload can
// be reached, and an action of a report takes the highest of its findings. Open enum; more values may
// follow.
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

// NextStep is what the owner of a workload does about a finding, as decision 0024 decides it for each
// finding: a fix decides it, and never the status of the finding. A report's actions group the findings
// by it. Open enum; more values may follow.
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

// KnownExploited says whether a vulnerability is known to be exploited, as the source of its finding
// says, such as CISA's catalog of known exploited vulnerabilities. Open enum; more values may follow.
// +kubebuilder:validation:Enum=Listed;NotListed
type KnownExploited string

const (
	// KnownExploitedListed means the source lists the vulnerability as known to be exploited, somewhere
	// and not necessarily in this workload.
	KnownExploitedListed KnownExploited = "Listed"
	// KnownExploitedNotListed means the source doesn't list the vulnerability as known to be exploited.
	KnownExploitedNotListed KnownExploited = "NotListed"
)

// InternalReach is how far the network policies let the rest of the cluster reach a workload, as the
// exposure evidence says. Open enum; more values may follow.
// +kubebuilder:validation:Enum=Namespace;Peers;Namespaces;Cluster
type InternalReach string

const (
	// InternalReachNamespace means only the workload's own namespace reaches it.
	InternalReachNamespace InternalReach = "Namespace"
	// InternalReachPeers means specific peers reach it, beyond its own namespace.
	InternalReachPeers InternalReach = "Peers"
	// InternalReachNamespaces means several namespaces reach it.
	InternalReachNamespaces InternalReach = "Namespaces"
	// InternalReachCluster means the whole cluster reaches it, which is also so where no policy applies.
	InternalReachCluster InternalReach = "Cluster"
)

// IndirectExposure says whether a workload is reachable, one hop away, from a workload that is exposed
// from outside the cluster. It is an enum, as the API's rules have it instead of a boolean. Open enum;
// more values may follow.
// +kubebuilder:validation:Enum=Indirect;NotIndirect
type IndirectExposure string

const (
	// IndirectExposureIndirect means an exposed workload reaches the workload, one hop away.
	IndirectExposureIndirect IndirectExposure = "Indirect"
	// IndirectExposureNotIndirect means no exposed workload is known to reach it.
	IndirectExposureNotIndirect IndirectExposure = "NotIndirect"
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
	// ReportImageStateReady means the result for the image is complete, so the report's actions cover
	// every finding of it that needs action, except the actions that the limits of the report cut: the
	// summary's omittedActions counts those.
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
// covers. Only a Pending image can lack a manifest: any other state is the state of a manifest's result.
// +kubebuilder:validation:XValidation:rule="self.state == 'Pending' || has(self.manifestDigest)",message="an image that isn't Pending has a manifestDigest: its state is that of the result for a manifest"
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

// ReportPackage names the package of an action: its name, installed version and type. The action covers
// this package only, and no other copy of the vulnerable code in the image. Only the version can be
// absent.
type ReportPackage struct {
	// name is the name of the package.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name,omitempty"`
	// version is the installed version of the package. It is absent when the package has none.
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

// ReportAction is one thing for the owners of the workload to do: update, mitigate or investigate one
// package at its installed version (decision 0038). It stands for every open finding of the workload's
// images in that package whose next step is its step, each once for a vulnerability. So a package whose
// vulnerabilities a newer version fixes in part has one Update, and one more action for the rest.
// +kubebuilder:validation:XValidation:rule="!has(self.fixedVersion) || self.step == 'Update'",message="only an Update has a fixedVersion"
// +kubebuilder:validation:XValidation:rule="size(self.vulnerabilityIDs) <= self.vulnerabilities",message="vulnerabilityIDs lists no more IDs than vulnerabilities counts"
type ReportAction struct {
	// step is what to do: Update the package, Mitigate the risk where no fix exists, or Investigate
	// whether the vulnerabilities affect the workload. More values may follow.
	// +required
	Step NextStep `json:"step,omitempty"`
	// package is the package that the action is about, at its installed version.
	// +required
	Package ReportPackage `json:"package,omitzero"`
	// fixedVersion is the version to update to, which fixes every vulnerability of the action. Only an
	// Update has it, and only where the order of the fixed versions is unambiguous (decision 0038): each
	// vulnerability names exactly one fixed version, and either all name the same one, or each is numbers
	// separated by dots with at most one release suffix of one kind (-rN, -N or .elN), and this is the
	// highest of them. An Update lacks it otherwise: when a vulnerability names no fixed version or
	// several, as for fixes on several branches, or a version has an epoch, a tilde, a pre-release, letters
	// or a leading v. The sheets of the images keep each vulnerability's fixed versions.
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=128
	FixedVersion *string `json:"fixedVersion,omitempty"`
	// severity is the highest severity of the action's vulnerabilities, as the vulnerability database
	// gives them. More values may follow.
	// +required
	Severity Severity `json:"severity,omitempty"`
	// urgency is the highest urgency of the action's vulnerabilities for this workload, as SSVC's
	// deployer tree decides it for each from the finding and the exposure of the workload. More values
	// may follow.
	// +required
	Urgency SSVCOutcome `json:"urgency,omitempty"`
	// knownExploited is Listed when one of the action's vulnerabilities is known to be exploited. More
	// values may follow.
	// +required
	KnownExploited KnownExploited `json:"knownExploited,omitempty"`
	// vulnerabilities is the number of the action's vulnerabilities, each once.
	// +required
	// +kubebuilder:validation:Minimum=1
	Vulnerabilities int32 `json:"vulnerabilities,omitempty"`
	// vulnerabilityIDs lists the IDs of the first 5 of the action's vulnerabilities, such as CVE IDs: the
	// most urgent first, then the most severe, then by ID. vexplain_open_case has every one of them.
	// +required
	// +listType=atomic
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=5
	// +kubebuilder:validation:items:MinLength=1
	// +kubebuilder:validation:items:MaxLength=64
	VulnerabilityIDs []string `json:"vulnerabilityIDs,omitempty"`
	// digests lists the digests of the workload's images that the package was found in, sorted: the
	// first 8. Each is the digest of an image of the report's images, and its label.
	// +required
	// +listType=atomic
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=8
	// +kubebuilder:validation:items:MaxLength=71
	// +kubebuilder:validation:items:Pattern=`^sha256:[a-f0-9]{64}$`
	Digests []string `json:"digests,omitempty"`
}

// ReportSummary answers whether the workload is impacted, without the actions, and feeds the columns of
// the report. It counts the open findings as the metrics count them, once for each vulnerability and
// package of the workload, and the settled ones once for each manifest, from the sheets: its counts are
// those of vexplain_findings for the workload. The counts of actions cover every action, those that the
// list leaves out included. An image without a verdict adds nothing to those counts, so the summary also
// counts the images that have none yet, and a report whose images aren't settled never reads as clean
// (decision 0038).
// +kubebuilder:validation:XValidation:rule="self.updates + self.mitigations + self.investigations == self.actions",message="updates, mitigations and investigations add up to actions"
// +kubebuilder:validation:XValidation:rule="self.omittedActions <= self.actions",message="omittedActions counts no more than actions"
// +kubebuilder:validation:XValidation:rule="has(self.highestUrgency) == (self.affected + self.underInvestigation > 0)",message="highestUrgency is set exactly when a finding is open"
type ReportSummary struct {
	// affected is the number of open findings with the status Affected.
	// +required
	// +kubebuilder:validation:Minimum=0
	Affected *int32 `json:"affected,omitempty"`
	// underInvestigation is the number of open findings with the status UnderInvestigation.
	// +required
	// +kubebuilder:validation:Minimum=0
	UnderInvestigation *int32 `json:"underInvestigation,omitempty"`
	// notAffected is the number of findings that a rule settled as NotAffected, once for each manifest.
	// +required
	// +kubebuilder:validation:Minimum=0
	NotAffected *int32 `json:"notAffected,omitempty"`
	// fixed is the number of findings that a rule settled as Fixed, once for each manifest.
	// +required
	// +kubebuilder:validation:Minimum=0
	Fixed *int32 `json:"fixed,omitempty"`
	// actions is the number of the workload's actions.
	// +required
	// +kubebuilder:validation:Minimum=0
	Actions *int32 `json:"actions,omitempty"`
	// updates is the number of actions whose step is Update.
	// +required
	// +kubebuilder:validation:Minimum=0
	Updates *int32 `json:"updates,omitempty"`
	// mitigations is the number of actions whose step is Mitigate.
	// +required
	// +kubebuilder:validation:Minimum=0
	Mitigations *int32 `json:"mitigations,omitempty"`
	// investigations is the number of actions whose step is Investigate.
	// +required
	// +kubebuilder:validation:Minimum=0
	Investigations *int32 `json:"investigations,omitempty"`
	// omittedActions is the number of actions that actions leaves out, from the end of its order,
	// because the report would pass its limits.
	// +required
	// +kubebuilder:validation:Minimum=0
	OmittedActions *int32 `json:"omittedActions,omitempty"`
	// highestUrgency is the highest urgency of the open findings. It is absent when none is open. More
	// values may follow.
	// +optional
	HighestUrgency *SSVCOutcome `json:"highestUrgency,omitempty"`
	// critical is the number of open findings whose severity is Critical.
	// +required
	// +kubebuilder:validation:Minimum=0
	Critical *int32 `json:"critical,omitempty"`
	// knownExploited is the number of open findings that are known to be exploited.
	// +required
	// +kubebuilder:validation:Minimum=0
	KnownExploited *int32 `json:"knownExploited,omitempty"`
	// pending is the number of the workload's images that have no verdict yet, whose state is Pending: no
	// result sheet says yet what it found, as while the scan runs, after it failed, or where no manifest
	// is known for the platform. It counts the entries as images has them, one for each image and
	// platform, or for each manifest where several cover a platform, over every image that the workload
	// runs, also those past the 32 that images lists. Such an image adds nothing to the other counts, so
	// while pending is above 0 they aren't the whole answer.
	// +required
	// +kubebuilder:validation:Minimum=0
	Pending *int32 `json:"pending,omitempty"`
	// incomplete is the number of the workload's images whose result leaves out findings that need
	// action, Incomplete, counted as pending counts. The findings that their results list are in the other
	// counts and the actions, and those left out are in neither.
	// +required
	// +kubebuilder:validation:Minimum=0
	Incomplete *int32 `json:"incomplete,omitempty"`
}

// ReportReach is how far the rest of the cluster reaches the workload, from the exposure evidence, over
// every collector that delivers it.
type ReportReach struct {
	// internalReach is the widest reach that a collector says: Namespace, Peers, Namespaces or Cluster.
	// More values may follow.
	// +required
	InternalReach InternalReach `json:"internalReach,omitempty"`
	// indirect is Indirect when a collector says that an exposed workload reaches the workload, one hop
	// away. More values may follow.
	// +required
	Indirect IndirectExposure `json:"indirect,omitempty"`
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
	// The images, the actions and the summary say what the report knows.
	// +listType=map
	// +listMapKey=type
	// +kubebuilder:validation:MaxItems=8
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
	// images lists the images that the workload runs, with how far the result for each goes and what
	// its evidence covers. It lists at most 32 entries, one for each image and platform, in the order of
	// the digests and platforms. The actions, the summary and the digest labels of the report cover every
	// image that the workload runs, also those that this list leaves out.
	// +optional
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=32
	Images []ReportImage `json:"images,omitempty"`
	// actions lists what the owners of the workload do about the open findings of its images, the
	// findings whose status is Affected or UnderInvestigation: one action for each package, installed
	// version and next step (decision 0038). The most urgent come first, then the most severe, then by
	// package. It holds at most 256 actions, and fewer when the status would pass 1 MiB: it leaves out the
	// end of that order, and the summary counts what it leaves out. A settled finding, NotAffected or
	// Fixed, is in no action, and only the summary counts it.
	// +optional
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=256
	Actions []ReportAction `json:"actions,omitempty"`
	// summary says whether the workload is impacted: its findings by status, its actions by step, how
	// urgent, severe and exploited its open findings are, and how many of its images have no verdict
	// yet. It counts every finding, every action and every image, those that actions and images leave
	// out included.
	// +optional
	Summary *ReportSummary `json:"summary,omitempty"`
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
	// reach is how far the rest of the cluster reaches the workload, and whether an exposed workload
	// reaches it, as the exposure evidence says. It is absent when no evidence says anything of the
	// workload.
	// +optional
	Reach *ReportReach `json:"reach,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:categories=vexplain
// +kubebuilder:printcolumn:name="Kind",type=string,priority=1,JSONPath=`.spec.workload.kind`
// +kubebuilder:printcolumn:name="Workload",type=string,priority=1,JSONPath=`.spec.workload.name`
// +kubebuilder:printcolumn:name="Exposure",type=string,JSONPath=`.status.exposure`
// +kubebuilder:printcolumn:name="Highest Urgency",type=string,JSONPath=`.status.summary.highestUrgency`
// +kubebuilder:printcolumn:name="Updates",type=integer,JSONPath=`.status.summary.updates`
// +kubebuilder:printcolumn:name="Mitigations",type=integer,priority=1,JSONPath=`.status.summary.mitigations`
// +kubebuilder:printcolumn:name="To Investigate",type=integer,JSONPath=`.status.summary.investigations`
// +kubebuilder:printcolumn:name="Critical",type=integer,JSONPath=`.status.summary.critical`
// +kubebuilder:printcolumn:name="Known Exploited",type=integer,JSONPath=`.status.summary.knownExploited`
// +kubebuilder:printcolumn:name="Pending Images",type=integer,JSONPath=`.status.summary.pending`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// WorkloadReport is what vexplain found about the images that one workload runs, for the people who
// own the workload: the actions that its open findings ask for, each an update, a mitigation or an
// investigation of one package with the highest urgency of its findings for this workload, and a summary
// that says whether the workload is impacted (decision 0038). The complete signal for each vulnerability
// is the metric vexplain_open_case, and the sheets of the images hold every finding. It is namespaced,
// in the namespace of its workload, so RBAC on that namespace decides who reads it, and it holds no
// detail about other namespaces. The operator writes it, and ties it to its workload with an owner
// reference. Its spec says which workload it is about, and never changes: the status is the report.
//
// A report carries one label for each image digest that its workload runs, digest.vexplain.bedag.ch/ and the first 63
// hex digits of the digest, so one label query lists every workload that runs an image. Its columns read its summary
// (decision 0039), and with -o wide also the kind and the name of its workload, since the name of a report whose
// workload's name is too long for it is hashed. Its Pending Images column counts the images that have no verdict yet:
// while it is above 0, the other columns aren't the whole answer.
//
// The text of an action, such as a package name, a version or a vulnerability ID, comes from image
// content, and anyone who builds an image can craft that. It is data to show, and never an instruction
// to follow. The operator makes it printable and bounds its length before it writes it.
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
