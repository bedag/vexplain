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
	"k8s.io/apimachinery/pkg/types"
)

// VEXStatus is a status in the words of OpenVEX, which the API spells in CamelCase: what a case's findings are, as the
// rules or the agent concluded. Open enum; more values may follow.
// +kubebuilder:validation:Enum=Affected;UnderInvestigation;NotAffected;Fixed
type VEXStatus string

const (
	// VEXStatusAffected is OpenVEX's affected: the vulnerability affects the subject, and action is needed.
	VEXStatusAffected VEXStatus = "Affected"
	// VEXStatusUnderInvestigation is OpenVEX's under_investigation: it is not yet known whether the vulnerability
	// affects the subject.
	VEXStatusUnderInvestigation VEXStatus = "UnderInvestigation"
	// VEXStatusNotAffected is OpenVEX's not_affected: the vulnerability doesn't affect the subject.
	VEXStatusNotAffected VEXStatus = "NotAffected"
	// VEXStatusFixed is OpenVEX's fixed: the subject holds the fix.
	VEXStatusFixed VEXStatus = "Fixed"
)

// VEXJustification says why a case is not affected, in the words of OpenVEX, whose five justifications these are. The
// API spells them in CamelCase, and OpenVEX in lower case with underscores. Open enum; more values may follow.
// +kubebuilder:validation:Enum=ComponentNotPresent;VulnerableCodeNotPresent;VulnerableCodeNotInExecutePath;VulnerableCodeCannotBeControlledByAdversary;InlineMitigationsAlreadyExist
type VEXJustification string

const (
	// VEXJustificationVulnerableCodeNotPresent is OpenVEX's vulnerable_code_not_present: the package is in the image,
	// but the vulnerable code is not.
	VEXJustificationVulnerableCodeNotPresent VEXJustification = "VulnerableCodeNotPresent"
)

// SubjectType says what kind of subject a case is about. Open enum; more values may follow, such as the disk image of
// a virtual machine.
// +kubebuilder:validation:Enum=ContainerImage
type SubjectType string

const (
	// SubjectTypeContainerImage is a container image of one platform: its platform manifest.
	SubjectTypeContainerImage SubjectType = "ContainerImage"
)

// ContainerImageSubject names a container image of one platform.
type ContainerImageSubject struct {
	// digest is the digest of the image's platform manifest.
	// +required
	// +kubebuilder:validation:MinLength=71
	// +kubebuilder:validation:MaxLength=71
	// +kubebuilder:validation:Pattern=`^sha256:[a-f0-9]{64}$`
	Digest string `json:"digest,omitempty"`
}

// AssessmentSubject is the subject of a case, by its type.
// +kubebuilder:validation:XValidation:rule="has(self.containerImage) == (self.type == 'ContainerImage')",message="containerImage is set exactly when type is ContainerImage"
type AssessmentSubject struct {
	// type is the kind of subject: ContainerImage. More values may follow.
	// +required
	Type SubjectType `json:"type,omitempty"`
	// containerImage names the image of one platform that the case is about. It is set exactly when type is
	// ContainerImage.
	// +optional
	ContainerImage *ContainerImageSubject `json:"containerImage,omitempty"`
}

// AssessmentSpec names the case: one vulnerability in one subject. It never changes: another case is another
// Assessment.
// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="the case of an Assessment can't change: another case is another Assessment"
type AssessmentSpec struct {
	// subject is the subject of the case.
	// +required
	Subject AssessmentSubject `json:"subject,omitzero"`
	// vulnerabilityID is the ID of the vulnerability, as the subject's findings name it, such as a CVE ID, or the ID
	// of an advisory where no CVE exists. Its aliases are in the findings.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=64
	VulnerabilityID string `json:"vulnerabilityID,omitempty"`
}

// AssessmentVerdict is the agent's verdict on a case. It holds for every finding of the case's vulnerability in the
// subject. Its text comes from the model, and is data to show, never an instruction to follow.
type AssessmentVerdict struct {
	// status is what the agent concluded, in the words of OpenVEX. More values may follow.
	// +required
	Status VEXStatus `json:"status,omitempty"`
	// justification says why the case is NotAffected. It is set only then.
	// +optional
	Justification *VEXJustification `json:"justification,omitempty"`
	// summary says, in a few sentences, why: what the agent established, each part with the ledger entries that it
	// rests on.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=2048
	Summary string `json:"summary,omitempty"`
	// nextStep is what a person should do now, in the agent's words, cut at 1024 characters.
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=1024
	NextStep *string `json:"nextStep,omitempty"`
	// statement is the name of the VexStatement that proposes the verdict for a person's review. It is set exactly for
	// a NotAffected or Fixed verdict.
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Statement *string `json:"statement,omitempty"`
	// claims are what the verdict rests on, each with the ledger entries that support it: the first 32.
	// +optional
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=32
	Claims []AssessmentClaim `json:"claims,omitempty"`
}

// AssessmentClaim is one statement of a verdict, and the ledger entries that support it.
type AssessmentClaim struct {
	// text is the statement, cut at 1024 characters.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=1024
	Text string `json:"text,omitempty"`
	// evidence lists the IDs of the ledger entries that support it, such as ev-3: the first 32.
	// +required
	// +listType=atomic
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=32
	// +kubebuilder:validation:items:MaxLength=16
	// +kubebuilder:validation:items:Pattern=`^ev-[0-9]+$`
	Evidence []string `json:"evidence,omitempty"`
}

// NoVerdictReason says what ended a case without a verdict. Open enum; more values may follow.
// +kubebuilder:validation:Enum=GaveUp;ValidatorRejected;MaxSteps;MaxTokens;Timeout;ContextLimit;ModelError
type NoVerdictReason string

const (
	// NoVerdictGaveUp means the agent found that the evidence can't settle the case.
	NoVerdictGaveUp NoVerdictReason = "GaveUp"
	// NoVerdictValidatorRejected means the validator rejected the agent's verdict twice, after its one repair.
	NoVerdictValidatorRejected NoVerdictReason = "ValidatorRejected"
	// NoVerdictMaxSteps means the case reached its profile's maxSteps.
	NoVerdictMaxSteps NoVerdictReason = "MaxSteps"
	// NoVerdictMaxTokens means the case's next step and its final call could have passed its profile's maxTokens.
	NoVerdictMaxTokens NoVerdictReason = "MaxTokens"
	// NoVerdictTimeout means the case ran out of its profile's timeoutSeconds.
	NoVerdictTimeout NoVerdictReason = "Timeout"
	// NoVerdictContextLimit means the case's next request would no longer have fit the model's context window.
	NoVerdictContextLimit NoVerdictReason = "ContextLimit"
	// NoVerdictModelError means the endpoint refused a request of the case as such.
	NoVerdictModelError NoVerdictReason = "ModelError"
)

// AssessmentNoVerdict says why the agent ended a case without a verdict.
type AssessmentNoVerdict struct {
	// reason says what ended the case: GaveUp, ValidatorRejected, MaxSteps, MaxTokens, Timeout, ContextLimit or
	// ModelError. More values may follow.
	// +optional
	Reason *NoVerdictReason `json:"reason,omitempty"`
	// summary says why there is no verdict, what was established, and what would settle the case. It comes from the
	// model, or from the limit that ended the case, and is data to show. A verdict that the validator rejected shows in
	// it as the agent's proposal, never as what was established.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=2048
	Summary string `json:"summary,omitempty"`
}

// ValidationResult is what the validator made of the last verdict that the agent submitted. Open enum; more values
// may follow.
// +kubebuilder:validation:Enum=Passed;Rejected
type ValidationResult string

const (
	// ValidationPassed means the validator accepted the verdict.
	ValidationPassed ValidationResult = "Passed"
	// ValidationRejected means the validator rejected it.
	ValidationRejected ValidationResult = "Rejected"
)

// AssessmentValidation is what the validator made of the agent's verdicts on a case.
type AssessmentValidation struct {
	// result is what the validator made of the last verdict: Passed or Rejected.
	// +required
	Result ValidationResult `json:"result,omitempty"`
	// repairs counts the rejected verdicts that the agent submitted again: 0 or 1, since it gets one repair.
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=1
	Repairs *int32 `json:"repairs,omitempty"`
}

// LedgerReference names the Ledger of a case: the record of its tool calls, in the inventory group.
type LedgerReference struct {
	// name is the name of the Ledger, which is the Assessment's.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name,omitempty"`
}

// RunnerType says which runner drove the model through a case. Open enum; more values may follow.
// +kubebuilder:validation:Enum=Builtin
type RunnerType string

const (
	// RunnerBuiltin is vexplain's own runner.
	RunnerBuiltin RunnerType = "Builtin"
)

// AssessmentRunner is the runner that judged a case.
type AssessmentRunner struct {
	// type is the runner: Builtin. More values may follow.
	// +required
	Type RunnerType `json:"type,omitempty"`
}

// AssessmentModel is what judged a case: the profile, the model and the prompt.
type AssessmentModel struct {
	// agentProfile is the name of the AgentProfile.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	AgentProfile string `json:"agentProfile,omitempty"`
	// modelConfig is the name of the profile's ModelConfig.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	ModelConfig string `json:"modelConfig,omitempty"`
	// endpoint is the ModelConfig's endpoint.
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=2048
	Endpoint *string `json:"endpoint,omitempty"`
	// model is the model that the endpoint served.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Model string `json:"model,omitempty"`
	// promptCore is the version of the core prompt, such as v2.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=16
	PromptCore string `json:"promptCore,omitempty"`
	// guidanceSHA256 is the SHA-256 of the profile's guidance, in hex.
	// +required
	// +kubebuilder:validation:MinLength=64
	// +kubebuilder:validation:MaxLength=64
	// +kubebuilder:validation:Pattern=`^[a-f0-9]{64}$`
	GuidanceSHA256 string `json:"guidanceSHA256,omitempty"`
	// guidanceResourceVersion is the resourceVersion of the ConfigMap that held the guidance. It is absent for the
	// guidance that the operator ships.
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=64
	GuidanceResourceVersion *string `json:"guidanceResourceVersion,omitempty"`
}

// AssessmentUsage is what a case took: the model calls, the tokens that the endpoint reported and the time.
type AssessmentUsage struct {
	// steps counts the model calls with tools.
	// +optional
	// +kubebuilder:validation:Minimum=0
	Steps *int32 `json:"steps,omitempty"`
	// promptTokens and completionTokens are the tokens that the endpoint reported for every request of the case.
	// +optional
	// +kubebuilder:validation:Minimum=0
	PromptTokens *int64 `json:"promptTokens,omitempty"`
	// completionTokens are the tokens that the model wrote.
	// +optional
	// +kubebuilder:validation:Minimum=0
	CompletionTokens *int64 `json:"completionTokens,omitempty"`
	// peakContextTokens is the most tokens that one request carried, estimated as bytes / 4, as the profile's
	// worstCaseContextTokens counts them.
	// +optional
	// +kubebuilder:validation:Minimum=0
	PeakContextTokens *int64 `json:"peakContextTokens,omitempty"`
	// durationSeconds is how long the case took.
	// +optional
	// +kubebuilder:validation:Minimum=0
	DurationSeconds *int32 `json:"durationSeconds,omitempty"`
}

// InvestigationReference names an Investigation.
type InvestigationReference struct {
	// namespace is the namespace of the Investigation.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	Namespace string `json:"namespace,omitempty"`
	// name is the name of the Investigation.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name,omitempty"`
	// uid is the Investigation's metadata.uid, so that an Investigation recreated under the same name is another one.
	// +required
	// +kubebuilder:validation:Type=string
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=36
	UID types.UID `json:"uid,omitempty"`
}

// QueueRequest is an investigation's request that the agent judge the case.
type QueueRequest struct {
	// investigationRef is the Investigation that wants the case judged.
	// +required
	InvestigationRef InvestigationReference `json:"investigationRef,omitzero"`
	// trigger is the Investigation's trigger. A case that an investigation of the trigger Once wants, which a person
	// asked for, goes first within its tier. More values may follow.
	// +required
	Trigger InvestigationTriggerType `json:"trigger,omitempty"`
}

// QueueOrder is the place of a case in the agent's queue, by the tiers of urgency, not by a score (decisions 0024 and
// 0050): the most urgent first, then a vulnerability known to be exploited, then the higher EPSS, then the more
// workloads.
type QueueOrder struct {
	// urgencyRank is the place of the case's most urgent outcome: 1 for Immediate, 2 OutOfCycle, 3 Scheduled, 4
	// Defer, 5 for none known, and 0 for an outcome that the hub doesn't know, which goes first.
	// +required
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=5
	UrgencyRank *int32 `json:"urgencyRank,omitempty"`
	// knownExploited says whether a finding of the case is known to be exploited: Listed or NotListed. More values
	// may follow, and go with Listed.
	// +required
	KnownExploited KnownExploited `json:"knownExploited,omitempty"`
	// epssPermille is the highest EPSS of the case's findings, in per mille. It is absent when none has one.
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=1000
	EPSSPermille *int32 `json:"epssPermille,omitempty"`
	// resources is the number of workloads that run the case's subject.
	// +required
	// +kubebuilder:validation:Minimum=0
	Resources *int32 `json:"resources,omitempty"`
}

// AssessmentQueue is what the agent's queue holds of a case that waits for the agent or is judged now (decision
// 0057). The hub writes it, and a worker clears it with the case's outcome.
type AssessmentQueue struct {
	// playbook is the playbook whose case file goes with the case.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	Playbook string `json:"playbook,omitempty"`
	// investigationRef is the investigation that queued the case, whose cap the judgement under way counts against.
	// The outcome of the judgement moves it to the status's investigationRef.
	// +optional
	InvestigationRef *InvestigationReference `json:"investigationRef,omitempty"`
	// requests are the investigations that want the case judged, at most 64. A case in progress may have none left:
	// it finishes.
	// +optional
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=64
	Requests []QueueRequest `json:"requests,omitempty"`
	// judgedAfter is the latest of the requests' oldest outcome that they reuse: an outcome on the case's current
	// inputs that was recorded before it doesn't count. It is absent when every request takes any.
	// +optional
	JudgedAfter *metav1.Time `json:"judgedAfter,omitempty"`
	// order is the case's place in the queue's tiers.
	// +required
	Order QueueOrder `json:"order,omitzero"`
	// runsIn is where the case's subject runs, with the exposure that the playbook's exposure rules decided for each
	// workload, as the hub found it when the case came into the queue, and since then each time that an investigation of
	// the queue's playbook queued it. The case file takes it from here, since only the hub decides exposure. It lies
	// outside the case's inputs, so that a change of it never makes a verdict stale.
	// +optional
	RunsIn *QueueRunsIn `json:"runsIn,omitempty"`
	// queuedTime is when the case came into the queue. It orders the cases of the same tiers.
	// +required
	QueuedTime *metav1.Time `json:"queuedTime,omitempty"`
	// failures counts the judgements of the case that failed after spending tokens, or whose worker stopped: five end
	// the case without a verdict.
	// +optional
	// +kubebuilder:validation:Minimum=0
	Failures *int32 `json:"failures,omitempty"`
	// misses counts the judgements of the case that failed in a row, for which the wait before the next one doubles.
	// +optional
	// +kubebuilder:validation:Minimum=0
	Misses *int32 `json:"misses,omitempty"`
	// notBefore is when a case that was handed back may be judged again.
	// +optional
	NotBefore *metav1.Time `json:"notBefore,omitempty"`
}

// QueueRunsIn is how far the workloads that run a queued case's subject can be reached, as the playbook's exposure rules
// decide it for each workload (the design of entry points, section 5.8), and how urgent the case is there.
type QueueRunsIn struct {
	// highestExposure is the highest exposure of the workloads, Open before Unknown, Controlled and Small. It is absent
	// when no workload is known to run the subject. More values may follow.
	// +optional
	HighestExposure *SSVCExposure `json:"highestExposure,omitempty"`
	// highestUrgency is the case's most urgent outcome over the exposures of the workloads. It is absent when none is
	// known. More values may follow.
	// +optional
	HighestUrgency *SSVCOutcome `json:"highestUrgency,omitempty"`
	// urgentWorkloads counts the workloads for which the case is Immediate or OutOfCycle, by each one's exposure.
	// +optional
	// +kubebuilder:validation:Minimum=0
	UrgentWorkloads *int32 `json:"urgentWorkloads,omitempty"`
	// clusters are the names of the clusters whose workloads the case counts, sorted, at most 256: those that run the
	// subject and that the playbook's match selects, as the hub found them with the rest of runsIn. A worker counts the
	// workloads of these clusters only, since it can't read the labels of the remote clusters. Without them, as in a
	// queue that an earlier version wrote, it counts every cluster's.
	// +optional
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=256
	// +kubebuilder:validation:items:MinLength=1
	// +kubebuilder:validation:items:MaxLength=63
	Clusters []string `json:"clusters,omitempty"`
	// exposure groups the workloads by their exposure and the rules that decided it, Open first, then Unknown,
	// Controlled and Small, and by the rules and the missing inputs within each. It holds the first 16 groups.
	// +optional
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=16
	Exposure []ExposureGroup `json:"exposure,omitempty"`
}

// ExposureGroup is a group of the workloads that run a case's subject: those of one exposure that the same rules
// decided, or that are Unknown for the same reasons.
type ExposureGroup struct {
	// exposure is the workloads' exposure: Open, Controlled, Small, or Unknown, which urgency counts as Open. More values
	// may follow.
	// +required
	Exposure SSVCExposure `json:"exposure,omitempty"`
	// rules are the names of the exposure rules that concluded the exposure, sorted, or, of an Unknown group, of those
	// that couldn't be evaluated. At most 8 are kept.
	// +optional
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=8
	// +kubebuilder:validation:items:MinLength=1
	// +kubebuilder:validation:items:MaxLength=63
	Rules []string `json:"rules,omitempty"`
	// missing are the names of the inputs that the rules of an Unknown group lacked, sorted: evidence that wasn't
	// there, or was past its maxAge. At most 8 are kept.
	// +optional
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=8
	// +kubebuilder:validation:items:MinLength=1
	// +kubebuilder:validation:items:MaxLength=63
	Missing []string `json:"missing,omitempty"`
	// workloads counts the workloads of the group.
	// +required
	// +kubebuilder:validation:Minimum=0
	Workloads *int32 `json:"workloads,omitempty"`
	// first names the group's first 5 workloads by their subject, sorted, such as
	// workload/cluster-a/team-a/Deployment.apps/shop. A workload that the hub counts and that presence doesn't name, as
	// in a cluster whose presence hasn't reached the hub, has no subject to show.
	// +optional
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=5
	// +kubebuilder:validation:items:MinLength=1
	// +kubebuilder:validation:items:MaxLength=512
	First []string `json:"first,omitempty"`
}

// QueueClaim names the worker that judges a case, and when its lease ends unless the worker renews it.
type QueueClaim struct {
	// worker is the name of the worker: its pod's name.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Worker string `json:"worker,omitempty"`
	// leaseEndTime is when the claim ends unless the worker renews it. The hub returns a case whose lease ended to the
	// queue.
	// +required
	LeaseEndTime *metav1.Time `json:"leaseEndTime,omitempty"`
}

// AssessmentStatus is the record of the case: the agent's verdict, or why there is none, and what it rested on.
// +kubebuilder:validation:XValidation:rule="!(has(self.verdict) && has(self.noVerdict))",message="an Assessment holds a verdict or a noVerdict, not both"
// +kubebuilder:validation:XValidation:rule="!has(self.claim) || has(self.queue)",message="a claim needs a queue"
type AssessmentStatus struct {
	// conditions represent the current state of the Assessment. Ready is False with the reason Queued while the case
	// waits for the agent, Judging while the agent judges it, and Withdrawn once no investigation wants it judged any
	// more, and True with the reason Judged once it recorded a verdict or no verdict. Reconciling and Stalled are present only while True, and give the reason and message of
	// Ready.
	// +optional
	// +listType=map
	// +listMapKey=type
	// +kubebuilder:validation:MaxItems=8
	Conditions []metav1.Condition `json:"conditions,omitempty"`
	// observedGeneration is the generation of the Assessment that the operator last acted on.
	// +optional
	// +kubebuilder:validation:Minimum=0
	ObservedGeneration *int64 `json:"observedGeneration,omitempty"`
	// verdict is the agent's verdict on the case. It is absent until the agent has judged the case, and when it ended
	// the case without one.
	// +optional
	Verdict *AssessmentVerdict `json:"verdict,omitempty"`
	// noVerdict says why the agent ended the case without a verdict.
	// +optional
	NoVerdict *AssessmentNoVerdict `json:"noVerdict,omitempty"`
	// validation is what the validator made of the agent's verdicts. It is absent when the agent submitted none.
	// +optional
	Validation *AssessmentValidation `json:"validation,omitempty"`
	// judgedTime is when the agent recorded the verdict, or the no-verdict. An investigation with a
	// spec.agent.verdictMaxAgeSeconds judges the case again once it is older than that.
	// +optional
	JudgedTime *metav1.Time `json:"judgedTime,omitempty"`
	// ledgerRef names the Ledger of the case: every tool call, with what the model was shown.
	// +optional
	LedgerRef *LedgerReference `json:"ledgerRef,omitempty"`
	// runner is the runner that judged the case.
	// +optional
	Runner *AssessmentRunner `json:"runner,omitempty"`
	// model is what judged the case: the profile, the model and the prompt.
	// +optional
	Model *AssessmentModel `json:"model,omitempty"`
	// usage is what the case took: model calls, tokens and time.
	// +optional
	Usage *AssessmentUsage `json:"usage,omitempty"`
	// inputHash is the SHA-256 of what the verdict rests on: the case's findings, by ID and package, and the data of
	// its case file's evidence. While it is that of the case's current inputs, the verdict is fresh, and an
	// investigation that selects the case reuses it.
	// +optional
	// +kubebuilder:validation:MinLength=71
	// +kubebuilder:validation:MaxLength=71
	// +kubebuilder:validation:Pattern=`^sha256:[a-f0-9]{64}$`
	InputHash *string `json:"inputHash,omitempty"`
	// caseFilePlaybook is the playbook whose case file the agent gets: that of the first investigation that queued the
	// case.
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	CaseFilePlaybook *string `json:"caseFilePlaybook,omitempty"`
	// playbooks lists the playbooks whose investigations selected the case, each once.
	// +optional
	// +listType=set
	// +kubebuilder:validation:MaxItems=64
	// +kubebuilder:validation:items:MinLength=1
	// +kubebuilder:validation:items:MaxLength=63
	Playbooks []string `json:"playbooks,omitempty"`
	// investigationRef is the investigation that the judgement whose outcome and usage the status holds was made for,
	// whose cap it counts against. A case queued again keeps it until its next outcome, which takes the queue's
	// investigationRef.
	// +optional
	InvestigationRef *InvestigationReference `json:"investigationRef,omitempty"`
	// queue is what the agent's queue holds of the case while it waits for the agent or is judged.
	// +optional
	Queue *AssessmentQueue `json:"queue,omitempty"`
	// claim names the worker that judges the case now, and when its lease ends.
	// +optional
	Claim *QueueClaim `json:"claim,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories=vexplain
// +kubebuilder:printcolumn:name="Vulnerability",type=string,JSONPath=`.spec.vulnerabilityID`
// +kubebuilder:printcolumn:name="Status",type=string,JSONPath=`.status.verdict.status`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Reason",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].reason`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// Assessment is the record of one case: one vulnerability in one subject, such as one CVE in one platform manifest
// (decision 0052). The hub creates it when an investigation selects a case without a fresh verdict, and never a
// person. It is cluster-scoped, one per case, and every investigation and playbook that meets the case reads it.
//
// It is named after its vulnerability and its subject, and labelled with both, vexplain.bedag.ch/vulnerability and
// vexplain.bedag.ch/digest, so that one label query lists every case of a vulnerability or of an image.
type Assessment struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec names the case
	// +required
	Spec AssessmentSpec `json:"spec"`

	// status is the record of the case
	// +optional
	Status AssessmentStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// AssessmentList contains a list of Assessment
type AssessmentList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []Assessment `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &Assessment{}, &AssessmentList{})
		return nil
	})
}
