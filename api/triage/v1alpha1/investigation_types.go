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

// The reasons of the Ready condition of an Investigation and of an Assessment.
const (
	// ReasonPlaybookNotFound means the playbook that the investigation names doesn't exist.
	ReasonPlaybookNotFound = "PlaybookNotFound"
	// ReasonAgentSettingsMissing means the investigation has no spec.agent, as one stored before spec.agent existed
	// reads back: it judges nothing until it is applied again with spec.agent.
	ReasonAgentSettingsMissing = "AgentSettingsMissing"
	// ReasonAgentNotAllowed means the playbook has no agent section, so none of its cases may go to the agent.
	ReasonAgentNotAllowed = "AgentNotAllowed"
	// ReasonInvalidCondition means a match condition, of the investigation or of its playbook, doesn't compile.
	ReasonInvalidCondition = "InvalidCondition"
	// ReasonAgentDisabled means the OperatorConfig switched the agent off. The investigation still shows its impact.
	ReasonAgentDisabled = "AgentDisabled"
	// ReasonInvalidSchedule means the cron expression of the trigger doesn't parse.
	ReasonInvalidSchedule = "InvalidSchedule"
	// ReasonDisabled means the investigation's state is Disabled: it judges nothing new, and keeps its status current.
	ReasonDisabled = "Disabled"
	// ReasonJudging means cases of the investigation wait for the agent, or are with it.
	ReasonJudging = "Judging"
	// ReasonCapReached means the investigation judged as many cases as spec.agent.maxCases allows, and left the rest.
	ReasonCapReached = "CapReached"
	// ReasonJudged means every case that the investigation selected has a verdict, or waits for none.
	ReasonJudged = "Judged"
	// ReasonQueued means the case of an Assessment waits for the agent.
	ReasonQueued = "Queued"
	// ReasonWithdrawn means no investigation wants the case of an Assessment judged any more: it left the agent's queue
	// unjudged.
	ReasonWithdrawn = "Withdrawn"
)

// PlaybookReference names a Playbook.
type PlaybookReference struct {
	// name is the name of the Playbook.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Name string `json:"name,omitempty"`
}

// MatchCondition is one condition, in CEL, that a case must meet, as a ValidatingAdmissionPolicy's matchCondition is
// one that a request must meet. It reads the variables finding, subject and impact, and gives a boolean. A condition
// that fails to evaluate doesn't select the case.
type MatchCondition struct {
	// name names the condition, in messages and in the list.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Name string `json:"name,omitempty"`
	// expression is the CEL expression, which gives a boolean.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=4096
	Expression string `json:"expression,omitempty"`
}

// InvestigationTriggerType says when an investigation runs. Open enum; more values may follow.
// +kubebuilder:validation:Enum=Once;Schedule;Continuous
type InvestigationTriggerType string

const (
	// InvestigationTriggerOnce runs when the investigation is created, and again only when its spec changes.
	InvestigationTriggerOnce InvestigationTriggerType = "Once"
	// InvestigationTriggerSchedule runs at the times of a cron expression.
	InvestigationTriggerSchedule InvestigationTriggerType = "Schedule"
	// InvestigationTriggerContinuous judges each eligible case that newly matches, as the sheets change.
	InvestigationTriggerContinuous InvestigationTriggerType = "Continuous"
)

// InvestigationTrigger says when an investigation runs, by its type.
// +kubebuilder:validation:XValidation:rule="has(self.schedule) == (self.type == 'Schedule')",message="schedule is set exactly when type is Schedule"
type InvestigationTrigger struct {
	// type is when the investigation runs: Once, Schedule or Continuous. More values may follow.
	// +required
	Type InvestigationTriggerType `json:"type,omitempty"`
	// schedule is a five-field cron expression, in UTC and without a time zone, as a collector's schedule is. It is
	// set exactly when type is Schedule.
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=128
	// +kubebuilder:validation:Pattern=`^\S+(\s+\S+){4}$`
	Schedule *string `json:"schedule,omitempty"`
}

// InvestigationState says whether an investigation judges new cases. Open enum; more values may follow.
// +kubebuilder:validation:Enum=Enabled;Disabled
type InvestigationState string

const (
	// InvestigationStateEnabled judges the cases that the investigation selects.
	InvestigationStateEnabled InvestigationState = "Enabled"
	// InvestigationStateDisabled judges nothing new, and keeps the status current.
	InvestigationStateDisabled InvestigationState = "Disabled"
)

// InvestigationJudgePolicy says when the agent judges a selected case again that has a fresh verdict. Open enum; more
// values may follow.
// +kubebuilder:validation:Enum=IfStale;IfJudgedElsewhere;Always
type InvestigationJudgePolicy string

const (
	// InvestigationJudgeIfStale judges a case that has no fresh verdict, and reuses a fresh one, whoever it was judged
	// for.
	InvestigationJudgeIfStale InvestigationJudgePolicy = "IfStale"
	// InvestigationJudgeIfJudgedElsewhere judges a case as IfStale does, and also one whose fresh verdict was judged for
	// another investigation, or for none.
	InvestigationJudgeIfJudgedElsewhere InvestigationJudgePolicy = "IfJudgedElsewhere"
	// InvestigationJudgeAlways judges a case that has no verdict judged for this investigation in this run: at or after
	// the run's startTime.
	InvestigationJudgeAlways InvestigationJudgePolicy = "Always"
)

// InvestigationAgent says how the agent works on an investigation's cases. Its guidance can't change once the
// investigation exists, so that a verdict judged for it was judged with the guidance that it has.
// +kubebuilder:validation:XValidation:rule="has(self.guidance) == has(oldSelf.guidance) && (!has(self.guidance) || self.guidance == oldSelf.guidance)",message="guidance can't change once the investigation exists, nor be added or removed: create a new investigation for other guidance"
type InvestigationAgent struct {
	// maxCases is the most cases that the agent judges for the investigation, the most urgent first. Cases whose fresh
	// verdict judgePolicy reuses don't count; status.cases.charged counts the rest. The selected cases beyond it show in
	// status.cases.overTheCap. A recreated investigation starts a new run with a fresh cap, and judges up to maxCases
	// again: a migration, a rename and a sync that replaces the object all recreate it. An apply that changes nothing
	// keeps the run and its cap. A changed spec of a Once investigation starts a new run too.
	// +required
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=1000
	MaxCases int32 `json:"maxCases,omitempty"`
	// verdictMaxAgeSeconds is how old a verdict may be, in seconds, when this investigation selects its case. An older
	// verdict is judged again, within the cap. Without it, a verdict stays fresh until its inputs change.
	// +optional
	// +kubebuilder:validation:Minimum=1
	VerdictMaxAgeSeconds *int64 `json:"verdictMaxAgeSeconds,omitempty"`
	// judgePolicy says when a selected case is judged: IfStale, the default, when it has no fresh verdict;
	// IfJudgedElsewhere also when its fresh verdict was judged for another investigation, or for none; and Always when
	// it has no verdict judged for this investigation in this run. Every judgement counts against maxCases. A
	// Continuous investigation takes only IfStale: its run never ends, so two that share a case would judge it in turn
	// until a cap runs out. More values may follow.
	// +optional
	// +kubebuilder:default=IfStale
	JudgePolicy *InvestigationJudgePolicy `json:"judgePolicy,omitempty"`
	// guidance is what a person knows about the investigation's vulnerabilities: what to check, and what mitigates them.
	// The agent gets it after the profile's guidance with each case that is charged to this investigation. It is never
	// evidence: it can't settle a case. It can't change once the investigation exists, nor be added or removed: other
	// guidance takes a new investigation. At most 4096 bytes in UTF-8.
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=4096
	// +kubebuilder:validation:XValidation:rule="size(bytes(self)) <= 4096",message="guidance is at most 4096 bytes in UTF-8"
	Guidance *string `json:"guidance,omitempty"`
}

// InvestigationSpec says which cases of a playbook to judge: by their vulnerabilities, by conditions, or both, the
// most urgent first, up to a cap.
// +kubebuilder:validation:XValidation:rule="!has(self.trigger) || self.trigger.type != 'Continuous' || !has(self.agent) || !has(self.agent.judgePolicy) || self.agent.judgePolicy == 'IfStale'",message="a Continuous investigation takes only judgePolicy IfStale: a Continuous run never ends, so two investigations that share a case would judge it in turn until a cap runs out"
type InvestigationSpec struct {
	// playbookRef names the Playbook whose cases the investigation judges. Its agent section says which of them may go
	// to the agent, and with what.
	// +required
	PlaybookRef PlaybookReference `json:"playbookRef,omitzero"`
	// vulnerabilities names the vulnerabilities to judge, each matched against a finding's vulnerabilityID and its
	// aliases, so that a GHSA ID finds its CVE. Without any, every case of the playbook is in scope.
	// +optional
	// +listType=set
	// +kubebuilder:validation:MaxItems=100
	// +kubebuilder:validation:items:MinLength=1
	// +kubebuilder:validation:items:MaxLength=64
	Vulnerabilities []string `json:"vulnerabilities,omitempty"`
	// matchConditions select the cases to judge, all of which must hold, besides those of the playbook's agent
	// section. They read the variables finding, subject and impact.
	// +optional
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:MaxItems=16
	MatchConditions []MatchCondition `json:"matchConditions,omitempty"`
	// trigger says when the investigation runs. It defaults to Once.
	// +optional
	// +kubebuilder:default={type: Once}
	Trigger *InvestigationTrigger `json:"trigger,omitempty"`
	// state says whether the investigation judges new cases: Enabled, the default, or Disabled. More values may
	// follow.
	// +optional
	// +kubebuilder:default=Enabled
	State *InvestigationState `json:"state,omitempty"`
	// agent says how the agent works on the selected cases: the cap, how old a verdict may be, when a fresh verdict is
	// judged again, and the guidance that the agent gets with each case.
	// +required
	Agent InvestigationAgent `json:"agent,omitzero"`
}

// InvestigationImpact says where the selected cases' findings are open, from the sheets and the hub's inventory,
// without the agent. A workload or namespace that runs two subjects counts for each.
type InvestigationImpact struct {
	// subjects is the number of subjects, such as platform manifests, with a selected case.
	// +required
	// +kubebuilder:validation:Minimum=0
	Subjects *int32 `json:"subjects,omitempty"`
	// resources is the number of workloads that run the subjects.
	// +required
	// +kubebuilder:validation:Minimum=0
	Resources *int32 `json:"resources,omitempty"`
	// namespaces is the number of namespaces that run the subjects.
	// +required
	// +kubebuilder:validation:Minimum=0
	Namespaces *int32 `json:"namespaces,omitempty"`
	// clusters is the number of clusters that run the subjects.
	// +required
	// +kubebuilder:validation:Minimum=0
	Clusters *int32 `json:"clusters,omitempty"`
	// urgentResources is the number of workloads for which a selected case is Immediate or OutOfCycle, by the
	// urgency of each workload's exposure.
	// +required
	// +kubebuilder:validation:Minimum=0
	UrgentResources *int32 `json:"urgentResources,omitempty"`
}

// InvestigationUsage is what the investigation's cases cost in tokens, as the endpoint reported them.
type InvestigationUsage struct {
	// promptTokens are the tokens that the requests carried.
	// +required
	// +kubebuilder:validation:Minimum=0
	PromptTokens *int64 `json:"promptTokens,omitempty"`
	// completionTokens are the tokens that the model wrote.
	// +required
	// +kubebuilder:validation:Minimum=0
	CompletionTokens *int64 `json:"completionTokens,omitempty"`
}

// InvestigationCases is the progress of an investigation's cases.
type InvestigationCases struct {
	// total is the number of selected cases: those of the named vulnerabilities, or every case of the playbook, that
	// every condition holds for and whose image runs in some workload.
	// +required
	// +kubebuilder:validation:Minimum=0
	Total *int32 `json:"total,omitempty"`
	// queued is the number of cases that wait for the agent.
	// +required
	// +kubebuilder:validation:Minimum=0
	Queued *int32 `json:"queued,omitempty"`
	// inProgress is the number of cases that the agent judges now.
	// +required
	// +kubebuilder:validation:Minimum=0
	InProgress *int32 `json:"inProgress,omitempty"`
	// charged is the number of cases that count against spec.agent.maxCases: those that this investigation handed to
	// the agent in this run, and for a Continuous investigation since its creation. A run starts it again at 0, and room
	// for new cases is maxCases less charged.
	// +required
	// +kubebuilder:validation:Minimum=0
	Charged *int32 `json:"charged,omitempty"`
	// judged is the number of cases that the agent judged in this run.
	// +required
	// +kubebuilder:validation:Minimum=0
	Judged *int32 `json:"judged,omitempty"`
	// reused is the number of cases whose fresh verdict the investigation reused.
	// +required
	// +kubebuilder:validation:Minimum=0
	Reused *int32 `json:"reused,omitempty"`
	// overTheCap is the number of selected cases that the cap keeps from the agent. They are part of total.
	// +required
	// +kubebuilder:validation:Minimum=0
	OverTheCap *int32 `json:"overTheCap,omitempty"`
	// judgedElsewhere is the number of selected cases whose fresh verdict, which the investigation shows, was judged for
	// another investigation, or for none: reused, judged in this run, or one that judgePolicy declines while its case
	// can't be queued, at the cap or after the run. This investigation's guidance didn't shape them.
	// +optional
	// +kubebuilder:validation:Minimum=0
	JudgedElsewhere *int32 `json:"judgedElsewhere,omitempty"`
	// notSelected is the number of cases in scope that a condition doesn't hold for, or whose image runs nowhere. They
	// are outside total.
	// +required
	// +kubebuilder:validation:Minimum=0
	NotSelected *int32 `json:"notSelected,omitempty"`
}

// InvestigationSummary counts the cases by their result, as OpenReports' summary counts results.
type InvestigationSummary struct {
	// fail is the number of cases that are Affected.
	// +required
	// +kubebuilder:validation:Minimum=0
	Fail *int32 `json:"fail,omitempty"`
	// pass is the number of cases that are NotAffected or Fixed.
	// +required
	// +kubebuilder:validation:Minimum=0
	Pass *int32 `json:"pass,omitempty"`
	// warn is the number of cases that are still UnderInvestigation.
	// +required
	// +kubebuilder:validation:Minimum=0
	Warn *int32 `json:"warn,omitempty"`
	// error is the number of cases that the agent ended without a verdict.
	// +required
	// +kubebuilder:validation:Minimum=0
	Error *int32 `json:"error,omitempty"`
	// skip is the number of cases that the cap keeps from the agent.
	// +required
	// +kubebuilder:validation:Minimum=0
	Skip *int32 `json:"skip,omitempty"`
}

// InvestigationResultType is the result of a case, in OpenReports' words. Open enum; more values may follow.
// +kubebuilder:validation:Enum=fail;pass;warn;error;skip
type InvestigationResultType string

const (
	// InvestigationResultFail is a case that is Affected.
	InvestigationResultFail InvestigationResultType = "fail"
	// InvestigationResultPass is a case that is NotAffected or Fixed.
	InvestigationResultPass InvestigationResultType = "pass"
	// InvestigationResultWarn is a case that is still UnderInvestigation.
	InvestigationResultWarn InvestigationResultType = "warn"
	// InvestigationResultError is a case that the agent ended without a verdict.
	InvestigationResultError InvestigationResultType = "error"
	// InvestigationResultSkip is a case that isn't judged, such as one over the cap.
	InvestigationResultSkip InvestigationResultType = "skip"
)

// NamespaceOwners names a namespace that runs a subject, and the owner values that owner attribution copied from it.
type NamespaceOwners struct {
	// cluster is the name of the namespace's cluster.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	Cluster string `json:"cluster,omitempty"`
	// namespace is the name of the namespace.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	Namespace string `json:"namespace,omitempty"`
	// values are the labels and annotations of the namespace that the owner attribution allows. They are data
	// written by the owners of the namespace.
	// +optional
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=32
	Values []OwnerValue `json:"values,omitempty"`
}

// InvestigationResult is one case of an investigation, in the shape of an action (decision 0042): what it is, how
// urgent, and whom to contact.
type InvestigationResult struct {
	// subject names the case's subject: for an image, its first repository and its platform manifest's digest,
	// repository@digest, or the digest alone when no repository is known.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=512
	Subject string `json:"subject,omitempty"`
	// vulnerabilityID is the ID of the case's vulnerability, as its findings name it.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=64
	VulnerabilityID string `json:"vulnerabilityID,omitempty"`
	// result is the case's result: fail, pass, warn, error or skip. More values may follow.
	// +required
	Result InvestigationResultType `json:"result,omitempty"`
	// status is the case's status in the words of OpenVEX: the most cautious status of the case's findings in the
	// playbook's sheet, which holds the agent's Affected or UnderInvestigation beside the rules' outcomes, and settles
	// a finding as an agent's NotAffected or Fixed only once a person accepted its statement. More values may follow.
	// +optional
	Status *VEXStatus `json:"status,omitempty"`
	// verdict is the agent's fresh verdict on the case, in the words of OpenVEX, shown beside status, which it never
	// changes itself. It is absent while the agent has none. More values may follow.
	// +optional
	Verdict *VEXStatus `json:"verdict,omitempty"`
	// review is where the review of the verdict's VexStatement stands, for a NotAffected or Fixed verdict: Proposed
	// until a person accepts or rejects it. It is absent while the sheet shows no review of the verdict. More values
	// may follow.
	// +optional
	Review *ReviewState `json:"review,omitempty"`
	// step is what the owners do next, by the status and whether a fix exists. It is absent for a settled case. More
	// values may follow.
	// +optional
	Step *ResourceStep `json:"step,omitempty"`
	// severity is the highest severity of the case's findings. More values may follow.
	// +required
	Severity Severity `json:"severity,omitempty"`
	// urgency is the case's highest urgency, by the exposure of the workloads that run its subject. It is absent when
	// no workload is known to run it. More values may follow.
	// +optional
	Urgency *SSVCOutcome `json:"urgency,omitempty"`
	// exposure is the highest exposure of the workloads that run the case's subject, as the playbook's exposure rules
	// decide it for each: Open, then Unknown, Controlled and Small. It is absent when no workload is known to run the
	// subject. More values may follow.
	// +optional
	Exposure *SSVCExposure `json:"exposure,omitempty"`
	// reason says why the case has its result: the first sentence of the agent's summary, at most 256 characters, or
	// why the case isn't judged, such as "over the cap". It may come from the model, and is data to show.
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=256
	Reason *string `json:"reason,omitempty"`
	// resources is the number of workloads that run the case's subject.
	// +required
	// +kubebuilder:validation:Minimum=0
	Resources *int32 `json:"resources,omitempty"`
	// owners names the first 5 namespaces that run the subject, by cluster and name, each with its owner values.
	// +optional
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=5
	Owners []NamespaceOwners `json:"owners,omitempty"`
}

// InvestigationStatus is the answer of an investigation: where the selected cases are open, how far the agent got,
// and where to start.
type InvestigationStatus struct {
	// conditions represent the current state of the Investigation. Ready is True with the reason Judged once every
	// selected case has a verdict or waits for none, and CapReached when the cap left cases out. It is False with the
	// reason Judging while cases wait for the agent or are with it, which Reconciling says too. It is False and
	// Stalled with the reason PlaybookNotFound, AgentNotAllowed, InvalidCondition, AgentSettingsMissing or
	// AgentDisabled when the investigation can't run; with AgentDisabled it still shows its impact and its results.
	// +optional
	// +listType=map
	// +listMapKey=type
	// +kubebuilder:validation:MaxItems=8
	Conditions []metav1.Condition `json:"conditions,omitempty"`
	// observedGeneration is the generation of the Investigation that the operator last acted on.
	// +optional
	// +kubebuilder:validation:Minimum=0
	ObservedGeneration *int64 `json:"observedGeneration,omitempty"`
	// startTime is when the current run started: the creation of the investigation and each change of its spec for
	// Once, each tick for Schedule, and the creation for Continuous, which never starts another.
	// +optional
	StartTime *metav1.Time `json:"startTime,omitempty"`
	// completionTime is when the run finished: nothing is queued or in progress, and every selected case is judged,
	// reused or skipped. A Continuous investigation never completes.
	// +optional
	CompletionTime *metav1.Time `json:"completionTime,omitempty"`
	// lastScheduleTime is when a Schedule investigation last started a run.
	// +optional
	LastScheduleTime *metav1.Time `json:"lastScheduleTime,omitempty"`
	// impact says where the selected cases' findings are open.
	// +optional
	Impact *InvestigationImpact `json:"impact,omitempty"`
	// cases is the progress of the investigation's cases.
	// +optional
	Cases *InvestigationCases `json:"cases,omitempty"`
	// summary counts the cases by their result.
	// +optional
	Summary *InvestigationSummary `json:"summary,omitempty"`
	// usage is the tokens that the cases charged to the investigation spent, judged in the current run.
	// +optional
	Usage *InvestigationUsage `json:"usage,omitempty"`
	// results lists where to start: the selected cases, the most urgent first, at most 20, and fewer when the status
	// would pass 512 KiB. omitted counts the rest.
	// +optional
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=20
	Results []InvestigationResult `json:"results,omitempty"`
	// omitted is the number of selected cases that results leaves out.
	// +optional
	// +kubebuilder:validation:Minimum=0
	Omitted *int32 `json:"omitted,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:categories=vexplain
// +kubebuilder:printcolumn:name="Playbook",type=string,JSONPath=`.spec.playbookRef.name`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Reason",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].reason`
// +kubebuilder:printcolumn:name="Subjects",type=integer,JSONPath=`.status.impact.subjects`
// +kubebuilder:printcolumn:name="Resources",type=integer,JSONPath=`.status.impact.resources`
// +kubebuilder:printcolumn:name="Urgent",type=integer,JSONPath=`.status.impact.urgentResources`
// +kubebuilder:printcolumn:name="Cases",type=integer,JSONPath=`.status.cases.total`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// Investigation asks the agent to judge a playbook's cases (decision 0051), and its status is the answer: where the
// cases' findings are open, how far the agent got, and where to start. It is namespaced, so RBAC alone decides who
// may create one, which spends tokens, and read where findings run across the fleet. vexplain's roles for it aren't
// aggregated into Kubernetes' edit and admin roles.
//
// The hub creates an Assessment for each selected case without a fresh verdict, and queues it. The cases aren't
// referenced one by one: each Assessment is labelled with its vulnerability and its subject.
type Investigation struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec says which cases to judge
	// +required
	Spec InvestigationSpec `json:"spec"`

	// status is the answer
	// +optional
	Status InvestigationStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// InvestigationList contains a list of Investigation
type InvestigationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []Investigation `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &Investigation{}, &InvestigationList{})
		return nil
	})
}
