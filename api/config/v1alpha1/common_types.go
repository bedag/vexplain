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

// This file holds the condition types and reasons that every kind of the config group shares,
// and the types that several kinds may use. A kind that needs a reason of its own adds it here,
// so the vocabulary stays in one place.

// SecretKeyRef points to one key of a Secret in the operator's namespace. The config kinds are
// cluster-scoped, so the namespace is not part of the reference: it is always the operator's.
type SecretKeyRef struct {
	// name is the name of the Secret.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
	Name string `json:"name,omitempty"`
	// key is the key of the Secret's data that holds the value.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[-._a-zA-Z0-9]+$`
	Key string `json:"key,omitempty"`
}

// Condition types.
const (
	// ConditionReady says whether the operator has accepted the object and can use it.
	ConditionReady = "Ready"
	// ConditionReconciling is True while the operator works towards the object's current generation,
	// retries something that may pass, or waits on something that passes, such as a rollout. It is
	// present only while True, and then gives the reason and message of Ready, which is False or
	// Unknown. kstatus reads it as in progress (decision 0036).
	ConditionReconciling = "Reconciling"
	// ConditionStalled is True while the operator can't go on without a change of the object, or of
	// something that it names. It is present only while True, and then gives the reason and message of
	// Ready, which is False. kstatus reads it as failed (decision 0036).
	ConditionStalled = "Stalled"
	// ConditionEvaluated says whether the last evaluations of a Rule had no errors. It is True when
	// they had none, and False with reason EvaluationErrors while findings can't be evaluated. Only a
	// Rule has it.
	ConditionEvaluated = "Evaluated"
)

// Reasons of the Ready condition. The set is open: more reasons may follow, so code that reads
// them must not assume it knows them all.
const (
	// ReasonValid means the object passed validation. Ready is True.
	ReasonValid = "Valid"
	// ReasonInvalid means the object holds a value the operator cannot use, for example a label
	// selector with a malformed expression. Ready is False, and the message names the field.
	ReasonInvalid = "Invalid"
	// ReasonUnknownValue means a field holds a value of an open enum that this version of the
	// operator does not know. Ready is False. The operator reports it and never panics.
	ReasonUnknownValue = "UnknownValue"
	// ReasonHealthy means the collector answers its standard gRPC health check with SERVING, and
	// nothing keeps it from being used. Ready is True.
	ReasonHealthy = "Healthy"
	// ReasonCollectorFailing means the collector can't be reached past the grace after the
	// operator's start, or after the operator issued the collector's certificate: a call of it
	// fails, as its health check does when it answers anything but SERVING, its Deployment has no
	// available replica after its rollout, its rollout exceeded its progress deadline, or an error
	// keeps the operator from checking it. Ready is False, and the message holds the error.
	ReasonCollectorFailing = "CollectorFailing"
	// ReasonNoData means a check of the collector failed within the grace after the operator's
	// start, or after the operator issued the collector's certificate, which the collector may not
	// have loaded yet, so its health is not known. Ready is Unknown, and the collector is still
	// used.
	ReasonNoData = "NoData"
	// ReasonAvailable means the last probe of a model endpoint succeeded. Ready is True.
	ReasonAvailable = "Available"
	// ReasonSecretNotFound means the Secret with the API key can't be used: it doesn't exist in
	// the operator's namespace, it doesn't carry the label vexplain.bedag.ch/llm-api-key: "true",
	// or it holds no value under the key. Ready is False, and no probe runs. The message names
	// the Secret, and never a value.
	ReasonSecretNotFound = "SecretNotFound"
	// ReasonUnauthorized means the endpoint rejected the API key. Ready is False.
	ReasonUnauthorized = "Unauthorized"
	// ReasonModelNotFound means the endpoint does not serve the model. Ready is False.
	ReasonModelNotFound = "ModelNotFound"
	// ReasonEndpointUnreachable means no usable answer came from the endpoint: a network error, a
	// timeout, a server error, or an answer outside the API. Ready is False, and the message says
	// which.
	ReasonEndpointUnreachable = "EndpointUnreachable"
)

// Reasons that the Ready condition of a Collector takes while the operator deploys its package and
// checks what the collector answers. They are open too: more reasons may follow.
const (
	// ReasonProgressing means the Deployment of the collector is rolling out: the Deployment
	// controller hasn't seen its spec yet, a replica of the spec is missing or still starting, or
	// an older one is left. The collector that answers may be an older one, or none yet, so the
	// operator asks it nothing. Ready is Unknown, and the collector is still used.
	ReasonProgressing = "Progressing"
	// ReasonPackageInvalid means the collector's answer to GetInfo or GetCapabilities is malformed:
	// it names no collector or version, declares a type of evidence outside the pattern or without a
	// schema, or holds more than status.capabilities can. Ready is False, and the message says what.
	ReasonPackageInvalid = "PackageInvalid"
	// ReasonIncompatibleAPI means the collector speaks no version of the collector API that this
	// version of the operator knows. Ready is False, and the collector gets no requests.
	ReasonIncompatibleAPI = "IncompatibleAPI"
	// ReasonSettingsInvalid means spec.settings fail the check against the settings schema that the
	// collector declares, or the collector's own check. Ready is False, and the message gives the
	// first problems.
	ReasonSettingsInvalid = "SettingsInvalid"
	// ReasonMissingPermissions means the service account of the collector lacks permissions that the
	// collector declares that it needs. Ready is False, and the message lists them. The operator
	// grants none: an admin binds the roles.
	ReasonMissingPermissions = "MissingPermissions"
	// ReasonRuntimeConfigInvalid means what the collector's CollectorRuntimeConfig shapes can't be
	// written: a template doesn't decode as the object that it shapes, the CollectorRuntimeConfig
	// that the Collector names doesn't exist, or the API server refuses the service account or the
	// Deployment that it shapes, as invalid, as a bad request or as forbidden, such as by an
	// admission webhook or a quota. Ready is False, the message says why, and what runs stays as it
	// was.
	ReasonRuntimeConfigInvalid = "RuntimeConfigInvalid"
)

// Reasons that the Ready condition of a Playbook takes when it can't be used. Its message names the
// collector, rule, input or playbook at fault. The set is open too.
const (
	// ReasonCollectorMissing means a Collector that the playbook names doesn't exist. Ready is False.
	ReasonCollectorMissing = "CollectorMissing"
	// ReasonTypeNotProduced means a Collector that the playbook names doesn't produce the type of
	// evidence that the playbook asks of it, as the capabilities in its status say. Ready is False.
	ReasonTypeNotProduced = "TypeNotProduced"
	// ReasonRuleMissing means a Rule that a step of the pipeline names doesn't exist. Ready is False.
	ReasonRuleMissing = "RuleMissing"
	// ReasonRuleNotReady means a Rule that a step of the pipeline names isn't Ready. Ready is False.
	ReasonRuleNotReady = "RuleNotReady"
	// ReasonInputMissing means a rule of the pipeline names an input that the playbook's evidence
	// doesn't supply: no piece of evidence has the name, or the one that has it is of another type.
	// Ready is False.
	ReasonInputMissing = "InputMissing"
	// ReasonConflict means another playbook, an older one, takes subjects of the same type, whatever
	// Collector delivers them. Only one playbook may, so that each subject keeps one verdict. Ready is
	// False for the newer of the two.
	ReasonConflict = "Conflict"
)

// ReasonEvaluationErrors is the reason of the Evaluated condition of a Rule while findings can't be
// evaluated: its CEL failed on a finding, hit its cost limit or ran past a bound on time, an input of
// the rule was missing, its match failed for a finding of the subject, or a playbook ran the rule while
// it wasn't Ready. Evaluated is False, and the message gives how many findings. The set of reasons is
// open too.
const ReasonEvaluationErrors = "EvaluationErrors"

// ReasonNoEvaluationErrors is the reason of the Evaluated condition of a Rule while its last evaluations
// could evaluate it for every finding. Evaluated is True.
const ReasonNoEvaluationErrors = "NoEvaluationErrors"
