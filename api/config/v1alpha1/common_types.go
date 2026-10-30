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
	// ReasonHealthy means the last report of a collector was a success. Ready is True.
	ReasonHealthy = "Healthy"
	// ReasonCollectorFailing means the last report of a collector was a failure. Ready is False,
	// and the message holds the error that the collector reported.
	ReasonCollectorFailing = "CollectorFailing"
	// ReasonNoData means the collector has not reported since the operator started, so its health
	// is not known. Ready is Unknown.
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
