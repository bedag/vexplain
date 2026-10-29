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

// LLMAPIKeyLabel is the label that a Secret must carry, with the value "true", before a
// ModelConfig may use it. The operator never loads a Secret without it, so whoever may write a
// ModelConfig can't have the operator send any other Secret of its namespace to an endpoint.
const LLMAPIKeyLabel = "vexplain.bedag.ch/llm-api-key"

// Provider says which API an endpoint speaks. Open enum; more values may follow.
// +kubebuilder:validation:Enum=OpenAICompatible
type Provider string

const (
	// ProviderOpenAICompatible is an endpoint that speaks the chat completions API of OpenAI.
	ProviderOpenAICompatible Provider = "OpenAICompatible"
)

// ModelConfigSpec says how the operator reaches a language model.
type ModelConfigSpec struct {
	// provider says which API the endpoint speaks. It defaults to OpenAICompatible, the only value
	// so far. More values may follow.
	// +optional
	// +kubebuilder:default=OpenAICompatible
	Provider *Provider `json:"provider,omitempty"`
	// endpoint is the base URL of the API, such as https://llm.example/v1. HTTPS only, because the
	// API key travels with every request.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=2048
	// +kubebuilder:validation:Pattern=`^https://`
	Endpoint string `json:"endpoint,omitempty"`
	// model is the name of the model, as the endpoint knows it.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Model string `json:"model,omitempty"`
	// apiKeySecretRef names a Secret in the operator namespace that carries the label
	// vexplain.bedag.ch/llm-api-key: "true", and the key of the Secret that holds the API key.
	// Unlabelled Secrets are treated as missing.
	// +required
	APIKeySecretRef SecretKeyRef `json:"apiKeySecretRef,omitzero"`
	// requestTimeoutSeconds bounds each request to the endpoint, in seconds. It defaults to 60.
	// The probe of the endpoint has its own bound of 10 seconds.
	// +optional
	// +kubebuilder:default=60
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=600
	RequestTimeoutSeconds *int32 `json:"requestTimeoutSeconds,omitempty"`
	// maxConcurrentRequests is the number of requests that the operator has in flight to the
	// endpoint at once. It defaults to 2.
	// +optional
	// +kubebuilder:default=2
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=64
	MaxConcurrentRequests *int32 `json:"maxConcurrentRequests,omitempty"`
	// temperatureMilli is the sampling temperature in thousandths, so 200 is 0.2. It defaults to
	// 200.
	// +optional
	// +kubebuilder:default=200
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=2000
	TemperatureMilli *int32 `json:"temperatureMilli,omitempty"`
	// probeIntervalSeconds is how often the operator probes the endpoint, in seconds. It defaults
	// to 300. A change of the Secret is probed at once.
	// +optional
	// +kubebuilder:default=300
	// +kubebuilder:validation:Minimum=30
	// +kubebuilder:validation:Maximum=86400
	ProbeIntervalSeconds *int32 `json:"probeIntervalSeconds,omitempty"`
}

// ModelConfigStatus is what the last probe of the endpoint found.
type ModelConfigStatus struct {
	// conditions represent the current state of the ModelConfig.
	// The Ready condition says whether the model can be used. It is True with reason Available when
	// the last probe succeeded. It is False with reason SecretNotFound when the Secret with the API
	// key is missing, does not carry the label vexplain.bedag.ch/llm-api-key: "true", or holds no
	// value under the key; no probe runs then. It is False with reason Unauthorized when the
	// endpoint rejected the key, ModelNotFound when the endpoint does not serve the model, and
	// EndpointUnreachable when no usable answer came, with the reason in the message. It is False
	// with reason UnknownValue when spec.provider is a provider that this version of the operator
	// does not know.
	// +optional
	// +listType=map
	// +listMapKey=type
	// +kubebuilder:validation:MaxItems=8
	Conditions []metav1.Condition `json:"conditions,omitempty"`
	// lastProbeTime is when the operator last probed the endpoint. It is not set when no probe
	// could run, for example when the Secret is missing.
	// +optional
	LastProbeTime *metav1.Time `json:"lastProbeTime,omitempty"`
	// lastProbeLatencyMilliseconds is how long the last probe took, in milliseconds. It is set
	// only while Ready is True, so a latency never stands next to a failure.
	// +optional
	// +kubebuilder:validation:Minimum=0
	LastProbeLatencyMilliseconds *int64 `json:"lastProbeLatencyMilliseconds,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Endpoint",type=string,JSONPath=`.spec.endpoint`
// +kubebuilder:printcolumn:name="Model",type=string,JSONPath=`.spec.model`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Reason",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].reason`
// +kubebuilder:printcolumn:name="Latency(ms)",type=integer,JSONPath=`.status.lastProbeLatencyMilliseconds`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// ModelConfig describes the connection to a language model: the endpoint, the model, the Secret
// with the API key and the request settings. It is cluster-scoped and lives on the hub.
//
// The operator probes the endpoint, at the interval of the spec and whenever the spec or the
// Secret changes, and reports in the status whether the model can be used.
type ModelConfig struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines how to reach the model
	// +required
	Spec ModelConfigSpec `json:"spec"`

	// status defines the observed state of ModelConfig
	// +optional
	Status ModelConfigStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// ModelConfigList contains a list of ModelConfig
type ModelConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []ModelConfig `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &ModelConfig{}, &ModelConfigList{})
		return nil
	})
}
