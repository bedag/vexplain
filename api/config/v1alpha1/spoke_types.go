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

// Condition types of a Spoke.
const (
	// ConditionConnected says whether the hub can reach the spoke and the credentials work.
	ConditionConnected = "Connected"
	// ConditionSynced says whether the hub's last pull from the spoke succeeded.
	ConditionSynced = "Synced"
)

// Reasons of the conditions of a Spoke. The set is open: more reasons may follow.
const (
	// ReasonConnected means the hub's last call to the spoke worked: it reached the spoke's endpoint, the token works,
	// and the cluster is the one that the hub first recorded.
	ReasonConnected = "Connected"
	// ReasonUnreachable means the hub can't reach the spoke's endpoint.
	ReasonUnreachable = "Unreachable"
	// ReasonCredentialsInvalid means the spoke rejected the credentials, or the Secret that holds them can't be used, as
	// when the endpoint that it names answers no identity that a Kubernetes API server gives: a UUID.
	ReasonCredentialsInvalid = "CredentialsInvalid"
	// ReasonIdentityChanged means the cluster behind the spoke's endpoint is not the one the hub first recorded in
	// status.clusterID, so the hub pulls nothing from it.
	ReasonIdentityChanged = "IdentityChanged"
	// ReasonTokenExpired means the token in the credentials has expired.
	ReasonTokenExpired = "TokenExpired"
	// ReasonSyncing means a pull from the spoke is in progress.
	ReasonSyncing = "Syncing"
	// ReasonSynced means the hub has copied what the spoke holds, and copies each change.
	ReasonSynced = "Synced"
	// ReasonNameInUse means the hub's own cluster has the Spoke's name, so the hub copies nothing under it: the copies
	// would take the keys of the hub's own records, and their deletion delete them.
	ReasonNameInUse = "NameInUse"
	// ReasonOwnCluster means the spoke's endpoint belongs to the hub's own cluster, so the hub copies nothing from it:
	// the copies would carry the hub's own identity, and they and the hub's own entries would replace each other.
	ReasonOwnCluster = "OwnCluster"
	// ReasonClusterNameMismatch means the spoke names its cluster otherwise than the Spoke is named, in its
	// OperatorConfig or by the default name, so the hub copies nothing from it and keeps the copies that it made: the
	// spoke's records carry the other name, and the hub would read their absence under the Spoke's as "runs nothing".
	ReasonClusterNameMismatch = "ClusterNameMismatch"
	// ReasonIdentityInUse means another Spoke records the identity of the cluster behind the spoke's endpoint already, so
	// the hub records it for this one neither, and copies nothing: two Spokes of one cluster would replace each other's
	// entries.
	ReasonIdentityInUse = "IdentityInUse"
)

// SpokeSpec records a remote cluster that the hub serves. The Spoke's name is the cluster's name.
type SpokeSpec struct {
	// labels describe the cluster, for the playbooks that apply to clusters with certain labels, as
	// OperatorConfig.clusterLabels does for the hub's own cluster. Keys are Kubernetes label keys and values are
	// label values.
	// +optional
	// +kubebuilder:validation:MaxProperties=32
	// +kubebuilder:validation:XValidation:rule="self.all(k, !format.qualifiedName().validate(k).hasValue())",message="every key must be a valid label key"
	// +kubebuilder:validation:XValidation:rule="self.all(k, !format.labelValue().validate(self[k]).hasValue())",message="every value must be a valid label value"
	Labels map[string]LabelValue `json:"labels,omitempty"`
	// credentialsSecretRef names the Secret, in the operator's namespace, that holds the credentials for the spoke.
	// +required
	CredentialsSecretRef SecretReference `json:"credentialsSecretRef,omitzero"`
}

// SpokeCollector is a collector of the spoke, as the spoke reported it.
type SpokeCollector struct {
	// name is the name of the collector.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name,omitempty"`
	// version is the version that the collector reported.
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=128
	Version *string `json:"version,omitempty"`
	// ready is the collector's Ready condition on the spoke: True, False or Unknown.
	// +optional
	// +kubebuilder:validation:Enum=True;False;Unknown
	Ready *metav1.ConditionStatus `json:"ready,omitempty"`
	// capabilities are what the collector declared, each produced type with its effective maxAgeSeconds.
	// +optional
	Capabilities *CollectorCapabilities `json:"capabilities,omitempty"`
}

// SpokeStatus is what the hub observed of the spoke.
type SpokeStatus struct {
	// conditions represent the current state of the Spoke. Connected says whether the hub reaches the spoke with
	// working credentials, and Synced whether its last pull succeeded. Ready is True when both are.
	// +optional
	// +listType=map
	// +listMapKey=type
	// +kubebuilder:validation:MaxItems=8
	Conditions []metav1.Condition `json:"conditions,omitempty"`
	// observedGeneration is the generation of the Spoke that the operator last acted on.
	// +optional
	// +kubebuilder:validation:Minimum=0
	ObservedGeneration *int64 `json:"observedGeneration,omitempty"`
	// clusterID is the identity that the cluster reported when the hub first connected. It may be cleared, but not
	// changed to another value, so that a spoke's endpoint can't silently come to point at another cluster.
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	ClusterID *string `json:"clusterID,omitempty"`
	// collectors are the collectors of the spoke.
	// +optional
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:MaxItems=64
	Collectors []SpokeCollector `json:"collectors,omitempty"`
	// lastSyncTime is when the hub's copy of the spoke last became current, as after the hub's start or a new token, or
	// last took a change of the spoke's records. While Synced is True, the copy stays current after it. Clearing
	// clusterID, to accept another cluster, clears it too, until the copy of that cluster is current.
	// +optional
	LastSyncTime *metav1.Time `json:"lastSyncTime,omitempty"`
	// tokenExpirationTime is when the token in the credentials expires, when it says so.
	// +optional
	TokenExpirationTime *metav1.Time `json:"tokenExpirationTime,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories=vexplain
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Reason",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].reason`
// +kubebuilder:printcolumn:name="Last sync",type=date,JSONPath=`.status.lastSyncTime`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// +kubebuilder:validation:XValidation:rule="self.metadata.name.size() <= 63 && self.metadata.name.matches('^[a-z0-9]([-a-z0-9]*[a-z0-9])?$')",message="the name is the cluster's name, so it must be a DNS label of at most 63 characters"

// Spoke records a remote cluster that the hub serves: how to reach it and how to label it. It is cluster-scoped and
// lives on the hub, and its name is the cluster's name.
type Spoke struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines how to reach the cluster
	// +required
	Spec SpokeSpec `json:"spec"`

	// status defines the observed state of Spoke
	// +optional
	// +kubebuilder:validation:XValidation:rule="!has(oldSelf.clusterID) || !has(self.clusterID) || self.clusterID == oldSelf.clusterID",message="status.clusterID can be cleared, but not changed to another value"
	Status SpokeStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// SpokeList contains a list of Spoke
type SpokeList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []Spoke `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &Spoke{}, &SpokeList{})
		return nil
	})
}
