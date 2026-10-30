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

// DigestKind says what the reported digest is. Open enum; more values may follow.
//
// The container runtime reports one of two kinds of digest for a running container, and only
// the first can be fetched from a registry.
// +kubebuilder:validation:Enum=RepoDigest;ImageID
type DigestKind string

const (
	// DigestKindRepoDigest is a repository digest: the digest of a manifest or of a multi-arch
	// index in a registry. The runtime also reports the repository it was pulled from.
	DigestKindRepoDigest DigestKind = "RepoDigest"
	// DigestKindImageID is an image ID: the digest of the image's configuration. No registry can
	// serve it, so the content of such an image can't be fetched.
	DigestKindImageID DigestKind = "ImageID"
)

// ImageInventorySpec identifies the image digest that an ImageInventory describes.
type ImageInventorySpec struct {
	// digest is the digest the container runtime reports for running containers:
	// a repository digest (often a multi-arch index) or an image ID.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=71
	// +kubebuilder:validation:Pattern=`^sha256:[a-f0-9]{64}$`
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="digest is immutable"
	Digest string `json:"digest,omitempty"`
}

// WorkloadReference points to a workload, and so to its WorkloadReport (phase 2).
type WorkloadReference struct {
	// apiGroup is the API group of the workload's kind. It is empty, or left out, for the core
	// group (bare pods).
	// +optional
	// +kubebuilder:validation:MaxLength=253
	APIGroup *string `json:"apiGroup,omitempty"`
	// kind is the kind of the workload, such as Deployment.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	Kind string `json:"kind,omitempty"`
	// namespace is the namespace of the workload.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	Namespace string `json:"namespace,omitempty"`
	// name is the name of the workload.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name,omitempty"`
}

// ClusterPresence says how a digest runs in one cluster.
type ClusterPresence struct {
	// cluster is the name of the cluster, as set in its OperatorConfig.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	Cluster string `json:"cluster,omitempty"`
	// clusterID is the identity of the cluster. Unlike the name, it never changes, so an entry
	// written under a former name can still be matched to its cluster.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=64
	ClusterID string `json:"clusterID,omitempty"`
	// namespaceCount is the number of namespaces in which the digest runs.
	// +required
	// +kubebuilder:validation:Minimum=0
	NamespaceCount *int32 `json:"namespaceCount,omitempty"`
	// workloadCount is the number of workloads that run the digest.
	// +required
	// +kubebuilder:validation:Minimum=0
	WorkloadCount *int32 `json:"workloadCount,omitempty"`
	// workloads lists the first 100 workloads, sorted by namespace, kind and name. If it is
	// shorter than workloadCount, the full list comes from the cluster's WorkloadReports.
	// +optional
	// +listType=map
	// +listMapKey=namespace
	// +listMapKey=kind
	// +listMapKey=name
	// +kubebuilder:validation:MaxItems=100
	Workloads []WorkloadReference `json:"workloads,omitempty"`
	// repositories lists the repositories the digest was pulled from.
	// +optional
	// +listType=set
	// +kubebuilder:validation:MaxItems=32
	// +kubebuilder:validation:items:MaxLength=255
	Repositories []string `json:"repositories,omitempty"`
	// firstSeenTime is when the digest was first seen running in this cluster.
	// +required
	FirstSeenTime *metav1.Time `json:"firstSeenTime,omitempty"`
}

// ImageInventoryStatus is the presence of the digest, per cluster.
type ImageInventoryStatus struct {
	// digestKind says what the digest is: a repository digest or an image ID. More values may follow.
	// +optional
	DigestKind *DigestKind `json:"digestKind,omitempty"`
	// clusters has one entry for every cluster in which the digest runs.
	// +optional
	// +listType=map
	// +listMapKey=cluster
	// +kubebuilder:validation:MaxItems=256
	Clusters []ClusterPresence `json:"clusters,omitempty"`
	// No conditions yet: nothing in phase 1 would set them. They arrive with the scanner.
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Digest",type=string,JSONPath=`.spec.digest`
// +kubebuilder:printcolumn:name="Kind",type=string,JSONPath=`.status.digestKind`
// +kubebuilder:printcolumn:name="Clusters",type=string,JSONPath=`.status.clusters[*].cluster`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// +kubebuilder:validation:XValidation:rule="self.metadata.name == self.spec.digest.replace(':', '-')",message="name must be the digest with ':' replaced by '-'"

// ImageInventory records one reported image digest, and the clusters in which it runs.
// It is cluster-scoped. Its name is the digest with ':' replaced by '-'.
type ImageInventory struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the digest that this object describes
	// +required
	Spec ImageInventorySpec `json:"spec"`

	// status defines the observed state of ImageInventory
	// +optional
	Status ImageInventoryStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// ImageInventoryList contains a list of ImageInventory
type ImageInventoryList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []ImageInventory `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &ImageInventory{}, &ImageInventoryList{})
		return nil
	})
}
