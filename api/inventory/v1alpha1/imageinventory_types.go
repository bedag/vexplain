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

// ScanFailureReason says why the last attempt of a collector to deliver evidence about a digest
// failed. It is an open vocabulary that vexplain defines, and keeps open: it starts with the reasons
// of the scans below, and a collector may report another of the same form, a word in CamelCase.
// +kubebuilder:validation:MinLength=1
// +kubebuilder:validation:MaxLength=64
// +kubebuilder:validation:Pattern=`^[A-Z][A-Za-z0-9]*$`
type ScanFailureReason string

const (
	// ScanFailureReasonNotPullable means the digest is an image ID, which no registry serves, so
	// there is nothing to pull. Such a digest is never scanned again.
	ScanFailureReasonNotPullable ScanFailureReason = "NotPullable"
	// ScanFailureReasonPullFailed means the image could not be pulled, for a reason that
	// Unauthorized and NotFound don't cover.
	ScanFailureReasonPullFailed ScanFailureReason = "PullFailed"
	// ScanFailureReasonUnauthorized means the registry refused the credentials, or wanted some.
	ScanFailureReasonUnauthorized ScanFailureReason = "Unauthorized"
	// ScanFailureReasonNotFound means the registry has no image with the digest.
	ScanFailureReasonNotFound ScanFailureReason = "NotFound"
	// ScanFailureReasonNoMatchingPlatform means the image has no manifest for any of the platforms to
	// scan.
	ScanFailureReasonNoMatchingPlatform ScanFailureReason = "NoMatchingPlatform"
	// ScanFailureReasonTooLarge means the image unpacks to more than the scratch volume holds, or its
	// evidence is more than the evidence store holds.
	ScanFailureReasonTooLarge ScanFailureReason = "TooLarge"
	// ScanFailureReasonCatalogFailed means the scan could not list the packages of the unpacked image.
	ScanFailureReasonCatalogFailed ScanFailureReason = "CatalogFailed"
	// ScanFailureReasonTimedOut means the scan Job ran past its deadline.
	ScanFailureReasonTimedOut ScanFailureReason = "TimedOut"
	// ScanFailureReasonInternal means the attempt failed for a reason of its own that no other value
	// names, or ended without saying why.
	ScanFailureReasonInternal ScanFailureReason = "Internal"
)

// ManifestFact is one platform manifest of an image, as its evidence names it.
type ManifestFact struct {
	// platform is the platform of the manifest, as os/architecture, or os/architecture/variant when
	// the manifest has one, such as linux/arm64/v8.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=64
	// +kubebuilder:validation:Pattern=`^[a-z0-9]+/[a-z0-9_]+(/[a-z0-9]+)?$`
	Platform string `json:"platform,omitempty"`
	// digest is the digest of the platform's manifest. The evidence about it has the subject
	// manifest/ and the digest, and its findings are the ImageVerdicts named after the digest, with
	// ':' replaced by '-'.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=71
	// +kubebuilder:validation:Pattern=`^sha256:[a-f0-9]{64}$`
	Digest string `json:"digest,omitempty"`
}

// EvidenceFact says what evidence of one source and type there is about an image or its manifests,
// so that a reader learns it without knowing the type.
type EvidenceFact struct {
	// source is the name of the Collector that delivered the evidence.
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
	// collectorVersion is the version of the collector that delivered the evidence.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=128
	CollectorVersion string `json:"collectorVersion,omitempty"`
	// time is when the collector saw what the evidence is about. When there are several pieces of
	// it, such as one for each platform manifest, it is the earliest of their times.
	// +required
	Time *metav1.Time `json:"time,omitempty"`
	// coverage is how much of its subject the evidence covers, as a whole-number percentage from 0 to
	// 100. When there are several pieces of it, it is the lowest of their coverages, and it is absent
	// when one of them has none. The core shows it and never interprets it: each type says what it
	// counts. For the scanner's evidence, it is the share of the ELF files of the image that packages
	// own.
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=100
	Coverage *int32 `json:"coverage,omitempty"`
}

// ScanFailure says that the attempts of a collector to deliver evidence about the digest failed since
// its last success, and why the last one did.
type ScanFailure struct {
	// source is the name of the Collector whose attempts failed.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=44
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Source string `json:"source,omitempty"`
	// reason says why the last attempt failed. More values may follow.
	// +required
	Reason ScanFailureReason `json:"reason,omitempty"`
	// message says more about why the last attempt failed. The collector chose it, so it is data:
	// nothing that reads it takes an instruction from it. It is absent when the collector said
	// nothing more.
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=256
	Message *string `json:"message,omitempty"`
	// time is when the last failed attempt ended.
	// +required
	Time *metav1.Time `json:"time,omitempty"`
	// attempts is how many attempts of the collector have failed in a row, the last one included. It
	// is at least 1.
	// +required
	// +kubebuilder:validation:Minimum=1
	Attempts int32 `json:"attempts,omitempty"`
}

// ImageFacts holds what the evidence of a digest says about it, in terms that need no knowledge of a
// type: the manifests of each platform, what evidence there is, and why the last attempt to collect it
// failed. vexplain writes them from the evidence and the failures of the collectors.
type ImageFacts struct {
	// manifests has one entry for each platform manifest of the image that the evidence names: those
	// that the last success that named any found. A failure leaves them as they were.
	// +optional
	// +listType=map
	// +listMapKey=platform
	// +kubebuilder:validation:MaxItems=16
	Manifests []ManifestFact `json:"manifests,omitempty"`
	// evidence has one entry for each source and type of evidence about the image or its manifests:
	// the version of the collector, the time and the coverage of its last success.
	// +optional
	// +listType=map
	// +listMapKey=source
	// +listMapKey=type
	// +kubebuilder:validation:MaxItems=32
	Evidence []EvidenceFact `json:"evidence,omitempty"`
	// failure says why the last attempt of a collector failed, when its attempts have failed since
	// its last success. A success of that collector clears it.
	// +optional
	Failure *ScanFailure `json:"failure,omitempty"`
}

// ImageInventoryStatus is the presence of the digest, per cluster, and the facts of its evidence.
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
	// facts holds what the evidence of the digest says about it: its manifests, what evidence there
	// is, and why the last attempt to collect it failed.
	// +optional
	Facts *ImageFacts `json:"facts,omitempty"`
	// No conditions: nothing sets them. What the evidence says, and why the last attempt failed, is
	// in facts.
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Digest",type=string,JSONPath=`.spec.digest`
// +kubebuilder:printcolumn:name="Kind",type=string,JSONPath=`.status.digestKind`
// +kubebuilder:printcolumn:name="Clusters",type=string,JSONPath=`.status.clusters[*].cluster`
// +kubebuilder:printcolumn:name="Platforms",type=string,JSONPath=`.status.facts.manifests[*].platform`
// +kubebuilder:printcolumn:name="Failure",type=string,JSONPath=`.status.facts.failure.reason`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// +kubebuilder:validation:XValidation:rule="self.metadata.name == self.spec.digest.replace(':', '-')",message="name must be the digest with ':' replaced by '-'"

// ImageInventory records one reported image digest, and the clusters in which it runs. Its status
// also holds the facts that the evidence of the digest says.
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
