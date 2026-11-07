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
	// platforms lists the platforms that the pods which run the digest in this cluster run on, from
	// their nodes, as os/architecture, or os/architecture/variant when the node has one. It holds at
	// most 8. The hub asks for the evidence of the image again when it lists a platform that no
	// manifest of the facts covers: at once for a platform that its last such request wasn't for, and
	// otherwise with the backoff of failed attempts, a day at most, since an image may not offer every
	// platform. It is empty when the cluster doesn't say, and then asks for nothing.
	// +optional
	// +listType=set
	// +kubebuilder:validation:MaxItems=8
	// +kubebuilder:validation:items:MinLength=1
	// +kubebuilder:validation:items:MaxLength=64
	// +kubebuilder:validation:items:Pattern=`^[a-z0-9]+/[a-z0-9_]+(/[a-z0-9]+)?$`
	Platforms []string `json:"platforms,omitempty"`
	// exposure is how far the workloads that run the digest in this cluster can be reached: the highest of
	// their exposures, with Unknown counted above Controlled, since a workload whose exposure is unknown
	// may be open. It is the system exposure of SSVC's deployer tree. It is empty until the cluster's
	// collectors of exposure have said what they know. More values may follow.
	// +optional
	Exposure *SSVCExposure `json:"exposure,omitempty"`
	// firstSeenTime is when the digest was first seen running in this cluster.
	// +required
	FirstSeenTime *metav1.Time `json:"firstSeenTime,omitempty"`
}

// SSVCExposure is how far workloads can be reached, the second input of SSVC's deployer tree. Open
// enum; more values may follow.
// +kubebuilder:validation:Enum=Small;Controlled;Open;Unknown
type SSVCExposure string

const (
	// SSVCExposureSmall means the workloads are reachable only from their own namespaces.
	SSVCExposureSmall SSVCExposure = "Small"
	// SSVCExposureControlled means the workloads are reachable indirectly, one hop behind an exposed
	// workload, or from beyond their namespaces.
	SSVCExposureControlled SSVCExposure = "Controlled"
	// SSVCExposureOpen means a workload is exposed externally.
	SSVCExposureOpen SSVCExposure = "Open"
	// SSVCExposureUnknown means no exposure is known of a workload, as when no collector has reported
	// any. Urgency counts it as Open.
	SSVCExposureUnknown SSVCExposure = "Unknown"
)

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

// ScanFailure says that the attempts of a collector to deliver evidence about the digest have failed
// since its last success, and why the last one did.
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
// type: the manifests of each platform, what evidence there is, and why the attempts of a collector
// to collect it failed. vexplain writes them from the evidence and the failures of the collectors.
type ImageFacts struct {
	// manifests has one entry for each platform of the image that the evidence names, with the
	// digest of its manifest. One manifest can be listed under two platforms, as an index can list it
	// under linux/arm64 and under linux/arm64/v8. They are the manifests that the last success that
	// named any found: a success of a source that names manifests replaces the list, since the scan
	// of an image says which of its manifests run. A failure leaves them as they were.
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
	// failures has one entry for each source whose attempts have failed since its last success: why
	// its last attempt failed, and how many have failed in a row. A failure of one source neither
	// replaces another's nor starts its count again, and a success of a source removes its entry.
	// +optional
	// +listType=map
	// +listMapKey=source
	// +kubebuilder:validation:MaxItems=8
	Failures []ScanFailure `json:"failures,omitempty"`
}

// ScanState says how far the scan of an image goes: Scanned, Pending, or the reason why the last
// attempt of a collector to deliver its evidence failed, as its ScanFailure says. It is an open
// vocabulary, as the reasons of the failures are: a word in CamelCase.
// +kubebuilder:validation:MinLength=1
// +kubebuilder:validation:MaxLength=64
// +kubebuilder:validation:Pattern=`^[A-Z][A-Za-z0-9]*$`
type ScanState string

const (
	// ScanStateScanned means that every manifest of the image's facts has a sheet with a verdict.
	ScanStateScanned ScanState = "Scanned"
	// ScanStatePending means that the image waits for its scan, or for the sheet of a manifest, and that no
	// attempt to deliver its evidence has failed since the last success.
	ScanStatePending ScanState = "Pending"
)

// ImageSummary answers how bad an image is, and feeds the columns of its ImageInventory (decision
// 0039). The hub writes it from the sheets of the image's manifests, its facts and the entries of the
// clusters, whenever one of them changes, and writes nothing else of the object: each cluster writes its
// own entry, and a write of the summary never undoes one.
// +kubebuilder:validation:XValidation:rule="has(self.open) == has(self.fixable)",message="open and fixable come together, from the sheets of the image's manifests"
// +kubebuilder:validation:XValidation:rule="!has(self.open) || self.fixable <= self.open",message="fixable counts no more findings than open"
// +kubebuilder:validation:XValidation:rule="self.scanState != 'Scanned' || has(self.open)",message="a Scanned image has the open findings of its sheets"
type ImageSummary struct {
	// image is the name of the image: the first of the repositories that the entries of the clusters
	// list, sorted. It is absent when they list none, as for an image ID.
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=255
	Image *string `json:"image,omitempty"`
	// workloads is the number of workloads that run the image, over every cluster.
	// +required
	// +kubebuilder:validation:Minimum=0
	Workloads *int32 `json:"workloads,omitempty"`
	// namespaces is the number of namespaces in which the image runs, over every cluster: a namespace of
	// the same name in two clusters counts twice.
	// +required
	// +kubebuilder:validation:Minimum=0
	Namespaces *int32 `json:"namespaces,omitempty"`
	// scanState says how far the scan of the image goes: Scanned when every manifest of its facts has a
	// sheet with a verdict, else the reason of the failure that the facts hold, the first by its
	// collector's name, and Pending otherwise. More values may follow.
	// +required
	ScanState ScanState `json:"scanState,omitempty"`
	// open is the most open findings that a sheet of the image's manifests counts. It is the most, and
	// not the sum: the platforms of an image almost always share their findings, and a sum would count a
	// vulnerability once for each platform. It is absent while no manifest of the image has a sheet with
	// a verdict, which says nothing about its findings.
	// +optional
	// +kubebuilder:validation:Minimum=0
	Open *int32 `json:"open,omitempty"`
	// fixable is the most fixable findings that a sheet of the image's manifests counts, for the reason
	// that open gives. It is absent when open is.
	// +optional
	// +kubebuilder:validation:Minimum=0
	Fixable *int32 `json:"fixable,omitempty"`
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
	// is, and why the attempts of a collector to collect it failed.
	// +optional
	Facts *ImageFacts `json:"facts,omitempty"`
	// summary answers how bad the image is, and feeds the columns of the object (decision 0039): its
	// name, its workloads and namespaces over every cluster, its scan state, and the most open and
	// fixable findings that a sheet of its manifests counts. The hub writes it, and nothing else writes
	// it. It is absent until the hub has summarized the image.
	// +optional
	Summary *ImageSummary `json:"summary,omitempty"`
	// No conditions: nothing sets them. What the evidence says, and why the last attempt failed, is
	// in facts.
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories={vexplain,vexplain-data}
// +kubebuilder:printcolumn:name="Image",type=string,JSONPath=`.status.summary.image`
// +kubebuilder:printcolumn:name="Workloads",type=integer,JSONPath=`.status.summary.workloads`
// +kubebuilder:printcolumn:name="Namespaces",type=integer,JSONPath=`.status.summary.namespaces`
// +kubebuilder:printcolumn:name="Scan State",type=string,JSONPath=`.status.summary.scanState`
// +kubebuilder:printcolumn:name="Open",type=integer,JSONPath=`.status.summary.open`
// +kubebuilder:printcolumn:name="Fixable",type=integer,JSONPath=`.status.summary.fixable`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// +kubebuilder:printcolumn:name="Platforms",type=string,JSONPath=`.status.facts.manifests[*].platform`,priority=1
// +kubebuilder:validation:XValidation:rule="self.metadata.name == self.spec.digest.replace(':', '-')",message="name must be the digest with ':' replaced by '-'"

// ImageInventory records one reported image digest, and the clusters in which it runs. Its status
// also holds the facts that the evidence of the digest says, and a summary of the image that its
// columns read. It is cluster-scoped. Its name is the digest with ':' replaced by '-', so no column
// shows the digest again.
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
