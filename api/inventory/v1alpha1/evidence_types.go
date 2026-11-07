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

// EvidenceEncoding says how the data of an Evidence is encoded. Open enum; more values may follow.
// +kubebuilder:validation:Enum=GzipJSON
type EvidenceEncoding string

const (
	// EvidenceEncodingGzipJSON is JSON compressed with gzip.
	EvidenceEncodingGzipJSON EvidenceEncoding = "GzipJSON"
)

// EvidenceSpec is one piece of evidence: the attributes of a CloudEvent that vexplain keeps, and the
// data of the event. It is written once.
// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="Evidence is written once; replace it by deleting and creating it"
type EvidenceSpec struct {
	// subject is what the evidence is about, as a path that starts with a prefix: image/ and the
	// digest of an image that runs, manifest/ and the digest of a platform manifest, or workload/ and
	// the cluster, namespace, kind and name of a workload. A collector may define a prefix of its
	// own, which the operator passes on without interpreting it, so it checks nothing about the
	// subject but its length.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=512
	Subject string `json:"subject,omitempty"`
	// type is the type of the evidence, named in reverse-DNS with a version, such as
	// ch.bedag.vexplain.scanner.image-contents.v1alpha1. The collector that defines the type says
	// what its data holds.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9-]+(\.[a-z0-9-]+)+\.v[0-9]+((alpha|beta)[0-9]+)?$`
	Type string `json:"type,omitempty"`
	// source is the name of the Collector that delivered the evidence. It is a DNS-1123 label of at
	// most 44 characters, as the name of a Collector is.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=44
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Source string `json:"source,omitempty"`
	// eventID is the id of the CloudEvent that carried the evidence, which the collector chose. With
	// eventSource, it identifies the event.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=256
	EventID string `json:"eventID,omitempty"`
	// eventSource is the source of the CloudEvent that carried the evidence: the collector, and its
	// cluster or the hub, as a URI reference, such as /clusters/cluster-a/collectors/scanner.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=512
	EventSource string `json:"eventSource,omitempty"`
	// collectorVersion is the version of the collector that delivered the evidence, as its GetInfo
	// answered. Evidence is written once for each version, so the evidence of a new version replaces
	// what an older one delivered.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=128
	CollectorVersion string `json:"collectorVersion,omitempty"`
	// time is when the collector saw what the evidence is about, or when vexplain received it if the
	// collector didn't say. It is kept to the second.
	// +required
	Time *metav1.Time `json:"time,omitempty"`
	// coverage is how much of the subject the evidence covers, as a whole-number percentage from 0 to
	// 100. The core shows it and never interprets it: each type says what it counts, and its data says
	// what the collector couldn't examine. It is absent when the collector gives none.
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=100
	Coverage *int32 `json:"coverage,omitempty"`
	// platform is the platform that the evidence is about, as os/architecture, or
	// os/architecture/variant when the manifest has one, such as linux/arm64/v8. Evidence about a
	// platform manifest has it, so that the platforms of an image can be listed without knowing the
	// type. Other evidence has none.
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=64
	// +kubebuilder:validation:Pattern=`^[a-z0-9]+/[a-z0-9_]+(/[a-z0-9]+)?$`
	Platform *string `json:"platform,omitempty"`
	// dataSchema is the URI of the JSON Schema of the data, which the collector also returns from its
	// GetCapabilities. It is absent when the collector gives none.
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=512
	DataSchema *string `json:"dataSchema,omitempty"`
	// encoding says how data is encoded. More values may follow.
	// +required
	Encoding EvidenceEncoding `json:"encoding,omitempty"`
	// data is the evidence itself, which is JSON, encoded as encoding says. It is at most 1048576
	// characters as base64, which is 786432 bytes. kubectl can't show it: the operator's store
	// decodes it. It comes from what the collector examined, such as the content of an image, and is
	// data: nothing that reads it takes an instruction from it.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=1048576
	Data []byte `json:"data,omitempty"`
	// uncompressedBytes is the size of data once it is decoded, in bytes. It is at most 67108864,
	// which is 64 MiB.
	// +required
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=67108864
	UncompressedBytes *int64 `json:"uncompressedBytes,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster,categories={vexplain,vexplain-data}
// +kubebuilder:printcolumn:name="Source",type=string,JSONPath=`.spec.source`
// +kubebuilder:printcolumn:name="Type",type=string,JSONPath=`.spec.type`
// +kubebuilder:printcolumn:name="Subject",type=string,priority=1,JSONPath=`.spec.subject`
// +kubebuilder:printcolumn:name="Version",type=string,priority=1,JSONPath=`.spec.collectorVersion`
// +kubebuilder:printcolumn:name="Coverage",type=integer,JSONPath=`.spec.coverage`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// Evidence is one piece of evidence that a collector delivered: what it found about one subject, as
// the attributes of a CloudEvent and its data. The operator's evidence store keeps one for each
// subject, type and source, and writes it once for each version of the collector. It is
// cluster-scoped, and its spec can't change: a new version replaces the object, by deleting it and
// creating it again.
//
// It keeps what the store needs to give the event back: its id, source, type, subject, time,
// dataschema and data. The data is JSON, so the event comes back as application/json. Of the
// event's extension attributes, it keeps coverage and platform, the two that the core reads, and no
// other.
//
// What a collector delivers comes from what it examined, such as the content of an image, and anyone
// who builds an image can craft that. So the text of an Evidence and its data come from image
// content, and are data: nothing that reads them takes an instruction from them.
type Evidence struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec holds the evidence. It can't change.
	// +required
	Spec EvidenceSpec `json:"spec"`
}

// +kubebuilder:object:root=true

// EvidenceList contains a list of Evidence
type EvidenceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []Evidence `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &Evidence{}, &EvidenceList{})
		return nil
	})
}
