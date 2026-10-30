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

// EvidenceEncoding says how the evidence of an ImagePackages is encoded. Open enum; more values may
// follow.
// +kubebuilder:validation:Enum=GzipJSON
type EvidenceEncoding string

const (
	// EvidenceEncodingGzipJSON is JSON compressed with gzip.
	EvidenceEncodingGzipJSON EvidenceEncoding = "GzipJSON"
)

// ImagePackagesSpec is what one scan found in one platform manifest. It is written once.
// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="ImagePackages are written once; replace one by deleting and creating it"
type ImagePackagesSpec struct {
	// manifestDigest is the digest of the platform manifest that was scanned.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=71
	// +kubebuilder:validation:Pattern=`^sha256:[a-f0-9]{64}$`
	ManifestDigest string `json:"manifestDigest,omitempty"`
	// platform is the platform of the manifest, as os/architecture, or os/architecture/variant when
	// the manifest has one, such as linux/arm64/v8.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=64
	// +kubebuilder:validation:Pattern=`^[a-z0-9]+/[a-z0-9_]+(/[a-z0-9]+)?$`
	Platform string `json:"platform,omitempty"`
	// scannerImage is the image of the scanner that made the evidence. A scan by a newer scanner
	// replaces the whole object.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=512
	ScannerImage string `json:"scannerImage,omitempty"`
	// scannedTime is when the scan finished.
	// +required
	ScannedTime *metav1.Time `json:"scannedTime,omitempty"`
	// encoding says how evidence is encoded. More values may follow.
	// +required
	Encoding EvidenceEncoding `json:"encoding,omitempty"`
	// evidence is what the scan found in the manifest: the packages of the image, and the facts that
	// the rules use about them. It is encoded as encoding says, and is at most 1048576 characters as
	// base64, which is 786432 bytes. kubectl can't show it: the operator's store decodes it.
	// +required
	// +kubebuilder:validation:MaxLength=1048576
	Evidence []byte `json:"evidence,omitempty"`
	// uncompressedBytes is the size of the evidence once it is decoded, in bytes.
	// +required
	// +kubebuilder:validation:Minimum=0
	UncompressedBytes *int64 `json:"uncompressedBytes,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Platform",type=string,JSONPath=`.spec.platform`
// +kubebuilder:printcolumn:name="Scanned",type=date,JSONPath=`.spec.scannedTime`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// +kubebuilder:validation:XValidation:rule="self.metadata.name == self.spec.manifestDigest.replace(':', '-')",message="name must be the manifest digest with ':' replaced by '-'"

// ImagePackages holds the evidence of one scan of one platform manifest: the packages that the scan
// found, and the facts that the rules use about them. It is cluster-scoped, and written once: to
// replace one, delete it and create it again. Its name is the manifest digest with ':' replaced by
// '-'.
type ImagePackages struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec holds the evidence. It can't change.
	// +required
	Spec ImagePackagesSpec `json:"spec"`
}

// +kubebuilder:object:root=true

// ImagePackagesList contains a list of ImagePackages
type ImagePackagesList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []ImagePackages `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &ImagePackages{}, &ImagePackagesList{})
		return nil
	})
}
