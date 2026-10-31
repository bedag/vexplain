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

// CollectorType says which source of data a Collector stands for. Open enum; more values may
// follow.
// +kubebuilder:validation:Enum=Workloads;Scanner
type CollectorType string

const (
	// CollectorTypeWorkloads is the pod inventory. It reads the pods of the cluster, takes the image
	// digests that their containers report, and maps each digest to the workloads that run it.
	CollectorTypeWorkloads CollectorType = "Workloads"
	// CollectorTypeScanner is the image scanner. For an image digest that needs facts, it runs a scan
	// Job in the operator's namespace. The Job pulls and unpacks the image and reports what it found,
	// and the operator records that in the ImageInventory of the digest, and in one ImagePackages for
	// each platform.
	CollectorTypeScanner CollectorType = "Scanner"
)

// WorkloadsCollectorSpec holds the settings of the Workloads collector. There are none yet. The
// empty object keeps a place for them, so that adding one later is not a breaking change.
type WorkloadsCollectorSpec struct{}

// ScannerCollectorSpec holds the settings of the built-in Scanner: how its scan Jobs run.
type ScannerCollectorSpec struct {
	// maxConcurrentScans is how many scan Jobs may run at once. It defaults to 2.
	// +optional
	// +kubebuilder:default=2
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=32
	MaxConcurrentScans *int32 `json:"maxConcurrentScans,omitempty"`
	// scanTimeoutSeconds is how long a scan Job may run before it is stopped, in seconds. It
	// defaults to 1800.
	// +optional
	// +kubebuilder:default=1800
	// +kubebuilder:validation:Minimum=60
	// +kubebuilder:validation:Maximum=21600
	ScanTimeoutSeconds *int32 `json:"scanTimeoutSeconds,omitempty"`
	// memoryLimitMebibytes is the memory limit of a scan Job's container, in mebibytes. It defaults
	// to 2048.
	// +optional
	// +kubebuilder:default=2048
	// +kubebuilder:validation:Minimum=256
	// +kubebuilder:validation:Maximum=65536
	MemoryLimitMebibytes *int32 `json:"memoryLimitMebibytes,omitempty"`
	// workspaceMebibytes is the size of the scratch volume an image is unpacked into, in mebibytes,
	// and so the largest unpacked image a scan accepts. It defaults to 10240.
	// +optional
	// +kubebuilder:default=10240
	// +kubebuilder:validation:Minimum=1024
	// +kubebuilder:validation:Maximum=1048576
	WorkspaceMebibytes *int32 `json:"workspaceMebibytes,omitempty"`
}

// CollectorSpec says which collector a Collector is, and holds the settings of that collector.
// It is a union: type is the discriminator, and the field named after the type, in lower camel
// case, holds the settings of that type.
// +kubebuilder:validation:XValidation:rule="has(self.workloads) == (self.type == 'Workloads')",message="workloads must be set exactly when type is Workloads"
// +kubebuilder:validation:XValidation:rule="has(self.scanner) == (self.type == 'Scanner')",message="scanner must be set exactly when type is Scanner"
type CollectorSpec struct {
	// type says which collector this is. More values may follow.
	// +required
	Type CollectorType `json:"type,omitempty"`
	// workloads holds the settings of the Workloads collector. It must be set when type is
	// Workloads, and must not be set for any other type.
	// +optional
	Workloads *WorkloadsCollectorSpec `json:"workloads,omitempty"`
	// scanner holds the settings of the Scanner collector. It must be set when type is Scanner, and
	// must not be set for any other type.
	// +optional
	Scanner *ScannerCollectorSpec `json:"scanner,omitempty"`
}

// CollectorStatus is the health of the collector, as far as the operator knows.
type CollectorStatus struct {
	// conditions represent the current state of the Collector.
	// The Ready condition says whether the collector works. It is True with reason Healthy when
	// the collector's last report was a success, and False with reason CollectorFailing, and the
	// error as its message, when the last report was a failure. It is Unknown with reason NoData
	// until the collector has reported since the operator started. It is False with reason
	// UnknownValue when spec.type is a type that this version of the operator does not know.
	// +listType=map
	// +listMapKey=type
	// +kubebuilder:validation:MaxItems=8
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
	// lastSuccessTime is when the collector last reported a success. A later failure leaves it
	// as it was, and so does a restart of the operator. The operator keeps health in memory, so
	// after a restart the field keeps its value until the collector reports a success.
	// +optional
	LastSuccessTime *metav1.Time `json:"lastSuccessTime,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Type",type=string,JSONPath=`.spec.type`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Reason",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].reason`
// +kubebuilder:printcolumn:name="Last Success",type=date,JSONPath=`.status.lastSuccessTime`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// +kubebuilder:validation:XValidation:rule="self.metadata.name == self.spec.type.lowerAscii()",message="a Collector is named after its type, in lower case"

// Collector is one source of data for the operator. It is cluster-scoped, and there is one per
// type, named after the type in lower case: the Workloads collector is named workloads, and the
// Scanner collector is named scanner.
//
// The operator creates the default Collectors when it starts, and never overwrites one that
// exists. A Collector reports health: its status shows whether the collector works and when it
// last succeeded. The Scanner Collector also holds the settings of the scan Jobs. Deleting the
// workloads Collector does not stop the pod inventory. The operator creates a default Collector
// again the next time it starts.
type Collector struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines which collector this is, and its settings
	// +required
	Spec CollectorSpec `json:"spec"`

	// status defines the observed state of Collector
	// +optional
	Status CollectorStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// CollectorList contains a list of Collector
type CollectorList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []Collector `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &Collector{}, &CollectorList{})
		return nil
	})
}
