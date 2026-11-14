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

// PlaybookCountsSpec says which playbook and which cluster the counts are about. It never changes.
type PlaybookCountsSpec struct {
	// playbook is the name of the Playbook whose results the counts add up.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="playbook is immutable"
	Playbook string `json:"playbook,omitempty"`
	// cluster is the name of the cluster whose resources the counts are about.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="cluster is immutable"
	Cluster string `json:"cluster,omitempty"`
}

// ActionCounts counts actions by their next step.
type ActionCounts struct {
	// updates is the number of actions whose step is Update.
	// +required
	// +kubebuilder:validation:Minimum=0
	Updates *int32 `json:"updates,omitempty"`
	// changes is the number of actions whose step is Change.
	// +required
	// +kubebuilder:validation:Minimum=0
	Changes *int32 `json:"changes,omitempty"`
	// mitigations is the number of actions whose step is Mitigate.
	// +required
	// +kubebuilder:validation:Minimum=0
	Mitigations *int32 `json:"mitigations,omitempty"`
	// investigations is the number of actions whose step is Investigate.
	// +required
	// +kubebuilder:validation:Minimum=0
	Investigations *int32 `json:"investigations,omitempty"`
}

// SeverityCounts counts actions by their severity. Negligible counts as Low.
type SeverityCounts struct {
	// critical is the number of actions whose severity is Critical.
	// +required
	// +kubebuilder:validation:Minimum=0
	Critical *int32 `json:"critical,omitempty"`
	// high is the number of actions whose severity is High.
	// +required
	// +kubebuilder:validation:Minimum=0
	High *int32 `json:"high,omitempty"`
	// medium is the number of actions whose severity is Medium.
	// +required
	// +kubebuilder:validation:Minimum=0
	Medium *int32 `json:"medium,omitempty"`
	// low is the number of actions whose severity is Low or Negligible.
	// +required
	// +kubebuilder:validation:Minimum=0
	Low *int32 `json:"low,omitempty"`
	// unknown is the number of actions whose severity is Unknown.
	// +required
	// +kubebuilder:validation:Minimum=0
	Unknown *int32 `json:"unknown,omitempty"`
}

// PlaybookCountsStatus is what one playbook found in one cluster. The cluster's spoke writes it.
// +kubebuilder:validation:XValidation:rule="self.failing <= self.judged",message="no more resources fail than are judged"
type PlaybookCountsStatus struct {
	// judged is the number of resources of the cluster that hold the playbook's results.
	// +optional
	// +kubebuilder:validation:Minimum=0
	Judged *int32 `json:"judged,omitempty"`
	// failing is the number of judged resources with at least one action of the playbook.
	// +optional
	// +kubebuilder:validation:Minimum=0
	Failing *int32 `json:"failing,omitempty"`
	// actions counts the playbook's actions in the cluster by step.
	// +optional
	Actions *ActionCounts `json:"actions,omitempty"`
	// severities counts the playbook's actions in the cluster by severity.
	// +optional
	Severities *SeverityCounts `json:"severities,omitempty"`
	// updatedTime is when the spoke last wrote counts that differ from the stored ones.
	// +optional
	UpdatedTime *metav1.Time `json:"updatedTime,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories={vexplain,vexplain-data}
// +kubebuilder:printcolumn:name="Playbook",type=string,JSONPath=`.spec.playbook`
// +kubebuilder:printcolumn:name="Cluster",type=string,JSONPath=`.spec.cluster`
// +kubebuilder:printcolumn:name="Judged",type=integer,JSONPath=`.status.judged`
// +kubebuilder:printcolumn:name="Failing",type=integer,JSONPath=`.status.failing`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// +kubebuilder:validation:XValidation:rule="self.metadata.name == self.spec.playbook + '.' + self.spec.cluster",message="name must be the playbook, a dot, and the cluster"

// PlaybookCounts is what one playbook found in one cluster, for the fleet picture of the playbook (decision
// 0043): the resources it judged and those that fail it, and its actions by step and by severity. The spoke of
// the cluster writes it, and the playbook controller of the hub sums it into the status of the Playbook. It is
// cluster-scoped, named after the playbook, a dot and the cluster, and owned by the Playbook, so that
// Kubernetes deletes it with the Playbook.
type PlaybookCounts struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec says which playbook and which cluster
	// +required
	Spec PlaybookCountsSpec `json:"spec"`

	// status holds the counts
	// +optional
	Status PlaybookCountsStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// PlaybookCountsList contains a list of PlaybookCounts
type PlaybookCountsList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []PlaybookCounts `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &PlaybookCounts{}, &PlaybookCountsList{})
		return nil
	})
}
