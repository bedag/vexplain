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

// RuntimeConfigReference names a CollectorRuntimeConfig.
type RuntimeConfigReference struct {
	// name is the name of the CollectorRuntimeConfig.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
	Name string `json:"name,omitempty"`
}

// CollectorSpec says which package a Collector installs, how its Deployment is shaped and what its
// settings are.
type CollectorSpec struct {
	// package is the OCI image that holds the collector, referenced by tag or by digest, such as
	// artifacts.example/collectors/hello:0.1.0. Upgrading the collector means changing it, and
	// changing it back is the rollback. The digest that actually runs is in status.packageDigest.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=512
	Package string `json:"package,omitempty"`
	// runtimeConfigRef names the CollectorRuntimeConfig that shapes the collector's Deployment. When
	// it is absent, the config named default applies.
	// +optional
	RuntimeConfigRef *RuntimeConfigReference `json:"runtimeConfigRef,omitempty"`
	// settings are the collector's own settings, an object of any shape: vexplain can't know the
	// settings of a collector that someone else wrote, so the schema keeps them as they are. The
	// operator checks them against the settings schema that the collector declares and with the
	// collector's own check, and reports SettingsInvalid when they fail.
	// +optional
	// +kubebuilder:pruning:PreserveUnknownFields
	// +kubebuilder:validation:Schemaless
	Settings *runtime.RawExtension `json:"settings,omitempty"`
}

// CollectorRole says where a collector runs. Open enum; more values may follow.
// +kubebuilder:validation:Enum=Spoke;Hub
type CollectorRole string

const (
	// CollectorRoleSpoke runs in a cluster with the spoke role, next to its workloads.
	CollectorRoleSpoke CollectorRole = "Spoke"
	// CollectorRoleHub runs in the hub's cluster.
	CollectorRoleHub CollectorRole = "Hub"
)

// EvidenceScope says where the evidence of a type goes. Open enum; more values may follow.
// +kubebuilder:validation:Enum=Spoke;Hub
type EvidenceScope string

const (
	// EvidenceScopeSpoke evidence stays in its cluster.
	EvidenceScopeSpoke EvidenceScope = "Spoke"
	// EvidenceScopeHub evidence goes to the hub, which collects it across clusters. Its subjects are
	// unique across clusters.
	EvidenceScopeHub EvidenceScope = "Hub"
)

// CollectorWatch says whether a collector streams its evidence. Open enum; more values may follow.
// +kubebuilder:validation:Enum=Supported;NotSupported
type CollectorWatch string

const (
	// CollectorWatchSupported means the collector streams its evidence: a full snapshot first, then
	// each change.
	CollectorWatchSupported CollectorWatch = "Supported"
	// CollectorWatchNotSupported means the collector delivers evidence only when an operation runs.
	CollectorWatchNotSupported CollectorWatch = "NotSupported"
)

// ProducedType is a type of evidence that a collector produces.
type ProducedType struct {
	// type is the type of the evidence, named in reverse-DNS with a version, such as
	// ch.bedag.vexplain.presence.v1alpha1.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9-]+(\.[a-z0-9-]+)+\.v[0-9]+((alpha|beta)[0-9]+)?$`
	Type string `json:"type,omitempty"`
	// scope says where the evidence of the type goes: to the hub, or nowhere but its cluster. More
	// values may follow.
	// +required
	Scope EvidenceScope `json:"scope,omitempty"`
}

// CollectorOperation is work that a collector does on demand, for one subject.
type CollectorOperation struct {
	// name is the name of the operation, which is unique in the collector.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	Name string `json:"name,omitempty"`
	// produces are the types of evidence that the operation returns.
	// +optional
	// +listType=set
	// +kubebuilder:validation:MaxItems=32
	// +kubebuilder:validation:items:MinLength=1
	// +kubebuilder:validation:items:MaxLength=253
	// +kubebuilder:validation:items:Pattern=`^[a-z0-9-]+(\.[a-z0-9-]+)+\.v[0-9]+((alpha|beta)[0-9]+)?$`
	Produces []string `json:"produces,omitempty"`
	// consumes are the types of evidence that the operation takes as input. vexplain gets the evidence
	// of these types for the subject before it runs the operation.
	// +optional
	// +listType=set
	// +kubebuilder:validation:MaxItems=32
	// +kubebuilder:validation:items:MinLength=1
	// +kubebuilder:validation:items:MaxLength=253
	// +kubebuilder:validation:items:Pattern=`^[a-z0-9-]+(\.[a-z0-9-]+)+\.v[0-9]+((alpha|beta)[0-9]+)?$`
	Consumes []string `json:"consumes,omitempty"`
}

// CollectorSchedule is work that vexplain asks a collector to do on a schedule.
type CollectorSchedule struct {
	// name is the name of the schedule, which is unique in the collector.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	Name string `json:"name,omitempty"`
	// cron is a five-field cron expression, in UTC.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=128
	Cron string `json:"cron,omitempty"`
}

// CollectorSource is a source of a collector's own, such as a vulnerability database, as its GetInfo
// reported it.
type CollectorSource struct {
	// name is the name of the source, which is unique in the collector.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	Name string `json:"name,omitempty"`
	// version is the version of the source's data.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=128
	Version string `json:"version,omitempty"`
	// builtTime is when the source's data was built, when the collector says.
	// +optional
	BuiltTime *metav1.Time `json:"builtTime,omitempty"`
}

// CollectorCapabilities is what a collector answered to GetCapabilities, in a bounded form. What
// stays with the collector is the schema of each type of evidence, the schema of its settings, the
// schema of each operation's parameters and the Kubernetes permissions that it needs.
type CollectorCapabilities struct {
	// roles are where the collector runs: in a cluster next to its workloads, in the hub's cluster,
	// or both. More values may follow.
	// +optional
	// +listType=set
	// +kubebuilder:validation:MaxItems=2
	Roles []CollectorRole `json:"roles,omitempty"`
	// produces are the types of evidence that the collector produces, each with its scope.
	// +optional
	// +listType=map
	// +listMapKey=type
	// +kubebuilder:validation:MaxItems=32
	Produces []ProducedType `json:"produces,omitempty"`
	// consumes are the types of evidence that the collector's operations take as input.
	// +optional
	// +listType=set
	// +kubebuilder:validation:MaxItems=32
	// +kubebuilder:validation:items:MinLength=1
	// +kubebuilder:validation:items:MaxLength=253
	// +kubebuilder:validation:items:Pattern=`^[a-z0-9-]+(\.[a-z0-9-]+)+\.v[0-9]+((alpha|beta)[0-9]+)?$`
	Consumes []string `json:"consumes,omitempty"`
	// watch says whether the collector streams its evidence. More values may follow.
	// +required
	Watch CollectorWatch `json:"watch,omitempty"`
	// operations are the work that the collector does on demand.
	// +optional
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:MaxItems=16
	Operations []CollectorOperation `json:"operations,omitempty"`
	// schedules are the work that the operator asks the collector to do on a schedule.
	// +optional
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:MaxItems=8
	Schedules []CollectorSchedule `json:"schedules,omitempty"`
}

// CollectorStatus is what the operator knows about the collector that a Collector installs.
type CollectorStatus struct {
	// conditions represent the current state of the Collector.
	// The Ready condition says whether the collector works. It is True with reason Healthy when the
	// collector answers its health check with SERVING. It is Unknown with reason Progressing while
	// its Deployment rolls out, and with reason NoData while a check fails within the grace after
	// the operator's start, or after the operator issued the collector's certificate. It is False
	// with reason CollectorFailing, and the error as its message, when the collector can't be
	// reached after that grace: a call of it fails, its Deployment has no available replica after
	// its rollout or exceeded its progress deadline, or an error keeps the operator from checking.
	// The other reasons of False say why the collector can't be used: PackageInvalid when its answer
	// to GetInfo or GetCapabilities is malformed, IncompatibleAPI when it speaks no version of the
	// collector API that the operator knows, SettingsInvalid when spec.settings fail the collector's
	// check, MissingPermissions when its service account lacks permissions that it declares, and
	// RuntimeConfigInvalid when what its runtime config shapes can't be written. The message says
	// what.
	// Reconciling and Stalled are present only while True, and give the reason and message of Ready,
	// so that kstatus can tell a collector in progress from one that is stuck. Reconciling comes with
	// Progressing and NoData: the operator waits on the rollout, or on the grace for health. Stalled
	// comes with every reason of False: PackageInvalid, IncompatibleAPI, SettingsInvalid,
	// MissingPermissions and RuntimeConfigInvalid need a change of the package, the spec, the
	// permissions or the runtime config, and CollectorFailing is reported only once the rollout and
	// the grace are over. Healthy has neither.
	// +listType=map
	// +listMapKey=type
	// +kubebuilder:validation:MaxItems=8
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
	// observedGeneration is the generation of the Collector that the operator last acted on.
	// +optional
	// +kubebuilder:validation:Minimum=0
	ObservedGeneration *int64 `json:"observedGeneration,omitempty"`
	// packageDigest is the digest of the image that runs, as the collector's pod reports it. It
	// differs from spec.package when that names a tag.
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=71
	// +kubebuilder:validation:Pattern=`^sha256:[a-f0-9]{64}$`
	PackageDigest *string `json:"packageDigest,omitempty"`
	// version is the version that the collector's GetInfo answered. Evidence is written at this
	// version, so a new version replaces what an older one delivered.
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=128
	Version *string `json:"version,omitempty"`
	// capabilities are what the collector's GetCapabilities answered, bounded in size.
	// +optional
	Capabilities *CollectorCapabilities `json:"capabilities,omitempty"`
	// sources are the versions of the collector's own sources, as its GetInfo reported them at the
	// last check. The operator writes them only when they change.
	// +optional
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:MaxItems=8
	Sources []CollectorSource `json:"sources,omitempty"`
	// lastSuccessTime is when the collector last passed its health check. While the collector stays
	// healthy, the operator writes a later time once this one is 5 minutes old, so it lags by up to
	// that. A later failure leaves it as it was, and so does a restart of the operator.
	// +optional
	LastSuccessTime *metav1.Time `json:"lastSuccessTime,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories=vexplain
// +kubebuilder:printcolumn:name="Version",type=string,JSONPath=`.status.version`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Reason",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].reason`
// +kubebuilder:printcolumn:name="Last Success",type=date,JSONPath=`.status.lastSuccessTime`
// +kubebuilder:printcolumn:name="Package",type=string,priority=1,JSONPath=`.spec.package`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// +kubebuilder:validation:XValidation:rule="self.metadata.name.matches('^[a-z0-9]([-a-z0-9]*[a-z0-9])?$')",message="a Collector is named with a DNS-1123 label, which has no dots"
// +kubebuilder:validation:XValidation:rule="size(self.metadata.name) <= 44",message="a Collector's name is at most 44 characters, because the Service vexplain-collector-<name> is a DNS-1035 label of at most 63 characters, and so is the first label of the collector's TLS server name"

// Collector installs one collector, a source of evidence, from its package. It is cluster-scoped, and
// installed means enabled: deleting the Collector removes the collector, and the evidence that it
// delivered.
//
// A Collector is named with a DNS-1123 label, because playbooks name the collectors that they read,
// and with at most 44 characters, because the operator names the Service of the collector
// vexplain-collector-<name>. That name is a DNS-1035 label, and so is the first label of the
// collector's TLS server name, and a label has 63 characters at most, which leaves 44 for the name.
// The status shows the digest that runs, what the collector describes itself as, and whether it works.
type Collector struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines which package the Collector installs, and its settings
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
