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

// CollectorRuntimeConfigSpec holds the templates that shape what the operator creates for a
// collector. Each is a patch for an object whose schema Kubernetes owns, so the schema keeps it as it
// is, and the operator checks that it decodes when it applies it.
type CollectorRuntimeConfigSpec struct {
	// deploymentTemplate shapes the collector's Deployment. The operator merges it onto its own
	// defaults as a strategic merge patch, and then sets the fields that the collector's contract
	// needs: the image, the certificates, the ports and the environment variables of the contract. The
	// collector's container is named collector. The defaults are hardened: the pod runs as non-root
	// with the RuntimeDefault seccomp profile, the container may not escalate its privileges, has a
	// read-only root filesystem and drops all capabilities, and the image pull policy is
	// IfNotPresent. A template may change any of that.
	// +optional
	// +kubebuilder:pruning:PreserveUnknownFields
	DeploymentTemplate *runtime.RawExtension `json:"deploymentTemplate,omitempty"`
	// serviceAccountTemplate shapes the metadata of the collector's service account, such as an
	// annotation for a cloud identity.
	// +optional
	// +kubebuilder:pruning:PreserveUnknownFields
	ServiceAccountTemplate *runtime.RawExtension `json:"serviceAccountTemplate,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// CollectorRuntimeConfig shapes the Deployment that a collector runs in, and the metadata of its
// service account, as Crossplane's DeploymentRuntimeConfig does for a function. A Collector names one
// in spec.runtimeConfigRef, and the config named default applies when it names none. The operator
// creates default empty, and never overwrites it. It is cluster-scoped and has no status.
//
// Writing a Collector or a CollectorRuntimeConfig amounts to creating pods in the operator's
// namespace, which Kubernetes' RBAC good practices treat as access to every Secret and service account
// there. So write access to both is only for people who are trusted with that namespace.
type CollectorRuntimeConfig struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the templates that shape a collector's Deployment and service account
	// +required
	Spec CollectorRuntimeConfigSpec `json:"spec"`
}

// +kubebuilder:object:root=true

// CollectorRuntimeConfigList contains a list of CollectorRuntimeConfig
type CollectorRuntimeConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []CollectorRuntimeConfig `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &CollectorRuntimeConfig{}, &CollectorRuntimeConfigList{})
		return nil
	})
}
