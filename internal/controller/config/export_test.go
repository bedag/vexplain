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

package config

import (
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	collectorv1alpha1 "github.com/bedag/vexplain/sdk/api/collector/v1alpha1"
)

// HealthGrace is how long after a start of the operator, or after a collector's certificate was issued again, a
// failing health check leaves the collector NoData.
const HealthGrace = healthGrace

// EnsureDefaultRuntimeConfig is what the deployer runs at its start: it creates the runtime config named default,
// empty, when it is missing.
var EnsureDefaultRuntimeConfig = ensureDefaultRuntimeConfig

// CapabilitiesOf returns what the deployer records of a collector's answer to GetCapabilities, or why the answer is
// malformed.
func CapabilitiesOf(answer *collectorv1alpha1.GetCapabilitiesResponse) (*configv1alpha1.CollectorCapabilities, error) {
	capabilities, _, err := capabilitiesOf(answer, "vexplain-system")
	return capabilities, err
}

// CheckInfo returns the version of a collector's answer to GetInfo, or the reason and the message of a Ready
// condition that refuses it.
func CheckInfo(answer *collectorv1alpha1.GetInfoResponse) (version, reason, message string) {
	version, refused := checkInfo(answer)
	if refused != nil {
		return "", refused.reason, refused.message
	}
	return version, "", ""
}

// DefaultDeployment returns the Deployment that the deployer wants for the collector of obj when no template shapes
// it: the defaults, with the contract set.
func DefaultDeployment(obj *configv1alpha1.Collector, namespace string, proxyEnv []corev1.EnvVar) *appsv1.Deployment {
	d := defaultDeployment(obj, namespace, proxyEnv)
	setContract(d, obj, namespace)
	return d
}

// WritesSpec says whether the deployer writes the spec of desired over live, the Deployment as the API server holds
// it.
func WritesSpec(desired, live *appsv1.Deployment) bool {
	hash, err := specHash(&desired.Spec)
	if err != nil {
		panic(err)
	}
	return specWanted(desired, hash, live)
}
