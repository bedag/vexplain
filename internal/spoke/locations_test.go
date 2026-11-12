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

package spoke_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bedag/vexplain/internal/spoke"
	sdkworkloads "github.com/bedag/vexplain/sdk/workloads"
)

// A location is the field path of a container in its workload, with the container named in its list: the pod spec is
// the workload's own for a Pod, under the job template for a CronJob, and under the pod template for every other kind.
// A sidecar is an init container that keeps running, so it is listed with the init containers.
func TestLocationIsTheFieldPathOfTheContainerInItsWorkload(t *testing.T) {
	container := sdkworkloads.ContainerRef{Name: webName, Kind: sdkworkloads.ContainerKindContainer}
	for name, tc := range map[string]struct {
		kind      string
		container sdkworkloads.ContainerRef
		want      string
	}{
		"a container of a Deployment":  {deployment, container, "spec.template.spec.containers[web]"},
		"a container of a StatefulSet": {"StatefulSet", container, "spec.template.spec.containers[web]"},
		"a container of a CronJob":     {"CronJob", container, "spec.jobTemplate.spec.template.spec.containers[web]"},
		"a container of a Pod":         {"Pod", container, "spec.containers[web]"},
		"an init container": {deployment, sdkworkloads.ContainerRef{Name: migrateName, Kind: sdkworkloads.ContainerKindInitContainer},
			"spec.template.spec.initContainers[migrate]"},
		"a sidecar of a Pod": {"Pod", sdkworkloads.ContainerRef{Name: proxyName, Kind: sdkworkloads.ContainerKindSidecar},
			"spec.initContainers[proxy]"},
	} {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, tc.want, spoke.Location(tc.kind, tc.container))
		})
	}
}
