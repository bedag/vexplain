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

package spoke

import (
	"slices"

	"github.com/bedag/vexplain/internal/text"
	sdkworkloads "github.com/bedag/vexplain/sdk/workloads"
)

// The limits of the locations of an action, which the schema of a report sets.
const (
	maxActionLocations = 8
	maxLocation        = 256
)

// Location is where a container is in a workload of the kind, as a field path whose list items are named (decision
// 0042): spec.containers[<name>] or spec.initContainers[<name>] for a Pod, the same under spec.jobTemplate.spec.template
// for a CronJob, and under spec.template for every other kind. A sidecar is an init container that keeps running, so it
// is listed with the init containers.
func Location(kind string, c sdkworkloads.ContainerRef) string {
	list := "containers"
	if c.Kind == sdkworkloads.ContainerKindInitContainer || c.Kind == sdkworkloads.ContainerKindSidecar {
		list = "initContainers"
	}
	return podSpecOf(kind) + "." + list + "[" + c.Name + "]"
}

// podSpecOf returns the path of the pod spec in a workload of the kind.
func podSpecOf(kind string) string {
	switch kind {
	case "Pod":
		return "spec"
	case "CronJob":
		return "spec.jobTemplate.spec.template.spec"
	}
	return "spec.template.spec"
}

// locationsOf returns the locations of the containers in a workload of the kind, made printable and cut to the schema's
// limit, sorted and each once, the first 8. An action names at least one location, so where no container is known, as
// from a collector that names none, it is the workload's pod spec.
func locationsOf(kind string, containers []sdkworkloads.ContainerRef) []string {
	out := make([]string, 0, len(containers))
	for _, c := range containers {
		out = append(out, text.CutChars(text.Printable(Location(kind, c)), maxLocation))
	}
	slices.Sort(out)
	out = slices.Compact(out)
	if len(out) == 0 {
		return []string{podSpecOf(kind)}
	}
	return out[:min(len(out), maxActionLocations)]
}
