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
	"cmp"
	"context"
	"maps"
	"slices"

	"k8s.io/apimachinery/pkg/types"

	sdkevidence "github.com/bedag/vexplain/sdk/evidence"
	"github.com/bedag/vexplain/sdk/workloads"
)

// Running is what the renderer reads of a cluster: what runs there, and how far it can be reached. Presence gives it
// for the spoke's own cluster; another implementation can give it for a cluster whose records it holds as copies.
type Running interface {
	// KnowsWhatRuns reports whether what it says runs is complete: what it doesn't name doesn't run.
	KnowsWhatRuns(ctx context.Context) (bool, error)
	// RunningReports returns the namespace and name of the report of each workload that runs, sorted.
	RunningReports() []types.NamespacedName
	// Running returns the workload whose report has the name in the namespace, with its images, or false when none runs.
	Running(namespace, report string) (RunningWorkload, bool)
	// Workloads returns the workloads that run the image of a digest, each once, sorted.
	Workloads(image string) []sdkevidence.PresenceWorkload
	// ExposureKnown reports whether what it says of exposure is complete, so that Unknown means unknown.
	ExposureKnown(ctx context.Context) (bool, error)
	// ExposureOf returns what a report shows of a workload's exposure.
	ExposureOf(w sdkevidence.PresenceWorkload) WorkloadExposure
}

// IndexRunning returns the workloads that run, by their reports, from the presence of each image, by its digest. A
// workload is the one that comes first in the image's Workloads for the report: the report is named after the kind and
// the name, so another API group or UID with them has no report of its own. An image's Repositories name its reference,
// the least of them.
//
// The caller must give each image's Workloads each once and sorted, as EachOnce makes them: the order decides which
// workload a report is of, and a workload named twice would add the pods of both.
func IndexRunning(images map[string]sdkevidence.Presence) map[types.NamespacedName]RunningWorkload {
	index := map[types.NamespacedName]*RunningWorkload{}
	platforms := map[types.NamespacedName]map[string]map[string]bool{}
	containers := map[types.NamespacedName]map[string]map[workloads.ContainerRef]bool{}
	for _, digest := range slices.Sorted(maps.Keys(images)) {
		image := images[digest]
		for _, w := range image.Workloads {
			key := types.NamespacedName{Namespace: w.Namespace, Name: ReportName(w)}
			running, ok := index[key]
			if !ok {
				running = &RunningWorkload{Workload: w}
				index[key] = running
				platforms[key] = map[string]map[string]bool{}
				containers[key] = map[string]map[workloads.ContainerRef]bool{}
			} else if refOf(running.Workload) != refOf(w) {
				continue
			}
			if platforms[key][digest] == nil {
				platforms[key][digest] = map[string]bool{}
				containers[key][digest] = map[workloads.ContainerRef]bool{}
				running.Images = append(running.Images, RunningImage{Digest: digest, Kind: kindOf(image),
					Ref: referenceOf(image)})
			}
			for _, pod := range w.Pods {
				if pod.Platform != "" {
					platforms[key][digest][pod.Platform] = true
				}
				for _, container := range pod.Containers {
					containers[key][digest][workloads.ContainerRef{Name: container.Name, Kind: container.Kind}] = true
				}
			}
		}
	}
	out := make(map[types.NamespacedName]RunningWorkload, len(index))
	for key, running := range index {
		for i := range running.Images {
			digest := running.Images[i].Digest
			running.Images[i].Platforms = slices.Sorted(maps.Keys(platforms[key][digest]))
			running.Images[i].Containers = slices.SortedFunc(maps.Keys(containers[key][digest]),
				func(a, b workloads.ContainerRef) int {
					return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.Kind, b.Kind))
				})
		}
		out[key] = *running
	}
	return out
}

// EachOnce returns the workloads each once, sorted by namespace, kind, name, API group and UID, as IndexRunning needs
// them: of a workload that two of them name, as two collectors can, the first says what it is. It sorts ws in place.
func EachOnce(ws []sdkevidence.PresenceWorkload) []sdkevidence.PresenceWorkload {
	slices.SortStableFunc(ws, func(a, b sdkevidence.PresenceWorkload) int {
		return cmp.Or(cmp.Compare(a.Namespace, b.Namespace), cmp.Compare(a.Kind, b.Kind), cmp.Compare(a.Name, b.Name),
			cmp.Compare(a.APIGroup, b.APIGroup), cmp.Compare(a.UID, b.UID))
	})
	return slices.CompactFunc(ws, func(a, b sdkevidence.PresenceWorkload) bool { return refOf(a) == refOf(b) })
}

// kindOf is the digestKind of an image's presence, ImageID where it says none.
func kindOf(p sdkevidence.Presence) string {
	if p.DigestKind == "" {
		return sdkevidence.DigestKindImageID
	}
	return p.DigestKind
}

// referenceOf is the reference of an image's presence: the least of its repositories, or none.
func referenceOf(p sdkevidence.Presence) string {
	if len(p.Repositories) == 0 {
		return ""
	}
	return slices.Min(p.Repositories)
}
