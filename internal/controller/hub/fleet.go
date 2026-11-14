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

package hub

import (
	"cmp"
	"slices"
	"strings"

	"k8s.io/utils/ptr"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/inventory"
)

// maxFleetClusters is how many clusters a Playbook's status lists.
const maxFleetClusters = 16

// fleetOf sums the counts of a playbook over its clusters into the fleet picture of its status (design 5.6): the
// summary over every cluster, and the clusters themselves, the most failing first, then by name, at most 16. It
// returns no summary and no clusters for no counts.
func fleetOf(counts []inventoryv1alpha1.PlaybookCounts) (*configv1alpha1.FleetSummary, []configv1alpha1.ClusterCounts) {
	if len(counts) == 0 {
		return nil, nil
	}
	var total inventory.Tally
	clusters := make([]configv1alpha1.ClusterCounts, 0, len(counts))
	for _, c := range counts {
		t := inventory.TallyOf(c.Status)
		total = total.Plus(t)
		clusters = append(clusters, configv1alpha1.ClusterCounts{
			Cluster: c.Spec.Cluster, Judged: ptr.To(t.Judged), Failing: ptr.To(t.Failing),
			Actions:    actionsOf(t),
			Severities: severitiesOf(t),
		})
	}
	slices.SortFunc(clusters, func(a, b configv1alpha1.ClusterCounts) int {
		return cmp.Or(cmp.Compare(*b.Failing, *a.Failing), strings.Compare(a.Cluster, b.Cluster))
	})
	return &configv1alpha1.FleetSummary{
		Clusters: ptr.To(int32(len(counts))), //nolint:gosec // a count of objects
		Judged:   ptr.To(total.Judged), Failing: ptr.To(total.Failing),
		Actions: actionsOf(total), Severities: severitiesOf(total),
	}, clusters[:min(len(clusters), maxFleetClusters)]
}

func actionsOf(t inventory.Tally) configv1alpha1.ActionCounts {
	return configv1alpha1.ActionCounts{Updates: ptr.To(t.Updates), Changes: ptr.To(t.Changes),
		Mitigations: ptr.To(t.Mitigations), Investigations: ptr.To(t.Investigations)}
}

func severitiesOf(t inventory.Tally) configv1alpha1.SeverityCounts {
	return configv1alpha1.SeverityCounts{Critical: ptr.To(t.Critical), High: ptr.To(t.High), Medium: ptr.To(t.Medium),
		Low: ptr.To(t.Low), Unknown: ptr.To(t.Unknown)}
}
