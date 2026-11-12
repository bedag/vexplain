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

package hub_test

import (
	"fmt"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/require"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/controller/hub"
	"github.com/bedag/vexplain/internal/inventory"
)

func TestTheFleetPictureSumsTheCountsOfTwoClusters(t *testing.T) {
	summary, clusters := hub.FleetOf([]inventoryv1alpha1.PlaybookCounts{
		*countsOf("p", "cluster-a", inventory.Tally{Judged: 10, Failing: 2, Updates: 3, Investigations: 1, Critical: 1, High: 3}),
		*countsOf("p", "cluster-b", inventory.Tally{Judged: 5, Failing: 4, Updates: 1, Changes: 2, Mitigations: 3,
			High: 1, Medium: 2, Low: 2, Unknown: 1}),
	})

	require.Equal(t, &configv1alpha1.FleetSummary{Clusters: ptr.To(int32(2)), Judged: ptr.To(int32(15)), Failing: ptr.To(int32(6)),
		Actions: configv1alpha1.ActionCounts{Updates: ptr.To(int32(4)), Changes: ptr.To(int32(2)),
			Mitigations: ptr.To(int32(3)), Investigations: ptr.To(int32(1))},
		Severities: configv1alpha1.SeverityCounts{Critical: ptr.To(int32(1)), High: ptr.To(int32(4)),
			Medium: ptr.To(int32(2)), Low: ptr.To(int32(2)), Unknown: ptr.To(int32(1))}}, summary)
	require.Equal(t, []string{otherCluster, localCluster}, []string{clusters[0].Cluster, clusters[1].Cluster},
		"the most failing first")
	require.EqualValues(t, 4, *clusters[0].Failing)
	require.EqualValues(t, 3, *clusters[0].Actions.Mitigations)
}

func TestTheFleetPictureListsAtMost16ClustersTheMostFailingFirstAndCountsThemAll(t *testing.T) {
	counts := make([]inventoryv1alpha1.PlaybookCounts, 0, 20)
	for i := range 20 {
		// Clusters 04 to 19 fail alike, so that their order is by name.
		failing := int32(1)
		if i < 3 {
			failing = int32(10 - i)
		}
		counts = append(counts, *countsOf("p", fmt.Sprintf("cluster-%02d", 19-i), inventory.Tally{Judged: 10, Failing: failing}))
	}

	summary, clusters := hub.FleetOf(counts)

	require.EqualValues(t, 20, *summary.Clusters, "the summary counts every cluster")
	require.EqualValues(t, 200, *summary.Judged)
	require.Len(t, clusters, 16)
	require.Equal(t, []string{"cluster-19", "cluster-18", "cluster-17", "cluster-00", "cluster-01"},
		[]string{clusters[0].Cluster, clusters[1].Cluster, clusters[2].Cluster, clusters[3].Cluster, clusters[4].Cluster})
	require.Equal(t, "cluster-12", clusters[15].Cluster)
}

func TestTheFleetPictureOfNoCountsIsAbsent(t *testing.T) {
	summary, clusters := hub.FleetOf(nil)
	require.Nil(t, summary)
	require.Nil(t, clusters)
}

var _ = Describe("The fleet picture", func() {
	It("sums the counts that the spokes write into the status of the playbook, and follows them", func() {
		const name = "fleet-picture"
		createPlaybook(name, vmPlaybook(nil, "fleet-rule"))
		var playbook configv1alpha1.Playbook
		Expect(k8sClient.Get(ctx, client.ObjectKey{Name: name}, &playbook)).To(Succeed())
		counts := inventory.NewCRDCountsStore(k8sClient, nil)
		put := func(cluster string, tally inventory.Tally) {
			GinkgoHelper()
			Expect(counts.Put(ctx, name, playbook.UID, cluster, tally)).To(Succeed())
		}
		put("cluster-a", inventory.Tally{Judged: 10, Failing: 2, Updates: 3})
		put("cluster-b", inventory.Tally{Judged: 5, Failing: 4, Updates: 1, Mitigations: 3})
		summary := func(g Gomega) *configv1alpha1.FleetSummary {
			var current configv1alpha1.Playbook
			g.Expect(k8sClient.Get(ctx, client.ObjectKey{Name: name}, &current)).To(Succeed())
			return current.Status.Summary
		}

		Eventually(summary, reaction, poll).Should(And(
			HaveField("Clusters", HaveValue(BeEquivalentTo(2))), HaveField("Judged", HaveValue(BeEquivalentTo(15))),
			HaveField("Failing", HaveValue(BeEquivalentTo(6))),
			HaveField("Actions.Updates", HaveValue(BeEquivalentTo(4))), HaveField("Actions.Mitigations", HaveValue(BeEquivalentTo(3)))))
		var current configv1alpha1.Playbook
		Expect(k8sClient.Get(ctx, client.ObjectKey{Name: name}, &current)).To(Succeed())
		Expect(current.Status.Clusters).To(HaveLen(2))
		Expect(current.Status.Clusters[0].Cluster).To(Equal("cluster-b"), "the most failing first")

		By("following a cluster whose counts change, and one whose counts go")
		put("cluster-a", inventory.Tally{Judged: 10, Failing: 8})
		Eventually(summary, reaction, poll).Should(HaveField("Failing", HaveValue(BeEquivalentTo(12))))
		Expect(counts.Delete(ctx, name, "cluster-b")).To(Succeed())
		Eventually(summary, reaction, poll).Should(And(HaveField("Clusters", HaveValue(BeEquivalentTo(1))),
			HaveField("Failing", HaveValue(BeEquivalentTo(8)))))
	})
})
