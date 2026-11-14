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

package inventory_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/inventory"
)

// newCounts returns the counts of a playbook for a cluster, under the name that the schema requires.
func newCounts(name string, playbook, cluster string) *inventoryv1alpha1.PlaybookCounts {
	return &inventoryv1alpha1.PlaybookCounts{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       inventoryv1alpha1.PlaybookCountsSpec{Playbook: playbook, Cluster: cluster},
	}
}

var _ = Describe("PlaybookCounts API", func() {
	It("takes the counts through the status subresource, under the name of its playbook and cluster", func() {
		counts := newCounts("counts-api.cluster-a", "counts-api", "cluster-a")
		Expect(k8sClient.Create(ctx, counts)).To(Succeed())
		DeferCleanup(func() { Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, counts))).To(Succeed()) })

		counts.Status = inventory.Tally{Judged: 10, Failing: 2, Updates: 3, Investigations: 1, Critical: 1, Unknown: 3}.Status()
		counts.Status.UpdatedTime = ptr.To(metav1.Now())
		Expect(k8sClient.Status().Update(ctx, counts)).To(Succeed())
	})

	DescribeTable("refuses",
		func(counts *inventoryv1alpha1.PlaybookCounts, message string) {
			err := k8sClient.Create(ctx, counts)
			Expect(apierrors.IsInvalid(err)).To(BeTrue(), "%v", err)
			Expect(err).To(MatchError(ContainSubstring(message)))
		},
		Entry("a name that isn't the playbook, a dot and the cluster",
			newCounts("counts-api-wrong", "counts-api", "cluster-a"), "name must be the playbook, a dot, and the cluster"),
		Entry("a playbook that isn't a DNS label", newCounts("Counts.cluster-a", "Counts", "cluster-a"), "spec.playbook"),
		Entry("a cluster that isn't a DNS label", newCounts("counts-api.Cluster", "counts-api", "Cluster"), "spec.cluster"),
	)

	It("refuses a spec that changes, and more resources failing than are judged", func() {
		counts := newCounts("counts-api-rules.cluster-a", "counts-api-rules", "cluster-a")
		Expect(k8sClient.Create(ctx, counts)).To(Succeed())
		DeferCleanup(func() { Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, counts))).To(Succeed()) })

		counts.Status = inventory.Tally{Judged: 1, Failing: 2}.Status()
		err := k8sClient.Status().Update(ctx, counts)
		Expect(apierrors.IsInvalid(err)).To(BeTrue(), "%v", err)
		Expect(err).To(MatchError(ContainSubstring("no more resources fail than are judged")))

		counts.Status = inventoryv1alpha1.PlaybookCountsStatus{}
		counts.Spec.Cluster = "cluster-b"
		err = k8sClient.Update(ctx, counts)
		Expect(apierrors.IsInvalid(err)).To(BeTrue(), "%v", err)
		Expect(err).To(MatchError(ContainSubstring("cluster is immutable")))
	})
})
