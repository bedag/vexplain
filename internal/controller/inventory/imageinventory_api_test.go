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
	"fmt"
	"slices"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/workloads"
)

// ImageInventory has no envtest suite of its own, so its schema rules and limits are checked here,
// against the real API server.
var _ = Describe("ImageInventory API", func() {
	It("rejects an object whose name is not its digest", func() {
		err := k8sClient.Create(ctx, &inventoryv1alpha1.ImageInventory{
			ObjectMeta: metav1.ObjectMeta{Name: inventory.NameForDigest(newDigest())},
			Spec:       inventoryv1alpha1.ImageInventorySpec{Digest: newDigest()},
		})

		Expect(err).To(Satisfy(apierrors.IsInvalid))
		Expect(err).To(MatchError(ContainSubstring("name must be the digest with ':' replaced by '-'")))
	})

	It("rejects a change of the digest", func() {
		// A pod runs the digest, so the pod inventory keeps the object while the spec changes it.
		ns, digest := newNamespace(), newDigest()
		createPod(ns, "p", nil, running(repoDigest(digest)))
		obj := expectInventory(digest, startup, inventoryv1alpha1.DigestKindRepoDigest,
			localEntry(1, 1, refs(workloadRef(podKind, ns, "p")), repository))

		// A merge patch carries no resourceVersion, so the API server checks it against the object
		// as it is, whatever the pod inventory has written since it was read.
		patch := client.MergeFrom(obj.DeepCopy())
		obj.Spec.Digest = newDigest()
		err := k8sClient.Patch(ctx, obj, patch)

		Expect(err).To(Satisfy(apierrors.IsInvalid))
		Expect(err).To(MatchError(ContainSubstring("digest is immutable")))
	})

	It("stores an entry at the limits of the schema, written by the CRD store", func() {
		const (
			team          = "team-a"
			daemonSetKind = "DaemonSet"
		)
		digest := newDigest()
		observation := inventory.Observation{
			Cluster:        "cluster-a",
			ClusterID:      "id-cluster-a",
			DigestKind:     inventoryv1alpha1.DigestKindRepoDigest,
			NamespaceCount: 1,
		}
		for i := range 101 {
			observation.Workloads = append(observation.Workloads, workloads.WorkloadRef{
				APIGroup: appsv1.GroupName, Kind: "Deployment", Namespace: team, Name: fmt.Sprintf("web-%03d", i),
			})
		}
		// Two DaemonSets that share namespace, kind and name, the key of the list, but not the API
		// group. They sort before the Deployments, so the list keeps their key.
		observation.Workloads = append(observation.Workloads,
			workloads.WorkloadRef{APIGroup: appsv1.GroupName, Kind: daemonSetKind, Namespace: team, Name: "agent"},
			workloads.WorkloadRef{APIGroup: "agents.example", Kind: daemonSetKind, Namespace: team, Name: "agent"},
		)
		for i := range 33 {
			observation.Repositories = append(observation.Repositories,
				fmt.Sprintf("artifacts.example/%s/app-%02d", team, i))
		}
		// The entry belongs to another cluster, so the pod inventory leaves it. Once the pod is gone
		// and the pod inventory has removed its own entry, the spec deletes the object.
		DeferCleanup(func() {
			Eventually(func(g Gomega) {
				g.Expect(stored(g, digest).Status.Clusters).To(HaveExactElements(HaveField("Cluster", observation.Cluster)))
			}, reaction, poll).Should(Succeed())
			Expect(k8sClient.Delete(ctx, &inventoryv1alpha1.ImageInventory{
				ObjectMeta: metav1.ObjectMeta{Name: inventory.NameForDigest(digest)},
			})).To(Succeed())
		})
		// The store creates an object before it writes the entry, and the pod inventory deletes an
		// object without entries, often in between. A pod that runs the digest here keeps the object.
		ns := newNamespace()
		createPod(ns, "p", nil, running(repoDigest(digest)))
		expectInventory(digest, startup, inventoryv1alpha1.DigestKindRepoDigest,
			localEntry(1, 1, refs(workloadRef(podKind, ns, "p")), repository))

		// The spec only writes through the store, so it needs no cache to watch through.
		Expect(inventory.NewCRDStore(k8sClient, nil).Observe(ctx, digest, observation)).To(Succeed())

		entries := stored(Default, digest).Status.Clusters
		Expect(entries).To(HaveExactElements(HaveField("Cluster", observation.Cluster), HaveField("Cluster", localCluster)))
		atLimits := entries[0]
		Expect(atLimits.WorkloadCount).To(HaveValue(Equal(int32(103))), "every workload counts")
		Expect(atLimits.Workloads).To(HaveLen(100))
		daemonSets := slices.DeleteFunc(slices.Clone(atLimits.Workloads),
			func(workload inventoryv1alpha1.WorkloadReference) bool { return workload.Kind != daemonSetKind })
		Expect(daemonSets).To(HaveLen(1), "the two DaemonSets share a key, so the list holds one of them")
		Expect(atLimits.Repositories).To(HaveLen(32))
	})
})
