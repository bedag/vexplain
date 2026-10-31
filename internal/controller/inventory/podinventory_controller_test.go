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
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/settings"
)

// These specs run against the manager that the suite starts through setup.Register, so the pod
// inventory under test is the production one, with the production watches, field index and gauge.
// envtest runs no kubelet and no controllers of its own: a spec writes the status of a pod as a
// kubelet would, and creates the ReplicaSets and Jobs that a Deployment or a CronJob would create.
//
// Every spec uses digests and namespaces of its own. The OperatorConfig, the health registry and
// the metrics are shared: a spec that sets the OperatorConfig deletes it afterwards, and every spec
// waits until the objects of its digests are gone, so that the next one starts from a clean slate.
var _ = Describe("Pod inventory", func() {
	It("records a pod that a Deployment runs through a ReplicaSet", func() {
		ns, digest := newNamespace(), newDigest()
		createObject(replicaSet(ns, "web-7c9d8f6b5", controlledBy(deploymentKind, "web")))
		createPod(ns, "web-7c9d8f6b5-x2k4p", controlledBy(replicaSetKind, "web-7c9d8f6b5"), running(repoDigest(digest)))

		expectInventory(digest, startup, inventoryv1alpha1.DigestKindRepoDigest,
			localEntry(1, 1, refs(workloadRef(deploymentKind, ns, "web")), repository))
	})

	It("counts the workloads and the namespaces that run a digest", func() {
		ns, otherNamespace, digest := newNamespace(), newNamespace(), newDigest()
		createObject(replicaSet(ns, "web-7c9d8f6b5", controlledBy(deploymentKind, "web")))
		createPod(ns, "web-7c9d8f6b5-a", controlledBy(replicaSetKind, "web-7c9d8f6b5"), running(repoDigest(digest)))
		createPod(ns, "web-7c9d8f6b5-b", controlledBy(replicaSetKind, "web-7c9d8f6b5"), running(repoDigest(digest)))
		createPod(ns, "p", nil, running(repoDigest(digest)))

		// The store sorts the workloads by namespace, kind and name, and newNamespace names
		// namespaces in the order it creates them.
		web, p := workloadRef(deploymentKind, ns, "web"), workloadRef(podKind, ns, "p")
		expectInventory(digest, startup, inventoryv1alpha1.DigestKindRepoDigest,
			localEntry(1, 2, refs(web, p), repository))

		By("running one more pod in a second namespace")
		createPod(otherNamespace, "p", nil, running(repoDigest(digest)))

		expectInventory(digest, reaction, inventoryv1alpha1.DigestKindRepoDigest,
			localEntry(2, 3, refs(web, p, workloadRef(podKind, otherNamespace, "p")), repository))
	})

	It("counts a pod that has succeeded, such as the pod of a finished CronJob", func() {
		ns, digest := newNamespace(), newDigest()
		createObject(job(ns, "nightly-29012345", controlledBy(cronJobKind, "nightly")))
		createPod(ns, "nightly-29012345-q7w2n", controlledBy(jobKind, "nightly-29012345"), corev1.PodStatus{
			Phase: corev1.PodSucceeded,
			ContainerStatuses: []corev1.ContainerStatus{{
				Name:    containerName,
				Image:   repository + ":1.0",
				ImageID: repoDigest(digest),
				State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{
					ExitCode: 0, Reason: "Completed",
				}},
			}},
		})

		expectInventory(digest, startup, inventoryv1alpha1.DigestKindRepoDigest,
			localEntry(1, 1, refs(workloadRef(cronJobKind, ns, "nightly")), repository))
	})

	It("records an image ID with its kind and without a repository", func() {
		ns, digest := newNamespace(), newDigest()
		createPod(ns, "p", nil, running("docker://"+digest))

		expectInventory(digest, startup, inventoryv1alpha1.DigestKindImageID,
			localEntry(1, 1, refs(workloadRef(podKind, ns, "p"))))
	})

	It("records nothing for a pending pod whose container reports no imageID yet", func() {
		ns, digest := newNamespace(), newDigest()
		// The pod names the digest in its spec. Only what the runtime reports counts, and it hasn't
		// reported anything yet.
		pod := newPod(ns, "p", repoDigest(digest), nil)
		start(pod, corev1.PodStatus{
			Phase:             corev1.PodPending,
			ContainerStatuses: []corev1.ContainerStatus{containerStatus(containerName, "")},
		})

		Consistently(lookup(digest), quiet, poll).Should(Satisfy(apierrors.IsNotFound))

		By("recording the pod once its container runs")
		pod.Status = running(repoDigest(digest))
		Expect(k8sClient.Status().Update(ctx, pod)).To(Succeed())

		expectInventory(digest, reaction, inventoryv1alpha1.DigestKindRepoDigest,
			localEntry(1, 1, refs(workloadRef(podKind, ns, "p")), repository))
	})

	It("records nothing for a digest that only an ephemeral container reports", func() {
		ns, digest, debugDigest := newNamespace(), newDigest(), newDigest()
		status := running(repoDigest(digest))
		// A debug session runs an image of its own. envtest takes the status without the ephemeral
		// container in the spec, and the pod inventory reads the status only.
		status.EphemeralContainerStatuses = []corev1.ContainerStatus{containerStatus("debugger", repoDigest(debugDigest))}
		createPod(ns, "p", nil, status)

		By("recording the digest of the container, which shows that the pod has been seen")
		expectInventory(digest, startup, inventoryv1alpha1.DigestKindRepoDigest,
			localEntry(1, 1, refs(workloadRef(podKind, ns, "p")), repository))
		Consistently(lookup(debugDigest), quiet, poll).Should(Satisfy(apierrors.IsNotFound))
	})

	It("deletes the object once the last pod that runs the digest is gone", func() {
		ns, digest := newNamespace(), newDigest()
		first := createPod(ns, "p", nil, running(repoDigest(digest)))
		second := createPod(ns, "q", nil, running(repoDigest(digest)))
		expectInventory(digest, startup, inventoryv1alpha1.DigestKindRepoDigest,
			localEntry(1, 2, refs(workloadRef(podKind, ns, "p"), workloadRef(podKind, ns, "q")), repository))

		By("deleting one of the two pods")
		deletePod(first)
		expectInventory(digest, reaction, inventoryv1alpha1.DigestKindRepoDigest,
			localEntry(1, 1, refs(workloadRef(podKind, ns, "q")), repository))

		By("deleting the other")
		deletePod(second)
		Eventually(lookup(digest), reaction, poll).Should(Satisfy(apierrors.IsNotFound))
	})

	It("moves a pod to the new digest when its container reports another one", func() {
		ns, before, after := newNamespace(), newDigest(), newDigest()
		pod := createPod(ns, "p", nil, running(repoDigest(before)))
		expectInventory(before, startup, inventoryv1alpha1.DigestKindRepoDigest,
			localEntry(1, 1, refs(workloadRef(podKind, ns, "p")), repository))

		By("restarting the container with an image of another digest")
		pod.Status = running(repoDigest(after))
		Expect(k8sClient.Status().Update(ctx, pod)).To(Succeed())

		expectInventory(after, reaction, inventoryv1alpha1.DigestKindRepoDigest,
			localEntry(1, 1, refs(workloadRef(podKind, ns, "p")), repository))
		Eventually(lookup(before), reaction, poll).Should(Satisfy(apierrors.IsNotFound))
	})

	Describe("scope", func() {
		It("deletes the object when the OperatorConfig excludes the namespace, with no change to the pod", func() {
			ns, digest := newNamespace(), newDigest()
			createPod(ns, "p", nil, running(repoDigest(digest)))
			expectInventory(digest, startup, inventoryv1alpha1.DigestKindRepoDigest,
				localEntry(1, 1, refs(workloadRef(podKind, ns, "p")), repository))

			// The API server labels every namespace with its own name.
			configure(configv1alpha1.OperatorConfigSpec{Scope: &configv1alpha1.Scope{
				ExcludeNamespaces: &metav1.LabelSelector{MatchLabels: map[string]string{corev1.LabelMetadataName: ns}},
			}})

			Eventually(lookup(digest), reaction, poll).Should(Satisfy(apierrors.IsNotFound))
		})

		It("deletes the object when a label takes the namespace out of scope", func() {
			configure(configv1alpha1.OperatorConfigSpec{Scope: &configv1alpha1.Scope{
				ExcludeNamespaces: &metav1.LabelSelector{MatchLabels: map[string]string{"vexplain": "off"}},
			}})
			ns, digest := newNamespace(), newDigest()
			createPod(ns, "p", nil, running(repoDigest(digest)))
			expectInventory(digest, startup, inventoryv1alpha1.DigestKindRepoDigest,
				localEntry(1, 1, refs(workloadRef(podKind, ns, "p")), repository))

			By("labelling the namespace vexplain=off")
			var namespace corev1.Namespace
			Expect(k8sClient.Get(ctx, client.ObjectKey{Name: ns}, &namespace)).To(Succeed())
			patch := client.MergeFrom(namespace.DeepCopy())
			namespace.Labels["vexplain"] = "off"
			Expect(k8sClient.Patch(ctx, &namespace, patch)).To(Succeed())

			Eventually(lookup(digest), reaction, poll).Should(Satisfy(apierrors.IsNotFound))
		})

		It("keeps the inventory, and reports a failure, while the scope does not parse", func() {
			ns, digest := newNamespace(), newDigest()
			createPod(ns, "p", nil, running(repoDigest(digest)))
			kept := expectInventory(digest, startup, inventoryv1alpha1.DigestKindRepoDigest,
				localEntry(1, 1, refs(workloadRef(podKind, ns, "p")), repository))

			configure(configv1alpha1.OperatorConfigSpec{Scope: unparsableScope()})

			Eventually(func(g Gomega) {
				_, lastErr, _ := collectorRegistry.Health(configv1alpha1.CollectorTypeWorkloads)
				g.Expect(lastErr).To(MatchError(ContainSubstring("includeNamespaces")))
			}, reaction, poll).Should(Succeed())
			Consistently(func(g Gomega) {
				g.Expect(stored(g, digest).ResourceVersion).To(Equal(kept.ResourceVersion))
			}, quiet, poll).Should(Succeed())
		})

		It("removes the entry of a digest whose pods went while the scope did not parse, once it parses", func() {
			ns, digest := newNamespace(), newDigest()
			pod := createPod(ns, "p", nil, running(repoDigest(digest)))
			expectInventory(digest, startup, inventoryv1alpha1.DigestKindRepoDigest,
				localEntry(1, 1, refs(workloadRef(podKind, ns, "p")), repository))
			configure(configv1alpha1.OperatorConfigSpec{Scope: unparsableScope()})

			By("deleting the pod while no reconcile can succeed")
			deletePod(pod)
			Consistently(lookup(digest), quiet, poll).Should(Succeed(), "nothing can remove the entry yet")

			By("fixing the scope")
			Expect(k8sClient.Delete(ctx, &configv1alpha1.OperatorConfig{
				ObjectMeta: metav1.ObjectMeta{Name: settings.ConfigName},
			})).To(Succeed())

			// No pod reports the digest any more. Only the store's list of digests brings it back to a
			// reconcile.
			Eventually(lookup(digest), reaction, poll).Should(Satisfy(apierrors.IsNotFound))
		})
	})

	It("recreates an object that was deleted by hand while the pod runs", func() {
		ns, digest := newNamespace(), newDigest()
		createPod(ns, "p", nil, running(repoDigest(digest)))
		entry := localEntry(1, 1, refs(workloadRef(podKind, ns, "p")), repository)
		original := expectInventory(digest, startup, inventoryv1alpha1.DigestKindRepoDigest, entry)

		Expect(k8sClient.Delete(ctx, original)).To(Succeed())

		Eventually(func(g Gomega) {
			recreated := stored(g, digest)
			g.Expect(recreated.UID).NotTo(Equal(original.UID), "it is a new object")
			g.Expect(withoutTimes(g, recreated.Status.Clusters)).To(Equal([]inventoryv1alpha1.ClusterPresence{entry}))
		}, reaction, poll).Should(Succeed())
	})

	It("repairs an entry that was changed by hand while the pod runs", func() {
		ns, digest := newNamespace(), newDigest()
		createPod(ns, "p", nil, running(repoDigest(digest)))
		entry := localEntry(1, 1, refs(workloadRef(podKind, ns, "p")), repository)
		edited := expectInventory(digest, startup, inventoryv1alpha1.DigestKindRepoDigest, entry)

		edited.Status.Clusters[0].WorkloadCount = ptr.To(int32(99))
		Expect(k8sClient.Status().Update(ctx, edited)).To(Succeed())

		expectInventory(digest, reaction, inventoryv1alpha1.DigestKindRepoDigest, entry)
	})

	Describe("cluster name", func() {
		It("renames the entry, and the series of the gauge of running images, with the cluster", func() {
			ns, digest := newNamespace(), newDigest()
			createPod(ns, "p", nil, running(repoDigest(digest)))
			entry := localEntry(1, 1, refs(workloadRef(podKind, ns, "p")), repository)
			expectInventory(digest, startup, inventoryv1alpha1.DigestKindRepoDigest, entry)
			Eventually(gaugeOnlyFor(localCluster), reaction, poll).Should(Succeed())

			configure(configv1alpha1.OperatorConfigSpec{ClusterName: ptr.To(renamedCluster)})

			entry.Cluster = renamedCluster
			expectInventory(digest, reaction, inventoryv1alpha1.DigestKindRepoDigest, entry)
			Eventually(gaugeOnlyFor(renamedCluster), reaction, poll).Should(Succeed())
		})

		It("deletes an entry under a former cluster name once no pod runs the digest", func() {
			digest := newDigest()
			// The cluster was called old-name while its pods ran the digest. Both are gone: the
			// pods, and the name.
			former := inventoryv1alpha1.ClusterPresence{
				Cluster:        "old-name",
				ClusterID:      kubeSystemUID(),
				NamespaceCount: ptr.To(int32(1)),
				WorkloadCount:  ptr.To(int32(1)),
				FirstSeenTime:  ptr.To(metav1.Now()),
			}
			// A new object has no entry until its status is written, and the pod inventory deletes an
			// object without entries, mostly before a second writer gets there. While the scope
			// doesn't parse, every reconcile fails and changes nothing, so the spec makes the object
			// whole first.
			configure(configv1alpha1.OperatorConfigSpec{Scope: unparsableScope()})
			obj := &inventoryv1alpha1.ImageInventory{
				ObjectMeta: metav1.ObjectMeta{Name: inventory.NameForDigest(digest)},
				Spec:       inventoryv1alpha1.ImageInventorySpec{Digest: digest},
			}
			Expect(k8sClient.Create(ctx, obj)).To(Succeed())
			obj.Status = inventoryv1alpha1.ImageInventoryStatus{
				DigestKind: ptr.To(inventoryv1alpha1.DigestKindRepoDigest),
				Clusters:   []inventoryv1alpha1.ClusterPresence{former},
			}
			Expect(k8sClient.Status().Update(ctx, obj)).To(Succeed())

			By("letting the pod inventory reconcile again, under the default name")
			Expect(k8sClient.Delete(ctx, &configv1alpha1.OperatorConfig{
				ObjectMeta: metav1.ObjectMeta{Name: settings.ConfigName},
			})).To(Succeed())

			Eventually(lookup(digest), reaction, poll).Should(Satisfy(apierrors.IsNotFound))
		})
	})

	It("counts a container whose imageID is not a digest, once, and records nothing for it", func() {
		before := unparsableImageIDs(Default)
		existing := inventoryNames()
		pod := createPod(newNamespace(), "p", nil, running("nginx:1.27"))

		Eventually(unparsableImageIDs, reaction, poll).Should(Equal(before + 1))

		By("counting it once, however often the pod changes")
		pod.Status.ContainerStatuses[0].RestartCount = 1
		Expect(k8sClient.Status().Update(ctx, pod)).To(Succeed())
		Consistently(unparsableImageIDs, quiet, poll).Should(Equal(before + 1))
		Expect(existing).To(ContainElements(inventoryNames()), "no object was created")
	})

	// A task pod is a pod that the operator runs for itself, such as a scan pod. It carries
	// workloads.TaskLabel and runs in the operator's namespace. It is no workload of the cluster,
	// so the inventory never counts it, and neither does the counter of the containers it skips.
	//
	// Anyone who can create pods can set a label. So a pod that carries the label in any other
	// namespace is a workload like any other, and counts: otherwise, setting the label would hide a
	// workload from triage.
	//
	// Each spec creates a pod with the label inside the operator's namespace and one outside it. The
	// one outside is a workload, so its effect shows, and that shows that the manager has seen both
	// when the one inside has none.
	Describe("a pod with the task label", func() {
		It("is recorded outside the operator's namespace, and not inside it", func() {
			ns, digest := newNamespace(), newDigest()
			start(newTaskPod(operatorNamespace, "scan-a"), running(repoDigest(digest)))
			start(newTaskPod(ns, "p"), running(repoDigest(digest)))

			entry := localEntry(1, 1, refs(workloadRef(podKind, ns, "p")), repository)
			expectInventory(digest, startup, inventoryv1alpha1.DigestKindRepoDigest, entry)
			Consistently(func(g Gomega) {
				g.Expect(withoutTimes(g, stored(g, digest).Status.Clusters)).To(
					Equal([]inventoryv1alpha1.ClusterPresence{entry}), "the task pod never joins the entry")
			}, quiet, poll).Should(Succeed())
		})

		It("has its unparsable containers counted outside the operator's namespace, and not inside it", func() {
			before := unparsableImageIDs(Default)
			start(newTaskPod(operatorNamespace, "scan-a"), running("nginx:1.27"))
			start(newTaskPod(newNamespace(), "p"), running("nginx:1.27"))

			Eventually(unparsableImageIDs, reaction, poll).Should(Equal(before + 1))
			Consistently(unparsableImageIDs, quiet, poll).Should(Equal(before+1), "the task pod adds nothing")
		})
	})

	It("reports a successful run of the Workloads collector", func() {
		started := time.Now()
		ns, digest := newNamespace(), newDigest()
		createPod(ns, "p", nil, running(repoDigest(digest)))
		expectInventory(digest, startup, inventoryv1alpha1.DigestKindRepoDigest,
			localEntry(1, 1, refs(workloadRef(podKind, ns, "p")), repository))

		Eventually(func(g Gomega) {
			lastSuccess, lastErr, known := collectorRegistry.Health(configv1alpha1.CollectorTypeWorkloads)
			g.Expect(known).To(BeTrue())
			g.Expect(lastErr).NotTo(HaveOccurred())
			g.Expect(lastSuccess).To(BeTemporally(">=", started))
		}, reaction, poll).Should(Succeed())
	})

	Describe("owners", func() {
		DescribeTable("attributes a pod to its top-level workload when its controller arrives late",
			func(newController func(namespace, name string, owner *metav1.OwnerReference) client.Object,
				controllerKind, topKind schema.GroupVersionKind) {
				ns, digest := newNamespace(), newDigest()
				createPod(ns, "c-x7k2p", controlledBy(controllerKind, "c"), running(repoDigest(digest)))
				By("attributing the pod to its controller, which doesn't exist yet")
				expectInventory(digest, startup, inventoryv1alpha1.DigestKindRepoDigest,
					localEntry(1, 1, refs(workloadRef(controllerKind, ns, "c")), repository))

				createObject(newController(ns, "c", controlledBy(topKind, "top")))

				expectInventory(digest, reaction, inventoryv1alpha1.DigestKindRepoDigest,
					localEntry(1, 1, refs(workloadRef(topKind, ns, "top")), repository))
			},
			Entry("a ReplicaSet of a Deployment", replicaSet, replicaSetKind, deploymentKind),
			Entry("a Job of a CronJob", job, jobKind, cronJobKind),
		)

		It("follows a ReplicaSet that a Deployment adopts", func() {
			ns, digest := newNamespace(), newDigest()
			orphan := createObject(replicaSet(ns, "web-7c9d8f6b5", nil))
			createPod(ns, "web-7c9d8f6b5-x2k4p", controlledBy(replicaSetKind, "web-7c9d8f6b5"), running(repoDigest(digest)))
			expectInventory(digest, startup, inventoryv1alpha1.DigestKindRepoDigest,
				localEntry(1, 1, refs(workloadRef(replicaSetKind, ns, "web-7c9d8f6b5")), repository))

			By("making Deployment web the controller of the ReplicaSet")
			patch := client.MergeFrom(orphan.DeepCopyObject().(client.Object))
			orphan.SetOwnerReferences([]metav1.OwnerReference{*controlledBy(deploymentKind, "web")})
			Expect(k8sClient.Patch(ctx, orphan, patch)).To(Succeed())

			expectInventory(digest, reaction, inventoryv1alpha1.DigestKindRepoDigest,
				localEntry(1, 1, refs(workloadRef(deploymentKind, ns, "web")), repository))
		})
	})
})
