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
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
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

// platformFacts returns the facts of one scanned platform, as the scanning spoke writes them.
func platformFacts(platform string) inventoryv1alpha1.PlatformFacts {
	return inventoryv1alpha1.PlatformFacts{
		Platform:            platform,
		ManifestDigest:      newManifestDigest(),
		CompletenessPercent: ptr.To[int32](97),
		ELFFiles:            ptr.To[int32](120),
		Packages:            ptr.To[int32](85),
	}
}

// failureOf returns the failure of a scan that failed with the reason, for the second time in a row.
func failureOf(reason inventoryv1alpha1.ScanFailureReason) *inventoryv1alpha1.ScanFailure {
	return &inventoryv1alpha1.ScanFailure{
		Reason:   reason,
		Time:     ptr.To(metav1.NewTime(time.Now().Truncate(time.Second))),
		Attempts: 2,
	}
}

// scanFacts returns facts that the schema accepts: a scan of two platforms, and a failure that
// followed it. The facts keep the platforms of the last success while a later scan fails.
func scanFacts() *inventoryv1alpha1.ImageFacts {
	return &inventoryv1alpha1.ImageFacts{
		ScannerImage: ptr.To(scannerImage),
		ScannedTime:  ptr.To(metav1.NewTime(time.Now().Truncate(time.Second))),
		Platforms:    []inventoryv1alpha1.PlatformFacts{platformFacts("linux/amd64"), platformFacts("linux/arm64/v8")},
		Failure:      failureOf("PullFailed"),
	}
}

// writeFacts sets status.facts of the ImageInventory of digest through the status subresource, as
// the scanning spoke does, and returns the object as the API server answered, with the error of the
// write. The pod inventory may write the object between the read and the write. That is a conflict,
// and no answer about the facts, so the write is tried again.
func writeFacts(digest string, facts *inventoryv1alpha1.ImageFacts) (*inventoryv1alpha1.ImageInventory, error) {
	GinkgoHelper()
	var (
		obj *inventoryv1alpha1.ImageInventory
		err error
	)
	Eventually(func(g Gomega) {
		obj = stored(g, digest)
		obj.Status.Facts = facts
		err = k8sClient.Status().Update(ctx, obj)
		g.Expect(err).NotTo(Satisfy(apierrors.IsConflict))
	}, reaction, poll).Should(Succeed())
	return obj, err
}

// The facts of a scan are written by the spoke that scans, into the status of the ImageInventory of
// a digest that it runs. The specs check what the schema takes, against the real API server. They
// look at what their own write returned, and never read the object again: the pod inventory writes
// the status of an object when it reconciles it, and these specs don't depend on what it keeps.
var _ = Describe("ImageInventory scan facts", Ordered, ContinueOnFailure, func() {
	var digest string

	BeforeAll(func() {
		// A pod that runs the digest keeps the object. The pod inventory deletes an object that has no
		// entries.
		ns := newNamespace()
		digest = newDigest()
		createPod(ns, "p", nil, running(repoDigest(digest)))
		expectInventory(digest, startup, inventoryv1alpha1.DigestKindRepoDigest,
			localEntry(1, 1, refs(workloadRef(podKind, ns, "p")), repository))
	})

	It("takes status.facts through the status subresource, beside the entries of the clusters", func() {
		facts := scanFacts()

		answer, err := writeFacts(digest, facts)

		Expect(err).NotTo(HaveOccurred())
		got := answer.Status.Facts
		Expect(got).NotTo(BeNil())
		Expect(got.ScannerImage).To(HaveValue(Equal(scannerImage)))
		Expect(got.ScannedTime.Time).To(BeTemporally("==", facts.ScannedTime.Time))
		Expect(got.Platforms).To(Equal(facts.Platforms))
		Expect(got.Failure.Reason).To(Equal(inventoryv1alpha1.ScanFailureReason("PullFailed")))
		Expect(got.Failure.Time.Time).To(BeTemporally("==", facts.Failure.Time.Time))
		Expect(got.Failure.Attempts).To(Equal(int32(2)))
		Expect(answer.Status.Clusters).To(HaveLen(1), "the entries of the clusters are not touched")
	})

	It("takes facts with no failure, and facts with a failure and no success yet", func() {
		afterSuccess := scanFacts()
		afterSuccess.Failure = nil
		beforeSuccess := &inventoryv1alpha1.ImageFacts{Failure: failureOf("TimedOut")}

		_, err := writeFacts(digest, afterSuccess)
		Expect(err).NotTo(HaveOccurred())
		_, err = writeFacts(digest, beforeSuccess)
		Expect(err).NotTo(HaveOccurred())
	})

	// The reasons are an open enum, and the spoke writes these nine. Each one the schema refused
	// would leave a failed scan without a record.
	It("takes every reason of a failed scan", func() {
		for _, reason := range []inventoryv1alpha1.ScanFailureReason{
			"NotPullable", "PullFailed", "Unauthorized", "NotFound", "NoMatchingPlatform",
			"TooLarge", "CatalogFailed", "TimedOut", "Internal",
		} {
			facts := scanFacts()
			facts.Failure = failureOf(reason)

			_, err := writeFacts(digest, facts)

			Expect(err).NotTo(HaveOccurred(), "the reason %s", reason)
		}
	})

	It("takes 16 platforms, the most that it holds", func() {
		facts := scanFacts()
		facts.Platforms = nil
		for i := range 16 {
			facts.Platforms = append(facts.Platforms, platformFacts(fmt.Sprintf("linux/arch%d", i)))
		}
		facts.ScannerImage = ptr.To(chars(512))

		_, err := writeFacts(digest, facts)

		Expect(err).NotTo(HaveOccurred())
	})

	DescribeTable("rejects facts that break the schema",
		func(mutate func(*inventoryv1alpha1.ImageFacts), message string) {
			facts := scanFacts()
			mutate(facts)

			_, err := writeFacts(digest, facts)

			Expect(err).To(Satisfy(apierrors.IsInvalid))
			Expect(err).To(MatchError(ContainSubstring(message)))
		},
		Entry("a scanner image of 513 characters",
			func(f *inventoryv1alpha1.ImageFacts) { f.ScannerImage = ptr.To(chars(513)) },
			"status.facts.scannerImage: Too long"),
		Entry("17 platforms",
			func(f *inventoryv1alpha1.ImageFacts) {
				f.Platforms = nil
				for i := range 17 {
					f.Platforms = append(f.Platforms, platformFacts(fmt.Sprintf("linux/arch%d", i)))
				}
			},
			"status.facts.platforms: Too many"),
		Entry("two entries for one platform",
			func(f *inventoryv1alpha1.ImageFacts) { f.Platforms[1].Platform = f.Platforms[0].Platform },
			"status.facts.platforms[1]: Duplicate value"),
		Entry("a platform without an architecture",
			func(f *inventoryv1alpha1.ImageFacts) { f.Platforms[0].Platform = "linux" },
			"status.facts.platforms[0].platform: Invalid value"),
		Entry("a platform in upper case",
			func(f *inventoryv1alpha1.ImageFacts) { f.Platforms[0].Platform = "Linux/amd64" },
			"status.facts.platforms[0].platform: Invalid value"),
		Entry("a platform with two variants",
			func(f *inventoryv1alpha1.ImageFacts) { f.Platforms[0].Platform = "linux/arm64/v8/v9" },
			"status.facts.platforms[0].platform: Invalid value"),
		Entry("a platform entry without a manifest digest",
			func(f *inventoryv1alpha1.ImageFacts) { f.Platforms[0].ManifestDigest = "" },
			"status.facts.platforms[0].manifestDigest: Required value"),
		Entry("a manifest digest that is not a sha256 digest",
			func(f *inventoryv1alpha1.ImageFacts) { f.Platforms[0].ManifestDigest = "sha256:abc" },
			"status.facts.platforms[0].manifestDigest: Invalid value"),
		Entry("a completeness of 101 percent",
			func(f *inventoryv1alpha1.ImageFacts) { f.Platforms[0].CompletenessPercent = ptr.To[int32](101) },
			"status.facts.platforms[0].completenessPercent: Invalid value"),
		Entry("a negative completeness",
			func(f *inventoryv1alpha1.ImageFacts) { f.Platforms[0].CompletenessPercent = ptr.To[int32](-1) },
			"status.facts.platforms[0].completenessPercent: Invalid value"),
		Entry("a platform entry without a completeness",
			func(f *inventoryv1alpha1.ImageFacts) { f.Platforms[0].CompletenessPercent = nil },
			"status.facts.platforms[0].completenessPercent: Required value"),
		Entry("a negative count of ELF files",
			func(f *inventoryv1alpha1.ImageFacts) { f.Platforms[0].ELFFiles = ptr.To[int32](-1) },
			"status.facts.platforms[0].elfFiles: Invalid value"),
		Entry("a negative count of packages",
			func(f *inventoryv1alpha1.ImageFacts) { f.Platforms[0].Packages = ptr.To[int32](-1) },
			"status.facts.platforms[0].packages: Invalid value"),
		Entry("a failure reason that no version knows",
			func(f *inventoryv1alpha1.ImageFacts) { f.Failure.Reason = unknownValue },
			`status.facts.failure.reason: Unsupported value: "`+unknownValue+`"`),
		Entry("a failure without a reason",
			func(f *inventoryv1alpha1.ImageFacts) { f.Failure.Reason = "" },
			"status.facts.failure.reason: Required value"),
		Entry("a failure without a time",
			func(f *inventoryv1alpha1.ImageFacts) { f.Failure.Time = nil },
			"status.facts.failure.time: Required value"),
		// A client that sends no attempts, or 0, which Go omits, sends none: a failure has failed once.
		Entry("a failure without attempts",
			func(f *inventoryv1alpha1.ImageFacts) { f.Failure.Attempts = 0 },
			"status.facts.failure.attempts: Required value"),
		Entry("a failure with a negative number of attempts",
			func(f *inventoryv1alpha1.ImageFacts) { f.Failure.Attempts = -1 },
			"status.facts.failure.attempts: Invalid value"),
	)

	// Go leaves out an attempts of 0, so a typed client can't send one. The schema still refuses it
	// from a client that can.
	It("rejects a failure with 0 attempts that a client sends", func() {
		obj := stored(Default, digest)
		patch := client.RawPatch(types.MergePatchType, []byte(
			`{"status":{"facts":{"failure":{"reason":"TimedOut","time":"2026-10-30T12:00:00Z","attempts":0}}}}`))

		err := k8sClient.Status().Patch(ctx, obj, patch)

		Expect(err).To(Satisfy(apierrors.IsInvalid))
		Expect(err).To(MatchError(ContainSubstring("status.facts.failure.attempts: Invalid value")))
	})
})
