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
		Expect(inventory.NewCRDStore(k8sClient, nil, func() string { return observation.Cluster }).
			Observe(ctx, digest, observation)).To(Succeed())

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

// The type of the scanner's evidence, which the facts of the specs record.
const imageContentsType = "ch.bedag.vexplain.scanner.image-contents.v1alpha1"

// manifestFact returns a platform manifest of an image, as the facts record it.
func manifestFact(platform string) inventoryv1alpha1.ManifestFact {
	return inventoryv1alpha1.ManifestFact{Platform: platform, Digest: newManifestDigest()}
}

// evidenceFact returns what the facts record of the evidence of a source and type: the collector's
// version, the time and the coverage.
func evidenceFact(source, evidenceType string) inventoryv1alpha1.EvidenceFact {
	return inventoryv1alpha1.EvidenceFact{
		Source:           source,
		Type:             evidenceType,
		CollectorVersion: "1.0.0",
		Time:             ptr.To(metav1.NewTime(time.Now().Truncate(time.Second))),
		Coverage:         ptr.To[int32](97),
	}
}

// failureOf returns the failure of the scanner's attempts, the last one for the reason, for the
// second time in a row.
func failureOf(reason inventoryv1alpha1.ScanFailureReason) *inventoryv1alpha1.ScanFailure {
	return &inventoryv1alpha1.ScanFailure{
		Source:   "scanner",
		Reason:   reason,
		Message:  ptr.To("the registry refused the pull"),
		Time:     ptr.To(metav1.NewTime(time.Now().Truncate(time.Second))),
		Attempts: 2,
	}
}

// scanFacts returns facts that the schema accepts: the scanner's evidence of two platforms, and a
// failure that followed it. The facts keep what the last success recorded while a later attempt
// fails.
func scanFacts() *inventoryv1alpha1.ImageFacts {
	return &inventoryv1alpha1.ImageFacts{
		Manifests: []inventoryv1alpha1.ManifestFact{manifestFact("linux/amd64"), manifestFact("linux/arm64/v8")},
		Evidence:  []inventoryv1alpha1.EvidenceFact{evidenceFact("scanner", imageContentsType)},
		Failure:   failureOf("PullFailed"),
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
		Expect(got.Manifests).To(Equal(facts.Manifests))
		Expect(got.Evidence).To(HaveLen(1))
		Expect(got.Evidence[0].Time.Time).To(BeTemporally("==", facts.Evidence[0].Time.Time))
		got.Evidence[0].Time = facts.Evidence[0].Time
		Expect(got.Evidence).To(Equal(facts.Evidence))
		Expect(got.Failure.Source).To(Equal("scanner"))
		Expect(got.Failure.Reason).To(Equal(inventoryv1alpha1.ScanFailureReason("PullFailed")))
		Expect(got.Failure.Message).To(HaveValue(Equal("the registry refused the pull")))
		Expect(got.Failure.Time.Time).To(BeTemporally("==", facts.Failure.Time.Time))
		Expect(got.Failure.Attempts).To(Equal(int32(2)))
		Expect(answer.Status.Clusters).To(HaveLen(1), "the entries of the clusters are not touched")
	})

	It("takes facts with no failure, facts with a failure and no success yet, and a failure without a message", func() {
		afterSuccess := scanFacts()
		afterSuccess.Failure = nil
		beforeSuccess := &inventoryv1alpha1.ImageFacts{Failure: failureOf("TimedOut")}
		withoutMessage := scanFacts()
		withoutMessage.Failure.Message = nil

		for _, facts := range []*inventoryv1alpha1.ImageFacts{afterSuccess, beforeSuccess, withoutMessage} {
			_, err := writeFacts(digest, facts)
			Expect(err).NotTo(HaveOccurred())
		}
	})

	// The reasons are an open vocabulary: it starts with the nine of the scans, and a collector may
	// report one of its own of the same form. Each one the schema refused would leave a failure
	// without a record.
	It("takes every reason of a failed scan, and a reason that a collector adds", func() {
		for _, reason := range []inventoryv1alpha1.ScanFailureReason{
			"NotPullable", "PullFailed", "Unauthorized", "NotFound", "NoMatchingPlatform",
			"TooLarge", "CatalogFailed", "TimedOut", "Internal", "RateLimited", inventoryv1alpha1.ScanFailureReason("A" + chars(63)),
		} {
			facts := scanFacts()
			facts.Failure = failureOf(reason)

			_, err := writeFacts(digest, facts)

			Expect(err).NotTo(HaveOccurred(), "the reason %s", reason)
		}
	})

	It("takes 16 manifests and 32 pieces of evidence, the most that it holds, with every text at its limit", func() {
		facts := scanFacts()
		facts.Manifests = nil
		for i := range 16 {
			facts.Manifests = append(facts.Manifests, manifestFact(fmt.Sprintf("linux/arch%d", i)))
		}
		facts.Evidence = nil
		for i := range 32 {
			fact := evidenceFact(fmt.Sprintf("collector-%02d", i), imageContentsType)
			fact.CollectorVersion = chars(128)
			facts.Evidence = append(facts.Evidence, fact)
		}
		facts.Evidence[0].Source = chars(44)
		facts.Evidence[1].Type = typeOfLength(253)
		facts.Failure.Source = chars(44)
		facts.Failure.Message = ptr.To(chars(256))

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
		Entry("17 manifests",
			func(f *inventoryv1alpha1.ImageFacts) {
				f.Manifests = nil
				for i := range 17 {
					f.Manifests = append(f.Manifests, manifestFact(fmt.Sprintf("linux/arch%d", i)))
				}
			},
			"status.facts.manifests: Too many"),
		Entry("two manifests of one platform",
			func(f *inventoryv1alpha1.ImageFacts) { f.Manifests[1].Platform = f.Manifests[0].Platform },
			"status.facts.manifests[1]: Duplicate value"),
		Entry("a platform without an architecture",
			func(f *inventoryv1alpha1.ImageFacts) { f.Manifests[0].Platform = "linux" },
			"status.facts.manifests[0].platform: Invalid value"),
		Entry("a platform in upper case",
			func(f *inventoryv1alpha1.ImageFacts) { f.Manifests[0].Platform = "Linux/amd64" },
			"status.facts.manifests[0].platform: Invalid value"),
		Entry("a platform with two variants",
			func(f *inventoryv1alpha1.ImageFacts) { f.Manifests[0].Platform = "linux/arm64/v8/v9" },
			"status.facts.manifests[0].platform: Invalid value"),
		Entry("a manifest without a digest",
			func(f *inventoryv1alpha1.ImageFacts) { f.Manifests[0].Digest = "" },
			"status.facts.manifests[0].digest: Required value"),
		Entry("a digest that is not a sha256 digest",
			func(f *inventoryv1alpha1.ImageFacts) { f.Manifests[0].Digest = "sha256:abc" },
			"status.facts.manifests[0].digest: Invalid value"),
		Entry("33 pieces of evidence",
			func(f *inventoryv1alpha1.ImageFacts) {
				f.Evidence = nil
				for i := range 33 {
					f.Evidence = append(f.Evidence, evidenceFact(fmt.Sprintf("collector-%02d", i), imageContentsType))
				}
			},
			"status.facts.evidence: Too many"),
		Entry("two pieces of evidence of one source and type",
			func(f *inventoryv1alpha1.ImageFacts) { f.Evidence = append(f.Evidence, f.Evidence[0]) },
			"status.facts.evidence[1]: Duplicate value"),
		Entry("evidence without a source",
			func(f *inventoryv1alpha1.ImageFacts) { f.Evidence[0].Source = "" },
			"status.facts.evidence[0].source: Required value"),
		Entry("evidence of a source that is no Collector's name",
			func(f *inventoryv1alpha1.ImageFacts) { f.Evidence[0].Source = "Scanner" },
			"status.facts.evidence[0].source: Invalid value"),
		Entry("evidence of a source of 45 characters",
			func(f *inventoryv1alpha1.ImageFacts) { f.Evidence[0].Source = chars(45) },
			"status.facts.evidence[0].source: Too long"),
		Entry("evidence without a type",
			func(f *inventoryv1alpha1.ImageFacts) { f.Evidence[0].Type = "" },
			"status.facts.evidence[0].type: Required value"),
		Entry("evidence of a type without a version",
			func(f *inventoryv1alpha1.ImageFacts) { f.Evidence[0].Type = "ch.bedag.vexplain.scanner.image-contents" },
			"status.facts.evidence[0].type: Invalid value"),
		Entry("evidence without a collector version",
			func(f *inventoryv1alpha1.ImageFacts) { f.Evidence[0].CollectorVersion = "" },
			"status.facts.evidence[0].collectorVersion: Required value"),
		Entry("evidence of a collector version of 129 characters",
			func(f *inventoryv1alpha1.ImageFacts) { f.Evidence[0].CollectorVersion = chars(129) },
			"status.facts.evidence[0].collectorVersion: Too long"),
		Entry("evidence without a time",
			func(f *inventoryv1alpha1.ImageFacts) { f.Evidence[0].Time = nil },
			"status.facts.evidence[0].time: Required value"),
		Entry("a coverage of 101 percent",
			func(f *inventoryv1alpha1.ImageFacts) { f.Evidence[0].Coverage = ptr.To[int32](101) },
			"status.facts.evidence[0].coverage: Invalid value"),
		Entry("a negative coverage",
			func(f *inventoryv1alpha1.ImageFacts) { f.Evidence[0].Coverage = ptr.To[int32](-1) },
			"status.facts.evidence[0].coverage: Invalid value"),
		Entry("a failure without a source",
			func(f *inventoryv1alpha1.ImageFacts) { f.Failure.Source = "" },
			"status.facts.failure.source: Required value"),
		Entry("a failure of a source that is no Collector's name",
			func(f *inventoryv1alpha1.ImageFacts) { f.Failure.Source = "scan_ner" },
			"status.facts.failure.source: Invalid value"),
		Entry("a failure without a reason",
			func(f *inventoryv1alpha1.ImageFacts) { f.Failure.Reason = "" },
			"status.facts.failure.reason: Required value"),
		Entry("a reason that is not one word",
			func(f *inventoryv1alpha1.ImageFacts) { f.Failure.Reason = "not found" },
			"status.facts.failure.reason: Invalid value"),
		Entry("a reason of 65 characters",
			func(f *inventoryv1alpha1.ImageFacts) {
				f.Failure.Reason = inventoryv1alpha1.ScanFailureReason("A" + chars(64))
			},
			"status.facts.failure.reason: Too long"),
		Entry("an empty message",
			func(f *inventoryv1alpha1.ImageFacts) { f.Failure.Message = ptr.To("") },
			"status.facts.failure.message: Invalid value"),
		Entry("a message of 257 characters",
			func(f *inventoryv1alpha1.ImageFacts) { f.Failure.Message = ptr.To(chars(257)) },
			"status.facts.failure.message: Too long"),
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
			`{"status":{"facts":{"failure":{"source":"scanner","reason":"TimedOut","time":"2026-10-30T12:00:00Z","attempts":0}}}}`))

		err := k8sClient.Status().Patch(ctx, obj, patch)

		Expect(err).To(Satisfy(apierrors.IsInvalid))
		Expect(err).To(MatchError(ContainSubstring("status.facts.failure.attempts: Invalid value")))
	})
})
