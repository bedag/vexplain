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
	"github.com/bedag/vexplain/sdk/workloads"
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
		digest := newDigest()
		observeHere(digest)
		obj := stored(Default, digest)

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
		// Nine platforms, the longest that the schema takes among them: the store keeps the first eight.
		for i := range 9 {
			observation.Platforms = append(observation.Platforms, fmt.Sprintf("linux/arch%d/%s", i, chars(52)))
		}
		// The spec only writes through the store, so it needs no cache to watch through.
		Expect(storeOf(observation.Cluster).Observe(ctx, digest, observation)).To(Succeed())

		entries := stored(Default, digest).Status.Clusters
		Expect(entries).To(HaveExactElements(HaveField("Cluster", observation.Cluster)))
		atLimits := entries[0]
		Expect(atLimits.WorkloadCount).To(HaveValue(Equal(int32(103))), "every workload counts")
		Expect(atLimits.Workloads).To(HaveLen(100))
		daemonSets := slices.DeleteFunc(slices.Clone(atLimits.Workloads),
			func(workload inventoryv1alpha1.WorkloadReference) bool { return workload.Kind != daemonSetKind })
		Expect(daemonSets).To(HaveLen(1), "the two DaemonSets share a key, so the list holds one of them")
		Expect(atLimits.Repositories).To(HaveLen(32))
		Expect(atLimits.Platforms).To(HaveLen(8))
		Expect(atLimits.Platforms[0]).To(HaveLen(64))
	})

	DescribeTable("refuses the platforms of an entry that break the schema",
		func(platforms []string, message string) {
			digest := newDigest()
			observeHere(digest)
			obj := stored(Default, digest)

			obj.Status.Clusters[0].Platforms = platforms
			err := k8sClient.Status().Update(ctx, obj)

			Expect(err).To(Satisfy(apierrors.IsInvalid))
			Expect(err).To(MatchError(ContainSubstring(message)))
		},
		Entry("nine of them", []string{
			amd64, "linux/arm64", "linux/arm/v7", "linux/arm/v6", "linux/386", "linux/ppc64le",
			"linux/s390x", "linux/riscv64", "linux/mips64le",
		}, "clusters[0].platforms: Too many"),
		Entry("an operating system without an architecture", []string{"linux"}, "clusters[0].platforms[0]: Invalid value"),
		Entry("a platform in upper case", []string{"Linux/AMD64"}, "clusters[0].platforms[0]: Invalid value"),
		Entry("a platform of 65 characters", []string{"linux/arm64/" + chars(53)}, "clusters[0].platforms[0]: Too long"),
		Entry("the same platform twice", []string{amd64, amd64}, "clusters[0].platforms[1]: Duplicate value"),
	)
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

// failureOf returns the failure of the attempts of a source, the last one for the reason, for the
// second time in a row.
func failureOf(source string, reason inventoryv1alpha1.ScanFailureReason) inventoryv1alpha1.ScanFailure {
	return inventoryv1alpha1.ScanFailure{
		Source:   source,
		Reason:   reason,
		Message:  ptr.To("the registry refused the pull"),
		Time:     ptr.To(metav1.NewTime(time.Now().Truncate(time.Second))),
		Attempts: 2,
	}
}

// scanFacts returns facts that the schema accepts: the scanner's evidence of two platforms, and a
// failure of the scanner that followed it. The facts keep what the last success recorded while a
// later attempt fails.
func scanFacts() *inventoryv1alpha1.ImageFacts {
	return &inventoryv1alpha1.ImageFacts{
		Manifests: []inventoryv1alpha1.ManifestFact{manifestFact("linux/amd64"), manifestFact("linux/arm64/v8")},
		Evidence:  []inventoryv1alpha1.EvidenceFact{evidenceFact("scanner", imageContentsType)},
		Failures:  []inventoryv1alpha1.ScanFailure{failureOf("scanner", "PullFailed")},
	}
}

// writeFacts sets status.facts of the ImageInventory of digest through the status subresource, as
// the scanning spoke does, and returns the object as the API server answered, with the error of the
// write.
func writeFacts(digest string, facts *inventoryv1alpha1.ImageFacts) (*inventoryv1alpha1.ImageInventory, error) {
	GinkgoHelper()
	obj := stored(Default, digest)
	obj.Status.Facts = facts
	err := k8sClient.Status().Update(ctx, obj)
	return obj, err
}

// The facts of a scan are written by the spoke that scans, into the status of the ImageInventory of
// a digest that it runs. The specs check what the schema takes, against the real API server. They
// look at what their own write returned.
var _ = Describe("ImageInventory scan facts", Ordered, ContinueOnFailure, func() {
	var digest string

	BeforeAll(func() {
		digest = newDigest()
		observeHere(digest)
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
		Expect(got.Failures).To(HaveLen(1))
		failure := got.Failures[0]
		Expect(failure.Source).To(Equal("scanner"))
		Expect(failure.Reason).To(Equal(inventoryv1alpha1.ScanFailureReason("PullFailed")))
		Expect(failure.Message).To(HaveValue(Equal("the registry refused the pull")))
		Expect(failure.Time.Time).To(BeTemporally("==", facts.Failures[0].Time.Time))
		Expect(failure.Attempts).To(Equal(int32(2)))
		Expect(answer.Status.Clusters).To(HaveLen(1), "the entries of the clusters are not touched")
	})

	It("takes facts with no failure, facts with a failure and no success yet, a failure without a message, and failures of several sources", func() {
		afterSuccess := scanFacts()
		afterSuccess.Failures = nil
		beforeSuccess := &inventoryv1alpha1.ImageFacts{Failures: []inventoryv1alpha1.ScanFailure{failureOf("scanner", "TimedOut")}}
		withoutMessage := scanFacts()
		withoutMessage.Failures[0].Message = nil
		ofSeveral := scanFacts()
		ofSeveral.Failures = append(ofSeveral.Failures, failureOf("matcher", "NotFound"))

		for _, facts := range []*inventoryv1alpha1.ImageFacts{afterSuccess, beforeSuccess, withoutMessage, ofSeveral} {
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
			facts.Failures = []inventoryv1alpha1.ScanFailure{failureOf("scanner", reason)}

			_, err := writeFacts(digest, facts)

			Expect(err).NotTo(HaveOccurred(), "the reason %s", reason)
		}
	})

	It("takes 16 manifests, 32 pieces of evidence and 8 failures, the most that it holds, with every text at its limit", func() {
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
		facts.Failures = nil
		for i := range 8 {
			facts.Failures = append(facts.Failures, failureOf(fmt.Sprintf("collector-%02d", i), "Internal"))
		}
		facts.Failures[0].Source = chars(44)
		facts.Failures[1].Message = ptr.To(chars(256))

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
		Entry("9 failures",
			func(f *inventoryv1alpha1.ImageFacts) {
				f.Failures = nil
				for i := range 9 {
					f.Failures = append(f.Failures, failureOf(fmt.Sprintf("collector-%02d", i), "Internal"))
				}
			},
			"status.facts.failures: Too many"),
		Entry("two failures of one source",
			func(f *inventoryv1alpha1.ImageFacts) {
				f.Failures = append(f.Failures, failureOf("scanner", "NotFound"))
			},
			"status.facts.failures[1]: Duplicate value"),
		Entry("a failure without a source",
			func(f *inventoryv1alpha1.ImageFacts) { f.Failures[0].Source = "" },
			"status.facts.failures[0].source: Required value"),
		Entry("a failure of a source that is no Collector's name",
			func(f *inventoryv1alpha1.ImageFacts) { f.Failures[0].Source = "scan_ner" },
			"status.facts.failures[0].source: Invalid value"),
		Entry("a failure without a reason",
			func(f *inventoryv1alpha1.ImageFacts) { f.Failures[0].Reason = "" },
			"status.facts.failures[0].reason: Required value"),
		Entry("a reason that is not one word",
			func(f *inventoryv1alpha1.ImageFacts) { f.Failures[0].Reason = "not found" },
			"status.facts.failures[0].reason: Invalid value"),
		Entry("a reason of 65 characters",
			func(f *inventoryv1alpha1.ImageFacts) {
				f.Failures[0].Reason = inventoryv1alpha1.ScanFailureReason("A" + chars(64))
			},
			"status.facts.failures[0].reason: Too long"),
		Entry("an empty message",
			func(f *inventoryv1alpha1.ImageFacts) { f.Failures[0].Message = ptr.To("") },
			"status.facts.failures[0].message: Invalid value"),
		Entry("a message of 257 characters",
			func(f *inventoryv1alpha1.ImageFacts) { f.Failures[0].Message = ptr.To(chars(257)) },
			"status.facts.failures[0].message: Too long"),
		Entry("a failure without a time",
			func(f *inventoryv1alpha1.ImageFacts) { f.Failures[0].Time = nil },
			"status.facts.failures[0].time: Required value"),
		// A client that sends no attempts, or 0, which Go omits, sends none: a failure has failed once.
		Entry("a failure without attempts",
			func(f *inventoryv1alpha1.ImageFacts) { f.Failures[0].Attempts = 0 },
			"status.facts.failures[0].attempts: Required value"),
		Entry("a failure with a negative number of attempts",
			func(f *inventoryv1alpha1.ImageFacts) { f.Failures[0].Attempts = -1 },
			"status.facts.failures[0].attempts: Invalid value"),
	)

	// Go leaves out an attempts of 0, so a typed client can't send one. The schema still refuses it
	// from a client that can.
	It("rejects a failure with 0 attempts that a client sends", func() {
		obj := stored(Default, digest)
		patch := client.RawPatch(types.MergePatchType, []byte(
			`{"status":{"facts":{"failures":[{"source":"scanner","reason":"TimedOut","time":"2026-10-30T12:00:00Z","attempts":0}]}}}`))

		err := k8sClient.Status().Patch(ctx, obj, patch)

		Expect(err).To(Satisfy(apierrors.IsInvalid))
		Expect(err).To(MatchError(ContainSubstring("status.facts.failures[0].attempts: Invalid value")))
	})
})
