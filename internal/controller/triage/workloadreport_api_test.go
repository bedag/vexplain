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

package triage_test

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/types"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	triagev1alpha1 "github.com/bedag/vexplain/api/triage/v1alpha1"
)

const (
	// maxActions is the most actions that a report lists.
	maxActions = 256
	// oneMiB is the size that the renderer keeps the status of a report under: about two thirds of the
	// 1.5 MiB that etcd takes for a request, which leaves room for the rest of the object.
	oneMiB = 1 << 20
	// workloadRule is the message of the rule that makes the spec of a report immutable.
	workloadRule = "the workload of a WorkloadReport can't change: delete the report to report on another workload"
	// imageContents is the type of evidence that the specs say an image's coverage is of.
	imageContents = "ch.bedag.vexplain.scanner.image-contents.v1alpha1"
	// scannerSource is the name of the Collector that delivers it.
	scannerSource = "scanner"
	// amd64 is the platform that the specs run their images on.
	amd64 = "linux/amd64"
	// guess is a value that no enum of the API has, in this version or in a later one.
	guess = "Guess"
	// statusField is the field of the status in the errors of the API server.
	statusField = "status"
	// digestLabel starts the label that names an image digest on a report.
	digestLabel = "digest.vexplain.bedag.ch/"
	// deployment and webName are the kind and the name of the workload that the specs report on.
	deployment = "Deployment"
	webName    = "web"
	// cve1 is the ID of the vulnerability of the actions that the specs write.
	cve1 = "CVE-2026-0001"
	// teamKey is the key of the label that the specs copy as an owner value, and teamA its value.
	teamKey = "team"
	teamA   = "team-a"
)

// reportCount numbers the reports that the specs create, which share one namespace.
var reportCount int

// newReport returns the report of a Deployment of the namespace, with no status. The status is a
// subresource, so the API server ignores one on create: a spec writes it in a second call.
func newReport() *triagev1alpha1.WorkloadReport {
	reportCount++
	return &triagev1alpha1.WorkloadReport{
		ObjectMeta: metav1.ObjectMeta{Namespace: workloadNamespace, Name: fmt.Sprintf("deployment-web-%03d", reportCount)},
		Spec: triagev1alpha1.WorkloadReportSpec{Workload: triagev1alpha1.WorkloadReference{
			APIGroup: ptr.To("apps"), Kind: deployment, Name: webName,
		}},
	}
}

// podWorkload returns a bare pod, a workload of the core group, which has no API group.
func podWorkload() triagev1alpha1.WorkloadReference {
	return triagev1alpha1.WorkloadReference{Kind: "Pod", Name: "web-0"}
}

// createReport creates obj, and deletes it after the spec.
func createReport(obj *triagev1alpha1.WorkloadReport) {
	GinkgoHelper()
	Expect(k8sClient.Create(ctx, obj)).To(Succeed())
	DeferCleanup(func() {
		Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, obj))).To(Succeed())
	})
}

// existingReport creates a report and returns it, to write a status to.
func existingReport() *triagev1alpha1.WorkloadReport {
	GinkgoHelper()
	obj := newReport()
	createReport(obj)
	return obj
}

// refusedWith matches the error of a request that the API server refused as invalid, and whose
// message holds each of parts: the field that it names, or the message of the rule that refused it.
func refusedWith(parts ...string) types.GomegaMatcher {
	matchers := make([]types.GomegaMatcher, 0, 1+len(parts))
	matchers = append(matchers, Satisfy(apierrors.IsInvalid))
	for _, part := range parts {
		matchers = append(matchers, MatchError(ContainSubstring(part)))
	}
	return And(matchers...)
}

// chars returns a string of n characters. The specs of a schema limit write a value of exactly that
// length, which the schema admits, and one that is a character longer, which it refuses.
func chars(n int) string {
	return strings.Repeat("a", n)
}

// typeOfLength returns a name that matches the pattern of types of evidence and is n characters
// long: a run of letters, then two more labels, the last of them the version.
func typeOfLength(n int) string {
	const tail = ".b.v1"
	return chars(n-len(tail)) + tail
}

// digestOf returns the sha256 digest that is made of the number n.
func digestOf(n int) string {
	return fmt.Sprintf("sha256:%064x", n)
}

// action returns an action that the schema accepts, with only what it requires.
func action() triagev1alpha1.ReportAction {
	return triagev1alpha1.ReportAction{
		Step: triagev1alpha1.NextStepUpdate,
		Package: triagev1alpha1.ReportPackage{
			Name: "brotli-libs", Version: ptr.To("1.1.0-r2"), Type: "apk",
		},
		Severity:         triagev1alpha1.SeverityHigh,
		Urgency:          triagev1alpha1.SSVCOutcomeScheduled,
		KnownExploited:   triagev1alpha1.KnownExploitedNotListed,
		Vulnerabilities:  1,
		VulnerabilityIDs: []string{cve1},
		Digests:          []string{digestOf(1)},
	}
}

// summary returns a summary that the schema accepts: one finding of each status, one action, an update.
func summary() *triagev1alpha1.ReportSummary {
	return &triagev1alpha1.ReportSummary{
		Affected:           ptr.To[int32](1),
		UnderInvestigation: ptr.To[int32](0),
		NotAffected:        ptr.To[int32](3),
		Fixed:              ptr.To[int32](2),
		Actions:            ptr.To[int32](1),
		Updates:            ptr.To[int32](1),
		Mitigations:        ptr.To[int32](0),
		Investigations:     ptr.To[int32](0),
		OmittedActions:     ptr.To[int32](0),
		HighestUrgency:     ptr.To(triagev1alpha1.SSVCOutcomeScheduled),
		Critical:           ptr.To[int32](0),
		KnownExploited:     ptr.To[int32](1),
		Pending:            ptr.To[int32](0),
		Incomplete:         ptr.To[int32](0),
	}
}

// fullStatus returns a status that the schema accepts, and that sets every field of it: one
// condition, one image with its coverage, one action with its optional fields, the summary, one owner
// value, and the exposure and the reach.
func fullStatus() triagev1alpha1.WorkloadReportStatus {
	listed := action()
	listed.FixedVersion = ptr.To("1.1.0-r3")
	listed.KnownExploited = triagev1alpha1.KnownExploitedListed
	return triagev1alpha1.WorkloadReportStatus{
		Conditions: []metav1.Condition{{
			Type:               "Ready",
			Status:             metav1.ConditionTrue,
			Reason:             "Rendered",
			Message:            "every image has its result",
			ObservedGeneration: 1,
			LastTransitionTime: metav1.NewTime(time.Now().Truncate(time.Second)),
		}},
		Images: []triagev1alpha1.ReportImage{{
			Digest:         digestOf(1),
			Platform:       ptr.To(amd64),
			ManifestDigest: ptr.To(digestOf(2)),
			State:          triagev1alpha1.ReportImageStateReady,
			Coverage: []triagev1alpha1.ReportCoverage{
				{Source: scannerSource, Type: imageContents, Coverage: ptr.To[int32](80)},
			},
		}},
		Actions: []triagev1alpha1.ReportAction{listed},
		Summary: summary(),
		Owner: []triagev1alpha1.OwnerValue{
			{Source: triagev1alpha1.OwnerSourceNamespaceLabel, Key: teamKey, Value: ptr.To(teamA)},
		},
		Exposure: ptr.To(triagev1alpha1.SSVCExposureOpen),
		Reach: &triagev1alpha1.ReportReach{
			InternalReach: triagev1alpha1.InternalReachCluster, Indirect: triagev1alpha1.IndirectExposureNotIndirect,
		},
	}
}

// ofAction changes the one action of the status that the rejection specs start from.
func ofAction(change func(*triagev1alpha1.ReportAction)) func(*triagev1alpha1.WorkloadReportStatus) {
	return func(status *triagev1alpha1.WorkloadReportStatus) { change(&status.Actions[0]) }
}

// ofSummary changes the summary of the status that the rejection specs start from.
func ofSummary(change func(*triagev1alpha1.ReportSummary)) func(*triagev1alpha1.WorkloadReportStatus) {
	return func(status *triagev1alpha1.WorkloadReportStatus) { change(status.Summary) }
}

// ofImage changes the one image of the status that the rejection specs start from.
func ofImage(change func(*triagev1alpha1.ReportImage)) func(*triagev1alpha1.WorkloadReportStatus) {
	return func(status *triagev1alpha1.WorkloadReportStatus) { change(&status.Images[0]) }
}

// ofCoverage changes the one coverage entry of the one image of the status.
func ofCoverage(change func(*triagev1alpha1.ReportCoverage)) func(*triagev1alpha1.WorkloadReportStatus) {
	return func(status *triagev1alpha1.WorkloadReportStatus) { change(&status.Images[0].Coverage[0]) }
}

// ofOwner changes the one owner value of the status that the rejection specs start from.
func ofOwner(change func(*triagev1alpha1.OwnerValue)) func(*triagev1alpha1.WorkloadReportStatus) {
	return func(status *triagev1alpha1.WorkloadReportStatus) { change(&status.Owner[0]) }
}

// ofReach changes the reach of the status that the rejection specs start from.
func ofReach(change func(*triagev1alpha1.ReportReach)) func(*triagev1alpha1.WorkloadReportStatus) {
	return func(status *triagev1alpha1.WorkloadReportStatus) { change(status.Reach) }
}

// largestAction returns an action whose texts are each length characters of text, or as many as the
// schema allows when that is fewer, with as many IDs and digests as it lists. The digests have the
// pattern of a digest, and so only its length.
func largestAction(length int, text string) triagev1alpha1.ReportAction {
	of := func(limit int) string { return strings.Repeat(text, min(length, limit)) }
	largest := action()
	largest.Package = triagev1alpha1.ReportPackage{Name: of(253), Version: ptr.To(of(128)), Type: of(32)}
	largest.FixedVersion = ptr.To(of(128))
	largest.Vulnerabilities = 1 << 30
	largest.VulnerabilityIDs = nil
	for i := range 5 {
		largest.VulnerabilityIDs = append(largest.VulnerabilityIDs, fmt.Sprint(i)+of(63))
	}
	largest.Digests = nil
	for i := range 8 {
		largest.Digests = append(largest.Digests, digestOf(i+1))
	}
	return largest
}

// fullLists returns 32 images, each with 32 coverage entries of the longest source and type, and 48
// owner values of the longest key and value: every list of a report but the actions at its limit.
func fullLists() ([]triagev1alpha1.ReportImage, []triagev1alpha1.OwnerValue) {
	images := make([]triagev1alpha1.ReportImage, 0, 32)
	for i := range 32 {
		coverage := make([]triagev1alpha1.ReportCoverage, 0, 32)
		for n := range 32 {
			coverage = append(coverage, triagev1alpha1.ReportCoverage{
				Source: fmt.Sprintf("source-%02d", n) + chars(35), Type: typeOfLength(253), Coverage: ptr.To[int32](100),
			})
		}
		images = append(images, triagev1alpha1.ReportImage{
			Digest: digestOf(i + 1), State: triagev1alpha1.ReportImageStatePending, Coverage: coverage,
		})
	}
	owner := make([]triagev1alpha1.OwnerValue, 0, 48)
	for n := range 48 {
		owner = append(owner, triagev1alpha1.OwnerValue{
			Source: triagev1alpha1.OwnerSourceNamespaceAnnotation,
			Key:    fmt.Sprintf("%s%02d/%s", chars(251), n, chars(63)), Value: ptr.To(chars(256)),
		})
	}
	return images, owner
}

// statusOfAtLeast returns the status of a report with every list at its limit, whose JSON is at least
// size bytes. Texts of one byte for each character can't reach 1 MiB at the schema's limits, so the
// texts of the actions are of a character that takes 3 bytes, which the schema counts as one, and grow
// one character at a time until the status is that large.
func statusOfAtLeast(size int) (triagev1alpha1.WorkloadReportStatus, int) {
	GinkgoHelper()
	images, owner := fullLists()
	for length := 1; length <= 253; length++ {
		status := fullStatus()
		status.Images, status.Owner = images, owner
		status.Actions = slices.Repeat([]triagev1alpha1.ReportAction{largestAction(length, "€")}, maxActions)
		status.Summary.Actions, status.Summary.Updates = ptr.To[int32](maxActions), ptr.To[int32](maxActions)
		encoded, err := json.Marshal(status)
		Expect(err).NotTo(HaveOccurred())
		if len(encoded) >= size {
			return status, len(encoded)
		}
	}
	Fail(fmt.Sprintf("no report of %d actions with texts that the schema allows is %d bytes long", maxActions, size))
	return triagev1alpha1.WorkloadReportStatus{}, 0
}

// rawStatusUpdate writes the status of fullStatus to the report as unstructured content, with the
// fields of its one action set as set says, each named by its path in the action. A Go struct can't
// say a value that its field leaves out, such as an empty string, and some specs need exactly that on
// the wire.
func rawStatusUpdate(report *triagev1alpha1.WorkloadReport, set map[string]any) error {
	GinkgoHelper()
	encoded, err := json.Marshal(report)
	Expect(err).NotTo(HaveOccurred())
	obj := &unstructured.Unstructured{Object: map[string]any{}}
	Expect(json.Unmarshal(encoded, &obj.Object)).To(Succeed())
	obj.SetGroupVersionKind(triagev1alpha1.GroupVersion.WithKind("WorkloadReport"))

	status := fullStatus()
	encoded, err = json.Marshal(status)
	Expect(err).NotTo(HaveOccurred())
	content := map[string]any{}
	Expect(json.Unmarshal(encoded, &content)).To(Succeed())
	listed, _, err := unstructured.NestedSlice(content, "actions")
	Expect(err).NotTo(HaveOccurred())
	for field, value := range set {
		path := strings.Split(field, ".")
		Expect(unstructured.SetNestedField(listed[0].(map[string]any), value, path...)).To(Succeed())
	}
	Expect(unstructured.SetNestedSlice(content, listed, "actions")).To(Succeed())
	Expect(unstructured.SetNestedField(obj.Object, content, statusField)).To(Succeed())

	return k8sClient.Status().Update(ctx, obj)
}

// The suite runs without the renderer of the reports, so these specs write the objects by hand, and
// check the rules of the schema against the real API server. The report is the status, so every spec
// of it goes through the status subresource.
var _ = Describe("WorkloadReport API", func() {
	Describe("the object", func() {
		It("takes the status through the status subresource, and returns it as written", func() {
			report := existingReport()
			status := fullStatus()
			report.Status = status

			Expect(k8sClient.Status().Update(ctx, report)).To(Succeed())

			var got triagev1alpha1.WorkloadReport
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(report), &got)).To(Succeed())
			Expect(got.Spec).To(Equal(report.Spec))
			Expect(got.Status.Conditions[0].LastTransitionTime.Time).To(
				BeTemporally("==", status.Conditions[0].LastTransitionTime.Time))
			got.Status.Conditions[0].LastTransitionTime = status.Conditions[0].LastTransitionTime
			Expect(got.Status).To(Equal(status))
		})

		It("drops a status that comes with the object, because the status is a subresource", func() {
			report := newReport()
			report.Status = fullStatus()
			createReport(report)

			var got triagev1alpha1.WorkloadReport
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(report), &got)).To(Succeed())
			Expect(got.Status.Actions).To(BeEmpty())
		})

		// The report is in the namespace of its workload, so a workload of one name in two namespaces has
		// a report of one name in each.
		It("is namespaced: one name can be a report in each of two namespaces", func() {
			report := newReport()
			createReport(report)
			other := newReport()
			other.Name, other.Namespace = report.Name, otherNamespace
			createReport(other)

			for _, namespace := range []string{workloadNamespace, otherNamespace} {
				var got triagev1alpha1.WorkloadReport
				key := client.ObjectKey{Namespace: namespace, Name: report.Name}
				Expect(k8sClient.Get(ctx, key, &got)).To(Succeed(), namespace)
			}
		})

		// A workload of the core group, such as a bare pod, has no API group.
		It("takes a workload of the core group, which has no API group", func() {
			report := newReport()
			report.Spec.Workload = podWorkload()
			createReport(report)

			var got triagev1alpha1.WorkloadReport
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(report), &got)).To(Succeed())
			Expect(got.Spec.Workload).To(Equal(podWorkload()))
		})
	})

	Describe("the workload", func() {
		DescribeTable("can't change on an existing report, in",
			func(change func(*triagev1alpha1.WorkloadReference)) {
				report := newReport()
				createReport(report)

				// A merge patch carries no resourceVersion, so the API server validates it against the
				// object as it is.
				patch := client.MergeFrom(report.DeepCopy())
				change(&report.Spec.Workload)
				err := k8sClient.Patch(ctx, report, patch)

				Expect(err).To(refusedWith(workloadRule))
			},
			Entry("the name", func(w *triagev1alpha1.WorkloadReference) { w.Name = "api" }),
			Entry("the kind", func(w *triagev1alpha1.WorkloadReference) { w.Kind = "StatefulSet" }),
			Entry("the API group", func(w *triagev1alpha1.WorkloadReference) { w.APIGroup = ptr.To("example.com") }),
			Entry("the API group, taken away", func(w *triagev1alpha1.WorkloadReference) { w.APIGroup = nil }),
		)

		It("can't gain an API group when it had none", func() {
			report := newReport()
			report.Spec.Workload = podWorkload()
			createReport(report)

			patch := client.MergeFrom(report.DeepCopy())
			report.Spec.Workload.APIGroup = ptr.To("apps")
			err := k8sClient.Patch(ctx, report, patch)

			Expect(err).To(refusedWith(workloadRule))
		})

		// Only the spec is written once. The operator labels the report with the digest of each image,
		// and ties it to its workload with an owner reference, so the rule on the spec must leave the
		// metadata alone. The label name of a digest is cut at 63 characters, which is as long as a label
		// name goes.
		It("lets the metadata of a report change, so that only its spec is written once", func() {
			report := newReport()
			createReport(report)

			patch := client.MergeFrom(report.DeepCopy())
			report.Labels = map[string]string{digestLabel + strings.Repeat("a", 63): ""}
			report.OwnerReferences = []metav1.OwnerReference{{
				APIVersion: "apps/v1", Kind: deployment, Name: webName, UID: "9f4d9a52-fc1a-4c6a-b3a5-6f1d2f7a0c11",
			}}

			Expect(k8sClient.Patch(ctx, report, patch)).To(Succeed())
		})

		It("holds a workload whose name, kind and API group are as long as they go", func() {
			report := newReport()
			report.Spec.Workload = triagev1alpha1.WorkloadReference{
				APIGroup: ptr.To(chars(253)), Kind: chars(63), Name: chars(253),
			}

			createReport(report)
		})

		DescribeTable("is refused when it",
			func(workload triagev1alpha1.WorkloadReference, field string) {
				report := newReport()
				report.Spec.Workload = workload

				Expect(k8sClient.Create(ctx, report)).To(refusedWith(field))
			},
			Entry("is absent",
				triagev1alpha1.WorkloadReference{}, "spec.workload: Required value"),
			Entry("has no kind",
				triagev1alpha1.WorkloadReference{Name: webName}, "spec.workload.kind: Required value"),
			Entry("has no name",
				triagev1alpha1.WorkloadReference{Kind: deployment}, "spec.workload.name: Required value"),
			Entry("has a kind of 64 characters",
				triagev1alpha1.WorkloadReference{Kind: chars(64), Name: webName}, "spec.workload.kind: Too long"),
			Entry("has a name of 254 characters",
				triagev1alpha1.WorkloadReference{Kind: deployment, Name: chars(254)}, "spec.workload.name: Too long"),
			Entry("has an API group of 254 characters",
				triagev1alpha1.WorkloadReference{APIGroup: ptr.To(chars(254)), Kind: deployment, Name: webName},
				"spec.workload.apiGroup: Too long"),
		)
	})

	Describe("the actions", func() {
		It("holds 256 actions, and refuses one more", func() {
			report := existingReport()
			report.Status.Actions = slices.Repeat([]triagev1alpha1.ReportAction{action()}, maxActions+1)

			err := k8sClient.Status().Update(ctx, report)

			Expect(err).To(refusedWith("status.actions: Too many"))

			report.Status.Actions = report.Status.Actions[:maxActions]
			Expect(k8sClient.Status().Update(ctx, report)).To(Succeed())
		})

		// A report with every list at its limit and texts of characters that take more than one byte
		// passes 1 MiB, so the schema can't be what keeps a report small: the renderer cuts the actions by
		// bytes, and keeps the status under 1 MiB. This is the biggest report that it writes.
		It("holds a report of 1 MiB, the size that the renderer keeps it under", func() {
			report := existingReport()
			status, size := statusOfAtLeast(oneMiB)
			Expect(size).To(BeNumerically("<", oneMiB+oneMiB/16), "the report is about 1 MiB, and not far above")
			report.Status = status

			Expect(k8sClient.Status().Update(ctx, report)).To(Succeed())

			var got triagev1alpha1.WorkloadReport
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(report), &got)).To(Succeed())
			Expect(got.Status.Actions).To(HaveLen(maxActions))
			Expect(got.Status.Actions[maxActions-1]).To(Equal(status.Actions[maxActions-1]))
		})

		It("holds every field of an action at its limit", func() {
			report := existingReport()
			report.Status.Actions = []triagev1alpha1.ReportAction{largestAction(253, "a")}

			Expect(k8sClient.Status().Update(ctx, report)).To(Succeed())
		})

		// A package can lack a version, and an action for it is still an action. An update can lack a
		// fixed version, when only the fix state says that a fix exists.
		It("accepts an action that has only what it requires", func() {
			report := existingReport()
			report.Status.Actions = []triagev1alpha1.ReportAction{action()}
			report.Status.Actions[0].Package.Version = nil

			Expect(k8sClient.Status().Update(ctx, report)).To(Succeed())

			var got triagev1alpha1.WorkloadReport
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(report), &got)).To(Succeed())
			Expect(got.Status.Actions).To(Equal(report.Status.Actions))
		})

		// The summary of a workload with no open finding has no highest urgency, and no action.
		It("accepts the summary of a workload with no open finding", func() {
			report := existingReport()
			report.Status.Summary = summary()
			report.Status.Summary.Affected, report.Status.Summary.HighestUrgency = ptr.To[int32](0), nil
			report.Status.Summary.Actions, report.Status.Summary.Updates = ptr.To[int32](0), ptr.To[int32](0)
			report.Status.Summary.KnownExploited = ptr.To[int32](0)

			Expect(k8sClient.Status().Update(ctx, report)).To(Succeed())
		})

		// An optional text that is present must say something. A Go struct leaves an empty string out, so
		// these specs put it on the wire.
		DescribeTable("refuses an optional text that is present and empty, in",
			func(field, path string) {
				report := existingReport()

				err := rawStatusUpdate(report, map[string]any{field: ""})

				Expect(err).To(refusedWith(path))
			},
			Entry("the version of the package", "package.version", "status.actions[0].package.version"),
			Entry("the fixed version", "fixedVersion", "status.actions[0].fixedVersion"),
		)
	})

	Describe("the values of the enums", func() {
		// The enums are open: a later version may add values, and this one refuses the values it doesn't
		// know. The names are the contract, so the spec spells each of them out.
		It("accepts every value", func() {
			report := existingReport()
			var actions []triagev1alpha1.ReportAction
			with := func(change func(*triagev1alpha1.ReportAction)) {
				a := action()
				change(&a)
				actions = append(actions, a)
			}
			for _, urgency := range []triagev1alpha1.SSVCOutcome{"Defer", "Scheduled", "OutOfCycle", "Immediate"} {
				with(func(a *triagev1alpha1.ReportAction) { a.Urgency = urgency })
			}
			for _, step := range []triagev1alpha1.NextStep{"Update", "Mitigate", "Investigate"} {
				with(func(a *triagev1alpha1.ReportAction) { a.Step = step })
			}
			for _, severity := range []triagev1alpha1.Severity{
				"Critical", "High", "Medium", "Low", "Negligible", "Unknown",
			} {
				with(func(a *triagev1alpha1.ReportAction) { a.Severity = severity })
			}
			for _, exploited := range []triagev1alpha1.KnownExploited{"Listed", "NotListed"} {
				with(func(a *triagev1alpha1.ReportAction) { a.KnownExploited = exploited })
			}
			report.Status.Actions = actions
			for _, state := range []triagev1alpha1.ReportImageState{"Pending", "Ready", "Incomplete"} {
				image := triagev1alpha1.ReportImage{Digest: digestOf(len(report.Status.Images) + 1), State: state}
				if state != triagev1alpha1.ReportImageStatePending {
					image.ManifestDigest = ptr.To(digestOf(len(report.Status.Images) + 100))
				}
				report.Status.Images = append(report.Status.Images, image)
			}
			for _, source := range []triagev1alpha1.OwnerSource{
				"NamespaceLabel", "NamespaceAnnotation", "WorkloadLabel",
			} {
				report.Status.Owner = append(report.Status.Owner, triagev1alpha1.OwnerValue{
					Source: source, Key: teamKey, Value: ptr.To(teamA),
				})
			}

			Expect(k8sClient.Status().Update(ctx, report)).To(Succeed())
		})

		It("accepts every value of the exposure", func() {
			report := existingReport()
			for _, exposure := range []triagev1alpha1.SSVCExposure{"Small", "Controlled", "Open", "Unknown"} {
				report.Status.Exposure = ptr.To(exposure)

				Expect(k8sClient.Status().Update(ctx, report)).To(Succeed(), string(exposure))
			}
		})

		It("accepts every value of the reach", func() {
			report := existingReport()
			for _, reach := range []triagev1alpha1.InternalReach{"Namespace", "Peers", "Namespaces", "Cluster"} {
				for _, indirect := range []triagev1alpha1.IndirectExposure{"Indirect", "NotIndirect"} {
					report.Status.Reach = &triagev1alpha1.ReportReach{InternalReach: reach, Indirect: indirect}

					Expect(k8sClient.Status().Update(ctx, report)).To(Succeed(), string(reach)+" "+string(indirect))
				}
			}
		})

		It("accepts every value of the highest urgency", func() {
			report := existingReport()
			report.Status.Summary = summary()
			for _, urgency := range []triagev1alpha1.SSVCOutcome{"Defer", "Scheduled", "OutOfCycle", "Immediate"} {
				report.Status.Summary.HighestUrgency = ptr.To(urgency)

				Expect(k8sClient.Status().Update(ctx, report)).To(Succeed(), string(urgency))
			}
		})
	})

	DescribeTable("refuses a status that breaks the schema",
		func(mutate func(*triagev1alpha1.WorkloadReportStatus), message string) {
			report := existingReport()
			report.Status = fullStatus()
			mutate(&report.Status)

			err := k8sClient.Status().Update(ctx, report)

			Expect(err).To(refusedWith(message))
		},
		// Values that no enum has.
		Entry("an urgency that no version knows",
			ofAction(func(a *triagev1alpha1.ReportAction) { a.Urgency = guess }),
			`status.actions[0].urgency: Unsupported value: "`+guess+`"`),
		Entry("a step that no version knows",
			ofAction(func(a *triagev1alpha1.ReportAction) { a.Step = guess }),
			`status.actions[0].step: Unsupported value: "`+guess+`"`),
		Entry("a severity that no version knows",
			ofAction(func(a *triagev1alpha1.ReportAction) { a.Severity = guess }),
			`status.actions[0].severity: Unsupported value: "`+guess+`"`),
		Entry("a known exploitation that no version knows",
			ofAction(func(a *triagev1alpha1.ReportAction) { a.KnownExploited = guess }),
			`status.actions[0].knownExploited: Unsupported value: "`+guess+`"`),
		Entry("a highest urgency that no version knows",
			ofSummary(func(s *triagev1alpha1.ReportSummary) { s.HighestUrgency = ptr.To(triagev1alpha1.SSVCOutcome(guess)) }),
			`status.summary.highestUrgency: Unsupported value: "`+guess+`"`),
		Entry("a state of an image that no version knows",
			ofImage(func(i *triagev1alpha1.ReportImage) { i.State = guess }),
			`status.images[0].state: Unsupported value: "`+guess+`"`),
		Entry("a source of an owner value that no version knows",
			ofOwner(func(o *triagev1alpha1.OwnerValue) { o.Source = guess }),
			`status.owner[0].source: Unsupported value: "`+guess+`"`),
		Entry("an exposure that no version knows",
			func(s *triagev1alpha1.WorkloadReportStatus) { s.Exposure = ptr.To(triagev1alpha1.SSVCExposure(guess)) },
			`status.exposure: Unsupported value: "`+guess+`"`),
		Entry("an internal reach that no version knows",
			ofReach(func(r *triagev1alpha1.ReportReach) { r.InternalReach = guess }),
			`status.reach.internalReach: Unsupported value: "`+guess+`"`),
		Entry("an indirect exposure that no version knows",
			ofReach(func(r *triagev1alpha1.ReportReach) { r.Indirect = guess }),
			`status.reach.indirect: Unsupported value: "`+guess+`"`),

		// What an action must have.
		Entry("an action without a step",
			ofAction(func(a *triagev1alpha1.ReportAction) { a.Step = "" }),
			"status.actions[0].step: Required value"),
		Entry("an action without a package",
			ofAction(func(a *triagev1alpha1.ReportAction) { a.Package = triagev1alpha1.ReportPackage{} }),
			"status.actions[0].package: Required value"),
		Entry("a package without a name",
			ofAction(func(a *triagev1alpha1.ReportAction) { a.Package.Name = "" }),
			"status.actions[0].package.name: Required value"),
		Entry("a package without a type",
			ofAction(func(a *triagev1alpha1.ReportAction) { a.Package.Type = "" }),
			"status.actions[0].package.type: Required value"),
		Entry("an action without a severity",
			ofAction(func(a *triagev1alpha1.ReportAction) { a.Severity = "" }),
			"status.actions[0].severity: Required value"),
		Entry("an action without an urgency",
			ofAction(func(a *triagev1alpha1.ReportAction) { a.Urgency = "" }),
			"status.actions[0].urgency: Required value"),
		Entry("an action without its known exploitation",
			ofAction(func(a *triagev1alpha1.ReportAction) { a.KnownExploited = "" }),
			"status.actions[0].knownExploited: Required value"),
		Entry("an action without its number of vulnerabilities",
			ofAction(func(a *triagev1alpha1.ReportAction) { a.Vulnerabilities = 0 }),
			"status.actions[0].vulnerabilities: Required value"),
		Entry("an action without vulnerability IDs",
			ofAction(func(a *triagev1alpha1.ReportAction) { a.VulnerabilityIDs = nil }),
			"status.actions[0].vulnerabilityIDs: Required value"),
		Entry("an action without digests",
			ofAction(func(a *triagev1alpha1.ReportAction) { a.Digests = nil }),
			"status.actions[0].digests: Required value"),
		Entry("a fixed version on an action that is no update",
			ofAction(func(a *triagev1alpha1.ReportAction) {
				a.Step, a.FixedVersion = triagev1alpha1.NextStepMitigate, ptr.To("1.2")
			}),
			"only an Update has a fixedVersion"),
		Entry("more vulnerability IDs than vulnerabilities",
			ofAction(func(a *triagev1alpha1.ReportAction) { a.VulnerabilityIDs = []string{cve1, "CVE-2026-0002"} }),
			"vulnerabilityIDs lists no more IDs than vulnerabilities counts"),

		// What a summary must have, and how its counts agree.
		Entry("a summary without the number of affected findings",
			ofSummary(func(s *triagev1alpha1.ReportSummary) { s.Affected = nil }),
			"status.summary.affected: Required value"),
		Entry("a summary without the number of findings under investigation",
			ofSummary(func(s *triagev1alpha1.ReportSummary) { s.UnderInvestigation = nil }),
			"status.summary.underInvestigation: Required value"),
		Entry("a summary without the number of findings that are not affected",
			ofSummary(func(s *triagev1alpha1.ReportSummary) { s.NotAffected = nil }),
			"status.summary.notAffected: Required value"),
		Entry("a summary without the number of findings that are fixed",
			ofSummary(func(s *triagev1alpha1.ReportSummary) { s.Fixed = nil }),
			"status.summary.fixed: Required value"),
		Entry("a summary without the number of actions",
			ofSummary(func(s *triagev1alpha1.ReportSummary) { s.Actions = nil }),
			"status.summary.actions: Required value"),
		Entry("a summary without the number of updates",
			ofSummary(func(s *triagev1alpha1.ReportSummary) { s.Updates = nil }),
			"status.summary.updates: Required value"),
		Entry("a summary without the number of mitigations",
			ofSummary(func(s *triagev1alpha1.ReportSummary) { s.Mitigations = nil }),
			"status.summary.mitigations: Required value"),
		Entry("a summary without the number of investigations",
			ofSummary(func(s *triagev1alpha1.ReportSummary) { s.Investigations = nil }),
			"status.summary.investigations: Required value"),
		Entry("a summary without the number of omitted actions",
			ofSummary(func(s *triagev1alpha1.ReportSummary) { s.OmittedActions = nil }),
			"status.summary.omittedActions: Required value"),
		Entry("a summary without the number of critical findings",
			ofSummary(func(s *triagev1alpha1.ReportSummary) { s.Critical = nil }),
			"status.summary.critical: Required value"),
		Entry("a summary without the number of known exploited findings",
			ofSummary(func(s *triagev1alpha1.ReportSummary) { s.KnownExploited = nil }),
			"status.summary.knownExploited: Required value"),
		Entry("a summary without the number of images that wait for their verdict",
			ofSummary(func(s *triagev1alpha1.ReportSummary) { s.Pending = nil }),
			"status.summary.pending: Required value"),
		Entry("a summary without the number of images whose result leaves findings out",
			ofSummary(func(s *triagev1alpha1.ReportSummary) { s.Incomplete = nil }),
			"status.summary.incomplete: Required value"),
		Entry("steps that don't add up to the actions",
			ofSummary(func(s *triagev1alpha1.ReportSummary) { s.Mitigations = ptr.To[int32](1) }),
			"updates, mitigations and investigations add up to actions"),
		Entry("more omitted actions than actions",
			ofSummary(func(s *triagev1alpha1.ReportSummary) { s.OmittedActions = ptr.To[int32](2) }),
			"omittedActions counts no more than actions"),
		Entry("open findings without a highest urgency",
			ofSummary(func(s *triagev1alpha1.ReportSummary) { s.HighestUrgency = nil }),
			"highestUrgency is set exactly when a finding is open"),
		Entry("a highest urgency without an open finding",
			ofSummary(func(s *triagev1alpha1.ReportSummary) { s.Affected = ptr.To[int32](0) }),
			"highestUrgency is set exactly when a finding is open"),
		Entry("a reach without an internal reach",
			ofReach(func(r *triagev1alpha1.ReportReach) { r.InternalReach = "" }),
			"status.reach.internalReach: Required value"),
		Entry("a reach without its indirect exposure",
			ofReach(func(r *triagev1alpha1.ReportReach) { r.Indirect = "" }),
			"status.reach.indirect: Required value"),
		Entry("an image without a digest",
			ofImage(func(i *triagev1alpha1.ReportImage) { i.Digest = "" }),
			"status.images[0].digest: Required value"),
		Entry("a Ready image without a manifest digest",
			ofImage(func(i *triagev1alpha1.ReportImage) { i.ManifestDigest = nil }),
			"an image that isn't Pending has a manifestDigest"),
		Entry("an Incomplete image without a manifest digest",
			ofImage(func(i *triagev1alpha1.ReportImage) {
				i.State, i.ManifestDigest = triagev1alpha1.ReportImageStateIncomplete, nil
			}),
			"an image that isn't Pending has a manifestDigest"),
		Entry("an image without a state",
			ofImage(func(i *triagev1alpha1.ReportImage) { i.State = "" }),
			"status.images[0].state: Required value"),
		Entry("a coverage without a source",
			ofCoverage(func(c *triagev1alpha1.ReportCoverage) { c.Source = "" }),
			"status.images[0].coverage[0].source: Required value"),
		Entry("a coverage without a type",
			ofCoverage(func(c *triagev1alpha1.ReportCoverage) { c.Type = "" }),
			"status.images[0].coverage[0].type: Required value"),
		Entry("a coverage without a number",
			ofCoverage(func(c *triagev1alpha1.ReportCoverage) { c.Coverage = nil }),
			"status.images[0].coverage[0].coverage: Required value"),
		Entry("an owner value without a source",
			ofOwner(func(o *triagev1alpha1.OwnerValue) { o.Source = "" }),
			"status.owner[0].source: Required value"),
		Entry("an owner value without a key",
			ofOwner(func(o *triagev1alpha1.OwnerValue) { o.Key = "" }),
			"status.owner[0].key: Required value"),
		Entry("an owner value without a value",
			ofOwner(func(o *triagev1alpha1.OwnerValue) { o.Value = nil }),
			"status.owner[0].value: Required value"),

		// One beyond each limit of a text.
		Entry("a vulnerability ID of 65 characters",
			ofAction(func(a *triagev1alpha1.ReportAction) { a.VulnerabilityIDs = []string{chars(65)} }),
			"status.actions[0].vulnerabilityIDs[0]: Too long"),
		Entry("an empty vulnerability ID",
			ofAction(func(a *triagev1alpha1.ReportAction) { a.VulnerabilityIDs = []string{""} }),
			"status.actions[0].vulnerabilityIDs[0]"),
		Entry("a package name of 254 characters",
			ofAction(func(a *triagev1alpha1.ReportAction) { a.Package.Name = chars(254) }),
			"status.actions[0].package.name: Too long"),
		Entry("a package version of 129 characters",
			ofAction(func(a *triagev1alpha1.ReportAction) { a.Package.Version = ptr.To(chars(129)) }),
			"status.actions[0].package.version: Too long"),
		Entry("a package type of 33 characters",
			ofAction(func(a *triagev1alpha1.ReportAction) { a.Package.Type = chars(33) }),
			"status.actions[0].package.type: Too long"),
		Entry("a fixed version of 129 characters",
			ofAction(func(a *triagev1alpha1.ReportAction) { a.FixedVersion = ptr.To(chars(129)) }),
			"status.actions[0].fixedVersion: Too long"),
		Entry("an owner key of 318 characters",
			ofOwner(func(o *triagev1alpha1.OwnerValue) { o.Key = chars(318) }),
			"status.owner[0].key: Too long"),
		Entry("an owner value of 257 characters",
			ofOwner(func(o *triagev1alpha1.OwnerValue) { o.Value = ptr.To(chars(257)) }),
			"status.owner[0].value: Too long"),

		// One beyond each limit of a list.
		Entry("6 vulnerability IDs on an action",
			ofAction(func(a *triagev1alpha1.ReportAction) {
				a.Vulnerabilities, a.VulnerabilityIDs = 6, slices.Repeat([]string{cve1}, 6)
			}),
			"status.actions[0].vulnerabilityIDs: Too many"),
		Entry("9 digests on an action",
			ofAction(func(a *triagev1alpha1.ReportAction) { a.Digests = slices.Repeat([]string{digestOf(1)}, 9) }),
			"status.actions[0].digests: Too many"),
		Entry("33 images",
			func(s *triagev1alpha1.WorkloadReportStatus) {
				s.Images = nil
				for i := range 33 {
					s.Images = append(s.Images, triagev1alpha1.ReportImage{
						Digest: digestOf(i + 1), State: triagev1alpha1.ReportImageStatePending,
					})
				}
			},
			"status.images: Too many"),
		Entry("33 coverage entries on an image",
			ofImage(func(i *triagev1alpha1.ReportImage) {
				i.Coverage = nil
				for n := range 33 {
					i.Coverage = append(i.Coverage, triagev1alpha1.ReportCoverage{
						Source: fmt.Sprintf("source-%02d", n), Type: imageContents, Coverage: ptr.To[int32](50),
					})
				}
			}),
			"status.images[0].coverage: Too many"),
		Entry("49 owner values",
			func(s *triagev1alpha1.WorkloadReportStatus) {
				s.Owner = nil
				for n := range 49 {
					s.Owner = append(s.Owner, triagev1alpha1.OwnerValue{
						Source: triagev1alpha1.OwnerSourceWorkloadLabel, Key: fmt.Sprintf("key-%02d", n), Value: ptr.To("v"),
					})
				}
			},
			"status.owner: Too many"),
		Entry("9 conditions",
			func(s *triagev1alpha1.WorkloadReportStatus) {
				s.Conditions = nil
				for n := range 9 {
					s.Conditions = append(s.Conditions, metav1.Condition{
						Type: fmt.Sprintf("Aspect%d", n), Status: metav1.ConditionTrue, Reason: "Rendered",
						Message: "ok", LastTransitionTime: metav1.Now(),
					})
				}
			},
			"status.conditions: Too many"),

		// Numbers.
		Entry("a negative number of vulnerabilities",
			ofAction(func(a *triagev1alpha1.ReportAction) { a.Vulnerabilities = -1 }),
			"status.actions[0].vulnerabilities: Invalid value"),
		Entry("a negative count of affected findings",
			ofSummary(func(s *triagev1alpha1.ReportSummary) { s.Affected = ptr.To[int32](-1) }),
			"status.summary.affected: Invalid value"),
		Entry("a negative count of findings that are fixed",
			ofSummary(func(s *triagev1alpha1.ReportSummary) { s.Fixed = ptr.To[int32](-1) }),
			"status.summary.fixed: Invalid value"),
		Entry("a negative count of critical findings",
			ofSummary(func(s *triagev1alpha1.ReportSummary) { s.Critical = ptr.To[int32](-1) }),
			"status.summary.critical: Invalid value"),
		Entry("a coverage of 101",
			ofCoverage(func(c *triagev1alpha1.ReportCoverage) { c.Coverage = ptr.To[int32](101) }),
			"status.images[0].coverage[0].coverage: Invalid value"),
		Entry("a coverage of -1",
			ofCoverage(func(c *triagev1alpha1.ReportCoverage) { c.Coverage = ptr.To[int32](-1) }),
			"status.images[0].coverage[0].coverage: Invalid value"),

		// Digests, platforms and the names of sources and types.
		Entry("a digest that is not a sha256 digest",
			ofImage(func(i *triagev1alpha1.ReportImage) { i.Digest = "sha256:abc" }),
			"status.images[0].digest"),
		Entry("a digest in upper case",
			ofImage(func(i *triagev1alpha1.ReportImage) { i.Digest = "sha256:" + strings.Repeat("A", 64) }),
			"status.images[0].digest"),
		Entry("a manifest digest that is not a sha256 digest",
			ofImage(func(i *triagev1alpha1.ReportImage) { i.ManifestDigest = ptr.To("sha256:abc") }),
			"status.images[0].manifestDigest"),
		Entry("a platform without an architecture",
			ofImage(func(i *triagev1alpha1.ReportImage) { i.Platform = ptr.To("linux") }),
			"status.images[0].platform"),
		Entry("a platform with a capital letter",
			ofImage(func(i *triagev1alpha1.ReportImage) { i.Platform = ptr.To("Linux/amd64") }),
			"status.images[0].platform"),
		Entry("a coverage source with a capital letter",
			ofCoverage(func(c *triagev1alpha1.ReportCoverage) { c.Source = "Scanner" }),
			"status.images[0].coverage[0].source"),
		Entry("a coverage source with a dot",
			ofCoverage(func(c *triagev1alpha1.ReportCoverage) { c.Source = "scan.ner" }),
			"status.images[0].coverage[0].source"),
		Entry("a coverage source of 45 characters",
			ofCoverage(func(c *triagev1alpha1.ReportCoverage) { c.Source = chars(45) }),
			"status.images[0].coverage[0].source: Too long"),
		Entry("a coverage type with no version",
			ofCoverage(func(c *triagev1alpha1.ReportCoverage) { c.Type = "ch.bedag.vexplain.scanner.image-contents" }),
			"status.images[0].coverage[0].type"),
		Entry("a coverage type with a capital letter",
			ofCoverage(func(c *triagev1alpha1.ReportCoverage) { c.Type = "ch.bedag.vexplain.Scanner.v1alpha1" }),
			"status.images[0].coverage[0].type"),
		Entry("a coverage type of 254 characters",
			ofCoverage(func(c *triagev1alpha1.ReportCoverage) { c.Type = typeOfLength(254) }),
			"status.images[0].coverage[0].type: Too long"),
		Entry("a digest of an action that is not a sha256 digest",
			ofAction(func(a *triagev1alpha1.ReportAction) { a.Digests = []string{"sha256:abc"} }),
			"status.actions[0].digests[0]"),
		Entry("an owner key that is no qualified name",
			ofOwner(func(o *triagev1alpha1.OwnerValue) { o.Key = "team owner" }),
			"status.owner[0].key"),

		// A map holds each key once.
		Entry("the same source and type twice in the coverage of an image",
			ofImage(func(i *triagev1alpha1.ReportImage) { i.Coverage = slices.Repeat(i.Coverage, 2) }),
			"status.images[0].coverage[1]: Duplicate value"),
		Entry("the same source and key twice in the owner values",
			func(s *triagev1alpha1.WorkloadReportStatus) { s.Owner = slices.Repeat(s.Owner, 2) },
			"status.owner[1]: Duplicate value"),
		Entry("the same type of condition twice",
			func(s *triagev1alpha1.WorkloadReportStatus) { s.Conditions = slices.Repeat(s.Conditions, 2) },
			"status.conditions[1]: Duplicate value"),
	)

	Describe("the lists that are maps", func() {
		// The key of a coverage entry is its source and type together, and the key of an owner value is
		// its source and key together: one half alone may repeat.
		It("accepts a source with two types, a type from two sources, and a key from two sources", func() {
			report := existingReport()
			report.Status.Images = []triagev1alpha1.ReportImage{{
				Digest:         digestOf(1),
				ManifestDigest: ptr.To(digestOf(2)),
				State:          triagev1alpha1.ReportImageStateReady,
				Coverage: []triagev1alpha1.ReportCoverage{
					{Source: scannerSource, Type: imageContents, Coverage: ptr.To[int32](80)},
					{Source: scannerSource, Type: "ch.bedag.vexplain.findings.v1alpha1", Coverage: ptr.To[int32](100)},
					{Source: "other-scanner", Type: imageContents, Coverage: ptr.To[int32](0)},
				},
			}}
			report.Status.Owner = []triagev1alpha1.OwnerValue{
				{Source: triagev1alpha1.OwnerSourceNamespaceLabel, Key: teamKey, Value: ptr.To(teamA)},
				{Source: triagev1alpha1.OwnerSourceWorkloadLabel, Key: teamKey, Value: ptr.To("team-b")},
				{Source: triagev1alpha1.OwnerSourceNamespaceLabel, Key: "contact", Value: ptr.To("")},
			}

			Expect(k8sClient.Status().Update(ctx, report)).To(Succeed())
		})

		// A label can have an empty value, and the owner value copies it as it is.
		It("keeps the empty value of an owner label", func() {
			report := existingReport()
			report.Status.Owner = []triagev1alpha1.OwnerValue{
				{Source: triagev1alpha1.OwnerSourceNamespaceLabel, Key: "contact", Value: ptr.To("")},
			}

			Expect(k8sClient.Status().Update(ctx, report)).To(Succeed())

			var got triagev1alpha1.WorkloadReport
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(report), &got)).To(Succeed())
			Expect(got.Status.Owner).To(Equal(report.Status.Owner))
		})

		// An image that no scan has resolved has no manifest yet, and so no result: the report lists it as
		// Pending, with only its digest, which is how it tells an image with no findings from one that
		// has no verdict.
		It("accepts an image that has no platform and no manifest yet", func() {
			report := existingReport()
			report.Status.Images = []triagev1alpha1.ReportImage{{
				Digest: digestOf(1), State: triagev1alpha1.ReportImageStatePending,
			}}

			Expect(k8sClient.Status().Update(ctx, report)).To(Succeed())

			var got triagev1alpha1.WorkloadReport
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(report), &got)).To(Succeed())
			Expect(got.Status.Images).To(Equal(report.Status.Images))
		})

		It("holds every list at its limit", func() {
			report := existingReport()
			report.Status.Images, report.Status.Owner = fullLists()
			report.Status.Actions = slices.Repeat([]triagev1alpha1.ReportAction{largestAction(253, "a")}, maxActions)

			Expect(k8sClient.Status().Update(ctx, report)).To(Succeed())
		})
	})
})
