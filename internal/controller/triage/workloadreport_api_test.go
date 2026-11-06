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
	// maxFindings is the most findings that a report lists.
	maxFindings = 1000
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
	// loadCheck is the name of the rule whose hints the specs write as status notes, and curlHint is
	// the text of one of them.
	loadCheck = "load-check"
	curlHint  = "reached by /usr/bin/curl"
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

// finding returns a finding that the schema accepts, with only what it requires.
func finding() triagev1alpha1.ReportFinding {
	return triagev1alpha1.ReportFinding{
		VulnerabilityID: "CVE-2026-0001",
		Package: triagev1alpha1.ReportPackage{
			Name: "brotli-libs", Version: ptr.To("1.1.0-r2"), Type: "apk",
		},
		Status:      triagev1alpha1.VEXStatusAffected,
		Urgency:     triagev1alpha1.SSVCOutcomeScheduled,
		NextStep:    triagev1alpha1.NextStepUpdate,
		ReviewState: triagev1alpha1.ReviewStateRuleSettled,
		Severity:    triagev1alpha1.SeverityHigh,
	}
}

// fullStatus returns a status that the schema accepts, and that sets every field of it: one
// condition, one image with its coverage, one finding with its optional fields, one owner value, and
// the counts and the exposure.
func fullStatus() triagev1alpha1.WorkloadReportStatus {
	listed := finding()
	listed.FixedVersion = ptr.To("1.1.0-r3")
	listed.Reason = ptr.To("known exploited")
	listed.StatusNotes = []triagev1alpha1.ReportStatusNote{
		{Rule: loadCheck, Text: curlHint},
	}
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
		Findings: []triagev1alpha1.ReportFinding{listed},
		Omitted:  ptr.To[int32](0),
		Counts: &triagev1alpha1.ReportCounts{
			Affected:           ptr.To[int32](1),
			UnderInvestigation: ptr.To[int32](0),
			NotAffected:        ptr.To[int32](3),
			Fixed:              ptr.To[int32](2),
		},
		Owner: []triagev1alpha1.OwnerValue{
			{Source: triagev1alpha1.OwnerSourceNamespaceLabel, Key: teamKey, Value: ptr.To(teamA)},
		},
		Exposure: ptr.To(triagev1alpha1.SSVCExposureOpen),
	}
}

// ofFinding changes the one finding of the status that the rejection specs start from.
func ofFinding(change func(*triagev1alpha1.ReportFinding)) func(*triagev1alpha1.WorkloadReportStatus) {
	return func(status *triagev1alpha1.WorkloadReportStatus) { change(&status.Findings[0]) }
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

// bulkyFinding returns a finding whose texts are each at most length characters long, or as long as
// the schema allows when that is less.
func bulkyFinding(length int) triagev1alpha1.ReportFinding {
	text := func(limit int) string { return chars(min(length, limit)) }
	bulky := finding()
	bulky.VulnerabilityID = text(64)
	bulky.Package = triagev1alpha1.ReportPackage{Name: text(253), Version: ptr.To(text(128)), Type: text(32)}
	bulky.FixedVersion = ptr.To(text(128))
	bulky.Reason = ptr.To(text(256))
	bulky.StatusNotes = []triagev1alpha1.ReportStatusNote{
		{Rule: text(63), Text: text(256)},
		{Rule: text(63), Text: text(256)},
	}
	return bulky
}

// statusOfAtLeast returns the status of a report with the most findings that it lists, whose JSON is
// at least size bytes. The texts of the findings grow, one character at a time, until it is.
func statusOfAtLeast(size int) (triagev1alpha1.WorkloadReportStatus, int) {
	GinkgoHelper()
	for length := 1; length <= 256; length++ {
		status := fullStatus()
		status.Findings = slices.Repeat([]triagev1alpha1.ReportFinding{bulkyFinding(length)}, maxFindings)
		encoded, err := json.Marshal(status)
		Expect(err).NotTo(HaveOccurred())
		if len(encoded) >= size {
			return status, len(encoded)
		}
	}
	Fail(fmt.Sprintf("no report of %d findings with texts that the schema allows is %d bytes long", maxFindings, size))
	return triagev1alpha1.WorkloadReportStatus{}, 0
}

// rawStatusUpdate writes the status of fullStatus to the report as unstructured content, with the
// fields of its one finding set as set says, each named by its path in the finding. A Go struct can't
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
	listed, _, err := unstructured.NestedSlice(content, "findings")
	Expect(err).NotTo(HaveOccurred())
	for field, value := range set {
		path := strings.Split(field, ".")
		Expect(unstructured.SetNestedField(listed[0].(map[string]any), value, path...)).To(Succeed())
	}
	Expect(unstructured.SetNestedSlice(content, listed, "findings")).To(Succeed())
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
			Expect(got.Status.Findings).To(BeEmpty())
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

	Describe("the findings", func() {
		It("holds 1000 findings, and refuses one more", func() {
			report := existingReport()
			report.Status.Findings = slices.Repeat([]triagev1alpha1.ReportFinding{finding()}, maxFindings+1)

			err := k8sClient.Status().Update(ctx, report)

			Expect(err).To(refusedWith("status.findings: Too many"))

			report.Status.Findings = report.Status.Findings[:maxFindings]
			Expect(k8sClient.Status().Update(ctx, report)).To(Succeed())
		})

		// A report at every maximum, with 1000 findings of the longest texts, would pass etcd's limit for
		// a request, so the schema can't be what keeps a report small: the renderer cuts the findings by
		// bytes, and keeps the status under 1 MiB. This is the biggest report that it writes.
		It("holds a report of 1 MiB, the size that the renderer keeps it under", func() {
			report := existingReport()
			status, size := statusOfAtLeast(oneMiB)
			Expect(size).To(BeNumerically("<", oneMiB+oneMiB/16), "the report is about 1 MiB, and not far above")
			report.Status = status

			Expect(k8sClient.Status().Update(ctx, report)).To(Succeed())

			var got triagev1alpha1.WorkloadReport
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(report), &got)).To(Succeed())
			Expect(got.Status.Findings).To(HaveLen(maxFindings))
			Expect(got.Status.Findings[maxFindings-1]).To(Equal(status.Findings[maxFindings-1]))
		})

		It("holds every field of a finding at its limit", func() {
			report := existingReport()
			largest := finding()
			largest.VulnerabilityID = chars(64)
			largest.Package = triagev1alpha1.ReportPackage{Name: chars(253), Version: ptr.To(chars(128)), Type: chars(32)}
			largest.FixedVersion = ptr.To(chars(128))
			largest.Reason = ptr.To(chars(256))
			largest.StatusNotes = slices.Repeat([]triagev1alpha1.ReportStatusNote{{Rule: chars(63), Text: chars(256)}}, 4)
			report.Status.Findings = []triagev1alpha1.ReportFinding{largest}

			Expect(k8sClient.Status().Update(ctx, report)).To(Succeed())
		})

		// A package can lack a version, and a finding for it is still a finding. A finding can lack a
		// fixed version, a reason and notes.
		It("accepts a finding that has only what it requires", func() {
			report := existingReport()
			report.Status.Findings = []triagev1alpha1.ReportFinding{finding()}
			report.Status.Findings[0].Package.Version = nil

			Expect(k8sClient.Status().Update(ctx, report)).To(Succeed())

			var got triagev1alpha1.WorkloadReport
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(report), &got)).To(Succeed())
			Expect(got.Status.Findings).To(Equal(report.Status.Findings))
		})

		// An optional text that is present must say something. A Go struct leaves an empty string out, so
		// these specs put it on the wire.
		DescribeTable("refuses an optional text that is present and empty, in",
			func(field, path string) {
				report := existingReport()

				err := rawStatusUpdate(report, map[string]any{field: ""})

				Expect(err).To(refusedWith(path))
			},
			Entry("the version of the package", "package.version", "status.findings[0].package.version"),
			Entry("the fixed version", "fixedVersion", "status.findings[0].fixedVersion"),
			Entry("the reason", "reason", "status.findings[0].reason"),
		)
	})

	Describe("the values of the enums", func() {
		// The enums are open: a later version may add values, and this one refuses the values it doesn't
		// know. The names are the contract, so the spec spells each of them out.
		It("accepts every value", func() {
			report := existingReport()
			var findings []triagev1alpha1.ReportFinding
			with := func(change func(*triagev1alpha1.ReportFinding)) {
				f := finding()
				change(&f)
				findings = append(findings, f)
			}
			for _, status := range []triagev1alpha1.VEXStatus{"Affected", "UnderInvestigation"} {
				with(func(f *triagev1alpha1.ReportFinding) { f.Status = status })
			}
			for _, urgency := range []triagev1alpha1.SSVCOutcome{"Defer", "Scheduled", "OutOfCycle", "Immediate"} {
				with(func(f *triagev1alpha1.ReportFinding) { f.Urgency = urgency })
			}
			for _, step := range []triagev1alpha1.NextStep{"Update", "Mitigate", "Investigate"} {
				with(func(f *triagev1alpha1.ReportFinding) { f.NextStep = step })
			}
			for _, state := range []triagev1alpha1.ReviewState{"RuleSettled", "Open"} {
				with(func(f *triagev1alpha1.ReportFinding) { f.ReviewState = state })
			}
			for _, severity := range []triagev1alpha1.Severity{
				"Critical", "High", "Medium", "Low", "Negligible", "Unknown",
			} {
				with(func(f *triagev1alpha1.ReportFinding) { f.Severity = severity })
			}
			report.Status.Findings = findings
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

		// A report lists the findings that need action: the other two statuses of OpenVEX settle a
		// finding, and only the counts have them.
		DescribeTable("refuses, as the status of a finding,",
			func(status triagev1alpha1.VEXStatus) {
				report := existingReport()
				report.Status.Findings = []triagev1alpha1.ReportFinding{finding()}
				report.Status.Findings[0].Status = status

				err := k8sClient.Status().Update(ctx, report)

				Expect(err).To(refusedWith(fmt.Sprintf("status.findings[0].status: Unsupported value: %q", status)))
			},
			Entry("NotAffected", triagev1alpha1.VEXStatus("NotAffected")),
			Entry("Fixed", triagev1alpha1.VEXStatus("Fixed")),
			Entry("a status that no version knows", triagev1alpha1.VEXStatus(guess)),
		)
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
			ofFinding(func(f *triagev1alpha1.ReportFinding) { f.Urgency = guess }),
			`status.findings[0].urgency: Unsupported value: "`+guess+`"`),
		Entry("a next step that no version knows",
			ofFinding(func(f *triagev1alpha1.ReportFinding) { f.NextStep = guess }),
			`status.findings[0].nextStep: Unsupported value: "`+guess+`"`),
		Entry("a review state that no version knows",
			ofFinding(func(f *triagev1alpha1.ReportFinding) { f.ReviewState = guess }),
			`status.findings[0].reviewState: Unsupported value: "`+guess+`"`),
		Entry("a severity that no version knows",
			ofFinding(func(f *triagev1alpha1.ReportFinding) { f.Severity = guess }),
			`status.findings[0].severity: Unsupported value: "`+guess+`"`),
		Entry("a state of an image that no version knows",
			ofImage(func(i *triagev1alpha1.ReportImage) { i.State = guess }),
			`status.images[0].state: Unsupported value: "`+guess+`"`),
		Entry("a source of an owner value that no version knows",
			ofOwner(func(o *triagev1alpha1.OwnerValue) { o.Source = guess }),
			`status.owner[0].source: Unsupported value: "`+guess+`"`),
		Entry("an exposure that no version knows",
			func(s *triagev1alpha1.WorkloadReportStatus) { s.Exposure = ptr.To(triagev1alpha1.SSVCExposure(guess)) },
			`status.exposure: Unsupported value: "`+guess+`"`),

		// What a finding must have.
		Entry("a finding without a vulnerability ID",
			ofFinding(func(f *triagev1alpha1.ReportFinding) { f.VulnerabilityID = "" }),
			"status.findings[0].vulnerabilityID: Required value"),
		Entry("a finding without a package",
			ofFinding(func(f *triagev1alpha1.ReportFinding) { f.Package = triagev1alpha1.ReportPackage{} }),
			"status.findings[0].package: Required value"),
		Entry("a package without a name",
			ofFinding(func(f *triagev1alpha1.ReportFinding) { f.Package.Name = "" }),
			"status.findings[0].package.name: Required value"),
		Entry("a package without a type",
			ofFinding(func(f *triagev1alpha1.ReportFinding) { f.Package.Type = "" }),
			"status.findings[0].package.type: Required value"),
		Entry("a finding without a status",
			ofFinding(func(f *triagev1alpha1.ReportFinding) { f.Status = "" }),
			"status.findings[0].status: Required value"),
		Entry("a finding without an urgency",
			ofFinding(func(f *triagev1alpha1.ReportFinding) { f.Urgency = "" }),
			"status.findings[0].urgency: Required value"),
		Entry("a finding without a next step",
			ofFinding(func(f *triagev1alpha1.ReportFinding) { f.NextStep = "" }),
			"status.findings[0].nextStep: Required value"),
		Entry("a finding without a review state",
			ofFinding(func(f *triagev1alpha1.ReportFinding) { f.ReviewState = "" }),
			"status.findings[0].reviewState: Required value"),
		Entry("a finding without a severity",
			ofFinding(func(f *triagev1alpha1.ReportFinding) { f.Severity = "" }),
			"status.findings[0].severity: Required value"),
		Entry("a note without a rule",
			ofFinding(func(f *triagev1alpha1.ReportFinding) {
				f.StatusNotes = []triagev1alpha1.ReportStatusNote{{Text: curlHint}}
			}),
			"status.findings[0].statusNotes[0].rule: Required value"),
		Entry("a note without a text",
			ofFinding(func(f *triagev1alpha1.ReportFinding) {
				f.StatusNotes = []triagev1alpha1.ReportStatusNote{{Rule: loadCheck}}
			}),
			"status.findings[0].statusNotes[0].text: Required value"),
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
		Entry("counts without the number of affected findings",
			func(s *triagev1alpha1.WorkloadReportStatus) { s.Counts.Affected = nil },
			"status.counts.affected: Required value"),
		Entry("counts without the number of findings under investigation",
			func(s *triagev1alpha1.WorkloadReportStatus) { s.Counts.UnderInvestigation = nil },
			"status.counts.underInvestigation: Required value"),
		Entry("counts without the number of findings that are not affected",
			func(s *triagev1alpha1.WorkloadReportStatus) { s.Counts.NotAffected = nil },
			"status.counts.notAffected: Required value"),
		Entry("counts without the number of findings that are fixed",
			func(s *triagev1alpha1.WorkloadReportStatus) { s.Counts.Fixed = nil },
			"status.counts.fixed: Required value"),
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
			ofFinding(func(f *triagev1alpha1.ReportFinding) { f.VulnerabilityID = chars(65) }),
			"status.findings[0].vulnerabilityID: Too long"),
		Entry("a package name of 254 characters",
			ofFinding(func(f *triagev1alpha1.ReportFinding) { f.Package.Name = chars(254) }),
			"status.findings[0].package.name: Too long"),
		Entry("a package version of 129 characters",
			ofFinding(func(f *triagev1alpha1.ReportFinding) { f.Package.Version = ptr.To(chars(129)) }),
			"status.findings[0].package.version: Too long"),
		Entry("a package type of 33 characters",
			ofFinding(func(f *triagev1alpha1.ReportFinding) { f.Package.Type = chars(33) }),
			"status.findings[0].package.type: Too long"),
		Entry("a fixed version of 129 characters",
			ofFinding(func(f *triagev1alpha1.ReportFinding) { f.FixedVersion = ptr.To(chars(129)) }),
			"status.findings[0].fixedVersion: Too long"),
		Entry("a reason of 257 characters",
			ofFinding(func(f *triagev1alpha1.ReportFinding) { f.Reason = ptr.To(chars(257)) }),
			"status.findings[0].reason: Too long"),
		Entry("a note whose text is 257 characters",
			ofFinding(func(f *triagev1alpha1.ReportFinding) {
				f.StatusNotes = []triagev1alpha1.ReportStatusNote{{Rule: loadCheck, Text: chars(257)}}
			}),
			"status.findings[0].statusNotes[0].text: Too long"),
		Entry("a note whose rule is 64 characters",
			ofFinding(func(f *triagev1alpha1.ReportFinding) {
				f.StatusNotes = []triagev1alpha1.ReportStatusNote{{Rule: chars(64), Text: curlHint}}
			}),
			"status.findings[0].statusNotes[0].rule: Too long"),
		Entry("an owner key of 318 characters",
			ofOwner(func(o *triagev1alpha1.OwnerValue) { o.Key = chars(318) }),
			"status.owner[0].key: Too long"),
		Entry("an owner value of 257 characters",
			ofOwner(func(o *triagev1alpha1.OwnerValue) { o.Value = ptr.To(chars(257)) }),
			"status.owner[0].value: Too long"),

		// One beyond each limit of a list.
		Entry("5 status notes on a finding",
			ofFinding(func(f *triagev1alpha1.ReportFinding) {
				f.StatusNotes = slices.Repeat([]triagev1alpha1.ReportStatusNote{{Rule: loadCheck, Text: "a hint"}}, 5)
			}),
			"status.findings[0].statusNotes: Too many"),
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
		Entry("a negative number of omitted findings",
			func(s *triagev1alpha1.WorkloadReportStatus) { s.Omitted = ptr.To[int32](-1) },
			"status.omitted: Invalid value"),
		Entry("a negative count of affected findings",
			func(s *triagev1alpha1.WorkloadReportStatus) { s.Counts.Affected = ptr.To[int32](-1) },
			"status.counts.affected: Invalid value"),
		Entry("a negative count of findings that are fixed",
			func(s *triagev1alpha1.WorkloadReportStatus) { s.Counts.Fixed = ptr.To[int32](-1) },
			"status.counts.fixed: Invalid value"),
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
		Entry("a note rule that is no DNS-1123 label",
			ofFinding(func(f *triagev1alpha1.ReportFinding) {
				f.StatusNotes = []triagev1alpha1.ReportStatusNote{{Rule: "Load.Check", Text: "a hint"}}
			}),
			"status.findings[0].statusNotes[0].rule"),
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
			images := make([]triagev1alpha1.ReportImage, 0, 32)
			for i := range 32 {
				coverage := make([]triagev1alpha1.ReportCoverage, 0, 32)
				for n := range 32 {
					coverage = append(coverage, triagev1alpha1.ReportCoverage{
						Source: fmt.Sprintf("source-%02d", n), Type: typeOfLength(253), Coverage: ptr.To[int32](100),
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
					Key:    fmt.Sprintf("example.com/%s%02d", chars(57), n), Value: ptr.To(chars(256)),
				})
			}
			report.Status.Images, report.Status.Owner = images, owner

			Expect(k8sClient.Status().Update(ctx, report)).To(Succeed())
		})
	})
})
