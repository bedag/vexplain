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
	"fmt"
	"slices"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/types"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	triagev1alpha1 "github.com/bedag/vexplain/api/triage/v1alpha1"
)

const (
	// guess is a value that no enum of the API has, in this version or in a later one.
	guess = "Guess"
	// webName is the name of the container that the actions of the specs are about.
	webName = "web"
	// cve1 is the ID of the vulnerability of the actions that the specs write.
	cve1 = "CVE-2026-0001"
	// teamKey is the key of the label that the specs copy as an owner value, and teamA its value.
	teamKey = "team"
	teamA   = "team-a"
)

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

// digestOf returns the sha256 digest that is made of the number n.
func digestOf(n int) string {
	return fmt.Sprintf("sha256:%064x", n)
}

// resourceReportCount numbers the resource reports that the specs create.
var resourceReportCount int

// existingResourceReport creates the report of a ConfigMap and returns it, to write a status to.
func existingResourceReport() *triagev1alpha1.ResourceReport {
	GinkgoHelper()
	resourceReportCount++
	report := &triagev1alpha1.ResourceReport{
		ObjectMeta: metav1.ObjectMeta{Namespace: workloadNamespace, Name: fmt.Sprintf("configmap-app-%03d", resourceReportCount)},
		Spec: triagev1alpha1.ResourceReportSpec{Resource: triagev1alpha1.ResourceReference{
			Kind: "ConfigMap", Name: "app",
		}},
	}
	Expect(k8sClient.Create(ctx, report)).To(Succeed())
	DeferCleanup(func() { Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, report))).To(Succeed()) })
	return report
}

// changeAction returns an action that changes the resource itself, which the schema accepts.
func changeAction() triagev1alpha1.ResourceAction {
	return triagev1alpha1.ResourceAction{
		Step:        triagev1alpha1.ResourceStepChange,
		Title:       "Move the password out of the ConfigMap",
		Locations:   []string{"data.DB_PASSWORD"},
		Severity:    triagev1alpha1.SeverityHigh,
		Requirement: triagev1alpha1.ResourceRequirement{Playbook: "config-maps", Rule: ptr.To("no-secrets")},
	}
}

// updateAction returns a vulnerability action: an Update of one package of one image.
func updateAction() triagev1alpha1.ResourceAction {
	return triagev1alpha1.ResourceAction{
		Step:             triagev1alpha1.ResourceStepUpdate,
		Title:            "Update brotli-libs",
		Locations:        []string{webName},
		Severity:         triagev1alpha1.SeverityHigh,
		Urgency:          ptr.To(triagev1alpha1.SSVCOutcomeScheduled),
		Requirement:      triagev1alpha1.ResourceRequirement{Playbook: "vulnerabilities"},
		Package:          &triagev1alpha1.ReportPackage{Name: "brotli-libs", Version: ptr.To("1.1.0-r2"), Type: "apk"},
		FixedVersion:     ptr.To("1.1.0-r3"),
		Vulnerabilities:  ptr.To[int32](1),
		VulnerabilityIDs: []string{cve1},
		KnownExploited:   ptr.To(triagev1alpha1.KnownExploitedNotListed),
		Digest:           ptr.To(digestOf(1)),
	}
}

// resourceSummary returns a summary that fits the actions: one Update and one Change.
func resourceSummary() *triagev1alpha1.ResourceSummary {
	return &triagev1alpha1.ResourceSummary{
		Actions: ptr.To[int32](2), Updates: ptr.To[int32](1), Changes: ptr.To[int32](1),
		Mitigations: ptr.To[int32](0), Investigations: ptr.To[int32](0), OmittedActions: ptr.To[int32](0),
		HighestSeverity: ptr.To(triagev1alpha1.SeverityHigh), HighestUrgency: ptr.To(triagev1alpha1.SSVCOutcomeScheduled),
		Critical: ptr.To[int32](0), KnownExploited: ptr.To[int32](0),
		PendingImages: ptr.To[int32](0), UnscannableImages: ptr.To[int32](1),
	}
}

// resourceStatus returns a status that the schema accepts and that sets every field of it.
func resourceStatus() triagev1alpha1.ResourceReportStatus {
	return triagev1alpha1.ResourceReportStatus{
		Images: []triagev1alpha1.ResourceImage{
			{
				Digest: ptr.To(digestOf(1)), Ref: ptr.To("registry.example/team-a/web:1.2"),
				ManifestDigests: []string{digestOf(2)}, State: triagev1alpha1.ResourceImageStateReady,
				Containers: []string{webName},
			},
			{
				Ref: ptr.To("registry.example/team-a/job:latest"), State: triagev1alpha1.ResourceImageStateUnscannable,
				Containers: []string{"job"},
			},
		},
		Actions: []triagev1alpha1.ResourceAction{updateAction(), changeAction()},
		Summary: resourceSummary(),
		Owner: []triagev1alpha1.OwnerValue{
			{Source: triagev1alpha1.OwnerSourceNamespaceLabel, Key: teamKey, Value: ptr.To(teamA)},
		},
		Exposure: ptr.To(triagev1alpha1.SSVCExposureOpen),
		Reach: &triagev1alpha1.ReportReach{
			InternalReach: triagev1alpha1.InternalReachCluster, Indirect: triagev1alpha1.IndirectExposureNotIndirect,
			WidenedBy: []triagev1alpha1.ReachWidening{
				{Kind: "Namespace", Name: teamA, Reason: "no policy in the namespace"},
				{Kind: "NetworkPolicy", Namespace: ptr.To(teamA), Name: webName, Rule: ptr.To[int32](0),
					Reason: "lets in an IP block, which can hold any address"},
			},
			Unseen: []triagev1alpha1.ReachUnseen{triagev1alpha1.ReachUnseenIPBlock},
		},
	}
}

// widening returns a widening of the reach whose texts are of the longest lengths that the schema takes.
func widening() triagev1alpha1.ReachWidening {
	return triagev1alpha1.ReachWidening{
		Kind: chars(63), Namespace: ptr.To(chars(63)), Name: chars(253), Rule: ptr.To[int32](2147483647),
		Reason: chars(256),
	}
}

var _ = Describe("ResourceReport API", func() {
	update := func(status triagev1alpha1.ResourceReportStatus) error {
		report := existingResourceReport()
		report.Status = status
		return k8sClient.Status().Update(ctx, report)
	}

	It("takes the status through the status subresource, and returns it as written", func() {
		report := existingResourceReport()
		report.Status = resourceStatus()
		Expect(k8sClient.Status().Update(ctx, report)).To(Succeed())

		var got triagev1alpha1.ResourceReport
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(report), &got)).To(Succeed())
		Expect(got.Status).To(Equal(resourceStatus()))
	})

	It("can't change its resource", func() {
		report := existingResourceReport()
		patch := client.MergeFrom(report.DeepCopy())
		report.Spec.Resource.Name = "other"
		Expect(k8sClient.Patch(ctx, report, patch)).To(refusedWith("the resource of a ResourceReport can't change"))
	})

	DescribeTable("refuses a status that breaks a rule",
		func(change func(*triagev1alpha1.ResourceReportStatus), parts ...string) {
			status := resourceStatus()
			change(&status)
			Expect(update(status)).To(refusedWith(parts...))
		},
		Entry("an image without a digest that isn't Unscannable", func(s *triagev1alpha1.ResourceReportStatus) {
			s.Images[1].State = triagev1alpha1.ResourceImageStatePending
		}, "only an Unscannable image has no digest"),
		Entry("a fixedVersion on a step other than Update", func(s *triagev1alpha1.ResourceReportStatus) {
			s.Actions[0].Step = triagev1alpha1.ResourceStepMitigate
			s.Summary.Updates, s.Summary.Mitigations = ptr.To[int32](0), ptr.To[int32](1)
		}, "only an Update has a fixedVersion"),
		Entry("steps that don't add up to the actions", func(s *triagev1alpha1.ResourceReportStatus) {
			s.Summary.Changes = ptr.To[int32](0)
		}, "add up to actions"),
		Entry("more omitted actions than actions", func(s *triagev1alpha1.ResourceReportStatus) {
			s.Summary.OmittedActions = ptr.To[int32](3)
		}, "omittedActions counts no more than actions"),
		Entry("a highestUrgency without a vulnerability action", func(s *triagev1alpha1.ResourceReportStatus) {
			s.Actions = []triagev1alpha1.ResourceAction{changeAction()}
			s.Summary.Actions, s.Summary.Updates = ptr.To[int32](1), ptr.To[int32](0)
		}, "highestUrgency is set exactly when a vulnerability action exists"),
		Entry("a vulnerability action without a highestUrgency", func(s *triagev1alpha1.ResourceReportStatus) {
			s.Summary.HighestUrgency = nil
		}, "highestUrgency is set exactly when a vulnerability action exists"),
		Entry("vulnerabilities without IDs", func(s *triagev1alpha1.ResourceReportStatus) {
			s.Actions[0].VulnerabilityIDs = nil
		}, "come together"),
		Entry("more IDs than vulnerabilities", func(s *triagev1alpha1.ResourceReportStatus) {
			s.Actions[0].VulnerabilityIDs = []string{cve1, "CVE-2026-0002"}
		}, "lists no more IDs than vulnerabilities counts"),
		Entry("no location", func(s *triagev1alpha1.ResourceReportStatus) {
			s.Actions[1].Locations = nil
		}, "locations"),
		Entry("nine locations", func(s *triagev1alpha1.ResourceReportStatus) {
			s.Actions[1].Locations = slices.Repeat([]string{webName}, 9)
		}, "locations"),
		Entry("a title of 257 characters", func(s *triagev1alpha1.ResourceReportStatus) {
			s.Actions[1].Title = chars(257)
		}, "title"),
		Entry("257 actions", func(s *triagev1alpha1.ResourceReportStatus) {
			s.Actions = slices.Repeat([]triagev1alpha1.ResourceAction{changeAction()}, 257)
		}, "actions"),
		Entry("33 images", func(s *triagev1alpha1.ResourceReportStatus) {
			s.Images = slices.Repeat([]triagev1alpha1.ResourceImage{s.Images[0]}, 33)
		}, "images"),
		Entry("a step that no enum has", func(s *triagev1alpha1.ResourceReportStatus) {
			s.Actions[1].Step = guess
		}, "step"),
		Entry("nine widenings of the reach", func(s *triagev1alpha1.ResourceReportStatus) {
			s.Reach.WidenedBy = slices.Repeat(s.Reach.WidenedBy[:1], 9)
		}, "widenedBy"),
		Entry("a widening whose reason is 257 characters", func(s *triagev1alpha1.ResourceReportStatus) {
			s.Reach.WidenedBy[0].Reason = chars(257)
		}, "reason"),
		Entry("a widening of a negative rule", func(s *triagev1alpha1.ResourceReportStatus) {
			s.Reach.WidenedBy[1].Rule = ptr.To[int32](-1)
		}, "rule"),
		Entry("a widening without a reason", func(s *triagev1alpha1.ResourceReportStatus) {
			s.Reach.WidenedBy[0].Reason = ""
		}, "reason"),
		Entry("an unseen input that no enum has", func(s *triagev1alpha1.ResourceReportStatus) {
			s.Reach.Unseen = []triagev1alpha1.ReachUnseen{guess}
		}, "unseen"),
		Entry("an unseen input twice", func(s *triagev1alpha1.ResourceReportStatus) {
			s.Reach.Unseen = []triagev1alpha1.ReachUnseen{triagev1alpha1.ReachUnseenIPBlock,
				triagev1alpha1.ReachUnseenIPBlock}
		}, "unseen"),
	)

	It("takes 8 widenings of the longest texts, and each unseen input", func() {
		status := resourceStatus()
		status.Reach.WidenedBy = slices.Repeat([]triagev1alpha1.ReachWidening{widening()}, 8)
		status.Reach.Unseen = []triagev1alpha1.ReachUnseen{triagev1alpha1.ReachUnseenAdminNetworkPolicy,
			triagev1alpha1.ReachUnseenCalicoNetworkPolicy, triagev1alpha1.ReachUnseenIPBlock,
			triagev1alpha1.ReachUnseenUnknownParentRef}
		Expect(update(status)).To(Succeed())
	})

	It("takes a status whose omitted actions may be the vulnerability ones", func() {
		status := resourceStatus()
		status.Actions = []triagev1alpha1.ResourceAction{changeAction()}
		status.Summary.Actions, status.Summary.Updates = ptr.To[int32](2), ptr.To[int32](1)
		status.Summary.OmittedActions = ptr.To[int32](1)
		Expect(update(status)).To(Succeed())
	})

	It("takes exactly 8 locations, 256 actions and 32 images", func() {
		status := resourceStatus()
		status.Actions = slices.Repeat([]triagev1alpha1.ResourceAction{changeAction()}, 256)
		status.Actions[0].Locations = slices.Repeat([]string{chars(256)}, 8)
		status.Actions[0].Title = chars(256)
		status.Summary.Actions, status.Summary.Updates, status.Summary.Changes = ptr.To[int32](256), ptr.To[int32](0), ptr.To[int32](256)
		status.Summary.HighestUrgency = nil
		status.Images = slices.Repeat([]triagev1alpha1.ResourceImage{status.Images[0]}, 32)
		Expect(update(status)).To(Succeed())
	})
})
