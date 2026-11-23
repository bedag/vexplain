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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	triagev1alpha1 "github.com/bedag/vexplain/api/triage/v1alpha1"
)

// statementCount numbers the statements that the specs create.
var statementCount int

// statement returns a VexStatement of an image's case, fixed, that the schema accepts, without a review.
func statement() *triagev1alpha1.VexStatement {
	statementCount++
	name := fmt.Sprintf("cve-2026-0001-%016x", 1000+statementCount)
	return &triagev1alpha1.VexStatement{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: triagev1alpha1.VexStatementSpec{
			Subject: triagev1alpha1.AssessmentSubject{
				Type:           triagev1alpha1.SubjectTypeContainerImage,
				ContainerImage: &triagev1alpha1.ContainerImageSubject{Digest: digestOf(1000 + statementCount)},
			},
			VulnerabilityID: cve1,
			Status:          triagev1alpha1.VEXStatusFixed,
			Origin:          triagev1alpha1.StatementOriginAgent,
			AssessmentRef:   triagev1alpha1.AssessmentReference{Name: name},
			InputHash:       "sha256:" + fmt.Sprintf("%064x", statementCount),
		},
	}
}

var _ = Describe("The VexStatement schema", func() {
	It("starts a statement's review as Proposed", func() {
		obj := statement()
		Expect(create(obj)).To(Succeed())

		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(obj), obj)).To(Succeed())
		Expect(obj.Spec.Review).NotTo(BeNil())
		Expect(obj.Spec.Review.State).To(HaveValue(Equal(triagev1alpha1.ReviewStateProposed)))
	})

	It("takes a review, which accepts or rejects the statement with a comment", func() {
		obj := statement()
		Expect(create(obj)).To(Succeed())

		obj.Spec.Review = &triagev1alpha1.VexStatementReview{State: ptr.To(triagev1alpha1.ReviewStateAccepted)}
		Expect(k8sClient.Update(ctx, obj)).To(refusedWith("comment"))

		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(obj), obj)).To(Succeed())
		obj.Spec.Review = &triagev1alpha1.VexStatementReview{State: ptr.To(triagev1alpha1.ReviewStateAccepted),
			Comment: ptr.To("The image holds the fixed package.")}
		Expect(k8sClient.Update(ctx, obj)).To(Succeed())

		obj.Spec.Review.State = ptr.To(triagev1alpha1.ReviewStateRejected)
		Expect(k8sClient.Update(ctx, obj)).To(Succeed())
	})

	It("refuses any change of the statement but its review", func() {
		obj := statement()
		Expect(create(obj)).To(Succeed())

		for name, change := range map[string]func(*triagev1alpha1.VexStatementSpec){
			"status": func(s *triagev1alpha1.VexStatementSpec) {
				s.Status = triagev1alpha1.VEXStatusNotAffected
				s.Justification = ptr.To(triagev1alpha1.VEXJustificationVulnerableCodeNotPresent)
			},
			"vulnerabilityID": func(s *triagev1alpha1.VexStatementSpec) { s.VulnerabilityID = cve2 },
			"subject":         func(s *triagev1alpha1.VexStatementSpec) { s.Subject.ContainerImage.Digest = digestOf(9999) },
			"assessmentRef":   func(s *triagev1alpha1.VexStatementSpec) { s.AssessmentRef.Name = "another" },
			"inputHash":       func(s *triagev1alpha1.VexStatementSpec) { s.InputHash = "sha256:" + fmt.Sprintf("%064x", 9999) },
		} {
			By("changing its " + name)
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(obj), obj)).To(Succeed())
			change(&obj.Spec)
			Expect(k8sClient.Update(ctx, obj)).To(refusedWith("only the review of a VexStatement can change"))
		}
	})

	It("states NotAffected, with its justification, or Fixed, without one", func() {
		affected := statement()
		affected.Spec.Status = triagev1alpha1.VEXStatusAffected
		Expect(create(affected)).To(refusedWith("NotAffected or Fixed"))

		unjustified := statement()
		unjustified.Spec.Status = triagev1alpha1.VEXStatusNotAffected
		Expect(create(unjustified)).To(refusedWith("justification"))

		justified := statement()
		justified.Spec.Justification = ptr.To(triagev1alpha1.VEXJustificationVulnerableCodeNotPresent)
		Expect(create(justified)).To(refusedWith("justification"))

		notAffected := statement()
		notAffected.Spec.Status = triagev1alpha1.VEXStatusNotAffected
		notAffected.Spec.Justification = ptr.To(triagev1alpha1.VEXJustificationVulnerableCodeNotPresent)
		Expect(create(notAffected)).To(Succeed())
	})
})
