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

package hub_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
)

var _ = Describe("The hub", func() {
	It("has a running image scanned, keeps the sheet of its manifest current, and removes both once nothing runs it", func() {
		matcher.set(v1, exampleMatch, otherMatch)
		namespace, digest, manifest := newNamespace(), newDigest(), newDigest()

		By("seeing the image run")
		pod := runWorkload(namespace, "app-0", digest)
		Eventually(lookup(digest, &inventoryv1alpha1.ImageInventory{}), startup, poll).Should(Succeed())

		By("asking the spoke for a scan, which its runner starts as a Job")
		job := expectScanJob(digest)

		By("storing the evidence of the scan, and the facts that name it")
		runScanPod(job, resultLog(digest, evidenceOf(manifest)))
		Eventually(manifestsOf(digest), reaction, poll).Should(Equal([]string{manifest}))

		By("writing the sheet that the rules make of the matches of the evidence")
		Eventually(statusOf(manifest), reaction, poll).Should(Equal(
			sheet(v1, scannerImage, counted{suppressed: 1, needsAssessment: 1}, otherReached, exampleNotLoadable)))

		By("writing the findings of a new database that changes them")
		matcher.set(v2, exploited(exampleMatch), otherMatch)
		changed := sheet(v2, scannerImage, counted{tracked: 1, needsAssessment: 1}, otherReached, exampleExploited)
		Eventually(statusOf(manifest), reaction, poll).Should(Equal(changed))

		By("keeping the sheet as it is when a new database finds the same")
		matched := matcher.matched(manifest)
		matcher.set(v3, exploited(exampleMatch), otherMatch)
		Eventually(func() int { return matcher.matched(manifest) }, reaction, poll).Should(BeNumerically(">", matched))
		Consistently(statusOf(manifest), quiet, poll).Should(Equal(changed))

		By("deleting the sheet and the evidence once no digest refers to the manifest")
		deletePod(pod)
		Eventually(lookup(digest, &inventoryv1alpha1.ImageInventory{}), reaction, poll).Should(Satisfy(apierrors.IsNotFound))
		Eventually(lookup(manifest, &inventoryv1alpha1.ImageVerdicts{}), reaction, poll).Should(Satisfy(apierrors.IsNotFound))
		Eventually(lookup(manifest, &inventoryv1alpha1.ImagePackages{}), reaction, poll).Should(Satisfy(apierrors.IsNotFound))
	})

	It("evaluates every manifest again when the OperatorConfig changes the minimum completeness", func() {
		matcher.set(v1, exampleMatch, otherMatch)
		digest, manifest := newDigest(), newDigest()

		By("scanning an image whose evidence is below the default minimum")
		runAndScan(newNamespace(), "app-0", digest, incompleteEvidenceOf(manifest))
		Eventually(statusOf(manifest), reaction, poll).Should(Equal(
			sheet(v1, scannerImage, counted{needsAssessment: 2}, otherGuarded, exampleGuarded)))

		By("lowering the minimum to the completeness of the evidence")
		operatorConfig := &configv1alpha1.OperatorConfig{
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
			Spec:       configv1alpha1.OperatorConfigSpec{Rules: &configv1alpha1.Rules{MinCompletenessPercent: ptr.To(int32(75))}},
		}
		Expect(k8sClient.Create(ctx, operatorConfig)).To(Succeed())
		DeferCleanup(func() { Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, operatorConfig))).To(Succeed()) })

		Eventually(statusOf(manifest), reaction, poll).Should(Equal(
			sheet(v1, scannerImage, counted{suppressed: 1, needsAssessment: 1}, otherReached, exampleNotLoadable)))
	})
})
