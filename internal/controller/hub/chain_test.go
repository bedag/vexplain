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

	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/scan/result"
	"github.com/bedag/vexplain/internal/tasks"
	subjects "github.com/bedag/vexplain/sdk/subject"
)

var _ = Describe("The hub", func() {
	It("has a running image scanned, keeps the sheet of its manifest current, and removes both once nothing runs it", func() {
		findings.set(v1, exampleMatch, otherMatch, goneMatch)
		namespace, digest, manifest := newNamespace(), newDigest(), newDigest()

		By("seeing the image run")
		app := runWorkload(namespace, "app-0", digest)
		Eventually(lookup(digest, &inventoryv1alpha1.ImageInventory{}), startup, poll).Should(Succeed())

		By("asking the spoke for the scanner's evidence, which its runner collects in a scan Job")
		job := expectScanJob(digest)
		Expect(requests.taken()).To(ContainElement(tasks.Request{
			Type: result.EvidenceType, Subject: subjects.Image(digest), Repositories: []string{repository},
		}))

		By("storing the evidence of the scan as a CloudEvent, and the facts that name it")
		runScanPod(job, resultLog(digest, evidenceOf(manifest)))
		Eventually(manifestsOf(digest), reaction, poll).Should(Equal([]string{manifest}))
		Expect(recordOf(manifest)(Default)).NotTo(BeNil())

		By("writing the sheet that the default playbook's rules make of the findings: open findings first, a settled one last")
		first := sheet(v1, contentsOf(manifest), counted{underInvestigation: 2, notAffected: 1}, otherReached, exampleUnreached, goneSettled)
		Eventually(statusOf(manifest), reaction, poll).Should(Equal(first))

		By("deleting the sheet when the evidence that its findings come from is gone")
		Expect(evidenceStore().DeleteSubject(ctx, subjects.Manifest(manifest))).To(Succeed())
		Eventually(statusOf(manifest), reaction, poll).Should(BeNil())

		By("asking for the evidence again, and writing the sheet again once it is back")
		runScanPod(expectScanJob(digest, job.Name), resultLog(digest, evidenceOf(manifest)))
		Eventually(recordOf(manifest), reaction, poll).ShouldNot(BeNil())
		Eventually(statusOf(manifest), reaction, poll).Should(Equal(
			sheet(v1, contentsOf(manifest), counted{underInvestigation: 2, notAffected: 1}, otherReached, exampleUnreached, goneSettled)))

		By("writing the findings of a new database that changes them: a known exploited vulnerability is held open")
		findings.set(v2, exploited(exampleMatch), otherMatch, goneMatch)
		findings.change()
		changed := sheet(v2, contentsOf(manifest), counted{underInvestigation: 2, notAffected: 1}, exampleExploited, otherReached, goneSettled)
		Eventually(statusOf(manifest), reaction, poll).Should(Equal(changed))

		By("keeping the sheet as it is when a new database finds the same")
		found := findings.found(manifest)
		findings.set(v3, exploited(exampleMatch), otherMatch, goneMatch)
		findings.change()
		Eventually(findings.foundOf(manifest), reaction, poll).Should(BeNumerically(">", found))
		Consistently(statusOf(manifest), quiet, poll).Should(Equal(changed), "the sheet keeps the version that last changed it")

		By("deleting the sheet and the evidence once no digest refers to the manifest")
		stopWorkload(app)
		Eventually(lookup(digest, &inventoryv1alpha1.ImageInventory{}), reaction, poll).Should(Satisfy(apierrors.IsNotFound))
		Eventually(lookup(manifest, &inventoryv1alpha1.ImageVerdicts{}), reaction, poll).Should(Satisfy(apierrors.IsNotFound))
		Eventually(recordOf(manifest), reaction, poll).Should(BeNil())
	})
})
