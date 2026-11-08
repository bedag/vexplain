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

package chain_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
)

// playbookName is the default playbook.
const playbookName = "container-cves"

// A producer's health doesn't stop a playbook (decision 0043): it only decides whether the producer is asked for
// work. While the scanner, the only producer of the contents and the SBOM that the default playbook needs, can't be
// used, the playbook stays Ready, and the vulnerabilities collector still matches the stored SBOMs again when its
// database changes, so that a new vulnerability isn't left out for as long as the scanner's outage lasts.
var _ = Describe("The hub, with the production wiring, while the scanner can't be used", func() {
	It("keeps the playbook Ready, and matches every stored SBOM again when the vulnerabilities collector's database "+
		"changes", func() {
		images := []string{digestOf(21), digestOf(22)}
		manifests := map[string]string{images[0]: digestOf(121), images[1]: digestOf(122)}
		scanner := newScannerStandIn(GinkgoT(), func(image string) string { return manifests[image] })
		vulnerabilities := newVulnerabilitiesStandIn(GinkgoT(), v1, libraryMatch)
		awaitForgotten(images...)

		By("installing the scanner, the vulnerabilities collector and the workloads collector, which reports two images")
		install("scanner", scanner)
		install("vulnerabilities", vulnerabilities)
		install("workloads", newWorkloadsStandIn(images...))
		for _, image := range images {
			Eventually(sheetOf(manifests[image]), startup, poll).Should(HaveField("FindingsVersion", HaveValue(Equal(v1))))
		}
		matched := len(vulnerabilities.matched())

		By("giving the scanner settings that its schema refuses, so that it can't be used")
		setSettings("scanner", []byte(`{"maxConcurrentScans": 99}`))
		Eventually(collectorReady("scanner"), startup, poll).Should(And(
			HaveField("Status", metav1.ConditionFalse),
			HaveField("Reason", configv1alpha1.ReasonSettingsInvalid),
		))
		Consistently(playbookReady, quiet, poll).Should(HaveField("Status", metav1.ConditionTrue),
			"the playbook stays Ready while the scanner can't be used")

		By("matching every stored SBOM again when the vulnerabilities collector says that its database changed")
		exploited := libraryMatch
		exploited.KnownExploited = true
		vulnerabilities.setDatabase(v2, exploited)
		for _, manifest := range manifests {
			Eventually(sheetOf(manifest), startup, poll).Should(And(
				Not(BeNil()),
				HaveField("FindingsVersion", HaveValue(Equal(v2))),
				HaveField("Findings", ConsistOf(HaveField("KnownExploited", inventoryv1alpha1.KnownExploitedListed))),
			))
		}
		Expect(len(vulnerabilities.matched())).To(BeNumerically(">=", matched+len(manifests)),
			"each manifest was matched again, from its stored SBOM")
	})
})

// playbookReady reads the Ready condition of the default playbook, or nil while it has none.
func playbookReady(g Gomega) *metav1.Condition {
	var playbook configv1alpha1.Playbook
	g.Expect(k8sClient.Get(ctx, client.ObjectKey{Name: playbookName}, &playbook)).To(Succeed())
	return meta.FindStatusCondition(playbook.Status.Conditions, configv1alpha1.ConditionReady)
}
