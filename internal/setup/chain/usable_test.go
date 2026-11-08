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
	"slices"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/inventory"
	subjects "github.com/bedag/vexplain/sdk/subject"
)

const (
	// unusableFor is how long the spec watches the hub leave a new image alone while the vulnerabilities collector is
	// unusable: several looks of the assessor at the image, each of which would ask for its evidence if the playbook
	// were Ready.
	unusableFor = 5 * time.Second
	// recovery bounds how long the hub takes to have that image scanned and its manifest matched once the
	// vulnerabilities collector can be used again: far less than the wait before the assessor looks at an image again
	// on its own, so only the Collector's change can have started it.
	recovery = 15 * time.Second
	// guardRule is the default rule that holds every finding open while the evidence covers too little.
	guardRule = "completeness-guard"
	// playbookName is the default playbook.
	playbookName = "container-cves"
)

// While the only producer of the findings can't be used, the default playbook isn't Ready: the findings have no
// Ready producer. It asks for no evidence and no match, and its sheets are evaluated again from their findings.
var _ = Describe("The hub, with the production wiring, while the findings collector can't be used", func() {
	It("keeps every sheet, evaluates it again when a rule changes, and asks and matches again once the collector can be "+
		"used", func() {
		images, later := []string{digestOf(11), digestOf(12)}, digestOf(13)
		manifests := map[string]string{images[0]: digestOf(111), images[1]: digestOf(112), later: digestOf(113)}
		scanner := newScannerStandIn(GinkgoT(), func(image string) string { return manifests[image] })
		vulnerabilities := newVulnerabilitiesStandIn(GinkgoT(), v1, libraryMatch)
		workloads := newWorkloadsStandIn(images...)
		awaitForgotten(append(slices.Clone(images), later)...)

		By("installing the scanner, the vulnerabilities collector and the workloads collector, which reports two images")
		install("scanner", scanner)
		install("vulnerabilities", vulnerabilities)
		install("workloads", workloads)
		for _, image := range images {
			Eventually(sheetOf(manifests[image]), startup, poll).Should(HaveField("FindingsVersion", HaveValue(Equal(v1))))
		}
		matched := len(vulnerabilities.matched())

		By("giving the vulnerabilities collector settings that its schema refuses, so that it can't be used")
		setSettings("vulnerabilities", []byte(`{"maxConcurrent": 99}`))
		Eventually(collectorReady("vulnerabilities"), startup, poll).Should(And(
			HaveField("Status", metav1.ConditionFalse),
			HaveField("Reason", configv1alpha1.ReasonSettingsInvalid),
		))
		Eventually(playbookReady, startup, poll).Should(And(
			HaveField("Status", metav1.ConditionFalse),
			HaveField("Reason", configv1alpha1.ReasonTypeNotProduced),
		), "the findings have no Ready producer")

		By("evaluating every sheet again from its findings when a rule changes, and deleting none")
		changeRule(guardRule, func(spec *configv1alpha1.RuleSpec) {
			spec.Condition = "contents.coverage < 101"
			spec.Reason = ptr.To("'completeness ' + string(contents.coverage) + '% is below 101%'")
		})
		for _, image := range images {
			Eventually(sheetOf(manifests[image]), startup, poll).Should(HaveField("Findings",
				ConsistOf(HaveField("Rule", HaveValue(Equal(guardRule))))))
		}
		Consistently(func() []*inventoryv1alpha1.ImageVerdictsStatus {
			return []*inventoryv1alpha1.ImageVerdictsStatus{sheetOf(manifests[images[0]])(), sheetOf(manifests[images[1]])()}
		}, quiet, poll).ShouldNot(ContainElement(BeNil()))
		Expect(vulnerabilities.matched()).To(HaveLen(matched), "nothing is matched while the vulnerabilities collector can't be used")

		By("asking for no evidence of an image that starts to run meanwhile, and matching nothing")
		workloads.add(later)
		Eventually(func() error {
			return k8sClient.Get(ctx, client.ObjectKey{Name: inventory.NameForDigest(later)}, &inventoryv1alpha1.ImageInventory{})
		}, startup, poll).Should(Succeed())
		Consistently(manifestsOf(later), unusableFor, poll).Should(BeEmpty())
		Expect(scanned(scanner, later)).To(BeFalse(), "the scanner was asked for nothing")
		Expect(sheetOf(manifests[later])()).To(BeNil())
		Expect(vulnerabilities.matched()).To(HaveLen(matched))

		By("asking for the evidence of that image, and matching its manifest, once the vulnerabilities collector can be used again")
		setSettings("vulnerabilities", nil)
		Eventually(sheetOf(manifests[later]), recovery, poll).Should(And(
			Not(BeNil()),
			HaveField("FindingsVersion", HaveValue(Equal(v1))),
			HaveField("Findings", ConsistOf(HaveField("Rule", HaveValue(Equal(guardRule))))),
		))
		Expect(vulnerabilities.matched()).To(HaveLen(matched + 1))

		By("matching every manifest again when the database changes, as usual")
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
	})
})

// awaitForgotten waits, after the spec, until the images are gone from the inventory, as presence forgets them once
// the spec's workloads collector is gone: the next spec installs a workloads collector of the same name, which must
// find no stream, and no image, of this one's.
func awaitForgotten(images ...string) {
	DeferCleanup(func() {
		for _, image := range images {
			Eventually(func() error {
				return k8sClient.Get(ctx, client.ObjectKey{Name: inventory.NameForDigest(image)}, &inventoryv1alpha1.ImageInventory{})
			}, startup, poll).Should(Satisfy(apierrors.IsNotFound))
		}
	})
}

// playbookReady reads the Ready condition of the default playbook, or nil while it has none.
func playbookReady(g Gomega) *metav1.Condition {
	var playbook configv1alpha1.Playbook
	g.Expect(k8sClient.Get(ctx, client.ObjectKey{Name: playbookName}, &playbook)).To(Succeed())
	return meta.FindStatusCondition(playbook.Status.Conditions, configv1alpha1.ConditionReady)
}

// scanned reports whether the scanner stand-in was asked to scan the image of digest.
func scanned(scanner *scannerStandIn, digest string) bool {
	return slices.ContainsFunc(scanner.scanned(), func(call scanCall) bool { return call.Subject == subjects.Image(digest) })
}

// collectorReady returns a function that reads the Ready condition of the Collector of the name, or nil while it has
// none.
func collectorReady(name string) func(g Gomega) *metav1.Condition {
	return func(g Gomega) *metav1.Condition {
		var c configv1alpha1.Collector
		g.Expect(k8sClient.Get(ctx, client.ObjectKey{Name: name}, &c)).To(Succeed())
		return meta.FindStatusCondition(c.Status.Conditions, configv1alpha1.ConditionReady)
	}
}

// setSettings writes the settings of the Collector of the name, or none for nil.
func setSettings(name string, settings []byte) {
	GinkgoHelper()
	Eventually(func(g Gomega) {
		var c configv1alpha1.Collector
		g.Expect(k8sClient.Get(ctx, client.ObjectKey{Name: name}, &c)).To(Succeed())
		c.Spec.Settings = nil
		if settings != nil {
			c.Spec.Settings = &runtime.RawExtension{Raw: settings}
		}
		g.Expect(k8sClient.Update(ctx, &c)).To(Succeed())
	}, startup, poll).Should(Succeed())
}

// changeRule changes the spec of the rule with the name, and changes it back after the spec.
func changeRule(name string, change func(*configv1alpha1.RuleSpec)) {
	GinkgoHelper()
	var before configv1alpha1.RuleSpec
	updateRule(name, func(spec *configv1alpha1.RuleSpec) {
		before = *spec.DeepCopy()
		change(spec)
	})
	DeferCleanup(func() {
		updateRule(name, func(spec *configv1alpha1.RuleSpec) { *spec = *before.DeepCopy() })
	})
}

// updateRule changes the spec of the rule with the name, and writes it, trying again after a conflict.
func updateRule(name string, change func(*configv1alpha1.RuleSpec)) {
	GinkgoHelper()
	Eventually(func(g Gomega) {
		var rule configv1alpha1.Rule
		g.Expect(k8sClient.Get(ctx, client.ObjectKey{Name: name}, &rule)).To(Succeed())
		change(&rule.Spec)
		g.Expect(k8sClient.Update(ctx, &rule)).To(Succeed())
	}, startup, poll).Should(Succeed())
}

// manifestsOf returns a function that reads the manifests that the facts of the image of digest name.
func manifestsOf(digest string) func() []string {
	return func() []string {
		var obj inventoryv1alpha1.ImageInventory
		if err := k8sClient.Get(ctx, client.ObjectKey{Name: inventory.NameForDigest(digest)}, &obj); err != nil ||
			obj.Status.Facts == nil {
			return nil
		}
		var manifests []string
		for _, manifest := range obj.Status.Facts.Manifests {
			manifests = append(manifests, manifest.Digest)
		}
		return manifests
	}
}
