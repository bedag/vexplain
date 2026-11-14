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
	"context"
	"errors"
	"slices"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	eventsv1 "k8s.io/api/events/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/controller/hub"
	"github.com/bedag/vexplain/internal/testenv/imagecontents"
	sdkevidence "github.com/bedag/vexplain/sdk/evidence"
)

// vmType is the type of the evidence of a playbook for virtual machines, which the VM collector of the
// suite produces. Such a playbook takes no subjects of the default one, and never conflicts with it.
const vmType = "com.example.vm.v1alpha1"

// extraType is a type of evidence that no Collector of the suite produces, and extra the name under which
// the specs supply it.
const (
	extraType = "com.example.extra.v1alpha1"
	extra     = "extra"
)

// nowhere names a Collector and a Rule that don't exist.
const nowhere = "nowhere"

// celTrue is CEL that holds for every finding.
const celTrue = "true"

// machineSBOM is the name under which a playbook for virtual machines takes the SBOM of each machine.
const machineSBOM = "machineSbom"

// vmPlaybook returns the spec of a playbook for virtual machines whose pipeline runs the rules, with the
// evidence, and the SBOM of each machine after it: the vulnerabilities collector consumes the SBOM, so that it
// takes part, and the playbook has findings.
func vmPlaybook(evidence []configv1alpha1.PlaybookEvidence, rules ...string) configv1alpha1.PlaybookSpec {
	spec := configv1alpha1.PlaybookSpec{
		Subjects: configv1alpha1.PlaybookSource{Type: vmType},
		Findings: configv1alpha1.PlaybookFindings{Type: ptr.To(sdkevidence.TypeFindings)},
		Evidence: append(slices.Clone(evidence), configv1alpha1.PlaybookEvidence{Name: machineSBOM, Type: sdkevidence.TypeSBOM}),
	}
	for _, rule := range rules {
		spec.Pipeline = append(spec.Pipeline, configv1alpha1.PlaybookStep{Rule: rule})
	}
	return spec
}

// brokenCondition is CEL that doesn't compile, which keeps a Rule from being Ready.
const brokenCondition = "finding."

// createPlaybook creates a playbook with the spec, and deletes it after the spec.
func createPlaybook(name string, spec configv1alpha1.PlaybookSpec) {
	GinkgoHelper()
	playbook := &configv1alpha1.Playbook{ObjectMeta: metav1.ObjectMeta{Name: name}, Spec: spec}
	Expect(k8sClient.Create(ctx, playbook)).To(Succeed())
	DeferCleanup(func() { Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, playbook))).To(Succeed()) })
}

// createRule creates a rule, and deletes it after the spec.
func createRule(rule *configv1alpha1.Rule) {
	GinkgoHelper()
	Expect(k8sClient.Create(ctx, rule)).To(Succeed())
	DeferCleanup(func() { Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, rule))).To(Succeed()) })
}

// holdRule returns a rule that holds every finding open, and needs the inputs.
func holdRule(name string, inputs ...configv1alpha1.RuleInput) *configv1alpha1.Rule {
	return &configv1alpha1.Rule{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: configv1alpha1.RuleSpec{
			Inputs:    inputs,
			Condition: celTrue,
			Outcome:   &configv1alpha1.RuleOutcome{Status: ptr.To(configv1alpha1.VEXStatusUnderInvestigation)},
		},
	}
}

// expectReady waits until the Ready condition of the playbook has the status and the reason, and
// returns it.
func expectReady(playbook string, status metav1.ConditionStatus, reason string) *metav1.Condition {
	GinkgoHelper()
	var ready *metav1.Condition
	Eventually(func(g Gomega) {
		ready = readyOf(&configv1alpha1.Playbook{}, playbook)(g)
		g.Expect(ready).NotTo(BeNil())
		g.Expect(ready.Status).To(Equal(status))
		g.Expect(ready.Reason).To(Equal(reason))
	}, reaction, poll).Should(Succeed())
	return ready
}

var _ = Describe("The playbook controller", func() {
	It("records a Warning event when a playbook turns not Ready, and when its reason changes, but not at every reconcile", func() {
		const name = "vm-cves-events"
		// The events API files the events of a cluster-scoped object in the namespace default.
		playbookEvents := func(g Gomega) []eventsv1.Event {
			var list eventsv1.EventList
			g.Expect(k8sClient.List(ctx, &list, client.InNamespace(metav1.NamespaceDefault),
				client.MatchingFields{"regarding.name": name})).To(Succeed())
			var out []eventsv1.Event
			for _, e := range list.Items {
				if e.Regarding.Kind == "Playbook" {
					out = append(out, e)
				}
			}
			return out
		}
		createPlaybook(name, vmPlaybook(nil, "events-rule"))
		missing := expectReady(name, metav1.ConditionFalse, configv1alpha1.ReasonRuleMissing)
		Eventually(playbookEvents, reaction, poll).Should(HaveLen(1))
		event := playbookEvents(Default)[0]
		Expect(event.Type).To(Equal(corev1.EventTypeWarning))
		Expect(event.Reason).To(Equal(configv1alpha1.ReasonRuleMissing), "the reason of Ready")
		Expect(event.Note).To(Equal(missing.Message))

		By("recording no further event while the reason stays, however often the playbook is checked again")
		// A Rule that comes and goes, of another name, has every playbook checked again.
		createRule(holdRule("events-unrelated"))
		Consistently(playbookEvents, quiet, poll).Should(ConsistOf(HaveField("Series", BeNil())))

		By("recording an event when the reason changes")
		broken := holdRule("events-rule")
		broken.Spec.Condition = brokenCondition
		createRule(broken)
		notReady := expectReady(name, metav1.ConditionFalse, configv1alpha1.ReasonRuleNotReady)
		Eventually(playbookEvents, reaction, poll).Should(ConsistOf(
			HaveField("Reason", configv1alpha1.ReasonRuleMissing),
			And(HaveField("Reason", configv1alpha1.ReasonRuleNotReady), HaveField("Note", notReady.Message)),
		))

		By("recording none when the playbook turns Ready")
		changeRule("events-rule", func(spec *configv1alpha1.RuleSpec) { spec.Condition = celTrue })
		expectReady(name, metav1.ConditionTrue, configv1alpha1.ReasonValid)
		Consistently(playbookEvents, quiet, poll).Should(HaveLen(2))
	})

	It("settles none of a playbook's findings once the only producer of a type that it needs is deleted, whose evidence goes with the sheet, and settles them again once it is back and has delivered again", func() {
		findings.set(v1, exampleMatch, otherMatch, goneMatch)
		digest, manifest := newDigest(), newDigest()
		runAndScan(newNamespace(), "app-0", digest, evidenceOf(manifest))
		settled := sheet(v1, restedOn(manifest), counted{underInvestigation: 2, notAffected: 1, fixable: 1}, otherReached, exampleUnreached, goneSettled)
		Eventually(statusOf(manifest), reaction, poll).Should(Equal(settled))

		By("deleting the scanner's Collector")
		Expect(k8sClient.Delete(ctx, collectorNamed(scanner))).To(Succeed())
		DeferCleanup(func() {
			Expect(client.IgnoreAlreadyExists(k8sClient.Create(ctx, collectorNamed(scanner)))).To(Succeed())
			recordCapabilities(GinkgoT(), k8sClient, scanner)
			expectReady(playbookName, metav1.ConditionTrue, configv1alpha1.ReasonValid)
		})

		ready := expectReady(playbookName, metav1.ConditionFalse, configv1alpha1.ReasonTypeNotProduced)
		Expect(ready.Message).To(And(ContainSubstring(imagecontents.Type), ContainSubstring(sdkevidence.TypeSBOM)))

		// The deployer's finalizer deletes the evidence that a deleted Collector delivered (design 5.9), and a sheet
		// whose evidence is gone goes with it: no verdict rests on evidence that is gone, so no finding stays settled.
		By("deleting the evidence of the deleted Collector, and the sheet that rested on it")
		Eventually(heldOf(manifest), reaction, poll).Should(BeEmpty())
		Eventually(statusOf(manifest), reaction, poll).Should(BeNil())

		By("settling the findings again once the Collector is back, and the spoke has scanned the image again")
		asked := requests.of(digest)()
		install(GinkgoT(), k8sClient, scanner)
		expectReady(playbookName, metav1.ConditionTrue, configv1alpha1.ReasonValid)
		answerWithScan(digest, expectRequest(digest, asked), evidenceOf(manifest))
		Eventually(heldOf(manifest), reaction, poll).Should(Equal(scanTypes))
		Eventually(statusOf(manifest), reaction, poll).Should(Equal(
			sheet(v1, restedOn(manifest), counted{underInvestigation: 2, notAffected: 1, fixable: 1}, otherReached, exampleUnreached, goneSettled)))
	})

	It("says when a rule of the pipeline needs an input that the playbook doesn't supply", func() {
		createRule(holdRule("needs-sbom", configv1alpha1.RuleInput{Name: sbomName, Type: sdkevidence.TypeSBOM}))
		createRule(holdRule("needs-other-contents", configv1alpha1.RuleInput{Name: contents, Type: "com.example.contents.v1"}))
		createPlaybook("vm-cves-inputs", vmPlaybook([]configv1alpha1.PlaybookEvidence{{Name: contents, Type: imagecontents.Type}},
			guardRule, "needs-sbom", "needs-other-contents"))

		ready := expectReady("vm-cves-inputs", metav1.ConditionFalse, configv1alpha1.ReasonInputMissing)

		Expect(ready.Message).To(ContainSubstring(`"needs-sbom"`))
		Expect(ready.Message).To(ContainSubstring(`"sbom"`))
		Expect(ready.Message).To(ContainSubstring(`"needs-other-contents"`), "an input of another type is missing too")
		Expect(ready.Message).NotTo(ContainSubstring(guardRule))
	})

	It("says when a rule of the pipeline is missing, or isn't Ready", func() {
		broken := holdRule("does-not-compile")
		broken.Spec.Condition = brokenCondition
		createRule(broken)
		createPlaybook("vm-cves-rules", vmPlaybook(nil, "does-not-compile"))
		ready := expectReady("vm-cves-rules", metav1.ConditionFalse, configv1alpha1.ReasonRuleNotReady)
		Expect(ready.Message).To(ContainSubstring(`"does-not-compile"`))

		update(&configv1alpha1.Playbook{}, "vm-cves-rules", func(playbook *configv1alpha1.Playbook) {
			playbook.Spec.Pipeline = append(playbook.Spec.Pipeline, configv1alpha1.PlaybookStep{Rule: nowhere})
		})
		ready = expectReady("vm-cves-rules", metav1.ConditionFalse, configv1alpha1.ReasonRuleMissing)
		Expect(ready.Message).To(ContainSubstring(`"` + nowhere + `"`))
	})

	It("says when no Collector produces a type that the playbook needs, as their capabilities show", func() {
		By("recording capabilities of the scanner that leave out its evidence")
		var collector configv1alpha1.Collector
		Expect(k8sClient.Get(ctx, client.ObjectKey{Name: scanner}, &collector)).To(Succeed())
		collector.Status.Capabilities = &configv1alpha1.CollectorCapabilities{
			Roles:    []configv1alpha1.CollectorRole{configv1alpha1.CollectorRoleSpoke},
			Produces: []configv1alpha1.ProducedType{{Type: "com.example.sbom.v1", Scope: configv1alpha1.EvidenceScopeHub}},
			Watch:    configv1alpha1.CollectorWatchNotSupported,
		}
		Expect(k8sClient.Status().Update(ctx, &collector)).To(Succeed())
		DeferCleanup(func() {
			recordCapabilities(GinkgoT(), k8sClient, scanner)
			expectReady(playbookName, metav1.ConditionTrue, configv1alpha1.ReasonValid)
		})

		ready := expectReady(playbookName, metav1.ConditionFalse, configv1alpha1.ReasonTypeNotProduced)

		Expect(ready.Message).To(ContainSubstring(imagecontents.Type))
		Expect(ready.Message).To(ContainSubstring(`the evidence "contents"`))
	})

	// A playbook needs its subjects, its findings and its required evidence. Evidence that it takes as
	// optional, as a pod refers to a ConfigMap with optional: true, keeps it Ready without a producer, unless
	// a findings producer consumes it.
	It("is not Ready while a type of required evidence has no producer, and Ready when the evidence is optional", func() {
		const name = "vm-cves-extra"
		createRule(holdRule("needs-extra", configv1alpha1.RuleInput{Name: extra, Type: extraType}))
		createPlaybook(name, vmPlaybook([]configv1alpha1.PlaybookEvidence{{Name: extra, Type: extraType}}, "needs-extra"))

		ready := expectReady(name, metav1.ConditionFalse, configv1alpha1.ReasonTypeNotProduced)
		Expect(ready.Message).To(And(ContainSubstring(extraType), ContainSubstring(`the evidence "extra"`)))

		update(&configv1alpha1.Playbook{}, name, func(playbook *configv1alpha1.Playbook) {
			playbook.Spec.Evidence[0].Requirement = ptr.To(configv1alpha1.EvidenceOptional)
		})
		expectReady(name, metav1.ConditionTrue, configv1alpha1.ReasonValid)
	})

	// Every Collector that produces a type counts, unless an entry pins its producers: then only those count,
	// and each must exist and declare the type.
	It("counts only the Collectors that an entry pins", func() {
		const name = "vm-cves-pins"
		createRule(holdRule("needs-vm-contents", configv1alpha1.RuleInput{Name: contents, Type: imagecontents.Type}))
		createPlaybook(name, vmPlaybook([]configv1alpha1.PlaybookEvidence{{Name: contents, Type: imagecontents.Type}},
			"needs-vm-contents"))
		expectReady(name, metav1.ConditionTrue, configv1alpha1.ReasonValid)

		By("pinning a Collector that doesn't produce the type, though the scanner does")
		update(&configv1alpha1.Playbook{}, name, func(playbook *configv1alpha1.Playbook) {
			playbook.Spec.Evidence[0].Collectors = []string{vulnerabilitiesCollector}
		})
		ready := expectReady(name, metav1.ConditionFalse, configv1alpha1.ReasonTypeNotProduced)
		Expect(ready.Message).To(ContainSubstring(`"vulnerabilities", pinned for the evidence "contents", produces no ` + imagecontents.Type))

		By("pinning a Collector that doesn't exist")
		update(&configv1alpha1.Playbook{}, name, func(playbook *configv1alpha1.Playbook) {
			playbook.Spec.Evidence[0].Collectors = []string{scanner, nowhere}
		})
		ready = expectReady(name, metav1.ConditionFalse, configv1alpha1.ReasonCollectorMissing)
		Expect(ready.Message).To(ContainSubstring(`"` + nowhere + `"`))

		By("pinning the scanner")
		update(&configv1alpha1.Playbook{}, name, func(playbook *configv1alpha1.Playbook) {
			playbook.Spec.Evidence[0].Collectors = []string{scanner}
		})
		expectReady(name, metav1.ConditionTrue, configv1alpha1.ReasonValid)

		By("pinning a Collector of the subjects that doesn't produce their type")
		update(&configv1alpha1.Playbook{}, name, func(playbook *configv1alpha1.Playbook) {
			playbook.Spec.Subjects.Collectors = []string{scanner}
		})
		ready = expectReady(name, metav1.ConditionFalse, configv1alpha1.ReasonTypeNotProduced)
		Expect(ready.Message).To(ContainSubstring(`"scanner", pinned for the subjects, produces no ` + vmType))
	})

	// Several playbooks run at once, also over subjects of one type (decision 0043): each keeps a sheet of each
	// manifest, and a playbook that goes takes its sheets with it.
	It("runs two playbooks that take the same subjects, each with a sheet of a manifest, until one goes", func() {
		const copyName = "container-cves-copy"
		var original configv1alpha1.Playbook
		Expect(k8sClient.Get(ctx, client.ObjectKey{Name: playbookName}, &original)).To(Succeed())
		createPlaybook(copyName, *original.Spec.DeepCopy())
		expectReady(copyName, metav1.ConditionTrue, configv1alpha1.ReasonValid)
		findings.set(v1, exampleMatch, otherMatch, goneMatch)
		digest, manifest := newDigest(), newDigest()

		runAndScan(newNamespace(), "app-0", digest, evidenceOf(manifest))

		Eventually(statusOf(manifest), reaction, poll).Should(HaveField("Playbook", HaveValue(Equal(playbookName))))
		Eventually(statusUnder(manifest, copyName), reaction, poll).Should(HaveField("Playbook", HaveValue(Equal(copyName))))
		Expect(readyOf(&configv1alpha1.Playbook{}, playbookName)(Default)).To(HaveField("Status", metav1.ConditionTrue))

		By("deleting the copy")
		Expect(k8sClient.Delete(ctx, &configv1alpha1.Playbook{ObjectMeta: metav1.ObjectMeta{Name: copyName}})).To(Succeed())

		Eventually(statusUnder(manifest, copyName), reaction, poll).Should(BeNil())
		Consistently(statusOf(manifest), quiet, poll).ShouldNot(BeNil(), "the default playbook keeps its sheet")
	})
})

// ---- the check of a playbook, on a fake client ----

// failing has the deployer's check of a Collector find it failing: its Ready condition is False.
func failing(t *testing.T, c client.Client, name string) {
	t.Helper()
	var collector configv1alpha1.Collector
	require.NoError(t, c.Get(t.Context(), client.ObjectKey{Name: name}, &collector))
	meta.SetStatusCondition(&collector.Status.Conditions, metav1.Condition{
		Type: configv1alpha1.ConditionReady, Status: metav1.ConditionFalse, Reason: configv1alpha1.ReasonCollectorFailing,
		Message: "As the deployer found it.",
	})
	require.NoError(t, c.Status().Update(t.Context(), &collector))
}

// unrecorded takes the capabilities out of the status of a Collector, as of one that hasn't answered yet.
func unrecorded(t *testing.T, c client.Client, name string) {
	t.Helper()
	var collector configv1alpha1.Collector
	require.NoError(t, c.Get(t.Context(), client.ObjectKey{Name: name}, &collector))
	collector.Status.Capabilities = nil
	require.NoError(t, c.Status().Update(t.Context(), &collector))
}

// deleting has a Collector start to be deleted, which a finalizer holds until its evidence is gone, as the
// deployer's does.
func deleting(t *testing.T, c client.Client, name string) {
	t.Helper()
	var collector configv1alpha1.Collector
	require.NoError(t, c.Get(t.Context(), client.ObjectKey{Name: name}, &collector))
	collector.Finalizers = append(collector.Finalizers, "vexplain.bedag.ch/evidence")
	require.NoError(t, c.Update(t.Context(), &collector))
	require.NoError(t, c.Delete(t.Context(), &collector))
}

// A producer of a type is a Collector whose recorded capabilities declare the type, and that isn't being deleted:
// the subjects, the findings and each piece of required evidence need one, and each Collector that an entry pins must
// exist and declare the type. Only a findings producer that takes part counts, one whose match consumes a type of the
// playbook's evidence, and what it consumes is required, whatever the playbook says: its match needs it. A producer's
// health plays no part (decision 0043): it only decides whether vexplain asks the producer for work, and the playbook
// goes on with the stored evidence and the other producers. Other optional evidence never keeps a playbook from being
// Ready.
func TestAPlaybookIsReadyWhenWhatItNeedsHasProducers(t *testing.T) {
	const noneTakesPart = `no Collector that produces ` + sdkevidence.TypeFindings + ` for the findings consumes a type of ` +
		`the playbook's evidence`
	for _, tc := range []struct {
		name    string
		change  func(t *testing.T, c client.Client)
		reason  string
		message string
	}{
		{name: "the install", reason: configv1alpha1.ReasonValid},
		{name: "the only producer of the evidence fails", change: func(t *testing.T, c client.Client) { failing(t, c, scanner) },
			reason: configv1alpha1.ReasonValid},
		{name: "the only producer of the subjects fails", change: func(t *testing.T, c client.Client) { failing(t, c, workloadsCollector) },
			reason: configv1alpha1.ReasonValid},
		{name: "the only producer of the findings fails",
			change: func(t *testing.T, c client.Client) { failing(t, c, vulnerabilitiesCollector) }, reason: configv1alpha1.ReasonValid},
		{name: "the only producer of the findings has recorded no capabilities",
			change:  func(t *testing.T, c client.Client) { unrecorded(t, c, vulnerabilitiesCollector) },
			reason:  configv1alpha1.ReasonTypeNotProduced,
			message: `no Collector produces ` + sdkevidence.TypeFindings + ` for the findings`},
		{name: "the only producer of the evidence is being deleted", change: func(t *testing.T, c client.Client) { deleting(t, c, scanner) },
			reason:  configv1alpha1.ReasonTypeNotProduced,
			message: `no Collector produces ` + imagecontents.Type + ` for the evidence "contents"`},
		{name: "a findings producer that consumes none of the evidence, without one that does", change: func(t *testing.T, c client.Client) {
			install(t, c, ownChecker)
			require.NoError(t, c.Delete(t.Context(), collectorNamed(vulnerabilitiesCollector)))
		}, reason: configv1alpha1.ReasonTypeNotProduced, message: noneTakesPart},
		{name: "a findings producer that consumes none of the evidence, beside one that does",
			change: func(t *testing.T, c client.Client) { install(t, c, ownChecker) }, reason: configv1alpha1.ReasonValid},
		{name: "the pinned producer of the findings consumes none of the evidence", change: func(t *testing.T, c client.Client) {
			install(t, c, ownChecker)
			changeUnitPlaybook(t, c, func(spec *configv1alpha1.PlaybookSpec) {
				spec.Findings.Collectors = []string{ownChecker}
			})
		}, reason: configv1alpha1.ReasonTypeNotProduced, message: noneTakesPart},
		{name: "the only producer of the findings takes no hub role, and has no match", change: func(t *testing.T, c client.Client) {
			var collector configv1alpha1.Collector
			require.NoError(t, c.Get(t.Context(), client.ObjectKey{Name: vulnerabilitiesCollector}, &collector))
			collector.Status.Capabilities.Roles = []configv1alpha1.CollectorRole{configv1alpha1.CollectorRoleSpoke}
			require.NoError(t, c.Status().Update(t.Context(), &collector))
		}, reason: configv1alpha1.ReasonTypeNotProduced, message: noneTakesPart},
		{name: "the only producer of optional evidence that the findings producer consumes has recorded no capabilities",
			change: func(t *testing.T, c client.Client) {
				unrecorded(t, c, scanner)
				changeUnitPlaybook(t, c, func(spec *configv1alpha1.PlaybookSpec) {
					for i := range spec.Evidence {
						spec.Evidence[i].Requirement = ptr.To(configv1alpha1.EvidenceOptional)
					}
				})
			}, reason: configv1alpha1.ReasonTypeNotProduced,
			message: `no Collector produces ` + sdkevidence.TypeSBOM + ` for the evidence "sbom"`},
		{name: "optional evidence that no findings producer consumes has no producer", change: func(t *testing.T, c client.Client) {
			changeUnitPlaybook(t, c, func(spec *configv1alpha1.PlaybookSpec) {
				spec.Evidence = append(spec.Evidence, configv1alpha1.PlaybookEvidence{
					Name: extra, Type: extraType, Requirement: ptr.To(configv1alpha1.EvidenceOptional),
				})
			})
		}, reason: configv1alpha1.ReasonValid},
		{name: "a pinned producer fails", change: func(t *testing.T, c client.Client) {
			install(t, c, secondScanner)
			failing(t, c, secondScanner)
			changeUnitPlaybook(t, c, func(spec *configv1alpha1.PlaybookSpec) {
				spec.Evidence[0].Collectors = []string{scanner, secondScanner}
			})
		}, reason: configv1alpha1.ReasonValid},
		{name: "a pinned producer has recorded no capabilities", change: func(t *testing.T, c client.Client) {
			install(t, c, secondScanner)
			unrecorded(t, c, secondScanner)
			changeUnitPlaybook(t, c, func(spec *configv1alpha1.PlaybookSpec) {
				spec.Evidence[0].Collectors = []string{scanner, secondScanner}
			})
		}, reason: configv1alpha1.ReasonTypeNotProduced,
			message: `"scanner-b", pinned for the evidence "contents", has recorded no capabilities yet`},
		{name: "the pinned producer of the subjects fails", change: func(t *testing.T, c client.Client) {
			failing(t, c, workloadsCollector)
			changeUnitPlaybook(t, c, func(spec *configv1alpha1.PlaybookSpec) {
				spec.Subjects.Collectors = []string{workloadsCollector}
			})
		}, reason: configv1alpha1.ReasonValid},
		{name: "the pinned producer of the subjects doesn't declare their type", change: func(t *testing.T, c client.Client) {
			changeUnitPlaybook(t, c, func(spec *configv1alpha1.PlaybookSpec) {
				spec.Subjects.Collectors = []string{scanner}
			})
		}, reason: configv1alpha1.ReasonTypeNotProduced,
			message: `"scanner", pinned for the subjects, produces no ` + sdkevidence.TypePresence},
		{name: "a pinned producer of the findings doesn't exist", change: func(t *testing.T, c client.Client) {
			changeUnitPlaybook(t, c, func(spec *configv1alpha1.PlaybookSpec) {
				spec.Findings.Collectors = []string{vulnerabilitiesCollector, nowhere}
			})
		}, reason: configv1alpha1.ReasonCollectorMissing, message: `"` + nowhere + `"`},
		// Several playbooks run at once (decision 0043). This one is older, by its name in the same second.
		{name: "an older playbook takes the same subjects", change: func(t *testing.T, c client.Client) {
			addPlaybook(t, c, "base-cves", func(*configv1alpha1.PlaybookSpec) {})
		}, reason: configv1alpha1.ReasonValid},
		{name: "the match selects clusters with an operator that doesn't exist", change: func(t *testing.T, c client.Client) {
			changeUnitPlaybook(t, c, func(spec *configv1alpha1.PlaybookSpec) {
				spec.Match = &configv1alpha1.PlaybookMatch{Clusters: &metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{{Key: stage, Operator: "Bogus", Values: []string{production}}},
				}}
			})
		}, reason: configv1alpha1.ReasonInvalid, message: `spec.match.clusters: "Bogus" is not a valid label selector operator`},
		{name: "the match selects namespaces by a key that is no label key", change: func(t *testing.T, c client.Client) {
			changeUnitPlaybook(t, c, func(spec *configv1alpha1.PlaybookSpec) {
				spec.Match = &configv1alpha1.PlaybookMatch{
					Namespaces: &metav1.LabelSelector{MatchLabels: map[string]string{"not a label key": "x"}},
				}
			})
		}, reason: configv1alpha1.ReasonInvalid, message: `spec.match.namespaces: `},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newAssessor(t, interceptor.Funcs{}, nil)
			if tc.change != nil {
				tc.change(t, f.client)
			}

			ready, err := hub.ReadyOf(t.Context(), f.client, playbookName)

			require.NoError(t, err)
			require.Equal(t, tc.reason, ready.Reason, ready.Message)
			require.Contains(t, ready.Message, tc.message)
		})
	}
}

// A read of the Collectors that fails says nothing of the producers: never that a type lacks one, nor that no findings
// producer takes part. The check returns it.
func TestTheCheckOfAPlaybookReturnsAFailedReadOfTheCollectors(t *testing.T) {
	errRead := errors.New("the cache is not synced yet")
	f := newAssessor(t, interceptor.Funcs{
		List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			if _, ok := list.(*configv1alpha1.CollectorList); ok {
				return errRead
			}
			return c.List(ctx, list, opts...)
		},
	}, nil)

	_, err := hub.ReadyOf(t.Context(), f.client, playbookName)

	require.ErrorIs(t, err, errRead)
}
