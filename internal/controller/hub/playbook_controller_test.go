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
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	eventsv1 "k8s.io/api/events/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/controller/hub"
	"github.com/bedag/vexplain/internal/settings"
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

// reachRule returns an exposure rule that reads the evidence of extraType as extra, which makes that evidence about
// workloads: the collectors of each cluster produce it.
func reachRule(name string) *configv1alpha1.Rule {
	return &configv1alpha1.Rule{ObjectMeta: metav1.ObjectMeta{Name: name}, Spec: configv1alpha1.RuleSpec{
		Inputs:    []configv1alpha1.RuleInput{{Name: extra, Type: extraType}},
		Condition: celTrue, Outcome: &configv1alpha1.RuleOutcome{Exposure: ptr.To(configv1alpha1.SSVCExposureSmall)},
	}}
}

// extraReach returns a collector of another cluster, as its Spoke lists it, that streams evidence of extraType.
func extraReach() configv1alpha1.SpokeCollector {
	return configv1alpha1.SpokeCollector{Name: "extra-reach", Capabilities: &configv1alpha1.CollectorCapabilities{
		Roles: []configv1alpha1.CollectorRole{configv1alpha1.CollectorRoleSpoke}, Watch: configv1alpha1.CollectorWatchNotSupported,
		Produces: []configv1alpha1.ProducedType{{Type: extraType, Scope: configv1alpha1.EvidenceScopeHub}},
	}}
}

// deleteSpokeAfterwards deletes the Spoke of the cluster after the spec.
func deleteSpokeAfterwards(cluster string) {
	DeferCleanup(func() {
		Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, &configv1alpha1.Spoke{ObjectMeta: metav1.ObjectMeta{Name: cluster}}))).
			To(Succeed())
	})
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
				client.MatchingFields{regardingName: name})).To(Succeed())
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
		// The finalizer removes the evidence before it releases the Collector, so the Collector may still be there.
		Eventually(func() error {
			return k8sClient.Get(ctx, client.ObjectKey{Name: scanner}, &configv1alpha1.Collector{})
		}, reaction, poll).Should(Satisfy(apierrors.IsNotFound))
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
		createRule(holdRule("needs-contents", configv1alpha1.RuleInput{Name: contents, Type: imagecontents.Type}))
		createPlaybook("vm-cves-inputs", vmPlaybook([]configv1alpha1.PlaybookEvidence{{Name: contents, Type: imagecontents.Type}},
			"needs-contents", "needs-sbom", "needs-other-contents"))

		ready := expectReady("vm-cves-inputs", metav1.ConditionFalse, configv1alpha1.ReasonInputMissing)

		Expect(ready.Message).To(ContainSubstring(`"needs-sbom"`))
		Expect(ready.Message).To(ContainSubstring(`"sbom"`))
		Expect(ready.Message).To(ContainSubstring(`"needs-other-contents"`), "an input of another type is missing too")
		Expect(ready.Message).NotTo(ContainSubstring(`"needs-contents"`))
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
			Roles:    []configv1alpha1.CollectorRole{configv1alpha1.CollectorRoleHub},
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

	// Evidence that only exposure rules read is about workloads, and comes from the collectors of each workload's own
	// cluster, which its Spoke lists (design of remote spokes 5.7).
	It("checks a playbook again when the collectors of a Spoke change, which produce evidence about workloads", func() {
		const name, rule, cluster = "vm-cves-spoke", "extra-exposure", "cluster-c"
		createRule(reachRule(rule))
		createPlaybook(name, vmPlaybook([]configv1alpha1.PlaybookEvidence{{Name: extra, Type: extraType}}, rule))
		expectReady(name, metav1.ConditionFalse, configv1alpha1.ReasonTypeNotProduced)

		By("recording a Spoke whose collector produces the evidence")
		addSpoke(GinkgoT(), k8sClient, cluster, extraReach())
		deleteSpokeAfterwards(cluster)
		expectReady(name, metav1.ConditionTrue, configv1alpha1.ReasonValid)

		By("taking the collector off the Spoke")
		listOn(GinkgoT(), k8sClient, cluster)
		expectReady(name, metav1.ConditionFalse, configv1alpha1.ReasonTypeNotProduced)
	})

	// A check reads the playbook from the manager's cache, which can still lack the controller's last status write. When
	// the inputs changed back meanwhile, the check finds there the status that it would write, and writes nothing, so the
	// status written last no longer matches the inputs. A status written over here stands for that write, which a spec
	// can't hold back from the cache.
	It("checks a playbook again when its status is written, puts the status right, and then writes nothing more", func() {
		const name = "vm-cves-written-over"
		createPlaybook(name, vmPlaybook(nil, nowhere))
		expectReady(name, metav1.ConditionFalse, configv1alpha1.ReasonRuleMissing)

		By("writing over the status a Ready condition that the playbook's inputs don't give")
		Eventually(func(g Gomega) {
			var playbook configv1alpha1.Playbook
			g.Expect(k8sClient.Get(ctx, client.ObjectKey{Name: name}, &playbook)).To(Succeed())
			meta.SetStatusCondition(&playbook.Status.Conditions, metav1.Condition{Type: configv1alpha1.ConditionReady,
				Status: metav1.ConditionTrue, Reason: configv1alpha1.ReasonValid, Message: "Written over."})
			g.Expect(k8sClient.Status().Update(ctx, &playbook)).To(Succeed())
		}, reaction, poll).Should(Succeed())

		expectReady(name, metav1.ConditionFalse, configv1alpha1.ReasonRuleMissing)
		resourceVersion := func(g Gomega) string {
			var playbook configv1alpha1.Playbook
			g.Expect(k8sClient.Get(ctx, client.ObjectKey{Name: name}, &playbook)).To(Succeed())
			return playbook.ResourceVersion
		}
		Consistently(resourceVersion, quiet, poll).Should(Equal(resourceVersion(Default)),
			"the check that the controller's own write starts finds nothing to change")
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
		{name: "a condition of the agent doesn't compile", change: func(t *testing.T, c client.Client) {
			changeUnitPlaybook(t, c, func(spec *configv1alpha1.PlaybookSpec) {
				spec.Agent = &configv1alpha1.PlaybookAgent{MatchConditions: []configv1alpha1.MatchCondition{
					{Name: "fine", Expression: "1 == 1"}, {Name: "unknown", Expression: "sbom.data.x == 1"},
				}}
			})
		}, reason: configv1alpha1.ReasonInvalid, message: `spec.agent.matchConditions "unknown"`},
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

// exposureEntry returns the default playbook's evidence of the exposure of workloads.
func exposureEntry(spec *configv1alpha1.PlaybookSpec) *configv1alpha1.PlaybookEvidence {
	return &spec.Evidence[slices.IndexFunc(spec.Evidence, func(e configv1alpha1.PlaybookEvidence) bool { return e.Name == exposureName })]
}

// requireExposure has the default playbook require the exposure of workloads, which it takes as optional.
func requireExposure(spec *configv1alpha1.PlaybookSpec) {
	exposureEntry(spec).Requirement = ptr.To(configv1alpha1.EvidenceRequired)
}

// pinNetworkReach has the default playbook take the exposure of workloads from the collectors named network-reach only.
func pinNetworkReach(spec *configv1alpha1.PlaybookSpec) {
	exposureEntry(spec).Collectors = []string{networkReach}
}

// A workload's evidence comes from the collectors of its own cluster (design of remote spokes 5.7): a playbook that
// requires exposure is Ready once a Spoke lists a producer of it, while the scanner, whose evidence is about images,
// runs on the hub. A pin matches the collector of its name in any cluster.
func TestAPlaybookIsReadyWhenASpokeProducesItsWorkloadType(t *testing.T) {
	f := newAssessor(t, interceptor.Funcs{}, nil)
	changeUnitPlaybook(t, f.client, requireExposure)
	ready, err := hub.ReadyOf(t.Context(), f.client, playbookName)
	require.NoError(t, err)
	require.Equal(t, configv1alpha1.ReasonTypeNotProduced, ready.Reason, "no cluster produces exposure yet")

	addSpoke(t, f.client, otherCluster, listed(networkReach))

	ready, err = hub.ReadyOf(t.Context(), f.client, playbookName)
	require.NoError(t, err)
	require.Equal(t, configv1alpha1.ReasonValid, ready.Reason, ready.Message)

	changeUnitPlaybook(t, f.client, pinNetworkReach)
	ready, err = hub.ReadyOf(t.Context(), f.client, playbookName)
	require.NoError(t, err)
	require.Equal(t, configv1alpha1.ReasonValid, ready.Reason, ready.Message)
}

// An image's evidence comes from the hub's own collectors, since the hub scans every image itself (decision 0066): a
// scanner that runs only on a spoke leaves the contents and the SBOM without a producer, while the spoke's
// network-reach gives the playbook the exposure that it requires.
func TestAPlaybookIsNotReadyWhenOnlyASpokeProducesAnImageType(t *testing.T) {
	f := newAssessor(t, interceptor.Funcs{}, nil)
	changeUnitPlaybook(t, f.client, requireExposure)
	require.NoError(t, f.client.Delete(t.Context(), collectorNamed(scanner)))
	addSpoke(t, f.client, otherCluster, listed(scanner), listed(networkReach))

	ready, err := hub.ReadyOf(t.Context(), f.client, playbookName)

	require.NoError(t, err)
	require.Equal(t, configv1alpha1.ReasonTypeNotProduced, ready.Reason, ready.Message)
	require.Contains(t, ready.Message, `no Collector produces `+imagecontents.Type+` for the evidence "contents"`)
	require.Contains(t, ready.Message, `no Collector produces `+sdkevidence.TypeSBOM+` for the evidence "sbom"`)
	require.NotContains(t, ready.Message, sdkevidence.TypeExposure)
}

// A playbook's subjects are presence, which each cluster's own collectors stream, as they do a workload's evidence: a
// hub that runs no presence of its own judges the copies of the spokes' (design of remote spokes 5.1 and 5.5). Its
// playbook is Ready once a Spoke lists a producer of presence, while the scanner and the matcher run on the hub, and
// isn't while no cluster has one. A pin of the subjects matches the collector of its name in any cluster.
func TestAPlaybookIsReadyWhenOnlyASpokeProducesItsSubjects(t *testing.T) {
	f := newAssessor(t, interceptor.Funcs{}, nil)
	require.NoError(t, f.client.Delete(t.Context(), collectorNamed(workloadsCollector)))
	addSpoke(t, f.client, otherCluster, listed(networkReach))
	ready, err := hub.ReadyOf(t.Context(), f.client, playbookName)
	require.NoError(t, err)
	require.Equal(t, configv1alpha1.ReasonTypeNotProduced, ready.Reason, ready.Message)
	require.Contains(t, ready.Message, `no Collector produces `+sdkevidence.TypePresence+` for the subjects`)

	addSpoke(t, f.client, "cluster-c", listed(workloadsCollector))

	ready, err = hub.ReadyOf(t.Context(), f.client, playbookName)
	require.NoError(t, err)
	require.Equal(t, configv1alpha1.ReasonValid, ready.Reason, ready.Message)

	changeUnitPlaybook(t, f.client, func(spec *configv1alpha1.PlaybookSpec) {
		spec.Subjects.Collectors = []string{workloadsCollector}
	})
	ready, err = hub.ReadyOf(t.Context(), f.client, playbookName)
	require.NoError(t, err)
	require.Equal(t, configv1alpha1.ReasonValid, ready.Reason, ready.Message)
}

// A playbook judges the images that several clusters run when its match selects one of them, by that cluster's own
// labels (design of remote spokes 5.8). A cluster that the labels don't name has none.
func TestJudgesInMatchesWhenOneClusterMatches(t *testing.T) {
	const unlabelled = "cluster-c"
	strict := unitPlaybook(t)
	prodOnly(&strict.Spec)
	labels := map[string]map[string]string{localCluster: {stage: development}, otherCluster: {stage: production}}

	require.True(t, hub.JudgesIn(strict, labels, []string{localCluster, otherCluster}))
	require.False(t, hub.JudgesIn(strict, labels, []string{localCluster, unlabelled}), "a cluster without labels")
	require.False(t, hub.JudgesIn(strict, labels, nil), "an image that runs nowhere")
	require.True(t, hub.JudgesIn(unitPlaybook(t), labels, []string{unlabelled}),
		"a playbook without a cluster selector judges in every cluster")
}

// A cluster that no OperatorConfig or Spoke names, such as one whose copies outlive its Spoke, counts for a playbook
// without a cluster selector only. So the judging and the cases' clusters agree on it, also for a selector that a
// cluster without labels would meet.
func TestAClusterThatTheHubDoesntKnowCountsOnlyWithoutAClusterSelector(t *testing.T) {
	const unknown = "cluster-c"
	notProd := unitPlaybook(t)
	notProd.Spec.Match = &configv1alpha1.PlaybookMatch{Clusters: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
		{Key: stage, Operator: metav1.LabelSelectorOpNotIn, Values: []string{production}}}}}
	labels := map[string]map[string]string{localCluster: {stage: development}, otherCluster: {}}

	require.True(t, hub.JudgesIn(notProd, labels, []string{otherCluster}), "a known cluster without labels")
	require.False(t, hub.JudgesIn(notProd, labels, []string{unknown}))
	require.Equal(t, []string{localCluster, otherCluster}, hub.MatchingClusters(notProd, labels))
	require.True(t, hub.JudgesIn(unitPlaybook(t), labels, []string{unknown}), "a playbook without a cluster selector")
}

// A playbook's cases count the workloads of the clusters that its match selects, among those that the hub knows: its own
// and the Spokes'. Without a cluster selector they count every cluster's, and with one that selects none, none.
func TestACasesClustersAreThoseThatItsPlaybookMatches(t *testing.T) {
	const thirdCluster = "cluster-c"
	playbook := unitPlaybook(t)
	labels := map[string]map[string]string{localCluster: {stage: development}, otherCluster: {stage: production},
		thirdCluster: {stage: production}}

	require.Nil(t, hub.MatchingClusters(playbook, labels))

	prodOnly(&playbook.Spec)
	require.Equal(t, []string{otherCluster, thirdCluster}, hub.MatchingClusters(playbook, labels))

	playbook.Spec.Match.Clusters.MatchLabels[stage] = "test"
	matching := hub.MatchingClusters(playbook, labels)
	require.NotNil(t, matching, "no cluster is not every cluster")
	require.Empty(t, matching)
}

// A workload's producers are kept per cluster (design of remote spokes 5.7): the local Collectors are those of the
// hub's own cluster, a Spoke lists those of its cluster, with the maxAge that it mirrors, and a source counts for every
// cluster, under "". A spoke's collector that declares exposure with the scope Spoke counts for nothing, and an image's
// evidence comes from the local Collectors only. A pin matches the collector of its name in each cluster, and one that
// a cluster lacks makes the piece's input missing there.
func TestTheExposureOfAPlaybookKeepsItsProducersPerCluster(t *testing.T) {
	f := newAssessor(t, interceptor.Funcs{}, nil)
	require.NoError(t, f.client.Create(t.Context(), &configv1alpha1.OperatorConfig{
		ObjectMeta: metav1.ObjectMeta{Name: settings.ConfigName},
		Spec:       configv1alpha1.OperatorConfigSpec{ClusterName: ptr.To(localCluster)},
	}))
	install(t, f.client, networkReach)
	install(t, f.client, dmzSource)
	changeUnitPlaybook(t, f.client, func(spec *configv1alpha1.PlaybookSpec) {
		spec.Evidence = append(spec.Evidence, configv1alpha1.PlaybookEvidence{Name: dmzName, Type: dmzType,
			Requirement: ptr.To(configv1alpha1.EvidenceOptional)})
	})
	hourly := listed(networkReach)
	hourly.Capabilities.Produces[0].MaxAgeSeconds = ptr.To(int64(time.Hour / time.Second))
	addSpoke(t, f.client, otherCluster, hourly, listed(scanner))
	const thirdCluster = "cluster-c"
	addSpoke(t, f.client, thirdCluster, listed(spokeReach))

	pe, err := hub.PlaybookExposureOf(t.Context(), f.client, playbookName)

	require.NoError(t, err)
	exposureProducers := map[string][]string{localCluster: {networkReach}, otherCluster: {networkReach}}
	require.Equal(t, map[string]map[string][]string{
		contents: {localCluster: {scanner}}, sbomName: {localCluster: {scanner}},
		exposureName: exposureProducers, dmzName: {"": {dmzSource}},
	}, pe.Producers)
	require.Equal(t, time.Hour, pe.MaxAges[[3]string{otherCluster, networkReach, sdkevidence.TypeExposure}])
	require.Zero(t, pe.MaxAges[[3]string{localCluster, networkReach, sdkevidence.TypeExposure}])
	require.Empty(t, pe.Absent[exposureName])

	changeUnitPlaybook(t, f.client, pinNetworkReach)
	pe, err = hub.PlaybookExposureOf(t.Context(), f.client, playbookName)

	require.NoError(t, err)
	require.Equal(t, exposureProducers, pe.Producers[exposureName])
	require.Equal(t, map[string]bool{thirdCluster: true}, pe.Absent[exposureName])
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

// A playbook's pipeline holds its finding rules and its exposure rules apart, by what each Rule concludes, also while
// one isn't Ready: the assessor evaluates the findings with the first, and the cases the workloads with the second. A
// rule that is missing says nothing of its kind, so it is in both. Either kind keeps the playbook from being Ready
// while it is missing or not Ready. The evidence that only the exposure rules read is about workloads, never about a
// manifest; evidence that a finding rule reads, or that a findings producer consumes, is about the manifest too.
func TestAPlaybookKeepsItsFindingRulesAndItsExposureRulesApart(t *testing.T) {
	findingRules := []string{knownExploitedRule, guardRule, removedRule, loadCheckRule, fixAvailableRule}
	exposureRules := []string{exposedOutsideCluster, reachableInCluster, ownNamespaceOnly}
	for _, tc := range []struct {
		name                        string
		change                      func(t *testing.T, c client.Client)
		reason                      string
		findingSteps, exposureSteps []string
		workloadEvidence            []string
	}{
		{name: "the install", reason: configv1alpha1.ReasonValid,
			findingSteps: findingRules, exposureSteps: exposureRules, workloadEvidence: []string{exposureName}},
		{name: "an exposure rule isn't Ready", change: func(t *testing.T, c client.Client) {
			changeUnitRule(t, c, exposedOutsideCluster, func(spec *configv1alpha1.RuleSpec) { spec.Condition = brokenCondition })
		}, reason: configv1alpha1.ReasonRuleNotReady,
			findingSteps: findingRules, exposureSteps: exposureRules, workloadEvidence: []string{exposureName}},
		{name: "an exposure rule is missing", change: func(t *testing.T, c client.Client) {
			require.NoError(t, c.Delete(t.Context(), &configv1alpha1.Rule{ObjectMeta: metav1.ObjectMeta{Name: ownNamespaceOnly}}))
		}, reason: configv1alpha1.ReasonRuleMissing,
			findingSteps: append(slices.Clone(findingRules), ownNamespaceOnly), exposureSteps: exposureRules,
			workloadEvidence: []string{exposureName}},
		{name: "a finding rule reads the exposure too", change: func(t *testing.T, c client.Client) {
			changeUnitRule(t, c, knownExploitedRule, func(spec *configv1alpha1.RuleSpec) {
				spec.Inputs = append(spec.Inputs, configv1alpha1.RuleInput{Name: exposureName, Type: sdkevidence.TypeExposure})
			})
		}, reason: configv1alpha1.ReasonValid, findingSteps: findingRules, exposureSteps: exposureRules},
		{name: "the findings producer consumes the exposure", change: func(t *testing.T, c client.Client) {
			install(t, c, networkReach)
			var collector configv1alpha1.Collector
			require.NoError(t, c.Get(t.Context(), client.ObjectKey{Name: vulnerabilitiesCollector}, &collector))
			match := &collector.Status.Capabilities.Operations[0]
			match.Consumes = append(match.Consumes, sdkevidence.TypeExposure)
			require.NoError(t, c.Status().Update(t.Context(), &collector))
		}, reason: configv1alpha1.ReasonValid, findingSteps: findingRules, exposureSteps: exposureRules},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newAssessor(t, interceptor.Funcs{}, nil)
			if tc.change != nil {
				tc.change(t, f.client)
			}

			ready, err := hub.ReadyOf(t.Context(), f.client, playbookName)
			require.NoError(t, err)
			findingSteps, exposureSteps, workloadEvidence, err := hub.PipelineOf(t.Context(), f.client, playbookName)
			require.NoError(t, err)

			require.Equal(t, tc.reason, ready.Reason, ready.Message)
			require.Equal(t, tc.findingSteps, findingSteps)
			require.Equal(t, tc.exposureSteps, exposureSteps)
			require.Equal(t, tc.workloadEvidence, workloadEvidence)
		})
	}
}
