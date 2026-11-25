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
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	eventsv1 "k8s.io/api/events/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	triagev1alpha1 "github.com/bedag/vexplain/api/triage/v1alpha1"
	"github.com/bedag/vexplain/internal/agent/cases"
	"github.com/bedag/vexplain/internal/evidence"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/settings"
	"github.com/bedag/vexplain/internal/urgency"
	sdkevidence "github.com/bedag/vexplain/sdk/evidence"
	subjects "github.com/bedag/vexplain/sdk/subject"
	"github.com/bedag/vexplain/sdk/workloads"
)

// regardingName is the field that events are selected by, for the object they concern.
const regardingName = "regarding.name"

// investigationDebounce is the pause of the investigation controller after a change of what investigations read, short
// in the suite so that a spec sees it act within its reaction time.
const investigationDebounce = 200 * time.Millisecond

// anotherInvestigation names an investigation that a verdict was judged for, beside the spec's own, and the uids that
// objects of these names, and an earlier object of the spec's own name, have.
const (
	anotherInvestigation = "another"
	anotherUID           = "7b0c1d2e-3f40-4a51-8b62-c73d84e95fa6"
	earlierUID           = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
)

// referenceTo returns the reference to the investigation of the key, with its uid as the API server set it.
func referenceTo(key types.NamespacedName) *triagev1alpha1.InvestigationReference {
	GinkgoHelper()
	obj := &triagev1alpha1.Investigation{}
	Expect(k8sClient.Get(ctx, key, obj)).To(Succeed())
	return &triagev1alpha1.InvestigationReference{Namespace: key.Namespace, Name: key.Name, UID: obj.UID}
}

// earlierObject returns the reference to an object of the key's namespace and name that is gone: another uid.
func earlierObject(key types.NamespacedName) *triagev1alpha1.InvestigationReference {
	return &triagev1alpha1.InvestigationReference{Namespace: key.Namespace, Name: key.Name, UID: earlierUID}
}

// createDisabled creates an investigation that is disabled, so that it judges nothing while the spec records the
// verdicts that are judged for it: only the API server gives it a uid. enable switches it on.
func createDisabled(namespace, name, playbook string, maxCases int32, change func(*triagev1alpha1.InvestigationSpec)) types.NamespacedName {
	GinkgoHelper()
	return createInvestigation(namespace, name, playbook, maxCases, func(s *triagev1alpha1.InvestigationSpec) {
		if change != nil {
			change(s)
		}
		s.State = ptr.To(triagev1alpha1.InvestigationStateDisabled)
	})
}

// enable switches on the investigation that createDisabled made.
func enable(key types.NamespacedName) {
	GinkgoHelper()
	Eventually(func(g Gomega) {
		obj := investigationOf(g, key)
		obj.Spec.State = ptr.To(triagev1alpha1.InvestigationStateEnabled)
		g.Expect(k8sClient.Update(ctx, obj)).To(Succeed())
	}, reaction, poll).Should(Succeed())
}

// criticalVector is a CVSS vector that reads as automatable, with a high human impact.
const criticalVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

// recordingQueue is the agent's queue of the suite: it records the cases that investigations queue, and reports
// nothing pending, as an agent that is idle.
type recordingQueue struct {
	mu    sync.Mutex
	added map[types.NamespacedName][]string
	// busy says how many cases of an investigation wait for the agent, as queued, or are with it.
	busy map[types.NamespacedName]int
	// inflight holds the cases that wait or are with the agent, whoever queued them, until finish.
	inflight map[string]bool
	// after holds the latest JudgedAfter that a request of each case asked for, as the queue keeps it.
	after map[string]time.Time
	// last holds each case as it was last handed over, from which the queue writes where it runs.
	last map[string]cases.Case
}

// finish says that the agent is done with the cases, so that the queue takes them again.
func (q *recordingQueue) finish(names ...string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for _, n := range names {
		delete(q.inflight, n)
	}
}

// keepBusy makes the queue report that the investigation has cases waiting, and stop reporting it after the spec.
func (q *recordingQueue) keepBusy(key types.NamespacedName, n int) {
	set := func(n int) {
		q.mu.Lock()
		defer q.mu.Unlock()
		if q.busy == nil {
			q.busy = map[types.NamespacedName]int{}
		}
		q.busy[key] = n
	}
	set(n)
	DeferCleanup(set, 0)
}

func (q *recordingQueue) Add(c cases.Case, r cases.Request) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	name := cases.Name(c.VulnerabilityID, c.ManifestDigest)
	if q.inflight == nil {
		q.inflight, q.added, q.after = map[string]bool{}, map[types.NamespacedName][]string{}, map[string]time.Time{}
		q.last = map[string]cases.Case{}
	}
	q.last[name] = c
	if r.JudgedAfter.After(q.after[name]) {
		q.after[name] = r.JudgedAfter
	}
	if !slices.Contains(q.added[r.Investigation], name) {
		q.added[r.Investigation] = append(q.added[r.Investigation], name)
	}
	if q.inflight[name] {
		return false
	}
	q.inflight[name] = true
	return true
}

// Keep forgets nothing: the suite's specs look at what was queued, whatever an investigation wants later.
func (q *recordingQueue) Keep(types.NamespacedName, []string) {}

func (q *recordingQueue) Pending(key types.NamespacedName, _ types.UID) (int, int) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.busy[key], 0
}

// of returns a function that gives the names of the cases that the investigation queued, sorted.
func (q *recordingQueue) of(key types.NamespacedName) func() []string {
	return func() []string {
		q.mu.Lock()
		defer q.mu.Unlock()
		return slices.Sorted(slices.Values(q.added[key]))
	}
}

// runsIn returns a function that gives where the case runs as the queue would write it into its Assessment, from the
// case as it was last handed over, or nil before it was.
func (q *recordingQueue) runsIn(name string) func() *triagev1alpha1.QueueRunsIn {
	return func() *triagev1alpha1.QueueRunsIn {
		q.mu.Lock()
		defer q.mu.Unlock()
		c, ok := q.last[name]
		if !ok {
			return nil
		}
		return cases.RunsInOf(c)
	}
}

// judgedAfter returns a function that gives the latest JudgedAfter that a request of the case asked for.
func (q *recordingQueue) judgedAfter(name string) func() time.Time {
	return func() time.Time {
		q.mu.Lock()
		defer q.mu.Unlock()
		return q.after[name]
	}
}

// investigatedCount numbers the playbooks of the investigation specs.
var investigatedCount int

// investigatedPlaybook creates a playbook for virtual machines whose sheets the specs write, so that the assessor
// never writes them, and returns its name. Its agent section is agent; nil leaves it out.
func investigatedPlaybook(agent *configv1alpha1.PlaybookAgent) string {
	GinkgoHelper()
	investigatedCount++
	name := fmt.Sprintf("investigated-%03d", investigatedCount)
	spec := vmPlaybook(nil, knownExploitedRule)
	spec.Agent = agent
	createPlaybook(name, spec)
	return name
}

// openFinding returns an open finding of the vulnerability in the package, as a sheet holds it.
func openFinding(id, pkg string) inventoryv1alpha1.Finding {
	return inventoryv1alpha1.Finding{
		VulnerabilityID: id,
		Package:         inventoryv1alpha1.PackageReference{ID: pkg + "-id", Name: pkg, Version: ptr.To("1.0"), Type: "apk"},
		Status:          inventoryv1alpha1.VEXStatusUnderInvestigation,
		Severity:        inventoryv1alpha1.SeverityHigh,
		FixState:        inventoryv1alpha1.FixStateNotFixed,
		KnownExploited:  inventoryv1alpha1.KnownExploitedNotListed,
		CVSS:            []inventoryv1alpha1.CVSS{{Version: ptr.To("3.1"), Vector: ptr.To(criticalVector)}},
	}
}

// exploitedFinding is openFinding of a vulnerability that the catalog of known exploited vulnerabilities lists.
func exploitedFinding(id, pkg string) inventoryv1alpha1.Finding {
	f := openFinding(id, pkg)
	f.KnownExploited = inventoryv1alpha1.KnownExploitedListed
	return f
}

// writeSheet writes the sheet of the manifest under the playbook, with the findings, as the assessor would, and deletes
// it after the spec.
func writeSheet(manifest, playbook string, findings ...inventoryv1alpha1.Finding) {
	GinkgoHelper()
	sheets := inventory.NewCRDVerdictsStore(k8sClient, cluster)
	Expect(sheets.Put(ctx, manifest, playbook, inventoryv1alpha1.ImageVerdictsStatus{
		Playbook: ptr.To(playbook), FindingsVersion: ptr.To(v1), Findings: findings,
	})).To(Succeed())
	DeferCleanup(func() { Expect(sheets.Delete(ctx, manifest, playbook)).To(Succeed()) })
}

// inNamespace is a namespace of otherCluster that runs an image, with its workloads by exposure.
func inNamespace(name string, byExposure map[inventoryv1alpha1.SSVCExposure]int32) inventory.NamespaceObservation {
	return inventory.NamespaceObservation{
		Name:       name,
		Owner:      []inventoryv1alpha1.OwnerValue{{Source: inventoryv1alpha1.OwnerSourceNamespaceLabel, Key: "team", Value: ptr.To(name)}},
		ByExposure: byExposure,
	}
}

// runsInOtherCluster reports, as the spoke of otherCluster does, that an image of one platform, whose digest is its
// manifest's, runs in the namespaces, and records its manifest in its facts, as a scan does. It forgets the image after
// the spec.
func runsInOtherCluster(manifest string, namespaces ...inventory.NamespaceObservation) {
	GinkgoHelper()
	store := inventory.NewCRDStore(k8sClient, nil, cluster)
	var refs []workloads.WorkloadRef
	for _, ns := range namespaces {
		for _, n := range ns.ByExposure {
			for i := range n {
				refs = append(refs, workloads.WorkloadRef{Kind: "Deployment", Namespace: ns.Name, Name: fmt.Sprintf("app-%d-%d", len(refs), i)})
			}
		}
	}
	Expect(store.Observe(ctx, manifest, inventory.Observation{
		Cluster: otherCluster, ClusterID: otherCluster + "-id", DigestKind: inventoryv1alpha1.DigestKindRepoDigest,
		Repositories: []string{repository}, Platforms: []string{linuxAMD64}, NamespaceCount: int32(len(namespaces)),
		Namespaces: namespaces, Exposure: inventoryv1alpha1.SSVCExposureOpen, Workloads: refs,
	})).To(Succeed())
	DeferCleanup(forget, GinkgoT(), store, manifest, otherCluster)
	setFacts(GinkgoT(), store, manifest, &inventoryv1alpha1.ImageFacts{
		Manifests: []inventoryv1alpha1.ManifestFact{{Platform: linuxAMD64, Digest: manifest}},
	})
}

// createInvestigation creates an Investigation of the playbook in the namespace, with the cap and the spec changed by
// change, and deletes it after the spec.
func createInvestigation(namespace, name, playbook string, maxCases int32, change func(*triagev1alpha1.InvestigationSpec)) types.NamespacedName {
	GinkgoHelper()
	obj := &triagev1alpha1.Investigation{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Spec: triagev1alpha1.InvestigationSpec{
			PlaybookRef: triagev1alpha1.PlaybookReference{Name: playbook},
			Agent:       triagev1alpha1.InvestigationAgent{MaxCases: maxCases},
		},
	}
	if change != nil {
		change(&obj.Spec)
	}
	Expect(k8sClient.Create(ctx, obj)).To(Succeed())
	DeferCleanup(func() { Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, obj))).To(Succeed()) })
	return client.ObjectKeyFromObject(obj)
}

// naming returns a change of an investigation's spec that names the vulnerabilities.
func naming(ids ...string) func(*triagev1alpha1.InvestigationSpec) {
	return func(s *triagev1alpha1.InvestigationSpec) { s.Vulnerabilities = ids }
}

// investigationOf reads the investigation of the key.
func investigationOf(g Gomega, key types.NamespacedName) *triagev1alpha1.Investigation {
	obj := &triagev1alpha1.Investigation{}
	g.Expect(k8sClient.Get(ctx, key, obj)).To(Succeed())
	return obj
}

// expectInvestigation waits until the investigation's Ready condition has the status and the reason, its status
// observes its generation, and check holds of it, and returns it.
func expectInvestigation(key types.NamespacedName, status metav1.ConditionStatus, reason string,
	check func(Gomega, *triagev1alpha1.Investigation)) *triagev1alpha1.Investigation {
	GinkgoHelper()
	var obj *triagev1alpha1.Investigation
	Eventually(func(g Gomega) {
		obj = investigationOf(g, key)
		ready := meta.FindStatusCondition(obj.Status.Conditions, configv1alpha1.ConditionReady)
		g.Expect(ready).NotTo(BeNil())
		g.Expect(ready.Status).To(Equal(status), ready.Message)
		g.Expect(ready.Reason).To(Equal(reason), ready.Message)
		g.Expect(obj.Status.ObservedGeneration).To(HaveValue(Equal(obj.Generation)))
		if check != nil {
			check(g, obj)
		}
	}, reaction, poll).Should(Succeed())
	return obj
}

// switchAgent sets the switch of the agent in the OperatorConfig, and switches it on again after the spec.
func switchAgent(state configv1alpha1.AgentState) {
	GinkgoHelper()
	set := func(state configv1alpha1.AgentState) error {
		cfg := &configv1alpha1.OperatorConfig{ObjectMeta: metav1.ObjectMeta{Name: settings.ConfigName}}
		_, err := controllerutil.CreateOrUpdate(ctx, k8sClient, cfg, func() error {
			cfg.Spec.Agent = &configv1alpha1.AgentSettings{State: ptr.To(state)}
			return nil
		})
		return err
	}
	Expect(set(state)).To(Succeed())
	DeferCleanup(func() { Expect(set(configv1alpha1.AgentStateEnabled)).To(Succeed()) })
}

// assessmentOf reads the Assessment of the case, or nil while there is none.
func assessmentOf(g Gomega, id, manifest string) *triagev1alpha1.Assessment {
	obj := &triagev1alpha1.Assessment{}
	err := k8sClient.Get(ctx, client.ObjectKey{Name: cases.Name(id, manifest)}, obj)
	if client.IgnoreNotFound(err) == nil && err != nil {
		return nil
	}
	g.Expect(err).NotTo(HaveOccurred())
	return obj
}

// deleteAssessmentsAfterwards deletes the Assessments of the vulnerability after the spec: they are cluster-scoped, and
// would be found by a later spec.
func deleteAssessmentsAfterwards(id string) {
	DeferCleanup(func() {
		Expect(k8sClient.DeleteAllOf(ctx, &triagev1alpha1.Assessment{},
			client.MatchingLabels{cases.VulnerabilityLabel: id})).To(Succeed())
	})
}

// recordVerdict records, as the agent does, an Affected verdict on the case of the finding, judged at the time, in the
// Assessment that the investigation created, or in one it creates when there is none.
func recordVerdict(id, manifest string, f inventoryv1alpha1.Finding, at time.Time) {
	GinkgoHelper()
	recordVerdictFor(id, manifest, f, at, nil)
}

// recordVerdictFor is recordVerdict of a judgement charged to the investigation to, or to none when it is nil.
func recordVerdictFor(id, manifest string, f inventoryv1alpha1.Finding, at time.Time, to *triagev1alpha1.InvestigationReference) {
	GinkgoHelper()
	name := cases.Name(id, manifest)
	Eventually(func(g Gomega) {
		a := assessmentOf(g, id, manifest)
		if a == nil {
			a = &triagev1alpha1.Assessment{
				ObjectMeta: metav1.ObjectMeta{Name: name, Labels: cases.Labels(id, manifest)},
				Spec: triagev1alpha1.AssessmentSpec{
					Subject: triagev1alpha1.AssessmentSubject{Type: triagev1alpha1.SubjectTypeContainerImage,
						ContainerImage: &triagev1alpha1.ContainerImageSubject{Digest: manifest}},
					VulnerabilityID: id,
				},
			}
			g.Expect(k8sClient.Create(ctx, a)).To(Succeed())
		}
		a.Status.Verdict = &triagev1alpha1.AssessmentVerdict{Status: triagev1alpha1.VEXStatusAffected, Summary: "It is affected."}
		a.Status.InputHash = ptr.To(cases.InputHash([]inventoryv1alpha1.Finding{f}, nil))
		a.Status.JudgedTime = ptr.To(metav1.NewTime(at))
		a.Status.InvestigationRef = to
		meta.SetStatusCondition(&a.Status.Conditions, metav1.Condition{Type: configv1alpha1.ConditionReady,
			Status: metav1.ConditionTrue, Reason: triagev1alpha1.ReasonJudged, ObservedGeneration: a.Generation})
		g.Expect(k8sClient.Status().Update(ctx, a)).To(Succeed())
	}, reaction, poll).Should(Succeed())
	agentQueue.finish(name)
}

// bump changes the spec of the investigation, so that it is reconciled at once.
func bump(key types.NamespacedName) {
	GinkgoHelper()
	Eventually(func(g Gomega) {
		obj := investigationOf(g, key)
		obj.Spec.Agent.MaxCases++
		g.Expect(k8sClient.Update(ctx, obj)).To(Succeed())
	}, reaction, poll).Should(Succeed())
}

// eventNotes returns the notes of the events of the reason of the investigation.
func eventNotes(g Gomega, key types.NamespacedName, reason string) []string {
	var list eventsv1.EventList
	g.Expect(k8sClient.List(ctx, &list, client.InNamespace(key.Namespace),
		client.MatchingFields{regardingName: key.Name})).To(Succeed())
	var notes []string
	for _, e := range list.Items {
		if e.Reason == reason {
			notes = append(notes, e.Note)
		}
	}
	return notes
}

// eventReasons returns the reasons of the events of the investigation.
func eventReasons(g Gomega, key types.NamespacedName) []string {
	var list eventsv1.EventList
	g.Expect(k8sClient.List(ctx, &list, client.InNamespace(key.Namespace),
		client.MatchingFields{regardingName: key.Name})).To(Succeed())
	reasons := make([]string, 0, len(list.Items))
	for _, e := range list.Items {
		reasons = append(reasons, e.Reason)
	}
	return reasons
}

// isUrgent says whether an outcome is one of the actions that the SOC chases.
func isUrgent(o configv1alpha1.SSVCOutcome) bool {
	return o == configv1alpha1.SSVCOutcomeImmediate || o == configv1alpha1.SSVCOutcomeOutOfCycle
}

// exposedPlaybook creates a playbook for virtual machines, as investigatedPlaybook does, which takes the exposure of
// workloads, optional, and whose pipeline ends with the exposure rules of the names, and returns its name.
func exposedPlaybook(rules ...string) string {
	GinkgoHelper()
	return exposedPlaybookFrom(nil, rules...)
}

// exposedPlaybookFrom creates a playbook as exposedPlaybook does, whose exposure comes from the Collectors of the names pins.
func exposedPlaybookFrom(pins []string, rules ...string) string {
	GinkgoHelper()
	investigatedCount++
	name := fmt.Sprintf("investigated-%03d", investigatedCount)
	spec := vmPlaybook([]configv1alpha1.PlaybookEvidence{{Name: exposureName, Type: sdkevidence.TypeExposure,
		Requirement: ptr.To(configv1alpha1.EvidenceOptional), Collectors: pins}}, append([]string{knownExploitedRule}, rules...)...)
	spec.Agent = &configv1alpha1.PlaybookAgent{}
	createPlaybook(name, spec)
	return name
}

// streamVersion is the version of the collectors whose streams deliver presence and exposure in the specs, and teamA
// the namespace of the workloads that they name.
const (
	streamVersion = "1.0.0"
	teamA         = "team-a"
)

// workloadIn returns the subject of the Deployment of the name in team-a of otherCluster.
func workloadIn(name string) string {
	return subjects.ForWorkload(subjects.Workload{Cluster: otherCluster, Namespace: teamA, Group: appsGroup,
		Kind: deployment, Name: name})
}

// streamPresence stores, as otherCluster's stream of workloads delivers it to the hub, the presence of the manifest,
// which the Deployments of the names in team-a run, and deletes it after the spec.
func streamPresence(manifest string, names ...string) {
	GinkgoHelper()
	data := sdkevidence.Presence{DigestKind: sdkevidence.DigestKindRepoDigest}
	for _, name := range names {
		data.Workloads = append(data.Workloads, sdkevidence.PresenceWorkload{Subject: workloadIn(name), APIGroup: appsGroup,
			Kind: deployment, Namespace: teamA, Name: name, UID: "uid-" + name})
	}
	e, err := sdkevidence.New(sdkevidence.TypePresence, subjects.Image(manifest), data,
		sdkevidence.WithSource("/clusters/"+otherCluster+"/collectors/"+workloadsCollector))
	Expect(err).NotTo(HaveOccurred())
	Expect(evidenceStore().Put(ctx, workloadsCollector, streamVersion, e, evidence.InCluster(otherCluster))).To(Succeed())
	DeferCleanup(func() {
		Expect(evidenceStore().Delete(ctx, evidence.Key{Subject: subjects.Image(manifest), Type: sdkevidence.TypePresence,
			Source: workloadsCollector, Cluster: otherCluster})).To(Succeed())
	})
}

// streamExposure stores, as otherCluster's stream of network-reach delivers it to the hub, the exposure of the
// Deployment of the name in team-a: reached from as far as reach says, and exposed outside the cluster through its
// node's network when exposed is set. It deletes it after the spec.
func streamExposure(name, reach string, exposed bool) {
	GinkgoHelper()
	streamExposureOf(networkReach, name, reach, exposed)
}

// streamExposureOf stores the exposure of the Deployment of the name in team-a as streamExposure does, as the stream of
// the Collector of the name collector delivered it.
func streamExposureOf(collector, name, reach string, exposed bool) {
	GinkgoHelper()
	data := sdkevidence.Exposure{InternalReach: reach}
	if exposed {
		data.External = sdkevidence.ExternalExposure{Exposed: true, Unchecked: []string{sdkevidence.UncheckedHostNetwork}}
	}
	e, err := sdkevidence.New(sdkevidence.TypeExposure, workloadIn(name), data,
		sdkevidence.WithSource("/clusters/"+otherCluster+"/collectors/"+collector))
	Expect(err).NotTo(HaveOccurred())
	Expect(evidenceStore().Put(ctx, collector, streamVersion, e, evidence.InCluster(otherCluster))).To(Succeed())
	DeferCleanup(func() {
		Expect(evidenceStore().Delete(ctx, evidence.Key{Subject: workloadIn(name), Type: sdkevidence.TypeExposure,
			Source: collector, Cluster: otherCluster})).To(Succeed())
	})
}

// expectUnknownExposure investigates the case of the vulnerability id with the playbook, whose image runs batch in team-a
// of otherCluster, which the Collector of the name from has streamed as reached from its namespace only, so that
// own-namespace-only would conclude Small, and waits until the case's exposure is Unknown.
func expectUnknownExposure(id, playbook, from string) {
	GinkgoHelper()
	manifest := newDigest()
	runsInOtherCluster(manifest, inNamespace("team-a", map[inventoryv1alpha1.SSVCExposure]int32{inventoryv1alpha1.SSVCExposureOpen: 1}))
	writeSheet(manifest, playbook, openFinding(id, "lib"))
	deleteAssessmentsAfterwards(id)
	streamPresence(manifest, "batch")
	streamExposureOf(from, "batch", "Namespace", false)

	key := createInvestigation(newNamespace(), "unknown", playbook, 10, naming(id))

	expectInvestigation(key, metav1.ConditionTrue, triagev1alpha1.ReasonJudged, func(g Gomega, obj *triagev1alpha1.Investigation) {
		g.Expect(obj.Status.Results).To(HaveLen(1))
		g.Expect(obj.Status.Results[0].Exposure).To(HaveValue(Equal(triagev1alpha1.SSVCExposureUnknown)))
	})
}

var _ = Describe("The investigation controller", func() {
	It("shows the impact without the agent: from the sheets and the inventory, with the owners of the first 5 namespaces", func() {
		const id = "CVE-2026-1001"
		switchAgent(configv1alpha1.AgentStateDisabled)
		playbook := investigatedPlaybook(&configv1alpha1.PlaybookAgent{})
		manifest := newDigest()
		// Four scores, as many as a sheet shows: rules couldn't evaluate the finding again, and conditions still read it.
		f := exploitedFinding(id, "lib")
		f.CVSS = append(f.CVSS, inventoryv1alpha1.CVSS{Version: ptr.To("2.0"), Vector: ptr.To("AV:N/AC:L/Au:N/C:C/I:C/A:C")},
			inventoryv1alpha1.CVSS{Version: ptr.To("3.0"), Vector: ptr.To(criticalVector)},
			inventoryv1alpha1.CVSS{Version: ptr.To("4.0"), Vector: ptr.To("CVSS:4.0/AV:N/AC:L/PR:N/UI:N/VC:H/VI:H/VA:H")})
		runsInOtherCluster(manifest,
			inNamespace("team-a", map[inventoryv1alpha1.SSVCExposure]int32{inventoryv1alpha1.SSVCExposureOpen: 2, inventoryv1alpha1.SSVCExposureSmall: 1}),
			inNamespace("team-b", map[inventoryv1alpha1.SSVCExposure]int32{inventoryv1alpha1.SSVCExposureSmall: 1}),
			inNamespace("team-c", map[inventoryv1alpha1.SSVCExposure]int32{inventoryv1alpha1.SSVCExposureSmall: 1}),
			inNamespace("team-d", map[inventoryv1alpha1.SSVCExposure]int32{inventoryv1alpha1.SSVCExposureSmall: 1}),
			inNamespace("team-e", map[inventoryv1alpha1.SSVCExposure]int32{inventoryv1alpha1.SSVCExposureSmall: 1}),
			inNamespace("team-f", map[inventoryv1alpha1.SSVCExposure]int32{inventoryv1alpha1.SSVCExposureSmall: 1}))
		writeSheet(manifest, playbook, f, openFinding("CVE-2026-1002", "lib"))
		deleteAssessmentsAfterwards(id)
		// The playbook has no exposure rules, and no presence of the image reached the hub: each of the 8 workloads that
		// the inventory counts is Unknown, which urgency counts as Open.
		urgent := int32(0)
		open := urgency.Decide(urgency.FromFinding(f, configv1alpha1.SSVCExposureOpen), nil)
		if isUrgent(open) {
			urgent = 8
		}

		key := createInvestigation(newNamespace(), "where", playbook, 10, naming(id))

		expectInvestigation(key, metav1.ConditionFalse, triagev1alpha1.ReasonAgentDisabled, func(g Gomega, obj *triagev1alpha1.Investigation) {
			g.Expect(meta.IsStatusConditionTrue(obj.Status.Conditions, configv1alpha1.ConditionStalled)).To(BeTrue())
			g.Expect(obj.Status.Impact).To(HaveValue(Equal(triagev1alpha1.InvestigationImpact{
				Subjects: ptr.To[int32](1), Resources: ptr.To[int32](8), Namespaces: ptr.To[int32](6), Clusters: ptr.To[int32](1),
				UrgentResources: ptr.To(urgent),
			})))
			g.Expect(obj.Status.Cases).To(HaveValue(HaveField("Total", HaveValue(Equal(int32(1))))))
			g.Expect(obj.Status.Summary).To(HaveValue(Equal(triagev1alpha1.InvestigationSummary{
				Fail: ptr.To[int32](0), Pass: ptr.To[int32](0), Warn: ptr.To[int32](1), Error: ptr.To[int32](0), Skip: ptr.To[int32](0),
			})))
			g.Expect(obj.Status.Results).To(HaveLen(1))
			result := obj.Status.Results[0]
			g.Expect(result.Subject).To(Equal(repository + "@" + manifest))
			g.Expect(result.VulnerabilityID).To(Equal(id))
			g.Expect(result.Result).To(Equal(triagev1alpha1.InvestigationResultWarn))
			g.Expect(result.Status).To(HaveValue(Equal(triagev1alpha1.VEXStatusUnderInvestigation)))
			g.Expect(result.Step).To(HaveValue(Equal(triagev1alpha1.ResourceStepInvestigate)))
			g.Expect(result.Severity).To(Equal(triagev1alpha1.SeverityHigh))
			g.Expect(result.Urgency).To(HaveValue(Equal(triagev1alpha1.SSVCOutcome(open))))
			g.Expect(result.Exposure).To(HaveValue(Equal(triagev1alpha1.SSVCExposureUnknown)))
			g.Expect(result.Resources).To(HaveValue(Equal(int32(8))))
			g.Expect(result.Owners).To(HaveLen(5))
			for n, owners := range result.Owners {
				name := fmt.Sprintf("team-%c", 'a'+n)
				g.Expect(owners.Cluster).To(Equal(otherCluster))
				g.Expect(owners.Namespace).To(Equal(name))
				g.Expect(owners.Values).To(ConsistOf(HaveField("Value", HaveValue(Equal(name)))))
			}
			g.Expect(obj.Status.Omitted).To(HaveValue(BeZero()))
		})
		Consistently(agentQueue.of(key), quiet, poll).Should(BeEmpty(), "the agent is off, so nothing is queued")
		Expect(assessmentOf(Default, id, manifest)).To(BeNil(), "the agent is off, so no Assessment is created")
	})

	It("decides the exposure of each case's workloads with the playbook's exposure rules, and follows a change of it", func() {
		const id = "CVE-2026-1011"
		playbook := exposedPlaybook(exposedOutsideCluster, reachableInCluster, ownNamespaceOnly)
		manifest := newDigest()
		f := openFinding(id, "lib")
		// The inventory counts both workloads at the spoke's Open.
		runsInOtherCluster(manifest, inNamespace("team-a", map[inventoryv1alpha1.SSVCExposure]int32{inventoryv1alpha1.SSVCExposureOpen: 2}))
		writeSheet(manifest, playbook, f)
		deleteAssessmentsAfterwards(id)
		streamPresence(manifest, "shop", "batch")
		streamExposure("shop", "Cluster", false)
		streamExposure("batch", "Namespace", false)
		name := cases.Name(id, manifest)
		group := func(exposure triagev1alpha1.SSVCExposure, rule, workload string) triagev1alpha1.ExposureGroup {
			return triagev1alpha1.ExposureGroup{Exposure: exposure, Rules: []string{rule}, Workloads: ptr.To(int32(1)),
				First: []string{workloadIn(workload)}}
		}
		at := func(exposure configv1alpha1.SSVCExposure) triagev1alpha1.SSVCOutcome {
			return triagev1alpha1.SSVCOutcome(urgency.Decide(urgency.FromFinding(f, exposure), nil))
		}

		key := createInvestigation(newNamespace(), "exposed", playbook, 10, naming(id))

		expectInvestigation(key, metav1.ConditionTrue, triagev1alpha1.ReasonJudged, func(g Gomega, obj *triagev1alpha1.Investigation) {
			g.Expect(obj.Status.Results).To(HaveLen(1))
			g.Expect(obj.Status.Results[0].Exposure).To(HaveValue(Equal(triagev1alpha1.SSVCExposureControlled)))
			g.Expect(obj.Status.Results[0].Urgency).To(HaveValue(Equal(at(configv1alpha1.SSVCExposureControlled))))
			g.Expect(obj.Status.Results[0].Resources).To(HaveValue(Equal(int32(2))))
		})
		Eventually(agentQueue.runsIn(name), reaction, poll).Should(HaveValue(HaveField("Exposure", Equal([]triagev1alpha1.ExposureGroup{
			group(triagev1alpha1.SSVCExposureControlled, reachableInCluster, "shop"),
			group(triagev1alpha1.SSVCExposureSmall, ownNamespaceOnly, "batch"),
		}))))

		By("exposing shop outside the cluster")
		streamExposure("shop", "Cluster", true)
		bump(key)

		expectInvestigation(key, metav1.ConditionTrue, triagev1alpha1.ReasonJudged, func(g Gomega, obj *triagev1alpha1.Investigation) {
			g.Expect(obj.Status.Results).To(HaveLen(1))
			g.Expect(obj.Status.Results[0].Exposure).To(HaveValue(Equal(triagev1alpha1.SSVCExposureOpen)))
			g.Expect(obj.Status.Results[0].Urgency).To(HaveValue(Equal(at(configv1alpha1.SSVCExposureOpen))))
		})
		Eventually(agentQueue.runsIn(name), reaction, poll).Should(HaveValue(And(
			HaveField("HighestExposure", HaveValue(Equal(triagev1alpha1.SSVCExposureOpen))),
			HaveField("Exposure", Equal([]triagev1alpha1.ExposureGroup{
				group(triagev1alpha1.SSVCExposureOpen, exposedOutsideCluster, "shop"),
				group(triagev1alpha1.SSVCExposureSmall, ownNamespaceOnly, "batch"),
			})))), "the case is handed over again with the exposure of now")
	})

	It("counts in a Rule's status the workloads that its exposure rule couldn't be evaluated for", func() {
		const id, broken = "CVE-2026-1012", "broken-exposure"
		createRule(&configv1alpha1.Rule{ObjectMeta: metav1.ObjectMeta{Name: broken}, Spec: configv1alpha1.RuleSpec{
			Inputs:    []configv1alpha1.RuleInput{{Name: exposureName, Type: sdkevidence.TypeExposure}},
			Condition: "exposure.data.nothing", Outcome: &configv1alpha1.RuleOutcome{Exposure: ptr.To(configv1alpha1.SSVCExposureOpen)},
		}})
		playbook := exposedPlaybook(broken, ownNamespaceOnly)
		manifest := newDigest()
		runsInOtherCluster(manifest, inNamespace("team-a", map[inventoryv1alpha1.SSVCExposure]int32{inventoryv1alpha1.SSVCExposureOpen: 1}))
		writeSheet(manifest, playbook, openFinding(id, "lib"))
		deleteAssessmentsAfterwards(id)
		streamPresence(manifest, "batch")
		streamExposure("batch", "Namespace", false)

		key := createInvestigation(newNamespace(), "broken", playbook, 10, naming(id))

		expectInvestigation(key, metav1.ConditionTrue, triagev1alpha1.ReasonJudged, func(g Gomega, obj *triagev1alpha1.Investigation) {
			g.Expect(obj.Status.Results).To(HaveLen(1))
			g.Expect(obj.Status.Results[0].Exposure).To(HaveValue(Equal(triagev1alpha1.SSVCExposureUnknown)),
				"a rule that fails counts as Unknown, above own-namespace-only's Small")
		})
		Eventually(conditionOf(&configv1alpha1.Rule{}, broken, configv1alpha1.ConditionEvaluated), reaction, poll).Should(And(
			HaveField("Status", metav1.ConditionFalse),
			HaveField("Message", "1 workload couldn't be evaluated in the last evaluations.")))
	})

	Context("leaves a workload Unknown whose exposure comes from no producer that counts for the exposure rules", func() {
		It("from a collector of the other cluster that declares exposure with the scope Spoke, whose records from before stay", func() {
			expectUnknownExposure("CVE-2026-1013", exposedPlaybookFrom([]string{spokeReach}, ownNamespaceOnly), spokeReach)
		})

		It("from a pinned Collector that doesn't declare exposure", func() {
			expectUnknownExposure("CVE-2026-1014", exposedPlaybookFrom([]string{vmCollector}, ownNamespaceOnly), vmCollector)
		})

		It("for an input that a rule takes with another type than the playbook's evidence", func() {
			const mistyped = "mistyped-reach"
			createRule(&configv1alpha1.Rule{ObjectMeta: metav1.ObjectMeta{Name: mistyped}, Spec: configv1alpha1.RuleSpec{
				Inputs:    []configv1alpha1.RuleInput{{Name: exposureName, Type: "com.example.reach.v1alpha1"}},
				Condition: "exposure.data.internalReach == 'Namespace'",
				Outcome:   &configv1alpha1.RuleOutcome{Exposure: ptr.To(configv1alpha1.SSVCExposureSmall)},
			}})
			expectUnknownExposure("CVE-2026-1015", exposedPlaybook(mistyped), networkReach)
		})
	})

	It("queues the most urgent cases up to the cap, and leaves the rest over the cap", func() {
		manifest := newDigest()
		playbook := investigatedPlaybook(&configv1alpha1.PlaybookAgent{})
		runsInOtherCluster(manifest, inNamespace("team-a", map[inventoryv1alpha1.SSVCExposure]int32{inventoryv1alpha1.SSVCExposureOpen: 1}))
		likely, unlikely := openFinding("CVE-2026-2002", "lib"), openFinding("CVE-2026-2003", "lib")
		likely.EPSSPermille, unlikely.EPSSPermille = ptr.To[int32](900), ptr.To[int32](10)
		writeSheet(manifest, playbook, unlikely, exploitedFinding("CVE-2026-2001", "lib"), likely)
		for _, id := range []string{"CVE-2026-2001", "CVE-2026-2002", "CVE-2026-2003"} {
			deleteAssessmentsAfterwards(id)
		}

		key := createInvestigation(newNamespace(), "capped", playbook, 2, nil)

		expectInvestigation(key, metav1.ConditionTrue, triagev1alpha1.ReasonCapReached, func(g Gomega, obj *triagev1alpha1.Investigation) {
			g.Expect(obj.Status.Cases).To(HaveValue(And(HaveField("Total", HaveValue(Equal(int32(3)))),
				HaveField("OverTheCap", HaveValue(Equal(int32(1)))))))
			g.Expect(obj.Status.Summary).To(HaveValue(HaveField("Skip", HaveValue(Equal(int32(1))))))
			g.Expect(obj.Status.Results).To(HaveLen(3))
			last := obj.Status.Results[2]
			g.Expect(last.VulnerabilityID).To(Equal("CVE-2026-2003"))
			g.Expect(last.Result).To(Equal(triagev1alpha1.InvestigationResultSkip))
			g.Expect(last.Reason).To(HaveValue(Equal("over the cap")))
		})
		Expect(agentQueue.of(key)()).To(Equal(slices.Sorted(slices.Values([]string{
			cases.Name("CVE-2026-2001", manifest), cases.Name("CVE-2026-2002", manifest),
		}))))
		Eventually(func(g Gomega) []eventsv1.Event {
			var list eventsv1.EventList
			g.Expect(k8sClient.List(ctx, &list, client.InNamespace(key.Namespace),
				client.MatchingFields{regardingName: key.Name})).To(Succeed())
			return list.Items
		}, reaction, poll).Should(ContainElement(HaveField("Reason", triagev1alpha1.ReasonCapReached)))
	})

	It("reuses a fresh Assessment, and doesn't queue its case", func() {
		const id = "CVE-2026-3001"
		manifest := newDigest()
		playbook := investigatedPlaybook(&configv1alpha1.PlaybookAgent{})
		runsInOtherCluster(manifest, inNamespace("team-a", map[inventoryv1alpha1.SSVCExposure]int32{inventoryv1alpha1.SSVCExposureOpen: 1}))
		f := openFinding(id, "lib")
		// The sheet holds the agent's Affected beside the rules' outcome, as the assessor writes it.
		f.Status = inventoryv1alpha1.VEXStatusAffected
		f.Agent = &inventoryv1alpha1.AgentVerdict{Assessment: cases.Name(id, manifest), Status: inventoryv1alpha1.VEXStatusAffected,
			RuleStatus: ptr.To(inventoryv1alpha1.VEXStatusUnderInvestigation)}
		writeSheet(manifest, playbook, f)
		deleteAssessmentsAfterwards(id)
		judged := &triagev1alpha1.Assessment{
			ObjectMeta: metav1.ObjectMeta{Name: cases.Name(id, manifest), Labels: cases.Labels(id, manifest)},
			Spec: triagev1alpha1.AssessmentSpec{
				Subject: triagev1alpha1.AssessmentSubject{Type: triagev1alpha1.SubjectTypeContainerImage,
					ContainerImage: &triagev1alpha1.ContainerImageSubject{Digest: manifest}},
				VulnerabilityID: id,
			},
		}
		Expect(k8sClient.Create(ctx, judged)).To(Succeed())
		judged.Status = triagev1alpha1.AssessmentStatus{
			Verdict: &triagev1alpha1.AssessmentVerdict{Status: triagev1alpha1.VEXStatusAffected,
				Summary: "The app links the library and decodes its input. No fix exists yet."},
			InputHash:        ptr.To(cases.InputHash([]inventoryv1alpha1.Finding{f}, nil)),
			CaseFilePlaybook: ptr.To("an-earlier-playbook"),
			Playbooks:        []string{"an-earlier-playbook"},
		}
		Expect(k8sClient.Status().Update(ctx, judged)).To(Succeed())

		key := createInvestigation(newNamespace(), "reuse", playbook, 5, nil)

		expectInvestigation(key, metav1.ConditionTrue, triagev1alpha1.ReasonJudged, func(g Gomega, obj *triagev1alpha1.Investigation) {
			g.Expect(obj.Status.Cases).To(HaveValue(HaveField("Reused", HaveValue(Equal(int32(1))))))
			g.Expect(obj.Status.Summary).To(HaveValue(HaveField("Fail", HaveValue(Equal(int32(1))))))
			g.Expect(obj.Status.Results).To(ConsistOf(And(
				HaveField("Result", triagev1alpha1.InvestigationResultFail),
				HaveField("Status", HaveValue(Equal(triagev1alpha1.VEXStatusAffected))),
				HaveField("Verdict", HaveValue(Equal(triagev1alpha1.VEXStatusAffected))),
				HaveField("Review", BeNil()),
				HaveField("Step", HaveValue(Equal(triagev1alpha1.ResourceStepMitigate))),
				HaveField("Reason", HaveValue(Equal("The app links the library and decodes its input."))))))
		})
		Expect(agentQueue.of(key)()).To(BeEmpty())
		Eventually(func(g Gomega) []string { return assessmentOf(g, id, manifest).Status.Playbooks }, reaction, poll).
			Should(ConsistOf("an-earlier-playbook", playbook))
	})

	It("keeps the sheet's result for an agent's NotAffected that nobody reviewed, and shows the verdict and its review beside it", func() {
		const id = "CVE-2026-3101"
		manifest := newDigest()
		playbook := investigatedPlaybook(&configv1alpha1.PlaybookAgent{})
		runsInOtherCluster(manifest, inNamespace("team-a", map[inventoryv1alpha1.SSVCExposure]int32{inventoryv1alpha1.SSVCExposureOpen: 1}))
		f := openFinding(id, "lib")
		f.Agent = &inventoryv1alpha1.AgentVerdict{Assessment: cases.Name(id, manifest), Status: inventoryv1alpha1.VEXStatusNotAffected,
			Justification: ptr.To(inventoryv1alpha1.VEXJustificationVulnerableCodeNotPresent),
			Review:        ptr.To(inventoryv1alpha1.ReviewStateProposed), Statement: ptr.To("statement-of-the-verdict")}
		writeSheet(manifest, playbook, f)
		deleteAssessmentsAfterwards(id)
		judged := &triagev1alpha1.Assessment{
			ObjectMeta: metav1.ObjectMeta{Name: cases.Name(id, manifest), Labels: cases.Labels(id, manifest)},
			Spec: triagev1alpha1.AssessmentSpec{
				Subject: triagev1alpha1.AssessmentSubject{Type: triagev1alpha1.SubjectTypeContainerImage,
					ContainerImage: &triagev1alpha1.ContainerImageSubject{Digest: manifest}},
				VulnerabilityID: id,
			},
		}
		Expect(k8sClient.Create(ctx, judged)).To(Succeed())
		judged.Status = triagev1alpha1.AssessmentStatus{
			Verdict: &triagev1alpha1.AssessmentVerdict{Status: triagev1alpha1.VEXStatusNotAffected,
				Justification: ptr.To(triagev1alpha1.VEXJustificationVulnerableCodeNotPresent),
				Summary:       "The image installs the fixed release. Its distribution backported the fix.",
				Statement:     ptr.To("statement-of-the-verdict")},
			InputHash: ptr.To(cases.InputHash([]inventoryv1alpha1.Finding{f}, nil)),
		}
		Expect(k8sClient.Status().Update(ctx, judged)).To(Succeed())

		key := createInvestigation(newNamespace(), "unreviewed", playbook, 5, nil)

		expectInvestigation(key, metav1.ConditionTrue, triagev1alpha1.ReasonJudged, func(g Gomega, obj *triagev1alpha1.Investigation) {
			g.Expect(obj.Status.Summary).To(HaveValue(And(HaveField("Pass", HaveValue(BeZero())),
				HaveField("Warn", HaveValue(Equal(int32(1)))))))
			g.Expect(obj.Status.Results).To(ConsistOf(And(
				HaveField("Result", triagev1alpha1.InvestigationResultWarn),
				HaveField("Status", HaveValue(Equal(triagev1alpha1.VEXStatusUnderInvestigation))),
				HaveField("Step", HaveValue(Equal(triagev1alpha1.ResourceStepInvestigate))),
				HaveField("Verdict", HaveValue(Equal(triagev1alpha1.VEXStatusNotAffected))),
				HaveField("Review", HaveValue(Equal(triagev1alpha1.ReviewStateProposed))),
				HaveField("Reason", HaveValue(Equal("The image installs the fixed release."))))))
		})
	})

	It("doesn't run a playbook without an agent section", func() {
		playbook := investigatedPlaybook(nil)

		key := createInvestigation(newNamespace(), "not-allowed", playbook, 5, nil)

		expectInvestigation(key, metav1.ConditionFalse, triagev1alpha1.ReasonAgentNotAllowed, func(g Gomega, obj *triagev1alpha1.Investigation) {
			g.Expect(meta.IsStatusConditionTrue(obj.Status.Conditions, configv1alpha1.ConditionStalled)).To(BeTrue())
		})
	})

	It("creates one Assessment of a case that two investigations select, with both playbooks", func() {
		const id = "CVE-2026-4001"
		manifest := newDigest()
		first, second := investigatedPlaybook(&configv1alpha1.PlaybookAgent{}), investigatedPlaybook(&configv1alpha1.PlaybookAgent{})
		runsInOtherCluster(manifest, inNamespace("team-a", map[inventoryv1alpha1.SSVCExposure]int32{inventoryv1alpha1.SSVCExposureOpen: 1}))
		writeSheet(manifest, first, openFinding(id, "lib"))
		writeSheet(manifest, second, openFinding(id, "lib"))
		deleteAssessmentsAfterwards(id)
		namespace := newNamespace()

		one := createInvestigation(namespace, "one", first, 5, naming(id))
		other := createInvestigation(namespace, "other", second, 5, naming(id))

		Eventually(func(g Gomega) {
			found := assessmentOf(g, id, manifest)
			g.Expect(found).NotTo(BeNil())
			g.Expect(found.Labels).To(Equal(cases.Labels(id, manifest)))
			g.Expect(found.Spec.VulnerabilityID).To(Equal(id))
			g.Expect(found.Spec.Subject.ContainerImage).To(HaveValue(HaveField("Digest", manifest)))
			g.Expect(found.Status.Playbooks).To(ConsistOf(first, second))
			g.Expect(found.Status.CaseFilePlaybook).To(HaveValue(BeElementOf(first, second)))
			ready := meta.FindStatusCondition(found.Status.Conditions, configv1alpha1.ConditionReady)
			g.Expect(ready).NotTo(BeNil())
			g.Expect(ready.Status).To(Equal(metav1.ConditionFalse))
			g.Expect(ready.Reason).To(Equal(triagev1alpha1.ReasonQueued))
			g.Expect(meta.IsStatusConditionTrue(found.Status.Conditions, configv1alpha1.ConditionReconciling)).To(BeTrue())
		}, reaction, poll).Should(Succeed())
		var list triagev1alpha1.AssessmentList
		Expect(k8sClient.List(ctx, &list, client.MatchingLabels{cases.VulnerabilityLabel: id})).To(Succeed())
		Expect(list.Items).To(HaveLen(1))
		Eventually(agentQueue.of(one), reaction, poll).Should(ConsistOf(cases.Name(id, manifest)))
		Eventually(agentQueue.of(other), reaction, poll).Should(ConsistOf(cases.Name(id, manifest)))
	})

	It("shows the first 20 results, and counts the rest as omitted", func() {
		manifest := newDigest()
		playbook := investigatedPlaybook(&configv1alpha1.PlaybookAgent{})
		runsInOtherCluster(manifest, inNamespace("team-a", map[inventoryv1alpha1.SSVCExposure]int32{inventoryv1alpha1.SSVCExposureSmall: 1}))
		findings := make([]inventoryv1alpha1.Finding, 0, 25)
		for i := range 25 {
			id := fmt.Sprintf("CVE-2026-5%03d", i)
			findings = append(findings, openFinding(id, "lib"))
			deleteAssessmentsAfterwards(id)
		}
		writeSheet(manifest, playbook, findings...)

		key := createInvestigation(newNamespace(), "many", playbook, 100, nil)

		expectInvestigation(key, metav1.ConditionTrue, triagev1alpha1.ReasonJudged, func(g Gomega, obj *triagev1alpha1.Investigation) {
			g.Expect(obj.Status.Cases).To(HaveValue(HaveField("Total", HaveValue(Equal(int32(25))))))
			g.Expect(obj.Status.Results).To(HaveLen(20))
			g.Expect(obj.Status.Omitted).To(HaveValue(Equal(int32(5))))
		})
	})

	It("is Stalled when it can't run: an unknown playbook, or a condition that doesn't compile", func() {
		namespace := newNamespace()
		unknown := createInvestigation(namespace, "unknown", nowhere, 5, nil)
		expectInvestigation(unknown, metav1.ConditionFalse, triagev1alpha1.ReasonPlaybookNotFound, nil)

		playbook := investigatedPlaybook(&configv1alpha1.PlaybookAgent{})
		broken := createInvestigation(namespace, "broken", playbook, 5, func(s *triagev1alpha1.InvestigationSpec) {
			s.MatchConditions = []triagev1alpha1.MatchCondition{{Name: "half-written", Expression: "finding."}}
		})
		ready := expectInvestigation(broken, metav1.ConditionFalse, triagev1alpha1.ReasonInvalidCondition, nil).Status.Conditions
		Expect(meta.FindStatusCondition(ready, configv1alpha1.ConditionReady).Message).To(ContainSubstring("half-written"))
	})
	It("runs a Once investigation again only when its spec changes", func() {
		const first, second = "CVE-2026-6001", "CVE-2026-6002"
		manifest := newDigest()
		playbook := investigatedPlaybook(&configv1alpha1.PlaybookAgent{})
		runsInOtherCluster(manifest, inNamespace("team-a", map[inventoryv1alpha1.SSVCExposure]int32{inventoryv1alpha1.SSVCExposureOpen: 1}))
		f := openFinding(first, "lib")
		writeSheet(manifest, playbook, f)
		for _, id := range []string{first, second} {
			deleteAssessmentsAfterwards(id)
		}
		recordVerdict(first, manifest, f, investigationClock.Now())
		started := investigationClock.Now()

		key := createInvestigation(newNamespace(), "once", playbook, 5, nil)

		expectInvestigation(key, metav1.ConditionTrue, triagev1alpha1.ReasonJudged, func(g Gomega, obj *triagev1alpha1.Investigation) {
			g.Expect(obj.Status.StartTime).NotTo(BeNil())
			g.Expect(obj.Status.StartTime.Time).To(BeTemporally("==", started.Truncate(time.Second)))
			g.Expect(obj.Status.CompletionTime).NotTo(BeNil())
		})

		By("a case that newly matches, with the spec unchanged")
		investigationClock.Step(time.Hour)
		sheets := inventory.NewCRDVerdictsStore(k8sClient, cluster)
		Expect(sheets.Put(ctx, manifest, playbook, inventoryv1alpha1.ImageVerdictsStatus{
			Playbook: ptr.To(playbook), FindingsVersion: ptr.To(v1), Findings: []inventoryv1alpha1.Finding{f, openFinding(second, "lib")},
		})).To(Succeed())
		expectInvestigation(key, metav1.ConditionTrue, triagev1alpha1.ReasonJudged, func(g Gomega, obj *triagev1alpha1.Investigation) {
			g.Expect(obj.Status.Cases).To(HaveValue(HaveField("Total", HaveValue(Equal(int32(2))))))
			g.Expect(obj.Status.StartTime.Time).To(BeTemporally("==", started.Truncate(time.Second)))
		})
		Consistently(agentQueue.of(key), quiet, poll).Should(BeEmpty())

		By("a change of the spec")
		changed := investigationClock.Now()
		bump(key)
		Eventually(agentQueue.of(key), reaction, poll).Should(ConsistOf(cases.Name(second, manifest)))
		expectInvestigation(key, metav1.ConditionTrue, triagev1alpha1.ReasonJudged, func(g Gomega, obj *triagev1alpha1.Investigation) {
			g.Expect(obj.Status.StartTime.Time).To(BeTemporally("==", changed.Truncate(time.Second)))
			g.Expect(obj.Status.CompletionTime).To(BeNil(), "the second case waits for the agent")
		})
	})

	It("skips a tick of a schedule while a run is going", func() {
		const id = "CVE-2026-6101"
		manifest := newDigest()
		playbook := investigatedPlaybook(&configv1alpha1.PlaybookAgent{})
		runsInOtherCluster(manifest, inNamespace("team-a", map[inventoryv1alpha1.SSVCExposure]int32{inventoryv1alpha1.SSVCExposureOpen: 1}))
		writeSheet(manifest, playbook, openFinding(id, "lib"))
		deleteAssessmentsAfterwards(id)
		investigationClock.Step(time.Hour)
		key := types.NamespacedName{Namespace: newNamespace(), Name: "ticking"}
		agentQueue.keepBusy(key, 1)

		createInvestigation(key.Namespace, key.Name, playbook, 5, func(s *triagev1alpha1.InvestigationSpec) {
			s.Trigger = &triagev1alpha1.InvestigationTrigger{Type: triagev1alpha1.InvestigationTriggerSchedule, Schedule: ptr.To("*/5 * * * *")}
		})

		Eventually(func(g Gomega) []string { return eventReasons(g, key) }, reaction, poll).Should(ContainElement("TickSkipped"))
		Consistently(func(g Gomega) *metav1.Time { return investigationOf(g, key).Status.LastScheduleTime }, quiet, poll).Should(BeNil())
		Expect(agentQueue.of(key)()).To(BeEmpty())

		By("the run is over")
		agentQueue.keepBusy(key, 0)
		ticked := investigationClock.Now()
		bump(key)
		Eventually(func(g Gomega) {
			obj := investigationOf(g, key)
			g.Expect(obj.Status.LastScheduleTime).NotTo(BeNil())
			g.Expect(obj.Status.LastScheduleTime.Time).To(BeTemporally("==", ticked.Truncate(time.Second)))
			g.Expect(obj.Status.StartTime.Time).To(BeTemporally("==", ticked.Truncate(time.Second)))
		}, reaction, poll).Should(Succeed())
		Eventually(agentQueue.of(key), reaction, poll).Should(ConsistOf(cases.Name(id, manifest)))
	})

	It("queues a case that a continuous investigation newly matches, and counts every case judged since its creation", func() {
		const a, b, c = "CVE-2026-6201", "CVE-2026-6202", "CVE-2026-6203"
		manifest := newDigest()
		playbook := investigatedPlaybook(&configv1alpha1.PlaybookAgent{})
		runsInOtherCluster(manifest, inNamespace("team-a", map[inventoryv1alpha1.SSVCExposure]int32{inventoryv1alpha1.SSVCExposureOpen: 1}))
		fa, fb, fc := openFinding(a, "lib"), openFinding(b, "lib"), openFinding(c, "lib")
		writeSheet(manifest, playbook, fa)
		for _, id := range []string{a, b, c} {
			deleteAssessmentsAfterwards(id)
		}
		put := func(findings ...inventoryv1alpha1.Finding) {
			Expect(inventory.NewCRDVerdictsStore(k8sClient, cluster).Put(ctx, manifest, playbook, inventoryv1alpha1.ImageVerdictsStatus{
				Playbook: ptr.To(playbook), FindingsVersion: ptr.To(v1), Findings: findings,
			})).To(Succeed())
		}

		key := createInvestigation(newNamespace(), "continuous", playbook, 2, func(s *triagev1alpha1.InvestigationSpec) {
			s.Trigger = &triagev1alpha1.InvestigationTrigger{Type: triagev1alpha1.InvestigationTriggerContinuous}
		})
		Eventually(agentQueue.of(key), reaction, poll).Should(ConsistOf(cases.Name(a, manifest)))
		recordVerdict(a, manifest, fa, investigationClock.Now())

		put(fa, fb)
		Eventually(agentQueue.of(key), reaction, poll).Should(ConsistOf(cases.Name(a, manifest), cases.Name(b, manifest)))
		recordVerdict(b, manifest, fb, investigationClock.Now())

		put(fa, fb, fc)
		expectInvestigation(key, metav1.ConditionTrue, triagev1alpha1.ReasonCapReached, func(g Gomega, obj *triagev1alpha1.Investigation) {
			g.Expect(obj.Status.Cases).To(HaveValue(And(HaveField("Judged", HaveValue(Equal(int32(2)))),
				HaveField("OverTheCap", HaveValue(Equal(int32(1)))))))
			g.Expect(obj.Status.CompletionTime).To(BeNil(), "a continuous investigation never completes")
		})
		Expect(agentQueue.of(key)()).NotTo(ContainElement(cases.Name(c, manifest)))
	})

	It("queues nothing for a disabled investigation, and keeps its status current", func() {
		const first, second = "CVE-2026-6301", "CVE-2026-6302"
		manifest := newDigest()
		playbook := investigatedPlaybook(&configv1alpha1.PlaybookAgent{})
		runsInOtherCluster(manifest, inNamespace("team-a", map[inventoryv1alpha1.SSVCExposure]int32{inventoryv1alpha1.SSVCExposureOpen: 1}))
		writeSheet(manifest, playbook, openFinding(first, "lib"))
		for _, id := range []string{first, second} {
			deleteAssessmentsAfterwards(id)
		}

		key := createInvestigation(newNamespace(), "disabled", playbook, 5, func(s *triagev1alpha1.InvestigationSpec) {
			s.State = ptr.To(triagev1alpha1.InvestigationStateDisabled)
		})

		expectInvestigation(key, metav1.ConditionFalse, triagev1alpha1.ReasonDisabled, func(g Gomega, obj *triagev1alpha1.Investigation) {
			g.Expect(obj.Status.Cases).To(HaveValue(HaveField("Total", HaveValue(Equal(int32(1))))))
			g.Expect(obj.Status.Impact).To(HaveValue(HaveField("Subjects", HaveValue(Equal(int32(1))))))
			g.Expect(obj.Status.StartTime).To(BeNil())
		})
		Expect(inventory.NewCRDVerdictsStore(k8sClient, cluster).Put(ctx, manifest, playbook, inventoryv1alpha1.ImageVerdictsStatus{
			Playbook: ptr.To(playbook), FindingsVersion: ptr.To(v1),
			Findings: []inventoryv1alpha1.Finding{openFinding(first, "lib"), openFinding(second, "lib")},
		})).To(Succeed())
		expectInvestigation(key, metav1.ConditionFalse, triagev1alpha1.ReasonDisabled, func(g Gomega, obj *triagev1alpha1.Investigation) {
			g.Expect(obj.Status.Cases).To(HaveValue(HaveField("Total", HaveValue(Equal(int32(2))))))
		})
		Consistently(agentQueue.of(key), quiet, poll).Should(BeEmpty())
		Expect(assessmentOf(Default, first, manifest)).To(BeNil())
	})

	It("judges a verdict again that is older than the max age", func() {
		const old, young = "CVE-2026-6401", "CVE-2026-6402"
		manifest := newDigest()
		playbook := investigatedPlaybook(&configv1alpha1.PlaybookAgent{})
		runsInOtherCluster(manifest, inNamespace("team-a", map[inventoryv1alpha1.SSVCExposure]int32{inventoryv1alpha1.SSVCExposureOpen: 1}))
		fo, fy := openFinding(old, "lib"), openFinding(young, "lib")
		writeSheet(manifest, playbook, fo, fy)
		for _, id := range []string{old, young} {
			deleteAssessmentsAfterwards(id)
		}
		recordVerdict(old, manifest, fo, investigationClock.Now().Add(-2*time.Hour))
		recordVerdict(young, manifest, fy, investigationClock.Now().Add(-10*time.Minute))

		key := createInvestigation(newNamespace(), "aged", playbook, 5, func(s *triagev1alpha1.InvestigationSpec) {
			s.Agent.VerdictMaxAgeSeconds = ptr.To[int64](3600)
		})

		Eventually(agentQueue.of(key), reaction, poll).Should(ConsistOf(cases.Name(old, manifest)))
		expectInvestigation(key, metav1.ConditionTrue, triagev1alpha1.ReasonJudged, func(g Gomega, obj *triagev1alpha1.Investigation) {
			g.Expect(obj.Status.Cases).To(HaveValue(HaveField("Reused", HaveValue(Equal(int32(1))))))
		})
	})

	It("records RunStarted and RunFinished as events, with the start and completion times", func() {
		const id = "CVE-2026-6501"
		manifest := newDigest()
		playbook := investigatedPlaybook(&configv1alpha1.PlaybookAgent{})
		runsInOtherCluster(manifest, inNamespace("team-a", map[inventoryv1alpha1.SSVCExposure]int32{inventoryv1alpha1.SSVCExposureOpen: 1}))
		f := openFinding(id, "lib")
		writeSheet(manifest, playbook, f)
		deleteAssessmentsAfterwards(id)
		recordVerdict(id, manifest, f, investigationClock.Now())
		now := investigationClock.Now()

		key := createInvestigation(newNamespace(), "events", playbook, 5, nil)

		expectInvestigation(key, metav1.ConditionTrue, triagev1alpha1.ReasonJudged, func(g Gomega, obj *triagev1alpha1.Investigation) {
			g.Expect(obj.Status.StartTime.Time).To(BeTemporally("==", now.Truncate(time.Second)))
			g.Expect(obj.Status.CompletionTime).NotTo(BeNil())
			g.Expect(eventReasons(g, key)).To(ContainElements("RunStarted", "RunFinished"))
		})
	})
	It("keeps the places of cases that wait for the agent when a more urgent case appears", func() {
		const a, b, c = "CVE-2026-6601", "CVE-2026-6602", "CVE-2026-6603"
		manifest := newDigest()
		playbook := investigatedPlaybook(&configv1alpha1.PlaybookAgent{})
		runsInOtherCluster(manifest, inNamespace("team-a", map[inventoryv1alpha1.SSVCExposure]int32{inventoryv1alpha1.SSVCExposureOpen: 1}))
		fa, fb := openFinding(a, "lib"), openFinding(b, "lib")
		fa.EPSSPermille, fb.EPSSPermille = ptr.To[int32](20), ptr.To[int32](10)
		writeSheet(manifest, playbook, fa, fb)
		for _, id := range []string{a, b, c} {
			deleteAssessmentsAfterwards(id)
		}
		key := types.NamespacedName{Namespace: newNamespace(), Name: "held"}
		createInvestigation(key.Namespace, key.Name, playbook, 2, nil)
		Eventually(agentQueue.of(key), reaction, poll).Should(ConsistOf(cases.Name(a, manifest), cases.Name(b, manifest)))
		agentQueue.keepBusy(key, 2)

		Expect(inventory.NewCRDVerdictsStore(k8sClient, cluster).Put(ctx, manifest, playbook, inventoryv1alpha1.ImageVerdictsStatus{
			Playbook: ptr.To(playbook), FindingsVersion: ptr.To(v1),
			Findings: []inventoryv1alpha1.Finding{fa, fb, exploitedFinding(c, "lib")},
		})).To(Succeed())

		expectInvestigation(key, metav1.ConditionFalse, triagev1alpha1.ReasonJudging, func(g Gomega, obj *triagev1alpha1.Investigation) {
			g.Expect(obj.Status.Cases).To(HaveValue(And(HaveField("Total", HaveValue(Equal(int32(3)))),
				HaveField("OverTheCap", HaveValue(Equal(int32(1)))))))
			g.Expect(obj.Status.Results).To(HaveLen(3))
			g.Expect(obj.Status.Results[0].VulnerabilityID).To(Equal(c))
			g.Expect(obj.Status.Results[0].Result).To(Equal(triagev1alpha1.InvestigationResultSkip))
		})
		Consistently(agentQueue.of(key), quiet, poll).Should(ConsistOf(cases.Name(a, manifest), cases.Name(b, manifest)))
	})

	It("charges a stale case that was judged again, so the cap holds", func() {
		const a, b = "CVE-2026-6701", "CVE-2026-6702"
		manifest := newDigest()
		playbook := investigatedPlaybook(&configv1alpha1.PlaybookAgent{})
		runsInOtherCluster(manifest, inNamespace("team-a", map[inventoryv1alpha1.SSVCExposure]int32{inventoryv1alpha1.SSVCExposureOpen: 1}))
		fa := openFinding(a, "lib")
		writeSheet(manifest, playbook, fa)
		for _, id := range []string{a, b} {
			deleteAssessmentsAfterwards(id)
		}
		key := createInvestigation(newNamespace(), "stale", playbook, 1, func(s *triagev1alpha1.InvestigationSpec) {
			s.Trigger = &triagev1alpha1.InvestigationTrigger{Type: triagev1alpha1.InvestigationTriggerContinuous}
		})
		Eventually(agentQueue.of(key), reaction, poll).Should(ConsistOf(cases.Name(a, manifest)))
		recordVerdict(a, manifest, fa, investigationClock.Now())

		By("its input changes, and another case newly matches")
		Expect(inventory.NewCRDVerdictsStore(k8sClient, cluster).Put(ctx, manifest, playbook, inventoryv1alpha1.ImageVerdictsStatus{
			Playbook: ptr.To(playbook), FindingsVersion: ptr.To(v1),
			Findings: []inventoryv1alpha1.Finding{openFinding(a, "other-lib"), openFinding(b, "lib")},
		})).To(Succeed())

		expectInvestigation(key, metav1.ConditionTrue, triagev1alpha1.ReasonCapReached, func(g Gomega, obj *triagev1alpha1.Investigation) {
			g.Expect(obj.Status.Cases).To(HaveValue(And(HaveField("Charged", HaveValue(Equal(int32(1)))),
				HaveField("OverTheCap", HaveValue(Equal(int32(2)))))))
		})
		Expect(agentQueue.of(key)()).To(ConsistOf(cases.Name(a, manifest)), "neither the stale case nor the new one goes over the cap")
	})
	It("counts the selected cases, and those left out", func() {
		running, gone := newDigest(), newDigest()
		playbook := investigatedPlaybook(&configv1alpha1.PlaybookAgent{})
		runsInOtherCluster(running, inNamespace("team-a", map[inventoryv1alpha1.SSVCExposure]int32{inventoryv1alpha1.SSVCExposureOpen: 1}))
		onRunning := make([]inventoryv1alpha1.Finding, 0, 8)
		for i := range 8 {
			f := openFinding(fmt.Sprintf("CVE-2026-69%02d", i), "lib")
			if i < 3 {
				f.Severity = inventoryv1alpha1.SeverityLow
			}
			onRunning = append(onRunning, f)
			deleteAssessmentsAfterwards(f.VulnerabilityID)
		}
		writeSheet(running, playbook, onRunning...)
		writeSheet(gone, playbook, openFinding("CVE-2026-6990", "lib"), openFinding("CVE-2026-6991", "lib"))

		key := createInvestigation(newNamespace(), "counted", playbook, 2, func(s *triagev1alpha1.InvestigationSpec) {
			s.MatchConditions = []triagev1alpha1.MatchCondition{{Name: "high", Expression: `finding.severity == "High"`}}
		})

		expectInvestigation(key, metav1.ConditionTrue, triagev1alpha1.ReasonCapReached, func(g Gomega, obj *triagev1alpha1.Investigation) {
			g.Expect(obj.Status.Cases).To(HaveValue(And(HaveField("Total", HaveValue(Equal(int32(5)))),
				HaveField("OverTheCap", HaveValue(Equal(int32(3)))), HaveField("NotSelected", HaveValue(Equal(int32(5)))),
				HaveField("Charged", HaveValue(Equal(int32(2)))))))
			g.Expect(obj.Status.Summary).To(HaveValue(HaveField("Skip", HaveValue(Equal(int32(3))))))
		})
	})

	It("doesn't let a case that left the selection and came back free room under the cap", func() {
		const a, b = "CVE-2026-6801", "CVE-2026-6802"
		manifest := newDigest()
		playbook := investigatedPlaybook(&configv1alpha1.PlaybookAgent{})
		runsInOtherCluster(manifest, inNamespace("team-a", map[inventoryv1alpha1.SSVCExposure]int32{inventoryv1alpha1.SSVCExposureOpen: 1}))
		fa, fb := openFinding(a, "lib"), openFinding(b, "lib")
		writeSheet(manifest, playbook, fa)
		for _, id := range []string{a, b} {
			deleteAssessmentsAfterwards(id)
		}
		put := func(findings ...inventoryv1alpha1.Finding) {
			Expect(inventory.NewCRDVerdictsStore(k8sClient, cluster).Put(ctx, manifest, playbook, inventoryv1alpha1.ImageVerdictsStatus{
				Playbook: ptr.To(playbook), FindingsVersion: ptr.To(v1), Findings: findings,
			})).To(Succeed())
		}
		key := createInvestigation(newNamespace(), "returns", playbook, 1, func(s *triagev1alpha1.InvestigationSpec) {
			s.Trigger = &triagev1alpha1.InvestigationTrigger{Type: triagev1alpha1.InvestigationTriggerContinuous}
		})
		Eventually(agentQueue.of(key), reaction, poll).Should(ConsistOf(cases.Name(a, manifest)))
		recordVerdict(a, manifest, fa, investigationClock.Now())

		By("A leaves the selection, and B matches")
		put(fb)
		expectInvestigation(key, metav1.ConditionTrue, triagev1alpha1.ReasonCapReached, func(g Gomega, obj *triagev1alpha1.Investigation) {
			g.Expect(obj.Status.Cases).To(HaveValue(And(HaveField("Charged", HaveValue(Equal(int32(1)))),
				HaveField("OverTheCap", HaveValue(Equal(int32(1)))))))
		})

		By("A comes back, with other inputs")
		put(openFinding(a, "other-lib"), fb)
		expectInvestigation(key, metav1.ConditionTrue, triagev1alpha1.ReasonCapReached, func(g Gomega, obj *triagev1alpha1.Investigation) {
			g.Expect(obj.Status.Cases).To(HaveValue(And(HaveField("Charged", HaveValue(Equal(int32(1)))),
				HaveField("OverTheCap", HaveValue(Equal(int32(2)))))))
		})
		Consistently(agentQueue.of(key), quiet, poll).Should(ConsistOf(cases.Name(a, manifest)))
	})

	It("starts the counter of a Once investigation again with a change of its spec", func() {
		const a, b = "CVE-2026-6901", "CVE-2026-6902"
		manifest := newDigest()
		playbook := investigatedPlaybook(&configv1alpha1.PlaybookAgent{})
		runsInOtherCluster(manifest, inNamespace("team-a", map[inventoryv1alpha1.SSVCExposure]int32{inventoryv1alpha1.SSVCExposureOpen: 1}))
		fa := openFinding(a, "lib")
		writeSheet(manifest, playbook, fa)
		for _, id := range []string{a, b} {
			deleteAssessmentsAfterwards(id)
		}
		key := createInvestigation(newNamespace(), "recount", playbook, 1, nil)
		Eventually(agentQueue.of(key), reaction, poll).Should(ConsistOf(cases.Name(a, manifest)))
		recordVerdict(a, manifest, fa, investigationClock.Now())
		Expect(inventory.NewCRDVerdictsStore(k8sClient, cluster).Put(ctx, manifest, playbook, inventoryv1alpha1.ImageVerdictsStatus{
			Playbook: ptr.To(playbook), FindingsVersion: ptr.To(v1), Findings: []inventoryv1alpha1.Finding{fa, openFinding(b, "lib")},
		})).To(Succeed())

		bump(key)

		Eventually(agentQueue.of(key), reaction, poll).Should(ConsistOf(cases.Name(a, manifest), cases.Name(b, manifest)))
		expectInvestigation(key, metav1.ConditionTrue, triagev1alpha1.ReasonJudged, func(g Gomega, obj *triagev1alpha1.Investigation) {
			g.Expect(obj.Status.Cases).To(HaveValue(HaveField("Charged", HaveValue(Equal(int32(1))))))
		})
	})

	It("sums the tokens of the cases that were judged for this object, in its run, and not for an earlier one of its name", func() {
		const a, b, c, old, earlierID = "CVE-2026-7001", "CVE-2026-7002", "CVE-2026-7003", "CVE-2026-7004", "CVE-2026-7005"
		manifest := newDigest()
		playbook := investigatedPlaybook(&configv1alpha1.PlaybookAgent{})
		runsInOtherCluster(manifest, inNamespace("team-a", map[inventoryv1alpha1.SSVCExposure]int32{inventoryv1alpha1.SSVCExposureOpen: 1}))
		ids := []string{a, b, c, old, earlierID}
		findings := make([]inventoryv1alpha1.Finding, len(ids))
		for i, id := range ids {
			findings[i] = openFinding(id, "lib")
			deleteAssessmentsAfterwards(id)
		}
		writeSheet(manifest, playbook, findings...)
		namespace := newNamespace()
		key := createDisabled(namespace, "tokens", playbook, 5, nil)
		mine := referenceTo(key)
		other := &triagev1alpha1.InvestigationReference{Namespace: namespace, Name: "elsewhere", UID: anotherUID}
		earlier := earlierObject(key)
		spent := func(id string, i int, to *triagev1alpha1.InvestigationReference, prompt, completion int64, at time.Time) {
			recordVerdictFor(id, manifest, findings[i], at, to)
			Eventually(func(g Gomega) {
				as := assessmentOf(g, id, manifest)
				as.Status.Usage = &triagev1alpha1.AssessmentUsage{PromptTokens: ptr.To(prompt), CompletionTokens: ptr.To(completion)}
				g.Expect(k8sClient.Status().Update(ctx, as)).To(Succeed())
			}, reaction, poll).Should(Succeed())
		}
		now := investigationClock.Now()
		spent(a, 0, mine, 100, 10, now)
		spent(b, 1, mine, 200, 20, now)
		spent(c, 2, other, 400, 40, now)
		spent(old, 3, mine, 800, 80, now.Add(-2*time.Hour))
		spent(earlierID, 4, earlier, 1600, 160, now)

		enable(key)

		expectInvestigation(key, metav1.ConditionTrue, triagev1alpha1.ReasonJudged, func(g Gomega, obj *triagev1alpha1.Investigation) {
			g.Expect(obj.Status.Usage).To(HaveValue(And(HaveField("PromptTokens", HaveValue(Equal(int64(300)))),
				HaveField("CompletionTokens", HaveValue(Equal(int64(30)))))))
		})
	})

	// judgePolicy (design of an investigation's guidance, 3.4): a case is judged once, and IfStale reuses its fresh
	// verdict whoever it was judged for, which status.cases.judgedElsewhere counts and an event names.
	It("reuses a verdict judged elsewhere under IfStale, counts it, and names up to 5 such cases in an event", func() {
		ids := []string{"CVE-2026-8001", "CVE-2026-8002", "CVE-2026-8003", "CVE-2026-8004", "CVE-2026-8005",
			"CVE-2026-8006", "CVE-2026-8007"}
		manifest := newDigest()
		playbook := investigatedPlaybook(&configv1alpha1.PlaybookAgent{})
		runsInOtherCluster(manifest, inNamespace("team-a", map[inventoryv1alpha1.SSVCExposure]int32{inventoryv1alpha1.SSVCExposureOpen: 1}))
		findings := make([]inventoryv1alpha1.Finding, len(ids))
		for i, id := range ids {
			findings[i] = openFinding(id, "lib")
			deleteAssessmentsAfterwards(id)
		}
		writeSheet(manifest, playbook, findings...)
		key := createDisabled(newNamespace(), "reuse-elsewhere", playbook, 5, func(s *triagev1alpha1.InvestigationSpec) {
			s.Agent.Guidance = ptr.To("Only images built with the HTTP/2 module are affected.")
		})
		mine := referenceTo(key)
		other := &triagev1alpha1.InvestigationReference{Namespace: key.Namespace, Name: anotherInvestigation, UID: anotherUID}
		before := investigationClock.Now().Add(-time.Hour)
		var elsewhere []string
		for i, id := range ids {
			switch i {
			case 0:
				recordVerdictFor(id, manifest, findings[i], before, mine)
			case 1, 2, 3:
				recordVerdictFor(id, manifest, findings[i], before, other)
				elsewhere = append(elsewhere, cases.Name(id, manifest))
			default:
				recordVerdictFor(id, manifest, findings[i], before, nil)
				elsewhere = append(elsewhere, cases.Name(id, manifest))
			}
		}

		enable(key)

		expectInvestigation(key, metav1.ConditionTrue, triagev1alpha1.ReasonJudged, func(g Gomega, obj *triagev1alpha1.Investigation) {
			g.Expect(obj.Spec.Agent.JudgePolicy).To(HaveValue(Equal(triagev1alpha1.InvestigationJudgeIfStale)))
			g.Expect(obj.Status.Cases).To(HaveValue(And(HaveField("Reused", HaveValue(Equal(int32(7)))),
				HaveField("JudgedElsewhere", HaveValue(Equal(int32(6)))))))
			notes := eventNotes(g, key, "JudgedElsewhere")
			g.Expect(notes).To(HaveLen(1))
			g.Expect(notes[0]).To(ContainSubstring("Set spec.agent.judgePolicy to IfJudgedElsewhere to judge them with " +
				"this investigation's guidance."))
			named := 0
			for _, name := range elsewhere {
				if strings.Contains(notes[0], name) {
					named++
				}
			}
			g.Expect(named).To(Equal(5), "the event names 5 of the 6 cases: %s", notes[0])
			g.Expect(notes[0]).NotTo(ContainSubstring(cases.Name(ids[0], manifest)))
		})
		Expect(agentQueue.of(key)()).To(BeEmpty())
	})

	It("judges a verdict judged elsewhere again under IfJudgedElsewhere, asking for one a second past it, and then reuses its own", func() {
		const theirs, nobodys, own = "CVE-2026-8101", "CVE-2026-8102", "CVE-2026-8103"
		manifest := newDigest()
		playbook := investigatedPlaybook(&configv1alpha1.PlaybookAgent{})
		runsInOtherCluster(manifest, inNamespace("team-a", map[inventoryv1alpha1.SSVCExposure]int32{inventoryv1alpha1.SSVCExposureOpen: 1}))
		ft, fn, fo := openFinding(theirs, "lib"), openFinding(nobodys, "lib"), openFinding(own, "lib")
		writeSheet(manifest, playbook, ft, fn, fo)
		for _, id := range []string{theirs, nobodys, own} {
			deleteAssessmentsAfterwards(id)
		}
		key := createDisabled(newNamespace(), "judged-elsewhere", playbook, 5, func(s *triagev1alpha1.InvestigationSpec) {
			s.Agent.JudgePolicy = ptr.To(triagev1alpha1.InvestigationJudgeIfJudgedElsewhere)
		})
		mine := referenceTo(key)
		before := investigationClock.Now().Add(-time.Hour).Truncate(time.Second)
		recordVerdictFor(theirs, manifest, ft, before, &triagev1alpha1.InvestigationReference{Namespace: key.Namespace,
			Name: anotherInvestigation, UID: anotherUID})
		recordVerdictFor(nobodys, manifest, fn, before.Add(-time.Minute), nil)
		recordVerdictFor(own, manifest, fo, before, mine)

		enable(key)

		Eventually(agentQueue.of(key), reaction, poll).Should(ConsistOf(cases.Name(theirs, manifest), cases.Name(nobodys, manifest)))
		Expect(agentQueue.judgedAfter(cases.Name(theirs, manifest))()).To(BeTemporally("==", before.Add(time.Second)))
		Expect(agentQueue.judgedAfter(cases.Name(nobodys, manifest))()).To(BeTemporally("==", before.Add(-time.Minute+time.Second)))
		expectInvestigation(key, metav1.ConditionTrue, triagev1alpha1.ReasonJudged, func(g Gomega, obj *triagev1alpha1.Investigation) {
			g.Expect(obj.Status.Cases).To(HaveValue(And(HaveField("Reused", HaveValue(Equal(int32(1)))),
				HaveField("Charged", HaveValue(Equal(int32(2)))), HaveField("JudgedElsewhere", HaveValue(BeZero())))))
		})

		By("reconciling again before the judgements land, which asks for the same")
		Eventually(func(g Gomega) {
			// A change of an Assessment of the playbook reconciles the investigation.
			a := assessmentOf(g, theirs, manifest)
			a.Labels["touched"] = "true"
			g.Expect(k8sClient.Update(ctx, a)).To(Succeed())
		}, reaction, poll).Should(Succeed())
		Consistently(agentQueue.judgedAfter(cases.Name(theirs, manifest)), quiet, poll).
			Should(BeTemporally("==", before.Add(time.Second)))

		By("landing the judgements, charged to the investigation, which reuses them and queues them no more")
		now := investigationClock.Now()
		recordVerdictFor(theirs, manifest, ft, now, mine)
		recordVerdictFor(nobodys, manifest, fn, now, mine)
		expectInvestigation(key, metav1.ConditionTrue, triagev1alpha1.ReasonJudged, func(g Gomega, obj *triagev1alpha1.Investigation) {
			g.Expect(obj.Status.Cases).To(HaveValue(And(HaveField("Judged", HaveValue(Equal(int32(2)))),
				HaveField("JudgedElsewhere", HaveValue(BeZero())))))
		})
		Consistently(func(g Gomega) {
			g.Expect(investigationOf(g, key).Status.Cases).To(HaveValue(HaveField("Charged", HaveValue(Equal(int32(2))))))
		}, quiet, poll).Should(Succeed())
		Expect(eventReasons(Default, key)).NotTo(ContainElement("JudgedElsewhere"))
	})

	// A verdict that the policy declines still shows, with its verdict, while the investigation can't queue its case: at
	// the cap, or once its run is over. It counts as judged elsewhere, not as over the cap.
	It("shows a verdict that IfJudgedElsewhere declines as reused while its case can't be queued: at the cap, or after the run", func() {
		const first, second = "CVE-2026-8301", "CVE-2026-8302"
		manifest := newDigest()
		playbook := investigatedPlaybook(&configv1alpha1.PlaybookAgent{})
		runsInOtherCluster(manifest, inNamespace("team-a", map[inventoryv1alpha1.SSVCExposure]int32{inventoryv1alpha1.SSVCExposureOpen: 1}))
		f1, f2 := openFinding(first, "lib"), openFinding(second, "lib")
		writeSheet(manifest, playbook, f1, f2)
		for _, id := range []string{first, second} {
			deleteAssessmentsAfterwards(id)
		}
		key := createDisabled(newNamespace(), "declined", playbook, 1, func(s *triagev1alpha1.InvestigationSpec) {
			s.Agent.JudgePolicy = ptr.To(triagev1alpha1.InvestigationJudgeIfJudgedElsewhere)
		})
		mine := referenceTo(key)
		other := &triagev1alpha1.InvestigationReference{Namespace: key.Namespace, Name: anotherInvestigation, UID: anotherUID}
		before := investigationClock.Now().Add(-time.Hour)
		recordVerdictFor(first, manifest, f1, before, other)
		recordVerdictFor(second, manifest, f2, before, other)
		findingOf := map[string]inventoryv1alpha1.Finding{first: f1, second: f2}
		bothShowTheirVerdict := func(g Gomega, obj *triagev1alpha1.Investigation) {
			g.Expect(obj.Status.Results).To(HaveLen(2))
			for _, r := range obj.Status.Results {
				g.Expect(r.Result).NotTo(Equal(triagev1alpha1.InvestigationResultSkip))
				g.Expect(r.Verdict).To(HaveValue(Equal(triagev1alpha1.VEXStatusAffected)), "the result of %s", r.VulnerabilityID)
			}
		}

		enable(key)

		By("queueing one case, which the cap has room for, and showing the other with its verdict")
		Eventually(agentQueue.of(key), reaction, poll).Should(HaveLen(1))
		queued := agentQueue.of(key)()[0]
		queuedID, otherID := first, second
		if queued == cases.Name(second, manifest) {
			queuedID, otherID = second, first
		}
		expectInvestigation(key, metav1.ConditionTrue, triagev1alpha1.ReasonJudged, func(g Gomega, obj *triagev1alpha1.Investigation) {
			g.Expect(obj.Status.Cases).To(HaveValue(And(HaveField("Charged", HaveValue(Equal(int32(1)))),
				HaveField("OverTheCap", HaveValue(BeZero())), HaveField("Reused", HaveValue(Equal(int32(1)))),
				HaveField("JudgedElsewhere", HaveValue(Equal(int32(1)))))))
			g.Expect(obj.Status.Results).To(ContainElement(And(HaveField("VulnerabilityID", otherID),
				HaveField("Verdict", HaveValue(Equal(triagev1alpha1.VEXStatusAffected))))))
			notes := eventNotes(g, key, "JudgedElsewhere")
			g.Expect(notes).NotTo(BeEmpty())
			g.Expect(notes[0]).To(ContainSubstring(cases.Name(otherID, manifest)))
			g.Expect(notes[0]).NotTo(ContainSubstring("Set spec.agent.judgePolicy"), "an investigation without guidance gets no hint")
		})

		By("landing the queued case's judgement, which ends the run, and then a newer verdict of it judged elsewhere")
		recordVerdictFor(queuedID, manifest, findingOf[queuedID], investigationClock.Now(), mine)
		expectInvestigation(key, metav1.ConditionTrue, triagev1alpha1.ReasonJudged, func(g Gomega, obj *triagev1alpha1.Investigation) {
			g.Expect(obj.Status.CompletionTime).NotTo(BeNil())
		})
		recordVerdictFor(queuedID, manifest, findingOf[queuedID], investigationClock.Now().Add(time.Minute), other)
		expectInvestigation(key, metav1.ConditionTrue, triagev1alpha1.ReasonJudged, func(g Gomega, obj *triagev1alpha1.Investigation) {
			g.Expect(obj.Status.Cases).To(HaveValue(And(HaveField("Charged", HaveValue(Equal(int32(1)))),
				HaveField("JudgedElsewhere", HaveValue(Equal(int32(2)))))))
			bothShowTheirVerdict(g, obj)
		})
		Expect(agentQueue.of(key)()).To(ConsistOf(queued), "the closed run queues nothing")
	})

	It("judges a verdict again under Always unless it was judged for the investigation in this run", func() {
		const earlier, inRun, elsewhereInRun = "CVE-2026-8201", "CVE-2026-8202", "CVE-2026-8203"
		manifest := newDigest()
		playbook := investigatedPlaybook(&configv1alpha1.PlaybookAgent{})
		runsInOtherCluster(manifest, inNamespace("team-a", map[inventoryv1alpha1.SSVCExposure]int32{inventoryv1alpha1.SSVCExposureOpen: 1}))
		fe, fr, fx := openFinding(earlier, "lib"), openFinding(inRun, "lib"), openFinding(elsewhereInRun, "lib")
		writeSheet(manifest, playbook, fe, fr, fx)
		for _, id := range []string{earlier, inRun, elsewhereInRun} {
			deleteAssessmentsAfterwards(id)
		}
		key := createDisabled(newNamespace(), "always", playbook, 5, func(s *triagev1alpha1.InvestigationSpec) {
			s.Agent.JudgePolicy = ptr.To(triagev1alpha1.InvestigationJudgeAlways)
		})
		mine := referenceTo(key)
		now := investigationClock.Now().Truncate(time.Second)
		recordVerdictFor(earlier, manifest, fe, now.Add(-time.Hour), mine)
		// Judged after the run's start, which is the clock's now.
		recordVerdictFor(inRun, manifest, fr, now.Add(time.Minute), mine)
		recordVerdictFor(elsewhereInRun, manifest, fx, now.Add(time.Minute), &triagev1alpha1.InvestigationReference{
			Namespace: key.Namespace, Name: anotherInvestigation, UID: anotherUID})

		enable(key)

		Eventually(agentQueue.of(key), reaction, poll).Should(ConsistOf(cases.Name(earlier, manifest),
			cases.Name(elsewhereInRun, manifest)))
		Expect(agentQueue.judgedAfter(cases.Name(earlier, manifest))()).To(BeTemporally("==", now.Add(-time.Hour+time.Second)))
		Expect(agentQueue.judgedAfter(cases.Name(elsewhereInRun, manifest))()).To(BeTemporally("==", now.Add(time.Minute+time.Second)))
		expectInvestigation(key, metav1.ConditionTrue, triagev1alpha1.ReasonJudged, func(g Gomega, obj *triagev1alpha1.Investigation) {
			g.Expect(obj.Status.Cases).To(HaveValue(And(HaveField("Charged", HaveValue(Equal(int32(2)))),
				HaveField("JudgedElsewhere", HaveValue(BeZero())))))
		})
	})

	// An investigation recreated under the same name is another object: a verdict judged for the earlier one isn't its
	// own, though the namespace and the name are the same.
	It("reuses a verdict judged for an earlier object of its name under IfStale, and counts and names it as earlier", func() {
		const id = "CVE-2026-8401"
		manifest := newDigest()
		playbook := investigatedPlaybook(&configv1alpha1.PlaybookAgent{})
		runsInOtherCluster(manifest, inNamespace("team-a", map[inventoryv1alpha1.SSVCExposure]int32{inventoryv1alpha1.SSVCExposureOpen: 1}))
		f := openFinding(id, "lib")
		writeSheet(manifest, playbook, f)
		deleteAssessmentsAfterwards(id)
		key := types.NamespacedName{Namespace: newNamespace(), Name: "recreated"}
		recordVerdictFor(id, manifest, f, investigationClock.Now().Add(-time.Hour), earlierObject(key))

		createInvestigation(key.Namespace, key.Name, playbook, 5, nil)

		expectInvestigation(key, metav1.ConditionTrue, triagev1alpha1.ReasonJudged, func(g Gomega, obj *triagev1alpha1.Investigation) {
			g.Expect(obj.Status.Cases).To(HaveValue(And(HaveField("Reused", HaveValue(Equal(int32(1)))),
				HaveField("JudgedElsewhere", HaveValue(Equal(int32(1)))))))
			notes := eventNotes(g, key, "JudgedElsewhere")
			g.Expect(notes).To(HaveLen(1))
			g.Expect(notes[0]).To(HavePrefix("1 selected cases reuse a verdict that was judged for an earlier recreated."))
		})
		Expect(agentQueue.of(key)()).To(BeEmpty())
	})

	It("judges a verdict of an earlier object of its name again under IfJudgedElsewhere", func() {
		const id = "CVE-2026-8402"
		manifest := newDigest()
		playbook := investigatedPlaybook(&configv1alpha1.PlaybookAgent{})
		runsInOtherCluster(manifest, inNamespace("team-a", map[inventoryv1alpha1.SSVCExposure]int32{inventoryv1alpha1.SSVCExposureOpen: 1}))
		f := openFinding(id, "lib")
		writeSheet(manifest, playbook, f)
		deleteAssessmentsAfterwards(id)
		key := types.NamespacedName{Namespace: newNamespace(), Name: "recreated-again"}
		recordVerdictFor(id, manifest, f, investigationClock.Now().Add(-time.Hour), earlierObject(key))

		createInvestigation(key.Namespace, key.Name, playbook, 5, func(s *triagev1alpha1.InvestigationSpec) {
			s.Agent.JudgePolicy = ptr.To(triagev1alpha1.InvestigationJudgeIfJudgedElsewhere)
		})

		Eventually(agentQueue.of(key), reaction, poll).Should(ConsistOf(cases.Name(id, manifest)))
	})
})
