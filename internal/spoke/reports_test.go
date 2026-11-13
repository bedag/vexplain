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

package spoke_test

import (
	"context"
	"fmt"
	"maps"
	"strings"
	"testing"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	triagev1alpha1 "github.com/bedag/vexplain/api/triage/v1alpha1"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/urgency"
	"github.com/bedag/vexplain/sdk/evidence"
)

// The tests of the reports run the spoke's renderer in a manager, as the operator's process runs it, against an API server of
// envtest. They hand Presence and Exposure what the streams would, and write the facts and the sheets that the hub would.
// Each test has a namespace of its own, so that no report of another test is the renderer's to delete.

// newNamespace creates a namespace that no other test has, for the workloads of a test.
func newNamespace(t *testing.T) string {
	t.Helper()
	return labelledNamespace(t, nil)
}

// labelledNamespace creates a namespace with the labels that no other test has, for the workloads of a test.
func labelledNamespace(t *testing.T, labels map[string]string) string {
	t.Helper()
	_, direct := startAPI(t)
	name := "team-" + rand.String(6)
	require.NoError(t, direct.Create(t.Context(), &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels}}))
	return name
}

// startReporting starts a spoke of the cluster that also renders the reports.
func startReporting(t *testing.T, c cluster) *spokeOf {
	t.Helper()
	return startSpokeWith(t, func() cluster { return c }, true)
}

// setFacts gives the image the facts that the hub's collectors would have recorded, once its object exists.
func setFacts(t *testing.T, c cluster, digest string, facts *inventoryv1alpha1.ImageFacts) {
	t.Helper()
	present(t, c, digest)
	_, direct := startAPI(t)
	exists, err := inventory.NewCRDStore(direct, nil, func() string { return c.name }).SetFacts(t.Context(), digest, facts)
	require.NoError(t, err)
	require.True(t, exists)
}

// defaultPlaybook is the playbook of the sheets that the tests write, unless they name another. The API server of the
// tests has it from its start.
const defaultPlaybook = "container-cves"

// playbookOf returns a playbook of the images in presence with the name, as the hub's admin writes one. It matches
// every cluster and namespace.
func playbookOf(name string) *configv1alpha1.Playbook {
	return &configv1alpha1.Playbook{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: configv1alpha1.PlaybookSpec{
			Subjects: configv1alpha1.PlaybookSource{Type: evidence.TypePresence},
			Findings: configv1alpha1.PlaybookFindings{Type: ptr.To(evidence.TypeFindings)},
			Pipeline: []configv1alpha1.PlaybookStep{{Rule: "known-exploited"}},
		},
	}
}

// putSheet writes the default playbook's sheet of a manifest, as the hub does, and deletes it when the test ends.
func putSheet(t *testing.T, manifest string, status inventoryv1alpha1.ImageVerdictsStatus) {
	t.Helper()
	putSheetOf(t, manifest, defaultPlaybook, status)
}

// stageKey is the label of the namespaces that the playbooks of the tests select. Each test selects values of its
// own, so that no other test's namespace has them.
const stageKey = "stage"

// createPlaybook creates a playbook of the images in presence with the name, which selects the namespaces whose stage
// is the value, and deletes it when the test ends.
func createPlaybook(t *testing.T, name, stage string) *configv1alpha1.Playbook {
	t.Helper()
	_, direct := startAPI(t)
	playbook := playbookOf(name)
	playbook.Spec.Match = &configv1alpha1.PlaybookMatch{
		Namespaces: &metav1.LabelSelector{MatchLabels: map[string]string{stageKey: stage}}}
	require.NoError(t, direct.Create(t.Context(), playbook))
	t.Cleanup(func() { assert.NoError(t, client.IgnoreNotFound(direct.Delete(context.Background(), playbook))) })
	return playbook
}

// putSheetOf writes the sheet of a manifest under the playbook, as the hub does, and deletes it when the test ends.
func putSheetOf(t *testing.T, manifest, playbook string, status inventoryv1alpha1.ImageVerdictsStatus) {
	t.Helper()
	_, direct := startAPI(t)
	verdicts := inventory.NewCRDVerdictsStore(direct, func() string { return clusterA })
	require.NoError(t, verdicts.Put(t.Context(), manifest, playbook, status))
	t.Cleanup(func() { assert.NoError(t, verdicts.Delete(context.Background(), manifest, playbook)) })
}

// reportOf returns the report of the namespace, or nil when there is none.
func reportOf(t *testing.T, namespace, name string) *triagev1alpha1.ResourceReport {
	t.Helper()
	_, direct := startAPI(t)
	var report triagev1alpha1.ResourceReport
	err := direct.Get(context.Background(), client.ObjectKey{Namespace: namespace, Name: name}, &report)
	if apierrors.IsNotFound(err) {
		return nil
	}
	require.NoError(t, err)
	return &report
}

// reportWhere waits until the report exists and holds, and returns it.
func reportWhere(t *testing.T, namespace, name string, holds func(*triagev1alpha1.ResourceReport) bool) *triagev1alpha1.ResourceReport {
	t.Helper()
	var report *triagev1alpha1.ResourceReport
	require.Eventually(t, func() bool {
		report = reportOf(t, namespace, name)
		return report != nil && holds(report)
	}, wait, tick, "the report %s/%s", namespace, name)
	return report
}

// noReport waits until there is no report of the name.
func noReport(t *testing.T, namespace, name string) {
	t.Helper()
	require.Eventually(t, func() bool { return reportOf(t, namespace, name) == nil }, wait, tick,
		"no report %s/%s", namespace, name)
}

// The facts of an image with a manifest for amd64, and the finding that its sheet holds.
func manifestFacts(manifest string) *inventoryv1alpha1.ImageFacts {
	return &inventoryv1alpha1.ImageFacts{Manifests: []inventoryv1alpha1.ManifestFact{{Platform: linuxAMD64, Digest: manifest}}}
}

// exploited returns a finding on the list of known exploited vulnerabilities, whose urgency moves with the exposure.
func exploited() inventoryv1alpha1.Finding {
	f := openFinding("CVE-2026-0001", "libexample")
	f.KnownExploited = inventoryv1alpha1.KnownExploitedListed
	return f
}

func TestAWorkloadWithASheetGetsAReportOwnedByItWithItsActions(t *testing.T) {
	c := newCluster()
	ns := newNamespace(t)
	s := startReporting(t, c)
	digest, manifest := newDigest(t), newDigest(t)
	web := running(ns, webName, linuxAMD64)
	web.Labels = []evidence.KeyValue{{Key: teamLabel, Value: teamA}}
	web.Pods[0].Containers = []evidence.PresenceContainer{{Name: webName, Kind: regularContainer}}
	s.presence.Snapshot("workloads", []cloudevents.Event{presenceEvent(t, digest, web)})
	setFacts(t, c, digest, manifestFacts(manifest))
	putSheet(t, manifest, sheetOf(manifest, exploited(), openFinding("CVE-2026-0002", "libother")).Status)

	report := reportWhere(t, ns, "deployment-web", func(r *triagev1alpha1.ResourceReport) bool {
		return len(r.Status.Actions) == 2
	})

	require.Equal(t, triagev1alpha1.ResourceReportSpec{Resource: triagev1alpha1.ResourceReference{
		APIGroup: ptr.To("apps"), Kind: deployment, Name: webName}}, report.Spec)
	require.Len(t, report.OwnerReferences, 1)
	require.Equal(t, "apps/v1", report.OwnerReferences[0].APIVersion)
	require.Equal(t, deployment, report.OwnerReferences[0].Kind)
	require.Equal(t, webName, report.OwnerReferences[0].Name)
	require.Equal(t, types.UID("uid-"+ns+"-web"), report.OwnerReferences[0].UID, "the workload owns its report, by its UID")
	require.Equal(t, map[string]string{"digest.vexplain.bedag.ch/" + strings.TrimPrefix(digest, "sha256:")[:63]: ""}, report.Labels)
	require.Equal(t, ptr.To(triagev1alpha1.SSVCOutcomeImmediate), report.Status.Actions[0].Urgency, "an unknown exposure counts as open")
	require.Equal(t, triagev1alpha1.ResourceStepUpdate, report.Status.Actions[0].Step)
	require.Equal(t, ptr.To(digest), report.Status.Actions[0].Digest)
	require.Equal(t, triagev1alpha1.ResourceRequirement{Playbook: defaultPlaybook}, report.Status.Actions[0].Requirement)
	require.Equal(t, []string{webLocation}, report.Status.Actions[0].Locations)
	require.EqualValues(t, 2, *report.Status.Summary.Updates)
	require.Equal(t, ptr.To(triagev1alpha1.SSVCExposureUnknown), report.Status.Exposure)
	require.Nil(t, report.Status.Reach, "no collector says how far the workload is reached")
	require.Equal(t, []string{manifest}, report.Status.Images[0].ManifestDigests)
	require.Equal(t, triagev1alpha1.ResourceImageStateReady, report.Status.Images[0].State)
	require.Equal(t, []string{webName}, report.Status.Images[0].Containers)
	require.Equal(t, []triagev1alpha1.OwnerValue{{Source: triagev1alpha1.OwnerSourceWorkloadLabel, Key: teamLabel,
		Value: ptr.To(teamA)}}, report.Status.Owner)
}

// A report is written only when its status changes.
func TestAReportIsWrittenOnlyWhenItsStatusChanges(t *testing.T) {
	c := newCluster()
	ns := newNamespace(t)
	s := startReporting(t, c)
	digest, manifest := newDigest(t), newDigest(t)
	web := running(ns, webName, linuxAMD64)
	s.presence.Snapshot("workloads", []cloudevents.Event{presenceEvent(t, digest, web)})
	setFacts(t, c, digest, manifestFacts(manifest))
	putSheet(t, manifest, sheetOf(manifest, exploited()).Status)
	report := reportWhere(t, ns, "deployment-web", func(r *triagev1alpha1.ResourceReport) bool { return len(r.Status.Actions) == 1 })

	s.presence.Upsert("workloads", presenceEvent(t, digest, web))
	s.presence.Snapshot("workloads", []cloudevents.Event{presenceEvent(t, digest, web)})

	require.Never(t, func() bool { return reportOf(t, ns, "deployment-web").ResourceVersion != report.ResourceVersion }, quiet, tick,
		"the same status is no write")
}

func TestAReportFollowsItsSheet(t *testing.T) {
	c := newCluster()
	ns := newNamespace(t)
	s := startReporting(t, c)
	digest, manifest := newDigest(t), newDigest(t)
	s.presence.Snapshot("workloads", []cloudevents.Event{presenceEvent(t, digest, running(ns, webName, linuxAMD64))})
	setFacts(t, c, digest, manifestFacts(manifest))
	reportWhere(t, ns, "deployment-web", func(r *triagev1alpha1.ResourceReport) bool {
		return len(r.Status.Images) == 1 && r.Status.Images[0].State == triagev1alpha1.ResourceImageStatePending
	})

	putSheet(t, manifest, sheetOf(manifest, exploited()).Status)

	report := reportWhere(t, ns, "deployment-web", func(r *triagev1alpha1.ResourceReport) bool { return len(r.Status.Actions) == 1 })
	require.Equal(t, triagev1alpha1.ResourceImageStateReady, report.Status.Images[0].State)
}

// A report follows what set its workload's reach and what the collector couldn't evaluate, also where its exposure and
// its reach stay as they were.
func TestAReportFollowsWhatSetItsReach(t *testing.T) {
	c := newCluster()
	ns := newNamespace(t)
	exposureCollector := newCollector(t, evidence.TypeExposure)
	s := startReporting(t, c)
	s.sees(t, exposureCollector)
	web := running(ns, webName, linuxAMD64)
	noPolicy := evidence.Widening{Kind: kindNamespace, Name: ns, Reason: "no policy in the namespace"}
	s.exposure.Snapshot(exposureCollector, []cloudevents.Event{exposureFor(t, web, evidence.Exposure{
		InternalReach: reachCluster, WidenedBy: []evidence.Widening{noPolicy}})})
	s.presence.Snapshot("workloads", []cloudevents.Event{presenceEvent(t, newDigest(t), web)})
	reportWhere(t, ns, "deployment-web", func(r *triagev1alpha1.ResourceReport) bool {
		return r.Status.Reach != nil && len(r.Status.Reach.WidenedBy) == 1
	})

	s.exposure.Upsert(exposureCollector, exposureFor(t, web, evidence.Exposure{InternalReach: reachCluster,
		WidenedBy: []evidence.Widening{{Kind: kindNetworkPolicy, Namespace: ns, Name: webName, Rule: ptr.To[int32](0),
			Reason: "lets in an IP block, which can hold any address"}},
		Unseen: []string{evidence.UnseenIPBlock}}))

	report := reportWhere(t, ns, "deployment-web", func(r *triagev1alpha1.ResourceReport) bool {
		return r.Status.Reach != nil && len(r.Status.Reach.Unseen) == 1
	})
	require.Equal(t, &triagev1alpha1.ReportReach{
		InternalReach: triagev1alpha1.InternalReachCluster, Indirect: triagev1alpha1.IndirectExposureNotIndirect,
		WidenedBy: []triagev1alpha1.ReachWidening{{Kind: kindNetworkPolicy, Namespace: ptr.To(ns), Name: webName,
			Rule: ptr.To[int32](0), Reason: "lets in an IP block, which can hold any address"}},
		Unseen: []triagev1alpha1.ReachUnseen{triagev1alpha1.ReachUnseenIPBlock},
	}, report.Status.Reach)
	require.Equal(t, ptr.To(triagev1alpha1.SSVCExposureControlled), report.Status.Exposure)
}

// playbooksOf returns the playbook of each action of a report, by the name of its package.
func playbooksOf(r *triagev1alpha1.ResourceReport) map[string]string {
	out := map[string]string{}
	for _, a := range r.Status.Actions {
		out[a.Package.Name] = a.Requirement.Playbook
	}
	return out
}

// A report holds the results of every playbook whose namespace selector selects the labels of its namespace, each action
// naming its playbook, and nothing of a playbook that leaves the namespace out. When the labels of the namespace change,
// its reports hold the results of the playbooks that select it now.
func TestAReportHoldsTheResultsOfThePlaybooksThatSelectItsNamespaceAndFollowsItsLabels(t *testing.T) {
	suffix := rand.String(6)
	prod, dev := "prod-"+suffix, "dev-"+suffix
	strict, lenient := createPlaybook(t, "strict-"+suffix, prod).Name, createPlaybook(t, "lenient-"+suffix, dev).Name
	c := newCluster()
	ns := labelledNamespace(t, map[string]string{stageKey: prod})
	s := startReporting(t, c)
	digest, manifest := newDigest(t), newDigest(t)
	s.presence.Snapshot("workloads", []cloudevents.Event{presenceEvent(t, digest, running(ns, webName, linuxAMD64))})
	setFacts(t, c, digest, manifestFacts(manifest))
	putSheet(t, manifest, sheetOf(manifest, exploited()).Status)
	putSheetOf(t, manifest, strict, playbookSheet(strict, manifest, openFinding("CVE-2026-0002", "libstrict")).Status)
	putSheetOf(t, manifest, lenient, playbookSheet(lenient, manifest, openFinding("CVE-2026-0003", "liblenient")).Status)

	report := reportWhere(t, ns, "deployment-web", func(r *triagev1alpha1.ResourceReport) bool {
		return len(r.Status.Actions) == 2
	})
	require.Equal(t, map[string]string{libExample: defaultPlaybook, "libstrict": strict}, playbooksOf(report),
		"the default playbook, which selects every namespace, and the strict one, which selects prod")
	require.Equal(t, triagev1alpha1.ResourceImageStateReady, report.Status.Images[0].State)

	_, direct := startAPI(t)
	namespace := &corev1.Namespace{}
	require.NoError(t, direct.Get(t.Context(), client.ObjectKey{Name: ns}, namespace))
	patch := client.MergeFrom(namespace.DeepCopy())
	namespace.Labels[stageKey] = dev
	require.NoError(t, direct.Patch(t.Context(), namespace, patch))

	reportWhere(t, ns, "deployment-web", func(r *triagev1alpha1.ResourceReport) bool {
		return maps.Equal(map[string]string{libExample: defaultPlaybook, "liblenient": lenient}, playbooksOf(r))
	})
}

// A playbook that begins to select a namespace has no verdict on its images until the hub has judged them, so they wait
// for it, and once the playbook is gone, they don't.
func TestAPlaybookThatComesOrGoesRendersTheReportsAgain(t *testing.T) {
	stage := "late-" + rand.String(6)
	c := newCluster()
	ns := labelledNamespace(t, map[string]string{stageKey: stage})
	s := startReporting(t, c)
	digest, manifest := newDigest(t), newDigest(t)
	s.presence.Snapshot("workloads", []cloudevents.Event{presenceEvent(t, digest, running(ns, webName, linuxAMD64))})
	setFacts(t, c, digest, manifestFacts(manifest))
	putSheet(t, manifest, sheetOf(manifest, exploited()).Status)
	stateIs := func(state triagev1alpha1.ResourceImageState) func(*triagev1alpha1.ResourceReport) bool {
		return func(r *triagev1alpha1.ResourceReport) bool {
			return len(r.Status.Actions) == 1 && len(r.Status.Images) == 1 && r.Status.Images[0].State == state
		}
	}
	reportWhere(t, ns, "deployment-web", stateIs(triagev1alpha1.ResourceImageStateReady))

	playbook := createPlaybook(t, stage, stage)

	report := reportWhere(t, ns, "deployment-web", stateIs(triagev1alpha1.ResourceImageStatePending))
	require.Equal(t, ptr.To(int32(1)), report.Status.Summary.PendingImages)

	_, direct := startAPI(t)
	require.NoError(t, direct.Delete(t.Context(), playbook))

	reportWhere(t, ns, "deployment-web", stateIs(triagev1alpha1.ResourceImageStateReady))
}

// A Playbook takes any name, the name of the renderer's own request for the counts too, and a change of its spec renders
// the reports again all the same: here its namespace selector, which begins to select a namespace.
func TestAPlaybookNamedAsTheRenderersCountsRendersTheReportsAgain(t *testing.T) {
	stage := "counted-" + rand.String(6)
	c := newCluster()
	ns := labelledNamespace(t, map[string]string{stageKey: stage})
	s := startReporting(t, c)
	digest, manifest := newDigest(t), newDigest(t)
	s.presence.Snapshot("workloads", []cloudevents.Event{presenceEvent(t, digest, running(ns, webName, linuxAMD64))})
	setFacts(t, c, digest, manifestFacts(manifest))
	putSheet(t, manifest, sheetOf(manifest, exploited()).Status)
	stateIs := func(state triagev1alpha1.ResourceImageState) func(*triagev1alpha1.ResourceReport) bool {
		return func(r *triagev1alpha1.ResourceReport) bool {
			return len(r.Status.Images) == 1 && r.Status.Images[0].State == state
		}
	}
	playbook := createPlaybook(t, "counts", "elsewhere-"+rand.String(6))
	reportWhere(t, ns, "deployment-web", stateIs(triagev1alpha1.ResourceImageStateReady))

	_, direct := startAPI(t)
	patch := client.MergeFrom(playbook.DeepCopy())
	playbook.Spec.Match.Namespaces.MatchLabels[stageKey] = stage
	require.NoError(t, direct.Patch(t.Context(), playbook, patch))

	reportWhere(t, ns, "deployment-web", stateIs(triagev1alpha1.ResourceImageStatePending))
}

func TestAWorkloadThatLeavesPresenceLosesItsReport(t *testing.T) {
	c := newCluster()
	ns := newNamespace(t)
	s := startReporting(t, c)
	digest := newDigest(t)
	web, api := running(ns, webName, linuxAMD64), running(ns, "api", linuxAMD64)
	s.presence.Snapshot("workloads", []cloudevents.Event{presenceEvent(t, digest, web, api)})
	reportWhere(t, ns, "deployment-web", func(*triagev1alpha1.ResourceReport) bool { return true })
	reportWhere(t, ns, "deployment-api", func(*triagev1alpha1.ResourceReport) bool { return true })

	s.presence.Snapshot("workloads", []cloudevents.Event{presenceEvent(t, digest, api)})

	noReport(t, ns, "deployment-web")
	require.NotNil(t, reportOf(t, ns, "deployment-api"), "the other workload keeps its report")

	s.presence.Snapshot("workloads", nil)

	noReport(t, ns, "deployment-api")
}

func TestAReportThatSomeoneDeletedComesBack(t *testing.T) {
	c := newCluster()
	ns := newNamespace(t)
	s := startReporting(t, c)
	digest := newDigest(t)
	s.presence.Snapshot("workloads", []cloudevents.Event{presenceEvent(t, digest, running(ns, webName, linuxAMD64))})
	report := reportWhere(t, ns, "deployment-web", func(*triagev1alpha1.ResourceReport) bool { return true })
	_, direct := startAPI(t)

	require.NoError(t, direct.Delete(t.Context(), report))

	reportWhere(t, ns, "deployment-web", func(r *triagev1alpha1.ResourceReport) bool { return r.UID != report.UID })
}

// After a start, presence knows no workload until its first complete snapshot, so a report that it doesn't know the
// workload of yet isn't one that is stale. The renderer writes and deletes nothing until then.
func TestAfterAStartNoReportIsDeletedOrRewrittenBeforePresencesFirstSnapshot(t *testing.T) {
	c := newCluster()
	ns := newNamespace(t)
	digest, manifest := newDigest(t), newDigest(t)
	web := running(ns, webName, linuxAMD64)
	before := startReporting(t, c)
	before.presence.Snapshot("workloads", []cloudevents.Event{presenceEvent(t, digest, web)})
	setFacts(t, c, digest, manifestFacts(manifest))
	putSheet(t, manifest, sheetOf(manifest, exploited()).Status)
	report := reportWhere(t, ns, "deployment-web", func(r *triagev1alpha1.ResourceReport) bool { return len(r.Status.Actions) == 1 })
	before.stop()
	// The sheet changes while the operator is down, so a render would rewrite the report.
	putSheet(t, manifest, sheetOf(manifest, exploited(), openFinding("CVE-2026-0002", "libother")).Status)

	after := startReporting(t, c)

	require.Never(t, func() bool {
		now := reportOf(t, ns, "deployment-web")
		return now == nil || now.ResourceVersion != report.ResourceVersion
	}, quiet, tick, "the report stays as it was until presence has its first complete snapshot")

	after.presence.Snapshot("workloads", []cloudevents.Event{presenceEvent(t, digest, web)})

	reportWhere(t, ns, "deployment-web", func(r *triagev1alpha1.ResourceReport) bool { return len(r.Status.Actions) == 2 })
}

func TestAfterAStartAReportOfAWorkloadThatIsGoneIsDeletedAtTheFirstSnapshot(t *testing.T) {
	c := newCluster()
	ns := newNamespace(t)
	digest := newDigest(t)
	before := startReporting(t, c)
	before.presence.Snapshot("workloads", []cloudevents.Event{presenceEvent(t, digest, running(ns, webName, linuxAMD64))})
	reportWhere(t, ns, "deployment-web", func(*triagev1alpha1.ResourceReport) bool { return true })
	before.stop()

	after := startReporting(t, c)
	require.Never(t, func() bool { return reportOf(t, ns, "deployment-web") == nil }, quiet, tick)
	after.presence.Snapshot("workloads", nil)

	noReport(t, ns, "deployment-web")
}

// After a start, exposure knows each workload at the first snapshot of its collector. A report keeps its exposure until
// then, and so the urgency of its findings, where a render would take Unknown for it, which counts as open. A new report
// has Unknown.
func TestAfterAStartAReportKeepsItsExposureUntilTheExposureCollectorsFirstSnapshot(t *testing.T) {
	c := newCluster()
	ns := newNamespace(t)
	exposureCollector := newCollector(t, evidence.TypeExposure)
	digest, manifest := newDigest(t), newDigest(t)
	web, api := running(ns, webName, linuxAMD64), running(ns, "api", linuxAMD64)
	before := startReporting(t, c)
	before.sees(t, exposureCollector)
	before.exposure.Snapshot(exposureCollector, []cloudevents.Event{exposureFor(t, web, reach("Namespace"))})
	before.presence.Snapshot("workloads", []cloudevents.Event{presenceEvent(t, digest, web)})
	setFacts(t, c, digest, manifestFacts(manifest))
	putSheet(t, manifest, sheetOf(manifest, exploited()).Status)
	small := reportWhere(t, ns, "deployment-web", func(r *triagev1alpha1.ResourceReport) bool {
		return len(r.Status.Actions) == 1 && ptr.Equal(r.Status.Exposure, ptr.To(triagev1alpha1.SSVCExposureSmall))
	})
	require.Equal(t, &triagev1alpha1.ReportReach{InternalReach: triagev1alpha1.InternalReachNamespace,
		Indirect: triagev1alpha1.IndirectExposureNotIndirect}, small.Status.Reach, "the reach that the collector gave")
	before.stop()
	smallUrgency := *small.Status.Actions[0].Urgency
	openUrgency := triagev1alpha1.SSVCOutcome(urgency.Decide(urgency.FromFinding(exploited(), configv1alpha1.SSVCExposureOpen), nil))
	require.NotEqual(t, openUrgency, smallUrgency, "the exposure changes the urgency of this finding")

	after := startReporting(t, c)
	after.sees(t, exposureCollector)
	after.presence.Snapshot("workloads", []cloudevents.Event{presenceEvent(t, digest, web, api)})

	fresh := reportWhere(t, ns, "deployment-api", func(r *triagev1alpha1.ResourceReport) bool { return len(r.Status.Actions) == 1 })
	require.Equal(t, ptr.To(triagev1alpha1.SSVCExposureUnknown), fresh.Status.Exposure, "a new report has no exposure to keep")
	require.Nil(t, fresh.Status.Reach, "nor a reach")
	require.Never(t, func() bool {
		now := reportOf(t, ns, "deployment-web")
		return now == nil || now.ResourceVersion != small.ResourceVersion
	}, quiet, tick, "the report of web keeps its exposure and reach, and its actions' urgency")

	after.exposure.Snapshot(exposureCollector, []cloudevents.Event{
		exposureFor(t, web, evidence.Exposure{External: exposed.External, InternalReach: reachCluster, Indirect: true}),
		exposureFor(t, api, reach("Namespace"))})

	now := reportWhere(t, ns, "deployment-web", func(r *triagev1alpha1.ResourceReport) bool {
		return ptr.Equal(r.Status.Exposure, ptr.To(triagev1alpha1.SSVCExposureOpen))
	})
	require.Equal(t, ptr.To(openUrgency), now.Status.Actions[0].Urgency, "it takes the new exposure, and the urgency that goes with it")
	require.Equal(t, &triagev1alpha1.ReportReach{InternalReach: triagev1alpha1.InternalReachCluster,
		Indirect: triagev1alpha1.IndirectExposureIndirect}, now.Status.Reach, "and the new reach")
	reportWhere(t, ns, "deployment-api", func(r *triagev1alpha1.ResourceReport) bool {
		return ptr.Equal(r.Status.Exposure, ptr.To(triagev1alpha1.SSVCExposureSmall))
	})
}

// The labels of a report name every image of the workload, also those past the 32 entries of its list.
func TestAReportHasADigestLabelForEveryImageAndAtMost32Entries(t *testing.T) {
	c := newCluster()
	ns := newNamespace(t)
	s := startReporting(t, c)
	web := running(ns, webName, linuxAMD64)
	events := make([]cloudevents.Event, 0, 40)
	for i := range 40 {
		// Digests that differ in their first digits, since a label holds only the first 63.
		digest := fmt.Sprintf("sha256:%02x%062d", i+1, 0)
		events = append(events, presenceEvent(t, digest, web))
	}

	s.presence.Snapshot(workloadsName, events)

	report := reportWhere(t, ns, "deployment-web", func(r *triagev1alpha1.ResourceReport) bool { return len(r.Status.Images) > 0 })
	require.Len(t, report.Status.Images, 32)
	require.Len(t, report.Labels, 40)
}

// After a start, presence knows what runs only once every collector that streams presence has sent its first snapshot.
// Until then nothing is forgotten, and no report is written or deleted: the first collector's snapshot doesn't name the
// workloads that only the second names.
func TestAfterAStartNothingIsForgottenOrDeletedBeforeEveryPresenceCollectorHasSentItsSnapshot(t *testing.T) {
	c := newCluster()
	ns := newNamespace(t)
	second := newCollector(t, evidence.TypePresence)
	digestA, digestB, stale := newDigest(t), newDigest(t), newDigest(t)
	a, b := running(ns, "a", linuxAMD64), running(ns, "b", linuxAMD64)
	before := startReporting(t, c)
	before.sees(t, second)
	before.presence.Snapshot(workloadsName, []cloudevents.Event{presenceEvent(t, digestA, a)})
	before.presence.Snapshot(second, []cloudevents.Event{presenceEvent(t, digestB, b)})
	reportWhere(t, ns, "deployment-a", func(*triagev1alpha1.ResourceReport) bool { return true })
	reportBefore := reportWhere(t, ns, "deployment-b", func(*triagev1alpha1.ResourceReport) bool { return true })
	present(t, c, digestB)
	observe(t, c, stale)
	before.stop()

	after := startReporting(t, c)
	after.sees(t, second)
	after.presence.Snapshot(workloadsName, []cloudevents.Event{presenceEvent(t, digestA, a)})

	require.Never(t, func() bool {
		now := reportOf(t, ns, "deployment-b")
		return now == nil || now.ResourceVersion != reportBefore.ResourceVersion || entryOf(t, c, digestB) == nil ||
			entryOf(t, c, stale) == nil
	}, quiet, tick, "with the second collector's snapshot missing, the entry and the report of its image stay, and so does the stale one")

	after.presence.Snapshot(second, []cloudevents.Event{presenceEvent(t, digestB, b)})

	absent(t, c, stale)
	stays(t, c, digestB, true)
	require.NotNil(t, reportOf(t, ns, "deployment-a"))
	require.NotNil(t, reportOf(t, ns, "deployment-b"))
}
