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
	_, direct := startAPI(t)
	name := "team-" + rand.String(6)
	require.NoError(t, direct.Create(t.Context(), &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}))
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

// putSheet writes the sheet of a manifest, as the hub does, and deletes it when the test ends.
func putSheet(t *testing.T, manifest string, status inventoryv1alpha1.ImageVerdictsStatus) {
	t.Helper()
	_, direct := startAPI(t)
	verdicts := inventory.NewCRDVerdictsStore(direct, func() string { return clusterA })
	require.NoError(t, verdicts.Put(t.Context(), manifest, status))
	t.Cleanup(func() { assert.NoError(t, verdicts.Delete(context.Background(), manifest)) })
}

// reportOf returns the report of the namespace, or nil when there is none.
func reportOf(t *testing.T, namespace, name string) *triagev1alpha1.WorkloadReport {
	t.Helper()
	_, direct := startAPI(t)
	var report triagev1alpha1.WorkloadReport
	err := direct.Get(context.Background(), client.ObjectKey{Namespace: namespace, Name: name}, &report)
	if apierrors.IsNotFound(err) {
		return nil
	}
	require.NoError(t, err)
	return &report
}

// reportWhere waits until the report exists and holds, and returns it.
func reportWhere(t *testing.T, namespace, name string, holds func(*triagev1alpha1.WorkloadReport) bool) *triagev1alpha1.WorkloadReport {
	t.Helper()
	var report *triagev1alpha1.WorkloadReport
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
	s.presence.Snapshot("workloads", []cloudevents.Event{presenceEvent(t, digest, web)})
	setFacts(t, c, digest, manifestFacts(manifest))
	putSheet(t, manifest, sheetOf(manifest, 100, exploited(), openFinding("CVE-2026-0002", "libother")).Status)

	report := reportWhere(t, ns, "deployment-web", func(r *triagev1alpha1.WorkloadReport) bool {
		return len(r.Status.Actions) == 2
	})

	require.Equal(t, triagev1alpha1.WorkloadReportSpec{Workload: triagev1alpha1.WorkloadReference{
		APIGroup: ptr.To("apps"), Kind: deployment, Name: webName}}, report.Spec)
	require.Len(t, report.OwnerReferences, 1)
	require.Equal(t, "apps/v1", report.OwnerReferences[0].APIVersion)
	require.Equal(t, deployment, report.OwnerReferences[0].Kind)
	require.Equal(t, webName, report.OwnerReferences[0].Name)
	require.Equal(t, types.UID("uid-"+ns+"-web"), report.OwnerReferences[0].UID, "the workload owns its report, by its UID")
	require.Equal(t, map[string]string{"digest.vexplain.bedag.ch/" + strings.TrimPrefix(digest, "sha256:")[:63]: ""}, report.Labels)
	require.Equal(t, triagev1alpha1.SSVCOutcomeImmediate, report.Status.Actions[0].Urgency, "an unknown exposure counts as open")
	require.Equal(t, triagev1alpha1.NextStepUpdate, report.Status.Actions[0].Step)
	require.Equal(t, []string{digest}, report.Status.Actions[0].Digests)
	require.EqualValues(t, 2, *report.Status.Summary.Affected)
	require.Equal(t, ptr.To(triagev1alpha1.SSVCExposureUnknown), report.Status.Exposure)
	require.Nil(t, report.Status.Reach, "no collector says how far the workload is reached")
	require.Equal(t, ptr.To(manifest), report.Status.Images[0].ManifestDigest)
	require.Equal(t, triagev1alpha1.ReportImageStateReady, report.Status.Images[0].State)
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
	putSheet(t, manifest, sheetOf(manifest, 100, exploited()).Status)
	report := reportWhere(t, ns, "deployment-web", func(r *triagev1alpha1.WorkloadReport) bool { return len(r.Status.Actions) == 1 })

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
	reportWhere(t, ns, "deployment-web", func(r *triagev1alpha1.WorkloadReport) bool {
		return len(r.Status.Images) == 1 && r.Status.Images[0].State == triagev1alpha1.ReportImageStatePending
	})

	putSheet(t, manifest, sheetOf(manifest, 100, exploited()).Status)

	report := reportWhere(t, ns, "deployment-web", func(r *triagev1alpha1.WorkloadReport) bool { return len(r.Status.Actions) == 1 })
	require.Equal(t, triagev1alpha1.ReportImageStateReady, report.Status.Images[0].State)
}

func TestAWorkloadThatLeavesPresenceLosesItsReport(t *testing.T) {
	c := newCluster()
	ns := newNamespace(t)
	s := startReporting(t, c)
	digest := newDigest(t)
	web, api := running(ns, webName, linuxAMD64), running(ns, "api", linuxAMD64)
	s.presence.Snapshot("workloads", []cloudevents.Event{presenceEvent(t, digest, web, api)})
	reportWhere(t, ns, "deployment-web", func(*triagev1alpha1.WorkloadReport) bool { return true })
	reportWhere(t, ns, "deployment-api", func(*triagev1alpha1.WorkloadReport) bool { return true })

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
	report := reportWhere(t, ns, "deployment-web", func(*triagev1alpha1.WorkloadReport) bool { return true })
	_, direct := startAPI(t)

	require.NoError(t, direct.Delete(t.Context(), report))

	reportWhere(t, ns, "deployment-web", func(r *triagev1alpha1.WorkloadReport) bool { return r.UID != report.UID })
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
	putSheet(t, manifest, sheetOf(manifest, 100, exploited()).Status)
	report := reportWhere(t, ns, "deployment-web", func(r *triagev1alpha1.WorkloadReport) bool { return len(r.Status.Actions) == 1 })
	before.stop()
	// The sheet changes while the operator is down, so a render would rewrite the report.
	putSheet(t, manifest, sheetOf(manifest, 100, exploited(), openFinding("CVE-2026-0002", "libother")).Status)

	after := startReporting(t, c)

	require.Never(t, func() bool {
		now := reportOf(t, ns, "deployment-web")
		return now == nil || now.ResourceVersion != report.ResourceVersion
	}, quiet, tick, "the report stays as it was until presence has its first complete snapshot")

	after.presence.Snapshot("workloads", []cloudevents.Event{presenceEvent(t, digest, web)})

	reportWhere(t, ns, "deployment-web", func(r *triagev1alpha1.WorkloadReport) bool { return len(r.Status.Actions) == 2 })
}

func TestAfterAStartAReportOfAWorkloadThatIsGoneIsDeletedAtTheFirstSnapshot(t *testing.T) {
	c := newCluster()
	ns := newNamespace(t)
	digest := newDigest(t)
	before := startReporting(t, c)
	before.presence.Snapshot("workloads", []cloudevents.Event{presenceEvent(t, digest, running(ns, webName, linuxAMD64))})
	reportWhere(t, ns, "deployment-web", func(*triagev1alpha1.WorkloadReport) bool { return true })
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
	putSheet(t, manifest, sheetOf(manifest, 100, exploited()).Status)
	small := reportWhere(t, ns, "deployment-web", func(r *triagev1alpha1.WorkloadReport) bool {
		return len(r.Status.Actions) == 1 && ptr.Equal(r.Status.Exposure, ptr.To(triagev1alpha1.SSVCExposureSmall))
	})
	require.Equal(t, &triagev1alpha1.ReportReach{InternalReach: triagev1alpha1.InternalReachNamespace,
		Indirect: triagev1alpha1.IndirectExposureNotIndirect}, small.Status.Reach, "the reach that the collector gave")
	before.stop()
	smallUrgency := small.Status.Actions[0].Urgency
	openUrgency := triagev1alpha1.SSVCOutcome(urgency.Decide(urgency.FromFinding(exploited(), configv1alpha1.SSVCExposureOpen), nil))
	require.NotEqual(t, openUrgency, smallUrgency, "the exposure changes the urgency of this finding")

	after := startReporting(t, c)
	after.sees(t, exposureCollector)
	after.presence.Snapshot("workloads", []cloudevents.Event{presenceEvent(t, digest, web, api)})

	fresh := reportWhere(t, ns, "deployment-api", func(r *triagev1alpha1.WorkloadReport) bool { return len(r.Status.Actions) == 1 })
	require.Equal(t, ptr.To(triagev1alpha1.SSVCExposureUnknown), fresh.Status.Exposure, "a new report has no exposure to keep")
	require.Nil(t, fresh.Status.Reach, "nor a reach")
	require.Never(t, func() bool {
		now := reportOf(t, ns, "deployment-web")
		return now == nil || now.ResourceVersion != small.ResourceVersion
	}, quiet, tick, "the report of web keeps its exposure and reach, and its actions' urgency")

	after.exposure.Snapshot(exposureCollector, []cloudevents.Event{
		exposureFor(t, web, evidence.Exposure{External: exposed.External, InternalReach: reachCluster, Indirect: true}),
		exposureFor(t, api, reach("Namespace"))})

	now := reportWhere(t, ns, "deployment-web", func(r *triagev1alpha1.WorkloadReport) bool {
		return ptr.Equal(r.Status.Exposure, ptr.To(triagev1alpha1.SSVCExposureOpen))
	})
	require.Equal(t, openUrgency, now.Status.Actions[0].Urgency, "it takes the new exposure, and the urgency that goes with it")
	require.Equal(t, &triagev1alpha1.ReportReach{InternalReach: triagev1alpha1.InternalReachCluster,
		Indirect: triagev1alpha1.IndirectExposureIndirect}, now.Status.Reach, "and the new reach")
	reportWhere(t, ns, "deployment-api", func(r *triagev1alpha1.WorkloadReport) bool {
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

	report := reportWhere(t, ns, "deployment-web", func(r *triagev1alpha1.WorkloadReport) bool { return len(r.Status.Images) > 0 })
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
	reportWhere(t, ns, "deployment-a", func(*triagev1alpha1.WorkloadReport) bool { return true })
	reportBefore := reportWhere(t, ns, "deployment-b", func(*triagev1alpha1.WorkloadReport) bool { return true })
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
