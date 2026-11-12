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
	"testing"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/settings"
	"github.com/bedag/vexplain/sdk/evidence"
)

// The tests of the counts run the renderer as the reports' tests do. The cluster has the name that no OperatorConfig
// changes, local, so each test judges with a playbook of its own, which only its namespace selects.

// localCluster is the name of the cluster when no OperatorConfig sets one.
const localCluster = "local"

// countsOf returns the counts of the playbook for the cluster, or nil when there are none, and deletes them when the test
// ends: no garbage collector deletes them with their Playbook here.
func countsOf(t *testing.T, playbook string) *inventoryv1alpha1.PlaybookCounts {
	t.Helper()
	return countsOfCluster(t, playbook, localCluster)
}

// countsOfCluster is countsOf for the counts under the cluster's name.
func countsOfCluster(t *testing.T, playbook, cluster string) *inventoryv1alpha1.PlaybookCounts {
	t.Helper()
	_, direct := startAPI(t)
	var counts inventoryv1alpha1.PlaybookCounts
	err := direct.Get(context.Background(), client.ObjectKey{Name: inventory.CountsName(playbook, cluster)}, &counts)
	if apierrors.IsNotFound(err) {
		return nil
	}
	require.NoError(t, err)
	return &counts
}

// countsWhere waits until the playbook's counts exist and hold, and returns them.
func countsWhere(t *testing.T, playbook string, holds func(inventory.Tally) bool) *inventoryv1alpha1.PlaybookCounts {
	t.Helper()
	_, direct := startAPI(t)
	t.Cleanup(func() {
		assert.NoError(t, client.IgnoreNotFound(direct.Delete(context.Background(), &inventoryv1alpha1.PlaybookCounts{
			ObjectMeta: metav1.ObjectMeta{Name: inventory.CountsName(playbook, localCluster)}})))
	})
	var counts *inventoryv1alpha1.PlaybookCounts
	require.Eventually(t, func() bool {
		counts = countsOf(t, playbook)
		return counts != nil && holds(inventory.TallyOf(counts.Status))
	}, wait, tick, "the counts of playbook %s", playbook)
	return counts
}

func TestTheSpokeWritesTheCountsOfEachPlaybookForItsCluster(t *testing.T) {
	stage, suffix := "counts-"+rand.String(6), rand.String(6)
	playbook := createPlaybook(t, "counts-"+suffix, stage)
	c := newCluster()
	ns := labelledNamespace(t, map[string]string{stageKey: stage})
	s := startReporting(t, c)
	web, api, late := running(ns, webName, linuxAMD64), running(ns, "api", linuxAMD64), running(ns, "late", linuxAMD64)
	webDigest, apiDigest, lateDigest := newDigest(t), newDigest(t), newDigest(t)
	webManifest, apiManifest, lateManifest := newDigest(t), newDigest(t), newDigest(t)
	s.presence.Snapshot("workloads", []cloudevents.Event{presenceEvent(t, webDigest, web),
		presenceEvent(t, apiDigest, api), presenceEvent(t, lateDigest, late)})
	setFacts(t, c, webDigest, manifestFacts(webManifest))
	setFacts(t, c, apiDigest, manifestFacts(apiManifest))
	setFacts(t, c, lateDigest, manifestFacts(lateManifest))
	critical := openFinding("CVE-2026-0001", "libcritical")
	critical.Severity = inventoryv1alpha1.SeverityCritical
	negligible := openFinding("CVE-2026-0002", "libnegligible")
	negligible.Severity = inventoryv1alpha1.SeverityNegligible
	// A finding that only needs a look is an Investigate action.
	look := openFinding("CVE-2026-0003", "liblook")
	look.Status = inventoryv1alpha1.VEXStatusUnderInvestigation
	look.Severity = inventoryv1alpha1.SeverityUnknown
	look.FixState, look.FixedVersions, look.FixTarget, look.UpdateTarget = inventoryv1alpha1.FixStateUnknown, nil, nil, nil
	putSheetOf(t, webManifest, playbook.Name, playbookSheet(playbook.Name, webManifest, critical, negligible, look).Status)
	// The api's sheet holds nothing open: judged, and not failing. The late workload has no sheet yet: not judged.
	putSheetOf(t, apiManifest, playbook.Name, playbookSheet(playbook.Name, apiManifest).Status)

	counts := countsWhere(t, playbook.Name, func(s inventory.Tally) bool { return s.Judged == 2 })

	require.Equal(t, inventoryv1alpha1.PlaybookCountsSpec{Playbook: playbook.Name, Cluster: localCluster}, counts.Spec)
	require.Len(t, counts.OwnerReferences, 1)
	require.Equal(t, "Playbook", counts.OwnerReferences[0].Kind)
	require.Equal(t, playbook.UID, counts.OwnerReferences[0].UID, "the Playbook owns its counts")
	require.Equal(t, inventory.Tally{Judged: 2, Failing: 1, Updates: 2, Investigations: 1, Critical: 1, Low: 1, Unknown: 1},
		inventory.TallyOf(counts.Status), "only the web resource has actions, and a negligible action counts as low")
	require.NotNil(t, counts.Status.UpdatedTime)
}

func TestTheSpokeWritesTheCountsAgainOnlyWhenTheyChangeAndDeletesThemWhenNothingIsJudged(t *testing.T) {
	stage, suffix := "once-"+rand.String(6), rand.String(6)
	playbook := createPlaybook(t, "once-"+suffix, stage)
	c := newCluster()
	ns := labelledNamespace(t, map[string]string{stageKey: stage})
	s := startReporting(t, c)
	digest, manifest := newDigest(t), newDigest(t)
	web := running(ns, webName, linuxAMD64)
	s.presence.Snapshot("workloads", []cloudevents.Event{presenceEvent(t, digest, web)})
	setFacts(t, c, digest, manifestFacts(manifest))
	putSheetOf(t, manifest, playbook.Name, playbookSheet(playbook.Name, manifest, openFinding("CVE-2026-0001", "libone")).Status)
	first := countsWhere(t, playbook.Name, func(s inventory.Tally) bool { return s.Failing == 1 })

	// A label of the namespace that no playbook selects by has its reports looked at again, which finds what the counts hold.
	// A time is kept to the second, so a write a second later would show.
	time.Sleep(1100 * time.Millisecond)
	_, direct := startAPI(t)
	namespace := &corev1.Namespace{}
	require.NoError(t, direct.Get(t.Context(), client.ObjectKey{Name: ns}, namespace))
	patch := client.MergeFrom(namespace.DeepCopy())
	namespace.Labels["unrelated"] = "label"
	require.NoError(t, direct.Patch(t.Context(), namespace, patch))
	require.Never(t, func() bool { return countsOf(t, playbook.Name).ResourceVersion != first.ResourceVersion }, 2*quiet, tick,
		"the same counts are no write, and no new time")

	putSheetOf(t, manifest, playbook.Name, playbookSheet(playbook.Name, manifest, openFinding("CVE-2026-0001", "libone"),
		openFinding("CVE-2026-0002", "libtwo")).Status)
	second := countsWhere(t, playbook.Name, func(s inventory.Tally) bool { return s.Updates == 2 })
	require.True(t, second.Status.UpdatedTime.After(first.Status.UpdatedTime.Time), "the time moves with the counts")

	s.presence.Snapshot("workloads", nil)
	require.Eventually(t, func() bool { return countsOf(t, playbook.Name) == nil }, wait, tick,
		"a cluster that judges nothing under the playbook has no counts")
}

// A cluster that is renamed has its counts under the new name only: the former ones would be summed with them.
func TestARenamedClusterTakesItsCountsToTheNewName(t *testing.T) {
	stage, suffix := "rename-"+rand.String(6), rand.String(6)
	playbook := createPlaybook(t, "rename-"+suffix, stage)
	c := newCluster()
	ns := labelledNamespace(t, map[string]string{stageKey: stage})
	s := startReporting(t, c)
	digest, manifest := newDigest(t), newDigest(t)
	s.presence.Snapshot("workloads", []cloudevents.Event{presenceEvent(t, digest, running(ns, webName, linuxAMD64))})
	setFacts(t, c, digest, manifestFacts(manifest))
	putSheetOf(t, manifest, playbook.Name, playbookSheet(playbook.Name, manifest, openFinding("CVE-2026-0001", "libone")).Status)
	countsWhere(t, playbook.Name, func(s inventory.Tally) bool { return s.Judged == 1 })

	renamed := "renamed-" + suffix
	_, direct := startAPI(t)
	config := &configv1alpha1.OperatorConfig{ObjectMeta: metav1.ObjectMeta{Name: settings.ConfigName},
		Spec: configv1alpha1.OperatorConfigSpec{ClusterName: ptr.To(renamed)}}
	require.NoError(t, direct.Create(t.Context(), config))
	t.Cleanup(func() {
		assert.NoError(t, client.IgnoreNotFound(direct.Delete(context.Background(), config)))
		assert.NoError(t, client.IgnoreNotFound(direct.Delete(context.Background(), &inventoryv1alpha1.PlaybookCounts{
			ObjectMeta: metav1.ObjectMeta{Name: inventory.CountsName(playbook.Name, renamed)}})))
	})

	require.Eventually(t, func() bool {
		return countsOfCluster(t, playbook.Name, renamed) != nil && countsOf(t, playbook.Name) == nil
	}, wait, tick, "the counts move to the new name, and none stay under the former one")
}

// After a start the series fill report by report. The counts of a cluster that stand wait for the first sweep to have
// looked at every report, and are then what they were: no write of part of them, and no delete.
func TestAfterAStartTheCountsAreWrittenOnlyOnceEveryReportHasBeenLookedAt(t *testing.T) {
	stage, suffix := "start-"+rand.String(6), rand.String(6)
	playbook := createPlaybook(t, "start-"+suffix, stage)
	c := newCluster()
	ns := labelledNamespace(t, map[string]string{stageKey: stage})
	const resources = 12
	digest, manifest := newDigest(t), newDigest(t)
	workloads := make([]evidence.PresenceWorkload, 0, resources)
	for i := range resources {
		workloads = append(workloads, running(ns, fmt.Sprintf("web-%d", i), linuxAMD64))
	}
	events := func() []cloudevents.Event { return []cloudevents.Event{presenceEvent(t, digest, workloads...)} }
	first := startReporting(t, c)
	first.presence.Snapshot("workloads", events())
	setFacts(t, c, digest, manifestFacts(manifest))
	putSheetOf(t, manifest, playbook.Name, playbookSheet(playbook.Name, manifest, openFinding("CVE-2026-0001", "libone")).Status)
	stored := countsWhere(t, playbook.Name, func(s inventory.Tally) bool { return s.Judged == resources })
	first.stop()

	// The renderer of the restarted spoke can't finish a report for a second, longer than the delay of the counts, and it
	// starts with no series: the counts that it would write then are none, or part of them.
	until := time.Now().Add(time.Second)
	verdictsWrap = func(v inventory.VerdictsStore) inventory.VerdictsStore {
		return lateVerdicts{VerdictsStore: v, until: until}
	}
	t.Cleanup(func() { verdictsWrap = nil })
	second := startReporting(t, c)
	second.presence.Snapshot("workloads", events())

	require.Never(t, func() bool {
		now := countsOf(t, playbook.Name)
		return now == nil || now.ResourceVersion != stored.ResourceVersion
	}, 5*time.Second, tick, "no counts are written or deleted while the reports are looked at, and the complete ones stand")
}
