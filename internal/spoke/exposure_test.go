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
	"testing"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	triagev1alpha1 "github.com/bedag/vexplain/api/triage/v1alpha1"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/spoke"
	"github.com/bedag/vexplain/sdk/evidence"
	"github.com/bedag/vexplain/sdk/subject"
)

// exposed and indirect are exposures that the tests start from.
var (
	exposed  = evidence.Exposure{External: evidence.ExternalExposure{Exposed: true}, InternalReach: "Namespace"}
	indirect = evidence.Exposure{InternalReach: "Namespace", Indirect: true}
)

// exposureFor returns the event of an exposure collector about the workload.
func exposureFor(t *testing.T, w evidence.PresenceWorkload, data evidence.Exposure) cloudevents.Event {
	t.Helper()
	e, err := evidence.New(evidence.TypeExposure, subjectOf(w), data, evidence.WithSource("/clusters/cluster-a/collectors/exposure"))
	require.NoError(t, err)
	return e
}

// subjectOf returns the subject of an exposure event about the workload.
func subjectOf(w evidence.PresenceWorkload) string {
	return subject.ForWorkload(subject.Workload{
		Cluster: clusterA, Namespace: w.Namespace, Group: w.APIGroup, Kind: w.Kind, Name: w.Name,
	})
}

func reach(r string) evidence.Exposure { return evidence.Exposure{InternalReach: r} }

func TestExposureMapsWhatACollectorSaysToTheSSVCValue(t *testing.T) {
	web := running("team-a", "web")
	for name, tc := range map[string]struct {
		data evidence.Exposure
		want configv1alpha1.SSVCExposure
	}{
		"exposed from outside":                 {exposed, configv1alpha1.SSVCExposureOpen},
		"exposed, and reached from everywhere": {evidence.Exposure{External: exposed.External, InternalReach: reachCluster}, configv1alpha1.SSVCExposureOpen},
		"reached indirectly":                   {indirect, configv1alpha1.SSVCExposureControlled},
		"reached by peers":                     {reach("Peers"), configv1alpha1.SSVCExposureControlled},
		"reached from several namespaces":      {reach("Namespaces"), configv1alpha1.SSVCExposureControlled},
		"reached from the whole cluster":       {reach("Cluster"), configv1alpha1.SSVCExposureControlled},
		"reached from its own namespace alone": {reach("Namespace"), configv1alpha1.SSVCExposureSmall},
	} {
		t.Run(name, func(t *testing.T) {
			e := spoke.NewExposure()
			e.Snapshot("exposure", []cloudevents.Event{exposureFor(t, web, tc.data)})
			require.Equal(t, tc.want, e.Of(web))
		})
	}
	t.Run("no evidence", func(t *testing.T) {
		require.Equal(t, configv1alpha1.SSVCExposureUnknown, spoke.NewExposure().Of(web))
	})
	t.Run("an event that doesn't follow the schema says nothing", func(t *testing.T) {
		e := spoke.NewExposure()
		e.Snapshot("exposure", []cloudevents.Event{exposureFor(t, web, reach("Planet"))})
		require.Equal(t, configv1alpha1.SSVCExposureUnknown, e.Of(web))
	})
}

func TestExposureOfAnImageIsTheHighestOfItsWorkloads(t *testing.T) {
	open, small, controlled, unknown := running("team-a", "open"), running("team-a", "small"),
		running("team-a", "controlled"), running("team-a", "unknown")
	e := spoke.NewExposure()
	e.Snapshot("exposure", []cloudevents.Event{exposureFor(t, open, exposed), exposureFor(t, small, reach("Namespace")),
		exposureFor(t, controlled, reach("Peers"))})
	for name, tc := range map[string]struct {
		workloads []evidence.PresenceWorkload
		want      configv1alpha1.SSVCExposure
	}{
		"Open and Small":         {[]evidence.PresenceWorkload{small, open}, configv1alpha1.SSVCExposureOpen},
		"Unknown and Controlled": {[]evidence.PresenceWorkload{controlled, unknown}, configv1alpha1.SSVCExposureUnknown},
		"Open and Unknown":       {[]evidence.PresenceWorkload{unknown, open}, configv1alpha1.SSVCExposureOpen},
		"Controlled and Small":   {[]evidence.PresenceWorkload{small, controlled}, configv1alpha1.SSVCExposureControlled},
		"Small alone":            {[]evidence.PresenceWorkload{small}, configv1alpha1.SSVCExposureSmall},
		"no workload":            {nil, configv1alpha1.SSVCExposureUnknown},
	} {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, tc.want, e.ForImage(tc.workloads))
		})
	}
}

// A workload is keyed by group, kind, namespace and name: the UID of its presence isn't in an exposure subject.
func TestExposureKeysAWorkloadWithoutItsUID(t *testing.T) {
	web := running("team-a", "web")
	e := spoke.NewExposure()
	e.Snapshot("exposure", []cloudevents.Event{exposureFor(t, web, exposed)})

	recreated := web
	recreated.UID = "another"
	require.Equal(t, configv1alpha1.SSVCExposureOpen, e.Of(recreated))
	other := web
	other.Kind = "StatefulSet"
	require.Equal(t, configv1alpha1.SSVCExposureUnknown, e.Of(other))
}

func TestExposureTakesTheHighestOfSeveralCollectorsAndForgetsOneAtATime(t *testing.T) {
	web := running("team-a", "web")
	e := spoke.NewExposure()
	e.Snapshot("first", []cloudevents.Event{exposureFor(t, web, reach("Namespace"))})
	e.Snapshot("second", []cloudevents.Event{exposureFor(t, web, reach("Peers"))})
	require.Equal(t, configv1alpha1.SSVCExposureControlled, e.Of(web))

	e.Upsert("first", exposureFor(t, web, exposed))
	require.Equal(t, configv1alpha1.SSVCExposureOpen, e.Of(web))

	e.Forget("first")
	require.Equal(t, configv1alpha1.SSVCExposureControlled, e.Of(web), "what the second said stays")

	e.Remove("second", evidence.TypeExposure, subjectOf(web))
	require.Equal(t, configv1alpha1.SSVCExposureUnknown, e.Of(web))
}

// A report shows the workload's reach beside its exposure: the widest internal reach that a collector says, and indirect
// when any collector says so (decision 0038). Without evidence there is no reach.
func TestExposureKeepsTheWidestReachAndIndirectWhenAnyCollectorSaysSo(t *testing.T) {
	web := running("team-a", "web")
	reachOf := func(r triagev1alpha1.InternalReach, i triagev1alpha1.IndirectExposure) *triagev1alpha1.ReportReach {
		return &triagev1alpha1.ReportReach{InternalReach: r, Indirect: i}
	}
	e := spoke.NewExposure()
	require.Equal(t, spoke.WorkloadExposure{SSVC: configv1alpha1.SSVCExposureUnknown}, e.ForReport(web), "no evidence, no reach")

	e.Snapshot("first", []cloudevents.Event{exposureFor(t, web, reach("Namespaces"))})
	require.Equal(t, spoke.WorkloadExposure{SSVC: configv1alpha1.SSVCExposureControlled,
		Reach: reachOf(triagev1alpha1.InternalReachNamespaces, triagev1alpha1.IndirectExposureNotIndirect)}, e.ForReport(web))

	e.Snapshot("second", []cloudevents.Event{exposureFor(t, web, indirect)})
	require.Equal(t, reachOf(triagev1alpha1.InternalReachNamespaces, triagev1alpha1.IndirectExposureIndirect), e.ForReport(web).Reach,
		"the wider reach of the first, and the second's indirect")

	e.Upsert("second", exposureFor(t, web, evidence.Exposure{External: exposed.External, InternalReach: reachCluster}))
	require.Equal(t, spoke.WorkloadExposure{SSVC: configv1alpha1.SSVCExposureOpen,
		Reach: reachOf(triagev1alpha1.InternalReachCluster, triagev1alpha1.IndirectExposureNotIndirect)}, e.ForReport(web))

	e.Forget("second")
	require.Equal(t, reachOf(triagev1alpha1.InternalReachNamespaces, triagev1alpha1.IndirectExposureNotIndirect), e.ForReport(web).Reach,
		"what the first said stays")

	e.Remove("first", evidence.TypeExposure, subjectOf(web))
	require.Nil(t, e.ForReport(web).Reach)
}

func TestASnapshotReplacesWhatTheCollectorSaidBefore(t *testing.T) {
	web, api := running("team-a", "web"), running("team-a", "api")
	e := spoke.NewExposure()
	e.Snapshot("exposure", []cloudevents.Event{exposureFor(t, web, exposed), exposureFor(t, api, exposed)})

	e.Snapshot("exposure", []cloudevents.Event{exposureFor(t, web, reach("Namespace"))})

	require.Equal(t, configv1alpha1.SSVCExposureSmall, e.Of(web))
	require.Equal(t, configv1alpha1.SSVCExposureUnknown, e.Of(api))
}

func exposureOfEntry(t *testing.T, c cluster, digest string) *inventoryv1alpha1.SSVCExposure {
	t.Helper()
	entry := entryOf(t, c, digest)
	require.NotNil(t, entry)
	return entry.Exposure
}

// resourceVersion returns the version of the ImageInventory of digest, which changes with each write.
func resourceVersion(t *testing.T, digest string) string {
	t.Helper()
	_, direct := startAPI(t)
	var obj inventoryv1alpha1.ImageInventory
	require.NoError(t, direct.Get(context.Background(), client.ObjectKey{Name: inventory.NameForDigest(digest)}, &obj))
	return obj.ResourceVersion
}

func TestAChangeOfAWorkloadsExposureRewritesTheEntriesOfItsImages(t *testing.T) {
	c := newCluster()
	s := startSpoke(t, c)
	exposureCollector := newCollector(t, evidence.TypeExposure)
	s.sees(t, exposureCollector)
	digest := newDigest(t)
	web := running("team-a", "web", linuxAMD64)
	s.exposure.Snapshot(exposureCollector, []cloudevents.Event{exposureFor(t, web, reach("Namespace"))})
	s.presence.Snapshot("workloads", []cloudevents.Event{presenceEvent(t, digest, web)})
	require.Eventually(t, func() bool {
		entry := entryOf(t, c, digest)
		return entry != nil && ptr.Equal(entry.Exposure, ptr.To(inventoryv1alpha1.SSVCExposureSmall))
	}, wait, tick, "the entry carries the exposure of its workload")

	s.exposure.Upsert(exposureCollector, exposureFor(t, web, exposed))
	require.Eventually(t, func() bool {
		return ptr.Equal(exposureOfEntry(t, c, digest), ptr.To(inventoryv1alpha1.SSVCExposureOpen))
	}, wait, tick, "the entry follows the change")

	// The same exposure again, and another that gives the same value, write nothing.
	version := resourceVersion(t, digest)
	s.exposure.Upsert(exposureCollector, exposureFor(t, web, exposed))
	s.exposure.Upsert(exposureCollector, exposureFor(t, web, evidence.Exposure{External: exposed.External, InternalReach: reachCluster}))
	require.Never(t, func() bool { return resourceVersion(t, digest) != version }, quiet, tick,
		"the entry isn't written again")
}

// After a start, presence knows each image at the first snapshot of its collector, and exposure knows each workload at
// the first snapshot of its own. The entry of an image keeps the exposure it had until then, instead of an Unknown that
// a snapshot of presence would write over it.
func TestAfterAStartAnEntryKeepsItsExposureUntilTheExposureCollectorsFirstSnapshot(t *testing.T) {
	c := newCluster()
	exposureCollector := newCollector(t, evidence.TypeExposure)
	digest := newDigest(t)
	web := running("team-a", "web", linuxAMD64)
	before := startSpoke(t, c)
	before.exposure.Snapshot(exposureCollector, []cloudevents.Event{exposureFor(t, web, exposed)})
	before.presence.Snapshot("workloads", []cloudevents.Event{presenceEvent(t, digest, web)})
	require.Eventually(t, func() bool {
		entry := entryOf(t, c, digest)
		return entry != nil && ptr.Equal(entry.Exposure, ptr.To(inventoryv1alpha1.SSVCExposureOpen))
	}, wait, tick)
	before.stop()

	after := startSpoke(t, c)
	after.presence.Snapshot("workloads", []cloudevents.Event{presenceEvent(t, digest, web)})
	require.Never(t, func() bool {
		entry := entryOf(t, c, digest)
		return entry == nil || !ptr.Equal(entry.Exposure, ptr.To(inventoryv1alpha1.SSVCExposureOpen))
	}, quiet, tick, "the entry keeps its exposure while the exposure collector hasn't sent its snapshot")
	version := resourceVersion(t, digest)

	after.exposure.Snapshot(exposureCollector, []cloudevents.Event{exposureFor(t, web, reach("Peers"))})
	require.Eventually(t, func() bool {
		return ptr.Equal(exposureOfEntry(t, c, digest), ptr.To(inventoryv1alpha1.SSVCExposureControlled))
	}, wait, tick, "the entry takes what the snapshot gives")
	changed := resourceVersion(t, digest)
	require.NotEqual(t, version, changed)
	require.Never(t, func() bool { return resourceVersion(t, digest) != changed }, quiet, tick,
		"the entry changed once")
}

// A new entry has no exposure while the exposure collector hasn't sent its first snapshot.
func TestANewEntryHasNoExposureUntilTheExposureCollectorsFirstSnapshot(t *testing.T) {
	c := newCluster()
	s := startSpoke(t, c)
	exposureCollector := newCollector(t, evidence.TypeExposure)
	s.sees(t, exposureCollector)
	digest := newDigest(t)
	web := running("team-a", "web", linuxAMD64)

	s.presence.Snapshot("workloads", []cloudevents.Event{presenceEvent(t, digest, web)})
	require.Nil(t, present(t, c, digest).Exposure)
	stays(t, c, digest, true)
	require.Nil(t, exposureOfEntry(t, c, digest))

	s.exposure.Snapshot(exposureCollector, []cloudevents.Event{exposureFor(t, web, exposed)})
	require.Eventually(t, func() bool {
		return ptr.Equal(exposureOfEntry(t, c, digest), ptr.To(inventoryv1alpha1.SSVCExposureOpen))
	}, wait, tick)
}

// With no collector that streams exposure to the spoke, nothing will say anything of it: Unknown is written at once.
func TestWithNoExposureCollectorAnEntryHasUnknownAtOnce(t *testing.T) {
	c := newCluster()
	s := startSpoke(t, c)
	digest := newDigest(t)

	s.presence.Snapshot("workloads", []cloudevents.Event{presenceEvent(t, digest, running("team-a", "web", linuxAMD64))})

	entry := present(t, c, digest)
	require.Equal(t, ptr.To(inventoryv1alpha1.SSVCExposureUnknown), entry.Exposure)
}

// The collectors that stream exposure to the spoke can change while an entry waits for them. When one is forgotten
// before its first snapshot, the entry takes what the others say.
func TestAnEntryWaitingForAForgottenCollectorTakesWhatTheOthersSay(t *testing.T) {
	c := newCluster()
	s := startSpoke(t, c)
	snapshots, forgotten := newCollector(t, evidence.TypeExposure), newCollector(t, evidence.TypeExposure)
	s.sees(t, snapshots)
	s.sees(t, forgotten)
	digest := newDigest(t)
	web := running("team-a", "web", linuxAMD64)
	s.exposure.Snapshot(snapshots, []cloudevents.Event{exposureFor(t, web, exposed)})
	s.presence.Snapshot("workloads", []cloudevents.Event{presenceEvent(t, digest, web)})
	require.Nil(t, present(t, c, digest).Exposure)
	stays(t, c, digest, true)
	require.Nil(t, exposureOfEntry(t, c, digest), "the other collector hasn't sent its snapshot")

	_, direct := startAPI(t)
	require.NoError(t, direct.Delete(t.Context(), &configv1alpha1.Collector{ObjectMeta: metav1.ObjectMeta{Name: forgotten}}))
	s.exposure.Forget(forgotten)

	require.Eventually(t, func() bool {
		return ptr.Equal(exposureOfEntry(t, c, digest), ptr.To(inventoryv1alpha1.SSVCExposureOpen))
	}, wait, tick, "the entry takes the exposure that the remaining collector gave")
}

// A Collector that stops being usable stops streaming. With no other collector that streams exposure, the entry that
// waited for it gets Unknown.
func TestAnEntryWaitingForACollectorThatIsNoLongerUsableGetsUnknown(t *testing.T) {
	c := newCluster()
	s := startSpoke(t, c)
	name := newCollector(t, evidence.TypeExposure)
	s.sees(t, name)
	digest := newDigest(t)
	s.presence.Snapshot("workloads", []cloudevents.Event{presenceEvent(t, digest, running("team-a", "web", linuxAMD64))})
	require.Nil(t, present(t, c, digest).Exposure)
	stays(t, c, digest, true)
	require.Nil(t, exposureOfEntry(t, c, digest))

	_, direct := startAPI(t)
	var collector configv1alpha1.Collector
	require.NoError(t, direct.Get(t.Context(), client.ObjectKey{Name: name}, &collector))
	meta.SetStatusCondition(&collector.Status.Conditions, metav1.Condition{
		Type: configv1alpha1.ConditionReady, Status: metav1.ConditionFalse, Reason: "Unreachable",
		Message: "The collector can't be reached.", ObservedGeneration: collector.Generation,
	})
	require.NoError(t, direct.Status().Update(t.Context(), &collector))

	require.Eventually(t, func() bool {
		return ptr.Equal(exposureOfEntry(t, c, digest), ptr.To(inventoryv1alpha1.SSVCExposureUnknown))
	}, wait, tick, "Unknown is written once nothing streams exposure")
}
