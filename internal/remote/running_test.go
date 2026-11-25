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

package remote_test

import (
	"context"
	"fmt"
	"testing"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlconfig "sigs.k8s.io/controller-runtime/pkg/config"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/evidence"
	"github.com/bedag/vexplain/internal/exposure"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/remote"
	"github.com/bedag/vexplain/internal/settings"
	"github.com/bedag/vexplain/internal/setup"
	internalspoke "github.com/bedag/vexplain/internal/spoke"
	sdkevidence "github.com/bedag/vexplain/sdk/evidence"
	"github.com/bedag/vexplain/sdk/subject"
	"github.com/bedag/vexplain/sdk/workloads"
)

// The tests of what the hub renders of a remote cluster hold the hub's copies of the cluster's records in the hub's
// stores, as the copier of its spoke leaves them, and read them through a view of the hub's evidence, as the hub does.
// No spoke is reached: what the hub renders comes from the copies alone.

// repository is where the images of the copies come from.
const repository = "artifacts.example/team-a/app"

// startHubView runs a view of the hub's evidence until the test ends, as the hub runs it, and returns it once it has read
// what the store holds.
func startHubView(t *testing.T) *exposure.View {
	t.Helper()
	mgr, err := ctrl.NewManager(hub.cfg, ctrl.Options{Scheme: scheme, Cache: setup.CacheOptions(namespace),
		Client: setup.ClientOptions(), Metrics: metricsserver.Options{BindAddress: "0"},
		// Each test that runs a view starts a manager of its own.
		Controller: ctrlconfig.Controller{SkipNameValidation: ptr.To(true)}})
	require.NoError(t, err)
	view := exposure.NewView(evidence.NewCRDStore(mgr.GetClient(), mgr.GetCache(),
		func() string { return settings.DefaultClusterName }))
	require.NoError(t, view.SetupWithManager(mgr))
	running, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- mgr.Start(running) }()
	t.Cleanup(func() {
		cancel()
		require.NoError(t, <-done)
	})
	require.Eventually(t, view.Synced, timeout, poll, "the view reads the hub's store")
	return view
}

// copyIn puts the event into the hub's evidence store as the copy of the record that the collector streamed in the
// cluster, as the copier puts one, and deletes it when the test ends.
func (h *hubSide) copyIn(cluster, collector string, e cloudevents.Event) {
	h.t.Helper()
	require.NoError(h.t, h.evidence.Put(ctx, collector, collectorVersion, e, evidence.InCluster(cluster)))
	h.t.Cleanup(func() { require.NoError(h.t, h.evidence.Delete(ctx, keyIn(cluster, collector, e))) })
}

// observeIn puts the entry of the cluster of the name and identity into the hub's inventory for the digest, as the
// copier observes the spoke's entry, and forgets it when the test ends.
func (h *hubSide) observeIn(name, id, digest string) {
	h.t.Helper()
	require.NoError(h.t, h.inventory.Observe(ctx, digest, inventory.Observation{Cluster: name, ClusterID: id,
		DigestKind: inventoryv1alpha1.DigestKindRepoDigest, Repositories: []string{repository}, NamespaceCount: 1}))
	h.t.Cleanup(func() { require.NoError(h.t, h.inventory.Forget(ctx, digest, name, id)) })
}

// presenceOf returns the presence of the image of the digest, pulled from the repository of the tests, which the
// workloads run.
func presenceOf(t *testing.T, digest string, ws ...sdkevidence.PresenceWorkload) cloudevents.Event {
	t.Helper()
	return newEvent(t, sdkevidence.TypePresence, subject.Image(digest), sdkevidence.Presence{
		DigestKind: sdkevidence.DigestKindRepoDigest, Repositories: []string{repository}, Workloads: ws})
}

// deploymentOn returns the Deployment of the name in team-a of the cluster, whose one pod runs on the platform, with a
// container of the workload's name.
func deploymentOn(cluster, name, platform string) sdkevidence.PresenceWorkload {
	return sdkevidence.PresenceWorkload{Subject: workloadIn(cluster, name), APIGroup: deploymentGroup, Kind: deployment,
		Namespace: teamA, Name: name, UID: "uid-" + name, Pods: []sdkevidence.PresencePod{{Name: name + "-0",
			Node: "node-0", Platform: platform, Containers: []sdkevidence.PresenceContainer{{Name: name,
				Kind: workloads.ContainerKindContainer}}}}}
}

// recorded sets the Spoke's status to what the hub's controller would have recorded: the identity, the collectors, and
// the Connected condition of the status and the reason, when it names one.
func recorded(t *testing.T, obj *configv1alpha1.Spoke, id string, collectors []configv1alpha1.SpokeCollector,
	connected metav1.ConditionStatus, reason string) {
	t.Helper()
	if id != "" {
		obj.Status.ClusterID = ptr.To(id)
	}
	obj.Status.Collectors = collectors
	if reason != "" {
		meta.SetStatusCondition(&obj.Status.Conditions, metav1.Condition{Type: configv1alpha1.ConditionConnected,
			Status: connected, Reason: reason, Message: "As the hub found it."})
	}
	require.NoError(t, hub.client.Status().Update(ctx, obj))
}

// nextName returns a cluster name that no other test has.
func nextName() string {
	return fmt.Sprintf("cluster-%d", spokes.Add(1))
}

// What runs in a remote cluster is what the hub's copies of the cluster's presence say, as the cluster's own presence
// would say it: each workload once, where two collectors name it the one whose name sorts first says what it is, and
// its exposure from the copies of its exposure. Another cluster's copies say nothing of it, and a caller may change
// what it gets.
func TestWhatRunsInARemoteClusterIsWhatItsCopiesSay(t *testing.T) {
	name, elsewhere := nextName(), nextName()
	h := hubOf(t, name)
	digest := newDigest()
	web, api := deploymentOn(name, "web", "linux/amd64"), deploymentOn(name, "api", "linux/amd64")
	// The runtime's collector, whose name sorts before workloads, names web too, on another platform.
	webByRuntime := deploymentOn(name, "web", "linux/arm64")
	h.copyIn(name, workloadsCollector, presenceOf(t, digest, web, api))
	h.copyIn(name, "runtime", presenceOf(t, digest, webByRuntime))
	h.copyIn(name, reachCollector, exposureIn(t, name, "web"))
	h.copyIn(elsewhere, workloadsCollector, presenceOf(t, digest, deploymentOn(elsewhere, "db", "linux/amd64")))
	view := startHubView(t)

	running := remote.RunningIn(view, name)

	knows, err := running.KnowsWhatRuns(ctx)
	require.NoError(t, err)
	require.True(t, knows, "it knows what runs once the view has read the store")
	knows, err = running.ExposureKnown(ctx)
	require.NoError(t, err)
	require.True(t, knows)
	require.Equal(t, []types.NamespacedName{{Namespace: teamA, Name: "deployment-api"},
		{Namespace: teamA, Name: "deployment-web"}}, running.RunningReports(), "the cluster's own workloads, sorted")
	got, ok := running.Running(teamA, "deployment-web")
	require.True(t, ok)
	require.Equal(t, webByRuntime, got.Workload)
	require.Equal(t, []internalspoke.RunningImage{{Digest: digest, Platforms: []string{"linux/arm64"},
		Containers: []workloads.ContainerRef{{Name: "web", Kind: workloads.ContainerKindContainer}},
		Kind:       sdkevidence.DigestKindRepoDigest, Ref: repository}}, got.Images)
	require.Equal(t, []sdkevidence.PresenceWorkload{api, webByRuntime}, running.Workloads(digest), "each once, sorted")
	require.Equal(t, internalspoke.WorkloadExposureOf(sdkevidence.Exposure{InternalReach: clusterReach}), running.ExposureOf(web))
	require.Equal(t, internalspoke.WorkloadExposure{SSVC: configv1alpha1.SSVCExposureUnknown}, running.ExposureOf(api),
		"no copy of its exposure")
	_, ok = running.Running(teamA, "deployment-db")
	require.False(t, ok, "a workload of another cluster")

	const changed = "changed"
	got.Workload.Pods[0].Containers[0].Name = changed
	got.Images[0].Platforms[0] = changed
	listed := running.Workloads(digest)
	listed[0].Pods[0].Name = changed
	reports := running.RunningReports()
	reports[0].Name = changed
	again, _ := running.Running(teamA, "deployment-web")
	require.Equal(t, webByRuntime, again.Workload, "a caller may change what it gets")
	require.Equal(t, []string{"linux/arm64"}, again.Images[0].Platforms)
	require.Equal(t, []sdkevidence.PresenceWorkload{api, webByRuntime}, running.Workloads(digest))
	require.Equal(t, "deployment-api", running.RunningReports()[0].Name)
}

// The hub renders the cluster of each Spoke that it copies from, also while it can't reach the spoke, with the Spoke's
// labels. It renders none whose copies would be the hub's own: one that it refused as named like its own cluster or as
// reaching it, one of its own cluster's name that it hasn't checked yet, and one that is being deleted.
func TestTheHubRendersOnlyTheSpokesThatItMayCopyFrom(t *testing.T) {
	view := startHubView(t)
	unreachable := namedSpoke(t, nextName(), nil)
	unreachable.Spec.Labels = map[string]configv1alpha1.LabelValue{"example.com/env": "test"}
	require.NoError(t, hub.client.Update(ctx, unreachable))
	recorded(t, unreachable, "id-unreachable", nil, metav1.ConditionFalse, configv1alpha1.ReasonUnreachable)
	recorded(t, namedSpoke(t, nextName(), nil), "", nil, metav1.ConditionFalse, configv1alpha1.ReasonNameInUse)
	recorded(t, namedSpoke(t, nextName(), nil), "", nil, metav1.ConditionFalse, configv1alpha1.ReasonOwnCluster)
	namedSpoke(t, settings.DefaultClusterName, nil)
	deleting := namedSpoke(t, nextName(), nil)
	deleting.Finalizers = []string{"test.vexplain.bedag.ch/hold"}
	require.NoError(t, hub.client.Update(ctx, deleting))
	require.NoError(t, hub.client.Delete(ctx, deleting))
	t.Cleanup(func() {
		require.NoError(t, client.IgnoreNotFound(hub.client.Get(ctx, client.ObjectKeyFromObject(deleting), deleting)))
		deleting.Finalizers = nil
		require.NoError(t, client.IgnoreNotFound(hub.client.Update(ctx, deleting)))
	})

	clusters, err := remote.Clusters(hub.client, view)(ctx)

	require.NoError(t, err)
	require.Len(t, clusters, 1)
	require.Equal(t, unreachable.Name, clusters[0].Name)
	require.Equal(t, map[string]string{"example.com/env": "test"}, clusters[0].Labels)
	_, known := clusters[0].NamespaceLabels(teamA)
	require.False(t, known, "the hub holds no copy of the namespace's labels")
	knows, err := clusters[0].Running.KnowsWhatRuns(ctx)
	require.NoError(t, err)
	require.True(t, knows)
}

// seriesOf collects the collectors through a registry, as a scrape does, and returns the value of each series of the
// metric of the name, by the values of its labels cluster and, when the series has it, collector.
func seriesOf(t *testing.T, name string, collectors ...prometheus.Collector) map[string]float64 {
	t.Helper()
	reg := prometheus.NewRegistry()
	for _, c := range collectors {
		require.NoError(t, reg.Register(c))
	}
	families, err := reg.Gather()
	require.NoError(t, err, "every series of the scrape is valid, and none repeats another")
	out := map[string]float64{}
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, m := range family.GetMetric() {
			var key []string
			for _, l := range m.GetLabel() {
				if l.GetName() == "cluster" || l.GetName() == "collector" {
					key = append(key, l.GetValue())
				}
			}
			out[fmt.Sprint(key)] = m.GetGauge().GetValue()
		}
	}
	return out
}

// An image with an entry of a remote cluster whose presence record the hub holds no copy of, as when the spoke's store
// refused the record, is missing from the cluster's series: the hub counts such images, for each cluster that it
// renders.
func TestARemoteImageWithoutPresenceIsCounted(t *testing.T) {
	name, refusedName := nextName(), nextName()
	recorded(t, namedSpoke(t, name, nil), "id-"+name, nil, metav1.ConditionFalse, configv1alpha1.ReasonUnreachable)
	recorded(t, namedSpoke(t, refusedName, nil), "id-"+refusedName, nil, metav1.ConditionFalse,
		configv1alpha1.ReasonNameInUse)
	h := hubOf(t, name)
	shown, missing := newDigest(), newDigest()
	h.observeIn(name, "id-"+name, shown)
	h.observeIn(name, "id-"+name, missing)
	h.observeIn(refusedName, "id-"+refusedName, missing)
	h.copyIn(name, workloadsCollector, presenceOf(t, shown, deploymentOn(name, "web", "linux/amd64")))
	view := startHubView(t)

	series := seriesOf(t, "vexplain_remote_images_without_presence",
		remote.NewSpokesCollector(hub.client, h.inventory, view, logr.Discard()))

	require.Equal(t, 1.0, series[fmt.Sprint([]string{name})])
	require.NotContains(t, series, fmt.Sprint([]string{refusedName}), "a refused Spoke has no series")
}

// The hub reads each remote collector's readiness from its Spoke, as the Spoke lists the spoke's collectors, and
// exports it as each cluster's own collectors' readiness is: one metric for the fleet.
func TestARemoteCollectorsReadinessIsASeries(t *testing.T) {
	name, refusedName := nextName(), nextName()
	view := startHubView(t)
	recorded(t, namedSpoke(t, name, nil), "", []configv1alpha1.SpokeCollector{
		{Name: workloadsCollector, Ready: ptr.To(metav1.ConditionTrue)},
		{Name: reachCollector, Ready: ptr.To(metav1.ConditionFalse)},
		{Name: "nodes"},
	}, metav1.ConditionTrue, configv1alpha1.ReasonConnected)
	recorded(t, namedSpoke(t, refusedName, nil), "", []configv1alpha1.SpokeCollector{
		{Name: workloadsCollector, Ready: ptr.To(metav1.ConditionTrue)},
	}, metav1.ConditionFalse, configv1alpha1.ReasonNameInUse)

	series := seriesOf(t, "vexplain_collector_ready",
		remote.NewSpokesCollector(hub.client, hubOf(t, name).inventory, view, logr.Discard()),
		internalspoke.NewCollectorsCollector(hub.client, logr.Discard()))

	require.Equal(t, 1.0, series[fmt.Sprint([]string{name, workloadsCollector})])
	require.Equal(t, 0.0, series[fmt.Sprint([]string{name, reachCollector})])
	require.Equal(t, 0.0, series[fmt.Sprint([]string{name, "nodes"})], "a collector whose readiness the hub didn't read")
	require.NotContains(t, series, fmt.Sprint([]string{refusedName, workloadsCollector}), "a refused Spoke has no series")
}
